package abuse

import (
	"fmt"
	"hash/maphash"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/ratelimit"
)

// EnumerationRule allows each client to request Limit distinct values of
// the parameters of a path template per Window, e.g. 100 different order
// IDs an hour for "GET /api/orders/{id}". The window of a client starts
// with its first request; requests for values that it already requested
// in the window are always allowed.
type EnumerationRule struct {
	// Method restricts the rule to one request method. Empty matches
	// every method.
	Method string
	// Path is the template, cleaned like the paths of rate limits (see
	// ratelimit.CleanPath). Segments of the form "{name}" match any
	// segment; the others must be equal.
	Path   string
	Limit  int
	Window time.Duration
}

// ParseEnumerationRule parses "[METHOD ]PATH=N/WINDOW", where the path has
// at least one parameter segment, e.g. "GET /api/orders/{id}=100/1h" or
// "/users/{user}/files/{file}=50/10m".
func ParseEnumerationRule(s string) (EnumerationRule, error) {
	i := strings.LastIndex(s, "=")
	if i < 0 {
		return EnumerationRule{}, fmt.Errorf("abuse: invalid enumeration rule %q: want [METHOD ]PATH=N/WINDOW, e.g. GET /api/orders/{id}=100/1h", s)
	}
	limit, window, err := ratelimit.ParseRate(s[i+1:])
	if err != nil {
		return EnumerationRule{}, fmt.Errorf("abuse: invalid enumeration rule %q: %w", s, err)
	}
	r := EnumerationRule{Limit: limit, Window: window}
	switch target := strings.Fields(s[:i]); len(target) {
	case 1:
		r.Path = target[0]
	case 2:
		r.Method, r.Path = strings.ToUpper(target[0]), target[1]
		if strings.Trim(r.Method, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			return EnumerationRule{}, fmt.Errorf("abuse: invalid enumeration rule %q: invalid method %q", s, target[0])
		}
	default:
		return EnumerationRule{}, fmt.Errorf("abuse: invalid enumeration rule %q: want [METHOD ]PATH=N/WINDOW", s)
	}
	if !strings.HasPrefix(r.Path, "/") {
		return EnumerationRule{}, fmt.Errorf("abuse: invalid enumeration rule %q: the path must start with \"/\"", s)
	}
	r.Path = ratelimit.CleanPath(r.Path)
	params := 0
	for _, seg := range r.segments() {
		switch {
		case isParameter(seg):
			params++
		case strings.ContainsAny(seg, "{}*"):
			return EnumerationRule{}, fmt.Errorf("abuse: invalid enumeration rule %q: a parameter must be a whole segment such as {id}", s)
		}
	}
	if params == 0 {
		return EnumerationRule{}, fmt.Errorf("abuse: invalid enumeration rule %q: the path has no parameter such as {id} to count", s)
	}
	return r, nil
}

func isParameter(seg string) bool {
	return len(seg) > 2 && seg[0] == '{' && seg[len(seg)-1] == '}'
}

func (r EnumerationRule) segments() []string { return strings.Split(r.Path, "/")[1:] }

// String returns the rule in the syntax of ParseEnumerationRule.
func (r EnumerationRule) String() string {
	return ratelimit.Rule{Method: r.Method, Path: r.Path, Limit: r.Limit, Window: r.Window}.String()
}

// value returns the values of the parameters of a cleaned path, joined, if
// the rule matches the request.
func (r EnumerationRule) value(method string, segs, tmpl []string) (string, bool) {
	if r.Method != "" && r.Method != method || len(segs) != len(tmpl) {
		return "", false
	}
	var b strings.Builder
	for i, t := range tmpl {
		switch {
		case isParameter(t):
			b.WriteString(segs[i])
			b.WriteByte('/')
		case t != segs[i]:
			return "", false
		}
	}
	return b.String(), true
}

// sweepInterval is how often each shard removes clients whose window has
// ended.
const sweepInterval = time.Minute

const numShards = 64

// enumerationLimiter tracks, for each client and rule, the hashes of the
// values requested in the current window: at most Limit of 8 bytes each.
type enumerationLimiter struct {
	rules     []EnumerationRule
	templates [][]string
	exempt    []netip.Prefix
	logger    *slog.Logger
	seed      maphash.Seed
	shards    [numShards]enumShard
	now       func() time.Time // for tests

	warnMu   sync.Mutex
	warnedAt time.Time
}

type enumShard struct {
	mu        sync.Mutex
	clients   map[enumKey]*enumState
	max       int
	lastSweep int64
}

type enumKey struct {
	client netip.Prefix
	rule   int
}

type enumState struct {
	// end is when the window ends, in Unix nanoseconds.
	end    int64
	hashes []uint64
	// eventID identifies the audit event of the current excess.
	eventID string
}

func newEnumerationLimiter(cfg Config) (*enumerationLimiter, error) {
	l := &enumerationLimiter{
		rules:  cfg.Enumerations,
		exempt: cfg.Exempt,
		logger: cfg.Logger,
		seed:   maphash.MakeSeed(),
		now:    time.Now,
	}
	for _, r := range cfg.Enumerations {
		if r.Limit < 1 || r.Window <= 0 || !strings.HasPrefix(r.Path, "/") {
			return nil, fmt.Errorf("abuse: invalid enumeration rule %q", r)
		}
		l.templates = append(l.templates, r.segments())
	}
	maxClients := cfg.MaxClients
	if maxClients == 0 {
		maxClients = ratelimit.DefaultMaxClients
	}
	for i := range l.shards {
		l.shards[i].clients = map[enumKey]*enumState{}
		l.shards[i].max = max(1, (maxClients+numShards-1)/numShards)
	}
	return l, nil
}

// allow counts the value of a request for the rules that match it and
// reports whether they are within their limits. A value over the limit of
// a rule is not counted for it.
func (l *enumerationLimiter) allow(r *http.Request, clientIP string) Decision {
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		addr = netip.Addr{}
	}
	addr = addr.Unmap()
	for _, p := range l.exempt {
		if p.Contains(addr) {
			return Decision{Allowed: true}
		}
	}
	segs := strings.Split(ratelimit.CleanPath(r.URL.Path), "/")[1:]
	var client netip.Prefix
	now := l.now().UnixNano()
	// Each rule on its own: rules rarely overlap, and an excess of one
	// rejects the request regardless of the others.
	for i, rule := range l.rules {
		v, ok := rule.value(r.Method, segs, l.templates[i])
		if !ok {
			continue
		}
		if !client.IsValid() {
			client = clientKey(addr)
		}
		key := enumKey{client, i}
		h := maphash.String(l.seed, v)
		sh := &l.shards[maphash.Comparable(l.seed, key)%numShards]
		sh.mu.Lock()
		if now-sh.lastSweep >= int64(sweepInterval) {
			l.sweep(sh, now)
		}
		st := sh.clients[key]
		if st == nil || st.end <= now {
			if st == nil && len(sh.clients) >= sh.max {
				l.makeRoom(sh, now)
			}
			st = &enumState{end: now + int64(rule.Window)}
			sh.clients[key] = st
		}
		switch {
		case slices.Contains(st.hashes, h):
		case len(st.hashes) < rule.Limit:
			st.hashes = append(st.hashes, h)
		default:
			d := Decision{Reason: ReasonEnumeration, Rule: rule.String(), Client: client, RetryAfter: time.Duration(st.end - now)}
			if st.eventID == "" {
				st.eventID = audit.NewID()
				d.First = true
			}
			d.EventID = st.eventID
			sh.mu.Unlock()
			return d
		}
		sh.mu.Unlock()
	}
	return Decision{Allowed: true}
}

// clientKey returns the address, or the /64 network of an IPv6 address,
// that requests are counted for.
func clientKey(a netip.Addr) netip.Prefix {
	if a.Is6() {
		p, _ := a.Prefix(ratelimit.IPv6Prefix)
		return p
	}
	return netip.PrefixFrom(a, a.BitLen())
}

// sweep removes the clients whose window has ended.
func (l *enumerationLimiter) sweep(sh *enumShard, now int64) {
	sh.lastSweep = now
	for k, st := range sh.clients {
		if st.end <= now {
			delete(sh.clients, k)
		}
	}
}

// makeRoom makes room for a new client in a full shard: first by removing
// the clients whose window has ended, then by forgetting an arbitrary one.
func (l *enumerationLimiter) makeRoom(sh *enumShard, now int64) {
	if now-sh.lastSweep >= int64(time.Second) {
		l.sweep(sh, now)
		if len(sh.clients) < sh.max {
			return
		}
	}
	for k := range sh.clients {
		delete(sh.clients, k) // map iteration order is random
		break
	}
	l.warnMu.Lock()
	defer l.warnMu.Unlock()
	if t := l.now(); t.Sub(l.warnedAt) >= time.Minute {
		l.warnedAt = t
		l.logger.Warn("enumeration limiter is tracking its maximum number of clients; forgetting some, which resets their limits",
			"hint", "raise -rate-limit-max-clients if this happens without an attack")
	}
}

// Len returns the number of clients and rules tracked.
func (l *enumerationLimiter) Len() int {
	n := 0
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		n += len(sh.clients)
		sh.mu.Unlock()
	}
	return n
}
