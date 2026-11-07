// Package ratelimit limits how many requests each client can send, overall
// and to selected paths, to slow down brute-force attacks and floods from
// single sources.
//
// Each rule allows Limit requests per Window to every client: a client can
// send up to Limit requests at once, after which its allowance refills at
// a steady rate of one request every Window/Limit (the generic cell rate
// algorithm, a token bucket that needs a single timestamp per client and
// rule). Requests that are rejected do not use up the allowance.
package ratelimit

import (
	"errors"
	"fmt"
	"hash/maphash"
	"log/slog"
	"net/http"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cmc-labo/prism-waf/internal/audit"
)

// IPv6Prefix is the length of the IPv6 prefix that counts as one client.
// A single host usually has a whole /64, so limiting single IPv6 addresses
// would be trivial to evade.
const IPv6Prefix = 64

// DefaultMaxClients is the default number of clients tracked at once.
const DefaultMaxClients = 100_000

// numShards splits the clients across locks to reduce contention.
const numShards = 64

// sweepInterval is how often each shard removes clients whose allowance
// has refilled completely, which the limiter no longer needs to remember.
const sweepInterval = time.Minute

// Rule limits the requests of each client that it matches.
type Rule struct {
	// Method restricts the rule to one request method, e.g. "POST". Empty
	// matches every method.
	Method string
	// Path restricts the rule to one path, or with a trailing "*" to
	// every path that starts with the part before it. Empty matches every
	// path. Paths are compared without case, after cleaning (see
	// CleanPath).
	Path string
	// Limit requests are allowed per Window.
	Limit  int
	Window time.Duration
}

// ParseRate parses "N/WINDOW", e.g. "100/1m", "5/10s" or "1000/h". The
// window is a Go duration; a bare unit means one of it.
func ParseRate(s string) (limit int, window time.Duration, err error) {
	n, w, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return 0, 0, fmt.Errorf("ratelimit: invalid rate %q: want N/WINDOW, e.g. 100/1m", s)
	}
	limit, err = strconv.Atoi(strings.TrimSpace(n))
	if err != nil || limit < 1 {
		return 0, 0, fmt.Errorf("ratelimit: invalid rate %q: the number of requests must be a positive integer", s)
	}
	w = strings.TrimSpace(w)
	if w != "" && (w[0] < '0' || w[0] > '9') {
		w = "1" + w
	}
	window, err = time.ParseDuration(w)
	if err != nil || window <= 0 {
		return 0, 0, fmt.Errorf("ratelimit: invalid rate %q: the window must be a positive duration, e.g. 1m", s)
	}
	if window/time.Duration(limit) == 0 {
		return 0, 0, fmt.Errorf("ratelimit: invalid rate %q: too many requests for the window", s)
	}
	return limit, window, nil
}

// ParseRule parses "[METHOD ]PATH=N/WINDOW", e.g. "POST /login=5/1m" or
// "/api/*=100/1m".
func ParseRule(s string) (Rule, error) {
	i := strings.LastIndex(s, "=")
	if i < 0 {
		return Rule{}, fmt.Errorf("ratelimit: invalid rule %q: want [METHOD ]PATH=N/WINDOW, e.g. POST /login=5/1m", s)
	}
	var r Rule
	var err error
	if r.Limit, r.Window, err = ParseRate(s[i+1:]); err != nil {
		return Rule{}, err
	}
	target := strings.Fields(s[:i])
	switch len(target) {
	case 1:
		r.Path = target[0]
	case 2:
		r.Method, r.Path = strings.ToUpper(target[0]), target[1]
		if !isToken(r.Method) {
			return Rule{}, fmt.Errorf("ratelimit: invalid rule %q: invalid method %q", s, target[0])
		}
	default:
		return Rule{}, fmt.Errorf("ratelimit: invalid rule %q: want [METHOD ]PATH=N/WINDOW", s)
	}
	if !strings.HasPrefix(r.Path, "/") {
		return Rule{}, fmt.Errorf("ratelimit: invalid rule %q: the path must start with \"/\"", s)
	}
	prefix, wildcard := strings.CutSuffix(r.Path, "*")
	if strings.Contains(prefix, "*") {
		return Rule{}, fmt.Errorf("ratelimit: invalid rule %q: \"*\" is only allowed at the end of the path", s)
	}
	if wildcard {
		r.Path = CleanPath(prefix)
		// Keep a trailing slash: "/api/*" must not match "/apikeys".
		if strings.HasSuffix(prefix, "/") && r.Path != "/" {
			r.Path += "/"
		}
		r.Path += "*"
	} else {
		r.Path = CleanPath(r.Path)
	}
	return r, nil
}

func isToken(s string) bool {
	for _, c := range s {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return s != ""
}

// String returns the rule in the syntax of ParseRule, or just the rate for
// a rule that matches every request.
func (r Rule) String() string {
	rate := strconv.Itoa(r.Limit) + "/" + formatWindow(r.Window)
	target := strings.TrimSpace(r.Method + " " + r.Path)
	if target == "" {
		return rate
	}
	return target + "=" + rate
}

// formatWindow formats a duration without the zero units that
// time.Duration.String adds, e.g. "1m" instead of "1m0s".
func formatWindow(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func (r Rule) matches(method, cleanPath string) bool {
	if r.Method != "" && r.Method != method {
		return false
	}
	if p, ok := strings.CutSuffix(r.Path, "*"); ok {
		// "/api/*" also matches "/api" itself.
		return strings.HasPrefix(cleanPath, p) || cleanPath+"/" == p
	}
	return r.Path == "" || r.Path == cleanPath
}

// interval is the time in which the allowance refills by one request.
func (r Rule) interval() int64 { return int64(r.Window) / int64(r.Limit) }

// CleanPath normalizes a URL path the way rules are matched: lower case,
// backslashes as slashes, without path parameters (";jsessionid=…"), dot
// segments, duplicate and trailing slashes. Backends that accept such
// variants of a path would otherwise let clients get around a rule.
func CleanPath(p string) string {
	p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	if strings.Contains(p, ";") {
		segs := strings.Split(p, "/")
		for i, s := range segs {
			segs[i], _, _ = strings.Cut(s, ";")
		}
		p = strings.Join(segs, "/")
	}
	return path.Clean("/" + p)
}

// ParsePrefixes parses a comma-separated list of IP addresses and CIDR
// prefixes.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.Contains(f, "/") {
			p, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, fmt.Errorf("ratelimit: invalid address %q: %w", f, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("ratelimit: invalid address %q: %w", f, err)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

// Config configures a Limiter.
type Config struct {
	// Rules are applied to every request that they match; a request is
	// rejected if any of them is exceeded. Each rule counts separately.
	Rules []Rule
	// Exempt clients are never limited, e.g. monitoring or office
	// networks.
	Exempt []netip.Prefix
	// MaxClients limits the memory used: when more clients are tracked,
	// some are forgotten, which resets their allowance. Zero means
	// DefaultMaxClients.
	MaxClients int
	// Logger is the operational log. Nil uses slog.Default().
	Logger *slog.Logger
}

// Limiter applies rate limit rules. It is safe for concurrent use.
type Limiter struct {
	rules  []Rule
	exempt []netip.Prefix
	logger *slog.Logger
	seed   maphash.Seed
	shards [numShards]shard
	now    func() time.Time // for tests

	warnMu   sync.Mutex
	warnedAt time.Time
}

type shard struct {
	mu        sync.Mutex
	clients   map[netip.Prefix]*client
	max       int
	lastSweep int64
}

// client is the state of one client, with an entry for each rule.
type client struct {
	rules []ruleState
}

type ruleState struct {
	// tat is the theoretical arrival time of the next request in Unix
	// nanoseconds: the allowance is used up while it is more than
	// Window - interval ahead of now.
	tat int64
	// eventID identifies the audit event of the current excess, from the
	// first rejected request until a request is allowed again.
	eventID string
}

// New returns a Limiter.
func New(cfg Config) (*Limiter, error) {
	if len(cfg.Rules) == 0 {
		return nil, errors.New("ratelimit: no rules")
	}
	for _, r := range cfg.Rules {
		if r.Limit < 1 || r.Window <= 0 || r.interval() == 0 {
			return nil, fmt.Errorf("ratelimit: invalid rule %q", r)
		}
	}
	if cfg.MaxClients < 0 {
		return nil, errors.New("ratelimit: the maximum number of clients must not be negative")
	}
	maxClients := cfg.MaxClients
	if maxClients == 0 {
		maxClients = DefaultMaxClients
	}
	l := &Limiter{
		rules:  cfg.Rules,
		exempt: cfg.Exempt,
		logger: cfg.Logger,
		seed:   maphash.MakeSeed(),
		now:    time.Now,
	}
	if l.logger == nil {
		l.logger = slog.Default()
	}
	for i := range l.shards {
		l.shards[i].clients = map[netip.Prefix]*client{}
		l.shards[i].max = max(1, (maxClients+numShards-1)/numShards)
	}
	return l, nil
}

// Rules returns the rules of the limiter.
func (l *Limiter) Rules() []Rule { return l.rules }

// Decision is the result of Allow.
type Decision struct {
	// Allowed is false if a rule is exceeded.
	Allowed bool
	// The other fields describe the exceeded rule.
	Rule Rule
	// Client is the address or, for IPv6, the /64 network that the
	// requests were counted for.
	Client netip.Prefix
	// RetryAfter is when the client may send the next request.
	RetryAfter time.Duration
	// EventID identifies the audit event of this excess. All requests
	// rejected until the client is allowed again share it.
	EventID string
	// First reports whether this is the first rejected request of the
	// excess, which should be logged.
	First bool
}

// Allow counts a request from the client with the given IP address and
// reports whether it is within the limits.
func (l *Limiter) Allow(r *http.Request, clientIP string) Decision {
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		// Not an IP address, e.g. a Unix socket: all such clients share
		// the zero key.
		addr = netip.Addr{}
	}
	addr = addr.Unmap()
	for _, p := range l.exempt {
		if p.Contains(addr) {
			return Decision{Allowed: true}
		}
	}
	var matched [8]int
	idx := matched[:0]
	cleanPath := CleanPath(r.URL.Path)
	for i, rule := range l.rules {
		if rule.matches(r.Method, cleanPath) {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return Decision{Allowed: true}
	}
	key := clientKey(addr)
	now := l.now().UnixNano()

	sh := &l.shards[maphash.Comparable(l.seed, key)%numShards]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if now-sh.lastSweep >= int64(sweepInterval) {
		l.sweep(sh, now)
	}
	c := sh.clients[key]
	if c == nil {
		if len(sh.clients) >= sh.max {
			l.makeRoom(sh, now)
		}
		c = &client{rules: make([]ruleState, len(l.rules))}
		sh.clients[key] = c
	}

	// Check every rule before counting the request for any of them, so a
	// rejected request does not use up the allowance of the others.
	denied := -1
	var retry int64
	for _, i := range idx {
		rule, st := l.rules[i], &c.rules[i]
		tat := max(st.tat, now)
		if wait := tat - now - (int64(rule.Window) - rule.interval()); wait > 0 && wait > retry {
			denied, retry = i, wait
		}
	}
	if denied < 0 {
		for _, i := range idx {
			st := &c.rules[i]
			st.tat = max(st.tat, now) + l.rules[i].interval()
			st.eventID = ""
		}
		return Decision{Allowed: true}
	}
	st := &c.rules[denied]
	d := Decision{Rule: l.rules[denied], Client: key, RetryAfter: time.Duration(retry)}
	if st.eventID == "" {
		st.eventID = audit.NewID()
		d.First = true
	}
	d.EventID = st.eventID
	return d
}

// clientKey returns the address, or the network of an IPv6 address, that
// requests are counted for.
func clientKey(a netip.Addr) netip.Prefix {
	if a.Is6() {
		p, _ := a.Prefix(IPv6Prefix)
		return p
	}
	return netip.PrefixFrom(a, a.BitLen())
}

// sweep removes the clients whose allowance has refilled for every rule.
func (l *Limiter) sweep(sh *shard, now int64) {
	sh.lastSweep = now
	for k, c := range sh.clients {
		if c.idle(now) {
			delete(sh.clients, k)
		}
	}
}

func (c *client) idle(now int64) bool {
	for _, st := range c.rules {
		if st.tat > now {
			return false
		}
	}
	return true
}

// makeRoom makes room for a new client in a full shard: first by removing
// idle clients, then by forgetting an arbitrary one.
func (l *Limiter) makeRoom(sh *shard, now int64) {
	// A full sweep for every new client would be slow; sweep at most once
	// a second.
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
	l.warnFull()
}

// warnFull logs that clients are being forgotten, at most once a minute.
func (l *Limiter) warnFull() {
	l.warnMu.Lock()
	defer l.warnMu.Unlock()
	now := l.now()
	if now.Sub(l.warnedAt) < time.Minute {
		return
	}
	l.warnedAt = now
	l.logger.Warn("rate limiter is tracking its maximum number of clients; forgetting some, which resets their limits",
		"hint", "raise -rate-limit-max-clients if this happens without an attack")
}

// Len returns the number of clients tracked.
func (l *Limiter) Len() int {
	n := 0
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		n += len(sh.clients)
		sh.mu.Unlock()
	}
	return n
}
