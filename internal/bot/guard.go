package bot

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/bits"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/ratelimit"
)

// Defaults of Config.
const (
	DefaultChallengeScore = 50
	DefaultDifficulty     = 18
	DefaultClearanceTTL   = 24 * time.Hour
	// MinSecretLength is the minimum length of Config.Secret in bytes.
	MinSecretLength = 32
	// MaxDifficulty limits the work, which doubles with every bit.
	MaxDifficulty = 30
)

// VerifyPath receives the solutions of challenges. It is handled by
// PrismWAF and never forwarded to the backend.
const VerifyPath = "/.prismwaf/challenge"

// CookieName is the name of the clearance cookie.
const CookieName = "prismwaf_clearance"

// Headers that pass the assessment of each request to the backend. Values
// sent by the client are replaced.
const (
	// ScoreHeader is the bot score, e.g. "60".
	ScoreHeader = "X-Prismwaf-Bot-Score"
	// CategoryHeader is the category, e.g. "search_engine".
	CategoryHeader = "X-Prismwaf-Bot-Category"
	// VerifiedHeader is "true" for a bot verified with DNS, else "false".
	VerifiedHeader = "X-Prismwaf-Bot-Verified"
)

// DefaultExemptPaths are never challenged: crawlers must be able to read
// robots.txt, and /.well-known/ holds files for machines, such as
// security.txt and ACME HTTP-01 challenges.
var DefaultExemptPaths = []string{"/robots.txt", "/favicon.ico", "/.well-known/*"}

// challengeTTL is how long a challenge can be solved.
const challengeTTL = 10 * time.Minute

// eventInterval is how long the audit event of a client's challenge or
// block is reused before a new one is logged, so a scraper does not flood
// the audit log.
const eventInterval = time.Minute

// maxEvents limits the memory of remembered audit events.
const maxEvents = 100_000

// Config configures a Guard.
type Config struct {
	// ChallengeScore is the bot score from which clients must solve a
	// challenge. Zero means DefaultChallengeScore.
	ChallengeScore int
	// BlockScore is the bot score from which requests are rejected
	// without a challenge. Zero disables blocking.
	BlockScore int
	// Difficulty is the number of leading zero bits that the SHA-256 hash
	// of a solution needs. A browser needs about 2^Difficulty hashes on
	// average. Zero means DefaultDifficulty.
	Difficulty int
	// ClearanceTTL is how long a solved challenge is valid. Zero means
	// DefaultClearanceTTL.
	ClearanceTTL time.Duration
	// Secret signs challenges and clearance cookies. Instances that share
	// clients must share it. Nil generates a random secret, which
	// invalidates all cookies when PrismWAF restarts.
	Secret []byte
	// Paths restricts the protection to these paths, in the syntax of
	// rate limit rules ("/search", "/articles/*"). Empty protects all
	// paths.
	Paths []string
	// ExemptPaths are never protected, in addition to DefaultExemptPaths.
	ExemptPaths []string
	// Exempt clients are never challenged or blocked.
	Exempt []netip.Prefix

	// VerifyBots checks with DNS that clients whose User-Agent names a
	// verifiable bot, such as Googlebot, really are that bot. Verified
	// bots are let through; impersonators get SignalFakeBot.
	VerifyBots bool
	// Resolver does the lookups of VerifyBots. Nil uses the system's.
	Resolver Resolver
	// AllowCategories are let through without a challenge, e.g.
	// CategorySocial for link previews. User-Agents can be faked, so a
	// category lets anyone through who claims to belong to it.
	AllowCategories []string
	// BlockCategories are rejected, e.g. CategoryAICrawler. They are
	// blocked even if verified.
	BlockCategories []string

	// Captcha, if set, is shown instead of the proof-of-work challenge to
	// clients whose score reaches CaptchaScore.
	Captcha *CaptchaConfig
	// CaptchaScore is the bot score from which the CAPTCHA is shown. Zero
	// means ChallengeScore: every challenge is a CAPTCHA.
	CaptchaScore int
	// Logger is the operational log, for problems with the CAPTCHA
	// provider. Nil uses slog.Default().
	Logger *slog.Logger
}

// Guard decides which requests must solve a challenge and serves the
// challenge. It is safe for concurrent use.
type Guard struct {
	challengeScore int
	blockScore     int
	difficulty     int
	ttl            time.Duration
	secret         []byte
	paths          []pathPattern
	exemptPaths    []pathPattern
	exempt         []netip.Prefix
	verifier       *verifier // nil unless bots are verified
	allowCategory  map[string]bool
	blockCategory  map[string]bool
	captcha        *captcha // nil without a CAPTCHA
	captchaScore   int
	logger         *slog.Logger
	now            func() time.Time // for tests

	mu     sync.Mutex
	events map[eventKey]event
}

type eventKey struct {
	client netip.Prefix
	action Action
}

type event struct {
	id      string
	expires time.Time
}

// New returns a Guard.
func New(cfg Config) (*Guard, error) {
	g := &Guard{
		challengeScore: cfg.ChallengeScore,
		blockScore:     cfg.BlockScore,
		difficulty:     cfg.Difficulty,
		ttl:            cfg.ClearanceTTL,
		secret:         cfg.Secret,
		exempt:         cfg.Exempt,
		now:            time.Now,
		events:         map[eventKey]event{},
		allowCategory:  map[string]bool{},
		blockCategory:  map[string]bool{},
		logger:         cfg.Logger,
	}
	if g.logger == nil {
		g.logger = slog.Default()
	}
	if g.challengeScore == 0 {
		g.challengeScore = DefaultChallengeScore
	}
	if g.difficulty == 0 {
		g.difficulty = DefaultDifficulty
	}
	if g.ttl == 0 {
		g.ttl = DefaultClearanceTTL
	}
	switch {
	case g.challengeScore < 1 || g.challengeScore > 100:
		return nil, errors.New("bot: the challenge score must be between 1 and 100")
	case g.blockScore < 0 || g.blockScore > 100:
		return nil, errors.New("bot: the block score must be between 1 and 100, or 0 to disable blocking")
	case g.difficulty < 1 || g.difficulty > MaxDifficulty:
		return nil, fmt.Errorf("bot: the difficulty must be between 1 and %d", MaxDifficulty)
	case g.ttl < time.Minute:
		return nil, errors.New("bot: the clearance lifetime must be at least 1m")
	}
	if g.secret == nil {
		g.secret = make([]byte, MinSecretLength)
		rand.Read(g.secret)
	} else if len(g.secret) < MinSecretLength {
		return nil, fmt.Errorf("bot: the secret must be at least %d bytes", MinSecretLength)
	}
	for _, c := range cfg.AllowCategories {
		if !isCategory(c) {
			return nil, fmt.Errorf("bot: unknown category %q", c)
		}
		g.allowCategory[c] = true
	}
	for _, c := range cfg.BlockCategories {
		if !isCategory(c) {
			return nil, fmt.Errorf("bot: unknown category %q", c)
		}
		if g.allowCategory[c] {
			return nil, fmt.Errorf("bot: category %q is both allowed and blocked", c)
		}
		g.blockCategory[c] = true
	}
	if cfg.VerifyBots {
		g.verifier = newVerifier(cfg.Resolver, func() time.Time { return g.now() })
	}
	if cfg.Captcha != nil {
		c, err := newCaptcha(cfg.Captcha)
		if err != nil {
			return nil, err
		}
		g.captcha = c
		g.captchaScore = cfg.CaptchaScore
		if g.captchaScore == 0 {
			g.captchaScore = g.challengeScore
		}
		if g.captchaScore < g.challengeScore || g.captchaScore > 100 {
			return nil, errors.New("bot: the CAPTCHA score must be between the challenge score and 100")
		}
	} else if cfg.CaptchaScore != 0 {
		return nil, errors.New("bot: a CAPTCHA score requires a CAPTCHA")
	}
	var err error
	if g.paths, err = parsePaths(cfg.Paths); err != nil {
		return nil, err
	}
	if g.exemptPaths, err = parsePaths(append(DefaultExemptPaths[:len(DefaultExemptPaths):len(DefaultExemptPaths)], cfg.ExemptPaths...)); err != nil {
		return nil, err
	}
	return g, nil
}

// ChallengeScore returns the score from which clients are challenged.
func (g *Guard) ChallengeScore() int { return g.challengeScore }

// BlockScore returns the score from which requests are blocked, or 0.
func (g *Guard) BlockScore() int { return g.blockScore }

// Difficulty returns the difficulty of challenges.
func (g *Guard) Difficulty() int { return g.difficulty }

// CaptchaScore returns the score from which a CAPTCHA is shown, or 0
// without a CAPTCHA.
func (g *Guard) CaptchaScore() int { return g.captchaScore }

// pathPattern is a path, or with a trailing "*" a path prefix, matched
// like the paths of rate limit rules.
type pathPattern string

// parsePaths validates and normalizes paths with the parser of rate limit
// rules, so that both accept and match the same paths.
func parsePaths(paths []string) ([]pathPattern, error) {
	var out []pathPattern
	for _, p := range paths {
		r, err := ratelimit.ParseRule(p + "=1/1s")
		if err != nil || r.Method != "" {
			return nil, fmt.Errorf("bot: invalid path %q: want a path such as /search or /articles/*", p)
		}
		out = append(out, pathPattern(r.Path))
	}
	return out, nil
}

func (p pathPattern) matches(cleanPath string) bool {
	if prefix, ok := strings.CutSuffix(string(p), "*"); ok {
		return strings.HasPrefix(cleanPath, prefix) || cleanPath+"/" == prefix
	}
	return string(p) == cleanPath
}

func matchAny(patterns []pathPattern, cleanPath string) bool {
	for _, p := range patterns {
		if p.matches(cleanPath) {
			return true
		}
	}
	return false
}

// Action is what to do with a request.
type Action int

const (
	// Allow forwards the request.
	Allow Action = iota
	// Challenge asks the client to solve a challenge first.
	Challenge
	// Block rejects the request.
	Block
)

func (a Action) String() string {
	switch a {
	case Challenge:
		return "challenge"
	case Block:
		return "block"
	}
	return "allow"
}

// Decision is the result of Check.
type Decision struct {
	Action Action
	Assessment
	// Cleared reports whether the client has a valid clearance cookie.
	Cleared bool
	// Captcha reports whether a challenge is a CAPTCHA rather than a
	// proof of work.
	Captcha bool
	// Client is the address, or the /64 network of an IPv6 address, that
	// clearance is bound to.
	Client netip.Prefix
	// EventID identifies the audit event of a challenge or block. A client
	// gets the same ID for a minute.
	EventID string
	// First reports whether the event is new and should be logged.
	First bool
}

// Check scores r and decides what to do with it. clientIP is the address
// of the client; secure reports whether the client connected with HTTPS.
func (g *Guard) Check(r *http.Request, clientIP string, secure bool) Decision {
	d := Decision{Assessment: Score(r, secure), Client: clientKey(clientIP)}
	if g.verifier != nil && d.bot != nil && d.bot.Verifiable() {
		if g.verifier.verify(r.Context(), clientIP, d.bot) {
			d.Verified = true
		} else {
			d.add(SignalFakeBot)
		}
	}
	if !g.protects(r, d.Client) {
		return d
	}
	switch {
	case g.blockCategory[d.Category]:
		d.Action = Block
	case d.Verified || g.allowCategory[d.Category]:
		return d
	case g.blockScore > 0 && d.Score >= g.blockScore:
		d.Action = Block
	case d.Score >= g.challengeScore:
		need := levelPoW
		if g.captcha != nil && d.Score >= g.captchaScore {
			need = levelCaptcha
		}
		if g.validClearance(r, d.Client, need) {
			d.Cleared = true
			return d
		}
		d.Action, d.Captcha = Challenge, need == levelCaptcha
	default:
		return d
	}
	d.EventID, d.First = g.event(d.Client, d.Action)
	return d
}

func (g *Guard) protects(r *http.Request, client netip.Prefix) bool {
	for _, p := range g.exempt {
		if p.Contains(client.Addr()) {
			return false
		}
	}
	cleanPath := ratelimit.CleanPath(r.URL.Path)
	if matchAny(g.exemptPaths, cleanPath) {
		return false
	}
	return len(g.paths) == 0 || matchAny(g.paths, cleanPath)
}

// event returns the ID of the audit event for a client's challenge or
// block, and whether it is new.
func (g *Guard) event(client netip.Prefix, a Action) (id string, first bool) {
	now := g.now()
	k := eventKey{client, a}
	g.mu.Lock()
	defer g.mu.Unlock()
	if e, ok := g.events[k]; ok && now.Before(e.expires) {
		return e.id, false
	}
	if len(g.events) >= maxEvents {
		for k, e := range g.events {
			if !now.Before(e.expires) {
				delete(g.events, k)
			}
		}
	}
	id = audit.NewID()
	if len(g.events) < maxEvents {
		g.events[k] = event{id, now.Add(eventInterval)}
	}
	return id, true
}

// clientKey returns the address, or the /64 network of an IPv6 address,
// that clearance is bound to. A client that is not an IP address, such as
// a Unix socket, gets the zero prefix.
func clientKey(clientIP string) netip.Prefix {
	a, err := netip.ParseAddr(clientIP)
	if err != nil {
		return netip.Prefix{}
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(ratelimit.IPv6Prefix)
		return p
	}
	return netip.PrefixFrom(a, a.BitLen())
}

// mac signs fields for a client. The User-Agent is included so that a
// cookie solved in a browser cannot be reused by a script with another
// User-Agent from the same address.
func (g *Guard) mac(kind string, client netip.Prefix, ua string, fields ...string) string {
	h := hmac.New(sha256.New, g.secret)
	h.Write([]byte(kind))
	for _, f := range append(fields, client.String(), ua) {
		h.Write([]byte{0})
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// Levels of clearance: a solved CAPTCHA also clears clients that only
// need a proof of work, but not the other way round.
const (
	levelPoW     = "1"
	levelCaptcha = "2"
)

// validClearance reports whether r carries a clearance cookie of at least
// the level that is valid for its client.
func (g *Guard) validClearance(r *http.Request, client netip.Prefix, level string) bool {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return false
	}
	f := strings.Split(c.Value, ".")
	if len(f) != 3 || f[1] < level || (f[1] != levelPoW && f[1] != levelCaptcha) {
		return false
	}
	t, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil || g.now().Unix() >= t {
		return false
	}
	want := g.mac("clearance", client, r.UserAgent(), f[0], f[1])
	return hmac.Equal([]byte(f[2]), []byte(want))
}

// newChallenge returns a challenge for a client: a random seed that has to
// be completed with a nonce, and a token that proves the seed was issued
// by PrismWAF to that client.
func (g *Guard) newChallenge(client netip.Prefix, ua string) (token, seed string) {
	var b [16]byte
	rand.Read(b[:])
	seed = hex.EncodeToString(b[:])
	issued := strconv.FormatInt(g.now().Unix(), 10)
	diff := strconv.Itoa(g.difficulty)
	return issued + "." + diff + "." + seed + "." + g.mac("challenge", client, ua, issued, diff, seed), seed
}

// Errors of verify.
var (
	errInvalidToken = errors.New("invalid challenge")
	errExpired      = errors.New("expired challenge")
	errWrongNonce   = errors.New("wrong solution")
)

// verify checks the solution of a challenge.
func (g *Guard) verify(token, nonce string, client netip.Prefix, ua string) error {
	f := strings.Split(token, ".")
	if len(f) != 4 {
		return errInvalidToken
	}
	issued, diff, seed, mac := f[0], f[1], f[2], f[3]
	if !hmac.Equal([]byte(mac), []byte(g.mac("challenge", client, ua, issued, diff, seed))) {
		return errInvalidToken
	}
	t, err1 := strconv.ParseInt(issued, 10, 64)
	d, err2 := strconv.Atoi(diff)
	if err1 != nil || err2 != nil {
		return errInvalidToken
	}
	if age := g.now().Sub(time.Unix(t, 0)); age > challengeTTL || age < -time.Minute {
		return errExpired
	}
	if len(nonce) == 0 || len(nonce) > 20 || strings.Trim(nonce, "0123456789") != "" {
		return errWrongNonce
	}
	// A challenge issued before the difficulty was lowered is still valid.
	if leadingZeroBits(sha256.Sum256([]byte(seed+nonce))) < min(d, g.difficulty) {
		return errWrongNonce
	}
	return nil
}

func leadingZeroBits(h [32]byte) int {
	n := 0
	for _, b := range h {
		if b != 0 {
			return n + bits.LeadingZeros8(b)
		}
		n += 8
	}
	return n
}

// clearanceCookie returns a clearance cookie of a level for a client.
func (g *Guard) clearanceCookie(client netip.Prefix, ua, level string, secure bool) *http.Cookie {
	exp := strconv.FormatInt(g.now().Add(g.ttl).Unix(), 10)
	return &http.Cookie{
		Name:     CookieName,
		Value:    exp + "." + level + "." + g.mac("clearance", client, ua, exp, level),
		Path:     "/",
		MaxAge:   int(g.ttl / time.Second),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}
