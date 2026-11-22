// Package prismwaf embeds PrismWAF in a Go program as net/http middleware,
// instead of running it as a reverse proxy in front of the program.
//
//	w, err := prismwaf.New(prismwaf.Options{RateLimit: "300/1m"})
//	if err != nil {
//		log.Fatal(err)
//	}
//	http.ListenAndServe(":8080", w.Middleware(mux))
//
// Requests are inspected with the built-in signatures, the OWASP Core Rule
// Set or both, and optionally rate limited per client, exactly as the
// prismwaf command does; blocked requests get the same responses and
// audit events. The other protections of the command, such as bot
// protection or API validation, are not available yet.
package prismwaf

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/crs"
	"github.com/cmc-labo/prism-waf/internal/ratelimit"
	"github.com/cmc-labo/prism-waf/internal/waf"
)

// Engine selects the rules that requests are inspected with.
type Engine string

const (
	// EngineBuiltin uses PrismWAF's own signatures. It is the default.
	EngineBuiltin Engine = "builtin"
	// EngineCRS uses the OWASP Core Rule Set v4.
	EngineCRS Engine = "crs"
	// EngineBoth uses the built-in signatures, then the CRS.
	EngineBoth Engine = "both"
)

// Mode controls what happens to requests that are detected as attacks.
type Mode string

const (
	// ModeBlock rejects detected requests. It is the default.
	ModeBlock Mode = "block"
	// ModeDetect only records them in the audit log and passes them on.
	ModeDetect Mode = "detect"
)

// DefaultMaxBodySize is the default of Options.MaxBodySize: 128 KiB.
const DefaultMaxBodySize = waf.DefaultMaxBodySize

// Options configures New. The zero value inspects requests with the
// built-in signatures, blocks attacks and writes audit events to standard
// output.
type Options struct {
	// Engine is EngineBuiltin, EngineCRS or EngineBoth. Empty means
	// EngineBuiltin.
	Engine Engine
	// CRSParanoiaLevel (1-4) and CRSAnomalyThreshold configure the CRS, as
	// -crs-paranoia-level and -crs-anomaly-threshold do. Zero means the
	// defaults, 1 and 5.
	CRSParanoiaLevel    int
	CRSAnomalyThreshold int
	// Mode is ModeBlock or ModeDetect. Empty means ModeBlock.
	Mode Mode
	// MaxBodySize is the largest request body in bytes that is inspected;
	// larger requests are rejected with 413. Zero means
	// DefaultMaxBodySize.
	MaxBodySize int64
	// RateLimit is the maximum request rate per client as N/WINDOW, e.g.
	// "300/1m"; excess requests get 429. Empty disables it.
	RateLimit string
	// RateLimitPaths are limits for single paths, e.g. "POST /login=5/1m",
	// as with -rate-limit-path.
	RateLimitPaths []string
	// RateLimitExempt are IPs or CIDRs of clients that are never rate
	// limited.
	RateLimitExempt []string
	// TrustedProxies are IPs or CIDRs of proxies in front of the program
	// whose X-Forwarded-For header is trusted for the client address.
	TrustedProxies []string
	// AuditLog receives an audit event for every blocked or detected
	// request, as JSON Lines. Nil means os.Stdout; use io.Discard to turn
	// audit logging off.
	AuditLog io.Writer
	// Logger is the operational log, e.g. for a full rate limiter. Nil
	// uses slog.Default().
	Logger *slog.Logger
}

// WAF inspects requests. It is safe for concurrent use; create one and use
// it for all handlers, so that they share rate limits.
type WAF struct {
	cfg waf.Config
}

// New returns a WAF configured with opts.
func New(opts Options) (*WAF, error) {
	cfg := waf.Config{Logger: opts.Logger}
	switch opts.Engine {
	case "", EngineBuiltin, EngineCRS, EngineBoth:
	default:
		return nil, fmt.Errorf("prismwaf: invalid engine %q: must be %q, %q or %q", opts.Engine, EngineBuiltin, EngineCRS, EngineBoth)
	}
	if opts.MaxBodySize < 0 {
		return nil, errors.New("prismwaf: the maximum body size must not be negative")
	}
	maxBody := opts.MaxBodySize
	if maxBody == 0 {
		maxBody = DefaultMaxBodySize
	}
	var signatures []waf.Signature
	if opts.Engine != EngineCRS {
		signatures = waf.DefaultSignatures
	}
	var err error
	if cfg.Inspector, err = waf.NewInspector(signatures, maxBody); err != nil {
		return nil, fmt.Errorf("prismwaf: %w", err)
	}
	if opts.Engine == EngineCRS || opts.Engine == EngineBoth {
		if cfg.CRS, err = crs.New(crs.Config{
			ParanoiaLevel:    opts.CRSParanoiaLevel,
			InboundThreshold: opts.CRSAnomalyThreshold,
			MaxBodySize:      maxBody,
		}); err != nil {
			return nil, fmt.Errorf("prismwaf: %w", err)
		}
	} else if opts.CRSParanoiaLevel != 0 || opts.CRSAnomalyThreshold != 0 {
		return nil, errors.New("prismwaf: the CRS options require EngineCRS or EngineBoth")
	}
	mode := ModeBlock
	if opts.Mode != "" {
		mode = opts.Mode
	}
	if cfg.Mode, err = waf.ParseMode(string(mode)); err != nil {
		return nil, fmt.Errorf("prismwaf: invalid mode %q: must be %q or %q", opts.Mode, ModeBlock, ModeDetect)
	}
	if cfg.TrustedProxies, err = waf.ParseTrustedProxies(strings.Join(opts.TrustedProxies, ",")); err != nil {
		return nil, fmt.Errorf("prismwaf: invalid trusted proxies: %w", err)
	}
	if cfg.RateLimiter, err = newLimiter(opts); err != nil {
		return nil, err
	}
	w := opts.AuditLog
	if w == nil {
		w = os.Stdout
	}
	cfg.Audit = audit.New(w)
	return &WAF{cfg: cfg}, nil
}

// newLimiter returns the rate limiter of opts, or nil without rate limits.
func newLimiter(opts Options) (*ratelimit.Limiter, error) {
	var rules []ratelimit.Rule
	if opts.RateLimit != "" {
		limit, window, err := ratelimit.ParseRate(opts.RateLimit)
		if err != nil {
			return nil, fmt.Errorf("prismwaf: invalid rate limit: %w", err)
		}
		rules = append(rules, ratelimit.Rule{Limit: limit, Window: window})
	}
	for _, v := range opts.RateLimitPaths {
		r, err := ratelimit.ParseRule(v)
		if err != nil {
			return nil, fmt.Errorf("prismwaf: invalid rate limit path: %w", err)
		}
		rules = append(rules, r)
	}
	exempt, err := ratelimit.ParsePrefixes(strings.Join(opts.RateLimitExempt, ","))
	if err != nil {
		return nil, fmt.Errorf("prismwaf: invalid rate limit exemption: %w", err)
	}
	if len(rules) == 0 {
		if len(exempt) > 0 {
			return nil, errors.New("prismwaf: RateLimitExempt requires RateLimit or RateLimitPaths")
		}
		return nil, nil
	}
	l, err := ratelimit.New(ratelimit.Config{Rules: rules, Exempt: exempt, Logger: opts.Logger})
	if err != nil {
		return nil, fmt.Errorf("prismwaf: %w", err)
	}
	return l, nil
}

// Middleware returns a handler that inspects each request and passes it on
// to next unless it is blocked. Its signature fits the middleware chains
// of most routers, e.g. chi's Use.
func (w *WAF) Middleware(next http.Handler) http.Handler {
	return waf.Middleware(next, w.cfg)
}
