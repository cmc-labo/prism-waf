// Package prismwaf embeds PrismWAF, a web application firewall, in a Go
// program as [net/http] middleware, instead of running it as a reverse
// proxy in front of the program.
//
// Create a [WAF] with [New] once and wrap the handlers to protect with
// [WAF.Middleware]:
//
//	w, err := prismwaf.New(prismwaf.Options{RateLimit: "300/1m"})
//	if err != nil {
//		log.Fatal(err)
//	}
//	http.ListenAndServe(":8080", w.Middleware(mux))
//
// Requests are inspected and rate limited exactly as the prismwaf command
// does; blocked requests get the same responses and audit events. The
// other protections of the command, such as bot protection, geo filtering
// or API validation, are not available in this package yet.
//
// # Inspection
//
// Options.Engine selects the rules: PrismWAF's built-in signatures
// ([EngineBuiltin], the default), the OWASP Core Rule Set v4 ([EngineCRS])
// or both ([EngineBoth]). The URL, headers and the request body up to
// Options.MaxBodySize are inspected; requests with a larger body are
// rejected.
//
// Options.Mode selects what happens to detected requests: [ModeBlock]
// rejects them, [ModeDetect] only records them in the audit log and passes
// them on, which is useful to check for false positives before blocking.
//
// # Rate limiting
//
// Options.RateLimit limits the requests of each client in total, and
// Options.RateLimitPaths the requests to single paths, such as a login
// form. Rate limits are checked before requests are inspected.
//
// # Responses
//
// In [ModeBlock], rejected requests are not passed on, and the client gets
//
//   - 403 Forbidden for a detected attack (or the status a CRS rule asks
//     for, such as 400 Bad Request for a body that cannot be parsed),
//   - 413 Request Entity Too Large for a body over Options.MaxBodySize,
//   - 429 Too Many Requests, with Retry-After, for a request over a rate
//     limit.
//
// The plain text body contains the status text and the ID of the audit
// event, e.g. "Forbidden\nEvent ID: ...", so that a user can report a false
// positive. gRPC calls get a gRPC status instead.
//
// # Audit log
//
// Every blocked or detected request is written to Options.AuditLog as
// one JSON object per line (JSON Lines), with the event ID, the client
// address, the reason (such as "signature", "crs", "body_too_large" or
// "rate_limit") and the details of the match. Sensitive headers such as
// Authorization and Cookie are masked.
//
// # Client address
//
// Rate limits and audit events use the address of the TCP peer as the
// client address. When the program runs behind a load balancer or
// reverse proxy, list it in Options.TrustedProxies, so that the client
// address is taken from its X-Forwarded-For header instead. The header is
// never trusted from other peers, since any client can set it.
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

// Engine selects the rules that requests are inspected with. See
// Options.Engine.
type Engine string

const (
	// EngineBuiltin uses PrismWAF's own signatures. It is the default.
	EngineBuiltin Engine = "builtin"
	// EngineCRS uses the OWASP Core Rule Set v4.
	EngineCRS Engine = "crs"
	// EngineBoth uses the built-in signatures, then the CRS for requests
	// that the signatures let through.
	EngineBoth Engine = "both"
)

// Mode controls what happens to requests that are detected as attacks.
// See Options.Mode.
type Mode string

const (
	// ModeBlock rejects detected requests. It is the default.
	ModeBlock Mode = "block"
	// ModeDetect only records them in the audit log and passes them on.
	// Use it to check a new deployment for false positives before
	// enabling blocking.
	ModeDetect Mode = "detect"
)

// DefaultMaxBodySize is the default of Options.MaxBodySize: 128 KiB, as for
// the prismwaf command.
const DefaultMaxBodySize = 128 << 10

// Options configures [New]. The zero value inspects requests with the
// built-in signatures, blocks attacks, does not rate limit and writes audit
// events to standard output.
type Options struct {
	// Engine is EngineBuiltin, EngineCRS or EngineBoth. Empty means
	// EngineBuiltin.
	Engine Engine
	// CRSParanoiaLevel is the CRS paranoia level, 1 to 4. Higher levels
	// enable more rules, which detect more attacks but also cause more
	// false positives. Zero means 1. It requires EngineCRS or EngineBoth.
	CRSParanoiaLevel int
	// CRSAnomalyThreshold is the inbound anomaly score at which the CRS
	// detects a request; each matching rule adds to the score. Zero means
	// 5. It requires EngineCRS or EngineBoth.
	CRSAnomalyThreshold int
	// Mode is ModeBlock or ModeDetect. Empty means ModeBlock.
	Mode Mode
	// MaxBodySize is the largest request body in bytes that is inspected;
	// larger requests are rejected with 413. Zero means
	// DefaultMaxBodySize.
	MaxBodySize int64
	// RateLimit is the maximum request rate per client as "N/WINDOW",
	// e.g. "300/1m" or "1000/h". WINDOW is a Go duration (see
	// [time.ParseDuration]); a bare unit means one of it. Excess requests
	// get 429 Too Many Requests. Empty disables it.
	RateLimit string
	// RateLimitPaths are additional limits per client for single paths as
	// "[METHOD ]PATH=N/WINDOW", e.g. "POST /login=5/1m" or
	// "/api/*=100/1m". A trailing "*" matches every path with that prefix.
	RateLimitPaths []string
	// RateLimitExempt are IP addresses or CIDR prefixes of clients that are
	// never rate limited, e.g. "10.0.0.0/8". It requires RateLimit or
	// RateLimitPaths.
	RateLimitExempt []string
	// TrustedProxies are IP addresses or CIDR prefixes of proxies in front
	// of the program whose X-Forwarded-For header is trusted to report the
	// client address. See "Client address" in the package documentation.
	TrustedProxies []string
	// AuditLog receives an audit event for every blocked or detected
	// request, as JSON Lines. Nil means os.Stdout; use io.Discard to turn
	// audit logging off.
	AuditLog io.Writer
	// Logger is the operational log, e.g. for a full rate limiter. Nil
	// uses [slog.Default].
	Logger *slog.Logger
}

// WAF inspects requests. Create it with [New] and wrap handlers with
// [WAF.Middleware].
//
// A WAF is safe for concurrent use. Create one and use it for all
// handlers, so that they share rate limits.
type WAF struct {
	cfg waf.Config
}

// New returns a WAF configured with opts. It returns an error if opts is
// invalid, e.g. an unknown [Engine] or [Mode], a malformed rate limit or
// address, or CRS options without the CRS engine.
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
// to next unless it is blocked. See "Responses" in the package
// documentation for what blocked requests get.
//
// Its signature fits the middleware chains of most routers, e.g. chi's
// Use. Handlers that should not be inspected, such as health checks, can
// be registered outside of it.
func (w *WAF) Middleware(next http.Handler) http.Handler {
	return waf.Middleware(next, w.cfg)
}
