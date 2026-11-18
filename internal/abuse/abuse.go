// Package abuse protects business flows from attacks whose requests are
// each valid, so that signatures cannot detect them:
//
//   - Guessing secrets through a flow, such as passwords at a login form,
//     one-time codes, coupon or gift card codes: failure limits count the
//     attempts of each client that fail (by the response status) and
//     reject the client's requests to the flow once it fails too often,
//     while successful requests are not limited.
//   - Harvesting records by enumerating their IDs, such as
//     /api/orders/1, /api/orders/2, …, which also finds the records of
//     other users if the application does not check who owns them
//     (broken object level authorization): enumeration limits count the
//     distinct IDs that each client requests and reject requests for new
//     ones over the limit, while the IDs already requested stay available.
//
// Clients are counted by IP address (the /64 network for IPv6) like the
// rate limits.
package abuse

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/cmc-labo/prism-waf/internal/ratelimit"
)

// Reasons of Decision, which are also the reasons of audit events.
const (
	ReasonFailureLimit = "failure_limit"
	ReasonEnumeration  = "enumeration"
)

// Config configures a Guard.
type Config struct {
	Failures     []FailureRule
	Enumerations []EnumerationRule
	// Exempt clients are never limited.
	Exempt []netip.Prefix
	// MaxClients limits the clients tracked at once by each failure rule
	// and by the enumeration rules together. Zero means
	// ratelimit.DefaultMaxClients.
	MaxClients int
	// Logger is the operational log. Nil uses slog.Default().
	Logger *slog.Logger
}

// Guard applies failure and enumeration limits. It is safe for concurrent
// use.
type Guard struct {
	failures []FailureRule
	// limiters count the failures of each rule.
	limiters []*ratelimit.Limiter
	enum     *enumerationLimiter
}

// New returns a Guard.
func New(cfg Config) (*Guard, error) {
	if len(cfg.Failures) == 0 && len(cfg.Enumerations) == 0 {
		return nil, errors.New("abuse: no rules")
	}
	if cfg.MaxClients < 0 {
		return nil, errors.New("abuse: the maximum number of clients must not be negative")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	g := &Guard{failures: cfg.Failures}
	for _, fr := range cfg.Failures {
		if len(fr.Statuses) == 0 {
			return nil, fmt.Errorf("abuse: failure rule %q has no statuses", fr.Rule)
		}
		l, err := ratelimit.New(ratelimit.Config{
			Rules:      []ratelimit.Rule{fr.Rule},
			Exempt:     cfg.Exempt,
			MaxClients: cfg.MaxClients,
			Logger:     cfg.Logger,
		})
		if err != nil {
			return nil, fmt.Errorf("abuse: %w", err)
		}
		g.limiters = append(g.limiters, l)
	}
	if len(cfg.Enumerations) > 0 {
		var err error
		if g.enum, err = newEnumerationLimiter(cfg); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// Decision is the result of Check.
type Decision struct {
	// Allowed is false if a limit is exceeded.
	Allowed bool
	// The other fields describe the exceeded limit.
	// Reason is ReasonFailureLimit or ReasonEnumeration.
	Reason string
	// Rule is the exceeded rule in the syntax it is parsed from.
	Rule string
	// Client is the address or, for IPv6, the /64 network that was
	// counted.
	Client netip.Prefix
	// RetryAfter is when the client may try again.
	RetryAfter time.Duration
	// EventID identifies the audit event of this excess, which all
	// requests rejected until the client is allowed again share.
	EventID string
	// First reports whether this is the first rejected request of the
	// excess, which should be logged.
	First bool
}

// Check reports whether a client may send a request, before it is
// forwarded. A request for an ID that is within the enumeration limits is
// counted; failures are counted by Record once the request is answered.
func (g *Guard) Check(r *http.Request, clientIP string) Decision {
	for i, l := range g.limiters {
		if d := l.Check(r, clientIP); !d.Allowed {
			return Decision{
				Reason: ReasonFailureLimit, Rule: g.failures[i].String(), Client: d.Client,
				RetryAfter: d.RetryAfter, EventID: d.EventID, First: d.First,
			}
		}
	}
	if g.enum != nil {
		return g.enum.allow(r, clientIP)
	}
	return Decision{Allowed: true}
}

// CountsFailures reports whether a failure rule applies to a request, so
// that its response status must be passed to Record.
func (g *Guard) CountsFailures(r *http.Request) bool {
	for _, fr := range g.failures {
		if fr.Matches(r) {
			return true
		}
	}
	return false
}

// Record counts a request as a failed attempt for the failure rules that
// apply to it and its response status.
func (g *Guard) Record(r *http.Request, clientIP string, status int) {
	for i, fr := range g.failures {
		if fr.Fails(status) {
			g.limiters[i].Count(r, clientIP)
		}
	}
}
