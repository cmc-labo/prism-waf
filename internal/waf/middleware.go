package waf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/bot"
	"github.com/cmc-labo/prism-waf/internal/crs"
	"github.com/cmc-labo/prism-waf/internal/geo"
	"github.com/cmc-labo/prism-waf/internal/graphql"
	"github.com/cmc-labo/prism-waf/internal/grpc"
	"github.com/cmc-labo/prism-waf/internal/openapi"
	"github.com/cmc-labo/prism-waf/internal/ratelimit"
)

// Limits on how much request data is copied into an audit event, so that a
// large attack payload cannot flood the log.
const (
	maxLoggedValue  = 4096
	maxLoggedData   = 1024
	maxLoggedURI    = 4096
	maxLoggedHeader = 1024
)

// sensitiveHeaders are masked in audit events, unless the attack itself was
// found in them, because they carry credentials of legitimate users.
var sensitiveHeaders = map[string]bool{
	"Authorization":       true,
	"Proxy-Authorization": true,
	"Cookie":              true,
	"X-Api-Key":           true,
	"X-Auth-Token":        true,
	"X-Csrf-Token":        true,
}

// Mode controls what happens to requests that are detected as attacks.
type Mode string

const (
	// ModeBlock rejects detected requests. It is the default.
	ModeBlock Mode = "block"
	// ModeDetect only records detected requests in the audit log and
	// forwards them to the backend. Use it to check a new deployment or new
	// signatures for false positives before enabling blocking.
	ModeDetect Mode = "detect"
)

// ParseMode parses "block" or "detect".
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case ModeBlock, ModeDetect:
		return m, nil
	}
	return "", fmt.Errorf("waf: invalid mode %q: must be %q or %q", s, ModeBlock, ModeDetect)
}

// Config configures Middleware.
type Config struct {
	// Inspector applies the built-in signatures and reads the request body
	// within its size limit. To use only the CRS, give it no signatures.
	Inspector *Inspector
	// CRS, if set, inspects requests that the built-in signatures let
	// through with the OWASP Core Rule Set.
	CRS *crs.Engine
	// OpenAPI, if set, rejects requests under the base paths of an
	// OpenAPI document that do not match it.
	OpenAPI *openapi.Validator
	// GraphQL, if set, parses the queries of requests to GraphQL
	// endpoints, rejects those over its limits and inspects their
	// arguments.
	GraphQL *graphql.Guard
	// GRPC checks the methods of gRPC calls. Nil blocks the server
	// reflection service and allows every other method.
	GRPC *grpc.Guard
	// Geo, if set, looks up the country of each client first, passes it
	// to the backend in geo.CountryHeader and in audit events, and blocks
	// clients from countries that are not allowed.
	Geo *geo.Filter
	// RateLimiter, if set, limits the request rate of each client before
	// requests are inspected.
	RateLimiter *ratelimit.Limiter
	// Bot, if set, scores how likely each request comes from a bot,
	// passes the score to the backend in bot.ScoreHeader and challenges
	// or blocks clients that look automated, after rate limiting and
	// before inspection.
	Bot *bot.Guard
	// Mode is ModeBlock or ModeDetect. The zero value means ModeBlock.
	Mode Mode
	// Audit receives an event for every blocked request. Nil disables audit
	// logging.
	Audit *audit.Logger
	// TrustedProxies are allowed to report the client address in
	// X-Forwarded-For.
	TrustedProxies TrustedProxies
	// Logger is the operational log. Nil uses slog.Default().
	Logger *slog.Logger
}

// Middleware inspects each request before passing it to next. Requests that
// match a signature or the CRS, requests whose body exceeds the inspection
// limit, requests over a rate limit, requests from countries that are not
// allowed and API requests that API protection rejects are recorded in the
// audit log. In ModeBlock they are then rejected with 403 Forbidden (or the
// status a CRS rule asks for, such as 400 for an unparsable body), 413
// Request Entity Too Large, 429 Too Many Requests, 403 Forbidden and 403
// Forbidden respectively; in ModeDetect they are forwarded to next
// unchanged. Likewise, clients that look like bots are challenged or
// blocked in ModeBlock and only logged in ModeDetect.
//
// gRPC and gRPC-Web calls are inspected message by message while they are
// forwarded (see serveGRPC), and rejected calls get a gRPC status.
func Middleware(next http.Handler, cfg Config) http.Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.GRPC == nil {
		cfg.GRPC = grpc.New(grpc.Config{})
	}
	detect := cfg.Mode == ModeDetect
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protocol, codec := grpc.ProtocolOf(r)
		block := func(code int, eventID string) { blockResponse(w, r, cfg, protocol, code, eventID) }

		// Countries come first: blocked clients should not count towards
		// rate limits or get challenges.
		if cfg.Geo != nil {
			d := cfg.Geo.Check(cfg.TrustedProxies.ClientIP(r))
			// A client must not set the country itself.
			r.Header.Del(geo.CountryHeader)
			if d.Country != "" {
				r.Header.Set(geo.CountryHeader, d.Country)
			}
			if !d.Allowed {
				if d.First {
					logGeoEvent(cfg, logger, r, d)
				}
				if !detect {
					block(http.StatusForbidden, d.EventID)
					return
				}
			}
		}

		// Rate limits come next: rejecting a flood is cheaper than
		// inspecting it.
		if cfg.RateLimiter != nil {
			d := cfg.RateLimiter.Allow(r, cfg.TrustedProxies.ClientIP(r))
			if !d.Allowed {
				if d.First {
					logRateLimitEvent(cfg, logger, r, d)
				}
				if !detect {
					w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(d.RetryAfter)))
					block(http.StatusTooManyRequests, d.EventID)
					return
				}
			}
		}

		if cfg.Bot != nil {
			clientIP, secure := cfg.TrustedProxies.ClientIP(r), cfg.TrustedProxies.IsHTTPS(r)
			if r.URL.Path == bot.VerifyPath {
				cfg.Bot.ServeVerify(w, r, clientIP, secure)
				return
			}
			d := cfg.Bot.Check(r, clientIP, secure)
			if d.First {
				logBotEvent(cfg, logger, r, d)
			}
			if !detect {
				switch {
				case d.Action == bot.Challenge && protocol == grpc.None:
					cfg.Bot.ServeChallenge(w, r, d)
					return
				case d.Action == bot.Challenge, d.Action == bot.Block:
					// A gRPC client cannot run a challenge.
					block(http.StatusForbidden, d.EventID)
					return
				}
			}
			// The backend can use the assessment, e.g. to hide content
			// from likely bots. A client must not set it itself.
			r.Header.Set(bot.ScoreHeader, strconv.Itoa(d.Score))
			r.Header.Set(bot.CategoryHeader, d.Category)
			r.Header.Set(bot.VerifiedHeader, strconv.FormatBool(d.Verified))
		}

		if protocol != grpc.None {
			serveGRPC(w, r, next, cfg, logger, protocol, codec)
			return
		}

		m, err := cfg.Inspector.Inspect(r)
		bodyRead := true
		switch {
		case errors.Is(err, ErrBodyTooLarge):
			bodyRead = false
			id := logEvent(cfg, logger, r, "body_too_large", nil)
			if !detect {
				block(http.StatusRequestEntityTooLarge, id)
				return
			}
		case err != nil:
			logger.Error("failed to inspect request", "remote_addr", r.RemoteAddr, "error", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		case m != nil:
			id := logEvent(cfg, logger, r, "signature", m)
			if !detect {
				block(http.StatusForbidden, id)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// API protection needs the body, which was not read if it was too
		// large (in ModeDetect).
		if bodyRead {
			if id := checkAPI(cfg, logger, r); id != "" && !detect {
				block(http.StatusForbidden, id)
				return
			}
		}

		if cfg.CRS != nil && !inspectCRS(cfg, logger, r, bufferedBody(r), block) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// inspectCRS inspects a request with the CRS and reports whether it may
// be forwarded; otherwise it has been answered.
func inspectCRS(cfg Config, logger *slog.Logger, r *http.Request, body []byte, block func(int, string)) bool {
	detect := cfg.Mode == ModeDetect
	id := audit.NewID()
	res, err := cfg.CRS.Inspect(r, body, cfg.TrustedProxies.ClientIP(r), id)
	switch {
	case err != nil:
		// Fail closed: an attack must not pass because of an engine
		// error.
		logger.Error("CRS inspection failed", "remote_addr", r.RemoteAddr, "event_id", id, "error", err)
		if !detect {
			block(http.StatusInternalServerError, id)
			return false
		}
	case res != nil:
		logCRSEvent(cfg, logger, r, id, res)
		if !detect {
			block(res.Status, id)
			return false
		}
	}
	return true
}

// checkAPI applies GraphQL protection and the OpenAPI document to a
// request whose body has been read. It returns the ID of the audit event
// of a rejected request, or "".
func checkAPI(cfg Config, logger *slog.Logger, r *http.Request) string {
	if cfg.GraphQL == nil && cfg.OpenAPI == nil {
		return ""
	}
	body := bufferedBody(r)
	if cfg.GraphQL != nil && cfg.GraphQL.Handles(r.URL.Path) {
		v, values := cfg.GraphQL.Check(r, body)
		if v != nil {
			return logAPIEvent(cfg, logger, r, &audit.API{
				Protocol: "graphql", Violation: v.Kind, Operation: v.Operation,
				Limit: v.Limit, Value: v.Value, Message: v.Message,
			})
		}
		// Each argument on its own, like the values of a JSON body.
		for _, val := range values {
			if m := cfg.Inspector.InspectValue(LocationGraphQL, val.Path, val.Value); m != nil {
				return logEvent(cfg, logger, r, "signature", m)
			}
		}
	}
	if cfg.OpenAPI != nil {
		if v := cfg.OpenAPI.Check(r, body); v != nil {
			return logAPIEvent(cfg, logger, r, &audit.API{
				Protocol: "openapi", Violation: v.Kind, Operation: v.Operation, Message: v.Message,
			})
		}
	}
	return ""
}

// blockResponse writes an error response that includes the event ID, so a
// user who is blocked by mistake can report it. Rule details are not
// disclosed to the client. gRPC calls get a gRPC status, and requests to
// GraphQL endpoints a GraphQL error, so that their clients can show it.
func blockResponse(w http.ResponseWriter, r *http.Request, cfg Config, protocol grpc.Protocol, code int, eventID string) {
	switch {
	case protocol != grpc.None:
		grpc.WriteError(w, protocol, grpc.StatusFromHTTP(code), http.StatusText(code)+"; event ID: "+eventID)
	case cfg.GraphQL != nil && cfg.GraphQL.Handles(r.URL.Path):
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(graphqlResponse{Errors: []graphqlError{{
			Message:    http.StatusText(code) + "; event ID: " + eventID,
			Extensions: graphqlExtensions{Code: strings.ToUpper(strings.ReplaceAll(http.StatusText(code), " ", "_")), EventID: eventID},
		}}})
	default:
		http.Error(w, http.StatusText(code)+"\nEvent ID: "+eventID, code)
	}
}

type graphqlResponse struct {
	Errors []graphqlError `json:"errors"`
}

type graphqlError struct {
	Message    string            `json:"message"`
	Extensions graphqlExtensions `json:"extensions"`
}

type graphqlExtensions struct {
	Code    string `json:"code"`
	EventID string `json:"eventId"`
}

// bufferedBody returns the request body that the Inspector buffered, or
// nil if there is none, e.g. because it was too large in ModeDetect.
func bufferedBody(r *http.Request) []byte {
	if r.GetBody == nil {
		return nil
	}
	rc, err := r.GetBody()
	if err != nil {
		return nil
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	return b
}

// logCRSEvent writes an audit event for a request the CRS detected.
func logCRSEvent(cfg Config, logger *slog.Logger, r *http.Request, id string, res *crs.Result) {
	e := newEvent(cfg, r, id, "crs", nil)
	detail := &audit.CRS{AnomalyScore: res.AnomalyScore, DecidingRule: res.RuleID, Rules: []audit.CRSRule{}}
	for _, rm := range res.Matches {
		if rm.ID == res.RuleID && rm.Severity == "" {
			continue // the deciding evaluation rule
		}
		value, _ := audit.Truncate(rm.Value, maxLoggedData)
		detail.Rules = append(detail.Rules, audit.CRSRule{
			ID: rm.ID, Message: rm.Message, Severity: rm.Severity, Variable: rm.Variable, Value: value,
		})
	}
	e.CRS = detail
	if a := res.Attack(); a != nil {
		e.Rule = &audit.Rule{ID: strconv.Itoa(a.ID), Category: crsCategory(a.Tags)}
		location, field, _ := strings.Cut(a.Variable, ":")
		value, truncated := audit.Truncate(a.Value, maxLoggedValue)
		data, _ := audit.Truncate(a.Data, maxLoggedData)
		e.Match = &audit.Match{
			Location:       location,
			Field:          field,
			Data:           data,
			Value:          value,
			ValueLength:    len(a.Value),
			ValueTruncated: truncated,
		}
	}
	writeEvent(cfg, logger, e)
}

// logRateLimitEvent writes an audit event for the first request of a
// client over a rate limit.
func logRateLimitEvent(cfg Config, logger *slog.Logger, r *http.Request, d ratelimit.Decision) {
	e := newEvent(cfg, r, d.EventID, "rate_limit", nil)
	e.RateLimit = &audit.RateLimit{
		Rule:       d.Rule.String(),
		Client:     d.Client.String(),
		RetryAfter: retryAfterSeconds(d.RetryAfter),
	}
	writeEvent(cfg, logger, e)
}

// logBotEvent writes an audit event for the first challenged or blocked
// request of a client in a minute.
func logBotEvent(cfg Config, logger *slog.Logger, r *http.Request, d bot.Decision) {
	e := newEvent(cfg, r, d.EventID, "bot", nil)
	if cfg.Mode != ModeDetect {
		e.Action = d.Action.String()
	}
	e.Bot = &audit.Bot{
		Score:    d.Score,
		Signals:  d.Signals,
		Category: d.Category,
		Name:     d.BotName,
		Verified: d.Verified,
		Client:   d.Client.String(),
	}
	if d.Action == bot.Challenge {
		e.Bot.Challenge = "pow"
		if d.Captcha {
			e.Bot.Challenge = "captcha"
		}
	}
	writeEvent(cfg, logger, e)
}

// logAPIEvent writes an audit event for a request that API protection
// rejected and returns its ID.
func logAPIEvent(cfg Config, logger *slog.Logger, r *http.Request, a *audit.API) string {
	e := newEvent(cfg, r, audit.NewID(), "api", nil)
	a.Message, _ = audit.Truncate(a.Message, maxLoggedData)
	e.API = a
	writeEvent(cfg, logger, e)
	return e.ID
}

// logGeoEvent writes an audit event for the first blocked request of a
// client in a minute.
func logGeoEvent(cfg Config, logger *slog.Logger, r *http.Request, d geo.Decision) {
	e := newEvent(cfg, r, d.EventID, "geo", nil)
	e.Geo = &audit.Geo{List: d.List, Client: d.Client.String()}
	writeEvent(cfg, logger, e)
}

// retryAfterSeconds rounds a wait up to whole seconds for Retry-After.
func retryAfterSeconds(d time.Duration) int {
	return max(1, int((d+time.Second-1)/time.Second))
}

// crsCategory derives a category such as "sqli" from a CRS rule's
// "attack-sqli" tag.
func crsCategory(tags []string) string {
	for _, t := range tags {
		if c, ok := strings.CutPrefix(t, "attack-"); ok {
			return c
		}
	}
	return "crs"
}

// logEvent writes an audit event for a detected request and returns its ID.
func logEvent(cfg Config, logger *slog.Logger, r *http.Request, reason string, m *Match) string {
	e := newEvent(cfg, r, audit.NewID(), reason, m)
	if m != nil {
		value, truncated := audit.Truncate(m.Value, maxLoggedValue)
		data, _ := audit.Truncate(m.Data, maxLoggedData)
		e.Rule = &audit.Rule{ID: m.Signature.ID, Category: m.Signature.Category}
		e.Match = &audit.Match{
			Location:       string(m.Location),
			Field:          m.Field,
			Base64:         m.Base64,
			Data:           data,
			Value:          value,
			ValueLength:    len(m.Value),
			ValueTruncated: truncated,
		}
	}
	writeEvent(cfg, logger, e)
	return e.ID
}

// newEvent returns an audit event for a detected request. Its action is
// "block" or, in ModeDetect, "detect".
func newEvent(cfg Config, r *http.Request, id, reason string, m *Match) *audit.Event {
	action := "block"
	if cfg.Mode == ModeDetect {
		action = "detect"
	}
	e := &audit.Event{
		Time:       time.Now().UTC(),
		ID:         id,
		ClientIP:   cfg.TrustedProxies.ClientIP(r),
		RemoteAddr: r.RemoteAddr,
		Action:     action,
		Reason:     reason,
		Request:    requestSummary(r, m),
	}
	if cfg.Geo != nil {
		// Set by Middleware, not by the client.
		e.Country = r.Header.Get(geo.CountryHeader)
	}
	return e
}

func writeEvent(cfg Config, logger *slog.Logger, e *audit.Event) {
	if cfg.Audit == nil {
		return
	}
	if err := cfg.Audit.Log(e); err != nil {
		logger.Error("failed to write audit event", "event_id", e.ID, "error", err)
	}
}

func requestSummary(r *http.Request, m *Match) audit.Request {
	uri, _ := audit.Truncate(r.RequestURI, maxLoggedURI)
	headers := make(map[string]string, len(r.Header))
	for name, values := range r.Header {
		v := strings.Join(values, ", ")
		if sensitiveHeaders[name] && !(m != nil && m.Location == LocationHeader && m.Field == name) {
			v = "[REDACTED]"
		}
		headers[name], _ = audit.Truncate(v, maxLoggedHeader)
	}
	return audit.Request{
		Method:        r.Method,
		URI:           uri,
		Proto:         r.Proto,
		Host:          r.Host,
		ContentLength: r.ContentLength,
		Headers:       headers,
	}
}
