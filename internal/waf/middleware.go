package waf

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/crs"
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
// match a signature or the CRS, and requests whose body exceeds the
// inspection limit, are recorded in the audit log. In ModeBlock they are
// then rejected with 403 Forbidden (or the status a CRS rule asks for, such
// as 400 for an unparsable body) and 413 Request Entity Too Large
// respectively; in ModeDetect they are forwarded to next unchanged.
func Middleware(next http.Handler, cfg Config) http.Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	detect := cfg.Mode == ModeDetect
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m, err := cfg.Inspector.Inspect(r)
		switch {
		case errors.Is(err, ErrBodyTooLarge):
			id := logEvent(cfg, logger, r, "body_too_large", nil)
			if !detect {
				blockResponse(w, http.StatusRequestEntityTooLarge, id)
				return
			}
		case err != nil:
			logger.Error("failed to inspect request", "remote_addr", r.RemoteAddr, "error", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		case m != nil:
			id := logEvent(cfg, logger, r, "signature", m)
			if !detect {
				blockResponse(w, http.StatusForbidden, id)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if cfg.CRS != nil {
			id := audit.NewID()
			res, err := cfg.CRS.Inspect(r, bufferedBody(r), cfg.TrustedProxies.ClientIP(r), id)
			switch {
			case err != nil:
				// Fail closed: an attack must not pass because of an
				// engine error.
				logger.Error("CRS inspection failed", "remote_addr", r.RemoteAddr, "error", err)
				if !detect {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
			case res != nil:
				logCRSEvent(cfg, logger, r, id, res)
				if !detect {
					blockResponse(w, res.Status, id)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// blockResponse writes an error response that includes the event ID, so a
// user who is blocked by mistake can report it. Rule details are not
// disclosed to the client.
func blockResponse(w http.ResponseWriter, code int, eventID string) {
	http.Error(w, http.StatusText(code)+"\nEvent ID: "+eventID, code)
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
	return &audit.Event{
		Time:       time.Now().UTC(),
		ID:         id,
		ClientIP:   cfg.TrustedProxies.ClientIP(r),
		RemoteAddr: r.RemoteAddr,
		Action:     action,
		Reason:     reason,
		Request:    requestSummary(r, m),
	}
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
