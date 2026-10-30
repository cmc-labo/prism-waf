package waf

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cmc-labo/prism-waf/internal/audit"
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
	Inspector *Inspector
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
// match a signature, and requests whose body exceeds the inspection limit,
// are recorded in the audit log. In ModeBlock they are then rejected with
// 403 Forbidden and 413 Request Entity Too Large respectively; in ModeDetect
// they are forwarded to next unchanged.
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

// logEvent writes an audit event for a detected request and returns its ID.
// The event's action is "block" or, in ModeDetect, "detect".
func logEvent(cfg Config, logger *slog.Logger, r *http.Request, reason string, m *Match) string {
	action := "block"
	if cfg.Mode == ModeDetect {
		action = "detect"
	}
	e := &audit.Event{
		Time:       time.Now().UTC(),
		ID:         audit.NewID(),
		ClientIP:   cfg.TrustedProxies.ClientIP(r),
		RemoteAddr: r.RemoteAddr,
		Action:     action,
		Reason:     reason,
		Request:    requestSummary(r, m),
	}
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
	if cfg.Audit != nil {
		if err := cfg.Audit.Log(e); err != nil {
			logger.Error("failed to write audit event", "event_id", e.ID, "error", err)
		}
	}
	return e.ID
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
