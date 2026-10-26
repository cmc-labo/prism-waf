package waf

import (
	"errors"
	"log/slog"
	"net/http"
)

// Middleware inspects each request before passing it to next. Requests that
// match a signature are rejected with 403 Forbidden, and requests whose body
// exceeds the inspection limit with 413 Request Entity Too Large.
func Middleware(next http.Handler, in *Inspector, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m, err := in.Inspect(r)
		if err != nil {
			if errors.Is(err, ErrBodyTooLarge) {
				logger.Warn("request blocked",
					"reason", "body too large",
					"remote_addr", r.RemoteAddr,
					"method", r.Method,
					"path", r.URL.Path,
				)
				http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
				return
			}
			logger.Error("failed to inspect request", "remote_addr", r.RemoteAddr, "error", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if m != nil {
			logger.Warn("request blocked",
				"signature", m.Signature.ID,
				"category", m.Signature.Category,
				"location", m.Location,
				"field", m.Field,
				"remote_addr", r.RemoteAddr,
				"method", r.Method,
				"path", r.URL.Path,
			)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
