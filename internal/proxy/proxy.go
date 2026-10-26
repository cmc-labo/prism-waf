// Package proxy implements the reverse proxy that forwards client requests
// to the protected backend server.
package proxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// New returns an http.Handler that forwards every request to backend
// unchanged, except for the standard X-Forwarded-* headers.
func New(backend *url.URL, logger *slog.Logger) (http.Handler, error) {
	if backend == nil || backend.Scheme == "" || backend.Host == "" {
		return nil, errors.New("proxy: backend URL must include scheme and host")
	}
	if logger == nil {
		logger = slog.Default()
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(backend)
			r.SetXForwarded()
			// Preserve the Host header sent by the client so that
			// virtual-host based backends keep working.
			r.Out.Host = r.In.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("backend request failed",
				"method", r.Method,
				"path", r.URL.Path,
				"error", err,
			)
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		},
	}
	return rp, nil
}

// ParseBackend parses and validates a backend URL such as "http://127.0.0.1:8081".
func ParseBackend(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid backend URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("proxy: backend URL %q must use http or https", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy: backend URL %q has no host", raw)
	}
	return u, nil
}
