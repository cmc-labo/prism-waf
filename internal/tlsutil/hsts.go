package tlsutil

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

// minPreloadMaxAge is the shortest max-age accepted by the HSTS preload list
// (https://hstspreload.org).
const minPreloadMaxAge = 365 * 24 * time.Hour

// HSTSPolicy is an HTTP Strict Transport Security policy (RFC 6797), which
// tells browsers to use only HTTPS for the site.
type HSTSPolicy struct {
	MaxAge            time.Duration
	IncludeSubdomains bool
	Preload           bool
}

// Validate reports whether the policy can be sent. Preload requires the
// settings demanded by the browsers' preload list.
func (p HSTSPolicy) Validate() error {
	if p.MaxAge < 0 {
		return errors.New("tlsutil: HSTS max-age must not be negative")
	}
	if p.Preload && (p.MaxAge < minPreloadMaxAge || !p.IncludeSubdomains) {
		return errors.New("tlsutil: HSTS preload requires a max-age of at least one year (8760h) and includeSubDomains")
	}
	return nil
}

// Header returns the value of the Strict-Transport-Security header.
func (p HSTSPolicy) Header() string {
	v := "max-age=" + strconv.FormatInt(int64(p.MaxAge/time.Second), 10)
	if p.IncludeSubdomains {
		v += "; includeSubDomains"
	}
	if p.Preload {
		v += "; preload"
	}
	return v
}

// HSTS adds the policy's Strict-Transport-Security header to every response
// sent over HTTPS, replacing one set by the backend. Browsers ignore the
// header over plain HTTP, so it is not sent there.
func HSTS(next http.Handler, p HSTSPolicy) http.Handler {
	value := p.Header()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			w = &hstsWriter{ResponseWriter: w, value: value}
		}
		next.ServeHTTP(w, r)
	})
}

// hstsWriter sets the header just before the response headers are written,
// so that it overrides the header copied from the backend response.
type hstsWriter struct {
	http.ResponseWriter
	value string
	wrote bool
}

func (w *hstsWriter) WriteHeader(code int) {
	// 1xx responses are followed by the final response.
	if !w.wrote && code >= 200 {
		w.wrote = true
		w.Header().Set("Strict-Transport-Security", w.value)
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *hstsWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer, e.g. to
// flush streamed backend responses.
func (w *hstsWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
