// Package proxy implements the reverse proxy that forwards client requests
// to the protected backend servers, balancing the load between them.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// Policy selects the backend for each request.
type Policy string

const (
	// RoundRobin sends requests to the backends in turn. It is the default.
	RoundRobin Policy = "round-robin"
	// LeastConn sends each request to the backend with the fewest requests
	// in progress, which suits requests of very different durations.
	LeastConn Policy = "least-conn"
)

// ParsePolicy parses "round-robin" or "least-conn".
func ParsePolicy(s string) (Policy, error) {
	switch p := Policy(s); p {
	case RoundRobin, LeastConn:
		return p, nil
	}
	return "", fmt.Errorf("proxy: invalid load balancing policy %q: must be %q or %q", s, RoundRobin, LeastConn)
}

// DefaultFailTimeout is how long a backend that refused a connection is
// skipped by default.
const DefaultFailTimeout = 10 * time.Second

// Config configures New.
type Config struct {
	// Backends receive the requests. At least one is required.
	Backends []*url.URL
	// Transport sends the requests to the backends; nil uses
	// http.DefaultTransport.
	Transport http.RoundTripper
	// Policy is RoundRobin or LeastConn. The zero value means RoundRobin.
	Policy Policy
	// FailTimeout is how long a backend that cannot be connected to is
	// skipped. Zero means DefaultFailTimeout.
	FailTimeout time.Duration
	// Logger is the operational log. Nil uses slog.Default().
	Logger *slog.Logger
}

// Proxy forwards every request to one of its backends unchanged, except for
// the standard X-Forwarded-* headers.
//
// A backend that cannot be connected to is skipped for Config.FailTimeout,
// and the request is retried on another backend. This is safe for every
// method because the failed backend never received the request; it is only
// done if the request body can be sent again (see http.Request.GetBody).
// Backends that fail an active health check (see HealthCheck) are skipped
// too. If every backend is unavailable, they are all tried anyway, so a
// wrong health state cannot cause an outage on its own.
type Proxy struct {
	backends    []*backend
	transport   http.RoundTripper
	policy      Policy
	failTimeout time.Duration
	logger      *slog.Logger
	next        atomic.Uint64    // round-robin position
	now         func() time.Time // for tests
}

type backend struct {
	url    *url.URL
	rp     *httputil.ReverseProxy
	active atomic.Int64 // requests in progress
	// downUntil is the UnixNano time until which the backend is skipped
	// after a connection failure.
	downUntil atomic.Int64
	// unhealthy is set by a failed active health check.
	unhealthy atomic.Bool
}

func (b *backend) available(now time.Time) bool {
	return !b.unhealthy.Load() && now.UnixNano() >= b.downUntil.Load()
}

// attempt records the error of one attempt to forward a request. The
// ReverseProxy error handler stores it instead of answering the client, so
// that ServeHTTP can retry on another backend.
type attempt struct{ err error }

type attemptKey struct{}

// New returns a Proxy for the configured backends.
func New(cfg Config) (*Proxy, error) {
	if len(cfg.Backends) == 0 {
		return nil, errors.New("proxy: at least one backend is required")
	}
	if cfg.Policy == "" {
		cfg.Policy = RoundRobin
	}
	if _, err := ParsePolicy(string(cfg.Policy)); err != nil {
		return nil, err
	}
	if cfg.FailTimeout <= 0 {
		cfg.FailTimeout = DefaultFailTimeout
	}
	if cfg.Transport == nil {
		cfg.Transport = http.DefaultTransport
	}
	transport := grpcTransport(cfg.Transport)
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	p := &Proxy{
		transport:   cfg.Transport,
		policy:      cfg.Policy,
		failTimeout: cfg.FailTimeout,
		logger:      cfg.Logger,
		now:         time.Now,
	}
	for _, u := range cfg.Backends {
		if u == nil || u.Scheme == "" || u.Host == "" {
			return nil, errors.New("proxy: backend URL must include scheme and host")
		}
		p.backends = append(p.backends, &backend{
			url: u,
			rp: &httputil.ReverseProxy{
				Transport: transport,
				Rewrite: func(r *httputil.ProxyRequest) {
					r.SetURL(u)
					r.SetXForwarded()
					// Preserve the Host header sent by the client so that
					// virtual-host based backends keep working.
					r.Out.Host = r.In.Host
				},
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					r.Context().Value(attemptKey{}).(*attempt).err = err
				},
			},
		})
	}
	return p, nil
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tried := make([]bool, len(p.backends))
	for {
		i := p.pick(tried)
		if i < 0 {
			break
		}
		tried[i] = true
		b := p.backends[i]

		a := &attempt{}
		b.serve(w, r.WithContext(context.WithValue(r.Context(), attemptKey{}, a)))
		if a.err == nil {
			return
		}
		if r.Context().Err() != nil {
			// The client went away, or the request was aborted on purpose,
			// e.g. a gRPC stream that the WAF blocked: not the backend's
			// fault, and nobody to answer.
			return
		}
		if !isConnectError(a.err) {
			p.fail(w, r, b, a.err)
			return
		}
		b.downUntil.Store(p.now().Add(p.failTimeout).UnixNano())
		p.logger.Warn("backend unreachable; skipping it", "backend", b.url.String(), "for", p.failTimeout, "error", a.err)
		if !rewindBody(r) {
			p.fail(w, r, b, a.err)
			return
		}
	}
	p.logger.Error("all backends failed", "method", r.Method, "path", r.URL.Path)
	http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
}

// serve forwards a request to the backend. The ReverseProxy panics with
// http.ErrAbortHandler when the response cannot be copied to the end.
func (b *backend) serve(w http.ResponseWriter, r *http.Request) {
	b.active.Add(1)
	defer b.active.Add(-1)
	b.rp.ServeHTTP(w, r)
}

func (p *Proxy) fail(w http.ResponseWriter, r *http.Request, b *backend, err error) {
	p.logger.Error("backend request failed",
		"backend", b.url.String(),
		"method", r.Method,
		"path", r.URL.Path,
		"error", err,
	)
	http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
}

// pick returns the index of the next backend that has not been tried, or
// -1 if all have been. Available backends are preferred.
func (p *Proxy) pick(tried []bool) int {
	n := len(p.backends)
	start := int(p.next.Add(1)-1) % n
	now := p.now()
	best, fallback := -1, -1
	for k := range n {
		i := (start + k) % n
		if tried[i] {
			continue
		}
		if fallback < 0 {
			fallback = i
		}
		b := p.backends[i]
		if !b.available(now) {
			continue
		}
		if p.policy == RoundRobin {
			return i
		}
		// LeastConn; ties go to the first in round-robin order, so equally
		// loaded backends still take turns.
		if best < 0 || b.active.Load() < p.backends[best].active.Load() {
			best = i
		}
	}
	if best >= 0 {
		return best
	}
	return fallback
}

// isConnectError reports whether err means that no connection to the
// backend could be made, so the backend did not receive the request.
func isConnectError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

// rewindBody prepares the request body to be sent again and reports
// whether that is possible.
func rewindBody(r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	if r.GetBody == nil {
		return false
	}
	body, err := r.GetBody()
	if err != nil {
		return false
	}
	r.Body = body
	return true
}

// grpcTransport returns a transport that sends gRPC calls to http://
// backends over HTTP/2 without TLS (h2c), as gRPC requires HTTP/2, and
// other requests through base. Over https://, HTTP/2 is negotiated with
// TLS.
func grpcTransport(base http.RoundTripper) http.RoundTripper {
	t, ok := base.(*http.Transport)
	if !ok {
		return base
	}
	h2c := t.Clone()
	h2c.Protocols = new(http.Protocols)
	h2c.Protocols.SetUnencryptedHTTP2(true)
	return &splitTransport{base: base, h2c: h2c}
}

type splitTransport struct {
	base, h2c http.RoundTripper
}

func (t *splitTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme == "http" && isGRPC(r.Header.Get("Content-Type")) {
		return t.h2c.RoundTrip(r)
	}
	return t.base.RoundTrip(r)
}

// isGRPC reports whether a content type is gRPC's, which needs HTTP/2,
// e.g. "application/grpc+proto"; gRPC-Web also works over HTTP/1.1.
func isGRPC(contentType string) bool {
	mt, _, _ := mime.ParseMediaType(contentType)
	return mt == "application/grpc" || strings.HasPrefix(mt, "application/grpc+")
}

// HealthCheck sends GET requests for path to every backend, immediately and
// then every interval, until ctx is canceled. Backends that do not answer
// within the timeout, or answer with a status other than 2xx or 3xx, are
// skipped until a later check succeeds. A successful check also makes a
// backend skipped after a connection failure available again.
func (p *Proxy) HealthCheck(ctx context.Context, path string, interval, timeout time.Duration) {
	client := &http.Client{
		Transport: p.transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for _, b := range p.backends {
			p.check(ctx, client, b, path)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *Proxy) check(ctx context.Context, client *http.Client, b *backend, path string) {
	u := *b.url
	u.Path, u.RawPath, u.RawQuery = path, "", ""
	err := func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		return nil
	}()
	if ctx.Err() != nil {
		return
	}
	// Log only changes of the health state.
	if err != nil {
		if !b.unhealthy.Swap(true) {
			p.logger.Warn("backend health check failed", "backend", b.url.String(), "url", u.String(), "error", err)
		}
		return
	}
	// A successful check also ends the skip after a connection failure, so
	// a restarted backend is used again without waiting for FailTimeout.
	wasDown := b.downUntil.Swap(0) > p.now().UnixNano()
	if b.unhealthy.Swap(false) || wasDown {
		p.logger.Info("backend healthy again", "backend", b.url.String())
	}
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
