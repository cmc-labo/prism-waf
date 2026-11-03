package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// namedBackend starts a backend that answers with its name and the request
// body.
func namedBackend(t *testing.T, name string) *url.URL {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		io.WriteString(w, name+":"+string(b))
	}))
	t.Cleanup(s.Close)
	u, _ := url.Parse(s.URL)
	return u
}

// deadBackend returns the URL of a port that refuses connections.
func deadBackend(t *testing.T) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return &url.URL{Scheme: "http", Host: addr}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mustProxy(t *testing.T, cfg Config) *Proxy {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = quietLogger()
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// send serves a request and returns the status and body.
func send(p http.Handler, r *http.Request) (int, string) {
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, r)
	return rec.Code, rec.Body.String()
}

// rewindable returns a POST request whose body can be sent again, as the
// WAF middleware prepares it.
func rewindable(body string) *http.Request {
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(body)), nil }
	return r
}

func TestRoundRobin(t *testing.T) {
	p := mustProxy(t, Config{Backends: []*url.URL{namedBackend(t, "a"), namedBackend(t, "b"), namedBackend(t, "c")}})
	var got []string
	for range 6 {
		code, body := send(p, httptest.NewRequest("GET", "/", nil))
		if code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		got = append(got, strings.TrimSuffix(body, ":"))
	}
	if strings.Join(got, "") != "abcabc" {
		t.Errorf("backends in order %q, want abcabc", got)
	}
}

func TestLeastConn(t *testing.T) {
	release := make(chan struct{})
	slowStarted := make(chan struct{}, 1)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slowStarted <- struct{}{}
		<-release
		io.WriteString(w, "slow")
	}))
	defer slow.Close()
	defer close(release)
	slowURL, _ := url.Parse(slow.URL)
	p := mustProxy(t, Config{Backends: []*url.URL{slowURL, namedBackend(t, "fast")}, Policy: LeastConn})

	// The first request occupies the slow backend.
	go send(p, httptest.NewRequest("GET", "/", nil))
	<-slowStarted
	// Round-robin would now alternate; least-conn sends everything to the
	// idle backend.
	for range 4 {
		if _, body := send(p, httptest.NewRequest("GET", "/", nil)); body != "fast:" {
			t.Fatalf("got %q, want the idle backend", body)
		}
	}
}

func TestLeastConnTiesTakeTurns(t *testing.T) {
	p := mustProxy(t, Config{Backends: []*url.URL{namedBackend(t, "a"), namedBackend(t, "b")}, Policy: LeastConn})
	_, first := send(p, httptest.NewRequest("GET", "/", nil))
	_, second := send(p, httptest.NewRequest("GET", "/", nil))
	if first == second {
		t.Errorf("idle backends did not take turns: %q, %q", first, second)
	}
}

// countingTransport counts the requests sent to each host.
type countingTransport struct {
	mu    sync.Mutex
	count map[string]int
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	if c.count == nil {
		c.count = map[string]int{}
	}
	c.count[r.URL.Host]++
	c.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

func (c *countingTransport) get(host string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count[host]
}

func TestRetryOnUnreachableBackend(t *testing.T) {
	dead := deadBackend(t)
	tr := &countingTransport{}
	p := mustProxy(t, Config{Backends: []*url.URL{dead, namedBackend(t, "live")}, Transport: tr, FailTimeout: time.Hour})

	// The request, including its body, reaches the live backend.
	if code, body := send(p, rewindable("payload")); code != http.StatusOK || body != "live:payload" {
		t.Fatalf("got %d %q, want the live backend with the body", code, body)
	}
	// The dead backend is now skipped instead of being tried again.
	for range 4 {
		if code, _ := send(p, httptest.NewRequest("GET", "/", nil)); code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
	}
	if n := tr.get(dead.Host); n != 1 {
		t.Errorf("dead backend tried %d times, want 1", n)
	}
}

func TestUnreachableBackendIsRetriedAfterFailTimeout(t *testing.T) {
	dead := deadBackend(t)
	tr := &countingTransport{}
	p := mustProxy(t, Config{Backends: []*url.URL{dead, namedBackend(t, "live")}, Transport: tr, FailTimeout: 50 * time.Millisecond})
	send(p, httptest.NewRequest("GET", "/", nil))
	time.Sleep(100 * time.Millisecond)
	send(p, httptest.NewRequest("GET", "/", nil)) // live (round-robin)
	send(p, httptest.NewRequest("GET", "/", nil)) // dead again
	if n := tr.get(dead.Host); n != 2 {
		t.Errorf("dead backend tried %d times, want 2", n)
	}
}

func TestNoRetryWithoutRewindableBody(t *testing.T) {
	p := mustProxy(t, Config{Backends: []*url.URL{deadBackend(t), namedBackend(t, "live")}})
	// A streamed body (no GetBody) may have been partly consumed, so it is
	// not sent again.
	r := httptest.NewRequest("POST", "/", io.NopCloser(bytes.NewReader([]byte("payload"))))
	if code, _ := send(p, r); code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", code)
	}
}

func TestAllBackendsUnreachable(t *testing.T) {
	tr := &countingTransport{}
	a, b := deadBackend(t), deadBackend(t)
	p := mustProxy(t, Config{Backends: []*url.URL{a, b}, Transport: tr})
	for range 2 {
		if code, _ := send(p, httptest.NewRequest("GET", "/", nil)); code != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", code)
		}
	}
	// Even when all are marked down, each request tries each backend once.
	if tr.get(a.Host) != 2 || tr.get(b.Host) != 2 {
		t.Errorf("attempts = %d, %d, want 2 each", tr.get(a.Host), tr.get(b.Host))
	}
}

// An error after the backend received the request is not retried, because
// the request may have had an effect.
func TestNoRetryAfterRequestWasSent(t *testing.T) {
	var hits atomic.Int32
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close() // no response
	}))
	defer broken.Close()
	brokenURL, _ := url.Parse(broken.URL)
	p := mustProxy(t, Config{Backends: []*url.URL{brokenURL, namedBackend(t, "live")}})

	if code, _ := send(p, rewindable("charge")); code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", code)
	}
	if hits.Load() != 1 {
		t.Errorf("broken backend hit %d times, want 1", hits.Load())
	}
	// The backend is not marked down: the next request goes to the live one
	// by round-robin, the one after to the broken one again.
	send(p, httptest.NewRequest("GET", "/", nil))
	send(p, httptest.NewRequest("GET", "/", nil))
	if hits.Load() != 2 {
		t.Errorf("broken backend hit %d times, want 2", hits.Load())
	}
}

func TestHealthCheck(t *testing.T) {
	var healthy atomic.Bool
	var served atomic.Int32
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			if !healthy.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			return
		}
		served.Add(1)
	}))
	defer flaky.Close()
	flakyURL, _ := url.Parse(flaky.URL + "/app") // the check ignores the backend's path
	p := mustProxy(t, Config{Backends: []*url.URL{flakyURL, namedBackend(t, "live")}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.HealthCheck(ctx, "/healthz", 10*time.Millisecond, time.Second)
	waitFor(t, func() bool { return p.backends[0].unhealthy.Load() })

	for range 4 {
		if _, body := send(p, httptest.NewRequest("GET", "/", nil)); body != "live:" {
			t.Fatalf("got %q, want the healthy backend", body)
		}
	}
	if served.Load() != 0 {
		t.Errorf("unhealthy backend served %d requests", served.Load())
	}

	healthy.Store(true)
	waitFor(t, func() bool { return !p.backends[0].unhealthy.Load() })
	send(p, httptest.NewRequest("GET", "/", nil))
	send(p, httptest.NewRequest("GET", "/", nil))
	if served.Load() != 1 {
		t.Errorf("recovered backend served %d of 2 requests, want 1", served.Load())
	}
}

func TestHealthCheckEndsFailTimeout(t *testing.T) {
	p := mustProxy(t, Config{Backends: []*url.URL{namedBackend(t, "a")}, FailTimeout: time.Hour})
	p.backends[0].downUntil.Store(time.Now().Add(time.Hour).UnixNano())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.HealthCheck(ctx, "/", time.Hour, time.Second)
	waitFor(t, func() bool { return p.backends[0].available(time.Now()) })
}

func TestAllBackendsUnhealthyAreStillTried(t *testing.T) {
	p := mustProxy(t, Config{Backends: []*url.URL{namedBackend(t, "a")}})
	p.backends[0].unhealthy.Store(true)
	if code, body := send(p, httptest.NewRequest("GET", "/", nil)); code != http.StatusOK || body != "a:" {
		t.Errorf("got %d %q, want the only backend despite its health state", code, body)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestNewValidates(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1")
	for _, cfg := range []Config{
		{},
		{Backends: []*url.URL{{Path: "/x"}}},
		{Backends: []*url.URL{u}, Policy: "random"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}

func TestParsePolicy(t *testing.T) {
	for _, s := range []string{"round-robin", "least-conn"} {
		if p, err := ParsePolicy(s); err != nil || string(p) != s {
			t.Errorf("ParsePolicy(%q) = %q, %v", s, p, err)
		}
	}
	if _, err := ParsePolicy("random"); err == nil {
		t.Error("invalid policy accepted")
	}
}
