package waf

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/ddos"
	"github.com/cmc-labo/prism-waf/internal/ratelimit"
)

func TestBan(t *testing.T) {
	limiter, _ := ratelimit.New(ratelimit.Config{Rules: []ratelimit.Rule{{Limit: 1, Window: time.Hour}}})
	bans, err := ddos.NewBans(ddos.BanConfig{Limit: 3, Window: time.Minute, Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	forwarded := 0
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded++ }), Config{
		Inspector: mustInspector(t, 0), RateLimiter: limiter, Bans: bans, Audit: audit.New(&buf),
	})
	do := func(target, ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", target, nil)
		r.RemoteAddr = ip + ":1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	// One request is allowed; two are rate limited and one is an attack:
	// three rejections.
	codes := []int{do("/", "192.0.2.1").Code, do("/", "192.0.2.1").Code, do("/", "192.0.2.1").Code}
	if fmt.Sprint(codes) != "[200 429 429]" {
		t.Fatalf("codes %v", codes)
	}
	// Errors of PrismWAF are not counted: none here. The attack is the
	// third rejection, after which the client is banned.
	if rec := do("/?q=<script>alert(1)</script>", "192.0.2.1"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attack: %d", rec.Code)
	}
	rec := do("/", "192.0.2.1")
	if rec.Code != http.StatusForbidden || rec.Header().Get("Connection") != "close" || rec.Header().Get("Retry-After") != "3600" {
		t.Fatalf("banned client: %d %v", rec.Code, rec.Header())
	}
	var ban *audit.Event
	n := 0
	for _, e := range decodeEvents(t, bytes.NewBuffer(buf.Bytes())) {
		if e.Reason == "ban" {
			ban = &e
			n++
		}
	}
	if n != 1 || ban.RateLimit == nil || *ban.RateLimit != (audit.RateLimit{Rule: "3/1m for 1h", Client: "192.0.2.1/32", RetryAfter: 3600}) ||
		!strings.Contains(rec.Body.String(), ban.ID) {
		t.Fatalf("%d ban events: %+v; body %q", n, ban, rec.Body)
	}
	before := buf.Len()
	do("/", "192.0.2.1")
	if buf.Len() != before {
		t.Error("requests during a ban logged")
	}
	if forwarded != 1 {
		t.Errorf("forwarded %d requests", forwarded)
	}
	if rec := do("/", "192.0.2.2"); rec.Code != http.StatusOK {
		t.Errorf("other client: %d", rec.Code)
	}
}

func TestBanNotInDetectMode(t *testing.T) {
	limiter, _ := ratelimit.New(ratelimit.Config{Rules: []ratelimit.Rule{{Limit: 1, Window: time.Hour}}})
	bans, _ := ddos.NewBans(ddos.BanConfig{Limit: 1, Window: time.Minute, Duration: time.Hour})
	cfg := Config{RateLimiter: limiter, Bans: bans, Mode: ModeDetect}
	for range 5 {
		if rec, _ := serveWithAudit(t, cfg, httptest.NewRequest("GET", "/", nil)); rec.Code != http.StatusOK {
			t.Fatalf("detect mode: %d", rec.Code)
		}
	}
}

func TestConcurrencyLimit(t *testing.T) {
	conc, _ := ddos.NewConcurrency(ddos.ConcurrencyConfig{Max: 3, MaxPerClient: 2})
	var buf bytes.Buffer
	var logs lockedBuffer
	started, finish := make(chan struct{}, 10), make(chan struct{})
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-finish
	}), Config{Inspector: mustInspector(t, 0), Concurrency: conc, Audit: audit.New(&buf), TrustedProxies: TrustedProxies{netip.MustParsePrefix("192.0.2.0/24")},
		Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	do := func(client string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("X-Forwarded-For", client)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	var wg sync.WaitGroup
	for _, client := range []string{"198.51.100.1", "198.51.100.1", "198.51.100.2"} {
		wg.Add(1)
		go func() { defer wg.Done(); do(client) }()
		<-started
	}
	// The client has 2 requests in progress.
	rec := do("198.51.100.1")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" {
		t.Errorf("client over its limit: %d", rec.Code)
	}
	// 3 requests are in progress in total.
	rec = do("198.51.100.3")
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" || strings.Contains(rec.Body.String(), "Event ID") {
		t.Errorf("overloaded: %d %q", rec.Code, rec.Body)
	}
	close(finish)
	wg.Wait()
	if rec := do("198.51.100.1"); rec.Code != http.StatusOK {
		t.Errorf("after the requests finished: %d", rec.Code)
	}
	events := decodeEvents(t, bytes.NewBuffer(buf.Bytes()))
	if len(events) != 1 || events[0].Reason != "concurrency" || events[0].RateLimit == nil ||
		*events[0].RateLimit != (audit.RateLimit{Rule: "2 in progress", Client: "198.51.100.1/32", RetryAfter: 1}) {
		t.Errorf("events %+v", events)
	}
	if !strings.Contains(logs.String(), "too many requests in progress") {
		t.Errorf("no overload warning: %q", logs.String())
	}
}

func TestSlowRequest(t *testing.T) {
	var buf bytes.Buffer
	forwarded := false
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = true }), Config{
		Inspector: mustInspector(t, 0), Audit: audit.New(&buf), Mode: ModeDetect,
		BodyTimeout: ddos.BodyTimeout{Timeout: 200 * time.Millisecond, MinRate: 1000},
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\nabc")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := io.ReadAll(c)
	if err != nil || !strings.HasPrefix(string(resp), "HTTP/1.1 408 ") || !strings.Contains(string(resp), "Connection: close") {
		t.Fatalf("response %q, %v", resp, err)
	}
	// Even in detection mode: the body cannot be forwarded.
	events := decodeEvents(t, bytes.NewBuffer(buf.Bytes()))
	if forwarded || len(events) != 1 || events[0].Reason != "slow_request" || events[0].Action != "block" ||
		!strings.Contains(string(resp), events[0].ID) {
		t.Errorf("forwarded %v, events %+v", forwarded, events)
	}
}

// lockedBuffer is a buffer for logs written by concurrent requests.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestConcurrencyLimitDetectMode(t *testing.T) {
	conc, _ := ddos.NewConcurrency(ddos.ConcurrencyConfig{Max: 1, MaxPerClient: 1})
	var logs lockedBuffer
	started, finish := make(chan struct{}, 10), make(chan struct{})
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			started <- struct{}{}
			<-finish
		}
	}), Config{Inspector: mustInspector(t, 0), Concurrency: conc, Mode: ModeDetect, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/slow", nil))
		close(done)
	}()
	<-started
	// Over both limits, but only logged.
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = ip + ":1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Errorf("detect mode, %s: %d", ip, rec.Code)
		}
	}
	close(finish)
	<-done
	if !strings.Contains(logs.String(), "detection mode, so not rejecting them") {
		t.Errorf("logs %q", logs.String())
	}
}
