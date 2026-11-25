package alert

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cmc-labo/prism-waf/internal/notify"
)

// recorder is a Notifier that records events.
type recorder struct {
	mu     sync.Mutex
	events []notify.Event
}

func (r *recorder) Notify(e notify.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// take returns the events recorded since the last call.
func (r *recorder) take() []notify.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.events
	r.events = nil
	return e
}

func names(events []notify.Event) string {
	var s []string
	for _, e := range events {
		s = append(s, e.Event+" "+e.Client)
	}
	return strings.Join(s, ",")
}

func newTestMonitor(t *testing.T, cfg Config) (*Monitor, *recorder, *time.Time, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	rec := &recorder{}
	cfg.Notifier = rec
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	// Windows start now, as if New had been called at that time.
	m.requests.tally.start, m.clients.tally.start, m.client.tally.start = now, now, now
	return m, rec, &now, &logs
}

func ip(s string) netip.Prefix {
	a := netip.MustParseAddr(s)
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p
	}
	return netip.PrefixFrom(a, 32)
}

func TestRequests(t *testing.T) {
	m, rec, now, logs := newTestMonitor(t, Config{Requests: Threshold{10, 5 * time.Minute}})
	for i := range 9 {
		m.RateLimited(ip("203.0.113.7"), "POST /login=5/1m")
		if i%3 == 0 {
			m.RateLimited(ip("198.51.100.4"), "300/1m")
		}
	}
	// 12 rejected requests; the 10th fired the alert.
	*now = now.Add(2 * time.Minute)
	m.RateLimited(ip("2001:db8::1"), "300/1m")
	got := rec.take()
	if names(got) != "rate_limited_requests " {
		t.Fatalf("events %s", names(got))
	}
	e := got[0]
	want := "Rate limits rejected 10 requests within less than a second (alert threshold: 10 per 5m0s). Top clients: 203.0.113.7 (7), 198.51.100.4 (3). Rules: POST /login=5/1m (7), 300/1m (3)."
	if e.Message != want || e.Severity != notify.SeverityWarning || e.Metric != MetricRequests || e.Count != 10 || e.Threshold != 10 || e.Window != "5m0s" || len(e.TopClients) != 2 {
		t.Errorf("event %+v\nmessage %s", e, e.Message)
	}
	if !strings.Contains(logs.String(), `level=WARN msg="rate limit alert" event=rate_limited_requests metric=requests count=10 threshold=10 window=5m0s`) {
		t.Errorf("log:\n%s", logs)
	}

	// Still over the threshold in the next window: no new alert.
	*now = now.Add(3 * time.Minute)
	for range 10 {
		m.RateLimited(ip("203.0.113.7"), "300/1m")
	}
	m.tick()
	if got := rec.take(); got != nil {
		t.Errorf("alerted again: %s", names(got))
	}
	// A window below the threshold resolves it.
	*now = now.Add(5 * time.Minute)
	m.RateLimited(ip("203.0.113.7"), "300/1m")
	m.tick()
	if got := rec.take(); got != nil {
		t.Errorf("resolved early: %s", names(got))
	}
	*now = now.Add(5 * time.Minute)
	m.tick()
	got = rec.take()
	if names(got) != "rate_limit_alert_resolved " {
		t.Fatalf("events %s", names(got))
	}
	want = "Rate-limited requests are below the alert threshold (10 per 5m0s) again after 15m0s: 24 requests rejected in total, at most 13 per window."
	if e := got[0]; e.Message != want || e.Severity != notify.SeverityInfo || e.Count != 24 || e.Metric != MetricRequests {
		t.Errorf("event %+v\nmessage %s", e, e.Message)
	}
	// A new surge is a new alert. Its time is measured from the first
	// rejected request, not from the start of the window.
	*now = now.Add(20 * time.Second)
	for range 10 {
		m.RateLimited(ip("203.0.113.7"), "300/1m")
	}
	got = rec.take()
	if names(got) != "rate_limited_requests " || !strings.HasPrefix(got[0].Message, "Rate limits rejected 10 requests within less than a second ") {
		t.Errorf("events %+v", got)
	}
}

func TestClients(t *testing.T) {
	m, rec, now, _ := newTestMonitor(t, Config{Clients: Threshold{3, time.Minute}})
	for range 5 {
		m.RateLimited(ip("203.0.113.1"), "300/1m")
		m.RateLimited(ip("203.0.113.2"), "300/1m")
	}
	if got := rec.take(); got != nil {
		t.Fatalf("alerted for 2 clients: %s", names(got))
	}
	*now = now.Add(30 * time.Second)
	m.RateLimited(ip("2001:db8:1:2::3"), "/api/*=100/1m")
	got := rec.take()
	if names(got) != "rate_limited_clients " {
		t.Fatalf("events %s", names(got))
	}
	want := "3 clients were rate limited within 30s (alert threshold: 3 per 1m0s). Top clients: 203.0.113.1 (5), 203.0.113.2 (5), 2001:db8:1:2::/64 (1). Rules: 300/1m (10), /api/*=100/1m (1)."
	if got[0].Message != want || got[0].Count != 3 {
		t.Errorf("message %s", got[0].Message)
	}
	*now = now.Add(time.Minute)
	m.tick()
	*now = now.Add(time.Minute)
	m.tick()
	got = rec.take()
	if names(got) != "rate_limit_alert_resolved " || !strings.HasPrefix(got[0].Message, "Rate-limited clients are below the alert threshold (3 per 1m0s) again after 2m0s: at most 3 clients per window.") || got[0].Count != 3 {
		t.Errorf("events %+v", got)
	}
}

func TestClient(t *testing.T) {
	m, rec, now, logs := newTestMonitor(t, Config{Client: Threshold{5, time.Minute}})
	for range 4 {
		m.RateLimited(ip("203.0.113.7"), "POST /login=5/1m")
		m.RateLimited(ip("198.51.100.4"), "300/1m")
	}
	if got := rec.take(); got != nil {
		t.Fatalf("alerted below the threshold: %s", names(got))
	}
	*now = now.Add(10 * time.Second)
	m.RateLimited(ip("203.0.113.7"), "300/1m")
	m.RateLimited(ip("203.0.113.7"), "300/1m") // already alerted
	got := rec.take()
	if names(got) != "rate_limited_client 203.0.113.7" {
		t.Fatalf("events %s", names(got))
	}
	want := "Client 203.0.113.7 was rate limited 5 times within 10s (alert threshold: 5 per 1m0s). Rules: POST /login=5/1m (4), 300/1m (1)."
	if e := got[0]; e.Message != want || e.Metric != MetricClient || e.Count != 5 || e.TopClients != nil {
		t.Errorf("event %+v\nmessage %s", e, e.Message)
	}
	// Still over the threshold in the next window: no new alert, while
	// another client gets one.
	*now = now.Add(time.Minute)
	for range 5 {
		m.RateLimited(ip("203.0.113.7"), "300/1m")
		m.RateLimited(ip("198.51.100.4"), "300/1m")
	}
	if got := names(rec.take()); got != "rate_limited_client 198.51.100.4" {
		t.Errorf("events %s", got)
	}
	// A window below the threshold ends the alert silently; the next
	// excess is alerted again.
	*now = now.Add(time.Minute)
	m.tick()
	*now = now.Add(time.Minute)
	m.tick()
	if got := rec.take(); got != nil {
		t.Errorf("events %s", names(got))
	}
	if !strings.Contains(logs.String(), `msg="rate limit alert resolved" metric=client client=203.0.113.7`) {
		t.Errorf("log:\n%s", logs)
	}
	for range 5 {
		m.RateLimited(ip("203.0.113.7"), "300/1m")
	}
	if got := names(rec.take()); got != "rate_limited_client 203.0.113.7" {
		t.Errorf("events %s", got)
	}
}

func TestTopIsLimited(t *testing.T) {
	m, rec, _, _ := newTestMonitor(t, Config{Requests: Threshold{100, time.Minute}})
	for i := range 100 {
		m.RateLimited(ip(fmt.Sprintf("192.0.2.%d", i%20)), fmt.Sprintf("/p%d=1/1m", i%7))
	}
	got := rec.take()
	if len(got) != 1 || len(got[0].TopClients) != topN || len(got[0].TopRules) != topN || got[0].TopRules[0] != (notify.Count{Name: "/p0=1/1m", Count: 15}) {
		t.Errorf("events %+v", got)
	}
}

func TestMaxClients(t *testing.T) {
	m, rec, _, _ := newTestMonitor(t, Config{Requests: Threshold{MaxClients + 10, time.Minute}})
	for i := range MaxClients + 10 {
		m.RateLimited(ip(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()), "300/1m")
	}
	got := rec.take()
	if len(got) != 1 || len(m.requests.tally.clients) != MaxClients ||
		!strings.Contains(got[0].Message, "More than 10000 clients; only the first are counted individually.") {
		t.Errorf("%d clients, events %+v", len(m.requests.tally.clients), got)
	}
}

func TestNew(t *testing.T) {
	for _, cfg := range []Config{
		{},
		{Requests: Threshold{Count: 10}},
		{Client: Threshold{-1, time.Minute}},
		{Clients: Threshold{MaxClients + 1, time.Minute}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
	// Without a notifier, alerts are only logged.
	m, err := New(Config{Requests: Threshold{1, time.Minute}, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	m.RateLimited(ip("192.0.2.1"), "300/1m")
}

// BenchmarkRateLimited measures the cost per rejected request during a
// flood from many clients, with all thresholds enabled.
func BenchmarkRateLimited(b *testing.B) {
	m, err := New(Config{
		Requests: Threshold{1 << 30, time.Minute},
		Clients:  Threshold{MaxClients, time.Minute},
		Client:   Threshold{1 << 30, time.Minute},
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		b.Fatal(err)
	}
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			m.RateLimited(netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 32), "300/1m")
		}
	})
}
