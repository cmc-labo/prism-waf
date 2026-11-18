package waf

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cmc-labo/prism-waf/internal/abuse"
	"github.com/cmc-labo/prism-waf/internal/audit"
)

func abuseGuard(t *testing.T, failures, enumerations []string) *abuse.Guard {
	t.Helper()
	var cfg abuse.Config
	for _, s := range failures {
		r, err := abuse.ParseFailureRule(s)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Failures = append(cfg.Failures, r)
	}
	for _, s := range enumerations {
		r, err := abuse.ParseEnumerationRule(s)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Enumerations = append(cfg.Enumerations, r)
	}
	g, err := abuse.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// abuseServer serves requests through Middleware to a backend that
// answers logins with the wrong password with 401, and returns the
// requests the backend got and the audit events.
type abuseServer struct {
	handler   http.Handler
	forwarded int
	audit     bytes.Buffer
}

func newAbuseServer(t *testing.T, cfg Config) *abuseServer {
	s := &abuseServer{}
	cfg.Audit = audit.New(&s.audit)
	if cfg.Inspector == nil {
		cfg.Inspector = mustInspector(t, 0)
	}
	s.handler = Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.forwarded++
		if r.URL.Path == "/login" && r.FormValue("password") != "right" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte("ok"))
		http.NewResponseController(w).Flush()
	}), cfg)
	return s
}

func (s *abuseServer) do(method, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = "203.0.113.7:1234"
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, r)
	return rec
}

func (s *abuseServer) events(t *testing.T) []audit.Event {
	t.Helper()
	var events []audit.Event
	dec := json.NewDecoder(bytes.NewReader(s.audit.Bytes()))
	for dec.More() {
		var e audit.Event
		if err := dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	return events
}

func TestFailureLimit(t *testing.T) {
	s := newAbuseServer(t, Config{Abuse: abuseGuard(t, []string{"POST /login=3/1h"}, nil)})
	// Successful logins and requests the WAF rejects do not count.
	for range 5 {
		if rec := s.do("POST", "/login?password=right"); rec.Code != http.StatusOK || !rec.Flushed {
			t.Fatalf("successful login: %d, flushed %v", rec.Code, rec.Flushed)
		}
		if rec := s.do("POST", "/login?password=x'+OR+'1'='1"); rec.Code != http.StatusForbidden {
			t.Fatalf("attack: %d", rec.Code)
		}
	}
	for i := range 3 {
		if rec := s.do("POST", "/login?password=wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failed login %d: %d", i+1, rec.Code)
		}
	}
	before := s.forwarded
	for range 3 {
		rec := s.do("POST", "/login?password=right")
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1200" {
			t.Fatalf("login after 3 failures: %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
		}
	}
	if s.forwarded != before {
		t.Error("rejected logins were forwarded")
	}
	// Other paths are not limited.
	if rec := s.do("GET", "/account"); rec.Code != http.StatusOK {
		t.Errorf("other path: %d", rec.Code)
	}

	var limited []audit.Event
	for _, e := range s.events(t) {
		if e.Reason == abuse.ReasonFailureLimit {
			limited = append(limited, e)
		}
	}
	if len(limited) != 1 {
		t.Fatalf("%d failure_limit events, want 1", len(limited))
	}
	e := limited[0]
	if e.Action != "block" || e.RateLimit == nil || *e.RateLimit != (audit.RateLimit{Rule: "POST /login=3/1h 401,403", Client: "203.0.113.7/32", RetryAfter: 1200}) {
		t.Errorf("event %+v, rate_limit %+v", e, e.RateLimit)
	}
}

func TestFailureLimitDetectMode(t *testing.T) {
	s := newAbuseServer(t, Config{Mode: ModeDetect, Abuse: abuseGuard(t, []string{"POST /login=2/1h"}, nil)})
	for range 5 {
		if rec := s.do("POST", "/login"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("detect mode: %d", rec.Code)
		}
	}
	events := s.events(t)
	if len(events) != 1 || events[0].Reason != abuse.ReasonFailureLimit || events[0].Action != "detect" {
		t.Errorf("events %+v", events)
	}
}

func TestEnumerationLimit(t *testing.T) {
	s := newAbuseServer(t, Config{Abuse: abuseGuard(t, nil, []string{"GET /api/orders/{id}=2/1h"})})
	for _, id := range []string{"1", "2", "1", "2"} {
		if rec := s.do("GET", "/api/orders/"+id); rec.Code != http.StatusOK {
			t.Fatalf("order %s: %d", id, rec.Code)
		}
	}
	for _, id := range []string{"3", "4"} {
		if rec := s.do("GET", "/api/orders/"+id); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "3600" {
			t.Fatalf("order %s: %d, Retry-After %q", id, rec.Code, rec.Header().Get("Retry-After"))
		}
	}
	if rec := s.do("GET", "/api/orders/1"); rec.Code != http.StatusOK {
		t.Errorf("order already seen: %d", rec.Code)
	}
	events := s.events(t)
	if len(events) != 1 || events[0].Reason != abuse.ReasonEnumeration || events[0].RateLimit == nil ||
		*events[0].RateLimit != (audit.RateLimit{Rule: "GET /api/orders/{id}=2/1h", Client: "203.0.113.7/32", RetryAfter: 3600}) {
		t.Errorf("events %+v", events)
	}
}

func TestFailureLimitAfterInformationalResponse(t *testing.T) {
	g := abuseGuard(t, []string{"POST /login=1/1h"}, nil)
	h := recordFailures(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusUnauthorized)
	}), g, "192.0.2.1")
	r := httptest.NewRequest("POST", "/login", nil)
	h.ServeHTTP(httptest.NewRecorder(), r)
	if d := g.Check(r, "192.0.2.1"); d.Allowed {
		t.Error("401 after 103 Early Hints not counted")
	}
}
