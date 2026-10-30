package waf

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cmc-labo/prism-waf/internal/audit"
)

func serveWithAudit(t *testing.T, cfg Config, r *http.Request) (*httptest.ResponseRecorder, []audit.Event) {
	t.Helper()
	var buf bytes.Buffer
	cfg.Audit = audit.New(&buf)
	if cfg.Inspector == nil {
		cfg.Inspector = mustInspector(t, 0)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	rec := httptest.NewRecorder()
	Middleware(next, cfg).ServeHTTP(rec, r)

	var events []audit.Event
	dec := json.NewDecoder(&buf)
	for dec.More() {
		var e audit.Event
		if err := dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	return rec, events
}

func TestAuditEventForBlockedRequest(t *testing.T) {
	tp, _ := ParseTrustedProxies("10.0.0.0/8")
	r := httptest.NewRequest("GET", "/items?id=1+UNION+SELECT+password+FROM+users", nil)
	r.RemoteAddr = "10.0.0.5:4321"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.Header.Set("User-Agent", "sqlmap/1.8")
	r.Header.Set("Cookie", "session=secret")
	r.Header.Set("Authorization", "Bearer secret")

	rec, events := serveWithAudit(t, Config{TrustedProxies: tp}, r)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	e := events[0]
	if !strings.Contains(rec.Body.String(), e.ID) {
		t.Errorf("response %q does not contain event ID %q", rec.Body.String(), e.ID)
	}
	if strings.Contains(rec.Body.String(), "SQLI") {
		t.Errorf("response discloses rule details: %q", rec.Body.String())
	}
	if e.ClientIP != "203.0.113.7" || e.RemoteAddr != "10.0.0.5:4321" {
		t.Errorf("client_ip = %q, remote_addr = %q", e.ClientIP, e.RemoteAddr)
	}
	if e.Action != "block" || e.Reason != "signature" || e.Time.IsZero() {
		t.Errorf("action = %q, reason = %q, time = %v", e.Action, e.Reason, e.Time)
	}
	if e.Rule == nil || e.Rule.ID != "SQLI-002" || e.Rule.Category != "sqli" {
		t.Errorf("rule = %+v", e.Rule)
	}
	if e.Match == nil || e.Match.Location != "query" || e.Match.Data != "union select" ||
		e.Match.Value != "id=1+UNION+SELECT+password+FROM+users" || e.Match.ValueTruncated {
		t.Errorf("match = %+v", e.Match)
	}
	if e.Request.Method != "GET" || e.Request.URI != "/items?id=1+UNION+SELECT+password+FROM+users" {
		t.Errorf("request = %+v", e.Request)
	}
	if e.Request.Headers["User-Agent"] != "sqlmap/1.8" {
		t.Errorf("User-Agent = %q", e.Request.Headers["User-Agent"])
	}
	for _, h := range []string{"Cookie", "Authorization"} {
		if e.Request.Headers[h] != "[REDACTED]" {
			t.Errorf("%s = %q, want [REDACTED]", h, e.Request.Headers[h])
		}
	}
}

func TestAuditEventKeepsSensitiveHeaderWhenItIsThePayload(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "id=' OR '1'='1")
	r.Header.Set("Authorization", "Bearer secret")

	_, events := serveWithAudit(t, Config{}, r)

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	e := events[0]
	if e.Match.Location != "header" || e.Match.Field != "Cookie" || e.Match.Value != "id=' OR '1'='1" {
		t.Errorf("match = %+v", e.Match)
	}
	if e.Request.Headers["Cookie"] != "id=' OR '1'='1" {
		t.Errorf("Cookie = %q, want the attack payload", e.Request.Headers["Cookie"])
	}
	if e.Request.Headers["Authorization"] != "[REDACTED]" {
		t.Errorf("Authorization = %q, want [REDACTED]", e.Request.Headers["Authorization"])
	}
}

func TestAuditEventBase64AndTruncation(t *testing.T) {
	payload := strings.Repeat("a", 10000) + ` PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`
	r := httptest.NewRequest("POST", "/api", strings.NewReader(payload))

	_, events := serveWithAudit(t, Config{}, r)

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	m := events[0].Match
	if m.Location != "body" || !m.Base64 || m.Data != "<script" {
		t.Errorf("match = %+v", m)
	}
	if !m.ValueTruncated || len(m.Value) != maxLoggedValue || m.ValueLength != len(payload) {
		t.Errorf("value_truncated = %v, len(value) = %d, value_length = %d", m.ValueTruncated, len(m.Value), m.ValueLength)
	}
}

func TestAuditEventForBodyTooLarge(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("a", 100)))

	rec, events := serveWithAudit(t, Config{Inspector: mustInspector(t, 10)}, r)

	if rec.Code != http.StatusRequestEntityTooLarge || len(events) != 1 {
		t.Fatalf("status = %d, events = %d", rec.Code, len(events))
	}
	e := events[0]
	if e.Reason != "body_too_large" || e.Rule != nil || e.Match != nil || e.Request.ContentLength != 100 {
		t.Errorf("event = %+v", e)
	}
}

func TestNoAuditEventForCleanRequest(t *testing.T) {
	rec, events := serveWithAudit(t, Config{}, httptest.NewRequest("GET", "/products?id=42", nil))
	if rec.Code != http.StatusOK || len(events) != 0 {
		t.Errorf("status = %d, events = %d", rec.Code, len(events))
	}
}

func TestDetectModeForwardsAndLogs(t *testing.T) {
	big := strings.Repeat("a", 100) + " <script>"
	tests := []struct {
		name       string
		req        func() *http.Request
		wantReason string
		wantBody   string
	}{
		{
			name:       "attack in query",
			req:        func() *http.Request { return httptest.NewRequest("GET", "/?q=<script>", nil) },
			wantReason: "signature",
		},
		{
			name: "attack in body",
			req: func() *http.Request {
				return httptest.NewRequest("POST", "/", strings.NewReader("id=1' OR '1'='1"))
			},
			wantReason: "signature",
			wantBody:   "id=1' OR '1'='1",
		},
		{
			name:       "body too large with Content-Length",
			req:        func() *http.Request { return httptest.NewRequest("POST", "/", strings.NewReader(big)) },
			wantReason: "body_too_large",
			wantBody:   big,
		},
		{
			name: "body too large without Content-Length",
			req: func() *http.Request {
				r := httptest.NewRequest("POST", "/", strings.NewReader(big))
				r.ContentLength = -1 // chunked: the limit is only noticed while reading
				return r
			},
			wantReason: "body_too_large",
			wantBody:   big,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			var reached bool
			var gotBody string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				b, _ := io.ReadAll(r.Body)
				gotBody = string(b)
				w.WriteHeader(http.StatusTeapot)
			})
			h := Middleware(next, Config{
				Inspector: mustInspector(t, 64),
				Mode:      ModeDetect,
				Audit:     audit.New(&buf),
			})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tc.req())

			if !reached || rec.Code != http.StatusTeapot {
				t.Fatalf("request not forwarded: reached = %v, status = %d", reached, rec.Code)
			}
			if gotBody != tc.wantBody {
				t.Errorf("backend body = %q, want %q", gotBody, tc.wantBody)
			}
			var e audit.Event
			if err := json.Unmarshal(buf.Bytes(), &e); err != nil {
				t.Fatalf("audit event: %v (%q)", err, buf.String())
			}
			if e.Action != "detect" || e.Reason != tc.wantReason {
				t.Errorf("action = %q, reason = %q; want detect, %s", e.Action, e.Reason, tc.wantReason)
			}
		})
	}
}

func TestBlockModeIsDefault(t *testing.T) {
	rec, events := serveWithAudit(t, Config{}, httptest.NewRequest("GET", "/?q=<script>", nil))
	if rec.Code != http.StatusForbidden || len(events) != 1 || events[0].Action != "block" {
		t.Errorf("status = %d, events = %+v", rec.Code, events)
	}
}

func TestParseMode(t *testing.T) {
	for _, s := range []string{"block", "detect"} {
		if m, err := ParseMode(s); err != nil || string(m) != s {
			t.Errorf("ParseMode(%q) = %q, %v", s, m, err)
		}
	}
	for _, s := range []string{"", "Block", "off", "monitor"} {
		if _, err := ParseMode(s); err == nil {
			t.Errorf("ParseMode(%q) succeeded, want error", s)
		}
	}
}
