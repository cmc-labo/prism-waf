package prismwaf_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/cmc-labo/prism-waf/prismwaf"
)

// app answers every request with "app" and the body it received.
var app = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	io.WriteString(w, "app "+string(body))
})

const sqli = "/search?q=" + "1%27%20OR%20%271%27%3D%271"

func serve(h http.Handler, method, target, body, remoteAddr string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if remoteAddr != "" {
		r.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// events decodes the audit events in buf.
func events(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	dec := json.NewDecoder(buf)
	for dec.More() {
		var e map[string]any
		if err := dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestMiddleware(t *testing.T) {
	for _, engine := range []prismwaf.Engine{"", prismwaf.EngineBuiltin, prismwaf.EngineCRS, prismwaf.EngineBoth} {
		t.Run(string(engine), func(t *testing.T) {
			var audit bytes.Buffer
			w, err := prismwaf.New(prismwaf.Options{Engine: engine, AuditLog: &audit})
			if err != nil {
				t.Fatal(err)
			}
			h := w.Middleware(app)

			if rec := serve(h, "GET", "/search?q=shoes", "", ""); rec.Code != 200 || rec.Body.String() != "app " {
				t.Errorf("normal request: %d %q", rec.Code, rec.Body)
			}
			// The body is passed on after it was inspected.
			if rec := serve(h, "POST", "/comments", "text=hello", ""); rec.Code != 200 || rec.Body.String() != "app text=hello" {
				t.Errorf("normal POST: %d %q", rec.Code, rec.Body)
			}
			if rec := serve(h, "GET", sqli, "", ""); rec.Code != 403 || strings.Contains(rec.Body.String(), "app") {
				t.Errorf("SQL injection: %d %q", rec.Code, rec.Body)
			}
			if rec := serve(h, "POST", "/comments", "text="+url.QueryEscape("<script>alert(1)</script>"), ""); rec.Code != 403 {
				t.Errorf("XSS in the body: %d", rec.Code)
			}
			ev := events(t, &audit)
			if len(ev) != 2 || ev[0]["action"] != "block" {
				t.Fatalf("audit events: %v", ev)
			}
			want := "signature"
			if engine == prismwaf.EngineCRS {
				want = "crs"
			}
			if ev[0]["reason"] != want {
				t.Errorf("reason %v, want %s", ev[0]["reason"], want)
			}
		})
	}
}

func TestDetectMode(t *testing.T) {
	var audit bytes.Buffer
	w, err := prismwaf.New(prismwaf.Options{Mode: prismwaf.ModeDetect, AuditLog: &audit})
	if err != nil {
		t.Fatal(err)
	}
	if rec := serve(w.Middleware(app), "GET", sqli, "", ""); rec.Code != 200 {
		t.Errorf("detected request: %d, want it passed on", rec.Code)
	}
	if ev := events(t, &audit); len(ev) != 1 || ev[0]["action"] != "detect" {
		t.Errorf("audit events: %v", ev)
	}
}

func TestMaxBodySize(t *testing.T) {
	w, err := prismwaf.New(prismwaf.Options{MaxBodySize: 10, AuditLog: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	h := w.Middleware(app)
	if rec := serve(h, "POST", "/", "0123456789", ""); rec.Code != 200 {
		t.Errorf("10 bytes: %d", rec.Code)
	}
	if rec := serve(h, "POST", "/", "0123456789a", ""); rec.Code != 413 {
		t.Errorf("11 bytes: %d, want 413", rec.Code)
	}
}

func TestRateLimit(t *testing.T) {
	var audit bytes.Buffer
	w, err := prismwaf.New(prismwaf.Options{
		RateLimit:       "100/1m",
		RateLimitPaths:  []string{"POST /login=2/1m"},
		RateLimitExempt: []string{"192.0.2.99"},
		TrustedProxies:  []string{"10.0.0.1"},
		AuditLog:        &audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Two handlers of one WAF share the limits.
	h1, h2 := w.Middleware(app), w.Middleware(app)
	login := func(h http.Handler, client string) int {
		r := httptest.NewRequest("POST", "/login", nil)
		r.RemoteAddr = "10.0.0.1:1234"
		r.Header.Set("X-Forwarded-For", client)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	got := []int{login(h1, "192.0.2.1"), login(h2, "192.0.2.1"), login(h1, "192.0.2.1"), login(h1, "192.0.2.2")}
	if want := []int{200, 200, 429, 200}; !slices.Equal(got, want) {
		t.Errorf("logins: %v, want %v (the client from X-Forwarded-For)", got, want)
	}
	for range 3 {
		if code := login(h1, "192.0.2.99"); code != 200 {
			t.Errorf("exempt client: %d", code)
		}
	}
	if ev := events(t, &audit); len(ev) != 1 || ev[0]["reason"] != "rate_limit" || ev[0]["client_ip"] != "192.0.2.1" {
		t.Errorf("audit events: %v", ev)
	}
}

func TestNewErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts prismwaf.Options
		want string
	}{
		{"engine", prismwaf.Options{Engine: "modsecurity"}, "invalid engine"},
		{"mode", prismwaf.Options{Mode: "log"}, "invalid mode"},
		{"body size", prismwaf.Options{MaxBodySize: -1}, "body size"},
		{"CRS option without the CRS", prismwaf.Options{CRSParanoiaLevel: 2}, "require EngineCRS"},
		{"paranoia level", prismwaf.Options{Engine: prismwaf.EngineCRS, CRSParanoiaLevel: 5}, "paranoia level"},
		{"rate", prismwaf.Options{RateLimit: "100"}, "invalid rate limit"},
		{"path rule", prismwaf.Options{RateLimitPaths: []string{"/login"}}, "invalid rate limit path"},
		{"exemption", prismwaf.Options{RateLimit: "1/1s", RateLimitExempt: []string{"example.com"}}, "invalid rate limit exemption"},
		{"exemption without a limit", prismwaf.Options{RateLimitExempt: []string{"192.0.2.1"}}, "requires RateLimit"},
		{"trusted proxy", prismwaf.Options{TrustedProxies: []string{"proxy"}}, "invalid trusted proxies"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := prismwaf.New(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}
}
