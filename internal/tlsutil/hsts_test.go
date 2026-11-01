package tlsutil

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"
)

func TestHSTSPolicyHeader(t *testing.T) {
	year := 365 * 24 * time.Hour
	for _, tc := range []struct {
		p    HSTSPolicy
		want string
	}{
		{HSTSPolicy{MaxAge: year}, "max-age=31536000"},
		{HSTSPolicy{MaxAge: 2 * year, IncludeSubdomains: true}, "max-age=63072000; includeSubDomains"},
		{HSTSPolicy{MaxAge: year, IncludeSubdomains: true, Preload: true}, "max-age=31536000; includeSubDomains; preload"},
	} {
		if err := tc.p.Validate(); err != nil {
			t.Errorf("%+v: %v", tc.p, err)
		}
		if got := tc.p.Header(); got != tc.want {
			t.Errorf("%+v: Header() = %q, want %q", tc.p, got, tc.want)
		}
	}
	for _, p := range []HSTSPolicy{
		{MaxAge: -time.Second},
		{MaxAge: 30 * 24 * time.Hour, IncludeSubdomains: true, Preload: true},
		{MaxAge: year, Preload: true},
	} {
		if p.Validate() == nil {
			t.Errorf("%+v: Validate() accepted an invalid policy", p)
		}
	}
}

func TestHSTS(t *testing.T) {
	p := HSTSPolicy{MaxAge: time.Hour}
	h := HSTS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=0") // from the backend
		http.Error(w, "Forbidden", http.StatusForbidden)
	}), p)

	r := httptest.NewRequest("GET", "/", nil)
	r.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if got := rec.Header().Values("Strict-Transport-Security"); len(got) != 1 || got[0] != "max-age=3600" {
		t.Errorf("HTTPS: Strict-Transport-Security = %q, want [max-age=3600]", got)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=0" {
		t.Errorf("plain HTTP: Strict-Transport-Security = %q, want the backend's header only", got)
	}
}

// The header must also be set when the handler writes the body without
// calling WriteHeader, and streaming through a reverse proxy must still work.
func TestHSTSThroughReverseProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=0")
		io.WriteString(w, "chunk1 ")
		http.NewResponseController(w).Flush()
		io.WriteString(w, "chunk2")
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	front := httptest.NewTLSServer(HSTS(httputil.NewSingleHostReverseProxy(u), HSTSPolicy{MaxAge: time.Hour}))
	defer front.Close()

	resp, err := front.Client().Get(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if got := resp.Header.Values("Strict-Transport-Security"); len(got) != 1 || got[0] != "max-age=3600" {
		t.Errorf("Strict-Transport-Security = %q, want [max-age=3600]", got)
	}
	if string(body) != "chunk1 chunk2" {
		t.Errorf("body = %q", body)
	}

	// A handler that only calls Write.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.TLS = &tls.ConnectionState{}
	HSTS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}), HSTSPolicy{MaxAge: time.Hour}).ServeHTTP(rec, r)
	if rec.Header().Get("Strict-Transport-Security") != "max-age=3600" {
		t.Error("header missing when only Write is called")
	}
}
