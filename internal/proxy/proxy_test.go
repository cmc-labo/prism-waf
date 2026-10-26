package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyForwardsRequest(t *testing.T) {
	var got struct {
		method, path, query, body, header, host, xff string
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.method = r.Method
		got.path = r.URL.Path
		got.query = r.URL.RawQuery
		got.body = string(b)
		got.header = r.Header.Get("X-Test")
		got.host = r.Host
		got.xff = r.Header.Get("X-Forwarded-For")
		w.Header().Set("X-Backend", "ok")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "hello from backend")
	}))
	defer backend.Close()

	u, err := ParseBackend(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(u, nil)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/api/items?id=42", strings.NewReader("payload"))
	req.Header.Set("X-Test", "value")
	req.Host = "example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	if string(body) != "hello from backend" {
		t.Errorf("body = %q", body)
	}
	if resp.Header.Get("X-Backend") != "ok" {
		t.Errorf("response header X-Backend not forwarded")
	}
	if got.method != http.MethodPost || got.path != "/api/items" || got.query != "id=42" {
		t.Errorf("backend saw %s %s?%s", got.method, got.path, got.query)
	}
	if got.body != "payload" {
		t.Errorf("backend body = %q", got.body)
	}
	if got.header != "value" {
		t.Errorf("backend X-Test = %q", got.header)
	}
	if got.host != "example.com" {
		t.Errorf("backend Host = %q, want example.com", got.host)
	}
	if got.xff == "" {
		t.Errorf("X-Forwarded-For not set")
	}
}

func TestProxyBackendDown(t *testing.T) {
	backend := httptest.NewServer(http.NotFoundHandler())
	u, _ := ParseBackend(backend.URL)
	backend.Close() // make the backend unreachable

	h, err := New(u, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

func TestParseBackend(t *testing.T) {
	for _, tc := range []struct {
		in      string
		wantErr bool
	}{
		{"http://127.0.0.1:8081", false},
		{"https://backend.internal", false},
		{"127.0.0.1:8081", true},
		{"ftp://example.com", true},
		{"http://", true},
	} {
		_, err := ParseBackend(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseBackend(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
	}
}
