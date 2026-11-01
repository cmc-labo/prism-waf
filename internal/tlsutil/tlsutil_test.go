package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCert writes a self-signed certificate for 127.0.0.1 and localhost
// with the given common name, and returns the certificate and key paths.
func writeCert(t *testing.T, dir, cn string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func leafCN(t *testing.T, c *tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCert(t, dir, "first")
	r, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := r.GetCertificate(nil)
	if cn := leafCN(t, c); cn != "first" {
		t.Fatalf("CN = %q, want first", cn)
	}

	// A renewed certificate is picked up on Reload.
	writeCert(t, dir, "second")
	if err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	c, _ = r.GetCertificate(nil)
	if cn := leafCN(t, c); cn != "second" {
		t.Fatalf("CN after reload = %q, want second", cn)
	}

	// A broken file does not replace the working certificate.
	os.WriteFile(certFile, []byte("garbage"), 0o644)
	if err := r.Reload(); err == nil {
		t.Fatal("Reload of broken certificate succeeded")
	}
	c, _ = r.GetCertificate(nil)
	if cn := leafCN(t, c); cn != "second" {
		t.Errorf("CN after failed reload = %q, want second", cn)
	}
}

func TestNewCertReloaderMissingFile(t *testing.T) {
	if _, err := NewCertReloader("/nonexistent/cert.pem", "/nonexistent/key.pem"); err == nil {
		t.Error("NewCertReloader succeeded with missing files")
	}
}

func TestServerConfig(t *testing.T) {
	certFile, keyFile := writeCert(t, t.TempDir(), "server")
	certs, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	// Serve the same way cmd/prismwaf does. (httptest.Server would inject
	// its own certificate and bypass GetCertificate.)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, r.Proto)
		}),
		TLSConfig: ServerConfig(certs),
		ErrorLog:  log.New(io.Discard, "", 0), // the rejected TLS 1.1 handshake
	}
	go srv.ServeTLS(ln, "", "")
	defer srv.Close()
	url := "https://" + ln.Addr().String()

	pool := x509.NewCertPool()
	pem, _ := os.ReadFile(certFile)
	pool.AppendCertsFromPEM(pem)

	// A modern client gets HTTP/2 with the configured certificate.
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2: true,
	}}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "HTTP/2.0" {
		t.Errorf("protocol = %q, want HTTP/2.0", body)
	}

	// TLS 1.1 and older are rejected.
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, MaxVersion: tls.VersionTLS11,
	}}}
	if _, err := old.Get(url); err == nil {
		t.Error("TLS 1.1 client was accepted")
	}
}

func TestBackendConfig(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCert(t, dir, "backend")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	backend.StartTLS()
	defer backend.Close()

	get := func(cfg *tls.Config) error {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		resp, err := c.Get(backend.URL)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}

	withCA, err := BackendConfig(certFile, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := get(withCA); err != nil {
		t.Errorf("with backend CA: %v", err)
	}

	systemCAs, _ := BackendConfig("", false)
	if err := get(systemCAs); err == nil {
		t.Error("self-signed backend accepted without its CA")
	}

	insecure, _ := BackendConfig("", true)
	if err := get(insecure); err != nil {
		t.Errorf("with verification disabled: %v", err)
	}

	if _, err := BackendConfig(certFile, true); err == nil {
		t.Error("CA together with insecure was accepted")
	}
	if _, err := BackendConfig(keyFile, false); err == nil {
		t.Error("a file without certificates was accepted as CA")
	}
}

func TestRedirectHandler(t *testing.T) {
	tests := []struct {
		port, host, target, want string
	}{
		{"443", "example.com", "/a/b?x=1&y=2", "https://example.com/a/b?x=1&y=2"},
		{"443", "example.com:80", "/", "https://example.com/"},
		{"", "example.com:8080", "/", "https://example.com/"},
		{"8443", "example.com:8080", "/login", "https://example.com:8443/login"},
		{"8443", "[2001:db8::1]:8080", "/", "https://[2001:db8::1]:8443/"},
		{"443", "[2001:db8::1]", "/", "https://[2001:db8::1]/"},
	}
	for _, tc := range tests {
		r := httptest.NewRequest("POST", tc.target, nil)
		r.Host = tc.host
		rec := httptest.NewRecorder()
		RedirectHandler(tc.port).ServeHTTP(rec, r)
		if rec.Code != http.StatusPermanentRedirect || rec.Header().Get("Location") != tc.want {
			t.Errorf("port %q, Host %q, %s: got %d %q, want 308 %q",
				tc.port, tc.host, tc.target, rec.Code, rec.Header().Get("Location"), tc.want)
		}
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Host = ""
	rec := httptest.NewRecorder()
	RedirectHandler("443").ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty Host: status = %d, want 400", rec.Code)
	}
}
