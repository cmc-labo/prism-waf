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
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// writeCert writes a self-signed certificate with the given common name,
// valid for 127.0.0.1 and dnsNames (default localhost) as a server and as a
// client, and returns the certificate and key paths.
func writeCert(t *testing.T, dir, cn string, dnsNames ...string) (certFile, keyFile string) {
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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}
	if len(dnsNames) > 0 {
		tmpl.DNSNames = dnsNames
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

// serveTLS serves handler with cfg the same way cmd/prismwaf does and
// returns the server's URL. (httptest.Server would inject its own
// certificate and bypass GetCertificate.)
func serveTLS(t *testing.T, cfg *tls.Config, handler http.HandlerFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:   handler,
		TLSConfig: cfg,
		ErrorLog:  log.New(io.Discard, "", 0), // rejected handshakes
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	return "https://" + ln.Addr().String()
}

func certPool(t *testing.T, files ...string) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	for _, f := range files {
		pem, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		pool.AppendCertsFromPEM(pem)
	}
	return pool
}

func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCert(t, dir, "first")
	r, err := NewCertReloader([]CertPair{{certFile, keyFile}})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := r.GetCertificate(&tls.ClientHelloInfo{})
	if cn := leafCN(t, c); cn != "first" {
		t.Fatalf("CN = %q, want first", cn)
	}

	// A renewed certificate is picked up on Reload.
	writeCert(t, dir, "second")
	if err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	c, _ = r.GetCertificate(&tls.ClientHelloInfo{})
	if cn := leafCN(t, c); cn != "second" {
		t.Fatalf("CN after reload = %q, want second", cn)
	}

	// A broken file does not replace the working certificate.
	os.WriteFile(certFile, []byte("garbage"), 0o644)
	if err := r.Reload(); err == nil {
		t.Fatal("Reload of broken certificate succeeded")
	}
	c, _ = r.GetCertificate(&tls.ClientHelloInfo{})
	if cn := leafCN(t, c); cn != "second" {
		t.Errorf("CN after failed reload = %q, want second", cn)
	}
}

func TestNewCertReloaderMissingFile(t *testing.T) {
	if _, err := NewCertReloader([]CertPair{{"/nonexistent/cert.pem", "/nonexistent/key.pem"}}); err == nil {
		t.Error("NewCertReloader succeeded with missing files")
	}
}

func TestServerConfig(t *testing.T) {
	certFile, keyFile := writeCert(t, t.TempDir(), "server")
	certs, err := NewCertReloader([]CertPair{{certFile, keyFile}})
	if err != nil {
		t.Fatal(err)
	}
	url := serveTLS(t, ServerConfig(ServerOptions{GetCertificate: certs.GetCertificate}), func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Proto)
	})
	pool := certPool(t, certFile)

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

func TestCertReloaderSNI(t *testing.T) {
	aCert, aKey := writeCert(t, t.TempDir(), "a", "a.example")
	bCert, bKey := writeCert(t, t.TempDir(), "b", "b.example")
	certs, err := NewCertReloader([]CertPair{{aCert, aKey}, {bCert, bKey}})
	if err != nil {
		t.Fatal(err)
	}
	url := serveTLS(t, ServerConfig(ServerOptions{GetCertificate: certs.GetCertificate}), func(http.ResponseWriter, *http.Request) {})
	addr := url[len("https://"):]

	served := func(serverName string) string {
		t.Helper()
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("%q: %v", serverName, err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	}
	for _, tc := range []struct{ serverName, wantCN string }{
		{"a.example", "a"},
		{"b.example", "b"},
		{"other.example", "a"}, // the first certificate is the default
		{"", "a"},              // no SNI, e.g. access by IP address
	} {
		if cn := served(tc.serverName); cn != tc.wantCN {
			t.Errorf("server name %q: got certificate %q, want %q", tc.serverName, cn, tc.wantCN)
		}
	}

	// If one of several files breaks, all current certificates stay.
	os.WriteFile(bCert, []byte("garbage"), 0o644)
	if err := certs.Reload(); err == nil {
		t.Fatal("Reload with a broken certificate succeeded")
	}
	if cn := served("b.example"); cn != "b" {
		t.Errorf("after failed reload, b.example got %q, want b", cn)
	}
}

func TestClientAuth(t *testing.T) {
	serverCert, serverKey := writeCert(t, t.TempDir(), "server")
	clientCAFile, clientKeyFile := writeCert(t, t.TempDir(), "client")
	strangerCert, strangerKey := writeCert(t, t.TempDir(), "stranger")
	certs, err := NewCertReloader([]CertPair{{serverCert, serverKey}})
	if err != nil {
		t.Fatal(err)
	}
	clientCAs, err := LoadCAs(clientCAFile)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := tls.LoadX509KeyPair(clientCAFile, clientKeyFile)
	stranger, _ := tls.LoadX509KeyPair(strangerCert, strangerKey)
	roots := certPool(t, serverCert)

	get := func(url string, cert *tls.Certificate) (string, error) {
		cfg := &tls.Config{RootCAs: roots}
		if cert != nil {
			// Send the certificate even if the server's CA list does not
			// name its issuer, which Go's client would otherwise skip.
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return cert, nil
			}
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}}
		resp, err := c.Get(url)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}
	// The handler reports the verified client, as the WAF sees it.
	whoami := func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			io.WriteString(w, "anonymous")
			return
		}
		io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}

	for _, tc := range []struct {
		mode string
		cert *tls.Certificate
		want string // "" means the connection is rejected
	}{
		{"require", &client, "client"},
		{"require", nil, ""},
		{"require", &stranger, ""},
		{"optional", &client, "client"},
		{"optional", nil, "anonymous"},
		{"optional", &stranger, ""},
	} {
		auth, err := ParseClientAuth(tc.mode)
		if err != nil {
			t.Fatal(err)
		}
		url := serveTLS(t, ServerConfig(ServerOptions{
			GetCertificate: certs.GetCertificate,
			ClientCAs:      clientCAs,
			ClientAuth:     auth,
		}), whoami)
		got, err := get(url, tc.cert)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s with %v: accepted as %q, want rejection", tc.mode, tc.cert != nil, got)
			}
		} else if err != nil || got != tc.want {
			t.Errorf("%s with %v: got %q, %v, want %q", tc.mode, tc.cert != nil, got, err, tc.want)
		}
	}
}

// The ACME CA validates TLS-ALPN-01 without a client certificate. Such
// connections must complete the handshake, but must not be usable for
// requests.
func TestACMEChallengeWithClientAuth(t *testing.T) {
	serverCert, serverKey := writeCert(t, t.TempDir(), "server")
	clientCA, _ := writeCert(t, t.TempDir(), "client")
	certs, _ := NewCertReloader([]CertPair{{serverCert, serverKey}})
	clientCAs, _ := LoadCAs(clientCA)
	var requests atomic.Int32
	url := serveTLS(t, ServerConfig(ServerOptions{
		GetCertificate: certs.GetCertificate,
		ACME:           true,
		ClientCAs:      clientCAs,
		ClientAuth:     tls.RequireAndVerifyClientCert,
	}), func(http.ResponseWriter, *http.Request) { requests.Add(1) })
	addr := url[len("https://"):]

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{acme.ALPNProto}})
	if err != nil {
		t.Fatalf("acme-tls/1 handshake without client certificate failed: %v", err)
	}
	if p := conn.ConnectionState().NegotiatedProtocol; p != acme.ALPNProto {
		t.Errorf("negotiated %q, want %q", p, acme.ALPNProto)
	}
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, _ := conn.Read(make([]byte, 1)); n != 0 || requests.Load() != 0 {
		t.Error("a request was served on the acme-tls/1 connection")
	}
	conn.Close()

	// Offering HTTP alongside acme-tls/1 does not skip client authentication.
	for _, protos := range [][]string{{"h2", "http/1.1"}, {acme.ALPNProto, "http/1.1"}} {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: protos}}}
		if resp, err := c.Get(url); err == nil {
			resp.Body.Close()
			t.Errorf("ALPN %q without client certificate was accepted", protos)
		}
	}
}

func TestServerConfigACMEProtocols(t *testing.T) {
	cfg := ServerConfig(ServerOptions{ACME: true})
	if !slices.Equal(cfg.NextProtos, []string{"h2", "http/1.1", acme.ALPNProto}) {
		t.Errorf("NextProtos = %q", cfg.NextProtos)
	}
	if cfg.GetConfigForClient != nil {
		t.Error("GetConfigForClient set without client authentication")
	}
}

func TestParseClientAuth(t *testing.T) {
	for in, want := range map[string]tls.ClientAuthType{
		"":         tls.NoClientCert,
		"none":     tls.NoClientCert,
		"require":  tls.RequireAndVerifyClientCert,
		"optional": tls.VerifyClientCertIfGiven,
	} {
		if got, err := ParseClientAuth(in); err != nil || got != want {
			t.Errorf("ParseClientAuth(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseClientAuth("request"); err == nil {
		t.Error("invalid mode accepted")
	}
}
