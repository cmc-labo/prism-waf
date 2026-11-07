package tlsutil

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	productionDir = "acme-v02.api.letsencrypt.org-directory"
	stagingDir    = "acme-staging-v02.api.letsencrypt.org-directory"
)

// logBuffer collects JSON log records.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// records returns the log records with the given message.
func (b *logBuffer) records(msg string) []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.buf.String()), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(line), &r) == nil && r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

func newLog() (*slog.Logger, *logBuffer) {
	b := &logBuffer{}
	return slog.New(slog.NewJSONHandler(b, nil)), b
}

// cachedCert returns a certificate in autocert's cache format.
func cachedCert(t *testing.T, name, issuerOrg string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subject := pkix.Name{CommonName: name, Organization: []string{issuerOrg}}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      subject,
		DNSNames:     []string{name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	var b bytes.Buffer
	pem.Encode(&b, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	return b.Bytes()
}

func validCert(t *testing.T, name, issuerOrg string) []byte {
	return cachedCert(t, name, issuerOrg, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestNewACMEManager(t *testing.T) {
	root := t.TempDir()
	a, err := NewACMEManager(ACMEConfig{
		Domains:  []string{"example.com", "WWW.example.com."},
		CacheDir: root,
		Email:    "admin@example.com",
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Only the configured domains may trigger a certificate request.
	for host, allowed := range map[string]bool{
		"example.com":      true,
		"www.example.com":  true,
		"evil.example.com": false,
		"example.org":      false,
	} {
		if err := a.m.HostPolicy(context.Background(), host); (err == nil) != allowed {
			t.Errorf("HostPolicy(%q) = %v, allowed %v", host, err, allowed)
		}
	}
	if a.DirectoryURL() != LetsEncryptProduction || a.m.Client.DirectoryURL != LetsEncryptProduction {
		t.Errorf("default directory = %q", a.m.Client.DirectoryURL)
	}
	if want := filepath.Join(root, productionDir); a.CacheDir() != want {
		t.Errorf("cache dir = %q, want %q", a.CacheDir(), want)
	}
	if fi, err := os.Stat(a.CacheDir()); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("cache dir: %v, %v", fi, err)
	}
	if b, _ := os.ReadFile(filepath.Join(a.CacheDir(), directoryURLFile)); strings.TrimSpace(string(b)) != LetsEncryptProduction {
		t.Errorf("directory-url = %q", b)
	}

	a, _ = NewACMEManager(ACMEConfig{Domains: []string{"example.com"}, CacheDir: root, DirectoryURL: LetsEncryptStaging})
	if a.m.Client.DirectoryURL != LetsEncryptStaging || a.CacheDir() != filepath.Join(root, stagingDir) {
		t.Errorf("staging: directory %q, cache %q", a.m.Client.DirectoryURL, a.CacheDir())
	}

	for _, c := range []ACMEConfig{
		{CacheDir: root},
		{Domains: []string{"example.com"}},
		{Domains: []string{"*.example.com"}, CacheDir: root},
		{Domains: []string{"192.0.2.1"}, CacheDir: root},
		{Domains: []string{""}, CacheDir: root},
		{Domains: []string{"localhost"}, CacheDir: root},
	} {
		if _, err := NewACMEManager(c); err == nil {
			t.Errorf("NewACMEManager(%+v) succeeded", c)
		}
	}
}

func TestCacheNamespace(t *testing.T) {
	for url, want := range map[string]string{
		LetsEncryptProduction:                          productionDir,
		LetsEncryptStaging:                             stagingDir,
		"https://ca.internal:9000/acme/acme/directory": "ca.internal-9000-acme-acme-directory",
		"https://../../etc":                            "etc",
		"":                                             "default",
	} {
		if got := cacheNamespace(url); got != want {
			t.Errorf("cacheNamespace(%q) = %q, want %q", url, got, want)
		}
	}
}

func TestACMECacheBelongsToOtherCA(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, productionDir, directoryURLFile), []byte("https://other.example/directory\n"))
	_, err := NewACMEManager(ACMEConfig{Domains: []string{"example.com"}, CacheDir: root})
	if err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Errorf("err = %v", err)
	}
}

func TestACMECacheNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	root := t.TempDir()
	os.Chmod(root, 0o500)
	defer os.Chmod(root, 0o700)
	_, err := NewACMEManager(ACMEConfig{Domains: []string{"example.com"}, CacheDir: root})
	if err == nil {
		t.Fatal("unwritable cache accepted")
	}
}

func TestACMECacheWarnsAboutPermissions(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0o755)
	logger, logs := newLog()
	if _, err := NewACMEManager(ACMEConfig{Domains: []string{"example.com"}, CacheDir: root, Logger: logger}); err != nil {
		t.Fatal(err)
	}
	if len(logs.records("ACME cache directory is accessible by other users; it contains private keys")) != 1 {
		t.Error("no warning about the cache permissions")
	}
}

func TestACMECacheMigration(t *testing.T) {
	root := t.TempDir()
	prod := validCert(t, "example.com", "Let's Encrypt")
	staging := validCert(t, "test.example.com", "(STAGING) Let's Encrypt")
	writeFile(t, filepath.Join(root, "acme_account+key"), []byte("-----BEGIN EC PRIVATE KEY-----\n-----END EC PRIVATE KEY-----\n"))
	writeFile(t, filepath.Join(root, "example.com"), prod)
	writeFile(t, filepath.Join(root, "test.example.com"), staging)
	writeFile(t, filepath.Join(root, "example.com+token"), []byte("x"))
	writeFile(t, filepath.Join(root, "notes.txt"), []byte("not a cache file"))

	// Starting with staging migrates its certificate and leaves the others.
	logger, logs := newLog()
	if _, err := NewACMEManager(ACMEConfig{Domains: []string{"example.com"}, CacheDir: root, DirectoryURL: LetsEncryptStaging, Logger: logger}); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(root, stagingDir, "test.example.com")) || !exists(filepath.Join(root, "example.com")) {
		t.Error("staging run: wrong migration")
	}
	if !exists(filepath.Join(root, "acme_account+key")) {
		t.Error("staging run: account key of the production certificate moved")
	}
	if len(logs.records("ACME cache: leaving a certificate from an older version in place; start with the CA that issued it to migrate it")) != 1 {
		t.Error("staging run: no warning about the production certificate")
	}

	// Starting with production migrates the rest.
	a, err := NewACMEManager(ACMEConfig{Domains: []string{"example.com"}, CacheDir: root})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"example.com", "acme_account+key"} {
		if b, _ := os.ReadFile(filepath.Join(a.CacheDir(), f)); len(b) == 0 {
			t.Errorf("%s not migrated", f)
		}
	}
	for _, f := range []string{"example.com", "example.com+token", "acme_account+key", "test.example.com"} {
		if exists(filepath.Join(root, f)) {
			t.Errorf("%s left in the cache root", f)
		}
	}
	if !exists(filepath.Join(root, "notes.txt")) {
		t.Error("unrelated file removed")
	}
}

func TestStagingCertsLeaveProductionCache(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, productionDir, "example.com"), validCert(t, "example.com", "(STAGING) Let's Encrypt"))
	writeFile(t, filepath.Join(root, productionDir, "www.example.com"), validCert(t, "www.example.com", "Let's Encrypt"))
	if _, err := NewACMEManager(ACMEConfig{Domains: []string{"example.com"}, CacheDir: root}); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(root, productionDir, "example.com")) || !exists(filepath.Join(root, stagingDir, "example.com")) {
		t.Error("staging certificate not moved to the staging cache")
	}
	if !exists(filepath.Join(root, productionDir, "www.example.com")) {
		t.Error("production certificate moved")
	}
}

// fakeACME returns a manager whose certificate requests are answered by
// get, with a controllable clock.
func fakeACME(t *testing.T, get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) (*ACMEManager, *time.Time, *logBuffer) {
	t.Helper()
	logger, logs := newLog()
	a, err := NewACMEManager(ACMEConfig{Domains: []string{"example.com", "www.example.com"}, CacheDir: t.TempDir(), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	a.get = get
	return a, &now, logs
}

func leafCert(t *testing.T, name string, notBefore, notAfter time.Time) *tls.Certificate {
	t.Helper()
	leaf := parseCachedCert(cachedCert(t, name, "Test CA", notBefore, notAfter))
	return &tls.Certificate{Leaf: leaf}
}

func TestACMEBackoff(t *testing.T) {
	var calls atomic.Int32
	var failing atomic.Bool
	failing.Store(true)
	a, now, logs := fakeACME(t, func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		calls.Add(1)
		if failing.Load() {
			return nil, errors.New("acme/autocert: no viable challenge type found")
		}
		return leafCert(t, hello.ServerName, time.Now(), time.Now().Add(90*24*time.Hour)), nil
	})
	hello := ecdsaHello("example.com")

	// expect makes a request and checks whether it reached autocert.
	expect := func(step string, reached bool) {
		t.Helper()
		before := calls.Load()
		a.GetCertificate(hello)
		if got := calls.Load() > before; got != reached {
			t.Errorf("%s: request reached autocert: %v, want %v", step, got, reached)
		}
	}
	expect("first", true)
	expect("during backoff", false)
	*now = now.Add(acmeMinBackoff)
	expect("after 10m", true)
	*now = now.Add(acmeMinBackoff)
	expect("10m after the second failure", false)
	*now = now.Add(acmeMinBackoff)
	expect("20m after the second failure", true)

	failures := logs.records("ACME certificate request failed")
	if len(failures) != 3 {
		t.Fatalf("%d failures logged, want 3", len(failures))
	}
	if r := failures[2]; r["failures"] != 3.0 || r["retry_in"] != float64(40*time.Minute) {
		t.Errorf("third failure: failures %v, retry_in %v", r["failures"], r["retry_in"])
	}
	_, err := a.GetCertificate(hello)
	if err == nil || !strings.Contains(err.Error(), "next attempt in") {
		t.Errorf("error during backoff = %v", err)
	}

	// Other certificates are not affected.
	before := calls.Load()
	a.GetCertificate(ecdsaHello("www.example.com"))
	a.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"}) // RSA-only client
	if calls.Load()-before != 2 {
		t.Error("backoff of example.com blocked other certificates")
	}

	// Recovery.
	failing.Store(false)
	*now = now.Add(acmeMaxBackoff)
	if _, err := a.GetCertificate(hello); err != nil {
		t.Fatal(err)
	}
	if len(logs.records("ACME certificate available again")) != 1 || len(logs.records("ACME certificate ready")) != 1 {
		t.Error("recovery not logged")
	}
	expect("after recovery", true)
}

func TestACMEBackoffIsCapped(t *testing.T) {
	a, now, logs := fakeACME(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return nil, errors.New("fail")
	})
	for range 8 {
		a.GetCertificate(ecdsaHello("example.com"))
		*now = now.Add(acmeMaxBackoff)
	}
	failures := logs.records("ACME certificate request failed")
	if len(failures) != 8 || failures[7]["retry_in"] != float64(acmeMaxBackoff) {
		t.Errorf("%d failures, last retry_in %v", len(failures), failures[len(failures)-1]["retry_in"])
	}
}

func TestACMERateLimitRetryAfter(t *testing.T) {
	rateLimited := &acme.Error{
		StatusCode:  http.StatusTooManyRequests,
		ProblemType: "urn:ietf:params:acme:error:rateLimited",
		Detail:      "too many failed authorizations recently",
		Header:      http.Header{"Retry-After": {"10800"}},
	}
	a, _, logs := fakeACME(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, rateLimited })
	a.GetCertificate(ecdsaHello("example.com"))
	r := logs.records("ACME certificate request failed")
	if len(r) != 1 || r[0]["retry_in"] != float64(3*time.Hour) || !strings.Contains(r[0]["hint"].(string), "rate limit") {
		t.Errorf("records = %v", r)
	}
}

func TestACMEConcurrentFailuresCountOnce(t *testing.T) {
	release := make(chan struct{})
	var waiting sync.WaitGroup
	a, _, logs := fakeACME(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		waiting.Done()
		<-release
		return nil, errors.New("fail")
	})
	var done sync.WaitGroup
	for range 3 {
		waiting.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			a.GetCertificate(ecdsaHello("example.com"))
		}()
	}
	waiting.Wait()
	close(release)
	done.Wait()
	if n := len(logs.records("ACME certificate request failed")); n != 1 {
		t.Errorf("%d failures logged for one request, want 1", n)
	}
	if s := a.certs["example.com"]; s.failures != 1 {
		t.Errorf("failures = %d, want 1", s.failures)
	}
}

func TestACMEPassesThroughOtherHandshakes(t *testing.T) {
	var calls atomic.Int32
	a, _, _ := fakeACME(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		calls.Add(1)
		return nil, errors.New("fail")
	})
	for range 3 {
		a.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example"})
		a.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com", SupportedProtos: []string{acme.ALPNProto}})
	}
	if calls.Load() != 6 || len(a.certs) != 0 {
		t.Errorf("calls %d, tracked %v", calls.Load(), a.certs)
	}
}

// acmeServer serves canned responses for the ACME transport.
func acmeServer(t *testing.T, contentType string, status int, header http.Header, body string) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range header {
			w.Header()[k] = v
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(s.Close)
	return s.URL
}

func roundTrip(t *testing.T, tr http.RoundTripper, url string) string {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestACMEValidationErrorsAreLogged(t *testing.T) {
	a, _, logs := fakeACME(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return nil, errors.New("acme/autocert: unable to satisfy \"…\" for domain \"example.com\": no viable challenge type found")
	})
	authz := `{"status":"invalid","identifier":{"type":"dns","value":"example.com"},"challenges":[` +
		`{"type":"tls-alpn-01","status":"invalid","error":{"type":"urn:ietf:params:acme:error:connection","detail":"203.0.113.10: Timeout during connect (likely firewall problem)","status":400}},` +
		`{"type":"http-01","status":"pending"}]}`
	url := acmeServer(t, "application/json", http.StatusOK, nil, authz)
	tr := newACMETransport(http.DefaultTransport, a)

	if got := roundTrip(t, tr, url); got != authz {
		t.Errorf("body passed on = %q", got)
	}
	roundTrip(t, tr, url) // polled again
	v := logs.records("ACME validation failed")
	if len(v) != 1 || v[0]["challenge"] != "tls-alpn-01" || !strings.Contains(v[0]["detail"].(string), "Timeout during connect") {
		t.Fatalf("validation records = %v", v)
	}

	a.GetCertificate(ecdsaHello("example.com"))
	r := logs.records("ACME certificate request failed")
	if len(r) != 1 {
		t.Fatalf("failure records = %v", r)
	}
	if !strings.Contains(r[0]["validation"].(string), "tls-alpn-01: urn:ietf:params:acme:error:connection: 203.0.113.10: Timeout during connect") {
		t.Errorf("validation = %v", r[0]["validation"])
	}
	if !strings.Contains(r[0]["hint"].(string), "could not connect") {
		t.Errorf("hint = %v", r[0]["hint"])
	}
}

func TestACMEProblemsAreLogged(t *testing.T) {
	a, _, logs := fakeACME(t, nil)
	tr := newACMETransport(http.DefaultTransport, a)

	body := `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many certificates already issued","status":429}`
	url := acmeServer(t, "application/problem+json", http.StatusTooManyRequests, http.Header{"Retry-After": {"3600"}}, body)
	if got := roundTrip(t, tr, url); got != body {
		t.Errorf("body passed on = %q", got)
	}
	r := logs.records("ACME request rejected")
	if len(r) != 1 || r[0]["retry_after"] != "3600" || r[0]["problem"] != "urn:ietf:params:acme:error:rateLimited" {
		t.Errorf("records = %v", r)
	}

	// Bad nonces are retried by the client and not worth a warning.
	roundTrip(t, tr, acmeServer(t, "application/problem+json", http.StatusBadRequest, nil, `{"type":"urn:ietf:params:acme:error:badNonce"}`))
	if len(logs.records("ACME request rejected")) != 1 {
		t.Error("badNonce logged")
	}
}

func TestACMECheckExpiry(t *testing.T) {
	var cert atomic.Pointer[tls.Certificate]
	a, now, logs := fakeACME(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert.Load(), nil })
	issued := now.Add(-80 * 24 * time.Hour)
	cert.Store(leafCert(t, "example.com", issued, issued.Add(90*24*time.Hour)))

	a.check()
	a.check()
	if n := len(logs.records("ACME certificate not renewed yet")); n != 2 { // one per domain
		t.Errorf("%d warnings, want one per domain", n)
	}
	*now = now.Add(25 * time.Hour)
	a.check()
	if n := len(logs.records("ACME certificate not renewed yet")); n != 4 {
		t.Errorf("%d warnings after a day, want 4", n)
	}
	*now = now.Add(20 * 24 * time.Hour)
	a.check()
	if n := len(logs.records("ACME certificate expired")); n != 2 {
		t.Errorf("%d expiry errors, want 2", n)
	}

	// A fresh certificate is fine.
	cert.Store(leafCert(t, "example.com", *now, now.Add(90*24*time.Hour)))
	*now = now.Add(2 * time.Hour)
	a.check()
	if n := len(logs.records("ACME certificate expired")); n != 2 {
		t.Errorf("fresh certificate reported as expired")
	}
}

func TestACMECheckRequestsECDSACertificates(t *testing.T) {
	var mu sync.Mutex
	var names []string
	a, _, logs := fakeACME(t, func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if !supportsECDSA(hello) {
			t.Error("check requested an RSA certificate")
		}
		mu.Lock()
		names = append(names, hello.ServerName)
		mu.Unlock()
		return leafCert(t, hello.ServerName, time.Now(), time.Now().Add(90*24*time.Hour)), nil
	})
	a.check()
	a.check()
	if strings.Join(names, ",") != "example.com,www.example.com,example.com,www.example.com" {
		t.Errorf("requested %v", names)
	}
	if n := len(logs.records("ACME certificate ready")); n != 2 {
		t.Errorf("%d ready records, want one per certificate", n)
	}
}

func TestACMECacheReportsStoredCertificates(t *testing.T) {
	logger, logs := newLog()
	var stored []string
	c := &acmeCache{
		DirCache: "",
		onCert:   func(key string, _ *x509.Certificate) { stored = append(stored, key) },
		logger:   logger,
	}
	c.DirCache = autocert.DirCache(t.TempDir())
	ctx := context.Background()
	c.Put(ctx, "example.com", validCert(t, "example.com", "Let's Encrypt"))
	c.Put(ctx, "example.com+token", validCert(t, "example.com", "Let's Encrypt"))
	c.Put(ctx, "abc+http-01", []byte("token"))
	c.Put(ctx, "acme_account+key", []byte("key"))
	if strings.Join(stored, ",") != "example.com" {
		t.Errorf("stored = %v", stored)
	}

	// Write errors are logged; autocert ignores them.
	c.DirCache = autocert.DirCache(filepath.Join(t.TempDir(), "file"))
	os.WriteFile(string(c.DirCache), nil, 0o600) // a file, not a directory
	if c.Put(ctx, "example.com", []byte("x")) == nil || len(logs.records("cannot write ACME cache; certificates will be requested again after a restart")) != 1 {
		t.Error("write error not reported")
	}
}
