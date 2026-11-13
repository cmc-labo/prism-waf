//go:build e2e

// Package e2e tests the prismwaf binary from the outside: each test builds
// and starts it with command line flags in front of a test backend and
// sends it real HTTP requests.
//
//	go test -tags e2e ./e2e/
//
// See docs/testing.md for the optional browser and live tests.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// binary is the prismwaf binary built by TestMain.
var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "prismwaf-e2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binary = filepath.Join(dir, "prismwaf")
	build := exec.Command("go", "build", "-o", binary, "../cmd/prismwaf")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building prismwaf:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// User-Agents of the tests.
const (
	chromeUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	curlUA     = "curl/8.5.0"
	googleUA   = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	gptbotUA   = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"
	sqlmapUA   = "sqlmap/1.8#stable (https://sqlmap.org)"
	uptimeUA   = "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)"
	headlessUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/130.0.0.0 Safari/537.36"
)

// browserHeaders are the headers of a browser navigation, without fetch
// metadata and client hints, which browsers send only over HTTPS.
var browserHeaders = map[string]string{
	"User-Agent":      chromeUA,
	"Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
	"Accept-Language": "ja,en-US;q=0.9",
	"Accept-Encoding": "gzip, deflate, br",
}

// backendHit is what the backend saw of a request.
type backendHit struct {
	URI      string `json:"uri"`
	Score    string `json:"score"`
	Category string `json:"category"`
	Verified string `json:"verified"`
}

// startBackend starts a backend that answers every request with a
// backendHit as JSON.
func startBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(backendHit{
			URI:      r.URL.RequestURI(),
			Score:    r.Header.Get("X-Prismwaf-Bot-Score"),
			Category: r.Header.Get("X-Prismwaf-Bot-Category"),
			Verified: r.Header.Get("X-Prismwaf-Bot-Verified"),
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// waf is a running prismwaf process.
type waf struct {
	URL      string
	auditLog string
	stderr   *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// wafOptions configures startWAF.
type wafOptions struct {
	args []string
	env  []string
	// tls serves HTTPS with a self-signed certificate.
	tls bool
	// backend is the backend URL; empty starts a new backend.
	backend string
}

// startWAF starts prismwaf with -bot-protection and the options, and waits
// until it accepts connections. The process is stopped at the end of the
// test.
func startWAF(t *testing.T, o wafOptions) *waf {
	t.Helper()
	if o.backend == "" {
		o.backend = startBackend(t).URL
	}
	dir := t.TempDir()
	addr := freeAddr(t)
	w := &waf{URL: "http://" + addr, auditLog: filepath.Join(dir, "audit.jsonl"), stderr: &syncBuffer{}}
	args := []string{"-listen", addr, "-backend", o.backend, "-audit-log", w.auditLog, "-bot-protection"}
	if o.tls {
		cert, key := selfSigned(t, dir, "localhost", "127.0.0.1")
		args = append(args, "-tls-cert", cert, "-tls-key", key)
		w.URL = "https://" + addr
	}
	cmd := exec.Command(binary, append(args, o.args...)...)
	cmd.Env = append(os.Environ(), o.env...)
	cmd.Stdout, cmd.Stderr = w.stderr, w.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-exited
		}
		if t.Failed() {
			t.Logf("prismwaf output:\n%s", w.stderr)
		}
	})
	for deadline := time.Now().Add(10 * time.Second); ; {
		select {
		case err := <-exited:
			t.Fatalf("prismwaf exited: %v\n%s", err, w.stderr)
		default:
		}
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return w
		}
		if time.Now().After(deadline) {
			t.Fatalf("prismwaf did not start\n%s", w.stderr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// runWAF runs prismwaf until it exits, for flags that are rejected.
func runWAF(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, append([]string{"-listen", freeAddr(t)}, args...)...).CombinedOutput()
	return string(out), err
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// auditEvent is the part of an audit event the tests check.
type auditEvent struct {
	ID       string `json:"id"`
	Reason   string `json:"reason"`
	Action   string `json:"action"`
	ClientIP string `json:"client_ip"`
	Bot      *struct {
		Score     int      `json:"score"`
		Signals   []string `json:"signals"`
		Category  string   `json:"category"`
		Name      string   `json:"name"`
		Verified  bool     `json:"verified"`
		Challenge string   `json:"challenge"`
		Client    string   `json:"client"`
	} `json:"bot"`
}

// events returns the audit events written so far.
func (w *waf) events(t *testing.T) []auditEvent {
	t.Helper()
	f, err := os.Open(w.auditLog)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var events []auditEvent
	s := bufio.NewScanner(f)
	for s.Scan() {
		var e auditEvent
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			t.Fatalf("audit log: %v: %s", err, s.Bytes())
		}
		events = append(events, e)
	}
	return events
}

// eventByID waits for the audit event with an ID; audit events are written
// after the response.
func (w *waf) eventByID(t *testing.T, id string) auditEvent {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, e := range w.events(t) {
			if e.ID == id {
				return e
			}
		}
	}
	t.Fatalf("no audit event %q in %+v", id, w.events(t))
	return auditEvent{}
}

// waitLog waits until a line of the output of prismwaf contains all parts.
func (w *waf) waitLog(t *testing.T, parts ...string) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, line := range strings.Split(w.stderr.String(), "\n") {
			found := true
			for _, p := range parts {
				found = found && strings.Contains(line, p)
			}
			if found {
				return
			}
		}
	}
	t.Errorf("no log line with %q in\n%s", parts, w.stderr)
}

// client is an HTTP client with a cookie jar that does not follow
// redirects, like a browser seen request by request.
type client struct {
	t       *testing.T
	base    *url.URL
	hc      *http.Client
	headers map[string]string
}

func (w *waf) client(t *testing.T, headers map[string]string) *client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	base, _ := url.Parse(w.URL)
	return &client{t: t, base: base, headers: headers, hc: &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
		// Send only the headers of the test, without Accept-Encoding.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// as returns a copy of the client with other headers and the same cookies.
func (c *client) as(headers map[string]string) *client {
	c2 := *c
	c2.headers = headers
	return &c2
}

// response is a response with its body read.
type response struct {
	*http.Response
	body string
}

func (c *client) do(method, path string, body url.Values, extra ...string) response {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = strings.NewReader(body.Encode())
	}
	req, err := http.NewRequest(method, c.base.String()+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		req.Header.Set(extra[i], extra[i+1])
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return response{resp, string(b)}
}

func (c *client) get(path string, extra ...string) response {
	c.t.Helper()
	return c.do("GET", path, nil, extra...)
}

// hit decodes what the backend saw; the request must have reached it.
func (r response) hit(t *testing.T) backendHit {
	t.Helper()
	var h backendHit
	if r.StatusCode != http.StatusOK || json.Unmarshal([]byte(r.body), &h) != nil {
		t.Fatalf("not served by the backend: %d\n%s", r.StatusCode, r.body)
	}
	return h
}

// cookie returns the clearance cookie the response set, or nil.
func (r response) cookie() *http.Cookie {
	for _, c := range r.Cookies() {
		if c.Name == "prismwaf_clearance" {
			return c
		}
	}
	return nil
}

var (
	inputRe   = regexp.MustCompile(`<input type="hidden" name="(\w+)" value="([^"]*)">`)
	eventIDRe = regexp.MustCompile(`Event ID: (\S+)`)
	nonceRe   = regexp.MustCompile(`'nonce-([^']+)'`)
)

// challenge is a challenge page.
type challenge struct {
	token, redirect string
	captcha         bool
}

// parseChallenge checks that the response is a challenge page and returns
// its form.
func parseChallenge(t *testing.T, r response) challenge {
	t.Helper()
	if r.StatusCode != http.StatusForbidden || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("not a challenge page: %d %s\n%s", r.StatusCode, r.Header.Get("Content-Type"), r.body)
	}
	fields := map[string]string{}
	for _, m := range inputRe.FindAllStringSubmatch(r.body, -1) {
		fields[m[1]] = htmlUnescape(m[2])
	}
	_, captcha := fields["captcha"]
	return challenge{token: fields["c"], redirect: fields["r"], captcha: captcha}
}

func htmlUnescape(s string) string {
	return strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&#34;", `"`, "&#39;", "'", "&#43;", "+").Replace(s)
}

// solve finds the nonce of a proof-of-work token "issued.difficulty.seed.mac".
func solve(t *testing.T, token string) string {
	t.Helper()
	f := strings.Split(token, ".")
	if len(f) != 4 {
		t.Fatalf("invalid challenge token %q", token)
	}
	d, _ := strconv.Atoi(f[1])
	for n := 0; ; n++ {
		h := sha256.Sum256([]byte(f[2] + strconv.Itoa(n)))
		if bits.LeadingZeros32(uint32(h[0])<<24|uint32(h[1])<<16|uint32(h[2])<<8|uint32(h[3])) >= d {
			return strconv.Itoa(n)
		}
	}
}

// pass gets a clearance cookie for the client by solving the proof-of-work
// challenge of path, and returns the response of the solution.
func (c *client) pass(path string, extra ...string) response {
	c.t.Helper()
	ch := parseChallenge(c.t, c.get(path, extra...))
	if ch.captcha {
		c.t.Fatalf("%s: CAPTCHA instead of proof of work", path)
	}
	return c.do("POST", "/.prismwaf/challenge", url.Values{"c": {ch.token}, "r": {ch.redirect}, "n": {solve(c.t, ch.token)}}, extra...)
}

// pki is a test certificate authority.
type pki struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	caFile string
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PrismWAF E2E CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	p := &pki{cert: cert, key: key, caFile: filepath.Join(t.TempDir(), "ca.pem")}
	os.WriteFile(p.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	return p
}

// issue returns a certificate for the names signed by the CA.
func (p *pki) issue(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// selfSigned writes a certificate and key for the names to dir.
func selfSigned(t *testing.T, dir string, names ...string) (certFile, keyFile string) {
	t.Helper()
	c := newPKI(t).issue(t, names...)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}), 0o644)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certFile, keyFile
}

// writeFile writes a file to a temporary directory and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// with returns a copy of headers with more headers set.
func with(headers map[string]string, kv ...string) map[string]string {
	h := make(map[string]string, len(headers)+len(kv)/2)
	for k, v := range headers {
		h[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		h[kv[i]] = kv[i+1]
	}
	return h
}
