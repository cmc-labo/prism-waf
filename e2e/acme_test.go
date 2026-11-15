//go:build e2e

package e2e

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The ACME tests run prismwaf against fakeCA (acmeca_test.go) and check
// the expiry notifications it sends to a webhook and a command.

const acmeDomain = "app.example"

// notification is what a webhook or a command receives, in any format.
type notification struct {
	Time     time.Time  `json:"time"`
	Event    string     `json:"event"`
	Severity string     `json:"severity"`
	Host     string     `json:"host"`
	Message  string     `json:"message"`
	Domain   string     `json:"domain"`
	Issuer   string     `json:"issuer"`
	Serial   string     `json:"serial"`
	NotAfter *time.Time `json:"not_after"`
	Error    string     `json:"error"`
	Failures int        `json:"failures"`
	RetryAt  *time.Time `json:"retry_at"`
	Text     string     `json:"text"`    // json and slack
	Content  string     `json:"content"` // discord

	at     time.Time         // when it was received
	header http.Header       // of a webhook
	raw    map[string]any    // the body
	env    map[string]string // PRISMWAF_* variables of a command
}

// webhook is a webhook endpoint that records the notifications it gets.
// It answers with the statuses in respond, one per request, then 200;
// a status of 0 makes it hang until the client gives up.
type webhook struct {
	URL string

	mu      sync.Mutex
	respond []int
	got     []notification
	tries   int
	changed chan struct{}
}

func startWebhook(t *testing.T, respond ...int) *webhook {
	t.Helper()
	h := &webhook{respond: respond, changed: make(chan struct{}, 1000)}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	h.URL = srv.URL + "/hooks/T000/SECRETTOKEN"
	return h
}

// startTLSWebhook is a webhook served over HTTPS with a certificate for
// 127.0.0.1 from its own CA, whose file it returns.
func startTLSWebhook(t *testing.T) (*webhook, string) {
	t.Helper()
	h := &webhook{changed: make(chan struct{}, 1000)}
	ca := newPKI(t)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.issue(t, "127.0.0.1")}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h.URL = srv.URL + "/hooks/T000/SECRETTOKEN"
	return h, ca.caFile
}

func (h *webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.tries++
	status := http.StatusOK
	if len(h.respond) > 0 {
		status, h.respond = h.respond[0], h.respond[1:]
	}
	if status == http.StatusOK {
		n := notification{at: time.Now(), header: r.Header.Clone()}
		if r.Method != http.MethodPost || r.URL.Path != "/hooks/T000/SECRETTOKEN" {
			n.Event = "unexpected " + r.Method + " " + r.URL.Path
		}
		json.Unmarshal(body, &n)
		json.Unmarshal(body, &n.raw)
		h.got = append(h.got, n)
	}
	h.mu.Unlock()
	h.changed <- struct{}{}
	switch status {
	case 0:
		<-r.Context().Done()
	case http.StatusOK:
		w.Write([]byte("ok"))
	default:
		http.Error(w, fmt.Sprintf("busy (%d)", status), status)
	}
}

// wait waits until the webhook has received n notifications.
func (h *webhook) wait(t *testing.T, n int, timeout time.Duration) []notification {
	t.Helper()
	deadline := time.After(timeout)
	for {
		h.mu.Lock()
		got := slices.Clone(h.got)
		h.mu.Unlock()
		if len(got) >= n {
			return got
		}
		select {
		case <-h.changed:
		case <-deadline:
			t.Fatalf("webhook: got %d notifications in %s, want %d: %+v", len(got), timeout, n, got)
		}
	}
}

func (h *webhook) received() []notification {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.got)
}

func (h *webhook) attempts() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tries
}

// command is a notification command that records the events it gets on
// standard input and in its environment.
type command struct {
	dir  string
	line string // for -acme-notify-command
}

func newCommand(t *testing.T) *command {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "notify.sh")
	os.WriteFile(script, []byte(`#!/bin/sh
set -e
dir=$(dirname "$0")
n=$(cat "$dir/count" 2>/dev/null || echo 0)
echo $((n + 1)) > "$dir/count"
cat > "$dir/stdin.$n"
env | grep '^PRISMWAF_' > "$dir/tmp"
mv "$dir/tmp" "$dir/env.$n" # env.N appears complete, after stdin.N
`), 0o700)
	return &command{dir: dir, line: script}
}

// received returns the events the command got.
func (c *command) received(t *testing.T) []notification {
	t.Helper()
	var got []notification
	for i := 0; ; i++ {
		stdin, err := os.ReadFile(filepath.Join(c.dir, fmt.Sprint("stdin.", i)))
		if err != nil {
			return got
		}
		env, err := os.ReadFile(filepath.Join(c.dir, fmt.Sprint("env.", i)))
		if err != nil {
			return got // stdin.N is being written
		}
		fi, _ := os.Stat(filepath.Join(c.dir, fmt.Sprint("env.", i)))
		n := notification{at: fi.ModTime(), env: map[string]string{}}
		if err := json.Unmarshal(stdin, &n); err != nil {
			t.Fatalf("command: standard input is not JSON: %v: %s", err, stdin)
		}
		json.Unmarshal(stdin, &n.raw)
		sc := bufio.NewScanner(strings.NewReader(string(env)))
		for sc.Scan() {
			k, v, _ := strings.Cut(sc.Text(), "=")
			n.env[k] = v
		}
		got = append(got, n)
	}
}

func (c *command) wait(t *testing.T, n int, timeout time.Duration) []notification {
	t.Helper()
	for deadline := time.Now().Add(timeout); ; time.Sleep(50 * time.Millisecond) {
		if got := c.received(t); len(got) >= n {
			return got
		} else if time.Now().After(deadline) {
			t.Fatalf("command: got %d notifications in %s, want %d: %+v", len(got), timeout, n, got)
		}
	}
}

// acmeWAF is prismwaf with certificates from a fakeCA.
type acmeWAF struct {
	*waf
	addr     string // HTTPS
	httpAddr string // -http-redirect, if any
	cache    string
}

type acmeOptions struct {
	domains  string // default acmeDomain
	cache    string // default a new directory
	http01   bool   // listen for HTTP-01 with -http-redirect
	args     []string
	listen   string
	httpAddr string
}

func startACMEWAF(t *testing.T, ca *fakeCA, o acmeOptions) *acmeWAF {
	t.Helper()
	if o.domains == "" {
		o.domains = acmeDomain
	}
	if o.cache == "" {
		o.cache = filepath.Join(t.TempDir(), "acme")
	}
	if o.listen == "" {
		o.listen = freeAddr(t)
	}
	w := &acmeWAF{addr: o.listen, cache: o.cache}
	args := []string{"-acme-domains", o.domains, "-acme-cache", o.cache, "-acme-directory", ca.URL}
	if o.http01 {
		w.httpAddr = o.httpAddr
		if w.httpAddr == "" {
			w.httpAddr = freeAddr(t)
		}
		args = append(args, "-http-redirect", w.httpAddr)
	}
	ca.target(w.httpAddr, w.addr)
	w.waf = startWAF(t, wafOptions{listen: o.listen, args: append(args, o.args...)})
	w.URL = "https://" + o.listen
	return w
}

// handshake connects with TLS to a domain and returns the certificate
// prismwaf presents, or the error of verifying it with the CA.
func (w *acmeWAF) handshake(t *testing.T, ca *fakeCA, domain string) (*x509.Certificate, error) {
	t.Helper()
	conn, err := tls.Dial("tcp", w.addr, &tls.Config{ServerName: domain, InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err = certs[0].Verify(x509.VerifyOptions{DNSName: domain, Roots: ca.pool(), Intermediates: inter})
	return certs[0], err
}

// get sends a request over HTTPS to domain, trusting the CA.
func (w *acmeWAF) get(t *testing.T, ca *fakeCA, domain, path string) (*http.Response, error) {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: domain, RootCAs: ca.pool()},
	}}
	req, _ := http.NewRequest("GET", "https://"+w.addr+path, nil)
	req.Host = domain
	req.Header = http.Header{"User-Agent": {chromeUA}, "Accept": {"text/html"}}
	resp, err := c.Do(req)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return resp, err
}

// waitLogFor is waitLog with a timeout, failing the test at once.
func (w *waf) waitLogFor(t *testing.T, timeout time.Duration, parts ...string) string {
	t.Helper()
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if line := w.logLine(parts...); line != "" {
			return line
		}
	}
	t.Fatalf("no log line with %q within %s in\n%s", parts, timeout, w.stderr)
	return ""
}

// logLine returns the first line of the output with all parts, or "".
func (w *waf) logLine(parts ...string) string {
	for _, line := range strings.Split(w.stderr.String(), "\n") {
		found := true
		for _, p := range parts {
			found = found && strings.Contains(line, p)
		}
		if found {
			return line
		}
	}
	return ""
}

func notifyArgs(h *webhook, format string, c *command) []string {
	var args []string
	if h != nil {
		args = append(args, "-acme-notify-webhook", h.URL, "-acme-notify-webhook-format", format)
	}
	if c != nil {
		args = append(args, "-acme-notify-command", c.line)
	}
	return args
}

func hostname(t *testing.T) string {
	t.Helper()
	h, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// checkEvent checks the fields every notification has, and those of the
// json format or a command.
func checkEvent(t *testing.T, n notification, event, severity string) {
	t.Helper()
	if n.Event != event || n.Severity != severity {
		t.Errorf("got %s/%s, want %s/%s: %+v", n.Event, n.Severity, event, severity, n)
	}
	if n.Host != hostname(t) || n.Message == "" || n.at.Sub(n.Time) > 75*time.Second || n.Time.Location() != time.UTC {
		t.Errorf("host, message or time wrong: %+v", n)
	}
	text := fmt.Sprintf("[PrismWAF %s] %s: %s", n.Host, strings.ToUpper(severity), n.Message)
	if n.env != nil {
		for k, want := range map[string]string{
			"PRISMWAF_EVENT": event, "PRISMWAF_SEVERITY": severity, "PRISMWAF_HOST": n.Host,
			"PRISMWAF_MESSAGE": n.Message, "PRISMWAF_TEXT": text, "PRISMWAF_DOMAIN": n.Domain,
			"PRISMWAF_TIME": n.Time.Format(time.RFC3339), "PRISMWAF_ERROR": n.Error,
		} {
			if n.env[k] != want {
				t.Errorf("%s=%q, want %q", k, n.env[k], want)
			}
		}
		if _, ok := n.raw["text"]; ok {
			t.Errorf("command input has a text field: %v", n.raw)
		}
	} else {
		if n.Text != text {
			t.Errorf("text %q, want %q", n.Text, text)
		}
		if ct, ua := n.header.Get("Content-Type"), n.header.Get("User-Agent"); ct != "application/json" || ua != "PrismWAF" {
			t.Errorf("Content-Type %q, User-Agent %q", ct, ua)
		}
	}
}

// TestACMECertificate obtains certificates from the CA with each challenge
// type, and checks that no notification is sent when all is well and that
// a restart uses the cache.
func TestACMECertificate(t *testing.T) {
	for _, tc := range []struct {
		name       string
		challenges []string
		http01     bool
	}{
		{"TLS-ALPN-01", []string{"tls-alpn-01", "http-01"}, false},
		{"HTTP-01", []string{"http-01"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := startCA(t)
			ca.challenges = tc.challenges
			hook, cmd := startWebhook(t), newCommand(t)
			w := startACMEWAF(t, ca, acmeOptions{http01: tc.http01, args: notifyArgs(hook, "json", cmd)})

			w.waitLogFor(t, 10*time.Second, "ACME certificate obtained", "certificate="+acmeDomain)
			cert, err := w.handshake(t, ca, acmeDomain)
			if err != nil {
				t.Fatal(err)
			}
			if issued := ca.certs(); len(issued) != 1 || !issued[0].Equal(cert) {
				t.Errorf("served %v, CA issued %v", cert.SerialNumber, issued)
			}
			if resp, err := w.get(t, ca, acmeDomain, "/hello"); err != nil || resp.StatusCode != http.StatusOK {
				t.Errorf("GET over HTTPS: %v %v", resp, err)
			}
			if tc.http01 {
				// Other requests on the HTTP port are redirected.
				noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				resp, err := noRedirect.Get("http://" + w.httpAddr + "/a?b=1")
				if err != nil || resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != w.URL+"/a?b=1" {
					t.Errorf("HTTP: %v %v", resp, err)
				} else {
					resp.Body.Close()
				}
			}
			w.waitLog(t, "ACME certificate notifications enabled", "webhook http://127.0.0.1:")
			// The certificate was checked right after it was obtained.
			time.Sleep(time.Second)
			if got, gotCmd := hook.received(), cmd.received(t); len(got)+len(gotCmd) > 0 {
				t.Errorf("notifications for a valid certificate: %+v %+v", got, gotCmd)
			}
			for _, line := range strings.Split(w.stderr.String(), "\n") {
				// The harness connects without TLS to see that prismwaf is up.
				if strings.Contains(line, "level=WARN") && !strings.Contains(line, "TLS handshake error") {
					t.Errorf("warning: %s", line)
				}
			}

			// A restart uses the cached certificate.
			w.stop()
			orders := ca.count("order")
			w2 := startACMEWAF(t, ca, acmeOptions{cache: w.cache, http01: tc.http01, args: notifyArgs(hook, "json", cmd)})
			w2.waitLogFor(t, 5*time.Second, "ACME certificate ready", "serial="+cert.SerialNumber.Text(16))
			if cert2, err := w2.handshake(t, ca, acmeDomain); err != nil || !cert2.Equal(cert) {
				t.Errorf("after restart: %v", err)
			}
			if n := ca.count("order"); n != orders {
				t.Errorf("%d new orders after restart", n-orders)
			}
		})
	}
}

// TestACMENotifyUnavailable starts with a CA that cannot validate the
// domains: each gets certificate_unavailable at the webhook and from the
// command, and clients are not let through to the CA during the backoff.
func TestACMENotifyUnavailable(t *testing.T) {
	ca := startCA(t)
	ca.setMode("invalid")
	hook, cmd := startWebhook(t), newCommand(t)
	start := time.Now()
	w := startACMEWAF(t, ca, acmeOptions{domains: "a.example,b.example", args: notifyArgs(hook, "json", cmd)})

	got := hook.wait(t, 2, 10*time.Second)
	gotCmd := cmd.wait(t, 2, 10*time.Second)
	for i, domain := range []string{"a.example", "b.example"} {
		for _, n := range []notification{got[i], gotCmd[i]} {
			checkEvent(t, n, "certificate_unavailable", "critical")
			if n.Domain != domain || n.Failures != 1 || n.Error == "" || n.NotAfter != nil {
				t.Errorf("%s: %+v", domain, n)
			}
			// The next attempt is 10 minutes after the failure.
			if n.RetryAt == nil || n.RetryAt.Sub(start) < 10*time.Minute-time.Second || n.RetryAt.Sub(start) > 10*time.Minute+5*time.Second {
				t.Errorf("%s: retry_at %v, started %v", domain, n.RetryAt, start)
			}
			want := "There is no certificate for " + domain + ": requesting one failed; HTTPS connections to it fail. Next attempt at " + n.RetryAt.Format(time.RFC3339)
			if !strings.HasPrefix(n.Message, want) {
				t.Errorf("message %q", n.Message)
			}
		}
		if env := gotCmd[i].env; env["PRISMWAF_FAILURES"] != "1" || env["PRISMWAF_NOT_AFTER"] != "" {
			t.Errorf("command environment %v", env)
		}
	}
	w.waitLog(t, "level=WARN", "ACME validation failed", "domain=a.example", "challenge=tls-alpn-01", "Timeout during connect", "hint=")
	w.waitLog(t, "level=INFO", "notification sent", "event=certificate_unavailable", "domain=b.example", "target=command")

	// Clients get no certificate, and do not make prismwaf ask the CA
	// again before the retry time.
	orders := ca.count("order")
	for range 3 {
		if _, err := w.handshake(t, ca, "a.example"); err == nil {
			t.Error("handshake succeeded without a certificate")
		}
	}
	if n := ca.count("order"); n != orders {
		t.Errorf("%d orders from client handshakes during the backoff", n-orders)
	}
	time.Sleep(500 * time.Millisecond)
	if n := len(hook.received()) + len(cmd.received(t)); n != 4 {
		t.Errorf("%d notifications, want 4", n)
	}
}

// TestACMENotifyCommandIsNotInjected passes an error of the CA that
// contains shell syntax to a command that uses it unquoted, with the slack
// format at the webhook.
func TestACMENotifyCommandIsNotInjected(t *testing.T) {
	ca := startCA(t)
	ca.setMode("reject")
	hook := startWebhook(t)
	dir := t.TempDir()
	line := `cd ` + dir + ` && printf '%s\n' "$PRISMWAF_ERROR" > error.txt && echo $PRISMWAF_MESSAGE > message.txt`
	w := startACMEWAF(t, ca, acmeOptions{args: append(notifyArgs(hook, "slack", nil), "-acme-notify-command", line)})

	got := hook.wait(t, 1, 10*time.Second)
	if len(got[0].raw) != 1 || !strings.HasPrefix(got[0].Text, "[PrismWAF "+hostname(t)+"] CRITICAL: There is no certificate for app.example: ") {
		t.Errorf("slack payload %v", got[0].raw)
	}
	w.waitLogFor(t, 5*time.Second, "notification sent", "target=command")
	b, _ := os.ReadFile(filepath.Join(dir, "error.txt"))
	if !strings.Contains(string(b), rejectDetail) {
		t.Errorf("PRISMWAF_ERROR=%q, want the detail %q", b, rejectDetail)
	}
	w.waitLog(t, "ACME request rejected", "problem=urn:ietf:params:acme:error:rejectedIdentifier", "hint=")
	for _, d := range []string{dir, "."} {
		if m, _ := filepath.Glob(filepath.Join(d, "PWNED*")); len(m) > 0 {
			t.Errorf("the shell ran code from the CA's error: %v", m)
			for _, f := range m {
				os.Remove(f)
			}
		}
	}
}

// slow skips a test that waits for a check or a retry with -short, and
// runs it in parallel with the other slow tests.
func slow(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("waits for the checks of prismwaf, a minute apart")
	}
	t.Parallel()
}

// TestACMENotifyExpiring starts with a cached certificate that should have
// been renewed and a CA that cannot validate. Renewal is attempted at
// once; when it has failed, certificate_expiring is sent at the next
// check, a minute later, in the discord format to the webhook, and the
// old certificate keeps being served.
func TestACMENotifyExpiring(t *testing.T) {
	slow(t)
	ca := startCA(t)
	ca.setMode("invalid")
	cache := filepath.Join(t.TempDir(), "acme")
	now := time.Now()
	old := ca.cacheCert(t, cache, acmeDomain, now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour))
	hook, cmd := startWebhook(t), newCommand(t)
	w := startACMEWAF(t, ca, acmeOptions{cache: cache, args: notifyArgs(hook, "discord", cmd)})

	// Renewal is attempted and fails, without a notification yet.
	w.waitLogFor(t, 5*time.Second, "ACME validation failed", "domain=app.example")
	time.Sleep(time.Second)
	if n := len(hook.received()) + len(cmd.received(t)); n > 0 {
		t.Errorf("%d notifications at the first check", n)
	}
	if cert, _ := w.handshake(t, ca, acmeDomain); cert == nil || !cert.Equal(old) {
		t.Errorf("the old certificate is not served")
	}

	got := hook.wait(t, 1, 70*time.Second)
	if d := got[0].at.Sub(now); d < 59*time.Second || d > 65*time.Second {
		t.Errorf("notified %s after the start, want a minute", d)
	}
	n := cmd.wait(t, 1, 5*time.Second)[0]
	checkEvent(t, n, "certificate_expiring", "warning")
	notAfter := old.NotAfter.UTC().Format(time.RFC3339)
	wantMsg := "The certificate for app.example expires in 10 days (" + notAfter + ") and has not been renewed."
	if !strings.HasPrefix(n.Message, wantMsg) {
		t.Errorf("message %q, want %q…", n.Message, wantMsg)
	}
	if n.Domain != acmeDomain || n.Issuer != old.Issuer.String() || n.Serial != old.SerialNumber.Text(16) ||
		n.NotAfter == nil || !n.NotAfter.Equal(old.NotAfter.Truncate(time.Second)) || n.Failures != 0 || n.RetryAt != nil {
		t.Errorf("event %+v", n)
	}
	if n.env["PRISMWAF_NOT_AFTER"] != notAfter {
		t.Errorf("PRISMWAF_NOT_AFTER=%q", n.env["PRISMWAF_NOT_AFTER"])
	}
	if len(got[0].raw) != 1 || got[0].Content != fmt.Sprintf("[PrismWAF %s] WARNING: %s", hostname(t), n.Message) {
		t.Errorf("discord payload %v", got[0].raw)
	}
	w.waitLog(t, "level=WARN", "ACME certificate not renewed yet", "expires_in=240h0m0s")
	if cert, _ := w.handshake(t, ca, acmeDomain); cert == nil || !cert.Equal(old) {
		t.Errorf("the old certificate is not served")
	}
}

// TestACMERenewalAtStartup starts with a cached certificate that should
// have been renewed while prismwaf was not running, and a CA that works:
// the certificate is renewed at once, without a notification, also at the
// next check.
func TestACMERenewalAtStartup(t *testing.T) {
	slow(t)
	ca := startCA(t)
	cache := filepath.Join(t.TempDir(), "acme")
	now := time.Now()
	old := ca.cacheCert(t, cache, acmeDomain, now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour))
	hook, cmd := startWebhook(t), newCommand(t)
	w := startACMEWAF(t, ca, acmeOptions{cache: cache, args: notifyArgs(hook, "json", cmd)})

	w.waitLogFor(t, 10*time.Second, "ACME certificate obtained")
	if cert, err := w.handshake(t, ca, acmeDomain); err != nil || cert.Equal(old) {
		t.Errorf("not renewed: %v", err)
	}
	time.Sleep(time.Until(now.Add(65 * time.Second)))
	if got := append(hook.received(), cmd.received(t)...); len(got) > 0 {
		t.Errorf("notified although renewal succeeded: %+v", got)
	}
	if line := w.logLine("ACME certificate not renewed yet"); line != "" {
		t.Errorf("logged: %s", line)
	}
	if n := len(ca.certs()); n != 1 {
		t.Errorf("%d certificates issued, want 1", n)
	}
}

// TestACMENotifyExpired runs until a certificate that is not renewed
// expires: certificate_expiring at the second check is followed by
// certificate_expired at the third, a minute later.
func TestACMENotifyExpired(t *testing.T) {
	slow(t)
	ca := startCA(t)
	ca.setMode("invalid")
	cache := filepath.Join(t.TempDir(), "acme")
	now := time.Now()
	old := ca.cacheCert(t, cache, acmeDomain, now.Add(-10*time.Minute), now.Add(70*time.Second))
	hook, cmd := startWebhook(t), newCommand(t)
	w := startACMEWAF(t, ca, acmeOptions{cache: cache, args: notifyArgs(hook, "json", cmd)})

	got := hook.wait(t, 1, 70*time.Second)
	checkEvent(t, got[0], "certificate_expiring", "warning")
	got = hook.wait(t, 2, 70*time.Second)
	checkEvent(t, got[1], "certificate_expired", "critical")
	notAfter := old.NotAfter.UTC().Format(time.RFC3339)
	if want := "The certificate for app.example expired at " + notAfter + ". Clients get certificate errors."; !strings.HasPrefix(got[1].Message, want) {
		t.Errorf("message %q", got[1].Message)
	}
	if d := got[1].at.Sub(got[0].at); d < 55*time.Second || d > 65*time.Second {
		t.Errorf("expired notified %s after expiring, want a minute", d)
	}
	gotCmd := cmd.wait(t, 2, 5*time.Second)
	checkEvent(t, gotCmd[1], "certificate_expired", "critical")
	w.waitLog(t, "level=ERROR", "ACME certificate expired", "not_after="+notAfter)

	// Clients still get the expired certificate.
	if cert, err := w.handshake(t, ca, acmeDomain); cert == nil || !cert.Equal(old) || !strings.Contains(fmt.Sprint(err), "expired") {
		t.Errorf("handshake: %v", err)
	}
	if n := len(hook.received()); n != 2 {
		t.Errorf("%d notifications, want 2", n)
	}
}

// TestNotifyRetry makes the webhook fail twice: the notification arrives
// with the third attempt, 10 seconds and a minute later. Skipped with
// -short.
func TestNotifyRetry(t *testing.T) {
	slow(t)
	ca := startCA(t)
	ca.setMode("invalid")
	hook := startWebhook(t, http.StatusServiceUnavailable, http.StatusBadGateway)
	start := time.Now()
	w := startACMEWAF(t, ca, acmeOptions{args: notifyArgs(hook, "json", nil)})

	w.waitLogFor(t, 5*time.Second, "level=WARN", "notification failed; retrying", "target=webhook", "503 Service Unavailable: busy (503)", "retry_in=10s")
	w.waitLogFor(t, 15*time.Second, "level=WARN", "notification failed; retrying", "502 Bad Gateway: busy (502)", "retry_in=1m0s")
	got := hook.wait(t, 1, 75*time.Second)
	if d := got[0].at.Sub(start); d < 70*time.Second || d > 75*time.Second {
		t.Errorf("delivered after %s", d)
	}
	checkEvent(t, got[0], "certificate_unavailable", "critical")
	w.waitLog(t, "level=INFO", "notification sent", "target=webhook")
	if n := hook.attempts(); n != 3 {
		t.Errorf("%d attempts", n)
	}
}

// TestNotifyFailure makes every target fail: each is tried three times,
// and the failure is logged with the message that was not delivered. The
// targets do not wait for each other. Skipped with -short.
func TestNotifyFailure(t *testing.T) {
	slow(t)
	ca := startCA(t)
	ca.setMode("invalid")
	hook := startWebhook(t, 500, 500, 500)
	dir := t.TempDir()
	line := `echo "try" >> ` + dir + `/tries; echo "mail: cannot send" >&2; exit 3`
	w := startACMEWAF(t, ca, acmeOptions{args: append(notifyArgs(hook, "json", nil), "-acme-notify-command", line)})

	w.waitLogFor(t, 80*time.Second, "level=ERROR", "notification failed", "target=webhook", "500 Internal Server Error: busy (500)", "message=\"There is no certificate for app.example")
	w.waitLogFor(t, 80*time.Second, "level=ERROR", "notification failed", "target=command", "exit status 3: mail: cannot send")
	if b, _ := os.ReadFile(filepath.Join(dir, "tries")); strings.Count(string(b), "try") != 3 {
		t.Errorf("command run %d times", strings.Count(string(b), "try"))
	}
	if n := hook.attempts(); n != 3 {
		t.Errorf("webhook tried %d times", n)
	}
}

// TestNotifyTargetsAreIndependent uses a webhook that does not answer and
// a command: the command is run at once, prismwaf keeps serving, and it
// stops promptly although a notification is pending.
func TestNotifyTargetsAreIndependent(t *testing.T) {
	ca := startCA(t)
	cache := filepath.Join(t.TempDir(), "acme")
	now := time.Now()
	ca.cacheCert(t, cache, "ok.example", now.Add(-time.Hour), now.Add(60*24*time.Hour))
	ca.setMode("invalid")
	hook := startWebhook(t, 0, 0, 0)
	cmd := newCommand(t)
	w := startACMEWAF(t, ca, acmeOptions{domains: "ok.example,bad.example", cache: cache, args: notifyArgs(hook, "json", cmd)})

	n := cmd.wait(t, 1, 5*time.Second)[0]
	if n.Domain != "bad.example" {
		t.Errorf("command got %+v", n)
	}
	for deadline := time.Now().Add(time.Second); hook.attempts() != 1 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if hook.attempts() != 1 {
		t.Errorf("webhook tried %d times", hook.attempts())
	}
	if resp, err := w.get(t, ca, "ok.example", "/"); err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("serving while the webhook hangs: %v %v", resp, err)
	}
	start := time.Now()
	w.stop()
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("stopped after %s", d)
	}
}

// TestNotifyTestFlag sends test notifications with -acme-notify-test to
// each webhook format, over HTTP and HTTPS, and to a command.
func TestNotifyTestFlag(t *testing.T) {
	base := []string{"-acme-domains", "app.example,www.app.example", "-acme-cache", filepath.Join(t.TempDir(), "acme"), "-acme-notify-test"}
	wantMsg := "Test notification: PrismWAF will notify here when a certificate for app.example, www.app.example is about to expire, has expired or cannot be obtained."
	for _, format := range []string{"json", "slack", "discord"} {
		t.Run(format, func(t *testing.T) {
			hook, cmd := startWebhook(t), newCommand(t)
			out, err := runWAF(t, append(base, notifyArgs(hook, format, cmd)...)...)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if !strings.Contains(out, "test notification sent") || !strings.Contains(out, "webhook http://127.0.0.1:") || strings.Contains(out, "SECRETTOKEN") {
				t.Errorf("output:\n%s", out)
			}
			got := hook.received()
			if len(got) != 1 {
				t.Fatalf("webhook got %+v", got)
			}
			text := fmt.Sprintf("[PrismWAF %s] INFO: %s", hostname(t), wantMsg)
			switch format {
			case "json":
				checkEvent(t, got[0], "test", "info")
				if got[0].Domain != "app.example" || got[0].Message != wantMsg {
					t.Errorf("%+v", got[0])
				}
			case "slack":
				if len(got[0].raw) != 1 || got[0].Text != text {
					t.Errorf("%v", got[0].raw)
				}
			case "discord":
				if len(got[0].raw) != 1 || got[0].Content != text {
					t.Errorf("%v", got[0].raw)
				}
			}
			n := cmd.received(t)
			if len(n) != 1 {
				t.Fatalf("command got %+v", n)
			}
			checkEvent(t, n[0], "test", "info")
		})
	}

	t.Run("HTTPS", func(t *testing.T) {
		hook, caFile := startTLSWebhook(t)
		args := append(base, notifyArgs(hook, "json", nil)...)
		// Not trusted.
		out, err := runWAF(t, args...)
		if err == nil || !strings.Contains(out, "certificate signed by unknown authority") || strings.Contains(out, "SECRETTOKEN") {
			t.Errorf("untrusted webhook: %v\n%s", err, out)
		}
		// Trusted through SSL_CERT_FILE.
		out, err = runWAFEnv(t, []string{"SSL_CERT_FILE=" + caFile, "SSL_CERT_DIR="}, args...)
		if err != nil || len(hook.received()) != 1 {
			t.Errorf("trusted webhook: %v\n%s", err, out)
		}
	})

	t.Run("failures", func(t *testing.T) {
		hook := startWebhook(t, http.StatusForbidden)
		hook.URL = strings.Replace(hook.URL, "http://", "http://user:pa55word@", 1) + "?key=SECRETKEY"
		closed := freeAddr(t)
		for _, tc := range []struct {
			name string
			args []string
			want []string
		}{
			{"status", notifyArgs(hook, "json", nil), []string{"test notification failed: webhook: webhook returned 403 Forbidden: busy (403)"}},
			{"unreachable", []string{"-acme-notify-webhook", "http://" + closed + "/hooks/SECRETTOKEN"}, []string{"webhook: dial tcp " + closed + ": connect: connection refused"}},
			{"command", []string{"-acme-notify-command", "echo no mail server >&2; exit 2"}, []string{"command: exit status 2: no mail server"}},
			{"both", []string{"-acme-notify-webhook", "http://" + closed + "/x", "-acme-notify-command", "exit 4"}, []string{"webhook: dial tcp", "command: exit status 4"}},
		} {
			out, err := runWAF(t, append(base, tc.args...)...)
			if err == nil {
				t.Errorf("%s: exit status 0\n%s", tc.name, out)
			}
			for _, s := range tc.want {
				if !strings.Contains(out, s) {
					t.Errorf("%s: no %q in\n%s", tc.name, s, out)
				}
			}
			for _, secret := range []string{"SECRETTOKEN", "SECRETKEY", "pa55word"} {
				if strings.Contains(out, secret) {
					t.Errorf("%s: %s in the output\n%s", tc.name, secret, out)
				}
			}
		}
	})
}

// TestNotifySecretsAreNotLogged runs prismwaf with a webhook URL with
// credentials that fails, and checks the log.
func TestNotifySecretsAreNotLogged(t *testing.T) {
	ca := startCA(t)
	ca.setMode("invalid")
	hook := startWebhook(t, 401, 401, 401)
	url := strings.Replace(hook.URL, "http://", "http://user:pa55word@", 1) + "?key=SECRETKEY"
	w := startACMEWAF(t, ca, acmeOptions{args: []string{"-acme-notify-webhook", url}})
	w.waitLogFor(t, 5*time.Second, "notification failed; retrying", "401 Unauthorized")
	for _, secret := range []string{"SECRETTOKEN", "SECRETKEY", "pa55word"} {
		if strings.Contains(w.stderr.String(), secret) {
			t.Errorf("%s in the log:\n%s", secret, w.stderr)
		}
	}
}

func TestNotifyInvalidFlags(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "acme")
	acme := []string{"-acme-domains", "app.example", "-acme-cache", cache}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-acme-notify-webhook", "https://hooks.example/SECRETTOKEN"}, "-acme-notify-* options require -acme-domains"},
		{[]string{"-acme-notify-command", "true"}, "-acme-notify-* options require -acme-domains"},
		{[]string{"-acme-notify-test"}, "-acme-notify-* options require -acme-domains"},
		{append(acme, "-acme-notify-test"), "-acme-notify-test requires -acme-notify-webhook or -acme-notify-command"},
		{append(acme, "-acme-notify-webhook", "ftp://hooks.example/SECRETTOKEN"), "invalid webhook URL: want an http:// or https:// URL"},
		{append(acme, "-acme-notify-webhook", "hooks.example/SECRETTOKEN"), "invalid webhook URL"},
		{append(acme, "-acme-notify-webhook", "https://hooks.example/x", "-acme-notify-webhook-format", "teams"), "invalid webhook format"},
		{append(acme, "-acme-notify-webhook-format", "slack"), "-acme-notify-webhook-format requires -acme-notify-webhook"},
		{append(acme, "-acme-notify-command", "true", "-acme-notify-webhook-format", "discord"), "-acme-notify-webhook-format requires -acme-notify-webhook"},
	} {
		out, err := runWAF(t, append(tc.args, "-backend", "http://127.0.0.1:1")...)
		var ee *exec.ExitError
		if !errors.As(err, &ee) || !strings.Contains(out, tc.want) || strings.Contains(out, "SECRETTOKEN") {
			t.Errorf("%q: %v, want %q\n%s", tc.args, err, tc.want, out)
		}
	}
}

// TestLiveWebhook sends a test notification to a real webhook, e.g. a
// Slack or Discord channel:
//
//	PRISMWAF_E2E_WEBHOOK=https://hooks.slack.com/services/… PRISMWAF_E2E_WEBHOOK_FORMAT=slack go test -tags e2e -run TestLiveWebhook ./e2e/
func TestLiveWebhook(t *testing.T) {
	url := os.Getenv("PRISMWAF_E2E_WEBHOOK")
	if url == "" {
		t.Skip("set PRISMWAF_E2E_WEBHOOK to a webhook URL, and PRISMWAF_E2E_WEBHOOK_FORMAT")
	}
	format := os.Getenv("PRISMWAF_E2E_WEBHOOK_FORMAT")
	if format == "" {
		format = "json"
	}
	out, err := runWAF(t, "-acme-domains", "app.example", "-acme-cache", filepath.Join(t.TempDir(), "acme"),
		"-acme-notify-webhook", url, "-acme-notify-webhook-format", format, "-acme-notify-test")
	if err != nil || !strings.Contains(out, "test notification sent") {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, url) {
		t.Errorf("the URL is in the output:\n%s", out)
	}
	t.Log("check the channel for: [PrismWAF " + hostname(t) + "] INFO: Test notification: …")
}
