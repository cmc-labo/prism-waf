//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The browser tests run the challenge pages in headless Chromium, driven
// by e2e/browser/cdp.mjs with Node.js. They are skipped if either is
// missing; PRISMWAF_E2E_CHROME sets the Chromium binary.

// pageResult is the output of cdp.mjs.
type pageResult struct {
	Error     string `json:"error"`
	URL       string `json:"url"`
	Text      string `json:"text"`
	Ms        int    `json:"ms"`
	Documents []struct {
		Method string `json:"method"`
		URL    string `json:"url"`
		Status int    `json:"status"`
	} `json:"documents"`
	Problems []string `json:"problems"`
}

// statuses returns the statuses of the top-level documents, e.g.
// [403 303 200] for a challenge that was solved.
func (p pageResult) statuses() []int {
	var s []int
	for _, d := range p.Documents {
		s = append(s, d.Status)
	}
	return s
}

type chrome struct {
	port string
}

// startChrome starts headless Chromium with extra flags.
func startChrome(t *testing.T, extra ...string) *chrome {
	t.Helper()
	bin := os.Getenv("PRISMWAF_E2E_CHROME")
	if bin == "" {
		for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"} {
			if p, err := exec.LookPath(name); err == nil {
				bin = p
				break
			}
		}
	}
	if bin == "" {
		t.Skip("no Chromium found; set PRISMWAF_E2E_CHROME")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("no Node.js found")
	}
	addr := freeAddr(t)
	port := addr[strings.LastIndex(addr, ":")+1:]
	args := append([]string{
		"--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run",
		"--user-data-dir=" + t.TempDir(), "--remote-debugging-port=" + port,
	}, extra...)
	cmd := exec.Command(bin, append(args, "about:blank")...)
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if resp, err := http.Get("http://127.0.0.1:" + port + "/json/version"); err == nil {
			resp.Body.Close()
			return &chrome{port: port}
		}
		if time.Now().After(deadline) {
			t.Fatalf("Chromium did not start\n%s", &out)
		}
	}
}

// open loads url in a new tab, clicks the CAPTCHA if click is set, and
// waits until the challenge is passed.
func (c *chrome) open(t *testing.T, url string, click string) pageResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	args := []string{"browser/cdp.mjs", c.port, url}
	if click != "" {
		args = append(args, click)
	}
	out, err := exec.CommandContext(ctx, "node", args...).Output()
	if err != nil {
		t.Fatalf("cdp.mjs: %v\n%s", err, out)
	}
	var r pageResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("cdp.mjs: %v\n%s", err, out)
	}
	t.Logf("%s: %v in %dms", url, r.statuses(), r.Ms)
	return r
}

// backendHit decodes what the backend saw from the page text.
func (p pageResult) hit(t *testing.T) backendHit {
	t.Helper()
	var h backendHit
	if p.Error != "" || json.Unmarshal([]byte(p.Text), &h) != nil {
		t.Fatalf("page not served by the backend: %s %s\n%s", p.Error, p.URL, p.Text)
	}
	if len(p.Problems) > 0 {
		t.Errorf("errors in the browser: %q", p.Problems)
	}
	return h
}

// TestBrowserProofOfWork solves the proof of work of the default
// difficulty in Chromium, over HTTP and HTTPS. Headless Chromium names
// itself HeadlessChrome and scores 60.
func TestBrowserProofOfWork(t *testing.T) {
	b := startChrome(t, "--ignore-certificate-errors")
	for _, tls := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP", true: "HTTPS"}[tls], func(t *testing.T) {
			w := startBotWAF(t, wafOptions{tls: tls})

			r := b.open(t, w.URL+"/hello?x=1&y=<b>", "")
			if h := r.hit(t); h.URI != "/hello?x=1&y=%3Cb%3E" || h.Score != "60" || h.Category != "automation" {
				t.Errorf("backend saw %+v", h)
			}
			if s := fmt.Sprint(r.statuses()); s != "[403 303 200]" {
				t.Errorf("statuses %s, want challenge, solution, page", s)
			}
			post := r.Documents[1]
			if post.Method != "" || !strings.HasSuffix(post.URL, "/.prismwaf/challenge") {
				t.Errorf("solution posted to %+v", post)
			}

			// The clearance cookie lets the browser through.
			r = b.open(t, w.URL+"/second", "")
			if r.hit(t); fmt.Sprint(r.statuses()) != "[200]" {
				t.Errorf("second page: %v", r.statuses())
			}
		})
	}
}

// TestLiveCaptcha solves the CAPTCHAs of the providers that offer test keys
// in Chromium, with the real providers. The test keys accept solutions for
// one host name each, which Chromium resolves to 127.0.0.1.
func TestLiveCaptcha(t *testing.T) {
	if os.Getenv("PRISMWAF_E2E_LIVE") == "" {
		t.Skip("set PRISMWAF_E2E_LIVE=1 to use the CAPTCHA providers")
	}
	rules := []string{}
	for _, k := range testKeys {
		rules = append(rules, "MAP "+k.host+" 127.0.0.1")
	}
	b := startChrome(t, "--host-resolver-rules="+strings.Join(rules, ", "))
	for _, k := range testKeys {
		t.Run(k.provider, func(t *testing.T) {
			w := startBotWAF(t, wafOptions{args: []string{
				"-bot-captcha", k.provider,
				"-bot-captcha-site-key", k.siteKey,
				"-bot-captcha-secret-file", writeFile(t, "secret", k.secret),
			}})
			port := w.URL[strings.LastIndex(w.URL, ":")+1:]
			r := b.open(t, "http://"+k.host+":"+port+"/page?a=1", k.click)
			if h := r.hit(t); h.URI != "/page?a=1" || h.Score != "60" {
				t.Errorf("backend saw %+v", h)
			}
			if s := fmt.Sprint(r.statuses()); s != "[403 303 200]" {
				t.Errorf("statuses %s", s)
			}
			// A solution for another host name is rejected, and the
			// administrator is told.
			r = b.open(t, "http://127.0.0.1:"+port+"/", k.click)
			if r.Error != "failed" {
				t.Errorf("solution for %s accepted on 127.0.0.1: %+v", k.host, r)
			}
			w.waitLog(t, "level=WARN", "the solution is for", k.host)
		})
	}
}

// Test keys published by the providers. They always pass.
var testKeys = []struct {
	provider, siteKey, secret string
	host                      string // host name that the solutions are for
	click                     string // checkbox to click, if any
}{
	// https://developers.cloudflare.com/turnstile/troubleshooting/testing/
	{"turnstile", "1x00000000000000000000AA", "1x0000000000000000000000000000000AA", "example.com", ""},
	// https://docs.hcaptcha.com/#integration-testing-test-keys
	{"hcaptcha", "10000000-ffff-ffff-ffff-000000000001", "0x0000000000000000000000000000000000000000", "dummy-key-pass", ".captcha iframe"},
	// https://developers.google.com/recaptcha/docs/faq
	{"recaptcha", "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI", "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe", "testkey.google.com", ".captcha iframe"},
}
