package bot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CAPTCHA providers.
const (
	CaptchaTurnstile   = "turnstile"
	CaptchaHCaptcha    = "hcaptcha"
	CaptchaRecaptcha   = "recaptcha"
	CaptchaRecaptchaV3 = "recaptcha-v3"
)

// CaptchaProviders lists the supported providers.
var CaptchaProviders = []string{CaptchaTurnstile, CaptchaHCaptcha, CaptchaRecaptcha, CaptchaRecaptchaV3}

// DefaultCaptchaMinScore is the reCAPTCHA v3 score from which a client
// passes. reCAPTCHA scores range from 0.0 (a bot) to 1.0 (a human).
const DefaultCaptchaMinScore = 0.5

// recaptchaAction is the action name of reCAPTCHA v3 challenges, which is
// checked on verification.
const recaptchaAction = "prismwaf_challenge"

const (
	captchaTimeout     = 10 * time.Second
	maxCaptchaResponse = 64 << 10
)

// CaptchaConfig configures a CAPTCHA challenge.
type CaptchaConfig struct {
	// Provider is one of CaptchaProviders.
	Provider string
	// SiteKey is the public key of the site at the provider.
	SiteKey string
	// Secret is the secret key, which verifies solutions with the
	// provider.
	Secret string
	// MinScore is the reCAPTCHA v3 score from which a client passes. Zero
	// means DefaultCaptchaMinScore.
	MinScore float64
	// HTTPClient calls the provider. Nil uses a client with a 10 second
	// timeout.
	HTTPClient *http.Client
}

// provider describes how to show and verify one provider's CAPTCHA.
type provider struct {
	script string
	// verifyURL receives the solution with the secret.
	verifyURL string
	// widgetClass is the class of the element that the script turns into
	// the widget; empty for invisible CAPTCHAs.
	widgetClass string
	// csp lists the sources the widget needs, for the Content-Security-
	// Policy of the challenge page.
	cspScript, cspFrame, cspStyle, cspConnect string
	// sendSiteKey adds the site key to verification requests.
	sendSiteKey bool
}

var providers = map[string]provider{
	CaptchaTurnstile: {
		script:      "https://challenges.cloudflare.com/turnstile/v0/api.js",
		verifyURL:   "https://challenges.cloudflare.com/turnstile/v0/siteverify",
		widgetClass: "cf-turnstile",
		cspScript:   "https://challenges.cloudflare.com",
		cspFrame:    "https://challenges.cloudflare.com",
	},
	CaptchaHCaptcha: {
		script:      "https://js.hcaptcha.com/1/api.js",
		verifyURL:   "https://api.hcaptcha.com/siteverify",
		widgetClass: "h-captcha",
		cspScript:   "https://hcaptcha.com https://*.hcaptcha.com",
		cspFrame:    "https://hcaptcha.com https://*.hcaptcha.com",
		cspStyle:    "https://hcaptcha.com https://*.hcaptcha.com",
		cspConnect:  "https://hcaptcha.com https://*.hcaptcha.com",
		sendSiteKey: true,
	},
	CaptchaRecaptcha: {
		script:      "https://www.google.com/recaptcha/api.js",
		verifyURL:   "https://www.google.com/recaptcha/api/siteverify",
		widgetClass: "g-recaptcha",
		cspScript:   "https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/",
		cspFrame:    "https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/",
	},
	CaptchaRecaptchaV3: {
		script:     "https://www.google.com/recaptcha/api.js?render=",
		verifyURL:  "https://www.google.com/recaptcha/api/siteverify",
		cspScript:  "https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/",
		cspFrame:   "https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/",
		cspConnect: "https://www.google.com/recaptcha/",
	},
}

// captcha shows and verifies CAPTCHAs of one provider.
type captcha struct {
	name     string
	p        provider
	siteKey  string
	secret   string
	minScore float64
	client   *http.Client
}

func newCaptcha(cfg *CaptchaConfig) (*captcha, error) {
	p, ok := providers[cfg.Provider]
	if !ok {
		return nil, fmt.Errorf("bot: unknown CAPTCHA provider %q: must be one of %s", cfg.Provider, strings.Join(CaptchaProviders, ", "))
	}
	if cfg.SiteKey == "" || cfg.Secret == "" {
		return nil, errors.New("bot: a CAPTCHA needs a site key and a secret key")
	}
	if strings.ContainsAny(cfg.SiteKey, "\"'<>&? \t\r\n") {
		return nil, errors.New("bot: invalid CAPTCHA site key")
	}
	c := &captcha{name: cfg.Provider, p: p, siteKey: cfg.SiteKey, secret: cfg.Secret, minScore: cfg.MinScore, client: cfg.HTTPClient}
	if c.minScore == 0 {
		c.minScore = DefaultCaptchaMinScore
	}
	if c.minScore < 0 || c.minScore > 1 {
		return nil, errors.New("bot: the CAPTCHA minimum score must be between 0 and 1")
	}
	if c.client == nil {
		c.client = &http.Client{Timeout: captchaTimeout}
	}
	if c.name == CaptchaRecaptchaV3 {
		c.p.script += url.QueryEscape(c.siteKey)
	}
	return c, nil
}

// csp returns the Content-Security-Policy of the challenge page.
func (c *captcha) csp(nonce string) string {
	join := func(self, extra string) string { return strings.TrimSpace(self + " " + extra) }
	policy := "default-src 'none'; script-src " + join("'nonce-"+nonce+"'", c.p.cspScript) +
		"; style-src " + join("'unsafe-inline'", c.p.cspStyle) +
		"; img-src data: https:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
	if c.p.cspFrame != "" {
		policy += "; frame-src " + c.p.cspFrame
	}
	if c.p.cspConnect != "" {
		policy += "; connect-src " + c.p.cspConnect
	}
	return policy
}

// Errors of a CAPTCHA verification.
var (
	errCaptchaFailed = errors.New("CAPTCHA not solved")
	// errCaptchaConfig and errCaptchaUnavailable are problems of PrismWAF
	// or the provider, not of the client, and are logged.
	errCaptchaConfig      = errors.New("CAPTCHA misconfigured")
	errCaptchaUnavailable = errors.New("CAPTCHA provider unavailable")
)

// siteverifyResponse is the answer of the providers' siteverify APIs,
// which share this format.
type siteverifyResponse struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
	Score      *float64 `json:"score"`
	ErrorCodes []string `json:"error-codes"`
}

// verify checks a solution with the provider. host is the host name the
// client requested, which the solution must have been made for.
func (c *captcha) verify(ctx context.Context, response, clientIP, host string) error {
	if response == "" || len(response) > 8192 {
		return errCaptchaFailed
	}
	form := url.Values{"secret": {c.secret}, "response": {response}}
	if clientIP != "" {
		form.Set("remoteip", clientIP)
	}
	if c.p.sendSiteKey {
		form.Set("sitekey", c.siteKey)
	}
	ctx, cancel := context.WithTimeout(ctx, captchaTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.p.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", errCaptchaUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s returned %s", errCaptchaUnavailable, c.p.verifyURL, resp.Status)
	}
	var res siteverifyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxCaptchaResponse)).Decode(&res); err != nil {
		return fmt.Errorf("%w: invalid response: %v", errCaptchaUnavailable, err)
	}
	for _, code := range res.ErrorCodes {
		// E.g. "invalid-input-secret", "missing-input-secret",
		// "sitekey-secret-mismatch": every solution would fail.
		if strings.Contains(code, "secret") || strings.Contains(code, "sitekey") {
			return fmt.Errorf("%w: %s", errCaptchaConfig, strings.Join(res.ErrorCodes, ", "))
		}
	}
	if !res.Success {
		return errCaptchaFailed
	}
	// A solution made on another site that uses the same keys must not be
	// accepted here.
	if res.Hostname != "" && !strings.EqualFold(res.Hostname, hostOnly(host)) {
		return fmt.Errorf("%w: the solution is for %q, not %q; are the site keys used by another site?", errCaptchaConfig, res.Hostname, hostOnly(host))
	}
	if c.name == CaptchaRecaptchaV3 {
		if res.Action != recaptchaAction || res.Score == nil || *res.Score < c.minScore {
			return errCaptchaFailed
		}
	}
	return nil
}

// hostOnly removes the port from a Host header.
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.Trim(host, "[]")
}
