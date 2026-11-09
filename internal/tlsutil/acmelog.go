package tlsutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// problem is an ACME error document (RFC 8555, section 6.7).
type problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

// authorization is the part of an ACME authorization object that reports
// failed challenges.
type authorization struct {
	Status     string `json:"status"`
	Identifier struct {
		Value string `json:"value"`
	} `json:"identifier"`
	Challenges []struct {
		Type   string   `json:"type"`
		Status string   `json:"status"`
		Error  *problem `json:"error"`
	} `json:"challenges"`
}

// acmeTransport logs the errors in the CA's responses. autocert discards
// why a challenge failed and only reports that none succeeded, so this is
// the only place the reason, e.g. a connection timeout or a CAA record,
// can be found.
type acmeTransport struct {
	base http.RoundTripper
	a    *ACMEManager

	mu   sync.Mutex
	seen map[string]bool // authorizations already reported
}

func newACMETransport(base http.RoundTripper, a *ACMEManager) *acmeTransport {
	return &acmeTransport{base: base, a: a, seen: map[string]bool{}}
}

// maxACMEResponse limits how much of a response is read for inspection.
const maxACMEResponse = 1 << 20

func (t *acmeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		// Renewals run in the background and report nothing, so this is
		// the only trace of a CA that cannot be reached.
		if r.Context().Err() == nil {
			args := []any{"url", r.URL.String(), "error", err}
			if hint := acmeHint("", err); hint != "" {
				args = append(args, "hint", hint)
			}
			t.a.logger.Warn("cannot reach the ACME CA", args...)
		}
		return resp, err
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") && !strings.HasPrefix(ct, "application/problem+json") {
		return resp, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxACMEResponse))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return resp, nil // the client reports the truncated body
	}
	if resp.StatusCode >= 400 {
		t.problem(r, resp, body)
	} else {
		t.authorization(r, body)
	}
	return resp, nil
}

// problem logs an error response.
func (t *acmeTransport) problem(r *http.Request, resp *http.Response, body []byte) {
	var p problem
	if json.Unmarshal(body, &p) != nil || p.Type == "" {
		return
	}
	if strings.HasSuffix(p.Type, ":badNonce") {
		return // retried by the client
	}
	args := []any{"url", r.URL.String(), "status", resp.StatusCode, "problem", p.Type, "detail", p.Detail}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		args = append(args, "retry_after", ra)
	}
	if hint := acmeHint(p.Type, nil); hint != "" {
		args = append(args, "hint", hint)
	}
	t.a.logger.Warn("ACME request rejected", args...)
}

// authorization logs the failed challenges of an invalid authorization.
func (t *acmeTransport) authorization(r *http.Request, body []byte) {
	var z authorization
	if json.Unmarshal(body, &z) != nil || z.Status != "invalid" || z.Identifier.Value == "" {
		return
	}
	// The client may fetch a failed authorization more than once.
	t.mu.Lock()
	key := r.URL.String()
	dup := t.seen[key]
	if len(t.seen) > 1000 {
		clear(t.seen)
	}
	t.seen[key] = true
	t.mu.Unlock()
	if dup {
		return
	}
	domain, err := normalizeDomain(z.Identifier.Value)
	if err != nil {
		domain = z.Identifier.Value
	}
	for _, c := range z.Challenges {
		if c.Error == nil {
			continue
		}
		t.a.recordValidation(domain, c.Type, *c.Error)
		args := []any{"domain", domain, "challenge", c.Type, "problem", c.Error.Type, "detail", c.Error.Detail}
		if hint := acmeHint(c.Error.Type, nil); hint != "" {
			args = append(args, "hint", hint)
		}
		t.a.logger.Warn("ACME validation failed", args...)
	}
}

// acmeHints suggest what to check for an ACME problem type.
var acmeHints = map[string]string{
	"connection":              "the CA could not connect: check that the domain's DNS records point to this server and that -listen is reachable as port 443 (TLS-ALPN-01) or -http-redirect as port 80 (HTTP-01) from the internet",
	"dns":                     "the CA could not resolve the domain: check its A and AAAA records",
	"caa":                     "a CAA DNS record of the domain does not allow this CA",
	"unauthorized":            "the CA got an unexpected answer: another server may answer for this domain, e.g. a proxy or CDN that terminates TLS, or the DNS records point elsewhere",
	"tls":                     "TLS failed during validation: a proxy in front of PrismWAF may terminate TLS",
	"rateLimited":             "rate limit reached: wait until the retry time; test setups with -acme-directory staging",
	"rejectedIdentifier":      "the CA does not issue certificates for this name",
	"userActionRequired":      "the CA requires an action, e.g. accepting new terms of service",
	"externalAccountRequired": "the CA requires external account binding, which PrismWAF does not support",
}

// acmeHint returns a hint for an ACME problem type, or for an error that
// is not from the CA, such as a failed connection to it.
func acmeHint(problemType string, err error) string {
	if i := strings.LastIndex(problemType, ":"); i >= 0 {
		if h, ok := acmeHints[problemType[i+1:]]; ok {
			return h
		}
	}
	var urlErr *url.Error
	var netErr net.Error
	if err != nil && (errors.As(err, &urlErr) || errors.As(err, &netErr)) {
		return "cannot reach the ACME CA: check outgoing HTTPS connections and -acme-directory"
	}
	return ""
}
