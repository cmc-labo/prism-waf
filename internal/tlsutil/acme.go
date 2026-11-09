package tlsutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/idna"

	"github.com/cmc-labo/prism-waf/internal/notify"
)

// Directory URLs of Let's Encrypt.
const (
	// LetsEncryptProduction issues trusted certificates. It is the default.
	LetsEncryptProduction = autocert.DefaultACMEDirectory
	// LetsEncryptStaging has higher rate limits but issues untrusted
	// certificates. Use it to test an ACME setup.
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Retry delays after a failed certificate request. They keep a broken
// setup from using up the CA's rate limits, e.g. Let's Encrypt's five
// failed validations per hour and name.
const (
	acmeMinBackoff = 10 * time.Minute
	acmeMaxBackoff = 2 * time.Hour
	// acmeRateLimitBackoff is the delay after a rate limit error that does
	// not say when to retry.
	acmeRateLimitBackoff = time.Hour
)

// acmeCheckInterval is how often Run checks the certificates.
const acmeCheckInterval = time.Minute

// acmeNotifyInterval is how often a notification is repeated while its
// problem lasts.
const acmeNotifyInterval = 24 * time.Hour

// Events notified to administrators.
const (
	eventExpiring    = "certificate_expiring"
	eventExpired     = "certificate_expired"
	eventUnavailable = "certificate_unavailable"
	eventRecovered   = "certificate_recovered"
)

// Notifier receives events for administrators; *notify.Notifier
// implements it.
type Notifier interface {
	Notify(notify.Event)
}

// ACMEConfig configures automatic certificates from an ACME CA such as
// Let's Encrypt.
type ACMEConfig struct {
	// Domains are the only host names certificates are requested for.
	// Restricting them prevents clients from triggering requests for
	// arbitrary names, which would exhaust the CA's rate limits.
	Domains []string
	// CacheDir stores the account key and the certificates, so that they
	// survive restarts. Each CA gets its own subdirectory (see
	// ACMEManager.CacheDir). It holds private keys and is created with
	// mode 0700.
	CacheDir string
	// Email is the optional contact address of the ACME account.
	Email string
	// DirectoryURL is the CA's ACME directory; empty means Let's Encrypt.
	DirectoryURL string
	// Logger receives certificate events and errors. Nil uses
	// slog.Default().
	Logger *slog.Logger
	// Notifier, if set, is told when a certificate is about to expire
	// without having been renewed, has expired or cannot be obtained, and
	// when it is fine again.
	Notifier Notifier
}

// ACMEManager obtains and renews certificates for the configured domains
// with autocert, adding a cache per CA, retries with backoff, and detailed
// logs of failures.
type ACMEManager struct {
	m            *autocert.Manager
	logger       *slog.Logger
	notifier     Notifier
	directoryURL string
	cacheDir     string
	domains      []string // normalized
	domainSet    map[string]bool

	// get obtains a certificate; it is m.GetCertificate except in tests.
	get func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	now func() time.Time

	mu          sync.Mutex
	certs       map[string]*certStatus // by cache key: "example.com" or "example.com+rsa"
	validations map[string][]validationError
}

// certStatus tracks the failures and log state of one certificate.
type certStatus struct {
	failures  int
	failedAt  time.Time
	retryAt   time.Time
	lastErr   error
	announced bool      // its details were logged
	warnedAt  time.Time // last expiry warning

	alert      string    // the event of the current problem notified, if any
	notifiedAt time.Time // when it was last notified
}

// validationError is a failed challenge reported by the CA.
type validationError struct {
	at        time.Time
	challenge string
	problem   problem
}

func (v validationError) String() string {
	return fmt.Sprintf("%s: %s: %s", v.challenge, v.problem.Type, v.problem.Detail)
}

// NewACMEManager returns a manager that obtains and renews certificates for
// the configured domains. Using it means agreeing to the CA's terms of
// service. It prepares the cache directory, migrating a cache from older
// versions, and fails if the directory cannot be written.
//
// The manager answers the TLS-ALPN-01 challenge through GetCertificate (see
// ServerOptions.ACME) and the HTTP-01 challenge through HTTPHandler, which
// must be served on port 80. Run must be called to obtain certificates
// ahead of the first client and to monitor them.
func NewACMEManager(c ACMEConfig) (*ACMEManager, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("tlsutil: ACME requires at least one domain")
	}
	a := &ACMEManager{
		logger:       c.Logger,
		notifier:     c.Notifier,
		directoryURL: c.DirectoryURL,
		domainSet:    map[string]bool{},
		now:          time.Now,
		certs:        map[string]*certStatus{},
		validations:  map[string][]validationError{},
	}
	if a.logger == nil {
		a.logger = slog.Default()
	}
	if a.directoryURL == "" {
		a.directoryURL = LetsEncryptProduction
	}
	for _, d := range c.Domains {
		switch {
		case d == "":
			return nil, errors.New("tlsutil: empty ACME domain")
		case strings.Contains(d, "*"):
			return nil, fmt.Errorf("tlsutil: ACME domain %q: wildcard certificates are not supported", d)
		case net.ParseIP(d) != nil:
			return nil, fmt.Errorf("tlsutil: ACME domain %q: IP addresses are not supported", d)
		}
		name, err := normalizeDomain(d)
		if err != nil {
			return nil, fmt.Errorf("tlsutil: ACME domain %q: %w", d, err)
		}
		if !strings.Contains(name, ".") {
			return nil, fmt.Errorf("tlsutil: ACME domain %q: a fully qualified domain name is required", d)
		}
		if !a.domainSet[name] {
			a.domainSet[name] = true
			a.domains = append(a.domains, name)
		}
	}
	if c.CacheDir == "" {
		return nil, errors.New("tlsutil: ACME requires a cache directory")
	}
	dir, err := prepareACMECache(c.CacheDir, a.directoryURL, a.logger)
	if err != nil {
		return nil, err
	}
	a.cacheDir = dir
	a.m = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(a.domains...),
		Cache:      &acmeCache{DirCache: autocert.DirCache(dir), onCert: a.certStored, logger: a.logger},
		Email:      c.Email,
		Client: &acme.Client{
			DirectoryURL: a.directoryURL,
			HTTPClient:   &http.Client{Transport: newACMETransport(http.DefaultTransport, a)},
		},
	}
	a.get = a.m.GetCertificate
	return a, nil
}

// CacheDir returns the directory that holds the cache of the configured CA.
func (a *ACMEManager) CacheDir() string { return a.cacheDir }

// DirectoryURL returns the directory URL of the CA.
func (a *ACMEManager) DirectoryURL() string { return a.directoryURL }

// HTTPHandler answers HTTP-01 challenges and passes all other requests to
// fallback.
func (a *ACMEManager) HTTPHandler(fallback http.Handler) http.Handler {
	return a.m.HTTPHandler(fallback)
}

// GetCertificate returns the certificate for a TLS handshake, obtaining it
// if necessary. After a failed request, further requests for the same
// certificate fail immediately until the retry delay has passed.
func (a *ACMEManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	key, domain, ok := a.certKey(hello)
	if !ok {
		// A challenge or a name autocert rejects anyway.
		return a.get(hello)
	}
	start := a.now()
	if err := a.waitErr(key, start); err != nil {
		return nil, err
	}
	cert, err := a.get(hello)
	if err != nil {
		a.failed(key, domain, start, err)
		return nil, err
	}
	a.succeeded(key, cert)
	return cert, nil
}

// certKey returns the cache key of the certificate a handshake needs and
// its domain, or false if the handshake is not for a configured domain.
func (a *ACMEManager) certKey(hello *tls.ClientHelloInfo) (key, domain string, ok bool) {
	if slices.Equal(hello.SupportedProtos, []string{acme.ALPNProto}) {
		return "", "", false
	}
	domain, err := normalizeDomain(hello.ServerName)
	if err != nil || !a.domainSet[domain] {
		return "", "", false
	}
	if !supportsECDSA(hello) {
		return domain + "+rsa", domain, true
	}
	return domain, domain, true
}

// waitErr returns an error if the certificate is waiting for a retry.
func (a *ACMEManager) waitErr(key string, now time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.certs[key]
	if s == nil || !now.Before(s.retryAt) {
		return nil
	}
	return fmt.Errorf("acme: no certificate for %s after %d failed attempts; next attempt in %s: %w",
		key, s.failures, s.retryAt.Sub(now).Round(time.Second), s.lastErr)
}

// failed records a failed certificate request that started at start.
func (a *ACMEManager) failed(key, domain string, start time.Time, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.status(key)
	if !s.failedAt.Before(start) {
		// Concurrent handshakes waited for the same request; count it once.
		return
	}
	now := a.now()
	s.failures++
	s.failedAt = now
	s.lastErr = err

	delay := min(acmeMinBackoff<<min(s.failures-1, 16), acmeMaxBackoff)
	rateLimited := false
	var ae *acme.Error
	if errors.As(err, &ae) {
		if retry, ok := acme.RateLimit(ae); ok {
			rateLimited = true
			if retry <= 0 {
				retry = acmeRateLimitBackoff
			}
			delay = max(delay, retry)
		}
	}
	s.retryAt = now.Add(delay)

	// The validation errors of this request; autocert only reports that
	// no challenge succeeded.
	var details []string
	problemType := ""
	for _, v := range a.validations[domain] {
		if now.Sub(v.at) < 10*time.Minute {
			details = append(details, v.String())
			problemType = v.problem.Type
		}
	}
	delete(a.validations, domain)
	if rateLimited {
		problemType = ae.ProblemType
	} else if ae != nil && problemType == "" {
		problemType = ae.ProblemType
	}

	args := []any{"domain", domain, "certificate", key, "error", err}
	if len(details) > 0 {
		args = append(args, "validation", strings.Join(details, "; "))
	}
	if hint := acmeHint(problemType, err); hint != "" {
		args = append(args, "hint", hint)
	}
	args = append(args, "failures", s.failures, "retry_in", delay.Round(time.Second), "retry_at", s.retryAt.Format(time.RFC3339))
	a.logger.Error("ACME certificate request failed", args...)
}

// succeeded records a successful certificate request.
func (a *ACMEManager) succeeded(key string, cert *tls.Certificate) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.certs[key]
	if s == nil {
		s = &certStatus{}
		a.certs[key] = s
	}
	if s.failures > 0 {
		a.logger.Info("ACME certificate available again", "certificate", key, "after_failures", s.failures)
		s.failures, s.retryAt, s.lastErr = 0, time.Time{}, nil
	}
	if !s.announced && cert.Leaf != nil {
		s.announced = true
		a.logger.Info("ACME certificate ready", certArgs(key, cert.Leaf)...)
	}
}

// certStored is called when autocert stores a new or renewed certificate.
func (a *ACMEManager) certStored(key string, leaf *x509.Certificate) {
	a.mu.Lock()
	a.status(key).announced = true
	a.mu.Unlock()
	a.logger.Info("ACME certificate obtained", certArgs(key, leaf)...)
}

// recordValidation records a failed challenge reported by the CA.
func (a *ACMEManager) recordValidation(domain, challenge string, p problem) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.validations[domain] = append(a.validations[domain], validationError{at: a.now(), challenge: challenge, problem: p})
}

func (a *ACMEManager) status(key string) *certStatus {
	s := a.certs[key]
	if s == nil {
		s = &certStatus{}
		a.certs[key] = s
	}
	return s
}

// Run obtains the certificates of all domains that are not cached and
// then checks them every minute until ctx is canceled: certificates that
// are missing are requested again once their retry delay has passed, and
// certificates that are close to expiry without having been renewed are
// logged. Checking also starts the renewal of cached certificates, which
// would otherwise only start when a client uses them. Call Run once the
// HTTPS listener accepts connections, so that the CA can validate.
func (a *ACMEManager) Run(ctx context.Context) {
	if a.directoryURL == LetsEncryptStaging {
		a.logger.Warn("using the Let's Encrypt staging environment: certificates are not trusted by browsers")
	}
	t := time.NewTicker(acmeCheckInterval)
	defer t.Stop()
	for {
		a.check()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// check ensures that the ECDSA certificate of every domain is available
// and not about to expire. RSA certificates are only obtained for clients
// that need them.
func (a *ACMEManager) check() {
	for _, d := range a.domains {
		cert, err := a.GetCertificate(ecdsaHello(d))
		if err != nil {
			a.unavailable(d, err) // logged when the request failed
			continue
		}
		if cert.Leaf != nil {
			a.checkExpiry(d, cert.Leaf)
		}
	}
}

// renewalOverdue reports whether a certificate should have been renewed
// by now. autocert starts renewing a third of the lifetime (at most 30
// days) before expiry, plus up to an hour of jitter, and retries failed
// renewals every 30 to 60 minutes. A certificate that is still in use a
// day after that (or half the period, for short-lived certificates)
// therefore means that renewal keeps failing.
func renewalOverdue(leaf *x509.Certificate, now time.Time) bool {
	window := min(leaf.NotAfter.Sub(leaf.NotBefore)/3, 30*24*time.Hour)
	grace := min(window/2, 24*time.Hour)
	return leaf.NotAfter.Sub(now) <= window-grace
}

// checkExpiry logs and notifies certificates that should have been
// renewed, and notifies when a certificate is fine again.
func (a *ACMEManager) checkExpiry(domain string, leaf *x509.Certificate) {
	now := a.now()
	if !renewalOverdue(leaf, now) {
		a.recovered(domain, leaf)
		return
	}
	left := leaf.NotAfter.Sub(now)
	a.mu.Lock()
	s := a.status(domain)
	interval := 24 * time.Hour
	if left <= 0 {
		interval = time.Hour
	}
	logIt := s.warnedAt.IsZero() || now.Sub(s.warnedAt) >= interval
	if logIt {
		s.warnedAt = now
	}
	a.mu.Unlock()

	notAfter := leaf.NotAfter.UTC()
	e := notify.Event{
		Domain:   domain,
		Issuer:   leaf.Issuer.String(),
		Serial:   leaf.SerialNumber.Text(16),
		NotAfter: &notAfter,
	}
	args := append(certArgs(domain, leaf), "hint", "renewal keeps failing; see the ACME errors in this log")
	if left <= 0 {
		if logIt {
			a.logger.Error("ACME certificate expired", args...)
		}
		e.Event, e.Severity = eventExpired, notify.SeverityCritical
		e.Message = fmt.Sprintf("The certificate for %s expired at %s. Clients get certificate errors. Renewal keeps failing; see the ACME errors in the PrismWAF log.",
			domain, notAfter.Format(time.RFC3339))
	} else {
		if logIt {
			a.logger.Warn("ACME certificate not renewed yet", append(args, "expires_in", left.Round(time.Hour))...)
		}
		e.Event, e.Severity = eventExpiring, notify.SeverityWarning
		e.Message = fmt.Sprintf("The certificate for %s expires in %s (%s) and has not been renewed. Renewal keeps failing; see the ACME errors in the PrismWAF log.",
			domain, formatDays(left), notAfter.Format(time.RFC3339))
	}
	a.raise(domain, e)
}

// unavailable notifies that a domain has no certificate because requesting
// one failed.
func (a *ACMEManager) unavailable(domain string, err error) {
	a.mu.Lock()
	s := a.status(domain)
	failures, retryAt := s.failures, s.retryAt.UTC().Truncate(time.Second)
	a.mu.Unlock()
	if failures == 0 {
		return // not a failed request
	}
	a.raise(domain, notify.Event{
		Event:    eventUnavailable,
		Severity: notify.SeverityCritical,
		Domain:   domain,
		Error:    err.Error(),
		Failures: failures,
		RetryAt:  &retryAt,
		Message: fmt.Sprintf("There is no certificate for %s: %s; HTTPS connections to it fail. Next attempt at %s. See the ACME errors in the PrismWAF log.",
			domain, failedTimes(failures), retryAt.Format(time.RFC3339)),
	})
}

// recovered notifies that the certificate of a domain is fine again after
// a problem was notified.
func (a *ACMEManager) recovered(domain string, leaf *x509.Certificate) {
	a.mu.Lock()
	s := a.status(domain)
	was := s.alert
	s.alert, s.notifiedAt = "", time.Time{}
	a.mu.Unlock()
	if was == "" || a.notifier == nil {
		return
	}
	notAfter := leaf.NotAfter.UTC()
	a.notifier.Notify(notify.Event{
		Event:    eventRecovered,
		Severity: notify.SeverityInfo,
		Domain:   domain,
		Issuer:   leaf.Issuer.String(),
		Serial:   leaf.SerialNumber.Text(16),
		NotAfter: &notAfter,
		Message:  fmt.Sprintf("The certificate for %s is valid again until %s.", domain, notAfter.Format(time.RFC3339)),
	})
}

// raise notifies a problem with the certificate of a domain: at once if it
// is new or worse than the one notified before, otherwise once a day.
func (a *ACMEManager) raise(domain string, e notify.Event) {
	if a.notifier == nil {
		return
	}
	now := a.now()
	a.mu.Lock()
	s := a.status(domain)
	if s.alert == e.Event && now.Sub(s.notifiedAt) < acmeNotifyInterval {
		a.mu.Unlock()
		return
	}
	s.alert, s.notifiedAt = e.Event, now
	a.mu.Unlock()
	e.Time = now.UTC()
	a.notifier.Notify(e)
}

func failedTimes(n int) string {
	if n == 1 {
		return "requesting one failed"
	}
	return fmt.Sprintf("requesting one failed %d times in a row", n)
}

// formatDays formats a duration in whole days, e.g. "9 days", or as a
// duration if it is less than a day.
func formatDays(d time.Duration) string {
	switch days := int(d.Round(24*time.Hour) / (24 * time.Hour)); {
	case days > 1:
		return fmt.Sprintf("%d days", days)
	case days == 1:
		return "1 day"
	}
	return d.Round(time.Minute).String()
}

func certArgs(key string, leaf *x509.Certificate) []any {
	return []any{
		"certificate", key,
		"issuer", leaf.Issuer.String(),
		"not_after", leaf.NotAfter.UTC().Format(time.RFC3339),
		"serial", leaf.SerialNumber.Text(16),
	}
}

// ecdsaHello returns a ClientHello for which autocert selects the ECDSA
// certificate of domain.
func ecdsaHello(domain string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:       domain,
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:  []tls.CurveID{tls.CurveP256},
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
}

// normalizeDomain converts a host name the way autocert does, so that the
// same certificate is used for EXAMPLE.com, example.com. and IDN forms.
func normalizeDomain(name string) (string, error) {
	name, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(name, "."), nil
}

// supportsECDSA reports whether a client accepts an ECDSA certificate. It
// mirrors autocert's choice between the ECDSA and the RSA certificate.
func supportsECDSA(hello *tls.ClientHelloInfo) bool {
	if hello.SignatureSchemes != nil {
		const ecdsaWithSHA1 tls.SignatureScheme = 0x0203
		if !slices.ContainsFunc(hello.SignatureSchemes, func(s tls.SignatureScheme) bool {
			switch s {
			case ecdsaWithSHA1, tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512:
				return true
			}
			return false
		}) {
			return false
		}
	}
	if hello.SupportedCurves != nil && !slices.Contains(hello.SupportedCurves, tls.CurveP256) {
		return false
	}
	return slices.ContainsFunc(hello.CipherSuites, func(c uint16) bool {
		switch c {
		case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
			return true
		}
		return false
	})
}
