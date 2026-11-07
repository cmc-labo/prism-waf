// Command prismwaf runs the PrismWAF reverse proxy.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/crs"
	"github.com/cmc-labo/prism-waf/internal/proxy"
	"github.com/cmc-labo/prism-waf/internal/ratelimit"
	"github.com/cmc-labo/prism-waf/internal/tlsutil"
	"github.com/cmc-labo/prism-waf/internal/waf"
)

func main() {
	var cfg config
	flag.StringVar(&cfg.listen, "listen", ":8080", "address to listen on")
	flag.Var(&cfg.backends, "backend", `backend server URL (http:// or https://); repeat or separate with commas for several backends (default "`+defaultBackend+`")`)
	flag.StringVar(&cfg.lbPolicy, "lb-policy", string(proxy.RoundRobin), `how to choose the backend for a request: "round-robin" or "least-conn"`)
	flag.DurationVar(&cfg.failTimeout, "backend-fail-timeout", proxy.DefaultFailTimeout, "how long to skip a backend that cannot be connected to")
	flag.StringVar(&cfg.healthPath, "health-check-path", "", `path to GET on every backend periodically, e.g. "/healthz"; backends that fail are skipped`)
	flag.DurationVar(&cfg.healthInterval, "health-check-interval", 10*time.Second, "interval between health checks")
	flag.DurationVar(&cfg.healthTimeout, "health-check-timeout", 5*time.Second, "timeout of a health check request")
	flag.StringVar(&cfg.engine, "engine", engineBuiltin, `rules to inspect requests with: "builtin" (PrismWAF signatures), "crs" (OWASP CRS v4) or "both"`)
	flag.IntVar(&cfg.crsParanoia, "crs-paranoia-level", crs.DefaultParanoiaLevel, "CRS paranoia level (1-4); higher detects more but causes more false positives")
	flag.IntVar(&cfg.crsThreshold, "crs-anomaly-threshold", crs.DefaultInboundThreshold, "CRS inbound anomaly score at which a request is blocked (a critical rule scores 5)")
	flag.IntVar(&cfg.crsMaxArgs, "crs-max-args", crs.DefaultMaxArgs, "maximum number of arguments (parameters, JSON/XML values) per request with the CRS; requests with more are rejected")
	flag.Var(&cfg.crsBefore, "crs-rules-before", "SecLang file loaded before the CRS rules, e.g. ctl:ruleRemoveById exclusions; repeatable, globs allowed")
	flag.Var(&cfg.crsAfter, "crs-rules-after", "SecLang file loaded after the CRS rules, e.g. SecRuleRemoveById exclusions; repeatable, globs allowed")
	flag.Int64Var(&cfg.maxBody, "max-body", waf.DefaultMaxBodySize, "maximum request body size in bytes to inspect; larger requests are rejected")
	flag.StringVar(&cfg.mode, "mode", string(waf.ModeBlock), `"block" to reject detected requests, "detect" to only log them`)
	flag.StringVar(&cfg.auditLog, "audit-log", "-", `file to append audit events (JSON Lines) to; "-" for standard output`)
	flag.StringVar(&cfg.trustedProxies, "trusted-proxies", "", "comma-separated IPs or CIDRs of proxies whose X-Forwarded-For is trusted")
	flag.StringVar(&cfg.rateLimit, "rate-limit", "", `maximum requests per client (IP address, /64 for IPv6) as N/WINDOW, e.g. "300/1m"; excess requests get 429`)
	flag.Var(&cfg.rateLimitPaths, "rate-limit-path", `per-client limit for one path as "[METHOD ]PATH=N/WINDOW", e.g. "POST /login=5/1m" or "/api/*=100/1m"; repeatable`)
	flag.StringVar(&cfg.rateLimitExempt, "rate-limit-exempt", "", "comma-separated IPs or CIDRs of clients that are never rate limited")
	flag.IntVar(&cfg.rateLimitMaxClients, "rate-limit-max-clients", ratelimit.DefaultMaxClients, "maximum number of clients whose request rate is tracked at once")
	flag.Var(&cfg.tlsCerts, "tls-cert", "PEM certificate chain file; enables HTTPS on -listen. Repeat with -tls-key for several domains (SNI); the first is the default")
	flag.Var(&cfg.tlsKeys, "tls-key", "PEM private key file for the -tls-cert at the same position")
	flag.StringVar(&cfg.acmeDomains, "acme-domains", "", "comma-separated domains to obtain certificates for from an ACME CA (Let's Encrypt); enables HTTPS on -listen")
	flag.StringVar(&cfg.acmeCache, "acme-cache", "", "directory to store ACME account keys and certificates in, one subdirectory per CA (required with -acme-domains)")
	flag.StringVar(&cfg.acmeEmail, "acme-email", "", "contact email registered with the ACME account")
	flag.StringVar(&cfg.acmeDirectory, "acme-directory", "", "ACME directory URL; default Let's Encrypt, \"staging\" for its staging environment")
	flag.StringVar(&cfg.httpRedirect, "http-redirect", "", `address of a plain HTTP listener that redirects to HTTPS, e.g. ":80"; also answers ACME HTTP-01 challenges (requires HTTPS)`)
	flag.DurationVar(&cfg.hsts.MaxAge, "hsts-max-age", 0, `send Strict-Transport-Security with this max-age on HTTPS responses, e.g. "8760h"; 0 disables`)
	flag.BoolVar(&cfg.hsts.IncludeSubdomains, "hsts-include-subdomains", false, "add includeSubDomains to the HSTS header")
	flag.BoolVar(&cfg.hsts.Preload, "hsts-preload", false, "add preload to the HSTS header (requires -hsts-max-age of at least 8760h and -hsts-include-subdomains)")
	flag.StringVar(&cfg.clientCA, "tls-client-ca", "", "PEM CA file to verify client certificates with (mutual TLS)")
	flag.StringVar(&cfg.clientAuth, "tls-client-auth", "", `client certificate mode with -tls-client-ca: "require" (default) or "optional"`)
	flag.StringVar(&cfg.backendCA, "backend-ca", "", "PEM CA file to verify an https:// backend with, instead of the system CAs")
	flag.BoolVar(&cfg.backendInsecure, "backend-insecure-skip-verify", false, "do not verify the https:// backend certificate (testing only)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(cfg, logger); err != nil {
		logger.Error("prismwaf exited with error", "error", err)
		os.Exit(1)
	}
}

type config struct {
	listen              string
	backends            stringList
	lbPolicy            string
	failTimeout         time.Duration
	healthPath          string
	healthInterval      time.Duration
	healthTimeout       time.Duration
	maxBody             int64
	engine              string
	crsParanoia         int
	crsThreshold        int
	crsMaxArgs          int
	crsBefore           stringList
	crsAfter            stringList
	mode                string
	auditLog            string
	trustedProxies      string
	rateLimit           string
	rateLimitPaths      stringList
	rateLimitExempt     string
	rateLimitMaxClients int
	tlsCerts            stringList
	tlsKeys             stringList
	acmeDomains         string
	acmeCache           string
	acmeEmail           string
	acmeDirectory       string
	httpRedirect        string
	hsts                tlsutil.HSTSPolicy
	clientCA            string
	clientAuth          string
	backendCA           string
	backendInsecure     bool
}

// stringList is a flag that can be repeated.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// Values of -engine.
const (
	engineBuiltin = "builtin"
	engineCRS     = "crs"
	engineBoth    = "both"
)

func (c config) builtinEnabled() bool {
	return c.engine == "" || c.engine == engineBuiltin || c.engine == engineBoth
}
func (c config) crsEnabled() bool { return c.engine == engineCRS || c.engine == engineBoth }

// maxHeaderBytes limits the request line and headers. The query string is
// inspected like the body but is not covered by -max-body, so Go's default
// of 1 MiB would allow far more expensive requests. Larger requests get
// 431 Request Header Fields Too Large.
const maxHeaderBytes = 64 << 10

// defaultBackend is used when no -backend is given.
const defaultBackend = "http://127.0.0.1:8081"

// backendURLs returns the -backend values, split at commas.
func (c config) backendURLs() []string {
	var urls []string
	for _, v := range c.backends {
		urls = append(urls, splitList(v)...)
	}
	if len(urls) == 0 {
		urls = []string{defaultBackend}
	}
	return urls
}

func (c config) rateLimitEnabled() bool { return c.rateLimit != "" || len(c.rateLimitPaths) > 0 }

// rateLimitRules parses -rate-limit and -rate-limit-path.
func (c config) rateLimitRules() ([]ratelimit.Rule, error) {
	var rules []ratelimit.Rule
	if c.rateLimit != "" {
		limit, window, err := ratelimit.ParseRate(c.rateLimit)
		if err != nil {
			return nil, fmt.Errorf("invalid -rate-limit: %w", err)
		}
		rules = append(rules, ratelimit.Rule{Limit: limit, Window: window})
	}
	for _, v := range c.rateLimitPaths {
		r, err := ratelimit.ParseRule(v)
		if err != nil {
			return nil, fmt.Errorf("invalid -rate-limit-path: %w", err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (c config) acmeEnabled() bool { return c.acmeDomains != "" }

func (c config) tlsEnabled() bool { return len(c.tlsCerts) > 0 || c.acmeEnabled() }

func (c config) validate() error {
	switch c.engine {
	case "", engineBuiltin, engineCRS, engineBoth:
	default:
		return fmt.Errorf("invalid -engine %q: must be %q, %q or %q", c.engine, engineBuiltin, engineCRS, engineBoth)
	}
	if !c.crsEnabled() && (len(c.crsBefore) > 0 || len(c.crsAfter) > 0) {
		return errors.New("-crs-rules-before and -crs-rules-after require -engine crs or both")
	}
	// Empty and zero values select the proxy package's defaults.
	if c.lbPolicy != "" {
		if _, err := proxy.ParsePolicy(c.lbPolicy); err != nil {
			return err
		}
	}
	if c.failTimeout < 0 {
		return errors.New("-backend-fail-timeout must not be negative")
	}
	if c.healthPath != "" {
		if !strings.HasPrefix(c.healthPath, "/") {
			return errors.New(`-health-check-path must start with "/"`)
		}
		if c.healthInterval <= 0 || c.healthTimeout <= 0 {
			return errors.New("-health-check-interval and -health-check-timeout must be positive")
		}
	}
	if !c.rateLimitEnabled() && c.rateLimitExempt != "" {
		return errors.New("-rate-limit-exempt requires -rate-limit or -rate-limit-path")
	}
	if _, err := c.rateLimitRules(); err != nil {
		return err
	}
	if _, err := ratelimit.ParsePrefixes(c.rateLimitExempt); err != nil {
		return fmt.Errorf("invalid -rate-limit-exempt: %w", err)
	}
	if c.rateLimitMaxClients < 0 {
		return errors.New("-rate-limit-max-clients must not be negative")
	}
	if len(c.tlsCerts) != len(c.tlsKeys) {
		return errors.New("each -tls-cert needs a matching -tls-key")
	}
	if len(c.tlsCerts) > 0 && c.acmeEnabled() {
		return errors.New("-tls-cert and -acme-domains are mutually exclusive")
	}
	if !c.acmeEnabled() && (c.acmeCache != "" || c.acmeEmail != "" || c.acmeDirectory != "") {
		return errors.New("-acme-cache, -acme-email and -acme-directory require -acme-domains")
	}
	if c.acmeEnabled() && c.acmeCache == "" {
		return errors.New("-acme-domains requires -acme-cache")
	}
	if !c.tlsEnabled() {
		switch {
		case c.httpRedirect != "":
			return errors.New("-http-redirect requires HTTPS (-tls-cert or -acme-domains)")
		case c.hsts != (tlsutil.HSTSPolicy{}):
			return errors.New("-hsts-* options require HTTPS (-tls-cert or -acme-domains)")
		case c.clientCA != "":
			return errors.New("-tls-client-ca requires HTTPS (-tls-cert or -acme-domains)")
		}
	}
	if c.hsts.MaxAge == 0 && (c.hsts.IncludeSubdomains || c.hsts.Preload) {
		return errors.New("-hsts-include-subdomains and -hsts-preload require -hsts-max-age")
	}
	if err := c.hsts.Validate(); err != nil {
		return err
	}
	if c.clientAuth != "" && c.clientCA == "" {
		return errors.New("-tls-client-auth requires -tls-client-ca")
	}
	if _, err := tlsutil.ParseClientAuth(c.clientAuth); err != nil {
		return err
	}
	return nil
}

func run(cfg config, logger *slog.Logger) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	var backends []*url.URL
	for _, raw := range cfg.backendURLs() {
		u, err := proxy.ParseBackend(raw)
		if err != nil {
			return err
		}
		backends = append(backends, u)
	}
	transport, err := backendTransport(cfg)
	if err != nil {
		return err
	}
	rp, err := proxy.New(proxy.Config{
		Backends:    backends,
		Transport:   transport,
		Policy:      proxy.Policy(cfg.lbPolicy),
		FailTimeout: cfg.failTimeout,
		Logger:      logger,
	})
	if err != nil {
		return err
	}
	var signatures []waf.Signature
	if cfg.builtinEnabled() {
		signatures = waf.DefaultSignatures
	}
	inspector, err := waf.NewInspector(signatures, cfg.maxBody)
	if err != nil {
		return err
	}
	var crsEngine *crs.Engine
	if cfg.crsEnabled() {
		start := time.Now()
		crsEngine, err = crs.New(crs.Config{
			ParanoiaLevel:    cfg.crsParanoia,
			InboundThreshold: cfg.crsThreshold,
			MaxArgs:          cfg.crsMaxArgs,
			RulesBefore:      cfg.crsBefore,
			RulesAfter:       cfg.crsAfter,
			MaxBodySize:      cfg.maxBody,
		})
		if err != nil {
			return err
		}
		logger.Info("OWASP CRS loaded", "version", crs.Version, "paranoia_level", cfg.crsParanoia,
			"anomaly_threshold", cfg.crsThreshold, "max_args", cfg.crsMaxArgs, "took", time.Since(start).Round(time.Millisecond))
	}
	mode, err := waf.ParseMode(cfg.mode)
	if err != nil {
		return err
	}
	tp, err := waf.ParseTrustedProxies(cfg.trustedProxies)
	if err != nil {
		return err
	}
	var limiter *ratelimit.Limiter
	if cfg.rateLimitEnabled() {
		rules, err := cfg.rateLimitRules()
		if err != nil {
			return err
		}
		exempt, err := ratelimit.ParsePrefixes(cfg.rateLimitExempt)
		if err != nil {
			return err
		}
		limiter, err = ratelimit.New(ratelimit.Config{
			Rules:      rules,
			Exempt:     exempt,
			MaxClients: cfg.rateLimitMaxClients,
			Logger:     logger,
		})
		if err != nil {
			return err
		}
	}
	auditLogger, closeAudit, err := audit.Open(cfg.auditLog)
	if err != nil {
		return err
	}
	defer closeAudit.Close()

	// Send net/http's own errors, such as failed TLS handshakes of clients
	// without a valid certificate, to the operational log.
	httpErrorLog := slog.NewLogLogger(logger.Handler(), slog.LevelWarn)
	var handler http.Handler = waf.Middleware(rp, waf.Config{
		Inspector:      inspector,
		CRS:            crsEngine,
		RateLimiter:    limiter,
		Mode:           mode,
		Audit:          auditLogger,
		TrustedProxies: tp,
		Logger:         logger,
	})
	if cfg.hsts.MaxAge > 0 {
		// Outermost, so that blocked responses carry the header too.
		handler = tlsutil.HSTS(handler, cfg.hsts)
	}
	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          httpErrorLog,
	}
	servers := []*http.Server{srv}

	var certs *tlsutil.CertReloader
	var acmeManager *tlsutil.ACMEManager
	if cfg.tlsEnabled() {
		opts := tlsutil.ServerOptions{}
		var redirect http.Handler
		if cfg.httpRedirect != "" {
			_, httpsPort, err := net.SplitHostPort(cfg.listen)
			if err != nil {
				return fmt.Errorf("invalid -listen address %q: %w", cfg.listen, err)
			}
			redirect = tlsutil.RedirectHandler(httpsPort)
		}
		if cfg.acmeEnabled() {
			m, err := tlsutil.NewACMEManager(tlsutil.ACMEConfig{
				Domains:      splitList(cfg.acmeDomains),
				CacheDir:     cfg.acmeCache,
				Email:        cfg.acmeEmail,
				DirectoryURL: acmeDirectoryURL(cfg.acmeDirectory),
				Logger:       logger,
			})
			if err != nil {
				return err
			}
			acmeManager = m
			opts.GetCertificate = m.GetCertificate
			opts.ACME = true
			if redirect != nil {
				redirect = m.HTTPHandler(redirect)
			}
		} else {
			pairs := make([]tlsutil.CertPair, len(cfg.tlsCerts))
			for i := range cfg.tlsCerts {
				pairs[i] = tlsutil.CertPair{CertFile: cfg.tlsCerts[i], KeyFile: cfg.tlsKeys[i]}
			}
			certs, err = tlsutil.NewCertReloader(pairs)
			if err != nil {
				return err
			}
			opts.GetCertificate = certs.GetCertificate
		}
		if cfg.clientCA != "" {
			if opts.ClientCAs, err = tlsutil.LoadCAs(cfg.clientCA); err != nil {
				return err
			}
			clientAuth := cfg.clientAuth
			if clientAuth == "" {
				clientAuth = "require"
			}
			if opts.ClientAuth, err = tlsutil.ParseClientAuth(clientAuth); err != nil {
				return err
			}
		}
		srv.TLSConfig = tlsutil.ServerConfig(opts)
		if redirect != nil {
			servers = append(servers, &http.Server{
				Addr:              cfg.httpRedirect,
				Handler:           redirect,
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       120 * time.Second,
				MaxHeaderBytes:    maxHeaderBytes,
				ErrorLog:          httpErrorLog,
			})
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if certs != nil {
		go reloadOnSIGHUP(ctx, certs, logger)
	}
	if cfg.healthPath != "" {
		go rp.HealthCheck(ctx, cfg.healthPath, cfg.healthInterval, cfg.healthTimeout)
	}

	scheme := "http"
	if cfg.tlsEnabled() {
		scheme = "https"
	}
	logger.Info("prismwaf started", "listen", cfg.listen, "scheme", scheme, "backends", cfg.backendURLs(), "lb_policy", cfg.lbPolicy, "engine", cfg.engine, "mode", mode, "audit_log", cfg.auditLog)
	if limiter != nil {
		rules := make([]string, len(limiter.Rules()))
		for i, r := range limiter.Rules() {
			rules[i] = r.String()
		}
		logger.Info("rate limiting enabled", "rules", rules, "exempt", cfg.rateLimitExempt)
		if len(tp) == 0 {
			logger.Info("rate limits count requests per TCP peer; behind a load balancer or CDN, set -trusted-proxies or all clients share one limit")
		}
	}
	if cfg.healthPath != "" {
		logger.Info("health checks enabled", "path", cfg.healthPath, "interval", cfg.healthInterval)
	}
	if cfg.httpRedirect != "" {
		logger.Info("redirecting HTTP to HTTPS", "listen", cfg.httpRedirect)
	}
	if cfg.acmeEnabled() {
		logger.Info("obtaining certificates via ACME", "domains", cfg.acmeDomains, "directory", acmeManager.DirectoryURL(), "cache", acmeManager.CacheDir())
		if cfg.httpRedirect == "" {
			logger.Info("ACME HTTP-01 challenge disabled; TLS-ALPN-01 requires -listen to be reachable on port 443")
		}
	}
	if cfg.hsts.MaxAge > 0 {
		logger.Info("HSTS enabled", "header", cfg.hsts.Header())
	}
	if srv.TLSConfig != nil && srv.TLSConfig.ClientAuth != tls.NoClientCert {
		logger.Info("client certificate authentication enabled", "mode", srv.TLSConfig.ClientAuth.String(), "ca", cfg.clientCA)
	}
	if mode == waf.ModeDetect {
		logger.Warn("detection mode: attacks are logged but NOT blocked")
	}
	if cfg.backendInsecure {
		logger.Warn("backend certificate verification is disabled")
	}

	// Listen before serving, so that the ACME CA can connect as soon as
	// certificates are requested.
	listeners := make([]net.Listener, len(servers))
	for i, s := range servers {
		ln, err := net.Listen("tcp", s.Addr)
		if err != nil {
			for _, l := range listeners[:i] {
				l.Close()
			}
			return err
		}
		listeners[i] = ln
	}
	errCh := make(chan error, len(servers))
	for i, s := range servers {
		go func() {
			if s.TLSConfig != nil {
				// The certificate comes from TLSConfig.GetCertificate.
				errCh <- s.ServeTLS(listeners[i], "", "")
			} else {
				errCh <- s.Serve(listeners[i])
			}
		}()
	}
	if acmeManager != nil {
		go acmeManager.Run(ctx)
	}

	var runErr error
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		if err := s.Shutdown(shutdownCtx); err != nil && runErr == nil {
			runErr = err
		}
	}
	return runErr
}

// splitList splits a comma-separated flag value, ignoring blanks.
func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// acmeDirectoryURL resolves the -acme-directory flag; "" means the
// default, Let's Encrypt.
func acmeDirectoryURL(s string) string {
	if s == "staging" {
		return tlsutil.LetsEncryptStaging
	}
	return s
}

// backendTransport returns the transport for requests to the backend, or
// nil to use http.DefaultTransport.
func backendTransport(cfg config) (http.RoundTripper, error) {
	if cfg.backendCA == "" && !cfg.backendInsecure {
		return nil, nil
	}
	tlsCfg, err := tlsutil.BackendConfig(cfg.backendCA, cfg.backendInsecure)
	if err != nil {
		return nil, err
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = tlsCfg
	return t, nil
}

// reloadOnSIGHUP reloads the TLS certificate whenever the process receives
// SIGHUP, so that renewed certificates are picked up without a restart.
func reloadOnSIGHUP(ctx context.Context, certs *tlsutil.CertReloader, logger *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			if err := certs.Reload(); err != nil {
				logger.Error("TLS certificate reload failed; keeping the current certificate", "error", err)
			} else {
				logger.Info("TLS certificate reloaded")
			}
		}
	}
}
