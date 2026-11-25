// Command prismwaf runs the PrismWAF reverse proxy.
package main

import (
	"cmp"
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
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/cmc-labo/prism-waf/internal/abuse"
	"github.com/cmc-labo/prism-waf/internal/alert"
	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/bot"
	"github.com/cmc-labo/prism-waf/internal/crs"
	"github.com/cmc-labo/prism-waf/internal/ddos"
	"github.com/cmc-labo/prism-waf/internal/geo"
	"github.com/cmc-labo/prism-waf/internal/graphql"
	"github.com/cmc-labo/prism-waf/internal/grpc"
	"github.com/cmc-labo/prism-waf/internal/notify"
	"github.com/cmc-labo/prism-waf/internal/openapi"
	"github.com/cmc-labo/prism-waf/internal/proxy"
	"github.com/cmc-labo/prism-waf/internal/ratelimit"
	"github.com/cmc-labo/prism-waf/internal/tlsutil"
	"github.com/cmc-labo/prism-waf/internal/waf"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(os.Args[2:]))
	}
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
	flag.Var(&cfg.failureLimits, "failure-limit", `per-client limit on failed attempts as "[METHOD ]PATH=N/WINDOW[ STATUS,...]", e.g. "POST /login=5/15m" (failures are 401 and 403 by default) or "POST /redeem=10/1h 4xx"; further requests get 429; repeatable`)
	flag.Var(&cfg.enumerationLimits, "enumeration-limit", `per-client limit on distinct IDs as "[METHOD ]PATH=N/WINDOW" with {name} segments, e.g. "GET /api/orders/{id}=100/1h"; requests for further IDs get 429; repeatable`)
	flag.StringVar(&cfg.rateLimitExempt, "rate-limit-exempt", "", "comma-separated IPs or CIDRs of clients that are never rate limited (nor failure or enumeration limited)")
	flag.IntVar(&cfg.rateLimitMaxClients, "rate-limit-max-clients", ratelimit.DefaultMaxClients, "maximum number of clients whose request rate is tracked at once (also per -failure-limit and for all -enumeration-limit rules)")
	flag.DurationVar(&cfg.readHeaderTimeout, "read-header-timeout", 10*time.Second, "time a client has to send the request line and headers, and a new connection its first bytes; 0 disables")
	flag.DurationVar(&cfg.bodyTimeout, "body-timeout", ddos.DefaultBodyTimeout, "time a client has to start sending a request body, extended by -body-min-rate; slower requests get 408; 0 disables")
	flag.Int64Var(&cfg.bodyMinRate, "body-min-rate", ddos.DefaultBodyMinRate, "minimum rate in bytes per second at which clients must send request bodies after -body-timeout")
	flag.IntVar(&cfg.maxConns, "max-conns", 0, "maximum open client connections; more are closed when accepted; 0 means no limit")
	flag.IntVar(&cfg.maxConnsPerIP, "max-conns-per-ip", 0, "maximum open connections per client IP (/64 for IPv6), except -trusted-proxies; 0 means no limit")
	flag.IntVar(&cfg.maxRequests, "max-requests", 0, "maximum requests in progress; more get 503; 0 means no limit")
	flag.IntVar(&cfg.maxClientRequests, "max-client-requests", 0, "maximum requests in progress per client; more get 429; 0 means no limit")
	flag.StringVar(&cfg.ban, "ban", "", `ban clients whose requests are rejected N times per WINDOW, e.g. "100/1m": all their requests get 403 and their connections are closed for -ban-duration`)
	flag.DurationVar(&cfg.banDuration, "ban-duration", 10*time.Minute, "how long a client is banned by -ban")
	flag.StringVar(&cfg.geoDB, "geo-db", "", "MaxMind DB file to look up the country of clients in (GeoLite2 or GeoIP2 Country or City, DB-IP IP to Country, IPinfo Lite); reloaded when it changes")
	flag.StringVar(&cfg.geoAllow, "geo-allow", "", `comma-separated ISO 3166-1 country codes to allow, e.g. "JP,US"; requests from other countries get 403 ("XX" is unknown)`)
	flag.StringVar(&cfg.geoBlock, "geo-block", "", `comma-separated ISO 3166-1 country codes to block with 403, e.g. "CN,RU" ("XX" is unknown)`)
	flag.StringVar(&cfg.geoExempt, "geo-exempt", "", "comma-separated IPs or CIDRs of clients that are never blocked by country")
	flag.StringVar(&cfg.openAPI, "openapi", "", "OpenAPI 3.0 or 3.1 document (YAML or JSON); requests under the paths of its servers that do not match it get 403")
	flag.Var(&cfg.graphqlPaths, "graphql-path", `GraphQL endpoint to protect, e.g. "/graphql"; repeatable, "*" at the end for a prefix`)
	flag.Var(&cfg.graphqlSchema, "graphql-schema", "GraphQL schema file (SDL); queries that are not valid for it get 403; repeatable")
	flag.IntVar(&cfg.graphqlMaxDepth, "graphql-max-depth", graphql.DefaultMaxDepth, "maximum nesting of fields in a GraphQL query")
	flag.IntVar(&cfg.graphqlMaxAliases, "graphql-max-aliases", graphql.DefaultMaxAliases, "maximum aliased fields per GraphQL request")
	flag.IntVar(&cfg.graphqlMaxFields, "graphql-max-fields", graphql.DefaultMaxFields, "maximum fields per GraphQL request, counting each use of a fragment")
	flag.IntVar(&cfg.graphqlMaxBatch, "graphql-max-batch", graphql.DefaultMaxBatch, "maximum operations in a batched GraphQL request")
	flag.BoolVar(&cfg.graphqlIntrospection, "graphql-introspection", false, "allow GraphQL introspection queries (__schema, __type)")
	flag.Var(&cfg.grpcDescriptors, "grpc-descriptor", "protobuf descriptor set (protoc --include_imports --descriptor_set_out); gRPC calls of other methods and messages that do not match get 403; repeatable")
	flag.BoolVar(&cfg.grpcReflection, "grpc-reflection", false, "allow calls of the gRPC server reflection service")
	flag.BoolVar(&cfg.botProtection, "bot-protection", false, "score how likely each request comes from a bot and make clients that look automated solve a proof-of-work challenge in JavaScript")
	flag.IntVar(&cfg.botChallengeScore, "bot-challenge-score", bot.DefaultChallengeScore, "bot score (0-100) from which clients must solve the challenge")
	flag.IntVar(&cfg.botBlockScore, "bot-block-score", 0, "bot score (0-100) from which requests are rejected with 403 without a challenge; 0 disables")
	flag.IntVar(&cfg.botDifficulty, "bot-difficulty", bot.DefaultDifficulty, fmt.Sprintf("leading zero bits of the challenge's SHA-256 hash (1-%d); each bit doubles the work of the browser", bot.MaxDifficulty))
	flag.DurationVar(&cfg.botClearanceTTL, "bot-clearance-ttl", bot.DefaultClearanceTTL, "how long a solved challenge lets a client through")
	flag.StringVar(&cfg.botSecretFile, "bot-secret-file", "", fmt.Sprintf("file with a key of at least %d bytes to sign challenges and cookies; share it between instances (default: a random key per process)", bot.MinSecretLength))
	flag.Var(&cfg.botPaths, "bot-path", `protect only this path, e.g. "/search" or "/articles/*"; repeatable (default: all paths)`)
	flag.Var(&cfg.botExemptPaths, "bot-exempt-path", `never protect this path, e.g. "/api/*"; repeatable (/robots.txt, /favicon.ico and /.well-known/* are always exempt)`)
	flag.StringVar(&cfg.botExempt, "bot-exempt", "", "comma-separated IPs or CIDRs of clients that are never challenged")
	flag.BoolVar(&cfg.botVerify, "bot-verify", true, "verify bots that name themselves, such as Googlebot and Bingbot, with reverse and forward DNS; let verified bots through and score impersonators higher")
	flag.StringVar(&cfg.botAllowCategories, "bot-allow-category", "", "comma-separated bot categories to let through without a challenge, e.g. \"social,monitoring\" (the User-Agent is not verified)")
	flag.StringVar(&cfg.botBlockCategories, "bot-block-category", "", "comma-separated bot categories to reject with 403, e.g. \"ai_crawler,seo\"")
	flag.StringVar(&cfg.botCaptcha, "bot-captcha", "", "CAPTCHA to show instead of the proof-of-work challenge: "+strings.Join(bot.CaptchaProviders, ", "))
	flag.StringVar(&cfg.botCaptchaSiteKey, "bot-captcha-site-key", "", "site key of the -bot-captcha provider")
	flag.StringVar(&cfg.botCaptchaSecretFile, "bot-captcha-secret-file", "", "file with the secret key of the -bot-captcha provider")
	flag.IntVar(&cfg.botCaptchaScore, "bot-captcha-score", 0, "bot score from which the CAPTCHA is shown instead of the proof-of-work challenge (default: -bot-challenge-score, i.e. always)")
	flag.Float64Var(&cfg.botCaptchaMinScore, "bot-captcha-min-score", bot.DefaultCaptchaMinScore, "reCAPTCHA v3 score (0.0-1.0) from which a client passes")
	flag.Var(&cfg.tlsCerts, "tls-cert", "PEM certificate chain file; enables HTTPS on -listen. Repeat with -tls-key for several domains (SNI); the first is the default")
	flag.Var(&cfg.tlsKeys, "tls-key", "PEM private key file for the -tls-cert at the same position")
	flag.StringVar(&cfg.acmeDomains, "acme-domains", "", "comma-separated domains to obtain certificates for from an ACME CA (Let's Encrypt); enables HTTPS on -listen")
	flag.StringVar(&cfg.acmeCache, "acme-cache", "", "directory to store ACME account keys and certificates in, one subdirectory per CA (required with -acme-domains)")
	flag.StringVar(&cfg.acmeEmail, "acme-email", "", "contact email registered with the ACME account")
	flag.StringVar(&cfg.acmeDirectory, "acme-directory", "", "ACME directory URL; default Let's Encrypt, \"staging\" for its staging environment")
	flag.StringVar(&cfg.acmeNotifyWebhook, "acme-notify-webhook", "", "URL to POST a notification to when a certificate is about to expire, has expired or cannot be obtained")
	flag.StringVar(&cfg.acmeNotifyFormat, "acme-notify-webhook-format", notify.FormatJSON, `payload of -acme-notify-webhook: "json", "slack" (also Mattermost, Google Chat) or "discord"`)
	flag.StringVar(&cfg.acmeNotifyCommand, "acme-notify-command", "", "shell command to run for each certificate notification; the event is passed as JSON on stdin and in PRISMWAF_* variables")
	flag.BoolVar(&cfg.acmeNotifyTest, "acme-notify-test", false, "send a test notification to the -acme-notify-* targets and exit")
	flag.DurationVar(&cfg.acmeNotifyRepeat, "acme-notify-repeat", tlsutil.DefaultNotifyRepeat, "how often a certificate notification is repeated while its problem lasts; 0 notifies each problem once")
	flag.StringVar(&cfg.acmeNotifyRateLimit, "acme-notify-rate-limit", defaultNotifyRateLimit, `most certificate notifications sent per window as N/WINDOW; the others are sent together when the window ends. "off" disables`)
	flag.StringVar(&cfg.alertRequests, "alert-rate-limited-requests", "", `alert when the rate limits reject this many requests of all clients together, as N/WINDOW, e.g. "1000/5m"`)
	flag.StringVar(&cfg.alertClients, "alert-rate-limited-clients", "", `alert when this many distinct clients exceed a rate limit, as N/WINDOW, e.g. "50/5m"`)
	flag.StringVar(&cfg.alertClient, "alert-rate-limited-client", "", `alert when the requests of one client are rejected by the rate limits this many times, as N/WINDOW, e.g. "300/5m"`)
	flag.StringVar(&cfg.alertWebhook, "alert-webhook", "", "URL to POST rate limit alerts to; alerts are always logged")
	flag.StringVar(&cfg.alertFormat, "alert-webhook-format", notify.FormatJSON, `payload of -alert-webhook: "json", "slack" (also Mattermost, Google Chat) or "discord"`)
	flag.StringVar(&cfg.alertCommand, "alert-command", "", "shell command to run for each rate limit alert; the alert is passed as JSON on stdin and in PRISMWAF_* variables")
	flag.StringVar(&cfg.alertNotifyRateLimit, "alert-notify-rate-limit", defaultNotifyRateLimit, `most alerts sent per window as N/WINDOW; the others are sent together when the window ends. "off" disables`)
	flag.BoolVar(&cfg.alertTest, "alert-test", false, "send a test alert to -alert-webhook and -alert-command and exit")
	flag.StringVar(&cfg.httpRedirect, "http-redirect", "", `address of a plain HTTP listener that redirects to HTTPS, e.g. ":80"; also answers ACME HTTP-01 challenges (requires HTTPS)`)
	flag.DurationVar(&cfg.hsts.MaxAge, "hsts-max-age", 0, `send Strict-Transport-Security with this max-age on HTTPS responses, e.g. "8760h"; 0 disables`)
	flag.BoolVar(&cfg.hsts.IncludeSubdomains, "hsts-include-subdomains", false, "add includeSubDomains to the HSTS header")
	flag.BoolVar(&cfg.hsts.Preload, "hsts-preload", false, "add preload to the HSTS header (requires -hsts-max-age of at least 8760h and -hsts-include-subdomains)")
	flag.StringVar(&cfg.clientCA, "tls-client-ca", "", "PEM CA file to verify client certificates with (mutual TLS)")
	flag.StringVar(&cfg.clientAuth, "tls-client-auth", "", `client certificate mode with -tls-client-ca: "require" (default) or "optional"`)
	flag.StringVar(&cfg.backendCA, "backend-ca", "", "PEM CA file to verify an https:// backend with, instead of the system CAs")
	flag.BoolVar(&cfg.backendInsecure, "backend-insecure-skip-verify", false, "do not verify the https:// backend certificate (testing only)")
	flag.StringVar(&cfg.probeListen, "probe-listen", "", `address of a separate listener for liveness and readiness probes (GET /healthz, /readyz), e.g. "127.0.0.1:9090" or ":9090" in a container`)
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintf(out, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(out, "\nEvery option can also be set with an environment variable, e.g. %s=300/1m for -rate-limit;\n"+
			"the command line takes precedence. Repeatable options take one value per line.\n", envName("rate-limit"))
	}
	flag.Parse()
	if err := applyEnv(flag.CommandLine, os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	flag.Visit(func(f *flag.Flag) { cfg.setFlags = append(cfg.setFlags, f.Name) })

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(cfg, logger); err != nil {
		logger.Error("prismwaf exited with error", "error", err)
		os.Exit(1)
	}
}

type config struct {
	listen               string
	backends             stringList
	lbPolicy             string
	failTimeout          time.Duration
	healthPath           string
	healthInterval       time.Duration
	healthTimeout        time.Duration
	maxBody              int64
	engine               string
	crsParanoia          int
	crsThreshold         int
	crsMaxArgs           int
	crsBefore            stringList
	crsAfter             stringList
	mode                 string
	auditLog             string
	trustedProxies       string
	rateLimit            string
	rateLimitPaths       stringList
	rateLimitExempt      string
	failureLimits        stringList
	enumerationLimits    stringList
	rateLimitMaxClients  int
	readHeaderTimeout    time.Duration
	bodyTimeout          time.Duration
	bodyMinRate          int64
	maxConns             int
	maxConnsPerIP        int
	maxRequests          int
	maxClientRequests    int
	ban                  string
	banDuration          time.Duration
	geoDB                string
	geoAllow             string
	geoBlock             string
	geoExempt            string
	openAPI              string
	graphqlPaths         stringList
	graphqlSchema        stringList
	graphqlMaxDepth      int
	graphqlMaxAliases    int
	graphqlMaxFields     int
	graphqlMaxBatch      int
	graphqlIntrospection bool
	grpcDescriptors      stringList
	grpcReflection       bool
	botProtection        bool
	botChallengeScore    int
	botBlockScore        int
	botDifficulty        int
	botClearanceTTL      time.Duration
	botSecretFile        string
	botPaths             stringList
	botExemptPaths       stringList
	botExempt            string
	botVerify            bool
	botAllowCategories   string
	botBlockCategories   string
	botCaptcha           string
	botCaptchaSiteKey    string
	botCaptchaSecretFile string
	botCaptchaScore      int
	botCaptchaMinScore   float64
	tlsCerts             stringList
	tlsKeys              stringList
	acmeDomains          string
	acmeCache            string
	acmeEmail            string
	acmeDirectory        string
	acmeNotifyWebhook    string
	acmeNotifyFormat     string
	acmeNotifyCommand    string
	acmeNotifyTest       bool
	acmeNotifyRepeat     time.Duration
	acmeNotifyRateLimit  string
	alertRequests        string
	alertClients         string
	alertClient          string
	alertWebhook         string
	alertFormat          string
	alertCommand         string
	alertNotifyRateLimit string
	alertTest            bool
	httpRedirect         string
	hsts                 tlsutil.HSTSPolicy
	clientCA             string
	clientAuth           string
	backendCA            string
	backendInsecure      bool
	probeListen          string
	// setFlags are the names of the flags given on the command line or
	// in environment variables, to reject options that would be ignored even when they have their
	// default value.
	setFlags []string
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

// validateDoS checks the options against denial of service.
func (c config) validateDoS() error {
	if c.readHeaderTimeout < 0 || c.bodyTimeout < 0 {
		return errors.New("-read-header-timeout and -body-timeout must not be negative")
	}
	if c.bodyMinRate < 0 {
		return errors.New("-body-min-rate must not be negative")
	}
	if c.maxConns < 0 || c.maxConnsPerIP < 0 || c.maxRequests < 0 || c.maxClientRequests < 0 {
		return errors.New("-max-conns, -max-conns-per-ip, -max-requests and -max-client-requests must not be negative")
	}
	if c.ban != "" {
		if _, _, err := ratelimit.ParseRate(c.ban); err != nil {
			return fmt.Errorf("invalid -ban: %w", err)
		}
		if c.banDuration <= 0 {
			return errors.New("-ban-duration must be positive")
		}
	} else if slices.Contains(c.setFlags, "ban-duration") {
		return errors.New("-ban-duration requires -ban")
	}
	return nil
}

func (c config) abuseEnabled() bool { return len(c.failureLimits) > 0 || len(c.enumerationLimits) > 0 }

// abuseConfig parses -failure-limit and -enumeration-limit.
func (c config) abuseConfig() (abuse.Config, error) {
	var ac abuse.Config
	for _, v := range c.failureLimits {
		r, err := abuse.ParseFailureRule(v)
		if err != nil {
			return ac, fmt.Errorf("invalid -failure-limit: %w", err)
		}
		ac.Failures = append(ac.Failures, r)
	}
	for _, v := range c.enumerationLimits {
		r, err := abuse.ParseEnumerationRule(v)
		if err != nil {
			return ac, fmt.Errorf("invalid -enumeration-limit: %w", err)
		}
		ac.Enumerations = append(ac.Enumerations, r)
	}
	return ac, nil
}

// geoConfig returns the configuration of the country filter, without the
// database, which is opened by run.
func (c config) geoConfig() (geo.Config, error) {
	allow, err := geo.ParseCountries(c.geoAllow)
	if err != nil {
		return geo.Config{}, fmt.Errorf("invalid -geo-allow: %w", err)
	}
	block, err := geo.ParseCountries(c.geoBlock)
	if err != nil {
		return geo.Config{}, fmt.Errorf("invalid -geo-block: %w", err)
	}
	exempt, err := ratelimit.ParsePrefixes(c.geoExempt)
	if err != nil {
		return geo.Config{}, fmt.Errorf("invalid -geo-exempt: %w", err)
	}
	return geo.Config{Allow: allow, Block: block, Exempt: exempt}, nil
}

// graphqlConfig returns the configuration of GraphQL protection, without
// the schema, which is loaded by run.
func (c config) graphqlConfig() graphql.Config {
	return graphql.Config{
		Paths:         c.graphqlPaths,
		MaxDepth:      c.graphqlMaxDepth,
		MaxAliases:    c.graphqlMaxAliases,
		MaxFields:     c.graphqlMaxFields,
		MaxBatch:      c.graphqlMaxBatch,
		Introspection: c.graphqlIntrospection,
	}
}

// botConfig returns the configuration of the bot guard, without the
// secret, which is read from -bot-secret-file by run.
func (c config) botConfig() (bot.Config, error) {
	exempt, err := ratelimit.ParsePrefixes(c.botExempt)
	if err != nil {
		return bot.Config{}, fmt.Errorf("invalid -bot-exempt: %w", err)
	}
	allow, err := bot.ParseCategories(c.botAllowCategories)
	if err != nil {
		return bot.Config{}, fmt.Errorf("invalid -bot-allow-category: %w", err)
	}
	block, err := bot.ParseCategories(c.botBlockCategories)
	if err != nil {
		return bot.Config{}, fmt.Errorf("invalid -bot-block-category: %w", err)
	}
	bc := bot.Config{
		ChallengeScore:  c.botChallengeScore,
		BlockScore:      c.botBlockScore,
		Difficulty:      c.botDifficulty,
		ClearanceTTL:    c.botClearanceTTL,
		Paths:           c.botPaths,
		ExemptPaths:     c.botExemptPaths,
		Exempt:          exempt,
		VerifyBots:      c.botVerify,
		AllowCategories: allow,
		BlockCategories: block,
		CaptchaScore:    c.botCaptchaScore,
	}
	if c.botCaptcha != "" {
		bc.Captcha = &bot.CaptchaConfig{
			Provider: c.botCaptcha,
			SiteKey:  c.botCaptchaSiteKey,
			MinScore: c.botCaptchaMinScore,
		}
	}
	return bc, nil
}

// readCaptchaSecret reads -bot-captcha-secret-file.
func readCaptchaSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("invalid -bot-captcha-secret-file: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New("invalid -bot-captcha-secret-file: the file is empty")
	}
	return s, nil
}

// readBotSecret reads -bot-secret-file. Surrounding whitespace, such as
// the newline of a key generated with "openssl rand -base64 32", is
// ignored.
func readBotSecret(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("invalid -bot-secret-file: %w", err)
	}
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) < bot.MinSecretLength {
		return nil, fmt.Errorf("invalid -bot-secret-file: the key must be at least %d bytes, e.g. from \"openssl rand -base64 32\"", bot.MinSecretLength)
	}
	return b, nil
}

func (c config) acmeEnabled() bool { return c.acmeDomains != "" }

func (c config) acmeNotifyEnabled() bool {
	return c.acmeNotifyWebhook != "" || c.acmeNotifyCommand != ""
}

// defaultNotifyRateLimit is the default of -acme-notify-rate-limit:
// enough for the problems and recoveries of a few domains, while a CA
// outage that affects many domains is sent as a digest.
const defaultNotifyRateLimit = "10/1h"

// notifier returns the notifier for ACME certificate events.
func (c config) notifier(logger *slog.Logger) (*notify.Notifier, error) {
	return newNotifier(c.acmeNotifyWebhook, c.acmeNotifyFormat, c.acmeNotifyCommand, c.acmeNotifyRateLimit, "-acme-notify-rate-limit", logger)
}

// newNotifier returns a notifier for a set of -*-webhook, -*-webhook-format,
// -*-command and -*-rate-limit options; rateFlag names the latter in
// errors.
func newNotifier(webhook, format, command, rate, rateFlag string, logger *slog.Logger) (*notify.Notifier, error) {
	if webhook == "" {
		format = "" // the default of the flag; irrelevant without a webhook
	}
	var limit int
	var window time.Duration
	if rate != "" && rate != "off" {
		var err error
		if limit, window, err = ratelimit.ParseRate(rate); err != nil {
			return nil, fmt.Errorf("invalid %s: %w", rateFlag, err)
		}
	}
	return notify.New(notify.Config{
		WebhookURL:    webhook,
		WebhookFormat: format,
		Command:       command,
		Logger:        logger,
		RateLimit:     limit,
		RateWindow:    window,
	})
}

func (c config) alertEnabled() bool {
	return c.alertRequests != "" || c.alertClients != "" || c.alertClient != ""
}

func (c config) alertNotifyEnabled() bool { return c.alertWebhook != "" || c.alertCommand != "" }

// alertNotifier returns the notifier for rate limit alerts.
func (c config) alertNotifier(logger *slog.Logger) (*notify.Notifier, error) {
	return newNotifier(c.alertWebhook, c.alertFormat, c.alertCommand, c.alertNotifyRateLimit, "-alert-notify-rate-limit", logger)
}

// alertConfig parses the -alert-rate-limited-* thresholds.
func (c config) alertConfig() (alert.Config, error) {
	var ac alert.Config
	for _, t := range []struct {
		flag, value string
		threshold   *alert.Threshold
	}{
		{"-alert-rate-limited-requests", c.alertRequests, &ac.Requests},
		{"-alert-rate-limited-clients", c.alertClients, &ac.Clients},
		{"-alert-rate-limited-client", c.alertClient, &ac.Client},
	} {
		if t.value == "" {
			continue
		}
		n, window, err := ratelimit.ParseRate(t.value)
		if err != nil {
			return ac, fmt.Errorf("invalid %s: %w", t.flag, err)
		}
		*t.threshold = alert.Threshold{Count: n, Window: window}
	}
	if ac.Clients.Count > alert.MaxClients {
		return ac, fmt.Errorf("invalid -alert-rate-limited-clients: at most %d clients", alert.MaxClients)
	}
	return ac, nil
}

// acmeNotifyRepeatInterval returns ACMEConfig.NotifyRepeat for
// -acme-notify-repeat.
func (c config) acmeNotifyRepeatInterval() time.Duration {
	if c.acmeNotifyRepeat == 0 {
		return -1 // never
	}
	return c.acmeNotifyRepeat
}

func (c config) tlsEnabled() bool { return len(c.tlsCerts) > 0 || c.acmeEnabled() }

func (c config) validate() error {
	if err := c.validateDoS(); err != nil {
		return err
	}
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
	if !c.rateLimitEnabled() && !c.abuseEnabled() && c.ban == "" && c.maxConnsPerIP == 0 && c.maxClientRequests == 0 && c.rateLimitExempt != "" {
		return errors.New("-rate-limit-exempt requires -rate-limit, -rate-limit-path, -failure-limit, -enumeration-limit, -ban, -max-conns-per-ip or -max-client-requests")
	}
	if _, err := c.rateLimitRules(); err != nil {
		return err
	}
	if _, err := c.abuseConfig(); err != nil {
		return err
	}
	if _, err := ratelimit.ParsePrefixes(c.rateLimitExempt); err != nil {
		return fmt.Errorf("invalid -rate-limit-exempt: %w", err)
	}
	if c.rateLimitMaxClients < 0 {
		return errors.New("-rate-limit-max-clients must not be negative")
	}
	if c.geoDB == "" && (c.geoAllow != "" || c.geoBlock != "" || c.geoExempt != "") {
		return errors.New("-geo-allow, -geo-block and -geo-exempt require -geo-db")
	}
	if c.geoAllow != "" && c.geoBlock != "" {
		return errors.New("-geo-allow and -geo-block are mutually exclusive")
	}
	if c.geoExempt != "" && c.geoAllow == "" && c.geoBlock == "" {
		return errors.New("-geo-exempt requires -geo-allow or -geo-block")
	}
	if _, err := c.geoConfig(); err != nil {
		return err
	}
	graphqlFlags := false
	for _, name := range c.setFlags {
		graphqlFlags = graphqlFlags || strings.HasPrefix(name, "graphql-") && name != "graphql-path"
	}
	if len(c.graphqlPaths) == 0 && (graphqlFlags || len(c.graphqlSchema) > 0 || c.graphqlIntrospection) {
		return errors.New("-graphql-* options require -graphql-path")
	}
	if len(c.graphqlPaths) > 0 {
		for _, l := range []struct {
			name  string
			value int
		}{{"depth", c.graphqlMaxDepth}, {"aliases", c.graphqlMaxAliases}, {"fields", c.graphqlMaxFields}, {"batch", c.graphqlMaxBatch}} {
			if l.value < 1 {
				return fmt.Errorf("-graphql-max-%s must be at least 1", l.name)
			}
		}
		if _, err := graphql.New(c.graphqlConfig()); err != nil {
			return fmt.Errorf("invalid -graphql-path: %w", err)
		}
	}
	botFlags, captchaFlags := false, false
	for _, name := range c.setFlags {
		botFlags = botFlags || strings.HasPrefix(name, "bot-") && name != "bot-protection"
		captchaFlags = captchaFlags || strings.HasPrefix(name, "bot-captcha-")
	}
	if !c.botProtection && (botFlags || c.botSecretFile != "" || len(c.botPaths) > 0 || len(c.botExemptPaths) > 0 || c.botExempt != "" ||
		c.botAllowCategories != "" || c.botBlockCategories != "" || c.botCaptcha != "") {
		return errors.New("-bot-* options require -bot-protection")
	}
	if c.botCaptcha == "" && (captchaFlags || c.botCaptchaSiteKey != "" || c.botCaptchaSecretFile != "" || c.botCaptchaScore != 0) {
		return errors.New("-bot-captcha-* options require -bot-captcha")
	}
	if c.botCaptcha != "" && (c.botCaptchaSiteKey == "" || c.botCaptchaSecretFile == "") {
		return errors.New("-bot-captcha requires -bot-captcha-site-key and -bot-captcha-secret-file")
	}
	if c.botProtection {
		bc, err := c.botConfig()
		if err != nil {
			return err
		}
		if bc.Captcha != nil {
			bc.Captcha.Secret = "checked at startup" // read by run
		}
		if _, err := bot.New(bc); err != nil {
			return fmt.Errorf("invalid -bot-* option: %w", err)
		}
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
	if !c.acmeEnabled() && (c.acmeNotifyEnabled() || c.acmeNotifyTest) {
		return errors.New("-acme-notify-* options require -acme-domains")
	}
	if c.acmeNotifyWebhook == "" && slices.Contains(c.setFlags, "acme-notify-webhook-format") {
		return errors.New("-acme-notify-webhook-format requires -acme-notify-webhook")
	}
	if !c.acmeNotifyEnabled() && (slices.Contains(c.setFlags, "acme-notify-repeat") || slices.Contains(c.setFlags, "acme-notify-rate-limit")) {
		return errors.New("-acme-notify-repeat and -acme-notify-rate-limit require -acme-notify-webhook or -acme-notify-command")
	}
	if c.acmeNotifyRepeat < 0 {
		return errors.New("-acme-notify-repeat must not be negative")
	}
	if c.acmeNotifyTest && !c.acmeNotifyEnabled() {
		return errors.New("-acme-notify-test requires -acme-notify-webhook or -acme-notify-command")
	}
	if c.acmeNotifyEnabled() {
		if _, err := c.notifier(nil); err != nil {
			return err
		}
	}
	if c.alertEnabled() {
		if !c.rateLimitEnabled() {
			return errors.New("-alert-rate-limited-* options require -rate-limit or -rate-limit-path")
		}
		if _, err := c.alertConfig(); err != nil {
			return err
		}
	}
	if c.alertNotifyEnabled() && !c.alertEnabled() && !c.alertTest {
		return errors.New("-alert-webhook and -alert-command require an -alert-rate-limited-* threshold")
	}
	if c.alertWebhook == "" && slices.Contains(c.setFlags, "alert-webhook-format") {
		return errors.New("-alert-webhook-format requires -alert-webhook")
	}
	if !c.alertNotifyEnabled() && slices.Contains(c.setFlags, "alert-notify-rate-limit") {
		return errors.New("-alert-notify-rate-limit requires -alert-webhook or -alert-command")
	}
	if c.alertTest && !c.alertNotifyEnabled() {
		return errors.New("-alert-test requires -alert-webhook or -alert-command")
	}
	if c.alertNotifyEnabled() {
		if _, err := c.alertNotifier(nil); err != nil {
			return err
		}
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
	var notifier *notify.Notifier
	if cfg.acmeNotifyEnabled() {
		var err error
		if notifier, err = cfg.notifier(logger); err != nil {
			return err
		}
	}
	var alertNotifier *notify.Notifier
	if cfg.alertNotifyEnabled() {
		var err error
		if alertNotifier, err = cfg.alertNotifier(logger); err != nil {
			return err
		}
	}
	if cfg.acmeNotifyTest || cfg.alertTest {
		if cfg.acmeNotifyTest {
			domains := splitList(cfg.acmeDomains)
			if err := sendTestNotification(notifier, domains[0], "Test notification: PrismWAF will notify here when a certificate for "+strings.Join(domains, ", ")+" is about to expire, has expired or cannot be obtained.", logger); err != nil {
				return err
			}
		}
		if cfg.alertTest {
			if err := sendTestNotification(alertNotifier, "", "Test alert: PrismWAF will alert here when the rate limits are triggered more often than the -alert-rate-limited-* thresholds.", logger); err != nil {
				return err
			}
		}
		return nil
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
	var geoFilter *geo.Filter
	if cfg.geoDB != "" {
		gc, err := cfg.geoConfig()
		if err != nil {
			return err
		}
		if gc.DB, err = geo.OpenDB(cfg.geoDB, logger); err != nil {
			return err
		}
		if geoFilter, err = geo.New(gc); err != nil {
			return err
		}
	}
	var apiSpec *openapi.Validator
	if cfg.openAPI != "" {
		if apiSpec, err = openapi.Load(cfg.openAPI); err != nil {
			return err
		}
	}
	var graphqlGuard *graphql.Guard
	if len(cfg.graphqlPaths) > 0 {
		gc := cfg.graphqlConfig()
		if len(cfg.graphqlSchema) > 0 {
			if gc.Schema, err = graphql.LoadSchema(cfg.graphqlSchema); err != nil {
				return err
			}
		}
		if graphqlGuard, err = graphql.New(gc); err != nil {
			return err
		}
	}
	grpcConfig := grpc.Config{Reflection: cfg.grpcReflection}
	if len(cfg.grpcDescriptors) > 0 {
		if grpcConfig.Schema, err = grpc.LoadSchema(cfg.grpcDescriptors); err != nil {
			return err
		}
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
	var alerts *alert.Monitor
	if cfg.alertEnabled() {
		ac, err := cfg.alertConfig()
		if err != nil {
			return err
		}
		ac.Logger = logger
		if alertNotifier != nil {
			// Not a typed nil in the interface.
			ac.Notifier = alertNotifier
		}
		if alerts, err = alert.New(ac); err != nil {
			return err
		}
	}
	var abuseGuard *abuse.Guard
	if cfg.abuseEnabled() {
		ac, err := cfg.abuseConfig()
		if err != nil {
			return err
		}
		if ac.Exempt, err = ratelimit.ParsePrefixes(cfg.rateLimitExempt); err != nil {
			return err
		}
		ac.MaxClients, ac.Logger = cfg.rateLimitMaxClients, logger
		if abuseGuard, err = abuse.New(ac); err != nil {
			return err
		}
	}
	dosExempt, err := ratelimit.ParsePrefixes(cfg.rateLimitExempt)
	if err != nil {
		return err
	}
	var bans *ddos.Bans
	if cfg.ban != "" {
		limit, window, _ := ratelimit.ParseRate(cfg.ban)
		if bans, err = ddos.NewBans(ddos.BanConfig{
			Limit: limit, Window: window, Duration: cfg.banDuration,
			Exempt: dosExempt, MaxClients: cfg.rateLimitMaxClients, Logger: logger,
		}); err != nil {
			return err
		}
	}
	var concurrency *ddos.Concurrency
	if cfg.maxRequests > 0 || cfg.maxClientRequests > 0 {
		if concurrency, err = ddos.NewConcurrency(ddos.ConcurrencyConfig{
			Max: cfg.maxRequests, MaxPerClient: cfg.maxClientRequests, Exempt: dosExempt,
		}); err != nil {
			return err
		}
	}
	var guard *bot.Guard
	if cfg.botProtection {
		bc, err := cfg.botConfig()
		if err != nil {
			return err
		}
		if cfg.botSecretFile != "" {
			if bc.Secret, err = readBotSecret(cfg.botSecretFile); err != nil {
				return err
			}
		}
		if bc.Captcha != nil {
			if bc.Captcha.Secret, err = readCaptchaSecret(cfg.botCaptchaSecretFile); err != nil {
				return err
			}
		}
		bc.Logger = logger
		if guard, err = bot.New(bc); err != nil {
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
		Inspector:       inspector,
		CRS:             crsEngine,
		Geo:             geoFilter,
		OpenAPI:         apiSpec,
		GraphQL:         graphqlGuard,
		GRPC:            grpc.New(grpcConfig),
		RateLimiter:     limiter,
		RateLimitAlerts: alerts,
		Abuse:           abuseGuard,
		Bans:            bans,
		Concurrency:     concurrency,
		BodyTimeout:     ddos.BodyTimeout{Timeout: cfg.bodyTimeout, MinRate: cfg.bodyMinRate},
		Bot:             guard,
		Mode:            mode,
		Audit:           auditLogger,
		TrustedProxies:  tp,
		Logger:          logger,
	})
	if cfg.hsts.MaxAge > 0 {
		// Outermost, so that blocked responses carry the header too.
		handler = tlsutil.HSTS(handler, cfg.hsts)
	}
	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           handler,
		ReadHeaderTimeout: cfg.readHeaderTimeout,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          httpErrorLog,
		// HTTP/2 also without TLS (h2c with prior knowledge), as gRPC
		// clients use on internal networks.
		Protocols: serverProtocols(),
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
			acmeCfg := tlsutil.ACMEConfig{
				Domains:      splitList(cfg.acmeDomains),
				CacheDir:     cfg.acmeCache,
				Email:        cfg.acmeEmail,
				DirectoryURL: acmeDirectoryURL(cfg.acmeDirectory),
				Logger:       logger,
			}
			if notifier != nil {
				// Not a typed nil in the interface.
				acmeCfg.Notifier = notifier
				acmeCfg.NotifyRepeat = cfg.acmeNotifyRepeatInterval()
			}
			m, err := tlsutil.NewACMEManager(acmeCfg)
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
				ReadHeaderTimeout: cfg.readHeaderTimeout,
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
	if geoFilter != nil {
		go geoFilter.DB().Run(ctx)
	}
	if cfg.healthPath != "" {
		go rp.HealthCheck(ctx, cfg.healthPath, cfg.healthInterval, cfg.healthTimeout)
	}

	scheme := "http"
	if cfg.tlsEnabled() {
		scheme = "https"
	}
	logger.Info("prismwaf started", "listen", cfg.listen, "scheme", scheme, "backends", cfg.backendURLs(), "lb_policy", cfg.lbPolicy, "engine", cfg.engine, "mode", mode, "audit_log", cfg.auditLog)
	if geoFilter != nil {
		m := geoFilter.DB().Metadata()
		built := m.BuildTime().UTC().Format(time.DateOnly)
		logger.Info("GeoIP enabled", "db", cfg.geoDB, "type", m.DatabaseType, "built", built,
			"allow", cfg.geoAllow, "block", cfg.geoBlock, "exempt", cfg.geoExempt)
		if geoFilter.DB().Stale(time.Now()) {
			logger.Warn("the GeoIP database is outdated", "built", built, "hint", "update it at least monthly")
		}
		if m.IPVersion == 4 {
			logger.Warn("the GeoIP database has only IPv4 addresses; IPv6 clients are unknown (XX)")
		}
		if len(tp) == 0 {
			logger.Info("countries are looked up for the TCP peer address; behind a load balancer or CDN, set -trusted-proxies, or the address of the proxy is looked up for every client")
		}
	}
	if apiSpec != nil {
		logger.Info("OpenAPI validation enabled", "document", cfg.openAPI, "version", apiSpec.Version(),
			"operations", apiSpec.Operations(), "paths", apiSpec.BasePaths())
	}
	if graphqlGuard != nil {
		gc := graphqlGuard.Config()
		logger.Info("GraphQL protection enabled", "paths", cfg.graphqlPaths, "schema", cfg.graphqlSchema,
			"max_depth", gc.MaxDepth, "max_aliases", gc.MaxAliases, "max_fields", gc.MaxFields, "max_batch", gc.MaxBatch,
			"introspection", gc.Introspection)
	}
	if grpcConfig.Schema != nil {
		logger.Info("gRPC schema validation enabled", "descriptors", cfg.grpcDescriptors, "services", grpcConfig.Schema.Services())
	}
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
	if abuseGuard != nil {
		// The rules as they are applied, with the default statuses.
		ac, _ := cfg.abuseConfig()
		var failures, enumerations []string
		for _, r := range ac.Failures {
			failures = append(failures, r.String())
		}
		for _, r := range ac.Enumerations {
			enumerations = append(enumerations, r.String())
		}
		logger.Info("business flow protection enabled", "failure_limits", failures, "enumeration_limits", enumerations, "exempt", cfg.rateLimitExempt)
		if len(tp) == 0 {
			logger.Info("failure and enumeration limits count requests per TCP peer; behind a load balancer or CDN, set -trusted-proxies or all clients share one limit")
		}
	}
	logger.Info("denial of service protection", "read_header_timeout", cfg.readHeaderTimeout,
		"body_timeout", cfg.bodyTimeout, "body_min_rate", cfg.bodyMinRate,
		"max_conns", cfg.maxConns, "max_conns_per_ip", cfg.maxConnsPerIP,
		"max_requests", cfg.maxRequests, "max_client_requests", cfg.maxClientRequests, "ban", banRule(bans))
	if guard != nil {
		blockScore := "disabled"
		if guard.BlockScore() > 0 {
			blockScore = fmt.Sprint(guard.BlockScore())
		}
		logger.Info("bot protection enabled", "challenge_score", guard.ChallengeScore(), "block_score", blockScore,
			"difficulty", guard.Difficulty(), "clearance_ttl", cfg.botClearanceTTL, "paths", cfg.botPaths, "exempt_paths", cfg.botExemptPaths, "exempt", cfg.botExempt,
			"verify_bots", cfg.botVerify, "allow_categories", cfg.botAllowCategories, "block_categories", cfg.botBlockCategories)
		if cfg.botCaptcha != "" {
			logger.Info("bot CAPTCHA enabled", "provider", cfg.botCaptcha, "score", guard.CaptchaScore())
		}
		if cfg.botSecretFile == "" {
			logger.Info("bot clearance cookies are signed with a random key: they become invalid when PrismWAF restarts, and other instances do not accept them; set -bot-secret-file to keep them")
		}
		if len(tp) == 0 {
			logger.Info("bot clearance is bound to the TCP peer address; behind a load balancer or CDN, set -trusted-proxies")
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
		if notifier != nil {
			logger.Info("ACME certificate notifications enabled", "targets", notifier.Targets(), "repeat", cfg.acmeNotifyRepeat, "rate_limit", cmp.Or(cfg.acmeNotifyRateLimit, "off"))
		} else {
			logger.Info("ACME certificate notifications disabled; set -acme-notify-webhook or -acme-notify-command to be told when certificates are not renewed")
		}
		if cfg.httpRedirect == "" {
			logger.Info("ACME HTTP-01 challenge disabled; TLS-ALPN-01 requires -listen to be reachable on port 443")
		}
	}
	if alerts != nil {
		args := []any{"requests", cmp.Or(cfg.alertRequests, "off"), "clients", cmp.Or(cfg.alertClients, "off"), "client", cmp.Or(cfg.alertClient, "off")}
		if alertNotifier != nil {
			args = append(args, "targets", alertNotifier.Targets(), "rate_limit", cmp.Or(cfg.alertNotifyRateLimit, "off"))
		}
		logger.Info("rate limit alerts enabled", args...)
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
	if cfg.probeListen != "" {
		logger.Info("probes enabled", "listen", cfg.probeListen, "liveness", "/healthz", "readiness", "/readyz")
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
		listeners[i] = ddos.NewListener(ln, ddos.ListenerConfig{
			FirstByteTimeout:  cfg.readHeaderTimeout,
			MaxConns:          cfg.maxConns,
			MaxConnsPerClient: cfg.maxConnsPerIP,
			// A proxy's connections carry many clients.
			Exempt: append(slices.Clone(tp), dosExempt...),
			Bans:   bans,
			Logger: logger,
		})
	}
	probe := &probes{}
	var probeSrv *http.Server
	if cfg.probeListen != "" {
		ln, err := net.Listen("tcp", cfg.probeListen)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return err
		}
		probeSrv = &http.Server{Handler: probe, ReadHeaderTimeout: 10 * time.Second, ErrorLog: httpErrorLog}
		go probeSrv.Serve(ln)
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
	if notifier != nil {
		go notifier.Run(ctx)
	}
	if alertNotifier != nil {
		go alertNotifier.Run(ctx)
	}
	if alerts != nil {
		go alerts.Run(ctx)
	}
	if acmeManager != nil {
		go acmeManager.Run(ctx)
	}
	probe.ready.Store(true)

	var runErr error
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	probe.ready.Store(false)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		if err := s.Shutdown(shutdownCtx); err != nil && runErr == nil {
			runErr = err
		}
	}
	// Last, so that probes see the shutdown.
	if probeSrv != nil {
		probeSrv.Shutdown(shutdownCtx)
	}
	return runErr
}

// banRule returns the rule of bans for the log, or "disabled".
func banRule(b *ddos.Bans) string {
	if b == nil {
		return "disabled"
	}
	return b.Rule()
}

// serverProtocols returns the protocols of the listeners: HTTP/1.1, and
// HTTP/2 with TLS and without (h2c).
func serverProtocols() *http.Protocols {
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetHTTP2(true)
	p.SetUnencryptedHTTP2(true)
	return p
}

// sendTestNotification sends a test notification to check the
// -acme-notify-* or -alert-* settings.
func sendTestNotification(n *notify.Notifier, domain, message string, logger *slog.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	err := n.Send(ctx, notify.Event{
		Event:    "test",
		Severity: notify.SeverityInfo,
		Domain:   domain,
		Message:  message,
	})
	if err != nil {
		return fmt.Errorf("test notification failed: %w", err)
	}
	logger.Info("test notification sent", "targets", n.Targets())
	return nil
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
