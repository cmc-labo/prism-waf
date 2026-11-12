# Configuration

PrismWAF is configured with command-line flags. Run `prismwaf -h` for the
built-in help. Flags that take several values can be repeated, and some
also accept comma-separated lists, as noted below.

## Proxy and backends

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:8080` | Address to listen on |
| `-backend` | `http://127.0.0.1:8081` | Backend server URL; repeat or separate with commas for several |
| `-lb-policy` | `round-robin` | `round-robin` or `least-conn` |
| `-backend-fail-timeout` | `10s` | How long to skip a backend that cannot be connected to |
| `-health-check-path` | (none) | Path to `GET` on every backend periodically, e.g. `/healthz` |
| `-health-check-interval` | `10s` | Interval between health checks |
| `-health-check-timeout` | `5s` | Timeout of a health check request |
| `-backend-ca` | (none) | PEM CA file for verifying an `https://` backend |
| `-backend-insecure-skip-verify` | `false` | Do not verify the backend certificate (testing only) |

See [Load balancing](load-balancing.md) and
[HTTPS backends](https.md#https-backends).

## Inspection

| Flag | Default | Description |
|------|---------|-------------|
| `-engine` | `builtin` | `builtin` (PrismWAF signatures), `crs` (OWASP CRS v4) or `both` |
| `-max-body` | `131072` (128 KiB) | Maximum request body size to inspect, in bytes; larger bodies get `413` |
| `-mode` | `block` | `block` to reject detected requests, `detect` to only log them |

See [Signature detection](detection.md), [OWASP Core Rule Set](crs.md) and
[Modes](audit-log.md#modes).

## OWASP Core Rule Set

Used with `-engine crs` or `-engine both`.

| Flag | Default | Description |
|------|---------|-------------|
| `-crs-paranoia-level` | `1` | Paranoia level, 1-4; higher detects more but causes more false positives |
| `-crs-anomaly-threshold` | `5` | Inbound anomaly score at which a request is blocked (a critical rule scores 5) |
| `-crs-max-args` | `1000` | Maximum number of arguments per request; requests with more get `400` |
| `-crs-rules-before` | (none) | SecLang file loaded before the CRS rules; repeatable, globs allowed |
| `-crs-rules-after` | (none) | SecLang file loaded after the CRS rules; repeatable, globs allowed |

See [OWASP Core Rule Set](crs.md#options) for details and use cases.

## Audit log and client IP

| Flag | Default | Description |
|------|---------|-------------|
| `-audit-log` | `-` (standard output) | File to append audit events to (created with mode `0600`) |
| `-trusted-proxies` | (none) | Comma-separated IPs/CIDRs of proxies whose `X-Forwarded-For` is trusted |

See [Audit log](audit-log.md#audit-log) and
[Client IP](audit-log.md#client-ip).

## Rate limiting

| Flag | Default | Description |
|------|---------|-------------|
| `-rate-limit` | (none) | Maximum requests per client, as `N/WINDOW`, e.g. `300/1m`; excess requests get `429` |
| `-rate-limit-path` | (none) | Limit per client for one path, as `[METHOD ]PATH=N/WINDOW`, e.g. `POST /login=5/1m` or `/api/*=100/1m`; repeatable |
| `-rate-limit-exempt` | (none) | Comma-separated IPs/CIDRs of clients that are never limited |
| `-rate-limit-max-clients` | `100000` | Maximum number of clients tracked at once |

A client is an IP address, or a `/64` network for IPv6. See
[Rate limiting](rate-limiting.md).

## Bot protection

| Flag | Default | Description |
|------|---------|-------------|
| `-bot-protection` | `false` | Score how likely each request comes from a bot and challenge clients that look automated |
| `-bot-challenge-score` | `50` | Bot score (1-100) from which clients must solve a proof-of-work challenge |
| `-bot-block-score` | `0` (disabled) | Bot score (1-100) from which requests get `403` without a challenge |
| `-bot-difficulty` | `18` | Leading zero bits of the challenge's SHA-256 hash, 1-30; every bit doubles the work |
| `-bot-clearance-ttl` | `24h` | How long a solved challenge lets a client through |
| `-bot-secret-file` | (random key) | File with a key of at least 32 bytes to sign challenges and cookies; share it between instances |
| `-bot-path` | (all paths) | Protect only this path, e.g. `/search` or `/articles/*`; repeatable |
| `-bot-exempt-path` | (none) | Never protect this path, e.g. `/api/*`; repeatable |
| `-bot-exempt` | (none) | Comma-separated IPs/CIDRs of clients that are never challenged |
| `-bot-verify` | `true` | Verify Googlebot, Bingbot and other bots that document it with reverse and forward DNS; let verified bots through |
| `-bot-allow-category` | (none) | Comma-separated bot categories to let through, e.g. `social,monitoring` (not verified) |
| `-bot-block-category` | (none) | Comma-separated bot categories to reject with `403`, e.g. `ai_crawler,seo` |
| `-bot-captcha` | (none) | CAPTCHA instead of the proof of work: `turnstile`, `hcaptcha`, `recaptcha` or `recaptcha-v3` |
| `-bot-captcha-site-key` | (none) | Site key of the CAPTCHA |
| `-bot-captcha-secret-file` | (none) | File with the secret key of the CAPTCHA |
| `-bot-captcha-score` | `-bot-challenge-score` | Bot score from which the CAPTCHA is shown instead of the proof of work |
| `-bot-captcha-min-score` | `0.5` | reCAPTCHA v3 score from which a client passes |

`/robots.txt`, `/favicon.ico` and `/.well-known/*` are always exempt. See
[Bot protection](bot-protection.md), including the
[categories](bot-protection.md#categories) and its effect on
[search engines](bot-protection.md#search-engines-and-link-previews).

## HTTPS

| Flag | Default | Description |
|------|---------|-------------|
| `-tls-cert`, `-tls-key` | (none) | PEM certificate chain and private key; enables HTTPS on `-listen`. Repeat for several domains |
| `-acme-domains` | (none) | Comma-separated domains to obtain certificates for via ACME; enables HTTPS on `-listen` |
| `-acme-cache` | (none) | Directory for ACME account keys and certificates, with one subdirectory per CA (required with `-acme-domains`) |
| `-acme-email` | (none) | Contact email for the ACME CA |
| `-acme-directory` | Let's Encrypt | ACME directory URL, or `staging` for Let's Encrypt's staging environment |
| `-acme-notify-webhook` | (none) | URL to `POST` a notification to when an ACME certificate is not renewed, expires or cannot be obtained |
| `-acme-notify-webhook-format` | `json` | `json`, `slack` (also Mattermost, Google Chat) or `discord` |
| `-acme-notify-command` | (none) | Shell command run for each notification, with the event as JSON on stdin and in `PRISMWAF_*` variables |
| `-acme-notify-test` | `false` | Send a test notification and exit |
| `-http-redirect` | (none) | Address of an HTTP listener that redirects to HTTPS and answers ACME HTTP-01 challenges, e.g. `:80` |
| `-hsts-max-age` | `0` (off) | Send `Strict-Transport-Security` with this max-age, e.g. `8760h` |
| `-hsts-include-subdomains` | `false` | Add `includeSubDomains` to the HSTS header |
| `-hsts-preload` | `false` | Add `preload` to the HSTS header |
| `-tls-client-ca` | (none) | PEM CA file; require client certificates signed by it (mutual TLS) |
| `-tls-client-auth` | `require` | `require` or `optional` client certificates with `-tls-client-ca` |

See [HTTPS](https.md) and [Automatic certificates](acme.md).

## Fixed limits

| Limit | Value | Response |
|-------|-------|----------|
| Request line and headers | 64 KiB | `431 Request Header Fields Too Large` |

## Signals

| Signal | Effect |
|--------|--------|
| `SIGHUP` | Reload the TLS certificates from `-tls-cert`/`-tls-key` without dropping connections. Only handled with `-tls-cert`; otherwise it terminates the process |
| `SIGINT`, `SIGTERM` | Shut down gracefully: stop accepting connections and wait up to 10 seconds for requests in progress |

Rule files (`-crs-rules-before`, `-crs-rules-after`) and other settings are
read only at startup.

## Examples

A production deployment that terminates TLS itself, with automatic
certificates, two backends, and the CRS in addition to the built-in
signatures:

```sh
prismwaf -listen :443 -http-redirect :80 \
  -acme-domains example.com -acme-cache /var/lib/prismwaf/acme \
  -acme-notify-webhook https://hooks.slack.com/services/T000/B000/XXXX -acme-notify-webhook-format slack \
  -hsts-max-age 8760h \
  -backend http://10.0.0.11:8080,http://10.0.0.12:8080 -health-check-path /healthz \
  -engine both -crs-rules-before /etc/prismwaf/before.conf -crs-rules-after /etc/prismwaf/after.conf \
  -rate-limit 600/1m -rate-limit-path "POST /login=5/1m" \
  -audit-log /var/log/prismwaf/audit.log
```

A first evaluation that only logs:

```sh
prismwaf -backend http://127.0.0.1:3000 -engine both -mode detect -audit-log audit.log
```
