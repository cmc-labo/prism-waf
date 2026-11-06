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

## HTTPS

| Flag | Default | Description |
|------|---------|-------------|
| `-tls-cert`, `-tls-key` | (none) | PEM certificate chain and private key; enables HTTPS on `-listen`. Repeat for several domains |
| `-acme-domains` | (none) | Comma-separated domains to obtain certificates for via ACME; enables HTTPS on `-listen` |
| `-acme-cache` | (none) | Directory for ACME account keys and certificates (required with `-acme-domains`) |
| `-acme-email` | (none) | Contact email for the ACME CA |
| `-acme-directory` | Let's Encrypt | ACME directory URL, or `staging` for Let's Encrypt's staging environment |
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
  -hsts-max-age 8760h \
  -backend http://10.0.0.11:8080,http://10.0.0.12:8080 -health-check-path /healthz \
  -engine both -crs-rules-before /etc/prismwaf/before.conf -crs-rules-after /etc/prismwaf/after.conf \
  -audit-log /var/log/prismwaf/audit.log
```

A first evaluation that only logs:

```sh
prismwaf -backend http://127.0.0.1:3000 -engine both -mode detect -audit-log audit.log
```
