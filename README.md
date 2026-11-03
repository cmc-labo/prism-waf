# PrismWAF

PrismWAF is a reverse-proxy Web Application Firewall written in Go.

> **Status:** early development. PrismWAF currently provides simple
> signature-based detection. More WAF features will be added incrementally.

## Features

- Reverse proxy to a single backend server
- HTTPS (TLS termination, HTTP/2, certificate reload without restart,
  several domains via SNI, automatic certificates via ACME/Let's Encrypt,
  HSTS, client certificates/mutual TLS, HTTP→HTTPS redirect) and HTTPS
  backends
- Signature-based detection of common attacks (SQL injection, XSS, path
  traversal, OS command injection, Log4Shell, XXE) in the request path,
  query string, headers and body
- JSON and XML bodies are parsed and every value is inspected on its own
- Request normalization that defeats encoding tricks, split keywords and
  Base64-encoded payloads
- Blocks matching requests with `403 Forbidden`, or only logs them in
  detection mode
- Audit log (JSON Lines) recording the client IP, the matched rule and the
  payload of every detected request

## Quick start

Requirements: Go 1.24 or later.

Start the example backend (an echo server on `:8081`):

```sh
go run ./examples/backend
```

In another terminal, start PrismWAF in front of it:

```sh
go run ./cmd/prismwaf -listen :8080 -backend http://127.0.0.1:8081
```

Send a request through the proxy:

```sh
curl -i http://127.0.0.1:8080/hello?name=prism
```

Try an attack payload; PrismWAF blocks it before it reaches the backend:

```sh
curl -i "http://127.0.0.1:8080/items?id=1%20UNION%20SELECT%20password"
# HTTP/1.1 403 Forbidden
```

## Signature detection

Each request is checked against the built-in signatures in
[`internal/waf/signature.go`](internal/waf/signature.go). A signature is
either a case-insensitive substring or an [RE2](https://github.com/google/re2/wiki/Syntax)
regular expression, so variants such as `UNION(SELECT …)`, `' || 1=1` or
`<svg/onload=…>` are covered by a single rule. RE2 runs in linear time, so a
signature cannot be abused for ReDoS. A request is blocked when a signature
matches any of the following:

- the URL path
- the query string
- any header value
- the request body; JSON and XML bodies value by value (see below)

Before matching, every value is normalized so that encoded or obfuscated
payloads are detected (see [`internal/normalize`](internal/normalize)):

| Evasion technique              | Example                      | Normalized    |
|--------------------------------|------------------------------|---------------|
| URL encoding (nested)          | `%253Cscript`                | `<script`     |
| IIS `%u` encoding              | `%u003Cscript`               | `<script`     |
| HTML entities                  | `&lt;` `&#60;` `&#x3c;`      | `<`           |
| JavaScript / JSON escapes      | `\x3c` `\u003c`              | `<`           |
| Overlong UTF-8                 | `%c0%ae%c0%ae/`              | `../`         |
| Fullwidth / compatibility (NFKC) | `＜ｓｃｒｉｐｔ＞`             | `<script>`    |
| Mixed case                     | `UnIoN SeLeCt`               | `union select`|
| NUL and zero-width characters  | `<scr%00ipt>`                | `<script>`    |
| Backslashes, `//`, `/./`       | `..\..\windows`              | `../../windows` |
| Whitespace variations          | `union%09%0aselect`          | `union select`|
| SQL comments                   | `union/**/select`            | `union select`|
| Log4j nested lookups           | `${${lower:j}ndi:`           | `${jndi:`     |

Decoders are applied repeatedly (up to five rounds) until the value stops
changing, so combinations such as URL-encoded HTML entities are unwrapped too.
Malformed escapes such as `%zz` are left as-is instead of aborting decoding.

Each value is matched in several forms:

| Form              | Purpose                                                        |
|-------------------|----------------------------------------------------------------|
| Raw (lowercased)  | Baseline                                                       |
| Normalized        | Decoded and canonicalized as above                             |
| Comments → spaces | `union/**/select` → `union select`                             |
| Keywords joined   | Undoes keyword splitting: `un/**/ion` → `union`, `'al'+'ert'` → `alert`, `c'a't` → `cat`, `c$@at` → `cat`, `cat${IFS}x` → `cat x`, `w^hoami` → `whoami` |
| Base64-decoded    | Tokens of 12+ Base64 / Base64url characters that decode to printable text are decoded and run through all of the above. Matches are logged with `base64=true`. |

Signature patterns should therefore be written in normalized form.

Large inputs are expensive to scan with regular expressions, so a signature
can declare `Keywords`: substrings that every match must contain. The regex
only runs when one of them is present, which makes typical inspection about
10× faster.

### JSON and XML bodies

Bodies with a JSON content type (`application/json`, `application/*+json`)
or an XML content type (`application/xml`, `text/xml`, `application/*+xml`
such as SOAP) are parsed, and every value is inspected on its own instead
of the body as a whole:

| Format | Inspected values | Example `match.field` |
|--------|------------------|-----------------------|
| JSON | Every string value and object key, including duplicate keys | `$.user.name`, `$.items[2]`, `$["a.b"]` |
| XML | Element text, attribute values, start tags (names only, to catch event handler attributes), comments, processing instructions, the DOCTYPE | `/order/item`, `/order/item/@id`, `/order/comment()`, `<!DOCTYPE>` |

This has three benefits:

- **Fewer false positives.** JSON and XML syntax around values can complete
  a pattern that no value contains: `{"filter":"and price>100"}` looks like
  `" and price>100` (SQL injection) to a raw scan, but the value alone is
  harmless.
- **Better detection.** Patterns that require the end of a value, such as
  `admin'--` or `; id`, now match inside a document. Escapes are decoded by
  the parser, and XML text is joined across CDATA sections, entity
  references and comments, so `<![CDATA[<scr]]><![CDATA[ipt>]]>` is
  inspected as `<script>`.
- **Precise audit events.** `match.field` names the value that matched and
  `match.value` holds its decoded content.

A body that is not valid UTF-8 or does not parse, for example truncated
JSON, a payload after the document, or an XML entity that only a DTD can
define, is inspected as a whole as before, so a malformed document cannot
hide a payload. Bodies with other content types are always inspected as a
whole.

XML bodies are also checked for XML external entity (XXE) attacks: external
entities and DTDs (`<!ENTITY x SYSTEM "…">`), entity expansion ("billion
laughs") and XInclude. These signatures apply to all other locations too.

### Body size

Request bodies are buffered in memory for inspection. Bodies larger than
`-max-body` (default 128 KiB, the same as ModSecurity's default for bodies
without files) are rejected with `413 Request Entity Too Large` rather than
partially inspected. Inspection cost grows with body size; a body crafted
to defeat the keyword prefilters takes about 100 ms of CPU at 128 KiB,
whether it is inspected raw or as JSON or XML, so raise the limit with
care.

The built-in signatures cover common payloads and their usual variations,
but no signature set is complete. Treat them as a baseline, not complete
protection.

## HTTPS

### Serving HTTPS to clients

Pass a certificate and key to serve HTTPS on `-listen`:

```sh
go run ./cmd/prismwaf -listen :443 \
  -tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
  -tls-key  /etc/letsencrypt/live/example.com/privkey.pem \
  -http-redirect :80
```

- TLS 1.2 or later is required; Go's default cipher suites are used.
- HTTP/2 is negotiated automatically.
- `-http-redirect` starts a plain HTTP listener that answers every request
  with `308 Permanent Redirect` to the same URL over HTTPS. It does not
  proxy anything.
- Send `SIGHUP` to reload the certificate without dropping connections,
  e.g. from a certbot deploy hook:
  `certbot renew --deploy-hook "pkill -HUP prismwaf"`.
  If the new files cannot be loaded, the current certificate stays in use
  and an error is logged.
- The backend receives `X-Forwarded-Proto: https`.

For local testing, create a self-signed certificate:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
  -keyout key.pem -out cert.pem
go run ./cmd/prismwaf -listen :8443 -tls-cert cert.pem -tls-key key.pem
curl --cacert cert.pem https://localhost:8443/
```

### Several domains (SNI)

Repeat `-tls-cert` and `-tls-key` in pairs. Each connection gets the first
certificate that is valid for the server name the client requests; clients
that request no name or an unknown one get the first certificate. All
certificates are reloaded on `SIGHUP`, and if any of them fails to load,
all current ones stay in use.

```sh
go run ./cmd/prismwaf -listen :443 \
  -tls-cert example.com.pem -tls-key example.com.key \
  -tls-cert example.org.pem -tls-key example.org.key
```

An RSA and an ECDSA certificate for the same name can be combined in the
same way; each client gets one it supports.

### Automatic certificates (ACME / Let's Encrypt)

PrismWAF can obtain and renew certificates itself instead of using
certificate files:

```sh
go run ./cmd/prismwaf -listen :443 -http-redirect :80 \
  -acme-domains example.com,www.example.com \
  -acme-cache /var/lib/prismwaf/acme \
  -acme-email admin@example.com
```

- Certificates are requested only for `-acme-domains`, so clients cannot
  make PrismWAF request certificates for arbitrary names and exhaust the
  CA's rate limits. Wildcards and IP addresses are not supported, and
  clients must send a server name (SNI).
- `-acme-cache` holds the account key and the certificates (mode 0700).
  Keep it across restarts; requesting new certificates on every start hits
  the rate limits quickly.
- The CA verifies the domains with the TLS-ALPN-01 challenge on port 443
  and, when `-http-redirect` is set, the HTTP-01 challenge on port 80. So
  `-listen` must be reachable as port 443, or `-http-redirect` as port 80,
  from the internet.
- Certificates are renewed automatically, 30 days (or a third of their
  lifetime, if shorter) before they expire.
- Using `-acme-domains` means accepting the CA's terms of service.
- Try a new setup with `-acme-directory staging` (Let's Encrypt's staging
  environment, untrusted certificates but higher rate limits) first. Any
  other ACME CA can be used by passing its directory URL.

`-acme-domains` and `-tls-cert` are mutually exclusive.

### HSTS

`-hsts-max-age` adds a `Strict-Transport-Security` header to every HTTPS
response, including blocked ones, so that browsers use only HTTPS for the
site from then on. A header sent by the backend is replaced.

```sh
go run ./cmd/prismwaf ... -hsts-max-age 8760h -hsts-include-subdomains
```

Browsers remember the policy for the whole max-age, so start with a short
value such as `5m` and increase it once HTTPS works everywhere.
`-hsts-include-subdomains` applies it to all subdomains as well.
`-hsts-preload` signals consent to be included in the browsers' preload
lists (<https://hstspreload.org>); it requires a max-age of at least one
year and `-hsts-include-subdomains`.

### Client certificates (mutual TLS)

`-tls-client-ca` requires clients to present a certificate signed by one
of the CAs in the given PEM file; others are rejected during the TLS
handshake, before any request reaches the WAF or the backend:

```sh
go run ./cmd/prismwaf ... -tls-client-ca clients-ca.pem
curl --cert alice.pem --key alice.key https://example.com/
```

With `-tls-client-auth optional`, clients without a certificate are
accepted too, but a certificate that is sent must be valid. Mutual TLS can
be combined with ACME; the CA's validation connections are exempted from
client authentication but cannot be used to send requests.

### HTTPS backends

Use an `https://` backend URL. Its certificate is verified against the
system CAs; for an internal CA or a self-signed certificate, pass it with
`-backend-ca`:

```sh
go run ./cmd/prismwaf -backend https://app.internal:8443 -backend-ca internal-ca.pem
```

`-backend-insecure-skip-verify` disables verification entirely. It makes the
connection vulnerable to interception and is meant for testing only.

## Modes

| Mode | `-mode` | Detected requests |
|------|---------|-------------------|
| Block (default) | `block` | Rejected with `403 Forbidden` (or `413` if the body is too large) and logged with `"action": "block"` |
| Detect | `detect` | Forwarded to the backend unchanged and logged with `"action": "detect"` |

Detection mode lets you find false positives on real traffic before
anything is blocked. A typical rollout:

```sh
# 1. Run in detection mode for a while
go run ./cmd/prismwaf -mode detect -audit-log audit.log

# 2. Review what would have been blocked, by rule and by path
jq -r 'select(.action == "detect") | [.rule.id // .reason, .request.uri] | @tsv' audit.log | sort | uniq -c | sort -rn

# 3. Once the remaining detections are real attacks, switch to blocking
go run ./cmd/prismwaf -mode block -audit-log audit.log
```

In detection mode, requests with bodies over `-max-body` are forwarded
without their body being inspected, and logged with
`"reason": "body_too_large"`. Only the first matching rule is logged for each
request.

## Audit log

Every detected request is written to the audit log as one JSON object per
line. By default it goes to standard output; use `-audit-log` to append to a
file instead (created with mode `0600`, since payloads may contain secrets).

```json
{
  "time": "2026-10-30T01:02:03.456Z",
  "id": "a09a5cdef27be9cb",
  "client_ip": "203.0.113.7",
  "remote_addr": "10.0.0.5:34402",
  "action": "block",
  "reason": "signature",
  "rule": { "id": "SQLI-002", "category": "sqli" },
  "match": {
    "location": "query",
    "data": "union(select",
    "value": "id=1+UNION(SELECT+password+FROM+users)",
    "value_length": 38
  },
  "request": {
    "method": "GET",
    "uri": "/items?id=1+UNION(SELECT+password+FROM+users)",
    "proto": "HTTP/1.1",
    "host": "shop.example.com",
    "content_length": 0,
    "headers": { "Cookie": "[REDACTED]", "User-Agent": "sqlmap/1.8" }
  }
}
```

| Field | Description |
|-------|-------------|
| `id` | Event ID. In block mode it is also returned in the `403`/`413` response body, so users can report false positives. |
| `client_ip` | Client address (see [Client IP](#client-ip)). |
| `action` | `block`, or `detect` in detection mode. |
| `reason` | `signature` or `body_too_large`. |
| `rule` | The signature that matched. |
| `match.location`, `match.field` | Where it matched: `path`, `query`, `header` (with the header name) or `body` (with the path of the value for JSON and XML bodies). |
| `match.data` | The text the signature matched, after normalization. |
| `match.value` | The raw value that was inspected, i.e. the payload as sent. Truncated to 4 KiB (`value_truncated`, `value_length`). |
| `match.base64` | `true` if the match was in Base64-decoded data. |
| `request.headers` | Request headers. `Authorization`, `Cookie` and other credential headers are `[REDACTED]`, unless the attack was found in that header. |

The response to the client only contains the event ID; rule details are not
disclosed.

Examples with [jq](https://jqlang.github.io/jq/):

```sh
# Top attacking IPs
jq -r .client_ip audit.log | sort | uniq -c | sort -rn | head
# Hits per rule
jq -r '.rule.id // .reason' audit.log | sort | uniq -c | sort -rn
# Look up an event reported by a user
jq 'select(.id == "a09a5cdef27be9cb")' audit.log
```

### Client IP

Behind a load balancer or CDN, the TCP peer is the proxy, not the client.
List your proxies with `-trusted-proxies` so that the client address is
taken from `X-Forwarded-For`:

```sh
go run ./cmd/prismwaf -trusted-proxies 10.0.0.0/8,192.0.2.1
```

`X-Forwarded-For` is only used when the request comes from a trusted proxy,
and it is read from right to left, skipping trusted proxies, so clients
cannot spoof their address by sending the header themselves.

## Options

| Flag       | Default                 | Description              |
|------------|-------------------------|--------------------------|
| `-listen`  | `:8080`                 | Address to listen on     |
| `-backend` | `http://127.0.0.1:8081` | Backend server URL       |
| `-max-body` | `131072` (128 KiB)     | Maximum request body size to inspect, in bytes |
| `-mode` | `block`                 | `block` to reject detected requests, `detect` to only log them |
| `-audit-log` | `-` (standard output) | File to append audit events to |
| `-trusted-proxies` | (none)          | Comma-separated IPs/CIDRs of proxies whose `X-Forwarded-For` is trusted |
| `-tls-cert`, `-tls-key` | (none)     | PEM certificate chain and private key; enables HTTPS on `-listen`. Repeat for several domains |
| `-acme-domains` | (none)             | Comma-separated domains to obtain certificates for via ACME; enables HTTPS on `-listen` |
| `-acme-cache` | (none)               | Directory for ACME account keys and certificates (required with `-acme-domains`) |
| `-acme-email` | (none)               | Contact email for the ACME CA |
| `-acme-directory` | Let's Encrypt    | ACME directory URL, or `staging` for Let's Encrypt's staging environment |
| `-http-redirect` | (none)            | Address of an HTTP listener that redirects to HTTPS and answers ACME HTTP-01 challenges, e.g. `:80` |
| `-hsts-max-age` | `0` (off)          | Send `Strict-Transport-Security` with this max-age, e.g. `8760h` |
| `-hsts-include-subdomains` | `false` | Add `includeSubDomains` to the HSTS header |
| `-hsts-preload` | `false`            | Add `preload` to the HSTS header |
| `-tls-client-ca` | (none)            | PEM CA file; require client certificates signed by it (mutual TLS) |
| `-tls-client-auth` | `require`       | `require` or `optional` client certificates with `-tls-client-ca` |
| `-backend-ca` | (none)               | PEM CA file for verifying an `https://` backend |
| `-backend-insecure-skip-verify` | `false` | Do not verify the backend certificate (testing only) |

## Development

```sh
go test ./...
go test ./internal/waf -run '^$' -bench .   # inspection benchmarks
go build -o bin/prismwaf ./cmd/prismwaf
```

## Project layout

```
cmd/prismwaf/        entry point
internal/proxy/      reverse proxy
internal/tlsutil/    TLS configuration, certificates (files, SNI, ACME), mTLS, HSTS, HTTPS redirect
internal/audit/      audit log (JSON Lines)
internal/normalize/  decoding and canonicalization of request data
internal/waf/        signatures, request inspection, JSON/XML body parsing
examples/backend/    echo server for local testing
```

## License

PrismWAF is released under the [MIT License](LICENSE).
