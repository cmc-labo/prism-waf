# PrismWAF

PrismWAF is a reverse-proxy Web Application Firewall written in Go.

> **Status:** early development. PrismWAF currently provides simple
> signature-based detection. More WAF features will be added incrementally.

## Features

- Reverse proxy to a single backend server
- Signature-based detection of common attacks (SQL injection, XSS, path
  traversal, OS command injection, Log4Shell) in the request path, query
  string, headers and body
- Request normalization that defeats encoding tricks, split keywords and
  Base64-encoded payloads
- Blocks matching requests with `403 Forbidden`
- Audit log (JSON Lines) recording the client IP, the matched rule and the
  payload of every blocked request

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
- the request body

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

Request bodies are buffered in memory for inspection. Bodies larger than
`-max-body` (default 128 KiB, the same as ModSecurity's default for bodies
without files) are rejected with `413 Request Entity Too Large` rather than
partially inspected. Inspection cost grows with body size; a body crafted
to defeat the keyword prefilters takes about 100 ms of CPU at 128 KiB, so
raise the limit with care.

The built-in signatures cover common payloads and their usual variations,
but no signature set is complete. Treat them as a baseline, not complete
protection.

## Audit log

Every blocked request is written to the audit log as one JSON object per
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
| `id` | Event ID. Also returned in the `403`/`413` response body, so users can report false positives. |
| `client_ip` | Client address (see [Client IP](#client-ip)). |
| `reason` | `signature` or `body_too_large`. |
| `rule` | The signature that matched. |
| `match.location`, `match.field` | Where it matched: `path`, `query`, `header` (with the header name) or `body`. |
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
| `-audit-log` | `-` (standard output) | File to append audit events to |
| `-trusted-proxies` | (none)          | Comma-separated IPs/CIDRs of proxies whose `X-Forwarded-For` is trusted |

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
internal/audit/      audit log (JSON Lines)
internal/normalize/  decoding and canonicalization of request data
internal/waf/        signatures and request inspection
examples/backend/    echo server for local testing
```

## License

PrismWAF is released under the [MIT License](LICENSE).
