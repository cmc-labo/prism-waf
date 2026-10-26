# PrismWAF

PrismWAF is a reverse-proxy Web Application Firewall written in Go.

> **Status:** early development. PrismWAF currently provides simple
> signature-based detection. More WAF features will be added incrementally.

## Features

- Reverse proxy to a single backend server
- Signature-based detection of common attacks (SQL injection, XSS, path
  traversal, OS command injection, Log4Shell) in the request path, query
  string, headers and body
- Blocks matching requests with `403 Forbidden` and logs the matched signature

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
[`internal/waf/signature.go`](internal/waf/signature.go). A signature is a
case-insensitive substring; a request is blocked when any of the following
contains one:

- the URL path
- the query string
- any header value
- the request body

Before matching, values are percent-decoded (up to three times, to catch
double encoding), lowercased, and runs of whitespace are collapsed to a single
space. Form bodies (`application/x-www-form-urlencoded`) are decoded as well.

Request bodies are buffered in memory for inspection. Bodies larger than
`-max-body` are rejected with `413 Request Entity Too Large` rather than
partially inspected.

The signatures are deliberately simple and will not stop obfuscated payloads.
Treat them as a baseline, not complete protection.

## Options

| Flag       | Default                 | Description              |
|------------|-------------------------|--------------------------|
| `-listen`  | `:8080`                 | Address to listen on     |
| `-backend` | `http://127.0.0.1:8081` | Backend server URL       |
| `-max-body` | `1048576` (1 MiB)      | Maximum request body size to inspect, in bytes |

## Development

```sh
go test ./...
go build -o bin/prismwaf ./cmd/prismwaf
```

## Project layout

```
cmd/prismwaf/      entry point
internal/proxy/    reverse proxy
internal/waf/      signatures and request inspection
examples/backend/  echo server for local testing
```

## License

PrismWAF is released under the [MIT License](LICENSE).
