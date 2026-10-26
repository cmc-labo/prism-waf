# PrismWAF

PrismWAF is a reverse-proxy Web Application Firewall written in Go.

> **Status:** early development. PrismWAF currently forwards requests to a
> backend without any inspection. WAF features will be added incrementally.

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

## Options

| Flag       | Default                 | Description              |
|------------|-------------------------|--------------------------|
| `-listen`  | `:8080`                 | Address to listen on     |
| `-backend` | `http://127.0.0.1:8081` | Backend server URL       |

## Development

```sh
go test ./...
go build -o bin/prismwaf ./cmd/prismwaf
```

## Project layout

```
cmd/prismwaf/      entry point
internal/proxy/    reverse proxy
examples/backend/  echo server for local testing
```
