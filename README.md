# PrismWAF

PrismWAF is a reverse-proxy Web Application Firewall written in Go.

> **Status:** early development. Options and the audit log format may
> still change.

## Features

- **Attack detection**: built-in signatures for SQL injection, XSS, path
  traversal, OS command injection, Log4Shell and XXE, with normalization
  that defeats encoding tricks ([details](docs/detection.md))
- **OWASP Core Rule Set v4**: optionally run the CRS through the
  [Coraza](https://coraza.io/) engine, embedded in the binary
  ([details](docs/crs.md))
- **Structured bodies**: JSON and XML bodies are parsed and every value is
  inspected on its own
- **Rate limiting**: limit requests per client, overall and per path, e.g.
  5 login attempts per minute ([details](docs/rate-limiting.md))
- **Detection mode and audit log**: log instead of block while tuning;
  JSON Lines events with the matched rule and payload
  ([details](docs/audit-log.md))
- **Load balancing**: several backends, round-robin or least-connections,
  failover and health checks ([details](docs/load-balancing.md))
- **HTTPS**: TLS termination, HTTP/2, SNI, HSTS, mutual TLS, HTTPS
  backends ([details](docs/https.md)), and automatic certificates from
  Let's Encrypt or any ACME CA ([details](docs/acme.md))

## Quick start

Requirements: Go 1.25 or later.

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

To add the OWASP Core Rule Set to the built-in signatures:

```sh
go run ./cmd/prismwaf -engine both -backend http://127.0.0.1:8081
```

## Documentation

- [Configuration](docs/configuration.md): all command-line flags
- [Signature detection](docs/detection.md)
- [OWASP Core Rule Set](docs/crs.md): engine selection, paranoia level,
  anomaly threshold, rule exclusions and use cases
- [Rate limiting](docs/rate-limiting.md)
- [Modes and audit log](docs/audit-log.md)
- [Load balancing](docs/load-balancing.md)
- [HTTPS](docs/https.md)
- [Automatic certificates (ACME / Let's Encrypt)](docs/acme.md)
- [Development](docs/development.md)

## License

PrismWAF is released under the [MIT License](LICENSE).

Binaries also contain third-party code under their own licenses, notably
[OWASP Coraza](https://github.com/corazawaf/coraza) and the
[OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)
(both Apache License 2.0).
