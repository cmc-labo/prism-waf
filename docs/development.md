# Development

```sh
go test ./...
go test -tags e2e ./e2e/                    # end-to-end tests of the binary
go test ./internal/waf -run '^$' -bench .   # inspection benchmarks
go build -o bin/prismwaf ./cmd/prismwaf
```

See [Testing](testing.md) for the end-to-end tests, their requirements and
the latest results.

## Project layout

```
cmd/prismwaf/        entry point
internal/proxy/      reverse proxy, load balancing, health checks
internal/tlsutil/    TLS configuration, certificates (files, SNI, ACME), mTLS, HSTS, HTTPS redirect
internal/audit/      audit log (JSON Lines)
internal/normalize/  decoding and canonicalization of request data
internal/waf/        signatures, request inspection, JSON/XML body parsing
internal/crs/        OWASP CRS v4 with the Coraza engine
internal/ratelimit/  request rate limits per client and path
internal/notify/     notifications to administrators (webhooks, commands)
internal/bot/        bot score, categories, DNS verification of bots, proof-of-work and CAPTCHA challenges
e2e/                 end-to-end tests of the binary (build tag e2e)
examples/backend/    echo server for local testing
```
