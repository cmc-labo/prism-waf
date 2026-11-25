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
cmd/prismwaf/        entry point, environment variables, probes
prismwaf/            public Go package: PrismWAF as net/http middleware
internal/proxy/      reverse proxy, load balancing, health checks
internal/tlsutil/    TLS configuration, certificates (files, SNI, ACME), mTLS, HSTS, HTTPS redirect
internal/audit/      audit log (JSON Lines)
internal/normalize/  decoding and canonicalization of request data
internal/waf/        signatures, request inspection, JSON/XML body parsing
internal/crs/        OWASP CRS v4 with the Coraza engine
internal/ratelimit/  request rate limits per client and path
internal/abuse/      failure and enumeration limits of business flows
internal/ddos/       connection limits, timeouts of slow clients, requests in progress, bans
internal/openapi/    validation of requests against OpenAPI documents
internal/graphql/    GraphQL query limits, introspection, schema validation
internal/grpc/       gRPC message streams, protobuf decoding, gRPC status responses
internal/geo/        country lookup in MaxMind DB files, allow and block lists (geotest/: test databases)
internal/notify/     notifications to administrators (webhooks, commands)
internal/alert/      alerts when the rate limits are triggered too often
internal/bot/        bot score, categories, DNS verification of bots, proof-of-work and CAPTCHA challenges
e2e/                 end-to-end tests of the binary (build tag e2e)
examples/backend/    echo server for local testing
examples/library/    application that embeds PrismWAF with the prismwaf package
examples/kubernetes/ PrismWAF as a sidecar in a Deployment
examples/compose/    PrismWAF in front of an application with Docker Compose
Dockerfile           container image (distroless, non-root)
```
