# Deployment options

PrismWAF can run in three ways:

| Option | How | Use when |
|--------|-----|----------|
| [Reverse proxy](#reverse-proxy) | The `prismwaf` binary in front of one or more backends | A server or VM; PrismWAF terminates TLS, balances backends |
| [Sidecar](#sidecar) | The container image next to the application, in the same pod or network namespace | Kubernetes, Docker Compose; one PrismWAF per application instance |
| [Library](#library) | The Go package `prismwaf` as `net/http` middleware | A Go application that should protect itself, without another process |

The sidecar is the reverse proxy in a container, with all of its
features. The library offers the core of it: inspection with the built-in
signatures and the CRS, detection mode, rate limiting and the audit log.

- [Container image](#container-image)
- [Configuration with environment variables](#configuration-with-environment-variables)
- [Probes and shutdown](#probes-and-shutdown)
- [Sidecar](#sidecar): [Kubernetes](#kubernetes), [Docker Compose](#docker-compose)
- [Library](#library)

## Reverse proxy

```sh
go build -o /usr/local/bin/prismwaf ./cmd/prismwaf
prismwaf -listen :443 -acme-domains example.com -acme-cache /var/lib/prismwaf/acme \
  -backend http://127.0.0.1:3000 -engine both
```

See [Configuration](configuration.md#examples) and the guides of each
feature. A systemd unit is shown under
[Automatic certificates](acme.md#run-as-a-systemd-service).

## Container image

```sh
docker build -t prismwaf .
docker run --rm -p 8080:8080 -e PRISMWAF_BACKEND=http://app.internal:3000 prismwaf
```

| Property | Value |
|----------|-------|
| Base | `gcr.io/distroless/static-debian12:nonroot`: no shell, no package manager |
| User | `nonroot` (UID 65532) |
| Size | about 23 MB, including the embedded CRS |
| Entry point | `/prismwaf`; arguments are flags, e.g. `docker run prismwaf -engine both` |
| Ports | `8080` (`-listen`, the default), `9090` (probes) |
| Environment | `PRISMWAF_PROBE_LISTEN=:9090` |
| Health check | `prismwaf healthcheck`, which queries `/readyz` at `PRISMWAF_PROBE_LISTEN` |
| Audit log | Standard output (`-audit-log -`, the default), next to the operational log on standard error |

Files such as certificates, keys, rule exclusions, API descriptions or
GeoIP databases are mounted into the container and passed by path, e.g.
`-e PRISMWAF_BOT_SECRET_FILE=/etc/prismwaf/bot.key`.

**Read-only root file system.** PrismWAF writes nothing to disk, except
the audit log file and the ACME cache if configured. The CRS engine,
Coraza, still checks at startup that the temporary directory is writable,
so with `-engine crs` or `both` mount a small writable volume on `/tmp`
(`docker run --read-only --tmpfs /tmp:size=1m ...`, or an `emptyDir` in
Kubernetes). Without it, PrismWAF exits with "the temporary directory must
be writable".

## Configuration with environment variables

Every flag can also be set with an environment variable: `PRISMWAF_`
followed by the flag name in upper case, with `-` replaced by `_`.

| Flag | Environment variable |
|------|----------------------|
| `-backend` | `PRISMWAF_BACKEND` |
| `-rate-limit` | `PRISMWAF_RATE_LIMIT` |
| `-bot-captcha-secret-file` | `PRISMWAF_BOT_CAPTCHA_SECRET_FILE` |

- **Precedence.** A flag on the command line wins over its variable.
- **Repeatable flags** such as `-rate-limit-path` or `-bot-exempt-path`
  take one value per line:

  ```yaml
  - name: PRISMWAF_RATE_LIMIT_PATH
    value: |
      POST /login=5/1m
      /api/*=100/1m
  ```

  Flags that accept comma-separated lists, such as `-backend` or
  `-trusted-proxies`, accept them in variables as well.
- **Booleans** are `true` or `false` (also `1`, `0`, `t`, `f`).
- **Empty variables are ignored**, so the flag keeps its default.
- **Unknown variables** starting with `PRISMWAF_` stop PrismWAF at startup
  (`unknown environment variable PRISMWAF_RATE_LIMITS: no such option`),
  so that a misspelled option is not silently ignored. Invalid values are
  reported with the variable's name.
- Options set with variables are validated like flags; error messages name
  the flag, e.g. `-ban-duration requires -ban`.
- **Secrets** are passed as files (`-bot-secret-file`,
  `-bot-captcha-secret-file`, `-tls-key`), not as values, so that they do
  not appear in the environment of the process.

## Probes and shutdown

`-probe-listen` starts a separate plain-HTTP listener for the probes of
the orchestrator. The image sets it to `:9090`.

| Path | Answers |
|------|---------|
| `GET /healthz` | `200 ok` while the process runs (liveness) |
| `GET /readyz` | `200 ready` once PrismWAF accepts connections; `503 not ready` before and while it shuts down (readiness) |

- The probes have a port of their own: on `-listen`, `/healthz` is an
  ordinary request that is inspected and forwarded to the backend.
- Do not expose the probe port outside the pod or host; it has no
  protection of its own.
- `prismwaf healthcheck [URL]` queries a probe and exits with status 0 if
  it answers `200`, 1 otherwise. Without a URL, it queries `/readyz` at
  the address in `PRISMWAF_PROBE_LISTEN`, so a port changed with that
  variable is followed, or else `http://127.0.0.1:9090/readyz`. The image
  uses it as its Docker `HEALTHCHECK`, because it has no shell or `curl`.
  If you move the probe port on the command line or turn it off
  (`-probe-listen ""`), override the health check (`--health-cmd`) or
  disable it (`docker run --no-healthcheck`).

On `SIGTERM` (and `SIGINT`), PrismWAF reports not ready, stops accepting
connections, lets requests in progress finish for up to 10 seconds and
exits. Keep the orchestrator's grace period above that (Kubernetes'
default is 30 seconds).

## Sidecar

As a sidecar, each instance of the application gets its own PrismWAF,
which listens on the pod's port and forwards to the application on the
loopback address:

```
client ─▶ load balancer / ingress ─▶ Service :80 ─▶ pod ┌ PrismWAF :8080 ─▶ app 127.0.0.1:3000 ┐
                                                         └ probes   :9090                       ┘
```

- **The application listens on `127.0.0.1` only**, so it cannot be reached
  without passing PrismWAF, not even from other pods.
- **Trusted proxies.** Requests arrive from the ingress controller or load
  balancer. Set `PRISMWAF_TRUSTED_PROXIES` to their addresses (for an
  ingress controller in the cluster, the pod network, e.g. `10.0.0.0/8`),
  so that rate limits, bot protection and the audit log see the client
  address from `X-Forwarded-For`, not the proxy's (see
  [Client IP](audit-log.md#client-ip)).
- **State is per pod.** Rate limits, bans and other counters are kept in
  each PrismWAF's memory. With 4 replicas behind a load balancer that
  spreads a client's requests, a client gets up to 4 × the limit; divide
  the limits by the number of replicas, or keep clients on one replica.
- **Shared keys.** Give every replica the same `-bot-secret-file` from a
  Secret, so that bot clearance cookies are valid on all of them.
- **Audit log.** Events go to standard output and so to the container
  log, from where the cluster's log collector ships them. Filter by the
  container name, and by lines starting with `{`, to separate them from
  the operational log on standard error.
- **Resources.** PrismWAF needs little: after startup and a few hundred
  requests, the container used about 8 MiB of memory with the built-in
  signatures and 36 MiB with `-engine both`. Rate limits and other
  counters add memory per tracked client. The CRS costs CPU per request;
  see [performance](crs.md#performance).

### Kubernetes

[`examples/kubernetes/sidecar.yaml`](../examples/kubernetes/sidecar.yaml)
is a complete Deployment and Service. Its main parts:

```yaml
initContainers:
  - name: prismwaf
    image: registry.example.com/prismwaf:1.0
    restartPolicy: Always        # a native sidecar (Kubernetes 1.29+)
    env:
      - name: PRISMWAF_BACKEND
        value: http://127.0.0.1:3000
      - name: PRISMWAF_ENGINE
        value: both
      - name: PRISMWAF_TRUSTED_PROXIES
        value: 10.0.0.0/8
    ports:
      - {name: http, containerPort: 8080}
      - {name: probes, containerPort: 9090}
    readinessProbe: {httpGet: {path: /readyz, port: probes}}
    livenessProbe: {httpGet: {path: /healthz, port: probes}}
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true   # with an emptyDir on /tmp for the CRS
containers:
  - name: app                        # listens on 127.0.0.1:3000
```

- **Native sidecar.** As an init container with `restartPolicy: Always`,
  PrismWAF starts before the application and stops after it, so no
  request reaches a stopped WAF during a rollout. On clusters before 1.29,
  put it in `containers` instead.
- **Service.** `targetPort: http` points at PrismWAF, not at the
  application.
- **Configuration.** Put long configurations in a ConfigMap and load it
  with `envFrom: [{configMapRef: {name: prismwaf}}]`; the keys are the
  variable names.
- **Changes.** Options are read at startup. After changing a ConfigMap,
  restart the pods (`kubectl rollout restart deployment/shop`).
- **Network policy.** Allow traffic to port 8080 only, from the ingress
  controller; the probe port needs no ingress, as the kubelet probes it.

### Docker Compose

[`examples/compose/compose.yaml`](../examples/compose/compose.yaml) puts
PrismWAF in front of the example backend:

```yaml
services:
  prismwaf:
    build: ../..
    ports: ["8080:8080"]
    environment:
      PRISMWAF_BACKEND: http://app:8081
      PRISMWAF_RATE_LIMIT: 300/1m
  app:
    # publishes no port: reachable only through PrismWAF
```

```sh
docker compose -f examples/compose/compose.yaml up --build
curl "http://localhost:8080/search?q=1'+OR+'1'='1"     # 403
```

`docker compose ps` shows PrismWAF as `healthy` once it is ready. To share
the application's network namespace as in a pod, use
`network_mode: service:app` on PrismWAF, publish the port on the
application's service and set the backend to `http://127.0.0.1:...`.

## Library

The package `github.com/cmc-labo/prism-waf/prismwaf` puts PrismWAF into a
Go program as `net/http` middleware.

```sh
go get github.com/cmc-labo/prism-waf/prismwaf
```

```go
waf, err := prismwaf.New(prismwaf.Options{
	Engine:         prismwaf.EngineBoth,
	RateLimit:      "300/1m",
	RateLimitPaths: []string{"POST /login=5/1m"},
})
if err != nil {
	log.Fatal(err)
}
http.ListenAndServe(":8080", waf.Middleware(mux))
```

A runnable program is in
[`examples/library`](../examples/library/main.go):

```sh
go run ./examples/library
curl "http://localhost:8080/search?q=1'+OR+'1'='1"     # 403
```

### Options

| Field | Default | Same as |
|-------|---------|---------|
| `Engine` | `EngineBuiltin` | `-engine`: `EngineBuiltin`, `EngineCRS` or `EngineBoth` |
| `CRSParanoiaLevel` | `1` | `-crs-paranoia-level` |
| `CRSAnomalyThreshold` | `5` | `-crs-anomaly-threshold` |
| `Mode` | `ModeBlock` | `-mode`: `ModeBlock` or `ModeDetect` |
| `MaxBodySize` | 128 KiB | `-max-body` |
| `RateLimit` | (none) | `-rate-limit`, e.g. `"300/1m"` |
| `RateLimitPaths` | (none) | `-rate-limit-path`, e.g. `"POST /login=5/1m"` |
| `RateLimitExempt` | (none) | `-rate-limit-exempt`, IPs or CIDRs |
| `TrustedProxies` | (none) | `-trusted-proxies`, IPs or CIDRs |
| `AuditLog` | `os.Stdout` | `-audit-log`; any `io.Writer`, `io.Discard` to turn it off |
| `Logger` | `slog.Default()` | The operational log |

`New` validates the options like the command validates its flags and
returns an error for invalid ones. Blocked requests get the same
responses as from the proxy (`403`, `413`, `429` with `Retry-After`, gRPC
status for gRPC calls) and the same [audit events](audit-log.md).

### Using it

- **One WAF per program.** Create it once and wrap all handlers with it:
  handlers wrapped by the same WAF share the rate limits.
- **Wrap the router.** `waf.Middleware(router)` works with any router that
  is an `http.Handler`: `net/http`'s `ServeMux`, chi, gorilla/mux, gin's
  `*gin.Engine`, echo's `*echo.Echo`. As route middleware: chi
  `r.Use(waf.Middleware)`, echo `e.Use(echo.WrapMiddleware(waf.Middleware))`.
- **Leave out what must not be inspected**, such as health checks, by
  routing them around the middleware, as the example does.
- **Bodies.** The middleware reads the body up to `MaxBodySize` to inspect
  it and hands it on unchanged, so handlers can read it as usual.
- **Server limits.** The proxy limits the request line and headers to
  64 KiB, because the query string is inspected like the body but not
  limited by `MaxBodySize`. Set `MaxHeaderBytes: 64 << 10` and a
  `ReadHeaderTimeout` on your `http.Server` as well.
- **Behind a proxy.** Set `TrustedProxies` to the load balancer's
  addresses, or rate limits count the proxy instead of the clients.

### Not in the library yet

Bot protection, API protection (OpenAPI, GraphQL, gRPC schemas),
business flow limits, geo filtering, bans, limits of connections and
requests in progress, CRS rule exclusion files and TLS are only available
in the reverse proxy and the sidecar. The internal packages may change;
only `prismwaf` is a public API, and it may still change while PrismWAF
is in early development.
