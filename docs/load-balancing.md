# Load balancing

Pass several backends by repeating `-backend` or separating URLs with
commas:

```sh
go run ./cmd/prismwaf \
  -backend http://10.0.0.11:8080,http://10.0.0.12:8080 \
  -backend http://10.0.0.13:8080 \
  -health-check-path /healthz
```

`-lb-policy` chooses the backend for each request:

| Policy | Behavior |
|--------|----------|
| `round-robin` (default) | The backends take turns. |
| `least-conn` | The backend with the fewest requests in progress; suits requests of very different durations. Equally loaded backends take turns. |

Failed backends are taken out of rotation in two ways:

- **Connection failures.** If a backend refuses the connection (or cannot be
  resolved or reached), the request is retried on the next backend, and the
  failed one is skipped for `-backend-fail-timeout` (default 10s). Retrying
  is safe for any method, including `POST`, because the failed backend never
  received the request. Errors after the request was sent, such as a
  backend that closes the connection without answering, are not retried
  and return `502 Bad Gateway`, since the request may already have had an
  effect.
- **Health checks.** With `-health-check-path`, PrismWAF sends `GET` for that
  path to every backend every `-health-check-interval` (default 10s).
  Backends that answer with an error status (400 or higher) or not within
  `-health-check-timeout` (default 5s) are skipped until a check succeeds
  again. A successful check also returns a backend that was skipped after a
  connection failure, so a restarted backend is used again immediately.
  Changes of the health state are logged.

If every backend is unavailable, all of them are tried anyway, so a wrong
health state alone cannot cause an outage; `502 Bad Gateway` is returned
when none of them answers.

Every backend gets the same request, including the client's `Host` header,
and the same TLS settings (`-backend-ca`, `-backend-insecure-skip-verify`).
Sticky sessions are not supported, so backends must share session state
or be stateless.

To try it locally, start several example backends; each reports its name
in the `X-Backend` response header:

```sh
go run ./examples/backend -listen :8081 -name b1 &
go run ./examples/backend -listen :8082 -name b2 &
go run ./cmd/prismwaf -backend http://127.0.0.1:8081,http://127.0.0.1:8082
curl -si http://localhost:8080/ | grep X-Backend
```
