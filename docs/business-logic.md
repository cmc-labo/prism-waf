# Business flow protection

Some attacks consist only of requests that are valid one by one, so
signatures and API validation cannot detect them. They abuse the logic of
the application: what it allows a client to do, and how often. PrismWAF
limits two of the most common ones per client:

| Attack | Examples | Protection |
|--------|----------|------------|
| Guessing a secret through a flow | Passwords at a login form (brute force, credential stuffing), one-time codes, password reset tokens, coupon and gift card codes | **Failure limits** (`-failure-limit`): a client that fails too often is rejected from the flow for a while; successful requests are not limited |
| Harvesting records by their IDs | Walking through `/api/orders/1`, `/2`, `/3`, …, which also reveals other users' records if the application does not check who owns them (broken object level authorization, [OWASP API1](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)); scraping profiles or invoices | **Enumeration limits** (`-enumeration-limit`): a client may request a number of distinct IDs per window; IDs it already requested stay available |

Both are counted per client, an IP address or the `/64` network of an
IPv6 address, like the [rate limits](rate-limiting.md), and share their
options for exempt clients and memory.

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -failure-limit "POST /login=5/15m" \
  -failure-limit "POST /api/redeem=10/1h 400,404" \
  -enumeration-limit "GET /api/orders/{id}=100/1h"
```

- [Options](#options)
- [Failure limits](#failure-limits)
- [Enumeration limits](#enumeration-limits)
- [Order of processing](#order-of-processing)
- [Responses and audit events](#responses-and-audit-events)
- [Rollout](#rollout)
- [Memory and performance](#memory-and-performance)
- [Limitations](#limitations)

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-failure-limit` | (none) | Limit on failed attempts per client, as `[METHOD ]PATH=N/WINDOW[ STATUS,...]`, e.g. `POST /login=5/15m` or `POST /api/redeem=10/1h 4xx`; repeatable |
| `-enumeration-limit` | (none) | Limit on distinct IDs per client, as `[METHOD ]PATH=N/WINDOW` with `{name}` segments, e.g. `GET /api/orders/{id}=100/1h`; repeatable |
| `-rate-limit-exempt` | (none) | Comma-separated IPs/CIDRs of clients that are never limited, by rate, failure or enumeration limits |
| `-rate-limit-max-clients` | `100000` | Maximum number of clients tracked at once, by each failure limit and by all enumeration limits together |
| `-trusted-proxies` | (none) | Needed behind a load balancer or CDN, so that clients are told apart (see [Client IP](audit-log.md#client-ip)) |

Paths are matched like those of [rate limits](rate-limiting.md#path-rules):
without case, after removing dot segments, duplicate and trailing slashes
and `;` parameters, so `/LOGIN/` and `/x/../login;jsessionid=1` are
`/login`. A method restricts a rule to that method. A window is a Go
duration, e.g. `30s`, `15m`, `1h`.

## Failure limits

A failure limit counts the requests to a flow whose **response** is a
failure, by its HTTP status. The statuses are given after the rate,
separated by commas: a code (`401`), a class (`4xx`) or a range
(`400-409`). The default is `401,403`, which login forms and APIs usually
answer wrong credentials with.

```sh
-failure-limit "POST /login=5/15m"                  # 401 or 403
-failure-limit "POST /api/2fa/verify=5/15m 400,401"  # one-time codes
-failure-limit "POST /api/gift-cards/*=10/1h 404"     # codes that do not exist
-failure-limit "POST /password-reset/*=5/1h 4xx"
```

`N/WINDOW` works like a [rate](rate-limiting.md#bursts-and-refilling): a
client may fail `N` times in a row, after which it may try again once
every `WINDOW/N`. With `5/15m`, a client that failed 5 times is rejected
for 3 minutes, then gets one more attempt every 3 minutes, which allows an
attacker 480 guesses a day instead of millions. Successful attempts do not
count, so users who log in often are never limited, unlike a rate limit on
the login form. While a client is limited, **all** its requests to the
flow are rejected without reaching the backend, also with the right
password: otherwise an attacker could keep guessing and only the failures
would be stopped.

The limit applies to the client, not to the account: an attacker cannot
lock a user out by failing at their account, and a user can log in from
another network while their address is limited.

Requests that PrismWAF itself rejects, such as attacks blocked by
signatures, are not counted, and neither are requests whose client went
away before the backend answered. Answers that are not failures, such as
`200`, `302` or `404` with the default statuses, are not counted either.

If the application answers a failed login with `200` and an error page,
or redirects to the login form again with `302`, its status does not tell
failures from successes, and a failure limit does not work with it; use a
[rate limit](rate-limiting.md#protect-a-login-form-against-password-guessing)
on the form instead, or make the application answer with `401`.

## Enumeration limits

An enumeration limit counts, for each client, the distinct values of the
`{name}` segments of a path template that it requests in a window:

```sh
-enumeration-limit "GET /api/orders/{id}=100/1h"
-enumeration-limit "/api/users/{user}/documents/{doc}=50/10m"
-enumeration-limit "GET /invoices/{number}=20/24h"
```

A parameter must be a whole segment (`{id}`, not `{id}.json`), and the
template must have at least one. Each `{name}` matches exactly one
segment, so `/api/orders/{id}` does not match `/api/orders/1/items`. With
several parameters, each combination counts once.

The window of a client starts with its first request to the template.
Within it, the client may request `N` distinct values; requests for values
it already requested are always allowed, so a user who reloads their
orders is never limited. The first request for one more value is rejected
until the window ends, and the window starts again with the client's next
request after that. Values are compared after the path is cleaned and
decoded, so `/api/orders/%31` and `/API/orders/1/` are the same order.

Choose `N` above what a real user needs in a window: the number of orders
a customer has, the documents a user opens in a session. To find it, run
in [detection mode](#rollout) first.

## Order of processing

Failure and enumeration limits are checked after
[countries](geo-filtering.md) and [rate limits](rate-limiting.md), and
before [bot protection](bot-protection.md) and the inspection of
requests, so that a client that guesses passwords does not get a
challenge that lets it go on. Requests that are then blocked as attacks
have been counted for enumeration limits, but not as failures.

Failure and enumeration limits do not apply to gRPC calls, whose status is
not an HTTP status.

## Responses and audit events

A rejected request gets `429 Too Many Requests` with `Retry-After`, the
number of seconds until the client may try again, and the event ID:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 180
Content-Type: text/plain; charset=utf-8

Too Many Requests
Event ID: 4f2a9c1e7b3d5a60
```

The first rejected request of each excess is logged; the following ones
share its event ID, until the client is allowed again. The reason is
`failure_limit` or `enumeration`, and the details are in `rate_limit`, as
for rate limits:

```json
{
  "time": "2026-11-19T08:15:02.123Z",
  "id": "4f2a9c1e7b3d5a60",
  "client_ip": "198.51.100.7",
  "remote_addr": "127.0.0.1:52144",
  "action": "block",
  "reason": "failure_limit",
  "rate_limit": {"rule": "POST /login=5/15m 401,403", "client": "198.51.100.7/32", "retry_after": 180},
  "request": {"method": "POST", "uri": "/login", "proto": "HTTP/1.1", "host": "shop.example", "content_length": 38, "headers": {"...": "..."}}
}
```

```sh
# Clients that guessed most often
jq -r 'select(.reason == "failure_limit") | .rate_limit.client' audit.log | sort | uniq -c | sort -rn
# Enumerations per rule
jq -r 'select(.reason == "enumeration") | .rate_limit.rule' audit.log | sort | uniq -c
```

At startup, PrismWAF logs the rules as they are applied, with the default
statuses:

```
level=INFO msg="business flow protection enabled" failure_limits="[POST /login=5/15m 401,403]" enumeration_limits="[GET /api/orders/{id}=100/1h]" exempt=""
```

## Rollout

1. Start with `-mode detect`: excesses are logged with `"action":
   "detect"`, and every request is forwarded.
2. Check the events of real users: offices and mobile networks share an
   address, and some users really open many orders. Raise the limits, or
   exempt known networks with `-rate-limit-exempt`.
3. Switch to `-mode block`.

Detection mode applies to all of PrismWAF; attacks are not blocked either
while it is on.

## Memory and performance

Each failure limit keeps a counter per client like a
[rate limit](rate-limiting.md#memory), only for clients that failed
recently. An enumeration limit keeps 8 bytes per distinct value and client
for the window: about 150 bytes per client and rule plus 10 bytes per
value, measured with Go 1.25. 100,000 clients that each requested 100
values take about 115 MB; lower `-rate-limit-max-clients` if that is too
much. When more clients are tracked, some are forgotten, which resets
their limits, and PrismWAF logs a warning.

A check takes about 0.3 µs, and about 1.3 µs for a client at an
enumeration limit of 1000 values (2 vCPUs, aarch64).

## Limitations

- **Per client, not per account.** Attacks spread over many addresses
  (botnets, residential proxies) stay below the limits of each address,
  and the users of a NAT share a limit. Account lockout, CAPTCHAs or
  [bot protection](bot-protection.md) in front of the flow are still
  needed against distributed attacks.
- **Failures by status only.** Applications that answer failures with
  `200` or `302` cannot use failure limits. Response bodies are not
  inspected.
- **Concurrent attempts.** A response is counted when it is complete, so a
  client that sends many attempts at once can exceed the limit by the
  number of attempts in flight.
- **IDs in the path only.** IDs in the query string or the body, e.g.
  `/orders?id=1` or GraphQL arguments, are not counted.
- **No ordering of steps.** Skipping a step of a flow, such as confirming
  an order without paying, or changing a price or a quantity, must be
  checked by the application; an [OpenAPI document](api-protection.md#rest-openapi)
  can reject values out of range, such as negative quantities.
- Counters are kept in memory by each process, so several instances count
  separately and a restart resets them (see
  [Several instances and restarts](rate-limiting.md#several-instances-and-restarts)).
