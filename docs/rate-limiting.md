# Rate limiting

PrismWAF can limit how many requests each client sends, overall and to
selected paths. This slows down password guessing and credential stuffing
against login forms, scraping, and floods from a small number of sources.

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -rate-limit 300/1m \
  -rate-limit-path "POST /login=5/1m"
```

Every client may send 300 requests per minute, of which 5 may be `POST
/login`. Requests over a limit get `429 Too Many Requests` with a
`Retry-After` header and are logged in the [audit log](audit-log.md).

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-rate-limit` | (none) | Limit on all requests of each client, as `N/WINDOW` |
| `-rate-limit-path` | (none) | Limit on the requests of each client to one path, as `[METHOD ]PATH=N/WINDOW`; repeatable |
| `-rate-limit-exempt` | (none) | Comma-separated IPs/CIDRs of clients that are never limited |
| `-rate-limit-max-clients` | `100000` | Maximum number of clients tracked at once |

Rate limiting is off unless `-rate-limit` or `-rate-limit-path` is given.

### Rates

`N/WINDOW` allows `N` requests per `WINDOW`. The window is a Go duration
such as `10s`, `1m`, `1h` or `1h30m`; a bare unit means one of it, so
`5/m` is `5/1m`.

### Path rules

`-rate-limit-path` takes an optional method, a path and a rate:

| Rule | Limits |
|------|--------|
| `POST /login=5/1m` | `POST` requests to `/login` |
| `/login=5/1m` | Requests to `/login` with any method |
| `/api/*=100/1m` | Requests to `/api` and every path below it, such as `/api/users/1`, but not `/apikeys` |
| `/admin*=10/1m` | Every path that starts with `/admin`, including `/administrator` |

- The query string is ignored: `/search?q=a` and `/search?q=b` are both
  `/search`.
- Paths are compared after normalization, so clients cannot get around a
  rule by writing the path differently. Case is ignored, and backslashes,
  duplicate and trailing slashes, `.` and `..` segments and path parameters
  (`;jsessionid=…`) are removed: `//Login/`, `/static/../login` and
  `/login;x=1` all count as `/login`. Percent-encoding is decoded first, as
  for routing.
- `*` is only allowed at the end of the path.
- The method is matched exactly: a rule for `GET` does not count `HEAD`.

## How the limits work

### Counting

Each rule counts separately, for each client. A request has to be within
every rule that matches it:

```sh
-rate-limit 300/1m -rate-limit-path "POST /login=5/1m" -rate-limit-path "/api/*=100/1m"
```

Here a `POST /login` counts towards the 300 and the 5, an API request
towards the 300 and the 100, and everything else towards the 300 only.
Rejected requests count towards no rule, so a client that is over the login
limit can still use the rest of the site.

### Bursts and refilling

A limit of `N/WINDOW` lets a client send `N` requests at once. After that,
its allowance refills steadily at one request every `WINDOW / N` (a token
bucket). With `POST /login=5/1m`:

- A user who mistypes their password a few times is not affected: up to 5
  attempts can be made at once.
- An attacker then gets one more attempt every 12 seconds: at most 5 per
  minute on average, or 7,200 per day instead of millions.
- After a full minute without requests, all 5 attempts are available again.

Because the allowance refills continuously, a client can send up to about
`2N - 1` requests within one window if it starts with a full allowance, but
never more than `N` per window on average. Choose `N` as the largest burst
you want to allow, and the window so that `N/WINDOW` is the sustained rate.

`Retry-After` tells the client when its next request will be allowed,
rounded up to whole seconds.

### Clients

A client is the address that PrismWAF reports as `client_ip` in the audit
log:

- **IPv4:** each address counts separately.
- **IPv6:** each `/64` network counts as one client, because a single host
  usually controls a whole `/64` and could otherwise use a new address for
  every request.
- **Behind a load balancer, CDN or reverse proxy:** set
  [`-trusted-proxies`](audit-log.md#client-ip) so that the client address
  is taken from `X-Forwarded-For`. Otherwise every request comes from the
  proxy and **all clients share one limit**. PrismWAF logs a reminder at
  startup when rate limiting is enabled without trusted proxies.

Many users can share one IPv4 address, e.g. behind a company or mobile
carrier NAT. Set limits that such a group of users stays below, and exempt
known networks with `-rate-limit-exempt`.

### Order of processing

Rate limits are checked before a request is inspected for attacks, so a
flood is rejected before PrismWAF spends time on its body. Requests that
are then blocked as attacks still count: a scanner that sends attack
payloads quickly is slowed down by the rate limit as well.

### Memory

PrismWAF remembers a client only while its allowance is not full, i.e. at
most one window after its last request; idle clients are removed about once
a minute. Each tracked client takes about 80 bytes plus 30 bytes per rule.

If more than `-rate-limit-max-clients` clients are tracked at once, for
example during a distributed attack from many addresses, PrismWAF forgets
some at random to make room, which resets their limits, and logs:

```
level=WARN msg="rate limiter is tracking its maximum number of clients; forgetting some, which resets their limits" hint="raise -rate-limit-max-clients if this happens without an attack"
```

The default of 100,000 clients takes about 10 MB with one rule and 15 MB
with three.

### Several instances and restarts

Counters are kept in memory by each PrismWAF process. With several
instances behind a load balancer, each one counts separately, so a client
whose requests are spread over `k` instances can send up to `k` times the
limit. Divide the limits by the number of instances, or use a load
balancer policy that sends each client to the same instance. Restarting
PrismWAF resets all counters.

## Responses and audit events

In block mode (`-mode block`, the default), a request over a limit gets:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 12
Content-Type: text/plain; charset=utf-8

Too Many Requests
Event ID: 9f3c2a7d51e04b68
```

In detection mode (`-mode detect`), it is forwarded to the backend and only
logged, with `"action": "detect"`. Use this to find suitable limits before
enforcing them; see [Find the right limits](#find-the-right-limits).

To keep the audit log readable during a flood, only the **first** rejected
request is logged each time a client exceeds a rule. The following
rejections return the same event ID and are not logged again, until the
client sends a request that is allowed by that rule.

```json
{
  "time": "2026-11-08T03:12:45.120Z",
  "id": "9f3c2a7d51e04b68",
  "client_ip": "203.0.113.7",
  "remote_addr": "203.0.113.7:51544",
  "action": "block",
  "reason": "rate_limit",
  "rate_limit": { "rule": "POST /login=5/1m", "client": "203.0.113.7/32", "retry_after": 12 },
  "request": {
    "method": "POST",
    "uri": "/login",
    "proto": "HTTP/1.1",
    "host": "shop.example.com",
    "content_length": 29,
    "headers": { "Content-Type": "application/x-www-form-urlencoded", "Cookie": "[REDACTED]" }
  }
}
```

| Field | Description |
|-------|-------------|
| `rate_limit.rule` | The exceeded rule. For `-rate-limit`, just the rate, e.g. `300/1m` |
| `rate_limit.client` | What was counted: the client address as `/32`, or its `/64` network for IPv6 |
| `rate_limit.retry_after` | Seconds until the client could send its next request |

The request body is not logged.

```sh
# Clients that exceeded a limit most often
jq -r 'select(.reason == "rate_limit") | .rate_limit.client' audit.log | sort | uniq -c | sort -rn | head
# Excesses per rule
jq -r 'select(.reason == "rate_limit") | .rate_limit.rule' audit.log | sort | uniq -c
```

## Use cases

### Protect a login form against password guessing

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -rate-limit-path "POST /login=5/1m" \
  -rate-limit-path "POST /password-reset=3/10m"
```

Only form submissions are limited; loading the login page with `GET` is
not. Add a rule for every endpoint that checks a secret: login, password
reset, two-factor codes, API token exchange. The limit is per client, so
it does not lock out a user's account when someone else attacks it.

Distributed attacks from many addresses (botnets, residential proxies) stay
below a per-client limit. Rate limiting reduces their speed per address,
but account lockout or CAPTCHAs in the application are still needed
against them.

### Limit an API

```sh
prismwaf -backend http://127.0.0.1:8000 \
  -rate-limit-path "/api/*=600/1m" \
  -rate-limit-path "POST /api/search=30/1m"
```

Every client may make 600 API calls per minute, 30 of them to the expensive
search endpoint. Well-behaved API clients can read `Retry-After` and back
off.

### A ceiling for the whole site

```sh
prismwaf -backend http://127.0.0.1:3000 -rate-limit 600/1m
```

A page load can mean dozens of requests for images, scripts and API calls,
so overall limits have to be generous. Check in detection mode first, or
serve static files from a CDN so they do not reach PrismWAF.

### Behind a load balancer or CDN

```sh
prismwaf -listen :8080 -backend http://127.0.0.1:3000 \
  -trusted-proxies 10.0.0.0/8 \
  -rate-limit 600/1m -rate-limit-path "POST /login=5/1m"
```

Without `-trusted-proxies`, all requests would come from the load balancer
and share one limit. Make sure the load balancer appends the client address
to `X-Forwarded-For`.

### Exempt monitoring and internal networks

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -rate-limit 300/1m \
  -rate-limit-exempt 192.0.2.10,198.51.100.0/24,2001:db8:100::/48
```

Uptime monitors, internal batch jobs and load tests should not be limited.
An exempt address is also exempt from path rules.

### Find the right limits

1. Run in detection mode with generous limits:

   ```sh
   prismwaf -mode detect -audit-log audit.log \
     -rate-limit 600/1m -rate-limit-path "POST /login=10/1m"
   ```

2. After a few days of normal traffic, see which clients would have been
   limited and by which rule:

   ```sh
   jq -r 'select(.reason == "rate_limit") | [.rate_limit.rule, .client_ip, .request.headers["User-Agent"]] | @tsv' audit.log | sort | uniq -c | sort -rn
   ```

3. If legitimate clients appear, raise their limit or exempt them. Then
   switch to `-mode block`.

Detection mode applies to all of PrismWAF; attacks are not blocked either
while it is on.

## Limitations

- PrismWAF limits HTTP requests. Floods of TCP connections or TLS
  handshakes, and attacks that saturate the network, have to be stopped
  before they reach PrismWAF, e.g. by the hosting provider or a CDN.
  PrismWAF's [fixed limits](configuration.md#fixed-limits) and timeouts
  protect against slow and oversized requests.
- Counters are per process and are reset by a restart (see
  [Several instances and restarts](#several-instances-and-restarts)).
- Limits are per client only. There is no limit on all clients together,
  per user account, per header value or per host name.
- Rules apply to every host name served by PrismWAF.
