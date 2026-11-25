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
| `-alert-rate-limited-requests` | (none) | [Alert](#alerts) when the rate limits reject this many requests of all clients together, as `N/WINDOW` |
| `-alert-rate-limited-clients` | (none) | [Alert](#alerts) when this many distinct clients exceed a limit, as `N/WINDOW` |
| `-alert-rate-limited-client` | (none) | [Alert](#alerts) when the requests of one client are rejected this many times, as `N/WINDOW` |
| `-alert-webhook` | (none) | URL to `POST` alerts to |
| `-alert-webhook-format` | `json` | Payload of the webhook: `json`, `slack` (also Mattermost, Google Chat) or `discord` |
| `-alert-command` | (none) | Shell command to run for each alert |
| `-alert-notify-rate-limit` | `10/1h` | Most alerts sent per window; the others are sent together when the window ends. `off` disables |
| `-alert-test` | `false` | Send a test alert to `-alert-webhook` and `-alert-command` and exit |

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
Clients [blocked by their country](geo-filtering.md) are rejected before
the rate limits and do not count, and so are [banned clients and requests
over the limits of requests in progress](ddos.md#order-of-processing). [Failure and enumeration
limits](business-logic.md) are checked after the rate limits.

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

## Alerts

The audit log records every client that exceeds a limit, but nobody reads
it while an attack is going on. PrismWAF can count how often the rate
limits are triggered and alert administrators when that exceeds a
threshold:

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -rate-limit 300/1m -rate-limit-path "POST /login=5/1m" \
  -alert-rate-limited-requests 1000/5m \
  -alert-rate-limited-clients 50/5m \
  -alert-rate-limited-client 300/5m \
  -alert-webhook https://hooks.slack.com/services/T000/B000/XXXX \
  -alert-webhook-format slack
```

```
[PrismWAF waf1] WARNING: Client 203.0.113.7 was rate limited 300 times within 1m42s (alert threshold: 300 per 5m0s). Rules: POST /login=5/1m (300).
[PrismWAF waf1] WARNING: 50 clients were rate limited within 3m10s (alert threshold: 50 per 5m0s). Top clients: 198.51.100.23 (41), 203.0.113.7 (38), 192.0.2.80 (12), 2001:db8:4:2::/64 (9), 192.0.2.81 (7). Rules: POST /login=5/1m (130), 300/1m (22).
[PrismWAF waf1] INFO: Rate-limited clients are below the alert threshold (50 per 5m0s) again after 25m0s: at most 104 clients per window.
```

### Thresholds

Each threshold is `N/WINDOW`, like a rate. All three are optional; use
the ones that match what you want to know:

| Option | Counts | Typical cause |
|--------|--------|---------------|
| `-alert-rate-limited-requests` | Rejected requests of all clients together | A flood, or a limit that is too low for normal traffic (e.g. after a release) |
| `-alert-rate-limited-clients` | Distinct clients (IPv6: `/64` networks) that were rejected | A distributed attack, such as credential stuffing from a botnet, where each address stays near the limit |
| `-alert-rate-limited-client` | Rejected requests of a single client | One aggressive client, e.g. a scraper or a password-guessing script; the alert names its IP |

Counting starts with the first request a limit rejects. In detection mode
(`-mode detect`), the requests that would have been rejected count, so
thresholds can be tuned before limits are enforced. Only `-rate-limit` and
`-rate-limit-path` count; failure and enumeration limits of
[business flow protection](business-logic.md), and the
[denial of service protection](ddos.md), do not.

To pick thresholds, look at how often the limits are exceeded on a normal
day (see the `jq` commands [above](#responses-and-audit-events)), and set
the threshold well above it. An alert should mean that something unusual
is going on.

### When PrismWAF alerts

The count starts over in each window (fixed windows from the start of
PrismWAF):

- A threshold is alerted **as soon as** it is reached, not at the end of
  the window. The alert lists the top 5 clients and rules of the window.
- While it lasts, it is not alerted again, however many windows exceed
  the threshold.
- A whole window below the threshold resolves it: for the requests and
  clients thresholds, PrismWAF sends `rate_limit_alert_resolved` with how
  long it lasted, the total of rejected requests, and the highest count of
  a window. A single
  client is only logged as resolved, so that many clients do not mean
  twice as many notifications. After that, the next excess is a new
  alert.

| Event | Severity | When |
|-------|----------|------|
| `rate_limited_requests` | `warning` | `-alert-rate-limited-requests` was reached |
| `rate_limited_clients` | `warning` | `-alert-rate-limited-clients` was reached |
| `rate_limited_client` | `warning` | A client reached `-alert-rate-limited-client` |
| `rate_limit_alert_resolved` | `info` | A window below the requests or clients threshold after its alert |
| `notification_digest` | Highest of its alerts | Alerts held back by `-alert-notify-rate-limit` |
| `test` | `info` | Sent by `-alert-test` |

When many clients exceed `-alert-rate-limited-client` at once, the first
10 alerts in an hour are sent and the others are held back and sent
together in one `notification_digest` when the hour ends (see
`-alert-notify-rate-limit`, which works like
[`-acme-notify-rate-limit`](acme.md#limiting-notifications)). Use
`-alert-rate-limited-clients` to learn about such attacks in one alert.

To limit memory during a distributed attack, each window counts at most
10,000 clients individually. Further clients still count as rejected
requests, but not as distinct clients or towards
`-alert-rate-limited-client`; the alert then says so.
`-alert-rate-limited-clients` must be at most 10,000.

### Where alerts go

Alerts are always written to the operational log, so that a log-based
monitoring system can pick them up:

```
level=WARN msg="rate limit alert" event=rate_limited_client metric=client client=203.0.113.7 count=300 threshold=300 window=5m0s message="Client 203.0.113.7 was rate limited 300 times within 1m42s (alert threshold: 300 per 5m0s). Rules: POST /login=5/1m (300)."
level=INFO msg="rate limit alert resolved" event=rate_limit_alert_resolved metric=requests count=15320 threshold=1000 window=5m0s message="…"
level=INFO msg="rate limit alert resolved" metric=client client=203.0.113.7 threshold="300 per 5m0s"
```

With `-alert-webhook` or `-alert-command`, they are also sent there. The
webhook formats, the command's input, retries and the handling of
secrets are the same as for
[certificate notifications](acme.md#webhooks); check the setup with
`-alert-test`. They may use the same URL or command as the
`-acme-notify-*` options. The `json` format and a command's standard
input have these fields in addition to `time`, `event`, `severity`,
`host` and `message`:

```json
{
  "event": "rate_limited_requests",
  "severity": "warning",
  "message": "Rate limits rejected 1000 requests within 2m13s (alert threshold: 1000 per 5m0s). Top clients: …",
  "metric": "requests",
  "count": 1000,
  "threshold": 1000,
  "window": "5m0s",
  "top_clients": [{ "name": "203.0.113.7", "count": 812 }, { "name": "198.51.100.4", "count": 120 }],
  "top_rules": [{ "name": "POST /login=5/1m", "count": 900 }, { "name": "300/1m", "count": 100 }]
}
```

| Field | Variable | Description |
|-------|----------|-------------|
| `metric` | `PRISMWAF_METRIC` | `requests`, `clients` or `client`: the threshold |
| `client` | `PRISMWAF_CLIENT` | For `rate_limited_client`: the client's IP, or its `/64` network for IPv6 |
| `count` | `PRISMWAF_COUNT` | Rejected requests or clients when the threshold was reached. For `rate_limit_alert_resolved`: the rejected requests while the alert lasted, or the most clients of a window |
| `threshold`, `window` | `PRISMWAF_THRESHOLD`, `PRISMWAF_WINDOW` | The threshold, e.g. `1000` and `5m0s` |
| `top_clients` | | Up to 5 clients with the most rejected requests in the window (not for `rate_limited_client`) |
| `top_rules` | | Up to 5 rules that rejected the most requests: of the window, or of the client |

A client in an alert can be [banned](ddos.md) automatically with `-ban`,
or blocked by hand, e.g. in the firewall.

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

A [failure limit](business-logic.md#failure-limits) such as
`-failure-limit "POST /login=5/15m"` is stricter for attackers and does
not limit users who log in successfully, if the application answers wrong
passwords with `401` or `403`.

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

- Rate limits count requests. Slow clients, connections and requests in
  progress are limited by [denial of service protection](ddos.md), which
  can also ban clients that keep exceeding the rate limits. Attacks that
  saturate the network have to be stopped before they reach PrismWAF,
  e.g. by the hosting provider or a CDN.
- Counters are per process and are reset by a restart (see
  [Several instances and restarts](#several-instances-and-restarts)).
- Limits are per client only. There is no limit on all clients together,
  per user account, per header value or per host name.
- Rules apply to every host name served by PrismWAF.
- [Alerts](#alerts) are counted per process, like the limits: with
  several instances, each one alerts on its own share of the traffic.
  Their state is reset by a restart.
