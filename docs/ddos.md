# Denial of service protection

[Rate limits](rate-limiting.md) count requests. Many denial of service
attacks send few requests, but hold what a server has least of:
connections, requests in progress and time. PrismWAF limits these too:

| Attack | Protection | Default |
|--------|------------|---------|
| Opening connections and sending nothing, or a request byte by byte (Slowloris) | Time to send the first bytes and the headers (`-read-header-timeout`) | 10 s |
| Sending a request body byte by byte (slow POST, R.U.D.Y.) | Minimum rate of request bodies (`-body-timeout`, `-body-min-rate`) | 20 s, then 500 bytes/s |
| Opening many connections from one address | Connections per client and in total (`-max-conns-per-ip`, `-max-conns`) | Off |
| Many slow requests at once, e.g. to an expensive search, which tie up the backend's workers | Requests in progress per client and in total (`-max-client-requests`, `-max-requests`) | Off |
| Clients that keep attacking after they are rejected | Temporary bans (`-ban`, `-ban-duration`) | Off |

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -rate-limit 300/1m \
  -max-conns 20000 -max-conns-per-ip 100 \
  -max-requests 2000 -max-client-requests 20 \
  -ban 300/1m -ban-duration 10m
```

Clients are counted by IP address, the `/64` network for IPv6, like the
rate limits. Behind a load balancer or CDN, set
[`-trusted-proxies`](audit-log.md#client-ip): connection limits then do
not apply to the proxies, and the other limits count the clients in
`X-Forwarded-For`.

- [Options](#options)
- [Timeouts of slow clients](#timeouts-of-slow-clients)
- [Connection limits](#connection-limits)
- [Requests in progress](#requests-in-progress)
- [Bans](#bans)
- [Order of processing](#order-of-processing)
- [Responses and audit events](#responses-and-audit-events)
- [Choosing the limits](#choosing-the-limits)
- [Measurements](#measurements)
- [Limitations and network-level attacks](#limitations-and-network-level-attacks)

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-read-header-timeout` | `10s` | Time a new connection has to send its first bytes and a client to send the request line and headers; also the TLS handshake timeout. `0` disables |
| `-body-timeout` | `20s` | Time a client has to start sending a request body; slower requests get `408`. `0` disables |
| `-body-min-rate` | `500` | Minimum rate of request bodies in bytes per second, after `-body-timeout` |
| `-max-conns` | `0` (no limit) | Maximum open client connections; more are closed when they are accepted |
| `-max-conns-per-ip` | `0` (no limit) | Maximum open connections per client address, except `-trusted-proxies` and `-rate-limit-exempt` |
| `-max-requests` | `0` (no limit) | Maximum requests in progress; more get `503` |
| `-max-client-requests` | `0` (no limit) | Maximum requests in progress per client; more get `429` |
| `-ban` | (none) | Ban clients whose requests are rejected `N` times per `WINDOW`, e.g. `100/1m` |
| `-ban-duration` | `10m` | How long a client is banned |
| `-rate-limit-exempt` | (none) | Clients that are never limited per client or banned |
| `-rate-limit-max-clients` | `100000` | Maximum number of clients tracked at once, also by bans |

## Timeouts of slow clients

**Headers.** A new connection must send its first bytes, and a client the
request line and headers, within `-read-header-timeout`. Connections that
send nothing or stop in the middle are closed. Idle keep-alive connections
are closed after 120 seconds, and idle HTTP/2 connections by the HTTP/2
server.

> **Fixed in this version.** Since PrismWAF accepts HTTP/2 without TLS
> (h2c) for gRPC, Go's `net/http` read the first 14 bytes of every
> plain-text connection without any deadline: a connection that sent
> nothing, or `G`, stayed open for ever, and `-read-header-timeout` did
> not help. PrismWAF now sets the deadline itself.

**Bodies.** A request body must start within `-body-timeout`, and the time
is extended by one second for every `-body-min-rate` bytes received, like
Apache's `mod_reqtimeout`. With the defaults, any client that sends more
than 500 bytes per second on average is not affected: a 1 MB upload over
a slow mobile connection at 10 KB/s takes 100 seconds and is allowed up
to about 35 minutes. A client that sends a body byte by byte to hold the
connection and a request in progress gets `408 Request Timeout` after
about 20 seconds, and the connection is closed. This happens in detection
mode too, as the body cannot be forwarded.

gRPC calls are not timed: their streams may pause for as long as the
application needs.

## Connection limits

`-max-conns-per-ip` limits the open connections of each client address,
and `-max-conns` all open connections. Connections over a limit are closed
as soon as they are accepted, before the TLS handshake, which saves the
CPU time of the handshake. Browsers open at most 6 connections per host
over HTTP/1.1 and one over HTTP/2, so a limit of 50 to 100 per address
leaves room for users behind a shared address (NAT).

Connections of `-trusted-proxies` carry many clients and are only counted
in `-max-conns`.

Closed connections are logged at most once a minute:

```
level=WARN msg="closing connections over the limits" reason=max_conns_per_client client=198.51.100.7:51234 closed_last_minute=48211 open=100
```

`reason` is `max_conns`, `max_conns_per_client` or `banned`.

## Requests in progress

`-max-client-requests` limits the requests of each client that are in
progress at once: from when PrismWAF receives the request until the
response has been sent. A client that sends many slow requests at once,
over many connections or HTTP/2 streams, gets `429` for the ones over the
limit, so it cannot occupy all workers of the backend. Browsers rarely
have more than 6 to 10 requests in progress per site.

`-max-requests` limits all requests in progress. Beyond it, PrismWAF
rejects new requests at once with `503 Service Unavailable` and
`Retry-After: 1` (load shedding), instead of queuing them until they time
out, so that the requests it accepts are answered in time. The limit of
each client is checked first, so a single client that causes the overload
gets `429`. Requests rejected with `503` are not audit events, as they are
not the client's fault; PrismWAF logs them at most once a minute:

```
level=WARN msg="too many requests in progress; rejecting requests with 503" max_requests=2000 count_last_minute=1843
```

WebSocket connections, server-sent events and gRPC streams are requests in
progress for as long as they are open. Set the limits above the number
that a client keeps open.

## Bans

With `-ban N/WINDOW`, a client whose requests are rejected `N` times per
`WINDOW`, for any reason, is banned for `-ban-duration`: all its requests
get `403` with `Connection: close`, and when the client is the TCP peer
(not behind a trusted proxy), its new connections are closed as soon as
they are accepted. This stops clients that keep sending requests that are
rejected anyway, such as floods over a rate limit, scanners and password
guessing, at the lowest cost.

Rejections are counted like a rate: `100/1m` allows bursts of 100
rejections, refilled at one every 0.6 seconds. Responses with a status of
`500` or above, such as errors of the CRS engine and `503` for overload,
do not count. In detection mode, no requests are rejected, so no client is
banned.

The ban starts with one audit event; the requests rejected during the ban
share its ID and are not logged.

## Order of processing

1. Connection limits and bans of TCP peers, when a connection is accepted.
2. `-read-header-timeout` until the request headers are read.
3. Bans of clients.
4. Requests in progress: per client, then in total.
5. Countries, rate limits, failure and enumeration limits, bot
   protection, inspection; `-body-timeout` applies while the body is read.

## Responses and audit events

| Situation | Status | Audit event `reason` |
|-----------|--------|----------------------|
| Body too slow | `408` with `Connection: close` | `slow_request` |
| Client over `-max-client-requests` | `429` with `Retry-After: 1` | `concurrency` (first request of each excess) |
| Over `-max-requests` | `503` with `Retry-After: 1`, without event ID | none (operational log) |
| Client banned | `403` with `Connection: close` and `Retry-After` | `ban` (once per ban) |
| Connection over a limit or of a banned client | Connection closed | none (operational log) |

gRPC calls get the gRPC status for the HTTP status: `ResourceExhausted`
for `429`, `Unavailable` for `503`, `PermissionDenied` for `403`.

Like the rate limits, `concurrency` and `ban` events have their details in
`rate_limit`:

```json
{"reason": "ban", "rate_limit": {"rule": "300/1m for 10m", "client": "198.51.100.7/32", "retry_after": 600}, "...": "..."}
{"reason": "concurrency", "rate_limit": {"rule": "20 in progress", "client": "198.51.100.7/32", "retry_after": 1}, "...": "..."}
```

```sh
# Banned clients
jq -r 'select(.reason == "ban") | [.time, .rate_limit.client] | @tsv' audit.log
# Why they were banned: their rejections before the ban
jq -r 'select(.client_ip == "198.51.100.7") | .reason' audit.log | sort | uniq -c
```

At startup, PrismWAF logs the settings:

```
level=INFO msg="denial of service protection" read_header_timeout=10s body_timeout=20s body_min_rate=500 max_conns=20000 max_conns_per_ip=100 max_requests=2000 max_client_requests=20 ban="300/1m for 10m"
```

## Choosing the limits

- **`-max-requests`**: what the backends can handle at once, e.g. the
  number of their workers or database connections, plus room for fast
  requests. Measure with a load test: the number of requests in progress
  at which response times start to rise.
- **`-max-client-requests`**: 10 to 20 for web sites, more for API
  clients that send requests in parallel, and exempt known API clients
  with `-rate-limit-exempt`.
- **`-max-conns-per-ip`**: 50 to 100. Without `-trusted-proxies` behind a
  load balancer, all clients come from its addresses: leave it off.
- **`-max-conns`**: below the file descriptor limit of the process (`ulimit
  -n`; systemd's `LimitNOFILE`), leaving room for connections to the
  backends. Each idle connection takes about 20 KB of memory.
- **`-ban`**: well above what a real user gets rejected, e.g. three times
  the rate limit. Run in detection mode first and look at the rejections
  per client.

## Measurements

Run on 2026-11-20 on Linux (aarch64, 2 vCPUs) with Go 1.25.0, with the
attacker on the same machine. The backend was an application with 50
workers. "Legit" is a normal request from another address during the
attack.

| Attack | Before | After |
|--------|--------|-------|
| 5000 connections from one address that send nothing | All kept open for ever | Closed after `-read-header-timeout`; with `-max-conns-per-ip 100`, at most 100 open |
| Slow POST: 2000 connections, one byte of the body every 5 s | All 2000 open for 60 s, until the attacker stopped | All closed after 20-25 s with `408` and a `slow_request` event |
| 500 requests at once from one client to an endpoint that takes 2 s | Legit requests timed out after 15 s | `-max-client-requests 20`: the attacker gets 20 at a time; legit requests answered in 2-14 ms |
| Flood over keep-alive from one client, 10 s, `-rate-limit 100/1s` | 808,613 requests answered with `429`, 1,099 forwarded, 9.6 s of CPU | `-ban 200/10s`: banned after its first 200 rejections, within a fraction of a second; 102 forwarded; 4.8 s of CPU, spent on closing its new connections |

## Limitations and network-level attacks

- **Network floods.** Attacks that fill the network link, SYN floods and
  UDP floods never reach PrismWAF. They have to be stopped before it: by
  the hosting provider, a DDoS protection service or a CDN.
- **Connection floods.** PrismWAF closes connections over a limit at once,
  but each still costs it an `accept` and a `close`: a client that
  reconnects in a loop can use up a CPU core. Limit new connections per
  address in the kernel, before they reach PrismWAF, e.g. with iptables:

  ```sh
  # At most 100 connections per address to port 443…
  iptables -A INPUT -p tcp --syn --dport 443 -m connlimit --connlimit-above 100 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
  # …and at most 50 new ones per second
  iptables -A INPUT -p tcp --syn --dport 443 -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 100 \
    --hashlimit-mode srcip --hashlimit-name prismwaf -j DROP
  ```

- **Distributed attacks.** Limits per client do not stop attacks from many
  addresses that each stay below them. `-max-requests` and `-max-conns`
  keep PrismWAF and the backends responsive, but legitimate requests are
  rejected along with the attack. [Bot protection](bot-protection.md) and
  [geo filtering](geo-filtering.md) can help tell them apart.
- **Slow responses.** A client that reads the response slowly holds the
  connection and the request in progress; it is limited by
  `-max-conns-per-ip` and `-max-client-requests`, but not timed.
- **HTTP/2.** Go limits the streams per connection (250) and protects
  against the known HTTP/2 attacks (Rapid Reset, CVE-2023-44487;
  CONTINUATION flood, CVE-2024-27316). Each stream is a request in progress
  for `-max-client-requests`.
- Counters are per process, like the rate limits.
