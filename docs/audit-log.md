# Modes and audit log

## Modes

| Mode | `-mode` | Detected requests |
|------|---------|-------------------|
| Block (default) | `block` | Rejected with `403 Forbidden` (`413` if the body is too large; `400` for some [CRS](crs.md#responses-and-audit-events) rules; `429` over a [rate limit](rate-limiting.md)) and logged with `"action": "block"` |
| Detect | `detect` | Forwarded to the backend unchanged and logged with `"action": "detect"` |

Detection mode lets you find false positives on real traffic before
anything is blocked. A typical rollout:

```sh
# 1. Run in detection mode for a while
go run ./cmd/prismwaf -mode detect -audit-log audit.log

# 2. Review what would have been blocked, by rule and by path
jq -r 'select(.action == "detect") | [.rule.id // .reason, .request.uri] | @tsv' audit.log | sort | uniq -c | sort -rn

# 3. Once the remaining detections are real attacks, switch to blocking
go run ./cmd/prismwaf -mode block -audit-log audit.log
```

In detection mode, requests with bodies over `-max-body` are forwarded
without their body being inspected, and logged with
`"reason": "body_too_large"`. For the built-in signatures, only the first
matching rule is logged for each request; CRS events list every matching
rule. See [Roll out the CRS safely](crs.md#roll-out-the-crs-safely) for the
CRS.

## Audit log

Every detected request is written to the audit log as one JSON object per
line. By default it goes to standard output; use `-audit-log` to append to a
file instead (created with mode `0600`, since payloads may contain secrets).

```json
{
  "time": "2026-10-30T01:02:03.456Z",
  "id": "a09a5cdef27be9cb",
  "client_ip": "203.0.113.7",
  "remote_addr": "10.0.0.5:34402",
  "action": "block",
  "reason": "signature",
  "rule": { "id": "SQLI-002", "category": "sqli" },
  "match": {
    "location": "query",
    "data": "union(select",
    "value": "id=1+UNION(SELECT+password+FROM+users)",
    "value_length": 38
  },
  "request": {
    "method": "GET",
    "uri": "/items?id=1+UNION(SELECT+password+FROM+users)",
    "proto": "HTTP/1.1",
    "host": "shop.example.com",
    "content_length": 0,
    "headers": { "Cookie": "[REDACTED]", "User-Agent": "sqlmap/1.8" }
  }
}
```

| Field | Description |
|-------|-------------|
| `id` | Event ID. In block mode it is also returned in the `403`/`413`/`429` response body, so users can report false positives. |
| `client_ip` | Client address (see [Client IP](#client-ip)). |
| `action` | `block`, or `detect` in detection mode. |
| `reason` | `signature`, `crs`, `body_too_large` or `rate_limit`. |
| `rule` | The signature that matched. For the CRS, the most severe matched rule, e.g. `{"id": "942100", "category": "sqli"}`, or the rule that rejected the request on its own (e.g. 200002). |
| `match.location`, `match.field` | Where it matched: `path`, `query`, `header` (with the header name) or `body` (with the path of the value for JSON and XML bodies). For the CRS, the ModSecurity variable and key, e.g. `ARGS` and `json.user.name`. |
| `match.data` | The text the signature matched, after normalization. |
| `match.value` | The raw value that was inspected, i.e. the payload as sent. Truncated to 4 KiB (`value_truncated`, `value_length`). |
| `match.base64` | `true` if the match was in Base64-decoded data. |
| `crs` | CRS details: `anomaly_score`, `deciding_rule` (usually 949110, "anomaly score exceeded") and `rules`, every matched rule with its `id`, `message`, `severity`, `variable` and matched `value`. |
| `rate_limit` | The exceeded [rate limit](rate-limiting.md#responses-and-audit-events): `rule`, `client` and `retry_after`. Only the first rejected request of each excess is logged. |
| `request.headers` | Request headers. `Authorization`, `Cookie` and other credential headers are `[REDACTED]`, unless the attack was found in that header. |

The response to the client only contains the event ID; rule details are not
disclosed.

Examples with [jq](https://jqlang.github.io/jq/):

```sh
# Top attacking IPs
jq -r .client_ip audit.log | sort | uniq -c | sort -rn | head
# Hits per rule
jq -r '.rule.id // .reason' audit.log | sort | uniq -c | sort -rn
# Look up an event reported by a user
jq 'select(.id == "a09a5cdef27be9cb")' audit.log
```

### Client IP

Behind a load balancer or CDN, the TCP peer is the proxy, not the client.
List your proxies with `-trusted-proxies` so that the client address is
taken from `X-Forwarded-For`:

```sh
go run ./cmd/prismwaf -trusted-proxies 10.0.0.0/8,192.0.2.1
```

`X-Forwarded-For` is only used when the request comes from a trusted proxy,
and it is read from right to left, skipping trusted proxies, so clients
cannot spoof their address by sending the header themselves.
