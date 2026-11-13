# OWASP Core Rule Set

PrismWAF can inspect requests with the
[OWASP Core Rule Set (CRS)](https://coreruleset.org/) v4, run by the
[OWASP Coraza](https://coraza.io/) WAF engine. The rules (CRS 4.25.0) are
embedded in the binary, so nothing needs to be installed.

- [How it works](#how-it-works)
- [Options](#options)
  - [`-engine`](#-engine)
  - [`-crs-paranoia-level`](#-crs-paranoia-level)
  - [`-crs-anomaly-threshold`](#-crs-anomaly-threshold)
  - [`-crs-max-args`](#-crs-max-args)
  - [`-crs-rules-before` and `-crs-rules-after`](#-crs-rules-before-and--crs-rules-after)
- [Responses and audit events](#responses-and-audit-events)
- [Use cases](#use-cases)
- [Performance](#performance)
- [Limitations](#limitations)

## How it works

```
request ─▶ body size limit ─▶ built-in signatures ─▶ CRS ─▶ backend
           (-max-body)        (-engine builtin|both)  (-engine crs|both)
```

The CRS works in *anomaly scoring* mode. Rules do not block on their own;
each matching rule adds points to the request's anomaly score according to
its severity:

| Severity | Points | Typical rules |
|----------|-------:|---------------|
| critical | 5 | Attack payloads: SQL injection, XSS, RCE, path traversal |
| error | 4 | Rarely used by request rules |
| warning | 3 | Protocol anomalies, e.g. a numeric IP address in `Host` |
| notice | 2 | Minor anomalies |

After all rules have run, rule 949110 compares the total with the
threshold (`-crs-anomaly-threshold`, default 5). At the default, a single
critical rule is enough to block, while a warning alone is not.

A few rules reject a request on their own, regardless of the score:

| Rule | Status | Reason |
|------|-------:|--------|
| 200002 | 400 | The JSON, XML or multipart body cannot be parsed |
| 200003 | 400 | The multipart body fails strict validation, e.g. it is unterminated |
| 9500001 | 400 | More arguments than `-crs-max-args` (added by PrismWAF) |

Coraza's XML parser is lenient: it rejects mismatched tags, but accepts
unclosed elements and bodies that are not XML at all. Such bodies are
still inspected as a whole, so payloads in them are detected.

Only the request rules (`REQUEST-*.conf`) are loaded. PrismWAF's other
features apply to the CRS as well: detection mode (`-mode detect`), the
audit log, the body size limit (`-max-body`) and the event ID in the error
response.

## Options

| Flag | Default | Values |
|------|---------|--------|
| `-engine` | `builtin` | `builtin`, `crs`, `both` |
| `-crs-paranoia-level` | `1` | 1-4 |
| `-crs-anomaly-threshold` | `5` | 1 or more |
| `-crs-max-args` | `1000` | 1 or more |
| `-crs-rules-before` | (none) | SecLang file or glob; repeatable |
| `-crs-rules-after` | (none) | SecLang file or glob; repeatable |

For the numeric options, `0` selects the default. Invalid values, rule
files that cannot be loaded, and `-crs-rules-*` without `-engine crs` or
`both` stop PrismWAF at startup with an error. An error in a rule file
starts with the file's name:

```
level=ERROR msg="prismwaf exited with error" error="crs: loading rules: /etc/prismwaf/after.conf: invalid WAF config from string: unknown directive \"secrulremovebyid\""
``` On a successful start,
PrismWAF logs the settings and how long loading took:

```
level=INFO msg="OWASP CRS loaded" version=4.25.0 paranoia_level=1 anomaly_threshold=5 max_args=1000 took=47ms
```

### `-engine`

Selects the rules that inspect requests.

| Value | Inspection | When to use it |
|-------|------------|----------------|
| `builtin` | PrismWAF's own signatures ([Signature detection](detection.md)) | Low latency and few false positives matter most; large bodies |
| `crs` | Only the CRS | You already run the CRS elsewhere, or want its exclusions and behavior unchanged |
| `both` | The built-in signatures first, then the CRS for requests they let through | Widest coverage |

With `both`, a request blocked by a built-in signature is not passed to
the CRS, so it is logged once, with `"reason": "signature"`. The CRS only
sees requests the signatures allowed, and its events have
`"reason": "crs"`.

### `-crs-paranoia-level`

The paranoia level (PL) selects how many rules are active. Each level adds
the rules of the levels below it.

| Level | Adds | False positives |
|-------|------|-----------------|
| 1 (default) | Rules for clear attack payloads | Rare; most applications run without exclusions |
| 2 | Rules for more SQL injection and XSS variants, plus stricter protocol checks | Expect some; tune with exclusions |
| 3 | Rules for evasion techniques and unusual characters | Frequent; suits applications with little user-generated text |
| 4 | Very strict rules, e.g. restricting special characters | Very frequent; needs extensive tuning |

Higher levels detect more evasions but run more rules, which costs more
CPU time, and match more legitimate input. Raise the level one step at a
time, and run each step in detection mode first (see
[Raising the paranoia level](#raise-the-paranoia-level-gradually)).

### `-crs-anomaly-threshold`

The score at which a request is blocked. Use it to trade detection for
false positives:

| Threshold | Effect |
|-----------|--------|
| `5` (default) | One critical rule, or two warnings, block a request |
| `10` | Two critical rules are needed; a single false positive cannot block, but neither can many real attacks with one obvious match |
| `3` or lower | A single warning blocks; strict and only practical after tuning |

The default is right for most deployments; prefer exclusions over a higher
threshold, because exclusions only affect the rule and the input that
cause the false positive. The threshold can also be raised for part of the
application only ([Per-path threshold](#raise-the-threshold-for-one-path)).

Requests below the threshold are not logged. To see how close legitimate
traffic comes to it, run in detection mode with `-crs-anomaly-threshold 1`
for a while; every request that matches any rule is then logged with its
score.

### `-crs-max-args`

The largest number of arguments a request may have: query parameters,
form fields, and the values in JSON and XML bodies. Requests with more are
rejected with `400 Bad Request` by rule 9500001, regardless of the anomaly
score.

Coraza stops collecting arguments at a fixed limit and never inspects the
rest, so without this check a payload placed after enough dummy arguments
would pass unnoticed. Raising the limit is not free either: every argument
costs about 0.1-0.25 ms of inspection, depending on the CPU. Keep the
default unless legitimate requests have more arguments, e.g. a JSON API
that accepts large arrays:

```sh
prismwaf -engine crs -crs-max-args 5000 -max-body 1048576
```

The audit log shows rejected requests as rule `9500001`.

### `-crs-rules-before` and `-crs-rules-after`

Load your own rules in ModSecurity's
[SecLang](https://coraza.io/docs/seclang/), mainly
[rule exclusions](https://coreruleset.org/docs/concepts/false_positives_tuning/)
for false positives. The rules are loaded in this order:

1. Coraza's recommended settings and the CRS setup
2. PrismWAF's settings from the flags (rules 900000, 900110, 9500001)
3. `-crs-rules-before` files
4. The CRS rules
5. `-crs-rules-after` files

| Flag | Put here | Examples |
|------|----------|----------|
| `-crs-rules-before` | Rules that run for each request, before the CRS rules: runtime exclusions with `ctl:` and changes to CRS `tx` variables | `ctl:ruleRemoveById`, `ctl:ruleRemoveTargetByTag`, `setvar:tx.allowed_methods=…` |
| `-crs-rules-after` | Directives that change CRS rules at startup, so the rules must already be loaded | `SecRuleRemoveById`, `SecRuleRemoveByTag`, `SecRuleUpdateTargetById`, `SecRuleUpdateTargetByTag` |

Rules about files:

- Both flags can be repeated and accept glob patterns, e.g.
  `-crs-rules-after '/etc/prismwaf/after.d/*.conf'`. Matching files are
  loaded in lexical order. A pattern that matches no file is an error, so a
  typo does not silently disable your exclusions.
- `Include` is not supported; list each file, or use a glob.
- Give your rules IDs below 100000. The CRS uses 900000-999999 and PrismWAF
  uses 9500001.
- A `-crs-rules-before` rule that sets `tx.blocking_paranoia_level` or
  `tx.inbound_anomaly_score_threshold` for every request overrides the
  flag; use the flags for global settings and rules for per-path ones.
- Rules are loaded at startup; restart PrismWAF to apply changes.

## Responses and audit events

| Outcome | Response | Audit `reason` |
|---------|----------|----------------|
| Score reaches the threshold | `403 Forbidden` | `crs` |
| Body cannot be parsed (rule 200002) | `400 Bad Request` | `crs` |
| Too many arguments (rule 9500001) | `400 Bad Request` | `crs` |
| Body larger than `-max-body` | `413 Request Entity Too Large` | `body_too_large` |
| Request line or headers over 64 KiB (plus a few KiB of margin from Go's HTTP server) | `431 Request Header Fields Too Large` | (not logged) |
| Internal error in the CRS engine | `500 Internal Server Error` (fail closed) | (operational log) |

In detection mode, the request is forwarded instead and logged with
`"action": "detect"`. The response body contains only the event ID.

A CRS event contains all rules that matched, which is what you need to
write an exclusion:

```json
{
  "id": "6b1f0e2c9d3a4b57",
  "action": "block",
  "reason": "crs",
  "rule": { "id": "941100", "category": "xss" },
  "match": { "location": "ARGS", "field": "json.content", "data": "…", "value": "<b onmouseover=alert(1)>hi</b>" },
  "crs": {
    "anomaly_score": 20,
    "deciding_rule": 949110,
    "rules": [
      { "id": 941100, "message": "XSS Attack Detected via libinjection", "severity": "critical", "variable": "ARGS:json.content", "value": "<b onmouseover=alert(1)>hi</b>" },
      { "id": 941120, "message": "XSS Filter - Category 2: Event Handler Vector", "severity": "critical", "variable": "ARGS:json.content", "value": "…" }
    ]
  },
  "request": { "method": "POST", "uri": "/cms/pages", "…": "…" }
}
```

- `rule` is the most severe matching rule, or the rule that rejected the
  request on its own (200002, 9500001). `category` comes from the rule's
  `attack-*` tag, e.g. `sqli`, `xss`, `rce`, `protocol`.
- `match.location` and `match.field` are the variable and key from the
  rule, e.g. `ARGS` and `json.content`, which is the name to use in an
  exclusion (`ARGS:json.content`). JSON values are named `json.` followed
  by their path: `{"user":{"name":…}}` is `ARGS:json.user.name`.
- `crs.rules` lists every rule that added to the score.

To find the rules that fire most often, by path, with
[jq](https://jqlang.github.io/jq/):

```sh
jq -r 'select(.reason == "crs") | .crs.rules[] as $r | [$r.id, $r.variable] | @tsv' audit.log | sort | uniq -c | sort -rn
jq -r 'select(.reason == "crs") | [.rule.id, (.request.uri | split("?")[0])] | @tsv' audit.log | sort | uniq -c | sort -rn
```

See [Audit log](audit-log.md) for all fields.

## Use cases

All examples below were tested with PrismWAF and CRS 4.25.0, and are
run by the end-to-end test `TestCRSExclusions` (see
[Testing](testing.md#owasp-core-rule-set)). Each one shows
the rule file and the command line; combine the rules into as many files
as you like.

### Roll out the CRS safely

Start in detection mode, collect real traffic, write exclusions for the
false positives, and block only once the remaining detections are attacks:

```sh
# 1. Log what the CRS would block
prismwaf -engine crs -mode detect -audit-log audit.log

# 2. Group the detections by rule and path (see above), write exclusions
#    into before.conf / after.conf, restart, repeat

# 3. Block
prismwaf -engine crs -mode block -audit-log audit.log \
  -crs-rules-before before.conf -crs-rules-after after.conf
```

To add the CRS to an existing deployment that already blocks with the
built-in signatures, use `-engine both` with `-mode detect` for step 1;
note that detection mode also stops the built-in signatures from blocking
during that time.

### Allow PUT, PATCH and DELETE for a REST API

The CRS only allows `GET`, `HEAD`, `POST` and `OPTIONS` by default. Other
methods match rule 911100 (critical), so a REST API is blocked:

```sh
curl -X DELETE http://localhost:8080/api/items/1   # 403, rule 911100
```

```apache
# before.conf
SecAction "id:1000,phase:1,pass,nolog,\
    setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"
```

### Accept other content types

Bodies with a content type that is not in the CRS's list, such as
`text/plain`, match rule 920420 (critical). Set the full list, adding the
types you need:

```apache
# before.conf
SecAction "id:1001,phase:1,pass,nolog,\
    setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json| |text/plain|'"
```

### Accept HTML in one field of one endpoint

A CMS accepts HTML in the `content` field of `/cms/` requests, which the
XSS rules (941xxx) flag. Exclude only that field, only for that path:

```apache
# before.conf
SecRule REQUEST_FILENAME "@beginsWith /cms/" \
    "id:1002,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=attack-xss;ARGS:json.content"
```

| Request | Result |
|---------|--------|
| `POST /cms/pages` with `{"content":"<b onmouseover=…>"}` | Allowed |
| `POST /cms/pages` with `{"title":"<b onmouseover=…>"}` | Blocked: other fields are still inspected |
| `POST /api/pages` with `{"content":"<b onmouseover=…>"}` | Blocked: other paths are still inspected |

Other rules, e.g. SQL injection, still inspect the field. For a form
field, the name is just the field name (`ARGS:content`).

### Exclude a parameter everywhere

Passwords contain arbitrary characters and often trigger the SQL injection
rules. Exclude the `password` field from them for all paths:

```apache
# after.conf
SecRuleUpdateTargetByTag "attack-sqli" "!ARGS:password"
```

`SecRuleUpdateTargetById 942100 "!ARGS:password"` does the same for a
single rule. Both directives change the loaded rules, so they belong in
`-crs-rules-after`.

### Disable a rule

If a rule does not suit your application at all, remove it. For example,
rule 920350 (warning) flags requests whose `Host` header is an IP address,
which is normal for health checks of internal services:

```apache
# after.conf
SecRuleRemoveById 920350
```

To disable a rule for some paths only, use `ctl:ruleRemoveById` in
`-crs-rules-before` instead:

```apache
# before.conf
SecRule REQUEST_FILENAME "@beginsWith /search" \
    "id:1003,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
```

### Let an internal security scanner through

Vulnerability scanners identify themselves in the `User-Agent` header,
which rule 913100 (critical) blocks. Allow your own scanner by its IP
address only:

```apache
# before.conf
SecRule REMOTE_ADDR "@ipMatch 10.0.0.50" \
    "id:1004,phase:1,pass,nolog,ctl:ruleRemoveById=913100"
```

`REMOTE_ADDR` is the client IP as PrismWAF determines it, so behind a load
balancer set `-trusted-proxies` (see [Client IP](audit-log.md#client-ip)).
The scanner's attack payloads are still detected. To let them reach the
backend as well, replace `ctl:ruleRemoveById=913100` with
`ctl:ruleEngine=DetectionOnly`; the scanner's requests are then neither
blocked nor logged by the CRS.

### Raise the threshold for one path

A legacy part of the application produces too many false positives to fix
now. Instead of raising the threshold globally, raise it for that path:

```apache
# before.conf
SecRule REQUEST_FILENAME "@beginsWith /legacy/" \
    "id:1005,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=10"
```

A request with one critical match (score 5) now passes on `/legacy/` and
is still blocked elsewhere.

### Raise the paranoia level gradually

For a high-value application such as an admin portal or a payment API,
move up one level at a time:

```sh
# Run PL2 in detection mode next to the PL1 deployment, or briefly instead of it
prismwaf -engine crs -crs-paranoia-level 2 -mode detect -audit-log pl2.log \
  -crs-rules-before before.conf -crs-rules-after after.conf

# After tuning the new false positives, block at PL2
prismwaf -engine crs -crs-paranoia-level 2 \
  -crs-rules-before before.conf -crs-rules-after after.conf
```

Keep the exclusions from the lower level; they still apply.

### Protect a JSON API with large requests

A JSON API receives documents of up to 1 MiB with up to 3,000 values. The
CRS cost grows with the body size and the number of values (see
[Performance](#performance)), so raise only the limits you need and
protect the CPU with a rate limit in front of PrismWAF:

```sh
prismwaf -engine both -max-body 1048576 -crs-max-args 3000
```

For APIs with very large bodies and tight latency budgets, `-engine
builtin` is often the better choice.

## Performance

The CRS is much more thorough than the built-in signatures, and much more
expensive. Coraza runs every rule with Go's linear-time regular expression
engine, which is safe from ReDoS but slow on large inputs. CPU time per
request at paranoia level 1:

| Request | Built-in | CRS |
|---------|---------:|----:|
| Typical `GET` | 0.02 ms | 0.6 ms |
| 128 KiB JSON body | 14 ms | 260 ms |
| 128 KiB body of other types (worst case) | 110 ms | 750 ms |
| 1000 arguments | — | about 110 ms |

The figures depend on the CPU: on a 2-vCPU ARM machine, the end-to-end
tests measured about 0.25 ms per argument, e.g. 250 ms for a 19 KiB JSON
body with 900 values, and 1 ms for a typical `GET`
(see [Testing](testing.md#results-1)).

Inspection time grows linearly with the body size: with `-max-body 32768`
the worst case is about a quarter of the above. Higher paranoia levels run
more rules and take longer. Recommendations:

- Lower `-max-body` to what your application needs.
- Limit request rates per client in front of PrismWAF, so that a client
  cannot use large requests to exhaust the CPU.
- Keep `-crs-max-args` low.
- Loading the CRS takes about 50 ms at startup.

## Limitations

- Responses are not inspected; the `RESPONSE-*` rules are not loaded.
- Rule files are read at startup; `SIGHUP` reloads certificates, not
  rules.
- Requests below the threshold are not logged, so the CRS's detection
  paranoia level (`tx.detection_paranoia_level`, which scores rules above
  the blocking level without blocking) has no visible effect.
