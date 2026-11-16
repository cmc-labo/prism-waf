# Testing

PrismWAF has two kinds of tests:

- **Unit tests** next to the code (`go test ./...`). They test each package
  with fakes: a fake DNS resolver, a fake `siteverify` API, a fixed clock.
- **End-to-end (E2E) tests** in [`e2e/`](../e2e). They build the
  `prismwaf` binary, start it with command-line flags in front of a test
  backend, and send it real HTTP requests. Some also drive headless
  Chromium.

| Feature | E2E tests | Results |
|---------|-----------|---------|
| [Bot protection](bot-protection.md) | [`bot_test.go`, `captcha_test.go`, `browser_test.go`, `live_test.go`](#bot-protection) | [2026-11-13](#results) |
| [OWASP Core Rule Set](crs.md) | [`crs_test.go`](#owasp-core-rule-set) | [2026-11-14](#results-1) |
| [ACME expiry notifications](acme.md#expiry-notifications) | [`acme_test.go`, `acmeca_test.go`](#acme-expiry-notifications) | [2026-11-15](#results-2) |

```sh
go test ./...                                      # unit tests
go test -tags e2e ./e2e/                           # E2E tests, ~4 minutes
go test -tags e2e -short ./e2e/                    # without the tests that wait for timers, ~35s
go test -tags e2e -run 'TestCRS' ./e2e/            # E2E tests of one feature
PRISMWAF_E2E_LIVE=1 go test -tags e2e -v ./e2e/   # also with real DNS and CAPTCHA providers
```

The E2E tests have the `e2e` build tag, so `go test ./...` skips them.

- [Requirements](#requirements)
- [How the E2E tests work](#how-the-e2e-tests-work)
- [Bot protection](#bot-protection)
- [OWASP Core Rule Set](#owasp-core-rule-set)
- [ACME expiry notifications](#acme-expiry-notifications)

## Requirements

| Tests | Needs | Without it |
|-------|-------|------------|
| HTTP tests (`TestBot*`, `TestCaptcha*`, `TestCRS*`, `TestACME*`, `TestNotify*`) | Go, `sh` | — |
| Browser tests (`TestBrowser*`) | Chromium or Chrome, Node.js 22 or later | Skipped |
| Live tests (`TestLive*`) | `PRISMWAF_E2E_LIVE=1`, Internet access, a browser for `TestLiveCaptcha` | Skipped |
| `TestLiveWebhook` | `PRISMWAF_E2E_WEBHOOK` (a webhook URL) and `PRISMWAF_E2E_WEBHOOK_FORMAT` | Skipped |

The browser is found as `chromium`, `chromium-browser`, `google-chrome` or
`google-chrome-stable` in `PATH`, or set with `PRISMWAF_E2E_CHROME`. The
tests start it headless with `--no-sandbox` and drive it through the
DevTools protocol with [`e2e/browser/cdp.mjs`](../e2e/browser/cdp.mjs).

## How the E2E tests work

```
 test client ──► prismwaf (the built binary, with flags) ──► test backend
 (HTTP, cookie jar,   │                                      (answers with what
  X-Forwarded-For)    │ HTTPS_PROXY + SSL_CERT_FILE           it received)
                      ▼
               fake siteverify API
               (Turnstile, hCaptcha, reCAPTCHA URLs)
```

- **One binary, many processes.** `TestMain` builds `prismwaf` once; each
  test starts its own process with its own flags, audit log file and
  backend, and stops it at the end. On failure, the test prints the
  process's log.
- **The test backend** answers with the method, URI and body it received
  and the `X-PrismWAF-Bot-*` headers, so the tests see what an application
  behind PrismWAF sees, and that allowed requests arrive unchanged.
- **The audit log** is read back after each blocked request: the event ID
  in the response must lead to an event with the expected reason, rule and
  details.
- **Many clients.** Where the client address matters, prismwaf runs with
  `-trusted-proxies 127.0.0.1`, so that each simulated client sets its own
  address in `X-Forwarded-For`.
- **Clients** have a cookie jar, do not follow redirects, and send only the
  headers of the test (no automatic `Accept-Encoding`), so that every
  request is seen as sent.

## Bot protection

```sh
go test -tags e2e -run 'TestBot|TestCaptcha|TestBrowser|TestLive' ./e2e/
```

How the bot protection tests reach their dependencies:

- **Proof of work** is solved in Go, with the same SHA-256 search as the
  page's JavaScript; the browser tests run the JavaScript itself.
- **CAPTCHAs without the providers.** The binary calls the real
  `siteverify` URLs. The test sets `HTTPS_PROXY` to a proxy that connects
  every host to a fake API, and `SSL_CERT_FILE` to a test CA that signed the
  fake API's certificate for `challenges.cloudflare.com`,
  `api.hcaptcha.com` and `www.google.com`. The fake answers depending on
  the solution token (`pass`, `fail`, `other-site`, `bad-secret`, `down`,
  `low-score`, `wrong-action`) and records what PrismWAF sent.
- **CAPTCHAs with the providers** (live). Chromium maps the host names that
  the providers' test keys are for (`example.com`, `dummy-key-pass`,
  `testkey.google.com`) to 127.0.0.1 with `--host-resolver-rules`, loads
  the real widget, and clicks its checkbox.

### Bot score, categories and challenges (`e2e/bot_test.go`)

| Test | Checks |
|------|--------|
| `TestBotProtection/browsers_pass` | A request with browser headers reaches the backend with score 0, category `browser`, verified `false` |
| `…/bot_headers_from_clients_are_replaced` | `X-PrismWAF-Bot-*` headers sent by clients are overwritten |
| `…/proof_of_work` | Challenge page: status 403, form with token and the original URL with its query, CSP with a nonce that matches the script, `worker-src blob:`, `frame-ancestors 'none'`, `Cache-Control: no-store`, `X-Robots-Tag: noindex`. A wrong nonce gets the failure page and no cookie. The right one gets `303` to the original URL and a cookie that is `HttpOnly`, not `Secure` over HTTP, `SameSite=Lax`, `Path=/`, 24 hours; the cookie then works on the whole site |
| `…/clearance_is_bound_to_the_client_and_User-Agent` | The cookie is rejected from another address or `User-Agent`; IPv6 clients share it within a /64 and not across /64s |
| `…/challenges_are_bound_to_the_client` | A solved token is rejected from another address or `User-Agent`; a token whose difficulty was edited is rejected |
| `…/forged_cookies_are_rejected` | Cookies with an edited level (proof of work → CAPTCHA), edited expiry or MAC, or an empty value are rejected |
| `…/redirects_stay_on_the_site` | `//evil.example/x`, `https://evil.example/`, `/\evil.example`, `javascript:` redirect to `/` |
| `…/other_methods_and_HEAD` | `POST` without a cookie gets a plain 403 (no page), `HEAD` gets 403 without a body, `GET` of the verify path gets 405; `POST` works with a cookie |
| `…/exemptions` | `/robots.txt`, `/favicon.ico`, `/.well-known/*`, `-bot-exempt-path /api/*` and `-bot-exempt` addresses are not challenged; `/apix` and `/api/../admin` are |
| `…/categories` | `-bot-block-category scanner,ai_crawler` blocks sqlmap and GPTBot with a plain 403 and a `block` audit event with the category, but not on exempt paths; `-bot-allow-category monitoring` lets UptimeRobot through |
| `…/clearance_does_not_bypass_inspection` | A client with a clearance cookie is still blocked by the signatures (SQL injection) |
| `…/audit_events` | The challenge event has reason `bot`, action `challenge`, score, signals, category, `challenge: pow` and the client network; five challenges in a minute give one event and one event ID |
| `…/concurrent_clients` | 20 clients solving challenges at the same time |
| `TestBotBlockScore` | `-bot-block-score 80` blocks a score of 80 with a plain 403 and challenges 60 |
| `TestBotPaths` | `-bot-path /search -bot-path /articles/*` protects `/search`, `/articles`, `/articles/…` and nothing else |
| `TestBotHTTPS` | Over HTTPS, missing fetch metadata and client hints add 40 points, and the cookie is `Secure` |
| `TestBotSharedSecret` | Instances with the same `-bot-secret-file` accept each other's cookies; an instance with a random key does not |
| `TestBotFakeGooglebot` | Googlebot's `User-Agent` from a non-Google address scores 90 with `fake_bot` and is challenged; with `-bot-verify=false` it scores 50 |
| `TestBotInvalidFlags` | prismwaf refuses to start with invalid or inconsistent `-bot-*` flags, with an error that names the problem |

### CAPTCHA (`e2e/captcha_test.go`)

`TestCaptcha` runs for each provider (`turnstile`, `hcaptcha`, `recaptcha`,
`recaptcha-v3`) with `-bot-captcha-score 70`:

- The same `User-Agent` scoring 60 gets the proof of work and, scoring 80,
  the CAPTCHA, even with a proof-of-work cookie.
- The CAPTCHA page has the provider's widget and site key (or, for v3, the
  `grecaptcha.execute` call), loads the provider's script, and its CSP
  allows the provider's domains with a nonce that matches the script.
- The audit event has `challenge: captcha`.
- Rejected solutions: not solved; for another host name; wrong secret;
  provider returns 503; for v3, score below `-bot-captcha-min-score` and
  wrong action. Each gets "The CAPTCHA could not be verified" without a
  cookie. Only the problems that affect every user (host name, secret,
  provider) are logged as `WARN`.
- An empty solution is rejected without calling the provider.
- A solution is sent to the provider's URL (checked through the proxy's
  `CONNECT` target) with the secret from `-bot-captcha-secret-file`
  (without the newline), the token and the client address, plus the site
  key for hCaptcha only.
- The CAPTCHA cookie lets the client through at both scores, and is bound
  to the client address.

`TestCaptchaProviderUnreachable` checks that nobody passes while the
provider cannot be reached, and that a `WARN` names the cause.

### Browser (`e2e/browser_test.go`)

| Test | Checks |
|------|--------|
| `TestBrowserProofOfWork` | Headless Chromium (`HeadlessChrome`, score 60) solves the proof of work at the default difficulty 18 in its Web Workers, over HTTP and HTTPS: challenge (403), solution (303), page (200) with the original URL; the next page loads directly (200). No JavaScript errors or CSP violations |
| `TestLiveCaptcha` (live) | Turnstile, hCaptcha and reCAPTCHA v2 with the providers' test keys: the real widget loads, is solved (with a click on the checkbox for hCaptcha and reCAPTCHA), and the client reaches the original URL with no JavaScript errors or CSP violations. The same keys on `127.0.0.1` are rejected as made for another host name, with a `WARN` |

### Live DNS (`e2e/live_test.go`)

`TestLiveVerifiedBots` verifies Googlebot (66.249.66.1) and Bingbot
(157.55.39.1) with real reverse and forward DNS lookups: they reach the
backend with verified `true` and category `search_engine`. The same
`User-Agent`s from 203.0.113.9 are challenged. The addresses come from
the operators' published ranges; if the test fails, check that they still
resolve, e.g. `host 66.249.66.1`.

### Results

Run on 2026-11-13 on Linux (aarch64, 2 vCPUs) with Go 1.25.0, Chromium
156 (headless) and Node.js 22.13.1, with `PRISMWAF_E2E_LIVE=1`:

| Test | Subtests | Result | Time |
|------|---------:|--------|-----:|
| `TestBotProtection` | 13 | Pass | 0.05s |
| `TestBotBlockScore`, `TestBotPaths`, `TestBotHTTPS`, `TestBotSharedSecret`, `TestBotFakeGooglebot`, `TestBotInvalidFlags` | — | Pass | 0.4s |
| `TestCaptcha` | 4 | Pass | 0.3s |
| `TestCaptchaProviderUnreachable` | — | Pass | 0.02s |
| `TestBrowserProofOfWork` | 2 | Pass | 8.5s |
| `TestLiveCaptcha` | 3 | Pass | 48s |
| `TestLiveVerifiedBots` | — | Pass | 0.5s |

The whole run took 59 seconds; without the live tests, it takes about 12
seconds, most of it starting Chromium. `go test -race -count=3` of the E2E
tests passed as well.

Measured in the browser tests:

| Page | Documents | Time |
|------|-----------|-----:|
| Proof of work, difficulty 18, HTTP | 403 → 303 → 200 | 230ms |
| Proof of work, difficulty 18, HTTPS | 403 → 303 → 200 | 455ms |
| Next page with the clearance cookie | 200 | 110-130ms |
| Turnstile (test keys) | 403 → 303 → 200 | 2.7s |
| hCaptcha (test keys, click) | 403 → 303 → 200 | 2.9s |
| reCAPTCHA v2 (test keys, click) | 403 → 303 → 200 | 10.2s |

The proof-of-work time depends on the machine and the browser's number of
cores; the times of the CAPTCHAs are mostly the providers' scripts loading
over the network.

**Mutation check.** To check that the tests catch regressions, these
changes were made to the code one at a time; each was caught by the HTTP
tests, and the code was restored:

| Change | Failing tests |
|--------|--------------:|
| CAPTCHA host name not checked | 5 |
| Clearance cookie not bound to the `User-Agent` | 13 |
| `-bot-allow-category` ignored | 3 |
| No CAPTCHA tier (`-bot-captcha-score` ignored) | 6 |
| `X-PrismWAF-Bot-Verified` from the client passed to the backend | 3 |
| No `Content-Security-Policy` on the challenge page | 4 |

**Problems found and fixed:**

| Problem | Found by | Fix |
|---------|----------|-----|
| `-bot-*` flags without `-bot-protection` were rejected only if their value differed from the zero value, so `-bot-difficulty`, `-bot-challenge-score`, `-bot-block-score`, `-bot-clearance-ttl` and `-bot-verify` were silently ignored; likewise `-bot-captcha-min-score` without `-bot-captcha` | `TestBotInvalidFlags` | Every `-bot-*` flag given on the command line now requires `-bot-protection`, and every `-bot-captcha-*` flag requires `-bot-captcha` |
| The reCAPTCHA v2 widget was blocked by the challenge page's CSP when it connected to `https://www.google.com/recaptcha/api2/clr`; solving still worked, but the browser reported CSP violations | `TestLiveCaptcha/recaptcha` | `connect-src https://www.google.com/recaptcha/` added for reCAPTCHA v2 |

**Not covered:**

- reCAPTCHA v3 with the real provider: Google offers no test keys for it.
  It is covered with the fake `siteverify` API.
- Image challenges of hCaptcha and reCAPTCHA, which the test keys never
  show.
- Clearance cookie expiry, as `-bot-clearance-ttl` is at least a minute;
  the unit tests cover it with a fixed clock.
- Behavior behind a real CDN or load balancer; the tests use
  `X-Forwarded-For` from 127.0.0.1.

## OWASP Core Rule Set

```sh
go test -tags e2e -run 'TestCRS' -v ./e2e/
```

The tests send requests with the headers of a browser and the host name
`app.example`: a numeric `Host` such as `127.0.0.1` matches rule 920350
(3 points), which the tests use on purpose only where they test it.

### What is tested (`e2e/crs_test.go`)

| Test | Checks |
|------|--------|
| `TestCRSDefaults` | At the defaults (`-engine crs`), 15 attacks are blocked with `403`, a `crs` audit event with the expected category, rule and field, deciding rule 949110, an anomaly score of at least 5 and the matched rules: SQL injection in the query, a form, nested JSON (`json.user.name`), multipart and a cookie; `UNION SELECT`; XSS in the query and JSON (`json.comment`); path traversal (`lfi`); command injection and Log4Shell (`rce`); PHP injection in XML; SQL injection and XSS in XML that is not well-formed; sqlmap's `User-Agent` (rule 913100). 9 normal requests reach the backend with their body unchanged and are not logged: a page with a query, a search with apostrophes, Japanese text, a form, JSON (small and 19 KiB), XML, multipart, `OPTIONS`. The response contains only the event ID. The startup log names CRS 4.25.0 and the settings |
| `TestCRSRejections` | With `-crs-max-args 20 -max-body 4096`: invalid JSON, XML and multipart get `400` with rule 200002, an unterminated multipart body rule 200003; 20 arguments pass, 21 (in a form, in the query and body together, or as a JSON array) get `400` with rule 9500001; a body of exactly 4096 bytes passes, a larger one gets `413` (`body_too_large`); `DELETE` gets `403` (rule 911100), a `text/plain` body `403` (rule 920420); a 60 KiB header passes, 100 KiB gets `431` and is not logged, on a new and on a reused connection |
| `TestCRSDetectMode` | With `-mode detect`, attacks reach the backend with their body, and each is logged with `"action": "detect"` |
| `TestCRSAnomalyThreshold` | Threshold 3: a numeric `Host` (one warning, score 3, rule 920350) is blocked, a host name is not. Threshold 5: the numeric `Host` passes, `DELETE` (one critical rule) is blocked. Threshold 10: `DELETE` passes, `UNION SELECT` (several rules) is blocked |
| `TestCRSParanoiaLevel` | 12 times `'(` in a parameter passes at level 1 and is blocked at level 2 by rule 942430. At level 2, the clean requests pass except the known false positives below |
| `TestCRSExclusions` | Every use case of [OWASP Core Rule Set](crs.md#use-cases), with the rule files from the documentation (`-crs-rules-before` file, `-crs-rules-after` glob of two files) and threshold 3: `PUT`, `PATCH`, `DELETE` and `text/plain` allowed; HTML allowed in `json.content` on `/cms/` only, while `json.title`, `/api/` and SQL injection in the same field are still blocked; `password` excluded from the SQL injection rules but `user` not; rule 920350 removed (a numeric `Host` passes at threshold 3); rule 942100 removed on `/search` only; sqlmap allowed from 10.0.0.50 (`X-Forwarded-For`), but not from 10.0.0.51, and its payloads still blocked; threshold 10 on `/legacy/` only |
| `TestCRSEngineBoth` | With `-engine both`, SQL injection is blocked by the built-in signatures and logged once with `"reason": "signature"`; `DELETE` and `text/plain`, which only the CRS checks, are blocked with `"reason": "crs"`; the clean requests pass; three requests, three events |
| `TestCRSConcurrent` | 32 clients sending 320 requests at once, half attacks and half clean; each gets the right status and audit event |
| `TestCRSInvalidFlags` | prismwaf refuses to start with an unknown `-engine`, paranoia level 5, a negative threshold or argument limit, `-crs-rules-*` without the CRS, a glob that matches no file, `Include` in a rule file, or an unknown directive, with an error that names the problem and, for rule files, the file |
| `TestCRSLatency` | Measures the latency through the binary with each engine; see below |

### Results

Run on 2026-11-14 on Linux (aarch64, 2 vCPUs) with Go 1.25.0:

| Test | Result | Time |
|------|--------|-----:|
| `TestCRSDefaults` | Pass | 0.2s |
| `TestCRSRejections` | Pass | 0.9s |
| `TestCRSDetectMode` | Pass | 0.1s |
| `TestCRSAnomalyThreshold` | Pass | 0.2s |
| `TestCRSParanoiaLevel` | Pass | 0.3s |
| `TestCRSExclusions` | Pass | 0.1s |
| `TestCRSEngineBoth` | Pass | 0.2s |
| `TestCRSConcurrent` | Pass | 1.3s |
| `TestCRSInvalidFlags` | Pass | 0.1s |
| `TestCRSLatency` | Pass | 11s |

`go test -race` and 10 repeated runs of `TestCRSConcurrent` passed as well.

**Latency.** Time from sending a request to receiving the backend's
response through prismwaf, over 21 requests on a reused connection, at
paranoia level 1:

| Request | `builtin` | `crs` | `both` |
|---------|----------:|------:|-------:|
| Typical `GET` (`/products?category=books&sort=price&page=2`) | 0.24 ms | 0.97 ms | 0.87 ms |
| 19 KiB JSON body with 900 values | 3.3 ms | 253 ms | 252 ms |

(Medians; the 90th percentiles were up to twice as high for the `GET` and
about 10% higher for the JSON body.) The CRS's cost grows with the number
of values in the body, about 0.25 ms per value on this machine; see
[Performance](crs.md#performance).

**False positives at paranoia level 2** among the normal requests of the
tests, which are worth an exclusion before blocking at level 2:

| Request | Rule |
|---------|------|
| `?q=O'Brien's pub` | 932240 (command injection evasion) |
| JSON with `"O'Brien's item"` | 932240 |
| JSON with `"note":"gift wrap, please"` | 942200 (SQL comment or space obfuscation) |

**Mutation check.** These changes to the code were each caught by the
tests, and the code was restored:

| Change | Failing tests |
|--------|--------------:|
| Coraza's body limit at `-max-body` again (the bug below) | 2 |
| `-crs-rules-before` files not loaded | 12 |
| Argument limit not enforced | 4 |
| `-crs-anomaly-threshold` ignored | 2 |
| `-crs-paranoia-level` ignored | 2 |
| Request body not passed to the CRS | 99 |

**Problems found and fixed:**

| Problem | Found by | Fix |
|---------|----------|-----|
| With `-engine crs` or `both`, a body of exactly `-max-body` bytes was rejected with `413`, while `-max-body` allows it (and `-engine builtin` did). Coraza rejects a body that *reaches* its limit | `TestCRSRejections` | Coraza's limit is now one byte above `-max-body`, which PrismWAF enforces itself |
| An error in a `-crs-rules-*` file did not say which file it was in, e.g. `unknown directive "secnosuchdirective"` | `TestCRSInvalidFlags` | The error now starts with the file name |

**Findings that need no change**, now documented in
[OWASP Core Rule Set](crs.md):

- Coraza's XML parser accepts XML that is not well-formed, such as
  unclosed elements or plain text, without rule 200002; only mismatched
  tags are rejected. The body is still inspected as a whole: SQL injection
  and XSS in such bodies are blocked.
- An unterminated multipart body is rejected by rule 200003 (strict
  multipart validation), not 200002.
- Go's limit on the request line and headers is 64 KiB plus a margin of
  4 KiB, and a little more on a reused connection: a 70 KiB header passed
  on a reused connection, 100 KiB did not.

**Not covered:**

- Paranoia levels 3 and 4 and the false positives they bring.
- The `500` response when the CRS engine fails, which cannot be caused from
  outside.
- Large bodies near the default `-max-body` of 128 KiB; the latency of
  bodies of this size is in [Performance](crs.md#performance).

## ACME expiry notifications

```sh
go test -tags e2e -run 'TestACME|TestNotify' -v ./e2e/
```

The tests run prismwaf with `-acme-domains` against a fake ACME CA, and
check the [expiry notifications](acme.md#expiry-notifications) that arrive
at a real webhook endpoint (an HTTP server in the test) and from a real
command (a shell script):

```
 fake ACME CA ◄─── ACME (RFC 8555) ───── prismwaf ── POST ──► webhook endpoint
 (acmeca_test.go)                         │    ▲               (records the body
      │                                   │    │                and headers)
      └── validates TLS-ALPN-01 / HTTP-01 ─────┘
                                          └── sh -c ──► command (records stdin
                                                        and PRISMWAF_* variables)
```

- **The fake CA** implements the ACME protocol as prismwaf's ACME library
  uses it: directory, nonces, account, orders, authorizations,
  challenges, finalization and certificate download. It validates the
  challenges for real, TLS-ALPN-01 with a handshake on `-listen` and
  HTTP-01 with a request to `-http-redirect`, and issues certificates
  from its own root. JWS signatures are not checked. A mode makes it fail:
  validation fails as if it could not connect (`connection` problem), new
  orders are rejected (`rejectedIdentifier`), or every request gets `503`.
- **Certificates in the cache** are written by the test in the format of
  the ACME library, with any validity period, as if prismwaf had obtained
  them before. This is how a certificate close to expiry is set up without
  waiting weeks.
- **Timers are not shortened.** prismwaf checks certificates at startup
  and then every minute, and retries notifications after 10 seconds and a
  minute; the tests wait for them. These tests are skipped with `-short`
  and run in parallel with each other, which adds about two minutes.

### What is tested (`e2e/acme_test.go`)

| Test | Checks |
|------|--------|
| `TestACMECertificate` | A certificate is obtained with TLS-ALPN-01, and with HTTP-01 when the CA offers only that; it is served with its chain and verifies against the CA, HTTPS requests reach the backend, other requests to `-http-redirect` get `308` to HTTPS. No notification and no warning is logged for a valid certificate. After a restart, the cached certificate is served without a new order |
| `TestACMENotifyUnavailable` | The CA cannot validate two domains: each gets `certificate_unavailable` (`critical`) at the webhook (`json`) and from the command, with `failures` 1, `retry_at` 10 minutes later, the error with the CA's reason (`Timeout during connect`), the message and `text`; the command gets the event on standard input (without `text`) and in `PRISMWAF_*` variables. The CA's reason is logged as `ACME validation failed` with a hint. Client handshakes fail and do not make prismwaf contact the CA again during the backoff; nothing is notified twice |
| `TestACMENotifyCommandIsNotInjected` | The CA rejects the order with a detail containing `$(touch …)`, backticks and `;`. A command that uses `$PRISMWAF_ERROR` and `$PRISMWAF_MESSAGE` (also unquoted) gets the detail as text, and nothing in it is run. The `slack` webhook gets only `{"text": …}` |
| `TestACMENotifyExpiring` | A cached certificate with 10 days left of 90 and a CA that cannot validate: renewal is attempted at once and fails, without a notification; at the next check, a minute later, `certificate_expiring` (`warning`) with the issuer, serial and `not_after` of the certificate, as `{"content": …}` to the `discord` webhook and to the command (`PRISMWAF_NOT_AFTER`). The old certificate keeps being served |
| `TestACMERenewalAtStartup` | The same certificate and a CA that works: it is renewed at once, and nothing is notified or warned, also at the next check |
| `TestACMENotifyExpired` | A certificate that expires 70 seconds after startup and is not renewed: `certificate_expiring` at the second check, `certificate_expired` (`critical`) a minute later, logged at once as `ACME certificate expired`. Clients then get the expired certificate |
| `TestNotifyRetry` | The webhook answers `503`, then `502`: the failures are logged with the status and the response body, retried after 10 seconds and a minute, and the notification arrives with the third attempt, 70 seconds after the first |
| `TestNotifyFailure` | The webhook and the command (exit status 3, a message on standard error) always fail: each is tried three times, and the failure is logged with the response or the output, and the message that was not delivered |
| `TestNotifyTargetsAreIndependent` | The webhook does not answer: the command is still run at once, prismwaf keeps serving HTTPS for another domain, and stops at once on `SIGTERM` |
| `TestNotifyTestFlag` | `-acme-notify-test` with each webhook format and a command, over HTTP and HTTPS (a webhook with a certificate from an unknown CA fails, and works once the CA is trusted with `SSL_CERT_FILE`). A `403`, a refused connection and a failing command each make prismwaf exit with an error that names the target and the reason |
| `TestNotifySecretsAreNotLogged` | A webhook URL with a token in the path, a password and a key in the query: neither the test output, the startup log nor the failure logs contain them |
| `TestNotifyInvalidFlags` | prismwaf refuses to start with notification flags without `-acme-domains`, `-acme-notify-test` without a target, a webhook URL that is not `http(s)://`, an unknown format, or `-acme-notify-webhook-format` without `-acme-notify-webhook`; the URL is not repeated in the error |
| `TestLiveWebhook` | With `PRISMWAF_E2E_WEBHOOK`, sends a test notification to a real service, e.g. a Slack or Discord channel |

`TestLiveWebhook` is not run by default, because it needs a webhook URL:

```sh
PRISMWAF_E2E_WEBHOOK=https://hooks.slack.com/services/… PRISMWAF_E2E_WEBHOOK_FORMAT=slack \
  go test -tags e2e -run TestLiveWebhook -v ./e2e/
```

### Results

Run on 2026-11-15 on Linux (aarch64, 2 vCPUs) with Go 1.25.0:

| Test | Result | Time |
|------|--------|-----:|
| `TestACMECertificate` | Pass | 2.2s |
| `TestACMENotifyUnavailable` | Pass | 0.7s |
| `TestACMENotifyCommandIsNotInjected` | Pass | 0.1s |
| `TestACMENotifyExpiring` | Pass | 60s |
| `TestACMERenewalAtStartup` | Pass | 65s |
| `TestACMENotifyExpired` | Pass | 120s |
| `TestNotifyRetry` | Pass | 70s |
| `TestNotifyFailure` | Pass | 70s |
| `TestNotifyTargetsAreIndependent` | Pass | 0.1s |
| `TestNotifyTestFlag` | Pass | 0.1s |
| `TestNotifySecretsAreNotLogged` | Pass | 0.1s |
| `TestNotifyInvalidFlags` | Pass | 0.1s |
| `TestLiveWebhook` | Not run (needs a webhook URL) | — |

The fast tests also passed 5 times in a row with `-race`. Measured
timings: a notification arrives within about 20 ms after the problem is
detected; with a webhook that fails twice, 70 seconds after the first
attempt; `certificate_expired` 60 seconds after `certificate_expiring`
(one check).

**Mutation check.** These changes to the code were each caught by the
tests, and the code was restored:

| Change | Failing tests |
|--------|--------------:|
| An overdue certificate reported at the first check again (the first bug below) | 2 |
| Targets served one after another again (the second bug below) | 1 |
| Expiry logged only an hour after the last warning again (the third bug below) | 1 |
| `-acme-notify-webhook-format` accepted without a webhook again | 1 |
| No `PRISMWAF_*` variables for the command | 6 |
| The CA's error appended to the command line (shell injection) | 1 |
| The webhook URL logged in full | 5 |
| The URL left in webhook connection errors | 3 |
| No retries | 2 |
| A worse problem not notified at once | 1 |
| The `slack` format sending the full event | 3 |
| The CA's reason left out of the notification's `error` | 1 |

The unit tests added with the fixes fail without them as well.

**Problems found and fixed:**

| Problem | Found by | Fix |
|---------|----------|-----|
| A cached certificate that was overdue for renewal at startup, e.g. after PrismWAF was stopped for some days, was reported as `certificate_expiring` (and logged as `ACME certificate not renewed yet`) at once, although the renewal started at the same moment and succeeded a few milliseconds later. A false alarm, followed a minute later by `certificate_recovered` | `TestACMERenewalAtStartup` | The first check after startup leaves overdue certificates to the renewal; they are reported at the next check if still not renewed. Expired certificates are not affected |
| Notifications were sent to the webhook and the command one after another. A webhook that did not answer delayed the command by up to about 100 seconds (three 10-second timeouts plus 70 seconds of retries) per notification, and the notifications behind it as well | `TestNotifyTargetsAreIndependent` | Each target has its own queue and worker |
| A certificate that expired less than an hour after the last `ACME certificate not renewed yet` warning was not logged as `ACME certificate expired` until that hour had passed, although it was notified at once | `TestACMENotifyExpired` | Expiry is logged at once, then hourly |
| `-acme-notify-webhook-format` without `-acme-notify-webhook` (e.g. with only a command) was silently ignored | `TestNotifyInvalidFlags` | It is now an error, like other options without the option they belong to |
| When the CA could not validate a domain, the notification's `error` was only the ACME library's generic `no viable challenge type found`; the CA's reason (e.g. `Timeout during connect`) was only in the log | `TestACMENotifyUnavailable` | `error` ends with `; validation:` and the CA's reasons |

**Findings that need no change:**

- Text from the CA reaches a command only through the environment and
  standard input, never the command line, so shell syntax in it is not
  run, even when the command uses the variable unquoted.
- On `SIGTERM`, a notification that is still being sent or retried is
  abandoned and logged as `notification failed` (`context canceled`);
  PrismWAF stops at once. Notifications are not kept across restarts, as
  documented in [Limitations](acme.md#limitations).

**Not covered:**

- The daily repetition of a notification and `certificate_recovered`,
  which need a day, or 10 to 60 minutes until the next attempt; the unit
  tests cover them with a fixed clock.
- The 30-second timeout of commands, and the limit of 100 waiting
  notifications.
- Rate limit responses of the CA, RSA certificates, and a real CA such as
  Let's Encrypt's staging environment.
- A real chat service, unless `TestLiveWebhook` is run with a URL.
