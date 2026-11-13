# Testing

PrismWAF has two kinds of tests:

- **Unit tests** next to the code (`go test ./...`). They test each package
  with fakes: a fake DNS resolver, a fake `siteverify` API, a fixed clock.
- **End-to-end (E2E) tests** in [`e2e/`](../e2e). They build the
  `prismwaf` binary, start it with command-line flags in front of a test
  backend, and send it real HTTP requests, with a cookie jar like a
  browser. Some also drive headless Chromium. So far they cover
  [bot protection](bot-protection.md).

```sh
go test ./...                                      # unit tests
go test -tags e2e ./e2e/                           # E2E tests, ~5s without a browser
PRISMWAF_E2E_LIVE=1 go test -tags e2e -v ./e2e/   # also with real DNS and CAPTCHA providers
```

The E2E tests have the `e2e` build tag, so `go test ./...` skips them.

## Requirements

| Tests | Needs | Without it |
|-------|-------|------------|
| HTTP tests (`TestBot*`, `TestCaptcha*`) | Go | — |
| Browser tests (`TestBrowser*`) | Chromium or Chrome, Node.js 22 or later | Skipped |
| Live tests (`TestLive*`) | `PRISMWAF_E2E_LIVE=1`, Internet access, a browser for `TestLiveCaptcha` | Skipped |

The browser is found as `chromium`, `chromium-browser`, `google-chrome` or
`google-chrome-stable` in `PATH`, or set with `PRISMWAF_E2E_CHROME`. The
tests start it headless with `--no-sandbox` and drive it through the
DevTools protocol with [`e2e/browser/cdp.mjs`](../e2e/browser/cdp.mjs).

## How the E2E tests work

```
 test client ──► prismwaf (the built binary, with flags) ──► test backend
 (HTTP, cookie jar,   │                                      (answers with the
  X-Forwarded-For)    │ HTTPS_PROXY + SSL_CERT_FILE           bot headers it got)
                      ▼
               fake siteverify API
               (Turnstile, hCaptcha, reCAPTCHA URLs)
```

- **One binary, many processes.** `TestMain` builds `prismwaf` once; each
  test starts its own process with its own flags, audit log file and
  backend, and stops it at the end. On failure, the test prints the
  process's log.
- **Many clients.** prismwaf runs with `-trusted-proxies 127.0.0.1`, so
  that each simulated client sets its own address in `X-Forwarded-For`.
- **The backend** answers with the `X-PrismWAF-Bot-*` headers it received,
  so the tests see what an application behind PrismWAF sees.
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

## What is tested

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

## Results

Run on 2026-11-13 on Linux (aarch64) with Go 1.25.0, Chromium 156
(headless) and Node.js 22.13.1, with `PRISMWAF_E2E_LIVE=1`:

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

### Mutation check

To check that the tests catch regressions, these changes were made to the
code one at a time; each was caught by the HTTP tests, and the code was
restored:

| Change | Failing tests |
|--------|--------------:|
| CAPTCHA host name not checked | 5 |
| Clearance cookie not bound to the `User-Agent` | 13 |
| `-bot-allow-category` ignored | 3 |
| No CAPTCHA tier (`-bot-captcha-score` ignored) | 6 |
| `X-PrismWAF-Bot-Verified` from the client passed to the backend | 3 |
| No `Content-Security-Policy` on the challenge page | 4 |

### Problems found and fixed

| Problem | Found by | Fix |
|---------|----------|-----|
| `-bot-*` flags without `-bot-protection` were rejected only if their value differed from the zero value, so `-bot-difficulty`, `-bot-challenge-score`, `-bot-block-score`, `-bot-clearance-ttl` and `-bot-verify` were silently ignored; likewise `-bot-captcha-min-score` without `-bot-captcha` | `TestBotInvalidFlags` | Every `-bot-*` flag given on the command line now requires `-bot-protection`, and every `-bot-captcha-*` flag requires `-bot-captcha` |
| The reCAPTCHA v2 widget was blocked by the challenge page's CSP when it connected to `https://www.google.com/recaptcha/api2/clr`; solving still worked, but the browser reported CSP violations | `TestLiveCaptcha/recaptcha` | `connect-src https://www.google.com/recaptcha/` added for reCAPTCHA v2 |

### Not covered

- reCAPTCHA v3 with the real provider: Google offers no test keys for it.
  It is covered with the fake `siteverify` API.
- Image challenges of hCaptcha and reCAPTCHA, which the test keys never
  show.
- Clearance cookie expiry, as `-bot-clearance-ttl` is at least a minute;
  the unit tests cover it with a fixed clock.
- Behavior behind a real CDN or load balancer; the tests use
  `X-Forwarded-For` from 127.0.0.1.
