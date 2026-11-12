# Bot protection

PrismWAF can tell browsers from bots and scrapers. Every request gets a
**bot score** from 0 (nothing suspicious) to 100 (certainly a bot), based on
its `User-Agent` and on headers that browsers always send. Clients whose
score reaches a threshold have to solve a **proof-of-work challenge** in
JavaScript, or optionally a **CAPTCHA** (Cloudflare Turnstile, hCaptcha or
Google reCAPTCHA), before they are let through. Browsers solve the proof of
work automatically in a fraction of a second and then get a cookie that
lets them through for a day; HTTP libraries, command-line tools and most
scrapers cannot.

Each client is also put in a **category**, such as `search_engine`,
`ai_crawler` or `automation`, which can be allowed or blocked as a whole.
Search engine crawlers are **verified** with DNS, so Googlebot and Bingbot
get through while impostors that only copy their `User-Agent` do not.

```sh
prismwaf -backend http://127.0.0.1:3000 -bot-protection
```

With this, `curl https://example.com/` gets a challenge page instead of the
site, while visitors with a browser do not notice anything.

## How it works

For each request, after [rate limiting](rate-limiting.md) and before
inspection for attacks:

1. The request is scored and categorized (see [Bot score](#bot-score) and
   [Categories](#categories)). If its `User-Agent` names a bot that can
   be [verified](#verified-bots), such as Googlebot, that is checked with
   DNS.
2. Requests to [exempt paths](#options) and from exempt clients are
   forwarded.
3. Categories in `-bot-block-category` are rejected with `403 Forbidden`.
4. Verified bots and categories in `-bot-allow-category` are forwarded.
5. With `-bot-block-score`, requests that reach it are rejected with
   `403 Forbidden`.
6. Requests that reach `-bot-challenge-score` (default 50) are answered
   with the challenge, unless the client has a valid clearance cookie.
   With [`-bot-captcha`](#captcha), the challenge is a CAPTCHA from
   `-bot-captcha-score` on.
7. Everything else is forwarded, with the score, category and verification
   in [headers](#passing-the-score-to-the-backend).

```
browser ──GET /page──▶ PrismWAF: score 0 ──────────────────────▶ backend
curl    ──GET /page──▶ PrismWAF: score 60 ─▶ 403 challenge page
headless browser ──GET /page──▶ score 60 ─▶ challenge page
                 ◀─ solves it in JavaScript, POST /.prismwaf/challenge
                 ◀─ 303 to /page + clearance cookie
                 ──GET /page + cookie──▶ PrismWAF ─────────────▶ backend
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-bot-protection` | `false` | Enable bot protection |
| `-bot-challenge-score` | `50` | Bot score (1-100) from which clients must solve the challenge |
| `-bot-block-score` | `0` (disabled) | Bot score (1-100) from which requests are rejected with `403` without a challenge |
| `-bot-difficulty` | `18` | Leading zero bits of the challenge's SHA-256 hash, 1-30; every bit doubles the work |
| `-bot-clearance-ttl` | `24h` | How long a solved challenge lets a client through; at least `1m` |
| `-bot-secret-file` | (random key) | File with a key of at least 32 bytes that signs challenges and cookies |
| `-bot-path` | (all paths) | Protect only this path; repeatable |
| `-bot-exempt-path` | (none) | Never protect this path; repeatable |
| `-bot-exempt` | (none) | Comma-separated IPs/CIDRs of clients that are never challenged or blocked |
| `-bot-verify` | `true` | Verify bots that name themselves, such as Googlebot, with DNS; let verified bots through |
| `-bot-allow-category` | (none) | Comma-separated [categories](#categories) to let through without a challenge |
| `-bot-block-category` | (none) | Comma-separated categories to reject with `403`, even if verified |
| `-bot-captcha` | (none) | [CAPTCHA](#captcha) provider: `turnstile`, `hcaptcha`, `recaptcha` (v2) or `recaptcha-v3` |
| `-bot-captcha-site-key` | (none) | Site key of the CAPTCHA |
| `-bot-captcha-secret-file` | (none) | File with the secret key of the CAPTCHA |
| `-bot-captcha-score` | `-bot-challenge-score` | Bot score from which the CAPTCHA is shown instead of the proof of work |
| `-bot-captcha-min-score` | `0.5` | reCAPTCHA v3 score (0.0-1.0) from which a client passes |

Paths are written and matched like the paths of
[rate limit rules](rate-limiting.md#path-rules): `/search` is one path,
`/articles/*` is `/articles` and everything below it, and paths are
compared after normalization, without case and the query string.
`/robots.txt`, `/favicon.ico` and `/.well-known/*` are always exempt, so
that crawlers can read `robots.txt` and ACME and `security.txt` keep
working.

## Bot score

The score is the sum of the points of the signals found, up to 100.

The `User-Agent` is checked first. If it is one of these, the score is
final:

| Signal | Points | When |
|--------|-------:|------|
| `no_user_agent` | 60 | No `User-Agent` header |
| `automation_tool` | 60 | An HTTP library, command-line tool, headless browser or scanner: `curl`, `Wget`, `python-requests`, `aiohttp`, `Scrapy`, `Go-http-client`, `okhttp`, `axios`, `HeadlessChrome`, `Selenium`, `Puppeteer`, `Playwright`, `sqlmap`, `Nuclei`, … |
| `crawler` | 50 | A [known bot](#categories) (`Googlebot`, `GPTBot`, `ClaudeBot`, `AhrefsBot`, `Twitterbot`, …) or another self-declared crawler: a name ending in `bot`, or containing `crawl`, `spider`, `scrape`, … |
| `unknown_client` | 30 | Not a browser, e.g. a mobile app (`MyApp/2.1`) |

If the `User-Agent` claims to be Chrome (or another Chromium-based
browser), Firefox or Safari, the request is checked for what that browser
would send:

| Signal | Points | When |
|--------|-------:|------|
| `missing_accept` | 20 | No `Accept` header |
| `missing_accept_language` | 30 | No `Accept-Language` header |
| `missing_accept_encoding` | 30 | No `Accept-Encoding` header |
| `http10` | 30 | HTTP/1.0 |
| `outdated_browser` | 20 | A version from before 2020, e.g. `Chrome/58`, typical of User-Agents copied into scripts |
| `missing_fetch_metadata` | 20 | HTTPS only: no `Sec-Fetch-Mode` (Chrome 80+, Firefox 90+, Safari 17+) |
| `missing_client_hints` | 20 | HTTPS only: no `Sec-CH-UA` (Chromium 90+) |

Bots that can be [verified](#verified-bots) add a signal if they are not:

| Signal | Points | When |
|--------|-------:|------|
| `fake_bot` | 40 | The `User-Agent` names a verifiable bot such as Googlebot, but the client address does not belong to it |

Browsers send `Sec-Fetch-*` and client hints only to HTTPS sites, so these
two signals apply when the client connected with HTTPS: to PrismWAF, or to
a [trusted proxy](audit-log.md#client-ip) that sets
`X-Forwarded-Proto: https`.

Examples:

| Client | Score | Signals |
|--------|------:|---------|
| Chrome, Firefox, Safari, Edge | 0 | |
| `curl https://example.com/` | 60 | `automation_tool` |
| Googlebot, GPTBot | 50 | `crawler`; Googlebot is let through once [verified](#verified-bots) |
| A scraper with Googlebot's `User-Agent` | 90 | `crawler`, `fake_bot` |
| A Python script with a Chrome `User-Agent`, over HTTPS | 70 | `missing_accept_language`, `missing_fetch_metadata`, `missing_client_hints` |
| The same script that also copies `Accept-Language` | 40 | `missing_fetch_metadata`, `missing_client_hints` |
| A mobile app calling an API | 30 | `unknown_client` |

With the default threshold of 50, a single missing header does not trigger
a challenge, but tools, crawlers and scripts that only fake the
`User-Agent` do. A false positive costs a real user a challenge that their
browser solves on its own, not a block.

## Categories

Every request is put in one category, from its `User-Agent`. The category
is logged, passed to the backend, and can be allowed or blocked with
`-bot-allow-category` and `-bot-block-category`.

| Category | Clients | Examples |
|----------|---------|----------|
| `browser` | Browsers, and clients that claim to be one | Chrome, Firefox, Safari |
| `search_engine` | Search engine crawlers | Googlebot, Bingbot, Applebot, YandexBot, Baiduspider, DuckDuckBot |
| `ai_crawler` | Crawlers and fetchers of AI companies | GPTBot, ChatGPT-User, ClaudeBot, PerplexityBot, CCBot, Bytespider, Amazonbot, meta-externalagent |
| `seo` | SEO and marketing tools | AhrefsBot, SemrushBot, MJ12bot, DotBot |
| `social` | Link previews of chat apps and social networks | facebookexternalhit, Twitterbot, Slackbot, Discordbot, LinkedInBot, TelegramBot |
| `monitoring` | Uptime monitors | UptimeRobot, Pingdom, StatusCake |
| `crawler` | Other self-declared bots and crawlers | `ExampleBot/1.0` |
| `automation` | HTTP libraries, command-line tools, headless browsers | curl, python-requests, Scrapy, HeadlessChrome, Playwright |
| `scanner` | Vulnerability and port scanners | sqlmap, Nikto, Nuclei, zgrab |
| `unknown` | No `User-Agent`, or one that is not recognized | `MyApp/2.1` |

`-bot-block-category` applies to every client in the category, verified or
not, and to bots that are honest about who they are. A scraper that
pretends to be a browser is not in `ai_crawler`; it is caught, if at all,
by its [score](#bot-score).

`-bot-allow-category` lets anyone through who claims to be in the
category, since only search engines can be [verified](#verified-bots).
Use it for categories where that is acceptable, e.g. `social` for link
previews of public pages, and keep it away from paths that need
protection.

## Verified bots

With `-bot-verify` (on by default), a request whose `User-Agent` names one
of the bots below is checked the way their operators document:

1. The reverse DNS name of the client address is looked up and must end in
   one of the bot's domains, e.g. `crawl-66-249-66-1.googlebot.com`.
2. That name is looked up in turn and must resolve to the client address,
   since anyone can set the reverse DNS name of their own addresses.

| Bot | Domains |
|-----|---------|
| Googlebot and Google's other crawlers (`Google-InspectionTool`, `Storebot-Google`, `GoogleOther`, `AdsBot-Google`, …) | `googlebot.com`, `google.com` |
| Bingbot (`bingbot`, `BingPreview`, `msnbot`) | `search.msn.com` |
| Applebot | `applebot.apple.com` |
| YandexBot | `yandex.ru`, `yandex.net`, `yandex.com` |
| Baiduspider | `baidu.com`, `baidu.jp` |
| Yahoo Slurp | `crawl.yahoo.net` |
| PetalBot | `petalsearch.com` |
| SeznamBot | `seznam.cz` |
| Amazonbot | `crawl.amazonbot.amazon` |

- **Verified:** the request is let through without a challenge (unless its
  category is blocked) and forwarded with `X-PrismWAF-Bot-Verified: true`.
- **Not verified:** the request gets the `fake_bot` signal: 50 + 40 = 90
  points, which is challenged, or blocked with `-bot-block-score 90` or
  lower.

Results are cached per address and bot: a day if verified, an hour if not,
five minutes if DNS failed. Only the first request from an address waits
for DNS, at most two seconds; concurrent requests share one lookup.
PrismWAF uses the system's DNS resolver, which must be able to resolve
public reverse DNS names.

Bots that publish IP address lists instead of DNS names, such as GPTBot,
ClaudeBot or DuckDuckBot, are not verified. To let them through, exempt
their published ranges with `-bot-exempt`.

## The challenge

A challenged `GET` or `HEAD` request gets `403 Forbidden` with a small page
("Checking your browser"). Its script searches for a number that, appended
to a random value from PrismWAF, gives a SHA-256 hash starting with
`-bot-difficulty` zero bits, in Web Workers on all CPU cores. It then posts
the number to `/.prismwaf/challenge`, which checks it, sets the clearance
cookie and redirects to the URL that was requested, including its query
string.

| `-bot-difficulty` | Hashes on average | 2-core PC (about 5 million hashes/s) |
|------------------:|------------------:|-------------------------------------:|
| 16 | 65,000 | 0.01 s |
| 18 (default) | 262,000 | 0.05 s |
| 20 | 1,000,000 | 0.2 s |
| 22 | 4,200,000 | 0.8 s |
| 24 | 16,800,000 | 3 s |

Phones are several times slower, and the time varies a lot because the
search is random: about one in twenty solutions takes three times the
average. The default makes the challenge invisible to users; it mainly
forces clients to run JavaScript. Raise it to make each solution cost
scrapers more CPU time, at the cost of a visible delay for real users who
are challenged.

Details:

- **Other methods:** a `POST` or other request cannot be repeated after the
  challenge, so it gets a plain `403` instead. In practice a browser
  already has the cookie from the page that sent the request.
- **No JavaScript:** the page asks to enable JavaScript. Such clients cannot
  get through while their score reaches the threshold.
- **No cookies:** the page asks to enable cookies instead of repeating the
  challenge forever.
- **Security:** the page sets a strict `Content-Security-Policy`, is not
  cached (`Cache-Control: no-store`) and not indexed
  (`X-Robots-Tag: noindex`). It only redirects to paths on the same site.
- **Reserved path:** `POST /.prismwaf/challenge` is handled by PrismWAF
  and never reaches the backend.
- **Expired challenge:** a challenge must be solved within 10 minutes. If
  a tab was left open longer, the page solves a new one automatically. If
  the solution is rejected for another reason, such as a changed IP
  address, the page shows "The browser check failed" with a link to try
  again.

## CAPTCHA

Instead of the proof of work, PrismWAF can show a CAPTCHA from one of these
providers:

| `-bot-captcha` | Provider | User interaction |
|----------------|----------|------------------|
| `turnstile` | [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/) | Usually none |
| `hcaptcha` | [hCaptcha](https://www.hcaptcha.com/) | Checkbox, sometimes an image puzzle |
| `recaptcha` | [Google reCAPTCHA v2](https://developers.google.com/recaptcha/docs/display) ("I'm not a robot") | Checkbox, sometimes an image puzzle |
| `recaptcha-v3` | [Google reCAPTCHA v3](https://developers.google.com/recaptcha/docs/v3) | None: the client passes if Google's score reaches `-bot-captcha-min-score` |

Create a site (widget) for your domain at the provider, then:

```sh
echo 'the-secret-key' > /etc/prismwaf/captcha.secret
chmod 600 /etc/prismwaf/captcha.secret
prismwaf ... -bot-protection \
  -bot-captcha turnstile -bot-captcha-site-key 0x4AAAAAAA... \
  -bot-captcha-secret-file /etc/prismwaf/captcha.secret
```

The secret key is read from a file so that it does not appear in the
process list.

### Proof of work for some, CAPTCHA for others

`-bot-captcha-score` decides who gets the CAPTCHA. By default it is the
challenge score, so every challenge is a CAPTCHA. With a higher value,
clients in between solve the invisible proof of work, and only the most
suspicious ones see the CAPTCHA:

```sh
prismwaf ... -bot-protection -bot-challenge-score 50 \
  -bot-captcha turnstile -bot-captcha-site-key ... -bot-captcha-secret-file ... \
  -bot-captcha-score 70
```

| Score | Example | Challenge |
|------:|---------|-----------|
| below 50 | Browsers | None |
| 50-69 | curl, crawlers, headless browsers | Proof of work |
| 70 and more | Scripts with a fake browser `User-Agent`, fake Googlebots | CAPTCHA |

A solved CAPTCHA also counts as a solved proof of work, but not the other
way round: a client with a proof-of-work cookie whose score reaches the
CAPTCHA score still has to solve the CAPTCHA.

### How it works

The challenge page loads the provider's script and shows its widget. When
it is solved, the page posts the provider's token to
`/.prismwaf/challenge`. PrismWAF sends it to the provider's `siteverify`
API with the secret key and the client address, and accepts it if:

- the provider reports success,
- the solution was made for the host name the client requested (so that a
  token solved on another site with the same keys is not accepted), and
- for reCAPTCHA v3, the action is `prismwaf_challenge` and the score
  reaches `-bot-captcha-min-score`.

The page's `Content-Security-Policy` allows the provider's domains. The
CAPTCHA needs the browser to reach the provider; PrismWAF needs to reach
its `siteverify` API over HTTPS (10 second timeout).

### When verification fails

The client sees "The CAPTCHA could not be verified" with a link to try
again. If the cause is not the client, PrismWAF logs it, because then
every user fails:

```
level=WARN msg="cannot verify CAPTCHA solutions" provider=turnstile error="CAPTCHA misconfigured: invalid-input-secret"
level=WARN msg="cannot verify CAPTCHA solutions" provider=hcaptcha error="CAPTCHA misconfigured: the solution is for \"www.example.com\", not \"example.com\"; are the site keys used by another site?"
level=WARN msg="cannot verify CAPTCHA solutions" provider=recaptcha error="CAPTCHA provider unavailable: ... i/o timeout"
```

| Error | Cause |
|-------|-------|
| `invalid-input-secret`, `sitekey-secret-mismatch` | Wrong secret key, or site key and secret key from different sites |
| `the solution is for "…", not "…"` | The host name is not registered for the site key at the provider, or the keys are shared with another site |
| `CAPTCHA provider unavailable` | PrismWAF cannot reach the provider: firewall, proxy or DNS |

Solving fails closed: while the provider cannot be reached, challenged
clients cannot get through. Clients with a valid clearance cookie and
clients below the challenge score are not affected.

### Testing

The providers publish test keys that always pass. Their solutions are made
for a fixed host name (Turnstile: `example.com`, hCaptcha:
`dummy-key-pass`, reCAPTCHA: `testkey.google.com`), so to try them, map
that name to PrismWAF on the test machine, e.g. in `/etc/hosts`, start
PrismWAF with the Turnstile test keys `1x00000000000000000000AA` (site) and
`1x0000000000000000000000000000000AA` (secret), and open
`http://example.com:8080/`. A normal browser scores 0 and is not
challenged: change its `User-Agent` in the developer tools (e.g. to
`curl/8.0`) or use a headless browser to see the CAPTCHA.

## Clearance cookie

After solving a challenge, the client gets the cookie `prismwaf_clearance`
(`HttpOnly`, `SameSite=Lax`, `Secure` over HTTPS) for `-bot-clearance-ttl`.
It is signed and bound to:

- **the client address:** the IP address, or its `/64` network for IPv6,
  as for [rate limiting](rate-limiting.md#clients). A scraper cannot solve
  the challenge once and share the cookie among its other addresses.
  Users whose address changes, e.g. when a phone switches between Wi-Fi
  and mobile data, solve a new challenge.
- **the `User-Agent`:** a cookie solved in a browser cannot be reused by a
  script with another `User-Agent`.

The signing key is random and generated at startup by default. Cookies
then become invalid when PrismWAF restarts, which challenges users again,
and with several instances behind a load balancer, each instance rejects
the others' cookies. To avoid both, give every instance the same key:

```sh
openssl rand -base64 32 > /etc/prismwaf/bot.key
chmod 600 /etc/prismwaf/bot.key
prismwaf ... -bot-protection -bot-secret-file /etc/prismwaf/bot.key
```

Anyone with the key can create valid cookies. Changing the key invalidates
all cookies.

## Passing the score to the backend

Every forwarded request carries the assessment in three headers, also for
exempt paths and clients and for clients with a clearance cookie. Values
sent by the client are replaced.

| Header | Example |
|--------|---------|
| `X-PrismWAF-Bot-Score` | `60` |
| `X-PrismWAF-Bot-Category` | `search_engine` (see [Categories](#categories)) |
| `X-PrismWAF-Bot-Verified` | `true` for a [verified bot](#verified-bots), otherwise `false` |

The application can use them, e.g. to leave out expensive parts of a page,
to require a CAPTCHA on a form for scores above 30, or to serve verified
search engines a lighter page.

## Responses and audit events

| Situation | Response |
|-----------|----------|
| Challenged `GET`/`HEAD` | `403` with the challenge page |
| Challenged other method | `403` with `Forbidden`, a hint to reload the page and the event ID |
| Score reaches `-bot-block-score`, or category in `-bot-block-category` | `403` with `Forbidden` and the event ID |

Challenges and blocks are logged in the [audit log](audit-log.md) with
`"reason": "bot"` and `"action": "challenge"` or `"block"`. To keep the log
readable, an event is logged for the first challenged (or blocked) request
of each client and then at most once a minute; the requests in between
share its event ID.

```json
{
  "time": "2026-11-11T00:42:39.652Z",
  "id": "03e3d9b493fb122f",
  "client_ip": "203.0.113.7",
  "remote_addr": "203.0.113.7:34716",
  "action": "challenge",
  "reason": "bot",
  "bot": {
    "score": 60,
    "signals": ["automation_tool"],
    "category": "automation",
    "challenge": "pow",
    "client": "203.0.113.7/32"
  },
  "request": {
    "method": "GET",
    "uri": "/articles/42",
    "proto": "HTTP/1.1",
    "host": "example.com",
    "content_length": 0,
    "headers": { "Accept": "*/*", "User-Agent": "curl/8.5.0" }
  }
}
```

| Field | Description |
|-------|-------------|
| `bot.score` | The bot score, 0-100 |
| `bot.signals` | The signals that added to it (see [Bot score](#bot-score)) |
| `bot.category` | The [category](#categories) |
| `bot.name` | The name of a known bot, e.g. `Googlebot` |
| `bot.verified` | `true` if the bot was [verified](#verified-bots) (only blocked categories log verified bots) |
| `bot.challenge` | `pow` or `captcha` for a challenge; absent for a block |
| `bot.client` | The address the clearance would be bound to: the client IP as `/32`, or its `/64` network for IPv6 |

Solved challenges are not logged.

```sh
# Challenges and blocks by category
jq -r 'select(.reason == "bot") | [.action, .bot.category, .bot.name // ""] | @tsv' audit.log | sort | uniq -c | sort -rn
# Which kinds of clients are challenged
jq -r 'select(.reason == "bot") | .bot.signals | join(",")' audit.log | sort | uniq -c | sort -rn
# The User-Agents of challenged clients
jq -r 'select(.reason == "bot") | .request.headers["User-Agent"]' audit.log | sort | uniq -c | sort -rn | head -20
```

In detection mode (`-mode detect`), nothing is challenged or blocked;
requests are forwarded and logged with `"action": "detect"`.

## Use cases

### Keep AI crawlers and scrapers away from content

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -bot-protection \
  -bot-exempt-path "/api/*" -bot-exempt-path "/feed.xml"
```

Articles and other pages can only be read with a browser. API clients and
feed readers, which are not browsers, are exempt. Ask well-behaved
crawlers to stay away in `robots.txt` as well; it stays readable.

### Block AI crawlers, keep search engines

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -bot-protection -bot-block-category ai_crawler,seo \
  -bot-allow-category social
```

AI and SEO crawlers that say who they are get `403`. Googlebot, Bingbot and
other verifiable search engines are let through after DNS verification, so
the site stays indexed; impostors are challenged. Link previews in chats
work. Tools and scrapers are challenged as before. Keep `robots.txt`
telling the crawlers the same, for those that respect it.

### A CAPTCHA for the most suspicious clients

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -bot-protection -bot-captcha turnstile \
  -bot-captcha-site-key 0x4AAAAAAA... -bot-captcha-secret-file /etc/prismwaf/captcha.secret \
  -bot-captcha-score 70
```

See [Proof of work for some, CAPTCHA for others](#proof-of-work-for-some-captcha-for-others).

### Protect only expensive pages

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -bot-protection -bot-path /search -bot-path "/export/*"
```

Only search and export, which scrapers like to hammer and which are costly
to serve, require a browser. The rest of the site, including what search
engines index, is not affected.

### Block obvious tools outright

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -bot-protection -bot-block-score 60
```

Requests with a score of 60 or more (no `User-Agent`, HTTP libraries and
tools, or browser `User-Agents` without browser headers) get a plain `403`
without a challenge; crawlers (50) are still challenged. Combine with
[rate limiting](rate-limiting.md) to slow down clients that solve the
challenge but then send too many requests.

### Behind a load balancer or CDN

```sh
prismwaf -listen :8080 -backend http://127.0.0.1:3000 \
  -trusted-proxies 10.0.0.0/8 \
  -bot-protection -bot-secret-file /etc/prismwaf/bot.key
```

Without `-trusted-proxies`, every request comes from the proxy: all clients
share its address, a cookie solved by one user would be valid for others
with the same `User-Agent`, and HTTPS-only signals are not checked. Make
sure the proxy appends the client address to `X-Forwarded-For` and sets
`X-Forwarded-Proto`. Use the same `-bot-secret-file` on every instance.

### Try it out before enforcing it

```sh
prismwaf -mode detect -audit-log audit.log -bot-protection
```

After a few days, check what would have been challenged with the `jq`
commands in [Responses and audit events](#responses-and-audit-events).
Exempt the clients and paths that must keep working, such as monitoring,
partner integrations, webhooks from payment providers and mobile app APIs.
Then switch to `-mode block`. Detection mode applies to all of PrismWAF.

## Search engines and link previews

Bots say that they are bots, so they are challenged and cannot solve the
challenge. PrismWAF does not let them through by their `User-Agent` alone,
because anyone can send `Googlebot` as a `User-Agent`. With bot protection
on all paths:

- **Search engines** in the [verified bots](#verified-bots) table are let
  through after DNS verification (`-bot-verify`, on by default). Others,
  such as DuckDuckBot, are challenged; exempt their published IP ranges
  with `-bot-exempt` if they matter.
- **Link previews** of chat apps and social networks (`Slackbot`,
  `Twitterbot`, `facebookexternalhit`, `Discordbot`) cannot be verified and
  are challenged, so links to the site get no preview. Allow them with
  `-bot-allow-category social`, knowing that anyone can claim to be a link
  preview, or protect only the paths that need it with `-bot-path`.

## Limitations

- The score is a heuristic. A scraper that copies every header of a real
  browser gets a low score and is not challenged; one that drives a real
  browser (Puppeteer, Playwright with a normal `User-Agent`) solves the
  challenge. Bot protection makes scraping more expensive; it does not make
  it impossible.
- Requests are scored one by one. Behavior across requests, mouse
  movements, TLS fingerprints (JA3/JA4) and IP reputation are not used.
- Only bots that document reverse DNS verification are verified (see
  [Verified bots](#verified-bots)). Bots that publish IP lists, and IP
  reputation or datacenter address lists in general, are not used.
- Categories come from the `User-Agent`. Blocking a category stops honest
  bots; scrapers that pretend to be browsers are left to the score.
- The CAPTCHA providers see the IP addresses and browser data of challenged
  visitors; mention them in your privacy policy. reCAPTCHA v3 was tested
  only with simulated provider responses, as Google offers no test keys for
  it.
- Clients without JavaScript or cookies cannot pass the challenge, which
  also affects some accessibility tools and very old browsers.
- The clearance is bound to the client address: users whose address
  changes often, or who share a NAT address, may solve challenges more
  often.
- Audit events are remembered in memory, per process.
