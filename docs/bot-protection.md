# Bot protection

PrismWAF can tell browsers from bots and scrapers. Every request gets a
**bot score** from 0 (nothing suspicious) to 100 (certainly a bot), based on
its `User-Agent` and on headers that browsers always send. Clients whose
score reaches a threshold have to solve a **proof-of-work challenge** in
JavaScript before they are let through. Browsers solve it automatically in
a fraction of a second and then get a cookie that lets them through for a
day; HTTP libraries, command-line tools and most scrapers cannot.

```sh
prismwaf -backend http://127.0.0.1:3000 -bot-protection
```

With this, `curl https://example.com/` gets a challenge page instead of the
site, while visitors with a browser do not notice anything.

## How it works

For each request, after [rate limiting](rate-limiting.md) and before
inspection for attacks:

1. The request is scored (see [Bot score](#bot-score)).
2. Requests to [exempt paths](#options) and from exempt clients are
   forwarded.
3. With `-bot-block-score`, requests that reach it are rejected with
   `403 Forbidden`.
4. Requests that reach `-bot-challenge-score` (default 50) are answered
   with the challenge, unless the client has a valid clearance cookie.
5. Everything else is forwarded, with the score in the
   [`X-PrismWAF-Bot-Score`](#passing-the-score-to-the-backend) header.

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
| `crawler` | 50 | A self-declared crawler: a name ending in `bot` (`Googlebot`, `GPTBot`, `ClaudeBot`, `AhrefsBot`, `Twitterbot`), or containing `crawl`, `spider`, `scrape`, … |
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

Browsers send `Sec-Fetch-*` and client hints only to HTTPS sites, so these
two signals apply when the client connected with HTTPS: to PrismWAF, or to
a [trusted proxy](audit-log.md#client-ip) that sets
`X-Forwarded-Proto: https`.

Examples:

| Client | Score | Signals |
|--------|------:|---------|
| Chrome, Firefox, Safari, Edge | 0 | |
| `curl https://example.com/` | 60 | `automation_tool` |
| Googlebot, GPTBot | 50 | `crawler` |
| A Python script with a Chrome `User-Agent`, over HTTPS | 70 | `missing_accept_language`, `missing_fetch_metadata`, `missing_client_hints` |
| The same script that also copies `Accept-Language` | 40 | `missing_fetch_metadata`, `missing_client_hints` |
| A mobile app calling an API | 30 | `unknown_client` |

With the default threshold of 50, a single missing header does not trigger
a challenge, but tools, crawlers and scripts that only fake the
`User-Agent` do. A false positive costs a real user a challenge that their
browser solves on its own, not a block.

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

Every forwarded request carries the score in `X-PrismWAF-Bot-Score`, e.g.
`X-PrismWAF-Bot-Score: 60`, also for exempt paths and clients and for
clients with a clearance cookie. A value sent by the client is replaced.
The application can use it, e.g. to leave out expensive parts of a page or
to require a CAPTCHA on a form for scores above 30.

## Responses and audit events

| Situation | Response |
|-----------|----------|
| Challenged `GET`/`HEAD` | `403` with the challenge page |
| Challenged other method | `403` with `Forbidden`, a hint to reload the page and the event ID |
| Score reaches `-bot-block-score` | `403` with `Forbidden` and the event ID |

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
  "bot": { "score": 60, "signals": ["automation_tool"], "client": "203.0.113.7/32" },
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
| `bot.client` | The address the clearance would be bound to: the client IP as `/32`, or its `/64` network for IPv6 |

Solved challenges are not logged.

```sh
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

Search engine crawlers and the link preview bots of chat apps and social
networks (`Slackbot`, `Twitterbot`, `facebookexternalhit`, `Discordbot`)
say that they are bots, so they are challenged, cannot solve the
challenge, and do not see the page. With bot protection on all paths:

- search engines stop indexing the site, and
- links to it get no preview (title and image) in chats and social media.

PrismWAF does not let them through by their `User-Agent`, because anyone
can send `Googlebot` as a `User-Agent`. If the site should be indexed:

- protect only the paths that matter with `-bot-path`, or
- exempt the published IP ranges of the crawlers with `-bot-exempt`. Google
  and Bing publish theirs (`googlebot.json`, `bingbot.json`); they change
  over time.

## Limitations

- The score is a heuristic. A scraper that copies every header of a real
  browser gets a low score and is not challenged; one that drives a real
  browser (Puppeteer, Playwright with a normal `User-Agent`) solves the
  challenge. Bot protection makes scraping more expensive; it does not make
  it impossible.
- Requests are scored one by one. Behavior across requests, mouse
  movements, TLS fingerprints (JA3/JA4) and IP reputation are not used.
- Search engines and other good bots are not verified (see
  [Search engines and link previews](#search-engines-and-link-previews)).
- Clients without JavaScript or cookies cannot pass the challenge, which
  also affects some accessibility tools and very old browsers.
- The clearance is bound to the client address: users whose address
  changes often, or who share a NAT address, may solve challenges more
  often.
- Audit events are remembered in memory, per process.
