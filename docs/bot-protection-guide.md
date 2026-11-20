# Bot protection guide

This guide explains how to plan, roll out and tune
[bot protection](bot-protection.md) for a real site, and how to keep it
from hurting your search rankings. The [reference](bot-protection.md)
describes every flag, the bot score and the challenge in detail; this guide
links to it instead of repeating it.

- [Plan: what to protect and what must keep working](#plan-what-to-protect-and-what-must-keep-working)
- [Roll out in five steps](#roll-out-in-five-steps)
- [Configurations for common sites](#configurations-for-common-sites)
- [Tuning](#tuning)
- [Troubleshooting false positives](#troubleshooting-false-positives)
- [Search engines and SEO](#search-engines-and-seo)
- [Checklist](#checklist)

## Plan: what to protect and what must keep working

Bot protection challenges clients that do not look like browsers. Before
turning it on, write down two lists.

**What bots cost you**, which decides how strict to be and where:

| Problem | Typical target | Main tools |
|---------|----------------|------------|
| Content scraping, AI training | Articles, product pages, listings | Challenge on all pages, `-bot-block-category ai_crawler` |
| Price and stock scraping | Product and search pages | Challenge, rate limits, [enumeration limits](business-logic.md#enumeration-limits) |
| Load from expensive pages | Search, filters, exports, reports | `-bot-path` on those pages, [rate limits](rate-limiting.md) |
| Credential stuffing, coupon guessing | Login, redeem forms | [Failure limits](business-logic.md) first; challenge the form pages |
| Vulnerability scanners | Everything | `-bot-block-score 60` or `-bot-block-category scanner`; the [CRS](crs.md) |
| Fake search engines | Everything | DNS verification (on by default) |

**Who must keep working**, which decides what to exempt:

| Client | Score without exemption | Exempt with |
|--------|------------------------:|-------------|
| Browsers | 0 | Nothing to do |
| Google, Bing and the other [verifiable search engines](bot-protection.md#verified-bots) | 50, let through once verified | Nothing to do; see [SEO](#search-engines-and-seo) |
| Other search engines (DuckDuckBot, …) | 50 | `-bot-exempt` with their published ranges |
| Link previews (Slack, X, Facebook, …) | 50 | `-bot-allow-category social` |
| Uptime monitors | 50 | `-bot-exempt` with their addresses, or `-bot-allow-category monitoring` |
| Feed readers (Feedly, …) | 50 | `-bot-exempt-path` for the feeds |
| Mobile apps and API clients | 30-60 | `-bot-exempt-path "/api/*"` |
| Webhooks of payment providers, GitHub, … | 30-60 | `-bot-exempt-path` for the webhook URLs |
| Partners, internal scripts, your own crawlers | 60 | `-bot-exempt` with their addresses |
| Load tests, end-to-end tests | 60 | `-bot-exempt` with the test machines |

A client with a score below the challenge score (50 by default) is never
affected, so mobile apps (`unknown_client`, 30) pass by default. HTTP
libraries such as `okhttp` or `python-requests` score 60 and do not; this is
why API paths are usually exempted.

Also decide:

- **Where TLS ends.** Behind a load balancer or CDN, set `-trusted-proxies`,
  or every client shares the proxy's address and the HTTPS-only signals
  are not checked (see
  [Behind a load balancer or CDN](bot-protection.md#behind-a-load-balancer-or-cdn)).
- **How many instances.** Several instances, and restarts, need a shared
  `-bot-secret-file`, or users are challenged again by every instance and
  after every restart.
- **What a CDN caches.** Pages served from a CDN cache never reach PrismWAF
  and are not protected. Protect pages that must not be scraped by not
  caching them at the CDN, or by the CDN's own bot protection.

## Roll out in five steps

### 1. Prepare

```sh
# A shared key, so that cookies survive restarts and work on every instance
openssl rand -base64 32 > /etc/prismwaf/bot.key
chmod 600 /etc/prismwaf/bot.key

# The resolver must answer reverse DNS queries for verification
dig +short -x 66.249.66.1        # crawl-66-249-66-1.googlebot.com.
dig +short crawl-66-249-66-1.googlebot.com   # 66.249.66.1
```

If `dig -x` returns nothing or times out, Googlebot cannot be verified and
will be challenged; fix the resolver before going further (see
[DNS failures](#dns-failures)).

### 2. Run in detection mode

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -mode detect -audit-log /var/log/prismwaf/audit.log \
  -bot-protection -bot-secret-file /etc/prismwaf/bot.key \
  -bot-exempt-path "/api/*" -bot-exempt-path "/webhooks/*"
```

Nothing is challenged; what would have been is logged with
`"action": "detect"`. `-mode detect` applies to all of PrismWAF, so other
protections stop blocking as well during this time. Run it for at least a
week, so that weekly jobs, monitors and crawlers show up.

### 3. Review

```sh
# Which kinds of clients would be challenged
jq -r 'select(.reason == "bot") | [.bot.category, .bot.name // "", (.bot.signals // [] | join(","))] | @tsv' audit.log \
  | sort | uniq -c | sort -rn | head -30
# Which paths
jq -r 'select(.reason == "bot") | .request.uri | sub("\\?.*"; "")' audit.log | sort | uniq -c | sort -rn | head -30
# The heaviest clients
jq -r 'select(.reason == "bot") | [.client_ip, .request.headers["User-Agent"]] | @tsv' audit.log \
  | sort | uniq -c | sort -rn | head -30
```

Events are logged once a minute per client, so the counts are clients ×
minutes, not requests. Sort what you find into three groups:

| What you see | Usually | Do |
|--------------|---------|----|
| `automation_tool`, `no_user_agent` from many addresses on content pages | Scrapers, scanners | Nothing: this is what you want to stop |
| `automation_tool` from a few known addresses, or on API paths | Your own scripts, partners, apps | `-bot-exempt` or `-bot-exempt-path` |
| `crawler` with a name you rely on (feed reader, monitor, link preview) | Legitimate bots | Allow its category, or exempt its addresses or paths |
| `search_engine` with `fake_bot` | Impostors, or a [DNS problem](#dns-failures) | Check a few addresses with `dig -x` |
| `missing_*` signals with a browser `User-Agent` | Scripts that fake a browser, or unusual browsers | Look at the addresses; see [Tuning](#tuning) if real users appear |

### 4. Enforce the challenge

Switch to `-mode block` with the exemptions you found. Keep the defaults
(challenge from 50, no blocking) at first: a false positive then costs a
real user a challenge that their browser solves in a fraction of a second,
not a block.

### 5. Tighten, one change at a time

After a week without complaints, add what your [plan](#plan-what-to-protect-and-what-must-keep-working)
calls for: blocked categories, a block score, a CAPTCHA for the most
suspicious clients, a higher difficulty or a shorter clearance. Watch the
audit log and, for search engines, the
[Search Console crawl stats](#check-that-search-engines-get-through)
after each change.

## Configurations for common sites

The examples leave out `-backend`, `-listen`, TLS and `-audit-log`.

### Blog, news or media site

Content must be indexed and shared, but not copied wholesale.

```sh
prismwaf ... \
  -bot-protection -bot-secret-file /etc/prismwaf/bot.key \
  -bot-block-category ai_crawler,seo \
  -bot-allow-category social \
  -bot-exempt-path /feed.xml -bot-exempt-path /sitemap.xml \
  -rate-limit 300/1m
```

- Verified search engines get through; AI and SEO crawlers that say who
  they are get `403`; link previews work; feeds stay readable for feed
  readers.
- `/sitemap.xml` is exempt for search engines that cannot be verified.
- Keep `robots.txt` consistent with this, for crawlers that respect it.
- Blocking `ai_crawler` also keeps the site out of AI search answers; see
  [AI crawlers](#ai-crawlers-and-ai-search).

### Online shop

Product and search pages are scraped for prices and stock; checkout and
payment callbacks must never be challenged.

```sh
prismwaf ... \
  -bot-protection -bot-secret-file /etc/prismwaf/bot.key \
  -bot-exempt-path "/api/*" -bot-exempt-path "/payments/webhook" \
  -bot-captcha turnstile -bot-captcha-site-key 0x4AAAAAAA... \
  -bot-captcha-secret-file /etc/prismwaf/captcha.secret -bot-captcha-score 70 \
  -rate-limit 300/1m -rate-limit-path "/search=30/1m" \
  -enumeration-limit "GET /products/{id}=300/1h"
```

- Tools and crawlers solve the invisible proof of work, which most scrapers
  cannot; scripts that fake a browser get a CAPTCHA.
- Scrapers that drive a real browser pass the challenge; the path rule for
  search and the enumeration limit slow them down after that.
- Google Shopping and ads crawlers (`Storebot-Google`, `AdsBot-Google`) are
  verified as Google and get through.

### Web application with a login

The application is used by signed-in users; only the public pages and the
login matter to bots.

```sh
prismwaf ... \
  -bot-protection -bot-secret-file /etc/prismwaf/bot.key \
  -bot-path /login -bot-path /signup -bot-path /password-reset \
  -failure-limit "POST /login=5/15m" \
  -rate-limit-path "POST /login=10/1m"
```

- Browsers score 0 and do not notice anything. A script that posts to
  `/login` directly scores 60 or more and gets `403`, as a `POST` cannot be
  challenged; one that fakes a browser well enough is left to the failure
  limit.
- The challenge stops simple scripts; failure limits stop guessing from
  clients that pass it.
- The rest of the application is not affected, including its API.

### Documentation or corporate site

Little to protect, and visibility matters, including in AI assistants.

```sh
prismwaf ... \
  -bot-protection -bot-secret-file /etc/prismwaf/bot.key \
  -bot-allow-category social,ai_crawler \
  -bot-block-score 60
```

- AI crawlers and link previews are let through; scanners, HTTP libraries
  and scripts are blocked outright without a challenge.
- Use `-bot-block-score` only where no legitimate tool needs to fetch
  pages; `curl` checks of your own then need `-bot-exempt`.

### API-only service

Bot protection is meant for browsers. An API's clients are programs, which
all score as bots, so do not enable it for API paths. Use
[API protection](api-protection.md), [rate limits](rate-limiting.md),
[business flow protection](business-logic.md) and authentication instead.

### Limited events: tickets, sales, sign-ups

Short peaks where bots compete with people for a limited supply.

```sh
prismwaf ... \
  -bot-protection -bot-secret-file /etc/prismwaf/bot.key \
  -bot-path "/events/*" -bot-path /checkout \
  -bot-captcha turnstile -bot-captcha-site-key ... -bot-captcha-secret-file ... \
  -bot-clearance-ttl 1h \
  -max-client-requests 10 -rate-limit-path "POST /checkout=5/1m"
```

- Every challenge is a CAPTCHA, and a clearance lasts an hour instead of a
  day, so each address has to solve it again for a new event.
- Requests in progress per client are limited
  ([DoS protection](ddos.md#requests-in-progress)), so a client cannot
  hold many checkouts at once.
- A CAPTCHA raises the price of automation but does not stop people paid
  to solve them; combine it with limits per account in the application.

## Tuning

### Challenge score

The challenge score decides who has to prove that they run a browser.
Lower it to catch more, raise it to bother fewer clients.

| `-bot-challenge-score` | Also challenges | Risk |
|-----------------------:|-----------------|------|
| 30 | Unknown clients: mobile apps, webhooks, `Google-Site-Verification`, uncommon tools | High: many legitimate programs; exempt their paths first |
| 40 | Scripts that fake a browser and copy `Accept-Language` | Medium: unusual browsers, privacy tools that strip headers |
| **50 (default)** | Crawlers, unverified search engines, link previews, feed readers, monitors | Low for users; plan for the bots you need |
| 60 | Only tools, missing `User-Agent`, and scripts that fake a browser | Lets self-declared crawlers through unchallenged |
| 70+ | Only fake browsers and fake search engines | Most scrapers pass |

Try a new score in detection mode first and compare the number of events
per category before and after, with the `jq` commands of
[step 3](#3-review).

### Block score

`-bot-block-score` rejects requests without a challenge. Blocks cost less
than challenges, but a false positive is then a real failure.

| `-bot-block-score` | Blocks | Use |
|-------------------:|--------|-----|
| 90 | Fake search engines, scripts with a browser `User-Agent` and almost no browser headers | Safe on most sites |
| 70 | Also scripts with a browser `User-Agent` that miss several browser headers, e.g. a Python script with a Chrome `User-Agent` over HTTPS | Sites with few unusual clients |
| 60 | Also every HTTP library, command-line tool and request without `User-Agent` | Sites where no legitimate tool fetches pages |

Blocks count towards [bans](ddos.md#bans) with `-ban`; challenge pages do
not. A client that keeps sending requests that are blocked is therefore
banned for `-ban-duration`, which also closes its connections early.

### Difficulty

The proof of work mainly forces clients to run JavaScript; its cost is
small for anyone with a browser, including scrapers that drive one.

- Keep the default `18` for sites with many phone users: about 0.05 s on a
  PC and a few tenths of a second on a slow phone.
- `20` is still hardly noticeable on PCs (0.2 s) and suits desktop
  audiences.
- `22` and more makes challenged users wait for seconds on phones. Prefer a
  CAPTCHA for the most suspicious clients (`-bot-captcha-score`) or a
  shorter clearance, which cost scrapers more than a harder puzzle.

### Clearance lifetime

A clearance is valid for one address and one `User-Agent` for
`-bot-clearance-ttl`.

| Lifetime | Effect |
|----------|--------|
| `24h` (default) | Users are challenged at most once a day per address |
| `1h` | A scraper must solve the challenge again every hour on each address; users with a challenge score see the page more often |
| `7d` | Fewer challenges for users with an unusual setup; a solved cookie can be reused longer |

Users are also challenged again when their address changes (a phone moving
between Wi-Fi and mobile data) and when their browser updates and its
`User-Agent` changes. For users with a score of 0 this never happens,
because they are not challenged at all.

### Paths

- **Protect all paths** when content itself is what scrapers want. Exempt
  the paths of machines: APIs, webhooks, feeds, sitemaps, health checks.
- **Protect selected paths** (`-bot-path`) when only some pages are
  expensive or sensitive: search, exports, login, checkout. The rest of
  the site, and search engines, are not affected at all.
- Static files (`/assets/*`) need no exemption: browsers send the clearance
  cookie with them. Exempting them saves only a little work.
- A challenged `POST` gets a plain `403`, as it cannot be repeated after a
  challenge. Browsers are rarely affected: they score 0, and one that was
  challenged got its cookie when it opened the page with the form. Programs
  that post to the site, such as payment returns and webhooks, need an
  exemption.

### Together with the other protections

Requests pass the protections in this order: bans, requests in progress,
countries, rate limits, business flows, bot protection, then inspection
for attacks. Consequences:

- Challenged requests count towards rate limits, so a scraper that ignores
  the challenge and retries is rate limited and, with `-ban`, banned.
- Rate limits and countries also apply to verified search engines; see
  [Rate limits and bans](#rate-limits-and-bans).
- After a client solves the challenge, only rate limits, business flow
  limits and the attack inspection stand between it and the backend. A
  scraper that drives a real browser is stopped by those, not by bot
  protection.

### Using the score in the application

The backend receives `X-PrismWAF-Bot-Score`, `-Category` and `-Verified`
with every request, also on exempt paths. Use them to react more finely
than PrismWAF can:

- Ask for a CAPTCHA on a sign-up or contact form only if the score is 30 or
  more.
- Skip expensive personalization or recommendations for scores of 50 or
  more.
- Log `X-PrismWAF-Bot-Verified` in the access log, to see how much of the
  traffic is verified search engines; the audit log does not record
  forwarded requests.

Serve search engines the same content as users, though; see
[Cloaking](#cloaking).

## Troubleshooting false positives

| Symptom | Cause | Fix |
|---------|-------|-----|
| All users challenged again after a restart or deploy | No `-bot-secret-file`: the key is random per process | Use a key file, the same on every instance |
| Users challenged on every other request | Several instances with different keys | The same `-bot-secret-file` everywhere |
| The challenge page repeats or says "enable cookies" | Cookies blocked, or a proxy that strips `Set-Cookie` | Fix the proxy; users must allow cookies for the site |
| Users on phones challenged often | Changing addresses | Expected for users with a challenge score; check why they score at all (`bot.signals`) |
| "The browser check failed" | The address changed between challenge and solution, e.g. a mobile network or a VPN with rotating exits | The link on the page solves a new challenge |
| Everyone shares one clearance, or `missing_fetch_metadata` never appears | PrismWAF behind a proxy without `-trusted-proxies` | Set `-trusted-proxies`; the proxy must set `X-Forwarded-For` and `X-Forwarded-Proto` |
| A mobile app or partner integration fails with `403` | It uses an HTTP library (score 60) | `-bot-exempt-path` for its API, or `-bot-exempt` for its addresses |
| Payment or webhook callbacks fail | Callbacks are programs, and often `POST`s | `-bot-exempt-path` for the callback URLs |
| Uptime monitor reports the site as down, or shows "Checking your browser" | Monitors are bots | Exempt the monitor's addresses or a health check path |
| Links shared in chats have no preview | Link previews are challenged | `-bot-allow-category social` |
| Users of a privacy browser or extension challenged | Stripped `Accept-Language` or client hints | Normal: they solve the challenge automatically. Raise the score only if many complain |
| Everyone with a CAPTCHA fails | Provider misconfiguration or unreachable | See [When verification fails](bot-protection.md#when-verification-fails) |

To find out why a particular user was challenged, ask for the event ID
shown on blocked responses, or look up their address:

```sh
jq 'select(.reason == "bot" and .client_ip == "203.0.113.7") | {time, action, bot, ua: .request.headers["User-Agent"]}' audit.log
```

## Search engines and SEO

Search engine crawlers are bots and say so. Bot protection therefore treats
them specially, and a mistake here can remove pages from search results.
This section explains what can go wrong and how to avoid it.

### How crawlers are treated

```
Googlebot UA ─▶ reverse DNS of the address ends in googlebot.com/google.com
                and resolves back to it?
                 ├─ yes ─▶ verified: forwarded, score 50, X-PrismWAF-Bot-Verified: true
                 └─ no  ─▶ fake_bot: score 90 ─▶ challenge (403), or block with -bot-block-score ≤ 90
DuckDuckBot UA ─▶ cannot be verified ─▶ score 50 ─▶ challenge (403)
```

- Google's crawlers for search, images, video, news, Shopping and ads
  (`Googlebot`, `Googlebot-Image`, `Storebot-Google`, `AdsBot-Google`,
  `Google-InspectionTool`, …) are all verified the same way.
- Bing, Apple, Yandex, Baidu, Yahoo, Petal, Seznam and Amazon are verified
  too; see the [table](bot-protection.md#verified-bots).
- Verified crawlers are let through even above `-bot-block-score`, unless
  their category is in `-bot-block-category`.
- `/robots.txt`, `/favicon.ico` and `/.well-known/*` are never challenged.
- The challenge page has `X-Robots-Tag: noindex` and
  `Cache-Control: no-store`, so it never ends up in an index or a cache
  in place of the page.

### Status codes and what search engines do with them

Search engines react to the status code, not to the page:

| PrismWAF responds | When | Google's reaction |
|-------------------|------|-------------------|
| `200` (forwarded) | Verified crawler | Normal crawling |
| `403` challenge or block | Crawler not verified, category blocked, banned, country blocked | The URL is not indexed; already indexed URLs are dropped if it persists |
| `429` | Rate limit, failure or enumeration limit, too many requests in progress | Crawling slows down; temporary errors do not drop pages |
| `503` | `-max-requests` reached | Same as `429` |

A short burst of `429` or `503` is harmless and is the right way to slow a
crawler down. `403` for real crawlers must not last: Google documents that
`4xx` responses other than `429` should not be used to limit crawling.

### What can go wrong

#### DNS failures

Verification needs the system's resolver to answer reverse DNS queries for
public addresses. If a lookup fails (timeout, `SERVFAIL`, a resolver that
only knows internal names), the crawler counts as **not verified**: it gets
the `fake_bot` signal and is challenged, until the lookup is retried five
minutes later. A resolver that is broken for hours means hours of `403` for
Googlebot.

- Use a reliable resolver: a local caching resolver (systemd-resolved,
  unbound) with public upstreams, or your provider's. Test with
  `dig -x 66.249.66.1`.
- Watch the audit log for search engines with `fake_bot` (see
  [Check that search engines get through](#check-that-search-engines-get-through)).
  Many such events from addresses that `dig -x` shows as Google's mean a
  DNS problem, not impostors.
- To remove the dependency on DNS for Google, exempt its published ranges
  (see [Exempting published crawler ranges](#exempting-published-crawler-ranges)).

#### Rate limits and bans

Rate limits, business flow limits, requests in progress and bans come
before bot protection and apply to verified crawlers as well. A large site
can see Googlebot send hundreds of requests a minute.

- `429` slows Googlebot down without harm. But every `429` also counts
  towards [`-ban`](ddos.md#bans): with `-rate-limit 300/1m -ban 300/1m`, a
  crawler that keeps going at 600 requests a minute is banned and gets
  `403` for `-ban-duration`.
- Exempt the crawlers' published ranges from these limits with
  `-rate-limit-exempt`, which also exempts them from bans and from the
  per-client connection and concurrency limits.
- Otherwise, set the global `-rate-limit` well above what crawlers send.
  Path rules for expensive pages (`/search`) rarely matter, as crawlers
  should not crawl search results anyway; disallow them in `robots.txt`.

#### Geo filtering

[Geo filtering](geo-filtering.md) comes before bot protection and has no
exemption for crawlers. Googlebot crawls mostly from the United States, so
`-geo-allow JP` alone also rejects Googlebot with `403`. Allow `US` as well,
or exempt the crawlers' ranges with `-geo-exempt`.

#### Search engines that cannot be verified

Crawlers that do not document reverse DNS verification, such as DuckDuckBot,
score 50 and are challenged, which they cannot solve. If they matter in
your market, exempt their published ranges with `-bot-exempt`, or protect
only selected paths with `-bot-path`. If a search engine you care about is
not recognized at all, its `User-Agent` decides its score; check the audit
log for it in detection mode.

#### Blocked categories

- `search_engine` in `-bot-block-category` removes the site from search
  engines. There is rarely a reason for it.
- `seo` blocks tools such as Ahrefs and Semrush. Their data, including your
  own backlink reports, then no longer covers the site; it does not affect
  rankings directly.
- `social` is challenged by default, so shared links get no preview, title
  or image. Previews affect how often links are clicked; allow the category
  on sites that are shared.

#### AI crawlers and AI search

The `ai_crawler` category contains both training crawlers (`GPTBot`,
`CCBot`, `ClaudeBot`) and the fetchers of AI search and assistants
(`OAI-SearchBot`, `ChatGPT-User`, `PerplexityBot`, `Claude-SearchBot`,
`Claude-User`). Blocking the category keeps the site out of training data
and out of the answers and citations of these assistants alike. Decide
which matters more for the site:

| Goal | Do |
|------|----|
| Not used for training, still cited by AI search | Leave `ai_crawler` challenged or allowed, and disallow only the training crawlers in `robots.txt` (`GPTBot`, `CCBot`, `ClaudeBot`, …), which they respect |
| Neither | `-bot-block-category ai_crawler` |
| Both | `-bot-allow-category ai_crawler`, knowing that anyone can claim to be one |

Google's AI features and Gemini training use the normal Googlebot, which
PrismWAF cannot and should not separate from search. To opt out of Gemini
training, add `User-agent: Google-Extended` with `Disallow: /` to
`robots.txt`; it does not affect search. Apple has the same with
`Applebot-Extended`.

#### Cloaking

Search engines penalize sites that show crawlers different content than
users. Do not use `X-PrismWAF-Bot-Verified` or the category to serve
search engines a different page, more text, or no paywall. Leaving out
parts that do not change the content, such as personalization, is fine.

#### Sitemaps, feeds and verification files

- Sitemaps are read by search engines, which are verified; exempt them
  (`-bot-exempt-path /sitemap.xml`) only for search engines that cannot be.
- Feed readers score 50 and are challenged; exempt the feeds.
- Search Console's HTML file verification (`Google-Site-Verification`)
  scores 30 and passes with the default challenge score. With a lower
  score, exempt the verification file or verify with a DNS record instead.

#### Page experience

Browsers score 0 and are not challenged, so Core Web Vitals measured from
real Chrome users are not affected. Users who are challenged wait for the
proof of work (0.05 s on a PC at the default difficulty) and a redirect.
Lab tools such as PageSpeed Insights or Lighthouse run from Google's
servers with a headless browser and may be challenged depending on the
headers they send; if their report shows "Checking your browser", the
measurement is of the challenge page, not of the site. Field data in
Search Console is unaffected.

### Exempting published crawler ranges

Google and Bing publish the addresses of their crawlers. Exempting them
makes search crawling independent of DNS, rate limits, bans and countries.

```sh
GOOGLE=$(curl -sL https://developers.google.com/static/crawling/ipranges/common-crawlers.json \
  | jq -r '[.prefixes[] | .ipv4Prefix // .ipv6Prefix] | join(",")')
BING=$(curl -sL https://www.bing.com/toolbox/bingbot.json \
  | jq -r '[.prefixes[] | .ipv4Prefix // .ipv6Prefix] | join(",")')
CRAWLERS="$GOOGLE,$BING"

prismwaf ... -bot-protection -bot-secret-file /etc/prismwaf/bot.key \
  -bot-exempt "$CRAWLERS" -rate-limit-exempt "$CRAWLERS" -geo-exempt "$CRAWLERS"
```

- These lists contain only the crawlers' addresses, not those of cloud
  customers, so exempting them does not let others in.
- Exempt clients skip bot protection entirely, whatever their
  `User-Agent`. Their requests are still inspected for attacks.
- The lists change. Refresh them regularly, e.g. daily from a timer that
  restarts PrismWAF; with `-bot-secret-file`, users keep their clearance
  across the restart.
- `-geo-exempt` is needed only with geo filtering.

### Check that search engines get through

**Google Search Console**

- *URL Inspection* → *Test live URL*: it fetches the page as
  `Google-InspectionTool` from Google's addresses, which PrismWAF verifies.
  The screenshot and HTML must show the page, not "Checking your browser".
- *Settings* → *Crawl stats*: watch the share of `403` responses and the
  host status after enabling bot protection and after each change.
- *Pages* (indexing report): pages excluded with "Blocked due to access
  forbidden (403)" mean that Googlebot was challenged or blocked.

**Bing Webmaster Tools** has the same with *URL Inspection* and the crawl
information.

**The audit log**

```sh
# Search engines that were challenged or blocked, by name and signals
jq -r 'select(.reason == "bot" and .bot.category == "search_engine")
       | [.action, .bot.name, (.bot.signals // [] | join(",")), .client_ip] | @tsv' audit.log \
  | sort | uniq -c | sort -rn | head
# Is the address really Google's? A real one resolves to googlebot.com or google.com
dig +short -x 66.249.66.1
```

Challenged search engines with `fake_bot` from addresses that are not
theirs are impostors, which is expected. From addresses that are theirs,
check DNS. Search engines rejected by the other protections appear with
other reasons, such as `rate_limit`, `ban` or `geo`; find them by their
`User-Agent`:

```sh
jq -r 'select(.reason != "bot") | select(.request.headers["User-Agent"] // "" | test("Googlebot|bingbot"))
       | [.reason, .action, .client_ip] | @tsv' audit.log | sort | uniq -c | sort -rn
```

**From your own machine**

```sh
# An impostor: your address is not Google's, so this must be challenged (403)
curl -s -o /dev/null -w '%{http_code}\n' -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' https://example.com/
# robots.txt must stay readable for everyone (200)
curl -s -o /dev/null -w '%{http_code}\n' -A 'curl/8.0' https://example.com/robots.txt
```

## Checklist

Before enforcing:

- [ ] `-trusted-proxies` set if PrismWAF is behind a proxy or CDN
- [ ] `-bot-secret-file` shared by all instances
- [ ] `dig -x 66.249.66.1` works on the PrismWAF host
- [ ] APIs, webhooks, feeds and health checks exempted
- [ ] Monitors, partners and test machines exempted by address
- [ ] A week in detection mode, audit log reviewed
- [ ] Geo filtering, rate limits and bans do not reject search engines
- [ ] `robots.txt` matches the categories you block

After enforcing:

- [ ] Search Console live test shows the page
- [ ] Crawl stats show no rise in `403`
- [ ] Shared links still have previews, if wanted
- [ ] No `fake_bot` events from genuine search engine addresses
- [ ] Crawler range lists refreshed regularly, if used
