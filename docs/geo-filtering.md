# Geo filtering

PrismWAF can look up the country of each client in a GeoIP database and
allow or block requests by country. This reduces the attack surface of
services that are only used in some countries, and lets you block
countries that send only attacks.

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -geo-db /var/lib/prismwaf/country.mmdb \
  -geo-allow JP,US
```

Clients from Japan and the United States reach the backend. Clients from
other countries, and public addresses with no country in the database, get
`403 Forbidden` and are logged in the [audit log](audit-log.md). The
backend is told the country of every client in the `X-Prismwaf-Country`
header.

- [Options](#options)
- [Country databases](#country-databases)
- [How it works](#how-it-works)
- [Responses and audit events](#responses-and-audit-events)
- [Use cases](#use-cases)
- [Logs](#logs)
- [Limitations](#limitations)

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-geo-db` | (none) | MaxMind DB file (`.mmdb`) to look up countries in. Reloaded when it changes |
| `-geo-allow` | (none) | Comma-separated country codes to allow; all other countries are blocked |
| `-geo-block` | (none) | Comma-separated country codes to block |
| `-geo-exempt` | (none) | Comma-separated IPs/CIDRs of clients that are never blocked by country |

- Countries are [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2)
  codes, in any case: `JP`, `us`, `DE`. `XX` stands for public addresses
  that the database has no country for.
- Codes that are not countries are rejected at startup, including common
  mistakes: `UK` (the code is `GB`), `EU`, `JPN`, `Japan`.
- `-geo-allow` and `-geo-block` are mutually exclusive.
- `-geo-db` alone blocks nothing. It only passes the country to the
  backend and adds it to audit events.
- Geo filtering is off unless `-geo-db` is given. The other options require
  it.

## Country databases

PrismWAF reads databases in the MaxMind DB format (`.mmdb`), which most
providers offer:

| Database | Provider | Access |
|----------|----------|--------|
| GeoLite2 Country, GeoLite2 City | [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | Free account and license key; GeoLite2 EULA |
| GeoIP2 Country, GeoIP2 City | MaxMind | Paid |
| IP to Country Lite | [DB-IP](https://db-ip.com/db/download/ip-to-country-lite) | Free download, monthly; CC BY 4.0, attribution required |
| IPinfo Lite | [IPinfo](https://ipinfo.io/lite) | Free account and token |

Check each provider's terms before use. A country database is enough;
city databases are larger, but work as well. Tested with DB-IP IP to
Country Lite (November 2026) and with test databases in the GeoLite2 and
IPinfo formats, see [Testing](testing.md#geo-filtering).

PrismWAF reads the country from `country.iso_code` (MaxMind, DB-IP),
then `registered_country.iso_code` (MaxMind gives only this for some
networks, e.g. anycast ones), then `country_code` (IPinfo). Databases
that cover only IPv4 can be used, but IPv6 clients are then `XX`.

At startup, PrismWAF rejects a file that is not a valid MaxMind DB, is
truncated, or has no country for `8.8.8.8` or `1.1.1.1` (e.g. an ASN
database by mistake). It warns if the database is more than 60 days old.

### Download and updates

With MaxMind's [`geoipupdate`](https://github.com/maxmind/geoipupdate),
set `EditionIDs GeoLite2-Country` in `GeoIP.conf` and run it twice a week,
e.g. from cron:

```sh
geoipupdate -d /var/lib/prismwaf
# -geo-db /var/lib/prismwaf/GeoLite2-Country.mmdb
```

DB-IP publishes a new file each month:

```sh
#!/bin/sh
# /etc/cron.weekly/prismwaf-geoip
set -e
dir=/var/lib/prismwaf
curl -fsSL "https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz" -o "$dir/country.mmdb.gz"
gunzip -c "$dir/country.mmdb.gz" > "$dir/country.mmdb.new"
mv "$dir/country.mmdb.new" "$dir/country.mmdb"
```

Early in a month, before the new file is published, `curl` fails and the
current file is kept.

Whatever tool you use, **replace the file in one step**: write the new
file next to the old one, then rename it over the old one (`mv`), as
`geoipupdate` does. PrismWAF checks the file every minute and reloads it
when its size or modification time changes, without a restart. If it
catches a file that is still being written, or the new file is invalid, it
logs `cannot reload the GeoIP database; keeping the one in use` and keeps
filtering with the previous database. It tries again when the file
changes.

The file is read into memory: about 8 MB for a country database. A lookup
takes well under a microsecond.

## How it works

### Which clients are looked up

The client address is the TCP peer, or, behind a proxy listed in
`-trusted-proxies`, the address it reports in `X-Forwarded-For` (see
[Client IP](audit-log.md#client-ip)). **Behind a load balancer or CDN,
set `-trusted-proxies`**, or the proxy's address is looked up for every
client. PrismWAF logs a reminder at startup when it is not set.

Addresses that are not on the public Internet have no country and always
pass, without a lookup:

- loopback (`127.0.0.0/8`, `::1`), private (`10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), link-local
  (`169.254.0.0/16`, `fe80::/10`) and shared address space
  (`100.64.0.0/10`, used inside carrier networks)
- clients that are not IP addresses, e.g. on a Unix socket

So health checks and internal clients are not blocked by an allow list.

### Decisions

| Setting | Allowed | Blocked |
|---------|---------|---------|
| `-geo-allow JP,US` | Clients from Japan and the United States | All other countries, and `XX` |
| `-geo-allow JP,US,XX` | Also public addresses with no country | All other countries |
| `-geo-block CN,RU` | All other countries, and `XX` | Clients from China and Russia |
| `-geo-block CN,RU,XX` | All other countries | Also public addresses with no country |

Clients in `-geo-exempt` are never blocked by country; their country is
still passed to the backend. As for the other exemptions, give single
addresses or CIDRs, e.g. `-geo-exempt 198.51.100.0/24,2001:db8:1::/48`.

### Order of processing

The country is checked first, before [rate limits](rate-limiting.md),
[bot protection](bot-protection.md) and inspection. Blocked clients do not
use up rate limits and are not challenged, and PrismWAF does not inspect
their requests.

### The country for the backend and in audit events

PrismWAF sets `X-Prismwaf-Country` on every request it forwards, e.g.
`X-Prismwaf-Country: JP`, or `XX` for unknown. It is absent for private
addresses. A value sent by the client is removed, so the backend can trust
the header if it is only reachable through PrismWAF. Use it, for example,
to choose a language or to require more checks from some countries.

With `-geo-db`, every audit event, of any reason, has a `country` field.

## Responses and audit events

In block mode (`-mode block`, the default), a client from a country that is
not allowed gets:

```
HTTP/1.1 403 Forbidden
Content-Type: text/plain; charset=utf-8

Forbidden
Event ID: 4e1f0a9c2b7d3856
```

In detection mode (`-mode detect`), the request is forwarded and only
logged, with `"action": "detect"`. Use it to see who would be blocked
before you enforce a list; see [Roll out a country list](#roll-out-a-country-list).

To keep the audit log readable, only the **first** blocked request of a
client is logged, then at most one a minute. The following requests
return the same event ID. An IPv6 client counts as its `/64` network.

```json
{
  "time": "2026-11-17T03:12:45.120Z",
  "id": "4e1f0a9c2b7d3856",
  "client_ip": "198.51.100.7",
  "remote_addr": "10.0.0.5:51544",
  "country": "CN",
  "action": "block",
  "reason": "geo",
  "geo": { "list": "allow", "client": "198.51.100.7/32" },
  "request": {
    "method": "GET",
    "uri": "/login",
    "proto": "HTTP/1.1",
    "host": "shop.example.com",
    "content_length": 0,
    "headers": { "User-Agent": "Mozilla/5.0 …", "X-Prismwaf-Country": "CN" }
  }
}
```

| Field | Description |
|-------|-------------|
| `country` | The client's country, `XX` if unknown |
| `geo.list` | `allow` if the country is not in `-geo-allow`, `block` if it is in `-geo-block` |
| `geo.client` | What the event is counted for: the client address as `/32`, or its `/64` network for IPv6 |

```sh
# Blocked clients per country
jq -r 'select(.reason == "geo") | .country' audit.log | sort | uniq -c | sort -rn
# Attacks per country, of any reason
jq -r '.country // "-"' audit.log | sort | uniq -c | sort -rn
```

## Use cases

### Allow only the countries of your users

A shop that sells only in Japan:

```sh
prismwaf -backend http://127.0.0.1:3000 -trusted-proxies 10.0.0.0/8 \
  -geo-db /var/lib/prismwaf/GeoLite2-Country.mmdb \
  -geo-allow JP \
  -geo-exempt 203.0.113.10,198.51.100.0/24
```

Exempt the external services that must reach you, e.g. a payment
provider's callbacks or an uptime monitor abroad. Search engine crawlers
mostly come from the United States: allow `US` as well, or exempt their
networks, if you want to stay in search results.

### Block countries that only send attacks

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -geo-db /var/lib/prismwaf/country.mmdb \
  -geo-block CN,RU,KP
```

Find candidates in the audit log with the `country` field, see
[Responses and audit events](#responses-and-audit-events).

### Pass the country to the application

```sh
prismwaf -backend http://127.0.0.1:3000 -geo-db /var/lib/prismwaf/country.mmdb
```

Nothing is blocked, and the backend reads `X-Prismwaf-Country`.

### Roll out a country list

1. Start with `-mode detect` and the list you plan.
2. After some days, look at what would have been blocked:
   ```sh
   jq -r 'select(.reason == "geo") | [.country, .request.uri] | @tsv' audit.log | sort | uniq -c | sort -rn | head -50
   ```
3. Exempt the legitimate clients that show up, then switch to
   `-mode block`.

Detection mode applies to all of PrismWAF; attacks are not blocked either
while it is on.

## Logs

| Level | Message | Meaning |
|-------|---------|---------|
| INFO | `GeoIP enabled` | At startup: the `db` file, its `type` and `built` date, and the `allow`, `block` and `exempt` options |
| INFO | `countries are looked up for the TCP peer address; …` | At startup without `-trusted-proxies` |
| WARN | `the GeoIP database is outdated` | At startup or reload, for a database built more than 60 days ago |
| WARN | `the GeoIP database has only IPv4 addresses; IPv6 clients are unknown (XX)` | At startup |
| INFO | `GeoIP database reloaded` | The file changed and was loaded, with its `type` and `built` date |
| ERROR | `cannot reload the GeoIP database; keeping the one in use` | The changed file is missing or invalid, with the `error`. Logged once per change of the file |

## Limitations

- **Locations are not identities.** VPNs, proxies, Tor and cloud servers
  let anyone appear to come from an allowed country. Geo filtering reduces
  noise and opportunistic attacks; it does not replace authentication or
  the other protections.
- **Databases are not perfect.** Country data is usually right for fixed
  and mobile networks, but addresses move between countries, and some
  networks (satellite, international carriers, roaming mobile users) appear
  in another country. Keep the database current and exempt clients that
  are blocked by mistake.
- The country is the only criterion: there is no filtering by region, city
  or network (ASN), and the lists apply to every path and host name.
- Country headers set by a CDN, such as `CF-IPCountry`, are not used;
  PrismWAF looks up the client address that `-trusted-proxies` gives it.
