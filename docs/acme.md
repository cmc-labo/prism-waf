# Automatic certificates (ACME / Let's Encrypt)

PrismWAF can obtain and renew TLS certificates itself from
[Let's Encrypt](https://letsencrypt.org/) or any other CA that speaks the
[ACME protocol](https://www.rfc-editor.org/rfc/rfc8555), instead of using
certificate files. No separate client such as certbot is needed.

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Options](#options)
- [Requirements](#requirements)
- [Caveats](#caveats)
- [Logs](#logs)
- [Use cases](#use-cases)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)

## Quick start

Point the DNS records of your domains at the server, open ports 80 and 443,
and run:

```sh
prismwaf -listen :443 -http-redirect :80 \
  -acme-domains example.com,www.example.com \
  -acme-cache /var/lib/prismwaf/acme \
  -acme-directory staging \
  -backend http://127.0.0.1:8081
```

PrismWAF obtains the certificates right after starting and logs the
result:

```
level=INFO msg="ACME certificate obtained" certificate=example.com issuer="CN=(STAGING) …,O=(STAGING) Let's Encrypt,C=US" not_after=2027-02-05T02:55:43Z serial=…
```

Once this works, remove `-acme-directory staging` and restart. The
production certificates are obtained and cached separately from the
staging ones (see [Staging and production](#staging-and-production)).

## How it works

```
                 ┌──────────────────────── PrismWAF ────────────────────────┐
client ─TLS:443─▶│ -listen        certificate from the cache               │─▶ backend
                 │                answers TLS-ALPN-01 challenges           │
CA ─────HTTP:80─▶│ -http-redirect answers HTTP-01 challenges,              │
                 │                redirects everything else to HTTPS (308) │
                 └──────────────────┬───────────────────────────────────────┘
                                    ▼
              -acme-cache/<CA>/ (account key, certificates)
```

1. **At startup.** Right after its listeners are open, PrismWAF loads the
   certificate of every domain from the cache, and requests the ones that
   are missing or expired. Issuance usually takes a few seconds. A client
   that connects before then waits for the certificate (at most 5
   minutes).
2. **Validation.** The CA checks that you control the domain by connecting
   back to it. PrismWAF answers two challenge types:
   - **TLS-ALPN-01** on `-listen`: the CA must reach it as port 443. Always
     enabled.
   - **HTTP-01** on `-http-redirect`: the CA must reach it as port 80.
     Enabled only with `-http-redirect`.

   TLS-ALPN-01 is tried first; with both enabled, either one succeeding is
   enough.
3. **Caching.** The account key and every certificate are stored in a
   directory for the CA below `-acme-cache` and reused after a restart.
4. **Renewal.** Each certificate is renewed in the background a third of
   its lifetime before it expires (30 days for Let's Encrypt's 90-day
   certificates), with a small random delay. If the CA issues shorter
   certificates, renewal starts correspondingly earlier. Renewal needs no
   restart and does not interrupt connections. A failed renewal is retried
   every 30 to 60 minutes while the current certificate stays in use.
5. **Monitoring.** Every minute, PrismWAF checks each domain: a missing
   certificate is requested again once its [retry delay](#retries-after-failures)
   has passed, and a certificate that should have been renewed by now is
   logged (see [Logs](#logs)).

Each domain gets its own certificate. Clients that support ECDSA (all
current browsers) get an ECDSA P-256 certificate. Very old clients that
only support RSA get a separate RSA certificate, which is requested the
first time such a client connects.

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-acme-domains` | (none) | Comma-separated domains to obtain certificates for. Enables ACME and HTTPS on `-listen` |
| `-acme-cache` | (none) | Directory for the account key and certificates. Required |
| `-acme-email` | (none) | Contact address registered with the CA account |
| `-acme-directory` | Let's Encrypt | ACME directory URL of the CA, or `staging` for Let's Encrypt's staging environment |
| `-http-redirect` | (none) | Plain HTTP listener, e.g. `:80`: answers HTTP-01 challenges and redirects all other requests to HTTPS |

Related options that work with ACME: `-hsts-max-age` (see
[HSTS](https.md#hsts)) and `-tls-client-ca` (see
[Mutual TLS with ACME](#an-admin-portal-with-client-certificates)).

### `-acme-domains`

The only names PrismWAF requests certificates for. A client that connects
with any other name, or without a name (e.g. `https://203.0.113.10/`),
fails the TLS handshake. This prevents clients from making PrismWAF
request certificates for arbitrary names, which would quickly use up the
CA's rate limits.

- List every name clients use, e.g. both `example.com` and
  `www.example.com`.
- Names are case-insensitive. Internationalized domain names can be given
  in Unicode or Punycode.
- Wildcards (`*.example.com`) and IP addresses are rejected at startup:
  wildcard certificates need the DNS-01 challenge, which PrismWAF does not
  support.
- Names must have at least two labels; `localhost` or `intranet` cannot be
  used.

### `-acme-cache`

Holds the private keys of the account and of every certificate, in one
subdirectory per CA, named after its directory URL:

```
/var/lib/prismwaf/acme/
├── acme-v02.api.letsencrypt.org-directory/           Let's Encrypt
│   ├── directory-url        the CA's directory URL
│   ├── acme_account+key     the ACME account key
│   ├── example.com          ECDSA certificate chain and private key
│   ├── example.com+rsa      RSA certificate, if an RSA-only client connected
│   └── *+token, *+http-01   temporary challenge data
└── acme-staging-v02.api.letsencrypt.org-directory/   Let's Encrypt staging
    └── …
```

At startup, PrismWAF:

- creates the directories with mode `0700` if they do not exist, and
  checks that it can write to them. If not, it stops with an error such as
  `ACME cache directory is not writable: … permission denied`, instead of
  failing later when the first certificate is issued.
- warns if `-acme-cache` is accessible by other users
  (`ACME cache directory is accessible by other users`). Fix it with
  `chmod 700`.
- refuses to start if the subdirectory's `directory-url` names another CA,
  which can only happen if files were copied by hand.

To prepare the directory for an unprivileged user:

```sh
sudo install -d -o prismwaf -g prismwaf -m 0700 /var/lib/prismwaf/acme
```

Keep the directory across restarts, deployments and container rebuilds
(e.g. on a persistent volume). Losing it means requesting all
certificates again, which can hit the rate limits. Back it up like any
other private key material.

**Caches of older versions.** Versions before the per-CA layout kept the
files directly in `-acme-cache`. They are moved automatically at startup,
and each move is logged (`ACME cache: moved file to the directory of its
CA`):

| Old file | Moved to |
|----------|----------|
| Certificate from Let's Encrypt staging (issuer `(STAGING) …`) | The staging directory |
| Other certificate | The directory of the configured CA. If that is staging, the file stays in place until PrismWAF runs with its CA |
| Account key | The directory of the configured CA, together with the certificates |
| Temporary challenge data | Deleted |

Files that are not cache entries are left alone. If the target already
exists, the old file stays in place and a warning names both.

### `-acme-email`

Registered as the contact address of the CA account. Let's Encrypt no
longer sends expiry reminder emails, so do not rely on it for monitoring;
see [Monitor certificate expiry](#monitor-certificate-expiry). The address
is registered when the account is created, on the first certificate
request with an empty cache; changing `-acme-email` later does not update
an existing account.

### `-acme-directory`

| Value | CA |
|-------|----|
| (empty) | Let's Encrypt production: `https://acme-v02.api.letsencrypt.org/directory` |
| `staging` | Let's Encrypt staging: `https://acme-staging-v02.api.letsencrypt.org/directory`. Much higher rate limits, but the certificates are not trusted by browsers |
| A URL | Any other ACME CA, e.g. an internal [step-ca](https://smallstep.com/docs/step-ca/) |

PrismWAF connects to the directory over HTTPS and verifies it against the
system's trusted CAs. For a CA with a private root certificate, add that
root to the system trust store, or set the `SSL_CERT_FILE` environment
variable to a file with the roots to trust.

CAs that require external account binding (EAB), such as ZeroSSL or
Google Trust Services, are not supported.

### `-http-redirect`

A plain HTTP listener with two jobs:

- Requests for `/.well-known/acme-challenge/…` with a configured domain in
  `Host` are answered for HTTP-01 validation (unknown tokens get `404`,
  other hosts `403`).
- All other requests get `308 Permanent Redirect` to the same URL over
  HTTPS. Nothing is proxied in plain HTTP.

The redirect uses the port of `-listen`: with `-listen :443` it points to
`https://example.com/…`, with `-listen :8443` to `https://example.com:8443/…`.

## Requirements

Before the first start, check:

- **DNS.** The `A` (and `AAAA`, if any) records of every domain point to
  the server. If a domain has an `AAAA` record, Let's Encrypt prefers
  IPv6 for validation, so a server that is not reachable over IPv6 can
  fail validation; make it reachable or remove the record.
- **Ports.** The CA must reach `-listen` as port 443 (TLS-ALPN-01) or
  `-http-redirect` as port 80 (HTTP-01) from the internet. The CA validates
  from several locations whose addresses are not published, so the ports
  cannot be restricted to the CA's IP addresses.
- **TLS end to end.** PrismWAF must receive the TLS connection itself. A
  load balancer, CDN or reverse proxy in front of it must pass TCP through
  (layer 4); one that terminates TLS cannot be combined with ACME in
  PrismWAF. Use the certificates of that service, or `-tls-cert`, instead.
- **CAA records.** If the domain has [CAA](https://letsencrypt.org/docs/caa/)
  DNS records, they must allow the CA, e.g. `0 issue "letsencrypt.org"`.
- **Privileges.** Ports below 1024 need root or the
  `CAP_NET_BIND_SERVICE` capability; see
  [Run as a systemd service](#run-as-a-systemd-service).
- **Outgoing HTTPS** from the server to the CA's directory.

## Caveats

### Terms of service

Using `-acme-domains` means accepting the CA's terms of service (for Let's
Encrypt, its [Subscriber Agreement](https://letsencrypt.org/repository/)).
PrismWAF accepts them automatically when it creates the account.

### Rate limits

Let's Encrypt limits how many certificates can be issued. At the time of
writing, the most relevant limits are:

| Limit | Value |
|-------|-------|
| New certificates per registered domain (e.g. all of `*.example.com`) | 50 per 7 days |
| New certificates for the same exact set of names | 5 per 7 days |
| Failed validations per name and account | 5 per hour |

See [Rate Limits](https://letsencrypt.org/docs/rate-limits/) for the
current values. Since PrismWAF requests one certificate per name, every
name in `-acme-domains` counts separately. To stay within the limits:

- Test new setups with `-acme-directory staging`.
- Keep `-acme-cache` across restarts.
- Read the `ACME validation failed` log and fix the cause before
  restarting: PrismWAF waits between attempts (see below), but a restart
  starts over and tries again immediately.

### Retries after failures

A failed certificate request is not retried at every connection. PrismWAF
waits, doubling the delay after each consecutive failure of the same
certificate:

| Failure | Next attempt after |
|--------:|-------------------:|
| 1 | 10 minutes |
| 2 | 20 minutes |
| 3 | 40 minutes |
| 4 | 80 minutes |
| 5 and later | 2 hours |

If the CA answers with a rate limit error, PrismWAF waits at least as long
as the CA's `Retry-After` says (one hour if it says nothing). During the
delay, clients connecting with that name fail the TLS handshake at once
instead of waiting. Other domains, and the RSA certificate of the same
domain, are not affected.

The delays are kept in memory. To try again right away after fixing a
problem, restart PrismWAF.

Renewals of existing certificates are retried by the ACME library every
30 to 60 minutes instead; the current certificate stays in use meanwhile.

### Staging and production

Every CA has its own cache directory, so switching between Let's
Encrypt's staging environment and production needs no manual steps:

```sh
# 1. Test: certificates go to acme/acme-staging-v02.api.letsencrypt.org-directory/
prismwaf ... -acme-directory staging -acme-cache /var/lib/prismwaf/acme
# 2. Production: certificates go to acme/acme-v02.api.letsencrypt.org-directory/
prismwaf ... -acme-cache /var/lib/prismwaf/acme
```

In step 2, PrismWAF finds no production certificates and requests them;
the staging certificates are kept but not used. Switching back to staging
uses the staging certificates again, if they have not expired. The same
applies to any two CAs.

A staging certificate in the production directory, for example copied
there by hand or left by an older version, is moved to the staging
directory at startup with the warning `ACME cache: moving a Let's Encrypt
staging certificate out of the cache of another CA`. While staging is
configured, PrismWAF logs `using the Let's Encrypt staging environment:
certificates are not trusted by browsers` at startup.

### `SIGHUP` terminates PrismWAF

In ACME mode, certificates are renewed automatically and `SIGHUP` is not
handled, so it terminates the process like `SIGTERM`. Do not reuse a
`pkill -HUP prismwaf` hook from a certbot setup, and do not set
`ExecReload=` to send `SIGHUP` in a systemd unit.

### First connection

Certificates are requested at startup, so clients normally do not wait.
Only a client that connects in the few seconds while a certificate is
being issued, or an RSA-only client (whose certificate is only requested
when needed), waits for it.

### Mutual exclusions

`-acme-domains` cannot be combined with `-tls-cert`/`-tls-key`. All
domains of one PrismWAF instance use either ACME or certificate files.

## Logs

PrismWAF writes ACME events to its operational log (standard error):

| Level | Message | Meaning |
|-------|---------|---------|
| INFO | `ACME certificate obtained` | A certificate was issued or renewed and stored in the cache. With `issuer`, `not_after` and `serial` |
| INFO | `ACME certificate ready` | A certificate from the cache is in use, logged once after startup |
| WARN | `ACME validation failed` | The CA could not validate a domain. With the `challenge`, the CA's `problem` type and `detail`, and a `hint` |
| WARN | `ACME request rejected` | The CA rejected a request, e.g. with a rate limit. With `status`, `problem`, `detail`, `retry_after` and a `hint` |
| ERROR | `ACME certificate request failed` | A certificate could not be obtained. With the `error`, the `validation` errors of the attempt, a `hint`, the number of consecutive `failures` and when the next attempt is made (`retry_in`, `retry_at`) |
| INFO | `ACME certificate available again` | A certificate was obtained after failures |
| WARN | `ACME certificate not renewed yet` | Less than half of the renewal period is left, so renewal has been failing for a while. Logged daily |
| ERROR | `ACME certificate expired` | The certificate in use has expired. Logged hourly |
| ERROR | `cannot write ACME cache; …` | A certificate could not be stored, e.g. because the disk is full; it would be requested again after a restart |
| WARN | `using the Let's Encrypt staging environment: …` | Staging is configured |

The library that implements ACME only reports that no challenge
succeeded; the CA's reason is taken from its responses and logged as
`ACME validation failed`, then repeated in the `validation` field of the
error:

```
level=WARN msg="ACME validation failed" domain=example.com challenge=tls-alpn-01 problem=urn:ietf:params:acme:error:connection detail="203.0.113.10: Timeout during connect (likely firewall problem)" hint="the CA could not connect: check that the domain's DNS records point to this server and that -listen is reachable as port 443 (TLS-ALPN-01) or -http-redirect as port 80 (HTTP-01) from the internet"
level=ERROR msg="ACME certificate request failed" domain=example.com certificate=example.com error="acme/autocert: unable to satisfy … for domain \"example.com\": no viable challenge type found" validation="tls-alpn-01: urn:ietf:params:acme:error:connection: 203.0.113.10: Timeout during connect (likely firewall problem)" hint="the CA could not connect: …" failures=1 retry_in=10m0s retry_at=2026-11-07T12:05:05Z
```

To follow only ACME events:

```sh
journalctl -u prismwaf -f | grep -E 'ACME|acme'
```

## Use cases

### A public website

A site with `example.com` and `www.example.com`, plain HTTP redirected to
HTTPS, and HSTS once HTTPS is confirmed working:

```sh
prismwaf -listen :443 -http-redirect :80 \
  -acme-domains example.com,www.example.com \
  -acme-cache /var/lib/prismwaf/acme \
  -acme-email admin@example.com \
  -hsts-max-age 5m \
  -backend http://127.0.0.1:3000
```

Raise `-hsts-max-age` to e.g. `8760h` after a few days without problems.
The backend sees `X-Forwarded-Proto: https`.

### Only port 443 is open

If port 80 cannot be opened, leave out `-http-redirect`. Validation then
uses TLS-ALPN-01 on port 443 only, which PrismWAF logs at startup:

```
level=INFO msg="ACME HTTP-01 challenge disabled; TLS-ALPN-01 requires -listen to be reachable on port 443"
```

Clients that type `http://example.com` then get no answer instead of a
redirect, so combine this with HSTS.

### Testing a new setup

Try the setup with the staging environment and check the log and the
certificate's issuer:

```sh
prismwaf -listen :443 -http-redirect :80 \
  -acme-domains example.com -acme-directory staging \
  -acme-cache /var/lib/prismwaf/acme

curl -skv https://example.com/ 2>&1 | grep 'issuer:'
# issuer: C=US; O=(STAGING) Let's Encrypt; ...
```

Then remove `-acme-directory staging` and restart; keep the same
`-acme-cache` (see [Staging and production](#staging-and-production)).

### Run as a systemd service

Run PrismWAF as an unprivileged user that may bind ports 80 and 443, with
the cache in the service's state directory:

```ini
# /etc/systemd/system/prismwaf.service
[Unit]
Description=PrismWAF
After=network-online.target
Wants=network-online.target

[Service]
User=prismwaf
Group=prismwaf
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
StateDirectory=prismwaf
StateDirectoryMode=0700
ExecStart=/usr/local/bin/prismwaf \
  -listen :443 -http-redirect :80 \
  -acme-domains example.com,www.example.com \
  -acme-cache /var/lib/prismwaf/acme \
  -backend http://127.0.0.1:3000 \
  -audit-log /var/log/prismwaf/audit.log
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin prismwaf
sudo install -d -o prismwaf -g prismwaf -m 0750 /var/log/prismwaf
sudo systemctl daemon-reload
sudo systemctl enable --now prismwaf
journalctl -u prismwaf -f
```

There is no `ExecReload=`; see [`SIGHUP` terminates PrismWAF](#sighup-terminates-prismwaf).

### Behind a TCP load balancer or port forwarding

ACME works behind a layer 4 load balancer or NAT that forwards ports 80
and 443 unchanged. Let PrismWAF listen on the same ports it is reached on,
because the HTTPS redirect uses the port of `-listen`: with external port
443 forwarded to `-listen :8443`, redirects would point to port 8443.

The client IP in the audit log is the load balancer's address unless it
preserves the source address (e.g. AWS Network Load Balancer with client
IP preservation). `-trusted-proxies` does not help here: it reads
`X-Forwarded-For`, which a TCP load balancer cannot add to encrypted
traffic.

### An admin portal with client certificates

Mutual TLS and ACME can be combined. The CA's TLS-ALPN-01 validation
connections are exempted from client authentication; they cannot be used
to send requests.

```sh
prismwaf -listen :443 \
  -acme-domains admin.example.com -acme-cache /var/lib/prismwaf/acme \
  -tls-client-ca staff-ca.pem \
  -backend http://127.0.0.1:9000
```

The portal is still reachable for validation on port 443, and only staff
with a certificate can use it. See [Client certificates](https.md#client-certificates-mutual-tls).

### Internal services with a private ACME CA

For internal domains that a public CA cannot validate, run an internal
ACME CA such as [step-ca](https://smallstep.com/docs/step-ca/) and point
PrismWAF at it. The internal CA must be able to reach PrismWAF on ports
443 or 80, and PrismWAF must trust the CA's root certificate:

```sh
SSL_CERT_FILE=/etc/prismwaf/internal-root.pem prismwaf -listen :443 \
  -acme-domains app.corp.example \
  -acme-directory https://ca.corp.example/acme/acme/directory \
  -acme-cache /var/lib/prismwaf/acme-internal \
  -backend http://127.0.0.1:8080
```

`SSL_CERT_FILE` replaces the system's trusted CAs for all of PrismWAF's
outgoing connections, including `https://` backends without
`-backend-ca`. To keep the public CAs as well, add the internal root to
the system trust store instead.

### Several PrismWAF instances

Running several instances with ACME for the same domains is possible but
not recommended. Each instance requests and renews certificates on its
own, instances started at the same time may each request the same
certificate, retry delays are not shared, and the challenge must be
answered by the instance the CA connects to. If you do, share one
`-acme-cache` directory between them (e.g. on a network file system):
PrismWAF stores the challenge data there as well, so any instance can
answer, and an instance started later uses the certificates already
there. For larger clusters, obtain certificates with a separate ACME
client (e.g. certbot) and distribute them as files for `-tls-cert`, which
also supports reloading with `SIGHUP`.

### Monitor certificate expiry

Renewal is automatic, but monitor it. PrismWAF logs `ACME certificate
not renewed yet` (WARN) and `ACME certificate expired` (ERROR); alert on
these and on `ACME certificate request failed`. Also check the expiry
date from outside, which catches problems the log cannot, such as a
stopped process:

```sh
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -enddate
# notAfter=Feb  4 10:12:33 2027 GMT
```

Alert if fewer than about 20 days remain for a 90-day certificate:
renewal starts 30 days before expiry, so this leaves about ten days to
fix a problem.

### Moving from certbot

To replace a certbot setup that used `-tls-cert` and `-tls-key`:

1. Replace `-tls-cert`/`-tls-key` with `-acme-domains` and `-acme-cache`.
   Existing certbot certificates are not imported; new ones are obtained,
   which counts toward the rate limits.
2. Remove the certbot deploy hook that sends `SIGHUP` to PrismWAF and
   disable certbot's renewal for these domains (`certbot delete --cert-name …`
   or its systemd timer), so that it no longer needs port 80.
3. Restart PrismWAF; it obtains the new certificates at startup.

## Troubleshooting

Look for `ACME validation failed`, `ACME request rejected` and `ACME
certificate request failed` in the log (see [Logs](#logs)); the `hint`
field suggests what to check. The most common problems:

| Problem type or message | Cause | Fix |
|-------------------------|-------|-----|
| `…:connection` | The CA could not connect to port 443 or 80 | Check DNS, firewall, port forwarding, and IPv6 (`AAAA` records) |
| `…:dns` | The CA could not resolve the domain | Check the `A` and `AAAA` records |
| `…:unauthorized` | The CA reached a server that gave the wrong answer | Make sure the DNS records point to this server and nothing in front of it terminates TLS |
| `…:tls` | TLS failed during validation | A proxy in front of PrismWAF may terminate TLS |
| `…:caa` | A CAA record does not allow the CA | Add the CA to the CAA records |
| `…:rateLimited` | A rate limit was hit | Wait until `retry_at`; test with staging |
| `…:externalAccountRequired` | The CA requires EAB | Not supported; use another CA or certificate files |
| `cannot reach the ACME CA` (hint) | No connection to the CA's directory | Check outgoing HTTPS, proxies and `-acme-directory` |
| `ACME cache directory is not writable` (at startup) | Wrong owner or mode of `-acme-cache` | `chown` the directory to the PrismWAF user and `chmod 700` it |
| `ACME cache directory … belongs to …` (at startup) | A CA's subdirectory was copied by hand | Move it back or remove it |

Failed TLS handshakes of clients are logged as well, at WARN:

| Message contains | Cause |
|------------------|-------|
| `not configured in HostWhitelist` | A client used a name that is not in `-acme-domains`; add it if it is yours, otherwise it is a scanner |
| `missing server name` | A client connected without SNI, e.g. by IP address |
| `no certificate for … next attempt in …` | The certificate is waiting for its retry delay after a failure |

To check what certificate is served for a name:

```sh
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

## Limitations

- Only the TLS-ALPN-01 and HTTP-01 challenges are supported. DNS-01, and
  therefore wildcard certificates, are not.
- Certificates for IP addresses are not supported.
- External account binding (EAB) is not supported, which rules out CAs
  that require it.
- Certificates cannot be revoked through PrismWAF.
- `-acme-domains` and `-tls-cert` cannot be mixed in one instance.
- Retry delays are kept in memory and start over after a restart.
- Renewal failures of existing certificates are retried every 30 to 60
  minutes by the ACME library, without the longer delays above.
