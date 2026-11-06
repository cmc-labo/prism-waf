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

Then request each domain once to obtain its certificate:

```sh
curl -sI https://example.com/      # staging certificates are untrusted: add -k
curl -sI https://www.example.com/
```

Once this works, switch to the production CA: remove `-acme-directory
staging` **and use a new, empty `-acme-cache` directory** (see
[Staging and production](#staging-and-production)).

## How it works

```
                 ┌──────────────────────── PrismWAF ────────────────────────┐
client ─TLS:443─▶│ -listen        certificate from cache, or obtained now  │─▶ backend
                 │                answers TLS-ALPN-01 challenges           │
CA ─────HTTP:80─▶│ -http-redirect answers HTTP-01 challenges,              │
                 │                redirects everything else to HTTPS (308) │
                 └──────────────────┬───────────────────────────────────────┘
                                    ▼
                         -acme-cache (account key, certificates)
```

1. **On demand.** A certificate is obtained the first time a client
   connects with that name (TLS SNI), not at startup. That client's
   handshake waits until the certificate is issued, which usually takes a
   few seconds and is given up after 5 minutes. Clients connecting at the
   same time for the same name wait for the same certificate.
2. **Validation.** The CA checks that you control the domain by connecting
   back to it. PrismWAF answers two challenge types:
   - **TLS-ALPN-01** on `-listen`: the CA must reach it as port 443. Always
     enabled.
   - **HTTP-01** on `-http-redirect`: the CA must reach it as port 80.
     Enabled only with `-http-redirect`.

   TLS-ALPN-01 is tried first; with both enabled, either one succeeding is
   enough.
3. **Caching.** The account key and every certificate are stored in
   `-acme-cache` and reused after a restart.
4. **Renewal.** Each certificate is renewed in the background a third of
   its lifetime before it expires (30 days for Let's Encrypt's 90-day
   certificates), with a small random delay. If the CA issues shorter
   certificates, renewal starts correspondingly earlier. Renewal needs no
   restart and does not interrupt connections. After a restart, a cached
   certificate's renewal is scheduled when it is first used; an expired
   cached certificate is replaced on the next connection.

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

Holds the private keys of the account and of every certificate. The
directory is created with mode `0700` and the files with mode `0600` when
the first certificate is obtained, not at startup, so make sure the user
running PrismWAF can create it:

```sh
sudo install -d -o prismwaf -g prismwaf -m 0700 /var/lib/prismwaf/acme
```

| File | Contents |
|------|----------|
| `acme_account+key` | The ACME account key |
| `example.com` | ECDSA certificate chain and private key for `example.com` |
| `example.com+rsa` | RSA certificate for `example.com`, if an RSA-only client connected |
| `*+token`, `*+http-01` | Temporary challenge data, deleted after validation |

Keep the directory across restarts, deployments and container rebuilds
(e.g. on a persistent volume). Losing it means requesting all
certificates again, which can hit the rate limits. Back it up like any
other private key material.

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
- Fix validation errors before retrying; a failed request is retried at
  the next connection for that name after one minute, so a broken setup
  that receives traffic keeps failing.

### Staging and production

The cache does not record which CA issued a certificate. A certificate
obtained from staging stays in the cache after removing `-acme-directory
staging`, and PrismWAF keeps serving the untrusted staging certificate
until it is renewed. Use a separate cache directory for each CA:

```sh
# staging
prismwaf ... -acme-directory staging -acme-cache /var/lib/prismwaf/acme-staging
# production
prismwaf ... -acme-cache /var/lib/prismwaf/acme
```

The same applies when switching between any two CAs.

### `SIGHUP` terminates PrismWAF

In ACME mode, certificates are renewed automatically and `SIGHUP` is not
handled, so it terminates the process like `SIGTERM`. Do not reuse a
`pkill -HUP prismwaf` hook from a certbot setup, and do not set
`ExecReload=` to send `SIGHUP` in a systemd unit.

### First connection

The first client to connect with a new name waits for the certificate to
be issued. Warm up the cache after deploying or adding a domain by
requesting each name once, e.g. `curl -sI https://example.com/`.

### Mutual exclusions

`-acme-domains` cannot be combined with `-tls-cert`/`-tls-key`. All
domains of one PrismWAF instance use either ACME or certificate files.

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

Try the setup with the staging environment and its own cache, and check
the certificate's issuer:

```sh
prismwaf -listen :443 -http-redirect :80 \
  -acme-domains example.com -acme-directory staging \
  -acme-cache /var/lib/prismwaf/acme-staging

curl -skv https://example.com/ 2>&1 | grep 'issuer:'
# issuer: C=US; O=(STAGING) Let's Encrypt; ...
```

Then switch to production with the production cache directory.

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
not recommended. Each instance renews certificates on its own, and the
challenge must be answered by the instance the CA connects to. If you do,
share one `-acme-cache` directory between them (e.g. on a network file
system): PrismWAF stores the challenge data there as well, so any instance
can answer. For larger clusters, obtain certificates with a separate ACME
client (e.g. certbot) and distribute them as files for `-tls-cert`, which
also supports reloading with `SIGHUP`.

### Monitor certificate expiry

Renewal is automatic, but monitor it, since a failing renewal is only
visible in PrismWAF's log. For example, check the expiry date from
outside:

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
3. Request each domain once to obtain the new certificates.

## Troubleshooting

Certificate errors appear in PrismWAF's operational log (standard error)
as failed TLS handshakes, and the client sees a TLS error:

```
level=WARN msg="http: TLS handshake error from 198.51.100.7:51234: acme/autocert: host \"test.example.com\" not configured in HostWhitelist"
```

| Message contains | Cause | Fix |
|------------------|-------|-----|
| `not configured in HostWhitelist` | A client used a name that is not in `-acme-domains` | Add the name if it is yours; otherwise this is a scanner and can be ignored |
| `missing server name` | A client connected without SNI, e.g. by IP address | Expected; connect by domain name |
| `server name component count invalid` | A single-label name such as `localhost` | Use a fully qualified domain name |
| `Timeout during connect`, `Connection refused` | The CA could not reach port 443 or 80 | Check DNS, firewall, port forwarding, IPv6 (`AAAA`) |
| `CAA record … prevents issuance` | A CAA record does not allow the CA | Add the CA to the CAA records |
| `rateLimited` | A rate limit was hit | Wait for the time in the message; test with staging |
| `permission denied` | The cache directory cannot be created or written | Fix the owner and mode of `-acme-cache` |

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
