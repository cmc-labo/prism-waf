# HTTPS

## Serving HTTPS to clients

Pass a certificate and key to serve HTTPS on `-listen`:

```sh
go run ./cmd/prismwaf -listen :443 \
  -tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
  -tls-key  /etc/letsencrypt/live/example.com/privkey.pem \
  -http-redirect :80
```

- TLS 1.2 or later is required; Go's default cipher suites are used.
- HTTP/2 is negotiated automatically.
- `-http-redirect` starts a plain HTTP listener that answers every request
  with `308 Permanent Redirect` to the same URL over HTTPS. It does not
  proxy anything.
- Send `SIGHUP` to reload the certificate without dropping connections,
  e.g. from a certbot deploy hook:
  `certbot renew --deploy-hook "pkill -HUP prismwaf"`.
  If the new files cannot be loaded, the current certificate stays in use
  and an error is logged.
- The backend receives `X-Forwarded-Proto: https`.

For local testing, create a self-signed certificate:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
  -keyout key.pem -out cert.pem
go run ./cmd/prismwaf -listen :8443 -tls-cert cert.pem -tls-key key.pem
curl --cacert cert.pem https://localhost:8443/
```

## Several domains (SNI)

Repeat `-tls-cert` and `-tls-key` in pairs. Each connection gets the first
certificate that is valid for the server name the client requests; clients
that request no name or an unknown one get the first certificate. All
certificates are reloaded on `SIGHUP`, and if any of them fails to load,
all current ones stay in use.

```sh
go run ./cmd/prismwaf -listen :443 \
  -tls-cert example.com.pem -tls-key example.com.key \
  -tls-cert example.org.pem -tls-key example.org.key
```

An RSA and an ECDSA certificate for the same name can be combined in the
same way; each client gets one it supports.

## Automatic certificates (ACME / Let's Encrypt)

PrismWAF can obtain and renew certificates itself instead of using
certificate files:

```sh
go run ./cmd/prismwaf -listen :443 -http-redirect :80 \
  -acme-domains example.com,www.example.com \
  -acme-cache /var/lib/prismwaf/acme \
  -acme-email admin@example.com
```

- Certificates are requested only for `-acme-domains`, so clients cannot
  make PrismWAF request certificates for arbitrary names and exhaust the
  CA's rate limits. Wildcards and IP addresses are not supported, and
  clients must send a server name (SNI).
- `-acme-cache` holds the account key and the certificates (mode 0700).
  Keep it across restarts; requesting new certificates on every start hits
  the rate limits quickly.
- The CA verifies the domains with the TLS-ALPN-01 challenge on port 443
  and, when `-http-redirect` is set, the HTTP-01 challenge on port 80. So
  `-listen` must be reachable as port 443, or `-http-redirect` as port 80,
  from the internet.
- Certificates are renewed automatically, 30 days (or a third of their
  lifetime, if shorter) before they expire.
- Using `-acme-domains` means accepting the CA's terms of service.
- Try a new setup with `-acme-directory staging` (Let's Encrypt's staging
  environment, untrusted certificates but higher rate limits) first. Any
  other ACME CA can be used by passing its directory URL.

`-acme-domains` and `-tls-cert` are mutually exclusive.

## HSTS

`-hsts-max-age` adds a `Strict-Transport-Security` header to every HTTPS
response, including blocked ones, so that browsers use only HTTPS for the
site from then on. A header sent by the backend is replaced.

```sh
go run ./cmd/prismwaf ... -hsts-max-age 8760h -hsts-include-subdomains
```

Browsers remember the policy for the whole max-age, so start with a short
value such as `5m` and increase it once HTTPS works everywhere.
`-hsts-include-subdomains` applies it to all subdomains as well.
`-hsts-preload` signals consent to be included in the browsers' preload
lists (<https://hstspreload.org>); it requires a max-age of at least one
year and `-hsts-include-subdomains`.

## Client certificates (mutual TLS)

`-tls-client-ca` requires clients to present a certificate signed by one
of the CAs in the given PEM file; others are rejected during the TLS
handshake, before any request reaches the WAF or the backend:

```sh
go run ./cmd/prismwaf ... -tls-client-ca clients-ca.pem
curl --cert alice.pem --key alice.key https://example.com/
```

With `-tls-client-auth optional`, clients without a certificate are
accepted too, but a certificate that is sent must be valid. Mutual TLS can
be combined with ACME; the CA's validation connections are exempted from
client authentication but cannot be used to send requests.

## HTTPS backends

Use an `https://` backend URL. Its certificate is verified against the
system CAs; for an internal CA or a self-signed certificate, pass it with
`-backend-ca`:

```sh
go run ./cmd/prismwaf -backend https://app.internal:8443 -backend-ca internal-ca.pem
```

`-backend-insecure-skip-verify` disables verification entirely. It makes the
connection vulnerable to interception and is meant for testing only.
