# PrismWAF documentation

| Guide | Contents |
|-------|----------|
| [Configuration](configuration.md) | Every command-line flag, grouped by topic, with deployment examples |
| [Signature detection](detection.md) | The built-in signatures, normalization of encoded payloads, JSON and XML bodies, the body size limit |
| [OWASP Core Rule Set](crs.md) | `-engine`, paranoia level, anomaly threshold, rule exclusions, tested use cases, performance |
| [Rate limiting](rate-limiting.md) | Limits per client and per path, bursts, IPv6, proxies, exemptions, tuning in detection mode |
| [Modes and audit log](audit-log.md) | Block and detection mode, the audit event format, client IP behind proxies |
| [Load balancing](load-balancing.md) | Several backends, balancing policies, failover, health checks |
| [HTTPS](https.md) | TLS termination, SNI, HSTS, mutual TLS, HTTPS backends |
| [Automatic certificates](acme.md) | ACME/Let's Encrypt: requirements, rate limits, staging, expiry notifications, systemd, troubleshooting |
| [Development](development.md) | Tests, benchmarks, building, project layout |
