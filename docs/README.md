# PrismWAF documentation

| Guide | Contents |
|-------|----------|
| [Configuration](configuration.md) | Every command-line flag, grouped by topic, with deployment examples |
| [Signature detection](detection.md) | The built-in signatures, normalization of encoded payloads, JSON and XML bodies, the body size limit |
| [OWASP Core Rule Set](crs.md) | `-engine`, paranoia level, anomaly threshold, rule exclusions, tested use cases, performance |
| [Rate limiting](rate-limiting.md) | Limits per client and per path, bursts, IPv6, proxies, exemptions, tuning in detection mode |
| [Denial of service protection](ddos.md) | Slow clients, connection limits, requests in progress and load shedding, bans, network-level attacks, measurements |
| [Business flow protection](business-logic.md) | Failure limits against password, code and coupon guessing, enumeration limits against ID harvesting, rollout in detection mode |
| [Geo filtering](geo-filtering.md) | Allowing or blocking countries, GeoIP databases and their updates, the country header for the backend, rollout in detection mode |
| [API protection](api-protection.md) | OpenAPI validation of REST requests, GraphQL limits, introspection and schema validation, gRPC and gRPC-Web inspection while streaming, responses and audit events, rollout |
| [Bot protection](bot-protection.md) | Bot score, categories, verified search engines, proof-of-work and CAPTCHA challenges, clearance cookies, rollout in detection mode |
| [Bot protection guide](bot-protection-guide.md) | Planning and rollout, configurations for common sites, tuning thresholds, troubleshooting false positives, search engines and SEO |
| [Modes and audit log](audit-log.md) | Block and detection mode, the audit event format, client IP behind proxies |
| [Load balancing](load-balancing.md) | Several backends, balancing policies, failover, health checks |
| [HTTPS](https.md) | TLS termination, SNI, HSTS, mutual TLS, HTTPS backends |
| [Automatic certificates](acme.md) | ACME/Let's Encrypt: requirements, rate limits, staging, expiry notifications, systemd, troubleshooting |
| [Testing](testing.md) | Unit and end-to-end tests of bot protection, the CRS, ACME expiry notifications (with a fake ACME CA), geo filtering, API protection, business flow protection and denial of service protection, browser and live tests, test results |
| [Development](development.md) | Tests, benchmarks, building, project layout |
