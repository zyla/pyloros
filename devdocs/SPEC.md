# Redlimitador Spec

A default-deny allowlist-based HTTPS filtering proxy for controlling AI agent network access.

## Purpose of this document

It is a declarative specification of what we want this product to be: features, technical choices (libraries, protocols, testing strategy), and configuration format. Code should ultimately be maintained to match the requirements here. When we want to change something in the product, we first modify the SPEC.

## Features

### Core
- Explicit HTTP proxy mode (clients set `HTTP_PROXY`/`HTTPS_PROXY`)
- MITM TLS interception for HTTPS traffic via CONNECT tunnels
- CONNECT restricted to port 443 (non-443 CONNECT requests are blocked)
- Allowlist rule engine: requests must match at least one rule to be allowed; everything else is blocked with HTTP 451
- TOML configuration file

### Rule Matching
- Rules specify: method, URL pattern, optional `websocket = true` flag
- `*` wildcard matches any character sequence (including across segments) in host, path, and query
- Method `*` matches any HTTP method
- Example: `https://*.github.com/api/*` matches `https://foo.github.com/api/v1/repos`

### Protocol Support
- HTTP/1.1
- HTTP/2
- WebSocket (upgrade detection + bidirectional frame forwarding)

### Certificate Management
- User-provided or auto-generated CA certificate/key
- Per-host certificate generation with in-memory LRU cache (1000 entries, 12h TTL)
- CLI command to generate CA cert/key pair

### CLI

subcommands:

- `run --config config.toml` — start proxy
- `generate-ca --out ./certs/` — generate CA cert/key
- `validate-config --config config.toml` — validate config file

### Logging
- Configurable log level (error/warn/info/debug/trace)
- Separate control over logging of allowed and blocked requests (e.g., log only blocked to reduce noise, or only allowed for auditing)

## Technical Decisions

- Explicit HTTP proxy (no iptables)
- MITM with CA for HTTPS inspection
- Tokio async runtime
- rustls + rcgen for TLS (pure Rust, no OpenSSL). Evaluated shelling out to
  `openssl` CLI for cert generation — it would only replace ~85 lines of rcgen
  code while adding a runtime system dependency, fork+exec latency on the
  per-host hot path, and temp file management. Not worth the tradeoff.
- TOML config
- `*` wildcard = multi-segment match
- HTTP 451 for blocked requests
- In-memory LRU cert cache
- clap (derive) CLI
- hyper for HTTP

## Configuration Format

```toml
[proxy]
bind_address = "127.0.0.1:8080"
ca_cert = "/path/to/ca.crt"
ca_key = "/path/to/ca.key"

[logging]
level = "info"
# log_requests accepts a bool (backward compat) or a table:
#   log_requests = true              # both allowed + blocked
#   log_requests = false             # neither
#   log_requests = { allowed = true, blocked = false }  # granular
log_requests = { allowed = true, blocked = true }

[[rules]]
method = "GET"
url = "https://api.example.com/health"

[[rules]]
method = "*"
url = "https://*.github.com/*"

[[rules]]
method = "GET"
url = "wss://realtime.example.com/socket"
websocket = true
```

## Testing

- unit tests where it makes sense
- end-to-end integration tests with wiremock
  - covering all features, including:
    - different filtering rules
    - different protocols (http/1.1, http/2, websocket)
- tests run in Github Actions
- test coverage is reported

### E2E Test Architecture

E2e tests exercise the full request flow: client → proxy (MITM) → upstream → response.

The proxy binds to port 0 and exposes its actual address via `bind()` / `serve_until_shutdown()` split on `ProxyServer`.

Since CONNECT is restricted to port 443 but test upstreams run on random ports, `TunnelHandler` supports an `upstream_port_override` that redirects forwarded connections to the test upstream's actual port. Similarly, `upstream_tls_config` allows injecting a `rustls::ClientConfig` that trusts the test CA (instead of webpki roots).
