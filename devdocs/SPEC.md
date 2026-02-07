# Redlimitador Spec

A default-deny allowlist-based HTTPS filtering proxy for controlling AI agent network access.

## Features

### Core
- Explicit HTTP proxy mode (clients set `HTTP_PROXY`/`HTTPS_PROXY`)
- MITM TLS interception for HTTPS traffic via CONNECT tunnels
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
- Optional request logging (allowed/blocked)

## Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Proxy mode | Explicit HTTP proxy | Simpler client config, no iptables needed |
| HTTPS inspection | MITM with CA | Required for content inspection |
| Async runtime | Tokio | Standard for Rust async networking |
| TLS | rustls + rcgen | Pure Rust, no OpenSSL dependency |
| Config format | TOML | Human-readable, supports comments |
| Wildcard semantics | `*` = multi-segment | Simpler rules, fewer edge cases |
| Blocked response | HTTP 451 | Clear intentional blocking signal |
| Cert caching | In-memory LRU | Balance of performance and memory |
| CLI | clap (derive) | Standard Rust CLI library |
| HTTP | hyper | Mature, supports HTTP/1.1 and HTTP/2 |

## Configuration Format

```toml
[proxy]
bind_address = "127.0.0.1:8080"
ca_cert = "/path/to/ca.crt"
ca_key = "/path/to/ca.key"

[logging]
level = "info"
log_requests = true

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

## Future Considerations
- Configuration hot-reload
- Protocol-specific filtering (e.g. git transport)
- Request body inspection
- Response filtering
- Rate limiting
- Metrics/observability
- Upstream proxy chaining

## Testing

- unit tests where it makes sense
- end-to-end integration tests with wiremock
  - covering all features, including:
    - different filtering rules
    - different protocols (http/1.1, http/2, websocket)
- tests run in Github Actions
- test coverage is reported
