# Redlimitador - Network Proxy for Agent Access Control

A filtering HTTPS proxy that enforces allowlist-based network access control for AI agents.

## Overview

Redlimitador intercepts HTTPS traffic via explicit HTTP proxy configuration and applies configurable allowlist rules. By default, all requests are blocked unless explicitly permitted.

### Key Features

- **Allowlist-based filtering**: Default-deny with explicit allow rules
- **HTTPS interception**: TLS termination (MITM) for inspecting encrypted traffic
- **Flexible pattern matching**: Wildcards for methods, hosts, paths, and query strings
- **Protocol support**: HTTP/1.1, HTTP/2, WebSocket
- **Certificate management**: User-provided or auto-generated CA certificates

## Architecture

```
┌─────────┐     ┌─────────────────────────────────────────┐     ┌──────────┐
│  Agent  │────▶│              Redlimitador               │────▶│  Target  │
│ (Client)│     │                                         │     │  Server  │
└─────────┘     │  ┌─────────┐  ┌─────────┐  ┌─────────┐ │     └──────────┘
                │  │ Proxy   │─▶│ Filter  │─▶│ Forward │ │
                │  │ Handler │  │ Engine  │  │         │ │
                │  └─────────┘  └─────────┘  └─────────┘ │
                │       │            │                    │
                │       ▼            ▼                    │
                │  ┌─────────┐  ┌─────────┐              │
                │  │  TLS    │  │ Config  │              │
                │  │ Terminator│ │ (Rules) │              │
                │  └─────────┘  └─────────┘              │
                └─────────────────────────────────────────┘
```

### Components

1. **Proxy Handler**: Accepts HTTP/HTTPS proxy requests (explicit proxy mode)
2. **TLS Terminator**: Performs MITM for HTTPS via CONNECT tunnels
3. **Filter Engine**: Evaluates requests against allowlist rules
4. **Forwarder**: Proxies allowed requests to upstream servers

## Configuration

Configuration uses TOML format:

```toml
[proxy]
bind_address = "127.0.0.1:8080"
# Path to CA certificate and key for MITM
ca_cert = "/path/to/ca.crt"
ca_key = "/path/to/ca.key"

[logging]
level = "debug"  # error, warn, info, debug, trace
log_requests = true

# Allowlist rules - requests must match at least one rule to be allowed
[[rules]]
# Simple exact match
method = "GET"
url = "https://api.example.com/health"

[[rules]]
# Wildcard in path - matches any single or multiple segments
method = "GET"
url = "https://api.example.com/users/*/profile"

[[rules]]
# Wildcard host
method = "POST"
url = "https://*.github.com/api/*"

[[rules]]
# Any method
method = "*"
url = "https://cdn.example.com/*"

[[rules]]
# Query string matching
method = "GET"
url = "https://api.example.com/search?q=*&limit=*"

[[rules]]
# WebSocket upgrade
method = "GET"
url = "wss://realtime.example.com/socket"
websocket = true
```

### Pattern Matching

- `*` in host: matches any subdomain segment(s) (e.g., `*.example.com` matches `api.example.com` and `a.b.example.com`)
- `*` in path: matches any path segment(s) (e.g., `/api/*/data` matches `/api/v1/data` and `/api/v1/v2/data`)
- `*` in query: matches any value for that parameter
- Method `*`: matches any HTTP method

## Implementation Phases

### Phase 1: Core Proxy Infrastructure ✅ [Current]
- [ ] Project setup (Cargo.toml, dependencies)
- [ ] Basic TCP listener and connection handling
- [ ] HTTP/1.1 CONNECT tunnel support
- [ ] Plain HTTP proxy forwarding (for testing)
- [ ] Basic request/response logging
- [ ] Unit tests for connection handling

### Phase 2: TLS/MITM Infrastructure
- [ ] CA certificate loading from config
- [ ] CLI tool for CA certificate generation
- [ ] Per-host certificate generation and caching
- [ ] TLS termination for CONNECT tunnels
- [ ] Upstream TLS connection to target servers
- [ ] Certificate cache with expiration
- [ ] Tests with self-signed certificates

### Phase 3: Configuration & Rule Engine
- [ ] TOML configuration parsing
- [ ] Rule data structures
- [ ] Pattern matching engine (hosts, paths, query strings)
- [ ] Wildcard compilation and matching
- [ ] Rule evaluation (allow if any match)
- [ ] Configuration hot-reload (optional)
- [ ] Comprehensive pattern matching tests

### Phase 4: Request Filtering
- [ ] HTTP request parsing and inspection
- [ ] Method/URL extraction from requests
- [ ] Filter integration with proxy pipeline
- [ ] HTTP 451 response for blocked requests
- [ ] Request logging (allowed/blocked)
- [ ] Integration tests with real HTTP traffic

### Phase 5: HTTP/2 Support
- [ ] HTTP/2 connection handling (h2 crate)
- [ ] HTTP/2 request inspection
- [ ] HTTP/2 forwarding to upstream
- [ ] Mixed HTTP/1.1 and HTTP/2 support
- [ ] HTTP/2 specific tests

### Phase 6: WebSocket Support
- [ ] WebSocket upgrade detection
- [ ] WebSocket handshake proxying
- [ ] Bidirectional WebSocket frame forwarding
- [ ] WebSocket-specific rules
- [ ] WebSocket tests

### Phase 7: Advanced Features (Future)
- [ ] Protocol-specific filtering (e.g., git HTTPS transport)
- [ ] Request body inspection
- [ ] Response filtering
- [ ] Rate limiting
- [ ] Metrics and observability
- [ ] Upstream proxy chaining

## Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Proxy mode | Explicit HTTP proxy | Simpler client configuration, no iptables needed |
| HTTPS inspection | MITM with user-provided CA | Required for content inspection |
| Async runtime | Tokio | De facto standard for Rust async networking |
| HTTP library | hyper | Mature, supports HTTP/1.1 and HTTP/2 |
| TLS library | rustls + rcgen | Pure Rust, good security defaults |
| Config format | TOML | Human-readable, supports comments |
| Wildcard matching | Multi-segment `*` | Simpler rules, fewer edge cases |
| Blocked response | HTTP 451 | Clear indication of intentional blocking |
| Cert caching | In-memory LRU | Balance of performance and memory |

## Dependencies

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
hyper = { version = "1", features = ["full"] }
hyper-util = "0.1"
http-body-util = "0.1"
rustls = "0.23"
tokio-rustls = "0.26"
rcgen = "0.13"              # Certificate generation
webpki-roots = "0.26"       # Root CA certificates
toml = "0.8"
serde = { version = "1", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = "0.3"
thiserror = "2"
clap = { version = "4", features = ["derive"] }
lru = "0.12"                # Certificate cache

[dev-dependencies]
reqwest = { version = "0.12", features = ["rustls-tls"] }
tokio-test = "0.4"
tempfile = "3"
assert_cmd = "2"
predicates = "3"
```

## Usage

### Generate CA Certificate

```bash
redlimitador generate-ca --out ./certs/
# Creates: ca.crt, ca.key
```

### Run Proxy

```bash
redlimitador run --config config.toml
# Or with defaults:
redlimitador run --ca-cert ca.crt --ca-key ca.key --bind 127.0.0.1:8080
```

### Client Configuration

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

# Trust the CA certificate (varies by system/application)
# For curl:
curl --cacert /path/to/ca.crt https://api.example.com/

# For system-wide (Ubuntu):
sudo cp ca.crt /usr/local/share/ca-certificates/redlimitador.crt
sudo update-ca-certificates
```

## Testing Strategy

1. **Unit tests**: Pattern matching, config parsing, rule evaluation
2. **Integration tests**: Full proxy flow with test servers
3. **TLS tests**: Certificate generation, MITM validation
4. **Protocol tests**: HTTP/1.1, HTTP/2, WebSocket handling
5. **Fuzz tests**: Pattern matching edge cases (optional)

## Security Considerations

- CA private key must be protected (file permissions, secure storage)
- Proxy should only bind to localhost by default
- Allowlist rules should be audited carefully
- Consider certificate pinning bypass implications
- Log files may contain sensitive URLs

## File Structure

```
redlimitador/
├── Cargo.toml
├── PLAN.md
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Library root
│   ├── config.rs            # Configuration parsing
│   ├── proxy/
│   │   ├── mod.rs
│   │   ├── server.rs        # Main proxy server
│   │   ├── handler.rs       # Request handling
│   │   └── tunnel.rs        # CONNECT tunnel handling
│   ├── tls/
│   │   ├── mod.rs
│   │   ├── ca.rs            # CA certificate management
│   │   ├── mitm.rs          # MITM certificate generation
│   │   └── cache.rs         # Certificate caching
│   ├── filter/
│   │   ├── mod.rs
│   │   ├── rules.rs         # Rule data structures
│   │   ├── matcher.rs       # Pattern matching
│   │   └── engine.rs        # Filter evaluation
│   └── error.rs             # Error types
├── tests/
│   ├── integration/
│   │   ├── proxy_test.rs
│   │   ├── filter_test.rs
│   │   └── tls_test.rs
│   └── fixtures/
│       └── test_config.toml
└── examples/
    └── basic_config.toml
```
