# Redlimitador Spec

A default-deny allowlist-based HTTPS filtering proxy for controlling AI agent network access.

## Purpose of this document

It is a declarative specification of what we want this product to be: features, behavior, technical choices (libraries, protocols), configuration format, and developer experience (CI/CD, tooling, workflow). It describes *what* and *why*, not *how* — implementation details like internal APIs, struct names, or macro usage belong in code and code comments, not here. Code and infrastructure should ultimately be maintained to match the requirements here. When we want to change something, we first modify the SPEC.

## Deployment Model

The intended deployment is one proxy per VM/container running an AI agent. All outbound traffic from the agent is routed through the proxy via `HTTP_PROXY`/`HTTPS_PROXY` environment variables, giving the proxy full visibility and control over the agent's network access.

## Features

> **Status convention:** All features are implemented and tested unless marked with `(planned)`. Remove the marker once implemented. Agents: scan for `(planned)` to find remaining work.

### Core
- Explicit HTTP proxy mode (clients configured via `HTTP_PROXY`/`HTTPS_PROXY` env vars)
- MITM TLS interception for HTTPS traffic via CONNECT tunnels
- Plain HTTP forwarding for non-CONNECT proxy requests (e.g. `http://` URLs used by apt-get)
- Hop-by-hop header stripping per RFC 7230 for forwarded HTTP requests
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
- rustls + rcgen for TLS (pure Rust, no OpenSSL) — see `DECISIONS.md` for evaluation
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
# Optional: override upstream port for all CONNECT forwards (testing only)
# upstream_override_port = 9443
# Optional: PEM CA cert to trust for upstream TLS (testing only)
# upstream_tls_ca = "/path/to/upstream-ca.crt"

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

- Unit tests where it makes sense
- End-to-end integration tests covering all features: filtering rules, plain HTTP forwarding, HTTPS (MITM), HTTP/2, WebSocket
- Binary-level smoke tests that spawn the real binary and drive it with `curl`
- Live API tests against production servers (skipped when credentials unavailable)
- CLI integration tests for all subcommands (`run`, `generate-ca`, `validate-config`)
- Tests run in GitHub Actions; coverage is reported

See `DECISIONS.md` for implementation details (test architecture, port override mechanism).

### Test Report Generation

Tests produce a human-readable report showing, for each test: what was done, what the result was, and what assertions were checked. The report is tightly coupled to actual test execution — descriptions are derived from real parameters (URLs, rules, CLI args), making drift between tests and report impossible.

- A standalone report generator tool (`tools/test-report/`) runs the test suite and produces Markdown + HTML output.
- The Markdown report is published to the GitHub Actions job summary so it's visible directly in the run without downloading artifacts.
- Reports are also uploaded as CI artifacts.

## Documentation

The project README (`README.md`) must contain:

- Project name, tagline, and brief description of what it does and why
- Overview of the deployment model (one proxy per VM/container)
- Quick-start guide: generate CA, create config, start proxy, configure client
- Configuration reference with example covering `[proxy]`, `[logging]`, and `[[rules]]` sections
- CLI reference for all subcommands (`run`, `generate-ca`, `validate-config`) with flags
- Build from source instructions (prerequisites, cargo build)
- How to run tests
- License (MIT)
