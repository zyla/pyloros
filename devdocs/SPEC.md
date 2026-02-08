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

### Git Rules (planned)

Git-specific rules provide a high-level way to control git smart HTTP operations (clone, fetch, push) without requiring users to understand the underlying protocol endpoints.

A rule has **either** `method` (HTTP rule) **or** `git` (git rule), never both. Having both is a config validation error. `websocket = true` and `git` are mutually exclusive.

```toml
# Allow clone/fetch from any repo in myorg
[[rules]]
git = "fetch"
url = "https://github.com/myorg/*"

# Allow push only to a specific repo, only to feature branches
[[rules]]
git = "push"
url = "https://github.com/myorg/deploy-tools"
branches = ["feature/*", "fix/*"]

# Allow all git operations to any github.com repo
[[rules]]
git = "*"
url = "https://github.com/*"
```

#### `git` field values

| Value   | Operations allowed   | Smart HTTP endpoints matched                          |
|---------|---------------------|-------------------------------------------------------|
| `fetch` | clone, fetch, pull  | `GET .../info/refs?service=git-upload-pack`, `POST .../git-upload-pack` |
| `push`  | push                | `GET .../info/refs?service=git-receive-pack`, `POST .../git-receive-pack` |
| `*`     | all                 | all four endpoints above                              |

The `url` is the repo base URL (what you'd pass to `git clone`). The proxy appends the git smart HTTP suffixes internally.

#### Branch restriction

The optional `branches` field restricts which refs a push can target. It is only valid on `git = "push"` or `git = "*"` rules; using it with `git = "fetch"` is a config error.

- Bare patterns like `feature/*` match against `refs/heads/feature/*`.
- Patterns starting with `refs/` are matched literally (escape hatch for tags, notes, etc.).
- Omitting `branches` means any ref is allowed.
- If a push updates multiple refs and **any** ref is disallowed, the **entire push** is blocked.

Branch restriction works by inspecting the pkt-line commands at the start of the `git-receive-pack` POST request body. These are plaintext lines before the binary pack data, so inspection is lightweight.

#### Compilation

A git rule is syntactic sugar. At rule compilation time, `git = "fetch", url = "https://github.com/org/*"` expands into internal matchers equivalent to:

```
GET  https://github.com/org/*/info/refs?service=git-upload-pack
POST https://github.com/org/*/git-upload-pack
```

For push rules with `branches`, the URL matchers are the same but the `git-receive-pack` POST matcher additionally inspects the request body to extract ref names and check them against the branch patterns.

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

# Git-specific rules (planned)
[[rules]]
git = "fetch"
url = "https://github.com/myorg/*"

[[rules]]
git = "push"
url = "https://github.com/myorg/agent-workspace"
branches = ["feature/*", "fix/*"]
```

## Testing

- Unit tests where it makes sense
- End-to-end integration tests covering all features: filtering rules, plain HTTP forwarding, HTTPS (MITM), HTTP/2, WebSocket
- CLI integration tests for all subcommands (`run`, `generate-ca`, `validate-config`)
- Tests run in GitHub Actions; coverage is reported
- When testing integration with external tools (git, curl, claude CLI, etc.), always verify that traffic actually went through the proxy — don't just check that the tool succeeded. Record requests at the upstream handler or check proxy logs for expected entries.

See `DECISIONS.md` for implementation details (E2E test architecture, port override mechanism).

### Binary-Level Tests

Binary-level smoke tests spawn the actual `redlimitador` binary and drive it with `curl`, configured via `HTTPS_PROXY` — the same mechanism real clients use. They verify end-to-end behavior including config parsing, CLI argument handling, and process lifecycle.

### Live API Tests

Binary-level tests that send real requests to external APIs (e.g. `api.anthropic.com`) through the proxy, verifying the full MITM TLS pipeline against production servers. These tests require the `claude` CLI to be installed and authenticated, and are skipped when either is unavailable (e.g. in CI).

### Mutation Testing

Mutation testing with `cargo-mutants` validates test suite quality. It is run manually (not in CI) and does not need automation. The goal is to kill all viable mutants for core logic (filtering, header manipulation, protocol handling). Surviving mutants in logging/debug/cosmetic code are acceptable.

When adding new code paths with conditional logic (especially `if`, `match`, `==`/`!=`), ensure tests exercise both branches. Default-port matching, header presence checks, and error classification are common sources of surviving mutants.

### Git Smart HTTP Tests

Integration tests verify that git smart HTTP operations (clone, push) work correctly through the proxy's HTTPS MITM pipeline. Tests run a local git smart HTTP server (via `git http-backend` CGI), route `git clone`/`git push` commands through the proxy, and verify end-to-end correctness.

### Test Report Generation

Tests produce a human-readable report showing, for each test: what was done, what the result was, and what assertions were checked. The report is tightly coupled to actual test execution — descriptions are derived from real parameters (URLs, rules, CLI args), making drift between tests and report impossible.

- A standalone report generator tool (`tools/test-report/`) runs the test suite and produces Markdown + HTML output.
- The Markdown report is published to the GitHub Actions job summary so it's visible directly in the run without downloading artifacts.
- Reports are also uploaded as CI artifacts.

Test actions (HTTP requests, CLI invocations, etc.) should be performed through wrapper functions that both execute the action and emit a matching report entry. Bare `t.action()` + manual code pairs are not acceptable — the action description and execution must be coupled in a single API call so they can't drift apart. Examples: `ReportingClient` for HTTP requests, `_reported()` variants of test helpers.

## Distribution

Statically-linked Linux x86_64 binaries (musl) are published as GitHub Release assets on version tags (`v*`). The release workflow builds the binary, runs tests against it, verifies static linking, and packages it as a tarball with SHA256 checksums.

A rolling `latest` pre-release is built from `main` on every push. It uses a fixed `latest` git tag (force-moved to HEAD) and is marked as a prerelease with `make_latest: false` so it doesn't override the versioned "Latest release" in the GitHub UI.

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
