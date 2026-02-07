# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build                  # Build the project
cargo test                   # Run all tests (unit + integration)
cargo test --lib             # Run unit tests only
cargo test --test filter_test  # Run a specific integration test file
cargo test pattern_matching  # Run tests matching a name pattern
cargo clippy                 # Lint
cargo fmt                    # Format code
```

## CLI Commands

```bash
cargo run -- run --config config.toml                    # Start proxy
cargo run -- generate-ca --out ./certs/                  # Generate CA cert/key
cargo run -- validate-config --config config.toml        # Validate config
```

## Development process

We're developing this very incrementally. Start simple, don't overcomplicate, leave corner cases for later.

IMPORTANT: Maintain progress in devdocs/TASKS.md.

After context compaction (when conversation history is summarized), reread relevant spec documents to stay on track with requirements and guidelines.

When facing design decisions, do the simpler thing but save it in devdocs/QUESTIONS.md for further consideration.

Any problems encountered with tools (build system, etc.) should also be documented in QUESTIONS.md under "Tool Issues Encountered" for future reference.

Commit after each phase/step is achieved and verified - don't accumulate too many changes before committing. When following a multi-phase plan, commit immediately after each phase passes its verificati
on tests.

Use e2e tests (and other types if suitable) to verify all functionality you're implementing, don't just wing it.

You can keep refining the spec document as we work and discover new things.

If you receive advice during development, you can add it to this section - will come handy during subsequent iterations.

## Architecture

Redlimitador is a default-deny allowlist-based HTTPS filtering proxy that uses MITM TLS interception to inspect encrypted traffic. It is designed for controlling AI agent network access.

**Request flow:** Client -> Proxy Handler -> TLS Terminator (MITM) -> Filter Engine (pattern match against allowlist rules) -> Forwarder -> Target Server. Blocked requests get HTTP 451.

### Module layout (`src/`)

- **`proxy/`** - HTTP proxy server: `server.rs` (TCP listener, connection dispatch), `handler.rs` (CONNECT vs plain HTTP routing, filter integration), `tunnel.rs` (CONNECT tunnel with MITM TLS handshake, upstream forwarding)
- **`filter/`** - Request filtering: `rules.rs` (FilterEngine compiles config rules, evaluates RequestInfo), `matcher.rs` (PatternMatcher for wildcard `*` matching on hosts/paths/queries, UrlPattern for full URL decomposition)
- **`tls/`** - Certificate management: `ca.rs` (CA generation/loading, per-host cert signing), `mitm.rs` (MitmCertificateGenerator wraps CA with caching, builds rustls ServerConfig), `cache.rs` (LRU cache with TTL for generated certs)
- **`config.rs`** - TOML config parsing into `Config`/`ProxyConfig`/`LoggingConfig`/`Rule` structs
- **`error.rs`** - `thiserror`-based error types (`RedlimitadorError`)
- **`main.rs`** - clap CLI with `run`, `generate-ca`, `validate-config` subcommands

### Key patterns

- Async throughout using Tokio; one spawned task per connection
- `FilterEngine` and `MitmCertificateGenerator` are wrapped in `Arc` for cross-task sharing
- Wildcard `*` matches any character sequence (including across path segments) - compiled once at startup
- Certificate cache: LRU with 1000 capacity, 12-hour TTL, mutex-protected
- TLS uses rustls (pure Rust, no OpenSSL dependency)

## Configuration

TOML format with three sections: `[proxy]` (bind address, CA cert/key paths), `[logging]` (level, log_requests), `[[rules]]` (method, url, optional websocket flag). See `examples/basic_config.toml` for reference. Test fixtures are in `tests/fixtures/`.

## Tests

Integration tests live in `tests/` (`filter_test.rs`, `tls_test.rs`). Unit tests are inline in their respective modules (`config.rs`, `matcher.rs`, `rules.rs`, `ca.rs`, `mitm.rs`, `cache.rs`). Tests use `tempfile` for temporary directories and `wiremock` for HTTP mocking.
