# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build                  # Build the project
cargo test                   # Run all tests (unit + integration)
cargo test --lib             # Run unit tests only
cargo test --test proxy_basic_test  # Run a specific integration test file
cargo test pattern_matching  # Run tests matching a name pattern
cargo clippy                 # Lint
cargo fmt                    # Format code

# Coverage (one-time setup: rustup component add llvm-tools-preview && cargo install cargo-llvm-cov)
cargo llvm-cov                                  # Text summary
cargo llvm-cov --html                           # HTML report in coverage/
cargo llvm-cov --lcov --output-path lcov.info   # LCOV format
```

## CLI Commands

```bash
cargo run -- run --config config.toml                    # Start proxy (--config is optional)
cargo run -- generate-ca --out ./certs/                  # Generate CA cert/key
cargo run -- validate-config --config config.toml        # Validate config
```

## Development process

`devdocs/SPEC.md` is a declarative specification of what we want this product to be: features, technical choices (libraries, protocols, testing strategy), and configuration format. Code should ultimately be maintained to match the requirements here. When we want to change something in the product, we first modify the SPEC.

IMPORTANT: Maintain progress in devdocs/TASKS.md.

After context compaction (when conversation history is summarized), reread `devdocs/SPEC.md` and any other relevant spec documents to stay on track with requirements and guidelines.

When facing design decisions, do the simpler thing but save it in devdocs/QUESTIONS.md for further consideration.

Any problems encountered with tools (build system, etc.) should also be documented in QUESTIONS.md under "Tool Issues Encountered" for future reference.

IMPORTANT: Commit immediately and automatically whenever a piece of work is done and verified. NEVER wait for the user to say "commit" — if it's done, commit it. This applies to every change: code, config, docs, anything. Don't accumulate changes. When following a multi-phase plan, commit after each phase passes its verification tests.

IMPORTANT: Every requirement in SPEC.md must be verified by tests. Prefer e2e tests by default; use unit tests only when e2e testing is not feasible for a particular requirement. Don't just wing it — if a feature isn't tested, it's not done.

IMPORTANT: If asked to implement something that's not in SPEC.md, insist on adding it to the spec first before writing any code.

You can keep refining the spec document as we work and discover new things, but confirm with human for major changes.

If you receive advice during development, you can add it to this section - will come handy during subsequent iterations.

When adding many tests, add them in groups with commit checkpoints — don't write 15 tests then commit once.

## Worktree Workflow

IMPORTANT: NEVER make code changes directly in the main working directory (`/home/zyla.linux/redlimitador`). ALL development work — including during plan mode exploration — MUST happen in a worktree. The very first step of any implementation task is to create a worktree. Do not edit files, run builds, or make commits in the main directory. If you catch yourself about to modify a file in the main directory, STOP and create a worktree first. This applies even for "small" or "trivial" changes.

**Setup (do this BEFORE any code changes):**

```bash
git branch claude/<feature-slug> main
mkdir -p ../redlimitador-worktrees
git worktree add ../redlimitador-worktrees/<feature-slug> claude/<feature-slug>
```

**Branch naming**: `claude/<feature-slug>` (lowercase, hyphen-separated).

**Location**: worktrees live in `../redlimitador-worktrees/<slug>/` (a sibling directory, not a subdirectory) so Grep/Glob don't find duplicate files.

**During development**: use absolute paths for all commands since shell state resets between Bash calls. Follow the same dev process (tests, commits, TASKS.md updates).

**Finishing**: default to `gh pr create`. For trivial changes where a PR would be overkill, merge locally. Ask the user if unclear.

**Cleanup** (after merge/PR):

```bash
git worktree remove ../redlimitador-worktrees/<feature-slug>
git branch -d claude/<feature-slug>
```

## Architecture

See `devdocs/SPEC.md` for product spec (features, configuration format, technical decisions).

### Module layout (`src/`)

- **`proxy/`** - HTTP proxy server: `server.rs` (TCP listener, connection dispatch), `handler.rs` (CONNECT vs plain HTTP routing, filter integration), `tunnel.rs` (CONNECT tunnel with MITM TLS handshake, upstream forwarding)
- **`filter/`** - Request filtering: `rules.rs` (FilterEngine compiles config rules, evaluates RequestInfo), `matcher.rs` (PatternMatcher for wildcard `*` matching on hosts/paths/queries, UrlPattern for full URL decomposition)
- **`tls/`** - Certificate management: `ca.rs` (CA generation/loading, per-host cert signing), `mitm.rs` (MitmCertificateGenerator wraps CA with caching, builds rustls ServerConfig), `cache.rs` (LRU cache with TTL for generated certs)
- **`config.rs`** - TOML config parsing into `Config`/`ProxyConfig`/`LoggingConfig`/`Rule` structs
- **`error.rs`** - `thiserror`-based error types (`Error`)
- **`main.rs`** - clap CLI with `run`, `generate-ca`, `validate-config` subcommands

### Key patterns

- Async throughout using Tokio; one spawned task per connection
- `FilterEngine` and `MitmCertificateGenerator` are wrapped in `Arc` for cross-task sharing

## Parallel Development

Multiple features can be developed simultaneously in separate worktrees. To avoid
merge conflicts:

- **Tests**: Each feature gets its own `tests/<feature>_test.rs` file. Never append
  tests for a new feature into an existing test file.
- **Shared infra**: Add new helpers to `tests/common/mod.rs` only when needed by
  multiple test files. Feature-specific helpers stay in the test file.
- **TASKS.md / SPEC.md**: These are shared docs that will conflict. Keep edits
  minimal and well-scoped. Rebase before merging.

## Tests

Integration tests live in `tests/`, split by feature area to minimize merge conflicts
across parallel worktrees:
- `proxy_basic_test.rs` — core proxy flow (allowed/blocked, wildcards, multi-rule)
- `proxy_forwarding_test.rs` — header forwarding, error handling, large bodies
- `http2_test.rs` — HTTP/2 protocol negotiation and translation
- `logging_test.rs` — granular request logging configuration
- `websocket_test.rs` — WebSocket upgrade and echo
- `filter_test.rs` — FilterEngine unit tests
- `tls_test.rs` — certificate generation and caching
- `cli_test.rs` — CLI subcommand validation

Shared test infrastructure (TestCa, TestProxy, TestUpstream, handlers) lives in
`tests/common/mod.rs`.

**Adding tests for new features**: Create a new test file (`tests/<feature>_test.rs`)
rather than appending to an existing one. This prevents merge conflicts when
multiple features are developed in parallel across worktrees.

Unit tests are inline in their respective modules (`config.rs`, `matcher.rs`, `rules.rs`, `ca.rs`, `mitm.rs`, `cache.rs`, `tunnel.rs`). Tests use `tempfile` for temporary directories and `wiremock` for HTTP mocking.
