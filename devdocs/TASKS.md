Dear agent, track progress here

## Completed

- [x] Add test coverage reporting with `cargo-llvm-cov`
- [x] Add end-to-end integration tests
  - [x] ProxyServer bind/serve split for port 0 discovery
  - [x] Upstream port override + injectable TLS config for testing
  - [x] Test infrastructure (TestCa, TestUpstream, TestProxy, test_client)
  - [x] Core e2e tests: allow/block/method filtering/empty ruleset
  - [x] Wildcard + multi-rule tests
  - [x] Header forwarding, error handling, large body tests
  - [x] Fix rcgen CA cert chain verification (from_ca_cert_der)
- [x] Add GitHub Actions CI (fmt, clippy, tests, coverage)
- [x] Add HTTP/2 support
  - [x] ALPN [h2, http/1.1] on MITM ServerConfig (client ↔ proxy)
  - [x] auto::Builder for MITM tunnel (auto-detect h1/h2 via ALPN)
  - [x] ALPN on upstream ClientConfig + protocol branching (proxy ↔ upstream)
  - [x] Test infrastructure: h2-capable TestUpstream, h1-only variants, test_client_h1_only
  - [x] E2E tests: h2 allowed, h1↔h2 protocol translation, h2 blocked 451, h2 large body
- [x] WebSocket support: bidirectional frame forwarding
  - [x] Extract `connect_upstream_tls()` and `rebuild_request_for_upstream()` helpers
  - [x] Add `forward_websocket()` with upgrade handshake + `copy_bidirectional`
  - [x] Branch on `is_websocket` in `handle_tunneled_request()`
  - [x] Test infrastructure: `ws_echo_handler()`, `ws_rule()`, `.with_upgrades()` on TestUpstream
  - [x] E2E tests: echo, blocked, multiple messages, binary, upstream rejection
