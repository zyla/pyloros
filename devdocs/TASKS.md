Dear agent, track progress here

- [x] Add test coverage reporting with `cargo-llvm-cov`
- [x] Add end-to-end integration tests
  - [x] ProxyServer bind/serve split for port 0 discovery
  - [x] Upstream port override + injectable TLS config for testing
  - [x] Test infrastructure (TestCa, TestUpstream, TestProxy, test_client)
  - [x] Core e2e tests: allow/block/method filtering/empty ruleset
  - [x] Wildcard + multi-rule tests
  - [x] Header forwarding, error handling, large body tests
  - [x] Fix rcgen CA cert chain verification (from_ca_cert_der)
