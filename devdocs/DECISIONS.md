# Design Decisions

Implementation-level rationale and architecture details that supplement the high-level
spec in `SPEC.md`. Record design decisions and tool issues directly here.

## rustls + rcgen vs OpenSSL

Evaluated shelling out to `openssl` CLI for cert generation — it would only replace
~85 lines of rcgen code while adding a runtime system dependency, fork+exec latency
on the per-host hot path, and temp file management. Not worth the tradeoff.

## E2E Test Architecture

E2E tests exercise the full request flow: client → proxy (MITM) → upstream → response.

The proxy binds to port 0 and exposes its actual address via `bind()` /
`serve_until_shutdown()` split on `ProxyServer`.

Since CONNECT is restricted to port 443 but test upstreams run on random ports,
`TunnelHandler` supports an `upstream_port_override` that redirects forwarded
connections to the test upstream's actual port. Similarly, `upstream_tls_config`
allows injecting a `rustls::ClientConfig` that trusts the test CA (instead of webpki
roots).

These overrides are also exposed as optional config fields (`upstream_override_port`,
`upstream_tls_ca`) so that binary-level tests can exercise the real CLI binary with
`curl`.

For binary-level tests, the proxy prints its actual listening address to stderr so
tests can use `bind_address = "127.0.0.1:0"` and discover the port at runtime.

Live API tests check for OAuth credentials at `~/.claude/.credentials.json` and skip
when unavailable.

