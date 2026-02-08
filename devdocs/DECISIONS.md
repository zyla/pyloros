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

## Git Rules Implementation

Git rules are syntactic sugar over the git smart HTTP protocol endpoints. A git rule
compiles into internal URL matchers at rule load time, so there is no runtime overhead
compared to writing the raw HTTP rules by hand.

### Smart HTTP endpoint mapping

Git smart HTTP uses four endpoints per repo:

| Operation | Method | URL                                            |
|-----------|--------|------------------------------------------------|
| fetch discovery | GET | `<repo>/info/refs?service=git-upload-pack`  |
| fetch data      | POST | `<repo>/git-upload-pack`                   |
| push discovery  | GET | `<repo>/info/refs?service=git-receive-pack` |
| push data       | POST | `<repo>/git-receive-pack`                  |

A `git = "fetch"` rule expands into matchers for the first two; `git = "push"` into the
last two; `git = "*"` into all four. The `url` from the rule is used as the `<repo>`
prefix — wildcards in the URL carry through naturally (e.g.
`https://github.com/org/*` → `https://github.com/org/*/info/refs?service=git-upload-pack`).

### Branch restriction via pkt-line inspection

The `branches` field on push rules requires inspecting the request body of the
`POST .../git-receive-pack` request. The body format is:

```
<old-sha> <new-sha> <ref-name>\0<capabilities>\n   ← first command
<old-sha> <new-sha> <ref-name>\n                   ← subsequent commands
0000                                                ← flush packet
<...pack data...>
```

Each line is prefixed with a 4-hex-digit length (pkt-line format). The ref update
commands are plaintext and come before any binary pack data, so inspection only needs
to buffer the first few hundred bytes.

The proxy reads pkt-lines until the flush packet (`0000`), extracts the ref names from
each command, checks them against the `branches` patterns, and either blocks the entire
request or forwards it (re-sending the buffered pkt-lines followed by the remaining
body stream).

