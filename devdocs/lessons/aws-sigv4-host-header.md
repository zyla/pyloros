# AWS SigV4: Host Header Must Be Set Before Signing

## Problem

When re-signing AWS SigV4 requests in the proxy, the signature was being
computed with one Host header value, but the actual request forwarded to AWS
had a different Host value — causing `SignatureDoesNotMatch` errors.

## Root Cause

The proxy's `rebuild_request_for_upstream()` sets the Host header to
`host:port` for the upstream connection. But SigV4 signing happens before
that, using the original Host header from the client request. AWS then
verifies the signature against the Host header it receives, which doesn't
match what was signed.

Additionally, AWS expects Host headers **without** the default port 443
(i.e., `sts.amazonaws.com` not `sts.amazonaws.com:443`).

## Solution

For SigV4 requests, set the Host header to its final upstream value
**before** signing:

```rust
// Set Host to final upstream value BEFORE signing
let upstream_host_value = if connect_port == 443 {
    host.to_string()        // AWS expects no :443
} else {
    format!("{}:{}", host, connect_port)
};
parts.headers.insert(HOST, HeaderValue::from_str(&upstream_host_value)?);

// Now sign — Host is already correct
credential_engine.inject_with_body(&request_info, &mut parts.headers, &body_bytes);

// Skip rebuild_request_for_upstream — Host is already set
```

## Key Takeaway

When any signing/hashing mechanism covers the Host header, ensure the Host is
set to its final value before computing the signature. The proxy's normal flow
of "sign first, set Host later" breaks SigV4's integrity guarantee.
