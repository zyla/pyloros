# Lessons Learned

## rcgen: CA cert chain verification requires `from_ca_cert_der`

When using rcgen to sign host certificates with a CA, `CertificateParams::from_ca_cert_der` (requires `x509-parser` feature) must be used to reconstruct the CA cert from its DER before calling `self_signed()`. Creating a new `CertificateParams` manually (even with the same DN/key usage) produces a different certificate (different serial, dates) that won't chain-verify against the original CA cert stored in client trust stores.

**Symptom**: `InvalidCertificate(UnknownIssuer)` when verifying a cert chain where the CA was reconstructed from params rather than parsed from DER.

**Fix**: `CertificateParams::from_ca_cert_der(&cert_der)` + `.self_signed(&key_pair)` preserves serial, validity, and subject key identifier so the signed child cert chains correctly.

## rustls CryptoProvider must be installed early

When both `aws-lc-rs` and `ring` features are enabled on rustls (common when reqwest pulls in one and direct deps pull in the other), you must call `rustls::crypto::aws_lc_rs::default_provider().install_default()` before any rustls operations. In test harnesses, do this at the earliest entry point (e.g., test CA generation) rather than just before the proxy starts.

## reqwest proxy + custom CA for MITM testing

To make reqwest work through a MITM proxy with a test CA:
- Use `reqwest::Proxy::all("http://<proxy-addr>")` (HTTP, not HTTPS, for the proxy URL)
- Use `add_root_certificate(Certificate::from_pem(...))` to trust the test CA
- The proxy generates MITM certs signed by the test CA; reqwest verifies the chain

## e2e test architecture for HTTPS proxy

Testing an HTTPS MITM proxy end-to-end requires:
1. **Port 443 restriction bypass**: CONNECT only allows port 443, but test upstreams bind to random ports. Add `upstream_port_override` to redirect forwarded connections.
2. **Injectable TLS config**: The proxy's upstream TLS config must trust the test CA instead of webpki roots. Add `upstream_tls_config` override.
3. **Bind/serve split**: Bind to port 0, discover the assigned port, then serve. Avoids port conflicts between parallel tests.
4. **Shared CA**: One TestCa generates certs for both the test upstream server and the proxy's MITM generator. The proxy's client config trusts this same CA for upstream connections.
