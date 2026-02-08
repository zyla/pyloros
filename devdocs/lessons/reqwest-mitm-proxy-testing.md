# reqwest proxy + custom CA for MITM testing

To make reqwest work through a MITM proxy with a test CA:
- Use `reqwest::Proxy::all("http://<proxy-addr>")` (HTTP, not HTTPS, for the proxy URL)
- Use `add_root_certificate(Certificate::from_pem(...))` to trust the test CA
- The proxy generates MITM certs signed by the test CA; reqwest verifies the chain
