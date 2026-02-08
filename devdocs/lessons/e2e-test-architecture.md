# e2e test architecture for HTTPS proxy

Testing an HTTPS MITM proxy end-to-end requires:
1. **Port 443 restriction bypass**: CONNECT only allows port 443, but test upstreams bind to random ports. Add `upstream_port_override` to redirect forwarded connections.
2. **Injectable TLS config**: The proxy's upstream TLS config must trust the test CA instead of webpki roots. Add `upstream_tls_config` override.
3. **Bind/serve split**: Bind to port 0, discover the assigned port, then serve. Avoids port conflicts between parallel tests.
4. **Shared CA**: One TestCa generates certs for both the test upstream server and the proxy's MITM generator. The proxy's client config trusts this same CA for upstream connections.
