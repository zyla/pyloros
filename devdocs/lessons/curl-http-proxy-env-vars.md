# curl HTTP proxy environment variables

## `http_proxy` must be lowercase

curl ignores uppercase `HTTP_PROXY` for `http://` URLs as a CGI security measure
(the `HTTP_PROXY` header in CGI maps to the env var, enabling request smuggling).
Use lowercase `http_proxy` for plain HTTP proxy configuration.

`HTTPS_PROXY` (uppercase) works fine for `https://` URLs — no CGI conflict there.

## `no_proxy` must be cleared for localhost

curl skips the proxy for `localhost` and `127.0.0.1` by default. When testing
proxy behavior with local upstreams, set `no_proxy=""` to force all traffic
through the proxy.
