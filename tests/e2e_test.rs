mod common;

use common::{
    echo_handler, ok_handler, rule, test_client, test_client_h1_only, TestCa, TestProxy,
    TestUpstream,
};

// ---------------------------------------------------------------------------
// Phase 5: Core e2e tests — allowed/blocked flow
// ---------------------------------------------------------------------------

/// Allowed GET reaches upstream and returns 200 + body.
#[tokio::test]
async fn test_allowed_get_returns_200() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("hello from upstream")).await;

    let proxy = TestProxy::start(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .await;

    let client = test_client(proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "hello from upstream");

    proxy.shutdown();
    upstream.shutdown();
}

/// Blocked request (no matching rule) returns 451 with X-Blocked-By header.
#[tokio::test]
async fn test_blocked_request_returns_451() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("should not reach")).await;

    // Rule only allows example.com, not localhost
    let proxy = TestProxy::start(
        &ca,
        vec![rule("GET", "https://example.com/*")],
        upstream.port(),
    )
    .await;

    let client = test_client(proxy.addr(), &ca);
    let resp = client
        .get("https://localhost/blocked")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 451);
    assert_eq!(
        resp.headers()
            .get("X-Blocked-By")
            .unwrap()
            .to_str()
            .unwrap(),
        "redlimitador"
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// Method filtering: rule allows GET but POST is blocked.
#[tokio::test]
async fn test_method_filtering() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("ok")).await;

    let proxy = TestProxy::start(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .await;

    let client = test_client(proxy.addr(), &ca);

    // GET should be allowed
    let resp = client.get("https://localhost/path").send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // POST should be blocked
    let resp = client.post("https://localhost/path").send().await.unwrap();
    assert_eq!(resp.status(), 451);

    proxy.shutdown();
    upstream.shutdown();
}

/// Empty ruleset blocks everything.
#[tokio::test]
async fn test_empty_ruleset_blocks_all() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("nope")).await;

    let proxy = TestProxy::start(&ca, vec![], upstream.port()).await;

    let client = test_client(proxy.addr(), &ca);
    let resp = client
        .get("https://localhost/anything")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 451);

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Phase 6: Wildcard + multi-rule tests
// ---------------------------------------------------------------------------

/// Wildcard method (`*`) allows GET, POST, PUT.
#[tokio::test]
async fn test_wildcard_method() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("ok")).await;

    let proxy =
        TestProxy::start(&ca, vec![rule("*", "https://localhost/*")], upstream.port()).await;

    let client = test_client(proxy.addr(), &ca);

    for method in &["GET", "POST", "PUT"] {
        let resp = client
            .request(method.parse().unwrap(), "https://localhost/test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{} should be allowed", method);
    }

    proxy.shutdown();
    upstream.shutdown();
}

/// Wildcard path: `/api/*` allows `/api/foo` but blocks `/other`.
#[tokio::test]
async fn test_wildcard_path() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("ok")).await;

    let proxy = TestProxy::start(
        &ca,
        vec![rule("GET", "https://localhost/api/*")],
        upstream.port(),
    )
    .await;

    let client = test_client(proxy.addr(), &ca);

    // /api/foo should be allowed
    let resp = client
        .get("https://localhost/api/foo")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // /api/foo/bar/baz should also be allowed (* is multi-segment)
    let resp = client
        .get("https://localhost/api/foo/bar/baz")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // /other should be blocked
    let resp = client.get("https://localhost/other").send().await.unwrap();
    assert_eq!(resp.status(), 451);

    proxy.shutdown();
    upstream.shutdown();
}

/// Multiple rules: correct allow/block behavior.
#[tokio::test]
async fn test_multiple_rules() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("ok")).await;

    let proxy = TestProxy::start(
        &ca,
        vec![
            rule("GET", "https://localhost/api/*"),
            rule("POST", "https://localhost/submit"),
        ],
        upstream.port(),
    )
    .await;

    let client = test_client(proxy.addr(), &ca);

    // GET /api/data — allowed by first rule
    let resp = client
        .get("https://localhost/api/data")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // POST /submit — allowed by second rule
    let resp = client
        .post("https://localhost/submit")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // POST /api/data — not allowed (first rule is GET only, second is /submit only)
    let resp = client
        .post("https://localhost/api/data")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 451);

    // GET /submit — not allowed (second rule is POST only)
    let resp = client.get("https://localhost/submit").send().await.unwrap();
    assert_eq!(resp.status(), 451);

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Phase 7: Header forwarding + error handling tests
// ---------------------------------------------------------------------------

/// Request headers are forwarded to upstream.
#[tokio::test]
async fn test_request_headers_forwarded() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, echo_handler()).await;

    let proxy = TestProxy::start(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .await;

    let client = test_client(proxy.addr(), &ca);
    let resp = client
        .get("https://localhost/headers")
        .header("X-Custom-Header", "test-value")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("x-custom-header: test-value"),
        "Expected custom header in echo body, got: {}",
        body
    );
}

/// Response headers are forwarded to client.
#[tokio::test]
async fn test_response_headers_forwarded() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, echo_handler()).await;

    let proxy = TestProxy::start(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .await;

    let client = test_client(proxy.addr(), &ca);
    let resp = client
        .get("https://localhost/headers")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    // echo_handler sets X-Echo: true
    assert_eq!(
        resp.headers().get("X-Echo").unwrap().to_str().unwrap(),
        "true"
    );
}

/// Upstream down returns 502 Bad Gateway.
#[tokio::test]
async fn test_upstream_down_returns_502() {
    let ca = TestCa::generate();
    // Start and immediately shutdown the upstream so its port is dead
    let upstream = TestUpstream::start(&ca, ok_handler("nope")).await;
    let dead_port = upstream.port();
    upstream.shutdown();
    // Give time for the upstream to close
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let proxy = TestProxy::start(&ca, vec![rule("GET", "https://localhost/*")], dead_port).await;

    let client = test_client(proxy.addr(), &ca);
    let resp = client.get("https://localhost/gone").send().await.unwrap();

    assert_eq!(resp.status(), 502);

    proxy.shutdown();
}

/// Large response body is forwarded intact.
#[tokio::test]
async fn test_large_response_body() {
    use std::sync::Arc;

    let ca = TestCa::generate();
    // Generate a ~100KB body
    let large_body: String = "x".repeat(100_000);
    let expected = large_body.clone();

    let handler: common::UpstreamHandler = Arc::new(move |_req| {
        let body = large_body.clone();
        Box::pin(async move {
            use bytes::Bytes;
            use http_body_util::{BodyExt, Full};
            Ok(hyper::Response::builder()
                .status(200)
                .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                .unwrap())
        })
    });

    let upstream = TestUpstream::start(&ca, handler).await;

    let proxy = TestProxy::start(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .await;

    let client = test_client(proxy.addr(), &ca);
    let resp = client.get("https://localhost/large").send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body.len(), expected.len());
    assert_eq!(body, expected);

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// HTTP/2 tests
// ---------------------------------------------------------------------------

/// Default client (h2-capable) talks to h2-capable upstream — response uses HTTP/2.
#[tokio::test]
async fn test_h2_allowed_request() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("h2 hello")).await;

    let proxy = TestProxy::start(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .await;

    let client = test_client(proxy.addr(), &ca);
    let resp = client.get("https://localhost/h2").send().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    assert_eq!(resp.text().await.unwrap(), "h2 hello");

    proxy.shutdown();
    upstream.shutdown();
}

/// HTTP/1.1-only client talks to h2-capable upstream — proxy translates protocol.
#[tokio::test]
async fn test_h1_client_to_h2_upstream() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("translated")).await;

    let proxy = TestProxy::start(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .await;

    // h1-only client forces HTTP/1.1 on client side
    let client = test_client_h1_only(proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").send().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.version(), reqwest::Version::HTTP_11);
    assert_eq!(resp.text().await.unwrap(), "translated");

    proxy.shutdown();
    upstream.shutdown();
}

/// h2-capable client talks to h1-only upstream — proxy translates protocol.
#[tokio::test]
async fn test_h2_client_to_h1_upstream() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start_h1_only(&ca, ok_handler("h1 only")).await;

    let proxy = TestProxy::start(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .await;

    let client = test_client(proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").send().await.unwrap();

    assert_eq!(resp.status(), 200);
    // Client negotiated h2 with proxy, but upstream is h1 — proxy translates
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    assert_eq!(resp.text().await.unwrap(), "h1 only");

    proxy.shutdown();
    upstream.shutdown();
}

/// Blocked request over HTTP/2 returns 451.
#[tokio::test]
async fn test_h2_blocked_returns_451() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("should not reach")).await;

    let proxy = TestProxy::start(
        &ca,
        vec![rule("GET", "https://example.com/*")],
        upstream.port(),
    )
    .await;

    let client = test_client(proxy.addr(), &ca);
    let resp = client
        .get("https://localhost/blocked")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 451);
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    assert_eq!(
        resp.headers()
            .get("X-Blocked-By")
            .unwrap()
            .to_str()
            .unwrap(),
        "redlimitador"
    );

    proxy.shutdown();
    upstream.shutdown();
}

/// Large body over HTTP/2 is forwarded intact.
#[tokio::test]
async fn test_h2_large_body() {
    use std::sync::Arc;

    let ca = TestCa::generate();
    let large_body: String = "y".repeat(100_000);
    let expected = large_body.clone();

    let handler: common::UpstreamHandler = Arc::new(move |_req| {
        let body = large_body.clone();
        Box::pin(async move {
            use bytes::Bytes;
            use http_body_util::{BodyExt, Full};
            Ok(hyper::Response::builder()
                .status(200)
                .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                .unwrap())
        })
    });

    let upstream = TestUpstream::start(&ca, handler).await;

    let proxy = TestProxy::start(
        &ca,
        vec![rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .await;

    let client = test_client(proxy.addr(), &ca);
    let resp = client.get("https://localhost/large").send().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    let body = resp.text().await.unwrap();
    assert_eq!(body.len(), expected.len());
    assert_eq!(body, expected);

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// CONNECT port restriction tests
// ---------------------------------------------------------------------------

/// CONNECT to a non-443 port is blocked with 451.
#[tokio::test]
async fn test_connect_non_443_port_blocked() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("should not reach")).await;

    let proxy =
        TestProxy::start(&ca, vec![rule("*", "https://localhost/*")], upstream.port()).await;

    // Raw TCP connect to proxy, send CONNECT with non-443 port
    let mut tcp = TcpStream::connect(proxy.addr()).await.unwrap();
    let connect_req = "CONNECT localhost:8080 HTTP/1.1\r\nHost: localhost:8080\r\n\r\n";
    tcp.write_all(connect_req.as_bytes()).await.unwrap();

    // Read response
    let mut buf = [0u8; 4096];
    let n = tcp.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);

    // Should be blocked with 451
    assert!(
        response.starts_with("HTTP/1.1 451"),
        "Expected 451 response, got: {}",
        response
    );
    assert!(
        response.contains("X-Blocked-By: redlimitador"),
        "Expected X-Blocked-By header, got: {}",
        response
    );
    assert!(
        response.contains("Only HTTPS connections are allowed"),
        "Expected blocking reason in body, got: {}",
        response
    );

    proxy.shutdown();
    upstream.shutdown();
}
