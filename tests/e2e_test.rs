mod common;

use common::{echo_handler, ok_handler, rule, test_client, TestCa, TestProxy, TestUpstream};

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
            use http_body_util::{combinators::BoxBody, BodyExt, Full};
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
