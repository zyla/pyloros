mod common;

use common::{ok_handler, rule, test_client, TestCa, TestProxy, TestUpstream};

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
    let resp = client
        .get("https://localhost/test")
        .send()
        .await
        .unwrap();

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
        resp.headers().get("X-Blocked-By").unwrap().to_str().unwrap(),
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
    let resp = client
        .get("https://localhost/path")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // POST should be blocked
    let resp = client
        .post("https://localhost/path")
        .send()
        .await
        .unwrap();
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
