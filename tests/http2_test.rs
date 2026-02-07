mod common;

use common::{
    ok_handler, rule, test_client, test_client_h1_only, TestCa, TestProxy, TestUpstream,
    UpstreamHandler,
};

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

    let handler: UpstreamHandler = Arc::new(move |_req| {
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
