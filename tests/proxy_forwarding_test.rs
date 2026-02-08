mod common;

use common::{
    echo_handler, ok_handler, rule, test_client, TestCa, TestProxy, TestUpstream, UpstreamHandler,
};

// ---------------------------------------------------------------------------
// Header forwarding + error handling tests
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
        response.contains("Request blocked by proxy policy"),
        "Expected blocked-by-policy message in body, got: {}",
        response
    );

    proxy.shutdown();
    upstream.shutdown();
}
