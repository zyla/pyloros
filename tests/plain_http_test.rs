mod common;

use common::{rule, test_client, TestCa, TestProxy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Plain HTTP forwarding tests
// ---------------------------------------------------------------------------

/// Allowed plain HTTP GET reaches upstream and returns 200 + body.
#[tokio::test]
async fn test_http_allowed_get_returns_200() {
    let ca = TestCa::generate();
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("hello plain http"))
        .mount(&upstream)
        .await;

    let port = upstream.address().port();
    let proxy = TestProxy::start(
        &ca,
        vec![rule("GET", "http://localhost/*")],
        port, // unused for plain HTTP, but required by TestProxy
    )
    .await;

    let client = test_client(proxy.addr(), &ca);
    let url = format!("http://localhost:{}/test", port);
    let resp = client.get(&url).send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "hello plain http");

    proxy.shutdown();
}

/// Blocked plain HTTP request returns 451.
#[tokio::test]
async fn test_http_blocked_request_returns_451() {
    let ca = TestCa::generate();
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("should not reach"))
        .mount(&upstream)
        .await;

    let port = upstream.address().port();
    // Rule only allows example.com, not localhost
    let proxy = TestProxy::start(&ca, vec![rule("GET", "http://example.com/*")], port).await;

    let client = test_client(proxy.addr(), &ca);
    let url = format!("http://localhost:{}/blocked", port);
    let resp = client.get(&url).send().await.unwrap();

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
}

/// Plain HTTP forwarding strips hop-by-hop headers and forwards custom headers.
#[tokio::test]
async fn test_http_headers_forwarded() {
    let ca = TestCa::generate();
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let port = upstream.address().port();
    let proxy = TestProxy::start(&ca, vec![rule("GET", "http://localhost/*")], port).await;

    let client = test_client(proxy.addr(), &ca);
    let url = format!("http://localhost:{}/headers", port);
    let resp = client
        .get(&url)
        .header("X-Custom-Header", "test-value")
        .header("Proxy-Connection", "keep-alive") // hop-by-hop, should be stripped
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    // Inspect what the upstream actually received
    let received = upstream.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let req = &received[0];

    assert_eq!(
        req.headers
            .get("x-custom-header")
            .unwrap()
            .to_str()
            .unwrap(),
        "test-value",
    );
    assert!(
        req.headers.get("proxy-connection").is_none(),
        "Hop-by-hop header proxy-connection should be stripped"
    );

    proxy.shutdown();
}

/// Plain HTTP upstream unreachable returns 502 Bad Gateway.
#[tokio::test]
async fn test_http_upstream_down_returns_502() {
    let ca = TestCa::generate();
    // Bind a port then drop the listener so nothing is listening
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = listener.local_addr().unwrap().port();
    drop(listener);

    let proxy = TestProxy::start(&ca, vec![rule("GET", "http://localhost/*")], dead_port).await;

    let client = test_client(proxy.addr(), &ca);
    let url = format!("http://localhost:{}/gone", dead_port);
    let resp = client.get(&url).send().await.unwrap();

    assert_eq!(resp.status(), 502);

    proxy.shutdown();
}

/// Plain HTTP POST with body is forwarded to upstream.
#[tokio::test]
async fn test_http_post_with_body() {
    let ca = TestCa::generate();
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("post ok"))
        .mount(&upstream)
        .await;

    let port = upstream.address().port();
    let proxy = TestProxy::start(&ca, vec![rule("POST", "http://localhost/*")], port).await;

    let client = test_client(proxy.addr(), &ca);
    let url = format!("http://localhost:{}/submit", port);
    let resp = client
        .post(&url)
        .body("hello from client")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "post ok");

    // Verify upstream received the POST with correct method and body
    let received = upstream.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let req = &received[0];
    assert_eq!(req.method.as_str(), "POST");
    assert_eq!(req.body, b"hello from client");

    proxy.shutdown();
}

/// When the client does not send a Host header, the proxy constructs one
/// in the format `host:port` for non-80 ports.
#[tokio::test]
async fn test_host_header_constructed_when_absent() {
    let ca = TestCa::generate();
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&upstream)
        .await;

    let port = upstream.address().port();
    let proxy = TestProxy::start(&ca, vec![rule("GET", "http://localhost/*")], port).await;

    // Send a raw HTTP request through the proxy *without* a Host header.
    // reqwest always adds Host, so we use a raw TCP stream.
    let mut stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
    let raw_request = format!("GET http://localhost:{}/host-test HTTP/1.1\r\n\r\n", port);
    stream.write_all(raw_request.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("200"),
        "Expected 200 response, got: {}",
        response
    );

    // Verify upstream received a constructed Host header
    let received = upstream.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let req = &received[0];
    let host_value = req.headers.get("host").unwrap().to_str().unwrap();
    assert_eq!(
        host_value,
        format!("localhost:{}", port),
        "Proxy should construct Host: localhost:<port> when client omits Host"
    );

    proxy.shutdown();
}

/// When the client sends an explicit Host header, the proxy preserves it
/// and does NOT overwrite it with a constructed one.
#[tokio::test]
async fn test_host_header_preserved_when_present() {
    let ca = TestCa::generate();
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&upstream)
        .await;

    let port = upstream.address().port();
    let proxy = TestProxy::start(&ca, vec![rule("GET", "http://localhost/*")], port).await;

    // Send a raw HTTP request with an explicit custom Host header
    let mut stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
    let raw_request = format!(
        "GET http://localhost:{}/host-test HTTP/1.1\r\nHost: custom.example.com\r\n\r\n",
        port
    );
    stream.write_all(raw_request.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("200"),
        "Expected 200 response, got: {}",
        response
    );

    // Verify upstream received the original Host header, not a constructed one
    let received = upstream.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let req = &received[0];
    let host_value = req.headers.get("host").unwrap().to_str().unwrap();
    assert_eq!(
        host_value, "custom.example.com",
        "Proxy should preserve client-provided Host header, not overwrite it"
    );

    proxy.shutdown();
}
