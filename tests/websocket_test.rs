mod common;

use common::{ok_handler, ws_echo_handler, ws_rule, TestCa, TestProxy, TestUpstream};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

/// Connect a WebSocket client through the HTTP CONNECT proxy to wss://localhost/path.
///
/// Returns a WebSocketStream ready for sending/receiving messages.
async fn ws_connect_through_proxy(
    proxy_addr: SocketAddr,
    ca: &TestCa,
    path: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>> {
    // Step 1: TCP connect to proxy
    let mut tcp = TcpStream::connect(proxy_addr).await.unwrap();

    // Step 2: Send HTTP CONNECT request
    let connect_req = "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n";
    tcp.write_all(connect_req.as_bytes()).await.unwrap();

    // Step 3: Read the 200 OK response from the proxy
    let mut buf = [0u8; 1024];
    let n = tcp.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "Expected 200 from CONNECT, got: {}",
        response
    );

    // Step 4: TLS handshake over the tunnel (proxy does MITM, so we trust the test CA)
    let tls_config = ca.client_tls_config();
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();

    // Step 5: WebSocket handshake over TLS
    let ws_url = format!("wss://localhost{}", path);
    let (ws_stream, _resp) = tokio_tungstenite::client_async(&ws_url, tls_stream)
        .await
        .expect("WebSocket handshake failed");

    ws_stream
}

// ---------------------------------------------------------------------------
// Group 1: Basic WebSocket echo + blocked
// ---------------------------------------------------------------------------

/// WebSocket echo through the proxy: send a text message, receive it back.
#[tokio::test]
async fn test_websocket_echo() {
    let t = test_report!("WebSocket echo through proxy");

    let ca = TestCa::generate();
    let upstream =
        TestUpstream::start_reported(&t, &ca, ws_echo_handler(), "ws echo handler").await;
    let proxy =
        TestProxy::start_reported(&t, &ca, vec![ws_rule("wss://localhost/*")], upstream.port())
            .await;

    t.action("WebSocket connect to wss://localhost/echo");
    let mut ws = ws_connect_through_proxy(proxy.addr(), &ca, "/echo").await;

    t.action("Send text message 'hello websocket'");
    ws.send(Message::Text("hello websocket".into()))
        .await
        .unwrap();

    let msg = ws.next().await.unwrap().unwrap();
    t.assert_eq(
        "Echo response",
        &msg,
        &Message::Text("hello websocket".into()),
    );

    ws.close(None).await.unwrap();
    proxy.shutdown();
    upstream.shutdown();
}

/// WebSocket request blocked by filter returns 451.
#[tokio::test]
async fn test_websocket_blocked_by_filter() {
    let t = test_report!("WebSocket blocked by filter returns 451");

    let ca = TestCa::generate();
    let upstream =
        TestUpstream::start_reported(&t, &ca, ws_echo_handler(), "ws echo handler").await;

    // Only allow example.com, not localhost
    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![ws_rule("wss://example.com/*")],
        upstream.port(),
    )
    .await;

    // Step 1: TCP connect to proxy
    t.action("TCP CONNECT + TLS handshake to localhost:443");
    let mut tcp = TcpStream::connect(proxy.addr()).await.unwrap();

    // Step 2: Send HTTP CONNECT
    let connect_req = "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n";
    tcp.write_all(connect_req.as_bytes()).await.unwrap();

    // Step 3: Read CONNECT response
    let mut buf = [0u8; 1024];
    let n = tcp.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.starts_with("HTTP/1.1 200"));

    // Step 4: TLS handshake
    let tls_config = ca.client_tls_config();
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();

    // Step 5: Send raw HTTP WebSocket upgrade request
    t.action("Send WebSocket upgrade request to /echo");
    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;
    let (mut read_half, mut write_half) = tokio::io::split(tls_stream);

    let upgrade_req = "GET /echo HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\
        \r\n";
    write_half.write_all(upgrade_req.as_bytes()).await.unwrap();

    // Step 6: Read the response — should be 451
    let mut resp_buf = vec![0u8; 4096];
    let n = read_half.read(&mut resp_buf).await.unwrap();
    let resp = String::from_utf8_lossy(&resp_buf[..n]).to_string();

    t.assert_starts_with("Response is 451", &resp, "HTTP/1.1 451");

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Group 2: Multiple messages + binary
// ---------------------------------------------------------------------------

/// Send several text messages and verify all are echoed back in order.
#[tokio::test]
async fn test_websocket_multiple_messages() {
    let t = test_report!("WebSocket multiple messages echoed in order");

    let ca = TestCa::generate();
    let upstream =
        TestUpstream::start_reported(&t, &ca, ws_echo_handler(), "ws echo handler").await;
    let proxy =
        TestProxy::start_reported(&t, &ca, vec![ws_rule("wss://localhost/*")], upstream.port())
            .await;

    t.action("WebSocket connect to wss://localhost/multi");
    let mut ws = ws_connect_through_proxy(proxy.addr(), &ca, "/multi").await;

    let messages = vec!["first", "second", "third", "fourth", "fifth"];
    for msg in &messages {
        t.action(format!("Send text '{}'", msg));
        ws.send(Message::Text((*msg).into())).await.unwrap();
    }

    for expected in &messages {
        let msg = ws.next().await.unwrap().unwrap();
        t.assert_eq(
            &format!("Echo of '{}'", expected),
            &msg,
            &Message::Text((*expected).into()),
        );
    }

    ws.close(None).await.unwrap();
    proxy.shutdown();
    upstream.shutdown();
}

/// Send binary data through the WebSocket proxy and verify integrity.
#[tokio::test]
async fn test_websocket_binary_message() {
    let t = test_report!("WebSocket binary message integrity");

    let ca = TestCa::generate();
    let upstream =
        TestUpstream::start_reported(&t, &ca, ws_echo_handler(), "ws echo handler").await;
    let proxy =
        TestProxy::start_reported(&t, &ca, vec![ws_rule("wss://localhost/*")], upstream.port())
            .await;

    t.action("WebSocket connect to wss://localhost/binary");
    let mut ws = ws_connect_through_proxy(proxy.addr(), &ca, "/binary").await;

    // Send binary data with all byte values 0-255
    let binary_data: Vec<u8> = (0..=255).collect();
    t.action("Send binary message (256 bytes, all byte values)");
    ws.send(Message::Binary(binary_data.clone().into()))
        .await
        .unwrap();

    let msg = ws.next().await.unwrap().unwrap();
    match msg {
        Message::Binary(data) => {
            t.assert_eq("Binary data length", &data.len(), &binary_data.len());
            t.assert_true(
                "Binary data matches",
                data.as_ref() == binary_data.as_slice(),
            );
        }
        other => panic!("Expected Binary message, got {:?}", other),
    }

    ws.close(None).await.unwrap();
    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Group 3: Upstream rejection
// ---------------------------------------------------------------------------

/// When upstream returns a non-101 response to a WebSocket upgrade, the proxy
/// forwards the rejection to the client.
#[tokio::test]
async fn test_websocket_upstream_rejects() {
    let t = test_report!("WebSocket upstream rejection forwarded");

    let ca = TestCa::generate();
    let upstream = TestUpstream::start_reported(
        &t,
        &ca,
        ok_handler("not a websocket server"),
        "returns 200 (not ws)",
    )
    .await;
    let proxy =
        TestProxy::start_reported(&t, &ca, vec![ws_rule("wss://localhost/*")], upstream.port())
            .await;

    // Manually do CONNECT + TLS + raw HTTP upgrade request
    t.action("TCP CONNECT + TLS handshake to localhost:443");
    let mut tcp = TcpStream::connect(proxy.addr()).await.unwrap();
    let connect_req = "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n";
    tcp.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = tcp.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.starts_with("HTTP/1.1 200"));

    let tls_config = ca.client_tls_config();
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();

    // Try WebSocket handshake — upstream doesn't support it, so it should fail
    t.action("WebSocket handshake to wss://localhost/ws (expect failure)");
    let ws_url = "wss://localhost/ws";
    let result = tokio_tungstenite::client_async(ws_url, tls_stream).await;

    t.assert_true("WebSocket handshake failed", result.is_err());
    let err = result.unwrap_err().to_string();
    t.assert_contains("Error mentions status 200", &err, "200");

    proxy.shutdown();
    upstream.shutdown();
}

// ---------------------------------------------------------------------------
// Group 4: Control frames
// ---------------------------------------------------------------------------

/// Ping frames are forwarded through the proxy tunnel; upstream tungstenite
/// auto-responds with a Pong carrying the same payload.
#[tokio::test]
async fn test_websocket_ping_pong() {
    let t = test_report!("WebSocket ping/pong control frames");

    let ca = TestCa::generate();
    let upstream =
        TestUpstream::start_reported(&t, &ca, ws_echo_handler(), "ws echo handler").await;
    let proxy =
        TestProxy::start_reported(&t, &ca, vec![ws_rule("wss://localhost/*")], upstream.port())
            .await;

    t.action("WebSocket connect to wss://localhost/ping");
    let mut ws = ws_connect_through_proxy(proxy.addr(), &ca, "/ping").await;

    // Send a Ping control frame
    t.action("Send Ping with payload 'ping-payload'");
    ws.send(Message::Ping(b"ping-payload".to_vec().into()))
        .await
        .unwrap();

    // Send a Text message to trigger the upstream to flush its auto-pong
    t.action("Send Text 'hello' to flush pong");
    ws.send(Message::Text("hello".into())).await.unwrap();

    // Collect the next 2 messages — expect Pong + Text echo (order not guaranteed)
    let mut received = Vec::new();
    for _ in 0..2 {
        let msg = ws.next().await.unwrap().unwrap();
        received.push(msg);
    }

    let has_pong = received.iter().any(|m| match m {
        Message::Pong(data) => data.as_ref() == b"ping-payload",
        _ => false,
    });
    let has_echo = received.iter().any(|m| *m == Message::Text("hello".into()));

    t.assert_true("Received Pong with correct payload", has_pong);
    t.assert_true("Received Text echo", has_echo);

    // Clean close
    ws.close(None).await.unwrap();
    proxy.shutdown();
    upstream.shutdown();
}
