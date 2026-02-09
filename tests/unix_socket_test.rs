//! Integration tests for Unix domain socket listening.
//!
//! Verifies that the proxy accepts connections and handles requests
//! correctly when bound to a Unix socket instead of TCP.

mod common;

use common::TestCa;
use pyloros::Config;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Start a proxy listening on a Unix socket. Returns the socket path and shutdown sender.
async fn start_unix_proxy(
    ca: &TestCa,
    rules: Vec<pyloros::config::Rule>,
    upstream_port: u16,
) -> (String, tokio::sync::oneshot::Sender<()>) {
    let sock_dir = TempDir::new().unwrap();
    let sock_path = sock_dir
        .path()
        .join("proxy.sock")
        .to_str()
        .unwrap()
        .to_string();

    let mut config = Config::minimal(sock_path.clone(), ca.cert_path.clone(), ca.key_path.clone());
    config.rules = rules;
    config.logging.log_allowed_requests = false;
    config.logging.log_blocked_requests = false;

    let client_tls = ca.client_tls_config();

    let mut server = pyloros::ProxyServer::new(config).unwrap();
    server = server
        .with_upstream_port_override(upstream_port)
        .with_upstream_tls(client_tls);

    let listen_addr = server.bind().await.unwrap();
    assert!(
        matches!(listen_addr, pyloros::ListenAddress::Unix(_)),
        "expected Unix listen address"
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = server.serve(shutdown_rx).await;
    });

    // Keep the temp dir alive by leaking it (cleaned up when the process exits).
    std::mem::forget(sock_dir);

    (sock_path, shutdown_tx)
}

/// Send a raw HTTP request over a Unix socket and return the response as a string.
/// Reads until the connection is closed or a timeout is reached.
async fn raw_http_via_unix(sock_path: &str, request: &str) -> String {
    let mut stream = UnixStream::connect(sock_path).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();

    // Read the response. The proxy may not close the connection immediately,
    // so read available data with a generous buffer and short poll.
    let mut buf = vec![0u8; 65536];
    let mut response = Vec::new();

    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => response.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => panic!("read error: {}", e),
            Err(_) => break, // timeout — assume response is complete
        }
    }

    String::from_utf8_lossy(&response).to_string()
}

#[tokio::test]
async fn allowed_request_through_unix_socket() {
    let t = test_report!("Allowed plain HTTP request through Unix socket proxy");

    let ca = TestCa::generate();

    // Use wiremock for plain HTTP (no TLS) upstream
    let upstream = wiremock::MockServer::start().await;
    t.setup("MockServer returning 200 'hello from upstream'");
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("hello from upstream"))
        .mount(&upstream)
        .await;
    let port = upstream.address().port();

    let (sock_path, shutdown_tx) =
        start_unix_proxy(&ca, vec![common::rule("GET", "http://localhost/*")], port).await;

    t.setup(format!("Proxy listening on Unix socket: {}", sock_path));

    t.action("Send plain HTTP GET via Unix socket");
    let response = raw_http_via_unix(
        &sock_path,
        &format!(
            "GET http://localhost:{}/test HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            port, port
        ),
    )
    .await;

    t.assert_contains("Response contains 200", &response, "200");
    t.assert_contains(
        "Response contains upstream body",
        &response,
        "hello from upstream",
    );

    shutdown_tx.send(()).unwrap();
}

#[tokio::test]
async fn blocked_request_through_unix_socket() {
    let t = test_report!("Blocked request through Unix socket returns 451");

    let ca = TestCa::generate();

    let upstream = common::TestUpstream::builder(&ca, common::ok_handler("should not see this"))
        .report(&t, "should not be reached")
        .start()
        .await;

    // No rules match this request
    let (sock_path, shutdown_tx) = start_unix_proxy(
        &ca,
        vec![common::rule("GET", "http://allowed.example.com/*")],
        upstream.port(),
    )
    .await;

    t.setup(format!("Proxy listening on Unix socket: {}", sock_path));

    t.action("Send blocked plain HTTP GET via Unix socket");
    let response = raw_http_via_unix(
        &sock_path,
        "GET http://blocked.example.com/test HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n",
    )
    .await;

    t.assert_contains("Response contains 451 status", &response, "451");
    t.assert_not_contains(
        "Response does not contain upstream body",
        &response,
        "should not see this",
    );

    shutdown_tx.send(()).unwrap();
    upstream.shutdown();
}

#[tokio::test]
async fn connect_tunnel_through_unix_socket() {
    let t = test_report!("CONNECT tunnel through Unix socket proxy");

    let ca = TestCa::generate();

    let upstream = common::TestUpstream::builder(&ca, common::ok_handler("tunnel response"))
        .report(&t, "returns 'tunnel response'")
        .start()
        .await;

    let (sock_path, shutdown_tx) = start_unix_proxy(
        &ca,
        vec![common::rule("GET", "https://localhost/*")],
        upstream.port(),
    )
    .await;

    t.setup(format!("Proxy listening on Unix socket: {}", sock_path));

    t.action("Send CONNECT request via Unix socket");

    let stream = UnixStream::connect(&sock_path).await.unwrap();
    let mut stream = tokio::io::BufStream::new(stream);

    // Send CONNECT
    stream
        .write_all(b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
        .await
        .unwrap();
    stream.flush().await.unwrap();

    // Read CONNECT response
    let mut response_buf = vec![0u8; 4096];
    let n = stream.read(&mut response_buf).await.unwrap();
    let connect_response = String::from_utf8_lossy(&response_buf[..n]).to_string();

    t.assert_contains("CONNECT response is 200", &connect_response, "200");

    // TLS handshake over the tunnel
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca.cert_der.clone()).unwrap();
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

    t.action("Perform TLS handshake over tunnel");
    let tls_stream = connector.connect(server_name, stream).await.unwrap();
    let mut tls_stream = tokio::io::BufStream::new(tls_stream);

    t.action("Send GET request over TLS tunnel");
    tls_stream
        .write_all(b"GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    tls_stream.flush().await.unwrap();

    let mut tls_response = String::new();
    tls_stream.read_to_string(&mut tls_response).await.unwrap();

    t.assert_contains("TLS response contains 200", &tls_response, "200");
    t.assert_contains(
        "TLS response contains upstream body",
        &tls_response,
        "tunnel response",
    );

    shutdown_tx.send(()).unwrap();
    upstream.shutdown();
}
