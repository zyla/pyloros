mod common;

use common::{ok_handler, rule, test_client, LogCapture, TestCa, TestUpstream};
use redlimitador::{Config, ProxyServer};

// ---------------------------------------------------------------------------
// Granular request logging config
// ---------------------------------------------------------------------------

/// With log_blocked=true, log_allowed=false: BLOCKED is logged, ALLOWED is not.
#[tokio::test]
async fn test_log_blocked_only() {
    let logs = LogCapture::new();

    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("logged")).await;

    let mut config = Config::minimal(
        "127.0.0.1:0".to_string(),
        ca.cert_path.clone(),
        ca.key_path.clone(),
    );
    config.rules = vec![rule("GET", "https://localhost/*")];
    config.logging.log_allowed_requests = false;
    config.logging.log_blocked_requests = true;

    let client_tls = ca.client_tls_config();
    let mut server = ProxyServer::new(config).unwrap();
    server = server
        .with_upstream_port_override(upstream.port())
        .with_upstream_tls(client_tls);

    let addr = server.bind().await.unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = server.serve(shutdown_rx).await;
    });

    let client = test_client(addr, &ca);

    // Allowed request — should NOT produce an ALLOWED log line
    let resp = client.get("https://localhost/ok").send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Blocked request — should produce a BLOCKED log line
    let resp = client
        .post("https://localhost/blocked")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 451);

    // Give spawned tasks a moment to flush log output
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert!(logs.contains("BLOCKED"), "expected BLOCKED log line");
    assert!(!logs.contains("ALLOWED"), "unexpected ALLOWED log line");

    let _ = shutdown_tx.send(());
    upstream.shutdown();
}

/// With log_allowed=true, log_blocked=false: ALLOWED is logged, BLOCKED is not.
#[tokio::test]
async fn test_log_allowed_only() {
    let logs = LogCapture::new();

    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("logged")).await;

    let mut config = Config::minimal(
        "127.0.0.1:0".to_string(),
        ca.cert_path.clone(),
        ca.key_path.clone(),
    );
    config.rules = vec![rule("GET", "https://localhost/*")];
    config.logging.log_allowed_requests = true;
    config.logging.log_blocked_requests = false;

    let client_tls = ca.client_tls_config();
    let mut server = ProxyServer::new(config).unwrap();
    server = server
        .with_upstream_port_override(upstream.port())
        .with_upstream_tls(client_tls);

    let addr = server.bind().await.unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = server.serve(shutdown_rx).await;
    });

    let client = test_client(addr, &ca);

    // Allowed request — should produce an ALLOWED log line
    let resp = client.get("https://localhost/ok").send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Blocked request — should NOT produce a BLOCKED log line
    let resp = client
        .post("https://localhost/blocked")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 451);

    // Give spawned tasks a moment to flush log output
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert!(logs.contains("ALLOWED"), "expected ALLOWED log line");
    assert!(!logs.contains("BLOCKED"), "unexpected BLOCKED log line");

    let _ = shutdown_tx.send(());
    upstream.shutdown();
}
