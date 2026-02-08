//! E2E tests for credential injection feature.

mod common;

use common::{echo_handler, rule, ReportingClient, TestCa, TestProxy, TestUpstream};
use redlimitador::config::Credential;

fn cred(url: &str, header: &str, value: &str) -> Credential {
    Credential::Header {
        url: url.to_string(),
        header: header.to_string(),
        value: value.to_string(),
    }
}

#[tokio::test]
async fn test_credential_injected_for_matching_https() {
    let t = test_report!("Credential injected for matching HTTPS request");
    let ca = TestCa::generate();
    let upstream = TestUpstream::start_reported(&t, &ca, echo_handler(), "echo").await;
    let proxy = TestProxy::start_with_credentials(
        &ca,
        vec![rule("*", "https://localhost/*")],
        vec![cred("https://localhost/*", "x-api-key", "real-secret")],
        upstream.port(),
    )
    .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp = client.get("https://localhost/test").await;
    let body = resp.text().await.unwrap();
    t.assert_contains("header injected", &body, "x-api-key: real-secret");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_credential_overwrites_existing_header() {
    let t = test_report!("Credential overwrites existing header");
    let ca = TestCa::generate();
    let upstream = TestUpstream::start_reported(&t, &ca, echo_handler(), "echo").await;
    let proxy = TestProxy::start_with_credentials(
        &ca,
        vec![rule("*", "https://localhost/*")],
        vec![cred("https://localhost/*", "x-api-key", "real-secret")],
        upstream.port(),
    )
    .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp = client
        .get_with_header("https://localhost/test", "x-api-key", "dummy-value")
        .await;
    let body = resp.text().await.unwrap();
    t.assert_contains("overwritten", &body, "x-api-key: real-secret");
    t.assert_not_contains("old value gone", &body, "dummy-value");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_credential_authorization_bearer() {
    let t = test_report!("Credential with Authorization Bearer format");
    let ca = TestCa::generate();
    let upstream = TestUpstream::start_reported(&t, &ca, echo_handler(), "echo").await;
    let proxy = TestProxy::start_with_credentials(
        &ca,
        vec![rule("*", "https://localhost/*")],
        vec![cred(
            "https://localhost/*",
            "authorization",
            "Bearer real-token",
        )],
        upstream.port(),
    )
    .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp = client.get("https://localhost/test").await;
    let body = resp.text().await.unwrap();
    t.assert_contains("bearer injected", &body, "authorization: Bearer real-token");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_no_injection_for_non_matching_url() {
    let t = test_report!("No injection for non-matching URL");
    let ca = TestCa::generate();
    let upstream = TestUpstream::start_reported(&t, &ca, echo_handler(), "echo").await;
    let proxy = TestProxy::start_with_credentials(
        &ca,
        vec![rule("*", "https://localhost/*")],
        vec![cred(
            "https://other.example.com/*",
            "x-api-key",
            "should-not-appear",
        )],
        upstream.port(),
    )
    .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp = client.get("https://localhost/test").await;
    let body = resp.text().await.unwrap();
    t.assert_not_contains("no injection", &body, "x-api-key");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_multiple_credentials_different_headers() {
    let t = test_report!("Multiple credentials for different headers both injected");
    let ca = TestCa::generate();
    let upstream = TestUpstream::start_reported(&t, &ca, echo_handler(), "echo").await;
    let proxy = TestProxy::start_with_credentials(
        &ca,
        vec![rule("*", "https://localhost/*")],
        vec![
            cred("https://localhost/*", "x-api-key", "key123"),
            cred("https://localhost/*", "x-custom", "custom-val"),
        ],
        upstream.port(),
    )
    .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp = client.get("https://localhost/test").await;
    let body = resp.text().await.unwrap();
    t.assert_contains("api key", &body, "x-api-key: key123");
    t.assert_contains("custom", &body, "x-custom: custom-val");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_credential_not_injected_for_blocked_request() {
    let t = test_report!("Credential not injected for blocked request");
    let ca = TestCa::generate();
    let upstream = TestUpstream::start_reported(&t, &ca, echo_handler(), "echo").await;
    // No rules → everything blocked
    let proxy = TestProxy::start_with_credentials(
        &ca,
        vec![],
        vec![cred("https://localhost/*", "x-api-key", "secret")],
        upstream.port(),
    )
    .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp = client.get("https://localhost/test").await;
    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_no_injection_over_plain_http() {
    let t = test_report!("No injection over plain HTTP");
    let ca = TestCa::generate();

    // Start a plain HTTP upstream (no TLS) for this test
    use bytes::Bytes;
    use http_body_util::{combinators::BoxBody, BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain_port = listener.local_addr().unwrap().port();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Simple echo handler over plain HTTP
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                result = listener.accept() => {
                    let (stream, _) = match result {
                        Ok(conn) => conn,
                        Err(_) => continue,
                    };

                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let service = service_fn(|req: Request<Incoming>| {
                            async move {
                                let mut header_lines = Vec::new();
                                for (name, value) in req.headers().iter() {
                                    header_lines.push(format!("{}: {}", name, value.to_str().unwrap_or("?")));
                                }
                                let body = format!("headers:\n{}\n", header_lines.join("\n"));
                                let body: BoxBody<Bytes, hyper::Error> =
                                    Full::new(Bytes::from(body))
                                        .map_err(|e| match e {})
                                        .boxed();
                                Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .body(body)
                                        .unwrap(),
                                )
                            }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(io, service)
                            .await;
                    });
                }
            }
        }
    });

    // Proxy with credential and an HTTP rule that allows the request
    let proxy = TestProxy::start_with_credentials(
        &ca,
        vec![rule("*", &format!("http://localhost:{}/*", plain_port))],
        vec![cred(
            &format!("http://localhost:{}/*", plain_port),
            "x-api-key",
            "should-not-inject",
        )],
        plain_port, // upstream_port (unused for plain HTTP forwarding)
    )
    .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());

    let resp = client
        .get(&format!("http://localhost:{}/test", plain_port))
        .await;
    let body = resp.text().await.unwrap();
    t.assert_not_contains("no injection on HTTP", &body, "x-api-key");

    proxy.shutdown();
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_credential_with_env_var() {
    let t = test_report!("Config with env var resolution");
    std::env::set_var("TEST_CRED_E2E_SECRET", "env-resolved-value");

    let ca = TestCa::generate();
    let upstream = TestUpstream::start_reported(&t, &ca, echo_handler(), "echo").await;
    let proxy = TestProxy::start_with_credentials(
        &ca,
        vec![rule("*", "https://localhost/*")],
        vec![cred(
            "https://localhost/*",
            "x-api-key",
            "${TEST_CRED_E2E_SECRET}",
        )],
        upstream.port(),
    )
    .await;
    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp = client.get("https://localhost/test").await;
    let body = resp.text().await.unwrap();
    t.assert_contains("env var resolved", &body, "x-api-key: env-resolved-value");

    proxy.shutdown();
    upstream.shutdown();
    std::env::remove_var("TEST_CRED_E2E_SECRET");
}
