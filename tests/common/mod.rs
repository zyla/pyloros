//! Test infrastructure for e2e proxy tests.

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use redlimitador::tls::{CertificateAuthority, GeneratedCa};
use redlimitador::{Config, ProxyServer};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// TestCa
// ---------------------------------------------------------------------------

/// A test CA that generates certs and saves them to a tempdir.
pub struct TestCa {
    pub ca: CertificateAuthority,
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: CertificateDer<'static>,
    pub dir: TempDir,
    pub cert_path: String,
    pub key_path: String,
}

impl TestCa {
    pub fn generate() -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let generated = GeneratedCa::generate().unwrap();
        let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
        let cert_der = ca.cert_der().clone();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("ca.crt");
        let key_path = dir.path().join("ca.key");
        generated.save(&cert_path, &key_path).unwrap();

        Self {
            ca,
            cert_pem: generated.cert_pem,
            key_pem: generated.key_pem,
            cert_der,
            cert_path: cert_path.to_str().unwrap().to_string(),
            key_path: key_path.to_str().unwrap().to_string(),
            dir,
        }
    }

    /// Build a rustls ClientConfig that trusts this CA (with h2 + h1 ALPN).
    pub fn client_tls_config(&self) -> Arc<ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(self.cert_der.clone()).unwrap();
        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    }

    /// Build a rustls ServerConfig for a given hostname signed by this CA (with h2 + h1 ALPN).
    pub fn server_tls_config(&self, hostname: &str) -> Arc<ServerConfig> {
        let (cert, key) = self.ca.generate_cert_for_host(hostname).unwrap();
        let cert_chain = vec![cert, self.cert_der.clone()];
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    }

    /// Build a rustls ServerConfig that only advertises HTTP/1.1 ALPN.
    pub fn server_tls_config_h1_only(&self, hostname: &str) -> Arc<ServerConfig> {
        let (cert, key) = self.ca.generate_cert_for_host(hostname).unwrap();
        let cert_chain = vec![cert, self.cert_der.clone()];
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }
}

// ---------------------------------------------------------------------------
// TestUpstream — a tiny HTTPS server
// ---------------------------------------------------------------------------

/// A handler function for the test upstream.
pub type UpstreamHandler =
    Arc<dyn Fn(Request<Incoming>) -> UpstreamResponse + Send + Sync + 'static>;

pub type UpstreamResponse = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>,
            > + Send,
    >,
>;

/// A test HTTPS upstream server.
pub struct TestUpstream {
    pub addr: SocketAddr,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl TestUpstream {
    /// Start a test upstream HTTPS server that responds with the given handler.
    pub async fn start(ca: &TestCa, handler: UpstreamHandler) -> Self {
        Self::start_for_host(ca, "localhost", handler).await
    }

    /// Start a test upstream HTTPS server with a cert for the given hostname (h2 + h1).
    pub async fn start_for_host(ca: &TestCa, hostname: &str, handler: UpstreamHandler) -> Self {
        let server_config = ca.server_tls_config(hostname);
        Self::start_with_config(server_config, handler).await
    }

    /// Start a test upstream HTTPS server that only speaks HTTP/1.1.
    pub async fn start_h1_only(ca: &TestCa, handler: UpstreamHandler) -> Self {
        let server_config = ca.server_tls_config_h1_only("localhost");
        Self::start_with_config(server_config, handler).await
    }

    async fn start_with_config(server_config: Arc<ServerConfig>, handler: UpstreamHandler) -> Self {
        let h1_only = !server_config.alpn_protocols.iter().any(|p| p == b"h2");
        let acceptor = TlsAcceptor::from(server_config);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    result = listener.accept() => {
                        let (stream, _) = match result {
                            Ok(conn) => conn,
                            Err(_) => continue,
                        };

                        let acceptor = acceptor.clone();
                        let handler = handler.clone();

                        tokio::spawn(async move {
                            let tls_stream = match acceptor.accept(stream).await {
                                Ok(s) => s,
                                Err(_) => return,
                            };
                            let io = TokioIo::new(tls_stream);

                            let service = service_fn(move |req: Request<Incoming>| {
                                let handler = handler.clone();
                                handler(req)
                            });

                            if h1_only {
                                let _ = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .with_upgrades()
                                    .await;
                            } else {
                                let _ = auto::Builder::new(TokioExecutor::new())
                                    .serve_connection_with_upgrades(io, service)
                                    .await;
                            }
                        });
                    }
                }
            }
        });

        Self { addr, shutdown_tx }
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// A simple upstream handler that returns 200 with a text body.
pub fn ok_handler(body: &'static str) -> UpstreamHandler {
    Arc::new(move |_req| {
        Box::pin(async move {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                .unwrap())
        })
    })
}

/// An upstream handler that echoes request details back.
pub fn echo_handler() -> UpstreamHandler {
    Arc::new(|req: Request<Incoming>| {
        Box::pin(async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();

            // Collect interesting headers
            let mut header_lines = Vec::new();
            for (name, value) in req.headers().iter() {
                header_lines.push(format!("{}: {}", name, value.to_str().unwrap_or("?")));
            }

            let body = format!(
                "method={}\npath={}\n{}\n",
                method,
                path,
                header_lines.join("\n")
            );

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .header("X-Echo", "true")
                .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                .unwrap())
        })
    })
}

// ---------------------------------------------------------------------------
// TestProxy — wraps ProxyServer with bind + spawn
// ---------------------------------------------------------------------------

pub struct TestProxy {
    pub addr: SocketAddr,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl TestProxy {
    /// Start a proxy configured with the given CA, rules, and upstream override.
    pub async fn start(
        ca: &TestCa,
        rules: Vec<redlimitador::config::Rule>,
        upstream_port: u16,
    ) -> Self {
        let mut config = Config::minimal(
            "127.0.0.1:0".to_string(),
            ca.cert_path.clone(),
            ca.key_path.clone(),
        );
        config.rules = rules;
        config.logging.log_requests = false;

        let client_tls = ca.client_tls_config();

        let mut server = ProxyServer::new(config).unwrap();
        server = server
            .with_upstream_port_override(upstream_port)
            .with_upstream_tls(client_tls);

        let addr = server.bind().await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let _ = server.serve(shutdown_rx).await;
        });

        Self { addr, shutdown_tx }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

// ---------------------------------------------------------------------------
// test_client — reqwest client that uses the proxy and trusts the test CA
// ---------------------------------------------------------------------------

/// Build a reqwest client that routes through the given proxy and trusts the test CA.
/// By default reqwest negotiates h2 when available.
pub fn test_client(proxy_addr: SocketAddr, ca: &TestCa) -> reqwest::Client {
    let proxy_url = format!("http://{}", proxy_addr);
    let proxy = reqwest::Proxy::all(&proxy_url).unwrap();

    let ca_cert = reqwest::tls::Certificate::from_pem(ca.cert_pem.as_bytes()).unwrap();

    reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(ca_cert)
        .build()
        .unwrap()
}

/// Build a reqwest client that forces HTTP/1.1 only (no h2 negotiation).
pub fn test_client_h1_only(proxy_addr: SocketAddr, ca: &TestCa) -> reqwest::Client {
    let proxy_url = format!("http://{}", proxy_addr);
    let proxy = reqwest::Proxy::all(&proxy_url).unwrap();

    let ca_cert = reqwest::tls::Certificate::from_pem(ca.cert_pem.as_bytes()).unwrap();

    reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(ca_cert)
        .http1_only()
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Rule helpers
// ---------------------------------------------------------------------------

pub fn rule(method: &str, url: &str) -> redlimitador::config::Rule {
    redlimitador::config::Rule {
        method: method.to_string(),
        url: url.to_string(),
        websocket: false,
    }
}

pub fn ws_rule(url: &str) -> redlimitador::config::Rule {
    redlimitador::config::Rule {
        method: "GET".to_string(),
        url: url.to_string(),
        websocket: true,
    }
}

/// An upstream handler that accepts WebSocket upgrades and echoes messages back.
pub fn ws_echo_handler() -> UpstreamHandler {
    use http_body_util::Empty;
    use tokio_tungstenite::WebSocketStream;

    Arc::new(|mut req: Request<Incoming>| {
        Box::pin(async move {
            // Verify this is a valid websocket upgrade request
            if !req
                .headers()
                .get(hyper::header::UPGRADE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.to_lowercase().contains("websocket"))
            {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(
                        Full::new(Bytes::from("Not a WebSocket request"))
                            .map_err(|e| match e {})
                            .boxed(),
                    )
                    .unwrap());
            }

            // Extract the upgrade future before sending the 101 response
            let on_upgrade = hyper::upgrade::on(&mut req);

            // Derive the Sec-WebSocket-Accept value
            let ws_key = req
                .headers()
                .get("sec-websocket-key")
                .map(|v| v.to_str().unwrap_or("").to_string())
                .unwrap_or_default();
            let accept = tungstenite_accept_key(&ws_key);

            // Spawn the echo task
            tokio::spawn(async move {
                let upgraded = match on_upgrade.await {
                    Ok(u) => u,
                    Err(e) => {
                        eprintln!("ws_echo_handler upgrade failed: {}", e);
                        return;
                    }
                };

                let ws = WebSocketStream::from_raw_socket(
                    TokioIo::new(upgraded),
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    None,
                )
                .await;

                use futures_util::{SinkExt, StreamExt};
                let (mut tx, mut rx) = ws.split();
                while let Some(Ok(msg)) = rx.next().await {
                    if msg.is_close() {
                        let _ = tx.close().await;
                        break;
                    }
                    if msg.is_text() || msg.is_binary() {
                        if tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                }
            });

            // Send 101 Switching Protocols response
            Ok(Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(hyper::header::UPGRADE, "websocket")
                .header(hyper::header::CONNECTION, "Upgrade")
                .header("Sec-WebSocket-Accept", accept)
                .body(
                    Empty::new()
                        .map_err(|e: std::convert::Infallible| match e {})
                        .boxed(),
                )
                .unwrap())
        })
    })
}

/// Compute the Sec-WebSocket-Accept value from a Sec-WebSocket-Key.
fn tungstenite_accept_key(key: &str) -> String {
    tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes())
}
