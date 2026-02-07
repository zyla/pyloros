//! CONNECT tunnel handling with TLS MITM

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::ClientConfig;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::error::{Error, Result};
use crate::filter::{FilterEngine, RequestInfo};
use crate::tls::MitmCertificateGenerator;

/// Handles CONNECT tunnels with TLS MITM
pub struct TunnelHandler {
    mitm_generator: Arc<MitmCertificateGenerator>,
    filter_engine: Arc<FilterEngine>,
    upstream_port_override: Option<u16>,
    upstream_tls_config: Option<Arc<ClientConfig>>,
}

impl TunnelHandler {
    pub fn new(
        mitm_generator: Arc<MitmCertificateGenerator>,
        filter_engine: Arc<FilterEngine>,
    ) -> Self {
        Self {
            mitm_generator,
            filter_engine,
            upstream_port_override: None,
            upstream_tls_config: None,
        }
    }

    pub fn with_logging(self, _enabled: bool) -> Self {
        // Logging is handled per-request now
        self
    }

    /// Override the upstream port for all forwarded connections (for testing).
    pub fn with_upstream_port_override(mut self, port: u16) -> Self {
        self.upstream_port_override = Some(port);
        self
    }

    /// Inject a custom TLS config for upstream connections (for testing with self-signed certs).
    pub fn with_upstream_tls(mut self, config: Arc<ClientConfig>) -> Self {
        self.upstream_tls_config = Some(config);
        self
    }

    /// Run a MITM tunnel on an upgraded connection
    pub async fn run_mitm_tunnel(
        &self,
        upgraded: hyper::upgrade::Upgraded,
        host: &str,
        port: u16,
        log_requests: bool,
    ) -> Result<()> {
        let upgraded = TokioIo::new(upgraded);

        // Create TLS acceptor for the client connection
        let server_config = self.mitm_generator.server_config_for_host(host)?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        // Accept TLS from client
        let client_tls = acceptor
            .accept(upgraded)
            .await
            .map_err(|e| Error::tls(format!("Failed to accept TLS from client: {}", e)))?;

        tracing::debug!(host = %host, "TLS handshake with client complete");

        // Create service to handle HTTP requests over TLS
        let host = host.to_string();
        let filter_engine = self.filter_engine.clone();
        let upstream_port_override = self.upstream_port_override;
        let upstream_tls_config = self.upstream_tls_config.clone();

        let service = service_fn(move |req: Request<Incoming>| {
            let host = host.clone();
            let filter_engine = filter_engine.clone();
            let upstream_tls_config = upstream_tls_config.clone();
            async move {
                handle_tunneled_request(
                    req,
                    host,
                    port,
                    filter_engine,
                    log_requests,
                    upstream_port_override,
                    upstream_tls_config,
                )
                .await
            }
        });

        // Serve HTTP/1.1 or HTTP/2 over the TLS connection (auto-detected via ALPN)
        let io = TokioIo::new(client_tls);
        let mut builder = auto::Builder::new(TokioExecutor::new());
        builder.http1().preserve_header_case(true).half_close(true);

        if let Err(e) = builder.serve_connection_with_upgrades(io, service).await {
            // Connection closed errors are normal
            let err_str = e.to_string();
            if !err_str.contains("connection closed") && !err_str.contains("early eof") {
                tracing::debug!("HTTP service error: {}", e);
            }
        }

        Ok(())
    }
}

/// Handle a request that came through the MITM tunnel
async fn handle_tunneled_request(
    req: Request<Incoming>,
    host: String,
    port: u16,
    filter_engine: Arc<FilterEngine>,
    log_requests: bool,
    upstream_port_override: Option<u16>,
    upstream_tls_config: Option<Arc<ClientConfig>>,
) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|s| s.to_string());

    // Check for WebSocket upgrade
    let is_websocket = req
        .headers()
        .get(hyper::header::UPGRADE)
        .map(|v| {
            v.to_str()
                .unwrap_or("")
                .to_lowercase()
                .contains("websocket")
        })
        .unwrap_or(false);

    // Create request info for filtering
    let request_info = if is_websocket {
        RequestInfo::websocket("https", &host, Some(port), &path, query.as_deref())
    } else {
        RequestInfo::http(&method, "https", &host, Some(port), &path, query.as_deref())
    };

    let full_url = request_info.full_url();

    // Check filter
    if !filter_engine.is_allowed(&request_info) {
        if log_requests {
            tracing::warn!(
                method = %method,
                url = %full_url,
                "BLOCKED"
            );
        }
        return Ok(blocked_response(&method, &full_url));
    }

    if log_requests {
        tracing::info!(
            method = %method,
            url = %full_url,
            "ALLOWED"
        );
    }

    // Forward the request to the actual server
    let connect_port = upstream_port_override.unwrap_or(port);
    let result = if is_websocket {
        forward_websocket(req, host, connect_port, upstream_tls_config).await
    } else {
        forward_request(req, host, connect_port, upstream_tls_config).await
    };

    match result {
        Ok(resp) => Ok(resp),
        Err(e) => {
            tracing::error!(error = %e, "Failed to forward request");
            Ok(error_response(&e.to_string()))
        }
    }
}

/// Connect to upstream over TLS, returning the TLS stream.
///
/// Shared by both `forward_request` (which branches h1/h2 based on ALPN)
/// and `forward_websocket` (which always uses h1 with upgrades).
async fn connect_upstream_tls(
    host: &str,
    port: u16,
    upstream_tls_config: Option<Arc<ClientConfig>>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let addr = format!("{}:{}", host, port);
    let tcp = TcpStream::connect(&addr)
        .await
        .map_err(|e| Error::proxy(format!("Failed to connect to {}: {}", addr, e)))?;

    // Set up TLS for upstream connection (with ALPN for h2 negotiation)
    let client_config = match upstream_tls_config {
        Some(config) => config,
        None => {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Arc::new(config)
        }
    };

    let connector = TlsConnector::from(client_config);

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| Error::proxy(format!("Invalid server name '{}': {}", host, e)))?;

    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| Error::tls(format!("TLS connection to {} failed: {}", host, e)))
}

/// Rebuild an incoming request for forwarding to the upstream server,
/// updating the Host header to match the target.
fn rebuild_request_for_upstream(
    parts: hyper::http::request::Parts,
    body: Incoming,
    host: &str,
    port: u16,
) -> Result<Request<Incoming>> {
    let mut builder = Request::builder().method(parts.method).uri(parts.uri);

    for (name, value) in parts.headers.iter() {
        if name == hyper::header::HOST {
            builder = builder.header(name, format!("{}:{}", host, port));
        } else {
            builder = builder.header(name, value);
        }
    }

    builder
        .body(body)
        .map_err(|e| Error::proxy(format!("Failed to build request: {}", e)))
}

/// Forward a request to the upstream server (supports h1 and h2 via ALPN).
async fn forward_request(
    req: Request<Incoming>,
    host: String,
    port: u16,
    upstream_tls_config: Option<Arc<ClientConfig>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let tls_stream = connect_upstream_tls(&host, port, upstream_tls_config).await?;

    // Check negotiated ALPN protocol
    let negotiated_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
    tracing::debug!(host = %host, h2 = negotiated_h2, "Upstream TLS handshake complete");

    let (parts, body) = req.into_parts();
    let req = rebuild_request_for_upstream(parts, body, &host, port)?;

    let io = TokioIo::new(tls_stream);

    if negotiated_h2 {
        // HTTP/2 handshake
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(|e| Error::proxy(format!("HTTP/2 handshake failed: {}", e)))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("HTTP/2 connection error: {}", e);
            }
        });

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| Error::proxy(format!("HTTP/2 request failed: {}", e)))?;

        let (parts, body) = resp.into_parts();
        let body = body.map_err(|e| e).boxed();
        Ok(Response::from_parts(parts, body))
    } else {
        // HTTP/1.1 handshake
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| Error::proxy(format!("HTTP handshake failed: {}", e)))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("Connection error: {}", e);
            }
        });

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| Error::proxy(format!("Request failed: {}", e)))?;

        let (parts, body) = resp.into_parts();
        let body = body.map_err(|e| e).boxed();
        Ok(Response::from_parts(parts, body))
    }
}

/// Forward a WebSocket upgrade request, then bidirectionally copy frames.
///
/// WebSocket always uses HTTP/1.1 (upgrade mechanism), so this bypasses
/// the h2 ALPN negotiation and forces an h1 connection with upgrades enabled.
async fn forward_websocket(
    mut req: Request<Incoming>,
    host: String,
    port: u16,
    upstream_tls_config: Option<Arc<ClientConfig>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let tls_stream = connect_upstream_tls(&host, port, upstream_tls_config).await?;
    let io = TokioIo::new(tls_stream);

    // WebSocket requires HTTP/1.1 with upgrades
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| Error::proxy(format!("HTTP handshake failed: {}", e)))?;

    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!("Connection error: {}", e);
        }
    });

    // Extract the client-side upgrade future via &mut (doesn't consume the request)
    let client_on_upgrade = hyper::upgrade::on(&mut req);

    let (parts, body) = req.into_parts();
    let upstream_req = rebuild_request_for_upstream(parts, body, &host, port)?;

    let mut resp = sender
        .send_request(upstream_req)
        .await
        .map_err(|e| Error::proxy(format!("WebSocket request failed: {}", e)))?;

    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        let (parts, body) = resp.into_parts();
        let body = body.map_err(|e| e).boxed();
        return Ok(Response::from_parts(parts, body));
    }

    // Extract the upstream upgrade future via &mut
    let upstream_on_upgrade = hyper::upgrade::on(&mut resp);

    // Build a 101 response to send back to the client, copying upgrade headers
    let mut client_resp = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (name, value) in resp.headers() {
        client_resp = client_resp.header(name, value);
    }

    let client_response = client_resp
        .body(
            Empty::new()
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )
        .map_err(|e| Error::proxy(format!("Failed to build 101 response: {}", e)))?;

    // Spawn a task to bridge the two upgraded connections
    tokio::spawn(async move {
        let (client_upgraded, upstream_upgraded) =
            match tokio::try_join!(client_on_upgrade, upstream_on_upgrade) {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::debug!("WebSocket upgrade failed: {}", e);
                    return;
                }
            };

        let mut client_io = TokioIo::new(client_upgraded);
        let mut upstream_io = TokioIo::new(upstream_upgraded);

        if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await {
            tracing::debug!("WebSocket bridge ended: {}", e);
        }
    });

    Ok(client_response)
}

/// Create an HTTP 451 response for blocked requests
fn blocked_response(method: &str, url: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = format!(
        "Request blocked by proxy policy\n\nMethod: {}\nURL: {}\n",
        method, url
    );

    Response::builder()
        .status(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS) // 451
        .header("Content-Type", "text/plain")
        .header("X-Blocked-By", "redlimitador")
        .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
        .unwrap()
}

/// Create an error response
fn error_response(message: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = format!("Proxy error: {}\n", message);

    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_response() {
        let resp = blocked_response("GET", "https://example.com/blocked");
        assert_eq!(resp.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    }

    #[test]
    fn test_error_response() {
        let resp = error_response("test error");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
