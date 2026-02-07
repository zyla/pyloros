//! CONNECT tunnel handling with TLS MITM

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
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
}

impl TunnelHandler {
    pub fn new(
        mitm_generator: Arc<MitmCertificateGenerator>,
        filter_engine: Arc<FilterEngine>,
    ) -> Self {
        Self {
            mitm_generator,
            filter_engine,
        }
    }

    pub fn with_logging(self, _enabled: bool) -> Self {
        // Logging is handled per-request now
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

        let service = service_fn(move |req: Request<Incoming>| {
            let host = host.clone();
            let filter_engine = filter_engine.clone();
            async move { handle_tunneled_request(req, host, port, filter_engine, log_requests).await }
        });

        // Serve HTTP/1.1 over the TLS connection
        let io = TokioIo::new(client_tls);
        if let Err(e) = http1::Builder::new()
            .preserve_header_case(true)
            .serve_connection(io, service)
            .with_upgrades()
            .await
        {
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
    match forward_request(req, host, port).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            tracing::error!(error = %e, "Failed to forward request");
            Ok(error_response(&e.to_string()))
        }
    }
}

/// Forward a request to the upstream server
async fn forward_request(
    req: Request<Incoming>,
    host: String,
    port: u16,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    // Connect to upstream
    let addr = format!("{}:{}", host, port);
    let tcp = TcpStream::connect(&addr)
        .await
        .map_err(|e| Error::proxy(format!("Failed to connect to {}: {}", addr, e)))?;

    // Set up TLS for upstream connection
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));

    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|e| Error::proxy(format!("Invalid server name '{}': {}", host, e)))?;

    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| Error::tls(format!("TLS connection to {} failed: {}", host, e)))?;

    let io = TokioIo::new(tls_stream);

    // Create HTTP connection
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| Error::proxy(format!("HTTP handshake failed: {}", e)))?;

    // Spawn connection driver
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("Connection error: {}", e);
        }
    });

    // Rebuild the request with proper host header
    let (parts, body) = req.into_parts();
    let mut builder = Request::builder().method(parts.method).uri(parts.uri);

    // Copy headers
    for (name, value) in parts.headers.iter() {
        // Update Host header to match actual target
        if name == hyper::header::HOST {
            builder = builder.header(name, format!("{}:{}", host, port));
        } else {
            builder = builder.header(name, value);
        }
    }

    let req = builder
        .body(body)
        .map_err(|e| Error::proxy(format!("Failed to build request: {}", e)))?;

    // Send request
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| Error::proxy(format!("Request failed: {}", e)))?;

    // Convert response body
    let (parts, body) = resp.into_parts();
    let body = body.map_err(|e| e).boxed();

    Ok(Response::from_parts(parts, body))
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
