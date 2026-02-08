//! HTTP request handler for the proxy

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpStream;

use super::response::{blocked_response, error_response};
use super::tunnel::TunnelHandler;
use crate::filter::{FilterEngine, RequestInfo};

/// Main proxy request handler
pub struct ProxyHandler {
    tunnel_handler: Arc<TunnelHandler>,
    filter_engine: Arc<FilterEngine>,
    log_allowed_requests: bool,
    log_blocked_requests: bool,
}

impl ProxyHandler {
    pub fn new(tunnel_handler: Arc<TunnelHandler>, filter_engine: Arc<FilterEngine>) -> Self {
        Self {
            tunnel_handler,
            filter_engine,
            log_allowed_requests: true,
            log_blocked_requests: true,
        }
    }

    pub fn with_request_logging(mut self, log_allowed: bool, log_blocked: bool) -> Self {
        self.log_allowed_requests = log_allowed;
        self.log_blocked_requests = log_blocked;
        self
    }

    /// Handle an incoming proxy request
    pub async fn handle(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        // Handle CONNECT requests (HTTPS tunneling)
        if req.method() == Method::CONNECT {
            return self.handle_connect(req).await;
        }

        // Handle regular HTTP requests (non-HTTPS)
        self.handle_http(req).await
    }

    async fn handle_connect(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let host = req.uri().host().unwrap_or("unknown").to_string();
        let port = req.uri().port_u16().unwrap_or(443);

        tracing::debug!(host = %host, port = %port, "CONNECT request");

        // Only allow HTTPS (port 443 or explicit https)
        if port != 443 {
            tracing::warn!(host = %host, port = %port, "Blocking non-HTTPS CONNECT");
            return Ok(blocked_response("CONNECT", &format!("{}:{}", host, port)));
        }

        // Get the upgrade future before we move the request
        let upgrade = hyper::upgrade::on(req);

        // Clone what we need for the spawned task
        let tunnel_handler = self.tunnel_handler.clone();
        let log_allowed = self.log_allowed_requests;
        let log_blocked = self.log_blocked_requests;

        // Spawn the tunnel handling
        tokio::spawn(async move {
            let upgraded = match upgrade.await {
                Ok(u) => u,
                Err(e) => {
                    tracing::error!(host = %host, error = %e, "Failed to upgrade connection");
                    return;
                }
            };

            if let Err(e) = tunnel_handler
                .run_mitm_tunnel(upgraded, &host, port, log_allowed, log_blocked)
                .await
            {
                // Don't log connection closed errors
                let err_str = e.to_string();
                if !err_str.contains("connection closed") && !err_str.contains("early eof") {
                    tracing::error!(host = %host, error = %e, "Tunnel error");
                }
            }
        });

        // Return 200 OK to indicate tunnel established
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Empty::<Bytes>::new().map_err(|e| match e {}).boxed())
            .unwrap())
    }

    async fn handle_http(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        // For plain HTTP proxy requests, the full URL is in the request URI
        let uri = req.uri();
        let method = req.method().to_string();

        let scheme = uri.scheme_str().unwrap_or("http");
        let host = uri.host().unwrap_or("unknown").to_string();
        let port = uri.port_u16();
        let path = uri.path();
        let query = uri.query();

        let request_info = RequestInfo::http(&method, scheme, &host, port, path, query);
        let full_url = request_info.full_url();

        // Check filter
        if !self.filter_engine.is_allowed(&request_info) {
            if self.log_blocked_requests {
                tracing::warn!(
                    method = %method,
                    url = %full_url,
                    "BLOCKED (HTTP)"
                );
            }
            return Ok(blocked_response(&method, &full_url));
        }

        if self.log_allowed_requests {
            tracing::info!(
                method = %method,
                url = %full_url,
                "ALLOWED (HTTP)"
            );
        }

        let upstream_port = port.unwrap_or(80);
        match forward_http_request(&host, upstream_port, req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                tracing::error!(host = %host, port = %upstream_port, error = %e, "HTTP forwarding error");
                Ok(error_response(&e.to_string()))
            }
        }
    }
}

/// Hop-by-hop headers that must not be forwarded (RFC 7230 §6.1).
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Forward a plain HTTP request to the upstream server.
async fn forward_http_request(
    host: &str,
    port: u16,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Box<dyn std::error::Error + Send + Sync>> {
    // Connect to upstream
    let addr = format!("{}:{}", host, port);
    let tcp = TcpStream::connect(&addr).await?;
    let io = TokioIo::new(tcp);

    // HTTP/1.1 handshake
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    // Spawn connection driver
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            let err_str = e.to_string();
            if !err_str.contains("connection closed") && !err_str.contains("early eof") {
                tracing::error!(error = %e, "HTTP upstream connection error");
            }
        }
    });

    // Rebuild request: relative URI, strip hop-by-hop headers, ensure Host header
    let (parts, body) = req.into_parts();

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let new_uri: hyper::Uri = path_and_query.parse()?;

    let mut builder = Request::builder().method(parts.method).uri(new_uri);

    // Copy headers, stripping hop-by-hop
    for (name, value) in &parts.headers {
        let name_lower = name.as_str().to_lowercase();
        if !HOP_BY_HOP_HEADERS.contains(&name_lower.as_str()) {
            builder = builder.header(name, value);
        }
    }

    // Ensure Host header is present
    if !parts.headers.contains_key(hyper::header::HOST) {
        if port == 80 {
            builder = builder.header(hyper::header::HOST, host);
        } else {
            builder = builder.header(hyper::header::HOST, format!("{}:{}", host, port));
        }
    }

    let upstream_req = builder.body(body)?;
    let resp = sender.send_request(upstream_req).await?;

    // Map the response body to BoxBody
    Ok(resp.map(|b| b.boxed()))
}
