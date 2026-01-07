//! HTTP request handler for the proxy

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use std::sync::Arc;

use super::tunnel::TunnelHandler;
use crate::filter::{FilterEngine, RequestInfo};

/// Main proxy request handler
pub struct ProxyHandler {
    tunnel_handler: Arc<TunnelHandler>,
    filter_engine: Arc<FilterEngine>,
    log_requests: bool,
}

impl ProxyHandler {
    pub fn new(tunnel_handler: Arc<TunnelHandler>, filter_engine: Arc<FilterEngine>) -> Self {
        Self {
            tunnel_handler,
            filter_engine,
            log_requests: true,
        }
    }

    pub fn with_logging(mut self, enabled: bool) -> Self {
        self.log_requests = enabled;
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
            return Ok(blocked_response(
                "CONNECT",
                &format!("{}:{}", host, port),
                "Only HTTPS connections are allowed",
            ));
        }

        // Get the upgrade future before we move the request
        let upgrade = hyper::upgrade::on(req);

        // Clone what we need for the spawned task
        let tunnel_handler = self.tunnel_handler.clone();
        let log_requests = self.log_requests;

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
                .run_mitm_tunnel(upgraded, &host, port, log_requests)
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
        let host = uri.host().unwrap_or("unknown");
        let port = uri.port_u16();
        let path = uri.path();
        let query = uri.query();

        let request_info = RequestInfo::http(&method, scheme, host, port, path, query);
        let full_url = request_info.full_url();

        // Check filter
        if !self.filter_engine.is_allowed(&request_info) {
            if self.log_requests {
                tracing::warn!(
                    method = %method,
                    url = %full_url,
                    "BLOCKED (HTTP)"
                );
            }
            return Ok(blocked_response(&method, &full_url, "Request blocked by policy"));
        }

        if self.log_requests {
            tracing::info!(
                method = %method,
                url = %full_url,
                "ALLOWED (HTTP)"
            );
        }

        // For plain HTTP, we could forward the request
        // But since we're focused on HTTPS, return an error for now
        Ok(Response::builder()
            .status(StatusCode::NOT_IMPLEMENTED)
            .header("Content-Type", "text/plain")
            .body(
                Full::new(Bytes::from("Plain HTTP forwarding not implemented. Use HTTPS.\n"))
                    .map_err(|e| match e {})
                    .boxed(),
            )
            .unwrap())
    }
}

/// Create an HTTP 451 response for blocked requests
fn blocked_response(
    method: &str,
    url: &str,
    reason: &str,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = format!(
        "Request blocked by proxy policy\n\nMethod: {}\nURL: {}\nReason: {}\n",
        method, url, reason
    );

    Response::builder()
        .status(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS) // 451
        .header("Content-Type", "text/plain")
        .header("X-Blocked-By", "redlimitador")
        .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
        .unwrap()
}
