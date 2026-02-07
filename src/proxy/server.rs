//! Main proxy server

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

use super::handler::ProxyHandler;
use super::tunnel::TunnelHandler;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::filter::FilterEngine;
use crate::tls::{CertificateAuthority, MitmCertificateGenerator};

/// The main proxy server
pub struct ProxyServer {
    config: Config,
    filter_engine: Arc<FilterEngine>,
    mitm_generator: Arc<MitmCertificateGenerator>,
}

impl ProxyServer {
    /// Create a new proxy server from configuration
    pub fn new(config: Config) -> Result<Self> {
        // Load CA certificate
        let ca_cert = config
            .proxy
            .ca_cert
            .as_ref()
            .ok_or_else(|| Error::config("CA certificate path not specified"))?;
        let ca_key = config
            .proxy
            .ca_key
            .as_ref()
            .ok_or_else(|| Error::config("CA key path not specified"))?;

        let ca = CertificateAuthority::from_files(ca_cert, ca_key)?;
        let mitm_generator = Arc::new(MitmCertificateGenerator::new(ca));

        // Build filter engine
        let filter_engine = Arc::new(FilterEngine::new(config.rules.clone())?);

        tracing::info!(
            rules = filter_engine.rule_count(),
            "Filter engine initialized"
        );

        Ok(Self {
            config,
            filter_engine,
            mitm_generator,
        })
    }

    /// Create a server with an existing filter engine and MITM generator
    pub fn with_components(
        config: Config,
        filter_engine: Arc<FilterEngine>,
        mitm_generator: Arc<MitmCertificateGenerator>,
    ) -> Self {
        Self {
            config,
            filter_engine,
            mitm_generator,
        }
    }

    /// Run the proxy server
    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = self.config.proxy.bind_address.parse().map_err(|e| {
            Error::config(format!(
                "Invalid bind address '{}': {}",
                self.config.proxy.bind_address, e
            ))
        })?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::proxy(format!("Failed to bind to {}: {}", addr, e)))?;

        tracing::info!(address = %addr, "Proxy server listening");

        // Create tunnel handler
        let tunnel_handler = Arc::new(
            TunnelHandler::new(self.mitm_generator.clone(), self.filter_engine.clone())
                .with_logging(self.config.logging.log_requests),
        );

        loop {
            let (stream, client_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to accept connection");
                    continue;
                }
            };

            tracing::debug!(client = %client_addr, "New connection");

            let tunnel_handler = tunnel_handler.clone();
            let filter_engine = self.filter_engine.clone();
            let log_requests = self.config.logging.log_requests;

            // Spawn handler for this connection
            tokio::spawn(async move {
                let io = TokioIo::new(stream);

                let tunnel_handler = tunnel_handler.clone();
                let filter_engine = filter_engine.clone();

                let service = service_fn(move |req| {
                    let handler = ProxyHandler::new(tunnel_handler.clone(), filter_engine.clone())
                        .with_logging(log_requests);
                    async move { handler.handle(req).await }
                });

                if let Err(e) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                {
                    if !e.to_string().contains("connection closed") {
                        tracing::debug!(client = %client_addr, error = %e, "Connection error");
                    }
                }
            });
        }
    }

    /// Run the proxy server with graceful shutdown
    pub async fn run_until_shutdown(
        &self,
        mut shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<()> {
        let addr: SocketAddr = self.config.proxy.bind_address.parse().map_err(|e| {
            Error::config(format!(
                "Invalid bind address '{}': {}",
                self.config.proxy.bind_address, e
            ))
        })?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::proxy(format!("Failed to bind to {}: {}", addr, e)))?;

        tracing::info!(address = %addr, "Proxy server listening");

        let tunnel_handler = Arc::new(
            TunnelHandler::new(self.mitm_generator.clone(), self.filter_engine.clone())
                .with_logging(self.config.logging.log_requests),
        );

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!("Shutdown signal received");
                    return Ok(());
                }
                result = listener.accept() => {
                    let (stream, client_addr) = match result {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to accept connection");
                            continue;
                        }
                    };

                    tracing::debug!(client = %client_addr, "New connection");

                    let tunnel_handler = tunnel_handler.clone();
                    let filter_engine = self.filter_engine.clone();
                    let log_requests = self.config.logging.log_requests;

                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);

                        let tunnel_handler = tunnel_handler.clone();
                        let filter_engine = filter_engine.clone();

                        let service = service_fn(move |req| {
                            let handler = ProxyHandler::new(
                                tunnel_handler.clone(),
                                filter_engine.clone(),
                            ).with_logging(log_requests);
                            async move { handler.handle(req).await }
                        });

                        if let Err(e) = http1::Builder::new()
                            .preserve_header_case(true)
                            .title_case_headers(true)
                            .serve_connection(io, service)
                            .with_upgrades()
                            .await
                        {
                            if !e.to_string().contains("connection closed") {
                                tracing::debug!(client = %client_addr, error = %e, "Connection error");
                            }
                        }
                    });
                }
            }
        }
    }

    /// Get the bind address
    pub fn bind_address(&self) -> &str {
        &self.config.proxy.bind_address
    }

    /// Get the filter engine
    pub fn filter_engine(&self) -> &Arc<FilterEngine> {
        &self.filter_engine
    }

    /// Get the MITM generator
    pub fn mitm_generator(&self) -> &Arc<MitmCertificateGenerator> {
        &self.mitm_generator
    }
}
