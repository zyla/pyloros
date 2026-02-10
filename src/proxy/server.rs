//! Main proxy server

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;

use super::handler::ProxyHandler;
use super::tunnel::TunnelHandler;
use crate::audit::AuditLogger;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::filter::{CredentialEngine, FilterEngine};
use crate::tls::{CertificateAuthority, MitmCertificateGenerator};

/// The address the proxy is listening on after bind().
pub enum ListenAddress {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl ListenAddress {
    /// Returns the TCP socket address, panicking if this is a Unix socket.
    /// Useful in tests that always bind to TCP.
    pub fn tcp_addr(&self) -> SocketAddr {
        match self {
            ListenAddress::Tcp(addr) => *addr,
            #[cfg(unix)]
            ListenAddress::Unix(path) => {
                panic!("expected TCP address, got Unix socket: {}", path.display())
            }
        }
    }
}

impl fmt::Display for ListenAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListenAddress::Tcp(addr) => write!(f, "{}", addr),
            #[cfg(unix)]
            ListenAddress::Unix(path) => write!(f, "{}", path.display()),
        }
    }
}

/// Internal enum wrapping the bound listener.
enum BoundListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

/// The main proxy server
pub struct ProxyServer {
    config: Config,
    filter_engine: Arc<FilterEngine>,
    credential_engine: Arc<CredentialEngine>,
    mitm_generator: Arc<MitmCertificateGenerator>,
    resolved_auth: Option<(String, String)>,
    audit_logger: Option<Arc<AuditLogger>>,
    listener: Option<BoundListener>,
    upstream_port_override: Option<u16>,
    upstream_host_override: Option<String>,
    upstream_tls_config: Option<Arc<ClientConfig>>,
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

        // Build credential engine
        let credential_engine = Arc::new(CredentialEngine::new(config.credentials.clone())?);

        // Resolve auth credentials at startup (expands ${ENV_VAR})
        let resolved_auth = config.resolved_auth()?;

        tracing::info!(
            rules = filter_engine.rule_count(),
            credentials = credential_engine.credential_count(),
            auth = resolved_auth.is_some(),
            "Filter engine initialized"
        );

        Ok(Self {
            config,
            filter_engine,
            credential_engine,
            mitm_generator,
            resolved_auth,
            audit_logger: None,
            listener: None,
            upstream_port_override: None,
            upstream_host_override: None,
            upstream_tls_config: None,
        })
    }

    /// Create a server with an existing filter engine and MITM generator
    pub fn with_components(
        config: Config,
        filter_engine: Arc<FilterEngine>,
        credential_engine: Arc<CredentialEngine>,
        mitm_generator: Arc<MitmCertificateGenerator>,
    ) -> Self {
        Self {
            config,
            filter_engine,
            credential_engine,
            mitm_generator,
            resolved_auth: None,
            audit_logger: None,
            listener: None,
            upstream_port_override: None,
            upstream_host_override: None,
            upstream_tls_config: None,
        }
    }

    /// Override the upstream port for all forwarded connections (for testing).
    pub fn with_upstream_port_override(mut self, port: u16) -> Self {
        self.upstream_port_override = Some(port);
        self
    }

    /// Override the upstream host for TCP connections (for testing with non-resolvable hostnames).
    /// The original hostname is still used for TLS SNI.
    pub fn with_upstream_host_override(mut self, host: String) -> Self {
        self.upstream_host_override = Some(host);
        self
    }

    /// Set the audit logger for structured request logging.
    pub fn with_audit_logger(mut self, logger: Arc<AuditLogger>) -> Self {
        self.audit_logger = Some(logger);
        self
    }

    /// Inject a custom TLS config for upstream connections (for testing with self-signed certs).
    pub fn with_upstream_tls(mut self, config: Arc<ClientConfig>) -> Self {
        self.upstream_tls_config = Some(config);
        self
    }

    /// Run the proxy server with graceful shutdown
    pub async fn run_until_shutdown(
        mut self,
        shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<()> {
        let local_addr = self.bind().await?;
        tracing::info!(address = %local_addr, "Proxy server listening");
        self.serve(shutdown).await
    }

    /// Bind the server to its configured address and return the listen address.
    ///
    /// For TCP, this is useful when binding to port 0 to discover the assigned port.
    /// For Unix sockets, the path from the config is returned.
    /// Call `serve()` afterwards to start accepting connections.
    pub async fn bind(&mut self) -> Result<ListenAddress> {
        let bind_address = &self.config.proxy.bind_address;

        // If the bind address contains '/', treat it as a Unix socket path
        #[cfg(unix)]
        if bind_address.contains('/') {
            let path = PathBuf::from(bind_address);

            // Remove stale socket file if it exists
            if path.exists() {
                std::fs::remove_file(&path).map_err(|e| {
                    Error::proxy(format!(
                        "Failed to remove stale socket '{}': {}",
                        path.display(),
                        e
                    ))
                })?;
            }

            let listener = UnixListener::bind(&path).map_err(|e| {
                Error::proxy(format!("Failed to bind to {}: {}", path.display(), e))
            })?;

            self.listener = Some(BoundListener::Unix(listener));
            return Ok(ListenAddress::Unix(path));
        }

        // Otherwise parse as TCP address
        let addr: SocketAddr = bind_address.parse().map_err(|e| {
            Error::config(format!("Invalid bind address '{}': {}", bind_address, e))
        })?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::proxy(format!("Failed to bind to {}: {}", addr, e)))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| Error::proxy(format!("Failed to get local address: {}", e)))?;

        self.listener = Some(BoundListener::Tcp(listener));
        Ok(ListenAddress::Tcp(local_addr))
    }

    /// Serve connections using a previously bound listener, with graceful shutdown.
    ///
    /// Must call `bind()` first. Panics if no listener is stored.
    pub async fn serve(mut self, mut shutdown: tokio::sync::oneshot::Receiver<()>) -> Result<()> {
        let listener = self
            .listener
            .take()
            .expect("must call bind() before serve()");

        let tunnel_handler = Arc::new(self.make_tunnel_handler());

        match listener {
            BoundListener::Tcp(tcp_listener) => loop {
                tokio::select! {
                    _ = &mut shutdown => {
                        tracing::info!("Shutdown signal received");
                        return Ok(());
                    }
                    result = tcp_listener.accept() => {
                        let (stream, client_addr) = match result {
                            Ok(conn) => conn,
                            Err(e) => {
                                tracing::error!(error = %e, "Failed to accept connection");
                                continue;
                            }
                        };

                        tracing::debug!(client = %client_addr, "New connection");
                        self.spawn_connection(stream, client_addr.to_string(), &tunnel_handler);
                    }
                }
            },
            #[cfg(unix)]
            BoundListener::Unix(unix_listener) => loop {
                tokio::select! {
                    _ = &mut shutdown => {
                        tracing::info!("Shutdown signal received");
                        return Ok(());
                    }
                    result = unix_listener.accept() => {
                        let (stream, _addr) = match result {
                            Ok(conn) => conn,
                            Err(e) => {
                                tracing::error!(error = %e, "Failed to accept connection");
                                continue;
                            }
                        };

                        tracing::debug!(client = "unix", "New connection");
                        self.spawn_connection(stream, "unix".to_string(), &tunnel_handler);
                    }
                }
            },
        }
    }

    /// Spawn a task to handle a single connection.
    fn spawn_connection<S>(
        &self,
        stream: S,
        client_addr: String,
        tunnel_handler: &Arc<TunnelHandler>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let tunnel_handler = tunnel_handler.clone();
        let filter_engine = self.filter_engine.clone();
        let auth = self.resolved_auth.clone();
        let log_allowed = self.config.logging.log_allowed_requests;
        let log_blocked = self.config.logging.log_blocked_requests;
        let audit_logger = self.audit_logger.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            let service = service_fn(move |req| {
                let handler = ProxyHandler::new(tunnel_handler.clone(), filter_engine.clone())
                    .with_request_logging(log_allowed, log_blocked)
                    .with_auth(auth.clone())
                    .with_audit_logger(audit_logger.clone());
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

    fn make_tunnel_handler(&self) -> TunnelHandler {
        let mut handler = TunnelHandler::new(
            self.mitm_generator.clone(),
            self.filter_engine.clone(),
            self.credential_engine.clone(),
        )
        .with_request_logging(
            self.config.logging.log_allowed_requests,
            self.config.logging.log_blocked_requests,
        );
        if let Some(port) = self.upstream_port_override {
            handler = handler.with_upstream_port_override(port);
        }
        if let Some(ref host) = self.upstream_host_override {
            handler = handler.with_upstream_host_override(host.clone());
        }
        if let Some(ref config) = self.upstream_tls_config {
            handler = handler.with_upstream_tls(config.clone());
        }
        if let Some(ref logger) = self.audit_logger {
            handler = handler.with_audit_logger(logger.clone());
        }
        handler
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
