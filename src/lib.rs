//! Redlimitador - A filtering HTTPS proxy for agent network access control
//!
//! This crate provides a filtering proxy that intercepts HTTPS traffic and applies
//! allowlist-based rules to control network access.
//!
//! # Features
//!
//! - **Allowlist-based filtering**: Default-deny with explicit allow rules
//! - **HTTPS interception**: TLS termination (MITM) for inspecting encrypted traffic
//! - **Flexible pattern matching**: Wildcards for methods, hosts, paths, and query strings
//! - **Certificate management**: User-provided or auto-generated CA certificates
//!
//! # Example
//!
//! ```no_run
//! use redlimitador::{Config, ProxyServer};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config::from_file("config.toml")?;
//!     let server = ProxyServer::new(config)?;
//!     server.run().await?;
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod error;
pub mod filter;
pub mod proxy;
pub mod tls;

pub use config::Config;
pub use error::{Error, Result};
pub use filter::{FilterEngine, RequestInfo};
pub use proxy::ProxyServer;
pub use tls::{CertificateAuthority, GeneratedCa, MitmCertificateGenerator};
