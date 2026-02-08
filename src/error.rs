//! Error types for pyloros

use std::io;

/// Main error type for the proxy
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Proxy error: {0}")]
    Proxy(String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Pattern error: {0}")]
    Pattern(String),

    #[error("HTTP error: {0}")]
    Http(#[from] hyper::Error),

    #[error("Request blocked: {method} {url}")]
    Blocked { method: String, url: String },
}

impl Error {
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }

    pub fn tls(msg: impl Into<String>) -> Self {
        Error::Tls(msg.into())
    }

    pub fn certificate(msg: impl Into<String>) -> Self {
        Error::Certificate(msg.into())
    }

    pub fn proxy(msg: impl Into<String>) -> Self {
        Error::Proxy(msg.into())
    }

    pub fn invalid_url(msg: impl Into<String>) -> Self {
        Error::InvalidUrl(msg.into())
    }

    pub fn pattern(msg: impl Into<String>) -> Self {
        Error::Pattern(msg.into())
    }

    pub fn blocked(method: impl Into<String>, url: impl Into<String>) -> Self {
        Error::Blocked {
            method: method.into(),
            url: url.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
