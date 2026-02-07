//! Configuration parsing and management

use serde::{Deserialize, Deserializer, Serialize};
use std::path::Path;

use crate::error::{Error, Result};

/// Main configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Proxy settings
    #[serde(default)]
    pub proxy: ProxyConfig,

    /// Logging settings
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Allowlist rules
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Proxy-specific configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    /// Address to bind the proxy server
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Path to CA certificate for MITM
    pub ca_cert: Option<String>,

    /// Path to CA private key for MITM
    pub ca_key: Option<String>,

    /// Override upstream port for all CONNECT forwards (testing only)
    #[serde(default)]
    pub upstream_override_port: Option<u16>,

    /// Path to PEM CA cert to trust for upstream TLS (testing only)
    #[serde(default)]
    pub upstream_tls_ca: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            ca_cert: None,
            ca_key: None,
            upstream_override_port: None,
            upstream_tls_ca: None,
        }
    }
}

fn default_bind_address() -> String {
    "127.0.0.1:8080".to_string()
}

/// Logging configuration
#[derive(Debug, Clone, Serialize)]
pub struct LoggingConfig {
    /// Log level (error, warn, info, debug, trace)
    pub level: String,

    /// Whether to log allowed requests
    pub log_allowed_requests: bool,

    /// Whether to log blocked requests
    pub log_blocked_requests: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            log_allowed_requests: true,
            log_blocked_requests: true,
        }
    }
}

/// Helper for deserializing `log_requests` as either a bool or a table.
#[derive(Deserialize)]
#[serde(untagged)]
enum LogRequestsValue {
    Bool(bool),
    Table {
        #[serde(default = "default_true")]
        allowed: bool,
        #[serde(default = "default_true")]
        blocked: bool,
    },
}

fn default_true() -> bool {
    true
}

/// Raw helper struct for deserializing LoggingConfig from TOML.
#[derive(Deserialize)]
struct LoggingConfigRaw {
    #[serde(default = "default_log_level")]
    level: String,
    #[serde(default)]
    log_requests: Option<LogRequestsValue>,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl<'de> Deserialize<'de> for LoggingConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = LoggingConfigRaw::deserialize(deserializer)?;
        let (log_allowed, log_blocked) = match raw.log_requests {
            None => (true, true),
            Some(LogRequestsValue::Bool(b)) => (b, b),
            Some(LogRequestsValue::Table { allowed, blocked }) => (allowed, blocked),
        };
        Ok(LoggingConfig {
            level: raw.level,
            log_allowed_requests: log_allowed,
            log_blocked_requests: log_blocked,
        })
    }
}

/// A single allowlist rule
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    /// HTTP method to match (or "*" for any)
    pub method: String,

    /// URL pattern to match (supports wildcards)
    pub url: String,

    /// Whether this rule applies to WebSocket connections
    #[serde(default)]
    pub websocket: bool,
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            Error::config(format!(
                "Failed to read config file '{}': {}",
                path.as_ref().display(),
                e
            ))
        })?;

        Self::parse(&content)
    }

    /// Parse configuration from a TOML string
    pub fn parse(content: &str) -> Result<Self> {
        toml::from_str(content).map_err(|e| Error::config(format!("Invalid TOML: {}", e)))
    }

    /// Create a minimal configuration with just the essentials
    pub fn minimal(bind_address: String, ca_cert: String, ca_key: String) -> Self {
        Self {
            proxy: ProxyConfig {
                bind_address,
                ca_cert: Some(ca_cert),
                ca_key: Some(ca_key),
                upstream_override_port: None,
                upstream_tls_ca: None,
            },
            logging: LoggingConfig::default(),
            rules: Vec::new(),
        }
    }

    /// Add a rule to the configuration
    pub fn add_rule(&mut self, method: impl Into<String>, url: impl Into<String>) {
        self.rules.push(Rule {
            method: method.into(),
            url: url.into(),
            websocket: false,
        });
    }

    /// Add a WebSocket rule to the configuration
    pub fn add_websocket_rule(&mut self, url: impl Into<String>) {
        self.rules.push(Rule {
            method: "GET".to_string(),
            url: url.into(),
            websocket: true,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
[proxy]
bind_address = "127.0.0.1:3128"
ca_cert = "/path/to/ca.crt"
ca_key = "/path/to/ca.key"
"#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.proxy.bind_address, "127.0.0.1:3128");
        assert_eq!(config.proxy.ca_cert, Some("/path/to/ca.crt".to_string()));
        assert_eq!(config.proxy.ca_key, Some("/path/to/ca.key".to_string()));
        assert!(config.rules.is_empty());
    }

    #[test]
    fn test_parse_config_with_rules() {
        let toml = r#"
[proxy]
bind_address = "127.0.0.1:8080"

[[rules]]
method = "GET"
url = "https://api.example.com/health"

[[rules]]
method = "POST"
url = "https://api.example.com/users/*/profile"

[[rules]]
method = "*"
url = "https://*.github.com/*"

[[rules]]
method = "GET"
url = "wss://realtime.example.com/socket"
websocket = true
"#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.rules.len(), 4);

        assert_eq!(config.rules[0].method, "GET");
        assert_eq!(config.rules[0].url, "https://api.example.com/health");
        assert!(!config.rules[0].websocket);

        assert_eq!(config.rules[1].method, "POST");
        assert_eq!(
            config.rules[1].url,
            "https://api.example.com/users/*/profile"
        );

        assert_eq!(config.rules[2].method, "*");
        assert_eq!(config.rules[2].url, "https://*.github.com/*");

        assert_eq!(config.rules[3].method, "GET");
        assert!(config.rules[3].websocket);
    }

    #[test]
    fn test_default_values() {
        let toml = "";
        let config = Config::parse(toml).unwrap();

        assert_eq!(config.proxy.bind_address, "127.0.0.1:8080");
        assert_eq!(config.logging.level, "info");
        assert!(config.logging.log_allowed_requests);
        assert!(config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_bool_false() {
        let toml = r#"
[logging]
level = "debug"
log_requests = false
"#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.logging.level, "debug");
        assert!(!config.logging.log_allowed_requests);
        assert!(!config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_bool_true() {
        let toml = r#"
[logging]
log_requests = true
"#;

        let config = Config::parse(toml).unwrap();
        assert!(config.logging.log_allowed_requests);
        assert!(config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_table_mixed() {
        let toml = r#"
[logging]
log_requests = { allowed = true, blocked = false }
"#;

        let config = Config::parse(toml).unwrap();
        assert!(config.logging.log_allowed_requests);
        assert!(!config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_table_partial_defaults() {
        let toml = r#"
[logging]
log_requests = { blocked = false }
"#;

        let config = Config::parse(toml).unwrap();
        assert!(config.logging.log_allowed_requests); // defaults to true
        assert!(!config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_omitted() {
        let toml = r#"
[logging]
level = "warn"
"#;

        let config = Config::parse(toml).unwrap();
        assert!(config.logging.log_allowed_requests);
        assert!(config.logging.log_blocked_requests);
    }

    #[test]
    fn test_upstream_override_fields() {
        let toml = r#"
[proxy]
bind_address = "127.0.0.1:0"
ca_cert = "/path/to/ca.crt"
ca_key = "/path/to/ca.key"
upstream_override_port = 9443
upstream_tls_ca = "/path/to/upstream-ca.crt"
"#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.proxy.upstream_override_port, Some(9443));
        assert_eq!(
            config.proxy.upstream_tls_ca,
            Some("/path/to/upstream-ca.crt".to_string())
        );
    }

    #[test]
    fn test_upstream_override_fields_default_to_none() {
        let toml = r#"
[proxy]
bind_address = "127.0.0.1:8080"
"#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.proxy.upstream_override_port, None);
        assert_eq!(config.proxy.upstream_tls_ca, None);
    }

    #[test]
    fn test_invalid_toml() {
        let toml = "this is not valid toml [[[";
        let result = Config::parse(toml);
        assert!(result.is_err());
    }
}
