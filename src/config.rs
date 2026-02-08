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
    /// HTTP method to match (or "*" for any). Required for HTTP rules, absent for git rules.
    #[serde(default)]
    pub method: Option<String>,

    /// URL pattern to match (supports wildcards)
    pub url: String,

    /// Whether this rule applies to WebSocket connections
    #[serde(default)]
    pub websocket: bool,

    /// Git operation: "fetch", "push", or "*". Mutually exclusive with `method`.
    #[serde(default)]
    pub git: Option<String>,

    /// Branch patterns for git push restriction. Only valid with git = "push" or git = "*".
    #[serde(default)]
    pub branches: Option<Vec<String>>,
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
        let config: Self =
            toml::from_str(content).map_err(|e| Error::config(format!("Invalid TOML: {}", e)))?;

        // Validate each rule
        for (i, rule) in config.rules.iter().enumerate() {
            Self::validate_rule(i, rule)?;
        }

        Ok(config)
    }

    /// Validate a single rule for consistency
    fn validate_rule(index: usize, rule: &Rule) -> Result<()> {
        let ctx = |msg: &str| Error::config(format!("Rule #{}: {}", index + 1, msg));

        match (&rule.method, &rule.git) {
            (Some(_), Some(_)) => {
                return Err(ctx(
                    "cannot have both `method` and `git` — use one or the other",
                ));
            }
            (None, None) => {
                return Err(ctx("must have either `method` or `git`"));
            }
            _ => {}
        }

        if rule.websocket && rule.git.is_some() {
            return Err(ctx("`websocket` and `git` are mutually exclusive"));
        }

        if let Some(ref git) = rule.git {
            match git.as_str() {
                "fetch" | "push" | "*" => {}
                other => {
                    return Err(ctx(&format!(
                        "invalid `git` value {:?} — must be \"fetch\", \"push\", or \"*\"",
                        other
                    )));
                }
            }

            if rule.branches.is_some() && git == "fetch" {
                return Err(ctx(
                    "`branches` is only valid with `git = \"push\"` or `git = \"*\"`",
                ));
            }
        }

        if rule.branches.is_some() && rule.git.is_none() {
            return Err(ctx("`branches` is only valid on git rules"));
        }

        Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_report;

    #[test]
    fn test_parse_minimal_config() {
        let t = test_report!("Parse minimal config");
        let toml = r#"
[proxy]
bind_address = "127.0.0.1:3128"
ca_cert = "/path/to/ca.crt"
ca_key = "/path/to/ca.key"
"#;

        let config = Config::parse(toml).unwrap();
        t.assert_eq(
            "bind_address",
            &config.proxy.bind_address.as_str(),
            &"127.0.0.1:3128",
        );
        t.assert_eq(
            "ca_cert",
            &config.proxy.ca_cert,
            &Some("/path/to/ca.crt".to_string()),
        );
        t.assert_eq(
            "ca_key",
            &config.proxy.ca_key,
            &Some("/path/to/ca.key".to_string()),
        );
        t.assert_true("no rules", config.rules.is_empty());
    }

    #[test]
    fn test_parse_config_with_rules() {
        let t = test_report!("Parse config with rules");
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
        t.assert_eq("rule count", &config.rules.len(), &4usize);
        t.assert_eq(
            "rule[0] method",
            &config.rules[0].method.as_deref(),
            &Some("GET"),
        );
        t.assert_eq(
            "rule[0] url",
            &config.rules[0].url.as_str(),
            &"https://api.example.com/health",
        );
        t.assert_true("rule[0] not websocket", !config.rules[0].websocket);
        t.assert_eq(
            "rule[1] method",
            &config.rules[1].method.as_deref(),
            &Some("POST"),
        );
        t.assert_eq(
            "rule[2] method",
            &config.rules[2].method.as_deref(),
            &Some("*"),
        );
        t.assert_true("rule[3] websocket", config.rules[3].websocket);
    }

    #[test]
    fn test_default_values() {
        let t = test_report!("Default config values");
        let config = Config::parse("").unwrap();

        t.assert_eq(
            "bind_address",
            &config.proxy.bind_address.as_str(),
            &"127.0.0.1:8080",
        );
        t.assert_eq("log level", &config.logging.level.as_str(), &"info");
        t.assert_true("log allowed default", config.logging.log_allowed_requests);
        t.assert_true("log blocked default", config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_bool_false() {
        let t = test_report!("log_requests = false disables both");
        let toml = r#"
[logging]
level = "debug"
log_requests = false
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq("level", &config.logging.level.as_str(), &"debug");
        t.assert_true("allowed disabled", !config.logging.log_allowed_requests);
        t.assert_true("blocked disabled", !config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_bool_true() {
        let t = test_report!("log_requests = true enables both");
        let toml = r#"
[logging]
log_requests = true
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_true("allowed enabled", config.logging.log_allowed_requests);
        t.assert_true("blocked enabled", config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_table_mixed() {
        let t = test_report!("log_requests table with mixed values");
        let toml = r#"
[logging]
log_requests = { allowed = true, blocked = false }
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_true("allowed enabled", config.logging.log_allowed_requests);
        t.assert_true("blocked disabled", !config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_table_partial_defaults() {
        let t = test_report!("log_requests table with partial keys defaults missing");
        let toml = r#"
[logging]
log_requests = { blocked = false }
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_true(
            "allowed defaults to true",
            config.logging.log_allowed_requests,
        );
        t.assert_true("blocked set to false", !config.logging.log_blocked_requests);
    }

    #[test]
    fn test_logging_config_omitted() {
        let t = test_report!("Omitted log_requests defaults to both true");
        let toml = r#"
[logging]
level = "warn"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_true("allowed enabled", config.logging.log_allowed_requests);
        t.assert_true("blocked enabled", config.logging.log_blocked_requests);
    }

    #[test]
    fn test_upstream_override_fields() {
        let t = test_report!("Upstream override config fields");
        let toml = r#"
[proxy]
bind_address = "127.0.0.1:0"
ca_cert = "/path/to/ca.crt"
ca_key = "/path/to/ca.key"
upstream_override_port = 9443
upstream_tls_ca = "/path/to/upstream-ca.crt"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq(
            "override port",
            &config.proxy.upstream_override_port,
            &Some(9443),
        );
        t.assert_eq(
            "upstream TLS CA",
            &config.proxy.upstream_tls_ca,
            &Some("/path/to/upstream-ca.crt".to_string()),
        );
    }

    #[test]
    fn test_upstream_override_fields_default_to_none() {
        let t = test_report!("Upstream overrides default to None");
        let toml = r#"
[proxy]
bind_address = "127.0.0.1:8080"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq(
            "override port None",
            &config.proxy.upstream_override_port,
            &None,
        );
        t.assert_eq(
            "upstream TLS CA None",
            &config.proxy.upstream_tls_ca,
            &None::<String>,
        );
    }

    #[test]
    fn test_invalid_toml() {
        let t = test_report!("Invalid TOML rejected");
        let result = Config::parse("this is not valid toml [[[");
        t.assert_true("parse error", result.is_err());
    }

    #[test]
    fn test_git_rule_fetch() {
        let t = test_report!("Git fetch rule parses correctly");
        let toml = r#"
[[rules]]
git = "fetch"
url = "https://github.com/myorg/*"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq("rule count", &config.rules.len(), &1usize);
        t.assert_eq("git", &config.rules[0].git.as_deref(), &Some("fetch"));
        t.assert_true("method is None", config.rules[0].method.is_none());
        t.assert_true("branches is None", config.rules[0].branches.is_none());
    }

    #[test]
    fn test_git_rule_push_with_branches() {
        let t = test_report!("Git push rule with branches parses correctly");
        let toml = r#"
[[rules]]
git = "push"
url = "https://github.com/myorg/repo"
branches = ["feature/*", "fix/*"]
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq("rule count", &config.rules.len(), &1usize);
        t.assert_eq("git", &config.rules[0].git.as_deref(), &Some("push"));
        let branches = config.rules[0].branches.as_ref().unwrap();
        t.assert_eq("branch count", &branches.len(), &2usize);
        t.assert_eq("branch[0]", &branches[0].as_str(), &"feature/*");
        t.assert_eq("branch[1]", &branches[1].as_str(), &"fix/*");
    }

    #[test]
    fn test_git_rule_star() {
        let t = test_report!("Git * rule parses correctly");
        let toml = r#"
[[rules]]
git = "*"
url = "https://github.com/*"
"#;
        let config = Config::parse(toml).unwrap();
        t.assert_eq("git", &config.rules[0].git.as_deref(), &Some("*"));
    }

    #[test]
    fn test_git_rule_validation_both_method_and_git() {
        let t = test_report!("Reject rule with both method and git");
        let toml = r#"
[[rules]]
method = "GET"
git = "fetch"
url = "https://example.com/*"
"#;
        let result = Config::parse(toml);
        t.assert_true("parse error", result.is_err());
        let err = result.unwrap_err().to_string();
        t.assert_contains("error mentions both", &err, "both");
    }

    #[test]
    fn test_git_rule_validation_neither_method_nor_git() {
        let t = test_report!("Reject rule with neither method nor git");
        let toml = r#"
[[rules]]
url = "https://example.com/*"
"#;
        let result = Config::parse(toml);
        t.assert_true("parse error", result.is_err());
        let err = result.unwrap_err().to_string();
        t.assert_contains("error mentions either", &err, "either");
    }

    #[test]
    fn test_git_rule_validation_websocket_with_git() {
        let t = test_report!("Reject rule with websocket and git");
        let toml = r#"
[[rules]]
git = "fetch"
url = "https://example.com/*"
websocket = true
"#;
        let result = Config::parse(toml);
        t.assert_true("parse error", result.is_err());
        let err = result.unwrap_err().to_string();
        t.assert_contains(
            "error mentions mutually exclusive",
            &err,
            "mutually exclusive",
        );
    }

    #[test]
    fn test_git_rule_validation_invalid_git_value() {
        let t = test_report!("Reject invalid git operation value");
        let toml = r#"
[[rules]]
git = "clone"
url = "https://example.com/*"
"#;
        let result = Config::parse(toml);
        t.assert_true("parse error", result.is_err());
        let err = result.unwrap_err().to_string();
        t.assert_contains("error mentions invalid", &err, "invalid");
    }

    #[test]
    fn test_git_rule_validation_branches_with_fetch() {
        let t = test_report!("Reject branches on fetch-only rule");
        let toml = r#"
[[rules]]
git = "fetch"
url = "https://example.com/*"
branches = ["main"]
"#;
        let result = Config::parse(toml);
        t.assert_true("parse error", result.is_err());
        let err = result.unwrap_err().to_string();
        t.assert_contains("error mentions branches", &err, "branches");
    }

    #[test]
    fn test_git_rule_validation_branches_on_http_rule() {
        let t = test_report!("Reject branches on HTTP rule");
        let toml = r#"
[[rules]]
method = "POST"
url = "https://example.com/*"
branches = ["main"]
"#;
        let result = Config::parse(toml);
        t.assert_true("parse error", result.is_err());
        let err = result.unwrap_err().to_string();
        t.assert_contains("error mentions git rules", &err, "git rules");
    }
}
