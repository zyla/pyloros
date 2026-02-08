//! Rule compilation and filter engine

use super::matcher::{PatternMatcher, UrlPattern};
use crate::config::Rule;
use crate::error::Result;

/// Information about a request to be filtered
#[derive(Debug, Clone)]
pub struct RequestInfo<'a> {
    pub method: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: Option<u16>,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub is_websocket: bool,
}

impl<'a> RequestInfo<'a> {
    /// Create a new RequestInfo for an HTTP request
    pub fn http(
        method: &'a str,
        scheme: &'a str,
        host: &'a str,
        port: Option<u16>,
        path: &'a str,
        query: Option<&'a str>,
    ) -> Self {
        Self {
            method,
            scheme,
            host,
            port,
            path,
            query,
            is_websocket: false,
        }
    }

    /// Create a new RequestInfo for a WebSocket upgrade
    pub fn websocket(
        scheme: &'a str,
        host: &'a str,
        port: Option<u16>,
        path: &'a str,
        query: Option<&'a str>,
    ) -> Self {
        Self {
            method: "GET",
            scheme,
            host,
            port,
            path,
            query,
            is_websocket: true,
        }
    }

    /// Get the full URL for logging
    pub fn full_url(&self) -> String {
        let port_str = match (self.scheme, self.port) {
            ("https", Some(443)) | ("https", None) => String::new(),
            ("http", Some(80)) | ("http", None) => String::new(),
            (_, Some(p)) => format!(":{}", p),
            (_, None) => String::new(),
        };

        match self.query {
            Some(q) => format!(
                "{}://{}{}{}?{}",
                self.scheme, self.host, port_str, self.path, q
            ),
            None => format!("{}://{}{}{}", self.scheme, self.host, port_str, self.path),
        }
    }
}

/// A compiled rule ready for efficient matching
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Method matcher (or None for "*" which matches any method)
    method: Option<PatternMatcher>,
    /// URL pattern matcher
    url: UrlPattern,
    /// Whether this rule is for WebSocket connections
    websocket: bool,
}

impl CompiledRule {
    /// Compile a rule from configuration
    pub fn compile(rule: &Rule) -> Result<Self> {
        let method = if rule.method == "*" {
            None
        } else {
            Some(PatternMatcher::new(&rule.method.to_uppercase())?)
        };

        let url = UrlPattern::new(&rule.url)?;

        Ok(Self {
            method,
            url,
            websocket: rule.websocket,
        })
    }

    /// Check if this rule matches the given request
    pub fn matches(&self, request: &RequestInfo) -> bool {
        // Check WebSocket flag
        if self.websocket != request.is_websocket {
            return false;
        }

        // Check method
        if let Some(ref method_matcher) = self.method {
            if !method_matcher.matches(request.method) {
                return false;
            }
        }

        // Check URL
        self.url.matches(
            request.scheme,
            request.host,
            request.port,
            request.path,
            request.query,
        )
    }
}

/// The filter engine that evaluates requests against rules
#[derive(Debug, Clone)]
pub struct FilterEngine {
    /// Compiled rules
    rules: Vec<CompiledRule>,
}

impl FilterEngine {
    /// Create a new filter engine with the given rules
    pub fn new(rules: Vec<Rule>) -> Result<Self> {
        let compiled: Result<Vec<_>> = rules.iter().map(CompiledRule::compile).collect();
        Ok(Self { rules: compiled? })
    }

    /// Create an empty filter engine (blocks everything)
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Check if a request is allowed
    ///
    /// Returns true if the request matches at least one rule
    pub fn is_allowed(&self, request: &RequestInfo) -> bool {
        self.rules.iter().any(|rule| rule.matches(request))
    }

    /// Get the number of rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for FilterEngine {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(method: &str, url: &str) -> Rule {
        Rule {
            method: method.to_string(),
            url: url.to_string(),
            websocket: false,
        }
    }

    fn make_ws_rule(url: &str) -> Rule {
        Rule {
            method: "GET".to_string(),
            url: url.to_string(),
            websocket: true,
        }
    }

    #[test]
    fn test_empty_engine_blocks_all() {
        let engine = FilterEngine::empty();
        let request = RequestInfo::http("GET", "https", "example.com", None, "/", None);
        assert!(!engine.is_allowed(&request));
    }

    #[test]
    fn test_exact_match() {
        let engine =
            FilterEngine::new(vec![make_rule("GET", "https://api.example.com/health")]).unwrap();

        let allowed = RequestInfo::http("GET", "https", "api.example.com", None, "/health", None);
        let wrong_method =
            RequestInfo::http("POST", "https", "api.example.com", None, "/health", None);
        let wrong_path = RequestInfo::http("GET", "https", "api.example.com", None, "/other", None);
        let wrong_host = RequestInfo::http("GET", "https", "other.com", None, "/health", None);

        assert!(engine.is_allowed(&allowed));
        assert!(!engine.is_allowed(&wrong_method));
        assert!(!engine.is_allowed(&wrong_path));
        assert!(!engine.is_allowed(&wrong_host));
    }

    #[test]
    fn test_wildcard_method() {
        let engine = FilterEngine::new(vec![make_rule("*", "https://cdn.example.com/*")]).unwrap();

        assert!(engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "cdn.example.com",
            None,
            "/file.js",
            None
        )));
        assert!(engine.is_allowed(&RequestInfo::http(
            "POST",
            "https",
            "cdn.example.com",
            None,
            "/upload",
            None
        )));
        assert!(engine.is_allowed(&RequestInfo::http(
            "DELETE",
            "https",
            "cdn.example.com",
            None,
            "/file",
            None
        )));
    }

    #[test]
    fn test_wildcard_host() {
        let engine =
            FilterEngine::new(vec![make_rule("GET", "https://*.github.com/api/*")]).unwrap();

        assert!(engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "api.github.com",
            None,
            "/api/repos",
            None
        )));
        assert!(engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "raw.github.com",
            None,
            "/api/files",
            None
        )));
        assert!(!engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "github.com",
            None,
            "/api/repos",
            None
        )));
    }

    #[test]
    fn test_wildcard_path() {
        let engine = FilterEngine::new(vec![make_rule(
            "POST",
            "https://api.example.com/users/*/comments",
        )])
        .unwrap();

        assert!(engine.is_allowed(&RequestInfo::http(
            "POST",
            "https",
            "api.example.com",
            None,
            "/users/123/comments",
            None
        )));
        assert!(engine.is_allowed(&RequestInfo::http(
            "POST",
            "https",
            "api.example.com",
            None,
            "/users/abc/def/comments",
            None
        )));
        assert!(!engine.is_allowed(&RequestInfo::http(
            "POST",
            "https",
            "api.example.com",
            None,
            "/users/comments",
            None
        )));
    }

    #[test]
    fn test_query_matching() {
        let engine =
            FilterEngine::new(vec![make_rule("GET", "https://api.example.com/search?q=*")])
                .unwrap();

        assert!(engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/search",
            Some("q=test")
        )));
        assert!(engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/search",
            Some("q=anything")
        )));
        assert!(!engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/search",
            None
        )));
        assert!(!engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/search",
            Some("other=param")
        )));
    }

    #[test]
    fn test_multiple_rules() {
        let engine = FilterEngine::new(vec![
            make_rule("GET", "https://api.example.com/public/*"),
            make_rule("POST", "https://api.example.com/data"),
            make_rule("*", "https://cdn.example.com/*"),
        ])
        .unwrap();

        assert!(engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/public/info",
            None
        )));
        assert!(engine.is_allowed(&RequestInfo::http(
            "POST",
            "https",
            "api.example.com",
            None,
            "/data",
            None
        )));
        assert!(engine.is_allowed(&RequestInfo::http(
            "PUT",
            "https",
            "cdn.example.com",
            None,
            "/file",
            None
        )));
        assert!(!engine.is_allowed(&RequestInfo::http(
            "DELETE",
            "https",
            "api.example.com",
            None,
            "/data",
            None
        )));
    }

    #[test]
    fn test_websocket_rules() {
        let engine = FilterEngine::new(vec![
            make_rule("GET", "https://api.example.com/http"),
            make_ws_rule("wss://api.example.com/socket"),
        ])
        .unwrap();

        // HTTP request should match HTTP rule
        assert!(engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/http",
            None
        )));

        // WebSocket should match WebSocket rule
        assert!(engine.is_allowed(&RequestInfo::websocket(
            "https",
            "api.example.com",
            None,
            "/socket",
            None
        )));

        // WebSocket should NOT match HTTP rule
        assert!(!engine.is_allowed(&RequestInfo::websocket(
            "https",
            "api.example.com",
            None,
            "/http",
            None
        )));

        // HTTP should NOT match WebSocket rule
        assert!(!engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/socket",
            None
        )));
    }

    #[test]
    fn test_port_matching() {
        let engine =
            FilterEngine::new(vec![make_rule("GET", "https://api.example.com:8443/api")]).unwrap();

        assert!(engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            Some(8443),
            "/api",
            None
        )));
        assert!(!engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            Some(443),
            "/api",
            None
        )));
        assert!(!engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/api",
            None
        )));
    }

    #[test]
    fn test_case_insensitive_method() {
        let engine =
            FilterEngine::new(vec![make_rule("get", "https://api.example.com/test")]).unwrap();

        assert!(engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/test",
            None
        )));
    }

    #[test]
    fn test_request_info_full_url() {
        let r1 = RequestInfo::http("GET", "https", "example.com", None, "/path", None);
        assert_eq!(r1.full_url(), "https://example.com/path");

        let r2 = RequestInfo::http(
            "GET",
            "https",
            "example.com",
            Some(8443),
            "/path",
            Some("q=1"),
        );
        assert_eq!(r2.full_url(), "https://example.com:8443/path?q=1");

        let r3 = RequestInfo::http("GET", "https", "example.com", Some(443), "/path", None);
        assert_eq!(r3.full_url(), "https://example.com/path");
    }

    #[test]
    fn test_rule_count() {
        let engine = FilterEngine::new(vec![
            make_rule("GET", "https://a.com/"),
            make_rule("GET", "https://b.com/"),
        ])
        .unwrap();

        assert_eq!(engine.rule_count(), 2);
    }

    #[test]
    fn test_complex_github_pattern() {
        let engine = FilterEngine::new(vec![
            make_rule("*", "https://*.github.com/*"),
            make_rule("*", "https://*.githubusercontent.com/*"),
        ])
        .unwrap();

        assert!(engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "api.github.com",
            None,
            "/repos/owner/repo",
            None
        )));
        assert!(engine.is_allowed(&RequestInfo::http(
            "POST",
            "https",
            "api.github.com",
            None,
            "/graphql",
            None
        )));
        assert!(engine.is_allowed(&RequestInfo::http(
            "GET",
            "https",
            "raw.githubusercontent.com",
            None,
            "/owner/repo/main/file.txt",
            None
        )));
    }
}
