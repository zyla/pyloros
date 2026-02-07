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
    use crate::test_report;

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
        let t = test_report!("Empty engine blocks all requests");
        let engine = FilterEngine::empty();
        let request = RequestInfo::http("GET", "https", "example.com", None, "/", None);
        t.assert_true("GET / blocked", !engine.is_allowed(&request));
    }

    #[test]
    fn test_exact_match() {
        let t = test_report!("Exact URL match");
        let engine =
            FilterEngine::new(vec![make_rule("GET", "https://api.example.com/health")]).unwrap();

        let allowed = RequestInfo::http("GET", "https", "api.example.com", None, "/health", None);
        let wrong_method =
            RequestInfo::http("POST", "https", "api.example.com", None, "/health", None);
        let wrong_path = RequestInfo::http("GET", "https", "api.example.com", None, "/other", None);
        let wrong_host = RequestInfo::http("GET", "https", "other.com", None, "/health", None);

        t.assert_true("exact match allowed", engine.is_allowed(&allowed));
        t.assert_true("wrong method blocked", !engine.is_allowed(&wrong_method));
        t.assert_true("wrong path blocked", !engine.is_allowed(&wrong_path));
        t.assert_true("wrong host blocked", !engine.is_allowed(&wrong_host));
    }

    #[test]
    fn test_wildcard_method() {
        let t = test_report!("Wildcard method * matches all");
        let engine = FilterEngine::new(vec![make_rule("*", "https://cdn.example.com/*")]).unwrap();

        for method in ["GET", "POST", "DELETE"] {
            let req = RequestInfo::http(method, "https", "cdn.example.com", None, "/file", None);
            t.assert_true(&format!("{} allowed", method), engine.is_allowed(&req));
        }
    }

    #[test]
    fn test_wildcard_host() {
        let t = test_report!("Wildcard host *.github.com");
        let engine =
            FilterEngine::new(vec![make_rule("GET", "https://*.github.com/api/*")]).unwrap();

        let api = RequestInfo::http("GET", "https", "api.github.com", None, "/api/repos", None);
        let raw = RequestInfo::http("GET", "https", "raw.github.com", None, "/api/files", None);
        let bare = RequestInfo::http("GET", "https", "github.com", None, "/api/repos", None);

        t.assert_true("api.github.com allowed", engine.is_allowed(&api));
        t.assert_true("raw.github.com allowed", engine.is_allowed(&raw));
        t.assert_true("github.com blocked", !engine.is_allowed(&bare));
    }

    #[test]
    fn test_wildcard_path() {
        let t = test_report!("Wildcard path /users/*/comments");
        let engine = FilterEngine::new(vec![make_rule(
            "POST",
            "https://api.example.com/users/*/comments",
        )])
        .unwrap();

        let single = RequestInfo::http(
            "POST",
            "https",
            "api.example.com",
            None,
            "/users/123/comments",
            None,
        );
        let multi = RequestInfo::http(
            "POST",
            "https",
            "api.example.com",
            None,
            "/users/abc/def/comments",
            None,
        );
        let empty = RequestInfo::http(
            "POST",
            "https",
            "api.example.com",
            None,
            "/users/comments",
            None,
        );

        t.assert_true("single segment allowed", engine.is_allowed(&single));
        t.assert_true("multi segment allowed", engine.is_allowed(&multi));
        t.assert_true("no segment blocked", !engine.is_allowed(&empty));
    }

    #[test]
    fn test_query_matching() {
        let t = test_report!("Query string wildcard matching");
        let engine =
            FilterEngine::new(vec![make_rule("GET", "https://api.example.com/search?q=*")])
                .unwrap();

        let with_q = RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/search",
            Some("q=test"),
        );
        let no_q = RequestInfo::http("GET", "https", "api.example.com", None, "/search", None);
        let wrong_q = RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/search",
            Some("other=param"),
        );

        t.assert_true("q=test allowed", engine.is_allowed(&with_q));
        t.assert_true("no query blocked", !engine.is_allowed(&no_q));
        t.assert_true("wrong query blocked", !engine.is_allowed(&wrong_q));
    }

    #[test]
    fn test_multiple_rules() {
        let t = test_report!("Multiple rules OR matching");
        let engine = FilterEngine::new(vec![
            make_rule("GET", "https://api.example.com/public/*"),
            make_rule("POST", "https://api.example.com/data"),
            make_rule("*", "https://cdn.example.com/*"),
        ])
        .unwrap();

        let public = RequestInfo::http(
            "GET",
            "https",
            "api.example.com",
            None,
            "/public/info",
            None,
        );
        let data = RequestInfo::http("POST", "https", "api.example.com", None, "/data", None);
        let cdn = RequestInfo::http("PUT", "https", "cdn.example.com", None, "/file", None);
        let blocked = RequestInfo::http("DELETE", "https", "api.example.com", None, "/data", None);

        t.assert_true("GET /public/* allowed", engine.is_allowed(&public));
        t.assert_true("POST /data allowed", engine.is_allowed(&data));
        t.assert_true("PUT cdn/* allowed", engine.is_allowed(&cdn));
        t.assert_true("DELETE /data blocked", !engine.is_allowed(&blocked));
    }

    #[test]
    fn test_websocket_rules() {
        let t = test_report!("WebSocket vs HTTP rule isolation");
        let engine = FilterEngine::new(vec![
            make_rule("GET", "https://api.example.com/http"),
            make_ws_rule("wss://api.example.com/socket"),
        ])
        .unwrap();

        let http_req = RequestInfo::http("GET", "https", "api.example.com", None, "/http", None);
        let ws_req = RequestInfo::websocket("https", "api.example.com", None, "/socket", None);
        let ws_on_http = RequestInfo::websocket("https", "api.example.com", None, "/http", None);
        let http_on_ws =
            RequestInfo::http("GET", "https", "api.example.com", None, "/socket", None);

        t.assert_true("HTTP matches HTTP rule", engine.is_allowed(&http_req));
        t.assert_true("WS matches WS rule", engine.is_allowed(&ws_req));
        t.assert_true(
            "WS does NOT match HTTP rule",
            !engine.is_allowed(&ws_on_http),
        );
        t.assert_true(
            "HTTP does NOT match WS rule",
            !engine.is_allowed(&http_on_ws),
        );
    }

    #[test]
    fn test_port_matching() {
        let t = test_report!("Port matching in rules");
        let engine =
            FilterEngine::new(vec![make_rule("GET", "https://api.example.com:8443/api")]).unwrap();

        let correct =
            RequestInfo::http("GET", "https", "api.example.com", Some(8443), "/api", None);
        let wrong = RequestInfo::http("GET", "https", "api.example.com", Some(443), "/api", None);
        let none = RequestInfo::http("GET", "https", "api.example.com", None, "/api", None);

        t.assert_true("port 8443 allowed", engine.is_allowed(&correct));
        t.assert_true("port 443 blocked", !engine.is_allowed(&wrong));
        t.assert_true("no port blocked", !engine.is_allowed(&none));
    }

    #[test]
    fn test_case_insensitive_method() {
        let t = test_report!("Case-insensitive method matching");
        let engine =
            FilterEngine::new(vec![make_rule("get", "https://api.example.com/test")]).unwrap();

        let req = RequestInfo::http("GET", "https", "api.example.com", None, "/test", None);
        t.assert_true("GET matches 'get'", engine.is_allowed(&req));
    }

    #[test]
    fn test_request_info_full_url() {
        let t = test_report!("RequestInfo::full_url() formatting");

        let r1 = RequestInfo::http("GET", "https", "example.com", None, "/path", None);
        t.assert_eq(
            "basic",
            &r1.full_url().as_str(),
            &"https://example.com/path",
        );

        let r2 = RequestInfo::http(
            "GET",
            "https",
            "example.com",
            Some(8443),
            "/path",
            Some("q=1"),
        );
        t.assert_eq(
            "with port+query",
            &r2.full_url().as_str(),
            &"https://example.com:8443/path?q=1",
        );

        let r3 = RequestInfo::http("GET", "https", "example.com", Some(443), "/path", None);
        t.assert_eq(
            "default port omitted",
            &r3.full_url().as_str(),
            &"https://example.com/path",
        );
    }

    #[test]
    fn test_rule_count() {
        let t = test_report!("FilterEngine::rule_count()");
        let engine = FilterEngine::new(vec![
            make_rule("GET", "https://a.com/"),
            make_rule("GET", "https://b.com/"),
        ])
        .unwrap();

        t.assert_eq("rule count", &engine.rule_count(), &2usize);
    }

    #[test]
    fn test_complex_github_pattern() {
        let t = test_report!("Complex GitHub-like wildcard patterns");
        let engine = FilterEngine::new(vec![
            make_rule("*", "https://*.github.com/*"),
            make_rule("*", "https://*.githubusercontent.com/*"),
        ])
        .unwrap();

        let api = RequestInfo::http(
            "GET",
            "https",
            "api.github.com",
            None,
            "/repos/owner/repo",
            None,
        );
        let graphql = RequestInfo::http("POST", "https", "api.github.com", None, "/graphql", None);
        let raw = RequestInfo::http(
            "GET",
            "https",
            "raw.githubusercontent.com",
            None,
            "/owner/repo/main/file.txt",
            None,
        );

        t.assert_true("api.github.com GET", engine.is_allowed(&api));
        t.assert_true("api.github.com POST", engine.is_allowed(&graphql));
        t.assert_true("raw.githubusercontent.com", engine.is_allowed(&raw));
    }
}
