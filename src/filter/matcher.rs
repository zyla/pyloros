//! Pattern matching for URL components

use crate::error::{Error, Result};

/// A compiled pattern that can match strings with wildcards
#[derive(Debug, Clone)]
pub struct PatternMatcher {
    /// The original pattern string
    pattern: String,
    /// Compiled segments for matching
    segments: Vec<Segment>,
}

#[derive(Debug, Clone)]
enum Segment {
    /// Literal text that must match exactly
    Literal(String),
    /// Wildcard (*) that matches any sequence of characters
    Wildcard,
}

impl PatternMatcher {
    /// Compile a pattern string into a matcher
    ///
    /// Patterns support:
    /// - `*` matches any sequence of characters (including empty)
    /// - All other characters are literal matches
    pub fn new(pattern: &str) -> Result<Self> {
        let segments = Self::compile(pattern)?;
        Ok(Self {
            pattern: pattern.to_string(),
            segments,
        })
    }

    fn compile(pattern: &str) -> Result<Vec<Segment>> {
        let mut segments = Vec::new();
        let mut current_literal = String::new();

        for ch in pattern.chars() {
            if ch == '*' {
                // Push any accumulated literal
                if !current_literal.is_empty() {
                    segments.push(Segment::Literal(std::mem::take(&mut current_literal)));
                }
                // Add wildcard (collapse consecutive wildcards)
                if !matches!(segments.last(), Some(Segment::Wildcard)) {
                    segments.push(Segment::Wildcard);
                }
            } else {
                current_literal.push(ch);
            }
        }

        // Push final literal if any
        if !current_literal.is_empty() {
            segments.push(Segment::Literal(current_literal));
        }

        Ok(segments)
    }

    /// Check if the pattern matches the given text
    pub fn matches(&self, text: &str) -> bool {
        self.match_segments(&self.segments, text)
    }

    fn match_segments(&self, segments: &[Segment], text: &str) -> bool {
        match segments.first() {
            None => text.is_empty(),
            Some(Segment::Literal(lit)) => {
                if let Some(rest) = text.strip_prefix(lit.as_str()) {
                    self.match_segments(&segments[1..], rest)
                } else {
                    false
                }
            }
            Some(Segment::Wildcard) => {
                // Wildcard matches any sequence
                // Try matching the rest of the pattern at every position
                if segments.len() == 1 {
                    // Trailing wildcard matches everything
                    true
                } else {
                    // Try matching rest of pattern at each position
                    for i in 0..=text.len() {
                        if self.match_segments(&segments[1..], &text[i..]) {
                            return true;
                        }
                    }
                    false
                }
            }
        }
    }

    /// Get the original pattern string
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Check if this pattern is a simple literal (no wildcards)
    pub fn is_literal(&self) -> bool {
        self.segments.len() == 1 && matches!(self.segments.first(), Some(Segment::Literal(_)))
    }
}

/// A URL pattern that matches scheme, host, path, and query
#[derive(Debug, Clone)]
pub struct UrlPattern {
    pub scheme: PatternMatcher,
    pub host: PatternMatcher,
    pub port: Option<u16>,
    pub path: PatternMatcher,
    pub query: Option<PatternMatcher>,
}

impl UrlPattern {
    /// Parse a URL pattern string
    ///
    /// Format: `scheme://host[:port]/path[?query]`
    /// Example: `https://*.example.com/api/*/data?q=*`
    pub fn new(pattern: &str) -> Result<Self> {
        // Parse scheme
        let (scheme_str, rest) = pattern
            .split_once("://")
            .ok_or_else(|| Error::pattern("URL pattern must include scheme (e.g., https://)"))?;

        // Handle WebSocket schemes
        let scheme_str = match scheme_str {
            "wss" => "https",
            "ws" => "http",
            other => other,
        };

        // Split host/port from path
        let (host_port, path_query) = if let Some(slash_idx) = rest.find('/') {
            (&rest[..slash_idx], &rest[slash_idx..])
        } else {
            (rest, "/")
        };

        // Parse host and port
        let (host_str, port) = if let Some(colon_idx) = host_port.rfind(':') {
            // Check if this is actually a port (not part of IPv6)
            let potential_port = &host_port[colon_idx + 1..];
            if let Ok(p) = potential_port.parse::<u16>() {
                (&host_port[..colon_idx], Some(p))
            } else {
                (host_port, None)
            }
        } else {
            (host_port, None)
        };

        // Split path and query
        let (path_str, query_str) = if let Some(q_idx) = path_query.find('?') {
            (&path_query[..q_idx], Some(&path_query[q_idx + 1..]))
        } else {
            (path_query, None)
        };

        Ok(Self {
            scheme: PatternMatcher::new(scheme_str)?,
            host: PatternMatcher::new(host_str)?,
            port,
            path: PatternMatcher::new(path_str)?,
            query: query_str.map(PatternMatcher::new).transpose()?,
        })
    }

    /// Check if this pattern matches the given URL components
    pub fn matches(
        &self,
        scheme: &str,
        host: &str,
        port: Option<u16>,
        path: &str,
        query: Option<&str>,
    ) -> bool {
        // Match scheme
        if !self.scheme.matches(scheme) {
            return false;
        }

        // Match host
        if !self.host.matches(host) {
            return false;
        }

        // Match port (if specified in pattern)
        if let Some(pattern_port) = self.port {
            match port {
                Some(p) if p == pattern_port => {}
                None => {
                    // Use default port for scheme
                    let default_port = match scheme {
                        "https" => 443,
                        "http" => 80,
                        _ => return false,
                    };
                    if default_port != pattern_port {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        // Match path
        if !self.path.matches(path) {
            return false;
        }

        // Match query (if pattern specifies one)
        if let Some(ref query_pattern) = self.query {
            match query {
                Some(q) => {
                    if !query_pattern.matches(q) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod pattern_matcher {
        use super::*;

        #[test]
        fn test_literal_match() {
            let m = PatternMatcher::new("hello").unwrap();
            assert!(m.matches("hello"));
            assert!(!m.matches("hello!"));
            assert!(!m.matches("hell"));
            assert!(!m.matches(""));
        }

        #[test]
        fn test_wildcard_only() {
            let m = PatternMatcher::new("*").unwrap();
            assert!(m.matches(""));
            assert!(m.matches("anything"));
            assert!(m.matches("anything/with/slashes"));
        }

        #[test]
        fn test_prefix_wildcard() {
            let m = PatternMatcher::new("*suffix").unwrap();
            assert!(m.matches("suffix"));
            assert!(m.matches("prefixsuffix"));
            assert!(m.matches("any/thing/suffix"));
            assert!(!m.matches("suffixnot"));
        }

        #[test]
        fn test_suffix_wildcard() {
            let m = PatternMatcher::new("prefix*").unwrap();
            assert!(m.matches("prefix"));
            assert!(m.matches("prefixsuffix"));
            assert!(m.matches("prefix/any/thing"));
            assert!(!m.matches("notprefix"));
        }

        #[test]
        fn test_middle_wildcard() {
            let m = PatternMatcher::new("start*end").unwrap();
            assert!(m.matches("startend"));
            assert!(m.matches("startmiddleend"));
            assert!(m.matches("start/middle/end"));
            assert!(!m.matches("startendnot"));
            assert!(!m.matches("notstartend"));
        }

        #[test]
        fn test_multiple_wildcards() {
            let m = PatternMatcher::new("a*b*c").unwrap();
            assert!(m.matches("abc"));
            assert!(m.matches("a_b_c"));
            assert!(m.matches("aXXXbYYYc"));
            assert!(!m.matches("ab"));
            assert!(!m.matches("bc"));
        }

        #[test]
        fn test_consecutive_wildcards_collapse() {
            let m = PatternMatcher::new("a**b").unwrap();
            // Should behave same as "a*b"
            assert!(m.matches("ab"));
            assert!(m.matches("aXb"));
        }

        #[test]
        fn test_path_segments() {
            let m = PatternMatcher::new("/api/*/data").unwrap();
            assert!(m.matches("/api/v1/data"));
            assert!(m.matches("/api/v1/v2/data"));
            assert!(m.matches("/api//data")); // Empty segment
            assert!(!m.matches("/api/data"));
            assert!(!m.matches("/api/v1/datax"));
        }

        #[test]
        fn test_host_patterns() {
            let m = PatternMatcher::new("*.example.com").unwrap();
            assert!(m.matches("api.example.com"));
            assert!(m.matches("a.b.example.com"));
            assert!(m.matches(".example.com")); // Edge case
            assert!(!m.matches("example.com"));
            assert!(!m.matches("notexample.com"));
        }

        #[test]
        fn test_is_literal() {
            assert!(PatternMatcher::new("literal").unwrap().is_literal());
            assert!(!PatternMatcher::new("wild*card").unwrap().is_literal());
            assert!(!PatternMatcher::new("*").unwrap().is_literal());
        }
    }

    mod url_pattern {
        use super::*;

        #[test]
        fn test_simple_url() {
            let p = UrlPattern::new("https://example.com/api/health").unwrap();
            assert!(p.matches("https", "example.com", None, "/api/health", None));
            assert!(!p.matches("http", "example.com", None, "/api/health", None));
            assert!(!p.matches("https", "other.com", None, "/api/health", None));
            assert!(!p.matches("https", "example.com", None, "/api/other", None));
        }

        #[test]
        fn test_wildcard_host() {
            let p = UrlPattern::new("https://*.example.com/api/*").unwrap();
            assert!(p.matches("https", "api.example.com", None, "/api/anything", None));
            assert!(p.matches("https", "sub.api.example.com", None, "/api/v1/data", None));
            assert!(!p.matches("https", "example.com", None, "/api/test", None));
        }

        #[test]
        fn test_with_port() {
            let p = UrlPattern::new("https://example.com:8443/api").unwrap();
            assert!(p.matches("https", "example.com", Some(8443), "/api", None));
            assert!(!p.matches("https", "example.com", Some(443), "/api", None));
            assert!(!p.matches("https", "example.com", None, "/api", None));
        }

        #[test]
        fn test_default_port() {
            let p = UrlPattern::new("https://example.com:443/api").unwrap();
            // None port should match default 443 for https
            assert!(p.matches("https", "example.com", None, "/api", None));
            assert!(p.matches("https", "example.com", Some(443), "/api", None));
        }

        #[test]
        fn test_with_query() {
            let p = UrlPattern::new("https://api.com/search?q=*&limit=*").unwrap();
            assert!(p.matches("https", "api.com", None, "/search", Some("q=test&limit=10")));
            assert!(p.matches(
                "https",
                "api.com",
                None,
                "/search",
                Some("q=anything&limit=100")
            ));
            assert!(!p.matches("https", "api.com", None, "/search", None));
            assert!(!p.matches("https", "api.com", None, "/search", Some("q=test")));
        }

        #[test]
        fn test_websocket_scheme() {
            let p = UrlPattern::new("wss://realtime.example.com/socket").unwrap();
            // wss is converted to https internally
            assert!(p.matches("https", "realtime.example.com", None, "/socket", None));
        }

        #[test]
        fn test_complex_path() {
            let p = UrlPattern::new("https://api.github.com/repos/*/commits/*").unwrap();
            assert!(p.matches(
                "https",
                "api.github.com",
                None,
                "/repos/user/repo/commits/abc123",
                None
            ));
            assert!(p.matches(
                "https",
                "api.github.com",
                None,
                "/repos/org/project/commits/main",
                None
            ));
        }

        #[test]
        fn test_any_method_any_path() {
            let p = UrlPattern::new("https://cdn.example.com/*").unwrap();
            assert!(p.matches("https", "cdn.example.com", None, "/", None));
            assert!(p.matches("https", "cdn.example.com", None, "/any/path/here.js", None));
        }

        #[test]
        fn test_root_path() {
            let p = UrlPattern::new("https://example.com/").unwrap();
            assert!(p.matches("https", "example.com", None, "/", None));
            assert!(!p.matches("https", "example.com", None, "/other", None));
        }

        #[test]
        fn test_no_path() {
            // URL without explicit path should default to /
            let p = UrlPattern::new("https://example.com").unwrap();
            assert!(p.matches("https", "example.com", None, "/", None));
        }

        #[test]
        fn test_invalid_pattern() {
            assert!(UrlPattern::new("not-a-url").is_err());
            assert!(UrlPattern::new("example.com/path").is_err());
        }
    }
}
