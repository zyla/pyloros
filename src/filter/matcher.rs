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
                    // Try matching rest of pattern at each char boundary.
                    // char_indices yields (byte_offset, char) for each character;
                    // we also need to try the position past the last character.
                    let mut last_end = 0;
                    for (i, _) in text.char_indices() {
                        if self.match_segments(&segments[1..], &text[i..]) {
                            return true;
                        }
                        last_end = i;
                    }
                    // Try the position after the last char (i.e., empty remainder)
                    if !text.is_empty() {
                        last_end += text[last_end..].chars().next().unwrap().len_utf8();
                    }
                    self.match_segments(&segments[1..], &text[last_end..])
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
        use pyloros_test_support::test_report;

        #[test]
        fn test_literal_match() {
            let t = test_report!("Literal string matching");
            let m = PatternMatcher::new("hello").unwrap();
            t.assert_true("exact match", m.matches("hello"));
            t.assert_true("extra char rejected", !m.matches("hello!"));
            t.assert_true("prefix rejected", !m.matches("hell"));
            t.assert_true("empty rejected", !m.matches(""));
        }

        #[test]
        fn test_wildcard_only() {
            let t = test_report!("Single wildcard matches everything");
            let m = PatternMatcher::new("*").unwrap();
            t.assert_true("empty string", m.matches(""));
            t.assert_true("any text", m.matches("anything"));
            t.assert_true("with slashes", m.matches("anything/with/slashes"));
        }

        #[test]
        fn test_prefix_wildcard() {
            let t = test_report!("Prefix wildcard *suffix");
            let m = PatternMatcher::new("*suffix").unwrap();
            t.assert_true("exact suffix", m.matches("suffix"));
            t.assert_true("with prefix", m.matches("prefixsuffix"));
            t.assert_true("with slashes", m.matches("any/thing/suffix"));
            t.assert_true("trailing chars rejected", !m.matches("suffixnot"));
        }

        #[test]
        fn test_suffix_wildcard() {
            let t = test_report!("Suffix wildcard prefix*");
            let m = PatternMatcher::new("prefix*").unwrap();
            t.assert_true("exact prefix", m.matches("prefix"));
            t.assert_true("with suffix", m.matches("prefixsuffix"));
            t.assert_true("with slashes", m.matches("prefix/any/thing"));
            t.assert_true("wrong prefix rejected", !m.matches("notprefix"));
        }

        #[test]
        fn test_middle_wildcard() {
            let t = test_report!("Middle wildcard start*end");
            let m = PatternMatcher::new("start*end").unwrap();
            t.assert_true("no middle", m.matches("startend"));
            t.assert_true("with middle", m.matches("startmiddleend"));
            t.assert_true("with slashes", m.matches("start/middle/end"));
            t.assert_true("trailing chars rejected", !m.matches("startendnot"));
            t.assert_true("wrong prefix rejected", !m.matches("notstartend"));
        }

        #[test]
        fn test_multiple_wildcards() {
            let t = test_report!("Multiple wildcards a*b*c");
            let m = PatternMatcher::new("a*b*c").unwrap();
            t.assert_true("minimal", m.matches("abc"));
            t.assert_true("underscores", m.matches("a_b_c"));
            t.assert_true("long segments", m.matches("aXXXbYYYc"));
            t.assert_true("missing c rejected", !m.matches("ab"));
            t.assert_true("missing a rejected", !m.matches("bc"));
        }

        #[test]
        fn test_consecutive_wildcards_collapse() {
            let t = test_report!("Consecutive ** collapses to *");
            let m = PatternMatcher::new("a**b").unwrap();
            t.assert_true("no middle", m.matches("ab"));
            t.assert_true("with middle", m.matches("aXb"));
        }

        #[test]
        fn test_path_segments() {
            let t = test_report!("Wildcard spans path segments");
            let m = PatternMatcher::new("/api/*/data").unwrap();
            t.assert_true("single segment", m.matches("/api/v1/data"));
            t.assert_true("multi segment", m.matches("/api/v1/v2/data"));
            t.assert_true("empty segment", m.matches("/api//data"));
            t.assert_true("no middle rejected", !m.matches("/api/data"));
            t.assert_true("extra suffix rejected", !m.matches("/api/v1/datax"));
        }

        #[test]
        fn test_host_patterns() {
            let t = test_report!("Host wildcard *.example.com");
            let m = PatternMatcher::new("*.example.com").unwrap();
            t.assert_true("api subdomain", m.matches("api.example.com"));
            t.assert_true("deep subdomain", m.matches("a.b.example.com"));
            t.assert_true("dot prefix edge case", m.matches(".example.com"));
            t.assert_true("bare domain rejected", !m.matches("example.com"));
            t.assert_true("different domain rejected", !m.matches("notexample.com"));
        }

        #[test]
        fn test_wildcard_multibyte_utf8() {
            let t = test_report!("Wildcard matches with multi-byte UTF-8 characters");
            let m = PatternMatcher::new("*end").unwrap();
            t.assert_true("café_end matches", m.matches("café_end"));
            t.assert_true("日本語end matches", m.matches("日本語end"));
            t.assert_true("emoji 🎉end matches", m.matches("🎉end"));

            let m2 = PatternMatcher::new("start*end").unwrap();
            t.assert_true("start_café_end matches", m2.matches("start_café_end"));
            t.assert_true(
                "start🎉middle🎉end matches",
                m2.matches("start🎉middle🎉end"),
            );
            t.assert_true("multi-byte no match", !m2.matches("start_café_enx"));

            // Non-matching pattern where the last char is multi-byte —
            // exercises the post-loop position advancement past a multi-byte char
            let m3 = PatternMatcher::new("*z").unwrap();
            t.assert_true("no match ending in multibyte", !m3.matches("aé"));
        }

        #[test]
        fn test_is_literal() {
            let t = test_report!("is_literal detection");
            t.assert_true(
                "literal",
                PatternMatcher::new("literal").unwrap().is_literal(),
            );
            t.assert_true(
                "wildcard not literal",
                !PatternMatcher::new("wild*card").unwrap().is_literal(),
            );
            t.assert_true(
                "star not literal",
                !PatternMatcher::new("*").unwrap().is_literal(),
            );
        }
    }

    mod url_pattern {
        use super::*;
        use pyloros_test_support::test_report;

        #[test]
        fn test_simple_url() {
            let t = test_report!("Simple URL pattern matching");
            let p = UrlPattern::new("https://example.com/api/health").unwrap();
            t.assert_true(
                "exact match",
                p.matches("https", "example.com", None, "/api/health", None),
            );
            t.assert_true(
                "wrong scheme",
                !p.matches("http", "example.com", None, "/api/health", None),
            );
            t.assert_true(
                "wrong host",
                !p.matches("https", "other.com", None, "/api/health", None),
            );
            t.assert_true(
                "wrong path",
                !p.matches("https", "example.com", None, "/api/other", None),
            );
        }

        #[test]
        fn test_wildcard_host() {
            let t = test_report!("URL pattern with wildcard host");
            let p = UrlPattern::new("https://*.example.com/api/*").unwrap();
            t.assert_true(
                "subdomain match",
                p.matches("https", "api.example.com", None, "/api/anything", None),
            );
            t.assert_true(
                "deep subdomain",
                p.matches("https", "sub.api.example.com", None, "/api/v1/data", None),
            );
            t.assert_true(
                "bare domain rejected",
                !p.matches("https", "example.com", None, "/api/test", None),
            );
        }

        #[test]
        fn test_with_port() {
            let t = test_report!("URL pattern with explicit port");
            let p = UrlPattern::new("https://example.com:8443/api").unwrap();
            t.assert_true(
                "correct port",
                p.matches("https", "example.com", Some(8443), "/api", None),
            );
            t.assert_true(
                "wrong port",
                !p.matches("https", "example.com", Some(443), "/api", None),
            );
            t.assert_true(
                "no port",
                !p.matches("https", "example.com", None, "/api", None),
            );
        }

        #[test]
        fn test_default_port() {
            let t = test_report!("URL pattern with default port 443");
            let p = UrlPattern::new("https://example.com:443/api").unwrap();
            t.assert_true(
                "None matches default 443",
                p.matches("https", "example.com", None, "/api", None),
            );
            t.assert_true(
                "explicit 443",
                p.matches("https", "example.com", Some(443), "/api", None),
            );
        }

        #[test]
        fn test_default_port_http() {
            let t = test_report!("URL pattern with default port 80 for HTTP");
            let p = UrlPattern::new("http://example.com:80/api").unwrap();
            t.assert_true(
                "None matches default 80",
                p.matches("http", "example.com", None, "/api", None),
            );
            t.assert_true(
                "explicit 80",
                p.matches("http", "example.com", Some(80), "/api", None),
            );
            t.assert_true(
                "wrong scheme rejected",
                !p.matches("https", "example.com", None, "/api", None),
            );
        }

        #[test]
        fn test_with_query() {
            let t = test_report!("URL pattern with query wildcards");
            let p = UrlPattern::new("https://api.com/search?q=*&limit=*").unwrap();
            t.assert_true(
                "matching query",
                p.matches("https", "api.com", None, "/search", Some("q=test&limit=10")),
            );
            t.assert_true(
                "different values",
                p.matches(
                    "https",
                    "api.com",
                    None,
                    "/search",
                    Some("q=anything&limit=100"),
                ),
            );
            t.assert_true(
                "no query rejected",
                !p.matches("https", "api.com", None, "/search", None),
            );
            t.assert_true(
                "partial query rejected",
                !p.matches("https", "api.com", None, "/search", Some("q=test")),
            );
        }

        #[test]
        fn test_websocket_scheme() {
            let t = test_report!("wss:// converted to https:// internally");
            let p = UrlPattern::new("wss://realtime.example.com/socket").unwrap();
            t.assert_true(
                "wss matches https",
                p.matches("https", "realtime.example.com", None, "/socket", None),
            );
        }

        #[test]
        fn test_complex_path() {
            let t = test_report!("Complex path with multiple wildcards");
            let p = UrlPattern::new("https://api.github.com/repos/*/commits/*").unwrap();
            t.assert_true(
                "user/repo path",
                p.matches(
                    "https",
                    "api.github.com",
                    None,
                    "/repos/user/repo/commits/abc123",
                    None,
                ),
            );
            t.assert_true(
                "org/project path",
                p.matches(
                    "https",
                    "api.github.com",
                    None,
                    "/repos/org/project/commits/main",
                    None,
                ),
            );
        }

        #[test]
        fn test_any_method_any_path() {
            let t = test_report!("Wildcard path matches everything under host");
            let p = UrlPattern::new("https://cdn.example.com/*").unwrap();
            t.assert_true(
                "root",
                p.matches("https", "cdn.example.com", None, "/", None),
            );
            t.assert_true(
                "deep path",
                p.matches("https", "cdn.example.com", None, "/any/path/here.js", None),
            );
        }

        #[test]
        fn test_root_path() {
            let t = test_report!("Root path / matching");
            let p = UrlPattern::new("https://example.com/").unwrap();
            t.assert_true(
                "root matches",
                p.matches("https", "example.com", None, "/", None),
            );
            t.assert_true(
                "other path rejected",
                !p.matches("https", "example.com", None, "/other", None),
            );
        }

        #[test]
        fn test_no_path() {
            let t = test_report!("URL without path defaults to /");
            let p = UrlPattern::new("https://example.com").unwrap();
            t.assert_true(
                "root matches",
                p.matches("https", "example.com", None, "/", None),
            );
        }

        #[test]
        fn test_invalid_pattern() {
            let t = test_report!("Invalid URL patterns rejected");
            t.assert_true("not-a-url", UrlPattern::new("not-a-url").is_err());
            t.assert_true("no scheme", UrlPattern::new("example.com/path").is_err());
        }
    }
}
