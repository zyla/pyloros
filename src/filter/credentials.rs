//! Credential injection engine

use hyper::header::HeaderMap;

use super::matcher::UrlPattern;
use crate::config::{resolve_credential_value, Credential};
use crate::error::Result;
use crate::filter::RequestInfo;

/// A resolved credential ready for matching and injection.
pub struct ResolvedCredential {
    url_pattern: UrlPattern,
    header: String,
    value: String,
}

/// Engine that matches requests and injects credentials into headers.
pub struct CredentialEngine {
    credentials: Vec<ResolvedCredential>,
}

impl CredentialEngine {
    /// Create a new credential engine, resolving env vars and compiling URL patterns.
    pub fn new(credentials: Vec<Credential>) -> Result<Self> {
        let mut resolved = Vec::with_capacity(credentials.len());
        for cred in &credentials {
            let value = resolve_credential_value(&cred.value)?;
            let url_pattern = UrlPattern::new(&cred.url)?;
            resolved.push(ResolvedCredential {
                url_pattern,
                header: cred.header.to_lowercase(),
                value,
            });
        }
        Ok(Self {
            credentials: resolved,
        })
    }

    /// Inject matching credentials into the request headers.
    ///
    /// For each credential whose URL pattern matches the request, the header
    /// is inserted or overwritten. If multiple credentials set the same header,
    /// the last match wins (config file order).
    pub fn inject(&self, request_info: &RequestInfo, headers: &mut HeaderMap) {
        for cred in &self.credentials {
            if cred.url_pattern.matches(
                request_info.scheme,
                request_info.host,
                request_info.port,
                request_info.path,
                request_info.query,
            ) {
                tracing::debug!(header = %cred.header, "Injecting credential");
                if let Ok(name) = hyper::header::HeaderName::from_bytes(cred.header.as_bytes()) {
                    if let Ok(val) = hyper::header::HeaderValue::from_str(&cred.value) {
                        headers.insert(name, val);
                    }
                }
            }
        }
    }

    /// Number of configured credentials.
    pub fn credential_count(&self) -> usize {
        self.credentials.len()
    }

    /// URL patterns for display (e.g. in validate-config output).
    pub fn url_patterns(&self) -> Vec<&str> {
        self.credentials
            .iter()
            .map(|c| c.url_pattern.scheme.pattern())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_report;

    fn make_credential(url: &str, header: &str, value: &str) -> Credential {
        Credential {
            url: url.to_string(),
            header: header.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn test_url_pattern_matching() {
        let t = test_report!("Credential matches request with wildcard URL");
        let engine = CredentialEngine::new(vec![make_credential(
            "https://api.example.com/*",
            "x-api-key",
            "secret123",
        )])
        .unwrap();

        let ri = RequestInfo::http("GET", "https", "api.example.com", None, "/v1/data", None);
        let mut headers = HeaderMap::new();
        engine.inject(&ri, &mut headers);
        t.assert_eq(
            "header injected",
            &headers.get("x-api-key").unwrap().to_str().unwrap(),
            &"secret123",
        );
    }

    #[test]
    fn test_header_overwrite() {
        let t = test_report!("Credential overwrites existing header");
        let engine = CredentialEngine::new(vec![make_credential(
            "https://api.example.com/*",
            "x-api-key",
            "real-secret",
        )])
        .unwrap();

        let ri = RequestInfo::http("GET", "https", "api.example.com", None, "/test", None);
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "dummy-value".parse().unwrap());
        engine.inject(&ri, &mut headers);
        t.assert_eq(
            "overwritten",
            &headers.get("x-api-key").unwrap().to_str().unwrap(),
            &"real-secret",
        );
    }

    #[test]
    fn test_multiple_credentials_different_headers() {
        let t = test_report!("Multiple credentials for different headers both injected");
        let engine = CredentialEngine::new(vec![
            make_credential("https://api.example.com/*", "x-api-key", "key123"),
            make_credential("https://api.example.com/*", "authorization", "Bearer tok"),
        ])
        .unwrap();

        let ri = RequestInfo::http("POST", "https", "api.example.com", None, "/data", None);
        let mut headers = HeaderMap::new();
        engine.inject(&ri, &mut headers);
        t.assert_eq(
            "x-api-key",
            &headers.get("x-api-key").unwrap().to_str().unwrap(),
            &"key123",
        );
        t.assert_eq(
            "authorization",
            &headers.get("authorization").unwrap().to_str().unwrap(),
            &"Bearer tok",
        );
    }

    #[test]
    fn test_last_match_wins() {
        let t = test_report!("Last match wins for same header");
        let engine = CredentialEngine::new(vec![
            make_credential("https://*.example.com/*", "x-api-key", "first"),
            make_credential("https://api.example.com/*", "x-api-key", "second"),
        ])
        .unwrap();

        let ri = RequestInfo::http("GET", "https", "api.example.com", None, "/test", None);
        let mut headers = HeaderMap::new();
        engine.inject(&ri, &mut headers);
        t.assert_eq(
            "last wins",
            &headers.get("x-api-key").unwrap().to_str().unwrap(),
            &"second",
        );
    }

    #[test]
    fn test_no_match() {
        let t = test_report!("No match leaves headers unchanged");
        let engine = CredentialEngine::new(vec![make_credential(
            "https://other.example.com/*",
            "x-api-key",
            "secret",
        )])
        .unwrap();

        let ri = RequestInfo::http("GET", "https", "api.example.com", None, "/test", None);
        let mut headers = HeaderMap::new();
        engine.inject(&ri, &mut headers);
        t.assert_true("no header added", headers.get("x-api-key").is_none());
    }

    #[test]
    fn test_credential_count() {
        let t = test_report!("credential_count returns correct count");
        let engine = CredentialEngine::new(vec![
            make_credential("https://a.com/*", "x-key", "a"),
            make_credential("https://b.com/*", "x-key", "b"),
        ])
        .unwrap();
        t.assert_eq("count", &engine.credential_count(), &2usize);
    }
}
