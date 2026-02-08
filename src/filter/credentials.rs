//! Credential injection engine

use hyper::header::HeaderMap;

use super::matcher::UrlPattern;
use crate::config::{resolve_credential_value, Credential};
use crate::error::Result;
use crate::filter::RequestInfo;

/// A resolved credential ready for matching and injection.
pub enum ResolvedCredential {
    Header {
        url_pattern: UrlPattern,
        header: String,
        value: String,
    },
    AwsSigV4 {
        url_pattern: UrlPattern,
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    },
}

impl ResolvedCredential {
    fn url_pattern(&self) -> &UrlPattern {
        match self {
            ResolvedCredential::Header { url_pattern, .. } => url_pattern,
            ResolvedCredential::AwsSigV4 { url_pattern, .. } => url_pattern,
        }
    }

    fn matches(&self, ri: &RequestInfo) -> bool {
        self.url_pattern()
            .matches(ri.scheme, ri.host, ri.port, ri.path, ri.query)
    }
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
            match cred {
                Credential::Header { url, header, value } => {
                    let value = resolve_credential_value(value)?;
                    let url_pattern = UrlPattern::new(url)?;
                    resolved.push(ResolvedCredential::Header {
                        url_pattern,
                        header: header.to_lowercase(),
                        value,
                    });
                }
                Credential::AwsSigV4 {
                    url,
                    access_key_id,
                    secret_access_key,
                    session_token,
                } => {
                    let access_key_id = resolve_credential_value(access_key_id)?;
                    let secret_access_key = resolve_credential_value(secret_access_key)?;
                    let session_token = session_token
                        .as_deref()
                        .map(resolve_credential_value)
                        .transpose()?;
                    let url_pattern = UrlPattern::new(url)?;
                    resolved.push(ResolvedCredential::AwsSigV4 {
                        url_pattern,
                        access_key_id,
                        secret_access_key,
                        session_token,
                    });
                }
            }
        }
        Ok(Self {
            credentials: resolved,
        })
    }

    /// Inject matching header credentials into the request headers.
    ///
    /// Only injects Header-type credentials. SigV4 credentials require body access
    /// and must use `inject_with_body()` instead.
    pub fn inject(&self, request_info: &RequestInfo, headers: &mut HeaderMap) {
        for cred in &self.credentials {
            if let ResolvedCredential::Header { header, value, .. } = cred {
                if cred.matches(request_info) {
                    tracing::debug!(header = %header, "Injecting credential");
                    if let Ok(name) = hyper::header::HeaderName::from_bytes(header.as_bytes()) {
                        if let Ok(val) = hyper::header::HeaderValue::from_str(value) {
                            headers.insert(name, val);
                        }
                    }
                }
            }
        }
    }

    /// Returns true if any matching credential needs body access (SigV4).
    pub fn needs_body(&self, request_info: &RequestInfo) -> bool {
        self.credentials.iter().any(|cred| {
            matches!(cred, ResolvedCredential::AwsSigV4 { .. }) && cred.matches(request_info)
        })
    }

    /// Inject all matching credentials including body-aware ones (SigV4).
    ///
    /// - For Header creds: sets/overwrites the header
    /// - For AwsSigV4 creds: parses existing Authorization for region/service,
    ///   strips old AWS headers, computes SigV4, sets new headers
    pub fn inject_with_body(
        &self,
        request_info: &RequestInfo,
        headers: &mut HeaderMap,
        body: &[u8],
    ) {
        for cred in &self.credentials {
            if !cred.matches(request_info) {
                continue;
            }
            match cred {
                ResolvedCredential::Header { header, value, .. } => {
                    tracing::debug!(header = %header, "Injecting credential");
                    if let Ok(name) = hyper::header::HeaderName::from_bytes(header.as_bytes()) {
                        if let Ok(val) = hyper::header::HeaderValue::from_str(value) {
                            headers.insert(name, val);
                        }
                    }
                }
                ResolvedCredential::AwsSigV4 {
                    access_key_id,
                    secret_access_key,
                    session_token,
                    ..
                } => {
                    // Parse existing Authorization header for region/service
                    let auth_header = headers
                        .get(hyper::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");

                    let parsed = match super::sigv4::parse_authorization(auth_header) {
                        Some(p) => p,
                        None => {
                            tracing::debug!(
                                "No parseable AWS Authorization header, skipping SigV4"
                            );
                            continue;
                        }
                    };

                    tracing::debug!(
                        region = %parsed.region,
                        service = %parsed.service,
                        "Re-signing request with AWS SigV4"
                    );

                    // Strip old AWS headers
                    headers.remove(hyper::header::AUTHORIZATION);
                    headers.remove("x-amz-date");
                    headers.remove("x-amz-content-sha256");
                    headers.remove("x-amz-security-token");

                    // Collect headers for signing (lowercase name, trimmed value)
                    let mut sign_headers: Vec<(String, String)> = headers
                        .iter()
                        .map(|(name, value)| {
                            (
                                name.as_str().to_lowercase(),
                                value.to_str().unwrap_or("").trim().to_string(),
                            )
                        })
                        .collect();
                    sign_headers.sort_by(|a, b| a.0.cmp(&b.0));

                    // Build canonical URI and query
                    let canonical_uri = request_info.path;
                    let query = request_info.query.unwrap_or("");

                    let new_headers = super::sigv4::sign_request(
                        access_key_id,
                        secret_access_key,
                        session_token.as_deref(),
                        request_info.method,
                        canonical_uri,
                        query,
                        &sign_headers,
                        body,
                        &parsed.region,
                        &parsed.service,
                    );

                    for (name, value) in new_headers {
                        if let Ok(header_name) =
                            hyper::header::HeaderName::from_bytes(name.as_bytes())
                        {
                            if let Ok(header_value) = hyper::header::HeaderValue::from_str(&value) {
                                headers.insert(header_name, header_value);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Number of configured credentials.
    pub fn credential_count(&self) -> usize {
        self.credentials.len()
    }

    /// Credential descriptions for display (e.g. in validate-config output).
    pub fn credential_descriptions(&self) -> Vec<String> {
        self.credentials
            .iter()
            .map(|c| match c {
                ResolvedCredential::Header {
                    url_pattern,
                    header,
                    ..
                } => {
                    format!("header={} url={}", header, url_pattern.scheme.pattern())
                }
                ResolvedCredential::AwsSigV4 { url_pattern, .. } => {
                    format!("aws-sigv4 url={}", url_pattern.scheme.pattern())
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_report;

    fn make_credential(url: &str, header: &str, value: &str) -> Credential {
        Credential::Header {
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
