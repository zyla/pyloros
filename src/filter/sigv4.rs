//! AWS Signature Version 4 signing implementation.

/// Parsed fields from an existing AWS Authorization header.
pub struct AwsAuthParsed {
    pub region: String,
    pub service: String,
}

/// Parse an existing Authorization header to extract region/service from the credential scope.
///
/// Expected format:
/// `AWS4-HMAC-SHA256 Credential=AKID/20250101/us-east-1/sts/aws4_request, ...`
pub fn parse_authorization(auth_header: &str) -> Option<AwsAuthParsed> {
    let auth = auth_header.trim();
    if !auth.starts_with("AWS4-HMAC-SHA256") {
        return None;
    }

    // Find Credential= field
    let cred_start = auth.find("Credential=")?;
    let after_cred = &auth[cred_start + "Credential=".len()..];
    let cred_end = after_cred.find([',', ' ']).unwrap_or(after_cred.len());
    let credential_value = &after_cred[..cred_end];

    // credential_value = "AKID/20250101/us-east-1/sts/aws4_request"
    let parts: Vec<&str> = credential_value.split('/').collect();
    if parts.len() < 5 {
        return None;
    }

    Some(AwsAuthParsed {
        region: parts[2].to_string(),
        service: parts[3].to_string(),
    })
}

/// Sign a request using AWS SigV4, returning headers to set.
///
/// Returns: `[(header_name, header_value), ...]` for Authorization, X-Amz-Date,
/// X-Amz-Content-Sha256, and optionally X-Amz-Security-Token.
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    _access_key_id: &str,
    _secret_access_key: &str,
    _session_token: Option<&str>,
    _method: &str,
    _canonical_uri: &str,
    _query: &str,
    _headers: &[(String, String)],
    _body: &[u8],
    _region: &str,
    _service: &str,
) -> Vec<(String, String)> {
    // Stub — Phase 3 will implement this
    Vec::new()
}
