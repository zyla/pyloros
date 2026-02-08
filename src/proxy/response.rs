//! Shared HTTP response helpers for blocked/error responses

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{Response, StatusCode};

/// Create an HTTP 451 response for blocked requests
pub fn blocked_response(method: &str, url: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = format!(
        "Request blocked by proxy policy\n\nMethod: {}\nURL: {}\n",
        method, url
    );

    Response::builder()
        .status(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS) // 451
        .header("Content-Type", "text/plain")
        .header("X-Blocked-By", "redlimitador")
        .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
        .unwrap()
}

/// Create an HTTP 502 Bad Gateway error response
pub fn error_response(message: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = format!("Proxy error: {}\n", message);

    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_response() {
        let resp = blocked_response("GET", "https://example.com/blocked");
        assert_eq!(resp.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    }

    #[test]
    fn test_error_response() {
        let resp = error_response("test error");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
