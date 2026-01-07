//! Integration tests for the filter engine

use redlimitador::config::Rule;
use redlimitador::filter::{FilterEngine, RequestInfo};

fn rule(method: &str, url: &str) -> Rule {
    Rule {
        method: method.to_string(),
        url: url.to_string(),
        websocket: false,
    }
}

fn ws_rule(url: &str) -> Rule {
    Rule {
        method: "GET".to_string(),
        url: url.to_string(),
        websocket: true,
    }
}

#[test]
fn test_empty_ruleset_blocks_everything() {
    let engine = FilterEngine::empty();

    let requests = vec![
        RequestInfo::http("GET", "https", "example.com", None, "/", None),
        RequestInfo::http("POST", "https", "api.example.com", None, "/data", None),
        RequestInfo::http("DELETE", "http", "localhost", Some(8080), "/resource", None),
    ];

    for req in requests {
        assert!(
            !engine.is_allowed(&req),
            "Request {} {} should be blocked by empty ruleset",
            req.method,
            req.full_url()
        );
    }
}

#[test]
fn test_exact_url_matching() {
    let engine = FilterEngine::new(vec![
        rule("GET", "https://api.example.com/health"),
    ])
    .unwrap();

    // Exact match - allowed
    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/health",
        None
    )));

    // Wrong method - blocked
    assert!(!engine.is_allowed(&RequestInfo::http(
        "POST",
        "https",
        "api.example.com",
        None,
        "/health",
        None
    )));

    // Wrong path - blocked
    assert!(!engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/other",
        None
    )));

    // Wrong host - blocked
    assert!(!engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "other.com",
        None,
        "/health",
        None
    )));

    // Wrong scheme - blocked
    assert!(!engine.is_allowed(&RequestInfo::http(
        "GET",
        "http",
        "api.example.com",
        None,
        "/health",
        None
    )));
}

#[test]
fn test_wildcard_method() {
    let engine = FilterEngine::new(vec![
        rule("*", "https://cdn.example.com/*"),
    ])
    .unwrap();

    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

    for method in methods {
        assert!(
            engine.is_allowed(&RequestInfo::http(
                method,
                "https",
                "cdn.example.com",
                None,
                "/file.js",
                None
            )),
            "{} should be allowed with wildcard method",
            method
        );
    }
}

#[test]
fn test_wildcard_host() {
    let engine = FilterEngine::new(vec![
        rule("GET", "https://*.github.com/*"),
    ])
    .unwrap();

    // Subdomains - allowed
    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.github.com",
        None,
        "/repos",
        None
    )));

    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "raw.github.com",
        None,
        "/file",
        None
    )));

    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "a.b.c.github.com",
        None,
        "/deep",
        None
    )));

    // No subdomain - blocked (pattern requires something before .github.com)
    assert!(!engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "github.com",
        None,
        "/repos",
        None
    )));
}

#[test]
fn test_wildcard_path() {
    let engine = FilterEngine::new(vec![
        rule("GET", "https://api.example.com/users/*/profile"),
    ])
    .unwrap();

    // Single segment wildcard
    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/users/123/profile",
        None
    )));

    // Multi-segment wildcard (should also match)
    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/users/org/team/member/profile",
        None
    )));

    // Missing wildcard content - blocked
    assert!(!engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/users/profile",
        None
    )));
}

#[test]
fn test_query_string_matching() {
    let engine = FilterEngine::new(vec![
        rule("GET", "https://api.example.com/search?q=*"),
    ])
    .unwrap();

    // With matching query - allowed
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
        Some("q=anything%20here")
    )));

    // Without query - blocked (rule requires query)
    assert!(!engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/search",
        None
    )));

    // Different query param - blocked
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
fn test_port_matching() {
    let engine = FilterEngine::new(vec![
        rule("GET", "https://api.example.com:8443/api"),
    ])
    .unwrap();

    // Explicit port match - allowed
    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        Some(8443),
        "/api",
        None
    )));

    // Wrong port - blocked
    assert!(!engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        Some(443),
        "/api",
        None
    )));

    // No port (defaults to 443) - blocked
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
fn test_default_port_matching() {
    let engine = FilterEngine::new(vec![
        rule("GET", "https://api.example.com:443/api"),
    ])
    .unwrap();

    // Explicit 443 - allowed
    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        Some(443),
        "/api",
        None
    )));

    // No port (defaults to 443) - allowed
    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/api",
        None
    )));
}

#[test]
fn test_multiple_rules() {
    let engine = FilterEngine::new(vec![
        rule("GET", "https://api.example.com/public/*"),
        rule("POST", "https://api.example.com/data"),
        rule("*", "https://cdn.example.com/*"),
    ])
    .unwrap();

    // First rule
    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/public/info",
        None
    )));

    // Second rule
    assert!(engine.is_allowed(&RequestInfo::http(
        "POST",
        "https",
        "api.example.com",
        None,
        "/data",
        None
    )));

    // Third rule
    assert!(engine.is_allowed(&RequestInfo::http(
        "PUT",
        "https",
        "cdn.example.com",
        None,
        "/file",
        None
    )));

    // No matching rule - blocked
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
        rule("GET", "https://api.example.com/http"),
        ws_rule("wss://api.example.com/socket"),
    ])
    .unwrap();

    // HTTP request matches HTTP rule
    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/http",
        None
    )));

    // WebSocket matches WebSocket rule
    assert!(engine.is_allowed(&RequestInfo::websocket(
        "https",
        "api.example.com",
        None,
        "/socket",
        None
    )));

    // WebSocket does NOT match HTTP rule
    assert!(!engine.is_allowed(&RequestInfo::websocket(
        "https",
        "api.example.com",
        None,
        "/http",
        None
    )));

    // HTTP does NOT match WebSocket rule
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
fn test_case_insensitive_method() {
    let engine = FilterEngine::new(vec![
        rule("get", "https://api.example.com/test"),
    ])
    .unwrap();

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
fn test_github_like_rules() {
    let engine = FilterEngine::new(vec![
        rule("*", "https://api.github.com/*"),
        rule("*", "https://*.githubusercontent.com/*"),
        rule("*", "https://github.com/*"),
    ])
    .unwrap();

    // GitHub API
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

    // Raw content
    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "raw.githubusercontent.com",
        None,
        "/owner/repo/main/file.txt",
        None
    )));

    // Main site
    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "github.com",
        None,
        "/owner/repo",
        None
    )));
}

#[test]
fn test_complex_path_patterns() {
    let engine = FilterEngine::new(vec![
        rule("GET", "https://api.example.com/v*/users/*/posts/*"),
    ])
    .unwrap();

    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/v1/users/123/posts/456",
        None
    )));

    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/v2/users/abc/posts/latest",
        None
    )));

    assert!(engine.is_allowed(&RequestInfo::http(
        "GET",
        "https",
        "api.example.com",
        None,
        "/v10/users/org/team/user/posts/2024/01/post",
        None
    )));
}

#[test]
fn test_request_info_full_url() {
    let r1 = RequestInfo::http("GET", "https", "example.com", None, "/path", None);
    assert_eq!(r1.full_url(), "https://example.com/path");

    let r2 = RequestInfo::http("GET", "https", "example.com", Some(8443), "/path", Some("q=1"));
    assert_eq!(r2.full_url(), "https://example.com:8443/path?q=1");

    let r3 = RequestInfo::http("GET", "http", "example.com", Some(80), "/path", None);
    assert_eq!(r3.full_url(), "http://example.com/path");

    let r4 = RequestInfo::http("GET", "https", "example.com", Some(443), "/path", None);
    assert_eq!(r4.full_url(), "https://example.com/path");
}
