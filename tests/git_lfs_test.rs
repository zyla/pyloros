//! Tests for Git-LFS batch endpoint filtering.
//!
//! These tests verify that git rules automatically generate LFS batch endpoint
//! rules and that the proxy correctly inspects the JSON body to allow/block
//! LFS download and upload operations.

mod common;

use common::{
    git_rule, git_rule_with_branches, ok_handler, rule, ReportingClient, TestCa, TestProxy,
    TestUpstream,
};

/// Helper to build an LFS batch JSON body.
fn lfs_batch_body(operation: &str) -> String {
    format!(
        r#"{{"operation":"{}","transfers":["basic"],"objects":[{{"oid":"abc123","size":42}}]}}"#,
        operation
    )
}

// ---------------------------------------------------------------------------
// Manual HTTP tests (crafted JSON, no real git-lfs binary needed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_lfs_download_allowed_by_fetch_rule() {
    let t = test_report!("LFS download allowed by git=fetch rule");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream =
        TestUpstream::start_reported(&t, &ca, ok_handler("lfs-batch-ok"), "LFS batch mock").await;

    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![git_rule("fetch", "https://localhost/org/repo")],
        upstream.port(),
    )
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("download"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch with operation=download");

    t.assert_eq("status 200", &resp.status().as_u16(), &200u16);
    let body = resp.text().await.unwrap();
    t.assert_eq("upstream reached", &body.as_str(), &"lfs-batch-ok");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_upload_blocked_by_fetch_rule() {
    let t = test_report!("LFS upload blocked by git=fetch rule (download only)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream =
        TestUpstream::start_reported(&t, &ca, ok_handler("should-not-reach"), "LFS mock").await;

    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![git_rule("fetch", "https://localhost/org/repo")],
        upstream.port(),
    )
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("upload"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch with operation=upload (should be blocked)");

    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_upload_allowed_by_push_rule() {
    let t = test_report!("LFS upload allowed by git=push rule");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream =
        TestUpstream::start_reported(&t, &ca, ok_handler("lfs-upload-ok"), "LFS mock").await;

    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![git_rule("push", "https://localhost/org/repo")],
        upstream.port(),
    )
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("upload"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch with operation=upload");

    t.assert_eq("status 200", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_download_blocked_by_push_rule() {
    let t = test_report!("LFS download blocked by git=push rule (upload only)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream =
        TestUpstream::start_reported(&t, &ca, ok_handler("should-not-reach"), "LFS mock").await;

    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![git_rule("push", "https://localhost/org/repo")],
        upstream.port(),
    )
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("download"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch with operation=download (should be blocked)");

    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_both_ops_allowed_by_star_rule() {
    let t = test_report!("Both LFS operations allowed by git=* rule");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::start_reported(&t, &ca, ok_handler("lfs-ok"), "LFS mock").await;

    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![git_rule("*", "https://localhost/org/repo")],
        upstream.port(),
    )
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp_dl = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("download"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch with operation=download");
    t.assert_eq("download status 200", &resp_dl.status().as_u16(), &200u16);

    let resp_ul = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("upload"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch with operation=upload");
    t.assert_eq("upload status 200", &resp_ul.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_blocked_on_plain_http() {
    let t = test_report!("LFS batch blocked on plain HTTP (body inspection requires HTTPS)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream =
        TestUpstream::start_reported(&t, &ca, ok_handler("should-not-reach"), "LFS mock").await;

    // Use an http:// URL in the rule so it matches plain HTTP requests
    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![git_rule("*", "http://localhost/org/repo")],
        upstream.port(),
    )
    .await;

    let client = ReportingClient::new_plain(&t, proxy.addr());
    let resp = client
        .inner()
        .post("http://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("download"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch over plain HTTP (should be blocked)");

    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_invalid_json_blocked() {
    let t = test_report!("LFS batch with invalid JSON body is blocked");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream =
        TestUpstream::start_reported(&t, &ca, ok_handler("should-not-reach"), "LFS mock").await;

    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![git_rule("*", "https://localhost/org/repo")],
        upstream.port(),
    )
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body("not valid json")
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch with invalid JSON (should be blocked)");

    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_missing_operation_blocked() {
    let t = test_report!("LFS batch with missing operation field is blocked");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream =
        TestUpstream::start_reported(&t, &ca, ok_handler("should-not-reach"), "LFS mock").await;

    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![git_rule("*", "https://localhost/org/repo")],
        upstream.port(),
    )
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(r#"{"objects":[{"oid":"abc","size":42}]}"#)
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch without operation field (should be blocked)");

    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_get_to_batch_blocked() {
    let t = test_report!("GET to LFS batch endpoint is blocked (only POST)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream =
        TestUpstream::start_reported(&t, &ca, ok_handler("should-not-reach"), "LFS mock").await;

    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![git_rule("*", "https://localhost/org/repo")],
        upstream.port(),
    )
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .get("https://localhost/org/repo/info/lfs/objects/batch")
        .await;

    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_branch_restricted_push_allows_lfs_upload() {
    let t =
        test_report!("Branch-restricted push rule allows LFS upload (branches don't apply to LFS)");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::start_reported(&t, &ca, ok_handler("lfs-ok"), "LFS mock").await;

    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![git_rule_with_branches(
            "push",
            "https://localhost/org/repo",
            &["feature/*"],
        )],
        upstream.port(),
    )
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("upload"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch upload with branch-restricted push rule");

    t.assert_eq("status 200", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_merged_scan_fetch_plus_push() {
    let t = test_report!("Separate fetch+push rules merge to allow both LFS operations");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream = TestUpstream::start_reported(&t, &ca, ok_handler("lfs-ok"), "LFS mock").await;

    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![
            git_rule("fetch", "https://localhost/org/repo"),
            git_rule("push", "https://localhost/org/repo"),
        ],
        upstream.port(),
    )
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp_dl = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("download"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch download (merged fetch+push rules)");
    t.assert_eq("download status 200", &resp_dl.status().as_u16(), &200u16);

    let resp_ul = client
        .inner()
        .post("https://localhost/org/repo/info/lfs/objects/batch")
        .header("Content-Type", "application/vnd.git-lfs+json")
        .body(lfs_batch_body("upload"))
        .send()
        .await
        .unwrap();
    t.action("POST LFS batch upload (merged fetch+push rules)");
    t.assert_eq("upload status 200", &resp_ul.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_transfer_url_requires_separate_rule() {
    let t = test_report!("LFS transfer URLs on different paths require separate HTTP rules");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream =
        TestUpstream::start_reported(&t, &ca, ok_handler("object-data"), "LFS object store mock")
            .await;

    // Only git rule — no separate rule for /lfs/objects/*
    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![git_rule("fetch", "https://localhost/org/repo")],
        upstream.port(),
    )
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    // GET to a transfer URL should be blocked (not covered by git rule)
    let resp = client
        .get("https://localhost/org/repo/lfs/objects/abc123def456")
        .await;
    t.action("GET transfer URL without separate rule (should be blocked)");
    t.assert_eq("status 451", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test]
async fn test_lfs_transfer_url_allowed_with_separate_rule() {
    let t = test_report!("LFS transfer URLs allowed when separate HTTP rule is present");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let upstream =
        TestUpstream::start_reported(&t, &ca, ok_handler("object-data"), "LFS object store mock")
            .await;

    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![
            git_rule("fetch", "https://localhost/org/repo"),
            rule("GET", "https://localhost/*/lfs/objects/*"),
        ],
        upstream.port(),
    )
    .await;

    let client = ReportingClient::new(&t, proxy.addr(), &ca);

    let resp = client
        .get("https://localhost/org/repo/lfs/objects/abc123def456")
        .await;
    t.assert_eq("status 200", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
    upstream.shutdown();
}
