//! Config live-reload integration tests.
//!
//! Tests verify that the proxy picks up configuration changes at runtime
//! without restarting, using an explicit reload trigger channel.

mod common;

use common::*;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// ReloadableProxy — test helper for config-file-based proxy with reload
// ---------------------------------------------------------------------------

struct ReloadableProxy {
    addr: SocketAddr,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    reload_tx: tokio::sync::mpsc::Sender<()>,
    reload_complete: Arc<tokio::sync::Notify>,
    config_path: PathBuf,
    _dir: tempfile::TempDir,
}

impl ReloadableProxy {
    /// Start a proxy from a TOML config string. Writes the config to a temp file
    /// and sets up reload trigger + completion notification.
    async fn start(ca: &TestCa, config_toml: &str, upstream_port: u16) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, config_toml).unwrap();

        let config = pyloros::Config::from_file(&config_path).unwrap();
        let mut server = pyloros::ProxyServer::new(config)
            .unwrap()
            .with_config_path(config_path.clone())
            .with_upstream_port_override(upstream_port)
            .with_upstream_tls(ca.client_tls_config());

        let reload_tx = server.reload_trigger();
        let reload_complete = server.reload_complete_notify();
        let addr = server.bind().await.unwrap().tcp_addr();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = server.serve(shutdown_rx).await;
        });

        Self {
            addr,
            shutdown_tx,
            reload_tx,
            reload_complete,
            config_path,
            _dir: dir,
        }
    }

    /// Write a new config and trigger a reload, waiting for completion.
    /// Safe in current_thread tokio runtime (default for #[tokio::test]).
    async fn reload(&self, config_toml: &str) {
        std::fs::write(&self.config_path, config_toml).unwrap();
        let notified = self.reload_complete.notified();
        self.reload_tx.send(()).await.unwrap();
        notified.await;
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// Generate the [proxy] section of a config TOML with CA paths from TestCa.
fn base_proxy_config(ca: &TestCa) -> String {
    format!(
        "[proxy]\nbind_address = \"127.0.0.1:0\"\nca_cert = \"{}\"\nca_key = \"{}\"\n",
        ca.cert_path, ca.key_path
    )
}

/// Attempt an HTTPS GET and return either the response or the error debug string.
/// reqwest surfaces 407 on CONNECT as a connection error, not an HTTP response.
async fn try_https_get(
    client: &ReportingClient<'_>,
    url: &str,
) -> Result<reqwest::Response, String> {
    client.report().action(format!("GET `{}`", url));
    match client.inner().get(url).send().await {
        Ok(resp) => Ok(resp),
        Err(e) => Err(format!("{:?}", e)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// After reloading with empty rules, new connections are blocked.
#[tokio::test]
async fn test_rules_reload() {
    let t = test_report!("Rules reload changes filtering behavior");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("Hello"))
        .report(&t, "responds 200")
        .start()
        .await;

    // Start with rule allowing GET https://localhost/*
    let config = format!(
        "{}\n[[rules]]\nmethod = \"GET\"\nurl = \"https://localhost/*\"\n",
        base_proxy_config(&ca)
    );
    let proxy = ReloadableProxy::start(&ca, &config, upstream.port()).await;
    t.setup("Proxy with rules: [`GET https://localhost/*`]");

    // Before reload: request is allowed
    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").await;
    t.assert_eq("before reload: status", &resp.status().as_u16(), &200u16);

    // Reload with no rules (blocks everything)
    let new_config = base_proxy_config(&ca);
    t.action("Reload config with empty rules");
    proxy.reload(&new_config).await;

    // After reload: new connection is blocked
    // Must create a new client — reqwest reuses CONNECT tunnels from old connections
    let client2 = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client2.get("https://localhost/test2").await;
    t.assert_eq("after reload: status", &resp.status().as_u16(), &451u16);

    proxy.shutdown();
}

/// Invalid config is rejected; old rules continue to work.
#[tokio::test]
async fn test_invalid_config_preserves_old_rules() {
    let t = test_report!("Invalid config reload preserves old rules");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("Hello"))
        .report(&t, "responds 200")
        .start()
        .await;

    let config = format!(
        "{}\n[[rules]]\nmethod = \"GET\"\nurl = \"https://localhost/*\"\n",
        base_proxy_config(&ca)
    );
    let proxy = ReloadableProxy::start(&ca, &config, upstream.port()).await;
    t.setup("Proxy with rule: `GET https://localhost/*`");

    // Before reload: request is allowed
    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").await;
    t.assert_eq("before reload: status", &resp.status().as_u16(), &200u16);

    // Reload with invalid TOML
    t.action("Reload config with invalid TOML");
    proxy.reload("this is not valid TOML [[[").await;

    // After invalid reload: new connections still use old rules
    let client2 = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client2.get("https://localhost/test2").await;
    t.assert_eq(
        "after invalid reload: status",
        &resp.status().as_u16(),
        &200u16,
    );

    proxy.shutdown();
}

/// After reloading with a new password, old password is rejected and new password works.
#[tokio::test]
async fn test_auth_reload() {
    let t = test_report!("Auth credential reload requires new password");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("Hello"))
        .report(&t, "responds 200")
        .start()
        .await;

    let config = format!(
        "{}auth_username = \"user\"\nauth_password = \"pass1\"\n\n\
         [[rules]]\nmethod = \"GET\"\nurl = \"https://localhost/*\"\n",
        base_proxy_config(&ca)
    );
    let proxy = ReloadableProxy::start(&ca, &config, upstream.port()).await;
    t.setup("Proxy with auth (user/pass1) and rule `GET https://localhost/*`");

    // With correct password (pass1): allowed
    let client = ReportingClient::new_with_proxy_auth(&t, proxy.addr(), &ca, "user", "pass1");
    let resp = client.get("https://localhost/test").await;
    t.assert_eq(
        "pass1 before reload: status",
        &resp.status().as_u16(),
        &200u16,
    );

    // Reload with new password
    let new_config = format!(
        "{}auth_username = \"user\"\nauth_password = \"pass2\"\n\n\
         [[rules]]\nmethod = \"GET\"\nurl = \"https://localhost/*\"\n",
        base_proxy_config(&ca)
    );
    t.action("Reload config with auth_password = pass2");
    proxy.reload(&new_config).await;

    // Old password should fail (407 — reqwest surfaces as connection error)
    let client_old = ReportingClient::new_with_proxy_auth(&t, proxy.addr(), &ca, "user", "pass1");
    let result = try_https_get(&client_old, "https://localhost/test2").await;
    t.assert_true("pass1 after reload: request failed", result.is_err());
    t.assert_contains(
        "error mentions proxy auth",
        &result.unwrap_err(),
        "ProxyAuthRequired",
    );

    // New password should work
    let client_new = ReportingClient::new_with_proxy_auth(&t, proxy.addr(), &ca, "user", "pass2");
    let resp = client_new.get("https://localhost/test3").await;
    t.assert_eq(
        "pass2 after reload: status",
        &resp.status().as_u16(),
        &200u16,
    );

    proxy.shutdown();
}

/// Changing bind_address logs a warning but proxy continues on old address.
#[tokio::test]
async fn test_non_reloadable_field_warns() {
    let t = test_report!("Non-reloadable bind_address change logs warning");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("Hello"))
        .report(&t, "responds 200")
        .start()
        .await;

    let config = format!(
        "{}\n[[rules]]\nmethod = \"GET\"\nurl = \"https://localhost/*\"\n",
        base_proxy_config(&ca)
    );

    let logs = LogCapture::new();
    let proxy = ReloadableProxy::start(&ca, &config, upstream.port()).await;
    t.setup("Proxy with bind_address 127.0.0.1:0");

    // Reload with different bind_address
    let new_config = format!(
        "[proxy]\nbind_address = \"127.0.0.1:9999\"\n\
         ca_cert = \"{}\"\nca_key = \"{}\"\n\n\
         [[rules]]\nmethod = \"GET\"\nurl = \"https://localhost/*\"\n",
        ca.cert_path, ca.key_path
    );
    t.action("Reload config with bind_address = 127.0.0.1:9999");
    proxy.reload(&new_config).await;

    t.assert_true(
        "warning logged about bind_address",
        logs.contains("bind_address changed but requires restart"),
    );

    // Proxy still works on original address
    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/test").await;
    t.assert_eq("proxy still works", &resp.status().as_u16(), &200u16);

    proxy.shutdown();
}

/// Audit log can be enabled via reload; only post-reload requests appear in the log.
#[tokio::test]
async fn test_audit_log_reload() {
    let t = test_report!("Audit log enabled via reload");
    let ca = TestCa::generate();
    let upstream = TestUpstream::builder(&ca, ok_handler("Hello"))
        .report(&t, "responds 200")
        .start()
        .await;

    // Start without audit log
    let config = format!(
        "{}\n[[rules]]\nmethod = \"GET\"\nurl = \"https://localhost/*\"\n",
        base_proxy_config(&ca)
    );
    let proxy = ReloadableProxy::start(&ca, &config, upstream.port()).await;
    t.setup("Proxy without audit log");

    let audit_dir = tempfile::tempdir().unwrap();
    let audit_path = audit_dir.path().join("audit.jsonl");

    // Make request before audit log is enabled
    let client = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client.get("https://localhost/before").await;
    t.assert_eq("before audit: status", &resp.status().as_u16(), &200u16);

    // Reload with audit log enabled
    let new_config = format!(
        "{}\n[logging]\naudit_log = \"{}\"\n\n\
         [[rules]]\nmethod = \"GET\"\nurl = \"https://localhost/*\"\n",
        base_proxy_config(&ca),
        audit_path.display()
    );
    t.action(format!(
        "Reload config with audit_log = {}",
        audit_path.display()
    ));
    proxy.reload(&new_config).await;

    // Make request after audit log is enabled (new connection)
    let client2 = ReportingClient::new(&t, proxy.addr(), &ca);
    let resp = client2.get("https://localhost/after").await;
    t.assert_eq("after audit: status", &resp.status().as_u16(), &200u16);

    // Give the audit logger a moment to flush
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Check audit log — should only have entries from after reload
    let entries = read_audit_entries(audit_path.to_str().unwrap());
    t.assert_true("has audit entries", !entries.is_empty());

    let urls: Vec<&str> = entries
        .iter()
        .filter_map(|e| e.get("url").and_then(|v| v.as_str()))
        .collect();
    t.assert_true(
        "no entries for /before",
        urls.iter().all(|u| !u.contains("/before")),
    );
    t.assert_true(
        "has entry for /after",
        urls.iter().any(|u| u.contains("/after")),
    );

    proxy.shutdown();
}
