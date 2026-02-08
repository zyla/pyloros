//! Binary-level integration tests that spawn the real `redlimitador` binary
//! and drive it with `curl`.

mod common;

use common::{ok_handler, TestCa, TestUpstream};
use std::io::{BufRead, BufReader, Read as _};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a TOML config string for the binary.
fn build_config_toml(
    ca_cert: &str,
    ca_key: &str,
    upstream_override_port: u16,
    upstream_tls_ca: &str,
    rules: &[(&str, &str)],
) -> String {
    let mut toml = format!(
        r#"[proxy]
bind_address = "127.0.0.1:0"
ca_cert = "{ca_cert}"
ca_key = "{ca_key}"
upstream_override_port = {upstream_override_port}
upstream_tls_ca = "{upstream_tls_ca}"

[logging]
level = "info"
log_requests = true

"#
    );

    for (method, url) in rules {
        toml.push_str(&format!(
            r#"[[rules]]
method = "{method}"
url = "{url}"

"#
        ));
    }

    toml
}

/// Spawn the proxy binary with the given config file path.
/// Parses stderr for the "Proxy server listening address=..." line to discover the port.
/// Returns (Child, port). A background thread drains stderr to prevent pipe blocking.
fn spawn_proxy(config_path: &Path) -> (Child, u16) {
    let bin = assert_cmd::cargo::cargo_bin!("redlimitador");

    let mut child = Command::new(bin)
        .args(["run", "--config", config_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn redlimitador binary");

    let stderr = child.stderr.take().expect("no stderr");

    // Background thread reads all stderr; sends port once found.
    let (tx, rx) = std::sync::mpsc::sync_channel::<u16>(1);

    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut sent = false;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if !sent {
                if let Some(port) = parse_listening_port(&line) {
                    let _ = tx.send(port);
                    sent = true;
                }
            }
        }
    });

    let port = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("timed out waiting for proxy to print listening address");

    (child, port)
}

/// Like `spawn_proxy`, but also collects all stderr lines into a shared buffer.
fn spawn_proxy_with_logs(config_path: &Path) -> (Child, u16, Arc<Mutex<Vec<String>>>) {
    let bin = assert_cmd::cargo::cargo_bin!("redlimitador");

    let mut child = Command::new(bin)
        .args(["run", "--config", config_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn redlimitador binary");

    let stderr = child.stderr.take().expect("no stderr");
    let (tx, rx) = std::sync::mpsc::sync_channel::<u16>(1);
    let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let logs_clone = Arc::clone(&logs);

    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut sent = false;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if !sent {
                if let Some(port) = parse_listening_port(&line) {
                    let _ = tx.send(port);
                    sent = true;
                }
            }
            logs_clone.lock().unwrap().push(line);
        }
    });

    let port = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("timed out waiting for proxy to print listening address");

    (child, port, logs)
}

/// Strip ANSI escape sequences from a string.
fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Extract port from a tracing log line like "... Proxy server listening address=127.0.0.1:PORT"
fn parse_listening_port(line: &str) -> Option<u16> {
    let clean = strip_ansi(line);
    let idx = clean.find("address=")?;
    let addr_str = clean[idx + "address=".len()..].trim();
    let colon = addr_str.rfind(':')?;
    addr_str[colon + 1..].parse().ok()
}

/// Run curl through the proxy via HTTPS_PROXY env var. Returns (status_code, body, stderr).
fn curl_get(proxy_port: u16, url: &str, ca_cert_path: &str) -> (u16, String, String) {
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);

    let output = Command::new("curl")
        .env("HTTPS_PROXY", &proxy_url)
        .args([
            "-s",
            "-S",
            "--cacert",
            ca_cert_path,
            "-w",
            "\n%{http_code}",
            "--max-time",
            "10",
            url,
        ])
        .output()
        .expect("failed to run curl");

    let full_output = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // The last line is the status code (from -w "\n%{http_code}")
    let (body, code) = full_output
        .trim_end()
        .rsplit_once('\n')
        .map_or_else(|| ("", full_output.trim()), |(body, code)| (body, code));

    let status: u16 = code.parse().unwrap_or_else(|_| {
        panic!(
            "failed to parse status code from curl output: {:?}, stderr: {}",
            full_output, stderr
        )
    });

    (status, body.to_string(), stderr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Spawn the binary, curl an allowed HTTPS request, verify 200 + body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_binary_allowed_get_returns_200() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("hello binary")).await;

    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");
    let config_toml = build_config_toml(
        &ca.cert_path,
        &ca.key_path,
        upstream.port(),
        &ca.cert_path,
        &[("GET", "https://localhost/*")],
    );
    std::fs::write(&config_path, &config_toml).unwrap();

    let (mut child, proxy_port) = spawn_proxy(&config_path);

    let (status, body, stderr) = curl_get(proxy_port, "https://localhost/test", &ca.cert_path);

    assert_eq!(status, 200, "expected 200, stderr: {}", stderr);
    assert_eq!(body, "hello binary");

    child.kill().ok();
    child.wait().ok();
    upstream.shutdown();
}

/// Spawn the binary, curl a blocked HTTPS request, verify 451.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_binary_blocked_request_returns_451() {
    let ca = TestCa::generate();
    let upstream = TestUpstream::start(&ca, ok_handler("should not reach")).await;

    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");
    // Rule only allows example.com, not localhost
    let config_toml = build_config_toml(
        &ca.cert_path,
        &ca.key_path,
        upstream.port(),
        &ca.cert_path,
        &[("GET", "https://example.com/*")],
    );
    std::fs::write(&config_path, &config_toml).unwrap();

    let (mut child, proxy_port) = spawn_proxy(&config_path);

    let (status, _body, stderr) = curl_get(proxy_port, "https://localhost/test", &ca.cert_path);

    assert_eq!(status, 451, "expected 451, stderr: {}", stderr);

    child.kill().ok();
    child.wait().ok();
    upstream.shutdown();
}

/// Generate a TOML config for connecting to real upstream servers (no test overrides).
fn build_real_config_toml(ca_cert: &str, ca_key: &str, rules: &[(&str, &str)]) -> String {
    let mut toml = format!(
        r#"[proxy]
bind_address = "127.0.0.1:0"
ca_cert = "{ca_cert}"
ca_key = "{ca_key}"

[logging]
level = "info"
log_requests = true

"#
    );

    for (method, url) in rules {
        toml.push_str(&format!(
            r#"[[rules]]
method = "{method}"
url = "{url}"

"#
        ));
    }

    toml
}

/// Run `claude -p "Say hi"` through the proxy, verify it gets a response and
/// the proxy logged an ALLOWED request to api.anthropic.com.
///
/// Skipped if `claude` CLI is not installed, not authenticated, or running
/// inside another Claude Code session (nested sessions hang).
///
/// NOTE: Nested `claude -p` hangs when spawned from within a Claude Code
/// session (the Node.js event loop busy-spins after completing the API call).
/// The root cause is unknown — it's not env vars, inherited FDs, stdin, or
/// process group. See `devdocs/lessons/nested-claude-code-hangs.md`.
/// Because most development on this project happens agentically, this test
/// is at risk of silently rotting. Run it manually from a standalone terminal
/// after changes to TLS/proxy logic:
///   cargo test test_binary_claude_code_through_proxy -- --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_binary_claude_code_through_proxy() {
    // Skip if running inside another claude session (nested claude -p hangs;
    // see devdocs/lessons/nested-claude-code-hangs.md)
    if std::env::var("CLAUDECODE").is_ok() {
        eprintln!("running inside Claude Code session, skipping");
        return;
    }

    // Skip if `claude` not on PATH
    if Command::new("claude").arg("--version").output().is_err() {
        eprintln!("claude CLI not found, skipping");
        return;
    }

    // Skip if not authenticated
    let home = std::env::var("HOME").expect("HOME not set");
    let creds_path = std::path::PathBuf::from(&home).join(".claude/.credentials.json");
    if !creds_path.exists() {
        eprintln!("claude not authenticated (~/.claude/.credentials.json missing), skipping");
        return;
    }

    let ca = TestCa::generate();

    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");
    let config_toml = build_real_config_toml(
        &ca.cert_path,
        &ca.key_path,
        &[
            ("*", "https://api.anthropic.com/*"),
            ("*", "https://statsig.anthropic.com/*"),
            ("*", "https://sentry.io/*"),
            ("*", "https://*.sentry.io/*"),
        ],
    );
    std::fs::write(&config_path, &config_toml).unwrap();

    let (mut child, proxy_port, proxy_logs) = spawn_proxy_with_logs(&config_path);

    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let mut claude_child = Command::new("claude")
        .args([
            "-p",
            "Say hi",
            "--model",
            "claude-haiku-4-5-20251001",
            "--max-turns",
            "1",
        ])
        .env("HTTPS_PROXY", &proxy_url)
        .env("NODE_EXTRA_CA_CERTS", &ca.cert_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn claude");

    let claude_pid = claude_child.id();

    // Wait with a 60-second timeout
    let timeout = std::time::Duration::from_secs(60);
    let start = std::time::Instant::now();
    let status = loop {
        match claude_child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() > timeout {
                    claude_child.kill().ok();
                    claude_child.wait().ok();
                    child.kill().ok();
                    child.wait().ok();
                    panic!(
                        "claude CLI timed out after {:?} (pid {})",
                        timeout, claude_pid
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => panic!("error waiting for claude: {}", e),
        }
    };

    let stdout = {
        let mut buf = Vec::new();
        claude_child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        String::from_utf8_lossy(&buf).to_string()
    };
    let stderr = {
        let mut buf = Vec::new();
        claude_child
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        String::from_utf8_lossy(&buf).to_string()
    };

    assert!(
        status.success(),
        "claude exited with {}\nstdout: {}\nstderr: {}",
        status,
        stdout,
        stderr,
    );
    assert!(
        !stdout.trim().is_empty(),
        "claude produced empty output\nstderr: {}",
        stderr,
    );

    // Verify the proxy actually intercepted an Anthropic API call
    let logs = proxy_logs.lock().unwrap();
    let saw_anthropic = logs.iter().any(|line| {
        let clean = strip_ansi(line);
        clean.contains("ALLOWED") && clean.contains("api.anthropic.com")
    });
    assert!(
        saw_anthropic,
        "proxy did not log an ALLOWED request to api.anthropic.com\nproxy logs:\n{}",
        logs.join("\n"),
    );

    eprintln!("claude response: {}", stdout.trim());

    child.kill().ok();
    child.wait().ok();
}

/// Run `generate-ca --out <tmpdir>`, verify cert and key files are created with valid PEM.
#[test]
fn test_binary_generate_ca() {
    let tmp = TempDir::new().unwrap();

    let bin = assert_cmd::cargo::cargo_bin!("redlimitador");
    let output = Command::new(bin)
        .args(["generate-ca", "--out", tmp.path().to_str().unwrap()])
        .output()
        .expect("failed to run generate-ca");

    assert!(
        output.status.success(),
        "generate-ca failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert_path = tmp.path().join("ca.crt");
    let key_path = tmp.path().join("ca.key");

    assert!(cert_path.exists(), "ca.crt not created");
    assert!(key_path.exists(), "ca.key not created");

    let cert_content = std::fs::read_to_string(&cert_path).unwrap();
    let key_content = std::fs::read_to_string(&key_path).unwrap();

    assert!(
        cert_content.contains("-----BEGIN CERTIFICATE-----"),
        "ca.crt missing PEM header"
    );
    assert!(
        key_content.contains("-----BEGIN PRIVATE KEY-----"),
        "ca.key missing PEM header"
    );
}
