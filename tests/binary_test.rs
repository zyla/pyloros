//! Binary-level integration tests that spawn the real `redlimitador` binary
//! and drive it with `curl`.

mod common;

use common::{ok_handler, TestCa, TestUpstream};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
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

/// Run curl through the proxy. Returns (status_code, body, stderr).
fn curl_get(proxy_port: u16, url: &str, ca_cert_path: &str) -> (u16, String, String) {
    let proxy_addr = format!("http://127.0.0.1:{}", proxy_port);

    let output = Command::new("curl")
        .args([
            "-s",
            "-S",
            "--proxy",
            &proxy_addr,
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
