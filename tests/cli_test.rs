//! Integration tests for CLI subcommands (validate-config, generate-ca)

mod common;

use common::TestReport;
use std::fs;
use tempfile::TempDir;

/// Run a CLI command and report it.
fn run_cli_reported(t: &TestReport, args: &[&str]) -> std::process::Output {
    let bin = assert_cmd::cargo::cargo_bin!("redlimitador");
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args);
    common::run_command_reported(t, &mut cmd)
}

// ---------- validate-config ----------

#[test]
fn validate_config_valid_minimal() {
    let t = test_report!("validate-config with minimal valid config");

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[proxy]
bind_address = "127.0.0.1:9090"
"#,
    )
    .unwrap();

    let output = run_cli_reported(
        &t,
        &["validate-config", "--config", config_path.to_str().unwrap()],
    );
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    t.assert_true("Exit success", output.status.success());
    t.assert_contains("Valid message", &stdout, "Configuration is valid!");
    t.assert_contains(
        "Bind address shown",
        &stdout,
        "Bind address: 127.0.0.1:9090",
    );
    t.assert_contains("Rules count", &stdout, "Rules: 0");
}

#[test]
fn validate_config_valid_with_rules() {
    let t = test_report!("validate-config with rules");

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[proxy]
bind_address = "127.0.0.1:8080"

[[rules]]
method = "GET"
url = "https://api.example.com/health"

[[rules]]
method = "*"
url = "https://*.github.com/*"

[[rules]]
method = "GET"
url = "wss://realtime.example.com/socket"
websocket = true
"#,
    )
    .unwrap();

    let output = run_cli_reported(
        &t,
        &["validate-config", "--config", config_path.to_str().unwrap()],
    );
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    t.assert_true("Exit success", output.status.success());
    t.assert_contains("Valid message", &stdout, "Configuration is valid!");
    t.assert_contains("Rules count", &stdout, "Rules: 3");
    t.assert_contains("Rule 1", &stdout, "1. GET https://api.example.com/health");
    t.assert_contains("Rule 2", &stdout, "2. * https://*.github.com/*");
    t.assert_contains(
        "Rule 3",
        &stdout,
        "3. GET wss://realtime.example.com/socket [WebSocket]",
    );
    t.assert_contains(
        "Compilation success",
        &stdout,
        "All 3 rules compiled successfully.",
    );
}

#[test]
fn validate_config_invalid_toml() {
    let t = test_report!("validate-config rejects invalid TOML");

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("bad.toml");
    fs::write(&config_path, "this is not valid toml [[[").unwrap();

    let output = run_cli_reported(
        &t,
        &["validate-config", "--config", config_path.to_str().unwrap()],
    );

    t.assert_true("Exit failure", !output.status.success());
}

#[test]
fn validate_config_nonexistent_file() {
    let t = test_report!("validate-config rejects nonexistent file");

    let output = run_cli_reported(
        &t,
        &[
            "validate-config",
            "--config",
            "/tmp/nonexistent_redlim.toml",
        ],
    );

    t.assert_true("Exit failure", !output.status.success());
}

#[test]
fn validate_config_invalid_rule_pattern() {
    let t = test_report!("validate-config rejects invalid rule pattern");

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[[rules]]
method = "GET"
url = "not-a-url"
"#,
    )
    .unwrap();

    let output = run_cli_reported(
        &t,
        &["validate-config", "--config", config_path.to_str().unwrap()],
    );

    t.assert_true("Exit failure", !output.status.success());
}

#[test]
fn validate_config_with_credentials() {
    let t = test_report!("validate-config with credentials");

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[[rules]]
method = "*"
url = "https://api.example.com/*"

[[credentials]]
url = "https://api.example.com/*"
header = "x-api-key"
value = "literal-key"

[[credentials]]
url = "https://other.com/*"
header = "authorization"
value = "Bearer tok"
"#,
    )
    .unwrap();

    let output = run_cli_reported(
        &t,
        &["validate-config", "--config", config_path.to_str().unwrap()],
    );
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    t.assert_true("Exit success", output.status.success());
    t.assert_contains("Credentials count", &stdout, "Credentials: 2");
    t.assert_contains(
        "Cred 1",
        &stdout,
        "1. header=x-api-key url=https://api.example.com/*",
    );
    t.assert_contains(
        "Cred 2",
        &stdout,
        "2. header=authorization url=https://other.com/*",
    );
    t.assert_contains(
        "Compilation success",
        &stdout,
        "All 2 credentials compiled successfully.",
    );
    // Values must never appear in output
    t.assert_not_contains("no secret in output", &stdout, "literal-key");
    t.assert_not_contains("no bearer in output", &stdout, "Bearer tok");
}

// ---------- generate-ca ----------

#[test]
fn generate_ca_default() {
    let t = test_report!("generate-ca with default names");

    let dir = TempDir::new().unwrap();

    let output = run_cli_reported(&t, &["generate-ca", "--out", dir.path().to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    t.assert_true("Exit success", output.status.success());
    t.assert_contains(
        "Success message",
        &stdout,
        "CA certificate generated successfully!",
    );

    let cert = fs::read_to_string(dir.path().join("ca.crt")).unwrap();
    let key = fs::read_to_string(dir.path().join("ca.key")).unwrap();

    t.assert_contains("Cert is PEM", &cert, "BEGIN CERTIFICATE");
    t.assert_contains("Key is PEM", &key, "BEGIN PRIVATE KEY");
}

#[test]
fn generate_ca_custom_names() {
    let t = test_report!("generate-ca with custom names");

    let dir = TempDir::new().unwrap();

    let output = run_cli_reported(
        &t,
        &[
            "generate-ca",
            "--out",
            dir.path().to_str().unwrap(),
            "--cert-name",
            "my.crt",
            "--key-name",
            "my.key",
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    t.assert_true("Exit success", output.status.success());
    t.assert_contains(
        "Success message",
        &stdout,
        "CA certificate generated successfully!",
    );
    t.assert_true("my.crt exists", dir.path().join("my.crt").exists());
    t.assert_true("my.key exists", dir.path().join("my.key").exists());

    let cert = fs::read_to_string(dir.path().join("my.crt")).unwrap();
    let key = fs::read_to_string(dir.path().join("my.key")).unwrap();
    t.assert_contains("Cert is PEM", &cert, "BEGIN CERTIFICATE");
    t.assert_contains("Key is PEM", &key, "BEGIN PRIVATE KEY");
}

#[test]
fn generate_ca_creates_output_dir() {
    let t = test_report!("generate-ca creates output directory if needed");

    let dir = TempDir::new().unwrap();
    let nested = dir.path().join("sub").join("dir");

    let output = run_cli_reported(&t, &["generate-ca", "--out", nested.to_str().unwrap()]);

    t.assert_true("Exit success", output.status.success());
    t.assert_true("ca.crt exists", nested.join("ca.crt").exists());
    t.assert_true("ca.key exists", nested.join("ca.key").exists());
}
