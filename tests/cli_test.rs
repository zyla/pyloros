//! Integration tests for CLI subcommands (validate-config, generate-ca)

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn cmd() -> Command {
    cargo_bin_cmd!()
}

// ---------- validate-config ----------

#[test]
fn validate_config_valid_minimal() {
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

    cmd()
        .args(["validate-config", "--config", config_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Configuration is valid!"))
        .stdout(predicate::str::contains("Bind address: 127.0.0.1:9090"))
        .stdout(predicate::str::contains("Rules: 0"));
}

#[test]
fn validate_config_valid_with_rules() {
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

    cmd()
        .args(["validate-config", "--config", config_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Configuration is valid!"))
        .stdout(predicate::str::contains("Rules: 3"))
        .stdout(predicate::str::contains(
            "1. GET https://api.example.com/health",
        ))
        .stdout(predicate::str::contains("2. * https://*.github.com/*"))
        .stdout(predicate::str::contains(
            "3. GET wss://realtime.example.com/socket [WebSocket]",
        ))
        .stdout(predicate::str::contains(
            "All 3 rules compiled successfully.",
        ));
}

#[test]
fn validate_config_invalid_toml() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("bad.toml");
    fs::write(&config_path, "this is not valid toml [[[").unwrap();

    cmd()
        .args(["validate-config", "--config", config_path.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn validate_config_nonexistent_file() {
    cmd()
        .args([
            "validate-config",
            "--config",
            "/tmp/nonexistent_redlim.toml",
        ])
        .assert()
        .failure();
}

#[test]
fn validate_config_invalid_rule_pattern() {
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

    cmd()
        .args(["validate-config", "--config", config_path.to_str().unwrap()])
        .assert()
        .failure();
}

// ---------- generate-ca ----------

#[test]
fn generate_ca_default() {
    let dir = TempDir::new().unwrap();

    cmd()
        .args(["generate-ca", "--out", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "CA certificate generated successfully!",
        ));

    let cert = fs::read_to_string(dir.path().join("ca.crt")).unwrap();
    let key = fs::read_to_string(dir.path().join("ca.key")).unwrap();

    assert!(cert.contains("BEGIN CERTIFICATE"));
    assert!(key.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn generate_ca_custom_names() {
    let dir = TempDir::new().unwrap();

    cmd()
        .args([
            "generate-ca",
            "--out",
            dir.path().to_str().unwrap(),
            "--cert-name",
            "my.crt",
            "--key-name",
            "my.key",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "CA certificate generated successfully!",
        ));

    assert!(dir.path().join("my.crt").exists());
    assert!(dir.path().join("my.key").exists());

    let cert = fs::read_to_string(dir.path().join("my.crt")).unwrap();
    let key = fs::read_to_string(dir.path().join("my.key")).unwrap();
    assert!(cert.contains("BEGIN CERTIFICATE"));
    assert!(key.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn generate_ca_creates_output_dir() {
    let dir = TempDir::new().unwrap();
    let nested = dir.path().join("sub").join("dir");

    cmd()
        .args(["generate-ca", "--out", nested.to_str().unwrap()])
        .assert()
        .success();

    assert!(nested.join("ca.crt").exists());
    assert!(nested.join("ca.key").exists());
}
