//! Git smart HTTP clone/push through the HTTPS proxy.
//!
//! These tests verify that git operations work end-to-end through the proxy's
//! MITM TLS pipeline. They use `git http-backend` (CGI) as the upstream server.

mod common;

use bytes::Bytes;
use common::{rule, run_command_reported, TestCa, TestProxy, TestUpstream};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Locate the `git-http-backend` binary via `git --exec-path`.
fn git_http_backend_path() -> PathBuf {
    let output = std::process::Command::new("git")
        .arg("--exec-path")
        .output()
        .expect("git --exec-path failed");
    assert!(output.status.success(), "git --exec-path returned non-zero");
    let exec_path = String::from_utf8(output.stdout)
        .expect("non-UTF-8 exec path")
        .trim()
        .to_string();
    let backend = PathBuf::from(exec_path).join("git-http-backend");
    assert!(
        backend.exists(),
        "git-http-backend not found at {:?}",
        backend
    );
    backend
}

/// Parse CGI response output into (status_code, headers, body).
fn parse_cgi_response(output: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    // Find the header/body boundary (\r\n\r\n or \n\n)
    let (header_end, body_start) =
        if let Some(pos) = output.windows(4).position(|w| w == b"\r\n\r\n") {
            (pos, pos + 4)
        } else if let Some(pos) = output.windows(2).position(|w| w == b"\n\n") {
            (pos, pos + 2)
        } else {
            // No body separator found — treat entire output as headers
            (output.len(), output.len())
        };

    let header_bytes = &output[..header_end];
    let body = output[body_start..].to_vec();

    let header_str = String::from_utf8_lossy(header_bytes);
    let mut status = 200u16;
    let mut headers = Vec::new();

    for line in header_str.lines() {
        if let Some(rest) = line.strip_prefix("Status:") {
            // e.g. "Status: 200 OK" or "Status: 404 Not Found"
            let rest = rest.trim();
            if let Some(code_str) = rest.split_whitespace().next() {
                if let Ok(code) = code_str.parse::<u16>() {
                    status = code;
                }
            }
        } else if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_string(), value.trim().to_string()));
        }
    }

    (status, headers, body)
}

/// Create an upstream handler that delegates to `git http-backend` CGI.
fn git_cgi_handler(backend_path: PathBuf, git_root: PathBuf) -> common::UpstreamHandler {
    std::sync::Arc::new(move |req: Request<Incoming>| {
        let backend_path = backend_path.clone();
        let git_root = git_root.clone();
        Box::pin(async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();
            let query = req.uri().query().unwrap_or("").to_string();
            let content_type = req
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let content_length = req
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            // Collect the request body
            let body_bytes = req.collect().await.unwrap().to_bytes();

            // Spawn git http-backend as CGI
            let mut cmd = std::process::Command::new(&backend_path);
            cmd.env("GIT_PROJECT_ROOT", &git_root)
                .env("GIT_HTTP_EXPORT_ALL", "1")
                .env("PATH_INFO", &path)
                .env("QUERY_STRING", &query)
                .env("REQUEST_METHOD", &method)
                .env("CONTENT_TYPE", &content_type)
                .env("SERVER_PROTOCOL", "HTTP/1.1")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            if !content_length.is_empty() {
                cmd.env("CONTENT_LENGTH", &content_length);
            }

            let mut child = cmd.spawn().expect("failed to spawn git http-backend");

            // Write request body to stdin
            if !body_bytes.is_empty() {
                use std::io::Write;
                let stdin = child.stdin.as_mut().unwrap();
                stdin.write_all(&body_bytes).unwrap();
            }
            // Drop stdin to signal EOF
            drop(child.stdin.take());

            let output = child.wait_with_output().expect("git http-backend failed");

            let (status, headers, body) = parse_cgi_response(&output.stdout);

            let mut builder = Response::builder().status(status);
            for (key, value) in &headers {
                builder = builder.header(key.as_str(), value.as_str());
            }

            Ok(builder
                .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                .unwrap())
        })
    })
}

/// Create a test git repo: a source repo with a commit, then a bare clone to serve.
/// Returns the path to the directory containing the bare repo (the GIT_PROJECT_ROOT).
fn create_test_repo(dir: &Path) -> PathBuf {
    let source_dir = dir.join("source");
    std::fs::create_dir_all(&source_dir).unwrap();

    // Initialize source repo and make a commit
    let run = |args: &[&str], cwd: &Path| {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    };

    run(&["init"], &source_dir);
    run(&["config", "user.email", "test@test.com"], &source_dir);
    run(&["config", "user.name", "Test User"], &source_dir);

    std::fs::write(
        source_dir.join("README.md"),
        "# Test Repository\nHello from git test!\n",
    )
    .unwrap();
    run(&["add", "README.md"], &source_dir);
    run(&["commit", "-m", "Initial commit"], &source_dir);

    // Create bare clone for serving
    let repos_dir = dir.join("repos");
    std::fs::create_dir_all(&repos_dir).unwrap();
    run(
        &[
            "clone",
            "--bare",
            source_dir.to_str().unwrap(),
            repos_dir.join("repo.git").to_str().unwrap(),
        ],
        dir,
    );

    repos_dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_clone_through_proxy() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Git clone through HTTPS proxy");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path());
    t.setup(format!("Created test git repo at {:?}", repos_dir));

    let upstream = TestUpstream::start_reported(
        &t,
        &ca,
        git_cgi_handler(backend_path, repos_dir),
        "git http-backend CGI",
    )
    .await;

    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![rule("*", "https://localhost/*")],
        upstream.port(),
    )
    .await;

    let clone_dir = tmp.path().join("cloned");

    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env(
                "HTTPS_PROXY",
                format!("http://127.0.0.1:{}", proxy.addr().port()),
            )
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );

    t.assert_eq("git clone exit code", &output.status.code().unwrap(), &0);
    t.assert_true(
        "cloned README.md exists",
        clone_dir.join("README.md").exists(),
    );

    let readme_content = std::fs::read_to_string(clone_dir.join("README.md")).unwrap();
    t.assert_contains("README content", &readme_content, "Hello from git test!");

    proxy.shutdown();
    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_git_push_through_proxy() {
    let backend_path = git_http_backend_path();

    let t = test_report!("Git push through HTTPS proxy");
    let ca = TestCa::generate();
    t.setup("Generated test CA");

    let tmp = TempDir::new().unwrap();
    let repos_dir = create_test_repo(tmp.path());
    t.setup(format!("Created test git repo at {:?}", repos_dir));

    // Enable receive-pack on the bare repo so pushes are accepted
    let bare_repo = repos_dir.join("repo.git");
    let run_git = |args: &[&str], cwd: &Path| {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run_git(&["config", "http.receivepack", "true"], &bare_repo);
    t.setup("Enabled http.receivepack on bare repo");

    let upstream = TestUpstream::start_reported(
        &t,
        &ca,
        git_cgi_handler(backend_path, repos_dir),
        "git http-backend CGI",
    )
    .await;

    let proxy = TestProxy::start_reported(
        &t,
        &ca,
        vec![rule("*", "https://localhost/*")],
        upstream.port(),
    )
    .await;

    let proxy_url = format!("http://127.0.0.1:{}", proxy.addr().port());

    // Step 1: Clone through proxy
    let clone_dir = tmp.path().join("cloned");
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args([
                "clone",
                "https://localhost/repo.git",
                clone_dir.to_str().unwrap(),
            ])
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git clone exit code", &output.status.code().unwrap(), &0);

    // Step 2: Make a new commit in the cloned repo
    std::fs::write(clone_dir.join("newfile.txt"), "pushed content\n").unwrap();
    run_git(&["add", "newfile.txt"], &clone_dir);
    run_git(&["commit", "-m", "Add newfile"], &clone_dir);
    t.action("Created new commit with newfile.txt");

    // Step 3: Push through proxy
    let output = run_command_reported(
        &t,
        std::process::Command::new("git")
            .args(["push"])
            .current_dir(&clone_dir)
            .env("HTTPS_PROXY", &proxy_url)
            .env("GIT_SSL_CAINFO", &ca.cert_path)
            .env("GIT_TERMINAL_PROMPT", "0"),
    );
    t.assert_eq("git push exit code", &output.status.code().unwrap(), &0);

    // Step 4: Verify the bare repo received the push
    let verify = std::process::Command::new("git")
        .args(["show", "HEAD:newfile.txt"])
        .current_dir(&bare_repo)
        .output()
        .unwrap();
    let content = String::from_utf8_lossy(&verify.stdout);
    t.assert_contains("bare repo has pushed file", &content, "pushed content");

    proxy.shutdown();
    upstream.shutdown();
}
