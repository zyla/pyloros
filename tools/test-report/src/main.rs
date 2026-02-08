use pulldown_cmark::{html, Options, Parser};
use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::Path;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let report_dir = std::env::temp_dir().join(format!("test-report-{}", std::process::id()));
    std::fs::create_dir_all(&report_dir).expect("failed to create report dir");

    // Run cargo test with TEST_REPORT_DIR set
    let mut cmd = Command::new("cargo");
    cmd.arg("test").arg("--color=never");

    // Forward extra args (e.g. test filters)
    let extra_args: Vec<String> = std::env::args().skip(1).collect();
    for arg in &extra_args {
        cmd.arg(arg);
    }

    cmd.env("TEST_REPORT_DIR", &report_dir);

    let output = cmd.output().expect("failed to run cargo test");
    let test_exit_code = output.status.code().unwrap_or(1);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Print cargo test output so the user can see it
    eprint!("{}", stderr);
    print!("{}", stdout);

    // Parse cargo test stdout for test results (fallback for non-reporting tests)
    let cargo_results = parse_cargo_test_output(&stdout);

    // Read report files
    let report_files = read_report_files(&report_dir);

    // Merge: report files take precedence, cargo results fill gaps
    let grouped = merge_results(&report_files, &cargo_results);

    // Detect GitHub source link base URL
    let source_base_url = detect_github_source_base();

    // Generate markdown
    let (total_pass, total_fail, total_skip) = count_results(&grouped);
    let markdown = generate_markdown(&grouped, total_pass, total_fail, total_skip, &source_base_url);

    // Write markdown
    std::fs::write("test-report.md", &markdown).expect("failed to write test-report.md");

    // Generate HTML from markdown
    let html_content = render_html(&markdown);
    std::fs::write("test-report.html", html_content).expect("failed to write test-report.html");

    // Cleanup temp dir
    let _ = std::fs::remove_dir_all(&report_dir);

    if test_exit_code == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// Parse cargo test stdout
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CargoTestResult {
    name: String,
    passed: bool,
}

fn parse_cargo_test_output(stdout: &str) -> Vec<CargoTestResult> {
    let mut results = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("test ") && (line.ends_with("... ok") || line.ends_with("... FAILED")) {
            let rest = &line[5..]; // strip "test "
            let passed = rest.ends_with("... ok");
            let name = if passed {
                rest.trim_end_matches(" ... ok")
            } else {
                rest.trim_end_matches(" ... FAILED")
            };
            results.push(CargoTestResult {
                name: name.trim().to_string(),
                passed,
            });
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Read report files
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TestReportFile {
    group: String,
    name: String,
    title: String,
    source: Option<String>,
    steps: Vec<String>,
    result: String,
}

fn read_report_files(dir: &Path) -> Vec<TestReportFile> {
    let mut reports = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return reports,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "txt") {
            if let Some(report) = parse_report_file(&path) {
                reports.push(report);
            }
        }
    }
    reports
}

fn parse_report_file(path: &Path) -> Option<TestReportFile> {
    let file = std::fs::File::open(path).ok()?;
    let reader = std::io::BufReader::new(file);

    let mut group = String::new();
    let mut name = String::new();
    let mut title = String::new();
    let mut source = None;
    let mut steps = Vec::new();
    let mut result = String::new();

    for line in reader.lines().map_while(Result::ok) {
        if let Some(val) = line.strip_prefix("GROUP: ") {
            group = val.to_string();
        } else if let Some(val) = line.strip_prefix("NAME: ") {
            name = val.to_string();
        } else if let Some(val) = line.strip_prefix("TITLE: ") {
            title = val.to_string();
        } else if let Some(val) = line.strip_prefix("SOURCE: ") {
            source = Some(val.to_string());
        } else if let Some(val) = line.strip_prefix("STEP ") {
            steps.push(val.to_string());
        } else if let Some(val) = line.strip_prefix("RESULT: ") {
            result = val.to_string();
        }
    }

    if name.is_empty() {
        return None;
    }

    Some(TestReportFile {
        group,
        name,
        title,
        source,
        steps,
        result,
    })
}

// ---------------------------------------------------------------------------
// Merge results
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum TestEntry {
    Reported(TestReportFile),
    Unreported { name: String, passed: bool },
}

impl TestEntry {
    fn name(&self) -> &str {
        match self {
            TestEntry::Reported(r) => &r.name,
            TestEntry::Unreported { name, .. } => name,
        }
    }

    fn passed(&self) -> bool {
        match self {
            TestEntry::Reported(r) => r.result == "pass",
            TestEntry::Unreported { passed, .. } => *passed,
        }
    }

    fn skipped(&self) -> bool {
        match self {
            TestEntry::Reported(r) => r.result.starts_with("skip"),
            TestEntry::Unreported { .. } => false,
        }
    }

    fn skip_reason(&self) -> Option<&str> {
        match self {
            TestEntry::Reported(r) => r.result.strip_prefix("skip: "),
            TestEntry::Unreported { .. } => None,
        }
    }
}

fn merge_results(
    reports: &[TestReportFile],
    cargo_results: &[CargoTestResult],
) -> BTreeMap<String, Vec<TestEntry>> {
    let mut grouped: BTreeMap<String, Vec<TestEntry>> = BTreeMap::new();

    // Add all reported tests
    let mut reported_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for report in reports {
        reported_names.insert(report.name.clone());
        grouped
            .entry(report.group.clone())
            .or_default()
            .push(TestEntry::Reported(report.clone()));
    }

    // Add unreported tests from cargo output
    for result in cargo_results {
        // The cargo test name might be like "test_foo" or "module::test_foo"
        let test_name = result.name.rsplit("::").next().unwrap_or(&result.name);
        if reported_names.contains(test_name) {
            continue;
        }

        // Derive group from cargo test name
        let group = if result.name.contains("::") {
            let parts: Vec<&str> = result.name.split("::").collect();
            if parts.len() >= 2 {
                parts[parts.len() - 2].to_string()
            } else {
                "other".to_string()
            }
        } else {
            "other".to_string()
        };

        grouped
            .entry(group)
            .or_default()
            .push(TestEntry::Unreported {
                name: test_name.to_string(),
                passed: result.passed,
            });
    }

    // Sort entries within each group by name
    for entries in grouped.values_mut() {
        entries.sort_by(|a, b| a.name().cmp(b.name()));
    }

    grouped
}

// ---------------------------------------------------------------------------
// Count results
// ---------------------------------------------------------------------------

fn count_results(grouped: &BTreeMap<String, Vec<TestEntry>>) -> (usize, usize, usize) {
    let mut pass = 0;
    let mut fail = 0;
    let mut skip = 0;
    for entries in grouped.values() {
        for entry in entries {
            if entry.skipped() {
                skip += 1;
            } else if entry.passed() {
                pass += 1;
            } else {
                fail += 1;
            }
        }
    }
    (pass, fail, skip)
}

// ---------------------------------------------------------------------------
// Generate markdown
// ---------------------------------------------------------------------------

fn group_display_name(group: &str) -> String {
    // Convert "proxy_basic_test" to "Proxy Basic"
    let name = group
        .trim_end_matches("_test")
        .trim_end_matches("_tests");
    name.split('_')
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().to_string() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Detect GitHub repo URL and current commit to build source links.
/// Returns a base like "https://github.com/user/repo/blob/abc123" or None.
fn detect_github_source_base() -> Option<String> {
    let remote = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()?;
    if !remote.status.success() {
        return None;
    }
    let url = String::from_utf8_lossy(&remote.stdout).trim().to_string();

    // Convert git@github.com:user/repo.git or https://github.com/user/repo.git to https://github.com/user/repo
    let repo_url = if let Some(rest) = url.strip_prefix("git@github.com:") {
        format!(
            "https://github.com/{}",
            rest.trim_end_matches(".git")
        )
    } else if url.starts_with("https://github.com/") {
        url.trim_end_matches(".git").to_string()
    } else {
        return None;
    };

    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !commit.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&commit.stdout).trim().to_string();

    Some(format!("{}/blob/{}", repo_url, sha))
}

/// Extract the label from an assertion message (text before the first `: `).
fn extract_label(msg: &str) -> &str {
    msg.split_once(": ").map(|(label, _)| label).unwrap_or(msg)
}

/// Render a step line, using a collapsible `<details>` block for long lines.
fn render_step(md: &mut String, prefix: &str, icon: &str, msg: &str) {
    let line = if icon.is_empty() {
        format!("- {}{}", prefix, msg)
    } else {
        format!("- {} {}", icon, msg)
    };

    if line.len() < 150 {
        md.push_str(&line);
        md.push('\n');
    } else {
        let label = extract_label(msg);
        let summary_text = if icon.is_empty() {
            format!("{}{}", prefix, label)
        } else {
            format!("{} {}", icon, label)
        };
        md.push_str(&format!(
            "<details>\n<summary>{}</summary>\n\n{}\n\n</details>\n",
            summary_text, msg
        ));
    }
}

fn generate_markdown(
    grouped: &BTreeMap<String, Vec<TestEntry>>,
    total_pass: usize,
    total_fail: usize,
    total_skip: usize,
    source_base_url: &Option<String>,
) -> String {
    let mut md = String::new();
    let now = chrono_like_now();

    md.push_str("# Test Report\n\n");

    let mut summary = format!("Generated: {} | **{} passed**", now, total_pass);
    if total_fail > 0 {
        summary.push_str(&format!(", **{} failed**", total_fail));
    } else {
        summary.push_str(", 0 failed");
    }
    if total_skip > 0 {
        summary.push_str(&format!(", {} skipped", total_skip));
    }
    summary.push_str("\n\n");
    md.push_str(&summary);

    for (group, entries) in grouped {
        let group_pass = entries.iter().filter(|e| e.passed()).count();
        let group_skip = entries.iter().filter(|e| e.skipped()).count();
        let group_total = entries.len();
        let display = group_display_name(group);

        let mut group_summary = format!(
            "## {} ({}) \u{2014} {} tests, {} passed",
            display, group, group_total, group_pass
        );
        if group_skip > 0 {
            group_summary.push_str(&format!(", {} skipped", group_skip));
        }
        group_summary.push_str("\n\n");
        md.push_str(&group_summary);

        for entry in entries {
            match entry {
                TestEntry::Reported(report) => {
                    let icon = if entry.skipped() {
                        "\u{23ed}\u{fe0f}"
                    } else if report.result == "pass" {
                        "\u{2705}"
                    } else {
                        "\u{274c}"
                    };
                    md.push_str(&format!("### {} {}\n", icon, report.name));

                    // Title + source link
                    let source_link = report.source.as_ref().and_then(|s| {
                        let base = source_base_url.as_ref()?;
                        // source is "file:line" e.g. "tests/proxy_basic_test.rs:12"
                        let (file, line) = s.split_once(':')?;
                        Some(format!("[source]({}/{}#L{})", base, file, line))
                    });

                    match (&report.title, &source_link) {
                        (title, Some(link)) if !title.is_empty() => {
                            md.push_str(&format!("**{}** \u{00b7} {}\n", title, link));
                        }
                        (title, None) if !title.is_empty() => {
                            md.push_str(&format!("**{}**\n", title));
                        }
                        (_, Some(link)) => {
                            md.push_str(&format!("{}\n", link));
                        }
                        _ => {}
                    }

                    // Show skip reason if skipped
                    if let Some(reason) = entry.skip_reason() {
                        md.push_str(&format!("*Skipped: {}*\n", reason));
                    }

                    for step in &report.steps {
                        if let Some(msg) = step.strip_prefix("setup: ") {
                            render_step(&mut md, "Setup: ", "", msg);
                        } else if let Some(msg) = step.strip_prefix("action: ") {
                            render_step(&mut md, "Action: ", "", msg);
                        } else if let Some(msg) = step.strip_prefix("assert_pass: ") {
                            render_step(&mut md, "", "\u{2705}", msg);
                        } else if let Some(msg) = step.strip_prefix("assert_fail: ") {
                            render_step(&mut md, "", "\u{274c}", msg);
                        }
                    }
                    md.push('\n');
                }
                TestEntry::Unreported { name, passed } => {
                    let icon = if *passed { "\u{2705}" } else { "\u{274c}" };
                    md.push_str(&format!("### {} {}\n\n", icon, name));
                }
            }
        }
    }

    md
}

fn chrono_like_now() -> String {
    // Simple timestamp without chrono dependency
    let output = Command::new("date")
        .arg("+%Y-%m-%d %H:%M:%S")
        .output()
        .ok();
    match output {
        Some(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        }
        _ => "unknown".to_string(),
    }
}

// ---------------------------------------------------------------------------
// HTML rendering
// ---------------------------------------------------------------------------

fn render_html(markdown: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);

    let parser = Parser::new_ext(markdown, options);
    let mut html_body = String::new();
    html::push_html(&mut html_body, parser);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Test Report</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    max-width: 900px;
    margin: 0 auto;
    padding: 2rem;
    line-height: 1.6;
    color: #333;
    background: #fafafa;
  }}
  h1 {{
    border-bottom: 2px solid #ddd;
    padding-bottom: 0.5rem;
  }}
  h2 {{
    margin-top: 2rem;
    color: #555;
    cursor: pointer;
    user-select: none;
  }}
  h2:hover {{
    color: #222;
  }}
  h3 {{
    margin-top: 1rem;
    margin-bottom: 0.25rem;
    font-size: 1rem;
  }}
  ul {{
    margin-top: 0.25rem;
    padding-left: 1.5rem;
  }}
  li {{
    margin-bottom: 0.15rem;
  }}
  code {{
    background: #e8e8e8;
    padding: 0.1rem 0.3rem;
    border-radius: 3px;
    font-size: 0.9em;
  }}
  details {{
    margin-bottom: 0.15rem;
    margin-left: 1.5rem;
  }}
  details summary {{
    cursor: pointer;
    list-style: none;
  }}
  details summary::before {{
    content: '\25b6  ';
    font-size: 0.7em;
    margin-right: 0.3em;
  }}
  details[open] summary::before {{
    content: '\25bc  ';
  }}
  details > p {{
    margin: 0.5rem 0;
    padding-left: 1rem;
    font-size: 0.9em;
    word-break: break-all;
  }}
  .group-content {{
    overflow: hidden;
    transition: max-height 0.3s ease;
  }}
  .group-content.collapsed {{
    max-height: 0 !important;
  }}
</style>
</head>
<body>
{html_body}
<script>
  document.querySelectorAll('h2').forEach(h2 => {{
    const content = [];
    let next = h2.nextElementSibling;
    while (next && next.tagName !== 'H2' && next.tagName !== 'H1') {{
      content.push(next);
      next = next.nextElementSibling;
    }}
    const wrapper = document.createElement('div');
    wrapper.className = 'group-content';
    h2.after(wrapper);
    content.forEach(el => wrapper.appendChild(el));

    h2.addEventListener('click', () => {{
      wrapper.classList.toggle('collapsed');
    }});
  }});
</script>
</body>
</html>"#
    )
}
