//! Test report infrastructure for unit tests.
//!
//! This module provides TestReport for recording test steps and writing
//! structured report files consumed by the test-report generator tool.
//! Only compiled during test builds (`#[cfg(test)]`).

use std::fmt::{Debug, Display};
use std::path::PathBuf;
use std::sync::Mutex;

/// Auto-detect the test name from the calling function.
/// Works for both sync and async test functions.
#[macro_export]
macro_rules! test_report {
    ($title:expr) => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        // Strip "::f" suffix
        let name = &name[..name.len() - 3];
        // In async fns, the path ends with "::{{closure}}" — strip that too
        let name = name.strip_suffix("::{{closure}}").unwrap_or(name);
        $crate::test_support::TestReport::new(name, $title, file!(), line!())
    }};
}

enum Step {
    Setup(String),
    Action(String),
    AssertPass(String),
    AssertFail(String),
    Output { label: String, text: String },
}

impl Step {
    fn to_report_line(&self) -> String {
        match self {
            Step::Setup(msg) => format!("STEP setup: {}", msg),
            Step::Action(msg) => format!("STEP action: {}", msg),
            Step::AssertPass(msg) => format!("STEP assert_pass: {}", msg),
            Step::AssertFail(msg) => format!("STEP assert_fail: {}", msg),
            Step::Output { label, text } => format!("STEP output {}: {:?}", label, text),
        }
    }
}

pub struct TestReport {
    full_path: String,
    title: String,
    steps: Mutex<Vec<Step>>,
    report_dir: Option<PathBuf>,
    source_file: String,
    source_line: u32,
    skipped: Mutex<Option<String>>,
}

impl TestReport {
    pub fn new(full_path: &str, title: &str, source_file: &str, source_line: u32) -> Self {
        let report_dir = std::env::var("TEST_REPORT_DIR").ok().map(PathBuf::from);
        Self {
            full_path: full_path.to_string(),
            title: title.to_string(),
            steps: Mutex::new(Vec::new()),
            report_dir,
            source_file: source_file.to_string(),
            source_line,
            skipped: Mutex::new(None),
        }
    }

    /// Mark this test as skipped with a reason. Call before returning early.
    #[allow(dead_code)]
    pub fn skip(&self, reason: impl Display) {
        *self.skipped.lock().unwrap() = Some(reason.to_string());
    }

    /// Format a Debug-formatted value for report display.
    /// Wraps in backticks. Truncates at `max_len` chars to prevent huge report files.
    fn truncate_for_display(debug_str: &str, max_len: usize) -> String {
        if debug_str.len() <= max_len {
            format!("`{}`", debug_str)
        } else {
            format!("`{}…` ({} bytes)", &debug_str[..max_len], debug_str.len())
        }
    }

    #[allow(dead_code)]
    pub fn setup(&self, msg: impl Display) {
        self.steps
            .lock()
            .unwrap()
            .push(Step::Setup(msg.to_string()));
    }

    #[allow(dead_code)]
    pub fn action(&self, msg: impl Display) {
        self.steps
            .lock()
            .unwrap()
            .push(Step::Action(msg.to_string()));
    }

    #[allow(dead_code)]
    pub fn output(&self, label: &str, text: &str) {
        self.steps.lock().unwrap().push(Step::Output {
            label: label.to_string(),
            text: text.to_string(),
        });
    }

    pub fn assert_eq<A, E>(&self, label: &str, actual: &A, expected: &E)
    where
        A: PartialEq<E> + Debug,
        E: Debug,
    {
        let pass = actual == expected;
        let actual_s = Self::truncate_for_display(&format!("{:?}", actual), 1000);
        let expected_s = Self::truncate_for_display(&format!("{:?}", expected), 1000);
        let msg = format!("{}: {} == {}", label, actual_s, expected_s);
        self.steps.lock().unwrap().push(if pass {
            Step::AssertPass(msg)
        } else {
            Step::AssertFail(msg.clone())
        });
        assert_eq!(actual, expected, "{}", label);
    }

    #[allow(dead_code)]
    pub fn assert_contains(&self, label: &str, haystack: &str, needle: &str) {
        let pass = haystack.contains(needle);
        let haystack_s = Self::truncate_for_display(&format!("{:?}", haystack), 1000);
        let needle_s = Self::truncate_for_display(&format!("{:?}", needle), 1000);
        let msg = format!("{}: {} contains {}", label, haystack_s, needle_s);
        self.steps.lock().unwrap().push(if pass {
            Step::AssertPass(msg)
        } else {
            Step::AssertFail(msg.clone())
        });
        assert!(
            pass,
            "{}: {:?} does not contain {:?}",
            label, haystack, needle
        );
    }

    #[allow(dead_code)]
    pub fn assert_starts_with(&self, label: &str, value: &str, prefix: &str) {
        let pass = value.starts_with(prefix);
        let value_s = Self::truncate_for_display(&format!("{:?}", value), 1000);
        let prefix_s = Self::truncate_for_display(&format!("{:?}", prefix), 1000);
        let msg = format!("{}: {} starts with {}", label, value_s, prefix_s);
        self.steps.lock().unwrap().push(if pass {
            Step::AssertPass(msg)
        } else {
            Step::AssertFail(msg.clone())
        });
        assert!(
            pass,
            "{}: {:?} does not start with {:?}",
            label, value, prefix
        );
    }

    pub fn assert_true(&self, label: &str, value: bool) {
        let msg = format!("{}: `{}`", label, value);
        self.steps.lock().unwrap().push(if value {
            Step::AssertPass(msg)
        } else {
            Step::AssertFail(msg.clone())
        });
        assert!(value, "{}", label);
    }

    /// Extract the group name (test file module) from the full path.
    fn group(&self) -> &str {
        let parts: Vec<&str> = self.full_path.split("::").collect();
        if parts.len() >= 2 {
            parts[parts.len() - 2]
        } else {
            &self.full_path
        }
    }

    /// Extract the test name (last segment) from the full path.
    fn name(&self) -> &str {
        self.full_path
            .rsplit("::")
            .next()
            .unwrap_or(&self.full_path)
    }

    fn write_report(&self) {
        let Some(dir) = &self.report_dir else {
            return;
        };

        let skip_reason = self.skipped.lock().unwrap().clone();
        let result = if let Some(reason) = &skip_reason {
            format!("skip: {}", reason)
        } else if std::thread::panicking() {
            "fail".to_string()
        } else {
            "pass".to_string()
        };

        let steps = self.steps.lock().unwrap();
        let mut lines = Vec::new();
        lines.push(format!("GROUP: {}", self.group()));
        lines.push(format!("NAME: {}", self.name()));
        lines.push(format!("TITLE: {}", self.title));
        lines.push(format!("SOURCE: {}:{}", self.source_file, self.source_line));
        for step in steps.iter() {
            lines.push(step.to_report_line());
        }
        lines.push(format!("RESULT: {}", result));
        lines.push(String::new());

        let sanitized = self.full_path.replace("::", "__");
        let path = dir.join(format!("{}.txt", sanitized));
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(path, lines.join("\n"));
    }
}

impl Drop for TestReport {
    fn drop(&mut self) {
        self.write_report();
    }
}
