//! Git pkt-line format parser for branch restriction enforcement.
//!
//! The git push protocol sends ref update commands in pkt-line format before
//! the pack data. Each command line has the form:
//!
//! ```text
//! <old-sha> <new-sha> <refname>\0<capabilities>\n   (first line)
//! <old-sha> <new-sha> <refname>\n                   (subsequent lines)
//! ```
//!
//! Lines are prefixed with a 4-hex-digit length. The sequence ends with a
//! flush packet (`0000`). We only need to read the pkt-line prefix to extract
//! ref names for branch checking.

use super::matcher::PatternMatcher;

/// Extract ref names from git push pkt-line data.
///
/// Reads pkt-lines until the flush packet (`0000`), parsing each command
/// line to extract the ref name (third space-separated field, before any
/// NUL-delimited capabilities).
///
/// Returns the list of ref names being pushed (e.g. `refs/heads/main`).
pub fn extract_push_refs(data: &[u8]) -> Vec<String> {
    let mut refs = Vec::new();
    let mut pos = 0;

    while pos + 4 <= data.len() {
        // Read 4-hex-digit length
        let len_str = match std::str::from_utf8(&data[pos..pos + 4]) {
            Ok(s) => s,
            Err(_) => break,
        };

        // Flush packet
        if len_str == "0000" {
            break;
        }

        let pkt_len = match usize::from_str_radix(len_str, 16) {
            Ok(n) => n,
            Err(_) => break,
        };

        if pkt_len < 4 || pos + pkt_len > data.len() {
            break;
        }

        // The pkt-line content (excluding the 4-byte length prefix)
        let content = &data[pos + 4..pos + pkt_len];

        // Parse: "<old-sha> <new-sha> <refname>[\0capabilities][\n]"
        if let Some(refname) = parse_ref_from_command(content) {
            refs.push(refname);
        }

        pos += pkt_len;
    }

    refs
}

/// Parse a single command line to extract the ref name.
fn parse_ref_from_command(content: &[u8]) -> Option<String> {
    // Strip trailing newline if present
    let content = if content.last() == Some(&b'\n') {
        &content[..content.len() - 1]
    } else {
        content
    };

    // Convert to string (command lines are ASCII)
    let line = std::str::from_utf8(content).ok()?;

    // Strip capabilities after NUL
    let line = line.split('\0').next().unwrap_or(line);

    // Split by spaces: old-sha, new-sha, refname
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() == 3 {
        Some(parts[2].to_string())
    } else {
        None
    }
}

/// Check if all push refs match the given branch patterns.
///
/// - Bare patterns (not starting with `refs/`) match against `refs/heads/<pattern>`.
/// - Patterns starting with `refs/` are matched literally.
/// - Returns `true` if all refs are allowed, `false` if any ref is disallowed.
/// - If no refs are found in the data, returns `true` (nothing to block).
pub fn check_push_branches(data: &[u8], patterns: &[PatternMatcher]) -> bool {
    let refs = extract_push_refs(data);
    if refs.is_empty() {
        return true;
    }

    for refname in &refs {
        if !ref_matches_any_pattern(refname, patterns) {
            return false;
        }
    }

    true
}

/// Check if a single ref matches any of the given branch patterns.
fn ref_matches_any_pattern(refname: &str, patterns: &[PatternMatcher]) -> bool {
    for pattern in patterns {
        let pat = pattern.pattern();
        if pat.starts_with("refs/") {
            // Literal ref pattern — match directly
            if pattern.matches(refname) {
                return true;
            }
        } else {
            // Bare branch pattern — match against refs/heads/<pattern>
            let full_ref = format!(
                "refs/heads/{}",
                refname.strip_prefix("refs/heads/").unwrap_or(refname)
            );
            let full_pattern = format!("refs/heads/{}", pat);
            // We need to create a temporary PatternMatcher for the full pattern
            if let Ok(full_matcher) = PatternMatcher::new(&full_pattern) {
                if full_matcher.matches(&full_ref) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_report;

    /// Build a pkt-line from a string (adds 4-hex-digit length prefix).
    fn pktline(content: &str) -> Vec<u8> {
        let len = content.len() + 4; // content + 4-byte length prefix
        format!("{:04x}{}", len, content).into_bytes()
    }

    /// Flush packet.
    fn flush() -> Vec<u8> {
        b"0000".to_vec()
    }

    #[test]
    fn test_extract_single_ref() {
        let t = test_report!("Extract single ref from push data");
        let mut data = Vec::new();
        data.extend(pktline(
            "0000000000000000000000000000000000000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/main\n",
        ));
        data.extend(flush());

        let refs = extract_push_refs(&data);
        t.assert_eq("ref count", &refs.len(), &1usize);
        t.assert_eq("ref name", &refs[0].as_str(), &"refs/heads/main");
    }

    #[test]
    fn test_extract_multiple_refs() {
        let t = test_report!("Extract multiple refs from push data");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!(
            "{} {} refs/heads/main\0report-status\n",
            old, new
        )));
        data.extend(pktline(&format!(
            "{} {} refs/heads/feature/test\n",
            old, new
        )));
        data.extend(flush());

        let refs = extract_push_refs(&data);
        t.assert_eq("ref count", &refs.len(), &2usize);
        t.assert_eq("ref[0]", &refs[0].as_str(), &"refs/heads/main");
        t.assert_eq("ref[1]", &refs[1].as_str(), &"refs/heads/feature/test");
    }

    #[test]
    fn test_extract_ref_with_capabilities() {
        let t = test_report!("Capabilities stripped from first pkt-line");
        let mut data = Vec::new();
        data.extend(pktline(
            "0000000000000000000000000000000000000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/dev\0report-status delete-refs ofs-delta\n",
        ));
        data.extend(flush());

        let refs = extract_push_refs(&data);
        t.assert_eq("ref count", &refs.len(), &1usize);
        t.assert_eq("ref name", &refs[0].as_str(), &"refs/heads/dev");
    }

    #[test]
    fn test_extract_empty_data() {
        let t = test_report!("Empty data returns no refs");
        let refs = extract_push_refs(b"0000");
        t.assert_eq("ref count", &refs.len(), &0usize);
    }

    #[test]
    fn test_extract_flush_only() {
        let t = test_report!("Flush-only data returns no refs");
        let refs = extract_push_refs(b"0000");
        t.assert_eq("ref count", &refs.len(), &0usize);
    }

    #[test]
    fn test_check_branches_allowed() {
        let t = test_report!("Branch check allows matching refs");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!(
            "{} {} refs/heads/feature/test\n",
            old, new
        )));
        data.extend(flush());

        let patterns = vec![PatternMatcher::new("feature/*").unwrap()];
        t.assert_true(
            "feature/test allowed",
            check_push_branches(&data, &patterns),
        );
    }

    #[test]
    fn test_check_branches_blocked() {
        let t = test_report!("Branch check blocks non-matching refs");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!("{} {} refs/heads/main\n", old, new)));
        data.extend(flush());

        let patterns = vec![PatternMatcher::new("feature/*").unwrap()];
        t.assert_true("main blocked", !check_push_branches(&data, &patterns));
    }

    #[test]
    fn test_check_branches_mixed_blocked() {
        let t = test_report!("Branch check blocks when any ref is disallowed");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!(
            "{} {} refs/heads/feature/ok\0report-status\n",
            old, new
        )));
        data.extend(pktline(&format!("{} {} refs/heads/main\n", old, new)));
        data.extend(flush());

        let patterns = vec![PatternMatcher::new("feature/*").unwrap()];
        t.assert_true(
            "mixed refs blocked (main not allowed)",
            !check_push_branches(&data, &patterns),
        );
    }

    #[test]
    fn test_check_branches_tag_blocked() {
        let t = test_report!("Tags blocked when only branch patterns specified");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!("{} {} refs/tags/v1.0\n", old, new)));
        data.extend(flush());

        let patterns = vec![PatternMatcher::new("feature/*").unwrap()];
        t.assert_true("tag blocked", !check_push_branches(&data, &patterns));
    }

    #[test]
    fn test_check_branches_refs_prefix_pattern() {
        let t = test_report!("refs/ prefixed pattern matches literally");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!("{} {} refs/tags/v1.0\n", old, new)));
        data.extend(flush());

        let patterns = vec![PatternMatcher::new("refs/tags/*").unwrap()];
        t.assert_true(
            "tag allowed by refs/ pattern",
            check_push_branches(&data, &patterns),
        );
    }

    #[test]
    fn test_check_branches_empty_data() {
        let t = test_report!("Empty push data passes branch check");
        let patterns = vec![PatternMatcher::new("feature/*").unwrap()];
        t.assert_true(
            "empty data allowed",
            check_push_branches(b"0000", &patterns),
        );
    }

    #[test]
    fn test_check_branches_multiple_patterns() {
        let t = test_report!("Multiple branch patterns (OR matching)");
        let old = "0000000000000000000000000000000000000000";
        let new = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut data = Vec::new();
        data.extend(pktline(&format!(
            "{} {} refs/heads/fix/bug-123\n",
            old, new
        )));
        data.extend(flush());

        let patterns = vec![
            PatternMatcher::new("feature/*").unwrap(),
            PatternMatcher::new("fix/*").unwrap(),
        ];
        t.assert_true(
            "fix/ matches second pattern",
            check_push_branches(&data, &patterns),
        );
    }
}
