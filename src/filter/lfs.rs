//! Git-LFS batch request body inspection.

/// Check whether an LFS batch request body contains an allowed operation.
///
/// The LFS batch endpoint (`POST {repo}/info/lfs/objects/batch`) sends a JSON body
/// with an `"operation"` field that is either `"download"` or `"upload"`.
/// Returns `true` if the operation matches any of `allowed_operations`.
/// Returns `false` for invalid JSON, missing operation field, or non-string values.
pub fn check_lfs_operation(body: &[u8], allowed_operations: &[String]) -> bool {
    let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };

    let Some(operation) = parsed.get("operation").and_then(|v| v.as_str()) else {
        return false;
    };

    allowed_operations.iter().any(|op| op == operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyloros_test_support::test_report;

    #[test]
    fn test_download_allowed_by_download() {
        let t = test_report!("LFS download operation allowed when download is permitted");
        let body = br#"{"operation": "download", "objects": []}"#;
        let allowed = vec!["download".to_string()];
        t.assert_true("download allowed", check_lfs_operation(body, &allowed));
    }

    #[test]
    fn test_upload_blocked_by_download_only() {
        let t = test_report!("LFS upload operation blocked when only download is permitted");
        let body = br#"{"operation": "upload", "objects": []}"#;
        let allowed = vec!["download".to_string()];
        t.assert_true("upload blocked", !check_lfs_operation(body, &allowed));
    }

    #[test]
    fn test_upload_allowed_by_upload() {
        let t = test_report!("LFS upload operation allowed when upload is permitted");
        let body = br#"{"operation": "upload", "objects": []}"#;
        let allowed = vec!["upload".to_string()];
        t.assert_true("upload allowed", check_lfs_operation(body, &allowed));
    }

    #[test]
    fn test_download_blocked_by_upload_only() {
        let t = test_report!("LFS download operation blocked when only upload is permitted");
        let body = br#"{"operation": "download", "objects": []}"#;
        let allowed = vec!["upload".to_string()];
        t.assert_true("download blocked", !check_lfs_operation(body, &allowed));
    }

    #[test]
    fn test_both_operations_allowed() {
        let t = test_report!("LFS both operations allowed when both are permitted");
        let allowed = vec!["download".to_string(), "upload".to_string()];
        let dl = br#"{"operation": "download", "objects": []}"#;
        let ul = br#"{"operation": "upload", "objects": []}"#;
        t.assert_true("download allowed", check_lfs_operation(dl, &allowed));
        t.assert_true("upload allowed", check_lfs_operation(ul, &allowed));
    }

    #[test]
    fn test_invalid_json() {
        let t = test_report!("LFS invalid JSON body is rejected");
        let body = b"not valid json";
        let allowed = vec!["download".to_string(), "upload".to_string()];
        t.assert_true("invalid JSON blocked", !check_lfs_operation(body, &allowed));
    }

    #[test]
    fn test_missing_operation_field() {
        let t = test_report!("LFS body missing operation field is rejected");
        let body = br#"{"objects": []}"#;
        let allowed = vec!["download".to_string(), "upload".to_string()];
        t.assert_true(
            "missing operation blocked",
            !check_lfs_operation(body, &allowed),
        );
    }

    #[test]
    fn test_non_string_operation() {
        let t = test_report!("LFS non-string operation field is rejected");
        let body = br#"{"operation": 42, "objects": []}"#;
        let allowed = vec!["download".to_string(), "upload".to_string()];
        t.assert_true(
            "non-string operation blocked",
            !check_lfs_operation(body, &allowed),
        );
    }

    #[test]
    fn test_unknown_operation() {
        let t = test_report!("LFS unknown operation value is rejected");
        let body = br#"{"operation": "verify", "objects": []}"#;
        let allowed = vec!["download".to_string(), "upload".to_string()];
        t.assert_true(
            "unknown operation blocked",
            !check_lfs_operation(body, &allowed),
        );
    }
}
