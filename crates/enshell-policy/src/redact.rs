//! Conservative secret-redaction utilities for audit logs and model-context capture.
//!
//! # Purpose
//!
//! Before an `AuditRecord` (or similar) is persisted, callers should run
//! user-supplied text through [`redact_text`] and JSON values through
//! [`redact_value`]. This replaces secret-looking substrings with the marker
//! `«redacted»`.
//!
//! # Design philosophy
//!
//! This module is **best-effort, not a security guarantee**. It uses simple
//! string-scanning heuristics — no regex crate — and is deliberately
//! conservative: it prefers to *miss* an exotic secret pattern rather than
//! mangle normal inputs such as file paths, port numbers, or prose.
//!
//! Specifically it does NOT redact:
//! - Filesystem paths (`/Users/me/Downloads`, `./notes.txt`)
//! - Port references (`port 3000`)
//! - Normal prose / URLs (`https://example.com/page`)
//! - Short tokens that happen to start with a sensitive prefix (min-length
//!   guards prevent false positives on common words like "skip-" or "pwd")
//!
//! # Replacement marker
//!
//! Redacted spans are replaced with `«redacted»` (U+00AB / U+00BB angle
//! quotation marks), which is visually distinctive and unlikely to appear in
//! normal input.

use serde_json::Value;

/// The replacement string inserted in place of each detected secret span.
const MARKER: &str = "\u{ab}redacted\u{bb}";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Redact secret-looking substrings from `input`.
///
/// Returns `(redacted_string, redaction_count)`. Each detected secret span is
/// replaced with `«redacted»`.  When no secrets are detected the original
/// string is returned unchanged and the count is `0`.
///
/// See the [module-level docs](self) for the list of detected patterns and
/// false-positive avoidance guarantees.
pub fn redact_text(input: &str) -> (String, u32) {
    let mut count = 0u32;

    // Apply detectors in order of specificity.  Each detector operates on
    // the progressively-redacted string so that a later detector does not
    // re-examine already-redacted spans.
    let mut s = input.to_owned();

    // 1. Private-key PEM blocks (done first because they span many characters)
    let (s2, n) = redact_pem_blocks(&s);
    s = s2;
    count += n;

    // 2. key=value / key: value patterns
    let (s3, n) = redact_key_value(&s);
    s = s3;
    count += n;

    // 3. Prefixed token patterns (token-level scan)
    let (s4, n) = redact_prefixed_tokens(&s);
    s = s4;
    count += n;

    (s, count)
}

/// Walk a JSON value in place, redacting secret-looking content in every
/// string leaf. Object values and array elements are visited recursively.
/// Non-string leaves (numbers, bools, null) are untouched.
///
/// Returns the total number of redactions performed across all leaves.
pub fn redact_value(value: &mut Value) -> u32 {
    match value {
        Value::String(s) => {
            let (redacted, count) = redact_text(s);
            *s = redacted;
            count
        }
        Value::Array(arr) => arr.iter_mut().map(redact_value).sum(),
        Value::Object(map) => map.values_mut().map(redact_value).sum(),
        // Numbers, bools, null — untouched
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Detector 1: PEM private-key blocks
// ---------------------------------------------------------------------------

/// Redact `-----BEGIN ... PRIVATE KEY-----` … `-----END ... PRIVATE KEY-----`
/// blocks (including the headers themselves).
///
/// Strategy: scan for `-----BEGIN`; verify the rest of that line contains
/// `PRIVATE KEY-----`; then find the corresponding `-----END ... PRIVATE KEY-----`
/// closing line and redact everything from the BEGIN up to and including the END.
fn redact_pem_blocks(input: &str) -> (String, u32) {
    const BEGIN: &str = "-----BEGIN";
    const END: &str = "-----END";
    const PRIVATE_KEY_CLOSE: &str = "PRIVATE KEY-----";

    let mut result = String::with_capacity(input.len());
    let mut remaining = input;
    let mut count = 0u32;

    while let Some(begin_pos) = remaining.find(BEGIN) {
        // Check the begin line contains "PRIVATE KEY-----"
        let after_begin_keyword = &remaining[begin_pos + BEGIN.len()..];

        // Find end of this line to confirm it's a PRIVATE KEY header
        let line_end = after_begin_keyword
            .find('\n')
            .unwrap_or(after_begin_keyword.len());
        let begin_line_rest = &after_begin_keyword[..line_end];

        if !begin_line_rest.contains(PRIVATE_KEY_CLOSE) {
            // Not a private key block — skip past this BEGIN
            result.push_str(&remaining[..begin_pos + BEGIN.len()]);
            remaining = &remaining[begin_pos + BEGIN.len()..];
            continue;
        }

        // We have a BEGIN ... PRIVATE KEY----- header.
        // Now find the matching END ... PRIVATE KEY-----
        let search_from = begin_pos + BEGIN.len() + line_end;
        let after_header = &remaining[search_from..];

        // Find "-----END" followed (somewhere on same line) by "PRIVATE KEY-----"
        let mut found_end: Option<usize> = None;
        let mut scan = after_header;
        let mut scan_offset = 0usize;
        while let Some(end_rel) = scan.find(END) {
            let abs_end_pos = search_from + scan_offset + end_rel;
            let after_end_keyword = &remaining[abs_end_pos + END.len()..];
            let end_line_end = after_end_keyword
                .find('\n')
                .unwrap_or(after_end_keyword.len());
            let end_line_rest = &after_end_keyword[..end_line_end];
            if end_line_rest.contains(PRIVATE_KEY_CLOSE) {
                // Found closing line; consume through end of that line
                let close_abs = abs_end_pos + END.len() + end_line_end;
                found_end = Some(close_abs);
                break;
            }
            // Advance past this "-----END" that wasn't a match
            scan_offset += end_rel + END.len();
            scan = &after_header[scan_offset..];
        }

        if let Some(end_abs) = found_end {
            result.push_str(&remaining[..begin_pos]);
            result.push_str(MARKER);
            count += 1;
            remaining = &remaining[end_abs..];
        } else {
            // No matching END — leave the rest untouched
            break;
        }
    }
    result.push_str(remaining);
    (result, count)
}

// ---------------------------------------------------------------------------
// Detector 2: key=value / key: value
// ---------------------------------------------------------------------------

/// Sensitive key names that trigger value redaction.
/// All comparisons are case-insensitive.
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "secret_key",
    "private_key",
    "client_secret",
    "authorization",
    "auth_token",
];

/// Scan for `<sensitive_key><sep><value>` patterns where sep is `=` or `:`
/// optionally surrounded by spaces, and redact the value.
///
/// The key is preserved; only the value run (up to next whitespace) is
/// replaced.
fn redact_key_value(input: &str) -> (String, u32) {
    let lower = input.to_lowercase();
    let bytes = input.as_bytes();
    let mut count = 0u32;

    // Build a list of (start, end) byte ranges to redact (the value spans)
    let mut spans: Vec<(usize, usize)> = Vec::new();

    for key in SENSITIVE_KEYS {
        let key_lower = key.to_lowercase();
        let key_len = key_lower.len();
        let mut search_start = 0usize;

        while search_start < lower.len() {
            let Some(key_pos) = lower[search_start..].find(key_lower.as_str()) else {
                break;
            };
            let abs_key_pos = search_start + key_pos;

            // Ensure the match is a whole "word" — the character before the key
            // (if any) must not be alphanumeric or '_' or '-'.
            if abs_key_pos > 0 {
                let prev = lower.as_bytes()[abs_key_pos - 1] as char;
                if prev.is_alphanumeric() || prev == '_' || prev == '-' {
                    // Part of a longer identifier — skip
                    search_start = abs_key_pos + 1;
                    continue;
                }
            }

            let after_key = abs_key_pos + key_len;

            // Skip optional spaces
            let mut cursor = after_key;
            while cursor < bytes.len() && bytes[cursor] == b' ' {
                cursor += 1;
            }

            // Expect `=` or `:`
            if cursor >= bytes.len() || (bytes[cursor] != b'=' && bytes[cursor] != b':') {
                search_start = abs_key_pos + 1;
                continue;
            }
            cursor += 1; // consume `=` or `:`

            // Skip optional spaces after separator
            while cursor < bytes.len() && bytes[cursor] == b' ' {
                cursor += 1;
            }

            // The value runs to the next whitespace (or end of string).
            // If the value is empty, skip (don't redact empty strings).
            let value_start = cursor;
            while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            let value_end = cursor;

            if value_end > value_start {
                spans.push((value_start, value_end));
                count += 1;
            }

            search_start = abs_key_pos + 1;
        }
    }

    if spans.is_empty() {
        return (input.to_owned(), 0);
    }

    // Merge overlapping spans and build the output string
    spans.sort_unstable_by_key(|&(s, _)| s);
    let merged = merge_spans(spans);

    let mut result = String::with_capacity(input.len());
    let mut pos = 0usize;
    for (start, end) in &merged {
        result.push_str(&input[pos..*start]);
        result.push_str(MARKER);
        pos = *end;
    }
    result.push_str(&input[pos..]);
    (result, count)
}

// ---------------------------------------------------------------------------
// Detector 3: prefixed tokens
// ---------------------------------------------------------------------------

/// Check if `token` (already stripped of surrounding punctuation) is a
/// recognisable secret.  Returns `true` if it should be redacted.
fn is_secret_token(token: &str) -> bool {
    let len = token.len();

    // GitHub personal access token prefixes
    const GH_PREFIXES: &[&str] = &["ghp_", "gho_", "ghs_", "ghr_", "github_pat_"];
    for prefix in GH_PREFIXES {
        if token.starts_with(prefix) && len >= 20 {
            return true;
        }
    }

    // Slack bot/user/app token prefixes
    const SLACK_PREFIXES: &[&str] = &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"];
    for prefix in SLACK_PREFIXES {
        if token.starts_with(prefix) {
            return true;
        }
    }

    // AWS access key id: AKIA followed by exactly 16 uppercase alphanumerics
    if token.starts_with("AKIA") && token.len() >= 20 {
        let suffix = &token[4..];
        // Must be exactly 16 chars of [A-Z0-9]
        if suffix.len() >= 16
            && suffix[..16]
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            return true;
        }
    }

    // Google API key: AIza + ≥ 30 more chars
    if token.starts_with("AIza") && len >= 34 {
        return true;
    }

    // OpenAI-style: sk- with total len ≥ 20
    if token.starts_with("sk-") && len >= 20 {
        return true;
    }

    // JWT: eyJ + len ≥ 20 + contains a dot
    if token.starts_with("eyJ") && len >= 20 && token.contains('.') {
        return true;
    }

    false
}

/// Strip leading and trailing ASCII punctuation (quotes, backticks, commas,
/// brackets, etc.) from a token for pattern matching, returning the inner
/// slice.
fn strip_surrounding_punctuation(s: &str) -> &str {
    const PUNCT: &[char] = &[
        '"', '\'', '`', ',', ';', '(', ')', '[', ']', '{', '}', '<', '>', '|',
    ];
    s.trim_matches(PUNCT as &[char])
}

/// Scan `input` split on ASCII whitespace; for each token that looks like a
/// secret, replace the token in the output with MARKER.
fn redact_prefixed_tokens(input: &str) -> (String, u32) {
    // We do a position-aware scan so we can reconstruct whitespace faithfully.
    let mut result = String::with_capacity(input.len());
    let mut count = 0u32;
    let mut pos = 0usize;
    let bytes = input.as_bytes();

    while pos < input.len() {
        // Skip whitespace, adding it to result
        let ws_start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        result.push_str(&input[ws_start..pos]);

        if pos >= input.len() {
            break;
        }

        // Find next whitespace to delimit the token
        let tok_start = pos;
        while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let raw_token = &input[tok_start..pos];

        let stripped = strip_surrounding_punctuation(raw_token);
        if is_secret_token(stripped) {
            // Replace the whole raw token (including surrounding punctuation) with MARKER
            result.push_str(MARKER);
            count += 1;
        } else {
            result.push_str(raw_token);
        }
    }

    (result, count)
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Merge a sorted list of `(start, end)` byte spans into non-overlapping
/// spans.
fn merge_spans(spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (s, e) in spans {
        if let Some(last) = merged.last_mut() {
            if s <= last.1 {
                last.1 = last.1.max(e);
                continue;
            }
        }
        merged.push((s, e));
    }
    merged
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // Helpers: build secret-shaped tokens at runtime so no contiguous
    // secret-shaped literal appears in the source file (which would trigger
    // GitHub secret-scanning push protection even for fake test fixtures).
    // -----------------------------------------------------------------------

    /// GitHub PAT: `ghp_` + 36 alphanumeric chars → total 40, satisfies len ≥ 20.
    fn ghp_token() -> String {
        format!("ghp_{}", "a".repeat(36))
    }

    /// GitHub PAT embedded in an auth sentence.
    fn ghp_token_in_sentence() -> String {
        format!(
            "Use this token: {}ABCDEFGHIJKLMNOPQRSTUVWXabcdef for auth",
            "ghp_"
        )
    }

    /// Slack bot token: `xoxb-` + 20 digits → satisfies the xoxb- prefix rule.
    fn slack_token() -> String {
        format!("xoxb-{}", "0".repeat(20))
    }

    /// AWS access key id: `AKIA` + 16 uppercase letters → total 20, satisfies AKIA rule.
    fn aws_key() -> String {
        format!("AKIA{}", "A".repeat(16))
    }

    /// OpenAI-style key: `sk-` + 40 lowercase chars → total 43, satisfies len ≥ 20.
    fn openai_key() -> String {
        format!("sk-{}", "c".repeat(40))
    }

    /// Google API key: `AIza` + 35 chars → total 39, satisfies len ≥ 34.
    fn google_key() -> String {
        format!("AIza{}", "B".repeat(35))
    }

    /// Minimal fake JWT: `eyJ` + 20-char header `.` 10-char payload `.` 20-char sig
    /// → total ≥ 20, contains a dot, satisfies the JWT rule.
    fn fake_jwt() -> String {
        format!(
            "eyJ{}.{}.{}",
            "a".repeat(20),
            "b".repeat(10),
            "c".repeat(20)
        )
    }

    /// `eyJ`-prefixed string that has NO dot — must NOT be redacted.
    /// Built at runtime because the literal would be long enough to look like a JWT header
    /// to GitHub's scanner.
    fn eyj_no_dot() -> String {
        format!("eyJ{}nodot", "a".repeat(30))
    }

    // -----------------------------------------------------------------------
    // Positive tests: prefixed tokens
    // -----------------------------------------------------------------------

    #[test]
    fn redacts_github_ghp_token() {
        // 40-char token (common GitHub PAT length after the prefix)
        let token = ghp_token();
        assert!(token.len() >= 20);
        let (out, count) = redact_text(&token);
        assert!(count >= 1, "expected at least 1 redaction, got {count}");
        assert!(!out.contains("ghp_"), "token should be gone");
        assert!(out.contains(MARKER), "marker should be present");
    }

    #[test]
    fn redacts_github_token_in_sentence() {
        let input = ghp_token_in_sentence();
        let (out, count) = redact_text(&input);
        assert!(count >= 1);
        assert!(!out.contains("ghp_"), "token should be redacted");
        assert!(
            out.contains("Use this token:"),
            "surrounding text preserved"
        );
    }

    #[test]
    fn redacts_aws_access_key() {
        // Classic AWS access key id shape
        let key = aws_key();
        let input = format!("{} rest of line", key);
        let (out, count) = redact_text(&input);
        assert!(count >= 1);
        assert!(!out.contains(&key), "AWS key should be gone");
        assert!(out.contains(MARKER));
    }

    #[test]
    fn redacts_openai_sk_token() {
        let token = openai_key();
        let (out, count) = redact_text(&token);
        assert!(count >= 1);
        assert!(!out.contains("sk-"), "sk- token should be gone");
        assert!(out.contains(MARKER));
    }

    #[test]
    fn redacts_google_api_key() {
        // AIza + 35 more chars
        let token = google_key();
        assert!(token.len() >= 34);
        let (out, count) = redact_text(&token);
        assert!(count >= 1);
        assert!(!out.contains("AIza"), "Google key should be gone");
        assert!(out.contains(MARKER));
    }

    #[test]
    fn redacts_jwt() {
        // A minimal fake JWT: eyJ<header>.<payload>.<signature>
        let jwt = fake_jwt();
        let (out, count) = redact_text(&jwt);
        assert!(count >= 1);
        assert!(!out.starts_with("eyJ"), "JWT should be redacted");
        assert!(out.contains(MARKER));
    }

    #[test]
    fn redacts_slack_bot_token() {
        let token = slack_token();
        let (out, count) = redact_text(&token);
        assert!(count >= 1);
        assert!(!out.contains("xoxb-"), "Slack token should be gone");
        assert!(out.contains(MARKER));
    }

    // -----------------------------------------------------------------------
    // Positive tests: key=value / key: value
    // -----------------------------------------------------------------------

    #[test]
    fn redacts_password_equals() {
        let input = "password=hunter2";
        let (out, count) = redact_text(input);
        assert!(count >= 1);
        assert!(out.contains("password="), "key should remain");
        assert!(!out.contains("hunter2"), "value should be gone");
        assert!(out.contains(MARKER));
    }

    #[test]
    fn redacts_api_key_colon() {
        let input = "API_KEY: abc123def456ghi789jkl";
        let (out, count) = redact_text(input);
        assert!(count >= 1);
        assert!(out.to_lowercase().contains("api_key"), "key should remain");
        assert!(!out.contains("abc123def456"), "value should be gone");
        assert!(out.contains(MARKER));
    }

    #[test]
    fn redacts_client_secret_with_spaces() {
        let input = "client_secret = s3cr3tvalue";
        let (out, count) = redact_text(input);
        assert!(count >= 1);
        assert!(out.contains("client_secret"), "key should remain");
        assert!(!out.contains("s3cr3tvalue"), "value should be gone");
        assert!(out.contains(MARKER));
    }

    #[test]
    fn redacts_authorization_header_value() {
        let jwt = fake_jwt();
        let input = format!("authorization: Bearer {}", jwt);
        let (out, count) = redact_text(&input);
        assert!(count >= 1);
        // The key should remain
        assert!(out.to_lowercase().contains("authorization"));
    }

    // -----------------------------------------------------------------------
    // Positive tests: PEM blocks
    // -----------------------------------------------------------------------

    #[test]
    fn redacts_pem_private_key_block() {
        let pem = concat!(
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4SJFdHkDODsR7Xk\n",
            "-----END RSA PRIVATE KEY-----"
        );
        let (out, count) = redact_text(pem);
        assert!(count >= 1);
        assert!(!out.contains("MIIEowIBAAKCAQEA"), "PEM body should be gone");
        assert!(out.contains(MARKER));
    }

    #[test]
    fn redacts_ec_private_key_block() {
        let pem = "-----BEGIN EC PRIVATE KEY-----\nABCDEFGHIJKL\n-----END EC PRIVATE KEY-----";
        let (out, count) = redact_text(pem);
        assert!(count >= 1);
        assert!(!out.contains("ABCDEFGHIJKL"), "EC key body should be gone");
        assert!(out.contains(MARKER));
    }

    // -----------------------------------------------------------------------
    // Negative tests: must NOT redact (count == 0, text unchanged)
    // -----------------------------------------------------------------------

    #[test]
    fn does_not_redact_find_large_files_sentence() {
        let input = "find the largest files in /Users/me/Downloads";
        let (out, count) = redact_text(input);
        assert_eq!(count, 0, "should not redact normal sentence");
        assert_eq!(out, input, "text should be unchanged");
    }

    #[test]
    fn does_not_redact_port_sentence() {
        let input = "what is using port 3000";
        let (out, count) = redact_text(input);
        assert_eq!(count, 0, "port reference should not be redacted");
        assert_eq!(out, input);
    }

    #[test]
    fn does_not_redact_compress_folder_sentence() {
        let input = "compress this folder";
        let (out, count) = redact_text(input);
        assert_eq!(count, 0);
        assert_eq!(out, input);
    }

    #[test]
    fn does_not_redact_normal_url() {
        let input = "https://example.com/page";
        let (out, count) = redact_text(input);
        assert_eq!(count, 0, "URL should not be redacted");
        assert_eq!(out, input);
    }

    #[test]
    fn does_not_redact_relative_path() {
        let input = "./notes.txt";
        let (out, count) = redact_text(input);
        assert_eq!(count, 0, "relative path should not be redacted");
        assert_eq!(out, input);
    }

    #[test]
    fn does_not_redact_short_sk_prefix() {
        // "sk-" with less than 20 total chars should not be redacted
        let input = "sk-short";
        assert!(input.len() < 20);
        let (out, count) = redact_text(input);
        assert_eq!(count, 0, "short sk- token should not be redacted");
        assert_eq!(out, input);
    }

    #[test]
    fn does_not_redact_normal_password_key_alone() {
        // "password" as a word without a `=` or `:` separator should not trigger
        let input = "I forgot my password today";
        let (out, count) = redact_text(input);
        assert_eq!(
            count, 0,
            "bare 'password' word should not trigger redaction"
        );
        assert_eq!(out, input);
    }

    #[test]
    fn does_not_redact_short_gh_prefix() {
        // "ghp_x" is way too short to be a real token (5 chars total)
        let input = "ghp_x";
        let (out, count) = redact_text(input);
        assert_eq!(count, 0, "short ghp_ token should not be redacted");
        assert_eq!(out, input);
    }

    // -----------------------------------------------------------------------
    // redact_value tests
    // -----------------------------------------------------------------------

    #[test]
    fn redact_value_redacts_secret_in_object_value() {
        let note_value = format!("token={}", ghp_token());
        let mut val = json!({
            "path": "/tmp/x",
            "note": note_value
        });
        let count = redact_value(&mut val);
        assert_eq!(count, 1);
        // path should be untouched
        assert_eq!(val["path"], json!("/tmp/x"));
        // note value should be redacted
        let note = val["note"].as_str().unwrap();
        assert!(note.contains("token="), "key 'token=' should remain");
        assert!(!note.contains("ghp_"), "token value should be gone");
        assert!(note.contains(MARKER));
    }

    #[test]
    fn redact_value_does_not_touch_numbers_bools_null() {
        let mut val = json!({
            "count": 42,
            "enabled": true,
            "nothing": null
        });
        let count = redact_value(&mut val);
        assert_eq!(count, 0);
        assert_eq!(val["count"], json!(42));
        assert_eq!(val["enabled"], json!(true));
        assert_eq!(val["nothing"], json!(null));
    }

    #[test]
    fn redact_value_walks_arrays() {
        let mut val = json!(["normal text", "password=s3cret", 42, true]);
        let count = redact_value(&mut val);
        assert_eq!(count, 1);
        assert_eq!(val[0], json!("normal text"));
        let second = val[1].as_str().unwrap();
        assert!(second.contains("password="));
        assert!(!second.contains("s3cret"));
        // numbers and bools untouched
        assert_eq!(val[2], json!(42));
        assert_eq!(val[3], json!(true));
    }

    #[test]
    fn redact_value_nested_object() {
        let mut val = json!({
            "db": {
                "host": "localhost",
                "password": "supersecret"
            }
        });
        // The inner object value "supersecret" is at key "password", but
        // redact_value operates on the string leaf directly.  The key=value
        // detector requires the key to appear IN the string value.
        // Here the string leaf is just "supersecret" without the key prefix,
        // so redact_text won't fire — which is CORRECT: the key is structural,
        // stored separately by JSON. Only the value string is passed to
        // redact_text.  This is acceptable / by design.
        let count = redact_value(&mut val);
        // "localhost" is plain, "supersecret" has no secret prefix → 0
        assert_eq!(count, 0);
    }

    #[test]
    fn redact_value_returns_correct_total_count() {
        let a_value = format!("token={}", ghp_token());
        let b_value = format!("{} extra", aws_key());
        let mut val = json!({
            "a": a_value,
            "b": b_value,
            "c": "plain"
        });
        let count = redact_value(&mut val);
        // "a" triggers key=value (token=...) AND the ghp_ prefix token;
        // but after key=value replaces the value with MARKER the prefix
        // detector won't see ghp_ any more → 1 redaction for "a"
        // "b" triggers AWS key → 1 redaction
        assert!(count >= 2, "expected ≥ 2 redactions, got {count}");
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn empty_input_returns_empty_unchanged() {
        let (out, count) = redact_text("");
        assert_eq!(count, 0);
        assert_eq!(out, "");
    }

    #[test]
    fn redact_text_does_not_double_redact_marker() {
        // If MARKER itself were passed in, the detectors should not touch it
        let (out, count) = redact_text(MARKER);
        assert_eq!(count, 0);
        assert_eq!(out, MARKER);
    }

    #[test]
    fn eyj_without_dot_not_redacted() {
        // An eyJ prefix without a dot is NOT a JWT — must not redact.
        // Built at runtime to avoid triggering GitHub secret-scanning on the literal.
        let input = eyj_no_dot();
        assert!(!input.contains('.'));
        assert!(input.len() >= 20);
        let (out, count) = redact_text(&input);
        assert_eq!(count, 0, "eyJ without dot should not be redacted");
        assert_eq!(out, input);
    }
}
