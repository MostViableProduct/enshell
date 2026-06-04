//! Deterministic fast-path matcher (§13).
//!
//! Before invoking any [`ModelProvider`](enshell_model::ModelProvider), the
//! orchestrator consults this matcher. If a request matches a **known phrasing**,
//! it resolves directly to a typed [`Intent`] with **no model call** — keeping the
//! most common requests instant, shrinking the hallucination surface, and making
//! those paths fully testable without a model present.
//!
//! # Precision over recall
//!
//! This matcher is intentionally **high-precision, low-recall**. It matches only
//! exact/near-exact canonical phrasings and templates whose intent is
//! *parameter-complete* (the port number, the file path). It must never short-
//! circuit the model for a request that carries qualifiers the model would
//! interpret better (e.g. "show me the nginx logs since yesterday" is **not**
//! fast-pathed — it falls through to the provider so the source/since parameters
//! are not silently dropped). On any doubt, it returns [`None`] and the model runs.
//!
//! # Trust boundary
//!
//! A fast-path match produces a [`Intent`] constructed by **trusted Rust**, so it
//! does not pass through [`enshell_intents::parse_model_output`] (that validator
//! exists for *untrusted* model strings). Everything downstream is unchanged: the
//! intent is still policy-classified, MVP-gated, adapter-rendered, previewed, and
//! confirmed exactly like a model-produced intent.

use enshell_intents::Intent;

/// Canonical phrasings that map to [`Intent::CheckSystemHealth`].
const HEALTH_PHRASES: &[&str] = &[
    "run a system health check",
    "run a health check",
    "check system health",
    "check my system health",
    "system health check",
    "run system diagnostics",
    "run diagnostics",
];

/// Canonical phrasings that map to a parameterless [`Intent::InspectLogs`].
///
/// Only phrasings with **no implied source/since/filter** belong here — anything
/// more specific must fall through to the model so those parameters survive.
const LOGS_PHRASES: &[&str] = &[
    "show me recent logs",
    "show recent logs",
    "show me the recent logs",
    "show recent log entries",
    "show me recent log entries",
    "view recent logs",
];

/// Phrasings that map to [`Intent::ListProcesses`].
const LIST_PROCESSES_PHRASES: &[&str] = &[
    "list processes",
    "list running processes",
    "show running processes",
    "show me running processes",
    "show processes",
    "what processes are running",
];

/// Phrasings that map to [`Intent::DiskUsage`].
const DISK_USAGE_PHRASES: &[&str] = &[
    "show disk usage",
    "disk usage",
    "show disk space",
    "check disk space",
    "how much disk space",
    "how much disk space is free",
];

/// Phrasings that map to [`Intent::NetworkConnections`].
const NETWORK_PHRASES: &[&str] = &[
    "show network connections",
    "list network connections",
    "show open connections",
    "what network connections are open",
];

/// Phrasings that map to [`Intent::GitStatus`].
const GIT_STATUS_PHRASES: &[&str] = &[
    "git status",
    "show git status",
    "what's the git status",
    "show me the git status",
];

/// Phrasings that map to [`Intent::ShowMemory`].
const MEMORY_PHRASES: &[&str] = &[
    "show memory usage",
    "memory usage",
    "show memory",
    "how much memory is free",
    "how much memory is used",
];

/// Phrasings that map to [`Intent::FindLargeFiles`] over the current directory.
const LARGE_FILES_HERE: &[&str] = &[
    "find the largest files here",
    "find the biggest files here",
    "show me the largest files here",
    "show me the biggest files here",
    "find the largest files in this folder",
    "find the biggest files in this folder",
    "what are the largest files here",
    "what are the biggest files here",
];

/// Phrasings that map to [`Intent::FindLargeFiles`] over `~/Downloads`.
const LARGE_FILES_DOWNLOADS: &[&str] = &[
    "find the biggest files in my downloads folder",
    "find the largest files in my downloads folder",
    "show me the biggest files in my downloads folder",
    "show me the largest files in my downloads folder",
    "what are the biggest files in my downloads folder",
    "what are the largest files in my downloads folder",
    "find the biggest files in my downloads",
    "find the largest files in my downloads",
];

/// Phrase prefixes that precede `" port <N>"` in a port-lookup request. The
/// remainder after `" port "` must be a bare, in-range port number — nothing else.
const PORT_PREFIXES: &[&str] = &[
    "what is using",
    "what's using",
    "whats using",
    "what is on",
    "what's on",
    "whats on",
    "what is listening on",
    "what's listening on",
    "whats listening on",
    "show me what is using",
    "show me what's using",
    "show me whats using",
    "what is using tcp",
    "what process is using",
    "what process is on",
];

/// Match a natural-language request against the known-phrasing table.
///
/// Returns `Some((intent, explanation))` on a confident match — the `explanation`
/// is a plain-English description used to build the preview, mirroring what a
/// model would supply. Returns [`None`] when nothing matches confidently, in which
/// case the caller invokes the model provider.
///
/// All matches are **read-only MVP intents**; the policy engine still classifies
/// and gates them downstream (this function never decides executability).
pub fn fast_path_match(user_request: &str) -> Option<(Intent, &'static str)> {
    let norm = normalize(user_request);

    // Port lookup (templated; the port number is the only parameter).
    if let Some(intent) = match_port(&norm) {
        return Some((
            intent,
            "I will check which process is listening on that port.",
        ));
    }

    // Open a file/folder (templated; the path is the only parameter). The path is
    // taken from the original request to preserve case.
    if let Some(intent) = match_open(&norm, user_request) {
        return Some((intent, "I will open the specified file or folder."));
    }

    // Parameterless / fixed-parameter canonical phrasings.
    let n = norm.as_str();
    if HEALTH_PHRASES.contains(&n) {
        return Some((
            Intent::CheckSystemHealth {},
            "I will run a system health check.",
        ));
    }
    if LOGS_PHRASES.contains(&n) {
        return Some((
            Intent::InspectLogs {
                source: None,
                since: None,
                filter: None,
            },
            "I will show recent log entries.",
        ));
    }
    if LARGE_FILES_HERE.contains(&n) {
        return Some((
            Intent::FindLargeFiles {
                path: ".".to_owned(),
                min_size: None,
                limit: Some(10),
            },
            "I will find the largest files in the specified directory.",
        ));
    }
    if LARGE_FILES_DOWNLOADS.contains(&n) {
        return Some((
            Intent::FindLargeFiles {
                path: "~/Downloads".to_owned(),
                min_size: None,
                limit: Some(10),
            },
            "I will find the largest files in the specified directory.",
        ));
    }
    if LIST_PROCESSES_PHRASES.contains(&n) {
        return Some((
            Intent::ListProcesses {},
            "I will list the running processes.",
        ));
    }
    if DISK_USAGE_PHRASES.contains(&n) {
        return Some((Intent::DiskUsage {}, "I will show filesystem disk usage."));
    }
    if NETWORK_PHRASES.contains(&n) {
        return Some((
            Intent::NetworkConnections {},
            "I will show active network connections.",
        ));
    }
    if GIT_STATUS_PHRASES.contains(&n) {
        return Some((
            Intent::GitStatus {},
            "I will show the git status of the current repository.",
        ));
    }
    if MEMORY_PHRASES.contains(&n) {
        return Some((Intent::ShowMemory {}, "I will show memory usage."));
    }

    None
}

/// Normalize a request for matching: trim, lowercase, collapse internal
/// whitespace to single spaces, and strip trailing `? . !` punctuation.
fn normalize(s: &str) -> String {
    let lowered = s.trim().to_lowercase();
    let collapsed = lowered.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed
        .trim_end_matches(['?', '.', '!'])
        .trim_end()
        .to_owned()
}

/// Match `<known prefix> port <N>` where `<N>` is a bare port in `1..=65535`.
///
/// Uses the **last** `" port "` so a trailing number is unambiguous; if anything
/// other than a single in-range number follows, returns `None`.
fn match_port(norm: &str) -> Option<Intent> {
    const KEY: &str = " port ";
    let idx = norm.rfind(KEY)?;
    let prefix = &norm[..idx];
    let rest = norm[idx + KEY.len()..].trim();
    if !PORT_PREFIXES.contains(&prefix) {
        return None;
    }
    let n: u32 = rest.parse().ok()?;
    if (1..=65535).contains(&n) {
        Some(Intent::FindProcessUsingPort { port: n as u16 })
    } else {
        None
    }
}

/// Match `open <path>` only when the argument **looks like an explicit path**,
/// so plain English like "open the browser" falls through to the model.
///
/// The path is taken from `original` (case-preserving) after the leading `open `.
fn match_open(norm: &str, original: &str) -> Option<Intent> {
    let rest_norm = norm.strip_prefix("open ")?;
    if !looks_like_path(rest_norm) {
        return None;
    }
    // "open " is 5 ASCII bytes regardless of the original's case, so this slice is
    // valid on the trimmed original and preserves the path's capitalisation.
    let path = original.trim().get("open ".len()..)?.trim();
    if path.is_empty() {
        return None;
    }
    Some(Intent::OpenFileOrFolder {
        path: path.to_owned(),
    })
}

/// A conservative "is this an explicit filesystem path?" check: POSIX absolute,
/// home-relative, explicit relative (`./`, `../`), or a Windows drive root.
fn looks_like_path(s: &str) -> bool {
    s.starts_with('/')
        || s.starts_with('~')
        || s.starts_with("./")
        || s.starts_with("../")
        || is_windows_drive(s)
}

/// True for a Windows drive prefix like `c:\` or `c:/`.
fn is_windows_drive(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn intent_of(req: &str) -> Option<Intent> {
        fast_path_match(req).map(|(i, _)| i)
    }

    // --- match: port (templated) --------------------------------------------

    #[test]
    fn matches_canonical_port_phrase() {
        assert_eq!(
            intent_of("what is using port 3000"),
            Some(Intent::FindProcessUsingPort { port: 3000 })
        );
    }

    #[test]
    fn matches_port_phrase_variants_and_normalizes() {
        for req in [
            "What is using port 3000?",
            "  what   is   using   port   3000  ",
            "WHAT IS LISTENING ON PORT 8080",
            "show me what is using port 22",
            "what process is on port 443",
        ] {
            assert!(
                matches!(intent_of(req), Some(Intent::FindProcessUsingPort { .. })),
                "expected a port match for {req:?}, got {:?}",
                intent_of(req)
            );
        }
    }

    #[test]
    fn port_extracts_correct_number() {
        assert_eq!(
            intent_of("what is listening on port 8080"),
            Some(Intent::FindProcessUsingPort { port: 8080 })
        );
    }

    // --- no-match: port out of range / extra tokens / unknown prefix --------

    #[test]
    fn rejects_out_of_range_port() {
        assert_eq!(intent_of("what is using port 99999"), None);
        assert_eq!(intent_of("what is using port 0"), None);
    }

    #[test]
    fn rejects_port_with_trailing_qualifier() {
        // A trailing qualifier means the model should interpret it, not the fast path.
        assert_eq!(intent_of("what is using port 3000 and 8080"), None);
        assert_eq!(intent_of("what is using port 3000 right now please"), None);
    }

    #[test]
    fn rejects_unknown_port_prefix() {
        // "kill" is a different (destructive) intent — must NOT be fast-pathed as a lookup.
        assert_eq!(intent_of("kill whatever is on port 3000"), None);
    }

    // --- match: health / logs / large files ---------------------------------

    #[test]
    fn matches_health_phrases() {
        for req in [
            "run a system health check",
            "check system health",
            "Run Diagnostics.",
        ] {
            assert_eq!(
                intent_of(req),
                Some(Intent::CheckSystemHealth {}),
                "for {req:?}"
            );
        }
    }

    #[test]
    fn matches_recent_logs_as_parameterless() {
        assert_eq!(
            intent_of("show me recent logs"),
            Some(Intent::InspectLogs {
                source: None,
                since: None,
                filter: None,
            })
        );
    }

    #[test]
    fn matches_large_files_here_with_dot_path_and_limit() {
        match intent_of("find the largest files here") {
            Some(Intent::FindLargeFiles { path, limit, .. }) => {
                assert_eq!(path, ".");
                assert_eq!(limit, Some(10));
            }
            other => panic!("expected FindLargeFiles, got {other:?}"),
        }
    }

    #[test]
    fn matches_large_files_downloads_with_downloads_path() {
        match intent_of("find the biggest files in my Downloads folder") {
            Some(Intent::FindLargeFiles { path, .. }) => assert_eq!(path, "~/Downloads"),
            other => panic!("expected FindLargeFiles, got {other:?}"),
        }
    }

    // --- match: open (templated, path-guarded) ------------------------------

    #[test]
    fn matches_open_with_explicit_path_preserving_case() {
        assert_eq!(
            intent_of("open /tmp/Notes.txt"),
            Some(Intent::OpenFileOrFolder {
                path: "/tmp/Notes.txt".to_owned(),
            })
        );
        assert_eq!(
            intent_of("Open ~/Documents"),
            Some(Intent::OpenFileOrFolder {
                path: "~/Documents".to_owned(),
            })
        );
    }

    #[test]
    fn open_matches_windows_drive_path() {
        assert_eq!(
            intent_of(r"open C:\Users\me\file.txt"),
            Some(Intent::OpenFileOrFolder {
                path: r"C:\Users\me\file.txt".to_owned(),
            })
        );
    }

    #[test]
    fn open_without_explicit_path_falls_through() {
        // Plain English — the model should handle these, not the fast path.
        assert_eq!(intent_of("open the browser"), None);
        assert_eq!(intent_of("open my email"), None);
    }

    // --- no-match: unknown / qualified requests -----------------------------

    #[test]
    fn unknown_request_returns_none() {
        assert_eq!(intent_of("fizzbuzz wibble"), None);
        assert_eq!(intent_of(""), None);
    }

    #[test]
    fn qualified_logs_request_falls_through_to_model() {
        // Implies a source/filter the model must capture — must not be fast-pathed
        // into a parameterless InspectLogs.
        assert_eq!(
            intent_of("show me the nginx error logs since yesterday"),
            None
        );
    }

    // --- normalize helper ----------------------------------------------------

    #[test]
    fn normalize_strips_trailing_punctuation_and_collapses_space() {
        assert_eq!(
            normalize("  Run   A   Health   Check?? "),
            "run a health check"
        );
    }
}
