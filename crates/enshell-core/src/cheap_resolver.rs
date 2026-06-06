//! The "cheap resolver" — a lightweight, rule-based middle layer between the
//! deterministic [`fast path`](crate::fastpath) and the LLM provider.
//!
//! ```text
//! fast_path -> cheap_resolver -> model provider -> parse_model_output -> policy
//! ```
//!
//! The fast path matches only exact/near-exact canonical phrasings. The cheap
//! resolver widens coverage to **conservative paraphrases** of the same fixed
//! read-only intent catalog using simple normalization + token scanning — no model
//! weights, no embeddings, fully unit-testable. Like the fast path, a hit produces
//! a **trusted, typed** [`Intent`] (it does NOT pass through
//! [`enshell_intents::parse_model_output`], which exists for untrusted model
//! strings); everything downstream — policy, MVP gate, render, confirm — is
//! identical.
//!
//! # Precision over recall (the whole point)
//!
//! This layer is **high-precision, low-recall**. It must never produce a *broader*
//! action than the user asked for. Two structural guards enforce that:
//!
//! 1. **Write/system disqualifier.** If the request contains any write/system verb
//!    (delete, install, kill, …) the resolver returns [`None`] immediately — it
//!    only ever produces read-only intents, and a mixed request ("…and kill it")
//!    must reach the policy engine / model, not be silently narrowed to its
//!    read-only half.
//! 2. **Exactly-one-category.** Every per-intent matcher is run; the resolver
//!    returns a hit **only if exactly one** category matched. Zero matches → fall
//!    through to the model; two or more (a compound like "disk and memory usage",
//!    or any keyword collision) → [`None`], so ambiguity always defers to the model.
//!
//! Each matcher additionally returns [`None`] the moment it sees a parameter it
//! cannot faithfully encode (a second port, a `min_size`, a specific log source),
//! so a parameter is never dropped.

use enshell_intents::Intent;

use crate::fastpath::{looks_like_path, normalize};

/// Write / system / destructive verbs. Their presence disqualifies the request
/// from the read-only cheap resolver entirely — it must reach policy/model, never
/// be narrowed to a read-only interpretation. Matched as whole words.
const DISQUALIFYING_VERBS: &[&str] = &[
    "delete",
    "remove",
    "rm",
    "erase",
    "trash",
    "install",
    "uninstall",
    "kill",
    "stop",
    "start",
    "restart",
    "reboot",
    "shutdown",
    "update",
    "upgrade",
    "format",
    "wipe",
    "chmod",
    "chown",
    "sudo",
    "create",
    "make",
    "rename",
    "move",
    "copy",
    "backup",
    "compress",
    "commit",
    "push",
    "enable",
    "disable",
    "write",
    "edit",
    "set",
];

/// Conservatively resolve a request to a trusted typed [`Intent`] with a short,
/// user-facing explanation — or [`None`] when not highly confident.
///
/// See the module docs for the precision guarantees. Returns `None` on any
/// ambiguity, compound request, write/system verb, or unencodable parameter.
pub fn cheap_resolve(request: &str) -> Option<(Intent, String)> {
    let norm = normalize(request);
    let n = norm.as_str();

    // Guard 1: a write/system verb means this is not a pure read-only diagnostic.
    if DISQUALIFYING_VERBS.iter().any(|v| has_word(n, v)) {
        return None;
    }

    // Guard 2: run every matcher; accept only if EXACTLY ONE category matches.
    let mut hits: Vec<(Intent, String)> = Vec::new();
    if let Some(h) = match_port(n) {
        hits.push(h);
    }
    if let Some(h) = match_large_files(n, request) {
        hits.push(h);
    }
    if let Some(h) = match_inspect_logs(n) {
        hits.push(h);
    }
    if let Some(h) = match_health(n) {
        hits.push(h);
    }
    if let Some(h) = match_disk_usage(n) {
        hits.push(h);
    }
    if let Some(h) = match_memory(n) {
        hits.push(h);
    }
    if let Some(h) = match_network(n) {
        hits.push(h);
    }
    if let Some(h) = match_list_processes(n) {
        hits.push(h);
    }
    if let Some(h) = match_git_status(n) {
        hits.push(h);
    }
    if let Some(h) = match_open(n, request) {
        hits.push(h);
    }

    if hits.len() == 1 {
        hits.pop()
    } else {
        // 0 → model handles it; 2+ → compound/ambiguous, model handles it.
        None
    }
}

// ---------------------------------------------------------------------------
// Small token helpers (operate on the already-normalized, space-collapsed string)
// ---------------------------------------------------------------------------

/// Whole-word containment: ` foo ` is in ` the foo bar ` but not ` foobar `.
fn has_word(n: &str, word: &str) -> bool {
    let padded = format!(" {n} ");
    padded.contains(&format!(" {word} "))
}

/// True if any of `words` appears as a whole word.
fn any_word(n: &str, words: &[&str]) -> bool {
    words.iter().any(|w| has_word(n, w))
}

/// True for an unambiguous deictic reference to the current directory. Whole-word
/// `here` (so "where"/"there" don't match) plus the multi-word phrases.
fn is_deictic_cwd(n: &str) -> bool {
    has_word(n, "here")
        || n.contains("this folder")
        || n.contains("this directory")
        || n.contains("current folder")
        || n.contains("current directory")
        || n.contains("current dir")
}

// ---------------------------------------------------------------------------
// Per-intent matchers — each conservative, each None on unencodable parameters
// ---------------------------------------------------------------------------

/// `find_process_using_port` — exactly one numeric, in-range port.
fn match_port(n: &str) -> Option<(Intent, String)> {
    if !has_word(n, "port") && !has_word(n, "ports") {
        return None;
    }
    // Must read as a port *lookup*, not some other use of the word "port".
    let lookup = any_word(
        n,
        &[
            "using",
            "use",
            "uses",
            "listening",
            "on",
            "holding",
            "bound",
            "owns",
            "owning",
            "occupying",
            "open",
            "has",
            "which",
            "what",
        ],
    );
    if !lookup {
        return None;
    }
    // Reject ranges like "3000-4000" / "3000 to 4000" (broader than one port).
    if has_digit_hyphen_range(n) || (n.contains(" to ") && count_numbers(n) >= 2) {
        return None;
    }
    // Exactly one number anywhere, and it must be a valid port.
    let nums = numbers(n);
    if nums.len() != 1 {
        return None; // zero, or "port 3000 and 8080" → defer to model
    }
    let p = nums[0];
    if !(1..=65535).contains(&p) {
        return None;
    }
    Some((
        Intent::FindProcessUsingPort { port: p as u16 },
        "I will check which process is listening on that port.".to_owned(),
    ))
}

/// `find_large_files` — largest/biggest/large files at a recognizable location.
/// Returns `None` if a size qualifier is present (`min_size` is not encoded here).
fn match_large_files(n: &str, original: &str) -> Option<(Intent, String)> {
    let size_word = any_word(n, &["largest", "biggest", "large", "huge"]);
    let file_word = any_word(n, &["file", "files"]);
    if !(size_word && file_word) {
        return None;
    }
    // A size qualifier means a `min_size` we cannot faithfully encode → defer.
    if n.contains("larger than")
        || n.contains("bigger than")
        || n.contains("greater than")
        || n.contains("more than")
        || n.contains("at least")
        || n.contains(" over ")
        || has_size_unit(n)
    {
        return None;
    }

    // Resolve the location, conservatively. This layer has the NL context the
    // adapter lacks, so it may map a clear "Downloads" to "~/Downloads".
    let path: String = if is_deictic_cwd(n) {
        ".".to_owned()
    } else if has_word(n, "downloads") {
        "~/Downloads".to_owned()
    } else if let Some(p) = explicit_path_token(original) {
        p
    } else {
        // Bare "find the largest files" → the current directory (the same default
        // the fast path uses for the deictic phrasings).
        ".".to_owned()
    };

    Some((
        Intent::FindLargeFiles {
            path,
            min_size: None,
            limit: Some(10),
        },
        "I will find the largest files in the specified directory.".to_owned(),
    ))
}

/// `inspect_logs` — recent logs only. Returns `None` if a specific source/filter
/// is present (those must reach the model), or a `since` we cannot encode.
fn match_inspect_logs(n: &str) -> Option<(Intent, String)> {
    if !any_word(n, &["log", "logs"]) {
        return None;
    }
    // Must read as "show me (recent) logs", not a log-filtering/source request.
    let recency = any_word(
        n,
        &[
            "recent", "latest", "last", "tail", "show", "view", "see", "read",
        ],
    );
    if !recency {
        return None;
    }
    // A filter request — defer to the model (don't drop the filter).
    if n.contains("containing")
        || n.contains("matching")
        || n.contains("filter")
        || n.contains("grep")
        || any_word(n, &["error", "errors", "warning", "warnings", "with"])
    {
        return None;
    }
    // A specific (non-system) source — defer. We allow only the implicit/"system"
    // log; any other "<x> logs" / "logs for <x>" / "logs from <x>" goes to the model.
    if has_specific_log_source(n) {
        return None;
    }

    // `since`: only the explicit "last/past hour" forms we can encode as "1h".
    let since = if n.contains("last hour")
        || n.contains("past hour")
        || has_word(n, "1h")
        || n.contains("last 1 hour")
    {
        Some("1h".to_owned())
    } else if mentions_unencodable_since(n) {
        // "since yesterday", "last 3 days", a date, etc. — defer to the model.
        return None;
    } else {
        // Bare "recent logs": omit `since` (matches the fast path's parameterless
        // mapping; the eval fixtures accept either an absent or a `since` window).
        None
    };

    Some((
        Intent::InspectLogs {
            source: None,
            since,
            filter: None,
        },
        "I will show recent log entries.".to_owned(),
    ))
}

/// `check_system_health`.
fn match_health(n: &str) -> Option<(Intent, String)> {
    let hit = n.contains("system health")
        || n.contains("health check")
        || n.contains("health-wise")
        || n.contains("overall health")
        || n.contains("how is my computer")
        || n.contains("how is my system")
        || n.contains("how is my machine")
        || n.contains("how's my computer")
        || n.contains("system vitals")
        || (has_word(n, "health") && any_word(n, &["computer", "system", "machine"]));
    hit.then(|| {
        (
            Intent::CheckSystemHealth {},
            "I will run a system health check.".to_owned(),
        )
    })
}

/// `disk_usage`.
fn match_disk_usage(n: &str) -> Option<(Intent, String)> {
    let hit = n.contains("disk usage")
        || n.contains("disk space")
        || n.contains("free space")
        || n.contains("space is being used")
        || n.contains("space is left")
        || (any_word(n, &["disk"]) && any_word(n, &["usage", "space", "full", "used"]));
    hit.then(|| {
        (
            Intent::DiskUsage {},
            "I will show filesystem disk usage.".to_owned(),
        )
    })
}

/// `show_memory`.
fn match_memory(n: &str) -> Option<(Intent, String)> {
    let hit = n.contains("memory usage")
        || n.contains("how much memory")
        || n.contains("how much ram")
        || n.contains("free memory")
        || n.contains("free ram")
        || n.contains("memory is free")
        || n.contains("ram is free")
        || (any_word(n, &["memory", "ram"])
            && any_word(n, &["usage", "free", "available", "used"]));
    hit.then(|| {
        (
            Intent::ShowMemory {},
            "I will show memory usage.".to_owned(),
        )
    })
}

/// `network_connections`.
fn match_network(n: &str) -> Option<(Intent, String)> {
    let hit = n.contains("network connections")
        || n.contains("network sockets")
        || n.contains("open connections")
        || n.contains("active connections")
        || n.contains("listening sockets")
        || (any_word(n, &["network"]) && any_word(n, &["connections", "sockets", "ports"]));
    hit.then(|| {
        (
            Intent::NetworkConnections {},
            "I will show active network connections.".to_owned(),
        )
    })
}

/// `list_processes`.
fn match_list_processes(n: &str) -> Option<(Intent, String)> {
    let hit = n.contains("running processes")
        || n.contains("list processes")
        || n.contains("show processes")
        || n.contains("what processes")
        || n.contains("what is running")
        || n.contains("whats running")
        || n.contains("what's running")
        || n.contains("currently running")
        || (any_word(n, &["processes", "process"])
            && any_word(n, &["running", "list", "show", "active"]));
    hit.then(|| {
        (
            Intent::ListProcesses {},
            "I will list the running processes.".to_owned(),
        )
    })
}

/// `git_status`.
fn match_git_status(n: &str) -> Option<(Intent, String)> {
    let hit = n.contains("git status")
        || n.contains("git state")
        || n.contains("working tree")
        || n.contains("working directory clean")
        || (has_word(n, "git")
            && any_word(n, &["status", "changes", "clean", "staged", "uncommitted"]))
        || ((n.contains("repo") || n.contains("repository"))
            && any_word(n, &["status", "clean", "changes"]));
    hit.then(|| {
        (
            Intent::GitStatus {},
            "I will show the git status of the current repository.".to_owned(),
        )
    })
}

/// `open_file_or_folder` — only an **explicit path**, behind an open-ish phrase.
/// (The bare "open <path>" form is already handled by the fast path.)
fn match_open(n: &str, original: &str) -> Option<(Intent, String)> {
    const PHRASES: &[&str] = &[
        "open up ",
        "please open ",
        "can you open ",
        "could you open ",
        "i want to open ",
        "open the file ",
        "open the folder ",
        "open the directory ",
    ];
    let phrase = PHRASES.iter().find(|p| n.starts_with(*p))?;
    let rest_norm = n.get(phrase.len()..)?.trim();
    if !looks_like_path(rest_norm) {
        return None;
    }
    // Re-extract from the original to preserve the path's case.
    let path = explicit_path_token(original)?;
    Some((
        Intent::OpenFileOrFolder { path },
        "I will open the specified file or folder.".to_owned(),
    ))
}

// ---------------------------------------------------------------------------
// Parameter scanners
// ---------------------------------------------------------------------------

/// All ASCII-digit runs in `n`, parsed as `u32` (saturating drops on overflow).
fn numbers(n: &str) -> Vec<u32> {
    n.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<u32>().ok())
        .collect()
}

fn count_numbers(n: &str) -> usize {
    numbers(n).len()
}

/// True for a `<digits>-<digits>` range like `3000-4000`.
fn has_digit_hyphen_range(n: &str) -> bool {
    let bytes = n.as_bytes();
    for i in 1..bytes.len().saturating_sub(1) {
        if bytes[i] == b'-' && bytes[i - 1].is_ascii_digit() && bytes[i + 1].is_ascii_digit() {
            return true;
        }
    }
    false
}

/// True if `n` contains a size-with-unit token like `100mb`, `2 gb`, `500k`.
fn has_size_unit(n: &str) -> bool {
    const UNITS: &[&str] = &[
        "kb",
        "mb",
        "gb",
        "tb",
        "kib",
        "mib",
        "gib",
        "tib",
        "bytes",
        "byte",
        "kilobytes",
        "megabytes",
        "gigabytes",
    ];
    // "<num><unit>" (e.g. "100mb") or "<num> <unit>" (e.g. "2 gb").
    let glued = n.split_whitespace().any(|tok| {
        UNITS.iter().any(|u| {
            tok.ends_with(u)
                && tok[..tok.len() - u.len()]
                    .chars()
                    .any(|c| c.is_ascii_digit())
        })
    });
    if glued {
        return true;
    }
    // Separated: a number token immediately followed by a unit token.
    let toks: Vec<&str> = n.split_whitespace().collect();
    toks.windows(2).any(|w| {
        w[0].chars().all(|c| c.is_ascii_digit()) && !w[0].is_empty() && UNITS.contains(&w[1])
    })
}

/// True if `n` names a *specific* (non-system) log source: a `<word> logs` /
/// `logs for <word>` / `logs from <word>` where `<word>` is not a generic
/// recency/possessive filler or "system" (the implicit default).
fn has_specific_log_source(n: &str) -> bool {
    const GENERIC: &[&str] = &[
        "the", "my", "all", "recent", "latest", "last", "some", "those", "these", "system",
        "systems", "log", "error", "of", "a", "an", "and", "current",
    ];
    let toks: Vec<&str> = n.split_whitespace().collect();
    for (i, &tok) in toks.iter().enumerate() {
        // "<word> logs": the token immediately before "logs"/"log".
        if (tok == "logs" || tok == "log") && i > 0 {
            let prev = toks[i - 1];
            if !GENERIC.contains(&prev) && !prev.chars().all(|c| !c.is_alphanumeric()) {
                return true;
            }
        }
        // "logs for/from <word>".
        if (tok == "for" || tok == "from")
            && i > 0
            && (toks[i - 1] == "logs" || toks[i - 1] == "log")
        {
            if let Some(&next) = toks.get(i + 1) {
                if !GENERIC.contains(&next) {
                    return true;
                }
            }
        }
    }
    false
}

/// True if `n` carries a time window we cannot encode as our single supported
/// `since = "1h"` (e.g. "since yesterday", "last 3 days", a date).
fn mentions_unencodable_since(n: &str) -> bool {
    n.contains("yesterday")
        || n.contains("today")
        || n.contains("since ")
        || n.contains(" days")
        || n.contains(" day ")
        || n.contains(" weeks")
        || n.contains(" week ")
        || n.contains(" minutes")
        || n.contains(" hours") // "last 3 hours" etc. — not the single "last hour" form
        || n.contains("this morning")
}

/// Extract the first explicit-path token (POSIX/home/relative/Windows-drive) from
/// the **original** request, preserving case. Returns `None` if there is none.
fn explicit_path_token(original: &str) -> Option<String> {
    original
        .split_whitespace()
        .map(|t| t.trim_end_matches(['?', '.', '!', ',']))
        .find(|t| looks_like_path(&t.to_lowercase()))
        .map(|t| t.to_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn intent_of(req: &str) -> Option<Intent> {
        cheap_resolve(req).map(|(i, _)| i)
    }

    // --- positive: port paraphrases ----------------------------------------
    #[test]
    fn resolves_port_paraphrases() {
        assert_eq!(
            intent_of("which application is holding on to port 8080"),
            Some(Intent::FindProcessUsingPort { port: 8080 })
        );
        assert_eq!(
            intent_of("what's listening on port 3000"),
            Some(Intent::FindProcessUsingPort { port: 3000 })
        );
        assert_eq!(
            intent_of("which process has port 5000 open"),
            Some(Intent::FindProcessUsingPort { port: 5000 })
        );
    }

    // --- negative: ambiguous / multiple / out-of-range ports ---------------
    #[test]
    fn rejects_ambiguous_ports() {
        assert_eq!(intent_of("what is using port 3000 and 8080"), None); // two ports
        assert_eq!(intent_of("what is using ports 3000-4000"), None); // range
        assert_eq!(intent_of("what is using the http port"), None); // no number
        assert_eq!(intent_of("what is using port 99999"), None); // out of range
    }

    // --- positive: large files (deictic, downloads, explicit path) ---------
    #[test]
    fn resolves_large_files_locations() {
        assert_eq!(
            intent_of("what are the biggest files under /var/log"),
            Some(Intent::FindLargeFiles {
                path: "/var/log".to_owned(),
                min_size: None,
                limit: Some(10),
            })
        );
        // Context-aware Downloads normalization — only valid in this NL-aware layer.
        assert_eq!(
            intent_of("which files are the largest in Downloads"),
            Some(Intent::FindLargeFiles {
                path: "~/Downloads".to_owned(),
                min_size: None,
                limit: Some(10),
            })
        );
        assert_eq!(
            intent_of("show me the largest files in the current directory"),
            Some(Intent::FindLargeFiles {
                path: ".".to_owned(),
                min_size: None,
                limit: Some(10),
            })
        );
    }

    // --- negative: a min_size we cannot encode must defer to the model -----
    #[test]
    fn rejects_large_files_with_size_qualifier() {
        assert_eq!(intent_of("find files larger than 100MB in Downloads"), None);
        assert_eq!(intent_of("find files over 2 gb here"), None);
        assert_eq!(intent_of("find files at least 500kb"), None);
    }

    // "where"/"there" must not be read as the deictic "here".
    #[test]
    fn where_is_not_deictic_here() {
        // No explicit/deictic/downloads location -> defaults to ".", never broader.
        assert_eq!(
            intent_of("where are my large files"),
            Some(Intent::FindLargeFiles {
                path: ".".to_owned(),
                min_size: None,
                limit: Some(10),
            })
        );
    }

    // --- positive: recent logs (bare and last-hour) ------------------------
    #[test]
    fn resolves_recent_logs() {
        assert_eq!(
            intent_of("let me see the recent logs"),
            Some(Intent::InspectLogs {
                source: None,
                since: None,
                filter: None,
            })
        );
        // Bare "recent logs" omits `since` (matches the fast path; the eval
        // fixtures accept either an absent or a present `since`).
        assert_eq!(
            intent_of("show me the logs from the last hour"),
            Some(Intent::InspectLogs {
                source: None,
                since: Some("1h".to_owned()),
                filter: None,
            })
        );
    }

    // --- negative: logs with a source/filter/unencodable-since -> defer -----
    #[test]
    fn rejects_qualified_logs() {
        assert_eq!(intent_of("show me the nginx logs"), None); // specific source
        assert_eq!(intent_of("show nginx logs since yesterday"), None); // source + since
        assert_eq!(intent_of("show me recent logs containing error"), None); // filter
        assert_eq!(intent_of("show me logs since yesterday"), None); // unencodable since
    }

    // --- positive: the parameterless diagnostics ---------------------------
    #[test]
    fn resolves_parameterless_diagnostics() {
        assert_eq!(
            intent_of("give me a rundown of this machine's overall health"),
            Some(Intent::CheckSystemHealth {})
        );
        assert_eq!(
            intent_of("how much disk space is being used up"),
            Some(Intent::DiskUsage {})
        );
        assert_eq!(
            intent_of("how much memory is free right now"),
            Some(Intent::ShowMemory {})
        );
        assert_eq!(
            intent_of("list the active network connections"),
            Some(Intent::NetworkConnections {})
        );
        assert_eq!(
            intent_of("what processes are currently running"),
            Some(Intent::ListProcesses {})
        );
        assert_eq!(
            intent_of("is my git working tree clean"),
            Some(Intent::GitStatus {})
        );
    }

    // --- positive: open an explicit path behind a paraphrase ---------------
    #[test]
    fn resolves_open_explicit_path_only() {
        assert_eq!(
            intent_of("please open /tmp/notes.txt"),
            Some(Intent::OpenFileOrFolder {
                path: "/tmp/notes.txt".to_owned(),
            })
        );
        // Vague targets never resolve.
        assert_eq!(intent_of("open the browser"), None);
        assert_eq!(intent_of("open up my email"), None);
    }

    // --- negative: write/system verbs disqualify entirely ------------------
    #[test]
    fn rejects_write_and_system_verbs() {
        assert_eq!(intent_of("delete the large files here"), None);
        assert_eq!(intent_of("install postgresql"), None);
        assert_eq!(intent_of("what is using port 3000 and kill it"), None);
        assert_eq!(intent_of("update all packages"), None);
    }

    // --- negative: compound / ambiguous requests defer (exactly-one rule) --
    #[test]
    fn rejects_compound_requests() {
        // disk + memory -> two categories -> None.
        assert_eq!(intent_of("show me disk and memory usage"), None);
        // logs + health -> two categories -> None.
        assert_eq!(intent_of("show recent logs and run a health check"), None);
    }

    // --- negative: nothing recognizable -> defer to the model --------------
    #[test]
    fn unrecognized_requests_return_none() {
        assert_eq!(intent_of("what's the weather like"), None);
        assert_eq!(intent_of("tell me a joke"), None);
        assert_eq!(intent_of(""), None);
    }
}
