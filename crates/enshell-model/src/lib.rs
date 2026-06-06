//! Model provider abstraction for enShell.
//!
//! # Overview
//!
//! This crate defines [`ModelProvider`], the trait all model runtimes implement,
//! and [`StubProvider`], a deterministic stand-in used for testing and development
//! before the real Gemma/llama.cpp provider is wired in.
//!
//! It also contains the [`prompt`] module which builds the text prompts fed to any
//! provider, including the future Gemma 4 / llama.cpp backend.
//!
//! # Boundary contract
//!
//! [`ModelProvider::infer`] returns a **raw, untrusted JSON string** — the model's
//! output verbatim (or the stub's constructed equivalent). Callers MUST validate
//! the string through [`enshell_intents::parse_model_output`] before trusting it.
//! The provider layer never returns a typed intent; the boundary is intentional.

use enshell_intents::{Intent, ProposedAction, RiskHint};
use enshell_os::Os;
use std::fmt;

// ---------------------------------------------------------------------------
// Prompt-construction module
// ---------------------------------------------------------------------------

pub mod grammar;
pub mod prompt;

// Re-export the key items at crate root for ergonomic access.
pub use grammar::{intent_grammar, intent_names};
pub use prompt::{build_prompt, few_shot_examples, intent_tool_schema, system_prompt, Prompt};

// ---------------------------------------------------------------------------
// ModelRequest
// ---------------------------------------------------------------------------

/// The natural-language request plus the privacy-minimal context (§4 Layer 3).
///
/// Only environment facts (not user content) are included by default. Richer
/// capture (last command text, stderr, git status, etc.) is opt-in via the
/// CLI and is NOT part of this struct's default surface.
#[derive(Debug, Clone)]
pub struct ModelRequest {
    /// The user's natural-language request.
    pub user_request: String,
    /// The operating system detected at runtime.
    pub os: Os,
    /// The current working directory path, if available.
    pub cwd: Option<String>,
}

// ---------------------------------------------------------------------------
// ModelError
// ---------------------------------------------------------------------------

/// Errors returned by [`ModelProvider::infer`].
#[derive(Debug)]
pub enum ModelError {
    /// The model runtime failed to produce output.
    InferenceFailed(String),
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModelError::InferenceFailed(msg) => write!(f, "inference failed: {msg}"),
        }
    }
}

impl std::error::Error for ModelError {}

// ---------------------------------------------------------------------------
// ModelProvider trait
// ---------------------------------------------------------------------------

/// Abstraction over a model runtime.
///
/// Implementors return the model's **raw JSON output** (untrusted); the caller
/// validates it with [`enshell_intents::parse_model_output`].
///
/// Keeping the return type as `String` (not a typed intent) is load-bearing:
/// it preserves the trust boundary defined in §7 — the model output is untrusted
/// until it passes the Rust validator.
pub trait ModelProvider {
    /// A short, human-readable name for this provider (e.g. `"stub"`, `"gemma-4"`).
    fn name(&self) -> &str;

    /// Run inference on `request` and return the model's raw JSON output string.
    ///
    /// The returned string must be validated by the caller via
    /// [`enshell_intents::parse_model_output`] before any intent is acted on.
    fn infer(&self, request: &ModelRequest) -> Result<String, ModelError>;
}

/// Forward [`ModelProvider`] through a boxed trait object.
///
/// The trait is object-safe, so the CLI can hold a `Box<dyn ModelProvider>`
/// selected at runtime (stub vs. the real llama.cpp-backed provider) and still
/// pass it to a generic `Orchestrator<P: ModelProvider>`. Each method simply
/// re-dispatches to the contained provider.
impl ModelProvider for Box<dyn ModelProvider> {
    fn name(&self) -> &str {
        (**self).name()
    }

    fn infer(&self, request: &ModelRequest) -> Result<String, ModelError> {
        (**self).infer(request)
    }
}

// ---------------------------------------------------------------------------
// StubProvider — deterministic stand-in
// ---------------------------------------------------------------------------

/// Deterministic stand-in for the LLM.
///
/// Maps a curated set of natural-language phrasings to intent JSON. Returns an
/// `ask_clarification` intent for anything it does not recognise. The JSON is
/// constructed from typed [`ProposedAction`] values and serialized via
/// `serde_json::to_string`, guaranteeing schema-valid output on every code path.
///
/// This provider is intended for:
/// - Unit and integration tests (round-trip validation via `parse_model_output`).
/// - Development and CI before the real llama.cpp provider is available.
/// - Manual smoke-testing of the orchestration pipeline.
pub struct StubProvider;

impl ModelProvider for StubProvider {
    fn name(&self) -> &str {
        "stub"
    }

    fn infer(&self, request: &ModelRequest) -> Result<String, ModelError> {
        let lower = request.user_request.to_lowercase();

        let proposed = if is_port_config_write(&lower) {
            // "open/allow/block/forward ... port N" (or a firewall request) is a
            // write/config action, NOT read-only port inspection — defer rather
            // than narrow it to `find_process_using_port`.
            build_proposed(
                Intent::AskClarification {
                    question: "That reads like a firewall/port change, which I can't \
                               do yet. Did you mean to see which process is using that port?"
                        .to_string(),
                    options: None,
                },
                "I need more information to help with that.",
                0.3,
            )
        } else if let Some(intent) = try_match_port(&lower) {
            build_proposed(
                intent,
                "I will check which process is listening on that port.",
                0.9,
            )
        } else if try_match_large_files(&lower) {
            let path = if lower.contains("download") {
                "~/Downloads".to_string()
            } else {
                ".".to_string()
            };
            build_proposed(
                Intent::FindLargeFiles {
                    path,
                    min_size: None,
                    limit: Some(10),
                },
                "I will find the largest files in the specified directory.",
                0.9,
            )
        } else if try_match_health(&lower) {
            build_proposed(
                Intent::CheckSystemHealth {},
                "I will run a system health check.",
                0.9,
            )
        } else if try_match_logs(&lower) {
            build_proposed(
                Intent::InspectLogs {
                    source: None,
                    since: None,
                    filter: None,
                },
                "I will show recent log entries.",
                0.9,
            )
        } else if let Some(intent) = try_match_open(&lower, &request.user_request) {
            build_proposed(intent, "I will open the specified file or folder.", 0.9)
        } else if try_match_git_status(&lower) {
            build_proposed(
                Intent::GitStatus {},
                "I will show the git status of the current repository.",
                0.9,
            )
        } else if try_match_list_processes(&lower) {
            build_proposed(
                Intent::ListProcesses {},
                "I will list the running processes.",
                0.9,
            )
        } else if try_match_network(&lower) {
            build_proposed(
                Intent::NetworkConnections {},
                "I will show active network connections.",
                0.9,
            )
        } else if try_match_disk_usage(&lower) {
            build_proposed(
                Intent::DiskUsage {},
                "I will show filesystem disk usage.",
                0.9,
            )
        } else if try_match_memory(&lower) {
            build_proposed(Intent::ShowMemory {}, "I will show memory usage.", 0.9)
        } else {
            build_proposed(
                Intent::AskClarification {
                    question: "I didn't understand that yet — can you rephrase?".to_string(),
                    options: None,
                },
                "I need more information to help with that.",
                0.3,
            )
        };

        serde_json::to_string(&proposed).map_err(|e| ModelError::InferenceFailed(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Match helpers (all operate on the lowercased request)
// ---------------------------------------------------------------------------

/// True if the request reads as a firewall / port-config **write** ("open port
/// 3000", "allow incoming on port 3000", "forward port 3000", a firewall rule) as
/// opposed to read-only port inspection. Such requests must not be narrowed to
/// `find_process_using_port`. (`open <path>` without "port" is unaffected.)
fn is_port_config_write(lower: &str) -> bool {
    if !lower.contains("port") {
        return false;
    }
    lower.starts_with("open ")
        || lower.contains("allow ")
        || lower.contains("block ")
        || lower.contains("forward ")
        || lower.contains("firewall")
}

/// Returns a `FindProcessUsingPort` intent if the request mentions "port" and
/// contains a valid port number (first run of ASCII digits in 1..=65535).
/// Returns `None` if no matching port is found, falling through to the default.
fn try_match_port(lower: &str) -> Option<Intent> {
    if !lower.contains("port") {
        return None;
    }
    let port = first_port_number(lower)?;
    Some(Intent::FindProcessUsingPort { port })
}

/// Scan `text` for the first contiguous run of ASCII digits and parse it as a
/// `u16` in 1..=65535. Returns `None` if no digits are found or the value is
/// out of range.
fn first_port_number(text: &str) -> Option<u16> {
    let mut digits_start: Option<usize> = None;
    let mut result: Option<u16> = None;

    for (i, ch) in text.char_indices() {
        if ch.is_ascii_digit() {
            if digits_start.is_none() {
                digits_start = Some(i);
            }
        } else if let Some(_start) = digits_start.take() {
            // End of a digit run — try to parse the slice we just finished.
            let digit_slice = &text[_start..i];
            if let Ok(n) = digit_slice.parse::<u32>() {
                if (1..=65535).contains(&n) {
                    result = Some(n as u16);
                    break;
                }
            }
            // Number out of range or parse failed — keep scanning.
        }
    }

    // Handle a digit run that ends at end of string.
    if result.is_none() {
        if let Some(start) = digits_start {
            if let Ok(n) = text[start..].parse::<u32>() {
                if (1..=65535).contains(&n) {
                    result = Some(n as u16);
                }
            }
        }
    }

    result
}

fn try_match_large_files(lower: &str) -> bool {
    lower.contains("biggest")
        || lower.contains("largest")
        || lower.contains("large file")
        || lower.contains("large files")
}

fn try_match_health(lower: &str) -> bool {
    lower.contains("health") || lower.contains("diagnostic")
}

fn try_match_logs(lower: &str) -> bool {
    lower.contains("log")
}

// Read-only diagnostics. These run after the port/large-files/health/logs/open
// matchers, so e.g. a port request is not stolen by the "process" keyword.
fn try_match_git_status(lower: &str) -> bool {
    lower.contains("git") && lower.contains("status")
}

fn try_match_list_processes(lower: &str) -> bool {
    lower.contains("process")
}

fn try_match_network(lower: &str) -> bool {
    lower.contains("network") || lower.contains("connection")
}

fn try_match_disk_usage(lower: &str) -> bool {
    lower.contains("disk")
}

/// Matches "memory" only (not "ram", which is a substring of words like "program").
fn try_match_memory(lower: &str) -> bool {
    lower.contains("memory")
}

/// Returns an `OpenFileOrFolder` intent if the (lowercased) request starts with
/// `"open "`. The path is taken from the original-case request (not the lowercased
/// copy) so path capitalisation is preserved.
fn try_match_open(lower: &str, original: &str) -> Option<Intent> {
    if lower.starts_with("open ") {
        let path = original["open ".len()..].trim().to_string();
        if !path.is_empty() {
            return Some(Intent::OpenFileOrFolder { path });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// ProposedAction builder
// ---------------------------------------------------------------------------

fn build_proposed(intent: Intent, explanation: &str, confidence: f32) -> ProposedAction {
    ProposedAction {
        intent,
        risk: Some(RiskHint::ReadOnly),
        requires_confirmation: true,
        explanation: explanation.to_string(),
        confidence,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use enshell_intents::{parse_model_output, Intent};
    use enshell_os::{current_os, Os};

    fn req(text: &str) -> ModelRequest {
        ModelRequest {
            user_request: text.to_string(),
            os: current_os(),
            cwd: None,
        }
    }

    fn infer_and_parse(text: &str) -> enshell_intents::ProposedAction {
        let stub = StubProvider;
        let json = stub.infer(&req(text)).expect("infer should not fail");
        parse_model_output(&json).unwrap_or_else(|e| {
            panic!(
                "parse_model_output failed for input {:?}\nJSON: {}\nError: {}",
                text, json, e
            )
        })
    }

    // ------------------------------------------------------------------
    // name()
    // ------------------------------------------------------------------

    #[test]
    fn name_is_non_empty() {
        let stub = StubProvider;
        let name = stub.name();
        assert!(!name.is_empty(), "name() must return a non-empty string");
    }

    #[test]
    fn name_is_stub() {
        assert_eq!(StubProvider.name(), "stub");
    }

    // ------------------------------------------------------------------
    // Box<dyn ModelProvider> delegation
    // ------------------------------------------------------------------

    /// A `Box<dyn ModelProvider>` must delegate `name()` and `infer()` to the
    /// contained provider. This is what lets the CLI hold a runtime-selected
    /// provider and still pass it to `Orchestrator<P: ModelProvider>`.
    #[test]
    fn boxed_provider_delegates_name_and_infer() {
        let boxed: Box<dyn ModelProvider> = Box::new(StubProvider);

        // name() forwards to the inner StubProvider.
        assert_eq!(boxed.name(), "stub");

        // infer() forwards too: the boxed result equals the direct result.
        let request = req("what is using port 3000");
        let via_box = boxed.infer(&request).expect("boxed infer ok");
        let direct = StubProvider.infer(&request).expect("direct infer ok");
        assert_eq!(via_box, direct, "boxed infer must match direct infer");

        // And the boxed output still validates through the trust boundary.
        let action = parse_model_output(&via_box).expect("boxed output validates");
        assert_eq!(action.intent, Intent::FindProcessUsingPort { port: 3000 });
    }

    // ------------------------------------------------------------------
    // Port intent
    // ------------------------------------------------------------------

    #[test]
    fn port_3000_returns_find_process_using_port() {
        let action = infer_and_parse("what is using port 3000");
        assert_eq!(
            action.intent,
            Intent::FindProcessUsingPort { port: 3000 },
            "expected FindProcessUsingPort {{ port: 3000 }}"
        );
    }

    #[test]
    fn port_8080_returns_correct_port() {
        let action = infer_and_parse("show me what is listening on port 8080");
        assert_eq!(action.intent, Intent::FindProcessUsingPort { port: 8080 });
    }

    /// A firewall / port-config write must NOT be narrowed to read-only port
    /// inspection — the stub defers (clarifies) instead.
    #[test]
    fn port_config_writes_are_not_read_as_port_inspection() {
        for req in [
            "open port 3000",
            "open firewall port 3000",
            "allow incoming on port 3000",
            "forward port 3000 to 8080",
        ] {
            let action = infer_and_parse(req);
            assert!(
                matches!(action.intent, Intent::AskClarification { .. }),
                "`{req}` must defer to clarification, got {:?}",
                action.intent
            );
        }
    }

    // ------------------------------------------------------------------
    // Large files intent
    // ------------------------------------------------------------------

    #[test]
    fn biggest_files_in_downloads_returns_find_large_files_with_downloads_path() {
        let action = infer_and_parse("show me the biggest files in my Downloads folder");
        match &action.intent {
            Intent::FindLargeFiles { path, .. } => {
                assert_eq!(path, "~/Downloads", "expected ~/Downloads path");
            }
            other => panic!("expected FindLargeFiles, got {other:?}"),
        }
    }

    #[test]
    fn largest_files_here_returns_find_large_files_with_dot_path() {
        let action = infer_and_parse("find the largest files here");
        match &action.intent {
            Intent::FindLargeFiles { path, .. } => {
                assert_eq!(path, ".", "expected '.' path");
            }
            other => panic!("expected FindLargeFiles, got {other:?}"),
        }
    }

    #[test]
    fn largest_files_has_limit_10() {
        let action = infer_and_parse("find the largest files here");
        match &action.intent {
            Intent::FindLargeFiles { limit, .. } => {
                assert_eq!(*limit, Some(10));
            }
            other => panic!("expected FindLargeFiles, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Health intent
    // ------------------------------------------------------------------

    #[test]
    fn system_health_check_returns_check_system_health() {
        let action = infer_and_parse("run a system health check");
        assert_eq!(
            action.intent,
            Intent::CheckSystemHealth {},
            "expected CheckSystemHealth"
        );
    }

    #[test]
    fn diagnostic_returns_check_system_health() {
        let action = infer_and_parse("run diagnostics");
        assert_eq!(action.intent, Intent::CheckSystemHealth {});
    }

    // ------------------------------------------------------------------
    // Logs intent
    // ------------------------------------------------------------------

    #[test]
    fn recent_logs_returns_inspect_logs() {
        let action = infer_and_parse("show me recent logs");
        assert!(
            matches!(action.intent, Intent::InspectLogs { .. }),
            "expected InspectLogs, got {:?}",
            action.intent
        );
    }

    #[test]
    fn inspect_logs_has_none_fields() {
        let action = infer_and_parse("show me recent logs");
        match &action.intent {
            Intent::InspectLogs {
                source,
                since,
                filter,
            } => {
                assert!(source.is_none());
                assert!(since.is_none());
                assert!(filter.is_none());
            }
            other => panic!("expected InspectLogs, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Open intent
    // ------------------------------------------------------------------

    #[test]
    fn open_tmp_notes_returns_open_file_or_folder() {
        let action = infer_and_parse("open /tmp/notes.txt");
        assert_eq!(
            action.intent,
            Intent::OpenFileOrFolder {
                path: "/tmp/notes.txt".to_string()
            },
            "expected OpenFileOrFolder with /tmp/notes.txt"
        );
    }

    #[test]
    fn open_preserves_path_case() {
        let action = infer_and_parse("open /home/User/MyFile.txt");
        match &action.intent {
            Intent::OpenFileOrFolder { path } => {
                // Path should preserve original capitalisation.
                assert_eq!(path, "/home/User/MyFile.txt");
            }
            other => panic!("expected OpenFileOrFolder, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Unrecognized → AskClarification
    // ------------------------------------------------------------------

    #[test]
    fn fizzbuzz_wibble_returns_ask_clarification() {
        let action = infer_and_parse("fizzbuzz wibble");
        assert!(
            matches!(action.intent, Intent::AskClarification { .. }),
            "expected AskClarification, got {:?}",
            action.intent
        );
    }

    #[test]
    fn ask_clarification_has_non_empty_question() {
        let action = infer_and_parse("fizzbuzz wibble");
        match &action.intent {
            Intent::AskClarification { question, .. } => {
                assert!(!question.trim().is_empty(), "question must be non-empty");
            }
            other => panic!("expected AskClarification, got {other:?}"),
        }
    }

    #[test]
    fn ask_clarification_has_low_confidence() {
        let action = infer_and_parse("fizzbuzz wibble");
        assert!(
            action.confidence < 0.5,
            "confidence for unrecognized request should be < 0.5, got {}",
            action.confidence
        );
    }

    // ------------------------------------------------------------------
    // Round-trip: every stub output validates via parse_model_output
    // ------------------------------------------------------------------

    #[test]
    fn all_stub_outputs_parse_successfully() {
        let cases = vec![
            "what is using port 3000",
            "show me the biggest files in my Downloads folder",
            "find the largest files here",
            "run a system health check",
            "open /tmp/notes.txt",
            "show me recent logs",
            "fizzbuzz wibble",
        ];

        let stub = StubProvider;
        for case in &cases {
            let json = stub.infer(&req(case)).expect("infer should not fail");
            let result = parse_model_output(&json);
            assert!(
                result.is_ok(),
                "parse_model_output failed for {:?}\nJSON: {}\nError: {}",
                case,
                json,
                result.unwrap_err()
            );
        }
    }

    // ------------------------------------------------------------------
    // Confidence: recognised intents have confidence >= 0.5
    // ------------------------------------------------------------------

    #[test]
    fn recognised_intents_have_high_confidence() {
        let cases = vec![
            "what is using port 3000",
            "show me the biggest files in my Downloads folder",
            "run a system health check",
            "open /tmp/notes.txt",
            "show me recent logs",
        ];

        let stub = StubProvider;
        for case in &cases {
            let json = stub.infer(&req(case)).unwrap();
            let action = parse_model_output(&json).unwrap();
            assert!(
                action.confidence >= 0.5,
                "expected confidence >= 0.5 for {:?}, got {}",
                case,
                action.confidence
            );
        }
    }

    // ------------------------------------------------------------------
    // ModelRequest fields are accessible
    // ------------------------------------------------------------------

    #[test]
    fn model_request_fields_are_accessible() {
        let r = ModelRequest {
            user_request: "hello".to_string(),
            os: Os::MacOs,
            cwd: Some("/tmp".to_string()),
        };
        assert_eq!(r.user_request, "hello");
        assert_eq!(r.os, Os::MacOs);
        assert_eq!(r.cwd, Some("/tmp".to_string()));
    }

    // ------------------------------------------------------------------
    // ModelError Display
    // ------------------------------------------------------------------

    #[test]
    fn model_error_display_inference_failed() {
        let err = ModelError::InferenceFailed("oops".to_string());
        let s = err.to_string();
        assert!(s.contains("oops"), "display should include error message");
        assert!(
            s.contains("inference failed"),
            "display should mention inference"
        );
    }

    // ------------------------------------------------------------------
    // first_port_number helper
    // ------------------------------------------------------------------

    #[test]
    fn first_port_number_finds_3000() {
        assert_eq!(first_port_number("port 3000 is busy"), Some(3000));
    }

    #[test]
    fn first_port_number_rejects_zero() {
        // "0" is not a valid port (must be >= 1)
        assert_eq!(first_port_number("port 0 test"), None);
    }

    #[test]
    fn first_port_number_rejects_above_65535() {
        assert_eq!(first_port_number("port 99999 test"), None);
    }

    #[test]
    fn first_port_number_finds_first_valid() {
        // "99999" is invalid; "80" is the first valid one
        assert_eq!(first_port_number("99999 and port 80"), Some(80));
    }

    #[test]
    fn first_port_number_returns_none_for_no_digits() {
        assert_eq!(first_port_number("no numbers here"), None);
    }
}
