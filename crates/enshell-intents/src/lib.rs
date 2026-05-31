//! The typed, versioned intent catalog and parameter schemas.
//!
//! # Overview
//!
//! This crate owns:
//! - The [`Intent`] enum: all supported typed intent variants, (de)serializable to/from
//!   the model's `"intent"` + `"parameters"` JSON shape.
//! - [`ProposedAction`]: wraps an intent with model advisory metadata (risk hint,
//!   explanation, confidence, requires_confirmation).
//! - [`parse_model_output`]: entry-point to parse **and validate** model JSON into a
//!   [`ProposedAction`]. Unknown top-level and parameter fields are rejected.
//! - [`parse_model_output_unchecked`]: structural deserialization only — no domain
//!   validation, intended for internal or test use.
//! - [`IntentError`]: typed errors for parse/validation failures.
//! - [`SCHEMA_VERSION`]: the catalog version; increment on breaking changes.
//!
//! # Risk authority note
//!
//! The [`RiskHint`] field on [`ProposedAction`] is the *model's advisory suggestion*.
//! Authoritative risk classification is the responsibility of `enshell-policy`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// Schema version for the intent catalog. Increment on breaking changes.
pub const SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by intent parsing and validation.
#[derive(Debug)]
pub enum IntentError {
    /// The JSON was structurally invalid.
    MalformedJson(serde_json::Error),
    /// A required parameter was missing or empty.
    MissingParameter(&'static str),
    /// A parameter failed a range/domain check.
    InvalidParameter {
        field: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for IntentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntentError::MalformedJson(e) => write!(f, "malformed JSON: {e}"),
            IntentError::MissingParameter(field) => {
                write!(f, "missing or empty required parameter: {field}")
            }
            IntentError::InvalidParameter { field, reason } => {
                write!(f, "invalid parameter '{field}': {reason}")
            }
        }
    }
}

impl std::error::Error for IntentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IntentError::MalformedJson(e) => Some(e),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for IntentError {
    fn from(e: serde_json::Error) -> Self {
        IntentError::MalformedJson(e)
    }
}

// ---------------------------------------------------------------------------
// Advisory risk hint (non-authoritative; from model output)
// ---------------------------------------------------------------------------

/// The model's *advisory* risk hint. Unknown values deserialize to [`RiskHint::Unknown`]
/// rather than failing — authoritative classification is `enshell-policy`'s job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskHint {
    ReadOnly,
    LocalWrite,
    LocalWriteCreate,
    LocalWriteMutating,
    PackageSystem,
    Network,
    SecretsSensitive,
    Destructive,
    Privileged,
    Unsupported,
    /// Fallback for any value the model emits that we don't recognise.
    #[serde(other)]
    Unknown,
}

// ---------------------------------------------------------------------------
// Intent enum
// ---------------------------------------------------------------------------

/// All supported intent variants.
///
/// Serialized with adjacent tagging: `"intent"` holds the variant name and
/// `"parameters"` holds the variant's fields as an object.
///
/// ```json
/// { "intent": "find_process_using_port", "parameters": { "port": 3000 } }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "intent", content = "parameters", rename_all = "snake_case")]
pub enum Intent {
    FindLargeFiles {
        path: String,
        min_size: Option<String>,
        limit: Option<u32>,
    },
    FindProcessUsingPort {
        port: u16,
    },
    KillProcess {
        pid: Option<u32>,
        name: Option<String>,
        port: Option<u16>,
        force: Option<bool>,
    },
    InstallPackage {
        name: String,
        manager: Option<String>,
        version: Option<String>,
    },
    StartService {
        name: String,
    },
    StopService {
        name: String,
    },
    OpenFileOrFolder {
        path: String,
    },
    CompressFolder {
        path: String,
        output: Option<String>,
        exclude: Option<Vec<String>>,
    },
    CreateBackup {
        path: String,
        dest: Option<String>,
    },
    ExplainError {
        command: Option<String>,
        stderr: Option<String>,
        exit_code: Option<i32>,
    },
    FixLastCommand {
        last_command: String,
        exit_code: i32,
        stderr: String,
    },
    UpdatePackages {
        manager: Option<String>,
        scope: Option<String>,
    },
    CheckSystemHealth {},
    InspectLogs {
        source: Option<String>,
        since: Option<String>,
        filter: Option<String>,
    },
    CreateProject {
        kind: String,
        name: String,
        path: Option<String>,
    },
    GitCommitChanges {
        message: String,
        add_all: Option<bool>,
    },
    AskClarification {
        question: String,
        options: Option<Vec<String>>,
    },
}

impl Intent {
    /// Validate parameter constraints.
    ///
    /// Does NOT do path/shell-injection sanitization (that is `enshell-adapters/os`'s
    /// responsibility), but DOES reject:
    /// - empty required strings (name, path, message, kind, last_command, question)
    /// - port == 0
    /// - limit == 0
    /// - exit_code range (any i32 is valid at this layer)
    pub fn validate(&self) -> Result<(), IntentError> {
        match self {
            Intent::FindLargeFiles { path, limit, .. } => {
                require_nonempty_str(path, "path")?;
                if let Some(l) = limit {
                    if *l == 0 {
                        return Err(IntentError::InvalidParameter {
                            field: "limit",
                            reason: "must be > 0",
                        });
                    }
                }
            }
            Intent::FindProcessUsingPort { port } => {
                if *port == 0 {
                    return Err(IntentError::InvalidParameter {
                        field: "port",
                        reason: "must be in 1..=65535",
                    });
                }
            }
            Intent::KillProcess { port, .. } => {
                if let Some(p) = port {
                    if *p == 0 {
                        return Err(IntentError::InvalidParameter {
                            field: "port",
                            reason: "must be in 1..=65535",
                        });
                    }
                }
            }
            Intent::InstallPackage { name, .. } => {
                require_nonempty_str(name, "name")?;
            }
            Intent::StartService { name } => {
                require_nonempty_str(name, "name")?;
            }
            Intent::StopService { name } => {
                require_nonempty_str(name, "name")?;
            }
            Intent::OpenFileOrFolder { path } => {
                require_nonempty_str(path, "path")?;
            }
            Intent::CompressFolder { path, .. } => {
                require_nonempty_str(path, "path")?;
            }
            Intent::CreateBackup { path, .. } => {
                require_nonempty_str(path, "path")?;
            }
            Intent::ExplainError { .. } => {
                // All fields optional; nothing to validate at this layer.
            }
            Intent::FixLastCommand {
                last_command,
                stderr,
                ..
            } => {
                require_nonempty_str(last_command, "last_command")?;
                // stderr may legitimately be empty (the caller passes it; we allow "")
                // but last_command must not be empty per spec.
                let _ = stderr; // accepted as-is
            }
            Intent::UpdatePackages { .. } => {
                // All fields optional.
            }
            Intent::CheckSystemHealth {} => {}
            Intent::InspectLogs { .. } => {
                // All optional.
            }
            Intent::CreateProject { kind, name, .. } => {
                require_nonempty_str(kind, "kind")?;
                require_nonempty_str(name, "name")?;
            }
            Intent::GitCommitChanges { message, .. } => {
                require_nonempty_str(message, "message")?;
            }
            Intent::AskClarification { question, .. } => {
                require_nonempty_str(question, "question")?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ProposedAction — the full model output envelope
// ---------------------------------------------------------------------------

/// The complete object emitted by the model: an intent plus advisory metadata.
///
/// ```json
/// {
///   "intent": "find_process_using_port",
///   "parameters": { "port": 3000 },
///   "risk": "read_only",
///   "requires_confirmation": true,
///   "explanation": "I will check which process is listening on port 3000.",
///   "confidence": 0.86
/// }
/// ```
///
/// The intent and parameters are flattened into the top-level object via `#[serde(flatten)]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposedAction {
    /// The typed intent (adjacently tagged: `"intent"` + `"parameters"`).
    #[serde(flatten)]
    pub intent: Intent,

    /// Advisory risk hint from the model. Non-authoritative; unknown values map to
    /// [`RiskHint::Unknown`] and do NOT cause a parse failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<RiskHint>,

    /// Whether the model suggests a confirmation prompt. Defaults to `true` when absent.
    #[serde(default = "default_true")]
    pub requires_confirmation: bool,

    /// Plain-English explanation of what the intent will do.
    pub explanation: String,

    /// Model's self-reported confidence in 0.0..=1.0.
    pub confidence: f32,
}

fn default_true() -> bool {
    true
}

impl ProposedAction {
    /// Validate the proposed action: checks intent parameters and confidence range.
    pub fn validate(&self) -> Result<(), IntentError> {
        self.intent.validate()?;
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err(IntentError::InvalidParameter {
                field: "confidence",
                reason: "must be in 0.0..=1.0",
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Strict envelope for two-stage parsing (rejects unknown top-level fields)
// ---------------------------------------------------------------------------

/// Internal envelope used in stage-1 of strict parsing.
///
/// `#[serde(deny_unknown_fields)]` here rejects any top-level key that is not
/// one of the five known metadata fields plus `intent` and `parameters`. This is
/// compatible because we are NOT using `#[serde(flatten)]` in this struct.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictEnvelope {
    intent: String,
    #[serde(default)]
    parameters: Value,
    #[serde(default)]
    risk: Option<RiskHint>,
    #[serde(default = "default_true")]
    requires_confirmation: bool,
    explanation: String,
    confidence: f32,
}

// ---------------------------------------------------------------------------
// Per-variant parameter structs for strict parameter deserialization
// ---------------------------------------------------------------------------
// Each struct mirrors the fields of the corresponding Intent variant and uses
// `#[serde(deny_unknown_fields)]` so that misspelled or extra parameter keys
// are rejected.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FindLargeFilesParams {
    path: String,
    min_size: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FindProcessUsingPortParams {
    port: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KillProcessParams {
    pid: Option<u32>,
    name: Option<String>,
    port: Option<u16>,
    force: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallPackageParams {
    name: String,
    manager: Option<String>,
    version: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartServiceParams {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopServiceParams {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenFileOrFolderParams {
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompressFolderParams {
    path: String,
    output: Option<String>,
    exclude: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBackupParams {
    path: String,
    dest: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainErrorParams {
    command: Option<String>,
    stderr: Option<String>,
    exit_code: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixLastCommandParams {
    last_command: String,
    exit_code: i32,
    stderr: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdatePackagesParams {
    manager: Option<String>,
    scope: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckSystemHealthParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectLogsParams {
    source: Option<String>,
    since: Option<String>,
    filter: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateProjectParams {
    kind: String,
    name: String,
    path: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GitCommitChangesParams {
    message: String,
    add_all: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AskClarificationParams {
    question: String,
    options: Option<Vec<String>>,
}

/// Build a typed `Intent` from an intent name string and a `serde_json::Value`
/// representing the parameters object. Each variant's parameters are deserialized
/// with `deny_unknown_fields` enforced via the per-variant param structs above.
fn build_intent_strict(intent_name: &str, params: Value) -> Result<Intent, IntentError> {
    macro_rules! parse_params {
        ($T:ty) => {
            serde_json::from_value::<$T>(params).map_err(IntentError::MalformedJson)
        };
    }

    match intent_name {
        "find_large_files" => {
            let p: FindLargeFilesParams = parse_params!(FindLargeFilesParams)?;
            Ok(Intent::FindLargeFiles {
                path: p.path,
                min_size: p.min_size,
                limit: p.limit,
            })
        }
        "find_process_using_port" => {
            let p: FindProcessUsingPortParams = parse_params!(FindProcessUsingPortParams)?;
            Ok(Intent::FindProcessUsingPort { port: p.port })
        }
        "kill_process" => {
            let p: KillProcessParams = parse_params!(KillProcessParams)?;
            Ok(Intent::KillProcess {
                pid: p.pid,
                name: p.name,
                port: p.port,
                force: p.force,
            })
        }
        "install_package" => {
            let p: InstallPackageParams = parse_params!(InstallPackageParams)?;
            Ok(Intent::InstallPackage {
                name: p.name,
                manager: p.manager,
                version: p.version,
            })
        }
        "start_service" => {
            let p: StartServiceParams = parse_params!(StartServiceParams)?;
            Ok(Intent::StartService { name: p.name })
        }
        "stop_service" => {
            let p: StopServiceParams = parse_params!(StopServiceParams)?;
            Ok(Intent::StopService { name: p.name })
        }
        "open_file_or_folder" => {
            let p: OpenFileOrFolderParams = parse_params!(OpenFileOrFolderParams)?;
            Ok(Intent::OpenFileOrFolder { path: p.path })
        }
        "compress_folder" => {
            let p: CompressFolderParams = parse_params!(CompressFolderParams)?;
            Ok(Intent::CompressFolder {
                path: p.path,
                output: p.output,
                exclude: p.exclude,
            })
        }
        "create_backup" => {
            let p: CreateBackupParams = parse_params!(CreateBackupParams)?;
            Ok(Intent::CreateBackup {
                path: p.path,
                dest: p.dest,
            })
        }
        "explain_error" => {
            let p: ExplainErrorParams = parse_params!(ExplainErrorParams)?;
            Ok(Intent::ExplainError {
                command: p.command,
                stderr: p.stderr,
                exit_code: p.exit_code,
            })
        }
        "fix_last_command" => {
            let p: FixLastCommandParams = parse_params!(FixLastCommandParams)?;
            Ok(Intent::FixLastCommand {
                last_command: p.last_command,
                exit_code: p.exit_code,
                stderr: p.stderr,
            })
        }
        "update_packages" => {
            let p: UpdatePackagesParams = parse_params!(UpdatePackagesParams)?;
            Ok(Intent::UpdatePackages {
                manager: p.manager,
                scope: p.scope,
            })
        }
        "check_system_health" => {
            let _p: CheckSystemHealthParams = parse_params!(CheckSystemHealthParams)?;
            Ok(Intent::CheckSystemHealth {})
        }
        "inspect_logs" => {
            let p: InspectLogsParams = parse_params!(InspectLogsParams)?;
            Ok(Intent::InspectLogs {
                source: p.source,
                since: p.since,
                filter: p.filter,
            })
        }
        "create_project" => {
            let p: CreateProjectParams = parse_params!(CreateProjectParams)?;
            Ok(Intent::CreateProject {
                kind: p.kind,
                name: p.name,
                path: p.path,
            })
        }
        "git_commit_changes" => {
            let p: GitCommitChangesParams = parse_params!(GitCommitChangesParams)?;
            Ok(Intent::GitCommitChanges {
                message: p.message,
                add_all: p.add_all,
            })
        }
        "ask_clarification" => {
            let p: AskClarificationParams = parse_params!(AskClarificationParams)?;
            Ok(Intent::AskClarification {
                question: p.question,
                options: p.options,
            })
        }
        other => Err(IntentError::MalformedJson(
            serde::de::Error::unknown_variant(other, KNOWN_INTENT_NAMES),
        )),
    }
}

const KNOWN_INTENT_NAMES: &[&str] = &[
    "find_large_files",
    "find_process_using_port",
    "kill_process",
    "install_package",
    "start_service",
    "stop_service",
    "open_file_or_folder",
    "compress_folder",
    "create_backup",
    "explain_error",
    "fix_last_command",
    "update_packages",
    "check_system_health",
    "inspect_logs",
    "create_project",
    "git_commit_changes",
    "ask_clarification",
];

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Parse **and validate** a JSON string produced by the model into a [`ProposedAction`].
///
/// This is the recommended entry point for all callers processing untrusted LLM output.
/// It performs two checks beyond bare deserialization:
///
/// 1. **Strict schema**: unknown top-level fields and unknown parameter fields are
///    rejected with [`IntentError::MalformedJson`].
/// 2. **Domain validation**: calls [`ProposedAction::validate`], which checks
///    parameter constraints (non-empty required strings, port ranges, confidence
///    range, etc.) and returns [`IntentError::MissingParameter`] or
///    [`IntentError::InvalidParameter`] on failure.
///
/// Use [`parse_model_output_unchecked`] only in internal/test code that intentionally
/// bypasses validation.
pub fn parse_model_output(json: &str) -> Result<ProposedAction, IntentError> {
    let action = parse_model_output_unchecked(json)?;
    action.validate()?;
    Ok(action)
}

/// Parse a JSON string produced by the model into a [`ProposedAction`] **without**
/// calling [`ProposedAction::validate`].
///
/// Unknown top-level and parameter fields are still rejected (strict schema), but
/// domain constraints (empty strings, port ranges, confidence bounds, etc.) are NOT
/// checked. This is suitable for internal or test code that needs to inspect
/// structurally-valid-but-domain-invalid data.
///
/// For production use at the untrusted LLM boundary, prefer [`parse_model_output`].
pub fn parse_model_output_unchecked(json: &str) -> Result<ProposedAction, IntentError> {
    // Stage 1: strict envelope parse — rejects unknown top-level fields.
    let envelope: StrictEnvelope = serde_json::from_str(json)?;

    // Stage 2: build typed Intent from name + parameters — rejects unknown param fields.
    let intent = build_intent_strict(&envelope.intent, envelope.parameters)?;

    Ok(ProposedAction {
        intent,
        risk: envelope.risk,
        requires_confirmation: envelope.requires_confirmation,
        explanation: envelope.explanation,
        confidence: envelope.confidence,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_nonempty_str(s: &str, field: &'static str) -> Result<(), IntentError> {
    if s.trim().is_empty() {
        Err(IntentError::MissingParameter(field))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Helper: build the golden JSON from the plan doc §4 Layer 3
    // ------------------------------------------------------------------
    fn golden_json() -> &'static str {
        r#"{
            "intent": "find_process_using_port",
            "parameters": { "port": 3000 },
            "risk": "read_only",
            "requires_confirmation": true,
            "explanation": "I will check which process is listening on port 3000.",
            "confidence": 0.86
        }"#
    }

    // ------------------------------------------------------------------
    // Schema version
    // ------------------------------------------------------------------
    #[test]
    fn schema_version_is_1() {
        assert_eq!(SCHEMA_VERSION, 1);
    }

    // ------------------------------------------------------------------
    // Golden model-output parse
    // ------------------------------------------------------------------
    #[test]
    fn parse_golden_model_output() {
        let action = parse_model_output(golden_json()).expect("should parse");
        assert_eq!(action.intent, Intent::FindProcessUsingPort { port: 3000 });
        assert_eq!(action.risk, Some(RiskHint::ReadOnly));
        assert!(action.requires_confirmation);
        assert_eq!(
            action.explanation,
            "I will check which process is listening on port 3000."
        );
        assert!((action.confidence - 0.86).abs() < 1e-4);
    }

    // ------------------------------------------------------------------
    // Round-trip: every variant
    // ------------------------------------------------------------------

    fn roundtrip(intent: &Intent) {
        // Wrap in a ProposedAction to get the full wire shape
        let action = ProposedAction {
            intent: intent.clone(),
            risk: None,
            requires_confirmation: false,
            explanation: "test".to_string(),
            confidence: 0.9,
        };
        let json = serde_json::to_string(&action).expect("serialize");
        let back: ProposedAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&back.intent, intent, "round-trip failed for: {json}");
    }

    #[test]
    fn roundtrip_find_large_files() {
        roundtrip(&Intent::FindLargeFiles {
            path: "/home/user".to_string(),
            min_size: Some("500M".to_string()),
            limit: Some(10),
        });
    }

    #[test]
    fn roundtrip_find_process_using_port() {
        roundtrip(&Intent::FindProcessUsingPort { port: 8080 });
    }

    #[test]
    fn roundtrip_kill_process() {
        roundtrip(&Intent::KillProcess {
            pid: Some(1234),
            name: None,
            port: None,
            force: Some(true),
        });
    }

    #[test]
    fn roundtrip_install_package() {
        roundtrip(&Intent::InstallPackage {
            name: "ripgrep".to_string(),
            manager: Some("brew".to_string()),
            version: None,
        });
    }

    #[test]
    fn roundtrip_start_service() {
        roundtrip(&Intent::StartService {
            name: "postgresql".to_string(),
        });
    }

    #[test]
    fn roundtrip_stop_service() {
        roundtrip(&Intent::StopService {
            name: "nginx".to_string(),
        });
    }

    #[test]
    fn roundtrip_open_file_or_folder() {
        roundtrip(&Intent::OpenFileOrFolder {
            path: "/tmp/foo".to_string(),
        });
    }

    #[test]
    fn roundtrip_compress_folder() {
        roundtrip(&Intent::CompressFolder {
            path: "/projects/app".to_string(),
            output: Some("/tmp/app.tar.gz".to_string()),
            exclude: Some(vec!["node_modules".to_string(), ".git".to_string()]),
        });
    }

    #[test]
    fn roundtrip_create_backup() {
        roundtrip(&Intent::CreateBackup {
            path: "/data".to_string(),
            dest: Some("/backups/data-2024".to_string()),
        });
    }

    #[test]
    fn roundtrip_explain_error() {
        roundtrip(&Intent::ExplainError {
            command: Some("cargo build".to_string()),
            stderr: Some("error[E0308]: mismatched types".to_string()),
            exit_code: Some(101),
        });
    }

    #[test]
    fn roundtrip_fix_last_command() {
        roundtrip(&Intent::FixLastCommand {
            last_command: "gti status".to_string(),
            exit_code: 127,
            stderr: "command not found: gti".to_string(),
        });
    }

    #[test]
    fn roundtrip_update_packages() {
        roundtrip(&Intent::UpdatePackages {
            manager: Some("apt".to_string()),
            scope: None,
        });
    }

    #[test]
    fn roundtrip_check_system_health() {
        roundtrip(&Intent::CheckSystemHealth {});
    }

    #[test]
    fn roundtrip_inspect_logs() {
        roundtrip(&Intent::InspectLogs {
            source: Some("system".to_string()),
            since: Some("1h".to_string()),
            filter: Some("error".to_string()),
        });
    }

    #[test]
    fn roundtrip_create_project() {
        roundtrip(&Intent::CreateProject {
            kind: "nextjs".to_string(),
            name: "my-app".to_string(),
            path: Some("/projects".to_string()),
        });
    }

    #[test]
    fn roundtrip_git_commit_changes() {
        roundtrip(&Intent::GitCommitChanges {
            message: "fix: correct off-by-one".to_string(),
            add_all: Some(true),
        });
    }

    #[test]
    fn roundtrip_ask_clarification_with_options() {
        roundtrip(&Intent::AskClarification {
            question: "Which package manager should I use?".to_string(),
            options: Some(vec!["brew".to_string(), "npm".to_string()]),
        });
    }

    #[test]
    fn roundtrip_ask_clarification_without_options() {
        roundtrip(&Intent::AskClarification {
            question: "Can you be more specific?".to_string(),
            options: None,
        });
    }

    // ------------------------------------------------------------------
    // ask_clarification parsing (with and without options)
    // ------------------------------------------------------------------
    #[test]
    fn parse_ask_clarification_with_options() {
        let json = r#"{
            "intent": "ask_clarification",
            "parameters": { "question": "Which manager?", "options": ["brew", "apt"] },
            "explanation": "Need more info.",
            "confidence": 0.5
        }"#;
        let action = parse_model_output(json).expect("should parse");
        assert_eq!(
            action.intent,
            Intent::AskClarification {
                question: "Which manager?".to_string(),
                options: Some(vec!["brew".to_string(), "apt".to_string()]),
            }
        );
    }

    #[test]
    fn parse_ask_clarification_without_options() {
        let json = r#"{
            "intent": "ask_clarification",
            "parameters": { "question": "Can you clarify?" },
            "explanation": "Unclear.",
            "confidence": 0.3
        }"#;
        let action = parse_model_output(json).expect("should parse");
        assert_eq!(
            action.intent,
            Intent::AskClarification {
                question: "Can you clarify?".to_string(),
                options: None,
            }
        );
    }

    // ------------------------------------------------------------------
    // Unknown risk hint must NOT fail parsing
    // ------------------------------------------------------------------
    #[test]
    fn unknown_risk_hint_does_not_fail_parse() {
        let json = r#"{
            "intent": "check_system_health",
            "parameters": {},
            "risk": "totally_made_up_tier",
            "explanation": "check health",
            "confidence": 0.9
        }"#;
        let action = parse_model_output(json).expect("should parse with unknown risk");
        assert_eq!(action.risk, Some(RiskHint::Unknown));
    }

    // ------------------------------------------------------------------
    // Reject: unknown intent name
    // ------------------------------------------------------------------
    #[test]
    fn reject_unknown_intent_name() {
        let json = r#"{
            "intent": "do_something_wild",
            "parameters": {},
            "explanation": "???",
            "confidence": 0.9
        }"#;
        let err = parse_model_output(json).expect_err("should fail on unknown intent");
        assert!(
            matches!(err, IntentError::MalformedJson(_)),
            "expected MalformedJson, got: {err}"
        );
    }

    // ------------------------------------------------------------------
    // Reject: malformed JSON
    // ------------------------------------------------------------------
    #[test]
    fn reject_malformed_json() {
        let err = parse_model_output("{not valid json}").expect_err("should fail");
        assert!(matches!(err, IntentError::MalformedJson(_)));
    }

    // ------------------------------------------------------------------
    // Reject: missing required parameter (empty required string)
    // (These use validate() directly since they test domain logic, not parse)
    // ------------------------------------------------------------------
    #[test]
    fn reject_empty_path_in_find_large_files() {
        let intent = Intent::FindLargeFiles {
            path: "".to_string(),
            min_size: None,
            limit: None,
        };
        let err = intent.validate().expect_err("empty path should fail");
        assert!(matches!(err, IntentError::MissingParameter("path")));
    }

    #[test]
    fn reject_whitespace_only_path() {
        let intent = Intent::FindLargeFiles {
            path: "   ".to_string(),
            min_size: None,
            limit: None,
        };
        let err = intent.validate().expect_err("whitespace path should fail");
        assert!(matches!(err, IntentError::MissingParameter("path")));
    }

    #[test]
    fn reject_empty_name_in_install_package() {
        let intent = Intent::InstallPackage {
            name: "".to_string(),
            manager: None,
            version: None,
        };
        let err = intent.validate().expect_err("empty name should fail");
        assert!(matches!(err, IntentError::MissingParameter("name")));
    }

    #[test]
    fn reject_empty_name_in_start_service() {
        let intent = Intent::StartService {
            name: "".to_string(),
        };
        let err = intent.validate().expect_err("empty name should fail");
        assert!(matches!(err, IntentError::MissingParameter("name")));
    }

    #[test]
    fn reject_empty_message_in_git_commit() {
        let intent = Intent::GitCommitChanges {
            message: "".to_string(),
            add_all: None,
        };
        let err = intent.validate().expect_err("empty message should fail");
        assert!(matches!(err, IntentError::MissingParameter("message")));
    }

    #[test]
    fn reject_empty_question_in_ask_clarification() {
        let intent = Intent::AskClarification {
            question: "".to_string(),
            options: None,
        };
        let err = intent.validate().expect_err("empty question should fail");
        assert!(matches!(err, IntentError::MissingParameter("question")));
    }

    #[test]
    fn reject_empty_kind_in_create_project() {
        let intent = Intent::CreateProject {
            kind: "".to_string(),
            name: "my-app".to_string(),
            path: None,
        };
        let err = intent.validate().expect_err("empty kind should fail");
        assert!(matches!(err, IntentError::MissingParameter("kind")));
    }

    #[test]
    fn reject_empty_last_command_in_fix_last_command() {
        let intent = Intent::FixLastCommand {
            last_command: "".to_string(),
            exit_code: 1,
            stderr: "error".to_string(),
        };
        let err = intent
            .validate()
            .expect_err("empty last_command should fail");
        assert!(matches!(err, IntentError::MissingParameter("last_command")));
    }

    // ------------------------------------------------------------------
    // Reject: port 0
    // ------------------------------------------------------------------
    #[test]
    fn reject_port_zero_in_find_process_using_port() {
        let intent = Intent::FindProcessUsingPort { port: 0 };
        let err = intent.validate().expect_err("port 0 should fail");
        assert!(
            matches!(err, IntentError::InvalidParameter { field: "port", .. }),
            "expected InvalidParameter for port, got: {err}"
        );
    }

    #[test]
    fn reject_port_zero_in_kill_process() {
        let intent = Intent::KillProcess {
            pid: None,
            name: None,
            port: Some(0),
            force: None,
        };
        let err = intent.validate().expect_err("port 0 should fail");
        assert!(matches!(
            err,
            IntentError::InvalidParameter { field: "port", .. }
        ));
    }

    // ------------------------------------------------------------------
    // Reject: limit == 0
    // ------------------------------------------------------------------
    #[test]
    fn reject_limit_zero_in_find_large_files() {
        let intent = Intent::FindLargeFiles {
            path: "/tmp".to_string(),
            min_size: None,
            limit: Some(0),
        };
        let err = intent.validate().expect_err("limit 0 should fail");
        assert!(matches!(
            err,
            IntentError::InvalidParameter { field: "limit", .. }
        ));
    }

    // ------------------------------------------------------------------
    // Reject: confidence out of range
    // ------------------------------------------------------------------
    #[test]
    fn reject_confidence_above_1() {
        let action = ProposedAction {
            intent: Intent::CheckSystemHealth {},
            risk: None,
            requires_confirmation: false,
            explanation: "ok".to_string(),
            confidence: 1.5,
        };
        let err = action.validate().expect_err("confidence > 1 should fail");
        assert!(matches!(
            err,
            IntentError::InvalidParameter {
                field: "confidence",
                ..
            }
        ));
    }

    #[test]
    fn reject_confidence_below_0() {
        let action = ProposedAction {
            intent: Intent::CheckSystemHealth {},
            risk: None,
            requires_confirmation: false,
            explanation: "ok".to_string(),
            confidence: -0.1,
        };
        let err = action.validate().expect_err("confidence < 0 should fail");
        assert!(matches!(
            err,
            IntentError::InvalidParameter {
                field: "confidence",
                ..
            }
        ));
    }

    #[test]
    fn accept_confidence_at_boundaries() {
        for c in [0.0_f32, 1.0_f32] {
            let action = ProposedAction {
                intent: Intent::CheckSystemHealth {},
                risk: None,
                requires_confirmation: false,
                explanation: "ok".to_string(),
                confidence: c,
            };
            action
                .validate()
                .unwrap_or_else(|e| panic!("confidence {c} should be valid, got: {e}"));
        }
    }

    // ------------------------------------------------------------------
    // Valid positive cases: validate() accepts good inputs
    // ------------------------------------------------------------------
    #[test]
    fn valid_find_process_using_port() {
        Intent::FindProcessUsingPort { port: 3000 }
            .validate()
            .expect("port 3000 should be valid");
    }

    #[test]
    fn valid_find_process_using_port_max() {
        Intent::FindProcessUsingPort { port: 65535 }
            .validate()
            .expect("port 65535 should be valid");
    }

    #[test]
    fn valid_find_process_using_port_min() {
        Intent::FindProcessUsingPort { port: 1 }
            .validate()
            .expect("port 1 should be valid");
    }

    #[test]
    fn valid_find_large_files_with_limit() {
        Intent::FindLargeFiles {
            path: "/home".to_string(),
            min_size: None,
            limit: Some(5),
        }
        .validate()
        .expect("limit 5 should be valid");
    }

    #[test]
    fn valid_check_system_health() {
        Intent::CheckSystemHealth {}
            .validate()
            .expect("no params to fail");
    }

    #[test]
    fn valid_proposed_action() {
        let action = ProposedAction {
            intent: Intent::FindProcessUsingPort { port: 8080 },
            risk: Some(RiskHint::ReadOnly),
            requires_confirmation: true,
            explanation: "Check port 8080".to_string(),
            confidence: 0.95,
        };
        action.validate().expect("should be valid");
    }

    // ------------------------------------------------------------------
    // requires_confirmation defaults to true when absent in JSON
    // ------------------------------------------------------------------
    #[test]
    fn requires_confirmation_defaults_to_true() {
        let json = r#"{
            "intent": "check_system_health",
            "parameters": {},
            "explanation": "health check",
            "confidence": 0.8
        }"#;
        let action = parse_model_output(json).expect("should parse");
        assert!(action.requires_confirmation, "should default to true");
    }

    // ------------------------------------------------------------------
    // IntentError: Display impl is meaningful
    // ------------------------------------------------------------------
    #[test]
    fn intent_error_display_missing_parameter() {
        let err = IntentError::MissingParameter("path");
        assert!(err.to_string().contains("path"));
    }

    #[test]
    fn intent_error_display_invalid_parameter() {
        let err = IntentError::InvalidParameter {
            field: "port",
            reason: "must be > 0",
        };
        let s = err.to_string();
        assert!(s.contains("port"));
        assert!(s.contains("must be > 0"));
    }

    #[test]
    fn intent_error_display_malformed_json() {
        let err = parse_model_output("{{").expect_err("should fail");
        let s = err.to_string();
        assert!(s.contains("malformed JSON"));
    }

    // ------------------------------------------------------------------
    // Fix 1: parse_model_output now validates — domain-invalid data rejected
    // ------------------------------------------------------------------

    /// parse_model_output rejects structurally-valid-but-domain-invalid JSON
    /// (port == 0 is valid JSON / structural, but invalid domain-wise).
    #[test]
    fn parse_model_output_rejects_domain_invalid_port_zero() {
        let json = r#"{
            "intent": "find_process_using_port",
            "parameters": { "port": 0 },
            "explanation": "check port 0",
            "confidence": 0.9
        }"#;
        let err = parse_model_output(json).expect_err("port 0 should be rejected");
        assert!(
            matches!(err, IntentError::InvalidParameter { field: "port", .. }),
            "expected InvalidParameter for port, got: {err}"
        );
    }

    /// parse_model_output_unchecked allows domain-invalid data through (for testing).
    #[test]
    fn parse_model_output_unchecked_allows_domain_invalid_port_zero() {
        let json = r#"{
            "intent": "find_process_using_port",
            "parameters": { "port": 0 },
            "explanation": "check port 0",
            "confidence": 0.9
        }"#;
        let action = parse_model_output_unchecked(json)
            .expect("unchecked should accept structurally-valid-but-domain-invalid JSON");
        assert_eq!(action.intent, Intent::FindProcessUsingPort { port: 0 });
    }

    /// parse_model_output_unchecked allows confidence out of range.
    #[test]
    fn parse_model_output_unchecked_allows_out_of_range_confidence() {
        let json = r#"{
            "intent": "check_system_health",
            "parameters": {},
            "explanation": "x",
            "confidence": 9.9
        }"#;
        let action =
            parse_model_output_unchecked(json).expect("unchecked should allow confidence > 1");
        assert!((action.confidence - 9.9).abs() < 1e-4);
    }

    // ------------------------------------------------------------------
    // Fix 2: strict schema — reject unknown fields
    // ------------------------------------------------------------------

    /// Extra top-level field must be rejected.
    #[test]
    fn reject_extra_top_level_field() {
        let json = r#"{
            "intent": "find_process_using_port",
            "parameters": { "port": 3000 },
            "explanation": "x",
            "confidence": 0.9,
            "bogus": true
        }"#;
        let err = parse_model_output(json).expect_err("extra top-level field should be rejected");
        assert!(
            matches!(err, IntentError::MalformedJson(_)),
            "expected MalformedJson, got: {err}"
        );
    }

    /// Extra parameter field must be rejected.
    #[test]
    fn reject_extra_parameter_field() {
        let json = r#"{
            "intent": "find_process_using_port",
            "parameters": { "port": 3000, "prt": 1 },
            "explanation": "x",
            "confidence": 0.9
        }"#;
        let err = parse_model_output(json).expect_err("extra parameter field should be rejected");
        assert!(
            matches!(err, IntentError::MalformedJson(_)),
            "expected MalformedJson, got: {err}"
        );
    }

    /// Misspelled parameter key must be rejected (e.g. "pth" instead of "path").
    #[test]
    fn reject_misspelled_parameter_field() {
        let json = r#"{
            "intent": "find_large_files",
            "parameters": { "pth": "/tmp", "min_size": null },
            "explanation": "x",
            "confidence": 0.9
        }"#;
        let err =
            parse_model_output(json).expect_err("misspelled parameter field should be rejected");
        assert!(
            matches!(err, IntentError::MalformedJson(_)),
            "expected MalformedJson, got: {err}"
        );
    }

    /// A well-formed object with all valid fields still parses correctly.
    #[test]
    fn accept_well_formed_object_with_all_valid_fields() {
        let json = r#"{
            "intent": "find_process_using_port",
            "parameters": { "port": 3000 },
            "risk": "read_only",
            "requires_confirmation": false,
            "explanation": "Checking which process uses port 3000.",
            "confidence": 0.95
        }"#;
        let action = parse_model_output(json).expect("fully valid object should parse");
        assert_eq!(action.intent, Intent::FindProcessUsingPort { port: 3000 });
        assert_eq!(action.risk, Some(RiskHint::ReadOnly));
        assert!(!action.requires_confirmation);
        assert!((action.confidence - 0.95).abs() < 1e-4);
    }

    /// Extra top-level field is also rejected by parse_model_output_unchecked
    /// (strict schema is enforced at both entry points).
    #[test]
    fn unchecked_also_rejects_extra_top_level_field() {
        let json = r#"{
            "intent": "check_system_health",
            "parameters": {},
            "explanation": "x",
            "confidence": 0.9,
            "sneaky": "injection"
        }"#;
        let err = parse_model_output_unchecked(json)
            .expect_err("unchecked should also reject unknown top-level fields");
        assert!(matches!(err, IntentError::MalformedJson(_)));
    }
}
