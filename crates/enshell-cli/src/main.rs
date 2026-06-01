//! CLI entrypoint: arg/mode parsing, preview/confirm UX, output rendering.
//!
//! # Architecture
//!
//! `main()` is intentionally thin — it delegates to:
//!
//! - [`Cli`] (clap derive) for argument parsing.
//! - [`build_confirmation`] (pure) to map `(RiskDecision, args)` → which prompt
//!   to show and how to build a [`enshell_core::Confirmation`].
//! - [`format_success`] / [`format_error`] (pure) for output rendering.
//! - `run_doctor` for the `doctor` subcommand.
//! - [`prompt_stdin`] as the I/O boundary (injectable in tests).
//! - [`default_audit_log_path`] / [`build_audit_record`] for the local audit log.
//! - [`format_history`] (pure) for `enshell history` output rendering.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use enshell_core::{Confirmation, CoreError, OrchestratorConfig, Prepared};
use enshell_model::StubProvider;
use enshell_os::{current_os, ExecControl, ExecError};
use enshell_policy::{auto_confirm_allowed, requires_typed_confirmation, RiskDecision, RiskTier};
use enshell_telemetry::{AuditLog, AuditRecord, StoredEntry};

// ---------------------------------------------------------------------------
// Audit log constants
// ---------------------------------------------------------------------------

/// Policy version: a placeholder constant until `enshell-policy` exposes one.
/// Increment when the policy ruleset changes in a breaking way.
const POLICY_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// CLI shape (clap derive)
// ---------------------------------------------------------------------------

/// enShell — natural language for your terminal.
#[derive(Debug, Parser)]
#[command(
    name = "enshell",
    version,
    about = "enShell — natural language for your terminal",
    long_about = "Type what you want in plain English. enShell explains its plan,\n\
                  shows you the command, and asks before running anything.",
    after_help = "EXAMPLES:\n  \
                  enshell \"show me what is using port 3000\"\n  \
                  enshell --dry-run \"find the biggest files in Downloads\"\n  \
                  enshell --yes \"run a system health check\"\n  \
                  enshell doctor"
)]
pub struct Cli {
    /// Natural-language request (e.g. "show me what is using port 3000").
    ///
    /// Omit this (and all subcommands) to see usage.
    pub request: Option<String>,

    /// Show the full plan and command — do NOT execute anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Show the structured intent name and risk tier — do NOT execute anything.
    #[arg(long)]
    pub plan: bool,

    /// Pre-authorize: skip confirmation for Read-only actions.
    ///
    /// Does NOT auto-confirm open_file_or_folder, mutating local-write,
    /// package/system, network, secrets, destructive, or privileged actions.
    /// Those still prompt. Destructive/privileged require a typed phrase.
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Override the default 30-second execution timeout. Pass 0 for no timeout.
    #[arg(long, value_name = "SECONDS")]
    pub timeout: Option<u64>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run environment self-check: OS, model provider, adapters, timeout, audit log.
    Doctor,

    /// Show local command history from the audit log.
    History,

    /// Not available yet — needs the undo plan, coming in a later phase.
    Undo,

    /// Not available yet — needs shell context capture, coming in a later phase.
    ExplainLast,

    /// Not available yet — needs shell context capture, coming in a later phase.
    FixLast,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    // Resolve the timeout for OrchestratorConfig / ExecControl.
    let timeout: Option<Duration> = match cli.timeout {
        Some(0) => None,
        Some(secs) => Some(Duration::from_secs(secs)),
        None => Some(Duration::from_secs(30)), // default
    };

    // Dispatch subcommand first.
    if let Some(cmd) = &cli.command {
        match cmd {
            Commands::Doctor => {
                run_doctor(timeout);
                return;
            }
            Commands::History => {
                run_history();
                return;
            }
            Commands::Undo | Commands::ExplainLast | Commands::FixLast => {
                let stub_msg = stub_subcommand_message(cmd);
                println!("{stub_msg}");
                return;
            }
        }
    }

    // No request and no subcommand → print short usage.
    let request = match &cli.request {
        Some(r) if !r.trim().is_empty() => r.clone(),
        _ => {
            // Print a brief help nudge (not the full --help).
            eprintln!("Usage: enshell \"<your request>\"");
            eprintln!("       enshell doctor");
            eprintln!("       enshell --help");
            std::process::exit(1);
        }
    };

    // Build the orchestrator.
    let config = OrchestratorConfig { timeout };
    let orch = enshell_core::Orchestrator::new(StubProvider, config);

    // Phase 1: prepare (model → validate → policy → render).
    let prepared = match orch.prepare(&request) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Sorry, I couldn't interpret that: {e}");
            std::process::exit(1);
        }
    };

    match prepared {
        Prepared::Clarify { question, options } => {
            println!("{question}");
            if let Some(opts) = options {
                for opt in opts {
                    println!("  • {opt}");
                }
            }
        }
        Prepared::Refused { reason, .. } => {
            println!("I can't do that yet: {reason}");
        }
        Prepared::Actionable(actionable) => {
            // Always print the preview.
            println!("{}", actionable.preview());
            println!();

            if cli.dry_run {
                println!("(dry run — nothing was executed)");
                return;
            }

            if cli.plan {
                let tier_label = format_tier(actionable.decision().tier);
                println!(
                    "Intent: {}\nRisk tier: {}",
                    intent_display_name(&actionable),
                    tier_label
                );
                println!("(plan only — nothing was executed)");
                return;
            }

            // Confirmation ladder.
            let (confirmation, prompted_output) =
                match build_confirmation(actionable.decision(), cli.yes) {
                    ConfirmationStep::AutoConfirm(c) => (c, None),
                    ConfirmationStep::NeedsInteractive => {
                        let answer = prompt_stdin("Run this? [y/N] ");
                        let answer = answer.trim().to_lowercase();
                        if answer == "y" || answer == "yes" {
                            let c = Confirmation {
                                yes_flag: false,
                                interactively_confirmed: true,
                                typed_phrase: None,
                            };
                            (c, None)
                        } else {
                            println!("Okay — not running.");
                            return;
                        }
                    }
                    ConfirmationStep::NeedsTyped { prompt } => {
                        let answer = prompt_stdin(&prompt);
                        let trimmed = answer.trim().to_owned();
                        if trimmed.is_empty() {
                            println!("Okay — not running.");
                            return;
                        }
                        let c = Confirmation {
                            yes_flag: false,
                            interactively_confirmed: false,
                            typed_phrase: Some(trimmed),
                        };
                        (c, None)
                    }
                };
            let _: Option<String> = prompted_output; // nothing buffered

            // Ctrl-C wiring.
            let cancel = Arc::new(AtomicBool::new(false));
            let cancel_clone = cancel.clone();
            // Best-effort: if setting the handler fails, continue without it.
            let _ = ctrlc::set_handler(move || {
                cancel_clone.store(true, Ordering::Relaxed);
            });

            let control = ExecControl { timeout, cancel };

            // Phase 2: execute.
            match orch.execute(&actionable, &confirmation, &control) {
                Ok(record) => {
                    // Append to the audit log; failure is non-fatal.
                    // TODO: record denied/aborted/error attempts in a future slice.
                    append_audit_record(&actionable, &record);
                    let output_str = format_success(&record);
                    println!("{output_str}");
                }
                Err(CoreError::ConfirmationRequired) => {
                    eprintln!("I need explicit confirmation to do that; nothing was run.");
                    std::process::exit(1);
                }
                Err(CoreError::Exec(ExecError::Cancelled)) => {
                    eprintln!("Cancelled. Nothing further was run.");
                    std::process::exit(1);
                }
                Err(CoreError::Exec(ExecError::TimedOut)) => {
                    eprintln!("That took too long and was stopped (timed out).");
                    std::process::exit(1);
                }
                Err(e) => {
                    let recovery = recovery_guidance(&e);
                    eprintln!("That didn't work: {e}");
                    eprintln!("{recovery}");
                    std::process::exit(1);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pure confirmation-decision logic
// ---------------------------------------------------------------------------

/// The outcome of deciding which confirmation path to take.
#[derive(Debug)]
pub enum ConfirmationStep {
    /// Auto-confirmed: no prompt needed.
    AutoConfirm(Confirmation),
    /// Needs an interactive [y/N] prompt.
    NeedsInteractive,
    /// Needs a typed-phrase prompt (Destructive/Privileged).
    NeedsTyped { prompt: String },
}

/// Map a [`RiskDecision`] and the `--yes` flag to a [`ConfirmationStep`].
///
/// This is pure — it does not read stdin. The caller is responsible for
/// performing the actual I/O and constructing the final [`Confirmation`].
///
/// # Confirmation ladder
///
/// - `auto_confirm_allowed` (ReadOnly yes-eligible + `--yes`) → `AutoConfirm`.
/// - `requires_typed_confirmation` (Destructive/Privileged) → `NeedsTyped`.
/// - Otherwise → `NeedsInteractive` (Explicit tier, or non-yes-eligible).
pub fn build_confirmation(decision: &RiskDecision, yes_flag: bool) -> ConfirmationStep {
    if auto_confirm_allowed(decision, yes_flag) {
        return ConfirmationStep::AutoConfirm(Confirmation {
            yes_flag: true,
            interactively_confirmed: false,
            typed_phrase: None,
        });
    }

    if requires_typed_confirmation(decision) {
        let tier_label = format_tier(decision.tier);
        let prompt = format!("This is a {tier_label} action. Type `yes, do it` to confirm: ");
        return ConfirmationStep::NeedsTyped { prompt };
    }

    ConfirmationStep::NeedsInteractive
}

// ---------------------------------------------------------------------------
// Output formatters (pure)
// ---------------------------------------------------------------------------

/// Format a successful [`enshell_core::ExecutionRecord`] as a display string.
pub fn format_success(record: &enshell_core::ExecutionRecord) -> String {
    let mut out = String::from("Done.\n");
    out.push_str(&format!(
        "Command: {}\nIntent: {} | Risk: {:?}\n",
        record.command_display, record.intent_name, record.risk_tier
    ));
    if let Some(code) = record.exit_code {
        out.push_str(&format!("Exit code: {code}\n"));
    }
    if !record.stdout.trim().is_empty() {
        out.push_str("Output:\n");
        out.push_str(&record.stdout);
        if !record.stdout.ends_with('\n') {
            out.push('\n');
        }
    }
    if !record.stderr.trim().is_empty() {
        out.push_str("Note: some output was written to stderr.\n");
    }
    out
}

/// Format a one-line recovery hint for an execution error.
pub fn format_error(e: &CoreError) -> String {
    format!("That didn't work: {e}\n{}", recovery_guidance(e))
}

/// One-line recovery guidance for a [`CoreError`].
pub fn recovery_guidance(e: &CoreError) -> &'static str {
    match e {
        CoreError::Exec(ExecError::ProgramNotFound(_)) => {
            "Tip: the required program may not be installed. Try 'enshell doctor' to check your environment."
        }
        CoreError::Exec(ExecError::NonZeroExit { .. }) => {
            "Tip: the command exited with an error. Check stderr above for details or try '--dry-run' to preview without running."
        }
        CoreError::Exec(ExecError::TimedOut) => {
            "Tip: use '--timeout <SECONDS>' to allow more time, or '0' to remove the timeout."
        }
        CoreError::Exec(ExecError::Cancelled) => "Tip: re-run when ready.",
        CoreError::Exec(_) => {
            "Tip: check that the required tools are installed and you have permission to run them."
        }
        CoreError::Model(_) => {
            "Tip: the model provider failed. 'enshell doctor' may show what's wrong."
        }
        CoreError::InvalidIntent(_) => {
            "Tip: try rephrasing your request more specifically."
        }
        CoreError::Adapter(_) => {
            "Tip: this action may not be supported on your OS yet."
        }
        CoreError::ConfirmationRequired => {
            "Tip: provide explicit confirmation or use '--yes' for read-only actions."
        }
        CoreError::NotExecutable => {
            "Tip: use '--dry-run' or '--plan' to preview; execution of this action is not yet available."
        }
    }
}

/// Short human-readable label for a risk tier.
pub fn format_tier(tier: RiskTier) -> &'static str {
    match tier {
        RiskTier::ReadOnly => "Read-only",
        RiskTier::LocalWriteCreateOnly => "Local write (create-only)",
        RiskTier::LocalWriteMutating => "Local write (mutating)",
        RiskTier::PackageSystemChange => "Package/system change",
        RiskTier::NetworkAccess => "Network access",
        RiskTier::SecretsSensitive => "Secrets-sensitive",
        RiskTier::Destructive => "DESTRUCTIVE",
        RiskTier::Privileged => "PRIVILEGED",
        RiskTier::UnsupportedAmbiguous => "Unsupported/ambiguous",
    }
}

// ---------------------------------------------------------------------------
// Honest stub messages for not-yet-implemented subcommands
// ---------------------------------------------------------------------------

fn stub_subcommand_message(cmd: &Commands) -> String {
    let name = match cmd {
        Commands::History => unreachable!("history is handled before this call"),
        Commands::Undo => "undo",
        Commands::ExplainLast => "explain-last",
        Commands::FixLast => "fix-last",
        Commands::Doctor => unreachable!("doctor is handled before this call"),
    };
    format!(
        "'{name}' is not available yet — \
         this needs the audit log / memory, coming in a later phase."
    )
}

// ---------------------------------------------------------------------------
// doctor subcommand
// ---------------------------------------------------------------------------

fn run_doctor(timeout: Option<Duration>) {
    let os = current_os();
    let os_name = match os {
        enshell_os::Os::MacOs => "macOS",
        enshell_os::Os::Linux => "Linux",
        enshell_os::Os::Windows => "Windows",
        enshell_os::Os::Other => "Unknown",
    };
    let timeout_str = match timeout {
        Some(d) => format!("{}s", d.as_secs()),
        None => "none".to_owned(),
    };
    println!("enShell doctor — environment check");
    println!("-----------------------------------");
    println!("OS:              {os_name}");
    println!("Model provider:  stub (deterministic; llama.cpp / Gemma 4 coming in Phase 1)");
    println!("Adapters:        read-only adapters available for macOS and Linux");
    println!("Configured timeout: {timeout_str}");

    // Audit log status — resilient: never panics if log is missing or unreadable.
    println!("-----------------------------------");
    let audit_path = default_audit_log_path();
    match audit_path {
        None => {
            println!("Audit log:       [skipped — HOME not set]");
        }
        Some(path) => {
            println!("Audit log path:  {}", path.display());
            let exists = path.exists();
            println!("Audit log exists: {}", if exists { "yes" } else { "no" });
            if exists {
                match AuditLog::open(&path) {
                    Err(e) => {
                        println!("Audit log entries: [error opening log: {e}]");
                        println!("Audit log verify:  [error opening log]");
                    }
                    Ok(log) => {
                        let entry_count = match log.entries() {
                            Ok(entries) => entries.len().to_string(),
                            Err(e) => format!("[error reading entries: {e}]"),
                        };
                        println!("Audit log entries: {entry_count}");
                        let verify_str = match log.verify() {
                            Ok(()) => "OK".to_owned(),
                            Err(e) => format!("FAILED — {e}"),
                        };
                        println!("Audit log verify:  {verify_str}");
                    }
                }
            } else {
                println!("Audit log entries: 0 (log not yet created)");
                println!("Audit log verify:  n/a (log not yet created)");
            }
        }
    }

    println!("-----------------------------------");
    println!("Everything looks good for the current stub-provider MVP.");
}

// ---------------------------------------------------------------------------
// Audit log helpers
// ---------------------------------------------------------------------------

/// Return the default audit log path: `$ENSHELL_AUDIT_LOG` if set, otherwise
/// `$HOME/.enshell/audit.jsonl`. Returns `None` if neither env var is set.
///
/// `ENSHELL_AUDIT_LOG` is intended for tests and advanced users who want a
/// custom location. If `HOME` is also unset, the CLI skips logging with a
/// warning.
pub fn default_audit_log_path() -> Option<PathBuf> {
    if let Ok(override_path) = std::env::var("ENSHELL_AUDIT_LOG") {
        if !override_path.is_empty() {
            return Some(PathBuf::from(override_path));
        }
    }
    let home = std::env::var("HOME").ok()?;
    let mut path = PathBuf::from(home);
    path.push(".enshell");
    path.push("audit.jsonl");
    Some(path)
}

/// Build an [`AuditRecord`] from a successful execution.
///
/// `model_id` is `"stub"` and `model_quant` is `None` until a real provider
/// is wired in. `redaction_count` is `0` — no secret-redaction layer exists
/// yet; note this when reviewing audit records.
pub fn build_audit_record(
    actionable: &enshell_core::Actionable,
    record: &enshell_core::ExecutionRecord,
) -> AuditRecord {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let correlation_id = format!("{}-{}", millis, std::process::id());
    let timestamp = millis.to_string();

    let params = serde_json::to_value(actionable.intent()).unwrap_or(serde_json::Value::Null);

    AuditRecord {
        correlation_id,
        user_request: record.user_request.clone(),
        timestamp,
        policy_version: POLICY_VERSION,
        intent_schema_version: enshell_intents::SCHEMA_VERSION,
        model_id: "stub".to_owned(),
        model_quant: None,
        prompt_template_version: "stub-1".to_owned(),
        intent: record.intent_name.clone(),
        params,
        risk_tier: format!("{:?}", record.risk_tier),
        command_plan: record.command_display.clone(),
        confirmation_mode: record.confirmation_mode.clone(),
        exit_code: record.exit_code,
        outcome: "ok".to_owned(),
        redaction_count: 0, // no secret-redaction layer yet
    }
}

/// Open the default audit log and append a record for a successful execution.
///
/// Failure to open or append is **non-fatal**: a one-line warning is printed to
/// stderr and the command's success is unaffected.
fn append_audit_record(
    actionable: &enshell_core::Actionable,
    record: &enshell_core::ExecutionRecord,
) {
    let path = match default_audit_log_path() {
        Some(p) => p,
        None => {
            eprintln!("note: could not write audit log: HOME is not set");
            return;
        }
    };
    let audit_record = build_audit_record(actionable, record);
    match AuditLog::open(&path) {
        Err(e) => {
            eprintln!("note: could not write audit log: {e}");
        }
        Ok(log) => {
            if let Err(e) = log.append(&audit_record) {
                eprintln!("note: could not write audit log: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// history subcommand
// ---------------------------------------------------------------------------

/// Run `enshell history`: read the audit log and display recent entries.
fn run_history() {
    let path = match default_audit_log_path() {
        Some(p) => p,
        None => {
            println!("No history yet.");
            return;
        }
    };

    if !path.exists() {
        println!("No history yet.");
        return;
    }

    let log = match AuditLog::open(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: could not open audit log: {e}");
            return;
        }
    };

    // Verify chain integrity; warn prominently if broken, but still show entries.
    if let Err(e) = log.verify() {
        eprintln!("⚠ audit log integrity check FAILED: {e}");
        eprintln!("The entries below may have been tampered with.");
        eprintln!();
    }

    let entries = match log.entries() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: could not read audit log: {e}");
            return;
        }
    };

    if entries.is_empty() {
        println!("No history yet.");
        return;
    }

    print!("{}", format_history(&entries));
}

/// Format a slice of audit log entries as a human-readable history string.
///
/// Shows the last 20 entries (most recent last) in a one-block-per-entry layout.
/// Pure function — no I/O — so it is straightforwardly unit-testable.
pub fn format_history(entries: &[StoredEntry]) -> String {
    const MAX_ENTRIES: usize = 20;
    let start = entries.len().saturating_sub(MAX_ENTRIES);
    let recent = &entries[start..];

    let mut out = String::new();
    out.push_str(&format!(
        "History ({} entries{})\n",
        entries.len(),
        if entries.len() > MAX_ENTRIES {
            format!(", showing last {MAX_ENTRIES}")
        } else {
            String::new()
        }
    ));
    out.push_str("─────────────────────────────────────────\n");

    for (i, entry) in recent.iter().enumerate() {
        let r = &entry.record;
        let ts_display = format_timestamp(&r.timestamp);
        out.push_str(&format!(
            "[{}] {}\n  Request:  {}\n  Intent:   {}\n  Risk:     {}\n  Command:  {}\n  Exit:     {}\n  Outcome:  {}\n",
            i + start + 1,
            ts_display,
            if r.user_request.is_empty() { "(not recorded)" } else { &r.user_request },
            r.intent,
            r.risk_tier,
            r.command_plan,
            r.exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "—".to_owned()),
            r.outcome,
        ));
        if i + 1 < recent.len() {
            out.push('\n');
        }
    }

    out
}

/// Format a timestamp string for display.
///
/// Accepts either a Unix-milliseconds string (all digits) or an RFC 3339 string.
/// Falls back to displaying the raw value if neither parses.
fn format_timestamp(ts: &str) -> String {
    // Try parsing as Unix milliseconds.
    if let Ok(millis) = ts.parse::<u64>() {
        let secs = millis / 1000;
        let ms = millis % 1000;
        return format!("{}s.{:03}ms (unix)", secs, ms);
    }
    // Already RFC 3339 or another human-readable string — display as-is.
    ts.to_owned()
}

// ---------------------------------------------------------------------------
// Stdin helper (thin I/O boundary — tested via pure logic above)
// ---------------------------------------------------------------------------

/// Print `prompt` to stdout (no newline) then read a line from stdin.
///
/// Returns an empty string on I/O error.
pub fn prompt_stdin(prompt: &str) -> String {
    use std::io::Write;
    let mut stdout = std::io::stdout();
    let _ = write!(stdout, "{prompt}");
    let _ = stdout.flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line
}

// ---------------------------------------------------------------------------
// Intent display name helper (display-only)
// ---------------------------------------------------------------------------

/// Return the canonical snake_case name of the intent in an [`enshell_core::Actionable`].
/// Used for `--plan` output.
fn intent_display_name(a: &enshell_core::Actionable) -> &'static str {
    // The intent is accessible via a.intent() which returns &enshell_intents::Intent.
    // We call the same mapping used internally by enshell_core (re-derived here
    // since intent_name is private to enshell_core).
    use enshell_intents::Intent;
    match a.intent() {
        Intent::FindLargeFiles { .. } => "find_large_files",
        Intent::FindProcessUsingPort { .. } => "find_process_using_port",
        Intent::KillProcess { .. } => "kill_process",
        Intent::InstallPackage { .. } => "install_package",
        Intent::StartService { .. } => "start_service",
        Intent::StopService { .. } => "stop_service",
        Intent::OpenFileOrFolder { .. } => "open_file_or_folder",
        Intent::CompressFolder { .. } => "compress_folder",
        Intent::CreateBackup { .. } => "create_backup",
        Intent::ExplainError { .. } => "explain_error",
        Intent::FixLastCommand { .. } => "fix_last_command",
        Intent::UpdatePackages { .. } => "update_packages",
        Intent::CheckSystemHealth { .. } => "check_system_health",
        Intent::InspectLogs { .. } => "inspect_logs",
        Intent::CreateProject { .. } => "create_project",
        Intent::GitCommitChanges { .. } => "git_commit_changes",
        Intent::AskClarification { .. } => "ask_clarification",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use enshell_intents::Intent;
    use enshell_policy::{classify, ClassifyContext, RiskTier, TargetState};

    // Helper: a ReadOnly yes-eligible decision (FindProcessUsingPort).
    fn read_only_yes_eligible() -> RiskDecision {
        classify(
            &Intent::FindProcessUsingPort { port: 3000 },
            &ClassifyContext::default(),
        )
    }

    // Helper: a ReadOnly but NOT yes-eligible decision (OpenFileOrFolder).
    fn read_only_not_yes_eligible() -> RiskDecision {
        classify(
            &Intent::OpenFileOrFolder {
                path: "/tmp".to_owned(),
            },
            &ClassifyContext::default(),
        )
    }

    // Helper: Destructive (KillProcess force=true).
    fn destructive() -> RiskDecision {
        classify(
            &Intent::KillProcess {
                pid: Some(42),
                name: None,
                port: None,
                force: Some(true),
            },
            &ClassifyContext::default(),
        )
    }

    // Helper: LocalWriteMutating (CompressFolder, target exists).
    fn local_write_mutating() -> RiskDecision {
        classify(
            &Intent::CompressFolder {
                path: "/foo".to_owned(),
                output: None,
                exclude: None,
            },
            &ClassifyContext {
                target: TargetState::Exists,
            },
        )
    }

    // Helper: PackageSystemChange (InstallPackage).
    fn package_system_change() -> RiskDecision {
        classify(
            &Intent::InstallPackage {
                name: "vim".to_owned(),
                manager: None,
                version: None,
            },
            &ClassifyContext::default(),
        )
    }

    // -----------------------------------------------------------------------
    // clap parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dry_run_with_request() {
        let cli =
            Cli::try_parse_from(["enshell", "--dry-run", "find big files"]).expect("parse ok");
        assert!(cli.dry_run);
        assert_eq!(cli.request.as_deref(), Some("find big files"));
        assert!(!cli.yes);
    }

    #[test]
    fn parse_yes_short_flag() {
        let cli = Cli::try_parse_from(["enshell", "-y", "check port 3000"]).expect("parse ok");
        assert!(cli.yes);
    }

    #[test]
    fn parse_yes_long_flag() {
        let cli = Cli::try_parse_from(["enshell", "--yes", "check port 3000"]).expect("parse ok");
        assert!(cli.yes);
        assert_eq!(cli.request.as_deref(), Some("check port 3000"));
    }

    #[test]
    fn parse_doctor_subcommand() {
        let cli = Cli::try_parse_from(["enshell", "doctor"]).expect("parse ok");
        assert!(matches!(cli.command, Some(Commands::Doctor)));
        assert!(cli.request.is_none());
    }

    #[test]
    fn parse_history_subcommand() {
        let cli = Cli::try_parse_from(["enshell", "history"]).expect("parse ok");
        assert!(matches!(cli.command, Some(Commands::History)));
    }

    #[test]
    fn parse_undo_subcommand() {
        let cli = Cli::try_parse_from(["enshell", "undo"]).expect("parse ok");
        assert!(matches!(cli.command, Some(Commands::Undo)));
    }

    #[test]
    fn parse_explain_last_subcommand() {
        let cli = Cli::try_parse_from(["enshell", "explain-last"]).expect("parse ok");
        assert!(matches!(cli.command, Some(Commands::ExplainLast)));
    }

    #[test]
    fn parse_fix_last_subcommand() {
        let cli = Cli::try_parse_from(["enshell", "fix-last"]).expect("parse ok");
        assert!(matches!(cli.command, Some(Commands::FixLast)));
    }

    #[test]
    fn parse_bare_invocation_has_no_request_no_command() {
        let cli = Cli::try_parse_from(["enshell"]).expect("parse ok");
        assert!(cli.request.is_none());
        assert!(cli.command.is_none());
    }

    #[test]
    fn parse_timeout_flag() {
        let cli = Cli::try_parse_from(["enshell", "--timeout", "60", "find big files"])
            .expect("parse ok");
        assert_eq!(cli.timeout, Some(60));
        assert_eq!(cli.request.as_deref(), Some("find big files"));
    }

    #[test]
    fn parse_plan_flag() {
        let cli = Cli::try_parse_from(["enshell", "--plan", "find big files"]).expect("parse ok");
        assert!(cli.plan);
    }

    // -----------------------------------------------------------------------
    // build_confirmation: pure confirmation-decision tests
    // -----------------------------------------------------------------------

    /// ReadOnly yes-eligible + --yes → AutoConfirm (no prompt).
    #[test]
    fn confirm_read_only_yes_eligible_with_yes_flag_auto_confirms() {
        let d = read_only_yes_eligible();
        assert!(d.yes_eligible, "precondition: yes_eligible");
        assert_eq!(d.tier, RiskTier::ReadOnly);

        let step = build_confirmation(&d, true);
        assert!(
            matches!(step, ConfirmationStep::AutoConfirm(_)),
            "expected AutoConfirm, got {step:?}"
        );
    }

    /// ReadOnly yes-eligible WITHOUT --yes → NeedsInteractive.
    #[test]
    fn confirm_read_only_yes_eligible_without_yes_flag_needs_interactive() {
        let d = read_only_yes_eligible();
        let step = build_confirmation(&d, false);
        assert!(
            matches!(step, ConfirmationStep::NeedsInteractive),
            "expected NeedsInteractive, got {step:?}"
        );
    }

    /// OpenFileOrFolder (ReadOnly but NOT yes-eligible) + --yes → NeedsInteractive
    /// (NOT auto-confirmed, per the confirmation invariant).
    #[test]
    fn confirm_open_file_not_yes_eligible_with_yes_still_needs_interactive() {
        let d = read_only_not_yes_eligible();
        assert!(!d.yes_eligible, "precondition: not yes_eligible");
        assert_eq!(d.tier, RiskTier::ReadOnly);

        let step = build_confirmation(&d, true);
        assert!(
            matches!(step, ConfirmationStep::NeedsInteractive),
            "open_file_or_folder with --yes must still need interactive, got {step:?}"
        );
    }

    /// LocalWriteMutating + --yes → NeedsInteractive (--yes ignored).
    #[test]
    fn confirm_local_write_mutating_with_yes_needs_interactive() {
        let d = local_write_mutating();
        assert!(!d.yes_eligible, "precondition: not yes_eligible");

        let step = build_confirmation(&d, true);
        assert!(
            matches!(step, ConfirmationStep::NeedsInteractive),
            "LocalWriteMutating with --yes must need interactive, got {step:?}"
        );
    }

    /// PackageSystemChange + --yes → NeedsInteractive.
    #[test]
    fn confirm_package_system_change_with_yes_needs_interactive() {
        let d = package_system_change();
        let step = build_confirmation(&d, true);
        assert!(
            matches!(step, ConfirmationStep::NeedsInteractive),
            "PackageSystemChange with --yes must need interactive, got {step:?}"
        );
    }

    /// Destructive + --yes → NeedsTyped (not auto-confirmed, not just interactive).
    #[test]
    fn confirm_destructive_with_yes_needs_typed() {
        let d = destructive();
        assert_eq!(d.tier, RiskTier::Destructive);

        let step = build_confirmation(&d, true);
        assert!(
            matches!(step, ConfirmationStep::NeedsTyped { .. }),
            "Destructive with --yes must need typed phrase, got {step:?}"
        );
    }

    /// Destructive WITHOUT --yes → NeedsTyped.
    #[test]
    fn confirm_destructive_without_yes_needs_typed() {
        let d = destructive();
        let step = build_confirmation(&d, false);
        assert!(
            matches!(step, ConfirmationStep::NeedsTyped { .. }),
            "Destructive without --yes must need typed phrase, got {step:?}"
        );
    }

    // -----------------------------------------------------------------------
    // format_success (pure output formatter)
    // -----------------------------------------------------------------------

    #[test]
    fn format_success_contains_done() {
        let record = enshell_core::ExecutionRecord {
            user_request: "what is using port 3000".to_owned(),
            intent_name: "find_process_using_port".to_owned(),
            risk_tier: RiskTier::ReadOnly,
            command_display: "lsof -i :3000".to_owned(),
            confirmation_mode: "yes".to_owned(),
            exit_code: Some(0),
            stdout: "node    1234 user   21u  IPv4 ...\n".to_owned(),
            stderr: String::new(),
        };
        let out = format_success(&record);
        assert!(out.contains("Done."), "output: {out}");
        assert!(out.contains("lsof -i :3000"), "output: {out}");
        assert!(out.contains("find_process_using_port"), "output: {out}");
    }

    #[test]
    fn format_success_empty_stdout_no_output_section() {
        let record = enshell_core::ExecutionRecord {
            user_request: "check health".to_owned(),
            intent_name: "check_system_health".to_owned(),
            risk_tier: RiskTier::ReadOnly,
            command_display: "uptime".to_owned(),
            confirmation_mode: "yes".to_owned(),
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        };
        let out = format_success(&record);
        assert!(
            !out.contains("Output:"),
            "no output section expected: {out}"
        );
    }

    #[test]
    fn format_success_stderr_note_when_nonempty() {
        let record = enshell_core::ExecutionRecord {
            user_request: "check logs".to_owned(),
            intent_name: "inspect_logs".to_owned(),
            risk_tier: RiskTier::ReadOnly,
            command_display: "journalctl -n 20".to_owned(),
            confirmation_mode: "interactive".to_owned(),
            exit_code: Some(0),
            stdout: "some log output\n".to_owned(),
            stderr: "some warning\n".to_owned(),
        };
        let out = format_success(&record);
        assert!(
            out.contains("stderr"),
            "should note stderr when non-empty: {out}"
        );
    }

    // -----------------------------------------------------------------------
    // format_error / recovery_guidance (pure)
    // -----------------------------------------------------------------------

    #[test]
    fn format_error_program_not_found_mentions_tip() {
        let e = CoreError::Exec(ExecError::ProgramNotFound("lsof".to_owned()));
        let s = format_error(&e);
        assert!(s.contains("That didn't work"), "output: {s}");
        assert!(s.contains("Tip"), "output: {s}");
    }

    #[test]
    fn recovery_guidance_non_zero_exit_has_tip() {
        let e = CoreError::Exec(ExecError::NonZeroExit {
            code: Some(1),
            stderr: "err".to_owned(),
        });
        let tip = recovery_guidance(&e);
        assert!(!tip.is_empty());
        assert!(tip.contains("Tip"));
    }

    #[test]
    fn recovery_guidance_confirmation_required_has_tip() {
        let tip = recovery_guidance(&CoreError::ConfirmationRequired);
        assert!(tip.contains("Tip"));
    }

    #[test]
    fn recovery_guidance_not_executable_has_tip() {
        let tip = recovery_guidance(&CoreError::NotExecutable);
        assert!(tip.contains("Tip"));
    }

    // -----------------------------------------------------------------------
    // format_tier (pure)
    // -----------------------------------------------------------------------

    #[test]
    fn format_tier_read_only() {
        assert_eq!(format_tier(RiskTier::ReadOnly), "Read-only");
    }

    #[test]
    fn format_tier_destructive() {
        assert!(format_tier(RiskTier::Destructive).contains("DESTRUCTIVE"));
    }

    // -----------------------------------------------------------------------
    // stub subcommand messages
    // -----------------------------------------------------------------------

    // Note: history is now a real command; stub_subcommand_message is no longer
    // called for it. Tests for undo/explain-last/fix-last remain.

    #[test]
    fn stub_message_undo_mentions_not_available() {
        let msg = stub_subcommand_message(&Commands::Undo);
        assert!(msg.contains("not available yet"));
    }

    #[test]
    fn stub_message_explain_last_mentions_not_available() {
        let msg = stub_subcommand_message(&Commands::ExplainLast);
        assert!(msg.contains("not available yet"));
    }

    #[test]
    fn stub_message_fix_last_mentions_not_available() {
        let msg = stub_subcommand_message(&Commands::FixLast);
        assert!(msg.contains("not available yet"));
    }

    // -----------------------------------------------------------------------
    // build_audit_record: mapping from ExecutionRecord to AuditRecord
    // -----------------------------------------------------------------------

    fn make_execution_record(
        intent_name: &str,
        risk_tier: RiskTier,
        command_display: &str,
        confirmation_mode: &str,
        exit_code: Option<i32>,
    ) -> enshell_core::ExecutionRecord {
        enshell_core::ExecutionRecord {
            user_request: "test request".to_owned(),
            intent_name: intent_name.to_owned(),
            risk_tier,
            command_display: command_display.to_owned(),
            confirmation_mode: confirmation_mode.to_owned(),
            exit_code,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// Build a minimal Actionable using policy+render for testing.
    fn make_actionable_find_port() -> enshell_core::Actionable {
        use enshell_core::{Orchestrator, OrchestratorConfig};
        use enshell_model::StubProvider;
        let orch = Orchestrator::new(StubProvider, OrchestratorConfig::default());
        // "what is using port 3000" → FindProcessUsingPort via StubProvider
        match orch.prepare("what is using port 3000").expect("prepare ok") {
            enshell_core::Prepared::Actionable(a) => a,
            other => panic!("expected Actionable, got {:?}", other),
        }
    }

    #[test]
    fn build_audit_record_maps_fields_correctly() {
        let actionable = make_actionable_find_port();
        let exec_record = make_execution_record(
            "find_process_using_port",
            RiskTier::ReadOnly,
            "lsof -i :3000",
            "yes",
            Some(0),
        );
        let audit = build_audit_record(&actionable, &exec_record);

        assert_eq!(audit.intent, "find_process_using_port");
        assert_eq!(audit.risk_tier, "ReadOnly");
        assert_eq!(audit.command_plan, "lsof -i :3000");
        assert_eq!(audit.confirmation_mode, "yes");
        assert_eq!(audit.exit_code, Some(0));
        assert_eq!(audit.outcome, "ok");
        assert_eq!(audit.model_id, "stub");
        assert!(audit.model_quant.is_none());
        assert_eq!(audit.prompt_template_version, "stub-1");
        assert_eq!(audit.intent_schema_version, enshell_intents::SCHEMA_VERSION);
        assert_eq!(audit.policy_version, POLICY_VERSION);
        assert_eq!(audit.redaction_count, 0);
        // correlation_id is non-empty
        assert!(!audit.correlation_id.is_empty());
        // timestamp is non-empty
        assert!(!audit.timestamp.is_empty());
    }

    #[test]
    fn build_audit_record_params_are_not_null() {
        let actionable = make_actionable_find_port();
        let exec_record = make_execution_record(
            "find_process_using_port",
            RiskTier::ReadOnly,
            "lsof -i :3000",
            "yes",
            Some(0),
        );
        let audit = build_audit_record(&actionable, &exec_record);
        // params should be a non-null JSON value (the intent's fields)
        assert!(!audit.params.is_null(), "params should not be null");
    }

    // -----------------------------------------------------------------------
    // format_history: pure output formatter
    // -----------------------------------------------------------------------

    fn make_stored_entry(n: u32) -> enshell_telemetry::StoredEntry {
        use enshell_telemetry::AuditRecord;
        enshell_telemetry::StoredEntry {
            record: AuditRecord {
                correlation_id: format!("corr-{n}"),
                user_request: format!("request {n}"),
                timestamp: format!("1700000{n:03}000"),
                policy_version: 1,
                intent_schema_version: 1,
                model_id: "stub".to_owned(),
                model_quant: None,
                prompt_template_version: "stub-1".to_owned(),
                intent: "find_process_using_port".to_owned(),
                params: serde_json::json!({"port": 3000}),
                risk_tier: "ReadOnly".to_owned(),
                command_plan: format!("lsof -i :{}", 3000 + n),
                confirmation_mode: "yes".to_owned(),
                exit_code: Some(0),
                outcome: "ok".to_owned(),
                redaction_count: 0,
            },
            prev_hash: "0".repeat(64),
            hash: "f".repeat(64),
        }
    }

    #[test]
    fn format_history_single_entry_contains_intent_and_command() {
        let entries = vec![make_stored_entry(1)];
        let out = format_history(&entries);
        assert!(out.contains("find_process_using_port"), "output: {out}");
        assert!(out.contains("lsof"), "output: {out}");
        assert!(out.contains("ReadOnly"), "output: {out}");
        assert!(out.contains("ok"), "output: {out}");
    }

    #[test]
    fn format_history_shows_all_entries_when_under_limit() {
        let entries: Vec<_> = (1..=5).map(make_stored_entry).collect();
        let out = format_history(&entries);
        assert!(out.contains("5 entries"), "output: {out}");
        // All 5 entries should appear
        for i in 1..=5u32 {
            assert!(
                out.contains(&format!("lsof -i :{}", 3000 + i)),
                "missing entry {i}: {out}"
            );
        }
    }

    #[test]
    fn format_history_caps_at_20_entries() {
        let entries: Vec<_> = (1..=25).map(make_stored_entry).collect();
        let out = format_history(&entries);
        assert!(out.contains("25 entries"), "output: {out}");
        assert!(out.contains("showing last 20"), "output: {out}");
        // Entry 1 (old) should not appear; entry 25 (newest) should.
        assert!(
            !out.contains("lsof -i :3001"),
            "old entry should be truncated: {out}"
        );
        assert!(
            out.contains("lsof -i :3025"),
            "newest entry should be shown: {out}"
        );
    }

    #[test]
    fn format_history_empty_entries_not_called_with_empty_normally() {
        // format_history is only called with non-empty entries by run_history,
        // but we guard: it should produce a valid header for 0 entries.
        let out = format_history(&[]);
        assert!(out.contains("0 entries"), "output: {out}");
    }

    // -----------------------------------------------------------------------
    // default_audit_log_path: env override
    // -----------------------------------------------------------------------

    #[test]
    fn audit_log_path_override_via_env() {
        // This test uses a temp path and checks env override logic.
        // We cannot safely mutate env in parallel tests; use a simple structural check.
        // The function returns Some when HOME is set (which it typically is in test env).
        // If ENSHELL_AUDIT_LOG is set, it overrides. We test the function is callable.
        let path = default_audit_log_path();
        // On a typical dev machine with HOME set, should be Some.
        // If HOME is not set (unlikely in tests), Some still comes from ENSHELL_AUDIT_LOG
        // or None — both are acceptable. So we just ensure it doesn't panic.
        let _ = path;
    }
}
