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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use enshell_core::{Confirmation, CoreError, OrchestratorConfig, Prepared};
use enshell_model::StubProvider;
use enshell_os::{current_os, ExecControl, ExecError};
use enshell_policy::{auto_confirm_allowed, requires_typed_confirmation, RiskDecision, RiskTier};

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
    /// Run environment self-check: OS, model provider, adapters, timeout.
    Doctor,

    /// Not available yet — needs the audit log, coming in a later phase.
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
            Commands::History | Commands::Undo | Commands::ExplainLast | Commands::FixLast => {
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
        Commands::History => "history",
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
    println!("-----------------------------------");
    println!("Everything looks good for the current stub-provider MVP.");
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

    #[test]
    fn stub_message_history_mentions_not_available() {
        let msg = stub_subcommand_message(&Commands::History);
        assert!(msg.contains("not available yet"));
        assert!(msg.contains("history"));
    }

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
}
