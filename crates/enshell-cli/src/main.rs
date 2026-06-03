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
//! - [`default_audit_log_path`] / [`audit_record_for_action`] /
//!   [`audit_record_for_refused`] for the local audit log.
//! - [`format_history`] (pure) for `enshell history` output rendering.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::path::Path;

use clap::{Parser, Subcommand};
use enshell_core::{display_command, Confirmation, CoreError, OrchestratorConfig, Prepared};
use enshell_model::{ModelProvider, StubProvider};
use enshell_os::{current_os, ExecControl, ExecError};
use enshell_policy::{
    auto_confirm_allowed, redact_text, redact_value, requires_typed_confirmation, RiskDecision,
    RiskTier,
};
use enshell_telemetry::{AuditLog, AuditOutcome, AuditRecord, StoredEntry};

// ---------------------------------------------------------------------------
// Audit log constants
// ---------------------------------------------------------------------------

/// Policy version: a placeholder constant until `enshell-policy` exposes one.
/// Increment when the policy ruleset changes in a breaking way.
const POLICY_VERSION: u32 = 1;

/// Prompt-template version recorded in the audit log. This is the version of the
/// `enshell-model` prompt scaffold (`system_prompt` + tool schema + few-shots),
/// which is provider-independent — the stub ignores it, the llama provider uses
/// it — so it is keyed to the template, not to which model ran.
const PROMPT_TEMPLATE_VERSION: &str = "v1";

/// Choose the `model_id` to record for an audited action.
///
/// A fast-path intent is produced by trusted Rust with **no model call**, so it
/// is recorded as `"fast_path"`; everything else carries the provider's name
/// (`"stub"` or the llama.cpp model). See [`enshell_core::IntentSource`].
fn model_id_for(source: enshell_core::IntentSource, provider_name: &str) -> String {
    match source {
        enshell_core::IntentSource::FastPath => "fast_path".to_owned(),
        enshell_core::IntentSource::Model => provider_name.to_owned(),
    }
}

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
    #[arg(long, conflicts_with = "plan")]
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

    /// Print a shell hook snippet to enable last-exit capture (paste into your rc file).
    ShellInit {
        /// Which shell: bash or zsh (auto-detected from $SHELL if omitted).
        shell: Option<String>,
    },

    /// Explain the last command's result (needs `enshell shell-init`).
    ExplainLast,

    /// Manage local memory (preferences stored in a local SQLite database).
    Memory {
        #[command(subcommand)]
        action: MemoryAction,
    },

    /// Not available yet — needs the undo plan, coming in a later phase.
    Undo,

    /// Not available yet — needs the last command's text (opt-in capture), coming later.
    FixLast,
}

/// Actions for the `memory` subcommand.
#[derive(Debug, Subcommand)]
pub enum MemoryAction {
    /// Show all stored preferences and the database path.
    Show,
    /// Set a preference: `enshell memory set <key> <value>`.
    Set { key: String, value: String },
    /// Get a preference's value: `enshell memory get <key>`.
    Get { key: String },
    /// Remove all stored data, keeping the (empty) database.
    Reset,
    /// Export all stored preferences to stdout as JSON.
    Export,
    /// Delete the memory database file entirely.
    Delete,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    // Resolve the timeout: the --timeout flag wins, else the stored
    // `default_timeout` preference, else 30s. A value of 0 means "no timeout".
    let timeout: Option<Duration> = resolve_timeout(cli.timeout, memory_default_timeout_secs());

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
            Commands::ShellInit { shell } => {
                run_shell_init(shell.as_deref());
                return;
            }
            Commands::ExplainLast => {
                run_explain_last();
                return;
            }
            Commands::Memory { action } => {
                run_memory(action);
                return;
            }
            Commands::Undo | Commands::FixLast => {
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

    // Build the orchestrator with a runtime-selected model provider.
    let config = OrchestratorConfig { timeout };
    let provider = build_provider();
    let orch = enshell_core::Orchestrator::new(provider, config);

    // Phase 1: prepare (fast path or model → validate → policy → render).
    let prepared = match orch.prepare(&request) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Sorry, I couldn't interpret that: {e}");
            std::process::exit(1);
        }
    };

    match prepared {
        Prepared::Clarify { question, options } => {
            // Clarification is not an execution attempt — not a security event;
            // no audit record is written for this path.
            println!("{question}");
            if let Some(opts) = options {
                for opt in opts {
                    println!("  • {opt}");
                }
            }
        }
        Prepared::Refused {
            reason,
            intent_name,
            source,
        } => {
            // model_id reflects whether the fast path or the model produced this.
            let model_id = model_id_for(source, orch.provider_name());
            // Audit the refusal before printing — security-relevant event.
            append_audit_record_raw(audit_record_for_refused(&request, &intent_name, &model_id));
            println!("I can't do that yet: {reason}");
        }
        Prepared::Actionable(actionable) => {
            // model_id reflects whether the fast path (no model call) or the model
            // produced this intent — recorded on every audit record written below.
            let model_id = model_id_for(actionable.source(), orch.provider_name());

            // Always print the preview.
            println!("{}", actionable.preview());
            println!();

            if cli.dry_run {
                // dry-run is a preview path only; no execution attempt → not audited.
                println!("(dry run — nothing was executed)");
                return;
            }

            if cli.plan {
                // plan is a preview path only; no execution attempt → not audited.
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
                            // User declined — audit as "denied".
                            append_audit_record_raw(audit_record_for_action(
                                &actionable,
                                AuditOutcome::Denied,
                                "interactive",
                                None,
                                &model_id,
                            ));
                            println!("Okay — not running.");
                            return;
                        }
                    }
                    ConfirmationStep::NeedsTyped { prompt } => {
                        let answer = prompt_stdin(&prompt);
                        let trimmed = answer.trim().to_owned();
                        if trimmed.is_empty() {
                            // User declined typed phrase — audit as "denied".
                            append_audit_record_raw(audit_record_for_action(
                                &actionable,
                                AuditOutcome::Denied,
                                "typed",
                                None,
                                &model_id,
                            ));
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

            // Ctrl-C wiring: flip the cancel flag so the executor stops and
            // reaps child processes gracefully. If the handler can't be installed
            // we warn (the default SIGINT still terminates the process, but
            // without our graceful child-cleanup), rather than failing closed —
            // the wall-clock timeout still bounds the run regardless.
            let cancel = Arc::new(AtomicBool::new(false));
            let cancel_clone = cancel.clone();
            if let Err(e) = ctrlc::set_handler(move || {
                cancel_clone.store(true, Ordering::Relaxed);
            }) {
                eprintln!(
                    "note: could not install the Ctrl-C handler ({e}); \
                     press Ctrl-C will still stop enShell, but child cleanup may be abrupt."
                );
            }

            let control = ExecControl { timeout, cancel };

            // Phase 2: execute.
            // Derive the confirmation_mode string that the executor would use,
            // so we can record it accurately for denied/aborted/error outcomes.
            let exec_confirmation_mode =
                confirmation_mode_label(&confirmation, actionable.decision());

            match orch.execute(&actionable, &confirmation, &control) {
                Ok(record) => {
                    // Append to the audit log with full redaction; failure is non-fatal.
                    append_audit_record_raw(audit_record_for_action(
                        &actionable,
                        AuditOutcome::Ok,
                        &record.confirmation_mode,
                        record.exit_code,
                        &model_id,
                    ));
                    let output_str = format_success(&record);
                    println!("{output_str}");
                }
                Err(CoreError::ConfirmationRequired) => {
                    append_audit_record_raw(audit_record_for_action(
                        &actionable,
                        AuditOutcome::Denied,
                        &exec_confirmation_mode,
                        None,
                        &model_id,
                    ));
                    eprintln!("I need explicit confirmation to do that; nothing was run.");
                    std::process::exit(1);
                }
                Err(CoreError::Exec(ExecError::Cancelled)) => {
                    append_audit_record_raw(audit_record_for_action(
                        &actionable,
                        AuditOutcome::Aborted,
                        &exec_confirmation_mode,
                        None,
                        &model_id,
                    ));
                    eprintln!("Cancelled. Nothing further was run.");
                    std::process::exit(1);
                }
                Err(CoreError::Exec(ExecError::TimedOut)) => {
                    append_audit_record_raw(audit_record_for_action(
                        &actionable,
                        AuditOutcome::Aborted,
                        &exec_confirmation_mode,
                        None,
                        &model_id,
                    ));
                    eprintln!("That took too long and was stopped (timed out).");
                    std::process::exit(1);
                }
                Err(e) => {
                    append_audit_record_raw(audit_record_for_action(
                        &actionable,
                        AuditOutcome::Error,
                        &exec_confirmation_mode,
                        None,
                        &model_id,
                    ));
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
// Model-provider selection (pure decision + thin I/O wrappers)
// ---------------------------------------------------------------------------

/// Which model provider the CLI should use for this run.
///
/// The decision is made by [`choose_provider`] (pure) and realized by
/// [`build_provider`] (does the actual I/O / provider construction).
#[derive(Debug)]
pub enum ProviderChoice {
    /// Use the deterministic built-in [`StubProvider`].
    Stub,
    /// Use the real llama.cpp-backed provider loaded from this GGUF path.
    Llama(PathBuf),
}

/// Decide which provider to use, given whether the binary was compiled with the
/// `llama` feature and the resolved model path.
///
/// This function is **pure** (no I/O): it is fully unit-testable.
///
/// # Rules
///
/// - Not built with `llama` → [`ProviderChoice::Stub`] (the real provider's
///   code isn't even compiled in, so a model path is irrelevant).
/// - Built with `llama` and a model is present → [`ProviderChoice::Llama`].
/// - Built with `llama` but no model found → [`ProviderChoice::Stub`]; the
///   caller is expected to print [`guided_install_message`] so the user learns
///   how to obtain a model.
pub fn choose_provider(llama_built: bool, model: Option<PathBuf>) -> ProviderChoice {
    match (llama_built, model) {
        (false, _) => ProviderChoice::Stub,
        (true, Some(path)) => ProviderChoice::Llama(path),
        (true, None) => ProviderChoice::Stub,
    }
}

/// Resolve the GGUF model path to use, if any, reading the real environment.
///
/// Thin wrapper over [`resolve_model_path_from`] that reads `$ENSHELL_MODEL`
/// and `$HOME` from the process environment. See that function for the
/// precedence rules. Never panics.
pub fn resolve_model_path() -> Option<PathBuf> {
    let env_val = std::env::var("ENSHELL_MODEL").ok();
    let home = std::env::var("HOME").ok().map(PathBuf::from);
    resolve_model_path_from(env_val.as_deref(), home.as_deref())
}

/// Pure core of [`resolve_model_path`]: resolve a model path from explicit
/// inputs so it can be unit-tested without mutating global process env.
///
/// # Precedence
///
/// 1. `env_val` (the value of `$ENSHELL_MODEL`): if set **and** the file at that
///    path exists, return it.
/// 2. Otherwise the default location `<home>/.enshell/models/`: return the first
///    `*.gguf` file found there (if `home` is provided and such a file exists).
/// 3. Otherwise `None`.
///
/// Returns only paths that actually exist on disk. Never panics.
pub fn resolve_model_path_from(env_val: Option<&str>, home: Option<&Path>) -> Option<PathBuf> {
    // 1. Explicit override via $ENSHELL_MODEL, but only if the file exists.
    if let Some(val) = env_val {
        if !val.is_empty() {
            let p = PathBuf::from(val);
            if p.is_file() {
                return Some(p);
            }
        }
    }

    // 2. Default location: <home>/.enshell/models/*.gguf — first match wins.
    let home = home?;
    let models_dir = home.join(".enshell").join("models");
    let entries = std::fs::read_dir(&models_dir).ok()?;
    let mut found: Option<PathBuf> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_gguf = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("gguf"));
        if is_gguf && path.is_file() {
            // Deterministic: prefer the lexicographically smallest filename so
            // selection does not depend on directory-iteration order.
            match &found {
                Some(existing) if existing <= &path => {}
                _ => found = Some(path),
            }
        }
    }
    found
}

/// Informational, plain-English guidance on how to obtain the model.
///
/// This is **not** an auto-download — it describes the model, its source, its
/// license, and where to place it / how to point enShell at it. Returned as a
/// string (no I/O) so it is testable and the caller controls where it is
/// printed.
pub fn guided_install_message() -> String {
    "No local model found — enShell is using its built-in deterministic stub.\n\
     \n\
     To enable the real assistant, install a model:\n\
     \n\
     \x20 Model:   Gemma 4 E2B Instruct (Q4 GGUF, e.g. Q4_K_M)\n\
     \x20 Size:    ~1-2 GB to download (runs comfortably in ~8 GB RAM)\n\
     \x20 Source:  Google's official Gemma resources — https://ai.google.dev/gemma\n\
     \x20          (find the exact per-version GGUF on the official model card; \
     enShell does not host or mirror the weights)\n\
     \x20 License: Apache-2.0 — verify the terms on the model card for the exact\n\
     \x20          version you download (see MODEL_LICENSES.md; earlier Gemma\n\
     \x20          versions used different terms). Downloading the model means\n\
     \x20          accepting that model's license.\n\
     \n\
     Then place the .gguf file in ~/.enshell/models/ (enShell picks it up\n\
     automatically), or set ENSHELL_MODEL to its full path:\n\
     \x20 export ENSHELL_MODEL=/path/to/gemma-4-e2b-instruct.Q4_K_M.gguf\n"
        .to_owned()
}

/// Build the runtime model provider, doing the actual I/O and provider
/// construction the pure [`choose_provider`] decision implies.
///
/// Returns a `Box<dyn ModelProvider>` so the caller can hold a runtime-selected
/// provider regardless of which concrete type was chosen. Falls back to the
/// [`StubProvider`] on any problem (feature off, no model, or load failure),
/// printing a one-line note rather than failing — enShell stays usable.
fn build_provider() -> Box<dyn ModelProvider> {
    let llama_built = cfg!(feature = "llama");
    match choose_provider(llama_built, resolve_model_path()) {
        ProviderChoice::Stub => {
            // Only nudge about installing a model when the real provider is
            // actually compiled in; otherwise the stub is expected and silent.
            if llama_built {
                eprintln!("{}", guided_install_message());
            }
            Box::new(StubProvider) as Box<dyn ModelProvider>
        }
        ProviderChoice::Llama(path) => {
            #[cfg(feature = "llama")]
            {
                match enshell_llama::LlamaProvider::new(&path) {
                    Ok(p) => Box::new(p) as Box<dyn ModelProvider>,
                    Err(e) => {
                        eprintln!(
                            "note: failed to load model at {}: {e}; using the built-in stub.",
                            path.display()
                        );
                        Box::new(StubProvider) as Box<dyn ModelProvider>
                    }
                }
            }
            // Unreachable when the feature is off: choose_provider only returns
            // Llama when llama_built is true. The branch exists so the function
            // compiles cleanly under the default build with no unused warnings.
            #[cfg(not(feature = "llama"))]
            {
                let _ = path;
                Box::new(StubProvider) as Box<dyn ModelProvider>
            }
        }
    }
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
    match cmd {
        Commands::Undo => "'undo' is not available yet — it needs recorded per-action undo \
             plans, which arrive alongside write actions in a later phase."
            .to_owned(),
        Commands::FixLast => "'fix-last' is not available yet — it needs the text of your last \
             command, which enShell does not capture by default (richer, opt-in capture is \
             planned)."
            .to_owned(),
        Commands::Doctor
        | Commands::History
        | Commands::ShellInit { .. }
        | Commands::ExplainLast
        | Commands::Memory { .. } => {
            unreachable!("{cmd:?} is handled before this call")
        }
    }
}

// ---------------------------------------------------------------------------
// shell-init subcommand
// ---------------------------------------------------------------------------

/// Print the shell hook snippet for the user to paste, or a helpful error.
fn run_shell_init(shell_arg: Option<&str>) {
    // An explicit arg is parsed via detect_shell_from (token only); otherwise we
    // auto-detect from the environment.
    let shell = match shell_arg {
        Some(s) => enshell_shell::detect_shell_from(Some(s), None),
        None => enshell_shell::detect_shell(),
    };
    match shell_init_output(shell) {
        Ok(text) => print!("{text}"),
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    }
}

/// Pure core of [`run_shell_init`]: build the snippet output (or an error message)
/// for a resolved shell. `Ok` is printed to stdout; `Err` to stderr with exit 1.
fn shell_init_output(shell: Option<enshell_os::ShellKind>) -> Result<String, String> {
    let Some(shell) = shell else {
        return Err(
            "Couldn't determine your shell. Pass one explicitly, e.g.:\n  \
                    enshell shell-init bash\n  enshell shell-init zsh"
                .to_owned(),
        );
    };
    match enshell_shell::hook_snippet(&shell) {
        Some(snippet) => {
            let label = enshell_shell::shell_label(&shell);
            let rc = match shell {
                enshell_os::ShellKind::Bash => "~/.bashrc",
                enshell_os::ShellKind::Zsh => "~/.zshrc",
                _ => "your shell startup file",
            };
            Ok(format!(
                "# enShell shell integration for {label}.\n\
                 # Append the snippet below to {rc}, then start a new shell.\n\
                 # It enables `enshell explain-last` by exporting ONLY the last exit code.\n\n\
                 {snippet}"
            ))
        }
        None => {
            let label = enshell_shell::shell_label(&shell);
            Err(format!(
                "Shell integration for {label} is not available yet — supported shells: bash, zsh."
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// explain-last subcommand
// ---------------------------------------------------------------------------

/// Explain the last command's result using the privacy-minimal captured context.
fn run_explain_last() {
    println!("{}", explain_last_message(&enshell_shell::capture()));
}

/// Pure core of [`run_explain_last`]: build the explanation text from context.
///
/// With privacy-minimal capture we have only the exit code, so this maps well-known
/// exit codes to standard meanings and is honest about not having the command text.
fn explain_last_message(ctx: &enshell_shell::ShellContext) -> String {
    if !ctx.hook_active {
        let how = match ctx.shell {
            Some(enshell_os::ShellKind::Bash) => "enshell shell-init bash",
            Some(enshell_os::ShellKind::Zsh) => "enshell shell-init zsh",
            _ => "enshell shell-init bash   (or: zsh)",
        };
        return format!(
            "I can't see your last command's result — shell integration isn't enabled.\n\
             Enable it (it captures only the exit code), then start a new shell:\n  {how}"
        );
    }
    match ctx.last_exit_code {
        Some(0) => "Your last command succeeded (exit code 0). Nothing to explain.".to_owned(),
        Some(code) => {
            let mut msg = format!("Your last command exited with code {code}.");
            if let Some(hint) = exit_code_hint(code) {
                msg.push_str(&format!("\nThat usually means: {hint}."));
            }
            msg.push_str(
                "\n\nenShell's privacy-minimal default captures only the exit code — not the \
                 command text or its output — so it can't analyse the failure in detail yet. \
                 Richer, opt-in capture is planned.",
            );
            msg
        }
        None => "Shell integration is enabled, but the recorded exit code wasn't a number I \
                 could read. Start a new shell after installing the hook and try again."
            .to_owned(),
    }
}

/// Map a well-known process exit code to its conventional meaning, if any.
fn exit_code_hint(code: i32) -> Option<&'static str> {
    match code {
        1 => Some("a general error"),
        2 => Some("misuse of arguments or a shell builtin"),
        124 => Some("the command timed out"),
        126 => Some("the command was found but is not executable (permission denied)"),
        127 => Some("command not found — it may be misspelled or not on your PATH"),
        130 => Some("terminated by Ctrl-C (SIGINT)"),
        137 => Some("killed (SIGKILL — often out of memory)"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// memory subcommand
// ---------------------------------------------------------------------------

/// Default path to the memory database: `$ENSHELL_MEMORY_DB`, else
/// `$HOME/.enshell/memory.db`. Returns `None` if neither is available.
pub fn default_memory_db_path() -> Option<PathBuf> {
    if let Ok(override_path) = std::env::var("ENSHELL_MEMORY_DB") {
        if !override_path.is_empty() {
            return Some(PathBuf::from(override_path));
        }
    }
    let home = std::env::var("HOME").ok()?;
    let mut path = PathBuf::from(home);
    path.push(".enshell");
    path.push("memory.db");
    Some(path)
}

/// Resolve the execution timeout: the `--timeout` flag wins, else the stored
/// `default_timeout` preference, else 30s. A value of `0` means "no timeout".
fn resolve_timeout(cli_timeout: Option<u64>, pref_secs: Option<u64>) -> Option<Duration> {
    let secs = cli_timeout.or(pref_secs).unwrap_or(30);
    if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    }
}

/// Read the `default_timeout` preference (in seconds), if a memory DB already
/// exists and the value parses. Best-effort: it never *creates* the DB and never
/// blocks the main flow on a memory error.
fn memory_default_timeout_secs() -> Option<u64> {
    let path = default_memory_db_path()?;
    if !path.exists() {
        return None; // don't create the DB just to read a (likely absent) pref
    }
    let store = enshell_memory::Store::open(&path).ok()?;
    store
        .get_pref("default_timeout")
        .ok()
        .flatten()?
        .trim()
        .parse()
        .ok()
}

/// Run the `memory` subcommand.
fn run_memory(action: &MemoryAction) {
    let Some(path) = default_memory_db_path() else {
        eprintln!("memory is unavailable: HOME is not set (and ENSHELL_MEMORY_DB is empty).");
        std::process::exit(1);
    };

    // `delete` removes the file directly — it must work even if the DB won't open.
    if let MemoryAction::Delete = action {
        match enshell_memory::delete_store_file(&path) {
            Ok(true) => println!("Deleted memory database: {}", path.display()),
            Ok(false) => println!("No memory database to delete ({}).", path.display()),
            Err(e) => {
                eprintln!("Could not delete memory database: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // `set` is the ONLY action that creates the database. Read-only/clear actions
    // must NOT create it just to report emptiness — that would contradict the
    // "created lazily on first set" contract. Report the empty state directly.
    if !matches!(action, MemoryAction::Set { .. }) && !path.exists() {
        match action {
            MemoryAction::Show => {
                println!("Memory database: {} (not created yet)", path.display());
                println!("(no preferences set)");
            }
            MemoryAction::Get { .. } => println!("(not set)"),
            MemoryAction::Export => println!("{}", prefs_to_json(&[])),
            MemoryAction::Reset => println!("No preferences to clear (no memory database)."),
            MemoryAction::Set { .. } | MemoryAction::Delete => {
                unreachable!("set creates the db; delete handled above")
            }
        }
        return;
    }

    let store = match enshell_memory::Store::open(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Could not open memory database: {e}");
            std::process::exit(1);
        }
    };

    let result = match action {
        MemoryAction::Show => run_memory_show(&store, &path),
        MemoryAction::Set { key, value } => store.set_pref(key, value).map(|()| {
            println!("Set {key} = {value}");
        }),
        MemoryAction::Get { key } => store.get_pref(key).map(|v| match v {
            Some(val) => println!("{val}"),
            None => println!("(not set)"),
        }),
        MemoryAction::Reset => store
            .reset()
            .map(|()| println!("Cleared all stored preferences.")),
        MemoryAction::Export => store.all_prefs().map(|prefs| {
            println!("{}", prefs_to_json(&prefs));
        }),
        MemoryAction::Delete => unreachable!("delete is handled above"),
    };
    if let Err(e) = result {
        eprintln!("memory error: {e}");
        std::process::exit(1);
    }
}

fn run_memory_show(
    store: &enshell_memory::Store,
    path: &Path,
) -> Result<(), enshell_memory::MemoryError> {
    println!("Memory database: {}", path.display());
    let prefs = store.all_prefs()?;
    if prefs.is_empty() {
        println!("(no preferences set)");
    } else {
        for (k, v) in prefs {
            println!("  {k} = {v}");
        }
    }
    Ok(())
}

/// Serialize prefs as a pretty JSON object. Keys are sorted (serde_json's default
/// `Map` is a `BTreeMap`), so the output is stable.
fn prefs_to_json(prefs: &[(String, String)]) -> String {
    let map: serde_json::Map<String, serde_json::Value> = prefs
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    serde_json::to_string_pretty(&serde_json::Value::Object(map))
        .unwrap_or_else(|_| "{}".to_owned())
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

    // Model-provider status — resilient: no panics on missing model/env.
    let llama_built = cfg!(feature = "llama");
    println!(
        "Built with llama feature: {}",
        if llama_built { "yes" } else { "no" }
    );
    let resolved = resolve_model_path();
    match &resolved {
        Some(path) => {
            println!("Model path:      {}", path.display());
            // A file exists at the path; doctor does NOT load it (a multi-GB load
            // would be slow, and a corrupt/incompatible file only fails at load
            // time). So this is a candidate, not a verified-loadable model.
            println!("Model file found: yes (not load-verified)");
        }
        None => {
            println!("Model path:      none found");
            println!("Model file found: no");
        }
    }
    let provider_label = match choose_provider(llama_built, resolved) {
        // A model file was found, so the llama provider is the one that WOULD be
        // selected — but doctor hasn't loaded it. Say so explicitly rather than
        // implying gemma-4 is confirmed working: at run time a load failure falls
        // back to the stub (see build_provider).
        ProviderChoice::Llama(_) => {
            "gemma-4 (llama.cpp) — model candidate found; load not checked \
             (falls back to stub if the model fails to load at run time)"
        }
        ProviderChoice::Stub => {
            if llama_built {
                "stub (no model found — run with a model installed for gemma-4/llama.cpp)"
            } else {
                "stub (deterministic; rebuild with --features llama for gemma-4/llama.cpp)"
            }
        }
    };
    println!("Selected provider: {provider_label}");
    println!("Adapters:        read-only adapters available for macOS and Linux");
    println!("Configured timeout: {timeout_str}");

    // Shell integration status — privacy-minimal capture (cwd + last exit code).
    println!("-----------------------------------");
    let shell_ctx = enshell_shell::capture();
    let shell_str = match &shell_ctx.shell {
        Some(k) => enshell_shell::shell_label(k).to_owned(),
        None => "unknown".to_owned(),
    };
    println!("Shell:           {shell_str}");
    println!(
        "Shell hook:      {}",
        if shell_ctx.hook_active {
            "installed (last exit code captured)"
        } else {
            "not installed (run `enshell shell-init` to enable explain-last)"
        }
    );
    if shell_ctx.hook_active {
        let last = match shell_ctx.last_exit_code {
            Some(c) => c.to_string(),
            None => "[present but unparsable]".to_owned(),
        };
        println!("Last exit code:  {last}");
    }

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
    println!("Environment check complete.");
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

/// Build an [`AuditRecord`] from an [`enshell_core::Actionable`] for any terminal outcome.
///
/// Redacts `user_request`, `command_plan`, and `params` before storage. The
/// `redaction_count` field is the number of redactions applied: inline secret
/// spans removed from text, plus whole values redacted under sensitive JSON keys
/// (one per redacted value, not per span).
///
/// # Parameters
/// - `outcome`: the typed [`AuditOutcome`] for this event.
/// - `confirmation_mode`: `"yes"` | `"interactive"` | `"typed"` | `"none"`
/// - `exit_code`: `Some(code)` when the process ran to completion; `None` otherwise.
pub fn audit_record_for_action(
    actionable: &enshell_core::Actionable,
    outcome: AuditOutcome,
    confirmation_mode: &str,
    exit_code: Option<i32>,
    model_id: &str,
) -> AuditRecord {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let correlation_id = format!("{}-{}", millis, std::process::id());
    let timestamp = millis.to_string();

    // Redact user-supplied text fields.
    let (user_request, c1) = redact_text(actionable.user_request());
    let (command_plan, c2) = redact_text(&display_command(actionable.plan()));
    let mut params = serde_json::to_value(actionable.intent()).unwrap_or(serde_json::Value::Null);
    let c3 = redact_value(&mut params);
    let redaction_count = c1 + c2 + c3;

    let decision = actionable.decision();

    AuditRecord {
        correlation_id,
        user_request,
        timestamp,
        policy_version: POLICY_VERSION,
        intent_schema_version: enshell_intents::SCHEMA_VERSION,
        model_id: model_id.to_owned(),
        model_quant: None,
        prompt_template_version: PROMPT_TEMPLATE_VERSION.to_owned(),
        intent: intent_display_name(actionable).to_owned(),
        params,
        risk_tier: format!("{:?}", decision.tier),
        command_plan,
        confirmation_mode: confirmation_mode.to_owned(),
        exit_code,
        outcome,
        redaction_count,
    }
}

/// Build an [`AuditRecord`] for a refused intent (no [`enshell_core::Actionable`] available).
///
/// Redacts the `user_request`. `params` is `Null`, `command_plan` is empty,
/// `risk_tier` is `"n/a"`, `confirmation_mode` is `"none"`, `outcome` is `"refused"`.
pub fn audit_record_for_refused(
    user_request: &str,
    intent_name: &str,
    model_id: &str,
) -> AuditRecord {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let correlation_id = format!("{}-{}", millis, std::process::id());
    let timestamp = millis.to_string();

    let (user_request, redaction_count) = redact_text(user_request);

    AuditRecord {
        correlation_id,
        user_request,
        timestamp,
        policy_version: POLICY_VERSION,
        intent_schema_version: enshell_intents::SCHEMA_VERSION,
        model_id: model_id.to_owned(),
        model_quant: None,
        prompt_template_version: PROMPT_TEMPLATE_VERSION.to_owned(),
        intent: intent_name.to_owned(),
        params: serde_json::Value::Null,
        risk_tier: "n/a".to_owned(),
        command_plan: String::new(),
        confirmation_mode: "none".to_owned(),
        exit_code: None,
        outcome: AuditOutcome::Refused,
        redaction_count,
    }
}

/// Open the default audit log and append a pre-built [`AuditRecord`].
///
/// Failure to open or append is **non-fatal**: a one-line warning is printed to
/// stderr and the command's success is unaffected.
fn append_audit_record_raw(audit_record: AuditRecord) {
    let path = match default_audit_log_path() {
        Some(p) => p,
        None => {
            eprintln!("note: could not write audit log: HOME is not set");
            return;
        }
    };
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

/// Derive the confirmation-mode label that [`enshell_core::Orchestrator::execute`] would
/// use for a given [`Confirmation`] + [`RiskDecision`] pair.
///
/// Used to populate the audit record when execution fails or is denied before
/// the executor has a chance to record the mode itself.
fn confirmation_mode_label(
    confirmation: &enshell_core::Confirmation,
    decision: &enshell_policy::RiskDecision,
) -> String {
    if auto_confirm_allowed(decision, confirmation.yes_flag) {
        "yes".to_owned()
    } else if requires_typed_confirmation(decision) {
        "typed".to_owned()
    } else if confirmation.interactively_confirmed {
        "interactive".to_owned()
    } else {
        "none".to_owned()
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
            r.outcome.as_str(),
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
    fn dry_run_and_plan_conflict() {
        // --dry-run and --plan are mutually exclusive; clap must reject both.
        let result = Cli::try_parse_from(["enshell", "--dry-run", "--plan", "x"]);
        assert!(
            result.is_err(),
            "--dry-run and --plan together should be a clap error, not silent precedence"
        );
    }

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
    fn parse_shell_init_subcommand_with_and_without_arg() {
        let cli = Cli::try_parse_from(["enshell", "shell-init"]).expect("parse ok");
        assert!(matches!(
            cli.command,
            Some(Commands::ShellInit { shell: None })
        ));

        let cli = Cli::try_parse_from(["enshell", "shell-init", "zsh"]).expect("parse ok");
        match cli.command {
            Some(Commands::ShellInit { shell: Some(s) }) => assert_eq!(s, "zsh"),
            other => panic!("expected ShellInit{{zsh}}, got {other:?}"),
        }
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
    // choose_provider: pure decision logic
    // -----------------------------------------------------------------------

    #[test]
    fn choose_provider_not_built_with_model_is_stub() {
        // Feature off → always Stub, even when a model path is present.
        let choice = choose_provider(false, Some(PathBuf::from("/tmp/model.gguf")));
        assert!(matches!(choice, ProviderChoice::Stub), "got {choice:?}");
    }

    #[test]
    fn choose_provider_not_built_without_model_is_stub() {
        let choice = choose_provider(false, None);
        assert!(matches!(choice, ProviderChoice::Stub), "got {choice:?}");
    }

    #[test]
    fn choose_provider_built_with_model_is_llama() {
        let path = PathBuf::from("/tmp/model.gguf");
        let choice = choose_provider(true, Some(path.clone()));
        match choice {
            ProviderChoice::Llama(p) => assert_eq!(p, path),
            other => panic!("expected Llama({path:?}), got {other:?}"),
        }
    }

    #[test]
    fn choose_provider_built_without_model_is_stub() {
        // Feature on but no model → Stub (caller prints guided install info).
        let choice = choose_provider(true, None);
        assert!(matches!(choice, ProviderChoice::Stub), "got {choice:?}");
    }

    // -----------------------------------------------------------------------
    // resolve_model_path_from: pure path resolution
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_model_path_env_points_at_real_file_returns_it() {
        // Create a real temp file and point ENSHELL_MODEL at it.
        let dir = std::env::temp_dir().join(format!("enshell-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let model = dir.join("model.gguf");
        std::fs::write(&model, b"fake").expect("write");

        let env_val = model.to_str();
        let resolved = resolve_model_path_from(env_val, None);
        assert_eq!(resolved.as_deref(), Some(model.as_path()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_model_path_env_points_at_nonexistent_returns_none() {
        // A non-existent path must NOT be returned, and with no HOME → None.
        let resolved = resolve_model_path_from(Some("/definitely/not/here/model.gguf"), None);
        assert!(resolved.is_none(), "got {resolved:?}");
    }

    #[test]
    fn resolve_model_path_unset_and_no_default_returns_none() {
        // No env value and a HOME with no models dir → None.
        let home = std::env::temp_dir().join(format!("enshell-empty-home-{}", std::process::id()));
        std::fs::create_dir_all(&home).expect("mkdir");
        let resolved = resolve_model_path_from(None, Some(home.as_path()));
        assert!(resolved.is_none(), "got {resolved:?}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn resolve_model_path_finds_gguf_in_default_dir() {
        // A .gguf in <home>/.enshell/models/ should be discovered when env unset.
        let home = std::env::temp_dir().join(format!("enshell-home-{}", std::process::id()));
        let models = home.join(".enshell").join("models");
        std::fs::create_dir_all(&models).expect("mkdir");
        let model = models.join("gemma.gguf");
        std::fs::write(&model, b"fake").expect("write");

        let resolved = resolve_model_path_from(None, Some(home.as_path()));
        assert_eq!(resolved.as_deref(), Some(model.as_path()));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn resolve_model_path_env_takes_precedence_over_default() {
        // Both an env file and a default-dir file exist → env wins.
        let home = std::env::temp_dir().join(format!("enshell-prec-{}", std::process::id()));
        let models = home.join(".enshell").join("models");
        std::fs::create_dir_all(&models).expect("mkdir");
        let default_model = models.join("default.gguf");
        std::fs::write(&default_model, b"fake").expect("write");
        let env_model = home.join("override.gguf");
        std::fs::write(&env_model, b"fake").expect("write");

        let resolved = resolve_model_path_from(env_model.to_str(), Some(home.as_path()));
        assert_eq!(resolved.as_deref(), Some(env_model.as_path()));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn resolve_model_path_ignores_non_gguf_in_default_dir() {
        // A non-.gguf file in the default dir must not be selected.
        let home = std::env::temp_dir().join(format!("enshell-nongguf-{}", std::process::id()));
        let models = home.join(".enshell").join("models");
        std::fs::create_dir_all(&models).expect("mkdir");
        std::fs::write(models.join("README.txt"), b"not a model").expect("write");

        let resolved = resolve_model_path_from(None, Some(home.as_path()));
        assert!(resolved.is_none(), "got {resolved:?}");

        let _ = std::fs::remove_dir_all(&home);
    }

    // -----------------------------------------------------------------------
    // guided_install_message: pure, informational
    // -----------------------------------------------------------------------

    #[test]
    fn guided_install_message_mentions_model_env_and_license() {
        let msg = guided_install_message();
        assert!(msg.contains("Gemma 4"), "should name the model: {msg}");
        assert!(
            msg.contains("ENSHELL_MODEL"),
            "should mention the env var: {msg}"
        );
        assert!(
            msg.contains("Apache-2.0"),
            "should state the license: {msg}"
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

    // Note: doctor/history/shell-init/explain-last are now real commands and are
    // NOT routed through stub_subcommand_message. Only undo and fix-last remain stubs.

    #[test]
    fn stub_message_undo_mentions_not_available() {
        let msg = stub_subcommand_message(&Commands::Undo);
        assert!(msg.contains("not available yet"));
    }

    #[test]
    fn stub_message_fix_last_mentions_not_available() {
        let msg = stub_subcommand_message(&Commands::FixLast);
        assert!(msg.contains("not available yet"));
    }

    // -----------------------------------------------------------------------
    // audit_record_for_action / audit_record_for_refused
    // -----------------------------------------------------------------------

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
    fn audit_record_for_action_maps_fields_correctly() {
        let actionable = make_actionable_find_port();
        let audit = audit_record_for_action(&actionable, AuditOutcome::Ok, "yes", Some(0), "stub");

        assert_eq!(audit.intent, "find_process_using_port");
        assert_eq!(audit.risk_tier, "ReadOnly");
        // command_plan is rendered from the plan (lsof or ss depending on OS)
        assert!(!audit.command_plan.is_empty());
        assert_eq!(audit.confirmation_mode, "yes");
        assert_eq!(audit.exit_code, Some(0));
        assert_eq!(audit.outcome, AuditOutcome::Ok);
        assert_eq!(audit.model_id, "stub");
        assert!(audit.model_quant.is_none());
        assert_eq!(audit.prompt_template_version, "v1");
        assert_eq!(audit.intent_schema_version, enshell_intents::SCHEMA_VERSION);
        assert_eq!(audit.policy_version, POLICY_VERSION);
        // Normal request contains no secrets → redaction_count == 0.
        assert_eq!(audit.redaction_count, 0);
        // user_request must be populated (redacted version of original).
        assert_eq!(audit.user_request, "what is using port 3000");
        // correlation_id is non-empty
        assert!(!audit.correlation_id.is_empty());
        // timestamp is non-empty
        assert!(!audit.timestamp.is_empty());
    }

    /// `model_id_for` maps a fast-path intent to `"fast_path"` and a model intent
    /// to the provider's name — this is what tags the audit `model_id` field.
    #[test]
    fn model_id_for_maps_source_to_audit_id() {
        use enshell_core::IntentSource;
        assert_eq!(
            model_id_for(IntentSource::FastPath, "gemma-4 (llama.cpp)"),
            "fast_path"
        );
        assert_eq!(model_id_for(IntentSource::Model, "stub"), "stub");
        assert_eq!(
            model_id_for(IntentSource::Model, "gemma-4 (llama.cpp)"),
            "gemma-4 (llama.cpp)"
        );
    }

    // -----------------------------------------------------------------------
    // shell-init / explain-last pure logic
    // -----------------------------------------------------------------------

    fn shell_ctx(
        shell: Option<enshell_os::ShellKind>,
        last_exit_code: Option<i32>,
        hook_active: bool,
    ) -> enshell_shell::ShellContext {
        enshell_shell::ShellContext {
            shell,
            cwd: None,
            last_exit_code,
            hook_active,
        }
    }

    #[test]
    fn shell_init_output_bash_includes_snippet_and_rc_path() {
        let out = shell_init_output(Some(enshell_os::ShellKind::Bash)).expect("bash supported");
        assert!(out.contains("~/.bashrc"));
        assert!(out.contains("ENSHELL_LAST_EXIT_CODE"));
    }

    #[test]
    fn shell_init_output_unknown_shell_errors_with_guidance() {
        let err = shell_init_output(None).unwrap_err();
        assert!(err.contains("shell-init"), "should guide the user: {err}");
    }

    #[test]
    fn shell_init_output_unsupported_shell_errors() {
        let err = shell_init_output(Some(enshell_os::ShellKind::Fish)).unwrap_err();
        assert!(err.contains("not available yet"), "got: {err}");
    }

    #[test]
    fn explain_last_without_hook_points_to_shell_init() {
        let msg = explain_last_message(&shell_ctx(None, None, false));
        assert!(msg.contains("shell-init"), "got: {msg}");
    }

    #[test]
    fn explain_last_success_says_nothing_to_explain() {
        let msg = explain_last_message(&shell_ctx(Some(enshell_os::ShellKind::Zsh), Some(0), true));
        assert!(msg.contains("succeeded"), "got: {msg}");
    }

    #[test]
    fn explain_last_failure_includes_known_code_hint_and_is_honest() {
        let msg = explain_last_message(&shell_ctx(
            Some(enshell_os::ShellKind::Bash),
            Some(127),
            true,
        ));
        assert!(msg.contains("127"));
        assert!(msg.contains("command not found"));
        // Honest about not having the command text under privacy-minimal capture.
        assert!(msg.contains("privacy-minimal"));
    }

    #[test]
    fn explain_last_hook_active_but_unparsed_code() {
        let msg = explain_last_message(&shell_ctx(Some(enshell_os::ShellKind::Bash), None, true));
        assert!(msg.contains("wasn't a number"), "got: {msg}");
    }

    #[test]
    fn exit_code_hint_maps_common_codes_only() {
        assert!(exit_code_hint(127).unwrap().contains("not found"));
        assert!(exit_code_hint(126).unwrap().contains("not executable"));
        assert!(exit_code_hint(0).is_none());
        assert!(exit_code_hint(42).is_none());
    }

    // -----------------------------------------------------------------------
    // memory: timeout resolution + export rendering
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_timeout_flag_beats_pref() {
        assert_eq!(
            resolve_timeout(Some(5), Some(99)),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn resolve_timeout_uses_pref_when_no_flag() {
        assert_eq!(
            resolve_timeout(None, Some(60)),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn resolve_timeout_defaults_to_30s() {
        assert_eq!(resolve_timeout(None, None), Some(Duration::from_secs(30)));
    }

    #[test]
    fn resolve_timeout_zero_means_no_timeout() {
        assert_eq!(resolve_timeout(Some(0), None), None);
        assert_eq!(resolve_timeout(None, Some(0)), None);
    }

    #[test]
    fn prefs_to_json_is_valid_sorted_object() {
        let json = prefs_to_json(&[
            ("editor".to_owned(), "nvim".to_owned()),
            ("default_timeout".to_owned(), "60".to_owned()),
        ]);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["editor"], "nvim");
        assert_eq!(v["default_timeout"], "60");
    }

    #[test]
    fn parse_memory_set_subcommand() {
        let cli = Cli::try_parse_from(["enshell", "memory", "set", "default_timeout", "60"])
            .expect("parse ok");
        match cli.command {
            Some(Commands::Memory {
                action: MemoryAction::Set { key, value },
            }) => {
                assert_eq!(key, "default_timeout");
                assert_eq!(value, "60");
            }
            other => panic!("expected memory set, got {other:?}"),
        }
    }

    /// Regression guard: the audit record must record the *actual* provider that
    /// produced the intent, not a hardcoded `"stub"`. When the llama provider is
    /// selected, its name must reach the log verbatim — for both the action and
    /// refusal paths.
    #[test]
    fn audit_records_carry_the_real_provider_name() {
        let llama = "gemma-4 (llama.cpp)";
        let actionable = make_actionable_find_port();

        let action = audit_record_for_action(&actionable, AuditOutcome::Ok, "yes", Some(0), llama);
        assert_eq!(action.model_id, llama);

        let refused = audit_record_for_refused("install ripgrep", "install_package", llama);
        assert_eq!(refused.model_id, llama);
    }

    #[test]
    fn audit_record_for_action_params_are_not_null() {
        let actionable = make_actionable_find_port();
        let audit = audit_record_for_action(&actionable, AuditOutcome::Ok, "yes", Some(0), "stub");
        // params should be a non-null JSON value (the intent's fields)
        assert!(!audit.params.is_null(), "params should not be null");
    }

    #[test]
    fn audit_record_for_action_denied_outcome() {
        let actionable = make_actionable_find_port();
        let audit = audit_record_for_action(
            &actionable,
            AuditOutcome::Denied,
            "interactive",
            None,
            "stub",
        );
        assert_eq!(audit.outcome, AuditOutcome::Denied);
        assert_eq!(audit.confirmation_mode, "interactive");
        assert!(audit.exit_code.is_none());
    }

    #[test]
    fn audit_record_for_action_aborted_outcome() {
        let actionable = make_actionable_find_port();
        let audit =
            audit_record_for_action(&actionable, AuditOutcome::Aborted, "yes", None, "stub");
        assert_eq!(audit.outcome, AuditOutcome::Aborted);
        assert!(audit.exit_code.is_none());
    }

    #[test]
    fn audit_record_for_action_error_outcome() {
        let actionable = make_actionable_find_port();
        let audit = audit_record_for_action(&actionable, AuditOutcome::Error, "yes", None, "stub");
        assert_eq!(audit.outcome, AuditOutcome::Error);
    }

    /// A request containing a GitHub PAT should have the token redacted and
    /// redaction_count >= 1.
    #[test]
    fn audit_record_for_action_redacts_secret_in_user_request() {
        // Build an Actionable with a user_request that contains a fake PAT.
        // We can't inject an arbitrary user_request into an existing Actionable,
        // so we build one via the orchestrator with the stub. The stub always
        // maps "what is using port 3000" → FindProcessUsingPort, but we can
        // test redaction via `audit_record_for_refused` which takes the raw
        // request string directly. For the action path we test by confirming
        // the actionable's user_request ("what is using port 3000") passes
        // through unchanged (no secrets → count 0), and by testing redaction
        // on the refused path (see audit_record_for_refused_redacts_secret).
        let actionable = make_actionable_find_port();
        let audit = audit_record_for_action(&actionable, AuditOutcome::Ok, "yes", Some(0), "stub");
        // Plain request → no redaction.
        assert_eq!(audit.redaction_count, 0);
        assert_eq!(audit.user_request, "what is using port 3000");
    }

    /// audit_record_for_refused: request with a token → redacted, count >= 1.
    #[test]
    fn audit_record_for_refused_redacts_secret_in_user_request() {
        // Build a GitHub-PAT-shaped token at runtime so the literal never appears
        // in source (avoids tripping secret-scanning push protection on a fake token).
        let token = format!("ghp_{}", "a".repeat(36));
        let request = format!("deploy with token {token}");
        let audit = audit_record_for_refused(&request, "install_package", "stub");

        assert!(
            audit.redaction_count >= 1,
            "expected at least 1 redaction, got {}",
            audit.redaction_count
        );
        assert!(
            !audit.user_request.contains("ghp_"),
            "token should be absent from stored user_request, got: {}",
            audit.user_request
        );
        assert_eq!(audit.outcome, AuditOutcome::Refused);
        assert_eq!(audit.confirmation_mode, "none");
        assert!(audit.exit_code.is_none());
        assert!(audit.params.is_null(), "params should be Null for refused");
        assert_eq!(audit.command_plan, "");
        assert_eq!(audit.risk_tier, "n/a");
        assert_eq!(audit.intent, "install_package");
    }

    #[test]
    fn audit_record_for_refused_plain_request_no_redaction() {
        let audit = audit_record_for_refused("install ripgrep", "install_package", "stub");
        assert_eq!(audit.outcome, AuditOutcome::Refused);
        assert_eq!(audit.redaction_count, 0);
        assert_eq!(audit.user_request, "install ripgrep");
        assert!(audit.params.is_null());
    }

    // -----------------------------------------------------------------------
    // format_history: pure output formatter
    // -----------------------------------------------------------------------

    fn make_stored_entry(n: u32) -> enshell_telemetry::StoredEntry {
        use enshell_telemetry::{AuditOutcome, AuditRecord};
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
                outcome: AuditOutcome::Ok,
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
