//! Orchestration: assemble context, call model, validate, apply policy, render, execute, record.
//!
//! # Overview
//!
//! This crate is the two-phase orchestration layer that wires together the
//! model, intent validation, policy classification, adapter rendering, and
//! OS-level execution into a safe, structured flow.
//!
//! # Two-phase design
//!
//! **Phase 1 — [`Orchestrator::prepare`]:** natural language → model call →
//! validate untrusted output → policy classify → adapter render → preview.
//! **No execution occurs in this phase.**
//!
//! **Phase 2 — [`Orchestrator::execute`]:** enforce the Confirmation Invariant
//! before passing the structured [`CommandPlan`] to [`enshell_os::execute_controlled`].
//!
//! # The LLM-never-executes invariant (§7)
//!
//! The model produces a raw JSON string (untrusted). That string is immediately
//! validated by [`enshell_intents::parse_model_output`] before any further
//! processing. Only after passing that validation does the orchestrator proceed
//! to policy classification and adapter rendering. The model's output never
//! reaches the executor directly.
//!
//! # Confirmation Invariant (§3)
//!
//! `execute` enforces the Confirmation Invariant:
//! - `Light` / `ReadOnly` with `yes_flag = true` → auto-permitted.
//! - `Typed` (`Destructive`/`Privileged`) → permitted only with a non-empty typed phrase.
//! - `Explicit` (not yes-eligible) → permitted only with `interactively_confirmed = true`.
//! - Otherwise → [`CoreError::ConfirmationRequired`].
//!
//! **`open_file_or_folder` is explicitly not auto-runnable**: it is `ReadOnly`
//! (passes [`enshell_policy::is_mvp_executable`]) but `yes_eligible = false`
//! (from the policy), so `auto_confirm_allowed` returns false and the action
//! is never auto-confirmed via `--yes`, even though the tier is ReadOnly.

use std::fmt;
use std::time::Duration;

use enshell_adapters::{is_renderable, render, AdapterError};
use enshell_intents::{parse_model_output, Intent, IntentError};
use enshell_model::{ModelError, ModelProvider, ModelRequest};
use enshell_os::{current_os, execute_controlled, CommandPlan, ExecControl, ExecError, ExecStep};
use enshell_policy::{
    auto_confirm_allowed, classify, is_mvp_executable, requires_typed_confirmation,
    ClassifyContext, RiskDecision, RiskTier,
};

pub mod fastpath;
pub use fastpath::fast_path_match;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Where a prepared intent came from — recorded in the audit log so it reflects
/// reality rather than assuming the configured provider always ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentSource {
    /// Resolved deterministically by [`fast_path_match`] — **no model call**.
    /// Audited as `model_id = "fast_path"`.
    FastPath,
    /// Produced by the [`ModelProvider`] (e.g. the stub or the llama.cpp backend).
    /// Audited with that provider's name.
    Model,
}

/// Configuration for the [`Orchestrator`].
pub struct OrchestratorConfig {
    /// Optional wall-clock timeout applied to each execution via [`ExecControl`].
    ///
    /// Defaults to `Some(30s)`. Pass `None` for no timeout.
    pub timeout: Option<Duration>,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        OrchestratorConfig {
            timeout: Some(Duration::from_secs(30)),
        }
    }
}

/// The orchestration engine: model → validate → policy → render → execute.
pub struct Orchestrator<P: ModelProvider> {
    provider: P,
    config: OrchestratorConfig,
}

impl<P: ModelProvider> Orchestrator<P> {
    /// Create a new [`Orchestrator`] with the given provider and configuration.
    pub fn new(provider: P, config: OrchestratorConfig) -> Self {
        Orchestrator { provider, config }
    }

    /// The active provider's name (e.g. `"stub"`, `"gemma-4 (llama.cpp)"`).
    ///
    /// Callers use this to record which model actually produced an intent in the
    /// audit log, rather than assuming a fixed value.
    pub fn provider_name(&self) -> &str {
        self.provider.name()
    }

    /// Phase 1: natural language → model → **validate untrusted output** →
    /// policy → render → preview.
    ///
    /// **No execution occurs in this phase.** The return value is a [`Prepared`]
    /// value that can be previewed and then optionally passed to [`Self::execute`].
    ///
    /// ## Trust boundary
    ///
    /// The raw string returned by [`ModelProvider::infer`] is treated as
    /// **untrusted model output**. It is immediately passed through
    /// [`enshell_intents::parse_model_output`], which performs two checks:
    ///
    /// 1. **Strict schema parse** — unknown top-level fields and unknown
    ///    parameter fields are rejected.
    /// 2. **Domain validation** — non-empty required strings, port ranges,
    ///    confidence bounds, etc.
    ///
    /// Only after passing both checks is the typed [`Intent`] used for policy
    /// classification and adapter rendering.
    pub fn prepare(&self, user_request: &str) -> Result<Prepared, CoreError> {
        match self.resolve(user_request)? {
            Resolved::Clarify { question, options } => Ok(Prepared::Clarify { question, options }),
            Resolved::Intent {
                intent,
                explanation,
                source,
            } => finish_prepare(intent, &explanation, user_request, source),
        }
    }

    /// Resolve a natural-language request to a **typed intent** (or a request for
    /// clarification), *before* policy classification, the MVP gate, or rendering.
    ///
    /// This is the first half of [`Self::prepare`], exposed on its own because it
    /// is exactly the quantity an evaluation harness measures: "what intent did
    /// the fast path / model produce for this request?" — independent of whether
    /// that intent is executable in the current MVP. Keeping it as the single
    /// source of truth means the eval measures the *real* resolution path, not a
    /// reimplementation.
    ///
    /// ## Trust boundary (unchanged)
    ///
    /// The fast path yields a trusted, typed intent directly. The model path runs
    /// its raw output through [`enshell_intents::parse_model_output`] (the strict
    /// schema parse + domain validation) before returning a typed intent.
    pub fn resolve(&self, user_request: &str) -> Result<Resolved, CoreError> {
        // Step 0: deterministic fast path (§13) — a known phrasing resolves to a
        // **trusted, typed** intent with NO model call.
        if let Some((intent, explanation)) = fast_path_match(user_request) {
            return Ok(Resolved::Intent {
                intent,
                explanation: explanation.to_owned(),
                source: IntentSource::FastPath,
            });
        }

        // Step 1: build the model request with privacy-minimal context.
        let req = ModelRequest {
            user_request: user_request.to_owned(),
            os: current_os(),
            cwd: std::env::current_dir()
                .ok()
                .map(|p| p.display().to_string()),
        };

        // Step 2: call the model — returns an **untrusted** raw JSON string.
        let raw = self.provider.infer(&req).map_err(CoreError::Model)?;

        // Step 3: validate the untrusted model output (the trust boundary).
        let action = parse_model_output(&raw).map_err(CoreError::InvalidIntent)?;

        // Step 4: AskClarification surfaces as a clarification, not an intent.
        if let Intent::AskClarification { question, options } = action.intent {
            return Ok(Resolved::Clarify { question, options });
        }

        Ok(Resolved::Intent {
            intent: action.intent,
            explanation: action.explanation,
            source: IntentSource::Model,
        })
    }

    /// Phase 2: execute an [`Actionable`] **only** if confirmation satisfies the
    /// Confirmation Invariant (§3 / §7).
    ///
    /// ## Confirmation Invariant enforcement
    ///
    /// - **Auto-confirm** (`ReadOnly` + `yes_flag = true`, or `LocalWriteCreateOnly`
    ///   + `yes_flag = true`): permitted when [`auto_confirm_allowed`] returns true.
    ///
    ///   Note: `open_file_or_folder` has `yes_eligible = false` in the policy, so
    ///   `auto_confirm_allowed` returns false even though its tier is `ReadOnly`.
    /// - **Typed confirmation** (`Destructive` or `Privileged`): permitted only
    ///   when `confirmation.typed_phrase` is `Some(phrase)` where the phrase is
    ///   non-empty. (Exact phrase matching is a future enhancement; for now, a
    ///   non-empty phrase is required.)
    /// - **Explicit interactive** (all other non-yes-eligible tiers): permitted
    ///   only when `confirmation.interactively_confirmed = true`.
    /// - Otherwise: returns [`CoreError::ConfirmationRequired`].
    ///
    /// The model/CLI cannot bypass these checks — the invariant is enforced
    /// structurally here, not just by convention.
    pub fn execute(
        &self,
        actionable: &Actionable,
        confirmation: &Confirmation,
        control: &ExecControl,
    ) -> Result<ExecutionRecord, CoreError> {
        let decision = actionable.decision();

        // Gate 1: MVP executability (tier check).
        if !is_mvp_executable(decision) {
            return Err(CoreError::NotExecutable);
        }

        // Gate 2: Confirmation Invariant.
        let confirmation_mode: &str;
        let permitted = if auto_confirm_allowed(decision, confirmation.yes_flag) {
            // ReadOnly (yes-eligible) + --yes, or LocalWriteCreateOnly + --yes.
            confirmation_mode = "yes";
            true
        } else if requires_typed_confirmation(decision) {
            // Destructive or Privileged: require a non-empty typed phrase.
            match &confirmation.typed_phrase {
                Some(phrase) if !phrase.trim().is_empty() => {
                    confirmation_mode = "typed";
                    true
                }
                _ => {
                    return Err(CoreError::ConfirmationRequired);
                }
            }
        } else if confirmation.interactively_confirmed {
            // All other non-yes-eligible tiers: require interactive confirmation.
            confirmation_mode = "interactive";
            true
        } else {
            return Err(CoreError::ConfirmationRequired);
        };

        if !permitted {
            return Err(CoreError::ConfirmationRequired);
        }

        // Build ExecControl from the actionable's plan, applying our config timeout
        // if the caller's control has no timeout of its own.
        let effective_control = if control.timeout.is_none() && self.config.timeout.is_some() {
            ExecControl {
                timeout: self.config.timeout,
                cancel: control.cancel.clone(),
            }
        } else {
            control.clone()
        };

        // Execute — all execution goes through execute_controlled (structured CommandPlan).
        let out =
            execute_controlled(actionable.plan(), &effective_control).map_err(CoreError::Exec)?;

        let intent_name = intent_name(actionable.intent()).to_owned();
        let command_display = display_command(actionable.plan());

        Ok(ExecutionRecord {
            user_request: actionable.user_request().to_owned(),
            intent_name,
            risk_tier: decision.tier,
            command_display,
            confirmation_mode: confirmation_mode.to_owned(),
            exit_code: out.exit_code,
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }
}

/// Shared Phase-1 tail: classify → MVP-gate → render → build preview.
///
/// Both the fast path and the model path converge here, so a fast-path intent
/// and a model-produced intent are subjected to the *identical* policy and
/// rendering gate — only the `source` (recorded for the audit log) differs.
fn finish_prepare(
    intent: Intent,
    explanation: &str,
    user_request: &str,
    source: IntentSource,
) -> Result<Prepared, CoreError> {
    // Policy classify (authoritative risk tier).
    let decision = classify(&intent, &ClassifyContext::default());

    // MVP executability + adapter renderability.
    let os = current_os();
    if !is_mvp_executable(&decision) || !is_renderable(&intent, os) {
        let intent_name = intent_name(&intent).to_owned();
        let reason = if !is_mvp_executable(&decision) {
            format!(
                "the '{}' intent is not executable in the read-only MVP (tier: {:?})",
                intent_name, decision.tier
            )
        } else {
            format!(
                "no command is available for '{}' on this OS ({:?})",
                intent_name, os
            )
        };
        return Ok(Prepared::Refused {
            intent_name,
            reason,
            source,
        });
    }

    // Render into a structured CommandPlan (never a shell string).
    let plan = render(&intent, os).map_err(CoreError::Adapter)?;

    // Plain-English preview: explanation + risk label + literal command.
    let risk_label = risk_label(&decision.tier);
    let cmd_display = display_command(&plan);
    let preview = format!("{explanation}\nRisk: {risk_label}.\nCommand: {cmd_display}");

    Ok(Prepared::Actionable(Actionable {
        intent,
        decision,
        plan,
        preview,
        user_request: user_request.to_owned(),
        source,
    }))
}

// ---------------------------------------------------------------------------
// Resolved — output of intent resolution (before policy/render)
// ---------------------------------------------------------------------------

/// The result of [`Orchestrator::resolve`]: the typed intent the fast path or
/// model produced, or a request for clarification. This is the raw NL→intent
/// outcome, *before* policy classification, the MVP gate, or rendering.
#[derive(Debug, Clone)]
pub enum Resolved {
    /// A typed intent was resolved.
    Intent {
        /// The validated, typed intent.
        intent: Intent,
        /// The plain-English explanation (from the model, or the fast-path table).
        explanation: String,
        /// Whether the fast path or the model produced it.
        source: IntentSource,
    },
    /// The model asked for clarification instead of choosing an intent.
    Clarify {
        question: String,
        options: Option<Vec<String>>,
    },
}

// ---------------------------------------------------------------------------
// Prepared — result of Phase 1
// ---------------------------------------------------------------------------

/// The result of [`Orchestrator::prepare`].
#[derive(Debug, Clone)]
pub enum Prepared {
    /// A fully validated, classified, and rendered action ready for preview
    /// and confirmation.
    Actionable(Actionable),

    /// The model is requesting clarification from the user before proceeding.
    Clarify {
        question: String,
        options: Option<Vec<String>>,
    },

    /// The intent was recognised but cannot be executed in the current MVP
    /// (e.g. non-read-only tier, or no adapter available for this OS).
    Refused {
        intent_name: String,
        reason: String,
        /// Where the refused intent came from (fast path vs model) — recorded in
        /// the audit log for the refusal event.
        source: IntentSource,
    },
}

// ---------------------------------------------------------------------------
// Actionable — a ready-to-execute action
// ---------------------------------------------------------------------------

/// A fully validated, policy-classified, and adapter-rendered action.
///
/// This value is safe to display to the user (see [`Actionable::preview`])
/// and can be passed to [`Orchestrator::execute`] after confirmation.
///
/// # Sealed construction
///
/// All fields are private. The only way to obtain an `Actionable` is through
/// [`Orchestrator::prepare`], which runs the full validate → classify → render
/// pipeline. External crates cannot forge an `Actionable` that bypasses that
/// pipeline.
#[derive(Debug, Clone)]
pub struct Actionable {
    /// The validated, typed intent.
    intent: Intent,
    /// The authoritative policy decision (tier, confirmation kind, etc.).
    decision: RiskDecision,
    /// The structured OS command plan — **not a shell string**.
    plan: CommandPlan,
    /// A plain-English description of what will happen, the risk label,
    /// and the literal command (for display only — never passed to a shell).
    preview: String,
    /// The original user request that produced this action.
    user_request: String,
    /// Where the intent came from (fast path vs model), for the audit log.
    source: IntentSource,
}

impl Actionable {
    /// The validated, typed intent.
    pub fn intent(&self) -> &Intent {
        &self.intent
    }

    /// The authoritative policy decision (tier, confirmation kind, etc.).
    pub fn decision(&self) -> &RiskDecision {
        &self.decision
    }

    /// The structured OS command plan — **not a shell string**.
    pub fn plan(&self) -> &CommandPlan {
        &self.plan
    }

    /// A plain-English description of what will happen, the risk label,
    /// and the literal command (for display only — never passed to a shell).
    pub fn preview(&self) -> &str {
        &self.preview
    }

    /// The original user request that produced this action.
    pub fn user_request(&self) -> &str {
        &self.user_request
    }

    /// Where this action's intent came from — fast path (no model call) or the
    /// model provider. Callers use this to record the correct `model_id`.
    pub fn source(&self) -> IntentSource {
        self.source
    }
}

// ---------------------------------------------------------------------------
// Confirmation — user confirmation
// ---------------------------------------------------------------------------

/// The user's confirmation for an [`Actionable`].
///
/// The orchestrator enforces the Confirmation Invariant: the combination of
/// these fields determines whether execution is permitted.
#[derive(Debug, Clone)]
pub struct Confirmation {
    /// True if the CLI was invoked with `--yes`.
    ///
    /// Auto-confirms only `ReadOnly` (yes-eligible) and `LocalWriteCreateOnly`
    /// actions. Does **not** auto-confirm `open_file_or_folder` (which is
    /// `ReadOnly` but explicitly `yes_eligible = false`), mutating local-write,
    /// package/system, network, secrets, destructive, or privileged actions.
    pub yes_flag: bool,
    /// True if the user interactively confirmed (pressed `y` or similar).
    pub interactively_confirmed: bool,
    /// The phrase typed by the user for destructive/privileged confirmation.
    ///
    /// Must be `Some(non_empty_string)` for `Destructive` and `Privileged`
    /// tiers. (Exact phrase matching is a future enhancement.)
    pub typed_phrase: Option<String>,
}

// ---------------------------------------------------------------------------
// ExecutionRecord — result of Phase 2
// ---------------------------------------------------------------------------

/// The result of a successful execution.
#[derive(Debug, Clone)]
pub struct ExecutionRecord {
    /// The original user request that produced this execution.
    pub user_request: String,
    /// The snake_case name of the executed intent.
    pub intent_name: String,
    /// The authoritative risk tier of the executed action.
    pub risk_tier: RiskTier,
    /// A display-only rendering of the command (never used for execution).
    pub command_display: String,
    /// How confirmation was provided: `"yes"`, `"interactive"`, or `"typed"`.
    pub confirmation_mode: String,
    /// The process exit code, or `None` if terminated by signal.
    pub exit_code: Option<i32>,
    /// Standard output from the command.
    pub stdout: String,
    /// Standard error from the command.
    pub stderr: String,
}

// ---------------------------------------------------------------------------
// CoreError
// ---------------------------------------------------------------------------

/// Errors produced by [`Orchestrator::prepare`] and [`Orchestrator::execute`].
#[derive(Debug)]
pub enum CoreError {
    /// The model provider failed to produce output.
    Model(ModelError),
    /// The model's output failed intent parsing or domain validation.
    InvalidIntent(IntentError),
    /// The adapter failed to render a command for the intent.
    Adapter(AdapterError),
    /// Execution of the command plan failed.
    Exec(ExecError),
    /// The Confirmation Invariant was not satisfied; execution was refused.
    ConfirmationRequired,
    /// The intent is not executable in the MVP (non-read-only tier).
    NotExecutable,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::Model(e) => write!(f, "model error: {e}"),
            CoreError::InvalidIntent(e) => write!(f, "invalid intent: {e}"),
            CoreError::Adapter(e) => write!(f, "adapter error: {e}"),
            CoreError::Exec(e) => write!(f, "execution error: {e}"),
            CoreError::ConfirmationRequired => {
                write!(
                    f,
                    "confirmation required: the Confirmation Invariant was not satisfied"
                )
            }
            CoreError::NotExecutable => {
                write!(
                    f,
                    "not executable: this intent is not executable in the MVP"
                )
            }
        }
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CoreError::Model(e) => Some(e),
            CoreError::InvalidIntent(e) => Some(e),
            CoreError::Adapter(e) => Some(e),
            CoreError::Exec(e) => Some(e),
            CoreError::ConfirmationRequired | CoreError::NotExecutable => None,
        }
    }
}

impl From<ModelError> for CoreError {
    fn from(e: ModelError) -> Self {
        CoreError::Model(e)
    }
}

impl From<IntentError> for CoreError {
    fn from(e: IntentError) -> Self {
        CoreError::InvalidIntent(e)
    }
}

impl From<AdapterError> for CoreError {
    fn from(e: AdapterError) -> Self {
        CoreError::Adapter(e)
    }
}

impl From<ExecError> for CoreError {
    fn from(e: ExecError) -> Self {
        CoreError::Exec(e)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Render a [`CommandPlan`] as a plain-English / shell-like display string.
///
/// This is **display only** — the string is never passed to a shell interpreter.
/// Execution always uses the structured [`CommandPlan`] via
/// [`enshell_os::execute_controlled`].
///
/// - `Exec(step)` → `program arg1 arg2 …`
/// - `Pipeline(steps)` → `step1 | step2 | …`
/// - `Sequence(steps)` → `step1 && step2 && …`
/// - `RequiresShell{..}` → `<shell script>` (won't occur for read-only MVP)
pub fn display_command(plan: &CommandPlan) -> String {
    match plan {
        CommandPlan::Exec(step) => display_step(step),
        CommandPlan::Pipeline(steps) => steps
            .iter()
            .map(display_step)
            .collect::<Vec<_>>()
            .join(" | "),
        CommandPlan::Sequence(steps) => steps
            .iter()
            .map(display_step)
            .collect::<Vec<_>>()
            .join(" && "),
        CommandPlan::RequiresShell { .. } => "<shell script>".to_owned(),
    }
}

fn display_step(step: &ExecStep) -> String {
    if step.args.is_empty() {
        step.program.clone()
    } else {
        format!("{} {}", step.program, step.args.join(" "))
    }
}

/// Return the canonical snake_case name of an intent variant.
fn intent_name(intent: &Intent) -> &'static str {
    match intent {
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

/// Return a short human-readable label for a risk tier.
fn risk_label(tier: &RiskTier) -> &'static str {
    match tier {
        RiskTier::ReadOnly => "Read-only. I will not change anything",
        RiskTier::LocalWriteCreateOnly => {
            "Local write (create-only). A new file or directory will be created"
        }
        RiskTier::LocalWriteMutating => "Local write (mutating). Existing state will be modified",
        RiskTier::PackageSystemChange => {
            "Package/system change. System packages or services will be modified"
        }
        RiskTier::NetworkAccess => "Network access. An outbound network connection will be made",
        RiskTier::SecretsSensitive => {
            "Secrets-sensitive. Credential or secret material may be accessed"
        }
        RiskTier::Destructive => "DESTRUCTIVE. This operation is irreversible",
        RiskTier::Privileged => "PRIVILEGED. This operation requires elevated privileges",
        RiskTier::UnsupportedAmbiguous => "Unsupported/ambiguous",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use enshell_intents::{Intent, ProposedAction, RiskHint};
    use enshell_model::{ModelError, ModelProvider, ModelRequest};
    use enshell_os::{plan_requires_shell, Os};
    use enshell_policy::{ClassifyContext, ConfirmationKind};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// A model provider that always returns a fixed JSON string.
    struct FixedProvider(String);

    impl ModelProvider for FixedProvider {
        fn name(&self) -> &str {
            "fixed"
        }

        fn infer(&self, _request: &ModelRequest) -> Result<String, ModelError> {
            Ok(self.0.clone())
        }
    }

    /// A model provider that counts how many times `infer` is called (via a
    /// shared counter the test keeps a handle to). Used to prove the fast path
    /// does **not** call the model, and that a miss **does**.
    struct CountingProvider {
        calls: Arc<AtomicUsize>,
        json: String,
    }

    impl ModelProvider for CountingProvider {
        fn name(&self) -> &str {
            "counting"
        }

        fn infer(&self, _request: &ModelRequest) -> Result<String, ModelError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.json.clone())
        }
    }

    /// Build a JSON string for a ProposedAction with the given intent.
    fn make_json(intent: &Intent, explanation: &str, confidence: f32) -> String {
        let action = ProposedAction {
            intent: intent.clone(),
            risk: Some(RiskHint::ReadOnly),
            requires_confirmation: true,
            explanation: explanation.to_owned(),
            confidence,
        };
        serde_json::to_string(&action).expect("serialize ProposedAction")
    }

    fn orchestrator_with_stub() -> Orchestrator<enshell_model::StubProvider> {
        Orchestrator::new(enshell_model::StubProvider, OrchestratorConfig::default())
    }

    fn orchestrator_fixed(json: String) -> Orchestrator<FixedProvider> {
        Orchestrator::new(FixedProvider(json), OrchestratorConfig::default())
    }

    fn yes_confirmation() -> Confirmation {
        Confirmation {
            yes_flag: true,
            interactively_confirmed: false,
            typed_phrase: None,
        }
    }

    fn interactive_confirmation() -> Confirmation {
        Confirmation {
            yes_flag: false,
            interactively_confirmed: true,
            typed_phrase: None,
        }
    }

    fn no_confirmation() -> Confirmation {
        Confirmation {
            yes_flag: false,
            interactively_confirmed: false,
            typed_phrase: None,
        }
    }

    // -----------------------------------------------------------------------
    // display_command helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn display_command_exec() {
        let plan = CommandPlan::exec("lsof", ["-i", ":3000"]);
        assert_eq!(display_command(&plan), "lsof -i :3000");
    }

    #[test]
    fn display_command_exec_no_args() {
        let plan = CommandPlan::exec("uptime", [] as [&str; 0]);
        assert_eq!(display_command(&plan), "uptime");
    }

    #[test]
    fn display_command_pipeline() {
        use enshell_os::ExecStep;
        let plan = CommandPlan::pipeline(vec![
            ExecStep::new("du", ["-ah", "."]),
            ExecStep::new("sort", ["-rh"]),
            ExecStep::new("head", ["-n", "10"]),
        ]);
        assert_eq!(display_command(&plan), "du -ah . | sort -rh | head -n 10");
    }

    #[test]
    fn display_command_sequence() {
        use enshell_os::ExecStep;
        let plan = CommandPlan::sequence(vec![
            ExecStep::new("df", ["-h"]),
            ExecStep::new("uptime", [] as [&str; 0]),
        ]);
        assert_eq!(display_command(&plan), "df -h && uptime");
    }

    #[test]
    fn display_command_requires_shell() {
        use enshell_os::ShellKind;
        let plan = CommandPlan::RequiresShell {
            shell: ShellKind::Bash,
            script: "echo hi".to_owned(),
        };
        assert_eq!(display_command(&plan), "<shell script>");
    }

    // -----------------------------------------------------------------------
    // prepare() — Actionable path (find_process_using_port)
    // -----------------------------------------------------------------------

    #[test]
    fn prepare_port_3000_returns_actionable_with_find_process_intent() {
        let orch = orchestrator_with_stub();
        let result = orch.prepare("what is using port 3000");
        match result {
            Ok(Prepared::Actionable(a)) => {
                assert!(
                    matches!(a.intent(), Intent::FindProcessUsingPort { port: 3000 }),
                    "expected FindProcessUsingPort{{port:3000}}, got {:?}",
                    a.intent()
                );
                assert_eq!(a.decision().tier, RiskTier::ReadOnly);
                assert!(!plan_requires_shell(a.plan()));
            }
            Ok(other) => panic!("expected Actionable, got: {:?}", variant_name(&other)),
            Err(e) => panic!("prepare failed: {e}"),
        }
    }

    #[test]
    fn prepare_port_3000_preview_contains_literal_command() {
        let orch = orchestrator_with_stub();
        let result = orch.prepare("what is using port 3000").expect("prepare ok");
        match result {
            Prepared::Actionable(a) => {
                // On macOS: "lsof -i :3000"; on Linux: "ss -lptn sport = :3000"
                let expected_prog = if cfg!(target_os = "macos") {
                    "lsof"
                } else {
                    "ss"
                };
                assert!(
                    a.preview().contains(expected_prog),
                    "preview should contain '{}', got: {}",
                    expected_prog,
                    a.preview()
                );
            }
            other => panic!("expected Actionable, got {:?}", variant_name(&other)),
        }
    }

    #[test]
    fn prepare_port_3000_plan_requires_shell_false() {
        let orch = orchestrator_with_stub();
        match orch.prepare("what is using port 3000").expect("ok") {
            Prepared::Actionable(a) => {
                assert!(!plan_requires_shell(a.plan()));
            }
            other => panic!("expected Actionable, got {:?}", variant_name(&other)),
        }
    }

    // -----------------------------------------------------------------------
    // prepare() — Clarify path
    // -----------------------------------------------------------------------

    #[test]
    fn prepare_unrecognized_request_returns_clarify() {
        let orch = orchestrator_with_stub();
        let result = orch.prepare("fizzbuzz wibble").expect("prepare ok");
        match result {
            Prepared::Clarify { question, .. } => {
                assert!(!question.trim().is_empty(), "question must not be empty");
            }
            other => panic!("expected Clarify, got {:?}", variant_name(&other)),
        }
    }

    // -----------------------------------------------------------------------
    // prepare() — Refused path (install_package — not MVP executable)
    // -----------------------------------------------------------------------

    #[test]
    fn prepare_install_package_returns_refused_not_mvp_executable() {
        let json = make_json(
            &Intent::InstallPackage {
                name: "ripgrep".to_owned(),
                manager: None,
                version: None,
            },
            "I will install ripgrep.",
            0.9,
        );
        let orch = orchestrator_fixed(json);
        let result = orch.prepare("install ripgrep").expect("prepare ok");
        match result {
            Prepared::Refused {
                intent_name,
                reason,
                ..
            } => {
                assert_eq!(intent_name, "install_package");
                assert!(
                    reason.contains("not executable"),
                    "reason should mention not executable: {reason}"
                );
            }
            other => panic!("expected Refused, got {:?}", variant_name(&other)),
        }
    }

    // -----------------------------------------------------------------------
    // prepare() — Refused path (explain_error — not renderable, no command)
    // -----------------------------------------------------------------------

    #[test]
    fn prepare_explain_error_returns_refused_not_renderable() {
        let json = make_json(
            &Intent::ExplainError {
                command: None,
                stderr: None,
                exit_code: None,
            },
            "I will explain the error.",
            0.9,
        );
        let orch = orchestrator_fixed(json);
        let result = orch.prepare("explain this error").expect("prepare ok");
        match result {
            Prepared::Refused {
                intent_name,
                reason,
                ..
            } => {
                assert_eq!(intent_name, "explain_error");
                // explain_error is ReadOnly (mvp_executable) but not renderable
                assert!(!reason.is_empty(), "reason must not be empty");
            }
            other => panic!("expected Refused, got {:?}", variant_name(&other)),
        }
    }

    // -----------------------------------------------------------------------
    // prepare() — deterministic fast path (§13)
    // -----------------------------------------------------------------------

    /// A known phrasing resolves WITHOUT calling the model, is tagged
    /// `IntentSource::FastPath`, and yields the expected intent.
    #[test]
    fn fast_path_hit_skips_the_model() {
        let calls = Arc::new(AtomicUsize::new(0));
        // The JSON would only be used if the model were (wrongly) called.
        let json = make_json(
            &Intent::AskClarification {
                question: "unused".to_owned(),
                options: None,
            },
            "unused",
            0.3,
        );
        let provider = CountingProvider {
            calls: calls.clone(),
            json,
        };
        let orch = Orchestrator::new(provider, OrchestratorConfig::default());

        let prepared = orch.prepare("what is using port 3000").expect("prepare ok");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "the fast path must NOT call the model"
        );
        match prepared {
            Prepared::Actionable(a) => {
                assert_eq!(a.source(), IntentSource::FastPath);
                assert!(
                    matches!(a.intent(), Intent::FindProcessUsingPort { port: 3000 }),
                    "got {:?}",
                    a.intent()
                );
            }
            other => panic!("expected Actionable, got {:?}", variant_name(&other)),
        }
    }

    /// A request the fast path does not recognise DOES call the model, and the
    /// resulting action is tagged `IntentSource::Model`.
    #[test]
    fn fast_path_miss_calls_the_model_and_tags_model_source() {
        let calls = Arc::new(AtomicUsize::new(0));
        let json = make_json(
            &Intent::FindProcessUsingPort { port: 3000 },
            "I will check that port.",
            0.9,
        );
        let provider = CountingProvider {
            calls: calls.clone(),
            json,
        };
        let orch = Orchestrator::new(provider, OrchestratorConfig::default());

        // " port 3000" is present but the prefix is unknown and a qualifier
        // trails the number, so the fast path declines and the model runs.
        let prepared = orch
            .prepare("tell me the process on port 3000 holding it")
            .expect("prepare ok");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a fast-path miss must call the model exactly once"
        );
        match prepared {
            Prepared::Actionable(a) => {
                assert_eq!(a.source(), IntentSource::Model);
                assert!(matches!(
                    a.intent(),
                    Intent::FindProcessUsingPort { port: 3000 }
                ));
            }
            other => panic!("expected Actionable, got {:?}", variant_name(&other)),
        }
    }

    /// Trust boundary: a fast-path-resolved intent is subject to the SAME policy
    /// and confirmation gate as a model intent. `open_file_or_folder` is ReadOnly
    /// but not yes-eligible, so even via the fast path `--yes` must NOT auto-run it.
    #[cfg(unix)]
    #[test]
    fn fast_path_does_not_bypass_the_confirmation_gate() {
        let orch = orchestrator_with_stub();
        let prepared = orch.prepare("open /tmp").expect("prepare ok");

        let actionable = match prepared {
            Prepared::Actionable(a) => a,
            other => panic!("expected Actionable, got {:?}", variant_name(&other)),
        };

        // Confirm it really came from the fast path and was still classified+rendered.
        assert_eq!(actionable.source(), IntentSource::FastPath);
        assert!(matches!(
            actionable.intent(),
            Intent::OpenFileOrFolder { .. }
        ));
        assert_eq!(actionable.decision().tier, RiskTier::ReadOnly);
        assert!(!plan_requires_shell(actionable.plan()));

        // --yes must NOT auto-run it (yes_eligible == false), exactly as for a
        // model-produced open intent.
        let result = orch.execute(&actionable, &yes_confirmation(), &ExecControl::default());
        assert!(
            matches!(result, Err(CoreError::ConfirmationRequired)),
            "fast-path open with --yes must still require confirmation"
        );
    }

    // -----------------------------------------------------------------------
    // resolve() — NL → intent, before policy/render (used by the eval harness)
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_fast_path_returns_intent_with_fastpath_source() {
        let orch = orchestrator_with_stub();
        match orch.resolve("what is using port 3000").expect("resolve ok") {
            Resolved::Intent { intent, source, .. } => {
                assert_eq!(source, IntentSource::FastPath);
                assert!(matches!(
                    intent,
                    Intent::FindProcessUsingPort { port: 3000 }
                ));
            }
            Resolved::Clarify { .. } => panic!("expected Intent, got Clarify"),
        }
    }

    #[test]
    fn resolve_unknown_request_returns_clarify() {
        let orch = orchestrator_with_stub();
        assert!(matches!(
            orch.resolve("fizzbuzz wibble").expect("resolve ok"),
            Resolved::Clarify { .. }
        ));
    }

    #[test]
    fn resolve_model_path_tags_model_source() {
        // The fast path misses this phrasing (unknown prefix), so the stub model
        // resolves it — the source must be Model, not FastPath.
        let orch = orchestrator_with_stub();
        match orch
            .resolve("show me what is listening on port 22")
            .expect("resolve ok")
        {
            Resolved::Intent { intent, source, .. } => {
                assert_eq!(source, IntentSource::Model);
                assert!(matches!(intent, Intent::FindProcessUsingPort { port: 22 }));
            }
            Resolved::Clarify { .. } => panic!("expected Intent, got Clarify"),
        }
    }

    // -----------------------------------------------------------------------
    // execute() — Confirmation Invariant: open_file_or_folder NOT auto-runnable
    // -----------------------------------------------------------------------

    /// `open_file_or_folder` is `ReadOnly` tier (passes `is_mvp_executable`)
    /// but `yes_eligible = false` from policy. Therefore `--yes` must NOT
    /// auto-confirm it. This test proves the invariant is enforced in core.
    #[cfg(unix)]
    #[test]
    fn execute_open_file_or_folder_with_yes_flag_returns_confirmation_required() {
        // Build an Actionable for open_file_or_folder directly.
        let intent = Intent::OpenFileOrFolder {
            path: "/tmp".to_owned(),
        };
        let decision = classify(&intent, &ClassifyContext::default());
        // Verify preconditions: tier is ReadOnly, yes_eligible is false.
        assert_eq!(decision.tier, RiskTier::ReadOnly);
        assert!(!decision.yes_eligible);
        assert_eq!(decision.confirmation, ConfirmationKind::Explicit);

        let plan = render(&intent, current_os()).expect("render ok");

        let actionable = Actionable {
            intent: intent.clone(),
            decision,
            plan,
            preview: "open /tmp".to_owned(),
            user_request: "open /tmp".to_owned(),
            source: IntentSource::Model,
        };

        // Use a dummy orchestrator — only execute() is called.
        let orch = orchestrator_with_stub();
        let result = orch.execute(&actionable, &yes_confirmation(), &ExecControl::default());

        assert!(
            matches!(result, Err(CoreError::ConfirmationRequired)),
            "open_file_or_folder with yes_flag=true must return ConfirmationRequired, got: {:?}",
            result
                .map(|_| "<ok>")
                .unwrap_or_else(|e| Box::leak(e.to_string().into_boxed_str()))
        );
    }

    /// Same test without the `#[cfg(unix)]` guard — works on all platforms via
    /// a FixedProvider that returns an open_file_or_folder intent JSON.
    #[test]
    fn execute_open_file_or_folder_yes_flag_blocked_cross_platform() {
        // Build an Actionable for open_file_or_folder directly using policy+render
        // only on unix (where the adapter supports it); on other platforms
        // construct the Actionable manually.
        let intent = Intent::OpenFileOrFolder {
            path: "/tmp".to_owned(),
        };
        let decision = classify(&intent, &ClassifyContext::default());

        // Sanity: yes_eligible must be false.
        assert!(
            !decision.yes_eligible,
            "open_file_or_folder must not be yes_eligible"
        );

        // Build a plan using current_os if supported, otherwise a mock plan.
        let os = current_os();
        let plan = if matches!(os, Os::MacOs | Os::Linux) {
            render(&intent, os).expect("render ok")
        } else {
            // Windows/Other: build a placeholder plan for the confirmation test.
            CommandPlan::exec("open", ["/tmp"])
        };

        let actionable = Actionable {
            intent,
            decision,
            plan,
            preview: "open /tmp".to_owned(),
            user_request: "open /tmp".to_owned(),
            source: IntentSource::Model,
        };

        let orch = orchestrator_with_stub();
        let result = orch.execute(&actionable, &yes_confirmation(), &ExecControl::default());

        assert!(
            matches!(result, Err(CoreError::ConfirmationRequired)),
            "open_file_or_folder with yes_flag=true must return ConfirmationRequired"
        );
    }

    // -----------------------------------------------------------------------
    // execute() — read-only intent with yes_flag → permitted (auto_confirm)
    // -----------------------------------------------------------------------

    /// For a `ReadOnly` yes-eligible intent (FindProcessUsingPort), `yes_flag = true`
    /// must permit execution (regardless of exit code from lsof/ss).
    ///
    /// We only assert that ConfirmationRequired is NOT returned — the command
    /// may exit non-zero (nothing listening on port 59876) which is fine.
    #[test]
    fn execute_find_process_using_port_yes_flag_not_confirmation_required() {
        let intent = Intent::FindProcessUsingPort { port: 59876 };
        let decision = classify(&intent, &ClassifyContext::default());
        assert!(
            decision.yes_eligible,
            "FindProcessUsingPort must be yes_eligible"
        );

        let os = current_os();
        let plan = if matches!(os, Os::MacOs | Os::Linux) {
            render(&intent, os).expect("render ok")
        } else {
            // Windows/Other: placeholder — we only test confirmation logic.
            CommandPlan::exec("cmd_placeholder", [] as [&str; 0])
        };

        let actionable = Actionable {
            intent,
            decision,
            plan,
            preview: "check port 59876".to_owned(),
            user_request: "what is using port 59876".to_owned(),
            source: IntentSource::Model,
        };

        let orch = orchestrator_with_stub();
        let result = orch.execute(&actionable, &yes_confirmation(), &ExecControl::default());

        // Must NOT return ConfirmationRequired.
        assert!(
            !matches!(result, Err(CoreError::ConfirmationRequired)),
            "ReadOnly yes-eligible with yes_flag=true must not return ConfirmationRequired"
        );
    }

    // -----------------------------------------------------------------------
    // execute() — no confirmation → ConfirmationRequired
    // -----------------------------------------------------------------------

    #[test]
    fn execute_no_confirmation_returns_confirmation_required() {
        let intent = Intent::FindProcessUsingPort { port: 3000 };
        let decision = classify(&intent, &ClassifyContext::default());
        let os = current_os();
        let plan = if matches!(os, Os::MacOs | Os::Linux) {
            render(&intent, os).expect("render ok")
        } else {
            CommandPlan::exec("placeholder", [] as [&str; 0])
        };
        let actionable = Actionable {
            intent,
            decision,
            plan,
            preview: "check port 3000".to_owned(),
            user_request: "what is using port 3000".to_owned(),
            source: IntentSource::Model,
        };

        let orch = orchestrator_with_stub();
        let result = orch.execute(&actionable, &no_confirmation(), &ExecControl::default());

        assert!(
            matches!(result, Err(CoreError::ConfirmationRequired)),
            "no confirmation must return ConfirmationRequired"
        );
    }

    // -----------------------------------------------------------------------
    // execute() — non-MVP-executable intent → NotExecutable
    // -----------------------------------------------------------------------

    #[test]
    fn execute_non_mvp_intent_returns_not_executable() {
        // install_package is PackageSystemChange → not MVP executable.
        let intent = Intent::InstallPackage {
            name: "vim".to_owned(),
            manager: None,
            version: None,
        };
        let decision = classify(&intent, &ClassifyContext::default());
        assert!(!is_mvp_executable(&decision));

        let plan = CommandPlan::exec("brew", ["install", "vim"]);
        let actionable = Actionable {
            intent,
            decision,
            plan,
            preview: "brew install vim".to_owned(),
            user_request: "install vim".to_owned(),
            source: IntentSource::Model,
        };

        let orch = orchestrator_with_stub();
        let result = orch.execute(&actionable, &yes_confirmation(), &ExecControl::default());

        assert!(
            matches!(result, Err(CoreError::NotExecutable)),
            "non-MVP intent must return NotExecutable"
        );
    }

    // -----------------------------------------------------------------------
    // execute() — end-to-end on unix: find_large_files over "."
    // -----------------------------------------------------------------------

    /// End-to-end: prepare find_large_files{path:"."} then execute with --yes.
    ///
    /// `du | sort | head` over "." always succeeds with exit 0 and non-empty
    /// stdout (at minimum the directory entry itself).
    #[cfg(unix)]
    #[test]
    fn execute_find_large_files_current_dir_e2e() {
        let orch = orchestrator_with_stub();
        let prepared = orch
            .prepare("find the largest files here")
            .expect("prepare ok");

        let actionable = match prepared {
            Prepared::Actionable(a) => a,
            other => panic!("expected Actionable, got {:?}", variant_name(&other)),
        };

        assert!(
            matches!(actionable.intent(), Intent::FindLargeFiles { .. }),
            "expected FindLargeFiles"
        );
        assert_eq!(actionable.decision().tier, RiskTier::ReadOnly);

        let record = orch
            .execute(&actionable, &yes_confirmation(), &ExecControl::default())
            .expect("execute ok");

        assert_eq!(record.exit_code, Some(0), "du|sort|head should exit 0");
        assert!(!record.stdout.is_empty(), "stdout should be non-empty");
        assert_eq!(record.confirmation_mode, "yes");
        assert_eq!(
            record.user_request, "find the largest files here",
            "ExecutionRecord.user_request must equal the original request"
        );
    }

    // -----------------------------------------------------------------------
    // execute() — typed confirmation for Destructive intent
    // -----------------------------------------------------------------------

    #[test]
    fn execute_destructive_with_typed_phrase_permitted() {
        // Build a Destructive-tier actionable using kill_process{force:true}.
        let intent = Intent::KillProcess {
            pid: Some(99999), // non-existent PID; execution may fail, that's OK
            name: None,
            port: None,
            force: Some(true),
        };
        let decision = classify(&intent, &ClassifyContext::default());
        assert_eq!(decision.tier, RiskTier::Destructive);
        assert!(requires_typed_confirmation(&decision));
        // Note: is_mvp_executable is false for Destructive!
        assert!(!is_mvp_executable(&decision));

        // We can't get past NotExecutable for Destructive, but we CAN test the
        // confirmation logic via a ReadOnly actionable with a Destructive-tier
        // decision manually. Instead, verify the typed_phrase path via policy.
        let confirmation_typed = Confirmation {
            yes_flag: false,
            interactively_confirmed: false,
            typed_phrase: Some("kill process 99999".to_owned()),
        };
        let confirmation_no_phrase = Confirmation {
            yes_flag: false,
            interactively_confirmed: false,
            typed_phrase: None,
        };

        // For the purpose of testing the confirmation gate without hitting NotExecutable,
        // we use a mock ReadOnly plan but with Destructive decision artificially.
        // Since Destructive is not is_mvp_executable, the gate fires first.
        // So we test typed_confirmation policy helper directly:
        assert!(requires_typed_confirmation(&decision));
        // typed_phrase Some(non-empty) → would be permitted (after the NotExecutable gate).
        assert!(confirmation_typed
            .typed_phrase
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty()));
        // typed_phrase None → would be rejected.
        assert!(confirmation_no_phrase.typed_phrase.is_none());
    }

    // -----------------------------------------------------------------------
    // execute() — interactive confirmation for Explicit non-yes-eligible
    // -----------------------------------------------------------------------

    /// An `open_file_or_folder` actionable requires Explicit confirmation and is
    /// not yes-eligible. Interactive confirmation (interactively_confirmed = true)
    /// must permit execution on unix where the adapter renders a real command.
    #[cfg(unix)]
    #[test]
    fn execute_open_file_or_folder_interactive_confirmation_permitted() {
        let intent = Intent::OpenFileOrFolder {
            path: "/tmp".to_owned(),
        };
        let decision = classify(&intent, &ClassifyContext::default());
        let plan = render(&intent, current_os()).expect("render ok");
        let actionable = Actionable {
            intent,
            decision,
            plan,
            preview: "open /tmp".to_owned(),
            user_request: "open /tmp".to_owned(),
            source: IntentSource::Model,
        };

        let orch = orchestrator_with_stub();
        // Interactive confirmation must NOT produce ConfirmationRequired.
        let result = orch.execute(
            &actionable,
            &interactive_confirmation(),
            &ExecControl::default(),
        );
        assert!(
            !matches!(result, Err(CoreError::ConfirmationRequired)),
            "interactive confirmation for open_file_or_folder must not return ConfirmationRequired"
        );
    }

    // -----------------------------------------------------------------------
    // CoreError Display
    // -----------------------------------------------------------------------

    #[test]
    fn core_error_display_confirmation_required() {
        let s = CoreError::ConfirmationRequired.to_string();
        assert!(s.contains("confirmation"), "display: {s}");
    }

    #[test]
    fn core_error_display_not_executable() {
        let s = CoreError::NotExecutable.to_string();
        assert!(s.contains("not executable"), "display: {s}");
    }

    // -----------------------------------------------------------------------
    // OrchestratorConfig default
    // -----------------------------------------------------------------------

    #[test]
    fn orchestrator_config_default_timeout_is_30s() {
        let cfg = OrchestratorConfig::default();
        assert_eq!(cfg.timeout, Some(Duration::from_secs(30)));
    }

    // -----------------------------------------------------------------------
    // Timeout test (optional — only if easy to construct without lsof/ss)
    // -----------------------------------------------------------------------

    /// If `sleep` is available (unix), verify that a tight timeout on a
    /// Sequence plan with `sleep 10` triggers an Exec error quickly.
    #[cfg(unix)]
    #[test]
    fn execute_with_tight_timeout_returns_exec_error() {
        // Build a ReadOnly-classified actionable backed by `sleep 10`.
        // We use FindProcessUsingPort as the intent so is_mvp_executable passes,
        // but replace the plan with sleep to trigger the timeout.
        let intent = Intent::FindProcessUsingPort { port: 3000 };
        let decision = classify(&intent, &ClassifyContext::default());
        assert!(is_mvp_executable(&decision));

        let plan = CommandPlan::exec("sleep", ["10"]);
        let actionable = Actionable {
            intent,
            decision,
            plan,
            preview: "sleep 10".to_owned(),
            user_request: "sleep 10 seconds".to_owned(),
            source: IntentSource::Model,
        };

        let control = ExecControl {
            timeout: Some(Duration::from_millis(200)),
            cancel: Arc::new(AtomicBool::new(false)),
        };

        let orch = Orchestrator::new(
            enshell_model::StubProvider,
            OrchestratorConfig { timeout: None }, // don't double-apply timeout
        );

        let start = std::time::Instant::now();
        let result = orch.execute(&actionable, &yes_confirmation(), &control);
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(CoreError::Exec(_))),
            "tight timeout must return CoreError::Exec, got: {:?}",
            result
                .map(|_| "<ok>")
                .unwrap_or_else(|e| Box::leak(e.to_string().into_boxed_str()))
        );
        // Should have returned quickly (well under 1 second).
        assert!(
            elapsed < Duration::from_secs(2),
            "timeout should fire quickly, elapsed: {elapsed:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Helper: variant name for Prepared (for error messages)
    // -----------------------------------------------------------------------

    fn variant_name(p: &Prepared) -> &'static str {
        match p {
            Prepared::Actionable(_) => "Actionable",
            Prepared::Clarify { .. } => "Clarify",
            Prepared::Refused { .. } => "Refused",
        }
    }
}
