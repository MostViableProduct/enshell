//! Deterministic risk classification, allow/deny lists, confirmation requirements.
//!
//! # Overview
//!
//! This crate is the **Layer 2 Safety & Policy Broker** described in the enShell
//! architecture plan. It accepts a typed [`enshell_intents::Intent`] and a
//! [`ClassifyContext`] supplied by the caller, and returns a deterministic
//! [`RiskDecision`].
//!
//! # Risk authority
//!
//! **Authoritative risk is assigned here from the intent type and parameters.**
//! The model's [`enshell_intents::RiskHint`] field is NEVER consulted by this
//! crate — `classify` does not accept a `RiskHint` argument and cannot be
//! influenced by it. This is enforced structurally: the function signature is
//! `classify(intent: &Intent, ctx: &ClassifyContext) -> RiskDecision`.
//!
//! # Confirmation Invariant (§3 of the architecture plan)
//!
//! > Nothing executes without the user's explicit confirmation.  `--yes` is valid
//! > **only** for `ReadOnly` and `LocalWriteCreateOnly`.  Every other tier always
//! > requires an interactive prompt; `Destructive` and `Privileged` additionally
//! > require a **typed** confirmation phrase.
//!
//! The helpers [`auto_confirm_allowed`], [`requires_typed_confirmation`], and
//! [`is_mvp_executable`] encode this invariant.

use enshell_intents::Intent;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Authoritative risk tier assigned by the policy engine.
///
/// Values are ordered from least to most impactful/dangerous but ordering is
/// NOT used for comparisons — tier identity is what matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskTier {
    /// Read-only diagnostics, no side effects.
    ReadOnly,
    /// Writes a **new** path that did not previously exist.
    LocalWriteCreateOnly,
    /// Overwrites or mutates existing state.
    LocalWriteMutating,
    /// Installs/removes packages, starts/stops services.
    PackageSystemChange,
    /// Makes outbound network connections.
    NetworkAccess,
    /// Reads or writes secrets, credentials, key material.
    SecretsSensitive,
    /// Recursive deletion, disk format, irreversible operations.
    Destructive,
    /// Requires elevated privileges (`sudo`, `runas`, etc.).
    Privileged,
    /// Ambiguous, unsupported, or clarification-only — never executed.
    UnsupportedAmbiguous,
}

/// The kind of user confirmation required before execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationKind {
    /// A light prompt (e.g. press any key, or skippable with `--yes`).
    Light,
    /// An explicit `[y/N]` interactive prompt.
    Explicit,
    /// The user must type a specific phrase (e.g. "delete 240 files").
    /// Also implies an elevation acknowledgement for `Privileged` tier.
    Typed,
}

/// Undo-plan requirement for this action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndoRequirement {
    /// Read-only or no-op; no undo needed.
    NotApplicable,
    /// An undo plan is strongly recommended.
    Recommended,
    /// An undo plan must be recorded before execution.
    Required,
    /// A mandatory backup/undo plan must be taken before execution.
    Mandatory,
}

/// The complete policy decision for a given intent + context.
#[derive(Debug, Clone)]
pub struct RiskDecision {
    /// The authoritative risk tier assigned by the policy engine.
    pub tier: RiskTier,
    /// The kind of confirmation required.
    pub confirmation: ConfirmationKind,
    /// Whether the user must additionally acknowledge privilege elevation.
    /// True only for `Privileged` tier.
    pub requires_elevation_ack: bool,
    /// Whether `--yes` may auto-confirm this action (without an interactive prompt).
    /// True only for `ReadOnly` and `LocalWriteCreateOnly`.
    pub yes_eligible: bool,
    /// Undo plan requirement.
    pub undo: UndoRequirement,
    /// Whether this tier is denied by default (user must clear the full ceremony).
    pub deny_by_default: bool,
    /// Human-readable reason summarising the classification decision.
    pub reason: &'static str,
}

/// Caller-supplied contextual facts used by `classify`.
///
/// All filesystem I/O is the caller's responsibility — `classify` is pure.
/// The default (`ClassifyContext::default()`) represents the conservative case:
/// `target_exists = false` (writing to a new, non-existent path).
#[derive(Debug, Clone, Default)]
pub struct ClassifyContext {
    /// `true`  → the target path (output file/dir) already exists on disk.
    ///           This causes write intents to be classified as mutating.
    /// `false` → target does not exist; write will create a new path (create-only).
    pub target_exists: bool,
}

// ---------------------------------------------------------------------------
// Core classification function
// ---------------------------------------------------------------------------

/// Classify an [`Intent`] into a [`RiskDecision`].
///
/// # Risk authority
///
/// The classification is derived **solely** from the intent type and the
/// caller-supplied [`ClassifyContext`].  The model's `RiskHint` is intentionally
/// excluded from the function signature and is never consulted here.
pub fn classify(intent: &Intent, ctx: &ClassifyContext) -> RiskDecision {
    match intent {
        // ------------------------------------------------------------------
        // Read-only intents: no side effects, safe to auto-run with --yes
        // ------------------------------------------------------------------
        Intent::FindLargeFiles { .. } => tier_decision(
            RiskTier::ReadOnly,
            "find_large_files reads the filesystem without modifying it",
        ),
        Intent::FindProcessUsingPort { .. } => tier_decision(
            RiskTier::ReadOnly,
            "find_process_using_port queries OS process/socket tables read-only",
        ),
        Intent::OpenFileOrFolder { .. } => tier_decision(
            RiskTier::ReadOnly,
            "open_file_or_folder launches the system GUI viewer; no writes occur",
        ),
        Intent::ExplainError { .. } => tier_decision(
            RiskTier::ReadOnly,
            "explain_error summarises a past failure in plain English; no execution",
        ),
        Intent::FixLastCommand { .. } => tier_decision(
            RiskTier::ReadOnly,
            "fix_last_command proposes a corrected intent but does not execute it; \
             the proposed fix is classified separately before any execution",
        ),
        Intent::CheckSystemHealth {} => tier_decision(
            RiskTier::ReadOnly,
            "check_system_health gathers diagnostic metrics without altering state",
        ),
        Intent::InspectLogs { .. } => tier_decision(
            RiskTier::ReadOnly,
            "inspect_logs reads log streams without modifying them",
        ),

        // ------------------------------------------------------------------
        // Local-write intents: create-only vs mutating depends on target_exists
        // ------------------------------------------------------------------
        Intent::CompressFolder { .. } => {
            if ctx.target_exists {
                tier_decision(
                    RiskTier::LocalWriteMutating,
                    "compress_folder: output archive already exists and would be overwritten",
                )
            } else {
                tier_decision(
                    RiskTier::LocalWriteCreateOnly,
                    "compress_folder: output archive does not exist; writing a new file",
                )
            }
        }
        Intent::CreateBackup { .. } => {
            if ctx.target_exists {
                tier_decision(
                    RiskTier::LocalWriteMutating,
                    "create_backup: destination already exists and would be overwritten",
                )
            } else {
                tier_decision(
                    RiskTier::LocalWriteCreateOnly,
                    "create_backup: destination does not exist; writing a new backup",
                )
            }
        }
        Intent::CreateProject { .. } => {
            if ctx.target_exists {
                tier_decision(
                    RiskTier::LocalWriteMutating,
                    "create_project: target directory already exists and would be modified",
                )
            } else {
                tier_decision(
                    RiskTier::LocalWriteCreateOnly,
                    "create_project: target directory does not exist; creating a new project",
                )
            }
        }
        Intent::GitCommitChanges { .. } => {
            // GitCommitChanges has no amend flag in the current intent schema.
            // A plain `git commit` always creates a new commit object and does
            // not overwrite existing history, so it is always create-only
            // regardless of ctx.target_exists.  If an `amend` flag is added in
            // a future schema version, it must be re-classified as mutating.
            tier_decision(
                RiskTier::LocalWriteCreateOnly,
                "git_commit_changes: creates a new commit object; no existing history is mutated \
                 (no amend flag in this schema version)",
            )
        }

        // ------------------------------------------------------------------
        // KillProcess: mutating normally; Destructive when force == Some(true)
        // ------------------------------------------------------------------
        Intent::KillProcess { force, .. } => {
            if matches!(force, Some(true)) {
                tier_decision(
                    RiskTier::Destructive,
                    "kill_process with force=true: forcibly terminates a process (SIGKILL / -9); \
                     irreversible",
                )
            } else {
                tier_decision(
                    RiskTier::LocalWriteMutating,
                    "kill_process: sends a termination signal to a running process; \
                     irreversible but graceful",
                )
            }
        }

        // ------------------------------------------------------------------
        // Package/system-change intents
        // ------------------------------------------------------------------
        Intent::InstallPackage { .. } => tier_decision(
            RiskTier::PackageSystemChange,
            "install_package modifies the system package database",
        ),
        Intent::StartService { .. } => tier_decision(
            RiskTier::PackageSystemChange,
            "start_service changes the running state of a system service",
        ),
        Intent::StopService { .. } => tier_decision(
            RiskTier::PackageSystemChange,
            "stop_service changes the running state of a system service",
        ),
        Intent::UpdatePackages { .. } => tier_decision(
            RiskTier::PackageSystemChange,
            "update_packages modifies installed package versions system-wide",
        ),

        // ------------------------------------------------------------------
        // Unsupported / ambiguous — never executed
        // ------------------------------------------------------------------
        Intent::AskClarification { .. } => tier_decision(
            RiskTier::UnsupportedAmbiguous,
            "ask_clarification is not an executable action; it requests user input",
        ),
    }
}

// ---------------------------------------------------------------------------
// Per-tier decision constructor (encodes the safety contract table from §3/§4)
// ---------------------------------------------------------------------------

/// Build a [`RiskDecision`] for the given tier, applying the canonical per-tier
/// rules from the architecture plan §3 Confirmation Invariant / §4 risk-tier table.
fn tier_decision(tier: RiskTier, reason: &'static str) -> RiskDecision {
    match tier {
        RiskTier::ReadOnly => RiskDecision {
            tier,
            confirmation: ConfirmationKind::Light,
            requires_elevation_ack: false,
            yes_eligible: true,
            undo: UndoRequirement::NotApplicable,
            deny_by_default: false,
            reason,
        },
        RiskTier::LocalWriteCreateOnly => RiskDecision {
            tier,
            confirmation: ConfirmationKind::Explicit,
            requires_elevation_ack: false,
            yes_eligible: true,
            undo: UndoRequirement::Recommended,
            deny_by_default: false,
            reason,
        },
        RiskTier::LocalWriteMutating => RiskDecision {
            tier,
            confirmation: ConfirmationKind::Explicit,
            requires_elevation_ack: false,
            yes_eligible: false,
            undo: UndoRequirement::Required,
            deny_by_default: false,
            reason,
        },
        RiskTier::PackageSystemChange => RiskDecision {
            tier,
            confirmation: ConfirmationKind::Explicit,
            requires_elevation_ack: false,
            yes_eligible: false,
            undo: UndoRequirement::Required,
            deny_by_default: false,
            reason,
        },
        RiskTier::NetworkAccess => RiskDecision {
            tier,
            confirmation: ConfirmationKind::Explicit,
            requires_elevation_ack: false,
            yes_eligible: false,
            undo: UndoRequirement::Required,
            deny_by_default: false,
            reason,
        },
        RiskTier::SecretsSensitive => RiskDecision {
            tier,
            confirmation: ConfirmationKind::Explicit,
            requires_elevation_ack: false,
            yes_eligible: false,
            undo: UndoRequirement::Required,
            deny_by_default: false,
            reason,
        },
        RiskTier::Destructive => RiskDecision {
            tier,
            confirmation: ConfirmationKind::Typed,
            requires_elevation_ack: false,
            yes_eligible: false,
            undo: UndoRequirement::Mandatory,
            deny_by_default: true,
            reason,
        },
        RiskTier::Privileged => RiskDecision {
            tier,
            confirmation: ConfirmationKind::Typed,
            requires_elevation_ack: true,
            yes_eligible: false,
            undo: UndoRequirement::Mandatory,
            deny_by_default: true,
            reason,
        },
        RiskTier::UnsupportedAmbiguous => RiskDecision {
            tier,
            confirmation: ConfirmationKind::Light,
            requires_elevation_ack: false,
            yes_eligible: false,
            undo: UndoRequirement::NotApplicable,
            deny_by_default: false,
            reason,
        },
    }
}

// ---------------------------------------------------------------------------
// Confirmation Invariant helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `--yes` may auto-confirm this action without an interactive
/// prompt.
///
/// Per the Confirmation Invariant (§3): `--yes` is valid ONLY for `ReadOnly` and
/// `LocalWriteCreateOnly`.  For every other tier this returns `false` even when
/// `yes_flag` is `true`.
pub fn auto_confirm_allowed(decision: &RiskDecision, yes_flag: bool) -> bool {
    yes_flag && decision.yes_eligible
}

/// Returns `true` if this action requires the user to type a confirmation phrase
/// (Destructive or Privileged tier).
pub fn requires_typed_confirmation(decision: &RiskDecision) -> bool {
    matches!(decision.tier, RiskTier::Destructive | RiskTier::Privileged)
}

/// Returns `true` if this action is executable in the MVP.
///
/// The MVP executes **only** `ReadOnly` intents.  Everything above that tier may
/// be classified and previewed but is not yet executed by the MVP runtime.
pub fn is_mvp_executable(decision: &RiskDecision) -> bool {
    decision.tier == RiskTier::ReadOnly
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use enshell_intents::Intent;

    // Helper: default context (target does not exist → create-only for write intents)
    fn ctx_new() -> ClassifyContext {
        ClassifyContext::default()
    }

    // Helper: context where the target already exists → mutating for write intents
    fn ctx_exists() -> ClassifyContext {
        ClassifyContext {
            target_exists: true,
        }
    }

    // -----------------------------------------------------------------------
    // Table-driven: each intent → expected tier
    // -----------------------------------------------------------------------

    #[test]
    fn find_large_files_is_read_only() {
        let intent = Intent::FindLargeFiles {
            path: "/tmp".into(),
            min_size: None,
            limit: None,
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::ReadOnly);
    }

    #[test]
    fn find_process_using_port_is_read_only() {
        let intent = Intent::FindProcessUsingPort { port: 3000 };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::ReadOnly);
    }

    #[test]
    fn open_file_or_folder_is_read_only() {
        let intent = Intent::OpenFileOrFolder {
            path: "/home/user/docs".into(),
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::ReadOnly);
    }

    #[test]
    fn explain_error_is_read_only() {
        let intent = Intent::ExplainError {
            command: Some("cargo build".into()),
            stderr: Some("error[E0308]".into()),
            exit_code: Some(101),
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::ReadOnly);
    }

    #[test]
    fn fix_last_command_is_read_only() {
        // FixLastCommand only *proposes* a fix; the proposed action is re-classified
        // separately. At classify-time it is read-only.
        let intent = Intent::FixLastCommand {
            last_command: "gti status".into(),
            exit_code: 127,
            stderr: "command not found".into(),
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::ReadOnly);
    }

    #[test]
    fn check_system_health_is_read_only() {
        let intent = Intent::CheckSystemHealth {};
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::ReadOnly);
    }

    #[test]
    fn inspect_logs_is_read_only() {
        let intent = Intent::InspectLogs {
            source: Some("system".into()),
            since: Some("1h".into()),
            filter: None,
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::ReadOnly);
    }

    // ------------------------------------------------------------------
    // KillProcess: graceful → LocalWriteMutating; force → Destructive
    // ------------------------------------------------------------------

    #[test]
    fn kill_process_graceful_is_local_write_mutating() {
        let intent = Intent::KillProcess {
            pid: Some(1234),
            name: None,
            port: None,
            force: None,
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::LocalWriteMutating);
    }

    #[test]
    fn kill_process_force_false_is_local_write_mutating() {
        let intent = Intent::KillProcess {
            pid: Some(1234),
            name: None,
            port: None,
            force: Some(false),
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::LocalWriteMutating);
    }

    #[test]
    fn kill_process_force_true_is_destructive() {
        let intent = Intent::KillProcess {
            pid: Some(1234),
            name: None,
            port: None,
            force: Some(true),
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::Destructive);
    }

    #[test]
    fn kill_process_force_true_deny_by_default() {
        let intent = Intent::KillProcess {
            pid: Some(999),
            name: None,
            port: None,
            force: Some(true),
        };
        let d = classify(&intent, &ctx_new());
        assert!(d.deny_by_default);
    }

    #[test]
    fn kill_process_force_true_undo_mandatory() {
        let intent = Intent::KillProcess {
            pid: Some(999),
            name: None,
            port: None,
            force: Some(true),
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.undo, UndoRequirement::Mandatory);
    }

    // ------------------------------------------------------------------
    // CompressFolder: ctx.target_exists controls tier
    // ------------------------------------------------------------------

    #[test]
    fn compress_folder_new_target_is_create_only() {
        let intent = Intent::CompressFolder {
            path: "/projects/app".into(),
            output: Some("/tmp/app.tar.gz".into()),
            exclude: None,
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::LocalWriteCreateOnly);
    }

    #[test]
    fn compress_folder_new_target_yes_eligible() {
        let intent = Intent::CompressFolder {
            path: "/projects/app".into(),
            output: None,
            exclude: None,
        };
        let d = classify(&intent, &ctx_new());
        assert!(d.yes_eligible, "create-only should be yes_eligible");
    }

    #[test]
    fn compress_folder_existing_target_is_mutating() {
        let intent = Intent::CompressFolder {
            path: "/projects/app".into(),
            output: Some("/tmp/app.tar.gz".into()),
            exclude: None,
        };
        let d = classify(&intent, &ctx_exists());
        assert_eq!(d.tier, RiskTier::LocalWriteMutating);
    }

    #[test]
    fn compress_folder_existing_target_not_yes_eligible() {
        let intent = Intent::CompressFolder {
            path: "/projects/app".into(),
            output: None,
            exclude: None,
        };
        let d = classify(&intent, &ctx_exists());
        assert!(
            !d.yes_eligible,
            "mutating should NOT be yes_eligible — --yes must not auto-run this"
        );
    }

    // ------------------------------------------------------------------
    // CreateBackup: ctx.target_exists controls tier
    // ------------------------------------------------------------------

    #[test]
    fn create_backup_new_dest_is_create_only() {
        let intent = Intent::CreateBackup {
            path: "/data".into(),
            dest: Some("/backups/data-2024".into()),
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::LocalWriteCreateOnly);
    }

    #[test]
    fn create_backup_existing_dest_is_mutating() {
        let intent = Intent::CreateBackup {
            path: "/data".into(),
            dest: None,
        };
        let d = classify(&intent, &ctx_exists());
        assert_eq!(d.tier, RiskTier::LocalWriteMutating);
    }

    // ------------------------------------------------------------------
    // CreateProject: ctx.target_exists controls tier
    // ------------------------------------------------------------------

    #[test]
    fn create_project_new_path_is_create_only() {
        let intent = Intent::CreateProject {
            kind: "nextjs".into(),
            name: "my-app".into(),
            path: None,
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::LocalWriteCreateOnly);
    }

    #[test]
    fn create_project_existing_path_is_mutating() {
        let intent = Intent::CreateProject {
            kind: "nextjs".into(),
            name: "my-app".into(),
            path: None,
        };
        let d = classify(&intent, &ctx_exists());
        assert_eq!(d.tier, RiskTier::LocalWriteMutating);
    }

    // ------------------------------------------------------------------
    // GitCommitChanges: always create-only (no amend flag in schema)
    // ------------------------------------------------------------------

    #[test]
    fn git_commit_changes_is_always_create_only() {
        let intent = Intent::GitCommitChanges {
            message: "feat: add thing".into(),
            add_all: Some(true),
        };
        // Even when target_exists=true, GitCommitChanges is create-only because
        // there is no amend flag in the current schema version.
        let d = classify(&intent, &ctx_exists());
        assert_eq!(d.tier, RiskTier::LocalWriteCreateOnly);
    }

    #[test]
    fn git_commit_changes_new_is_create_only() {
        let intent = Intent::GitCommitChanges {
            message: "fix: correction".into(),
            add_all: None,
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::LocalWriteCreateOnly);
    }

    // ------------------------------------------------------------------
    // Package/system change intents
    // ------------------------------------------------------------------

    #[test]
    fn install_package_is_package_system_change() {
        let intent = Intent::InstallPackage {
            name: "ripgrep".into(),
            manager: None,
            version: None,
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::PackageSystemChange);
    }

    #[test]
    fn start_service_is_package_system_change() {
        let intent = Intent::StartService {
            name: "postgresql".into(),
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::PackageSystemChange);
    }

    #[test]
    fn stop_service_is_package_system_change() {
        let intent = Intent::StopService {
            name: "nginx".into(),
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::PackageSystemChange);
    }

    #[test]
    fn update_packages_is_package_system_change() {
        let intent = Intent::UpdatePackages {
            manager: Some("apt".into()),
            scope: None,
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::PackageSystemChange);
    }

    // ------------------------------------------------------------------
    // AskClarification → UnsupportedAmbiguous
    // ------------------------------------------------------------------

    #[test]
    fn ask_clarification_is_unsupported_ambiguous() {
        let intent = Intent::AskClarification {
            question: "Which package manager?".into(),
            options: Some(vec!["brew".into(), "apt".into()]),
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::UnsupportedAmbiguous);
    }

    #[test]
    fn ask_clarification_is_not_mvp_executable() {
        let intent = Intent::AskClarification {
            question: "Can you clarify?".into(),
            options: None,
        };
        let d = classify(&intent, &ctx_new());
        assert!(!is_mvp_executable(&d));
    }

    // ------------------------------------------------------------------
    // auto_confirm_allowed — POSITIVE cases
    // ------------------------------------------------------------------

    #[test]
    fn auto_confirm_allowed_for_read_only_with_yes() {
        let intent = Intent::CheckSystemHealth {};
        let d = classify(&intent, &ctx_new());
        assert!(auto_confirm_allowed(&d, true));
    }

    #[test]
    fn auto_confirm_allowed_for_create_only_with_yes() {
        let intent = Intent::CompressFolder {
            path: "/foo".into(),
            output: None,
            exclude: None,
        };
        let d = classify(&intent, &ctx_new());
        assert!(auto_confirm_allowed(&d, true));
    }

    // ------------------------------------------------------------------
    // auto_confirm_allowed — NEGATIVE cases (--yes must NOT auto-run these)
    // ------------------------------------------------------------------

    #[test]
    fn auto_confirm_not_allowed_for_destructive_even_with_yes() {
        let intent = Intent::KillProcess {
            pid: Some(1),
            name: None,
            port: None,
            force: Some(true),
        };
        let d = classify(&intent, &ctx_new());
        assert!(
            !auto_confirm_allowed(&d, true),
            "Destructive must NOT be auto-confirmed with --yes"
        );
    }

    #[test]
    fn auto_confirm_not_allowed_for_package_system_change_even_with_yes() {
        let intent = Intent::InstallPackage {
            name: "htop".into(),
            manager: None,
            version: None,
        };
        let d = classify(&intent, &ctx_new());
        assert!(
            !auto_confirm_allowed(&d, true),
            "PackageSystemChange must NOT be auto-confirmed with --yes"
        );
    }

    #[test]
    fn auto_confirm_not_allowed_for_local_write_mutating_even_with_yes() {
        let intent = Intent::CompressFolder {
            path: "/foo".into(),
            output: None,
            exclude: None,
        };
        let d = classify(&intent, &ctx_exists()); // mutating because target exists
        assert!(
            !auto_confirm_allowed(&d, true),
            "LocalWriteMutating must NOT be auto-confirmed with --yes"
        );
    }

    #[test]
    fn auto_confirm_not_allowed_for_kill_process_graceful_with_yes() {
        // KillProcess without force is LocalWriteMutating → no auto-confirm
        let intent = Intent::KillProcess {
            pid: Some(42),
            name: None,
            port: None,
            force: None,
        };
        let d = classify(&intent, &ctx_new());
        assert!(
            !auto_confirm_allowed(&d, true),
            "LocalWriteMutating kill must NOT be auto-confirmed with --yes"
        );
    }

    #[test]
    fn auto_confirm_false_when_yes_flag_false() {
        // Even for ReadOnly, if yes_flag is false, no auto-confirm
        let intent = Intent::CheckSystemHealth {};
        let d = classify(&intent, &ctx_new());
        assert!(!auto_confirm_allowed(&d, false));
    }

    // ------------------------------------------------------------------
    // requires_typed_confirmation
    // ------------------------------------------------------------------

    #[test]
    fn requires_typed_confirmation_for_destructive() {
        let intent = Intent::KillProcess {
            pid: Some(1),
            name: None,
            port: None,
            force: Some(true),
        };
        let d = classify(&intent, &ctx_new());
        assert!(requires_typed_confirmation(&d));
    }

    #[test]
    fn requires_typed_confirmation_false_for_read_only() {
        let intent = Intent::FindLargeFiles {
            path: "/tmp".into(),
            min_size: None,
            limit: None,
        };
        let d = classify(&intent, &ctx_new());
        assert!(!requires_typed_confirmation(&d));
    }

    #[test]
    fn requires_typed_confirmation_false_for_package_system_change() {
        let intent = Intent::UpdatePackages {
            manager: None,
            scope: None,
        };
        let d = classify(&intent, &ctx_new());
        assert!(!requires_typed_confirmation(&d));
    }

    // ------------------------------------------------------------------
    // Destructive tier: full property checks
    // ------------------------------------------------------------------

    #[test]
    fn destructive_tier_full_properties() {
        let intent = Intent::KillProcess {
            pid: Some(1),
            name: None,
            port: None,
            force: Some(true),
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::Destructive);
        assert_eq!(d.confirmation, ConfirmationKind::Typed);
        assert!(!d.yes_eligible);
        assert!(d.deny_by_default);
        assert_eq!(d.undo, UndoRequirement::Mandatory);
        assert!(requires_typed_confirmation(&d));
        assert!(!is_mvp_executable(&d));
    }

    // ------------------------------------------------------------------
    // Privileged tier properties (constructed directly via tier_decision
    // since no current intent maps here — the tier exists for future use)
    // ------------------------------------------------------------------

    #[test]
    fn privileged_tier_properties_via_tier_decision() {
        let d = tier_decision(RiskTier::Privileged, "test privileged");
        assert_eq!(d.tier, RiskTier::Privileged);
        assert_eq!(d.confirmation, ConfirmationKind::Typed);
        assert!(
            d.requires_elevation_ack,
            "Privileged must require elevation ack"
        );
        assert!(!d.yes_eligible);
        assert!(d.deny_by_default);
        assert_eq!(d.undo, UndoRequirement::Mandatory);
        assert!(requires_typed_confirmation(&d));
        assert!(!is_mvp_executable(&d));
    }

    // ------------------------------------------------------------------
    // is_mvp_executable: true ONLY for ReadOnly
    // ------------------------------------------------------------------

    #[test]
    fn is_mvp_executable_true_for_read_only() {
        let intent = Intent::FindProcessUsingPort { port: 8080 };
        let d = classify(&intent, &ctx_new());
        assert!(is_mvp_executable(&d));
    }

    #[test]
    fn is_mvp_executable_false_for_create_only() {
        let intent = Intent::CompressFolder {
            path: "/foo".into(),
            output: None,
            exclude: None,
        };
        let d = classify(&intent, &ctx_new());
        assert!(!is_mvp_executable(&d));
    }

    #[test]
    fn is_mvp_executable_false_for_mutating() {
        let intent = Intent::CompressFolder {
            path: "/foo".into(),
            output: None,
            exclude: None,
        };
        let d = classify(&intent, &ctx_exists());
        assert!(!is_mvp_executable(&d));
    }

    #[test]
    fn is_mvp_executable_false_for_package_system_change() {
        let intent = Intent::StartService {
            name: "nginx".into(),
        };
        let d = classify(&intent, &ctx_new());
        assert!(!is_mvp_executable(&d));
    }

    #[test]
    fn is_mvp_executable_false_for_unsupported_ambiguous() {
        let intent = Intent::AskClarification {
            question: "what?".into(),
            options: None,
        };
        let d = classify(&intent, &ctx_new());
        assert!(!is_mvp_executable(&d));
    }

    // ------------------------------------------------------------------
    // ReadOnly tier: full property checks
    // ------------------------------------------------------------------

    #[test]
    fn read_only_full_properties() {
        let intent = Intent::InspectLogs {
            source: None,
            since: None,
            filter: None,
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::ReadOnly);
        assert_eq!(d.confirmation, ConfirmationKind::Light);
        assert!(!d.requires_elevation_ack);
        assert!(d.yes_eligible);
        assert_eq!(d.undo, UndoRequirement::NotApplicable);
        assert!(!d.deny_by_default);
    }

    // ------------------------------------------------------------------
    // LocalWriteCreateOnly full property checks
    // ------------------------------------------------------------------

    #[test]
    fn local_write_create_only_full_properties() {
        let intent = Intent::CreateBackup {
            path: "/data".into(),
            dest: None,
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::LocalWriteCreateOnly);
        assert_eq!(d.confirmation, ConfirmationKind::Explicit);
        assert!(!d.requires_elevation_ack);
        assert!(d.yes_eligible);
        assert_eq!(d.undo, UndoRequirement::Recommended);
        assert!(!d.deny_by_default);
    }

    // ------------------------------------------------------------------
    // LocalWriteMutating full property checks
    // ------------------------------------------------------------------

    #[test]
    fn local_write_mutating_full_properties() {
        let intent = Intent::CreateBackup {
            path: "/data".into(),
            dest: None,
        };
        let d = classify(&intent, &ctx_exists());
        assert_eq!(d.tier, RiskTier::LocalWriteMutating);
        assert_eq!(d.confirmation, ConfirmationKind::Explicit);
        assert!(!d.requires_elevation_ack);
        assert!(!d.yes_eligible);
        assert_eq!(d.undo, UndoRequirement::Required);
        assert!(!d.deny_by_default);
    }

    // ------------------------------------------------------------------
    // PackageSystemChange full property checks
    // ------------------------------------------------------------------

    #[test]
    fn package_system_change_full_properties() {
        let intent = Intent::InstallPackage {
            name: "vim".into(),
            manager: Some("brew".into()),
            version: None,
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::PackageSystemChange);
        assert_eq!(d.confirmation, ConfirmationKind::Explicit);
        assert!(!d.requires_elevation_ack);
        assert!(!d.yes_eligible);
        assert_eq!(d.undo, UndoRequirement::Required);
        assert!(!d.deny_by_default);
    }

    // ------------------------------------------------------------------
    // UnsupportedAmbiguous full property checks
    // ------------------------------------------------------------------

    #[test]
    fn unsupported_ambiguous_full_properties() {
        let intent = Intent::AskClarification {
            question: "Which manager?".into(),
            options: None,
        };
        let d = classify(&intent, &ctx_new());
        assert_eq!(d.tier, RiskTier::UnsupportedAmbiguous);
        assert!(!d.yes_eligible);
        assert!(!d.deny_by_default); // just don't run — not blocked by deny_by_default
        assert_eq!(d.undo, UndoRequirement::NotApplicable);
    }

    // ------------------------------------------------------------------
    // ClassifyContext::default() is target_exists = false
    // ------------------------------------------------------------------

    #[test]
    fn classify_context_default_is_target_not_exists() {
        let ctx = ClassifyContext::default();
        assert!(!ctx.target_exists);
    }

    // ------------------------------------------------------------------
    // reason field is non-empty for every intent
    // ------------------------------------------------------------------

    fn all_test_intents() -> Vec<Intent> {
        vec![
            Intent::FindLargeFiles {
                path: "/tmp".into(),
                min_size: None,
                limit: None,
            },
            Intent::FindProcessUsingPort { port: 80 },
            Intent::KillProcess {
                pid: Some(1),
                name: None,
                port: None,
                force: None,
            },
            Intent::KillProcess {
                pid: Some(1),
                name: None,
                port: None,
                force: Some(true),
            },
            Intent::InstallPackage {
                name: "x".into(),
                manager: None,
                version: None,
            },
            Intent::StartService { name: "svc".into() },
            Intent::StopService { name: "svc".into() },
            Intent::OpenFileOrFolder {
                path: "/tmp".into(),
            },
            Intent::CompressFolder {
                path: "/foo".into(),
                output: None,
                exclude: None,
            },
            Intent::CreateBackup {
                path: "/foo".into(),
                dest: None,
            },
            Intent::ExplainError {
                command: None,
                stderr: None,
                exit_code: None,
            },
            Intent::FixLastCommand {
                last_command: "cmd".into(),
                exit_code: 1,
                stderr: "err".into(),
            },
            Intent::UpdatePackages {
                manager: None,
                scope: None,
            },
            Intent::CheckSystemHealth {},
            Intent::InspectLogs {
                source: None,
                since: None,
                filter: None,
            },
            Intent::CreateProject {
                kind: "rust".into(),
                name: "proj".into(),
                path: None,
            },
            Intent::GitCommitChanges {
                message: "msg".into(),
                add_all: None,
            },
            Intent::AskClarification {
                question: "q?".into(),
                options: None,
            },
        ]
    }

    #[test]
    fn reason_is_nonempty_for_all_intents() {
        for intent in all_test_intents() {
            let d = classify(&intent, &ctx_new());
            assert!(
                !d.reason.is_empty(),
                "reason was empty for intent: {intent:?}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Structural proof: RiskHint is never consulted
    // The classify function signature `classify(intent: &Intent, ctx: &ClassifyContext)`
    // structurally excludes RiskHint — this test simply confirms the same intent
    // produces the same decision regardless of what a model might have put in
    // its risk hint field (by showing classify is deterministic given the same inputs).
    // ------------------------------------------------------------------

    #[test]
    fn classification_is_deterministic_and_hint_irrelevant() {
        // Run classify twice with the same inputs; results must be identical.
        // (Since classify never accepts a RiskHint, any RiskHint the model
        // emitted has no path into classify — this is enforced by the type system.)
        let intent = Intent::CheckSystemHealth {};
        let ctx = ctx_new();
        let d1 = classify(&intent, &ctx);
        let d2 = classify(&intent, &ctx);
        assert_eq!(d1.tier, d2.tier);
        assert_eq!(d1.yes_eligible, d2.yes_eligible);
        assert_eq!(d1.deny_by_default, d2.deny_by_default);
    }
}
