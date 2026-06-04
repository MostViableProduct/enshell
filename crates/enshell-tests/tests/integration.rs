//! Cross-crate integration tests for the read-only MVP execution chain:
//!
//!   Intent  ->  enshell-policy (classify)  ->  enshell-adapters (render)
//!           ->  enshell-os (CommandPlan, no-shell execute)
//!
//! These prove the safety properties hold *end to end across crates*, not just
//! within each unit. They are the integration counterpart to the per-crate tests.

use enshell_adapters::{render, AdapterError};
use enshell_intents::Intent;
use enshell_os::{current_os, plan_requires_shell, Os};
// `execute` actually runs a CommandPlan, which only the `#[cfg(unix)]` full-chain
// test below does; gating it keeps the Windows compile-check warning-clean.
#[cfg(unix)]
use enshell_os::execute;
use enshell_policy::{
    auto_confirm_allowed, classify, is_mvp_executable, requires_typed_confirmation,
    ClassifyContext, RiskTier,
};

/// A read-only intent classifies as ReadOnly, is MVP-executable, is `--yes`
/// eligible, and renders to a shell-free CommandPlan on every supported OS.
#[test]
fn read_only_intent_classifies_renders_and_is_shell_free() {
    let intent = Intent::FindProcessUsingPort { port: 3000 };

    let decision = classify(&intent, &ClassifyContext::default());
    assert_eq!(decision.tier, RiskTier::ReadOnly);
    assert!(is_mvp_executable(&decision));
    assert!(auto_confirm_allowed(&decision, true)); // --yes may auto-run read-only

    for os in [Os::MacOs, Os::Linux] {
        let plan = render(&intent, os).expect("read-only intent should render");
        assert!(
            !plan_requires_shell(&plan),
            "rendered plan for {os:?} must not require a shell"
        );
    }
}

/// A destructive intent is gated at every layer: not MVP-executable, `--yes`
/// cannot auto-run it, typed confirmation is required, and the adapter refuses
/// to render a command for it in the read-only MVP.
#[test]
fn destructive_intent_is_gated_end_to_end() {
    let intent = Intent::KillProcess {
        pid: None,
        name: None,
        port: Some(3000),
        force: Some(true),
    };

    let decision = classify(&intent, &ClassifyContext::default());
    assert_eq!(decision.tier, RiskTier::Destructive);
    assert!(!is_mvp_executable(&decision));
    assert!(
        !auto_confirm_allowed(&decision, true),
        "--yes must never auto-confirm a destructive action"
    );
    assert!(requires_typed_confirmation(&decision));

    assert!(matches!(
        render(&intent, Os::MacOs),
        Err(AdapterError::NotYetImplemented { .. })
    ));
}

/// A package/system-change intent is not executable in the read-only MVP, and
/// the adapter does not render a command for it yet.
#[test]
fn write_intent_is_not_mvp_executable() {
    let intent = Intent::InstallPackage {
        name: "postgresql".to_string(),
        manager: None,
        version: None,
    };

    let decision = classify(&intent, &ClassifyContext::default());
    assert!(!is_mvp_executable(&decision));
    assert!(matches!(
        render(&intent, Os::MacOs),
        Err(AdapterError::NotYetImplemented { .. })
    ));
}

/// `open_file_or_folder` is read-only tier but is side-effecting (launches an
/// external handler), so it is never `--yes`-auto-runnable, and the adapter
/// refuses URL/scheme arguments — only local paths render.
#[test]
fn open_file_or_folder_is_gated_and_rejects_urls() {
    // Policy: read-only tier, but NOT --yes eligible (always requires confirmation).
    let local = Intent::OpenFileOrFolder {
        path: "/Users/example/notes.txt".to_string(),
    };
    let decision = classify(&local, &ClassifyContext::default());
    assert_eq!(decision.tier, RiskTier::ReadOnly);
    assert!(
        !auto_confirm_allowed(&decision, true),
        "--yes must never auto-run open_file_or_folder"
    );

    // Adapter: a local path renders to a shell-free Exec; a URL is rejected.
    let plan = render(&local, Os::MacOs).expect("local path should render");
    assert!(!plan_requires_shell(&plan));

    let url = Intent::OpenFileOrFolder {
        path: "http://example.com".to_string(),
    };
    assert!(matches!(
        render(&url, Os::MacOs),
        Err(AdapterError::InvalidParameter { .. })
    ));
}

/// Intents that don't map to a command (clarification / explanation) are
/// reported as unsupported by the adapter rather than producing a plan.
#[test]
fn non_executable_intent_is_unsupported_by_adapter() {
    let intent = Intent::AskClarification {
        question: "which port?".to_string(),
        options: None,
    };
    assert!(matches!(
        render(&intent, current_os()),
        Err(AdapterError::Unsupported { .. })
    ));
}

/// Full chain on Unix: a read-only `find_large_files` intent renders to a
/// `du | sort | head` pipeline and the no-shell executor actually runs it
/// (via OS pipes, no `sh -c`), producing output. Uses this crate's own
/// directory as a small, always-present target.
#[cfg(unix)]
#[test]
fn full_chain_executes_read_only_pipeline_on_unix() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let intent = Intent::FindLargeFiles {
        path: dir.to_string(),
        min_size: None,
        limit: Some(5),
    };

    let decision = classify(&intent, &ClassifyContext::default());
    assert!(is_mvp_executable(&decision));

    let plan = render(&intent, current_os()).expect("find_large_files should render");
    assert!(!plan_requires_shell(&plan));

    let output = execute(&plan).expect("du|sort|head pipeline should execute");
    assert_eq!(output.exit_code, Some(0));
    assert!(
        !output.stdout.is_empty(),
        "du|sort|head over a non-empty directory should produce output"
    );
}
