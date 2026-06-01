//! End-to-end orchestration tests: a natural-language string flows through the
//! whole read-only MVP pipeline using the deterministic stub model:
//!
//!   NL request -> enshell-model (StubProvider, untrusted JSON)
//!             -> enshell-core::prepare (validate -> classify -> render)
//!             -> preview / confirmation
//!             -> enshell-core::execute (no-shell CommandPlan via the executor)
//!
//! This proves the orchestration layer wires the pieces together AND keeps the
//! safety properties end to end with a real (stub) model in the loop.

use enshell_core::{Orchestrator, OrchestratorConfig, Prepared};
use enshell_model::StubProvider;
use enshell_os::ExecControl;

fn orchestrator() -> Orchestrator<StubProvider> {
    Orchestrator::new(StubProvider, OrchestratorConfig::default())
}

/// A recognized read-only request prepares into an actionable plan whose preview
/// shows the literal command.
#[test]
fn natural_language_prepares_a_read_only_action() {
    let prepared = orchestrator()
        .prepare("what is using port 3000")
        .expect("prepare should succeed");

    match prepared {
        Prepared::Actionable(a) => {
            assert!(
                a.preview().contains("3000"),
                "preview should mention the port; got: {}",
                a.preview()
            );
            // The rendered plan must be shell-free.
            assert!(!enshell_os::plan_requires_shell(a.plan()));
        }
        other => panic!("expected Actionable, got {other:?}"),
    }
}

/// An unrecognized request surfaces as a clarification, not a guessed action.
#[test]
fn unrecognized_request_asks_for_clarification() {
    let prepared = orchestrator()
        .prepare("fizzbuzz wibble zort")
        .expect("prepare should succeed");
    assert!(
        matches!(prepared, Prepared::Clarify { .. }),
        "expected Clarify, got {prepared:?}"
    );
}

/// `open <path>` is side-effecting (launches a handler): even via natural
/// language and `--yes`, core refuses to auto-run it without interactive
/// confirmation. (We assert the gate WITHOUT actually launching anything.)
#[test]
fn open_request_is_not_auto_runnable_with_yes() {
    let orch = orchestrator();
    let prepared = orch
        .prepare("open /tmp/enshell-example.txt")
        .expect("prepare should succeed");

    let actionable = match prepared {
        Prepared::Actionable(a) => a,
        other => panic!("expected Actionable, got {other:?}"),
    };

    let confirmation = enshell_core::Confirmation {
        yes_flag: true,
        interactively_confirmed: false,
        typed_phrase: None,
    };
    let result = orch.execute(&actionable, &confirmation, &ExecControl::default());
    assert!(
        matches!(result, Err(enshell_core::CoreError::ConfirmationRequired)),
        "--yes must not auto-run open_file_or_folder; got {result:?}"
    );
}

/// Full chain on Unix: "find the largest files here" -> stub -> validated intent
/// -> ReadOnly policy -> du|sort|head plan -> executed via the no-shell executor,
/// producing real output with exit code 0.
#[cfg(unix)]
#[test]
fn full_natural_language_chain_executes_on_unix() {
    let orch = orchestrator();
    let prepared = orch
        .prepare("find the largest files here")
        .expect("prepare should succeed");

    let actionable = match prepared {
        Prepared::Actionable(a) => a,
        other => panic!("expected Actionable, got {other:?}"),
    };
    assert!(!enshell_os::plan_requires_shell(actionable.plan()));

    // Read-only + --yes is auto-confirmable per the Confirmation Invariant.
    let confirmation = enshell_core::Confirmation {
        yes_flag: true,
        interactively_confirmed: false,
        typed_phrase: None,
    };
    let record = orch
        .execute(&actionable, &confirmation, &ExecControl::default())
        .expect("read-only pipeline should execute");

    assert_eq!(record.exit_code, Some(0));
    assert!(
        !record.stdout.is_empty(),
        "du|sort|head over the current directory should produce output"
    );
}
