//! `enshell-eval` — run the NL→intent evaluation against the deterministic
//! fast path + stub provider and print a report. Exits non-zero if any case
//! fails, so it doubles as a check you can run locally or in CI.
//!
//! When a real model is available, this is the harness you point at it (swap the
//! provider) to measure Phase-0 readiness against the same fixtures.

use enshell_eval::{load_cases, run, READ_ONLY_FIXTURE};
use enshell_model::StubProvider;

fn main() {
    let cases = match load_cases(READ_ONLY_FIXTURE) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load fixture: {e}");
            std::process::exit(2);
        }
    };

    let report = run(StubProvider, &cases);

    println!("enShell eval — read-only fixture (provider: stub + fast path)");
    println!("-------------------------------------------------------------");
    for (id, reason) in &report.failures {
        println!("FAIL  {id}: {reason}");
    }
    println!(
        "{}/{} passed ({:.1}%)",
        report.passed,
        report.total,
        report.accuracy() * 100.0
    );

    if report.passed != report.total {
        std::process::exit(1);
    }
}
