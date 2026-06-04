//! Evaluation harness: measures **NL → intent accuracy** against a committed
//! fixture set.
//!
//! # Why this exists
//!
//! It is the yardstick for the model decision (§19.2 Open Question B): when a real
//! Gemma model is plugged in, the *same* fixtures and scoring answer the only
//! question that matters — "does this model produce correct intents often enough
//! for Phase 0, or do we step up to E4B?". Today it runs against the deterministic
//! fast path + stub and is asserted at 100% as a CI regression gate.
//!
//! Resolution goes through [`enshell_core::Orchestrator::resolve`] — the *real*
//! NL→intent path — so the harness measures the product, not a reimplementation.

use enshell_core::{Orchestrator, OrchestratorConfig, Resolved};
use enshell_intents::{parse_model_output, Intent};
use enshell_model::{ModelProvider, ModelRequest};
use enshell_os::current_os;
use serde::Deserialize;
use serde_json::{Map, Value};

/// The committed read-only fixture set, embedded at compile time so the harness
/// (binary and tests) is independent of the current working directory.
pub const READ_ONLY_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../eval/read_only.jsonl"
));

/// One evaluation case: a natural-language request and the intent it should
/// resolve to.
#[derive(Debug, Clone, Deserialize)]
pub struct EvalCase {
    /// Stable identifier (for reporting).
    pub id: String,
    /// The natural-language request.
    pub nl: String,
    /// The expected intent kind (snake_case, e.g. `find_process_using_port`).
    pub kind: String,
    /// Parameters that must match exactly.
    #[serde(default)]
    pub required: Map<String, Value>,
    /// Parameter keys that MAY appear (with any value) without failing — e.g. a
    /// field enShell fills with a default that a model is free to vary.
    #[serde(default)]
    pub allowed: Vec<String>,
}

/// The outcome of scoring one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail(String),
}

impl Outcome {
    pub fn is_pass(&self) -> bool {
        matches!(self, Outcome::Pass)
    }
}

/// Parse a JSONL fixture into cases. Blank lines are ignored.
pub fn load_cases(jsonl: &str) -> Result<Vec<EvalCase>, String> {
    let mut cases = Vec::new();
    for (i, line) in jsonl.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let case: EvalCase =
            serde_json::from_str(trimmed).map_err(|e| format!("line {}: {e}", i + 1))?;
        cases.push(case);
    }
    Ok(cases)
}

/// Score a produced intent against an expected case.
///
/// Pass iff: the kind matches, every `required` key/value matches exactly, and
/// every produced parameter with a **non-null** value is whitelisted by
/// `required` or `allowed` (so a model inventing extra fields fails). A `None`
/// produced intent (clarification or error) always fails.
pub fn score_case(case: &EvalCase, produced: Option<&Intent>) -> Outcome {
    let Some(intent) = produced else {
        return Outcome::Fail("no intent resolved (clarification or error)".to_owned());
    };

    // Intent serializes as {"intent": <kind>, "parameters": {...}} (adjacent tag).
    let value = match serde_json::to_value(intent) {
        Ok(v) => v,
        Err(e) => return Outcome::Fail(format!("could not serialize intent: {e}")),
    };

    let kind = value.get("intent").and_then(Value::as_str).unwrap_or("");
    if kind != case.kind {
        return Outcome::Fail(format!("kind: expected {}, got {kind}", case.kind));
    }

    let empty = Map::new();
    let params = value
        .get("parameters")
        .and_then(Value::as_object)
        .unwrap_or(&empty);

    // Required fields must match exactly.
    for (k, want) in &case.required {
        match params.get(k) {
            Some(got) if got == want => {}
            Some(got) => return Outcome::Fail(format!("param {k}: expected {want}, got {got}")),
            None => return Outcome::Fail(format!("param {k}: missing (expected {want})")),
        }
    }

    // No surprise non-null fields outside required ∪ allowed.
    for (k, v) in params {
        if v.is_null() {
            continue;
        }
        if case.required.contains_key(k) || case.allowed.iter().any(|a| a == k) {
            continue;
        }
        return Outcome::Fail(format!("unexpected parameter {k} = {v}"));
    }

    Outcome::Pass
}

/// The result of running a fixture set against a provider.
#[derive(Debug, Clone)]
pub struct Report {
    pub total: usize,
    pub passed: usize,
    /// `(case id, failure reason)` for every failing case.
    pub failures: Vec<(String, String)>,
}

impl Report {
    /// Accuracy in `[0.0, 1.0]`. An empty run scores `1.0` (nothing failed).
    pub fn accuracy(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            self.passed as f64 / self.total as f64
        }
    }
}

/// Run `cases` through an [`Orchestrator`] built on `provider`, scoring each by
/// resolving its NL to an intent via [`Orchestrator::resolve`] (the real path).
pub fn run<P: ModelProvider>(provider: P, cases: &[EvalCase]) -> Report {
    let orch = Orchestrator::new(provider, OrchestratorConfig::default());
    let mut passed = 0;
    let mut failures = Vec::new();

    for case in cases {
        let produced: Option<Intent> = match orch.resolve(&case.nl) {
            Ok(Resolved::Intent { intent, .. }) => Some(intent),
            Ok(Resolved::Clarify { .. }) | Err(_) => None,
        };
        match score_case(case, produced.as_ref()) {
            Outcome::Pass => passed += 1,
            Outcome::Fail(reason) => failures.push((case.id.clone(), reason)),
        }
    }

    Report {
        total: cases.len(),
        passed,
        failures,
    }
}

/// Run `cases` through the **provider in isolation** — bypassing the fast path —
/// so every case actually exercises the model.
///
/// This is what a *model-accuracy* eval wants: [`run`] goes through
/// `Orchestrator::resolve`, where the deterministic fast path would resolve the
/// common phrasings without ever calling the model, masking the model's real
/// accuracy. Here we call `provider.infer` + [`parse_model_output`] directly —
/// the canonical provider contract — so the number reflects the model. Use this
/// for `enshell-eval --model <gguf>`; use [`run`] for the end-to-end view.
pub fn run_provider_only<P: ModelProvider>(provider: P, cases: &[EvalCase]) -> Report {
    let mut passed = 0;
    let mut failures = Vec::new();

    for case in cases {
        let req = ModelRequest {
            user_request: case.nl.clone(),
            os: current_os(),
            cwd: None,
        };
        // infer (untrusted string) -> validate -> typed intent; AskClarification
        // and any error count as "no intent" (a fail for a concrete-intent case).
        let produced: Option<Intent> = provider
            .infer(&req)
            .ok()
            .and_then(|raw| parse_model_output(&raw).ok())
            .and_then(|action| match action.intent {
                Intent::AskClarification { .. } => None,
                other => Some(other),
            });

        match score_case(case, produced.as_ref()) {
            Outcome::Pass => passed += 1,
            Outcome::Fail(reason) => failures.push((case.id.clone(), reason)),
        }
    }

    Report {
        total: cases.len(),
        passed,
        failures,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use enshell_model::StubProvider;

    #[test]
    fn fixture_loads_and_is_nonempty() {
        let cases = load_cases(READ_ONLY_FIXTURE).expect("fixture parses");
        assert!(cases.len() >= 10, "expected the curated read-only set");
    }

    /// CI gate: the curated read-only fixtures must ALL resolve correctly via the
    /// fast path + stub. A regression in fast-path / stub / intent mapping fails here.
    #[test]
    fn read_only_fixture_passes_against_stub_and_fast_path() {
        let cases = load_cases(READ_ONLY_FIXTURE).expect("fixture parses");
        let report = run(StubProvider, &cases);
        assert_eq!(
            report.passed, report.total,
            "eval failures: {:?}",
            report.failures
        );
    }

    /// The fixtures must ALSO be resolvable provider-only (fast path bypassed), so
    /// a real-model `--model` run measures against cases the model can actually
    /// reach — not ones the fast path was silently covering.
    #[test]
    fn read_only_fixture_passes_provider_only_against_stub() {
        let cases = load_cases(READ_ONLY_FIXTURE).expect("fixture parses");
        let report = run_provider_only(StubProvider, &cases);
        assert_eq!(
            report.passed, report.total,
            "provider-only eval failures: {:?}",
            report.failures
        );
    }

    // --- score_case (pure) ---------------------------------------------------

    fn case(kind: &str, required: Value, allowed: &[&str]) -> EvalCase {
        EvalCase {
            id: "t".to_owned(),
            nl: "n".to_owned(),
            kind: kind.to_owned(),
            required: required.as_object().cloned().unwrap_or_default(),
            allowed: allowed.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn pass_on_kind_and_required_match() {
        let c = case(
            "find_process_using_port",
            serde_json::json!({"port": 3000}),
            &[],
        );
        let intent = Intent::FindProcessUsingPort { port: 3000 };
        assert_eq!(score_case(&c, Some(&intent)), Outcome::Pass);
    }

    #[test]
    fn fail_on_kind_mismatch() {
        let c = case(
            "find_process_using_port",
            serde_json::json!({"port": 3000}),
            &[],
        );
        assert!(matches!(
            score_case(&c, Some(&Intent::CheckSystemHealth {})),
            Outcome::Fail(_)
        ));
    }

    #[test]
    fn fail_on_required_value_mismatch() {
        let c = case(
            "find_process_using_port",
            serde_json::json!({"port": 3000}),
            &[],
        );
        let intent = Intent::FindProcessUsingPort { port: 9999 };
        assert!(matches!(score_case(&c, Some(&intent)), Outcome::Fail(_)));
    }

    #[test]
    fn pass_with_null_optionals_and_whitelisted_field() {
        // FindLargeFiles serializes limit:10, min_size:null. required pins path,
        // allowed whitelists limit, and the null min_size is ignored.
        let c = case(
            "find_large_files",
            serde_json::json!({"path": "."}),
            &["limit"],
        );
        let intent = Intent::FindLargeFiles {
            path: ".".to_owned(),
            min_size: None,
            limit: Some(10),
        };
        assert_eq!(score_case(&c, Some(&intent)), Outcome::Pass);
    }

    #[test]
    fn fail_on_surprise_non_null_field() {
        // limit present and non-null but NOT whitelisted → fail.
        let c = case("find_large_files", serde_json::json!({"path": "."}), &[]);
        let intent = Intent::FindLargeFiles {
            path: ".".to_owned(),
            min_size: None,
            limit: Some(10),
        };
        assert!(matches!(score_case(&c, Some(&intent)), Outcome::Fail(_)));
    }

    #[test]
    fn fail_on_no_intent() {
        let c = case("check_system_health", serde_json::json!({}), &[]);
        assert!(matches!(score_case(&c, None), Outcome::Fail(_)));
    }

    #[test]
    fn empty_run_scores_full_accuracy() {
        let report = Report {
            total: 0,
            passed: 0,
            failures: vec![],
        };
        assert_eq!(report.accuracy(), 1.0);
    }
}
