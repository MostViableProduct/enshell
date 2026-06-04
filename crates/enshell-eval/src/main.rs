//! `enshell-eval` — run the NL→intent evaluation against the read-only fixtures.
//!
//! Two modes:
//!
//! - **Default** (no `--model`): run end-to-end through the deterministic fast
//!   path + stub. Always 100% — a regression check you can run locally or in CI.
//! - **`--model <path.gguf>`** (requires building with `--features llama`): run
//!   every fixture through the **real model in isolation** (fast path bypassed) to
//!   measure whether it produces correct intents often enough for Phase 0.
//!
//! See `docs/contributor-guides/model-verification.md` for the full runbook.

use enshell_eval::{load_cases, run, EvalCase, Report, READ_ONLY_FIXTURE};
use enshell_model::StubProvider;

const USAGE: &str = "\
enshell-eval — run the NL->intent eval against the read-only fixtures.

USAGE:
  enshell-eval [--threshold <0-100>]
      Run end-to-end against the deterministic stub + fast path (default).
  enshell-eval --model <path.gguf> [--threshold <0-100>]
      Run every case through the real model in isolation (fast path bypassed).
      Requires building with --features llama.

OPTIONS:
  --model <path>       GGUF model file to evaluate (needs --features llama).
  --threshold <0-100>  Exit non-zero if accuracy is below this percent (default 100).
  -h, --help           Show this help.";

struct Args {
    model: Option<String>,
    threshold: f64,
    help: bool,
}

fn parse_args<I: Iterator<Item = String>>(args: I) -> Result<Args, String> {
    let mut model = None;
    let mut threshold = 100.0_f64;
    let mut help = false;
    let mut it = args;

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" => help = true,
            "--model" => {
                model = Some(it.next().ok_or("--model requires a path argument")?);
            }
            "--threshold" => {
                let v = it.next().ok_or("--threshold requires a value")?;
                let t: f64 = v.parse().map_err(|_| format!("invalid --threshold: {v}"))?;
                if !(0.0..=100.0).contains(&t) {
                    return Err(format!("--threshold must be in 0..=100, got {t}"));
                }
                threshold = t;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(Args {
        model,
        threshold,
        help,
    })
}

fn main() {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    if args.help {
        println!("{USAGE}");
        return;
    }

    let cases = match load_cases(READ_ONLY_FIXTURE) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load fixture: {e}");
            std::process::exit(2);
        }
    };

    let (label, report) = match &args.model {
        Some(path) => (
            format!("model in isolation: {path}"),
            run_model(path, &cases),
        ),
        None => (
            "stub + fast path (end-to-end)".to_string(),
            run(StubProvider, &cases),
        ),
    };

    println!("enShell eval — read-only fixture ({label})");
    println!("-------------------------------------------------------------");
    for (id, reason) in &report.failures {
        println!("FAIL  {id}: {reason}");
    }
    println!(
        "{}/{} passed ({:.1}%) — threshold {:.0}%",
        report.passed,
        report.total,
        report.accuracy() * 100.0,
        args.threshold
    );

    if report.accuracy() * 100.0 < args.threshold {
        std::process::exit(1);
    }
}

/// Load the GGUF at `path` and run the fixtures through it in isolation.
#[cfg(feature = "llama")]
fn run_model(path: &str, cases: &[EvalCase]) -> Report {
    let provider = match enshell_llama::LlamaProvider::new(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to load model {path}: {e}");
            std::process::exit(2);
        }
    };
    enshell_eval::run_provider_only(provider, cases)
}

/// Without the `llama` feature there is no real provider to load.
#[cfg(not(feature = "llama"))]
fn run_model(_path: &str, _cases: &[EvalCase]) -> Report {
    eprintln!("--model requires the `llama` feature. Rebuild and run with:");
    eprintln!("  cargo run -p enshell-eval --features llama -- --model <path.gguf>");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args, String> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn defaults_are_stub_threshold_100() {
        let a = parse(&[]).expect("ok");
        assert!(a.model.is_none());
        assert_eq!(a.threshold, 100.0);
        assert!(!a.help);
    }

    #[test]
    fn parses_model_and_threshold() {
        let a = parse(&["--model", "/m.gguf", "--threshold", "80"]).expect("ok");
        assert_eq!(a.model.as_deref(), Some("/m.gguf"));
        assert_eq!(a.threshold, 80.0);
    }

    #[test]
    fn rejects_out_of_range_threshold() {
        assert!(parse(&["--threshold", "150"]).is_err());
    }

    #[test]
    fn rejects_unknown_arg_and_missing_value() {
        assert!(parse(&["--bogus"]).is_err());
        assert!(parse(&["--model"]).is_err());
    }

    #[test]
    fn help_flag_is_recognised() {
        assert!(parse(&["--help"]).expect("ok").help);
        assert!(parse(&["-h"]).expect("ok").help);
    }
}
