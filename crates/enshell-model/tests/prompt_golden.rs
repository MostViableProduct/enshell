//! Golden-snapshot tests for the model prompt (§14: golden prompts).
//!
//! These pin the exact text fed to the model: the system prompt, the intent tool
//! schema, the few-shot examples, and the fully-assembled prompt for a canonical
//! request. A change to any of them shifts model behaviour, so it must be a
//! **deliberate, reviewed edit** — not silent drift from an unrelated change.
//!
//! ## Updating goldens after an intentional prompt change
//!
//! ```text
//! ENSHELL_BLESS=1 cargo test -p enshell-model --test prompt_golden
//! ```
//!
//! then review the diff in `tests/golden/` and commit it. Without `ENSHELL_BLESS`,
//! the tests compare against the committed goldens and fail on any difference.
//!
//! No snapshot framework / extra dependency: the goldens are plain committed files
//! and the comparison is an exact string match.

use std::path::PathBuf;

use enshell_model::{
    build_prompt, few_shot_examples, intent_grammar, intent_tool_schema, system_prompt,
    ModelRequest,
};
use enshell_os::Os;

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name)
}

/// Compare `actual` to the committed golden `name`. In bless mode (`ENSHELL_BLESS`
/// set) (over)write the golden instead of asserting.
fn check_golden(name: &str, actual: &str) {
    let path = golden_path(name);

    if std::env::var_os("ENSHELL_BLESS").is_some() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create golden dir");
        }
        std::fs::write(&path, actual).expect("write golden");
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "golden '{name}' missing or unreadable ({e}). Generate it with: \
             ENSHELL_BLESS=1 cargo test -p enshell-model --test prompt_golden"
        )
    });

    assert_eq!(
        actual, expected,
        "prompt golden '{name}' changed. If this was intentional, re-bless with \
         `ENSHELL_BLESS=1 cargo test -p enshell-model --test prompt_golden` and commit the diff."
    );
}

/// A fixed request for the full-prompt golden, so the snapshot is deterministic.
fn canonical_request() -> ModelRequest {
    ModelRequest {
        user_request: "what is using port 3000".to_string(),
        os: Os::Linux,
        cwd: Some("/home/user/project".to_string()),
    }
}

#[test]
fn golden_system_prompt() {
    check_golden("system_prompt.txt", &system_prompt());
}

#[test]
fn golden_intent_tool_schema() {
    let pretty = serde_json::to_string_pretty(&intent_tool_schema()).expect("schema serializes");
    check_golden("intent_tool_schema.json", &pretty);
}

#[test]
fn golden_few_shot_examples() {
    let mut rendered = String::new();
    for (i, (user, json)) in few_shot_examples().iter().enumerate() {
        rendered.push_str(&format!(
            "[Example {}]\nUser: {}\nAssistant: {}\n\n",
            i + 1,
            user,
            json
        ));
    }
    check_golden("few_shot_examples.txt", &rendered);
}

#[test]
fn golden_build_prompt() {
    let prompt = build_prompt(&canonical_request());
    check_golden("build_prompt.txt", &prompt.text);
}

#[test]
fn golden_intent_grammar() {
    check_golden("intent_grammar.gbnf", &intent_grammar());
}
