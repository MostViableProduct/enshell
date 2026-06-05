//! GBNF grammar derived from the intent catalog (Track A.3).
//!
//! [`intent_grammar`] returns a [GBNF] grammar that constrains a model's decoding
//! to a `ProposedAction` JSON object whose `intent` is one of the known intent
//! names. It sharply reduces the two failure modes small models actually hit —
//! **malformed JSON** and **invented intent names** — at generation time: the
//! string rule excludes raw control characters, numbers are well-formed, and the
//! object structure is balanced, while the `intent` field is restricted to the
//! catalog.
//!
//! It is **not** a substitute for validation. The grammar does not encode every
//! JSON nuance (e.g. lone unicode surrogate escapes), required parameters, or
//! exact value domains. [`enshell_intents::parse_model_output`] (the strict schema
//! parse + domain checks) remains the authoritative validator after generation.
//! The grammar *does* constrain each intent's `parameters` object to that intent's
//! declared keys with the right value type (see [`intent_grammar`]), so the model
//! cannot spill a stray top-level field such as `confidence` into `parameters` —
//! a real failure mode the per-intent coupling closes off at generation time.
//!
//! The intent-name alternatives are derived from [`crate::intent_tool_schema`], so
//! the grammar and the schema the model is shown share a single source of truth
//! and cannot drift apart.
//!
//! [GBNF]: https://github.com/ggml-org/llama.cpp/blob/master/grammars/README.md

use crate::intent_tool_schema;

/// The intent names the catalog exposes, in schema order.
///
/// Derived from [`crate::intent_tool_schema`] (the `intents[].name` fields).
pub fn intent_names() -> Vec<String> {
    intent_tool_schema()
        .get("intents")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|i| i.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// A GBNF grammar constraining decoding to a valid `ProposedAction` JSON object.
///
/// The `intent` name and its `parameters` object are **coupled per intent**: each
/// intent gets its own `<intent>-params` rule whose members are restricted to that
/// intent's declared parameter keys (with the right value type). This prevents the
/// model from nesting stray keys inside `parameters` — e.g. spilling the top-level
/// `confidence` field into the params object, a real failure mode observed on the
/// E2B model. Both the per-intent parameter shapes and the intent-name set are
/// derived from [`crate::intent_tool_schema`], the single source of truth, so the
/// grammar cannot drift from the schema the model is shown.
///
/// Intended for `LlamaSampler::grammar(model, &intent_grammar(), "root")`.
pub fn intent_grammar() -> String {
    let schema = intent_tool_schema();
    let intents = schema
        .get("intents")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // `"\"<s>\""` — the GBNF literal matching the quoted JSON string `s`.
    let lit = |s: &str| format!("\"\\\"{s}\\\"\"");

    let mut actions: Vec<String> = Vec::new();
    let mut param_rules: Vec<String> = Vec::new();

    for intent in &intents {
        let name = intent
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default();
        // GBNF rule names accept `[a-zA-Z0-9-]` only — the real llama.cpp parser
        // rejects underscores (found the hard way). Intent names use underscores,
        // so the rule base swaps them for dashes; the JSON *literals* keep them.
        let base = name.replace('_', "-");

        // One `action` alternative couples this intent name with its own params
        // rule and the shared trailer (risk / confirm / explanation / confidence).
        actions.push(format!(
            "( {name} ws \",\" ws {params} ws \":\" ws {base}-params ws \",\" ws trailer )",
            name = lit(name),
            params = lit("parameters"),
        ));

        match intent.get("parameters").and_then(|p| p.as_object()) {
            Some(p) if !p.is_empty() => {
                let members: Vec<String> = p
                    .iter()
                    .map(|(key, spec)| {
                        let value_rule = match spec.get("type").and_then(|t| t.as_str()) {
                            Some("integer" | "number") => "number",
                            Some("boolean") => "boolean",
                            Some("array") => "array",
                            _ => "string",
                        };
                        format!("{} ws \":\" ws {value_rule}", lit(key))
                    })
                    .collect();
                // Members may appear in any order; required-ness, duplicates and
                // exact value domains are enforced downstream by `parse_model_output`.
                // The point here is that ONLY these keys are admissible.
                param_rules.push(format!("{base}-member ::= {}", members.join(" | ")));
                param_rules.push(format!(
                    "{base}-params ::= \"{{\" ws ( {base}-member ( \",\" ws {base}-member )* )? \"}}\" ws"
                ));
            }
            _ => {
                // No parameters: only the empty object is valid.
                param_rules.push(format!("{base}-params ::= \"{{\" ws \"}}\" ws"));
            }
        }
    }

    let action_rule = format!("action ::= {}", actions.join(" | "));
    let param_section = param_rules.join("\n");
    format!("{ROOT_RULE}\n{action_rule}\n{param_section}\n{GRAMMAR_TAIL}")
}

// The grammar's fixed parts. `root` routes through the generated `action` rule,
// which couples each intent name with its own `<intent>-params` shape (see
// `intent_grammar`) so the params object cannot carry stray top-level keys.
const ROOT_RULE: &str = r#"root ::= "{" ws "\"intent\"" ws ":" ws action ws "}" ws"#;

// `trailer` is the shared tail every action ends with. `risk-field` is optional
// because `ProposedAction::risk` is `Option<RiskHint>` (omitted when absent) and
// is left permissive (any string or null) since risk is advisory and the policy
// engine re-derives the authoritative tier. The JSON building blocks
// (object/array/value/string/number) are the standard llama.cpp json grammar.
//
// `ws` is BOUNDED (`{0,16}`, not the usual unbounded `*`). `ws` appears between
// every token and is the only rule that admits raw newlines (`char` excludes
// U+0000..=U+001F), so an unbounded `ws` lets greedy decoding fall into a
// newline-repetition loop in a whitespace slot: every `\n` stays grammar-valid,
// the object never closes, and generation runs to MAX_GENERATED_TOKENS, yielding
// truncated JSON ("EOF while parsing an object at line N"). Found the hard way on
// a real model (greedy, no repetition penalty); the bound caps consecutive
// whitespace and forces progress to the next structural token, guaranteeing the
// object closes within the token budget. The few-shots emit compact JSON (zero
// whitespace), so the bound never constrains well-formed output — only the loop.
const GRAMMAR_TAIL: &str = r#"trailer ::= risk-field "\"requires_confirmation\"" ws ":" ws boolean ws "," ws "\"explanation\"" ws ":" ws string ws "," ws "\"confidence\"" ws ":" ws number ws
risk-field ::= ( "\"risk\"" ws ":" ws ( string | "null" ) ws "," ws )?
object ::= "{" ws ( member ( "," ws member )* )? "}" ws
member ::= string ws ":" ws value
array ::= "[" ws ( value ( "," ws value )* )? "]" ws
value ::= object | array | string | number | boolean | "null"
string ::= "\"" char* "\"" ws
char ::= [^"\\\x7F\x00-\x1F] | "\\" ( ["\\/bfnrt] | "u" hex hex hex hex )
hex ::= [0-9a-fA-F]
number ::= "-"? ( "0" | [1-9] [0-9]* ) ( "." [0-9]+ )? ( ( "e" | "E" ) ( "-" | "+" )? [0-9]+ )? ws
boolean ::= "true" | "false"
ws ::= [ \t\n]{0,16}"#;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn intent_names_match_the_catalog() {
        let names = intent_names();
        assert_eq!(
            names.len(),
            22,
            "expected all 22 catalog intents: {names:?}"
        );
        assert!(names.contains(&"find_process_using_port".to_string()));
        assert!(names.contains(&"ask_clarification".to_string()));
    }

    #[test]
    fn grammar_constrains_intent_to_every_catalog_name() {
        let g = intent_grammar();
        for name in intent_names() {
            // The grammar must offer the GBNF literal `"\"<name>\""` as an alternative.
            let literal = format!("\"\\\"{name}\\\"\"");
            assert!(
                g.contains(&literal),
                "grammar is missing the intent-name alternative for {name}"
            );
        }
        // The placeholder must have been substituted.
        assert!(!g.contains("@INTENT_NAMES@"), "placeholder not substituted");
    }

    #[test]
    fn grammar_has_the_proposed_action_top_level_keys() {
        let g = intent_grammar();
        for key in [
            "\\\"intent\\\"",
            "\\\"parameters\\\"",
            "\\\"risk\\\"",
            "\\\"requires_confirmation\\\"",
            "\\\"explanation\\\"",
            "\\\"confidence\\\"",
        ] {
            assert!(g.contains(key), "grammar is missing top-level key {key}");
        }
    }

    #[test]
    fn grammar_makes_risk_optional() {
        let g = intent_grammar();
        // `risk-field` wraps its body in `( ... )?` so an omitted risk key is legal.
        let risk_rule = g
            .lines()
            .find(|l| l.trim_start().starts_with("risk-field ::="))
            .expect("risk-field rule present");
        assert!(
            risk_rule.contains("(") && risk_rule.trim_end().ends_with(")?"),
            "risk-field must be optional: {risk_rule}"
        );
    }

    #[test]
    fn grammar_string_rule_excludes_control_chars() {
        let g = intent_grammar();
        let char_rule = g
            .lines()
            .find(|l| l.trim_start().starts_with("char ::="))
            .expect("char rule present");
        // Unescaped string chars MUST exclude JSON control characters
        // (U+0000..=U+001F); otherwise constrained decoding could still emit a
        // string that serde_json rejects.
        assert!(
            char_rule.contains(r"\x00-\x1F"),
            "char rule must exclude control characters: {char_rule}"
        );
        // The lax `[^"\\]` class (control chars allowed) must not be used.
        assert!(
            !char_rule.contains(r#"[^"\\]"#),
            "char rule must not use the control-char-permitting [^\"\\\\] class: {char_rule}"
        );
    }

    /// `ws` must be BOUNDED, not the unbounded `*`. `ws` is the only rule that
    /// admits raw newlines, so an unbounded `ws ::= [ \t\n]*` lets greedy decoding
    /// loop on newlines in a whitespace slot until the token cap, truncating the
    /// object (observed on a real model as "EOF while parsing an object at line
    /// N"). The bound guarantees the object closes within the token budget.
    #[test]
    fn grammar_ws_is_bounded_to_prevent_whitespace_loops() {
        let g = intent_grammar();
        let ws_rule = g
            .lines()
            .find(|l| l.trim_start().starts_with("ws ::="))
            .expect("ws rule present");
        assert!(
            !ws_rule.trim_end().ends_with('*'),
            "ws must not be unbounded (`*`) — that permits a newline decode loop: {ws_rule}"
        );
        assert!(
            ws_rule.contains("{0,") && ws_rule.contains('}'),
            "ws must use a bounded repetition like `{{0,16}}`: {ws_rule}"
        );
    }

    /// Every intent must get its own `<intent>-params` rule so the params object
    /// is constrained per intent (the coupling that prevents stray-key nesting).
    #[test]
    fn every_intent_has_a_params_rule() {
        let g = intent_grammar();
        for name in intent_names() {
            let base = name.replace('_', "-");
            assert!(
                g.contains(&format!("{base}-params ::=")),
                "missing per-intent params rule for `{name}`"
            );
        }
    }

    /// The core of the per-intent fix: `parameters` admits ONLY that intent's
    /// declared keys, so the model can no longer nest a top-level field (the
    /// observed `confidence`-inside-`parameters` failure) into the params object.
    #[test]
    fn grammar_constrains_parameters_to_declared_keys_per_intent() {
        let g = intent_grammar();

        // inspect_logs: only source/since/filter — never confidence/explanation.
        let inspect = g
            .lines()
            .find(|l| l.trim_start().starts_with("inspect-logs-member ::="))
            .expect("inspect-logs-member rule present");
        for ok in ["source", "since", "filter"] {
            assert!(
                inspect.contains(ok),
                "inspect_logs must admit `{ok}`: {inspect}"
            );
        }
        for forbidden in ["confidence", "explanation", "requires_confirmation"] {
            assert!(
                !inspect.contains(forbidden),
                "inspect_logs params must NOT admit `{forbidden}` (the nesting bug): {inspect}"
            );
        }

        // A parameterless intent admits ONLY the empty object.
        let health = g
            .lines()
            .find(|l| l.trim_start().starts_with("check-system-health-params ::="))
            .expect("check-system-health-params present");
        assert_eq!(
            health.trim(),
            r#"check-system-health-params ::= "{" ws "}" ws"#,
            "a no-param intent must admit only the empty object"
        );

        // Value types are honored: port -> number, force -> boolean, exclude -> array.
        assert!(
            g.contains(r#""\"port\"" ws ":" ws number"#),
            "port must be typed as a number"
        );
        assert!(
            g.contains(r#""\"force\"" ws ":" ws boolean"#),
            "force must be typed as a boolean"
        );
        assert!(
            g.contains(r#""\"exclude\"" ws ":" ws array"#),
            "exclude must be typed as an array"
        );

        // `root` routes through the coupled `action` rule, not a bare generic object.
        let root = g
            .lines()
            .find(|l| l.trim_start().starts_with("root ::="))
            .expect("root present");
        assert!(
            root.contains(" action "),
            "root must route through the per-intent `action` rule: {root}"
        );
    }

    // --- structural well-formedness lint (no FFI / no model needed) ----------

    /// Remove GBNF string literals (`"..."`) and char classes (`[...]`) so the
    /// remaining word tokens are exactly rule references.
    fn strip_literals_and_classes(rhs: &str) -> String {
        let mut out = String::new();
        let mut chars = rhs.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => {
                    // Skip to the closing unescaped quote.
                    while let Some(d) = chars.next() {
                        if d == '\\' {
                            chars.next(); // escaped char inside the literal
                        } else if d == '"' {
                            break;
                        }
                    }
                }
                '[' => {
                    // Skip to the closing ']' ('\]' escapes).
                    while let Some(d) = chars.next() {
                        if d == '\\' {
                            chars.next();
                        } else if d == ']' {
                            break;
                        }
                    }
                }
                _ => out.push(c),
            }
        }
        out
    }

    fn rules(g: &str) -> Vec<(&str, &str)> {
        g.lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .filter_map(|l| l.split_once("::=").map(|(a, b)| (a.trim(), b.trim())))
            .collect()
    }

    /// llama.cpp's GBNF parser (`is_word_char`) accepts rule-name characters
    /// `[a-zA-Z0-9-]` only — **not** underscores. A rule name like `intent_name`
    /// makes the real parser stop mid-identifier and reject the entire grammar
    /// ("failed to parse grammar"), even though it is a perfectly valid Rust
    /// string and passes the structural lint. This was found the hard way running
    /// a real model; the check below is the regression guard.
    #[test]
    fn grammar_rule_names_use_llama_cpp_identifier_charset() {
        let g = intent_grammar();
        for (lhs, _) in rules(&g) {
            let first = lhs.chars().next().expect("non-empty rule name");
            assert!(
                first.is_ascii_alphabetic(),
                "rule name `{lhs}` must start with an ASCII letter"
            );
            assert!(
                lhs.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "rule name `{lhs}` must use only [a-zA-Z0-9-] (llama.cpp GBNF \
                 is_word_char); underscores make the real parser reject the grammar"
            );
        }
    }

    #[test]
    fn grammar_is_structurally_well_formed() {
        let g = intent_grammar();
        let rules = rules(&g);
        let defined: HashSet<&str> = rules.iter().map(|(lhs, _)| *lhs).collect();

        assert!(defined.contains("root"), "grammar must define `root`");

        // Every identifier referenced on a RHS (after stripping literals/classes)
        // must be a defined rule — catches a typo'd or deleted rule name.
        for (lhs, rhs) in &rules {
            let stripped = strip_literals_and_classes(rhs);
            for tok in stripped
                .split(|c: char| !(c.is_alphanumeric() || c == '-'))
                .filter(|t| !t.is_empty())
            {
                let first = tok.chars().next().unwrap();
                // GBNF rule names are letter-initial `[a-zA-Z][a-zA-Z0-9-]*`
                // (dashes are part of the name; see is_word_char in llama.cpp).
                if first.is_alphabetic() {
                    assert!(
                        defined.contains(tok),
                        "rule `{lhs}` references undefined rule `{tok}`"
                    );
                }
            }
        }
    }
}
