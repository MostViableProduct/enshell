//! GBNF grammar derived from the intent catalog (Track A.3).
//!
//! [`intent_grammar`] returns a [GBNF] grammar that constrains a model's decoding
//! to a syntactically-valid `ProposedAction` JSON object whose `intent` is one of
//! the known intent names. This kills the two failure modes small models actually
//! hit — **malformed JSON** and **invented intent names** — at generation time.
//!
//! Per-intent **parameter** shapes are intentionally *not* constrained here: the
//! `parameters` object is left general and validated after generation by
//! [`enshell_intents::parse_model_output`] (the strict schema parse + domain
//! checks). Constraining params per-intent is a clean future refinement.
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

/// A GBNF grammar constraining decoding to a valid `ProposedAction` JSON object
/// with `intent` restricted to the known intent names.
///
/// Intended for `LlamaSampler::grammar(model, &intent_grammar(), "root")`.
pub fn intent_grammar() -> String {
    // Each name becomes the GBNF literal that matches the quoted JSON string,
    // e.g. `find_large_files` -> `"\"find_large_files\""`.
    let alternation = intent_names()
        .iter()
        .map(|n| format!("\"\\\"{n}\\\"\""))
        .collect::<Vec<_>>()
        .join(" | ");
    GRAMMAR_TEMPLATE.replace("@INTENT_NAMES@", &alternation)
}

// One rule per line. `risk_field` is optional because `ProposedAction::risk` is
// `Option<RiskHint>` with `skip_serializing_if = "Option::is_none"` (omitted when
// absent); it is left permissive (any string or null) since risk is advisory and
// the policy engine re-derives the authoritative tier. The JSON building blocks
// (object/array/value/string/number) are the standard llama.cpp json grammar.
const GRAMMAR_TEMPLATE: &str = r#"root ::= "{" ws "\"intent\"" ws ":" ws intent_name ws "," ws "\"parameters\"" ws ":" ws object ws "," ws risk_field "\"requires_confirmation\"" ws ":" ws boolean ws "," ws "\"explanation\"" ws ":" ws string ws "," ws "\"confidence\"" ws ":" ws number ws "}" ws
risk_field ::= ( "\"risk\"" ws ":" ws ( string | "null" ) ws "," ws )?
intent_name ::= @INTENT_NAMES@
object ::= "{" ws ( member ( "," ws member )* )? "}" ws
member ::= string ws ":" ws value
array ::= "[" ws ( value ( "," ws value )* )? "]" ws
value ::= object | array | string | number | boolean | "null"
string ::= "\"" char* "\"" ws
char ::= [^"\\] | "\\" ( ["\\/bfnrt] | "u" hex hex hex hex )
hex ::= [0-9a-fA-F]
number ::= "-"? ( "0" | [1-9] [0-9]* ) ( "." [0-9]+ )? ( ( "e" | "E" ) ( "-" | "+" )? [0-9]+ )? ws
boolean ::= "true" | "false"
ws ::= [ \t\n]*
"#;

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
            17,
            "expected all 17 catalog intents: {names:?}"
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
        // `risk_field` wraps its body in `( ... )?` so an omitted risk key is legal.
        let risk_rule = g
            .lines()
            .find(|l| l.trim_start().starts_with("risk_field ::="))
            .expect("risk_field rule present");
        assert!(
            risk_rule.contains("(") && risk_rule.trim_end().ends_with(")?"),
            "risk_field must be optional: {risk_rule}"
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
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .filter(|t| !t.is_empty())
            {
                let first = tok.chars().next().unwrap();
                if first.is_alphabetic() || first == '_' {
                    assert!(
                        defined.contains(tok),
                        "rule `{lhs}` references undefined rule `{tok}`"
                    );
                }
            }
        }
    }
}
