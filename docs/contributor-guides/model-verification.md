# Model verification & the eval harness

> **Scope.** How to measure NL→intent accuracy, and how to verify a real Gemma
> model (the Phase-0 default is **Gemma 4 E2B**; see the planning doc §13/§19).
> The default eval runs in CI; the real-model steps need a GGUF file + a machine
> with a C++ toolchain and so are run by hand.

## The eval harness

`enshell-eval` scores natural-language requests against a committed fixture set of
`NL → expected intent` cases ([`eval/read_only.jsonl`](../../eval/read_only.jsonl)).
A case passes iff the produced intent's **kind** matches, its **required** fields
match exactly, and it has no surprise (non-null, non-whitelisted) parameters.

Run it against the deterministic stub + fast path (always 100% — a regression
gate that also runs in `cargo test`):

```bash
cargo run -p enshell-eval
# enShell eval — read-only fixture (stub + fast path (end-to-end))
# 13/13 passed (100.0%) — threshold 100%
```

`--threshold <0-100>` makes the process exit non-zero below that accuracy (default
100). Two measurement modes:

- **default** — end-to-end via `Orchestrator::resolve` (fast path **then** model),
  i.e. what a user actually gets.
- **`--model <path>`** — every case through the **model in isolation**, fast path
  bypassed. This is the number that answers "does the model produce correct
  intents?" — without it, the fast path would silently resolve the common
  phrasings and hide the model's real accuracy.

## Verifying a real model (E2B)

### Prerequisites

- A **C++ toolchain + `cmake`** (the `llama` feature compiles llama.cpp).
- A **Gemma 4 E2B Instruct GGUF** (Q4, e.g. `Q4_K_M`). GGUF builds are community
  conversions of Google's Apache-2.0 weights — Google's own card
  (<https://ai.google.dev/gemma>) serves the original weights, **not** GGUFs.
  enShell hosts/mirrors nothing; verify the Apache-2.0 license per version
  (downloading means accepting that license).

#### Reproducibility — the exact file this runbook was verified against

| Field | Value |
|---|---|
| Repo | [`unsloth/gemma-4-E2B-it-GGUF`](https://huggingface.co/unsloth/gemma-4-E2B-it-GGUF) — third-party Q4_K_M requant of Google's Apache-2.0 weights |
| File | `gemma-4-E2B-it-Q4_K_M.gguf` |
| Size | `3106736256` bytes (~3.11 GB) |
| SHA-256 | `9378bc471710229ef165709b62e34bfb62231420ddaf6d729e727305b5b8672d` |

Any equivalent Gemma 4 E2B Instruct **Q4_K_M** GGUF should give comparable
accuracy; this file is pinned so the numbers below are reproducible. Download
(no Hugging Face account needed) and verify integrity:

```bash
mkdir -p ~/.enshell/models
curl -L --fail -o ~/.enshell/models/gemma-4-E2B-it-Q4_K_M.gguf \
  https://huggingface.co/unsloth/gemma-4-E2B-it-GGUF/resolve/main/gemma-4-E2B-it-Q4_K_M.gguf
shasum -a 256 ~/.enshell/models/gemma-4-E2B-it-Q4_K_M.gguf
# → 9378bc471710229ef165709b62e34bfb62231420ddaf6d729e727305b5b8672d
```

enShell auto-discovers `~/.enshell/models/*.gguf`, so the eval and CLI below find
it without `--model`/`ENSHELL_MODEL` once it's in that directory.

### 1. Score the model against the fixtures

```bash
cargo run -p enshell-eval --features llama -- \
  --model /path/to/gemma-4-e2b-instruct.Q4_K_M.gguf
```

This runs every fixture through the real model (decoding is automatically
**GBNF-constrained** to a valid `ProposedAction` shape with a known intent name —
see `enshell-model::grammar`), then scores the produced intents. It prints the
per-case failures and the overall accuracy. Add `--threshold 90` to get a non-zero
exit below 90%.

### 2. Smoke-test the end-to-end CLI

```bash
export ENSHELL_MODEL=/path/to/gemma-4-e2b-instruct.Q4_K_M.gguf
cargo run -p enshell-cli --features llama -- doctor
cargo run -p enshell-cli --features llama -- --dry-run "what is using port 3000"
```

`doctor` should report the model as a load candidate; `--dry-run` should preview a
plan without executing. (Alternatively, drop the `.gguf` into `~/.enshell/models/`
and enShell picks it up automatically.)

### 3. Interpret the result

This is the empirical answer to **Open Question B** (planning doc §19.2):

- **Clears your bar** → Gemma 4 E2B is good for the Phase-0 read-only MVP. Record
  the accuracy and the exact model/quant in the planning doc.
- **Falls short** → in rough order of cost: tighten the prompt/few-shots (re-bless
  the goldens, §A.2), add per-intent parameter constraints to the grammar, or
  **step up to Gemma 4 E4B** (the documented upgrade tier).

There is no officially-pinned pass threshold yet — picking it *is* the Phase-0
exercise. Run once without `--threshold` to see the number, then decide.

## Extending the fixture set

Add lines to [`eval/read_only.jsonl`](../../eval/read_only.jsonl):

```json
{"id":"<unique-id>","nl":"<request>","kind":"<intent_name>","required":{"<k>":<v>},"allowed":["<k>"]}
```

- `required` — parameters that must match exactly.
- `allowed` — non-required parameter keys that may appear (e.g. a default `limit`);
  any other non-null parameter fails the case.

A new case must be resolvable by **both** the stub (so the `cargo test` gate stays
green) and, ideally, exercise a real model phrasing. Keep cases read-only (the MVP
executes read-only only).

## Notes

- The default build compiles **no** C++; only `--features llama` pulls in
  llama.cpp. CI compiles (but does not run) the `--features llama` eval path, so the
  `--model` wiring cannot rot.
- Live inference is **not** run in CI — it needs the multi-GB model and real
  hardware. Everything else here (fixtures, scoring, grammar, prompt goldens) is
  exercised by `cargo test`.
