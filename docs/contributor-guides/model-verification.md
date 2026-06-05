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

The **CLI** auto-discovers `~/.enshell/models/*.gguf` (so `enshell` finds the model
without `$ENSHELL_MODEL` — step 2 below). The **eval** is explicit: it uses the real
model only when you pass `--model <path>`; with no `--model` it runs the stub + fast
path end-to-end instead.

### 1. Score the model against the fixtures

```bash
# Real model in isolation (fast path bypassed). `--threshold 0` just measures;
# the default threshold is 100, which exits non-zero unless every case passes.
cargo run --release -p enshell-eval --features llama -- \
  --model ~/.enshell/models/gemma-4-E2B-it-Q4_K_M.gguf --threshold 0
```

This runs every fixture through the real model (decoding is automatically
**GBNF-constrained** to a valid `ProposedAction` shape with a known intent name —
see `enshell-model::grammar`), then scores the produced intents and prints the
per-case failures and overall accuracy. `--threshold` defaults to **100** (exit
non-zero below that); pass `--threshold 0` to just measure, or `--threshold <N>` to
gate at N%.

#### Recorded result — Gemma 4 E2B (2026-06-04, baseline, pre-robustness-fixes)

First end-to-end verification of the real-model path, **before** the inspect_logs /
grammar / parser-normalization changes below. Greedy + GBNF-constrained decoding is
deterministic, so this reproduces exactly against the pinned file *at that commit*.

| Field | Value |
|---|---|
| Command | `cargo run --release -p enshell-eval --features llama -- --model ~/.enshell/models/gemma-4-E2B-it-Q4_K_M.gguf --threshold 0` |
| Model | `gemma-4-E2B-it-Q4_K_M.gguf`, SHA-256 `9378bc47…b8672d` (the pin above) |
| Hardware | Apple M1 Pro, 16 GB, macOS 26.5 — Metal, 36/36 layers offloaded |
| Wall time | ~239 s for model load + all 19 cases (~13 s/case; the ~3.4k-token prompt dominates) |
| Result | **14/19 (73.7%)** raw intent accuracy (model in isolation, fast path bypassed) |

Failures — in normal use the fast path resolves the common phrasings before the
model is reached, so everyday accuracy is higher than this isolated number:

| Case | Failure | Bucket |
|---|---|---|
| `large-downloads-model` | path `"Downloads"` vs expected `"~/Downloads"` | path normalization |
| `health-check` | no intent (clarified/errored) | model miss |
| `disk-usage` | no intent (clarified/errored) | model miss |
| `logs-recent` | added `source = "system"` | extra param |
| `logs-short` | added `source = "system"` | extra param |

These point at prompt / few-shot tuning. (The adapter already rejects the `source`
param the model adds — see the `inspect_logs` fidelity note in `enshell-adapters`.)
Raising this toward a pass threshold is the accuracy-tuning step.

#### Recorded result — cumulative after the robustness fixes (2026-06-05)

Re-measured at commit `4ba499e` after four end-to-end robustness fixes (inspect_logs
source steering + `source="system"` backstop; bounded-`ws` grammar; per-intent
`parameters` grammar; inspect_logs `filter`/`source` rendering). Same command/model;
hardware was a 4-vCPU/8 GB CPU droplet (no Metal — ~2.4 min/case, ~45 min total).

| Result | **13/19 (68.4%)** raw intent accuracy (model in isolation, fast path bypassed) |
|---|---|

The number **dipped from 14/19** even though robustness improved markedly. This is
expected and worth understanding: the fixes closed failure modes the fixtures never
exercise (truncated JSON, stray-key nesting, rejected `filter`/`source` paraphrases),
while the grammar restructuring perturbs greedy decoding, shifting unrelated cases.
The eval is a deliberately harsh isolated metric; everyday accuracy is buffered by
the fast path.

| Case | Failure | Bucket |
|---|---|---|
| `large-here-largest` | path `"here"` vs expected `"."` | path (deictic) |
| `large-here-biggest` | path `"here"` vs expected `"."` | path (deictic) |
| `large-downloads` | added `min_size = "100M"` | extra param |
| `large-downloads-model` | path `"Downloads"` vs `"~/Downloads"` | path (context-dependent) |
| `logs-recent` | added `filter = ""` | blank optional |
| `logs-short` | added `filter = ""` | blank optional |

**Follow-up:** trusted parser cleanups in `enshell-intents` —
blank/whitespace-only optionals collapse to `None` and the deictic `here`/`this
folder`/`current directory` → `.` for `find_large_files.path`. These are
post-generation transforms, so they do not perturb the model's other outputs.

#### Recorded result — after parser cleanups (2026-06-05, Metal)

Confirming run at commit `68295a6`, back on the **Metal** reference machine (Apple
M1 Pro, 16 GB) — directly comparable to the 14/19 baseline above (the 13/19 row was
the slower CPU droplet; backend FP differences mean per-case results are only
comparable within the same backend).

| Result | **16/19 (84.2%)** raw intent accuracy — best measured; +2 vs the 14/19 Metal baseline |
|---|---|

| Case | Failure | Bucket |
|---|---|---|
| `large-downloads-model` | path `"Downloads"` vs `"~/Downloads"` | path (context-dependent; **deferred**) |
| `logs-recent` | added `since = "1h"` | extra param (semantically plausible) |
| `logs-short` | added `since = "1h"` | extra param (semantically plausible) |

`large-here-largest`/`large-here-biggest` are now **fixed** (deictic `here` → `.`,
confirmed end to end). The logs cases keep *moving* their stray param
(`source="system"` → `filter=""` → now `since="1h"`); `since="1h"` is a reasonable
reading of "recent logs" = "logs from the last hour", so the remaining gap is the
**open product decision** (model-verification §Extending): accept `since` as valid
for these fixtures, add request-context repair, or steer the model to omit it. The
`Downloads` → `~/Downloads` case is the deliberately-deferred context-dependent
rewrite.

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
