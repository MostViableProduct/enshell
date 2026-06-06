# enShell

> **Natural language for your terminal**

enShell is a cross-platform, AI-native shell layer for macOS, Linux, and Windows.
You describe what you want in plain English instead of memorizing terminal commands;
enShell explains its plan, shows the exact command, labels the risk, and asks for
confirmation before doing anything. Inference runs **locally by default** (Gemma 4
via llama.cpp), so your requests don't leave your machine.

```bash
enshell "show me what is using port 3000"
enshell "find the biggest files in my Downloads folder"
enshell "why did the last command fail?"
```

## Status

**Early development.** A working **read-only MVP** runs end to end. The default
build interprets requests with a **deterministic stub model** (no C++, no model
download) so the CLI works out of the box and CI stays hermetic. The `enshell`
binary builds and runs:

```bash
enshell --dry-run "what is using port 3000"   # preview the plan + command, run nothing
enshell --yes "find the largest files here"   # read-only, auto-confirmed, executes
enshell history                                # past actions (tamper-evident audit log)
enshell doctor                                 # environment self-check
```

It recognizes a curated set of read-only requests (process-on-port, large files,
system health, logs, open), previews them in plain English, asks for confirmation,
executes via a no-shell command executor, and records each run to a local,
**tamper-evident (hash-chained) audit log** surfaced by `enshell history`.

The real **Gemma 4 / llama.cpp provider is now wired** behind an optional `llama`
Cargo feature: when you build with `--features llama` and a GGUF model is present
(via `$ENSHELL_MODEL` or the default path), the CLI selects it at runtime and falls
back to the stub if no model is found. This path is **compile-verified in CI on
macOS and Linux**, and live inference has now been **verified end to end** on Apple
Silicon (Metal) against Gemma 4 E2B — best measured **18/19 (94.7%) raw intent
accuracy** on the read-only eval set (a 14/19 first baseline, raised by grammar,
parser, and eval-fixture fixes; model in isolation; in normal use the fast path
resolves common phrasings before the model is reached). It is **not
exercised in CI** (real inference needs hardware + weights) and accuracy tuning is
ongoing, so treat the provider as **proven-but-early** (`enshell doctor` reports it
as a *candidate*, since it doesn't load the weights).
Write/system actions are designed but not yet executable (read-only only). Not a
finished product.

## How it works (design)

enShell is a **command broker, not an autopilot**. The local model never executes
commands — it proposes a *structured intent*, and trusted Rust code validates it,
classifies its risk, renders the correct OS-specific command (as a structured plan,
not a shell string), previews it in plain English, and executes only after you
confirm.

Common, unambiguous requests (e.g. "what is using port 3000") are resolved by a
**deterministic fast path** *before* any model runs — instant, model-independent,
and audited as `model_id = fast_path`. The fast path produces a trusted typed
intent and still goes through the identical policy → render → confirm gate; it
only declines (handing off to the model) when a request carries parameters it
shouldn't guess at.

## Documentation

- 🚀 **[Getting started](docs/user-guides/getting-started.md)** — install, the
  request families that work today, commands & flags, and the three resolution
  paths (fast-path / stub / llama). *Authoritative for current behavior.*
- 🛡️ **[Safety model](docs/security/safety-model.md)** — the trust boundary, risk
  tiers, the Confirmation Invariant, the no-shell executor, and the audit log.
- 📄 **[Full plan](docs/planning/enshell-ai-native-shell-plan.md)** — the complete
  design, roadmap, and rationale. *Authoritative for the vision.*
- 🧪 **[Model verification](docs/contributor-guides/model-verification.md)** — the
  eval harness and how to measure a real Gemma model (contributors).
- 🔒 **[`SECURITY.md`](SECURITY.md)** — reporting a vulnerability.

## Planned highlights

- **Local-first by default** — Gemma 4 E2B (Q4) via llama.cpp; guided install, no
  silent download; telemetry off; no cloud dependency.
- **Five-layer architecture** — natural-language wrapper → safety/policy broker →
  local model runtime → shell integration → OS-level adapters.
- **Safety first** — eight-tier risk policy; destructive/privileged actions denied
  by default; typed confirmation for the riskiest; structured execution with no
  shell interpreter.
- **Transparent & reversible** — plain-English previews, tamper-evident local audit
  log, and a three-tier recovery model (auto / assisted / irreversible).
- **Privacy-minimal** — by default a model request carries only your request text,
  OS, and working directory; the last exit code is captured only via an opt-in shell
  hook (`enshell shell-init`); secrets, file contents, env values, and clipboard are
  never captured. (History/memory capture is separate and not yet implemented.)
- **Cross-platform** — macOS, Linux, and Windows (PowerShell-first).

## Roadmap (summary)

Phase 0 research & design → Phase 1 read-only MVP (macOS/Linux) → Phase 2
cross-platform core (+Windows) → Phase 3 safe system actions → Phase 4
non-technical UX → Phase 5 autonomous maintenance agents → Phase 6 ecosystem.
See the planning document for details.

## Contributing

Early governance uses the **Developer Certificate of Origin (DCO)** — sign off your
commits with `git commit -s`. No CLA is required at launch.

## License

enShell's source and documentation are licensed under the **Apache License 2.0** —
see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

External components (llama.cpp, Gemma 4 model weights, OS tools, package managers)
are **separately licensed** and not covered by enShell's license; see
[`NOTICE`](NOTICE). Model weights are **not** bundled. Final licensing and
distribution should be reviewed by counsel before any public release beyond this
planning stage.
