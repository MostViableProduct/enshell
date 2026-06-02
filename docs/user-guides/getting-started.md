# enShell — Getting Started

> **Scope of this document.** This guide describes **what enShell actually does
> today** (the read-only MVP). For the full design and roadmap, see
> [`docs/planning/enshell-ai-native-shell-plan.md`](../planning/enshell-ai-native-shell-plan.md),
> which is the authoritative source for the *vision*; this guide is authoritative
> for *current behavior*. For the safety guarantees, see
> [the safety model](../security/safety-model.md).

enShell turns a natural-language request into a **previewed, confirmed** command.
You type what you want; enShell explains the plan, shows the exact command, labels
the risk, and runs it only after you confirm.

```bash
enshell "show me what is using port 3000"
```

## Current status (read this first)

enShell is in **early development**. Today it:

- Runs **read-only** diagnostics only, on **macOS and Linux**.
- Interprets requests with a built-in **deterministic stub model** by default — no
  model download, no network, works out of the box.
- Recognises a small set of request families (below). Anything else is handled
  safely — a clarifying question when it's unrecognised, or a refusal when it maps to
  a known but not-yet-supported action (e.g. a package install). It never guesses.

It does **not** yet run write/system actions, support Windows, or perform live
inference with a downloaded Gemma model. See [Not yet available](#not-yet-available).

## Install and run

enShell is a Rust workspace; the binary is `enshell` (from the `enshell-cli`
crate). Until packaged releases exist, build from source:

```bash
# Run directly from the workspace:
cargo run -p enshell-cli -- "what is using port 3000"

# Or build a release binary and run it:
cargo build --release -p enshell-cli
./target/release/enshell "what is using port 3000"
```

`cargo run -p enshell-cli -- <args>` and `enshell <args>` are equivalent; this
guide uses `enshell` for brevity.

Verify your environment at any time:

```bash
enshell doctor
```

## The basic flow

For a natural-language request, enShell **previews then confirms**:

```text
$ enshell "find the largest files here"
I will find the largest files in the specified directory.
Risk: Read-only. I will not change anything.
Command: du -ah . | sort -rh | head -n 10

Run this? [y/N]
```

Nothing runs until you answer `y`. The literal command is always shown — enShell
never hides what it will run.

## How a request is resolved: three paths

A request is turned into a *structured intent* by one of three resolvers, in order.
Each produces the same kind of typed intent and is then subjected to the **same**
policy → render → confirm gate (see [the safety model](../security/safety-model.md)).
The audit log records which one ran in its `model_id` field:

| Path | When it runs | `model_id` in the audit log |
|---|---|---|
| **Fast path** | A common, unambiguous phrasing matches a known template — **no model is called**. | `fast_path` |
| **Stub model** | Default build, fast path missed — a deterministic, offline stand-in interprets the request. | `stub` |
| **llama.cpp / Gemma 4** | Built with `--features llama` and a model file is present (see below). | `gemma-4 (llama.cpp)` |

The fast path is deliberately conservative: it only matches phrasings whose intent
is unambiguous and fully specified (e.g. a bare port number). A request carrying
extra qualifiers it shouldn't guess at falls through to the model.

## Commands and flags

```text
enshell "<request>"          Interpret, preview, confirm, then execute.
enshell --dry-run "<req>"    Show the full plan + exact command. Runs nothing.
enshell --plan "<req>"       Show the intent name + risk tier only. Runs nothing.
enshell --yes "<req>"        Pre-authorise read-only auto-confirm (see below).
enshell --timeout <SECONDS>  Override the 30s execution timeout (0 = no timeout).

enshell doctor               Environment self-check (OS, provider, adapters, audit log).
enshell history              Show past actions from the local audit log.
```

`--dry-run` is the safe way to see exactly what a request would run without
running it. It (and `--plan`) produce output only for executable **read-only**
actions; a request that maps to a not-yet-supported write/system action is refused
outright, so there is no plan to show.

**What `--yes` does — and does not do.** `--yes` pre-authorises confirmation for
**read-only** actions only. It does **not** auto-confirm `open` (which always
prompts), nor any write/system/destructive/privileged action. In the current MVP
only read-only actions execute at all, so `--yes` simply skips the `[y/N]` prompt
for those. The full rules are the Confirmation Invariant in
[the safety model](../security/safety-model.md).

## What enShell understands today

These read-only request families resolve end-to-end on macOS and Linux. The exact
command is always shown in the preview (and via `--dry-run`):

| You can ask… | Intent | macOS | Linux |
|---|---|---|---|
| "what is using port 3000" | `find_process_using_port` | `lsof -i :3000` | `ss -lptn 'sport = :3000'` |
| "find the largest files here" / "…in my Downloads folder" | `find_large_files` | `du -ah <path> \| sort -rh \| head -n 10` | same |
| "run a system health check" | `check_system_health` | `df -h && uptime && vm_stat` | `df -h && uptime && free -h` |
| "show me recent logs" | `inspect_logs` | `log show --style syslog --last 1h` | `journalctl --no-pager -n 200` |
| "open /path/to/file" | `open_file_or_folder` | `open <path>` | `xdg-open <path>` |

Notes:

- `open` only accepts a **local file/folder path** (URLs and URI schemes are
  rejected) and **always** prompts for confirmation — `--yes` will not auto-run it.
- The pipelines/sequences above are *display renderings*. enShell executes them as
  structured argv steps through OS pipes — **never** via a shell (`sh -c`). See
  [the safety model](../security/safety-model.md#no-shell-by-construction).
- A request that doesn't map to a supported read-only action is handled safely:
  a clarifying question when it's unrecognised, or a refusal when it maps to a known
  but not-yet-supported action (e.g. a package install). enShell never guesses into
  executing.

## Using the real Gemma 4 model (optional, experimental)

By default enShell uses the stub. To use the real local model via llama.cpp:

```bash
# Requires cmake + a C++ toolchain (llama.cpp is compiled from source).
export ENSHELL_MODEL=/path/to/gemma-4-e4b-instruct.Q4_K_M.gguf
cargo run -p enshell-cli --features llama -- "what is using port 3000"
```

If no model file is found, enShell falls back to the stub. `enshell doctor` reports
whether a model **candidate** was found — it does not load the weights, so a present
file is not a guarantee the model will load.

> **Status: experimental and unverified.** The llama.cpp/Gemma 4 path is compiled
> and type-checked in CI on macOS and Linux, but live inference against a real model
> has **not** yet been verified end to end. Treat it as wired-but-unproven.

## Inspecting what happened

Every executed (or refused) action is appended to a local, tamper-evident audit log:

```bash
enshell history     # one line per recorded action
```

The log is local-only and never sent anywhere. Details — fields, redaction, and the
hash-chain integrity check — are in [the safety model](../security/safety-model.md#audit-log).

## Not yet available

These are designed (see the [planning doc](../planning/enshell-ai-native-shell-plan.md))
but **not** implemented in the current MVP. enShell will refuse or report them rather
than pretend:

- **Write / system actions** — installing packages, starting/stopping services,
  deleting/compressing files, git commits, backups, etc. These are recognised but
  **refused** in the read-only MVP (planned for Phase 3, after safety testing).
- **Windows** — only macOS and Linux are supported today.
- **`enshell undo`, `enshell explain-last`, `enshell fix-last`** — placeholders;
  they print a "not available yet" notice (they need recorded undo plans / shell
  context capture).
- **Verified live Gemma inference** — see the experimental note above.

## See also

- [Safety model](../security/safety-model.md) — the guarantees behind the preview/confirm flow.
- [Planning document](../planning/enshell-ai-native-shell-plan.md) — full design, roadmap, and rationale.
- [`SECURITY.md`](../../SECURITY.md) — how to report a vulnerability.
