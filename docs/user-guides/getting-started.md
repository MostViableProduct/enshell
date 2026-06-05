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

- Runs **read-only** diagnostics only, on **macOS and Linux** — plus a **subset on
  Windows** (6 of the 10 workflows; see the table below).
- Interprets requests with a built-in **deterministic stub model** by default — no
  model download, no network, works out of the box.
- Recognises a small set of request families (below). Anything else is handled
  safely — a clarifying question when it's unrecognised, or a refusal when it maps to
  a known but not-yet-supported action (e.g. a package install). It never guesses.

It does **not** yet run write/system actions or support **every** workflow on
Windows. Live inference with a downloaded Gemma model now works but is **early**
(verified to run; ~74% raw model accuracy so far — see below). See
[Not yet available](#not-yet-available).

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

enshell doctor               Environment self-check (OS, provider, adapters, shell, audit log).
enshell history              Show past actions from the local audit log.
enshell shell-init [SHELL]   Print a shell hook snippet to paste into your rc file.
enshell explain-last         Explain the last command's result (needs the hook).
enshell memory <action>      Manage stored preferences (show/set/get/reset/export/delete).
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

These read-only request families resolve end-to-end on macOS and Linux; a subset
also resolves on **Windows** (the rest are deferred — see the Windows column and the
note beneath the table). The exact command is always shown in the preview (and via
`--dry-run`):

| You can ask… | Intent | macOS | Linux | Windows |
|---|---|---|---|---|
| "what is using port 3000" | `find_process_using_port` | `lsof -i :3000` | `ss -lptn 'sport = :3000'` | — (deferred) |
| "find the largest files here" / "…in my Downloads folder" | `find_large_files` | `du -ah <path> \| sort -rh \| head -n 10` | same | — (deferred) |
| "run a system health check" | `check_system_health` | `df -h && uptime && vm_stat` | `df -h && uptime && free -h` | `systeminfo` |
| "show me recent logs" | `inspect_logs` | `log show --style syslog --last 1h` | `journalctl --no-pager -n 200` | `wevtutil qe System /c:200 /rd:true /f:text` |
| "open /path/to/file" | `open_file_or_folder` | `open <path>` | `xdg-open <path>` | — (deferred) |
| "list running processes" | `list_processes` | `ps aux` | `ps aux` | `tasklist` |
| "show disk usage" | `disk_usage` | `df -h` | `df -h` | — (deferred) |
| "show network connections" | `network_connections` | `netstat -an` | `ss -tuna` | `netstat -an` |
| "git status" | `git_status` | `git --no-optional-locks status` | `git --no-optional-locks status` | `git --no-optional-locks status` |
| "show memory usage" | `show_memory` | `vm_stat` | `free -h` | `systeminfo` |

**Windows support (newly added, less battle-tested).** Windows renders the six
workflows above that have a genuine no-shell `.exe` form. The rendered commands are
unit-tested and the Windows build is compile-checked in CI, but end-to-end execution
on Windows has had far less real-world testing than macOS/Linux — treat it as
wired-but-young. The four "— (deferred)" workflows are intentionally left
unsupported on Windows for now: `find_process_using_port`, `find_large_files`, and
`disk_usage` have no precise command form that avoids a PowerShell *cmdlet* (and
enShell never runs a shell), while `open_file_or_folder` needs Windows-aware path
validation (drive letters vs URI schemes, UNC/network paths) that is deferred to its
own slice. enShell refuses these on Windows rather than guessing. One supported
workflow is also narrower on Windows: `inspect_logs` shows only **recent** logs there
— a time-qualified request ("logs since yesterday") is **refused**, not silently
broadened, until the Windows time query lands (macOS/Linux honor the time window).

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
export ENSHELL_MODEL=/path/to/gemma-4-e2b-instruct.Q4_K_M.gguf
cargo run -p enshell-cli --features llama -- "what is using port 3000"
```

If no model file is found, enShell falls back to the stub. `enshell doctor` reports
whether a model **candidate** was found — it does not load the weights, so a present
file is not a guarantee the model will load.

> **Status: verified to run, but early.** The llama.cpp/Gemma 4 path is compiled
> and type-checked in CI on macOS and Linux, and live inference has now been
> verified end to end on Apple Silicon (Metal) against Gemma 4 E2B — the first real
> run scored **73.7% (14/19) raw intent accuracy** on the read-only eval set (the
> model in isolation; in normal use the fast path resolves the common phrasings
> before the model is reached, so everyday accuracy is higher). It is **not**
> exercised in CI (real inference needs hardware + weights) and accuracy tuning is
> ongoing, so treat it as proven-but-early rather than production-ready. See
> [the model-verification runbook](../contributor-guides/model-verification.md) for
> the exact model, command, and results.

## Inspecting what happened

Every executed (or refused) action is appended to a local, tamper-evident audit log:

```bash
enshell history     # one line per recorded action
```

The log is local-only and never sent anywhere. Details — fields, redaction, and the
hash-chain integrity check — are in [the safety model](../security/safety-model.md#audit-log).

## Shell integration (optional, opt-in)

By default enShell can't see your *last command's exit code* — a child process can't
read the parent shell's `$?`. Installing a small hook fixes that and enables
`enshell explain-last`. It is **opt-in**: enShell prints a snippet; you paste it.

```bash
enshell shell-init        # auto-detect your shell, or: shell-init bash | zsh
# → append the printed snippet to ~/.bashrc or ~/.zshrc, then start a new shell
```

The hook exports **only** the last exit code and the shell name — nothing else (no
command text, no output). With it installed:

```bash
$ enshell explain-last
Your last command exited with code 127.
That usually means: command not found — it may be misspelled or not on your PATH.
```

`explain-last` maps well-known exit codes to their conventional meaning. It does
**not** see the command text or its error output (privacy-minimal default), so it
can't analyse a failure in detail yet — richer, opt-in capture is planned.
`enshell doctor` shows whether the hook is installed.

## Preferences (memory)

enShell keeps a small local preferences store in a SQLite database
(`~/.enshell/memory.db`, override with `$ENSHELL_MEMORY_DB`). SQLite is **bundled**,
so building/installing enShell needs no system `libsqlite3`.

```bash
enshell memory set default_timeout 90   # set a preference
enshell memory get default_timeout      # → 90
enshell memory show                     # list all prefs + the db path
enshell memory export                   # dump prefs as JSON
enshell memory reset                    # clear all prefs (keep the empty db)
enshell memory delete                   # remove the database file entirely
```

The one preference enShell currently consumes is **`default_timeout`** (seconds):
when set, it becomes the default execution timeout, overridable per-run with
`--timeout` (and `0` means "no timeout"). The store is created lazily — only once
you set a preference.

The store is **local-only and never transmitted**, and is intended for **non-secret
configuration**. It is separate from the audit log; `memory reset`/`delete` clear
preferences and do not touch the audit log.

## Not yet available

These are designed (see the [planning doc](../planning/enshell-ai-native-shell-plan.md))
but **not** implemented in the current MVP. enShell will refuse or report them rather
than pretend:

- **Write / system actions** — installing packages, starting/stopping services,
  deleting/compressing files, git commits, backups, etc. These are recognised but
  **refused** in the read-only MVP (planned for Phase 3, after safety testing).
- **Full Windows parity** — Windows now runs 6 of the 10 read-only workflows
  (newly added; rendered commands are unit-tested and the build is compile-checked
  in CI, but end-to-end Windows execution is less battle-tested than macOS/Linux).
  The remaining four (`find_process_using_port`, `find_large_files`, `disk_usage`,
  `open_file_or_folder`) are deferred — see the request table above for why.
- **`enshell undo` and `enshell fix-last`** — placeholders; they print a "not
  available yet" notice. `undo` needs recorded per-action undo plans; `fix-last`
  needs the last command's *text*, which is opt-in capture (not the default).
  (`enshell explain-last` **is** available once the shell hook is installed — see
  [Shell integration](#shell-integration-optional-opt-in).)
- **Production-grade / CI-exercised live inference** — live inference is verified to
  *run* (73.7% raw accuracy on Gemma 4 E2B), but it isn't exercised in CI and the
  model accuracy isn't yet tuned to a pass bar. See the experimental note above.

## See also

- [Safety model](../security/safety-model.md) — the guarantees behind the preview/confirm flow.
- [Planning document](../planning/enshell-ai-native-shell-plan.md) — full design, roadmap, and rationale.
- [`SECURITY.md`](../../SECURITY.md) — how to report a vulnerability.
