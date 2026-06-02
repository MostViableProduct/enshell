# enShell — Safety Model

> **Scope.** This describes the safety guarantees enShell enforces **today**. The
> full design (all risk tiers, the threat model, the recovery model) lives in
> [`docs/planning/enshell-ai-native-shell-plan.md`](../planning/enshell-ai-native-shell-plan.md)
> §3, §6, §7, §15 — the authoritative source for the design. This document is
> authoritative for *current behavior* and does not restate the full tables; where
> it summarises, the planning doc governs.

## The one rule

> **The model never executes commands.** It proposes a *structured, typed intent*.
> Trusted Rust code validates, classifies, renders, previews, and (only after
> confirmation) executes that intent.

Everything below follows from this. The model's output is data, not instructions.

## Trust boundary

```text
   UNTRUSTED                          TRUSTED (Rust)                         EXECUTION
   ─────────                          ──────────────                          ─────────
 user text ─┐
 (+ model   ├─► model ─► raw JSON ─► validate ─► policy ─► render ─► preview ─► confirm ─► run
  output)  ─┘  (untrusted)          (parse +    (classify) (adapter) (you see) (you /     (argv,
                                     domain                            it       --yes)     no shell)
                                     checks)
```

Everything left of **validate** is untrusted — including the model's own output and
any context fed to it. Trust begins only after the Rust validator
(`enshell_intents::parse_model_output`) accepts the JSON: a strict schema parse
(unknown fields rejected) plus domain checks (port ranges, non-empty fields, etc.).

**The fast path and the trust boundary.** A [fast-path](../user-guides/getting-started.md#how-a-request-is-resolved-three-paths)
match produces a typed intent constructed by *trusted Rust*, so it has no untrusted
string to validate and skips `parse_model_output`. It is otherwise identical: the
same policy classification, MVP gate, adapter rendering, preview, and confirmation
apply. The fast path is an optimisation in front of the gate, never a way around it.

## Risk tiers

The policy engine — **not the model** — assigns every intent an authoritative risk
tier from its type and parameters (the model's self-reported risk is ignored). The
tiers run from `ReadOnly` through `LocalWrite` (create-only / mutating),
`PackageSystemChange`, `NetworkAccess`, `SecretsSensitive`, `Destructive`, and
`Privileged`, plus `UnsupportedAmbiguous`. The full table is plan §4.

**In the current MVP, only `ReadOnly` intents execute.** Anything above that tier is
recognised and classified, then **refused before any command is rendered** — you get
a short "I can't do that yet" message, not a plan or preview. (`--dry-run` and
`--plan` therefore apply only to executable `ReadOnly` actions; the design goal of
previewing higher-tier actions is a later phase, not current behavior.) This is
enforced in code by the MVP gate, not by convention.

## Confirmation Invariant

> Nothing executes without confirmation — interactive by default, or in advance via
> `--yes`. `--yes` is valid **only** for `ReadOnly` and create-only `LocalWrite`.
> Every higher tier always prompts; `Destructive`/`Privileged` additionally require a
> **typed** phrase. `open_file_or_folder` is `ReadOnly` but is **never** `--yes`-able
> (it launches an external handler), so it always prompts.

Because only `ReadOnly` executes in the MVP, `--yes` today simply skips the `[y/N]`
prompt for read-only diagnostics (except `open`, which always asks). The invariant is
enforced structurally in `enshell-core::Orchestrator::execute`, which returns
`ConfirmationRequired` rather than running when the invariant is not satisfied.

## No shell, by construction

enShell never runs `sh -c`. Adapters emit a structured `CommandPlan`:

- `Exec` — one process, argv array.
- `Pipeline` / `Sequence` — multiple `ExecStep`s wired with OS pipes / run in order.
  These hold **`ExecStep`s, not nested plans**, so a shell step cannot be hidden
  inside them.
- `RequiresShell` — the only variant that invokes an interpreter; it is **top-level
  only**, deny-by-default, and **not produced by any MVP adapter**.

Parameters are bound positionally as argv elements and are never concatenated into a
command line, so shell injection is eliminated as a class. The display strings you
see in previews (e.g. `du -ah . | sort -rh | head -n 10`) are *renderings* of the
plan — not how it is executed. You can confirm any request's plan with `--dry-run`.

## Audit log

Every execution attempt — success, denial, abort, error, or refusal — is appended to
a local, append-only audit log. Each record carries:

`correlation_id`, `timestamp`, `policy_version`, `intent_schema_version`,
`model_id` (`fast_path` / `stub` / the model name), `model_quant`,
`prompt_template_version`, `intent`, `params`, `risk_tier`, `command_plan`,
`confirmation_mode`, `exit_code`, `outcome`, and `redaction_count`.

**Tamper-evidence.** Records are hash-chained: each stores a hash of the previous
record, so deleting or editing any past record breaks the chain and is detectable.
Verify it mechanically:

```bash
enshell doctor      # prints "Audit log verify:  OK" or "FAILED — <reason>"
enshell history     # one line per recorded action
```

The log is **local-only** and never transmitted. Concurrent writers are serialised
with a file lock (exclusive on append, shared on read).

## Secret redaction

Before anything is written to the audit log, the `user_request`, the rendered
command, and the intent parameters are scanned and redacted: secret-shaped text and
sensitive JSON keys (tokens, keys, `.env`-style values) are replaced with a
`«redacted»` marker, and the count is recorded in `redaction_count`. Secret values
are never persisted.

## Privacy

Context capture is **privacy-minimal by default**. Today the request handed to the
model (`ModelRequest`) carries only your **request text**, the detected **OS**, and
the **current working directory** path — nothing else. The additional environment
facts the design calls for (shell type, last exit code, enShell's own history)
require the shell-integration layer and are **planned, not yet captured**.

By design, the literal text of past commands, stdout/stderr, full shell history, and
an environment summary will be **opt-in**; environment variable *values*, file
contents, secrets, tokens, SSH keys, and clipboard contents are **never** captured.
Inference is local by default — nothing leaves your machine. (See plan §9 for the
full policy.)

## Reporting a vulnerability

See [`SECURITY.md`](../../SECURITY.md). Please do not open public issues for security
reports.
