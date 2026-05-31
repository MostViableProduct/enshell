# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue to report a security vulnerability.**

enShell uses **GitHub private vulnerability reporting**. To report a
vulnerability:

1. Go to the **Security** tab of this repository on GitHub.
2. Click **"Report a vulnerability"**.
3. Fill in the details of the issue — what you found, how to reproduce it, and
   what impact you believe it has.

GitHub's private reporting mechanism routes your report directly to the
maintainers without public disclosure. We will acknowledge receipt and keep you
updated as we investigate.

If you are unable to use GitHub's private reporting for any reason, you can also
reach the maintainers privately via GitHub (direct message to a maintainer listed
in the repository, or by opening a private discussion if that option is
available).

**Do not share vulnerability details publicly** (e.g. in issues, pull requests,
or social media) until the maintainers have had a reasonable opportunity to
assess and address it.

---

## Supported Versions

enShell is currently at **Planning Stage (Phase 0)**. No production release has
been shipped. There are no supported versions at this time.

| Version | Supported |
|---|---|
| Any pre-release / planning-stage artifact | No formal support |
| First stable release (not yet available) | TBD |

Security reports are still welcome during the planning stage — if you find an
issue in the design, threat model, or planned architecture, please report it as
described above.

---

## Scope

The following are in scope for security reports:

- The enShell source code in this repository.
- The security design, threat model, and architectural decisions documented in
  [`docs/planning/enshell-ai-native-shell-plan.md`](docs/planning/enshell-ai-native-shell-plan.md)
  (§15 Security Threat Model).
- Any planned or actual mechanisms for command execution, policy enforcement,
  local model inference, or data handling.

The following are **out of scope** for this project's security process (but you
should report them to the relevant upstream projects):

- Vulnerabilities in llama.cpp itself — report to the llama.cpp project.
- Vulnerabilities in Gemma model weights — report to Google.
- Vulnerabilities in third-party Rust crates — report to the relevant crate
  maintainers and/or via the [RustSec Advisory Database](https://rustsec.org/).
- Vulnerabilities in the operating systems or shells that enShell runs alongside.

---

## Response Expectations

Because enShell is in its early planning phase and has a small maintainer team,
we cannot commit to specific SLA timelines. Our intent is to:

- Acknowledge your report within a reasonable timeframe after receipt.
- Provide an initial assessment of severity and scope.
- Keep you informed of progress toward a fix or architectural change.
- Credit reporters (with your permission) in release notes or a security
  advisory when a fix is published.

---

## Security-First Posture

enShell's design is built around a security-first posture. The threat model
documented in §15 of the planning document covers the primary threat categories
the project is designed to address, including:

- Prompt injection from terminal output.
- Shell injection via model-generated commands.
- Privilege escalation.
- Secret leakage.
- Supply-chain attacks.
- Model hallucination leading to unsafe commands.

The core architectural invariant — the LLM may never directly execute commands;
it proposes typed structured intents; trusted Rust code validates, maps,
previews, and executes actions — is the primary mechanism through which many of
these threats are mitigated by construction.

We take security reports seriously at every stage of development. Reporting a
design-level concern during the planning phase is especially valuable: it is far
less costly to address architectural issues before code is written.
