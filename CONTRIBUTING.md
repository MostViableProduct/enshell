# Contributing to enShell

Thank you for your interest in contributing to enShell. This document explains
how to get started, how to submit contributions, and the governance rules that
apply.

---

## Project Status

enShell is currently at **Planning Stage (Phase 0)**. There is no runnable code
yet. The repository contains a planning document and governance files. If you
want to understand the intended design before contributing code, start here:

- [`docs/planning/enshell-ai-native-shell-plan.md`](docs/planning/enshell-ai-native-shell-plan.md)

Issues and discussions about the design, architecture, and plan are welcome while
we are in this phase.

---

## Code of Conduct

By participating in this project you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

---

## Contribution Governance: DCO (No CLA Required)

enShell uses the **Developer Certificate of Origin (DCO)** for contribution
governance. There is **no Contributor License Agreement (CLA)** required to
contribute.

What this means:

- You sign off each commit to certify that you have the right to submit the
  contribution under the project's license and that you agree to the DCO terms
  (see the full text below).
- You do this by adding a `Signed-off-by` trailer to your commits:

  ```sh
  git commit -s -m "your commit message"
  ```

  This adds a line like the following to your commit message:

  ```
  Signed-off-by: Your Name <your@email.example>
  ```

- Pull requests that include commits without a `Signed-off-by` line will not be
  merged.

The full DCO text is reproduced at the end of this document so you know exactly
what you are certifying.

---

## License

By contributing to enShell, you agree that your contributions are licensed under
the **Apache License, Version 2.0** (the same license as the project). See
[`LICENSE`](LICENSE) for the full text.

---

## Dev Setup

### Prerequisites

- **Rust toolchain** — install via [rustup](https://rustup.rs/):

  ```sh
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

  The repository will include a `rust-toolchain.toml` (or `rust-toolchain`) file
  pinning the minimum stable version once the workspace is bootstrapped.

### Build

```sh
cargo build
```

### Run tests

```sh
cargo test
```

### Lint and format

```sh
cargo fmt --all           # format
cargo clippy --all-targets -- -D warnings   # lint
```

These will be required to pass on all pull requests.

### Dependency / license checks

Once CI tooling is wired in, run locally before submitting a PR:

```sh
cargo deny check
```

See [`DEPENDENCIES.md`](DEPENDENCIES.md) for details.

---

## Branching and Pull Request Conventions

- **Default branch:** `main`.
- **Feature branches:** use descriptive names, e.g. `feat/intent-schema-v0`,
  `fix/policy-tier-classification`, `docs/update-security-policy`.
- **Commits:** write clear, imperative-mood commit messages. Sign off every
  commit with `git commit -s`.
- **Pull requests:**
  - Target `main` unless otherwise directed.
  - Include a clear description of the change and why it is being made.
  - Reference relevant issues (e.g. `Closes #42`).
  - Keep PRs focused. Large changes are easier to review when broken into
    smaller, self-contained units.
- **Reviews:** at least one maintainer approval is required before merging.

---

## Reporting Security Issues

Please do **not** open a public GitHub issue for security vulnerabilities. See
[`SECURITY.md`](SECURITY.md) for the responsible disclosure process.

---

## Developer Certificate of Origin, Version 1.1

The following is the full text of the DCO that you certify by adding a
`Signed-off-by` line to your commits.

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Source: https://developercertificate.org
