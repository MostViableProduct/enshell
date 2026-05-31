# Dependency License Inventory

This file is the dependency license inventory for the enShell workspace.

> **This file is intended to be generated and kept current in CI.** The
> instructions below describe the process. Do not edit the dependency table by
> hand — run the generation commands instead.

---

## Current Status

**The workspace currently has no third-party dependencies.**

enShell is at **Planning Stage (Phase 0)**. The Rust workspace skeleton uses only
the Rust standard library (`std`). No third-party crates are listed in any
`Cargo.toml` yet.

This file will be regenerated as dependencies are added. The generated content
will replace or supplement the placeholder text in this document.

---

## Intended Generation Process

Once dependencies are added, the following tools and commands maintain this file
and the project's license compliance posture. All three are listed in the planned
technical stack (see `docs/planning/enshell-ai-native-shell-plan.md` §10 and
§13).

### 1. Human-readable notice generation — `cargo about`

Generates a notice file from the full transitive dependency tree.

```sh
# Install (once)
cargo install cargo-about

# Generate (run from the workspace root)
cargo about generate about.hbs > DEPENDENCIES.md
```

A template (`about.hbs`) in the repository root controls the output format. The
generated file lists every crate, its license, and the copyright/attribution text
required by that license.

### 2. License allowlist enforcement — `cargo deny`

Enforces a license allowlist; the CI build fails on disallowed or unknown
licenses. Configuration lives in `deny.toml` at the workspace root.

```sh
# Install (once)
cargo install cargo-deny

# Check (run in CI and locally before submitting a PR)
cargo deny check licenses
cargo deny check bans
cargo deny check advisories
```

Any dependency whose license is not in the allowlist causes a build failure.
Unknown licenses also fail — this prevents silently picking up a dependency whose
terms haven't been reviewed.

### 3. SBOM generation — `cargo cyclonedx`

Produces a CycloneDX Software Bill of Materials (SBOM) per release artifact.

```sh
# Install (once)
cargo install cargo-cyclonedx

# Generate (run as part of the release pipeline)
cargo cyclonedx --format json --output-file sbom.json
```

The SBOM is attached to every GitHub Release artifact so downstream users and
integrators can inspect the full dependency tree.

---

## CI Integration

When the tooling is wired in (Epic A3 in the project roadmap), CI will:

1. Run `cargo deny check` on every pull request — a license violation or
   advisory hit blocks merge.
2. Regenerate `DEPENDENCIES.md` via `cargo about generate` as part of the
   release build and commit the result.
3. Attach `sbom.json` (CycloneDX) to every tagged release artifact.

---

## Relationship to Other License Files

- [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) — third-party source
  dependency notices (human-authored overview; will be supplemented or replaced
  by the `cargo about` output).
- [`MODEL_LICENSES.md`](MODEL_LICENSES.md) — model weight licenses and
  attribution (tracked separately from Rust crates).
- [`NOTICE`](NOTICE) — top-level Apache-2.0 attribution for enShell.
