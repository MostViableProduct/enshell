# Third-Party Notices

This file tracks third-party source dependencies included in or linked by enShell
and their licenses.

> **Plain-English warning:** This file is an engineering artifact, not legal advice.
> Final licensing — especially anything touching model weights and third-party
> binaries — **must be reviewed by qualified counsel before public release.**

---

## Current Status

The workspace has third-party dependencies in three groups:

- **Serialization** (`enshell-intents`, `enshell-model`, `enshell-telemetry`,
  `enshell-cli`): `serde` (+`serde_derive`, `serde_core`), `serde_json`, and their
  transitive crates (`itoa`, `memchr`, `zmij` — David Tolnay's `ryu`-successor float
  formatter, `proc-macro2`, `quote`, `syn`, `unicode-ident`).
- **CLI** (`enshell-cli`): `clap` (argument parsing, with `derive`) and `ctrlc`
  (Ctrl-C → cancellation), plus their transitive crates (anstyle/anstream,
  clap_builder/clap_lex/clap_derive, etc.).
- **Hashing** (`enshell-telemetry`, for the tamper-evident audit-log hash chain):
  `sha2` (RustCrypto) and its transitive crates (`digest`, `block-buffer`,
  `crypto-common`, `cpufeatures`, `typenum`, `const-oid`, `hybrid-array`, `libc`).

Together these are roughly **40 third-party crates**. Every one resolves to a
permissive, Apache-2.0-compatible license drawn from the allowlist in
[`deny.toml`](deny.toml): **Apache-2.0, MIT, Unicode-3.0, Unlicense** (a few crates
additionally offer `Zlib` as an *alternative* in an `OR` expression; it is not the
selected/required license, so it is not in the allowlist).

This is **enforced by `cargo deny check`** on every push and pull request
(`.github/workflows/ci.yml`): a dependency whose license is not satisfiable from the
allowlist fails CI. Because the tree is now too large to enumerate by hand without
drift, the authoritative per-crate inventory is the lockfile + `cargo deny`; a
machine-generated SBOM / notice file (`cargo about`, `cargo cyclonedx`) is the
planned mechanism for a frozen per-crate listing (see below).

---

## How Third-Party Dependencies Will Be Tracked

As crates are added to the workspace, every third-party source dependency will
be listed here with:

- **Name** — crate/library name and version range in use.
- **License** — the SPDX identifier of the license (e.g. `MIT`, `Apache-2.0`).
- **Copyright/Attribution** — the upstream copyright notice(s) required by the
  license.
- **Source** — canonical URL (crates.io, GitHub, etc.).
- **Bundled or linked** — whether the dependency is statically linked, dynamically
  linked, or invoked as a subprocess.

Planned CI tooling (per `docs/planning/enshell-ai-native-shell-plan.md` §10 and
§13):

- **`cargo about`** — generates a human-readable notice file from the dependency
  tree. Run with:
  ```
  cargo about generate about.hbs > THIRD_PARTY_NOTICES.md
  ```
- **`cargo deny`** — enforces a license allowlist; the CI build fails on
  disallowed or unknown licenses. Configuration lives in `deny.toml`.
- **`cargo cyclonedx`** — generates a CycloneDX SBOM per release artifact.

Once those tools are wired in, this file will be generated and checked in as part
of every release build. The generated content will replace the placeholder text
in this section.

---

## External Components That enShell Interoperates With (Not Bundled)

The following components are **separate works** that enShell is designed to
interoperate with. They are **not** included in this repository and are **not**
covered by enShell's Apache-2.0 license grant. Each retains its own copyright
and license.

### llama.cpp

- **License:** MIT
- **Copyright:** Copyright (c) the llama.cpp authors and contributors. See the
  upstream repository for the full author list.
- **Source:** https://github.com/ggerganov/llama.cpp
- **Relationship to enShell:** enShell invokes or links llama.cpp at runtime as
  the local inference engine. The integration mechanism (Rust FFI bindings or
  subprocess) is an open question to be resolved in Phase 0 (see planning doc
  §19.2 item A). Either way, llama.cpp is a separate work — it is not bundled
  in this repository and is not relicensed.
- **Full MIT License text:** available at the upstream repository linked above.

### Gemma 4 Model Weights

Gemma 4 model weights are a **separate work** with their own copyright and
attribution. They are not bundled or redistributed by enShell. See
[`MODEL_LICENSES.md`](MODEL_LICENSES.md) for the per-profile license details,
attribution, and the per-version verification requirement.

---

## Consistency Note

The separation described here is intentional ("mere aggregation"): enShell's
Apache-2.0 grant applies to enShell's own source code and documentation, not to
external tools, model weights, package managers, or OS utilities it interoperates
with. See also [`NOTICE`](NOTICE) and [`MODEL_LICENSES.md`](MODEL_LICENSES.md).
