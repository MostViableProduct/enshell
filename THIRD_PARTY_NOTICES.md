# Third-Party Notices

This file tracks third-party source dependencies included in or linked by enShell
and their licenses.

> **Plain-English warning:** This file is an engineering artifact, not legal advice.
> Final licensing — especially anything touching model weights and third-party
> binaries — **must be reviewed by qualified counsel before public release.**

---

## Current Status

Phase 1 implementation has begun, so the workspace now has its first third-party
dependencies, introduced by `enshell-intents` for JSON (de)serialization of model
output:

| Direct dependency | Used by | License |
|---|---|---|
| `serde` (with `derive`) | `enshell-intents` | MIT OR Apache-2.0 |
| `serde_json` | `enshell-intents` | MIT OR Apache-2.0 |

Transitive dependencies pulled in by the above (all permissive and
Apache-2.0-compatible): `serde_core`, `serde_derive`, `itoa`, `memchr`
(Unlicense OR MIT), `zmij` (David Tolnay's Schubfach-based double-to-string
formatter — the successor to `ryu`, used by `serde_json`), `proc-macro2`,
`quote`, `syn`, `unicode-ident` — each MIT OR Apache-2.0 unless noted.

All current dependencies are permissive and compatible with enShell's Apache-2.0
license. **License identifiers above are asserted from known upstream metadata,
not yet tool-verified** — they will be machine-generated and enforced in CI
(`cargo about` / `cargo deny`, see below) before any release.

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
