# Model Licenses and Attribution

This file documents the license and attribution information for the AI model
weights that enShell is designed to use.

> **Plain-English warning:** This file is an engineering artifact, not legal
> advice. Model-weight licensing can change between versions and is separate from
> the license that governs enShell's own source code. The exact terms for any
> specific model and version **must be re-verified against the official model card
> or LICENSE file published by the model's copyright holder before distribution.**
> This is especially important for Gemma: earlier Gemma releases (Gemma 1, Gemma
> 2) shipped under the custom "Gemma Terms of Use," not Apache-2.0. Do not assume
> a future model or version carries the same terms. Final licensing should be
> reviewed by qualified counsel before any public release.

---

## Important: Weights Are a Separate Work

enShell's Apache-2.0 license grant applies to **enShell's own source code and
documentation only.** The model weights listed here are:

- **Separate works** with their own copyright and their own license terms.
- **Not bundled or redistributed by enShell.** The user obtains them through a
  guided install flow: enShell detects when weights are missing, displays the
  model name, size, source, license notice, and disk requirement, and requires
  the user's **explicit consent** before any download begins (see planning doc
  §4 Layer 3 and §19.1 item 2).
- **Obtained from the official source** (Google's Gemma repository / Hugging
  Face model card). enShell does not host or mirror the weights.
- **Subject to their own copyright and attribution.** enShell's Apache-2.0 grant
  does not itself convey any rights to the weights.

---

## Gemma 4 — License and Attribution

| Field | Value |
|---|---|
| **Model family** | Gemma 4 |
| **Publisher / Copyright holder** | Google LLC |
| **License** | Apache License, Version 2.0 |
| **License URL** | https://www.apache.org/licenses/LICENSE-2.0 |
| **Official model card / source** | Google's official Gemma resources: https://ai.google.dev/gemma *(confirm the exact per-version model card / GGUF source before download)* |
| **Per-version verification** | Required — see note below |

> **Per-version verification requirement:** The Apache-2.0 grant above was
> confirmed for the Gemma 4 release at the time of this document. Earlier Gemma
> model versions (Gemma 1, Gemma 2) used the custom "Gemma Terms of Use" rather
> than Apache-2.0. **Before distributing or guiding users to download any
> specific model file or version, re-verify the license against Google's official
> model card and/or the `LICENSE` file in the model repository for that exact
> version.** Do not rely on this document alone.

**Attribution notice** (to be reproduced where required by the Apache-2.0 license
terms, and displayed to users during guided install):

```
Gemma is provided by Google LLC under the Apache License, Version 2.0.
Copyright Google LLC. All rights reserved.
```

---

## Model Profiles

enShell defines three hardware profiles, each using a different Gemma 4
quantization. All three use Gemma 4 weights and are covered by the license and
attribution above.

| Profile | Model | Quantization | Use case | Min machine |
|---|---|---|---|---|
| **Default** | Gemma 4 E4B Instruct | Q4 (GGUF, e.g. `Q4_K_M`) | Full intent set for supported tiers | Modern laptop, 16 GB RAM |
| **Fallback (low-resource)** | Gemma 4 E2B Instruct | Q4 (GGUF) | Read-only workflows and command explanation only | < 16 GB RAM |
| **Advanced / pro** | Gemma 4 26B A4B | Q4 (GGUF) | Stronger reasoning, multi-step diagnostics, future autonomous agents | Workstation / GPU |

All three profiles are installed via the same **guided install flow**: enShell
does not silently download weights. The user sees the model size, source URL,
license notice, and disk space requirement before any download begins, and must
give explicit consent.

---

## Guided Install: What the User Sees

During guided model installation, enShell will display (at minimum):

- The model name, variant, and quantization being installed.
- The download source (official Hugging Face / Google repository URL).
- The license under which the weights are distributed (with the attribution notice
  above).
- The approximate download size and disk space required.
- A prompt requiring explicit user consent before the download starts.

This flow ensures the user is informed of the separate license terms for the
weights before they acquire them.

---

## Relationship to Other License Files

- [`NOTICE`](NOTICE) — top-level Apache-2.0 attribution for enShell and a
  summary of the external components it interoperates with.
- [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) — third-party **source**
  dependency inventory (crates, linked libraries). Model weights are tracked
  here, in `MODEL_LICENSES.md`, not in `THIRD_PARTY_NOTICES.md`.
- [`DEPENDENCIES.md`](DEPENDENCIES.md) — generated Rust crate dependency tree.
