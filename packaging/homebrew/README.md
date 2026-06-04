# Homebrew packaging

[`enshell.rb`](enshell.rb) is a **build-from-source** Homebrew formula for the
`enshell` CLI. Homebrew installs Rust as a build dependency, runs
`cargo install` against the committed `Cargo.lock`, and drops the `enshell`
binary on your `PATH`. The default build is dependency-light: no llama.cpp / C++
(the optional `llama` feature stays off); the only C compiled is **bundled
SQLite**, via the C compiler Homebrew already provides.

> Status: there is no tagged release yet, so installation is **HEAD-only**
> (builds the latest `main`). When a `vX.Y.Z` tag is cut, uncomment the
> `url`/`sha256` block in the formula for stable installs — see
> [Cutting a stable release](#cutting-a-stable-release).

## Install on a DigitalOcean droplet (Linux)

A droplet is a Linux box, so this uses **Homebrew on Linux**. On a fresh Ubuntu
droplet:

```bash
# 1. Install Homebrew on Linux (one-time; pulls its own gcc toolchain).
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
eval "$($(brew --prefix 2>/dev/null || echo /home/linuxbrew/.linuxbrew/bin)/brew shellenv)"

# 2. Build + install enShell from the latest main (compiles from source).
brew install --HEAD \
  https://raw.githubusercontent.com/MostViableProduct/enshell/main/packaging/homebrew/enshell.rb

# 3. Verify.
enshell doctor
enshell "what is using port 3000"     # read-only; previews + asks before running
```

`brew install --HEAD <url>` reads the formula from the raw URL and builds the
current `main`. Re-run the same command to update to a newer `main`.

> **Heads-up on Homebrew-on-Linux for a server.** Linuxbrew installs its own
> toolchain and is heavyweight for a throwaway test box. If you'd rather not run
> brew on the droplet, the formula's build step is just `cargo build --release`
> — see [Without Homebrew](#without-homebrew-lighter-for-a-server).

## Install on macOS

```bash
brew install --HEAD \
  https://raw.githubusercontent.com/MostViableProduct/enshell/main/packaging/homebrew/enshell.rb
```

(macOS uses the Command Line Tools C compiler for bundled SQLite; if you hit a
compiler error, run `xcode-select --install` once.)

## Without Homebrew (lighter for a server)

The formula compiles `crates/enshell-cli`; you can do the same directly with a
Rust toolchain on the droplet (via [rustup](https://rustup.rs)):

```bash
git clone https://github.com/MostViableProduct/enshell.git
cd enshell
cargo build --release -p enshell-cli
./target/release/enshell doctor
# optionally: install onto PATH
cargo install --locked --path crates/enshell-cli   # → ~/.cargo/bin/enshell
```

Or build the binary on one machine and `scp ./target/release/enshell` to the
droplet (same OS/arch). The binary is self-contained apart from the libc it was
built against.

## Cutting a stable release

To move off HEAD-only installs:

1. Bump the workspace `version` in the root `Cargo.toml` (currently `0.0.0`),
   commit.
2. Tag and push: `git tag v0.1.0 && git push origin v0.1.0`. GitHub then serves
   the source tarball at the `archive/refs/tags/v0.1.0.tar.gz` URL in the formula.
3. Compute its checksum:
   `curl -sL https://github.com/MostViableProduct/enshell/archive/refs/tags/v0.1.0.tar.gz | shasum -a 256`
4. Uncomment and fill the `url`/`sha256` lines in [`enshell.rb`](enshell.rb).
   `brew install <formula>` (no `--HEAD`) then builds the pinned release.

## Promoting to a tap (clean `brew install`)

For a one-line `brew tap … && brew install enshell` experience, move this
formula into a tap repository named `homebrew-<tap>` (e.g.
`MostViableProduct/homebrew-enshell`, with the formula at `Formula/enshell.rb`).
Users then run:

```bash
brew tap mostviableproduct/enshell https://github.com/MostViableProduct/homebrew-enshell
brew install --HEAD enshell    # or `brew install enshell` once a release is tagged
```

## Verifying the formula

The formula passes Homebrew's checks (`brew style` + `brew audit`) and its
`cargo install` build step is verified. To re-check locally in a throwaway tap:

```bash
tap="$(brew --repository)/Library/Taps/you/homebrew-localtest"
mkdir -p "$tap/Formula" && cp packaging/homebrew/enshell.rb "$tap/Formula/"
brew style you/localtest/enshell
brew audit --formula you/localtest/enshell
brew untap you/localtest
```
