class Enshell < Formula
  desc "AI-native shell: natural language to a previewed, confirmed command"
  homepage "https://github.com/MostViableProduct/enshell"
  license "Apache-2.0"

  # HEAD install (builds the latest `main`):
  #   brew install --HEAD <this-formula>
  head "https://github.com/MostViableProduct/enshell.git", branch: "main"

  # Stable install: uncomment and fill in once a `vX.Y.Z` tag exists.
  #   1. bump the workspace `version` in Cargo.toml, commit
  #   2. git tag v0.1.0 && git push origin v0.1.0   (GitHub auto-creates the tarball)
  #   3. curl -sL <url below> | shasum -a 256        (compute the sha256)
  # url "https://github.com/MostViableProduct/enshell/archive/refs/tags/v0.1.0.tar.gz"
  # sha256 "REPLACE_WITH_TARBALL_SHA256"

  # Rust is needed only to build; the installed binary has no runtime Rust dep.
  depends_on "rust" => :build

  def install
    # Build and install ONLY the `enshell` binary from the workspace's CLI crate.
    # Default features → no llama.cpp / C++ (the optional `llama` feature is left
    # off); the only C compiled is bundled SQLite, via the C compiler Homebrew
    # provides (Command Line Tools on macOS, gcc on Homebrew/Linux). `--locked`
    # builds against the committed Cargo.lock for a reproducible dependency set.
    system "cargo", "install", *std_cargo_args(path: "crates/enshell-cli")
  end

  test do
    # The CLI prints its plain-English banner (contains "enShell") and exits 0 —
    # this is fully offline (no model download, no network).
    assert_match "enShell", shell_output("#{bin}/enshell --help")
    # `doctor` is a no-network environment self-check; assert it runs and reports.
    assert_match "enShell doctor", shell_output("#{bin}/enshell doctor")
  end
end
