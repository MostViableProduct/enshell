//! Shell detection, hook-snippet generation, and privacy-minimal context capture.
//!
//! # What this layer does (and does not) capture
//!
//! enShell is **privacy-minimal by default**: with no shell integration installed,
//! the only context available is the OS and the current working directory. The
//! *last command's exit code* cannot be observed by a child process — it lives in
//! the parent interactive shell — so capturing it requires an **opt-in** hook the
//! user installs themselves.
//!
//! This module generates that hook as a snippet the user pastes into their shell
//! startup file (`enshell shell-init`). The hook exports two environment variables
//! before each prompt:
//!
//! - [`LAST_EXIT_ENV`] — the previous command's exit code.
//! - [`SHELL_ENV`] — the active shell name (so detection is exact).
//!
//! It captures **nothing else** — not the command text, not its output, not the
//! environment. [`capture`] reads those variables (plus the cwd) back into a
//! [`ShellContext`]. The presence of [`LAST_EXIT_ENV`] is what
//! [`ShellContext::hook_active`] reports.
//!
//! The hook writes only an exit code and a shell name — neither is sensitive — and
//! it is never installed automatically; the user must paste it.

use std::path::PathBuf;

use enshell_os::ShellKind;

/// Environment variable the installed hook exports with the previous command's
/// exit code. Its presence is the signal that the hook is active.
pub const LAST_EXIT_ENV: &str = "ENSHELL_LAST_EXIT_CODE";

/// Environment variable the installed hook exports naming the active shell.
pub const SHELL_ENV: &str = "ENSHELL_SHELL";

/// Privacy-minimal context captured from the environment.
///
/// Every field is best-effort: a missing or unparsable value becomes `None`
/// rather than an error, so capture never fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellContext {
    /// The detected shell, if recognised.
    pub shell: Option<ShellKind>,
    /// The current working directory, if available.
    pub cwd: Option<PathBuf>,
    /// The previous command's exit code — only available when the hook is active.
    pub last_exit_code: Option<i32>,
    /// True when the enShell hook is installed (i.e. [`LAST_EXIT_ENV`] is present),
    /// even if its value did not parse.
    pub hook_active: bool,
}

/// Detect the active shell from the real environment.
///
/// [`SHELL_ENV`] (set explicitly by our hook) takes precedence over the basename
/// of `$SHELL`. Returns `None` for an unrecognised or absent shell.
pub fn detect_shell() -> Option<ShellKind> {
    detect_shell_from(
        std::env::var(SHELL_ENV).ok().as_deref(),
        std::env::var("SHELL").ok().as_deref(),
    )
}

/// Pure core of [`detect_shell`]: resolve a shell from the two env values.
///
/// `enshell_shell` is the value of [`SHELL_ENV`] (preferred, set by our hook);
/// `shell_path` is the value of `$SHELL` (e.g. `/bin/zsh`), used as a fallback.
pub fn detect_shell_from(
    enshell_shell: Option<&str>,
    shell_path: Option<&str>,
) -> Option<ShellKind> {
    if let Some(s) = enshell_shell {
        if let Some(kind) = shell_kind_from_token(s) {
            return Some(kind);
        }
    }
    let path = shell_path?;
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    shell_kind_from_token(base)
}

/// Map a shell name token (e.g. `"zsh"`, `"-bash"`, `"pwsh"`) to a [`ShellKind`].
fn shell_kind_from_token(token: &str) -> Option<ShellKind> {
    // Login shells appear as "-bash"; strip a single leading '-'.
    let t = token.trim().trim_start_matches('-').to_lowercase();
    match t.as_str() {
        "bash" => Some(ShellKind::Bash),
        "zsh" => Some(ShellKind::Zsh),
        "fish" => Some(ShellKind::Fish),
        "pwsh" | "powershell" => Some(ShellKind::PowerShell),
        _ => None,
    }
}

/// Capture privacy-minimal context from the real environment.
pub fn capture() -> ShellContext {
    capture_from(
        detect_shell(),
        std::env::current_dir().ok(),
        std::env::var(LAST_EXIT_ENV).ok().as_deref(),
    )
}

/// Pure core of [`capture`]: build a [`ShellContext`] from already-read inputs.
///
/// `hook_active` is true whenever `last_exit_raw` is `Some` (the var exists),
/// even if the value fails to parse — a malformed value still proves the hook ran.
pub fn capture_from(
    shell: Option<ShellKind>,
    cwd: Option<PathBuf>,
    last_exit_raw: Option<&str>,
) -> ShellContext {
    let hook_active = last_exit_raw.is_some();
    let last_exit_code = last_exit_raw.and_then(|s| s.trim().parse::<i32>().ok());
    ShellContext {
        shell,
        cwd,
        last_exit_code,
        hook_active,
    }
}

/// The paste-able hook snippet for `shell`, or `None` if not yet supported.
///
/// Supported today: [`ShellKind::Bash`] and [`ShellKind::Zsh`]. The snippet is
/// idempotent (re-sourcing it does not stack the hook) and exports only the exit
/// code and shell name.
pub fn hook_snippet(shell: &ShellKind) -> Option<&'static str> {
    match shell {
        ShellKind::Bash => Some(BASH_HOOK),
        ShellKind::Zsh => Some(ZSH_HOOK),
        ShellKind::Fish | ShellKind::PowerShell => None,
    }
}

/// A short human-readable name for a [`ShellKind`].
pub fn shell_label(shell: &ShellKind) -> &'static str {
    match shell {
        ShellKind::Bash => "bash",
        ShellKind::Zsh => "zsh",
        ShellKind::Fish => "fish",
        ShellKind::PowerShell => "powershell",
    }
}

const BASH_HOOK: &str = r#"# enShell shell integration — captures ONLY the last exit code + shell name.
# Add to ~/.bashrc, then start a new shell.
__enshell_capture() { local __ec=$?; export ENSHELL_LAST_EXIT_CODE=$__ec; export ENSHELL_SHELL=bash; }
case "${PROMPT_COMMAND:-}" in
  *__enshell_capture*) ;;
  *) PROMPT_COMMAND="__enshell_capture${PROMPT_COMMAND:+; $PROMPT_COMMAND}" ;;
esac
"#;

const ZSH_HOOK: &str = r#"# enShell shell integration — captures ONLY the last exit code + shell name.
# Add to ~/.zshrc, then start a new shell.
__enshell_capture() { export ENSHELL_LAST_EXIT_CODE=$?; export ENSHELL_SHELL=zsh; }
autoload -Uz add-zsh-hook && add-zsh-hook precmd __enshell_capture
"#;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- detect_shell_from ---------------------------------------------------

    #[test]
    fn enshell_shell_env_takes_precedence() {
        // Even if $SHELL says bash, ENSHELL_SHELL=zsh (set by our hook) wins.
        assert_eq!(
            detect_shell_from(Some("zsh"), Some("/bin/bash")),
            Some(ShellKind::Zsh)
        );
    }

    #[test]
    fn falls_back_to_shell_basename() {
        assert_eq!(
            detect_shell_from(None, Some("/bin/zsh")),
            Some(ShellKind::Zsh)
        );
        assert_eq!(
            detect_shell_from(None, Some("/usr/bin/bash")),
            Some(ShellKind::Bash)
        );
    }

    #[test]
    fn strips_login_shell_dash() {
        assert_eq!(
            detect_shell_from(Some("-bash"), None),
            Some(ShellKind::Bash)
        );
    }

    #[test]
    fn unknown_or_absent_shell_is_none() {
        assert_eq!(detect_shell_from(Some("nu"), None), None);
        assert_eq!(detect_shell_from(None, Some("/bin/nu")), None);
        assert_eq!(detect_shell_from(None, None), None);
    }

    #[test]
    fn unknown_enshell_shell_falls_through_to_path() {
        // A bogus ENSHELL_SHELL must not block the $SHELL fallback.
        assert_eq!(
            detect_shell_from(Some("garbage"), Some("/bin/zsh")),
            Some(ShellKind::Zsh)
        );
    }

    // --- capture_from --------------------------------------------------------

    #[test]
    fn capture_marks_hook_active_and_parses_exit_code() {
        let ctx = capture_from(Some(ShellKind::Zsh), Some(PathBuf::from("/tmp")), Some("0"));
        assert!(ctx.hook_active);
        assert_eq!(ctx.last_exit_code, Some(0));
        assert_eq!(ctx.shell, Some(ShellKind::Zsh));
    }

    #[test]
    fn capture_parses_nonzero_exit_code() {
        let ctx = capture_from(Some(ShellKind::Bash), None, Some("127"));
        assert_eq!(ctx.last_exit_code, Some(127));
    }

    #[test]
    fn capture_without_hook_has_no_exit_code() {
        let ctx = capture_from(Some(ShellKind::Bash), None, None);
        assert!(!ctx.hook_active);
        assert_eq!(ctx.last_exit_code, None);
    }

    #[test]
    fn capture_with_garbage_exit_is_active_but_unparsed() {
        // The var being present proves the hook ran, even if the value is junk.
        let ctx = capture_from(None, None, Some("not-a-number"));
        assert!(ctx.hook_active);
        assert_eq!(ctx.last_exit_code, None);
    }

    // --- hook_snippet --------------------------------------------------------

    #[test]
    fn bash_snippet_uses_prompt_command_and_exports_exit_code() {
        let s = hook_snippet(&ShellKind::Bash).expect("bash supported");
        assert!(s.contains("PROMPT_COMMAND"));
        assert!(s.contains(LAST_EXIT_ENV));
        // Idempotency guard present.
        assert!(s.contains("*__enshell_capture*"));
    }

    #[test]
    fn zsh_snippet_uses_precmd_and_exports_exit_code() {
        let s = hook_snippet(&ShellKind::Zsh).expect("zsh supported");
        assert!(s.contains("add-zsh-hook precmd"));
        assert!(s.contains(LAST_EXIT_ENV));
    }

    #[test]
    fn unsupported_shells_have_no_snippet() {
        assert!(hook_snippet(&ShellKind::Fish).is_none());
        assert!(hook_snippet(&ShellKind::PowerShell).is_none());
    }

    #[test]
    fn shell_label_is_stable() {
        assert_eq!(shell_label(&ShellKind::Bash), "bash");
        assert_eq!(shell_label(&ShellKind::Zsh), "zsh");
    }
}
