//! Intent to OS-specific command rendering.
//!
//! This crate maps a typed [`Intent`] to a [`CommandPlan`] for the current
//! (or specified) OS.  All command construction happens in **trusted Rust
//! code** — the model never produces commands directly.
//!
//! # Scope (this slice)
//!
//! Read-only intents on **macOS** and **Linux**:
//!
//! | Intent | macOS | Linux |
//! |---|---|---|
//! | [`FindProcessUsingPort`] | `lsof -i :<port>` | `ss -lptn 'sport = :<port>'` |
//! | [`FindLargeFiles`] | `du -ah <path> \| sort -rh \| head -n <limit>` | same |
//! | [`OpenFileOrFolder`] | `open <path>` | `xdg-open <path>` |
//! | [`InspectLogs`] | `log show --style syslog --last <since>` | `journalctl --no-pager -n 200 [--since <since>]` |
//! | [`CheckSystemHealth`] | `df -h; uptime; vm_stat` (Sequence) | `df -h; uptime; free -h` (Sequence) |
//!
//! # Deferred / out-of-scope
//!
//! - `min_size` parameter on [`FindLargeFiles`] is **ignored** in this slice;
//!   `du` enumerates all files and the caller chooses with `head`.  Document
//!   this as a known limitation; a future slice can add `find … -size +<n>`
//!   pre-filtering.
//! - `source` and `filter` parameters on [`InspectLogs`] are **deferred**;
//!   a future slice will add `--predicate` / grep post-filtering.
//! - Write/system intents (`InstallPackage`, `KillProcess`, `CompressFolder`,
//!   `CreateBackup`, `CreateProject`, `GitCommitChanges`, `StartService`,
//!   `StopService`, `UpdatePackages`) → [`AdapterError::NotYetImplemented`].
//! - `ExplainError`, `FixLastCommand`, `AskClarification` → [`AdapterError::Unsupported`]
//!   (these are handled by the explanation/clarification layer, not by a shell command).
//! - `Os::Windows` / `Os::Other` → [`AdapterError::UnsupportedOs`].
//!
//! [`FindProcessUsingPort`]: enshell_intents::Intent::FindProcessUsingPort
//! [`FindLargeFiles`]: enshell_intents::Intent::FindLargeFiles
//! [`OpenFileOrFolder`]: enshell_intents::Intent::OpenFileOrFolder
//! [`InspectLogs`]: enshell_intents::Intent::InspectLogs
//! [`CheckSystemHealth`]: enshell_intents::Intent::CheckSystemHealth

use std::fmt;

use enshell_intents::Intent;
use enshell_os::{CommandPlan, ExecStep, Os};

// ---------------------------------------------------------------------------
// AdapterError
// ---------------------------------------------------------------------------

/// Errors produced by [`render`].
#[derive(Debug)]
pub enum AdapterError {
    /// The intent does not map to a shell command; it is handled by a higher
    /// layer (explanation / clarification).  Examples: `ExplainError`,
    /// `FixLastCommand`, `AskClarification`.
    Unsupported {
        intent: &'static str,
        reason: &'static str,
    },

    /// The intent is valid but its adapter has not been implemented yet in
    /// this slice (write / system intents).
    NotYetImplemented { intent: &'static str, os: Os },

    /// The requested OS is not supported for this intent in the current slice.
    /// Currently `Windows` and `Other` fall into this bucket.
    UnsupportedOs { intent: &'static str, os: Os },
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterError::Unsupported { intent, reason } => {
                write!(f, "intent '{intent}' does not map to a command: {reason}")
            }
            AdapterError::NotYetImplemented { intent, os } => {
                write!(f, "intent '{intent}' is not yet implemented for {os:?}")
            }
            AdapterError::UnsupportedOs { intent, os } => {
                write!(f, "intent '{intent}' is not supported on {os:?}")
            }
        }
    }
}

impl std::error::Error for AdapterError {}

// ---------------------------------------------------------------------------
// Tilde expansion helpers
// ---------------------------------------------------------------------------

/// Pure tilde-expansion: substitutes `home` for a leading `~` or `~/`.
///
/// - `~/Downloads` with `Some("/u/alice")` → `"/u/alice/Downloads"`
/// - `~` alone with `Some("/u/alice")` → `"/u/alice"`
/// - Any other path is returned unchanged.
/// - If `home` is `None` the path is returned unchanged.
fn expand_tilde_with_home(path: &str, home: Option<&str>) -> String {
    let Some(home) = home else {
        return path.to_owned();
    };
    if path == "~" {
        return home.to_owned();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return format!("{home}/{rest}");
    }
    path.to_owned()
}

/// Expand a leading `~` or `~/` in `path` using `$HOME`.
///
/// Thin wrapper around [`expand_tilde_with_home`] that reads `HOME` from the
/// process environment.  If `HOME` is unset the path is returned unchanged.
fn expand_tilde(path: &str) -> String {
    expand_tilde_with_home(path, std::env::var("HOME").ok().as_deref())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Render a read-only [`Intent`] into a [`CommandPlan`] for the given OS.
///
/// The resulting plan is guaranteed to satisfy
/// `enshell_os::plan_requires_shell(&plan) == false`
/// for all intents in scope.
///
/// # Errors
///
/// Returns [`AdapterError::Unsupported`] for intents that have no shell
/// command equivalent (`ExplainError`, `FixLastCommand`, `AskClarification`).
///
/// Returns [`AdapterError::NotYetImplemented`] for write/system intents that
/// are out of scope for this slice.
///
/// Returns [`AdapterError::UnsupportedOs`] when `os` is `Windows` or `Other`
/// for an otherwise-supported intent.
pub fn render(intent: &Intent, os: Os) -> Result<CommandPlan, AdapterError> {
    match intent {
        // ── Read-only intents ─────────────────────────────────────────────
        Intent::FindProcessUsingPort { port } => render_find_process_using_port(*port, os),

        Intent::FindLargeFiles { path, limit, .. } => {
            // min_size is intentionally ignored in this slice; see module doc.
            render_find_large_files(path, *limit, os)
        }

        Intent::OpenFileOrFolder { path } => render_open_file_or_folder(path, os),

        Intent::InspectLogs { since, .. } => {
            // source and filter are deferred; see module doc.
            render_inspect_logs(since.as_deref(), os)
        }

        Intent::CheckSystemHealth {} => render_check_system_health(os),

        // ── Unsupported: no command equivalent ───────────────────────────
        Intent::ExplainError { .. } => Err(AdapterError::Unsupported {
            intent: "explain_error",
            reason: "handled by the explanation layer, not a shell command",
        }),

        Intent::FixLastCommand { .. } => Err(AdapterError::Unsupported {
            intent: "fix_last_command",
            reason: "handled by the clarification/correction layer, not a shell command",
        }),

        Intent::AskClarification { .. } => Err(AdapterError::Unsupported {
            intent: "ask_clarification",
            reason: "handled by the clarification layer, not a shell command",
        }),

        // ── Not yet implemented: write/system intents ─────────────────────
        Intent::InstallPackage { .. } => Err(AdapterError::NotYetImplemented {
            intent: "install_package",
            os,
        }),

        Intent::KillProcess { .. } => Err(AdapterError::NotYetImplemented {
            intent: "kill_process",
            os,
        }),

        Intent::CompressFolder { .. } => Err(AdapterError::NotYetImplemented {
            intent: "compress_folder",
            os,
        }),

        Intent::CreateBackup { .. } => Err(AdapterError::NotYetImplemented {
            intent: "create_backup",
            os,
        }),

        Intent::CreateProject { .. } => Err(AdapterError::NotYetImplemented {
            intent: "create_project",
            os,
        }),

        Intent::GitCommitChanges { .. } => Err(AdapterError::NotYetImplemented {
            intent: "git_commit_changes",
            os,
        }),

        Intent::StartService { .. } => Err(AdapterError::NotYetImplemented {
            intent: "start_service",
            os,
        }),

        Intent::StopService { .. } => Err(AdapterError::NotYetImplemented {
            intent: "stop_service",
            os,
        }),

        Intent::UpdatePackages { .. } => Err(AdapterError::NotYetImplemented {
            intent: "update_packages",
            os,
        }),
    }
}

// ---------------------------------------------------------------------------
// Per-intent render helpers
// ---------------------------------------------------------------------------

fn render_find_process_using_port(port: u16, os: Os) -> Result<CommandPlan, AdapterError> {
    match os {
        Os::MacOs => {
            // lsof -i :<port>
            Ok(CommandPlan::exec("lsof", ["-i", &format!(":{port}")]))
        }
        Os::Linux => {
            // ss -lptn 'sport = :<port>'
            // The filter is a single argv element — never split across words.
            Ok(CommandPlan::exec(
                "ss",
                ["-lptn", &format!("sport = :{port}")],
            ))
        }
        Os::Windows | Os::Other => Err(AdapterError::UnsupportedOs {
            intent: "find_process_using_port",
            os,
        }),
    }
}

fn render_find_large_files(
    path: &str,
    limit: Option<u32>,
    os: Os,
) -> Result<CommandPlan, AdapterError> {
    match os {
        Os::MacOs | Os::Linux => {
            let expanded = expand_tilde(path);
            let n = limit.unwrap_or(10).to_string();
            Ok(CommandPlan::pipeline(vec![
                ExecStep::new("du", ["-ah", &expanded]),
                ExecStep::new("sort", ["-rh"]),
                ExecStep::new("head", ["-n", &n]),
            ]))
        }
        Os::Windows | Os::Other => Err(AdapterError::UnsupportedOs {
            intent: "find_large_files",
            os,
        }),
    }
}

fn render_open_file_or_folder(path: &str, os: Os) -> Result<CommandPlan, AdapterError> {
    let expanded = expand_tilde(path);
    match os {
        Os::MacOs => Ok(CommandPlan::exec("open", [&expanded])),
        Os::Linux => Ok(CommandPlan::exec("xdg-open", [&expanded])),
        Os::Windows | Os::Other => Err(AdapterError::UnsupportedOs {
            intent: "open_file_or_folder",
            os,
        }),
    }
}

fn render_inspect_logs(since: Option<&str>, os: Os) -> Result<CommandPlan, AdapterError> {
    match os {
        Os::MacOs => {
            // log show --style syslog --last <since|"1h">
            let since_val = since.unwrap_or("1h");
            Ok(CommandPlan::exec(
                "log",
                ["show", "--style", "syslog", "--last", since_val],
            ))
        }
        Os::Linux => {
            // journalctl --no-pager -n 200 [--since <since>]
            let mut args: Vec<String> =
                vec!["--no-pager".to_owned(), "-n".to_owned(), "200".to_owned()];
            if let Some(s) = since {
                args.push("--since".to_owned());
                args.push(s.to_owned());
            }
            Ok(CommandPlan::Exec(ExecStep {
                program: "journalctl".to_owned(),
                args,
            }))
        }
        Os::Windows | Os::Other => Err(AdapterError::UnsupportedOs {
            intent: "inspect_logs",
            os,
        }),
    }
}

fn render_check_system_health(os: Os) -> Result<CommandPlan, AdapterError> {
    match os {
        Os::MacOs => Ok(CommandPlan::sequence(vec![
            ExecStep::new("df", ["-h"]),
            ExecStep::new("uptime", [] as [&str; 0]),
            ExecStep::new("vm_stat", [] as [&str; 0]),
        ])),
        Os::Linux => Ok(CommandPlan::sequence(vec![
            ExecStep::new("df", ["-h"]),
            ExecStep::new("uptime", [] as [&str; 0]),
            ExecStep::new("free", ["-h"]),
        ])),
        Os::Windows | Os::Other => Err(AdapterError::UnsupportedOs {
            intent: "check_system_health",
            os,
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use enshell_os::plan_requires_shell;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Extract the single `ExecStep` from a `CommandPlan::Exec`, panicking otherwise.
    fn as_exec(plan: &CommandPlan) -> &ExecStep {
        match plan {
            CommandPlan::Exec(step) => step,
            other => panic!("expected Exec, got {other:?}"),
        }
    }

    /// Extract the `Vec<ExecStep>` from a `CommandPlan::Pipeline`, panicking otherwise.
    fn as_pipeline(plan: &CommandPlan) -> &Vec<ExecStep> {
        match plan {
            CommandPlan::Pipeline(steps) => steps,
            other => panic!("expected Pipeline, got {other:?}"),
        }
    }

    /// Extract the `Vec<ExecStep>` from a `CommandPlan::Sequence`, panicking otherwise.
    fn as_sequence(plan: &CommandPlan) -> &Vec<ExecStep> {
        match plan {
            CommandPlan::Sequence(steps) => steps,
            other => panic!("expected Sequence, got {other:?}"),
        }
    }

    // ── Golden argv: FindProcessUsingPort ─────────────────────────────────────

    #[test]
    fn find_process_using_port_macos_golden_argv() {
        let intent = Intent::FindProcessUsingPort { port: 3000 };
        let plan = render(&intent, Os::MacOs).expect("render should succeed");
        let step = as_exec(&plan);
        assert_eq!(step.program, "lsof");
        assert_eq!(step.args, vec!["-i", ":3000"]);
    }

    #[test]
    fn find_process_using_port_linux_golden_argv() {
        let intent = Intent::FindProcessUsingPort { port: 3000 };
        let plan = render(&intent, Os::Linux).expect("render should succeed");
        let step = as_exec(&plan);
        assert_eq!(step.program, "ss");
        assert_eq!(step.args, vec!["-lptn", "sport = :3000"]);
    }

    #[test]
    fn find_process_using_port_macos_no_shell() {
        let intent = Intent::FindProcessUsingPort { port: 8080 };
        let plan = render(&intent, Os::MacOs).unwrap();
        assert!(!plan_requires_shell(&plan));
    }

    #[test]
    fn find_process_using_port_linux_no_shell() {
        let intent = Intent::FindProcessUsingPort { port: 8080 };
        let plan = render(&intent, Os::Linux).unwrap();
        assert!(!plan_requires_shell(&plan));
    }

    // ── Golden argv: FindLargeFiles ───────────────────────────────────────────

    #[test]
    fn find_large_files_macos_golden_argv() {
        let intent = Intent::FindLargeFiles {
            path: "/tmp".to_owned(),
            min_size: None,
            limit: Some(5),
        };
        let plan = render(&intent, Os::MacOs).expect("render should succeed");
        let steps = as_pipeline(&plan);
        assert_eq!(steps.len(), 3);
        // du -ah /tmp
        assert_eq!(steps[0].program, "du");
        assert_eq!(steps[0].args, vec!["-ah", "/tmp"]);
        // sort -rh
        assert_eq!(steps[1].program, "sort");
        assert_eq!(steps[1].args, vec!["-rh"]);
        // head -n 5
        assert_eq!(steps[2].program, "head");
        assert_eq!(steps[2].args, vec!["-n", "5"]);
    }

    #[test]
    fn find_large_files_linux_golden_argv() {
        let intent = Intent::FindLargeFiles {
            path: "/home/user".to_owned(),
            min_size: None,
            limit: Some(10),
        };
        let plan = render(&intent, Os::Linux).expect("render should succeed");
        let steps = as_pipeline(&plan);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].program, "du");
        assert_eq!(steps[0].args, vec!["-ah", "/home/user"]);
        assert_eq!(steps[1].program, "sort");
        assert_eq!(steps[1].args, vec!["-rh"]);
        assert_eq!(steps[2].program, "head");
        assert_eq!(steps[2].args, vec!["-n", "10"]);
    }

    #[test]
    fn find_large_files_default_limit_is_10() {
        let intent = Intent::FindLargeFiles {
            path: "/tmp".to_owned(),
            min_size: None,
            limit: None, // no limit specified → default 10
        };
        let plan = render(&intent, Os::MacOs).unwrap();
        let steps = as_pipeline(&plan);
        assert_eq!(steps[2].args, vec!["-n", "10"]);
    }

    #[test]
    fn find_large_files_no_shell_macos() {
        let intent = Intent::FindLargeFiles {
            path: "/tmp".to_owned(),
            min_size: None,
            limit: None,
        };
        assert!(!plan_requires_shell(&render(&intent, Os::MacOs).unwrap()));
    }

    #[test]
    fn find_large_files_no_shell_linux() {
        let intent = Intent::FindLargeFiles {
            path: "/tmp".to_owned(),
            min_size: None,
            limit: None,
        };
        assert!(!plan_requires_shell(&render(&intent, Os::Linux).unwrap()));
    }

    // ── Tilde expansion ───────────────────────────────────────────────────────
    //
    // All tests below call the pure `expand_tilde_with_home` helper directly so
    // that no test mutates the process environment.

    #[test]
    fn tilde_slash_path_with_home() {
        assert_eq!(
            expand_tilde_with_home("~/Downloads", Some("/test-home")),
            "/test-home/Downloads"
        );
    }

    #[test]
    fn tilde_bare_with_home() {
        assert_eq!(expand_tilde_with_home("~", Some("/my/home")), "/my/home");
    }

    #[test]
    fn tilde_slash_path_no_home_unchanged() {
        assert_eq!(expand_tilde_with_home("~/x", None), "~/x");
    }

    #[test]
    fn no_tilde_absolute_path_unchanged_with_home() {
        assert_eq!(
            expand_tilde_with_home("/absolute/path", Some("/irrelevant")),
            "/absolute/path"
        );
    }

    #[test]
    fn no_tilde_absolute_path_unchanged_without_home() {
        assert_eq!(
            expand_tilde_with_home("/absolute/path", None),
            "/absolute/path"
        );
    }

    #[test]
    fn find_large_files_no_tilde_path_unchanged() {
        let intent = Intent::FindLargeFiles {
            path: "/absolute/path".to_owned(),
            min_size: None,
            limit: None,
        };
        let plan = render(&intent, Os::Linux).unwrap();
        let steps = as_pipeline(&plan);
        assert_eq!(steps[0].args[1], "/absolute/path");
    }

    // ── Golden argv: OpenFileOrFolder ─────────────────────────────────────────

    #[test]
    fn open_file_or_folder_macos_golden_argv() {
        let intent = Intent::OpenFileOrFolder {
            path: "/Users/me/file.txt".to_owned(),
        };
        let plan = render(&intent, Os::MacOs).expect("render should succeed");
        let step = as_exec(&plan);
        assert_eq!(step.program, "open");
        assert_eq!(step.args, vec!["/Users/me/file.txt"]);
    }

    #[test]
    fn open_file_or_folder_linux_golden_argv() {
        let intent = Intent::OpenFileOrFolder {
            path: "/home/user/docs".to_owned(),
        };
        let plan = render(&intent, Os::Linux).expect("render should succeed");
        let step = as_exec(&plan);
        assert_eq!(step.program, "xdg-open");
        assert_eq!(step.args, vec!["/home/user/docs"]);
    }

    #[test]
    fn open_file_or_folder_tilde_expansion_macos() {
        // Test the pure helper directly — no env mutation needed.
        assert_eq!(
            expand_tilde_with_home("~/Documents", Some("/home/testuser")),
            "/home/testuser/Documents"
        );
    }

    #[test]
    fn open_file_or_folder_no_shell_macos() {
        let intent = Intent::OpenFileOrFolder {
            path: "/tmp".to_owned(),
        };
        assert!(!plan_requires_shell(&render(&intent, Os::MacOs).unwrap()));
    }

    #[test]
    fn open_file_or_folder_no_shell_linux() {
        let intent = Intent::OpenFileOrFolder {
            path: "/tmp".to_owned(),
        };
        assert!(!plan_requires_shell(&render(&intent, Os::Linux).unwrap()));
    }

    // ── InspectLogs ───────────────────────────────────────────────────────────

    #[test]
    fn inspect_logs_macos_default_since() {
        let intent = Intent::InspectLogs {
            source: None,
            since: None,
            filter: None,
        };
        let plan = render(&intent, Os::MacOs).unwrap();
        let step = as_exec(&plan);
        assert_eq!(step.program, "log");
        assert_eq!(step.args, vec!["show", "--style", "syslog", "--last", "1h"]);
    }

    #[test]
    fn inspect_logs_macos_with_since() {
        let intent = Intent::InspectLogs {
            source: None,
            since: Some("2h".to_owned()),
            filter: None,
        };
        let plan = render(&intent, Os::MacOs).unwrap();
        let step = as_exec(&plan);
        assert_eq!(step.program, "log");
        assert_eq!(step.args, vec!["show", "--style", "syslog", "--last", "2h"]);
    }

    #[test]
    fn inspect_logs_linux_no_since() {
        let intent = Intent::InspectLogs {
            source: None,
            since: None,
            filter: None,
        };
        let plan = render(&intent, Os::Linux).unwrap();
        let step = as_exec(&plan);
        assert_eq!(step.program, "journalctl");
        assert_eq!(step.args, vec!["--no-pager", "-n", "200"]);
    }

    #[test]
    fn inspect_logs_linux_with_since() {
        let intent = Intent::InspectLogs {
            source: None,
            since: Some("30m".to_owned()),
            filter: None,
        };
        let plan = render(&intent, Os::Linux).unwrap();
        let step = as_exec(&plan);
        assert_eq!(step.program, "journalctl");
        assert_eq!(step.args, vec!["--no-pager", "-n", "200", "--since", "30m"]);
    }

    #[test]
    fn inspect_logs_no_shell_macos() {
        let intent = Intent::InspectLogs {
            source: None,
            since: None,
            filter: None,
        };
        assert!(!plan_requires_shell(&render(&intent, Os::MacOs).unwrap()));
    }

    #[test]
    fn inspect_logs_no_shell_linux() {
        let intent = Intent::InspectLogs {
            source: None,
            since: None,
            filter: None,
        };
        assert!(!plan_requires_shell(&render(&intent, Os::Linux).unwrap()));
    }

    // ── CheckSystemHealth ─────────────────────────────────────────────────────

    #[test]
    fn check_system_health_macos_sequence() {
        let intent = Intent::CheckSystemHealth {};
        let plan = render(&intent, Os::MacOs).unwrap();
        let steps = as_sequence(&plan);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].program, "df");
        assert_eq!(steps[0].args, vec!["-h"]);
        assert_eq!(steps[1].program, "uptime");
        assert!(steps[1].args.is_empty());
        assert_eq!(steps[2].program, "vm_stat");
        assert!(steps[2].args.is_empty());
    }

    #[test]
    fn check_system_health_linux_sequence() {
        let intent = Intent::CheckSystemHealth {};
        let plan = render(&intent, Os::Linux).unwrap();
        let steps = as_sequence(&plan);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].program, "df");
        assert_eq!(steps[0].args, vec!["-h"]);
        assert_eq!(steps[1].program, "uptime");
        assert!(steps[1].args.is_empty());
        assert_eq!(steps[2].program, "free");
        assert_eq!(steps[2].args, vec!["-h"]);
    }

    #[test]
    fn check_system_health_no_shell_macos() {
        let intent = Intent::CheckSystemHealth {};
        assert!(!plan_requires_shell(&render(&intent, Os::MacOs).unwrap()));
    }

    #[test]
    fn check_system_health_no_shell_linux() {
        let intent = Intent::CheckSystemHealth {};
        assert!(!plan_requires_shell(&render(&intent, Os::Linux).unwrap()));
    }

    // ── Unsupported intents ───────────────────────────────────────────────────

    #[test]
    fn explain_error_returns_unsupported() {
        let intent = Intent::ExplainError {
            command: None,
            stderr: None,
            exit_code: None,
        };
        let err = render(&intent, Os::MacOs).expect_err("should be Unsupported");
        assert!(
            matches!(
                err,
                AdapterError::Unsupported {
                    intent: "explain_error",
                    ..
                }
            ),
            "expected Unsupported(explain_error), got: {err}"
        );
    }

    #[test]
    fn fix_last_command_returns_unsupported() {
        let intent = Intent::FixLastCommand {
            last_command: "ls -z".to_owned(),
            exit_code: 1,
            stderr: "invalid option".to_owned(),
        };
        let err = render(&intent, Os::Linux).expect_err("should be Unsupported");
        assert!(matches!(
            err,
            AdapterError::Unsupported {
                intent: "fix_last_command",
                ..
            }
        ));
    }

    #[test]
    fn ask_clarification_returns_unsupported() {
        let intent = Intent::AskClarification {
            question: "Which folder?".to_owned(),
            options: None,
        };
        let err = render(&intent, Os::MacOs).expect_err("should be Unsupported");
        assert!(matches!(
            err,
            AdapterError::Unsupported {
                intent: "ask_clarification",
                ..
            }
        ));
    }

    // ── NotYetImplemented: write/system intents ───────────────────────────────

    #[test]
    fn install_package_returns_not_yet_implemented() {
        let intent = Intent::InstallPackage {
            name: "ripgrep".to_owned(),
            manager: None,
            version: None,
        };
        let err = render(&intent, Os::MacOs).expect_err("should be NotYetImplemented");
        assert!(matches!(
            err,
            AdapterError::NotYetImplemented {
                intent: "install_package",
                ..
            }
        ));
    }

    #[test]
    fn kill_process_returns_not_yet_implemented() {
        let intent = Intent::KillProcess {
            pid: Some(1234),
            name: None,
            port: None,
            force: None,
        };
        let err = render(&intent, Os::Linux).expect_err("should be NotYetImplemented");
        assert!(matches!(
            err,
            AdapterError::NotYetImplemented {
                intent: "kill_process",
                ..
            }
        ));
    }

    #[test]
    fn update_packages_returns_not_yet_implemented() {
        let intent = Intent::UpdatePackages {
            manager: None,
            scope: None,
        };
        let err = render(&intent, Os::MacOs).expect_err("should be NotYetImplemented");
        assert!(matches!(
            err,
            AdapterError::NotYetImplemented {
                intent: "update_packages",
                ..
            }
        ));
    }

    #[test]
    fn compress_folder_returns_not_yet_implemented() {
        let intent = Intent::CompressFolder {
            path: "/tmp/foo".to_owned(),
            output: None,
            exclude: None,
        };
        let err = render(&intent, Os::Linux).expect_err("should be NotYetImplemented");
        assert!(matches!(
            err,
            AdapterError::NotYetImplemented {
                intent: "compress_folder",
                ..
            }
        ));
    }

    #[test]
    fn create_backup_returns_not_yet_implemented() {
        let intent = Intent::CreateBackup {
            path: "/data".to_owned(),
            dest: None,
        };
        let err = render(&intent, Os::MacOs).expect_err("should be NotYetImplemented");
        assert!(matches!(
            err,
            AdapterError::NotYetImplemented {
                intent: "create_backup",
                ..
            }
        ));
    }

    #[test]
    fn start_service_returns_not_yet_implemented() {
        let intent = Intent::StartService {
            name: "nginx".to_owned(),
        };
        let err = render(&intent, Os::Linux).expect_err("should be NotYetImplemented");
        assert!(matches!(
            err,
            AdapterError::NotYetImplemented {
                intent: "start_service",
                ..
            }
        ));
    }

    #[test]
    fn stop_service_returns_not_yet_implemented() {
        let intent = Intent::StopService {
            name: "nginx".to_owned(),
        };
        let err = render(&intent, Os::MacOs).expect_err("should be NotYetImplemented");
        assert!(matches!(
            err,
            AdapterError::NotYetImplemented {
                intent: "stop_service",
                ..
            }
        ));
    }

    #[test]
    fn create_project_returns_not_yet_implemented() {
        let intent = Intent::CreateProject {
            kind: "nextjs".to_owned(),
            name: "my-app".to_owned(),
            path: None,
        };
        let err = render(&intent, Os::MacOs).expect_err("should be NotYetImplemented");
        assert!(matches!(
            err,
            AdapterError::NotYetImplemented {
                intent: "create_project",
                ..
            }
        ));
    }

    #[test]
    fn git_commit_returns_not_yet_implemented() {
        let intent = Intent::GitCommitChanges {
            message: "fix: something".to_owned(),
            add_all: None,
        };
        let err = render(&intent, Os::Linux).expect_err("should be NotYetImplemented");
        assert!(matches!(
            err,
            AdapterError::NotYetImplemented {
                intent: "git_commit_changes",
                ..
            }
        ));
    }

    // ── UnsupportedOs ─────────────────────────────────────────────────────────

    #[test]
    fn find_process_using_port_windows_returns_unsupported_os() {
        let intent = Intent::FindProcessUsingPort { port: 3000 };
        let err = render(&intent, Os::Windows).expect_err("should be UnsupportedOs");
        assert!(matches!(
            err,
            AdapterError::UnsupportedOs {
                intent: "find_process_using_port",
                os: Os::Windows,
            }
        ));
    }

    #[test]
    fn find_process_using_port_other_returns_unsupported_os() {
        let intent = Intent::FindProcessUsingPort { port: 3000 };
        let err = render(&intent, Os::Other).expect_err("should be UnsupportedOs");
        assert!(matches!(
            err,
            AdapterError::UnsupportedOs {
                intent: "find_process_using_port",
                os: Os::Other,
            }
        ));
    }

    #[test]
    fn find_large_files_windows_returns_unsupported_os() {
        let intent = Intent::FindLargeFiles {
            path: "C:\\Users".to_owned(),
            min_size: None,
            limit: None,
        };
        let err = render(&intent, Os::Windows).expect_err("should be UnsupportedOs");
        assert!(matches!(
            err,
            AdapterError::UnsupportedOs {
                intent: "find_large_files",
                ..
            }
        ));
    }

    #[test]
    fn open_file_or_folder_windows_returns_unsupported_os() {
        let intent = Intent::OpenFileOrFolder {
            path: "C:\\file.txt".to_owned(),
        };
        let err = render(&intent, Os::Windows).expect_err("should be UnsupportedOs");
        assert!(matches!(
            err,
            AdapterError::UnsupportedOs {
                intent: "open_file_or_folder",
                ..
            }
        ));
    }

    #[test]
    fn check_system_health_windows_returns_unsupported_os() {
        let intent = Intent::CheckSystemHealth {};
        let err = render(&intent, Os::Windows).expect_err("should be UnsupportedOs");
        assert!(matches!(
            err,
            AdapterError::UnsupportedOs {
                intent: "check_system_health",
                ..
            }
        ));
    }

    // ── AdapterError Display ──────────────────────────────────────────────────

    #[test]
    fn adapter_error_unsupported_display_contains_intent_and_reason() {
        let err = AdapterError::Unsupported {
            intent: "explain_error",
            reason: "no command",
        };
        let s = err.to_string();
        assert!(s.contains("explain_error"), "display: {s}");
        assert!(s.contains("no command"), "display: {s}");
    }

    #[test]
    fn adapter_error_not_yet_implemented_display_contains_intent() {
        let err = AdapterError::NotYetImplemented {
            intent: "install_package",
            os: Os::MacOs,
        };
        let s = err.to_string();
        assert!(s.contains("install_package"), "display: {s}");
    }

    #[test]
    fn adapter_error_unsupported_os_display_contains_intent() {
        let err = AdapterError::UnsupportedOs {
            intent: "find_process_using_port",
            os: Os::Windows,
        };
        let s = err.to_string();
        assert!(s.contains("find_process_using_port"), "display: {s}");
    }

    // ── expand_tilde_with_home unit tests ────────────────────────────────────
    // (These supplement the tilde-expansion tests above; no env mutation.)

    #[test]
    fn expand_tilde_with_home_subpath() {
        assert_eq!(
            expand_tilde_with_home("~/foo/bar", Some("/my/home")),
            "/my/home/foo/bar"
        );
    }

    #[test]
    fn expand_tilde_with_home_relative_path_unchanged() {
        assert_eq!(
            expand_tilde_with_home("relative/path", Some("/my/home")),
            "relative/path"
        );
    }
}
