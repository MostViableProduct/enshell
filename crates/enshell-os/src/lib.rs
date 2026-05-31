//! Low-level OS detection and sandboxed process execution for enShell.
//!
//! # Safety contract
//!
//! **No shell interpreter is ever invoked by this crate** unless the top-level
//! [`CommandPlan`] variant is explicitly [`CommandPlan::RequiresShell`], in which
//! case the executor returns [`ExecError::ShellNotPermitted`] — because the MVP
//! deny-by-default policy never permits shell execution.
//!
//! All other variants (`Exec`, `Pipeline`, `Sequence`) run each [`ExecStep`] via
//! `std::process::Command::new(program).args(args)` — an argv array, never a
//! shell string — eliminating shell-injection as a class.
//!
//! # Type-level guarantee against nested shells
//!
//! [`Pipeline`](CommandPlan::Pipeline) and [`Sequence`](CommandPlan::Sequence)
//! hold `Vec<ExecStep>`, **not** `Vec<CommandPlan>`. Because [`ExecStep`] contains
//! only a program name and argv, there is no way to embed a
//! [`CommandPlan::RequiresShell`] inside a pipeline or sequence at the type level.
//! The [`plan_requires_shell`] predicate is therefore a simple, non-recursive
//! top-level variant check.

use std::io;
use std::process::{Command, Stdio};

// ─── OS detection ────────────────────────────────────────────────────────────

/// The operating system family detected at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    MacOs,
    Linux,
    Windows,
    Other,
}

/// Returns the operating system detected at compile time via `cfg!(target_os = …)`.
///
/// This is deterministic and zero-cost (evaluated at compile time through inlining).
pub fn current_os() -> Os {
    if cfg!(target_os = "macos") {
        Os::MacOs
    } else if cfg!(target_os = "linux") {
        Os::Linux
    } else if cfg!(target_os = "windows") {
        Os::Windows
    } else {
        Os::Other
    }
}

// ─── CommandPlan types ───────────────────────────────────────────────────────

/// A single process invocation: one program with an argv list.
///
/// Arguments are passed positionally and are **never** concatenated into a shell
/// command line. This is the atomic unit of safe execution in enShell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecStep {
    /// The program to execute (looked up via `PATH` if not an absolute path).
    pub program: String,
    /// The argument list passed directly to the OS as an argv array.
    pub args: Vec<String>,
}

impl ExecStep {
    /// Construct an [`ExecStep`] from a program name and an iterable of arguments.
    ///
    /// ```rust
    /// use enshell_os::ExecStep;
    /// let step = ExecStep::new("echo", ["hello"]);
    /// assert_eq!(step.program, "echo");
    /// assert_eq!(step.args, vec!["hello"]);
    /// ```
    pub fn new<S, I>(program: S, args: I) -> Self
    where
        S: Into<String>,
        I: IntoIterator,
        I::Item: Into<String>,
    {
        ExecStep {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

/// The shell interpreter kind, used only in [`CommandPlan::RequiresShell`].
///
/// This variant is **deny-by-default**: the executor returns
/// [`ExecError::ShellNotPermitted`] without running the script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellKind {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

/// A structured execution plan.
///
/// The type is intentionally split so that a shell cannot be nested inside a
/// pipeline or sequence:
///
/// - [`Pipeline`](CommandPlan::Pipeline) and [`Sequence`](CommandPlan::Sequence)
///   hold `Vec<ExecStep>` — argv-only, no interpreter.
/// - [`RequiresShell`](CommandPlan::RequiresShell) is the **only** variant that
///   names a shell interpreter and it is **always** at the top level. The executor
///   denies it by default in the MVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandPlan {
    /// Run a single process with an argv array.
    Exec(ExecStep),

    /// Run `steps[0] | steps[1] | … | steps[n]` via OS pipes.
    ///
    /// All processes are spawned directly; no shell is involved.
    /// Returns the stdout of the last stage.
    ///
    /// An empty vec is an error.
    Pipeline(Vec<ExecStep>),

    /// Run each step in order; stop and return [`ExecError::NonZeroExit`] on the
    /// first non-zero exit code. Returns the output of the last step on success.
    ///
    /// An empty vec is an error.
    Sequence(Vec<ExecStep>),

    /// A script that requires a shell interpreter.
    ///
    /// **TOP-LEVEL ONLY** — cannot be nested inside `Pipeline` or `Sequence`
    /// because those variants hold `Vec<ExecStep>`, not `Vec<CommandPlan>`.
    ///
    /// **DENY-BY-DEFAULT**: [`execute`] returns [`ExecError::ShellNotPermitted`]
    /// for this variant. It exists to make "does this plan need a shell?" a
    /// trivial top-level check rather than a recursive tree walk.
    RequiresShell { shell: ShellKind, script: String },
}

impl CommandPlan {
    /// Convenience constructor — wraps [`ExecStep::new`] in `Exec`.
    ///
    /// ```rust
    /// use enshell_os::CommandPlan;
    /// let plan = CommandPlan::exec("echo", ["hello"]);
    /// ```
    pub fn exec<S, I>(program: S, args: I) -> Self
    where
        S: Into<String>,
        I: IntoIterator,
        I::Item: Into<String>,
    {
        CommandPlan::Exec(ExecStep::new(program, args))
    }

    /// Convenience constructor for a pipeline.
    ///
    /// ```rust
    /// use enshell_os::{CommandPlan, ExecStep};
    /// let plan = CommandPlan::pipeline(vec![
    ///     ExecStep::new("echo", ["hello"]),
    ///     ExecStep::new("cat", ["-"]),
    /// ]);
    /// ```
    pub fn pipeline(steps: Vec<ExecStep>) -> Self {
        CommandPlan::Pipeline(steps)
    }

    /// Convenience constructor for a sequence.
    ///
    /// ```rust
    /// use enshell_os::{CommandPlan, ExecStep};
    /// let plan = CommandPlan::sequence(vec![
    ///     ExecStep::new("true", [] as [&str; 0]),
    ///     ExecStep::new("echo", ["ok"]),
    /// ]);
    /// ```
    pub fn sequence(steps: Vec<ExecStep>) -> Self {
        CommandPlan::Sequence(steps)
    }
}

/// Returns `true` iff the top-level variant is [`CommandPlan::RequiresShell`].
///
/// This is a trivial non-recursive check by construction: `Pipeline` and
/// `Sequence` hold `Vec<ExecStep>`, so a shell variant cannot be nested inside
/// them.
pub fn plan_requires_shell(plan: &CommandPlan) -> bool {
    matches!(plan, CommandPlan::RequiresShell { .. })
}

// ─── Executor ────────────────────────────────────────────────────────────────

/// The captured output of a successfully executed [`CommandPlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// Captured standard output (UTF-8; non-UTF-8 bytes are replaced with the
    /// Unicode replacement character).
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// The process exit code, or `None` if the process was terminated by a
    /// signal (Unix) or the code is otherwise unavailable.
    pub exit_code: Option<i32>,
}

/// Errors produced by [`execute`].
#[derive(Debug)]
pub enum ExecError {
    /// The program was not found on `PATH` (maps `io::ErrorKind::NotFound`).
    ProgramNotFound(String),
    /// The process could not be spawned (reason other than not-found).
    Spawn(io::Error),
    /// An I/O error occurred while reading output or wiring pipes.
    Io(io::Error),
    /// The process exited with a non-zero exit code.
    NonZeroExit { code: Option<i32>, stderr: String },
    /// The plan's top-level variant is [`CommandPlan::RequiresShell`], which is
    /// denied by default. No process was spawned.
    ShellNotPermitted,
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::ProgramNotFound(p) => write!(f, "program not found: {p}"),
            ExecError::Spawn(e) => write!(f, "failed to spawn process: {e}"),
            ExecError::Io(e) => write!(f, "I/O error: {e}"),
            ExecError::NonZeroExit { code, stderr } => {
                write!(f, "process exited with code {code:?}: {stderr}")
            }
            ExecError::ShellNotPermitted => {
                write!(f, "RequiresShell plans are denied by default")
            }
        }
    }
}

impl std::error::Error for ExecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ExecError::Spawn(e) | ExecError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Map an `io::Error` from spawning `program` to the appropriate [`ExecError`].
fn map_spawn_error(program: &str, err: io::Error) -> ExecError {
    if err.kind() == io::ErrorKind::NotFound {
        ExecError::ProgramNotFound(program.to_owned())
    } else {
        ExecError::Spawn(err)
    }
}

/// Execute a [`CommandPlan`] without invoking a shell.
///
/// # Contract
///
/// - `Exec` / `Pipeline` / `Sequence` run each [`ExecStep`] via
///   `std::process::Command::new(program).args(args)` — no `sh -c`, no string
///   concatenation, no shell interpretation.
/// - `RequiresShell` is **always** denied: returns
///   [`ExecError::ShellNotPermitted`] without spawning any process.
///
/// # Sequence output
///
/// For [`CommandPlan::Sequence`], the **last** step's output is returned on
/// success. Each earlier step's stdout and stderr are captured but discarded
/// (they are not accumulated). If any step exits non-zero, execution stops
/// immediately and that step's stderr is included in [`ExecError::NonZeroExit`].
pub fn execute(plan: &CommandPlan) -> Result<ExecOutput, ExecError> {
    match plan {
        CommandPlan::Exec(step) => execute_step(step),

        CommandPlan::Pipeline(steps) => execute_pipeline(steps),

        CommandPlan::Sequence(steps) => execute_sequence(steps),

        CommandPlan::RequiresShell { .. } => Err(ExecError::ShellNotPermitted),
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Run a single [`ExecStep`] and capture its output.
fn execute_step(step: &ExecStep) -> Result<ExecOutput, ExecError> {
    let output = Command::new(&step.program)
        .args(&step.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| map_spawn_error(&step.program, e))?;

    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if output.status.success() {
        Ok(ExecOutput {
            stdout,
            stderr,
            exit_code,
        })
    } else {
        Err(ExecError::NonZeroExit {
            code: exit_code,
            stderr,
        })
    }
}

/// Wire `steps[i].stdout → steps[i+1].stdin` using OS pipes; return the last
/// stage's captured output.
fn execute_pipeline(steps: &[ExecStep]) -> Result<ExecOutput, ExecError> {
    if steps.is_empty() {
        return Err(ExecError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Pipeline must have at least one step",
        )));
    }

    // Special-case: a single step behaves like Exec.
    if steps.len() == 1 {
        return execute_step(&steps[0]);
    }

    // Spawn the first process with piped stdout.
    let first = &steps[0];
    let mut prev_child = Command::new(&first.program)
        .args(&first.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| map_spawn_error(&first.program, e))?;

    // Spawn intermediate processes, each reading from the previous child's stdout.
    for step in &steps[1..steps.len() - 1] {
        let stdin_pipe = prev_child
            .stdout
            .take()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "could not take stdout from child",
                )
            })
            .map(Stdio::from)
            .map_err(ExecError::Io)?;

        let child = Command::new(&step.program)
            .args(&step.args)
            .stdin(stdin_pipe)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| map_spawn_error(&step.program, e))?;

        // We no longer need the previous child's handle; let it finish.
        // Drop it so its write-end of the pipe is closed, signalling EOF to
        // the next child when the pipe drains.
        drop(prev_child);
        prev_child = child;
    }

    // Spawn the last process; capture its stdout so we can return it.
    // `steps` is guaranteed non-empty (checked at function entry), but we handle
    // the empty case without panicking rather than relying on `.expect()`.
    let last = match steps.last() {
        Some(step) => step,
        None => {
            return Err(ExecError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pipeline has no steps",
            )))
        }
    };
    let stdin_pipe = prev_child
        .stdout
        .take()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "could not take stdout from child",
            )
        })
        .map(Stdio::from)
        .map_err(ExecError::Io)?;

    let last_child = Command::new(&last.program)
        .args(&last.args)
        .stdin(stdin_pipe)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| map_spawn_error(&last.program, e))?;

    // Wait for the last child to finish, capturing its output.
    let output = last_child.wait_with_output().map_err(ExecError::Io)?;

    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if output.status.success() {
        Ok(ExecOutput {
            stdout,
            stderr,
            exit_code,
        })
    } else {
        Err(ExecError::NonZeroExit {
            code: exit_code,
            stderr,
        })
    }
}

/// Run each step in order; stop on first non-zero exit. Return last step's output.
fn execute_sequence(steps: &[ExecStep]) -> Result<ExecOutput, ExecError> {
    if steps.is_empty() {
        return Err(ExecError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Sequence must have at least one step",
        )));
    }

    let mut last_output = ExecOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: None,
    };

    for step in steps {
        last_output = execute_step(step)?; // propagates NonZeroExit, stopping the sequence
    }

    Ok(last_output)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── OS detection ──────────────────────────────────────────────────────────

    /// `current_os()` should return a sensible value for the host, not `Other`.
    /// On macOS and Linux CI this will be MacOs or Linux; on Windows, Windows.
    #[test]
    fn test_current_os_is_known() {
        let os = current_os();
        // In practice, CI runs on macOS, Linux, or Windows — none should be Other.
        assert!(
            matches!(os, Os::MacOs | Os::Linux | Os::Windows),
            "unexpected Os::Other on this platform"
        );
    }

    #[test]
    fn test_current_os_returns_consistent_value() {
        // Deterministic: two calls return the same value.
        assert_eq!(current_os(), current_os());
    }

    // ── plan_requires_shell ───────────────────────────────────────────────────

    #[test]
    fn test_plan_requires_shell_exec_is_false() {
        let plan = CommandPlan::exec("echo", ["hello"]);
        assert!(!plan_requires_shell(&plan));
    }

    #[test]
    fn test_plan_requires_shell_pipeline_is_false() {
        let plan = CommandPlan::pipeline(vec![
            ExecStep::new("echo", ["hello"]),
            ExecStep::new("cat", ["-"]),
        ]);
        assert!(!plan_requires_shell(&plan));
    }

    #[test]
    fn test_plan_requires_shell_sequence_is_false() {
        let plan = CommandPlan::sequence(vec![
            ExecStep::new("true", [] as [&str; 0]),
            ExecStep::new("echo", ["ok"]),
        ]);
        assert!(!plan_requires_shell(&plan));
    }

    #[test]
    fn test_plan_requires_shell_requires_shell_is_true() {
        let plan = CommandPlan::RequiresShell {
            shell: ShellKind::Bash,
            script: "echo hello".to_owned(),
        };
        assert!(plan_requires_shell(&plan));
    }

    // ── Type-level guarantee ──────────────────────────────────────────────────
    //
    // `Pipeline(Vec<ExecStep>)` and `Sequence(Vec<ExecStep>)` hold `ExecStep`,
    // NOT `CommandPlan`. It is therefore a compile-time error to place a
    // `RequiresShell` variant inside a pipeline or sequence.
    //
    // The following would not compile:
    //
    //   CommandPlan::Pipeline(vec![
    //       CommandPlan::RequiresShell { shell: ShellKind::Bash, script: "...".to_owned() },
    //   ]);
    //
    // because `Vec<ExecStep>` requires `ExecStep`, not `CommandPlan`.
    // This is a compile-time guarantee that shells cannot be nested — no runtime
    // check or recursion is needed.
    #[test]
    fn test_pipeline_holds_exec_steps_not_command_plans() {
        // If this compiles, the type guarantee is in place.
        // The _plan variable is intentionally unused — the compile check IS the test.
        let _plan: CommandPlan = CommandPlan::Pipeline(vec![
            ExecStep::new("echo", ["a"]),
            ExecStep::new("cat", ["-"]),
        ]);
        // No RequiresShell can appear here — ExecStep has no such variant.
        assert!(!plan_requires_shell(&_plan));
    }

    // ── RequiresShell → ShellNotPermitted (all platforms) ────────────────────

    #[test]
    fn test_requires_shell_returns_shell_not_permitted() {
        let plan = CommandPlan::RequiresShell {
            shell: ShellKind::Bash,
            script: "echo injected".to_owned(),
        };
        let result = execute(&plan);
        assert!(
            matches!(result, Err(ExecError::ShellNotPermitted)),
            "expected ShellNotPermitted, got {result:?}"
        );
    }

    #[test]
    fn test_requires_shell_zsh_not_permitted() {
        let plan = CommandPlan::RequiresShell {
            shell: ShellKind::Zsh,
            script: "ls".to_owned(),
        };
        assert!(matches!(execute(&plan), Err(ExecError::ShellNotPermitted)));
    }

    #[test]
    fn test_requires_shell_powershell_not_permitted() {
        let plan = CommandPlan::RequiresShell {
            shell: ShellKind::PowerShell,
            script: "Get-Process".to_owned(),
        };
        assert!(matches!(execute(&plan), Err(ExecError::ShellNotPermitted)));
    }

    // ── Program not found (all platforms) ────────────────────────────────────

    #[test]
    fn test_program_not_found_returns_program_not_found_error() {
        let plan = CommandPlan::exec("__enshell_nonexistent_program_xyz_123__", [] as [&str; 0]);
        let result = execute(&plan);
        match result {
            Err(ExecError::ProgramNotFound(prog)) => {
                assert_eq!(prog, "__enshell_nonexistent_program_xyz_123__");
            }
            other => panic!("expected ProgramNotFound, got {other:?}"),
        }
    }

    // ── Unix integration tests ────────────────────────────────────────────────

    #[cfg(unix)]
    mod unix {
        use super::*;

        // ── Exec ──────────────────────────────────────────────────────────────

        /// `echo hello` → stdout "hello\n", exit 0.
        #[test]
        fn test_exec_echo_hello() {
            let plan = CommandPlan::exec("echo", ["hello"]);
            let output = execute(&plan).expect("echo should succeed");
            assert_eq!(output.stdout, "hello\n");
            assert_eq!(output.exit_code, Some(0));
        }

        /// `true` → exit 0, empty stdout.
        #[test]
        fn test_exec_true_succeeds() {
            let plan = CommandPlan::exec("true", [] as [&str; 0]);
            let output = execute(&plan).expect("true should succeed");
            assert_eq!(output.exit_code, Some(0));
        }

        /// `false` → NonZeroExit.
        #[test]
        fn test_exec_false_returns_non_zero_exit() {
            let plan = CommandPlan::exec("false", [] as [&str; 0]);
            let result = execute(&plan);
            assert!(
                matches!(result, Err(ExecError::NonZeroExit { .. })),
                "expected NonZeroExit, got {result:?}"
            );
        }

        // ── Pipeline ──────────────────────────────────────────────────────────

        /// `printf "c\na\nb\n" | sort` → "a\nb\nc\n"
        #[test]
        fn test_pipeline_printf_sort() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("printf", ["c\na\nb\n"]),
                ExecStep::new("sort", [] as [&str; 0]),
            ]);
            let output = execute(&plan).expect("printf | sort should succeed");
            assert_eq!(output.stdout, "a\nb\nc\n");
            assert_eq!(output.exit_code, Some(0));
        }

        /// `echo hello | wc -c` → byte count of "hello\n" = 6.
        /// `wc -c` output format varies by platform (may include leading spaces),
        /// so we parse the number rather than asserting the exact string.
        #[test]
        fn test_pipeline_echo_wc() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("echo", ["hello"]),
                ExecStep::new("wc", ["-c"]),
            ]);
            let output = execute(&plan).expect("echo | wc -c should succeed");
            let count: u64 = output
                .stdout
                .trim()
                .parse()
                .expect("wc -c should print a number");
            // "hello\n" is 6 bytes.
            assert_eq!(count, 6, "unexpected byte count: {}", output.stdout);
        }

        /// `echo hello | cat -` → "hello\n"
        #[test]
        fn test_pipeline_echo_cat() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("echo", ["hello"]),
                ExecStep::new("cat", ["-"]),
            ]);
            let output = execute(&plan).expect("echo | cat should succeed");
            assert_eq!(output.stdout, "hello\n");
        }

        /// Three-stage pipeline: `printf "c\na\nb\n" | sort | head -1` → "a\n"
        #[test]
        fn test_pipeline_three_stages() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("printf", ["c\na\nb\n"]),
                ExecStep::new("sort", [] as [&str; 0]),
                ExecStep::new("head", ["-1"]),
            ]);
            let output = execute(&plan).expect("3-stage pipeline should succeed");
            assert_eq!(output.stdout, "a\n");
        }

        // ── Sequence ──────────────────────────────────────────────────────────

        /// `[true, echo ok]` → runs both, returns "ok\n".
        #[test]
        fn test_sequence_true_then_echo() {
            let plan = CommandPlan::sequence(vec![
                ExecStep::new("true", [] as [&str; 0]),
                ExecStep::new("echo", ["ok"]),
            ]);
            let output = execute(&plan).expect("sequence should succeed");
            assert_eq!(output.stdout, "ok\n");
            assert_eq!(output.exit_code, Some(0));
        }

        /// `[false, echo should_not_run]` → stops at `false`, returns NonZeroExit.
        ///
        /// The critical assertion: the second step ("echo should_not_run") must
        /// NOT have run. We verify this by checking that the output does NOT
        /// contain "should_not_run", and that the error is `NonZeroExit`.
        #[test]
        fn test_sequence_stops_on_first_failure() {
            let plan = CommandPlan::sequence(vec![
                ExecStep::new("false", [] as [&str; 0]),
                ExecStep::new("echo", ["should_not_run"]),
            ]);
            let result = execute(&plan);
            match result {
                Err(ExecError::NonZeroExit { code, stderr }) => {
                    // `false` exits with code 1 on POSIX.
                    assert_eq!(code, Some(1));
                    // The "echo should_not_run" step must not have produced output
                    // that ended up in the error value.
                    assert!(
                        !stderr.contains("should_not_run"),
                        "second step should not have run, but stderr contains 'should_not_run': {stderr:?}"
                    );
                }
                other => panic!("expected NonZeroExit, got {other:?}"),
            }
        }

        /// Three-step sequence where the middle step fails.
        #[test]
        fn test_sequence_stops_at_middle_failure() {
            let plan = CommandPlan::sequence(vec![
                ExecStep::new("true", [] as [&str; 0]),
                ExecStep::new("false", [] as [&str; 0]),
                ExecStep::new("echo", ["third_should_not_run"]),
            ]);
            let result = execute(&plan);
            assert!(
                matches!(result, Err(ExecError::NonZeroExit { .. })),
                "expected NonZeroExit, got {result:?}"
            );
        }

        // ── Constructor smoke tests ───────────────────────────────────────────

        #[test]
        fn test_exec_step_new() {
            let step = ExecStep::new("sort", ["-r"]);
            assert_eq!(step.program, "sort");
            assert_eq!(step.args, vec!["-r"]);
        }

        #[test]
        fn test_command_plan_exec_constructor() {
            let plan = CommandPlan::exec("echo", ["hi"]);
            assert!(matches!(plan, CommandPlan::Exec(_)));
        }

        #[test]
        fn test_command_plan_pipeline_constructor() {
            let plan = CommandPlan::pipeline(vec![ExecStep::new("echo", ["a"])]);
            assert!(matches!(plan, CommandPlan::Pipeline(_)));
        }

        #[test]
        fn test_command_plan_sequence_constructor() {
            let plan = CommandPlan::sequence(vec![ExecStep::new("true", [] as [&str; 0])]);
            assert!(matches!(plan, CommandPlan::Sequence(_)));
        }
    }
}
