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
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Maximum number of bytes retained from an intermediate stage's stderr.
///
/// The drain thread always reads to EOF (so no pipe ever blocks), but only the
/// first `MAX_STAGE_STDERR` bytes are stored.
const MAX_STAGE_STDERR: usize = 8 * 1024;

/// Read `reader` to EOF, retaining at most `cap` bytes but **consuming all
/// input** (so a writer never blocks on a full pipe).
///
/// Returns the retained (bounded) bytes.  On read error, returns whatever
/// was captured so far.
///
/// ```rust
/// use std::io::Cursor;
/// // Input smaller than cap → full data returned.
/// let data = b"hello".to_vec();
/// let buf = Cursor::new(data.clone());
/// // (access via crate internals in doc-test is restricted; see unit tests)
/// let _ = buf; // illustrative only
/// ```
fn drain_bounded<R: Read>(mut reader: R, cap: usize) -> Vec<u8> {
    let mut retained = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match reader.read(&mut tmp) {
            Ok(0) => break, // EOF
            Ok(n) => {
                if retained.len() < cap {
                    let space = cap - retained.len();
                    let to_store = n.min(space);
                    retained.extend_from_slice(&tmp[..to_store]);
                }
                // Whether or not we stored bytes, we keep reading to drain.
            }
            Err(_) => break, // I/O error — return what we have
        }
    }
    retained
}

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

/// Controls for a single execution: an optional wall-clock timeout and a
/// cooperative cancellation flag (e.g. wired to Ctrl-C by the CLI).
///
/// Passing `&ExecControl::default()` to [`execute_controlled`] is identical in
/// behaviour to calling [`execute`] — the no-control fast path is taken.
#[derive(Clone)]
pub struct ExecControl {
    /// Maximum wall-clock time to allow the execution to run. `None` means no limit.
    pub timeout: Option<Duration>,
    /// Cooperative cancellation flag. Set to `true` from another thread (e.g. a
    /// Ctrl-C handler) to request cancellation. The executor checks this on each
    /// poll tick and returns [`ExecError::Cancelled`] when it is set.
    pub cancel: Arc<AtomicBool>,
}

impl Default for ExecControl {
    fn default() -> Self {
        Self {
            timeout: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Errors produced by [`execute`] and [`execute_controlled`].
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
    /// The execution wall-clock deadline was exceeded. All spawned processes were
    /// killed and reaped before this error was returned.
    TimedOut,
    /// The execution was cancelled via [`ExecControl::cancel`]. All spawned
    /// processes were killed and reaped before this error was returned.
    Cancelled,
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
            ExecError::TimedOut => write!(f, "execution timed out"),
            ExecError::Cancelled => write!(f, "execution was cancelled"),
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

/// Returns `true` if `status` indicates the process was terminated by SIGPIPE
/// (signal 13).
///
/// Used in [`execute_pipeline`] to tolerate upstream stages that are killed by
/// SIGPIPE when a downstream stage (e.g. `head`) closes its stdin early — a
/// normal Unix truncating-pipeline behavior.
#[cfg(unix)]
fn terminated_by_sigpipe(status: &std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt;
    status.signal() == Some(13) // SIGPIPE
}

#[cfg(not(unix))]
fn terminated_by_sigpipe(_status: &std::process::ExitStatus) -> bool {
    false
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
    execute_controlled(plan, &ExecControl::default())
}

/// Execute a [`CommandPlan`] with optional timeout and cooperative cancellation.
///
/// # Fast path (no control active)
///
/// When `control.timeout` is `None` **and** `control.cancel` is not already set,
/// this function delegates directly to the same blocking implementation paths used
/// by [`execute`]. The behaviour is byte-identical to `execute(plan)`.
///
/// # Poll path (timeout or cancel active)
///
/// When a timeout is set or the cancel flag could plausibly be used, a poll-based
/// path is taken:
///
/// - Processes are spawned the same way (no shell; `RequiresShell` still denied).
/// - stdout and stderr are drained by background threads so polling never deadlocks
///   on a full pipe.
/// - The executor polls with [`std::process::Child::try_wait`] on a 20 ms interval.
///   On each tick it checks: (a) whether the cancel flag is set → kills all
///   children, joins drain threads, returns [`ExecError::Cancelled`]; (b) whether
///   the deadline has been exceeded → same cleanup, returns [`ExecError::TimedOut`].
/// - On normal completion, output is collected and the same exit-status rules as
///   the blocking path are applied (non-zero exit → [`ExecError::NonZeroExit`];
///   SIGPIPE on upstream pipeline stages tolerated).
/// - Cleanup always uses `kill_and_reap` / `abort_pipeline` — no process is
///   ever left running after this function returns.
///
/// # Sequence time tracking
///
/// For [`CommandPlan::Sequence`] with a timeout, the remaining deadline is passed
/// to each step's poll loop. Cancellation is also checked between steps.
pub fn execute_controlled(
    plan: &CommandPlan,
    control: &ExecControl,
) -> Result<ExecOutput, ExecError> {
    // Fast path: no timeout AND the cancel arc is exclusively owned by this
    // ExecControl (strong_count == 1 means no external thread can set it) AND
    // not already set → delegate to the unchanged blocking paths.
    //
    // The strong_count check is the key: `execute(&plan)` creates a fresh
    // `ExecControl::default()` whose Arc has count 1.  A caller that clones the
    // Arc to wire up a Ctrl-C handler will have count >= 2, so we correctly take
    // the poll path.
    let cancel_is_unshared = Arc::strong_count(&control.cancel) == 1;
    if control.timeout.is_none() && cancel_is_unshared && !control.cancel.load(Ordering::Relaxed) {
        return match plan {
            CommandPlan::Exec(step) => execute_step(step),
            CommandPlan::Pipeline(steps) => execute_pipeline(steps),
            CommandPlan::Sequence(steps) => execute_sequence(steps),
            CommandPlan::RequiresShell { .. } => Err(ExecError::ShellNotPermitted),
        };
    }

    // Poll path: a timeout is set or the cancel flag is already set.
    match plan {
        CommandPlan::RequiresShell { .. } => Err(ExecError::ShellNotPermitted),
        CommandPlan::Exec(step) => {
            let deadline = control.timeout.map(|d| Instant::now() + d);
            execute_step_controlled(step, deadline, &control.cancel)
        }
        CommandPlan::Pipeline(steps) => {
            let deadline = control.timeout.map(|d| Instant::now() + d);
            execute_pipeline_controlled(steps, deadline, &control.cancel)
        }
        CommandPlan::Sequence(steps) => {
            let deadline = control.timeout.map(|d| Instant::now() + d);
            execute_sequence_controlled(steps, deadline, &control.cancel)
        }
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

/// Kill and wait every child in `children`, ignoring errors (best-effort cleanup).
fn kill_and_reap(children: &mut [std::process::Child]) {
    for child in children.iter_mut() {
        // Best-effort: ignore kill errors (process may have already exited).
        let _ = child.kill();
    }
    for child in children.iter_mut() {
        let _ = child.wait();
    }
}

/// Abort a partially-spawned pipeline: kill+reap all children FIRST (closing
/// their stderr so the drain threads hit EOF), THEN join the drain threads.
///
/// Doing it in this order avoids a hang where a join waits on a drain thread
/// that is blocked reading a still-running child's stderr.
fn abort_pipeline(
    mut children: Vec<std::process::Child>,
    stderr_threads: Vec<thread::JoinHandle<Vec<u8>>>,
) {
    kill_and_reap(&mut children);
    for handle in stderr_threads {
        let _ = handle.join();
    }
}

/// Wire `steps[i].stdout → steps[i+1].stdin` using OS pipes; return the last
/// stage's captured output.
///
/// # Lifecycle
///
/// - Every spawned child handle is kept until all stages have been spawned and
///   the last stage has finished, then each intermediate child is waited/reaped
///   in order. This ensures no zombie processes are left behind and that all
///   exit statuses are checked.
///
/// - Intermediate stages use `Stdio::piped()` for stderr. Immediately after
///   each spawn the pipe is handed to a background thread that runs
///   [`drain_bounded`]. The thread reads the pipe to EOF (so no producer ever
///   blocks on a full buffer), retaining up to [`MAX_STAGE_STDERR`] bytes.
///   The `JoinHandle<Vec<u8>>` is stored in a parallel vec (`stderr_threads`),
///   aligned with `intermediate_children` by index.
///
/// - If spawning stage `i` fails, all already-spawned children are killed and
///   waited before the error is returned, preventing leaks.  All in-flight
///   stderr drain threads are joined before returning.
///
/// - If **any** stage exits non-zero (and is not tolerated — see below), the
///   function returns [`ExecError::NonZeroExit`]. The FIRST failing intermediate
///   stage's own captured stderr is included; if that join fails, a fallback
///   message naming the stage index is used. The last stage's captured stderr is
///   used when no intermediate stage failed.
///
/// - **SIGPIPE tolerance for upstream stages**: An upstream (non-last) stage
///   terminated by SIGPIPE — e.g. because a downstream stage like `head` closed
///   the pipe after reading enough — is treated as success. Only a genuine
///   non-zero exit code or a non-SIGPIPE termination signal in an upstream stage
///   fails the pipeline. The last stage is always checked strictly (its stdout is
///   fully drained by us, so it will not be SIGPIPE-killed; a real failure there
///   must still surface).
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

    // ── Phase 1: spawn all stages ─────────────────────────────────────────────
    //
    // We keep every child handle so we can wait/reap them all after the last
    // stage finishes. `intermediate_children` accumulates children for indices
    // 0..n-2; `stderr_threads` holds the corresponding drain threads (same
    // index alignment).

    // Spawn the first process. stderr is piped and immediately handed to a
    // drain thread so the pipe never fills up.
    let first = &steps[0];
    let mut prev_child = Command::new(&first.program)
        .args(&first.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| map_spawn_error(&first.program, e))?;

    // Take the first child's stderr pipe and start draining it.
    let first_stderr_thread: thread::JoinHandle<Vec<u8>> = {
        // prev_child.stderr is Some because we configured Stdio::piped().
        // If somehow it isn't, we fall back gracefully via drain_bounded on an
        // empty reader.
        let pipe = prev_child.stderr.take();
        thread::spawn(move || match pipe {
            Some(p) => drain_bounded(p, MAX_STAGE_STDERR),
            None => Vec::new(),
        })
    };

    // Accumulate all intermediate children and their stderr drain threads.
    let mut intermediate_children: Vec<std::process::Child> = Vec::new();
    let mut stderr_threads: Vec<thread::JoinHandle<Vec<u8>>> = Vec::new();

    // We'll push the first child/thread when we move it into intermediate_children
    // (either below in the loop, or after the loop when we wire the last stage).

    let mut prev_stderr_thread: thread::JoinHandle<Vec<u8>> = first_stderr_thread;

    // Spawn intermediate stages (indices 1..n-2), each reading from the
    // previous child's stdout.
    for step in &steps[1..steps.len() - 1] {
        let stdin_pipe = match prev_child.stdout.take() {
            Some(pipe) => Stdio::from(pipe),
            None => {
                // Cannot take stdout — kill everything already spawned.
                intermediate_children.push(prev_child);
                stderr_threads.push(prev_stderr_thread);
                abort_pipeline(intermediate_children, stderr_threads);
                return Err(ExecError::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "could not take stdout from child",
                )));
            }
        };

        let child = Command::new(&step.program)
            .args(&step.args)
            .stdin(stdin_pipe)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        match child {
            Ok(mut c) => {
                // Start draining the new child's stderr immediately.
                let pipe = c.stderr.take();
                let drain_handle = thread::spawn(move || match pipe {
                    Some(p) => drain_bounded(p, MAX_STAGE_STDERR),
                    None => Vec::new(),
                });
                // Commit prev_child and its thread to the intermediate vecs.
                intermediate_children.push(prev_child);
                stderr_threads.push(prev_stderr_thread);
                prev_child = c;
                prev_stderr_thread = drain_handle;
            }
            Err(e) => {
                // Spawn failed: reap all already-spawned children before returning.
                intermediate_children.push(prev_child);
                stderr_threads.push(prev_stderr_thread);
                abort_pipeline(intermediate_children, stderr_threads);
                return Err(map_spawn_error(&step.program, e));
            }
        }
    }

    // `steps` is guaranteed to have len >= 2 here (checked above), so
    // `steps.last()` is always `Some`.
    let last = match steps.last() {
        Some(step) => step,
        None => {
            intermediate_children.push(prev_child);
            stderr_threads.push(prev_stderr_thread);
            abort_pipeline(intermediate_children, stderr_threads);
            return Err(ExecError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pipeline has no steps",
            )));
        }
    };

    let stdin_pipe = match prev_child.stdout.take() {
        Some(pipe) => Stdio::from(pipe),
        None => {
            intermediate_children.push(prev_child);
            stderr_threads.push(prev_stderr_thread);
            abort_pipeline(intermediate_children, stderr_threads);
            return Err(ExecError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "could not take stdout from child",
            )));
        }
    };
    // Push the second-to-last intermediate child/thread now that stdout is taken.
    intermediate_children.push(prev_child);
    stderr_threads.push(prev_stderr_thread);

    // Spawn the last stage with both stdout and stderr captured for the caller.
    let last_child = Command::new(&last.program)
        .args(&last.args)
        .stdin(stdin_pipe)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let last_child = match last_child {
        Ok(c) => c,
        Err(e) => {
            abort_pipeline(intermediate_children, stderr_threads);
            return Err(map_spawn_error(&last.program, e));
        }
    };

    // ── Phase 2: wait for the last stage, then reap intermediates ─────────────
    //
    // We wait on the last child first (collecting its stdout/stderr), then wait
    // on each intermediate child in order to reap them and check exit codes.
    // The stderr drain threads run concurrently with all of this.

    let last_output = match last_child.wait_with_output() {
        Ok(output) => output,
        Err(e) => {
            // `last_child` was consumed by `wait_with_output`, so only
            // `intermediate_children` and `stderr_threads` need cleanup.
            // Route through `abort_pipeline` for consistent kill/reap order:
            // kills children first (closing their stderr pipes so drain threads
            // reach EOF), then joins the drain threads.
            abort_pipeline(intermediate_children, stderr_threads);
            return Err(ExecError::Io(e));
        }
    };

    let last_exit_code = last_output.status.code();
    let last_stdout = String::from_utf8_lossy(&last_output.stdout).into_owned();
    let last_stderr = String::from_utf8_lossy(&last_output.stderr).into_owned();

    // ── Phase 3: reap intermediate children, check each exit status ───────────
    //
    // Wait on each intermediate child (in spawn order) and collect any failure.
    // We use the FIRST non-zero exit we encounter as the authoritative error.
    let mut first_failure: Option<ExecError> = None;
    let mut first_failing_idx: Option<usize> = None;

    for (idx, child) in intermediate_children.iter_mut().enumerate() {
        match child.wait() {
            Ok(status) if status.success() => {}
            // An intermediate stage killed by SIGPIPE is tolerated — this is the
            // normal outcome when a downstream stage (e.g. `head`) closes its
            // stdin after reading enough data, causing the upstream writer to
            // receive SIGPIPE on its next write.  It is not a genuine failure.
            Ok(status) if terminated_by_sigpipe(&status) => {}
            Ok(status) => {
                if first_failure.is_none() {
                    first_failing_idx = Some(idx);
                    // Placeholder; we'll fill in stderr after joining threads.
                    first_failure = Some(ExecError::NonZeroExit {
                        code: status.code(),
                        stderr: String::new(), // filled below
                    });
                }
            }
            Err(_) => {
                // wait() itself failed (rare); record only if no earlier failure.
                if first_failure.is_none() {
                    first_failure = Some(ExecError::Io(io::Error::other(format!(
                        "failed to wait on pipeline stage {idx}"
                    ))));
                }
            }
        }
    }

    // ── Phase 4: join ALL stderr drain threads ────────────────────────────────
    //
    // Always join every thread before returning so none outlive this call.
    // Collect results; we need the failing stage's bytes (if any).
    let stderr_captures: Vec<Vec<u8>> = stderr_threads
        .into_iter()
        .map(|h| h.join().unwrap_or_default())
        .collect();

    // Now attach the right stderr to the failure (if any).
    if let Some(err) = first_failure {
        let err = match (err, first_failing_idx) {
            (ExecError::NonZeroExit { code, .. }, Some(idx)) => {
                let captured = stderr_captures
                    .get(idx)
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                let stderr = if !captured.is_empty() {
                    captured
                } else if !last_stderr.is_empty() {
                    last_stderr
                } else {
                    format!("pipeline stage {idx} exited with non-zero status")
                };
                ExecError::NonZeroExit { code, stderr }
            }
            (other, _) => other,
        };
        return Err(err);
    }

    // Now check the last stage.
    if last_output.status.success() {
        Ok(ExecOutput {
            stdout: last_stdout,
            stderr: last_stderr,
            exit_code: last_exit_code,
        })
    } else {
        Err(ExecError::NonZeroExit {
            code: last_exit_code,
            stderr: last_stderr,
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

// ── Poll-based controlled execution ──────────────────────────────────────────

/// Poll interval for the controlled execution paths.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Check cancel and deadline on each poll tick. Returns `Some(err)` if either
/// condition is triggered, or `None` to continue.
fn check_control(cancel: &AtomicBool, deadline: Option<Instant>) -> Option<ExecError> {
    if cancel.load(Ordering::Relaxed) {
        return Some(ExecError::Cancelled);
    }
    if let Some(dl) = deadline {
        if Instant::now() >= dl {
            return Some(ExecError::TimedOut);
        }
    }
    None
}

/// Read `reader` to EOF, collecting all bytes (unbounded). Used for the single-step
/// stdout drain where we want the full output, not just the first `cap` bytes.
fn drain_full<R: Read>(mut reader: R) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match reader.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    buf
}

/// Poll-based single-step executor. Spawns the process, drains stdout+stderr via
/// threads, and polls with `try_wait()` until completion, timeout, or cancellation.
fn execute_step_controlled(
    step: &ExecStep,
    deadline: Option<Instant>,
    cancel: &AtomicBool,
) -> Result<ExecOutput, ExecError> {
    // Bail immediately if already cancelled or past deadline.
    if let Some(err) = check_control(cancel, deadline) {
        return Err(err);
    }

    let mut child = Command::new(&step.program)
        .args(&step.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| map_spawn_error(&step.program, e))?;

    // Drain stdout and stderr via threads so polling never deadlocks on a full pipe.
    let stdout_pipe = child.stdout.take();
    let stdout_thread: thread::JoinHandle<Vec<u8>> = thread::spawn(move || match stdout_pipe {
        Some(p) => drain_full(p),
        None => Vec::new(),
    });

    let stderr_pipe = child.stderr.take();
    let stderr_thread: thread::JoinHandle<Vec<u8>> = thread::spawn(move || match stderr_pipe {
        Some(p) => drain_bounded(p, MAX_STAGE_STDERR),
        None => Vec::new(),
    });

    // Poll loop.
    loop {
        if let Some(err) = check_control(cancel, deadline) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(err);
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout_bytes = stdout_thread.join().unwrap_or_default();
                let stderr_bytes = stderr_thread.join().unwrap_or_default();
                let exit_code = status.code();
                let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
                let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();

                return if status.success() {
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
                };
            }
            Ok(None) => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(ExecError::Io(e));
            }
        }
    }
}

/// Poll-based pipeline executor. Mirrors `execute_pipeline` but polls `try_wait`
/// on the last stage and checks cancel/deadline on each tick.
///
/// All intermediate children and their drain threads are tracked throughout;
/// on timeout or cancellation `abort_pipeline` kills+reaps everyone before
/// returning, preventing orphaned processes.
fn execute_pipeline_controlled(
    steps: &[ExecStep],
    deadline: Option<Instant>,
    cancel: &AtomicBool,
) -> Result<ExecOutput, ExecError> {
    if steps.is_empty() {
        return Err(ExecError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Pipeline must have at least one step",
        )));
    }

    if steps.len() == 1 {
        return execute_step_controlled(&steps[0], deadline, cancel);
    }

    if let Some(err) = check_control(cancel, deadline) {
        return Err(err);
    }

    // ── Phase 1: spawn all stages (same wiring as execute_pipeline) ────────────

    let first = &steps[0];
    let mut prev_child = Command::new(&first.program)
        .args(&first.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| map_spawn_error(&first.program, e))?;

    let first_stderr_thread: thread::JoinHandle<Vec<u8>> = {
        let pipe = prev_child.stderr.take();
        thread::spawn(move || match pipe {
            Some(p) => drain_bounded(p, MAX_STAGE_STDERR),
            None => Vec::new(),
        })
    };

    let mut intermediate_children: Vec<std::process::Child> = Vec::new();
    let mut stderr_threads: Vec<thread::JoinHandle<Vec<u8>>> = Vec::new();
    let mut prev_stderr_thread: thread::JoinHandle<Vec<u8>> = first_stderr_thread;

    for step in &steps[1..steps.len() - 1] {
        let stdin_pipe = match prev_child.stdout.take() {
            Some(pipe) => Stdio::from(pipe),
            None => {
                intermediate_children.push(prev_child);
                stderr_threads.push(prev_stderr_thread);
                abort_pipeline(intermediate_children, stderr_threads);
                return Err(ExecError::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "could not take stdout from child",
                )));
            }
        };

        match Command::new(&step.program)
            .args(&step.args)
            .stdin(stdin_pipe)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(mut c) => {
                let pipe = c.stderr.take();
                let drain_handle = thread::spawn(move || match pipe {
                    Some(p) => drain_bounded(p, MAX_STAGE_STDERR),
                    None => Vec::new(),
                });
                intermediate_children.push(prev_child);
                stderr_threads.push(prev_stderr_thread);
                prev_child = c;
                prev_stderr_thread = drain_handle;
            }
            Err(e) => {
                intermediate_children.push(prev_child);
                stderr_threads.push(prev_stderr_thread);
                abort_pipeline(intermediate_children, stderr_threads);
                return Err(map_spawn_error(&step.program, e));
            }
        }
    }

    let last = match steps.last() {
        Some(step) => step,
        None => {
            intermediate_children.push(prev_child);
            stderr_threads.push(prev_stderr_thread);
            abort_pipeline(intermediate_children, stderr_threads);
            return Err(ExecError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pipeline has no steps",
            )));
        }
    };

    let stdin_pipe = match prev_child.stdout.take() {
        Some(pipe) => Stdio::from(pipe),
        None => {
            intermediate_children.push(prev_child);
            stderr_threads.push(prev_stderr_thread);
            abort_pipeline(intermediate_children, stderr_threads);
            return Err(ExecError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "could not take stdout from child",
            )));
        }
    };
    intermediate_children.push(prev_child);
    stderr_threads.push(prev_stderr_thread);

    // Spawn the last stage with stdout and stderr drained by threads.
    let mut last_child = match Command::new(&last.program)
        .args(&last.args)
        .stdin(stdin_pipe)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            abort_pipeline(intermediate_children, stderr_threads);
            return Err(map_spawn_error(&last.program, e));
        }
    };

    // Drain last stage's stdout (full capture) and stderr via threads.
    let last_stdout_pipe = last_child.stdout.take();
    let last_stdout_thread: thread::JoinHandle<Vec<u8>> =
        thread::spawn(move || match last_stdout_pipe {
            Some(p) => drain_full(p),
            None => Vec::new(),
        });
    let last_stderr_pipe = last_child.stderr.take();
    let last_stderr_thread: thread::JoinHandle<Vec<u8>> =
        thread::spawn(move || match last_stderr_pipe {
            Some(p) => drain_bounded(p, MAX_STAGE_STDERR),
            None => Vec::new(),
        });

    // ── Phase 2: poll the last stage, checking cancel/deadline on each tick ────

    let last_status = loop {
        if let Some(err) = check_control(cancel, deadline) {
            // Kill last child + all intermediates, join all threads, then return.
            let _ = last_child.kill();
            let _ = last_child.wait();
            abort_pipeline(intermediate_children, stderr_threads);
            let _ = last_stdout_thread.join();
            let _ = last_stderr_thread.join();
            return Err(err);
        }

        match last_child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                let _ = last_child.kill();
                let _ = last_child.wait();
                abort_pipeline(intermediate_children, stderr_threads);
                let _ = last_stdout_thread.join();
                let _ = last_stderr_thread.join();
                return Err(ExecError::Io(e));
            }
        }
    };

    // ── Phase 3: reap intermediate children by polling, checking cancel/deadline ──
    //
    // After the last stage exits, intermediates may still be running (e.g. in
    // `sleep 10 | true`, `sleep` keeps running after `true` exits).  We must
    // NOT block with `child.wait()` here because that would ignore the deadline
    // and cancel flag — a 200ms timeout would not fire until `sleep` finishes.
    //
    // Instead we poll each intermediate with `try_wait()`, sleeping POLL_INTERVAL
    // between rounds, and check cancel/deadline on every tick.  On abort we kill
    // all remaining children, join drain threads, and return the control error.

    let last_exit_code = last_status.code();
    let last_stdout_bytes = last_stdout_thread.join().unwrap_or_default();
    let last_stderr_bytes = last_stderr_thread.join().unwrap_or_default();
    let last_stdout = String::from_utf8_lossy(&last_stdout_bytes).into_owned();
    let last_stderr = String::from_utf8_lossy(&last_stderr_bytes).into_owned();

    // Track which intermediates have already been reaped and their exit status.
    // `None` = not yet exited; `Some(result)` = exited with this outcome.
    let n = intermediate_children.len();
    let mut intermediate_results: Vec<Option<Result<std::process::ExitStatus, ()>>> = vec![None; n];

    // Poll until every intermediate is reaped or we hit a control condition.
    loop {
        // Check cancel/deadline before each round of polling.
        if let Some(ctrl_err) = check_control(cancel, deadline) {
            // Kill + reap only intermediates that have NOT already exited;
            // already-reaped children (intermediate_results[idx] == Some) were
            // collected via try_wait() and need no further handling.
            for (idx, child) in intermediate_children.iter_mut().enumerate() {
                if intermediate_results[idx].is_none() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
            for handle in stderr_threads {
                let _ = handle.join();
            }
            return Err(ctrl_err);
        }

        let mut all_done = true;
        for (idx, child) in intermediate_children.iter_mut().enumerate() {
            if intermediate_results[idx].is_some() {
                // Already reaped.
                continue;
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    intermediate_results[idx] = Some(Ok(status));
                }
                Ok(None) => {
                    // Still running.
                    all_done = false;
                }
                Err(_) => {
                    // try_wait itself failed; record as an error result.
                    intermediate_results[idx] = Some(Err(()));
                }
            }
        }

        if all_done {
            break;
        }

        thread::sleep(POLL_INTERVAL);
    }

    // All intermediates are now reaped.  Collect results into first_failure.
    let mut first_failure: Option<ExecError> = None;
    let mut first_failing_idx: Option<usize> = None;

    for (idx, result) in intermediate_results.into_iter().enumerate() {
        match result {
            Some(Ok(status)) if status.success() => {}
            Some(Ok(status)) if terminated_by_sigpipe(&status) => {}
            Some(Ok(status)) => {
                if first_failure.is_none() {
                    first_failing_idx = Some(idx);
                    first_failure = Some(ExecError::NonZeroExit {
                        code: status.code(),
                        stderr: String::new(),
                    });
                }
            }
            Some(Err(())) | None => {
                if first_failure.is_none() {
                    first_failure = Some(ExecError::Io(io::Error::other(format!(
                        "failed to wait on pipeline stage {idx}"
                    ))));
                }
            }
        }
    }

    let stderr_captures: Vec<Vec<u8>> = stderr_threads
        .into_iter()
        .map(|h| h.join().unwrap_or_default())
        .collect();

    if let Some(err) = first_failure {
        let err = match (err, first_failing_idx) {
            (ExecError::NonZeroExit { code, .. }, Some(idx)) => {
                let captured = stderr_captures
                    .get(idx)
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                let stderr = if !captured.is_empty() {
                    captured
                } else if !last_stderr.is_empty() {
                    last_stderr
                } else {
                    format!("pipeline stage {idx} exited with non-zero status")
                };
                ExecError::NonZeroExit { code, stderr }
            }
            (other, _) => other,
        };
        return Err(err);
    }

    if last_status.success() {
        Ok(ExecOutput {
            stdout: last_stdout,
            stderr: last_stderr,
            exit_code: last_exit_code,
        })
    } else {
        Err(ExecError::NonZeroExit {
            code: last_exit_code,
            stderr: last_stderr,
        })
    }
}

/// Poll-based sequence executor. Runs each step via `execute_step_controlled`,
/// tracking remaining time across steps and checking cancellation between steps.
fn execute_sequence_controlled(
    steps: &[ExecStep],
    deadline: Option<Instant>,
    cancel: &AtomicBool,
) -> Result<ExecOutput, ExecError> {
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
        // Check cancel/deadline before each step (also checked inside the step).
        if let Some(err) = check_control(cancel, deadline) {
            return Err(err);
        }
        // The deadline is passed through unchanged; each step polls against the
        // same wall-clock deadline, so remaining time naturally shrinks.
        last_output = execute_step_controlled(step, deadline, cancel)?;
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

        /// `false | true` → upstream failure detected; must NOT report success.
        ///
        /// A correct pipeline waits and checks all stages. `true` exits 0 but
        /// `false` exits 1, so the pipeline must return `NonZeroExit`.
        #[test]
        fn test_pipeline_upstream_false_is_detected() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("false", [] as [&str; 0]),
                ExecStep::new("true", [] as [&str; 0]),
            ]);
            let result = execute(&plan);
            assert!(
                matches!(result, Err(ExecError::NonZeroExit { .. })),
                "expected NonZeroExit from upstream `false`, got {result:?}"
            );
        }

        /// `true | false` → last stage fails; must return `NonZeroExit`.
        #[test]
        fn test_pipeline_last_stage_false_is_detected() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("true", [] as [&str; 0]),
                ExecStep::new("false", [] as [&str; 0]),
            ]);
            let result = execute(&plan);
            assert!(
                matches!(result, Err(ExecError::NonZeroExit { .. })),
                "expected NonZeroExit from last-stage `false`, got {result:?}"
            );
        }

        /// `echo hi | cat` → success, stdout "hi\n".
        #[test]
        fn test_pipeline_echo_hi_cat() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("echo", ["hi"]),
                ExecStep::new("cat", [] as [&str; 0]),
            ]);
            let output = execute(&plan).expect("echo hi | cat should succeed");
            assert_eq!(output.stdout, "hi\n");
            assert_eq!(output.exit_code, Some(0));
        }

        /// `printf "c\na\nb\n" | sort | head -n 2` → "a\nb\n" (3-stage happy path).
        #[test]
        fn test_pipeline_three_stage_sort_head() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("printf", ["c\na\nb\n"]),
                ExecStep::new("sort", [] as [&str; 0]),
                ExecStep::new("head", ["-n", "2"]),
            ]);
            let output = execute(&plan).expect("3-stage pipeline should succeed");
            assert_eq!(output.stdout, "a\nb\n");
            assert_eq!(output.exit_code, Some(0));
        }

        /// `echo hi | <bogus_program> | cat` → `ProgramNotFound`, no panic/hang.
        ///
        /// Verifies that a spawn failure mid-pipeline cleans up already-spawned
        /// children instead of leaking them.
        #[test]
        fn test_pipeline_bad_intermediate_program() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("echo", ["hi"]),
                ExecStep::new("__enshell_nonexistent_xyz_middle__", [] as [&str; 0]),
                ExecStep::new("cat", [] as [&str; 0]),
            ]);
            let result = execute(&plan);
            assert!(
                matches!(result, Err(ExecError::ProgramNotFound(_))),
                "expected ProgramNotFound for bad intermediate program, got {result:?}"
            );
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

        // ── Pipeline upstream stderr capture ──────────────────────────────────

        /// `ls /nonexistent | cat` — the upstream `ls` exits non-zero and should
        /// produce a non-empty stderr message captured by the drain thread.
        #[test]
        fn test_pipeline_upstream_stderr_is_captured() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("ls", ["/nonexistent_enshell_xyz"]),
                ExecStep::new("cat", [] as [&str; 0]),
            ]);
            let result = execute(&plan);
            match result {
                Err(ExecError::NonZeroExit { stderr, .. }) => {
                    assert!(
                        !stderr.is_empty(),
                        "expected non-empty stderr from failing `ls`, got empty string"
                    );
                }
                other => panic!(
                    "expected NonZeroExit from upstream `ls /nonexistent_enshell_xyz`, got {other:?}"
                ),
            }
        }

        /// `sleep 5 | __missing__ | cat` — spawn failure mid-pipeline must return
        /// promptly with `ProgramNotFound`, NOT hang.
        ///
        /// Regression test for the cleanup-order bug: if children are killed AFTER
        /// drain threads are joined, the join blocks on `sleep 5`'s open stderr pipe
        /// (which never reaches EOF until the child is killed), causing a deadlock.
        ///
        /// The correct fix (`abort_pipeline`) kills+reaps children first, which
        /// closes their stderr pipes and causes drain threads to see EOF promptly.
        /// With the fix the call completes in milliseconds; the 5s timeout guards
        /// against a regression hanging CI.
        #[test]
        fn test_pipeline_spawn_failure_does_not_hang() {
            use std::sync::mpsc;
            use std::time::Duration;

            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("sleep", ["5"]),
                ExecStep::new("__enshell_missing_program__", [] as [&str; 0]),
                ExecStep::new("cat", [] as [&str; 0]),
            ]);

            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(execute(&plan));
            });

            let result = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("execute() hung on pipeline spawn failure — cleanup-order regression");

            assert!(
                matches!(result, Err(ExecError::ProgramNotFound(_))),
                "expected ProgramNotFound, got {result:?}"
            );
        }

        // ── SIGPIPE tolerance tests ───────────────────────────────────────────

        /// `yes | head -n 1` — `yes` produces infinite output; `head` reads one
        /// line then closes its stdin, sending SIGPIPE to `yes`.  The upstream
        /// `yes` stage is SIGPIPE-killed but that must be tolerated (it is the
        /// normal truncating-pipeline behavior).  The pipeline must succeed and
        /// return "y\n".
        ///
        /// This test also verifies promptness: because `yes` is an infinite
        /// producer, failure to tolerate SIGPIPE would cause `head` to succeed
        /// while the executor waits on `yes` forever.  The 5-second timeout
        /// guards against that regression.
        #[test]
        fn test_pipeline_yes_head_tolerates_sigpipe() {
            use std::sync::mpsc;
            use std::time::Duration;

            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("yes", [] as [&str; 0]),
                ExecStep::new("head", ["-n", "1"]),
            ]);

            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(execute(&plan));
            });

            let result = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("execute() hung on yes|head — SIGPIPE not tolerated on upstream stage");

            let output = result.expect("yes | head -n 1 should succeed");
            assert_eq!(
                output.stdout, "y\n",
                "unexpected stdout: {:?}",
                output.stdout
            );
        }

        /// `false | true` — `false` exits with code 1 (NOT SIGPIPE).  The upstream
        /// failure must still be detected and return `NonZeroExit`.
        ///
        /// Regression guard: SIGPIPE tolerance must not swallow genuine failures.
        #[test]
        fn test_pipeline_false_true_still_fails() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("false", [] as [&str; 0]),
                ExecStep::new("true", [] as [&str; 0]),
            ]);
            let result = execute(&plan);
            assert!(
                matches!(result, Err(ExecError::NonZeroExit { .. })),
                "expected NonZeroExit from upstream `false` (exit code 1, not SIGPIPE), got {result:?}"
            );
        }

        /// `ls /nonexistent_enshell_xyz | cat` — `ls` exits non-zero with a real
        /// error message on stderr.  Must still return `NonZeroExit` with non-empty
        /// captured stderr.
        ///
        /// Regression guard: SIGPIPE tolerance must not swallow genuine failures,
        /// and captured stderr must reach the caller.
        #[test]
        fn test_pipeline_ls_nonexistent_cat_still_fails_with_stderr() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("ls", ["/nonexistent_enshell_xyz"]),
                ExecStep::new("cat", [] as [&str; 0]),
            ]);
            let result = execute(&plan);
            match result {
                Err(ExecError::NonZeroExit { stderr, .. }) => {
                    assert!(
                        !stderr.is_empty(),
                        "expected non-empty stderr from failing `ls /nonexistent_enshell_xyz`, got empty string"
                    );
                }
                other => panic!(
                    "expected NonZeroExit from `ls /nonexistent_enshell_xyz | cat`, got {other:?}"
                ),
            }
        }
    }

    // ── drain_bounded unit tests (all platforms) ──────────────────────────────

    /// Input larger than cap → exactly `cap` bytes returned, no hang.
    #[test]
    fn test_drain_bounded_larger_than_cap() {
        let cap = 16;
        let data = vec![b'x'; 100 * 1024]; // 100 KB
        let cursor = std::io::Cursor::new(data);
        let result = drain_bounded(cursor, cap);
        assert_eq!(
            result.len(),
            cap,
            "should retain exactly cap bytes when input exceeds cap"
        );
        assert!(result.iter().all(|&b| b == b'x'));
    }

    /// Input smaller than cap → all bytes returned.
    #[test]
    fn test_drain_bounded_smaller_than_cap() {
        let cap = 256;
        let data = b"hello world".to_vec();
        let expected_len = data.len();
        let cursor = std::io::Cursor::new(data.clone());
        let result = drain_bounded(cursor, cap);
        assert_eq!(
            result.len(),
            expected_len,
            "should return full input when smaller than cap"
        );
        assert_eq!(result, data);
    }

    /// Input exactly equal to cap → all bytes returned.
    #[test]
    fn test_drain_bounded_exact_cap() {
        let cap = 8;
        let data = vec![b'a'; cap];
        let cursor = std::io::Cursor::new(data.clone());
        let result = drain_bounded(cursor, cap);
        assert_eq!(result, data);
    }

    /// Empty input → empty result.
    #[test]
    fn test_drain_bounded_empty_input() {
        let cursor = std::io::Cursor::new(vec![]);
        let result = drain_bounded(cursor, 1024);
        assert!(result.is_empty());
    }

    // ── execute_controlled tests (Unix) ──────────────────────────────────────

    #[cfg(unix)]
    mod controlled {
        use super::*;
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        /// Timeout: `sleep 10` with a 200ms timeout → `Err(TimedOut)` returned
        /// well within 2 seconds (not 10 seconds). Verifies the process was killed.
        #[test]
        fn test_controlled_timeout_sleep() {
            let plan = CommandPlan::exec("sleep", ["10"]);
            let control = ExecControl {
                timeout: Some(Duration::from_millis(200)),
                ..ExecControl::default()
            };

            let (tx, rx) = mpsc::channel();
            let start = Instant::now();
            std::thread::spawn(move || {
                let _ = tx.send(execute_controlled(&plan, &control));
            });

            let result = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("execute_controlled hung — timeout did not fire within 5s");

            let elapsed = start.elapsed();
            assert!(
                matches!(result, Err(ExecError::TimedOut)),
                "expected TimedOut, got {result:?}"
            );
            assert!(
                elapsed < Duration::from_secs(2),
                "timeout took too long: {elapsed:?}"
            );
        }

        /// Cancel: a thread sets `cancel` after ~100ms; `sleep 10` → `Err(Cancelled)` promptly.
        #[test]
        fn test_controlled_cancel_sleep() {
            let plan = CommandPlan::exec("sleep", ["10"]);
            let control = ExecControl::default();
            let cancel_flag = Arc::clone(&control.cancel);

            // Trigger cancellation after 100ms.
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                cancel_flag.store(true, Ordering::Relaxed);
            });

            let (tx, rx) = mpsc::channel();
            let start = Instant::now();
            std::thread::spawn(move || {
                let _ = tx.send(execute_controlled(&plan, &control));
            });

            let result = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("execute_controlled hung — cancel did not fire within 5s");

            let elapsed = start.elapsed();
            assert!(
                matches!(result, Err(ExecError::Cancelled)),
                "expected Cancelled, got {result:?}"
            );
            assert!(
                elapsed < Duration::from_secs(2),
                "cancel took too long: {elapsed:?}"
            );
        }

        /// No-timeout: `execute_controlled` with `ExecControl::default()` on a fast
        /// command → `Ok`, output matches `execute`.
        #[test]
        fn test_controlled_no_timeout_echo() {
            let plan = CommandPlan::exec("echo", ["hi"]);
            let controlled_result =
                execute_controlled(&plan, &ExecControl::default()).expect("should succeed");
            let plain_result = execute(&plan).expect("should succeed");
            assert_eq!(controlled_result.stdout, plain_result.stdout);
            assert_eq!(controlled_result.stdout, "hi\n");
        }

        /// Timeout that is NOT exceeded: `echo hi` with a 5s timeout → `Ok "hi\n"`.
        #[test]
        fn test_controlled_timeout_not_exceeded() {
            let plan = CommandPlan::exec("echo", ["hi"]);
            let control = ExecControl {
                timeout: Some(Duration::from_secs(5)),
                ..ExecControl::default()
            };
            let output = execute_controlled(&plan, &control).expect("echo should succeed");
            assert_eq!(output.stdout, "hi\n");
        }

        /// Pipeline timeout: `sleep 10 | cat` with a 200ms timeout → `TimedOut`,
        /// both children killed (returns well under 10s).
        #[test]
        fn test_controlled_pipeline_timeout() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("sleep", ["10"]),
                ExecStep::new("cat", [] as [&str; 0]),
            ]);
            let control = ExecControl {
                timeout: Some(Duration::from_millis(200)),
                ..ExecControl::default()
            };

            let (tx, rx) = mpsc::channel();
            let start = Instant::now();
            std::thread::spawn(move || {
                let _ = tx.send(execute_controlled(&plan, &control));
            });

            let result = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("execute_controlled pipeline hung — timeout did not fire within 5s");

            let elapsed = start.elapsed();
            assert!(
                matches!(result, Err(ExecError::TimedOut)),
                "expected TimedOut from pipeline, got {result:?}"
            );
            assert!(
                elapsed < Duration::from_secs(2),
                "pipeline timeout took too long: {elapsed:?}"
            );
        }

        /// Pipeline timeout with a long-running INTERMEDIATE stage: `sleep 10 | true`
        /// with a 200ms timeout → `Err(TimedOut)` returned promptly (well under 2s).
        ///
        /// This is the specific regression case for the "controlled pipeline ignores
        /// deadline while reaping intermediates" bug: `true` exits immediately (it is
        /// the last stage), but `sleep 10` keeps running as an intermediate.  If the
        /// intermediate is reaped with a blocking `wait()`, the 200ms timeout never
        /// fires until `sleep` finishes ~10s later.
        ///
        /// The fix polls intermediates with `try_wait()` and checks cancel/deadline on
        /// each tick, so the timeout fires promptly and `sleep` is killed+reaped before
        /// this function returns (no orphaned processes).
        #[test]
        fn test_controlled_pipeline_timeout_sleep_intermediate() {
            let plan = CommandPlan::pipeline(vec![
                ExecStep::new("sleep", ["10"]),
                ExecStep::new("true", [] as [&str; 0]),
            ]);
            let control = ExecControl {
                timeout: Some(Duration::from_millis(200)),
                ..ExecControl::default()
            };

            let (tx, rx) = mpsc::channel();
            let start = Instant::now();
            std::thread::spawn(move || {
                let _ = tx.send(execute_controlled(&plan, &control));
            });

            // Guard: if the bug is present the call blocks ~10s; recv_timeout catches it.
            let result = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("execute_controlled hung — intermediate reap did not check deadline");

            let elapsed = start.elapsed();
            assert!(
                matches!(result, Err(ExecError::TimedOut)),
                "expected TimedOut from `sleep 10 | true`, got {result:?}"
            );
            assert!(
                elapsed < Duration::from_secs(2),
                "pipeline intermediate-reap timeout took too long: {elapsed:?}"
            );
        }

        /// RequiresShell is still denied even through execute_controlled with a
        /// timeout set.
        #[test]
        fn test_controlled_requires_shell_still_denied() {
            let plan = CommandPlan::RequiresShell {
                shell: ShellKind::Bash,
                script: "echo hi".to_owned(),
            };
            let control = ExecControl {
                timeout: Some(Duration::from_secs(1)),
                ..ExecControl::default()
            };
            assert!(matches!(
                execute_controlled(&plan, &control),
                Err(ExecError::ShellNotPermitted)
            ));
        }
    }
}
