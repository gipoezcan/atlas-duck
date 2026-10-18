//! `cli_flows` security cases (Task 25): §13 S-01 (a squatter endpoint gets nothing), S-02 (the
//! launched app is not part of the CLI's process tree, session or job), §3.2 (a), §4.7 "How to
//! launch", V13.
//!
//! - `s02_app_parent_is_not_cli` and (Windows) `s01_squatter_pipe_cli_sends_nothing_e2e` are
//!   ordinary flows: they skip unless `ATLAS_DUCK_CLI_FLOWS=1`, like every flow.
//! - `s02_app_survives_cli_tree_kill` and (Windows) `s02_kill_on_job_close_job` kill a process
//!   tree or close a job object: `#[ignore]`d, and they refuse to run unless `CI == "true"` (the
//!   CI step "S-02 launch survival" runs them with `--ignored s02_`).
//!
//! The launched app cannot be inspected from outside on Linux (non-dumpable, `startup/crash.rs`),
//! but `/proc/<pid>/stat` stays readable (ppid, process group and session are never hidden); the
//! app's pid comes from `test-control/pid` (`testing/control.rs` `write_pid`). Every check of a
//! parent is made while the CLI still runs: once it has exited, a Unix orphan is reparented to
//! init or a subreaper whatever it was, so "ppid != CLI pid" alone would prove nothing. On Unix
//! the session id carries the proof (PD-23: the first child calls `setsid`, `launch/unix.rs`).
//!
//! `launch_blocked_by_job` is not a guaranteed diagnosis (T15 review, ledger): the "blocked"
//! branch of the job test accepts `unreachable` with reason `launch_blocked_by_job` or `not_running` and decide
//! by evidence (no app holds the instance lock, no app process in the job).

use std::fs;
use std::process::Stdio;
use std::time::{Duration, Instant};

use atlas_duck_app_lib::testing::control::PID_FILE;
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::{Child, ChildStderr};

use crate::flows::{Notice, detail, error_code, jira_world, notices, run};
use crate::harness::{CLI_EXE, CliRun, Result, World, opted_in, parse_envelope};
// The process facts and the Toolhelp/job helpers are shared with `mcp_flows` (`procs.rs`).
#[cfg(windows)]
use crate::procs::win;
#[cfg(unix)]
use crate::procs::{Session, own_session};
use crate::procs::{ci_only, describe, proc_facts};

// ---- constants -------------------------------------------------------------------------------------

/// The CI step that runs the `#[ignore]`d cases here (`--ignored s02_`, with `CI=true`). The
/// `#[ignore = "..."]` attributes repeat it as a literal (an attribute takes no constant).
const IGNORE_S02: &str = "CI: S-02 launch survival";
/// A Jira read the scripted approver keeps `pending` (PD-03 `atlas-test:hold`).
const HOLD: [&str; 6] = [
    "jira",
    "issue",
    "get",
    "ABC-1",
    "--reason",
    "atlas-test:hold",
];
/// The parent check's run waits out this deadline after the notice and ends exit 4 `pending`
/// (I-17 shape; a cold start fits in it on every CI leg, `i17_cold_start_within_timeout`).
const PARENT_TIMEOUT: &str = "30";
/// The kill tests' runs: long enough that the CLI is still waiting when the test kills it.
const KILL_TIMEOUT: &str = "120";
/// The submission notice appears after at most a cold start of the app plus the submit.
const NOTICE_WITHIN: Duration = Duration::from_secs(90);
/// A spawned process that has to end does so within this.
const ENDS_WITHIN: Duration = Duration::from_secs(60);
/// The app writes `test-control/pid` when its control watcher starts.
const PID_WITHIN: Duration = Duration::from_secs(15);
/// `crates/cli/src/connected.rs` `ENV_FORCE_OWNER_MISMATCH` (test builds only).
#[cfg(windows)]
const ENV_FORCE_OWNER_MISMATCH: &str = "ATLAS_DUCK_TEST_FORCE_OWNER_MISMATCH";
/// `crates/cli/src/connected.rs` `MSG_SERVER_IDENTITY` (§3.2 (a)).
#[cfg(windows)]
const MSG_SERVER_IDENTITY: &str = "the atlas-duck endpoint is not owned by this user";
/// The two reasons a launch the job (or a missing shell) stopped can carry (`launch/mod.rs`
/// `launch_failed`: `BlockedByJob` → `launch_blocked_by_job`, any other launch error →
/// `not_running`).
const BLOCKED_REASONS: [&str; 2] = ["launch_blocked_by_job", "not_running"];

// ---- pure helpers (unit-tested below) --------------------------------------------------------------

/// A launch stopped before any app started: exit 5 `unreachable` with one of
/// [`BLOCKED_REASONS`], no request id.
fn is_blocked_launch(exit: i32, env: &Envelope) -> bool {
    exit == 5
        && env.status == Status::Failed
        && error_code(env) == Some(ErrorCode::Unreachable)
        && env.request_id.is_none()
        && detail(env, "reason")
            .and_then(Value::as_str)
            .is_some_and(|r| BLOCKED_REASONS.contains(&r))
}

/// What `cmd /d /s /c <tail>` runs: with `/s` cmd strips the first and the last quote of the
/// tail, leaving `"<exe>" <args>` (the exe quoted, so a path with spaces survives). The args are
/// this file's constants: no spaces, quotes or cmd metacharacters.
fn cmd_tail(exe: &str, args: &[&str]) -> String {
    format!("\"\"{exe}\" {}\"", args.join(" "))
}

// ---- spawning the CLI ------------------------------------------------------------------------------

/// `atlas-duck <args>` with the world's environment plus `extra` (they win), stdin null, stdout and
/// stderr piped, killed when dropped. Not spawned yet: callers add their own flags.
fn cli_command(world: &World, args: &[&str], extra: &[(&str, &str)]) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(CLI_EXE);
    cmd.args(args).env_clear().current_dir(world.root());
    for (k, v) in world.env() {
        cmd.env(k, v);
    }
    for (k, v) in extra {
        cmd.env(k, v);
    }
    io_setup(&mut cmd);
    cmd
}

fn io_setup(cmd: &mut tokio::process::Command) {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
}

/// A spawned CLI whose stderr was read up to its submission notice, or to its end.
struct Started {
    child: Child,
    pid: u32,
    stderr: BufReader<ChildStderr>,
    /// What stderr held so far.
    seen: String,
    /// `None`: stderr ended (the process ended) before any notice.
    notice: Option<Notice>,
}

/// Reads `child`'s stderr line by line until the first submission notice or the end of the
/// stream, for at most [`NOTICE_WITHIN`].
async fn until_notice(mut child: Child, what: &str) -> Result<Started> {
    let pid = child.id().ok_or("the spawned process has no pid")?;
    let mut stderr = BufReader::new(child.stderr.take().ok_or("no stderr pipe")?);
    let mut seen = String::new();
    let read = async {
        let mut line = String::new();
        loop {
            line.clear();
            if stderr.read_line(&mut line).await? == 0 {
                return Ok::<Option<Notice>, std::io::Error>(None);
            }
            seen.push_str(&line);
            if let Some(n) = notices(&line).0.into_iter().next() {
                return Ok(Some(n));
            }
        }
    };
    let notice = match tokio::time::timeout(NOTICE_WITHIN, read).await {
        Ok(found) => found?,
        Err(_) => {
            return Err(
                format!("{what}: no notice and no end within {NOTICE_WITHIN:?}: {seen:?}").into(),
            );
        }
    };
    Ok(Started {
        child,
        pid,
        stderr,
        seen,
        notice,
    })
}

/// Waits (60 s) for the started process to end: exit code, stdout, all of stderr, the envelope.
async fn finish(started: Started) -> Result<CliRun> {
    let Started {
        child,
        mut stderr,
        seen,
        ..
    } = started;
    let mut rest = String::new();
    let (out, read) = tokio::join!(
        tokio::time::timeout(ENDS_WITHIN, child.wait_with_output()),
        stderr.read_to_string(&mut rest)
    );
    let out = out.map_err(|_| format!("the process did not end within {ENDS_WITHIN:?}"))??;
    read?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    Ok(CliRun {
        envelope: parse_envelope(&stdout),
        exit: out.status.code().unwrap_or(-1),
        stdout,
        stderr: seen + &rest,
    })
}

/// Polls (15 s) for the app's own pid in `test-control/pid`.
async fn wait_app_pid(world: &World) -> Result<u32> {
    let file = world.control_dir().join(PID_FILE);
    let start = Instant::now();
    loop {
        if let Ok(text) = fs::read_to_string(&file)
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            return Ok(pid);
        }
        if start.elapsed() > PID_WITHIN {
            return Err(format!(
                "the app wrote no test-control/pid within {PID_WITHIN:?}\n{}",
                world.diagnostics()
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn pid_file_now(world: &World) -> Option<u32> {
    fs::read_to_string(world.control_dir().join(PID_FILE))
        .ok()
        .and_then(|t| t.trim().parse().ok())
}

/// After the CLI that started it was killed: the same app (`test-control/pid` unchanged, the
/// instance lock still held) answers `status <id>` with `pending` over its endpoint.
///
/// Order matters: the lock and the pid are checked before the `status` run, because a `status`
/// against a dead app would cold-start a new one (and that one would not know a pending read of
/// the old one: I-26).
async fn same_app_still_serves(world: &World, app_pid: u32, id: &str) -> Result<()> {
    assert!(
        world.app_running()?,
        "no process holds instance.lock after the kill: the app died with the CLI\n{}",
        world.diagnostics()
    );
    assert_eq!(
        pid_file_now(world),
        Some(app_pid),
        "test-control/pid changed: another app started\n{}",
        world.diagnostics()
    );
    let st = run(world, &["status", id]).await?;
    assert_eq!(
        st.exit,
        0,
        "status {id}: {}\n{}",
        st.stdout,
        world.diagnostics()
    );
    assert_eq!(
        st.envelope.as_ref().map(|e| e.status),
        Some(Status::Pending),
        "status {id} after the kill: {}",
        st.stdout
    );
    assert_eq!(
        pid_file_now(world),
        Some(app_pid),
        "the status run started another app\n{}",
        world.diagnostics()
    );
    Ok(())
}

/// The "blocked" outcome: the CLI ended before any notice with a launch refusal, and no app runs.
fn expect_blocked(world: &World, r: &CliRun, what: &str) -> Result<()> {
    let env = r.envelope.as_ref().ok_or_else(|| {
        format!(
            "{what}: no envelope: {:?} (stderr {:?})",
            r.stdout, r.stderr
        )
    })?;
    assert!(
        is_blocked_launch(r.exit, env),
        "{what}: the CLI ended without a notice and without a launch refusal: exit {}: {}\nstderr: {}\n{}",
        r.exit,
        r.stdout,
        r.stderr,
        world.diagnostics()
    );
    assert!(
        !world.app_running()?,
        "{what}: the launch was refused but an app holds instance.lock\n{}",
        world.diagnostics()
    );
    assert_eq!(
        pid_file_now(world),
        None,
        "{what}: the launch was refused but an app wrote test-control/pid"
    );
    Ok(())
}

// ---- S-02: the app's parent and session --------------------------------------------------------------

/// S-02 (§4.7 "How to launch", PD-21, PD-23): a cold start through the CLI leaves the app outside
/// the CLI's process tree. While the CLI still waits for its held read, the app's parent is
/// neither the CLI nor the test, and on Unix the app's session differs from the CLI's (which is
/// the test's own: the test does not start the CLI in a new session).
///
/// Source: `launch/unix.rs` `spawn_detached` (`fork`, `setsid` in the first child, `fork`, the
/// first child exits: the app is an orphan in its own session), `launch/windows.rs`
/// `spawn_detached` (step 1 the shell process as parent, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`;
/// step 2 the stub, which exits after it started the app), `testing/control.rs` (`pid`).
/// The run then ends on its own, exit 4 `pending` at its deadline (I-17).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s02_app_parent_is_not_cli() -> Result<()> {
    if !opted_in("s02_app_parent_is_not_cli") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mut args = HOLD.to_vec();
    args.extend(["--timeout", PARENT_TIMEOUT]);
    let child = cli_command(&world, &args, &[]).spawn()?;
    let mut started = until_notice(child, "the held read").await?;
    let Some(notice) = started.notice.clone() else {
        let r = finish(started).await?;
        return Err(format!(
            "no submission notice: exit {}: {}\nstderr: {}\n{}",
            r.exit,
            r.stdout,
            r.stderr,
            world.diagnostics()
        )
        .into());
    };
    let cli_pid = started.pid;
    let app_pid = wait_app_pid(&world).await?;
    let cli = proc_facts(cli_pid)?;
    let app = proc_facts(app_pid)?;
    // Both reads happened while the CLI ran (it waits out its deadline after the notice).
    assert!(
        started.child.try_wait()?.is_none(),
        "the CLI ended before the parent was read: the check would prove nothing"
    );
    let test_pid = std::process::id();
    println!(
        "S02 parent: app {app_pid} {app:?}, parent {}; cli {cli_pid} {cli:?}; test {test_pid}",
        describe(app.ppid)
    );
    assert_ne!(app_pid, cli_pid, "the app pid is the CLI's");
    assert_ne!(
        app.ppid, cli_pid,
        "the app's parent is the CLI (request {})",
        notice.request_id
    );
    assert_ne!(app.ppid, test_pid, "the app's parent is the test process");
    #[cfg(unix)]
    {
        let own = own_session()?;
        assert_eq!(
            cli.session,
            Session::Id(own),
            "the CLI is not in the test's session: the comparison below would mean nothing"
        );
        assert_ne!(
            app.session,
            Session::Id(own),
            "the app is in the CLI's session {own} (no setsid in the launch)"
        );
        assert_ne!(app.pgid, cli.pgid, "the app is in the CLI's process group");
    }
    #[cfg(windows)]
    {
        let _ = cli;
        // The live ancestors of the app (`win::live_ancestors` stops at the dead stub, or where a
        // parent pid was reused): neither the CLI nor the test may be among them.
        let chain = win::live_ancestors(app_pid)?;
        let shown: Vec<String> = chain
            .iter()
            .map(|p| format!("{} {}", p.pid, p.exe))
            .collect();
        println!("S02 live ancestors of the app {app_pid}: {shown:?}");
        assert!(
            !chain.iter().any(|p| p.pid == cli_pid),
            "the CLI {cli_pid} is an ancestor of the app: {shown:?}"
        );
        assert!(
            !chain.iter().any(|p| p.pid == test_pid),
            "the test process {test_pid} is an ancestor of the app: {shown:?}"
        );
    }
    let r = finish(started).await?;
    assert_eq!(
        r.exit, 4,
        "the held read did not end pending: {}\nstderr: {}",
        r.stdout, r.stderr
    );
    Ok(())
}

// ---- S-02 / V13: killing the CLI's tree, closing its job -----------------------------------------------

/// S-02 (CI): the agent's whole process tree is killed while the CLI waits for a held read; the
/// app it launched survives and still holds the request `pending`.
///
/// Unix: the CLI is the leader of its own process group (`process_group(0)`) and the test sends
/// `SIGKILL` to the group (`kill(-pgid)`); the app left the group with `setsid`
/// (`launch/unix.rs` `first_child`). Windows: `cmd /c atlas-duck ...` and `taskkill /T /F` on
/// cmd's pid, which ends cmd and every live descendant by parent pid; the app's parent is the
/// shell (step 1) or the stub, which already exited (step 2).
/// The test adds no job, so a CLI that ends without a launch notice is an error on every OS (a
/// refusal is never an environment fact here). Prints `V13 tree_kill_case=survived`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI: S-02 launch survival"]
async fn s02_app_survives_cli_tree_kill() -> Result<()> {
    ci_only(IGNORE_S02, std::env::var("CI").ok().as_deref())?;
    if !opted_in("s02_app_survives_cli_tree_kill") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mut args = HOLD.to_vec();
    args.extend(["--timeout", KILL_TIMEOUT]);
    let child = spawn_tree(&world, &args)?;
    // Windows: until the kill succeeded, an error path ends cmd's tree.
    #[cfg(windows)]
    let mut guard = TreeGuard::armed(child.id());
    let started = until_notice(child, "the held read").await?;
    let Some(notice) = started.notice.clone() else {
        let r = finish(started).await?;
        return Err(format!(
            "no submission notice: exit {}: {}\nstderr: {}\n{}",
            r.exit,
            r.stdout,
            r.stderr,
            world.diagnostics()
        )
        .into());
    };
    let app_pid = wait_app_pid(&world).await?;
    #[cfg(unix)]
    let ended = kill_tree(&world, started, app_pid).await?;
    #[cfg(windows)]
    let ended = kill_tree(&world, started, app_pid, &mut guard).await?;
    println!("S02 tree kill: the CLI tree ended with {ended}");
    same_app_still_serves(&world, app_pid, &notice.request_id).await?;
    println!("V13 tree_kill_case=survived app_pid={app_pid}");
    Ok(())
}

/// Unix: the CLI as the leader of a new process group.
#[cfg(unix)]
fn spawn_tree(world: &World, args: &[&str]) -> Result<Child> {
    let mut cmd = cli_command(world, args, &[]);
    cmd.process_group(0);
    Ok(cmd.spawn()?)
}

/// Windows: `cmd /d /s /c "<CLI> <args>"`, so the CLI is cmd's child (the tree `taskkill /T`
/// walks).
#[cfg(windows)]
fn spawn_tree(world: &World, args: &[&str]) -> Result<Child> {
    use std::os::windows::process::CommandExt;
    let system_root = std::env::var_os("SystemRoot").ok_or("SystemRoot is not set")?;
    let cmd_exe = std::path::Path::new(&system_root)
        .join("System32")
        .join("cmd.exe");
    let mut std_cmd = std::process::Command::new(cmd_exe);
    std_cmd
        .args(["/d", "/s", "/c"])
        .raw_arg(cmd_tail(CLI_EXE, args))
        .env_clear()
        .current_dir(world.root());
    for (k, v) in world.env() {
        std_cmd.env(k, v);
    }
    let mut cmd = tokio::process::Command::from(std_cmd);
    io_setup(&mut cmd);
    Ok(cmd.spawn()?)
}

/// Unix: `SIGKILL` to the CLI's process group; the CLI must end by that signal, and the app must
/// not have been in the group.
#[cfg(unix)]
async fn kill_tree(world: &World, started: Started, app_pid: u32) -> Result<String> {
    use std::os::unix::process::ExitStatusExt;
    let pgid = started.pid;
    let app = proc_facts(app_pid)?;
    assert_ne!(
        app.pgid,
        Some(pgid),
        "the app is in the CLI's process group: the kill below would end it"
    );
    let group = libc::pid_t::try_from(pgid)?;
    // SAFETY: plain call; the group is the CLI's own (`process_group(0)` made it its leader).
    if unsafe { libc::kill(-group, libc::SIGKILL) } != 0 {
        return Err(format!(
            "kill(-{pgid}, SIGKILL): {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    let Started { mut child, .. } = started;
    let status = tokio::time::timeout(ENDS_WITHIN, child.wait())
        .await
        .map_err(|_| "the killed CLI did not end")??;
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the CLI did not end by SIGKILL: {status}\n{}",
        world.diagnostics()
    );
    Ok(format!("{status}; the app was {app:?}"))
}

/// Windows: ends `taskkill /T /F /PID <cmd>` of the cmd this test spawned when the test fails
/// before its own kill succeeded (otherwise the CLI would wait out its 120 s deadline). Disarmed
/// once the kill ran, or when the tree is not the one the test expects (then nothing is killed).
#[cfg(windows)]
struct TreeGuard(Option<u32>);

#[cfg(windows)]
impl TreeGuard {
    fn armed(cmd_pid: Option<u32>) -> TreeGuard {
        TreeGuard(cmd_pid)
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

#[cfg(windows)]
impl Drop for TreeGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0.take() {
            // Best effort: the process may be gone already.
            let _ = std::process::Command::new("taskkill")
                .args(["/T", "/F", "/PID", &pid.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// Windows: `taskkill /T /F /PID <cmd>`. The CLI (cmd's `atlas-duck.exe` child) must be gone
/// afterwards; the app's parent was never the CLI. The kill runs only if cmd's transitive
/// descendants are exactly the CLI and optionally `conhost.exe`, each created after cmd: `/T`
/// walks parent pids (which Windows never clears), so anything else could be a stranger.
#[cfg(windows)]
async fn kill_tree(
    world: &World,
    started: Started,
    app_pid: u32,
    guard: &mut TreeGuard,
) -> Result<String> {
    let cmd_pid = started.pid;
    let all = win::processes()?;
    let cli_pid = all
        .iter()
        .find(|p| p.ppid == cmd_pid && p.exe.eq_ignore_ascii_case("atlas-duck.exe"))
        .map(|p| p.pid)
        .ok_or_else(|| format!("no atlas-duck.exe child of cmd {cmd_pid}"))?;
    let app = proc_facts(app_pid)?;
    assert_ne!(
        app.ppid, cli_pid,
        "the app's parent is the CLI: taskkill /T would end it"
    );
    let tree = win::descendants(&all, cmd_pid)?;
    let described: Vec<String> = tree
        .iter()
        .map(|p| format!("{} {}", p.pid, p.exe))
        .collect();
    println!("S02 descendants of cmd {cmd_pid} before the kill: {described:?}");
    let expected = tree.iter().all(|p| {
        p.pid == cli_pid || (p.exe.eq_ignore_ascii_case("conhost.exe") && p.pid != app_pid)
    }) && tree.iter().any(|p| p.pid == cli_pid);
    if !expected {
        guard.disarm();
        return Err(format!(
            "refusing taskkill /T on cmd {cmd_pid}: its descendants are {described:?}, expected only the CLI {cli_pid} (and conhost.exe)"
        )
        .into());
    }
    let out = std::process::Command::new("taskkill")
        .args(["/T", "/F", "/PID", &cmd_pid.to_string()])
        .stdin(Stdio::null())
        .output()?;
    if out.status.success() {
        guard.disarm();
    }
    println!(
        "S02 taskkill /T /F /PID {cmd_pid}: {} {} {}",
        out.status,
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let Started { mut child, .. } = started;
    let status = tokio::time::timeout(ENDS_WITHIN, child.wait())
        .await
        .map_err(|_| "cmd did not end after taskkill")??;
    // A terminated process can stay listed for a moment while a handle to it is open.
    let start = Instant::now();
    while win::processes()?.iter().any(|p| p.pid == cli_pid) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the CLI {cli_pid} still runs 10 s after taskkill /T\n{}",
            world.diagnostics()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(format!(
        "{status}; the app's parent was {}",
        describe(app.ppid)
    ))
}

/// S-02 / V13 (Windows CI): the test puts the CLI into a job with `KILL_ON_JOB_CLOSE` and without
/// `BREAKAWAY_OK` (it starts it suspended, assigns it, resumes it), waits for the notice, lists the
/// job's processes and closes the job. Either the app is not in the job and survives the close
/// with its request pending (`survived`: the shell-parent path, whose child takes the shell's
/// job), or the CLI ended with a launch refusal and no `atlas-duck-app.exe` is in the job
/// (`blocked`: `job_breakaway` reads this job, which allows no breakaway). Prints
/// `V13 job_case=<survived|blocked> shell_window=<some|none>`; `blocked` with a shell window is a
/// failure (step 1 would have launched outside the job).
///
/// Source: `launch/windows.rs` `spawn_detached` and `job_breakaway` (`QueryInformationJobObject`
/// of the innermost job), mirrored from its `probe_in_job` test (suspended child, nested job).
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI: S-02 launch survival"]
async fn s02_kill_on_job_close_job() -> Result<()> {
    use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

    ci_only(IGNORE_S02, std::env::var("CI").ok().as_deref())?;
    if !opted_in("s02_kill_on_job_close_job") {
        return Ok(());
    }
    let world = jira_world().await?;
    let job = win::Job::kill_on_close()?;
    let mut args = HOLD.to_vec();
    args.extend(["--timeout", KILL_TIMEOUT]);
    let mut cmd = cli_command(&world, &args, &[]);
    cmd.creation_flags(CREATE_SUSPENDED);
    let child = cmd.spawn()?;
    let cli_pid = child.id().ok_or("the CLI has no pid")?;
    job.assign(child.raw_handle().ok_or("the CLI has no handle")?)?;
    // One thread, unless something injected another (resuming a running thread is a no-op).
    let resumed = win::resume_threads(cli_pid)?;
    assert!(
        resumed >= 1,
        "no thread of the suspended CLI {cli_pid} to resume"
    );
    let started = until_notice(child, "the held read in the job").await?;

    // Before the close (the close kills every process in the job).
    let in_job = job.pids()?;
    let names = win::processes()?;
    let named: Vec<String> = in_job
        .iter()
        .map(|pid| {
            names
                .iter()
                .find(|p| p.pid == *pid)
                .map_or_else(|| format!("{pid} (gone)"), |p| format!("{pid} {}", p.exe))
        })
        .collect();
    println!("S02 job processes before the close: {named:?}");
    let app_in_job = in_job.iter().any(|pid| {
        names
            .iter()
            .any(|p| p.pid == *pid && p.exe.eq_ignore_ascii_case("atlas-duck-app.exe"))
    });

    // Step 1 of the launch needs a shell window (`GetShellWindow`) to take as parent: a runner
    // with one has no reason to refuse the launch.
    let shell_window = if win::has_shell_window() {
        "some"
    } else {
        "none"
    };
    let Some(notice) = started.notice.clone() else {
        let r = finish(started).await?;
        assert!(
            !app_in_job,
            "the launch was refused but an atlas-duck-app.exe is in the job: {named:?}"
        );
        drop(job);
        expect_blocked(&world, &r, "job")?;
        assert_eq!(
            shell_window,
            "none",
            "the launch was refused although a shell window exists, so step 1 should have launched outside the job (exit {}: {})\n{}",
            r.exit,
            r.stdout.trim(),
            world.diagnostics()
        );
        println!("V13 job_case=blocked shell_window={shell_window}");
        return Ok(());
    };
    let app_pid = wait_app_pid(&world).await?;
    println!(
        "S02 job: app {app_pid}, parent {}",
        describe(proc_facts(app_pid)?.ppid)
    );
    assert!(
        in_job.contains(&cli_pid),
        "control: the CLI {cli_pid} is not in the test's job {named:?}"
    );
    assert!(
        !in_job.contains(&app_pid) && !app_in_job,
        "the app {app_pid} is in the CLI's job (closing it would end the app): {named:?}"
    );
    let closed = Instant::now();
    drop(job);
    let Started { mut child, .. } = started;
    let status = tokio::time::timeout(ENDS_WITHIN, child.wait())
        .await
        .map_err(|_| "the CLI did not end when its job was closed")??;
    let ended_after = closed.elapsed();
    println!("S02 job closed: the CLI ended with {status} after {ended_after:?}");
    // The close ended it, not its own 120 s deadline (which is exit 4 `pending`).
    assert!(
        ended_after < Duration::from_secs(5),
        "the CLI ended {ended_after:?} after the job close: not the close's doing ({status})"
    );
    assert_ne!(
        status.code(),
        Some(4),
        "the CLI ended with its own deadline's exit 4, not by the job close"
    );
    same_app_still_serves(&world, app_pid, &notice.request_id).await?;
    println!("V13 job_case=survived app_pid={app_pid} shell_window={shell_window}");
    Ok(())
}

// ---- S-01: a squatter pipe gets nothing (Windows) ---------------------------------------------------

/// A pipe of the test's own under this user's SID prefix, with the app's descriptor (`PipeSecurity`),
/// named in `<data>/endpoint` (one line, no newline, PD-26), served on a task that accepts one
/// client and reads from it.
#[cfg(windows)]
struct Squatter {
    name: String,
    /// The bytes the client sent: everything up to its close, or (`first_only`) the first read.
    task: tokio::task::JoinHandle<std::io::Result<(Vec<u8>, Ending)>>,
}

/// How the squatter's read ended.
#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
enum Ending {
    /// `first_only`: the first read returned.
    FirstRead,
    /// `read_to_end` returned: the client closed.
    Eof,
    /// `ErrorKind::BrokenPipe`: the client closed.
    BrokenPipe,
    /// `ErrorKind::NotConnected` (`ERROR_PIPE_NOT_CONNECTED`).
    NotConnected,
}

#[cfg(windows)]
fn squat(world: &World, first_only: bool) -> Result<Squatter> {
    use atlas_duck_ipc::paths::{
        DataDirResolution, EndpointLocation, check_data_dir, endpoint_location, write_endpoint_file,
    };
    use atlas_duck_ipc::transport::windows::new_pipe_name;
    use atlas_duck_ipc::transport::windows::security::PipeSecurity;
    use tokio::net::windows::named_pipe::ServerOptions;

    let DataDirResolution::Local(data) = check_data_dir(world.data_dir())? else {
        return Err("the test data dir is not a local data dir".into());
    };
    let EndpointLocation::WindowsPipePrefix(prefix) = endpoint_location(&data, world.host())?
    else {
        return Err("no pipe prefix on Windows".into());
    };
    let name = new_pipe_name(&prefix)?;
    // The app's own descriptor (owner = this user's SID), so the CLI's real check accepts the pipe
    // and only the forced check refuses it. Not the default descriptor: the check wants the pipe's
    // owner to be the user SID too, and a pipe an elevated administrator creates (the CI runner)
    // is owned by BUILTIN\Administrators by default.
    let security = PipeSecurity::for_current_user()?;
    let mut attrs = security.attributes();
    // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES whose descriptor lives in `security`,
    // borrowed for the whole call; CreateNamedPipeW copies it.
    let mut server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(&name, (&raw mut attrs).cast())
    }?;
    write_endpoint_file(&data, &name)?;
    let task = tokio::spawn(async move {
        server.connect().await?;
        let mut got = Vec::new();
        if first_only {
            let mut buf = [0u8; 64];
            let n = server.read(&mut buf).await?;
            got.extend_from_slice(&buf[..n]);
            return Ok((got, Ending::FirstRead));
        }
        // A client that closed reads as EOF or `BrokenPipe` (transport_windows.rs
        // `s01_squatter_pipe_cli_sends_nothing`), or `NotConnected` (`ERROR_PIPE_NOT_CONNECTED`)
        // when the connect was already pending as it came and went. The bytes are 0 either way.
        match server.read_to_end(&mut got).await {
            Ok(_) => Ok((got, Ending::Eof)),
            Err(e) => match e.kind() {
                std::io::ErrorKind::BrokenPipe => Ok((got, Ending::BrokenPipe)),
                std::io::ErrorKind::NotConnected => Ok((got, Ending::NotConnected)),
                _ => Err(e),
            },
        }
    });
    Ok(Squatter { name, task })
}

#[cfg(windows)]
async fn squatter_bytes(s: Squatter, what: &str) -> Result<(Vec<u8>, Ending)> {
    let name = s.name;
    match tokio::time::timeout(Duration::from_secs(30), s.task).await {
        Ok(joined) => Ok(joined??),
        Err(_) => Err(format!(
            "{what}: the CLI never connected to (or never closed) the squatter pipe {name}"
        )
        .into()),
    }
}

/// S-01 (§3.2 (a), §13 "simulated"): an endpoint whose server another account created. The test
/// creates its own pipe under this user's SID prefix (so discovery accepts the name and the
/// liveness probe sees a pipe: no launch), owned by this user like the app's (so the real check
/// would accept it: `server_owner_ok` wants the server process's user and the pipe's owner to be
/// this user), and runs the CLI with
/// `ATLAS_DUCK_TEST_FORCE_OWNER_MISMATCH=1`, which makes the owner check refuse every server
/// (`connected.rs`, test builds only). The CLI exits 5 `server_identity`, `retryable: false`, and
/// the pipe read 0 bytes before the client closed.
///
/// Control first, without the hook: the same CLI against the same kind of pipe does write (its
/// hello), so the 0 bytes below come from the check, not from a CLI that never got there. The
/// control's CLI then reads no answer, which is `server_identity` too (`client.rs` `handshake`).
/// The case asserts the pipe was connected at all (`squatter_bytes` times out otherwise).
///
/// Source: `discover.rs` `endpoint_present` (prefix check, then `pipe_exists`), `client.rs`
/// `open` (Windows: endpoint file, prefix, `connect_checked`), `transport/windows/mod.rs`
/// `connect_checked` (the probe runs before any byte; false drops the client), `connected.rs`
/// `connect_error` (`ServerIdentity` → `server_identity`, not retryable, exit 5).
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s01_squatter_pipe_cli_sends_nothing_e2e() -> Result<()> {
    if !opted_in("s01_squatter_pipe_cli_sends_nothing_e2e") {
        return Ok(());
    }
    let world = World::new(crate::harness::WorldOpts::default())?;

    // Control: no hook, the CLI writes into the pipe.
    let control = squat(&world, true)?;
    let child = cli_command(&world, &["instances", "--timeout", "30"], &[]).spawn()?;
    let (sent, ending) = squatter_bytes(control, "control").await?;
    let r = finish(until_notice(child, "control").await?).await?;
    println!(
        "S01 control: the CLI without the hook sent {} bytes (ending {ending:?}), then exit {}: {}",
        sent.len(),
        r.exit,
        r.stdout.trim()
    );
    assert!(
        !sent.is_empty(),
        "control: the CLI without the hook sent nothing (ending {ending:?}): the case below would \
         prove nothing\nexit {}\nstdout: {}\nstderr: {}",
        r.exit,
        r.stdout.trim(),
        r.stderr.trim()
    );

    // The case: the forced mismatch.
    let squatter = squat(&world, false)?;
    let child = cli_command(
        &world,
        &["instances", "--timeout", "30"],
        &[(ENV_FORCE_OWNER_MISMATCH, "1")],
    )
    .spawn()?;
    let r = finish(until_notice(child, "squatter").await?).await?;
    let what = format!(
        "squatter (the CLI exited {}: {}; stderr {})",
        r.exit,
        r.stdout.trim(),
        r.stderr.trim()
    );
    let (got, ending) = squatter_bytes(squatter, &what).await?;
    println!(
        "S01 squatter_bytes_received={} ending={ending:?}",
        got.len()
    );
    assert!(
        got.is_empty(),
        "the CLI sent {} bytes to a server whose owner check failed: {:?}\n{what}",
        got.len(),
        String::from_utf8_lossy(&got)
    );
    let env = r
        .envelope
        .as_ref()
        .ok_or_else(|| format!("no envelope: {:?} (stderr {:?})", r.stdout, r.stderr))?;
    let err = env
        .error
        .as_ref()
        .ok_or_else(|| format!("no error: {}", r.stdout))?;
    assert_eq!(r.exit, 5, "{}\nstderr: {}", r.stdout, r.stderr);
    assert_eq!(env.status, Status::Failed, "{}", r.stdout);
    assert_eq!(err.code, ErrorCode::ServerIdentity, "{}", r.stdout);
    assert!(!err.retryable, "{}", r.stdout);
    assert_eq!(err.message, MSG_SERVER_IDENTITY, "{}", r.stdout);
    assert!(env.request_id.is_none(), "{}", r.stdout);
    // The pipe answered the liveness probe: nothing was launched.
    assert!(
        !world.app_running()?,
        "an app was launched\n{}",
        world.diagnostics()
    );
    assert_eq!(pid_file_now(&world), None, "an app was launched");
    Ok(())
}

// ---- unit tests of the pure helpers -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(code: ErrorCode, reason: Option<&str>) -> Envelope {
        let mut env = Envelope::failed(code, true, "x");
        if let (Some(r), Some(err)) = (reason, env.error.as_mut()) {
            let mut d = serde_json::Map::new();
            d.insert("reason".to_owned(), Value::from(r));
            err.details = Some(d);
        }
        env
    }

    #[test]
    fn blocked_launch_is_exit_5_unreachable_with_a_blocking_reason() {
        for r in BLOCKED_REASONS {
            assert!(
                is_blocked_launch(5, &failed(ErrorCode::Unreachable, Some(r))),
                "{r}"
            );
            assert!(
                !is_blocked_launch(4, &failed(ErrorCode::Unreachable, Some(r))),
                "{r}"
            );
        }
        for r in ["launch_timeout", "no_gui_session", "first_run"] {
            assert!(
                !is_blocked_launch(5, &failed(ErrorCode::Unreachable, Some(r))),
                "{r}"
            );
        }
        assert!(!is_blocked_launch(5, &failed(ErrorCode::Unreachable, None)));
        assert!(!is_blocked_launch(
            5,
            &failed(ErrorCode::ServerIdentity, Some("not_running"))
        ));
        let mut with_id = failed(ErrorCode::Unreachable, Some("not_running"));
        with_id.request_id = Some("req_1".to_owned());
        assert!(!is_blocked_launch(5, &with_id));
    }

    #[test]
    fn cmd_tail_quotes_the_exe_inside_the_outer_quotes() {
        assert_eq!(
            cmd_tail(r"C:\a b\atlas-duck.exe", &["jira", "issue", "get"]),
            r#"""C:\a b\atlas-duck.exe" jira issue get""#
        );
    }
}
