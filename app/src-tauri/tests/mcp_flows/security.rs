//! `mcp_flows` security cases (M9 Task 16): §13 S-02 for `atlas-duck mcp`, §4.7 "How to launch",
//! §4.6 (stdout carries only JSON-RPC), V13.
//!
//! The server is spawned by the test as a desktop MCP client would: piped stdin and stdout, no
//! app running. Its first connected tool call launches the app (`launch/`), which must then be
//! no part of the server's process tree, session, job or pipes.
//!
//! - `s02_mcp_stdout_only_jsonrpc_on_auto_launch`, `s02_mcp_stdout_closes_when_mcp_exits` and
//!   `s02_app_parent_is_not_mcp` run on every OS and, like every flow, skip unless
//!   `ATLAS_DUCK_CLI_FLOWS=1`.
//! - `s02_mcp_without_console_auto_launches` (Windows) starts the server with `CREATE_NO_WINDOW`
//!   and runs in Windows CI (lead ruling R13); a failure is diagnosed from the CI log (plan Step 2b).
//! - `s02_app_survives_mcp_tree_kill` (Windows) kills a process tree: `#[ignore]`d, and it refuses
//!   to run unless `CI == "true"`. It prints the V13 line
//!   `V13 mcp_tree_kill_case=<survived|blocked> app_pid=<pid|none> shell_window=<some|none>`.
//!
//! Every wait is bounded (the driver's timeouts, or a loop with its own deadline). A child that is
//! still running when a test fails is killed when its handle drops (`kill_on_drop`); an app the
//! server launched is quit by the world's drop.
//!
//! Source: `launch/unix.rs` `spawn_detached` (`setsid`, double fork, stdio on `/dev/null`, every
//! other descriptor closed), `launch/windows.rs` (`bInheritHandles = FALSE`, null standard handles,
//! `DETACHED_PROCESS`; step 1 the shell as parent, step 2 the stub) and `testing/control.rs`
//! (`test-control/pid`). The helpers that read another process live in `cli_flows/procs.rs`.

use std::fs;
use std::process::Stdio;
use std::time::{Duration, Instant};

use atlas_duck_app_lib::testing::control::PID_FILE;
use atlas_duck_ipc::paths::ENDPOINT_FILE;
use serde_json::{Value, json};

use crate::driver::{CallOutcome, McpChild};
use crate::flows::jira_world;
use crate::harness::{CLI_EXE, PAT_CANARY, Result, World, opted_in};
#[cfg(unix)]
use crate::procs::{Session, own_session};
#[cfg(windows)]
use crate::procs::{ci_only, win};
use crate::procs::{describe, proc_facts};
#[cfg(windows)]
use atlas_duck_ipc::envelope::Status;

// ---- constants -------------------------------------------------------------------------------------

/// The `ATLAS_DUCK_MCP_TIMEOUT` variable (§4.6).
const TIMEOUT_ENV: &str = "ATLAS_DUCK_MCP_TIMEOUT";
/// A cold start of the app fits in this on every CI leg (`i17_mcp_cold_start_within_timeout` uses
/// 30 s).
const LAUNCH_TIMEOUT: &str = "50";
/// The tree-kill case: long enough that the held read is still waiting when the test kills.
#[cfg(windows)]
const KILL_TIMEOUT: &str = "120";
/// After `close_stdin` the server ends and stdout reaches its end within this (S-02).
const EXIT_WITHIN: Duration = Duration::from_secs(5);
/// The app writes `test-control/pid` when its control watcher starts.
const PID_WITHIN: Duration = Duration::from_secs(15);
/// The submitted notification of a held read appears after at most a cold start plus the submit.
#[cfg(windows)]
const SUBMITTED_WITHIN: Duration = Duration::from_secs(90);
/// The CI step that runs the `#[ignore]`d case (`--ignored s02_`, with `CI=true`); the
/// `#[ignore = "..."]` attribute repeats it as a literal.
#[cfg(windows)]
const IGNORE_S02: &str = "CI: S-02 step";
/// The two reasons a launch the job (or a missing shell) stopped can carry (`launch/mod.rs`
/// `launch_failed`: `BlockedByJob` -> `launch_blocked_by_job`, any other launch error ->
/// `not_running`).
const BLOCKED_REASONS: [&str; 2] = ["launch_blocked_by_job", "not_running"];
/// The tool call of the cold start: a read the scripted approver releases at once, with a progress
/// token so that notifications are on stdout too.
const TOKEN: &str = "tok-s02";

// ---- pure helpers (unit-tested below) --------------------------------------------------------------

/// Every line is a JSON-RPC 2.0 message (§4.6: stdout carries only JSON-RPC), and there are at
/// least `min` of them. The driver checks each line as it reads it; this checks the whole
/// transcript again, so the assertion does not depend on the driver having looked.
fn check_jsonrpc_lines(lines: &[String], min: usize) -> std::result::Result<(), String> {
    if lines.len() < min {
        return Err(format!(
            "{} stdout lines, expected at least {min}: {lines:?}",
            lines.len()
        ));
    }
    for line in lines {
        let v: Value =
            serde_json::from_str(line).map_err(|e| format!("not JSON ({e}): {line:?}"))?;
        let obj = v
            .as_object()
            .ok_or_else(|| format!("not a JSON object: {line:?}"))?;
        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(format!("no \"jsonrpc\": \"2.0\": {line:?}"));
        }
        let request_or_notification = obj.get("method").is_some_and(Value::is_string);
        let response =
            obj.contains_key("id") && (obj.contains_key("result") || obj.contains_key("error"));
        if !(request_or_notification || response) {
            return Err(format!(
                "neither a request, a notification nor a response: {line:?}"
            ));
        }
    }
    Ok(())
}

/// A launch stopped before any app started, as a tool result: an error with the `failed` envelope
/// `unreachable`, one of [`BLOCKED_REASONS`], and no request id.
fn is_blocked_result(is_error: bool, env: &Value) -> bool {
    is_error
        && env["status"] == "failed"
        && env["error"]["code"] == "unreachable"
        && env["request_id"].is_null()
        && env["error"]["details"]["reason"]
            .as_str()
            .is_some_and(|r| BLOCKED_REASONS.contains(&r))
}

/// The transitive descendants of the server before the kill are, if any, console hosts (a server
/// started without a console gets a `conhost.exe` of its own), and the app is none of them:
/// `taskkill /T` walks parent pids, which Windows never clears, so anything else could be a
/// stranger.
#[cfg(windows)]
fn only_console_hosts(tree: &[win::Proc], app_pid: u32) -> bool {
    tree.iter()
        .all(|p| p.exe.eq_ignore_ascii_case("conhost.exe") && p.pid != app_pid)
}

// ---- spawning and driving the server ---------------------------------------------------------------

/// `atlas-duck mcp` with the world's environment and `ATLAS_DUCK_MCP_TIMEOUT=<timeout>`, stdio
/// piped, killed when dropped. Not spawned yet: callers add their own flags.
fn mcp_command(world: &World, timeout: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(CLI_EXE);
    cmd.arg("mcp").env_clear().current_dir(world.root());
    for (k, v) in world.env() {
        cmd.env(k, v);
    }
    cmd.env(TIMEOUT_ENV, timeout);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd
}

fn endpoint_exists(world: &World) -> Result<bool> {
    Ok(world.data_dir().join(ENDPOINT_FILE).try_exists()?)
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

#[cfg(windows)]
fn pid_file_now(world: &World) -> Option<u32> {
    fs::read_to_string(world.control_dir().join(PID_FILE))
        .ok()
        .and_then(|t| t.trim().parse().ok())
}

/// A released read, as the cold start's tool call.
async fn released_read(mcp: &mut McpChild) -> Result<CallOutcome> {
    mcp.call(
        "jira_issue_get",
        json!({"key": "ABC-1", "reason": "atlas-test:release"}),
        Some(TOKEN),
    )
    .await
}

/// Spawns `cmd` (an `atlas-duck mcp`), completes the handshake and makes the first connected tool
/// call: with no app running, that call auto-launches it. Checks the call succeeded, that the app
/// was launched (nothing before the call launched anything) and that every stdout line so far is
/// JSON-RPC.
async fn launch_session(
    world: &World,
    mut cmd: tokio::process::Command,
    client: &str,
) -> Result<McpChild> {
    assert!(
        !endpoint_exists(world)?,
        "an app was running before the first call"
    );
    let mut mcp = McpChild::new(cmd.spawn()?)?;
    mcp.initialize(client).await?;
    assert!(
        !endpoint_exists(world)?,
        "the handshake launched the app\n{}",
        mcp.transcript()
    );
    let out = released_read(&mut mcp).await?;
    assert!(
        !out.is_error(),
        "the auto-launching call failed: {}\n{}\n{}",
        out.structured(),
        mcp.transcript(),
        world.diagnostics()
    );
    assert_eq!(
        out.structured()["status"],
        "released",
        "{}",
        mcp.transcript()
    );
    assert!(
        endpoint_exists(world)?,
        "the first call did not launch the app\n{}",
        mcp.transcript()
    );
    let lines = mcp.raw_stdout_lines();
    if let Err(why) = check_jsonrpc_lines(&lines, 2) {
        panic!("stdout of atlas-duck mcp: {why}\n{}", mcp.transcript());
    }
    for line in &lines {
        assert!(!line.contains(PAT_CANARY), "the PAT canary is on stdout");
    }
    Ok(mcp)
}

/// The end of a session: stdin closed, stdout read to its end (what the server prints on its way
/// out is checked like every other line), the server ends with success, the app is quit.
async fn finish_session(world: &World, mut mcp: McpChild) -> Result<()> {
    mcp.close_stdin();
    mcp.wait_stdout_eof(EXIT_WITHIN).await?;
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    if let Err(why) = check_jsonrpc_lines(&mcp.raw_stdout_lines(), 2) {
        panic!("stdout of atlas-duck mcp: {why}\n{}", mcp.transcript());
    }
    world.quit_app().await?;
    Ok(())
}

// ---- S-02: stdout --------------------------------------------------------------------------------------

/// S-02 / §4.6, all OS: no app runs; the first tool call of the session launches it, and every
/// line `atlas-duck mcp` wrote to stdout during the handshake, the launch and the call is a
/// JSON-RPC 2.0 message (no log line, no launcher output; the launched app's stdio is the null
/// device). Nothing is launched before that call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s02_mcp_stdout_only_jsonrpc_on_auto_launch() -> Result<()> {
    if !opted_in("s02_mcp_stdout_only_jsonrpc_on_auto_launch") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mcp = launch_session(
        &world,
        mcp_command(&world, LAUNCH_TIMEOUT),
        "mcp-flows-s02-stdout",
    )
    .await?;
    finish_session(&world, mcp).await
}

/// S-02 / §4.7, all OS: after the auto-launch, stdin is closed. The server ends and its stdout
/// reaches the end within 5 s, which happens only when no process holds the write end: the launched
/// app, and every intermediate process of the launch, got no copy of the server's stdout. The app
/// still runs afterwards (it is the same one, `test-control/pid` unchanged).
///
/// Source: `launch/unix.rs` (`dup2` of `/dev/null` onto 0-2 and `close_range` in the grandchild
/// that executes the app; the first child exits before `spawn_detached` returns), `launch/windows.rs`
/// (`bInheritHandles = FALSE` and null standard handles for the shell-parented app, the stub and
/// the app the stub starts).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s02_mcp_stdout_closes_when_mcp_exits() -> Result<()> {
    if !opted_in("s02_mcp_stdout_closes_when_mcp_exits") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mut mcp = launch_session(
        &world,
        mcp_command(&world, LAUNCH_TIMEOUT),
        "mcp-flows-s02-eof",
    )
    .await?;
    let app_pid = wait_app_pid(&world).await?;

    let closed = Instant::now();
    mcp.close_stdin();
    mcp.wait_stdout_eof(EXIT_WITHIN).await?;
    let exit = mcp.wait_exit().await?;
    let took = closed.elapsed();
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    assert!(
        took < EXIT_WITHIN,
        "the server needed {took:?} to end after stdin closed (S-02: {EXIT_WITHIN:?})\n{}",
        mcp.transcript()
    );
    println!("S02 mcp exit: stdout closed and the server ended {took:?} after stdin closed");

    // The server is gone (its run has ended, so the lock probe cannot disturb a launch): the app
    // it launched still runs, and is the same one.
    assert!(
        world.app_running()?,
        "no process holds instance.lock after the server ended: the app died with it\n{}",
        world.diagnostics()
    );
    assert_eq!(
        fs::read_to_string(world.control_dir().join(PID_FILE))
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok()),
        Some(app_pid),
        "test-control/pid changed"
    );
    world.quit_app().await?;
    Ok(())
}

// ---- S-02: the app's parent ---------------------------------------------------------------------------

/// S-02 (§4.7, PD-21, PD-23), all OS: while `atlas-duck mcp` runs, the app it launched has a parent
/// that is neither the server nor the test. On Unix the app is also in another session and process
/// group than the server (which is in the test's own: the test does not start it in a new
/// session). On Windows the live ancestors of the app (`win::live_ancestors` stops at the dead
/// stub, or where a parent pid was reused) include neither the server nor the test.
///
/// Every read is made while the server still runs: once it has exited, a Unix orphan is reparented
/// to init or a subreaper whatever it was, so "ppid != server pid" alone would prove nothing. The
/// final call proves the server was the same live process throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s02_app_parent_is_not_mcp() -> Result<()> {
    if !opted_in("s02_app_parent_is_not_mcp") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mut mcp = launch_session(
        &world,
        mcp_command(&world, LAUNCH_TIMEOUT),
        "mcp-flows-s02-parent",
    )
    .await?;
    let mcp_pid = mcp.pid().ok_or("the server has no pid")?;
    let app_pid = wait_app_pid(&world).await?;
    let server = proc_facts(mcp_pid)?;
    let app = proc_facts(app_pid)?;
    let test_pid = std::process::id();
    println!(
        "S02 parent: app {app_pid} {app:?}, parent {}; mcp {mcp_pid} {server:?}; test {test_pid}",
        describe(app.ppid)
    );
    assert_ne!(app_pid, mcp_pid, "the app pid is the server's");
    assert_ne!(
        app.ppid, mcp_pid,
        "the app's parent is the MCP server {mcp_pid}"
    );
    assert_ne!(app.ppid, test_pid, "the app's parent is the test process");
    #[cfg(unix)]
    {
        let own = own_session()?;
        assert_eq!(
            server.session,
            Session::Id(own),
            "the server is not in the test's session: the comparison below would mean nothing"
        );
        assert_ne!(
            app.session,
            Session::Id(own),
            "the app is in the server's session {own} (no setsid in the launch)"
        );
        assert_ne!(
            app.pgid, server.pgid,
            "the app is in the server's process group"
        );
    }
    #[cfg(windows)]
    {
        let _ = server;
        let chain = win::live_ancestors(app_pid)?;
        let shell = win::shell_pid();
        let shown: Vec<String> = chain
            .iter()
            .map(|p| format!("{} {}", p.pid, p.exe))
            .collect();
        println!("S02 live ancestors of the app {app_pid}: {shown:?}; shell pid {shell:?}");
        assert!(
            !chain.iter().any(|p| p.pid == mcp_pid),
            "the MCP server {mcp_pid} is an ancestor of the app: {shown:?}"
        );
        assert!(
            !chain.iter().any(|p| p.pid == test_pid),
            "the test process {test_pid} is an ancestor of the app: {shown:?}"
        );
        // The positive form (plan: "the shell or the stub's exited pid"): the nearest live
        // ancestor is the shell process (step 1), or none is alive (step 2: the stub is gone).
        assert!(
            chain.is_empty() || Some(chain[0].pid) == shell,
            "the app's nearest live ancestor is neither the shell {shell:?} nor absent: {shown:?}"
        );
    }
    // The server lived through the reads above.
    let alive = mcp.call("instances_list", json!({}), None).await?;
    assert!(
        !alive.is_error(),
        "the server was not serving after the reads: {}\n{}",
        alive.structured(),
        mcp.transcript()
    );
    finish_session(&world, mcp).await
}

// ---- S-02: no console (Windows) ------------------------------------------------------------------------

/// S-02 / lead ruling R13 (Windows CI): desktop MCP clients start servers without a console, and
/// the M4 CI step runs `cli_flows` with `pwsh` for a console, so a launch or session check that
/// depends on a console would only show here. The server is created with `CREATE_NO_WINDOW`; the
/// auto-launch must succeed exactly as in the console case, and stdout carries only JSON-RPC.
/// Not `#[ignore]`d: it runs with the other flows. If it fails in CI, the cause is diagnosed from
/// the log (plan Step 2b); this test is not weakened to hide it.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s02_mcp_without_console_auto_launches() -> Result<()> {
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    if !opted_in("s02_mcp_without_console_auto_launches") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mut cmd = mcp_command(&world, LAUNCH_TIMEOUT);
    cmd.creation_flags(CREATE_NO_WINDOW);
    let mcp = launch_session(&world, cmd, "mcp-flows-s02-no-console").await?;
    finish_session(&world, mcp).await
}

// ---- S-02 / V13: killing the server's tree (Windows) ----------------------------------------------------

/// What the held read's first minutes produced: its request id (a notification said it was
/// submitted), or the call's answer before any id.
#[cfg(windows)]
enum Held {
    Submitted(String),
    Answered(CallOutcome),
}

/// After the server was killed: the same app (`test-control/pid` unchanged, the instance lock
/// still held) answers `status <id>` with `pending` over its endpoint.
///
/// Order matters: the lock and the pid are checked before the `status` run, because a `status`
/// against a dead app would cold-start a new one (and that one would not know a pending read of
/// the old one: I-26).
#[cfg(windows)]
async fn same_app_still_serves(world: &World, app_pid: u32, id: &str) -> Result<()> {
    assert!(
        world.app_running()?,
        "no process holds instance.lock after the kill: the app died with the server\n{}",
        world.diagnostics()
    );
    assert_eq!(
        pid_file_now(world),
        Some(app_pid),
        "test-control/pid changed: another app started\n{}",
        world.diagnostics()
    );
    let st = world.cli(&["status", id]).await?;
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

/// S-02 (CI): the server's process tree is killed while a read the approver holds is `pending`:
/// the server auto-launched the app for it, the app survives with the request still `pending`
/// (`atlas-duck status <id>` through the CLI), and `taskkill /T /F /PID <server>` ends the server.
/// The test adds no job object; the other acceptable outcome is the launch refused before any
/// request was made (`launch_blocked_by_job` or `not_running`, no request id, no app running, and
/// no shell window on this runner: with one, step 1 would have launched outside the job).
///
/// The kill runs only if the server's transitive descendants are, if any, console hosts, each
/// created after the server and none of them the app, and the app's parent is not the server.
/// Prints `V13 mcp_tree_kill_case=<survived|blocked> app_pid=<pid|none> shell_window=<some|none>`.
///
/// Source: `launch/windows.rs` `spawn_detached` (the app's parent is the shell, or the stub, which
/// already exited), the M4 twin `cli_flows/security.rs` `s02_app_survives_cli_tree_kill`.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI: S-02 step"]
async fn s02_app_survives_mcp_tree_kill() -> Result<()> {
    use crate::flows::submitted_id;

    ci_only(IGNORE_S02, std::env::var("CI").ok().as_deref())?;
    if !opted_in("s02_app_survives_mcp_tree_kill") {
        return Ok(());
    }
    let world = jira_world().await?;
    // The child is killed when `mcp` drops, so an early return leaves no server behind.
    let mut mcp = McpChild::new(mcp_command(&world, KILL_TIMEOUT).spawn()?)?;
    let mcp_pid = mcp.pid().ok_or("the server has no pid")?;
    mcp.initialize("mcp-flows-s02-tree-kill").await?;
    let call_id = mcp
        .send_call(
            "jira_issue_get",
            json!({"key": "ABC-1", "reason": "atlas-test:hold"}),
            Some(TOKEN),
        )
        .await?;

    let until = Instant::now() + SUBMITTED_WITHIN;
    let mut notes = Vec::new();
    let held = loop {
        if let Some(out) = mcp.poll_call(call_id, Duration::from_millis(200)).await? {
            break Held::Answered(out);
        }
        notes.extend(mcp.take_notifications());
        if let Some(id) = submitted_id(&notes, TOKEN) {
            break Held::Submitted(id);
        }
        if Instant::now() > until {
            return Err(format!(
                "no submitted notification and no answer within {SUBMITTED_WITHIN:?}\n{}\n{}",
                mcp.transcript(),
                world.diagnostics()
            )
            .into());
        }
    };
    // Step 1 of the launch needs a shell window (`GetShellWindow`) to take as parent: a runner
    // with one has no reason to refuse the launch.
    let shell_window = if win::has_shell_window() {
        "some"
    } else {
        "none"
    };

    match held {
        Held::Answered(out) => {
            let env = out.structured();
            assert!(
                is_blocked_result(out.is_error(), env),
                "the held read ended before it was submitted and without a launch refusal: \
                 {env}\n{}\n{}",
                mcp.transcript(),
                world.diagnostics()
            );
            assert!(
                !world.app_running()?,
                "the launch was refused but an app holds instance.lock\n{}",
                world.diagnostics()
            );
            assert_eq!(
                pid_file_now(&world),
                None,
                "the launch was refused but an app wrote test-control/pid"
            );
            assert_eq!(
                shell_window,
                "none",
                "the launch was refused although a shell window exists, so step 1 should have \
                 launched outside the job: {env}\n{}",
                world.diagnostics()
            );
            println!("V13 mcp_tree_kill_case=blocked app_pid=none shell_window={shell_window}");
            mcp.close_stdin();
            let exit = mcp.wait_exit().await?;
            assert!(exit.success(), "{exit}\n{}", mcp.transcript());
            Ok(())
        }
        Held::Submitted(id) => {
            let app_pid = wait_app_pid(&world).await?;
            let all = win::processes()?;
            let app = proc_facts(app_pid)?;
            assert_ne!(
                app.ppid, mcp_pid,
                "the app's parent is the MCP server: taskkill /T would end it"
            );
            let tree = win::descendants(&all, mcp_pid)?;
            let described: Vec<String> = tree
                .iter()
                .map(|p| format!("{} {}", p.pid, p.exe))
                .collect();
            println!("S02 descendants of the server {mcp_pid} before the kill: {described:?}");
            assert!(
                only_console_hosts(&tree, app_pid),
                "refusing taskkill /T on {mcp_pid}: its descendants are {described:?}, expected \
                 none or only console hosts"
            );
            let out = std::process::Command::new("taskkill")
                .args(["/T", "/F", "/PID", &mcp_pid.to_string()])
                .stdin(Stdio::null())
                .output()?;
            println!(
                "S02 taskkill /T /F /PID {mcp_pid}: {} {} {}",
                out.status,
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
            assert!(out.status.success(), "taskkill failed: {}", out.status);
            let status = mcp.wait_exit().await?;
            // A terminated process can stay listed for a moment while a handle to it is open.
            let start = Instant::now();
            while win::processes()?.iter().any(|p| p.pid == mcp_pid) {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "the server {mcp_pid} still runs 10 s after taskkill /T\n{}",
                    world.diagnostics()
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            println!(
                "S02 tree kill: the server ended with {status}; the app's parent was {}",
                describe(app.ppid)
            );
            same_app_still_serves(&world, app_pid, &id).await?;
            println!(
                "V13 mcp_tree_kill_case=survived app_pid={app_pid} shell_window={shell_window}"
            );
            world.quit_app().await?;
            Ok(())
        }
    }
}

// ---- unit tests of the pure helpers -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(list: &[&str]) -> Vec<String> {
        list.iter().map(|l| (*l).to_owned()).collect()
    }

    #[test]
    fn jsonrpc_lines_accept_the_three_message_kinds() {
        let ok = lines(&[
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":"x","method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-1,"message":"m"}}"#,
        ]);
        assert_eq!(check_jsonrpc_lines(&ok, 4), Ok(()));
        assert!(check_jsonrpc_lines(&ok, 5).is_err(), "too few lines");
        assert!(check_jsonrpc_lines(&[], 1).is_err());
    }

    #[test]
    fn jsonrpc_lines_reject_everything_else() {
        for bad in [
            "starting up...",
            "",
            "[]",
            r#"{"id":1,"result":{}}"#,
            r#"{"jsonrpc":"1.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0"}"#,
            r#"{"jsonrpc":"2.0","id":1}"#,
            r#"{"jsonrpc":"2.0","method":5}"#,
            r#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#,
        ] {
            let mixed = lines(&[r#"{"jsonrpc":"2.0","id":1,"result":{}}"#, bad]);
            let err = check_jsonrpc_lines(&mixed, 1).err();
            assert!(err.is_some(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn blocked_result_is_a_failed_unreachable_without_id() {
        let blocked = |reason: &str| {
            json!({"status": "failed", "request_id": null,
                   "error": {"code": "unreachable", "details": {"reason": reason}}})
        };
        for r in BLOCKED_REASONS {
            assert!(is_blocked_result(true, &blocked(r)), "{r}");
            assert!(!is_blocked_result(false, &blocked(r)), "{r}: not an error");
        }
        for r in ["launch_timeout", "no_gui_session", "connection_lost"] {
            assert!(!is_blocked_result(true, &blocked(r)), "{r}");
        }
        let mut with_id = blocked("not_running");
        with_id["request_id"] = json!("req_1");
        assert!(!is_blocked_result(true, &with_id));
        let mut other_code = blocked("not_running");
        other_code["error"]["code"] = json!("protocol_mismatch");
        assert!(!is_blocked_result(true, &other_code));
        assert!(!is_blocked_result(true, &json!({})));
    }

    #[cfg(windows)]
    #[test]
    fn only_console_hosts_below_the_server_and_never_the_app() {
        let proc = |pid: u32, exe: &str| win::Proc {
            pid,
            ppid: 1,
            exe: exe.to_owned(),
        };
        assert!(only_console_hosts(&[], 10));
        assert!(only_console_hosts(&[proc(5, "conhost.exe")], 10));
        assert!(only_console_hosts(&[proc(5, "CONHOST.EXE")], 10));
        assert!(!only_console_hosts(&[proc(5, "cmd.exe")], 10));
        assert!(!only_console_hosts(&[proc(10, "conhost.exe")], 10));
        assert!(!only_console_hosts(
            &[proc(5, "conhost.exe"), proc(6, "atlas-duck-app.exe")],
            10
        ));
    }
}
