//! `cli_flows` II (Task 24): cold start and launch hygiene (I-17, I-20, V12), the gate states over
//! the real endpoint (§2.5, PD-04, PD-35, PD-39), the data-dir and `doctor` cases (I-42, I-44,
//! §4.7), a crash and restart (I-26), a newer config (U-21) and two app instances (S-01).
//!
//! Like `flows.rs` every flow here spawns a binary and starts with `opted_in(..)`; the pure
//! helpers (allowlist predicates, the config and header edits, the `doctor` shape check) have unit
//! tests that run everywhere. The two `#[ignore]`d `locality-mounts` flows are compiled
//! everywhere and run by their own CI job (Task 26).
//!
//! A CLI-launched app has no stderr we can read (the CLI detaches it): such a flow observes it
//! through the endpoint file and the `test-control/` files only. `launch_blocked_by_job` is never
//! asserted (T15 review: it is not a guaranteed diagnosis).

use std::collections::BTreeSet;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use atlas_duck_app_lib::testing::control::{DELAY_STARTUP_FILE, QUIT_FILE};
use atlas_duck_app_lib::testing::keystore::{MODE_NOT_LOCAL, MODE_UNAVAILABLE, set_mode};
use atlas_duck_app_lib::testing::provision;
use atlas_duck_atlassian::testing::TEST_USER;
use atlas_duck_atlassian::testing::fixtures::{self, JIRA_9_12_VERSION};
use atlas_duck_audit::{DB_FILE, EntryName, EventFlags, EventType, KeyStore};
use atlas_duck_core::gate::MSG_FIRST_RUN;
use atlas_duck_ipc::envelope::{ErrorCode, Status};
use atlas_duck_ipc::paths::{
    CliToml, ENDPOINT_FILE, PINNED_SCHEMA_VERSION, PinnedPaths, write_cli_toml, write_pinned,
};
use serde_json::{Value, json};

use crate::flows::{
    audit_headers, check_run, data_at, detail, jira, jira_world, launch_artifacts, notices,
    request_rows, run, submit_pending, wait_status,
};
use crate::harness::{APP_EXE, CLI_EXE, CliRun, Result, World, WorldOpts, opted_in};

// ---- constants -------------------------------------------------------------------------------------

/// How long the app may take to publish its endpoint after a CLI (or a test) launched it.
const ENDPOINT_WITHIN: Duration = Duration::from_secs(30);
/// How long a spawned process that has to end does so within.
const ENDS_WITHIN: Duration = Duration::from_secs(60);
/// The mock holds the comment POST this long: the write stays `executing` while the app shuts
/// down (`gate_shutting_down_over_endpoint`).
const WRITE_HELD: Duration = Duration::from_secs(8);
/// `status req_000..`: an id of the right shape that no request has.
const NO_SUCH_ID: &str = "req_00000000000000000000000000000000";
const COMMENT_PARAMS: &str = r#"{"key":"ABC-1","body":"Seen on staging.","body_format":"wiki"}"#;

/// `launch::MSG_LAUNCH_TIMEOUT`.
const MSG_LAUNCH_TIMEOUT: &str =
    "the atlas-duck app did not become reachable in time; nothing was queued";
/// `discover::MSG_APP_NOT_FOUND` (§3.2).
const MSG_APP_NOT_FOUND: &str = "atlas-duck app not found; reinstall or re-run Install CLI to PATH";
/// `GateState::ShuttingDown.envelope()` (`crates/core/src/gate.rs`).
const MSG_SHUTTING_DOWN: &str = "atlas-duck is shutting down";
/// `GateState::StoreNewer.envelope()`.
const MSG_STORE_NEWER: &str =
    "the audit store was written by a newer atlas-duck; upgrade atlas-duck";

/// The PD-31 `data.local` keys (`crates/cli/src/doctor.rs` `local_checks`).
const LOCAL_KEYS: [&str; 15] = [
    "cli_version",
    "build_id",
    "install_mode",
    "app_path",
    "app_path_found",
    "on_path",
    "endpoint",
    "endpoint_exists",
    "data_dir",
    "data_dir_local",
    "data_dir_reason",
    "keyring_local",
    "job_blocks_breakaway",
    "wsl",
    "wsl_warning",
];
/// `data.app` of a serving `Core`: `engine/handler.rs` `doctor` (`instances`, `config_unreadable`,
/// `pac_configured`) plus `AppHandler::doctor` (`tray_host`, `secret_service`, `ipc_accepting`).
const APP_KEYS: [&str; 6] = [
    "instances",
    "config_unreadable",
    "pac_configured",
    "tray_host",
    "secret_service",
    "ipc_accepting",
];
/// `data.app.instances.<alias>` (PD-11, `engine/handler.rs` `doctor`).
const INSTANCE_KEYS: [&str; 9] = [
    "configured",
    "config_error",
    "reachable",
    "needs_token",
    "locked",
    "tls_error",
    "proxy_error",
    "identity_header",
    "version_supported",
];

// ---- pure helpers (unit-tested below) --------------------------------------------------------------

/// The names the CLI copies into a launched app's environment (`crates/cli/src/launch/env.rs`
/// `KEEP`, `TEST_KEEP` with `test-env`, `LC_*`, and the `PATH` it sets; Windows also adds
/// `SystemRoot`). `__CF_USER_TEXT_ENCODING` is what macOS itself may add to any process.
const ALLOWED_NAMES: [&[&str]; 4] = [
    &[
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "HOME",
        "USERPROFILE",
        "LANG",
        "TMP",
        "TEMP",
        "TMPDIR",
        "SystemRoot",
    ],
    &["ATLAS_DUCK_TEST_HOME", "ATLAS_DUCK_TEST_KEYSTORE"],
    &["PATH"],
    &["__CF_USER_TEXT_ENCODING"],
];

/// Windows names are case-insensitive, every other OS compares exactly.
fn same_name(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn is_allowed_name(name: &str) -> bool {
    let lc = name.len() > 3 && name.get(..3).is_some_and(|p| same_name(p, "LC_"));
    lc || ALLOWED_NAMES
        .iter()
        .flat_map(|names| names.iter())
        .any(|allowed| same_name(name, allowed))
}

/// The names of `names` that are not on the launched app's allowlist.
fn outside_allowlist(names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter(|n| !is_allowed_name(n))
        .cloned()
        .collect()
}

/// The names that must never reach a launched app, in any case: the proxy variables, the agent's
/// own name variable and the loader hooks.
fn hostile_names(names: &[String]) -> Vec<String> {
    const HOSTILE: [&str; 6] = [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "atlas_duck_agent",
        "ld_preload",
    ];
    names
        .iter()
        .filter(|n| {
            let lower = n.to_ascii_lowercase();
            HOSTILE.contains(&lower.as_str()) || lower.starts_with("dyld_")
        })
        .cloned()
        .collect()
}

/// The text of a `config.toml` as a newer binary would have written it: the root
/// `schema_version = 1` raised to 2 and a table this binary has never heard of appended. `None`
/// when the file has no root `schema_version = 1` line.
fn with_newer_schema(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut at_root = true;
    let mut raised = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            at_root = false;
        }
        let is_version = at_root
            && trimmed
                .split_once('=')
                .is_some_and(|(k, v)| k.trim() == "schema_version" && v.trim() == "1");
        if is_version && !raised {
            out.push_str("schema_version = 2\n");
            raised = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !raised {
        return None;
    }
    out.push_str("\n[from_a_newer_release]\nsome_new_key = true\n");
    Some(out)
}

/// SQLite file format: bytes 60..64 of the main database file are the big-endian `user_version`.
/// The audit store refuses a `user_version` above its own head (`schema::gate_up_to`, PD-39).
fn set_user_version(db: &Path, version: u32) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new().read(true).write(true).open(db)?;
    file.seek(SeekFrom::Start(60))?;
    file.write_all(&version.to_be_bytes())?;
    file.sync_all()
}

fn keys_of(v: &Value) -> BTreeSet<String> {
    v.as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn expect_keys(what: &str, v: &Value, want: &[&str], problems: &mut Vec<String>) {
    let have = keys_of(v);
    let want: BTreeSet<String> = want.iter().map(|k| (*k).to_owned()).collect();
    if have != want {
        problems.push(format!("{what}: keys {have:?}, expected {want:?}"));
    }
}

/// Everything §4.7 / PD-31 / PD-11 / PD-30 say about the shape of a `doctor` answer from a
/// serving `Core` with the instances `aliases`; `leaks` are strings that must not appear anywhere.
fn doctor_problems(data: &Value, aliases: &[&str], linux: bool, leaks: &[&str]) -> Vec<String> {
    let mut p = Vec::new();
    expect_keys("data", data, &["local", "app", "app_unavailable"], &mut p);
    expect_keys("data.local", &data["local"], &LOCAL_KEYS, &mut p);
    expect_keys("data.app", &data["app"], &APP_KEYS, &mut p);
    if !data["app_unavailable"].is_null() {
        p.push(format!("app_unavailable: {}", data["app_unavailable"]));
    }
    let instances = &data["app"]["instances"];
    expect_keys("data.app.instances", instances, aliases, &mut p);
    for alias in aliases {
        expect_keys(
            &format!("data.app.instances.{alias}"),
            &instances[*alias],
            &INSTANCE_KEYS,
            &mut p,
        );
    }
    for key in ["tray_host", "secret_service"] {
        let v = &data["app"][key];
        if linux != v.is_string() || (!linux && !v.is_null()) {
            p.push(format!("app.{key} is {v} (linux: {linux})"));
        }
    }
    if !data["app"]["pac_configured"].is_boolean() {
        p.push(format!(
            "app.pac_configured: {}",
            data["app"]["pac_configured"]
        ));
    }
    let text = data.to_string();
    for needle in std::iter::once(&"://").chain(leaks) {
        if text.contains(needle) {
            p.push(format!("the answer contains {needle:?}"));
        }
    }
    p
}

// ---- helpers that touch the machine ----------------------------------------------------------------

/// Waits (30 s) until `<data>/endpoint` exists.
async fn wait_for_endpoint(world: &World) -> Result<()> {
    let path = world.data_dir().join(ENDPOINT_FILE);
    let start = Instant::now();
    loop {
        if path.try_exists()? {
            return Ok(());
        }
        if start.elapsed() > ENDPOINT_WITHIN {
            return Err(format!("no {} within {ENDPOINT_WITHIN:?}", path.display()).into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn endpoint_exists(world: &World) -> Result<bool> {
    Ok(world.data_dir().join(ENDPOINT_FILE).try_exists()?)
}

/// The envelope of `r` is a failure with this exit code, error code, `details.reason`, message,
/// `retryable: true`, no request id and no data: the shape of every gate and every launch refusal
/// (`gate.rs` `GateState::envelope`, `discover.rs` `refusal`, `launch/mod.rs`).
fn expect_failure(
    r: &CliRun,
    exit: i32,
    code: ErrorCode,
    reason: &str,
    message: &str,
) -> Result<()> {
    let env = r
        .envelope
        .as_ref()
        .ok_or_else(|| format!("no envelope: {:?}", r.stdout))?;
    let err = env
        .error
        .as_ref()
        .ok_or_else(|| format!("no error: {}", r.stdout))?;
    let found = detail(env, "reason").and_then(Value::as_str);
    if r.exit != exit
        || env.status != Status::Failed
        || err.code != code
        || !err.retryable
        || found != Some(reason)
        || err.message != message
        || env.request_id.is_some()
        || env.data.is_some()
    {
        return Err(format!(
            "expected exit {exit} {code:?} reason {reason:?} message {message:?} (retryable): got exit {}: {}",
            r.exit, r.stdout
        )
        .into());
    }
    Ok(())
}

/// `data` of a `doctor` run: exit 0 and `status: succeeded` are checked here.
fn doctor_data(r: &CliRun) -> Result<&Value> {
    let env = r.envelope.as_ref().ok_or("no envelope")?;
    if r.exit != 0 || env.status != Status::Succeeded {
        return Err(format!("doctor: exit {}: {}", r.exit, r.stdout).into());
    }
    env.data
        .as_ref()
        .ok_or_else(|| format!("doctor: no data: {}", r.stdout).into())
}

/// `atlas-duck <args>` through the executable `exe` (a copy of the CLI, say) with the world's
/// environment; the same checks as `run`.
async fn run_exe(world: &World, exe: &Path, args: &[&str]) -> Result<CliRun> {
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(args).env_clear().current_dir(world.root());
    for (k, v) in world.env() {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let child = cmd.spawn()?;
    let out = tokio::time::timeout(ENDS_WITHIN, child.wait_with_output())
        .await
        .map_err(|_| {
            format!(
                "{} {args:?} did not end within {ENDS_WITHIN:?}",
                exe.display()
            )
        })??;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let r = CliRun {
        envelope: crate::harness::parse_envelope(&stdout),
        exit: out.status.code().unwrap_or(-1),
        stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    check_run(args, &r)?;
    Ok(r)
}

fn pinned_dir(world: &World) -> Result<PathBuf> {
    Ok(world
        .pinned_file()
        .parent()
        .ok_or("the pinned file has no parent")?
        .to_path_buf())
}

fn no_launch_artifacts(world: &World, data: &Path) -> Result<()> {
    let left = launch_artifacts(data, &pinned_dir(world)?)?;
    if left.is_empty() {
        Ok(())
    } else {
        Err(format!("a launch left {left:?}").into())
    }
}

fn app_start_count(world: &World) -> Result<usize> {
    Ok(audit_headers(world)?
        .iter()
        .filter(|h| h.event_type == EventType::APP_START)
        .count())
}

/// A loopback listener that counts the connections it is offered: the "proxy" of the I-20 flow.
struct ProxyTrap {
    url: String,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ProxyTrap {
    fn start() -> Result<ProxyTrap> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let url = format!("http://{}", listener.local_addr()?);
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen, done) = (hits.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok(_) => {
                        seen.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        Ok(ProxyTrap {
            url,
            hits,
            stop,
            thread: Some(thread),
        })
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for ProxyTrap {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// ---- I-17: cold start and the deadline ---------------------------------------------------------------

/// I-17: with no app running, `jira issue get --timeout 30 --reason atlas-test:hold` launches the
/// app, submits, and waits out the deadline: exit 4 `pending` (the server's own pending envelope,
/// which carries `op_id` and `instance`) after about 30 s, with the one submission notice on
/// stderr. The app was launched: its endpoint exists afterwards.
///
/// Source: `launch/mod.rs` `ensure_running` (spawn + poll for the endpoint), `connected.rs`
/// `submit_wait` (notice, then `await_request` with the time left to the deadline), core
/// `handler.rs` `await_request` (answers pending at the timeout), `exit.rs` (pending is 4).
/// The lower bound is 29 s: the deadline is wall clock from the CLI's own start, which is after
/// the test's. A cold start slower than 30 s would end `launch_timeout` instead (exit 5).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i17_cold_start_within_timeout() -> Result<()> {
    if !opted_in("i17_cold_start_within_timeout") {
        return Ok(());
    }
    let world = jira_world().await?;
    assert!(!endpoint_exists(&world)?, "an endpoint before any launch");
    let args = [
        "jira",
        "issue",
        "get",
        "ABC-1",
        "--timeout",
        "30",
        "--reason",
        "atlas-test:hold",
    ];
    let start = Instant::now();
    let r = run(&world, &args).await?;
    let took = start.elapsed();
    assert_eq!(r.exit, 4, "{}", r.stdout);
    let env = r.envelope.as_ref().ok_or("no envelope")?;
    assert_eq!(env.status, Status::Pending, "{}", r.stdout);
    assert!(env.error.is_none(), "{}", r.stdout);
    assert_eq!(env.op_id.as_deref(), Some("jira.issue.get"));
    assert_eq!(env.instance.as_deref(), Some("jira-main"));
    let (found, other) = notices(&r.stderr);
    assert_eq!((found.len(), other), (1, 0), "stderr: {:?}", r.stderr);
    assert_eq!(Some(&found[0].request_id), env.request_id.as_ref());
    assert!(
        took >= Duration::from_secs(29) && took < Duration::from_secs(40),
        "the run took {took:?}"
    );
    assert!(endpoint_exists(&world)?, "the app was not launched");
    Ok(())
}

/// I-17: a deadline that runs out before the app is up ends `unreachable {launch_timeout}`
/// (exit 5, `retryable: true`, no request id): nothing was submitted, so once the app is up
/// `requests list` is empty.
///
/// `test-control/delay-startup-ms = 3000` (the app sleeps before its first `open`, `serve.rs`
/// `start`) and `--timeout 1`: `ensure_running` spawns the app, polls for `min(20 s, remaining)`
/// and returns `launch_timeout` (`launch/mod.rs`, last arm: a data dir without an endpoint). The
/// upper bound is far under the 20 s poll limit and absorbs a slow launch on a loaded runner. A
/// first `ops list` runs the CLI once without the app, so the 1 s deadline does not meet the
/// first start of a freshly built executable (a virus scan on Windows).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i17_deadline_before_submission_launch_timeout() -> Result<()> {
    if !opted_in("i17_deadline_before_submission_launch_timeout") {
        return Ok(());
    }
    let world = jira_world().await?;
    run(&world, &["ops", "list"]).await?;
    world.write_control(DELAY_STARTUP_FILE, "3000")?;
    let start = Instant::now();
    let r = run(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--timeout",
            "1",
            "--reason",
            "atlas-test:release",
        ],
    )
    .await?;
    let took = start.elapsed();
    expect_failure(
        &r,
        5,
        ErrorCode::Unreachable,
        "launch_timeout",
        MSG_LAUNCH_TIMEOUT,
    )?;
    assert!(took < Duration::from_secs(15), "the run took {took:?}");
    // The launched app comes up after its delay; nothing was queued.
    wait_for_endpoint(&world).await?;
    let list = run(&world, &["requests", "list"]).await?;
    assert_eq!(list.exit, 0, "{}", list.stdout);
    let rows = request_rows(list.envelope.as_ref().ok_or("no envelope")?);
    assert!(rows.is_empty(), "a request was queued: {rows:?}");
    Ok(())
}

/// `--timeout 0` on a cold start: the pre-submission steps keep their own limits (the 20 s
/// poll, 30 s per step), so the app is launched, the request submitted, the notice printed and
/// the pending envelope returned at once (exit 4); the request is `pending` in the app.
///
/// Source: `connected.rs` `submit_wait` (`opts.timeout == Some(0)` returns the submit reply after
/// the notice), `deadline.rs` (`Some(0)` is unbounded), `submit_pending` checks exit 4, status
/// `pending` and the one notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_zero_returns_pending_after_cold_start() -> Result<()> {
    if !opted_in("timeout_zero_returns_pending_after_cold_start") {
        return Ok(());
    }
    let world = jira_world().await?;
    let id = submit_pending(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--reason",
            "atlas-test:hold",
        ],
    )
    .await?;
    assert!(endpoint_exists(&world)?, "the app was not launched");
    let st = run(&world, &["status", &id]).await?;
    assert_eq!(st.exit, 0, "{}", st.stdout);
    assert_eq!(
        st.envelope.as_ref().map(|e| e.status),
        Some(Status::Pending)
    );
    Ok(())
}

// ---- I-20: the launched app's environment --------------------------------------------------------------

/// A `PATH` of the test's own that holds nothing (the directory need not exist).
#[cfg(windows)]
const TEST_PATH: &str = r"C:\atlas-duck-test-path";
#[cfg(not(windows))]
const TEST_PATH: &str = "/atlas-duck-test-path";

/// I-20 (§4.7): the CLI is started with proxy variables in three spellings, the agent's name
/// variable, a loader hook and a hostile `PATH`; the app it launches has none of them. Its
/// `test-control/env-names.json` (names only, written by the app at start) holds no proxy name in
/// any case, no `ATLAS_DUCK_AGENT`, no `LD_PRELOAD`, and every name is on the allowlist (plus
/// `PATH`, and `SystemRoot` on Windows, and the two test variables).
///
/// Source: `launch/env.rs` (`KEEP`, `TEST_KEEP`, `LC_*`, the system `PATH`; Windows `windows.rs`
/// adds `SystemRoot` and `PATH`), `testing/control.rs` `write_env_names`. The subset check is the
/// likeliest assertion to fail: a name the app itself sets (GTK, WebKit, CoreFoundation) before
/// the control dir writes the file would show up here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i20_launched_app_env_allowlist_no_proxy() -> Result<()> {
    if !opted_in("i20_launched_app_env_allowlist_no_proxy") {
        return Ok(());
    }
    let opts = WorldOpts::default()
        .with_env("HTTP_PROXY", "http://127.0.0.1:9")
        .with_env("https_proxy", "http://127.0.0.1:9")
        .with_env("ALL_PROXY", "socks5://127.0.0.1:9")
        .with_env("NO_PROXY", "*")
        .with_env("ATLAS_DUCK_AGENT", "agent-from-env")
        .with_env("LD_PRELOAD", "/atlas-duck-test-path/preload.so")
        .with_env("PATH", TEST_PATH);
    let mut world = World::new(opts)?;
    world
        .provision_store(&[("jira-main", atlas_duck_registry::Product::Jira)])
        .await?;
    let r = run(&world, &["instances"]).await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    let names = world.env_names()?;
    assert!(
        names.iter().any(|n| same_name(n, "ATLAS_DUCK_TEST_HOME")),
        "env-names.json is not the launched app's: {names:?}"
    );
    assert!(names.iter().any(|n| same_name(n, "PATH")), "{names:?}");
    assert_eq!(hostile_names(&names), Vec::<String>::new(), "{names:?}");
    assert_eq!(outside_allowlist(&names), Vec::<String>::new(), "{names:?}");
    Ok(())
}

/// I-20: with `HTTP_PROXY`/`HTTPS_PROXY` (both cases) pointing at a loopback listener, a release
/// flow through a CLI-launched app completes (the mock saw the request) and the listener was
/// never connected to.
///
/// The harness provisions the instance with `ProxySetting::Direct`, so the app would not use an
/// environment proxy for it in any case: this flow shows nothing leaks through the launch, it
/// does not exercise the "system proxy" setting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i20_launched_app_sends_nothing_through_env_proxy() -> Result<()> {
    if !opted_in("i20_launched_app_sends_nothing_through_env_proxy") {
        return Ok(());
    }
    let trap = ProxyTrap::start()?;
    let opts = WorldOpts::default()
        .with_env("HTTP_PROXY", &trap.url)
        .with_env("HTTPS_PROXY", &trap.url)
        .with_env("http_proxy", &trap.url)
        .with_env("https_proxy", &trap.url);
    let mut world = World::new(opts)?;
    world
        .provision_store(&[("jira-main", atlas_duck_registry::Product::Jira)])
        .await?;
    let r = run(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--reason",
            "atlas-test:release",
        ],
    )
    .await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    let reached = jira(&world)?
        .received()
        .await
        .iter()
        .any(|req| req.url.path().ends_with("/issue/ABC-1"));
    assert!(reached, "the mock never saw the request");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(trap.hits(), 0, "something connected to the env proxy");
    Ok(())
}

// ---- V12: no inherited handles -------------------------------------------------------------------------

/// The targets of `/proc/<pid>/fd`.
#[cfg(target_os = "linux")]
fn fd_links(pid: u32) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
        if let Ok(target) = fs::read_link(entry?.path()) {
            out.push(target);
        }
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
struct OpenFd(libc::c_int);

#[cfg(target_os = "linux")]
impl Drop for OpenFd {
    fn drop(&mut self) {
        // SAFETY: closes the descriptor `libc::open` returned; it is closed once, here.
        unsafe {
            libc::close(self.0);
        }
    }
}

/// V12 (Linux): the test opens a file WITHOUT `O_CLOEXEC`, so every child it spawns inherits the
/// descriptor; the CLI cold-starts the app; `/proc/<app pid>/fd` has no link to the file. Two
/// controls make the absence mean something: a plain child of the test (`sleep`) does inherit
/// the descriptor, and the app's own `instance.lock` shows in its table.
///
/// Source: `launch/unix.rs` (double fork, exec with the allowlisted environment), `test-control/pid`
/// (written by the app at start). The Windows half (an inheritable event, `test-control/marker`)
/// is Task 25's; macOS has no flow here (no `/proc`, no cheap fd listing without a helper binary).
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v12_launched_app_inherits_no_handles() -> Result<()> {
    use std::os::unix::ffi::OsStrExt;

    use atlas_duck_app_lib::testing::control::PID_FILE;
    if !opted_in("v12_launched_app_inherits_no_handles") {
        return Ok(());
    }
    let world = jira_world().await?;
    let marker = world.root().join("v12-marker");
    fs::write(&marker, b"v12")?;
    let marker = fs::canonicalize(&marker)?;
    let path = std::ffi::CString::new(marker.as_os_str().as_bytes())?;
    // SAFETY: `path` is a valid NUL-terminated string that outlives the call; `open` has no
    // other precondition. No `O_CLOEXEC` on purpose: the descriptor must reach children.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let _fd = OpenFd(fd);

    // Control 1: a direct child inherits it.
    let mut sleeper = std::process::Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let inherited = fd_links(sleeper.id());
    let _ = sleeper.kill();
    let _ = sleeper.wait();
    assert!(
        inherited?.contains(&marker),
        "the test's own child did not inherit the marker: the flow proves nothing"
    );

    // The CLI inherits it too and cold-starts the app.
    let r = run(&world, &["instances"]).await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    let pid_file = world.control_dir().join(PID_FILE);
    let start = Instant::now();
    let pid: u32 = loop {
        if let Some(pid) = fs::read_to_string(&pid_file)
            .ok()
            .and_then(|t| t.trim().parse().ok())
        {
            break pid;
        }
        if start.elapsed() > Duration::from_secs(10) {
            return Err("the app wrote no test-control/pid".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let links = fd_links(pid)?;
    // Control 2: the app's table is readable and holds its own lock file.
    assert!(
        links.iter().any(|l| l.ends_with("instance.lock")),
        "no instance.lock among the app's descriptors: {links:?}"
    );
    assert!(
        !links.contains(&marker),
        "the launched app inherited the marker descriptor: {links:?}"
    );
    Ok(())
}

// ---- gate states over the endpoint --------------------------------------------------------------------

/// §2.5 / PD-04 / L46: a pinned data dir with no store (first run): a launched app serves the
/// first-run gate. Every op is `not_configured {first_run}` (exit 9, the message verbatim,
/// `retryable: true`, no request id); `doctor` still answers (exit 0, `data.app.gate ==
/// first_run`, the app's extras); `ops list` is local and unchanged, `ops list --instance` and
/// `instances` are the gate's envelope.
///
/// Source: `serve.rs` `Opener::first_open` (no `audit.db` -> `FirstRun`), `core/gate.rs`
/// (`GateHandler`: every method but `hello`, `doctor` and the local ops answers the state's
/// envelope; `doctor` is `{gate: first_run}`), `app_handler.rs` (the extras).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gate_first_run_over_endpoint() -> Result<()> {
    if !opted_in("gate_first_run_over_endpoint") {
        return Ok(());
    }
    let world = World::new(WorldOpts::default())?;
    let first =
        |r: &CliRun| expect_failure(r, 9, ErrorCode::NotConfigured, "first_run", MSG_FIRST_RUN);
    let r = run(&world, &["jira", "search", "project = ABC"]).await?;
    first(&r)?;
    let r = run(&world, &["instances"]).await?;
    first(&r)?;
    let r = run(&world, &["ops", "list", "--instance", "jira-main"]).await?;
    first(&r)?;

    let list = run(&world, &["ops", "list"]).await?;
    assert_eq!(
        list.stdout,
        atlas_duck_core::ops_list_local().to_json_line()
    );

    let r = run(&world, &["doctor"]).await?;
    let data = doctor_data(&r)?;
    assert_eq!(data["app"]["gate"], "first_run", "{}", r.stdout);
    assert_eq!(data["app"]["ipc_accepting"], true, "{}", r.stdout);
    assert!(data["app_unavailable"].is_null(), "{}", r.stdout);
    expect_keys("data.local", &data["local"], &LOCAL_KEYS, &mut Vec::new());
    Ok(())
}

/// One world whose store is locked in a way `prepare` sets up: a launched app serves the locked
/// gate and an op is `locked {reason}`: exit 9, `retryable: true`, the fixed message.
async fn locked_case(
    case: &str,
    reason: &str,
    prepare: impl FnOnce(&World) -> Result<()>,
) -> Result<()> {
    let world = jira_world().await?;
    prepare(&world)?;
    let r = run(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--reason",
            "atlas-test:release",
        ],
    )
    .await?;
    expect_failure(
        &r,
        9,
        ErrorCode::Locked,
        reason,
        &format!("atlas-duck is locked ({reason})"),
    )
    .map_err(|e| format!("{case}: {e}").into())
}

/// §8.7 / §2.5: the three locked reasons over the endpoint, one world each (the keystore mode or
/// entry is changed AFTER provisioning): the file keystore in mode `unavailable` ->
/// `keychain_unavailable`, in mode `not_local` -> `keyring_not_local`, and the `kek` entry file
/// deleted -> `keychain_lost`.
///
/// Source: `audit/open.rs` `preflight` (locality first, then the canary self-test, then the KEK:
/// `Ok(None)` is `KeychainLost`), `testing/keystore.rs` (modes), `serve.rs` (the gate is served
/// for every `Locked`; `keychain_unavailable` also starts the retry loop, which keeps failing).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gate_locked_reasons_over_endpoint() -> Result<()> {
    if !opted_in("gate_locked_reasons_over_endpoint") {
        return Ok(());
    }
    locked_case("unavailable", "keychain_unavailable", |w| {
        Ok(set_mode(w.keys_dir(), MODE_UNAVAILABLE)?)
    })
    .await?;
    locked_case("not_local", "keyring_not_local", |w| {
        Ok(set_mode(w.keys_dir(), MODE_NOT_LOCAL)?)
    })
    .await?;
    locked_case("kek deleted", "keychain_lost", |w| {
        let keys = provision(w.keys_dir(), w.install_id())?;
        keys.delete(&EntryName::Kek)
            .map_err(|e| format!("delete kek: {e:?}"))?;
        Ok(())
    })
    .await
}

/// PD-39 / §8.13: a store whose `user_version` is newer than this binary's is never opened: a
/// launched app serves the `store_newer` gate. An op is `unreachable {store_newer}` (exit 5,
/// `retryable: true`), `doctor` says `gate == store_newer`.
///
/// The store is made newer by writing the SQLite header's `user_version` (bytes 60..64, big
/// endian) of the cleanly shut down `audit.db`; `schema.rs` `read_versions` reads it through
/// `PRAGMA user_version` on a read-only, WAL-ignoring connection. No `-wal` or `-shm` file may
/// exist (`Store::shutdown` leaves none, T20).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gate_store_newer_over_endpoint() -> Result<()> {
    if !opted_in("gate_store_newer_over_endpoint") {
        return Ok(());
    }
    let world = jira_world().await?;
    let db = world.data_dir().join(DB_FILE);
    for sidecar in [format!("{DB_FILE}-wal"), format!("{DB_FILE}-shm")] {
        let path = world.data_dir().join(sidecar);
        if path.try_exists()? {
            return Err(format!("{} exists after a clean shutdown", path.display()).into());
        }
    }
    set_user_version(&db, 99)?;
    let r = run(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--reason",
            "atlas-test:release",
        ],
    )
    .await?;
    expect_failure(
        &r,
        5,
        ErrorCode::Unreachable,
        "store_newer",
        MSG_STORE_NEWER,
    )?;
    let d = run(&world, &["doctor"]).await?;
    assert_eq!(
        doctor_data(&d)?["app"]["gate"],
        "store_newer",
        "{}",
        d.stdout
    );
    Ok(())
}

/// §2.5 step 1 over the endpoint: while the app shuts down with a write still `executing` (the
/// mock answers the comment POST after 8 s), a new submit is refused `unreachable
/// {app_shutting_down}` (exit 5, `retryable: true`); then the write ends (`WRITE_EXECUTED`
/// before `APP_STOP`) and the app exits.
///
/// Source: `core.rs` `shutdown` / `engine::enter_submit` (a submit after `begin_shutdown` gets
/// `GateState::ShuttingDown.envelope()`; other methods keep working), `shutdown.rs` `sweep` (an
/// `executing` write is waited for up to 60 s), `testing/control.rs` (`quit` runs
/// `serve::shutdown_then_exit`, polled every 100 ms). The control file is polled, so the first
/// submit can land before the app noticed it: the submits are repeated (every 200 ms, for 5 s)
/// until one meets the shutdown; an early one is just a pending request that the sweep
/// cancels.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gate_shutting_down_over_endpoint() -> Result<()> {
    if !opted_in("gate_shutting_down_over_endpoint") {
        return Ok(());
    }
    let world = jira_world().await?;
    jira(&world)?
        .json_delayed(
            "/rest/api/2/issue/ABC-1/comment",
            201,
            fixtures::JIRA_COMMENT,
            WRITE_HELD,
        )
        .await;
    let write = submit_pending(
        &world,
        &[
            "call",
            "jira.comment.add",
            "--params",
            COMMENT_PARAMS,
            "--reason",
            "atlas-test:approve",
        ],
    )
    .await?;
    wait_status(&world, &write, |e| e.status == Status::Executing).await?;
    world.write_control(QUIT_FILE, "")?;

    let until = Instant::now() + Duration::from_secs(5);
    let refused = loop {
        let r = run(&world, &["jira", "issue", "get", "ABC-1", "--timeout", "0"]).await?;
        if r.exit == 5 {
            break r;
        }
        if Instant::now() > until {
            return Err(format!("no submit met the shutdown; the last: {}", r.stdout).into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    expect_failure(
        &refused,
        5,
        ErrorCode::Unreachable,
        "app_shutting_down",
        MSG_SHUTTING_DOWN,
    )?;

    world.wait_app_gone().await?;
    let headers = audit_headers(&world)?;
    let position = |t: EventType| {
        headers
            .iter()
            .position(|h| h.event_type == t && h.request_id.as_deref() == Some(write.as_str()))
    };
    let executed = position(EventType::WRITE_EXECUTED).ok_or("the write did not end executed")?;
    let stop = headers
        .iter()
        .rposition(|h| h.event_type == EventType::APP_STOP)
        .ok_or("no APP_STOP")?;
    assert!(executed < stop, "APP_STOP before the write's outcome");
    assert!(
        position(EventType::CANCELLED).is_none(),
        "the executing write was cancelled"
    );
    Ok(())
}

/// PD-35: the gate counts the four methods it refuses and only those. In first run one each of
/// `submit` (`jira search`), `script run`, `await` and `cancel` give `refused == 4` in
/// `test-control/refused`; `status`, `requests list` and `instances` (the state's envelope, not
/// counted) leave it at 4.
///
/// Source: `core/gate.rs` `GateHandler` (`refuse()` in `submit`, `submit_script`,
/// `await_request`, `cancel`; `status`, `requests_list`, `instances_list` answer
/// `state.envelope()`), `testing/control.rs` (the counter is mirrored every 100 ms, on change).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gate_refused_counter_four_methods() -> Result<()> {
    if !opted_in("gate_refused_counter_four_methods") {
        return Ok(());
    }
    let world = World::new(WorldOpts::default())?;
    let script = world.root().join("noop.js");
    fs::write(&script, "1 + 1\n")?;
    let script = script.to_string_lossy().into_owned();
    let counted: [Vec<&str>; 4] = [
        vec!["jira", "search", "project = ABC"],
        vec!["script", "run", &script],
        vec!["await", NO_SUCH_ID],
        vec!["cancel", NO_SUCH_ID],
    ];
    for args in &counted {
        let r = run(&world, args).await?;
        expect_failure(&r, 9, ErrorCode::NotConfigured, "first_run", MSG_FIRST_RUN)
            .map_err(|e| format!("{args:?}: {e}"))?;
    }
    let four = world
        .wait_refused(Duration::from_secs(5), |v| v == Some(4))
        .await?;
    assert_eq!(four, Some(Some(4)), "the refused count never reached 4");
    for args in [
        vec!["status", NO_SUCH_ID],
        vec!["requests", "list"],
        vec!["instances"],
    ] {
        let r = run(&world, &args).await?;
        expect_failure(&r, 9, ErrorCode::NotConfigured, "first_run", MSG_FIRST_RUN)
            .map_err(|e| format!("{args:?}: {e}"))?;
    }
    // The mirror runs every 100 ms: a late increment would show within this.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(world.refused_now()?, Some(Some(4)));
    Ok(())
}

// ---- I-42: data dir problems, nothing launched ------------------------------------------------------------

/// I-42: pinned to a data dir that was removed: the CLI refuses `not_configured
/// {data_dir_missing}` (exit 9) and launches nothing: no endpoint, no launch lock, the dir is not
/// re-created. `doctor` still exits 0 with `local.data_dir_reason` and `app_unavailable`.
///
/// Source: `discover.rs` `resolution_state` (`Missing` -> `refusal(data_dir_missing)`),
/// `launch/mod.rs` `ensure_running` step 1 (a refused data dir never launches), `doctor.rs`
/// `app_answer` / `local_checks`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i42_cli_data_dir_missing_no_launch() -> Result<()> {
    if !opted_in("i42_cli_data_dir_missing_no_launch") {
        return Ok(());
    }
    let world = World::new(WorldOpts::default())?;
    fs::remove_dir_all(world.data_dir())?;
    let r = run(&world, &["jira", "issue", "get", "ABC-1"]).await?;
    expect_failure(
        &r,
        9,
        ErrorCode::NotConfigured,
        "data_dir_missing",
        "atlas-duck is not configured (data_dir_missing)",
    )?;
    let d = run(&world, &["doctor"]).await?;
    let data = doctor_data(&d)?;
    assert_eq!(data["local"]["data_dir_reason"], "data_dir_missing");
    assert!(data["local"]["data_dir_local"].is_null(), "{}", d.stdout);
    assert!(data["app"].is_null(), "{}", d.stdout);
    assert_eq!(data["app_unavailable"]["reason"], "data_dir_missing");
    assert!(!world.data_dir().exists(), "the data dir was re-created");
    no_launch_artifacts(&world, world.data_dir())
}

/// A data dir on a volume that is not local, created and pinned for `world`: Linux an NFS mount
/// (`ATLAS_DUCK_TEST_NFS_DIR`, the locality-mounts job), Windows the administrative share of the
/// test home's own drive (`\\localhost\C$\...`). `None` elsewhere.
#[cfg(target_os = "linux")]
fn not_local_data_dir(_world: &World) -> Result<Option<PathBuf>> {
    let nfs = std::env::var("ATLAS_DUCK_TEST_NFS_DIR")
        .map_err(|_| "ATLAS_DUCK_TEST_NFS_DIR is not set (the locality-mounts job sets it)")?;
    let dir = Path::new(&nfs).join("data");
    fs::create_dir_all(&dir)?;
    Ok(Some(dir))
}

#[cfg(windows)]
fn not_local_data_dir(world: &World) -> Result<Option<PathBuf>> {
    let root = world.root().to_string_lossy().into_owned();
    let mut chars = root.chars();
    let (Some(drive), Some(':')) = (chars.next(), chars.next()) else {
        return Err(format!("the test home {root:?} has no drive letter").into());
    };
    let rest = chars.as_str().trim_start_matches('\\');
    let dir = PathBuf::from(format!(r"\\localhost\{drive}$\{rest}\unc-data"));
    fs::create_dir_all(&dir)?;
    Ok(Some(dir))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn not_local_data_dir(_world: &World) -> Result<Option<PathBuf>> {
    Ok(None)
}

/// I-42: pinned to a data dir that is not on a local volume: `not_configured
/// {data_dir_not_local}` (exit 9), nothing launched. Runs in the locality-mounts CI job.
///
/// Source: `discover.rs` `resolution_state` (`NotLocal`), `ensure_running` step 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI: locality-mounts job"]
async fn i42_cli_data_dir_not_local_no_launch() -> Result<()> {
    if !opted_in("i42_cli_data_dir_not_local_no_launch") {
        return Ok(());
    }
    let world = World::new(WorldOpts::default())?;
    let Some(dir) = not_local_data_dir(&world)? else {
        println!("not applicable: no non-local data dir on this OS");
        return Ok(());
    };
    write_pinned(
        &world.pinned_file(),
        &PinnedPaths {
            schema_version: PINNED_SCHEMA_VERSION,
            data_dir: dir.clone(),
            config_dir: world.config_dir().to_path_buf(),
            install_id: Some(world.install_id().to_owned()),
        },
    )
    .map_err(|e| format!("{e:?}"))?;
    let r = run(&world, &["jira", "issue", "get", "ABC-1"]).await?;
    expect_failure(
        &r,
        9,
        ErrorCode::NotConfigured,
        "data_dir_not_local",
        "atlas-duck is not configured (data_dir_not_local)",
    )?;
    no_launch_artifacts(&world, &dir)
}

/// I-42: the CLI alone in `<root>/bin` (no app next to it) with a `cli.toml` that names a missing
/// path: `unreachable {not_running}` (exit 5) with the §3.2 hint verbatim, never
/// `server_identity` (nothing was connected to), and nothing launched.
///
/// Source: `discover.rs` `locate_app` (`$APPIMAGE`, the app next to the executable, `cli.toml`'s
/// `app_path` if it is an existing file) -> `NotFound`, `ensure_running` step 3 -> `app_not_found()`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i42_cli_toml_missing_app_path_not_running() -> Result<()> {
    if !opted_in("i42_cli_toml_missing_app_path_not_running") {
        return Ok(());
    }
    let world = World::new(WorldOpts::default())?;
    let bin = world.root().join("bin");
    fs::create_dir_all(&bin)?;
    let exe = bin.join(Path::new(CLI_EXE).file_name().ok_or("no CLI file name")?);
    fs::copy(CLI_EXE, &exe)?;
    write_cli_toml(
        &world.cli_toml(),
        &CliToml {
            app_path: Some(world.root().join("gone").join("atlas-duck-app")),
        },
    )
    .map_err(|e| format!("{e:?}"))?;
    let r = run_exe(&world, &exe, &["jira", "issue", "get", "ABC-1"]).await?;
    expect_failure(
        &r,
        5,
        ErrorCode::Unreachable,
        "not_running",
        MSG_APP_NOT_FOUND,
    )?;
    no_launch_artifacts(&world, world.data_dir())
}

// ---- doctor ---------------------------------------------------------------------------------------------

/// §4.7 / PD-31 / PD-11 / PD-30: `doctor` against a serving `Core` with one instance: exit 0;
/// `data.local` has exactly the PD-31 keys; `data.app` exactly the six app keys, with
/// `instances.jira-main` exactly the nine PD-11 keys (not configured away, no token needed, not
/// locked); `tray_host` and `secret_service` are strings on Linux and `null` elsewhere; the whole
/// answer holds no `://`, no mock user and no mock version string.
///
/// Source: `doctor.rs` `local_checks`, `engine/handler.rs` `doctor`, `app_handler.rs`
/// `DoctorExtras::fields`, `secret_service.rs` (`Some(..)` on every Linux probe),
/// `tray_host.rs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_reports_section_4_7_fields() -> Result<()> {
    if !opted_in("doctor_reports_section_4_7_fields") {
        return Ok(());
    }
    let world = jira_world().await?;
    let r = run(&world, &["doctor"]).await?;
    let data = doctor_data(&r)?;
    let problems = doctor_problems(
        data,
        &["jira-main"],
        cfg!(target_os = "linux"),
        &[TEST_USER, JIRA_9_12_VERSION],
    );
    assert!(problems.is_empty(), "{problems:#?}\n{}", r.stdout);
    let local = &data["local"];
    assert_eq!(local["app_path_found"], true);
    assert_eq!(local["endpoint_exists"], true);
    assert_eq!(local["data_dir_local"], true);
    assert!(local["data_dir_reason"].is_null());
    assert_eq!(data["app"]["ipc_accepting"], true);
    let row = &data["app"]["instances"]["jira-main"];
    assert_eq!(row["configured"], true, "{row}");
    assert_eq!(row["needs_token"], false, "{row}");
    assert_eq!(row["locked"], false, "{row}");
    Ok(())
}

/// I-44 (Linux, locality-mounts job): `doctor` reports `local.keyring_local == false` when
/// `XDG_DATA_HOME` is on an NFS mount (`$ATLAS_DUCK_TEST_NFS_DIR/xdg`) and `true` when it is on
/// the local disk.
///
/// Source: `doctor.rs` `keyring_local_for` (`keyring_dirs_for` lists `$XDG_DATA_HOME/keyrings`
/// and `kwalletd` and the home's `.local/share` ones; one that is not local makes the answer
/// `false`; a dir that does not exist is judged by its nearest existing ancestor).
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI: locality-mounts job"]
async fn i44_doctor_keyring_local_false_on_nfs() -> Result<()> {
    if !opted_in("i44_doctor_keyring_local_false_on_nfs") {
        return Ok(());
    }
    let nfs = std::env::var("ATLAS_DUCK_TEST_NFS_DIR")
        .map_err(|_| "ATLAS_DUCK_TEST_NFS_DIR is not set (the locality-mounts job sets it)")?;
    let on_nfs = Path::new(&nfs).join("xdg");
    fs::create_dir_all(&on_nfs)?;
    let local = World::new(WorldOpts::default())?;
    let on_disk = local.root().join("xdg");
    fs::create_dir_all(&on_disk)?;
    drop(local);
    for (xdg, want) in [(on_nfs, false), (on_disk, true)] {
        let world =
            World::new(WorldOpts::default().with_env("XDG_DATA_HOME", &xdg.to_string_lossy()))?;
        let r = run(&world, &["doctor"]).await?;
        let data = doctor_data(&r)?;
        assert_eq!(
            data["local"]["keyring_local"],
            json!(want),
            "XDG_DATA_HOME {}: {}",
            xdg.display(),
            r.stdout
        );
    }
    Ok(())
}

// ---- I-26: crash and restart --------------------------------------------------------------------------------

/// I-26 (app half): a read that is `pending` when the app is killed hard is `abandoned` after the
/// restart: `await <id>` gives exit 7 `abandoned`, `retryable: true`. The restart went through
/// the real `audit::open` and `Core::start`: one `ABANDONED` record for the request, no record
/// carries the integrity-incident flag (the startup `VERIFY` of the unclean store found no
/// incident; an informational `VERIFY` row would be allowed), and the log holds exactly two more
/// `APP_START` records than before the run.
///
/// Source: `core.rs` `start` (the §11.3 reconciliation after `open`), `engine/envelope.rs`
/// (`ABANDONED` -> exit 7, retryable), `audit/verify.rs` (a `VERIFY` row only for a finding;
/// `integrity_incident` is set on incident findings only, `writer.rs`).
/// Hard kill: `AppProc::kill_hard` (the app pid only).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i26_app_killed_pending_read_abandoned_after_restart() -> Result<()> {
    if !opted_in("i26_app_killed_pending_read_abandoned_after_restart") {
        return Ok(());
    }
    let world = jira_world().await?;
    let before = app_start_count(&world)?;
    let mut app = world.start_app().await?;
    let id = submit_pending(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--reason",
            "atlas-test:hold",
        ],
    )
    .await?;
    app.kill_hard()?;
    let _restarted = world.start_app().await?;
    let r = run(&world, &["await", &id]).await?;
    assert_eq!(r.exit, 7, "{}", r.stdout);
    let env = r.envelope.as_ref().ok_or("no envelope")?;
    assert_eq!(env.status, Status::Abandoned, "{}", r.stdout);
    assert_eq!(env.request_id.as_deref(), Some(id.as_str()));
    let err = env.error.as_ref().ok_or("no error")?;
    assert_eq!((err.code, err.retryable), (ErrorCode::Abandoned, true));

    world.quit_app().await?;
    let headers = audit_headers(&world)?;
    let abandoned = headers
        .iter()
        .filter(|h| {
            h.event_type == EventType::ABANDONED && h.request_id.as_deref() == Some(id.as_str())
        })
        .count();
    assert_eq!(abandoned, 1, "ABANDONED records for {id}");
    assert!(
        headers
            .iter()
            .all(|h| !h.flags.contains(EventFlags::INTEGRITY_INCIDENT)),
        "a record carries the integrity-incident flag"
    );
    let starts = headers
        .iter()
        .filter(|h| h.event_type == EventType::APP_START)
        .count();
    assert_eq!(starts, before + 2);
    Ok(())
}

// ---- U-21: a newer config ----------------------------------------------------------------------------------------

/// U-21 (M4 clause): a `config.toml` written by a newer release (`schema_version = 2` and a table
/// this binary does not know) does not stop the app: it starts, serves a release flow from the
/// instances in the file, records `APP_START {config_read_only: {schema_version: 2, parsed:
/// true}}` and never rewrites the file (byte-identical after the run).
///
/// Source: `config/mod.rs` `load_config_with` (`version > head` -> `ReadOnly`, known keys read,
/// never written), `config/instances.rs` (instances are read from a `ReadOnly` document),
/// `reconcile.rs` `app_start_event` (`config_read_only` at the payload's top level).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u21_newer_config_read_only_serves_requests() -> Result<()> {
    if !opted_in("u21_newer_config_read_only_serves_requests") {
        return Ok(());
    }
    let world = jira_world().await?;
    let path = world
        .config_dir()
        .join(atlas_duck_core::config::CONFIG_FILE_NAME);
    let text = fs::read_to_string(&path)?;
    let newer = with_newer_schema(&text)
        .ok_or_else(|| format!("no root `schema_version = 1` line in {text:?}"))?;
    fs::write(&path, &newer)?;

    let r = run(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--reason",
            "atlas-test:release",
        ],
    )
    .await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    let env = r.envelope.as_ref().ok_or("no envelope")?;
    assert_eq!(env.status, Status::Released, "{}", r.stdout);
    assert_eq!(data_at(env, &["result", "key"]), Some(&json!("ABC-1")));

    world.quit_app().await?;
    assert_eq!(
        fs::read_to_string(&path)?,
        newer,
        "the config was rewritten"
    );
    let records = world.audit_records()?;
    let (_, start) = records
        .iter()
        .rev()
        .find(|(t, _)| *t == EventType::APP_START)
        .ok_or("no APP_START")?;
    assert_eq!(
        start["config_read_only"],
        json!({"schema_version": 2, "parsed": true}),
        "{start}"
    );
    Ok(())
}

// ---- S-01: two app instances ---------------------------------------------------------------------------------------

/// S-01 (two instances, one store): a second `atlas-duck-app --background` of the same test home
/// but another environment (`LANG`, `TMP`/`TEMP`/`TMPDIR`, `XDG_RUNTIME_DIR`) exits 0 within 10 s
/// without serving: the endpoint file is the first app's, the first app still answers, and the
/// store holds one `APP_START` more than before the run.
///
/// Source: `lib.rs` `run_gui` (the single-instance plugin forwards a same-host relaunch and
/// exits; behind it `startup::gate` returns `AlreadyRunning` for a held `instance.lock` ->
/// `process::exit(0)`). Either path ends the second process with 0 before it opens the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s01_two_app_instances_one_store() -> Result<()> {
    if !opted_in("s01_two_app_instances_one_store") {
        return Ok(());
    }
    let world = jira_world().await?;
    let before = app_start_count(&world)?;
    let _first = world.start_app().await?;
    let endpoint = world.data_dir().join(ENDPOINT_FILE);
    let endpoint_before = fs::read(&endpoint)?;

    let other = world.root().join("s01-other");
    let overrides = [
        ("LANG", "de_DE.UTF-8"),
        ("TMP", other.to_str().ok_or("non-UTF-8 test home")?),
        ("TEMP", other.to_str().ok_or("non-UTF-8 test home")?),
        ("TMPDIR", other.to_str().ok_or("non-UTF-8 test home")?),
        (
            "XDG_RUNTIME_DIR",
            other.to_str().ok_or("non-UTF-8 test home")?,
        ),
    ];
    let mut cmd = std::process::Command::new(APP_EXE);
    cmd.arg("--background")
        .env_clear()
        .current_dir(world.root())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (k, v) in world.env() {
        if !overrides.iter().any(|(name, _)| k == *name) {
            cmd.env(k, v);
        }
    }
    for (k, v) in overrides {
        cmd.env(k, v);
    }
    let mut second = cmd.spawn()?;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = second.try_wait()? {
            break status;
        }
        if start.elapsed() > Duration::from_secs(10) {
            let _ = second.kill();
            let _ = second.wait();
            return Err("the second app did not exit within 10 s".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(status.code(), Some(0), "second app: {status}");
    assert_eq!(
        fs::read(&endpoint)?,
        endpoint_before,
        "the endpoint changed"
    );
    let r = run(&world, &["instances"]).await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);

    world.quit_app().await?;
    assert_eq!(app_start_count(&world)?, before + 1);
    Ok(())
}

// ---- unit tests of the helpers (run everywhere) ---------------------------------------------------------------------------------

#[cfg(test)]
mod helper_tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn the_allowlist_takes_the_cli_names_and_nothing_else() {
        let ok = names(&[
            "PATH",
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "DISPLAY",
            "ATLAS_DUCK_TEST_HOME",
            "ATLAS_DUCK_TEST_KEYSTORE",
            "SystemRoot",
            "__CF_USER_TEXT_ENCODING",
        ]);
        assert!(outside_allowlist(&ok).is_empty());
        let bad = names(&[
            "HTTP_PROXY",
            "LD_PRELOAD",
            "ATLAS_DUCK_AGENT",
            "LC_",
            "LCX",
            "FOO",
        ]);
        assert_eq!(outside_allowlist(&bad), bad);
        // Names are exact off Windows, case-insensitive on it.
        assert_eq!(
            outside_allowlist(&names(&["path"])).is_empty(),
            cfg!(windows)
        );
    }

    #[test]
    fn hostile_names_are_found_in_any_case() {
        let all = names(&[
            "HTTP_PROXY",
            "https_proxy",
            "All_Proxy",
            "NO_PROXY",
            "ATLAS_DUCK_AGENT",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
        ]);
        assert_eq!(hostile_names(&all), all);
        assert!(hostile_names(&names(&["PATH", "ATLAS_DUCK_TEST_HOME", "HOME"])).is_empty());
    }

    #[test]
    fn a_config_is_made_newer_at_its_root_only() {
        let text = "written_by = \"0.1.0\"\nschema_version = 1\n\n[instances.a]\nschema_version = 1\nbase_url = \"x\"\n";
        let newer = with_newer_schema(text);
        assert_eq!(
            newer.as_deref(),
            Some(
                "written_by = \"0.1.0\"\nschema_version = 2\n\n[instances.a]\nschema_version = 1\nbase_url = \"x\"\n\n[from_a_newer_release]\nsome_new_key = true\n"
            )
        );
        // No root version line (or one that is not 1): nothing to raise.
        assert_eq!(with_newer_schema("[t]\nschema_version = 1\n"), None);
        assert_eq!(with_newer_schema("schema_version = 3\n"), None);
        assert_eq!(with_newer_schema(""), None);
    }

    #[test]
    fn the_user_version_is_written_big_endian_at_offset_60() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("db");
        fs::write(&db, vec![0xAA; 100])?;
        set_user_version(&db, 99)?;
        let bytes = fs::read(&db)?;
        assert_eq!(bytes.len(), 100);
        assert_eq!(&bytes[60..64], &[0, 0, 0, 99]);
        assert!(bytes[..60].iter().chain(&bytes[64..]).all(|b| *b == 0xAA));
        Ok(())
    }

    fn good_doctor(linux: bool) -> Value {
        let row = json!({
            "configured": true, "config_error": null, "reachable": null, "needs_token": false,
            "locked": false, "tls_error": null, "proxy_error": null, "identity_header": null,
            "version_supported": null
        });
        let local: serde_json::Map<String, Value> = LOCAL_KEYS
            .iter()
            .map(|k| ((*k).to_owned(), Value::Null))
            .collect();
        let extra = if linux { json!("present") } else { Value::Null };
        json!({
            "local": local,
            "app": {
                "instances": { "jira-main": row },
                "config_unreadable": false,
                "pac_configured": false,
                "tray_host": extra.clone(),
                "secret_service": extra,
                "ipc_accepting": true
            },
            "app_unavailable": null
        })
    }

    #[test]
    fn a_well_formed_doctor_answer_has_no_problems() {
        for linux in [true, false] {
            assert_eq!(
                doctor_problems(&good_doctor(linux), &["jira-main"], linux, &["jdoe"]),
                Vec::<String>::new(),
                "linux {linux}"
            );
        }
    }

    #[test]
    fn doctor_problems_name_each_deviation() {
        let mut d = good_doctor(true);
        d["local"]["extra"] = json!(1);
        d["app"]["instances"]["jira-main"]["more"] = json!(true);
        d["app"]["pac_configured"] = json!("no");
        d["app_unavailable"] = json!({"code": "x"});
        d["app"]["secret_service"] = json!("http://leak/jdoe");
        let problems = doctor_problems(&d, &["jira-main"], true, &["jdoe"]);
        let joined = problems.join("\n");
        for needle in [
            "data.local",
            "data.app.instances.jira-main",
            "pac_configured",
            "app_unavailable",
            "\"://\"",
            "\"jdoe\"",
        ] {
            assert!(joined.contains(needle), "{needle} not in\n{joined}");
        }
        // Linux wants strings, the others null.
        assert!(!doctor_problems(&good_doctor(true), &["jira-main"], false, &[]).is_empty());
        assert!(!doctor_problems(&good_doctor(false), &["jira-main"], true, &[]).is_empty());
        // A missing alias is a problem too.
        assert!(!doctor_problems(&good_doctor(true), &["other"], true, &[]).is_empty());
    }

    #[test]
    fn the_proxy_trap_counts_connections() -> Result<()> {
        let trap = ProxyTrap::start()?;
        assert_eq!(trap.hits(), 0);
        let addr = trap.url.trim_start_matches("http://").to_owned();
        let _conn = std::net::TcpStream::connect(&addr)?;
        let start = Instant::now();
        while trap.hits() == 0 && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(trap.hits(), 1);
        Ok(())
    }

    #[test]
    fn expect_failure_checks_every_part() -> Result<()> {
        let mut env = atlas_duck_ipc::envelope::Envelope::failed(
            ErrorCode::NotConfigured,
            true,
            "atlas-duck is not configured (x)",
        );
        if let Some(e) = env.error.as_mut() {
            let mut d = serde_json::Map::new();
            d.insert("reason".into(), json!("x"));
            e.details = Some(d);
        }
        let run = |exit: i32| CliRun {
            stdout: env.to_json_line(),
            stderr: String::new(),
            exit,
            envelope: Some(env.clone()),
        };
        let msg = "atlas-duck is not configured (x)";
        expect_failure(&run(9), 9, ErrorCode::NotConfigured, "x", msg)?;
        assert!(expect_failure(&run(5), 9, ErrorCode::NotConfigured, "x", msg).is_err());
        assert!(expect_failure(&run(9), 9, ErrorCode::Locked, "x", msg).is_err());
        assert!(expect_failure(&run(9), 9, ErrorCode::NotConfigured, "y", msg).is_err());
        assert!(expect_failure(&run(9), 9, ErrorCode::NotConfigured, "x", "other").is_err());
        Ok(())
    }
}
