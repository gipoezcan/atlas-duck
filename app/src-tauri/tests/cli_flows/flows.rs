//! `cli_flows` I (Task 23): the end-to-end flows of §13 I-03, I-10, I-15, I-16, I-39, U-05 (CLI
//! half), X-08 and the S-16 CLI-channel slice, over the real `atlas-duck` and `atlas-duck-app`
//! binaries, a store provisioned in the wizard's order and mock Atlassian servers.
//!
//! Every flow spawns a binary and therefore starts with [`opted_in`]: it skips unless
//! `ATLAS_DUCK_CLI_FLOWS=1` (CI). The pure helpers below (canary forms, notice parsing, the exit
//! oracle, the launch-artifact scan, ...) have ordinary unit tests that run everywhere.
//!
//! Conventions: every CLI run of this file goes through [`run`], which checks what holds for every
//! run (one envelope line on stdout, `exit == §4.3 matrix`, the PAT canary absent from stdout and
//! stderr). Requests are decided by the scripted approver through the `atlas-test:<directive>`
//! reason (PD-03). A request is submitted without waiting with `--timeout 0`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_duck_app_lib::testing::control::ENV_NAMES_FILE;
use atlas_duck_app_lib::testing::provision;
use atlas_duck_atlassian::testing::fixtures;
use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::{EventHeader, EventType, KeyStore, OpenConfig, SystemClock};
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::paths::{DataDirResolution, ENDPOINT_FILE, check_data_dir};
use atlas_duck_ipc::proto::exit_code;
use atlas_duck_registry::Product;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr};

use crate::harness::{CLI_EXE, CliRun, PAT_CANARY, Result, World, WorldOpts, opted_in};

// ---- constants ---------------------------------------------------------------------------------

/// The `--agent` name of the audit flow.
const AGENT: &str = "atlas-flows";
/// How long a `status` may take (it never waits; the bound only absorbs process start-up).
const STATUS_WITHIN: Duration = Duration::from_secs(5);
/// A request is decided by the approver within this long (it ticks every 50 ms).
const DECIDED_WITHIN: Duration = Duration::from_secs(30);
/// The submission notice appears after at most a cold start of the app plus the submit.
const NOTICE_WITHIN: Duration = Duration::from_secs(90);
/// A spawned CLI that has to end (after a kill, an interrupt, a broken pipe) does so within this.
const ENDS_WITHIN: Duration = Duration::from_secs(60);
/// The mock holds a fetch this long (I-10: a request held in `Fetching`).
const FETCH_HELD: Duration = Duration::from_secs(20);
/// The mock delays a fetch this long (X-08: the final write happens after the pipe is closed).
#[cfg(not(unix))]
const FETCH_DELAYED: Duration = Duration::from_millis(1500);
/// §4.3: the verbatim message of `pending` + `connection_lost` (the `<id>` is literal).
const MSG_CONNECTION_LOST: &str = "use `await <id>`; the request may be `abandoned`";

const ERR_404_BODY: &str = r#"{"errorMessages":["Issue does not exist"],"errors":{}}"#;
const ERR_500_BODY: &str = r#"{"errorMessages":["Server error"],"errors":{}}"#;

// ---- pure helpers (unit-tested below) --------------------------------------------------------

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64 of `bytes` (RFC 4648), padded or not, standard or URL-safe alphabet.
fn base64(bytes: &[u8], url_safe: bool, pad: bool) -> String {
    let table = if url_safe { B64_URL } else { B64_STD };
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        // A chunk of 1, 2 or 3 bytes carries 2, 3 or 4 characters.
        let carried = chunk.len() + 1;
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            let index = usize::try_from((n >> shift) & 63).unwrap_or(0);
            if i < carried {
                out.push(table.get(index).copied().map_or('?', char::from));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// `%XX` for every byte, upper or lower case hex.
fn percent_all(bytes: &[u8], upper: bool) -> String {
    bytes
        .iter()
        .map(|b| {
            if upper {
                format!("%{b:02X}")
            } else {
                format!("%{b:02x}")
            }
        })
        .collect()
}

/// Every spelling of `secret` a log, a header or a message could carry: raw, hex, percent-encoded
/// (all bytes, both cases) and base64 (both alphabets, at each of the three alignments, with only
/// the characters that do not depend on the neighbouring bytes).
fn secret_forms(secret: &str) -> Vec<String> {
    let bytes = secret.as_bytes();
    let mut forms = vec![
        secret.to_owned(),
        bytes.iter().map(|b| format!("{b:02x}")).collect(),
        percent_all(bytes, true),
        percent_all(bytes, false),
    ];
    for url_safe in [false, true] {
        for lead in 0..3usize {
            let mut shifted = vec![b'x'; lead];
            shifted.extend_from_slice(bytes);
            let full = base64(&shifted, url_safe, false);
            // The characters holding bits of the lead bytes, and the last character of a partial
            // group (its low bits belong to whatever follows), depend on the neighbours.
            let start = [0usize, 2, 3].get(lead).copied().unwrap_or(0);
            let tail = usize::from(shifted.len() % 3 != 0);
            if let Some(stable) = full.get(start..full.len().saturating_sub(tail)) {
                forms.push(stable.to_owned());
            }
        }
    }
    forms.sort();
    forms.dedup();
    forms
}

/// The first form of the PAT canary that `text` contains.
fn canary_in(text: &str) -> Option<String> {
    secret_forms(PAT_CANARY)
        .into_iter()
        .find(|form| !form.is_empty() && text.contains(form.as_str()))
}

/// What the CLI prints on stderr right after the server accepted a request (PD-19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Notice {
    pub(crate) request_id: String,
    pub(crate) params_sha256: Option<String>,
}

/// `Some` for one `{"event":"submitted","request_id":..,"params_sha256":..,"status":"pending"}`.
fn parse_notice(line: &str) -> Option<Notice> {
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    if v["event"] != "submitted" || v["status"] != "pending" {
        return None;
    }
    Some(Notice {
        request_id: v["request_id"].as_str()?.to_owned(),
        params_sha256: v["params_sha256"].as_str().map(str::to_owned),
    })
}

/// The notices of `stderr` and the number of non-empty lines that are not one.
pub(crate) fn notices(stderr: &str) -> (Vec<Notice>, usize) {
    let mut found = Vec::new();
    let mut other = 0;
    for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
        match parse_notice(line) {
            Some(n) => found.push(n),
            None => other += 1,
        }
    }
    (found, other)
}

/// The last non-empty line of `stderr` as an envelope (`--output text`: the envelope with
/// `data: null`, PD-15).
fn last_envelope_line(stderr: &str) -> Option<Envelope> {
    let line = stderr.lines().rev().find(|l| !l.trim().is_empty())?;
    serde_json::from_str(line.trim()).ok()
}

/// §4.3 / PD-20: the exit code the matrix gives an envelope; `status` exits 0 for every known
/// request (the envelope carries its id and is not `unknown_request`).
fn expected_exit(env: &Envelope, is_status: bool) -> i32 {
    let unknown = env.error.as_ref().map(|e| e.code) == Some(ErrorCode::UnknownRequest);
    if is_status && env.request_id.is_some() && !unknown {
        return 0;
    }
    exit_code(env)
}

fn is_status(args: &[&str]) -> bool {
    args.first() == Some(&"status")
}

pub(crate) fn error_code(env: &Envelope) -> Option<ErrorCode> {
    env.error.as_ref().map(|e| e.code)
}

/// `error.details[key]`.
pub(crate) fn detail<'a>(env: &'a Envelope, key: &str) -> Option<&'a Value> {
    env.error.as_ref()?.details.as_ref()?.get(key)
}

/// `data` walked along `path`.
pub(crate) fn data_at<'a>(env: &'a Envelope, path: &[&str]) -> Option<&'a Value> {
    let mut v = env.data.as_ref()?;
    for key in path {
        v = v.get(*key)?;
    }
    Some(v)
}

/// The rows of a `requests list` envelope (`data.requests`).
pub(crate) fn request_rows(env: &Envelope) -> Vec<Value> {
    data_at(env, &["requests"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// What a command that must never launch the app leaves behind (PD-22): `<data>/endpoint`,
/// `<data>/launch.lock` and any `launch*` file in the pinned dir (`launch-<host>.lock`).
pub(crate) fn launch_artifacts(data: &Path, pinned_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for path in [data.join(ENDPOINT_FILE), data.join("launch.lock")] {
        if path.try_exists()? {
            found.push(path);
        }
    }
    match fs::read_dir(pinned_dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                if entry.file_name().to_string_lossy().starts_with("launch") {
                    found.push(entry.path());
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(found)
}

/// The same file, however the two paths are spelled.
fn same_exe(a: &Path, b: &Path) -> bool {
    a == b
        || matches!(
            (fs::canonicalize(a), fs::canonicalize(b)),
            (Ok(x), Ok(y)) if x == y
        )
}

/// `text` with the request id replaced, so two envelopes of different requests compare.
fn without_id(text: &str, id: &str) -> String {
    text.replace(id, "<request_id>")
}

// ---- running the CLI -----------------------------------------------------------------------------

/// `atlas-duck <args>` to its end. Checks what holds for every run: stdout is exactly one envelope
/// line, its exit code is the §4.3 matrix (status override included), and the PAT canary is in
/// neither stream (S-16).
pub(crate) async fn run(world: &World, args: &[&str]) -> Result<CliRun> {
    let r = world.cli(args).await?;
    check_run(args, &r)?;
    Ok(r)
}

pub(crate) fn check_run(args: &[&str], r: &CliRun) -> Result<()> {
    no_canary(args, r)?;
    let env = r.envelope.as_ref().ok_or_else(|| {
        format!(
            "atlas-duck {args:?}: stdout holds no envelope: {:?} (stderr {:?})",
            r.stdout, r.stderr
        )
    })?;
    if r.stdout.matches('\n').count() != 1 || !r.stdout.ends_with('\n') {
        return Err(format!(
            "atlas-duck {args:?}: stdout is not one line: {:?}",
            r.stdout
        )
        .into());
    }
    let want = expected_exit(env, is_status(args));
    if r.exit != want {
        return Err(format!(
            "atlas-duck {args:?}: exit {} but the matrix says {want}: {}",
            r.exit, r.stdout
        )
        .into());
    }
    Ok(())
}

fn no_canary(args: &[&str], r: &CliRun) -> Result<()> {
    for (name, text) in [("stdout", &r.stdout), ("stderr", &r.stderr)] {
        if let Some(form) = canary_in(text) {
            return Err(
                format!("atlas-duck {args:?}: {name} carries the PAT canary ({form})").into(),
            );
        }
    }
    Ok(())
}

/// `run`, with `stdin` written to the CLI's standard input.
async fn run_with_stdin(world: &World, args: &[&str], stdin: &str) -> Result<CliRun> {
    let mut child = spawn_cli(world, args, SpawnOpts::default().with_stdin())?;
    let mut pipe = child.stdin.take().ok_or("no stdin pipe")?;
    pipe.write_all(stdin.as_bytes()).await?;
    drop(pipe);
    let r = collect(child, String::new(), args).await?;
    check_run(args, &r)?;
    Ok(r)
}

#[derive(Debug, Clone, Copy, Default)]
struct SpawnOpts {
    stdin: bool,
    /// Windows: `CREATE_NEW_PROCESS_GROUP`, so `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)`
    /// reaches this child only.
    new_group: bool,
}

impl SpawnOpts {
    fn with_stdin(mut self) -> Self {
        self.stdin = true;
        self
    }
    fn with_new_group(mut self) -> Self {
        self.new_group = true;
        self
    }
}

/// `atlas-duck <args>` still running: stdout and stderr piped, the world's environment (the same
/// one `World::cli` gives), killed when dropped.
fn spawn_cli(world: &World, args: &[&str], opts: SpawnOpts) -> Result<Child> {
    let mut cmd = tokio::process::Command::new(CLI_EXE);
    cmd.args(args).env_clear().current_dir(world.root());
    for (k, v) in world.env() {
        cmd.env(k, v);
    }
    cmd.stdin(if opts.stdin {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);
    #[cfg(windows)]
    if opts.new_group {
        // CREATE_NEW_PROCESS_GROUP
        cmd.creation_flags(0x0000_0200);
    }
    #[cfg(not(windows))]
    let _ = opts.new_group;
    Ok(cmd.spawn()?)
}

/// The end of a spawned CLI: `stderr_so_far` (what the caller already read) plus the rest.
async fn collect(child: Child, stderr_so_far: String, args: &[&str]) -> Result<CliRun> {
    let out = tokio::time::timeout(ENDS_WITHIN, child.wait_with_output())
        .await
        .map_err(|_| format!("atlas-duck {args:?} did not end within {ENDS_WITHIN:?}"))??;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = stderr_so_far + &String::from_utf8_lossy(&out.stderr);
    Ok(CliRun {
        envelope: crate::harness::parse_envelope(&stdout),
        exit: out.status.code().unwrap_or(-1),
        stdout,
        stderr,
    })
}

/// A spawned CLI that printed its submission notice and now waits for the decision.
struct Waiting {
    child: Child,
    stderr: BufReader<ChildStderr>,
    /// What was read from stderr up to and including the notice line.
    seen: String,
    notice: Notice,
    pid: u32,
    args: Vec<String>,
}

async fn read_notice(reader: &mut BufReader<ChildStderr>, seen: &mut String) -> Result<Notice> {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Err(format!("stderr ended before the submission notice: {seen:?}").into());
        }
        seen.push_str(&line);
        if let Some(notice) = parse_notice(&line) {
            return Ok(notice);
        }
    }
}

/// Spawns the CLI and reads its stderr until the submission notice (the request exists).
async fn spawn_waiting(world: &World, args: &[&str], opts: SpawnOpts) -> Result<Waiting> {
    let mut child = spawn_cli(world, args, opts)?;
    let pid = child.id().ok_or("the CLI has no pid")?;
    let mut reader = BufReader::new(child.stderr.take().ok_or("no stderr pipe")?);
    let mut seen = String::new();
    let notice =
        match tokio::time::timeout(NOTICE_WITHIN, read_notice(&mut reader, &mut seen)).await {
            Ok(found) => found?,
            Err(_) => {
                return Err(format!(
                    "atlas-duck {args:?} printed no notice within {NOTICE_WITHIN:?}: {seen:?}"
                )
                .into());
            }
        };
    if let Some(form) = canary_in(&seen) {
        return Err(format!("atlas-duck {args:?}: stderr carries the PAT canary ({form})").into());
    }
    Ok(Waiting {
        child,
        stderr: reader,
        seen,
        notice,
        pid,
        args: args.iter().map(|a| (*a).to_owned()).collect(),
    })
}

impl Waiting {
    /// Waits for the CLI to end on its own and checks the run like [`run`] does.
    async fn finish(self) -> Result<CliRun> {
        let args: Vec<&str> = self.args.iter().map(String::as_str).collect();
        let Waiting {
            child,
            mut stderr,
            seen,
            ..
        } = self;
        let mut rest = String::new();
        let mut r = collect(child, seen, &args).await?;
        // The reader still holds what the CLI wrote after the notice (nothing, in json mode).
        stderr.read_to_string(&mut rest).await?;
        r.stderr.push_str(&rest);
        no_canary(&args, &r)?;
        Ok(r)
    }
}

// ---- the world ---------------------------------------------------------------------------------------

/// A test home with one Jira instance `jira-main`, the first CLI call cold-starts the app.
pub(crate) async fn jira_world() -> Result<World> {
    let mut world = World::new(WorldOpts::default())?;
    world
        .provision_store(&[("jira-main", Product::Jira)])
        .await?;
    Ok(world)
}

pub(crate) fn jira(world: &World) -> Result<&atlas_duck_atlassian::testing::MockDc> {
    world
        .mock("jira-main")
        .ok_or_else(|| "no mock for jira-main".into())
}

/// Brings the app up (a cold start through the first CLI call) so the timings of what follows do
/// not include it.
async fn warm(world: &World) -> Result<()> {
    let r = run(world, &["instances"]).await?;
    if r.exit != 0 {
        return Err(format!("instances: exit {}: {}", r.exit, r.stdout).into());
    }
    Ok(())
}

pub(crate) fn request_id_of(env: &Envelope) -> Result<String> {
    env.request_id
        .clone()
        .ok_or_else(|| format!("no request id in {}", env.to_json_line()).into())
}

/// Submits a request and returns at once: `--timeout 0` prints the notice and the pending
/// envelope (exit 4). The id is the notice's and the envelope's.
pub(crate) async fn submit_pending(world: &World, args: &[&str]) -> Result<String> {
    let mut full = args.to_vec();
    full.extend(["--timeout", "0"]);
    let r = run(world, &full).await?;
    let env = r.envelope.as_ref().ok_or("no envelope")?;
    if r.exit != 4 || env.status != Status::Pending {
        return Err(format!(
            "{args:?} did not return pending: exit {}: {}",
            r.exit, r.stdout
        )
        .into());
    }
    let id = request_id_of(env)?;
    let (found, other) = notices(&r.stderr);
    if found.len() != 1 || other != 0 || found[0].request_id != id {
        return Err(format!("{args:?}: notice mismatch for {id}: {:?}", r.stderr).into());
    }
    Ok(id)
}

/// Polls `status <id>` until `accept` holds for its envelope.
pub(crate) async fn wait_status(
    world: &World,
    id: &str,
    accept: impl Fn(&Envelope) -> bool,
) -> Result<Envelope> {
    let start = Instant::now();
    loop {
        let r = run(world, &["status", id]).await?;
        let env = r.envelope.ok_or("no envelope")?;
        if accept(&env) {
            return Ok(env);
        }
        if start.elapsed() > DECIDED_WITHIN {
            return Err(format!(
                "{id} was not decided within {DECIDED_WITHIN:?}: {}",
                env.to_json_line()
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

fn open_status(env: &Envelope) -> bool {
    matches!(env.status, Status::Pending | Status::Executing)
}

pub(crate) fn decided(env: &Envelope) -> bool {
    !open_status(env)
}

/// Every header of the audit log in order. Needs the app gone (the instance lock).
pub(crate) fn audit_headers(world: &World) -> Result<Vec<EventHeader>> {
    let DataDirResolution::Local(data) = check_data_dir(world.data_dir())? else {
        return Err("the test data dir is not a local data dir".into());
    };
    let lock = InstanceLock::acquire(&data, world.host())
        .map_err(|e| format!("the app still runs: {e}"))?;
    let keys: Arc<dyn KeyStore> = Arc::new(provision(world.keys_dir(), world.install_id())?);
    let mut cfg = OpenConfig::new(Arc::new(SystemClock::new()), keys);
    cfg.pinned_install_id = Some(world.install_id().to_owned());
    let store = atlas_duck_audit::testing::open_existing(&data, &lock, cfg)
        .map_err(|e| format!("{e:?}"))?;
    let headers = store.recent_headers(Duration::from_secs(24 * 3600));
    store.shutdown();
    drop(lock);
    let mut headers = headers.map_err(|e| format!("{e:?}"))?;
    headers.sort_by_key(|h| h.seq);
    Ok(headers)
}

// ---- U-05: local commands -----------------------------------------------------------------------------

/// U-05 (CLI half): `--help`, a typo, `ops list` and `ops describe` are answered locally: no app,
/// no endpoint, no launch lock (PD-22), nothing on stderr.
///
/// Source: `crates/cli/src/lib.rs` `execute` (Help / OpsList / OpsDescribe without `--instance`
/// answer before `execute_connected`), `argv.rs` `parse` (an unknown op flag is a `usage` error
/// after the loop, `--help` wins over it), `local.rs`.
///
/// The plan's "no pinned file" check cannot be met: `World::new` writes a pinned file, so the
/// check here is "no launch artifacts" (`launch_artifacts`) and "the app never runs".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u05_help_typo_ops_local_never_launch() -> Result<()> {
    if !opted_in("u05_help_typo_ops_local_never_launch") {
        return Ok(());
    }
    let world = World::new(WorldOpts::default())?;
    let pinned = world.pinned_file();
    let pinned_dir = pinned.parent().ok_or("the pinned file has no parent")?;
    let cases: [(&[&str], i32, Option<ErrorCode>); 5] = [
        (&["--help"], 0, None),
        (
            &["jira", "issue", "get", "ABC-1", "--bogus"],
            2,
            Some(ErrorCode::Usage),
        ),
        (&["ops", "list"], 0, None),
        (&["ops", "describe", "jira.issue.get"], 0, None),
        (&["ops", "describe", "jira.nope"], 2, Some(ErrorCode::Usage)),
    ];
    for (args, exit, code) in cases {
        let r = run(&world, args).await?;
        assert_eq!(r.exit, exit, "{args:?}: {}", r.stdout);
        let env = r.envelope.as_ref().ok_or("no envelope")?;
        assert_eq!(error_code(env), code, "{args:?}: {}", r.stdout);
        assert_eq!(env.request_id, None, "{args:?}");
        assert!(r.stderr.is_empty(), "{args:?}: stderr {:?}", r.stderr);
        let left = launch_artifacts(world.data_dir(), pinned_dir)?;
        assert!(left.is_empty(), "{args:?} left {left:?}");
        assert!(!world.app_running()?, "{args:?} started the app");
    }
    Ok(())
}

/// U-05: the CLI's local `ops list` / `ops describe` are byte-equal to `core::gate`'s, the
/// failure envelope included (core now carries `details {op_id}` like the CLI, T11 review).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u05_cli_ops_equal_core() -> Result<()> {
    if !opted_in("u05_cli_ops_equal_core") {
        return Ok(());
    }
    let world = World::new(WorldOpts::default())?;
    let list = run(&world, &["ops", "list"]).await?;
    assert_eq!(
        list.stdout,
        atlas_duck_core::ops_list_local().to_json_line()
    );
    for op in ["jira.search", "jira.issue.get", "confluence.page.update"] {
        let r = run(&world, &["ops", "describe", op]).await?;
        assert_eq!(r.exit, 0, "{op}");
        assert_eq!(
            r.stdout,
            atlas_duck_core::ops_describe_local(op).to_json_line(),
            "{op}"
        );
    }
    let r = run(&world, &["ops", "describe", "jira.nope"]).await?;
    assert_eq!(r.exit, 2);
    assert_eq!(
        r.stdout,
        atlas_duck_core::ops_describe_local("jira.nope").to_json_line()
    );
    // A huge id is clipped the same way on both sides.
    let huge = "x".repeat(300);
    let r = run(&world, &["ops", "describe", &huge]).await?;
    assert_eq!(
        r.stdout,
        atlas_duck_core::ops_describe_local(&huge).to_json_line()
    );
    Ok(())
}

// ---- I-03: the decision flows ---------------------------------------------------------------------------

/// I-03: a read is released by the scripted approver. The notice is the one stderr line and names
/// the envelope's request.
///
/// Source: `crates/cli/src/connected.rs` `submit_wait` (notice only from a pending submit reply),
/// `output.rs` `write_notice_to` (one `{"event":"submitted",..}` line), core `engine/envelope.rs`
/// `released_data` (`data.result`), `ops` registry `jira issue get <key>`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i03_read_release_flow() -> Result<()> {
    if !opted_in("i03_read_release_flow") {
        return Ok(());
    }
    let world = jira_world().await?;
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
    assert!(env.error.is_none());
    assert_eq!(env.op_id.as_deref(), Some("jira.issue.get"));
    assert_eq!(env.instance.as_deref(), Some("jira-main"));
    assert_eq!(data_at(env, &["result", "key"]), Some(&json!("ABC-1")));
    let (found, other) = notices(&r.stderr);
    assert_eq!(
        other, 0,
        "stderr carries more than the notice: {:?}",
        r.stderr
    );
    assert_eq!(found.len(), 1, "stderr: {:?}", r.stderr);
    assert_eq!(Some(&found[0].request_id), env.request_id.as_ref());
    assert!(found[0].params_sha256.is_some());
    Ok(())
}

/// The three enrichment answers of a `jira.issue.create` in `ABC` with issue type `Bug` (M5
/// Task 12: the projects, the project's issue types, the issue type's createmeta fields).
async fn mount_create_stages(mock: &atlas_duck_atlassian::testing::MockDc) {
    mock.json("/rest/api/2/project", 200, fixtures::JIRA_PROJECTS)
        .await;
    mock.json(
        "/rest/api/2/issue/createmeta/ABC/issuetypes",
        200,
        fixtures::JIRA_CREATEMETA_ISSUETYPES,
    )
    .await;
    mock.json(
        "/rest/api/2/issue/createmeta/ABC/issuetypes/10002",
        200,
        fixtures::JIRA_CREATEMETA_FIELDS,
    )
    .await;
}

/// I-03: a write is approved: `succeeded` with the receipt. The create's enrichment resolves the
/// project and the issue type and reads its fields; the approved POST answers 201.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i03_write_approve_flow() -> Result<()> {
    if !opted_in("i03_write_approve_flow") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mock = jira(&world)?;
    mount_create_stages(mock).await;
    mock.json("/rest/api/2/issue", 201, fixtures::JIRA_ISSUE_CREATED)
        .await;
    let r = run(
        &world,
        &[
            "jira",
            "issue",
            "create",
            "--project",
            "ABC",
            "--type",
            "Bug",
            "--summary",
            "Flow test",
            "--reason",
            "atlas-test:approve",
        ],
    )
    .await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    let env = r.envelope.as_ref().ok_or("no envelope")?;
    assert_eq!(env.status, Status::Succeeded, "{}", r.stdout);
    assert_eq!(data_at(env, &["receipt", "key"]), Some(&json!("ABC-3")));
    assert!(env.error.is_none());
    Ok(())
}

/// I-03: a read is denied: exit 3, `denied`, the approver's reason as the message, not retryable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i03_read_deny_flow() -> Result<()> {
    if !opted_in("i03_read_deny_flow") {
        return Ok(());
    }
    let world = jira_world().await?;
    let r = run(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--reason",
            "atlas-test:deny",
        ],
    )
    .await?;
    assert_eq!(r.exit, 3, "{}", r.stdout);
    let env = r.envelope.as_ref().ok_or("no envelope")?;
    assert_eq!(env.status, Status::Denied);
    let err = env.error.as_ref().ok_or("no error")?;
    assert_eq!(err.code, ErrorCode::Denied);
    assert_eq!(err.message, "denied by test");
    assert!(!err.retryable);
    assert!(env.data.is_none());
    Ok(())
}

/// I-03: the audit log names the CLI: `client_kind`, `agent_name` (from `--agent`) and the CLI's
/// pid in the plaintext columns of `REQUEST_RECEIVED`; `peer_origin_exe` is the test binary (the
/// CLI's parent) or null where the walk could not see it; `DELIVERED` exists for the released
/// read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i03_audit_records_name_cli_and_peer() -> Result<()> {
    if !opted_in("i03_audit_records_name_cli_and_peer") {
        return Ok(());
    }
    let world = jira_world().await?;
    warm(&world).await?;
    let args = [
        "jira",
        "issue",
        "get",
        "ABC-1",
        "--agent",
        AGENT,
        "--reason",
        "atlas-test:release",
    ];
    let child = spawn_cli(&world, &args, SpawnOpts::default())?;
    let pid = child.id().ok_or("the CLI has no pid")?;
    let r = collect(child, String::new(), &args).await?;
    check_run(&args, &r)?;
    let env = r.envelope.as_ref().ok_or("no envelope")?;
    assert_eq!(env.status, Status::Released, "{}", r.stdout);
    let id = request_id_of(env)?;

    world.quit_app().await?;
    let headers = audit_headers(&world)?;
    let received = headers
        .iter()
        .find(|h| {
            h.event_type == EventType::REQUEST_RECEIVED && h.request_id.as_deref() == Some(&id)
        })
        .ok_or("no REQUEST_RECEIVED for the request")?;
    assert_eq!(received.actor.client_kind.as_deref(), Some("cli"));
    assert_eq!(received.actor.agent_name.as_deref(), Some(AGENT));
    assert_eq!(received.actor.peer_pid, Some(pid));
    if let Some(origin) = &received.actor.peer_origin_exe {
        let me = std::env::current_exe()?;
        assert!(
            same_exe(origin, &me),
            "the origin is {origin:?}, the test binary is {me:?}"
        );
    }
    assert!(
        headers
            .iter()
            .any(|h| h.event_type == EventType::DELIVERED && h.request_id.as_deref() == Some(&id)),
        "no DELIVERED for the released read"
    );
    Ok(())
}

// ---- I-10: cancel over IPC -----------------------------------------------------------------------------------

/// I-10: `cancel` of a request held in `Fetching` (the mock holds the fetch) and of one in
/// `AwaitingRelease` (never decided) gives byte-identical envelopes apart from the request id:
/// exit 7, `cancelled`, `details.reason == by_client`, `retryable: false`.
///
/// Source: core `engine/envelope.rs` `cancelled_by_client` (same envelope whatever the internal
/// state), `handler.rs` `cancel`; CLI `connected.rs` `short_call`; exit 7 from `ipc::proto::exit_code`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i10_cancel_identical_over_ipc() -> Result<()> {
    if !opted_in("i10_cancel_identical_over_ipc") {
        return Ok(());
    }
    let world = jira_world().await?;
    jira(&world)?
        .json_delayed(
            "/rest/api/2/issue/SLOW-1",
            200,
            fixtures::JIRA_ISSUE,
            FETCH_HELD,
        )
        .await;
    warm(&world).await?;
    let fetching = submit_pending(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "SLOW-1",
            "--reason",
            "atlas-test:hold",
        ],
    )
    .await?;
    let awaiting = submit_pending(
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
    // The quick fetch has returned and the item waits for a release; the slow one is still held.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    // The slow request really reached the mock (held there): the cancel meets a `Fetching` request.
    let reached = Instant::now();
    loop {
        let seen = jira(&world)?.received().await;
        if seen.iter().any(|r| r.url.path().ends_with("/issue/SLOW-1")) {
            break;
        }
        if reached.elapsed() > Duration::from_secs(10) {
            return Err("the slow fetch never reached the mock".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let a = run(&world, &["cancel", &fetching]).await?;
    let b = run(&world, &["cancel", &awaiting]).await?;
    for (r, id) in [(&a, &fetching), (&b, &awaiting)] {
        assert_eq!(r.exit, 7, "{}", r.stdout);
        let env = r.envelope.as_ref().ok_or("no envelope")?;
        assert_eq!(env.status, Status::Cancelled);
        assert_eq!(env.request_id.as_deref(), Some(id.as_str()));
        let err = env.error.as_ref().ok_or("no error")?;
        assert_eq!(err.code, ErrorCode::Cancelled);
        assert!(!err.retryable);
        assert_eq!(detail(env, "reason"), Some(&json!("by_client")));
    }
    assert_eq!(
        without_id(&a.stdout, &fetching),
        without_id(&b.stdout, &awaiting)
    );
    // The audit log: only the request that was in flight left a `cancelled_in_flight` read record
    // (`payloads.rs` 452-457: `outcome`, `reason`), with `by_client` (`payloads.rs` 647).
    world.quit_app().await?;
    let in_flight = world
        .audit_records()?
        .into_iter()
        .filter(|(t, p)| {
            *t == EventType::READ_FETCHED && p.get("outcome") == Some(&json!("cancelled_in_flight"))
        })
        .collect::<Vec<_>>();
    assert_eq!(in_flight.len(), 1, "{in_flight:?}");
    assert_eq!(in_flight[0].1.get("reason"), Some(&json!("by_client")));
    Ok(())
}

// ---- I-15: a killed CLI -------------------------------------------------------------------------------------------

/// I-15: a CLI killed hard while it waits leaves its request `pending`: `requests list` shows
/// it, `requests list --match-params-file -` finds exactly that row by `{op_id, params}` (the
/// notice's `params_sha256` is the row's), `status` says `pending`, exit 0.
///
/// Source: `argv.rs` `match_params` (`{op_id, params, instance?}` from `-` = stdin), core
/// `handler.rs` `requests_list` / `match_key` (the hash of op, instance id and params), the
/// request is not tied to the connection (spec §11.3, I-15).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i15_cli_killed_mid_wait_request_survives() -> Result<()> {
    if !opted_in("i15_cli_killed_mid_wait_request_survives") {
        return Ok(());
    }
    let world = jira_world().await?;
    warm(&world).await?;
    let mut w = spawn_waiting(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--reason",
            "atlas-test:hold",
            "--timeout",
            "100",
        ],
        SpawnOpts::default(),
    )
    .await?;
    let id = w.notice.request_id.clone();
    let sha = w
        .notice
        .params_sha256
        .clone()
        .ok_or("the notice has no params_sha256")?;
    // Unix: SIGKILL; Windows: TerminateProcess on this one child (not a tree kill).
    w.child.kill().await?;
    let _ = w.child.wait().await?;

    let list = run(&world, &["requests", "list"]).await?;
    let env = list.envelope.as_ref().ok_or("no envelope")?;
    let rows = request_rows(env);
    let row = rows
        .iter()
        .find(|r| r["request_id"] == id.as_str())
        .ok_or_else(|| format!("{id} is not listed: {}", list.stdout))?;
    assert_eq!(row["status"], "pending");
    assert_eq!(row["params_sha256"], sha.as_str());

    let matched = run_with_stdin(
        &world,
        &["requests", "list", "--match-params-file", "-"],
        r#"{"op_id":"jira.issue.get","params":{"key":"ABC-1"}}"#,
    )
    .await?;
    let rows = request_rows(matched.envelope.as_ref().ok_or("no envelope")?);
    assert_eq!(rows.len(), 1, "{}", matched.stdout);
    assert_eq!(rows[0]["request_id"], id.as_str());

    let status = run(&world, &["status", &id]).await?;
    assert_eq!(status.exit, 0, "{}", status.stdout);
    assert_eq!(
        status.envelope.as_ref().map(|e| e.status),
        Some(Status::Pending)
    );
    Ok(())
}

// ---- I-16: status and await -----------------------------------------------------------------------------------------------

/// I-16: `status` never waits and never reveals: exit 0 for a pending, a released, a denied (with
/// the upstream hint), a released upstream error and a failed write; `data` null, no
/// `error.details`, the fixed message "use await for details" on the failures. No `DELIVERED` is
/// caused by `status`: after quit the log holds exactly the one an `await` made.
///
/// Source: core `engine/envelope.rs` `status_envelope` (reduced error `{code, retryable}` with
/// `MSG_USE_AWAIT`, never data), `record_status` (`WRITE_DENIED` with a hint carries its code;
/// `READ_RELEASED` of an upstream-error item is `failed`/`upstream_http`; `WRITE_FAILED` with a
/// response is `upstream_http`), `deliver.rs` (only `await` appends `DELIVERED`); CLI `exit.rs`
/// `exit_for` (status exits 0 for a known request).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i16_status_immediate_exit0_no_data() -> Result<()> {
    if !opted_in("i16_status_immediate_exit0_no_data") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mock = jira(&world)?;
    mock.json("/rest/api/2/issue/ABC-2", 200, fixtures::JIRA_ISSUE)
        .await;
    // A 404 item (a held write's enrichment GET answers it), a 500 item, and a refused write.
    mock.json("/rest/api/2/issue/ERR-1", 404, ERR_404_BODY)
        .await;
    mock.json("/rest/api/2/issue/ERR-1/transitions", 404, ERR_404_BODY)
        .await;
    mock.json("/rest/api/2/issue/ERR-500", 500, ERR_500_BODY)
        .await;
    mock.json(
        "/rest/api/2/issue/ABC-1/comment",
        400,
        fixtures::JIRA_ERROR_400,
    )
    .await;
    warm(&world).await?;

    let comment = r#"{"key":"ABC-1","body":"Seen on staging.","body_format":"wiki"}"#;
    let transition = r#"{"key":"ERR-1","transition":"Done"}"#;
    let pending = submit_pending(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-2",
            "--reason",
            "atlas-test:hold",
        ],
    )
    .await?;
    let released = submit_pending(
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
    let denied = submit_pending(
        &world,
        &[
            "call",
            "jira.issue.transition",
            "--params",
            transition,
            "--reason",
            "atlas-test:deny-details",
        ],
    )
    .await?;
    let upstream = submit_pending(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ERR-500",
            "--reason",
            "atlas-test:release",
        ],
    )
    .await?;
    let failed_write = submit_pending(
        &world,
        &[
            "call",
            "jira.comment.add",
            "--params",
            comment,
            "--reason",
            "atlas-test:approve",
        ],
    )
    .await?;
    for id in [&released, &denied, &upstream, &failed_write] {
        wait_status(&world, id, decided).await?;
    }

    // (id, status, error code, retryable)
    let expected: [(&String, Status, Option<ErrorCode>); 5] = [
        (&pending, Status::Pending, None),
        (&released, Status::Released, None),
        (&denied, Status::Denied, Some(ErrorCode::UpstreamHttp)),
        (&upstream, Status::Failed, Some(ErrorCode::UpstreamHttp)),
        (&failed_write, Status::Failed, Some(ErrorCode::UpstreamHttp)),
    ];
    for (id, status, code) in expected {
        let start = Instant::now();
        let r = run(&world, &["status", id]).await?;
        assert!(
            start.elapsed() < STATUS_WITHIN,
            "status of {id} took {:?}",
            start.elapsed()
        );
        assert_eq!(r.exit, 0, "{}", r.stdout);
        let env = r.envelope.as_ref().ok_or("no envelope")?;
        assert_eq!(env.status, status, "{}", r.stdout);
        assert_eq!(env.request_id.as_deref(), Some(id.as_str()));
        assert!(env.data.is_none(), "status carries data: {}", r.stdout);
        assert!(env.meta.is_none(), "status carries meta: {}", r.stdout);
        assert_eq!(error_code(env), code, "{}", r.stdout);
        if let Some(err) = &env.error {
            assert_eq!(err.message, "use await for details");
            assert!(
                err.details.is_none(),
                "status carries details: {}",
                r.stdout
            );
            assert!(!err.retryable);
        }
    }

    // One await: one delivery, with the data.
    let delivered = run(&world, &["await", &released]).await?;
    assert_eq!(delivered.exit, 0, "{}", delivered.stdout);
    assert_eq!(
        data_at(
            delivered.envelope.as_ref().ok_or("no envelope")?,
            &["result", "key"]
        ),
        Some(&json!("ABC-1"))
    );

    world.quit_app().await?;
    let headers = audit_headers(&world)?;
    let deliveries: Vec<&EventHeader> = headers
        .iter()
        .filter(|h| h.event_type == EventType::DELIVERED)
        .collect();
    assert_eq!(
        deliveries.len(),
        1,
        "status caused a DELIVERED: {deliveries:?}"
    );
    assert_eq!(deliveries[0].request_id.as_deref(), Some(released.as_str()));
    Ok(())
}

/// I-16: `await <pending id> --timeout 2` ends with the pending envelope (exit 4) after the
/// timeout, not before and not long after.
///
/// Source: `connected.rs` `await_request` (`timeout_ms` = the time left to the deadline, the
/// call is bounded by the deadline + 2 s), core `handler.rs` `await_request` (waits at most
/// `timeout_ms`, then answers the pending envelope). The lower bound is 1.8 s: the server's wait is
/// the remaining time in whole milliseconds, measured from the CLI's own start.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i16_await_honours_timeout() -> Result<()> {
    if !opted_in("i16_await_honours_timeout") {
        return Ok(());
    }
    let world = jira_world().await?;
    warm(&world).await?;
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
    let start = Instant::now();
    let r = run(&world, &["await", &id, "--timeout", "2"]).await?;
    let took = start.elapsed();
    assert_eq!(r.exit, 4, "{}", r.stdout);
    let env = r.envelope.as_ref().ok_or("no envelope")?;
    assert_eq!(env.status, Status::Pending);
    assert_eq!(env.request_id.as_deref(), Some(id.as_str()));
    // The server's own pending envelope carries `op_id` and `instance` (`handler.rs` 440-445);
    // the CLI's fallback `pending_for(id, None)` does not (`connected.rs` 174-180). Seeing them
    // proves the server answered at the timeout rather than the CLI giving up at deadline + 2 s.
    assert_eq!(env.op_id.as_deref(), Some("jira.issue.get"));
    assert_eq!(env.instance.as_deref(), Some("jira-main"));
    assert!(
        took >= Duration::from_millis(1800) && took < Duration::from_millis(3500),
        "await --timeout 2 took {took:?}"
    );
    Ok(())
}

// ---- I-39: the matrix on real envelopes -------------------------------------------------------------------------------------------

/// I-39: terminal envelopes the app really produces follow the §4.3 matrix: `run` checks
/// `exit == matrix` (status override included) on every one; here also `retryable`: `denied`
/// false, cancelled `by_client` false, a refused write false, a released read has no error, an
/// unknown request is exit 2 without an id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i39_real_envelopes_match_matrix() -> Result<()> {
    if !opted_in("i39_real_envelopes_match_matrix") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mock = jira(&world)?;
    mock.json("/rest/api/2/issue/ERR-500", 500, ERR_500_BODY)
        .await;
    mock.json(
        "/rest/api/2/issue/ABC-1/comment",
        400,
        fixtures::JIRA_ERROR_400,
    )
    .await;
    mount_create_stages(mock).await;
    mock.json("/rest/api/2/issue", 201, fixtures::JIRA_ISSUE_CREATED)
        .await;
    let comment = r#"{"key":"ABC-1","body":"Seen on staging.","body_format":"wiki"}"#;

    let released = run(
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
    assert_eq!(
        (released.exit, released.envelope.as_ref().map(|e| e.status)),
        (0, Some(Status::Released))
    );
    assert!(
        released
            .envelope
            .as_ref()
            .ok_or("no envelope")?
            .error
            .is_none()
    );

    let created = run(
        &world,
        &[
            "jira",
            "issue",
            "create",
            "--project",
            "ABC",
            "--type",
            "Bug",
            "--summary",
            "Matrix",
            "--reason",
            "atlas-test:approve",
        ],
    )
    .await?;
    assert_eq!(
        (created.exit, created.envelope.as_ref().map(|e| e.status)),
        (0, Some(Status::Succeeded))
    );

    let denied = run(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--reason",
            "atlas-test:deny",
        ],
    )
    .await?;
    assert_eq!(denied.exit, 3);
    let err = denied
        .envelope
        .as_ref()
        .and_then(|e| e.error.as_ref())
        .ok_or("no error")?;
    assert_eq!((err.code, err.retryable), (ErrorCode::Denied, false));

    let upstream = run(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ERR-500",
            "--reason",
            "atlas-test:release",
        ],
    )
    .await?;
    assert_eq!(upstream.exit, 6, "{}", upstream.stdout);
    let err = upstream
        .envelope
        .as_ref()
        .and_then(|e| e.error.as_ref())
        .ok_or("no error")?;
    assert_eq!((err.code, err.retryable), (ErrorCode::UpstreamHttp, false));

    let refused = run(
        &world,
        &[
            "call",
            "jira.comment.add",
            "--params",
            comment,
            "--reason",
            "atlas-test:approve",
        ],
    )
    .await?;
    assert_eq!(refused.exit, 6, "{}", refused.stdout);
    let err = refused
        .envelope
        .as_ref()
        .and_then(|e| e.error.as_ref())
        .ok_or("no error")?;
    assert_eq!((err.code, err.retryable), (ErrorCode::UpstreamHttp, false));

    let held = submit_pending(
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
    let cancelled = run(&world, &["cancel", &held]).await?;
    assert_eq!(cancelled.exit, 7, "{}", cancelled.stdout);
    let err = cancelled
        .envelope
        .as_ref()
        .and_then(|e| e.error.as_ref())
        .ok_or("no error")?;
    assert_eq!((err.code, err.retryable), (ErrorCode::Cancelled, false));

    // The status override: a known request exits 0 whatever it ended as; an unknown id is exit 2.
    for id in [&held] {
        let r = run(&world, &["status", id]).await?;
        assert_eq!(r.exit, 0, "{}", r.stdout);
    }
    let unknown = run(&world, &["status", "req_00000000000000000000000000000000"]).await?;
    assert_eq!(unknown.exit, 2, "{}", unknown.stdout);
    let env = unknown.envelope.as_ref().ok_or("no envelope")?;
    assert_eq!(error_code(env), Some(ErrorCode::UnknownRequest));
    assert_eq!(env.request_id, None);
    Ok(())
}

/// I-39 (exit 9 row): an app with no instance at all answers an op with `not_configured`,
/// `details.reason == no_instance`, `retryable: true`, exit 9, no request id.
///
/// Source: core `tests/handler.rs` `pd01_no_instance_at_all_names_the_product` (the same
/// answer for a store without instances), `exit.rs` row `no_instance` (exit 9), `ipc::proto`
/// `exit_code` (`NotConfigured` -> 9).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i39_no_instance_exit9() -> Result<()> {
    if !opted_in("i39_no_instance_exit9") {
        return Ok(());
    }
    let mut world = World::new(WorldOpts::default())?;
    world.provision_store(&[]).await?;
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
    assert_eq!(r.exit, 9, "{}", r.stdout);
    let env = r.envelope.as_ref().ok_or("no envelope")?;
    let err = env.error.as_ref().ok_or("no error")?;
    assert_eq!((err.code, err.retryable), (ErrorCode::NotConfigured, true));
    assert_eq!(detail(env, "reason"), Some(&json!("no_instance")));
    assert_eq!(env.request_id, None);
    Ok(())
}

/// I-39 / §11.3: the app dies after the submit reply: the waiting CLI exits 4 with
/// `pending` + `connection_lost` (`retryable: false`, the same request id, the verbatim message);
/// after a restart `await <id>` says `abandoned`, exit 7, retryable.
///
/// Source: `connected.rs` `await_error` (`ConnectionLost` -> `connection_lost_pending(id, base)`),
/// `MSG_CONNECTION_LOST`; core `envelope.rs` `record_status` (`ABANDONED` -> retryable true) and
/// the §11.3 reconciliation at start. A killed app leaves its endpoint file; `World::start_app`
/// removes it before the restart (T22 review fix), so it returns only for the new app.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i39_connection_lost_after_submit_exit4() -> Result<()> {
    if !opted_in("i39_connection_lost_after_submit_exit4") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mut app = world.start_app().await?;
    let w = spawn_waiting(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--reason",
            "atlas-test:hold",
            "--timeout",
            "30",
        ],
        SpawnOpts::default(),
    )
    .await?;
    let id = w.notice.request_id.clone();
    app.kill_hard()?;
    let r = w.finish().await?;
    assert_eq!(r.exit, 4, "{}", r.stdout);
    let env = r.envelope.as_ref().ok_or("no envelope")?;
    assert_eq!(env.status, Status::Pending);
    assert_eq!(env.request_id.as_deref(), Some(id.as_str()));
    let err = env.error.as_ref().ok_or("no error")?;
    assert_eq!(err.code, ErrorCode::Unreachable);
    assert!(!err.retryable);
    assert_eq!(err.message, MSG_CONNECTION_LOST);
    assert_eq!(detail(env, "reason"), Some(&json!("connection_lost")));

    let _restarted = world.start_app().await?;
    let r = run(&world, &["await", &id]).await?;
    assert_eq!(r.exit, 7, "{}", r.stdout);
    let env = r.envelope.as_ref().ok_or("no envelope")?;
    assert_eq!(env.status, Status::Abandoned);
    assert_eq!(env.request_id.as_deref(), Some(id.as_str()));
    let err = env.error.as_ref().ok_or("no error")?;
    assert_eq!((err.code, err.retryable), (ErrorCode::Abandoned, true));
    Ok(())
}

// ---- X-08: output and interrupts -------------------------------------------------------------------------------------------------------

/// X-08: `--output text`: stdout is the pretty `data.result`, stderr ends with the envelope as
/// one line with `data: null`; exit 0.
///
/// Source: `output.rs` `emit_to` / `render_text` (PD-15: `data.result` pretty, then the envelope
/// with `data` removed on stderr, after the submission notice).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x08_output_text_split() -> Result<()> {
    if !opted_in("x08_output_text_split") {
        return Ok(());
    }
    let world = jira_world().await?;
    let args = [
        "--output",
        "text",
        "jira",
        "issue",
        "get",
        "ABC-1",
        "--reason",
        "atlas-test:release",
    ];
    let r = world.cli(&args).await?;
    no_canary(&args, &r)?;
    assert_eq!(r.exit, 0, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
    let result: Value = serde_json::from_str(&r.stdout)?;
    assert_eq!(result["key"], "ABC-1");
    assert_eq!(r.stdout, serde_json::to_string_pretty(&result)? + "\n");
    assert!(
        r.stdout.starts_with("{\n  \""),
        "not pretty: {:?}",
        r.stdout
    );
    let (found, _) = notices(&r.stderr);
    assert_eq!(found.len(), 1, "stderr: {:?}", r.stderr);
    let env = last_envelope_line(&r.stderr).ok_or("stderr does not end with an envelope")?;
    assert_eq!(env.status, Status::Released);
    assert!(env.data.is_none());
    assert_eq!(Some(&found[0].request_id), env.request_id.as_ref());
    Ok(())
}

#[cfg(unix)]
const INTERRUPTS: &[&str] = &["INT", "TERM", "HUP"];
#[cfg(windows)]
const INTERRUPTS: &[&str] = &["CTRL_BREAK"];

/// Interrupts the waiting CLI `pid`: Unix `kill -<signal>`, Windows `CTRL_BREAK_EVENT` to the
/// process group the child was created with.
#[cfg(unix)]
fn interrupt(pid: u32, signal: &str) -> Result<()> {
    let status = std::process::Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(format!("kill -{signal} {pid} failed: {status}").into());
    }
    Ok(())
}

#[cfg(windows)]
fn interrupt(pid: u32, _signal: &str) -> Result<()> {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};
    // SAFETY: a plain call; `pid` is the id of the process group the child was created with
    // (`CREATE_NEW_PROCESS_GROUP`), the event reaches that group's console processes only.
    let sent = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) };
    if sent == 0 {
        return Err(format!("GenerateConsoleCtrlEvent: {}", io::Error::last_os_error()).into());
    }
    Ok(())
}

/// X-08: an interrupt (Unix `SIGINT`, `SIGTERM`, `SIGHUP` in turn; Windows `CTRL_BREAK`) on a
/// waiting CLI prints one `pending` envelope and exits 4; the request is not cancelled.
///
/// Source: `interrupt.rs` `Guard` (handlers installed by `connector.interrupts()` before the
/// connect), `connected.rs` `await_request` (`Wait::Interrupted` -> the submit reply's pending
/// envelope), `lib.rs` `run` (exit from the envelope: pending is 4). `CTRL_CLOSE` is T16's unit
/// test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x08_interrupt_prints_pending_exit4_no_cancel() -> Result<()> {
    if !opted_in("x08_interrupt_prints_pending_exit4_no_cancel") {
        return Ok(());
    }
    let world = jira_world().await?;
    warm(&world).await?;
    for signal in INTERRUPTS {
        let w = spawn_waiting(
            &world,
            &[
                "jira",
                "issue",
                "get",
                "ABC-1",
                "--reason",
                "atlas-test:hold",
                "--timeout",
                "100",
            ],
            SpawnOpts::default().with_new_group(),
        )
        .await?;
        let id = w.notice.request_id.clone();
        interrupt(w.pid, signal)?;
        let r = w.finish().await?;
        assert_eq!(r.exit, 4, "{signal}: {}", r.stdout);
        let env = r.envelope.as_ref().ok_or("no envelope")?;
        assert_eq!(env.status, Status::Pending, "{signal}: {}", r.stdout);
        assert_eq!(env.request_id.as_deref(), Some(id.as_str()));
        assert_eq!(
            r.stdout.matches('\n').count(),
            1,
            "{signal}: {:?}",
            r.stdout
        );
        let st = run(&world, &["status", &id]).await?;
        assert_eq!(
            st.envelope.as_ref().map(|e| e.status),
            Some(Status::Pending),
            "{signal}: the interrupt cancelled the request: {}",
            st.stdout
        );
    }
    Ok(())
}

/// X-08: the reader of stdout goes away while the CLI waits: the CLI ends with exit 4 and the
/// request is never cancelled (it is released by the approver afterwards). Unix: the hang-up poll
/// (every 500 ms) ends it within 3 s; Windows: the final write fails once the request is
/// released (the fetch is delayed, so the release comes after the drop).
///
/// Source: `interrupt.rs` `stdout_hung_up` (`POLLERR`/`POLLHUP` on fd 1), `output.rs`
/// `emit_to` (a failed stdout write is exit 4, PD-16).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x08_broken_pipe_exit4_no_cancel() -> Result<()> {
    if !opted_in("x08_broken_pipe_exit4_no_cancel") {
        return Ok(());
    }
    // Unix: the fetch outlasts the 3 s bound by a wide margin, so only the hang-up poll
    // (`interrupt.rs` 154-163) can end the CLI in time; a final write after the release would be
    // too late. Windows has no poll and relies on the final write, so the short delay stays.
    #[cfg(unix)]
    let delay = Duration::from_secs(8);
    #[cfg(not(unix))]
    let delay = FETCH_DELAYED;
    let world = jira_world().await?;
    jira(&world)?
        .json_delayed("/rest/api/2/issue/SLOW-1", 200, fixtures::JIRA_ISSUE, delay)
        .await;
    warm(&world).await?;
    let mut w = spawn_waiting(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "SLOW-1",
            "--reason",
            "atlas-test:release",
            "--timeout",
            "100",
        ],
        SpawnOpts::default(),
    )
    .await?;
    let id = w.notice.request_id.clone();
    drop(w.child.stdout.take());
    let dropped = Instant::now();
    let status = tokio::time::timeout(ENDS_WITHIN, w.child.wait())
        .await
        .map_err(|_| "the CLI did not end after its stdout was closed")??;
    assert_eq!(status.code(), Some(4), "exit {status}");
    #[cfg(unix)]
    assert!(
        dropped.elapsed() < Duration::from_secs(3),
        "the hang-up poll took {:?}",
        dropped.elapsed()
    );
    #[cfg(not(unix))]
    let _ = dropped;
    // Unix: the CLI left long before the 8 s fetch ended, so the request is still `pending`
    // (not released yet): the exit came from the hang-up poll, not from a final write.
    #[cfg(unix)]
    {
        let now = run(&world, &["status", &id]).await?;
        let env = now.envelope.as_ref().ok_or("no envelope")?;
        assert_eq!(env.status, Status::Pending, "{}", now.stdout);
    }
    // Never cancelled: the approver releases it after the delayed fetch.
    let env = wait_status(&world, &id, decided).await?;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    Ok(())
}

// ---- S-16: the PAT canary -------------------------------------------------------------------------------------------------------------------------

/// S-16 (CLI channel slice): across a spread of commands the PAT canary is in neither stdout nor
/// stderr, in any of its spellings (`run` checks every run of this file the same way), and
/// `env-names.json` holds names only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s16_pat_canary_absent_from_cli_channels() -> Result<()> {
    if !opted_in("s16_pat_canary_absent_from_cli_channels") {
        return Ok(());
    }
    let world = jira_world().await?;
    // The canary reached the keystore at provisioning and the app uses it on every fetch.
    let released = run(
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
    assert_eq!(released.exit, 0, "{}", released.stdout);
    // Positive control: the canary did go upstream on the read itself (`Authorization: Bearer
    // <pat>`, `client/send.rs` 129), so its absence from the CLI channels below is meaningful.
    // Only the read's path counts: the connection test at provisioning and the field-name cache
    // fills (PD-46) carry it too.
    let canary_sent = jira(&world)?.received().await.iter().any(|r| {
        r.url.path().ends_with("/issue/ABC-1")
            && r.headers
                .values()
                .any(|v| String::from_utf8_lossy(v.as_bytes()).contains(PAT_CANARY))
    });
    assert!(canary_sent, "no upstream request carried the PAT canary");
    let held = submit_pending(
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
    let probes: Vec<Vec<&str>> = vec![
        vec!["instances"],
        vec!["doctor"],
        vec!["requests", "list"],
        vec!["status", &held],
        vec!["ops", "list", "--instance", "jira-main"],
        vec!["cancel", &held],
        vec!["status", "req_00000000000000000000000000000000"],
    ];
    for args in &probes {
        run(&world, args).await?;
    }

    let names = world.env_names()?;
    assert!(!names.is_empty(), "env-names.json is empty");
    let root = world.root().to_string_lossy().into_owned();
    for name in &names {
        assert!(
            canary_in(name).is_none(),
            "a name carries the canary: {name}"
        );
        assert!(
            !name.contains('=')
                && !name.contains('/')
                && !name.contains('\\')
                && !name.contains(&root),
            "env-names.json holds more than a name: {name:?}"
        );
    }
    // Every value the test gave the app is absent from the file: only names are written.
    let file = fs::read_to_string(world.control_dir().join(ENV_NAMES_FILE))?;
    for (name, value) in world.env() {
        let value = value.to_string_lossy();
        if value.len() > 3 {
            assert!(
                !file.contains(value.as_ref()),
                "env-names.json holds the value of {name:?}"
            );
        }
    }
    Ok(())
}

// ---- unit tests of the helpers (run everywhere) ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[test]
    fn base64_known_vectors() {
        for (input, padded, bare) in [
            (&b""[..], "", ""),
            (b"f", "Zg==", "Zg"),
            (b"fo", "Zm8=", "Zm8"),
            (b"foo", "Zm9v", "Zm9v"),
            (b"foob", "Zm9vYg==", "Zm9vYg"),
            (b"fooba", "Zm9vYmE=", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input, false, true), padded);
            assert_eq!(base64(input, false, false), bare);
        }
        // The alphabets differ in the last two characters only.
        assert_eq!(base64(&[0xfb, 0xff], false, true), "+/8=");
        assert_eq!(base64(&[0xfb, 0xff], true, true), "-_8=");
    }

    #[test]
    fn the_canary_is_found_in_every_spelling() {
        let canary = PAT_CANARY;
        let bytes = canary.as_bytes();
        assert!(canary_in(canary).is_some());
        assert!(canary_in(&format!("Authorization: Bearer {canary}")).is_some());
        assert!(canary_in(&percent_all(bytes, true)).is_some());
        assert!(canary_in(&percent_all(bytes, false)).is_some());
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert!(canary_in(&hex).is_some());
        // Base64 at each alignment, both alphabets: the canary embedded after 0, 1 and 2 bytes.
        for url_safe in [false, true] {
            for lead in ["", "a", "ab"] {
                let text = format!("{lead}{canary}tail");
                let encoded = base64(text.as_bytes(), url_safe, true);
                assert!(
                    canary_in(&format!("token={encoded};")).is_some(),
                    "lead {lead:?} url_safe {url_safe}: {encoded}"
                );
            }
        }
    }

    #[test]
    fn other_text_does_not_carry_the_canary() {
        assert!(canary_in("").is_none());
        assert!(canary_in(r#"{"status":"released","data":{"result":{"key":"ABC-1"}}}"#).is_none());
        assert!(canary_in("PATCANARY").is_none());
        // None of the forms is empty (an empty form would match everything).
        assert!(secret_forms(PAT_CANARY).iter().all(|f| f.len() >= 8));
    }

    #[test]
    fn notice_lines() {
        let line =
            r#"{"event":"submitted","request_id":"req_1","params_sha256":"ab","status":"pending"}"#;
        assert_eq!(
            parse_notice(line),
            Some(Notice {
                request_id: "req_1".into(),
                params_sha256: Some("ab".into())
            })
        );
        let no_hash =
            r#"{"event":"submitted","request_id":"req_1","params_sha256":null,"status":"pending"}"#;
        assert_eq!(parse_notice(no_hash).map(|n| n.params_sha256), Some(None));
        assert_eq!(parse_notice("{}"), None);
        assert_eq!(parse_notice("not json"), None);
        assert_eq!(
            parse_notice(r#"{"event":"other","request_id":"r","status":"pending"}"#),
            None
        );
        let (found, other) = notices(&format!("{line}\n\nwarning: x\n"));
        assert_eq!((found.len(), other), (1, 1));
    }

    fn envelope(status: Status, code: Option<ErrorCode>, id: Option<&str>) -> Envelope {
        let mut env = Envelope::failed(code.unwrap_or(ErrorCode::Internal), false, "m");
        env.status = status;
        env.request_id = id.map(str::to_owned);
        if code.is_none() {
            env.error = None;
        }
        env
    }

    #[test]
    fn the_exit_oracle_follows_the_matrix_and_the_status_override() {
        let released = envelope(Status::Released, None, Some("req_1"));
        assert_eq!(expected_exit(&released, false), 0);
        let denied = envelope(Status::Denied, Some(ErrorCode::Denied), Some("req_1"));
        assert_eq!(expected_exit(&denied, false), 3);
        assert_eq!(expected_exit(&denied, true), 0);
        let cancelled = envelope(Status::Cancelled, Some(ErrorCode::Cancelled), Some("req_1"));
        assert_eq!(expected_exit(&cancelled, false), 7);
        let pending = envelope(Status::Pending, None, Some("req_1"));
        assert_eq!(expected_exit(&pending, false), 4);
        // An unknown request, and a failure that carries no id, are not "known".
        let unknown = envelope(Status::Failed, Some(ErrorCode::UnknownRequest), None);
        assert_eq!(expected_exit(&unknown, true), 2);
        let down = envelope(Status::Failed, Some(ErrorCode::Unreachable), None);
        assert_eq!(expected_exit(&down, true), 5);
        assert!(is_status(&["status", "req_1"]));
        assert!(!is_status(&["cancel", "status"]));
    }

    #[test]
    fn envelope_accessors() {
        let mut env = envelope(Status::Failed, Some(ErrorCode::Cancelled), Some("req_1"));
        let mut d = serde_json::Map::new();
        d.insert("reason".into(), json!("by_client"));
        if let Some(e) = env.error.as_mut() {
            e.details = Some(d);
        }
        env.data = Some(json!({"result": {"key": "ABC-1"}, "requests": [{"request_id": "req_1"}]}));
        assert_eq!(detail(&env, "reason"), Some(&json!("by_client")));
        assert_eq!(detail(&env, "other"), None);
        assert_eq!(data_at(&env, &["result", "key"]), Some(&json!("ABC-1")));
        assert_eq!(data_at(&env, &["result", "nope"]), None);
        assert_eq!(request_rows(&env).len(), 1);
        assert_eq!(error_code(&env), Some(ErrorCode::Cancelled));
    }

    #[test]
    fn text_mode_stderr_ends_with_an_envelope() {
        let notice =
            r#"{"event":"submitted","request_id":"req_1","params_sha256":"ab","status":"pending"}"#;
        let mut env = envelope(Status::Released, None, Some("req_1"));
        env.data = None;
        let text = format!("{notice}\n{}", env.to_json_line());
        assert_eq!(
            last_envelope_line(&text).map(|e| e.status),
            Some(Status::Released)
        );
        assert!(last_envelope_line("").is_none());
        assert!(last_envelope_line(notice).is_none());
    }

    #[test]
    fn launch_artifacts_names_the_endpoint_and_both_locks() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let data = tmp.path().join("data");
        let pinned = tmp.path().join("pinned");
        fs::create_dir_all(&data)?;
        // No pinned dir at all: nothing found.
        assert!(launch_artifacts(&data, &pinned)?.is_empty());
        fs::create_dir_all(&pinned)?;
        fs::write(pinned.join("paths-host.toml"), "x")?;
        assert!(launch_artifacts(&data, &pinned)?.is_empty());
        fs::write(data.join(ENDPOINT_FILE), "x")?;
        fs::write(data.join("launch.lock"), "")?;
        fs::write(pinned.join("launch-host.lock"), "")?;
        fs::write(pinned.join("launch.lock"), "")?;
        let found = launch_artifacts(&data, &pinned)?;
        assert_eq!(found.len(), 4, "{found:?}");
        Ok(())
    }

    #[test]
    fn same_exe_compares_files_not_spellings() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let a = tmp.path().join("a.exe");
        let b = tmp.path().join("b.exe");
        fs::write(&a, "")?;
        fs::write(&b, "")?;
        assert!(same_exe(&a, &a));
        assert!(same_exe(&a, &tmp.path().join(".").join("a.exe")));
        assert!(!same_exe(&a, &b));
        assert!(!same_exe(&a, &tmp.path().join("missing.exe")));
        Ok(())
    }

    #[test]
    fn ids_are_masked_for_comparison() {
        assert_eq!(
            without_id(r#"{"request_id":"req_abc","x":"req_abc"}"#, "req_abc"),
            r#"{"request_id":"<request_id>","x":"<request_id>"}"#
        );
    }
}
