//! `script_flows` (M8 Task 26): nine flows of the real binaries on the script path, each against a
//! store provisioned in the wizard's order with one Jira instance `jira` (the mock answers the
//! fixture set). Scripts are files under the test root, passed to `script run` by path. A run is
//! decided by the scripted approver through the `atlas-test:<directive>` reason (PD-03): `release`
//! releases a read or a script, any other name (`hold`) leaves the request on its release item.
//!
//! Every flow spawns binaries and therefore starts with [`opted_in`]: it skips unless
//! `ATLAS_DUCK_CLI_FLOWS=1` (CI). Nothing waits without a bound: every CLI run ends within the
//! harness timeout, every poll below has a deadline, and a flow fails by assertion or error.
//!
//! What a script does while a flow looks at it is made structural, not timed: a call to a mock path
//! that answers late holds a run in flight, a busy loop on `Date.now()` holds a slot, and the
//! mock's request log says when a run reached its call.

use std::time::{Duration, Instant};

use atlas_duck_app_lib::testing::control::QUEUE_FILE;
use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::proto::exit_code;
use atlas_duck_registry::Product;
use serde_json::{Value, json};

use crate::harness::{CliRun, PAT_CANARY, Result, World, WorldOpts, instance_rows, opted_in};

const HOLD: &str = "atlas-test:hold";
const RELEASE: &str = "atlas-test:release";
/// The wait of a released script: the CLI returns when the run is decided.
const LONG_WAIT: &str = "100";
/// How long a poll of the mock or of a status waits for what it expects.
const POLL_DEADLINE: Duration = Duration::from_secs(90);

const ISSUE_PREFIX: &str = "/rest/api/2/issue/";

// ---- helpers -----------------------------------------------------------------------------------

async fn jira_world(opts: WorldOpts) -> Result<World> {
    let mut world = World::new(opts)?;
    world.provision_store(&[("jira", Product::Jira)]).await?;
    Ok(world)
}

fn jira(world: &World) -> Result<&MockDc> {
    world.mock("jira").ok_or_else(|| "no mock for jira".into())
}

/// A script file under the test root; its absolute path.
fn script_file(world: &World, name: &str, body: &str) -> Result<String> {
    let dir = world.root().join("scripts");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(name);
    std::fs::write(&path, body)?;
    Ok(path.to_string_lossy().into_owned())
}

/// The `exit` the §4.3 matrix gives an envelope; `status` exits 0 for every known request.
fn expected_exit(env: &Envelope, is_status: bool) -> i32 {
    let unknown = env.error.as_ref().map(|e| e.code) == Some(ErrorCode::UnknownRequest);
    if is_status && env.request_id.is_some() && !unknown {
        return 0;
    }
    exit_code(env)
}

/// One `atlas-duck <args>` run. What holds for every run: stdout is one envelope line, its exit
/// code is the matrix's, and the PAT canary is on neither stream.
async fn run(world: &World, args: &[&str]) -> Result<CliRun> {
    let r = world.cli(args).await?;
    for (name, text) in [("stdout", &r.stdout), ("stderr", &r.stderr)] {
        if text.contains(PAT_CANARY) {
            return Err(format!("the PAT canary is on {name} of {args:?}").into());
        }
    }
    let env = r.envelope.as_ref().ok_or_else(|| {
        format!(
            "{args:?}: no envelope on stdout: {:?} (stderr {:?})",
            r.stdout, r.stderr
        )
    })?;
    if r.stdout.matches('\n').count() != 1 || !r.stdout.ends_with('\n') {
        return Err(format!("{args:?}: stdout is not one line: {:?}", r.stdout).into());
    }
    let want = expected_exit(env, args.first() == Some(&"status"));
    if r.exit != want {
        return Err(format!(
            "{args:?}: exit {} but the matrix says {want}: {}",
            r.exit, r.stdout
        )
        .into());
    }
    Ok(r)
}

fn envelope(r: &CliRun) -> Result<&Envelope> {
    r.envelope
        .as_ref()
        .ok_or_else(|| format!("no envelope: {:?}", r.stdout).into())
}

/// `script run <file> <extra..>`, to its end.
async fn script(world: &World, file: &str, extra: &[&str]) -> Result<CliRun> {
    let mut args = vec!["script", "run", file];
    args.extend_from_slice(extra);
    run(world, &args).await
}

/// `script run <file> --reason <directive> <extra..>` submitted without waiting (`--timeout 0`):
/// the pending envelope's id.
async fn submit(world: &World, file: &str, directive: &str, extra: &[&str]) -> Result<String> {
    let mut args = vec!["script", "run", file, "--reason", directive];
    args.extend_from_slice(extra);
    submit_args(world, &args).await
}

async fn submit_args(world: &World, args: &[&str]) -> Result<String> {
    let mut full = args.to_vec();
    full.extend(["--timeout", "0"]);
    let r = run(world, &full).await?;
    let env = envelope(&r)?;
    if r.exit != 4 || env.status != Status::Pending {
        return Err(format!(
            "{args:?} did not return pending: exit {}: {}",
            r.exit, r.stdout
        )
        .into());
    }
    env.request_id
        .clone()
        .ok_or_else(|| format!("no request id in {}", r.stdout).into())
}

/// The request ids on the scripted approver's queue mirror (`test-control/queue.json`): the
/// requests that wait for a decision. A script run is on it only once it has ended (its release
/// item); a run that is queued for a slot, running or in flight is not. A read is on it once its
/// fetch is done. Empty before the mirror exists.
fn queued_ids(world: &World) -> Result<Vec<String>> {
    let path = world.control_dir().join(QUEUE_FILE);
    let mut last = None;
    // A reader can meet the file while the app renames a new one over it (Windows): try again.
    for _ in 0..10 {
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let rows: Vec<Value> = serde_json::from_str(&text)?;
                return Ok(rows
                    .iter()
                    .filter_map(|r| r["request_id"].as_str().map(str::to_owned))
                    .collect());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    Err(last.map_or_else(|| "no queue mirror".into(), Into::into))
}

/// Waits (bounded by [`POLL_DEADLINE`], returns as soon as it holds) until every id is on the
/// approver's queue: each of those script runs has ended and waits on its release item.
async fn wait_queued(world: &World, ids: &[&str]) -> Result<()> {
    let start = Instant::now();
    loop {
        let queued = queued_ids(world)?;
        if ids.iter().all(|id| queued.iter().any(|q| q == id)) {
            return Ok(());
        }
        if start.elapsed() > POLL_DEADLINE {
            return Err(format!(
                "not all of {ids:?} reached the queue in {POLL_DEADLINE:?}: {queued:?}"
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Fails with a clear message when one of `ids` is already on the queue: the run the flow wants
/// in flight, running or waiting for a slot has ended (the flow ran too slowly for its set-up).
fn assert_not_queued(world: &World, ids: &[&str], what: &str) -> Result<()> {
    let queued = queued_ids(world)?;
    let ended: Vec<&&str> = ids
        .iter()
        .filter(|id| queued.iter().any(|q| q == **id))
        .collect();
    if ended.is_empty() {
        Ok(())
    } else {
        Err(
            format!("{what}: {ended:?} already ended (on the queue), the set-up was too slow")
                .into(),
        )
    }
}

async fn cancel(world: &World, id: &str) -> Result<CliRun> {
    run(world, &["cancel", id]).await
}

/// `data` walked along `path`.
fn data_at<'a>(env: &'a Envelope, path: &[&str]) -> Option<&'a Value> {
    let mut v = env.data.as_ref()?;
    for key in path {
        v = v.get(*key)?;
    }
    Some(v)
}

fn code_of(env: &Envelope) -> Option<ErrorCode> {
    env.error.as_ref().map(|e| e.code)
}

fn detail<'a>(env: &'a Envelope, key: &str) -> Option<&'a Value> {
    env.error.as_ref()?.details.as_ref()?.get(key)
}

/// The envelope without what differs between two requests: their id and the `meta` clocks.
fn shape(env: &Envelope) -> Result<Value> {
    let mut v = serde_json::to_value(env)?;
    v["request_id"] = Value::Null;
    v["meta"] = Value::Null;
    Ok(v)
}

/// [`shape`] without the request's routing fields too: a cancel answer echoes the request's
/// `op_id` and `instance` (`cancelled_by_client` builds it from the request head), and those
/// differ between a script and a read. What I-10 requires to be identical is the rest: status,
/// error code, message, retryable and `details.reason`.
fn answer_shape(env: &Envelope) -> Result<Value> {
    let mut v = shape(env)?;
    v["op_id"] = Value::Null;
    v["instance"] = Value::Null;
    Ok(v)
}

/// How many requests the mock saw at `p` (under the context path), any method.
async fn hits(mock: &MockDc, p: &str) -> usize {
    let want = mock.path(p);
    mock.received()
        .await
        .iter()
        .filter(|r| r.url.path() == want)
        .count()
}

/// Waits (bounded) until the mock saw at least `n` requests at `p`: a run reached its call.
async fn wait_hits(mock: &MockDc, p: &str, n: usize) -> Result<()> {
    let start = Instant::now();
    loop {
        if hits(mock, p).await >= n {
            return Ok(());
        }
        if start.elapsed() > POLL_DEADLINE {
            return Err(format!("{p} saw {} of {n} requests", hits(mock, p).await).into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// How many requests the mock saw so far, and later those after the first `before`.
async fn received_count(mock: &MockDc) -> usize {
    mock.received().await.len()
}

/// Every audit record of the world, read after the app quit (the log needs the app gone).
async fn audit(world: &World) -> Result<Vec<(EventType, Value)>> {
    world.quit_app().await?;
    world.audit_records()
}

fn payloads(records: &[(EventType, Value)], kind: EventType) -> Vec<&Value> {
    records
        .iter()
        .filter(|(t, _)| *t == kind)
        .map(|(_, v)| v)
        .collect()
}

fn count_of(records: &[(EventType, Value)], kind: EventType) -> usize {
    payloads(records, kind).len()
}

/// A script that reaches its call and then holds its slot busy for 100 s: well past what a flow
/// needs (the flow cancels it), and under the 120 s default `timeout_s`, so a holder never ends
/// by itself nor by a limit.
fn spinner(key: &str) -> String {
    format!(
        "await atlas.call('jira.issue.get', {{key: '{key}'}});\n\
         const end = Date.now() + 100000;\n\
         while (Date.now() < end) {{}}\n\
         return 'spun';\n"
    )
}

/// `body` as a script file, run with the release directive to its end.
async fn released(world: &World, name: &str, body: &str) -> Result<CliRun> {
    let file = script_file(world, name, body)?;
    script(world, &file, &["--reason", RELEASE, "--timeout", LONG_WAIT]).await
}

fn texts_hold_none(r: &CliRun, needles: &[&str]) -> Result<()> {
    for needle in needles {
        for (name, text) in [("stdout", &r.stdout), ("stderr", &r.stderr)] {
            if text.contains(needle) {
                return Err(format!("{name} leaks {needle:?}: {text}").into());
            }
        }
    }
    Ok(())
}

fn is_dry(env: &Envelope) -> bool {
    env.meta
        .as_ref()
        .and_then(|m| m.get("dry_run"))
        .is_some_and(|v| !v.is_null() && *v != json!(false))
}

// ---- the flows ---------------------------------------------------------------------------------

/// The harness over the real worker: a released script answers with its result and the run's
/// audit trail has the script events.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_flows_smoke() -> Result<()> {
    if !opted_in("script_flows_smoke") {
        return Ok(());
    }
    let world = jira_world(WorldOpts::default()).await?;
    let file = script_file(&world, "smoke.js", "return {n: 1 + 1, args};")?;
    let r = script(
        &world,
        &file,
        &[
            "--args",
            r#"{"a":1}"#,
            "--reason",
            RELEASE,
            "--timeout",
            LONG_WAIT,
        ],
    )
    .await?;
    let env = envelope(&r)?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    assert_eq!(env.status, Status::Released, "{}", r.stdout);
    assert_eq!(
        data_at(env, &["result"]),
        Some(&json!({"n": 2, "args": {"a": 1}})),
        "{}",
        r.stdout
    );
    let records = audit(&world).await?;
    for kind in [
        EventType::REQUEST_RECEIVED,
        EventType::SCRIPT_STARTED,
        EventType::SCRIPT_FINISHED,
        EventType::SCRIPT_RELEASED,
        EventType::DELIVERED,
    ] {
        assert_eq!(count_of(&records, kind), 1, "{kind:?} in {records:?}");
    }
    Ok(())
}

/// U-03: a dry run (full and sparse) answers calls from the op examples and never reaches the
/// upstream: not for a read, not for `atlas.all`, and a bad op or a write op is a catchable
/// rejection. Over the real worker; the mock saw no issue and no search request, and the audit
/// has dry-run records and no run, no call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u03_dry_run_no_http_real_worker() -> Result<()> {
    if !opted_in("u03_dry_run_no_http_real_worker") {
        return Ok(());
    }
    let world = jira_world(WorldOpts::default()).await?;
    let mock = jira(&world)?;
    let reads = script_file(
        &world,
        "dry_reads.js",
        "const one = await atlas.call('jira.issue.get', {key: 'DRY-1'});\n\
         const all = await atlas.all('jira.search', {jql: 'project = DRY', max: 10});\n\
         return {one: one !== undefined, all: all !== undefined};\n",
    )?;
    let rejects = script_file(
        &world,
        "dry_rejects.js",
        "const out = {};\n\
         try { await atlas.call('jira.no.such.op', {}); out.bad = 'ok'; }\n\
         catch (e) { out.bad = e.class; }\n\
         try { await atlas.call('jira.comment.add', {key: 'DRY-1', body: 'x'}); out.write = 'ok'; }\n\
         catch (e) { out.write = e.class; }\n\
         return out;\n",
    )?;
    // The app is up (and has done whatever it asks the mock at start) before the count.
    run(&world, &["instances"]).await?;
    let before = received_count(mock).await;
    let mut dry_runs = 0;
    for file in [&reads, &rejects] {
        for mode in ["--dry-run=full", "--dry-run=sparse"] {
            let r = script(&world, file, &[mode, "--timeout", LONG_WAIT]).await?;
            let env = envelope(&r)?;
            assert_eq!(r.exit, 0, "{mode}: {}", r.stdout);
            assert_eq!(env.status, Status::Succeeded, "{mode}: {}", r.stdout);
            assert!(is_dry(env), "no dry_run in meta: {}", r.stdout);
            assert!(
                data_at(env, &["logs"]).is_some(),
                "no logs in data: {}",
                r.stdout
            );
            if file == &rejects {
                // A bad op and a write are rejected like in a real run, whatever the dry-run mode.
                assert_eq!(
                    data_at(env, &["result"]),
                    Some(&json!({"bad": "validation", "write": "validation"})),
                    "{}",
                    r.stdout
                );
            } else {
                assert_eq!(
                    data_at(env, &["result", "one"]),
                    Some(&json!(true)),
                    "{}",
                    r.stdout
                );
            }
            dry_runs += 1;
        }
    }
    // No request for the issue or for a search reached the upstream.
    let touched: Vec<String> = mock
        .received()
        .await
        .iter()
        .skip(before)
        .map(|r| r.url.path().to_owned())
        .filter(|p| p.contains("/issue/") || p.contains("/search") || p.contains("/comment"))
        .collect();
    assert!(
        touched.is_empty(),
        "a dry run reached the upstream: {touched:?}"
    );
    // The instance is untouched.
    let r = run(&world, &["instances"]).await?;
    let rows = instance_rows(envelope(&r)?);
    assert!(
        rows.iter().all(|row| row["state"] == json!("ok")),
        "{}",
        r.stdout
    );
    let records = audit(&world).await?;
    assert_eq!(count_of(&records, EventType::SCRIPT_DRY_RUN), dry_runs);
    for kind in [
        EventType::SCRIPT_STARTED,
        EventType::SCRIPT_CALL_SENT,
        EventType::SCRIPT_CALL,
    ] {
        assert_eq!(count_of(&records, kind), 0, "{kind:?}: {records:?}");
    }
    Ok(())
}

/// I-7: while a script's request is pending, the streams of the CLI are the same whatever the run
/// did: a result, a thrown error, a failing upstream call and a run the host stopped at its time
/// limit give the same `status` and the same `await --timeout 1` (modulo the id), and neither
/// carries a word of what happened. The audit, read after the quit, shows the runs did end
/// differently.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i07_script_streams_identical_real_worker() -> Result<()> {
    if !opted_in("i07_script_streams_identical_real_worker") {
        return Ok(());
    }
    let world = jira_world(WorldOpts::default()).await?;
    let mock = jira(&world)?;
    mock.json(
        &format!("{ISSUE_PREFIX}NOPE-9"),
        404,
        r#"{"errorMessages":["Issue Does Not Exist"],"errors":{}}"#,
    )
    .await;
    let sources = [
        ("i07_result.js", "return {secret: 'CANARY-RESULT-1'};"),
        ("i07_throw.js", "throw new Error('CANARY-ERROR-2');"),
        (
            "i07_404.js",
            "await atlas.call('jira.issue.get', {key: 'NOPE-9'});\nreturn 'CANARY-NOT-REACHED';",
        ),
        (
            "i07_spin.js",
            "await atlas.call('jira.issue.get', {key: 'ABC-1'});\nwhile (true) {}\n",
        ),
    ];
    let mut ids = Vec::new();
    for (name, body) in sources {
        let file = script_file(&world, name, body)?;
        let limits = if name == "i07_spin.js" {
            vec!["--limits", r#"{"timeout_s":5}"#]
        } else {
            Vec::new()
        };
        ids.push(submit(&world, &file, HOLD, &limits).await?);
    }
    // Every run is over (the spinner after its five seconds and the kill): the answers below are
    // those of a request whose script ended, which is where a leak would show. Only an ended run
    // is on the approver's queue (its release item), whichever way it ended.
    wait_queued(&world, &ids.iter().map(String::as_str).collect::<Vec<_>>()).await?;

    let leaks = [
        "CANARY",
        "NOPE-9",
        "TypeError",
        "does not exist",
        "script_limit",
        "script_error",
        "timeout_s",
        "upstream",
    ];
    let mut shapes = Vec::new();
    for id in &ids {
        for args in [
            vec!["status", id.as_str()],
            vec!["status", id.as_str()],
            vec!["await", id.as_str(), "--timeout", "1"],
        ] {
            let r = run(&world, &args).await?;
            let env = envelope(&r)?;
            assert_eq!(env.status, Status::Pending, "{args:?}: {}", r.stdout);
            texts_hold_none(&r, &leaks)?;
            shapes.push((args[0], shape(env)?));
        }
    }
    let (first_status, first_await) = (&shapes[0].1, &shapes[2].1);
    for (kind, s) in &shapes {
        let want = if *kind == "status" {
            first_status
        } else {
            first_await
        };
        assert_eq!(s, want, "{kind} differs between the four runs");
    }
    for id in &ids {
        let r = cancel(&world, id).await?;
        assert_eq!(r.exit, 7, "{}", r.stdout);
    }
    let records = audit(&world).await?;
    let ended = count_of(&records, EventType::SCRIPT_FINISHED)
        + count_of(&records, EventType::SCRIPT_FAILED);
    assert_eq!(ended, 4, "each run ended once: {records:?}");
    let failed = payloads(&records, EventType::SCRIPT_FAILED);
    assert!(
        failed.iter().any(|p| p["reason"] == json!("timeout_s")),
        "the spinner was not stopped by its limit: {failed:?}"
    );
    assert_eq!(count_of(&records, EventType::SCRIPT_RELEASED), 0);
    Ok(())
}

/// I-10: a cancel is the same answer in every phase: a run that waits for a slot, two runs in
/// flight (a call the upstream answers late), a run that finished and waits on its release item,
/// a read that is fetching and a read that waits for release. Every `cancel` is exit 7,
/// `cancelled`, reason `by_client`, identical apart from the request's own id, op and instance.
/// The audit shows the two killed runs failed as `cancelled_by_client`, six requests cancelled
/// and nothing released. Which phase a request is in comes from the approver's queue mirror
/// (only an ended run or a fetched read is on it), not from sleeps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i10_cancel_identical_every_phase_real_worker() -> Result<()> {
    if !opted_in("i10_cancel_identical_every_phase_real_worker") {
        return Ok(());
    }
    let world = jira_world(WorldOpts::default()).await?;
    let mock = jira(&world)?;
    // Below the 30 s of one upstream call.
    let late = Duration::from_secs(28);
    mock.json_delayed(
        &format!("{ISSUE_PREFIX}SLOW-1"),
        200,
        fixtures::JIRA_ISSUE,
        late,
    )
    .await;
    mock.json_delayed(
        &format!("{ISSUE_PREFIX}SLOW-2"),
        200,
        fixtures::JIRA_ISSUE,
        late,
    )
    .await;
    let quick = script_file(&world, "i10_quick.js", "return 'quick';")?;
    let slow = script_file(
        &world,
        "i10_slow.js",
        "await atlas.call('jira.issue.get', {key: 'SLOW-1'});\nreturn 'slow';",
    )?;

    // The two that wait on a release item come first, before any late answer is pending: a run
    // that finished, and a read that was fetched. Each is on the approver's queue once it is
    // there (a structural wait, no sleep).
    let finished = submit(&world, &quick, HOLD, &[]).await?;
    let awaiting =
        submit_args(&world, &["jira", "issue", "get", "ABC-1", "--reason", HOLD]).await?;
    wait_queued(&world, &[finished.as_str(), awaiting.as_str()]).await?;
    // Two runs in flight fill both slots. From their calls on, the upstream answers in 28 s, so
    // the rest of the set-up and the cancels below are a handful of CLI calls.
    let flying_a = submit(&world, &slow, HOLD, &[]).await?;
    let flying_b = submit(&world, &slow, HOLD, &[]).await?;
    wait_hits(mock, &format!("{ISSUE_PREFIX}SLOW-1"), 2).await?;
    // A run that waits for a slot: both are taken, so it cannot have started (it would be on the
    // queue at once, its script is a `return`).
    let waiting = submit(&world, &quick, HOLD, &[]).await?;
    // A read that is fetching (its answer is late, too).
    let fetching = submit_args(
        &world,
        &["jira", "issue", "get", "SLOW-2", "--reason", HOLD],
    )
    .await?;
    wait_hits(mock, &format!("{ISSUE_PREFIX}SLOW-2"), 1).await?;
    // The phases are the intended ones: none of these has ended (an ended run or a fetched read
    // is on the queue), so the cancels below meet them as in flight, waiting and fetching.
    let open = [
        flying_a.as_str(),
        flying_b.as_str(),
        waiting.as_str(),
        fetching.as_str(),
    ];
    assert_not_queued(&world, &open, "I-10 set-up")?;

    // `waiting` goes first: cancelling an in-flight run frees its slot, and the queue would start
    // the waiting run before the cancel reaches it (a third `SCRIPT_FAILED`, or a release item).
    // Then the two in-flight runs, before their late answer lands, and the rest.
    let ids = [
        &waiting, &flying_a, &flying_b, &fetching, &awaiting, &finished,
    ];
    let mut answers = Vec::new();
    for id in ids {
        let r = cancel(&world, id).await?;
        let env = envelope(&r)?;
        assert_eq!(r.exit, 7, "{}", r.stdout);
        assert_eq!(env.status, Status::Cancelled, "{}", r.stdout);
        assert_eq!(env.request_id.as_deref(), Some(id.as_str()));
        assert_eq!(code_of(env), Some(ErrorCode::Cancelled));
        assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
        assert_eq!(detail(env, "reason"), Some(&json!("by_client")));
        answers.push(answer_shape(env)?);
    }
    // Identical in every phase: the same envelope apart from the request's id, op and instance.
    for a in &answers {
        assert_eq!(a, &answers[0], "the cancel answers differ");
    }
    let records = audit(&world).await?;
    let failed = payloads(&records, EventType::SCRIPT_FAILED);
    assert_eq!(failed.len(), 2, "{failed:?}");
    for p in failed {
        assert_eq!(p["reason"], json!("cancelled_by_client"));
        assert_eq!(p["direct"], json!(false));
    }
    assert_eq!(count_of(&records, EventType::CANCELLED), 6, "{records:?}");
    assert_eq!(count_of(&records, EventType::SCRIPT_RELEASED), 0);
    assert_eq!(count_of(&records, EventType::READ_RELEASED), 0);
    Ok(())
}

/// I-13: what a run is told does not depend on the slots. Two real runs hold both slots (each
/// reached its call, then spins). Meanwhile a dry run succeeds (its own pool), a syntax error is
/// refused at once as `script_syntax`, an unknown limit is a usage error, and a third and fourth
/// real run are accepted as pending, not busy: the fourth has not reached its call. Cancelling
/// one holder lets the queue run: the third (a loop the host stops at its limit, never
/// dispatched) goes to its release item and is released; the fourth then reaches its call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i13_slot_timing_independent_real_worker() -> Result<()> {
    if !opted_in("i13_slot_timing_independent_real_worker") {
        return Ok(());
    }
    let world = jira_world(WorldOpts::default()).await?;
    let mock = jira(&world)?;
    mock.json(&format!("{ISSUE_PREFIX}DONE-1"), 200, fixtures::JIRA_ISSUE)
        .await;
    let hold_slot = script_file(&world, "i13_spin.js", &spinner("ABC-1"))?;
    let limit_loop = script_file(&world, "i13_limit.js", "while (true) {}")?;
    let after = script_file(
        &world,
        "i13_after.js",
        "await atlas.call('jira.issue.get', {key: 'DONE-1'});\nreturn 'done';",
    )?;
    let dry = script_file(&world, "i13_dry.js", "return 1;")?;
    let bad = script_file(&world, "i13_bad.js", "return (;")?;

    let spin_a = submit(&world, &hold_slot, HOLD, &[]).await?;
    let spin_b = submit(&world, &hold_slot, HOLD, &[]).await?;
    wait_hits(mock, &format!("{ISSUE_PREFIX}ABC-1"), 2).await?;

    // Both slots are busy: none of these is told so.
    let r = script(&world, &dry, &["--dry-run=full", "--timeout", LONG_WAIT]).await?;
    assert_eq!(envelope(&r)?.status, Status::Succeeded, "{}", r.stdout);
    let r = script(&world, &bad, &["--timeout", LONG_WAIT]).await?;
    let env = envelope(&r)?;
    assert_eq!(r.exit, 8, "{}", r.stdout);
    assert_eq!(code_of(env), Some(ErrorCode::ScriptSyntax), "{}", r.stdout);
    let r = script(
        &world,
        &dry,
        &["--limits", r#"{"bogus":1}"#, "--timeout", LONG_WAIT],
    )
    .await?;
    assert_eq!(r.exit, 2, "{}", r.stdout);
    let queued_limit = submit(
        &world,
        &limit_loop,
        RELEASE,
        &["--limits", r#"{"timeout_s":6}"#],
    )
    .await?;
    let queued_after = submit(&world, &after, RELEASE, &[]).await?;
    // Both holders are still spinning (an ended holder would be on the queue), so the two runs
    // above wait for a slot.
    assert_not_queued(&world, &[spin_a.as_str(), spin_b.as_str()], "I-13 holders")?;
    // "Has not started" is a negative: nothing to wait for, so one short, bounded look. The
    // structural half is the line above (no slot is free) and the `pending` answers.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(hits(mock, &format!("{ISSUE_PREFIX}DONE-1")).await, 0);
    for id in [&queued_limit, &queued_after] {
        let r = run(&world, &["status", id]).await?;
        assert_eq!(envelope(&r)?.status, Status::Pending, "{}", r.stdout);
    }

    // A slot frees: the queue runs, in order. `await` (it returns the moment the run is released,
    // bounded by the CLI's `--timeout`) delivers the data; `status` never carries any.
    let r = cancel(&world, &spin_a).await?;
    assert_eq!(r.exit, 7, "{}", r.stdout);
    let r = run(&world, &["await", &queued_limit, "--timeout", LONG_WAIT]).await?;
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Released, "{}", r.stdout);
    assert_eq!(
        r.exit, 8,
        "the limit stop is a script_error item: {}",
        r.stdout
    );
    assert_eq!(
        data_at(env, &["script_error", "class"]),
        Some(&json!("script_limit")),
        "{}",
        r.stdout
    );
    let r = run(&world, &["await", &queued_after, "--timeout", LONG_WAIT]).await?;
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Released, "{}", r.stdout);
    assert_eq!(r.exit, 0, "{}", r.stdout);
    assert_eq!(
        data_at(env, &["result"]),
        Some(&json!("done")),
        "{}",
        r.stdout
    );
    assert_eq!(hits(mock, &format!("{ISSUE_PREFIX}DONE-1")).await, 1);
    // The other holder was in flight all along.
    assert_not_queued(&world, &[spin_b.as_str()], "I-13 second holder")?;
    let r = cancel(&world, &spin_b).await?;
    assert_eq!(r.exit, 7, "{}", r.stdout);

    let records = audit(&world).await?;
    let started = payloads(&records, EventType::SCRIPT_STARTED);
    assert_eq!(
        started
            .iter()
            .filter(|p| p["queued"] == json!(true))
            .count(),
        2,
        "{started:?}"
    );
    let failed = payloads(&records, EventType::SCRIPT_FAILED);
    let stopped: Vec<_> = failed
        .iter()
        .filter(|p| p["reason"] == json!("timeout_s"))
        .collect();
    assert_eq!(stopped.len(), 1, "{failed:?}");
    assert_eq!(stopped[0]["queued"], json!(true));
    assert_eq!(stopped[0]["dispatched"], json!(false));
    assert_eq!(stopped[0]["direct"], json!(false));
    assert_eq!(
        failed
            .iter()
            .filter(|p| p["reason"] == json!("cancelled_by_client"))
            .count(),
        2,
        "{failed:?}"
    );
    Ok(())
}

/// I-14: the rule that decides whether a stopped run is a direct, data-free failure or goes to
/// release. A host timeout during a call (the call is cancelled in flight), after a call the
/// upstream answered with an error, and a script that reads more than `max_fetch_mb` all end on a
/// release item (pending, never a direct failure). A syntax error and a loop that never made a call
/// are direct, data-free, exit 8. The queued run's limit is in I-13; the user's kill (case 5) is
/// UI only and is covered by the core test and the app e2e.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i14_dispatch_rule_cases_real_worker() -> Result<()> {
    if !opted_in("i14_dispatch_rule_cases_real_worker") {
        return Ok(());
    }
    let world = jira_world(WorldOpts::default()).await?;
    let mock = jira(&world)?;
    mock.json_delayed(
        &format!("{ISSUE_PREFIX}SLOW-1"),
        200,
        fixtures::JIRA_ISSUE,
        Duration::from_secs(28),
    )
    .await;
    mock.json(
        &format!("{ISSUE_PREFIX}NOPE-9"),
        404,
        r#"{"errorMessages":["Issue Does Not Exist"],"errors":{}}"#,
    )
    .await;
    let mut big: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    big["fields"]["description"] = json!("x".repeat(2 * 1024 * 1024));
    mock.json(&format!("{ISSUE_PREFIX}BIG-1"), 200, &big.to_string())
        .await;

    let in_flight = script_file(
        &world,
        "i14_in_flight.js",
        "await atlas.call('jira.issue.get', {key: 'SLOW-1'});\nreturn 1;",
    )?;
    let after_error = script_file(
        &world,
        "i14_after_error.js",
        "try { await atlas.call('jira.issue.get', {key: 'NOPE-9'}); } catch (e) {}\nwhile (true) {}\n",
    )?;
    let too_big = script_file(
        &world,
        "i14_too_big.js",
        "try { await atlas.call('jira.issue.get', {key: 'BIG-1'}); } catch (e) {}\nreturn 'after';",
    )?;
    let mut ids = Vec::new();
    ids.push(
        submit(
            &world,
            &in_flight,
            HOLD,
            &["--limits", r#"{"timeout_s":6}"#],
        )
        .await?,
    );
    ids.push(
        submit(
            &world,
            &after_error,
            HOLD,
            &["--limits", r#"{"timeout_s":6}"#],
        )
        .await?,
    );
    wait_hits(mock, &format!("{ISSUE_PREFIX}SLOW-1"), 1).await?;
    wait_hits(mock, &format!("{ISSUE_PREFIX}NOPE-9"), 1).await?;
    // Both slots are used until the two limits are reached: the third waits for one.
    ids.push(
        submit(
            &world,
            &too_big,
            HOLD,
            &["--limits", r#"{"max_fetch_mb":1}"#],
        )
        .await?,
    );
    wait_hits(mock, &format!("{ISSUE_PREFIX}BIG-1"), 1).await?;
    // All three runs end on a release item (the two limits at their 6 s, the third once a slot is
    // free): each is on the approver's queue, held there by the `hold` directive.
    wait_queued(&world, &ids.iter().map(String::as_str).collect::<Vec<_>>()).await?;
    for id in &ids {
        let r = run(&world, &["status", id]).await?;
        assert_eq!(envelope(&r)?.status, Status::Pending, "{}", r.stdout);
    }

    // Direct: never queued, never dispatched.
    let syntax = script_file(&world, "i14_syntax.js", "return (;")?;
    let r = script(&world, &syntax, &["--reason", HOLD, "--timeout", LONG_WAIT]).await?;
    let env = envelope(&r)?;
    assert_eq!(r.exit, 8, "{}", r.stdout);
    assert_eq!(env.status, Status::Failed);
    assert_eq!(code_of(env), Some(ErrorCode::ScriptSyntax));
    assert!(env.data.is_none(), "{}", r.stdout);
    let spin = script_file(&world, "i14_spin.js", "while (true) {}")?;
    let r = script(
        &world,
        &spin,
        &[
            "--reason",
            HOLD,
            "--limits",
            r#"{"timeout_s":5}"#,
            "--timeout",
            LONG_WAIT,
        ],
    )
    .await?;
    let env = envelope(&r)?;
    assert_eq!(r.exit, 8, "{}", r.stdout);
    assert_eq!(env.status, Status::Failed, "{}", r.stdout);
    assert_eq!(code_of(env), Some(ErrorCode::ScriptLimit), "{}", r.stdout);
    assert!(env.data.is_none(), "{}", r.stdout);

    for id in &ids {
        cancel(&world, id).await?;
    }
    let records = audit(&world).await?;
    let calls = payloads(&records, EventType::SCRIPT_CALL);
    assert!(
        calls
            .iter()
            .any(|p| p["outcome"] == json!("cancelled_in_flight")),
        "case 1: no call cancelled in flight: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|p| p["rejection"] == json!("max_fetch_mb") && p["outcome"] == json!("too_large")),
        "case 3: no call over max_fetch_mb: {calls:?}"
    );
    let failed = payloads(&records, EventType::SCRIPT_FAILED);
    let stopped: Vec<_> = failed
        .iter()
        .filter(|p| p["reason"] == json!("timeout_s") && p["direct"] == json!(false))
        .collect();
    assert_eq!(stopped.len(), 2, "cases 1 and 2: {failed:?}");
    for p in &stopped {
        assert_eq!(p["dispatched"], json!(true));
    }
    let direct: Vec<_> = failed
        .iter()
        .filter(|p| p["direct"] == json!(true))
        .collect();
    assert_eq!(direct.len(), 2, "case 4: {failed:?}");
    assert!(direct.iter().all(|p| p["dispatched"] == json!(false)));
    assert!(direct.iter().any(|p| p["reason"] == json!("script_syntax")));
    Ok(())
}

/// I-23: what a script sees of the upstream's answers, over the real worker. A redirect, an HTML
/// `200` and an HTML `401` are `upstream_unavailable` (and say so in the audit rows) without a
/// token re-check: the instance stays `ok` and the credential works. A JSON `401` is
/// `upstream_http` when the re-check passes (the token is fine) and `needs_token` when the
/// re-check fails: the instance goes to `needs_token`. The re-check is one `SYSTEM_FETCH` each.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i23_script_call_paths_real() -> Result<()> {
    if !opted_in("i23_script_call_paths_real") {
        return Ok(());
    }
    let world = jira_world(WorldOpts::default()).await?;
    let mock = jira(&world)?;
    mock.redirect(&format!("{ISSUE_PREFIX}R-1"), "/elsewhere")
        .await;
    mock.html(&format!("{ISSUE_PREFIX}H-1"), 200).await;
    mock.html(&format!("{ISSUE_PREFIX}U-1"), 401).await;
    mock.json(
        &format!("{ISSUE_PREFIX}J-1"),
        401,
        r#"{"errorMessages":["denied"],"errors":{}}"#,
    )
    .await;
    let classify = |keys: &str| {
        format!(
            "const out = {{}};\n\
             for (const key of {keys}) {{\n\
               try {{ await atlas.call('jira.issue.get', {{key}}); out[key] = 'ok'; }}\n\
               catch (e) {{ out[key] = e.class; }}\n\
             }}\n\
             return out;\n"
        )
    };
    let soft = script_file(&world, "i23_soft.js", &classify("['R-1', 'H-1', 'U-1']"))?;
    let r = script(
        &world,
        &soft,
        &["--reason", RELEASE, "--timeout", LONG_WAIT],
    )
    .await?;
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Released, "{}", r.stdout);
    for key in ["R-1", "H-1", "U-1"] {
        assert_eq!(
            data_at(env, &["result", key]),
            Some(&json!("upstream_unavailable")),
            "{key}: {}",
            r.stdout
        );
    }
    let r = run(&world, &["instances"]).await?;
    assert!(
        instance_rows(envelope(&r)?)
            .iter()
            .all(|row| row["state"] == json!("ok")),
        "{}",
        r.stdout
    );
    // The credential still works.
    let r = run(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--reason",
            RELEASE,
            "--timeout",
            LONG_WAIT,
        ],
    )
    .await?;
    assert_eq!(envelope(&r)?.status, Status::Released, "{}", r.stdout);
    let records = audit(&world).await?;
    let rejections: Vec<&str> = payloads(&records, EventType::SCRIPT_CALL)
        .iter()
        .filter_map(|p| p["rejection"].as_str())
        .collect();
    for want in ["redirect_3xx", "non_json_2xx", "non_json_401"] {
        assert!(rejections.contains(&want), "{want} not in {rejections:?}");
    }
    // A re-check commits two `SYSTEM_FETCH` records (`phase: start`, then `phase: result` per
    // call): count by purpose and phase, `(starts, results)`.
    let rechecks = |records: &[(EventType, Value)]| {
        let phase = |want: &str| {
            payloads(records, EventType::SYSTEM_FETCH)
                .iter()
                .filter(|p| p["purpose"] == json!("token_recheck") && p["phase"] == json!(want))
                .count()
        };
        (phase("start"), phase("result"))
    };
    assert_eq!(
        rechecks(&records),
        (0, 0),
        "a soft failure re-checked the token"
    );

    // The JSON 401: the re-check passes (the fixture's `myself` answers).
    let hard = script_file(&world, "i23_hard.js", &classify("['J-1']"))?;
    let r = script(
        &world,
        &hard,
        &["--reason", RELEASE, "--timeout", LONG_WAIT],
    )
    .await?;
    assert_eq!(
        data_at(envelope(&r)?, &["result", "J-1"]),
        Some(&json!("upstream_http")),
        "{}",
        r.stdout
    );
    // The re-check fails: the identity answer is anonymous, as a token the server dropped.
    let mock = jira(&world)?;
    mock.server().reset().await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Anonymous)
        .await;
    mock.json(
        &format!("{ISSUE_PREFIX}J-1"),
        401,
        r#"{"errorMessages":["denied"],"errors":{}}"#,
    )
    .await;
    let r = script(
        &world,
        &hard,
        &["--reason", RELEASE, "--timeout", LONG_WAIT],
    )
    .await?;
    assert_eq!(
        data_at(envelope(&r)?, &["result", "J-1"]),
        Some(&json!("needs_token")),
        "{}",
        r.stdout
    );
    let r = run(&world, &["instances"]).await?;
    assert!(
        instance_rows(envelope(&r)?)
            .iter()
            .any(|row| row["state"] == json!("needs_token")),
        "{}",
        r.stdout
    );
    let records = audit(&world).await?;
    // One re-check per JSON 401: two starts, each with its one result.
    assert_eq!(rechecks(&records), (2, 2), "one re-check per JSON 401");
    Ok(())
}

/// S-11: the containment corpus over the real worker. No network, process or module global; a call
/// to one is a `ReferenceError`, which is data and goes to release; a static import is a syntax
/// error and a dynamic one rejects; a loop and a heap bomb are stopped by their limits; deep
/// recursion is a `RangeError` the script survives; a write op is a `validation` rejection that
/// never reaches the mock; and what a run read never reaches the CLI before its release (a held
/// twin is silent, the released twin carries it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s11_containment_corpus() -> Result<()> {
    if !opted_in("s11_containment_corpus") {
        return Ok(());
    }
    let world = jira_world(WorldOpts::default()).await?;
    let mock = jira(&world)?;

    // The globals a script must not have.
    let r = released(
        &world,
        "s11_typeof.js",
        "const names = ['fetch', 'XMLHttpRequest', 'WebSocket', 'require', 'process', 'Buffer',\n\
         'setTimeout', 'setInterval', 'setImmediate', 'Deno', 'module', 'exports', '__filename',\n\
         'std', 'os'];\n\
         const out = {};\n\
         for (const n of names) { out[n] = eval('typeof ' + n); }\n\
         return out;\n",
    )
    .await?;
    let env = envelope(&r)?;
    match data_at(env, &["result"]).and_then(Value::as_object) {
        Some(map) => {
            assert!(
                map.values().all(|v| v == &json!("undefined")),
                "a forbidden global exists: {}",
                r.stdout
            );
        }
        // eval itself may be absent: then the sweep is a ReferenceError, which is as closed.
        None => assert_eq!(
            data_at(env, &["script_error", "class"]),
            Some(&json!("ReferenceError")),
            "{}",
            r.stdout
        ),
    }

    // Using one.
    let r = released(
        &world,
        "s11_fetch.js",
        "const r = await fetch('http://127.0.0.1:9/x');\nreturn 1;",
    )
    .await?;
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Released, "{}", r.stdout);
    assert_eq!(
        data_at(env, &["script_error", "class"]),
        Some(&json!("ReferenceError")),
        "{}",
        r.stdout
    );

    // Modules.
    let r = released(
        &world,
        "s11_static_import.js",
        "import x from 'os';\nreturn 1;",
    )
    .await?;
    let env = envelope(&r)?;
    assert_eq!(r.exit, 8, "{}", r.stdout);
    assert_eq!(code_of(env), Some(ErrorCode::ScriptSyntax), "{}", r.stdout);
    let r = released(
        &world,
        "s11_dynamic_import.js",
        "try { await import('os'); return 'loaded'; } catch (e) { return 'rejected'; }",
    )
    .await?;
    assert_eq!(
        data_at(envelope(&r)?, &["result"]),
        Some(&json!("rejected")),
        "{}",
        r.stdout
    );

    // Recursion: the engine's stack limit, caught.
    let r = released(&world,
        "s11_recursion.js",
        "function f(n) { return f(n + 1) + 1; }\ntry { f(0); return 'no limit'; } catch (e) { return e.name; }",
    )
    .await?;
    assert_eq!(
        data_at(envelope(&r)?, &["result"]),
        Some(&json!("RangeError")),
        "{}",
        r.stdout
    );

    // A write op: rejected before it is sent.
    let r = released(&world,
        "s11_write.js",
        "try { await atlas.call('jira.comment.add', {key: 'ABC-1', body: 'x'}); return 'sent'; }\ncatch (e) { return e.class; }",
    )
    .await?;
    assert_eq!(
        data_at(envelope(&r)?, &["result"]),
        Some(&json!("validation")),
        "{}",
        r.stdout
    );
    let written = mock
        .received()
        .await
        .iter()
        .filter(|req| req.method.as_str() != "GET")
        .count();
    assert_eq!(written, 0, "a script wrote to the upstream");

    // The loop: stopped at the limit, before any call: direct and data-free.
    let spin = script_file(&world, "s11_loop.js", "while (true) {}")?;
    let r = script(
        &world,
        &spin,
        &[
            "--reason",
            RELEASE,
            "--limits",
            r#"{"timeout_s":5}"#,
            "--timeout",
            LONG_WAIT,
        ],
    )
    .await?;
    let env = envelope(&r)?;
    assert_eq!(r.exit, 8, "{}", r.stdout);
    assert_eq!(code_of(env), Some(ErrorCode::ScriptLimit), "{}", r.stdout);
    assert!(env.data.is_none(), "{}", r.stdout);

    // A heap bomb: no call and no queue (the slots are free), so a limit is direct and data-free,
    // like the loop above: `failed`, `script_limit`, exit 8. Which limit measured it first is in
    // the audit below: `heap_mb` (the allocator's refusal), or `process_mb` where the OS limit
    // fires before it.
    let bomb = script_file(
        &world,
        "s11_bomb.js",
        "const keep = [];\nwhile (true) { keep.push('x'.repeat(1000000)); }\n",
    )?;
    let r = script(
        &world,
        &bomb,
        &[
            "--reason",
            RELEASE,
            "--limits",
            r#"{"heap_mb":32,"max_call_result_mb":4,"process_mb":160,"timeout_s":30}"#,
            "--timeout",
            LONG_WAIT,
        ],
    )
    .await?;
    let env = envelope(&r)?;
    assert_eq!(r.exit, 8, "{}", r.stdout);
    assert_eq!(env.status, Status::Failed, "{}", r.stdout);
    assert_eq!(code_of(env), Some(ErrorCode::ScriptLimit), "{}", r.stdout);
    assert!(env.data.is_none(), "{}", r.stdout);

    // A limit after a call is data-dependent: not a direct failure, a release item.
    let after_call = script_file(
        &world,
        "s11_limit_after_call.js",
        "await atlas.call('jira.issue.get', {key: 'ABC-1'});\nwhile (true) {}\n",
    )?;
    let r = script(
        &world,
        &after_call,
        &[
            "--reason",
            RELEASE,
            "--limits",
            r#"{"timeout_s":5}"#,
            "--timeout",
            LONG_WAIT,
        ],
    )
    .await?;
    assert_eq!(envelope(&r)?.status, Status::Released, "{}", r.stdout);

    // What a run read stays on the release item until it is released.
    let canary = "S11-DATA-CANARY-7f3a";
    let secret = script_file(
        &world,
        "s11_data.js",
        &format!(
            "const i = await atlas.call('jira.issue.get', {{key: 'ABC-1'}});\nthrow new Error('{canary}');"
        ),
    )?;
    let id = submit(&world, &secret, HOLD, &[]).await?;
    // The run has ended (its error is on the release item): the answers below are those of a
    // request that holds the data.
    wait_queued(&world, &[id.as_str()]).await?;
    for args in [
        vec!["status", id.as_str()],
        vec!["await", id.as_str(), "--timeout", "1"],
    ] {
        let r = run(&world, &args).await?;
        assert_eq!(envelope(&r)?.status, Status::Pending, "{}", r.stdout);
        texts_hold_none(&r, &[canary, "script_error", "Error"])?;
    }
    cancel(&world, &id).await?;
    let r = script(
        &world,
        &secret,
        &["--reason", RELEASE, "--timeout", LONG_WAIT],
    )
    .await?;
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Released, "{}", r.stdout);
    assert!(
        r.stdout.contains(canary),
        "the released twin lacks the error: {}",
        r.stdout
    );

    let records = audit(&world).await?;
    assert_eq!(count_of(&records, EventType::SCRIPT_DENIED), 0);
    let failed = payloads(&records, EventType::SCRIPT_FAILED);
    assert!(
        failed.iter().any(|p| {
            p["direct"] == json!(true)
                && matches!(p["reason"].as_str(), Some("heap_mb" | "process_mb"))
        }),
        "the heap bomb was not a direct memory-limit stop: {failed:?}"
    );
    assert!(
        failed
            .iter()
            .any(|p| p["direct"] == json!(true) && p["reason"] == json!("timeout_s")),
        "the loop was not a direct timeout stop: {failed:?}"
    );
    Ok(())
}

/// I-41 / §9.1: the worker binary replaced after the app's start is an app upgrade: the next
/// script is refused as `sandbox_unavailable` with `app_upgraded` (retryable: restart the app),
/// never as a protocol violation, and so is every script after it (the flag stays until the app
/// restarts), while a plain read still works. The audit has the reason. The install is a private
/// copy (`copy_install`): the build output is never replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i41_replaced_sandbox_binary_is_app_upgraded() -> Result<()> {
    if !opted_in("i41_replaced_sandbox_binary_is_app_upgraded") {
        return Ok(());
    }
    let world = jira_world(WorldOpts::default().with_copy_install()).await?;
    let file = script_file(&world, "i41.js", "return 'before';")?;
    // The worker works, and the app has recorded its identity.
    let r = script(
        &world,
        &file,
        &["--reason", RELEASE, "--timeout", LONG_WAIT],
    )
    .await?;
    assert_eq!(envelope(&r)?.status, Status::Released, "{}", r.stdout);
    let r = script(&world, &file, &["--dry-run=full", "--timeout", LONG_WAIT]).await?;
    assert_eq!(envelope(&r)?.status, Status::Succeeded, "{}", r.stdout);

    // The replacement: the same bytes and one more, renamed over the worker.
    let worker = world
        .installed_worker()
        .ok_or("no installed worker")?
        .to_path_buf();
    let mut bytes = std::fs::read(&worker)?;
    bytes.push(0);
    let next = worker.with_extension("new");
    std::fs::write(&next, &bytes)?;
    let mut renamed = false;
    for _ in 0..40 {
        if std::fs::rename(&next, &worker).is_ok() {
            renamed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(renamed, "the worker could not be replaced");

    for args in [
        vec!["--reason", RELEASE, "--timeout", LONG_WAIT],
        vec!["--reason", RELEASE, "--timeout", LONG_WAIT],
        vec!["--dry-run=full", "--timeout", LONG_WAIT],
    ] {
        let r = script(&world, &file, &args).await?;
        let env = envelope(&r)?;
        assert_eq!(r.exit, 8, "{}", r.stdout);
        assert_eq!(env.status, Status::Failed, "{}", r.stdout);
        assert_eq!(
            code_of(env),
            Some(ErrorCode::SandboxUnavailable),
            "{}",
            r.stdout
        );
        assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
        assert_eq!(
            detail(env, "reason"),
            Some(&json!("app_upgraded")),
            "{}",
            r.stdout
        );
        texts_hold_none(&r, &["protocol_violation"])?;
    }
    // The rest of the product is not affected.
    let r = run(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--reason",
            RELEASE,
            "--timeout",
            LONG_WAIT,
        ],
    )
    .await?;
    assert_eq!(envelope(&r)?.status, Status::Released, "{}", r.stdout);

    let records = audit(&world).await?;
    let failed = payloads(&records, EventType::SCRIPT_FAILED);
    assert!(
        failed.iter().any(|p| {
            p["reason"] == json!("sandbox_unavailable")
                && p["details"]["reason"] == json!("app_upgraded")
        }),
        "no app_upgraded failure in the audit: {failed:?}"
    );
    assert!(
        !failed
            .iter()
            .any(|p| p["reason"] == json!("protocol_violation")),
        "{failed:?}"
    );
    Ok(())
}
