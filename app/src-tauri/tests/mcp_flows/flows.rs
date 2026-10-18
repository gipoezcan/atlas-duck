//! `mcp_flows` (M9 Tasks 13-14): the real `atlas-duck mcp` over the stdio driver, against the real
//! app and mock Atlassian servers. Task 13 is the smoke flow; Task 14 the end-to-end flows I-04,
//! I-16, I-17 and I-41 (§4.6) and the recovery of a pending request after an app crash.
//!
//! Every flow spawns a binary and therefore starts with [`opted_in`]: it skips unless
//! `ATLAS_DUCK_CLI_FLOWS=1` (CI). Every wait is bounded (the driver's timeouts, or a loop with its
//! own deadline), so a flow fails by assertion or timeout and never hangs.
//!
//! Harness facts the flows rely on:
//! - An app that `atlas-duck mcp` auto-launched has no `AppProc`. A flow that must kill an app, or
//!   start it with its own environment, starts it through `World::start_app*` before the MCP
//!   child's first connected tool call; the child then connects to it and never launches.
//! - `World::quit_app` leaves `test-control/quit` behind and the app never removes it: a later app
//!   of the same home (started by the test or auto-launched by the MCP child) would end at once.
//!   [`quit_app`] removes the file.
//! - Heartbeats run only while the `request.await` is in flight (ledger L159), so a flow that counts
//!   them connects first (`instances_list`) and then sends the waiting call.

use std::time::{Duration, Instant};

use atlas_duck_app_lib::testing::ENV_TEST_SERVER_BUILD_ID;
use atlas_duck_app_lib::testing::control::{DELAY_STARTUP_FILE, QUIT_FILE};
use atlas_duck_atlassian::testing::fixtures::{self, JIRA_COMMENT};
use atlas_duck_atlassian::testing::{MockDc, TEST_USER, UserKind};
use atlas_duck_audit::request_set::requests_from_json;
use atlas_duck_audit::{EventType, RequestRecord};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_ipc::paths::ENDPOINT_FILE;
use atlas_duck_registry::Product;
use serde_json::{Value, json};

use crate::driver::{CallOutcome, McpChild};
use crate::harness::{PAT_CANARY, Result, World, WorldOpts, opted_in};

/// The number of tools of the full set: one per registry op plus `script_run`, `request_await`,
/// `request_status`, `request_cancel`, `request_list`, `ops_list`, `ops_describe` and
/// `instances_list`.
const FULL_TOOL_COUNT: usize = 54;

/// §4.6, verbatim (`mcp/result.rs` `RESTART_TEXT`, typed out here so the flow does not compare the
/// implementation with itself): the first text block of every `protocol_mismatch` and every
/// `unreachable` result.
const RESTART_TEXT: &str = "atlas-duck was restarted or upgraded; restart this MCP server (or your MCP client) if this persists";
/// The `ATLAS_DUCK_MCP_TIMEOUT` variable (§4.6).
const TIMEOUT_ENV: &str = "ATLAS_DUCK_MCP_TIMEOUT";
/// A build id that differs from the client's and is newer than any real one.
const OTHER_BUILD: &str = "999.0.0+mcp-flows-other";
/// How long a decision of the scripted approver may take (it ticks every 50 ms).
const DECIDED_WITHIN: Duration = Duration::from_secs(30);
/// The mock holds the comment POST this long: the write stays `executing` while the app shuts
/// down (`i41_mcp_app_shutting_down_is_error`).
const WRITE_HELD: Duration = Duration::from_secs(12);
/// How long the shutdown flow keeps submitting until one submit meets the shutdown; well under
/// [`WRITE_HELD`], which is the length of the whole shutdown window.
const SHUTDOWN_PROBE_WITHIN: Duration = Duration::from_secs(8);
const ERR_404_BODY: &str = r#"{"errorMessages":["Issue does not exist"],"errors":{}}"#;
const ERR_500_BODY: &str = r#"{"errorMessages":["Server error"],"errors":{}}"#;
const COMMENT_PARAMS: &str = r#"{"key":"ABC-1","body":"Seen on staging.","body_format":"wiki"}"#;
/// X-05 data canaries. `X05_SEARCH` and `X05_KEPT` sit in a `summary` the approver releases;
/// `X05_DROPPED` sits in the `description` it drops; `X05_CONTROL` sits in the `description` of an
/// issue released whole (the positive control: that field does reach released bytes).
const X05_SEARCH: &str = "CANARY-X05-SEARCH-6b1d9e40";
const X05_KEPT: &str = "CANARY-X05-KEPT-2f87c3a5";
const X05_DROPPED: &str = "CANARY-X05-DROPPED-91c4d7e8";
const X05_CONTROL: &str = "CANARY-X05-CONTROL-0a53b6f2";
/// The scripted approver's drop of the redacted read (`atlas-test:release-redacted <path>`).
const X05_REDACT_REASON: &str = "atlas-test:release-redacted fields.description";
/// The field list of the app's start fill of the field-name cache (as `jira_flows`).
const X05_FIELDS: &str = r#"[{"id":"summary","name":"Summary","custom":false,"schema":{"type":"string","system":"summary"}},{"id":"customfield_10200","name":"Team","custom":true,"schema":{"type":"option","custom":"com.atlassian.jira.plugin.system.customfieldtypes:select","customId":10200}}]"#;

// ---- helpers -----------------------------------------------------------------------------------

/// One Jira instance `jira-main`; the first connected tool call cold-starts the app through the
/// test home unless the flow started it.
pub(crate) async fn jira_world() -> Result<World> {
    let mut world = World::new(WorldOpts::default())?;
    world
        .provision_store(&[("jira-main", Product::Jira)])
        .await?;
    Ok(world)
}

fn jira(world: &World) -> Result<&atlas_duck_atlassian::testing::MockDc> {
    world
        .mock("jira-main")
        .ok_or_else(|| "no mock for jira-main".into())
}

/// Spawns `atlas-duck mcp` with `ATLAS_DUCK_MCP_TIMEOUT=<timeout>` and completes the handshake.
async fn mcp_client(world: &World, client_name: &str, timeout: &str) -> Result<McpChild> {
    let mut mcp = McpChild::new(world.mcp_spawn(&["mcp"], &[(TIMEOUT_ENV, timeout)])?)?;
    mcp.initialize(client_name).await?;
    Ok(mcp)
}

/// [`World::quit_app`], then the `quit` control file is removed again (see the module comment).
async fn quit_app(world: &World) -> Result<()> {
    world.quit_app().await?;
    match std::fs::remove_file(world.control_dir().join(QUIT_FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn endpoint_exists(world: &World) -> Result<bool> {
    Ok(world.data_dir().join(ENDPOINT_FILE).try_exists()?)
}

/// Polls (at most `within`) until the app of this home has published its endpoint.
async fn wait_for_endpoint(world: &World, within: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if endpoint_exists(world)? {
            return Ok(());
        }
        if start.elapsed() > within {
            return Err(format!("no endpoint within {within:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn status_of(env: &Value) -> &str {
    env["status"].as_str().unwrap_or("")
}

fn error_code(env: &Value) -> &str {
    env["error"]["code"].as_str().unwrap_or("")
}

fn error_reason(env: &Value) -> &str {
    env["error"]["details"]["reason"].as_str().unwrap_or("")
}

/// The first text block of a tool result.
fn first_text(out: &CallOutcome) -> String {
    out.result["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// `jira_issue_get ABC-1` released at once by the scripted approver.
async fn release_get(mcp: &mut McpChild) -> Result<CallOutcome> {
    mcp.call(
        "jira_issue_get",
        json!({"key": "ABC-1", "reason": "atlas-test:release"}),
        None,
    )
    .await
}

/// The result is the released envelope of a successful read.
fn assert_released(mcp: &McpChild, out: &CallOutcome) {
    assert!(!out.is_error(), "{}", mcp.transcript());
    assert_eq!(
        status_of(out.structured()),
        "released",
        "{}",
        mcp.transcript()
    );
}

/// The result is an error that tells the agent to restart the MCP server: `unreachable` or
/// `protocol_mismatch`, with the §4.6 text first.
fn assert_restart_error(mcp: &McpChild, out: &CallOutcome) {
    let env = out.structured();
    assert!(out.is_error(), "{env}\n{}", mcp.transcript());
    assert!(
        matches!(error_code(env), "unreachable" | "protocol_mismatch"),
        "{env}\n{}",
        mcp.transcript()
    );
    assert_eq!(first_text(out), RESTART_TEXT, "{}", mcp.transcript());
}

/// The progress notifications of `token`, in wire order.
fn progress_of(notes: &[Value], token: &str) -> Vec<Value> {
    notes
        .iter()
        .filter(|n| {
            n["method"] == "notifications/progress" && n["params"]["progressToken"] == token
        })
        .cloned()
        .collect()
}

/// The id of the "submitted request_id=<id> status=pending" notification of `token`, if one was
/// seen.
pub(crate) fn submitted_id(notes: &[Value], token: &str) -> Option<String> {
    progress_of(notes, token).iter().find_map(|n| {
        let message = n["params"]["message"].as_str()?;
        let rest = message.strip_prefix("submitted request_id=")?;
        rest.split_whitespace().next().map(str::to_owned)
    })
}

/// Reads the wire (at most 30 s) until the waiting call `call_id` has told its id through the
/// "submitted" notification. Every notification read on the way is added to `notes`.
async fn wait_submitted(
    mcp: &mut McpChild,
    call_id: u64,
    token: &str,
    notes: &mut Vec<Value>,
) -> Result<String> {
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        // An error here is the call being answered before it told its id, or a dead wire.
        mcp.expect_no_response(call_id, Duration::from_millis(200))
            .await?;
        notes.extend(mcp.take_notifications());
        if let Some(id) = submitted_id(notes, token) {
            return Ok(id);
        }
        if Instant::now() > until {
            return Err(format!("no submitted notification\n{}", mcp.transcript()).into());
        }
    }
}

/// Polls `request_status` until `accept` holds for the envelope; every poll is a short call.
async fn wait_status(
    mcp: &mut McpChild,
    id: &str,
    accept: impl Fn(&Value) -> bool,
) -> Result<Value> {
    let start = Instant::now();
    loop {
        let out = mcp
            .call("request_status", json!({"request_id": id}), None)
            .await?;
        let env = out.structured().clone();
        if accept(&env) {
            return Ok(env);
        }
        if start.elapsed() > DECIDED_WITHIN {
            return Err(
                format!("{id} did not reach the status within {DECIDED_WITHIN:?}: {env}").into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

fn open_status(env: &Value) -> bool {
    matches!(status_of(env), "pending" | "executing")
}

// ---- smoke -------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_flows_smoke() -> Result<()> {
    if !opted_in("mcp_flows_smoke") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mut mcp = McpChild::new(world.mcp_spawn(&["mcp"], &[])?)?;
    mcp.initialize("mcp-flows").await?;

    let tools = mcp.list_tools().await?;
    assert_eq!(tools.len(), FULL_TOOL_COUNT, "{}", mcp.transcript());

    let call = mcp
        .call(
            "jira_issue_get",
            json!({"key": "ABC-1", "reason": "atlas-test:release"}),
            None,
        )
        .await?;
    assert!(!call.is_error(), "{}", mcp.transcript());
    assert_eq!(
        call.structured()["status"],
        "released",
        "{}",
        mcp.transcript()
    );
    for line in mcp.raw_stdout_lines() {
        assert!(!line.contains(PAT_CANARY), "the PAT canary is on stdout");
    }

    // End of input: the server ends by itself, with success.
    mcp.close_stdin();
    let status = mcp.wait_exit().await?;
    assert!(status.success(), "{status}\n{}", mcp.transcript());
    world.quit_app().await?;
    Ok(())
}

// ---- I-04: heartbeats, the timeout result, cancellation --------------------------------------------

/// I-04 end to end (§4.6): with `ATLAS_DUCK_MCP_TIMEOUT=12` and a progress token, a read the
/// approver holds answers (1) a "submitted request_id=<id> status=pending" notification first, (2)
/// at least two heartbeats (a message-less notification every 5 s from the call's receipt, so at
/// 5 s and 10 s), then (3) after about 12 s the `pending` result: `isError: false`, the id, and
/// the §4.6 sentence as the first text. `notifications/cancelled` for a second waiting call
/// (`request_await`) ends that wait without a response and without touching the request: it is
/// still `pending` for `request_status`; only `request_cancel` cancels it (`cancelled`,
/// `by_client`, `isError: true`).
///
/// Source: `mcp/progress.rs` (`wait_with_progress`: timer at receipt + 5 s, `Delay`; the
/// notification is awaited before the response is written), `mcp/call.rs` (`submit_and_wait`,
/// `await_request`), `mcp/result.rs` (`timeout_text`, `is_error`). The app is started first and
/// `instances_list` connects before the waiting call, so the await starts within milliseconds of
/// the receipt and the 10 s tick has two seconds of slack before the 12 s deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i04_e2e_heartbeat_timeout_cancel() -> Result<()> {
    if !opted_in("i04_e2e_heartbeat_timeout_cancel") {
        return Ok(());
    }
    const TOKEN: &str = "tok-i04";
    let world = jira_world().await?;
    let _app = world.start_app().await?;
    let mut mcp = mcp_client(&world, "mcp-flows-i04", "12").await?;
    let warm = mcp.call("instances_list", json!({}), None).await?;
    assert!(!warm.is_error(), "{}", mcp.transcript());

    let start = Instant::now();
    let call_id = mcp
        .send_call(
            "jira_issue_get",
            json!({"key": "ABC-1", "reason": "atlas-test:hold"}),
            Some(TOKEN),
        )
        .await?;
    let out = mcp.wait_call(call_id, Duration::from_secs(45)).await?;
    let took = start.elapsed();

    // The §4.6 result: pending, not an error, the id, the fixed sentence first.
    let env = out.structured();
    assert!(!out.is_error(), "{env}\n{}", mcp.transcript());
    assert_eq!(status_of(env), "pending", "{env}");
    assert!(env["error"].is_null(), "{env}");
    let id = env["request_id"]
        .as_str()
        .ok_or_else(|| format!("no request id: {env}"))?
        .to_owned();
    assert_eq!(
        first_text(&out),
        format!("Approval pending. Call request_await with request_id={id}. Do not resubmit."),
        "{}",
        mcp.transcript()
    );
    // The deadline is measured from the receipt, which is after `start`: not before 12 s, and
    // (generous for a slow runner) not much later.
    assert!(
        took >= Duration::from_secs(11) && took < Duration::from_secs(40),
        "the call took {took:?}"
    );

    // The notifications: "submitted" first, then only heartbeats (no message), all of this call's
    // token, `progress` strictly increasing from 1, none after the result (they were read before
    // it by construction of the driver: the result is the last line of the call).
    let progress = progress_of(&out.notifications, TOKEN);
    let first = progress
        .first()
        .ok_or_else(|| format!("no progress notification\n{}", mcp.transcript()))?;
    assert_eq!(
        first["params"]["message"],
        format!("submitted request_id={id} status=pending"),
        "{}",
        mcp.transcript()
    );
    let heartbeats = progress
        .iter()
        .skip(1)
        .filter(|n| n["params"]["message"].is_null())
        .count();
    assert_eq!(
        heartbeats,
        progress.len() - 1,
        "a notification after the first is not a heartbeat: {progress:?}"
    );
    assert!(
        heartbeats >= 2,
        "{heartbeats} heartbeats in {took:?}\n{}",
        mcp.transcript()
    );
    // rmcp serializes `progress` as a float (`1.0`), so `as_u64()` would read it as absent.
    let counters: Vec<f64> = progress
        .iter()
        .map(|n| n["params"]["progress"].as_f64().unwrap_or(0.0))
        .collect();
    assert_eq!(counters.first(), Some(&1.0), "{counters:?}");
    assert!(
        counters.windows(2).all(|w| w[0] < w[1]),
        "progress is not strictly increasing: {counters:?}"
    );

    // `notifications/cancelled` stops a wait and nothing else. The first read proves the await is
    // in flight (its own 12 s deadline is far away); no response arrives, before or after the
    // cancel.
    let second = mcp
        .send_call("request_await", json!({"request_id": id}), None)
        .await?;
    mcp.expect_no_response(second, Duration::from_millis(1500))
        .await?;
    mcp.cancel(second).await?;
    mcp.expect_no_response(second, Duration::from_secs(3))
        .await?;

    // The request lives on.
    let status = mcp
        .call("request_status", json!({"request_id": id}), None)
        .await?;
    assert!(!status.is_error(), "{}", mcp.transcript());
    assert_eq!(
        status_of(status.structured()),
        "pending",
        "{}",
        mcp.transcript()
    );

    // Only `request_cancel` cancels it.
    let cancelled = mcp
        .call("request_cancel", json!({"request_id": id}), None)
        .await?;
    let env = cancelled.structured();
    assert!(cancelled.is_error(), "{env}\n{}", mcp.transcript());
    assert_eq!(status_of(env), "cancelled", "{env}");
    assert_eq!(error_code(env), "cancelled", "{env}");
    assert_eq!(error_reason(env), "by_client", "{env}");

    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    quit_app(&world).await?;
    Ok(())
}

// ---- I-16: request_status never waits --------------------------------------------------------------

/// I-16 over MCP (§4.4): `request_status` answers at once with `isError: false` for a known id in
/// every state: `pending` (held), `released`, `denied` (with details), a read released after an
/// upstream error (`release-status-only`: `failed`, `upstream_http`), and a `failed` write
/// (the mock refuses the comment). Each answer takes under 2 s, carries the id, no data and no
/// meta, and an error part is only the fixed "use await for details" (nothing is revealed).
///
/// With `ATLAS_DUCK_MCP_TIMEOUT=0` every submit returns its `pending` envelope at once, so the five
/// requests are queued back to back; the decided ones are polled with `request_status` itself.
/// Source: `mcp/call.rs` (`zero_timeout`), `mcp/result.rs` (`ToolKind::Status`: a known id is never
/// an error), core `engine/envelope.rs` `status_envelope` (reduced error, never data); the CLI
/// twin is `cli_flows` `i16_status_immediate_exit0_no_data`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i16_mcp_request_status_immediate() -> Result<()> {
    if !opted_in("i16_mcp_request_status_immediate") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mock = jira(&world)?;
    mock.json("/rest/api/2/issue/ABC-2", 200, fixtures::JIRA_ISSUE)
        .await;
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
    let _app = world.start_app().await?;
    let mut mcp = mcp_client(&world, "mcp-flows-i16", "0").await?;

    let submissions = [
        (
            "pending",
            "jira_issue_get",
            json!({"key": "ABC-2", "reason": "atlas-test:hold"}),
        ),
        (
            "released",
            "jira_issue_get",
            json!({"key": "ABC-1", "reason": "atlas-test:release"}),
        ),
        (
            "denied",
            "jira_issue_transition",
            json!({"key": "ERR-1", "transition": "Done", "reason": "atlas-test:deny-details"}),
        ),
        (
            "upstream",
            "jira_issue_get",
            json!({"key": "ERR-500", "reason": "atlas-test:release-status-only"}),
        ),
        (
            "failed_write",
            "jira_comment_add",
            json!({"key": "ABC-1", "body": "Seen on staging.", "body_format": "wiki",
                   "reason": "atlas-test:approve"}),
        ),
    ];
    let mut ids = Vec::new();
    for (label, tool, args) in submissions {
        let out = mcp.call(tool, args, None).await?;
        let env = out.structured();
        assert!(!out.is_error(), "{label}: {env}\n{}", mcp.transcript());
        assert_eq!(status_of(env), "pending", "{label}: {env}");
        let id = env["request_id"]
            .as_str()
            .ok_or_else(|| format!("{label}: no request id: {env}"))?
            .to_owned();
        ids.push((label, id));
    }
    for (label, id) in &ids {
        if *label != "pending" {
            wait_status(&mut mcp, id, |env| !open_status(env)).await?;
        }
    }

    for (label, id) in &ids {
        let start = Instant::now();
        let out = mcp
            .call("request_status", json!({"request_id": id}), None)
            .await?;
        let took = start.elapsed();
        let env = out.structured();
        assert!(
            took < Duration::from_secs(2),
            "{label}: status took {took:?}"
        );
        assert!(!out.is_error(), "{label}: {env}\n{}", mcp.transcript());
        assert_eq!(env["request_id"], id.as_str(), "{label}: {env}");
        assert!(env["data"].is_null(), "{label}: status carries data: {env}");
        assert!(env["meta"].is_null(), "{label}: status carries meta: {env}");
        match *label {
            "pending" => assert_eq!(status_of(env), "pending", "{env}"),
            "released" => assert_eq!(status_of(env), "released", "{env}"),
            "denied" => assert_eq!(status_of(env), "denied", "{env}"),
            // A read released after an upstream error is `failed` (`record_status`).
            _ => assert_eq!(status_of(env), "failed", "{label}: {env}"),
        }
        if matches!(*label, "pending" | "released") {
            assert!(env["error"].is_null(), "{label}: {env}");
        } else {
            assert_eq!(error_code(env), "upstream_http", "{label}: {env}");
            assert_eq!(env["error"]["retryable"], false, "{label}: {env}");
        }
        if !env["error"].is_null() {
            assert_eq!(
                env["error"]["message"], "use await for details",
                "{label}: {env}"
            );
            assert!(
                env["error"]["details"].is_null(),
                "{label}: status carries details: {env}"
            );
        }
    }

    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    quit_app(&world).await?;
    Ok(())
}

// ---- I-17: cold start and the deadline --------------------------------------------------------------

/// I-17 over MCP: with no app running and `ATLAS_DUCK_MCP_TIMEOUT=30`, the first tool call of the
/// session launches the app, connects, submits and returns the released read, within 30 s plus
/// 5 s of slack measured from sending the call; the app was launched (its endpoint exists). The
/// handshake and `tools/list` before it never launched anything.
///
/// Source: `mcp/session.rs` (nothing connects before the first connected call), `connected.rs`
/// `reach` (discover, launch poll, connect, `hello`), `mcp/call.rs` (the deadline starts at the
/// receipt, launch and handshake included). A cold start slower than 30 s would end
/// `launch_timeout` instead, which fails the status assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i17_mcp_cold_start_within_timeout() -> Result<()> {
    if !opted_in("i17_mcp_cold_start_within_timeout") {
        return Ok(());
    }
    let world = jira_world().await?;
    assert!(!endpoint_exists(&world)?, "an endpoint before any launch");
    let mut mcp = mcp_client(&world, "mcp-flows-i17", "30").await?;
    let tools = mcp.list_tools().await?;
    assert_eq!(tools.len(), FULL_TOOL_COUNT, "{}", mcp.transcript());
    assert!(
        !endpoint_exists(&world)?,
        "initialize or tools/list launched the app"
    );

    let start = Instant::now();
    let id = mcp
        .send_call(
            "jira_issue_get",
            json!({"key": "ABC-1", "reason": "atlas-test:release"}),
            None,
        )
        .await?;
    let out = mcp.wait_call(id, Duration::from_secs(50)).await?;
    let took = start.elapsed();
    assert_released(&mcp, &out);
    assert!(
        took < Duration::from_secs(35),
        "the cold start took {took:?}"
    );
    assert!(endpoint_exists(&world)?, "the app was not launched");

    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    quit_app(&world).await?;
    Ok(())
}

/// I-17 over MCP: a deadline that runs out before the app is up ends `unreachable
/// {launch_timeout}` (`isError`, `retryable: true`, no request id, the §4.6 restart text): the app
/// starts after `delay-startup-ms = 8000`, the deadline is `ATLAS_DUCK_MCP_TIMEOUT=3`. Nothing was
/// submitted, so once the launched app is up `request_list` is empty. The server keeps serving:
/// the later call reconnects to the app that came up.
///
/// Source: `launch/mod.rs` `ensure_running` (the poll is capped by the deadline; T11 caps the
/// Windows stub wait too), `testing/control.rs` (`delay-startup-ms`, the app sleeps before its
/// first `open`). The upper bound on the first call is far under the 20 s poll limit and absorbs a
/// slow runner (the first start of a freshly built executable); it only has to show that the call
/// honoured its 3 s and did not wait for the app.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i17_mcp_deadline_before_submit_launch_timeout() -> Result<()> {
    if !opted_in("i17_mcp_deadline_before_submit_launch_timeout") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mut mcp = mcp_client(&world, "mcp-flows-i17b", "3").await?;
    world.write_control(DELAY_STARTUP_FILE, "8000")?;

    let start = Instant::now();
    let out = release_get(&mut mcp).await?;
    let took = start.elapsed();
    let env = out.structured();
    assert_restart_error(&mcp, &out);
    assert_eq!(error_code(env), "unreachable", "{env}");
    assert_eq!(error_reason(env), "launch_timeout", "{env}");
    assert_eq!(env["error"]["retryable"], true, "{env}");
    assert!(env["request_id"].is_null(), "{env}");
    assert!(took < Duration::from_secs(15), "the call took {took:?}");

    // The launched app comes up after its delay; nothing was queued. The first calls may still
    // meet a gate or a slow first connect, so the listing is retried (each call is bounded by the
    // 3 s deadline).
    wait_for_endpoint(&world, Duration::from_secs(60)).await?;
    let mut listed = None;
    for _ in 0..8 {
        let out = mcp.call("request_list", json!({}), None).await?;
        if !out.is_error() {
            listed = Some(out);
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let listed =
        listed.ok_or_else(|| format!("request_list never answered\n{}", mcp.transcript()))?;
    let rows = listed.structured()["data"]["requests"]
        .as_array()
        .ok_or_else(|| format!("no data.requests: {}", listed.structured()))?;
    assert!(rows.is_empty(), "a request was queued: {rows:?}");

    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    quit_app(&world).await?;
    Ok(())
}

// ---- I-41: the app restarts under a running MCP server ---------------------------------------------------

/// I-41 over MCP (§4.6, §3.3): the app quits under a running `atlas-duck mcp`. The next call either
/// fails (`isError`, `unreachable` or `protocol_mismatch`, the restart text first) or, by the
/// launch rules, relaunches the app and succeeds: one of the two is asserted, and in both the
/// server is still serving afterwards. With the app running again (relaunched, or started by the
/// test), the next call is `released`: the same `atlas-duck mcp` process re-handshakes.
///
/// Source: `mcp/session.rs` (a closed connection is replaced by the next call), `mcp/call.rs`
/// `note`, `connected.rs` `reach` (a missing app is launched). `quit_app` removes the `quit` file:
/// without it the relaunched app would quit at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i41_mcp_app_restart_rehandshake() -> Result<()> {
    if !opted_in("i41_mcp_app_restart_rehandshake") {
        return Ok(());
    }
    let world = jira_world().await?;
    let _app = world.start_app().await?;
    let mut mcp = mcp_client(&world, "mcp-flows-i41", "30").await?;
    let first = release_get(&mut mcp).await?;
    assert_released(&mcp, &first);

    quit_app(&world).await?;
    let after = release_get(&mut mcp).await?;
    let relaunched = if after.is_error() {
        assert_restart_error(&mcp, &after);
        false
    } else {
        assert_released(&mcp, &after);
        true
    };

    // The app is running again: either the call above launched it, or (an error answer) the test
    // starts it; with the endpoint gone after a clean quit, a launch under way is waited for.
    if !relaunched {
        match wait_for_endpoint(&world, Duration::from_secs(10)).await {
            Ok(()) => {}
            Err(_) => {
                let _restarted = world.start_app().await?;
                let again = release_get(&mut mcp).await?;
                assert_released(&mcp, &again);
                mcp.close_stdin();
                let exit = mcp.wait_exit().await?;
                assert!(exit.success(), "{exit}\n{}", mcp.transcript());
                quit_app(&world).await?;
                return Ok(());
            }
        }
    }
    let mut recovered = None;
    for _ in 0..3 {
        let out = release_get(&mut mcp).await?;
        if !out.is_error() {
            recovered = Some(out);
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let recovered =
        recovered.ok_or_else(|| format!("no call succeeded again\n{}", mcp.transcript()))?;
    assert_released(&mcp, &recovered);

    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    quit_app(&world).await?;
    Ok(())
}

/// I-41 over MCP (§3.3, L16): the app is replaced by one that answers `hello` with another build.
/// The next call is an error with the restart text (`protocol_mismatch` for a newer app, carrying
/// both builds; `unreachable {app_upgraded}` for an older one); the app is quit and started again
/// at the client's build and the next call of the very same `atlas-duck mcp` process is
/// `released`.
///
/// Both apps are started by the test (`start_app`, `start_app_with_env`): the override
/// `ATLAS_DUCK_TEST_SERVER_BUILD_ID` is read from the app's own environment at start only, and an
/// MCP auto-launch would drop it (PD-129). No MCP call is made between the quit and the start, so
/// nothing launches an app of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i41_mcp_app_build_changed_is_error_then_rehandshake() -> Result<()> {
    if !opted_in("i41_mcp_app_build_changed_is_error_then_rehandshake") {
        return Ok(());
    }
    let world = jira_world().await?;
    let _app = world.start_app().await?;
    let mut mcp = mcp_client(&world, "mcp-flows-i41b", "30").await?;
    let first = release_get(&mut mcp).await?;
    assert_released(&mcp, &first);

    quit_app(&world).await?;
    let _other = world
        .start_app_with_env(&[(ENV_TEST_SERVER_BUILD_ID, OTHER_BUILD)])
        .await?;
    let mismatch = release_get(&mut mcp).await?;
    assert_restart_error(&mcp, &mismatch);
    let env = mismatch.structured();
    // The override is newer than the client, so this is never `app_upgraded`.
    assert_eq!(error_code(env), "protocol_mismatch", "{env}");
    assert_eq!(
        env["error"]["details"]["server_build"], OTHER_BUILD,
        "{env}"
    );
    assert!(env["error"]["details"]["client_build"].is_string(), "{env}");
    assert!(env["request_id"].is_null(), "{env}");

    // The app comes back at the client's build: the same server process recovers.
    quit_app(&world).await?;
    let _same = world.start_app_with_env(&[]).await?;
    let again = release_get(&mut mcp).await?;
    assert_released(&mcp, &again);

    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    quit_app(&world).await?;
    Ok(())
}

/// I-41 over MCP (§2.5 step 1, §3.3): while the app shuts down with a write still `executing` (the
/// mock answers the comment POST after 12 s), a submit is refused `unreachable
/// {app_shutting_down}`: `isError`, the restart text first. `not_running` is accepted too (the
/// app may have finished), never a success: the loop ends on the first `unreachable` answer and
/// fails when none comes within 8 s.
///
/// The connection is made before the quit (`instances_list`), so the refusal is the submit's own
/// (the core keeps answering other methods while it shuts down); a new connection's `hello` is
/// refused with the same reason. The control file is polled by the app, so the first submits may
/// land before it noticed the quit: they are released reads and the loop goes on (a request the
/// sweep cancels answers `cancelled`, also not `unreachable`). The write is submitted through the
/// CLI with `--timeout 0` to keep the MCP server's own deadline out of it.
///
/// Source: `core.rs` `shutdown` / `engine::enter_submit`, `shutdown.rs` `sweep` (an `executing`
/// write is waited for up to 60 s); the CLI twin is `cli_flows` `gate_shutting_down_over_endpoint`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i41_mcp_app_shutting_down_is_error() -> Result<()> {
    if !opted_in("i41_mcp_app_shutting_down_is_error") {
        return Ok(());
    }
    let world = jira_world().await?;
    jira(&world)?
        .json_delayed(
            "/rest/api/2/issue/ABC-1/comment",
            201,
            JIRA_COMMENT,
            WRITE_HELD,
        )
        .await;
    let _app = world.start_app().await?;
    let mut mcp = mcp_client(&world, "mcp-flows-i41c", "30").await?;
    let warm = mcp.call("instances_list", json!({}), None).await?;
    assert!(!warm.is_error(), "{}", mcp.transcript());

    // A write that stays `executing` for 12 s keeps the app in its shutdown for that long.
    let submitted = world
        .cli(&[
            "call",
            "jira.comment.add",
            "--params",
            COMMENT_PARAMS,
            "--reason",
            "atlas-test:approve",
            "--timeout",
            "0",
        ])
        .await?;
    let env = submitted.envelope.as_ref().ok_or("no envelope")?;
    if submitted.exit != 4 || env.status != Status::Pending {
        return Err(format!("the write did not return pending: {}", submitted.stdout).into());
    }
    let write = env.request_id.clone().ok_or("no request id")?;
    wait_status(&mut mcp, &write, |env| status_of(env) == "executing").await?;
    world.write_control(QUIT_FILE, "")?;

    let until = Instant::now() + SHUTDOWN_PROBE_WITHIN;
    let refused = loop {
        let id = mcp
            .send_call(
                "jira_issue_get",
                json!({"key": "ABC-1", "reason": "atlas-test:release"}),
                None,
            )
            .await?;
        let out = mcp.wait_call(id, Duration::from_secs(30)).await?;
        let env = out.structured();
        if out.is_error()
            && error_code(env) == "unreachable"
            && matches!(error_reason(env), "app_shutting_down" | "not_running")
        {
            break out;
        }
        if Instant::now() > until {
            return Err(format!(
                "no submit met the shutdown; the last: {}\n{}",
                out.structured(),
                mcp.transcript()
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_restart_error(&mcp, &refused);
    let env = refused.structured();
    assert!(
        matches!(error_reason(env), "app_shutting_down" | "not_running"),
        "{env}"
    );
    assert!(env["request_id"].is_null(), "{env}");

    // The write ends, then the app: the server was never asked to exit and still ends on EOF.
    world.wait_app_gone().await?;
    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    // The app is gone: no quit file may linger for a later app of this home.
    quit_app(&world).await?;
    Ok(())
}

// ---- recovery after a crash -------------------------------------------------------------------------

/// §4.4, L63 over MCP: a held read is `pending` when the app is killed hard. The waiting call ends
/// `pending` with the id and `connection_lost` (`isError`, the restart text); after the restart
/// `request_list {match_params}` finds the id (the agent recovers without resubmitting) and
/// `request_await` answers `abandoned` (`isError`, `retryable: true`). The request was not run
/// again: the mock saw no more reads of the issue after the kill, and the audit log holds exactly
/// one `REQUEST_RECEIVED` (nothing was submitted twice).
///
/// Source: `mcp/call.rs` `await_request` (`await_error` -> `connection_lost_pending`), core
/// `reconcile` (the §11.3 reconciliation after `open`), the CLI twins `i39_connection_lost_after_
/// submit_exit4` and `i26_app_killed_pending_read_abandoned_after_restart`. The app is started
/// first so the test owns its process and can kill it; `start_app` removes the stale endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_recovered_with_request_list_not_resubmitted() -> Result<()> {
    if !opted_in("pending_recovered_with_request_list_not_resubmitted") {
        return Ok(());
    }
    const TOKEN: &str = "tok-recover";
    let world = jira_world().await?;
    let mut app = world.start_app().await?;
    let mut mcp = mcp_client(&world, "mcp-flows-recover", "30").await?;

    let call_id = mcp
        .send_call(
            "jira_issue_get",
            json!({"key": "ABC-1", "reason": "atlas-test:hold"}),
            Some(TOKEN),
        )
        .await?;
    let mut notes = Vec::new();
    let id = wait_submitted(&mut mcp, call_id, TOKEN, &mut notes).await?;
    let reads = async |world: &World| -> Result<usize> {
        Ok(jira(world)?
            .received()
            .await
            .iter()
            .filter(|req| req.url.path().ends_with("/issue/ABC-1"))
            .count())
    };
    // The app fetches the read before it holds for approval: wait until the mock has seen it, so
    // the kill cannot race the fetch and the count below is not vacuous.
    let fetch_deadline = Instant::now() + Duration::from_secs(15);
    while reads(&world).await? < 1 {
        if Instant::now() > fetch_deadline {
            return Err(format!("the app never fetched ABC-1\n{}", mcp.transcript()).into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    app.kill_hard()?;
    let reads_at_kill = reads(&world).await?;
    assert_eq!(reads_at_kill, 1, "one fetch before the kill");

    // The wait ends with the id kept and nothing cancelled.
    let lost = mcp.wait_call(call_id, Duration::from_secs(45)).await?;
    let env = lost.structured();
    assert!(lost.is_error(), "{env}\n{}", mcp.transcript());
    assert_eq!(status_of(env), "pending", "{env}");
    assert_eq!(env["request_id"], id.as_str(), "{env}");
    assert_eq!(error_code(env), "unreachable", "{env}");
    assert_eq!(error_reason(env), "connection_lost", "{env}");
    assert_eq!(first_text(&lost), RESTART_TEXT, "{}", mcp.transcript());

    let _restarted = world.start_app().await?;

    // The agent recovers the id from the arguments of its call.
    let listed = mcp
        .call(
            "request_list",
            json!({"match_params": {"op_id": "jira.issue.get", "params": {"key": "ABC-1"}}}),
            None,
        )
        .await?;
    assert!(!listed.is_error(), "{}", mcp.transcript());
    let rows = listed.structured()["data"]["requests"]
        .as_array()
        .ok_or_else(|| format!("no data.requests: {}", listed.structured()))?;
    assert_eq!(rows.len(), 1, "{}", listed.structured());
    assert_eq!(
        rows[0]["request_id"],
        id.as_str(),
        "{}",
        listed.structured()
    );
    assert_eq!(rows[0]["status"], "abandoned", "{}", listed.structured());

    let awaited = mcp
        .call("request_await", json!({"request_id": id}), None)
        .await?;
    let env = awaited.structured();
    assert!(awaited.is_error(), "{env}\n{}", mcp.transcript());
    assert_eq!(status_of(env), "abandoned", "{env}");
    assert_eq!(env["request_id"], id.as_str(), "{env}");
    assert_eq!(error_code(env), "abandoned", "{env}");
    assert_eq!(env["error"]["retryable"], true, "{env}");

    // Not executed again by the restart, by the listing or by the await.
    assert_eq!(
        reads(&world).await?,
        reads_at_kill,
        "the abandoned read reached the mock again"
    );

    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    quit_app(&world).await?;
    let records = world.audit_records()?;
    let received = records
        .iter()
        .filter(|(event, _)| *event == EventType::REQUEST_RECEIVED)
        .count();
    assert_eq!(received, 1, "REQUEST_RECEIVED records");
    Ok(())
}

// ---- X-05: the SC1 walk, Jira half ----------------------------------------------------------------------

/// A Jira issue of the standard fixture under `key`, with its `summary` and `description` replaced.
fn x05_issue(key: &str, summary: &str, description: &str) -> Result<String> {
    let mut issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    issue["key"] = json!(key);
    issue["fields"]["summary"] = json!(summary);
    issue["fields"]["description"] = json!(description);
    Ok(serde_json::to_string(&issue)?)
}

/// The standard search page with `X05_SEARCH` in the summary of its first issue.
fn x05_search_page() -> Result<String> {
    let mut page: Value = serde_json::from_str(fixtures::JIRA_SEARCH_PAGE)?;
    page["issues"][0]["fields"]["summary"] = json!(format!("Login page times out {X05_SEARCH}"));
    Ok(serde_json::to_string(&page)?)
}

/// The mock answers of the walk: the canary issues `ABC-7` (summary `X05_KEPT`, description
/// `X05_DROPPED`) and `ABC-8` (description `X05_CONTROL`), the search page, the field list, the
/// enrichment and the `201` of a create and the declared `204` of an edit.
async fn x05_mount(mock: &MockDc) -> Result<()> {
    mock.json("/rest/api/2/field", 200, X05_FIELDS).await;
    mock.json(
        "/rest/api/2/issue/ABC-7",
        200,
        &x05_issue(
            "ABC-7",
            &format!("Seven {X05_KEPT}"),
            &format!("Private notes {X05_DROPPED}"),
        )?,
    )
    .await;
    mock.json(
        "/rest/api/2/issue/ABC-8",
        200,
        &x05_issue("ABC-8", "Eight", &format!("Public notes {X05_CONTROL}"))?,
    )
    .await;
    // The provisioning already answers the search path: this one goes ahead of it.
    mock.json_first("/rest/api/2/search", 200, &x05_search_page()?)
        .await;
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
    mock.json("/rest/api/2/issue", 201, fixtures::JIRA_ISSUE_CREATED)
        .await;
    mock.empty_for("PUT", "/rest/api/2/issue/ABC-1", 204).await;
    Ok(())
}

/// The front end a walk goes through. `Cli` keeps every byte of stdout and stderr of every run in
/// `seen` (name, text) for the canary sweep; the MCP child keeps its own wire.
enum Front<'a> {
    Cli {
        world: &'a World,
        seen: &'a mut Vec<(String, String)>,
    },
    Mcp(&'a mut McpChild),
}

impl Front<'_> {
    /// One op through this front end and its envelope. `ok` says which end of the outcome is
    /// expected: a success (`released`, `succeeded`: exit 0, no `isError`) or a refusal (`denied`:
    /// exit 3, `isError`).
    async fn run(&mut self, cli: &[&str], tool: &str, args: Value, ok: bool) -> Result<Value> {
        match self {
            Front::Cli { world, seen } => {
                let r = world.cli(cli).await?;
                seen.push((format!("atlas-duck {cli:?} stdout"), r.stdout.clone()));
                seen.push((format!("atlas-duck {cli:?} stderr"), r.stderr.clone()));
                let want = if ok { 0 } else { 3 };
                if r.exit != want {
                    return Err(format!(
                        "atlas-duck {cli:?}: exit {} not {want}\n{}\n{}",
                        r.exit, r.stdout, r.stderr
                    )
                    .into());
                }
                let env: Value = serde_json::from_str(r.stdout.trim()).map_err(|e| {
                    format!(
                        "atlas-duck {cli:?}: stdout is no envelope ({e}): {}",
                        r.stdout
                    )
                })?;
                Ok(env)
            }
            Front::Mcp(mcp) => {
                let out = mcp.call(tool, args, None).await?;
                if out.is_error() == ok {
                    return Err(format!(
                        "{tool}: isError is {} but {} was expected\n{}",
                        out.is_error(),
                        if ok { "a success" } else { "a refusal" },
                        mcp.transcript()
                    )
                    .into());
                }
                Ok(out.structured().clone())
            }
        }
    }
}

/// The writes the mock received so far, in arrival order: every request that is neither a `GET`
/// nor the read-only search `POST`, as (method, path, body bytes).
async fn x05_writes(mock: &MockDc) -> Vec<(String, String, Vec<u8>)> {
    let search = mock.path("/rest/api/2/search");
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() != "GET" && r.url.path() != search)
        .map(|r| {
            (
                r.method.as_str().to_owned(),
                r.url.path().to_owned(),
                r.body,
            )
        })
        .collect()
}

/// The three reads, two approved writes and two denied writes of one front end. `who` (`cli` or
/// `mcp`) is part of every written summary, so the bytes the mock received name their origin.
async fn x05_walk(front: &mut Front<'_>, mock: &MockDc, who: &str) -> Result<()> {
    // jira.search, released: the summary canary is in the released bytes.
    let env = front
        .run(
            &[
                "jira",
                "search",
                "project = ABC",
                "--reason",
                "atlas-test:release",
            ],
            "jira_search",
            json!({"jql": "project = ABC", "reason": "atlas-test:release"}),
            true,
        )
        .await?;
    assert_eq!(status_of(&env), "released", "{who} search: {env}");
    assert!(
        env.to_string().contains(X05_SEARCH),
        "{who} search: the released canary is missing: {env}"
    );

    // jira.issue.get, released redacted: the dropped field is gone, the rest is there.
    let env = front
        .run(
            &[
                "jira",
                "issue",
                "get",
                "ABC-7",
                "--reason",
                X05_REDACT_REASON,
            ],
            "jira_issue_get",
            json!({"key": "ABC-7", "reason": X05_REDACT_REASON}),
            true,
        )
        .await?;
    assert_eq!(status_of(&env), "released", "{who} redacted get: {env}");
    assert_eq!(env["redacted"], json!(true), "{who} redacted get: {env}");
    assert!(
        env["data"]["result"]["fields"]["description"].is_null(),
        "{who} redacted get: the dropped field is still there: {env}"
    );
    assert!(
        env.to_string().contains(X05_KEPT),
        "{who} redacted get: the released canary is missing: {env}"
    );
    assert!(
        !env.to_string().contains(X05_DROPPED),
        "{who} redacted get: the dropped canary is in the envelope: {env}"
    );

    // Positive control: an issue released whole carries its description canary.
    let env = front
        .run(
            &[
                "jira",
                "issue",
                "get",
                "ABC-8",
                "--reason",
                "atlas-test:release",
            ],
            "jira_issue_get",
            json!({"key": "ABC-8", "reason": "atlas-test:release"}),
            true,
        )
        .await?;
    assert_eq!(status_of(&env), "released", "{who} control get: {env}");
    assert!(
        env.to_string().contains(X05_CONTROL),
        "{who} control get: the description canary did not reach the released bytes: {env}"
    );

    // Two approved writes: each reaches the mock exactly once, at its own endpoint.
    let summary = format!("x05 {who} create");
    let before = x05_writes(mock).await.len();
    let env = front
        .run(
            &[
                "jira",
                "issue",
                "create",
                "--project",
                "ABC",
                "--type",
                "Bug",
                "--summary",
                &summary,
                "--reason",
                "atlas-test:approve",
            ],
            "jira_issue_create",
            json!({"project": "ABC", "issuetype": "Bug", "summary": summary,
                   "reason": "atlas-test:approve"}),
            true,
        )
        .await?;
    assert_eq!(status_of(&env), "succeeded", "{who} create: {env}");
    let writes = x05_writes(mock).await;
    assert_eq!(writes.len(), before + 1, "{who} create: {writes:?}");
    assert_eq!(
        writes[before].0, "POST",
        "{who} create: the mock saw {writes:?}"
    );
    assert_eq!(
        writes[before].1,
        mock.path("/rest/api/2/issue"),
        "{who} create"
    );

    let summary = format!("x05 {who} edit");
    let field = format!("summary=\"{summary}\"");
    let before = writes.len();
    let env = front
        .run(
            &[
                "jira",
                "issue",
                "edit",
                "ABC-1",
                "--field",
                &field,
                "--reason",
                "atlas-test:approve",
            ],
            "jira_issue_edit",
            json!({"key": "ABC-1", "fields": {"summary": summary},
                   "reason": "atlas-test:approve"}),
            true,
        )
        .await?;
    assert_eq!(status_of(&env), "succeeded", "{who} edit: {env}");
    let writes = x05_writes(mock).await;
    assert_eq!(writes.len(), before + 1, "{who} edit: {writes:?}");
    assert_eq!(
        writes[before].0, "PUT",
        "{who} edit: the mock saw {writes:?}"
    );
    assert_eq!(
        writes[before].1,
        mock.path("/rest/api/2/issue/ABC-1"),
        "{who} edit"
    );

    // Two denied writes: refused, and the mock hears nothing.
    let before = writes.len();
    let env = front
        .run(
            &[
                "jira",
                "issue",
                "create",
                "--project",
                "ABC",
                "--type",
                "Bug",
                "--summary",
                "x05 denied create",
                "--reason",
                "atlas-test:deny",
            ],
            "jira_issue_create",
            json!({"project": "ABC", "issuetype": "Bug", "summary": "x05 denied create",
                   "reason": "atlas-test:deny"}),
            false,
        )
        .await?;
    assert_eq!(status_of(&env), "denied", "{who} denied create: {env}");
    let env = front
        .run(
            &[
                "jira",
                "issue",
                "edit",
                "ABC-1",
                "--field",
                "summary=\"x05 denied edit\"",
                "--reason",
                "atlas-test:deny",
            ],
            "jira_issue_edit",
            json!({"key": "ABC-1", "fields": {"summary": "x05 denied edit"},
                   "reason": "atlas-test:deny"}),
            false,
        )
        .await?;
    assert_eq!(status_of(&env), "denied", "{who} denied edit: {env}");
    assert_eq!(
        x05_writes(mock).await.len(),
        before,
        "{who}: a denied write reached the mock"
    );
    Ok(())
}

/// The requests of every `WRITE_APPROVED` record, in log order.
fn x05_approved(records: &[(EventType, Value)]) -> Result<Vec<RequestRecord>> {
    let mut all = Vec::new();
    for (kind, payload) in records {
        if *kind == EventType::WRITE_APPROVED {
            let set = requests_from_json(&payload["requests"])
                .map_err(|e| format!("WRITE_APPROVED requests: {e:?}"))?;
            all.extend(set);
        }
    }
    Ok(all)
}

/// X-05, Jira half (SC1, §13 canary sweep), through the CLI and through MCP against the same app
/// and the same mock Jira. Each front end runs the same walk: `jira.search` released, `jira.issue.get`
/// released with `fields.description` dropped by the approver, `jira.issue.create` and
/// `jira.issue.edit` approved, and one denied create and one denied edit.
///
/// What it proves: (1) the canary of the dropped field is in no stdout byte, no MCP message and no
/// stderr line of either front end, while the canaries of the released fields are in the released
/// bytes and a control issue's description canary is too (so the absence is not vacuous); (2) the
/// mock received exactly the approved bytes: its writes, in order, are the `requests` of the
/// `WRITE_APPROVED` records (method, URL, body), and there are no others; (3) a denied write sends
/// nothing to the mock (checked per write, and by the final count of writes).
///
/// Source: `jira_flows` (`md_comment_sent_as_wiki`, `i36_edit_conflict_denied_exit3`), `cli_flows`
/// `i03_write_approve_flow`, the approver directives of `testing/approver.rs`, audit
/// `request_set.rs` (`requests_to_json`). The app is started first, so both front ends use one
/// app; the audit log is read after the app quit. Confluence and script legs are Task 24.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x05_sc1_walk_jira_cli_and_mcp() -> Result<()> {
    if !opted_in("x05_sc1_walk_jira_cli_and_mcp") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mock = jira(&world)?;
    x05_mount(mock).await?;
    let _app = world.start_app().await?;

    // The CLI half.
    let mut seen: Vec<(String, String)> = Vec::new();
    {
        let mut cli = Front::Cli {
            world: &world,
            seen: &mut seen,
        };
        x05_walk(&mut cli, mock, "cli").await?;
    }

    // The MCP half, the same walk.
    let mut mcp = mcp_client(&world, "mcp-flows-x05", "30").await?;
    x05_walk(&mut Front::Mcp(&mut mcp), mock, "mcp").await?;
    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    // Read the rest of stdout up to its end, so a late line does not go unscanned.
    mcp.wait_stdout_eof(Duration::from_secs(10)).await?;
    for (n, line) in mcp.raw_stdout_lines().into_iter().enumerate() {
        seen.push((format!("atlas-duck mcp stdout line {n}"), line));
    }
    seen.push(("atlas-duck mcp stderr".into(), mcp.stderr_text()));

    // The canary sweep: nothing the dropped field held, and no PAT, on any channel.
    // 14 CLI channels (7 calls, stdout and stderr each), 8 MCP stdout lines (the initialize
    // response and 7 call responses) and the MCP stderr.
    assert_eq!(
        seen.len(),
        14 + 8 + 1,
        "the sweep saw {} channels",
        seen.len()
    );
    for (name, text) in &seen {
        assert!(
            !text.contains(X05_DROPPED),
            "the dropped canary is in {name}: {text}"
        );
        assert!(!text.contains(PAT_CANARY), "the PAT canary is in {name}");
    }

    // The mock received exactly what the approvals covered.
    let sent = x05_writes(mock).await;
    quit_app(&world).await?;
    let records = world.audit_records()?;
    let approved = x05_approved(&records)?;
    assert_eq!(approved.len(), 4, "approved request sets: {approved:?}");
    assert_eq!(sent.len(), 4, "the mock received {} writes", sent.len());
    let origins = [
        ("cli create", "/rest/api/2/issue"),
        ("cli edit", "/rest/api/2/issue/ABC-1"),
        ("mcp create", "/rest/api/2/issue"),
        ("mcp edit", "/rest/api/2/issue/ABC-1"),
    ];
    for ((request, (method, path, body)), (origin, endpoint)) in
        approved.iter().zip(&sent).zip(origins)
    {
        assert_eq!(&request.method, method, "{origin}");
        assert_eq!(
            request.resolved_url,
            format!("{}{endpoint}", mock.base_url()),
            "{origin}: the approved URL; the mock saw {path}"
        );
        assert_eq!(
            &request.body_bytes, body,
            "{origin}: the bytes on the wire are not the approved bytes"
        );
        assert!(
            String::from_utf8_lossy(body).contains(&format!("x05 {origin}")),
            "{origin}: the written body is {:?}",
            String::from_utf8_lossy(body)
        );
    }
    let denied = records
        .iter()
        .filter(|(kind, _)| *kind == EventType::WRITE_DENIED)
        .count();
    assert_eq!(denied, 4, "WRITE_DENIED records");
    Ok(())
}

// ---- Confluence tools (Task 22) ------------------------------------------------------------------

/// The fixture set's page and its wire path under the context path.
const WIKI_PAGE_ID: &str = "65537";
const WIKI_PAGE_PATH: &str = "/rest/api/content/65537";
/// The `userKey` `MockDc::mount_fixture_set` answers `user/current` with for Confluence.
const WIKI_USER_KEY: &str = "8a7f808a1";

/// One Confluence instance `wiki` (the only one of its product, so a tool call without `instance`
/// routes to it); the mock answers the fixture set: `user/current`, the applinks manifest, page
/// `65537` at version 7 and a search page.
async fn wiki_world() -> Result<World> {
    let mut world = World::new(WorldOpts::default())?;
    world
        .provision_store(&[("wiki", Product::Confluence)])
        .await?;
    Ok(world)
}

fn wiki(world: &World) -> Result<&MockDc> {
    world.mock("wiki").ok_or_else(|| "no mock for wiki".into())
}

/// The mock started over (as `confluence_flows`): no mount of the fixture set is left, only the
/// identity and the applinks answers of the provisioning.
async fn restart_wiki(mock: &MockDc) {
    mock.server().reset().await;
    mock.confluence_user_current(UserKind::Known, TEST_USER, WIKI_USER_KEY)
        .await;
    mock.applinks_manifest(fixtures::CONFLUENCE_8_5_VERSION)
        .await;
}

/// The fixture page as the historical version 6 (stage 2 of a page update).
fn wiki_historical_page() -> Result<String> {
    let mut v: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE)?;
    v["status"] = json!("historical");
    v["version"]["number"] = json!(6);
    v["body"]["storage"]["value"] = json!("<p>Check the build, first draft.</p>");
    Ok(v.to_string())
}

/// The fixture search page as the first of five results: a page size of one, `totalSize` 5 and a
/// `_links.next`, so a read of `max` 1 stops with a continuation.
fn wiki_search_first_of_five() -> Result<String> {
    let mut v: Value = serde_json::from_str(fixtures::CONFLUENCE_SEARCH_PAGE)?;
    v["limit"] = json!(1);
    v["totalSize"] = json!(5);
    v["_links"]["next"] = json!("/rest/api/search?start=1&limit=1");
    Ok(v.to_string())
}

/// Task 22: the Confluence tools through MCP, against the same app and mock as the CLI's
/// `confluence_flows` (this flow is their MCP twin). Four calls, in this order:
/// 1. `confluence_page_get {id, format: markdown}` released: `data.result.body.format` is
///    `markdown` and `meta.conversion` is there.
/// 2. `confluence_search {cql, max: 1}` released against a page that has more: the tool description
///    carries the `meta.page.next_start` sentence, and `meta.page` is the one the core wrote.
/// 3. `confluence_page_update` of a Markdown body with a `page get` placeholder: `failed` /
///    `markdown_placeholders`, `isError`, and nothing fetched or written.
/// 4. `confluence_page_update` from base version 6 of a page at version 7, denied by the
///    scripted approver (`atlas-test:deny`; the conflict hold takes no hint): `denied`, `isError`,
///    exactly the two page GETs (the second `version=6&status=historical`), no `PUT` at the mock.
///
/// Source: `confluence_flows` (`page_update_conflict_denied_exit3`, `placeholders_rejected_exit2`,
/// `page_get_markdown_released_with_conversion_meta`, `cql_rewrite_on_the_wire`), `engine/read.rs`
/// (`meta.page`: start, returned, total, truncated, next_start), `ipc::proto::exit_code` (a failed
/// `markdown_placeholders` is exit 2, so `isError`), the tool catalog `mcp_tools_full.json`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confluence_tools_end_to_end() -> Result<()> {
    if !opted_in("confluence_tools_end_to_end") {
        return Ok(());
    }
    let world = wiki_world().await?;
    let mock = wiki(&world)?;
    // The search page mount goes ahead of the fixture's; the page and identity mounts of the
    // fixture set serve the first calls and are reset before the conflict.
    mock.json_first("/rest/api/search", 200, &wiki_search_first_of_five()?)
        .await;
    let _app = world.start_app().await?;
    let mut mcp = mcp_client(&world, "mcp-flows-confluence", "30").await?;

    // 1. page get as Markdown.
    let out = mcp
        .call(
            "confluence_page_get",
            json!({"id": WIKI_PAGE_ID, "format": "markdown", "reason": "atlas-test:release"}),
            None,
        )
        .await?;
    assert_released(&mcp, &out);
    let env = out.structured();
    assert_eq!(
        env["data"]["result"]["body"]["format"],
        json!("markdown"),
        "{env}"
    );
    assert!(env["meta"]["conversion"]["lossy"].is_boolean(), "{env}");
    assert!(env["meta"]["conversion"]["lost"].is_object(), "{env}");

    // 2. search, paginated.
    let tools = mcp.list_tools().await?;
    let search = tools
        .iter()
        .find(|t| t["name"] == "confluence_search")
        .ok_or("no confluence_search tool")?;
    let description = search["description"].as_str().unwrap_or_default();
    assert!(
        description.contains("continue only from meta.page.next_start"),
        "the next_start sentence is missing: {description}"
    );
    let out = mcp
        .call(
            "confluence_search",
            json!({"cql": "space = DOC", "max": 1, "reason": "atlas-test:release"}),
            None,
        )
        .await?;
    assert_released(&mcp, &out);
    assert_eq!(
        out.structured()["meta"]["page"],
        json!({"start": 0, "returned": 1, "total": 5, "truncated": true, "next_start": 1}),
        "{}",
        out.structured()
    );

    // 3. a placeholder in a Markdown body: refused before anything is fetched or queued.
    let fetched_before = mock.received().await.len();
    let out = mcp
        .call(
            "confluence_page_update",
            json!({"id": WIKI_PAGE_ID, "base_version": 7, "body": "[macro: toc {}]",
                   "reason": "atlas-test:approve"}),
            None,
        )
        .await?;
    let env = out.structured();
    assert!(out.is_error(), "{env}\n{}", mcp.transcript());
    assert_eq!(status_of(env), "failed", "{env}");
    assert_eq!(error_code(env), "markdown_placeholders", "{env}");
    assert_eq!(
        env["error"]["details"]["placeholders"],
        json!([{"kind": "macro", "count": 1}]),
        "{env}"
    );
    assert_eq!(
        mock.received().await.len(),
        fetched_before,
        "a refused body reached the mock"
    );

    // 4. a stale base version: the conflict hold, denied.
    restart_wiki(mock).await;
    mock.json_once(WIKI_PAGE_PATH, 200, fixtures::CONFLUENCE_PAGE)
        .await;
    mock.json(WIKI_PAGE_PATH, 200, &wiki_historical_page()?)
        .await;
    let out = mcp
        .call(
            "confluence_page_update",
            json!({"id": WIKI_PAGE_ID, "base_version": 6, "body": "**done**",
                   "reason": "atlas-test:deny"}),
            None,
        )
        .await?;
    let env = out.structured();
    assert!(out.is_error(), "{env}\n{}", mcp.transcript());
    assert_eq!(status_of(env), "denied", "{env}");
    // The log was cleared by the reset, so these are the update's own GETs: the current page
    // (stage 1), then the base version (stage 2: `version=6&status=historical`).
    let page_path = mock.path(WIKI_PAGE_PATH);
    let received = mock.received().await;
    let gets: Vec<Vec<(String, String)>> = received
        .iter()
        .filter(|r| r.method.as_str() == "GET" && r.url.path() == page_path)
        .map(|r| {
            r.url
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .collect();
    assert_eq!(gets.len(), 2, "{gets:?}");
    let has = |q: &[(String, String)], name: &str, value: &str| {
        q.iter().any(|(k, v)| k == name && v == value)
    };
    assert!(!has(&gets[0], "status", "historical"), "{gets:?}");
    assert!(has(&gets[1], "version", "6"), "{gets:?}");
    assert!(has(&gets[1], "status", "historical"), "{gets:?}");
    let puts = received
        .iter()
        .filter(|r| r.method.as_str() == "PUT")
        .count();
    assert_eq!(puts, 0, "a denied update reached the mock");

    for line in mcp.raw_stdout_lines() {
        assert!(!line.contains(PAT_CANARY), "the PAT canary is on stdout");
    }
    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    quit_app(&world).await?;
    Ok(())
}

// ---- script_run (Task 23) --------------------------------------------------------------------------

/// `ATLAS_DUCK_MCP_TIMEOUT` of the script flows that wait for a decision: the first script of an app
/// waits for the sandbox probe (up to 60 s, counted toward the timeout), as `script_flows` waits 100 s.
const SCRIPT_TIMEOUT: &str = "100";
/// How long the driver waits for the answer of such a call (a little over [`SCRIPT_TIMEOUT`]).
const SCRIPT_ANSWER_WITHIN: Duration = Duration::from_secs(130);
/// How long a poll of the mock waits for a script to reach its call.
const SCRIPT_REACHED_WITHIN: Duration = Duration::from_secs(90);
const ISSUE_ABC_1: &str = "/issue/ABC-1";
const ISSUE_ABC_2: &str = "/issue/ABC-2";

/// One Jira instance `jira-main` (as [`jira_world`]) in a world built with `opts`.
async fn script_world(opts: WorldOpts) -> Result<World> {
    let mut world = World::new(opts)?;
    world
        .provision_store(&[("jira-main", Product::Jira)])
        .await?;
    Ok(world)
}

/// `script_run {source, reason?, dry_run?}` to its answer (bounded by [`SCRIPT_ANSWER_WITHIN`]).
async fn script_run(
    mcp: &mut McpChild,
    source: &str,
    reason: Option<&str>,
    dry_run: Option<&str>,
) -> Result<CallOutcome> {
    let mut args = json!({ "source": source });
    if let Some(reason) = reason {
        args["reason"] = json!(reason);
    }
    if let Some(mode) = dry_run {
        args["dry_run"] = json!(mode);
    }
    let id = mcp.send_call("script_run", args, None).await?;
    mcp.wait_call(id, SCRIPT_ANSWER_WITHIN).await
}

/// How many requests the mock saw whose path ends with `suffix` (any method).
async fn reads_ending(mock: &MockDc, suffix: &str) -> usize {
    mock.received()
        .await
        .iter()
        .filter(|req| req.url.path().ends_with(suffix))
        .count()
}

/// Polls (at most [`SCRIPT_REACHED_WITHIN`]) until the mock saw a request whose path ends with
/// `suffix`: the script (or read) reached its call.
async fn wait_reached(mock: &MockDc, suffix: &str) -> Result<()> {
    let start = Instant::now();
    loop {
        if reads_ending(mock, suffix).await >= 1 {
            return Ok(());
        }
        if start.elapsed() > SCRIPT_REACHED_WITHIN {
            return Err(format!("no request for {suffix} within {SCRIPT_REACHED_WITHIN:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The envelope of a cancel without what differs between two requests: their id, the `meta` clocks
/// and the routing fields (a cancel answer echoes the request's `op_id` and `instance`).
fn cancel_shape(env: &Value) -> Value {
    let mut v = env.clone();
    for key in ["request_id", "meta", "op_id", "instance"] {
        v[key] = Value::Null;
    }
    v
}

/// The §9.5 dry run is a `succeeded` envelope with `meta.dry_run: true` (an error of the script
/// is `data.script_error`, never a result).
fn assert_dry_run(mcp: &McpChild, out: &CallOutcome, what: &str) {
    let env = out.structured();
    assert_eq!(
        status_of(env),
        "succeeded",
        "{what}: {env}\n{}",
        mcp.transcript()
    );
    assert_eq!(env["meta"]["dry_run"], json!(true), "{what}: {env}");
    assert!(env["error"].is_null(), "{what}: {env}");
}

/// Task 23, U-03 over MCP: dry runs, full and sparse, need no approval and never reach the
/// upstream. A script that reads answers `succeeded`, `meta.dry_run: true`, `isError: false`, with
/// `data.result` and `data.logs`; a script that throws at runtime answers `succeeded` as well but
/// with `data.script_error` (exit 8, so `isError: true`, PD-121) and no result. The mock saw no
/// request for an issue, a search or a comment meanwhile.
///
/// Source: `script_flows` `u03_dry_run_no_http_real_worker` (the same sources, the same mock
/// filter), `engine/envelope.rs` `dry_run_succeeded`, `mcp/result.rs` `is_error` (a `script_error`
/// in `data` is exit 8). The app is started first and `instances_list` connects before the count,
/// so whatever the app asks the mock at its start is behind the baseline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_run_dry_run_full_and_sparse() -> Result<()> {
    if !opted_in("script_run_dry_run_full_and_sparse") {
        return Ok(());
    }
    let world = script_world(WorldOpts::default()).await?;
    let mock = jira(&world)?;
    let _app = world.start_app().await?;
    let mut mcp = mcp_client(&world, "mcp-flows-script-dry", SCRIPT_TIMEOUT).await?;
    let warm = mcp.call("instances_list", json!({}), None).await?;
    assert!(!warm.is_error(), "{}", mcp.transcript());
    let before = mock.received().await.len();

    let reads = "const one = await atlas.call('jira.issue.get', {key: 'DRY-1'});\n\
                 const all = await atlas.all('jira.search', {jql: 'project = DRY', max: 10});\n\
                 return {one: one !== undefined, all: all !== undefined};\n";
    for mode in ["full", "sparse"] {
        let out = script_run(&mut mcp, reads, None, Some(mode)).await?;
        let env = out.structured();
        assert!(!out.is_error(), "{mode}: {env}\n{}", mcp.transcript());
        assert_dry_run(&mcp, &out, mode);
        assert_eq!(
            env["data"]["result"],
            json!({"one": true, "all": true}),
            "{mode}: {env}"
        );
        assert!(env["data"]["logs"].is_array(), "{mode}: {env}");
        assert!(env["data"]["script_error"].is_null(), "{mode}: {env}");
    }

    let throws = "throw new Error('dry boom');\n";
    for mode in ["full", "sparse"] {
        let out = script_run(&mut mcp, throws, None, Some(mode)).await?;
        let env = out.structured();
        assert!(out.is_error(), "{mode}: {env}\n{}", mcp.transcript());
        assert_dry_run(&mcp, &out, mode);
        assert!(env["data"]["script_error"].is_object(), "{mode}: {env}");
        assert!(env["data"]["result"].is_null(), "{mode}: {env}");
    }

    // The mock heard nothing of any of the four runs.
    let touched: Vec<String> = mock
        .received()
        .await
        .iter()
        .skip(before)
        .map(|r| r.url.path().to_owned())
        .filter(|p| p.contains("/issue") || p.contains("/search") || p.contains("/comment"))
        .collect();
    assert!(
        touched.is_empty(),
        "a dry run reached the upstream: {touched:?}"
    );

    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    quit_app(&world).await?;
    let records = world.audit_records()?;
    let dry = records
        .iter()
        .filter(|(kind, _)| *kind == EventType::SCRIPT_DRY_RUN)
        .count();
    assert_eq!(dry, 4, "SCRIPT_DRY_RUN records");
    for kind in [EventType::SCRIPT_STARTED, EventType::SCRIPT_CALL] {
        let n = records.iter().filter(|(k, _)| *k == kind).count();
        assert_eq!(n, 0, "{kind:?} after dry runs only: {records:?}");
    }
    Ok(())
}

/// Task 23: a real run of a multi-call read script ends in a release item the scripted approver
/// releases (`atlas-test:release`): `released`, `isError: false`, `data.result` is what the script
/// returned, no `meta.dry_run`, and the mock saw both reads. The audit has one run, one release.
///
/// Source: `script_flows` `script_flows_smoke` (the audit kinds), `engine/envelope.rs`
/// `released_script` (`data {result}`), the approver directive `release` (it fits a `script` item).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_run_real_run_released() -> Result<()> {
    if !opted_in("script_run_real_run_released") {
        return Ok(());
    }
    let world = script_world(WorldOpts::default()).await?;
    let mock = jira(&world)?;
    mock.json("/rest/api/2/issue/ABC-2", 200, fixtures::JIRA_ISSUE)
        .await;
    let _app = world.start_app().await?;
    let mut mcp = mcp_client(&world, "mcp-flows-script-real", SCRIPT_TIMEOUT).await?;

    let source = "const a = await atlas.call('jira.issue.get', {key: 'ABC-1'});\n\
                  const b = await atlas.call('jira.issue.get', {key: 'ABC-2'});\n\
                  return {calls: 2, a: typeof a, b: typeof b};\n";
    let out = script_run(&mut mcp, source, Some("atlas-test:release"), None).await?;
    let env = out.structured();
    assert!(!out.is_error(), "{env}\n{}", mcp.transcript());
    assert_eq!(status_of(env), "released", "{env}\n{}", mcp.transcript());
    assert_eq!(
        env["data"]["result"],
        json!({"calls": 2, "a": "object", "b": "object"}),
        "{env}"
    );
    assert!(env["data"]["script_error"].is_null(), "{env}");
    assert!(env["error"].is_null(), "{env}");
    assert!(
        env["meta"]["dry_run"].is_null() || env["meta"]["dry_run"] == json!(false),
        "{env}"
    );
    assert!(
        reads_ending(mock, ISSUE_ABC_1).await >= 1 && reads_ending(mock, ISSUE_ABC_2).await >= 1,
        "the mock did not see both reads"
    );
    for line in mcp.raw_stdout_lines() {
        assert!(!line.contains(PAT_CANARY), "the PAT canary is on stdout");
    }

    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    quit_app(&world).await?;
    let records = world.audit_records()?;
    for kind in [
        EventType::SCRIPT_STARTED,
        EventType::SCRIPT_FINISHED,
        EventType::SCRIPT_RELEASED,
    ] {
        let n = records.iter().filter(|(k, _)| *k == kind).count();
        assert_eq!(n, 1, "{kind:?} in {records:?}");
    }
    Ok(())
}

/// Task 23, PD-121: a script that read something and then threw is a release item like a result;
/// the scripted approver releases it with its error details (`release`): the status is `released`
/// and the result is an error (`isError: true`): `data.script_error` carries the message, there is
/// no `data.result` and no `error` part. `request_status` of the id stays a plain answer (a known
/// id is never an error, §4.4) without data.
///
/// Source: `script_flows` `s11_containment_corpus` (a thrown error released with `release` carries
/// its message), `engine/envelope.rs` `released_script`, `ipc::proto::exit_code` (`released` with
/// `data.script_error` is exit 8), `mcp/result.rs` `is_error`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_error_released_is_error_result() -> Result<()> {
    if !opted_in("script_error_released_is_error_result") {
        return Ok(());
    }
    const CANARY: &str = "MCP-SCRIPT-ERROR-CANARY-4c81";
    let world = script_world(WorldOpts::default()).await?;
    let _app = world.start_app().await?;
    let mut mcp = mcp_client(&world, "mcp-flows-script-error", SCRIPT_TIMEOUT).await?;

    let source = format!(
        "await atlas.call('jira.issue.get', {{key: 'ABC-1'}});\nthrow new Error('{CANARY}');\n"
    );
    let out = script_run(&mut mcp, &source, Some("atlas-test:release"), None).await?;
    let env = out.structured();
    assert!(out.is_error(), "{env}\n{}", mcp.transcript());
    assert_eq!(status_of(env), "released", "{env}\n{}", mcp.transcript());
    assert!(env["error"].is_null(), "{env}");
    assert!(env["data"]["result"].is_null(), "{env}");
    assert!(env["data"]["script_error"].is_object(), "{env}");
    assert!(
        env["data"]["script_error"].to_string().contains(CANARY),
        "the released error lacks its message: {env}"
    );
    let id = env["request_id"]
        .as_str()
        .ok_or_else(|| format!("no request id: {env}"))?
        .to_owned();

    let status = mcp
        .call("request_status", json!({"request_id": id}), None)
        .await?;
    let env = status.structured();
    assert!(!status.is_error(), "{env}\n{}", mcp.transcript());
    assert_eq!(status_of(env), "released", "{env}");
    assert!(env["data"].is_null(), "status carries data: {env}");

    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    quit_app(&world).await?;
    Ok(())
}

/// Task 23, I-10 over MCP: `request_cancel` of a script that is `Running` (it made its call and
/// holds its slot busy) is the very envelope of a cancelled read: `cancelled`, `cancelled`,
/// `retryable: false`, `details.reason: by_client`, `isError: true`, equal apart from the id, the
/// `meta` clocks and the echoed `op_id`/`instance`. The cancelled script then reports `cancelled`
/// to `request_status`.
///
/// `ATLAS_DUCK_MCP_TIMEOUT=0` returns each submit as `pending` at once. The script reaching its
/// call is structural (the mock saw the request), not timed.
///
/// Source: `script_flows` `i10_cancel_identical_every_phase_real_worker` (`spinner`, `answer_shape`),
/// `i04_e2e_heartbeat_timeout_cancel` (the read's cancel).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_cancel_running_identical_envelope() -> Result<()> {
    if !opted_in("script_cancel_running_identical_envelope") {
        return Ok(());
    }
    let world = script_world(WorldOpts::default()).await?;
    let mock = jira(&world)?;
    mock.json("/rest/api/2/issue/ABC-2", 200, fixtures::JIRA_ISSUE)
        .await;
    let _app = world.start_app().await?;
    let mut mcp = mcp_client(&world, "mcp-flows-script-cancel", "0").await?;

    // Reaches its call, then holds its slot busy for 100 s (under the 120 s default limit, so it
    // never ends by itself or by a limit; the cancel ends it).
    let spinner = "await atlas.call('jira.issue.get', {key: 'ABC-1'});\n\
                   const end = Date.now() + 100000;\n\
                   while (Date.now() < end) {}\n\
                   return 'spun';\n";
    let submitted = script_run(&mut mcp, spinner, Some("atlas-test:hold"), None).await?;
    let env = submitted.structured();
    assert!(!submitted.is_error(), "{env}\n{}", mcp.transcript());
    assert_eq!(status_of(env), "pending", "{env}");
    let script_id = env["request_id"]
        .as_str()
        .ok_or_else(|| format!("no request id: {env}"))?
        .to_owned();
    // A read the approver holds, for the comparison.
    let read = mcp
        .call(
            "jira_issue_get",
            json!({"key": "ABC-2", "reason": "atlas-test:hold"}),
            None,
        )
        .await?;
    let env = read.structured();
    assert_eq!(status_of(env), "pending", "{env}");
    let read_id = env["request_id"]
        .as_str()
        .ok_or_else(|| format!("no request id: {env}"))?
        .to_owned();

    // Both are in flight: the script made its call (it is `Running` from there on, spinning) and
    // the read was fetched. The spinner has not ended: it is still open.
    wait_reached(mock, ISSUE_ABC_1).await?;
    wait_reached(mock, ISSUE_ABC_2).await?;
    let open = mcp
        .call("request_status", json!({"request_id": script_id}), None)
        .await?;
    assert!(
        open_status(open.structured()),
        "the script is not open: {}\n{}",
        open.structured(),
        mcp.transcript()
    );

    let mut shapes = Vec::new();
    for (label, id) in [("script", &script_id), ("read", &read_id)] {
        let out = mcp
            .call("request_cancel", json!({"request_id": id}), None)
            .await?;
        let env = out.structured();
        assert!(out.is_error(), "{label}: {env}\n{}", mcp.transcript());
        assert_eq!(status_of(env), "cancelled", "{label}: {env}");
        assert_eq!(env["request_id"], id.as_str(), "{label}: {env}");
        assert_eq!(error_code(env), "cancelled", "{label}: {env}");
        assert_eq!(env["error"]["retryable"], false, "{label}: {env}");
        assert_eq!(error_reason(env), "by_client", "{label}: {env}");
        shapes.push(cancel_shape(env));
    }
    assert_eq!(
        shapes[0], shapes[1],
        "the cancel of a running script differs from the cancel of a read"
    );

    let status = mcp
        .call("request_status", json!({"request_id": script_id}), None)
        .await?;
    assert_eq!(
        status_of(status.structured()),
        "cancelled",
        "{}\n{}",
        status.structured(),
        mcp.transcript()
    );

    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    quit_app(&world).await?;
    let records = world.audit_records()?;
    let released = records
        .iter()
        .filter(|(kind, _)| *kind == EventType::SCRIPT_RELEASED)
        .count();
    assert_eq!(released, 0, "a cancelled script was released: {records:?}");
    Ok(())
}

/// Task 23, I-41 over MCP (§3.4, §9.1, L168): the sandbox worker binary replaced after the app's
/// start is an app upgrade. Every later `script_run` (real or dry) is `failed` /
/// `sandbox_unavailable` with `details.reason: app_upgraded`, `retryable: true` and `isError: true`
/// (exit 8, PD-121), never a protocol violation, and the same `atlas-duck mcp` process keeps
/// serving: a plain read is `released` afterwards.
///
/// The world is built with `WorldOpts::copy_install` (M8 Task 26): the CLI, the app and the worker
/// run from a private copy and the flow replaces the copied worker, never the build output. The
/// replacement is the one of `script_flows` `i41_replaced_sandbox_binary_is_app_upgraded` (the same
/// bytes plus one, renamed over the worker, retried while Windows still holds it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i41_sandbox_replaced_is_error_with_retryable() -> Result<()> {
    if !opted_in("i41_sandbox_replaced_is_error_with_retryable") {
        return Ok(());
    }
    let world = script_world(WorldOpts::default().with_copy_install()).await?;
    let _app = world.start_app().await?;
    let mut mcp = mcp_client(&world, "mcp-flows-i41-sandbox", SCRIPT_TIMEOUT).await?;

    // The worker works, and the app has recorded its identity.
    let source = "return 'before';";
    let out = script_run(&mut mcp, source, Some("atlas-test:release"), None).await?;
    assert_eq!(
        status_of(out.structured()),
        "released",
        "{}\n{}",
        out.structured(),
        mcp.transcript()
    );
    assert!(!out.is_error(), "{}", mcp.transcript());
    let out = script_run(&mut mcp, source, None, Some("full")).await?;
    assert_dry_run(&mcp, &out, "before the replacement");
    assert!(!out.is_error(), "{}", mcp.transcript());

    // The replacement: the same bytes and one more, renamed over the copied worker.
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

    for (reason, dry_run) in [
        (Some("atlas-test:release"), None),
        (Some("atlas-test:release"), None),
        (None, Some("full")),
    ] {
        let out = script_run(&mut mcp, source, reason, dry_run).await?;
        let env = out.structured();
        assert!(out.is_error(), "{env}\n{}", mcp.transcript());
        assert_eq!(status_of(env), "failed", "{env}\n{}", mcp.transcript());
        assert_eq!(error_code(env), "sandbox_unavailable", "{env}");
        assert_eq!(error_reason(env), "app_upgraded", "{env}");
        assert_eq!(env["error"]["retryable"], true, "{env}");
        assert!(
            !env.to_string().contains("protocol_violation"),
            "a protocol violation: {env}"
        );
    }

    // The rest of the product, and the server, are not affected.
    let read = release_get(&mut mcp).await?;
    assert_released(&mcp, &read);
    let listed = mcp.call("instances_list", json!({}), None).await?;
    assert!(!listed.is_error(), "{}", mcp.transcript());

    mcp.close_stdin();
    let exit = mcp.wait_exit().await?;
    assert!(exit.success(), "{exit}\n{}", mcp.transcript());
    quit_app(&world).await?;
    let records = world.audit_records()?;
    let failed: Vec<&Value> = records
        .iter()
        .filter(|(kind, _)| *kind == EventType::SCRIPT_FAILED)
        .map(|(_, payload)| payload)
        .collect();
    assert!(
        failed.iter().any(|p| {
            p["reason"] == json!("sandbox_unavailable")
                && p["details"]["reason"] == json!("app_upgraded")
        }),
        "no app_upgraded failure in the audit: {failed:?}"
    );
    Ok(())
}
