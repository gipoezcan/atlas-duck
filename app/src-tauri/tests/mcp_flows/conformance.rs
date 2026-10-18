//! I-05 (M9 Task 15): the official TypeScript MCP SDK client against `atlas-duck mcp`.
//!
//! The test provisions Jira, starts the app, spawns `node ci/mcp-conformance/conformance.mjs`
//! (which spawns `atlas-duck mcp` through the SDK's `StdioClientTransport`) and asserts the one
//! JSON line per scenario it prints. It is `#[ignore]`d (the CI conformance step runs it with
//! `--ignored i05_`, after `npm ci`), so the regular `mcp_flows` steps never count it as a pass;
//! inside, it fails (never returns `Ok`) without `ATLAS_DUCK_MCP_CONFORMANCE=1` or without
//! `ci/mcp-conformance/node_modules`, so the conformance step cannot pass vacuously either. On
//! Linux it runs through `ci/cli-flows-linux.sh` (display and private session bus).
//!
//! Facts the scenarios rely on:
//! - The SDK's stdio transport hands the child only a short allow list of the parent's variables
//!   plus the `env` it is given, so the whole environment of the `atlas-duck mcp` child travels as
//!   JSON in `ATLAS_DUCK_CONFORMANCE_ENV` and `conformance.mjs` passes it as `env`.
//! - `large_released` serves a 3 MiB description, not 8 MiB: the SDK's `ReadBuffer` allows 10 MiB
//!   per line (`STDIO_DEFAULT_MAX_BUFFER_SIZE`) and the result carries the envelope twice
//!   (`structuredContent` and the text block), so 8 MiB of data cannot arrive. See the T15 report.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use atlas_duck_atlassian::testing::fixtures;
use atlas_duck_registry::Product;
use serde_json::{Value, json};

use crate::harness::{CLI_EXE, Result, World, WorldOpts, opted_in};

const OPT_IN_CONFORMANCE: &str = "ATLAS_DUCK_MCP_CONFORMANCE";
/// `ATLAS_DUCK_MCP_TIMEOUT` of the `atlas-duck mcp` child (the `pending` scenario waits this long).
const MCP_TIMEOUT: &str = "5";
/// The size of the mock issue's `description` in `large_released`.
const BIG_DESCRIPTION_BYTES: usize = 3 * 1024 * 1024;
/// The whole run, node included, must end within this.
const RUN_LIMIT: Duration = Duration::from_secs(300);

/// What each scenario must print: `(scenario, isError, status, error_code)`.
const EXPECTED: &[(&str, bool, &str, Option<&str>)] = &[
    ("pending", false, "pending", None),
    ("denied", true, "denied", None),
    ("expired", true, "expired", None),
    ("failed", true, "failed", Some("validation")),
    ("redacted_released", false, "released", None),
    ("write", false, "succeeded", None),
    ("generic_call", false, "released", None),
    ("large_released", false, "released", None),
];

fn project_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("ci")
        .join("mcp-conformance")
}

/// A Jira issue of the standard fixture with a `description` of `bytes` bytes, under key `ABC-BIG`.
fn big_issue(bytes: usize) -> Result<String> {
    let mut issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    issue["key"] = json!("ABC-BIG");
    issue["fields"]["description"] = json!("x".repeat(bytes));
    Ok(serde_json::to_string(&issue)?)
}

/// The three enrichment answers of a `jira.issue.create` in `ABC` with issue type `Bug`, then the
/// approved POST.
async fn mount_write(mock: &atlas_duck_atlassian::testing::MockDc) {
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
}

/// Checks the printed lines against [`EXPECTED`]: exactly these scenarios, once each, with these
/// values (the four fields only).
fn check_lines(stdout: &str) -> std::result::Result<(), String> {
    let mut seen: BTreeMap<String, Value> = BTreeMap::new();
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let v: Value =
            serde_json::from_str(line).map_err(|e| format!("not a JSON line ({e}): {line:?}"))?;
        let name = v["scenario"]
            .as_str()
            .ok_or_else(|| format!("no scenario in {line:?}"))?
            .to_owned();
        if seen.insert(name.clone(), v).is_some() {
            return Err(format!("scenario {name} printed twice"));
        }
    }
    for (name, is_error, status, code) in EXPECTED {
        let v = seen
            .remove(*name)
            .ok_or_else(|| format!("scenario {name} printed no line"))?;
        let want = json!({
            "scenario": name,
            "isError": is_error,
            "status": status,
            "error_code": code,
        });
        if v != want {
            return Err(format!("scenario {name}: got {v}, expected {want}"));
        }
    }
    match seen.keys().next() {
        Some(extra) => Err(format!("unexpected scenario {extra}")),
        None => Ok(()),
    }
}

#[test]
fn expected_lines_are_checked_strictly() {
    let all: String = EXPECTED
        .iter()
        .map(|(n, e, s, c)| {
            format!(
                "{}\n",
                json!({"scenario": n, "isError": e, "status": s, "error_code": c})
            )
        })
        .collect();
    assert_eq!(check_lines(&all), Ok(()));
    let missing = all.lines().skip(1).collect::<Vec<_>>().join("\n");
    assert!(check_lines(&missing).is_err());
    let doubled = format!("{all}{all}");
    assert!(check_lines(&doubled).is_err());
    assert!(check_lines(&all.replace("pending", "released")).is_err());
    assert!(check_lines("garbage").is_err());
}

/// I-05: every scenario of `conformance.mjs` holds with the official TypeScript SDK client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI: M9 conformance step (needs npm ci)"]
async fn i05_ts_sdk_conformance() -> Result<()> {
    if !opted_in("i05_ts_sdk_conformance") {
        return Ok(());
    }
    if std::env::var(OPT_IN_CONFORMANCE).as_deref() != Ok("1") {
        return Err(format!(
            "{OPT_IN_CONFORMANCE}=1 is not set: the conformance step must set it, a run without it \
             would prove nothing"
        )
        .into());
    }
    let dir = project_dir();
    if !dir.join("node_modules").is_dir() {
        return Err(format!(
            "{} has no node_modules: run `npm ci` in ci/mcp-conformance first",
            dir.display()
        )
        .into());
    }

    let mut world = World::new(WorldOpts::default())?;
    world
        .provision_store(&[("jira-main", Product::Jira)])
        .await?;
    let mock = world.mock("jira-main").ok_or("no mock for jira-main")?;
    mount_write(mock).await;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.json(
        "/rest/api/2/issue/ABC-BIG",
        200,
        &big_issue(BIG_DESCRIPTION_BYTES)?,
    )
    .await;
    let _app = world.start_app().await?;

    // The environment of the `atlas-duck mcp` child, as a JSON object for the SDK's `env` option.
    let mut mcp_env: BTreeMap<String, String> = world
        .env()
        .into_iter()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect();
    mcp_env.insert("ATLAS_DUCK_MCP_TIMEOUT".into(), MCP_TIMEOUT.into());

    let mut cmd = tokio::process::Command::new("node");
    cmd.arg("conformance.mjs")
        .current_dir(&dir)
        .env_clear()
        .envs(world.env())
        .env("ATLAS_DUCK_BIN", CLI_EXE)
        .env(
            "ATLAS_DUCK_CONFORMANCE_ENV",
            serde_json::to_string(&mcp_env)?,
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let child = cmd.spawn()?;
    let out = tokio::time::timeout(RUN_LIMIT, child.wait_with_output())
        .await
        .map_err(|_| format!("conformance.mjs did not end within {RUN_LIMIT:?}"))??;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "conformance.mjs failed ({}):\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
        out.status
    );
    if let Err(why) = check_lines(&stdout) {
        return Err(format!("{why}\n--- stdout\n{stdout}\n--- stderr\n{stderr}").into());
    }
    world.quit_app().await?;
    Ok(())
}
