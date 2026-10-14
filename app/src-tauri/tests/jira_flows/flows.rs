//! `jira_flows` (M5 Task 23): eight flows of the real binaries on the new Jira paths, each against
//! a store provisioned in the wizard's order and the mock Jira `jira-main`. Requests are decided
//! by the scripted approver through the `atlas-test:<directive>` reason (PD-03); the wire is read
//! back from the mock (`MockDc::received`).
//!
//! Every flow spawns a binary and therefore starts with [`opted_in`]: it skips unless
//! `ATLAS_DUCK_CLI_FLOWS=1` (CI).
//!
//! Mounts: a `MockDc` answers the first mount that matches, so a flow never mounts a path the
//! fixture set of the provisioning already answers (`/issue/ABC-1`, `/search`, `/myself`,
//! `/serverInfo`) with something else. Every answer of the mock carries `X-AUSERNAME` (the §7.2
//! per-response identity check), the empty `201` and the `204`s included.

use atlas_duck_atlassian::testing::{MockDc, fixtures};
use atlas_duck_audit::EventType;
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::proto::exit_code;
use atlas_duck_registry::Product;
use serde_json::{Value, json};

use crate::harness::{CliRun, PAT_CANARY, Result, World, WorldOpts, opted_in};

/// The wire path of the create (`POST`), the project list, the issue types and the `Bug` fields.
const CREATE_PATH: &str = "/rest/api/2/issue";
const PROJECTS_PATH: &str = "/rest/api/2/project";
const ISSUETYPES_PATH: &str = "/rest/api/2/issue/createmeta/ABC/issuetypes";
const BUG_FIELDS_PATH: &str = "/rest/api/2/issue/createmeta/ABC/issuetypes/10002";
/// The field list of the app's start fill of the field-name cache (PD-46).
const FIELDS: &str = r#"[{"id":"summary","name":"Summary","custom":false,"schema":{"type":"string","system":"summary"}},{"id":"customfield_10200","name":"Team","custom":true,"schema":{"type":"option","custom":"com.atlassian.jira.plugin.system.customfieldtypes:select","customId":10200}}]"#;

// ---- helpers -----------------------------------------------------------------------------------

/// A test home with one Jira instance `jira-main` whose mock already answers the field list
/// (the first CLI call cold-starts the app, which fetches it).
async fn jira_world() -> Result<World> {
    let mut world = World::new(WorldOpts::default())?;
    world
        .provision_store(&[("jira-main", Product::Jira)])
        .await?;
    jira(&world)?.json("/rest/api/2/field", 200, FIELDS).await;
    Ok(world)
}

fn jira(world: &World) -> Result<&MockDc> {
    world
        .mock("jira-main")
        .ok_or_else(|| "no mock for jira-main".into())
}

/// One `atlas-duck <args>` run. What holds for every run: when stdout holds an envelope, the exit
/// code is the one the §4.3 matrix gives it, and the PAT canary is on neither stream.
async fn run(world: &World, args: &[&str]) -> Result<CliRun> {
    let r = world.cli(args).await?;
    for (name, text) in [("stdout", &r.stdout), ("stderr", &r.stderr)] {
        if text.contains(PAT_CANARY) {
            return Err(format!("the PAT canary is on {name} of {args:?}").into());
        }
    }
    if let Some(env) = &r.envelope {
        let want = exit_code(env);
        if r.exit != want {
            return Err(format!(
                "{args:?}: exit {} but the matrix says {want}: {}",
                r.exit, r.stdout
            )
            .into());
        }
    }
    Ok(r)
}

fn envelope(r: &CliRun) -> Result<&Envelope> {
    r.envelope
        .as_ref()
        .ok_or_else(|| format!("no envelope on stdout: {:?} / {:?}", r.stdout, r.stderr).into())
}

/// `data` walked along `path`.
fn data_at<'a>(env: &'a Envelope, path: &[&str]) -> Option<&'a Value> {
    let mut v = env.data.as_ref()?;
    for key in path {
        v = v.get(*key)?;
    }
    Some(v)
}

/// `error.code` as its wire name.
fn error_code(env: &Envelope) -> Result<Value> {
    let err = env.error.as_ref().ok_or("no error in the envelope")?;
    Ok(serde_json::to_value(err.code)?)
}

/// The bodies of the requests `method` `path` the mock received.
async fn sent(mock: &MockDc, method: &str, path: &str) -> Result<Vec<Value>> {
    let want = mock.path(path);
    let mut out = Vec::new();
    for req in mock.received().await {
        if req.method.as_str() == method && req.url.path() == want {
            out.push(serde_json::from_slice(&req.body)?);
        }
    }
    Ok(out)
}

/// How many requests of `method` the mock received at all.
async fn count_of(mock: &MockDc, method: &str) -> usize {
    mock.received()
        .await
        .iter()
        .filter(|r| r.method.as_str() == method)
        .count()
}

/// Every audit record of the world, read after the app quit (the log needs the app gone).
async fn audit(world: &World) -> Result<Vec<(EventType, Value)>> {
    world.quit_app().await?;
    world.audit_records()
}

/// How many records of `kind` the log holds.
fn records_of(records: &[(EventType, Value)], kind: EventType) -> usize {
    records.iter().filter(|(t, _)| *t == kind).count()
}

/// The three enrichment answers of a `jira.issue.create` in `ABC` with issue type `Bug`; the
/// `Bug` createmeta marks the option field `customfield_10200` (`Team`) required (PD-49).
async fn mount_team_stages(mock: &MockDc) {
    let fields = json!({
        "maxResults": 50, "startAt": 0, "total": 3, "isLast": true,
        "values": [
            {"required": true, "schema": {"type": "string", "system": "summary"},
             "name": "Summary", "fieldId": "summary", "hasDefaultValue": false},
            {"required": true,
             "schema": {"type": "option",
                        "custom": "com.atlassian.jira.plugin.system.customfieldtypes:select",
                        "customId": 10200},
             "name": "Team", "fieldId": "customfield_10200", "hasDefaultValue": false,
             "operations": ["set"], "allowedValues": [{"id": "10400", "value": "Platform"}]},
            {"required": true, "schema": {"type": "user", "system": "reporter"},
             "name": "Reporter", "fieldId": "reporter", "hasDefaultValue": true}
        ]
    });
    mock.json(PROJECTS_PATH, 200, fixtures::JIRA_PROJECTS).await;
    mock.json(ISSUETYPES_PATH, 200, fixtures::JIRA_CREATEMETA_ISSUETYPES)
        .await;
    mock.json(BUG_FIELDS_PATH, 200, &fields.to_string()).await;
}

// ---- the flows ---------------------------------------------------------------------------------

/// The harness over the Jira ops: a read is released, `jira.issue.get` answers with the issue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_flows_smoke() -> Result<()> {
    if !opted_in("jira_flows_smoke") {
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
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Released, "{}", r.stdout);
    assert_eq!(data_at(env, &["result", "key"]), Some(&json!("ABC-1")));
    Ok(())
}

/// PD-42 / T7: a markdown comment goes out as wiki text, `{toc}` escaped, and with the
/// converter's trailing newline (the wire bytes are the bytes the approver checked). The
/// receipt is the comment's id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn md_comment_sent_as_wiki() -> Result<()> {
    if !opted_in("md_comment_sent_as_wiki") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mock = jira(&world)?;
    mock.json(
        "/rest/api/2/issue/ABC-1/comment",
        201,
        fixtures::JIRA_COMMENT,
    )
    .await;
    let r = run(
        &world,
        &[
            "jira",
            "comment",
            "add",
            "ABC-1",
            "--body",
            "**done** {toc}",
            "--reason",
            "atlas-test:approve",
        ],
    )
    .await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Succeeded, "{}", r.stdout);
    assert_eq!(data_at(env, &["receipt"]), Some(&json!({ "id": "20001" })));
    let posts = sent(mock, "POST", "/rest/api/2/issue/ABC-1/comment").await?;
    assert_eq!(posts.len(), 1, "{posts:?}");
    assert_eq!(posts[0]["body"], json!("*done* \\{toc\\}\n"));
    let records = audit(&world).await?;
    assert_eq!(records_of(&records, EventType::WRITE_APPROVED), 1);
    assert_eq!(records_of(&records, EventType::WRITE_EXECUTED), 1);
    Ok(())
}

/// I-18 (PD-49): the create's createmeta marks a required option field the agent did not send;
/// the approver fills it with its first allowed value and approves the edited revision. The
/// envelope says `edited`, the keys it added, and the field went out as the option's id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i18_create_missing_field_edit_and_approve() -> Result<()> {
    if !opted_in("i18_create_missing_field_edit_and_approve") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mock = jira(&world)?;
    mount_team_stages(mock).await;
    mock.json(CREATE_PATH, 201, fixtures::JIRA_ISSUE_CREATED)
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
            "s",
            "--reason",
            "atlas-test:edit-preadded",
        ],
    )
    .await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Succeeded, "{}", r.stdout);
    assert!(env.edited, "{}", r.stdout);
    assert_eq!(
        data_at(env, &["edited_keys", "added"]),
        Some(&json!(["fields.customfield_10200"])),
        "{}",
        r.stdout
    );
    let posts = sent(mock, "POST", CREATE_PATH).await?;
    assert_eq!(posts.len(), 1, "{posts:?}");
    assert_eq!(
        posts[0]["fields"]["customfield_10200"],
        json!({ "id": "10400" })
    );
    let records = audit(&world).await?;
    assert_eq!(records_of(&records, EventType::WRITE_EDITED), 1);
    assert_eq!(records_of(&records, EventType::WRITE_APPROVED), 1);
    Ok(())
}

/// I-36: an edit whose `--expected` baseline differs from what the issue holds (the mock's
/// summary is "Login page times out") is denied by the human: exit 3, `denied`, nothing written.
/// The control differs only in `--expected` (the summary the issue holds): the human approves it
/// and exactly one `PUT` goes out, answered with the declared empty `204`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i36_edit_conflict_denied_exit3() -> Result<()> {
    if !opted_in("i36_edit_conflict_denied_exit3") {
        return Ok(());
    }
    let world = jira_world().await?;
    // The declared success of the edit is an empty `204`; a method-specific mount wins over the
    // fixture's any-method `/issue/ABC-1` answer (which would be an `outcome_unknown`).
    jira(&world)?
        .empty_for("PUT", "/rest/api/2/issue/ABC-1", 204)
        .await;
    let edit = |expected: &'static str, reason: &'static str| {
        [
            "jira",
            "issue",
            "edit",
            "ABC-1",
            "--field",
            "summary=\"new\"",
            "--expected",
            expected,
            "--reason",
            reason,
        ]
    };
    let r = run(&world, &edit("{\"summary\":\"old\"}", "atlas-test:deny")).await?;
    assert_eq!(r.exit, 3, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Denied, "{}", r.stdout);
    assert_eq!(count_of(jira(&world)?, "PUT").await, 0);

    let r = run(
        &world,
        &edit(
            "{\"summary\":\"Login page times out\"}",
            "atlas-test:approve",
        ),
    )
    .await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    assert_eq!(envelope(&r)?.status, Status::Succeeded, "{}", r.stdout);
    let puts = sent(jira(&world)?, "PUT", "/rest/api/2/issue/ABC-1").await?;
    assert_eq!(puts.len(), 1, "{puts:?}");
    assert_eq!(puts[0]["fields"]["summary"], json!("new"));

    let records = audit(&world).await?;
    assert_eq!(records_of(&records, EventType::WRITE_DENIED), 1);
    assert_eq!(records_of(&records, EventType::WRITE_APPROVED), 1);
    Ok(())
}

/// PD-45: `jira.issue.get --comments` releases the issue with the comments merged under
/// `fields.comment.comments`, as many as the mock's page holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue_get_comments_released() -> Result<()> {
    if !opted_in("issue_get_comments_released") {
        return Ok(());
    }
    let world = jira_world().await?;
    let comment = |id: u64, body: &str| {
        json!({
            "self": format!("https://jira.corp.example/rest/api/2/issue/10001/comment/{id}"),
            "id": id.to_string(),
            "author": {"name": "jdoe", "key": "JIRAUSER1", "displayName": "Jane Doe"},
            "body": body,
            "created": "2026-10-06T10:00:00.000+0200",
            "updated": "2026-10-06T10:00:00.000+0200"
        })
    };
    let page = json!({
        "startAt": 0, "maxResults": 50, "total": 2,
        "comments": [comment(30_000, "first"), comment(30_001, "second")]
    });
    jira(&world)?
        .json("/rest/api/2/issue/ABC-1/comment", 200, &page.to_string())
        .await;
    let r = run(
        &world,
        &[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--comments",
            "--reason",
            "atlas-test:release",
        ],
    )
    .await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Released, "{}", r.stdout);
    let comments = data_at(env, &["result", "fields", "comment", "comments"])
        .and_then(Value::as_array)
        .ok_or_else(|| format!("no comments in {}", r.stdout))?;
    assert_eq!(comments.len(), 2, "{}", r.stdout);
    let ids: Vec<&str> = comments
        .iter()
        .filter_map(|c| c.get("id").and_then(Value::as_str))
        .collect();
    assert_eq!(ids, ["30000", "30001"], "{}", r.stdout);
    let mock = jira(&world)?;
    let endpoint = mock.path("/rest/api/2/issue/ABC-1/comment");
    let fetched = mock
        .received()
        .await
        .iter()
        .any(|req| req.method.as_str() == "GET" && req.url.path() == endpoint);
    assert!(fetched, "the comment endpoint was not fetched");
    Ok(())
}

/// PD-53: `issueLink` answers `201` with an empty `text/html` body; the write succeeded with an
/// empty receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issuelink_201_empty_succeeded() -> Result<()> {
    if !opted_in("issuelink_201_empty_succeeded") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mock = jira(&world)?;
    let types = json!({ "issueLinkTypes": [{
        "id": "10000", "name": "Blocks", "inward": "is blocked by", "outward": "blocks"
    }] });
    mock.json("/rest/api/2/issueLinkType", 200, &types.to_string())
        .await;
    mock.empty("/rest/api/2/issueLink", 201, Some("text/html"))
        .await;
    let r = run(
        &world,
        &[
            "jira",
            "issuelink",
            "create",
            "--type",
            "Blocks",
            "--inward",
            "ABC-2",
            "--outward",
            "ABC-1",
            "--reason",
            "atlas-test:approve",
        ],
    )
    .await?;
    assert_eq!(r.exit, 0, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Succeeded, "{}", r.stdout);
    assert_eq!(data_at(env, &["receipt"]), Some(&json!({})), "{}", r.stdout);
    let posts = sent(mock, "POST", "/rest/api/2/issueLink").await?;
    assert_eq!(posts.len(), 1, "{posts:?}");
    assert_eq!(posts[0]["type"]["name"], json!("Blocks"));
    assert_eq!(posts[0]["inwardIssue"]["key"], json!("ABC-2"));
    assert_eq!(posts[0]["outwardIssue"]["key"], json!("ABC-1"));
    let records = audit(&world).await?;
    assert_eq!(records_of(&records, EventType::WRITE_APPROVED), 1);
    assert_eq!(records_of(&records, EventType::WRITE_EXECUTED), 1);
    Ok(())
}

/// §5.4 step 2 / I-35: a transition name the issue has no match for holds the write; the human
/// denies with the resolution hint without the candidate list: exit 3, `denied` with the code
/// `resolution_failed`, and the details name the param but carry no `candidates`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unresolved_transition_deny_hint_exit3() -> Result<()> {
    if !opted_in("unresolved_transition_deny_hint_exit3") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mock = jira(&world)?;
    mock.json(
        "/rest/api/2/issue/ABC-1/transitions",
        200,
        fixtures::JIRA_TRANSITIONS,
    )
    .await;
    let r = run(
        &world,
        &[
            "jira",
            "issue",
            "transition",
            "ABC-1",
            "--transition",
            "Doen",
            "--reason",
            "atlas-test:deny-hint",
        ],
    )
    .await?;
    assert_eq!(r.exit, 3, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(env.status, Status::Denied, "{}", r.stdout);
    assert_eq!(error_code(env)?, json!("resolution_failed"), "{}", r.stdout);
    let details = env
        .error
        .as_ref()
        .and_then(|e| e.details.as_ref())
        .ok_or_else(|| format!("no details in {}", r.stdout))?;
    assert_eq!(details.get("param"), Some(&json!("transition")));
    assert!(!details.contains_key("candidates"), "{}", r.stdout);
    assert_eq!(count_of(mock, "POST").await, 0);
    let records = audit(&world).await?;
    let denied: Vec<&Value> = records
        .iter()
        .filter(|(t, _)| *t == EventType::WRITE_DENIED)
        .map(|(_, p)| p)
        .collect();
    assert_eq!(denied.len(), 1, "{records:?}");
    assert_eq!(denied[0]["hint"]["code"], json!("resolution_failed"));
    assert_eq!(records_of(&records, EventType::WRITE_APPROVED), 0);
    Ok(())
}

/// U-02 (§7.3): 51 issues in one sprint move are refused at validation, exit 2, after the
/// request is received and before anything is queued: it is rejected, nothing is pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u02_move_51_issues_usage_exit2() -> Result<()> {
    if !opted_in("u02_move_51_issues_usage_exit2") {
        return Ok(());
    }
    let world = jira_world().await?;
    let keys: Vec<String> = (1..=51).map(|n| format!("ABC-{n}")).collect();
    let r = run(
        &world,
        &[
            "jira",
            "sprint",
            "move-issues",
            "7",
            "--issues",
            &keys.join(","),
        ],
    )
    .await?;
    assert_eq!(r.exit, 2, "{}", r.stdout);
    let env = envelope(&r)?;
    assert_eq!(error_code(env)?, json!("validation"), "{}", r.stdout);
    assert!(env.request_id.is_some(), "{}", r.stdout);

    let list = run(&world, &["requests", "list", "--state", "pending"]).await?;
    assert_eq!(list.exit, 0, "{}", list.stdout);
    let rows = data_at(envelope(&list)?, &["requests"])
        .and_then(Value::as_array)
        .ok_or_else(|| format!("no request list in {}", list.stdout))?;
    assert!(rows.is_empty(), "{}", list.stdout);
    assert_eq!(count_of(jira(&world)?, "POST").await, 0);
    let records = audit(&world).await?;
    assert_eq!(records_of(&records, EventType::REQUEST_RECEIVED), 1);
    assert_eq!(records_of(&records, EventType::REQUEST_REJECTED), 1);
    assert_eq!(records_of(&records, EventType::PREVIEW_SHOWN), 0);
    assert_eq!(records_of(&records, EventType::WRITE_APPROVED), 0);
    Ok(())
}
