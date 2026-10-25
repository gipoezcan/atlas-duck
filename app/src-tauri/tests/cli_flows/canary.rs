//! M10 T29 (§13 canary sweep, S-16 process half, S-14; §1.4 SC1/SC4, §10.2, §8.10): the real
//! `atlas-duck` and `atlas-duck-app` against three canary Jira mocks (the harness's canary mode:
//! every response field, header, error body and version string a canary, one canary PAT per
//! instance, the run's canary recovery passphrase), decisions by the scripted approver.
//!
//! Paths (Jira; the Confluence fixtures are D2): release, release-redacted, deny,
//! deny-with-details, deny-with-hint, expire, cancel, upstream-error, `upstream_unavailable` and
//! outcome-unknown on `jira-a`; stale on `jira-b` (the stale check's identity call and its re-check
//! answer without `X-AUSERNAME`); recheck-failed on `jira-c` (the re-check's `/myself` answers
//! 503).
//!
//! Captured: every CLI stdout, stderr and exit code (the paths, `status` of each request,
//! `requests list`, `ops list`, `ops describe --instance`, `doctor`, `instances`), the diagnostic
//! logs (S-14), the app's stderr (the test build's file under the test home, `startup::crash`),
//! every file under `<data>/webview` (incl. `Crashpad`), the decrypted audit payloads (read from
//! the store after the app quit, as `ci_fixture_verify` reads), a backup bundle (snapshot,
//! recovery blob, manifest), the recovery note and an export directory (both made from the quit
//! store in this process: neither has a CLI command). IPC frames are not captured: no frame tap
//! exists, and every frame's content reaches the CLI's stdout/stderr or the audit payloads. The
//! scripted approver decides in-process, so this half has no Tauri channel (`canary_tauri.rs`).
//!
//! Rules: a PAT canary (raw, base64, percent-encoded) is in no captured byte and reached each mock
//! only in `Authorization`; the passphrase canary is nowhere (the note included); the diagnostic
//! logs, the app's stderr, the webview files and the note carry no data canary; a data canary on
//! a CLI stream is one the agent-visible bytes hold: a `READ_RELEASED` payload's released bytes
//! or one of the [`ALLOWLIST`] sources (the §10.2 table); the field the redaction dropped is on no
//! CLI stream.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use atlas_duck_app_lib::credential::{NoteFacts, note_text};
use atlas_duck_app_lib::diag::LOG_DIR_NAME;
use atlas_duck_app_lib::startup::crash::WEBVIEW_DIR_NAME;
use atlas_duck_app_lib::testing::provision;
use atlas_duck_atlassian::testing::{MockDc, XAuser};
use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::types::RustChosenPath;
use atlas_duck_audit::{EventType, ExportControl, KeyStore, OpenConfig, SystemClock, TimeRange};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};
use atlas_duck_registry::Product;
use serde_json::{Value, json};

use crate::flows::{decided, run, submit_pending, wait_status};
use crate::harness::{
    CANARY_ERR_404, CANARY_ERR_500, CANARY_OUTCOME_UNKNOWN, CANARY_UNAVAILABLE, Canaries, CliRun,
    Result, World, WorldOpts, canary_issue, hits, opted_in, secret_forms,
};

const INSTANCES: [&str; 3] = ["jira-a", "jira-b", "jira-c"];
/// Every wait of the sweep is bounded by this.
const WAIT: Duration = Duration::from_secs(60);
const MYSELF: &str = "/rest/api/2/myself";

/// The §10.2 allowlist (shared with the spec): the audit sources whose bytes may reach the agent
/// besides a `READ_RELEASED` payload's released bytes. The key is `<event type>.<payload key>`.
const ALLOWLIST: [(&str, &str); 3] = [
    (
        "WRITE_DENIED.hint",
        "§10.2 Deny hints: enrichment-error details reach the agent only when the user attaches \
         them to a deny",
    ),
    (
        "WRITE_EXECUTED.result",
        "§10.2 Write receipts: the op's result_projection is released by approving the write",
    ),
    (
        "WRITE_FAILED.response",
        "§10.2 Write error text: the errorMessages/errors of a failed approved write",
    ),
];

/// One captured channel: a name and its bytes.
struct Captured {
    name: String,
    bytes: Vec<u8>,
    /// A CLI stream (the agent's channel); everything else carries no data canary at all.
    agent: bool,
}

fn capture_run(out: &mut Vec<Captured>, label: &str, r: &CliRun) {
    out.push(Captured {
        name: format!("{label} stdout (exit {})", r.exit),
        bytes: r.stdout.clone().into_bytes(),
        agent: true,
    });
    out.push(Captured {
        name: format!("{label} stderr"),
        bytes: r.stderr.clone().into_bytes(),
        agent: true,
    });
}

/// Every regular file below `dir` (none when it does not exist).
fn files_below(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(p),
                Ok(t) if t.is_file() => out.push(p),
                _ => {}
            }
        }
    }
    out.sort();
    out
}

fn capture_files(out: &mut Vec<Captured>, what: &str, files: &[PathBuf]) -> Result<()> {
    for f in files {
        out.push(Captured {
            name: format!("{what} {}", f.display()),
            bytes: fs::read(f)?,
            agent: false,
        });
    }
    Ok(())
}

/// Waits until the mock received at least `n` `GET /myself` since its reset.
async fn myself_calls(mock: &MockDc, n: usize) -> Result<()> {
    let start = Instant::now();
    loop {
        let got = mock
            .received()
            .await
            .iter()
            .filter(|r| r.url.path().ends_with(MYSELF))
            .count();
        if got >= n {
            return Ok(());
        }
        if start.elapsed() > WAIT {
            return Err(format!("{got} of {n} /myself calls within {WAIT:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The agent-visible bytes of the log: each `READ_RELEASED` payload's `released`, and the
/// [`ALLOWLIST`] sources.
fn agent_visible(records: &[(EventType, Value)]) -> Vec<String> {
    let mut out = Vec::new();
    for (t, p) in records {
        if *t == EventType::READ_RELEASED
            && let Some(r) = p.get("released")
        {
            out.push(r.to_string());
        }
        for (source, _) in ALLOWLIST {
            let Some((event, key)) = source.split_once('.') else {
                continue;
            };
            if t.as_str() == event
                && let Some(v) = p.get(key)
            {
                out.push(v.to_string());
            }
        }
    }
    out
}

/// Splits a CLI stream into the bytes an envelope gates (each envelope line's `data` and
/// `error.details`) and the rest (every other line, and each envelope with those two nulled).
fn split_envelopes(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (mut gated, mut rest) = (Vec::new(), Vec::new());
    for line in String::from_utf8_lossy(bytes).lines() {
        let parsed: Option<Value> = serde_json::from_str(line.trim()).ok();
        match parsed {
            Some(mut env) if env.get("status").is_some() => {
                if let Some(d) = env.get_mut("data") {
                    gated.extend_from_slice(d.to_string().as_bytes());
                    *d = Value::Null;
                }
                if let Some(d) = env.get_mut("error").and_then(|e| e.get_mut("details")) {
                    gated.extend_from_slice(d.to_string().as_bytes());
                    *d = Value::Null;
                }
                rest.extend_from_slice(env.to_string().as_bytes());
            }
            _ => rest.extend_from_slice(line.as_bytes()),
        }
        gated.push(b'\n');
        rest.push(b'\n');
    }
    (gated, rest)
}

/// Backup and export of the quit store (the app is gone), into `<root>/canary-out`.
fn backup_and_export(world: &World) -> Result<PathBuf> {
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
    let out = world.root().join("canary-out");
    fs::create_dir_all(&out)?;
    let made = (|| -> Result<()> {
        store
            .backup(RustChosenPath::from_native_dialog(out.clone()))
            .map_err(|e| format!("backup: {e:?}"))?;
        let cancel = AtomicBool::new(false);
        let progress = |_: u64, _: u64| {};
        store
            .export(
                TimeRange::all(),
                RustChosenPath::from_native_dialog(out.clone()),
                &ExportControl {
                    progress: &progress,
                    cancel: &cancel,
                },
            )
            .map_err(|e| format!("export: {e:?}"))?;
        let (install_id, chain_id) = (store.install_id().to_owned(), store.head().2);
        let note = note_text(&NoteFacts {
            host: world.host().to_owned(),
            os_user: atlas_duck_app_lib::credential::os_user(),
            install_id,
            chain_id,
            data_dir: world.data_dir().display().to_string(),
        });
        fs::write(out.join("recovery-note.txt"), note)?;
        Ok(())
    })();
    store.shutdown();
    drop(lock);
    made?;
    Ok(out)
}

/// S-16 process half, S-14 (see the module docs). CI only (spawns the binaries).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s16_canary_sweep_process_channels() -> Result<()> {
    if !opted_in("s16_canary_sweep_process_channels") {
        return Ok(());
    }
    let canaries = Canaries::new()?;
    let mut world = World::new(WorldOpts::default().with_canaries(canaries.clone()))?;
    world
        .provision_store(&[
            ("jira-a", Product::Jira),
            ("jira-b", Product::Jira),
            ("jira-c", Product::Jira),
        ])
        .await?;
    // Started by the harness, so the test build writes its stderr to the file.
    let mut app = world.start_app().await?;
    let mut cap: Vec<Captured> = Vec::new();
    let mut ids: Vec<(String, String)> = Vec::new();
    let issue = |key: &str, directive: &str| -> Vec<String> {
        [
            "--instance",
            "jira-a",
            "jira",
            "issue",
            "get",
            key,
            "--reason",
            directive,
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    };
    let call = |alias: &str, op: &str, params: Value, directive: &str| -> Vec<String> {
        vec![
            "--instance".into(),
            alias.into(),
            "call".into(),
            op.into(),
            "--params".into(),
            params.to_string(),
            "--reason".into(),
            directive.into(),
        ]
    };
    let comment = |key: &str| json!({"key": key, "body": "Seen.", "body_format": "wiki"});

    // The paths that end by themselves: run each to its terminal envelope.
    let terminal: Vec<(&str, Vec<String>, Status)> = vec![
        (
            "release",
            issue("CAN-1", "atlas-test:release"),
            Status::Released,
        ),
        (
            "release-redacted",
            issue("CAN-2", "atlas-test:release-redacted fields.description"),
            Status::Released,
        ),
        ("deny", issue("CAN-3", "atlas-test:deny"), Status::Denied),
        (
            "deny-with-details",
            call(
                "jira-a",
                "jira.issue.transition",
                json!({"key": CANARY_ERR_404[0], "transition": "Done"}),
                "atlas-test:deny-details",
            ),
            Status::Denied,
        ),
        (
            "deny-with-hint",
            call(
                "jira-a",
                "jira.issue.transition",
                json!({"key": CANARY_ERR_404[1], "transition": "Done"}),
                "atlas-test:deny-hint",
            ),
            Status::Denied,
        ),
        (
            "expire",
            issue("CAN-4", "atlas-test:expire"),
            Status::Expired,
        ),
        (
            "upstream-error",
            issue(CANARY_ERR_500, "atlas-test:release"),
            Status::Failed,
        ),
        (
            "upstream_unavailable",
            issue(CANARY_UNAVAILABLE, "atlas-test:hold"),
            Status::Failed,
        ),
        (
            "outcome-unknown",
            call(
                "jira-a",
                "jira.comment.add",
                comment(CANARY_OUTCOME_UNKNOWN),
                "atlas-test:approve",
            ),
            Status::OutcomeUnknown,
        ),
    ];
    for (label, args, want) in &terminal {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = run(&world, &args).await?;
        let env = r.envelope.as_ref().ok_or("no envelope")?;
        assert_eq!(
            env.status,
            *want,
            "{label}: {}\n{}",
            r.stdout,
            world.diagnostics()
        );
        if let Some(id) = &env.request_id {
            ids.push(((*label).to_owned(), id.clone()));
        }
        capture_run(&mut cap, label, &r);
    }

    // cancel
    let args = issue("CAN-5", "atlas-test:hold");
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let cancelled = submit_pending(&world, &args).await?;
    let r = run(&world, &["cancel", &cancelled]).await?;
    capture_run(&mut cap, "cancel", &r);
    let env = wait_status(&world, &cancelled, decided).await?;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    ids.push(("cancel".into(), cancelled));

    // stale (jira-b) and recheck-failed (jira-c): the mocks are reset before the submit, so the
    // approver's approve meets the stale check's identity call as set up here.
    let stale_args = [
        ("stale", "jira-b", XAuser::Missing),
        ("recheck-failed", "jira-c", XAuser::Missing),
    ];
    for (label, alias, header) in stale_args {
        let mock = world.mock(alias).ok_or("no mock")?;
        mock.server().reset().await;
        mock.json(
            "/rest/api/2/issue/STL-1",
            200,
            &canary_issue(&canaries, "STL-1"),
        )
        .await;
        let (name, key) = (
            mock.user().to_owned(),
            crate::harness::canary_user_key(mock.user()),
        );
        if label == "stale" {
            mock.jira_myself(&name, &key, header).await;
        } else {
            mock.jira_myself_once(&name, &key, header).await;
            mock.html(MYSELF, 503).await;
        }
        let args = call(
            alias,
            "jira.comment.add",
            comment("STL-1"),
            "atlas-test:approve",
        );
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let id = submit_pending(&world, &args).await?;
        // The stale check's identity call and the re-check's.
        myself_calls(mock, 2).await?;
        let r = run(&world, &["status", &id]).await?;
        capture_run(&mut cap, &format!("{label} status"), &r);
        let r = run(&world, &["cancel", &id]).await?;
        capture_run(&mut cap, &format!("{label} cancel"), &r);
        ids.push((label.to_owned(), id));
    }

    // The read-only commands.
    for (label, id) in &ids {
        let r = run(&world, &["status", id]).await?;
        capture_run(&mut cap, &format!("{label} status"), &r);
    }
    for args in [
        &["requests", "list"][..],
        &["ops", "list"][..],
        &["--instance", "jira-a", "ops", "list"][..],
        &["--instance", "jira-a", "ops", "describe", "jira.issue.get"][..],
        &["doctor"][..],
        &["instances"][..],
    ] {
        let r = world.cli(args).await?;
        capture_run(&mut cap, &args.join(" "), &r);
    }

    app.quit()?;
    world.wait_app_gone().await?;

    // What the app left behind.
    let stderr_file = world.stderr_file();
    assert!(
        stderr_file.is_file(),
        "the test build wrote no stderr file: {}",
        world.diagnostics()
    );
    capture_files(&mut cap, "app stderr", &[stderr_file])?;
    capture_files(
        &mut cap,
        "diagnostic log",
        &files_below(&world.data_dir().join(LOG_DIR_NAME)),
    )?;
    capture_files(
        &mut cap,
        "webview",
        &files_below(&world.data_dir().join(WEBVIEW_DIR_NAME)),
    )?;
    let records = world.audit_records()?;
    let out = backup_and_export(&world)?;
    let outputs = files_below(&out);
    assert!(
        outputs.iter().any(|p| p.ends_with("recovery.bin")),
        "no backup: {outputs:?}"
    );
    assert!(
        outputs.iter().any(|p| p.ends_with("events.jsonl")),
        "no export: {outputs:?}"
    );

    // ---- the sweep ----
    let mut problems: Vec<String> = Vec::new();
    let mut secrets: Vec<(String, Vec<String>)> = INSTANCES
        .iter()
        .map(|a| (format!("PAT {a}"), secret_forms(&world.pat(a))))
        .collect();
    secrets.push(("passphrase".into(), secret_forms(&world.passphrase())));
    let data: Vec<String> = canaries.data_all().into_iter().map(|(_, c)| c).collect();
    let visible = agent_visible(&records);
    let dropped: Vec<String> = canaries
        .data_all()
        .into_iter()
        .filter(|(label, c)| {
            label == "issue.description"
                && records.iter().any(|(t, p)| {
                    let text = p.to_string();
                    *t == EventType::READ_FETCHED
                        && text.contains("CAN-2")
                        && text.contains(c.as_str())
                })
                && !visible.iter().any(|v| v.contains(c.as_str()))
        })
        .map(|(_, c)| c)
        .collect();

    // The PATs reached each mock only in `Authorization`.
    for alias in INSTANCES {
        let pat = world.pat(alias);
        let forms = secret_forms(&pat);
        let mut sent = 0;
        for r in world.mock(alias).ok_or("no mock")?.received().await {
            let auth = r
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            if auth.contains(&pat) {
                sent += 1;
            }
            let mut rest = r.url.to_string().into_bytes();
            rest.extend_from_slice(&r.body);
            for (name, value) in r.headers.iter() {
                if name.as_str() != "authorization" {
                    rest.extend_from_slice(value.as_bytes());
                }
            }
            if !hits(&rest, &forms).is_empty() {
                problems.push(format!("{alias}: the PAT outside Authorization"));
            }
        }
        // jira-b and jira-c were reset: their earlier requests are gone, the approve's are left.
        if sent == 0 {
            problems.push(format!("{alias}: no request carried the PAT"));
        }
    }

    // Every captured channel.
    let audit_texts: Vec<(String, Vec<u8>)> = records
        .iter()
        .map(|(t, p)| (format!("audit payload {t:?}"), p.to_string().into_bytes()))
        .collect();
    let mut file_texts: Vec<(String, Vec<u8>)> = Vec::new();
    for f in &outputs {
        file_texts.push((format!("backup/export/note {}", f.display()), fs::read(f)?));
    }
    for (name, bytes) in cap
        .iter()
        .map(|c| (c.name.clone(), c.bytes.clone()))
        .chain(audit_texts)
        .chain(file_texts.iter().cloned())
    {
        for (kind, forms) in &secrets {
            let found = hits(&bytes, forms);
            if !found.is_empty() {
                problems.push(format!("{name} carries the {kind} canary {found:?}"));
            }
        }
    }
    for c in &cap {
        if !c.agent {
            for canary in hits(&c.bytes, &data) {
                problems.push(format!("{} carries the data canary {canary}", c.name));
            }
            continue;
        }
        // The agent's channel: a data canary sits only in an envelope's `data` or
        // `error.details` (X-05, 7494d2a), and only one the agent-visible bytes hold.
        let (gated, rest) = split_envelopes(&c.bytes);
        for canary in hits(&gated, &data) {
            if dropped.iter().any(|d| d == canary) {
                problems.push(format!("{} carries the dropped field {canary}", c.name));
            } else if !visible.iter().any(|v| v.contains(canary)) {
                problems.push(format!(
                    "{} carries the data canary {canary}, which no agent-visible bytes hold: {}",
                    c.name,
                    String::from_utf8_lossy(&c.bytes)
                ));
            }
        }
        for canary in hits(&rest, &data) {
            problems.push(format!(
                "{} carries the data canary {canary} outside `data` and `error.details`: {}",
                c.name,
                String::from_utf8_lossy(&rest)
            ));
        }
    }
    for (name, bytes) in &file_texts {
        if name.ends_with("recovery-note.txt") && !hits(bytes, &data).is_empty() {
            problems.push(format!("{name} carries a data canary"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));

    // Not vacuous: released canaries reached the agent, the paths reached their records.
    assert!(
        cap.iter()
            .any(|c| c.agent && !hits(&c.bytes, &data).is_empty()),
        "no CLI stream carries a released canary: the sweep would be blind"
    );
    assert!(!dropped.is_empty(), "the redaction dropped nothing");
    let payload_of = |t: EventType| -> Vec<String> {
        records
            .iter()
            .filter(|(e, _)| *e == t)
            .map(|(_, p)| p.to_string())
            .collect()
    };
    let stale = payload_of(EventType::WRITE_STALE);
    for reason in ["identity_header_missing", "recheck_failed"] {
        assert!(
            stale.iter().any(|p| p.contains(reason)),
            "{reason}: {stale:?}"
        );
    }
    let denied = payload_of(EventType::WRITE_DENIED);
    assert!(
        denied.iter().any(|p| p.contains("hint")),
        "no deny hint: {denied:?}"
    );
    Ok(())
}
