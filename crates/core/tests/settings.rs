#![cfg(feature = "testing")]
//! M6 Task 8: `SettingsAdmin` (Δ3), the `[limits] jira_comments_cap` and `[ui] attention_mode`
//! keys (Δ6), the live comments cap (PD-63, PD-76), "Prune backlog now" (L37) and "Verify now"
//! (PD-82, M2 handoff).

mod common;

use std::sync::Arc;

use atlas_duck_audit::EventType;
use atlas_duck_core::config::limits::limits_config;
use atlas_duck_core::config::load_config;
use atlas_duck_core::config::requests::expiry_hours;
use atlas_duck_core::config::ui::attention_mode_config;
use atlas_duck_core::engine::queue::MIB;
use atlas_duck_core::settings::{LIFT_HOLD_TEXT, PRUNE_BACKLOG_TEXT};
use atlas_duck_core::testing::Harness;
use atlas_duck_core::{
    AttentionMode, Confirm, SettingChangeReq, SettingsAdmin, SettingsError, SettingsView,
    ShutdownReason, VerifyNow,
};
use atlas_duck_ipc::envelope::Status;
use common::jira::{comment_page, comments_path, gets_on, mount_comments, mount_issue, query};
use common::{TestError, TestResult, request_id};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use SettingChangeReq::{
    AttentionMode as Mode, CandidateCacheMb, ExpiryHours, JiraCommentsCap, LegalHold,
    MaxPendingBytesMb, RetentionDays,
};

/// `apply` off the async workers, as the app calls it (PD-13).
async fn apply(
    s: &Arc<dyn SettingsAdmin>,
    changes: Vec<SettingChangeReq>,
) -> Result<Result<SettingsView, SettingsError>, TestError> {
    let s = s.clone();
    Ok(tokio::task::spawn_blocking(move || s.apply(changes)).await?)
}

async fn view(s: &Arc<dyn SettingsAdmin>) -> Result<SettingsView, TestError> {
    let s = s.clone();
    Ok(tokio::task::spawn_blocking(move || s.view()).await?)
}

/// The `CONFIG_CHANGED` payloads with `key`.
async fn config_changed(h: &Harness, key: &str) -> Result<Vec<Value>, TestError> {
    Ok(h.events_of(EventType::CONFIG_CHANGED)
        .await?
        .into_iter()
        .filter(|p| p["key"] == key)
        .collect())
}

fn sha_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn raise(name: &str, old: &str, new: &str) -> String {
    format!(
        "Raise {name} from {old} to {new}? Higher limits let agents fetch more data before you \
         review it."
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x02_lift_hold_and_lower_retention_need_confirmation() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    // Setting the hold is not security-weakening: no dialog.
    apply(&s, vec![LegalHold(true)]).await??;
    assert!(h.confirmer().texts().is_empty());
    let holds = h.events_of(EventType::LEGAL_HOLD_CHANGED).await?;
    assert_eq!(holds.len(), 1);
    assert_eq!(holds[0]["source"], "app");
    assert_eq!(holds[0]["confirmed"], Value::Null);

    // Cancel: nothing logged, both values unchanged (the second dialog is never shown).
    let lower = "Lower audit retention from 100 to 92 days? Records older than 92 days will be \
                 pruned.";
    h.confirmer().push(Confirm::Cancel);
    let r = apply(&s, vec![LegalHold(false), RetentionDays(92)]).await?;
    assert_eq!(r.err(), Some(SettingsError::Cancelled));
    assert_eq!(h.confirmer().texts(), [LIFT_HOLD_TEXT]);
    assert_eq!(h.events_of(EventType::LEGAL_HOLD_CHANGED).await?.len(), 1);
    assert!(config_changed(&h, "retention_days").await?.is_empty());
    let v = view(&s).await?;
    assert!(v.legal_hold);
    assert_eq!(v.retention_days, 100);

    // Ok, Ok: both apply, each record carries its own dialog's hash.
    h.confirmer().push(Confirm::Ok);
    h.confirmer().push(Confirm::Ok);
    let v = apply(&s, vec![LegalHold(false), RetentionDays(92)]).await??;
    assert!(!v.legal_hold);
    assert_eq!(v.retention_days, 92);
    assert_eq!(
        h.confirmer().texts(),
        [LIFT_HOLD_TEXT, LIFT_HOLD_TEXT, lower]
    );
    let holds = h.events_of(EventType::LEGAL_HOLD_CHANGED).await?;
    let lifted = holds.last().ok_or("no LEGAL_HOLD_CHANGED")?;
    assert_eq!(lifted["source"], "app");
    assert_eq!(lifted["new"], false);
    assert_eq!(lifted["applied"], true);
    assert_eq!(
        lifted["confirmed"]["dialog_text_sha256"],
        sha_hex(LIFT_HOLD_TEXT)
    );
    let ret = config_changed(&h, "retention_days").await?;
    let [r] = ret.as_slice() else {
        return Err(format!("{} retention records", ret.len()).into());
    };
    assert_eq!(r["source"], "app");
    assert_eq!(
        (r["old"].clone(), r["new"].clone()),
        (json!(100), json!(92))
    );
    assert_eq!(r["confirmed"]["dialog_text_sha256"], sha_hex(lower));

    // Raising retention needs nothing.
    apply(&s, vec![RetentionDays(150)]).await??;
    assert_eq!(h.confirmer().texts().len(), 3);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raising_a_limit_needs_confirmation_lowering_does_not() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let file_cap = |h: &Harness| -> Result<Option<u32>, TestError> {
        Ok(limits_config(&load_config(&h.config_path())?)?.jira_comments_cap)
    };
    // Cancel: no record, the file and the cap in force unchanged.
    h.confirmer().push(Confirm::Cancel);
    let r = apply(&s, vec![JiraCommentsCap(200)]).await?;
    assert_eq!(r.err(), Some(SettingsError::Cancelled));
    let text = raise("the Jira comments cap", "100", "200");
    assert_eq!(h.confirmer().texts(), [text.as_str()]);
    assert!(config_changed(&h, "jira_comments_cap").await?.is_empty());
    assert_eq!(file_cap(&h)?, None);
    assert_eq!(view(&s).await?.limits.jira_comments_cap, 100);

    // Ok: recorded with the dialog hash, then written, then in force.
    h.confirmer().push(Confirm::Ok);
    let v = apply(&s, vec![JiraCommentsCap(200)]).await??;
    assert_eq!(v.limits.jira_comments_cap, 200);
    assert_eq!(file_cap(&h)?, Some(200));
    let recs = config_changed(&h, "jira_comments_cap").await?;
    let [r] = recs.as_slice() else {
        return Err(format!("{} records", recs.len()).into());
    };
    assert_eq!(r["source"], "app");
    assert_eq!(
        (r["old"].clone(), r["new"].clone()),
        (json!(100), json!(200))
    );
    assert_eq!(r["applied"], true);
    assert_eq!(r["confirmed"]["dialog_text_sha256"], sha_hex(&text));

    // Lowering: no dialog, a plain record.
    let shown = h.confirmer().texts().len();
    let v = apply(
        &s,
        vec![
            JiraCommentsCap(50),
            CandidateCacheMb(256),
            MaxPendingBytesMb(Some(64)),
            ExpiryHours(12),
        ],
    )
    .await??;
    assert_eq!(
        h.confirmer().texts().len(),
        shown,
        "no dialog for a lowering"
    );
    assert_eq!(v.limits.jira_comments_cap, 50);
    let recs = config_changed(&h, "jira_comments_cap").await?;
    assert_eq!(
        recs.last().map(|r| r["confirmed"].clone()),
        Some(Value::Null)
    );

    // Every other limit's raise needs its own dialog; removing the pending cap is a raise.
    for (change, text) in [
        (
            CandidateCacheMb(1024),
            raise("the candidate cache (MiB)", "256", "1024"),
        ),
        (
            MaxPendingBytesMb(None),
            raise("the pending-bytes cap (MiB)", "64", "no cap"),
        ),
        (
            ExpiryHours(48),
            raise("the request expiry (hours)", "12", "48"),
        ),
    ] {
        h.confirmer().push(Confirm::Cancel);
        let r = apply(&s, vec![change]).await?;
        assert_eq!(r.err(), Some(SettingsError::Cancelled));
        assert_eq!(h.confirmer().texts().last(), Some(&text));
    }
    // An unchanged value is no change: no dialog, no record.
    let (shown, recs) = (
        h.confirmer().texts().len(),
        h.events_of(EventType::CONFIG_CHANGED).await?.len(),
    );
    apply(&s, vec![JiraCommentsCap(50), ExpiryHours(12)]).await??;
    assert_eq!(h.confirmer().texts().len(), shown);
    assert_eq!(h.events_of(EventType::CONFIG_CHANGED).await?.len(), recs);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retention_below_92_refused() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let r = apply(&s, vec![RetentionDays(91)]).await?;
    assert_eq!(
        r.err(),
        Some(SettingsError::Invalid {
            key: "retention_days"
        })
    );
    // One out-of-bounds change refuses the whole call before anything happens.
    let r = apply(&s, vec![JiraCommentsCap(10), RetentionDays(0)]).await?;
    assert!(matches!(r, Err(SettingsError::Invalid { .. })));
    // A key named twice too.
    let r = apply(&s, vec![JiraCommentsCap(10), JiraCommentsCap(20)]).await?;
    assert!(matches!(r, Err(SettingsError::Invalid { .. })));
    assert!(h.confirmer().texts().is_empty());
    assert!(config_changed(&h, "retention_days").await?.is_empty());
    assert!(config_changed(&h, "jira_comments_cap").await?.is_empty());
    let v = view(&s).await?;
    assert_eq!((v.retention_days, v.limits.jira_comments_cap), (100, 100));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comments_cap_applies_live() -> TestResult {
    const KEY: &str = "ABC-7";
    let h = Harness::jira().await?;
    let s = h.core().settings();
    apply(&s, vec![JiraCommentsCap(10)]).await??;
    let mock = h.mock("jira-main").ok_or("no jira mock")?;
    mount_issue(
        mock,
        KEY,
        &json!({"id": "10007", "key": KEY, "fields": {"summary": "s"}}),
    )
    .await;
    mount_comments(mock, KEY, &[comment_page(0, 10, 250, 10, false)]).await;
    // The same core, no restart: the next read is validated with the new cap.
    let env = h
        .submit("jira.issue.get", json!({ "key": KEY, "comments": true }))
        .await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let gets = gets_on(mock, &comments_path(KEY)).await;
    let [only] = gets.as_slice() else {
        return Err(format!("{} comment GETs", gets.len()).into());
    };
    assert_eq!(query(only, "maxResults").as_deref(), Some("10"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_limits_apply_after_restart() -> TestResult {
    let mut h = Harness::jira().await?;
    let s = h.core().settings();
    assert!(view(&s).await?.restart_pending.is_empty());
    let v = apply(
        &s,
        vec![
            CandidateCacheMb(256),
            MaxPendingBytesMb(Some(64)),
            ExpiryHours(12),
        ],
    )
    .await??;
    assert_eq!(
        v.restart_pending,
        ["candidate_cache_mb", "max_pending_bytes_mb", "expiry_hours"]
    );
    assert_eq!(v.limits.candidate_cache_mb, 256);
    assert_eq!(v.limits.max_pending_bytes_mb, Some(64));
    assert_eq!(v.limits.expiry_hours, 12);
    // This run keeps what it started with.
    let running = *h.engine().limits();
    assert_eq!(running.candidate_cache_bytes, 512 * MIB);
    assert_eq!(running.max_pending_bytes, None);
    assert_eq!(h.engine().expiry().as_secs(), 24 * 3600);
    let cfg = load_config(&h.config_path())?;
    assert_eq!(expiry_hours(&cfg)?, Some(12));

    h.restart().await?;
    let running = *h.engine().limits();
    assert_eq!(running.candidate_cache_bytes, 256 * MIB);
    assert_eq!(running.max_pending_bytes, Some(64 * MIB));
    assert_eq!(h.engine().expiry().as_secs(), 12 * 3600);
    assert!(view(&h.core().settings()).await?.restart_pending.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attention_mode_change_is_plain_config_changed() -> TestResult {
    let mut h = Harness::jira().await?;
    let s = h.core().settings();
    assert_eq!(
        view(&s).await?.attention_mode,
        AttentionMode::ShowWithoutActivating
    );
    let v = apply(&s, vec![Mode(AttentionMode::ShowAndFocus)]).await??;
    assert!(
        h.confirmer().texts().is_empty(),
        "§10.3: not security-weakening"
    );
    assert_eq!(v.attention_mode, AttentionMode::ShowAndFocus);
    assert!(v.restart_pending.is_empty(), "applies at once");
    let recs = config_changed(&h, "attention_mode").await?;
    let [r] = recs.as_slice() else {
        return Err(format!("{} records", recs.len()).into());
    };
    assert_eq!(r["source"], "app");
    assert_eq!(r["old"], "show_without_activating");
    assert_eq!(r["new"], "show_and_focus");
    assert_eq!(r["applied"], true);
    assert_eq!(r["confirmed"], Value::Null);
    let cfg = load_config(&h.config_path())?;
    assert_eq!(
        attention_mode_config(&cfg)?,
        Some(AttentionMode::ShowAndFocus)
    );
    h.restart().await?;
    assert_eq!(
        view(&h.core().settings()).await?.attention_mode,
        AttentionMode::ShowAndFocus
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_only_config_refuses_file_changes_with_banner() -> TestResult {
    let h = Harness::builder()
        .config_text("schema_version = 2\nwritten_by = \"9.1.0\"\n[future]\nkey = 1\n")
        .start()
        .await?;
    let s = h.core().settings();
    let before = std::fs::read(h.config_path())?;
    let text = "config written by v9.1.0; settings read-only until you upgrade";
    let v = view(&s).await?;
    let banner = v.config_read_only.clone().ok_or("no banner")?;
    assert_eq!((banner.kind, banner.text.as_str()), ("read_only", text));
    for change in [
        JiraCommentsCap(50),
        CandidateCacheMb(256),
        ExpiryHours(12),
        Mode(AttentionMode::BadgeOnly),
    ] {
        match apply(&s, vec![change]).await? {
            Err(SettingsError::ConfigReadOnly(b)) => assert_eq!(b.text, text),
            other => return Err(format!("{other:?}").into()),
        }
    }
    // A batch with one file-backed change refuses all of it, before any dialog.
    let r = apply(&s, vec![LegalHold(true), JiraCommentsCap(50)]).await?;
    assert!(matches!(r, Err(SettingsError::ConfigReadOnly(_))));
    assert_eq!(std::fs::read(h.config_path())?, before, "never rewritten");
    assert!(h.confirmer().texts().is_empty());
    assert!(h.events_of(EventType::LEGAL_HOLD_CHANGED).await?.is_empty());
    // The audit-authoritative settings still change.
    let v = apply(&s, vec![RetentionDays(120)]).await??;
    assert_eq!(v.retention_days, 120);
    assert_eq!(std::fs::read(h.config_path())?, before);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prune_backlog_now_requires_confirmation() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    h.confirmer().push(Confirm::Cancel);
    let s2 = s.clone();
    let r = tokio::task::spawn_blocking(move || s2.prune_backlog_now()).await?;
    assert_eq!(r.err(), Some(SettingsError::Cancelled));
    assert_eq!(h.confirmer().texts(), [PRUNE_BACKLOG_TEXT]);
    assert!(h.events_of(EventType::PRUNE).await?.is_empty());
    h.confirmer().push(Confirm::Ok);
    let s2 = s.clone();
    let r = tokio::task::spawn_blocking(move || s2.prune_backlog_now()).await?;
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(h.confirmer().texts().len(), 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verify_now_err_is_did_not_complete() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let s2 = s.clone();
    let first = tokio::task::spawn_blocking(move || s2.verify_now()).await?;
    assert_eq!(first, VerifyNow::Verified);
    assert_eq!(first.text(), "verified");
    // A store that cannot run the verification: never a pass.
    h.store().shutdown();
    let s2 = s.clone();
    let r = tokio::task::spawn_blocking(move || s2.verify_now()).await?;
    assert_eq!(r, VerifyNow::DidNotComplete);
    assert_eq!(
        serde_json::to_value(r)?,
        json!({"result": "did_not_complete", "text": "verification did not complete"})
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_app_change_logs_config_changed() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let s2 = s.clone();
    tokio::task::spawn_blocking(move || {
        s2.record_app_change(
            "cli_install",
            json!({"installed": false}),
            json!({"installed": true}),
        )
    })
    .await??;
    let recs = config_changed(&h, "cli_install").await?;
    let [r] = recs.as_slice() else {
        return Err(format!("{} records", recs.len()).into());
    };
    assert_eq!(
        *r,
        json!({"source": "app", "key": "cli_install", "old": {"installed": false},
               "new": {"installed": true}, "applied": true})
    );
    // Settings and audit-policy keys go through `apply` / the store, never through here.
    for key in [
        "jira_comments_cap",
        "retention_days",
        "legal_hold",
        "anchor_dir",
        "instance.ins_x.origin",
        "Bad Key",
        "",
    ] {
        let s2 = s.clone();
        let k = key.to_owned();
        let r = tokio::task::spawn_blocking(move || s2.record_app_change(&k, json!(1), json!(2)))
            .await?;
        assert!(
            matches!(r, Err(SettingsError::Invalid { .. })),
            "{key}: {r:?}"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_append_changes_nothing() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let before = std::fs::read(h.config_path())?;
    h.plan().fail_all(true);
    for change in [
        JiraCommentsCap(10),
        Mode(AttentionMode::BadgeOnly),
        LegalHold(true),
    ] {
        let r = apply(&s, vec![change]).await?;
        assert!(matches!(r, Err(SettingsError::Audit(_))), "{r:?}");
    }
    h.plan().fail_all(false);
    assert_eq!(std::fs::read(h.config_path())?, before);
    let v = view(&s).await?;
    assert_eq!(v.limits.jira_comments_cap, 100);
    assert_eq!(v.attention_mode, AttentionMode::ShowWithoutActivating);
    assert!(!v.legal_hold);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settings_writes_refused_after_shutdown() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    h.core().shutdown(ShutdownReason::Quit).await;
    let r = apply(&s, vec![JiraCommentsCap(10)]).await?;
    assert_eq!(r.err(), Some(SettingsError::ShuttingDown));
    let s2 = s.clone();
    let (prune, verify, app) = tokio::task::spawn_blocking(move || {
        (
            s2.prune_backlog_now(),
            s2.verify_now(),
            s2.record_app_change("cli_install", json!(false), json!(true)),
        )
    })
    .await?;
    assert_eq!(prune.err(), Some(SettingsError::ShuttingDown));
    assert_eq!(verify, VerifyNow::DidNotComplete);
    assert_eq!(app.err(), Some(SettingsError::ShuttingDown));
    assert!(h.confirmer().texts().is_empty());
    assert!(config_changed(&h, "jira_comments_cap").await?.is_empty());
    assert!(config_changed(&h, "cli_install").await?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_after_the_shutdown_began_changes_nothing() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let go_rx = std::sync::Mutex::new(go_rx);
    h.confirmer().set_hook(Arc::new(move |_| {
        let _ = tx.send(());
        let _ = go_rx.lock().map(|r| r.recv());
    }));
    h.confirmer().push(Confirm::Ok);
    let s2 = s.clone();
    let task = tokio::task::spawn_blocking(move || s2.apply(vec![JiraCommentsCap(500)]));
    tokio::task::spawn_blocking(move || rx.recv()).await??;
    // The dialog is open: the shutdown waits its bounded drain, then the user answers Ok.
    let shutdown = h.core().shutdown(ShutdownReason::Quit);
    let answer = async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = go_tx.send(());
    };
    let (_, ()) = tokio::join!(shutdown, answer);
    assert_eq!(task.await?.err(), Some(SettingsError::ShuttingDown));
    assert!(config_changed(&h, "jira_comments_cap").await?.is_empty());
    assert_eq!(
        limits_config(&load_config(&h.config_path())?)?.jira_comments_cap,
        None
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_made_while_the_dialog_is_open_is_a_conflict() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let inner = s.clone();
    // While the raise dialog is open, another window lowers the cap (no dialog).
    h.confirmer().set_hook(Arc::new(move |_| {
        let _ = inner.apply(vec![JiraCommentsCap(20)]);
    }));
    h.confirmer().push(Confirm::Ok);
    let r = apply(&s, vec![JiraCommentsCap(500)]).await?;
    assert_eq!(r.err(), Some(SettingsError::Conflict));
    assert_eq!(view(&s).await?.limits.jira_comments_cap, 20);
    let recs = config_changed(&h, "jira_comments_cap").await?;
    assert_eq!(recs.len(), 1, "only the lowering");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lowered_retention_is_not_raised_again_by_the_file() -> TestResult {
    let mut h = Harness::builder()
        .jira("jira-main")
        .extra_config("[audit]\nretention_days = 150\nlegal_hold = true\n")
        .start()
        .await?;
    let s = h.core().settings();
    let v = view(&s).await?;
    assert_eq!(
        (v.retention_days, v.legal_hold),
        (150, true),
        "X-01 at start"
    );
    h.confirmer().push(Confirm::Ok);
    h.confirmer().push(Confirm::Ok);
    apply(&s, vec![RetentionDays(120), LegalHold(false)]).await??;
    let text = std::fs::read_to_string(h.config_path())?;
    assert!(text.contains("retention_days = 120"), "{text}");
    assert!(text.contains("legal_hold = false"), "{text}");
    h.restart().await?;
    let v = view(&h.core().settings()).await?;
    assert_eq!((v.retention_days, v.legal_hold), (120, false));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn view_reports_store_health_and_settings() -> TestResult {
    let h = Harness::jira().await?;
    let v = view(&h.core().settings()).await?;
    assert_eq!(v.retention_days, 100);
    assert!(!v.legal_hold);
    assert_eq!(v.config_read_only, None);
    assert_eq!(v.health.open_incidents, 0);
    assert_eq!(v.health.prune_backlog, None);
    let json = serde_json::to_value(&v)?;
    assert_eq!(json["limits"]["jira_comments_cap"], 100);
    assert_eq!(json["attention_mode"], "show_without_activating");
    Ok(())
}
