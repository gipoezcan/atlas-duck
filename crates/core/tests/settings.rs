#![cfg(feature = "testing")]
//! M6 Task 8: `SettingsAdmin` (Δ3), the `[limits] jira_comments_cap` and `[ui] attention_mode`
//! keys (Δ6), the live comments cap (PD-63, PD-76), "Prune backlog now" (L37) and "Verify now"
//! (PD-82, M2 handoff).

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use atlas_duck_audit::EventType;
use atlas_duck_core::config::limits::limits_config;
use atlas_duck_core::config::requests::expiry_hours;
use atlas_duck_core::config::scripts::{scripts_config, start_limits};
use atlas_duck_core::config::ui::attention_mode_config;
use atlas_duck_core::config::{ConfigState, load_config};
use atlas_duck_core::engine::queue::MIB;
use atlas_duck_core::settings::{
    ALLOW_DEGRADED_TEXT, LIFT_HOLD_TEXT, PRUNE_BACKLOG_TEXT, ScriptLimitsReq,
};
use atlas_duck_core::testing::Harness;
use atlas_duck_core::{
    AttentionMode, Confirm, SettingChangeReq, SettingsAdmin, SettingsError, SettingsView,
    ShutdownReason, VerifyNow,
};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_ipc::sandbox::ScriptLimits;
use common::jira::{comment_page, comments_path, gets_on, mount_comments, mount_issue, query};
use common::{TestError, TestResult, request_id};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use SettingChangeReq::{
    AllowDegradedScripts, AttentionMode as Mode, CandidateCacheMb, ExpiryHours, JiraCommentsCap,
    LegalHold, MaxPendingBytesMb, RetentionDays, ScriptLimits as Scripts,
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

/// PD-82's third outcome: a finding that is an incident (a `PRUNE` whose snapshot names fewer
/// than the 92 retention days of §8.8) is `incident` with its count, and the fixed text.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verify_now_three_outcomes() -> TestResult {
    use atlas_duck_audit::testing::{FakePrune, insert_fake_prune};
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let s2 = s.clone();
    let ok = tokio::task::spawn_blocking(move || s2.verify_now()).await?;
    assert_eq!(ok.text(), "verified");
    insert_fake_prune(
        &h.store(),
        FakePrune {
            first_retained_seq: 2,
            cutoff: "2026-06-01".into(),
            settings: json!({"retention_days": 30, "legal_hold": false}),
            update_first_retained: false,
        },
    )?;
    let s2 = s.clone();
    let r = tokio::task::spawn_blocking(move || s2.verify_now()).await?;
    let VerifyNow::Incident { count } = r else {
        return Err(format!("not an incident: {r:?}").into());
    };
    assert!(count >= 1);
    assert_eq!(r.text(), "integrity incident: see Audit");
    assert_eq!(
        serde_json::to_value(r)?,
        json!({"result": "incident", "count": count, "text": "integrity incident: see Audit"})
    );
    h.store().shutdown();
    let r = tokio::task::spawn_blocking(move || s.verify_now()).await?;
    assert_eq!(r.text(), "verification did not complete");
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

/// M6 T8 review I-1: the records commit, the file cannot take the value (`[limits]` is not a
/// table, so `set_key` refuses it): `ConfigWrite`, a corrective `applied: false` record that
/// names the reason, nothing changed in the file or in force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_config_write_after_the_records_is_recorded_and_reported() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let broken = "schema_version = 1\nlimits = 1\n";
    std::fs::write(h.config_path(), broken)?;
    for change in [JiraCommentsCap(10), Mode(AttentionMode::BadgeOnly)] {
        let key = change.key();
        let r = apply(&s, vec![change]).await?;
        // The attention mode lives in `[ui]`, which is a table: only the cap's write fails.
        if key == "jira_comments_cap" {
            assert_eq!(r.err(), Some(SettingsError::ConfigWrite));
            let recs = config_changed(&h, key).await?;
            let applied: Vec<_> = recs.iter().map(|p| p["applied"].clone()).collect();
            assert_eq!(applied, [json!(true), json!(false)], "{recs:?}");
            assert!(recs[0].get("reason").is_none());
            assert_eq!(recs[1]["reason"], "config_write_failed");
            assert_eq!(recs[1]["old"], recs[0]["old"]);
            assert_eq!(recs[1]["new"], recs[0]["new"]);
            assert_eq!(std::fs::read_to_string(h.config_path())?, broken);
            assert_eq!(view(&s).await?.limits.jira_comments_cap, 100);
        } else {
            assert!(r.is_ok(), "{r:?}");
        }
    }
    Ok(())
}

/// M6 T8 review I-3: `SettingsAdmin` and the instance writers share one lock, so concurrent
/// read-modify-write edits of `config.toml` all survive.
#[test]
fn concurrent_config_edits_all_survive() -> TestResult {
    use atlas_duck_core::config::update_config;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "schema_version = 1\n")?;
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let path = path.clone();
            std::thread::spawn(move || {
                for i in 0..20 {
                    let key = format!("k_{t}_{i}");
                    let r = update_config(&path, |doc| {
                        doc[key.as_str()] = toml_edit::value(1);
                        Ok::<(), ()>(())
                    });
                    assert!(matches!(r, Ok(Ok(()))));
                }
            })
        })
        .collect();
    for t in threads {
        t.join().map_err(|_| "a writer thread panicked")?;
    }
    let text = std::fs::read_to_string(&path)?;
    for t in 0..8 {
        for i in 0..20 {
            assert!(text.contains(&format!("k_{t}_{i} = 1")), "lost k_{t}_{i}");
        }
    }
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
    // The script limits in force (M8 Δ6): the eight §9.4 keys at their defaults.
    assert_eq!(v.limits.script, ScriptLimits::default());
    // Not on the wire until the Settings UI task widens its closed validator and fixture.
    assert!(json["limits"].get("script").is_none());
    Ok(())
}

// ---- M8 Task 14: script limits (PD-139, PD-140) ----------------------------------------------

fn script_req(f: impl FnOnce(&mut ScriptLimitsReq)) -> SettingChangeReq {
    let mut r = ScriptLimitsReq::default();
    f(&mut r);
    Scripts(r)
}

fn file_scripts(h: &Harness) -> Result<ScriptLimits, TestError> {
    Ok(scripts_config(&load_config(&h.config_path())?)?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn script_limits_defaults_from_config() -> TestResult {
    // No `[scripts]` table: the spec's defaults, in the view, the engine and admission.
    let h = Harness::jira().await?;
    let v = view(&h.core().settings()).await?;
    assert_eq!(v.limits.script, ScriptLimits::default());
    assert_eq!(h.engine().limits().script, ScriptLimits::default());
    assert_eq!(
        h.engine().admission().script_limits(),
        ScriptLimits::default()
    );
    assert_eq!(
        scripts_config(&ConfigState::Absent)?,
        ScriptLimits::default()
    );

    // A partial table: the named keys, the defaults for the rest.
    let h = Harness::builder()
        .jira("jira-main")
        .extra_config("[scripts]\ntimeout_s = 240\nmax_calls = 100\n")
        .start()
        .await?;
    let want = ScriptLimits {
        timeout_s: 240,
        max_calls: 100,
        ..ScriptLimits::default()
    };
    assert_eq!(view(&h.core().settings()).await?.limits.script, want);
    assert_eq!(h.engine().limits().script, want);
    assert_eq!(h.engine().admission().script_limits(), want);
    assert!(view(&h.core().settings()).await?.restart_pending.is_empty());

    // A table that is refused as a whole: the core runs with the defaults (fail safe).
    let h = Harness::builder()
        .jira("jira-main")
        .extra_config("[scripts]\ntimeout_s = 240\nmax_result_mb = 17\n")
        .start()
        .await?;
    assert_eq!(h.engine().limits().script, ScriptLimits::default());
    Ok(())
}

#[test]
fn script_limit_bounds_respect_frame_and_release_caps() -> TestResult {
    // Settings: the frame cap (24 MiB host -> worker) and the release cap (16 MiB) bound the two
    // result keys at 16; everything else at 4 x the spec default.
    type Set = fn(&mut ScriptLimitsReq);
    let refused: [(Set, &str); 10] = [
        (|r| r.max_call_result_mb = Some(17), "max_call_result_mb"),
        (|r| r.max_result_mb = Some(17), "max_result_mb"),
        (|r| r.max_call_result_mb = Some(0), "max_call_result_mb"),
        (|r| r.timeout_s = Some(481), "timeout_s"),
        (|r| r.heap_mb = Some(1025), "heap_mb"),
        (|r| r.process_mb = Some(2049), "process_mb"),
        (|r| r.max_calls = Some(801), "max_calls"),
        (|r| r.max_fetch_mb = Some(201), "max_fetch_mb"),
        (|r| r.max_concurrent_calls = Some(0), "max_concurrent_calls"),
        (
            |r| r.max_concurrent_calls = Some(17),
            "max_concurrent_calls",
        ),
    ];
    for (f, key) in refused {
        assert_eq!(
            script_req(f).validate(),
            Err(SettingsError::Invalid { key }),
            "{key}"
        );
    }
    let accepted: [Set; 9] = [
        |r| r.max_call_result_mb = Some(16),
        |r| r.max_result_mb = Some(16),
        |r| r.timeout_s = Some(480),
        |r| r.heap_mb = Some(1024),
        |r| r.process_mb = Some(2048),
        |r| r.max_calls = Some(800),
        |r| r.max_fetch_mb = Some(200),
        |r| r.max_concurrent_calls = Some(1),
        |r| r.max_concurrent_calls = Some(16),
    ];
    for f in accepted {
        assert_eq!(script_req(f).validate(), Ok(()));
    }

    // The `[scripts]` file table: the same bounds, refused like any other invalid config value
    // (the key named, never the value).
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("config.toml");
    let load = |text: &str| -> Result<_, TestError> {
        std::fs::write(&path, format!("schema_version = 1\n[scripts]\n{text}"))?;
        Ok(scripts_config(&load_config(&path)?))
    };
    for (text, key) in [
        ("max_call_result_mb = 17\n", "max_call_result_mb"),
        ("max_result_mb = 17\n", "max_result_mb"),
        ("timeout_s = 481\n", "timeout_s"),
        ("max_concurrent_calls = 0\n", "max_concurrent_calls"),
        ("max_concurrent_calls = 17\n", "max_concurrent_calls"),
        ("max_calls = \"many\"\n", "max_calls"),
        ("max_calls = -1\n", "max_calls"),
    ] {
        match load(text)? {
            Err(e) => {
                let shown = e.to_string();
                assert!(shown.contains(key), "{text}: {shown}");
                assert!(!shown.contains("481") && !shown.contains("many"), "{shown}");
            }
            Ok(l) => return Err(format!("{text}: accepted as {l:?}").into()),
        }
    }
    let top = load(
        "max_call_result_mb = 16\nmax_result_mb = 16\ntimeout_s = 480\nmax_concurrent_calls = 16\n",
    )?;
    assert_eq!(top?.timeout_s, 480);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounds_are_checked_by_apply_before_anything_happens() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    for req in [
        script_req(|r| r.max_call_result_mb = Some(17)),
        script_req(|r| r.max_result_mb = Some(17)),
        script_req(|r| r.timeout_s = Some(481)),
        script_req(|r| r.max_concurrent_calls = Some(17)),
    ] {
        let r = apply(&s, vec![req]).await?;
        assert!(matches!(r, Err(SettingsError::Invalid { .. })), "{r:?}");
    }
    assert!(h.confirmer().texts().is_empty());
    assert!(config_changed(&h, "script_limits").await?.is_empty());
    assert_eq!(view(&s).await?.limits.script, ScriptLimits::default());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raising_script_limit_needs_native_confirmation() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let text = raise("the script timeout (s)", "120", "240");
    // Cancel: no record, no file key, the limit in force unchanged.
    h.confirmer().push(Confirm::Cancel);
    let r = apply(&s, vec![script_req(|r| r.timeout_s = Some(240))]).await?;
    assert_eq!(r.err(), Some(SettingsError::Cancelled));
    assert_eq!(h.confirmer().texts(), [text.as_str()]);
    assert!(config_changed(&h, "script_limits").await?.is_empty());
    assert_eq!(file_scripts(&h)?, ScriptLimits::default());
    assert_eq!(h.engine().admission().script_limits().timeout_s, 120);

    // Ok: recorded with the dialog hash, written to `[scripts]`, in force at once.
    h.confirmer().push(Confirm::Ok);
    let v = apply(&s, vec![script_req(|r| r.timeout_s = Some(240))]).await??;
    assert_eq!(v.limits.script.timeout_s, 240);
    assert_eq!(file_scripts(&h)?.timeout_s, 240);
    assert_eq!(h.engine().admission().script_limits().timeout_s, 240);
    assert!(v.restart_pending.is_empty(), "{:?}", v.restart_pending);
    let recs = config_changed(&h, "script_limits").await?;
    let [r] = recs.as_slice() else {
        return Err(format!("{} records", recs.len()).into());
    };
    assert_eq!(r["source"], "app");
    assert_eq!(r["old"], json!({ "timeout_s": 120 }));
    assert_eq!(r["new"], json!({ "timeout_s": 240 }));
    assert_eq!(r["applied"], true);
    assert_eq!(r["confirmed"]["dialog_text_sha256"], sha_hex(&text));
    // An unchanged value is no change: no dialog, no record.
    let shown = h.confirmer().texts().len();
    apply(&s, vec![script_req(|r| r.timeout_s = Some(240))]).await??;
    assert_eq!(h.confirmer().texts().len(), shown);
    assert_eq!(config_changed(&h, "script_limits").await?.len(), 1);
    // A Settings key is not an app-owned key.
    let reserved = s.record_app_change("script_limits", json!(1), json!(2));
    assert_eq!(reserved.err(), Some(SettingsError::Invalid { key: "key" }));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raising_two_script_limits_one_dialog_one_line_each() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    // Two raised keys and one lowered one: one dialog, a line per raised key in §9.4 key order.
    let text = [
        raise("the script timeout (s)", "120", "240"),
        raise("the script call limit", "200", "300"),
    ]
    .join("\n");
    h.confirmer().push(Confirm::Ok);
    let v = apply(
        &s,
        vec![script_req(|r| {
            r.max_calls = Some(300);
            r.max_fetch_mb = Some(10);
            r.timeout_s = Some(240);
        })],
    )
    .await??;
    assert_eq!(h.confirmer().texts(), [text.as_str()]);
    let want = ScriptLimits {
        timeout_s: 240,
        max_calls: 300,
        max_fetch_mb: 10,
        ..ScriptLimits::default()
    };
    assert_eq!(v.limits.script, want);
    assert_eq!(file_scripts(&h)?, want);
    let recs = config_changed(&h, "script_limits").await?;
    let [r] = recs.as_slice() else {
        return Err(format!("{} records", recs.len()).into());
    };
    assert_eq!(r["confirmed"]["dialog_text_sha256"], sha_hex(&text));
    assert_eq!(
        r["new"],
        json!({ "timeout_s": 240, "max_calls": 300, "max_fetch_mb": 10 })
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lowering_script_limit_plain_config_changed() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let v = apply(
        &s,
        vec![script_req(|r| {
            r.timeout_s = Some(60);
            r.max_calls = Some(100);
        })],
    )
    .await??;
    assert!(h.confirmer().texts().is_empty(), "no dialog for a lowering");
    assert_eq!(
        (v.limits.script.timeout_s, v.limits.script.max_calls),
        (60, 100)
    );
    assert_eq!(h.engine().admission().script_limits(), v.limits.script);
    assert_eq!(file_scripts(&h)?, v.limits.script);
    let recs = config_changed(&h, "script_limits").await?;
    let [r] = recs.as_slice() else {
        return Err(format!("{} records", recs.len()).into());
    };
    assert_eq!(r["confirmed"], Value::Null);
    assert_eq!(r["old"], json!({ "timeout_s": 120, "max_calls": 200 }));
    assert_eq!(r["new"], json!({ "timeout_s": 60, "max_calls": 100 }));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invariants_enforced_in_settings() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    // Invariant 2 on the resulting set: process_mb >= heap_mb + 88 (default heap 256: 344).
    let r = apply(&s, vec![script_req(|r| r.process_mb = Some(343))]).await?;
    assert_eq!(r.err(), Some(SettingsError::Invalid { key: "process_mb" }));
    // Raising the heap alone breaks it against the unchanged process limit (512 < 513 + 88).
    let r = apply(&s, vec![script_req(|r| r.heap_mb = Some(513))]).await?;
    assert_eq!(r.err(), Some(SettingsError::Invalid { key: "process_mb" }));
    // Invariant 1 (PD-140, k = 8): heap_mb >= 8 x max_call_result_mb (default 16: 128).
    let r = apply(&s, vec![script_req(|r| r.heap_mb = Some(127))]).await?;
    assert_eq!(r.err(), Some(SettingsError::Invalid { key: "heap_mb" }));
    // Nothing happened: no dialog, no record, no file key, the view unchanged.
    assert!(h.confirmer().texts().is_empty());
    assert!(config_changed(&h, "script_limits").await?.is_empty());
    assert_eq!(file_scripts(&h)?, ScriptLimits::default());
    assert_eq!(view(&s).await?.limits.script, ScriptLimits::default());

    // The boundaries are accepted, and the check is on the set the call leaves behind.
    let v = apply(&s, vec![script_req(|r| r.heap_mb = Some(128))]).await??;
    assert_eq!(v.limits.script.heap_mb, 128);
    let v = apply(&s, vec![script_req(|r| r.process_mb = Some(216))]).await??;
    assert_eq!(v.limits.script.process_mb, 216);
    let v = apply(
        &s,
        vec![script_req(|r| {
            r.heap_mb = Some(64);
            r.max_call_result_mb = Some(8);
        })],
    )
    .await??;
    assert_eq!(
        (v.limits.script.heap_mb, v.limits.script.max_call_result_mb),
        (64, 8)
    );
    // Raising the call result back needs the heap to follow in the same call.
    let r = apply(&s, vec![script_req(|r| r.max_call_result_mb = Some(16))]).await?;
    assert_eq!(r.err(), Some(SettingsError::Invalid { key: "heap_mb" }));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_edit_applies_at_next_start() -> TestResult {
    let mut h = Harness::jira().await?;
    let s = h.core().settings();
    let path = h.config_path();
    let mut text = std::fs::read_to_string(&path)?;
    text.push_str("\n[scripts]\ntimeout_s = 90\n");
    std::fs::write(&path, text)?;
    // This run keeps what it started with; the view says the file differs ("applies after
    // restart", PD-76 as for the memory limits).
    let v = view(&s).await?;
    assert_eq!(v.limits.script, ScriptLimits::default());
    assert_eq!(v.restart_pending, ["script_limits"]);
    assert_eq!(
        h.engine().admission().script_limits(),
        ScriptLimits::default()
    );

    h.restart().await?;
    let want = ScriptLimits {
        timeout_s: 90,
        ..ScriptLimits::default()
    };
    assert_eq!(h.engine().limits().script, want);
    assert_eq!(h.engine().admission().script_limits(), want);
    let v = view(&h.core().settings()).await?;
    assert_eq!(v.limits.script, want);
    assert!(v.restart_pending.is_empty());
    Ok(())
}

/// The `[scripts]` table as the next start would read it, which must load.
fn next_start(h: &Harness) -> Result<ScriptLimits, TestError> {
    file_scripts(h).map_err(|e| format!("the file would not load at the next start: {e}").into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settings_change_repairs_a_refused_scripts_table() -> TestResult {
    // Review I-2 scenario A: the table is refused (defaults live), a Settings change must not
    // leave the bad key behind to revert it at the next start.
    let h = Harness::builder()
        .jira("jira-main")
        .extra_config("[scripts]\nmax_result_mb = 17\n")
        .start()
        .await?;
    let s = h.core().settings();
    let v = apply(&s, vec![script_req(|r| r.timeout_s = Some(60))]).await??;
    let want = ScriptLimits {
        timeout_s: 60,
        ..ScriptLimits::default()
    };
    assert_eq!(v.limits.script, want);
    assert_eq!(next_start(&h)?, want);
    assert!(v.restart_pending.is_empty(), "{:?}", v.restart_pending);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settings_change_cannot_pair_with_a_pending_file_edit() -> TestResult {
    // Review I-2 scenario B: the file holds a valid pending pair (heap 1024, process 2048); a
    // process_mb of 600 passes against the live heap (256) but not against the file's.
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let mut text = std::fs::read_to_string(h.config_path())?;
    text.push_str("\n[scripts]\nheap_mb = 1024\nprocess_mb = 2048\n");
    std::fs::write(h.config_path(), text)?;
    let v = view(&s).await?;
    assert_eq!(v.restart_pending, ["script_limits"]);
    h.confirmer().push(Confirm::Ok);
    let v = apply(&s, vec![script_req(|r| r.process_mb = Some(600))]).await??;
    assert_eq!(v.limits.script.process_mb, 600);
    assert_eq!(next_start(&h)?, v.limits.script);
    assert!(v.restart_pending.is_empty(), "{:?}", v.restart_pending);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn setting_the_live_value_clears_a_pending_file_edit() -> TestResult {
    // Review I-2 scenario C: the file says 300, the live value is 120; setting 120 is not "no
    // change" for the file.
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let mut text = std::fs::read_to_string(h.config_path())?;
    text.push_str("\n[scripts]\ntimeout_s = 300\n");
    std::fs::write(h.config_path(), text)?;
    assert_eq!(view(&s).await?.restart_pending, ["script_limits"]);
    let v = apply(&s, vec![script_req(|r| r.timeout_s = Some(120))]).await??;
    assert!(v.restart_pending.is_empty(), "{:?}", v.restart_pending);
    assert_eq!(next_start(&h)?, ScriptLimits::default());
    // Nothing changed live: no dialog, no record.
    assert!(h.confirmer().texts().is_empty());
    assert!(config_changed(&h, "script_limits").await?.is_empty());

    // A hand edit that does not load is cleared the same way.
    let text = std::fs::read_to_string(h.config_path())?;
    let broken = text.replace("max_result_mb = 16", "max_result_mb = 17");
    assert_ne!(broken, text, "the table holds max_result_mb");
    std::fs::write(h.config_path(), broken)?;
    assert!(file_scripts(&h).is_err());
    apply(&s, vec![script_req(|r| r.timeout_s = Some(120))]).await??;
    assert_eq!(next_start(&h)?, ScriptLimits::default());
    Ok(())
}

/// Every `tracing` event of the calling thread, as text (message and fields).
struct ThreadLog(std::sync::Mutex<Vec<String>>);

struct Fields<'a>(&'a mut String);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={value:?}", field.name()));
    }
}

struct ThreadSink(Arc<ThreadLog>);

impl tracing::Subscriber for ThreadSink {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = String::new();
        event.record(&mut Fields(&mut line));
        self.0
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(line);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn a_refused_scripts_table_is_logged_at_start() -> TestResult {
    // Review I-1: the `[audit]` precedent logs a malformed value; the table is refused as a
    // whole and the limits fall back to the defaults, so the start says so (key, no value).
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("config.toml");
    let load = |text: &str| -> Result<_, TestError> {
        std::fs::write(&path, format!("schema_version = 1\n[scripts]\n{text}"))?;
        Ok(load_config(&path)?)
    };
    let log = Arc::new(ThreadLog(std::sync::Mutex::new(Vec::new())));
    let _guard = tracing::subscriber::set_default(ThreadSink(log.clone()));
    let lines = || log.0.lock().unwrap_or_else(|e| e.into_inner()).clone();

    // A table that loads logs nothing.
    let ok = load("timeout_s = 90\n")?;
    assert_eq!(start_limits(&ok).timeout_s, 90);
    assert!(lines().is_empty(), "{:?}", lines());

    for (text, class) in [
        ("max_result_mb = 17\ntimeout_s = 91\n", "max_result_mb"),
        ("heap_mb = 100\n", "heap_mb"),
    ] {
        let before = lines().len();
        assert_eq!(start_limits(&load(text)?), ScriptLimits::default());
        let l = lines();
        let [.., last] = l.as_slice() else {
            return Err(format!("{text}: nothing logged").into());
        };
        assert_eq!(l.len(), before + 1, "{l:?}");
        assert!(last.contains("scripts") && last.contains(class), "{last}");
        assert!(last.contains("spec defaults"), "{last}");
        assert!(!last.contains("17") && !last.contains("91"), "{last}");
    }
    Ok(())
}

// ---- M8 Task 15: "Allow scripts with degraded confinement" (PD-141, Δ6, Δ7) ------------------

/// Whether the policy core reads before each runner call allows degraded confinement.
fn degraded_policy(h: &Harness) -> bool {
    h.core().script_policy().allow_degraded
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn degraded_toggle_needs_native_confirmation_and_logs_config_changed() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    assert!(!view(&s).await?.allow_degraded_scripts, "absent = off");
    assert!(!degraded_policy(&h));
    h.confirmer().push(Confirm::Ok);
    let v = apply(&s, vec![AllowDegradedScripts(true)]).await??;
    assert_eq!(h.confirmer().texts(), [ALLOW_DEGRADED_TEXT]);
    assert!(v.allow_degraded_scripts);
    assert!(degraded_policy(&h), "read fresh from the audit settings");
    let recs = config_changed(&h, "allow_degraded_scripts").await?;
    let [r] = recs.as_slice() else {
        return Err(format!("{} records", recs.len()).into());
    };
    assert_eq!(
        *r,
        json!({
            "source": "app", "key": "allow_degraded_scripts", "old": false, "requested": true,
            "new": true, "applied": true,
            "confirmed": {"dialog_text_sha256": sha_hex(ALLOW_DEGRADED_TEXT)},
        })
    );
    // Audit-authoritative (L32): the store's view holds it, nothing else.
    assert!(h.store().settings().allow_degraded_scripts);
    // Setting what is in force is no change: no dialog, no record.
    apply(&s, vec![AllowDegradedScripts(true)]).await??;
    assert_eq!(h.confirmer().texts().len(), 1);
    assert_eq!(config_changed(&h, "allow_degraded_scripts").await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn degraded_toggle_cancel_changes_nothing() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let events = h.event_count().await?;
    h.confirmer().push(Confirm::Cancel);
    let r = apply(&s, vec![AllowDegradedScripts(true)]).await?;
    assert_eq!(r.err(), Some(SettingsError::Cancelled));
    assert_eq!(h.confirmer().texts(), [ALLOW_DEGRADED_TEXT]);
    assert_eq!(h.event_count().await?, events, "nothing logged");
    assert!(!view(&s).await?.allow_degraded_scripts);
    assert!(!degraded_policy(&h));
    assert!(!h.store().settings().allow_degraded_scripts);
    // One `Cancel` applies none of the call's changes, the plain ones included.
    h.confirmer().push(Confirm::Cancel);
    let r = apply(&s, vec![RetentionDays(150), AllowDegradedScripts(true)]).await?;
    assert_eq!(r.err(), Some(SettingsError::Cancelled));
    assert_eq!(h.event_count().await?, events);
    assert_eq!(view(&s).await?.retention_days, 100);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn degraded_toggle_off_needs_no_confirmation() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    h.confirmer().push(Confirm::Ok);
    apply(&s, vec![AllowDegradedScripts(true)]).await??;
    assert!(degraded_policy(&h));
    let shown = h.confirmer().texts().len();
    let v = apply(&s, vec![AllowDegradedScripts(false)]).await??;
    assert_eq!(
        h.confirmer().texts().len(),
        shown,
        "§10.3: turning it off is stricter"
    );
    assert!(!v.allow_degraded_scripts);
    assert!(!degraded_policy(&h));
    let recs = config_changed(&h, "allow_degraded_scripts").await?;
    let off = recs.last().ok_or("no record")?;
    assert_eq!(
        *off,
        json!({
            "source": "app", "key": "allow_degraded_scripts", "old": true, "requested": false,
            "new": false, "applied": true, "confirmed": null,
        })
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn degraded_toggle_flipped_while_its_dialog_is_open_is_a_conflict() -> TestResult {
    let h = Harness::jira().await?;
    let s = h.core().settings();
    let inner = s.clone();
    let once = AtomicBool::new(false);
    // While this window's dialog is open, another window turns it on first (its own dialog,
    // answered by the first `Ok`).
    h.confirmer().set_hook(Arc::new(move |_| {
        if !once.swap(true, Ordering::SeqCst) {
            let _ = inner.apply(vec![AllowDegradedScripts(true)]);
        }
    }));
    h.confirmer().push(Confirm::Ok);
    h.confirmer().push(Confirm::Ok);
    let r = apply(&s, vec![AllowDegradedScripts(true)]).await?;
    assert_eq!(r.err(), Some(SettingsError::Conflict));
    assert_eq!(h.confirmer().texts(), [ALLOW_DEGRADED_TEXT; 2]);
    assert!(view(&s).await?.allow_degraded_scripts);
    assert!(degraded_policy(&h));
    let recs = config_changed(&h, "allow_degraded_scripts").await?;
    assert_eq!(recs.len(), 1, "only the other window's");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn degraded_toggle_survives_restart() -> TestResult {
    let mut h = Harness::jira().await?;
    h.confirmer().push(Confirm::Ok);
    apply(&h.core().settings(), vec![AllowDegradedScripts(true)]).await??;
    h.restart().await?;
    assert!(view(&h.core().settings()).await?.allow_degraded_scripts);
    assert!(degraded_policy(&h));
    apply(&h.core().settings(), vec![AllowDegradedScripts(false)]).await??;
    h.restart().await?;
    assert!(!view(&h.core().settings()).await?.allow_degraded_scripts);
    assert!(!degraded_policy(&h));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn degraded_toggle_has_no_config_file_path() -> TestResult {
    // A `config.toml` that names the toggle anywhere turns nothing on (R2: no file key).
    let h = Harness::builder()
        .jira("jira-main")
        .extra_config(
            "[audit]\nallow_degraded_scripts = true\n[scripts]\nallow_degraded_scripts = true\n\
             [sandbox]\nallow_degraded_scripts = true\n",
        )
        .start()
        .await?;
    let s = h.core().settings();
    assert!(!view(&s).await?.allow_degraded_scripts);
    assert!(!degraded_policy(&h));
    assert!(
        config_changed(&h, "allow_degraded_scripts")
            .await?
            .is_empty(),
        "the file is never reconciled into it"
    );
    // The change writes no file: `config.toml` stays byte for byte.
    let before = std::fs::read(h.config_path())?;
    h.confirmer().push(Confirm::Ok);
    apply(&s, vec![AllowDegradedScripts(true)]).await??;
    apply(&s, vec![AllowDegradedScripts(false)]).await??;
    assert_eq!(std::fs::read(h.config_path())?, before);
    // Nor is it a key an app-owned record may name.
    let s2 = s.clone();
    let r = tokio::task::spawn_blocking(move || {
        s2.record_app_change("allow_degraded_scripts", json!(false), json!(true))
    })
    .await?;
    assert!(matches!(r, Err(SettingsError::Invalid { .. })), "{r:?}");
    assert!(!degraded_policy(&h));

    // A read-only `config.toml` refuses every file-backed change, not this one.
    let h = Harness::builder()
        .config_text("schema_version = 2\nwritten_by = \"9.1.0\"\n[future]\nkey = 1\n")
        .start()
        .await?;
    let s = h.core().settings();
    let before = std::fs::read(h.config_path())?;
    h.confirmer().push(Confirm::Ok);
    let v = apply(&s, vec![AllowDegradedScripts(true)]).await??;
    assert!(v.allow_degraded_scripts);
    assert!(degraded_policy(&h));
    assert_eq!(std::fs::read(h.config_path())?, before);
    Ok(())
}
