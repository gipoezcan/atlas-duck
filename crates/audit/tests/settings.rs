//! The audit-authoritative settings (§8.8, §7.7, §10.3, L32, P5; X-01, X-02 store half): the
//! view, `apply_setting`'s confirmation rules, the config-file reconcile, and that a setting
//! outlives the pruning of the events that set it.

mod common;

use atlas_duck_audit::error::AuditError;
use atlas_duck_audit::testing::MemKeyring;
use atlas_duck_audit::types::{Confirmed, EventType};
use atlas_duck_audit::{
    FilePolicy, InstancePolicy, OpenConfig, PruneOutcome, PruneSkip, SettingChange, Settings,
    StartupOutcome, Store, open,
};
use common::*;
use serde_json::{Value, json};

fn confirmed() -> Confirmed {
    Confirmed {
        dialog_text_sha256: [7; 32],
    }
}

/// A corroborated store (`synchronous=NORMAL`), the config file not reconciled yet.
fn corroborated() -> (Store, Fixture) {
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |cfg| {
        cfg.hooks.synchronous_normal = true;
    });
    corroborate_now(&store, &f.clock);
    (store, f)
}

fn reconciled() -> (Store, Fixture) {
    let (store, f) = corroborated();
    store
        .reconcile_config_file(&FilePolicy::default())
        .expect("reconcile");
    (store, f)
}

fn payload(store: &Store, seq: u64) -> Value {
    serde_json::from_slice(&store.read_payload(seq).expect("read_payload")).expect("json")
}

/// Seqs of every retained row of `event_type`.
fn seqs(f: &Fixture, event_type: EventType) -> Vec<u64> {
    let c = raw_conn(f);
    let mut st = c
        .prepare("SELECT seq FROM events WHERE event_type = ?1 ORDER BY seq")
        .expect("prepare");
    st.query_map([event_type.as_str()], |r| r.get::<_, i64>(0))
        .expect("query")
        .map(|s| s.expect("seq") as u64)
        .collect()
}

fn head_seq(store: &Store) -> u64 {
    store.head().0
}

fn config(f: &Fixture) -> OpenConfig {
    let mut cfg = f.config();
    cfg.hooks.synchronous_normal = true;
    cfg
}

fn reopen(store: &Store, f: &Fixture) -> Store {
    store.shutdown();
    match open(&f.data, &f.lock, config(f)).expect("open") {
        StartupOutcome::Ready { store, .. } => {
            assert!(!store.health().settings_unreadable);
            store
        }
        other => panic!("not ready: {other:?}"),
    }
}

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

fn origin(id: &str, v: Option<&str>) -> SettingChange {
    SettingChange::InstanceOrigin {
        instance_id: id.into(),
        origin: v.map(str::to_string),
    }
}

fn ca(id: &str, v: Option<&str>) -> SettingChange {
    SettingChange::InstanceCaFingerprint {
        instance_id: id.into(),
        fingerprint: v.map(str::to_string),
    }
}

fn proxy(id: &str, v: Option<&str>) -> SettingChange {
    SettingChange::InstanceProxy {
        instance_id: id.into(),
        proxy: v.map(str::to_string),
    }
}

/// `apply_setting` without a confirmation must refuse and log nothing.
fn needs_confirmation(store: &Store, change: SettingChange, what: &str) {
    let before = head_seq(store);
    assert_eq!(
        store.apply_setting(change, None).unwrap_err(),
        AuditError::NeedsConfirmation(what.to_string().leak())
    );
    assert_eq!(head_seq(store), before, "nothing is logged");
}

#[test]
fn defaults() {
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    let v = store.settings();
    assert_eq!(v.retention_days, 100);
    assert!(!v.legal_hold);
    assert_eq!(v.anchor_dir, None);
    assert!(v.instances.is_empty());
    assert_eq!(v, Settings::default());
}

#[test]
fn settings_json_round_trip_and_strictness() {
    let mut v = Settings {
        retention_days: 150,
        legal_hold: true,
        anchor_dir: s("D:/anchors"),
        ..Settings::default()
    };
    v.instances.insert(
        "i1".into(),
        InstancePolicy {
            origin: s("https://jira.example"),
            ca_fingerprint: None,
            proxy: s("direct"),
        },
    );
    assert_eq!(Settings::from_json(&v.to_json()).expect("round trip"), v);
    // An instance without any value is not part of the view.
    let mut j = v.to_json();
    j["instances"]["i2"] = json!({"origin": null, "ca_fingerprint": null, "proxy": null});
    assert_eq!(Settings::from_json(&j).expect("empty instance"), v);
    // Missing key, retention below the minimum, wrong types: refused.
    for bad in [
        json!({"retention_days": 92, "legal_hold": false}),
        json!({"anchor_dir": null, "instances": {}, "legal_hold": false, "retention_days": 91}),
        json!({"anchor_dir": 5, "instances": {}, "legal_hold": false, "retention_days": 100}),
        json!({"anchor_dir": null, "instances": {}, "legal_hold": "no", "retention_days": 100}),
        json!({"anchor_dir": null, "instances": {"i": {"origin": null}}, "legal_hold": false, "retention_days": 100}),
        json!([]),
    ] {
        assert!(Settings::from_json(&bad).is_err(), "{bad}");
    }
}

#[test]
fn x01_file_below_minimum_raised_and_logged() {
    let (store, f) = corroborated();
    // Corroborated, config file not reconciled: the queued attempt waits, nothing is pruned.
    for _ in 0..105 {
        day(&store, &f.clock, 1);
    }
    assert!(seqs(&f, EventType::PRUNE).is_empty());

    let rows = store
        .reconcile_config_file(&FilePolicy {
            retention_days: Some(50),
            ..FilePolicy::default()
        })
        .expect("reconcile");
    assert_eq!(rows.len(), 1);
    let cc = rows[0].seq;
    assert_eq!(
        payload(&store, cc),
        json!({
            "source": "file", "key": "retention_days", "old": 100, "requested": 50,
            "new": 92, "applied": false, "confirmed": null,
        })
    );
    assert_eq!(store.settings().retention_days, 100);

    // The prune that was queued behind the unreconciled file runs after the CONFIG_CHANGED.
    sync_writer(&store);
    let prunes = seqs(&f, EventType::PRUNE);
    assert!(!prunes.is_empty(), "the queued attempt ran");
    assert!(
        prunes[0] > cc,
        "CONFIG_CHANGED {cc} before PRUNE {}",
        prunes[0]
    );

    let rows = store
        .reconcile_config_file(&FilePolicy {
            retention_days: Some(150),
            ..FilePolicy::default()
        })
        .expect("reconcile");
    assert_eq!(rows.len(), 1);
    let p = payload(&store, rows[0].seq);
    assert_eq!(p["applied"], json!(true));
    assert_eq!(p["new"], json!(150));
    assert_eq!(p["requested"], json!(150));
    assert_eq!(store.settings().retention_days, 150);

    // Nothing differs now: nothing is logged.
    let head = head_seq(&store);
    let rows = store
        .reconcile_config_file(&FilePolicy {
            retention_days: Some(150),
            ..FilePolicy::default()
        })
        .expect("reconcile");
    assert!(rows.is_empty());
    assert_eq!(head_seq(&store), head);
    // A lowering the clamp hides is still logged: the file asked for 50, 92 is in force.
    let (store, _f) = reconciled();
    store
        .apply_setting(SettingChange::RetentionDays(92), Some(confirmed()))
        .expect("92");
    let rows = store
        .reconcile_config_file(&FilePolicy {
            retention_days: Some(50),
            ..FilePolicy::default()
        })
        .expect("reconcile");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        payload(&store, rows[0].seq),
        json!({
            "source": "file", "key": "retention_days", "old": 92, "requested": 50,
            "new": 92, "applied": false, "confirmed": null,
        })
    );
    assert_eq!(store.settings().retention_days, 92);
}

#[test]
fn x01_prune_waits_for_reconcile() {
    let (store, f) = corroborated();
    store.append_batch(day_events(2)).expect("append");
    sync_writer(&store);
    assert_eq!(
        store.prune(None).expect("prune"),
        PruneOutcome::Skipped(PruneSkip::ConfigNotReconciled)
    );
    assert_eq!(
        store.prune(Some(confirmed())).expect("prune"),
        PruneOutcome::Skipped(PruneSkip::ConfigNotReconciled)
    );
    store
        .reconcile_config_file(&FilePolicy::default())
        .expect("reconcile");
    assert!(!matches!(
        store.prune(None).expect("prune"),
        PruneOutcome::Skipped(PruneSkip::ConfigNotReconciled)
    ));
    assert!(seqs(&f, EventType::CONFIG_CHANGED).is_empty());
}

#[test]
fn x02_lift_legal_hold_needs_confirmation() {
    let (store, f) = reconciled();
    let c = store
        .apply_setting(SettingChange::LegalHold(true), None)
        .expect("set");
    assert_eq!(
        payload(&store, c.seq),
        json!({"source": "app", "old": false, "new": true, "applied": true, "confirmed": null})
    );
    assert_eq!(seqs(&f, EventType::LEGAL_HOLD_CHANGED), vec![c.seq]);
    assert!(store.settings().legal_hold);

    // The file cannot lift it: logged, not applied.
    let rows = store
        .reconcile_config_file(&FilePolicy {
            legal_hold: Some(false),
            ..FilePolicy::default()
        })
        .expect("reconcile");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        payload(&store, rows[0].seq),
        json!({"source": "file", "old": true, "new": false, "applied": false, "confirmed": null})
    );
    assert!(store.settings().legal_hold);

    needs_confirmation(&store, SettingChange::LegalHold(false), "legal_hold");
    assert!(store.settings().legal_hold);

    let c = store
        .apply_setting(SettingChange::LegalHold(false), Some(confirmed()))
        .expect("lift");
    assert_eq!(
        payload(&store, c.seq),
        json!({
            "source": "app", "old": true, "new": false, "applied": true,
            "confirmed": {"dialog_text_sha256": "07".repeat(32)},
        })
    );
    assert!(!store.settings().legal_hold);

    // The file may set it.
    let rows = store
        .reconcile_config_file(&FilePolicy {
            legal_hold: Some(true),
            ..FilePolicy::default()
        })
        .expect("reconcile");
    assert_eq!(rows.len(), 1);
    assert_eq!(payload(&store, rows[0].seq)["applied"], json!(true));
    assert!(store.settings().legal_hold);
}

#[test]
fn legal_hold_pauses_prune_through_the_view() {
    let (store, f) = reconciled();
    store
        .apply_setting(SettingChange::LegalHold(true), None)
        .expect("set");
    for _ in 0..105 {
        day(&store, &f.clock, 1);
    }
    assert!(seqs(&f, EventType::PRUNE).is_empty());
    assert_eq!(
        store.prune(None).expect("prune"),
        PruneOutcome::Skipped(PruneSkip::LegalHold)
    );
    store
        .apply_setting(SettingChange::LegalHold(false), Some(confirmed()))
        .expect("lift");
    day(&store, &f.clock, 1);
    assert!(!seqs(&f, EventType::PRUNE).is_empty());
}

#[test]
fn lower_retention_needs_confirmation() {
    let (store, _f) = reconciled();
    // Raising is plain.
    let c = store
        .apply_setting(SettingChange::RetentionDays(150), None)
        .expect("raise");
    assert_eq!(
        payload(&store, c.seq),
        json!({
            "source": "app", "key": "retention_days", "old": 100, "requested": 150,
            "new": 150, "applied": true, "confirmed": null,
        })
    );
    assert_eq!(store.settings().retention_days, 150);
    needs_confirmation(&store, SettingChange::RetentionDays(120), "retention_days");
    assert_eq!(store.settings().retention_days, 150);
    let c = store
        .apply_setting(SettingChange::RetentionDays(120), Some(confirmed()))
        .expect("lower");
    assert_eq!(store.settings().retention_days, 120);
    assert_eq!(
        payload(&store, c.seq)["confirmed"],
        json!({"dialog_text_sha256": "07".repeat(32)})
    );
}

#[test]
fn retention_below_92_invalid() {
    let (store, _f) = reconciled();
    let before = head_seq(&store);
    for confirm in [None, Some(confirmed())] {
        assert!(matches!(
            store.apply_setting(SettingChange::RetentionDays(91), confirm),
            Err(AuditError::Invalid(_))
        ));
    }
    assert_eq!(head_seq(&store), before);
    assert_eq!(store.settings().retention_days, 100);
    store
        .apply_setting(SettingChange::RetentionDays(92), Some(confirmed()))
        .expect("the minimum itself is fine");
    assert_eq!(store.settings().retention_days, 92);
}

#[test]
fn unchanged_value_is_invalid_and_logs_nothing() {
    let (store, _f) = reconciled();
    let before = head_seq(&store);
    for change in [
        SettingChange::RetentionDays(100),
        SettingChange::LegalHold(false),
        SettingChange::AnchorDir(None),
        origin("i1", None),
        proxy("i1", None),
        SettingChange::AnchorDir(s("")),
        origin("", s("https://x").as_deref()),
    ] {
        assert!(
            matches!(
                store.apply_setting(change.clone(), Some(confirmed())),
                Err(AuditError::Invalid(_))
            ),
            "{change:?}"
        );
    }
    assert_eq!(head_seq(&store), before);
}

#[test]
fn anchor_dir_change_needs_confirmation() {
    let (store, _f) = reconciled();
    needs_confirmation(&store, SettingChange::AnchorDir(s("D:/a")), "anchor_dir");
    assert_eq!(store.settings().anchor_dir, None);
    let c = store
        .apply_setting(SettingChange::AnchorDir(s("D:/a")), Some(confirmed()))
        .expect("set");
    assert_eq!(payload(&store, c.seq)["key"], json!("anchor_dir"),);
    assert_eq!(store.settings().anchor_dir, s("D:/a"));
    needs_confirmation(&store, SettingChange::AnchorDir(s("D:/b")), "anchor_dir");
    needs_confirmation(&store, SettingChange::AnchorDir(None), "anchor_dir");
    store
        .apply_setting(SettingChange::AnchorDir(None), Some(confirmed()))
        .expect("remove");
    assert_eq!(store.settings().anchor_dir, None);
}

#[test]
fn file_never_touches_the_anchor_dir() {
    let (store, _f) = reconciled();
    let rows = store
        .reconcile_config_file(&FilePolicy {
            anchor_dir: Some(s("D:/file")),
            ..FilePolicy::default()
        })
        .expect("reconcile");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        payload(&store, rows[0].seq),
        json!({
            "source": "file", "key": "anchor_dir", "old": null, "requested": "D:/file",
            "new": "D:/file", "applied": false, "confirmed": null,
        })
    );
    assert_eq!(store.settings().anchor_dir, None);
    // `Some(None)` against no anchor directory is no difference.
    let rows = store
        .reconcile_config_file(&FilePolicy {
            anchor_dir: Some(None),
            ..FilePolicy::default()
        })
        .expect("reconcile");
    assert!(rows.is_empty());
}

#[test]
fn instance_origin_needs_confirmation() {
    let (store, f) = reconciled();
    needs_confirmation(
        &store,
        origin("i1", Some("https://a.example")),
        "instance_origin",
    );
    assert!(store.settings().instances.is_empty());
    let c = store
        .apply_setting(origin("i1", Some("https://a.example")), Some(confirmed()))
        .expect("add");
    assert_eq!(payload(&store, c.seq)["key"], json!("instance.i1.origin"));
    assert_eq!(
        store.settings().instances["i1"].origin,
        s("https://a.example")
    );
    // The row names the instance (never an alias).
    let seq = seqs(&f, EventType::CONFIG_CHANGED).pop().expect("row");
    let id: Option<String> = raw_conn(&f)
        .query_row(
            "SELECT instance_id FROM events WHERE seq = ?1",
            [seq as i64],
            |r| r.get(0),
        )
        .expect("instance_id");
    assert_eq!(id, s("i1"));

    needs_confirmation(
        &store,
        origin("i1", Some("https://b.example")),
        "instance_origin",
    );
    needs_confirmation(&store, origin("i1", None), "instance_origin");
    store
        .apply_setting(origin("i1", None), Some(confirmed()))
        .expect("remove");
    assert!(store.settings().instances.is_empty());
}

#[test]
fn ca_fingerprint_add_needs_confirmation_remove_does_not() {
    let (store, _f) = reconciled();
    needs_confirmation(&store, ca("i1", Some("ab:cd")), "instance_ca_fingerprint");
    store
        .apply_setting(ca("i1", Some("ab:cd")), Some(confirmed()))
        .expect("add");
    assert_eq!(store.settings().instances["i1"].ca_fingerprint, s("ab:cd"));
    needs_confirmation(&store, ca("i1", Some("ef:01")), "instance_ca_fingerprint");
    store
        .apply_setting(ca("i1", None), None)
        .expect("removing is plain");
    assert!(store.settings().instances.is_empty());
}

#[test]
fn proxy_change_plain() {
    let (store, _f) = reconciled();
    store
        .apply_setting(proxy("i1", Some("direct")), None)
        .expect("direct");
    assert_eq!(store.settings().instances["i1"].proxy, s("direct"));
    store
        .apply_setting(proxy("i1", Some("proxy.example:3128")), None)
        .expect("explicit");
    assert_eq!(
        store.settings().instances["i1"].proxy,
        s("proxy.example:3128")
    );
    store.apply_setting(proxy("i1", None), None).expect("none");
    assert!(store.settings().instances.is_empty());
}

#[test]
fn instance_ids_with_dots_stay_distinct() {
    let (store, _f) = reconciled();
    store
        .apply_setting(proxy("a.origin", Some("direct")), None)
        .expect("set");
    store
        .apply_setting(origin("a", Some("https://a.example")), Some(confirmed()))
        .expect("set");
    let v = store.settings();
    assert_eq!(v.instances["a.origin"].proxy, s("direct"));
    assert_eq!(v.instances["a.origin"].origin, None);
    assert_eq!(v.instances["a"].origin, s("https://a.example"));
}

#[test]
fn settings_survive_restart_without_a_prune() {
    let (store, f) = reconciled();
    store
        .apply_setting(SettingChange::RetentionDays(150), None)
        .expect("retention");
    store
        .apply_setting(SettingChange::LegalHold(true), None)
        .expect("hold");
    store
        .apply_setting(origin("i1", Some("https://a.example")), Some(confirmed()))
        .expect("origin");
    store
        .apply_setting(proxy("i1", Some("direct")), None)
        .expect("proxy");
    let before = store.settings();
    let store = reopen(&store, &f);
    assert_eq!(store.settings(), before);
    assert_eq!(before.retention_days, 150);
    assert!(before.legal_hold);
}

#[test]
fn settings_survive_prune_of_their_events() {
    let (store, f) = reconciled();
    store
        .apply_setting(SettingChange::RetentionDays(150), None)
        .expect("retention");
    store
        .apply_setting(SettingChange::LegalHold(true), None)
        .expect("hold");
    store
        .apply_setting(SettingChange::LegalHold(false), Some(confirmed()))
        .expect("lift");
    store
        .apply_setting(origin("i1", Some("https://a.example")), Some(confirmed()))
        .expect("origin");
    store
        .apply_setting(proxy("i1", Some("direct")), None)
        .expect("proxy");
    let early: Vec<u64> = [EventType::CONFIG_CHANGED, EventType::LEGAL_HOLD_CHANGED]
        .into_iter()
        .flat_map(|t| seqs(&f, t))
        .collect();
    assert_eq!(early.len(), 5);
    let want = store.settings();

    for _ in 0..400 {
        day(&store, &f.clock, 1);
    }
    assert!(!seqs(&f, EventType::PRUNE).is_empty());
    let left: Vec<u64> = [EventType::CONFIG_CHANGED, EventType::LEGAL_HOLD_CHANGED]
        .into_iter()
        .flat_map(|t| seqs(&f, t))
        .collect();
    assert!(
        left.is_empty(),
        "every early settings row is pruned: {left:?}"
    );
    assert_eq!(store.settings(), want);

    let store = reopen(&store, &f);
    assert_eq!(store.settings(), want);
    assert_eq!(store.settings().retention_days, 150);
    assert_eq!(
        store.settings().instances["i1"].origin,
        s("https://a.example")
    );
    assert!(store.full_verify().is_empty());
}

#[test]
fn later_events_overlay_the_prune_snapshot() {
    let (store, f) = reconciled();
    store
        .apply_setting(SettingChange::RetentionDays(150), None)
        .expect("retention");
    for _ in 0..160 {
        day(&store, &f.clock, 1);
    }
    assert!(!seqs(&f, EventType::PRUNE).is_empty());
    // Changed after the latest PRUNE: the snapshot says 150, the later row wins.
    store
        .apply_setting(SettingChange::LegalHold(true), None)
        .expect("hold");
    store
        .apply_setting(SettingChange::RetentionDays(200), None)
        .expect("retention");
    let want = store.settings();
    assert_eq!((want.retention_days, want.legal_hold), (200, true));
    assert_eq!(reopen(&store, &f).settings(), want);
}

#[test]
fn non_policy_config_changed_ignored() {
    let (store, f) = reconciled();
    for key in [
        "attention_mode",
        "retention",
        "legal_hold",
        "instance.i1",
        "instance..origin",
    ] {
        store
            .append(ev(
                EventType::CONFIG_CHANGED,
                None,
                json!({"source": "app", "key": key, "old": 1, "new": 500, "applied": true}),
            ))
            .expect("appendable");
    }
    // No `key` at all.
    store
        .append(ev(
            EventType::CONFIG_CHANGED,
            None,
            json!({"new": 500, "applied": true}),
        ))
        .expect("appendable");
    assert_eq!(store.settings(), Settings::default());
    assert_eq!(reopen(&store, &f).settings(), Settings::default());
}

#[test]
fn odd_config_changed_payloads_never_poison_the_view() {
    let (store, f) = reconciled();
    for payload in [
        json!(null),
        json!([1]),
        json!("x"),
        json!(7),
        json!({"key": 5}),
    ] {
        store
            .append(ev(EventType::CONFIG_CHANGED, None, payload))
            .expect("appendable");
    }
    let store = reopen(&store, &f);
    assert!(!store.health().settings_unreadable);
    assert_eq!(store.settings(), Settings::default());
    store
        .reconcile_config_file(&FilePolicy::default())
        .expect("reconcile");
    store
        .apply_setting(SettingChange::RetentionDays(150), None)
        .expect("apply");
    assert_eq!(store.settings().retention_days, 150);
}

#[test]
fn file_difference_records_are_appendable_but_never_applied() {
    let (store, f) = reconciled();
    // Spec §7.1: a file value that differs from the stored instance policy is logged, not applied.
    for key in ["retention_days", "instance.i1.origin", "instance.i1.proxy"] {
        store
            .append(ev(
                EventType::CONFIG_CHANGED,
                None,
                json!({"source": "file", "key": key, "old": null, "new": "x", "applied": false}),
            ))
            .expect("a not-applied file record");
    }
    // Any other combination that could change state stays refused.
    for p in [
        json!({"source": "file", "key": "anchor_dir", "new": "x", "applied": true}),
        json!({"source": "app", "key": "anchor_dir", "new": "x", "applied": false}),
        json!({"source": "file", "key": "anchor_dir", "new": "x"}),
        json!({"source": "file", "key": "anchor_dir", "new": "x", "applied": "false"}),
    ] {
        assert!(
            matches!(
                store.append(ev(EventType::CONFIG_CHANGED, None, p.clone())),
                Err(AuditError::Invalid(_))
            ),
            "{p}"
        );
    }
    assert_eq!(store.settings(), Settings::default());
    let store = reopen(&store, &f);
    assert_eq!(store.settings(), Settings::default());
}

#[test]
fn policy_key_cannot_be_appended() {
    let (store, f) = reconciled();
    let before = head_seq(&store);
    for key in [
        "retention_days",
        "anchor_dir",
        "instance.i1.origin",
        "instance.i1.ca_fingerprint",
        "instance.i1.proxy",
    ] {
        assert!(
            matches!(
                store.append(ev(
                    EventType::CONFIG_CHANGED,
                    None,
                    json!({"source": "app", "key": key, "old": null, "new": 500, "applied": true}),
                )),
                Err(AuditError::Invalid(_))
            ),
            "{key}"
        );
    }
    assert_eq!(head_seq(&store), before);
    assert!(seqs(&f, EventType::CONFIG_CHANGED).is_empty());
    // Nor can the legal hold event (it was store-owned already).
    assert!(matches!(
        store.append(ev(
            EventType::LEGAL_HOLD_CHANGED,
            None,
            json!({"source": "app", "old": false, "new": true, "applied": true}),
        )),
        Err(AuditError::Invalid(_))
    ));
}

#[test]
fn unreadable_settings_row_blocks_prune_and_changes() {
    let (store, f) = reconciled();
    store
        .apply_setting(origin("i1", Some("https://a.example")), Some(confirmed()))
        .expect("origin");
    let c = store
        .apply_setting(SettingChange::LegalHold(true), None)
        .expect("hold");
    store.shutdown();
    // Damage the legal hold row's ciphertext: its payload no longer decrypts.
    raw_conn(&f)
        .execute(
            "UPDATE events SET payload_ct = zeroblob(length(payload_ct)) WHERE seq = ?1",
            [c.seq as i64],
        )
        .expect("tamper");
    let store = match open(&f.data, &f.lock, config(&f)) {
        Ok(StartupOutcome::Ready { store, .. }) => store,
        other => panic!("not ready: {other:?}"),
    };
    assert!(store.health().settings_unreadable);
    // Instance policy is withheld while the view is untrusted: nothing counts as confirmed.
    assert!(store.settings().instances.is_empty());
    assert!(store.prune(None).is_err());
    assert!(
        store
            .apply_setting(SettingChange::RetentionDays(150), None)
            .is_err()
    );
    assert!(store.reconcile_config_file(&FilePolicy::default()).is_err());
}
