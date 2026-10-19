//! Recovery-tier store APIs (M10 Task 9; §8.6, §8.7, PD-169, PD-170, L116): the recovery
//! passphrase change (its `recovery` row and `CREDENTIAL_CHANGED` in one transaction), re-anchor
//! (an integrity incident, offered only while an anchor entry is missing outside an interrupted
//! restore) and "forget old install" over the installs only an archived store names. Every test
//! runs on `MemKeyStore`; `recovery_tier_os.rs` repeats three of them on the real keychain.

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_duck_audit::anchors::{BarrierKind, FirstRetainedAnchor, HeadAnchor};
use atlas_duck_audit::crypto::Kek;
use atlas_duck_audit::encoding::ZERO_HASH;
use atlas_duck_audit::error::{AuditError, OpenError, RestoreError};
use atlas_duck_audit::keystore::{EntryName, KeyStore, KeyStoreError, service_name};
use atlas_duck_audit::recovery::open_recovery;
use atlas_duck_audit::testing::{self, FaultPoint, Faults, KeyOpKind, MemKeyStore, MemKeyring};
use atlas_duck_audit::types::{Confirmed, EventFlags, EventType, RustChosenPath};
use atlas_duck_audit::{
    ArchivedDb, FindingKind, LockedReason, MissingAnchor, OpenConfig, PASSPHRASE_MISMATCH,
    PASSPHRASE_TOO_SHORT, StartupOutcome, Store, VerifyFinding, VerifyOutcome,
    archive_and_start_fresh, create_new_store, forget_install, new_ids, open, orphan_installs,
    recover_this_log, restore_from_source,
};
use common::*;
use secrecy::SecretString;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------------------
// helpers

/// 26 characters: a passphrase other than the fixture's.
const NEW_PASS: &str = "a new recovery passphrase";

fn pass(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn confirmed() -> Confirmed {
    Confirmed {
        dialog_text_sha256: [7; 32],
    }
}

fn chosen(p: &Path) -> RustChosenPath {
    RustChosenPath::from_native_dialog(p.to_path_buf())
}

fn payload(store: &Store, seq: u64) -> Value {
    serde_json::from_slice(&store.read_payload(seq).expect("read_payload")).expect("json")
}

fn raw(ring: &MemKeyring, install_id: &str, account: &str) -> Option<Vec<u8>> {
    ring.raw_get(&service_name(install_id), account)
}

fn keychain_head(ring: &MemKeyring, install_id: &str) -> Option<HeadAnchor> {
    raw(ring, install_id, "head_anchor").map(|b| HeadAnchor::from_entry(&b).expect("head anchor"))
}

fn keychain_first_retained(ring: &MemKeyring, install_id: &str) -> Option<FirstRetainedAnchor> {
    raw(ring, install_id, "first_retained_anchor")
        .map(|b| FirstRetainedAnchor::from_entry(&b).expect("first-retained anchor"))
}

fn recovery_blob(f: &Fixture) -> Vec<u8> {
    raw_conn(f)
        .query_row("SELECT blob FROM recovery WHERE id = 1", [], |r| r.get(0))
        .expect("recovery row")
}

fn ready(o: StartupOutcome) -> (Store, VerifyOutcome) {
    match o {
        StartupOutcome::Ready { store, verify, .. } => (store, verify),
        other => panic!("expected Ready, got {other:?}"),
    }
}

fn kinds(f: &[VerifyFinding]) -> Vec<FindingKind> {
    f.iter().map(|x| x.kind).collect()
}

fn rows_of(f: &Fixture, t: EventType) -> Vec<RawRow> {
    dump_rows(f)
        .into_iter()
        .filter(|r| r.event_type == t.as_str())
        .collect()
}

/// `VERIFY` rows whose payload `result` is `result`.
fn verify_results(store: &Store, f: &Fixture, result: &str) -> Vec<u64> {
    rows_of(f, EventType::VERIFY)
        .into_iter()
        .filter(|r| payload(store, r.seq)["result"] == result)
        .map(|r| r.seq)
        .collect()
}

/// Polls `cond` for up to 10 s (the anchor thread retries in the background).
fn wait_for(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A record naming instance `id` in its plaintext `instance_id` column.
fn instance_event(id: &str) -> atlas_duck_audit::types::NewEvent {
    let mut e = ev(EventType::READ_FETCHED, Some("r1"), json!({ "body": id }));
    e.instance_id = Some(id.to_string());
    e
}

/// Install A ran a store with instances `i1` and `i2` and a PAT entry for each; the store was
/// archived ("Archive old DB and start fresh") and install B started fresh beside it, with
/// another passphrase. Returns B's live store, the fixture (its `install_id` is A's), B's install
/// id and keystore, and the archive.
struct TwoInstalls {
    live: Store,
    f: Fixture,
    b_id: String,
    b_keys: Arc<MemKeyStore>,
    archived: ArchivedDb,
}

const B_PASS: &str = "install b recovery passphrase";

fn two_installs() -> TwoInstalls {
    let (a, f) = new_store(fake_clock(START), MemKeyring::new());
    a.append_batch(vec![instance_event("i1"), instance_event("i2")])
        .expect("append");
    a.append_batch(mixed(5)).expect("append");
    for id in ["i1", "i2"] {
        f.keys()
            .set(&EntryName::Pat(id.into()), b"token")
            .expect("pat");
    }
    a.flush_head_anchor().expect("flush");
    a.shutdown();
    let archived = archive_and_start_fresh(&f.data, &f.lock, confirmed()).expect("archive");

    let (b_id, b_chain) = new_ids().expect("ids");
    let b_keys = Arc::new(MemKeyStore::new(f.ring.clone(), &b_id));
    let mut inp = input(&b_id, &b_chain, B_PASS, B_PASS);
    inp.archived_db = Some(archived.clone());
    inp.archive_confirmed = Some(confirmed());
    let live = create_new_store(
        &f.data,
        &f.lock,
        OpenConfig::new(f.clock.clone(), b_keys.clone()),
        inp,
    )
    .expect("install B");
    live.append_batch(vec![instance_event("i9")])
        .expect("append");
    b_keys
        .set(&EntryName::Pat("i9".into()), b"b token")
        .expect("pat");
    live.flush_head_anchor().expect("flush");
    TwoInstalls {
        live,
        f,
        b_id,
        b_keys,
        archived,
    }
}

const ANCHOR_ACCOUNTS: [&str; 3] = ["kek", "head_anchor", "first_retained_anchor"];

// ---------------------------------------------------------------------------------------
// Recovery-passphrase change (§8.6, PD-169)

#[test]
fn change_recovery_passphrase_rewraps_and_logs() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(6)).expect("append");
    let kek_entry = raw(&f.ring, &f.install_id, "kek").expect("kek");
    let kek = Kek::from_entry_bytes(&kek_entry).expect("kek entry");
    let before = recovery_blob(&f);
    let (head, _, _) = store.head();

    let c = store
        .change_recovery_passphrase(&pass(NEW_PASS), &pass(NEW_PASS))
        .expect("change");
    assert_eq!(c.seq, head + 1);
    assert_eq!(store.head().0, c.seq);
    let changed = rows_of(&f, EventType::CREDENTIAL_CHANGED);
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].seq, c.seq);
    assert_eq!(changed[0].record_hash, c.record_hash);
    assert_eq!(
        payload(&store, c.seq),
        json!({ "change": "recovery_passphrase" })
    );

    // Re-wrapped: the same KEK under the new passphrase only; layout 1 kept.
    let after = recovery_blob(&f);
    assert_ne!(after, before);
    assert_eq!((after.len(), after[0]), (before.len(), before[0]));
    assert!(open_recovery(&pass(NEW_PASS), &after).expect("new passphrase") == kek);
    assert!(open_recovery(&pass(PASSPHRASE), &after).is_err());
    // The keychain KEK is untouched, and the chain verifies.
    assert_eq!(
        raw(&f.ring, &f.install_id, "kek").as_deref(),
        Some(kek_entry.as_slice())
    );
    assert_eq!(store.full_verify(), vec![]);

    // A backup taken afterwards carries the new blob.
    let out = tempfile::tempdir().expect("out dir");
    let receipt = store.backup(chosen(out.path())).expect("backup");
    let bin = std::fs::read(receipt.bundle_dir.join("recovery.bin")).expect("recovery.bin");
    assert_eq!(bin, after);
}

#[test]
fn second_entry_mismatch_commits_nothing() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(3)).expect("append");
    let head = store.head();
    let blob = recovery_blob(&f);

    assert_eq!(
        store.change_recovery_passphrase(&pass(NEW_PASS), &pass("a new recovery passphrasf")),
        Err(AuditError::Invalid(PASSPHRASE_MISMATCH))
    );
    assert_eq!(
        store.change_recovery_passphrase(&pass("too short"), &pass("too short")),
        Err(AuditError::Invalid(PASSPHRASE_TOO_SHORT))
    );
    assert_eq!(store.head(), head);
    assert_eq!(recovery_blob(&f), blob);
    assert!(rows_of(&f, EventType::CREDENTIAL_CHANGED).is_empty());

    // The entries are compared after NFC (§8.6): composed and decomposed é are one passphrase.
    store
        .change_recovery_passphrase(
            &pass("caf\u{e9} recovery passphrase"),
            &pass("cafe\u{301} recovery passphrase"),
        )
        .expect("NFC-equal entries");
}

#[test]
fn old_passphrase_no_longer_recovers_new_one_does() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(4)).expect("append");
    store
        .change_recovery_passphrase(&pass(NEW_PASS), &pass(NEW_PASS))
        .expect("change");
    store.flush_head_anchor().expect("flush");
    store.shutdown();

    // The keychain KEK is lost.
    f.keys().delete(&EntryName::Kek).expect("delete kek");
    match open(&f.data, &f.lock, f.config()).expect("open") {
        StartupOutcome::Locked(LockedReason::KeychainLost { .. }) => {}
        other => panic!("expected keychain_lost, got {other:?}"),
    }
    assert!(matches!(
        recover_this_log(&f.data, &f.lock, f.config(), &pass(PASSPHRASE)),
        Err(OpenError::WrongPassphrase)
    ));
    assert_eq!(raw(&f.ring, &f.install_id, "kek"), None);
    let (s, report) =
        recover_this_log(&f.data, &f.lock, f.config(), &pass(NEW_PASS)).expect("recover");
    assert!(report.verify_seq > 0);
    assert!(raw(&f.ring, &f.install_id, "kek").is_some());
    s.shutdown();
}

#[test]
fn passphrase_change_row_and_record_in_one_transaction() {
    let faults = Faults::new();
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |cfg| {
        cfg.hooks.faults = Some(faults.clone());
    });
    store.append_batch(mixed(3)).expect("append");
    let head = store.head();
    let blob = recovery_blob(&f);

    // A failure between the recovery row and the record commits neither.
    faults.fail(FaultPoint::RecoveryRowWritten, 1);
    store
        .change_recovery_passphrase(&pass(NEW_PASS), &pass(NEW_PASS))
        .expect_err("injected fault");
    assert_eq!(store.head(), head);
    assert_eq!(recovery_blob(&f), blob);
    assert!(rows_of(&f, EventType::CREDENTIAL_CHANGED).is_empty());

    // The store goes on, and a retry commits both.
    let c = store
        .change_recovery_passphrase(&pass(NEW_PASS), &pass(NEW_PASS))
        .expect("retry");
    assert_eq!(c.seq, head.0 + 1);
    assert!(open_recovery(&pass(NEW_PASS), &recovery_blob(&f)).is_ok());
    assert_eq!(rows_of(&f, EventType::CREDENTIAL_CHANGED).len(), 1);
    assert_eq!(store.full_verify(), vec![]);
}

/// Resumes a paused writer when dropped, so a failing assertion never leaves it blocked (the
/// fixture's shutdown would wait for it).
struct Resume(Arc<Faults>);

impl Drop for Resume {
    fn drop(&mut self) {
        self.0.resume_writer();
    }
}

#[test]
fn passphrase_change_prepared_before_a_restore_is_refused() {
    let faults = Faults::new();
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |cfg| {
        cfg.hooks.faults = Some(faults.clone());
    });
    let head = store.head();
    let blob = recovery_blob(&f);

    // The blob is sealed on the caller's thread; the writer takes the command only after a
    // restore replaced the store (simulated: the generation a restore commit bumps).
    let resume = Resume(faults.clone());
    faults.pause_writer();
    let s2 = store.clone();
    let change =
        std::thread::spawn(move || s2.change_recovery_passphrase(&pass(NEW_PASS), &pass(NEW_PASS)));
    assert!(
        faults.wait_writer_paused(Duration::from_secs(60)),
        "the change never reached the writer"
    );
    store.testing_bump_generation();
    drop(resume);
    let r = change.join().expect("change thread");
    assert!(matches!(r, Err(AuditError::Invalid(_))), "{r:?}");
    assert_eq!(store.head(), head);
    assert_eq!(recovery_blob(&f), blob);
    assert!(rows_of(&f, EventType::CREDENTIAL_CHANGED).is_empty());
}

#[test]
fn append_refuses_the_recovery_passphrase_change_only() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let head = store.head();
    assert!(matches!(
        store.append(ev(
            EventType::CREDENTIAL_CHANGED,
            None,
            json!({ "change": "recovery_passphrase" })
        )),
        Err(AuditError::Invalid(_))
    ));
    assert_eq!(store.head(), head);
    // CREDENTIAL_CHANGED stays appendable for its other changes (M3, writer.rs).
    store
        .append(ev(
            EventType::CREDENTIAL_CHANGED,
            None,
            json!({ "change": "added", "new_user_key": "u1" }),
        ))
        .expect("a token change");
    assert_eq!(rows_of(&f, EventType::CREDENTIAL_CHANGED).len(), 1);
}

// ---------------------------------------------------------------------------------------
// Re-anchor (§8.7, PD-170, M2 handoff T15)

#[test]
fn re_anchor_logs_incident_and_rewrites() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(8)).expect("append");
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    // The first-retained entry is deleted (a user, a keychain cleanup): only prune writes it.
    f.keys()
        .delete(&EntryName::FirstRetainedAnchor)
        .expect("delete");

    let (s, v) = ready(open(&f.data, &f.lock, f.config()).expect("open"));
    assert!(kinds(&v.findings).contains(&FindingKind::AnchorMissing));
    let startup = v.verify_seq.expect("startup VERIFY");
    assert_eq!(
        s.health().anchors_missing,
        Some(MissingAnchor::FirstRetained)
    );
    let genesis = dump_rows(&f)[0].record_hash;

    let c = s.re_anchor(confirmed()).expect("re-anchor");
    let row = dump_rows(&f)
        .into_iter()
        .find(|r| r.seq == c.seq)
        .expect("row");
    assert_eq!(row.event_type, "VERIFY");
    assert_ne!(row.flags & EventFlags::INTEGRITY_INCIDENT.bits(), 0);
    let p = payload(&s, c.seq);
    assert_eq!(p["scope"], "re_anchor");
    assert_eq!(p["result"], "re_anchored");
    assert_eq!(p["findings"][0]["kind"], "re_anchored");
    assert!(
        p["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|x| x["kind"] == "anchor_missing"),
        "{p}"
    );
    assert_eq!(p["dialog_text_sha256"], hex::encode([7u8; 32]));
    // Its own incident, needing INTEGRITY_ACK like any other.
    assert_eq!(s.open_incidents(), vec![startup, c.seq]);

    // Both anchors rewritten from the verified store.
    assert_eq!(
        keychain_first_retained(&f.ring, &f.install_id),
        Some(FirstRetainedAnchor {
            chain_id: f.chain_id.clone(),
            genesis_hash: genesis,
            first_retained_seq: 1,
            first_retained_prev_hash: ZERO_HASH,
        })
    );
    let head = keychain_head(&f.ring, &f.install_id).expect("head anchor");
    assert_eq!(head.chain_id, f.chain_id);
    assert!(head.seq >= c.seq);
    let h = s.health();
    assert_eq!(h.anchors_missing, None);
    assert_eq!(h.anchors_blocked, None);
    assert_eq!(s.full_verify(), vec![]);
    s.flush_head_anchor().expect("flush");
    s.shutdown();

    // The next start finds nothing.
    let (s, v) = ready(open(&f.data, &f.lock, f.config()).expect("open"));
    assert_eq!(v.findings, vec![]);
    assert_eq!(s.health().anchors_missing, None);
    s.shutdown();
}

#[test]
fn anchors_missing_follows_the_keychain() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(4)).expect("append");
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    for e in [EntryName::HeadAnchor, EntryName::FirstRetainedAnchor] {
        f.keys().delete(&e).expect("delete");
    }
    // The head anchor cannot be written for now.
    f.ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::HeadAnchor),
        KeyStoreError::Unavailable,
        u32::MAX,
    );
    let mut cfg = f.config();
    cfg.hooks.fast_anchor_backoff = true;
    let (s, v) = ready(open(&f.data, &f.lock, cfg).expect("open"));
    assert_eq!(
        kinds(&v.findings)
            .iter()
            .filter(|k| **k == FindingKind::AnchorMissing)
            .count(),
        2
    );
    wait_for("a failed head anchor write", || {
        s.health().anchor_write_failing
    });
    assert_eq!(s.health().anchors_missing, Some(MissingAnchor::Both));

    // Once the head anchor is written again only the first-retained entry stays missing
    // (nothing but prune, a restore or re-anchor writes it).
    f.ring.clear_faults();
    wait_for("the head anchor", || {
        keychain_head(&f.ring, &f.install_id).is_some()
    });
    wait_for("the health update", || {
        s.health().anchors_missing == Some(MissingAnchor::FirstRetained)
    });
    s.shutdown();
}

#[test]
fn re_anchor_refused_when_anchors_present_or_restore_interrupted() {
    // Nothing missing: refused, nothing logged, the keychain untouched.
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(3)).expect("append");
    store.flush_head_anchor().expect("flush");
    let head = store.head();
    let fr = keychain_first_retained(&f.ring, &f.install_id);
    assert_eq!(store.health().anchors_missing, None);
    assert!(matches!(
        store.re_anchor(confirmed()),
        Err(AuditError::Invalid(_))
    ));
    assert_eq!(store.head(), head);
    assert_eq!(keychain_first_retained(&f.ring, &f.install_id), fr);

    // An interrupted restore whose anchor reset keeps failing: the anchors are not the restored
    // chain's yet, and it is not a lost anchor (PD-170).
    let out = tempfile::tempdir().expect("out dir");
    let bundle = store.backup(chosen(out.path())).expect("backup");
    let faults = Faults::new();
    let (b, fb) = new_store_with(fake_clock(START), MemKeyring::new(), |cfg| {
        cfg.hooks.faults = Some(faults.clone());
    });
    b.append_batch(mixed(5)).expect("append");
    b.flush_head_anchor().expect("flush");
    faults.fail(FaultPoint::AfterKekReseal, 1);
    assert!(
        b.restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None)
            .is_err()
    );
    drop(b);
    fb.ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::FirstRetainedAnchor),
        KeyStoreError::Unavailable,
        u32::MAX,
    );
    let mut cfg = fb.config();
    cfg.hooks.fast_anchor_backoff = true;
    let (s, v) = ready(open(&fb.data, &fb.lock, cfg).expect("open"));
    assert_eq!(
        kinds(&v.findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    let h = s.health();
    assert_eq!(h.anchors_blocked, Some(BarrierKind::Restore));
    assert_eq!(h.anchors_missing, None);
    let head = s.head();
    assert!(matches!(
        s.re_anchor(confirmed()),
        Err(AuditError::Invalid(_))
    ));
    assert_eq!(s.head(), head);
    assert!(verify_results(&s, &fb, "re_anchored").is_empty());
    s.shutdown();
}

#[test]
fn re_anchor_refused_when_the_store_does_not_verify() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(6)).expect("append");
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    f.keys()
        .delete(&EntryName::FirstRetainedAnchor)
        .expect("delete");
    // A record altered without the KEK: re-anchoring would launder it.
    {
        let c = raw_conn(&f);
        let mut r = dump_conn(&c)
            .into_iter()
            .find(|r| r.seq == 3)
            .expect("row 3");
        r.ts_utc = "2026-10-08T12:00:00.001Z".into();
        write_row(&c, &r);
    }
    let (s, v) = ready(open(&f.data, &f.lock, f.config()).expect("open"));
    assert!(v.verify_seq.is_some());
    assert_eq!(
        s.health().anchors_missing,
        Some(MissingAnchor::FirstRetained)
    );
    let before = s.head().0;

    assert!(matches!(
        s.re_anchor(confirmed()),
        Err(AuditError::Invalid(_))
    ));
    // The verification that refused it is recorded as a full verification, and nothing else.
    assert!(verify_results(&s, &f, "re_anchored").is_empty());
    let after: Vec<RawRow> = dump_rows(&f)
        .into_iter()
        .filter(|r| r.seq > before)
        .collect();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].event_type, "VERIFY");
    let p = payload(&s, after[0].seq);
    assert_eq!(p["scope"], "full");
    assert_ne!(after[0].flags & EventFlags::INTEGRITY_INCIDENT.bits(), 0);
    let found: Vec<&Value> = p["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|x| &x["kind"])
        .collect();
    assert!(found.contains(&&json!("chain_broken")), "{p}");
    assert!(found.contains(&&json!("anchor_missing")), "{p}");
    assert_eq!(keychain_first_retained(&f.ring, &f.install_id), None);
    let h = s.health();
    assert_eq!(h.anchors_missing, Some(MissingAnchor::FirstRetained));
    assert_eq!(h.anchors_blocked, None);
    s.shutdown();
}

#[test]
fn anchors_missing_none_during_interrupted_restore() {
    let (a, _fa) = new_store(fake_clock(START), MemKeyring::new());
    a.append_batch(mixed(7)).expect("append");
    a.flush_head_anchor().expect("flush");
    let out = tempfile::tempdir().expect("out dir");
    let bundle = a.backup(chosen(out.path())).expect("backup");

    // A new machine: no prior anchor, the restore crashes after its KEK re-seal.
    let fb = fixture(fake_clock(START), MemKeyring::new());
    let faults = Faults::new();
    let mut cfg = fb.config();
    cfg.hooks.faults = Some(faults.clone());
    faults.fail(FaultPoint::AfterKekReseal, 1);
    match restore_from_source(
        &fb.data,
        &fb.lock,
        cfg,
        chosen(&bundle.bundle_dir),
        &pass(PASSPHRASE),
        None,
    ) {
        Err(OpenError::Restore(RestoreError::CommittedIncomplete { .. })) => {}
        other => panic!("expected CommittedIncomplete, got {other:?}"),
    }
    assert_eq!(keychain_head(&fb.ring, &fb.install_id), None);
    assert_eq!(keychain_first_retained(&fb.ring, &fb.install_id), None);
    // Both entries absent, yet the verdict names no missing anchor: the restore's reset is due.
    let v = testing::startup_verdict(&fb.data, &fb.config()).expect("verdict");
    assert!(v.anchor_actions.complete_restore.is_some());
    assert_eq!(v.anchor_actions.anchors_missing, None);

    // The next start completes it, but the head anchor cannot be written yet: no anchor entry of
    // the restored chain is there, and still nothing is "missing" (M2 T16 M-7).
    fb.ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::HeadAnchor),
        KeyStoreError::Unavailable,
        u32::MAX,
    );
    let mut cfg = fb.config();
    cfg.hooks.fast_anchor_backoff = true;
    let (s, v) = ready(open(&fb.data, &fb.lock, cfg).expect("open"));
    assert_eq!(
        kinds(&v.findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    assert_eq!(keychain_head(&fb.ring, &fb.install_id), None);
    let h = s.health();
    assert_eq!(h.anchors_blocked, Some(BarrierKind::Restore));
    assert_eq!(h.anchors_missing, None);

    // The reset lands: both anchors there, nothing missing, nothing blocked.
    fb.ring.clear_faults();
    wait_for("the anchor reset", || s.health().anchors_blocked.is_none());
    assert_eq!(
        keychain_head(&fb.ring, &fb.install_id).map(|a| a.chain_id),
        Some(s.head().2)
    );
    assert_eq!(s.health().anchors_missing, None);
    s.shutdown();
}

// ---------------------------------------------------------------------------------------
// Forget old install (PD-170, T20 m-9)

#[test]
fn orphan_installs_lists_archived_install_ids_only() {
    let t = two_installs();
    let a_id = t.f.install_id.clone();
    // An install with keychain entries that no archived store names, and a stray file.
    let (c_id, _) = new_ids().expect("ids");
    MemKeyStore::new(t.f.ring.clone(), &c_id)
        .set(&EntryName::Kek, b"another install")
        .expect("kek");
    std::fs::write(t.f.dir.path().join("archived").join("notes.txt"), b"x").expect("stray");
    // A restore of the archive into the live install archives B's own store (`replaced_db`),
    // whose records name the live install: never an orphan.
    let report = t
        .live
        .restore(
            chosen(&t.f.dir.path().join(&t.archived.file)),
            &pass(PASSPHRASE),
            None,
        )
        .expect("restore");
    let replaced = report.replaced_db.expect("replaced_db");

    let orphans = orphan_installs(&t.f.data, &*t.b_keys).expect("orphan_installs");
    assert_eq!(orphans.len(), 1, "{orphans:?}");
    let o = &orphans[0];
    assert_eq!(o.install_id(), a_id);
    assert_eq!(o.archived_files(), std::slice::from_ref(&t.archived.file));
    assert!(!o.archived_files().contains(&replaced.file));
    let mut want: Vec<String> = ANCHOR_ACCOUNTS.iter().map(|s| s.to_string()).collect();
    want.extend(["pat/i1".to_string(), "pat/i2".to_string()]);
    want.sort();
    assert_eq!(o.entries(), want.as_slice());
    t.live.shutdown();
}

#[test]
fn forget_install_deletes_pats_keeps_kek_by_default() {
    let t = two_installs();
    let a_id = t.f.install_id.clone();
    let a_keys: Vec<Option<Vec<u8>>> = ANCHOR_ACCOUNTS
        .iter()
        .map(|a| raw(&t.f.ring, &a_id, a))
        .collect();
    assert!(a_keys.iter().all(Option::is_some));
    let b_before: Vec<Option<Vec<u8>>> = ["kek", "head_anchor", "first_retained_anchor", "pat/i9"]
        .iter()
        .map(|a| raw(&t.f.ring, &t.b_id, a))
        .collect();
    let orphans = orphan_installs(&t.f.data, &*t.b_keys).expect("orphan_installs");
    let o = orphans
        .iter()
        .find(|o| o.install_id() == a_id)
        .expect("install A");

    // Never the live install: a keystore of install A refuses A's orphan entry.
    let a_store = MemKeyStore::new(t.f.ring.clone(), &a_id);
    assert!(matches!(
        forget_install(&a_store, o, confirmed(), None),
        Err(OpenError::Invalid(_))
    ));
    assert!(raw(&t.f.ring, &a_id, "pat/i1").is_some());

    let report = forget_install(&*t.b_keys, o, confirmed(), None).expect("forget");
    assert_eq!(report.install_id, a_id);
    assert!(!report.keys_deleted);
    assert_eq!(report.deleted, ["pat/i1", "pat/i2", "canary"]);
    for a in ["pat/i1", "pat/i2", "canary"] {
        assert_eq!(raw(&t.f.ring, &a_id, a), None, "{a}");
    }
    // The archived log's keys stay (recoverable as before); install B is untouched.
    let a_after: Vec<Option<Vec<u8>>> = ANCHOR_ACCOUNTS
        .iter()
        .map(|a| raw(&t.f.ring, &a_id, a))
        .collect();
    assert_eq!(a_after, a_keys);
    let b_after: Vec<Option<Vec<u8>>> = ["kek", "head_anchor", "first_retained_anchor", "pat/i9"]
        .iter()
        .map(|a| raw(&t.f.ring, &t.b_id, a))
        .collect();
    assert_eq!(b_after, b_before);
    // Still listed, with the entries that are left.
    let orphans = orphan_installs(&t.f.data, &*t.b_keys).expect("orphan_installs");
    let mut left: Vec<String> = ANCHOR_ACCOUNTS.iter().map(|s| s.to_string()).collect();
    left.sort();
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].entries(), left.as_slice());
    t.live.shutdown();
}

#[test]
fn forget_install_with_keys_deletes_all_and_archive_still_restores_with_passphrase() {
    let t = two_installs();
    let a_id = t.f.install_id.clone();
    let a_chain = t.archived.chain_id.clone();
    let orphans = orphan_installs(&t.f.data, &*t.b_keys).expect("orphan_installs");
    let report = forget_install(&*t.b_keys, &orphans[0], confirmed(), Some(confirmed()))
        .expect("forget with keys");
    assert!(report.keys_deleted);
    assert_eq!(
        report.deleted,
        [
            "pat/i1",
            "pat/i2",
            "canary",
            "first_retained_anchor",
            "head_anchor",
            "kek"
        ]
    );
    for a in ["pat/i1", "pat/i2", "canary"]
        .iter()
        .chain(ANCHOR_ACCOUNTS.iter())
    {
        assert_eq!(raw(&t.f.ring, &a_id, a), None, "{a}");
    }
    assert!(raw(&t.f.ring, &t.b_id, "kek").is_some());
    // Nothing of install A is left to forget.
    assert_eq!(
        orphan_installs(&t.f.data, &*t.b_keys).expect("orphan_installs"),
        vec![]
    );

    // The archived log opens with its own recovery passphrase through a restore (§8.7).
    let rep = t
        .live
        .restore(
            chosen(&t.f.dir.path().join(&t.archived.file)),
            &pass(PASSPHRASE),
            None,
        )
        .expect("restore the archive");
    assert_eq!(rep.source_chain_id, a_chain);
    assert_eq!(t.live.head().2, rep.new_chain_id);
    t.live.shutdown();
}
