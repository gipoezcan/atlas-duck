//! Anchor-dir line types and the verifier side (§8.5, §8.7; U-06 anchor-dir clauses, U-14
//! anchored `clock_behind`, P7). The writer is M10: the lines here are produced with
//! `to_line` from a real test store's rows and written into a temp anchor dir
//! (`<dir>/<chain_id>.jsonl`) that the store's `anchor_dir` setting (confirmed) names.

mod common;

use std::path::{Path, PathBuf};
use std::time::Instant;

use atlas_duck_audit::anchor_dir::{AnchorLine, AnchorLineError, file_name, parse_line, to_line};
use atlas_duck_audit::anchors::{FirstRetainedAnchor, HeadAnchor};
use atlas_duck_audit::keystore::service_name;
use atlas_duck_audit::testing::{self, FakePrune, MemKeyring};
use atlas_duck_audit::types::{Confirmed, EventFlags, EventType};
use atlas_duck_audit::{
    FindingKind, OpenConfig, SettingChange, Settings, StartupOutcome, Store, VerifyFinding, open,
};
use common::*;
use rusqlite::Connection;
use serde_json::json;
use tempfile::TempDir;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/anchor_dir");

// ---------------------------------------------------------------------------------------
// helpers

fn confirmed() -> Confirmed {
    Confirmed {
        dialog_text_sha256: [9; 32],
    }
}

fn dir_text(dir: &Path) -> String {
    dir.to_string_lossy().into_owned()
}

/// A store whose `anchor_dir` setting (confirmed) names a fresh temp dir. The setting's
/// `CONFIG_CHANGED` is seq 2 (an immediate-line type, NULL epoch: nothing corroborated yet).
fn anchored_store() -> (Store, Fixture, TempDir) {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let dir = tempfile::tempdir().expect("anchor dir");
    store
        .apply_setting(
            SettingChange::AnchorDir(Some(dir_text(dir.path()))),
            Some(confirmed()),
        )
        .expect("anchor dir setting");
    (store, f, dir)
}

/// The `PRUNE` settings snapshot (exactly the four keys of `Settings::to_json`) that keeps
/// the anchor dir in the view once the `CONFIG_CHANGED` that set it is pruned.
fn snapshot(dir: &Path) -> serde_json::Value {
    Settings {
        retention_days: 92,
        anchor_dir: Some(dir_text(dir)),
        ..Settings::default()
    }
    .to_json()
}

fn fake_prune(store: &Store, dir: &Path, first_retained_seq: u64, cutoff: &str) -> u64 {
    let seq = testing::insert_fake_prune(
        store,
        FakePrune {
            first_retained_seq,
            cutoff: cutoff.into(),
            settings: snapshot(dir),
            update_first_retained: true,
        },
    )
    .expect("fake prune")
    .seq;
    store.flush_head_anchor().expect("flush");
    seq
}

fn header(f: &Fixture) -> AnchorLine {
    AnchorLine::Header {
        chain_id: f.chain_id.clone(),
        install_id: f.install_id.clone(),
        host: "testhost".into(),
        os_user: "alice".into(),
        created_at: START.into(),
    }
}

fn record_line(r: &RawRow) -> AnchorLine {
    AnchorLine::Record {
        seq: r.seq,
        record_hash: r.record_hash,
        epoch: r.epoch.clone(),
        clock_behind: EventFlags::from_bits(r.flags).contains(EventFlags::BEHIND),
    }
}

fn immediate_line(r: &RawRow) -> AnchorLine {
    AnchorLine::Immediate {
        seq: r.seq,
        record_hash: r.record_hash,
        epoch: r.epoch.clone(),
        event_type: r.event_type.clone(),
    }
}

fn detached_line(r: &RawRow) -> AnchorLine {
    AnchorLine::Detached {
        seq: r.seq,
        record_hash: r.record_hash,
        epoch: r.epoch.clone(),
        detached_at: "2026-10-08T13:00:00.000Z".into(),
    }
}

/// One `Prune` line per `prune_log` row.
fn prune_lines(f: &Fixture) -> Vec<AnchorLine> {
    let c = raw_conn(f);
    let mut st = c
        .prepare(
            "SELECT first_retained_seq, last_pruned_record_hash, cutoff_epoch FROM prune_log \
             ORDER BY prune_seq",
        )
        .expect("prepare");
    st.query_map([], |r| {
        let prev: Vec<u8> = r.get(1)?;
        Ok(AnchorLine::Prune {
            first_retained_seq: r.get::<_, i64>(0)? as u64,
            first_retained_prev_hash: prev.try_into().expect("32 bytes"),
            cutoff_epoch: r.get(2)?,
        })
    })
    .expect("query")
    .map(|r| r.expect("row"))
    .collect()
}

fn write_lines(dir: &Path, chain_id: &str, lines: &[AnchorLine]) {
    let text: String = lines.iter().map(|l| to_line(l) + "\n").collect();
    std::fs::write(dir.join(file_name(chain_id)), text).expect("write anchor file");
}

/// Header, then a `Record` line for every row (and an `Immediate` line for every
/// `CONFIG_CHANGED`/`CLOCK_ANOMALY`).
fn lines_for_rows(f: &Fixture, rows: &[RawRow]) -> Vec<AnchorLine> {
    let mut lines = vec![header(f)];
    for r in rows {
        lines.push(record_line(r));
        if r.event_type == "CONFIG_CHANGED" || r.event_type == "CLOCK_ANOMALY" {
            lines.push(immediate_line(r));
        }
    }
    lines
}

fn reopen_with(f: &Fixture, tweak: impl FnOnce(&mut OpenConfig)) -> Store {
    let mut cfg = f.config();
    tweak(&mut cfg);
    testing::open_existing(&f.data, &f.lock, cfg).expect("open_existing")
}

/// `full_verify` on a fresh handle; the store must still accept appends afterwards.
fn full_verify_with(f: &Fixture, tweak: impl FnOnce(&mut OpenConfig)) -> Vec<VerifyFinding> {
    let store = reopen_with(f, tweak);
    let out = store.full_verify();
    store
        .append(ev(EventType::APP_START, None, json!({ "after": "verify" })))
        .expect("store still usable after verification");
    store.shutdown();
    out
}

fn full_verify_fresh(f: &Fixture) -> Vec<VerifyFinding> {
    full_verify_with(f, |_| {})
}

fn verdict_findings(f: &Fixture) -> Vec<VerifyFinding> {
    testing::startup_verdict(&f.data, &f.config())
        .expect("startup verdict")
        .findings
}

fn kinds(fs: &[VerifyFinding]) -> Vec<FindingKind> {
    fs.iter().map(|f| f.kind).collect()
}

fn has(fs: &[VerifyFinding], kind: FindingKind, seq: u64) -> bool {
    fs.iter()
        .any(|f| f.kind == kind && (f.observed_seq == Some(seq) || f.expected_seq == Some(seq)))
}

fn has_kind(fs: &[VerifyFinding], kind: FindingKind) -> bool {
    fs.iter().any(|f| f.kind == kind)
}

fn anchor_dir_findings(fs: &[VerifyFinding]) -> Vec<&VerifyFinding> {
    fs.iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::AnchorDirMismatch | FindingKind::AnchoredRecordPrunedEarly
            )
        })
        .collect()
}

fn set_target(c: &Connection, seq: u64, target: &str) {
    c.execute(
        "UPDATE events SET target = ?1 WHERE seq = ?2",
        rusqlite::params![target, seq as i64],
    )
    .expect("tamper");
}

// ---------------------------------------------------------------------------------------
// line types

#[test]
fn parse_all_line_types() {
    let text = std::fs::read_to_string(PathBuf::from(FIXTURES).join("all_line_types.jsonl"))
        .expect("fixture");
    let lines: Vec<AnchorLine> = text
        .lines()
        .map(|l| parse_line(l).unwrap_or_else(|e| panic!("{l}: {e}")))
        .collect();
    for (raw, l) in text.lines().zip(&lines) {
        assert_eq!(to_line(l), raw, "round trip");
    }
    assert_eq!(lines.len(), 8);
    assert_eq!(
        lines[0],
        AnchorLine::Header {
            chain_id: "0123456789abcdef0123456789abcdef".into(),
            install_id: "fedcba9876543210fedcba9876543210".into(),
            host: "testhost".into(),
            os_user: "alice".into(),
            created_at: "2026-10-08T12:00:00.000Z".into(),
        }
    );
    assert_eq!(
        lines[1],
        AnchorLine::Record {
            seq: 1,
            record_hash: [0x11; 32],
            epoch: None,
            clock_behind: false,
        }
    );
    assert!(matches!(
        &lines[2],
        AnchorLine::Record { seq: 2, epoch: Some(e), clock_behind: false, .. } if e == "2026-10-08"
    ));
    assert!(matches!(
        &lines[3],
        AnchorLine::Record {
            seq: 3,
            clock_behind: true,
            ..
        }
    ));
    assert!(matches!(
        &lines[4],
        AnchorLine::Immediate { seq: 4, event_type, epoch: Some(_), .. } if event_type == "CONFIG_CHANGED"
    ));
    assert!(matches!(
        &lines[5],
        AnchorLine::Immediate { seq: 5, epoch: None, event_type, .. } if event_type == "INTEGRITY_ACK"
    ));
    assert_eq!(
        lines[6],
        AnchorLine::Prune {
            first_retained_seq: 6,
            first_retained_prev_hash: [0xcc; 32],
            cutoff_epoch: "2026-06-01".into(),
        }
    );
    assert!(matches!(
        &lines[7],
        AnchorLine::Detached { seq: 7, record_hash, detached_at, .. }
            if *record_hash == [0xee; 32] && detached_at == "2026-10-09T08:30:00.000Z"
    ));
    assert_eq!(
        file_name("0123456789abcdef0123456789abcdef"),
        "0123456789abcdef0123456789abcdef.jsonl"
    );

    let bad =
        std::fs::read_to_string(PathBuf::from(FIXTURES).join("bad_lines.jsonl")).expect("fixture");
    let errs: Vec<AnchorLineError> = bad.lines().map(|l| parse_line(l).expect_err(l)).collect();
    assert_eq!(
        errs,
        vec![
            AnchorLineError::UnknownKey("note".into()),
            AnchorLineError::BadValue("record_hash"),
            AnchorLineError::BadValue("record_hash"),
            AnchorLineError::MissingKey("seq"),
        ]
    );
}

#[test]
fn parse_rejects_other_malformed_lines() {
    let h = "a".repeat(64);
    let cases: Vec<(String, AnchorLineError)> = vec![
        ("not json".into(), AnchorLineError::NotJson),
        ("[1,2]".into(), AnchorLineError::NotObject),
        (
            format!("{{\"epoch\":null, \"record_hash\":\"{h}\",\"seq\":2}}"),
            AnchorLineError::NotCanonical,
        ),
        (
            format!("{{\"seq\":2,\"epoch\":null,\"record_hash\":\"{h}\"}}"),
            AnchorLineError::NotCanonical,
        ),
        (
            format!("{{\"epoch\":null,\"record_hash\":\"{h}\",\"seq\":2,\"seq\":2}}"),
            AnchorLineError::NotCanonical,
        ),
        (
            format!("{{\"clock_behind\":false,\"epoch\":null,\"record_hash\":\"{h}\",\"seq\":2}}"),
            AnchorLineError::BadValue("clock_behind"),
        ),
        (
            format!("{{\"epoch\":null,\"record_hash\":\"{h}\",\"seq\":0}}"),
            AnchorLineError::BadValue("seq"),
        ),
        (
            format!("{{\"epoch\":null,\"record_hash\":\"{h}\",\"seq\":-1}}"),
            AnchorLineError::BadValue("seq"),
        ),
        (
            format!("{{\"epoch\":null,\"record_hash\":\"{h}\",\"seq\":9007199254740992}}"),
            AnchorLineError::BadValue("seq"),
        ),
        (
            format!("{{\"epoch\":\"2026-13-01\",\"record_hash\":\"{h}\",\"seq\":2}}"),
            AnchorLineError::BadValue("epoch"),
        ),
        (
            format!(
                "{{\"epoch\":null,\"event_type\":\"APP_START\",\"record_hash\":\"{h}\",\"seq\":2}}"
            ),
            AnchorLineError::BadValue("event_type"),
        ),
        (
            format!(
                "{{\"epoch\":null,\"event_type\":\"ANCHOR_DETACHED\",\"record_hash\":\"{h}\",\"seq\":2}}"
            ),
            AnchorLineError::MissingKey("detached_at"),
        ),
        (
            format!(
                "{{\"cutoff_epoch\":\"2026-06-01\",\"first_retained_prev_hash\":\"{h}\",\"first_retained_seq\":6,\"seq\":6}}"
            ),
            AnchorLineError::UnknownKey("seq".into()),
        ),
        (
            "{\"chain_id\":\"0123456789ABCDEF0123456789ABCDEF\",\"created_at\":\"2026-10-08T12:00:00.000Z\",\"host\":\"h\",\"install_id\":\"fedcba9876543210fedcba9876543210\",\"os_user\":\"u\"}".into(),
            AnchorLineError::BadValue("chain_id"),
        ),
        (
            "{\"chain_id\":\"0123456789abcdef0123456789abcdef\",\"created_at\":\"yesterday\",\"host\":\"h\",\"install_id\":\"fedcba9876543210fedcba9876543210\",\"os_user\":\"u\"}".into(),
            AnchorLineError::BadValue("created_at"),
        ),
        (
            format!("{{\"epoch\":null,\"record_hash\":\"{h}\",\"seq\":2}}\r"),
            AnchorLineError::NotCanonical,
        ),
        (
            format!("{{\"epoch\":null,\"record_hash\":\"{}\",\"seq\":2}}", "x".repeat(5000)),
            AnchorLineError::TooLong,
        ),
    ];
    for (line, want) in cases {
        assert_eq!(parse_line(&line), Err(want), "{line}");
    }
}

// ---------------------------------------------------------------------------------------
// retained records

#[test]
fn anchored_record_matches() {
    let (store, f, dir) = anchored_store();
    corroborate(&store);
    store.append_batch(mixed(12)).expect("append");
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    let rows = dump_rows(&f);
    let mut lines = lines_for_rows(&f, &rows);
    lines.push(detached_line(rows.last().expect("rows")));
    write_lines(dir.path(), &f.chain_id, &lines);

    let v = verdict_findings(&f);
    assert!(v.is_empty(), "{v:?}");
    let fs = full_verify_fresh(&f);
    assert!(fs.is_empty(), "{fs:?}");
}

#[test]
fn null_epoch_lines_accepted() {
    // Nothing corroborated: every row (GENESIS, the setting, the events) has a NULL epoch.
    let (store, f, dir) = anchored_store();
    store.append_batch(mixed(6)).expect("append");
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    let rows = dump_rows(&f);
    assert!(rows.iter().all(|r| r.epoch.is_none()));
    write_lines(dir.path(), &f.chain_id, &lines_for_rows(&f, &rows));
    let fs = full_verify_fresh(&f);
    assert!(fs.is_empty(), "{fs:?}");

    // A line claiming an epoch for a NULL-epoch record does not match it.
    let mut lines = lines_for_rows(&f, &rows);
    lines.push(AnchorLine::Record {
        seq: 3,
        record_hash: rows[2].record_hash,
        epoch: Some("2026-10-08".into()),
        clock_behind: false,
    });
    write_lines(dir.path(), &f.chain_id, &lines);
    let fs = full_verify_fresh(&f);
    assert!(has(&fs, FindingKind::AnchorDirMismatch, 3), "{fs:?}");
}

#[test]
fn u06_anchored_record_rewritten() {
    let (store, f, dir) = anchored_store();
    corroborate(&store);
    store.append_batch(mixed(20)).expect("append");
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    // Sparse daily lines: every fourth record from seq 4 on.
    let rows = dump_rows(&f);
    let mut lines = vec![header(&f)];
    lines.extend(rows.iter().filter(|r| r.seq % 4 == 0).map(record_line));
    write_lines(dir.path(), &f.chain_id, &lines);
    assert!(full_verify_fresh(&f).is_empty());

    // An attacker without the anchor dir rewrites seq 9 and rehashes everything after it,
    // keychain head anchor included.
    let k = 9;
    set_target(&raw_conn(&f), k, "PROJ-forged");
    let head = rehash_from(&f, k);
    set_keychain_head(&f, &head);

    let fs = full_verify_fresh(&f);
    assert!(
        !has_kind(&fs, FindingKind::ChainBroken) && !has_kind(&fs, FindingKind::AnchorMismatch),
        "the chain and the keychain are consistent: {fs:?}"
    );
    assert!(has(&fs, FindingKind::AnchorDirMismatch, 12), "{fs:?}");
    let first = fs
        .iter()
        .filter(|x| x.kind == FindingKind::AnchorDirMismatch)
        .filter_map(|x| x.expected_seq)
        .min();
    assert_eq!(first, Some(12), "the first anchored seq >= k: {fs:?}");
    assert!(!has(&fs, FindingKind::AnchorDirMismatch, 8), "{fs:?}");
    let at12 = fs
        .iter()
        .find(|x| x.kind == FindingKind::AnchorDirMismatch && x.expected_seq == Some(12))
        .expect("finding at 12");
    assert_eq!(at12.expected_hash, Some(rows[11].record_hash));
    assert_ne!(at12.observed_hash, at12.expected_hash);
}

#[test]
fn startup_compares_anchor_dir() {
    let (store, f, dir) = anchored_store();
    corroborate(&store);
    store.append_batch(mixed(20)).expect("append");
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    let rows = dump_rows(&f);
    let mut lines = vec![header(&f)];
    lines.extend(rows.iter().filter(|r| r.seq % 4 == 0).map(record_line));
    write_lines(dir.path(), &f.chain_id, &lines);
    set_target(&raw_conn(&f), 9, "PROJ-forged");
    let head = rehash_from(&f, 9);
    set_keychain_head(&f, &head);

    let (store, verify) = match open(&f.data, &f.lock, f.config()).expect("open") {
        StartupOutcome::Ready { store, verify } => (store, verify),
        other => panic!("not ready: {other:?}"),
    };
    assert!(
        has(&verify.findings, FindingKind::AnchorDirMismatch, 12),
        "{:?}",
        kinds(&verify.findings)
    );
    let vseq = verify.verify_seq.expect("a startup VERIFY was appended");
    assert_eq!(store.open_incidents(), vec![vseq]);
    let flags: i64 = raw_conn(&f)
        .query_row(
            "SELECT flags FROM events WHERE seq = ?1",
            [vseq as i64],
            |r| r.get(0),
        )
        .expect("VERIFY row");
    assert!(EventFlags::from_bits(flags as u64).contains(EventFlags::INTEGRITY_INCIDENT));
    store.shutdown();
}

#[test]
fn u06_anchored_seq_beyond_head() {
    let (store, f, dir) = anchored_store();
    corroborate(&store);
    store.append_batch(mixed(10)).expect("append");
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    let rows = dump_rows(&f);
    write_lines(dir.path(), &f.chain_id, &lines_for_rows(&f, &rows));
    let old_head = rows.last().expect("rows").seq;

    // Rollback: the last three records are gone and the keychain head names the new head.
    raw_conn(&f)
        .execute("DELETE FROM events WHERE seq > ?1", [(old_head - 3) as i64])
        .expect("truncate");
    let new_head = &rows[(old_head - 4) as usize];
    set_keychain_head(
        &f,
        &atlas_duck_audit::anchors::HeadAnchor {
            chain_id: new_head.chain_id.clone(),
            seq: new_head.seq,
            record_hash: new_head.record_hash,
        },
    );
    let fs = full_verify_fresh(&f);
    for seq in old_head - 2..=old_head {
        assert!(
            has(&fs, FindingKind::AnchorDirMismatch, seq),
            "{seq}: {fs:?}"
        );
    }
    assert!(!has(&fs, FindingKind::AnchorDirMismatch, old_head - 3));
    assert!(has(
        &verdict_findings(&f),
        FindingKind::AnchorDirMismatch,
        old_head
    ));
}

#[test]
fn immediate_line_event_type_mismatch() {
    let (store, f, dir) = anchored_store();
    corroborate(&store);
    store.append_batch(mixed(4)).expect("append");
    store.shutdown();
    let rows = dump_rows(&f);
    let setting = &rows[1];
    assert_eq!(setting.event_type, "CONFIG_CHANGED");
    let mut wrong = immediate_line(setting);
    if let AnchorLine::Immediate { event_type, .. } = &mut wrong {
        *event_type = "LEGAL_HOLD_CHANGED".into();
    }
    write_lines(dir.path(), &f.chain_id, &[header(&f), wrong]);
    let fs = full_verify_fresh(&f);
    assert!(has(&fs, FindingKind::AnchorDirMismatch, 2), "{fs:?}");
    assert_eq!(anchor_dir_findings(&fs).len(), 1, "{fs:?}");

    write_lines(
        dir.path(),
        &f.chain_id,
        &[header(&f), immediate_line(setting)],
    );
    assert!(full_verify_fresh(&f).is_empty());
}

#[test]
fn record_line_must_match_flag_and_chain() {
    let (store, f, dir) = anchored_store();
    corroborate(&store);
    store.append_batch(mixed(8)).expect("append");
    store.shutdown();
    let rows = dump_rows(&f);

    // `clock_behind: true` for a record without the flag.
    let mut flagged = record_line(&rows[4]);
    if let AnchorLine::Record { clock_behind, .. } = &mut flagged {
        *clock_behind = true;
    }
    write_lines(dir.path(), &f.chain_id, &[header(&f), flagged]);
    let fs = full_verify_fresh(&f);
    assert!(has(&fs, FindingKind::AnchorDirMismatch, 5), "{fs:?}");

    // A record moved to another chain (rehashed, keychain head too) no longer matches the
    // line of this chain's file, although its new record_hash is consistent.
    write_lines(
        dir.path(),
        &f.chain_id,
        &[header(&f), record_line(&rows[4]), record_line(&rows[6])],
    );
    assert!(full_verify_fresh(&f).is_empty());
    raw_conn(&f)
        .execute(
            "UPDATE events SET chain_id = 'ffffffffffffffffffffffffffffffff' WHERE seq = 5",
            [],
        )
        .expect("tamper");
    let head = rehash_from(&f, 5);
    set_keychain_head(&f, &head);
    let fs = full_verify_fresh(&f);
    assert!(
        fs.iter().any(|x| x.kind == FindingKind::AnchorDirMismatch
            && x.expected_seq == Some(5)
            && x.detail.contains("another chain")),
        "{fs:?}"
    );
}

#[test]
fn header_must_name_the_chain_and_come_first() {
    let (store, f, dir) = anchored_store();
    store.shutdown();
    let rows = dump_rows(&f);

    let mut other = header(&f);
    if let AnchorLine::Header { chain_id, .. } = &mut other {
        *chain_id = "ffffffffffffffffffffffffffffffff".into();
    }
    write_lines(dir.path(), &f.chain_id, &[other]);
    let fs = full_verify_fresh(&f);
    assert!(has_kind(&fs, FindingKind::AnchorDirMismatch), "{fs:?}");

    write_lines(
        dir.path(),
        &f.chain_id,
        &[record_line(&rows[0]), header(&f)],
    );
    let fs = full_verify_fresh(&f);
    assert!(has_kind(&fs, FindingKind::AnchorDirMismatch), "{fs:?}");

    // A second header later in the file.
    write_lines(
        dir.path(),
        &f.chain_id,
        &[header(&f), record_line(&rows[0]), header(&f)],
    );
    let fs = full_verify_fresh(&f);
    assert!(
        fs.iter()
            .any(|x| x.detail.contains("header line after line 1")),
        "{fs:?}"
    );

    // An empty file has no header either.
    write_lines(dir.path(), &f.chain_id, &[]);
    let fs = full_verify_fresh(&f);
    assert!(fs.iter().any(|x| x.detail.contains("is empty")), "{fs:?}");
}

// ---------------------------------------------------------------------------------------
// reading the anchor dir

#[test]
fn unreadable_lines_and_dirs_are_findings() {
    let (store, f, dir) = anchored_store();
    store.shutdown();

    // The dir exists but holds no file for this chain yet (the writer is M10): no finding.
    assert!(full_verify_fresh(&f).is_empty());

    // A line that does not parse is never skipped.
    let good = to_line(&header(&f));
    std::fs::write(
        dir.path().join(file_name(&f.chain_id)),
        format!("{good}\n{{\"seq\":1}}\n"),
    )
    .expect("write");
    let fs = full_verify_fresh(&f);
    assert!(
        fs.iter()
            .any(|x| x.kind == FindingKind::AnchorDirMismatch && x.detail.contains("line 2")),
        "{fs:?}"
    );

    // A configured dir that cannot be read is not a clean pass, at startup either.
    let path = dir.path().to_path_buf();
    dir.close().expect("remove anchor dir");
    assert!(!path.exists());
    let fs = full_verify_fresh(&f);
    assert!(has_kind(&fs, FindingKind::AnchorDirMismatch), "{fs:?}");
    assert!(has_kind(
        &verdict_findings(&f),
        FindingKind::AnchorDirMismatch
    ));
}

#[test]
fn unreadable_anchor_dir_setting_is_a_finding() {
    let (store, f, _dir) = anchored_store();
    corroborate(&store);
    store.append_batch(mixed(4)).expect("append");
    store.shutdown();
    // The setting's CONFIG_CHANGED (seq 2) no longer decrypts (rehashed, keychain head too):
    // which anchor dir is configured is unknown, which is not "none".
    let mut r = dump_rows(&f).swap_remove(1);
    assert_eq!(r.event_type, "CONFIG_CHANGED");
    r.nonce[0] ^= 1;
    write_row(&raw_conn(&f), &r);
    let head = rehash_from(&f, 2);
    set_keychain_head(&f, &head);
    let unknown = |fs: &[VerifyFinding]| {
        fs.iter()
            .any(|x| x.kind == FindingKind::AnchorDirMismatch && x.detail.contains("anchor_dir"))
    };
    let v = verdict_findings(&f);
    assert!(unknown(&v), "{v:?}");
    let fs = full_verify_fresh(&f);
    assert!(unknown(&fs), "{fs:?}");
}

/// A store whose last `PRUNE` (first retained seq 6) committed but whose first-retained
/// update did not happen (a crash right after the commit): the head anchor is before it.
fn interrupted_prune() -> (Fixture, TempDir, u64) {
    let (store, f, dir) = anchored_store();
    corroborate(&store);
    store.append_batch(mixed(10)).expect("append");
    store.testing_enable_anchors();
    store.flush_head_anchor().expect("flush");
    store.testing_pause_anchors();
    let prune = testing::insert_fake_prune(
        &store,
        FakePrune {
            first_retained_seq: 6,
            cutoff: "2026-06-01".into(),
            settings: snapshot(dir.path()),
            update_first_retained: false,
        },
    )
    .expect("fake prune")
    .seq;
    store.shutdown();
    (f, dir, prune)
}

fn keychain_anchor(f: &Fixture, entry: &str) -> Option<Vec<u8>> {
    f.ring.raw_get(&service_name(&f.install_id), entry)
}

fn open_ready(f: &Fixture) -> (Store, Vec<VerifyFinding>) {
    match open(&f.data, &f.lock, f.config()).expect("open") {
        StartupOutcome::Ready { store, verify } => (store, verify.findings),
        other => panic!("not ready: {other:?}"),
    }
}

#[test]
fn contradicting_anchor_line_blocks_interrupted_prune_reconciliation() {
    let (f, dir, _) = interrupted_prune();
    let v = testing::startup_verdict(&f.data, &f.config()).expect("verdict");
    assert!(
        has_kind(&v.findings, FindingKind::InterruptedPruneReconciled),
        "{v:?}"
    );
    assert!(v.anchor_actions.set_first_retained.is_some());

    // A readable line that contradicts the store: not reconciled.
    let rows = dump_rows(&f);
    let mut wrong = record_line(rows.last().expect("rows"));
    if let AnchorLine::Record { record_hash, .. } = &mut wrong {
        record_hash[0] ^= 1;
    }
    write_lines(dir.path(), &f.chain_id, &[header(&f), wrong]);
    let v = testing::startup_verdict(&f.data, &f.config()).expect("verdict");
    assert!(
        has_kind(&v.findings, FindingKind::AnchorDirMismatch),
        "{v:?}"
    );
    assert!(
        has_kind(&v.findings, FindingKind::FirstRetainedMismatch),
        "{v:?}"
    );
    assert!(v.anchor_actions.set_first_retained.is_none());
    assert!(v.anchor_actions.defer_prune.is_none());
}

#[test]
fn unreadable_anchor_dir_defers_interrupted_prune_reconciliation() {
    let (f, dir, prune) = interrupted_prune();
    let path = dir.path().to_path_buf();
    dir.close().expect("remove anchor dir");

    // Started while the share is offline: an incident for the unreadable dir, but neither a
    // FirstRetainedMismatch nor a reconciliation; the head anchor stays at or before the PRUNE.
    let (store, findings) = open_ready(&f);
    assert!(
        has_kind(&findings, FindingKind::AnchorDirMismatch),
        "{findings:?}"
    );
    assert!(
        !has_kind(&findings, FindingKind::FirstRetainedMismatch),
        "{findings:?}"
    );
    assert!(
        !has_kind(&findings, FindingKind::InterruptedPruneReconciled),
        "{findings:?}"
    );
    assert_eq!(
        store.health().anchors_blocked,
        Some(atlas_duck_audit::anchors::BarrierKind::Prune)
    );
    assert!(store.health().first_retained_update_pending);
    store.append_batch(mixed(4)).expect("append");
    store.flush_head_anchor().expect("flush");
    let head =
        HeadAnchor::from_entry(&keychain_anchor(&f, "head_anchor").expect("head")).expect("layout");
    assert!(
        head.seq <= prune,
        "head anchor {} passed PRUNE {prune}",
        head.seq
    );
    store.shutdown();
    let first = keychain_anchor(&f, "first_retained_anchor").expect("first-retained");
    assert_eq!(
        FirstRetainedAnchor::from_entry(&first)
            .expect("layout")
            .first_retained_seq,
        1
    );

    // The share is back: the next start reconciles the prune without an incident.
    std::fs::create_dir(&path).expect("restore anchor dir");
    let (store, findings) = open_ready(&f);
    assert!(
        has_kind(&findings, FindingKind::InterruptedPruneReconciled),
        "{findings:?}"
    );
    assert!(
        findings.iter().all(|x| !x.kind.is_incident()),
        "{findings:?}"
    );
    store.flush_head_anchor().expect("flush");
    store.shutdown();
    let first = keychain_anchor(&f, "first_retained_anchor").expect("first-retained");
    assert_eq!(
        FirstRetainedAnchor::from_entry(&first)
            .expect("layout")
            .first_retained_seq,
        6
    );
}

#[test]
fn anchor_file_of_newlines_is_bounded() {
    let (store, f, dir) = anchored_store();
    store.shutdown();
    std::fs::write(
        dir.path().join(file_name(&f.chain_id)),
        vec![b'\n'; 1 << 20],
    )
    .expect("write");
    let started = Instant::now();
    let fs = full_verify_fresh(&f);
    let mismatches = fs
        .iter()
        .filter(|x| x.kind == FindingKind::AnchorDirMismatch)
        .count();
    assert!(mismatches <= 20, "{mismatches} findings");
    let summaries = fs
        .iter()
        .filter(|x| x.detail.contains("more lines are not valid anchor lines"))
        .count();
    assert_eq!(summaries, 1, "{fs:?}");
    assert!(
        fs.iter()
            .any(|x| x.detail.contains("more than 1000000 lines")),
        "{fs:?}"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
}

#[test]
fn relative_anchor_dir_is_a_finding() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.shutdown();
    let fs = full_verify_with(&f, |cfg| cfg.anchor_dir = Some(PathBuf::from("anchors")));
    assert!(
        fs.iter().any(|x| x.kind == FindingKind::AnchorDirMismatch
            && x.detail.contains("not an absolute path")),
        "{fs:?}"
    );
}

#[test]
fn store_setting_wins_over_open_config() {
    // No setting: OpenConfig.anchor_dir is used.
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.shutdown();
    let bad = tempfile::tempdir().expect("dir");
    let line = AnchorLine::Record {
        seq: 1,
        record_hash: [0x42; 32],
        epoch: None,
        clock_behind: false,
    };
    write_lines(bad.path(), &f.chain_id, &[header(&f), line]);
    let fs = full_verify_with(&f, |cfg| cfg.anchor_dir = Some(bad.path().to_path_buf()));
    assert!(has(&fs, FindingKind::AnchorDirMismatch, 1), "{fs:?}");

    // With a setting, the store's own value is authoritative.
    let store = reopen_with(&f, |_| {});
    let good = tempfile::tempdir().expect("dir");
    store
        .apply_setting(
            SettingChange::AnchorDir(Some(dir_text(good.path()))),
            Some(confirmed()),
        )
        .expect("setting");
    store.shutdown();
    let fs = full_verify_with(&f, |cfg| cfg.anchor_dir = Some(bad.path().to_path_buf()));
    assert!(fs.is_empty(), "{fs:?}");
}

// ---------------------------------------------------------------------------------------
// prune lines and pruned records

#[test]
fn prune_line_mismatch() {
    let (store, f, dir) = anchored_store();
    corroborate(&store);
    store.append_batch(mixed(10)).expect("append");
    fake_prune(&store, dir.path(), 6, "2026-06-01");
    store.shutdown();
    let mut lines = vec![header(&f)];
    lines.extend(prune_lines(&f));
    write_lines(dir.path(), &f.chain_id, &lines);
    let fs = full_verify_fresh(&f);
    assert!(fs.is_empty(), "{fs:?}");

    let mut wrong = prune_lines(&f).pop().expect("a prune line");
    if let AnchorLine::Prune { cutoff_epoch, .. } = &mut wrong {
        *cutoff_epoch = "2026-06-02".into();
    }
    write_lines(dir.path(), &f.chain_id, &[header(&f), wrong]);
    let fs = full_verify_fresh(&f);
    assert!(has(&fs, FindingKind::AnchorDirMismatch, 6), "{fs:?}");
    assert!(has_kind(
        &verdict_findings(&f),
        FindingKind::AnchorDirMismatch
    ));
}

#[test]
fn u06_anchored_record_pruned_inside_retention() {
    let (store, f, dir) = anchored_store();
    corroborate(&store);
    store.append_batch(mixed(10)).expect("append");
    store.flush_head_anchor().expect("flush");
    let rows = dump_rows(&f);
    // A forged prune whose cutoff is not later than the anchored epoch 2026-10-08.
    fake_prune(&store, dir.path(), 8, "2026-06-01");
    store.shutdown();
    let mut lines = lines_for_rows(&f, &rows);
    lines.extend(prune_lines(&f));
    write_lines(dir.path(), &f.chain_id, &lines);

    let fs = full_verify_fresh(&f);
    let pruned_with_epoch: Vec<u64> = rows
        .iter()
        .filter(|r| r.seq < 8 && r.epoch.is_some())
        .map(|r| r.seq)
        .collect();
    assert!(!pruned_with_epoch.is_empty());
    for seq in &pruned_with_epoch {
        assert!(
            has(&fs, FindingKind::AnchoredRecordPrunedEarly, *seq),
            "{seq}: {fs:?}"
        );
    }
    // The NULL-epoch records are not judged; the retained ones match.
    for r in rows.iter().filter(|r| r.epoch.is_none() || r.seq >= 8) {
        assert!(
            !has(&fs, FindingKind::AnchoredRecordPrunedEarly, r.seq)
                && !has(&fs, FindingKind::AnchorDirMismatch, r.seq),
            "{}: {fs:?}",
            r.seq
        );
    }
    assert!(has_kind(
        &verdict_findings(&f),
        FindingKind::AnchoredRecordPrunedEarly
    ));
}

#[test]
fn anchored_record_pruned_after_retention_passes() {
    let (store, f, dir) = anchored_store();
    corroborate(&store);
    store.append_batch(mixed(10)).expect("append");
    // 100 days later the records of 2026-10-08 may go (cutoff 2026-10-09, retention 92).
    f.clock.advance(DAY * 100);
    corroborate_now(&store, &f.clock);
    store.append_batch(mixed(3)).expect("append");
    let first_new = store.head().0 - 2;
    store.flush_head_anchor().expect("flush");
    let rows = dump_rows(&f);
    fake_prune(&store, dir.path(), first_new, "2026-10-09");
    store.shutdown();
    let mut lines = lines_for_rows(&f, &rows);
    lines.extend(prune_lines(&f));
    write_lines(dir.path(), &f.chain_id, &lines);
    let fs = full_verify_fresh(&f);
    assert!(fs.is_empty(), "{fs:?}");
}

/// A store with a `clock_behind` episode: three records with the right clock (2026-10-08),
/// then the local clock 12 days behind the server (records flagged `clock_behind`, epoch held
/// at 2026-10-08), then the clock corrected (2026-10-20, unflagged). Returns the seqs of the
/// flagged records and of the first unflagged record after them.
fn behind_episode() -> (Store, Fixture, TempDir, Vec<u64>, u64) {
    let (store, f, dir) = anchored_store();
    corroborate(&store);
    store.append_batch(day_events(3)).expect("append");
    store.observe_server_date(
        "i1",
        server_time("2026-10-20T12:00:00.000Z"),
        Instant::now(),
    );
    store.append_batch(day_events(3)).expect("append");
    f.clock.set_wall(at("2026-10-20T12:30:00.000Z"));
    corroborate_now(&store, &f.clock);
    store.append_batch(day_events(3)).expect("append");
    store.flush_head_anchor().expect("flush");
    let rows = dump_rows(&f);
    let behind: Vec<u64> = rows
        .iter()
        .filter(|r| EventFlags::from_bits(r.flags).contains(EventFlags::BEHIND))
        .map(|r| r.seq)
        .collect();
    assert!(behind.len() >= 3, "episode records flagged");
    let last = *behind.last().expect("flagged");
    let witness = rows
        .iter()
        .find(|r| r.seq == last + 1)
        .expect("record after");
    assert!(!EventFlags::from_bits(witness.flags).contains(EventFlags::BEHIND));
    assert_eq!(&witness.ts_utc[..10], "2026-10-20");
    for r in rows.iter().filter(|r| behind.contains(&r.seq)) {
        assert_eq!(r.epoch.as_deref(), Some("2026-10-08"));
    }
    (store, f, dir, behind, last + 1)
}

#[test]
fn u14_anchored_clock_behind_pruned_early() {
    let (store, f, dir, behind, witness) = behind_episode();
    let rows = dump_rows(&f);
    // A forged prune removes the episode but keeps its first unflagged successor, whose
    // date(ts_utc) 2026-10-20 is not older than the cutoff: the episode was pruned early.
    // The cutoff is later than the held epoch, so the epoch rule alone would pass it.
    fake_prune(&store, dir.path(), witness, "2026-10-09");
    store.shutdown();
    let mut lines = lines_for_rows(&f, &rows);
    lines.extend(prune_lines(&f));
    write_lines(dir.path(), &f.chain_id, &lines);

    let fs = full_verify_fresh(&f);
    for seq in &behind {
        assert!(
            has(&fs, FindingKind::AnchoredRecordPrunedEarly, *seq),
            "{seq}: {fs:?}"
        );
    }
    // The records before the episode (epoch 2026-10-08 < cutoff) were pruned in time.
    for r in rows.iter().filter(|r| r.seq < behind[0]) {
        assert!(
            !has(&fs, FindingKind::AnchoredRecordPrunedEarly, r.seq),
            "{fs:?}"
        );
    }
}

#[test]
fn u14_clock_behind_pruned_with_its_successor_passes() {
    let (store, f, dir, behind, witness) = behind_episode();
    // 100 real days later the first unflagged record (2026-10-20) is older than the cutoff:
    // the episode goes together with it, as the §8.8 prefix rule allows.
    f.clock.advance(DAY * 100);
    corroborate_now(&store, &f.clock);
    store.append_batch(day_events(2)).expect("append");
    store.flush_head_anchor().expect("flush");
    let rows = dump_rows(&f);
    fake_prune(&store, dir.path(), witness + 1, "2026-10-21");
    store.shutdown();
    let mut lines = lines_for_rows(&f, &rows);
    lines.extend(prune_lines(&f));
    write_lines(dir.path(), &f.chain_id, &lines);

    let fs = full_verify_fresh(&f);
    assert!(fs.is_empty(), "{fs:?}");
    assert!(behind.iter().all(|s| *s < witness));
}
