//! Compliance export (§8.10, PD-159..PD-161, PD-181; T7): `Store::export` writes
//! `events.jsonl`, `prune_log.jsonl` and `manifest.json` (last) into a new subdirectory it
//! creates itself under a `.partial` staging name, then the store-owned `EXPORT
//! {manifest_sha256, first_seq, last_seq, rows}`, then renames the directory to its final name.
//! Every failure, a cancel and a failed final append leave no directory and no `EXPORT`, or
//! name the staging directory they could not remove.

mod common;

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use atlas_duck_audit::anchor_dir::{AnchorLine, file_name, to_line};
use atlas_duck_audit::encoding::FIELD_LIST;
use atlas_duck_audit::error::AuditError;
use atlas_duck_audit::export::MAX_EXPORT_PAYLOAD_FIELD_BYTES;
use atlas_duck_audit::testing::{self, FakePrune, FaultPoint, Faults, MemKeyring};
use atlas_duck_audit::types::{Actor, Confirmed, EventType, RustChosenPath};
use atlas_duck_audit::{
    ExportControl, ExportReceipt, MAX_EXPORT_LINE_BYTES, MAX_PAYLOAD_LEN, Store, TimeRange,
};
use atlas_duck_ipc::jcs::to_jcs_vec;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------------------
// helpers

/// The stamp of the fixture clock (`START`) in a directory name.
const STAMP: &str = "20261008T120000Z";

fn chosen(p: &Path) -> RustChosenPath {
    RustChosenPath::from_native_dialog(p.to_path_buf())
}

fn confirmed() -> Confirmed {
    Confirmed {
        dialog_text_sha256: [7; 32],
        dialog_lang: None,
    }
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// An export with no progress observer and no cancel.
fn export(store: &Store, out: &Path, range: TimeRange) -> Result<ExportReceipt, AuditError> {
    let cancel = AtomicBool::new(false);
    let progress = |_: u64, _: u64| {};
    store.export(
        range,
        chosen(out),
        &ExportControl {
            progress: &progress,
            cancel: &cancel,
        },
    )
}

fn dir_name(chain_id: &str, first: u64, last: u64) -> String {
    format!("atlas-duck-export-{chain_id}-{first}-{last}-{STAMP}")
}

/// The name the export directory has until the `EXPORT` record is logged.
fn staging_name(chain_id: &str, first: u64, last: u64) -> String {
    format!("{}.partial", dir_name(chain_id, first, last))
}

/// The entries of `out` (the chosen directory).
fn entries(out: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(out)
        .expect("read_dir")
        .map(|e| e.expect("entry").path())
        .collect();
    v.sort();
    v
}

fn file_names(dir: &Path) -> BTreeSet<String> {
    entries(dir)
        .iter()
        .map(|p| p.file_name().expect("name").to_string_lossy().into_owned())
        .collect()
}

/// Every line of `events.jsonl`, raw (without the `\n`).
fn raw_lines(dir: &Path) -> Vec<Vec<u8>> {
    let bytes = std::fs::read(dir.join("events.jsonl")).expect("events.jsonl");
    assert!(bytes.ends_with(b"\n"), "every line ends with a newline");
    bytes[..bytes.len() - 1]
        .split(|b| *b == b'\n')
        .map(<[u8]>::to_vec)
        .collect()
}

fn lines(dir: &Path) -> Vec<Value> {
    raw_lines(dir)
        .iter()
        .map(|l| serde_json::from_slice(l).expect("line is JSON"))
        .collect()
}

fn manifest(dir: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).expect("manifest"))
        .expect("manifest is JSON")
}

fn count(f: &Fixture, t: EventType) -> usize {
    dump_rows(f)
        .iter()
        .filter(|r| r.event_type == t.as_str())
        .count()
}

fn hex_of(v: &Value) -> Option<Vec<u8>> {
    v.as_str().map(|s| hex::decode(s).expect("lowercase hex"))
}

fn text_of(v: &Value) -> Option<String> {
    v.as_str().map(str::to_owned)
}

fn int_of(v: &Value) -> Option<u64> {
    v.as_u64()
}

fn hash32(v: &Value) -> [u8; 32] {
    hex_of(v).expect("hash").try_into().expect("32 bytes")
}

/// The row a line describes, rebuilt from its columns alone.
fn row_of(l: &Value) -> RawRow {
    RawRow {
        seq: int_of(&l["seq"]).expect("seq"),
        format_version: int_of(&l["format_version"]).expect("format_version"),
        chain_id: text_of(&l["chain_id"]).expect("chain_id"),
        ts_utc: text_of(&l["ts_utc"]).expect("ts_utc"),
        epoch: text_of(&l["epoch"]),
        request_id: text_of(&l["request_id"]),
        event_type: text_of(&l["event_type"]).expect("event_type"),
        op_id: text_of(&l["op_id"]),
        op_class: text_of(&l["op_class"]),
        instance_id: text_of(&l["instance_id"]),
        target: text_of(&l["target"]),
        agent_name: text_of(&l["agent_name"]),
        agent_name_source: text_of(&l["agent_name_source"]),
        client_kind: text_of(&l["client_kind"]),
        connection_id: text_of(&l["connection_id"]),
        peer_pid: int_of(&l["peer_pid"]),
        peer_exe: hex_of(&l["peer_exe"]),
        peer_origin_exe: hex_of(&l["peer_origin_exe"]),
        os_user: text_of(&l["os_user"]),
        atlassian_user: text_of(&l["atlassian_user"]),
        atlassian_user_key: text_of(&l["atlassian_user_key"]),
        decision: text_of(&l["decision"]),
        flags: int_of(&l["flags"]).expect("flags"),
        payload_len: int_of(&l["payload_len"]).expect("payload_len"),
        payload_sha256: hash32(&l["payload_sha256"]),
        key_id: int_of(&l["key_id"]).expect("key_id"),
        nonce: hex_of(&l["nonce"])
            .expect("nonce")
            .try_into()
            .expect("12 bytes"),
        payload_ct: STANDARD
            .decode(l["payload_ct"].as_str().expect("payload_ct"))
            .expect("payload_ct base64"),
        prev_hash: hash32(&l["prev_hash"]),
        record_hash: [0; 32],
    }
}

/// A few rows of every column shape, including the OS path columns.
fn varied(n: usize) -> Vec<atlas_duck_audit::NewEvent> {
    let mut evs = mixed(n);
    if let Some(e) = evs.get_mut(1) {
        e.actor = Actor {
            peer_exe: Some(PathBuf::from("/usr/bin/agent ü")),
            peer_origin_exe: Some(PathBuf::from("C:\\Tools\\origin.exe")),
            atlassian_user: Some("Ann \"Q\" Smith\n".into()),
            ..Actor::default()
        };
        e.op_id = Some("jira.issue.get".into());
    }
    evs
}

// ---------------------------------------------------------------------------------------
// format

#[test]
fn export_writes_three_files_manifest_last() {
    let faults = Faults::new();
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
        c.hooks.faults = Some(faults.clone());
        c.hooks.export_batch_rows = Some(4);
    });
    store.append_batch(varied(9)).expect("append");
    let (head, head_hash, chain) = store.head();
    let out = tempfile::tempdir().expect("out");
    let dir = out.path().join(dir_name(&chain, 1, head));
    let staging = out.path().join(staging_name(&chain, 1, head));

    // At every progress call only events.jsonl exists; at the final append all three do, all
    // in the staging directory: the final name appears only after the EXPORT is logged.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let at_append = Arc::new(Mutex::new(None));
    {
        let (dir, staging) = (dir.clone(), staging.clone());
        let at_append = at_append.clone();
        faults.on_hit(FaultPoint::ExportBeforeAppend, move || {
            assert!(!dir.exists(), "no final name before the EXPORT");
            *at_append.lock().expect("lock") = Some(file_names(&staging));
        });
    }
    let cancel = AtomicBool::new(false);
    let progress = |_: u64, _: u64| {
        assert!(!dir.exists(), "no final name before the EXPORT");
        seen.lock().expect("lock").push(file_names(&staging));
    };
    let r = store
        .export(
            TimeRange::all(),
            chosen(out.path()),
            &ExportControl {
                progress: &progress,
                cancel: &cancel,
            },
        )
        .expect("export");

    let only_events = BTreeSet::from(["events.jsonl".to_string()]);
    let seen = seen.lock().expect("lock").clone();
    assert_eq!(seen.len(), 3, "10 rows in batches of 4");
    assert!(seen.iter().all(|s| *s == only_events), "{seen:?}");
    let all = BTreeSet::from([
        "events.jsonl".to_string(),
        "manifest.json".to_string(),
        "prune_log.jsonl".to_string(),
    ]);
    assert_eq!(at_append.lock().expect("lock").clone(), Some(all.clone()));
    assert_eq!(file_names(&dir), all);
    assert_eq!(entries(out.path()), vec![dir.clone()], "one new directory");

    assert_eq!(r.dir_name, dir_name(&chain, 1, head));
    assert_eq!((r.first_seq, r.last_seq, r.rows), (1, head, head));
    assert_eq!(r.chain_ids, vec![chain.clone()]);
    assert_eq!(r.unanchored_from, None, "no anchor dir");

    // Every line is JCS with exactly the columns, and rebuilds its row's record_hash.
    let db = dump_rows(&f);
    let raw = raw_lines(&dir);
    assert_eq!(raw.len() as u64, head);
    let mut keys: BTreeSet<String> = FIELD_LIST.iter().map(|k| k.to_string()).collect();
    keys.insert("payload_b64".into());
    keys.insert("payload".into());
    for (i, l) in raw.iter().enumerate() {
        let v: Value = serde_json::from_slice(l).expect("JSON");
        assert_eq!(&to_jcs_vec(&v).expect("jcs"), l, "line {i} is not JCS");
        let got: BTreeSet<String> = v.as_object().expect("object").keys().cloned().collect();
        assert_eq!(got, keys, "line {i}");
        let rebuilt = row_of(&v);
        assert_eq!(rebuilt.seq, db[i].seq);
        assert_eq!(rebuilt.recompute(), db[i].record_hash, "line {i}");
    }
    let peer = &lines(&dir)[2];
    assert_eq!(
        hex_of(&peer["peer_exe"]),
        db[2].peer_exe.clone(),
        "OS paths as hex of the stored bytes"
    );

    let m = manifest(&dir);
    let events = std::fs::read(dir.join("events.jsonl")).expect("events");
    let prune_log = std::fs::read(dir.join("prune_log.jsonl")).expect("prune_log");
    assert!(prune_log.is_empty(), "no prune yet");
    let accountability = m["accountability"].as_str().expect("accountability");
    assert!(accountability.contains("accountable principal is the approving OS user"));
    assert_eq!(
        m,
        json!({
            "format": "atlas-duck-export/1",
            "app_version": atlas_duck_ipc::build_info::APP_VERSION,
            "build_id": atlas_duck_ipc::build_info::BUILD_ID,
            "exported_at": START,
            "install": {
                "install_id": f.install_id,
                "host": m["install"]["host"],
                "os_user": m["install"]["os_user"],
            },
            "requested_range": {
                "from_utc": "0000-01-01T00:00:00.000Z",
                "to_utc": "9999-12-31T23:59:59.999Z",
            },
            "first_seq": 1,
            "last_seq": head,
            "rows": head,
            "boundary_prev_hash": hex::encode([0u8; 32]),
            "head": { "seq": head, "record_hash": hex::encode(head_hash) },
            "chain_ids": [chain],
            "restore_records": [],
            "key_recovered_records": [],
            "anchor_dir_configured": false,
            "last_anchored_seq": null,
            "events_sha256": hex::encode(sha256(&events)),
            "prune_log_sha256": hex::encode(sha256(&prune_log)),
            "accountability": accountability,
        })
    );
    assert!(m["install"]["host"].as_str().is_some_and(|h| !h.is_empty()));
    assert!(
        m["install"]["os_user"]
            .as_str()
            .is_some_and(|u| !u.is_empty())
    );
}

#[test]
fn export_appends_export_record_with_manifest_hash() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(5)).expect("append");
    let (head, _, chain) = store.head();
    let out = tempfile::tempdir().expect("out");
    let r = export(&store, out.path(), TimeRange::all()).expect("export");
    let dir = out.path().join(&r.dir_name);
    let bytes = std::fs::read(dir.join("manifest.json")).expect("manifest");
    assert_eq!(r.manifest_sha256, sha256(&bytes));
    assert_eq!(r.export_seq, head + 1);
    assert_eq!(store.head().0, r.export_seq, "EXPORT is the new head");
    let rows = dump_rows(&f);
    let last = rows.last().expect("rows");
    assert_eq!(
        (last.seq, last.event_type.as_str()),
        (r.export_seq, "EXPORT")
    );
    assert_eq!(last.chain_id, chain);
    let payload: Value =
        serde_json::from_slice(&store.read_payload(r.export_seq).expect("payload")).expect("json");
    assert_eq!(
        payload,
        json!({
            "manifest_sha256": hex::encode(sha256(&bytes)),
            "first_seq": 1,
            "last_seq": head,
            "rows": head,
        })
    );
    // The EXPORT record itself is not in the export.
    assert_eq!(lines(&dir).len() as u64, head);
}

#[test]
fn export_range_resolution_widens_to_contiguous_seq() {
    let clock = fake_clock(START);
    let (store, f) = new_store(clock.clone(), MemKeyring::new());
    let t0 = at(START).0;
    let min = 60_000;
    // ts_utc is not monotonic: seqs 2..=6 at +10, +1, +20, +5 and +30 minutes.
    for m in [10, 1, 20, 5, 30] {
        clock.set_wall(atlas_duck_audit::UtcInstant(t0 + m * min));
        store
            .append(ev(EventType::APP_START, None, json!({ "m": m })))
            .expect("append");
    }
    clock.set_wall(at(START));
    let range = TimeRange {
        from_utc: atlas_duck_audit::UtcInstant(t0 + 5 * min),
        to_utc: atlas_duck_audit::UtcInstant(t0 + 20 * min),
    };

    // No record inside the times (between +20 and +30 nothing; first with ts >= +21 is seq 6,
    // last with ts <= +29 is seq 5): Invalid, nothing written.
    let empty = TimeRange {
        from_utc: atlas_duck_audit::UtcInstant(t0 + 21 * min),
        to_utc: atlas_duck_audit::UtcInstant(t0 + 29 * min),
    };
    let out2 = tempfile::tempdir().expect("out");
    assert!(matches!(
        export(&store, out2.path(), empty),
        Err(AuditError::Invalid(_))
    ));
    // A range that ends before it starts.
    let reversed = TimeRange {
        from_utc: range.to_utc,
        to_utc: range.from_utc,
    };
    assert!(matches!(
        export(&store, out2.path(), reversed),
        Err(AuditError::Invalid(_))
    ));
    assert!(entries(out2.path()).is_empty());
    assert_eq!(count(&f, EventType::EXPORT), 0);

    // First record with ts >= +5: seq 2 (+10); last with ts <= +20: seq 5 (+5). Seq 3 (+1) lies
    // outside the times and is exported all the same.
    let out = tempfile::tempdir().expect("out");
    let r = export(&store, out.path(), range).expect("export");
    assert_eq!((r.first_seq, r.last_seq, r.rows), (2, 5, 4));
    let dir = out.path().join(&r.dir_name);
    let seqs: Vec<u64> = lines(&dir)
        .iter()
        .map(|l| int_of(&l["seq"]).expect("seq"))
        .collect();
    assert_eq!(seqs, vec![2, 3, 4, 5]);
    let m = manifest(&dir);
    assert_eq!(
        m["requested_range"],
        json!({ "from_utc": "2026-10-08T12:05:00.000Z", "to_utc": "2026-10-08T12:20:00.000Z" })
    );
    let rows = dump_rows(&f);
    assert_eq!(m["boundary_prev_hash"], hex::encode(rows[1].prev_hash));
    assert_eq!(m["head"]["record_hash"], hex::encode(rows[4].record_hash));
    assert_eq!(count(&f, EventType::EXPORT), 1);
}

#[test]
fn export_full_range_default() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(8)).expect("append");
    testing::insert_fake_prune(
        &store,
        FakePrune {
            first_retained_seq: 4,
            cutoff: "2026-06-01".into(),
            settings: store.settings().to_json(),
            update_first_retained: false,
        },
    )
    .expect("prune");
    let (head, _, chain) = store.head();
    let out = tempfile::tempdir().expect("out");
    let r = export(&store, out.path(), TimeRange::all()).expect("export");
    assert_eq!((r.first_seq, r.last_seq), (4, head));
    assert_eq!(r.dir_name, dir_name(&chain, 4, head));
    let dir = out.path().join(&r.dir_name);
    let rows = dump_rows(&f);
    assert_eq!(rows[0].seq, 4);
    assert_eq!(
        manifest(&dir)["boundary_prev_hash"],
        hex::encode(rows[0].prev_hash)
    );
    // prune_log.jsonl: every row, every column.
    let pl = std::fs::read_to_string(dir.join("prune_log.jsonl")).expect("prune_log");
    let pl: Vec<Value> = pl
        .lines()
        .map(|l| serde_json::from_str(l).expect("JSON"))
        .collect();
    assert_eq!(pl.len(), 1);
    let keys: BTreeSet<&str> = pl[0]
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "cutoff_epoch",
            "first_retained_seq",
            "last_pruned_record_hash",
            "prev_row_hash",
            "prune_seq",
            "range_start",
            "row_hash",
        ])
    );
    assert_eq!(pl[0]["first_retained_seq"], 4);
    assert_eq!(pl[0]["range_start"], 1);
    assert_eq!(pl[0]["cutoff_epoch"], "2026-06-01");
}

#[test]
fn export_marks_unanchored_after_last_line() {
    let anchor = tempfile::tempdir().expect("anchor dir");
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    // seq 2: CONFIG_CHANGED anchor_dir, which gets an immediate line in the new dir.
    store
        .change_anchor_dir(Some(chosen(anchor.path())), confirmed())
        .expect("anchor dir");
    assert!(store.testing_anchor_dir_drain(), "anchor-dir lines written");
    // seqs 3..=5: NULL epoch, no daily line.
    store.append_batch(mixed(3)).expect("append");
    assert!(store.testing_anchor_dir_drain());
    let (head, _, chain) = store.head();
    assert_eq!(head, 5);
    // A forged line naming seq 5 with another hash anchors nothing.
    let forged = to_line(&AnchorLine::Record {
        seq: 5,
        record_hash: [9; 32],
        epoch: None,
        clock_behind: false,
    });
    std::fs::OpenOptions::new()
        .append(true)
        .open(anchor.path().join(file_name(&chain)))
        .and_then(|mut file| file.write_all(format!("{forged}\n").as_bytes()))
        .expect("forged line");

    let out = tempfile::tempdir().expect("out");
    let r = export(&store, out.path(), TimeRange::all()).expect("export");
    assert_eq!(r.unanchored_from, Some(3));
    let dir = out.path().join(&r.dir_name);
    let marks: Vec<Option<bool>> = lines(&dir)
        .iter()
        .map(|l| l.get("unanchored").map(|u| u.as_bool().expect("bool")))
        .collect();
    assert_eq!(marks, vec![None, None, Some(true), Some(true), Some(true)]);
    let m = manifest(&dir);
    assert_eq!(m["anchor_dir_configured"], true);
    assert_eq!(m["last_anchored_seq"], 2);
    assert_eq!(count(&f, EventType::EXPORT), 1);
}

#[test]
fn export_without_anchored_line_in_range_marks_every_row() {
    let anchor = tempfile::tempdir().expect("anchor dir");
    let clock = fake_clock(START);
    let (store, _f) = new_store(clock.clone(), MemKeyring::new());
    store
        .change_anchor_dir(Some(chosen(anchor.path())), confirmed())
        .expect("anchor dir");
    assert!(store.testing_anchor_dir_drain());
    clock.advance(Duration::from_secs(3600));
    let later = atlas_duck_audit::UtcInstant(at(START).0 + 3_600_000);
    store.append_batch(mixed(3)).expect("append");
    assert!(store.testing_anchor_dir_drain());
    let out = tempfile::tempdir().expect("out");
    // Only seqs 3..=5 (one hour later): the anchored seq 2 lies before the range.
    let r = export(
        &store,
        out.path(),
        TimeRange {
            from_utc: later,
            to_utc: atlas_duck_audit::UtcInstant(i64::MAX),
        },
    )
    .expect("export");
    assert_eq!((r.first_seq, r.last_seq), (3, 5));
    assert_eq!(r.unanchored_from, Some(3));
    let dir = out.path().join(&r.dir_name);
    assert!(lines(&dir).iter().all(|l| l["unanchored"] == true));
    assert_eq!(manifest(&dir)["last_anchored_seq"], Value::Null);
}

#[test]
fn export_refuses_existing_dir_name() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(3)).expect("append");
    let (head, _, chain) = store.head();
    // The final name and the staging name: neither is written into, renamed or removed.
    for name in [dir_name(&chain, 1, head), staging_name(&chain, 1, head)] {
        let out = tempfile::tempdir().expect("out");
        let taken = out.path().join(&name);
        std::fs::create_dir(&taken).expect("dir");
        std::fs::write(taken.join("keep.txt"), b"mine").expect("marker");
        assert_eq!(
            export(&store, out.path(), TimeRange::all()),
            Err(AuditError::Invalid(
                "an export directory of this name already exists"
            )),
            "{name}"
        );
        assert_eq!(entries(out.path()), vec![taken.clone()], "{name}");
        assert_eq!(file_names(&taken), BTreeSet::from(["keep.txt".to_string()]));
        assert_eq!(
            std::fs::read(taken.join("keep.txt")).expect("marker"),
            b"mine"
        );
    }
    assert_eq!(count(&f, EventType::EXPORT), 0);
}

/// The final name appears after the `EXPORT` was logged, before the rename: the user's entry is
/// not touched (an empty directory included, which `rename(2)` would replace) and the complete
/// export stays under its staging name (`ExportNotRenamed`).
#[test]
fn export_final_name_taken_before_rename_is_not_touched() {
    for marker in [true, false] {
        let faults = Faults::new();
        let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
            c.hooks.faults = Some(faults.clone());
        });
        store.append_batch(mixed(3)).expect("append");
        let (head, _, chain) = store.head();
        let out = tempfile::tempdir().expect("out");
        let taken = out.path().join(dir_name(&chain, 1, head));
        let staging = out.path().join(staging_name(&chain, 1, head));
        {
            let taken = taken.clone();
            faults.on_hit(FaultPoint::ExportBeforeAppend, move || {
                std::fs::create_dir(&taken).expect("dir");
                if marker {
                    std::fs::write(taken.join("keep.txt"), b"mine").expect("marker");
                }
            });
        }
        let r = match export(&store, out.path(), TimeRange::all()) {
            Err(AuditError::ExportNotRenamed(r)) => r,
            other => panic!("marker {marker}: not ExportNotRenamed: {other:?}"),
        };
        assert_eq!(r.dir_name, staging_name(&chain, 1, head));
        assert_eq!((r.first_seq, r.last_seq, r.export_seq), (1, head, head + 1));
        assert_eq!(count(&f, EventType::EXPORT), 1, "the export is logged");
        assert_eq!(entries(out.path()), vec![taken.clone(), staging.clone()]);
        if marker {
            assert_eq!(file_names(&taken), BTreeSet::from(["keep.txt".to_string()]));
            assert_eq!(
                std::fs::read(taken.join("keep.txt")).expect("marker"),
                b"mine"
            );
        } else {
            assert!(file_names(&taken).is_empty(), "the empty dir stays empty");
        }
        check_complete(&staging, &r);
    }
}

/// `staging` holds the three files of the logged export `r`.
fn check_complete(staging: &Path, r: &ExportReceipt) {
    assert_eq!(
        file_names(staging),
        BTreeSet::from([
            "events.jsonl".to_string(),
            "manifest.json".to_string(),
            "prune_log.jsonl".to_string(),
        ])
    );
    let bytes = std::fs::read(staging.join("manifest.json")).expect("manifest");
    assert_eq!(r.manifest_sha256, sha256(&bytes));
}

#[test]
fn export_location_must_be_an_absolute_directory() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let out = tempfile::tempdir().expect("out");
    let file = out.path().join("a-file");
    std::fs::write(&file, b"x").expect("file");
    let not_a_dir = "the export location is not a directory";
    for (bad, why) in [
        (file.clone(), not_a_dir),
        // Refused for being relative, whether or not it resolves to a directory.
        (
            PathBuf::from("relative-dir"),
            "the export location is not an absolute path",
        ),
        (out.path().join("missing"), not_a_dir),
    ] {
        assert_eq!(
            export(&store, &bad, TimeRange::all()),
            Err(AuditError::Invalid(why)),
            "{bad:?}"
        );
    }
    assert_eq!(entries(out.path()), vec![file]);
    assert_eq!(count(&f, EventType::EXPORT), 0);
}

#[test]
fn export_payload_b64_hashes_to_payload_sha256() {
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(varied(12)).expect("append");
    let out = tempfile::tempdir().expect("out");
    let r = export(&store, out.path(), TimeRange::all()).expect("export");
    let dir = out.path().join(&r.dir_name);
    for l in lines(&dir) {
        let seq = int_of(&l["seq"]).expect("seq");
        let plain = STANDARD
            .decode(l["payload_b64"].as_str().expect("payload_b64"))
            .expect("base64");
        assert_eq!(plain.len() as u64, int_of(&l["payload_len"]).expect("len"));
        assert_eq!(sha256(&plain), hash32(&l["payload_sha256"]), "seq {seq}");
        assert_eq!(
            plain,
            store.read_payload(seq).expect("payload").to_vec(),
            "seq {seq}"
        );
        let parsed: Value = serde_json::from_slice(&plain).expect("JSON payload");
        assert_eq!(l["payload"], parsed, "seq {seq}");
    }
}

#[test]
fn export_payload_field_only_up_to_1_mib() {
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    // JCS of {"s":"<n>"} is n + 8 bytes.
    let at_cap = MAX_EXPORT_PAYLOAD_FIELD_BYTES as usize - 8;
    store
        .append_batch(vec![
            ev(
                EventType::READ_FETCHED,
                None,
                json!({ "s": "a".repeat(at_cap) }),
            ),
            ev(
                EventType::READ_FETCHED,
                None,
                json!({ "s": "b".repeat(at_cap + 1) }),
            ),
        ])
        .expect("append");
    let out = tempfile::tempdir().expect("out");
    let r = export(&store, out.path(), TimeRange::all()).expect("export");
    let ls = lines(&out.path().join(&r.dir_name));
    let (a, b) = (&ls[1], &ls[2]);
    assert_eq!(
        int_of(&a["payload_len"]),
        Some(MAX_EXPORT_PAYLOAD_FIELD_BYTES)
    );
    assert_eq!(a["payload"]["s"].as_str().map(str::len), Some(at_cap));
    assert_eq!(
        int_of(&b["payload_len"]),
        Some(MAX_EXPORT_PAYLOAD_FIELD_BYTES + 1)
    );
    assert!(b.get("payload").is_none(), "no parsed copy above 1 MiB");
    let plain = STANDARD
        .decode(b["payload_b64"].as_str().expect("payload_b64"))
        .expect("base64");
    assert_eq!(sha256(&plain), hash32(&b["payload_sha256"]));
}

/// A 96 MiB plaintext (the largest the store takes), nearly incompressible: its line stays
/// within `MAX_EXPORT_LINE_BYTES` and carries the plaintext once (no `payload` copy).
#[test]
#[ignore = "CI: large-payload export step"]
fn export_line_cap_holds_for_max_payload() {
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let n = MAX_PAYLOAD_LEN as usize - 8;
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let s: String = (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ALPHABET[(x & 63) as usize] as char
        })
        .collect();
    let c = store
        .append(ev(EventType::READ_FETCHED, None, json!({ "s": s })))
        .expect("append the largest payload");
    drop(s);
    let out = tempfile::tempdir().expect("out");
    let r = export(&store, out.path(), TimeRange::all()).expect("export");
    let file = std::fs::File::open(out.path().join(&r.dir_name).join("events.jsonl"))
        .expect("events.jsonl");
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut found = false;
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).expect("read") == 0 {
            break;
        }
        let body = line.strip_suffix(b"\n").expect("newline");
        assert!(body.len() as u64 <= MAX_EXPORT_LINE_BYTES, "{}", body.len());
        let v: Value = serde_json::from_slice(body).expect("JSON");
        if int_of(&v["seq"]) == Some(c.seq) {
            found = true;
            assert_eq!(int_of(&v["payload_len"]), Some(MAX_PAYLOAD_LEN));
            assert!(v.get("payload").is_none());
            let plain = STANDARD
                .decode(v["payload_b64"].as_str().expect("payload_b64"))
                .expect("base64");
            assert_eq!(sha256(&plain), hash32(&v["payload_sha256"]));
        }
    }
    assert!(found, "the large row is exported");
}

// ---------------------------------------------------------------------------------------
// store-owned record, permissions

#[test]
fn append_refuses_export_event() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let e = store.append(ev(
        EventType::EXPORT,
        None,
        json!({ "manifest_sha256": hex::encode([1u8; 32]), "first_seq": 1, "last_seq": 1, "rows": 1 }),
    ));
    assert!(matches!(e, Err(AuditError::Invalid(_))), "{e:?}");
    assert_eq!(count(&f, EventType::EXPORT), 0);
}

#[cfg(unix)]
#[test]
fn export_files_owner_only_unix() {
    use std::os::unix::fs::PermissionsExt;
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(2)).expect("append");
    let out = tempfile::tempdir().expect("out");
    let r = export(&store, out.path(), TimeRange::all()).expect("export");
    let dir = out.path().join(&r.dir_name);
    let mode = |p: &Path| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    for name in ["events.jsonl", "prune_log.jsonl", "manifest.json"] {
        assert_eq!(mode(&dir.join(name)), 0o600, "{name}");
    }
}

// ---------------------------------------------------------------------------------------
// failures leave nothing behind

#[test]
fn export_append_failure_removes_dir() {
    // (a) The store is closed right before the final append.
    let faults = Faults::new();
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
        c.hooks.faults = Some(faults.clone());
    });
    store.append_batch(mixed(3)).expect("append");
    let handle = Mutex::new(Some(store.clone()));
    faults.on_hit(FaultPoint::ExportBeforeAppend, move || {
        if let Some(s) = handle.lock().expect("lock").take() {
            s.shutdown();
        }
    });
    let out = tempfile::tempdir().expect("out");
    let e = export(&store, out.path(), TimeRange::all());
    assert_eq!(e, Err(AuditError::Closed));
    assert!(entries(out.path()).is_empty(), "the export dir is removed");
    let types = testing::event_types(&f.data).expect("event types");
    assert!(!types.iter().any(|t| t == "EXPORT"), "{types:?}");

    // (b) The append itself fails; the store goes on.
    let faults = Faults::new();
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
        c.hooks.faults = Some(faults.clone());
    });
    store.append_batch(mixed(3)).expect("append");
    faults.fail(FaultPoint::ExportBeforeAppend, 1);
    let out = tempfile::tempdir().expect("out");
    assert!(matches!(
        export(&store, out.path(), TimeRange::all()),
        Err(AuditError::AppendFailed(_))
    ));
    assert!(entries(out.path()).is_empty(), "the export dir is removed");
    assert_eq!(count(&f, EventType::EXPORT), 0);
    let r = export(&store, out.path(), TimeRange::all()).expect("a retry exports");
    assert_eq!(entries(out.path()), vec![out.path().join(r.dir_name)]);
}

#[test]
fn export_cancel_removes_partial_dir() {
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
        c.hooks.export_batch_rows = Some(2);
    });
    store.append_batch(mixed(7)).expect("append");
    let (head, _, _) = store.head();
    // (a) Cancelled after the first batch; (b) after the last one, before the manifest.
    for cancel_at in [2, head] {
        let cancel = AtomicBool::new(false);
        let calls = Mutex::new(Vec::new());
        let progress = |done: u64, total: u64| {
            calls.lock().expect("lock").push((done, total));
            if done >= cancel_at {
                cancel.store(true, Ordering::SeqCst);
            }
        };
        let out = tempfile::tempdir().expect("out");
        let e = store.export(
            TimeRange::all(),
            chosen(out.path()),
            &ExportControl {
                progress: &progress,
                cancel: &cancel,
            },
        );
        assert_eq!(e, Err(AuditError::Cancelled), "cancel at {cancel_at}");
        assert!(entries(out.path()).is_empty(), "no partial dir");
        assert_eq!(count(&f, EventType::EXPORT), 0);
        assert_eq!(
            calls.lock().expect("lock").last().copied(),
            Some((cancel_at, head)),
            "no batch after the cancel"
        );
    }
}

#[test]
fn export_progress_reports_batches() {
    let (store, _f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
        c.hooks.export_batch_rows = Some(4);
    });
    store.append_batch(mixed(8)).expect("append");
    assert_eq!(store.head().0, 9);
    let cancel = AtomicBool::new(false);
    let calls = Mutex::new(Vec::new());
    let progress = |done: u64, total: u64| calls.lock().expect("lock").push((done, total));
    let out = tempfile::tempdir().expect("out");
    store
        .export(
            TimeRange::all(),
            chosen(out.path()),
            &ExportControl {
                progress: &progress,
                cancel: &cancel,
            },
        )
        .expect("export");
    assert_eq!(
        calls.into_inner().expect("lock"),
        vec![(4, 9), (8, 9), (9, 9)]
    );
}

#[test]
fn export_does_not_block_appends() {
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
        c.hooks.export_batch_rows = Some(2);
    });
    store.append_batch(mixed(5)).expect("append");
    let (head, _, _) = store.head();
    let appended = Mutex::new(Vec::new());
    let progress = |done: u64, _: u64| {
        if done != 2 {
            return;
        }
        // From another thread, bounded: a writer held by the export would time out here.
        let (tx, rx) = std::sync::mpsc::channel();
        let s = store.clone();
        std::thread::spawn(move || {
            let _ = tx.send(s.append(ev(EventType::APP_START, None, json!({ "during": true }))));
        });
        appended
            .lock()
            .expect("lock")
            .push(rx.recv_timeout(Duration::from_secs(10)));
    };
    let cancel = AtomicBool::new(false);
    let out = tempfile::tempdir().expect("out");
    let r = store
        .export(
            TimeRange::all(),
            chosen(out.path()),
            &ExportControl {
                progress: &progress,
                cancel: &cancel,
            },
        )
        .expect("export");
    let appended = appended.into_inner().expect("lock");
    assert_eq!(appended.len(), 1);
    let during = match &appended[0] {
        Ok(Ok(c)) => *c,
        other => panic!("the append during the export did not complete: {other:?}"),
    };
    assert_eq!(during.seq, head + 1);
    // The range was resolved before: the new row is not exported, the EXPORT comes after it.
    assert_eq!(r.last_seq, head);
    assert_eq!(r.export_seq, head + 2);
    assert_eq!(count(&f, EventType::EXPORT), 1);
}

#[test]
fn prune_between_batches_aborts_and_cleans_up() {
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
        c.hooks.export_batch_rows = Some(2);
    });
    store.append_batch(mixed(9)).expect("append");
    let pruned = Mutex::new(None);
    let progress = |done: u64, _: u64| {
        if done == 2 {
            // Rows 1..=5 go: 3..=5 are not exported yet.
            *pruned.lock().expect("lock") = Some(testing::insert_fake_prune(
                &store,
                FakePrune {
                    first_retained_seq: 6,
                    cutoff: "2026-06-01".into(),
                    settings: store.settings().to_json(),
                    update_first_retained: false,
                },
            ));
        }
    };
    let cancel = AtomicBool::new(false);
    let out = tempfile::tempdir().expect("out");
    let e = store.export(
        TimeRange::all(),
        chosen(out.path()),
        &ExportControl {
            progress: &progress,
            cancel: &cancel,
        },
    );
    assert!(
        matches!(pruned.lock().expect("lock").as_ref(), Some(Ok(_))),
        "the prune ran"
    );
    assert_eq!(
        e,
        Err(AuditError::Invalid(
            "a record of the export range is missing"
        ))
    );
    assert!(entries(out.path()).is_empty(), "the partial dir is removed");
    assert_eq!(count(&f, EventType::EXPORT), 0);
}

#[test]
fn prune_of_exported_rows_only_does_not_abort() {
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
        c.hooks.export_batch_rows = Some(2);
    });
    store.append_batch(mixed(5)).expect("append");
    let (head, _, _) = store.head();
    let pruned = Mutex::new(None);
    let progress = |done: u64, _: u64| {
        if done == 4 {
            // Rows 1..=4 go, all exported already (the batch boundary among them); 5 and 6
            // are still to come.
            *pruned.lock().expect("lock") = Some(testing::insert_fake_prune(
                &store,
                FakePrune {
                    first_retained_seq: 5,
                    cutoff: "2026-06-01".into(),
                    settings: store.settings().to_json(),
                    update_first_retained: false,
                },
            ));
        }
    };
    let cancel = AtomicBool::new(false);
    let out = tempfile::tempdir().expect("out");
    let r = store
        .export(
            TimeRange::all(),
            chosen(out.path()),
            &ExportControl {
                progress: &progress,
                cancel: &cancel,
            },
        )
        .expect("export");
    assert!(matches!(pruned.lock().expect("lock").as_ref(), Some(Ok(_))));
    assert_eq!((r.first_seq, r.last_seq), (1, head));
    let seqs: Vec<u64> = lines(&out.path().join(&r.dir_name))
        .iter()
        .map(|l| int_of(&l["seq"]).expect("seq"))
        .collect();
    assert_eq!(seqs, (1..=head).collect::<Vec<_>>());
    assert_eq!(count(&f, EventType::EXPORT), 1);
}

#[test]
fn export_aborts_when_exported_rows_change() {
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
        c.hooks.export_batch_rows = Some(2);
    });
    store.append_batch(mixed(5)).expect("append");
    let tampered = Mutex::new(false);
    let progress = |done: u64, _: u64| {
        if done == 2 {
            // The batch boundary (seq 2) is no longer the row that was written.
            let n = raw_conn(&f)
                .execute(
                    "UPDATE events SET record_hash = ?1 WHERE seq = 2",
                    [vec![0xAAu8; 32]],
                )
                .expect("tamper");
            *tampered.lock().expect("lock") = n == 1;
        }
    };
    let cancel = AtomicBool::new(false);
    let out = tempfile::tempdir().expect("out");
    let e = store.export(
        TimeRange::all(),
        chosen(out.path()),
        &ExportControl {
            progress: &progress,
            cancel: &cancel,
        },
    );
    assert!(*tampered.lock().expect("lock"), "row 2 was changed");
    assert_eq!(
        e,
        Err(AuditError::Invalid(
            "the exported records changed during the export"
        ))
    );
    assert!(entries(out.path()).is_empty());
    assert_eq!(count(&f, EventType::EXPORT), 0);
}

#[test]
fn export_fails_closed_on_an_undecryptable_row() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(4)).expect("append");
    raw_conn(&f)
        .execute(
            "UPDATE events SET payload_ct = ?1 WHERE seq = 3",
            [vec![0u8; 48]],
        )
        .expect("tamper");
    let out = tempfile::tempdir().expect("out");
    assert_eq!(
        export(&store, out.path(), TimeRange::all()),
        Err(AuditError::Decrypt { seq: 3 })
    );
    assert!(
        entries(out.path()).is_empty(),
        "no export without every payload"
    );
    assert_eq!(count(&f, EventType::EXPORT), 0);
}

#[test]
fn export_refuses_a_chain_id_that_is_not_an_id() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(2)).expect("append");
    raw_conn(&f)
        .execute(
            "UPDATE events SET chain_id = '../../escape' WHERE seq = 1",
            [],
        )
        .expect("tamper");
    let out = tempfile::tempdir().expect("out");
    let e = export(&store, out.path(), TimeRange::all());
    assert!(
        matches!(e, Err(AuditError::InvalidRecord { seq: 1, .. })),
        "{e:?}"
    );
    assert!(entries(out.path()).is_empty());
    assert_eq!(count(&f, EventType::EXPORT), 0);
}

/// I-1: the cleanup of a failed export cannot remove its directory. `manifest.json` is unlinked
/// first all the same, and the error names the leftover (it holds decrypted records).
#[test]
fn export_cleanup_failure_names_the_leftover() {
    let faults = Faults::new();
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
        c.hooks.faults = Some(faults.clone());
    });
    store.append_batch(mixed(3)).expect("append");
    let (head, _, chain) = store.head();
    faults.fail(FaultPoint::ExportBeforeAppend, 1);
    let out = tempfile::tempdir().expect("out");
    testing::fail_remove_dir_under(out.path());
    let e = export(&store, out.path(), TimeRange::all());
    let (dir_name, cause) = match e {
        Err(AuditError::ExportLeftover { dir_name, cause }) => (dir_name, cause),
        other => panic!("not ExportLeftover: {other:?}"),
    };
    assert_eq!(dir_name, staging_name(&chain, 1, head));
    assert!(
        matches!(*cause, AuditError::AppendFailed(_)),
        "the export's own error: {cause:?}"
    );
    let left = out.path().join(&dir_name);
    assert_eq!(entries(out.path()), vec![left.clone()]);
    assert_eq!(
        file_names(&left),
        BTreeSet::from(["events.jsonl".to_string(), "prune_log.jsonl".to_string()]),
        "manifest.json is gone: the leftover never reads as an export"
    );
    assert_eq!(count(&f, EventType::EXPORT), 0);
}

/// I-3 (PD-181 quit): a cancel set while a batch runs ends the export before the next row of
/// that batch, not at the batch's end.
#[test]
fn export_cancel_mid_batch_stops_before_the_next_row() {
    let faults = Faults::new();
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
        c.hooks.faults = Some(faults.clone());
        c.hooks.export_batch_rows = Some(10);
    });
    store.append_batch(mixed(5)).expect("append");
    assert_eq!(store.head().0, 6, "one batch holds every row");
    let cancel = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(AtomicU32::new(0));
    {
        let (cancel, hits) = (cancel.clone(), hits.clone());
        faults.on_hit(FaultPoint::ExportRow, move || {
            if hits.fetch_add(1, Ordering::SeqCst) + 1 == 3 {
                cancel.store(true, Ordering::SeqCst);
            }
        });
    }
    let progress_calls = AtomicU32::new(0);
    let progress = |_: u64, _: u64| {
        progress_calls.fetch_add(1, Ordering::SeqCst);
    };
    let out = tempfile::tempdir().expect("out");
    let e = store.export(
        TimeRange::all(),
        chosen(out.path()),
        &ExportControl {
            progress: &progress,
            cancel: &cancel,
        },
    );
    assert_eq!(e, Err(AuditError::Cancelled));
    assert_eq!(hits.load(Ordering::SeqCst), 3, "no row after the cancel");
    assert_eq!(
        progress_calls.load(Ordering::SeqCst),
        0,
        "the cancel was taken inside the batch"
    );
    assert!(entries(out.path()).is_empty(), "no partial dir");
    let types = testing::event_types(&f.data).expect("event types");
    assert!(!types.iter().any(|t| t == "EXPORT"), "{types:?}");
}

/// M-10: a restore (the store file generation moves on) between batches ends the export before
/// the next batch.
#[test]
fn export_restore_between_batches_aborts() {
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
        c.hooks.export_batch_rows = Some(2);
    });
    store.append_batch(mixed(5)).expect("append");
    let calls = Mutex::new(Vec::new());
    let progress = |done: u64, _: u64| {
        calls.lock().expect("lock").push(done);
        if done == 2 {
            store.testing_bump_generation();
        }
    };
    let cancel = AtomicBool::new(false);
    let out = tempfile::tempdir().expect("out");
    let e = store.export(
        TimeRange::all(),
        chosen(out.path()),
        &ExportControl {
            progress: &progress,
            cancel: &cancel,
        },
    );
    assert_eq!(
        e,
        Err(AuditError::Invalid(
            "the store was restored while the export ran"
        ))
    );
    assert_eq!(
        calls.into_inner().expect("lock"),
        vec![2],
        "no batch after the restore"
    );
    assert!(entries(out.path()).is_empty());
    assert_eq!(count(&f, EventType::EXPORT), 0);
}

/// M-10: a restore after the last check, right before the append: the writer refuses the
/// `EXPORT` computed from the old store file, and the directory goes.
#[test]
fn export_restore_before_append_is_refused_by_the_writer() {
    let faults = Faults::new();
    let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
        c.hooks.faults = Some(faults.clone());
    });
    store.append_batch(mixed(3)).expect("append");
    let handle = Mutex::new(Some(store.clone()));
    faults.on_hit(FaultPoint::ExportBeforeAppend, move || {
        if let Some(s) = handle.lock().expect("lock").take() {
            s.testing_bump_generation();
        }
    });
    let out = tempfile::tempdir().expect("out");
    assert_eq!(
        export(&store, out.path(), TimeRange::all()),
        Err(AuditError::Invalid(
            "the store was restored while this record was prepared"
        ))
    );
    assert!(entries(out.path()).is_empty());
    assert_eq!(count(&f, EventType::EXPORT), 0);
}

/// M-10: a configured anchor dir that cannot be read anchors nothing: every row is marked.
#[test]
fn export_with_unreadable_anchor_dir_marks_every_row() {
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    let gone = tempfile::tempdir().expect("parent");
    let missing = gone.path().join("offline-share");
    store
        .testing_set_anchor_dir(Some(missing.to_string_lossy().into_owned()), confirmed())
        .expect("anchor dir");
    store.append_batch(mixed(3)).expect("append");
    let (head, _, _) = store.head();
    let out = tempfile::tempdir().expect("out");
    let r = export(&store, out.path(), TimeRange::all()).expect("export");
    assert_eq!(r.unanchored_from, Some(1));
    let dir = out.path().join(&r.dir_name);
    let ls = lines(&dir);
    assert_eq!(ls.len() as u64, head);
    assert!(ls.iter().all(|l| l["unanchored"] == true));
    let m = manifest(&dir);
    assert_eq!(m["anchor_dir_configured"], true);
    assert_eq!(m["last_anchored_seq"], Value::Null);
}

/// M-10: a line with the right seq and `record_hash`, but in another chain's file, anchors
/// nothing.
#[test]
fn export_line_of_another_chain_does_not_anchor() {
    let anchor = tempfile::tempdir().expect("anchor dir");
    let clock = fake_clock(START);
    let (store, f) = new_store(clock.clone(), MemKeyring::new());
    clock.advance(Duration::from_secs(3600));
    let later = atlas_duck_audit::UtcInstant(at(START).0 + 3_600_000);
    store
        .change_anchor_dir(Some(chosen(anchor.path())), confirmed())
        .expect("anchor dir");
    assert!(store.testing_anchor_dir_drain());
    store.append_batch(mixed(3)).expect("append");
    assert!(store.testing_anchor_dir_drain());
    assert_eq!(store.head().0, 5);
    // Seq 1 (outside the exported range: its payload no longer decrypts) now names another
    // chain, so that chain's file is read too.
    let other = "f".repeat(32);
    raw_conn(&f)
        .execute("UPDATE events SET chain_id = ?1 WHERE seq = 1", [&other])
        .expect("tamper");
    let rows = dump_rows(&f);
    let line = to_line(&AnchorLine::Record {
        seq: 5,
        record_hash: rows[4].record_hash,
        epoch: None,
        clock_behind: false,
    });
    std::fs::write(anchor.path().join(file_name(&other)), format!("{line}\n")).expect("line");

    let out = tempfile::tempdir().expect("out");
    let r = export(
        &store,
        out.path(),
        TimeRange {
            from_utc: later,
            to_utc: atlas_duck_audit::UtcInstant(i64::MAX),
        },
    )
    .expect("export");
    assert_eq!((r.first_seq, r.last_seq), (2, 5));
    assert_eq!(r.unanchored_from, Some(3), "seq 5 is not anchored");
    assert_eq!(
        manifest(&out.path().join(&r.dir_name))["last_anchored_seq"],
        2
    );
}

/// M-10: a hole in the seqs that was always there ends the export, at a batch start and inside a
/// batch, with a message that does not claim a removal during the export.
#[test]
fn export_seq_gap_fails_closed() {
    for (batch_rows, want) in [
        (
            2,
            AuditError::Invalid("a record of the export range is missing"),
        ),
        (
            10,
            AuditError::InvalidRecord {
                seq: 3,
                what: "the record is missing",
            },
        ),
    ] {
        let (store, f) = new_store_with(fake_clock(START), MemKeyring::new(), |c| {
            c.hooks.export_batch_rows = Some(batch_rows);
        });
        store.append_batch(mixed(5)).expect("append");
        let n = raw_conn(&f)
            .execute("DELETE FROM events WHERE seq = 3", [])
            .expect("hole");
        assert_eq!(n, 1);
        let out = tempfile::tempdir().expect("out");
        assert_eq!(
            export(&store, out.path(), TimeRange::all()),
            Err(want),
            "batches of {batch_rows}"
        );
        assert!(entries(out.path()).is_empty());
        assert_eq!(count(&f, EventType::EXPORT), 0);
    }
}

#[test]
fn export_on_a_closed_store_is_closed() {
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    store.shutdown();
    let out = tempfile::tempdir().expect("out");
    assert_eq!(
        export(&store, out.path(), TimeRange::all()),
        Err(AuditError::Closed)
    );
    assert!(entries(out.path()).is_empty());
}

// ---------------------------------------------------------------------------------------
// M14 T18: TimeRange::through_seq (PD-254)

fn export_through(
    store: &Store,
    out: &Path,
    range: atlas_duck_audit::SeqBoundRange,
) -> Result<ExportReceipt, AuditError> {
    let cancel = AtomicBool::new(false);
    let progress = |_: u64, _: u64| {};
    store.export_through(
        range,
        chosen(out),
        &ExportControl {
            progress: &progress,
            cancel: &cancel,
        },
    )
}

#[test]
fn through_seq_ends_exactly_at_the_seq() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(6)).expect("append");
    let head = store.head().0;
    let all = TimeRange::all();
    // Ends at seq 4 although later rows are inside every time bound.
    let out = tempfile::tempdir().expect("out");
    let r = export_through(&store, out.path(), TimeRange::through_seq(all.from_utc, 4))
        .expect("export");
    assert_eq!((r.first_seq, r.last_seq, r.rows), (1, 4, 4));
    let dir = out.path().join(&r.dir_name);
    assert_eq!(lines(&dir).len(), 4);
    let m: Value = serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap())
        .expect("manifest");
    assert_eq!(m["head"]["seq"], 4);
    assert_eq!(m["requested_range"]["to_utc"], all.to_utc.to_rfc3339_ms());
    // Through the head: everything; the EXPORT row of the first export is beyond it.
    let out = tempfile::tempdir().expect("out");
    let r = export_through(
        &store,
        out.path(),
        TimeRange::through_seq(all.from_utc, head),
    )
    .expect("export");
    assert_eq!(r.last_seq, head);
    assert_eq!(count(&f, EventType::EXPORT), 2);
}

#[test]
fn through_seq_beyond_the_head_or_before_the_range_is_refused() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(3)).expect("append");
    let head = store.head().0;
    let all = TimeRange::all();
    let out = tempfile::tempdir().expect("out");
    match export_through(
        &store,
        out.path(),
        TimeRange::through_seq(all.from_utc, head + 1),
    ) {
        Err(AuditError::Invalid(why)) => {
            assert_eq!(why, atlas_duck_audit::export::EXPORT_BEYOND_HEAD)
        }
        other => panic!("{other:?}"),
    }
    // A from-time after every record: no records.
    let late = atlas_duck_audit::UtcInstant(i64::MAX);
    assert!(matches!(
        export_through(&store, out.path(), TimeRange::through_seq(late, head)),
        Err(AuditError::Invalid(_))
    ));
    assert!(entries(out.path()).is_empty());
    assert_eq!(count(&f, EventType::EXPORT), 0);
}
