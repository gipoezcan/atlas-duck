//! The export verifier (§8.10 `verify-export`, PD-162, PD-163, §12.1 exit codes; T8): exit 0
//! against a trust root that covers the whole export, 20 when internally consistent without one,
//! 21 on tamper or fork, 22 when the input cannot be read as an export. It reads only the export
//! directory and the anchor dir, never a key, and bounds its memory whatever the input.
//!
//! The counting allocator below is per thread (the verifier runs on its caller's thread), so the
//! tests of this binary may run in parallel without polluting each other's peaks.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use atlas_duck_audit::anchor_dir::{AnchorLine, file_name, to_line};
use atlas_duck_audit::clock::Clock;
use atlas_duck_audit::testing::{self, FakePrune, FixtureKind, MemKeyring};
use atlas_duck_audit::types::{Confirmed, EventType, RustChosenPath};
use atlas_duck_audit::verify_export::{FsRead, Limits, OsFs, verify_export_with};
use atlas_duck_audit::{
    ExportControl, ExportReceipt, ExportVerdict, MAX_EXPORT_LINE_BYTES, MAX_PAYLOAD_LEN, Store,
    TimeRange, UtcInstant, verify_export,
};
use atlas_duck_ipc::jcs::to_jcs_vec;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, TestCaseError, TestRunner};
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------------------
// A per-thread counting allocator

struct Counting;

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn grew(n: usize) {
    let _ = LIVE.try_with(|l| {
        let now = l.get().saturating_add(n as isize);
        l.set(now);
        let _ = PEAK.try_with(|p| {
            if now > p.get() {
                p.set(now);
            }
        });
    });
}

fn shrank(n: usize) {
    let _ = LIVE.try_with(|l| l.set(l.get().saturating_sub(n as isize)));
}

// SAFETY: every call forwards to `System` with the caller's arguments; the counters only observe.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc` is passed through unchanged.
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            grew(l.size());
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: the caller's contract for `dealloc` is passed through unchanged.
        unsafe { System.dealloc(p, l) };
        shrank(l.size());
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        // SAFETY: the caller's contract for `realloc` is passed through unchanged.
        let q = unsafe { System.realloc(p, l, new) };
        if !q.is_null() {
            if new >= l.size() {
                grew(new - l.size());
            } else {
                shrank(l.size() - new);
            }
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// `f`'s result and the peak heap of this thread above its live bytes at the start of `f`.
fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.with(Cell::get);
    PEAK.with(|p| p.set(base));
    let t = f();
    let peak = PEAK.with(Cell::get) - base;
    (t, usize::try_from(peak).unwrap_or(0))
}

// ---------------------------------------------------------------------------------------
// helpers

fn chosen(p: &Path) -> RustChosenPath {
    RustChosenPath::from_native_dialog(p.to_path_buf())
}

fn confirmed() -> Confirmed {
    Confirmed {
        dialog_text_sha256: [7; 32],
    }
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// An export and the directory it lives in.
struct Exported {
    _out: tempfile::TempDir,
    dir: PathBuf,
    hash: [u8; 32],
    receipt: ExportReceipt,
}

fn export(store: &Store, range: TimeRange) -> Exported {
    let out = tempfile::tempdir().expect("out");
    let cancel = AtomicBool::new(false);
    let progress = |_: u64, _: u64| {};
    let receipt = store
        .export(
            range,
            chosen(out.path()),
            &ExportControl {
                progress: &progress,
                cancel: &cancel,
            },
        )
        .expect("export");
    let dir = out.path().join(&receipt.dir_name);
    let hash = sha256(&std::fs::read(dir.join("manifest.json")).expect("manifest"));
    assert_eq!(hash, receipt.manifest_sha256);
    Exported {
        _out: out,
        dir,
        hash,
        receipt,
    }
}

fn export_all(store: &Store) -> Exported {
    export(store, TimeRange::all())
}

/// A copy of the export's three files under the same directory name (each tamper case gets
/// its own).
struct Copy {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
}

fn copy_export(src: &Path) -> Copy {
    let tmp = tempfile::tempdir().expect("copy");
    let dir = tmp.path().join(src.file_name().expect("name"));
    std::fs::create_dir(&dir).expect("dir");
    for f in ["events.jsonl", "prune_log.jsonl", "manifest.json"] {
        std::fs::copy(src.join(f), dir.join(f)).expect("copy file");
    }
    Copy { _tmp: tmp, dir }
}

fn last(v: &ExportVerdict) -> &str {
    v.report().last().map(String::as_str).unwrap_or("")
}

fn has_line(v: &ExportVerdict, line: &str) -> bool {
    v.report().iter().any(|l| l == line)
}

fn has_prefix(v: &ExportVerdict, prefix: &str) -> bool {
    v.report().iter().any(|l| l.starts_with(prefix))
}

#[track_caller]
fn expect(v: &ExportVerdict, code: u8, what: &str) {
    assert_eq!(v.exit_code(), code, "{what}: {:#?}", v.report());
}

const MANIFEST_OK: &str = "verified against the manifest SHA-256";
const ANCHOR_OK: &str = "verified against the anchor dir";
const BOTH_OK: &str = "verified against the manifest SHA-256 and the anchor dir";
const NO_ROOT: &str = "internally consistent; trust root NOT verified";

fn hex_of(v: &Value) -> Option<Vec<u8>> {
    v.as_str().map(|s| hex::decode(s).expect("lowercase hex"))
}

fn text_of(v: &Value) -> Option<String> {
    v.as_str().map(str::to_owned)
}

fn hash32(v: &Value) -> [u8; 32] {
    hex_of(v).expect("hash").try_into().expect("32 bytes")
}

/// The row a line describes, rebuilt from its columns alone.
fn row_of(l: &Value) -> RawRow {
    RawRow {
        seq: l["seq"].as_u64().expect("seq"),
        format_version: l["format_version"].as_u64().expect("format_version"),
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
        peer_pid: l["peer_pid"].as_u64(),
        peer_exe: hex_of(&l["peer_exe"]),
        peer_origin_exe: hex_of(&l["peer_origin_exe"]),
        os_user: text_of(&l["os_user"]),
        atlassian_user: text_of(&l["atlassian_user"]),
        atlassian_user_key: text_of(&l["atlassian_user_key"]),
        decision: text_of(&l["decision"]),
        flags: l["flags"].as_u64().expect("flags"),
        payload_len: l["payload_len"].as_u64().expect("payload_len"),
        payload_sha256: hash32(&l["payload_sha256"]),
        key_id: l["key_id"].as_u64().expect("key_id"),
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

/// An export as an attacker without any key sees it: every line, the manifest and the
/// `prune_log` rows, rewritten consistently on `save` (file hashes, manifest).
struct Forge {
    dir: PathBuf,
    manifest: Value,
    lines: Vec<Value>,
    prune: Vec<Value>,
}

fn jsonl(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .expect("jsonl")
        .lines()
        .map(|l| serde_json::from_str(l).expect("JSON line"))
        .collect()
}

fn jcs_lines(vs: &[Value]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in vs {
        out.extend(to_jcs_vec(v).expect("jcs"));
        out.push(b'\n');
    }
    out
}

impl Forge {
    fn load(dir: &Path) -> Forge {
        Forge {
            dir: dir.to_path_buf(),
            manifest: serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap())
                .unwrap(),
            lines: jsonl(&dir.join("events.jsonl")),
            prune: jsonl(&dir.join("prune_log.jsonl")),
        }
    }

    /// Recomputes every `record_hash` and link after the first line (keeping its `prev_hash`)
    /// and the manifest's range claims.
    fn rehash(&mut self) {
        let mut prev: Option<[u8; 32]> = None;
        for l in &mut self.lines {
            if let Some(p) = prev {
                l["prev_hash"] = json!(hex::encode(p));
            }
            prev = Some(row_of(l).recompute());
        }
        let first = &self.lines[0];
        let lastl = self.lines.last().expect("lines");
        let mut chains: Vec<String> = Vec::new();
        for l in &self.lines {
            let c = l["chain_id"].as_str().expect("chain").to_string();
            if chains.last() != Some(&c) {
                chains.push(c);
            }
        }
        let (first_seq, last_seq) = (first["seq"].clone(), lastl["seq"].clone());
        let boundary = first["prev_hash"].clone();
        let m = &mut self.manifest;
        m["first_seq"] = first_seq;
        m["last_seq"] = last_seq.clone();
        m["rows"] = json!(self.lines.len());
        m["boundary_prev_hash"] = boundary;
        m["head"] = json!({ "seq": last_seq, "record_hash": hex::encode(prev.expect("rows")) });
        m["chain_ids"] = json!(chains);
    }

    /// The `record_hash` of line `i` as it stands.
    fn record_hash(&self, i: usize) -> [u8; 32] {
        row_of(&self.lines[i]).recompute()
    }

    fn save(&mut self) -> [u8; 32] {
        let events = jcs_lines(&self.lines);
        let prune = jcs_lines(&self.prune);
        self.manifest["events_sha256"] = json!(hex::encode(sha256(&events)));
        self.manifest["prune_log_sha256"] = json!(hex::encode(sha256(&prune)));
        std::fs::write(self.dir.join("events.jsonl"), events).expect("events");
        std::fs::write(self.dir.join("prune_log.jsonl"), prune).expect("prune_log");
        let m = to_jcs_vec(&self.manifest).expect("manifest");
        std::fs::write(self.dir.join("manifest.json"), &m).expect("manifest");
        sha256(&m)
    }

    /// Recomputes the `prune_log` row hash chain (the row hash is unkeyed).
    fn rehash_prune_log(&mut self) {
        let mut prev = [0u8; 32];
        for r in &mut self.prune {
            r["prev_row_hash"] = json!(hex::encode(prev));
            let h = atlas_duck_audit::encoding::prune_row_hash(
                &prev,
                r["prune_seq"].as_u64().expect("prune_seq"),
                r["range_start"].as_u64().expect("range_start"),
                r["cutoff_epoch"].as_str().expect("cutoff"),
                &hash32(&r["last_pruned_record_hash"]),
                r["first_retained_seq"].as_u64().expect("frs"),
            );
            r["row_hash"] = json!(hex::encode(h));
            prev = h;
        }
    }
}

/// Raw `events.jsonl` lines (without their newlines).
fn raw_lines(dir: &Path) -> Vec<Vec<u8>> {
    let bytes = std::fs::read(dir.join("events.jsonl")).expect("events");
    bytes[..bytes.len() - 1]
        .split(|b| *b == b'\n')
        .map(<[u8]>::to_vec)
        .collect()
}

fn write_raw_lines(dir: &Path, lines: &[Vec<u8>]) {
    let mut out = Vec::new();
    for l in lines {
        out.extend_from_slice(l);
        out.push(b'\n');
    }
    std::fs::write(dir.join("events.jsonl"), out).expect("events");
}

/// Edits line `i` as a JSON value and writes it back in JCS form; nothing else changes.
fn edit_line(dir: &Path, i: usize, f: impl FnOnce(&mut Value)) {
    let mut lines = raw_lines(dir);
    let mut v: Value = serde_json::from_slice(&lines[i]).expect("line");
    f(&mut v);
    lines[i] = to_jcs_vec(&v).expect("jcs");
    write_raw_lines(dir, &lines);
}

fn append_anchor_line(anchor: &Path, chain: &str, line: &AnchorLine) {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(anchor.join(file_name(chain)))
        .expect("chain file");
    file.write_all(format!("{}\n", to_line(line)).as_bytes())
        .expect("line");
}

fn record_line(seq: u64, record_hash: [u8; 32]) -> AnchorLine {
    AnchorLine::Record {
        seq,
        record_hash,
        epoch: None,
        clock_behind: false,
    }
}

fn fake_prune(store: &Store, cutoff: &str, settings: Value) -> u64 {
    let c = testing::insert_fake_prune(
        store,
        FakePrune {
            first_retained_seq: 1,
            cutoff: cutoff.into(),
            settings,
            update_first_retained: false,
        },
    )
    .expect("prune");
    c.seq
}

/// A store with an anchor dir: seq 2 (`CONFIG_CHANGED anchor_dir`) and seq 9 (`PRUNE`, with its
/// `Prune` line) have immediate lines; seqs 3..=8 are unanchored. The last row is anchored.
fn anchored_store() -> (Store, Fixture, tempfile::TempDir) {
    let anchor = tempfile::tempdir().expect("anchor dir");
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store
        .change_anchor_dir(Some(chosen(anchor.path())), confirmed())
        .expect("anchor dir");
    store.append_batch(mixed(6)).expect("append");
    let seq = fake_prune(&store, "2026-06-01", store.settings().to_json());
    assert_eq!(seq, 9);
    assert!(store.testing_anchor_dir_drain(), "anchor-dir lines written");
    (store, f, anchor)
}

fn basic_store(n: usize) -> (Store, Fixture) {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(varied(n)).expect("append");
    (store, f)
}

/// `mixed`, with OS path columns and text that needs escaping on one row.
fn varied(n: usize) -> Vec<atlas_duck_audit::NewEvent> {
    let mut evs = mixed(n);
    if let Some(e) = evs.get_mut(1) {
        e.actor = atlas_duck_audit::types::Actor {
            peer_exe: Some(PathBuf::from("/usr/bin/agent ü")),
            peer_origin_exe: Some(PathBuf::from("C:\\Tools\\origin.exe")),
            atlassian_user: Some("Ann \"Q\" Smith\n".into()),
            ..Default::default()
        };
    }
    evs
}

// ---------------------------------------------------------------------------------------
// S-03 and the trust-root verdicts

#[test]
fn s03_verify_pass_tamper_no_trust_root() {
    let (store, _f) = basic_store(12);
    let ex = export_all(&store);
    let v = verify_export(&ex.dir, None, Some(ex.hash));
    expect(&v, 0, "pass with the manifest hash");
    assert_eq!(last(&v), MANIFEST_OK);

    let v = verify_export(&ex.dir, None, None);
    expect(&v, 20, "no trust root");
    assert_eq!(last(&v), NO_ROOT);

    let c = copy_export(&ex.dir);
    edit_line(&c.dir, 3, |l| l["target"] = json!("tampered"));
    let v = verify_export(&c.dir, None, Some(ex.hash));
    expect(&v, 21, "tamper");
    assert!(last(&v).starts_with("TAMPERED: "), "{:?}", v.report());
}

#[test]
fn export_fixture_kinds_verify_as_documented() {
    for kind in [
        FixtureKind::Pass,
        FixtureKind::Tamper,
        FixtureKind::NoTrustRoot,
    ] {
        let out = tempfile::tempdir().expect("out");
        let info = testing::export_fixture(kind, out.path()).expect("fixture");
        let hash = (kind != FixtureKind::NoTrustRoot).then_some(info.manifest_sha256);
        let v = verify_export(&info.dir, None, hash);
        assert_eq!(
            v.exit_code(),
            info.expected_exit,
            "{kind:?}: {:#?}",
            v.report()
        );
        // Only the export directory is left in `out`.
        let names: Vec<PathBuf> = std::fs::read_dir(out.path())
            .expect("out")
            .map(|e| e.expect("entry").path())
            .collect();
        assert_eq!(names, vec![info.dir.clone()], "{kind:?}");
    }
}

/// T36b item 4 (T28 M-4): the pass fixture with an anchor dir verifies with both trust roots
/// (exit 0, the "manifest SHA-256 and the anchor dir" verdict); no other kind carries one; the
/// anchor dir sits beside the export, with the store's lines in it; a wrong manifest hash or a
/// line that contradicts a row turns the same fixture into exit 21.
#[test]
fn export_fixture_with_anchor_dir_verifies_with_both_roots() {
    let out = tempfile::tempdir().expect("out");
    let info =
        testing::export_fixture(FixtureKind::PassWithAnchorDir, out.path()).expect("fixture");
    let anchor = info.anchor_dir.clone().expect("an anchor dir");
    assert_eq!(anchor.parent(), Some(out.path()), "beside the export");
    let mut names: Vec<PathBuf> = std::fs::read_dir(out.path())
        .expect("out")
        .map(|e| e.expect("entry").path())
        .collect();
    names.sort();
    let mut want = vec![info.dir.clone(), anchor.clone()];
    want.sort();
    assert_eq!(names, want, "the export and the anchor dir, nothing else");
    assert_eq!(info.expected_exit, 0);

    let v = verify_export(&info.dir, Some(&anchor), Some(info.manifest_sha256));
    assert_eq!(v.exit_code(), 0, "{:#?}", v.report());
    assert_eq!(last(&v), BOTH_OK);
    // The anchor dir proves seq 2 (its `CONFIG_CHANGED`); the manifest hash covers the rest.
    assert!(
        has_line(
            &v,
            "anchor dir: ok up to seq 2; rows 3..7 covered by the manifest SHA-256 only"
        ),
        "{:?}",
        v.report()
    );

    let mut wrong = info.manifest_sha256;
    wrong[0] ^= 1;
    expect(
        &verify_export(&info.dir, Some(&anchor), Some(wrong)),
        21,
        "wrong manifest hash",
    );

    // The anchor dir is the one the fixture has to give: the plain kinds have none.
    for kind in [
        FixtureKind::Pass,
        FixtureKind::Tamper,
        FixtureKind::NoTrustRoot,
    ] {
        let plain = tempfile::tempdir().expect("out");
        let info = testing::export_fixture(kind, plain.path()).expect("fixture");
        assert_eq!(info.anchor_dir, None, "{kind:?}");
    }
}

#[test]
fn manifest_hash_mismatch_is_21() {
    let (store, _f) = basic_store(6);
    let ex = export_all(&store);
    let mut wrong = ex.hash;
    wrong[0] ^= 1;
    let v = verify_export(&ex.dir, None, Some(wrong));
    expect(&v, 21, "wrong manifest hash");
    assert!(has_line(&v, "manifest: mismatch"), "{:?}", v.report());
    assert!(last(&v).starts_with("TAMPERED: "));
}

#[test]
fn anchor_dir_mismatch_is_21() {
    let (store, _f, anchor) = anchored_store();
    let ex = export_all(&store);
    let chain = ex.receipt.chain_ids[0].clone();
    assert_eq!(
        verify_export(&ex.dir, Some(anchor.path()), None).exit_code(),
        0
    );
    // A line naming seq 5 (no genuine line names it) with another hash.
    append_anchor_line(anchor.path(), &chain, &record_line(5, [9; 32]));
    let v = verify_export(&ex.dir, Some(anchor.path()), None);
    expect(&v, 21, "anchor line contradicts a row");
    assert!(last(&v).starts_with("TAMPERED: "), "{:?}", v.report());
    let v = verify_export(&ex.dir, Some(anchor.path()), Some(ex.hash));
    expect(&v, 21, "both roots, anchor contradicts");
}

#[test]
fn anchor_and_manifest_both_required_to_pass_when_given() {
    let (store, _f, anchor) = anchored_store();
    let ex = export_all(&store);
    let v = verify_export(&ex.dir, Some(anchor.path()), Some(ex.hash));
    expect(&v, 0, "both good");
    assert_eq!(last(&v), BOTH_OK);

    let mut wrong = ex.hash;
    wrong[31] ^= 0x80;
    let v = verify_export(&ex.dir, Some(anchor.path()), Some(wrong));
    expect(&v, 21, "anchor good, manifest wrong");

    let chain = ex.receipt.chain_ids[0].clone();
    append_anchor_line(anchor.path(), &chain, &record_line(4, [3; 32]));
    let v = verify_export(&ex.dir, Some(anchor.path()), Some(ex.hash));
    expect(&v, 21, "manifest good, anchor contradicts");
}

#[test]
fn anchor_only_exit_0_only_when_last_row_anchored() {
    let (store, _f, anchor) = anchored_store();
    let ex = export_all(&store);
    let v = verify_export(&ex.dir, Some(anchor.path()), None);
    expect(&v, 0, "last row (the PRUNE) anchored");
    assert_eq!(last(&v), ANCHOR_OK);
    assert!(has_line(&v, "anchor dir: ok"), "{:?}", v.report());

    // Seq 10 is the first EXPORT; 11..=13 follow, none anchored.
    store.append_batch(mixed(3)).expect("append");
    assert!(store.testing_anchor_dir_drain());
    let ex2 = export_all(&store);
    assert_eq!(ex2.receipt.last_seq, 13);
    let v = verify_export(&ex2.dir, Some(anchor.path()), None);
    expect(&v, 20, "unanchored tail");
    assert!(
        has_line(
            &v,
            "anchor dir: ok up to seq 9; rows 10..13 unanchored, not covered by a trust root; \
             give --manifest-sha256"
        ),
        "{:?}",
        v.report()
    );
    assert_eq!(last(&v), NO_ROOT);
    let v = verify_export(&ex2.dir, Some(anchor.path()), Some(ex2.hash));
    expect(&v, 0, "the manifest covers the tail");
    assert_eq!(last(&v), BOTH_OK);
}

/// Three phases an hour apart: rows of phase 0 (seq 2 anchored), phase 1 (`first..=last`, its
/// last row a PRUNE with an immediate line), phase 2 (a later PRUNE, anchored). The export covers
/// phase 1 only.
fn three_phase() -> (Store, Fixture, tempfile::TempDir, Exported) {
    let anchor = tempfile::tempdir().expect("anchor dir");
    let clock = fake_clock(START);
    let (store, f) = new_store(clock.clone(), MemKeyring::new());
    store
        .change_anchor_dir(Some(chosen(anchor.path())), confirmed())
        .expect("anchor dir");
    store.append_batch(mixed(4)).expect("append");
    clock.advance(Duration::from_secs(3600));
    let t1 = clock.now_utc();
    store.append_batch(mixed(5)).expect("append");
    fake_prune(&store, "2026-06-01", store.settings().to_json());
    clock.advance(Duration::from_secs(3600));
    let t2 = clock.now_utc();
    store.append_batch(mixed(3)).expect("append");
    fake_prune(&store, "2026-06-02", store.settings().to_json());
    assert!(store.testing_anchor_dir_drain());
    let ex = export(
        &store,
        TimeRange {
            from_utc: t1,
            to_utc: UtcInstant(t2.0 - 1),
        },
    );
    assert_eq!((ex.receipt.first_seq, ex.receipt.last_seq), (7, 12));
    (store, f, anchor, ex)
}

#[test]
fn anchor_lines_outside_range_ignored() {
    let (_store, _f, anchor, ex) = three_phase();
    let chain = ex.receipt.chain_ids[0].clone();
    // Forged lines outside 6..=12 (seq 6 is the boundary) are never findings.
    for seq in [3, 4, 13, 14, 40] {
        append_anchor_line(anchor.path(), &chain, &record_line(seq, [0xEE; 32]));
    }
    let v = verify_export(&ex.dir, Some(anchor.path()), None);
    expect(&v, 0, "lines outside the range");
    assert_eq!(last(&v), ANCHOR_OK);
    let v = verify_export(&ex.dir, Some(anchor.path()), Some(ex.hash));
    expect(&v, 0, "with the manifest too");
}

#[test]
fn boundary_checked_against_line_before_first_seq() {
    let anchor = tempfile::tempdir().expect("anchor dir");
    let clock = fake_clock(START);
    let (store, _f) = new_store(clock.clone(), MemKeyring::new());
    store
        .change_anchor_dir(Some(chosen(anchor.path())), confirmed())
        .expect("anchor dir");
    store.append_batch(mixed(3)).expect("append");
    // Seq 6: an anchored PRUNE, the row right before the export.
    assert_eq!(
        fake_prune(&store, "2026-06-01", store.settings().to_json()),
        6
    );
    clock.advance(Duration::from_secs(3600));
    let t1 = clock.now_utc();
    store.append_batch(mixed(4)).expect("append");
    assert!(store.testing_anchor_dir_drain());
    let ex = export(
        &store,
        TimeRange {
            from_utc: t1,
            to_utc: UtcInstant(i64::MAX),
        },
    );
    assert_eq!((ex.receipt.first_seq, ex.receipt.last_seq), (7, 10));
    let v = verify_export(&ex.dir, Some(anchor.path()), None);
    expect(&v, 20, "no in-range line; the boundary line agrees");

    // A consistent forgery with another boundary: only the line at seq 6 contradicts it.
    let c = copy_export(&ex.dir);
    let mut fg = Forge::load(&c.dir);
    fg.lines[0]["prev_hash"] = json!(hex::encode([0x42; 32]));
    fg.rehash();
    fg.save();
    expect(
        &verify_export(&c.dir, None, None),
        20,
        "the forgery is internally consistent",
    );
    let v = verify_export(&c.dir, Some(anchor.path()), None);
    expect(&v, 21, "boundary contradicts the line at first_seq - 1");
    assert!(last(&v).starts_with("TAMPERED: "), "{:?}", v.report());
}

/// A `prune_log` row whose `PRUNE` lies before the exported range is matched by the anchor dir's
/// `Prune` line alone: altering it (with the row-hash chain recomputed) contradicts that line.
#[test]
fn prune_line_without_its_row_is_21_with_the_anchor_dir() {
    let anchor = tempfile::tempdir().expect("anchor dir");
    let clock = fake_clock(START);
    let (store, _f) = new_store(clock.clone(), MemKeyring::new());
    store
        .change_anchor_dir(Some(chosen(anchor.path())), confirmed())
        .expect("anchor dir");
    store.append_batch(mixed(3)).expect("append");
    assert_eq!(
        fake_prune(&store, "2026-06-01", store.settings().to_json()),
        6
    );
    clock.advance(Duration::from_secs(3600));
    let t1 = clock.now_utc();
    store.append_batch(mixed(4)).expect("append");
    assert!(store.testing_anchor_dir_drain());
    let ex = export(
        &store,
        TimeRange {
            from_utc: t1,
            to_utc: UtcInstant(i64::MAX),
        },
    );
    assert_eq!(
        ex.receipt.first_seq, 7,
        "the PRUNE (seq 6) lies before the range"
    );
    expect(
        &verify_export(&ex.dir, Some(anchor.path()), None),
        20,
        "honest",
    );
    let c = copy_export(&ex.dir);
    let mut fg = Forge::load(&c.dir);
    fg.prune[0]["cutoff_epoch"] = json!("2026-05-01");
    fg.rehash_prune_log();
    fg.save();
    expect(
        &verify_export(&c.dir, None, None),
        20,
        "consistent without a root",
    );
    let v = verify_export(&c.dir, Some(anchor.path()), None);
    expect(&v, 21, "the Prune line matches no prune_log row");
    assert!(
        has_prefix(&v, "anchor dir: mismatch: a Prune line"),
        "{:?}",
        v.report()
    );
}

/// The recipient's anchor dir is newer than the export: a prune committed after it has a `Prune`
/// line that no row of the export's `prune_log.jsonl` matches, which is no contradiction.
#[test]
fn prune_after_the_export_is_no_contradiction() {
    let (store, _f, anchor) = anchored_store();
    let ex = export_all(&store);
    assert_eq!(ex.receipt.last_seq, 9);
    store.append_batch(mixed(2)).expect("append");
    let later = fake_prune(&store, "2026-06-05", store.settings().to_json());
    assert!(later > ex.receipt.last_seq);
    assert!(store.testing_anchor_dir_drain());
    let v = verify_export(&ex.dir, Some(anchor.path()), Some(ex.hash));
    expect(&v, 0, "manifest and the newer anchor dir");
    let v = verify_export(&ex.dir, Some(anchor.path()), None);
    expect(
        &v,
        0,
        "the newer anchor dir alone (the last row is anchored)",
    );
    assert!(has_line(&v, "anchor dir: ok"), "{:?}", v.report());
}

#[test]
fn partial_range_export_verifies() {
    let anchor = tempfile::tempdir().expect("anchor dir");
    let clock = fake_clock(START);
    let (store, _f) = new_store(clock.clone(), MemKeyring::new());
    store
        .change_anchor_dir(Some(chosen(anchor.path())), confirmed())
        .expect("anchor dir");
    store.append_batch(mixed(299)).expect("append");
    // Seq 302 prunes seqs 1..=99 (with an immediate and a Prune line below the range).
    let c = testing::insert_fake_prune(
        &store,
        FakePrune {
            first_retained_seq: 100,
            cutoff: "2026-06-01".into(),
            settings: store.settings().to_json(),
            update_first_retained: false,
        },
    )
    .expect("prune");
    assert_eq!(c.seq, 302);
    store.append_batch(mixed(197)).expect("append");
    assert_eq!(store.head().0, 499);
    clock.advance(Duration::from_secs(3600));
    let t1 = clock.now_utc();
    store.append_batch(mixed(301)).expect("append");
    assert_eq!(store.head().0, 800);
    clock.advance(Duration::from_secs(3600));
    store.append_batch(mixed(100)).expect("append");
    let c = testing::insert_fake_prune(
        &store,
        FakePrune {
            first_retained_seq: 100,
            cutoff: "2026-06-02".into(),
            settings: store.settings().to_json(),
            update_first_retained: false,
        },
    )
    .expect("prune");
    assert_eq!(c.seq, 901, "a line above the range");
    assert!(store.testing_anchor_dir_drain());
    let ex = export(
        &store,
        TimeRange {
            from_utc: t1,
            to_utc: t1,
        },
    );
    assert_eq!((ex.receipt.first_seq, ex.receipt.last_seq), (500, 800));
    let v = verify_export(&ex.dir, None, Some(ex.hash));
    expect(&v, 0, "manifest");
    let v = verify_export(&ex.dir, Some(anchor.path()), Some(ex.hash));
    expect(&v, 0, "manifest and anchor dir");
    assert!(
        !v.report()
            .iter()
            .any(|l| l.contains("first_retained") || l.contains("first retained")),
        "{:?}",
        v.report()
    );
    // No line of the anchor dir names a row: the anchor dir verified nothing (T8 review I-3).
    assert_eq!(last(&v), MANIFEST_OK, "{:?}", v.report());
    let v = verify_export(&ex.dir, Some(anchor.path()), None);
    expect(&v, 20, "no anchored line in 500..=800");
}

/// Real prunes over 130 corroborated days with an anchor dir: every `PRUNE` has an epoch (so
/// the retention judgement runs), daily `Record` lines carry epochs, and the `Prune` lines pair
/// with their immediate lines.
#[test]
fn export_of_a_pruned_store_verifies() {
    let mut sim = Sim::new("2026-01-05T09:00:00.000Z", 92, 0);
    let anchor = tempfile::tempdir().expect("anchor dir");
    sim.store
        .change_anchor_dir(Some(chosen(anchor.path())), confirmed())
        .expect("anchor dir");
    sim.days(130, 2);
    assert!(sim.deleted_count() > 0, "the store pruned");
    assert!(sim.store.testing_anchor_dir_drain());
    let ex = export_all(&sim.store);
    let rows = jsonl(&ex.dir.join("prune_log.jsonl"));
    assert!(!rows.is_empty());
    let v = verify_export(&ex.dir, Some(anchor.path()), Some(ex.hash));
    expect(&v, 0, "manifest and anchor dir");
    assert!(has_line(&v, "prune_log: ok"), "{:?}", v.report());
    let v = verify_export(&ex.dir, Some(anchor.path()), None);
    assert!(
        matches!(v.exit_code(), 0 | 20),
        "anchor dir only: {:?}",
        v.report()
    );
    assert!(
        !v.report()
            .iter()
            .any(|l| l.starts_with("anchor dir: mismatch") || l.starts_with("anchor dir: fork")),
        "{:?}",
        v.report()
    );
}

// ---------------------------------------------------------------------------------------
// the tamper matrix, per trust root

#[test]
fn verify_export_tamper_matrix() {
    // An export with a prune (prune_log row and Prune line), an anchor dir and an unanchored
    // tail (rows 10..=12 after the anchored PRUNE at 9).
    let (store, _f, anchor) = anchored_store();
    store.append_batch(mixed(3)).expect("append");
    assert!(store.testing_anchor_dir_drain());
    let ex = export_all(&store);
    assert_eq!(ex.receipt.last_seq, 12);
    assert_eq!(ex.receipt.unanchored_from, Some(10));
    expect(&verify_export(&ex.dir, None, Some(ex.hash)), 0, "honest");

    // --- With --manifest-sha256: any change is 21.
    type Edit = Box<dyn Fn(&Path)>;
    let swap = |key: &'static str| -> Edit {
        Box::new(move |d: &Path| {
            let mut ls = raw_lines(d);
            let mut a: Value = serde_json::from_slice(&ls[3]).unwrap();
            let mut b: Value = serde_json::from_slice(&ls[4]).unwrap();
            std::mem::swap(&mut a[key], &mut b[key]);
            ls[3] = to_jcs_vec(&a).unwrap();
            ls[4] = to_jcs_vec(&b).unwrap();
            write_raw_lines(d, &ls);
        })
    };
    let cases: Vec<(&str, Edit)> = vec![
        (
            "modify a row",
            Box::new(|d: &Path| edit_line(d, 4, |l| l["target"] = json!("x"))),
        ),
        (
            "delete a row",
            Box::new(|d: &Path| {
                let mut ls = raw_lines(d);
                ls.remove(5);
                write_raw_lines(d, &ls);
            }),
        ),
        (
            "reorder rows",
            Box::new(|d: &Path| {
                let mut ls = raw_lines(d);
                ls.swap(4, 5);
                write_raw_lines(d, &ls);
            }),
        ),
        (
            "truncate head",
            Box::new(|d: &Path| {
                let mut ls = raw_lines(d);
                ls.remove(0);
                write_raw_lines(d, &ls);
            }),
        ),
        (
            "truncate tail",
            Box::new(|d: &Path| {
                let mut ls = raw_lines(d);
                ls.pop();
                write_raw_lines(d, &ls);
            }),
        ),
        ("payload_ct swap", swap("payload_ct")),
        ("payload_b64 swap", swap("payload_b64")),
        (
            "payload display edit",
            Box::new(|d: &Path| {
                let i = raw_lines(d)
                    .iter()
                    .position(|l| {
                        serde_json::from_slice::<Value>(l)
                            .unwrap()
                            .get("payload")
                            .is_some()
                    })
                    .expect("a line with payload");
                edit_line(d, i, |l| l["payload"] = json!({"forged": true}));
            }),
        ),
        (
            "unanchored flag edit",
            Box::new(|d: &Path| {
                edit_line(d, 10, |l| {
                    l.as_object_mut().unwrap().remove("unanchored");
                })
            }),
        ),
        (
            "prune_log row altered",
            Box::new(|d: &Path| {
                let mut fg = Forge::load(d);
                fg.prune[0]["cutoff_epoch"] = json!("2026-05-01");
                fg.rehash_prune_log();
                std::fs::write(d.join("prune_log.jsonl"), jcs_lines(&fg.prune)).unwrap();
            }),
        ),
        (
            "prune_log row deleted",
            Box::new(|d: &Path| std::fs::write(d.join("prune_log.jsonl"), b"").unwrap()),
        ),
        (
            "manifest field changed",
            Box::new(|d: &Path| {
                let mut m: Value =
                    serde_json::from_slice(&std::fs::read(d.join("manifest.json")).unwrap())
                        .unwrap();
                m["exported_at"] = json!("2026-10-09T00:00:00.000Z");
                std::fs::write(d.join("manifest.json"), to_jcs_vec(&m).unwrap()).unwrap();
            }),
        ),
        (
            "consistent forgery",
            Box::new(|d: &Path| {
                let mut fg = Forge::load(d);
                fg.lines[4]["target"] = json!("forged");
                fg.rehash();
                fg.save();
            }),
        ),
    ];
    for (what, edit) in &cases {
        let c = copy_export(&ex.dir);
        edit(&c.dir);
        let v = verify_export(&c.dir, None, Some(ex.hash));
        expect(&v, 21, &format!("manifest root: {what}"));
    }

    // --- With --anchor-dir only (rows up to seq 9 anchored; 10..=12 are not).
    expect(
        &verify_export(&ex.dir, Some(anchor.path()), None),
        20,
        "honest, unanchored tail",
    );
    let anchor_case = |what: &str, code: u8, edit: &dyn Fn(&mut Forge)| {
        let c = copy_export(&ex.dir);
        let mut fg = Forge::load(&c.dir);
        edit(&mut fg);
        fg.save();
        let v = verify_export(&c.dir, Some(anchor.path()), None);
        expect(&v, code, &format!("anchor root: {what}"));
        v
    };
    anchor_case("a row at or before the last anchored line", 21, &|fg| {
        fg.lines[4]["target"] = json!("forged");
        fg.rehash();
    });
    anchor_case("a prune_log row matched by a Prune line", 21, &|fg| {
        fg.prune[0]["cutoff_epoch"] = json!("2026-05-01");
        fg.rehash_prune_log();
    });
    anchor_case(
        "boundary contradicting the line at first_seq - 1",
        21,
        &|fg| {
            // The first two rows dropped: the line at seq 2 names the boundary.
            fg.lines.drain(..2);
            fg.lines[0]["prev_hash"] = json!(hex::encode([0x42; 32]));
            fg.rehash();
        },
    );
    let v = anchor_case("truncate head", 20, &|fg| {
        fg.lines.drain(..3);
        fg.rehash();
    });
    assert!(
        has_prefix(&v, "anchor dir: ok up to seq 9;"),
        "smaller range, same tail rule: {:?}",
        v.report()
    );
    let v = anchor_case("truncate tail after the last anchored line", 20, &|fg| {
        fg.lines.pop();
        fg.rehash();
    });
    assert!(
        has_line(
            &v,
            "anchor dir: ok up to seq 9; rows 10..11 unanchored, not covered by a trust root; \
             give --manifest-sha256"
        ),
        "{:?}",
        v.report()
    );
    anchor_case("truncate the tail to the last anchored line", 0, &|fg| {
        fg.lines.truncate(9);
        fg.rehash();
        fg.manifest["last_anchored_seq"] = json!(9);
    });
    // Neither `payload` nor `unanchored` is covered by a record_hash: both are checked against
    // what is (the plaintext, the manifest's last_anchored_seq).
    anchor_case("payload display edit, consistent", 21, &|fg| {
        let i = fg
            .lines
            .iter()
            .position(|l| l.get("payload").is_some())
            .expect("a line with payload");
        fg.lines[i]["payload"] = json!({"forged": true});
    });
    anchor_case("unanchored flag edit, consistent", 21, &|fg| {
        fg.lines[10].as_object_mut().unwrap().remove("unanchored");
    });

    // --- Neither: only internal consistency.
    let neither = |what: &str, code: u8, edit: &dyn Fn(&Path)| {
        let c = copy_export(&ex.dir);
        edit(&c.dir);
        let v = verify_export(&c.dir, None, None);
        expect(&v, code, &format!("no root: {what}"));
        v
    };
    let v = neither("chain break", 21, &|d| {
        edit_line(d, 4, |l| l["target"] = json!("x"))
    });
    assert!(has_prefix(&v, "chain: broken at seq "), "{:?}", v.report());
    let v = neither("payload_sha256 mismatch", 21, &|d| {
        let mut fg = Forge::load(d);
        let other = b"{\"other\":1}";
        fg.lines[4]["payload_b64"] = json!(STANDARD.encode(other));
        fg.lines[4]["payload_len"] = json!(other.len());
        if fg.lines[4].get("payload").is_some() {
            fg.lines[4]["payload"] = json!({"other": 1});
        }
        fg.save();
    });
    assert!(
        has_line(&v, "payloads: mismatch at seq 5"),
        "{:?}",
        v.report()
    );
    let v = neither("payload display edit", 21, &|d| {
        let mut fg = Forge::load(d);
        let i = fg
            .lines
            .iter()
            .position(|l| l.get("payload").is_some())
            .expect("a line with payload");
        fg.lines[i]["payload"] = json!({"forged": true});
        fg.save();
    });
    assert!(
        has_prefix(&v, "payloads: mismatch at seq "),
        "{:?}",
        v.report()
    );
    let v = neither("restore boundary", 21, &|d| {
        let mut fg = Forge::load(d);
        // A chain switch without a RESTORE, rehashed.
        let other = "ef".repeat(16);
        for l in &mut fg.lines[6..] {
            l["chain_id"] = json!(other);
        }
        fg.rehash();
        fg.save();
    });
    assert!(
        has_line(&v, "restore boundaries: mismatch at seq 7"),
        "{:?}",
        v.report()
    );
    let v = neither("consistent but altered", 20, &|d| {
        let mut fg = Forge::load(d);
        fg.lines[4]["target"] = json!("forged");
        fg.rehash();
        fg.save();
    });
    assert_eq!(last(&v), NO_ROOT);
}

/// `{"params": [[…[1]…]]}` nesting `depth` deep (the object counts).
fn nested(depth: usize) -> Value {
    let mut v = json!(1);
    for _ in 1..depth {
        v = Value::Array(vec![v]);
    }
    json!({ "params": v })
}

/// An agent's params nesting 64 or more deep get no `payload` display field (the line would nest
/// deeper than the verifier reads); 63 deep still do. Every one verifies (T8 review I-1).
#[test]
fn deeply_nested_payload_exports_and_verifies() {
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    let depths = [63usize, 64, 80, 126];
    store
        .append_batch(
            depths
                .iter()
                .map(|d| {
                    ev(
                        EventType::REQUEST_RECEIVED,
                        Some(&format!("depth-{d}")),
                        nested(*d),
                    )
                })
                .collect(),
        )
        .expect("append");
    let ex = export_all(&store);
    let lines = jsonl(&ex.dir.join("events.jsonl"));
    for d in depths {
        let id = json!(format!("depth-{d}"));
        let l = lines.iter().find(|l| l["request_id"] == id).expect("row");
        assert_eq!(l.get("payload").is_some(), d < 64, "depth {d}");
    }
    let v = verify_export(&ex.dir, None, Some(ex.hash));
    expect(&v, 0, "with the manifest SHA-256");
    assert_eq!(last(&v), MANIFEST_OK);
    expect(&verify_export(&ex.dir, None, None), 20, "without a root");
}

/// The verifier accepts a line without `payload` only where the exporter writes none: a JCS
/// plaintext of at most 1 MiB nesting at most 63 deep must show it (T8 review I-1).
#[test]
fn missing_payload_on_a_shallow_row_is_refused() {
    let (store, _f, anchor) = anchored_store();
    let ex = export_all(&store);
    expect(
        &verify_export(&ex.dir, Some(anchor.path()), None),
        0,
        "honest",
    );
    let c = copy_export(&ex.dir);
    let mut fg = Forge::load(&c.dir);
    // Seq 2 (`CONFIG_CHANGED anchor_dir`) has an immediate line.
    assert!(fg.lines[1].get("payload").is_some());
    fg.lines[1].as_object_mut().unwrap().remove("payload");
    fg.save();
    let v = verify_export(&c.dir, None, None);
    expect(&v, 21, "no root");
    assert!(
        has_line(&v, "payloads: mismatch at seq 2"),
        "{:?}",
        v.report()
    );
    let v = verify_export(&c.dir, Some(anchor.path()), None);
    expect(&v, 21, "anchor dir only");
}

/// A line naming a row with its record hash but another epoch contradicts the row; it is no
/// fork, whose evidence is two record hashes for one seq (T8 review M-3).
#[test]
fn same_hash_line_of_another_epoch_is_a_mismatch_not_a_fork() {
    let (store, _f, anchor) = anchored_store();
    let ex = export_all(&store);
    let chain = ex.receipt.chain_ids[0].clone();
    let fg = Forge::load(&ex.dir);
    assert_eq!(fg.lines[8]["seq"], json!(9));
    let epoch = if fg.lines[8]["epoch"] == json!("2026-10-01") {
        "2026-10-02"
    } else {
        "2026-10-01"
    };
    append_anchor_line(
        anchor.path(),
        &chain,
        &AnchorLine::Record {
            seq: 9,
            record_hash: fg.record_hash(8),
            epoch: Some(epoch.into()),
            clock_behind: false,
        },
    );
    let v = verify_export(&ex.dir, Some(anchor.path()), None);
    expect(&v, 21, "a line contradicting the row's epoch");
    assert!(last(&v).starts_with("TAMPERED: "), "{:?}", v.report());
    assert!(has_prefix(&v, "anchor dir: mismatch: "), "{:?}", v.report());
}

/// A record of a format this verifier does not read cannot be judged: 22, not TAMPERED (T8
/// review M-6).
#[test]
fn a_record_format_of_another_version_cannot_be_verified() {
    let (store, _f) = basic_store(4);
    let ex = export_all(&store);
    let c = copy_export(&ex.dir);
    let mut fg = Forge::load(&c.dir);
    assert!(fg.lines.len() > 3);
    fg.lines[2]["format_version"] = json!(2);
    fg.save();
    let v = verify_export(&c.dir, None, None);
    expect(&v, 22, "format_version 2");
    assert!(
        last(&v).starts_with("cannot verify: ") && last(&v).contains("format_version 2"),
        "{:?}",
        v.report()
    );
    assert!(has_line(&v, "chain: ok"), "{:?}", v.report());
}

/// More rows than the manifest claims: the walk stops there and the export is TAMPERED.
#[test]
fn more_rows_than_the_manifest_claims_is_21() {
    let (store, _f) = basic_store(4);
    let ex = export_all(&store);
    let c = copy_export(&ex.dir);
    let mut fg = Forge::load(&c.dir);
    let extra = fg.lines.last().expect("rows").clone();
    fg.lines.push(extra);
    fg.save();
    let v = verify_export(&c.dir, None, None);
    expect(&v, 21, "a row beyond the manifest's count");
    assert_eq!(
        last(&v),
        "TAMPERED: events.jsonl holds more rows than the manifest claims"
    );
}

/// Files beside the export's three are named in the report (names that are not plain ASCII only
/// counted) and never verified (T8 review M-5).
#[test]
fn other_entries_of_the_export_dir_are_reported() {
    let (store, _f) = basic_store(4);
    let ex = export_all(&store);
    let c = copy_export(&ex.dir);
    std::fs::write(c.dir.join("events-readable.txt"), b"x").unwrap();
    std::fs::create_dir(c.dir.join("notes")).unwrap();
    std::fs::write(c.dir.join("r\u{e9}sum\u{e9} 1.txt"), b"x").unwrap();
    let v = verify_export(&c.dir, None, Some(ex.hash));
    expect(&v, 0, "the export itself is unchanged");
    assert!(
        has_line(
            &v,
            "export dir: 3 other entries, not part of the export and not verified: \
             events-readable.txt, notes and 1 more"
        ),
        "{:?}",
        v.report()
    );
    assert_eq!(last(&v), MANIFEST_OK);
}

#[test]
fn request_set_hash_mismatch_is_21_without_a_trust_root() {
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    store
        .append_batch(vec![write_approved(1, true), write_approved(2, false)])
        .expect("append");
    let ex = export_all(&store);
    let v = verify_export(&ex.dir, None, None);
    expect(&v, 21, "request_set_hash");
    assert!(
        has_line(&v, "writes: request_set_hash mismatch at seq 3"),
        "{:?}",
        v.report()
    );
    let v = verify_export(&ex.dir, None, Some(ex.hash));
    expect(&v, 21, "the manifest does not make a bad record good");
}

// ---------------------------------------------------------------------------------------
// forks and restores

/// A store with an anchor dir across a same-machine rollback restore: the `RESTORE` and the
/// records after it are of a new chain; the records the rollback gave up stay in the old chain's
/// file's span (`records_lost`).
fn restored_store() -> (Store, Fixture, tempfile::TempDir, u64, Value) {
    let anchor = tempfile::tempdir().expect("anchor dir");
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    store
        .change_anchor_dir(Some(chosen(anchor.path())), confirmed())
        .expect("anchor dir");
    store.append_batch(mixed(10)).expect("append");
    store.flush_head_anchor().expect("flush");
    let out = tempfile::tempdir().expect("backup dir");
    let bundle = store.backup(chosen(out.path())).expect("backup");
    store.append_batch(mixed(5)).expect("append");
    store.flush_head_anchor().expect("flush");
    let rep = store
        .restore(
            chosen(&bundle.bundle_dir),
            &SecretString::from(PASSPHRASE.to_string()),
            confirmed(),
            Some(confirmed()),
        )
        .expect("restore");
    assert!(rep.records_lost > 0);
    // More rows after the restore than it gave up, so seqs beyond the lost span are exported.
    store
        .append_batch(mixed(rep.records_lost as usize + 4))
        .expect("append");
    assert!(store.testing_anchor_dir_drain());
    let p: Value =
        serde_json::from_slice(&store.read_payload(rep.restore_seq).expect("payload")).unwrap();
    (store, f, anchor, rep.restore_seq, p)
}

#[test]
fn u15_restore_boundary_in_export_verifies() {
    let (store, f, anchor, restore_seq, p) = restored_store();
    let ex = export_all(&store);
    assert_eq!(ex.receipt.chain_ids.len(), 2, "two chains");
    assert_eq!(ex.receipt.chain_ids[0], f.chain_id);
    let v = verify_export(&ex.dir, None, Some(ex.hash));
    expect(&v, 0, "manifest");
    assert!(has_line(&v, "restore boundaries: ok"), "{:?}", v.report());
    let v = verify_export(&ex.dir, Some(anchor.path()), Some(ex.hash));
    expect(&v, 0, "manifest and anchor dir");

    // A line of the old chain naming a record the rollback gave up is accounted for.
    let source_head = p["source_head_seq"].as_u64().expect("source_head_seq");
    assert_eq!(source_head, restore_seq - 1);
    append_anchor_line(
        anchor.path(),
        &f.chain_id,
        &record_line(source_head + 1, [0x5A; 32]),
    );
    let v = verify_export(&ex.dir, Some(anchor.path()), Some(ex.hash));
    expect(&v, 0, "a lost record's line is covered by records_lost");
}

#[test]
fn verify_export_fork_reported_as_fork() {
    // (b) Another chain of this installation shares rows with the export.
    let (store, _f, anchor) = anchored_store();
    let ex = export_all(&store);
    let fg = Forge::load(&ex.dir);
    let install = fg.manifest["install"].clone();
    let other = "ab".repeat(16);
    append_anchor_line(
        anchor.path(),
        &other,
        &AnchorLine::Header {
            chain_id: other.clone(),
            install_id: install["install_id"].as_str().unwrap().into(),
            host: install["host"].as_str().unwrap().into(),
            os_user: install["os_user"].as_str().unwrap().into(),
            created_at: START.into(),
        },
    );
    for i in 2..5 {
        let seq = fg.lines[i]["seq"].as_u64().unwrap();
        append_anchor_line(anchor.path(), &other, &record_line(seq, fg.record_hash(i)));
    }
    append_anchor_line(anchor.path(), &other, &record_line(6, [0x66; 32]));
    let v = verify_export(&ex.dir, Some(anchor.path()), None);
    expect(&v, 21, "fork (b)");
    assert!(last(&v).starts_with("FORK: "), "{:?}", v.report());

    // (c) Anchored lines of a RESTORE's source chain beyond its source head that records_lost
    // does not cover.
    let (store, f, anchor, _restore_seq, p) = restored_store();
    let ex = export_all(&store);
    let source_head = p["source_head_seq"].as_u64().unwrap();
    let lost = p["records_lost"].as_u64().unwrap();
    assert!(source_head + lost < ex.receipt.last_seq, "in the range");
    append_anchor_line(
        anchor.path(),
        &f.chain_id,
        &record_line(source_head + lost + 1, [0x77; 32]),
    );
    let v = verify_export(&ex.dir, Some(anchor.path()), Some(ex.hash));
    expect(&v, 21, "fork (c)");
    assert!(last(&v).starts_with("FORK: "), "{:?}", v.report());
}

/// A chain file of this installation naming a row of the export by its exact record hash is fork
/// evidence even when its chain is the source of the `RESTORE` the export starts with: no honest
/// writer puts a line for one chain's record into another chain's file (T8 review M-7).
#[test]
fn source_chain_file_naming_an_export_row_is_a_fork() {
    let anchor = tempfile::tempdir().expect("anchor dir");
    let clock = fake_clock(START);
    let (store, f) = new_store(clock.clone(), MemKeyring::new());
    store
        .change_anchor_dir(Some(chosen(anchor.path())), confirmed())
        .expect("anchor dir");
    store.append_batch(mixed(4)).expect("append");
    store.flush_head_anchor().expect("flush");
    let out = tempfile::tempdir().expect("backup dir");
    let bundle = store.backup(chosen(out.path())).expect("backup");
    store.append_batch(mixed(2)).expect("append");
    store.flush_head_anchor().expect("flush");
    clock.advance(Duration::from_secs(3600));
    let t1 = clock.now_utc();
    let rep = store
        .restore(
            chosen(&bundle.bundle_dir),
            &SecretString::from(PASSPHRASE.to_string()),
            confirmed(),
            Some(confirmed()),
        )
        .expect("restore");
    store.append_batch(mixed(3)).expect("append");
    assert!(store.testing_anchor_dir_drain());
    let ex = export(
        &store,
        TimeRange {
            from_utc: t1,
            to_utc: UtcInstant(i64::MAX),
        },
    );
    assert_eq!(
        ex.receipt.first_seq, rep.restore_seq,
        "starts at the RESTORE"
    );
    assert!(!ex.receipt.chain_ids.contains(&f.chain_id));
    let v = verify_export(&ex.dir, Some(anchor.path()), Some(ex.hash));
    expect(&v, 0, "honest");

    let fg = Forge::load(&ex.dir);
    let seq = fg.lines[1]["seq"].as_u64().expect("seq");
    append_anchor_line(
        anchor.path(),
        &f.chain_id,
        &record_line(seq, fg.record_hash(1)),
    );
    let v = verify_export(&ex.dir, Some(anchor.path()), Some(ex.hash));
    expect(
        &v,
        21,
        "the source chain's file names a row of the new chain",
    );
    assert!(last(&v).starts_with("FORK: "), "{:?}", v.report());
}

#[test]
fn fork_same_seq_two_hashes_reported_as_fork() {
    let (store, _f, anchor) = anchored_store();
    let ex = export_all(&store);
    let chain = ex.receipt.chain_ids[0].clone();
    // Seq 9 has its genuine immediate line; a second installation wrote another for seq 9.
    append_anchor_line(anchor.path(), &chain, &record_line(9, [0x99; 32]));
    let v = verify_export(&ex.dir, Some(anchor.path()), None);
    expect(&v, 21, "fork (a)");
    assert!(last(&v).starts_with("FORK: "), "{:?}", v.report());
}

#[test]
fn prune_snapshot_with_allow_degraded_scripts_verifies() {
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(3)).expect("append");
    let plain = store.settings().to_json();
    let mut degraded = plain.clone();
    degraded["allow_degraded_scripts"] = json!(true);
    fake_prune(&store, "2026-06-01", plain);
    fake_prune(&store, "2026-06-02", degraded);
    let ex = export_all(&store);
    let v = verify_export(&ex.dir, None, Some(ex.hash));
    expect(&v, 0, "both snapshot shapes");
    assert!(has_line(&v, "prune_log: ok"), "{:?}", v.report());

    // A key this verifier does not know (a newer version's setting) cannot be judged: 22 (T8
    // review M-6), at the top level or in an instance policy.
    let snapshot = |edit: &dyn Fn(&mut Value)| {
        let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
        store.append_batch(mixed(3)).expect("append");
        let mut s = store.settings().to_json();
        edit(&mut s);
        fake_prune(&store, "2026-06-01", s);
        let ex = export_all(&store);
        verify_export(&ex.dir, None, Some(ex.hash))
    };
    let policy = json!({"ca_fingerprint": null, "origin": "https://jira.example", "proxy": null});
    for (what, v) in [
        ("top level", snapshot(&|s| s["unknown_key"] = json!(1))),
        (
            "instance policy",
            snapshot(&|s| {
                let mut p = policy.clone();
                p["pinned_key"] = json!("x");
                s["instances"] = json!({ "jira": p });
            }),
        ),
    ] {
        expect(&v, 22, &format!("a newer settings key ({what})"));
        assert!(
            last(&v).starts_with("cannot verify: ") && last(&v).contains("settings snapshot"),
            "{what}: {:?}",
            v.report()
        );
    }
    expect(
        &snapshot(&|s| s["instances"] = json!({ "jira": policy.clone() })),
        0,
        "a known instance policy",
    );

    // A snapshot the store's parser refuses for its known keys is a finding.
    let v = snapshot(&|s| s["retention_days"] = json!("ninety"));
    expect(&v, 21, "malformed snapshot");
    assert!(has_prefix(&v, "prune_log: "), "{:?}", v.report());
}

// ---------------------------------------------------------------------------------------
// hostile input

#[test]
fn partial_dir_is_refused() {
    let (store, _f) = basic_store(4);
    let ex = export_all(&store);
    let tmp = tempfile::tempdir().expect("tmp");
    let partial = tmp.path().join(format!(
        "{}.partial",
        ex.dir.file_name().unwrap().to_string_lossy()
    ));
    std::fs::create_dir(&partial).unwrap();
    for f in ["events.jsonl", "prune_log.jsonl", "manifest.json"] {
        std::fs::copy(ex.dir.join(f), partial.join(f)).unwrap();
    }
    let v = verify_export(&partial, None, Some(ex.hash));
    expect(&v, 22, ".partial");
    assert!(last(&v).starts_with("cannot verify: "), "{:?}", v.report());
    assert!(last(&v).contains(".partial"), "{:?}", v.report());
}

#[test]
fn duplicate_keys_and_missing_files_are_refused() {
    let (store, _f) = basic_store(4);
    let ex = export_all(&store);

    // A line with a key twice.
    let c = copy_export(&ex.dir);
    let mut ls = raw_lines(&c.dir);
    let l = String::from_utf8(ls[1].clone()).unwrap();
    ls[1] = l.replacen("{", "{\"seq\":2,", 1).into_bytes();
    write_raw_lines(&c.dir, &ls);
    let v = verify_export(&c.dir, None, None);
    expect(&v, 22, "duplicate key in a line");

    // The manifest with a key twice (its own hash given: the bytes are what was promised).
    let c = copy_export(&ex.dir);
    let m = std::fs::read_to_string(c.dir.join("manifest.json")).unwrap();
    let dup = m.replacen("{", "{\"rows\":1,", 1);
    std::fs::write(c.dir.join("manifest.json"), &dup).unwrap();
    let v = verify_export(&c.dir, None, Some(sha256(dup.as_bytes())));
    expect(&v, 22, "duplicate key in the manifest");

    for f in ["events.jsonl", "prune_log.jsonl", "manifest.json"] {
        let c = copy_export(&ex.dir);
        std::fs::remove_file(c.dir.join(f)).unwrap();
        let v = verify_export(&c.dir, None, Some(ex.hash));
        assert!(
            matches!(v.exit_code(), 21 | 22),
            "{f} missing: {:?}",
            v.report()
        );
        assert!(v.exit_code() == 22 || f != "manifest.json");
    }
    let v = verify_export(&ex.dir.join("missing"), None, None);
    expect(&v, 22, "no such directory");
}

/// On Windows creating a symbolic link needs a privilege (or Developer Mode): without it the test
/// says so on stderr and checks nothing.
#[cfg(any(unix, windows))]
#[test]
fn symlinked_export_file_is_refused() {
    let (store, _f) = basic_store(4);
    let ex = export_all(&store);
    let c = copy_export(&ex.dir);
    let elsewhere = c._tmp.path().join("events-elsewhere.jsonl");
    let link = c.dir.join("events.jsonl");
    std::fs::rename(&link, &elsewhere).unwrap();
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(&elsewhere, &link);
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(&elsewhere, &link);
    if let Err(e) = made {
        // ERROR_PRIVILEGE_NOT_HELD
        if cfg!(windows) && e.raw_os_error() == Some(1314) {
            eprintln!("symlinked_export_file_is_refused: SKIPPED, no privilege to create a link");
            return;
        }
        panic!("symlink: {e}");
    }
    let v = verify_export(&c.dir, None, Some(ex.hash));
    expect(&v, 22, "a symlinked events.jsonl");
    assert!(
        last(&v).contains("events.jsonl is not a regular file"),
        "{:?}",
        v.report()
    );
}

#[test]
fn bounds_of_prune_log_and_anchor_dir_are_enforced() {
    let (store, _f, anchor) = anchored_store();
    let ex = export_all(&store);
    let lim = |f: &dyn Fn(&mut Limits)| {
        let mut l = Limits::default();
        f(&mut l);
        l
    };
    let run = |l: Limits, anchor: Option<&Path>| {
        verify_export_with(&OsFs, l, &ex.dir, anchor, Some(ex.hash))
    };
    expect(&run(Limits::default(), Some(anchor.path())), 0, "defaults");
    let v = run(lim(&|l| l.prune_log_rows = 0), None);
    expect(&v, 22, "more prune_log rows than the bound");
    let v = run(lim(&|l| l.prune_log = 10), None);
    expect(&v, 22, "prune_log.jsonl longer than the bound");
    let v = run(lim(&|l| l.line = 100), None);
    expect(&v, 22, "an events line longer than the bound");
    let v = run(lim(&|l| l.manifest = 100), None);
    expect(&v, 22, "manifest longer than the bound");
    for i in 0..3 {
        std::fs::write(anchor.path().join(format!("extra-{i}.jsonl")), b"").unwrap();
    }
    let v = run(lim(&|l| l.anchor_files = 3), Some(anchor.path()));
    expect(&v, 22, "too many *.jsonl files");
    assert!(
        last(&v).contains("anchor dir has too many files"),
        "{:?}",
        v.report()
    );
}

/// Records every path the verifier asks the file system about.
struct Recording {
    seen: Mutex<Vec<PathBuf>>,
}

impl Recording {
    fn note(&self, p: &Path) {
        self.seen.lock().unwrap().push(p.to_path_buf());
    }
}

impl FsRead for Recording {
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.note(path);
        OsFs.metadata(path)
    }
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        self.note(path);
        OsFs.canonicalize(path)
    }
    fn read_dir(&self, path: &Path, each: &mut dyn FnMut(OsString) -> bool) -> io::Result<()> {
        self.note(path);
        OsFs.read_dir(path, each)
    }
    fn open(&self, path: &Path) -> io::Result<File> {
        self.note(path);
        OsFs.open(path)
    }
}

#[test]
fn verify_export_never_opens_keychain_or_live_db() {
    // The signature takes no key store and no data dir.
    let _: fn(&Path, Option<&Path>, Option<[u8; 32]>) -> ExportVerdict = verify_export;
    let (store, f, anchor) = anchored_store();
    let ex = export_all(&store);
    // Files of other installations and names that are no chain id sit in the anchor dir.
    std::fs::write(anchor.path().join("not-a-chain.jsonl"), b"{}\n").unwrap();
    std::fs::write(
        anchor.path().join(format!("{}.jsonl", "cd".repeat(16))),
        b"x\n",
    )
    .unwrap();
    let check = |dir: &Path, root: Option<&Path>, hash: Option<[u8; 32]>| {
        let rec = Recording {
            seen: Mutex::new(Vec::new()),
        };
        let v = verify_export_with(&rec, Limits::default(), dir, root, hash);
        let seen = rec.seen.into_inner().unwrap();
        assert!(!seen.is_empty());
        for p in &seen {
            assert!(
                p.starts_with(dir) || root.is_some_and(|r| p.starts_with(r)),
                "opened outside the export and the anchor dir: {p:?}"
            );
            assert!(!p.starts_with(f.dir.path()), "the live data dir: {p:?}");
        }
        v
    };
    expect(
        &check(&ex.dir, Some(anchor.path()), Some(ex.hash)),
        0,
        "honest",
    );
    // A manifest whose chain_ids would name a path outside the anchor dir.
    let c = copy_export(&ex.dir);
    let mut fg = Forge::load(&c.dir);
    fg.manifest["chain_ids"] = json!(["../../../../x"]);
    fg.save();
    let v = check(&c.dir, Some(anchor.path()), None);
    assert!(matches!(v.exit_code(), 21 | 22), "{:?}", v.report());
}

#[test]
fn verify_export_never_decrypts() {
    let src =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/verify_export.rs"))
            .expect("source");
    for word in ["Deks", "decrypt", "KeyStore", "Kek"] {
        assert!(!src.contains(word), "verify_export.rs names {word}");
    }
    // Of the crypto module only the payload bound and the constant-time compare (T8 review M-7).
    let crypto: Vec<&str> = src
        .lines()
        .filter(|l| l.contains("crypto::"))
        .map(str::trim)
        .collect();
    assert_eq!(crypto, ["use crate::crypto::{MAX_PAYLOAD_LEN, ct_eq};"]);
}

#[test]
fn report_last_line_texts_verbatim() {
    let (store, _f, anchor) = anchored_store();
    let ex = export_all(&store);
    let chain = &ex.receipt.chain_ids[0];
    let v = verify_export(&ex.dir, None, Some(ex.hash));
    assert_eq!(
        v.report(),
        &[
            format!("rows 9 from seq 1 to 9, chains {chain}"),
            "chain: ok".to_string(),
            "payloads: ok".to_string(),
            "writes: ok".to_string(),
            "prune_log: ok".to_string(),
            "restore boundaries: ok".to_string(),
            "manifest: ok".to_string(),
            "anchor dir: not checked".to_string(),
            MANIFEST_OK.to_string(),
        ]
    );
    assert_eq!(
        last(&verify_export(&ex.dir, Some(anchor.path()), None)),
        ANCHOR_OK
    );
    assert_eq!(
        last(&verify_export(&ex.dir, Some(anchor.path()), Some(ex.hash))),
        BOTH_OK
    );
    // Both roots given, but the anchor dir (empty, or another installation's) names no row: only
    // the manifest SHA-256 verified the export (T8 review I-3).
    let empty = tempfile::tempdir().expect("empty anchor dir");
    let v = verify_export(&ex.dir, Some(empty.path()), Some(ex.hash));
    expect(&v, 0, "manifest, and an anchor dir naming no row");
    assert_eq!(
        &v.report()[7..],
        &[
            "anchor dir: no line names a row of this export; rows 1..9 covered by the manifest \
             SHA-256 only"
                .to_string(),
            MANIFEST_OK.to_string(),
        ]
    );
    let v = verify_export(&ex.dir, None, None);
    assert!(has_line(&v, "manifest: not checked"));
    assert_eq!(last(&v), NO_ROOT);
    let v = verify_export(&ex.dir.join("nope"), None, None);
    assert!(last(&v).starts_with("cannot verify: "), "{:?}", v.report());
}

// ---------------------------------------------------------------------------------------
// bounded memory

/// The verifier's documented working set per row (module doc "Working set"): this many times the
/// line bound, one value tree of at most [`TREE_TEXT`] bytes of JSON text (at most
/// [`TREE_FACTOR`] times its text), and fixed buffers under [`FIXED`].
const LINE_FACTOR: usize = 4;
const TREE_TEXT: usize = 1 << 20;
const TREE_FACTOR: usize = 32;
const FIXED: usize = 128 << 10;

fn documented_bound(line: u64) -> usize {
    let line = usize::try_from(line).expect("line bound");
    LINE_FACTOR * line + TREE_FACTOR * line.min(TREE_TEXT) + FIXED
}

/// An export whose row 3 `edit` changes (rehashed), and the length of its longest line.
fn forged_row(edit: impl FnOnce(&mut Value)) -> (Copy, u64) {
    let (store, _f) = basic_store(4);
    let ex = export_all(&store);
    let c = copy_export(&ex.dir);
    let mut fg = Forge::load(&c.dir);
    edit(&mut fg.lines[2]);
    fg.rehash();
    fg.save();
    let longest = raw_lines(&c.dir).iter().map(Vec::len).max().expect("lines");
    (c, longest as u64)
}

/// A text column with escapes costs serde_json a scratch copy (up to twice the decoded text by
/// `Vec` doubling: `"\n"`, then the long run reserved exactly, then the second escape doubles it)
/// and the owned `String`, beside the line buffer (T8 review I-2). The line bound is set to the
/// line's length so the line buffer is measured at its cap.
#[test]
fn escaped_text_column_stays_within_the_documented_bound() {
    let run = 4 << 20;
    let (c, longest) = forged_row(|l| {
        let mut target = String::with_capacity(run + 2);
        target.push('\n');
        target.extend(std::iter::repeat_n('a', run));
        target.push('\n');
        l["target"] = json!(target);
    });
    let lim = Limits {
        line: longest,
        ..Limits::default()
    };
    let (v, peak) = peak_during(|| verify_export_with(&OsFs, lim, &c.dir, None, None));
    expect(&v, 20, "a consistent forgery");
    eprintln!(
        "verify_export escaped text column: line {longest} bytes, peak {peak} bytes ({:.2} x)",
        peak as f64 / longest as f64
    );
    let bound = LINE_FACTOR * longest as usize + FIXED;
    assert!(peak <= bound, "peak {peak} > {bound}");
}

/// The absence check of `payload` parses a plaintext of at most 1 MiB into a value tree (T8
/// review I-1): the largest tree per byte of text is a list of one-digit numbers.
#[test]
fn value_tree_of_a_small_plaintext_stays_within_the_documented_bound() {
    let n = (TREE_TEXT - 1) / 2;
    let mut plain = String::with_capacity(TREE_TEXT);
    plain.push('[');
    for i in 0..n {
        plain.push_str(if i + 1 < n { "0," } else { "0]" });
    }
    assert!(plain.len() <= TREE_TEXT);
    let (c, longest) = forged_row(|l| {
        l["payload_b64"] = json!(STANDARD.encode(&plain));
        l["payload_len"] = json!(plain.len());
        l["payload_sha256"] = json!(hex::encode(sha256(plain.as_bytes())));
        l.as_object_mut().unwrap().remove("payload");
    });
    let lim = Limits {
        line: longest,
        ..Limits::default()
    };
    let (v, peak) = peak_during(|| verify_export_with(&OsFs, lim, &c.dir, None, None));
    expect(&v, 21, "a JCS plaintext of 1 MiB without its payload field");
    assert!(
        has_line(&v, "payloads: mismatch at seq 3"),
        "{:?}",
        v.report()
    );
    eprintln!(
        "verify_export value tree of {} bytes: peak {peak} bytes",
        plain.len()
    );
    let bound = documented_bound(longest);
    assert!(peak <= bound, "peak {peak} > {bound}");
}

/// What the garbage cases change in one of the three files.
#[derive(Debug, Clone)]
enum Mutation {
    Flip {
        file: usize,
        at: usize,
        byte: u8,
    },
    Truncate {
        file: usize,
        keep: usize,
    },
    Insert {
        file: usize,
        at: usize,
        bytes: Vec<u8>,
    },
    Replace {
        file: usize,
        bytes: Vec<u8>,
    },
    /// A claimed number far beyond any real one, in place of a key's value.
    Claim {
        file: usize,
        key: usize,
        value: usize,
    },
    /// A line of deeply nested arrays.
    Deep {
        file: usize,
        depth: usize,
    },
    /// A line longer than the (lowered) line bound.
    Long {
        file: usize,
        extra: usize,
    },
}

const FILES: [&str; 3] = ["events.jsonl", "prune_log.jsonl", "manifest.json"];
const CLAIM_KEYS: [&str; 8] = [
    "payload_len",
    "rows",
    "first_seq",
    "last_seq",
    "seq",
    "prune_seq",
    "key_id",
    "last_anchored_seq",
];
const CLAIMS: [&str; 6] = [
    "18446744073709551615",
    "9007199254740993",
    "1e308",
    "-1",
    "340282366920938463463374607431768211456",
    "0",
];

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (0..3usize, any::<usize>(), any::<u8>()).prop_map(|(file, at, byte)| Mutation::Flip {
            file,
            at,
            byte
        }),
        (0..3usize, any::<usize>()).prop_map(|(file, keep)| Mutation::Truncate { file, keep }),
        (
            0..3usize,
            any::<usize>(),
            proptest::collection::vec(any::<u8>(), 1..64)
        )
            .prop_map(|(file, at, bytes)| Mutation::Insert { file, at, bytes }),
        (0..3usize, proptest::collection::vec(any::<u8>(), 0..512))
            .prop_map(|(file, bytes)| Mutation::Replace { file, bytes }),
        (0..3usize, 0..CLAIM_KEYS.len(), 0..CLAIMS.len())
            .prop_map(|(file, key, value)| Mutation::Claim { file, key, value }),
        (0..3usize, 50..400usize).prop_map(|(file, depth)| Mutation::Deep { file, depth }),
        (0..3usize, 1..256usize).prop_map(|(file, extra)| Mutation::Long { file, extra }),
    ]
}

/// The lowered bounds of the garbage run (the real ones would need 257 MiB lines).
fn small_limits() -> Limits {
    Limits {
        line: 64 * 1024,
        manifest: 16 * 1024,
        prune_log: 64 * 1024,
        prune_log_rows: 1000,
        prune_log_line: 4096,
        anchor_file: 64 * 1024,
        anchor_files: 16,
        ..Limits::default()
    }
}

fn apply(m: &Mutation, files: &mut [Vec<u8>; 3], lim: &Limits) {
    let at = |len: usize, i: usize| if len == 0 { 0 } else { i % (len + 1) };
    match m {
        Mutation::Flip { file, at: i, byte } => {
            let f = &mut files[*file];
            if !f.is_empty() {
                let i = i % f.len();
                f[i] = if f[i] == *byte { byte ^ 1 } else { *byte };
            } else {
                f.push(*byte);
            }
        }
        Mutation::Truncate { file, keep } => {
            let f = &mut files[*file];
            let n = if f.is_empty() { 0 } else { keep % f.len() };
            f.truncate(n);
        }
        Mutation::Insert { file, at: i, bytes } => {
            let f = &mut files[*file];
            let i = at(f.len(), *i);
            f.splice(i..i, bytes.iter().copied());
        }
        Mutation::Replace { file, bytes } => files[*file] = bytes.clone(),
        Mutation::Claim { file, key, value } => {
            let f = &mut files[*file];
            let text = String::from_utf8_lossy(f).into_owned();
            let pat = format!("\"{}\":", CLAIM_KEYS[*key]);
            match text.find(&pat) {
                Some(start) => {
                    let from = start + pat.len();
                    let end = text[from..]
                        .find([',', '}'])
                        .map_or(text.len(), |e| from + e);
                    *f =
                        format!("{}{}{}", &text[..from], CLAIMS[*value], &text[end..]).into_bytes();
                }
                None => f.extend_from_slice(format!("{pat}{}", CLAIMS[*value]).as_bytes()),
            }
        }
        Mutation::Deep { file, depth } => {
            let mut line = "[".repeat(*depth);
            line.push_str(&"]".repeat(*depth));
            line.push('\n');
            files[*file].splice(0..0, line.into_bytes());
        }
        Mutation::Long { file, extra } => {
            let n = lim.line.max(lim.manifest) as usize + extra;
            let mut line = vec![b'a'; n];
            line.push(b'\n');
            files[*file].splice(0..0, line);
        }
    }
}

#[test]
fn verify_export_garbage_never_panics() {
    let (store, _f, anchor) = anchored_store();
    store.append_batch(varied(6)).expect("append");
    let ex = export_all(&store);
    let template: [Vec<u8>; 3] = FILES.map(|f| std::fs::read(ex.dir.join(f)).expect("file"));
    let lim = small_limits();
    let cases = std::env::var("ATLAS_DUCK_VERIFY_EXPORT_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(256);
    // The documented bound at the lowered line bound, never a claimed number.
    let bound = documented_bound(lim.line);
    // The manifest keys no check compares with the files: a change to them alone may verify.
    let free_text = [
        "accountability",
        "app_version",
        "build_id",
        "exported_at",
        "install",
        "requested_range",
    ];
    let claims = |bytes: &[u8]| -> Option<Value> {
        let mut v: Value = serde_json::from_slice(bytes).ok()?;
        let o = v.as_object_mut()?;
        for k in free_text {
            o.remove(k);
        }
        Some(v)
    };
    let template_claims = claims(&template[2]);
    let mut runner = TestRunner::new(ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    });
    let worst = Cell::new(0);
    runner
        .run(&(mutation(), any::<bool>()), |(m, with_anchor)| {
            let mut files = template.clone();
            apply(&m, &mut files, &lim);
            prop_assume!(files != template);
            let tmp = tempfile::tempdir().expect("tmp");
            let dir = tmp.path().join(ex.dir.file_name().expect("name"));
            std::fs::create_dir(&dir).expect("dir");
            for (name, bytes) in FILES.iter().zip(&files) {
                std::fs::write(dir.join(name), bytes).expect("write");
            }
            let root = with_anchor.then_some(anchor.path());
            let free_only = files[..2] == template[..2] && claims(&files[2]) == template_claims;
            // (a) the honest manifest's hash: every change is 21 or 22; (b) no manifest root: never
            // 0 (the template's last rows are unanchored, so the anchor dir alone never verifies
            // it); (c) the mutated manifest's own hash, so its parser and every claim are judged
            // against the files: 21 or 22 unless only free text changed.
            for (mode, given) in [
                ("honest manifest", Some(ex.hash)),
                ("no manifest root", None),
                ("mutated manifest", Some(sha256(&files[2]))),
            ] {
                let (v, peak) = peak_during(|| verify_export_with(&OsFs, lim, &dir, root, given));
                worst.set(worst.get().max(peak));
                let code = v.exit_code();
                let ok = match given {
                    None => code != 0,
                    Some(h) if h == ex.hash => matches!(code, 21 | 22),
                    Some(_) => matches!(code, 21 | 22) || (free_only && code == 0),
                };
                if !ok {
                    return Err(TestCaseError::fail(format!(
                        "{mode}: {m:?}: {:?}",
                        v.report()
                    )));
                }
                if peak > bound {
                    return Err(TestCaseError::fail(format!(
                        "{mode}: {m:?}: peak {peak} > {bound}"
                    )));
                }
            }
            Ok(())
        })
        .expect("no garbage export verifies, and each stays within the bound");
    eprintln!(
        "verify_export garbage: {cases} cases, worst peak {} bytes (bound {bound})",
        worst.get()
    );
}

/// The largest plaintext the store takes, exported by T7 and verified: exit 0, with the
/// verifier's peak heap within its documented bound ([`documented_bound`] of
/// `MAX_EXPORT_LINE_BYTES`; this honest row needs far less, about one line).
#[test]
#[ignore = "CI: large-payload export step"]
fn max_size_payload_round_trips() {
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
    store
        .append(ev(EventType::READ_FETCHED, None, json!({ "s": s })))
        .expect("append the largest payload");
    drop(s);
    let ex = export_all(&store);
    let (v, peak) = peak_during(|| verify_export(&ex.dir, None, Some(ex.hash)));
    expect(&v, 0, "the largest row");
    let bound = documented_bound(MAX_EXPORT_LINE_BYTES);
    eprintln!("verify_export of a 96 MiB payload: peak {peak} bytes (bound {bound})");
    assert!(peak <= bound, "peak {peak} > {bound}");
}
