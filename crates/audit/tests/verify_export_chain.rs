//! M14 T19 (SM-6.3, PD-259): `verify-export` of a server export with its anchor-chain excerpt.
//! A pinned anchor head binds the export rows up to the highest in-range leaf entry (0 when that
//! is the last row, else 20); any contradiction is 21; an excerpt that cannot be read or breaks a
//! bound is 22. Exports come from a real store; excerpts from `testing::AnchorSeq`, the way the
//! server's export job writes them.
//!
//! A separate test binary from `verify_export.rs` so its per-thread counting allocator measures
//! only these cases.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use atlas_duck_audit::server_anchor::{EXCERPT_FILE, EXCERPT_MANIFEST_FILE};
use atlas_duck_audit::testing::{AnchorSeq, MemKeyring, write_excerpt};
use atlas_duck_audit::types::RustChosenPath;
use atlas_duck_audit::verify_export::{
    ANCHOR_CHAIN_OK, AnchorChain, Limits, MANIFEST_AND_CHAIN_OK, MSG_ONE_MODE, OsFs,
    verify_export_full_with,
};
use atlas_duck_audit::{ExportControl, ExportVerdict, Store, TimeRange, verify_export_full};
use common::*;
use proptest::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------------------
// A per-thread counting allocator (as in verify_export.rs)

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

fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.with(Cell::get);
    PEAK.with(|p| p.set(base));
    let t = f();
    let peak = PEAK.with(Cell::get) - base;
    (t, usize::try_from(peak).unwrap_or(0))
}

// ---------------------------------------------------------------------------------------
// helpers

const USER: &str = "0123456789abcdef0123456789abcdef";
const MANIFEST_OK: &str = "verified against the manifest SHA-256";
const NO_ROOT: &str = "internally consistent; trust root NOT verified";

/// A store export: its directory, manifest hash, chain id and per-row record hashes.
struct Exported {
    _out: tempfile::TempDir,
    dir: PathBuf,
    hash: [u8; 32],
    chain: String,
    /// `record_hash` of seq `i + 1`.
    rows: Vec<[u8; 32]>,
}

fn exported(n: usize) -> Exported {
    let (store, _f) = new_store(fake_clock(START), MemKeyring::new());
    store.append_batch(mixed(n)).expect("append");
    export_of(&store)
}

fn export_of(store: &Store) -> Exported {
    let out = tempfile::tempdir().expect("out");
    let cancel = AtomicBool::new(false);
    let progress = |_: u64, _: u64| {};
    let receipt = store
        .export(
            TimeRange::all(),
            RustChosenPath::from_native_dialog(out.path().to_path_buf()),
            &ExportControl {
                progress: &progress,
                cancel: &cancel,
            },
        )
        .expect("export");
    let dir = out.path().join(&receipt.dir_name);
    let text = std::fs::read_to_string(dir.join("events.jsonl")).expect("events");
    let lines: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("line"))
        .collect();
    let chain = lines[0]["chain_id"].as_str().expect("chain").to_owned();
    // A row's record hash is the next row's prev_hash; the last one is the manifest's head.
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).expect("manifest"))
            .expect("manifest json");
    let hex32 = |v: &Value| {
        let mut h = [0u8; 32];
        hex::decode_to_slice(v.as_str().expect("hash"), &mut h).expect("hex");
        h
    };
    let mut rows: Vec<[u8; 32]> = lines
        .iter()
        .skip(1)
        .map(|l| hex32(&l["prev_hash"]))
        .collect();
    rows.push(hex32(&manifest["head"]["record_hash"]));
    Exported {
        _out: out,
        dir,
        hash: receipt.manifest_sha256,
        chain,
        rows,
    }
}

impl Exported {
    fn last(&self) -> u64 {
        self.rows.len() as u64
    }

    /// The leaf tuple of row `seq`.
    fn mine(&self, seq: u64) -> Option<(&str, &str, u64, [u8; 32])> {
        Some((USER, &self.chain, seq, self.rows[seq as usize - 1]))
    }

    /// An anchor sequence: a start row, a `HEADS` naming seq `mid`, an operational row, a
    /// `HEADS` naming seq `anchored` (among three other users).
    fn seq(&self, mid: u64, anchored: u64) -> AnchorSeq {
        let mut a = AnchorSeq::new();
        a.op("SERVER_START");
        a.heads(self.mine(mid), 2);
        a.op("AUDITOR_READ");
        a.heads(self.mine(anchored), 3);
        a
    }

    fn excerpt(&self) -> PathBuf {
        self.dir.join(EXCERPT_FILE)
    }

    fn verify(&self, head: Option<(u64, [u8; 32])>, manifest: Option<[u8; 32]>) -> ExportVerdict {
        verify_export_full(
            &self.dir,
            None,
            Some(AnchorChain {
                excerpt: &self.excerpt(),
                head,
            }),
            manifest,
        )
    }
}

fn last_line(v: &ExportVerdict) -> &str {
    v.report().last().map(String::as_str).unwrap_or("")
}

#[track_caller]
fn expect(v: &ExportVerdict, code: u8, what: &str) {
    assert_eq!(v.exit_code(), code, "{what}: {:#?}", v.report());
}

fn chain_line(v: &ExportVerdict) -> &str {
    v.report()
        .iter()
        .find(|l| l.starts_with("anchor chain: "))
        .map(String::as_str)
        .unwrap_or("")
}

fn read_lines(p: &Path) -> Vec<Vec<u8>> {
    std::fs::read(p)
        .expect("excerpt")
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn write_lines(p: &Path, lines: &[Vec<u8>]) {
    let mut out = Vec::new();
    for l in lines {
        out.extend_from_slice(l);
        out.push(b'\n');
    }
    std::fs::write(p, out).expect("write");
}

// ---------------------------------------------------------------------------------------
// The verdicts

#[test]
fn a_pinned_head_that_anchors_the_last_row_verifies() {
    let ex = exported(6);
    let a = ex.seq(3, ex.last());
    a.write(&ex.dir, 1, a.head().0, &ex.chain).unwrap();
    let v = ex.verify(Some(a.head()), None);
    expect(&v, 0, "pinned head");
    assert_eq!(last_line(&v), ANCHOR_CHAIN_OK);
    assert_eq!(chain_line(&v), "anchor chain: ok");
    // The excerpt files are verified, so not named as other entries.
    assert!(
        !v.report().iter().any(|l| l.contains(EXCERPT_MANIFEST_FILE)),
        "{:#?}",
        v.report()
    );
    // Both roots: the manifest hash and the pinned head.
    let v = ex.verify(Some(a.head()), Some(ex.hash));
    expect(&v, 0, "both roots");
    assert_eq!(last_line(&v), MANIFEST_AND_CHAIN_OK);
    // A pin at an earlier row binds through that row's leaf entries only.
    let v = ex.verify(Some((2, row_hash_at(&ex, 2))), None);
    expect(&v, 20, "earlier pin");
    assert!(
        chain_line(&v).contains("rows after seq 3 are not anchored"),
        "{v:#?}"
    );
}

/// The hash of excerpt row `seq`, read back from the file.
fn row_hash_at(ex: &Exported, seq: u64) -> [u8; 32] {
    let lines = read_lines(&ex.excerpt());
    let v: Value = serde_json::from_slice(&lines[seq as usize - 1]).unwrap();
    let mut h = [0u8; 32];
    hex::decode_to_slice(v["hash"].as_str().unwrap(), &mut h).unwrap();
    h
}

#[test]
fn a_wrong_or_absent_pin_is_a_contradiction() {
    let ex = exported(6);
    let a = ex.seq(3, ex.last());
    a.write(&ex.dir, 1, a.head().0, &ex.chain).unwrap();
    let (s, mut h) = a.head();
    h[0] ^= 1;
    let v = ex.verify(Some((s, h)), None);
    expect(&v, 21, "pin hash wrong");
    assert!(last_line(&v).starts_with("TAMPERED: "), "{v:#?}");
    let v = ex.verify(Some((s + 5, a.head().1)), None);
    expect(&v, 21, "pin seq absent");
    assert!(chain_line(&v).contains("is not in the excerpt"), "{v:#?}");
}

#[test]
fn a_leaf_that_names_another_record_hash_is_a_contradiction() {
    let ex = exported(6);
    let mut a = AnchorSeq::new();
    a.op("SERVER_START");
    let mut wrong = ex.rows[5];
    wrong[31] ^= 1;
    a.heads(Some((USER, &ex.chain, 6, wrong)), 2);
    a.write(&ex.dir, 1, 2, &ex.chain).unwrap();
    // Pinned or not, a leaf entry contradicting a row is 21.
    for head in [Some(a.head()), None] {
        let v = ex.verify(head, Some(ex.hash));
        expect(&v, 21, "leaf mismatch");
        assert!(
            chain_line(&v).contains("seq 6 with another record hash"),
            "{v:#?}"
        );
    }
}

#[test]
fn tampered_gapped_or_foreign_excerpts_are_contradictions() {
    let ex = exported(6);
    let a = ex.seq(3, ex.last());
    let head = a.head();
    // A row hash changed.
    a.write(&ex.dir, 1, head.0, &ex.chain).unwrap();
    let mut lines = read_lines(&ex.excerpt());
    let mut v: Value = serde_json::from_slice(&lines[2]).unwrap();
    v["ts_utc"] = Value::from("2026-10-27T11:00:00.000Z");
    lines[2] = serde_json::to_vec(&v).unwrap();
    write_lines(&ex.excerpt(), &lines);
    let r = ex.verify(Some(head), None);
    expect(&r, 21, "row hash tampered");
    // A gap.
    a.write(&ex.dir, 1, head.0, &ex.chain).unwrap();
    let mut lines = read_lines(&ex.excerpt());
    lines.remove(2);
    write_lines(&ex.excerpt(), &lines);
    let r = ex.verify(Some(head), None);
    expect(&r, 21, "gap");
    assert!(chain_line(&r).contains("where seq 3 belongs"), "{r:#?}");
    // Another chain's excerpt.
    a.write(&ex.dir, 1, head.0, "c-someone-else").unwrap();
    let r = ex.verify(Some(head), None);
    expect(&r, 21, "foreign chain");
    // The manifest's last row is not the file's.
    a.write(&ex.dir, 1, head.0, &ex.chain).unwrap();
    let mut m = a.manifest(1, head.0, &ex.chain);
    m.last_hash = hex::encode([7u8; 32]);
    write_excerpt(&ex.dir, &a.lines(1, head.0), &m).unwrap();
    let r = ex.verify(None, None);
    expect(&r, 21, "last hash");
}

#[test]
fn an_anchoring_older_than_the_export_binds_only_its_rows() {
    let ex = exported(6);
    let a = ex.seq(2, 4);
    a.write(&ex.dir, 1, a.head().0, &ex.chain).unwrap();
    let v = ex.verify(Some(a.head()), None);
    expect(&v, 20, "rows 5..6 unanchored");
    assert!(
        chain_line(&v).contains("rows after seq 4 are not anchored"),
        "{v:#?}"
    );
    assert_eq!(last_line(&v), NO_ROOT);
    // With the manifest hash it is verified by the manifest and binds rows of the chain too.
    let v = ex.verify(Some(a.head()), Some(ex.hash));
    expect(&v, 0, "manifest");
    assert_eq!(last_line(&v), MANIFEST_AND_CHAIN_OK);
}

#[test]
fn without_a_pin_the_excerpt_is_consistency_only() {
    let ex = exported(6);
    let a = ex.seq(3, ex.last());
    a.write(&ex.dir, 1, a.head().0, &ex.chain).unwrap();
    let v = ex.verify(None, None);
    expect(&v, 20, "no pin, no manifest");
    assert_eq!(last_line(&v), NO_ROOT);
    let unanchored = |v: &ExportVerdict| {
        let l = chain_line(v);
        assert!(
            l.starts_with("anchor chain: unanchored; no head pinned") && !l.contains("ok"),
            "{v:#?}"
        );
    };
    unanchored(&v);
    let v = ex.verify(None, Some(ex.hash));
    expect(&v, 0, "manifest only");
    assert_eq!(last_line(&v), MANIFEST_OK);
    unanchored(&v);
}

#[test]
fn an_anchor_dir_and_an_excerpt_together_are_refused() {
    let ex = exported(3);
    let a = ex.seq(1, 3);
    a.write(&ex.dir, 1, a.head().0, &ex.chain).unwrap();
    let anchor = tempfile::tempdir().unwrap();
    let v = verify_export_full(
        &ex.dir,
        Some(anchor.path()),
        Some(AnchorChain {
            excerpt: &ex.excerpt(),
            head: Some(a.head()),
        }),
        Some(ex.hash),
    );
    expect(&v, 22, "two modes");
    assert!(last_line(&v).contains(MSG_ONE_MODE), "{v:#?}");
}

// ---------------------------------------------------------------------------------------
// Bounds

#[test]
fn an_over_long_line_is_refused_without_allocating_it() {
    let ex = exported(3);
    let a = ex.seq(1, 3);
    a.write(&ex.dir, 1, a.head().0, &ex.chain).unwrap();
    // A 32 MiB "line" claiming nothing in particular; the bound is 64 KiB.
    let mut lines = read_lines(&ex.excerpt());
    lines[1] = vec![b'x'; 32 * 1024 * 1024];
    write_lines(&ex.excerpt(), &lines);
    let lim = Limits {
        anchor_chain_line: 64 * 1024,
        ..Limits::default()
    };
    let (v, peak) = peak_during(|| {
        verify_export_full_with(
            &OsFs,
            lim,
            &ex.dir,
            None,
            Some(AnchorChain {
                excerpt: &ex.excerpt(),
                head: Some(a.head()),
            }),
            Some(ex.hash),
        )
    });
    expect(&v, 22, "over-long line");
    assert!(last_line(&v).contains("line 2 is longer than"), "{v:#?}");
    assert!(peak < 1024 * 1024, "peak {peak}");
}

#[test]
fn more_rows_than_the_bound_is_refused() {
    let ex = exported(2);
    let mut a = AnchorSeq::new();
    for _ in 0..100_001 {
        a.op("AUDITOR_READ");
    }
    // The manifest claims the bound exactly; the file holds one row more.
    let m = a.manifest(1, 100_000, &ex.chain);
    write_excerpt(&ex.dir, &a.lines(1, 100_001), &m).unwrap();
    let v = ex.verify(None, Some(ex.hash));
    expect(&v, 22, "100 001 rows");
    assert!(last_line(&v).contains("more than 100000 rows"), "{v:#?}");
    // A manifest naming a longer span is refused before the file is read.
    let m = a.manifest(1, 100_001, &ex.chain);
    write_excerpt(&ex.dir, &a.lines(1, 2), &m).unwrap();
    let v = ex.verify(None, Some(ex.hash));
    expect(&v, 22, "span");
}

#[test]
fn a_missing_or_malformed_excerpt_cannot_be_verified() {
    let ex = exported(3);
    let a = ex.seq(1, 3);
    let v = ex.verify(Some(a.head()), Some(ex.hash));
    expect(&v, 22, "missing excerpt manifest");
    a.write(&ex.dir, 1, a.head().0, &ex.chain).unwrap();
    std::fs::remove_file(ex.excerpt()).unwrap();
    let v = ex.verify(Some(a.head()), Some(ex.hash));
    expect(&v, 22, "missing excerpt");
    a.write(&ex.dir, 1, a.head().0, &ex.chain).unwrap();
    let mut lines = read_lines(&ex.excerpt());
    lines[0] = b"{\"v\":2}".to_vec();
    write_lines(&ex.excerpt(), &lines);
    let v = ex.verify(Some(a.head()), Some(ex.hash));
    expect(&v, 22, "not an excerpt line");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    /// Mutated excerpt bytes: a verdict, never a panic, within 10 s per case.
    #[test]
    fn mutated_excerpts_never_panic_or_hang(
        edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..8),
        cut in proptest::option::of(any::<usize>()),
    ) {
        thread_local! {
            static FIX: (Exported, AnchorSeq, Vec<u8>) = {
                let ex = exported(4);
                let a = ex.seq(2, 4);
                a.write(&ex.dir, 1, a.head().0, &ex.chain).unwrap();
                let bytes = std::fs::read(ex.excerpt()).unwrap();
                (ex, a, bytes)
            };
        }
        FIX.with(|(ex, a, bytes)| {
            let mut b = bytes.clone();
            for (pos, val) in &edits {
                let i = pos % b.len();
                b[i] = *val;
            }
            if let Some(c) = cut {
                b.truncate(c % (b.len() + 1));
            }
            std::fs::write(ex.excerpt(), &b).unwrap();
            let start = std::time::Instant::now();
            let v = ex.verify(Some(a.head()), Some(ex.hash));
            prop_assert!(start.elapsed() < Duration::from_secs(10));
            prop_assert!([0, 20, 21, 22].contains(&v.exit_code()));
            // An untouched excerpt stays verified; a changed one never claims the chain.
            if b != *bytes {
                prop_assert_ne!(last_line(&v), MANIFEST_AND_CHAIN_OK);
            }
            Ok(())
        })?;
    }
}

#[test]
fn excerpt_digest_is_stable() {
    // The helper's lines are deterministic: a fixed sequence hashes the same every run.
    let mut a = AnchorSeq::new();
    a.op("SERVER_START");
    a.heads(Some((USER, "c1", 1, [1; 32])), 2);
    let d1: [u8; 32] = Sha256::digest(a.lines(1, 2).concat()).into();
    let mut b = AnchorSeq::new();
    b.op("SERVER_START");
    b.heads(Some((USER, "c1", 1, [1; 32])), 2);
    let d2: [u8; 32] = Sha256::digest(b.lines(1, 2).concat()).into();
    assert_eq!(d1, d2);
}
