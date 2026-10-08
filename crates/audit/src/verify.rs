//! Verification (§8.7): the startup check against the pre-migration store (chain from the
//! latest `PRUNE`/`RESTORE`/`APP_START` to the head, the anchor rule with the unanchored tail,
//! the interrupted-prune and interrupted-restore rules) and the full verification (whole
//! chain, decrypt pass, `request_set_hash`, DEK references, prune judgement, `RESTORE`
//! boundaries). Both only read; the `VERIFY` row is appended by the store.
//!
//! Every hash comparison is constant-time ([`ct_eq`]). Finding details carry numbers, ids,
//! dates and fixed text only, never payload bytes.

use std::collections::{BTreeSet, HashMap};

use chrono::{Days, NaiveDate};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::anchor_dir::{self, AnchorDirLines, LostSpan, VerifyCtx};
use crate::anchors::{FirstRetainedAnchor, HeadAnchor};
use crate::clock::parse_epoch;
use crate::crypto::{self, Dek, Kek, ct_eq};
use crate::encoding::{self, FIELD_LIST, FORMAT_VERSION, RowFields, ZERO_HASH};
use crate::error::{AuditError, OpenError};
use crate::request_set::{request_set_hash, requests_from_json};
use crate::types::EventFlags;

/// At most this many findings of one kind are listed; the rest are counted in one summary
/// finding, so a `VERIFY` payload stays far below the payload cap whatever the damage.
pub const MAX_FINDINGS_PER_KIND: usize = 100;

/// `retention_days` minimum (§8.8); a `PRUNE` whose snapshot names less is judged an incident.
pub const MIN_RETENTION_DAYS: u64 = 92;

/// Every flag bit up to and including `integrity_incident`; anything above is never valid.
const KNOWN_FLAG_BITS: u64 = (EventFlags::INTEGRITY_INCIDENT.bits() << 1) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FindingKind {
    // incident kinds
    ChainBroken,
    SeqGap,
    UnknownFlagBits,
    FormatVersionUnsupported,
    PruneLogBroken,
    PruneLogNotContiguous,
    PruneLogRowMismatch,
    FirstRetainedMismatch,
    AnchorMismatch,
    AnchorAhead,
    AnchorMissing,
    InstallIdMismatch,
    PayloadHashMismatch,
    DecryptFailed,
    RequestSetHashMismatch,
    DestroyedKeyReferenced,
    PruneInsideRetention,
    RestoreBoundaryMismatch,
    AnchorDirMismatch,
    AnchoredRecordPrunedEarly,
    // informational kinds
    UnanchoredTail,
    InterruptedPruneReconciled,
    InterruptedRestoreReconciled,
}

impl FindingKind {
    /// The snake_case name used in `VERIFY` payloads (`result`, `findings[].kind`).
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingKind::ChainBroken => "chain_broken",
            FindingKind::SeqGap => "seq_gap",
            FindingKind::UnknownFlagBits => "unknown_flag_bits",
            FindingKind::FormatVersionUnsupported => "format_version_unsupported",
            FindingKind::PruneLogBroken => "prune_log_broken",
            FindingKind::PruneLogNotContiguous => "prune_log_not_contiguous",
            FindingKind::PruneLogRowMismatch => "prune_log_row_mismatch",
            FindingKind::FirstRetainedMismatch => "first_retained_mismatch",
            FindingKind::AnchorMismatch => "anchor_mismatch",
            FindingKind::AnchorAhead => "anchor_ahead",
            FindingKind::AnchorMissing => "anchor_missing",
            FindingKind::InstallIdMismatch => "install_id_mismatch",
            FindingKind::PayloadHashMismatch => "payload_hash_mismatch",
            FindingKind::DecryptFailed => "decrypt_failed",
            FindingKind::RequestSetHashMismatch => "request_set_hash_mismatch",
            FindingKind::DestroyedKeyReferenced => "destroyed_key_referenced",
            FindingKind::PruneInsideRetention => "prune_inside_retention",
            FindingKind::RestoreBoundaryMismatch => "restore_boundary_mismatch",
            FindingKind::AnchorDirMismatch => "anchor_dir_mismatch",
            FindingKind::AnchoredRecordPrunedEarly => "anchored_record_pruned_early",
            FindingKind::UnanchoredTail => "unanchored_tail",
            FindingKind::InterruptedPruneReconciled => "interrupted_prune_reconciled",
            FindingKind::InterruptedRestoreReconciled => "interrupted_restore_reconciled",
        }
    }

    /// Everything except the three informational kinds is an integrity incident.
    pub fn is_incident(&self) -> bool {
        !matches!(
            self,
            FindingKind::UnanchoredTail
                | FindingKind::InterruptedPruneReconciled
                | FindingKind::InterruptedRestoreReconciled
        )
    }
}

/// Findings about the chain itself; an interrupted prune or restore is reconciled only when
/// none of them (and no anchor-dir line contradicting the store) was found.
const CHAIN_KINDS: [FindingKind; 11] = [
    FindingKind::ChainBroken,
    FindingKind::SeqGap,
    FindingKind::UnknownFlagBits,
    FindingKind::FormatVersionUnsupported,
    FindingKind::PruneLogBroken,
    FindingKind::PruneLogNotContiguous,
    FindingKind::PruneLogRowMismatch,
    FindingKind::FirstRetainedMismatch,
    FindingKind::DecryptFailed,
    FindingKind::PayloadHashMismatch,
    FindingKind::RestoreBoundaryMismatch,
];

/// One finding (F.11 `findings[]`). The hashes are chain hashes (not secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyFinding {
    pub kind: FindingKind,
    pub expected_seq: Option<u64>,
    pub expected_hash: Option<[u8; 32]>,
    pub observed_seq: Option<u64>,
    pub observed_hash: Option<[u8; 32]>,
    pub detail: String,
}

impl VerifyFinding {
    pub(crate) fn new(kind: FindingKind, detail: impl Into<String>) -> VerifyFinding {
        VerifyFinding {
            kind,
            expected_seq: None,
            expected_hash: None,
            observed_seq: None,
            observed_hash: None,
            detail: detail.into(),
        }
    }

    pub(crate) fn expected(mut self, seq: Option<u64>, hash: Option<[u8; 32]>) -> VerifyFinding {
        self.expected_seq = seq;
        self.expected_hash = hash;
        self
    }

    pub(crate) fn observed(mut self, seq: Option<u64>, hash: Option<[u8; 32]>) -> VerifyFinding {
        self.observed_seq = seq;
        self.observed_hash = hash;
        self
    }

    fn to_json(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "expected_seq": self.expected_seq,
            "expected_hash": self.expected_hash.map(hex::encode),
            "observed_seq": self.observed_seq,
            "observed_hash": self.observed_hash.map(hex::encode),
            "detail": self.detail,
        })
    }
}

/// What a verification run produced (C.3). `verify_seq` is the `VERIFY` row appended for it,
/// if any (a clean startup appends none).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyOutcome {
    pub findings: Vec<VerifyFinding>,
    pub unanchored_tail: u64,
    pub verify_seq: Option<u64>,
}

/// The `VERIFY` payload (F.11): `result` is the first incident kind, else the first
/// informational kind, else `"ok"`.
pub(crate) fn verify_payload(
    scope: &str,
    findings: &[VerifyFinding],
    detected_at: &str,
    unanchored_tail: Option<u64>,
) -> Value {
    let result = findings
        .iter()
        .find(|f| f.kind.is_incident())
        .or_else(|| findings.first())
        .map_or("ok", |f| f.kind.as_str());
    json!({
        "scope": scope,
        "result": result,
        "findings": findings.iter().map(VerifyFinding::to_json).collect::<Vec<_>>(),
        "detected_at": detected_at,
        "unanchored_tail": unanchored_tail,
    })
}

/// The interrupted-restore completion the verdict asks for (T16 carries it out): the anchors
/// the reset writes. `genesis_hash` is the retained `GENESIS`'s hash, else the current
/// first-retained anchor's; T16 replaces it with the backup manifest's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreCompletion {
    pub restore_seq: u64,
    pub head: HeadAnchor,
    pub first_retained: FirstRetainedAnchor,
}

/// Anchor updates `open()` performs after the step-3 `VERIFY` is committed (§8.7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnchorActions {
    /// The head anchor does not name the DB head: it is rewritten once anchors are enabled.
    pub advance_head: bool,
    /// Interrupted prune: the first-retained anchor to write (from the latest `prune_log` row).
    pub set_first_retained: Option<FirstRetainedAnchor>,
    /// The `PRUNE` record `set_first_retained` belongs to; the head anchor stays capped at it
    /// until the first-retained update succeeded (§8.5).
    pub prune_record: Option<HeadAnchor>,
    /// Interrupted restore: the reset to complete (T16).
    pub complete_restore: Option<RestoreCompletion>,
    /// An interrupted prune that would be reconciled, but the anchor dir could not be read: the
    /// head anchor stays capped at this `PRUNE` for the whole process (no first-retained
    /// write), so the next start, with the dir readable, can still reconcile it.
    pub defer_prune: Option<HeadAnchor>,
    /// The same for an interrupted restore: the `RESTORE` seq; no head anchor is written.
    pub defer_restore: Option<u64>,
}

/// The startup verdict (§8.7 step 3), held in memory until step 4 appends its `VERIFY`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartupVerdict {
    pub findings: Vec<VerifyFinding>,
    pub unanchored_tail: u64,
    pub anchor_actions: AnchorActions,
}

impl StartupVerdict {
    /// For tests: `open()` passes every finding on to the `VERIFY` row.
    #[cfg(any(test, feature = "testing"))]
    pub fn has_incident(&self) -> bool {
        self.findings.iter().any(|f| f.kind.is_incident())
    }
}

/// What startup verification is given (§8.7 step 3).
pub(crate) struct StartupInputs<'a> {
    pub(crate) conn: &'a Connection,
    pub(crate) kek: &'a Kek,
    pub(crate) head_anchor: Option<HeadAnchor>,
    pub(crate) first_retained: Option<FirstRetainedAnchor>,
    pub(crate) store_install_id: Option<String>,
    pub(crate) pinned_install_id: Option<String>,
    /// The anchor dir as read (`None`: none configured).
    pub(crate) anchor_lines: Option<AnchorDirLines>,
}

// ---------------------------------------------------------------------------------------
// Findings collector

#[derive(Default)]
struct Findings {
    list: Vec<VerifyFinding>,
    /// Per kind in order of first appearance.
    counts: Vec<KindCount>,
}

struct KindCount {
    kind: FindingKind,
    n: usize,
    /// Lowest and highest seq named by an omitted finding.
    first_omitted: Option<u64>,
    last_omitted: Option<u64>,
}

impl Findings {
    fn push(&mut self, f: VerifyFinding) {
        let idx = match self.counts.iter().position(|c| c.kind == f.kind) {
            Some(i) => i,
            None => {
                self.counts.push(KindCount {
                    kind: f.kind,
                    n: 0,
                    first_omitted: None,
                    last_omitted: None,
                });
                self.counts.len() - 1
            }
        };
        let c = &mut self.counts[idx];
        c.n += 1;
        if c.n <= MAX_FINDINGS_PER_KIND {
            self.list.push(f);
        } else if let Some(seq) = f.observed_seq.or(f.expected_seq) {
            c.first_omitted = Some(c.first_omitted.map_or(seq, |s| s.min(seq)));
            c.last_omitted = Some(c.last_omitted.map_or(seq, |s| s.max(seq)));
        }
    }

    fn any_of(&self, kinds: &[FindingKind]) -> bool {
        self.counts.iter().any(|c| kinds.contains(&c.kind))
    }

    /// The listed findings, then one summary per capped kind naming how many were omitted
    /// and the lowest (`expected_seq`) and highest (`observed_seq`) seq among them.
    fn finish(mut self) -> Vec<VerifyFinding> {
        for c in &self.counts {
            if c.n > MAX_FINDINGS_PER_KIND {
                let mut s = VerifyFinding::new(
                    c.kind,
                    format!(
                        "{} further findings of this kind omitted",
                        c.n - MAX_FINDINGS_PER_KIND
                    ),
                );
                s.expected_seq = c.first_omitted;
                s.observed_seq = c.last_omitted;
                self.list.push(s);
            }
        }
        self.list
    }
}

// ---------------------------------------------------------------------------------------
// Row access

fn sql_seq(seq: u64) -> i64 {
    i64::try_from(seq).unwrap_or(i64::MAX)
}

fn u64_of(v: ValueRef<'_>) -> Option<u64> {
    match v {
        ValueRef::Integer(i) => u64::try_from(i).ok(),
        _ => None,
    }
}

fn blob32(v: ValueRef<'_>) -> Option<[u8; 32]> {
    match v {
        ValueRef::Blob(b) => <[u8; 32]>::try_from(b).ok(),
        _ => None,
    }
}

fn text_of(v: ValueRef<'_>) -> Option<String> {
    match v {
        ValueRef::Text(t) => std::str::from_utf8(t).ok().map(str::to_owned),
        _ => None,
    }
}

/// Lowercase hex of exactly 32 bytes.
pub(crate) fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.bytes().any(|c| c.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

fn select_rows(filter: &str) -> String {
    format!(
        "SELECT {}, record_hash FROM events {filter}",
        FIELD_LIST.join(", ")
    )
}

/// A row selected with `select_rows`: its fields and its stored `record_hash`.
fn parse_row<'r>(row: &'r rusqlite::Row<'_>) -> Result<(RowFields<'r>, [u8; 32]), AuditError> {
    let f = RowFields::from_row(row)?;
    let stored = row
        .get_ref(FIELD_LIST.len())
        .ok()
        .and_then(blob32)
        .ok_or(AuditError::Invalid("events record_hash is not 32 bytes"))?;
    Ok((f, stored))
}

/// The plaintext head of one row; a malformed column reads as `None`.
struct RowHead {
    seq: u64,
    record_hash: Option<[u8; 32]>,
    prev_hash: Option<[u8; 32]>,
    chain_id: Option<String>,
    event_type: Option<String>,
}

fn row_head(conn: &Connection, seq: u64) -> rusqlite::Result<Option<RowHead>> {
    conn.query_row(
        "SELECT record_hash, prev_hash, chain_id, event_type FROM events WHERE seq = ?1",
        [sql_seq(seq)],
        |r| {
            Ok(RowHead {
                seq,
                record_hash: blob32(r.get_ref(0)?),
                prev_hash: blob32(r.get_ref(1)?),
                chain_id: text_of(r.get_ref(2)?),
                event_type: text_of(r.get_ref(3)?),
            })
        },
    )
    .optional()
}

/// `(min(seq), max(seq))`.
fn bounds(conn: &Connection) -> rusqlite::Result<(Option<u64>, Option<u64>)> {
    conn.query_row("SELECT min(seq), max(seq) FROM events", [], |r| {
        Ok((u64_of(r.get_ref(0)?), u64_of(r.get_ref(1)?)))
    })
}

fn latest_of(conn: &Connection, types: &str) -> rusqlite::Result<Option<u64>> {
    conn.query_row(
        &format!("SELECT max(seq) FROM events WHERE event_type IN ({types})"),
        [],
        |r| Ok(u64_of(r.get_ref(0)?)),
    )
}

/// Runs `g` on row `seq` (parsed, or the parse error); `None` when there is no such row.
fn with_row<T>(
    conn: &Connection,
    seq: u64,
    g: impl FnOnce(Result<(RowFields<'_>, [u8; 32]), AuditError>) -> rusqlite::Result<T>,
) -> rusqlite::Result<Option<T>> {
    let mut stmt = conn.prepare_cached(&select_rows("WHERE seq = ?1"))?;
    let mut rows = stmt.query([sql_seq(seq)])?;
    match rows.next()? {
        None => Ok(None),
        Some(row) => g(parse_row(row)).map(Some),
    }
}

/// The store's `install_id` (§8.6): `target` of the latest `RESTORE`, else of `GENESIS`, else
/// of the newest retained `APP_START` that carries one. Plaintext only.
pub(crate) fn store_install_id(conn: &Connection) -> rusqlite::Result<Option<String>> {
    for sql in [
        "SELECT target FROM events WHERE event_type = 'RESTORE' ORDER BY seq DESC LIMIT 1",
        "SELECT target FROM events WHERE event_type = 'GENESIS' ORDER BY seq LIMIT 1",
        "SELECT target FROM events WHERE event_type = 'APP_START' AND target IS NOT NULL \
         ORDER BY seq DESC LIMIT 1",
    ] {
        let found: Option<Option<String>> = conn
            .query_row(sql, [], |r| Ok(text_of(r.get_ref(0)?)))
            .optional()?;
        if let Some(t) = found {
            return Ok(t);
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------------------
// Decryption

enum KeyState {
    Live(Dek),
    /// `wrapped_dek` NULL or `destroyed_at` set.
    Destroyed,
    /// No `keys` row.
    Missing,
    /// The wrapped key does not open under this KEK, `key_id` and month.
    Unwrap,
}

pub(crate) enum DecryptError {
    KeyMissing(u64),
    KeyDestroyed(u64),
    KeyUnwrap(u64),
    /// AES-GCM (wrong key, nonce, AAD or ciphertext) or zstd failed.
    Open,
    PayloadHash,
}

/// The DEKs of one verification run, unwrapped once per `key_id`.
pub(crate) struct Deks<'k> {
    kek: &'k Kek,
    keys: HashMap<u64, KeyState>,
}

impl<'k> Deks<'k> {
    pub(crate) fn new(kek: &'k Kek) -> Deks<'k> {
        Deks {
            kek,
            keys: HashMap::new(),
        }
    }

    fn load(&self, conn: &Connection, key_id: u64) -> rusqlite::Result<KeyState> {
        let Ok(id) = i64::try_from(key_id) else {
            return Ok(KeyState::Missing);
        };
        let row = conn
            .query_row(
                "SELECT month, wrapped_dek, destroyed_at FROM keys WHERE key_id = ?1",
                [id],
                |r| {
                    let month = match r.get_ref(0)? {
                        ValueRef::Null => Ok(None),
                        v => text_of(v).map(Some).ok_or(()),
                    };
                    let wrapped = match r.get_ref(1)? {
                        ValueRef::Null => None,
                        ValueRef::Blob(b) => Some(b.to_vec()),
                        _ => Some(Vec::new()),
                    };
                    let destroyed = !matches!(r.get_ref(2)?, ValueRef::Null);
                    Ok((month, wrapped, destroyed))
                },
            )
            .optional()?;
        Ok(match row {
            None => KeyState::Missing,
            Some((_, None, _)) | Some((_, _, true)) => KeyState::Destroyed,
            Some((Err(()), _, _)) => KeyState::Unwrap,
            Some((Ok(month), Some(wrapped), false)) => {
                match crypto::unwrap_dek(self.kek, key_id, month.as_deref(), &wrapped) {
                    Ok(d) => KeyState::Live(d),
                    Err(_) => KeyState::Unwrap,
                }
            }
        })
    }

    /// The JCS payload bytes of `f`, checked against `payload_sha256` (F.3).
    pub(crate) fn decrypt(
        &mut self,
        conn: &Connection,
        f: &RowFields<'_>,
    ) -> rusqlite::Result<Result<Zeroizing<Vec<u8>>, DecryptError>> {
        if !self.keys.contains_key(&f.key_id) {
            let st = self.load(conn, f.key_id)?;
            self.keys.insert(f.key_id, st);
        }
        let dek = match self.keys.get(&f.key_id) {
            Some(KeyState::Live(d)) => d,
            Some(KeyState::Destroyed) => return Ok(Err(DecryptError::KeyDestroyed(f.key_id))),
            Some(KeyState::Unwrap) => return Ok(Err(DecryptError::KeyUnwrap(f.key_id))),
            Some(KeyState::Missing) | None => {
                return Ok(Err(DecryptError::KeyMissing(f.key_id)));
            }
        };
        Ok(open_row(dek, f))
    }

    /// `decrypt`, then the payload as JSON (`Ok(None)`: decrypted but not JSON).
    pub(crate) fn decrypt_json(
        &mut self,
        conn: &Connection,
        f: &RowFields<'_>,
    ) -> rusqlite::Result<Result<Option<Value>, DecryptError>> {
        Ok(self
            .decrypt(conn, f)?
            .map(|plain| serde_json::from_slice::<Value>(&plain).ok()))
    }
}

fn open_row(dek: &Dek, f: &RowFields<'_>) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    let aad = encoding::aad(f).map_err(|_| DecryptError::Open)?;
    let compressed = Zeroizing::new(
        crypto::open(dek, f.nonce, &aad, f.payload_ct, f.seq).map_err(|_| DecryptError::Open)?,
    );
    let plain = Zeroizing::new(
        crypto::decompress(&compressed, f.payload_len).map_err(|_| DecryptError::Open)?,
    );
    let digest: [u8; 32] = Sha256::digest(plain.as_slice()).into();
    if !ct_eq(&digest, f.payload_sha256) {
        return Err(DecryptError::PayloadHash);
    }
    Ok(plain)
}

fn decrypt_finding(seq: u64, e: &DecryptError) -> VerifyFinding {
    let (kind, detail) = match e {
        DecryptError::KeyMissing(k) => (
            FindingKind::DecryptFailed,
            format!("data key {k} is missing"),
        ),
        DecryptError::KeyDestroyed(k) => (
            FindingKind::DestroyedKeyReferenced,
            format!("data key {k} is destroyed but still referenced"),
        ),
        DecryptError::KeyUnwrap(k) => (
            FindingKind::DecryptFailed,
            format!("data key {k} does not unwrap"),
        ),
        DecryptError::Open => (
            FindingKind::DecryptFailed,
            "payload does not decrypt".to_string(),
        ),
        DecryptError::PayloadHash => (
            FindingKind::PayloadHashMismatch,
            "payload does not match payload_sha256".to_string(),
        ),
    };
    VerifyFinding::new(kind, detail).observed(Some(seq), None)
}

// ---------------------------------------------------------------------------------------
// Chain walk

/// The row before the one being visited.
struct Prev {
    seq: u64,
    record_hash: [u8; 32],
    chain_id: String,
}

/// Walks `events` from `from` to the head: seq contiguity, `format_version`, flag bits,
/// `record_hash` recomputed (T02), `prev_hash` links, and `chain_id` changing only at a
/// `RESTORE` (§8.11). `visit` sees every readable row with its stored hash and predecessor.
fn walk(
    conn: &Connection,
    from: u64,
    out: &mut Findings,
    mut visit: impl FnMut(
        &mut Findings,
        &RowFields<'_>,
        &[u8; 32],
        Option<&Prev>,
    ) -> rusqlite::Result<()>,
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(&select_rows("WHERE seq >= ?1 ORDER BY seq"))?;
    let mut rows = stmt.query([sql_seq(from)])?;
    let mut expect = Some(from);
    let mut prev: Option<Prev> = None;
    let mut segment: Option<String> = None;
    while let Some(row) = rows.next()? {
        let raw_seq = row.get_ref(0).ok().and_then(u64_of);
        let (f, stored) = match parse_row(row) {
            Ok(p) => p,
            Err(e) => {
                out.push(
                    VerifyFinding::new(FindingKind::ChainBroken, format!("unreadable row: {e}"))
                        .observed(raw_seq, None),
                );
                prev = None;
                expect = raw_seq.and_then(|s| s.checked_add(1));
                continue;
            }
        };
        let seq = f.seq;
        // After a gap the link check would only repeat the same cause.
        let mut linked = true;
        if let Some(e) = expect
            && seq != e
        {
            out.push(
                VerifyFinding::new(FindingKind::SeqGap, "records are missing before this seq")
                    .expected(Some(e), None)
                    .observed(Some(seq), None),
            );
            linked = false;
        }
        if f.format_version != FORMAT_VERSION {
            // Recomputing with the v1 field list would only produce a misleading ChainBroken.
            out.push(
                VerifyFinding::new(
                    FindingKind::FormatVersionUnsupported,
                    format!("format_version {}", f.format_version),
                )
                .observed(Some(seq), Some(stored)),
            );
        } else {
            match f.record_hash() {
                Ok(h) if ct_eq(&h, &stored) => {}
                Ok(h) => out.push(
                    VerifyFinding::new(
                        FindingKind::ChainBroken,
                        "record_hash does not match the record",
                    )
                    .expected(Some(seq), Some(h))
                    .observed(Some(seq), Some(stored)),
                ),
                Err(e) => out.push(
                    VerifyFinding::new(FindingKind::ChainBroken, format!("unhashable row: {e}"))
                        .observed(Some(seq), Some(stored)),
                ),
            }
        }
        if f.flags & !KNOWN_FLAG_BITS != 0 {
            out.push(
                VerifyFinding::new(
                    FindingKind::UnknownFlagBits,
                    format!("flags {:#x}", f.flags),
                )
                .observed(Some(seq), Some(stored)),
            );
        }
        if linked
            && let Some(p) = &prev
            && !ct_eq(f.prev_hash, &p.record_hash)
        {
            out.push(
                VerifyFinding::new(
                    FindingKind::ChainBroken,
                    "prev_hash does not link to the record before it",
                )
                .expected(Some(p.seq), Some(p.record_hash))
                .observed(Some(seq), Some(*f.prev_hash)),
            );
        }
        if f.event_type == "RESTORE" {
            segment = Some(f.chain_id.to_owned());
        } else if segment.as_deref() != Some(f.chain_id) {
            if segment.is_some() {
                out.push(
                    VerifyFinding::new(
                        FindingKind::RestoreBoundaryMismatch,
                        "chain_id changes without a RESTORE",
                    )
                    .observed(Some(seq), Some(stored)),
                );
            }
            segment = Some(f.chain_id.to_owned());
        }
        visit(out, &f, &stored, prev.as_ref())?;
        prev = Some(Prev {
            seq,
            record_hash: stored,
            chain_id: f.chain_id.to_owned(),
        });
        expect = seq.checked_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// prune_log (§8.5, F.9)

pub(crate) struct PruneLogRow {
    pub(crate) prune_seq: u64,
    pub(crate) range_start: u64,
    pub(crate) cutoff_epoch: String,
    pub(crate) last_pruned: [u8; 32],
    pub(crate) first_retained_seq: u64,
    prev_row_hash: [u8; 32],
    row_hash: [u8; 32],
}

/// All rows by `prune_seq`; a row with a malformed column is a `PruneLogBroken` finding and
/// is left out (which also breaks the row chain after it).
fn load_prune_log(conn: &Connection, out: &mut Findings) -> rusqlite::Result<Vec<PruneLogRow>> {
    let mut stmt = conn.prepare(
        "SELECT prune_seq, range_start, cutoff_epoch, last_pruned_record_hash, \
         first_retained_seq, prev_row_hash, row_hash FROM prune_log ORDER BY prune_seq",
    )?;
    let mut rows = stmt.query([])?;
    let mut log = Vec::new();
    while let Some(r) = rows.next()? {
        let parsed = (|| {
            Some(PruneLogRow {
                prune_seq: u64_of(r.get_ref(0).ok()?)?,
                range_start: u64_of(r.get_ref(1).ok()?)?,
                cutoff_epoch: text_of(r.get_ref(2).ok()?)?,
                last_pruned: blob32(r.get_ref(3).ok()?)?,
                first_retained_seq: u64_of(r.get_ref(4).ok()?)?,
                prev_row_hash: blob32(r.get_ref(5).ok()?)?,
                row_hash: blob32(r.get_ref(6).ok()?)?,
            })
        })();
        match parsed {
            Some(p) => log.push(p),
            None => out.push(
                VerifyFinding::new(FindingKind::PruneLogBroken, "unreadable prune_log row")
                    .observed(r.get_ref(0).ok().and_then(u64_of), None),
            ),
        }
    }
    Ok(log)
}

/// Row-hash chain from `ZERO_HASH` (L51) and contiguity from seq 1 (§8.5).
fn check_prune_log(log: &[PruneLogRow], out: &mut Findings) {
    let mut prev_hash = ZERO_HASH;
    let mut prev_first = 1u64;
    let mut prev_last = ZERO_HASH;
    for r in log {
        let at = Some(r.prune_seq);
        if !ct_eq(&r.prev_row_hash, &prev_hash) {
            out.push(
                VerifyFinding::new(
                    FindingKind::PruneLogBroken,
                    "prev_row_hash does not link to the row before it",
                )
                .expected(at, Some(prev_hash))
                .observed(at, Some(r.prev_row_hash)),
            );
        }
        let h = encoding::prune_row_hash(
            &r.prev_row_hash,
            r.prune_seq,
            r.range_start,
            &r.cutoff_epoch,
            &r.last_pruned,
            r.first_retained_seq,
        );
        if !ct_eq(&h, &r.row_hash) {
            out.push(
                VerifyFinding::new(
                    FindingKind::PruneLogBroken,
                    "row_hash does not match the row",
                )
                .expected(at, Some(h))
                .observed(at, Some(r.row_hash)),
            );
        }
        if r.range_start != prev_first {
            out.push(
                VerifyFinding::new(
                    FindingKind::PruneLogNotContiguous,
                    "range does not start at the previous first_retained_seq",
                )
                .expected(Some(prev_first), None)
                .observed(Some(r.range_start), None),
            );
        }
        if r.first_retained_seq < r.range_start || r.first_retained_seq > r.prune_seq {
            out.push(
                VerifyFinding::new(
                    FindingKind::PruneLogNotContiguous,
                    "first_retained_seq lies outside the range or after its PRUNE",
                )
                .observed(Some(r.first_retained_seq), None),
            );
        }
        if r.first_retained_seq == r.range_start && !ct_eq(&r.last_pruned, &prev_last) {
            out.push(
                VerifyFinding::new(
                    FindingKind::PruneLogNotContiguous,
                    "an empty range must carry the previous last_pruned_record_hash",
                )
                .expected(at, Some(prev_last))
                .observed(at, Some(r.last_pruned)),
            );
        }
        prev_hash = r.row_hash;
        prev_first = r.first_retained_seq;
        prev_last = r.last_pruned;
    }
}

/// `(first_retained_seq, last_pruned_record_hash)` of the latest row, else of `GENESIS`.
fn latest_values(log: &[PruneLogRow]) -> (u64, [u8; 32]) {
    log.last()
        .map_or((1, ZERO_HASH), |r| (r.first_retained_seq, r.last_pruned))
}

/// The values of the row before the latest one (`GENESIS` values with a single row).
fn second_latest_values(log: &[PruneLogRow]) -> (u64, [u8; 32]) {
    match log.len() {
        0 | 1 => (1, ZERO_HASH),
        n => (log[n - 2].first_retained_seq, log[n - 2].last_pruned),
    }
}

/// First retained record against the latest row (§8.7 step 3).
fn check_first_retained(
    conn: &Connection,
    first: Option<u64>,
    log: &[PruneLogRow],
    out: &mut Findings,
) -> rusqlite::Result<()> {
    let (frs, last) = latest_values(log);
    let Some(first) = first else {
        out.push(
            VerifyFinding::new(
                FindingKind::FirstRetainedMismatch,
                "the store has no records",
            )
            .expected(Some(frs), Some(last)),
        );
        return Ok(());
    };
    if first != frs {
        out.push(
            VerifyFinding::new(
                FindingKind::FirstRetainedMismatch,
                "the first retained record is not the prune log's first_retained_seq",
            )
            .expected(Some(frs), None)
            .observed(Some(first), None),
        );
    }
    let r = row_head(conn, first)?;
    let prev = r.as_ref().and_then(|r| r.prev_hash);
    if !prev.is_some_and(|p| ct_eq(&p, &last)) {
        out.push(
            VerifyFinding::new(
                FindingKind::FirstRetainedMismatch,
                "the first retained record's prev_hash is not the last pruned record_hash",
            )
            .expected(Some(frs), Some(last))
            .observed(Some(first), prev),
        );
    }
    if first == 1 && r.and_then(|r| r.event_type).as_deref() != Some("GENESIS") {
        out.push(
            VerifyFinding::new(
                FindingKind::FirstRetainedMismatch,
                "record 1 is not GENESIS",
            )
            .observed(Some(1), None),
        );
    }
    Ok(())
}

/// A `PRUNE` payload against its `prune_log` row (F.11, L51). `false` on any mismatch.
fn check_prune_payload(
    out: &mut Findings,
    seq: u64,
    payload: Option<&Value>,
    row: Option<&PruneLogRow>,
) -> bool {
    let Some(row) = row else {
        out.push(
            VerifyFinding::new(
                FindingKind::PruneLogRowMismatch,
                "PRUNE record has no prune_log row",
            )
            .observed(Some(seq), None),
        );
        return false;
    };
    let claimed = payload
        .and_then(|p| p.get("prune_log_row_hash"))
        .and_then(Value::as_str)
        .and_then(hex32);
    let mut ok = true;
    if !claimed.is_some_and(|h| ct_eq(&h, &row.row_hash)) {
        out.push(
            VerifyFinding::new(
                FindingKind::PruneLogRowMismatch,
                "PRUNE payload's prune_log_row_hash is not its row's row_hash",
            )
            .expected(Some(seq), Some(row.row_hash))
            .observed(Some(seq), claimed),
        );
        ok = false;
    }
    let range = payload.and_then(|p| p.get("range"));
    let cutoff = payload
        .and_then(|p| p.get("cutoff"))
        .and_then(Value::as_str);
    if range != Some(&json!([row.range_start, row.first_retained_seq]))
        || cutoff != Some(row.cutoff_epoch.as_str())
    {
        out.push(
            VerifyFinding::new(
                FindingKind::PruneLogRowMismatch,
                "PRUNE payload's range or cutoff differs from its prune_log row",
            )
            .observed(Some(seq), None),
        );
        ok = false;
    }
    ok
}

/// The latest row's `PRUNE` record exists, is the newest `PRUNE`, decrypts and carries the
/// row's hash (§8.7 step 4). `true` when all hold (or there is no prune).
fn check_latest_prune(
    conn: &Connection,
    deks: &mut Deks<'_>,
    log: &[PruneLogRow],
    out: &mut Findings,
) -> rusqlite::Result<bool> {
    let newest_prune = latest_of(conn, "'PRUNE'")?;
    let Some(latest) = log.last() else {
        if let Some(seq) = newest_prune {
            out.push(
                VerifyFinding::new(
                    FindingKind::PruneLogRowMismatch,
                    "PRUNE record without any prune_log row",
                )
                .observed(Some(seq), None),
            );
            return Ok(false);
        }
        return Ok(true);
    };
    if newest_prune != Some(latest.prune_seq) {
        out.push(
            VerifyFinding::new(
                FindingKind::PruneLogRowMismatch,
                "the newest PRUNE record is not the latest prune_log row's",
            )
            .expected(Some(latest.prune_seq), Some(latest.row_hash))
            .observed(newest_prune, None),
        );
        return Ok(false);
    }
    let checked = with_row(conn, latest.prune_seq, |parsed| {
        let Ok((f, _)) = parsed else {
            return Ok(false);
        };
        match deks.decrypt_json(conn, &f)? {
            Ok(payload) => Ok(check_prune_payload(
                out,
                latest.prune_seq,
                payload.as_ref(),
                Some(latest),
            )),
            Err(e) => {
                out.push(decrypt_finding(latest.prune_seq, &e));
                Ok(false)
            }
        }
    })?;
    Ok(checked.unwrap_or(false))
}

// ---------------------------------------------------------------------------------------
// RESTORE boundary (§8.11)

/// What is wrong with `RESTORE` row `f` as a segment boundary; empty when it matches.
fn restore_problems(
    f: &RowFields<'_>,
    payload: Option<&Value>,
    prev: Option<&Prev>,
) -> Vec<&'static str> {
    let mut bad = Vec::new();
    let Some(p) = payload else {
        return vec!["RESTORE payload is not readable"];
    };
    let field = |k: &str| p.get(k);
    if field("source_head_seq").and_then(Value::as_u64) != f.seq.checked_sub(1) {
        bad.push("source_head_seq is not the record before RESTORE");
    }
    let src_hash = field("source_head_hash")
        .and_then(Value::as_str)
        .and_then(hex32);
    if !src_hash.is_some_and(|h| ct_eq(&h, f.prev_hash)) {
        bad.push("source_head_hash is not RESTORE's prev_hash");
    }
    if field("new_chain_id").and_then(Value::as_str) != Some(f.chain_id) {
        bad.push("RESTORE's chain_id is not its new_chain_id");
    }
    if let Some(prev) = prev
        && Some(prev.seq) == f.seq.checked_sub(1)
        && field("source_chain_id").and_then(Value::as_str) != Some(prev.chain_id.as_str())
    {
        bad.push("the record before RESTORE is not of its source_chain_id");
    }
    bad
}

fn prior_anchor(payload: &Value) -> Result<Option<HeadAnchor>, ()> {
    match payload.get("prior_keychain_anchor") {
        None => Err(()),
        Some(Value::Null) => Ok(None),
        Some(a) => Ok(Some(HeadAnchor {
            chain_id: a
                .get("chain_id")
                .and_then(Value::as_str)
                .ok_or(())?
                .to_owned(),
            seq: a.get("seq").and_then(Value::as_u64).ok_or(())?,
            record_hash: a
                .get("record_hash")
                .and_then(Value::as_str)
                .and_then(hex32)
                .ok_or(())?,
        })),
    }
}

fn same_anchor(a: &HeadAnchor, b: &HeadAnchor) -> bool {
    a.chain_id == b.chain_id && a.seq == b.seq && ct_eq(&a.record_hash, &b.record_hash)
}

// ---------------------------------------------------------------------------------------
// Anchor rule (§8.7)

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Startup: informational findings and anchor actions.
    Startup,
    /// Full verification at runtime: an anchor lagging the head or a pending first-retained
    /// update is normal operation, not a finding.
    Full,
}

struct AnchorCheck<'a> {
    mode: Mode,
    head_anchor: Option<&'a HeadAnchor>,
    first_retained: Option<&'a FirstRetainedAnchor>,
    /// The entry exists but has a newer layout byte (only at runtime: the startup gate
    /// refuses it). It is an `AnchorMismatch`, never "absent".
    head_newer: Option<u8>,
    first_retained_newer: Option<u8>,
    /// The latest `PRUNE` exists, decrypts and carries its row's hash (§8.7 (c)).
    latest_prune_ok: bool,
    head: Option<&'a RowHead>,
    first: Option<u64>,
    log: &'a [PruneLogRow],
    /// No chain, prune-log, first-retained or decrypt finding so far, and no anchor-dir line
    /// that contradicts the store.
    clean: bool,
    /// The anchor dir (or a file or line of it) could not be read: a reconciliation is
    /// deferred to a start that can read it rather than refused.
    anchor_dir_unread: bool,
}

struct AnchorResult {
    actions: AnchorActions,
    unanchored_tail: u64,
}

/// The interrupted-restore rule (§8.7): the latest `RESTORE` verifies as the latest segment
/// boundary (a valid boundary with no `PRUNE` after it; records of any other type may follow,
/// e.g. the `APP_START` of a session whose completion failed or was deferred), the chain is
/// clean, and the head anchor still names the `prior_keychain_anchor` (or is absent while that
/// is null).
fn interrupted_restore(
    conn: &Connection,
    deks: &mut Deks<'_>,
    c: &AnchorCheck<'_>,
) -> rusqlite::Result<Option<RestoreCompletion>> {
    let Some(r) = latest_of(conn, "'RESTORE'")? else {
        return Ok(None);
    };
    let Some(head) = c.head else {
        return Ok(None);
    };
    // A `PRUNE` after it would be a later boundary: the restore barrier keeps prune from
    // running before the completion, so one there was not written by an unfinished restore.
    if !c.clean || c.head_newer.is_some() || latest_of(conn, "'PRUNE'")? > Some(r) {
        return Ok(None);
    }
    let before = match r.checked_sub(1) {
        Some(s) if c.first.is_some_and(|f| s >= f) => row_head(conn, s)?,
        _ => None,
    };
    let prev = before.and_then(|b| {
        Some(Prev {
            seq: b.seq,
            record_hash: b.record_hash?,
            chain_id: b.chain_id?,
        })
    });
    let matched = with_row(conn, r, |parsed| {
        let Ok((f, _)) = parsed else {
            return Ok(None);
        };
        let Ok(Some(payload)) = deks.decrypt_json(conn, &f)? else {
            return Ok(None);
        };
        if !restore_problems(&f, Some(&payload), prev.as_ref()).is_empty() {
            return Ok(None);
        }
        let Ok(prior) = prior_anchor(&payload) else {
            return Ok(None);
        };
        let anchor_matches = match (c.head_anchor, &prior) {
            (None, None) => true,
            (Some(a), Some(p)) => same_anchor(a, p),
            _ => false,
        };
        Ok(anchor_matches.then(|| f.chain_id.to_owned()))
    })?
    .flatten();
    let Some(new_chain) = matched else {
        return Ok(None);
    };
    if head.chain_id.as_deref() != Some(new_chain.as_str()) {
        return Ok(None);
    }
    let (Some(head_hash), (frs, last)) = (head.record_hash, latest_values(c.log)) else {
        return Ok(None);
    };
    // The retained `GENESIS`, else the value of a first-retained anchor the interrupted reset
    // already wrote for the restored chain, else zero (informational once `GENESIS` is
    // pruned). Never the replaced chain's value the keychain may still hold.
    let genesis_hash = match c.first {
        Some(1) => row_head(conn, 1)?.and_then(|g| g.record_hash),
        _ => None,
    }
    .or(c
        .first_retained
        .filter(|f| f.chain_id == new_chain)
        .map(|f| f.genesis_hash))
    .unwrap_or(ZERO_HASH);
    Ok(Some(RestoreCompletion {
        restore_seq: r,
        head: HeadAnchor {
            chain_id: new_chain.clone(),
            seq: head.seq,
            record_hash: head_hash,
        },
        first_retained: FirstRetainedAnchor {
            chain_id: new_chain,
            genesis_hash,
            first_retained_seq: frs,
            first_retained_prev_hash: last,
        },
    }))
}

fn check_anchors(
    conn: &Connection,
    deks: &mut Deks<'_>,
    c: &AnchorCheck<'_>,
    out: &mut Findings,
) -> rusqlite::Result<AnchorResult> {
    let mut res = AnchorResult {
        actions: AnchorActions::default(),
        unanchored_tail: 0,
    };
    let head_anchor_hash = c.head.and_then(|h| h.record_hash);
    res.actions.advance_head = match (c.head, c.head_anchor, head_anchor_hash) {
        (Some(h), Some(a), Some(hh)) => {
            !(Some(a.chain_id.as_str()) == h.chain_id.as_deref()
                && a.seq == h.seq
                && ct_eq(&a.record_hash, &hh))
        }
        (Some(_), _, _) => true,
        (None, _, _) => false,
    };
    if let Some(rc) = interrupted_restore(conn, deks, c)? {
        if c.mode == Mode::Startup && c.anchor_dir_unread {
            res.actions.defer_restore = Some(rc.restore_seq);
        } else if c.mode == Mode::Startup {
            out.push(
                VerifyFinding::new(
                    FindingKind::InterruptedRestoreReconciled,
                    "the anchor reset after RESTORE did not happen",
                )
                .observed(Some(rc.restore_seq), None),
            );
            res.actions.complete_restore = Some(rc);
        }
        return Ok(res);
    }

    // Head anchor.
    let mut anchor_ok_seq: Option<u64> = None;
    match (c.head_anchor, c.head) {
        (None, _) => out.push(match c.head_newer {
            Some(n) => VerifyFinding::new(
                FindingKind::AnchorMismatch,
                format!("the head anchor has the newer layout {n}"),
            ),
            None => VerifyFinding::new(FindingKind::AnchorMissing, "the head anchor is missing"),
        }),
        (Some(a), None) => out.push(
            VerifyFinding::new(FindingKind::AnchorAhead, "the store has no records")
                .expected(Some(a.seq), Some(a.record_hash)),
        ),
        (Some(a), Some(h)) => {
            let observed = (Some(h.seq), h.record_hash);
            if h.chain_id.as_deref() != Some(a.chain_id.as_str()) {
                out.push(
                    VerifyFinding::new(
                        FindingKind::AnchorMismatch,
                        "the head anchor names another chain",
                    )
                    .expected(Some(a.seq), Some(a.record_hash))
                    .observed(observed.0, observed.1),
                );
            } else if a.seq > h.seq {
                out.push(
                    VerifyFinding::new(
                        FindingKind::AnchorAhead,
                        "the head anchor is ahead of the store",
                    )
                    .expected(Some(a.seq), Some(a.record_hash))
                    .observed(observed.0, observed.1),
                );
            } else {
                let at = row_head(conn, a.seq)?.and_then(|r| r.record_hash);
                match at {
                    Some(hash) if ct_eq(&hash, &a.record_hash) => {
                        anchor_ok_seq = Some(a.seq);
                        if a.seq < h.seq {
                            res.unanchored_tail = h.seq - a.seq;
                            if c.mode == Mode::Startup {
                                out.push(
                                    VerifyFinding::new(
                                        FindingKind::UnanchoredTail,
                                        format!("{} unanchored tail records", h.seq - a.seq),
                                    )
                                    .expected(Some(a.seq), Some(a.record_hash))
                                    .observed(observed.0, observed.1),
                                );
                            }
                        }
                    }
                    other => out.push(
                        VerifyFinding::new(
                            FindingKind::AnchorMismatch,
                            if other.is_some() {
                                "the anchored record has another record_hash"
                            } else {
                                "the anchored record is missing"
                            },
                        )
                        .expected(Some(a.seq), Some(a.record_hash))
                        .observed(Some(a.seq), other),
                    ),
                }
            }
        }
    }

    // First-retained anchor.
    let Some(fr) = c.first_retained else {
        out.push(match c.first_retained_newer {
            Some(n) => VerifyFinding::new(
                FindingKind::AnchorMismatch,
                format!("the first-retained anchor has the newer layout {n}"),
            ),
            None => VerifyFinding::new(
                FindingKind::AnchorMissing,
                "the first-retained anchor is missing",
            ),
        });
        return Ok(res);
    };
    let head_chain = c.head.and_then(|h| h.chain_id.as_deref());
    let genesis_ok = match c.first {
        Some(1) => row_head(conn, 1)?
            .and_then(|g| g.record_hash)
            .is_some_and(|g| ct_eq(&g, &fr.genesis_hash)),
        _ => true,
    };
    let chain_ok = head_chain == Some(fr.chain_id.as_str());
    let (frs, last) = latest_values(c.log);
    if !genesis_ok || !chain_ok {
        out.push(
            VerifyFinding::new(
                FindingKind::FirstRetainedMismatch,
                if genesis_ok {
                    "the first-retained anchor names another chain"
                } else {
                    "the first-retained anchor's genesis_hash is not GENESIS's record_hash"
                },
            )
            .observed(Some(fr.first_retained_seq), Some(fr.genesis_hash)),
        );
        return Ok(res);
    }
    if fr.first_retained_seq == frs && ct_eq(&fr.first_retained_prev_hash, &last) {
        return Ok(res);
    }
    // Interrupted prune (§8.7 (a)–(d)).
    let (pf, pl) = second_latest_values(c.log);
    let reconciles = c.log.last().filter(|latest| {
        fr.first_retained_seq == pf                                     // (a)
            && ct_eq(&fr.first_retained_prev_hash, &pl)
            && latest.range_start == fr.first_retained_seq              // (b)
            && c.clean && c.latest_prune_ok                             // (c)
            && anchor_ok_seq.is_some_and(|a| latest.prune_seq >= a) // (d)
    });
    let prune_hash = match reconciles {
        Some(latest) => row_head(conn, latest.prune_seq)?.and_then(|r| r.record_hash),
        None => None,
    };
    match (reconciles, prune_hash, head_chain) {
        (Some(latest), Some(prune_hash), Some(chain)) => {
            if c.mode == Mode::Startup && c.anchor_dir_unread {
                res.actions.defer_prune = Some(HeadAnchor {
                    chain_id: chain.to_owned(),
                    seq: latest.prune_seq,
                    record_hash: prune_hash,
                });
            } else if c.mode == Mode::Startup {
                out.push(
                    VerifyFinding::new(
                        FindingKind::InterruptedPruneReconciled,
                        "the first-retained update after PRUNE did not happen",
                    )
                    .expected(Some(frs), Some(last))
                    .observed(
                        Some(fr.first_retained_seq),
                        Some(fr.first_retained_prev_hash),
                    ),
                );
                res.actions.set_first_retained = Some(FirstRetainedAnchor {
                    chain_id: fr.chain_id.clone(),
                    genesis_hash: fr.genesis_hash,
                    first_retained_seq: frs,
                    first_retained_prev_hash: last,
                });
                res.actions.prune_record = Some(HeadAnchor {
                    chain_id: chain.to_owned(),
                    seq: latest.prune_seq,
                    record_hash: prune_hash,
                });
            }
        }
        _ => out.push(
            VerifyFinding::new(
                FindingKind::FirstRetainedMismatch,
                "the first-retained anchor does not match the latest prune_log row",
            )
            .expected(Some(frs), Some(last))
            .observed(
                Some(fr.first_retained_seq),
                Some(fr.first_retained_prev_hash),
            ),
        ),
    }
    Ok(res)
}

/// What the anchor-dir checks found: a line contradicting the store (it blocks the
/// interrupted-prune/restore reconciliation like a chain finding), and whether something
/// could not be read (the reconciliation is deferred instead).
#[derive(Default)]
struct AnchorDirState {
    contradicted: bool,
    unread: bool,
}

/// The spans of superseded chains that the retained `RESTORE`s account for (see
/// [`LostSpan`]). A `RESTORE` that does not decrypt or parse accounts for nothing (fail
/// closed: its file's lines are then compared as usual).
fn lost_spans(conn: &Connection, deks: &mut Deks<'_>) -> rusqlite::Result<Vec<LostSpan>> {
    let seqs: Vec<u64> = {
        let mut st = conn.prepare("SELECT seq FROM events WHERE event_type = 'RESTORE'")?;
        let rows = st.query_map([], |r| Ok(u64_of(r.get_ref(0)?)))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect()
    };
    let mut out = Vec::new();
    for seq in seqs {
        let span = with_row(conn, seq, |parsed| {
            let Ok((f, _)) = parsed else {
                return Ok(None);
            };
            let Ok(Some(p)) = deks.decrypt_json(conn, &f)? else {
                return Ok(None);
            };
            let (Some(chain), Some(head), Some(lost), Ok(prior)) = (
                p.get("source_chain_id").and_then(Value::as_str),
                p.get("source_head_seq").and_then(Value::as_u64),
                p.get("records_lost").and_then(Value::as_u64),
                prior_anchor(&p),
            ) else {
                return Ok(None);
            };
            Ok(LostSpan::of(
                chain,
                head,
                prior.as_ref().map(|a| (a.chain_id.as_str(), a.seq)),
                lost,
            ))
        })?;
        out.extend(span.flatten());
    }
    Ok(out)
}

/// The anchor-dir checks (§8.7) against the latest `prune_log` row, through the per-kind cap.
fn check_anchor_dir(
    conn: &Connection,
    lines: Option<&AnchorDirLines>,
    log: &[PruneLogRow],
    head: Option<u64>,
    lost: &[LostSpan],
    out: &mut Findings,
) -> rusqlite::Result<AnchorDirState> {
    let Some(lines) = lines else {
        return Ok(AnchorDirState::default());
    };
    for p in &lines.problems {
        out.push(p.clone());
    }
    let ctx = VerifyCtx {
        conn,
        first_retained_seq: latest_values(log).0,
        head,
        prune_log: log,
        lost,
    };
    let found = anchor_dir::check(lines, &ctx)?;
    let state = AnchorDirState {
        contradicted: !found.is_empty(),
        unread: !lines.problems.is_empty(),
    };
    for f in found {
        out.push(f);
    }
    Ok(state)
}

// ---------------------------------------------------------------------------------------
// Startup (§8.7 step 3)

/// Startup verification. Every step appends findings; only an I/O error returns early.
pub(crate) fn startup(inp: &StartupInputs<'_>) -> Result<StartupVerdict, OpenError> {
    run_startup(inp).map_err(|e| OpenError::Sqlite(e.to_string()))
}

fn run_startup(inp: &StartupInputs<'_>) -> rusqlite::Result<StartupVerdict> {
    // One read transaction: every step sees the same snapshot.
    let tx = inp.conn.unchecked_transaction()?;
    let conn: &Connection = &tx;
    let mut out = Findings::default();
    let mut deks = Deks::new(inp.kek);

    // 1.–3. Bounds, prune_log, first retained record.
    let (first, head) = bounds(conn)?;
    let log = load_prune_log(conn, &mut out)?;
    check_prune_log(&log, &mut out);
    check_first_retained(conn, first, &log, &mut out)?;
    // 4. The latest PRUNE carries the latest row's hash.
    let latest_prune_ok = check_latest_prune(conn, &mut deks, &log, &mut out)?;
    // 5. Chain from the scope start (and the anchored record and latest PRUNE, if earlier).
    // While the head anchor is absent or names another chain than the head record (only an
    // unfinished restore leaves it so, unless something is wrong), the latest RESTORE is
    // walked through too: the interrupted-restore rule needs it verified even when later
    // records (an APP_START of a session whose completion failed) moved the scope start on.
    let scope_start = latest_of(conn, "'PRUNE', 'RESTORE', 'APP_START'")?.or(first);
    let head_chain = match head {
        Some(h) => row_head(conn, h)?.and_then(|r| r.chain_id),
        None => None,
    };
    let unfinished_restore = match &inp.head_anchor {
        Some(a) if head_chain.as_deref() == Some(a.chain_id.as_str()) => None,
        _ => latest_of(conn, "'RESTORE'")?,
    };
    if let (Some(first), Some(head)) = (first, head) {
        let in_store = |s: &u64| *s >= first && *s <= head;
        let lo = [
            scope_start,
            inp.head_anchor.as_ref().map(|a| a.seq),
            log.last().map(|r| r.prune_seq),
            unfinished_restore,
        ]
        .into_iter()
        .flatten()
        .filter(in_store)
        .min()
        .unwrap_or(head);
        // One record earlier, so the scope start's own link is checked too.
        let from = lo.saturating_sub(1).max(first);
        walk(conn, from, &mut out, |_, _, _, _| Ok(()))?;
    }
    // 6. Decrypt the head record.
    if let Some(h) = head {
        with_row(conn, h, |parsed| {
            if let Ok((f, _)) = parsed
                && let Err(e) = deks.decrypt(conn, &f)?
            {
                out.push(decrypt_finding(h, &e));
            }
            Ok(())
        })?;
    }
    // 7. install_id cross-check (§8.6); only when the store's id is determinable.
    if let (Some(store_id), Some(pinned)) = (&inp.store_install_id, &inp.pinned_install_id)
        && store_id != pinned
    {
        out.push(VerifyFinding::new(
            FindingKind::InstallIdMismatch,
            format!("the store's install_id {store_id} is not the pinned install_id {pinned}"),
        ));
    }
    // The anchor dir, when configured: a contradicting line blocks the reconciliations below,
    // a dir that cannot be read defers them (the head anchor stays capped).
    let lost = match &inp.anchor_lines {
        Some(_) => lost_spans(conn, &mut deks)?,
        None => Vec::new(),
    };
    let dir = check_anchor_dir(conn, inp.anchor_lines.as_ref(), &log, head, &lost, &mut out)?;
    // 8.–9. Anchor rule, interrupted prune and restore.
    let head_row = match head {
        Some(h) => row_head(conn, h)?,
        None => None,
    };
    let clean = !out.any_of(&CHAIN_KINDS) && !dir.contradicted;
    let anchors = check_anchors(
        conn,
        &mut deks,
        &AnchorCheck {
            mode: Mode::Startup,
            head_anchor: inp.head_anchor.as_ref(),
            first_retained: inp.first_retained.as_ref(),
            head_newer: None,
            first_retained_newer: None,
            latest_prune_ok,
            head: head_row.as_ref(),
            first,
            log: &log,
            clean,
            anchor_dir_unread: dir.unread,
        },
        &mut out,
    )?;
    drop(tx);
    Ok(StartupVerdict {
        findings: out.finish(),
        unanchored_tail: anchors.unanchored_tail,
        anchor_actions: anchors.actions,
    })
}

// ---------------------------------------------------------------------------------------
// Full verification (§8.7 "Full verification")

/// The keychain anchors as read when full verification started (head first). An entry that
/// is absent is `None`; one with a newer layout byte is `None` with its `*_newer` set. A
/// keychain that did not answer never gets here: the run does not complete.
pub(crate) struct KeychainAnchors {
    pub(crate) head: Option<HeadAnchor>,
    pub(crate) first_retained: Option<FirstRetainedAnchor>,
    pub(crate) head_newer: Option<u8>,
    pub(crate) first_retained_newer: Option<u8>,
}

/// A `PRUNE` judged by the retention and legal hold of its own settings snapshot (L52).
fn judge_prune(out: &mut Findings, seq: u64, epoch: NaiveDate, payload: &Value) {
    let settings = payload.get("settings");
    let retention = settings
        .and_then(|s| s.get("retention_days"))
        .and_then(Value::as_u64);
    let hold = settings
        .and_then(|s| s.get("legal_hold"))
        .and_then(Value::as_bool);
    let cutoff = payload
        .get("cutoff")
        .and_then(Value::as_str)
        .and_then(parse_epoch);
    let (Some(retention), Some(hold), Some(cutoff)) = (retention, hold, cutoff) else {
        out.push(
            VerifyFinding::new(
                FindingKind::PruneInsideRetention,
                "PRUNE settings snapshot or cutoff is unreadable",
            )
            .observed(Some(seq), None),
        );
        return;
    };
    let finding = |detail: String| {
        VerifyFinding::new(FindingKind::PruneInsideRetention, detail).observed(Some(seq), None)
    };
    if hold {
        out.push(finding("pruned while legal hold was on".into()));
    }
    if retention < MIN_RETENTION_DAYS {
        out.push(finding(format!(
            "retention of {retention} days is below the {MIN_RETENTION_DAYS}-day minimum"
        )));
    }
    let limit = epoch.checked_sub_days(Days::new(retention));
    if limit.is_none_or(|l| cutoff > l) {
        out.push(finding(format!(
            "cutoff {cutoff} lies inside the {retention}-day retention of PRUNE epoch {epoch}"
        )));
    }
}

/// Full verification on a read-only connection: one read transaction, so a concurrent
/// writer is not seen half-way. The caller read the keychain anchors (head first, then
/// first-retained) before calling, so they never name a record newer than this snapshot.
/// The anchor-dir lines were likewise read before the snapshot, so none names a record the
/// snapshot lacks (M10 writes a line only after its record committed).
pub(crate) fn full(
    conn: &Connection,
    kek: &Kek,
    anchors: &KeychainAnchors,
    anchor_lines: Option<&AnchorDirLines>,
) -> Result<Vec<VerifyFinding>, AuditError> {
    run_full(conn, kek, anchors, anchor_lines).map_err(|e| AuditError::Io(e.to_string()))
}

fn run_full(
    conn: &Connection,
    kek: &Kek,
    k: &KeychainAnchors,
    anchor_lines: Option<&AnchorDirLines>,
) -> rusqlite::Result<Vec<VerifyFinding>> {
    let tx = conn.unchecked_transaction()?;
    let conn: &Connection = &tx;
    let mut out = Findings::default();
    let mut deks = Deks::new(kek);

    let (first, head) = bounds(conn)?;
    let log = load_prune_log(conn, &mut out)?;
    check_prune_log(&log, &mut out);
    check_first_retained(conn, first, &log, &mut out)?;
    // Only its verdict: the walk below reports every PRUNE (the latest included) and every
    // row without its PRUNE, so its findings would be duplicates here.
    let latest_prune_ok = check_latest_prune(conn, &mut deks, &log, &mut Findings::default())?;
    let by_seq: HashMap<u64, &PruneLogRow> = log.iter().map(|r| (r.prune_seq, r)).collect();

    // Key errors are reported once per key_id, not once per row.
    let mut reported_keys: BTreeSet<u64> = BTreeSet::new();
    // `PRUNE`s with a NULL epoch wait for their effective epoch (L36).
    let mut pending: Vec<(u64, Value)> = Vec::new();
    if let Some(first) = first {
        walk(conn, first, &mut out, |out, f, _, prev| {
            let seq = f.seq;
            let payload = match deks.decrypt_json(conn, f)? {
                Ok(p) => p,
                Err(e) => {
                    let key = match &e {
                        DecryptError::KeyMissing(k)
                        | DecryptError::KeyDestroyed(k)
                        | DecryptError::KeyUnwrap(k) => Some(*k),
                        DecryptError::Open | DecryptError::PayloadHash => None,
                    };
                    if key.is_none_or(|k| reported_keys.insert(k)) {
                        out.push(decrypt_finding(seq, &e));
                    }
                    None
                }
            };
            let epoch = f.epoch.map(|e| (e, parse_epoch(e)));
            if let Some((_, Some(e))) = epoch {
                for (pseq, p) in pending.drain(..) {
                    judge_prune(out, pseq, e, &p);
                }
            }
            let Some(payload) = payload else {
                return Ok(());
            };
            match f.event_type {
                "WRITE_APPROVED" => {
                    let claimed = payload
                        .get("request_set_hash")
                        .and_then(Value::as_str)
                        .and_then(hex32);
                    let requests = payload.get("requests").map(requests_from_json);
                    match (claimed, requests) {
                        (Some(claimed), Some(Ok(reqs))) => {
                            let h = request_set_hash(&reqs);
                            if !ct_eq(&h, &claimed) {
                                out.push(
                                    VerifyFinding::new(
                                        FindingKind::RequestSetHashMismatch,
                                        "request_set_hash differs from the stored requests",
                                    )
                                    .expected(Some(seq), Some(claimed))
                                    .observed(Some(seq), Some(h)),
                                );
                            }
                        }
                        _ => out.push(
                            VerifyFinding::new(
                                FindingKind::RequestSetHashMismatch,
                                "requests or request_set_hash is unreadable",
                            )
                            .observed(Some(seq), None),
                        ),
                    }
                }
                "PRUNE" => {
                    check_prune_payload(out, seq, Some(&payload), by_seq.get(&seq).copied());
                    match epoch {
                        Some((_, Some(e))) => judge_prune(out, seq, e, &payload),
                        Some((_, None)) => out.push(
                            VerifyFinding::new(
                                FindingKind::PruneInsideRetention,
                                "PRUNE epoch is unreadable",
                            )
                            .observed(Some(seq), None),
                        ),
                        None => pending.push((seq, payload)),
                    }
                }
                "RESTORE" => {
                    for p in restore_problems(f, Some(&payload), prev) {
                        out.push(
                            VerifyFinding::new(FindingKind::RestoreBoundaryMismatch, p)
                                .observed(Some(seq), None),
                        );
                    }
                }
                _ => {}
            }
            Ok(())
        })?;
    }
    for (seq, _) in pending {
        out.push(
            VerifyFinding::new(
                FindingKind::PruneInsideRetention,
                "PRUNE has no effective epoch",
            )
            .observed(Some(seq), None),
        );
    }
    // Every retained PRUNE has its row (checked above); every retained row's PRUNE is a PRUNE.
    for r in &log {
        if first.is_some_and(|f| r.prune_seq >= f)
            && row_head(conn, r.prune_seq)?
                .and_then(|h| h.event_type)
                .as_deref()
                != Some("PRUNE")
        {
            out.push(
                VerifyFinding::new(
                    FindingKind::PruneLogRowMismatch,
                    "the prune_log row's PRUNE record is missing",
                )
                .expected(Some(r.prune_seq), Some(r.row_hash)),
            );
        }
    }
    let lost = match anchor_lines {
        Some(_) => lost_spans(conn, &mut deks)?,
        None => Vec::new(),
    };
    let dir = check_anchor_dir(conn, anchor_lines, &log, head, &lost, &mut out)?;
    let head_row = match head {
        Some(h) => row_head(conn, h)?,
        None => None,
    };
    let clean = !out.any_of(&CHAIN_KINDS) && !dir.contradicted;
    check_anchors(
        conn,
        &mut deks,
        &AnchorCheck {
            mode: Mode::Full,
            head_anchor: k.head.as_ref(),
            first_retained: k.first_retained.as_ref(),
            head_newer: k.head_newer,
            first_retained_newer: k.first_retained_newer,
            latest_prune_ok,
            head: head_row.as_ref(),
            first,
            log: &log,
            clean,
            anchor_dir_unread: dir.unread,
        },
        &mut out,
    )?;
    drop(tx);
    Ok(out.finish())
}

// ---------------------------------------------------------------------------------------
// Anchor rebuild ("Recover this log", §8.7 step 4)

/// The retained `GENESIS`'s `record_hash` (record 1 of type `GENESIS`), if any.
pub(crate) fn retained_genesis_hash(conn: &Connection) -> rusqlite::Result<Option<[u8; 32]>> {
    Ok(row_head(conn, 1)?
        .filter(|g| g.event_type.as_deref() == Some("GENESIS"))
        .and_then(|g| g.record_hash))
}

/// `(first_retained_seq, last_pruned_record_hash)` of the latest readable `prune_log` row, else
/// `GENESIS`'s values: what startup verification compares the first-retained anchor with.
pub(crate) fn latest_prune_values(conn: &Connection) -> rusqlite::Result<(u64, [u8; 32])> {
    let log = load_prune_log(conn, &mut Findings::default())?;
    Ok(latest_values(&log))
}

// ---------------------------------------------------------------------------------------
// Restore source (§8.11 step 1)

/// The plaintext checks of a restore source before its passphrase is asked for (§8.11 step
/// 1): the `prune_log` chain and contiguity, the first retained record against its latest
/// row, and the chain from there to the head (hashes, links, seqs, `chain_id` changing only at
/// a `RESTORE`). Every finding is an incident kind.
pub(crate) fn snapshot_chain(conn: &Connection) -> rusqlite::Result<Vec<VerifyFinding>> {
    let tx = conn.unchecked_transaction()?;
    let conn: &Connection = &tx;
    let mut out = Findings::default();
    let (first, _) = bounds(conn)?;
    let log = load_prune_log(conn, &mut out)?;
    check_prune_log(&log, &mut out);
    check_first_retained(conn, first, &log, &mut out)?;
    if let Some(first) = first {
        walk(conn, first, &mut out, |_, _, _, _| Ok(()))?;
    }
    drop(tx);
    Ok(out.finish())
}

/// The checks of a restore source that need its KEK (after the passphrase): the latest `PRUNE`
/// decrypts and carries its row's hash, the head record decrypts, and every `RESTORE` is a
/// valid segment boundary (§8.11).
pub(crate) fn snapshot_keyed(conn: &Connection, kek: &Kek) -> rusqlite::Result<Vec<VerifyFinding>> {
    let tx = conn.unchecked_transaction()?;
    let conn: &Connection = &tx;
    let mut out = Findings::default();
    let mut deks = Deks::new(kek);
    let (first, head) = bounds(conn)?;
    let log = load_prune_log(conn, &mut Findings::default())?;
    check_latest_prune(conn, &mut deks, &log, &mut out)?;
    if let Some(h) = head {
        with_row(conn, h, |parsed| {
            match parsed {
                Ok((f, _)) => {
                    if let Err(e) = deks.decrypt(conn, &f)? {
                        out.push(decrypt_finding(h, &e));
                    }
                }
                Err(e) => out.push(
                    VerifyFinding::new(FindingKind::ChainBroken, format!("unreadable row: {e}"))
                        .observed(Some(h), None),
                ),
            }
            Ok(())
        })?;
    }
    let restores: Vec<u64> = {
        let mut st = conn.prepare("SELECT seq FROM events WHERE event_type = 'RESTORE'")?;
        let rows = st.query_map([], |r| Ok(u64_of(r.get_ref(0)?)))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect()
    };
    for seq in restores {
        let prev = match seq.checked_sub(1) {
            Some(s) if first.is_some_and(|f| s >= f) => row_head(conn, s)?.and_then(|b| {
                Some(Prev {
                    seq: b.seq,
                    record_hash: b.record_hash?,
                    chain_id: b.chain_id?,
                })
            }),
            _ => None,
        };
        with_row(conn, seq, |parsed| {
            let Ok((f, _)) = parsed else {
                return Ok(());
            };
            match deks.decrypt_json(conn, &f)? {
                Ok(payload) => {
                    for p in restore_problems(&f, payload.as_ref(), prev.as_ref()) {
                        out.push(
                            VerifyFinding::new(FindingKind::RestoreBoundaryMismatch, p)
                                .observed(Some(seq), None),
                        );
                    }
                }
                Err(e) => out.push(decrypt_finding(seq, &e)),
            }
            Ok(())
        })?;
    }
    drop(tx);
    Ok(out.finish())
}

/// The anchor-dir checks (§8.11 step 1: "against the anchor directory's lines for that
/// `chain_id`") of a restore source. Every finding, a dir that cannot be read included, is
/// one: a restore is never verified against a dir it could not read. `rollback` is the span
/// of the snapshot's own chain the restore being made gives up (a confirmed same-machine
/// rollback), as its `RESTORE` will record it.
pub(crate) fn snapshot_anchor_dir(
    conn: &Connection,
    kek: &Kek,
    lines: Option<&AnchorDirLines>,
    rollback: Option<LostSpan>,
) -> rusqlite::Result<Vec<VerifyFinding>> {
    let tx = conn.unchecked_transaction()?;
    let conn: &Connection = &tx;
    let mut out = Findings::default();
    let (_, head) = bounds(conn)?;
    let log = load_prune_log(conn, &mut Findings::default())?;
    let mut lost = match lines {
        Some(_) => lost_spans(conn, &mut Deks::new(kek))?,
        None => Vec::new(),
    };
    lost.extend(rollback);
    check_anchor_dir(conn, lines, &log, head, &lost, &mut out)?;
    drop(tx);
    Ok(out.finish())
}
