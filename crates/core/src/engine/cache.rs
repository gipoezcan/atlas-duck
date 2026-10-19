//! The candidate LRU and the rebuild from the audit log (§5.2 memory budget, I-37).
//!
//! Once a read's `READ_FETCHED` is committed, memory keeps only the queue metadata (the current
//! redaction ops and the candidate hash of `candidate_rev`) plus this cache, bounded by
//! `candidate_cache_mb`. The cache accounts each candidate by hand (its serialized bytes plus an
//! estimate of its parsed tree) and evicts least-recently-used candidates while over the cap. An
//! evicted candidate is rebuilt from the committed record: decrypt it, re-run the op's
//! deterministic normalization, re-apply the stored redaction ops and compare the SHA-256 with
//! the current `candidate_rev.candidate_hash` (inv. 4, 5). A rebuild never makes a network call;
//! a mismatch fails the item closed (Release disabled, `internal` banner, only Deny remains).
//!
//! **One construction path (Task 21 contract).** The first candidate of a revision and every
//! rebuild must be produced by the same two steps, or every rebuild would mismatch: a
//! normalization `fn(&READ_FETCHED payload) -> bare body` that reads only the committed payload
//! (its `responses` via [`fetched_refs`] and its committed `user_resolutions`, never the
//! live user cache), then [`build_candidate`] (stored ops on the bare body, `serde_json::to_vec`,
//! SHA-256). Task 21 builds its forward candidate as `build_candidate(spec, normalize(&payload),
//! ops)` with the payload it just committed, and passes the same `normalize` to
//! `Engine::candidate`.

use std::borrow::Cow;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use atlas_duck_atlassian::UpstreamResponse;
use atlas_duck_audit::{AuditError, EventType};
use atlas_duck_registry::{OperationSpec, RELEASE_CAP_BYTES};
use lru::LruCache;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::audit_port::AuditPort;
use crate::payloads::body_ref_from_json;
use crate::redact::{self, BlockReason, RedactionMeta, RedactionOp};

/// Estimated bytes of one map entry beside its key and value (allocator and tree overhead).
const MAP_ENTRY_OVERHEAD: u64 = 32;

/// A request's candidate: the exact bytes the approver sees and the agent may receive, their
/// SHA-256 and the parsed tree the previewer reads.
pub struct Candidate {
    bytes: Arc<[u8]>,
    hash: [u8; 32],
    value: Arc<Value>,
    charge: u64,
}

impl Candidate {
    pub fn from_value(value: Value) -> Result<Candidate, serde_json::Error> {
        let bytes = serialize_exact(&value)?;
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        let charge = len_u64(bytes.len()).saturating_add(value_heap_estimate(&value));
        Ok(Candidate {
            bytes,
            hash,
            value: Arc::new(value),
            charge,
        })
    }

    /// The serialized candidate (what Raw pages slice and what is hashed).
    pub fn bytes(&self) -> &Arc<[u8]> {
        &self.bytes
    }

    /// SHA-256 of `bytes()`; the fields are private, so the pair cannot drift apart.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    pub fn value(&self) -> &Arc<Value> {
        &self.value
    }

    /// What the cache counts for this candidate: its bytes plus its tree.
    pub fn charge(&self) -> u64 {
        self.charge
    }
}

/// An `io::Write` that only counts bytes.
struct Counter(usize);

impl std::io::Write for Counter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `serde_json::to_vec(value)` written straight into one allocation of the exact length (I-37):
/// a growing `Vec` ends at up to twice the length, and `Arc<[u8]>::from(Vec)` copies it once
/// more. The length comes from a counting pass, so a candidate costs its bytes once.
fn serialize_exact(value: &Value) -> Result<Arc<[u8]>, serde_json::Error> {
    let mut n = Counter(0);
    serde_json::to_writer(&mut n, value)?;
    // `RepeatN` has an exact length: collected into one allocation, no intermediate `Vec`.
    let mut bytes: Arc<[u8]> = std::iter::repeat_n(0u8, n.0).collect();
    let short = || serde_json::Error::io(std::io::Error::other("serialized length changed"));
    let mut out: &mut [u8] = Arc::get_mut(&mut bytes).ok_or_else(short)?;
    serde_json::to_writer(&mut out, value)?;
    if !out.is_empty() {
        return Err(short());
    }
    Ok(bytes)
}

/// Type name and sizes only, never content (§7.7, §10.1).
impl std::fmt::Debug for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Candidate")
            .field("bytes", &self.bytes.len())
            .field("charge", &self.charge)
            .finish()
    }
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Heap bytes of a parsed tree, estimated: one `Value` slot per array element and map value,
/// string and key bytes, and a fixed overhead per map entry. Iterative, so any depth is fine.
fn value_heap_estimate(v: &Value) -> u64 {
    let slot = len_u64(std::mem::size_of::<Value>());
    let string = len_u64(std::mem::size_of::<String>());
    let mut total = 0u64;
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        let here = match v {
            Value::String(s) => len_u64(s.len()),
            Value::Array(a) => {
                stack.extend(a.iter());
                len_u64(a.len()).saturating_mul(slot)
            }
            Value::Object(o) => {
                let mut n = 0u64;
                for (k, child) in o {
                    n = n.saturating_add(slot + string + MAP_ENTRY_OVERHEAD + len_u64(k.len()));
                    stack.push(child);
                }
                n
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => 0,
        };
        total = total.saturating_add(here);
    }
    total
}

struct Inner {
    lru: LruCache<String, Arc<Candidate>>,
    bytes: u64,
}

/// The byte-bounded candidate LRU (`candidate_cache_mb`, §5.2).
pub struct CandidateCache {
    cap: u64,
    inner: Mutex<Inner>,
}

impl CandidateCache {
    pub fn new(cap_bytes: u64) -> CandidateCache {
        CandidateCache {
            cap: cap_bytes,
            inner: Mutex::new(Inner {
                lru: LruCache::unbounded(),
                bytes: 0,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn cap(&self) -> u64 {
        self.cap
    }

    /// Bytes counted now; never above `cap`.
    pub fn bytes(&self) -> u64 {
        self.lock().bytes
    }

    pub fn len(&self) -> usize {
        self.lock().lru.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Caches `c` under `request_id` (replacing an older one) and evicts least-recently-used
    /// candidates while over the cap. A candidate larger than the whole cache is not kept: it is
    /// rebuilt whenever it is needed.
    pub fn insert(&self, request_id: &str, c: Arc<Candidate>) {
        let mut g = self.lock();
        if let Some(old) = g.lru.pop(request_id) {
            g.bytes = g.bytes.saturating_sub(old.charge);
        }
        if c.charge > self.cap {
            return;
        }
        g.bytes = g.bytes.saturating_add(c.charge);
        g.lru.push(request_id.to_owned(), c);
        while g.bytes > self.cap {
            match g.lru.pop_lru() {
                Some((_, evicted)) => g.bytes = g.bytes.saturating_sub(evicted.charge),
                None => {
                    g.bytes = 0;
                    break;
                }
            }
        }
    }

    /// The cached candidate, marked as most recently used.
    pub fn get(&self, request_id: &str) -> Option<Arc<Candidate>> {
        self.lock().lru.get(request_id).cloned()
    }

    /// Whether a candidate is cached, without touching its recency.
    pub fn contains(&self, request_id: &str) -> bool {
        self.lock().lru.contains(request_id)
    }

    pub fn remove(&self, request_id: &str) {
        let mut g = self.lock();
        if let Some(old) = g.lru.pop(request_id) {
            g.bytes = g.bytes.saturating_sub(old.charge);
        }
    }

    pub fn clear(&self) {
        let mut g = self.lock();
        g.lru.clear();
        g.bytes = 0;
    }
}

/// Why a candidate could not be rebuilt.
#[derive(Debug)]
pub enum RebuildError {
    /// The request has no committed candidate record.
    NoSource,
    /// The store could not answer this call (closed, I/O): only this call fails, a later one
    /// may succeed (PD-40).
    Transient(AuditError),
    /// The record is unusable for good (decrypt failure, payload hash mismatch, invalid or
    /// missing record, PD-40): Release is disabled like for `HashMismatch`.
    Permanent(AuditError),
    /// The record or the normalization did not give a candidate.
    Malformed,
    /// A stored redaction op no longer applies.
    Blocked,
    /// The rebuilt bytes are not the current revision's (§5.2: fail closed).
    HashMismatch,
}

impl RebuildError {
    /// Sorts a store failure into `Permanent` (the record itself is bad) or `Transient`. Every
    /// variant is listed, so a new `AuditError` has to be sorted here.
    ///
    /// `Invalid(_)` is `Permanent` on the assumption that `headers_for_request` and
    /// `read_payload` raise it only for bad row or payload data (a column of the wrong shape, a
    /// payload that does not decompress). The other `Invalid` sources (`crypto`'s "key length",
    /// writer, anchor and settings checks) cannot reach a read: the key is fixed-size, from the
    /// key store, and the rest belong to writes.
    pub fn from_audit(e: AuditError) -> RebuildError {
        match e {
            AuditError::Closed
            | AuditError::Io(_)
            | AuditError::AppendFailed(_)
            | AuditError::KeyStore(_)
            | AuditError::StorageLow
            | AuditError::AnchorThreadDead
            | AuditError::AnchorFlushTimeout
            | AuditError::AnchorOutcomeUnknown
            | AuditError::NeedsConfirmation(_)
            | AuditError::Restore(_)
            | AuditError::Cancelled
            | AuditError::ExportLeftover { .. }
            | AuditError::ExportNotRenamed(_) => RebuildError::Transient(e),
            AuditError::Decrypt { .. }
            | AuditError::PayloadHash { .. }
            | AuditError::InvalidRecord { .. }
            | AuditError::NotFound { .. }
            | AuditError::Invalid(_) => RebuildError::Permanent(e),
        }
    }

    /// Every failure except a transient store failure is permanent for this revision: Release is
    /// disabled and only Deny remains (§5.2). A transient failure fails only this call.
    pub fn disables_release(&self) -> bool {
        !matches!(self, RebuildError::Transient(_))
    }
}

/// The records a candidate is rebuilt from: `READ_FETCHED`; for scripts `SCRIPT_FINISHED` or the
/// `SCRIPT_FAILED {direct: false}` that holds the error-details candidate (Task 27).
pub const CANDIDATE_SOURCES: [EventType; 3] = [
    EventType::READ_FETCHED,
    EventType::SCRIPT_FINISHED,
    EventType::SCRIPT_FAILED,
];

/// The pages (or the error response) of a `READ_FETCHED` payload with their bytes restored
/// (`payloads::read_fetched`'s `responses`; `body_from_json` per body).
pub fn fetched_responses(payload: &Value) -> Result<Vec<UpstreamResponse>, RebuildError> {
    Ok(fetched_refs(payload)?
        .into_iter()
        .map(|r| UpstreamResponse {
            status: r.status,
            content_type: r.content_type.map(str::to_owned),
            body: r.body.into_owned(),
        })
        .collect())
}

/// One response of a `READ_FETCHED` payload, read in place.
pub struct FetchedRef<'a> {
    pub status: u16,
    pub content_type: Option<&'a str>,
    /// Borrowed from the payload when it was stored as text (I-37: a 16 MiB page is parsed
    /// where it is, not copied first).
    pub body: Cow<'a, [u8]>,
}

/// [`fetched_responses`] without copying the bodies stored as text; same checks.
pub fn fetched_refs(payload: &Value) -> Result<Vec<FetchedRef<'_>>, RebuildError> {
    let Some(rs) = payload.get("responses").and_then(Value::as_array) else {
        return Err(RebuildError::Malformed);
    };
    rs.iter()
        .map(|r| {
            let status = r
                .get("status")
                .and_then(Value::as_u64)
                .and_then(|s| u16::try_from(s).ok())
                .ok_or(RebuildError::Malformed)?;
            let content_type = match r.get("content_type") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => Some(s.as_str()),
                Some(_) => return Err(RebuildError::Malformed),
            };
            let body = r
                .get("body")
                .and_then(body_ref_from_json)
                .ok_or(RebuildError::Malformed)?;
            Ok(FetchedRef {
                status,
                content_type,
                body,
            })
        })
        .collect()
}

/// The candidate of a revision: the stored redaction ops applied to the bare normalized body
/// (T14 handoff: paths are body-absolute), then serialized and hashed. The one construction path
/// for the first build and every rebuild.
pub fn build_candidate(
    spec: &OperationSpec,
    body: Value,
    ops: &[RedactionOp],
) -> Result<Candidate, RebuildError> {
    build_redacted(spec, body, ops).map(|(c, _)| c)
}

/// What a revision's ops did besides its bytes (`meta.redactions`, "also appears in").
#[derive(Clone)]
pub struct RedactionReport {
    pub meta: RedactionMeta,
    pub also_appears_in: Vec<String>,
}

/// The candidate of `body` without ops, and whether the §5.3 mirror check blocks its release (a
/// mirror entry without a counterpart). A read's first build and the [`rebuild`] of that revision
/// show such a candidate with Release disabled (T10 review I-1; M-11: its flagged entries can be
/// dropped); a new revision refuses it ([`build_redacted`]: undoing every redaction). The same
/// bytes either way, so the hash a rebuild compares is this one.
pub fn build_unredacted(
    spec: &OperationSpec,
    body: Value,
) -> Result<(Candidate, bool), RebuildError> {
    let blocked = redact::mirror_blocked(&body, &spec.redaction_rules);
    let c = Candidate::from_value(body).map_err(|_| RebuildError::Malformed)?;
    Ok((c, blocked))
}

/// [`build_candidate`] with the report of the ops (`None` without ops); a new redacted revision
/// is built through this, so it hashes exactly as its rebuild will. Ops that block (§5.3), a
/// candidate without ops that fails the mirror check (§5.3: a rebuild before release, or a
/// revision whose redactions were all undone), or a redacted candidate over the 16 MiB release
/// cap (every-occurrence masks can grow a body: each match becomes `[REDACTED]`; §5.2 step 4,
/// and with it the 24 MiB IPC frame), are `Blocked`.
pub fn build_redacted(
    spec: &OperationSpec,
    body: Value,
    ops: &[RedactionOp],
) -> Result<(Candidate, Option<RedactionReport>), RebuildError> {
    let check = check_redacted(spec, body, ops)?;
    if !check.blocked.is_empty() {
        return Err(RebuildError::Blocked);
    }
    Ok((check.candidate, check.report))
}

/// What [`build_redacted`] decides on, every reason kept: the UI's `redaction_preview` shows it
/// (M6 Δ2), so the preview and the release path cannot disagree.
pub struct RedactionCheck {
    /// The candidate the ops give (also when they block).
    pub candidate: Candidate,
    /// Empty ⇒ the release path takes these ops: the §5.3 checks of `redact::apply`, the mirror
    /// check of a candidate without ops, and the 16 MiB release cap (`OverReleaseCap`).
    pub blocked: Vec<BlockReason>,
    /// `None` without ops.
    pub report: Option<RedactionReport>,
    /// The single-occurrence masks' "N other occurrences remain", summed.
    pub other_occurrences: u64,
}

/// The one check behind [`build_redacted`] (see there).
pub fn check_redacted(
    spec: &OperationSpec,
    body: Value,
    ops: &[RedactionOp],
) -> Result<RedactionCheck, RebuildError> {
    if ops.is_empty() {
        let blocked = redact::mirror_reasons(&body, &spec.redaction_rules);
        let candidate = Candidate::from_value(body).map_err(|_| RebuildError::Malformed)?;
        return Ok(RedactionCheck {
            candidate,
            blocked,
            report: None,
            other_occurrences: 0,
        });
    }
    let out = redact::apply(
        &body,
        &spec.redaction_rules,
        spec.paginated.map(|p| p.items_key),
        ops,
    );
    drop(body);
    let mut blocked = out.blocked;
    let candidate = Candidate::from_value(out.released).map_err(|_| RebuildError::Malformed)?;
    if len_u64(candidate.bytes().len()) > RELEASE_CAP_BYTES {
        blocked.push(BlockReason::OverReleaseCap {
            path: String::new(),
        });
    }
    Ok(RedactionCheck {
        candidate,
        blocked,
        report: Some(RedactionReport {
            meta: out.meta,
            also_appears_in: out.also_appears_in,
        }),
        other_occurrences: out.other_occurrences,
    })
}

/// Rebuilds `request_id`'s candidate from its last committed candidate record (blocking: call it
/// off the async runtime). `normalize` maps the decrypted payload to the bare body exactly as the
/// first build did; it must read nothing but the payload.
///
/// The `bool` is `true` for a revision without ops whose candidate the §5.3 mirror check blocks
/// (M5 M-11, M8 T19c): rebuilt like the first build ([`build_unredacted`]), so the approver keeps
/// its tree and can drop the flagged entries; its release stays disabled (the caller's
/// `rebuild_failed`). The hash comparison applies to it as to every rebuild: a mismatch is
/// `HashMismatch`, never a tree.
pub fn rebuild<N>(
    port: &dyn AuditPort,
    request_id: &str,
    spec: &OperationSpec,
    ops: &[RedactionOp],
    expected: &[u8; 32],
    normalize: N,
) -> Result<(Candidate, bool), RebuildError>
where
    N: FnOnce(&Value) -> Result<Value, RebuildError>,
{
    let body = source_body(port, request_id, normalize)?;
    let (c, mirror_blocked) = if ops.is_empty() {
        build_unredacted(spec, body)?
    } else {
        (build_candidate(spec, body, ops)?, false)
    };
    if &c.hash != expected {
        return Err(RebuildError::HashMismatch);
    }
    Ok((c, mirror_blocked))
}

/// The normalized body of `request_id`'s last committed candidate record, before any redaction
/// op (blocking): what a new set of ops is applied to (§5.3, Task 21).
pub fn source_body<N>(
    port: &dyn AuditPort,
    request_id: &str,
    normalize: N,
) -> Result<Value, RebuildError>
where
    N: FnOnce(&Value) -> Result<Value, RebuildError>,
{
    normalize(&source_payload(port, request_id)?)
}

/// The decrypted payload of `request_id`'s last committed candidate record (blocking): what
/// [`source_body`] normalizes. A script's preview reads the logs and stderr of a result from it
/// (T17: they are in the record, not in the candidate).
pub fn source_payload(port: &dyn AuditPort, request_id: &str) -> Result<Value, RebuildError> {
    let headers = port
        .headers_for_request(request_id)
        .map_err(RebuildError::from_audit)?;
    let source = headers
        .iter()
        .rev()
        .find(|h| CANDIDATE_SOURCES.contains(&h.event_type))
        .ok_or(RebuildError::NoSource)?;
    let bytes = port
        .read_payload(source.seq)
        .map_err(RebuildError::from_audit)?;
    serde_json::from_slice(&bytes).map_err(|_| RebuildError::Malformed)
}
