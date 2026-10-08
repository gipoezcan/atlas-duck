//! Keychain anchors (§8.5, F.6): the entry layouts `0x01 ‖ JCS(object)`, and the `audit-anchor`
//! thread, the only writer of the two entries after first run (T07 writes them once at first
//! run). The writer thread publishes each committed head into [`AnchorShared`]; this thread
//! batches them (one keychain write per [`BATCH_WINDOW`] of dirtiness at most), honours the
//! prune/restore barriers and writes nothing until startup verification called `enable`. A
//! failing keychain never touches the chain: it is retried with backoff and shown in
//! `StoreHealth`, never an incident (§8.8).

use std::fmt;
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use atlas_duck_ipc::jcs::to_jcs_vec;
use serde::Deserialize;
use serde_json::json;

use crate::error::AuditError;
use crate::keystore::{EntryName, KeyStore, KeyStoreError};

/// Leading layout byte of the `head_anchor` and `first_retained_anchor` entries (F.6).
pub const ANCHOR_LAYOUT: u8 = 1;

/// `{chain_id, record_hash, seq}` (F.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadAnchor {
    pub chain_id: String,
    pub seq: u64,
    pub record_hash: [u8; 32],
}

/// `{chain_id, first_retained_prev_hash, first_retained_seq, genesis_hash}` (F.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstRetainedAnchor {
    pub chain_id: String,
    pub genesis_hash: [u8; 32],
    pub first_retained_seq: u64,
    pub first_retained_prev_hash: [u8; 32],
}

/// A stored anchor entry could not be read (§8.13 version gate on the layout byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorEntryError {
    NewerLayout(u8),
    Malformed,
}

impl fmt::Display for AnchorEntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnchorEntryError::NewerLayout(n) => write!(f, "keychain anchor has newer layout {n}"),
            AnchorEntryError::Malformed => f.write_str("keychain anchor is malformed"),
        }
    }
}

impl std::error::Error for AnchorEntryError {}

fn entry(v: &serde_json::Value) -> Result<Vec<u8>, AuditError> {
    // Only a seq above 2^53 − 1 can fail here; never truncate it.
    let body = to_jcs_vec(v).map_err(|_| AuditError::Invalid("anchor is not encodable as JCS"))?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(ANCHOR_LAYOUT);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Layout byte check, then the JSON body (callers also require the exact JCS bytes).
fn body<'de, T: Deserialize<'de>>(b: &'de [u8]) -> Result<T, AnchorEntryError> {
    match b.first() {
        None | Some(0) => Err(AnchorEntryError::Malformed),
        Some(&n) if n > ANCHOR_LAYOUT => Err(AnchorEntryError::NewerLayout(n)),
        Some(_) => serde_json::from_slice(&b[1..]).map_err(|_| AnchorEntryError::Malformed),
    }
}

fn hash32(s: &str) -> Result<[u8; 32], AnchorEntryError> {
    let v = hex::decode(s).map_err(|_| AnchorEntryError::Malformed)?;
    if s.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err(AnchorEntryError::Malformed);
    }
    v.try_into().map_err(|_| AnchorEntryError::Malformed)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadJson {
    chain_id: String,
    record_hash: String,
    seq: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirstRetainedJson {
    chain_id: String,
    first_retained_prev_hash: String,
    first_retained_seq: u64,
    genesis_hash: String,
}

impl HeadAnchor {
    pub fn to_entry(&self) -> Result<Vec<u8>, AuditError> {
        entry(&json!({
            "chain_id": self.chain_id,
            "record_hash": hex::encode(self.record_hash),
            "seq": self.seq,
        }))
    }

    pub fn from_entry(b: &[u8]) -> Result<HeadAnchor, AnchorEntryError> {
        let j: HeadJson = body(b)?;
        let a = HeadAnchor {
            chain_id: j.chain_id,
            seq: j.seq,
            record_hash: hash32(&j.record_hash)?,
        };
        match a.to_entry() {
            Ok(e) if e == b => Ok(a),
            _ => Err(AnchorEntryError::Malformed),
        }
    }
}

impl FirstRetainedAnchor {
    pub fn to_entry(&self) -> Result<Vec<u8>, AuditError> {
        entry(&json!({
            "chain_id": self.chain_id,
            "first_retained_prev_hash": hex::encode(self.first_retained_prev_hash),
            "first_retained_seq": self.first_retained_seq,
            "genesis_hash": hex::encode(self.genesis_hash),
        }))
    }

    pub fn from_entry(b: &[u8]) -> Result<FirstRetainedAnchor, AnchorEntryError> {
        let j: FirstRetainedJson = body(b)?;
        let a = FirstRetainedAnchor {
            chain_id: j.chain_id,
            genesis_hash: hash32(&j.genesis_hash)?,
            first_retained_seq: j.first_retained_seq,
            first_retained_prev_hash: hash32(&j.first_retained_prev_hash)?,
        };
        match a.to_entry() {
            Ok(e) if e == b => Ok(a),
            _ => Err(AnchorEntryError::Malformed),
        }
    }
}

/// The keychain anchors could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AnchorLoadError {
    /// A layout byte newer than this build (§8.13 version gate).
    Newer(u8),
    KeyStore(KeyStoreError),
}

fn read_entry<T>(
    keys: &dyn KeyStore,
    e: EntryName,
    parse: fn(&[u8]) -> Result<T, AnchorEntryError>,
) -> Result<Option<T>, AnchorLoadError> {
    match keys.get(&e).map_err(AnchorLoadError::KeyStore)? {
        None => Ok(None),
        Some(b) => match parse(&b) {
            Ok(a) => Ok(Some(a)),
            Err(AnchorEntryError::NewerLayout(n)) => Err(AnchorLoadError::Newer(n)),
            Err(AnchorEntryError::Malformed) => Ok(None),
        },
    }
}

/// The head anchor entry; absent or malformed is `None` (verification reports it missing).
pub(crate) fn load_head(keys: &dyn KeyStore) -> Result<Option<HeadAnchor>, AnchorLoadError> {
    read_entry(keys, EntryName::HeadAnchor, HeadAnchor::from_entry)
}

/// The first-retained anchor entry; absent or malformed is `None`.
pub(crate) fn load_first_retained(
    keys: &dyn KeyStore,
) -> Result<Option<FirstRetainedAnchor>, AnchorLoadError> {
    read_entry(
        keys,
        EntryName::FirstRetainedAnchor,
        FirstRetainedAnchor::from_entry,
    )
}

/// Reads the head anchor, then the first-retained anchor. That order matters while the store
/// runs: the anchor thread writes first-retained before head, so a head read first never
/// names a `PRUNE` whose first-retained update the second read cannot see. An absent or
/// malformed entry is `None` (verification reports it as missing).
pub(crate) fn load_anchors(
    keys: &dyn KeyStore,
) -> Result<(Option<HeadAnchor>, Option<FirstRetainedAnchor>), AnchorLoadError> {
    let head = load_head(keys)?;
    Ok((head, load_first_retained(keys)?))
}

/// The head anchor trails the newest commit by at most this long; commits inside one window
/// share one keychain write.
pub(crate) const BATCH_WINDOW: Duration = Duration::from_millis(900);

/// How long `flush_head_anchor`, the restore completion and `shutdown` wait for the anchor
/// thread (a hung keychain call must not hang the app).
pub(crate) const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest idle wait of the anchor thread.
const MAX_WAIT: Duration = Duration::from_secs(1);

/// Retry delay after the `failures`-th consecutive failure: 1, 2, 4, 8, 16, 32, 60, 60 … s.
pub(crate) fn backoff(failures: u32) -> Duration {
    Duration::from_secs(match failures {
        0 | 1 => 1,
        2 => 2,
        3 => 4,
        4 => 8,
        5 => 16,
        6 => 32,
        _ => 60,
    })
}

/// What holds the head anchor back.
#[derive(Debug, Clone)]
pub(crate) enum Barrier {
    /// The head anchor may reach `seq` (the `PRUNE` record) but not beyond until the
    /// first-retained entry holds `first_retained` (§8.7 (d)).
    Prune {
        seq: u64,
        record_hash: [u8; 32],
        first_retained: FirstRetainedAnchor,
    },
    /// No head write at all until the restore completion step wrote both entries: an anchor
    /// from before the `RESTORE` would describe the replaced DB. `reset` is the completion
    /// (the anchors of the restored store): once set, the anchor thread writes it, retrying with
    /// backoff like a prune's first-retained update, and lifts the barrier on success (§8.11
    /// step 5). `None` while the restore is still running (or for "Recover this log", whose
    /// one-shot `complete_restore` writes the anchors).
    Restore {
        seq: u64,
        reset: Option<RestoreReset>,
    },
    /// Like `Restore` but nothing lifts it in this process: an interrupted restore whose
    /// startup reconciliation was deferred because the anchor dir could not be read. Neither
    /// `complete_restore` nor a reset applies to it, so the head anchor keeps naming the
    /// `prior_keychain_anchor` and the next start can still reconcile it (§8.7).
    RestoreHold,
    /// Like `Prune` but nothing lifts it in this process: an interrupted prune whose startup
    /// reconciliation was deferred because the anchor dir could not be read. The head anchor
    /// stays at or before the `PRUNE`, so the next start can still reconcile it (§8.7 (d)).
    /// Only a restore replaces it (`swap_barrier`): the store it belongs to is replaced, and
    /// it comes back if the restore fails before its commit. The same holds for `RestoreHold`.
    Hold { seq: u64, record_hash: [u8; 32] },
    /// A prune is about to commit: the slot is taken so its `Prune` barrier can be set right
    /// after the commit and before the new head is published. Caps and writes nothing (nothing
    /// past the current head is published meanwhile).
    PruneReserved,
}

/// The anchors a restore completion writes: first-retained, then head (§8.11 step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RestoreReset {
    pub(crate) head: HeadAnchor,
    pub(crate) first_retained: FirstRetainedAnchor,
}

impl Barrier {
    fn kind(&self) -> BarrierKind {
        match self {
            Barrier::Prune { .. } | Barrier::Hold { .. } | Barrier::PruneReserved => {
                BarrierKind::Prune
            }
            Barrier::Restore { .. } | Barrier::RestoreHold => BarrierKind::Restore,
        }
    }
}

/// Which barrier holds the anchors back (for `StoreHealth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierKind {
    /// The first-retained update after a `PRUNE` is pending; the head anchor is capped.
    Prune,
    /// A `RESTORE` is not completed; no head anchor is written.
    Restore,
}

struct RestoreJob {
    head: HeadAnchor,
    first_retained: FirstRetainedAnchor,
    reply: SyncSender<Result<(), AuditError>>,
}

type FlushReply = SyncSender<Result<(), KeyStoreError>>;

pub(crate) struct AnchorState {
    enabled: bool,
    head: Option<HeadAnchor>,
    written_head: Option<HeadAnchor>,
    barrier: Option<Barrier>,
    dirty_since: Option<Instant>,
    flush_requested: bool,
    stop: bool,
    failures: u32,
    next_retry: Option<Instant>,
    last_error: Option<KeyStoreError>,
    waiters: Vec<FlushReply>,
    restore_job: Option<RestoreJob>,
    /// Told the outcome of the next restore-reset attempt.
    reset_waiters: Vec<FlushReply>,
    /// The batch window (tests shorten or stretch it).
    window: Duration,
    wait_timeout: Duration,
    /// The thread panicked: nothing will ever be written again.
    dead: bool,
    /// The thread left its loop (stop or panic).
    exited: bool,
}

impl AnchorState {
    fn new() -> AnchorState {
        AnchorState {
            window: BATCH_WINDOW,
            wait_timeout: DEFAULT_WAIT_TIMEOUT,
            dead: false,
            exited: false,
            enabled: false,
            head: None,
            written_head: None,
            barrier: None,
            dirty_since: None,
            flush_requested: false,
            stop: false,
            failures: 0,
            next_retry: None,
            last_error: None,
            waiters: Vec::new(),
            restore_job: None,
            reset_waiters: Vec::new(),
        }
    }

    /// The head anchor to write now: the head, capped at an open prune barrier, nothing while
    /// disabled or behind a restore barrier.
    fn flush_target(&self) -> Option<HeadAnchor> {
        if !self.enabled {
            return None;
        }
        match &self.barrier {
            Some(Barrier::Restore { .. } | Barrier::RestoreHold) => None,
            Some(
                Barrier::Prune {
                    seq, record_hash, ..
                }
                | Barrier::Hold { seq, record_hash },
            ) => self.head.as_ref().map(|h| {
                if h.seq > *seq {
                    HeadAnchor {
                        chain_id: h.chain_id.clone(),
                        seq: *seq,
                        record_hash: *record_hash,
                    }
                } else {
                    h.clone()
                }
            }),
            Some(Barrier::PruneReserved) | None => self.head.clone(),
        }
    }

    fn prune_pending(&self) -> bool {
        self.enabled && matches!(self.barrier, Some(Barrier::Prune { .. }))
    }

    /// A restore completion is armed and not yet written. Like the restore job it does not
    /// wait for `enable`: it is armed only after the verification it completes.
    fn reset_pending(&self) -> bool {
        matches!(self.barrier, Some(Barrier::Restore { reset: Some(_), .. }))
    }

    fn retry_ok(&self, now: Instant) -> bool {
        self.next_retry.is_none_or(|t| now >= t)
    }

    fn retry_in(&self, now: Instant) -> Duration {
        self.next_retry
            .map_or(Duration::ZERO, |t| t.saturating_duration_since(now))
    }

    fn dirty_for(&self, now: Instant) -> Duration {
        self.dirty_since
            .map_or(Duration::ZERO, |d| now.saturating_duration_since(d))
    }

    /// The target, if it differs from what the keychain holds.
    /// A head of the same chain with a lower seq than the keychain's is never written.
    fn head_stale(&self) -> Option<HeadAnchor> {
        self.flush_target().filter(|t| {
            self.written_head.as_ref() != Some(t)
                && !matches!(&self.written_head, Some(w) if w.chain_id == t.chain_id && w.seq > t.seq)
        })
    }

    /// A stale head always has an open batch window, whatever made it stale (barrier lifted,
    /// restore head older than the published one).
    fn touch(&mut self, now: Instant) {
        if self.dirty_since.is_none() && self.head_stale().is_some() {
            self.dirty_since = Some(now);
        }
    }

    fn head_due(&self, now: Instant) -> bool {
        self.head_stale().is_some() && self.dirty_for(now) >= self.window && self.retry_ok(now)
    }

    pub(crate) fn work_due(&self, now: Instant) -> bool {
        self.stop
            || self.flush_requested
            || self.restore_job.is_some()
            || ((self.prune_pending() || self.reset_pending()) && self.retry_ok(now))
            || self.head_due(now)
    }

    pub(crate) fn next_wakeup(&self, now: Instant) -> Duration {
        if self.stop || self.flush_requested || self.restore_job.is_some() {
            return Duration::ZERO;
        }
        let mut w = MAX_WAIT;
        if self.prune_pending() || self.reset_pending() {
            w = w.min(self.retry_in(now));
        }
        if let (Some(d), Some(_)) = (self.dirty_since, self.head_stale()) {
            let window = (d + self.window).saturating_duration_since(now);
            w = w.min(window.max(self.retry_in(now)));
        }
        w
    }

    fn schedule_retry(&mut self, e: KeyStoreError, now: Instant, scale_div: u32) {
        self.failures = self.failures.saturating_add(1);
        self.next_retry = Some(now + backoff(self.failures) / scale_div.max(1));
        self.last_error = Some(e);
    }

    /// Why `flush`/`complete_restore`/`install_barrier` cannot be served.
    fn unusable(&self) -> AuditError {
        if self.dead {
            AuditError::AnchorThreadDead
        } else {
            AuditError::Closed
        }
    }

    fn clear_failure(&mut self) {
        self.failures = 0;
        self.next_retry = None;
        self.last_error = None;
    }
}

/// The anchor state shared between the writer thread, the `Store` handles and the anchor
/// thread. The keychain is only ever called with the state lock released, so keychain latency
/// never blocks `append`.
pub(crate) struct AnchorShared {
    state: Mutex<AnchorState>,
    cv: Condvar,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What `Store::health` reports about the anchors.
pub(crate) struct AnchorHealth {
    pub(crate) write_failing: bool,
    pub(crate) first_retained_pending: bool,
    pub(crate) blocked: Option<BarrierKind>,
    pub(crate) thread_dead: bool,
}

/// Releases an installed barrier when dropped, unless [`BarrierGuard::complete`] says the
/// operation went through (the anchor thread, or the restore completion, lifts it then). Hold
/// it across the `PRUNE`/`RESTORE` work so an error path cannot leave the anchors blocked.
pub struct BarrierGuard {
    shared: Option<Arc<AnchorShared>>,
}

impl BarrierGuard {
    /// The operation succeeded: the barrier stays until its update/reset lifts it.
    pub fn complete(mut self) {
        self.shared = None;
    }

    /// Replaces the reserved slot of [`AnchorShared::reserve_prune_barrier`] with `b`.
    pub(crate) fn arm(&self, b: Barrier) -> Result<(), AuditError> {
        match &self.shared {
            Some(s) => s.arm_reserved(b),
            None => Err(AuditError::Invalid("the barrier guard was completed")),
        }
    }
}

impl Drop for BarrierGuard {
    fn drop(&mut self) {
        if let Some(s) = self.shared.take() {
            s.clear_barrier();
        }
    }
}

impl AnchorShared {
    pub(crate) fn new() -> AnchorShared {
        AnchorShared {
            state: Mutex::new(AnchorState::new()),
            cv: Condvar::new(),
        }
    }

    /// Start state once the writer is ready: the head as the writer loaded it, and whether the
    /// keychain already holds it (first run) or not.
    pub(crate) fn init(
        &self,
        enabled: bool,
        head: HeadAnchor,
        anchored: bool,
        window: Duration,
        wait_timeout: Duration,
    ) {
        let mut st = lock(&self.state);
        st.window = window;
        st.wait_timeout = wait_timeout;
        st.enabled = enabled;
        st.written_head = anchored.then(|| head.clone());
        st.head = Some(head);
        st.dirty_since = None;
    }

    /// After a commit, from the writer thread. Only the first unflushed commit opens the
    /// batch window (and wakes the thread to time it).
    pub(crate) fn publish_head(&self, h: HeadAnchor) {
        let mut st = lock(&self.state);
        st.head = Some(h);
        if st.dirty_since.is_none() {
            st.dirty_since = Some(Instant::now());
            drop(st);
            self.cv.notify_all();
        }
    }

    /// Startup verification passed: anchor writes may begin.
    pub(crate) fn enable(&self) {
        let mut st = lock(&self.state);
        st.enabled = true;
        if st.dirty_since.is_none() && st.head_stale().is_some() {
            st.dirty_since = Some(Instant::now());
        }
        drop(st);
        self.cv.notify_all();
    }

    /// Anchor writes stop again until the next `enable` (tests hold the keychain at an older
    /// head with it; prune when it could not set its barrier).
    pub(crate) fn disable(&self) {
        lock(&self.state).enabled = false;
    }

    /// Installs the one barrier; a second one is refused (it would silently lift the first).
    /// Retry state of earlier failures is dropped so the new barrier is attempted at once.
    pub(crate) fn install_barrier(
        self: &Arc<Self>,
        b: Barrier,
    ) -> Result<BarrierGuard, AuditError> {
        {
            let mut st = lock(&self.state);
            if st.stop || st.dead {
                return Err(st.unusable());
            }
            if st.barrier.is_some() {
                return Err(AuditError::Invalid(
                    "an anchor barrier is already installed",
                ));
            }
            st.barrier = Some(b);
            st.clear_failure();
        }
        self.cv.notify_all();
        Ok(BarrierGuard {
            shared: Some(self.clone()),
        })
    }

    /// Takes the barrier slot for a prune before its transaction (see
    /// [`Barrier::PruneReserved`]); refused like a second barrier. The guard releases it.
    pub(crate) fn reserve_prune_barrier(self: &Arc<Self>) -> Result<BarrierGuard, AuditError> {
        {
            let mut st = lock(&self.state);
            if st.stop || st.dead {
                return Err(st.unusable());
            }
            if st.barrier.is_some() {
                return Err(AuditError::Invalid(
                    "an anchor barrier is already installed",
                ));
            }
            st.barrier = Some(Barrier::PruneReserved);
        }
        Ok(BarrierGuard {
            shared: Some(self.clone()),
        })
    }

    /// The reserved (or released) slot becomes `b`; another barrier is never replaced.
    fn arm_reserved(&self, b: Barrier) -> Result<(), AuditError> {
        {
            let mut st = lock(&self.state);
            match st.barrier {
                None | Some(Barrier::PruneReserved) => {}
                Some(_) => {
                    return Err(AuditError::Invalid("another anchor barrier is installed"));
                }
            }
            st.barrier = Some(b);
            st.clear_failure();
        }
        self.cv.notify_all();
        Ok(())
    }

    /// Replaces whatever barrier is installed with `b` and returns the old one, so a restore
    /// can hold the head anchor still while it reads the keychain and put the old barrier back
    /// if it fails before its commit (a prune's pending first-retained update, a deferred
    /// reconciliation): the restore replaces the store those barriers belong to (N-6, owned
    /// deliberately). Waits until a keychain write already in flight has returned, so the
    /// keychain does not change behind the caller once this returns `Ok`.
    pub(crate) fn swap_barrier(&self, b: Option<Barrier>) -> Result<Option<Barrier>, AuditError> {
        let old = {
            let mut st = lock(&self.state);
            if st.stop || st.dead {
                return Err(st.unusable());
            }
            let old = std::mem::replace(&mut st.barrier, b);
            st.clear_failure();
            old
        };
        self.cv.notify_all();
        // A flush is answered by the thread's next turn, i.e. after any write in flight.
        let (tx, rx) = sync_channel(1);
        {
            let mut st = lock(&self.state);
            st.waiters.push(tx);
            st.flush_requested = true;
        }
        self.cv.notify_all();
        let wait = lock(&self.state).wait_timeout;
        let quiet = match rx.recv_timeout(wait) {
            Ok(_) => Ok(()),
            Err(RecvTimeoutError::Timeout) => Err(AuditError::AnchorFlushTimeout),
            Err(RecvTimeoutError::Disconnected) => Err(self.after_disconnect()),
        };
        match quiet {
            Ok(()) => Ok(old),
            Err(e) => {
                // The caller gives up: the barrier it replaced comes back.
                self.restore_barrier(old);
                Err(e)
            }
        }
    }

    /// Puts back a barrier taken by [`AnchorShared::swap_barrier`] (error paths before the
    /// restore commit).
    pub(crate) fn restore_barrier(&self, old: Option<Barrier>) {
        {
            let mut st = lock(&self.state);
            st.barrier = old;
            st.clear_failure();
        }
        self.cv.notify_all();
    }

    /// Arms the completion of the restore barrier at `seq` (installed and not yet armed): the
    /// anchor thread writes `reset` (first-retained, then head), retries it with backoff and
    /// lifts the barrier once it succeeded. The receiver gets the outcome of the first attempt.
    pub(crate) fn arm_restore_reset(
        &self,
        seq: u64,
        reset: RestoreReset,
    ) -> Result<std::sync::mpsc::Receiver<Result<(), KeyStoreError>>, AuditError> {
        let (tx, rx) = sync_channel(1);
        {
            let mut st = lock(&self.state);
            if st.stop || st.dead {
                return Err(st.unusable());
            }
            if reset.head.chain_id != reset.first_retained.chain_id || reset.head.seq < seq {
                return Err(AuditError::Invalid(
                    "restore anchors do not fit the RESTORE",
                ));
            }
            match &mut st.barrier {
                Some(Barrier::Restore { seq: s, reset: r }) if *s == seq && r.is_none() => {
                    *r = Some(reset);
                }
                _ => {
                    return Err(AuditError::Invalid(
                        "no unarmed restore barrier for this RESTORE",
                    ));
                }
            }
            st.clear_failure();
            st.reset_waiters.push(tx);
        }
        self.cv.notify_all();
        Ok(rx)
    }

    /// Waits (at most the wait timeout) for the outcome of the first reset attempt armed by
    /// [`AnchorShared::arm_restore_reset`]. A failure or a timeout is not the restore's error:
    /// the thread keeps retrying, and `health()` shows it (§8.11 step 5).
    pub(crate) fn wait_reset(
        &self,
        rx: std::sync::mpsc::Receiver<Result<(), KeyStoreError>>,
    ) -> Option<Result<(), KeyStoreError>> {
        let wait = lock(&self.state).wait_timeout;
        rx.recv_timeout(wait).ok()
    }

    /// Lifts any barrier and resets the retry state: a [`BarrierGuard`] releasing its own
    /// barrier, and the `testing` hook.
    pub(crate) fn clear_barrier(&self) {
        {
            let mut st = lock(&self.state);
            st.barrier = None;
            st.clear_failure();
        }
        self.cv.notify_all();
    }

    /// Synchronous flush (C.3): the keychain error of the attempt, if any. `Ok` when there is
    /// nothing to write (disabled, behind a restore barrier, already current).
    pub(crate) fn flush(&self) -> Result<(), AuditError> {
        let (tx, rx) = sync_channel(1);
        {
            let mut st = lock(&self.state);
            if st.stop || st.dead {
                return Err(st.unusable());
            }
            st.waiters.push(tx);
            st.flush_requested = true;
        }
        self.cv.notify_all();
        let wait = lock(&self.state).wait_timeout;
        match rx.recv_timeout(wait) {
            Ok(r) => r.map_err(AuditError::KeyStore),
            Err(RecvTimeoutError::Timeout) => Err(AuditError::AnchorFlushTimeout),
            Err(RecvTimeoutError::Disconnected) => Err(self.after_disconnect()),
        }
    }

    /// The restore completion step: writes both entries (on the anchor thread) and lifts the
    /// restore barrier. `head` must be at or past the barrier's `RESTORE` record.
    pub(crate) fn complete_restore(
        &self,
        head: HeadAnchor,
        first_retained: FirstRetainedAnchor,
    ) -> Result<(), AuditError> {
        let (reply, rx) = sync_channel(1);
        {
            let mut st = lock(&self.state);
            if st.stop || st.dead {
                return Err(st.unusable());
            }
            if head.chain_id != first_retained.chain_id {
                return Err(AuditError::Invalid("restore anchors name different chains"));
            }
            match &st.barrier {
                Some(Barrier::Restore { seq, reset: None }) if head.seq >= *seq => {}
                _ => {
                    return Err(AuditError::Invalid(
                        "no restore barrier for this head anchor",
                    ));
                }
            }
            if st.restore_job.is_some() {
                return Err(AuditError::Invalid("a restore completion is in progress"));
            }
            st.restore_job = Some(RestoreJob {
                head,
                first_retained,
                reply,
            });
        }
        self.cv.notify_all();
        let wait = lock(&self.state).wait_timeout;
        match rx.recv_timeout(wait) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => {
                // Take the job back if the thread never started it, so it cannot write and lift
                // the barrier after the caller was told it failed. If the thread already took it,
                // its write may still land: the outcome is unknown, and a retry sees no job.
                if lock(&self.state).restore_job.take().is_some() {
                    Err(AuditError::AnchorFlushTimeout)
                } else {
                    Err(AuditError::AnchorOutcomeUnknown)
                }
            }
            Err(RecvTimeoutError::Disconnected) => Err(self.after_disconnect()),
        }
    }

    pub(crate) fn health(&self) -> AnchorHealth {
        let st = lock(&self.state);
        AnchorHealth {
            write_failing: st.failures > 0 || st.dead,
            first_retained_pending: matches!(
                st.barrier,
                Some(Barrier::Prune { .. } | Barrier::Hold { .. })
            ),
            blocked: st.barrier.as_ref().map(Barrier::kind),
            thread_dead: st.dead,
        }
    }

    /// The thread dropped our reply sender: it stopped or panicked. Wait until it left, so the
    /// error says which.
    fn after_disconnect(&self) -> AuditError {
        let mut st = lock(&self.state);
        let end = Instant::now() + st.wait_timeout;
        while !st.exited {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            st = self
                .cv
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        st.unusable()
    }

    /// Stops the thread without a write; waiting callers get `Closed`. Waits at most the wait
    /// timeout for the thread to leave (a hung keychain call): `false` = it did not.
    pub(crate) fn stop(&self) -> bool {
        let mut st = lock(&self.state);
        st.stop = true;
        self.cv.notify_all();
        let end = Instant::now() + st.wait_timeout;
        while !st.exited {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            st = self
                .cv
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        true
    }
}

fn encode_err(_: AuditError) -> KeyStoreError {
    KeyStoreError::Other("anchor is not encodable".into())
}

fn set_head(keys: &dyn KeyStore, h: &HeadAnchor) -> Result<(), KeyStoreError> {
    keys.set(&EntryName::HeadAnchor, &h.to_entry().map_err(encode_err)?)
}

fn set_first_retained(keys: &dyn KeyStore, f: &FirstRetainedAnchor) -> Result<(), KeyStoreError> {
    keys.set(
        &EntryName::FirstRetainedAnchor,
        &f.to_entry().map_err(encode_err)?,
    )
}

fn answer(waiters: Vec<FlushReply>, r: &Result<(), KeyStoreError>) {
    for w in waiters {
        let _ = w.send(r.clone());
    }
}

/// The `audit-anchor` thread. `scale_div` shortens the retry backoff (tests only). A panic in
/// the loop (a misbehaving keychain backend) marks the state dead and releases every waiter, so
/// callers get `AnchorThreadDead` and `health()` reports it instead of hanging. Release builds
/// use `panic = "abort"` (§7.7), where a panic ends the process: this is defence in depth for
/// debug and test builds (unwinding) only.
pub(crate) fn run(shared: Arc<AnchorShared>, keys: Arc<dyn KeyStore>, scale_div: u32) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_loop(&shared, &*keys, scale_div);
    }));
    let mut st = lock(&shared.state);
    if r.is_err() {
        st.dead = true;
    }
    st.waiters.clear();
    st.reset_waiters.clear();
    st.restore_job = None;
    st.exited = true;
    drop(st);
    shared.cv.notify_all();
}

fn run_loop(shared: &AnchorShared, keys: &dyn KeyStore, scale_div: u32) {
    let mut st = lock(&shared.state);
    loop {
        let now = Instant::now();
        st.touch(now);
        if !st.work_due(now) {
            let w = st.next_wakeup(now);
            st = shared
                .cv
                .wait_timeout(st, w)
                .unwrap_or_else(|e| e.into_inner())
                .0;
            continue;
        }
        if st.stop {
            // Never a write on the way out; `flush` callers learn the store closed.
            break;
        }
        // A restore completion writes both entries on its own.
        if let Some(job) = st.restore_job.take() {
            drop(st);
            let r = set_first_retained(keys, &job.first_retained)
                .and_then(|()| set_head(keys, &job.head));
            st = lock(&shared.state);
            let reply = match r {
                Ok(()) => {
                    st.barrier = None;
                    // A published head newer than the restore head (same chain) stays the head
                    // and is anchored next; the keychain now holds the restore head.
                    let newer = matches!(&st.head, Some(h)
                        if h.chain_id == job.head.chain_id && h.seq > job.head.seq);
                    if !newer {
                        st.head = Some(job.head.clone());
                    }
                    st.written_head = Some(job.head);
                    st.dirty_since = None;
                    st.clear_failure();
                    Ok(())
                }
                Err(e) => {
                    st.failures = st.failures.saturating_add(1);
                    st.last_error = Some(e.clone());
                    Err(AuditError::KeyStore(e))
                }
            };
            let _ = job.reply.send(reply);
            continue;
        }
        // An armed restore completion: both entries, retried with backoff until it lands.
        if let Some(Barrier::Restore {
            seq: restore_seq,
            reset: Some(reset),
        }) = st.barrier.clone()
            && (st.flush_requested || st.retry_ok(Instant::now()))
        {
            drop(st);
            let r = set_first_retained(keys, &reset.first_retained)
                .and_then(|()| set_head(keys, &reset.head));
            st = lock(&shared.state);
            match &r {
                Ok(()) => {
                    // Only the barrier this write belonged to; it may have been replaced.
                    if matches!(&st.barrier, Some(Barrier::Restore { seq, reset: Some(_) })
                        if *seq == restore_seq)
                    {
                        st.barrier = None;
                    }
                    // As for the restore job: a newer head of the restored chain stays the
                    // head and is anchored next.
                    let newer = matches!(&st.head, Some(h)
                        if h.chain_id == reset.head.chain_id && h.seq > reset.head.seq);
                    if !newer {
                        st.head = Some(reset.head.clone());
                    }
                    st.written_head = Some(reset.head);
                    st.dirty_since = None;
                    st.clear_failure();
                }
                Err(e) => st.schedule_retry(e.clone(), Instant::now(), scale_div),
            }
            for w in std::mem::take(&mut st.reset_waiters) {
                let _ = w.send(r.clone());
            }
            if let Err(e) = r {
                // A flush behind a pending reset reports why the anchors are not written.
                st.flush_requested = false;
                answer(std::mem::take(&mut st.waiters), &Err(e));
            }
            continue;
        }
        let flushing = st.flush_requested;
        st.flush_requested = false;
        let waiters = std::mem::take(&mut st.waiters);
        if !st.enabled {
            answer(waiters, &Ok(()));
            continue;
        }
        let mut result: Result<(), KeyStoreError> = Ok(());
        // 1. A pending first-retained update (prune) comes first.
        if let Some(Barrier::Prune {
            seq: prune_seq,
            first_retained,
            ..
        }) = st.barrier.clone()
            && (flushing || st.retry_ok(Instant::now()))
        {
            drop(st);
            let r = set_first_retained(keys, &first_retained);
            st = lock(&shared.state);
            match r {
                Ok(()) => {
                    // Only the barrier this write belonged to; it may have been released.
                    if matches!(&st.barrier, Some(Barrier::Prune { seq, .. }) if *seq == prune_seq)
                    {
                        st.barrier = None;
                    }
                    st.clear_failure();
                }
                Err(e) => {
                    st.schedule_retry(e.clone(), Instant::now(), scale_div);
                    answer(waiters, &Err(e));
                    continue;
                }
            }
        }
        // 2. The head anchor up to the barrier-capped target, at most once per window.
        let now = Instant::now();
        if let Some(target) = st.head_stale()
            && (flushing || (st.dirty_for(now) >= st.window && st.retry_ok(now)))
        {
            drop(st);
            let r = set_head(keys, &target);
            st = lock(&shared.state);
            match r {
                Ok(()) => {
                    st.written_head = Some(target);
                    st.clear_failure();
                    // Commits during the write kept the window open: it restarts only if
                    // something newer than the written anchor remains.
                    st.dirty_since = st.head_stale().map(|_| Instant::now());
                }
                Err(e) => {
                    st.schedule_retry(e.clone(), Instant::now(), scale_div);
                    result = Err(e);
                }
            }
        }
        answer(waiters, &result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(seq: u64) -> HeadAnchor {
        HeadAnchor {
            chain_id: "c".into(),
            seq,
            record_hash: [seq as u8; 32],
        }
    }

    fn fr() -> FirstRetainedAnchor {
        FirstRetainedAnchor {
            chain_id: "c".into(),
            genesis_hash: [9; 32],
            first_retained_seq: 5,
            first_retained_prev_hash: [4; 32],
        }
    }

    fn state(enabled: bool, written: u64, head_seq: u64, dirty: Option<Instant>) -> AnchorState {
        let mut s = AnchorState::new();
        s.enabled = enabled;
        s.written_head = Some(head(written));
        s.head = Some(head(head_seq));
        s.dirty_since = dirty;
        s
    }

    #[test]
    fn backoff_sequence() {
        let v: Vec<u64> = (1..=9).map(|n| backoff(n).as_secs()).collect();
        assert_eq!(v, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
    }

    #[test]
    fn batch_window_gates_the_write() {
        let t0 = Instant::now();
        let s = state(true, 1, 7, Some(t0));
        assert!(!s.work_due(t0 + Duration::from_millis(899)));
        assert!(s.work_due(t0 + BATCH_WINDOW));
        assert_eq!(
            s.next_wakeup(t0 + Duration::from_millis(400)).as_millis(),
            500
        );
    }

    #[test]
    fn disabled_state_is_never_due() {
        let t0 = Instant::now();
        let s = state(false, 1, 7, Some(t0));
        assert!(s.flush_target().is_none());
        assert!(!s.work_due(t0 + Duration::from_secs(60)));
    }

    #[test]
    fn prune_barrier_caps_the_target_and_restore_blocks_it() {
        let t0 = Instant::now();
        let mut s = state(true, 1, 9, Some(t0));
        s.barrier = Some(Barrier::Prune {
            seq: 5,
            record_hash: [5; 32],
            first_retained: fr(),
        });
        assert_eq!(s.flush_target(), Some(head(5)));
        s.head = Some(head(4));
        assert_eq!(s.flush_target(), Some(head(4)));
        s.barrier = Some(Barrier::Restore {
            seq: 5,
            reset: None,
        });
        assert_eq!(s.flush_target(), None);
        assert!(!s.head_due(t0 + Duration::from_secs(5)));
    }

    #[test]
    fn retry_time_defers_work_but_not_a_flush() {
        let t0 = Instant::now();
        let mut s = state(true, 1, 7, Some(t0));
        s.schedule_retry(KeyStoreError::Unavailable, t0 + BATCH_WINDOW, 1);
        let now = t0 + BATCH_WINDOW;
        assert!(!s.work_due(now));
        assert!(s.work_due(now + Duration::from_secs(1)));
        s.flush_requested = true;
        assert!(s.work_due(now));
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;

    fn head(seq: u64) -> HeadAnchor {
        HeadAnchor {
            chain_id: "c".into(),
            seq,
            record_hash: [seq as u8; 32],
        }
    }

    fn fr() -> FirstRetainedAnchor {
        FirstRetainedAnchor {
            chain_id: "c".into(),
            genesis_hash: [9; 32],
            first_retained_seq: 5,
            first_retained_prev_hash: [4; 32],
        }
    }

    fn shared(enabled: bool) -> Arc<AnchorShared> {
        let a = Arc::new(AnchorShared::new());
        a.init(enabled, head(1), true, BATCH_WINDOW, DEFAULT_WAIT_TIMEOUT);
        a
    }

    #[test]
    fn first_commit_opens_a_window_that_ends_within_the_batch_window() {
        let a = shared(true);
        for seq in 2..=51 {
            a.publish_head(head(seq));
        }
        let st = lock(&a.state);
        let now = Instant::now();
        assert!(st.next_wakeup(now) <= BATCH_WINDOW);
        assert_eq!(st.head_stale(), Some(head(51)));
    }

    #[test]
    fn head_with_a_lower_seq_is_never_stale() {
        let mut s = AnchorState::new();
        s.enabled = true;
        s.written_head = Some(head(9));
        s.head = Some(head(4));
        assert_eq!(s.head_stale(), None);
        let other = HeadAnchor {
            chain_id: "d".into(),
            ..head(4)
        };
        s.head = Some(other.clone());
        assert_eq!(s.head_stale(), Some(other));
    }

    #[test]
    fn touch_opens_a_window_for_a_stale_head() {
        let mut s = AnchorState::new();
        s.enabled = true;
        s.written_head = Some(head(1));
        s.head = Some(head(3));
        assert!(s.dirty_since.is_none());
        let t0 = Instant::now();
        s.touch(t0);
        assert_eq!(s.dirty_since, Some(t0));
    }

    #[test]
    fn a_second_barrier_is_refused_and_the_guard_releases() {
        let a = shared(true);
        let g = a
            .install_barrier(Barrier::Restore {
                seq: 2,
                reset: None,
            })
            .expect("first barrier");
        assert!(matches!(
            a.install_barrier(Barrier::Prune {
                seq: 3,
                record_hash: [3; 32],
                first_retained: fr(),
            }),
            Err(AuditError::Invalid(_))
        ));
        assert_eq!(a.health().blocked, Some(BarrierKind::Restore));
        drop(g);
        assert_eq!(a.health().blocked, None);
        // Completed guards keep the barrier for the anchor thread to lift.
        let g = a
            .install_barrier(Barrier::Restore {
                seq: 2,
                reset: None,
            })
            .expect("again");
        g.complete();
        assert_eq!(a.health().blocked, Some(BarrierKind::Restore));
    }

    #[test]
    fn installing_a_barrier_resets_stale_retry_state() {
        let a = shared(true);
        {
            let mut st = lock(&a.state);
            st.schedule_retry(KeyStoreError::Unavailable, Instant::now(), 1);
        }
        assert!(a.health().write_failing);
        let _g = a
            .install_barrier(Barrier::Restore {
                seq: 2,
                reset: None,
            })
            .expect("barrier");
        assert!(!a.health().write_failing);
    }
}
