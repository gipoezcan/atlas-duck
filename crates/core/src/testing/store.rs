//! A real M2 store in a temp dir (Q4: `create_new_store` with the audit doubles) and
//! `FaultyAudit`, which fails chosen appends with the error the real writer returns for a
//! rolled-back append (`AuditError::AppendFailed`, Q2). If M2's store API changes, adapt this
//! file and `audit_port.rs` only.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::testing::{FakeClock, Faults, FreeSpaceStub, MemKeyStore, MemKeyring};
use atlas_duck_audit::{
    AuditError, Committed, Confirmed, EventFlags, EventHeader, EventType, FirstRunInput, Hooks,
    NewEvent, OpenConfig, QueryKind, ReconcileReport, SettingChange, Settings, Store, UtcInstant,
    create_new_store, new_ids,
};
use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};
use secrecy::SecretString;
use tempfile::TempDir;
use zeroize::Zeroizing;

use crate::audit_port::AuditPort;

pub type TestError = Box<dyn std::error::Error>;

/// The fake wall clock's start (the M2 tests' `START`).
pub const TEMP_STORE_START: &str = "2026-10-08T12:00:00.000Z";
/// 21 characters, above the 12-character minimum.
const PASSPHRASE: &str = "correct horse battery";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A first-run store (`GENESIS` committed) in its own temp data dir, with a fake clock, an
/// in-memory keyring and unlimited free space. Dropping it shuts the store down (every clone of
/// `store()` then answers `Closed`) before the directory is removed.
pub struct TempStore {
    store: Store,
    clock: Arc<FakeClock>,
    ring: Arc<MemKeyring>,
    free_space: Arc<FreeSpaceStub>,
    install_id: String,
    _lock: InstanceLock,
    dir: TempDir,
}

impl TempStore {
    pub fn new() -> Result<TempStore, TestError> {
        TempStore::with_hooks(Hooks::default())
    }

    /// With the store's own fault points (`FaultPoint::WriterBeforeCommit` etc.).
    pub fn with_faults(faults: Arc<Faults>) -> Result<TempStore, TestError> {
        TempStore::with_hooks(Hooks {
            faults: Some(faults),
            ..Hooks::default()
        })
    }

    /// An install of its own over a keyring that other installs share (Q4, I-43): its entries
    /// are scoped by its `install_id`.
    pub fn with_ring(ring: Arc<MemKeyring>) -> Result<TempStore, TestError> {
        TempStore::build(Hooks::default(), ring)
    }

    fn with_hooks(hooks: Hooks) -> Result<TempStore, TestError> {
        TempStore::build(hooks, MemKeyring::new())
    }

    fn build(hooks: Hooks, ring: Arc<MemKeyring>) -> Result<TempStore, TestError> {
        let dir = tempfile::tempdir()?;
        let data = match check_data_dir(dir.path())? {
            DataDirResolution::Local(d) => d,
            _ => return Err("the temp dir is not a local data dir".into()),
        };
        let lock = InstanceLock::acquire(&data, "testhost")?;
        let start = UtcInstant::parse_rfc3339_ms(TEMP_STORE_START).ok_or("bad TEMP_STORE_START")?;
        let clock = Arc::new(FakeClock::new(start));
        let free_space = FreeSpaceStub::new(u64::MAX);
        let (install_id, chain_id) = new_ids()?;
        let mut cfg = OpenConfig::new(
            clock.clone(),
            Arc::new(MemKeyStore::new(ring.clone(), &install_id)),
        );
        cfg.free_space = Some(free_space.clone());
        cfg.hooks = hooks;
        let store = create_new_store(
            &data,
            &lock,
            cfg,
            FirstRunInput {
                install_id: install_id.clone(),
                chain_id,
                passphrase: SecretString::from(PASSPHRASE.to_owned()),
                passphrase_confirm: SecretString::from(PASSPHRASE.to_owned()),
                archived_db: None,
            },
        )?;
        Ok(TempStore {
            store,
            clock,
            ring,
            free_space,
            install_id,
            _lock: lock,
            dir,
        })
    }

    pub fn store(&self) -> Store {
        self.store.clone()
    }

    pub fn port(&self) -> Arc<dyn AuditPort> {
        Arc::new(self.store.clone())
    }

    pub fn clock(&self) -> &Arc<FakeClock> {
        &self.clock
    }

    pub fn ring(&self) -> &Arc<MemKeyring> {
        &self.ring
    }

    /// Free bytes the admission check sees (`set(..)` low to get `StorageLow`).
    pub fn free_space(&self) -> &Arc<FreeSpaceStub> {
        &self.free_space
    }

    pub fn install_id(&self) -> &str {
        &self.install_id
    }

    pub fn data_dir(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        self.store.shutdown();
    }
}

/// Which appends `FaultyAudit` fails. Every event that reaches `append`/`append_batch` counts
/// as one attempt of its type, failed ones included, so "the Nth `REQUEST_RECEIVED`" fails once
/// and the next attempt goes through.
#[derive(Debug, Default)]
pub struct FaultPlan {
    nth: Mutex<HashMap<EventType, BTreeSet<u32>>>,
    seen: Mutex<HashMap<EventType, u32>>,
    fail_all: AtomicBool,
    /// Event types whose committed payloads read back tampered (`tamper_released_text`).
    tamper: Mutex<BTreeSet<EventType>>,
    tampered_seqs: Mutex<BTreeSet<u64>>,
    /// Committed rows whose payload this port cannot decrypt (`fail_read_payload`).
    unreadable: Mutex<BTreeSet<u64>>,
    /// While on, every committed `append`/`append_batch` call is kept (`appends`).
    recording: AtomicBool,
    calls: Mutex<Vec<Vec<RecordedEvent>>>,
}

/// One event of a committed `append`/`append_batch` call, as the port was handed it.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordedEvent {
    pub event_type: EventType,
    pub request_id: Option<String>,
    pub flags: EventFlags,
    pub payload: serde_json::Value,
}

impl RecordedEvent {
    fn of(ev: &NewEvent) -> RecordedEvent {
        RecordedEvent {
            event_type: ev.event_type,
            request_id: ev.request_id.clone(),
            flags: ev.flags,
            payload: ev.payload.clone(),
        }
    }
}

impl FaultPlan {
    pub fn new() -> Arc<FaultPlan> {
        Arc::new(FaultPlan::default())
    }

    /// The `n`-th (1-based) append attempt of `t` fails; a batch containing it fails whole.
    pub fn fail_nth(&self, t: EventType, n: u32) {
        lock(&self.nth).entry(t).or_default().insert(n);
    }

    /// While on, every `append`, `append_batch` and `apply_setting` fails.
    pub fn fail_all(&self, on: bool) {
        self.fail_all.store(on, Ordering::SeqCst);
    }

    /// Append attempts of `t` seen so far.
    pub fn attempts(&self, t: EventType) -> u32 {
        lock(&self.seen).get(&t).copied().unwrap_or(0)
    }

    /// From now on, every committed `append` / `append_batch` call is kept with its events in
    /// order (L43: "one audit transaction"). Off by default: payloads are cloned.
    pub fn record_appends(&self, on: bool) {
        self.recording.store(on, Ordering::SeqCst);
    }

    /// The committed calls recorded so far, oldest first; one `Vec` per call.
    pub fn appends(&self) -> Vec<Vec<RecordedEvent>> {
        lock(&self.calls).clone()
    }

    fn note_call(&self, evs: Vec<RecordedEvent>) {
        lock(&self.calls).push(evs);
    }

    /// The payload of row `seq` can no longer be decrypted through this port
    /// (`AuditError::Invalid`), as a corrupted row would fail (RF-4 seeding skips it).
    pub fn fail_read_payload(&self, seq: u64) {
        lock(&self.unreadable).insert(seq);
    }

    /// Records of `t` committed from now on read back with one letter of their
    /// `released.text` changed (a record altered after commit; inv. 2 at delivery). The stored
    /// record is untouched; only `read_payload` through this port sees the change.
    pub fn tamper_released_text(&self, t: EventType) {
        lock(&self.tamper).insert(t);
    }

    fn note_committed(&self, t: EventType, seq: u64) {
        if lock(&self.tamper).contains(&t) {
            lock(&self.tampered_seqs).insert(seq);
        }
    }

    /// The payload as a tampering reader would see it.
    fn tampered(&self, seq: u64, bytes: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
        if !lock(&self.tampered_seqs).contains(&seq) {
            return bytes;
        }
        let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return bytes;
        };
        if let Some(text) = v.pointer_mut("/released/text")
            && let Some(s) = text.as_str()
        {
            let changed: String = {
                let mut done = false;
                s.chars()
                    .map(|c| {
                        if !done && c.is_ascii_lowercase() {
                            done = true;
                            c.to_ascii_uppercase()
                        } else {
                            c
                        }
                    })
                    .collect()
            };
            *text = serde_json::Value::String(changed);
        }
        Zeroizing::new(serde_json::to_vec(&v).unwrap_or_default())
    }

    /// Counts the attempts and decides before anything reaches the store.
    fn check<'a>(&self, types: impl IntoIterator<Item = &'a NewEvent>) -> Result<(), AuditError> {
        let nth = lock(&self.nth);
        let mut seen = lock(&self.seen);
        let mut hit = None;
        for ev in types {
            let n = seen.entry(ev.event_type).or_insert(0);
            *n += 1;
            if hit.is_none() && nth.get(&ev.event_type).is_some_and(|s| s.contains(n)) {
                hit = Some((ev.event_type, *n));
            }
        }
        if let Some((t, n)) = hit {
            return Err(AuditError::AppendFailed(format!(
                "injected failure of {} attempt {n}",
                t.as_str()
            )));
        }
        self.check_switch()
    }

    fn check_switch(&self) -> Result<(), AuditError> {
        if self.fail_all.load(Ordering::SeqCst) {
            return Err(AuditError::AppendFailed("injected failure (switch)".into()));
        }
        Ok(())
    }
}

/// An `AuditPort` that fails appends per its `FaultPlan` and forwards everything else. A failed
/// append never reaches the wrapped port, so nothing is committed (as with a real rollback).
pub struct FaultyAudit {
    inner: Arc<dyn AuditPort>,
    plan: Arc<FaultPlan>,
}

impl FaultyAudit {
    pub fn wrap(inner: Arc<dyn AuditPort>, plan: Arc<FaultPlan>) -> FaultyAudit {
        FaultyAudit { inner, plan }
    }

    pub fn plan(&self) -> &Arc<FaultPlan> {
        &self.plan
    }
}

impl AuditPort for FaultyAudit {
    fn append(&self, ev: NewEvent) -> Result<Committed, AuditError> {
        self.plan.check([&ev])?;
        let t = ev.event_type;
        let recorded = self
            .plan
            .recording
            .load(Ordering::SeqCst)
            .then(|| vec![RecordedEvent::of(&ev)]);
        let c = self.inner.append(ev)?;
        self.plan.note_committed(t, c.seq);
        if let Some(r) = recorded {
            self.plan.note_call(r);
        }
        Ok(c)
    }

    fn append_batch(&self, evs: Vec<NewEvent>) -> Result<Vec<Committed>, AuditError> {
        self.plan.check(&evs)?;
        let types: Vec<EventType> = evs.iter().map(|e| e.event_type).collect();
        let recorded = self
            .plan
            .recording
            .load(Ordering::SeqCst)
            .then(|| evs.iter().map(RecordedEvent::of).collect::<Vec<_>>());
        let cs = self.inner.append_batch(evs)?;
        for (t, c) in types.iter().zip(&cs) {
            self.plan.note_committed(*t, c.seq);
        }
        if let Some(r) = recorded {
            self.plan.note_call(r);
        }
        Ok(cs)
    }

    fn admission_check(&self) -> Result<(), AuditError> {
        self.inner.admission_check()
    }

    fn query_tag(&self, kind: QueryKind, query: &str) -> String {
        self.inner.query_tag(kind, query)
    }

    fn read_payload(&self, seq: u64) -> Result<Zeroizing<Vec<u8>>, AuditError> {
        if lock(&self.plan.unreadable).contains(&seq) {
            return Err(AuditError::Invalid(
                "payload cannot be decrypted (test hook)",
            ));
        }
        self.inner
            .read_payload(seq)
            .map(|b| self.plan.tampered(seq, b))
    }

    fn headers_for_request(&self, request_id: &str) -> Result<Vec<EventHeader>, AuditError> {
        self.inner.headers_for_request(request_id)
    }

    fn recent_headers(&self, since: Duration) -> Result<Vec<EventHeader>, AuditError> {
        self.inner.recent_headers(since)
    }

    fn reconcile_after_crash(&self) -> Result<ReconcileReport, AuditError> {
        self.inner.reconcile_after_crash()
    }

    fn observe_server_date(&self, instance_id: &str, d: SystemTime, at: Instant) {
        self.inner.observe_server_date(instance_id, d, at)
    }

    fn settings(&self) -> Settings {
        self.inner.settings()
    }

    fn apply_setting(
        &self,
        c: SettingChange,
        confirmed: Option<Confirmed>,
    ) -> Result<Committed, AuditError> {
        self.plan.check_switch()?;
        self.inner.apply_setting(c, confirmed)
    }

    fn flush_head_anchor(&self) -> Result<(), AuditError> {
        self.inner.flush_head_anchor()
    }
}
