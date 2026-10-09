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
    AuditError, Committed, Confirmed, EventHeader, EventType, FirstRunInput, Hooks, NewEvent,
    OpenConfig, QueryKind, ReconcileReport, SettingChange, Settings, Store, UtcInstant,
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

    fn with_hooks(hooks: Hooks) -> Result<TempStore, TestError> {
        let dir = tempfile::tempdir()?;
        let data = match check_data_dir(dir.path())? {
            DataDirResolution::Local(d) => d,
            _ => return Err("the temp dir is not a local data dir".into()),
        };
        let lock = InstanceLock::acquire(&data, "testhost")?;
        let start = UtcInstant::parse_rfc3339_ms(TEMP_STORE_START).ok_or("bad TEMP_STORE_START")?;
        let clock = Arc::new(FakeClock::new(start));
        let ring = MemKeyring::new();
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
        self.inner.append(ev)
    }

    fn append_batch(&self, evs: Vec<NewEvent>) -> Result<Vec<Committed>, AuditError> {
        self.plan.check(&evs)?;
        self.inner.append_batch(evs)
    }

    fn admission_check(&self) -> Result<(), AuditError> {
        self.inner.admission_check()
    }

    fn query_tag(&self, kind: QueryKind, query: &str) -> String {
        self.inner.query_tag(kind, query)
    }

    fn read_payload(&self, seq: u64) -> Result<Zeroizing<Vec<u8>>, AuditError> {
        self.inner.read_payload(seq)
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
