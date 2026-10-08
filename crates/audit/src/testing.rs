#![cfg(any(test, feature = "testing"))]
//! Test doubles: a controllable clock, an in-memory keyring with fault points, store fault
//! points and a free-space stub.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::admission::FreeSpaceProbe;
use crate::clock::{Clock, UtcInstant};
use crate::error::AuditError;
use crate::keystore::{EntryName, KeyStore, KeyStoreError, KeyringLocality, service_name};

pub use crate::prune::{PruneRow, effective_epochs, guarded_effective_epochs, prunable_prefix_len};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Wall and monotonic time that only move when a test says so.
pub struct FakeClock {
    wall: Mutex<UtcInstant>,
    mono: Mutex<Duration>,
}

impl FakeClock {
    pub fn new(start: UtcInstant) -> Self {
        FakeClock {
            wall: Mutex::new(start),
            mono: Mutex::new(Duration::ZERO),
        }
    }

    /// Both clocks move forward.
    pub fn advance(&self, d: Duration) {
        self.advance_wall_only(d);
        self.advance_mono_only(d);
    }

    pub fn advance_mono_only(&self, d: Duration) {
        *lock(&self.mono) += d;
    }

    pub fn advance_wall_only(&self, d: Duration) {
        lock(&self.wall).0 += d.as_millis() as i64;
    }

    pub fn set_wall(&self, t: UtcInstant) {
        *lock(&self.wall) = t;
    }

    /// Wall clock only; negative moves it backwards.
    pub fn jump_wall_days(&self, days: i64) {
        lock(&self.wall).0 += days * 86_400_000;
    }
}

impl Clock for FakeClock {
    fn now_utc(&self) -> UtcInstant {
        *lock(&self.wall)
    }

    fn suspend_aware_elapsed(&self) -> Duration {
        *lock(&self.mono)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOpKind {
    Get,
    Set,
    Delete,
}

/// One recorded keyring call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyOp {
    pub kind: KeyOpKind,
    pub full_name: String,
}

struct Fault {
    op: KeyOpKind,
    entry: Option<EntryName>,
    err: KeyStoreError,
    times: u32,
}

/// One shared keyring, like one daemon; several `MemKeyStore`s (installs) can use it.
pub struct MemKeyring {
    entries: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    faults: Mutex<Vec<Fault>>,
    unavailable: AtomicBool,
    corrupt_gets: AtomicU32,
    locality: Mutex<KeyringLocality>,
    log: Mutex<Vec<KeyOp>>,
}

impl MemKeyring {
    pub fn new() -> Arc<MemKeyring> {
        Arc::new(MemKeyring {
            entries: Mutex::new(BTreeMap::new()),
            faults: Mutex::new(Vec::new()),
            unavailable: AtomicBool::new(false),
            corrupt_gets: AtomicU32::new(0),
            locality: Mutex::new(KeyringLocality::Local),
            log: Mutex::new(Vec::new()),
        })
    }

    /// The next `times` calls of kind `op` (on `entry`, or on any entry if `None`) fail with `err`.
    pub fn fail_next(
        &self,
        op: KeyOpKind,
        entry: Option<EntryName>,
        err: KeyStoreError,
        times: u32,
    ) {
        lock(&self.faults).push(Fault {
            op,
            entry,
            err,
            times,
        });
    }

    /// Drops every pending `fail_next` fault.
    pub fn clear_faults(&self) {
        lock(&self.faults).clear();
    }

    /// Every operation fails with `Unavailable` while set.
    pub fn set_unavailable(&self, v: bool) {
        self.unavailable.store(v, Ordering::SeqCst);
    }

    /// The next `times` successful `get`s of an existing entry return other bytes.
    pub fn corrupt_next_gets(&self, times: u32) {
        self.corrupt_gets.store(times, Ordering::SeqCst);
    }

    pub fn set_locality(&self, l: KeyringLocality) {
        *lock(&self.locality) = l;
    }

    /// "Keychain wiped": removes every entry of the install.
    pub fn wipe_install(&self, install_id: &str) {
        let service = service_name(install_id);
        lock(&self.entries).retain(|(s, _), _| *s != service);
    }

    pub fn raw_get(&self, service: &str, account: &str) -> Option<Vec<u8>> {
        lock(&self.entries)
            .get(&(service.to_string(), account.to_string()))
            .cloned()
    }

    /// Every call so far (also failed ones), for "no keyring write" assertions.
    pub fn ops(&self) -> Vec<KeyOp> {
        lock(&self.log).clone()
    }

    fn check(&self, kind: KeyOpKind, install_id: &str, e: &EntryName) -> Result<(), KeyStoreError> {
        lock(&self.log).push(KeyOp {
            kind,
            full_name: e.full_name(install_id),
        });
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Unavailable);
        }
        let mut faults = lock(&self.faults);
        if let Some(f) = faults
            .iter_mut()
            .find(|f| f.times > 0 && f.op == kind && f.entry.as_ref().is_none_or(|x| x == e))
        {
            f.times -= 1;
            return Err(f.err.clone());
        }
        Ok(())
    }
}

/// One install's view of a [`MemKeyring`].
pub struct MemKeyStore {
    install_id: String,
    ring: Arc<MemKeyring>,
}

impl MemKeyStore {
    pub fn new(ring: Arc<MemKeyring>, install_id: &str) -> Self {
        MemKeyStore {
            install_id: install_id.to_string(),
            ring,
        }
    }

    fn key(&self, e: &EntryName) -> (String, String) {
        (service_name(&self.install_id), e.account())
    }
}

impl KeyStore for MemKeyStore {
    fn install_id(&self) -> &str {
        &self.install_id
    }

    fn get(&self, e: &EntryName) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        self.ring.check(KeyOpKind::Get, &self.install_id, e)?;
        let found = lock(&self.ring.entries).get(&self.key(e)).cloned();
        Ok(found.map(|mut v| {
            let corrupt = self
                .ring
                .corrupt_gets
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
            if corrupt {
                v.iter_mut().for_each(|b| *b ^= 0xA5);
            }
            Zeroizing::new(v)
        }))
    }

    fn set(&self, e: &EntryName, v: &[u8]) -> Result<(), KeyStoreError> {
        self.ring.check(KeyOpKind::Set, &self.install_id, e)?;
        lock(&self.ring.entries).insert(self.key(e), v.to_vec());
        Ok(())
    }

    fn delete(&self, e: &EntryName) -> Result<(), KeyStoreError> {
        self.ring.check(KeyOpKind::Delete, &self.install_id, e)?;
        lock(&self.ring.entries).remove(&self.key(e));
        Ok(())
    }

    fn locality(&self) -> KeyringLocality {
        lock(&self.ring.locality).clone()
    }
}

/// Where the store consults [`Faults`] (feature `testing` only; release builds have no hooks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    /// Inside the append transaction, after every row was inserted, before `COMMIT`.
    WriterBeforeCommit,
    /// Inside the append transaction, after each inserted row.
    WriterAfterRow,
    /// At the top of every writer command: blocks while [`Faults::pause_writer`] is in force.
    WriterPause,
    /// First run: after `GENESIS` committed and both anchors were written, before the rename.
    FirstRunBeforeRename,
    /// `open()` step 4: right after the startup `VERIFY` committed (or was not needed), before
    /// any anchor action or anchor write is allowed.
    AfterStartupVerifyAppend,
    /// Anchor writes are enabled (startup step 4, or `testing_enable_anchors`). Observation
    /// only: an armed failure is ignored.
    AnchorsEnabled,
    /// Inside the prune transaction, after the `PRUNE` row, before `COMMIT`.
    AfterPruneTxBeforeCommit,
    /// Right after the prune `COMMIT`: an armed failure stops the writer there (a simulated
    /// crash: no prune barrier, the new head is never published).
    AfterPruneCommit,
    /// "Recover this log": right after the recovery `VERIFY` and `KEY_RECOVERED` committed,
    /// before the KEK is re-sealed and the anchors are rebuilt. An armed failure ends the
    /// recovery there.
    AfterKeyRecoveredAppend,
}

/// Runs when a [`FaultPoint`] is reached (see [`Faults::on_hit`]).
type Observer = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct PauseState {
    requested: bool,
    paused: bool,
}

/// Injected failures and a writer pause, shared between a test and the store's [`crate::store::Hooks`].
pub struct Faults {
    armed: Mutex<HashMap<FaultPoint, (u32, u32)>>,
    observers: Mutex<HashMap<FaultPoint, Vec<Observer>>>,
    pause: Mutex<PauseState>,
    cv: Condvar,
}

impl Faults {
    pub fn new() -> Arc<Faults> {
        Arc::new(Faults {
            armed: Mutex::new(HashMap::new()),
            observers: Mutex::new(HashMap::new()),
            pause: Mutex::new(PauseState::default()),
            cv: Condvar::new(),
        })
    }

    /// The next `times` hits of `p` fail.
    pub fn fail(&self, p: FaultPoint, times: u32) {
        self.fail_after(p, 0, times);
    }

    /// The `skip` next hits of `p` pass, then `times` hits fail.
    pub fn fail_after(&self, p: FaultPoint, skip: u32, times: u32) {
        lock(&self.armed).insert(p, (skip, times));
    }

    /// `f` runs every time `p` is reached, before an armed failure of `p` is applied (tests
    /// snapshot state at that moment).
    pub fn on_hit(&self, p: FaultPoint, f: impl Fn() + Send + Sync + 'static) {
        lock(&self.observers)
            .entry(p)
            .or_default()
            .push(Arc::new(f));
    }

    /// From the next command on, the writer blocks at [`FaultPoint::WriterPause`].
    pub fn pause_writer(&self) {
        lock(&self.pause).requested = true;
    }

    /// Whether the writer is blocked in the pause within `timeout`.
    pub fn wait_writer_paused(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut st = lock(&self.pause);
        while !st.paused {
            let left = deadline.saturating_duration_since(Instant::now());
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

    pub fn resume_writer(&self) {
        lock(&self.pause).requested = false;
        self.cv.notify_all();
    }

    pub(crate) fn hit(&self, p: FaultPoint) -> Result<(), AuditError> {
        if p == FaultPoint::WriterPause {
            let mut st = lock(&self.pause);
            if st.requested {
                st.paused = true;
                self.cv.notify_all();
                while st.requested {
                    st = self.cv.wait(st).unwrap_or_else(|e| e.into_inner());
                }
                st.paused = false;
            }
            return Ok(());
        }
        let observers = lock(&self.observers).get(&p).cloned().unwrap_or_default();
        for f in observers {
            f();
        }
        let mut armed = lock(&self.armed);
        match armed.get_mut(&p) {
            Some((skip, _)) if *skip > 0 => {
                *skip -= 1;
                Ok(())
            }
            Some((_, times)) if *times > 0 => {
                *times -= 1;
                Err(AuditError::AppendFailed(format!("injected fault at {p:?}")))
            }
            _ => Ok(()),
        }
    }
}

/// A [`FreeSpaceProbe`] reporting a settable number of bytes, or an error.
pub struct FreeSpaceStub {
    bytes: AtomicU64,
    fail: AtomicBool,
}

impl FreeSpaceStub {
    pub fn new(bytes: u64) -> Arc<FreeSpaceStub> {
        Arc::new(FreeSpaceStub {
            bytes: AtomicU64::new(bytes),
            fail: AtomicBool::new(false),
        })
    }

    pub fn set(&self, bytes: u64) {
        self.bytes.store(bytes, Ordering::SeqCst);
    }

    /// While set, every probe returns an I/O error.
    pub fn set_failing(&self, v: bool) {
        self.fail.store(v, Ordering::SeqCst);
    }
}

impl FreeSpaceProbe for FreeSpaceStub {
    fn free_bytes(&self, _path: &Path) -> std::io::Result<u64> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("injected free-space probe failure"));
        }
        Ok(self.bytes.load(Ordering::SeqCst))
    }
}

/// Input of [`insert_fake_prune`]: the store-level effect of a prune without its rules, for
/// tamper tests that need prunes at chosen seqs (`Store::prune` is the real one).
#[derive(Debug, Clone)]
pub struct FakePrune {
    /// Records below it are deleted; the next `prune_log` row's range ends here.
    pub first_retained_seq: u64,
    /// `YYYY-MM-DD`.
    pub cutoff: String,
    /// The `PRUNE` payload's settings snapshot, e.g. `{"retention_days": 92, "legal_hold": false}`.
    pub settings: serde_json::Value,
    /// Install the prune barrier, so the anchor thread writes the first-retained anchor before
    /// the head passes the `PRUNE` (a real prune); `false` leaves the keychain untouched (a
    /// crash right after the commit).
    pub update_first_retained: bool,
}

/// One `prune_log` row and its `PRUNE` record in one transaction (crate-internal writer
/// command); no DEK is destroyed.
pub fn insert_fake_prune(
    store: &crate::store::Store,
    prune: FakePrune,
) -> Result<crate::types::Committed, AuditError> {
    store.testing_fake_prune(prune)
}

fn kek_from(keys: &dyn KeyStore) -> Result<crate::crypto::Kek, crate::error::OpenError> {
    use crate::error::OpenError;
    let b = keys
        .get(&EntryName::Kek)?
        .ok_or(OpenError::Invalid("the keychain holds no KEK"))?;
    crate::crypto::Kek::from_entry_bytes(&b)
        .map_err(|_| OpenError::Invalid("the keychain KEK is malformed"))
}

/// `open()` steps 1–3 without step 4: the version gate, the keychain cases and the startup
/// verdict, held in memory. Writes nothing but the keychain canary of the self-test. An outcome
/// other than a verdict is an error: `StoreNewer` → `NewerStore(found)`, `Locked` →
/// `KeyStore(Other(reason))`, no `audit.db` → `Io(NotFound)`.
pub fn startup_verdict(
    data: &atlas_duck_ipc::paths::LocalDataDir,
    cfg: &crate::store::OpenConfig,
) -> Result<crate::verify::StartupVerdict, crate::error::OpenError> {
    use crate::error::OpenError;
    use crate::open::{Preflight, StartupOutcome};
    match crate::open::preflight(data, cfg)? {
        Preflight::Verified { verdict, .. } => Ok(*verdict),
        Preflight::Stop(StartupOutcome::StoreNewer { found }) => Err(OpenError::NewerStore(found)),
        Preflight::Stop(StartupOutcome::Locked(r)) => {
            Err(OpenError::KeyStore(KeyStoreError::Other(r.as_str().into())))
        }
        Preflight::Stop(_) => Err(OpenError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "audit.db does not exist",
        ))),
    }
}

/// A store handle on an existing `audit.db` without startup verification (tamper tests that
/// need a handle on a store `open()` would flag): KEK from the keychain, writer started,
/// anchor writes disabled until [`apply_startup`].
pub fn open_existing(
    data: &atlas_duck_ipc::paths::LocalDataDir,
    lock: &crate::lock::InstanceLock,
    cfg: crate::store::OpenConfig,
) -> Result<crate::store::Store, crate::error::OpenError> {
    if lock.path().parent() != Some(data.path()) {
        return Err(crate::error::OpenError::Invalid(
            "instance.lock of another data dir",
        ));
    }
    let kek = kek_from(&*cfg.keys)?;
    let genesis_hash = crate::anchors::load_first_retained(&*cfg.keys)
        .ok()
        .flatten()
        .map(|f| f.genesis_hash);
    crate::open::start_existing(data, cfg, kek, genesis_hash)
}

/// `open()` step 4 for a verdict: its `VERIFY`, the anchor actions, then anchors enabled.
pub fn apply_startup(
    store: &crate::store::Store,
    verdict: &crate::verify::StartupVerdict,
) -> Result<crate::verify::VerifyOutcome, AuditError> {
    store.apply_startup(verdict)
}
