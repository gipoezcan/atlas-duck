#![cfg(any(test, feature = "testing"))]
//! Test doubles: a controllable clock, an in-memory keyring with fault points, store fault
//! points and a free-space stub.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
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

    /// As `OsKeyStore`: `None` for anything but an install id.
    fn for_install(&self, install_id: &str) -> Option<Box<dyn KeyStore>> {
        crate::open::is_id(install_id)
            .then(|| Box::new(MemKeyStore::new(self.ring.clone(), install_id)) as Box<dyn KeyStore>)
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
    /// "Recover this log": both anchors were rebuilt, the KEK is not re-sealed yet (a crash
    /// there leaves the keychain lost). An armed failure ends the recovery there.
    AfterRecoveryAnchors,
    /// Restore: the commit rename happened; an armed failure makes the data dir sync after it
    /// fail (a post-commit error, never "nothing replaced").
    CommitDirSync,
    /// Restore: right after the "RESTORE commit" (the staging file renamed to `audit.db`),
    /// before the KEK is re-sealed. An armed failure is a crash there: the restore stops and a
    /// live store's writer stops with it.
    AfterRestoreCommit,
    /// Restore: the KEK is re-sealed, the anchors are not reset yet. An armed failure is a
    /// crash there, as for `AfterRestoreCommit`.
    AfterKekReseal,
    /// Export: every file is written and flushed, `manifest.json` last; the `EXPORT` record is
    /// not appended yet. An armed failure fails that append.
    ExportBeforeAppend,
    /// Export: at the top of each row of a batch, before the row's cancel check. An armed
    /// failure ends the export there.
    ExportRow,
    /// Recovery-passphrase change: inside its transaction, after the `recovery` row was
    /// rewritten and before its `CREDENTIAL_CHANGED` is inserted. An armed failure rolls both back.
    RecoveryRowWritten,
    /// Re-anchor: its full verification ran, nothing is logged or read for the rewrite yet. An
    /// armed failure ends the re-anchor there.
    ReAnchorVerified,
    /// Re-anchor: its `re_anchored` `VERIFY` committed and the anchors to write are read; the
    /// completion is not handed to the anchor thread yet. An armed failure ends it there.
    ReAnchorBeforeComplete,
    /// Restore (live store): its barrier replaced whatever was installed; the keychain is not
    /// read yet and nothing is committed. An armed failure fails the restore there.
    RestoreBarrierHeld,
    /// Restore (both entry points): the restore completed (KEK re-sealed, anchor reset armed);
    /// its confirmation record (`CONFIG_CHANGED {key: restore_backup}`) is not appended yet. An
    /// armed failure fails that append.
    RestoreConfirmationAppend,
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

/// Every rename [`durable_rename`] made in this process, in order (one process runs many tests
/// in parallel: [`durable_renames_into`] keeps a test's own).
static DURABLE_RENAMES: Mutex<Vec<(PathBuf, PathBuf)>> = Mutex::new(Vec::new());

pub(crate) fn record_durable_rename(from: &Path, to: &Path) {
    lock(&DURABLE_RENAMES).push((from.to_path_buf(), to.to_path_buf()));
}

/// The `(from, to)` of every rename `durable_rename` made whose target lies under `dir`, in
/// order: call-site tests (restore commit, first run, archive).
pub fn durable_renames_into(dir: &Path) -> Vec<(PathBuf, PathBuf)> {
    lock(&DURABLE_RENAMES)
        .iter()
        .filter(|(_, to)| to.starts_with(dir))
        .cloned()
        .collect()
}

/// Directories whose flush (`sync_dir`) fails; a flush of a directory under one of them fails.
static SYNC_DIR_FAULTS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

pub(crate) fn sync_dir_fault(dir: &Path) -> bool {
    lock(&SYNC_DIR_FAULTS).iter().any(|p| dir.starts_with(p))
}

/// From now on the directory flush fails for `dir` and everything below it (a FAT stick, a
/// share or a drop folder that refuses it). Scoped by path: parallel tests are not affected.
pub fn fail_sync_dir_under(dir: &Path) {
    lock(&SYNC_DIR_FAULTS).push(dir.to_path_buf());
}

/// Directories under which the removal of a failed export's staging directory fails.
static REMOVE_DIR_FAULTS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

pub(crate) fn remove_dir_fault(dir: &Path) -> bool {
    lock(&REMOVE_DIR_FAULTS).iter().any(|p| dir.starts_with(p))
}

/// From now on a failed export cannot remove its staging directory under `dir` (a scanner holds
/// a file in it). Only the directory removal fails: `manifest.json` is still unlinked first.
/// Scoped by path: parallel tests are not affected.
pub fn fail_remove_dir_under(dir: &Path) {
    lock(&REMOVE_DIR_FAULTS).push(dir.to_path_buf());
}

/// The store's rename (Windows: `MoveFileExW` with `MOVEFILE_WRITE_THROUGH`).
pub fn durable_rename(from: &Path, to: &Path) -> std::io::Result<()> {
    crate::open::durable_rename(from, to)
}

/// The `MoveFileExW` flags `durable_rename` passes.
#[cfg(windows)]
pub fn durable_move_flags() -> u32 {
    crate::open::DURABLE_MOVE_FLAGS
}

/// The Windows directory flush with an injected opener: `open(dir, flags)` returns the handle
/// that is flushed.
#[cfg(windows)]
pub fn sync_dir_with(
    dir: &Path,
    open: &dyn Fn(&Path, u32) -> std::io::Result<std::fs::File>,
) -> std::io::Result<()> {
    crate::open::sync_dir_with(dir, open)
}

/// The opener the Windows directory flush uses: `path` with `flags` as its
/// `dwFlagsAndAttributes`.
#[cfg(windows)]
pub fn open_dir_handle(path: &Path, flags: u32) -> std::io::Result<std::fs::File> {
    crate::open::open_dir_handle(path, flags)
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

/// The `recovery` row of the store in `data` as stored (`blob`, `created_at`), read on a read-only
/// connection: for "the row is byte-identical" assertions (I-34). `None` without a row.
pub fn recovery_row(
    data: &atlas_duck_ipc::paths::LocalDataDir,
) -> Result<Option<(Vec<u8>, String)>, crate::error::OpenError> {
    use rusqlite::OptionalExtension;
    let conn = crate::schema::open_peek(&crate::schema::db_path(data))?;
    conn.query_row(
        "SELECT blob, created_at FROM recovery WHERE id = 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
    .map_err(crate::open::sql)
}

/// The plaintext `event_type` of every record of the store in `data`, in `seq` order, read on a
/// read-only connection (no KEK): for "no second `GENESIS`" assertions (I-34).
pub fn event_types(
    data: &atlas_duck_ipc::paths::LocalDataDir,
) -> Result<Vec<String>, crate::error::OpenError> {
    let conn = crate::schema::open_peek(&crate::schema::db_path(data))?;
    let mut stmt = conn
        .prepare("SELECT event_type FROM events ORDER BY seq")
        .map_err(crate::open::sql)?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(crate::open::sql)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(crate::open::sql)
}

/// `open()` step 4 for a verdict: its `VERIFY`, the anchor actions, then anchors enabled.
pub fn apply_startup(
    store: &crate::store::Store,
    verdict: &crate::verify::StartupVerdict,
) -> Result<crate::verify::VerifyOutcome, AuditError> {
    store.apply_startup(verdict)
}

/// The compliance-export fixtures of S-03 (T8; used by T28's CLI flow and T31's AppImage step).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureKind {
    /// An honest export: exit 0 with its `manifest_sha256`.
    Pass,
    /// One row of `events.jsonl` changed after the export: exit 21 with the `manifest_sha256`.
    Tamper,
    /// An honest export verified without a trust root: exit 20.
    NoTrustRoot,
    /// An honest export of a store that had an anchor dir: exit 0 with the `manifest_sha256` and
    /// `anchor_dir` together (both trust roots).
    PassWithAnchorDir,
}

/// The anchor dir [`FixtureKind::PassWithAnchorDir`] leaves next to the export.
const ANCHOR_DIR_NAME: &str = "atlas-duck-fixture-anchors";

/// A fixture [`export_fixture`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureInfo {
    /// The export directory (inside the `out` given).
    pub dir: PathBuf,
    /// The anchor dir the store wrote its lines to (inside `out`, next to `dir`): `Some` for
    /// [`FixtureKind::PassWithAnchorDir`] only.
    pub anchor_dir: Option<PathBuf>,
    /// SHA-256 of the honest `manifest.json` (what `EXPORT` logged).
    pub manifest_sha256: [u8; 32],
    /// What `verify-export` exits with: with `--manifest-sha256` for `Pass` and `Tamper`,
    /// without any trust root for `NoTrustRoot`.
    pub expected_exit: u8,
}

/// Writes an export fixture of `kind` into the existing directory `out`: a throwaway store
/// (in-memory keyring, fixed clock) in `out/atlas-duck-fixture-store` with a few records of
/// several kinds, its full-range export, then the store is closed and its directory removed.
/// The generated files are never committed (`tests/fixtures/export/*/README.md`).
pub fn export_fixture(kind: FixtureKind, out: &Path) -> std::io::Result<FixtureInfo> {
    use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};
    use serde_json::json;

    use crate::request_set::{RequestRecord, request_set_hash, requests_to_json};
    use crate::types::{EventType, ExportControl, NewEvent, RustChosenPath, TimeRange};

    /// Removes the store directory it created when dropped (an early error included); declared
    /// before the store and its lock, so it drops after them (T8 review M-8).
    struct RemoveOnDrop(Option<PathBuf>);
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            if let Some(d) = self.0.take() {
                let _ = std::fs::remove_dir_all(d);
            }
        }
    }

    let fail = |what: &str| std::io::Error::other(format!("export fixture: {what}"));
    let store_dir = out.join("atlas-duck-fixture-store");
    // An existing entry of that name is never ours to remove.
    std::fs::create_dir(&store_dir)?;
    let mut cleanup = RemoveOnDrop(Some(store_dir.clone()));
    // The anchor dir outlives the store (it is what `verify-export --anchor-dir` reads); it is
    // removed only when the fixture fails.
    let anchor = (kind == FixtureKind::PassWithAnchorDir).then(|| out.join(ANCHOR_DIR_NAME));
    let mut anchor_cleanup = RemoveOnDrop(None);
    if let Some(a) = &anchor {
        std::fs::create_dir(a)?;
        anchor_cleanup.0 = Some(a.clone());
    }
    let data = match check_data_dir(&store_dir) {
        Ok(DataDirResolution::Local(d)) => d,
        _ => return Err(fail("the store directory is not a local data dir")),
    };
    let lock = crate::lock::InstanceLock::acquire(&data, "fixture-host")
        .map_err(|_| fail("instance.lock"))?;
    let (install_id, chain_id) = crate::open::new_ids().map_err(|_| fail("ids"))?;
    let start =
        UtcInstant::parse_rfc3339_ms("2026-10-08T12:00:00.000Z").ok_or_else(|| fail("clock"))?;
    let cfg = crate::store::OpenConfig::new(
        Arc::new(FakeClock::new(start)),
        Arc::new(MemKeyStore::new(MemKeyring::new(), &install_id)),
    );
    let pass = secrecy::SecretString::from("export fixture passphrase".to_string());
    let store = crate::open::create_new_store(
        &data,
        &lock,
        cfg,
        crate::open::FirstRunInput {
            install_id,
            chain_id,
            passphrase: pass.clone(),
            passphrase_confirm: pass,
            archived_db: None,
            anchor_dir: None,
            archive_confirmed: None,
        },
    )
    .map_err(|_| fail("create the store"))?;
    let ev = |t: EventType, payload: serde_json::Value| NewEvent {
        event_type: t,
        request_id: Some("fixture-request".into()),
        op_id: None,
        op_class: None,
        instance_id: None,
        target: None,
        actor: Default::default(),
        decision: None,
        flags: Default::default(),
        payload,
    };
    let requests = vec![RequestRecord {
        index: 0,
        method: "POST".into(),
        resolved_url: "https://jira.example/rest/api/2/issue".into(),
        content_type: Some("application/json".into()),
        body_bytes: b"{\"fields\":{}}".to_vec(),
    }];
    // The anchor dir of `PassWithAnchorDir`: its `CONFIG_CHANGED anchor_dir` row (seq 2) has an
    // immediate line; the rows after it are covered by the manifest hash only.
    if let Some(anchor) = &anchor {
        store
            .change_anchor_dir(
                Some(RustChosenPath::from_native_dialog(anchor.clone())),
                crate::types::Confirmed {
                    dialog_text_sha256: [7; 32],
                },
            )
            .map_err(|_| fail("anchor dir"))?;
    }
    let events = vec![
        ev(EventType::REQUEST_RECEIVED, json!({"op": "jira.search"})),
        ev(EventType::READ_FETCHED, json!({"status": 200, "body": "x"})),
        ev(EventType::READ_RELEASED, json!({"summary": "one issue"})),
        ev(EventType::DELIVERED, json!({"ok": true})),
        ev(
            EventType::WRITE_APPROVED,
            json!({
                "candidate_rev": 1,
                "request_set_hash": hex::encode(request_set_hash(&requests)),
                "requests": requests_to_json(&requests),
            }),
        ),
    ];
    let exported = store
        .append_batch(events)
        .map_err(|_| fail("append"))
        .and_then(|_| {
            // The lines of the rows above are in the anchor dir before the export reads it.
            if anchor.is_some() && !store.testing_anchor_dir_drain() {
                return Err(fail("anchor-dir lines not written"));
            }
            let cancel = AtomicBool::new(false);
            let progress = |_: u64, _: u64| {};
            store
                .export(
                    TimeRange::all(),
                    RustChosenPath::from_native_dialog(out.to_path_buf()),
                    &ExportControl {
                        progress: &progress,
                        cancel: &cancel,
                    },
                )
                .map_err(|_| fail("export"))
        });
    store.shutdown();
    drop(store);
    drop(lock);
    cleanup.0 = None;
    std::fs::remove_dir_all(&store_dir)?;
    let receipt = exported?;
    anchor_cleanup.0 = None;
    let dir = out.join(&receipt.dir_name);
    if kind == FixtureKind::Tamper {
        let events = dir.join(crate::export::EVENTS_FILE);
        let text = std::fs::read(&events)?;
        let mut lines: Vec<serde_json::Value> = text
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(serde_json::from_slice)
            .collect::<Result<_, _>>()
            .map_err(|_| fail("read events.jsonl"))?;
        let row = lines.get_mut(2).ok_or_else(|| fail("too few rows"))?;
        row["target"] = json!("tampered");
        let mut text = Vec::new();
        for l in &lines {
            text.extend(
                atlas_duck_ipc::jcs::to_jcs_vec(l).map_err(|_| fail("encode events.jsonl"))?,
            );
            text.push(b'\n');
        }
        std::fs::write(&events, text)?;
    }
    Ok(FixtureInfo {
        dir,
        anchor_dir: anchor,
        manifest_sha256: receipt.manifest_sha256,
        expected_exit: match kind {
            FixtureKind::Pass | FixtureKind::PassWithAnchorDir => 0,
            FixtureKind::Tamper => 21,
            FixtureKind::NoTrustRoot => 20,
        },
    })
}

// ---- M14 T19: an in-memory server anchor sequence and its excerpt ---------------------------

/// One row of an [`AnchorSeq`].
struct SeqRow {
    seq: u64,
    ts_utc: String,
    kind: String,
    body: Vec<u8>,
    prev: [u8; 32],
    hash: [u8; 32],
    entry: Option<crate::server_anchor::LeafEntry>,
}

/// A server anchor chain built in memory (v2 rows), to write excerpts the way the server's
/// export job does (PD-253) without a server.
#[derive(Default)]
pub struct AnchorSeq {
    rows: Vec<SeqRow>,
}

impl AnchorSeq {
    pub fn new() -> Self {
        AnchorSeq::default()
    }

    fn push(
        &mut self,
        kind: &str,
        body: Vec<u8>,
        entry: Option<crate::server_anchor::LeafEntry>,
    ) -> u64 {
        let seq = self.rows.len() as u64 + 1;
        let prev = self
            .rows
            .last()
            .map_or(crate::server_anchor::GENESIS_PREV, |r| r.hash);
        let ts_utc = format!("2026-10-27T10:{:02}:{:02}.000Z", (seq / 60) % 60, seq % 60);
        let hash = crate::server_anchor::row_hash(seq, &ts_utc, kind, &body, &prev);
        self.rows.push(SeqRow {
            seq,
            ts_utc,
            kind: kind.to_owned(),
            body,
            prev,
            hash,
            entry,
        });
        seq
    }

    /// An operational row (its body never goes into an excerpt).
    pub fn op(&mut self, kind: &str) -> u64 {
        let body = format!("{{\"n\":{}}}", self.rows.len() + 1).into_bytes();
        self.push(kind, body, None)
    }

    /// A `HEADS` row with `others` other users' leaves and, when given, the leaf of
    /// `(user_id, chain_id, head_seq, record_hash)`.
    pub fn heads(&mut self, mine: Option<(&str, &str, u64, [u8; 32])>, others: usize) -> u64 {
        use crate::server_anchor::{LeafEntry, heads_body_jcs, leaf_hash};
        let n = self.rows.len() as u64 + 1;
        let mut leaves: Vec<[u8; 32]> = (0..others)
            .map(|i| leaf_hash(&format!("other{i}"), "c-other", n, &[0x5a; 32]))
            .collect();
        let my_leaf = mine.map(|(u, c, s, h)| (leaf_hash(u, c, s, &h), (u, c, s, h)));
        if let Some((l, _)) = &my_leaf {
            leaves.push(*l);
        }
        let body = heads_body_jcs(&leaves).unwrap_or_default();
        let mut sorted: Vec<[u8; 32]> = leaves;
        // Lowercase hex sorts like the bytes.
        sorted.sort();
        let entry = my_leaf.map(|(l, (u, c, s, h))| LeafEntry {
            user_id: u.to_owned(),
            chain_id: c.to_owned(),
            head_seq: s,
            record_hash: h,
            leaf_index: sorted.iter().position(|x| *x == l).unwrap_or(0) as u64,
        });
        self.push("HEADS", body, entry)
    }

    /// The last row: `(seq, hash)`.
    pub fn head(&self) -> (u64, [u8; 32]) {
        self.rows
            .last()
            .map_or((0, crate::server_anchor::GENESIS_PREV), |r| (r.seq, r.hash))
    }

    /// The excerpt lines of `[first, last]`: full where a leaf entry is, opaque elsewhere.
    pub fn lines(&self, first: u64, last: u64) -> Vec<Vec<u8>> {
        self.rows
            .iter()
            .filter(|r| (first..=last).contains(&r.seq))
            .map(|r| {
                crate::server_anchor::excerpt_line_jcs(
                    r.seq,
                    &r.ts_utc,
                    &r.kind,
                    &r.body,
                    &r.prev,
                    &r.hash,
                    r.entry.as_ref().map(Some),
                )
            })
            .collect()
    }

    /// The excerpt manifest of `[first, last]` for `chain_id`.
    pub fn manifest(
        &self,
        first: u64,
        last: u64,
        chain_id: &str,
    ) -> crate::server_anchor::ExcerptManifest {
        let last_hash = self
            .rows
            .iter()
            .find(|r| r.seq == last)
            .map_or([0; 32], |r| r.hash);
        crate::server_anchor::ExcerptManifest {
            format: crate::server_anchor::EXCERPT_FORMAT.to_owned(),
            issuer: "https://duck.example.test".to_owned(),
            first_seq: first,
            last_seq: last,
            last_hash: hex::encode(last_hash),
            chain_id: chain_id.to_owned(),
        }
    }

    /// Writes `anchor-chain.jsonl` and `anchor-chain.manifest.json` of `[first, last]` into `dir`.
    pub fn write(&self, dir: &Path, first: u64, last: u64, chain_id: &str) -> std::io::Result<()> {
        write_excerpt(
            dir,
            &self.lines(first, last),
            &self.manifest(first, last, chain_id),
        )
    }
}

/// Writes excerpt `lines` (each ended by a newline) and `manifest` into `dir`.
pub fn write_excerpt(
    dir: &Path,
    lines: &[Vec<u8>],
    manifest: &crate::server_anchor::ExcerptManifest,
) -> std::io::Result<()> {
    let mut text = Vec::new();
    for l in lines {
        text.extend_from_slice(l);
        text.push(b'\n');
    }
    std::fs::write(dir.join(crate::server_anchor::EXCERPT_FILE), text)?;
    std::fs::write(
        dir.join(crate::server_anchor::EXCERPT_MANIFEST_FILE),
        manifest.to_jcs(),
    )
}
