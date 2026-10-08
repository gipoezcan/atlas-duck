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
}

#[derive(Default)]
struct PauseState {
    requested: bool,
    paused: bool,
}

/// Injected failures and a writer pause, shared between a test and the store's [`crate::store::Hooks`].
pub struct Faults {
    armed: Mutex<HashMap<FaultPoint, (u32, u32)>>,
    pause: Mutex<PauseState>,
    cv: Condvar,
}

impl Faults {
    pub fn new() -> Arc<Faults> {
        Arc::new(Faults {
            armed: Mutex::new(HashMap::new()),
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
