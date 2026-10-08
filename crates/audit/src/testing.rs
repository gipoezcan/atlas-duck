#![cfg(any(test, feature = "testing"))]
//! Test doubles: a controllable clock and an in-memory keyring with fault points.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::clock::{Clock, UtcInstant};
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
