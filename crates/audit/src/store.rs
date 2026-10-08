//! The `Store` handle (C.3): a cheap `Clone` over the single writer thread. Appends are
//! prepared on the caller's thread and committed by the writer; reads use a read-only
//! connection on the caller's thread (WAL reader) and never block on the writer.

use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use atlas_duck_ipc::paths::LocalDataDir;
use rusqlite::{Connection, OptionalExtension};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::admission::{self, DEFAULT_MIN_FREE_BYTES, FreeSpaceProbe, OsFreeSpace};
use crate::anchors::{
    self, AnchorLoadError, Barrier, BarrierGuard, BarrierKind, FirstRetainedAnchor, HeadAnchor,
};
use crate::clock::{Clock, UtcInstant};
use crate::crypto::{self, Kek};
use crate::encoding::{self, FIELD_LIST, RowFields};
use crate::error::{AuditError, OpenError};
use crate::keystore::KeyStore;
use crate::schema;
use crate::types::{Committed, EventFlags, EventType, NewEvent, QueryKind};
use crate::verify::{
    self, FindingKind, KeychainAnchors, StartupVerdict, VerifyFinding, VerifyOutcome,
};
use crate::writer::{self, Cmd, PreparedEvent, Shared, Writer, WriterParts};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What `open()` and `create_new_store()` are given (C.3 fields first, then additions).
pub struct OpenConfig {
    pub clock: Arc<dyn Clock>,
    pub keys: Arc<dyn KeyStore>,
    pub pinned_install_id: Option<String>,
    pub anchor_dir: Option<PathBuf>,
    /// Low-space admission threshold (§8.1), default 2 GiB.
    pub min_free_bytes: u64,
    /// `None` = the OS probe (`GetDiskFreeSpaceExW` / `statvfs`).
    pub free_space: Option<Arc<dyn FreeSpaceProbe>>,
    /// Empty unless feature `testing`.
    pub hooks: Hooks,
}

impl OpenConfig {
    pub fn new(clock: Arc<dyn Clock>, keys: Arc<dyn KeyStore>) -> Self {
        OpenConfig {
            clock,
            keys,
            pinned_install_id: None,
            anchor_dir: None,
            min_free_bytes: DEFAULT_MIN_FREE_BYTES,
            free_space: None,
            hooks: Hooks::default(),
        }
    }
}

/// Test hooks. Release builds compile it to an empty struct.
#[derive(Clone, Default)]
pub struct Hooks {
    #[cfg(any(test, feature = "testing"))]
    pub faults: Option<Arc<crate::testing::Faults>>,
    /// Writer connection runs `synchronous=NORMAL` (long scenario tests only, T13).
    #[cfg(any(test, feature = "testing"))]
    pub synchronous_normal: bool,
    /// The store starts with anchor writes disabled, as `open()` does until startup
    /// verification passed; `Store::testing_enable_anchors` lifts it.
    #[cfg(any(test, feature = "testing"))]
    pub anchors_disabled: bool,
    /// The anchor retry backoff runs ten times faster.
    #[cfg(any(test, feature = "testing"))]
    pub fast_anchor_backoff: bool,
    /// Overrides the anchor batch window (default 900 ms).
    #[cfg(any(test, feature = "testing"))]
    pub anchor_batch_window: Option<std::time::Duration>,
    /// Overrides the wait of `flush_head_anchor` and `shutdown` on the anchor thread (10 s).
    #[cfg(any(test, feature = "testing"))]
    pub anchor_wait_timeout: Option<std::time::Duration>,
    /// Migrations run after [`schema::MIGRATIONS`]; their highest `to` is this build's schema
    /// head for the version gate.
    #[cfg(any(test, feature = "testing"))]
    pub extra_migrations: Vec<schema::Migration>,
}

impl Hooks {
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn fault(&self, p: crate::testing::FaultPoint) -> Result<(), AuditError> {
        match &self.faults {
            Some(f) => f.hit(p),
            None => Ok(()),
        }
    }

    /// The migration table `open()` runs: [`schema::MIGRATIONS`] plus the test migrations.
    pub(crate) fn migrations(&self) -> Vec<schema::Migration> {
        #[allow(unused_mut)]
        let mut all = schema::MIGRATIONS.to_vec();
        #[cfg(any(test, feature = "testing"))]
        all.extend_from_slice(&self.extra_migrations);
        all
    }

    /// The newest `user_version` this build opens (the version gate).
    pub(crate) fn schema_head(&self) -> u32 {
        self.migrations()
            .iter()
            .map(|m| m.to)
            .fold(schema::SCHEMA_HEAD, u32::max)
    }
}

impl fmt::Debug for Hooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hooks")
    }
}

/// `K_q` of the query tag (F.7), derived once at open. Never printed.
struct QueryKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for QueryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QueryKey([REDACTED])")
    }
}

/// Store state for Settings/tray (T09 fills the incidents, T11 prune).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoreHealth {
    pub anchor_write_failing: bool,
    pub first_retained_update_pending: bool,
    pub storage_low: bool,
    pub open_incidents: usize,
    pub prune_backlog_days: u32,
    /// Anchor writes are held back by an unfinished prune or restore.
    pub anchors_blocked: Option<BarrierKind>,
    /// The anchor thread panicked: no anchor is written until restart.
    pub anchor_thread_dead: bool,
}

/// One row's ciphertext and what opening it needs. No `Debug`: it holds a wrapped key.
struct Sealed {
    aad: Vec<u8>,
    key_id: u64,
    month: Option<String>,
    wrapped_dek: Vec<u8>,
    nonce: [u8; 12],
    payload_ct: Vec<u8>,
    payload_len: u64,
    payload_sha256: [u8; 32],
}

struct Inner {
    tx: Mutex<Option<SyncSender<Cmd>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    anchor_thread: Mutex<Option<JoinHandle<()>>>,
    shared: Arc<Shared>,
    install_id: String,
    /// Read by `full_verify` for the anchors; only the anchor thread writes them.
    keys: Arc<dyn KeyStore>,
    kek: Kek,
    query_key: QueryKey,
    clock: Arc<dyn Clock>,
    db_path: PathBuf,
    data_dir: PathBuf,
    min_free_bytes: u64,
    free_space: Arc<dyn FreeSpaceProbe>,
    reader: Mutex<Option<Connection>>,
    /// Fault points of the startup steps (feature `testing`).
    #[cfg(any(test, feature = "testing"))]
    hooks: Hooks,
}

impl Inner {
    /// Stops the writer after the commands already queued, then the anchor thread; never
    /// writes an anchor.
    fn stop(&self) {
        if let Some(tx) = lock(&self.tx).take() {
            let _ = tx.send(Cmd::Shutdown);
        }
        if let Some(h) = lock(&self.thread).take() {
            let _ = h.join();
        }
        let exited = self.shared.anchors.stop();
        if let Some(h) = lock(&self.anchor_thread).take() {
            // A thread stuck in a keychain call is detached rather than waited for forever.
            if exited {
                let _ = h.join();
            }
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let head = lock(&self.inner.shared.head);
        f.debug_struct("Store")
            .field("install_id", &self.inner.install_id)
            .field("chain_id", &head.chain_id)
            .field("head_seq", &head.seq)
            .finish_non_exhaustive()
    }
}

fn system_to_utc(t: SystemTime) -> Option<UtcInstant> {
    let ms = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).ok()?,
        Err(e) => i64::try_from(e.duration().as_millis()).ok().map(|m| -m)?,
    };
    let u = UtcInstant(ms);
    u.try_to_rfc3339_ms().map(|_| u)
}

/// How the anchor state starts.
pub(crate) struct AnchorInit {
    /// Anchor writes allowed from the start (first run); `open()` starts disabled until the
    /// startup verification passed (§8.7).
    pub(crate) enabled: bool,
    /// The keychain already holds the head the writer starts with (first run).
    pub(crate) head_anchored: bool,
}

impl Store {
    /// Spawns the writer and the anchor thread; `init` runs on the writer thread and returns
    /// the ready writer.
    pub(crate) fn start<F>(
        data: &LocalDataDir,
        cfg: OpenConfig,
        kek: Kek,
        install_id: String,
        anchors: AnchorInit,
        init: F,
    ) -> Result<Store, OpenError>
    where
        F: FnOnce(WriterParts) -> Result<Writer, OpenError> + Send + 'static,
    {
        let shared = Shared::new();
        #[cfg(any(test, feature = "testing"))]
        let hooks = cfg.hooks.clone();
        let parts = WriterParts {
            clock: cfg.clock.clone(),
            kek: kek.clone(),
            shared: shared.clone(),
            hooks: cfg.hooks.clone(),
        };
        let (tx, thread) = writer::spawn(move || init(parts))?;
        let h = lock(&shared.head).clone();
        #[allow(unused_mut)]
        let mut enabled = anchors.enabled;
        #[allow(unused_mut)]
        let mut scale_div = 1;
        #[allow(unused_mut)]
        let mut window = anchors::BATCH_WINDOW;
        #[allow(unused_mut)]
        let mut wait_timeout = anchors::DEFAULT_WAIT_TIMEOUT;
        #[cfg(any(test, feature = "testing"))]
        {
            window = cfg.hooks.anchor_batch_window.unwrap_or(window);
            wait_timeout = cfg.hooks.anchor_wait_timeout.unwrap_or(wait_timeout);
            enabled &= !cfg.hooks.anchors_disabled;
            if cfg.hooks.fast_anchor_backoff {
                scale_div = 10;
            }
        }
        shared.anchors.init(
            enabled,
            HeadAnchor {
                chain_id: h.chain_id,
                seq: h.seq,
                record_hash: h.hash,
            },
            anchors.head_anchored,
            window,
            wait_timeout,
        );
        let spawned = {
            let shared = shared.anchors.clone();
            let keys = cfg.keys.clone();
            std::thread::Builder::new()
                .name("audit-anchor".into())
                .spawn(move || anchors::run(shared, keys, scale_div))
        };
        let anchor_thread = match spawned {
            Ok(t) => t,
            Err(e) => {
                let _ = tx.send(Cmd::Shutdown);
                let _ = thread.join();
                return Err(e.into());
            }
        };
        Ok(Store {
            inner: Arc::new(Inner {
                tx: Mutex::new(Some(tx)),
                thread: Mutex::new(Some(thread)),
                anchor_thread: Mutex::new(Some(anchor_thread)),
                shared,
                install_id,
                keys: cfg.keys,
                query_key: QueryKey(crypto::query_key(&kek)),
                kek,
                clock: cfg.clock,
                db_path: schema::db_path(data),
                data_dir: data.path().to_path_buf(),
                min_free_bytes: cfg.min_free_bytes,
                free_space: cfg.free_space.unwrap_or_else(|| Arc::new(OsFreeSpace)),
                reader: Mutex::new(None),
                #[cfg(any(test, feature = "testing"))]
                hooks,
            }),
        })
    }

    fn sender(&self) -> Result<SyncSender<Cmd>, AuditError> {
        lock(&self.inner.tx).clone().ok_or(AuditError::Closed)
    }

    fn send_append(&self, evs: Vec<PreparedEvent>) -> Result<Vec<Committed>, AuditError> {
        let (reply, rx) = sync_channel(1);
        self.sender()?
            .send(Cmd::Append { evs, reply })
            .map_err(|_| AuditError::Closed)?;
        // A writer that stopped or panicked drops the reply sender.
        rx.recv().map_err(|_| AuditError::Closed)?
    }

    /// Appends one event; returns only after the commit is durable (`synchronous=FULL`). On
    /// `Err` nothing was committed and the caller must fail closed (§11.1).
    pub fn append(&self, ev: NewEvent) -> Result<Committed, AuditError> {
        let p = PreparedEvent::from_new(ev)?;
        self.send_append(vec![p])?
            .pop()
            .ok_or_else(|| AuditError::AppendFailed("the writer returned no row".into()))
    }

    /// Appends all events in one transaction, all or nothing. An empty batch commits nothing
    /// and returns an empty list.
    pub fn append_batch(&self, evs: Vec<NewEvent>) -> Result<Vec<Committed>, AuditError> {
        if evs.is_empty() {
            return Ok(Vec::new());
        }
        let prepared = evs
            .into_iter()
            .map(PreparedEvent::from_new)
            .collect::<Result<Vec<_>, _>>()?;
        let n = prepared.len();
        let out = self.send_append(prepared)?;
        if out.len() != n {
            return Err(AuditError::AppendFailed(
                "the writer returned another row count".into(),
            ));
        }
        Ok(out)
    }

    /// Low-space admission (§8.1): `StorageLow` when the DB volume has no more than
    /// `min_free_bytes` free or the probe fails. Never touches the writer.
    pub fn admission_check(&self) -> Result<(), AuditError> {
        admission::check(
            &*self.inner.free_space,
            &self.inner.data_dir,
            self.inner.min_free_bytes,
        )
    }

    /// `"jql:<hex>"` / `"cql:<hex>"` (F.7, L38).
    pub fn query_tag(&self, kind: QueryKind, query: &str) -> String {
        crypto::query_tag(&self.inner.query_key.0, kind, query)
    }

    /// The JCS payload bytes of record `seq`, decrypted (AES-GCM over the row's AAD, F.3) and
    /// checked against `payload_sha256`. It does not check `record_hash`/`prev_hash`: chain
    /// verification is `full_verify`/startup (T09). After `shutdown()` it returns `Closed`.
    pub fn read_payload(&self, seq: u64) -> Result<Zeroizing<Vec<u8>>, AuditError> {
        let sealed = self.read_sealed(seq)?;
        let decrypt = AuditError::Decrypt { seq };
        let cached = lock(&self.inner.shared.dek_cache)
            .get(&sealed.key_id)
            .cloned();
        let dek = match cached {
            Some(d) => d,
            None => crypto::unwrap_dek(
                &self.inner.kek,
                sealed.key_id,
                sealed.month.as_deref(),
                &sealed.wrapped_dek,
            )
            .map_err(|_| decrypt.clone())?,
        };
        let compressed = Zeroizing::new(crypto::open(
            &dek,
            &sealed.nonce,
            &sealed.aad,
            &sealed.payload_ct,
            seq,
        )?);
        let plain = Zeroizing::new(
            crypto::decompress(&compressed, sealed.payload_len).map_err(|_| decrypt)?,
        );
        let digest: [u8; 32] = Sha256::digest(plain.as_slice()).into();
        if !crypto::ct_eq(&digest, &sealed.payload_sha256) {
            return Err(AuditError::PayloadHash { seq });
        }
        Ok(plain)
    }

    /// Copies what decryption needs out of the database; the reader lock is held only here,
    /// not across decryption and decompression.
    fn read_sealed(&self, seq: u64) -> Result<Sealed, AuditError> {
        let seq_i = i64::try_from(seq).map_err(|_| AuditError::NotFound { seq })?;
        let io = |e: rusqlite::Error| AuditError::Io(e.to_string());
        let mut guard = lock(&self.inner.reader);
        if lock(&self.inner.tx).is_none() {
            return Err(AuditError::Closed);
        }
        if guard.is_none() {
            *guard = Some(
                schema::open_ro(&self.inner.db_path).map_err(|e| AuditError::Io(e.to_string()))?,
            );
        }
        let Some(conn) = guard.as_ref() else {
            return Err(AuditError::Closed);
        };
        let sql = format!(
            "SELECT {} FROM events WHERE seq = ?1",
            FIELD_LIST.join(", ")
        );
        let mut stmt = conn.prepare_cached(&sql).map_err(io)?;
        let mut rows = stmt.query([seq_i]).map_err(io)?;
        let Some(row) = rows.next().map_err(io)? else {
            return Err(AuditError::NotFound { seq });
        };
        let decrypt = AuditError::Decrypt { seq };
        let f = RowFields::from_row(row).map_err(|_| decrypt.clone())?;
        let key: Option<(Option<String>, Option<Vec<u8>>)> = conn
            .query_row(
                "SELECT month, wrapped_dek FROM keys WHERE key_id = ?1",
                [i64::try_from(f.key_id).map_err(|_| decrypt.clone())?],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(io)?;
        let Some((month, Some(wrapped_dek))) = key else {
            return Err(decrypt);
        };
        Ok(Sealed {
            aad: encoding::aad(&f).map_err(|_| decrypt)?,
            key_id: f.key_id,
            month,
            wrapped_dek,
            nonce: *f.nonce,
            payload_ct: f.payload_ct.to_vec(),
            payload_len: f.payload_len,
            payload_sha256: *f.payload_sha256,
        })
    }

    /// A server `Date` header seen at `at` (§8.8 source (a)). Never blocks on the writer: if
    /// the writer's queue is full the observation is dropped (it repeats on every response).
    pub fn observe_server_date(&self, _instance_id: &str, server_date: SystemTime, at: Instant) {
        let Some(server) = system_to_utc(server_date) else {
            return;
        };
        let since = at.elapsed();
        let mono_at = self
            .inner
            .clock
            .suspend_aware_elapsed()
            .saturating_sub(since);
        let back = i64::try_from(since.as_millis()).unwrap_or(i64::MAX);
        let local = UtcInstant(self.inner.clock.now_utc().0.saturating_sub(back));
        let Ok(tx) = self.sender() else {
            return;
        };
        if let Err(TrySendError::Full(_)) = tx.try_send(Cmd::ObserveDate {
            server,
            local,
            mono_at,
        }) {
            self.inner
                .shared
                .dropped_observations
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The committed head: `(seq, record_hash, chain_id)`.
    pub fn head(&self) -> (u64, [u8; 32], String) {
        let h = lock(&self.inner.shared.head);
        (h.seq, h.hash, h.chain_id.clone())
    }

    pub fn install_id(&self) -> &str {
        &self.inner.install_id
    }

    /// Writes the head anchor now (C.3), e.g. after `APP_STOP`. Returns the keychain error of
    /// the attempt, if any. `Ok(())` and no write while anchors are disabled (before startup
    /// verification) or held back by a restore barrier; behind a prune barrier it writes the
    /// capped head. Never an incident: a failure is also in `health()`.
    pub fn flush_head_anchor(&self) -> Result<(), AuditError> {
        self.inner.shared.anchors.flush()
    }

    /// Startup verification passed: the anchor thread may write (§8.7 "no anchor writes
    /// before verification").
    pub(crate) fn enable_anchors(&self) {
        #[cfg(any(test, feature = "testing"))]
        let _ = self
            .inner
            .hooks
            .fault(crate::testing::FaultPoint::AnchorsEnabled);
        self.inner.shared.anchors.enable();
    }

    /// Holds the head anchor back (prune/restore). The guard releases the barrier when
    /// dropped unless `complete()` was called; an error path therefore cannot leave the anchors
    /// blocked. Install it BEFORE the `PRUNE`/`RESTORE` commit becomes visible. A second barrier
    /// is refused.
    #[allow(dead_code)] // called by prune/restore (T11)
    pub(crate) fn install_barrier(&self, b: Barrier) -> Result<BarrierGuard, AuditError> {
        self.inner.shared.anchors.install_barrier(b)
    }

    /// Lifts the barrier explicitly.
    #[allow(dead_code)] // called by prune/restore (T11)
    pub(crate) fn clear_barrier(&self) {
        self.inner.shared.anchors.clear_barrier();
    }

    /// The restore completion step: writes both anchors and lifts the restore barrier.
    #[allow(dead_code)] // called by restore (T11)
    pub(crate) fn complete_restore_anchors(
        &self,
        head: HeadAnchor,
        first_retained: FirstRetainedAnchor,
    ) -> Result<(), AuditError> {
        self.inner
            .shared
            .anchors
            .complete_restore(head, first_retained)
    }

    pub fn health(&self) -> StoreHealth {
        let a = self.inner.shared.anchors.health();
        StoreHealth {
            anchor_write_failing: a.write_failing,
            first_retained_update_pending: a.first_retained_pending,
            anchors_blocked: a.blocked,
            anchor_thread_dead: a.thread_dead,
            storage_low: self.admission_check().is_err(),
            open_incidents: lock(&self.inner.shared.incidents).len(),
            ..StoreHealth::default()
        }
    }

    /// Full verification (C.3, §8.7): the whole chain, `prune_log`, a decrypt pass, every
    /// `WRITE_APPROVED`'s `request_set_hash`, DEK references, every retained `PRUNE` judged by
    /// its own settings snapshot, `RESTORE` boundaries and the keychain anchors; then one
    /// `VERIFY {scope: "full"}` (`result: "ok"` and no `integrity_incident` flag when clean).
    ///
    /// A run that cannot complete is never reported as a pass, and appends no `VERIFY`
    /// claiming one. This `Vec` API (C.3) has no error channel, so non-completion is reported
    /// as a `ChainBroken` finding whose `detail` starts "verification did not complete": the
    /// only finding when the store is closed, the keychain does not answer (the anchor checks
    /// cannot run) or the database is unreadable; after the run's findings when only the
    /// `VERIFY` append fails. Callers that show the result (M6 `verify_now`) use
    /// [`Store::try_full_verify`], which returns the error instead. A keychain anchor with a
    /// newer layout byte (the startup gate admitted the current one) is an `AnchorMismatch`.
    pub fn full_verify(&self) -> Vec<VerifyFinding> {
        let incomplete = |e: AuditError| {
            VerifyFinding::new(
                FindingKind::ChainBroken,
                format!("verification did not complete: {e}"),
            )
        };
        match self.run_full_verify() {
            Err(e) => vec![incomplete(e)],
            Ok(mut findings) => {
                if let Err(e) = self.append_verify("full", &findings, None) {
                    findings.push(incomplete(e));
                }
                findings
            }
        }
    }

    /// `full_verify` with its errors. Runs on its own read-only connection on the calling
    /// thread (one read transaction); only the final `VERIFY` append goes through the writer.
    /// The keychain is read before the snapshot is taken, head anchor first, so an anchor
    /// never names a record the snapshot lacks. A keychain that does not answer ends the run
    /// with `Err(KeyStore)` and no `VERIFY` (an unavailable keychain is never an incident,
    /// §8.8, but a run without the anchor checks is not a pass either).
    pub fn try_full_verify(&self) -> Result<VerifyOutcome, AuditError> {
        let findings = self.run_full_verify()?;
        let c = self.append_verify("full", &findings, None)?;
        Ok(VerifyOutcome {
            findings,
            unanchored_tail: 0,
            verify_seq: Some(c.seq),
        })
    }

    /// The findings of a full verification, without the `VERIFY` append.
    fn run_full_verify(&self) -> Result<Vec<VerifyFinding>, AuditError> {
        self.sender()?;
        // A keychain that does not answer ends the run (no "ok" without the anchor checks);
        // a newer layout byte in one entry (the startup gate admitted the current one) is a
        // finding, and the other entry is still checked.
        fn split<T>(
            r: Result<Option<T>, AnchorLoadError>,
        ) -> Result<(Option<T>, Option<u8>), AuditError> {
            match r {
                Ok(a) => Ok((a, None)),
                Err(AnchorLoadError::Newer(n)) => Ok((None, Some(n))),
                Err(AnchorLoadError::KeyStore(e)) => Err(AuditError::KeyStore(e)),
            }
        }
        let (head, head_newer) = split(anchors::load_head(&*self.inner.keys))?;
        let (first_retained, first_retained_newer) =
            split(anchors::load_first_retained(&*self.inner.keys))?;
        let k = KeychainAnchors {
            head,
            first_retained,
            head_newer,
            first_retained_newer,
        };
        let conn =
            schema::open_ro(&self.inner.db_path).map_err(|e| AuditError::Io(e.to_string()))?;
        verify::full(&conn, &self.inner.kek, &k)
    }

    /// Seqs of the integrity-incident `VERIFY` records without a later `INTEGRITY_ACK` (C.3),
    /// ascending.
    pub fn open_incidents(&self) -> Vec<u64> {
        lock(&self.inner.shared.incidents).iter().copied().collect()
    }

    /// "Acknowledge integrity incident" (§8.7): appends `INTEGRITY_ACK {verify_seq, os_user,
    /// note}` with the plaintext `os_user`. `Invalid` if `verify_seq` is not an open incident
    /// (checked again on the writer thread, so a second ack of the same run is refused).
    pub fn acknowledge_incident(
        &self,
        verify_seq: u64,
        os_user: &str,
        note: &str,
    ) -> Result<Committed, AuditError> {
        if os_user.is_empty() {
            return Err(AuditError::Invalid("os_user is empty"));
        }
        if !lock(&self.inner.shared.incidents).contains(&verify_seq) {
            return Err(AuditError::Invalid("not an open integrity incident"));
        }
        let mut p = PreparedEvent::system(
            EventType::INTEGRITY_ACK,
            &json!({ "verify_seq": verify_seq, "os_user": os_user, "note": note }),
        )?;
        p.os_user = Some(os_user.to_string());
        p.ack_of = Some(verify_seq);
        self.send_append(vec![p])?
            .pop()
            .ok_or_else(|| AuditError::AppendFailed("the writer returned no row".into()))
    }

    /// One `VERIFY` record for a run (F.11), flagged `integrity_incident` iff any finding is
    /// an incident kind.
    pub(crate) fn append_verify(
        &self,
        scope: &str,
        findings: &[VerifyFinding],
        unanchored_tail: Option<u64>,
    ) -> Result<Committed, AuditError> {
        let detected_at = self
            .inner
            .clock
            .now_utc()
            .try_to_rfc3339_ms()
            .ok_or_else(|| {
                AuditError::AppendFailed("wall clock outside years 0000..=9999".into())
            })?;
        let payload = verify::verify_payload(scope, findings, &detected_at, unanchored_tail);
        let mut p = PreparedEvent::system(EventType::VERIFY, &payload)?;
        if findings.iter().any(|f| f.kind.is_incident()) {
            p.store_flags = EventFlags::INTEGRITY_INCIDENT;
        }
        self.send_append(vec![p])?
            .pop()
            .ok_or_else(|| AuditError::AppendFailed("the writer returned no row".into()))
    }

    /// Startup step 4 after migrations (§8.7): appends the verdict's `VERIFY` (none when it
    /// has no finding), then the anchor actions, then enables anchor writes. An interrupted
    /// prune gets its prune barrier (first-retained written before the head passes the
    /// `PRUNE`); an interrupted restore gets a restore barrier, which only the restore
    /// completion (T16) lifts. If the `VERIFY` append fails, anchors stay disabled.
    pub(crate) fn apply_startup(&self, v: &StartupVerdict) -> Result<VerifyOutcome, AuditError> {
        let verify_seq = if v.findings.is_empty() {
            None
        } else {
            let tail = (v.unanchored_tail > 0).then_some(v.unanchored_tail);
            Some(self.append_verify("startup", &v.findings, tail)?.seq)
        };
        #[cfg(any(test, feature = "testing"))]
        self.inner
            .hooks
            .fault(crate::testing::FaultPoint::AfterStartupVerifyAppend)?;
        let a = &v.anchor_actions;
        if let Some(rc) = &a.complete_restore {
            self.install_barrier(Barrier::Restore {
                seq: rc.restore_seq,
            })?
            .complete();
        } else if let (Some(fr), Some(p)) = (&a.set_first_retained, &a.prune_record) {
            self.install_barrier(Barrier::Prune {
                seq: p.seq,
                record_hash: p.record_hash,
                first_retained: fr.clone(),
            })?
            .complete();
        }
        self.enable_anchors();
        Ok(VerifyOutcome {
            findings: v.findings.clone(),
            unanchored_tail: v.unanchored_tail,
            verify_seq,
        })
    }

    /// Startup step 4 (§8.13): runs the pending migrations on the writer's connection, each
    /// with its `SCHEMA_MIGRATED` row in the same transaction. Returns the `(from, to)` span,
    /// `None` when nothing was pending. Call before the startup `VERIFY` and with anchor
    /// writes disabled.
    pub(crate) fn run_migrations(&self) -> Result<Option<(u32, u32)>, OpenError> {
        let closed = || OpenError::Io(std::io::Error::other("the audit writer stopped"));
        let (reply, rx) = sync_channel(1);
        self.sender()
            .map_err(|_| closed())?
            .send(Cmd::Migrate { reply })
            .map_err(|_| closed())?;
        rx.recv().map_err(|_| closed())?
    }

    /// `meta.written_by` = this build (advisory, §8.13), after startup step 4.
    pub(crate) fn update_written_by(&self) -> Result<(), OpenError> {
        let closed = || OpenError::Io(std::io::Error::other("the audit writer stopped"));
        let (reply, rx) = sync_channel(1);
        self.sender()
            .map_err(|_| closed())?
            .send(Cmd::SetWrittenBy { reply })
            .map_err(|_| closed())?;
        rx.recv().map_err(|_| closed())?
    }

    /// Stops the writer after the commands already queued; later calls get `Closed`. Never
    /// writes an anchor.
    pub fn shutdown(&self) {
        self.inner.stop();
        *lock(&self.inner.reader) = None;
    }

    /// `enable_anchors` for integration tests (feature `testing`).
    #[cfg(any(test, feature = "testing"))]
    pub fn testing_enable_anchors(&self) {
        self.enable_anchors();
    }

    /// No anchor write until `testing_enable_anchors` (feature `testing`): the keychain keeps
    /// the anchors it holds now.
    #[cfg(any(test, feature = "testing"))]
    pub fn testing_pause_anchors(&self) {
        self.inner.shared.anchors.disable();
    }

    /// `testing::insert_fake_prune` (feature `testing`).
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn testing_fake_prune(
        &self,
        prune: crate::testing::FakePrune,
    ) -> Result<Committed, AuditError> {
        let anchor = if prune.update_first_retained {
            let (_, fr) = anchors::load_anchors(&*self.inner.keys)
                .map_err(|_| AuditError::Invalid("keychain anchors unreadable"))?;
            let fr = fr.ok_or(AuditError::Invalid("first-retained anchor missing"))?;
            Some((fr.chain_id, fr.genesis_hash))
        } else {
            None
        };
        let (reply, rx) = sync_channel(1);
        self.sender()?
            .send(Cmd::FakePrune {
                prune,
                anchor,
                reply,
            })
            .map_err(|_| AuditError::Closed)?;
        rx.recv().map_err(|_| AuditError::Closed)?
    }

    /// A prune barrier at `seq` (feature `testing`).
    #[cfg(any(test, feature = "testing"))]
    pub fn testing_prune_barrier(
        &self,
        seq: u64,
        record_hash: [u8; 32],
        first_retained: FirstRetainedAnchor,
    ) -> Result<BarrierGuard, AuditError> {
        self.install_barrier(Barrier::Prune {
            seq,
            record_hash,
            first_retained,
        })
    }

    /// A restore barrier at `seq` (feature `testing`).
    #[cfg(any(test, feature = "testing"))]
    pub fn testing_restore_barrier(&self, seq: u64) -> Result<BarrierGuard, AuditError> {
        self.install_barrier(Barrier::Restore { seq })
    }

    /// `clear_barrier` for integration tests (feature `testing`).
    #[cfg(any(test, feature = "testing"))]
    pub fn testing_clear_barrier(&self) {
        self.clear_barrier();
    }

    /// `complete_restore_anchors` for integration tests (feature `testing`).
    #[cfg(any(test, feature = "testing"))]
    pub fn testing_complete_restore_anchors(
        &self,
        head: HeadAnchor,
        first_retained: FirstRetainedAnchor,
    ) -> Result<(), AuditError> {
        self.complete_restore_anchors(head, first_retained)
    }

    /// A pragma as the writer connection reports it (feature `testing`).
    #[cfg(any(test, feature = "testing"))]
    pub fn testing_pragma(&self, name: &'static str) -> Result<i64, AuditError> {
        let (reply, rx) = sync_channel(1);
        self.sender()?
            .send(Cmd::Pragma { name, reply })
            .map_err(|_| AuditError::Closed)?;
        rx.recv().map_err(|_| AuditError::Closed)?
    }

    /// `observe_server_date` calls dropped on a full queue (feature `testing`).
    #[cfg(any(test, feature = "testing"))]
    pub fn testing_dropped_observations(&self) -> u64 {
        self.inner
            .shared
            .dropped_observations
            .load(Ordering::Relaxed)
    }
}
