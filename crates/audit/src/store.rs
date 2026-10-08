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
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::admission::{self, DEFAULT_MIN_FREE_BYTES, FreeSpaceProbe, OsFreeSpace};
use crate::clock::{Clock, UtcInstant};
use crate::crypto::{self, Kek};
use crate::encoding::{self, FIELD_LIST, RowFields};
use crate::error::{AuditError, OpenError};
use crate::keystore::KeyStore;
use crate::schema;
use crate::types::{Committed, NewEvent, QueryKind};
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
}

impl Hooks {
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn fault(&self, p: crate::testing::FaultPoint) -> Result<(), AuditError> {
        match &self.faults {
            Some(f) => f.hit(p),
            None => Ok(()),
        }
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

/// Store state for Settings/tray (T08 fills the anchor fields, T09 incidents, T11 prune).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoreHealth {
    pub anchor_write_failing: bool,
    pub first_retained_update_pending: bool,
    pub storage_low: bool,
    pub open_incidents: usize,
    pub prune_backlog_days: u32,
}

struct Inner {
    tx: Mutex<Option<SyncSender<Cmd>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    shared: Arc<Shared>,
    install_id: String,
    kek: Kek,
    query_key: QueryKey,
    clock: Arc<dyn Clock>,
    db_path: PathBuf,
    data_dir: PathBuf,
    min_free_bytes: u64,
    free_space: Arc<dyn FreeSpaceProbe>,
    reader: Mutex<Option<Connection>>,
}

impl Inner {
    /// Stops the writer after the commands already queued; never writes an anchor.
    fn stop(&self) {
        if let Some(tx) = lock(&self.tx).take() {
            let _ = tx.send(Cmd::Shutdown);
        }
        if let Some(h) = lock(&self.thread).take() {
            let _ = h.join();
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

impl Store {
    /// Spawns the writer; `init` runs on the writer thread and returns the ready writer.
    pub(crate) fn start<F>(
        data: &LocalDataDir,
        cfg: OpenConfig,
        kek: Kek,
        install_id: String,
        init: F,
    ) -> Result<Store, OpenError>
    where
        F: FnOnce(WriterParts) -> Result<Writer, OpenError> + Send + 'static,
    {
        let shared = Shared::new();
        let parts = WriterParts {
            clock: cfg.clock.clone(),
            kek: kek.clone(),
            shared: shared.clone(),
            hooks: cfg.hooks.clone(),
        };
        let (tx, thread) = writer::spawn(move || init(parts))?;
        Ok(Store {
            inner: Arc::new(Inner {
                tx: Mutex::new(Some(tx)),
                thread: Mutex::new(Some(thread)),
                shared,
                install_id,
                query_key: QueryKey(crypto::query_key(&kek)),
                kek,
                clock: cfg.clock,
                db_path: schema::db_path(data),
                data_dir: data.path().to_path_buf(),
                min_free_bytes: cfg.min_free_bytes,
                free_space: cfg.free_space.unwrap_or_else(|| Arc::new(OsFreeSpace)),
                reader: Mutex::new(None),
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

    /// The JCS payload bytes of record `seq`, decrypted and checked against `payload_sha256`.
    pub fn read_payload(&self, seq: u64) -> Result<Zeroizing<Vec<u8>>, AuditError> {
        let seq_i = i64::try_from(seq).map_err(|_| AuditError::NotFound { seq })?;
        let io = |e: rusqlite::Error| AuditError::Io(e.to_string());
        let mut guard = lock(&self.inner.reader);
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
        let Some((month, Some(wrapped))) = key else {
            return Err(decrypt);
        };
        let cached = lock(&self.inner.shared.dek_cache).get(&f.key_id).cloned();
        let dek = match cached {
            Some(d) => d,
            None => crypto::unwrap_dek(&self.inner.kek, f.key_id, month.as_deref(), &wrapped)
                .map_err(|_| decrypt.clone())?,
        };
        let aad = encoding::aad(&f).map_err(|_| decrypt.clone())?;
        let compressed = Zeroizing::new(crypto::open(&dek, f.nonce, &aad, f.payload_ct, seq)?);
        let plain = Zeroizing::new(
            crypto::decompress(&compressed, f.payload_len).map_err(|_| decrypt.clone())?,
        );
        let digest: [u8; 32] = Sha256::digest(plain.as_slice()).into();
        if &digest != f.payload_sha256 {
            return Err(AuditError::PayloadHash { seq });
        }
        Ok(plain)
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

    pub fn health(&self) -> StoreHealth {
        StoreHealth {
            storage_low: self.admission_check().is_err(),
            ..StoreHealth::default()
        }
    }

    /// Stops the writer after the commands already queued; later calls get `Closed`. Never
    /// writes an anchor.
    pub fn shutdown(&self) {
        self.inner.stop();
        *lock(&self.inner.reader) = None;
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
