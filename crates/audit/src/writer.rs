//! The single writer thread (§8.1): the only owner of the read-write connection, the chain
//! head, the `ClockState`, DEK creation and the post-commit caches. Callers prepare payloads
//! on their own thread (F.3 steps 1–3); the writer stamps `seq`/`ts_utc`/`epoch`/flags,
//! encrypts, hashes and commits one `BEGIN IMMEDIATE` transaction per command, and replies
//! only after `COMMIT` returned (`synchronous=FULL`, §5.1 inv. 1).

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

use atlas_duck_ipc::build_info::APP_VERSION;
use atlas_duck_ipc::jcs::{JcsError, to_jcs_vec};
use chrono::{Datelike, NaiveDate};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::anchors::{AnchorShared, HeadAnchor};
#[cfg(any(test, feature = "testing"))]
use crate::anchors::{Barrier, FirstRetainedAnchor};
use crate::clock::{
    AnomalyKind, ClockAnomaly, ClockState, Stamp, UtcInstant, epoch_text, month_text, parse_epoch,
};
use crate::crypto::{self, Dek, Kek, MAX_PAYLOAD_LEN};
use crate::encoding::{self, FIELD_LIST, FORMAT_VERSION, RowFields, ZERO_HASH};
use crate::error::{AuditError, OpenError};
use crate::prune::{PruneOutcome, PruneSkip, Settings};
use crate::schema;
use crate::store::Hooks;
use crate::types::{Committed, Confirmed, EventFlags, EventType, NewEvent};

/// Bound of the command channel (plan decision).
pub(crate) const CHANNEL_BOUND: usize = 64;

/// Event types only the store itself writes, each through a `Store` method with its own
/// bookkeeping or confirmation (C.3, §8.3): chain start, `prune_log`, segment boundary,
/// incidents and acks, migrations, key recovery/rotation (a DEK in the same transaction),
/// clock episodes, the legal hold (Rust-drawn confirmation, §8.8), backup and export receipts.
/// `append` refuses them. `CONFIG_CHANGED` stays appendable by `core` (T12 gates policy keys).
const STORE_OWNED: [EventType; 12] = [
    EventType::GENESIS,
    EventType::PRUNE,
    EventType::RESTORE,
    EventType::VERIFY,
    EventType::INTEGRITY_ACK,
    EventType::SCHEMA_MIGRATED,
    EventType::KEY_RECOVERED,
    EventType::KEY_ROTATED,
    EventType::CLOCK_ANOMALY,
    EventType::LEGAL_HOLD_CHANGED,
    EventType::BACKUP,
    EventType::EXPORT,
];

/// Runs a fault point of the `testing` hooks; compiles to nothing in release builds.
macro_rules! fault {
    ($hooks:expr, $point:ident) => {
        #[cfg(any(test, feature = "testing"))]
        {
            $hooks.fault(crate::testing::FaultPoint::$point)?;
        }
    };
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn sql(e: rusqlite::Error) -> AuditError {
    AuditError::AppendFailed(format!("database error: {e}"))
}

fn sql_open(e: rusqlite::Error) -> OpenError {
    OpenError::Sqlite(e.to_string())
}

pub(crate) fn int(v: u64) -> Result<i64, AuditError> {
    i64::try_from(v).map_err(|_| AuditError::AppendFailed("integer column above 2^63".into()))
}

/// `ts_utc` / `created_at` text; an instant outside years 0000..=9999 fails closed.
pub(crate) fn ts_text(t: UtcInstant) -> Result<String, AuditError> {
    t.try_to_rfc3339_ms()
        .ok_or_else(|| AuditError::AppendFailed("wall clock outside years 0000..=9999".into()))
}

/// One event after F.3 steps 1–3 (JCS, SHA-256, zstd), ready for the writer. No `Debug`: it
/// holds the compressed plaintext.
pub(crate) struct PreparedEvent {
    pub(crate) event_type: EventType,
    pub(crate) request_id: Option<String>,
    pub(crate) op_id: Option<String>,
    pub(crate) op_class: Option<String>,
    pub(crate) instance_id: Option<String>,
    pub(crate) target: Option<String>,
    pub(crate) agent_name: Option<String>,
    pub(crate) agent_name_source: Option<String>,
    pub(crate) client_kind: Option<String>,
    pub(crate) connection_id: Option<String>,
    pub(crate) peer_pid: Option<u64>,
    pub(crate) peer_exe: Option<Vec<u8>>,
    pub(crate) peer_origin_exe: Option<Vec<u8>>,
    pub(crate) os_user: Option<String>,
    pub(crate) atlassian_user: Option<String>,
    pub(crate) atlassian_user_key: Option<String>,
    pub(crate) decision: Option<&'static str>,
    /// Caller flags, masked with `CALLER_SETTABLE`.
    pub(crate) flags: EventFlags,
    /// Store-managed non-clock flags (`integrity_incident` on `VERIFY` only).
    pub(crate) store_flags: EventFlags,
    /// `INTEGRITY_ACK` only: the open incident it closes. The writer refuses the append when
    /// that incident is not open (checked on the writer thread, so two acks cannot race).
    pub(crate) ack_of: Option<u64>,
    pub(crate) payload_len: u64,
    pub(crate) payload_sha256: [u8; 32],
    pub(crate) compressed: Zeroizing<Vec<u8>>,
}

fn jcs_error(e: JcsError) -> AuditError {
    match e {
        JcsError::IntegerOutOfRange => AuditError::Invalid("payload integer outside ±(2^53 − 1)"),
        JcsError::Serialize(_) => AuditError::Invalid("payload is not encodable as JCS"),
    }
}

impl PreparedEvent {
    /// The public `append` path: refuses store-owned event types.
    pub(crate) fn from_new(ev: NewEvent) -> Result<PreparedEvent, AuditError> {
        if STORE_OWNED.contains(&ev.event_type) {
            return Err(AuditError::Invalid(
                "this event type is written by the store only",
            ));
        }
        PreparedEvent::build(ev)
    }

    fn build(ev: NewEvent) -> Result<PreparedEvent, AuditError> {
        let plain = Zeroizing::new(to_jcs_vec(&ev.payload).map_err(jcs_error)?);
        let payload_len = plain.len() as u64;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(AuditError::Invalid("payload above 64 MiB"));
        }
        let payload_sha256: [u8; 32] = Sha256::digest(plain.as_slice()).into();
        let compressed = Zeroizing::new(crypto::compress(&plain)?);
        let a = ev.actor;
        Ok(PreparedEvent {
            event_type: ev.event_type,
            request_id: ev.request_id,
            op_id: ev.op_id,
            op_class: ev.op_class,
            instance_id: ev.instance_id,
            target: ev.target,
            agent_name: a.agent_name,
            agent_name_source: a.agent_name_source,
            client_kind: a.client_kind,
            connection_id: a.connection_id,
            peer_pid: a.peer_pid.map(u64::from),
            peer_exe: a.peer_exe.as_deref().map(encoding::os_path_bytes),
            peer_origin_exe: a.peer_origin_exe.as_deref().map(encoding::os_path_bytes),
            os_user: a.os_user,
            atlassian_user: a.atlassian_user,
            atlassian_user_key: a.atlassian_user_key,
            decision: ev.decision.map(|d| d.as_str()),
            flags: ev.flags & EventFlags::CALLER_SETTABLE,
            store_flags: EventFlags::default(),
            ack_of: None,
            payload_len,
            payload_sha256,
            compressed,
        })
    }

    /// A store-written event with only a payload (and the columns the caller sets after).
    pub(crate) fn system(
        event_type: EventType,
        payload: &Value,
    ) -> Result<PreparedEvent, AuditError> {
        PreparedEvent::build(NewEvent {
            event_type,
            request_id: None,
            op_id: None,
            op_class: None,
            instance_id: None,
            target: None,
            actor: Default::default(),
            decision: None,
            flags: EventFlags::default(),
            payload: payload.clone(),
        })
    }

    /// `CLOCK_ANOMALY {kind, local, server, reason: null}` (F.11).
    pub(crate) fn clock_anomaly(a: &ClockAnomaly) -> Result<PreparedEvent, AuditError> {
        let kind = match a.kind {
            AnomalyKind::LocalAhead => "local_ahead",
            AnomalyKind::LocalBehind => "local_behind",
        };
        PreparedEvent::system(
            EventType::CLOCK_ANOMALY,
            &json!({
                "kind": kind,
                "local": ts_text(a.local)?,
                "server": ts_text(a.server)?,
                "reason": null,
            }),
        )
    }
}

/// How a committed row changes the open-incident set.
#[derive(Clone, Copy)]
pub(crate) enum IncidentChange {
    Opened(u64),
    Acknowledged(u64),
}

/// The chain head as the writer sees it.
#[derive(Clone)]
pub(crate) struct Head {
    pub(crate) seq: u64,
    pub(crate) hash: [u8; 32],
    pub(crate) chain_id: String,
}

/// The committed head published for `Store::head()`.
#[derive(Clone)]
pub(crate) struct HeadView {
    pub(crate) seq: u64,
    pub(crate) hash: [u8; 32],
    pub(crate) chain_id: String,
}

/// State shared between the `Store` handles and the writer. The writer is the only thread
/// that writes `head` and `dek_cache`, and only after a `COMMIT` returned.
pub(crate) struct Shared {
    pub(crate) head: Mutex<HeadView>,
    pub(crate) dek_cache: Mutex<HashMap<u64, Dek>>,
    /// `observe_server_date` calls dropped because the channel was full.
    pub(crate) dropped_observations: AtomicU64,
    /// The head handed to the anchor thread after every commit (T08).
    pub(crate) anchors: Arc<AnchorShared>,
    /// Seqs of open integrity incidents (T09): loaded at open, updated after every commit of
    /// a flagged `VERIFY` or an `INTEGRITY_ACK`.
    pub(crate) incidents: Mutex<BTreeSet<u64>>,
    /// Days the cutoff of the latest prune run stayed behind its unclamped value (L37).
    pub(crate) prune_backlog_days: AtomicU32,
}

impl Shared {
    pub(crate) fn new() -> Arc<Shared> {
        Arc::new(Shared {
            head: Mutex::new(HeadView {
                seq: 0,
                hash: ZERO_HASH,
                chain_id: String::new(),
            }),
            dek_cache: Mutex::new(HashMap::new()),
            dropped_observations: AtomicU64::new(0),
            anchors: Arc::new(AnchorShared::new()),
            incidents: Mutex::new(BTreeSet::new()),
            prune_backlog_days: AtomicU32::new(0),
        })
    }
}

/// Everything the writer needs besides its connection.
pub(crate) struct WriterParts {
    pub(crate) clock: Arc<dyn crate::clock::Clock>,
    pub(crate) kek: Kek,
    pub(crate) shared: Arc<Shared>,
    pub(crate) hooks: Hooks,
    /// `GENESIS`'s `record_hash` from the first-retained anchor, for a store whose `GENESIS`
    /// is already pruned (a retained `GENESIS` row wins).
    pub(crate) genesis_hash: Option<[u8; 32]>,
}

pub(crate) type AppendReply = SyncSender<Result<Vec<Committed>, AuditError>>;

pub(crate) enum Cmd {
    Append {
        evs: Vec<PreparedEvent>,
        reply: AppendReply,
    },
    ObserveDate {
        server: UtcInstant,
        local: UtcInstant,
        mono_at: Duration,
    },
    /// Startup step 4 (§8.13): the pending migrations and their `SCHEMA_MIGRATED` rows.
    Migrate {
        reply: SyncSender<Result<Option<(u32, u32)>, OpenError>>,
    },
    /// `meta.written_by` = this build (after startup step 4, §8.13).
    SetWrittenBy {
        reply: SyncSender<Result<(), OpenError>>,
    },
    /// A prune run (C.3 `Store::prune`); `confirm` lifts the clamp and the cadence check.
    Prune {
        confirm: Option<Confirmed>,
        reply: SyncSender<Result<PruneOutcome, AuditError>>,
    },
    /// The settings prune uses until T12's view (feature `testing`).
    #[cfg(any(test, feature = "testing"))]
    SetSettings {
        settings: Settings,
        reply: SyncSender<Result<(), AuditError>>,
    },
    /// What `reconcile_config_file` (T12) records: prune may run in this process.
    #[cfg(any(test, feature = "testing"))]
    SetConfigReconciled {
        reply: SyncSender<Result<(), AuditError>>,
    },
    #[cfg(any(test, feature = "testing"))]
    Pragma {
        name: &'static str,
        reply: SyncSender<Result<i64, AuditError>>,
    },
    /// `testing::insert_fake_prune`: a `prune_log` row and its `PRUNE` record at a chosen
    /// seq, without the prune rules. `anchor` = `(chain_id, genesis_hash)` installs the prune
    /// barrier for the first-retained update.
    #[cfg(any(test, feature = "testing"))]
    FakePrune {
        prune: crate::testing::FakePrune,
        anchor: Option<(String, [u8; 32])>,
        reply: SyncSender<Result<Committed, AuditError>>,
    },
    Shutdown,
}

pub(crate) struct WriterState {
    pub(crate) clock: Arc<dyn crate::clock::Clock>,
    pub(crate) clock_state: ClockState,
    pub(crate) head: Head,
    kek: Kek,
    pub(crate) shared: Arc<Shared>,
    pub(crate) hooks: Hooks,
    /// `GENESIS`'s `record_hash` (the first-retained anchor names it); `None`: unknown, and
    /// prune fails closed.
    pub(crate) genesis_hash: Option<[u8; 32]>,
    /// The settings in force (T12 replaces this with its view).
    pub(crate) settings: Settings,
    /// The config file was reconciled in this process (T12): until then no prune runs.
    pub(crate) config_reconciled: bool,
    /// An automatic prune attempt is queued; it runs between commands.
    pub(crate) prune_due: bool,
    /// The head epoch at the last published commit (an advance queues an attempt).
    published_epoch: Option<NaiveDate>,
    /// Reasons a prune-skip `CLOCK_ANOMALY` was logged for in this process.
    pub(crate) skips_logged: BTreeSet<&'static str>,
    /// The head `ts_utc` a `ClockBeforeHead` skip was measured against: its own anomaly row
    /// (stamped with the earlier `now`) must not disarm the guard.
    pub(crate) clock_floor: Option<UtcInstant>,
    /// A fault point simulated a crash: the writer stops (feature `testing`).
    pub(crate) crashed: bool,
}

impl WriterState {
    fn new(parts: WriterParts, clock_state: ClockState, head: Head) -> WriterState {
        WriterState {
            clock: parts.clock,
            published_epoch: clock_state.prev_epoch,
            clock_state,
            head,
            kek: parts.kek,
            shared: parts.shared,
            hooks: parts.hooks,
            genesis_hash: parts.genesis_hash,
            settings: Settings::default(),
            config_reconciled: false,
            prune_due: false,
            skips_logged: BTreeSet::new(),
            clock_floor: None,
            crashed: false,
        }
    }

    fn into_parts(self) -> WriterParts {
        WriterParts {
            clock: self.clock,
            kek: self.kek,
            shared: self.shared,
            hooks: self.hooks,
            genesis_hash: self.genesis_hash,
        }
    }
}

pub(crate) struct Writer {
    pub(crate) conn: Connection,
    pub(crate) st: WriterState,
}

/// `(seq, record_hash, chain_id, epoch, ts_utc, flags)` of the head row, as stored.
type HeadRow = (i64, Vec<u8>, String, Option<String>, String, i64);

fn insert_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let marks: Vec<String> = (1..=FIELD_LIST.len() + 1)
            .map(|i| format!("?{i}"))
            .collect();
        format!(
            "INSERT INTO events ({}, record_hash) VALUES ({})",
            FIELD_LIST.join(", "),
            marks.join(", ")
        )
    })
}

/// Binds the 29 `FIELD_LIST` values with their SQLite types (TEXT vs BLOB matters to
/// `RowFields::from_row`) plus `record_hash`.
fn insert_row(
    tx: &Transaction<'_>,
    f: &RowFields<'_>,
    record_hash: &[u8; 32],
) -> Result<(), AuditError> {
    let peer_pid = f.peer_pid.map(int).transpose()?;
    let mut st = tx.prepare_cached(insert_sql()).map_err(sql)?;
    st.execute(rusqlite::params![
        int(f.seq)?,
        int(f.format_version)?,
        f.chain_id,
        f.ts_utc,
        f.epoch,
        f.request_id,
        f.event_type,
        f.op_id,
        f.op_class,
        f.instance_id,
        f.target,
        f.agent_name,
        f.agent_name_source,
        f.client_kind,
        f.connection_id,
        peer_pid,
        f.peer_exe,
        f.peer_origin_exe,
        f.os_user,
        f.atlassian_user,
        f.atlassian_user_key,
        f.decision,
        int(f.flags)?,
        int(f.payload_len)?,
        &f.payload_sha256[..],
        int(f.key_id)?,
        &f.nonce[..],
        f.payload_ct,
        &f.prev_hash[..],
        &record_hash[..],
    ])
    .map_err(sql)?;
    Ok(())
}

impl WriterState {
    /// The DEK for a record of `epoch` (§8.6): the newest live key of that month (`month IS
    /// NULL` for a NULL epoch), created if missing. Keys created here go to `new_keys` and
    /// reach the shared cache only after `COMMIT` (a rolled-back key row must never be cached).
    fn dek_for(
        &self,
        tx: &Transaction<'_>,
        epoch: Option<NaiveDate>,
        ts: &str,
        mono: Duration,
        new_keys: &mut HashMap<u64, Dek>,
    ) -> Result<(u64, Dek), AuditError> {
        let month = epoch.map(month_text);
        let found: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT key_id, wrapped_dek FROM keys WHERE month IS ?1 AND wrapped_dek IS NOT NULL \
                 ORDER BY key_id DESC LIMIT 1",
                [&month],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(sql)?;
        if let Some((id, wrapped)) = found {
            let id = u64::try_from(id)
                .map_err(|_| AuditError::AppendFailed("negative key_id".into()))?;
            if let Some(d) = new_keys.get(&id) {
                return Ok((id, d.clone()));
            }
            if let Some(d) = lock(&self.shared.dek_cache).get(&id) {
                return Ok((id, d.clone()));
            }
            let dek = crypto::unwrap_dek(&self.kek, id, month.as_deref(), &wrapped)
                .map_err(|_| AuditError::AppendFailed(format!("data key {id} does not unwrap")))?;
            new_keys.insert(id, dek.clone());
            return Ok((id, dek));
        }
        // Never a DEK for a month after the corroborated date (§8.6). Normal operation only
        // creates a month key when a corroborated epoch enters the month; a missing key for an
        // uncorroborated `prev_epoch` month means the `keys` table lost a row: fail closed.
        if let Some(e) = epoch {
            let allowed = matches!(
                self.clock_state.corroborated_date(mono),
                Some(cd) if (e.year(), e.month()) <= (cd.year(), cd.month())
            );
            if !allowed {
                return Err(AuditError::AppendFailed(
                    "refusing to create a data key for a month that is not corroborated".into(),
                ));
            }
        }
        let next: i64 = tx
            .query_row("SELECT COALESCE(MAX(key_id), 0) + 1 FROM keys", [], |r| {
                r.get(0)
            })
            .map_err(sql)?;
        let id =
            u64::try_from(next).map_err(|_| AuditError::AppendFailed("negative key_id".into()))?;
        let dek = Dek::generate()?;
        let wrapped = crypto::wrap_dek(&self.kek, id, month.as_deref(), &dek)?;
        tx.execute(
            "INSERT INTO keys(key_id, month, wrapped_dek, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![next, month, wrapped, ts],
        )
        .map_err(sql)?;
        new_keys.insert(id, dek.clone());
        Ok((id, dek))
    }

    /// F.3 steps 4–5, `record_hash`, insert; advances the in-memory head.
    fn insert_one(
        &mut self,
        tx: &Transaction<'_>,
        st: &Stamp,
        p: &PreparedEvent,
        mono: Duration,
        new_keys: &mut HashMap<u64, Dek>,
    ) -> Result<Committed, AuditError> {
        let ts = ts_text(st.ts_utc)?;
        let epoch = st.epoch.map(epoch_text);
        let (key_id, dek) = self.dek_for(tx, st.epoch, &ts, mono, new_keys)?;
        let seq = self
            .head
            .seq
            .checked_add(1)
            .filter(|s| i64::try_from(*s).is_ok())
            .ok_or_else(|| AuditError::AppendFailed("seq exhausted".into()))?;
        let flags = (p.flags & EventFlags::CALLER_SETTABLE) | st.clock_flags | p.store_flags;
        let nonce = crypto::random_nonce()?;
        let mut fields = RowFields {
            seq,
            format_version: FORMAT_VERSION,
            chain_id: &self.head.chain_id,
            ts_utc: &ts,
            epoch: epoch.as_deref(),
            request_id: p.request_id.as_deref(),
            event_type: p.event_type.as_str(),
            op_id: p.op_id.as_deref(),
            op_class: p.op_class.as_deref(),
            instance_id: p.instance_id.as_deref(),
            target: p.target.as_deref(),
            agent_name: p.agent_name.as_deref(),
            agent_name_source: p.agent_name_source.as_deref(),
            client_kind: p.client_kind.as_deref(),
            connection_id: p.connection_id.as_deref(),
            peer_pid: p.peer_pid,
            peer_exe: p.peer_exe.as_deref(),
            peer_origin_exe: p.peer_origin_exe.as_deref(),
            os_user: p.os_user.as_deref(),
            atlassian_user: p.atlassian_user.as_deref(),
            atlassian_user_key: p.atlassian_user_key.as_deref(),
            decision: p.decision,
            flags: flags.bits(),
            payload_len: p.payload_len,
            payload_sha256: &p.payload_sha256,
            key_id,
            nonce: &nonce,
            payload_ct: &[],
            prev_hash: &self.head.hash,
        };
        let aad = encoding::aad(&fields)?;
        let ct = crypto::seal(&dek, &nonce, &aad, &p.compressed)?;
        fields.payload_ct = &ct;
        let record_hash = fields.record_hash()?;
        insert_row(tx, &fields, &record_hash)?;
        self.head = Head {
            seq,
            hash: record_hash,
            chain_id: self.head.chain_id.clone(),
        };
        Ok(Committed { seq, record_hash })
    }

    /// Stamps and inserts `evs` in order, preceded by a `CLOCK_ANOMALY` row when a
    /// local-behind episode starts. Returns the caller's rows only.
    fn insert_all(
        &mut self,
        tx: &Transaction<'_>,
        evs: Vec<PreparedEvent>,
        new_keys: &mut HashMap<u64, Dek>,
    ) -> Result<Vec<Committed>, AuditError> {
        let mono = self.clock.suspend_aware_elapsed();
        if let Some(a) = self
            .clock_state
            .behind_transition(self.clock.now_utc(), mono)
        {
            let row = PreparedEvent::clock_anomaly(&a)?;
            let st = self.clock_state.stamp(self.clock.now_utc(), mono);
            self.insert_one(tx, &st, &row, mono, new_keys)?;
            fault!(self.hooks, WriterAfterRow);
        }
        let mut out = Vec::with_capacity(evs.len());
        for p in &evs {
            let st = self.clock_state.stamp(self.clock.now_utc(), mono);
            out.push(self.insert_one(tx, &st, p, mono, new_keys)?);
            fault!(self.hooks, WriterAfterRow);
        }
        Ok(out)
    }

    /// One store-written row, stamped now, inside the caller's transaction. No clock-episode
    /// row goes before it (callers bind the row's seq in advance); the episode is logged with
    /// the next append.
    pub(crate) fn append_in_tx(
        &mut self,
        tx: &Transaction<'_>,
        p: &PreparedEvent,
        new_keys: &mut HashMap<u64, Dek>,
    ) -> Result<Committed, AuditError> {
        let mono = self.clock.suspend_aware_elapsed();
        let stamp = self.clock_state.stamp(self.clock.now_utc(), mono);
        self.insert_one(tx, &stamp, p, mono, new_keys)
    }

    /// After `COMMIT` returned: publish the head and the new keys, and hand the head to the
    /// anchor thread (never blocks on the keychain). A head whose epoch date advanced queues
    /// a prune attempt (L37 cadence).
    pub(crate) fn post_commit(
        &mut self,
        new_keys: HashMap<u64, Dek>,
        incidents: &[IncidentChange],
    ) {
        if self.clock_state.prev_epoch > self.published_epoch {
            self.prune_due = true;
        }
        self.published_epoch = self.clock_state.prev_epoch;
        lock(&self.shared.dek_cache).extend(new_keys);
        if !incidents.is_empty() {
            let mut open = lock(&self.shared.incidents);
            for c in incidents {
                match *c {
                    IncidentChange::Opened(seq) => open.insert(seq),
                    IncidentChange::Acknowledged(seq) => open.remove(&seq),
                };
            }
        }
        *lock(&self.shared.head) = HeadView {
            seq: self.head.seq,
            hash: self.head.hash,
            chain_id: self.head.chain_id.clone(),
        };
        self.shared.anchors.publish_head(HeadAnchor {
            chain_id: self.head.chain_id.clone(),
            seq: self.head.seq,
            record_hash: self.head.hash,
        });
    }
}

fn open_conn(path: &Path, flags: OpenFlags, hooks: &Hooks) -> Result<Connection, OpenError> {
    let conn = Connection::open_with_flags(path, flags).map_err(sql_open)?;
    schema::apply_connection_pragmas(&conn).map_err(sql_open)?;
    #[cfg(any(test, feature = "testing"))]
    if hooks.synchronous_normal {
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(sql_open)?;
    }
    #[cfg(not(any(test, feature = "testing")))]
    let _ = hooks;
    Ok(conn)
}

impl Writer {
    /// A new, empty database file at `path` with schema v1 and no record yet (first run).
    pub(crate) fn create(
        path: &Path,
        parts: WriterParts,
        chain_id: &str,
    ) -> Result<Writer, OpenError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(sql_open)?;
        schema::create_v1(&conn).map_err(sql_open)?;
        drop(conn);
        let conn = open_conn(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            &parts.hooks,
        )?;
        let head = Head {
            seq: 0,
            hash: ZERO_HASH,
            chain_id: chain_id.to_string(),
        };
        Ok(Writer {
            conn,
            st: WriterState::new(parts, ClockState::default(), head),
        })
    }

    /// Opens an existing store read-write (never creates it), runs the version gate on this
    /// WAL-aware connection and loads the head. Writes nothing.
    pub(crate) fn open(path: &Path, parts: WriterParts) -> Result<Writer, OpenError> {
        let conn = open_conn(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            &parts.hooks,
        )?;
        schema::gate_open_connection_up_to(&conn, parts.hooks.schema_head())?;
        let row: Option<HeadRow> = conn
            .query_row(
                "SELECT seq, record_hash, chain_id, epoch, ts_utc, flags FROM events \
                 ORDER BY seq DESC LIMIT 1",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(sql_open)?;
        let (seq, hash, chain_id, epoch, ts, flags) =
            row.ok_or_else(|| OpenError::Integrity("the store has no records".into()))?;
        let bad = |what: &str| OpenError::Integrity(format!("head record has an invalid {what}"));
        let seq = u64::try_from(seq).map_err(|_| bad("seq"))?;
        let hash: [u8; 32] = hash.try_into().map_err(|_| bad("record_hash"))?;
        let epoch = epoch
            .map(|e| parse_epoch(&e).ok_or_else(|| bad("epoch")))
            .transpose()?;
        let ts = UtcInstant::parse_rfc3339_ms(&ts).ok_or_else(|| bad("ts_utc"))?;
        let flags = EventFlags::from_bits(u64::try_from(flags).map_err(|_| bad("flags"))?);
        *lock(&parts.shared.incidents) = crate::incidents::load_open(&conn, &parts.kek)?;
        let genesis: Option<Vec<u8>> = conn
            .query_row(
                "SELECT record_hash FROM events WHERE seq = 1 AND event_type = 'GENESIS'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql_open)?;
        let mut parts = parts;
        if let Some(g) = genesis {
            parts.genesis_hash = Some(g.try_into().map_err(|_| bad("GENESIS record_hash"))?);
        }
        let head = Head {
            seq,
            hash,
            chain_id,
        };
        let st = WriterState::new(parts, ClockState::from_head(epoch, ts, flags), head);
        *lock(&st.shared.head) = HeadView {
            seq,
            hash,
            chain_id: st.head.chain_id.clone(),
        };
        Ok(Writer { conn, st })
    }

    /// `GENESIS` (seq 1, F.11), the uncorroborated DEK (key_id 1, `month` NULL) and the
    /// `recovery` row, in one transaction on a store created by [`Writer::create`].
    pub(crate) fn write_genesis(
        &mut self,
        recovery_blob: &[u8],
        install_id: &str,
        archived_db: Option<Value>,
    ) -> Result<Committed, AuditError> {
        if self.st.head.seq != 0 {
            return Err(AuditError::AppendFailed(
                "GENESIS on a non-empty store".into(),
            ));
        }
        let st = &mut self.st;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let mono = st.clock.suspend_aware_elapsed();
        let stamp = st.clock_state.stamp(st.clock.now_utc(), mono);
        let created_at = ts_text(stamp.ts_utc)?;
        let mut p = PreparedEvent::system(
            EventType::GENESIS,
            &json!({
                "chain_id": st.head.chain_id,
                "install_id": install_id,
                "created_at": created_at,
                "archived_db": archived_db.unwrap_or(Value::Null),
                "previous_chain_id": null,
                "previous_last_anchor": null,
            }),
        )?;
        p.target = Some(install_id.to_string());
        tx.execute(
            "INSERT INTO recovery(id, blob, created_at) VALUES (1, ?1, ?2)",
            rusqlite::params![recovery_blob, created_at],
        )
        .map_err(sql)?;
        let mut new_keys = HashMap::new();
        let c = st.insert_one(&tx, &stamp, &p, mono, &mut new_keys)?;
        tx.commit().map_err(sql)?;
        st.genesis_hash = Some(c.record_hash);
        st.post_commit(new_keys, &[]);
        Ok(c)
    }

    /// Checkpoints and closes the connection so the file can be renamed, then fsyncs it. Fails
    /// if SQLite left a non-empty `-wal` behind (renaming only the main file would lose it).
    pub(crate) fn close_for_rename(self, path: &Path) -> Result<WriterParts, OpenError> {
        let Writer { conn, st } = self;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(sql_open)?;
        conn.close().map_err(|(_, e)| sql_open(e))?;
        for suffix in ["-wal", "-shm"] {
            let mut side = path.as_os_str().to_owned();
            side.push(suffix);
            let side = std::path::PathBuf::from(side);
            match std::fs::metadata(&side) {
                Ok(m) if suffix == "-wal" && m.len() > 0 => {
                    return Err(OpenError::Integrity(
                        "the new store kept a non-empty write-ahead log".into(),
                    ));
                }
                Ok(_) => std::fs::remove_file(&side)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?
            .sync_all()?;
        Ok(st.into_parts())
    }

    /// One append command: one transaction, all or nothing. On any error the transaction rolls
    /// back and the in-memory clock state and head are restored to their values before it.
    pub(crate) fn append_tx(
        &mut self,
        evs: Vec<PreparedEvent>,
    ) -> Result<Vec<Committed>, AuditError> {
        {
            let open = lock(&self.st.shared.incidents);
            if evs
                .iter()
                .any(|p| p.ack_of.is_some_and(|v| !open.contains(&v)))
            {
                return Err(AuditError::Invalid("not an open integrity incident"));
            }
        }
        let effects: Vec<(bool, Option<u64>)> = evs
            .iter()
            .map(|p| {
                let opens = p.event_type == EventType::VERIFY
                    && p.store_flags.contains(EventFlags::INTEGRITY_INCIDENT);
                (opens, p.ack_of)
            })
            .collect();
        let snapshot = (self.st.clock_state.clone(), self.st.head.clone());
        let mut new_keys = HashMap::new();
        let st = &mut self.st;
        let result = (|| -> Result<Vec<Committed>, AuditError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql)?;
            let out = st.insert_all(&tx, evs, &mut new_keys)?;
            fault!(st.hooks, WriterBeforeCommit);
            tx.commit().map_err(sql)?;
            Ok(out)
        })();
        match &result {
            Ok(out) => {
                let mut changes = Vec::new();
                for (c, (opens, ack)) in out.iter().zip(&effects) {
                    if *opens {
                        changes.push(IncidentChange::Opened(c.seq));
                    }
                    if let Some(v) = ack {
                        changes.push(IncidentChange::Acknowledged(*v));
                    }
                }
                self.st.post_commit(new_keys, &changes);
            }
            Err(_) => (self.st.clock_state, self.st.head) = snapshot,
        }
        result
    }

    /// A server `Date` (§8.8 source (a)). A local-ahead episode start is logged as its own
    /// `CLOCK_ANOMALY` row; if that append fails the corroboration is forgotten too (it is
    /// repeated on the next response), so the episode is not silently marked as logged.
    /// The first corroboration of the process queues a prune attempt (L37 cadence).
    fn observe(&mut self, server: UtcInstant, local: UtcInstant, mono_at: Duration) {
        let before = self.st.clock_state.clone();
        if let Some(a) = self.st.clock_state.observe(server, local, mono_at) {
            let logged = PreparedEvent::clock_anomaly(&a).and_then(|row| self.append_tx(vec![row]));
            if logged.is_err() {
                self.st.clock_state = before.clone();
            }
        }
        if !before.is_corroborated() && self.st.clock_state.is_corroborated() {
            self.st.prune_due = true;
        }
    }

    /// A queued automatic attempt. One deferred by the unreconciled config file stays queued.
    fn run_queued_prune(&mut self) {
        let r = self.prune_run(None);
        self.st.prune_due = matches!(r, Ok(PruneOutcome::Skipped(PruneSkip::ConfigNotReconciled)));
    }

    /// Every pending migration step in one transaction, each followed by its
    /// `SCHEMA_MIGRATED {from, to, app_version}` row in that transaction (§8.13). On error
    /// everything rolls back (`MigrationFailed`) and the in-memory clock state and head are
    /// restored; a DEK created for a rolled-back row never reaches the cache.
    fn migrate(&mut self) -> Result<Option<(u32, u32)>, OpenError> {
        let migrations = self.st.hooks.migrations();
        let snapshot = (self.st.clock_state.clone(), self.st.head.clone());
        let mut new_keys = HashMap::new();
        let st = &mut self.st;
        let result = schema::run_migrations(&mut self.conn, &migrations, &mut |tx, from, to| {
            let p = PreparedEvent::system(
                EventType::SCHEMA_MIGRATED,
                &json!({ "from": from, "to": to, "app_version": APP_VERSION }),
            )?;
            st.append_in_tx(tx, &p, &mut new_keys)?;
            Ok(())
        });
        match &result {
            Ok(Some(_)) => self.st.post_commit(new_keys, &[]),
            Ok(None) => {}
            Err(_) => (self.st.clock_state, self.st.head) = snapshot,
        }
        result
    }

    /// Deletes `seq < first_retained_seq`, writes the next `prune_log` row and its `PRUNE`
    /// in one transaction (no DEK destruction, no clock or cadence rules).
    #[cfg(any(test, feature = "testing"))]
    fn fake_prune(
        &mut self,
        p: &crate::testing::FakePrune,
        anchor: Option<(String, [u8; 32])>,
    ) -> Result<Committed, AuditError> {
        let snapshot = (self.st.clock_state.clone(), self.st.head.clone());
        let mut new_keys = HashMap::new();
        let st = &mut self.st;
        let to32 = |v: Vec<u8>| {
            <[u8; 32]>::try_from(v).map_err(|_| AuditError::Invalid("hash is not 32 bytes"))
        };
        let result = (|| -> Result<(Committed, u64, [u8; 32]), AuditError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql)?;
            let latest: Option<(i64, Vec<u8>, Vec<u8>)> = tx
                .query_row(
                    "SELECT first_retained_seq, last_pruned_record_hash, row_hash FROM prune_log \
                     ORDER BY prune_seq DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
                .map_err(sql)?;
            let (range_start, carried, prev_row_hash) = match latest {
                Some((f, l, h)) => (
                    u64::try_from(f).map_err(|_| AuditError::Invalid("negative seq"))?,
                    to32(l)?,
                    to32(h)?,
                ),
                None => (1, ZERO_HASH, ZERO_HASH),
            };
            let frs = p.first_retained_seq;
            let prune_seq = st.head.seq + 1;
            if frs < range_start || frs > prune_seq {
                return Err(AuditError::Invalid(
                    "first_retained_seq outside the prunable range",
                ));
            }
            let last_pruned = if frs > range_start {
                to32(
                    tx.query_row(
                        "SELECT record_hash FROM events WHERE seq = ?1",
                        [int(frs - 1)?],
                        |r| r.get(0),
                    )
                    .map_err(sql)?,
                )?
            } else {
                carried
            };
            tx.execute("DELETE FROM events WHERE seq < ?1", [int(frs)?])
                .map_err(sql)?;
            let row_hash = encoding::prune_row_hash(
                &prev_row_hash,
                prune_seq,
                range_start,
                &p.cutoff,
                &last_pruned,
                frs,
            );
            tx.execute(
                "INSERT INTO prune_log (prune_seq, range_start, cutoff_epoch, \
                 last_pruned_record_hash, first_retained_seq, prev_row_hash, row_hash) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    int(prune_seq)?,
                    int(range_start)?,
                    p.cutoff,
                    &last_pruned[..],
                    int(frs)?,
                    &prev_row_hash[..],
                    &row_hash[..],
                ],
            )
            .map_err(sql)?;
            let ev = PreparedEvent::system(
                EventType::PRUNE,
                &json!({
                    "range": [range_start, frs],
                    "count": frs - range_start,
                    "cutoff": p.cutoff,
                    "clamped": false,
                    "baseline": p.cutoff,
                    "destroyed_key_ids": [],
                    "prune_log_row_hash": hex::encode(row_hash),
                    "settings": p.settings,
                }),
            )?;
            let c = st.append_in_tx(&tx, &ev, &mut new_keys)?;
            if c.seq != prune_seq {
                return Err(AuditError::AppendFailed(
                    "PRUNE did not get the expected seq".into(),
                ));
            }
            tx.commit().map_err(sql)?;
            Ok((c, frs, last_pruned))
        })();
        match result {
            Ok((c, frs, last_pruned)) => {
                // Before the head is published, as a real prune does (T08 handoff).
                if let Some((chain_id, genesis_hash)) = anchor
                    && let Ok(g) = self.st.shared.anchors.install_barrier(Barrier::Prune {
                        seq: c.seq,
                        record_hash: c.record_hash,
                        first_retained: FirstRetainedAnchor {
                            chain_id,
                            genesis_hash,
                            first_retained_seq: frs,
                            first_retained_prev_hash: last_pruned,
                        },
                    })
                {
                    g.complete();
                }
                self.st.post_commit(new_keys, &[]);
                Ok(c)
            }
            Err(e) => {
                (self.st.clock_state, self.st.head) = snapshot;
                Err(e)
            }
        }
    }

    fn run(mut self, rx: Receiver<Cmd>) {
        while let Ok(cmd) = rx.recv() {
            #[cfg(any(test, feature = "testing"))]
            let _ = self.st.hooks.fault(crate::testing::FaultPoint::WriterPause);
            match cmd {
                Cmd::Append { evs, reply } => {
                    let r = self.append_tx(evs);
                    let _ = reply.send(r);
                }
                Cmd::ObserveDate {
                    server,
                    local,
                    mono_at,
                } => self.observe(server, local, mono_at),
                Cmd::Migrate { reply } => {
                    let r = self.migrate();
                    let _ = reply.send(r);
                }
                Cmd::SetWrittenBy { reply } => {
                    let r = schema::set_written_by(&self.conn).map_err(sql_open);
                    let _ = reply.send(r);
                }
                Cmd::Prune { confirm, reply } => {
                    let r = self.prune_run(confirm.as_ref());
                    let _ = reply.send(r);
                }
                #[cfg(any(test, feature = "testing"))]
                Cmd::SetSettings { settings, reply } => {
                    self.st.settings = settings;
                    let _ = reply.send(Ok(()));
                }
                #[cfg(any(test, feature = "testing"))]
                Cmd::SetConfigReconciled { reply } => {
                    self.st.config_reconciled = true;
                    let _ = reply.send(Ok(()));
                }
                #[cfg(any(test, feature = "testing"))]
                Cmd::Pragma { name, reply } => {
                    let r = self
                        .conn
                        .pragma_query_value(None, name, |r| r.get::<_, i64>(0))
                        .map_err(|e| AuditError::Io(e.to_string()));
                    let _ = reply.send(r);
                }
                #[cfg(any(test, feature = "testing"))]
                Cmd::FakePrune {
                    prune,
                    anchor,
                    reply,
                } => {
                    let r = self.fake_prune(&prune, anchor);
                    let _ = reply.send(r);
                }
                Cmd::Shutdown => break,
            }
            if !self.st.crashed && self.st.prune_due {
                self.run_queued_prune();
            }
            if self.st.crashed {
                break;
            }
        }
    }
}

/// Starts the `audit-writer` thread. `init` runs on that thread (so only the writer thread
/// ever holds the read-write connection) and its error is returned here.
pub(crate) fn spawn<F>(init: F) -> Result<(SyncSender<Cmd>, JoinHandle<()>), OpenError>
where
    F: FnOnce() -> Result<Writer, OpenError> + Send + 'static,
{
    let (tx, rx) = sync_channel::<Cmd>(CHANNEL_BOUND);
    let (itx, irx) = sync_channel::<Result<(), OpenError>>(1);
    let handle = std::thread::Builder::new()
        .name("audit-writer".into())
        .spawn(move || match init() {
            Ok(w) => {
                let _ = itx.send(Ok(()));
                w.run(rx);
            }
            Err(e) => {
                let _ = itx.send(Err(e));
            }
        })?;
    match irx.recv() {
        Ok(Ok(())) => Ok((tx, handle)),
        Ok(Err(e)) => {
            let _ = handle.join();
            Err(e)
        }
        Err(_) => {
            let _ = handle.join();
            Err(OpenError::Io(std::io::Error::other(
                "the audit writer thread stopped during start",
            )))
        }
    }
}
