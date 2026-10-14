//! The one path from `core` to the audit store (C.3), and the audit-before-effect seam
//! (§5.1 inv. 1): `CommittedSet` holds the ids whose start record (`REQUEST_RECEIVED`,
//! `SCRIPT_STARTED`, `SYSTEM_FETCH {phase: start}`) is durably committed, and per write the
//! revision of its latest committed `WRITE_APPROVED` (Δ6); `StoreProbe` answers
//! `atlassian::CoverIssuer` from it, so no PAT-bearing request is sent before that commit and no
//! write before its approval's. An id enters the set only through `commit_request_received` /
//! `commit_system_fetch_start` / `commit_records`, and only after `AuditPort::append` (or
//! `append_batch`) returned `Ok`; an `Err` marks nothing (fail closed).
//! "`Ok`" means "durably committed" only for the real `Store` port: the composition root
//! (`core.rs`) wires `StoreProbe` over the set that the `Store` port commits to, and Task 30's
//! scanner keeps other `AuditPort`/`CommitProbe` impls and `CoverIssuer::new` calls in tests.
//!
//! If M2's store API changes, adapt this file and `testing/store.rs` only.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime};

use atlas_duck_atlassian::{CommitProbe, DateObserver};
use atlas_duck_audit::{
    AuditError, Committed, Confirmed, EventHeader, EventType, FilePolicy, NewEvent, QueryKind,
    ReconcileReport, SettingChange, Settings, Store,
};
use serde_json::Value;
use zeroize::Zeroizing;

/// The audit store as `core` sees it: exactly one production impl (`audit::Store`) and the
/// `testing` wrappers. Every method blocks until the store answered (appends: until the
/// `synchronous=FULL` commit); async callers go through `spawn_blocking` (PD-25).
pub trait AuditPort: Send + Sync {
    /// `Ok` only after the commit is durable; on `Err` nothing was committed.
    fn append(&self, ev: NewEvent) -> Result<Committed, AuditError>;
    /// All or nothing, in one transaction.
    fn append_batch(&self, evs: Vec<NewEvent>) -> Result<Vec<Committed>, AuditError>;
    /// Low-space admission (§8.1): `StorageLow` refuses a submit before anything is queued.
    fn admission_check(&self) -> Result<(), AuditError>;
    /// `"jql:<hex>"` / `"cql:<hex>"` for `NewEvent.target` (L38).
    fn query_tag(&self, kind: QueryKind, query: &str) -> String;
    /// The decrypted JCS payload. Its `Debug` prints the bytes: never `Debug`-format or log it.
    fn read_payload(&self, seq: u64) -> Result<Zeroizing<Vec<u8>>, AuditError>;
    fn headers_for_request(&self, request_id: &str) -> Result<Vec<EventHeader>, AuditError>;
    /// A full scan of `events`: call it once per listing or seeding, never per request.
    fn recent_headers(&self, since: Duration) -> Result<Vec<EventHeader>, AuditError>;
    /// Startup only (it races live appends). An `Err` is an integrity problem that
    /// `Core::start` must surface as a `StartError`, with no `APP_START` (Task 28).
    fn reconcile_after_crash(&self) -> Result<ReconcileReport, AuditError>;
    /// A server `Date` header seen at `at` (§8.8 corroboration). Never blocks on the writer.
    fn observe_server_date(&self, instance_id: &str, d: SystemTime, at: Instant);
    fn settings(&self) -> Settings;
    fn apply_setting(
        &self,
        c: SettingChange,
        confirmed: Option<Confirmed>,
    ) -> Result<Committed, AuditError>;
    fn flush_head_anchor(&self) -> Result<(), AuditError>;
    /// X-01 (§8.8): logs the `config.toml` audit-policy values that differ from the settings in
    /// force and lets prune run in this process. `Core::start` calls it before anything else
    /// that appends; an `Err` leaves prune blocked.
    fn reconcile_config_file(&self, file: &FilePolicy) -> Result<Vec<Committed>, AuditError>;
}

impl AuditPort for Store {
    fn append(&self, ev: NewEvent) -> Result<Committed, AuditError> {
        Store::append(self, ev)
    }

    fn append_batch(&self, evs: Vec<NewEvent>) -> Result<Vec<Committed>, AuditError> {
        Store::append_batch(self, evs)
    }

    fn admission_check(&self) -> Result<(), AuditError> {
        Store::admission_check(self)
    }

    fn query_tag(&self, kind: QueryKind, query: &str) -> String {
        Store::query_tag(self, kind, query)
    }

    fn read_payload(&self, seq: u64) -> Result<Zeroizing<Vec<u8>>, AuditError> {
        Store::read_payload(self, seq)
    }

    fn headers_for_request(&self, request_id: &str) -> Result<Vec<EventHeader>, AuditError> {
        Store::headers_for_request(self, request_id)
    }

    fn recent_headers(&self, since: Duration) -> Result<Vec<EventHeader>, AuditError> {
        Store::recent_headers(self, since)
    }

    fn reconcile_after_crash(&self) -> Result<ReconcileReport, AuditError> {
        Store::reconcile_after_crash(self)
    }

    fn observe_server_date(&self, instance_id: &str, d: SystemTime, at: Instant) {
        Store::observe_server_date(self, instance_id, d, at)
    }

    fn settings(&self) -> Settings {
        Store::settings(self)
    }

    fn apply_setting(
        &self,
        c: SettingChange,
        confirmed: Option<Confirmed>,
    ) -> Result<Committed, AuditError> {
        Store::apply_setting(self, c, confirmed)
    }

    fn flush_head_anchor(&self) -> Result<(), AuditError> {
        Store::flush_head_anchor(self)
    }

    fn reconcile_config_file(&self, file: &FilePolicy) -> Result<Vec<Committed>, AuditError> {
        Store::reconcile_config_file(self, file)
    }
}

/// Ids whose start record is durably committed, and per write the revision counter of its latest
/// committed `WRITE_APPROVED` (Δ6, M3 final review M-18). In memory only: after a restart nothing
/// is covered until a new start record commits, and no write approved before it can be sent.
#[derive(Debug, Default)]
pub struct CommittedSet {
    requests: RwLock<HashSet<String>>,
    fetches: RwLock<HashSet<String>>,
    approvals: RwLock<HashMap<String, u64>>,
}

fn read<T>(l: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|e| e.into_inner())
}

fn write<T>(l: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|e| e.into_inner())
}

impl CommittedSet {
    /// Only with the `Ok` of the append that committed `REQUEST_RECEIVED` / `SCRIPT_STARTED`.
    /// Private to this module: `commit_request_received` is the one caller, so no other core
    /// code can mark an id (compile-time).
    fn mark_request(&self, request_id: &str) {
        write(&self.requests).insert(request_id.to_owned());
    }

    /// Only with the `Ok` of the append that committed `SYSTEM_FETCH {phase: start}`; private,
    /// like `mark_request` (`commit_system_fetch_start` is the one caller).
    fn mark_fetch(&self, fetch_id: &str) {
        write(&self.fetches).insert(fetch_id.to_owned());
    }

    /// Only with the `Ok` of the append that committed `WRITE_APPROVED` for revision `counter`
    /// of `request_id`; private, like `mark_request` (`commit_records` is the one caller). A
    /// later approval replaces an earlier one.
    fn mark_write_approved(&self, request_id: &str, counter: u64) {
        write(&self.approvals).insert(request_id.to_owned(), counter);
    }

    /// At terminal: no further request is sent under this id (nor its write). Call it only after
    /// `commit_request_received` returned (a `forget` racing the append-to-mark window would
    /// leave the id marked).
    pub fn forget_request(&self, request_id: &str) {
        write(&self.requests).remove(request_id);
        self.forget_write_approved(request_id);
    }

    /// The write holds no live approval any more (it left `StaleCheck`/`Executing`): no write
    /// cover for any of its revisions until a new `WRITE_APPROVED` commits.
    pub fn forget_write_approved(&self, request_id: &str) {
        write(&self.approvals).remove(request_id);
    }

    /// After the fetch's last `phase: result` record.
    pub fn forget_fetch(&self, fetch_id: &str) {
        write(&self.fetches).remove(fetch_id);
    }

    pub fn request_committed(&self, request_id: &str) -> bool {
        read(&self.requests).contains(request_id)
    }

    pub fn fetch_started(&self, fetch_id: &str) -> bool {
        read(&self.fetches).contains(fetch_id)
    }

    /// Revision `counter` is the latest committed approval of `request_id`, whose start record is
    /// committed and which is not terminal.
    pub fn write_approved(&self, request_id: &str, counter: u64) -> bool {
        self.request_committed(request_id)
            && read(&self.approvals).get(request_id) == Some(&counter)
    }
}

/// `atlassian::CommitProbe` over the committed set. Core builds its `CoverIssuer` from this and
/// nothing else (no always-true probe outside tests; Task 30 checks `CoverIssuer::new` callers).
pub struct StoreProbe(pub Arc<CommittedSet>);

impl CommitProbe for StoreProbe {
    fn request_committed(&self, request_id: &str) -> bool {
        self.0.request_committed(request_id)
    }

    fn system_fetch_started(&self, fetch_id: &str) -> bool {
        self.0.fetch_started(fetch_id)
    }

    fn write_approved(&self, request_id: &str, candidate_counter: u64) -> bool {
        self.0.write_approved(request_id, candidate_counter)
    }
}

/// `atlassian::DateObserver` → `AuditPort::observe_server_date` (§8.8 source (a)). The client
/// reports only responses that arrived over a verified TLS connection.
pub struct DateBridge(pub Arc<dyn AuditPort>);

impl DateObserver for DateBridge {
    fn observe(&self, instance_id: &str, server_date: SystemTime, at: Instant) {
        self.0.observe_server_date(instance_id, server_date, at)
    }
}

/// The one place that appends a request's start record (`REQUEST_RECEIVED` or
/// `SCRIPT_STARTED`): on `Ok` the request id is cover-ready, on `Err` nothing is marked. Any
/// other event, or one without a `request_id`, is refused before the append (`Invalid`).
pub fn commit_request_received(
    port: &dyn AuditPort,
    set: &CommittedSet,
    ev: NewEvent,
) -> Result<Committed, AuditError> {
    if !matches!(
        ev.event_type,
        EventType::REQUEST_RECEIVED | EventType::SCRIPT_STARTED
    ) {
        return Err(AuditError::Invalid(
            "a request start record is REQUEST_RECEIVED or SCRIPT_STARTED",
        ));
    }
    let Some(request_id) = ev.request_id.clone() else {
        return Err(AuditError::Invalid(
            "a request start record needs a request_id",
        ));
    };
    let committed = port.append(ev)?;
    set.mark_request(&request_id);
    Ok(committed)
}

/// The one place that appends `SYSTEM_FETCH {phase: "start", fetch_id}` (§8.3): on `Ok`
/// `fetch_id` is cover-ready. The event must be that start record for exactly `fetch_id`.
pub fn commit_system_fetch_start(
    port: &dyn AuditPort,
    set: &CommittedSet,
    ev: NewEvent,
    fetch_id: &str,
) -> Result<Committed, AuditError> {
    let is_start = ev.event_type == EventType::SYSTEM_FETCH
        && ev.request_id.is_none()
        && ev.payload.get("phase").and_then(Value::as_str) == Some("start")
        && ev.payload.get("fetch_id").and_then(Value::as_str) == Some(fetch_id);
    if !is_start {
        return Err(AuditError::Invalid(
            "a system fetch start record is SYSTEM_FETCH {phase: start} for this fetch_id",
        ));
    }
    let committed = port.append(ev)?;
    set.mark_fetch(fetch_id);
    Ok(committed)
}

/// The one place that marks a write approval (Δ6, M3 final review M-18): appends a transition's
/// records (one `append` for one record, else one `append_batch`, in order) and, on `Ok`, marks
/// `(request_id, candidate_rev.counter)` of every `WRITE_APPROVED` among them, so a write cover
/// exists only for a committed approval of that revision. On `Err` nothing is marked. A
/// `WRITE_APPROVED` without a `request_id` or an integer `candidate_rev.counter` refuses the
/// whole call before anything is appended (`Invalid`). Every other record passes through.
/// Crate-private, like `Engine::committed` (T20 review m3): no code outside `core` can mark the
/// engine's set; tests reach it through `testing::commit_records`.
pub(crate) fn commit_records(
    port: &dyn AuditPort,
    set: &CommittedSet,
    mut evs: Vec<NewEvent>,
) -> Result<Vec<Committed>, AuditError> {
    let mut approvals = Vec::new();
    for ev in evs
        .iter()
        .filter(|e| e.event_type == EventType::WRITE_APPROVED)
    {
        let counter = ev
            .payload
            .get("candidate_rev")
            .and_then(|r| r.get("counter"))
            .and_then(Value::as_u64);
        let (Some(request_id), Some(counter)) = (ev.request_id.clone(), counter) else {
            return Err(AuditError::Invalid(
                "a WRITE_APPROVED names its request_id and candidate_rev.counter",
            ));
        };
        approvals.push((request_id, counter));
    }
    let committed = if evs.len() == 1 {
        match evs.pop() {
            Some(ev) => vec![port.append(ev)?],
            None => Vec::new(),
        }
    } else {
        port.append_batch(evs)?
    };
    for (request_id, counter) in &approvals {
        set.mark_write_approved(request_id, *counter);
    }
    Ok(committed)
}
