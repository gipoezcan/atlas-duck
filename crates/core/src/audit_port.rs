//! The one path from `core` to the audit store (C.3), and the audit-before-effect seam
//! (§5.1 inv. 1): `CommittedSet` holds the ids whose start record (`REQUEST_RECEIVED`,
//! `SCRIPT_STARTED`, `SYSTEM_FETCH {phase: start}`) is durably committed; `StoreProbe` answers
//! `atlassian::CoverIssuer` from it, so no PAT-bearing request is sent before that commit.
//! An id enters the set only through `commit_request_received` / `commit_system_fetch_start`,
//! and only after `AuditPort::append` returned `Ok`; an `Err` marks nothing (fail closed).
//! "`Ok`" means "durably committed" only for the real `Store` port: the composition root
//! (`core.rs`) wires `StoreProbe` over the set that the `Store` port commits to, and Task 30's
//! scanner keeps other `AuditPort`/`CommitProbe` impls and `CoverIssuer::new` calls in tests.
//!
//! If M2's store API changes, adapt this file and `testing/store.rs` only.

use std::collections::HashSet;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime};

use atlas_duck_atlassian::{CommitProbe, DateObserver};
use atlas_duck_audit::{
    AuditError, Committed, Confirmed, EventHeader, EventType, NewEvent, QueryKind, ReconcileReport,
    SettingChange, Settings, Store,
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
}

/// Ids whose start record is durably committed. In memory only: after a restart nothing is
/// covered until a new start record commits.
#[derive(Debug, Default)]
pub struct CommittedSet {
    requests: RwLock<HashSet<String>>,
    fetches: RwLock<HashSet<String>>,
}

fn read(l: &RwLock<HashSet<String>>) -> RwLockReadGuard<'_, HashSet<String>> {
    l.read().unwrap_or_else(|e| e.into_inner())
}

fn write(l: &RwLock<HashSet<String>>) -> RwLockWriteGuard<'_, HashSet<String>> {
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

    /// At terminal: no further request is sent under this id. Call it only after
    /// `commit_request_received` returned (a `forget` racing the append-to-mark window would
    /// leave the id marked).
    pub fn forget_request(&self, request_id: &str) {
        write(&self.requests).remove(request_id);
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
