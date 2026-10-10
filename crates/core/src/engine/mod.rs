//! The request broker: the map of pending requests, each with its §5.1 model and a status watch,
//! the hello sessions, the instance table and the audit port. Every state change that has an
//! audit record goes through [`Engine::transition`] (PD-19: step a clone, append, then replace
//! or re-step); appends run on `spawn_blocking` and no entry lock is held across them (PD-25).
//!
//! A request is in the map from the moment its `REQUEST_RECEIVED` is committed and validation
//! passed until its terminal record is committed (T17 M-2: never before the commit returned).
//! Terminal answers then come from the committed records (`status`, `await`, `requests list`).
//! The one exception is a terminal state the store could not record (an append failure, §11.1):
//! the entry stays in memory with its error, since the log cannot say it.
//!
//! Record-bearing transitions of one request are serialized by the entry's transition gate (an
//! async mutex held across clone-step, append and apply), so two racing terminal events (two
//! cancels, cancel against expiry, a decision against a cancel) never both commit. Each
//! transition runs in its own task: a caller whose future is dropped (a client that went away)
//! cannot leave a committed record unapplied to memory.
//!
//! Admission (Task 20, `queue`): an entry holds its admission [`Ticket`] from insertion until it
//! is terminal; `Engine::after_change` drops it there (every terminal path, logged or not, goes
//! through it) together with the cached candidate (`cache`).
//!
//! Reads (Task 21, `read`) and writes (Task 22, `write`) are dispatched right after insertion;
//! `await` hands terminal answers over through `deliver`, which reads the committed records
//! only.

pub mod cache;
pub mod cancel;
pub mod deliver;
pub mod envelope;
pub mod handler;
pub mod queue;
pub mod read;
pub mod write;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard};
use std::time::Duration;

use atlas_duck_atlassian::{
    BuildError, CoverIssuer, CredentialProvider, FetchControl, InstanceClient, ReadBudget,
};
use atlas_duck_audit::ScriptFailedFlags;
use atlas_duck_audit::{AuditError, Clock, EventHeader, EventType, NewEvent, is_terminal};
use atlas_duck_ipc::envelope::{ErrorCode, Status};
use atlas_duck_ipc::proto::{ClientKind, Hello};
use atlas_duck_registry::{OpClass, OperationSpec};
use serde_json::Value;
use tokio::sync::{Semaphore, watch};

use crate::audit_port::{AuditPort, CommittedSet};
use crate::core::NativeConfirmer;
use crate::decision::SessionKey;
use crate::gate::{UiEvent, UiSink};
use crate::http_factory::{HttpFactory, InstanceHttpSpec};
use crate::instances::InstanceTable;
use crate::lifecycle::model::{
    Applied, Event, Kind, Model, Phase, Rejection, Terminal, agent_status, is_pending, step,
};
use crate::normalize::NormalizedHello;
use crate::payloads::{EventCtx, PreviewFetchPurpose};
use crate::proxy::ResolvedProxy;
use crate::redact::RedactionOp;
use crate::similarity::{SimOutcome, SimRecord, SimilarityIndex, sim_key};
use crate::validate::Validated;

use cache::{Candidate, CandidateCache, RebuildError};
use envelope::{OpenStatus, RecordStatus};
use queue::{Admission, Limits, Ticket};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The routing fields every envelope of a request carries (§4.2), and nothing else: the
/// pending/executing envelope is built from these alone (§4.5, `envelope::pending_envelope`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub request_id: String,
    pub op_id: String,
    /// The instance alias the request was routed to.
    pub instance: String,
}

/// The error a terminal state the store could not record carries (append failure, §11.1).
#[derive(Debug, Clone, PartialEq)]
pub struct TerminalError {
    pub code: ErrorCode,
    pub retryable: bool,
    pub message: String,
}

/// What changes under the entry lock.
#[derive(Debug, Clone)]
pub struct EntryState {
    pub model: Model,
    /// SHA-256 of the current candidate (Tasks 20–22); zero until one exists.
    pub candidate_hash: [u8; 32],
    /// Returned to the queue by a stale check (Task 22).
    pub stale: bool,
    /// Caution warnings of the current revision (Tasks 21/22).
    pub caution_count: u32,
    /// The redaction ops of the current revision (§5.2 queue metadata; Task 21 sets them): a
    /// rebuild re-applies them.
    pub redaction_ops: Vec<RedactionOp>,
    /// A rebuild of the current revision failed for good (§5.2): Release stays disabled with the
    /// `internal` banner; only Deny remains.
    pub rebuild_failed: bool,
    /// `Some` only for a terminal state the store does not know (append failure).
    pub unlogged_terminal: Option<TerminalError>,
    /// A read's release item (set when `READ_FETCHED` committed; Task 21).
    pub read: Option<read::ReadState>,
    /// A write's params, enrichment verdict and request list (Task 22).
    pub write: Option<write::WriteState>,
    /// The expiry timer fired while the model could not expire (`StaleCheck`, `Executing`,
    /// `Running`, `DryRunning`; Task 12 review I-4): the request expires as soon as it is in a
    /// phase that can ([`Engine::transition`] re-checks).
    pub expiry_due: bool,
}

impl EntryState {
    /// §5.1 inv. 6 as Rust decides it: the model's flag, and never after a failed rebuild of this
    /// revision (T20 I-1: `rebuild_failed` is the authority wherever approvability is read).
    pub fn approvable(&self) -> bool {
        self.model.approvable() && !self.rebuild_failed
    }
}

/// One request the engine holds.
pub struct RequestEntry {
    pub head: RequestHead,
    pub spec: &'static OperationSpec,
    pub instance_id: String,
    /// Lowercase hex (§4.4).
    pub params_sha256: String,
    /// From the agent's params (§2.3).
    pub target_display: String,
    /// RFC 3339 UTC, ms.
    pub submitted_at: String,
    submitted_mono: Duration,
    clock: Arc<dyn Clock>,
    /// Normalized (§3.3).
    pub agent_name: Option<String>,
    /// Normalized `reason`, cut for the queue row.
    pub reason_excerpt: Option<String>,
    pub unusual: bool,
    pub session: SessionKey,
    /// `None` only for a request whose validation failed.
    pub validated: Option<Validated>,
    /// The id columns of every later record of this request.
    pub ctx: EventCtx,
    state: Mutex<EntryState>,
    status: watch::Sender<Status>,
    /// The admission place (§3.3, §5.2), held until terminal.
    ticket: Mutex<Option<Ticket>>,
    /// Serializes record-bearing transitions (held across the append; never the state lock).
    gate: Arc<tokio::sync::Mutex<()>>,
    /// The cancel handle and capture of the read in flight (Task 24 aborts through it); dropped
    /// once `READ_FETCHED` is committed and at terminal.
    fetch: Mutex<Option<FetchControl>>,
    /// The app-initiated GET of a write in flight (purpose and resolved path): what a
    /// `cancelled_in_flight` record of it names (Task 24).
    in_flight: Mutex<Option<InFlight>>,
}

/// The GET a write's control is currently running (`PREVIEW_FETCH` `purpose` and `path`).
#[derive(Debug, Clone)]
pub(crate) struct InFlight {
    pub purpose: PreviewFetchPurpose,
    pub path: String,
}

/// The parts of a new entry the handler fills in.
pub struct NewEntry {
    pub head: RequestHead,
    pub spec: &'static OperationSpec,
    pub instance_id: String,
    pub params_sha256: String,
    pub target_display: String,
    pub agent_name: Option<String>,
    pub reason_excerpt: Option<String>,
    pub unusual: bool,
    pub session: SessionKey,
    pub validated: Option<Validated>,
    pub ctx: EventCtx,
    pub model: Model,
    pub unlogged_terminal: Option<TerminalError>,
    /// From `Admission::admit`; an entry created terminal never keeps it.
    pub ticket: Option<Ticket>,
}

impl RequestEntry {
    fn new(n: NewEntry, clock: Arc<dyn Clock>) -> RequestEntry {
        let (status, _) = watch::channel(agent_status(&n.model));
        // A request inserted already terminal (an unlogged rejection) is pending no more.
        let ticket = n.ticket.filter(|_| is_pending(n.model.phase()));
        RequestEntry {
            head: n.head,
            spec: n.spec,
            instance_id: n.instance_id,
            params_sha256: n.params_sha256,
            target_display: n.target_display,
            submitted_at: clock.now_utc().to_rfc3339_ms(),
            submitted_mono: clock.suspend_aware_elapsed(),
            clock,
            agent_name: n.agent_name,
            reason_excerpt: n.reason_excerpt,
            unusual: n.unusual,
            session: n.session,
            validated: n.validated,
            ctx: n.ctx,
            state: Mutex::new(EntryState {
                model: n.model,
                candidate_hash: [0; 32],
                stale: false,
                caution_count: 0,
                redaction_ops: Vec::new(),
                rebuild_failed: false,
                unlogged_terminal: n.unlogged_terminal,
                read: None,
                write: None,
                expiry_due: false,
            }),
            status,
            ticket: Mutex::new(ticket),
            gate: Arc::new(tokio::sync::Mutex::new(())),
            fetch: Mutex::new(None),
            in_flight: Mutex::new(None),
        }
    }

    /// Hold it only to read or to step-and-replace; never across an append or an `.await`.
    pub fn state(&self) -> MutexGuard<'_, EntryState> {
        lock(&self.state)
    }

    pub fn kind(&self) -> Kind {
        kind_of(self.spec)
    }

    /// `"read"` / `"write"`.
    pub fn class(&self) -> &'static str {
        class_str(self.spec)
    }

    /// Since submission, on the suspend-aware clock.
    pub fn age(&self) -> Duration {
        self.clock
            .suspend_aware_elapsed()
            .saturating_sub(self.submitted_mono)
    }

    /// The agent-visible status (§4.5).
    pub fn agent_status(&self) -> Status {
        agent_status(&self.state().model)
    }

    /// Wakes on every agent-visible status change.
    pub fn subscribe(&self) -> watch::Receiver<Status> {
        self.status.subscribe()
    }

    /// Gives the admission place back; idempotent (the ticket is taken once).
    fn release_ticket(&self) {
        let ticket = lock(&self.ticket).take();
        drop(ticket);
    }

    /// Whether the entry still holds its admission place.
    pub fn holds_ticket(&self) -> bool {
        lock(&self.ticket).is_some()
    }

    /// The control of the fetch in flight, if any (Task 24: cancel and in-flight capture).
    pub fn fetch_control(&self) -> Option<FetchControl> {
        lock(&self.fetch).clone()
    }

    fn set_fetch_control(&self, ctl: Option<FetchControl>) {
        if ctl.is_none() {
            *lock(&self.in_flight) = None;
        }
        *lock(&self.fetch) = ctl;
    }

    /// A write's GET starts (`Some`) or ended (`None`): only a GET that is in flight gets a
    /// `cancelled_in_flight` record.
    pub(crate) fn set_in_flight(&self, f: Option<InFlight>) {
        *lock(&self.in_flight) = f;
    }

    pub(crate) fn in_flight(&self) -> Option<InFlight> {
        lock(&self.in_flight).clone()
    }

    fn publish(&self) {
        let now = self.agent_status();
        self.status.send_if_modified(|cur| {
            let changed = *cur != now;
            *cur = now;
            changed
        });
    }
}

pub(crate) fn kind_of(spec: &OperationSpec) -> Kind {
    match spec.class {
        OpClass::Read => Kind::Read,
        OpClass::Write => Kind::Write,
    }
}

pub(crate) fn class_str(spec: &OperationSpec) -> &'static str {
    match spec.class {
        OpClass::Read => "read",
        OpClass::Write => "write",
    }
}

/// §4.3: `audit_failure` is retryable for reads and scripts, never for writes.
pub(crate) fn audit_failure_retryable(kind: Kind) -> bool {
    kind != Kind::Write
}

/// The hello of one connection (§3.3), raw for the audit payload and normalized for display.
#[derive(Debug, Clone)]
pub struct Session {
    pub hello: Hello,
    pub normalized: NormalizedHello,
}

impl Session {
    /// §5.6: `agent_name` + `peer_origin_exe` (MCP: `connection_id`) + `cwd_basename`.
    pub fn key(&self, conn: &atlas_duck_ipc::proto::ConnectionMeta) -> SessionKey {
        SessionKey {
            agent_name: self.normalized.agent_name.clone(),
            peer_origin_exe: conn.peer.peer_origin_exe.clone(),
            connection_id: (self.hello.client_kind == ClientKind::Mcp)
                .then(|| conn.connection_id.clone()),
            cwd_basename: self.normalized.cwd_basename.clone(),
        }
    }
}

/// What a failed append does to the request (PD-19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnAuditFailure {
    /// §5.1 inv. 1, §11.1: the request goes to `Failed` (`OutcomeUnknown` from `Executing`).
    FailRequest,
    /// The record only enables a later decision (`PREVIEW_SHOWN`, §5.6): nothing changes and the
    /// caller gets the error, so "opened" stays clear (fail closed without ending the request).
    KeepRequest,
}

/// One instance's client and the proxy decision it was built with (§7.2: the PAC hint of a
/// connection failure depends on it).
pub struct InstanceHttp {
    pub client: InstanceClient,
    pub proxy: ResolvedProxy,
}

/// Why no client could be built for an instance.
#[derive(Debug)]
pub enum ClientError {
    /// The instance left the table or has no usable base URL.
    NoInstance,
    /// The custom CA bundle could not be read.
    CaBundle,
    Build(BuildError),
}

/// Why a [`Engine::transition`] did not apply.
#[derive(Debug, Clone, PartialEq)]
pub enum TransitionError {
    /// The model rejected the event on the clone: nothing was logged.
    Rejected(Rejection),
    /// The record committed, but the model changed meanwhile and rejects the event now (PD-19
    /// "re-step, never overwrite"): the record names a revision that is no longer current.
    Raced(Rejection),
    /// The append failed: the request went to `Failed` (`OutcomeUnknown` from `Executing`).
    Audit(AuditError),
}

/// An event stepped on a clone of the model (PD-19), with the revision and phase it was
/// stepped from, waiting for its record to commit.
struct Prepared {
    clone: Model,
    applied: Applied,
    rev: u64,
    phase: Phase,
}

impl Prepared {
    /// Steps a clone of `st.model`; nothing changes.
    fn step(st: &EntryState, event: Event) -> Result<Prepared, Rejection> {
        let mut clone = st.model.clone();
        let applied = step(&mut clone, event)?;
        Ok(Prepared {
            clone,
            applied,
            rev: st.model.rev(),
            phase: st.model.phase(),
        })
    }

    /// After the record committed: replace the model with the clone if nothing changed since,
    /// else re-step the current model with the same event (never overwrite a newer model);
    /// `on_apply` runs under the state lock only when the event applied.
    fn apply<A, G>(
        self,
        entry: &RequestEntry,
        event: Event,
        on_apply: A,
        guard: G,
    ) -> Result<Applied, TransitionError>
    where
        A: FnOnce(&mut EntryState),
        G: Fn(&Model) -> bool,
    {
        let mut st = entry.state();
        let applied = if st.model.rev() == self.rev && st.model.phase() == self.phase {
            st.model = self.clone;
            // A rebuild that failed meanwhile (`Engine::candidate`) disabled Release on this
            // revision; the clone predates it and must not switch approval back on (T20 I-1).
            if st.rebuild_failed {
                st.model.set_approvable(false);
            }
            Ok(self.applied)
        } else if !guard(&st.model) {
            Err(TransitionError::Raced(Rejection::StaleRev {
                current: st.model.rev(),
            }))
        } else {
            step(&mut st.model, event).map_err(TransitionError::Raced)
        };
        if applied.is_ok() {
            on_apply(&mut st);
        }
        applied
    }
}

/// One entry's held transition gate: proof for the gated sections ([`Engine::cancel_locked`]).
pub(crate) type GateGuard = tokio::sync::OwnedMutexGuard<()>;

/// Held transition gates ([`Engine::lock_gates`]): proof for [`Engine::commit_batch`]. The field
/// is never read: holding the guards is its whole purpose (dropping `Gates` releases them).
pub(crate) struct Gates(#[allow(dead_code)] Vec<tokio::sync::OwnedMutexGuard<()>>);

/// What an accepted event of a batch step brings to the entry state.
pub(crate) type OnApply = Box<dyn FnOnce(&mut EntryState) + Send>;

/// One request of a batch commit: its event, its record (already marked `with_batch`) and the
/// state its accepted event brings.
pub(crate) struct BatchStep {
    pub entry: Arc<RequestEntry>,
    pub event: Event,
    pub record: NewEvent,
    pub on_apply: OnApply,
}

/// Why [`Engine::commit_batch`] decided nothing.
#[derive(Debug)]
pub(crate) enum BatchCommitError {
    /// Step `.0` was rejected on its clone: nothing was appended.
    Rejected(usize, Rejection),
    /// The one append failed: nothing committed.
    Audit(AuditError),
}

pub struct EngineDeps {
    pub port: Arc<dyn AuditPort>,
    pub committed: Arc<CommittedSet>,
    pub covers: CoverIssuer,
    pub http: Arc<HttpFactory>,
    pub credentials: Arc<dyn CredentialProvider>,
    pub confirmer: Arc<dyn NativeConfirmer>,
    pub clock: Arc<dyn Clock>,
    pub ui: Arc<dyn UiSink>,
    pub instances: InstanceTable,
    pub limits: Limits,
    /// The runtime the synchronous `DecisionApi` runs its async part on (PD-13).
    pub runtime: tokio::runtime::Handle,
    /// "Possible duplicate" / "similar request" (§5.6); Task 28 passes the seeded one.
    pub similarity: SimilarityIndex,
    /// §4.4: how long a request may stay pending (`[requests] expiry_hours`, default 24 h).
    pub expiry: Duration,
    #[cfg(feature = "testing")]
    pub hooks: crate::core::TestHooks,
}

/// Terminal answers are immutable once recorded: a bounded memo of them keeps polling and
/// listing from decrypting the same records again (insertion order, oldest out first).
pub(crate) struct Recent<V> {
    cap: usize,
    map: HashMap<String, V>,
    order: VecDeque<String>,
}

impl<V: Clone> Recent<V> {
    pub(crate) fn new(cap: usize) -> Recent<V> {
        Recent {
            cap,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub(crate) fn get(&self, key: &str) -> Option<V> {
        self.map.get(key).cloned()
    }

    pub(crate) fn insert(&mut self, key: &str, v: V) {
        if self.map.insert(key.to_owned(), v).is_none() {
            self.order.push_back(key.to_owned());
        }
        while self.map.len() > self.cap {
            match self.order.pop_front() {
                Some(old) => {
                    self.map.remove(&old);
                }
                None => break,
            }
        }
    }
}

/// How many terminal answers / list rows are memoized.
const RECENT_MEMO: usize = 4096;

pub struct Engine {
    port: Arc<dyn AuditPort>,
    committed: Arc<CommittedSet>,
    covers: CoverIssuer,
    http: Arc<HttpFactory>,
    #[allow(dead_code)]
    credentials: Arc<dyn CredentialProvider>,
    #[allow(dead_code)]
    confirmer: Arc<dyn NativeConfirmer>,
    clock: Arc<dyn Clock>,
    ui: Arc<dyn UiSink>,
    instances: RwLock<InstanceTable>,
    /// By `connection_id`. M4 owns connection lifetimes; the handler trait has no disconnect
    /// call yet, so entries live as long as the core (handoff to M4).
    sessions: Mutex<HashMap<String, Session>>,
    entries: RwLock<HashMap<String, Arc<RequestEntry>>>,
    shutting_down: AtomicBool,
    admission: Admission,
    /// §5.2: at most `limits.fetching` direct reads in `Fetching` (Task 21 acquires).
    fetch_slots: Arc<Semaphore>,
    candidates: CandidateCache,
    /// Recorded terminal statuses (with the start record's instance id).
    terminal_status: Mutex<Recent<(RecordStatus, Option<String>)>>,
    /// `requests list` rows of recorded terminals.
    terminal_rows: Arc<Mutex<Recent<handler::ListRow>>>,
    /// Built on first use per instance id (Task 25 rebuilds them on configuration changes).
    clients: Mutex<HashMap<String, Arc<InstanceHttp>>>,
    runtime: tokio::runtime::Handle,
    similarity: SimilarityIndex,
    expiry: Duration,
    /// L43: one batch dialog at a time; a second `decide_batch` waits here. One `Core` per
    /// process, so this is the process-wide gate PD-13 names.
    batch_dialog: tokio::sync::Mutex<()>,
    /// §5.6 "Needs attention": post-approval failures and unknown outcomes until acknowledged
    /// (UI state, not audited, reset on restart).
    needs_attention: Mutex<BTreeSet<String>>,
    #[cfg(feature = "testing")]
    hooks: crate::core::TestHooks,
}

impl Engine {
    pub fn new(d: EngineDeps) -> Engine {
        #[cfg(feature = "testing")]
        let expiry = d.hooks.expiry.unwrap_or(d.expiry);
        #[cfg(not(feature = "testing"))]
        let expiry = d.expiry;
        Engine {
            port: d.port,
            committed: d.committed,
            covers: d.covers,
            http: d.http,
            credentials: d.credentials,
            confirmer: d.confirmer,
            clock: d.clock,
            ui: d.ui,
            instances: RwLock::new(d.instances),
            sessions: Mutex::new(HashMap::new()),
            entries: RwLock::new(HashMap::new()),
            shutting_down: AtomicBool::new(false),
            admission: Admission::new(d.limits),
            fetch_slots: Arc::new(Semaphore::new(
                d.limits.fetching.min(Semaphore::MAX_PERMITS),
            )),
            candidates: CandidateCache::new(d.limits.candidate_cache_bytes),
            terminal_status: Mutex::new(Recent::new(RECENT_MEMO)),
            terminal_rows: Arc::new(Mutex::new(Recent::new(RECENT_MEMO))),
            clients: Mutex::new(HashMap::new()),
            runtime: d.runtime,
            similarity: d.similarity,
            expiry,
            batch_dialog: tokio::sync::Mutex::new(()),
            needs_attention: Mutex::new(BTreeSet::new()),
            #[cfg(feature = "testing")]
            hooks: d.hooks,
        }
    }

    #[allow(dead_code)] // `blocking` is the async path; kept for synchronous callers (Task 23)
    pub(crate) fn port(&self) -> &Arc<dyn AuditPort> {
        &self.port
    }

    pub fn committed(&self) -> &Arc<CommittedSet> {
        &self.committed
    }

    /// Covers only for ids whose start record committed (§5.1 inv. 1).
    pub(crate) fn covers(&self) -> &CoverIssuer {
        &self.covers
    }

    pub fn http(&self) -> &Arc<HttpFactory> {
        &self.http
    }

    #[allow(dead_code)] // token recheck and connection tests (Tasks 25/26)
    pub(crate) fn credentials(&self) -> &Arc<dyn CredentialProvider> {
        &self.credentials
    }

    pub(crate) fn confirmer(&self) -> &Arc<dyn NativeConfirmer> {
        &self.confirmer
    }

    /// The "possible duplicate" / "similar request" index (§5.6).
    pub fn similarity(&self) -> &SimilarityIndex {
        &self.similarity
    }

    /// L43: held for a whole `decide_batch`, dialog included.
    pub(crate) fn batch_dialog(&self) -> &tokio::sync::Mutex<()> {
        &self.batch_dialog
    }

    /// §5.6: a post-approval failure or unknown outcome stays under "Needs attention" until
    /// acknowledged; the UI is told the new count.
    pub(crate) fn flag_attention(&self, request_id: &str) {
        let count = {
            let mut set = lock(&self.needs_attention);
            if !set.insert(request_id.to_owned()) {
                return;
            }
            set.len()
        };
        self.ui.emit(UiEvent::NeedsAttentionChanged {
            count: u32::try_from(count).unwrap_or(u32::MAX),
        });
    }

    /// `DecisionApi::acknowledge_attention` (in memory, not audited).
    pub(crate) fn acknowledge_attention(&self, request_ids: &[String]) {
        let count = {
            let mut set = lock(&self.needs_attention);
            let before = set.len();
            for id in request_ids {
                set.remove(id);
            }
            if set.len() == before {
                return;
            }
            set.len()
        };
        self.ui.emit(UiEvent::NeedsAttentionChanged {
            count: u32::try_from(count).unwrap_or(u32::MAX),
        });
    }

    /// The unacknowledged "Needs attention" ids (sorted).
    pub fn needs_attention(&self) -> Vec<String> {
        lock(&self.needs_attention).iter().cloned().collect()
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    pub fn ui(&self) -> &Arc<dyn UiSink> {
        &self.ui
    }

    pub fn instances(&self) -> RwLockReadGuard<'_, InstanceTable> {
        self.instances
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// §4.4: how long a request may stay pending.
    pub fn expiry(&self) -> Duration {
        self.expiry
    }

    pub fn limits(&self) -> &Limits {
        self.admission.limits()
    }

    /// The pending counts and reservations (§3.3, §5.2).
    pub fn admission(&self) -> &Admission {
        &self.admission
    }

    /// §5.2: a read holds a permit while it is in `Fetching`.
    pub fn fetch_slots(&self) -> &Arc<Semaphore> {
        &self.fetch_slots
    }

    /// The candidate LRU (§5.2).
    pub fn candidates(&self) -> &CandidateCache {
        &self.candidates
    }

    #[cfg(feature = "testing")]
    pub fn hooks(&self) -> &crate::core::TestHooks {
        &self.hooks
    }

    pub(crate) fn terminal_rows(&self) -> &Arc<Mutex<Recent<handler::ListRow>>> {
        &self.terminal_rows
    }

    /// §7.2: 120 s, 50 MiB per read and 32 MiB per response (tests may shorten the budget).
    pub fn read_budget(&self) -> ReadBudget {
        #[cfg(feature = "testing")]
        if let Some(b) = self.hooks.read_budget {
            return b;
        }
        ReadBudget::default()
    }

    /// The instance's client, built on first use: its proxy is resolved (L42) and its custom CA
    /// read off the async runtime (both can block).
    pub(crate) async fn client(&self, instance_id: &str) -> Result<Arc<InstanceHttp>, ClientError> {
        if let Some(c) = lock(&self.clients).get(instance_id) {
            return Ok(c.clone());
        }
        let (product, base, proxy, ca_bundle) = {
            let table = self.instances();
            let inst = table.by_id(instance_id).ok_or(ClientError::NoInstance)?;
            let base = inst.base.clone().ok_or(ClientError::NoInstance)?;
            let product = match inst.product {
                atlas_duck_registry::Product::Jira => atlas_duck_atlassian::Product::Jira,
                atlas_duck_registry::Product::Confluence => {
                    atlas_duck_atlassian::Product::Confluence
                }
            };
            (product, base, inst.proxy.clone(), inst.ca_bundle.clone())
        };
        let (http, id) = (self.http.clone(), instance_id.to_owned());
        let built = tokio::task::spawn_blocking(move || {
            let ca_pem = match ca_bundle {
                Some(path) => Some(std::fs::read(path).map_err(|_| ClientError::CaBundle)?),
                None => None,
            };
            let spec = InstanceHttpSpec {
                instance_id: id,
                product,
                base,
                ca_pem,
                proxy,
            };
            http.build(&spec)
                .map(|(client, proxy)| InstanceHttp { client, proxy })
                .map_err(ClientError::Build)
        })
        .await
        .unwrap_or(Err(ClientError::NoInstance))?;
        let built = Arc::new(built);
        Ok(lock(&self.clients)
            .entry(instance_id.to_owned())
            .or_insert(built)
            .clone())
    }

    /// The synchronous `DecisionApi` runs its async part on the core's runtime and waits on a
    /// plain channel (PD-13). A caller on a multi-thread runtime's worker (or its `block_on`
    /// thread) waits through `block_in_place`, which hands the worker's queue to another thread,
    /// so the decision's own tasks still run even with every worker waiting. A caller on a
    /// current-thread runtime is refused: blocking it could starve the very task it waits for
    /// (this also refuses a `spawn_blocking` thread of a current-thread runtime, which could
    /// block safely; the check cannot tell them apart). `None` if refused or if the task died.
    ///
    /// Contract for M4/M6 (review M-3): the core runs on a multi-thread runtime (with a
    /// current-thread one every decision is refused), and `DecisionApi` is never called from a
    /// `LocalSet` (`block_in_place` panics there). A refusal reaches the caller as
    /// `DecisionError::Audit` with the message "the decision could not run".
    pub(crate) fn run_sync<T, F>(&self, fut: F) -> Option<T>
    where
        T: Send + 'static,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        use tokio::runtime::{Handle, RuntimeFlavor};
        let flavor = Handle::try_current().ok().map(|h| h.runtime_flavor());
        let on_runtime = flavor.is_some();
        if flavor.is_some_and(|f| f != RuntimeFlavor::MultiThread) {
            return None;
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.runtime.spawn(async move {
            let _ = tx.send(fut.await);
        });
        if on_runtime {
            tokio::task::block_in_place(|| rx.recv().ok())
        } else {
            rx.recv().ok()
        }
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    pub(crate) fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }

    pub(crate) fn remember_session(&self, connection_id: &str, session: Session) {
        lock(&self.sessions).insert(connection_id.to_owned(), session);
    }

    pub fn session(&self, connection_id: &str) -> Option<Session> {
        lock(&self.sessions).get(connection_id).cloned()
    }

    pub fn entry(&self, request_id: &str) -> Option<Arc<RequestEntry>> {
        self.entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(request_id)
            .cloned()
    }

    /// Every entry in memory: the pending ones and any unlogged terminal.
    pub fn pending_entries(&self) -> Vec<Arc<RequestEntry>> {
        self.entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// Call only after `commit_request_received` returned `Ok` for this id (T17 M-2).
    pub(crate) fn insert(&self, n: NewEntry) -> Arc<RequestEntry> {
        let entry = Arc::new(RequestEntry::new(n, self.clock.clone()));
        self.entries
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(entry.head.request_id.clone(), entry.clone());
        // §5.6: a validated request is known to the duplicate and similarity flags from now on.
        if let Some(v) = &entry.validated
            && is_pending(entry.state().model.phase())
        {
            self.similarity.on_submit(SimRecord {
                request_id: entry.head.request_id.clone(),
                op_id: entry.head.op_id.clone(),
                instance_id: entry.instance_id.clone(),
                params_sha256: Some(entry.params_sha256.clone()),
                key: sim_key(entry.spec, &v.params),
            });
        }
        entry
    }

    /// A blocking store call off the async runtime (PD-25). A panicked task is a failure: the
    /// caller treats it like a failed append (nothing is assumed committed).
    pub async fn blocking<T, F>(&self, f: F) -> Result<T, AuditError>
    where
        T: Send + 'static,
        F: FnOnce(&dyn AuditPort) -> Result<T, AuditError> + Send + 'static,
    {
        let port = self.port.clone();
        tokio::task::spawn_blocking(move || f(&*port))
            .await
            .unwrap_or_else(|_| Err(AuditError::AppendFailed("blocking task failed".into())))
    }

    /// PD-19 log-then-apply: step a clone (rejected → nothing logged), append the record built
    /// from the clone, then replace the model if nothing changed meanwhile, else re-step the
    /// current model with the same event. An append failure takes the request to `Failed`
    /// (`OutcomeUnknown` from `Executing`, M-8). Watchers wake on every agent-visible change.
    ///
    /// The entry's transition gate is held from the clone step through the apply, so a second
    /// transition sees the first one's result (e.g. a second cancel finds the request terminal
    /// and logs nothing); the re-step branch is then only a defence. The whole sequence runs in
    /// its own task and is driven to completion even if the caller's future is dropped.
    pub async fn transition<R>(
        self: &Arc<Self>,
        entry: &Arc<RequestEntry>,
        event: Event,
        record: R,
    ) -> Result<Applied, TransitionError>
    where
        R: FnOnce(&Model) -> NewEvent + Send + 'static,
    {
        self.transition_with(
            entry,
            event,
            move |m| vec![record(m)],
            OnAuditFailure::FailRequest,
            |_| {},
        )
        .await
    }

    /// [`Engine::transition`] with several records (one `append_batch`, in order), a choice of
    /// what an append failure does, and `on_apply`, run under the state lock in the critical
    /// section that applies the event (only when it applied, by replace or re-step), so state of
    /// the new revision (candidate hash, ops, approvability) never shows apart from the model.
    pub async fn transition_with<R, A>(
        self: &Arc<Self>,
        entry: &Arc<RequestEntry>,
        event: Event,
        records: R,
        on_fail: OnAuditFailure,
        on_apply: A,
    ) -> Result<Applied, TransitionError>
    where
        R: FnOnce(&Model) -> Vec<NewEvent> + Send + 'static,
        A: FnOnce(&mut EntryState) + Send + 'static,
    {
        self.transition_guarded(entry, event, records, on_fail, on_apply, |_| true)
            .await
    }

    /// [`Engine::transition_with`] that applies only while `guard` holds for the current model
    /// (checked under the transition gate before anything is appended, and again on a re-step):
    /// a task bound to one generation of a request (Task 22: a stale check bound to its
    /// approval) never applies an event to a later one. A failed guard is
    /// `Rejected(StaleRev)`, nothing logged.
    pub(crate) async fn transition_guarded<R, A, G>(
        self: &Arc<Self>,
        entry: &Arc<RequestEntry>,
        event: Event,
        records: R,
        on_fail: OnAuditFailure,
        on_apply: A,
        guard: G,
    ) -> Result<Applied, TransitionError>
    where
        R: FnOnce(&Model) -> Vec<NewEvent> + Send + 'static,
        A: FnOnce(&mut EntryState) + Send + 'static,
        G: Fn(&Model) -> bool + Send + 'static,
    {
        let (engine, entry) = (self.clone(), entry.clone());
        tokio::spawn(async move {
            engine
                .transition_gated(&entry, event, records, on_fail, on_apply, guard)
                .await
        })
        .await
        .unwrap_or_else(|_| {
            Err(TransitionError::Audit(AuditError::AppendFailed(
                "transition task failed".into(),
            )))
        })
    }

    async fn transition_gated<R, A, G>(
        &self,
        entry: &Arc<RequestEntry>,
        event: Event,
        records: R,
        on_fail: OnAuditFailure,
        on_apply: A,
        guard: G,
    ) -> Result<Applied, TransitionError>
    where
        R: FnOnce(&Model) -> Vec<NewEvent>,
        A: FnOnce(&mut EntryState),
        G: Fn(&Model) -> bool,
    {
        let gate = entry.gate.clone().lock_owned().await;
        let prepared = {
            let st = entry.state();
            if !guard(&st.model) {
                return Err(TransitionError::Rejected(Rejection::StaleRev {
                    current: st.model.rev(),
                }));
            }
            Prepared::step(&st, event).map_err(TransitionError::Rejected)?
        };
        let mut evs = records(&prepared.clone);
        let appended = if evs.len() == 1 {
            match evs.pop() {
                Some(ev) => self.blocking(move |p| p.append(ev).map(|_| ())).await,
                None => Ok(()),
            }
        } else {
            self.blocking(move |p| p.append_batch(evs).map(|_| ()))
                .await
        };
        if let Err(e) = appended {
            if on_fail == OnAuditFailure::FailRequest {
                self.fail_unlogged(entry);
            }
            return Err(TransitionError::Audit(e));
        }
        #[cfg(feature = "testing")]
        if let Some(pause) = self.hooks.pause_in_transition.clone() {
            pause.hold().await;
        }
        let applied = prepared.apply(entry, event, on_apply, guard);
        self.after_change(entry);
        // Task 12 review I-4: a request whose timer fired while its phase could not expire (or
        // whose time is up) expires the moment it is back in a phase that can, under this same
        // gate, so no decision can be taken on the new revision first.
        if applied.is_ok() {
            self.expire_if_due(entry, &gate);
        }
        applied
    }

    /// The transition gates of `entries`, taken in the order given (L43: `decide_batch` sorts
    /// them by request id, so two batches never wait on each other crosswise). While they are
    /// held no record-bearing transition of these requests can run.
    pub(crate) async fn lock_gates(entries: &[Arc<RequestEntry>]) -> Gates {
        let mut held = Vec::with_capacity(entries.len());
        for e in entries {
            held.push(e.gate.clone().lock_owned().await);
        }
        Gates(held)
    }

    /// L43 / §5.6 seam: `lead` (`BATCH_CONFIRMED`) and every step's record in **one**
    /// `append_batch`, `lead` first, then each step's model event applied (PD-19 replace or
    /// re-step) with its `on_apply`. Every step's event is stepped on a clone before anything
    /// is appended: a rejection there (the request changed since the caller's check, e.g. a
    /// rebuild failure cleared approvability) appends nothing and names the step. An append
    /// failure decides nothing and leaves every request as it was (the batch failed, not the
    /// requests). The caller holds every step's gate (`gates`), taken before its last check.
    pub(crate) async fn commit_batch(
        &self,
        _gates: &Gates,
        lead: NewEvent,
        steps: Vec<BatchStep>,
    ) -> Result<Vec<Result<Applied, TransitionError>>, BatchCommitError> {
        let mut prepared = Vec::with_capacity(steps.len());
        let mut evs = Vec::with_capacity(steps.len() + 1);
        evs.push(lead);
        for (i, s) in steps.into_iter().enumerate() {
            let p = Prepared::step(&s.entry.state(), s.event)
                .map_err(|r| BatchCommitError::Rejected(i, r))?;
            evs.push(s.record);
            prepared.push((s.entry, s.event, p, s.on_apply));
        }
        self.blocking(move |p| p.append_batch(evs).map(|_| ()))
            .await
            .map_err(BatchCommitError::Audit)?;
        // `after_change` with every item's gate held, as `transition_gated` runs it with its
        // own: it wakes watchers (a non-blocking `watch` send) and drops per-request state
        // (ticket, fetch control, cached candidate, map entry); nothing in it waits on a gate.
        let mut out = Vec::with_capacity(prepared.len());
        for (entry, event, p, on_apply) in prepared {
            out.push(p.apply(&entry, event, on_apply, |_| true));
            self.after_change(&entry);
        }
        Ok(out)
    }

    /// An event without an audit record (`FetchStarted`, `CandidateChanged`), under the
    /// transition gate so it never interleaves with a record-bearing transition. With
    /// `expect_rev`, a revision that moved on meanwhile refuses it (`StaleRev`). `on_apply` runs
    /// under the state lock when the event applied.
    pub(crate) async fn step_unlogged<A>(
        &self,
        entry: &Arc<RequestEntry>,
        event: Event,
        expect_rev: Option<u64>,
        on_apply: A,
    ) -> Result<Applied, Rejection>
    where
        A: FnOnce(&mut EntryState),
    {
        let _gate = entry.gate.clone().lock_owned().await;
        let applied = {
            let mut st = entry.state();
            match expect_rev {
                Some(rev) if st.model.rev() != rev => Err(Rejection::StaleRev {
                    current: st.model.rev(),
                }),
                _ => {
                    let applied = step(&mut st.model, event);
                    if applied.is_ok() {
                        on_apply(&mut st);
                    }
                    applied
                }
            }
        };
        self.after_change(entry);
        applied
    }

    /// §11.1 fail closed: the request goes to `Failed` (`audit_failure`), or `OutcomeUnknown`
    /// when it was executing (M-8); the store cannot know it, so the entry keeps the error.
    fn fail_unlogged(&self, entry: &Arc<RequestEntry>) {
        {
            let mut st = entry.state();
            if step(&mut st.model, Event::AuditFailure).is_ok() {
                st.unlogged_terminal = Some(match st.model.phase() {
                    Phase::Done(Terminal::OutcomeUnknown) => TerminalError {
                        code: ErrorCode::UpstreamUnknownOutcome,
                        retryable: false,
                        message: envelope::MSG_OUTCOME_UNKNOWN.to_owned(),
                    },
                    _ => TerminalError {
                        code: ErrorCode::AuditFailure,
                        retryable: audit_failure_retryable(entry.kind()),
                        message: envelope::MSG_AUDIT_FAILURE.to_owned(),
                    },
                });
            }
        }
        self.after_change(entry);
    }

    /// Wake the watchers; at a terminal state no further request is sent under this id, the
    /// admission place and the cached candidate are given back, and a recorded terminal is
    /// answered from the log from now on. Every path that makes a request terminal ends here.
    fn after_change(&self, entry: &Arc<RequestEntry>) {
        entry.publish();
        let (terminal, logged, outcome) = {
            let st = entry.state();
            (
                !is_pending(st.model.phase()),
                st.unlogged_terminal.is_none(),
                sim_outcome(&st),
            )
        };
        if terminal {
            if let Some(o) = outcome {
                self.similarity
                    .on_status(&entry.head.request_id, o, self.clock.now_utc());
            }
            self.committed.forget_request(&entry.head.request_id);
            entry.release_ticket();
            entry.set_fetch_control(None);
            self.candidates.remove(&entry.head.request_id);
            if logged {
                self.entries
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&entry.head.request_id);
            }
        }
    }

    /// The current revision's candidate: from the cache if it holds this revision's bytes, else
    /// rebuilt from the committed record off the runtime (§5.2) and cached. `normalize` is the
    /// op's normalization of the record (see `cache`'s Task 21 contract). A permanent failure
    /// (hash mismatch, malformed record, a stored op that no longer applies) disables Release for
    /// this revision; an unreadable store fails only this call.
    pub async fn candidate<N>(
        &self,
        entry: &Arc<RequestEntry>,
        normalize: N,
    ) -> Result<Arc<Candidate>, RebuildError>
    where
        N: FnOnce(&Value) -> Result<Value, RebuildError> + Send + 'static,
    {
        let id = entry.head.request_id.clone();
        let (expected, ops) = {
            let st = entry.state();
            (st.candidate_hash, st.redaction_ops.clone())
        };
        match self.candidates.get(&id) {
            Some(c) if c.hash() == &expected => return Ok(c),
            Some(_) => self.candidates.remove(&id),
            None => {}
        }
        let spec = entry.spec;
        let rid = id.clone();
        let rebuilt = self
            .blocking(move |p| Ok(cache::rebuild(p, &rid, spec, &ops, &expected, normalize)))
            .await
            .unwrap_or_else(|e| Err(RebuildError::Audit(e)));
        match rebuilt {
            Ok(c) => {
                let c = Arc::new(c);
                // A newer revision or a terminal state meanwhile: do not cache stale bytes.
                // Under the entry lock, so a terminal step cannot slip between the check and the
                // insert (`after_change` removes the candidate after the model turned terminal).
                let st = entry.state();
                if &st.candidate_hash == c.hash() && is_pending(st.model.phase()) {
                    self.candidates.insert(&id, c.clone());
                }
                drop(st);
                Ok(c)
            }
            Err(e) => {
                // No candidate yet (zero hash): nothing to disable; `NoSource` is expected then.
                if e.disables_release() && expected != [0; 32] {
                    let mut st = entry.state();
                    if st.candidate_hash == expected {
                        st.rebuild_failed = true;
                        st.model.set_approvable(false);
                    }
                }
                Err(e)
            }
        }
    }

    /// The request's status as its committed records say (§4.4): `None` for an id the log does
    /// not know. Decrypts only the rows whose meaning depends on their payload, and a recorded
    /// terminal only once (memoized: it can no longer change).
    pub async fn status_from_records(
        &self,
        request_id: &str,
    ) -> Result<Option<RecordStatus>, AuditError> {
        let memo = lock(&self.terminal_status).get(request_id);
        let found = match memo {
            Some(hit) => Some(hit),
            None => {
                let id = request_id.to_owned();
                let found = self
                    .blocking(move |p| {
                        let headers = p.headers_for_request(&id)?;
                        records_status(p, &headers)
                    })
                    .await?;
                if let Some(rs) = &found
                    && OpenStatus::of(rs.0.status).is_none()
                {
                    lock(&self.terminal_status).insert(request_id, rs.clone());
                }
                found
            }
        };
        Ok(self.with_alias(found))
    }

    /// [`Engine::status_from_records`] without an await, for the synchronous cancel path.
    pub(crate) fn status_from_records_sync(
        &self,
        request_id: &str,
    ) -> Result<Option<RecordStatus>, AuditError> {
        let memo = lock(&self.terminal_status).get(request_id);
        let found = match memo {
            Some(hit) => Some(hit),
            None => {
                let headers = self.port.headers_for_request(request_id)?;
                let found = records_status(&*self.port, &headers)?;
                if let Some(rs) = &found
                    && OpenStatus::of(rs.0.status).is_none()
                {
                    lock(&self.terminal_status).insert(request_id, rs.clone());
                }
                found
            }
        };
        Ok(self.with_alias(found))
    }

    /// The start record's instance id as the alias it still has.
    fn with_alias(&self, found: Option<(RecordStatus, Option<String>)>) -> Option<RecordStatus> {
        found.map(|(rs, instance_id)| {
            let alias = instance_id
                .as_deref()
                .and_then(|id| self.instances().by_id(id).map(|i| i.alias.clone()));
            RecordStatus {
                instance: alias,
                ..rs
            }
        })
    }
}

/// What a terminal state means for "similar request" (§5.6: decided or executed).
fn sim_outcome(st: &EntryState) -> Option<SimOutcome> {
    let Phase::Done(t) = st.model.phase() else {
        return None;
    };
    Some(match t {
        Terminal::Released(_) | Terminal::ReleasedRedacted(_) => SimOutcome::Released,
        Terminal::Denied => SimOutcome::Denied,
        Terminal::Succeeded => SimOutcome::Executed,
        Terminal::OutcomeUnknown => SimOutcome::OutcomeUnknown,
        // A write that failed after its approval was decided; any other failure was not.
        Terminal::Failed if st.write.as_ref().is_some_and(|w| w.approved_hash.is_some()) => {
            SimOutcome::Failed
        }
        Terminal::Failed
        | Terminal::Rejected
        | Terminal::Expired
        | Terminal::Cancelled(_)
        | Terminal::Abandoned => SimOutcome::Gone,
    })
}

/// Decrypts one payload as JSON; `None` if it cannot be read or parsed.
pub(crate) fn payload_json(p: &dyn AuditPort, seq: u64) -> Option<Value> {
    let bytes = p.read_payload(seq).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// `SCRIPT_FAILED` is terminal only when `direct` or `reason = audit_failure` (§8.3).
fn terminal_flags(p: &dyn AuditPort, h: &EventHeader) -> Option<ScriptFailedFlags> {
    if h.event_type != EventType::SCRIPT_FAILED {
        return None;
    }
    let v = payload_json(p, h.seq)?;
    Some(ScriptFailedFlags {
        direct: v.get("direct").and_then(Value::as_bool).unwrap_or(false),
        reason: v
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    })
}

/// The first terminal record of `headers` (seq order).
fn terminal_of<'a>(p: &dyn AuditPort, headers: &'a [EventHeader]) -> Option<&'a EventHeader> {
    headers.iter().find(|h| {
        let flags = terminal_flags(p, h);
        is_terminal(h, flags.as_ref())
    })
}

/// The terminal record's payload, decrypted only when its meaning needs it.
fn terminal_payload(p: &dyn AuditPort, terminal: Option<&EventHeader>) -> Option<Value> {
    terminal
        .filter(|h| envelope::needs_payload(h.event_type))
        .and_then(|h| payload_json(p, h.seq))
}

/// The status of the request `start` began, ended by `terminal` (with `payload`) or still open.
fn status_at(
    start: &EventHeader,
    terminal: Option<&EventHeader>,
    payload: Option<&Value>,
) -> RecordStatus {
    let (status, error) = match terminal {
        None => (Status::Pending, None),
        Some(h) => envelope::record_status(h.event_type, payload, start.op_class.as_deref()),
    };
    RecordStatus {
        request_id: start.request_id.clone().unwrap_or_default(),
        op_id: start.op_id.clone(),
        instance: None,
        status,
        error,
    }
}

/// The first terminal record of `headers` (seq order), with its payload when its meaning needs
/// it, plus the start record's `instance_id` (mapped to an alias by the caller).
#[allow(clippy::type_complexity)]
fn records_status(
    p: &dyn AuditPort,
    headers: &[EventHeader],
) -> Result<Option<(RecordStatus, Option<String>)>, AuditError> {
    let Some(start) = headers.first() else {
        return Ok(None);
    };
    let terminal = terminal_of(p, headers);
    let payload = terminal_payload(p, terminal);
    Ok(Some((
        status_at(start, terminal, payload.as_ref()),
        start.instance_id.clone(),
    )))
}
