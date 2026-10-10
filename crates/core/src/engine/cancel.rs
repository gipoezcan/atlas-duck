//! Cancel and expiry (§4.4, §5.2 step 3, §5.4 step 2, §2.5 step 2; Task 24).
//!
//! [`Engine::cancel_now`] (synchronous, non-runtime callers) and [`Engine::cancel_and_wait`]
//! (async callers, the shutdown sweep) run the same gated section. Neither waits on the network,
//! an aborted connection or a reaped process; they hold only `std::sync` locks plus the entry's
//! transition gate (`try_lock`, polled, for `cancel_now`; awaited for the async path).
//!
//! **The gate rule (Task 21 handoff, binding).** The request's [`FetchControl`] is cancelled and
//! its capture taken only while the entry's transition gate is held ([`Engine::cancel_locked`]),
//! in the same gated section that commits `[READ_FETCHED | PREVIEW_FETCH {cancelled_in_flight}?,
//! CANCELLED | EXPIRED]`. A fetch task that sees its control cancelled answers with a gated
//! `FetchFailedDirect`/`recheck_failed`, which the model refuses once this section made the
//! request terminal; a control cancelled outside the gate would let that task end the request
//! `internal` first. The read stores its control before it mints its cover (`read.rs::fetch`):
//! a cancel before that point has forgotten the id (no cover is ever minted), one after it finds
//! the control.
//!
//! **Expiry.** One timer per pending request (`sleep(submitted_at + expiry)`, never reset: a
//! `Stale` return to `AwaitingApproval` does not restart it, §4.4). While the model cannot
//! expire (`StaleCheck`, `Executing`, `Running`, `DryRunning`: bounded by their own budgets)
//! the timer only sets `expiry_due`; [`Engine::transition`] expires the request under its own
//! gate the moment a transition leaves those phases for one that can.

use std::sync::Arc;
use std::time::Duration;

use atlas_duck_audit::{EventType, NewEvent};
use atlas_duck_ipc::envelope::{Envelope, Status};
use serde_json::json;

use super::envelope::{self, OpenStatus, RecordStatus};
use super::{Engine, GateGuard, Prepared, RequestEntry};
use crate::lifecycle::model::{CancelReason, Event, Kind, Phase, Rejection, is_pending};
use crate::payloads::{self, FetchRecord, InFlightReason, ReadFetched};

/// Who ends the request (§4.4, §2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelCause {
    /// The agent's `cancel`.
    Client,
    /// The expiry timer (or `expire_now`).
    Expiry,
    /// The shutdown path (§2.5 step 2, Task 28).
    Shutdown(ShutdownReason),
}

/// Why the app ends its pending requests (a client cancel is [`CancelCause::Client`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    AppQuit,
    OsShutdown,
}

impl ShutdownReason {
    fn cancel_reason(self) -> CancelReason {
        match self {
            Self::AppQuit => CancelReason::AppQuit,
            Self::OsShutdown => CancelReason::OsShutdown,
        }
    }
}

impl CancelCause {
    fn event(self) -> Event {
        match self {
            Self::Client => Event::Cancel(CancelReason::ByClient),
            Self::Expiry => Event::Expire,
            Self::Shutdown(r) => Event::Cancel(r.cancel_reason()),
        }
    }

    /// The `reason` of a `cancelled_in_flight` record.
    fn in_flight(self) -> InFlightReason {
        match self {
            Self::Client => InFlightReason::ByClient,
            Self::Expiry => InFlightReason::Expired,
            Self::Shutdown(ShutdownReason::AppQuit) => InFlightReason::AppQuit,
            Self::Shutdown(ShutdownReason::OsShutdown) => InFlightReason::OsShutdown,
        }
    }

    fn terminal_record(self, entry: &RequestEntry) -> NewEvent {
        match self.event() {
            Event::Cancel(r) => payloads::cancelled(&entry.ctx, r),
            _ => payloads::expired(&entry.ctx),
        }
    }
}

/// What one try of [`Engine::cancel_attempt`] came to.
pub(crate) enum Attempt {
    /// This call made the request terminal; the envelope is the cause's answer.
    Ended(Box<Envelope>),
    /// The request is in memory and this call changed nothing (not cancellable, already
    /// terminal, expiry deferred, or the append failed): the current state answers.
    Unchanged(Arc<RequestEntry>),
    /// Not in memory: the records answer.
    Gone,
}

/// [`Engine::cancel_now`] could not take the entry's gate: another transition held it (across
/// an append) for the whole wait, so **nothing was ended or changed**. This is not an answer
/// about the request; retry, or use the awaited path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelBusy;

/// What the gated section did.
enum Locked {
    Ended,
    Unchanged,
}

/// Tries of 1 ms [`Engine::cancel_now`] waits for a busy gate (a transition holds it across one
/// append) before it reports [`CancelBusy`].
const BUSY_TRIES: u32 = 5_000;

impl Engine {
    /// The state-independent cancel (§4.4) for **synchronous, non-runtime** callers: no `await`,
    /// no network.
    ///
    /// A request that is `pending` (any phase before `executing` was emitted) ends `cancelled` /
    /// `expired` with its in-flight bytes committed first; one that is `executing`, terminal or
    /// not in memory is answered with its current reduced status (never `DELIVERED`, never data).
    /// A gate held by another transition is polled in 1 ms steps (bounded by `BUSY_TRIES`); if it
    /// stays held the call returns `Err(CancelBusy)` and has done nothing, so a caller can tell
    /// "could not run" from "not cancellable".
    ///
    /// **Never call it from a runtime thread**: gates are held across `.await` points, so the
    /// blocking poll can starve the very task that holds the gate (current-thread runtime).
    /// Async callers, the shutdown sweep (Task 28) included, use [`Engine::cancel_and_wait`].
    pub fn cancel_now(&self, request_id: &str, cause: CancelCause) -> Result<Envelope, CancelBusy> {
        for _ in 0..BUSY_TRIES {
            match self.try_attempt(request_id, cause) {
                Some(attempt) => return Ok(self.attempt_envelope(request_id, attempt)),
                None => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        Err(CancelBusy)
    }

    /// The answer of a finished attempt.
    fn attempt_envelope(&self, request_id: &str, attempt: Attempt) -> Envelope {
        match attempt {
            Attempt::Ended(env) => *env,
            Attempt::Unchanged(entry) => self.current_answer_sync(&entry),
            Attempt::Gone => self.records_answer_sync(request_id),
        }
    }

    /// [`Engine::cancel_now`] for async callers: the same attempt, but a busy gate is awaited
    /// (`lock_owned().await`: fair, no polling), and the whole thing runs in its own task so a
    /// dropped caller does not leave a cancel half-waited (the gated section is atomic). It
    /// always runs the attempt: there is no busy outcome.
    pub(crate) async fn cancel_awaited(
        self: &Arc<Self>,
        request_id: &str,
        cause: CancelCause,
    ) -> Attempt {
        let (engine, id) = (self.clone(), request_id.to_owned());
        tokio::spawn(async move { engine.attempt_awaited(&id, cause).await })
            .await
            .unwrap_or(Attempt::Gone)
    }

    /// [`Engine::cancel_awaited`] with the envelope `cancel_now` answers: the entry point of the
    /// shutdown sweep (Task 28), which must use the awaited path.
    pub async fn cancel_and_wait(
        self: &Arc<Self>,
        request_id: &str,
        cause: CancelCause,
    ) -> Envelope {
        let attempt = self.cancel_awaited(request_id, cause).await;
        self.attempt_envelope(request_id, attempt)
    }

    /// PD-14: the expiry path now (the timer calls the same code); `false` if the request did
    /// not end (not in memory, or its phase cannot expire: it then expires when it can).
    pub async fn expire_now(self: &Arc<Self>, request_id: &str) -> bool {
        matches!(
            self.cancel_awaited(request_id, CancelCause::Expiry).await,
            Attempt::Ended(_)
        )
    }

    /// One non-waiting try: the entry's gate by `try_lock`, then the gated section. `None`: the
    /// gate is busy and nothing was done.
    fn try_attempt(&self, request_id: &str, cause: CancelCause) -> Option<Attempt> {
        let Some(entry) = self.entry(request_id) else {
            return Some(Attempt::Gone);
        };
        let gate = entry.gate.clone().try_lock_owned().ok()?;
        Some(self.attempt_locked(entry, &gate, cause))
    }

    /// The attempt with the gate awaited.
    pub(crate) async fn attempt_awaited(&self, request_id: &str, cause: CancelCause) -> Attempt {
        let Some(entry) = self.entry(request_id) else {
            return Attempt::Gone;
        };
        let gate = entry.gate.clone().lock_owned().await;
        self.attempt_locked(entry, &gate, cause)
    }

    fn attempt_locked(
        &self,
        entry: Arc<RequestEntry>,
        gate: &GateGuard,
        cause: CancelCause,
    ) -> Attempt {
        match self.cancel_locked(&entry, gate, cause) {
            Locked::Ended => Attempt::Ended(Box::new(ended_envelope(&entry, cause))),
            Locked::Unchanged => Attempt::Unchanged(entry),
        }
    }

    /// The gated section (`gate` is the proof that the entry's transition gate is held).
    ///
    /// 1. Step a clone with the cause's event: a rejection (`NotCancellable`, terminal) changes
    ///    nothing; an `Expire` the phase refuses (`Illegal`) sets `expiry_due`.
    /// 2. Only now, with the model accepting the end, the control is cancelled and its capture
    ///    taken; bytes that were sent become `READ_FETCHED {cancelled_in_flight, ..}` (a read) or
    ///    `PREVIEW_FETCH {purpose, cancelled_in_flight, ..}` (the GET of a write in flight).
    /// 3. One `append_batch` of `[in-flight record?, CANCELLED | EXPIRED]`; a failed append
    ///    fails the request (`audit_failure`, §11.1).
    /// 4. The model applies, the admission place is released ([`Engine::after_change`]).
    fn cancel_locked(
        &self,
        entry: &Arc<RequestEntry>,
        _gate: &GateGuard,
        cause: CancelCause,
    ) -> Locked {
        let event = cause.event();
        let (prepared, fetching) = {
            let mut st = entry.state();
            if !is_pending(st.model.phase()) {
                return Locked::Unchanged;
            }
            let fetching = matches!(st.model.phase(), Phase::Fetching);
            match Prepared::step(&st, event) {
                Ok(p) => (p, fetching),
                Err(Rejection::Illegal) if matches!(event, Event::Expire) => {
                    st.expiry_due = true;
                    return Locked::Unchanged;
                }
                Err(_) => return Locked::Unchanged,
            }
        };
        let mut records = Vec::with_capacity(3);
        // Review I-2: the record of a GET that finished but that no append committed yet goes
        // first (§5.4 step 2: every GET of an enrichment or stale check is logged).
        if let Some(done) = entry.take_parked() {
            records.push(done);
        }
        if let Some(ctl) = entry.fetch_control() {
            ctl.cancel();
            let cap = ctl.take_captured();
            let reason = cause.in_flight();
            if cap.sent {
                match entry.kind() {
                    // Review I-1: only a read aborted in `Fetching` has an unrecorded fetch; in
                    // `AwaitingRelease` its `READ_FETCHED` is committed already.
                    Kind::Read if fetching => {
                        let size = cap
                            .pages
                            .iter()
                            .map(|p| p.body.len() as u64)
                            .sum::<u64>()
                            .saturating_add(cap.partial.len() as u64);
                        records.push(payloads::read_fetched(
                            &entry.ctx,
                            &ReadFetched::CancelledInFlight {
                                reason,
                                responses: &cap.pages,
                                partial: &cap.partial,
                                size,
                            },
                            None,
                        ));
                    }
                    Kind::Write => {
                        if let Some(f) = entry.in_flight() {
                            records.push(payloads::preview_fetch(
                                &entry.ctx,
                                f.purpose,
                                "GET",
                                &f.path,
                                &FetchRecord::CancelledInFlight {
                                    reason,
                                    received: &cap.partial,
                                },
                            ));
                        }
                    }
                    Kind::Read | Kind::Script | Kind::DryRun => {}
                }
            }
        }
        // Task 27: a running script is killed here (`RunHandle::kill(KillReason::Client)`,
        // without awaiting `wait`) and `SCRIPT_FAILED {cancelled_by_client}` goes first.
        records.push(cause.terminal_record(entry));
        let appended = if records.len() == 1 {
            records
                .pop()
                .map_or(Ok(()), |ev| self.port().append(ev).map(|_| ()))
        } else {
            self.port().append_batch(records).map(|_| ())
        };
        if appended.is_err() {
            self.fail_unlogged(entry);
            return Locked::Unchanged;
        }
        let applied = prepared.apply(entry, event, |_| {}, |_| true);
        self.after_change(entry);
        if applied.is_ok() {
            Locked::Ended
        } else {
            Locked::Unchanged
        }
    }

    /// Task 12 review I-4, called by [`Engine::transition`] under its gate after a model
    /// replace: a request whose timer fired while its phase could not expire (or whose time is
    /// up) expires now if the new phase can.
    pub(super) fn expire_if_due(&self, entry: &Arc<RequestEntry>, gate: &GateGuard) {
        let due = {
            let st = entry.state();
            is_pending(st.model.phase()) && (st.expiry_due || entry.age() >= self.expiry())
        };
        if due {
            let _ = self.cancel_locked(entry, gate, CancelCause::Expiry);
        }
    }

    /// The timer of one pending request: `sleep(submitted_at + expiry)`, then
    /// `cancel(.., Expiry)`. It ends when the request does and never resets (§4.4).
    pub(crate) fn arm_expiry(self: &Arc<Self>, entry: &Arc<RequestEntry>) {
        if !is_pending(entry.state().model.phase()) {
            return;
        }
        let remaining = self.expiry().saturating_sub(entry.age());
        let (weak, entry) = (Arc::downgrade(self), entry.clone());
        let mut rx = entry.subscribe();
        tokio::spawn(async move {
            let ended = async {
                loop {
                    if OpenStatus::of(*rx.borrow_and_update()).is_none()
                        || rx.changed().await.is_err()
                    {
                        return;
                    }
                }
            };
            tokio::select! {
                () = tokio::time::sleep(remaining) => {}
                () = ended => return,
            }
            let id = entry.head.request_id.clone();
            if let Some(engine) = weak.upgrade() {
                let _ = engine.attempt_awaited(&id, CancelCause::Expiry).await;
            }
        });
    }

    /// The reduced status of an in-memory entry, without any await (`cancel`'s answer when it
    /// ended nothing, §4.4 "afterwards it returns the current status").
    pub(crate) fn current_answer_sync(&self, entry: &Arc<RequestEntry>) -> Envelope {
        let (status, unlogged) = {
            let st = entry.state();
            (
                crate::lifecycle::model::agent_status(&st.model),
                st.unlogged_terminal.clone(),
            )
        };
        if let Some(open) = OpenStatus::of(status) {
            return envelope::pending_envelope(
                &entry.head.request_id,
                Some(&entry.head.op_id),
                Some(&entry.head.instance),
                open,
            );
        }
        if let Some(e) = unlogged {
            return envelope::unlogged_envelope(&entry.head, status, &e, true);
        }
        self.records_answer_sync(&entry.head.request_id)
    }

    /// The reduced status of an id answered from the records; `unknown_request` if the log does
    /// not know it.
    pub(crate) fn records_answer_sync(&self, request_id: &str) -> Envelope {
        match self.status_from_records_sync(request_id) {
            Ok(Some(rs)) => envelope::status_envelope(&rs),
            Ok(None) => envelope::unknown_request(),
            Err(_) => envelope::audit_unreadable(),
        }
    }
}

/// The answer of the call that ended the request: the identical `cancelled` envelope for a
/// client cancel (§4.4); for expiry and shutdown what a poll of the committed record says.
fn ended_envelope(entry: &RequestEntry, cause: CancelCause) -> Envelope {
    let (t, payload) = match cause {
        CancelCause::Client => return envelope::cancelled_by_client(&entry.head),
        CancelCause::Expiry => (EventType::EXPIRED, None),
        CancelCause::Shutdown(r) => {
            let reason = match r {
                ShutdownReason::AppQuit => "app_quit",
                ShutdownReason::OsShutdown => "os_shutdown",
            };
            (EventType::CANCELLED, Some(json!({ "reason": reason })))
        }
    };
    let (status, error): (Status, _) =
        envelope::record_status(t, payload.as_ref(), Some(entry.class()));
    envelope::status_envelope(&RecordStatus {
        request_id: entry.head.request_id.clone(),
        op_id: Some(entry.head.op_id.clone()),
        instance: Some(entry.head.instance.clone()),
        status,
        error,
    })
}
