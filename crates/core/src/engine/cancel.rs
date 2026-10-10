//! Cancel and expiry (§4.4, §5.2 step 3, §5.4 step 2, §2.5 step 2; Task 24).
//!
//! [`Engine::cancel_now`] is the one synchronous path to a cancelled, expired or shutdown-ended
//! request. It never awaits (so it never waits on the network, an aborted connection or a
//! reaped process) and holds only `std::sync` locks plus the entry's transition gate, which it
//! takes with `try_lock`.
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
use crate::lifecycle::model::{CancelReason, Event, Kind, Rejection, is_pending};
use crate::payloads::{self, FetchRecord, InFlightReason, ReadFetched};

/// Who ends the request (§4.4, §2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelCause {
    /// The agent's `cancel`.
    Client,
    /// The expiry timer (or `expire_now`).
    Expiry,
    /// The shutdown path (§2.5 step 2, Task 28).
    Shutdown(CancelReason),
}

impl CancelCause {
    fn event(self) -> Event {
        match self {
            Self::Client => Event::Cancel(CancelReason::ByClient),
            Self::Expiry => Event::Expire,
            Self::Shutdown(r) => Event::Cancel(r),
        }
    }

    /// The `reason` of a `cancelled_in_flight` record.
    fn in_flight(self) -> InFlightReason {
        match self {
            Self::Client => InFlightReason::ByClient,
            Self::Expiry => InFlightReason::Expired,
            Self::Shutdown(CancelReason::AppQuit) => InFlightReason::AppQuit,
            Self::Shutdown(CancelReason::OsShutdown) => InFlightReason::OsShutdown,
            Self::Shutdown(CancelReason::ByClient) => InFlightReason::ByClient,
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
    /// Another record-bearing transition holds the entry's gate right now.
    Busy,
}

/// What the gated section did.
enum Locked {
    Ended,
    Unchanged,
}

/// Tries of 1 ms [`Engine::cancel_now`] waits for a busy gate (a transition holds it across one
/// append) before it answers with the current state.
const BUSY_TRIES: u32 = 5_000;

impl Engine {
    /// The state-independent cancel (§4.4): a synchronous function, no `await`, no network.
    ///
    /// A request that is `pending` (any phase before `executing` was emitted) ends `cancelled` /
    /// `expired` with its in-flight bytes committed first; one that is `executing`, terminal or
    /// not in memory is answered with its current reduced status (never `DELIVERED`, never data).
    /// A gate held by another transition is waited for in 1 ms steps (bounded by `BUSY_TRIES`);
    /// async callers use [`Engine::cancel_awaited`], which yields instead of sleeping.
    pub fn cancel_now(&self, request_id: &str, cause: CancelCause) -> Envelope {
        for _ in 0..BUSY_TRIES {
            match self.cancel_attempt(request_id, cause) {
                Attempt::Ended(env) => return *env,
                Attempt::Unchanged(entry) => return self.current_answer_sync(&entry),
                Attempt::Gone => return self.records_answer_sync(request_id),
                Attempt::Busy => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        match self.entry(request_id) {
            Some(entry) => self.current_answer_sync(&entry),
            None => self.records_answer_sync(request_id),
        }
    }

    /// [`Engine::cancel_now`] for async callers: the same attempt, but a busy gate is awaited
    /// with a yielding sleep, and the whole thing runs in its own task so a dropped caller does
    /// not leave a cancel half-waited (the attempt itself is atomic).
    pub(crate) async fn cancel_awaited(
        self: &Arc<Self>,
        request_id: &str,
        cause: CancelCause,
    ) -> Attempt {
        let (engine, id) = (self.clone(), request_id.to_owned());
        tokio::spawn(async move {
            loop {
                match engine.cancel_attempt(&id, cause) {
                    Attempt::Busy => tokio::time::sleep(Duration::from_millis(1)).await,
                    other => return other,
                }
            }
        })
        .await
        .unwrap_or(Attempt::Gone)
    }

    /// PD-14: the expiry path now (the timer calls the same code); `false` if the request did
    /// not end (not in memory, or its phase cannot expire: it then expires when it can).
    pub async fn expire_now(self: &Arc<Self>, request_id: &str) -> bool {
        matches!(
            self.cancel_awaited(request_id, CancelCause::Expiry).await,
            Attempt::Ended(_)
        )
    }

    /// One non-waiting try: the entry's gate by `try_lock`, then the gated section.
    pub(crate) fn cancel_attempt(&self, request_id: &str, cause: CancelCause) -> Attempt {
        let Some(entry) = self.entry(request_id) else {
            return Attempt::Gone;
        };
        let Ok(gate) = entry.gate.clone().try_lock_owned() else {
            return Attempt::Busy;
        };
        match self.cancel_locked(&entry, &gate, cause) {
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
        let prepared = {
            let mut st = entry.state();
            if !is_pending(st.model.phase()) {
                return Locked::Unchanged;
            }
            match Prepared::step(&st, event) {
                Ok(p) => p,
                Err(Rejection::Illegal) if matches!(event, Event::Expire) => {
                    st.expiry_due = true;
                    return Locked::Unchanged;
                }
                Err(_) => return Locked::Unchanged,
            }
        };
        let mut records = Vec::with_capacity(2);
        if let Some(ctl) = entry.fetch_control() {
            ctl.cancel();
            let cap = ctl.take_captured();
            let reason = cause.in_flight();
            if cap.sent {
                match entry.kind() {
                    Kind::Read => {
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
                    Kind::Script | Kind::DryRun => {}
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
            loop {
                let Some(engine) = weak.upgrade() else {
                    return;
                };
                match engine.cancel_attempt(&id, CancelCause::Expiry) {
                    Attempt::Busy => tokio::time::sleep(Duration::from_millis(1)).await,
                    _ => return,
                }
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
                CancelReason::ByClient => "by_client",
                CancelReason::AppQuit => "app_quit",
                CancelReason::OsShutdown => "os_shutdown",
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
