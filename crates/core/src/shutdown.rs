//! The shutdown path (§2.5 steps 2-5, I-40, Task 28). Step 1 (`begin_shutdown`: every new
//! `submit` / `submit_script` is refused `app_shutting_down`) is the caller's.
//!
//! Everything that is not `executing` ends `cancelled` with the app's reason through the awaited
//! cancel path ([`Engine::cancel_awaited`], never `cancel_now`, which reports `CancelBusy` for a
//! gate another transition holds): reads in `Fetching` and fetches already written commit their
//! `cancelled_in_flight` record first (I-11), a script is killed and gets a non-terminal
//! `SCRIPT_FAILED` before its `CANCELLED`, a write in `StaleCheck` is cancellable on this path
//! (and only on this one). Writes that are `executing` are waited for (their own flow logs the
//! outcome) for at most the 60 s that the write call is bounded by.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::engine::Engine;
use crate::engine::cancel::{Attempt, CancelCause, ShutdownReason as CancelWhy};
use crate::lifecycle::model::{Phase, is_pending};
use crate::payloads::{self, AppStopReason};

/// How long a write that is `executing` is waited for: the budget of a write call (§7.2).
pub(crate) const WRITE_WAIT: Duration = Duration::from_secs(60);

/// How often a waiting sweep looks at the writes it waits for.
const POLL: Duration = Duration::from_millis(20);

/// Rounds of "cancel what is not executing": a decision or a write returning to the queue while
/// the sweep runs can make a request cancellable again.
const ROUNDS: u32 = 4;

/// What the sweep did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Swept {
    pub cancelled: u32,
    pub writes_waited: u32,
}

fn phase_of(e: &crate::engine::RequestEntry) -> Phase {
    e.state().model.phase()
}

/// Cancels every pending request that is not `executing`; returns how many ended.
async fn cancel_round(engine: &Arc<Engine>, cause: CancelCause) -> u32 {
    let mut ended = 0;
    for _ in 0..ROUNDS {
        let ids: Vec<String> = engine
            .pending_entries()
            .into_iter()
            .filter(|e| {
                let p = phase_of(e);
                is_pending(p) && p != Phase::Executing
            })
            .map(|e| e.head.request_id.clone())
            .collect();
        if ids.is_empty() {
            break;
        }
        let mut progressed = false;
        for id in ids {
            if matches!(engine.cancel_awaited(&id, cause).await, Attempt::Ended(_)) {
                ended += 1;
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    ended
}

/// §2.5 steps 2-4.
pub(crate) async fn sweep(engine: &Arc<Engine>, why: CancelWhy, write_wait: Duration) -> Swept {
    let cause = CancelCause::Shutdown(why);
    let mut swept = Swept {
        cancelled: cancel_round(engine, cause).await,
        writes_waited: 0,
    };
    let mut waiting: Vec<_> = engine
        .pending_entries()
        .into_iter()
        .filter(|e| phase_of(e) == Phase::Executing)
        .collect();
    swept.writes_waited = u32::try_from(waiting.len()).unwrap_or(u32::MAX);
    let deadline = Instant::now() + write_wait;
    while !waiting.is_empty() && Instant::now() < deadline {
        waiting.retain(|e| phase_of(e) == Phase::Executing);
        if !waiting.is_empty() {
            tokio::time::sleep(POLL).await;
        }
    }
    // A write that came back to the queue (a version conflict) or a request that arrived while
    // the sweep ran is not executing any more: it ends here too.
    swept.cancelled += cancel_round(engine, cause).await;
    swept
}

/// §2.5 step 5: flush the head anchor, append `APP_STOP`, flush again so the anchor covers it.
/// A failed flush is not an error (`health()` shows it); a failed append is returned.
pub(crate) async fn stop(
    engine: &Arc<Engine>,
    reason: AppStopReason,
) -> Result<(), atlas_duck_audit::AuditError> {
    let flush = |engine: &Arc<Engine>| {
        let engine = engine.clone();
        async move {
            let _ = engine.blocking(|p| p.flush_head_anchor()).await;
        }
    };
    flush(engine).await;
    engine
        .blocking(move |p| p.append(payloads::app_stop(reason)).map(|_| ()))
        .await?;
    flush(engine).await;
    Ok(())
}
