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

use std::collections::HashSet;
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

/// The writes that are `executing` now.
fn executing(engine: &Arc<Engine>) -> Vec<Arc<crate::engine::RequestEntry>> {
    engine
        .pending_entries()
        .into_iter()
        .filter(|e| phase_of(e) == Phase::Executing)
        .collect()
}

/// §2.5 steps 2-4. The waiting set is listed again on every poll: a write that a version
/// conflict sent back to the queue and that was approved again can become `executing` during the
/// wait, and is waited for like the others.
pub(crate) async fn sweep(engine: &Arc<Engine>, why: CancelWhy, write_wait: Duration) -> Swept {
    let cause = CancelCause::Shutdown(why);
    let mut swept = Swept::default();
    let mut seen: HashSet<String> = HashSet::new();
    let deadline = Instant::now() + write_wait;
    // A round that finds nothing executing is repeated once more (round, then list again): a
    // write whose stale check completed while the round cancelled earlier ids has turned
    // `executing` by now, and is waited for like the others. The sweep ends on a second empty
    // list in a row or when the budget is over; the last round before it also ends what came
    // back to the queue (a version conflict) or arrived while the sweep ran.
    let mut settled = false;
    loop {
        swept.cancelled += cancel_round(engine, cause).await;
        let running = executing(engine);
        seen.extend(running.iter().map(|e| e.head.request_id.clone()));
        if Instant::now() >= deadline {
            break;
        }
        if running.is_empty() {
            if settled {
                break;
            }
            settled = true;
            continue;
        }
        settled = false;
        tokio::time::sleep(POLL).await;
    }
    swept.writes_waited = u32::try_from(seen.len()).unwrap_or(u32::MAX);
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
