//! The worker's interrupt checks (spec §9.3 "Interrupt handler checks the deadline and the op
//! budget"; plan M8 PD-135).
//!
//! The host's own timer decides `timeout_s` and kills the process; the worker's deadline is only a
//! backstop at `timeout_s + 2 s`, and a run it stops is a runtime error, never a limit. There is
//! no cancel flag: a cancel, a user kill and a shutdown kill the process (§9.3, L167).
//!
//! QuickJS calls the interrupt handler once per `JS_INTERRUPT_COUNTER_INIT` (10 000) interpreter
//! ticks (loop back-edges and calls), so the [`OpBudget`] counts callbacks, not instructions.
//!
//! Only code that polls reaches the handler: the interpreter, regex execution (libregexp polls
//! during backtracking) and some array natives (`every`, `reduce`, `includes`, `indexOf`,
//! `lastIndexOf`, `find`). Other native loops never poll, e.g.
//! `Array.prototype.copyWithin.call({ length: 2 ** 53 - 1 }, 0, 1)` probes and deletes about
//! 9e15 properties inside one native call without allocating. Neither the backstop deadline nor
//! the op budget can stop such a run; the host's `timeout_s` kill (PD-135) ends it, which is
//! correct: the host's timer is the authoritative one.

use std::time::{Duration, Instant};

use atlas_duck_ipc::sandbox::ScriptLimits;

/// How far past `timeout_s` the worker's own deadline lies (plan value, PD-135).
pub const BACKSTOP_SLACK: Duration = Duration::from_secs(2);

/// Interrupt callbacks a run may use (plan value, PD-135): 2^25 callbacks ≈ 3.4 × 10^11
/// interpreter ticks. It bounds a CPU-bound run of polling code whose clock reads stall; the
/// deadline normally ends a run first.
///
/// Headroom estimate, not a measurement: the budget outlasts the largest configurable timeout
/// (4 × 120 s + 2 s = 482 s) only while the interpreter runs below about 3.4e11 / 482 ≈ 7e8
/// ticks/s. A bare `for (;;) {}` is one `OP_goto` plus a counter decrement per tick, and its
/// rate on CI hardware is unmeasured (Task 25 measures it). If the budget fires first, a long
/// CPU-bound run ends as a worker-reported `OpBudget` runtime error instead of the host's
/// `timeout_s`: conservative, never a leak.
pub const OP_BUDGET_CALLBACKS: u64 = 1 << 25;

/// The worker's backstop for a run: `timeout_s + 2 s`.
pub fn backstop(limits: &ScriptLimits) -> Duration {
    Duration::from_secs(u64::from(limits.timeout_s)).saturating_add(BACKSTOP_SLACK)
}

/// A wall-clock deadline; `None` inside means "never" (a duration past the clock's range).
#[derive(Debug, Clone, Copy)]
pub struct Deadline(Option<Instant>);

impl Deadline {
    /// The deadline `after` from now.
    pub fn after(after: Duration) -> Self {
        Deadline(Instant::now().checked_add(after))
    }

    /// Whether the deadline has passed.
    pub fn expired(&self) -> bool {
        self.0.is_some_and(|at| Instant::now() >= at)
    }
}

/// A countdown of interrupt callbacks.
#[derive(Debug, Clone)]
pub struct OpBudget {
    remaining: u64,
}

impl OpBudget {
    /// A budget of `callbacks` interrupt callbacks.
    pub fn new(callbacks: u64) -> Self {
        OpBudget {
            remaining: callbacks,
        }
    }

    /// Spends one callback; `true` once the budget is used up.
    pub fn tick(&mut self) -> bool {
        match self.remaining.checked_sub(1) {
            Some(rest) => {
                self.remaining = rest;
                false
            }
            None => true,
        }
    }
}

impl Default for OpBudget {
    fn default() -> Self {
        OpBudget::new(OP_BUDGET_CALLBACKS)
    }
}
