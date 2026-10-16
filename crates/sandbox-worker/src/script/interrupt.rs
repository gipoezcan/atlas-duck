//! The worker's interrupt checks (spec §9.3 "Interrupt handler checks the deadline and the op
//! budget"; plan M8 PD-135).
//!
//! The host's own timer decides `timeout_s` and kills the process; the worker's deadline is only a
//! backstop at `timeout_s + 2 s`, and a run it stops is a runtime error, never a limit. There is
//! no cancel flag: a cancel, a user kill and a shutdown kill the process (§9.3, L167).
//!
//! QuickJS calls the interrupt handler once per `JS_INTERRUPT_COUNTER_INIT` (10 000) interpreter
//! ticks (loop back-edges and calls), so the [`OpBudget`] counts callbacks, not instructions.

use std::time::{Duration, Instant};

use atlas_duck_ipc::sandbox::ScriptLimits;

/// How far past `timeout_s` the worker's own deadline lies (plan value, PD-135).
pub const BACKSTOP_SLACK: Duration = Duration::from_secs(2);

/// Interrupt callbacks a run may use (plan value, PD-135): 2^25 callbacks ≈ 3.4 × 10^11
/// interpreter ticks, more than any run executes within the largest configurable timeout
/// (4 × 120 s + 2 s) on current hardware. It bounds a CPU-bound run whose clock reads stall; the
/// deadline normally ends it first.
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
