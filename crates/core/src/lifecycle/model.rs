//! Pure model of the §5.1 state machine. No I/O, no clock, no audit: the engine logs, then calls
//! `step` with the event the log entry represents; a `Rejection` means "do not log the transition".

use atlas_duck_ipc::envelope::Status;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Read,
    Write,
    Script,
    DryRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseItem {
    Result,
    UpstreamError,
    Outcome,
    ScriptResult,
    ScriptErrorDetails,
}

/// `AwaitingApproval(...)` sub-states (§5.1). Only `Preview` can be approvable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hold {
    Preview,
    EnrichmentError,
    Collision,
    UnresolvedName,
    Conflict,
    IdentityMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
    ByClient,
    AppQuit,
    OsShutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    Rejected,
    Failed,
    Released,
    ReleasedRedacted,
    Denied,
    Succeeded,
    OutcomeUnknown,
    Expired,
    Cancelled(CancelReason),
    Abandoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Received,
    Validated,
    Fetching,
    AwaitingRelease(ReleaseItem),
    Enriching,
    AwaitingApproval(Hold),
    StaleCheck,
    Executing,
    Compiling,
    SlotWait,
    Running,
    DryRunning,
    Done(Terminal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleReason {
    Changed,
    RecheckFailed,
    IdentityMismatch,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecOutcome {
    Succeeded,
    Failed,
    OutcomeUnknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceEvt {
    CredentialChanged,
    InstanceChanged,
    UserRenamed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    ValidationPassed,
    ValidationFailed,
    FetchStarted,
    Fetched(ReleaseItem),
    FetchFailedDirect,
    EnrichStarted,
    Enriched(Hold),
    EnrichFailedDirect,
    CompileStarted,
    CompileOk,
    CompileFailed,
    SlotAcquired,
    RunEnded {
        direct: bool,
        item: ReleaseItem,
    },
    DryRunStarted,
    DryRunEnded {
        ok: bool,
    },
    PreviewShown {
        rev: u64,
    },
    CandidateChanged, // redaction set changed, re-render, script invalidation
    Release {
        rev: u64,
        redacted: bool,
    },
    Approve {
        rev: u64,
    },
    Edit {
        rev: u64,
        target_or_baseline_changed: bool,
        rerun_enrichment: bool,
    },
    Deny {
        rev: u64,
    },
    StalePassed,
    Stale(StaleReason),
    VersionConflict,
    Executed(ExecOutcome),
    Instance(InstanceEvt),
    Cancel(CancelReason),
    Expire,
    AuditFailure,
    Crash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    Illegal,
    StaleRev { current: u64 },
    NotOpened,
    NotApprovable,
    TargetParamEdit,
    NotCancellable,
}

/// What the engine must do after an accepted event (besides logging, which it did before).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    pub rev_bumped: bool,
    pub became_terminal: bool,
}

#[derive(Debug, Clone)]
pub struct Model {
    pub kind: Kind,
    phase: Phase,
    rev: u64,
    opened: bool,
    approvable: bool,
    executing_emitted: bool,
    approved_unreturned: bool,
}

impl Model {
    pub fn new(kind: Kind) -> Model {
        Model {
            kind,
            phase: Phase::Received,
            rev: 0,
            opened: false,
            approvable: false,
            executing_emitted: false,
            approved_unreturned: false,
        }
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn rev(&self) -> u64 {
        self.rev
    }
    pub fn opened(&self) -> bool {
        self.opened
    }
    pub fn approvable(&self) -> bool {
        self.approvable
    }
    pub fn approved_unreturned(&self) -> bool {
        self.approved_unreturned
    }
    /// Rust-computed approvability (§5.1 inv. 6) for the *current* revision.
    pub fn set_approvable(&mut self, v: bool) {
        self.approvable = v;
    }

    fn bump(&mut self) {
        self.rev += 1;
        self.opened = false;
        self.approvable = false;
    }
}

pub fn is_pending(p: Phase) -> bool {
    !matches!(p, Phase::Done(_))
}

/// The agent-visible status (§4.5): `pending` until terminal, except `executing` once a write's
/// stale check passed, which then sticks until terminal (also across a version-conflict return).
pub fn agent_status(m: &Model) -> Status {
    match m.phase {
        Phase::Done(t) => match t {
            Terminal::Rejected | Terminal::Failed => Status::Failed,
            Terminal::Released | Terminal::ReleasedRedacted => Status::Released,
            Terminal::Denied => Status::Denied,
            Terminal::Succeeded => Status::Succeeded,
            Terminal::OutcomeUnknown => Status::OutcomeUnknown,
            Terminal::Expired => Status::Expired,
            Terminal::Cancelled(_) => Status::Cancelled,
            Terminal::Abandoned => Status::Abandoned,
        },
        _ if m.executing_emitted => Status::Executing,
        _ => Status::Pending,
    }
}

pub fn step(m: &mut Model, e: Event) -> Result<Applied, Rejection> {
    use Event as E;
    use Phase as P;
    let before = m.rev;
    let done = |m: &mut Model, t: Terminal| {
        m.phase = P::Done(t);
    };
    match (m.phase, e) {
        (P::Done(_), E::Cancel(_)) => return Err(Rejection::NotCancellable),
        (P::Done(_), _) => return Err(Rejection::Illegal),

        // Crash reconciliation (§11.3): approved and not returned → outcome_unknown, else abandoned.
        (_, E::Crash) => {
            let t = if m.approved_unreturned {
                Terminal::OutcomeUnknown
            } else {
                Terminal::Abandoned
            };
            done(m, t);
        }
        (P::Executing, E::AuditFailure) => done(m, Terminal::OutcomeUnknown), // sent but unlogged
        (_, E::AuditFailure) => done(m, Terminal::Failed),

        (P::Received, E::ValidationPassed) => m.phase = P::Validated,
        (P::Received, E::ValidationFailed) => done(m, Terminal::Rejected),

        (P::Validated, E::FetchStarted) if m.kind == Kind::Read => m.phase = P::Fetching,
        (P::Validated, E::EnrichStarted) if m.kind == Kind::Write => m.phase = P::Enriching,
        (P::Validated, E::CompileStarted) if m.kind == Kind::Script => m.phase = P::Compiling,
        (P::Validated, E::DryRunStarted) if m.kind == Kind::DryRun => m.phase = P::DryRunning,

        (P::Fetching, E::Fetched(item))
            if matches!(
                item,
                ReleaseItem::Result | ReleaseItem::UpstreamError | ReleaseItem::Outcome
            ) =>
        {
            m.phase = P::AwaitingRelease(item);
            m.bump();
        }
        (P::Fetching, E::FetchFailedDirect) => done(m, Terminal::Failed),

        (P::Enriching, E::Enriched(hold)) => {
            m.phase = P::AwaitingApproval(hold);
            m.bump();
        }
        (P::Enriching, E::EnrichFailedDirect) => done(m, Terminal::Failed),

        (P::Compiling, E::CompileOk) => m.phase = P::SlotWait,
        (P::Compiling, E::CompileFailed) => done(m, Terminal::Failed),
        (P::SlotWait, E::SlotAcquired) => m.phase = P::Running,
        (P::Running, E::RunEnded { direct: true, .. }) => done(m, Terminal::Failed),
        (
            P::Running,
            E::RunEnded {
                direct: false,
                item,
            },
        ) if matches!(
            item,
            ReleaseItem::ScriptResult | ReleaseItem::ScriptErrorDetails
        ) =>
        {
            m.phase = P::AwaitingRelease(item);
            m.bump();
        }
        (P::DryRunning, E::DryRunEnded { ok }) => done(
            m,
            if ok {
                Terminal::Succeeded
            } else {
                Terminal::Failed
            },
        ),

        // "Opened" for the current revision only (§5.6).
        (P::AwaitingRelease(_) | P::AwaitingApproval(_), E::PreviewShown { rev }) => {
            if rev != m.rev {
                return Err(Rejection::StaleRev { current: m.rev });
            }
            m.opened = true;
        }
        (P::AwaitingRelease(_) | P::AwaitingApproval(_), E::CandidateChanged) => m.bump(),

        (P::AwaitingRelease(item), E::Release { rev, redacted }) => {
            if rev != m.rev {
                return Err(Rejection::StaleRev { current: m.rev });
            }
            if !m.opened {
                return Err(Rejection::NotOpened);
            }
            if !m.approvable {
                return Err(Rejection::NotApprovable);
            }
            if redacted && item == ReleaseItem::Outcome {
                return Err(Rejection::Illegal);
            }
            done(
                m,
                if redacted {
                    Terminal::ReleasedRedacted
                } else {
                    Terminal::Released
                },
            );
        }
        (P::AwaitingRelease(_) | P::AwaitingApproval(_), E::Deny { rev }) => {
            if rev != m.rev {
                return Err(Rejection::StaleRev { current: m.rev });
            }
            done(m, Terminal::Denied);
        }

        (P::AwaitingApproval(hold), E::Approve { rev }) => {
            if rev != m.rev {
                return Err(Rejection::StaleRev { current: m.rev });
            }
            if !m.opened {
                return Err(Rejection::NotOpened);
            }
            if hold != Hold::Preview || !m.approvable {
                return Err(Rejection::NotApprovable);
            }
            m.phase = P::StaleCheck;
            m.approved_unreturned = true;
        }
        (
            P::AwaitingApproval(_),
            E::Edit {
                rev,
                target_or_baseline_changed,
                rerun_enrichment,
            },
        ) => {
            if rev != m.rev {
                return Err(Rejection::StaleRev { current: m.rev });
            }
            if target_or_baseline_changed {
                return Err(Rejection::TargetParamEdit);
            }
            if rerun_enrichment {
                m.phase = P::Enriching;
                m.opened = false;
                m.approvable = false;
            } else {
                m.bump();
            }
        }
        // credential_changed / instance_changed / user_renamed (§5.1): a new revision, but the hold
        // is an enrichment verdict and stays until a refresh (`Enriched`) re-decides it (inv. 6).
        (P::AwaitingApproval(_), E::Instance(_)) => m.bump(),
        // Refresh (§5.4 step 5, §7.1): re-enrichment of a queued write; the rev bumps at `Enriched`.
        (P::AwaitingApproval(_), E::EnrichStarted) if m.kind == Kind::Write => {
            m.phase = P::Enriching;
            m.opened = false;
            m.approvable = false;
        }
        (
            P::AwaitingRelease(ReleaseItem::ScriptResult | ReleaseItem::ScriptErrorDetails),
            E::Instance(_),
        ) => m.bump(),

        (P::StaleCheck, E::StalePassed) => {
            m.phase = P::Executing;
            m.executing_emitted = true;
        }
        (P::StaleCheck, E::Stale(reason)) => {
            let hold = if reason == StaleReason::IdentityMismatch {
                Hold::IdentityMismatch
            } else {
                Hold::Preview
            };
            m.phase = P::AwaitingApproval(hold);
            m.approved_unreturned = false;
            m.bump();
        }
        (
            P::StaleCheck,
            E::Instance(InstanceEvt::CredentialChanged | InstanceEvt::InstanceChanged),
        ) => {
            m.phase = P::AwaitingApproval(Hold::Preview);
            m.approved_unreturned = false;
            m.bump();
        }
        (P::Executing, E::Executed(o)) => done(
            m,
            match o {
                ExecOutcome::Succeeded => Terminal::Succeeded,
                ExecOutcome::Failed => Terminal::Failed,
                ExecOutcome::OutcomeUnknown => Terminal::OutcomeUnknown,
            },
        ),
        (P::Executing, E::VersionConflict) => {
            m.phase = P::AwaitingApproval(Hold::Conflict);
            m.approved_unreturned = false;
            m.bump(); // executing_emitted stays true (§4.5)
        }
        // Origin guard refusal or a pre-send connection failure at execution: nothing left the
        // client, so the write returns to the queue as recheck_failed (Task 10 `NotSent`/`OriginGuardRefused`).
        (P::Executing, E::Stale(StaleReason::RecheckFailed)) => {
            m.phase = P::AwaitingApproval(Hold::Preview);
            m.approved_unreturned = false;
            m.bump();
        }

        // Cancel / expiry (§4.4, §2.5): never from StaleCheck/Executing except shutdown from StaleCheck.
        (P::Executing, E::Cancel(_)) => return Err(Rejection::NotCancellable),
        (P::StaleCheck, E::Cancel(CancelReason::ByClient)) => {
            return Err(Rejection::NotCancellable);
        }
        // Once `executing` was emitted the agent keeps seeing it until terminal (§4.5): a write
        // returned to the queue answers a client cancel like one still executing (§4.4).
        (_, E::Cancel(CancelReason::ByClient)) if m.executing_emitted => {
            return Err(Rejection::NotCancellable);
        }
        (P::StaleCheck, E::Cancel(r)) => done(m, Terminal::Cancelled(r)),
        (_, E::Cancel(r)) => done(m, Terminal::Cancelled(r)),
        (P::StaleCheck | P::Executing | P::Running | P::DryRunning, E::Expire) => {
            return Err(Rejection::Illegal);
        }
        (_, E::Expire) => done(m, Terminal::Expired),

        _ => return Err(Rejection::Illegal),
    }
    Ok(Applied {
        rev_bumped: m.rev != before,
        became_terminal: matches!(m.phase, P::Done(_)),
    })
}

#[cfg(test)]
mod tests {
    use super::Event as E;
    use super::Phase as P;
    use super::*;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const KINDS: [Kind; 4] = [Kind::Read, Kind::Write, Kind::Script, Kind::DryRun];
    const ITEMS: [ReleaseItem; 5] = [
        ReleaseItem::Result,
        ReleaseItem::UpstreamError,
        ReleaseItem::Outcome,
        ReleaseItem::ScriptResult,
        ReleaseItem::ScriptErrorDetails,
    ];
    const READ_ITEMS: [ReleaseItem; 3] = [
        ReleaseItem::Result,
        ReleaseItem::UpstreamError,
        ReleaseItem::Outcome,
    ];
    const SCRIPT_ITEMS: [ReleaseItem; 2] =
        [ReleaseItem::ScriptResult, ReleaseItem::ScriptErrorDetails];
    const HOLDS: [Hold; 6] = [
        Hold::Preview,
        Hold::EnrichmentError,
        Hold::Collision,
        Hold::UnresolvedName,
        Hold::Conflict,
        Hold::IdentityMismatch,
    ];
    const REASONS: [CancelReason; 3] = [
        CancelReason::ByClient,
        CancelReason::AppQuit,
        CancelReason::OsShutdown,
    ];
    const STALE: [StaleReason; 3] = [
        StaleReason::Changed,
        StaleReason::RecheckFailed,
        StaleReason::IdentityMismatch,
    ];
    const OUTCOMES: [ExecOutcome; 3] = [
        ExecOutcome::Succeeded,
        ExecOutcome::Failed,
        ExecOutcome::OutcomeUnknown,
    ];
    const INSTANCE: [InstanceEvt; 3] = [
        InstanceEvt::CredentialChanged,
        InstanceEvt::InstanceChanged,
        InstanceEvt::UserRenamed,
    ];
    const TERMINALS: [Terminal; 12] = [
        Terminal::Rejected,
        Terminal::Failed,
        Terminal::Released,
        Terminal::ReleasedRedacted,
        Terminal::Denied,
        Terminal::Succeeded,
        Terminal::OutcomeUnknown,
        Terminal::Expired,
        Terminal::Cancelled(CancelReason::ByClient),
        Terminal::Cancelled(CancelReason::AppQuit),
        Terminal::Cancelled(CancelReason::OsShutdown),
        Terminal::Abandoned,
    ];

    /// One index per `Event` variant. The match has no wildcard, so a new variant fails to
    /// compile here until `all_events` (and the sweep's `expected`) know about it.
    fn event_index(e: Event) -> usize {
        match e {
            E::ValidationPassed => 0,
            E::ValidationFailed => 1,
            E::FetchStarted => 2,
            E::Fetched(_) => 3,
            E::FetchFailedDirect => 4,
            E::EnrichStarted => 5,
            E::Enriched(_) => 6,
            E::EnrichFailedDirect => 7,
            E::CompileStarted => 8,
            E::CompileOk => 9,
            E::CompileFailed => 10,
            E::SlotAcquired => 11,
            E::RunEnded { .. } => 12,
            E::DryRunStarted => 13,
            E::DryRunEnded { .. } => 14,
            E::PreviewShown { .. } => 15,
            E::CandidateChanged => 16,
            E::Release { .. } => 17,
            E::Approve { .. } => 18,
            E::Edit { .. } => 19,
            E::Deny { .. } => 20,
            E::StalePassed => 21,
            E::Stale(_) => 22,
            E::VersionConflict => 23,
            E::Executed(_) => 24,
            E::Instance(_) => 25,
            E::Cancel(_) => 26,
            E::Expire => 27,
            E::AuditFailure => 28,
            E::Crash => 29,
        }
    }
    const EVENT_VARIANTS: usize = 30;

    /// Same guard for `Phase`: a new phase must be added to `all_phases` and `targets`.
    fn phase_index(p: Phase) -> usize {
        match p {
            P::Received => 0,
            P::Validated => 1,
            P::Fetching => 2,
            P::AwaitingRelease(_) => 3,
            P::Enriching => 4,
            P::AwaitingApproval(_) => 5,
            P::StaleCheck => 6,
            P::Executing => 7,
            P::Compiling => 8,
            P::SlotWait => 9,
            P::Running => 10,
            P::DryRunning => 11,
            P::Done(_) => 12,
        }
    }
    const PHASE_VARIANTS: usize = 13;

    /// Every phase with every sub-state (33).
    fn all_phases() -> Vec<Phase> {
        let mut v = vec![P::Received, P::Validated, P::Fetching];
        v.extend(ITEMS.map(P::AwaitingRelease));
        v.push(P::Enriching);
        v.extend(HOLDS.map(P::AwaitingApproval));
        v.extend([
            P::StaleCheck,
            P::Executing,
            P::Compiling,
            P::SlotWait,
            P::Running,
            P::DryRunning,
        ]);
        v.extend(TERMINALS.map(P::Done));
        v
    }

    /// Every event with every field value; rev-carrying events use `rev`.
    fn all_events(rev: u64) -> Vec<Event> {
        let mut v = vec![E::ValidationPassed, E::ValidationFailed, E::FetchStarted];
        v.extend(ITEMS.map(E::Fetched));
        v.extend([E::FetchFailedDirect, E::EnrichStarted]);
        v.extend(HOLDS.map(E::Enriched));
        v.extend([
            E::EnrichFailedDirect,
            E::CompileStarted,
            E::CompileOk,
            E::CompileFailed,
            E::SlotAcquired,
        ]);
        for direct in [false, true] {
            v.extend(ITEMS.map(|item| E::RunEnded { direct, item }));
        }
        v.extend([
            E::DryRunStarted,
            E::DryRunEnded { ok: true },
            E::DryRunEnded { ok: false },
            E::PreviewShown { rev },
            E::CandidateChanged,
            E::Release {
                rev,
                redacted: false,
            },
            E::Release {
                rev,
                redacted: true,
            },
            E::Approve { rev },
        ]);
        for target_or_baseline_changed in [false, true] {
            for rerun_enrichment in [false, true] {
                v.push(E::Edit {
                    rev,
                    target_or_baseline_changed,
                    rerun_enrichment,
                });
            }
        }
        v.extend([E::Deny { rev }, E::StalePassed]);
        v.extend(STALE.map(E::Stale));
        v.push(E::VersionConflict);
        v.extend(OUTCOMES.map(E::Executed));
        v.extend(INSTANCE.map(E::Instance));
        v.extend(REASONS.map(E::Cancel));
        v.extend([E::Expire, E::AuditFailure, E::Crash]);
        v
    }

    /// Everything observable about a model, for "a rejection changes nothing" checks.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Snap {
        kind: Kind,
        phase: Phase,
        rev: u64,
        opened: bool,
        approvable: bool,
        executing_emitted: bool,
        approved_unreturned: bool,
        status: Status,
    }

    fn snap(m: &Model) -> Snap {
        Snap {
            kind: m.kind,
            phase: m.phase(),
            rev: m.rev(),
            opened: m.opened(),
            approvable: m.approvable(),
            executing_emitted: m.executing_emitted,
            approved_unreturned: m.approved_unreturned(),
            status: agent_status(m),
        }
    }

    /// A scripted engine step: an event, or the engine's `set_approvable`.
    #[derive(Debug, Clone, Copy)]
    enum S {
        V(Event),
        A(bool),
    }
    use S::{A, V};

    /// Runs `steps` from `Received`; every event must be accepted.
    fn run(kind: Kind, steps: &[S]) -> Result<Model, Box<dyn std::error::Error>> {
        let mut m = Model::new(kind);
        for (i, s) in steps.iter().enumerate() {
            match *s {
                A(v) => m.set_approvable(v),
                V(e) => {
                    let at = m.phase();
                    step(&mut m, e).map_err(|r| format!("step {i}: {e:?} in {at:?}: {r:?}"))?;
                }
            }
        }
        Ok(m)
    }

    /// `e` must be accepted.
    fn ok(m: &mut Model, e: Event) -> Result<Applied, Box<dyn std::error::Error>> {
        let at = m.phase();
        Ok(step(m, e).map_err(|r| format!("{e:?} in {at:?}: {r:?}"))?)
    }

    /// `e` must be rejected with `want` and leave the model untouched.
    fn rejects(m: &mut Model, e: Event, want: Rejection) -> TestResult {
        let before = snap(m);
        let got = step(m, e);
        assert_eq!(got, Err(want), "{e:?} in {:?}", before.phase);
        assert_eq!(snap(m), before, "rejected {e:?} changed the model");
        Ok(())
    }

    fn read_to(item: ReleaseItem) -> Vec<S> {
        vec![
            V(E::ValidationPassed),
            V(E::FetchStarted),
            V(E::Fetched(item)),
        ]
    }
    fn write_to(hold: Hold) -> Vec<S> {
        vec![
            V(E::ValidationPassed),
            V(E::EnrichStarted),
            V(E::Enriched(hold)),
        ]
    }
    fn script_to(item: ReleaseItem) -> Vec<S> {
        vec![
            V(E::ValidationPassed),
            V(E::CompileStarted),
            V(E::CompileOk),
            V(E::SlotAcquired),
            V(E::RunEnded {
                direct: false,
                item,
            }),
        ]
    }
    /// Opens revision 1 (the first candidate) and lets the engine mark it approvable.
    fn open(mut steps: Vec<S>) -> Vec<S> {
        steps.extend([V(E::PreviewShown { rev: 1 }), A(true)]);
        steps
    }
    fn with(mut steps: Vec<S>, more: &[S]) -> Vec<S> {
        steps.extend_from_slice(more);
        steps
    }
    fn to_stale_check() -> Vec<S> {
        with(open(write_to(Hold::Preview)), &[V(E::Approve { rev: 1 })])
    }
    fn to_executing() -> Vec<S> {
        with(to_stale_check(), &[V(E::StalePassed)])
    }

    /// A path to a reachable state, plus what the path did that the phase alone does not show.
    struct Target {
        kind: Kind,
        phase: Phase,
        steps: Vec<S>,
        /// `executing` was emitted on the way (a write back in the queue after `StalePassed`).
        emitted: bool,
    }

    fn tg(kind: Kind, phase: Phase, steps: Vec<S>) -> Target {
        Target {
            kind,
            phase,
            steps,
            emitted: false,
        }
    }

    /// A path to every phase (per kind where the entry depends on it), plus the write states
    /// reached again after `executing` was emitted.
    fn targets() -> Vec<Target> {
        let vp = V(E::ValidationPassed);
        let mut t = Vec::new();
        for k in KINDS {
            t.push(tg(k, P::Received, vec![]));
            t.push(tg(k, P::Validated, vec![vp]));
        }
        t.push(tg(Kind::Read, P::Fetching, vec![vp, V(E::FetchStarted)]));
        for i in READ_ITEMS {
            t.push(tg(Kind::Read, P::AwaitingRelease(i), open(read_to(i))));
        }
        t.push(tg(Kind::Write, P::Enriching, vec![vp, V(E::EnrichStarted)]));
        for h in HOLDS {
            t.push(tg(Kind::Write, P::AwaitingApproval(h), open(write_to(h))));
        }
        t.push(tg(Kind::Write, P::StaleCheck, to_stale_check()));
        t.push(Target {
            emitted: true,
            ..tg(Kind::Write, P::Executing, to_executing())
        });
        let compiling = vec![vp, V(E::CompileStarted)];
        t.push(tg(Kind::Script, P::Compiling, compiling.clone()));
        let slot_wait = with(compiling, &[V(E::CompileOk)]);
        t.push(tg(Kind::Script, P::SlotWait, slot_wait.clone()));
        t.push(tg(
            Kind::Script,
            P::Running,
            with(slot_wait, &[V(E::SlotAcquired)]),
        ));
        for i in SCRIPT_ITEMS {
            t.push(tg(Kind::Script, P::AwaitingRelease(i), open(script_to(i))));
        }
        t.push(tg(
            Kind::DryRun,
            P::DryRunning,
            vec![vp, V(E::DryRunStarted)],
        ));

        // Back in the queue after `executing` was emitted (§4.5: the status stays `executing`).
        let conflict = with(
            to_executing(),
            &[
                V(E::VersionConflict),
                V(E::PreviewShown { rev: 2 }),
                A(true),
            ],
        );
        let not_sent = with(
            to_executing(),
            &[
                V(E::Stale(StaleReason::RecheckFailed)),
                V(E::PreviewShown { rev: 2 }),
                A(true),
            ],
        );
        let re_approved = with(not_sent.clone(), &[V(E::Approve { rev: 2 })]);
        for (phase, steps) in [
            (P::AwaitingApproval(Hold::Conflict), conflict.clone()),
            (P::AwaitingApproval(Hold::Preview), not_sent.clone()),
            (P::Enriching, with(conflict, &[V(E::EnrichStarted)])),
            (
                P::Enriching,
                with(
                    not_sent,
                    &[V(E::Edit {
                        rev: 2,
                        target_or_baseline_changed: false,
                        rerun_enrichment: true,
                    })],
                ),
            ),
            (P::StaleCheck, re_approved.clone()),
            (P::Executing, with(re_approved, &[V(E::StalePassed)])),
        ] {
            t.push(Target {
                emitted: true,
                ..tg(Kind::Write, phase, steps)
            });
        }

        let released = open(read_to(ReleaseItem::Result));
        let done = |t: Terminal| P::Done(t);
        t.push(tg(
            Kind::Read,
            done(Terminal::Rejected),
            vec![V(E::ValidationFailed)],
        ));
        t.push(tg(
            Kind::Read,
            done(Terminal::Failed),
            vec![vp, V(E::FetchStarted), V(E::FetchFailedDirect)],
        ));
        t.push(tg(
            Kind::Read,
            done(Terminal::Released),
            with(
                released.clone(),
                &[V(E::Release {
                    rev: 1,
                    redacted: false,
                })],
            ),
        ));
        t.push(tg(
            Kind::Read,
            done(Terminal::ReleasedRedacted),
            with(
                released.clone(),
                &[V(E::Release {
                    rev: 1,
                    redacted: true,
                })],
            ),
        ));
        t.push(tg(
            Kind::Read,
            done(Terminal::Denied),
            with(released, &[V(E::Deny { rev: 1 })]),
        ));
        t.push(tg(
            Kind::DryRun,
            done(Terminal::Succeeded),
            vec![vp, V(E::DryRunStarted), V(E::DryRunEnded { ok: true })],
        ));
        t.push(Target {
            emitted: true,
            ..tg(
                Kind::Write,
                done(Terminal::OutcomeUnknown),
                with(
                    to_executing(),
                    &[V(E::Executed(ExecOutcome::OutcomeUnknown))],
                ),
            )
        });
        t.push(tg(Kind::Read, done(Terminal::Expired), vec![V(E::Expire)]));
        for r in REASONS {
            t.push(tg(
                Kind::Script,
                done(Terminal::Cancelled(r)),
                vec![V(E::Cancel(r))],
            ));
        }
        t.push(tg(
            Kind::Write,
            done(Terminal::Abandoned),
            vec![V(E::Crash)],
        ));
        t
    }

    /// The §5.1 transition table as the sweep expects it, for a model reached by `targets`
    /// (current revision opened and approvable, events carrying the current revision). Written
    /// row by row from the spec diagram and the plan decisions; everything unlisted is `Illegal`.
    /// `Ok((next phase, rev bumped))`.
    fn expected(t: &Target, e: Event) -> Result<(Phase, bool), Rejection> {
        use ReleaseItem as I;
        let (kind, phase) = (t.kind, t.phase);
        let to = |p: Phase| -> Result<(Phase, bool), Rejection> { Ok((p, false)) };
        let bump = |p: Phase| -> Result<(Phase, bool), Rejection> { Ok((p, true)) };
        let done = |t: Terminal| -> Result<(Phase, bool), Rejection> { Ok((P::Done(t), false)) };
        let approved = matches!(phase, P::StaleCheck | P::Executing);
        let decidable = matches!(phase, P::AwaitingRelease(_) | P::AwaitingApproval(_));
        match (phase, e) {
            // Terminal is final; a cancel then answers with the current status (§4.4).
            (P::Done(_), E::Cancel(_)) => Err(Rejection::NotCancellable),
            (P::Done(_), _) => Err(Rejection::Illegal),

            // §11.3: approved and not returned → outcome_unknown, everything else abandoned.
            (_, E::Crash) if approved => done(Terminal::OutcomeUnknown),
            (_, E::Crash) => done(Terminal::Abandoned),
            // §5.1 "Infrastructure failures → Failed"; plan: sent but unlogged → outcome_unknown.
            (P::Executing, E::AuditFailure) => done(Terminal::OutcomeUnknown),
            (_, E::AuditFailure) => done(Terminal::Failed),
            // §4.4, §2.5: StaleCheck only via the shutdown path, Executing never; once
            // `executing` was shown the client cannot cancel (§4.5), only the shutdown path can.
            (P::Executing, E::Cancel(_)) => Err(Rejection::NotCancellable),
            (P::StaleCheck, E::Cancel(CancelReason::ByClient)) => Err(Rejection::NotCancellable),
            (_, E::Cancel(CancelReason::ByClient)) if t.emitted => Err(Rejection::NotCancellable),
            (_, E::Cancel(r)) => done(Terminal::Cancelled(r)),
            // Plan: phases bounded by their own budgets ignore expiry.
            (P::StaleCheck | P::Executing | P::Running | P::DryRunning, E::Expire) => {
                Err(Rejection::Illegal)
            }
            (_, E::Expire) => done(Terminal::Expired),

            // Received ─validate─▶ Validated | Rejected.
            (P::Received, E::ValidationPassed) => to(P::Validated),
            (P::Received, E::ValidationFailed) => done(Terminal::Rejected),
            // One entry per kind.
            (P::Validated, E::FetchStarted) if kind == Kind::Read => to(P::Fetching),
            (P::Validated, E::EnrichStarted) if kind == Kind::Write => to(P::Enriching),
            (P::Validated, E::CompileStarted) if kind == Kind::Script => to(P::Compiling),
            (P::Validated, E::DryRunStarted) if kind == Kind::DryRun => to(P::DryRunning),

            // Read: Fetching → AwaitingRelease(result | upstream-error | outcome) | Failed.
            (P::Fetching, E::Fetched(i @ (I::Result | I::UpstreamError | I::Outcome))) => {
                bump(P::AwaitingRelease(i))
            }
            (P::Fetching, E::FetchFailedDirect) => done(Terminal::Failed),
            // Write: Enriching → AwaitingApproval(any hold) | Failed.
            (P::Enriching, E::Enriched(h)) => bump(P::AwaitingApproval(h)),
            (P::Enriching, E::EnrichFailedDirect) => done(Terminal::Failed),
            // Script: Compiling → SlotWait → Running → AwaitingRelease(result | error-details).
            (P::Compiling, E::CompileOk) => to(P::SlotWait),
            (P::Compiling, E::CompileFailed) => done(Terminal::Failed),
            (P::SlotWait, E::SlotAcquired) => to(P::Running),
            (P::Running, E::RunEnded { direct: true, .. }) => done(Terminal::Failed),
            (
                P::Running,
                E::RunEnded {
                    direct: false,
                    item: i @ (I::ScriptResult | I::ScriptErrorDetails),
                },
            ) => bump(P::AwaitingRelease(i)),
            // Dry run: never reaches the release flow.
            (P::DryRunning, E::DryRunEnded { ok: true }) => done(Terminal::Succeeded),
            (P::DryRunning, E::DryRunEnded { ok: false }) => done(Terminal::Failed),

            // Waiting for a decision (§5.6, inv. 5).
            (_, E::PreviewShown { .. }) if decidable => to(phase),
            (_, E::CandidateChanged) if decidable => bump(phase),
            (_, E::Deny { .. }) if decidable => done(Terminal::Denied),
            // An outcome item has no redactable content (§5.2 step 6).
            (P::AwaitingRelease(I::Outcome), E::Release { redacted: true, .. }) => {
                Err(Rejection::Illegal)
            }
            (
                P::AwaitingRelease(_),
                E::Release {
                    redacted: false, ..
                },
            ) => done(Terminal::Released),
            (P::AwaitingRelease(_), E::Release { redacted: true, .. }) => {
                done(Terminal::ReleasedRedacted)
            }
            // Only AwaitingApproval(preview) is approvable (inv. 6).
            (P::AwaitingApproval(Hold::Preview), E::Approve { .. }) => to(P::StaleCheck),
            (P::AwaitingApproval(_), E::Approve { .. }) => Err(Rejection::NotApprovable),
            (
                P::AwaitingApproval(_),
                E::Edit {
                    target_or_baseline_changed: true,
                    ..
                },
            ) => Err(Rejection::TargetParamEdit),
            (
                P::AwaitingApproval(_),
                E::Edit {
                    rerun_enrichment: true,
                    ..
                },
            ) => to(P::Enriching),
            (P::AwaitingApproval(_), E::Edit { .. }) => bump(phase),
            // Instance events never re-decide the hold (inv. 6); a refresh does.
            (P::AwaitingApproval(_), E::Instance(_)) => bump(phase),
            (P::AwaitingApproval(_), E::EnrichStarted) if kind == Kind::Write => to(P::Enriching),
            (P::AwaitingRelease(I::ScriptResult | I::ScriptErrorDetails), E::Instance(_)) => {
                bump(phase)
            }

            // StaleCheck → Executing | Stale → AwaitingApproval (§5.4 step 5).
            (P::StaleCheck, E::StalePassed) => to(P::Executing),
            (P::StaleCheck, E::Stale(StaleReason::IdentityMismatch)) => {
                bump(P::AwaitingApproval(Hold::IdentityMismatch))
            }
            (P::StaleCheck, E::Stale(_)) => bump(P::AwaitingApproval(Hold::Preview)),
            (
                P::StaleCheck,
                E::Instance(InstanceEvt::CredentialChanged | InstanceEvt::InstanceChanged),
            ) => bump(P::AwaitingApproval(Hold::Preview)),
            // Executing → outcome | version conflict | not sent (§5.4 step 6, Task 10).
            (P::Executing, E::Executed(ExecOutcome::Succeeded)) => done(Terminal::Succeeded),
            (P::Executing, E::Executed(ExecOutcome::Failed)) => done(Terminal::Failed),
            (P::Executing, E::Executed(ExecOutcome::OutcomeUnknown)) => {
                done(Terminal::OutcomeUnknown)
            }
            (P::Executing, E::VersionConflict) => bump(P::AwaitingApproval(Hold::Conflict)),
            (P::Executing, E::Stale(StaleReason::RecheckFailed)) => {
                bump(P::AwaitingApproval(Hold::Preview))
            }

            _ => Err(Rejection::Illegal),
        }
    }

    #[test]
    fn sweep_tables_cover_every_variant() -> TestResult {
        let mut events = [false; EVENT_VARIANTS];
        for e in all_events(7) {
            events[event_index(e)] = true;
        }
        assert!(
            events.iter().all(|&b| b),
            "all_events misses a variant: {events:?}"
        );
        let mut phases = [false; PHASE_VARIANTS];
        for p in all_phases() {
            phases[phase_index(p)] = true;
        }
        assert!(
            phases.iter().all(|&b| b),
            "all_phases misses a variant: {phases:?}"
        );
        assert_eq!(all_phases().len(), 33);
        Ok(())
    }

    /// U-01: every reachable (kind, phase) × every event with every field value.
    #[test]
    fn u01_every_state_event_pair() -> TestResult {
        let targets = targets();
        let mut failures = Vec::new();
        for p in all_phases() {
            if !targets.iter().any(|t| t.phase == p) {
                failures.push(format!("no target reaches {p:?}"));
            }
        }
        let mut pairs = 0usize;
        for t in &targets {
            let (kind, phase) = (t.kind, t.phase);
            let m = run(kind, &t.steps)?;
            if m.phase() != phase || m.executing_emitted != t.emitted {
                failures.push(format!(
                    "{kind:?} path ends in {:?} (emitted {}), not {phase:?}",
                    m.phase(),
                    m.executing_emitted
                ));
                continue;
            }
            for e in all_events(m.rev()) {
                pairs += 1;
                let mut n = m.clone();
                let before = snap(&n);
                let got = step(&mut n, e);
                let after = snap(&n);
                let want = expected(t, e);
                let fine = match (got, want) {
                    (Ok(a), Ok((next, bumped))) => {
                        after.phase == next
                            && a.rev_bumped == bumped
                            && after.rev == before.rev + u64::from(bumped)
                            && a.became_terminal != is_pending(next)
                            && (!bumped || (!after.opened && !after.approvable))
                    }
                    (Err(r), Err(w)) => r == w && after == before,
                    _ => false,
                };
                if !fine {
                    failures.push(format!(
                        "{kind:?} {phase:?} + {e:?}: got {got:?} ending in {:?}, want {want:?}",
                        after.phase
                    ));
                }
            }
        }
        assert!(pairs > 2000, "sweep too small: {pairs}");
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("\n").into())
        }
    }

    #[test]
    fn read_paths() -> TestResult {
        // Fetching → AwaitingRelease(result) → Released; only `pending` before the decision.
        let mut m = run(Kind::Read, &read_to(ReleaseItem::Result))?;
        assert_eq!(m.phase(), P::AwaitingRelease(ReleaseItem::Result));
        assert_eq!((m.rev(), m.opened(), m.approvable()), (1, false, false));
        assert_eq!(agent_status(&m), Status::Pending);
        ok(&mut m, E::PreviewShown { rev: 1 })?;
        m.set_approvable(true);
        let a = ok(
            &mut m,
            E::Release {
                rev: 1,
                redacted: false,
            },
        )?;
        assert_eq!(
            a,
            Applied {
                rev_bumped: false,
                became_terminal: true
            }
        );
        assert_eq!(m.phase(), P::Done(Terminal::Released));
        assert_eq!(agent_status(&m), Status::Released);

        // Release with redactions.
        let mut m = run(Kind::Read, &open(read_to(ReleaseItem::Result)))?;
        ok(
            &mut m,
            E::Release {
                rev: 1,
                redacted: true,
            },
        )?;
        assert_eq!(m.phase(), P::Done(Terminal::ReleasedRedacted));
        assert_eq!(agent_status(&m), Status::Released);

        // Upstream-error card: release (status only is a redaction) or deny.
        let mut m = run(Kind::Read, &open(read_to(ReleaseItem::UpstreamError)))?;
        ok(
            &mut m,
            E::Release {
                rev: 1,
                redacted: true,
            },
        )?;
        assert_eq!(m.phase(), P::Done(Terminal::ReleasedRedacted));
        let mut m = run(Kind::Read, &read_to(ReleaseItem::UpstreamError))?;
        ok(&mut m, E::Deny { rev: 1 })?; // deny needs no opened preview
        assert_eq!(m.phase(), P::Done(Terminal::Denied));
        assert_eq!(agent_status(&m), Status::Denied);

        // Outcome item: Release outcome or Deny, never a redacted release.
        let mut m = run(Kind::Read, &open(read_to(ReleaseItem::Outcome)))?;
        rejects(
            &mut m,
            E::Release {
                rev: 1,
                redacted: true,
            },
            Rejection::Illegal,
        )?;
        ok(
            &mut m,
            E::Release {
                rev: 1,
                redacted: false,
            },
        )?;
        assert_eq!(m.phase(), P::Done(Terminal::Released));

        // Data-free direct failure, validation failure.
        let mut m = run(Kind::Read, &[V(E::ValidationPassed), V(E::FetchStarted)])?;
        rejects(
            &mut m,
            E::Fetched(ReleaseItem::ScriptResult),
            Rejection::Illegal,
        )?;
        ok(&mut m, E::FetchFailedDirect)?;
        assert_eq!(m.phase(), P::Done(Terminal::Failed));
        assert_eq!(agent_status(&m), Status::Failed);
        let m = run(Kind::Read, &[V(E::ValidationFailed)])?;
        assert_eq!(m.phase(), P::Done(Terminal::Rejected));
        assert_eq!(agent_status(&m), Status::Failed);

        // A read enters only through FetchStarted; reads ignore instance events.
        let mut m = run(Kind::Read, &[V(E::ValidationPassed)])?;
        for e in [E::EnrichStarted, E::CompileStarted, E::DryRunStarted] {
            rejects(&mut m, e, Rejection::Illegal)?;
        }
        let mut m = run(Kind::Read, &open(read_to(ReleaseItem::Result)))?;
        rejects(
            &mut m,
            E::Instance(InstanceEvt::CredentialChanged),
            Rejection::Illegal,
        )?;
        rejects(&mut m, E::Approve { rev: 1 }, Rejection::Illegal)?;
        Ok(())
    }

    #[test]
    fn write_paths() -> TestResult {
        // Happy path: pending until the stale check passes, then executing until terminal.
        let mut m = run(Kind::Write, &open(write_to(Hold::Preview)))?;
        assert_eq!(
            (m.phase(), m.rev()),
            (P::AwaitingApproval(Hold::Preview), 1)
        );
        assert_eq!(agent_status(&m), Status::Pending);
        let a = ok(&mut m, E::Approve { rev: 1 })?;
        assert_eq!(
            a,
            Applied {
                rev_bumped: false,
                became_terminal: false
            }
        );
        assert_eq!(m.phase(), P::StaleCheck);
        assert!(m.approved_unreturned());
        assert_eq!(agent_status(&m), Status::Pending); // a failing stale check stays invisible
        ok(&mut m, E::StalePassed)?;
        assert_eq!(m.phase(), P::Executing);
        assert_eq!(agent_status(&m), Status::Executing);
        ok(&mut m, E::Executed(ExecOutcome::Succeeded))?;
        assert_eq!(agent_status(&m), Status::Succeeded);
        for (o, t, s) in [
            (ExecOutcome::Failed, Terminal::Failed, Status::Failed),
            (
                ExecOutcome::OutcomeUnknown,
                Terminal::OutcomeUnknown,
                Status::OutcomeUnknown,
            ),
        ] {
            let mut m = run(Kind::Write, &to_executing())?;
            ok(&mut m, E::Executed(o))?;
            assert_eq!((m.phase(), agent_status(&m)), (P::Done(t), s));
        }

        // Enrichment: direct failure, or any hold; only Preview approvable.
        let mut m = run(Kind::Write, &[V(E::ValidationPassed), V(E::EnrichStarted)])?;
        ok(&mut m, E::EnrichFailedDirect)?;
        assert_eq!(m.phase(), P::Done(Terminal::Failed));
        for h in HOLDS.into_iter().filter(|h| *h != Hold::Preview) {
            let mut m = run(Kind::Write, &open(write_to(h)))?;
            assert!(m.approvable()); // even if the engine wrongly marks it approvable
            rejects(&mut m, E::Approve { rev: 1 }, Rejection::NotApprovable)?;
            ok(&mut m, E::Deny { rev: 1 })?;
            assert_eq!(m.phase(), P::Done(Terminal::Denied));
        }

        // Stale check fails: back to the queue, new revision, unopened, still pending.
        for (reason, hold) in [
            (StaleReason::Changed, Hold::Preview),
            (StaleReason::RecheckFailed, Hold::Preview),
            (StaleReason::IdentityMismatch, Hold::IdentityMismatch),
        ] {
            let mut m = run(Kind::Write, &to_stale_check())?;
            let a = ok(&mut m, E::Stale(reason))?;
            assert!(a.rev_bumped);
            assert_eq!((m.phase(), m.rev()), (P::AwaitingApproval(hold), 2));
            assert!(!m.opened() && !m.approvable() && !m.approved_unreturned());
            assert_eq!(agent_status(&m), Status::Pending);
        }
        let mut m = run(Kind::Write, &to_stale_check())?;
        ok(&mut m, E::Instance(InstanceEvt::InstanceChanged))?;
        assert_eq!(
            (m.phase(), m.rev()),
            (P::AwaitingApproval(Hold::Preview), 2)
        );
        assert!(!m.approved_unreturned());
        let mut m = run(Kind::Write, &to_stale_check())?;
        rejects(
            &mut m,
            E::Instance(InstanceEvt::UserRenamed),
            Rejection::Illegal,
        )?;

        // Version conflict keeps `executing` (§4.5) and lands in the unapprovable conflict hold.
        let mut m = run(Kind::Write, &to_executing())?;
        ok(&mut m, E::VersionConflict)?;
        assert_eq!(
            (m.phase(), m.rev()),
            (P::AwaitingApproval(Hold::Conflict), 2)
        );
        assert_eq!(agent_status(&m), Status::Executing);
        ok(&mut m, E::PreviewShown { rev: 2 })?;
        m.set_approvable(true);
        rejects(&mut m, E::Approve { rev: 2 }, Rejection::NotApprovable)?;
        assert_eq!(agent_status(&m), Status::Executing);
        ok(&mut m, E::Deny { rev: 2 })?;
        assert_eq!(agent_status(&m), Status::Denied);

        // Not sent at execution (origin guard, pre-send connection failure): back as recheck_failed.
        let mut m = run(Kind::Write, &to_executing())?;
        rejects(&mut m, E::Stale(StaleReason::Changed), Rejection::Illegal)?;
        ok(&mut m, E::Stale(StaleReason::RecheckFailed))?;
        assert_eq!(
            (m.phase(), m.rev()),
            (P::AwaitingApproval(Hold::Preview), 2)
        );
        assert_eq!(agent_status(&m), Status::Executing);

        // Edits: plain edit bumps; enrichment-relevant edit re-enriches and bumps at Enriched.
        let mut m = run(Kind::Write, &open(write_to(Hold::Preview)))?;
        ok(
            &mut m,
            E::Edit {
                rev: 1,
                target_or_baseline_changed: false,
                rerun_enrichment: false,
            },
        )?;
        assert_eq!(
            (m.phase(), m.rev(), m.opened()),
            (P::AwaitingApproval(Hold::Preview), 2, false)
        );
        let a = ok(
            &mut m,
            E::Edit {
                rev: 2,
                target_or_baseline_changed: false,
                rerun_enrichment: true,
            },
        )?;
        assert!(!a.rev_bumped);
        assert_eq!(
            (m.phase(), m.rev(), m.opened(), m.approvable()),
            (P::Enriching, 2, false, false)
        );
        ok(&mut m, E::Enriched(Hold::Collision))?;
        assert_eq!(
            (m.phase(), m.rev()),
            (P::AwaitingApproval(Hold::Collision), 3)
        );
        let mut m = run(Kind::Write, &open(write_to(Hold::Preview)))?;
        let target = E::Edit {
            rev: 1,
            target_or_baseline_changed: true,
            rerun_enrichment: false,
        };
        rejects(&mut m, target, Rejection::TargetParamEdit)?;

        // Refresh of a queued write (re-enrichment) and instance events in the queue.
        let mut m = run(Kind::Write, &open(write_to(Hold::IdentityMismatch)))?;
        ok(&mut m, E::EnrichStarted)?;
        assert_eq!((m.phase(), m.rev(), m.opened()), (P::Enriching, 1, false));
        // Instance events bump the revision but never re-decide the hold (inv. 6): only the
        // refresh's `Enriched` does.
        for h in HOLDS {
            for ev in INSTANCE {
                let mut m = run(Kind::Write, &open(write_to(h)))?;
                let a = ok(&mut m, E::Instance(ev))?;
                assert!(a.rev_bumped);
                assert_eq!(
                    (m.phase(), m.rev(), m.opened(), m.approvable()),
                    (P::AwaitingApproval(h), 2, false, false),
                    "{h:?} + {ev:?}"
                );
            }
        }
        // The lost-update case: a conflict hold survives a token change even if the engine
        // wrongly marks the new revision approvable; a refresh decides it again.
        let mut m = run(Kind::Write, &open(write_to(Hold::Conflict)))?;
        ok(&mut m, E::Instance(InstanceEvt::CredentialChanged))?;
        ok(&mut m, E::PreviewShown { rev: 2 })?;
        m.set_approvable(true);
        rejects(&mut m, E::Approve { rev: 2 }, Rejection::NotApprovable)?;
        ok(&mut m, E::EnrichStarted)?;
        ok(&mut m, E::Enriched(Hold::Preview))?;
        assert_eq!(
            (m.phase(), m.rev()),
            (P::AwaitingApproval(Hold::Preview), 3)
        );
        Ok(())
    }

    #[test]
    fn script_paths() -> TestResult {
        let mut m = run(
            Kind::Script,
            &[V(E::ValidationPassed), V(E::CompileStarted)],
        )?;
        assert_eq!(m.phase(), P::Compiling);
        ok(&mut m, E::CompileOk)?;
        assert_eq!(m.phase(), P::SlotWait);
        ok(&mut m, E::SlotAcquired)?;
        assert_eq!(m.phase(), P::Running);
        assert_eq!(agent_status(&m), Status::Pending);
        rejects(&mut m, E::Expire, Rejection::Illegal)?; // bounded by timeout_s
        rejects(
            &mut m,
            E::RunEnded {
                direct: false,
                item: ReleaseItem::Result,
            },
            Rejection::Illegal,
        )?;
        ok(
            &mut m,
            E::RunEnded {
                direct: false,
                item: ReleaseItem::ScriptResult,
            },
        )?;
        assert_eq!(
            (m.phase(), m.rev()),
            (P::AwaitingRelease(ReleaseItem::ScriptResult), 1)
        );
        ok(&mut m, E::PreviewShown { rev: 1 })?;
        m.set_approvable(true);
        rejects(&mut m, E::Approve { rev: 1 }, Rejection::Illegal)?;
        ok(
            &mut m,
            E::Release {
                rev: 1,
                redacted: true,
            },
        )?;
        assert_eq!(m.phase(), P::Done(Terminal::ReleasedRedacted));

        // Error details go through the release flow too.
        let mut m = run(Kind::Script, &script_to(ReleaseItem::ScriptErrorDetails))?;
        ok(&mut m, E::Deny { rev: 1 })?;
        assert_eq!(m.phase(), P::Done(Terminal::Denied));

        // Only a direct SCRIPT_FAILED is returned without release; compile errors too.
        let running = [
            V(E::ValidationPassed),
            V(E::CompileStarted),
            V(E::CompileOk),
            V(E::SlotAcquired),
        ];
        for item in ITEMS {
            let mut m = run(Kind::Script, &running)?;
            ok(&mut m, E::RunEnded { direct: true, item })?;
            assert_eq!(m.phase(), P::Done(Terminal::Failed));
        }
        let mut m = run(
            Kind::Script,
            &[V(E::ValidationPassed), V(E::CompileStarted)],
        )?;
        ok(&mut m, E::CompileFailed)?;
        assert_eq!(agent_status(&m), Status::Failed);

        // Client cancel kills a running script.
        let mut m = run(Kind::Script, &running)?;
        ok(&mut m, E::Cancel(CancelReason::ByClient))?;
        assert_eq!(
            m.phase(),
            P::Done(Terminal::Cancelled(CancelReason::ByClient))
        );

        // Instance events invalidate a script candidate (new revision).
        let mut m = run(Kind::Script, &open(script_to(ReleaseItem::ScriptResult)))?;
        ok(&mut m, E::Instance(InstanceEvt::CredentialChanged))?;
        assert_eq!((m.rev(), m.opened()), (2, false));
        rejects(
            &mut m,
            E::Release {
                rev: 1,
                redacted: false,
            },
            Rejection::StaleRev { current: 2 },
        )?;

        // Dry run: never in the release flow.
        for (ok_, t) in [(true, Terminal::Succeeded), (false, Terminal::Failed)] {
            let mut m = run(Kind::DryRun, &[V(E::ValidationPassed), V(E::DryRunStarted)])?;
            rejects(&mut m, E::Expire, Rejection::Illegal)?;
            ok(&mut m, E::DryRunEnded { ok: ok_ })?;
            assert_eq!(m.phase(), P::Done(t));
            assert_eq!(m.rev(), 0);
        }
        Ok(())
    }

    #[test]
    fn decision_rules() -> TestResult {
        // Approve on an unopened revision → NotOpened (even if approvable).
        let mut m = run(Kind::Write, &with(write_to(Hold::Preview), &[A(true)]))?;
        rejects(&mut m, E::Approve { rev: 1 }, Rejection::NotOpened)?;
        // Opened but not approvable (Rust-computed, inv. 6).
        ok(&mut m, E::PreviewShown { rev: 1 })?;
        m.set_approvable(false);
        rejects(&mut m, E::Approve { rev: 1 }, Rejection::NotApprovable)?;
        // Stale revisions, both directions.
        m.set_approvable(true);
        rejects(
            &mut m,
            E::Approve { rev: 0 },
            Rejection::StaleRev { current: 1 },
        )?;
        rejects(
            &mut m,
            E::Approve { rev: 2 },
            Rejection::StaleRev { current: 1 },
        )?;
        ok(&mut m, E::Approve { rev: 1 })?;
        // A second approval is not a transition.
        rejects(&mut m, E::Approve { rev: 1 }, Rejection::Illegal)?;
        // Approve on the conflict hold.
        let mut m = run(Kind::Write, &open(write_to(Hold::Conflict)))?;
        rejects(&mut m, E::Approve { rev: 1 }, Rejection::NotApprovable)?;

        // Precedence: StaleRev before NotOpened before NotApprovable before the outcome rule.
        let mut m = run(Kind::Write, &write_to(Hold::Conflict))?;
        rejects(
            &mut m,
            E::Approve { rev: 0 },
            Rejection::StaleRev { current: 1 },
        )?;
        rejects(&mut m, E::Approve { rev: 1 }, Rejection::NotOpened)?;
        let mut m = run(Kind::Read, &read_to(ReleaseItem::Outcome))?;
        let redacted = E::Release {
            rev: 1,
            redacted: true,
        };
        rejects(
            &mut m,
            E::Release {
                rev: 2,
                redacted: true,
            },
            Rejection::StaleRev { current: 1 },
        )?;
        rejects(&mut m, redacted, Rejection::NotOpened)?;
        ok(&mut m, E::PreviewShown { rev: 1 })?;
        rejects(&mut m, redacted, Rejection::NotApprovable)?;
        m.set_approvable(true);
        rejects(&mut m, redacted, Rejection::Illegal)?;

        // Opening is per revision: an old PreviewShown cannot open the new one.
        let mut m = run(Kind::Read, &read_to(ReleaseItem::Result))?;
        rejects(
            &mut m,
            E::PreviewShown { rev: 0 },
            Rejection::StaleRev { current: 1 },
        )?;
        ok(&mut m, E::PreviewShown { rev: 1 })?;
        m.set_approvable(true);
        let a = ok(&mut m, E::CandidateChanged)?;
        assert_eq!(
            a,
            Applied {
                rev_bumped: true,
                became_terminal: false
            }
        );
        assert_eq!((m.rev(), m.opened(), m.approvable()), (2, false, false));
        rejects(
            &mut m,
            E::PreviewShown { rev: 1 },
            Rejection::StaleRev { current: 2 },
        )?;
        m.set_approvable(true);
        rejects(
            &mut m,
            E::Release {
                rev: 2,
                redacted: false,
            },
            Rejection::NotOpened,
        )?;
        ok(&mut m, E::PreviewShown { rev: 2 })?;
        ok(
            &mut m,
            E::Release {
                rev: 2,
                redacted: false,
            },
        )?;

        // Every rev-carrying decision with a wrong revision, in every decidable state.
        for Target {
            kind, phase, steps, ..
        } in targets()
        {
            if !matches!(phase, P::AwaitingRelease(_) | P::AwaitingApproval(_)) {
                continue;
            }
            let mut m = run(kind, &steps)?;
            let cur = m.rev();
            for rev in [cur - 1, cur + 1] {
                for e in [
                    E::PreviewShown { rev },
                    E::Release {
                        rev,
                        redacted: false,
                    },
                    E::Release {
                        rev,
                        redacted: true,
                    },
                    E::Approve { rev },
                    E::Deny { rev },
                    E::Edit {
                        rev,
                        target_or_baseline_changed: false,
                        rerun_enrichment: false,
                    },
                    E::Edit {
                        rev,
                        target_or_baseline_changed: true,
                        rerun_enrichment: true,
                    },
                ] {
                    let want = match (phase, e) {
                        (P::AwaitingRelease(_), E::Approve { .. } | E::Edit { .. })
                        | (P::AwaitingApproval(_), E::Release { .. }) => Rejection::Illegal,
                        _ => Rejection::StaleRev { current: cur },
                    };
                    rejects(&mut m, e, want)?;
                }
            }
        }
        Ok(())
    }

    #[test]
    fn cancel_rules() -> TestResult {
        for Target {
            kind,
            phase,
            steps,
            emitted,
            ..
        } in targets()
        {
            for r in REASONS {
                let mut m = run(kind, &steps)?;
                let before = agent_status(&m);
                match phase {
                    P::Done(_) | P::Executing => {
                        rejects(&mut m, E::Cancel(r), Rejection::NotCancellable)?
                    }
                    P::StaleCheck if r == CancelReason::ByClient => {
                        rejects(&mut m, E::Cancel(r), Rejection::NotCancellable)?;
                        assert_eq!(m.phase(), P::StaleCheck);
                    }
                    // After `executing` was emitted the client cancel answers `executing`, like a
                    // write still on the wire (§4.4, §4.5); the shutdown path still cancels.
                    _ if emitted && r == CancelReason::ByClient => {
                        rejects(&mut m, E::Cancel(r), Rejection::NotCancellable)?;
                        assert_eq!(before, Status::Executing);
                        assert_eq!(agent_status(&m), Status::Executing, "{phase:?}");
                    }
                    _ => {
                        let a = ok(&mut m, E::Cancel(r))?;
                        assert!(a.became_terminal);
                        assert_eq!(m.phase(), P::Done(Terminal::Cancelled(r)));
                        assert_eq!(agent_status(&m), Status::Cancelled);
                    }
                }
            }
            let mut m = run(kind, &steps)?;
            match phase {
                P::Done(_) | P::StaleCheck | P::Executing | P::Running | P::DryRunning => {
                    rejects(&mut m, E::Expire, Rejection::Illegal)?
                }
                _ => {
                    ok(&mut m, E::Expire)?;
                    assert_eq!(agent_status(&m), Status::Expired);
                }
            }
        }
        // A pre-execution stale return is invisible (still `pending`), so the agent may cancel it.
        let mut m = run(Kind::Write, &to_stale_check())?;
        ok(&mut m, E::Stale(StaleReason::Changed))?;
        ok(&mut m, E::Cancel(CancelReason::ByClient))?;
        assert_eq!(agent_status(&m), Status::Cancelled);
        // After a version conflict the queued write stays `executing` for every client cancel,
        // and the user's deny or the expiry still end it (plan decision, spec silent).
        let mut m = run(Kind::Write, &to_executing())?;
        ok(&mut m, E::VersionConflict)?;
        rejects(
            &mut m,
            E::Cancel(CancelReason::ByClient),
            Rejection::NotCancellable,
        )?;
        assert_eq!(agent_status(&m), Status::Executing);
        let mut n = m.clone();
        ok(&mut n, E::Expire)?;
        assert_eq!(agent_status(&n), Status::Expired);
        ok(&mut m, E::Cancel(CancelReason::OsShutdown))?;
        assert_eq!(agent_status(&m), Status::Cancelled);
        Ok(())
    }

    #[test]
    fn crash_rules() -> TestResult {
        // Approved and not returned → outcome_unknown, even after non-terminal trailing events.
        let mut m = run(Kind::Write, &to_stale_check())?;
        rejects(&mut m, E::PreviewShown { rev: 1 }, Rejection::Illegal)?;
        ok(&mut m, E::Crash)?;
        assert_eq!(m.phase(), P::Done(Terminal::OutcomeUnknown));
        assert_eq!(agent_status(&m), Status::OutcomeUnknown);
        let mut m = run(Kind::Write, &to_executing())?;
        ok(&mut m, E::Crash)?;
        assert_eq!(m.phase(), P::Done(Terminal::OutcomeUnknown));

        // Returned to the queue → abandoned.
        for back in [
            E::Stale(StaleReason::Changed),
            E::Stale(StaleReason::IdentityMismatch),
            E::Instance(InstanceEvt::CredentialChanged),
        ] {
            let mut m = run(Kind::Write, &to_stale_check())?;
            ok(&mut m, back)?;
            ok(&mut m, E::PreviewShown { rev: 2 })?;
            ok(&mut m, E::Crash)?;
            assert_eq!(m.phase(), P::Done(Terminal::Abandoned), "after {back:?}");
        }
        for back in [E::VersionConflict, E::Stale(StaleReason::RecheckFailed)] {
            let mut m = run(Kind::Write, &to_executing())?;
            ok(&mut m, back)?;
            ok(&mut m, E::Crash)?;
            assert_eq!(m.phase(), P::Done(Terminal::Abandoned), "after {back:?}");
            assert_eq!(agent_status(&m), Status::Abandoned);
        }
        // Re-approved after a stale return → outcome_unknown again.
        let mut m = run(Kind::Write, &to_stale_check())?;
        ok(&mut m, E::Stale(StaleReason::Changed))?;
        ok(&mut m, E::PreviewShown { rev: 2 })?;
        m.set_approvable(true);
        ok(&mut m, E::Approve { rev: 2 })?;
        ok(&mut m, E::Crash)?;
        assert_eq!(m.phase(), P::Done(Terminal::OutcomeUnknown));

        // Never approved → abandoned, in every pending phase of every kind.
        for Target {
            kind, phase, steps, ..
        } in targets()
        {
            let mut m = run(kind, &steps)?;
            match phase {
                P::Done(_) => rejects(&mut m, E::Crash, Rejection::Illegal)?,
                P::StaleCheck | P::Executing => {}
                _ => {
                    ok(&mut m, E::Crash)?;
                    assert_eq!(
                        m.phase(),
                        P::Done(Terminal::Abandoned),
                        "{kind:?} {phase:?}"
                    );
                }
            }
        }

        // Audit failure: fail closed, except a write already sent (plan decision).
        let mut m = run(Kind::Write, &to_executing())?;
        ok(&mut m, E::AuditFailure)?;
        assert_eq!(m.phase(), P::Done(Terminal::OutcomeUnknown));
        let mut m = run(Kind::Write, &to_stale_check())?;
        ok(&mut m, E::AuditFailure)?;
        assert_eq!(m.phase(), P::Done(Terminal::Failed));
        let mut m = run(Kind::Read, &open(read_to(ReleaseItem::Result)))?;
        ok(&mut m, E::AuditFailure)?;
        assert_eq!(agent_status(&m), Status::Failed);
        Ok(())
    }

    #[test]
    fn u01_stale_loops_bump_rev() -> TestResult {
        let mut m = run(Kind::Write, &open(write_to(Hold::Preview)))?;
        let start = m.rev();
        for i in 0..50u64 {
            ok(&mut m, E::Approve { rev: start + i })?;
            ok(&mut m, E::Stale(StaleReason::Changed))?;
            let rev = start + i + 1;
            assert_eq!(m.rev(), rev);
            // The engine recomputes approvability for the new revision; it still needs opening.
            m.set_approvable(true);
            rejects(&mut m, E::Approve { rev }, Rejection::NotOpened)?;
            ok(&mut m, E::PreviewShown { rev })?;
            assert_eq!(agent_status(&m), Status::Pending);
        }
        assert_eq!(m.rev(), start + 50);
        Ok(())
    }

    #[test]
    fn u01_rev_race_rejects_old_rev() -> TestResult {
        let mut m = run(Kind::Read, &read_to(ReleaseItem::Result))?;
        ok(&mut m, E::PreviewShown { rev: 1 })?;
        m.set_approvable(true);
        ok(&mut m, E::CandidateChanged)?;
        m.set_approvable(true);
        rejects(
            &mut m,
            E::Release {
                rev: 1,
                redacted: false,
            },
            Rejection::StaleRev { current: 2 },
        )?;
        Ok(())
    }

    // ---- U-01 property test: random event sequences against a reference checker ----

    #[derive(Debug, Clone, Copy)]
    enum RevOff {
        Cur,
        Prev,
        Next,
    }

    /// An event whose `rev` (if any) is resolved against the model at replay time.
    #[derive(Debug, Clone, Copy)]
    enum T {
        Fixed(Event),
        /// The natural next event of the current phase (keeps sequences from dying early).
        Advance(u8),
        Shown(RevOff),
        Release(RevOff, bool),
        Approve(RevOff),
        Edit(RevOff, bool, bool),
        Deny(RevOff),
    }

    fn resolve(t: T, m: &Model) -> Event {
        let r = |o: RevOff| match o {
            RevOff::Cur => m.rev(),
            RevOff::Prev => m.rev().wrapping_sub(1),
            RevOff::Next => m.rev() + 1,
        };
        match t {
            T::Fixed(e) => e,
            T::Shown(o) => E::PreviewShown { rev: r(o) },
            T::Release(o, redacted) => E::Release {
                rev: r(o),
                redacted,
            },
            T::Approve(o) => E::Approve { rev: r(o) },
            T::Edit(o, a, b) => E::Edit {
                rev: r(o),
                target_or_baseline_changed: a,
                rerun_enrichment: b,
            },
            T::Deny(o) => E::Deny { rev: r(o) },
            T::Advance(c) => {
                let c = usize::from(c);
                match m.phase() {
                    P::Received => E::ValidationPassed,
                    P::Validated => match m.kind {
                        Kind::Read => E::FetchStarted,
                        Kind::Write => E::EnrichStarted,
                        Kind::Script => E::CompileStarted,
                        Kind::DryRun => E::DryRunStarted,
                    },
                    P::Fetching => E::Fetched(READ_ITEMS[c % 3]),
                    P::Enriching if c % 2 == 0 => E::Enriched(Hold::Preview),
                    P::Enriching => E::Enriched(HOLDS[c % 6]),
                    P::Compiling => E::CompileOk,
                    P::SlotWait => E::SlotAcquired,
                    P::Running => E::RunEnded {
                        direct: false,
                        item: SCRIPT_ITEMS[c % 2],
                    },
                    P::DryRunning => E::DryRunEnded { ok: c % 2 == 0 },
                    P::AwaitingRelease(_) | P::AwaitingApproval(_) => {
                        E::PreviewShown { rev: m.rev() }
                    }
                    P::StaleCheck if c % 4 != 0 => E::StalePassed,
                    P::StaleCheck => E::Stale(STALE[c % 3]),
                    P::Executing => match c % 5 {
                        0 => E::VersionConflict,
                        1 => E::Stale(StaleReason::RecheckFailed),
                        _ => E::Executed(OUTCOMES[c % 3]),
                    },
                    P::Done(_) => E::Crash,
                }
            }
        }
    }

    fn ends_requests(e: Event) -> bool {
        matches!(
            e,
            E::Crash | E::Cancel(_) | E::Expire | E::AuditFailure | E::ValidationFailed
        )
    }

    fn rev_off() -> impl Strategy<Value = RevOff> {
        prop_oneof![4 => Just(RevOff::Cur), 1 => Just(RevOff::Prev), 1 => Just(RevOff::Next)]
    }

    fn template() -> impl Strategy<Value = T> {
        let fixed: Vec<Event> = all_events(0)
            .into_iter()
            .filter(|e| {
                !matches!(
                    e,
                    E::PreviewShown { .. }
                        | E::Release { .. }
                        | E::Approve { .. }
                        | E::Edit { .. }
                        | E::Deny { .. }
                )
            })
            .collect();
        let (ending, other): (Vec<Event>, Vec<Event>) =
            fixed.into_iter().partition(|e| ends_requests(*e));
        prop_oneof![
            10 => any::<u8>().prop_map(T::Advance),
            5 => proptest::sample::select(other).prop_map(T::Fixed),
            1 => proptest::sample::select(ending).prop_map(T::Fixed),
            2 => rev_off().prop_map(T::Shown),
            2 => (rev_off(), any::<bool>()).prop_map(|(o, x)| T::Release(o, x)),
            3 => rev_off().prop_map(T::Approve),
            1 => (rev_off(), any::<bool>(), any::<bool>()).prop_map(|(o, a, b)| T::Edit(o, a, b)),
            1 => rev_off().prop_map(T::Deny),
        ]
    }

    fn toggle() -> impl Strategy<Value = Option<bool>> {
        prop_oneof![3 => Just(None), 2 => Just(Some(true)), 1 => Just(Some(false))]
    }

    fn sequences() -> impl Strategy<Value = (Kind, Vec<(Option<bool>, T)>)> {
        (
            proptest::sample::select(KINDS.to_vec()),
            proptest::collection::vec((toggle(), template()), 1..=60),
        )
    }

    /// What the checker remembers from the accepted events so far.
    struct Shadow {
        /// Revision of the last accepted `PreviewShown`.
        opened_at: Option<u64>,
        /// An accepted `StalePassed` exists.
        stale_passed: bool,
        /// An accepted `Approve` exists with no later return to the queue or terminal decision.
        approved_live: bool,
    }

    fn may_bump(e: Event) -> bool {
        matches!(
            e,
            E::Fetched(_)
                | E::Enriched(_)
                | E::RunEnded { direct: false, .. }
                | E::CandidateChanged
                | E::Edit {
                    rerun_enrichment: false,
                    ..
                }
                | E::Stale(_)
                | E::VersionConflict
                | E::Instance(_)
        )
    }

    /// The U-01 invariants for one step: (1)–(7) from plan Task 12 Step 1, (8)–(9) from its review.
    fn check(
        b: &Snap,
        a: &Snap,
        e: Event,
        res: Result<Applied, Rejection>,
        sh: &mut Shadow,
    ) -> Result<(), TestCaseError> {
        // (1) once Done, the phase never changes.
        if !is_pending(b.phase) {
            prop_assert!(res.is_err(), "{:?} accepted in {:?}", e, b.phase);
            prop_assert_eq!(a.phase, b.phase);
        }
        // (9) once `executing` was emitted, a client cancel is never accepted (§4.4, §4.5).
        if sh.stale_passed && e == E::Cancel(CancelReason::ByClient) {
            prop_assert!(res.is_err(), "client cancel accepted in {:?}", b.phase);
        }
        let applied = match res {
            Err(_) => {
                prop_assert_eq!(a, b, "rejected {:?} changed the model", e);
                return Ok(());
            }
            Ok(x) => x,
        };
        prop_assert_eq!(applied.became_terminal, !is_pending(a.phase));
        // (2) rev never decreases; it moves by one, only on the listed events.
        prop_assert!(
            a.rev == b.rev || a.rev == b.rev + 1,
            "{:?}: {} -> {}",
            e,
            b.rev,
            a.rev
        );
        let bumped = a.rev != b.rev;
        prop_assert_eq!(applied.rev_bumped, bumped);
        if bumped {
            prop_assert!(may_bump(e), "{:?} bumped the revision", e);
            // (3) a new revision is unopened (and not yet approvable).
            prop_assert!(
                !a.opened && !a.approvable,
                "{:?} left the new rev opened",
                e
            );
        }
        // (4) Release/Approve only on the opened current revision, approvable at that moment.
        if matches!(e, E::Release { .. } | E::Approve { .. }) {
            prop_assert_eq!(sh.opened_at, Some(b.rev), "{:?} on an unopened revision", e);
            prop_assert!(b.approvable, "{:?} accepted while not approvable", e);
        }
        if let E::PreviewShown { rev } = e {
            prop_assert_eq!(rev, b.rev);
            sh.opened_at = Some(rev);
        }
        // (6) Executing only from StaleCheck; StaleCheck only through an accepted Approve.
        if a.phase == P::Executing && b.phase != P::Executing {
            prop_assert!(b.phase == P::StaleCheck && e == E::StalePassed, "{:?}", e);
        }
        if a.phase == P::StaleCheck && b.phase != P::StaleCheck {
            prop_assert!(matches!(e, E::Approve { .. }), "{:?} entered StaleCheck", e);
            prop_assert_eq!(b.phase, P::AwaitingApproval(Hold::Preview));
        }
        // (8) A hold is an enrichment verdict: set only by `Enriched`, a stale return or a version
        // conflict; instance events, edits and candidate changes in the queue keep it (inv. 6).
        if let (P::AwaitingApproval(h0), P::AwaitingApproval(h1)) = (b.phase, a.phase) {
            prop_assert_eq!(h0, h1, "{:?} changed the hold", e);
        }
        if matches!(a.phase, P::AwaitingApproval(_)) && !matches!(b.phase, P::AwaitingApproval(_)) {
            prop_assert!(
                matches!(e, E::Enriched(_) | E::Stale(_) | E::VersionConflict)
                    || (b.phase == P::StaleCheck && matches!(e, E::Instance(_))),
                "{:?} entered {:?}",
                e,
                a.phase
            );
        }
        // (7) Crash → outcome_unknown iff approved and not returned.
        match e {
            E::Approve { .. } => sh.approved_live = true,
            E::Stale(_) | E::VersionConflict | E::Deny { .. } | E::Executed(_) => {
                sh.approved_live = false
            }
            E::Instance(InstanceEvt::CredentialChanged | InstanceEvt::InstanceChanged)
                if b.phase == P::StaleCheck =>
            {
                sh.approved_live = false
            }
            E::Crash => {
                let want = if sh.approved_live {
                    Terminal::OutcomeUnknown
                } else {
                    Terminal::Abandoned
                };
                prop_assert_eq!(a.phase, P::Done(want));
            }
            _ => {}
        }
        if is_pending(a.phase) {
            prop_assert_eq!(a.approved_unreturned, sh.approved_live);
        }
        // (5) `pending` before the first accepted StalePassed, never `pending` after it.
        if e == E::StalePassed {
            sh.stale_passed = true;
        }
        if sh.stale_passed {
            prop_assert_ne!(a.status, Status::Pending);
        } else if is_pending(a.phase) {
            prop_assert_eq!(a.status, Status::Pending);
        }
        Ok(())
    }

    type Visit<'a> = &'a mut dyn FnMut(&Snap, Event, Result<Applied, Rejection>, &Snap);

    fn replay(
        kind: Kind,
        seq: &[(Option<bool>, T)],
        visit: Visit<'_>,
    ) -> Result<(), TestCaseError> {
        let mut m = Model::new(kind);
        let mut sh = Shadow {
            opened_at: None,
            stale_passed: false,
            approved_live: false,
        };
        for &(toggle, t) in seq {
            if let Some(v) = toggle {
                m.set_approvable(v);
            }
            let e = resolve(t, &m);
            let b = snap(&m);
            let res = step(&mut m, e);
            let a = snap(&m);
            visit(&b, e, res, &a);
            check(&b, &a, e, res, &mut sh)?;
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        #[test]
        fn u01_model_invariants_random_sequences((kind, seq) in sequences()) {
            replay(kind, &seq, &mut |_, _, _, _| {})?;
        }
    }

    /// The property test is only as good as its generator: with the same case count, the
    /// sequences must visit every phase and get every event variant accepted somewhere.
    #[test]
    fn u01_generator_reaches_every_phase_and_event() -> TestResult {
        let mut runner = TestRunner::deterministic();
        let strategy = sequences();
        let mut seen: Vec<Phase> = Vec::new();
        let mut accepted = [false; EVENT_VARIANTS];
        let mut crash_unknown = false;
        let mut hold_kept = false;
        let mut queued_executing_cancel_refused = false;
        for _ in 0..4096 {
            let (kind, seq) = strategy
                .new_tree(&mut runner)
                .map_err(|r| format!("{r:?}"))?
                .current();
            replay(kind, &seq, &mut |b, e, res, a| {
                for p in [b.phase, a.phase] {
                    if !seen.contains(&p) {
                        seen.push(p);
                    }
                }
                if res.is_ok() {
                    accepted[event_index(e)] = true;
                    crash_unknown |= e == E::Crash && a.phase == P::Done(Terminal::OutcomeUnknown);
                    hold_kept |= matches!(e, E::Instance(_))
                        && b.phase != P::AwaitingApproval(Hold::Preview)
                        && matches!(b.phase, P::AwaitingApproval(_));
                } else {
                    queued_executing_cancel_refused |= e == E::Cancel(CancelReason::ByClient)
                        && b.executing_emitted
                        && matches!(b.phase, P::AwaitingApproval(_) | P::Enriching);
                }
            })
            .map_err(|e| format!("{e:?}"))?;
        }
        let missing: Vec<Phase> = all_phases()
            .into_iter()
            .filter(|p| !seen.contains(p))
            .collect();
        assert!(missing.is_empty(), "never visited: {missing:?}");
        assert!(accepted.iter().all(|&b| b), "never accepted: {accepted:?}");
        assert!(crash_unknown, "no crash after an approval");
        assert!(hold_kept, "no instance event on a non-preview hold");
        assert!(
            queued_executing_cancel_refused,
            "no client cancel of a queued write after `executing`"
        );
        Ok(())
    }
}
