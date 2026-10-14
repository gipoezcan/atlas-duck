//! Staged enrichment (Δ3 C.7, Task 12): the one driver of a write's enrichment GETs, for the
//! initial enrichment, an edit's re-run and a refresh (§5.4 steps 2, 4, 5).
//!
//! The op's [`EnrichRule::plan`] is called with the answers so far until it says `Judge`; each
//! `Fetch` is one round of GETs. Every GET runs under the request's cover (minted once, only for
//! an id whose `REQUEST_RECEIVED` committed, §5.1 inv. 1) and one `FetchControl`, and is recorded
//! as `PREVIEW_FETCH {purpose}`: a GET's record is committed before the next GET leaves, in this
//! round or the next; the last GET's record is committed with the event it decides (`Enriched`, or
//! the failure). Each answer is classified exactly as before (`write::enrich_effect`, or
//! `write::recheck` in a refresh); the first one that is not usable 2xx JSON ends the enrichment.
//! A plan that asks for a round past [`MAX_ENRICH_STAGES`] fails closed: an "enrichment failed"
//! hold with no hint (a refresh: `recheck_failed {internal}`), and that round's GETs never leave.

use std::sync::Arc;

use atlas_duck_atlassian::FetchControl;
use atlas_duck_audit::NewEvent;
use serde_json::Value;

use super::write::{
    Effect, Failure, FailureHint, Gated, GetMode, Recheck, call_path, enrich_effect, gate_get,
    get_record, internal_effect, park, recheck, recheck_failed,
};
use super::{Engine, InFlight, InstanceHttp, RequestEntry};
use crate::ops::{
    EnrichCtx, EnrichFailure, EnrichPurpose, EnrichRule, EnrichStep, EnrichVerdict,
    MAX_ENRICH_STAGES,
};
use crate::payloads::PreviewFetchPurpose;

/// Plan wording: the card of an enrichment whose plan asked for more rounds than
/// [`MAX_ENRICH_STAGES`] (a bug, not data: nothing the agent may be told).
pub const TEXT_TOO_MANY_ROUNDS: &str =
    "the write's preparation needed more enrichment requests than allowed";

/// How one enrichment ended.
pub(super) enum EnrichOutcome {
    /// Every GET answered usable JSON and the plan said `Judge`: the judge's verdict, and the last
    /// GET's record (parked, committed with `Enriched`; `None` when nothing was fetched).
    Judged {
        verdict: Box<EnrichVerdict>,
        last: Option<NewEvent>,
    },
    /// A GET failed (or the enrichment could not go on): the failing or last GET's record and
    /// what the failure means (`write::enrich_failed`).
    Failed {
        record: Option<NewEvent>,
        fail: Result<Effect, Recheck>,
    },
    /// The request left the pending phases meanwhile (an append was refused): nothing more.
    Stopped,
}

/// One enrichment of `entry` with `rule` over `params`. `refreshing`: a §5.4 step 5 refresh,
/// whose GETs are all recorded as `purpose: refresh` (the purpose override) and classified with
/// `write::recheck`; otherwise each GET keeps its plan purpose (`resolve` / `enrich`, PD-24).
pub(super) async fn run(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
    http: &InstanceHttp,
    rule: &EnrichRule,
    params: &Value,
    refreshing: bool,
) -> EnrichOutcome {
    let mode = if refreshing {
        GetMode::Recheck
    } else {
        GetMode::Enrich
    };
    let ctx = EnrichCtx {
        spec: entry.spec,
        params,
    };
    let mut answers: Vec<Value> = Vec::new();
    // The last GET's record: parked, committed before the next GET leaves or with the verdict.
    let mut held: Option<NewEvent> = None;
    let mut cover = None;
    let mut rounds = 0usize;
    loop {
        let calls = match (rule.plan)(&ctx, &answers) {
            EnrichStep::Judge => break,
            EnrichStep::Fetch(calls) => calls,
        };
        if rounds == MAX_ENRICH_STAGES {
            return EnrichOutcome::Failed {
                record: held,
                fail: too_many_rounds(refreshing),
            };
        }
        rounds += 1;
        for (purpose, call) in calls {
            if let Some(record) = held.take()
                && !engine.append_pending(entry, vec![record], None).await
            {
                return EnrichOutcome::Stopped;
            }
            if cover.is_none() {
                let ctl = FetchControl::new();
                entry.set_fetch_control(Some(ctl.clone()));
                // §5.1 inv. 1: only an id whose `REQUEST_RECEIVED` committed gets a cover.
                cover = engine
                    .covers()
                    .for_request(&entry.head.request_id)
                    .ok()
                    .map(|c| (ctl, c));
            }
            let Some((ctl, cov)) = cover.as_ref() else {
                return EnrichOutcome::Failed {
                    record: None,
                    fail: internal_effect(refreshing),
                };
            };
            let purpose = match (refreshing, purpose) {
                (true, _) => PreviewFetchPurpose::Refresh,
                (false, EnrichPurpose::Enrich) => PreviewFetchPurpose::Enrich,
                (false, EnrichPurpose::Resolve) => PreviewFetchPurpose::Resolve,
            };
            let mut attempt = 0u8;
            let (record, got) = loop {
                let seen = engine.identity_epoch(&entry.instance_id);
                // The control served the GETs before: `sent` is this GET's own flag (T24 M-4).
                ctl.begin_call();
                // A cancel while this GET is in flight records it (`cancelled_in_flight`,
                // Task 24), once its request was handed to the connection (`sent`).
                entry.set_in_flight(Some(InFlight {
                    purpose,
                    path: call_path(http.client.base(), &call),
                }));
                let outcome = http.client.get_ctl(cov, &call, ctl).await;
                entry.set_in_flight(None);
                let record = get_record(&entry.ctx, purpose, http.client.base(), &call, &outcome);
                park(engine, entry, &record).await;
                let gated = gate_get(
                    engine,
                    &entry.instance_id,
                    seen,
                    outcome,
                    mode,
                    attempt == 0,
                )
                .await;
                match gated {
                    // A rename: the first answer is recorded, the GET runs once more (§7.1).
                    Gated::Rerun => {
                        attempt += 1;
                        if !engine.append_pending(entry, vec![record], None).await {
                            return EnrichOutcome::Stopped;
                        }
                    }
                    Gated::Proceed(outcome) => {
                        let got = if refreshing {
                            recheck(outcome).map_err(Err)
                        } else {
                            enrich_effect(outcome, &http.proxy).map_err(Ok)
                        };
                        break (record, got);
                    }
                    Gated::Held(effect) => break (record, Err(Ok(effect))),
                    Gated::Stale(fail) => break (record, Err(Err(fail))),
                }
            };
            match got {
                Ok(v) => answers.push(v),
                Err(fail) => {
                    return EnrichOutcome::Failed {
                        record: Some(record),
                        fail,
                    };
                }
            }
            held = Some(record);
        }
    }
    EnrichOutcome::Judged {
        verdict: Box::new((rule.judge)(&ctx, &answers)),
        last: held,
    }
}

/// Δ3: a fifth round is refused, fail closed.
fn too_many_rounds(refreshing: bool) -> Result<Effect, Recheck> {
    if refreshing {
        return Err(recheck_failed("internal"));
    }
    Ok(Effect::Held(Failure {
        card: EnrichFailure {
            status: None,
            text: TEXT_TOO_MANY_ROUNDS.to_owned(),
            outcome: None,
        },
        hint: FailureHint::None,
    }))
}
