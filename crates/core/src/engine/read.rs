//! The read flow (§5.2 steps 2–6, Task 21): from `Validated` through `Fetching` to a release item
//! (`AwaitingRelease(result | upstream-error | outcome)`) or a data-free direct failure.
//!
//! 1. A fetch slot (§5.2 memory budget: at most 8 reads in `Fetching`), cancel-aware; the agent
//!    sees `pending` either way. `FetchStarted` has no record.
//! 2. The op's executor builds the read plan; it runs under the request's cover (§5.1 inv. 1)
//!    with a `FetchControl` kept in the entry (Task 24 cancels through it).
//! 3. [`classify_read`] is the one place that maps a `FetchOutcome`/`PagedOutcome` to what
//!    happens next (§5.2 step 6, §7.2, §11.2).
//! 4. `READ_FETCHED` is the record of `Fetched(item)` (or, with `READ_FAILED`, of
//!    `FetchFailedDirect`); it carries every byte received.
//! 5. The candidate is built from that record's payload by [`normalize`], the same function a
//!    rebuild uses (`cache`'s one construction path), then hashed and cached in the same critical
//!    section that applies `Fetched` (rev 1).
//!
//! The candidate is the **bare** body (`{result}` is added at delivery): paged results are the
//! first page's object with the items of every page under `items_key` (server totals as sent);
//! an upstream error is `{status, error_messages}`; an outcome item `{code, hint}`. Nothing of a
//! candidate reaches an envelope before a release (§4.5): the agent sees `pending` throughout.

use std::fmt;
use std::sync::Arc;

use atlas_duck_atlassian::{
    BodyFailure, ConnClass, FetchControl, FetchFailure, FetchOutcome, PageEnd, PagedOutcome,
    PostSendKind, UnavailableReason, UpstreamResponse,
};
use atlas_duck_audit::NewEvent;
use atlas_duck_ipc::envelope::ErrorCode;
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::{
    Level, OutcomeKind as CardKind, PreviewBody, PreviewHeader, cap_error_text,
};
use atlas_duck_registry::{OperationSpec, RELEASE_CAP_BYTES};
use serde_json::{Map, Value, json};
use tokio::sync::OwnedSemaphorePermit;

use super::cache::{Candidate, RebuildError, build_candidate, fetched_responses};
use super::envelope::{MSG_IDENTITY_HEADER, OpenStatus};
use super::{Engine, InstanceHttp, OnAuditFailure, RequestEntry};
use crate::gate::{AttentionKind, UiEvent};
use crate::identity::{self, Lost};
use crate::instances::InstanceState;
use crate::lifecycle::model::{Event, ReleaseItem};
use crate::ops::generic::{count_value, fallback_preview, invisible_warnings, query_display};
use crate::ops::{
    ExecCtx, ExecPlan, PreviewCtx, PreviewInput, PreviewModel, ReadPlan, ReadView, op_table,
};
use crate::payloads::{self, CapOrBudget, EventCtx, OutcomeKind, ReadFetched};
use crate::proxy::{PAC_HINT, ResolvedProxy};
use crate::redact::RedactionMeta;

/// §5.2 step 6: the fixed hint a released outcome item carries. Plan wording: the spec names the
/// hint ("narrow `fields`/`max`/`expand`") without fixing its text.
pub const OUTCOME_HINT: &str = "narrow fields, max or expand";
/// §11.2 (verbatim): a connection failure on an unknown certificate issuer.
pub const HINT_TLS_UNKNOWN_ISSUER: &str = "certificate not trusted — add a custom CA in Settings";
/// §11.2 template "server certificate problem (<class>) — contact the server administrator",
/// verbatim but for `<class>`, which is "invalid certificate" here: the client reports name
/// mismatch, expiry and unsupported certificates as one `ConnClass::TlsCertificate`.
pub const HINT_TLS_CERTIFICATE: &str =
    "server certificate problem (invalid certificate) — contact the server administrator";
/// §11.2 (verbatim; the spec's code span around `doctor` is kept as backticks): proxy
/// unreachable or 407.
pub const HINT_PROXY: &str = "proxy error — see `doctor`";
/// Plan wording: the other connection-level classes.
const MSG_DNS: &str = "the server name could not be resolved";
const MSG_CONNECT: &str = "the server could not be reached";
const MSG_CONNECT_TIMEOUT: &str = "the connection to the server timed out";
const MSG_TLS_HANDSHAKE: &str = "the TLS handshake with the server failed";
/// Plan wording: `upstream_unavailable` decided from status and headers (§7.2).
const MSG_REDIRECT: &str = "the server answered with a redirect";
const MSG_NON_JSON: &str = "the server answered without JSON (e.g. a login or maintenance page)";
const MSG_NON_JSON_401: &str = "the server answered 401 without JSON";
pub(crate) const MSG_IDENTITY: &str = "the server's answer was not attributed to the token's user";
pub(crate) const MSG_NEEDS_TOKEN: &str =
    "the instance needs a token: set it in the atlas-duck credential window";
const MSG_INTERNAL: &str = "the read could not be run";
const MSG_ABORTED: &str = "the read was aborted";

/// The facts `meta.page` needs (§7.5), kept from the fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageFacts {
    /// The agent's `start`.
    pub start: u64,
    pub total: Option<u64>,
    /// `None` only when the server reported the end of the results.
    pub next_start: Option<u64>,
    /// Items across the 2xx pages, before any drop.
    pub items_fetched: u64,
}

/// A read's release item: what its preview, its release and its `meta` need besides the
/// candidate bytes (UI and record only; nothing here reaches an envelope before a release).
#[derive(Clone)]
pub struct ReadState {
    pub item: ReleaseItem,
    /// Outcome items: which cap, budget or failure the card names (§6.3).
    pub outcome: Option<CardKind>,
    /// Bytes and responses received (outcome card, UI only).
    pub received: u64,
    pub pages: u64,
    pub page: Option<PageFacts>,
    pub server_total: Option<u64>,
    pub more_available: bool,
    /// `Validated::truncated_by_clamp`.
    pub clamped: bool,
    /// Results the normalization removed (§7.4: `confluence.search` results without a `content`
    /// object), counted in `meta.redactions.items_dropped`.
    pub normalized_dropped: u64,
    /// What the current revision's redaction ops did (`None` without ops).
    pub redaction_meta: Option<RedactionMeta>,
    /// "also appears in" of the current revision's masks (§6.3; UI only).
    pub also_appears_in: Vec<String>,
}

/// Counts and kinds only (§7.7): field names and paths can be Atlassian data.
impl fmt::Debug for ReadState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadState")
            .field("item", &self.item)
            .field("outcome", &self.outcome)
            .field("received", &self.received)
            .field("pages", &self.pages)
            .field("page", &self.page)
            .field("normalized_dropped", &self.normalized_dropped)
            .field("redacted", &self.redaction_meta.is_some())
            .finish_non_exhaustive()
    }
}

// ---- the flow ---------------------------------------------------------------------------------

/// Starts the read of a request that just entered the map in `Validated` (Task 19 step 9). A
/// read task that panics fails its request `internal` (gated like every record-bearing end),
/// instead of leaving it in `Fetching` with its admission place until expiry.
pub(crate) fn dispatch(engine: &Arc<Engine>, entry: &Arc<RequestEntry>) {
    let (engine, entry) = (engine.clone(), entry.clone());
    let read = tokio::spawn(run(engine.clone(), entry.clone()));
    tokio::spawn(async move {
        if read.await.is_err() {
            let d = Direct::internal(MSG_INTERNAL, Vec::new());
            direct(&engine, &entry, d).await;
        }
    });
}

async fn run(engine: Arc<Engine>, entry: Arc<RequestEntry>) {
    #[cfg(feature = "testing")]
    if let Some(pause) = engine.hooks().pause_before_fetch.clone() {
        pause.hold().await;
    }
    let Some(_permit) = fetch_slot(&engine, &entry).await else {
        return;
    };
    // Cancelled or expired while waiting for the slot: the model refuses, nothing is sent.
    if engine
        .step_unlogged(&entry, Event::FetchStarted, None, |_| {})
        .await
        .is_err()
    {
        return;
    }
    // PD-03 for an admitted request: an instance that went bad while this one waited for its
    // slot is not called (Task 26).
    let state = engine
        .instances()
        .by_id(&entry.instance_id)
        .map(|i| i.state);
    if let Some(d) = state.and_then(state_refusal) {
        settle(&engine, &entry, Classified::Direct(d)).await;
        return;
    }
    let classified = fetch_classified(&engine, &entry).await;
    settle(&engine, &entry, classified).await;
}

/// A direct failure for an instance that is `needs_token` or in an identity-header state (§7.2
/// *Header lost*): nothing is sent.
pub(crate) fn state_refusal(state: InstanceState) -> Option<Direct> {
    match state {
        InstanceState::NeedsToken => Some(Direct::needs_token(Vec::new())),
        InstanceState::IdentityHeaderMissing => {
            Some(Direct::header_lost(Lost::Missing, Vec::new()))
        }
        InstanceState::IdentityHeaderMismatch => {
            Some(Direct::header_lost(Lost::Mismatch, Vec::new()))
        }
        InstanceState::Ok | InstanceState::InsecureScheme | InstanceState::InstanceUnconfirmed => {
            None
        }
    }
}

/// The fetch and its classification, with the identity handling of Task 26 in between: a failed
/// identity check or a JSON 401 runs the token re-check (§7.1) and the table of
/// [`identity::effect`] decides what the read becomes. A rename re-fetches once under the same
/// request id; the first answer is recorded audit-only before the second fetch.
async fn fetch_classified(engine: &Arc<Engine>, entry: &Arc<RequestEntry>) -> Classified {
    let mut refetched = false;
    loop {
        let seen = engine.identity_epoch(&entry.instance_id);
        let (fetched, http) = match fetch(engine, entry).await {
            Ok(f) => f,
            Err(message) => return Classified::Direct(Direct::internal(message, Vec::new())),
        };
        let Some(trigger) = fetched_trigger(&fetched) else {
            return classify_read(fetched, &http.proxy);
        };
        // The re-fetch failed the check again: `upstream_unavailable`, retryable (§7.1).
        let effect = if refetched {
            identity::Effect::HeaderCheckFailed
        } else {
            let result = identity::recheck(engine, &entry.instance_id, seen).await;
            identity::effect(identity::Path::DirectRead, trigger, &result)
        };
        match effect {
            identity::Effect::Ordinary => {
                return classify_read(ordinary(fetched), &http.proxy);
            }
            identity::Effect::Refetch => {
                let (earlier, answer) = split_answer(fetched);
                let mut responses = earlier;
                responses.extend(answer);
                let first = payloads::read_fetched(
                    &entry.ctx,
                    &ReadFetched::Unavailable {
                        responses: &responses,
                        reason: "identity_check",
                    },
                    None,
                );
                if !engine.append_pending(entry, vec![first], None).await {
                    return Classified::Cancelled;
                }
                refetched = true;
            }
            other => return identity_classified(other, fetched),
        }
    }
}

/// The trigger of a read's fetch, if its answer failed the identity check or is a JSON 401.
fn fetched_trigger(f: &Fetched) -> Option<identity::Trigger> {
    match f {
        Fetched::Single(o) => identity::trigger(o),
        Fetched::Paged { outcome, .. } => match &outcome.failure {
            Some(failure) => identity::failure_trigger(failure),
            None if outcome.end == PageEnd::Failed
                && outcome.pages.last().is_some_and(|r| r.status == 401) =>
            {
                Some(identity::Trigger::Json401)
            }
            None => None,
        },
    }
}

/// The fetch as the ordinary answer it is once the re-check passed on a JSON 401.
fn ordinary(f: Fetched) -> Fetched {
    match f {
        Fetched::Single(o) => Fetched::Single(identity::as_response(o)),
        Fetched::Paged { mut outcome, start } => {
            if let Some(FetchFailure::IdentityCheckFailed { response, .. }) = outcome.failure.take()
            {
                outcome.pages.push(response);
                outcome.end = PageEnd::Failed;
            }
            Fetched::Paged { outcome, start }
        }
    }
}

/// The complete responses before the triggering answer, and that answer.
fn split_answer(f: Fetched) -> (Vec<UpstreamResponse>, Option<UpstreamResponse>) {
    match f {
        Fetched::Single(FetchOutcome::Failed(FetchFailure::IdentityCheckFailed {
            response,
            ..
        })) => (Vec::new(), Some(response)),
        Fetched::Single(FetchOutcome::Response(r)) => (Vec::new(), Some(r)),
        Fetched::Single(FetchOutcome::Failed(_)) => (Vec::new(), None),
        Fetched::Paged { mut outcome, .. } => match outcome.failure.take() {
            Some(FetchFailure::IdentityCheckFailed { response, .. }) => {
                (outcome.pages, Some(response))
            }
            _ => {
                let last = outcome.pages.pop();
                (outcome.pages, last)
            }
        },
    }
}

/// What the identity table makes of a read that is not re-fetched (§7.1): `needs_token`, the
/// identity-header states, or `upstream_unavailable` (retryable) for a passing or inconclusive
/// re-check. The answer is audit-only (RF-2a); after a first page the failure is an outcome item
/// like every direct class (review I-1).
fn identity_classified(effect: identity::Effect, fetched: Fetched) -> Classified {
    let (mut responses, answer) = split_answer(fetched);
    let later_page = !responses.is_empty();
    responses.extend(answer);
    let d = match effect {
        identity::Effect::NeedsToken => Direct::needs_token(responses),
        identity::Effect::HeaderLost(l) => Direct::header_lost(l, responses),
        _ => Direct {
            code: ErrorCode::UpstreamUnavailable,
            message: MSG_IDENTITY.to_owned(),
            cause: Some(("reason", "identity_check")),
            reason_detail: None,
            responses,
        },
    };
    gate_later(d, later_page)
}

/// A fetch slot (§5.2), or `None` once the request is terminal (cancel, expiry) meanwhile.
async fn fetch_slot(engine: &Engine, entry: &RequestEntry) -> Option<OwnedSemaphorePermit> {
    let mut rx = entry.subscribe();
    let slots = engine.fetch_slots().clone();
    let ended = async move {
        loop {
            if OpenStatus::of(*rx.borrow_and_update()).is_none() || rx.changed().await.is_err() {
                return;
            }
        }
    };
    tokio::select! {
        permit = slots.acquire_owned() => permit.ok(),
        () = ended => None,
    }
}

/// What the client returned for the plan.
pub(crate) enum Fetched {
    Single(FetchOutcome),
    Paged { outcome: PagedOutcome, start: u64 },
}

/// Runs the op's read plan under the request's cover. `Err` = nothing was sent.
async fn fetch(
    engine: &Arc<Engine>,
    entry: &Arc<RequestEntry>,
) -> Result<(Fetched, Arc<InstanceHttp>), &'static str> {
    let validated = entry.validated.as_ref().ok_or(MSG_INTERNAL)?;
    let op = op_table().get(entry.spec.id).ok_or(MSG_INTERNAL)?;
    let http = engine
        .client(&entry.instance_id)
        .await
        .map_err(|_| "the instance's connection settings (custom CA or proxy) cannot be used")?;
    let plan = (op.executor)(&ExecCtx {
        spec: entry.spec,
        params: &validated.params,
        base: http.client.base(),
        enrichment: None,
        effective_max: validated.effective_max,
    });
    let Ok(ExecPlan::Read(plan)) = plan else {
        return Err(MSG_INTERNAL);
    };
    // The control first, then the cover: a cancel that ran before this point has forgotten the
    // id (no cover is minted); one that runs after it finds the control (review M-5).
    let ctl = FetchControl::new();
    entry.set_fetch_control(Some(ctl.clone()));
    // §5.1 inv. 1: only an id whose `REQUEST_RECEIVED` committed gets a cover.
    let cover = engine
        .covers()
        .for_request(&entry.head.request_id)
        .map_err(|_| MSG_INTERNAL)?;
    let budget = engine.read_budget();
    let start = validated
        .params
        .get("start")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let client = &http.client;
    let fetched = match plan {
        ReadPlan::Get(call) => Fetched::Single(client.get_ctl(&cover, &call, &ctl).await),
        ReadPlan::Paged { call, max_items } => Fetched::Paged {
            outcome: client
                .read_paginated_ctl(&cover, &call, &budget, max_items, &ctl)
                .await,
            start,
        },
        ReadPlan::Search {
            call,
            items_key,
            max_items,
        } => Fetched::Paged {
            outcome: client
                .read_paginated_search_ctl(&cover, &call, &items_key, &budget, max_items, &ctl)
                .await,
            start,
        },
    };
    Ok((fetched, http))
}

// ---- classification -----------------------------------------------------------------------------

/// What a fetch becomes (§5.2 step 6).
pub(crate) enum Classified {
    Item(ItemRecord),
    Direct(Direct),
    /// Aborted through the control (Task 24 records the bytes and the terminal event).
    Cancelled,
}

/// A release item's `READ_FETCHED` content before it is recorded.
pub(crate) struct ItemRecord {
    item: ReleaseItem,
    /// Complete responses (pages, the upstream error, the response whose body failed).
    responses: Vec<UpstreamResponse>,
    outcome: Option<OutcomeFacts>,
    page: Option<PageFacts>,
    server_total: Option<u64>,
    more_available: bool,
}

struct OutcomeFacts {
    kind: OutcomeKind,
    cap: Option<CapOrBudget>,
    card: CardKind,
    /// Bytes of the response being read when it stopped.
    partial: Vec<u8>,
    /// The diagnosis of a later-page failure that is gated instead of direct (`class` or
    /// `reason`), kept in the record only.
    cause: Option<(&'static str, &'static str)>,
}

/// A data-free direct failure (§5.2 step 6 "directly returned without release").
pub(crate) struct Direct {
    code: ErrorCode,
    message: String,
    /// `("class", ..)` or `("reason", ..)` in the record.
    cause: Option<(&'static str, &'static str)>,
    /// `details.reason` in the envelope: only the §4.3 identity-header states (ruling 4
    /// carve-out); every other class or reason stays in the record.
    reason_detail: Option<&'static str>,
    /// Responses received before the failure was decided (audit-only, RF-2a).
    responses: Vec<UpstreamResponse>,
}

impl Direct {
    /// §7.1: a confirmed token failure (exit 9); the answer behind it is audit-only.
    fn needs_token(responses: Vec<UpstreamResponse>) -> Direct {
        Direct {
            code: ErrorCode::NeedsToken,
            message: MSG_NEEDS_TOKEN.to_owned(),
            cause: None,
            reason_detail: None,
            responses,
        }
    }

    /// §7.2 *Header lost*: `upstream_unavailable` with the reason and the admin hint
    /// (`retryable: false` follows from the reason, envelope).
    fn header_lost(lost: Lost, responses: Vec<UpstreamResponse>) -> Direct {
        Direct {
            code: ErrorCode::UpstreamUnavailable,
            message: MSG_IDENTITY_HEADER.to_owned(),
            cause: Some(("reason", lost.reason())),
            reason_detail: Some(lost.reason()),
            responses,
        }
    }

    fn internal(message: &str, responses: Vec<UpstreamResponse>) -> Direct {
        Direct {
            code: ErrorCode::Internal,
            message: message.to_owned(),
            cause: None,
            reason_detail: None,
            responses,
        }
    }
}

impl ItemRecord {
    fn size(&self) -> u64 {
        let partial = self.outcome.as_ref().map_or(0, |o| o.partial.len());
        self.responses
            .iter()
            .map(|r| r.body.len())
            .chain(std::iter::once(partial))
            .map(|n| u64::try_from(n).unwrap_or(u64::MAX))
            .fold(0u64, u64::saturating_add)
    }

    fn record(&self, ctx: &EventCtx) -> NewEvent {
        let fetched = match (&self.outcome, self.item) {
            (Some(o), _) => ReadFetched::Outcome {
                outcome: o.kind,
                cap_or_budget: o.cap,
                responses: &self.responses,
                partial: &o.partial,
                size: self.size(),
            },
            (None, ReleaseItem::UpstreamError) => ReadFetched::UpstreamError {
                responses: &self.responses,
            },
            (None, _) => ReadFetched::Pages {
                responses: &self.responses,
            },
        };
        let mut ev = payloads::read_fetched(ctx, &fetched, None);
        if let (Some((k, v)), Some(o)) = (
            self.outcome.as_ref().and_then(|o| o.cause),
            ev.payload.as_object_mut(),
        ) {
            o.insert(k.into(), v.into());
        }
        ev
    }

    fn outcome(
        responses: Vec<UpstreamResponse>,
        kind: OutcomeKind,
        cap: Option<CapOrBudget>,
        card: CardKind,
        partial: Vec<u8>,
    ) -> ItemRecord {
        ItemRecord {
            item: ReleaseItem::Outcome,
            responses,
            outcome: Some(OutcomeFacts {
                kind,
                cap,
                card,
                partial,
                cause: None,
            }),
            page: None,
            server_total: None,
            more_available: false,
        }
    }
}

fn status_2xx(r: &UpstreamResponse) -> bool {
    (200..300).contains(&r.status)
}

/// The single source of truth for what a read's result becomes (§5.2 step 6, §7.2, §11.2).
pub(crate) fn classify_read(fetched: Fetched, proxy: &ResolvedProxy) -> Classified {
    match fetched {
        Fetched::Single(FetchOutcome::Response(r)) => {
            let item = if status_2xx(&r) {
                ReleaseItem::Result
            } else {
                // Any non-2xx answer (incl. the final 429; a JSON 401 after a passing re-check).
                ReleaseItem::UpstreamError
            };
            Classified::Item(ItemRecord {
                item,
                responses: vec![r],
                outcome: None,
                page: None,
                server_total: None,
                more_available: false,
            })
        }
        Fetched::Single(FetchOutcome::Failed(f)) => classify_failure(f, Vec::new(), proxy),
        Fetched::Paged { outcome, start } => {
            let page = PageFacts {
                start,
                total: outcome.server_total,
                next_start: outcome.next_start,
                items_fetched: outcome.items_fetched,
            };
            let paged = |item, responses| {
                Classified::Item(ItemRecord {
                    item,
                    responses,
                    outcome: None,
                    page: Some(page),
                    server_total: outcome.server_total,
                    more_available: outcome.next_start.is_some(),
                })
            };
            match (outcome.end, outcome.failure) {
                (_, Some(f)) => classify_failure(f, outcome.pages, proxy),
                // `Failed` without a failure: the last page is the answer that ended paging.
                (PageEnd::Failed, None) => paged(ReleaseItem::UpstreamError, outcome.pages),
                (PageEnd::ResultsEnded | PageEnd::MaxReached, None) => {
                    paged(ReleaseItem::Result, outcome.pages)
                }
                // Never built without a failure (Task 10); gated like the failure would be.
                (PageEnd::FetchCap50MiB, None) => Classified::Item(ItemRecord::outcome(
                    outcome.pages,
                    OutcomeKind::TooLarge,
                    Some(CapOrBudget::FetchCap50MiB),
                    CardKind::FetchCap50,
                    Vec::new(),
                )),
                (PageEnd::ReadBudget120s, None) => Classified::Item(ItemRecord::outcome(
                    outcome.pages,
                    OutcomeKind::Timeout,
                    Some(CapOrBudget::ReadBudget120s),
                    CardKind::ReadBudget120,
                    Vec::new(),
                )),
            }
        }
    }
}

/// A failure, with the complete responses received before it (earlier pages). §5.2 step 6
/// returns a failure directly only when nothing about it depends on what the query selected;
/// whether a later page is requested at all does, so after a first page every direct class
/// (connection, status/header-decided, token, identity) becomes a gated outcome item and
/// "there was a page 2" never reaches the agent without a release (review I-1). An `internal`
/// failure (a bug, not data) stays direct.
fn classify_failure(
    f: FetchFailure,
    responses: Vec<UpstreamResponse>,
    proxy: &ResolvedProxy,
) -> Classified {
    let later_page = !responses.is_empty();
    match classify_one(f, responses, proxy) {
        Classified::Direct(d) => gate_later(d, later_page),
        c => c,
    }
}

/// A direct failure on a later page becomes an outcome item (`internal` stays direct).
fn gate_later(d: Direct, later_page: bool) -> Classified {
    if later_page && d.code != ErrorCode::Internal {
        Classified::Item(gated(d))
    } else {
        Classified::Direct(d)
    }
}

/// A direct failure on a later page as an outcome item: `upstream_network` for a connection
/// class, `upstream_unavailable` for the rest; the class or reason stays in the record.
fn gated(d: Direct) -> ItemRecord {
    let (kind, card) = if d.code == ErrorCode::UpstreamNetwork {
        (OutcomeKind::Network, CardKind::NetworkAfterSend)
    } else {
        (OutcomeKind::Unparsable, CardKind::LaterPageRefused)
    };
    let cause = d.cause.or(match d.code {
        ErrorCode::NeedsToken => Some(("reason", "needs_token")),
        _ => None,
    });
    let mut rec = ItemRecord::outcome(d.responses, kind, None, card, Vec::new());
    if let Some(o) = rec.outcome.as_mut() {
        o.cause = cause;
    }
    rec
}

fn classify_one(
    f: FetchFailure,
    mut responses: Vec<UpstreamResponse>,
    proxy: &ResolvedProxy,
) -> Classified {
    let outcome = |responses, kind, cap, card, partial| {
        Classified::Item(ItemRecord::outcome(responses, kind, cap, card, partial))
    };
    match f {
        // Connection-level, before the request was written: data-free (§11.2).
        FetchFailure::PreSendConnection(class) => Classified::Direct(Direct {
            code: ErrorCode::UpstreamNetwork,
            message: connection_message(class, proxy),
            cause: Some(("class", class_name(class))),
            reason_detail: None,
            responses,
        }),
        // Decided from status and headers alone (§7.2, L44): direct, the body audit-only (RF-2a).
        FetchFailure::StatusHeaderDecided { reason, response } => {
            responses.push(response);
            // §4.3: the identity-header states name their reason (instance-level, data-free).
            let reason_detail = matches!(
                reason,
                UnavailableReason::IdentityHeaderMissing
                    | UnavailableReason::IdentityHeaderMismatch
            )
            .then(|| unavailable_name(reason));
            Classified::Direct(Direct {
                code: ErrorCode::UpstreamUnavailable,
                message: unavailable_message(reason).to_owned(),
                cause: Some(("reason", unavailable_name(reason))),
                reason_detail,
                responses,
            })
        }
        // After a JSON 2xx head every failure is gated (Review Focus 2).
        FetchFailure::BodyDecided { kind, response } => {
            responses.push(response);
            let kind = match kind {
                BodyFailure::ParseFailure => OutcomeKind::Unparsable,
                BodyFailure::ReadError => OutcomeKind::Network,
            };
            outcome(
                responses,
                kind,
                None,
                CardKind::JsonBodyUnreadable,
                Vec::new(),
            )
        }
        FetchFailure::PostSend { kind, received } => {
            let (o, cap, card) = match kind {
                PostSendKind::PerCallTimeout => (
                    OutcomeKind::Timeout,
                    Some(CapOrBudget::CallTimeout30s),
                    CardKind::PerCallTimeout30,
                ),
                PostSendKind::NetworkError => {
                    (OutcomeKind::Network, None, CardKind::NetworkAfterSend)
                }
                PostSendKind::ResponseCap32MiB => (
                    OutcomeKind::TooLarge,
                    Some(CapOrBudget::ResponseCap32MiB),
                    CardKind::ResponseCap32,
                ),
                PostSendKind::FetchCap50MiB => (
                    OutcomeKind::TooLarge,
                    Some(CapOrBudget::FetchCap50MiB),
                    CardKind::FetchCap50,
                ),
                PostSendKind::ReadBudget120s => (
                    OutcomeKind::Timeout,
                    Some(CapOrBudget::ReadBudget120s),
                    CardKind::ReadBudget120,
                ),
            };
            outcome(responses, o, cap, card, received)
        }
        // The read budget ran out in the limiter before anything left: gated anyway (whether a
        // read waits that long is not data, but the outcome item is the fail-closed side).
        FetchFailure::BudgetExpiredBeforeSend => outcome(
            responses,
            OutcomeKind::Timeout,
            Some(CapOrBudget::ReadBudget120s),
            CardKind::ReadBudget120,
            Vec::new(),
        ),
        FetchFailure::OriginGuardRefused | FetchFailure::NeedsToken => Classified::Direct(Direct {
            code: ErrorCode::NeedsToken,
            message: MSG_NEEDS_TOKEN.to_owned(),
            cause: None,
            reason_detail: None,
            responses,
        }),
        // Reached for a failed check the re-check did not turn into anything else (Task 26,
        // `fetch_classified`): `upstream_unavailable`, body audit-only.
        FetchFailure::IdentityCheckFailed { response, .. } => {
            responses.push(response);
            Classified::Direct(Direct {
                code: ErrorCode::UpstreamUnavailable,
                message: MSG_IDENTITY.to_owned(),
                cause: Some(("reason", "identity_check")),
                reason_detail: None,
                responses,
            })
        }
        FetchFailure::CancelledInFlight { .. } | FetchFailure::CancelledBeforeSend => {
            Classified::Cancelled
        }
        FetchFailure::MethodGuardRefused => Classified::Direct(Direct::internal(
            "the read plan was refused by the method guard",
            responses,
        )),
    }
}

pub(crate) fn connection_message(class: ConnClass, proxy: &ResolvedProxy) -> String {
    let base = match class {
        ConnClass::TlsUnknownIssuer => HINT_TLS_UNKNOWN_ISSUER,
        ConnClass::TlsCertificate => HINT_TLS_CERTIFICATE,
        ConnClass::ProxyConnect | ConnClass::ProxyConnect407 => HINT_PROXY,
        ConnClass::Dns => MSG_DNS,
        ConnClass::Connect => MSG_CONNECT,
        ConnClass::ConnectTimeout => MSG_CONNECT_TIMEOUT,
        ConnClass::TlsHandshake => MSG_TLS_HANDSHAKE,
    };
    // §7.2: the PAC hint only where the instance followed an OS setting that uses PAC.
    if proxy.uses_os && proxy.pac_configured {
        format!("{base}; {PAC_HINT}")
    } else {
        base.to_owned()
    }
}

pub(crate) fn class_name(class: ConnClass) -> &'static str {
    match class {
        ConnClass::Dns => "dns",
        ConnClass::Connect => "connect",
        ConnClass::ConnectTimeout => "connect_timeout",
        ConnClass::TlsHandshake => "tls_handshake",
        ConnClass::TlsUnknownIssuer => "tls_unknown_issuer",
        ConnClass::TlsCertificate => "tls_certificate",
        ConnClass::ProxyConnect => "proxy_connect",
        ConnClass::ProxyConnect407 => "proxy_connect_407",
    }
}

pub(crate) fn unavailable_name(r: UnavailableReason) -> &'static str {
    match r {
        UnavailableReason::Redirect3xx => "redirect_3xx",
        UnavailableReason::NonJson2xx => "non_json_2xx",
        UnavailableReason::NonJson401 => "non_json_401",
        UnavailableReason::IdentityHeaderMissing => "identity_header_missing",
        UnavailableReason::IdentityHeaderMismatch => "identity_header_mismatch",
    }
}

pub(crate) fn unavailable_message(r: UnavailableReason) -> &'static str {
    match r {
        UnavailableReason::Redirect3xx => MSG_REDIRECT,
        UnavailableReason::NonJson2xx => MSG_NON_JSON,
        UnavailableReason::NonJson401 => MSG_NON_JSON_401,
        UnavailableReason::IdentityHeaderMissing | UnavailableReason::IdentityHeaderMismatch => {
            MSG_IDENTITY
        }
    }
}

// ---- records, candidates ------------------------------------------------------------------------

/// What `settle` hands to the transition for a release item.
struct Built {
    record: NewEvent,
    candidate: Arc<Candidate>,
    state: ReadState,
    caution: u32,
}

/// The approver-side context of a read's preview.
pub(crate) struct ReadContext<'a> {
    pub spec: &'static OperationSpec,
    pub alias: &'a str,
    pub params: &'a Value,
    pub target_display: &'a str,
}

/// Records the fetch and applies `Fetched(item)` (rev 1) or `FetchFailedDirect`.
async fn settle(engine: &Arc<Engine>, entry: &Arc<RequestEntry>, classified: Classified) {
    match classified {
        // Task 24 contract: the control is cancelled only inside `cancel_now`'s gated section,
        // which records the bytes and the terminal event; by the time this transition gets the
        // gate the request is terminal and nothing is recorded here. A request still pending
        // then would never end otherwise: it fails `internal` (fail closed), with what arrived.
        Classified::Cancelled => {
            let captured = entry.fetch_control().map(|c| c.take_captured().pages);
            let d = Direct::internal(MSG_ABORTED, captured.unwrap_or_default());
            direct(engine, entry, d).await;
        }
        Classified::Direct(d) => direct(engine, entry, d).await,
        Classified::Item(rec) => {
            let (spec, ctx) = (entry.spec, entry.ctx.clone());
            let clamped = entry
                .validated
                .as_ref()
                .is_some_and(|v| v.truncated_by_clamp);
            let params = entry
                .validated
                .as_ref()
                .map(|v| v.params.clone())
                .unwrap_or(Value::Null);
            let (alias, target) = (entry.head.instance.clone(), entry.target_display.clone());
            // Normalizing up to 50 MiB of pages and building the preview is CPU work.
            let built = tokio::task::spawn_blocking(move || {
                let cx = ReadContext {
                    spec,
                    alias: &alias,
                    params: &params,
                    target_display: &target,
                };
                // A 2xx body the client accepted that the candidate cannot be built from (e.g.
                // JSON nested deeper than `serde_json::Value` parses) depends on the content:
                // gated as an unparsable outcome, never a direct failure (review I-2).
                build_item(&cx, &ctx, rec, clamped).or_else(|responses| {
                    let rec = ItemRecord::outcome(
                        responses,
                        OutcomeKind::Unparsable,
                        None,
                        CardKind::JsonBodyUnreadable,
                        Vec::new(),
                    );
                    build_item(&cx, &ctx, rec, clamped)
                })
            })
            .await;
            match built {
                Ok(Ok(b)) => item(engine, entry, b).await,
                Ok(Err(responses)) => {
                    let d = Direct::internal("the response could not be processed", responses);
                    direct(engine, entry, d).await;
                }
                Err(_) => {
                    let d = Direct::internal("the response could not be processed", Vec::new());
                    direct(engine, entry, d).await;
                }
            }
        }
    }
}

/// `[READ_FETCHED (the answer, audit-only), READ_FAILED]` in one batch, then `failed` (§5.2 step 6).
async fn direct(engine: &Arc<Engine>, entry: &Arc<RequestEntry>, d: Direct) {
    let ctx = entry.ctx.clone();
    let records = move |_: &crate::lifecycle::model::Model| {
        let mut evs = Vec::new();
        if !d.responses.is_empty() {
            let reason = d.cause.map_or("internal", |(_, v)| v);
            evs.push(payloads::read_fetched(
                &ctx,
                &ReadFetched::Unavailable {
                    responses: &d.responses,
                    reason,
                },
                None,
            ));
        }
        let mut details = Map::new();
        if let Some(r) = d.reason_detail {
            details.insert("reason".into(), r.into());
        }
        evs.push(payloads::read_failed(
            &ctx,
            d.code,
            &d.message,
            &Value::Object(details),
            d.cause,
        ));
        evs
    };
    // A cancel or expiry that landed first already ended the request: nothing to record.
    let _ = engine
        .transition_with(
            entry,
            Event::FetchFailedDirect,
            records,
            OnAuditFailure::FailRequest,
            |_| {},
        )
        .await;
}

async fn item(engine: &Arc<Engine>, entry: &Arc<RequestEntry>, b: Built) {
    let Built {
        record,
        candidate,
        state,
        caution,
    } = b;
    let item = state.item;
    let (cache, id) = (engine.clone(), entry.head.request_id.clone());
    let owner = entry.clone();
    let applied = engine
        .transition_with(
            entry,
            Event::Fetched(item),
            move |_| vec![record],
            OnAuditFailure::FailRequest,
            move |st| {
                st.candidate_hash = *candidate.hash();
                st.redaction_ops = Vec::new();
                st.rebuild_failed = false;
                st.caution_count = caution;
                st.read = Some(state);
                // §5.1 inv. 6: a fresh read candidate has no ops to block it.
                st.model.set_approvable(true);
                cache.candidates().insert(&id, candidate);
                // The raw fetch is freed once `READ_FETCHED` is committed (§5.2 memory budget),
                // in this gated step: a cancel or expiry after it must not find a control to
                // record a second time (Task 24 review I-1).
                owner.set_fetch_control(None);
            },
        )
        .await;
    if applied.is_ok() {
        let ui = engine.ui();
        ui.emit(UiEvent::QueueChanged {
            request_ids: vec![entry.head.request_id.clone()],
        });
        ui.emit(UiEvent::Attention {
            kind: AttentionKind::New,
            count: 1,
        });
    }
}

/// The record, the candidate built from that record's payload and the queue facts. `Err` holds
/// the responses when the record cannot be turned into a candidate (an internal failure).
fn build_item(
    cx: &ReadContext<'_>,
    ctx: &EventCtx,
    mut rec: ItemRecord,
    clamped: bool,
) -> Result<Built, Vec<UpstreamResponse>> {
    let mut record = rec.record(ctx);
    let built = normalize_with_drops(cx.spec, &record.payload)
        .and_then(|(body, dropped)| Ok((build_candidate(cx.spec, body, &[])?, dropped)));
    let (mut candidate, mut dropped) = match built {
        Ok(b) => b,
        Err(_) => return Err(rec.responses),
    };
    // §5.2 step 4: the 16 MiB release cap on the serialized candidate.
    let over_cap = u64::try_from(candidate.bytes().len()).unwrap_or(u64::MAX) > RELEASE_CAP_BYTES;
    if rec.item == ReleaseItem::Result && over_cap {
        drop(candidate);
        rec = ItemRecord::outcome(
            rec.responses,
            OutcomeKind::TooLarge,
            Some(CapOrBudget::ReleaseCap16MiB),
            CardKind::ReleaseCap16,
            Vec::new(),
        );
        record = rec.record(ctx);
        let built = normalize_with_drops(cx.spec, &record.payload)
            .and_then(|(body, _)| build_candidate(cx.spec, body, &[]));
        candidate = match built {
            Ok(c) => c,
            Err(_) => return Err(rec.responses),
        };
        dropped = 0;
    }
    let state = ReadState {
        item: rec.item,
        outcome: rec.outcome.as_ref().map(|o| o.card),
        received: rec.size(),
        pages: u64::try_from(rec.responses.len()).unwrap_or(u64::MAX),
        page: rec.page,
        server_total: rec.server_total,
        more_available: rec.more_available,
        clamped,
        normalized_dropped: dropped,
        redaction_meta: None,
        also_appears_in: Vec::new(),
    };
    let caution = caution_count(&preview_model(cx, &state, &candidate));
    Ok(Built {
        record,
        candidate: Arc::new(candidate),
        state,
        caution,
    })
}

/// Caution-level warnings of a preview (§5.6 "caution (N)").
pub(crate) fn caution_count(m: &PreviewModel) -> u32 {
    let n = m
        .warnings
        .iter()
        .filter(|w| w.level == Level::Caution)
        .count();
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The bare candidate body of a committed `READ_FETCHED` payload: the one normalization the
/// first build and every rebuild use (`cache`'s contract). Reads nothing but the payload.
pub fn normalize(spec: &OperationSpec, payload: &Value) -> Result<Value, RebuildError> {
    normalize_with_drops(spec, payload).map(|(body, _)| body)
}

/// [`normalize`] for `Engine::candidate`.
pub(crate) fn normalizer(
    spec: &'static OperationSpec,
) -> impl FnOnce(&Value) -> Result<Value, RebuildError> + Send + 'static {
    move |payload| normalize(spec, payload)
}

/// [`normalize`] plus the number of results it removed (§7.4).
fn normalize_with_drops(
    spec: &OperationSpec,
    payload: &Value,
) -> Result<(Value, u64), RebuildError> {
    if let Some(outcome) = payload.get("outcome") {
        let code = outcome
            .as_str()
            .and_then(outcome_code)
            .ok_or(RebuildError::Malformed)?;
        let code = serde_json::to_value(code).map_err(|_| RebuildError::Malformed)?;
        return Ok((json!({ "code": code, "hint": OUTCOME_HINT }), 0));
    }
    // A direct failure's answer is never a candidate.
    if payload.get("unavailable").is_some() {
        return Err(RebuildError::Malformed);
    }
    let responses = fetched_responses(payload)?;
    if payload.get("upstream_error") == Some(&Value::Bool(true)) {
        let last = responses.last().ok_or(RebuildError::Malformed)?;
        return Ok((error_candidate(last), 0));
    }
    result_body(spec, responses)
}

/// The released code of an outcome (§5.2 step 6): caps → `result_too_large`, timeouts and
/// network failures → `upstream_network`, a JSON body that does not parse →
/// `upstream_unavailable`. `cancelled_in_flight` is never a candidate.
fn outcome_code(outcome: &str) -> Option<ErrorCode> {
    match outcome {
        "too_large" => Some(ErrorCode::ResultTooLarge),
        "timeout" | "network" => Some(ErrorCode::UpstreamNetwork),
        "unparsable" => Some(ErrorCode::UpstreamUnavailable),
        _ => None,
    }
}

/// The result: one response's JSON, or for a paged op the first page's object with the items of
/// every page under `items_key` (server totals as sent, §4.2). `confluence.search` results
/// without a `content` object are removed and counted (§7.4 defence in depth).
fn result_body(
    spec: &OperationSpec,
    responses: Vec<UpstreamResponse>,
) -> Result<(Value, u64), RebuildError> {
    let mut pages = responses
        .into_iter()
        .map(|r| serde_json::from_slice::<Value>(&r.body).map_err(|_| RebuildError::Malformed));
    let mut body = pages.next().ok_or(RebuildError::Malformed)??;
    if let Some(paging) = spec.paginated
        && body.is_object()
    {
        let mut items = match body.get_mut(paging.items_key).map(Value::take) {
            Some(Value::Array(a)) => a,
            _ => Vec::new(),
        };
        for page in pages {
            if let Some(Value::Array(a)) = page?.get_mut(paging.items_key).map(Value::take) {
                items.extend(a);
            }
        }
        let mut dropped = 0u64;
        if spec.id == "confluence.search" {
            let before = items.len();
            items.retain(|r| r.get("content").is_some_and(Value::is_object));
            dropped = u64::try_from(before - items.len()).unwrap_or(u64::MAX);
        }
        if let Some(o) = body.as_object_mut() {
            o.insert(paging.items_key.to_owned(), Value::Array(items));
        }
        return Ok((body, dropped));
    }
    Ok((body, 0))
}

/// The upstream-error candidate `{status, error_messages}` (§5.2 step 6, §6.3).
fn error_candidate(r: &UpstreamResponse) -> Value {
    json!({ "status": r.status, "error_messages": error_text(&r.body) })
}

/// Atlassian `errorMessages` and `errors` (Confluence DC: `message`) as text, capped at 2 KiB
/// (§6.3, §11.2). A body that is not JSON gives no text (it stays in the record).
pub(crate) fn error_text(body: &[u8]) -> String {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return String::new();
    };
    let mut lines: Vec<String> = Vec::new();
    if let Some(list) = v.get("errorMessages").and_then(Value::as_array) {
        lines.extend(list.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    if let Some(map) = v.get("errors").and_then(Value::as_object) {
        for (k, m) in map {
            if let Some(m) = m.as_str() {
                lines.push(format!("{k}: {m}"));
            }
        }
    }
    if lines.is_empty()
        && let Some(m) = v.get("message").and_then(Value::as_str)
    {
        lines.push(m.to_owned());
    }
    cap_error_text(&lines.join("\n"))
}

// ---- previews and release metadata -------------------------------------------------------------

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The preview of a read item: the op's previewer for a result, the compact cards for an upstream
/// error and an outcome (§6.3). Header counts run over the full candidate (§6.1).
pub(crate) fn preview_model(cx: &ReadContext<'_>, read: &ReadState, c: &Candidate) -> PreviewModel {
    let value = c.value();
    let byte_size = len_u64(c.bytes().len());
    match read.item {
        ReleaseItem::Result => {
            let previewer = op_table()
                .get(cx.spec.id)
                .map_or(fallback_preview as crate::ops::PreviewerFn, |o| o.previewer);
            previewer(&PreviewCtx {
                spec: cx.spec,
                instance_alias: cx.alias,
                params: cx.params,
                input: PreviewInput::Read(ReadView {
                    candidate: value,
                    byte_size,
                    server_total: read.server_total,
                    more_available: read.more_available,
                    clamped: read.clamped,
                }),
            })
        }
        ReleaseItem::UpstreamError => {
            let status = value
                .get("status")
                .and_then(Value::as_u64)
                .and_then(|s| u16::try_from(s).ok())
                .unwrap_or(0);
            let text = value
                .get("error_messages")
                .and_then(Value::as_str)
                .unwrap_or_default();
            card(
                cx,
                value,
                byte_size,
                PreviewBody::upstream_error(status, &escape_for_display(text)),
            )
        }
        _ => {
            let query = query_display(cx.spec, cx.params)
                .unwrap_or_else(|| escape_for_display(cx.target_display));
            let body = PreviewBody::Outcome {
                outcome: read.outcome.unwrap_or(CardKind::NetworkAfterSend),
                size_or_pages: format!(
                    "{} bytes received, {} responses",
                    read.received, read.pages
                ),
                query,
            };
            card(cx, value, byte_size, body)
        }
    }
}

fn card(cx: &ReadContext<'_>, value: &Value, byte_size: u64, body: PreviewBody) -> PreviewModel {
    let (bidi, other) = count_value(value);
    let mut warnings = Vec::new();
    invisible_warnings(&mut warnings, bidi, other);
    let query = query_display(cx.spec, cx.params);
    PreviewModel {
        header: PreviewHeader {
            instance_alias: cx.alias.to_owned(),
            op_id: cx.spec.id.to_owned(),
            class: "read".to_owned(),
            item_count: None,
            byte_size,
            fields_included: value
                .as_object()
                .map(|o| o.keys().map(|k| escape_for_display(k)).collect())
                .unwrap_or_default(),
            hidden_in_preview_bytes: 0,
            bidi_controls: bidi,
            other_invisible: other,
            executes_as: None,
            receipt_fields: Vec::new(),
            query: query.clone(),
        },
        body,
        warnings,
        query,
    }
}

/// `meta.page` (§7.5, paged ops) and `meta.redactions` (§4.2) of a release, stored in its
/// `READ_RELEASED` so a delivery needs nothing but the record. `returned` counts the released
/// items, so `returned + items_dropped` equals the items fetched.
pub(crate) fn release_meta(spec: &OperationSpec, read: &ReadState, released: &Value) -> Value {
    let mut meta = Map::new();
    // An upstream error's details have no items: `meta.page` belongs to a released result.
    if let (ReleaseItem::Result, Some(p), Some(paging)) = (read.item, read.page, spec.paginated) {
        let returned = released
            .get(paging.items_key)
            .and_then(Value::as_array)
            .map_or(0, |a| len_u64(a.len()));
        meta.insert(
            "page".into(),
            json!({
                "start": p.start,
                "returned": returned,
                "total": p.total,
                "truncated": p.next_start.is_some(),
                "next_start": p.next_start,
            }),
        );
    }
    if read.redaction_meta.is_some() || read.normalized_dropped > 0 {
        let mut r = read.redaction_meta.clone().unwrap_or_default();
        r.items_dropped = r.items_dropped.saturating_add(read.normalized_dropped);
        meta.insert(
            "redactions".into(),
            serde_json::to_value(r).unwrap_or(Value::Null),
        );
    }
    Value::Object(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn error_text_joins_and_caps() -> TestResult {
        let body = br#"{"errorMessages":["Issue does not exist"],"errors":{"summary":"required"}}"#;
        assert_eq!(error_text(body), "Issue does not exist\nsummary: required");
        assert_eq!(error_text(b"<html>no</html>"), "");
        assert_eq!(error_text(br#"{"statusCode":400,"message":"dup"}"#), "dup");
        let long = format!(r#"{{"errorMessages":["{}"]}}"#, "x".repeat(5000));
        assert!(error_text(long.as_bytes()).len() <= atlas_duck_preview::ERROR_TEXT_CAP_BYTES);
        Ok(())
    }

    fn direct_proxy() -> ResolvedProxy {
        ResolvedProxy {
            choice: atlas_duck_atlassian::ProxyChoice::Direct,
            pac_configured: false,
            uses_os: false,
            os_read_failed: false,
            effective: "direct".to_owned(),
        }
    }

    fn answer(status: u16, ct: &str) -> UpstreamResponse {
        UpstreamResponse {
            status,
            content_type: Some(ct.to_owned()),
            body: b"<html>x</html>".to_vec(),
        }
    }

    /// Ruling 4 carve-out: only the §4.3 identity-header reasons reach the envelope's details.
    #[test]
    fn identity_header_reason_is_the_only_detail() -> TestResult {
        let f = |reason| FetchFailure::StatusHeaderDecided {
            reason,
            response: answer(200, "text/html"),
        };
        for (reason, detail) in [
            (
                UnavailableReason::IdentityHeaderMissing,
                Some("identity_header_missing"),
            ),
            (
                UnavailableReason::IdentityHeaderMismatch,
                Some("identity_header_mismatch"),
            ),
            (UnavailableReason::Redirect3xx, None),
            (UnavailableReason::NonJson2xx, None),
        ] {
            match classify_failure(f(reason), Vec::new(), &direct_proxy()) {
                Classified::Direct(d) => assert_eq!(d.reason_detail, detail, "{reason:?}"),
                _ => return Err(format!("{reason:?} not direct").into()),
            }
        }
        Ok(())
    }

    /// Review I-1: after a first page, no failure class is direct.
    #[test]
    fn later_page_failures_are_gated() -> TestResult {
        let page1 = || vec![answer(200, "application/json")];
        let cases = [
            (
                FetchFailure::PreSendConnection(ConnClass::Dns),
                OutcomeKind::Network,
                ("class", "dns"),
            ),
            (
                FetchFailure::StatusHeaderDecided {
                    reason: UnavailableReason::Redirect3xx,
                    response: answer(302, "text/html"),
                },
                OutcomeKind::Unparsable,
                ("reason", "redirect_3xx"),
            ),
            (
                FetchFailure::NeedsToken,
                OutcomeKind::Unparsable,
                ("reason", "needs_token"),
            ),
            (
                FetchFailure::IdentityCheckFailed {
                    observed: atlas_duck_atlassian::IdentityObserved::Missing,
                    response: answer(200, "application/json"),
                },
                OutcomeKind::Unparsable,
                ("reason", "identity_check"),
            ),
        ];
        for (f, kind, cause) in cases {
            match classify_failure(f, page1(), &direct_proxy()) {
                Classified::Item(rec) => {
                    assert_eq!(rec.item, ReleaseItem::Outcome);
                    let o = rec.outcome.as_ref().ok_or("no outcome")?;
                    assert_eq!((o.kind, o.cause), (kind, Some(cause)));
                }
                _ => return Err(format!("{cause:?} not gated").into()),
            }
        }
        // A bug is not data: the method guard stays direct.
        assert!(matches!(
            classify_failure(FetchFailure::MethodGuardRefused, page1(), &direct_proxy()),
            Classified::Direct(_)
        ));
        Ok(())
    }

    #[test]
    fn outcome_codes() {
        assert_eq!(outcome_code("too_large"), Some(ErrorCode::ResultTooLarge));
        assert_eq!(outcome_code("timeout"), Some(ErrorCode::UpstreamNetwork));
        assert_eq!(outcome_code("network"), Some(ErrorCode::UpstreamNetwork));
        assert_eq!(
            outcome_code("unparsable"),
            Some(ErrorCode::UpstreamUnavailable)
        );
        assert_eq!(outcome_code("cancelled_in_flight"), None);
    }
}
