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
    AuditCover, BodyFailure, ConnClass, FetchControl, FetchFailure, FetchOutcome, InstanceClient,
    PageEnd, PagedOutcome, PostSendKind, ReadBudget, UnavailableReason, UpstreamResponse,
};
use atlas_duck_audit::NewEvent;
use atlas_duck_ipc::envelope::ErrorCode;
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::{
    Level, OutcomeKind as CardKind, PreviewBody, PreviewHeader, cap_error_text,
};
use atlas_duck_registry::{OperationSpec, Product, RELEASE_CAP_BYTES};
use serde_json::{Map, Value, json};
use tokio::sync::OwnedSemaphorePermit;

use super::cache::{Candidate, RebuildError, build_candidate, build_unredacted, fetched_refs};
use super::envelope::{MSG_IDENTITY_HEADER, OpenStatus};
use super::{Engine, InstanceHttp, OnAuditFailure, RequestEntry};
use crate::gate::{AttentionKind, UiEvent};
use crate::identity::{self, Lost};
use crate::instances::InstanceState;
use crate::lifecycle::model::{Event, ReleaseItem};
use crate::metadata::{FieldCache, FieldNames};
use crate::ops::generic::{count_value, fallback_preview, invisible_warnings, query_display};
use crate::ops::{
    ExecPlan, PreviewCtx, PreviewInput, PreviewModel, ReadPlan, ReadView, jira, op_table,
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
    /// `jira.issue.get --comments` stopped at the comments cap: `(fetched, server total)`.
    pub comments_truncated: Option<(u64, u64)>,
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
    // S-15: a read whose JQL holds the hook's text dies here, after `REQUEST_RECEIVED`. The
    // payload names nothing of the request.
    #[cfg(feature = "testing")]
    if let Some(needle) = engine.hooks().panic_on_jql.as_deref()
        && entry
            .validated
            .as_ref()
            .and_then(|v| v.params.get("jql"))
            .and_then(Value::as_str)
            .is_some_and(|jql| jql.contains(needle))
    {
        std::panic::panic_any("read task panic (test hook)");
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
pub(super) fn fetched_trigger(f: &Fetched) -> Option<identity::Trigger> {
    match f {
        Fetched::Single(o) => identity::trigger(o),
        Fetched::Paged { outcome, .. } | Fetched::Composite { outcome } => paged_trigger(outcome),
    }
}

fn paged_trigger(outcome: &PagedOutcome) -> Option<identity::Trigger> {
    match &outcome.failure {
        Some(failure) => identity::failure_trigger(failure),
        None if outcome.end == PageEnd::Failed
            && outcome.pages.last().is_some_and(|r| r.status == 401) =>
        {
            Some(identity::Trigger::Json401)
        }
        None => None,
    }
}

/// The fetch as the ordinary answer it is once the re-check passed on a JSON 401.
pub(super) fn ordinary(f: Fetched) -> Fetched {
    match f {
        Fetched::Single(o) => Fetched::Single(identity::as_response(o)),
        Fetched::Paged { outcome, start } => Fetched::Paged {
            outcome: paged_ordinary(outcome),
            start,
        },
        Fetched::Composite { outcome } => Fetched::Composite {
            outcome: paged_ordinary(outcome),
        },
    }
}

fn paged_ordinary(mut outcome: PagedOutcome) -> PagedOutcome {
    if let Some(FetchFailure::IdentityCheckFailed { response, .. }) = outcome.failure.take() {
        outcome.pages.push(response);
        outcome.end = PageEnd::Failed;
    }
    outcome
}

/// The complete responses before the triggering answer, and that answer.
pub(super) fn split_answer(f: Fetched) -> (Vec<UpstreamResponse>, Option<UpstreamResponse>) {
    match f {
        Fetched::Single(FetchOutcome::Failed(FetchFailure::IdentityCheckFailed {
            response,
            ..
        })) => (Vec::new(), Some(response)),
        Fetched::Single(FetchOutcome::Response(r)) => (Vec::new(), Some(r)),
        Fetched::Single(FetchOutcome::Failed(_)) => (Vec::new(), None),
        Fetched::Paged { mut outcome, .. } | Fetched::Composite { mut outcome } => {
            match outcome.failure.take() {
                Some(FetchFailure::IdentityCheckFailed { response, .. }) => {
                    (outcome.pages, Some(response))
                }
                _ => {
                    let last = outcome.pages.pop();
                    (outcome.pages, last)
                }
            }
        }
    }
}

/// What the identity table makes of a read that is not re-fetched (§7.1): `needs_token`, the
/// identity-header states, or `upstream_unavailable` (retryable) for a passing or inconclusive
/// re-check. The answer is audit-only (RF-2a); after a first page the failure is an outcome item
/// like every direct class (review I-1).
pub(super) fn identity_classified(effect: identity::Effect, fetched: Fetched) -> Classified {
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
    Paged {
        outcome: PagedOutcome,
        start: u64,
    },
    /// `jira.issue.get --comments` after a 2xx issue answer (PD-45): `pages[0]` is the issue,
    /// the rest and every other field are the comment pages'. An issue answer that is not 2xx
    /// is `Single` (no comment page was requested).
    Composite {
        outcome: PagedOutcome,
    },
}

/// Runs `plan` under `cover` with `ctl` (the direct read and a script's host call). A composite
/// read sends the issue GET, then the comment pages with what is left of the one read budget
/// (time and bytes): `budget` bounds the read as a whole (§7.2).
pub(crate) async fn run_plan(
    client: &InstanceClient,
    cover: &AuditCover,
    plan: &ReadPlan,
    budget: &ReadBudget,
    ctl: &FetchControl,
    start: u64,
) -> Fetched {
    match plan {
        ReadPlan::Get(call) => Fetched::Single(client.get_ctl(cover, call, ctl).await),
        ReadPlan::Paged { call, max_items } => Fetched::Paged {
            outcome: client
                .read_paginated_ctl(cover, call, budget, *max_items, ctl)
                .await,
            start,
        },
        ReadPlan::Search {
            call,
            items_key,
            max_items,
        } => Fetched::Paged {
            outcome: client
                .read_paginated_search_ctl(cover, call, items_key, budget, *max_items, ctl)
                .await,
            start,
        },
        ReadPlan::IssueWithComments {
            issue,
            comments,
            max_items,
            ..
        } => {
            let began = tokio::time::Instant::now();
            // A 2xx issue answer is kept in `ctl`: a cancel during the comment pages records it.
            let issue = match client.get_kept_ctl(cover, issue, ctl).await {
                FetchOutcome::Response(r) if status_2xx(&r) => r,
                other => return Fetched::Single(other),
            };
            let issue_bytes = u64::try_from(issue.body.len()).unwrap_or(u64::MAX);
            let left = ReadBudget {
                total: budget.total.saturating_sub(began.elapsed()),
                max_bytes: budget.max_bytes.saturating_sub(issue_bytes),
                ..*budget
            };
            let mut outcome = client
                .read_paginated_ctl(cover, comments, &left, *max_items, ctl)
                .await;
            outcome.pages.insert(0, issue);
            Fetched::Composite { outcome }
        }
    }
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
    let plan = (op.executor)(&engine.exec_ctx(
        entry.spec,
        &validated.params,
        http.client.base(),
        None,
        validated.effective_max,
        validated.comments_cap,
    ));
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
    let fetched = run_plan(&http.client, &cover, &plan, &budget, &ctl, start).await;
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
    pub(super) item: ReleaseItem,
    /// Complete responses (pages, the upstream error, the response whose body failed).
    pub(super) responses: Vec<UpstreamResponse>,
    pub(super) outcome: Option<OutcomeFacts>,
    pub(super) page: Option<PageFacts>,
    server_total: Option<u64>,
    more_available: bool,
    /// A composite read's comments stopped at the cap: `(fetched, server total)` (PD-45).
    pub(super) comments_truncated: Option<(u64, u64)>,
}

pub(super) struct OutcomeFacts {
    pub(super) kind: OutcomeKind,
    cap: Option<CapOrBudget>,
    card: CardKind,
    /// Bytes of the response being read when it stopped.
    pub(super) partial: Vec<u8>,
    /// The diagnosis of a later-page failure that is gated instead of direct (`class` or
    /// `reason`), kept in the record only.
    cause: Option<(&'static str, &'static str)>,
}

/// A data-free direct failure (§5.2 step 6 "directly returned without release").
pub(crate) struct Direct {
    pub(super) code: ErrorCode,
    pub(super) message: String,
    /// `("class", ..)` or `("reason", ..)` in the record.
    pub(super) cause: Option<(&'static str, &'static str)>,
    /// `details.reason` in the envelope: only the §4.3 identity-header states (ruling 4
    /// carve-out); every other class or reason stays in the record.
    pub(super) reason_detail: Option<&'static str>,
    /// Responses received before the failure was decided (audit-only, RF-2a).
    pub(super) responses: Vec<UpstreamResponse>,
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
    pub(super) fn size(&self) -> u64 {
        let partial = self.outcome.as_ref().map_or(0, |o| o.partial.len());
        self.responses
            .iter()
            .map(|r| r.body.len())
            .chain(std::iter::once(partial))
            .map(|n| u64::try_from(n).unwrap_or(u64::MAX))
            .fold(0u64, u64::saturating_add)
    }

    pub(super) fn record(&self, ctx: &EventCtx) -> NewEvent {
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
            comments_truncated: None,
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
                comments_truncated: None,
            })
        }
        Fetched::Single(FetchOutcome::Failed(f)) => classify_failure(f, Vec::new(), proxy),
        // Classified as paging (the issue is the first page, so every comment-page failure is a
        // later-page one: gated, review I-1), then stripped of the paging facts: the op is not
        // paginated and has no `meta.page` (PD-45).
        Fetched::Composite { outcome } => {
            let truncated = match outcome.server_total {
                Some(total) if outcome.next_start.is_some() && outcome.items_fetched < total => {
                    Some((outcome.items_fetched, total))
                }
                _ => None,
            };
            match classify_read(Fetched::Paged { outcome, start: 0 }, proxy) {
                Classified::Item(mut rec) => {
                    if rec.item == ReleaseItem::Result {
                        rec.comments_truncated = truncated;
                    }
                    rec.page = None;
                    rec.server_total = None;
                    rec.more_available = false;
                    Classified::Item(rec)
                }
                other => other,
            }
        }
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
                    comments_truncated: None,
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
    /// The §5.3 mirror check fails on the candidate: Release disabled from the start.
    mirror_blocked: bool,
}

/// The approver-side context of a read's preview.
pub(crate) struct ReadContext<'a> {
    pub spec: &'static OperationSpec,
    pub alias: &'a str,
    pub params: &'a Value,
    pub target_display: &'a str,
    /// The cached Jira field names ([`preview_field_names`]); `None` for Confluence.
    pub field_names: Option<Arc<FieldNames>>,
}

/// The field names a read preview of `entry` shows (PD-46): for a Jira read, the instance's
/// cached map as it is now. A map whose last fill started at least `FIELD_CACHE_TTL` ago is
/// refreshed in the background; this preview never waits for it.
pub(crate) fn preview_field_names(
    engine: &Arc<Engine>,
    entry: &RequestEntry,
) -> Option<Arc<FieldNames>> {
    if entry.spec.product != Product::Jira {
        return None;
    }
    FieldCache::refresh_if_stale(engine, &entry.instance_id);
    engine.field_cache().snapshot(&entry.instance_id)
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
            let field_names = preview_field_names(engine, entry);
            // Normalizing up to 50 MiB of pages and building the preview is CPU work.
            let built = tokio::task::spawn_blocking(move || {
                let cx = ReadContext {
                    spec,
                    alias: &alias,
                    params: &params,
                    target_display: &target,
                    field_names,
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
        mirror_blocked,
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
                // §5.1 inv. 6: a fresh read candidate has no ops; only the mirror check (§5.3)
                // can block it, as a rebuild failure does (`internal` banner, only Deny).
                st.rebuild_failed = mirror_blocked;
                st.caution_count = caution;
                st.read = Some(state);
                st.model.set_approvable(!mirror_blocked);
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
    let shape = ReadShape::of(cx.spec, cx.params);
    let mut record = rec.record(ctx);
    // §5.3 mirror check on the unredacted candidate (T10 review I-1): a candidate that fails it
    // is still shown, but Release stays disabled (`rebuild_failed`: `internal` banner, only Deny
    // remains) until a redaction drops the orphan entry.
    let built =
        normalize_with_drops(cx.spec, shape, &record.payload).and_then(|(body, dropped)| {
            let (c, blocked) = build_unredacted(cx.spec, body)?;
            Ok((c, dropped, blocked))
        });
    let (mut candidate, mut dropped, mut mirror_blocked) = match built {
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
        let built = normalize_with_drops(cx.spec, shape, &record.payload)
            .and_then(|(body, _)| build_candidate(cx.spec, body, &[]));
        candidate = match built {
            Ok(c) => c,
            Err(_) => return Err(rec.responses),
        };
        dropped = 0;
        mirror_blocked = false;
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
        comments_truncated: rec.comments_truncated,
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
        mirror_blocked,
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

/// How a read's 2xx pages become its body. Decided by the op and its committed (validated)
/// params alone, never by fetched content, so the first build and every rebuild agree (PD-45:
/// the `READ_FETCHED` payload of a composite read has no shape of its own).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadShape {
    /// One response, or the pages of a paged op.
    Plain,
    /// `jira.issue.get --comments`: the issue, then the comment pages, merged into
    /// `fields.comment` (and with `rendered`, `renderedFields.comment`).
    IssueWithComments { rendered: bool },
}

impl ReadShape {
    pub fn of(spec: &OperationSpec, params: &Value) -> ReadShape {
        if spec.id == "jira.issue.get" && jira::wants_comments(params) {
            ReadShape::IssueWithComments {
                rendered: jira::comments_rendered(params),
            }
        } else {
            ReadShape::Plain
        }
    }
}

/// The bare candidate body of a committed `READ_FETCHED` payload: the one normalization the
/// first build and every rebuild use (`cache`'s contract). Reads nothing but the payload and the
/// request's validated `params` (which decide the [`ReadShape`]).
pub fn normalize(
    spec: &OperationSpec,
    params: &Value,
    payload: &Value,
) -> Result<Value, RebuildError> {
    normalize_with_drops(spec, ReadShape::of(spec, params), payload).map(|(body, _)| body)
}

/// [`normalize`] for `Engine::candidate`, with the shape decided from `params` up front.
pub(crate) fn normalizer(
    spec: &'static OperationSpec,
    params: &Value,
) -> impl FnOnce(&Value) -> Result<Value, RebuildError> + Send + 'static {
    let shape = ReadShape::of(spec, params);
    move |payload| normalize_with_drops(spec, shape, payload).map(|(body, _)| body)
}

/// [`normalize`] plus the number of results it removed (§7.4).
fn normalize_with_drops(
    spec: &OperationSpec,
    shape: ReadShape,
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
    let responses = fetched_refs(payload)?;
    if payload.get("upstream_error") == Some(&Value::Bool(true)) {
        let last = responses.last().ok_or(RebuildError::Malformed)?;
        return Ok((error_candidate(last.status, &last.body), 0));
    }
    result_value(spec, shape, responses.iter().map(|r| &*r.body))
}

/// The result of a read's 2xx pages in its [`ReadShape`] (the direct read's candidate, a script
/// host call's result).
pub(super) fn result_value<'a>(
    spec: &OperationSpec,
    shape: ReadShape,
    bodies: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(Value, u64), RebuildError> {
    match shape {
        ReadShape::Plain => result_body(spec, bodies),
        ReadShape::IssueWithComments { rendered } => {
            merge_comments(bodies, rendered).map(|body| (body, 0))
        }
    }
}

/// PD-45: the issue (the first body) with `fields.comment = {startAt, maxResults, total,
/// comments}`: the first comment page's numbers as the server sent them (the total unchanged)
/// and the comments of every page in order, replacing whatever `fields.comment` the issue had.
/// With `rendered`, each comment's `renderedBody` moves out of the field side into
/// `renderedFields.comment.comments [{id, body}]`, one entry per comment (`body: null` when the
/// server sent none), so the M3 mirror `fields.comment.comments ↔ renderedFields.comment.comments`
/// (key `id`) finds a counterpart for every comment.
fn merge_comments<'a>(
    bodies: impl IntoIterator<Item = &'a [u8]>,
    rendered: bool,
) -> Result<Value, RebuildError> {
    let mut pages = bodies
        .into_iter()
        .map(|b| serde_json::from_slice::<Value>(b).map_err(|_| RebuildError::Malformed));
    let mut issue = pages.next().ok_or(RebuildError::Malformed)??;
    let mut first = pages.next().ok_or(RebuildError::Malformed)??;
    let mut comments = match first.get_mut("comments").map(Value::take) {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    };
    for page in pages {
        if let Some(Value::Array(a)) = page?.get_mut("comments").map(Value::take) {
            comments.extend(a);
        }
    }
    let mut mirror = Vec::new();
    for c in &mut comments {
        let Some(c) = c.as_object_mut() else { continue };
        let body = c.remove("renderedBody").unwrap_or(Value::Null);
        if rendered {
            let mut entry = Map::new();
            entry.insert("id".into(), c.get("id").cloned().unwrap_or(Value::Null));
            entry.insert("body".into(), body);
            mirror.push(Value::Object(entry));
        }
    }
    let mut comment = Map::new();
    for key in ["startAt", "maxResults", "total"] {
        if let Some(v) = first.get_mut(key).map(Value::take) {
            comment.insert(key.into(), v);
        }
    }
    comment.insert("comments".into(), Value::Array(comments));
    let root = issue.as_object_mut().ok_or(RebuildError::Malformed)?;
    object_at(root, "fields")
        .ok_or(RebuildError::Malformed)?
        .insert("comment".into(), Value::Object(comment));
    if rendered {
        let mut rendered_comment = Map::new();
        rendered_comment.insert("comments".into(), Value::Array(mirror));
        object_at(root, "renderedFields")
            .ok_or(RebuildError::Malformed)?
            .insert("comment".into(), Value::Object(rendered_comment));
    }
    Ok(issue)
}

/// The object under `key`, made an (empty) object first when it is absent or not one.
fn object_at<'m>(map: &'m mut Map<String, Value>, key: &str) -> Option<&'m mut Map<String, Value>> {
    let slot = map.entry(key.to_owned()).or_insert(Value::Null);
    if !slot.is_object() {
        *slot = Value::Object(Map::new());
    }
    slot.as_object_mut()
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
pub(super) fn result_body<'a>(
    spec: &OperationSpec,
    bodies: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(Value, u64), RebuildError> {
    let mut pages = bodies
        .into_iter()
        .map(|b| serde_json::from_slice::<Value>(b).map_err(|_| RebuildError::Malformed));
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
fn error_candidate(status: u16, body: &[u8]) -> Value {
    json!({ "status": status, "error_messages": error_text(body) })
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
                    comments_truncated: read.comments_truncated,
                }),
                field_names: cx.field_names.as_deref(),
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
            let mut text = escape_for_display(text);
            if comment_page_failed(cx, read) {
                text = format!("{COMMENT_PAGE_NOTE}\n{text}");
            }
            card(
                cx,
                value,
                byte_size,
                PreviewBody::upstream_error(status, &text),
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

/// plan text (T10): leads the error text when a comment page of `jira.issue.get --comments`
/// failed, since a 404 there reads as "issue not found". Card-only (T10 review M-3): the
/// released candidate, and so the agent, carries Jira's own `{status, error_messages}` alone.
const COMMENT_PAGE_NOTE: &str =
    "the failing request was the issue's comment list, not the issue itself";

/// An upstream error of the composite read (PD-45) that is not the issue's own answer: the
/// issue GET is the first response and was 2xx, so a record of two or more responses ended on a
/// comment page.
fn comment_page_failed(cx: &ReadContext<'_>, read: &ReadState) -> bool {
    cx.spec.id == "jira.issue.get" && jira::wants_comments(cx.params) && read.pages >= 2
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
            release_blocked: None,
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

    /// PD-45 edge shapes: a comment without `renderedBody` keeps its mirror entry (`body: null`),
    /// missing or non-object `fields`/`renderedFields` are made objects, the issue's own
    /// `fields.comment` is replaced, and anything but an issue object plus a comment page is
    /// `Malformed`.
    #[test]
    fn merge_comments_edge_shapes() -> TestResult {
        let issue = br#"{"key":"ABC-1","renderedFields":null}"#;
        let page = br#"{"startAt":0,"maxResults":50,"total":2,"comments":[{"id":"1","body":"a","renderedBody":"<p>a</p>"},{"id":"2","body":"b"}],"extra":true}"#;
        let merged = merge_comments([&issue[..], &page[..]], true).map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            merged["fields"]["comment"],
            json!({"startAt": 0, "maxResults": 50, "total": 2,
                   "comments": [{"id": "1", "body": "a"}, {"id": "2", "body": "b"}]})
        );
        assert_eq!(
            merged["renderedFields"],
            json!({"comment": {"comments": [{"id": "1", "body": "<p>a</p>"}, {"id": "2", "body": null}]}})
        );
        // Unrendered: no mirror is built, `renderedBody` still never reaches the field side.
        let replaced = br#"{"key":"ABC-1","fields":{"comment":{"comments":[{"id":"9"}]}}}"#;
        let merged =
            merge_comments([&replaced[..], &page[..]], false).map_err(|e| format!("{e:?}"))?;
        assert!(merged.get("renderedFields").is_none());
        assert_eq!(
            merged["fields"]["comment"]["comments"][0],
            json!({"id": "1", "body": "a"})
        );
        assert_eq!(merged["fields"]["comment"]["total"], 2);
        assert!(matches!(
            merge_comments([&issue[..]], false),
            Err(RebuildError::Malformed)
        ));
        assert!(matches!(
            merge_comments([&b"[1]"[..], &page[..]], false),
            Err(RebuildError::Malformed)
        ));
        Ok(())
    }

    /// The composite's truncation fact needs all three: more pages exist (`next_start`), and
    /// fewer comments than the server's total were fetched. The pager never ends with `Some`
    /// and `items_fetched >= total`, so the second conjunct is pinned here, on a crafted outcome.
    #[test]
    fn composite_truncated_needs_more_pages_and_a_short_count() -> TestResult {
        let truncated = |next_start, items_fetched, server_total| -> Result<_, String> {
            let outcome = PagedOutcome {
                pages: vec![answer(200, "application/json")],
                items_fetched,
                end: PageEnd::MaxReached,
                failure: None,
                next_start,
                server_total,
            };
            match classify_read(Fetched::Composite { outcome }, &direct_proxy()) {
                Classified::Item(rec) => Ok(rec.comments_truncated),
                _ => Err("not an item".to_owned()),
            }
        };
        assert_eq!(truncated(Some(100), 100, Some(250))?, Some((100, 250)));
        assert_eq!(truncated(None, 100, Some(250))?, None);
        assert_eq!(truncated(Some(100), 100, Some(100))?, None);
        assert_eq!(truncated(Some(100), 100, Some(40))?, None);
        assert_eq!(truncated(Some(100), 100, None)?, None);
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
