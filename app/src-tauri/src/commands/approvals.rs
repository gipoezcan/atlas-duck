//! The Approvals window's commands (C.10 + Δ1, §5.6). M6 T10: `preview_fetch`, T11: `raw_page`,
//! T12: the rest. Each command is a thin `#[tauri::command]` (`core()`, the blocking pool,
//! `finish`) over a pure function of `&dyn DecisionApi` that the tests drive directly: core
//! decides, this layer only maps the wire types and never decides anything itself.

use atlas_duck_core::{
    BatchOutcome, CandidateRev, Decision, DecisionApi, DecisionOutcome, QueueItem, RecentItem,
    RedactionContext, RedactionReport, RequestDetail,
};
use atlas_duck_preview::render::raw::incomplete_tail;
use atlas_duck_preview::{Platform, Preview, render};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime};

use super::dto::{
    Args, BatchItems, CandidateRevDto, DecisionDto, DenyDetailsDto, EditsDto, PreviewOpsDto,
    Reason, RedactionOpWire, RedactionOpsDto, RequestId, RequestIds, SessionId,
};
use super::{CommandError, blocking, core, finish};

/// Runs `f` over the serving core's `DecisionApi` on the blocking pool (M3 PD-13) and records the
/// response (S-16). `NotReady` without a serving core.
async fn with_decisions<R, T, F>(app: &AppHandle<R>, f: F) -> Result<T, CommandError>
where
    R: Runtime,
    T: Serialize + Send + 'static,
    F: FnOnce(&dyn DecisionApi) -> Result<T, CommandError> + Send + 'static,
{
    let response = match core(app) {
        Ok(core) => {
            let decisions = core.decisions();
            blocking(move || f(&*decisions)).await
        }
        Err(e) => Err(e),
    };
    finish(app, response)
}

/// `queue_list {}` (C.10): the queue rows, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueListArgs {}

#[tauri::command]
pub async fn queue_list<R: Runtime>(
    app: AppHandle<R>,
    args: Args<QueueListArgs>,
) -> Result<Vec<QueueItem>, CommandError> {
    let Args(QueueListArgs {}) = args;
    with_decisions(&app, |d| Ok(d.queue_list())).await
}

/// `queue_get {request_id}` (C.10): one row; `not_found` once it left the queue.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueGetArgs {
    pub request_id: RequestId,
}

pub fn queue_get_dto(d: &dyn DecisionApi, request_id: &str) -> Result<QueueItem, CommandError> {
    d.queue_get(request_id).ok_or(CommandError::NotFound)
}

/// What `queue_get` returns (T14): the queue row and the Request tab's facts (params, hash,
/// reason, connection). `queue_list` rows stay light and carry no `request`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct QueueDetail {
    pub item: QueueItem,
    pub request: RequestDetail,
}

pub fn queue_detail_dto(
    d: &dyn DecisionApi,
    request_id: &str,
) -> Result<QueueDetail, CommandError> {
    let item = queue_get_dto(d, request_id)?;
    let request = d.request_detail(request_id).ok_or(CommandError::NotFound)?;
    Ok(QueueDetail { item, request })
}

#[tauri::command]
pub async fn queue_get<R: Runtime>(
    app: AppHandle<R>,
    args: Args<QueueGetArgs>,
) -> Result<QueueDetail, CommandError> {
    let Args(QueueGetArgs { request_id }) = args;
    with_decisions(&app, move |d| queue_detail_dto(d, request_id.as_str())).await
}

/// `decide {request_id, decision, candidate_rev, edits?, redactions?, reason?, deny_details?}`
/// (C.10, PD-20, PD-66): one decision on the revision the approver saw. Which combinations make
/// sense (a release of a write, an approve of an unopened revision, an edit of a target) is
/// core's call and its refusals pass through unchanged.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideArgs {
    pub request_id: RequestId,
    pub decision: DecisionDto,
    pub candidate_rev: CandidateRevDto,
    pub edits: Option<EditsDto>,
    pub redactions: Option<RedactionOpsDto>,
    pub reason: Option<Reason>,
    pub deny_details: Option<DenyDetailsDto>,
}

impl DecideArgs {
    /// The core decision, field for field.
    pub fn into_decision(self) -> Decision {
        Decision {
            request_id: self.request_id.into_inner(),
            decision: self.decision.0,
            candidate_rev: self.candidate_rev.0,
            edits: self.edits.map(|e| e.0),
            redactions: self.redactions.map(|r| r.0),
            reason: self.reason.map(Reason::into_inner),
            deny_details: self.deny_details.map(|d| d.0),
        }
    }
}

pub fn decide_dto(d: &dyn DecisionApi, args: DecideArgs) -> Result<DecisionOutcome, CommandError> {
    Ok(d.decide(args.into_decision())?)
}

#[tauri::command]
pub async fn decide<R: Runtime>(
    app: AppHandle<R>,
    args: Args<DecideArgs>,
) -> Result<DecisionOutcome, CommandError> {
    let Args(args) = args;
    with_decisions(&app, move |d| decide_dto(d, args)).await
}

/// `decide_batch {items}` (C.10, L43): the natural positive decision of each item, all or
/// nothing; core confirms in its own native dialog (U-32).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideBatchArgs {
    pub items: BatchItems,
}

pub fn decide_batch_dto(
    d: &dyn DecisionApi,
    items: BatchItems,
) -> Result<BatchOutcome, CommandError> {
    Ok(d.decide_batch(items.0)?)
}

#[tauri::command]
pub async fn decide_batch<R: Runtime>(
    app: AppHandle<R>,
    args: Args<DecideBatchArgs>,
) -> Result<BatchOutcome, CommandError> {
    let Args(DecideBatchArgs { items }) = args;
    with_decisions(&app, move |d| decide_batch_dto(d, items)).await
}

/// How many items a batch deny denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DenyCount {
    pub denied: u64,
}

fn deny_count(n: usize) -> DenyCount {
    DenyCount {
        denied: u64::try_from(n).unwrap_or(u64::MAX),
    }
}

/// `deny_batch {request_ids, reason}` (Δ1, L43): no dialog, per item, not all-or-nothing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyBatchArgs {
    pub request_ids: RequestIds,
    pub reason: Reason,
}

pub fn deny_batch_dto(
    d: &dyn DecisionApi,
    request_ids: &RequestIds,
    reason: &Reason,
) -> Result<DenyCount, CommandError> {
    Ok(deny_count(
        d.deny_batch(request_ids.as_slice(), reason.as_str())?,
    ))
}

#[tauri::command]
pub async fn deny_batch<R: Runtime>(
    app: AppHandle<R>,
    args: Args<DenyBatchArgs>,
) -> Result<DenyCount, CommandError> {
    let Args(DenyBatchArgs {
        request_ids,
        reason,
    }) = args;
    with_decisions(&app, move |d| deny_batch_dto(d, &request_ids, &reason)).await
}

/// `deny_session {session_id, reason}` (Δ1, PD-86): denies the queued items of one session.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenySessionArgs {
    pub session_id: SessionId,
    pub reason: Reason,
}

/// The session key behind `session_id` is found in the queue here, in Rust; no path crosses the
/// webview boundary. An id no queued item carries is `not_found` and denies nothing.
pub fn deny_session_dto(
    d: &dyn DecisionApi,
    session_id: &SessionId,
    reason: &Reason,
) -> Result<DenyCount, CommandError> {
    let session = d
        .queue_list()
        .into_iter()
        .find(|item| item.session_id == session_id.as_str())
        .map(|item| item.session)
        .ok_or(CommandError::NotFound)?;
    Ok(deny_count(d.deny_session(session, reason.as_str())?))
}

#[tauri::command]
pub async fn deny_session<R: Runtime>(
    app: AppHandle<R>,
    args: Args<DenySessionArgs>,
) -> Result<DenyCount, CommandError> {
    let Args(DenySessionArgs { session_id, reason }) = args;
    with_decisions(&app, move |d| deny_session_dto(d, &session_id, &reason)).await
}

/// `acknowledge_attention {request_ids}` (C.10): in memory, not audited.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeAttentionArgs {
    pub request_ids: RequestIds,
}

#[tauri::command]
pub async fn acknowledge_attention<R: Runtime>(
    app: AppHandle<R>,
    args: Args<AcknowledgeAttentionArgs>,
) -> Result<(), CommandError> {
    let Args(AcknowledgeAttentionArgs { request_ids }) = args;
    with_decisions(&app, move |d| {
        d.acknowledge_attention(request_ids.as_slice());
        Ok(())
    })
    .await
}

/// `recent_list {}` (Δ1): the "Recently decided (24 h) / Needs attention" rows.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentListArgs {}

#[tauri::command]
pub async fn recent_list<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RecentListArgs>,
) -> Result<Vec<RecentItem>, CommandError> {
    let Args(RecentListArgs {}) = args;
    with_decisions(&app, |d| Ok(d.recent())).await
}

/// `redaction_preview {request_id, candidate_rev, ops}` (Δ1, Δ2): what `ops` would do to an
/// opened revision; UI-only, nothing is logged.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionPreviewArgs {
    pub request_id: RequestId,
    pub candidate_rev: CandidateRevDto,
    pub ops: PreviewOpsDto,
}

pub fn redaction_preview_dto(
    d: &dyn DecisionApi,
    args: &RedactionPreviewArgs,
) -> Result<RedactionReport, CommandError> {
    Ok(d.redaction_preview(args.request_id.as_str(), args.candidate_rev.0, &args.ops.0)?)
}

#[tauri::command]
pub async fn redaction_preview<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RedactionPreviewArgs>,
) -> Result<RedactionReport, CommandError> {
    let Args(args) = args;
    with_decisions(&app, move |d| redaction_preview_dto(d, &args)).await
}

/// `preview_fetch {request_id, candidate_rev?}` (Δ1). Without `candidate_rev` the current
/// revision is shown (a missing `Option` field is `None`; no `#[serde(default)]` around a bounded
/// newtype, `check-commands`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewFetchArgs {
    pub request_id: RequestId,
    pub candidate_rev: Option<CandidateRevDto>,
}

/// `{preview, srcdoc, redaction}` (Δ1, PD-67; `redaction` M6 T17): the preview model for the
/// Structured/Raw/Request tabs, the Rust-rendered document the UI sets as the `srcDoc` of the
/// `<iframe sandbox="">`, and what the redaction panel builds on (`null` for a write or a read
/// outcome item).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewFetchResponse {
    pub preview: Preview,
    pub srcdoc: String,
    pub redaction: Option<RedactionContextDto>,
}

/// `RedactionContext` with its ops in the wire form the UI sends back (`RedactionOpWire`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedactionContextDto {
    pub ops: Vec<RedactionOpWire>,
    pub url_fields: Vec<&'static str>,
}

impl From<&RedactionContext> for RedactionContextDto {
    fn from(c: &RedactionContext) -> Self {
        RedactionContextDto {
            ops: c.ops.iter().map(RedactionOpWire::from).collect(),
            url_fields: c.url_fields.clone(),
        }
    }
}

/// What `preview_fetch` does over a `DecisionApi`: core commits `PREVIEW_SHOWN` before it returns
/// the preview (§5.6 "Opened"); the document is rendered from that same preview.
pub fn preview_fetch_dto(
    decisions: &dyn DecisionApi,
    request_id: &str,
    rev: Option<CandidateRev>,
) -> Result<PreviewFetchResponse, CommandError> {
    let delivery = decisions
        .preview_fetch(request_id, rev)
        .map_err(CommandError::from_candidate_read)?;
    let srcdoc = render::document(&delivery.preview, Platform::current());
    Ok(PreviewFetchResponse {
        redaction: delivery.redaction.as_ref().map(RedactionContextDto::from),
        preview: delivery.preview,
        srcdoc,
    })
}

/// `preview_fetch` (§5.6 "Opened"): on the blocking pool as well (a large candidate takes a
/// while to render).
#[tauri::command]
pub async fn preview_fetch<R: Runtime>(
    app: AppHandle<R>,
    args: Args<PreviewFetchArgs>,
) -> Result<PreviewFetchResponse, CommandError> {
    let Args(PreviewFetchArgs {
        request_id,
        candidate_rev,
    }) = args;
    with_decisions(&app, move |d| {
        preview_fetch_dto(d, request_id.as_str(), candidate_rev.map(|r| r.0))
    })
    .await
}

/// `raw_page {request_id, candidate_rev, page}` (Δ1, PD-68): the page of an opened revision.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPageArgs {
    pub request_id: RequestId,
    pub candidate_rev: CandidateRevDto,
    pub page: u64,
}

/// `{page, page_count, total_bytes, bytes_b64, display}` (PD-68): the exact slice of the hashed
/// candidate bytes as base64 (for the copy gesture and X-07 only) and the text the UI shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawPageDto {
    pub page: u64,
    pub page_count: u64,
    pub total_bytes: u64,
    pub bytes_b64: String,
    pub display: String,
}

/// One Raw page through `decisions` (PD-68): refused like core refuses it (`NotDecidable`,
/// `Stale`, `Invalid(NotOpened)`), a page past the last is `InvalidArgument {page}`. The UTF-8
/// carry into the page is derived here from the bytes of the page before it, never taken from the
/// UI; the last page shows an incomplete tail as bytes.
pub fn raw_page_dto(
    decisions: &dyn DecisionApi,
    request_id: &str,
    rev: CandidateRev,
    page: u64,
) -> Result<RawPageDto, CommandError> {
    let current = decisions
        .raw_page(request_id, rev, page)
        .map_err(CommandError::from_candidate_read)?;
    if page >= current.page_count {
        return Err(CommandError::InvalidArgument { field: "page" });
    }
    let carry = match page.checked_sub(1) {
        Some(before) => {
            let previous = decisions
                .raw_page(request_id, rev, before)
                .map_err(CommandError::from_candidate_read)?;
            incomplete_tail(&previous.bytes).to_vec()
        }
        None => Vec::new(),
    };
    let display = if page + 1 == current.page_count {
        render::raw_display_last(&current.bytes, &carry)
    } else {
        render::raw_display(&current.bytes, &carry)
    };
    Ok(RawPageDto {
        page: current.page,
        page_count: current.page_count,
        total_bytes: current.total_bytes,
        bytes_b64: base64::engine::general_purpose::STANDARD.encode(&current.bytes),
        display: display.text,
    })
}

/// `raw_page` (PD-68): on the blocking pool (a 256 KiB slice, twice, and the projection).
#[tauri::command]
pub async fn raw_page<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RawPageArgs>,
) -> Result<RawPageDto, CommandError> {
    let Args(RawPageArgs {
        request_id,
        candidate_rev,
        page,
    }) = args;
    with_decisions(&app, move |d| {
        raw_page_dto(d, request_id.as_str(), candidate_rev.0, page)
    })
    .await
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::commands::dto::{FIELD_PAYLOAD, parse};

    const HASH: &str = "abababababababababababababababababababababababababababababababab";

    #[test]
    fn raw_page_args_need_an_id_a_revision_and_a_page() {
        let id = format!("req_{}", "a".repeat(24));
        let rev = json!({"counter": 3, "candidate_hash": HASH});
        let ok = parse::<RawPageArgs>(&json!({"request_id": id, "candidate_rev": rev, "page": 2}));
        assert!(
            matches!(&ok, Ok(a) if a.page == 2 && a.candidate_rev.0.counter == 3),
            "{ok:?}"
        );
        for (body, field) in [
            (json!({"request_id": id, "page": 0}), "candidate_rev"),
            (
                json!({"request_id": id, "candidate_rev": rev}),
                FIELD_PAYLOAD,
            ),
            (
                json!({"request_id": id, "candidate_rev": rev, "page": -1}),
                FIELD_PAYLOAD,
            ),
            (
                json!({"request_id": id, "candidate_rev": rev, "page": "1"}),
                FIELD_PAYLOAD,
            ),
            (
                json!({"request_id": id, "candidate_rev": rev, "page": 0, "carry": ""}),
                FIELD_PAYLOAD,
            ),
            (
                json!({"request_id": "x", "candidate_rev": rev, "page": 0}),
                "request_id",
            ),
            (
                json!({"request_id": id, "candidate_rev": {"counter": 1}, "page": 0}),
                "candidate_rev",
            ),
        ] {
            assert_eq!(
                parse::<RawPageArgs>(&body),
                Err(CommandError::InvalidArgument { field }),
                "{body}"
            );
        }
    }

    #[test]
    fn preview_fetch_args_take_an_id_and_an_optional_revision() {
        let id = format!("req_{}", "a".repeat(24));
        let bare = parse::<PreviewFetchArgs>(&json!({ "request_id": id }));
        assert!(
            matches!(&bare, Ok(a) if a.candidate_rev.is_none()),
            "{bare:?}"
        );
        let null = parse::<PreviewFetchArgs>(&json!({ "request_id": id, "candidate_rev": null }));
        assert!(
            matches!(&null, Ok(a) if a.candidate_rev.is_none()),
            "{null:?}"
        );
        let rev = json!({"counter": 3, "candidate_hash": HASH});
        let with = parse::<PreviewFetchArgs>(&json!({ "request_id": id, "candidate_rev": rev }));
        assert!(
            matches!(&with, Ok(a) if a.candidate_rev.is_some_and(|r| r.0.counter == 3)),
            "{with:?}"
        );
        for (body, field) in [
            (json!({}), "request_id"),
            (json!({"request_id": "req_short"}), "request_id"),
            (
                json!({"request_id": id, "candidate_rev": {"counter": 1}}),
                "candidate_rev",
            ),
            (json!({"request_id": id, "page": 1}), FIELD_PAYLOAD),
            (json!([id]), FIELD_PAYLOAD),
        ] {
            assert_eq!(
                parse::<PreviewFetchArgs>(&body),
                Err(CommandError::InvalidArgument { field }),
                "{body}"
            );
        }
    }
}
