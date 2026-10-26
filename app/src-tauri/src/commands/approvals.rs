//! The Approvals window's commands (C.10 + Δ1, §5.6). M6 T10: `preview_fetch`, T11: `raw_page`,
//! T12: the rest. Each command is a thin `#[tauri::command]` (`core()`, the blocking pool,
//! `finish`) over a pure function of `&dyn DecisionApi` that the tests drive directly: core
//! decides, this layer only maps the wire types and never decides anything itself.

use atlas_duck_core::{
    BatchOutcome, CandidateRev, DecisionApi, DecisionOutcome, QueueItem, RecentItem,
    RedactionReport,
};
use serde::Serialize;
use tauri::{AppHandle, Runtime};

use super::dto::{Args, BatchItems, Reason, RequestIds, SessionId};
use super::{CommandError, blocking, core, finish};

// The argument structs and response DTOs live in core (M12 PD-206), shared with the server.
pub use atlas_duck_core::decision::wire::{
    AcknowledgeAttentionArgs, DecideArgs, DecideBatchArgs, DenyBatchArgs, DenyCount,
    DenySessionArgs, PreviewFetchArgs, PreviewFetchResponse, QueueDetail, QueueGetArgs,
    QueueListArgs, RawPageArgs, RawPageDto, RecentListArgs, RedactionContextDto,
    RedactionPreviewArgs, preview_fetch_response,
};
use atlas_duck_core::decision::wire::{RawPageError, raw_page_response};

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
#[tauri::command]
pub async fn queue_list<R: Runtime>(
    app: AppHandle<R>,
    args: Args<QueueListArgs>,
) -> Result<Vec<QueueItem>, CommandError> {
    let Args(QueueListArgs {}) = args;
    with_decisions(&app, |d| Ok(d.queue_list())).await
}

/// `queue_get {request_id}` (C.10): one row; `not_found` once it left the queue.
pub fn queue_get_dto(d: &dyn DecisionApi, request_id: &str) -> Result<QueueItem, CommandError> {
    d.queue_get(request_id).ok_or(CommandError::NotFound)
}

/// What `queue_get` returns (T14): the queue row and the Request tab's facts.
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

fn deny_count(n: usize) -> DenyCount {
    DenyCount::of(n)
}

/// `deny_batch {request_ids, reason}` (Δ1, L43): no dialog, per item, not all-or-nothing.
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
    Ok(preview_fetch_response(delivery))
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

/// `raw_page {request_id, candidate_rev, page}` (Δ1, PD-68): one Raw page through `decisions`
/// (core's `raw_page_response`, shared with the server): refused like core refuses it
/// (`NotDecidable`, `Stale`, `Invalid(NotOpened)`), a page past the last is
/// `InvalidArgument {page}`.
pub fn raw_page_dto(
    decisions: &dyn DecisionApi,
    request_id: &str,
    rev: CandidateRev,
    page: u64,
) -> Result<RawPageDto, CommandError> {
    raw_page_response(decisions, request_id, rev, page).map_err(|e| match e {
        RawPageError::Decision(e) => CommandError::from_candidate_read(e),
        RawPageError::PageOutOfRange => CommandError::InvalidArgument { field: "page" },
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
