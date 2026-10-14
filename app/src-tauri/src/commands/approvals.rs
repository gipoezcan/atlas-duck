//! The Approvals window's commands (C.10 + Δ1, §5.6). M6 T10: `preview_fetch`; Task 12 adds the
//! rest.

use atlas_duck_core::{CandidateRev, DecisionApi};
use atlas_duck_preview::render::raw::incomplete_tail;
use atlas_duck_preview::{Platform, Preview, render};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime};

use super::dto::{Args, CandidateRevDto, RequestId};
use super::{CommandError, blocking, core, finish};

/// `preview_fetch {request_id, candidate_rev?}` (Δ1). Without `candidate_rev` the current
/// revision is shown (a missing `Option` field is `None`; no `#[serde(default)]` around a bounded
/// newtype, `check-commands`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewFetchArgs {
    pub request_id: RequestId,
    pub candidate_rev: Option<CandidateRevDto>,
}

/// `{preview, srcdoc}` (Δ1, PD-67): the preview model for the Structured/Raw/Request tabs and the
/// Rust-rendered document the UI sets as the `srcDoc` of the `<iframe sandbox="">`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewFetchResponse {
    pub preview: Preview,
    pub srcdoc: String,
}

/// `preview_fetch` (§5.6 "Opened"): core commits `PREVIEW_SHOWN` before it returns the preview;
/// the document is rendered on the blocking pool as well (a large candidate takes a while).
#[tauri::command]
pub async fn preview_fetch<R: Runtime>(
    app: AppHandle<R>,
    args: Args<PreviewFetchArgs>,
) -> Result<PreviewFetchResponse, CommandError> {
    let Args(PreviewFetchArgs {
        request_id,
        candidate_rev,
    }) = args;
    let response = match core(&app) {
        Ok(core) => {
            let decisions = core.decisions();
            blocking(move || {
                let preview = decisions
                    .preview_fetch(request_id.as_str(), candidate_rev.map(|r| r.0))?
                    .preview;
                let srcdoc = render::document(&preview, Platform::current());
                Ok(PreviewFetchResponse { preview, srcdoc })
            })
            .await
        }
        Err(e) => Err(e),
    };
    finish(&app, response)
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
    let current = decisions.raw_page(request_id, rev, page)?;
    if page >= current.page_count {
        return Err(CommandError::InvalidArgument { field: "page" });
    }
    let carry = match page.checked_sub(1) {
        Some(before) => {
            let previous = decisions.raw_page(request_id, rev, before)?;
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
    let response = match core(&app) {
        Ok(core) => {
            let decisions = core.decisions();
            blocking(move || raw_page_dto(&*decisions, request_id.as_str(), candidate_rev.0, page))
                .await
        }
        Err(e) => Err(e),
    };
    finish(&app, response)
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
