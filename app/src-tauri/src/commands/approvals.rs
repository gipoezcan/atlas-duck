//! The Approvals window's commands (C.10 + Δ1, §5.6). M6 T10: `preview_fetch`; Task 12 adds the
//! rest.

use atlas_duck_preview::{Platform, Preview, render};
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::commands::dto::{FIELD_PAYLOAD, parse};

    const HASH: &str = "abababababababababababababababababababababababababababababababab";

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
