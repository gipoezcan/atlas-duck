//! The wiki text of a Jira body param (PD-42, PD-43, §7.6): `description` of
//! `jira.issue.create` and `body` of `jira.comment.add`, the two params whose op declares
//! `body_format`. Markdown (the default) is converted and re-parsed by the hard check in the
//! executor, so the validation dry call (handler step 8) rejects an unrecorded construct with
//! `REQUEST_REJECTED`, exit 2, before any enrichment GET. Every later render converts the same
//! params to the same bytes, and the text sent is exactly the text checked.

use atlas_duck_convert::{Unrecorded, hard_check_wiki, markdown_to_wiki};
use atlas_duck_ipc::envelope::ErrorCode;
use serde_json::{Map, Value};

use super::{ExecCtx, ExecError};
use crate::validate::{ValidationError, invalid};

/// plan text (PD-43): the message of a failed hard check, followed by the construct kind.
pub const UNRECORDED_MESSAGE: &str = "markdown conversion produced an unrecorded";
/// plan text (T7 review M-4): Markdown with nothing but whitespace converts to `"\n"`, which Jira
/// refuses (400) only after a human approved the write.
pub const EMPTY_MESSAGE: &str = "is empty after markdown conversion";

/// `None` when `param` is absent; with `body_format: wiki` the text verbatim; otherwise (Markdown,
/// also when `body_format` is absent) the converted text, after the hard check passed. Converted
/// text that is only whitespace is refused (`validation`, the param and the fixed message).
pub(crate) fn wiki_text(ctx: &ExecCtx<'_>, param: &str) -> Result<Option<String>, ExecError> {
    let Some(text) = ctx.params.get(param).and_then(Value::as_str) else {
        return Ok(None);
    };
    if ctx.params.get("body_format").and_then(Value::as_str) == Some("wiki") {
        return Ok(Some(text.to_owned()));
    }
    let (wiki, emitted) = markdown_to_wiki(text);
    if wiki.trim().is_empty() {
        return Err(ExecError::Invalid(invalid(param, EMPTY_MESSAGE, None)));
    }
    #[cfg(feature = "testing")]
    let wiki = match ctx.test_fault {
        Some(fault) => fault.apply(ctx.spec.product, &wiki),
        None => wiki,
    };
    hard_check_wiki(&wiki, &emitted).map_err(|e| ExecError::Invalid(unrecorded(param, e)))?;
    Ok(Some(wiki))
}

/// `validation`, `details {param, construct, count}`: the kind and the number, never the text.
/// Also the storage hard check's error (`confluence_body`).
pub(crate) fn unrecorded(param: &str, e: Unrecorded) -> ValidationError {
    let construct = e.kind.as_str();
    let mut details = Map::new();
    details.insert("param".to_owned(), Value::from(param));
    details.insert("construct".to_owned(), Value::from(construct));
    details.insert("count".to_owned(), Value::from(e.count));
    ValidationError {
        code: ErrorCode::Validation,
        message: format!("{UNRECORDED_MESSAGE} {construct}"),
        details,
    }
}
