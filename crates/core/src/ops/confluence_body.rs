//! The storage body of a Confluence write (§7.6, PD-94, PD-97, PD-98): `body` of
//! `confluence.page.update` (and, from Tasks 16/18, `page.create` and `comment.add`). With
//! `body_format: storage` the agent's storage is checked fail-closed and sent verbatim; otherwise
//! (Markdown, also when `body_format` is absent) the placeholder check runs first (§5.4 step 1),
//! then the conversion and the storage hard check. All of it runs in the executor, so the
//! validation dry call (handler step 8) rejects a failure with `REQUEST_REJECTED`, exit 2, before
//! any enrichment GET; every later render converts the same params to the same bytes, and the
//! storage sent is exactly the storage checked. Every check depends on the params only (§2.3).

use atlas_duck_convert::storage::MAX_DEPTH;
use atlas_duck_convert::{
    ConstructKind, PlaceholderHit, StorageReject, Unrecorded, check_markdown_placeholders,
    check_storage_body, hard_check_storage, markdown_to_storage,
};
use atlas_duck_ipc::envelope::ErrorCode;
use serde_json::{Map, Value, json};

use super::jira_body::{EMPTY_MESSAGE, unrecorded};
use super::{ExecCtx, ExecError, str_param};
use crate::validate::{ValidationError, invalid};

/// The body param of every Confluence write that carries one.
const BODY: &str = "body";

/// §7.6 (verbatim): the hint of a Markdown body that still holds `page get` placeholders.
pub const PLACEHOLDER_HINT: &str = "fetch with `--format storage` and submit `body_format=storage`";

/// plan text (T4 review m-6, T9 review I-1, lead ruling): appended to [`PLACEHOLDER_HINT`], so an agent whose
/// genuine prose matched the grammar knows the CommonMark escapes that keep it as text (PD-98).
pub const PLACEHOLDER_ESCAPE_GUIDANCE: &str = "To keep such text as prose, escape it: `\\@` before `@user:`, `\\[` before `[macro:` and before the `[` of a `confluence:` link or image, `\\<` before a `confluence:` autolink.";

/// plan text (PD-94): the message of a refused `body_format=storage` body, followed by the
/// reason (`StorageReject::as_str`).
pub const STORAGE_REJECTED_MESSAGE: &str = "storage body rejected:";

/// plan text (T6 review, T9 review m-2): the converted Markdown nests deeper than atlas-duck's
/// storage parser reads, so the hard check failed closed on the agent's structure, not on a
/// converter fault. The bound counts storage elements, not Markdown levels: a list level is
/// `<ul><li>`, two elements.
pub fn too_deep_message() -> String {
    format!(
        "the Markdown nests too deeply: its storage would nest more than {MAX_DEPTH} elements \
         deep, atlas-duck's parser limit (a nested list level takes two elements, so about \
         half as many levels)"
    )
}

/// Whether a Markdown body that converts to nothing is refused (`validation`, [`EMPTY_MESSAGE`]).
/// A page may be written empty; a comment may not (Task 18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmptyBody {
    Allow,
    #[allow(dead_code)] // `confluence.comment.add` (Task 18)
    Refuse,
}

/// Whether `body` is Markdown: every `body_format` but `storage`, and none (§7.6: the default).
pub(crate) fn is_markdown(params: &Value) -> bool {
    params.get("body_format").and_then(Value::as_str) != Some("storage")
}

/// The storage to send for `body`: verbatim after [`check_storage_body`] for
/// `body_format: storage`; otherwise the Markdown converted, after the placeholder check and the
/// storage hard check passed.
pub(crate) fn storage_text(ctx: &ExecCtx<'_>, empty: EmptyBody) -> Result<String, ExecError> {
    let text = str_param(ctx.params, BODY);
    if !is_markdown(ctx.params) {
        check_storage_body(text).map_err(|r| ExecError::Invalid(storage_rejected(r)))?;
        return Ok(text.to_owned());
    }
    check_markdown_placeholders(text).map_err(|hits| ExecError::Invalid(placeholders(&hits)))?;
    let (storage, emitted) = markdown_to_storage(text);
    if empty == EmptyBody::Refuse && storage.trim().is_empty() {
        return Err(ExecError::Invalid(invalid(BODY, EMPTY_MESSAGE, None)));
    }
    #[cfg(feature = "testing")]
    let storage = match ctx.test_fault {
        Some(fault) => fault.apply(ctx.spec.product, &storage),
        None => storage,
    };
    hard_check_storage(&storage, &emitted)
        .map_err(|e| ExecError::Invalid(hard_check_failed(&storage, e)))?;
    Ok(storage)
}

/// `validation`, `details {param, storage}`: the reason, never the body.
fn storage_rejected(reason: StorageReject) -> ValidationError {
    let mut details = Map::new();
    details.insert("param".to_owned(), Value::from(BODY));
    details.insert("storage".to_owned(), Value::from(reason.as_str()));
    ValidationError {
        code: ErrorCode::Validation,
        message: format!("{STORAGE_REJECTED_MESSAGE} {}", reason.as_str()),
        details,
    }
}

/// `markdown_placeholders`, `details {placeholders: [{kind, count}]}` (§4.3, §7.6): the kinds in
/// the check's order (link, image, macro, user), never the text.
fn placeholders(hits: &[PlaceholderHit]) -> ValidationError {
    let list: Vec<Value> = hits
        .iter()
        .map(|h| json!({"kind": h.kind.as_str(), "count": h.count}))
        .collect();
    let mut details = Map::new();
    details.insert("placeholders".to_owned(), Value::Array(list));
    ValidationError {
        code: ErrorCode::MarkdownPlaceholders,
        message: format!("{PLACEHOLDER_HINT}. {PLACEHOLDER_ESCAPE_GUIDANCE}"),
        details,
    }
}

/// A failed hard check (PD-97). It fails closed with `Markup` (count 1) when the re-parse of the
/// output is not `xml_ok`; the only such cause agent Markdown can reach is nesting deeper than the
/// parser's 64 levels (the converter escapes every `<` and `&`, replaces what XML forbids and
/// writes no DOCTYPE or PI), so a `TooDeep` re-check names the nesting. Anything else is a
/// converter fault: the kind and the count.
fn hard_check_failed(storage: &str, e: Unrecorded) -> ValidationError {
    let fail_closed = e.kind == ConstructKind::Markup && e.count == 1;
    if fail_closed && check_storage_body(storage) == Err(StorageReject::TooDeep) {
        let mut details = Map::new();
        details.insert("param".to_owned(), Value::from(BODY));
        details.insert(
            "storage".to_owned(),
            Value::from(StorageReject::TooDeep.as_str()),
        );
        return ValidationError {
            code: ErrorCode::Validation,
            message: too_deep_message(),
            details,
        };
    }
    unrecorded(BODY, e)
}

#[cfg(test)]
mod tests {
    use atlas_duck_atlassian::normalize_base_url;

    use super::*;

    /// `storage_text` of `body` (with `body_format` when given) as `page.update` params.
    fn run(
        body: &str,
        format: Option<&str>,
        empty: EmptyBody,
    ) -> Result<Result<String, ExecError>, String> {
        let spec = atlas_duck_registry::get("confluence.page.update").ok_or("no op")?;
        let base =
            normalize_base_url("https://wiki.example.invalid/ctx").map_err(|e| e.to_string())?;
        let mut params = json!({ "id": "65537", "base_version": 7, "body": body });
        if let Some(f) = format {
            params["body_format"] = json!(f);
        }
        let ctx = ExecCtx {
            spec,
            params: &params,
            base: &base,
            enrichment: None,
            effective_max: None,
            comments_cap: None,
            #[cfg(feature = "testing")]
            test_fault: None,
        };
        Ok(storage_text(&ctx, empty))
    }

    /// Whitespace-only Markdown converts to nothing: `Allow` sends it, `Refuse` answers with the
    /// static message before any fault could mask it; a verbatim storage body is never checked.
    #[test]
    fn empty_markdown_body_allowed_or_refused() -> Result<(), String> {
        for body in ["", " ", " \n\n "] {
            for format in [None, Some("markdown")] {
                match run(body, format, EmptyBody::Allow)? {
                    Ok(storage) => assert!(storage.trim().is_empty(), "{body:?}"),
                    Err(_) => return Err(format!("Allow refused {body:?}")),
                }
                match run(body, format, EmptyBody::Refuse)? {
                    Err(ExecError::Invalid(e)) => {
                        assert_eq!(e.code, ErrorCode::Validation);
                        assert_eq!(e.message, format!("params/body: {EMPTY_MESSAGE}"));
                        assert_eq!(e.details.get("param"), Some(&json!("body")));
                    }
                    _ => return Err(format!("Refuse did not refuse {body:?}")),
                }
            }
        }
        // Text that converts to something, and verbatim storage, pass in both modes.
        for empty in [EmptyBody::Allow, EmptyBody::Refuse] {
            assert!(matches!(run("hi", None, empty)?, Ok(s) if s == "<p>hi</p>"));
            assert!(matches!(run(" ", Some("storage"), empty)?, Ok(s) if s == " "));
        }
        Ok(())
    }
}
