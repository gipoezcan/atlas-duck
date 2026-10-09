//! Confluence specifics in M3: the `confluence.search` CQL type-filter rewrite (§7.4, part of the
//! static validation of §5.2 step 1) and `confluence.page.update` (PD-09).

use atlas_duck_atlassian::GetCall;
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use serde_json::{Map, Value, json};

use super::{
    EnrichCtx, EnrichPurpose, EnrichRule, EnrichVerdict, ExecCtx, ExecError, ExecPlan, PreviewCtx,
    PreviewModel, generic, get_call, json_request, resolve_url, str_param,
};
use crate::lifecycle::model::Hold;
use crate::validate::{ValidationError, invalid};

/// §7.4: the content types a search may return.
pub const CQL_TYPE_FILTER: &str = "type in (page,blogpost,comment,attachment)";

const CONTENT_PATH: &str = "/rest/api/content/{id}";

// ---- CQL rewrite (§7.4) ------------------------------------------------------------------------

/// A CQL token outside quoted strings. Byte offsets into the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Word {
        start: usize,
        end: usize,
    },
    Open,
    Close,
    /// A quoted string (`'…'`, `"…"`).
    Str,
    Comma,
    /// An operator character (`=`, `!`, `~`, `<`, `>`).
    Op,
}

/// Fixed rejection texts: an error never echoes the CQL (§7.4 "rejected locally").
const MSG_UNTERMINATED: &str = "unterminated quoted string";
const MSG_BACKSLASH: &str = "backslash outside a quoted string";
const MSG_PARENS: &str = "parentheses do not balance";
const MSG_ORDER_BY: &str = "ORDER BY is allowed once, at the end, outside parentheses";
const MSG_EMPTY: &str = "query is empty";

fn cql_error(message: &str) -> ValidationError {
    invalid("cql", message, None)
}

/// Splits `cql` into tokens with their parenthesis depth (before the token). Quoted strings
/// (`'…'`, `"…"`, backslash escapes inside) are opaque. Fails closed on an unterminated string,
/// a backslash outside a string (the server might read the next paren or quote differently) and
/// parentheses that close below depth 0 or stay open.
fn tokenize(cql: &str) -> Result<Vec<(Tok, u32)>, ValidationError> {
    let bytes = cql.as_bytes();
    let mut out = Vec::new();
    let mut depth: u32 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\'' | b'"' => {
                let quote = b;
                let mut j = i + 1;
                loop {
                    match bytes.get(j) {
                        None => return Err(cql_error(MSG_UNTERMINATED)),
                        Some(b'\\') => j += 2,
                        Some(&c) if c == quote => break,
                        Some(_) => j += 1,
                    }
                }
                out.push((Tok::Str, depth));
                i = j + 1;
            }
            b'\\' => return Err(cql_error(MSG_BACKSLASH)),
            b'(' => {
                out.push((Tok::Open, depth));
                depth += 1;
                i += 1;
            }
            b')' => {
                depth = depth.checked_sub(1).ok_or_else(|| cql_error(MSG_PARENS))?;
                out.push((Tok::Close, depth));
                i += 1;
            }
            _ if b.is_ascii_whitespace() => i += 1,
            b',' => {
                out.push((Tok::Comma, depth));
                i += 1;
            }
            b'=' | b'!' | b'~' | b'<' | b'>' => {
                out.push((Tok::Op, depth));
                i += 1;
            }
            _ => {
                let start = i;
                while i < bytes.len()
                    && !bytes[i].is_ascii_whitespace()
                    && !matches!(
                        bytes[i],
                        b'\''
                            | b'"'
                            | b'\\'
                            | b'('
                            | b')'
                            | b'='
                            | b'!'
                            | b'~'
                            | b'<'
                            | b'>'
                            | b','
                    )
                {
                    i += 1;
                }
                out.push((Tok::Word { start, end: i }, depth));
            }
        }
    }
    if depth != 0 {
        return Err(cql_error(MSG_PARENS));
    }
    Ok(out)
}

/// §7.4: `(<rest>) AND type in (page,blogpost,comment,attachment)` followed by the one trailing
/// `ORDER BY …` clause (at depth 0, without parentheses) if there is one. Anything else that
/// could escape the wrapping is a `validation` error with `details {param: "cql"}` and a fixed
/// message (no CQL text).
pub fn effective_cql(cql: &str) -> Result<String, ValidationError> {
    let tokens = tokenize(cql)?;
    let word = |t: &Tok| match *t {
        Tok::Word { start, end } => Some(&cql[start..end]),
        _ => None,
    };
    let order_by: Vec<usize> = tokens
        .windows(2)
        .enumerate()
        .filter(|(_, w)| {
            word(&w[0].0).is_some_and(|s| s.eq_ignore_ascii_case("order"))
                && word(&w[1].0).is_some_and(|s| s.eq_ignore_ascii_case("by"))
        })
        .map(|(i, _)| i)
        .collect();
    let (rest, clause) = match order_by.as_slice() {
        [] => (cql, None),
        [at] => {
            let (Tok::Word { start, .. }, 0) = tokens[*at] else {
                return Err(cql_error(MSG_ORDER_BY));
            };
            if !is_sort_clause(&tokens[*at + 2..], word) {
                return Err(cql_error(MSG_ORDER_BY));
            }
            (&cql[..start], Some(cql[start..].trim_end()))
        }
        _ => return Err(cql_error(MSG_ORDER_BY)),
    };
    let rest = rest.trim();
    if rest.is_empty() {
        return Err(cql_error(MSG_EMPTY));
    }
    Ok(match clause {
        Some(clause) => format!("({rest}) AND {CQL_TYPE_FILTER} {clause}"),
        None => format!("({rest}) AND {CQL_TYPE_FILTER}"),
    })
}

/// The tokens after `ORDER BY`: `key [asc|desc] (, key [asc|desc])*`, a key being a field word or
/// a quoted name. An operator, a parenthesis or an `AND`/`OR`/`NOT` word means WHERE content after
/// the sort clause (a mid-query `ORDER BY`, §7.4): rejected.
fn is_sort_clause<'q>(tokens: &[(Tok, u32)], word: impl Fn(&Tok) -> Option<&'q str>) -> bool {
    #[derive(PartialEq)]
    enum Want {
        Key,
        DirOrComma,
        Comma,
    }
    let mut want = Want::Key;
    for (tok, _) in tokens {
        let text = word(tok);
        if text.is_some_and(|w| {
            ["and", "or", "not"]
                .iter()
                .any(|k| w.eq_ignore_ascii_case(k))
        }) {
            return false;
        }
        want = match (want, tok) {
            (Want::Key, Tok::Word { .. } | Tok::Str) => Want::DirOrComma,
            (Want::DirOrComma, Tok::Word { .. })
                if text.is_some_and(|w| {
                    w.eq_ignore_ascii_case("asc") || w.eq_ignore_ascii_case("desc")
                }) =>
            {
                Want::Comma
            }
            (Want::DirOrComma | Want::Comma, Tok::Comma) => Want::Key,
            _ => return false,
        };
    }
    want != Want::Key
}

/// The generic read plan with the rewritten CQL; a CQL the rewrite refuses is `Invalid` before
/// any fetch (the validation hook of this op: the engine's dry executor call).
pub fn search_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    let effective = effective_cql(str_param(ctx.params, "cql")).map_err(ExecError::Invalid)?;
    let mut params = ctx.params.clone();
    if let Some(map) = params.as_object_mut() {
        map.insert("cql".to_owned(), Value::from(effective));
    }
    generic::read_plan(ctx, &params)
}

/// The Fallback with the effective CQL as sent (§6.3 "Confluence search").
pub fn search_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let mut model = generic::fallback_preview(ctx);
    model.query = effective_cql(str_param(ctx.params, "cql"))
        .ok()
        .map(|q| escape_for_display(&q));
    model.header.query = model.query.clone();
    model
}

// ---- confluence.page.update --------------------------------------------------------------------

pub static PAGE_UPDATE_ENRICH: EnrichRule = EnrichRule {
    plan: page_update_plan,
    judge: page_update_judge,
};

fn page_update_plan(ctx: &EnrichCtx<'_>) -> Vec<(EnrichPurpose, GetCall)> {
    vec![(
        EnrichPurpose::Enrich,
        get_call(
            CONTENT_PATH,
            ctx.params,
            &[("expand", "body.storage,version,space")],
        ),
    )]
}

/// `version.number` of a content answer.
pub(crate) fn content_version(v: &Value) -> Option<u64> {
    v.get("version")?.get("number")?.as_u64()
}

fn page_update_judge(ctx: &EnrichCtx<'_>, responses: &[Value]) -> EnrichVerdict {
    let Some(page) = responses.first() else {
        return EnrichVerdict::unusable();
    };
    let facts = (
        content_version(page),
        page.get("title").and_then(Value::as_str),
        page.get("space")
            .and_then(|s| s.get("key"))
            .and_then(Value::as_str),
    );
    let (Some(current), Some(title), Some(space_key)) = facts else {
        return EnrichVerdict::unusable();
    };
    // The op sends `"type": "page"`: a blog post or comment id is not this op's target.
    if page.get("type").and_then(Value::as_str) != Some("page") {
        return EnrichVerdict::unusable();
    }
    let mut resolved = Map::new();
    resolved.insert("title".to_owned(), Value::from(title));
    resolved.insert("space_key".to_owned(), Value::from(space_key));
    let baseline = json!({"version": current, "title": title, "space_key": space_key});
    let mut verdict = EnrichVerdict::preview(baseline, resolved);

    let base = ctx.params.get("base_version").and_then(Value::as_u64);
    if base != Some(current) {
        let base = base.unwrap_or(0);
        let text = warning::conflict(base, current);
        verdict.hold = Hold::Conflict;
        verdict
            .warnings
            .push(Warning::new(WarningId::Conflict, text.clone()));
        verdict.conflict = Some(text);
        // The agent's base body (`?version=<base>&status=historical`) and its diff are M7.
        verdict.diff_text = format!("base version v{base}, current version v{current}");
    }
    verdict
}

/// `PUT /rest/api/content/{id}` with `version.number = base_version + 1` (§7.4), the current
/// title unless one is given, and the storage body (PD-09: `body_format = storage` only).
pub fn page_update_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    // Path check first, so the validation dry call reports a bad placeholder before enrichment.
    resolve_url(ctx.base, ctx.spec.endpoint.path, ctx.params, &[])?;
    let verdict = ctx
        .enrichment
        .filter(|v| v.hold == Hold::Preview)
        .ok_or(ExecError::EnrichmentRequired)?;
    let current = |name: &str| verdict.resolved.get(name).and_then(Value::as_str);
    let (Some(current_title), Some(space_key)) = (current("title"), current("space_key")) else {
        return Err(ExecError::EnrichmentRequired);
    };
    let next = ctx
        .params
        .get("base_version")
        .and_then(Value::as_u64)
        .and_then(|b| b.checked_add(1))
        .ok_or_else(|| ExecError::Invalid(invalid("base_version", "not a usable version", None)))?;
    let title = ctx
        .params
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or(current_title);
    let body = json!({
        "id": str_param(ctx.params, "id"),
        "type": "page",
        "title": title,
        "space": {"key": space_key},
        "body": {"storage": {"value": str_param(ctx.params, "body"), "representation": "storage"}},
        "version": {"number": next},
    });
    json_request(ctx, &body)
}
