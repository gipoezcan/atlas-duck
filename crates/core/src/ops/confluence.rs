//! Confluence specifics: the `confluence.search` CQL type-filter rewrite (§7.4, part of the
//! static validation of §5.2 step 1), its release list (PD-101) and `cql_broad` (PD-102),
//! `confluence.page.update`
//! (storage verbatim or Markdown converted, `confluence_body`; two enrichment stages with the
//! agent's base body on a conflict, PD-104) and, from M7, the `format` of the page reads (PD-100).

use std::sync::Arc;

use atlas_duck_convert::storage;
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_registry::OperationSpec;
use serde_json::{Map, Value, json};

use super::confluence_body::{EmptyBody, is_markdown, storage_text};
use super::confluence_preview::search_table;
use super::{
    ConfluenceFacts, EnrichCtx, EnrichPurpose, EnrichRule, EnrichStep, EnrichVerdict, ExecCtx,
    ExecError, ExecPlan, PageRef, PreviewCtx, PreviewModel, ReadPlan, WriteSummaryFacts, generic,
    get_call, json_request, resolve_url, str_param,
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
    /// An operator character (`=`, `!`, `~`, `<`, `>`), with its byte.
    Op(u8),
}

/// Fixed rejection texts: an error never echoes the CQL (§7.4 "rejected locally").
const MSG_UNTERMINATED: &str = "unterminated quoted string";
const MSG_BACKSLASH: &str = "backslash outside a quoted string";
const MSG_PARENS: &str = "parentheses do not balance";
const MSG_ORDER_BY: &str = "ORDER BY is allowed once, at the end, outside parentheses";
const MSG_EMPTY: &str = "query is empty";
const MSG_TOO_DEEP: &str = "parentheses nest deeper than 64 levels";

/// The deepest parenthesis nesting a CQL may have (T30 review I-1): [`cql_broad`] recurses once
/// per level, so the tokenizer bounds it far below what a worker stack holds.
pub const CQL_MAX_DEPTH: u32 = 64;

fn cql_error(message: &str) -> ValidationError {
    invalid("cql", message, None)
}

/// Splits `cql` into tokens with their parenthesis depth (before the token). Quoted strings
/// (`'…'`, `"…"`, backslash escapes inside) are opaque. Fails closed on an unterminated string,
/// a backslash outside a string (the server might read the next paren or quote differently),
/// parentheses that close below depth 0 or stay open, and nesting deeper than [`CQL_MAX_DEPTH`].
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
                if depth > CQL_MAX_DEPTH {
                    return Err(cql_error(MSG_TOO_DEEP));
                }
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
                out.push((Tok::Op(b), depth));
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

/// PD-102 (provisional, lead ruling Q11): the fields that narrow a search when a clause names one
/// as `<field> = …` or `<field> IN (…)`. `space.key` and `space.title` name the space as `space`
/// does; `container` is the content whose attachments and comments are searched.
pub const CQL_NARROWING_FIELDS: [&str; 12] = [
    "space",
    "space.key",
    "space.title",
    "ancestor",
    "parent",
    "container",
    "id",
    "content",
    "title",
    "label",
    "creator",
    "contributor",
];

/// §6.2 Info `cql_broad` "CQL may enumerate many results" (PD-102): the one place of the rule.
/// True unless the agent's CQL (before the rewrite) narrows: every `OR` alternative of its outer
/// level holds an operand that is a clause `<field> = …` or `<field> IN (…)` with a field of
/// [`CQL_NARROWING_FIELDS`] (ASCII case-insensitive), or a parenthesized group that itself narrows.
/// An operand directly after `NOT` never narrows, nor do `!=`, `~`, `!~`, `<`, `>`, `<=`, `>=` and
/// `NOT IN`. Values are not analysed; tokens are those of the rewrite's tokenizer, so quoted text
/// never counts. A CQL the tokenizer refuses (rejected at validation) is not flagged.
pub fn cql_broad(cql: &str) -> bool {
    let Ok(tokens) = tokenize(cql) else {
        return false;
    };
    !narrows(cql, &tokens, 0)
}

fn word_is(cql: &str, tok: &Tok, w: &str) -> bool {
    matches!(*tok, Tok::Word { start, end } if cql[start..end].eq_ignore_ascii_case(w))
}

/// PD-102: every `OR` alternative of one parenthesis level (`depth`) narrows. Recurses once per
/// level (through [`alternative_narrows`]), at most [`CQL_MAX_DEPTH`] deep: `tokenize` refuses more.
fn narrows(cql: &str, toks: &[(Tok, u32)], depth: u32) -> bool {
    toks.split(|(t, d)| *d == depth && word_is(cql, t, "or"))
        .all(|alt| alternative_narrows(cql, alt, depth))
}

/// One operand of `alt` at `depth`, not after `NOT`, is a narrowing clause or a narrowing group.
fn alternative_narrows(cql: &str, alt: &[(Tok, u32)], depth: u32) -> bool {
    let mut i = 0;
    while i < alt.len() {
        let prev = i.checked_sub(1).map(|p| &alt[p].0);
        let negated = prev.is_some_and(|p| word_is(cql, p, "not"));
        match alt[i] {
            (Tok::Open, d)
                if d == depth
                    && prev.is_none_or(|p| word_is(cql, p, "and") || word_is(cql, p, "not")) =>
            {
                // A group (an `IN (…)` list or a function call `now(…)` has another word before it).
                let close = alt[i + 1..]
                    .iter()
                    .position(|&(t, d)| d == depth && t == Tok::Close)
                    .map_or(alt.len(), |p| i + 1 + p);
                if !negated && narrows(cql, &alt[i + 1..close.min(alt.len())], depth + 1) {
                    return true;
                }
                i = close + 1;
                continue;
            }
            (Tok::Word { start, end }, d)
                if d == depth
                    && !negated
                    && CQL_NARROWING_FIELDS
                        .iter()
                        .any(|f| cql[start..end].eq_ignore_ascii_case(f)) =>
            {
                match alt.get(i + 1) {
                    Some((Tok::Op(b'='), _)) => return true,
                    Some((t, _)) if word_is(cql, t, "in") => return true,
                    _ => {}
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// PD-101 (lead ruling Q7; §7.4 "releases `totalSize` and per result `content.id`,
/// `content.type`, `title`, `resultGlobalContainer.title`, `url`, `lastModified`, `excerpt?`"):
/// the root keys a search keeps, so the paging metadata stays as sent.
const SEARCH_ROOT_KEYS: [&str; 6] = ["results", "start", "limit", "size", "totalSize", "_links"];

/// PD-101: the keys a search result keeps, each with the keys its object keeps (`None`: the
/// value as sent).
const SEARCH_RESULT_KEYS: [(&str, Option<&[&str]>); 6] = [
    ("content", Some(&["id", "type"])),
    ("title", None),
    ("resultGlobalContainer", Some(&["title"])),
    ("url", None),
    ("lastModified", None),
    ("excerpt", None),
];

/// PD-101: a search answer pruned to the §7.4 release list: the root to [`SEARCH_ROOT_KEYS`],
/// each result to [`SEARCH_RESULT_KEYS`] (a nested object keeps only its listed keys; a listed
/// object key whose value is no object is removed). A function of the answer alone, so every
/// rebuild agrees.
pub(crate) fn prune_search(root: &mut Value, results: &mut [Value]) {
    if let Some(map) = root.as_object_mut() {
        map.retain(|k, _| SEARCH_ROOT_KEYS.contains(&k.as_str()));
    }
    for result in results {
        let Some(map) = result.as_object_mut() else {
            continue;
        };
        map.retain(
            |key, value| match SEARCH_RESULT_KEYS.iter().find(|(k, _)| k == key) {
                None => false,
                Some((_, None)) => true,
                Some((_, Some(keep))) => value.as_object_mut().is_some_and(|inner| {
                    inner.retain(|k, _| keep.contains(&k.as_str()));
                    true
                }),
            },
        );
    }
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

/// §6.3 "Confluence search": the result table ([`search_table`]) under the effective CQL as sent,
/// and the Info `cql_broad` ([`cql_broad`], PD-102; not on a Fallback card). An answer that is no result list (an
/// upstream error) keeps the Fallback.
pub fn search_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    let table = search_table(ctx);
    let cql = str_param(ctx.params, "cql");
    let broad = table.is_some() && cql_broad(cql);
    let mut model = table.unwrap_or_else(|| generic::fallback_preview(ctx));
    model.query = effective_cql(cql).ok().map(|q| escape_for_display(&q));
    model.header.query = model.query.clone();
    if broad {
        model
            .warnings
            .push(Warning::new(WarningId::CqlBroad, warning::TEXT_CQL_BROAD));
    }
    model
}

// ---- page formats (PD-100) ---------------------------------------------------------------------

/// The `format` of `confluence.page.get` and of `confluence.page.history` with `version` (§7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFormat {
    /// The default: `body.storage` converted to Markdown with the committed user map.
    Markdown,
    /// `body.storage` as sent.
    Storage,
    /// `body.view` (the server-rendered HTML) instead of `body.storage`.
    View,
}

impl BodyFormat {
    /// The validated `format` param; absent means `markdown` (validation applies no defaults,
    /// and the schema enum admits nothing else).
    fn of(params: &Value) -> BodyFormat {
        match params.get("format").and_then(Value::as_str) {
            Some("storage") => BodyFormat::Storage,
            Some("view") => BodyFormat::View,
            _ => BodyFormat::Markdown,
        }
    }
}

/// The body format of a read that carries a page body, with whether it is a historical version
/// (`confluence.page.history` on its alternative endpoint, i.e. with `version`); `None` for every
/// other read, the history summary included (it has no body and ignores `format`, PD-100).
/// Decided from the op and the validated params alone: the request's `expand` and the
/// normalization (`ReadShape`) both ask here. The history trigger is the registry's own
/// (`alt_endpoint.when_param_present`, as `generic` picks the endpoint; T10 review m-6).
pub fn body_format(spec: &OperationSpec, params: &Value) -> Option<(BodyFormat, bool)> {
    match spec.id {
        "confluence.page.get" => Some((BodyFormat::of(params), false)),
        "confluence.page.history"
            if spec.alt_endpoint.is_some_and(|alt| {
                params
                    .get(alt.when_param_present)
                    .is_some_and(|v| !v.is_null())
            }) =>
        {
            Some((BodyFormat::of(params), true))
        }
        _ => None,
    }
}

/// The registry read plan, with `body.storage` swapped for `body.view` in its `expand` for
/// `format=view` (PD-100: `body.view,version,space,ancestors`, history `body.view,version`).
fn body_read_plan(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    let plan = generic::read_plan(ctx, ctx.params)?;
    if body_format(ctx.spec, ctx.params).map(|(f, _)| f) != Some(BodyFormat::View) {
        return Ok(plan);
    }
    // Fail closed (T10 review m-1): `view` is only ever one GET; any other plan would send
    // `body.storage` and release it as `view`.
    let ExecPlan::Read(ReadPlan::Get(mut call)) = plan else {
        return Err(ExecError::Invalid(ValidationError {
            code: atlas_duck_ipc::envelope::ErrorCode::Internal,
            message: "the view format of the read cannot be planned".to_owned(),
            details: Map::new(),
        }));
    };
    for (name, value) in &mut call.query {
        if name.as_str() == "expand" {
            *value = value
                .split(',')
                .map(|e| if e == "body.storage" { "body.view" } else { e })
                .collect::<Vec<_>>()
                .join(",");
        }
    }
    Ok(ExecPlan::Read(ReadPlan::Get(call)))
}

/// `confluence.page.get`: the content with the expand of its `format` (PD-100).
pub fn page_get_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    body_read_plan(ctx)
}

/// `confluence.page.history`: the summary, or with `version` the historical content with the
/// expand of its `format` (PD-100).
pub fn page_history_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    body_read_plan(ctx)
}

// ---- confluence.page.update --------------------------------------------------------------------

/// PD-104: two stages (Δ3): the current page, then (only when the agent's `base_version` is not
/// the current version) the agent's base version's body; the judge holds the conflict, keeps both
/// bodies for the card ([`ConfluenceFacts`]), holds an update whose bodies are past
/// [`PAGE_BODY_LIMIT`] (T15 review I-1) and a Markdown update over a current body that does not
/// parse.
pub static PAGE_UPDATE_ENRICH: EnrichRule = EnrichRule {
    plan: page_update_plan,
    judge: page_update_judge,
};

/// PD-104 stage 1: the page with its storage, version, space and ancestors.
const PAGE_UPDATE_EXPAND: &str = "body.storage,version,space,ancestors";

/// Stage 1, then stage 2 (§5.4 step 2 verbatim: `?version=<base_version>&status=historical&
/// expand=body.storage`) when the current page answered a version other than the base and a
/// body the card can keep ([`PAGE_BODY_LIMIT`]; past it the judge holds the update anyway).
fn page_update_plan(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichStep {
    match answers {
        [] => EnrichStep::Fetch(vec![(
            EnrichPurpose::Enrich,
            get_call(CONTENT_PATH, ctx.params, &[("expand", PAGE_UPDATE_EXPAND)]),
        )]),
        [current] if storage_of(current).is_some_and(|s| s.len() > PAGE_BODY_LIMIT) => {
            EnrichStep::Judge
        }
        [current] => match (base_version(ctx.params), content_version(current)) {
            (Some(base), Some(now)) if base != now => {
                let version = base.to_string();
                EnrichStep::Fetch(vec![(
                    EnrichPurpose::Enrich,
                    get_call(
                        CONTENT_PATH,
                        ctx.params,
                        &[
                            ("version", version.as_str()),
                            ("status", "historical"),
                            ("expand", "body.storage"),
                        ],
                    ),
                )])
            }
            _ => EnrichStep::Judge,
        },
        _ => EnrichStep::Judge,
    }
}

fn base_version(params: &Value) -> Option<u64> {
    params.get("base_version").and_then(Value::as_u64)
}

/// `version.number` of a content answer.
pub(crate) fn content_version(v: &Value) -> Option<u64> {
    v.get("version")?.get("number")?.as_u64()
}

/// `body.storage.value` of a content answer.
fn storage_of(v: &Value) -> Option<&str> {
    v.get("body")?.get("storage")?.get("value")?.as_str()
}

/// PD-94 (plan text): the card of a Markdown update held because the current page's storage does
/// not parse (plan review I-3 c).
pub const TEXT_CURRENT_UNPARSABLE: &str =
    "the current page storage could not be parsed; what this update removes cannot be counted";

/// T15 review I-1 (lead ruling c): the most storage bytes an update keeps of the current page and
/// of its base version for the card, the update card's diff budget (16 MiB, the host-call default
/// `max_call_result_mb`). A longer body is held (`EnrichmentError`, [`TEXT_PAGE_TOO_LARGE`]), so a
/// pending update holds at most two bodies of this size.
pub const PAGE_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// T15 review I-1: the card of an update held because a page body is past [`PAGE_BODY_LIMIT`].
pub const TEXT_PAGE_TOO_LARGE: &str = "the page storage is larger than 16 MiB, the preview's \
     diff budget; this update cannot be previewed or approved here";

/// T15 review m-1: `confluence.page.update`'s previewer with its Markdown projections held to
/// `budget` bytes (the op table's previewer uses the 16 MiB diff budget).
#[cfg(feature = "testing")]
pub fn update_preview_within(ctx: &PreviewCtx<'_>, budget: usize) -> PreviewModel {
    super::confluence_preview::update_preview_within(ctx, budget)
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
        storage_of(page),
        base_version(ctx.params),
    );
    let (Some(current), Some(title), Some(space_key), Some(current_storage), Some(base)) = facts
    else {
        return EnrichVerdict::unusable();
    };
    // The op sends `"type": "page"`: a blog post or comment id is not this op's target.
    if page.get("type").and_then(Value::as_str) != Some("page") {
        return EnrichVerdict::unusable();
    }
    let mut resolved = Map::new();
    resolved.insert("title".to_owned(), Value::from(title));
    resolved.insert("space_key".to_owned(), Value::from(space_key));
    // The stale rule compares the version this answer read (`stale::PAGE_UPDATE`); the conflict
    // below is judged on the same answer, so both name the same current version.
    let baseline = json!({"version": current, "title": title, "space_key": space_key});
    let mut verdict = EnrichVerdict::preview(baseline, resolved);
    let mut facts = ConfluenceFacts {
        space_key: space_key.to_owned(),
        space_name: page
            .get("space")
            .and_then(|s| s.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        page: Some(PageRef {
            id: str_param(ctx.params, "id").to_owned(),
            title: title.to_owned(),
        }),
        ..ConfluenceFacts::default()
    };
    let too_large = |s: &str| s.len() > PAGE_BODY_LIMIT;

    if too_large(current_storage) {
        // T15 review I-1 (lead ruling c): a body past the diff budget is not kept (fail closed;
        // judged first: the plan asked for no base body then).
        verdict.hold = Hold::EnrichmentError;
        facts.page_too_large = true;
    } else if base != current {
        // Stage 2 answered the agent's base version: its body is the "before" of both diffs.
        // Fail closed when the answer is not that version of this page.
        let Some(base_storage) = responses
            .get(1)
            .filter(|h| is_base_answer(h, str_param(ctx.params, "id"), base))
            .and_then(storage_of)
        else {
            return EnrichVerdict::unusable();
        };
        if too_large(base_storage) {
            // No conflict card without the base body: the hold says why instead.
            verdict.hold = Hold::EnrichmentError;
            facts.page_too_large = true;
        } else {
            facts.current_storage = Some(Arc::from(current_storage));
            facts.base_storage = Some(Arc::from(base_storage));
            let text = warning::conflict(base, current);
            verdict.hold = Hold::Conflict;
            verdict
                .warnings
                .push(Warning::new(WarningId::Conflict, text.clone()));
            verdict.conflict = Some(text.into());
            verdict.diff_text = format!("base version v{base}, current version v{current}");
        }
    } else if is_markdown(ctx.params) && !storage::parse(current_storage).xml_ok {
        // PD-94: what a Markdown update removes cannot be counted (T7 review m-4: the judge
        // parses itself; `lossy_update` does not say which path it took).
        verdict.hold = Hold::EnrichmentError;
        facts.current_unparsable = true;
    } else {
        facts.current_storage = Some(Arc::from(current_storage));
    }
    verdict.summary = Some(WriteSummaryFacts {
        confluence: Some(facts),
        ..WriteSummaryFacts::default()
    });
    verdict
}

/// A stage-2 answer is the base version of the page: its `id`, its `version.number` when it
/// carries one (the expand names only the body: DC may leave the version out, so an answer
/// without one is taken as the version asked for), and its `status` `historical` when it carries
/// one (T15 review I-2: a server or proxy that ignored `version` / `status=historical` answers
/// the current page, which is no base). T25's live run checks the shape.
fn is_base_answer(answer: &Value, id: &str, base: u64) -> bool {
    let same_page = answer.get("id").and_then(Value::as_str) == Some(id);
    let same_version = answer
        .get("version")
        .is_none_or(|_| content_version(answer) == Some(base));
    let historical = answer
        .get("status")
        .is_none_or(|s| s.as_str() == Some("historical"));
    same_page && same_version && historical
}

/// `PUT /rest/api/content/{id}` with `version.number = base_version + 1` (§7.4), the current
/// title unless one is given, and the storage body (`confluence_body::storage_text`: storage
/// verbatim, or the Markdown converted). Rendered under the conflict hold too (T8 review I-1:
/// the conflict card shows the request, and its intended change is computed from it); that hold
/// is never approvable.
pub fn page_update_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    // Path check and body checks first, so the validation dry call reports a bad path
    // placeholder or a refused body before enrichment (§5.4 step 1).
    resolve_url(ctx.base, ctx.spec.endpoint.path, ctx.params, &[])?;
    let storage = storage_text(ctx, EmptyBody::Allow)?;
    let verdict = ctx
        .enrichment
        .filter(|v| matches!(v.hold, Hold::Preview | Hold::Conflict))
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
        "body": {"storage": {"value": storage, "representation": "storage"}},
        "version": {"number": next},
    });
    json_request(ctx, &body)
}
