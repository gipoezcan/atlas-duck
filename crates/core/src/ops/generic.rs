//! Registry-driven executors and previewers (PD-09): the template/paginated read plan every read
//! uses, the `NotInThisBuild` write executor, the §6.3 Fallback (JSON tree) and the write-request
//! preview, the receipt projection (§4.2), and the table cells and list tables both products'
//! previewers share (§6.3 "Lists", PD-114).

use std::collections::HashSet;

use atlas_duck_atlassian::{GetCall, HttpRequestSpec, PagedCall, SearchCall};
use atlas_duck_preview::invisible::{self, escape_for_display};
use atlas_duck_preview::mixed_script::is_mixed_script;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_preview::{
    BodyView, ItemCount, PreviewBody, PreviewHeader, RequestView, body_digest_line, json_tree,
};
use atlas_duck_registry::{
    BodySource, Endpoint, OpClass, OperationSpec, Product, Projection, QueryValue, TargetDisplay,
};
use base64::Engine as _;
use serde_json::{Map, Value};

use super::{
    ExecCtx, ExecError, ExecPlan, PreviewCtx, PreviewInput, PreviewModel, ReadPlan, ReadView,
    WriteView, path_params, resolve_url,
};
use crate::lifecycle::model::Hold;
use crate::metadata::one_line;

/// §7.5: the agent's offset param of every paginated op.
const START_PARAM: &str = "start";

/// The page size of a paginated op that has no `max` cap (none in v1).
const DEFAULT_PAGE_SIZE: u32 = 50;

/// At most this many "mixed-script identifier" warnings per preview (first in document order).
const MAX_MIXED_SCRIPT_WARNINGS: usize = 20;

/// Shown for an `EnrichmentError` hold whose fetch answered but not in the expected shape.
const UNUSABLE_ENRICHMENT_TEXT: &str = "the server's answer did not have the expected shape";

/// Ops whose result root is a user object (or a list of them): their `name` is a username.
const USER_ROOT_OPS: &[&str] = &[
    "jira.myself",
    "jira.user.assignable",
    "confluence.user.current",
];

/// Object keys whose value is a user object (or a list of them) in Jira and Confluence answers.
const USER_OBJECT_KEYS: &[&str] = &[
    "author",
    "assignee",
    "reporter",
    "creator",
    "updateAuthor",
    "lead",
    "by",
    "createdBy",
    "users",
];

/// Keys whose string value is an identifier (§6.4: issue keys, space keys, usernames).
const IDENTIFIER_KEYS: &[&str] = &["key", "spaceKey", "username", "userKey"];

/// Write params that are identifiers (issue/project/space keys, usernames).
const WRITE_IDENTIFIER_PARAMS: &[&str] = &[
    "key", "project", "space", "inward", "outward", "assignee", "issueKey", "username", "issues",
];

// ---- read plans ------------------------------------------------------------------------------

/// Every read (PD-09): the registry endpoint (or `alt_endpoint`) with the validated params.
pub fn read_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    read_plan(ctx, ctx.params)
}

/// PD-09: an op the build does not run (no registry write since M7 Task 20a).
pub fn not_in_this_build(_ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    Err(ExecError::NotInThisBuild)
}

/// The read plan for `params` (an op-specific executor may pass a derived view of the params,
/// e.g. the rewritten CQL).
pub(crate) fn read_plan(ctx: &ExecCtx<'_>, params: &Value) -> Result<ExecPlan, ExecError> {
    let spec = ctx.spec;
    let endpoint = endpoint_for(spec, params);
    let page_size = page_size(spec, ctx.effective_max);
    let start = params.get(START_PARAM).and_then(Value::as_u64).unwrap_or(0);

    if endpoint.body == BodySource::ParamsAsJson {
        let paging = spec.paginated.ok_or_else(missing_paging)?;
        resolve_url(ctx.base, endpoint.path, params, &[])?;
        let body = search_body(
            spec,
            params,
            paging.offset_param,
            paging.limit_param,
            start,
            page_size,
        );
        return Ok(ExecPlan::Read(ReadPlan::Search {
            call: SearchCall {
                endpoint_template: endpoint.path.to_owned(),
                body,
            },
            items_key: paging.items_key.to_owned(),
            max_items: u64::from(page_size),
        }));
    }

    let query = query_pairs(spec, &endpoint, params, ctx.effective_max);
    resolve_url(ctx.base, endpoint.path, params, &query)?;
    let get = GetCall {
        endpoint_template: endpoint.path.to_owned(),
        params: path_params(endpoint.path, params),
        query,
    };
    Ok(ExecPlan::Read(match spec.paginated {
        None => ReadPlan::Get(get),
        Some(paging) => ReadPlan::Paged {
            call: PagedCall {
                get,
                items_key: paging.items_key.to_owned(),
                offset_param: paging.offset_param.to_owned(),
                limit_param: paging.limit_param.to_owned(),
                page_size,
                start,
            },
            max_items: u64::from(page_size),
        },
    }))
}

fn missing_paging() -> ExecError {
    ExecError::Invalid(crate::validate::ValidationError {
        code: atlas_duck_ipc::envelope::ErrorCode::Internal,
        message: "operation paging is not declared".to_owned(),
        details: Map::new(),
    })
}

fn endpoint_for(spec: &OperationSpec, params: &Value) -> Endpoint {
    match spec.alt_endpoint {
        Some(alt)
            if params
                .get(alt.when_param_present)
                .is_some_and(|v| !v.is_null()) =>
        {
            alt.endpoint
        }
        _ => spec.endpoint,
    }
}

/// The clamped `max` (`Validated::effective_max`), else the op's default.
fn page_size(spec: &OperationSpec, effective_max: Option<u32>) -> u32 {
    effective_max
        .or_else(|| spec.caps.max.map(|m| m.default))
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .max(1)
}

/// A param's value as the request sends it: the clamped `max`, or the registry's default
/// `fields` when the agent sent none (§7.3).
fn param_value(
    spec: &OperationSpec,
    params: &Value,
    name: &str,
    effective_max: Option<u32>,
) -> Option<Value> {
    if let (Some(cap), Some(max)) = (spec.caps.max, effective_max)
        && cap.param == name
    {
        return Some(Value::from(max));
    }
    // An empty list counts as absent: `fields=` would make Jira fall back to every navigable field.
    let empty = |v: &&Value| v.is_null() || v.as_array().is_some_and(Vec::is_empty);
    if let Some(v) = params.get(name).filter(|v| !empty(v)) {
        return Some(v.clone());
    }
    let rules = spec.field_rules?;
    if rules.fields_param == Some(name) && !rules.default_fields.is_empty() {
        return Some(Value::from(rules.default_fields));
    }
    None
}

/// A query value: scalars as text, lists comma-joined.
fn query_text(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Array(items) => Some(
            items
                .iter()
                .filter_map(query_text)
                .collect::<Vec<_>>()
                .join(","),
        ),
        Value::Object(_) => Some(v.to_string()),
    }
}

/// The registry's query list in order (§7.3/§7.4); pagination appends its own offset/limit.
fn query_pairs(
    spec: &OperationSpec,
    endpoint: &Endpoint,
    params: &Value,
    effective_max: Option<u32>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for q in endpoint.query {
        let value = match q.value {
            QueryValue::Const(c) => Some(c.to_owned()),
            QueryValue::Param(p) => {
                param_value(spec, params, p, effective_max).and_then(|v| query_text(&v))
            }
            QueryValue::ParamOr { param, default } => Some(
                param_value(spec, params, param, effective_max)
                    .and_then(|v| query_text(&v))
                    .unwrap_or_else(|| default.to_owned()),
            ),
            QueryValue::ParamBoolFlag {
                param,
                value_if_true,
            } => (params.get(param) == Some(&Value::Bool(true))).then(|| value_if_true.to_owned()),
        };
        if let Some(value) = value {
            out.push((q.name.to_owned(), value));
        }
    }
    out
}

/// `jira.search` (`BodySource::ParamsAsJson`): the params minus `start`/`max`, the server's page
/// fields, and the default `fields` when the agent sent none.
fn search_body(
    spec: &OperationSpec,
    params: &Value,
    offset_param: &str,
    limit_param: &str,
    start: u64,
    page_size: u32,
) -> Value {
    let max_param = spec.caps.max.map(|m| m.param);
    let mut body = Map::new();
    for (k, v) in params.as_object().into_iter().flatten() {
        let empty = v.is_null() || v.as_array().is_some_and(Vec::is_empty);
        if k == START_PARAM || Some(k.as_str()) == max_param || empty {
            continue;
        }
        body.insert(k.clone(), v.clone());
    }
    if let Some(rules) = spec.field_rules
        && let Some(name) = rules.fields_param
        && !body.contains_key(name)
        && !rules.default_fields.is_empty()
    {
        body.insert(name.to_owned(), Value::from(rules.default_fields));
    }
    body.insert(offset_param.to_owned(), Value::from(start));
    body.insert(limit_param.to_owned(), Value::from(page_size));
    Value::Object(body)
}

// ---- receipts ----------------------------------------------------------------------------------

/// §4.2 / §5.6: the receipt the agent gets from a write response (`result_projection`): the
/// listed fields (dotted paths) that exist (of `results[0]` for `FirstResultFields` when the
/// answer is `{"results":[…]}`, M7 Δ4 b), the agent's own labels, or `{}`.
pub fn project_receipt(spec: &OperationSpec, response: &Value, params: &Value) -> Value {
    match spec.result_projection {
        Projection::Empty => Value::Object(Map::new()),
        Projection::AgentLabels => {
            let mut out = Map::new();
            let labels = params
                .get("labels")
                .cloned()
                .unwrap_or(Value::Array(Vec::new()));
            out.insert("labels".to_owned(), labels);
            Value::Object(out)
        }
        Projection::Fields(paths) => project_fields(response, paths),
        Projection::FirstResultFields(paths) => {
            // An empty `results` projects to `{}`: no object is the receipt's.
            let first = match response.get("results").and_then(Value::as_array) {
                Some(results) => results.first().unwrap_or(&Value::Null),
                None => response,
            };
            project_fields(first, paths)
        }
    }
}

/// The listed fields (dotted paths) of `response` that exist.
fn project_fields(response: &Value, paths: &[&str]) -> Value {
    let mut out = Map::new();
    for path in paths {
        let segments: Vec<&str> = path.split('.').collect();
        let mut at = Some(response);
        for seg in &segments {
            at = at.and_then(|v| v.get(*seg));
        }
        if let Some(value) = at {
            insert_path(&mut out, &segments, value.clone());
        }
    }
    Value::Object(out)
}

fn insert_path(out: &mut Map<String, Value>, segments: &[&str], value: Value) {
    let Some((last, parents)) = segments.split_last() else {
        return;
    };
    let mut at = out;
    for seg in parents {
        let slot = at
            .entry((*seg).to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if !slot.is_object() {
            *slot = Value::Object(Map::new());
        }
        let Value::Object(next) = slot else { return };
        at = next;
    }
    at.insert((*last).to_owned(), value);
}

/// "agent receives: id, key" (§5.6).
pub fn receipt_fields(spec: &OperationSpec) -> Vec<String> {
    match spec.result_projection {
        Projection::Fields(paths) | Projection::FirstResultFields(paths) => {
            paths.iter().map(|p| (*p).to_owned()).collect()
        }
        Projection::AgentLabels => vec!["labels".to_owned()],
        Projection::Empty => Vec::new(),
    }
}

// ---- previews ----------------------------------------------------------------------------------

/// §6.3 Fallback: the JSON tree with sizes. A write input renders as [`write_preview`].
pub fn fallback_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    match &ctx.input {
        PreviewInput::Read(view) => read_fallback(ctx, view),
        PreviewInput::Write(view) => write_model(ctx, view),
    }
}

/// The write preview: the exact request list (§5.1 inv. 4) or the hold's card (§6.3).
pub fn write_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    fallback_preview(ctx)
}

fn class_name(spec: &OperationSpec) -> String {
    match spec.class {
        OpClass::Read => "read".to_owned(),
        OpClass::Write => "write".to_owned(),
    }
}

fn read_fallback(ctx: &PreviewCtx<'_>, view: &ReadView<'_>) -> PreviewModel {
    let tree = json_tree(view.candidate);
    let (header, warnings) = read_parts(ctx, view, tree.hidden_bytes());
    let query = header.query.clone();
    PreviewModel {
        header,
        body: PreviewBody::JsonTree { tree },
        warnings,
        query,
    }
}

/// The header and the warnings every read preview shares, whatever its body layout: the `*all`
/// Caution, the classifier counts and their warnings, mixed-script identifiers and the cap
/// notes. `hidden_in_preview_bytes` is what the layout does not show of the candidate.
pub(crate) fn read_parts(
    ctx: &PreviewCtx<'_>,
    view: &ReadView<'_>,
    hidden_in_preview_bytes: u64,
) -> (PreviewHeader, Vec<Warning>) {
    let spec = ctx.spec;
    let candidate = view.candidate;
    let (bidi, other) = count_value(candidate);
    let item_count = item_count(spec, view);

    let mut warnings = Vec::new();
    if requested_all_fields(spec, ctx.params) {
        warnings.push(Warning::new(WarningId::AllFields, warning::TEXT_ALL_FIELDS));
    }
    invisible_warnings(&mut warnings, bidi, other);
    let mut idents = Identifiers::default();
    idents.scan(candidate, USER_ROOT_OPS.contains(&spec.id));
    idents.push_warnings(&mut warnings);
    if view.clamped && view.more_available {
        let shown = item_count.map_or(0, |c| c.shown);
        let requested = spec
            .caps
            .max
            .and_then(|cap| ctx.params.get(cap.param))
            .and_then(Value::as_u64);
        let of = view.server_total.or(requested).unwrap_or(shown);
        warnings.push(Warning::new(
            WarningId::TruncatedByCap,
            warning::truncated_by_cap(shown, of),
        ));
    }
    // PD-45: `jira.issue.get --comments` stopped at the comments cap.
    if let Some((fetched, total)) = view.comments_truncated {
        warnings.push(Warning::new(
            WarningId::TruncatedByCap,
            warning::truncated_by_cap(fetched, total),
        ));
    }

    let header = PreviewHeader {
        instance_alias: ctx.instance_alias.to_owned(),
        op_id: spec.id.to_owned(),
        class: class_name(spec),
        item_count,
        byte_size: view.byte_size,
        fields_included: fields_included(spec, ctx.params, candidate),
        hidden_in_preview_bytes,
        bidi_controls: bidi,
        other_invisible: other,
        executes_as: None,
        receipt_fields: Vec::new(),
        query: query_display(spec, ctx.params),
        release_blocked: None,
    };
    (header, warnings)
}

// ---- tables: cells and lists (§6.3 "Lists", PD-114) ------------------------------------------

/// A table cell shows at most this many chars; Raw has the rest.
pub(crate) const CELL_CAP_CHARS: usize = 200;

/// A table has at most this many rows; the last row says how many items it leaves out.
pub(crate) const TABLE_ROW_CAP: usize = 500;

/// The columns of a table come from this many first items.
pub(crate) const COLUMN_SAMPLE_ITEMS: usize = 50;

/// A table has at most this many columns; the keys beyond count as hidden.
pub(crate) const MAX_COLUMNS: usize = 40;

/// A column name shows at most this many chars; the cut bytes count as hidden.
const COLUMN_NAME_CAP_CHARS: usize = 64;

/// A page key or identifier is skipped (not counted as hidden) only when it has the expected
/// type and, for a string, is at most this many bytes: nothing reaches the agent unshown and
/// uncounted.
pub(crate) const IDENT_CAP_BYTES: usize = 256;

pub(crate) fn short_string(v: &Value) -> bool {
    matches!(v, Value::String(s) if s.len() <= IDENT_CAP_BYTES)
}

/// A key of a result root that is page mechanics (shown as the count), not content: a number, a
/// bool or a short string of the expected kind, as the product's list answers carry them (Jira
/// `startAt`/`maxResults`/`total`/`isLast`/`expand`, Confluence `start`/`limit`/`size`/
/// `totalSize`).
fn is_page_mechanic(product: Product, key: &str, value: &Value) -> bool {
    match (product, key) {
        (Product::Jira, "startAt" | "maxResults" | "total") => value.is_number(),
        (Product::Jira, "isLast") => value.is_boolean(),
        (Product::Jira, "expand") => short_string(value),
        (Product::Confluence, "start" | "limit" | "size" | "totalSize") => value.is_number(),
        _ => false,
    }
}

/// Bytes a key and its value take as compact JSON: what a layout that drops them hides.
pub(crate) fn pair_bytes(key: &str, value: &Value) -> u64 {
    u64::try_from(key.len().saturating_add(value.to_string().len())).unwrap_or(u64::MAX)
}

pub(crate) fn bytes_of(value: &Value) -> u64 {
    u64::try_from(value.to_string().len()).unwrap_or(u64::MAX)
}

/// `s` cut to at most `cap` bytes at a char boundary, and how many bytes were cut.
pub(crate) fn cut_at(s: &str, cap: usize) -> (&str, u64) {
    if s.len() <= cap {
        return (s, 0);
    }
    let mut end = cap;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    (&s[..end], u64::try_from(s.len() - end).unwrap_or(u64::MAX))
}

/// `s` cut to at most `cap` chars, and how many bytes were cut.
pub(crate) fn cut_chars(s: &str, cap: usize) -> (&str, u64) {
    match s.char_indices().nth(cap) {
        None => (s, 0),
        Some((at, _)) => (&s[..at], u64::try_from(s.len() - at).unwrap_or(u64::MAX)),
    }
}

/// `raw` cut at `cap` chars, display-escaped and one line, then cut at `cap` chars again (the
/// escape widens an invisible char to `⟨U+XXXX⟩`): the text, and the bytes cut in all.
pub(crate) fn capped_text(raw: &str, cap: usize) -> (String, u64) {
    let (kept, cut) = cut_chars(raw, cap);
    let escaped = one_line(escape_for_display(kept));
    let (shown, cut_escaped) = cut_chars(&escaped, cap);
    (shown.to_owned(), cut.saturating_add(cut_escaped))
}

/// A table cell: the string itself, else compact JSON, cut at [`CELL_CAP_CHARS`] after escaping
/// (said in the cell, the cut bytes added to `hidden`), display-escaped and one line.
fn cell(value: &Value, hidden: &mut u64) -> String {
    let full = match value {
        Value::String(s) => std::borrow::Cow::Borrowed(s.as_str()),
        other => std::borrow::Cow::Owned(other.to_string()),
    };
    let (shown, cut) = capped_text(&full, CELL_CAP_CHARS);
    if cut == 0 {
        return shown;
    }
    *hidden = hidden.saturating_add(cut);
    format!("{shown}… {cut} more bytes (see Raw)")
}

/// A column name (display-escaped, one line) cut at [`COLUMN_NAME_CAP_CHARS`]; the cut bytes are
/// added to `hidden`.
pub(crate) fn column_name(raw: &str, hidden: &mut u64) -> String {
    let (shown, cut) = capped_text(raw, COLUMN_NAME_CAP_CHARS);
    if cut == 0 {
        return shown;
    }
    *hidden = hidden.saturating_add(cut);
    format!("{shown}…")
}

/// A table cell of an item's member, or empty where the item has none.
pub(crate) fn cell_of(member: Option<&Value>, hidden: &mut u64) -> String {
    member.map_or_else(String::new, |v| cell(v, hidden))
}

/// The row that says what the row cap left out; its text is in the first cell.
pub(crate) fn omitted_row(columns: usize, omitted: usize) -> Vec<String> {
    let mut row = vec![format!("… {omitted} more items (see Raw)")];
    row.resize(columns.max(1), String::new());
    row
}

/// The result root's keys that are neither the item array nor page mechanics: hidden.
pub(crate) fn other_root_bytes(product: Product, root: &Value, items_key: Option<&str>) -> u64 {
    let Some(map) = root.as_object() else {
        return 0;
    };
    map.iter()
        .filter(|(k, v)| Some(k.as_str()) != items_key && !is_page_mechanic(product, k, v))
        .fold(0u64, |sum, (k, v)| sum.saturating_add(pair_bytes(k, v)))
}

/// The count of a table: the paging facts of the read, else what the list holds.
pub(crate) fn table_count(header: &mut PreviewHeader, shown: usize) -> Option<ItemCount> {
    let shown = u64::try_from(shown).unwrap_or(u64::MAX);
    let count = header.item_count.unwrap_or(ItemCount {
        shown,
        total: Some(shown),
        more_available: false,
    });
    header.item_count = Some(count);
    Some(count)
}

/// How a product's list answers are laid out as a table (PD-114).
struct ListShape {
    /// The item arrays tried after the registry's `items_key` (an array root needs none).
    item_keys: &'static [&'static str],
    /// The keys a table puts first, in this order, where the items have them.
    leading: &'static [&'static str],
    /// A nested object's `title`, `key` or `name` (scalar) becomes a column of its own, named
    /// `<member>.<key>` (one level: `space.key`, `space.name`).
    flatten: bool,
}

/// The M5 Jira lists: unchanged by PD-114 (no flattening).
const JIRA_LISTS: ListShape = ListShape {
    item_keys: &[
        "values",
        "issueLinkTypes",
        "transitions",
        "worklogs",
        "comments",
    ],
    leading: &["id", "key", "name", "displayName"],
    flatten: false,
};

/// PD-114: Confluence lists hold their items under `results` (also the unpaginated
/// `label.list` and `attachment.list`) and name their nested containers (`space`, `container`).
const CONFLUENCE_LISTS: ListShape = ListShape {
    item_keys: &["results"],
    leading: &["id", "key", "name", "title"],
    flatten: true,
};

/// The nested members a [`ListShape::flatten`] table shows, in this order.
const NESTED_COLUMN_KEYS: [&str; 3] = ["title", "key", "name"];

fn list_shape(product: Product) -> &'static ListShape {
    match product {
        Product::Jira => &JIRA_LISTS,
        Product::Confluence => &CONFLUENCE_LISTS,
    }
}

fn is_scalar(v: &Value) -> bool {
    !matches!(v, Value::Array(_) | Value::Object(_))
}

/// The items of a list answer (an array root, the registry's `items_key`, else the product's
/// item arrays) and the root key holding them; `None` when the candidate holds no item list.
pub(crate) fn list_items<'a>(
    spec: &OperationSpec,
    candidate: &'a Value,
) -> Option<(&'a [Value], Option<&'static str>)> {
    match candidate {
        Value::Array(items) => Some((items, None)),
        Value::Object(map) => spec
            .paginated
            .map(|p| p.items_key)
            .into_iter()
            .chain(list_shape(spec.product).item_keys.iter().copied())
            .find_map(|k| {
                map.get(k)
                    .and_then(Value::as_array)
                    .map(|a| (&a[..], Some(k)))
            }),
        _ => None,
    }
}

/// One column of a list table: an item's scalar member, or (flattened) a scalar member of an
/// item's nested object.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Column<'a> {
    key: &'a str,
    nested: Option<&'static str>,
}

impl Column<'_> {
    /// The item's value this column shows, when it is a scalar.
    fn value_in<'v>(&self, item: &'v Map<String, Value>) -> Option<&'v Value> {
        let member = item.get(self.key)?;
        match self.nested {
            None => Some(member),
            Some(sub) => member.as_object()?.get(sub),
        }
        .filter(|v| is_scalar(v))
    }

    fn name(&self) -> String {
        match self.nested {
            None => self.key.to_owned(),
            Some(sub) => format!("{}.{sub}", self.key),
        }
    }
}

/// The columns one member of an item gives: itself when scalar; with `flatten`, the scalar
/// `title`/`key`/`name` of a nested object.
fn member_columns<'a>(
    key: &'a str,
    value: &'a Value,
    flatten: bool,
) -> impl Iterator<Item = Column<'a>> {
    let direct = is_scalar(value).then_some(Column { key, nested: None });
    let nested = value
        .as_object()
        .filter(|_| flatten)
        .into_iter()
        .flat_map(move |o| {
            NESTED_COLUMN_KEYS
                .iter()
                .filter(move |sub| o.get(**sub).is_some_and(is_scalar))
                .map(move |sub| Column {
                    key,
                    nested: Some(*sub),
                })
        });
    direct.into_iter().chain(nested)
}

/// The columns of the first [`COLUMN_SAMPLE_ITEMS`] items, at most [`MAX_COLUMNS`]: the leading
/// keys of the shape first (in its order), then the rest in first-seen order. (A JSON object
/// here has no insertion order, its keys come sorted, so "first seen" is per item in key order.)
fn list_columns<'a>(items: &'a [Value], shape: &ListShape) -> Vec<Column<'a>> {
    let mut leading: Vec<Option<Column<'a>>> = vec![None; shape.leading.len()];
    let mut rest: Vec<Column<'a>> = Vec::new();
    let mut seen: HashSet<Column<'a>> = HashSet::new();
    let columns = items
        .iter()
        .take(COLUMN_SAMPLE_ITEMS)
        .filter_map(Value::as_object)
        .flat_map(|m| {
            m.iter()
                .flat_map(|(k, v)| member_columns(k, v, shape.flatten))
        });
    for column in columns {
        let slot = (column.nested.is_none())
            .then(|| shape.leading.iter().position(|l| *l == column.key))
            .flatten();
        if let Some(slot) = slot {
            if let Some(entry) = leading.get_mut(slot) {
                entry.get_or_insert(column);
            }
        } else if rest.len() < MAX_COLUMNS && seen.insert(column) {
            rest.push(column);
        }
        // Everything the columns can hold is known: the remaining keys are not scanned.
        if rest.len() >= MAX_COLUMNS && leading.iter().all(Option::is_some) {
            break;
        }
    }
    leading
        .into_iter()
        .flatten()
        .chain(rest)
        .take(MAX_COLUMNS)
        .collect()
}

/// The bytes of an item's member that its row does not show: an unshown member in full; of a
/// nested object with flattened columns, the members those columns do not show.
fn unshown_member_bytes(key: &str, value: &Value, columns: &[Column<'_>]) -> u64 {
    if is_scalar(value) {
        return if columns.contains(&Column { key, nested: None }) {
            0
        } else {
            pair_bytes(key, value)
        };
    }
    let flattened = |sub: &str| {
        columns
            .iter()
            .any(|c| c.key == key && c.nested.is_some_and(|n| n == sub))
    };
    match value {
        Value::Object(nested) if columns.iter().any(|c| c.key == key && c.nested.is_some()) => {
            nested
                .iter()
                .filter(|(k, v)| !(is_scalar(v) && flattened(k)))
                .fold(0u64, |sum, (k, v)| sum.saturating_add(pair_bytes(k, v)))
        }
        _ => pair_bytes(key, value),
    }
}

/// §6.3 "Lists" (PD-114): an item list (an array root, the registry's `items_key`, else the
/// product's item arrays) as a table whose columns are the scalar keys of the first 50 items in
/// first-seen order (the product's identifying keys first; for Confluence also a nested object's
/// `title`/`key`/`name`, one level), a row per item. `None` for a result that is no list of
/// objects with such keys: the caller keeps the §6.3 Fallback (the JSON tree). What the table
/// leaves out (nested values, later items' extra keys, other root keys) is counted in
/// `hidden_in_preview_bytes`; Raw has the exact bytes.
pub(crate) fn list_table(ctx: &PreviewCtx<'_>) -> Option<PreviewModel> {
    let PreviewInput::Read(view) = &ctx.input else {
        return None;
    };
    let shape = list_shape(ctx.spec.product);
    let (items, items_key) = list_items(ctx.spec, view.candidate)?;
    let columns = list_columns(items, shape);
    if columns.is_empty() {
        return None;
    }

    let mut hidden = other_root_bytes(ctx.spec.product, view.candidate, items_key);
    let mut rows: Vec<Vec<String>> = Vec::with_capacity(items.len().min(TABLE_ROW_CAP + 1));
    for (n, item) in items.iter().enumerate() {
        let (Some(map), true) = (item.as_object(), n < TABLE_ROW_CAP) else {
            hidden = hidden.saturating_add(bytes_of(item));
            continue;
        };
        rows.push(
            columns
                .iter()
                .map(|c| cell_of(c.value_in(map), &mut hidden))
                .collect(),
        );
        for (k, v) in map {
            hidden = hidden.saturating_add(unshown_member_bytes(k, v, &columns));
        }
    }
    if items.len() > TABLE_ROW_CAP {
        rows.push(omitted_row(columns.len(), items.len() - TABLE_ROW_CAP));
    }

    let columns: Vec<String> = columns
        .iter()
        .map(|c| column_name(&c.name(), &mut hidden))
        .collect();
    let (mut header, warnings) = read_parts(ctx, view, hidden);
    let count = table_count(&mut header, items.len());
    let query = header.query.clone();
    Some(PreviewModel {
        header,
        body: PreviewBody::Table {
            columns,
            rows,
            count,
        },
        warnings,
        query,
    })
}

/// The list previewer (PD-114): [`list_table`], else the §6.3 Fallback.
pub fn list_preview(ctx: &PreviewCtx<'_>) -> PreviewModel {
    list_table(ctx).unwrap_or_else(|| fallback_preview(ctx))
}

/// Searches show their query (§6.3); keyed ops none.
pub(crate) fn query_display(spec: &OperationSpec, params: &Value) -> Option<String> {
    match spec.target_display {
        TargetDisplay::Query { param } => params
            .get(param)
            .and_then(Value::as_str)
            .map(escape_for_display),
        _ => None,
    }
}

fn requested_all_fields(spec: &OperationSpec, params: &Value) -> bool {
    spec.field_rules
        .and_then(|r| r.fields_param)
        .and_then(|name| params.get(name))
        .and_then(Value::as_array)
        .is_some_and(|list| list.iter().any(|v| v.as_str() == Some("*all")))
}

fn item_count(spec: &OperationSpec, view: &ReadView<'_>) -> Option<ItemCount> {
    let len = |v: &Value| {
        v.as_array()
            .map(|a| u64::try_from(a.len()).unwrap_or(u64::MAX))
    };
    if let Some(paging) = spec.paginated {
        return Some(ItemCount {
            shown: view
                .candidate
                .get(paging.items_key)
                .and_then(len)
                .unwrap_or(0),
            total: view.server_total,
            more_available: view.more_available,
        });
    }
    len(view.candidate).map(|n| ItemCount {
        shown: n,
        total: Some(n),
        more_available: false,
    })
}

/// The requested (or default) `fields`, else the keys of the result items (first seen first).
fn fields_included(spec: &OperationSpec, params: &Value, candidate: &Value) -> Vec<String> {
    if let Some(rules) = spec.field_rules
        && let Some(name) = rules.fields_param
    {
        if let Some(list) = params.get(name).and_then(Value::as_array) {
            return list
                .iter()
                .filter_map(Value::as_str)
                .map(escape_for_display)
                .collect();
        }
        if !rules.default_fields.is_empty() {
            return rules
                .default_fields
                .iter()
                .map(|f| (*f).to_owned())
                .collect();
        }
    }
    let items: Vec<&Value> = match (spec.paginated, candidate) {
        (Some(paging), _) => candidate
            .get(paging.items_key)
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_default(),
        (None, Value::Array(a)) => a.iter().collect(),
        (None, other) => vec![other],
    };
    let mut out: Vec<String> = Vec::new();
    // A set, not `out.contains`: an item may hold ~10^5 distinct keys.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for item in items {
        for key in item.as_object().into_iter().flat_map(Map::keys) {
            let shown = escape_for_display(key);
            if seen.insert(shown.clone()) {
                out.push(shown);
            }
        }
    }
    out
}

fn write_model(ctx: &PreviewCtx<'_>, view: &WriteView<'_>) -> PreviewModel {
    let spec = ctx.spec;
    let (views, hidden): (Vec<RequestView>, Vec<u64>) =
        view.requests.iter().map(request_view).unzip();
    let (mut bidi, mut other) = (0, 0);
    for r in view.requests {
        let (b, o) = count_request(r);
        bidi += b;
        other += o;
    }

    let body = match view.hold {
        Hold::Conflict => PreviewBody::Conflict {
            summary: view
                .enrichment
                .and_then(|v| v.conflict.clone())
                .unwrap_or_else(|| "conflict: changed since the agent read it".to_owned()),
            diff_text: view
                .enrichment
                .map(|v| v.diff_text.clone())
                .unwrap_or_default(),
            // M7 Δ2 (M6 T10 review M-5): the card shows the requests; the rendered diffs base →
            // current and base → outgoing are Confluence's (Task 15), empty until then.
            base_to_current: Vec::new(),
            intended: Vec::new(),
            requests: views,
        },
        Hold::UnresolvedName => match view.enrichment.and_then(|v| v.unresolved.as_ref()) {
            Some((param, value, matches, candidates)) => PreviewBody::UnresolvedName {
                param: param.clone(),
                value: escape_for_display(value),
                matches: *matches,
                candidates: candidates.iter().map(|c| escape_for_display(c)).collect(),
            },
            None => PreviewBody::enrichment_error(None, UNUSABLE_ENRICHMENT_TEXT, None),
        },
        Hold::EnrichmentError => match view.failure {
            Some(f) => {
                PreviewBody::enrichment_error(f.status, &escape_for_display(&f.text), f.outcome)
            }
            None => PreviewBody::enrichment_error(None, UNUSABLE_ENRICHMENT_TEXT, None),
        },
        Hold::Preview | Hold::Collision | Hold::IdentityMismatch => {
            PreviewBody::WriteRequests { requests: views }
        }
    };

    let mut warnings: Vec<Warning> = view
        .enrichment
        .map(|v| v.warnings.clone())
        .unwrap_or_default();
    invisible_warnings(&mut warnings, bidi, other);
    let mut idents = Identifiers::default();
    for name in WRITE_IDENTIFIER_PARAMS {
        match ctx.params.get(*name) {
            Some(Value::String(s)) => idents.check(s),
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .for_each(|s| idents.check(s)),
            _ => {}
        }
    }
    idents.push_warnings(&mut warnings);

    PreviewModel {
        header: PreviewHeader {
            instance_alias: ctx.instance_alias.to_owned(),
            op_id: spec.id.to_owned(),
            class: class_name(spec),
            item_count: None,
            byte_size: view
                .requests
                .iter()
                .map(|r| u64::try_from(r.body.len()).unwrap_or(u64::MAX))
                .sum(),
            fields_included: ctx
                .params
                .as_object()
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default(),
            // M7 Δ2 (T8 review m-2): the request bytes the views replace by digest lines.
            hidden_in_preview_bytes: hidden.into_iter().fold(0, u64::saturating_add),
            bidi_controls: bidi,
            other_invisible: other,
            executes_as: None,
            receipt_fields: receipt_fields(spec),
            query: None,
            release_blocked: None,
        },
        body,
        warnings,
        query: None,
    }
}

/// M7 Δ2 (PD-109): a part body of a multipart request is shown as sent only when it is UTF-8, at
/// most this many bytes and no file part; otherwise its one size and SHA-256 line stands for it.
const PART_SHOWN_MAX_BYTES: usize = 4 * 1024;

/// M7 Δ2 backstop: any other request body above this size is shown as its size and SHA-256 only.
const BODY_SHOWN_MAX_BYTES: usize = 1024 * 1024;

/// The view of one request (§5.4 step 4, M7 Δ2, plan review I-4) and the bytes of its body the
/// view does not show (`hidden_in_preview_bytes`, T8 review m-2). A `multipart/form-data` body is
/// the text envelope as sent (boundary lines, part headers, the parts that are UTF-8 and at most
/// [`PART_SHOWN_MAX_BYTES`]) with every file part, and every other part, replaced by
/// [`body_digest_line`]: the preview never carries a file. A multipart body that does not split
/// exactly into its parts, and any other body above [`BODY_SHOWN_MAX_BYTES`], is a
/// [`BodyView::Digest`] (fail closed: never text, never base64). Anything else is the UTF-8 text,
/// or base64. `WRITE_APPROVED` and `request_set_hash` still cover the real bytes.
fn request_view(r: &HttpRequestSpec) -> (RequestView, u64) {
    let (body, hidden) = body_view(r);
    let view = RequestView {
        index: r.index,
        method: r.method.clone(),
        resolved_url: r.resolved_url.clone(),
        content_type: r.content_type.clone(),
        body,
    };
    (view, hidden)
}

fn body_view(r: &HttpRequestSpec) -> (BodyView, u64) {
    let len = len_u64(r.body.len());
    let digest = || {
        let view = BodyView::Digest {
            bytes: len,
            sha256: crate::payloads::sha256_hex(&r.body),
        };
        (view, len)
    };
    if r.body.is_empty() {
        return (BodyView::None, 0);
    }
    if let Some(ct) = r.content_type.as_deref().filter(|ct| is_multipart(ct)) {
        return match multipart_parts(ct, &r.body) {
            Some(split) => {
                let (text, hidden) = split.envelope();
                (BodyView::Text(text), hidden)
            }
            None => digest(),
        };
    }
    if r.body.len() > BODY_SHOWN_MAX_BYTES {
        return digest();
    }
    match std::str::from_utf8(&r.body) {
        Ok(text) => (BodyView::Text(text.to_owned()), 0),
        Err(_) => (
            BodyView::Base64(base64::engine::general_purpose::STANDARD.encode(&r.body)),
            0,
        ),
    }
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The media type of `content_type` is `multipart/form-data` (ASCII case-insensitive).
fn is_multipart(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("multipart/form-data"))
}

/// The `boundary` parameter of a multipart content type (quotes removed); `None` when absent or
/// empty.
fn multipart_boundary(content_type: &str) -> Option<&str> {
    content_type.split(';').skip(1).find_map(|param| {
        let (name, value) = param.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("boundary") {
            return None;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        (!value.is_empty()).then_some(value)
    })
}

/// The first occurrence of `needle` in `hay`.
pub(crate) fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A multipart body split exactly into its parts: `--b CRLF headers CRLF CRLF body` per part, each
/// followed by `CRLF --b`, the last by `--` CRLF (the layout `confluence_ext::multipart` writes).
struct MultipartSplit<'a> {
    boundary: &'a str,
    /// `(headers, body)` per part, in order.
    parts: Vec<(&'a str, &'a [u8])>,
}

/// [`MultipartSplit`] of `body`, or `None` when it does not follow that layout exactly (no
/// boundary, a missing delimiter, header bytes that are not UTF-8 or longer than
/// [`PART_SHOWN_MAX_BYTES`], anything after the closing delimiter).
fn multipart_parts<'a>(content_type: &'a str, body: &'a [u8]) -> Option<MultipartSplit<'a>> {
    let boundary = multipart_boundary(content_type)?;
    let open = format!("--{boundary}\r\n");
    let next = format!("\r\n--{boundary}");
    let mut rest = body.strip_prefix(open.as_bytes())?;
    let mut parts = Vec::new();
    loop {
        let head_end = find_bytes(rest, b"\r\n\r\n")?;
        if head_end > PART_SHOWN_MAX_BYTES {
            return None;
        }
        let headers = std::str::from_utf8(rest.get(..head_end)?).ok()?;
        let after = rest.get(head_end + 4..)?;
        let end = find_bytes(after, next.as_bytes())?;
        parts.push((headers, after.get(..end)?));
        let tail = after.get(end + next.len()..)?;
        if tail == b"--\r\n" {
            return Some(MultipartSplit { boundary, parts });
        }
        rest = tail.strip_prefix(b"\r\n")?;
    }
}

impl MultipartSplit<'_> {
    /// A part whose headers name a file (`filename` in its `Content-Disposition`): never shown.
    fn is_file(headers: &str) -> bool {
        headers.lines().any(|line| {
            let line = line.to_ascii_lowercase();
            line.starts_with("content-disposition:") && line.contains("filename")
        })
    }

    /// The text envelope and the bytes it replaces by digest lines.
    fn envelope(&self) -> (String, u64) {
        let b = self.boundary;
        let mut out = format!("--{b}\r\n");
        let mut hidden = 0u64;
        for (i, (headers, body)) in self.parts.iter().enumerate() {
            if i > 0 {
                out.push_str(&format!("\r\n--{b}\r\n"));
            }
            out.push_str(headers);
            out.push_str("\r\n\r\n");
            match std::str::from_utf8(body) {
                Ok(text) if !Self::is_file(headers) && body.len() <= PART_SHOWN_MAX_BYTES => {
                    out.push_str(text);
                }
                _ => {
                    let n = len_u64(body.len());
                    out.push_str(&body_digest_line(n, &crate::payloads::sha256_hex(body)));
                    hidden = hidden.saturating_add(n);
                }
            }
        }
        out.push_str(&format!("\r\n--{b}--\r\n"));
        (out, hidden)
    }

    /// §6.4 counts over the part headers and every part body that is UTF-8 (shown or not).
    fn count(&self) -> (u64, u64) {
        self.parts
            .iter()
            .map(|(headers, body)| {
                let body = std::str::from_utf8(body).map_or((0, 0), invisible::count);
                add(invisible::count(headers), body)
            })
            .fold((0, 0), add)
    }
}

// ---- classifier counts and identifiers -------------------------------------------------------

/// §6.4 counts over every decoded string (object keys and values), never over serialized JSON:
/// `serde_json` writes C0 controls as escapes, which the classifier would not see (T6 handoff).
pub(crate) fn count_value(v: &Value) -> (u64, u64) {
    match v {
        Value::String(s) => invisible::count(s),
        Value::Array(items) => items.iter().map(count_value).fold((0, 0), add),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| add(invisible::count(k), count_value(v)))
            .fold((0, 0), add),
        _ => (0, 0),
    }
}

fn add(a: (u64, u64), b: (u64, u64)) -> (u64, u64) {
    (a.0 + b.0, a.1 + b.1)
}

/// A request body: a multipart body per part (its headers, a filename and a comment included,
/// even beside a binary file), else decoded JSON strings, else the UTF-8 text, else nothing
/// (binary).
fn count_request(r: &HttpRequestSpec) -> (u64, u64) {
    let split = r
        .content_type
        .as_deref()
        .filter(|ct| is_multipart(ct))
        .and_then(|ct| multipart_parts(ct, &r.body));
    if let Some(split) = split {
        return split.count();
    }
    match serde_json::from_slice::<Value>(&r.body) {
        Ok(v) => count_value(&v),
        Err(_) => std::str::from_utf8(&r.body).map_or((0, 0), invisible::count),
    }
}

pub(crate) fn invisible_warnings(warnings: &mut Vec<Warning>, bidi: u64, other: u64) {
    if bidi > 0 {
        warnings.push(Warning::new(
            WarningId::BidiControls,
            warning::bidi_controls(bidi),
        ));
    }
    if other > 0 {
        warnings.push(Warning::new(
            WarningId::OtherInvisible,
            warning::other_invisible(other),
        ));
    }
}

/// Mixed-script hits (§6.4), only on identifiers: issue/project/space keys, usernames and URL
/// hosts. Names of statuses, projects or components are prose and never checked.
#[derive(Default)]
struct Identifiers {
    hits: Vec<String>,
}

impl Identifiers {
    fn check(&mut self, ident: &str) {
        if is_mixed_script(ident) && !self.hits.iter().any(|h| h == ident) {
            self.hits.push(ident.to_owned());
        }
    }

    /// A URL host, IDNA-decoded first: a punycode host is all ASCII and never mixed (T6 handoff).
    fn check_url(&mut self, s: &str) {
        let Some(host) = url_host(s) else { return };
        let (unicode, _) = idna::domain_to_unicode(host);
        self.check(&unicode);
    }

    /// Walks `v`; `user` says the current value is a user object (or a list of them).
    fn scan(&mut self, v: &Value, user: bool) {
        match v {
            Value::String(s) => self.check_url(s),
            Value::Array(items) => items.iter().for_each(|i| self.scan(i, user)),
            Value::Object(map) => {
                for (k, v) in map {
                    match v {
                        Value::String(s) => {
                            if IDENTIFIER_KEYS.contains(&k.as_str()) || (user && k == "name") {
                                self.check(s);
                            }
                            self.check_url(s);
                        }
                        _ => self.scan(v, USER_OBJECT_KEYS.contains(&k.as_str())),
                    }
                }
            }
            _ => {}
        }
    }

    fn push_warnings(self, warnings: &mut Vec<Warning>) {
        for hit in self.hits.into_iter().take(MAX_MIXED_SCRIPT_WARNINGS) {
            warnings.push(Warning::new(
                WarningId::MixedScript,
                warning::mixed_script(&escape_for_display(&hit)),
            ));
        }
    }
}

/// The host of an absolute `http(s)://` URL (no userinfo, no port); IP literals are skipped.
fn url_host(s: &str) -> Option<&str> {
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    if host_port.starts_with('[') {
        return None;
    }
    let host = match host_port.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host_port,
    };
    (!host.is_empty()).then_some(host)
}
