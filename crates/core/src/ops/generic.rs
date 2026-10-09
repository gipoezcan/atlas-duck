//! Registry-driven executors and previewers (PD-09): the template/paginated read plan every read
//! uses, the `NotInThisBuild` write executor, the §6.3 Fallback (JSON tree) and the write-request
//! preview, and the receipt projection (§4.2).

use atlas_duck_atlassian::{GetCall, HttpRequestSpec, PagedCall, SearchCall};
use atlas_duck_preview::invisible::{self, escape_for_display};
use atlas_duck_preview::mixed_script::is_mixed_script;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_preview::{BodyView, ItemCount, PreviewBody, PreviewHeader, RequestView, json_tree};
use atlas_duck_registry::{
    BodySource, Endpoint, OpClass, OperationSpec, Projection, QueryValue, TargetDisplay,
};
use base64::Engine as _;
use serde_json::{Map, Value};

use super::{
    ExecCtx, ExecError, ExecPlan, PreviewCtx, PreviewInput, PreviewModel, ReadPlan, ReadView,
    WriteView, path_params, resolve_url,
};
use crate::lifecycle::model::Hold;

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

/// PD-09: writes completed in M5/M7.
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
/// listed fields (dotted paths) that exist, the agent's own labels, or `{}`.
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
        Projection::Fields(paths) => {
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
    }
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
        Projection::Fields(paths) => paths.iter().map(|p| (*p).to_owned()).collect(),
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
    let spec = ctx.spec;
    let candidate = view.candidate;
    let tree = json_tree(candidate);
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

    let query = query_display(spec, ctx.params);
    PreviewModel {
        header: PreviewHeader {
            instance_alias: ctx.instance_alias.to_owned(),
            op_id: spec.id.to_owned(),
            class: class_name(spec),
            item_count,
            byte_size: view.byte_size,
            fields_included: fields_included(spec, ctx.params, candidate),
            hidden_in_preview_bytes: tree.hidden_bytes(),
            bidi_controls: bidi,
            other_invisible: other,
            executes_as: None,
            receipt_fields: Vec::new(),
            query: query.clone(),
        },
        body: PreviewBody::JsonTree { tree },
        warnings,
        query,
    }
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
    for item in items {
        for key in item.as_object().into_iter().flat_map(Map::keys) {
            let shown = escape_for_display(key);
            if !out.contains(&shown) {
                out.push(shown);
            }
        }
    }
    out
}

fn write_model(ctx: &PreviewCtx<'_>, view: &WriteView<'_>) -> PreviewModel {
    let spec = ctx.spec;
    let views: Vec<RequestView> = view.requests.iter().map(request_view).collect();
    let (mut bidi, mut other) = (0, 0);
    for r in view.requests {
        let (b, o) = count_body(&r.body);
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
            hidden_in_preview_bytes: 0,
            bidi_controls: bidi,
            other_invisible: other,
            executes_as: None,
            receipt_fields: receipt_fields(spec),
            query: None,
        },
        body,
        warnings,
        query: None,
    }
}

/// Raw view of one request: the body as UTF-8 text, or base64 for anything else (§5.4 step 4).
fn request_view(r: &HttpRequestSpec) -> RequestView {
    let body = if r.body.is_empty() {
        BodyView::None
    } else {
        match std::str::from_utf8(&r.body) {
            Ok(text) => BodyView::Text(text.to_owned()),
            Err(_) => BodyView::Base64(base64::engine::general_purpose::STANDARD.encode(&r.body)),
        }
    };
    RequestView {
        index: r.index,
        method: r.method.clone(),
        resolved_url: r.resolved_url.clone(),
        content_type: r.content_type.clone(),
        body,
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

/// A request body: decoded JSON strings, else the UTF-8 text, else nothing (binary).
fn count_body(body: &[u8]) -> (u64, u64) {
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => count_value(&v),
        Err(_) => std::str::from_utf8(body).map_or((0, 0), invisible::count),
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
