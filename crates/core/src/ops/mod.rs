//! The op table (§2.3, C.7): one [`OpImpl`] per registry id. Executors turn validated params (and,
//! for writes, the enrichment verdict) into the exact read plan or HTTP request list (§5.1 inv. 3);
//! previewers build the preview model; enrichment and stale rules are GET plans plus pure judges.
//!
//! Everything here is a pure function of its context: no I/O, no clock, no audit. The engine
//! fetches what a plan names and hands the parsed 2xx JSON bodies to the judge. Executors are
//! deterministic (same context, same bytes): `WRITE_APPROVED` hashes their output.

pub mod confluence;
pub mod generic;
pub mod jira;
pub mod stale;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

use atlas_duck_atlassian::{
    GetCall, HttpRequestSpec, NormalizedBaseUrl, PagedCall, SearchCall, TemplateError, build_url,
};
use atlas_duck_ipc::envelope::ErrorCode;
use atlas_duck_preview::{OutcomeKind, PreviewBody, PreviewHeader, Warning};
use atlas_duck_registry::{Method, OperationSpec};
use serde_json::{Map, Value};

use crate::lifecycle::model::Hold;
use crate::validate::{ValidationError, invalid};

/// C.7 (+ PD-26 `enrich`, `enrich_keys`). Function pointers only, no closures.
#[derive(Clone, Copy)]
pub struct OpImpl {
    pub executor: ExecutorFn,
    pub previewer: PreviewerFn,
    /// §5.4 step 5 per-op rule; only writes have one (PD-10).
    pub stale_check: Option<StaleCheckFn>,
    /// Writes only: the enrichment GETs and their judge (§5.4 step 2).
    pub enrich: Option<EnrichFn>,
    /// Params whose edit re-runs enrichment (§5.4 step 4, `edit::apply_edits`).
    pub enrich_keys: &'static [&'static str],
}

impl fmt::Debug for OpImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpImpl")
            .field("stale_check", &self.stale_check.is_some())
            .field("enrich", &self.enrich.is_some())
            .field("enrich_keys", &self.enrich_keys)
            .finish_non_exhaustive()
    }
}

pub type ExecutorFn = fn(&ExecCtx<'_>) -> Result<ExecPlan, ExecError>;
pub type PreviewerFn = fn(&PreviewCtx<'_>) -> PreviewModel;
pub type StaleCheckFn = &'static StaleRule;
pub type EnrichFn = &'static EnrichRule;

/// The stale-check GETs (logged `PREVIEW_FETCH {purpose: stale_check}`) and their judge, which
/// gets the parsed 2xx JSON bodies in plan order.
pub struct StaleRule {
    pub plan: fn(&StaleCtx<'_>) -> Vec<GetCall>,
    pub judge: fn(&StaleCtx<'_>, &[Value]) -> StaleVerdict,
}

/// The enrichment GETs and their judge, which gets the parsed 2xx JSON bodies in plan order.
pub struct EnrichRule {
    pub plan: fn(&EnrichCtx<'_>) -> Vec<(EnrichPurpose, GetCall)>,
    pub judge: fn(&EnrichCtx<'_>, &[Value]) -> EnrichVerdict,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExecPlan {
    Read(ReadPlan),
    /// Exactly the requests `WRITE_APPROVED` hashes and `send_approved` sends.
    Write(Vec<HttpRequestSpec>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReadPlan {
    Get(GetCall),
    /// `max_items`: the clamped `max` (`read_paginated_ctl`).
    Paged {
        call: PagedCall,
        max_items: u64,
    },
    /// `jira.search`, the one allowlisted read `POST` (`read_paginated_search_ctl`).
    Search {
        call: SearchCall,
        items_key: String,
        max_items: u64,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExecError {
    /// PD-09: a write completed in M5/M7; answered at validation as `internal`.
    NotInThisBuild,
    /// A static check only the op knows (e.g. the `confluence.search` CQL rules): answered at
    /// validation with the error's code, never echoing the offending value.
    Invalid(ValidationError),
    /// Additive (plan Δ C.7): the write's request list needs a `Preview` enrichment verdict
    /// (resolved ids, current title/space) that is not there yet. A dry executor call at
    /// validation passes on it; the engine renders a write only after `Enriched(Preview)`.
    EnrichmentRequired,
}

/// PD-09 (plan text): the `internal` message of a write completed in M5/M7.
pub const NOT_IN_THIS_BUILD_MESSAGE: &str = "operation not available in this build";

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecError::NotInThisBuild => f.write_str(NOT_IN_THIS_BUILD_MESSAGE),
            ExecError::Invalid(e) => fmt::Display::fmt(e, f),
            ExecError::EnrichmentRequired => f.write_str("the write is not enriched yet"),
        }
    }
}

impl std::error::Error for ExecError {}

/// What an executor sees. `params` are the params that run (after edits); never the delivery
/// view (`executed_params`).
pub struct ExecCtx<'a> {
    pub spec: &'static OperationSpec,
    pub params: &'a Value,
    pub base: &'a NormalizedBaseUrl,
    /// The latest enrichment verdict (writes); `None` for reads and the validation dry call.
    pub enrichment: Option<&'a EnrichVerdict>,
    /// `Validated::effective_max`: the clamped `max` of ops with a `max` cap.
    pub effective_max: Option<u32>,
}

pub struct EnrichCtx<'a> {
    pub spec: &'static OperationSpec,
    pub params: &'a Value,
}

pub struct StaleCtx<'a> {
    pub spec: &'static OperationSpec,
    pub params: &'a Value,
    /// `EnrichVerdict::baseline` of the approved revision.
    pub baseline: &'a Value,
}

/// `PREVIEW_FETCH {purpose}` of an enrichment GET (PD-24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrichPurpose {
    Enrich,
    /// A name-resolution lookup (project, issue type, transition, ...).
    Resolve,
}

impl EnrichPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            EnrichPurpose::Enrich => "enrich",
            EnrichPurpose::Resolve => "resolve",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum StaleVerdict {
    Unchanged,
    /// `delta`: the §5.4 step 5 baseline delta the re-review leads with (display-escaped).
    Changed {
        delta: String,
    },
}

/// Redacting `Debug` (§7.7): the delta can name Atlassian values.
impl fmt::Debug for StaleVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StaleVerdict::Unchanged => f.write_str("Unchanged"),
            StaleVerdict::Changed { delta } => {
                write!(f, "Changed {{ delta: <{} bytes> }}", delta.len())
            }
        }
    }
}

/// The judge's answer (§5.4 step 2). `hold` decides approvability together with the instance
/// state; `baseline` is the stale-check baseline; `resolved` feeds the executor.
#[derive(Clone, PartialEq)]
pub struct EnrichVerdict {
    pub hold: Hold,
    pub baseline: Value,
    pub resolved: Map<String, Value>,
    /// `(param, submitted value, match count, candidate names ≤ 10)` for `UnresolvedName`.
    pub unresolved: Option<(String, String, u64, Vec<String>)>,
    /// The conflict summary for `Conflict` (display-escaped).
    pub conflict: Option<String>,
    pub warnings: Vec<Warning>,
    /// Additive: the `Conflict` preview's diff text (agent's read state against the current
    /// one; display-escaped). Empty for every other hold.
    pub diff_text: String,
}

impl EnrichVerdict {
    /// A `Preview` verdict.
    pub fn preview(baseline: Value, resolved: Map<String, Value>) -> EnrichVerdict {
        EnrichVerdict {
            hold: Hold::Preview,
            baseline,
            resolved,
            unresolved: None,
            conflict: None,
            warnings: Vec::new(),
            diff_text: String::new(),
        }
    }

    /// An answer the judge cannot use (a missing field, a short response list): Approve stays
    /// disabled (fail closed).
    pub fn unusable() -> EnrichVerdict {
        EnrichVerdict {
            hold: Hold::EnrichmentError,
            ..EnrichVerdict::preview(Value::Null, Map::new())
        }
    }
}

/// Redacting `Debug` (§7.7): baseline and resolved values are Atlassian data.
impl fmt::Debug for EnrichVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrichVerdict")
            .field("hold", &self.hold)
            .field("resolved", &self.resolved.keys().collect::<Vec<_>>())
            .field("unresolved", &self.unresolved.is_some())
            .field("conflict", &self.conflict.is_some())
            .field("warnings", &self.warnings.len())
            .finish_non_exhaustive()
    }
}

/// What a previewer sees. The engine fills `executes_as` and everything outside the model
/// (`candidate_rev`, approvability, Raw pager, `also_appears_in`).
pub struct PreviewCtx<'a> {
    pub spec: &'static OperationSpec,
    pub instance_alias: &'a str,
    /// The params that run (reads: the validated params).
    pub params: &'a Value,
    pub input: PreviewInput<'a>,
}

pub enum PreviewInput<'a> {
    Read(ReadView<'a>),
    Write(WriteView<'a>),
}

/// A read's release candidate (`ReleaseItem::Result`); upstream-error and outcome cards are the
/// engine's (§6.3).
pub struct ReadView<'a> {
    /// The bare candidate body (paged: the concatenated object, server totals unchanged).
    pub candidate: &'a Value,
    /// Exact candidate byte size.
    pub byte_size: u64,
    /// `PagedOutcome::server_total`.
    pub server_total: Option<u64>,
    /// Paging stopped before the results ended (`next_start` is `Some`).
    pub more_available: bool,
    /// `Validated::truncated_by_clamp`: the agent asked for more than the hard cap.
    pub clamped: bool,
}

pub struct WriteView<'a> {
    /// The executor's request list (empty while no `Preview` verdict exists).
    pub requests: &'a [HttpRequestSpec],
    pub hold: Hold,
    pub enrichment: Option<&'a EnrichVerdict>,
    /// The failed enrichment fetch behind an `EnrichmentError` hold (§6.3 "Enrichment error").
    pub failure: Option<&'a EnrichFailure>,
}

/// An enrichment fetch that did not return usable 2xx JSON (§5.4 step 2 table).
#[derive(Clone, PartialEq, Eq)]
pub struct EnrichFailure {
    pub status: Option<u16>,
    /// `errorMessages`/`errors` text (capped by the preview builder).
    pub text: String,
    pub outcome: Option<OutcomeKind>,
}

impl fmt::Debug for EnrichFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrichFailure")
            .field("status", &self.status)
            .field("text", &format_args!("len={}", self.text.len()))
            .field("outcome", &self.outcome)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PreviewModel {
    pub header: PreviewHeader,
    pub body: PreviewBody,
    pub warnings: Vec<Warning>,
    /// Additive: the effective query as sent, display-escaped (§6.3: Confluence search shows the
    /// CQL after the §7.4 rewrite; `jira.search` its JQL). `None` for keyed ops.
    pub query: Option<String>,
}

/// Redacting `Debug` (§7.7): no body content.
impl fmt::Debug for PreviewModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreviewModel")
            .field("op_id", &self.header.op_id)
            .field(
                "warnings",
                &self.warnings.iter().map(|w| w.id).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

const READ: OpImpl = OpImpl {
    executor: generic::read_executor,
    previewer: generic::fallback_preview,
    stale_check: None,
    enrich: None,
    enrich_keys: &[],
};

/// PD-09: completed in M5/M7.
const LATER_WRITE: OpImpl = OpImpl {
    executor: generic::not_in_this_build,
    previewer: generic::fallback_preview,
    stale_check: None,
    enrich: None,
    enrich_keys: &[],
};

/// One entry per registry id, in registry order (U-05: `tests/op_table.rs` checks the set).
static ENTRIES: &[(&str, OpImpl)] = &[
    ("jira.myself", READ),
    ("jira.project.list", READ),
    ("jira.project.get", READ),
    (
        "jira.issue.get",
        OpImpl {
            executor: jira::issue_get_executor,
            ..READ
        },
    ),
    ("jira.search", READ),
    ("jira.comment.list", READ),
    ("jira.worklog.list", READ),
    ("jira.transition.list", READ),
    ("jira.issue.editmeta", READ),
    ("jira.createmeta.issuetypes", READ),
    ("jira.createmeta.fields", READ),
    ("jira.field.list", READ),
    ("jira.issuelinktype.list", READ),
    ("jira.attachment.meta", READ),
    ("jira.user.assignable", READ),
    ("jira.board.list", READ),
    ("jira.sprint.list", READ),
    ("jira.sprint.issues", READ),
    ("jira.backlog.issues", READ),
    (
        "jira.issue.create",
        OpImpl {
            executor: jira::issue_create_executor,
            previewer: generic::write_preview,
            stale_check: None,
            enrich: Some(&jira::ISSUE_CREATE_ENRICH),
            enrich_keys: &["project", "issuetype"],
        },
    ),
    (
        "jira.issue.edit",
        OpImpl {
            executor: jira::issue_edit_executor,
            previewer: generic::write_preview,
            stale_check: Some(&stale::ISSUE_EDIT),
            enrich: Some(&jira::ISSUE_EDIT_ENRICH),
            enrich_keys: &["fields", "update"],
        },
    ),
    (
        "jira.comment.add",
        OpImpl {
            executor: jira::comment_add_executor,
            previewer: generic::write_preview,
            stale_check: None,
            enrich: None,
            enrich_keys: &[],
        },
    ),
    (
        "jira.issue.transition",
        OpImpl {
            executor: jira::issue_transition_executor,
            previewer: generic::write_preview,
            stale_check: Some(&stale::ISSUE_TRANSITION),
            enrich: Some(&jira::ISSUE_TRANSITION_ENRICH),
            enrich_keys: &["transition"],
        },
    ),
    ("jira.issue.assign", LATER_WRITE),
    ("jira.worklog.add", LATER_WRITE),
    ("jira.issuelink.create", LATER_WRITE),
    ("jira.sprint.move_issues", LATER_WRITE),
    ("jira.backlog.move_issues", LATER_WRITE),
    ("confluence.user.current", READ),
    ("confluence.space.list", READ),
    ("confluence.space.get", READ),
    ("confluence.page.get", READ),
    ("confluence.page.find", READ),
    (
        "confluence.search",
        OpImpl {
            executor: confluence::search_executor,
            previewer: confluence::search_preview,
            ..READ
        },
    ),
    ("confluence.page.children", READ),
    ("confluence.comment.list", READ),
    ("confluence.label.list", READ),
    ("confluence.attachment.list", READ),
    ("confluence.page.history", READ),
    ("confluence.page.create", LATER_WRITE),
    (
        "confluence.page.update",
        OpImpl {
            executor: confluence::page_update_executor,
            previewer: generic::write_preview,
            stale_check: Some(&stale::PAGE_UPDATE),
            enrich: Some(&confluence::PAGE_UPDATE_ENRICH),
            enrich_keys: &["body", "title"],
        },
    ),
    ("confluence.page.move", LATER_WRITE),
    ("confluence.comment.add", LATER_WRITE),
    ("confluence.label.add", LATER_WRITE),
    ("confluence.label.remove", LATER_WRITE),
    ("confluence.attachment.upload", LATER_WRITE),
];

/// The rows of the explicit table before deduplication: U-05 checks it equals `op_table().len()`,
/// so a duplicated id cannot silently shadow another row.
pub fn entry_count() -> usize {
    ENTRIES.len()
}

/// C.7: one entry per registry id (46).
pub fn op_table() -> &'static BTreeMap<&'static str, OpImpl> {
    static TABLE: OnceLock<BTreeMap<&'static str, OpImpl>> = OnceLock::new();
    TABLE.get_or_init(|| ENTRIES.iter().copied().collect())
}

// ---- helpers shared by the product modules ---------------------------------------------------

/// The `{name}` placeholders of an endpoint template, in order.
pub(crate) fn placeholders(template: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else { break };
        out.push(&after[..close]);
        rest = &after[close + 1..];
    }
    out
}

/// Only the template's placeholder params (C.4: `GetCall.params` fills placeholders only).
pub(crate) fn path_params(template: &str, params: &Value) -> Value {
    let mut out = Map::new();
    for name in placeholders(template) {
        if let Some(v) = params.get(name) {
            out.insert(name.to_owned(), v.clone());
        }
    }
    Value::Object(out)
}

/// `build_url` with its error as an executor error: a missing or unusable placeholder value is
/// `validation` for that param, a malformed template is `internal` (registry data).
pub(crate) fn resolve_url(
    base: &NormalizedBaseUrl,
    template: &str,
    params: &Value,
    query: &[(String, String)],
) -> Result<String, ExecError> {
    build_url(base, template, &path_params(template, params), query)
        .map(|u| u.as_str().to_owned())
        .map_err(|e| ExecError::Invalid(template_error(&e)))
}

fn template_error(e: &TemplateError) -> ValidationError {
    match e {
        TemplateError::MissingParam(name) => invalid(name, "required", None),
        TemplateError::BadParam(name) => invalid(name, "not usable in a URL path", None),
        TemplateError::BadTemplate => ValidationError {
            code: ErrorCode::Internal,
            message: "operation endpoint cannot be built".to_owned(),
            details: Map::new(),
        },
    }
}

/// A `GetCall` for a fixed template and query, with the placeholder params taken from `params`.
pub(crate) fn get_call(template: &str, params: &Value, query: &[(&str, &str)]) -> GetCall {
    GetCall {
        endpoint_template: template.to_owned(),
        params: path_params(template, params),
        query: query
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

pub(crate) fn method_name(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
    }
}

/// The op's one `application/json` write request (every v1 write is one request, §7.2) to its
/// registry endpoint.
pub(crate) fn json_request(ctx: &ExecCtx<'_>, body: &Value) -> Result<ExecPlan, ExecError> {
    let method = method_name(ctx.spec.endpoint.method);
    let resolved_url = resolve_url(ctx.base, ctx.spec.endpoint.path, ctx.params, &[])?;
    let body = serde_json::to_vec(body).map_err(|_| {
        ExecError::Invalid(ValidationError {
            code: ErrorCode::Internal,
            message: "request body cannot be serialized".to_owned(),
            details: Map::new(),
        })
    })?;
    Ok(ExecPlan::Write(vec![HttpRequestSpec {
        index: 0,
        method: method.to_owned(),
        resolved_url,
        content_type: Some("application/json".to_owned()),
        body,
    }]))
}

/// The largest `EnrichVerdict::diff_text` (bytes, including the trailing ellipsis).
pub const DIFF_TEXT_CAP_BYTES: usize = 16 * 1024;

/// Cuts a conflict diff to [`DIFF_TEXT_CAP_BYTES`] at a char boundary; a cut text ends in `…`.
pub(crate) fn cap_diff_text(s: &str) -> String {
    if s.len() <= DIFF_TEXT_CAP_BYTES {
        return s.to_owned();
    }
    let mut end = DIFF_TEXT_CAP_BYTES - '…'.len_utf8();
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// A string param, or `""`.
pub(crate) fn str_param<'a>(params: &'a Value, name: &str) -> &'a str {
    params.get(name).and_then(Value::as_str).unwrap_or("")
}
