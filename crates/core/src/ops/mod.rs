//! The op table (§2.3, C.7): one [`OpImpl`] per registry id. Executors turn validated params (and,
//! for writes, the enrichment verdict) into the exact read plan or HTTP request list (§5.1 inv. 3);
//! previewers build the preview model; enrichment and stale rules are GET plans plus pure judges.
//!
//! Everything here is a pure function of its context: no I/O, no clock, no audit. The engine
//! fetches what a plan names and hands the parsed 2xx JSON bodies to the judge. Executors are
//! deterministic (same context, same bytes): `WRITE_APPROVED` hashes their output.

pub mod confluence;
pub(crate) mod confluence_body;
pub(crate) mod confluence_preview;
pub mod generic;
pub mod jira;
pub(crate) mod jira_body;
pub mod jira_ext;
pub mod jira_preview;
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

/// Staged enrichment (Δ3 C.7): `plan` gets the parsed 2xx JSON answers so far (in the order
/// their GETs were planned, over every earlier round) and names the next round's GETs or says
/// `Judge`; `judge` then gets every answer. The engine runs at most [`MAX_ENRICH_STAGES`] rounds.
pub struct EnrichRule {
    pub plan: fn(&EnrichCtx<'_>, &[Value]) -> EnrichStep,
    pub judge: fn(&EnrichCtx<'_>, &[Value]) -> EnrichVerdict,
}

impl fmt::Debug for EnrichRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrichRule").finish_non_exhaustive()
    }
}

/// What an enrichment plan asks for next (Δ3).
#[derive(Debug, Clone, PartialEq)]
pub enum EnrichStep {
    /// One round: these GETs, in this order, each recorded before the next one leaves.
    Fetch(Vec<(EnrichPurpose, GetCall)>),
    /// No further GET: the judge decides on the answers so far.
    Judge,
}

/// Δ3: at most this many `Fetch` rounds; a plan that asks for another one fails the enrichment
/// closed (an "enrichment failed" hold, Approve disabled).
pub const MAX_ENRICH_STAGES: usize = 4;

/// One enrichment round from a fixed plan (the single-round M3 rules, wrapped for Δ3): its GETs
/// while nothing was answered yet, then `Judge`. An empty plan is `Judge` at once.
pub(crate) fn single_round(calls: Vec<(EnrichPurpose, GetCall)>, answers: &[Value]) -> EnrichStep {
    if answers.is_empty() && !calls.is_empty() {
        EnrichStep::Fetch(calls)
    } else {
        EnrichStep::Judge
    }
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
    /// `jira.issue.get --comments` (PD-45): the issue GET, then the `jira.comment.list` pages up
    /// to `max_items` (the comments cap), under one cover, one control and one read budget.
    /// `rendered`: the pages carry `renderedBody` and the merge builds `renderedFields.comment`.
    /// `comments` is boxed so the plan stays small (`clippy::large_enum_variant`).
    IssueWithComments {
        issue: GetCall,
        comments: Box<PagedCall>,
        max_items: u64,
        rendered: bool,
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
    /// `Validated::comments_cap` (Δ7): at most this many comments for `jira.issue.get
    /// --comments`; `None` for every other op and for writes.
    pub comments_cap: Option<u32>,
    /// U-24 (PD-64): the engine copies `TestHooks::converter_fault` here; `jira_body` and
    /// `confluence_body` append it to converted Markdown of its product before the hard check.
    /// Absent from production builds.
    #[cfg(feature = "testing")]
    pub test_fault: Option<crate::testing::ConverterFault>,
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
    /// Δ4 (PD-49): the required fields without a default that no param sets, in createmeta
    /// order (raw server text). A Caution, never a block; a deny may attach them.
    pub missing_fields: Vec<MissingField>,
    /// How many missing fields there are in all; `missing_fields` keeps at most
    /// `jira::MAX_MISSING_FIELDS` (T12 review M5: a cut list says so).
    pub missing_fields_total: u64,
    /// Δ4: resolved display facts for the write previews (raw server text; the previewer
    /// escapes them).
    pub summary: Option<WriteSummaryFacts>,
}

/// Δ4 (PD-49): one missing required field of a `jira.issue.create`, as createmeta names it. The
/// strings are raw server text: escaped for display by whoever shows them, delivered raw in a
/// `missing_fields` deny hint (like resolution candidates).
#[derive(Clone, PartialEq, Eq)]
pub struct MissingField {
    pub id: String,
    pub name: String,
    /// `schema.type` (`option`, `array`, `number`, `string`, ...); `""` when absent.
    pub schema_type: String,
    /// Additive: `schema.items` of an `array` field (`option` for a multi-select), which the edit
    /// form's input kind needs; never delivered.
    pub schema_items: Option<String>,
    /// The first [`MAX_ALLOWED_VALUES`] of createmeta's `allowedValues`.
    pub allowed_values: Vec<AllowedValue>,
    /// How many `allowedValues` createmeta listed (T12 review M5: a cut list says so).
    pub allowed_total: u64,
}

/// Redacting `Debug` (§7.7): names and values are Atlassian data.
impl fmt::Debug for MissingField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MissingField")
            .field("id", &format_args!("len={}", self.id.len()))
            .field("allowed_values", &self.allowed_values.len())
            .field("allowed_total", &self.allowed_total)
            .finish_non_exhaustive()
    }
}

/// One allowed value of a missing field (T12 review I1): the name it is shown and listed by,
/// and the value a request sends for it.
#[derive(Clone, PartialEq, Eq)]
pub struct AllowedValue {
    /// `value`, else `name`, else `id` (raw, cut to the name cap).
    pub label: String,
    /// The field value Jira takes for this pick, already in the field's shape: `{"id": ..}` when
    /// createmeta gives an id, else `{"value": ..}` (the raw value, never cut), inside an array
    /// for an `array` of `option`. `None`: neither is there, so a pick of it is refused.
    pub wire: Option<Value>,
}

/// Redacting `Debug` (§7.7).
impl fmt::Debug for AllowedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AllowedValue")
            .field("wire", &self.wire.is_some())
            .finish_non_exhaustive()
    }
}

/// Δ4 / PD-49: at most this many allowed values per missing field (the `Choice` cap).
pub const MAX_ALLOWED_VALUES: usize = atlas_duck_preview::form::CHOICE_MAX_VALUES;

/// Δ4: what enrichment resolved, for the write previews' sentence and rows (raw server text).
/// Later tasks add their facts (from/to status, assignee, link phrases, sprint).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct WriteSummaryFacts {
    /// `jira.issue.create`: the resolved project's key and name, the issue type's id and name.
    pub project_key: Option<String>,
    pub project_name: Option<String>,
    pub issue_type_id: Option<String>,
    pub issue_type: Option<String>,
    /// `jira.issue.create`: createmeta's `(fieldId, name)` of the `fields` keys the params set
    /// (T12 review M8: the card names them like the Caution does); at most
    /// `jira::MAX_MISSING_FIELDS`.
    pub field_names: Vec<(String, String)>,
    /// `jira.issue.transition` (T14): the name of the status the issue is in and of the status the
    /// resolved transition leads to; `field_names` then holds the transition screen's names of
    /// the `fields` keys the params set.
    pub from_status: Option<String>,
    pub to_status: Option<String>,
    /// `jira.issue.transition` (T14 review M5): the resolved transition's name (its id is the
    /// request's).
    pub transition_name: Option<String>,
    /// `jira.issue.assign` (T15, PD-52): the issue's current assignee (`None`: unassigned) and the
    /// user the assignee param resolved to (`None`: an unassign).
    pub assignee_from: Option<JiraUser>,
    pub assignee_to: Option<JiraUser>,
    /// `jira.issuelink.create` (T16, PD-53): the link type the `type` param resolved to.
    pub link_type: Option<JiraLinkType>,
    /// `jira.sprint.move_issues` (T18, PD-54): the sprint enrichment read.
    pub sprint: Option<JiraSprint>,
}

/// T18: the target sprint of a `jira.sprint.move_issues` as enrichment read it (raw server text).
/// The card names the sprint only when `id` is the one the sent URL moves into (PD-54).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct JiraSprint {
    pub id: u64,
    /// Never cut: the card cuts it for display.
    pub name: String,
    /// `future`, `active` or `closed`.
    pub state: String,
}

/// Redacting `Debug` (§7.7).
impl fmt::Debug for JiraSprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JiraSprint")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// T15: a Jira user as enrichment read it (raw server text). Payloads send `name`; the preview
/// shows `name` and `key` (§7.3), the stale rule compares `key` (PD-52).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct JiraUser {
    pub name: Option<String>,
    pub key: Option<String>,
    /// Cut to the name cap (display only).
    pub display_name: Option<String>,
}

/// Redacting `Debug` (§7.7).
impl fmt::Debug for JiraUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JiraUser").finish_non_exhaustive()
    }
}

/// T16: an issue link type as enrichment read it (raw server text). The request names it by
/// `name` (PD-53); the link card reads `outward` from the `inwardIssue` and `inward` back
/// (direction pending the T24 live probe).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct JiraLinkType {
    pub id: String,
    /// Never cut: the card compares it with the name the request sends.
    pub name: String,
    /// The phrases, cut to the name cap (display only).
    pub inward: String,
    pub outward: String,
}

/// Redacting `Debug` (§7.7).
impl fmt::Debug for JiraLinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JiraLinkType").finish_non_exhaustive()
    }
}

/// Redacting `Debug` (§7.7).
impl fmt::Debug for WriteSummaryFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteSummaryFacts").finish_non_exhaustive()
    }
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
            missing_fields: Vec::new(),
            missing_fields_total: 0,
            summary: None,
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
            .field("missing_fields", &self.missing_fields.len())
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
    /// Δ5 (PD-46): the instance's cached `/rest/api/2/field` id → name map for Jira reads, as
    /// it was when the preview was built; `None` = unknown (ids shown). Display-only.
    pub field_names: Option<&'a crate::metadata::FieldNames>,
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
    /// `jira.issue.get --comments` stopped at the comments cap: `(comments fetched, server
    /// total)`, shown as Info `truncated_by_cap(N, total)` (PD-45). `None` otherwise. For such a
    /// read `more_available`/`server_total` describe the comment pages, not the issue.
    pub comments_truncated: Option<(u64, u64)>,
    /// Δ3 (PD-100): what the storage → Markdown conversion of a Confluence page body reduced;
    /// `None` for every other read (and for a page read without a storage body).
    pub conversion: Option<atlas_duck_convert::ConversionReport>,
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
    (
        "jira.myself",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.project.list",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.project.get",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.issue.get",
        OpImpl {
            executor: jira::issue_get_executor,
            previewer: jira_preview::issue_preview,
            ..READ
        },
    ),
    (
        "jira.search",
        OpImpl {
            previewer: jira_preview::search_preview,
            ..READ
        },
    ),
    (
        "jira.comment.list",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.worklog.list",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.transition.list",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.issue.editmeta",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.createmeta.issuetypes",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.createmeta.fields",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.field.list",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.issuelinktype.list",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.attachment.meta",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.user.assignable",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.board.list",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.sprint.list",
        OpImpl {
            previewer: jira_preview::list_preview,
            ..READ
        },
    ),
    (
        "jira.sprint.issues",
        OpImpl {
            previewer: jira_preview::search_preview,
            ..READ
        },
    ),
    (
        "jira.backlog.issues",
        OpImpl {
            previewer: jira_preview::search_preview,
            ..READ
        },
    ),
    (
        "jira.issue.create",
        OpImpl {
            executor: jira::issue_create_executor,
            previewer: jira_preview::create_preview,
            stale_check: None,
            enrich: Some(&jira::ISSUE_CREATE_ENRICH),
            // PD-49: an edit that adds `fields.<id>` (or the `description` a createmeta marks
            // required) re-runs enrichment, so the warning follows the params that run.
            enrich_keys: &["project", "issuetype", "fields", "description"],
        },
    ),
    (
        "jira.issue.edit",
        OpImpl {
            executor: jira::issue_edit_executor,
            previewer: jira_preview::edit_preview,
            stale_check: Some(&stale::ISSUE_EDIT),
            enrich: Some(&jira::ISSUE_EDIT_ENRICH),
            enrich_keys: &["fields", "update"],
        },
    ),
    (
        "jira.comment.add",
        OpImpl {
            executor: jira::comment_add_executor,
            previewer: jira_preview::comment_preview,
            stale_check: None,
            enrich: None,
            enrich_keys: &[],
        },
    ),
    (
        "jira.issue.transition",
        OpImpl {
            executor: jira::issue_transition_executor,
            previewer: jira_preview::transition_preview,
            stale_check: Some(&stale::ISSUE_TRANSITION),
            enrich: Some(&jira::ISSUE_TRANSITION_ENRICH),
            enrich_keys: &["transition", "fields", "comment"],
        },
    ),
    (
        "jira.issue.assign",
        OpImpl {
            executor: jira_ext::issue_assign_executor,
            previewer: jira_preview::assign_preview,
            stale_check: Some(&stale::ISSUE_ASSIGN),
            enrich: Some(&jira_ext::ISSUE_ASSIGN_ENRICH),
            // §5.4 step 4: an edited assignee is resolved again.
            enrich_keys: &["assignee"],
        },
    ),
    (
        "jira.worklog.add",
        OpImpl {
            executor: jira_ext::worklog_add_executor,
            previewer: jira_preview::worklog_preview,
            // §5.4 step 5: "none" (additive op); no enrichment (PD-55). The pre-write identity
            // call still runs.
            stale_check: None,
            enrich: None,
            enrich_keys: &[],
        },
    ),
    (
        "jira.issuelink.create",
        OpImpl {
            executor: jira_ext::issuelink_create_executor,
            previewer: jira_preview::issuelink_preview,
            // §5.4 step 5: "none" (additive op).
            stale_check: None,
            enrich: Some(&jira_ext::ISSUELINK_CREATE_ENRICH),
            // §5.4 step 4: an edited type is resolved again; the comment is sent verbatim.
            enrich_keys: &["type"],
        },
    ),
    (
        "jira.sprint.move_issues",
        OpImpl {
            executor: jira_ext::sprint_move_executor,
            previewer: jira_preview::move_preview,
            // PD-54: the sprint is still future or active.
            stale_check: Some(&stale::SPRINT_MOVE),
            enrich: Some(&jira_ext::SPRINT_MOVE_ENRICH),
            // Both params are targets (L06: not editable), so nothing re-runs enrichment.
            enrich_keys: &[],
        },
    ),
    (
        "jira.backlog.move_issues",
        OpImpl {
            executor: jira_ext::backlog_move_executor,
            previewer: jira_preview::move_preview,
            // PD-54: no enrichment, no stale rule (§5.4 step 5: an idempotent op); the
            // pre-write identity call still runs.
            stale_check: None,
            enrich: None,
            enrich_keys: &[],
        },
    ),
    ("confluence.user.current", READ),
    ("confluence.space.list", READ),
    ("confluence.space.get", READ),
    (
        "confluence.page.get",
        OpImpl {
            executor: confluence::page_get_executor,
            ..READ
        },
    ),
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
    (
        "confluence.page.history",
        OpImpl {
            executor: confluence::page_history_executor,
            ..READ
        },
    ),
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
