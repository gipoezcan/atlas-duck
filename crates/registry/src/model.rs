//! The C.1 data model. Only `&'static` data and `Copy` enums: no fn pointers, no I/O.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Product {
    Jira,
    Confluence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpClass {
    Read,
    Write,
}

/// §5.6 similarity kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Similarity {
    Target,
    Create,
    MoveIssues,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuccessBody {
    Json,
    Empty,
}

/// A per-op override of the default 2xx is registry data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusSet {
    Any2xx,
    Exactly(&'static [u16]),
}

/// §5.3: dropping field X also drops these locations.
///
/// Path convention (one for the whole crate; `core::redact` resolves it): `copies` and `mirrors`
/// are **item-relative**. The item root is the element of `paginated.items_key` for a paged op
/// and the document root otherwise, and a dropped path `fields.<X>` under that item root selects
/// the copies under the same root. Only `RootPath` and `url_fields` are document-absolute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyRule {
    /// Item-relative: `"renderedFields.{field}"`, `"names.{field}"`, `"schema.{field}"`,
    /// `"editmeta.fields.{field}"`.
    Path(&'static str),
    /// Document-root location of a paged response, not under any item (e.g. the `names` and
    /// `schema` maps of a `jira.search` response). Removed on a whole-field (`AllItems`) drop of
    /// `{field}` in any item.
    RootPath(&'static str),
    ChangelogItems {
        items_path: &'static str,
        /// `"field"`, `"fieldId"`.
        key_fields: &'static [&'static str],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuccessShape {
    pub statuses: StatusSet,
    pub body: SuccessBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSpec {
    pub items_key: &'static str,
    pub offset_param: &'static str,
    pub limit_param: &'static str,
}

/// E.g. `{src: "fields.comment.comments", dst: "renderedFields.comment.comments", key: "id"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mirror {
    pub src: &'static str,
    pub dst: &'static str,
    pub key: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionRules {
    /// Item-relative (see [`CopyRule`]).
    pub copies: &'static [CopyRule],
    /// `src`/`dst` are item-relative, like `copies`.
    pub mirrors: &'static [Mirror],
    /// Document-absolute patterns: `*` one key, `[]` every element; a leading `[]` segment
    /// addresses the elements of a root array (`[].self`).
    pub url_fields: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryValue {
    Param(&'static str),
    Const(&'static str),
    ParamBoolFlag {
        param: &'static str,
        value_if_true: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryParam {
    pub name: &'static str,
    pub value: QueryValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodySource {
    None,
    /// The `jira.search` body, built by `core` from the params.
    ParamsAsJson,
    OpSpecific,
}

/// Template data `core` hands to `atlassian` (C.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub method: Method,
    /// E.g. `"/rest/api/2/issue/{key}"`.
    pub path: &'static str,
    pub query: &'static [QueryParam],
    pub body: BodySource,
}

/// `confluence.page.history` with `version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AltEndpoint {
    pub when_param_present: &'static str,
    pub endpoint: Endpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagKind {
    Str,
    Int,
    Bool,
    Json,
    CsvList,
    /// `--field id=<json>`.
    KeyJsonPairs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagBinding {
    pub param: &'static str,
    pub flag: &'static str,
    pub kind: FlagKind,
    pub file_variant: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CliBinding {
    /// E.g. `["jira", "issue", "get"]`.
    pub noun_path: &'static [&'static str],
    /// The param bound to the positional argument.
    pub positional: Option<&'static str>,
    pub flags: &'static [FlagBinding],
}

/// §2.3 `target_display` rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetDisplay {
    Param(&'static str),
    Query {
        param: &'static str,
    },
    CreateIn(&'static str),
    Pair(&'static str, &'static str),
    MoveInto {
        sprint_param: Option<&'static str>,
        issues_param: &'static str,
    },
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldRules {
    pub fields_param: Option<&'static str>,
    pub fields_map_param: Option<&'static str>,
    pub expand_param: Option<&'static str>,
    pub expand_allow: &'static [&'static str],
    /// The `fields` applied when the agent sends none (documented by `describe`); `&[]` = none.
    pub default_fields: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxCap {
    pub param: &'static str,
    pub default: u32,
    pub hard_cap_default: u32,
    pub configurable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub max: Option<MaxCap>,
    pub move_limit: Option<u32>,
    pub comments_cap: Option<u32>,
    pub upload_max_bytes: Option<u64>,
    /// 16 MiB unless lower.
    pub static_result_cap_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Projection {
    Fields(&'static [&'static str]),
    AgentLabels,
    Empty,
}

/// One registry operation (§2.3). JSON-valued fields are text (a `serde_json::Value` cannot be a
/// `const`) read through the `*_json()` accessors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationSpec {
    pub id: &'static str,
    pub product: Product,
    pub class: OpClass,
    pub endpoint: Endpoint,
    pub alt_endpoint: Option<AltEndpoint>,
    /// JSON Schema (draft 2020-12) text; `additionalProperties: false`.
    pub params_schema: &'static str,
    pub cli: CliBinding,
    pub target_params: &'static [&'static str],
    /// `["base_version"]`, `["expected"]` or `[]`.
    pub conflict_baselines: &'static [&'static str],
    pub target_display: TargetDisplay,
    pub similarity: Similarity,
    pub field_rules: Option<FieldRules>,
    pub caps: Caps,
    pub min_version: Option<Version>,
    pub paginated: Option<PageSpec>,
    pub result_projection: Projection,
    pub success: SuccessShape,
    pub redaction_rules: RedactionRules,
    pub result_example: &'static str,
    pub result_example_sparse: &'static str,
    pub result_schema: &'static str,
    /// Write ops: `describe` adds the §2.3 sentence.
    pub write_guidance: bool,
}

impl OperationSpec {
    pub fn params_schema_json(&self) -> Value {
        serde_json::from_str(self.params_schema).unwrap_or(Value::Null)
    }

    pub fn result_schema_json(&self) -> Value {
        serde_json::from_str(self.result_schema).unwrap_or(Value::Null)
    }

    pub fn result_example_json(&self) -> Value {
        serde_json::from_str(self.result_example).unwrap_or(Value::Null)
    }

    pub fn result_example_sparse_json(&self) -> Value {
        serde_json::from_str(self.result_example_sparse).unwrap_or(Value::Null)
    }
}
