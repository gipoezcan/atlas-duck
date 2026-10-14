//! The preview base model (C.6): what core hands to the approvals UI (§6.1, §6.3).

use serde::{Deserialize, Serialize};

use crate::diff::DiffLine;
use crate::form::EditForm;
use crate::json_tree::JsonNode;
use crate::warning::Warning;

/// Size of one Raw page; the bytes themselves stay in core (C.7 `RawPage`).
pub const RAW_PAGE_BYTES: u64 = 256 * 1024;

/// Names the classifier's Unicode and emoji table versions so counts are reproducible (§6.4, §8.3,
/// V31). Both are literals read from the pinned crates; `tests/invisible.rs` checks them:
/// - `icu-17.0`: `icu_properties_data` 2.3.0 README "generated with CLDR version 48.2.1, ICU
///   version release-78.1rc"; ICU 78 is the Unicode 17.0 release, and the data assigns U+10940
///   to Sidetic (new in 17.0).
/// - `emoji-17.0`: `emojis` 0.9.0 README "Uses Unicode v17.0 emoji specification"
///   (`emojis::UNICODE_VERSION`).
pub const PREVIEW_BUILDER_VERSION: &str = concat!("pb1;icu-", "17.0", ";emoji-", "17.0");

/// `UpstreamError.error_messages_text` cap (bytes, including the trailing ellipsis).
pub const ERROR_TEXT_CAP_BYTES: usize = 2048;

/// Revision of a candidate: `counter` increments on every change; the hash is SHA-256 over the
/// candidate (computed in core, which re-exports this type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CandidateRev {
    pub counter: u64,
    #[serde(with = "hex32")]
    pub candidate_hash: [u8; 32],
}

/// Lowercase hex of exactly 32 bytes; anything else (uppercase, wrong length) is rejected.
mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        if s.bytes().any(|c| c.is_ascii_uppercase()) {
            return Err(D::Error::custom("hash must be lowercase hex"));
        }
        hex::decode(&s)
            .map_err(D::Error::custom)?
            .try_into()
            .map_err(|_| D::Error::custom("hash must be 32 bytes"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Preview {
    pub candidate_rev: CandidateRev,
    pub approvable: bool,
    pub header: PreviewHeader,
    pub warnings: Vec<Warning>,
    pub body: PreviewBody,
    pub raw: RawPager,
    pub also_appears_in: Vec<String>,
    pub preview_builder_version: String,
    /// §5.4 step 4: the editable inputs of a write preview; `None` where there is no edit step.
    pub edit_form: Option<EditForm>,
    /// PD-70: exactly the deny details core accepts for this revision (the UI offers no other;
    /// core still checks every decision). Empty for reads and scripts.
    pub deny_offers: Vec<DenyOffer>,
    /// PD-70: the text the deny reason field starts with (a conflict hold's fixed prefill).
    pub deny_prefill: Option<String>,
}

/// One deny detail the approver may attach (PD-70, C.7 `DenyDetails`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DenyOffer {
    pub kind: DenyOfferKind,
    /// The detail has an optional part the approver may include (messages, candidates,
    /// allowed values); `false` when including it would change nothing.
    pub has_optional_detail: bool,
}

/// The `DenyDetails` kinds (§5.4 step 2, §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyOfferKind {
    UpstreamHttp,
    OutcomeHint,
    ResolutionFailed,
    MissingFields,
}

/// §6.1 item 3 plus the classifier counts (§6.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewHeader {
    pub instance_alias: String,
    pub op_id: String,
    pub class: String,
    pub item_count: Option<ItemCount>,
    pub byte_size: u64,
    pub fields_included: Vec<String>,
    pub hidden_in_preview_bytes: u64,
    pub bidi_controls: u64,
    pub other_invisible: u64,
    pub executes_as: Option<String>,
    pub receipt_fields: Vec<String>,
    /// The effective query as sent, display-escaped (§6.3: a Confluence search shows its CQL
    /// after the §7.4 rewrite, `jira.search` its JQL); `None` for keyed ops.
    pub query: Option<String>,
    /// M5 M-11: the Caution banner of a candidate that failed closed (§5.2: only Deny remains);
    /// core's fixed text, `None` otherwise.
    pub release_blocked: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ItemCount {
    pub shown: u64,
    /// `None` when the server reports no total ("N shown, more available").
    pub total: Option<u64>,
    pub more_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    ReleaseCap16,
    ResponseCap32,
    FetchCap50,
    ReadBudget120,
    PerCallTimeout30,
    NetworkAfterSend,
    JsonBodyUnreadable,
    /// A later page of a paginated read was refused or answered without usable JSON (redirect,
    /// non-JSON, token or identity failure, connection failure): gated, because whether a
    /// later page is requested depends on the results (Task 21 review I-1).
    LaterPageRefused,
}

/// A request body as shown in the Request tab: text, or base64 for binary/multipart (§5.4 step 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum BodyView {
    None,
    Text(String),
    Base64(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestView {
    pub index: u32,
    pub method: String,
    pub resolved_url: String,
    pub content_type: Option<String>,
    pub body: BodyView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PreviewBody {
    /// §6.3 Fallback.
    JsonTree {
        tree: JsonNode,
    },
    WriteRequests {
        requests: Vec<RequestView>,
    },
    UpstreamError {
        status: u16,
        /// Capped to [`ERROR_TEXT_CAP_BYTES`]; build with [`PreviewBody::upstream_error`].
        error_messages_text: String,
    },
    Outcome {
        outcome: OutcomeKind,
        size_or_pages: String,
        query: String,
    },
    EnrichmentError {
        status: Option<u16>,
        text: String,
        outcome: Option<OutcomeKind>,
    },
    UnresolvedName {
        param: String,
        value: String,
        matches: u64,
        candidates: Vec<String>,
    },
    Conflict {
        summary: String,
        diff_text: String,
    },
    CouldNotRecheck {
        class: String,
        requests: Vec<RequestView>,
    },
    /// §6.3 Jira issue: the card, the fields, the rendered description and the comments. Plain
    /// strings are display-escaped text (the UI renders them as text); the `*_html` strings are
    /// sanitized HTML (by core, before they get here; the type does not enforce it).
    JiraIssue {
        card: IssueCard,
        fields: Vec<FieldRow>,
        description_html: Option<String>,
        comments: Vec<CommentView>,
    },
    /// §6.3 Jira search and the lists. Every cell and column name is display-escaped text.
    Table {
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
        count: Option<ItemCount>,
    },
    /// §6.3 create, comment, assign, link, labels, worklog, sprint move. `constructs` lists the
    /// wiki constructs of the outgoing text (PD-47). `sentence`, `rows` and (as core builds them,
    /// PD-47) the `constructs` entries are display-escaped text (see [`ConstructList`]).
    WriteSummary {
        sentence: String,
        rows: Vec<(String, String)>,
        constructs: Option<ConstructList>,
        requests: Vec<RequestView>,
    },
    /// §6.3 edit/update: the rendered and the raw line diff; `raw_only_changes` counts hunks that
    /// only the raw diff shows (PD-51). Diff line texts are untrusted text exactly as in the
    /// input (they carry their `\n`/`\r`, see [`DiffLine`]): the UI renders them as text and makes
    /// line terminators and trailing whitespace visible. A `LineDiff.truncated` diff must be
    /// flagged by the builder (a warning), since its lines are not the whole change. Each field's
    /// section starts with a `DiffOp::Field` line naming it (T13); the UI shows that line as a
    /// heading, apart from the text lines.
    EditDiff {
        rendered: Vec<DiffLine>,
        raw: Vec<DiffLine>,
        raw_only_changes: u64,
        requests: Vec<RequestView>,
    },
    /// §6.3 transition. Status names and field rows are display-escaped text. `constructs` lists
    /// the wiki constructs of the comment sent with the transition (PD-47, M5 T14: Δ2 had no place
    /// for them); `None` without a comment. `transition` is the transition sent, `<name> (<id>)`
    /// (the bare id when Jira named none), display-escaped (T14 review M5: two transitions to the
    /// same status differ only there).
    Transition {
        transition: String,
        from: String,
        to: String,
        fields: Vec<(String, String)>,
        constructs: Option<ConstructList>,
        requests: Vec<RequestView>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssueCard {
    pub key: String,
    pub summary: String,
    pub issue_type: String,
    pub status: String,
    pub priority: Option<String>,
    pub assignee: Option<String>,
    pub reporter: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldRow {
    pub id: String,
    /// `customfield_N (unknown field)` when the instance field list does not name it.
    pub name: String,
    pub value_text: String,
    pub restricted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommentView {
    pub id: String,
    pub author: Option<String>,
    pub created: Option<String>,
    pub body_html: String,
    pub restricted: bool,
}

/// The wiki constructs of an outgoing text, in document order per kind (PD-47). Entries (macro
/// names, mention names, link targets, file names) are wiki-derived, agent-controlled text that
/// core display-escapes (PD-47) but does not otherwise neutralize: the UI must render them as
/// text, never as HTML or a live link.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ConstructList {
    pub macros: Vec<String>,
    pub mentions: Vec<String>,
    pub includes: Vec<String>,
    pub links: Vec<String>,
    pub images: Vec<String>,
    pub attachments: Vec<String>,
}

impl PreviewBody {
    /// `UpstreamError` with the message text capped (2 KiB, char boundary, trailing `…`).
    pub fn upstream_error(status: u16, error_messages: &str) -> PreviewBody {
        PreviewBody::UpstreamError {
            status,
            error_messages_text: cap_error_text(error_messages),
        }
    }
}

impl PreviewBody {
    /// `EnrichmentError` with the text capped like `UpstreamError` (§6.3).
    pub fn enrichment_error(
        status: Option<u16>,
        text: &str,
        outcome: Option<OutcomeKind>,
    ) -> PreviewBody {
        PreviewBody::EnrichmentError {
            status,
            text: cap_error_text(text),
            outcome,
        }
    }
}

/// Cuts `s` to at most [`ERROR_TEXT_CAP_BYTES`] bytes at a char boundary; a cut text ends in `…`.
pub fn cap_error_text(s: &str) -> String {
    if s.len() <= ERROR_TEXT_CAP_BYTES {
        return s.to_owned();
    }
    let mut end = ERROR_TEXT_CAP_BYTES - '…'.len_utf8();
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Raw view paging; the bytes stay in core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RawPager {
    pub total_bytes: u64,
    pub page_bytes: u64,
    pub page_count: u64,
}

impl RawPager {
    /// Pages of [`RAW_PAGE_BYTES`]; an empty Raw still has one (empty) page.
    pub fn for_total(total_bytes: u64) -> RawPager {
        RawPager {
            total_bytes,
            page_bytes: RAW_PAGE_BYTES,
            page_count: total_bytes.div_ceil(RAW_PAGE_BYTES).max(1),
        }
    }
}
