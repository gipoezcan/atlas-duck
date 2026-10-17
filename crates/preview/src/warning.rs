//! §6.2 warnings: stable ids, exactly one level per id, fixed texts.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Caution,
    Info,
}

/// C.6 list, snake_case on the wire (recorded in `PREVIEW_SHOWN`, §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningId {
    // Caution
    RestrictedComments,
    SecurityLevel,
    AllFields,
    BidiControls,
    OtherInvisible,
    MixedScript,
    RawOnlyDiff,
    LossyUpdate,
    ServerRenderedView,
    PossibleDuplicate,
    SimilarRequest,
    Conflict,
    MissingRequiredFields,
    ChangedSinceReview,
    CouldNotRecheck,
    TokenChanged,
    TokenIdentityMismatch,
    IdentityHeaderLost,
    UserRenamed,
    InstanceUrlChanged,
    /// M5 T13 (T6 handoff): an edit diff was cut at its caps, so its lines are not the whole
    /// change.
    DiffTruncated,
    /// M5 T13 review M-1: an edit section shows what is sent without the field's current value
    /// (no baseline for it, or an operation list that sets the value), so it is not a diff.
    NoCurrentValue,
    /// M5 T16 review I1: a `jira.issuelink.create` type named only by its inward phrase, so the
    /// link reads the other way round from the agent's wording.
    LinkTypeInwardPhrase,
    /// M7 Δ2 (PD-105, §6.3 "duplicate-title warning (Confluence)"): a page with the title of a
    /// `confluence.page.create` already exists in its space; Approve stays enabled.
    DuplicateTitle,
    /// M8 T17 (M5 M-13, R8): a script run read with `renderedFields`; a drop of a field leaves
    /// its rendered copy (a plan text, a §6.2 amendment).
    ScriptRenderedCopies,
    // Info
    LinkedIssueSummaries,
    CustomFields,
    TruncatedByCap,
    HostCallsLossy,
    UnknownMacros,
    UnresolvedMention,
    CqlBroad,
    SourceFormattingRemoved,
    /// M5 T12 review M10 (PD-49): createmeta field pages past the page cap were not read.
    RequiredFieldListIncomplete,
}

impl WarningId {
    pub const ALL: [WarningId; 34] = [
        WarningId::RestrictedComments,
        WarningId::SecurityLevel,
        WarningId::AllFields,
        WarningId::BidiControls,
        WarningId::OtherInvisible,
        WarningId::MixedScript,
        WarningId::RawOnlyDiff,
        WarningId::LossyUpdate,
        WarningId::ServerRenderedView,
        WarningId::PossibleDuplicate,
        WarningId::SimilarRequest,
        WarningId::Conflict,
        WarningId::MissingRequiredFields,
        WarningId::ChangedSinceReview,
        WarningId::CouldNotRecheck,
        WarningId::TokenChanged,
        WarningId::TokenIdentityMismatch,
        WarningId::IdentityHeaderLost,
        WarningId::UserRenamed,
        WarningId::InstanceUrlChanged,
        WarningId::DiffTruncated,
        WarningId::NoCurrentValue,
        WarningId::LinkTypeInwardPhrase,
        WarningId::DuplicateTitle,
        WarningId::ScriptRenderedCopies,
        WarningId::LinkedIssueSummaries,
        WarningId::CustomFields,
        WarningId::TruncatedByCap,
        WarningId::HostCallsLossy,
        WarningId::UnknownMacros,
        WarningId::UnresolvedMention,
        WarningId::CqlBroad,
        WarningId::SourceFormattingRemoved,
        WarningId::RequiredFieldListIncomplete,
    ];

    pub fn level(self) -> Level {
        match self {
            WarningId::RestrictedComments
            | WarningId::SecurityLevel
            | WarningId::AllFields
            | WarningId::BidiControls
            | WarningId::OtherInvisible
            | WarningId::MixedScript
            | WarningId::RawOnlyDiff
            | WarningId::LossyUpdate
            | WarningId::ServerRenderedView
            | WarningId::PossibleDuplicate
            | WarningId::SimilarRequest
            | WarningId::Conflict
            | WarningId::MissingRequiredFields
            | WarningId::ChangedSinceReview
            | WarningId::CouldNotRecheck
            | WarningId::TokenChanged
            | WarningId::TokenIdentityMismatch
            | WarningId::IdentityHeaderLost
            | WarningId::UserRenamed
            | WarningId::InstanceUrlChanged
            | WarningId::DiffTruncated
            | WarningId::NoCurrentValue
            | WarningId::LinkTypeInwardPhrase
            | WarningId::DuplicateTitle
            | WarningId::ScriptRenderedCopies => Level::Caution,
            WarningId::LinkedIssueSummaries
            | WarningId::CustomFields
            | WarningId::TruncatedByCap
            | WarningId::HostCallsLossy
            | WarningId::UnknownMacros
            | WarningId::UnresolvedMention
            | WarningId::CqlBroad
            | WarningId::SourceFormattingRemoved
            | WarningId::RequiredFieldListIncomplete => Level::Info,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    pub id: WarningId,
    pub level: Level,
    pub text: String,
}

impl Warning {
    /// The level comes from the id, so one level per id is structural (§13).
    pub fn new(id: WarningId, text: impl Into<String>) -> Warning {
        Warning {
            id,
            level: id.level(),
            text: text.into(),
        }
    }
}

// Fixed texts, §6.2 (verbatim).

/// §6.2 (verbatim)
pub const TEXT_RESTRICTED_COMMENTS: &str = "includes restricted-visibility comments";
/// §6.2 (verbatim)
pub const TEXT_SECURITY_LEVEL: &str = "issue has a security level";
/// §6.2 (verbatim)
pub const TEXT_ALL_FIELDS: &str = "all fields requested (`*all`)";
/// §6.2 (verbatim)
pub const TEXT_SERVER_RENDERED_VIEW: &str =
    "server-rendered view: macros may include content from other pages";
/// §6.2 (verbatim)
pub const TEXT_CHANGED_SINCE_REVIEW: &str = "Changed since you reviewed";
/// §6.2 (verbatim)
pub const TEXT_COULD_NOT_RECHECK: &str = "Could not re-check target";
/// §6.2 (verbatim)
pub const TEXT_IDENTITY_HEADER_LOST: &str = "Jira did not send a matching X-AUSERNAME (possibly stripped by a reverse proxy); ask the Jira administrator";
/// §6.2 (verbatim)
pub const TEXT_UNKNOWN_MACROS: &str = "body contains unknown macros";
/// §6.2 (verbatim)
pub const TEXT_UNRESOLVED_MENTION: &str = "mention could not be resolved";
/// §6.2 (verbatim)
pub const TEXT_CQL_BROAD: &str = "CQL may enumerate many results";
/// §6.2 (verbatim)
pub const TEXT_SOURCE_FORMATTING_REMOVED: &str =
    "source formatting removed (hidden/colour styling present)";

/// plan text (M8 T17, M5 M-13, R8; a §6.2 amendment)
pub const TEXT_SCRIPT_RENDERED_COPIES: &str = "this result may contain rendered copies of fields (renderedFields); dropping a field does not drop its copy; use mask in every occurrence";

// Parameterized texts, §6.2 (verbatim templates).

/// "token changed: now executes as <user>" (§7.1)
pub fn token_changed(user: &str) -> String {
    format!("token changed: now executes as {user}")
}

/// "token no longer resolves to <user>" (§5.4 step 5)
pub fn token_no_longer_resolves(user: &str) -> String {
    format!("token no longer resolves to {user}")
}

/// "Atlassian username changed: <old> → <new>" (§7.1)
pub fn user_renamed(old: &str, new: &str) -> String {
    format!("Atlassian username changed: {old} → {new}")
}

/// "instance URL changed: <old> → <new>" (§7.1)
pub fn instance_url_changed(old: &str, new: &str) -> String {
    format!("instance URL changed: {old} → {new}")
}

/// "conflict: page changed since the agent read it (v5 → v6)" (§5.4 step 2)
pub fn conflict(vn: u64, vm: u64) -> String {
    format!("conflict: page changed since the agent read it (v{vn} → v{vm})")
}

/// "possible duplicate of req_…" (§5.6)
pub fn possible_duplicate(req: &str) -> String {
    format!("possible duplicate of {req}")
}

/// "similar to req_… executed 14:02"; `when` is `"executed 14:02"` or `"outcome unknown"` (§5.6).
pub fn similar_request(req: &str, when: &str) -> String {
    format!("similar to {req} {when}")
}

/// "contains N bidirectional control characters" (§6.4)
pub fn bidi_controls(n: u64) -> String {
    format!("contains {n} bidirectional control characters")
}

/// "contains N other invisible characters" (§6.4)
pub fn other_invisible(n: u64) -> String {
    format!("contains {n} other invisible characters")
}

/// "mixed-script identifier: <issue key / space key / username / URL host>" (§6.4)
pub fn mixed_script(ident: &str) -> String {
    format!("mixed-script identifier: {ident}")
}

/// "missing required fields: Team (customfield_10200, option)" (§5.4 step 2)
pub fn missing_required_fields(list: &str) -> String {
    format!("missing required fields: {list}")
}

/// "required-field list incomplete: 4 of N pages read" (M5 T12 review M10, PD-49); without a
/// page count, "4 of more than 4 pages read".
pub fn required_field_list_incomplete(read: u64, pages: Option<u64>) -> String {
    match pages {
        Some(n) => format!("required-field list incomplete: {read} of {n} pages read"),
        None => format!("required-field list incomplete: {read} of more than {read} pages read"),
    }
}

/// "result truncated by cap (N of M)"
pub fn truncated_by_cap(n: u64, m: u64) -> String {
    format!("result truncated by cap ({n} of {m})")
}

/// "N changes not visible in rendered diff" (§6.3)
pub fn raw_only_diff(n: u64) -> String {
    format!("{n} changes not visible in rendered diff")
}

/// plan text (M5 T13, T6 handoff): "diff truncated: N bytes not shown (see Request)"; the
/// Request tab holds every byte that is sent.
pub fn diff_truncated(n: u64) -> String {
    format!("diff truncated: {n} bytes not shown (see Request)")
}

/// plan text (M5 T13 review M-1): "N fields shown as sent, without their current value"; such a
/// section lists the sent value (or operations) as added lines only.
pub fn no_current_value(n: u64) -> String {
    format!("{n} fields shown as sent, without their current value")
}

/// plan text (M5 T16 review I1): "link type named by its inward phrase 'is blocked by': the
/// inward issue gets the outward phrase 'blocks'"; the caller display-escapes both phrases.
pub fn link_type_inward_phrase(inward: &str, outward: &str) -> String {
    format!(
        "link type named by its inward phrase '{inward}': the inward issue gets the outward phrase '{outward}'"
    )
}

/// plan text (PD-105): "a page titled '<title>' already exists in <space>"; the caller
/// display-escapes both.
pub fn duplicate_title(title: &str, space: &str) -> String {
    format!("a page titled '{title}' already exists in {space}")
}

/// "this update will remove N macros / M images / K links" (§7.6), plus ", L layouts" when
/// layouts are lost (M7 lead ruling Q10, PD-104: §6.2 amendment).
pub fn lossy_update(macros: u64, images: u64, links: u64, layouts: u64) -> String {
    let mut text =
        format!("this update will remove {macros} macros / {images} images / {links} links");
    if layouts > 0 {
        text.push_str(&format!(", {layouts} layouts"));
    }
    text
}

/// "includes summary/status of N linked/parent/sub-task issues"
pub fn linked_issue_summaries(n: u64) -> String {
    format!("includes summary/status of {n} linked/parent/sub-task issues")
}

/// "contains N custom fields"
pub fn custom_fields(n: u64) -> String {
    format!("contains {n} custom fields")
}

/// "N host calls returned truncated or lossy data" (§9.5)
pub fn host_calls_lossy(n: u64) -> String {
    format!("{n} host calls returned truncated or lossy data")
}
