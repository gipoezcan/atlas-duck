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
    /// M15 T10b: the German form, built with the text from its typed values (never on the wire).
    #[serde(skip)]
    de: Option<String>,
}

impl Warning {
    /// The level comes from the id, so one level per id is structural (§13).
    pub fn new(id: WarningId, text: impl Into<WarnText>) -> Warning {
        let WarnText { en, de } = text.into();
        Warning {
            id,
            level: id.level(),
            text: en,
            de,
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

// Parameterized texts, §6.2 (verbatim templates). M15 T10b fix I-2, m-1: each builds its German
// form from its typed values: only a count this code computed is written the German way (`n`); a
// user name, URL, request id, version, title or phrase goes into the German form unchanged, and
// nothing is parsed back out of the English text.

/// A count written the German way ("1.234").
fn n(v: u64) -> String {
    crate::Lang::De.count(v)
}

/// "token changed: now executes as <user>" (§7.1)
pub fn token_changed(user: &str) -> WarnText {
    WarnText::new(
        format!("token changed: now executes as {user}"),
        format!("Token geändert: wird jetzt ausgeführt als {user}"),
    )
}

/// "token no longer resolves to <user>" (§5.4 step 5)
pub fn token_no_longer_resolves(user: &str) -> WarnText {
    WarnText::new(
        format!("token no longer resolves to {user}"),
        format!("Token gehört nicht mehr zu {user}"),
    )
}

/// "Atlassian username changed: <old> → <new>" (§7.1)
pub fn user_renamed(old: &str, new: &str) -> WarnText {
    WarnText::new(
        format!("Atlassian username changed: {old} → {new}"),
        format!("Atlassian-Benutzername geändert: {old} → {new}"),
    )
}

/// "instance URL changed: <old> → <new>" (§7.1)
pub fn instance_url_changed(old: &str, new: &str) -> WarnText {
    WarnText::new(
        format!("instance URL changed: {old} → {new}"),
        format!("Instanz-URL geändert: {old} → {new}"),
    )
}

/// "conflict: page changed since the agent read it (v5 → v6)" (§5.4 step 2); versions are
/// identifiers, not counts.
pub fn conflict(vn: u64, vm: u64) -> WarnText {
    WarnText::new(
        format!("conflict: page changed since the agent read it (v{vn} → v{vm})"),
        format!(
            "Konflikt: Die Seite wurde geändert, seit der Agent sie gelesen hat (v{vn} → v{vm})"
        ),
    )
}

/// "Changed since you reviewed: <what changed>" (§5.4); the delta is core's own text.
pub fn changed_since_review(delta: &str) -> WarnText {
    WarnText::new(
        format!("{TEXT_CHANGED_SINCE_REVIEW}: {delta}"),
        format!("Seit Ihrer Prüfung geändert: {delta}"),
    )
}

/// "possible duplicate of req_…" (§5.6)
pub fn possible_duplicate(req: &str) -> WarnText {
    WarnText::new(
        format!("possible duplicate of {req}"),
        format!("mögliches Duplikat von {req}"),
    )
}

/// "similar to req_… executed 14:02"; `when` is `"executed 14:02"` or `"outcome unknown"` (§5.6).
/// `when` is core's own text (`SimHit::when`), never an agent's: its leading word is ours.
pub fn similar_request(req: &str, when: &str) -> WarnText {
    let de = match when {
        "pending" => format!("ähnlich zu {req}, ausstehend"),
        "outcome unknown" => format!("ähnlich zu {req}, Ergebnis unbekannt"),
        _ => match when.split_once(' ') {
            Some(("executed", at)) => format!("ähnlich zu {req}, ausgeführt {at}"),
            Some(("denied", at)) => format!("ähnlich zu {req}, abgelehnt {at}"),
            Some(("released", at)) => format!("ähnlich zu {req}, übergeben {at}"),
            Some(("failed", at)) => format!("ähnlich zu {req}, fehlgeschlagen {at}"),
            _ => format!("ähnlich zu {req} {when}"),
        },
    };
    WarnText::new(format!("similar to {req} {when}"), de)
}

/// "contains N bidirectional control characters" (§6.4)
pub fn bidi_controls(c: u64) -> WarnText {
    WarnText::new(
        format!("contains {c} bidirectional control characters"),
        format!("enthält {} bidirektionale Steuerzeichen", n(c)),
    )
}

/// "contains N other invisible characters" (§6.4)
pub fn other_invisible(c: u64) -> WarnText {
    WarnText::new(
        format!("contains {c} other invisible characters"),
        format!("enthält {} andere unsichtbare Zeichen", n(c)),
    )
}

/// "mixed-script identifier: <issue key / space key / username / URL host>" (§6.4)
pub fn mixed_script(ident: &str) -> WarnText {
    WarnText::new(
        format!("mixed-script identifier: {ident}"),
        format!("Bezeichner mit gemischter Schrift: {ident}"),
    )
}

/// "missing required fields: Team (customfield_10200, option)" (§5.4 step 2)
pub fn missing_required_fields(list: &str) -> WarnText {
    WarnText::new(
        format!("missing required fields: {list}"),
        format!("fehlende Pflichtfelder: {list}"),
    )
}

/// "required-field list incomplete: 4 of N pages read" (M5 T12 review M10, PD-49); without a
/// page count, "4 of more than 4 pages read".
pub fn required_field_list_incomplete(read: u64, pages: Option<u64>) -> WarnText {
    match pages {
        Some(p) => WarnText::new(
            format!("required-field list incomplete: {read} of {p} pages read"),
            format!(
                "Pflichtfeldliste unvollständig: {} von {} Seiten gelesen",
                n(read),
                n(p)
            ),
        ),
        None => WarnText::new(
            format!("required-field list incomplete: {read} of more than {read} pages read"),
            format!(
                "Pflichtfeldliste unvollständig: {} von mehr als {} Seiten gelesen",
                n(read),
                n(read)
            ),
        ),
    }
}

/// "result truncated by cap (N of M)"
pub fn truncated_by_cap(shown: u64, of: u64) -> WarnText {
    WarnText::new(
        format!("result truncated by cap ({shown} of {of})"),
        format!(
            "Ergebnis durch Obergrenze gekürzt ({} von {})",
            n(shown),
            n(of)
        ),
    )
}

/// "N changes not visible in rendered diff" (§6.3)
pub fn raw_only_diff(c: u64) -> WarnText {
    WarnText::new(
        format!("{c} changes not visible in rendered diff"),
        format!(
            "{} Änderungen sind im gerenderten Diff nicht sichtbar",
            n(c)
        ),
    )
}

/// plan text (M5 T13, T6 handoff): "diff truncated: N bytes not shown (see Request)"; the
/// Request tab holds every byte that is sent.
pub fn diff_truncated(c: u64) -> WarnText {
    WarnText::new(
        format!("diff truncated: {c} bytes not shown (see Request)"),
        format!(
            "Diff gekürzt: {} Bytes nicht angezeigt (siehe Anfrage)",
            n(c)
        ),
    )
}

/// plan text (M5 T13 review M-1): "N fields shown as sent, without their current value"; such a
/// section lists the sent value (or operations) as added lines only.
pub fn no_current_value(c: u64) -> WarnText {
    WarnText::new(
        format!("{c} fields shown as sent, without their current value"),
        format!(
            "{} Felder wie gesendet angezeigt, ohne ihren aktuellen Wert",
            n(c)
        ),
    )
}

/// plan text (M5 T16 review I1): "link type named by its inward phrase 'is blocked by': the
/// inward issue gets the outward phrase 'blocks'"; the caller display-escapes both phrases.
pub fn link_type_inward_phrase(inward: &str, outward: &str) -> WarnText {
    WarnText::new(
        format!(
            "link type named by its inward phrase '{inward}': the inward issue gets the outward phrase '{outward}'"
        ),
        format!(
            "Verknüpfungstyp über seine eingehende Bezeichnung „{inward}“ benannt: Der eingehende Vorgang erhält die ausgehende Bezeichnung „{outward}“"
        ),
    )
}

/// plan text (PD-105): "a page titled '<title>' already exists in <space>"; the caller
/// display-escapes both.
pub fn duplicate_title(title: &str, space: &str) -> WarnText {
    WarnText::new(
        format!("a page titled '{title}' already exists in {space}"),
        format!("Eine Seite mit dem Titel „{title}“ gibt es bereits in {space}"),
    )
}

/// "this update will remove N macros / M images / K links" (§7.6), plus ", L layouts" when
/// layouts are lost (M7 lead ruling Q10, PD-104: §6.2 amendment).
pub fn lossy_update(macros: u64, images: u64, links: u64, layouts: u64) -> WarnText {
    let mut en =
        format!("this update will remove {macros} macros / {images} images / {links} links");
    let mut de = format!(
        "diese Aktualisierung entfernt {} Makros / {} Bilder / {} Links",
        n(macros),
        n(images),
        n(links)
    );
    if layouts > 0 {
        en.push_str(&format!(", {layouts} layouts"));
        de.push_str(&format!(", {} Layouts", n(layouts)));
    }
    WarnText::new(en, de)
}

/// "includes summary/status of N linked/parent/sub-task issues"
pub fn linked_issue_summaries(c: u64) -> WarnText {
    WarnText::new(
        format!("includes summary/status of {c} linked/parent/sub-task issues"),
        format!(
            "enthält Zusammenfassung/Status von {} verknüpften, übergeordneten oder Unteraufgaben-Vorgängen",
            n(c)
        ),
    )
}

/// "contains N custom fields"
pub fn custom_fields(c: u64) -> WarnText {
    WarnText::new(
        format!("contains {c} custom fields"),
        format!("enthält {} benutzerdefinierte Felder", n(c)),
    )
}

/// "N host calls returned truncated or lossy data" (§9.5)
pub fn host_calls_lossy(c: u64) -> WarnText {
    WarnText::new(
        format!("{c} host calls returned truncated or lossy data"),
        format!(
            "{} Host-Aufrufe lieferten gekürzte oder verlustbehaftete Daten",
            n(c)
        ),
    )
}

// ---- M15 T10b: the warnings in the preview's language ---------------------------------------

/// The German form of each fixed text (looked up by the whole English text, never by a part).
const FIXED_DE: &[(&str, &str)] = &[
    (
        TEXT_RESTRICTED_COMMENTS,
        "enthält Kommentare mit eingeschränkter Sichtbarkeit",
    ),
    (TEXT_SECURITY_LEVEL, "Vorgang hat eine Sicherheitsstufe"),
    (TEXT_ALL_FIELDS, "alle Felder angefordert (`*all`)"),
    (
        TEXT_SERVER_RENDERED_VIEW,
        "serverseitig gerenderte Ansicht: Makros können Inhalte anderer Seiten enthalten",
    ),
    (TEXT_CHANGED_SINCE_REVIEW, "Seit Ihrer Prüfung geändert"),
    (
        TEXT_COULD_NOT_RECHECK,
        "Ziel konnte nicht erneut geprüft werden",
    ),
    (
        TEXT_IDENTITY_HEADER_LOST,
        "Jira hat kein passendes X-AUSERNAME gesendet (möglicherweise von einem Reverse Proxy entfernt); wenden Sie sich an den Jira-Administrator",
    ),
    (TEXT_UNKNOWN_MACROS, "Inhalt enthält unbekannte Makros"),
    (
        TEXT_UNRESOLVED_MENTION,
        "Erwähnung konnte nicht aufgelöst werden",
    ),
    (TEXT_CQL_BROAD, "CQL kann sehr viele Ergebnisse liefern"),
    (
        TEXT_SOURCE_FORMATTING_REMOVED,
        "Quellformatierung entfernt (versteckte oder farbige Formatierung vorhanden)",
    ),
    (
        TEXT_SCRIPT_RENDERED_COPIES,
        "dieses Ergebnis kann gerenderte Kopien von Feldern enthalten (renderedFields); das Entfernen eines Felds entfernt seine Kopie nicht; maskieren Sie jedes Vorkommen",
    ),
];

/// A warning's text and its German form (M15 T10b). The parameterized texts above build both from
/// typed values; a fixed text gets its German form by an exact lookup; any other text has none
/// and is shown as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarnText {
    en: String,
    de: Option<String>,
}

impl WarnText {
    fn new(en: String, de: String) -> WarnText {
        WarnText { en, de: Some(de) }
    }

    /// The English text (what core records and compares).
    pub fn as_str(&self) -> &str {
        &self.en
    }

    /// The German text, when this text has a German form.
    pub fn de(&self) -> Option<&str> {
        self.de.as_deref()
    }
}

impl From<String> for WarnText {
    fn from(en: String) -> WarnText {
        let de = FIXED_DE
            .iter()
            .find(|(e, _)| *e == en)
            .map(|(_, d)| (*d).to_owned());
        WarnText { en, de }
    }
}

impl From<&str> for WarnText {
    fn from(en: &str) -> WarnText {
        WarnText::from(en.to_owned())
    }
}

impl From<WarnText> for String {
    fn from(t: WarnText) -> String {
        t.en
    }
}

impl std::ops::Deref for WarnText {
    type Target = str;
    fn deref(&self) -> &str {
        &self.en
    }
}

impl std::fmt::Display for WarnText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.en)
    }
}

impl PartialEq<WarnText> for String {
    fn eq(&self, other: &WarnText) -> bool {
        *self == other.en
    }
}

impl PartialEq<&str> for WarnText {
    fn eq(&self, other: &&str) -> bool {
        self.en == *other
    }
}

impl PartialEq<String> for WarnText {
    fn eq(&self, other: &String) -> bool {
        self.en == *other
    }
}

impl PartialEq<WarnText> for str {
    fn eq(&self, other: &WarnText) -> bool {
        self == other.en
    }
}

/// The warning's text in `lang`: English as core wrote it; German by the form built with it. A
/// text with no German form stays English.
pub fn shown(lang: crate::Lang, w: &Warning) -> String {
    match (lang, &w.de) {
        (crate::Lang::De, Some(de)) => de.clone(),
        _ => w.text.clone(),
    }
}
