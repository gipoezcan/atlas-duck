//! The Audit window's read-only queries as wire DTOs (M10 T12; moved here from the app's
//! `commands::audit` by M14 Task 16, PD-251, so the server serves them with the same shapes):
//! `audit_query`, `audit_trail`, `audit_payload`, `audit_status`. Argument structs are closed
//! (`deny_unknown_fields`) and bounded while parsed; every answer carries plaintext columns only,
//! display-escaped, except `audit_payload`, which carries the payload page as the sandboxed
//! document and its PD-68 display text. Errors are [`AuditReadError`] (no text); the app and the
//! server map it to their own error wire.

use atlas_duck_audit::{
    AuditCursor, AuditError, AuditFilter, AuditPage, AuditTrail, DecisionColumn, EventFlags,
    EventHeader, EventType, MAX_AUDIT_PAGE_ROWS, MAX_FILTER_TEXT_BYTES, Store, UtcInstant,
};
pub use atlas_duck_preview::Platform;
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::render::{self, raw::incomplete_tail};
use serde::{Deserialize, Deserializer, Serialize};

use super::wire::{RequestId, refuse};
use crate::StoreHealthView;

/// The rows of a page when the call names no cursor.
pub const DEFAULT_PAGE_ROWS: u32 = 200;
/// `audit_status` lists at most this many open incidents (newest first); `incident_count` counts
/// them all.
pub const MAX_LISTED_INCIDENTS: usize = 100;
/// The longest `VERIFY.result` the window shows (the finding kinds are short snake_case words).
const MAX_RESULT_CHARS: usize = 64;

// `payload` shows a one-page payload as the tree: the renderer must parse a whole page (T12
// review M-7; a smaller tree bound would silently turn such payloads into Raw text).
const _: () = assert!(render::AUDIT_TREE_MAX_BYTES == atlas_duck_audit::PAYLOAD_PAGE_BYTES);

/// Why a read failed: a refused argument, an unknown seq, a closed store, a record that does not
/// decrypt or verify, anything else. No error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditReadError {
    InvalidArgument { field: &'static str },
    NotFound,
    NotReady,
    Unreadable { seq: u64 },
    Failed,
}

// ---------- arguments ----------
/// An RFC 3339 UTC instant with milliseconds and `Z` (the `ts_utc` text, F.1), or `null`.
fn utc<'de, D: Deserializer<'de>>(
    d: D,
    field: &'static str,
) -> Result<Option<UtcInstant>, D::Error> {
    match Option::<String>::deserialize(d).map_err(|_| refuse::<D::Error>(field))? {
        None => Ok(None),
        Some(s) => UtcInstant::parse_rfc3339_ms(&s)
            .map(Some)
            .ok_or_else(|| refuse(field)),
    }
}

fn filter_utc<'de, D: Deserializer<'de>>(d: D) -> Result<Option<UtcInstant>, D::Error> {
    utc(d, "filter")
}

pub fn from_utc<'de, D: Deserializer<'de>>(d: D) -> Result<Option<UtcInstant>, D::Error> {
    utc(d, "from_utc")
}

pub fn to_utc<'de, D: Deserializer<'de>>(d: D) -> Result<Option<UtcInstant>, D::Error> {
    utc(d, "to_utc")
}

/// An exact-match filter text: at most [`MAX_FILTER_TEXT_BYTES`] (the store's own bound), no NUL.
fn filter_text<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    match Option::<String>::deserialize(d).map_err(|_| refuse::<D::Error>("filter"))? {
        Some(s) if s.len() > MAX_FILTER_TEXT_BYTES || s.contains('\0') => Err(refuse("filter")),
        other => Ok(other),
    }
}

fn filter_decision<'de, D: Deserializer<'de>>(d: D) -> Result<Option<DecisionColumn>, D::Error> {
    match Option::<String>::deserialize(d).map_err(|_| refuse::<D::Error>("filter"))? {
        None => Ok(None),
        Some(s) => DecisionColumn::parse(&s)
            .map(Some)
            .ok_or_else(|| refuse("filter")),
    }
}

/// The `flags` bits by their §8.2 names.
const FLAG_NAMES: [(EventFlags, &str); 8] = [
    (EventFlags::EDITED, "edited"),
    (EventFlags::REDACTED, "redacted"),
    (EventFlags::BATCH, "batch"),
    (EventFlags::STALE, "stale"),
    (EventFlags::BACKWARDS, "clock_backwards"),
    (EventFlags::FORWARD, "clock_forward"),
    (EventFlags::BEHIND, "clock_behind"),
    (EventFlags::INTEGRITY_INCIDENT, "integrity_incident"),
];

/// Names of the §8.2 flags (each one bit), at most one of each.
fn filter_flags<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<EventFlags>, D::Error> {
    let names = Vec::<String>::deserialize(d).map_err(|_| refuse::<D::Error>("filter"))?;
    if names.len() > FLAG_NAMES.len() {
        return Err(refuse("filter"));
    }
    let mut out = Vec::with_capacity(names.len());
    for name in &names {
        let flag = FLAG_NAMES
            .iter()
            .find(|(_, n)| n == name)
            .map(|(f, _)| *f)
            .ok_or_else(|| refuse::<D::Error>("filter"))?;
        if !out.contains(&flag) {
            out.push(flag);
        }
    }
    Ok(out)
}

/// §8.3 event type names, at most one of each.
fn filter_event_types<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<EventType>, D::Error> {
    let names = Vec::<String>::deserialize(d).map_err(|_| refuse::<D::Error>("filter"))?;
    if names.len() > EventType::ALL.len() {
        return Err(refuse("filter"));
    }
    let mut out = Vec::with_capacity(names.len());
    for name in &names {
        let t = EventType::parse(name).ok_or_else(|| refuse::<D::Error>("filter"))?;
        if !out.contains(&t) {
            out.push(t);
        }
    }
    Ok(out)
}

/// The Audit window's filter (§8.10): plaintext columns only, `target` by prefix; no payload search
/// (L38). Every key may be absent or `null` (no constraint). A refused value names `filter`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterArgs {
    #[serde(default, deserialize_with = "filter_utc")]
    pub from_utc: Option<UtcInstant>,
    #[serde(default, deserialize_with = "filter_utc")]
    pub to_utc: Option<UtcInstant>,
    #[serde(default, deserialize_with = "filter_text")]
    pub agent_name: Option<String>,
    #[serde(default, deserialize_with = "filter_text")]
    pub op_id: Option<String>,
    #[serde(default, deserialize_with = "filter_text")]
    pub op_class: Option<String>,
    #[serde(default, deserialize_with = "filter_text")]
    pub instance_id: Option<String>,
    #[serde(default, deserialize_with = "filter_text")]
    pub target: Option<String>,
    #[serde(default, deserialize_with = "filter_decision")]
    pub decision: Option<DecisionColumn>,
    #[serde(default, deserialize_with = "filter_flags")]
    pub flags_any: Vec<EventFlags>,
    #[serde(default, deserialize_with = "filter_event_types")]
    pub event_types: Vec<EventType>,
}

impl FilterArgs {
    pub fn into_filter(self) -> AuditFilter {
        AuditFilter {
            from_utc: self.from_utc,
            to_utc: self.to_utc,
            agent_name: self.agent_name,
            op_id: self.op_id,
            op_class: self.op_class,
            instance_id: self.instance_id,
            target: self.target,
            decision: self.decision,
            flags_any: self.flags_any,
            event_types: self.event_types,
        }
    }
}

fn page_limit<'de, D: Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    match u32::deserialize(d) {
        Ok(n) if (1..=MAX_AUDIT_PAGE_ROWS).contains(&n) => Ok(n),
        _ => Err(refuse("cursor")),
    }
}

/// A page's keyset position (`AuditCursor`): rows with `seq < before_seq`, newest first, `limit`
/// of them (1 to [`MAX_AUDIT_PAGE_ROWS`]). The UI sends back the `next` it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorArgs {
    #[serde(default)]
    pub before_seq: Option<u64>,
    #[serde(deserialize_with = "page_limit")]
    pub limit: u32,
}

/// `audit_query {filter, cursor?}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQueryArgs {
    pub filter: FilterArgs,
    #[serde(default)]
    pub cursor: Option<CursorArgs>,
}

/// `audit_trail {request_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditTrailArgs {
    pub request_id: RequestId,
}

/// `audit_payload {seq, page?}`: page 0 when absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPayloadArgs {
    pub seq: u64,
    #[serde(default)]
    pub page: Option<u32>,
}

/// `audit_status {}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditStatusArgs {}

// ---------- answers ----------

/// One event's plaintext columns (§8.2) as the window shows them: every text display-escaped
/// (agent, peer and Atlassian strings are untrusted), flags by name, no payload.
/// One event's plaintext columns (§8.2) as the window shows them: every text display-escaped
/// (agent, peer and Atlassian strings are untrusted), flags by name, no payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventHeaderDto {
    pub seq: u64,
    pub ts_utc: String,
    pub epoch: Option<String>,
    pub chain_id: String,
    pub event_type: &'static str,
    pub request_id: Option<String>,
    pub op_id: Option<String>,
    pub op_class: Option<String>,
    pub instance_id: Option<String>,
    pub target: Option<String>,
    pub decision: Option<&'static str>,
    pub flags: Vec<&'static str>,
    pub agent_name: Option<String>,
    pub agent_name_source: Option<String>,
    pub client_kind: Option<String>,
    pub connection_id: Option<String>,
    pub peer_pid: Option<u32>,
    pub peer_exe: Option<String>,
    pub peer_origin_exe: Option<String>,
    pub os_user: Option<String>,
    pub atlassian_user: Option<String>,
    pub atlassian_user_key: Option<String>,
    pub payload_len: u64,
    pub key_id: u64,
}

fn shown(s: &Option<String>) -> Option<String> {
    s.as_deref().map(escape_for_display)
}

fn shown_path(p: &Option<std::path::PathBuf>) -> Option<String> {
    p.as_deref()
        .map(|p| escape_for_display(&p.to_string_lossy()))
}

impl EventHeaderDto {
    pub fn of(h: &EventHeader) -> EventHeaderDto {
        EventHeaderDto {
            seq: h.seq,
            ts_utc: escape_for_display(&h.ts_utc),
            epoch: shown(&h.epoch),
            chain_id: escape_for_display(&h.chain_id),
            event_type: h.event_type.as_str(),
            request_id: shown(&h.request_id),
            op_id: shown(&h.op_id),
            op_class: shown(&h.op_class),
            instance_id: shown(&h.instance_id),
            target: shown(&h.target),
            decision: h.decision.map(DecisionColumn::as_str),
            flags: FLAG_NAMES
                .iter()
                .filter(|(f, _)| h.flags.contains(*f))
                .map(|(_, n)| *n)
                .collect(),
            agent_name: shown(&h.actor.agent_name),
            agent_name_source: shown(&h.actor.agent_name_source),
            client_kind: shown(&h.actor.client_kind),
            connection_id: shown(&h.actor.connection_id),
            peer_pid: h.actor.peer_pid,
            peer_exe: shown_path(&h.actor.peer_exe),
            peer_origin_exe: shown_path(&h.actor.peer_origin_exe),
            os_user: shown(&h.actor.os_user),
            atlassian_user: shown(&h.actor.atlassian_user),
            atlassian_user_key: shown(&h.actor.atlassian_user_key),
            payload_len: h.payload_len,
            key_id: h.key_id,
        }
    }
}

/// The `cursor` to send back for the next page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CursorDto {
    pub before_seq: Option<u64>,
    pub limit: u32,
}

/// `audit_query`'s answer: rows newest first. `next` is set while more rows may follow, also
/// after an empty page the store's row budget ended early: the window follows it until `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditPageDto {
    pub rows: Vec<EventHeaderDto>,
    pub next: Option<CursorDto>,
    pub scanned: u64,
}

impl AuditPageDto {
    fn of(p: &AuditPage) -> AuditPageDto {
        AuditPageDto {
            rows: p.rows.iter().map(EventHeaderDto::of).collect(),
            next: p.next.map(|c| CursorDto {
                before_seq: c.before_seq,
                limit: c.limit,
            }),
            scanned: p.scanned,
        }
    }
}

/// The `DELIVERED` facts of a request (§8.10 highlight, advisory): `count > 1` is "delivered more
/// than once", `to_other_peer` "delivered to a different program".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DeliveriesDto {
    pub count: u64,
    pub to_other_peer: bool,
}

/// `audit_trail`'s answer: every retained header of the request, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditTrailDto {
    pub headers: Vec<EventHeaderDto>,
    pub deliveries: DeliveriesDto,
}

impl AuditTrailDto {
    fn of(t: &AuditTrail) -> AuditTrailDto {
        AuditTrailDto {
            headers: t.headers.iter().map(EventHeaderDto::of).collect(),
            deliveries: DeliveriesDto {
                count: t.deliveries.count,
                to_other_peer: t.deliveries.to_other_peer,
            },
        }
    }
}

/// `audit_payload`'s answer (PD-67, PD-68): `srcdoc` is the sandboxed document of the page (the
/// JSON tree when the payload is one page, else the page as text) and `display` the page's PD-68
/// projection (escapes and whitespace marked, a UTF-8 sequence cut by the boundary carried).
/// `credential_change` is set on every page of a `CREDENTIAL_CHANGED` record whose `change` is a
/// failed keychain step, for the window's fixed line (L126); `null` for anything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditPayloadDto {
    pub srcdoc: String,
    pub page: u32,
    pub page_count: u32,
    pub total_bytes: u64,
    pub display: String,
    pub credential_change: Option<CredentialChangeFailure>,
}

/// The two corrective `CREDENTIAL_CHANGED.change` values (the keychain write or delete that followed
/// the record failed); closed, never the payload's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialChangeFailure {
    StoreFailed,
    DeleteFailed,
}

/// One open integrity incident: the `VERIFY` seq and, from its record, the result and the time it
/// was detected (`null` both when the record cannot be read).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IncidentDto {
    pub verify_seq: u64,
    pub result: Option<String>,
    pub detected_at: Option<String>,
}

/// `audit_status`'s answer (§8.10, L134): the open incidents (at most [`MAX_LISTED_INCIDENTS`],
/// newest first), their count, the store health and the anchor directory (display only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditStatusDto {
    pub open_incidents: Vec<IncidentDto>,
    pub incident_count: u64,
    pub health: StoreHealthView,
    pub anchor_dir: Option<String>,
}

// ---------- the reads (sync) ----------

/// A store read's failure: an unknown seq is `not_found`, a closed store `not_ready`, a record
/// that cannot be read `audit/unreadable`, anything else `audit/failed`. No error text.
fn read_error(e: AuditError) -> AuditReadError {
    match e {
        AuditError::NotFound { .. } => AuditReadError::NotFound,
        AuditError::Closed => AuditReadError::NotReady,
        AuditError::Decrypt { seq }
        | AuditError::PayloadHash { seq }
        | AuditError::InvalidRecord { seq, .. } => AuditReadError::Unreadable { seq },
        _ => AuditReadError::Failed,
    }
}

/// `audit_query`: one page of matching headers (plaintext columns only; L38).
pub fn query(store: &Store, args: AuditQueryArgs) -> Result<AuditPageDto, AuditReadError> {
    let cursor = args
        .cursor
        .map_or(AuditCursor::first(DEFAULT_PAGE_ROWS), |c| AuditCursor {
            before_seq: c.before_seq,
            limit: c.limit,
        });
    match store.query(&args.filter.into_filter(), cursor) {
        Ok(page) => Ok(AuditPageDto::of(&page)),
        Err(AuditError::Invalid(_)) => Err(AuditReadError::InvalidArgument { field: "filter" }),
        Err(e) => Err(read_error(e)),
    }
}

/// `audit_trail`: every header of a request and its delivery summary.
pub fn trail(store: &Store, request_id: &str) -> Result<AuditTrailDto, AuditReadError> {
    store
        .trail(request_id)
        .map(|t| AuditTrailDto::of(&t))
        .map_err(read_error)
}

/// `audit_payload`: page `page` of record `seq`'s decrypted payload (PD-68 paging over
/// `Store::payload_view`). The UTF-8 carry into a page comes from the page before it, read here,
/// never from the UI; a page past the last is `invalid_argument {page}`.
pub fn payload(
    store: &Store,
    seq: u64,
    page: u32,
    platform: Platform,
) -> Result<AuditPayloadDto, AuditReadError> {
    let view = |p: u32| match store.payload_view(seq, p) {
        Err(AuditError::Invalid(_)) => Err(AuditReadError::InvalidArgument { field: "page" }),
        other => other.map_err(read_error),
    };
    let current = view(page)?;
    let carry = match page.checked_sub(1) {
        Some(before) => zeroize::Zeroizing::new(incomplete_tail(&view(before)?.bytes).to_vec()),
        None => zeroize::Zeroizing::new(Vec::new()),
    };
    let last = page.saturating_add(1) == current.page_count;
    let display = if last {
        render::raw_display_last(&current.bytes, &carry)
    } else {
        render::raw_display(&current.bytes, &carry)
    }
    .text;
    let srcdoc = if current.page_count == 1 {
        render::audit_payload_document(&current.bytes, platform)
    } else {
        render::audit_payload_page_document(&display, platform)
    };
    Ok(AuditPayloadDto {
        srcdoc,
        page: current.page,
        page_count: current.page_count,
        total_bytes: current.total_bytes,
        display,
        credential_change: credential_failure(store, seq),
    })
}

/// L126: the failed keychain step a `CREDENTIAL_CHANGED` record `seq` names in its payload's
/// `change` (`store_failed`, `delete_failed`), else `None`: another change, another record kind,
/// or a record that cannot be read here (the payload view itself says that). The kind comes from
/// the record's header (a primary-key lookup of the one row at `seq`: no `query` window walk), so
/// other records are not decrypted again.
fn credential_failure(store: &Store, seq: u64) -> Option<CredentialChangeFailure> {
    if store.event_type_at(seq).ok()? != EventType::CREDENTIAL_CHANGED {
        return None;
    }
    let bytes = store.read_payload(seq).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    match payload.get("change").and_then(serde_json::Value::as_str)? {
        "store_failed" => Some(CredentialChangeFailure::StoreFailed),
        "delete_failed" => Some(CredentialChangeFailure::DeleteFailed),
        _ => None,
    }
}

/// The result and detected-at time of the `VERIFY` record `seq`, as its payload holds them (its
/// `result` and `detected_at` keys; the rest is not read): a short snake_case word and the RFC 3339
/// text the store wrote. Anything else is `unreadable` (fail closed: the dialog names only what the
/// record says).
pub fn incident_facts(store: &Store, seq: u64) -> Result<(String, String), AuditReadError> {
    let unreadable = AuditReadError::Unreadable { seq };
    let bytes = store.read_payload(seq).map_err(read_error)?;
    let payload: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| unreadable)?;
    let key = |k: &str| payload.get(k).and_then(serde_json::Value::as_str);
    let (Some(result), Some(detected_at)) = (key("result"), key("detected_at")) else {
        return Err(unreadable);
    };
    let word = (1..=MAX_RESULT_CHARS).contains(&result.len())
        && result
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !word || UtcInstant::parse_rfc3339_ms(detected_at).is_none() {
        return Err(unreadable);
    }
    Ok((result.to_owned(), detected_at.to_owned()))
}

/// `audit_status`: the open incidents with their facts, the health and the anchor directory.
pub fn status(store: &Store) -> Result<AuditStatusDto, AuditReadError> {
    let open = store.open_incidents();
    let open_incidents = open
        .iter()
        .rev()
        .take(MAX_LISTED_INCIDENTS)
        .map(|&verify_seq| {
            let facts = incident_facts(store, verify_seq).ok();
            IncidentDto {
                verify_seq,
                result: facts.as_ref().map(|f| f.0.clone()),
                detected_at: facts.map(|f| f.1),
            }
        })
        .collect();
    Ok(AuditStatusDto {
        open_incidents,
        incident_count: u64::try_from(open.len()).unwrap_or(u64::MAX),
        health: StoreHealthView::of(&store.health()),
        anchor_dir: store
            .settings()
            .anchor_dir
            .as_deref()
            .map(escape_for_display),
    })
}
