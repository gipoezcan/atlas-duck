//! The approvals commands' wire types (C.10 + Δ1, PD-66), shared by the desktop app's Tauri
//! commands and the server's `/api/cmd/*` endpoints (M12 PD-206): the bounded argument newtypes and
//! argument structs (`#[serde(deny_unknown_fields)]`), the response DTOs the app adds to core's own
//! types, and the `UiEvent` → `(name, payload)` table of the UI events. Pure serde, no Tauri: the
//! app's `commands::dto`, `commands::approvals` and `ui_sink` re-export these under their old
//! names.
//!
//! A bounded newtype refuses an out-of-bounds value while the body is parsed, so a refused value
//! is answered with its field before any handler (and any core call) runs: [`parse`] returns the
//! field a newtype refused, or [`FIELD_PAYLOAD`] for any other refusal.

use std::cell::Cell;

use atlas_duck_preview::{Platform, Preview, PreviewBody, render};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};

use crate::{
    AttentionKind, BatchItem, CandidateRev, Decision, DecisionApi, DecisionError, DecisionKind,
    DenyDetails, DropScope, Edits, PreviewDelivery, QueueItem, RedactionContext, RedactionOp,
    RedactionPreset, RequestDetail, UiEvent, UrlMode,
};

/// `field` of a body that is not a JSON object of the command's argument struct (unknown key,
/// wrong type, missing key, raw bytes).
pub const FIELD_PAYLOAD: &str = "payload";
/// PD-66: a request id is `req_` and 20 to 64 of `[A-Za-z0-9_-]`.
pub const REQUEST_ID_MIN: usize = 20;
pub const REQUEST_ID_MAX: usize = 64;
/// §3.3 / PD-66: a human reason is at most 1 000 characters.
pub const REASON_MAX_CHARS: usize = 1_000;

thread_local! {
    /// The field a bounded newtype refused during the current `parse` (the parse is synchronous,
    /// on this thread).
    static REFUSED: Cell<Option<&'static str>> = const { Cell::new(None) };
}

/// A serde error for `field`, noted for [`parse`] so the answer can name it (for the bounded
/// newtypes of every command module).
pub fn refuse<E: serde::de::Error>(field: &'static str) -> E {
    REFUSED.with(|r| r.set(Some(field)));
    E::custom(field)
}

/// Parses a command body into `T`: a value a bounded newtype refused (out of bounds, wrong type or
/// missing) is `Err` with that newtype's field; any other refusal (unknown key, a plain field of
/// the wrong type or missing) is `Err(FIELD_PAYLOAD)`, and so is a body that is not a JSON object
/// (serde would take a struct's fields positionally from an array). The serde message is never
/// passed on.
pub fn parse<T: DeserializeOwned>(body: &Value) -> Result<T, &'static str> {
    if !body.is_object() {
        return Err(FIELD_PAYLOAD);
    }
    REFUSED.with(|r| r.set(None));
    let parsed = T::deserialize(body);
    let field = REFUSED.with(Cell::take);
    parsed.map_err(|_| field.unwrap_or(FIELD_PAYLOAD))
}

/// PD-66 request id: `^req_[A-Za-z0-9_-]{20,64}$`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RequestId(String);

impl RequestId {
    pub fn is_valid(s: &str) -> bool {
        s.strip_prefix("req_").is_some_and(|rest| {
            (REQUEST_ID_MIN..=REQUEST_ID_MAX).contains(&rest.len())
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d).map_err(|_| refuse::<D::Error>("request_id"))?;
        if RequestId::is_valid(&s) {
            Ok(RequestId(s))
        } else {
            Err(refuse("request_id"))
        }
    }
}

/// A human reason (§3.3, PD-66): at most [`REASON_MAX_CHARS`] characters, no `\0`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Reason(String);

impl Reason {
    pub fn is_valid(s: &str) -> bool {
        !s.contains('\0') && s.chars().count() <= REASON_MAX_CHARS
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<'de> Deserialize<'de> for Reason {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d).map_err(|_| refuse::<D::Error>("reason"))?;
        if Reason::is_valid(&s) {
            Ok(Reason(s))
        } else {
            Err(refuse("reason"))
        }
    }
}

/// A candidate revision `{counter, candidate_hash}` with nothing else: `CandidateRev`'s own
/// `Deserialize` (lowercase hex of exactly 32 bytes) under a closed key set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CandidateRevDto(pub CandidateRev);

impl<'de> Deserialize<'de> for CandidateRevDto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        const KEYS: [&str; 2] = ["counter", "candidate_hash"];
        let v = Value::deserialize(d).map_err(|_| refuse::<D::Error>("candidate_rev"))?;
        let closed = v
            .as_object()
            .is_some_and(|m| m.keys().all(|k| KEYS.contains(&k.as_str())));
        if !closed {
            return Err(refuse("candidate_rev"));
        }
        CandidateRev::deserialize(v)
            .map(CandidateRevDto)
            .map_err(|_| refuse("candidate_rev"))
    }
}

/// Parses `d` as a JSON value and then as `T`; a refusal at either step names `field`.
fn nested<'de, T: DeserializeOwned, D: Deserializer<'de>>(
    d: D,
    field: &'static str,
) -> Result<T, D::Error> {
    let v = Value::deserialize(d).map_err(|_| refuse::<D::Error>(field))?;
    T::deserialize(v).map_err(|_| refuse::<D::Error>(field))
}

/// plan text (PD-66): `edits` is at most 1 MiB of serialized JSON.
pub const EDITS_MAX_BYTES: usize = 1 << 20;
/// plan text (PD-66): at most 1 000 redaction ops, and 1 000 request ids or batch items per call
/// (the queue holds far fewer; the bound only keeps a call finite).
pub const LIST_MAX: usize = 1_000;
/// plan text (PD-66): a string of one redaction op (and the value of a `drop_item`) is at most
/// 64 KiB.
pub const OP_STRING_MAX_BYTES: usize = 64 << 10;
/// Defence in depth (final review M-15): all redaction ops of one call together are at most 2 MiB of
/// serialized JSON, the isolation hook's own payload cap; each op is bounded on its own as well.
pub const REDACTION_OPS_MAX_BYTES: usize = 2 << 20;
/// PD-86: a session id is the lowercase hex SHA-256 of the session key.
pub const SESSION_ID_LEN: usize = 64;

/// The five decision kinds of C.7 (`DecisionKind` has no `Deserialize`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionDto(pub DecisionKind);

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum DecisionWire {
    Approve,
    ApproveEdited,
    Release,
    ReleaseRedacted,
    Deny,
}

impl<'de> Deserialize<'de> for DecisionDto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(DecisionDto(
            match nested::<DecisionWire, D>(d, "decision")? {
                DecisionWire::Approve => DecisionKind::Approve,
                DecisionWire::ApproveEdited => DecisionKind::ApproveEdited,
                DecisionWire::Release => DecisionKind::Release,
                DecisionWire::ReleaseRedacted => DecisionKind::ReleaseRedacted,
                DecisionWire::Deny => DecisionKind::Deny,
            },
        ))
    }
}

/// The deny-hint choice (§5.4/§6.3/§11.2): the wire form of `DenyDetails`' own serialization, a
/// closed set of keys per kind. Core still decides whether it accepts the kind (PD-70).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenyDetailsDto(pub DenyDetails);

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum DenyDetailsWire {
    UpstreamHttp { include_messages: bool },
    OutcomeHint,
    ResolutionFailed { include_candidates: bool },
    MissingFields { include_allowed_values: bool },
}

impl<'de> Deserialize<'de> for DenyDetailsDto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(DenyDetailsDto(
            match nested::<DenyDetailsWire, D>(d, "deny_details")? {
                DenyDetailsWire::UpstreamHttp { include_messages } => {
                    DenyDetails::UpstreamHttp { include_messages }
                }
                DenyDetailsWire::OutcomeHint => DenyDetails::OutcomeHint,
                DenyDetailsWire::ResolutionFailed { include_candidates } => {
                    DenyDetails::ResolutionFailed { include_candidates }
                }
                DenyDetailsWire::MissingFields {
                    include_allowed_values,
                } => DenyDetails::MissingFields {
                    include_allowed_values,
                },
            },
        ))
    }
}

/// The human's edits `{set, remove}` (C.7), at most [`EDITS_MAX_BYTES`] of JSON; a missing key is
/// empty. Whether a key may be edited is core's decision (targets and baselines are immutable).
#[derive(Debug, Clone, PartialEq)]
pub struct EditsDto(pub Edits);

impl<'de> Deserialize<'de> for EditsDto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bad = || refuse::<D::Error>("edits");
        let v = Value::deserialize(d).map_err(|_| bad())?;
        let m = v.as_object().ok_or_else(bad)?;
        if !m.keys().all(|k| k == "set" || k == "remove") || !bounded_json(&v, EDITS_MAX_BYTES) {
            return Err(bad());
        }
        let set = match m.get("set") {
            None => serde_json::Map::new(),
            Some(s) => s.as_object().cloned().ok_or_else(bad)?,
        };
        let remove = match m.get("remove") {
            None => Vec::new(),
            Some(Value::Array(a)) if a.len() <= LIST_MAX => a
                .iter()
                .map(|k| k.as_str().map(str::to_owned))
                .collect::<Option<Vec<String>>>()
                .ok_or_else(bad)?,
            Some(_) => return Err(bad()),
        };
        Ok(EditsDto(Edits { set, remove }))
    }
}

/// One redaction op in its wire form: the externally tagged shape `RedactionOp` serializes to,
/// every key closed. The two `*_loc` fields are redaction-grammar locations inside the candidate
/// JSON (`issues[key=A].fields`), not filesystem paths. Their wire names are the Rust names (the
/// `check-commands` rule holds wire names too, so there is no rename back to `path`).
/// `Serialize` (M6 T17): a revision's ops go back to the UI in this same form (`preview_fetch`),
/// so the UI resends them unchanged in front of new ones.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RedactionOpWire {
    DropItem {
        array_loc: String,
        key: String,
        value: Value,
    },
    DropField {
        field_loc: String,
        scope: DropScope,
    },
    MaskText {
        text: String,
        every_occurrence: bool,
        at: Option<String>,
    },
    UrlField {
        mode: UrlMode,
    },
    Preset(RedactionPreset),
}

impl RedactionOpWire {
    fn within_bounds(&self) -> bool {
        let ok = |s: &str| s.len() <= OP_STRING_MAX_BYTES;
        match self {
            Self::DropItem {
                array_loc,
                key,
                value,
            } => ok(array_loc) && ok(key) && bounded_json(value, OP_STRING_MAX_BYTES),
            Self::DropField { field_loc, .. } => ok(field_loc),
            Self::MaskText { text, at, .. } => ok(text) && at.as_deref().is_none_or(ok),
            Self::UrlField { .. } | Self::Preset(_) => true,
        }
    }

    fn into_op(self) -> RedactionOp {
        match self {
            Self::DropItem {
                array_loc,
                key,
                value,
            } => RedactionOp::DropItem {
                array_path: array_loc,
                key,
                value,
            },
            Self::DropField { field_loc, scope } => RedactionOp::DropField {
                path: field_loc,
                scope,
            },
            Self::MaskText {
                text,
                every_occurrence,
                at,
            } => RedactionOp::MaskText {
                text,
                every_occurrence,
                at,
            },
            Self::UrlField { mode } => RedactionOp::UrlField { mode },
            Self::Preset(p) => RedactionOp::Preset(p),
        }
    }
}

/// Redacting, as `RedactionOp`'s own `Debug` (§7.7): lengths, never the text, path or value.
impl std::fmt::Debug for RedactionOpWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.clone().into_op(), f)
    }
}

impl From<&RedactionOp> for RedactionOpWire {
    fn from(op: &RedactionOp) -> Self {
        match op.clone() {
            RedactionOp::DropItem {
                array_path,
                key,
                value,
            } => Self::DropItem {
                array_loc: array_path,
                key,
                value,
            },
            RedactionOp::DropField { path, scope } => Self::DropField {
                field_loc: path,
                scope,
            },
            RedactionOp::MaskText {
                text,
                every_occurrence,
                at,
            } => Self::MaskText {
                text,
                every_occurrence,
                at,
            },
            RedactionOp::UrlField { mode } => Self::UrlField { mode },
            RedactionOp::Preset(p) => Self::Preset(p),
        }
    }
}

/// At most [`LIST_MAX`] redaction ops, each inside its bounds (PD-66); a refusal names `field`.
fn redaction_ops<'de, D: Deserializer<'de>>(
    d: D,
    field: &'static str,
) -> Result<Vec<RedactionOp>, D::Error> {
    let bad = || refuse::<D::Error>(field);
    let v = Value::deserialize(d).map_err(|_| bad())?;
    if !bounded_json(&v, REDACTION_OPS_MAX_BYTES) {
        return Err(bad());
    }
    let Value::Array(items) = v else {
        return Err(bad());
    };
    if items.len() > LIST_MAX {
        return Err(bad());
    }
    let mut ops = Vec::with_capacity(items.len());
    for item in items {
        let wire = RedactionOpWire::deserialize(item).map_err(|_| bad())?;
        if !wire.within_bounds() {
            return Err(bad());
        }
        ops.push(wire.into_op());
    }
    Ok(ops)
}

/// The `redactions` of a decision.
#[derive(Debug, Clone, PartialEq)]
pub struct RedactionOpsDto(pub Vec<RedactionOp>);

impl<'de> Deserialize<'de> for RedactionOpsDto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        redaction_ops(d, "redactions").map(RedactionOpsDto)
    }
}

/// The `ops` of a redaction preview.
#[derive(Debug, Clone, PartialEq)]
pub struct PreviewOpsDto(pub Vec<RedactionOp>);

impl<'de> Deserialize<'de> for PreviewOpsDto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        redaction_ops(d, "ops").map(PreviewOpsDto)
    }
}

/// One to [`LIST_MAX`] request ids (PD-66 pattern each).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RequestIds(Vec<String>);

impl RequestIds {
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RequestIds {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let ids: Vec<String> = nested(d, "request_ids")?;
        if (1..=LIST_MAX).contains(&ids.len()) && ids.iter().all(|s| RequestId::is_valid(s)) {
            Ok(RequestIds(ids))
        } else {
            Err(refuse("request_ids"))
        }
    }
}

/// One batch item: the request and the revision the approver saw.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchItemWire {
    request_id: RequestId,
    candidate_rev: CandidateRevDto,
}

/// One to [`LIST_MAX`] `{request_id, candidate_rev}` items of a batch decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchItems(pub Vec<BatchItem>);

impl<'de> Deserialize<'de> for BatchItems {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bad = || refuse::<D::Error>("items");
        let v = Value::deserialize(d).map_err(|_| bad())?;
        let Value::Array(items) = v else {
            return Err(bad());
        };
        if !(1..=LIST_MAX).contains(&items.len()) {
            return Err(bad());
        }
        items
            .into_iter()
            .map(|item| {
                BatchItemWire::deserialize(item)
                    .map(|w| BatchItem {
                        request_id: w.request_id.into_inner(),
                        candidate_rev: w.candidate_rev.0,
                    })
                    .map_err(|_| bad())
            })
            .collect::<Result<Vec<_>, _>>()
            .map(BatchItems)
    }
}

/// PD-86: a session id, 64 lowercase hex characters; the app resolves it to the session key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    pub fn is_valid(s: &str) -> bool {
        s.len() == SESSION_ID_LEN && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d).map_err(|_| refuse::<D::Error>("session_id"))?;
        if SessionId::is_valid(&s) {
            Ok(SessionId(s))
        } else {
            Err(refuse("session_id"))
        }
    }
}

/// True when `v` serializes to at most `max_bytes` bytes of JSON (counted, not built: the count
/// stops at the first byte past the cap).
pub fn bounded_json(v: &Value, max_bytes: usize) -> bool {
    struct Counter {
        n: usize,
        max: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.n = self.n.saturating_add(buf.len());
            if self.n > self.max {
                return Err(std::io::Error::other("over the cap"));
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(
        Counter {
            n: 0,
            max: max_bytes,
        },
        v,
    )
    .is_ok()
}

/// `app_status {}` (Δ1, read-only).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppStatusArgs {}

/// PD-90 line level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusLevel {
    Caution,
    Info,
}

/// One PD-90 status line: a fixed id, app-generated text, a level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusLineDto {
    pub id: &'static str,
    pub text: String,
    pub level: StatusLevel,
}

// ---- the approvals commands (C.10 + Δ1) ----------------------------------------------------

/// `queue_list {}` (C.10): the queue rows, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueListArgs {}

/// `queue_get {request_id}` (C.10): one row; `not_found` once it left the queue.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueGetArgs {
    pub request_id: RequestId,
}

/// What `queue_get` returns (T14): the queue row and the Request tab's facts (params, hash,
/// reason, connection). `queue_list` rows stay light and carry no `request`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct QueueDetail {
    pub item: QueueItem,
    pub request: RequestDetail,
}

/// `decide {request_id, decision, candidate_rev, edits?, redactions?, reason?, deny_details?}`
/// (C.10, PD-20, PD-66): one decision on the revision the approver saw. Which combinations make
/// sense (a release of a write, an approve of an unopened revision, an edit of a target) is
/// core's call and its refusals pass through unchanged.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideArgs {
    pub request_id: RequestId,
    pub decision: DecisionDto,
    pub candidate_rev: CandidateRevDto,
    pub edits: Option<EditsDto>,
    pub redactions: Option<RedactionOpsDto>,
    pub reason: Option<Reason>,
    pub deny_details: Option<DenyDetailsDto>,
}

impl DecideArgs {
    /// The core decision, field for field.
    pub fn into_decision(self) -> Decision {
        Decision {
            request_id: self.request_id.into_inner(),
            decision: self.decision.0,
            candidate_rev: self.candidate_rev.0,
            edits: self.edits.map(|e| e.0),
            redactions: self.redactions.map(|r| r.0),
            reason: self.reason.map(Reason::into_inner),
            deny_details: self.deny_details.map(|d| d.0),
        }
    }
}

/// `decide_batch {items}` (C.10, L43): the natural positive decision of each item, all or
/// nothing; core confirms in its own native dialog (U-32).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideBatchArgs {
    pub items: BatchItems,
}

/// How many items a batch deny denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DenyCount {
    pub denied: u64,
}

impl DenyCount {
    /// `n` denied items (saturating).
    pub fn of(n: usize) -> DenyCount {
        DenyCount {
            denied: u64::try_from(n).unwrap_or(u64::MAX),
        }
    }
}

/// `deny_batch {request_ids, reason}` (Δ1, L43): no dialog, per item, not all-or-nothing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyBatchArgs {
    pub request_ids: RequestIds,
    pub reason: Reason,
}

/// `deny_session {session_id, reason}` (Δ1, PD-86): denies the queued items of one session.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenySessionArgs {
    pub session_id: SessionId,
    pub reason: Reason,
}

/// `acknowledge_attention {request_ids}` (C.10): in memory, not audited.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeAttentionArgs {
    pub request_ids: RequestIds,
}

/// `recent_list {}` (Δ1): the "Recently decided (24 h) / Needs attention" rows.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentListArgs {}

/// `redaction_preview {request_id, candidate_rev, ops}` (Δ1, Δ2): what `ops` would do to an
/// opened revision; UI-only, nothing is logged.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionPreviewArgs {
    pub request_id: RequestId,
    pub candidate_rev: CandidateRevDto,
    pub ops: PreviewOpsDto,
}

/// `preview_fetch {request_id, candidate_rev?}` (Δ1). Without `candidate_rev` the current
/// revision is shown (a missing `Option` field is `None`; no `#[serde(default)]` around a bounded
/// newtype, `check-commands`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewFetchArgs {
    pub request_id: RequestId,
    pub candidate_rev: Option<CandidateRevDto>,
}

/// `{preview, srcdoc, redaction}` (Δ1, PD-67; `redaction` M6 T17): the preview model for the
/// Structured/Raw/Request tabs, the Rust-rendered document the UI sets as the `srcDoc` of the
/// `<iframe sandbox="">`, and what the redaction panel builds on (`null` for a write or a read
/// outcome item).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewFetchResponse {
    pub preview: Preview,
    pub srcdoc: String,
    pub redaction: Option<RedactionContextDto>,
}

/// `RedactionContext` with its ops in the wire form the UI sends back (`RedactionOpWire`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedactionContextDto {
    pub ops: Vec<RedactionOpWire>,
    pub url_fields: Vec<&'static str>,
}

impl From<&RedactionContext> for RedactionContextDto {
    fn from(c: &RedactionContext) -> Self {
        RedactionContextDto {
            ops: c.ops.iter().map(RedactionOpWire::from).collect(),
            url_fields: c.url_fields.clone(),
        }
    }
}

/// The response for a delivered preview: the document rendered from it, and the preview without
/// the attachment thumbnail (T20b review m-1). The thumbnail reaches the screen only through the
/// document (no UI code reads `thumbnail_data_uri`), so at the 2 MiB cap it is sent once, not
/// twice.
pub fn preview_fetch_response(delivery: PreviewDelivery) -> PreviewFetchResponse {
    let srcdoc = render::document(&delivery.preview, Platform::current());
    let mut preview = delivery.preview;
    if let PreviewBody::AttachmentUpload {
        thumbnail_data_uri, ..
    } = &mut preview.body
    {
        *thumbnail_data_uri = None;
    }
    PreviewFetchResponse {
        redaction: delivery.redaction.as_ref().map(RedactionContextDto::from),
        preview,
        srcdoc,
    }
}

/// `raw_page {request_id, candidate_rev, page}` (Δ1, PD-68): the page of an opened revision.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPageArgs {
    pub request_id: RequestId,
    pub candidate_rev: CandidateRevDto,
    pub page: u64,
}

/// `{page, page_count, total_bytes, bytes_b64, display}` (PD-68): the exact slice of the hashed
/// candidate bytes as base64 (for the copy gesture and X-07 only) and the text the UI shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawPageDto {
    pub page: u64,
    pub page_count: u64,
    pub total_bytes: u64,
    pub bytes_b64: String,
    pub display: String,
}

/// Why a Raw page could not be answered.
#[derive(Debug, Clone, PartialEq)]
pub enum RawPageError {
    /// Core refused the read of the candidate (`NotDecidable`, `Stale`, `Invalid(..)`).
    Decision(DecisionError),
    /// A page past the last (`invalid_argument {page}` on the wire).
    PageOutOfRange,
}

/// One Raw page through `decisions` (PD-68), shared by the desktop command and the server: the
/// UTF-8 carry into the page is derived from the bytes of the page before it, never taken from
/// the UI; the last page shows an incomplete tail as bytes.
pub fn raw_page_response(
    decisions: &dyn DecisionApi,
    request_id: &str,
    rev: CandidateRev,
    page: u64,
) -> Result<RawPageDto, RawPageError> {
    use base64::Engine as _;
    let current = decisions
        .raw_page(request_id, rev, page)
        .map_err(RawPageError::Decision)?;
    if page >= current.page_count {
        return Err(RawPageError::PageOutOfRange);
    }
    let carry = match page.checked_sub(1) {
        Some(before) => {
            let previous = decisions
                .raw_page(request_id, rev, before)
                .map_err(RawPageError::Decision)?;
            render::raw::incomplete_tail(&previous.bytes).to_vec()
        }
        None => Vec::new(),
    };
    let display = if page + 1 == current.page_count {
        render::raw_display_last(&current.bytes, &carry)
    } else {
        render::raw_display(&current.bytes, &carry)
    };
    Ok(RawPageDto {
        page: current.page,
        page_count: current.page_count,
        total_bytes: current.total_bytes,
        bytes_b64: base64::engine::general_purpose::STANDARD.encode(&current.bytes),
        display: display.text,
    })
}

// ---- UI events (C.10) ----------------------------------------------------------------------

/// The C.10 event name and payload of a core event. Payloads carry ids and counts only, never an
/// agent string, a param or a fetched value (§5.6, §10.1). The desktop `UiSink` emits these as
/// Tauri events, the server's as SSE events (PD-206).
pub fn ui_event_json(e: &UiEvent) -> (&'static str, Value) {
    match e {
        UiEvent::QueueChanged { request_ids } => {
            ("queue_changed", json!({ "request_ids": request_ids }))
        }
        UiEvent::Attention { kind, count } => (
            "attention",
            json!({ "kind": attention_kind(*kind), "count": count }),
        ),
        UiEvent::StatusBanner { line_ids } => ("status_banner", json!({ "line_ids": line_ids })),
        UiEvent::NeedsAttentionChanged { count } => {
            ("needs_attention_changed", json!({ "count": count }))
        }
        UiEvent::RunningScriptsChanged => ("running_scripts_changed", Value::Null),
        UiEvent::CredentialContextChanged => ("credential_context_changed", Value::Null),
    }
}

fn attention_kind(k: AttentionKind) -> &'static str {
    match k {
        AttentionKind::New => "new",
        AttentionKind::Stale => "stale",
        AttentionKind::Failed => "failed",
        AttentionKind::OutcomeUnknown => "outcome_unknown",
    }
}

/// One representative value of each response DTO the approvals commands return, equal to the
/// UI fixtures `app/ui/src/shared/ipc/fixtures/<name>.json` that the UI validators are tested
/// against (the app's `dto_fixtures` test writes them). Binds the Rust DTOs to those fixtures for
/// desktop and server alike.
#[cfg(any(test, feature = "testing"))]
pub mod golden {
    use atlas_duck_ipc::envelope::Status;
    use serde_json::{Value, json};

    use super::{
        DenyCount, QueueDetail, RawPageDto, RedactionContextDto, StatusLevel, StatusLineDto,
    };
    use crate::redact::BlockReason;
    use crate::{
        BatchOutcome, CandidateRev, DecisionOutcome, DropScope, QueueItem, RecentItem,
        RedactionContext, RedactionOp, RedactionPreset, RedactionReport, RequestDetail, SessionKey,
        UrlMode,
    };

    const REQ: &str = "req_0123456789abcdefghij";
    const REQ_2: &str = "req_abcdefghij0123456789";

    fn rev() -> CandidateRev {
        CandidateRev {
            counter: 2,
            candidate_hash: [0xab; 32],
        }
    }

    /// Every fixture name with the serialized samples it must equal.
    pub fn golden() -> Result<Vec<(&'static str, Value)>, serde_json::Error> {
        Ok(vec![
            ("queue_item", serde_json::to_value(queue_items())?),
            ("queue_detail", serde_json::to_value(queue_details())?),
            ("recent_item", serde_json::to_value(recent_items())?),
            (
                "decision_outcome",
                serde_json::to_value(decision_outcomes())?,
            ),
            ("batch_outcome", serde_json::to_value(batch_outcomes())?),
            ("deny_count", serde_json::to_value(deny_counts())?),
            (
                "redaction_report",
                serde_json::to_value(redaction_reports())?,
            ),
            (
                "redaction_context",
                serde_json::to_value(redaction_contexts())?,
            ),
            ("raw_page", serde_json::to_value(raw_pages())?),
            ("status_line", serde_json::to_value(status_lines())?),
        ])
    }

    fn queue_item(full: bool) -> QueueItem {
        // Never serialized (PD-86); only its id and label reach the wire.
        let session = SessionKey {
            agent_name: full.then(|| "claude-code".into()),
            peer_origin_exe: None,
            connection_id: None,
            cwd_basename: "atlas-duck".into(),
        };
        let (request_id, op_id, class, target) = if full {
            (REQ, "jira.issue.get", "read", "PROJ-1")
        } else {
            (
                "req_nullnullnullnullnull",
                "jira.issue.create",
                "write",
                "PROJ",
            )
        };
        QueueItem {
            request_id: request_id.into(),
            op_id: op_id.into(),
            class,
            instance_alias: "work".into(),
            target_display: target.into(),
            agent_name: full.then(|| "claude-code".into()),
            agent_unverified: true,
            reason_excerpt: full.then(|| "look up the ticket".into()),
            unusual: false,
            age_s: if full { 12 } else { 3 },
            stale: false,
            caution_count: u32::from(full),
            possible_duplicate_of: full.then(|| REQ_2.into()),
            similar_to: None,
            session_id: session.id(),
            session_label: session.label(),
            session,
            opened: false,
            approvable: true,
            candidate_rev: if full {
                rev()
            } else {
                CandidateRev {
                    counter: 1,
                    candidate_hash: [0xab; 32],
                }
            },
        }
    }

    /// A full row and one of an agent that sent no name and no reason (every `Option` null).
    pub fn queue_items() -> Vec<QueueItem> {
        vec![queue_item(true), queue_item(false)]
    }

    pub fn queue_details() -> Vec<QueueDetail> {
        vec![
            QueueDetail {
                item: queue_item(true),
                request: RequestDetail {
                    params: json!({ "key": "PROJ-1", "fields": ["summary", "status"] }),
                    params_sha256: "cd".repeat(32),
                    reason: Some("look up the ticket".into()),
                    submitted_at: "2026-10-14T09:30:00.000Z".into(),
                    client_kind: Some("cli".into()),
                    agent_name: Some("claude-code".into()),
                    agent_name_source: Some("flag".into()),
                    cwd_basename: "atlas-duck".into(),
                    connection_id: Some("conn-0001".into()),
                    peer_pid: Some(4242),
                    peer_exe: Some("/usr/bin/atlas".into()),
                    peer_origin_exe: Some("/usr/bin/zsh".into()),
                    peer_chain: vec!["4242 /usr/bin/atlas".into(), "4100 /usr/bin/zsh".into()],
                },
            },
            QueueDetail {
                item: queue_item(false),
                request: RequestDetail {
                    params: Value::Null,
                    params_sha256: "ef".repeat(32),
                    reason: None,
                    submitted_at: "2026-10-14T09:31:00.000Z".into(),
                    client_kind: None,
                    agent_name: None,
                    agent_name_source: None,
                    cwd_basename: "atlas-duck".into(),
                    connection_id: None,
                    peer_pid: None,
                    peer_exe: None,
                    peer_origin_exe: None,
                    peer_chain: vec![],
                },
            },
        ]
    }

    pub fn recent_items() -> Vec<RecentItem> {
        vec![
            RecentItem {
                request_id: REQ.into(),
                op_id: "jira.comment.add".into(),
                class: "write",
                instance_alias: "work".into(),
                target_display: "PROJ-1".into(),
                status: Status::Failed,
                decided_at: "2026-10-14T09:30:00.000Z".into(),
                error_text: Some("HTTP 403: no permission".into()),
                needs_attention: true,
                acknowledged: false,
            },
            RecentItem {
                request_id: REQ_2.into(),
                op_id: "jira.issue.get".into(),
                class: "read",
                instance_alias: "work".into(),
                target_display: "PROJ-2".into(),
                status: Status::Released,
                decided_at: "2026-10-14T09:31:00.000Z".into(),
                error_text: None,
                needs_attention: false,
                acknowledged: false,
            },
        ]
    }

    pub fn decision_outcomes() -> Vec<DecisionOutcome> {
        vec![
            DecisionOutcome {
                request_id: REQ.into(),
                status: Status::Released,
            },
            DecisionOutcome {
                request_id: REQ_2.into(),
                status: Status::Pending,
            },
        ]
    }

    pub fn batch_outcomes() -> Vec<BatchOutcome> {
        vec![BatchOutcome {
            batch_id: "batch_0123456789abcdefghij".into(),
            items: decision_outcomes(),
        }]
    }

    pub fn deny_counts() -> Vec<DenyCount> {
        vec![DenyCount { denied: 0 }, DenyCount { denied: 3 }]
    }

    pub fn redaction_reports() -> Vec<RedactionReport> {
        vec![
            RedactionReport {
                blocked: vec![BlockReason::MaskStillOccurs {
                    path: "fields.summary".into(),
                }],
                also_appears_in: vec!["fields.description".into(), "comment[2]".into()],
                other_occurrences: 3,
                released_bytes: 1_024,
            },
            RedactionReport {
                blocked: vec![],
                also_appears_in: vec![],
                other_occurrences: 0,
                released_bytes: 512,
            },
            // Every other reason the UI labels (M6 T17).
            RedactionReport {
                blocked: vec![
                    BlockReason::UnstableEncoding {
                        path: "fields.description".into(),
                    },
                    BlockReason::ReencodeAmbiguous {
                        path: "self".into(),
                    },
                    BlockReason::MirrorOrphan {
                        path: "renderedFields.comment.comments[1]".into(),
                    },
                    BlockReason::MirrorUnmatchable {
                        path: "renderedFields.worklog.worklogs[0]".into(),
                    },
                    BlockReason::OpTargetMissing {
                        path: "fields.user.email".into(),
                    },
                    BlockReason::OverReleaseCap {
                        path: String::new(),
                    },
                ],
                also_appears_in: vec![],
                other_occurrences: 0,
                released_bytes: 16_777_217,
            },
        ]
    }

    /// `preview_fetch`'s `redaction` (M6 T17): a first revision, and one with every op kind.
    pub fn redaction_contexts() -> Vec<RedactionContextDto> {
        let ops = vec![
            RedactionOp::DropItem {
                array_path: "fields.comment.comments".into(),
                key: "id".into(),
                value: json!("10001"),
            },
            RedactionOp::DropField {
                path: "issues[key=ABC-1].fields.summary".into(),
                scope: DropScope::PerItem,
            },
            RedactionOp::DropField {
                path: "issues[key=ABC-1].fields.labels".into(),
                scope: DropScope::AllItems,
            },
            RedactionOp::MaskText {
                text: "Falcon".into(),
                every_occurrence: true,
                at: None,
            },
            RedactionOp::MaskText {
                text: "Falcon".into(),
                every_occurrence: false,
                at: Some("fields.description".into()),
            },
            RedactionOp::UrlField {
                mode: UrlMode::ReplaceWhole,
            },
            RedactionOp::UrlField {
                mode: UrlMode::Drop,
            },
            RedactionOp::Preset(RedactionPreset::StatusOnly),
            RedactionOp::Preset(RedactionPreset::ErrorClassOnly),
        ];
        [
            RedactionContext {
                ops: Vec::new(),
                url_fields: vec!["self", "fields.attachment[].content"],
                flagged: Vec::new(),
            },
            RedactionContext {
                ops,
                url_fields: Vec::new(),
                flagged: Vec::new(),
            },
        ]
        .iter()
        .map(RedactionContextDto::from)
        .collect()
    }

    pub fn raw_pages() -> Vec<RawPageDto> {
        vec![
            RawPageDto {
                page: 0,
                page_count: 2,
                total_bytes: 262_150,
                bytes_b64: "YQ0KYv8=".into(),
                display: "a⟨U+000D⟩\nb⟨0xFF⟩".into(),
            },
            RawPageDto {
                page: 1,
                page_count: 2,
                total_bytes: 262_150,
                bytes_b64: String::new(),
                display: String::new(),
            },
        ]
    }

    pub fn status_lines() -> Vec<StatusLineDto> {
        vec![
            StatusLineDto {
                id: "locked_refused",
                text: "Locked — 3 requests refused".into(),
                level: StatusLevel::Caution,
            },
            StatusLineDto {
                id: "needs_attention",
                text: "2 need attention".into(),
                level: StatusLevel::Info,
            },
            StatusLineDto {
                id: "anchor_dir_write_failing",
                text: "Writing to the anchor directory fails; 3 lines wait and will be retried."
                    .into(),
                level: StatusLevel::Caution,
            },
            StatusLineDto {
                id: "anchor_dir_lines_pending",
                text: "1 line waits to be written to the anchor directory.".into(),
                level: StatusLevel::Caution,
            },
            StatusLineDto {
                id: "anchors_missing",
                text: "The head anchor entry is missing from the keychain.".into(),
                level: StatusLevel::Caution,
            },
        ]
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The UI fixtures, read at compile time (the app's `dto_fixtures` test writes them).
    const FIXTURES: [(&str, &str); 10] = [
        (
            "queue_item",
            include_str!("../../../../app/ui/src/shared/ipc/fixtures/queue_item.json"),
        ),
        (
            "queue_detail",
            include_str!("../../../../app/ui/src/shared/ipc/fixtures/queue_detail.json"),
        ),
        (
            "recent_item",
            include_str!("../../../../app/ui/src/shared/ipc/fixtures/recent_item.json"),
        ),
        (
            "decision_outcome",
            include_str!("../../../../app/ui/src/shared/ipc/fixtures/decision_outcome.json"),
        ),
        (
            "batch_outcome",
            include_str!("../../../../app/ui/src/shared/ipc/fixtures/batch_outcome.json"),
        ),
        (
            "deny_count",
            include_str!("../../../../app/ui/src/shared/ipc/fixtures/deny_count.json"),
        ),
        (
            "redaction_report",
            include_str!("../../../../app/ui/src/shared/ipc/fixtures/redaction_report.json"),
        ),
        (
            "redaction_context",
            include_str!("../../../../app/ui/src/shared/ipc/fixtures/redaction_context.json"),
        ),
        (
            "raw_page",
            include_str!("../../../../app/ui/src/shared/ipc/fixtures/raw_page.json"),
        ),
        (
            "status_line",
            include_str!("../../../../app/ui/src/shared/ipc/fixtures/status_line.json"),
        ),
    ];

    #[test]
    fn wire_matches_ui_fixtures() {
        let golden = golden::golden().unwrap();
        assert_eq!(golden.len(), FIXTURES.len());
        for ((name, got), (fixture, text)) in golden.iter().zip(FIXTURES) {
            assert_eq!(*name, fixture);
            let want: Value = serde_json::from_str(text).unwrap();
            assert_eq!(got, &want, "{name} differs from its UI fixture");
        }
    }

    #[test]
    fn ui_event_names_and_payloads() {
        let rows = [
            (
                UiEvent::QueueChanged {
                    request_ids: vec!["req_1".into()],
                },
                "queue_changed",
                json!({"request_ids": ["req_1"]}),
            ),
            (
                UiEvent::Attention {
                    kind: AttentionKind::OutcomeUnknown,
                    count: 2,
                },
                "attention",
                json!({"kind": "outcome_unknown", "count": 2}),
            ),
            (
                UiEvent::StatusBanner {
                    line_ids: Vec::new(),
                },
                "status_banner",
                json!({"line_ids": []}),
            ),
            (
                UiEvent::NeedsAttentionChanged { count: 3 },
                "needs_attention_changed",
                json!({"count": 3}),
            ),
            (
                UiEvent::RunningScriptsChanged,
                "running_scripts_changed",
                Value::Null,
            ),
            (
                UiEvent::CredentialContextChanged,
                "credential_context_changed",
                Value::Null,
            ),
        ];
        for (event, name, payload) in rows {
            assert_eq!(ui_event_json(&event), (name, payload));
        }
    }

    #[test]
    fn parse_names_the_refused_field() {
        let id = format!("req_{}", "a".repeat(24));
        assert_eq!(
            parse::<QueueGetArgs>(&json!({"request_id": "req_short"})),
            Err("request_id")
        );
        assert_eq!(
            parse::<QueueGetArgs>(&json!({"request_id": id, "x": 1})),
            Err(FIELD_PAYLOAD)
        );
        assert_eq!(parse::<QueueGetArgs>(&json!([id])), Err(FIELD_PAYLOAD));
        assert!(parse::<QueueGetArgs>(&json!({ "request_id": id })).is_ok());
    }
}
