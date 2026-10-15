//! App-side wire DTOs (PD-66, §2.4): every command takes its whole invoke body as one typed
//! argument struct (`Args<T>`, `#[serde(deny_unknown_fields)]`), and the bounded newtypes below
//! refuse out-of-bounds values while the body is parsed, so a refused value is answered
//! `{kind: "invalid_argument", field}` before the handler (and any core call) runs. Responses are
//! core types (already `Serialize`) or the app DTOs here.

use std::cell::Cell;

use atlas_duck_core::{
    BatchItem, CandidateRev, DecisionKind, DenyDetails, DropScope, Edits, RedactionOp,
    RedactionPreset, UrlMode,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use tauri::Runtime;
use tauri::ipc::{CommandArg, CommandItem, InvokeBody, InvokeError};

use super::CommandError;

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
pub(crate) fn refuse<E: serde::de::Error>(field: &'static str) -> E {
    REFUSED.with(|r| r.set(Some(field)));
    E::custom(field)
}

/// Parses an invoke body into `T`: a value a bounded newtype refused (out of bounds, wrong type or
/// missing) is `InvalidArgument {field}` with that newtype's field; any other refusal (unknown
/// key, a plain field of the wrong type or missing) is
/// `InvalidArgument {field: "payload"}`, and so is a body that is not a JSON object (serde would
/// take a struct's fields positionally from an array). The serde message is never passed on.
pub fn parse<T: DeserializeOwned>(body: &Value) -> Result<T, CommandError> {
    if !body.is_object() {
        return Err(CommandError::InvalidArgument {
            field: FIELD_PAYLOAD,
        });
    }
    REFUSED.with(|r| r.set(None));
    let parsed = T::deserialize(body);
    let field = REFUSED.with(Cell::take);
    parsed.map_err(|_| CommandError::InvalidArgument {
        field: field.unwrap_or(FIELD_PAYLOAD),
    })
}

/// The whole invoke body of a command as its argument struct. A body the struct refuses never
/// reaches the handler: the webview gets the [`CommandError`] (recorded by the test-build capture
/// like every other response).
pub struct Args<T>(pub T);

impl<'de, R: Runtime, T: DeserializeOwned> CommandArg<'de, R> for Args<T> {
    fn from_command(command: CommandItem<'de, R>) -> Result<Self, InvokeError> {
        let parsed = match command.message.payload() {
            InvokeBody::Json(body) => parse::<T>(body),
            InvokeBody::Raw(_) => Err(CommandError::InvalidArgument {
                field: FIELD_PAYLOAD,
            }),
        };
        parsed.map(Args).map_err(|e| {
            #[cfg(feature = "scripted-approver")]
            super::capture::command(
                tauri::Manager::app_handle(command.message.webview_ref()),
                &e,
            );
            InvokeError(serde_json::to_value(&e).unwrap_or(Value::Null))
        })
    }
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const HASH: &str = "abababababababababababababababababababababababababababababababab";

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Probe {
        #[allow(dead_code)]
        request_id: RequestId,
        #[allow(dead_code)]
        reason: Option<Reason>,
        #[allow(dead_code)]
        candidate_rev: Option<CandidateRevDto>,
    }

    fn field(body: Value) -> Option<&'static str> {
        match parse::<Probe>(&body) {
            Err(CommandError::InvalidArgument { field }) => Some(field),
            _ => None,
        }
    }

    #[test]
    fn request_id_pattern() {
        let min = format!("req_{}", "a".repeat(REQUEST_ID_MIN));
        let max = format!("req_{}", "Z9_-".repeat(REQUEST_ID_MAX / 4));
        assert!(RequestId::is_valid(&min));
        assert!(RequestId::is_valid(&max));
        for bad in [
            format!("req_{}", "a".repeat(REQUEST_ID_MIN - 1)),
            format!("req_{}", "a".repeat(REQUEST_ID_MAX + 1)),
            format!("REQ_{}", "a".repeat(REQUEST_ID_MIN)),
            format!("req_{}.", "a".repeat(REQUEST_ID_MIN)),
            format!("req_{}é", "a".repeat(REQUEST_ID_MIN)),
            String::new(),
        ] {
            assert!(!RequestId::is_valid(&bad), "{bad}");
        }
    }

    #[test]
    fn a_refused_value_names_its_field_and_a_later_parse_starts_clean() {
        let id = format!("req_{}", "a".repeat(24));
        assert_eq!(
            field(json!({"request_id": "req_short"})),
            Some("request_id")
        );
        assert_eq!(field(json!({"request_id": 7})), Some("request_id"));
        let long = "x".repeat(REASON_MAX_CHARS + 1);
        assert_eq!(
            field(json!({"request_id": id, "reason": long})),
            Some("reason")
        );
        // The next refusal is structural: the field of the previous parse must not leak into it.
        assert_eq!(
            field(json!({"request_id": id, "x": 1})),
            Some(FIELD_PAYLOAD)
        );
        // A missing bounded value is refused by its newtype too, so it is named.
        assert_eq!(field(json!({})), Some("request_id"));
        assert_eq!(field(json!([id])), Some(FIELD_PAYLOAD));
        assert!(parse::<Probe>(&json!({"request_id": id})).is_ok());
    }

    #[test]
    fn reason_counts_characters_not_bytes() {
        assert!(Reason::is_valid(&"é".repeat(REASON_MAX_CHARS)));
        assert!(!Reason::is_valid(&"é".repeat(REASON_MAX_CHARS + 1)));
        assert!(!Reason::is_valid("a\0b"));
        assert!(Reason::is_valid(""));
    }

    #[test]
    fn candidate_rev_is_closed_and_lowercase() {
        let id = format!("req_{}", "a".repeat(24));
        let ok = json!({"request_id": id, "candidate_rev": {"counter": 1, "candidate_hash": HASH}});
        assert!(parse::<Probe>(&ok).is_ok());
        for rev in [
            json!({"counter": 1, "candidate_hash": HASH.to_uppercase()}),
            json!({"counter": 1, "candidate_hash": &HASH[2..]}),
            json!({"counter": 1, "candidate_hash": format!("zz{}", &HASH[2..])}),
            json!({"counter": 1, "candidate_hash": HASH, "extra": true}),
            json!({"counter": -1, "candidate_hash": HASH}),
            json!("1"),
        ] {
            let body = json!({"request_id": id, "candidate_rev": rev});
            assert_eq!(field(body), Some("candidate_rev"), "{rev}");
        }
    }

    #[test]
    fn bounded_json_counts_the_serialized_form() {
        let v = json!({"a": "xyz"});
        let len = serde_json::to_vec(&v).map(|b| b.len()).unwrap_or(0);
        assert!(bounded_json(&v, len));
        assert!(!bounded_json(&v, len - 1));
        assert!(bounded_json(&Value::Null, 4));
        assert!(!bounded_json(&Value::Null, 3));
    }

    #[test]
    fn app_status_args_take_nothing() {
        assert_eq!(parse::<AppStatusArgs>(&json!({})), Ok(AppStatusArgs {}));
        assert_eq!(
            parse::<AppStatusArgs>(&json!({"x": 1})),
            Err(CommandError::InvalidArgument {
                field: FIELD_PAYLOAD
            })
        );
        assert!(parse::<AppStatusArgs>(&json!([])).is_err());
    }

    /// M6 T17: a revision's ops go to the UI in the wire form and come back in front of new
    /// ones; what the UI resends unchanged must be the very ops core holds (`decide` compares
    /// them to tell "release this revision" from "make a new one").
    #[test]
    fn redaction_ops_round_trip_through_their_wire_form() {
        let ops = vec![
            RedactionOp::DropItem {
                array_path: "issues[key=A].fields.comment.comments".into(),
                key: "id".into(),
                value: json!("10001"),
            },
            RedactionOp::DropField {
                path: "issues[3].fields.summary".into(),
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
                at: Some("issues[0].fields.summary".into()),
            },
            RedactionOp::UrlField {
                mode: UrlMode::Drop,
            },
            RedactionOp::Preset(RedactionPreset::StatusOnly),
        ];
        let wire: Vec<RedactionOpWire> = ops.iter().map(RedactionOpWire::from).collect();
        let sent = serde_json::to_value(&wire).unwrap();
        assert_eq!(
            sent,
            json!([
                {"drop_item": {"array_loc": "issues[key=A].fields.comment.comments", "key": "id", "value": "10001"}},
                {"drop_field": {"field_loc": "issues[3].fields.summary", "scope": "all_items"}},
                {"mask_text": {"text": "Falcon", "every_occurrence": true, "at": null}},
                {"mask_text": {"text": "Falcon", "every_occurrence": false, "at": "issues[0].fields.summary"}},
                {"url_field": {"mode": "drop"}},
                {"preset": "status_only"}
            ])
        );
        let back: RedactionOpsDto = serde_json::from_value(sent).unwrap();
        assert_eq!(back.0, ops);
        // The wire form's `Debug` redacts like the op's own.
        let debug = format!("{:?}", wire[3]);
        assert!(
            !debug.contains("Falcon") && !debug.contains("summary"),
            "{debug}"
        );
    }
}
