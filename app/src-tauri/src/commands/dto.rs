//! App-side wire DTOs (PD-66, §2.4): every command takes its whole invoke body as one typed
//! argument struct (`Args<T>`, `#[serde(deny_unknown_fields)]`), and the bounded newtypes refuse
//! out-of-bounds values while the body is parsed, so a refused value is answered
//! `{kind: "invalid_argument", field}` before the handler (and any core call) runs. Responses are
//! core types (already `Serialize`) or the app DTOs here.
//!
//! The bounded newtypes, the approvals argument structs and their response DTOs live in
//! `atlas_duck_core::decision::wire` (M12 PD-206: the server's `/api/cmd/*` parses the same
//! bodies); they are re-exported here under their old names.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use tauri::Runtime;
use tauri::ipc::{CommandArg, CommandItem, InvokeBody, InvokeError};

use super::CommandError;

/// A serde error for `field`, noted for [`parse`] so the answer can name it (for the bounded
/// newtypes of every command module).
pub(crate) use atlas_duck_core::decision::wire::refuse;
pub use atlas_duck_core::decision::wire::{
    AppStatusArgs, BatchItems, CandidateRevDto, DecisionDto, DenyDetailsDto, EDITS_MAX_BYTES,
    EditsDto, FIELD_PAYLOAD, LIST_MAX, OP_STRING_MAX_BYTES, PreviewOpsDto, REASON_MAX_CHARS,
    REDACTION_OPS_MAX_BYTES, REQUEST_ID_MAX, REQUEST_ID_MIN, Reason, RedactionOpWire,
    RedactionOpsDto, RequestId, RequestIds, SESSION_ID_LEN, SessionId, StatusLevel, StatusLineDto,
    bounded_json,
};

/// Parses an invoke body into `T`: a value a bounded newtype refused (out of bounds, wrong type or
/// missing) is `InvalidArgument {field}` with that newtype's field; any other refusal (unknown
/// key, a plain field of the wrong type or missing) is
/// `InvalidArgument {field: "payload"}`, and so is a body that is not a JSON object (serde would
/// take a struct's fields positionally from an array). The serde message is never passed on.
pub fn parse<T: DeserializeOwned>(body: &Value) -> Result<T, CommandError> {
    atlas_duck_core::decision::wire::parse(body)
        .map_err(|field| CommandError::InvalidArgument { field })
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

/// A wizard step as the page names it (PD-77): one of [`crate::wizard::STEP_NAMES`], so a step
/// of any other text or length is refused with `field: "step"` before the handler runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct StepName(String);

impl StepName {
    pub fn new(s: &str) -> Option<Self> {
        crate::wizard::STEP_NAMES
            .contains(&s)
            .then(|| Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for StepName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d).map_err(|_| refuse::<D::Error>("step"))?;
        StepName::new(&s).ok_or_else(|| refuse("step"))
    }
}

#[cfg(test)]
mod tests {
    use atlas_duck_core::{DropScope, RedactionOp, RedactionPreset, UrlMode};
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

    /// M-15: each op is within 64 KiB, but all ops of one call together are capped.
    #[test]
    fn redaction_ops_are_capped_in_total() {
        let op = |n: usize| json!({"mask_text": {"text": "x".repeat(n), "every_occurrence": true, "at": null}});
        // 20 ops of 60 000 bytes (1.2 MB) pass; 40 (2.4 MB, each op inside its own bound) do not.
        let few: Vec<Value> = (0..20).map(|_| op(60_000)).collect();
        let many: Vec<Value> = (0..40).map(|_| op(60_000)).collect();
        assert!(serde_json::from_value::<RedactionOpsDto>(Value::Array(few.clone())).is_ok());
        assert!(serde_json::from_value::<PreviewOpsDto>(Value::Array(few)).is_ok());
        assert!(serde_json::from_value::<RedactionOpsDto>(Value::Array(many.clone())).is_err());
        assert!(serde_json::from_value::<PreviewOpsDto>(Value::Array(many)).is_err());
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
