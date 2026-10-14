//! App-side wire DTOs (PD-66, §2.4): every command takes its whole invoke body as one typed
//! argument struct (`Args<T>`, `#[serde(deny_unknown_fields)]`), and the bounded newtypes below
//! refuse out-of-bounds values while the body is parsed, so a refused value is answered
//! `{kind: "invalid_argument", field}` before the handler (and any core call) runs. Responses are
//! core types (already `Serialize`) or the app DTOs here.

use std::cell::Cell;

use atlas_duck_core::CandidateRev;
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
}
