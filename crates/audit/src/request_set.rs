//! `request_set_hash` and the `requests` JSON of `WRITE_APPROVED` (§5.1 inv. 3, plan F.8).

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::encoding::{Field, hash_frame};
use crate::error::AuditError;

pub const REQUEST_SET_DOMAIN: &[u8] = b"atlas-duck/request-set/v1";

/// One HTTP request of an approved set: the same five fields as `atlassian::HttpRequestSpec`
/// (C.3). `Debug` never prints the URL or the body (both are payload plaintext).
#[derive(Clone, PartialEq, Eq)]
pub struct RequestRecord {
    pub index: u32,
    pub method: String,
    pub resolved_url: String,
    pub content_type: Option<String>,
    pub body_bytes: Vec<u8>,
}

impl fmt::Debug for RequestRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestRecord")
            .field("index", &self.index)
            .field("method", &self.method)
            .field("content_type", &self.content_type)
            .field("body_len", &self.body_bytes.len())
            .finish_non_exhaustive()
    }
}

/// `SHA-256("atlas-duck/request-set/v1" ‖ u32 BE count ‖ for each record in slice order:
/// frame(Int index) ‖ frame(method) ‖ frame(resolved_url) ‖ frame(content_type or Null) ‖
/// frame(body_bytes))` (F.8).
pub fn request_set_hash(requests: &[RequestRecord]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(REQUEST_SET_DOMAIN);
    // More than u32::MAX records cannot exist in memory; the records are self-delimiting
    // frames, so saturating the (then redundant) count keeps the encoding injective.
    h.update(
        u32::try_from(requests.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for r in requests {
        for f in [
            Field::Int(u64::from(r.index)),
            Field::Bytes(r.method.as_bytes()),
            Field::Bytes(r.resolved_url.as_bytes()),
            r.content_type
                .as_deref()
                .map_or(Field::Null, |c| Field::Bytes(c.as_bytes())),
            Field::Bytes(&r.body_bytes),
        ] {
            hash_frame(&mut h, &f);
        }
    }
    h.finalize().into()
}

/// `[{"index":0,"method":"POST","url":"https://…","content_type":"…"|null,"body_b64":"…"}]`
/// with padded RFC 4648 base64 (F.8).
pub fn requests_to_json(requests: &[RequestRecord]) -> Value {
    Value::Array(
        requests
            .iter()
            .map(|r| {
                json!({
                    "index": r.index,
                    "method": r.method,
                    "url": r.resolved_url,
                    "content_type": r.content_type,
                    "body_b64": STANDARD.encode(&r.body_bytes),
                })
            })
            .collect(),
    )
}

/// Parses exactly the shape `requests_to_json` writes: an array of objects with the five
/// keys and no others, `content_type` explicit (string or null), `index` within u32, and
/// canonical padded base64. Anything else is `Invalid`.
pub fn requests_from_json(v: &Value) -> Result<Vec<RequestRecord>, AuditError> {
    let items = v
        .as_array()
        .ok_or(AuditError::Invalid("requests is not an array"))?;
    items.iter().map(record_from_json).collect()
}

const KEYS: [&str; 5] = ["index", "method", "url", "content_type", "body_b64"];

fn record_from_json(v: &Value) -> Result<RequestRecord, AuditError> {
    let o: &Map<String, Value> = v
        .as_object()
        .ok_or(AuditError::Invalid("request is not an object"))?;
    if o.len() != KEYS.len() || !KEYS.iter().all(|k| o.contains_key(*k)) {
        return Err(AuditError::Invalid(
            "request must have exactly index, method, url, content_type, body_b64",
        ));
    }
    let field = |k: &str| {
        o.get(k).ok_or(AuditError::Invalid(
            "request must have exactly index, method, url, content_type, body_b64",
        ))
    };
    let string = |k: &str| {
        field(k)?
            .as_str()
            .map(str::to_owned)
            .ok_or(AuditError::Invalid("request field is not a string"))
    };
    let index = field("index")?
        .as_u64()
        .and_then(|i| u32::try_from(i).ok())
        .ok_or(AuditError::Invalid("request index is not a u32"))?;
    let content_type = match field("content_type")? {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        _ => {
            return Err(AuditError::Invalid(
                "request content_type is not a string or null",
            ));
        }
    };
    let body_bytes = STANDARD
        .decode(string("body_b64")?)
        .map_err(|_| AuditError::Invalid("request body_b64 is not padded base64"))?;
    Ok(RequestRecord {
        index,
        method: string("method")?,
        resolved_url: string("url")?,
        content_type,
        body_bytes,
    })
}
