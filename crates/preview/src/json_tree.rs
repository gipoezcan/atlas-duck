//! §6.3 Fallback: the JSON tree shown when an op has no dedicated layout.

use serde::Serialize;
use serde_json::Value;

/// Strings longer than this (bytes) are collapsed in the preview; Raw keeps them (§5.1 inv. 4).
pub const JSON_STRING_COLLAPSE_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JsonNode {
    Null,
    Bool {
        value: bool,
    },
    Number {
        text: String,
    },
    String {
        text: String,
    },
    /// A string over [`JSON_STRING_COLLAPSE_BYTES`]; its content is not in the preview.
    Collapsed {
        byte_len: u64,
        hidden_bytes: u64,
    },
    Array {
        /// Serialized (compact JSON) size of the whole array in bytes.
        size: u64,
        items: Vec<JsonNode>,
    },
    Object {
        size: u64,
        entries: Vec<(String, JsonNode)>,
    },
}

impl JsonNode {
    /// Total bytes collapsed anywhere below (and including) this node.
    pub fn hidden_bytes(&self) -> u64 {
        match self {
            JsonNode::Collapsed { hidden_bytes, .. } => *hidden_bytes,
            JsonNode::Array { items, .. } => items.iter().map(JsonNode::hidden_bytes).sum(),
            JsonNode::Object { entries, .. } => entries.iter().map(|(_, n)| n.hidden_bytes()).sum(),
            _ => 0,
        }
    }
}

pub fn json_tree(v: &Value) -> JsonNode {
    build(v).0
}

fn json_len(s: &str) -> u64 {
    // JSON-escaped length including the quotes; serializing a str cannot fail.
    serde_json::to_string(s).map_or(0, |j| j.len() as u64)
}

/// Returns the node and its compact-JSON size in bytes.
fn build(v: &Value) -> (JsonNode, u64) {
    match v {
        Value::Null => (JsonNode::Null, 4),
        Value::Bool(b) => (JsonNode::Bool { value: *b }, if *b { 4 } else { 5 }),
        Value::Number(n) => {
            let text = n.to_string();
            let len = text.len() as u64;
            (JsonNode::Number { text }, len)
        }
        Value::String(s) => {
            let len = json_len(s);
            if s.len() > JSON_STRING_COLLAPSE_BYTES {
                let b = s.len() as u64;
                (
                    JsonNode::Collapsed {
                        byte_len: b,
                        hidden_bytes: b,
                    },
                    len,
                )
            } else {
                (JsonNode::String { text: s.clone() }, len)
            }
        }
        Value::Array(a) => {
            let built: Vec<(JsonNode, u64)> = a.iter().map(build).collect();
            let size = 2
                + built.iter().map(|(_, s)| s).sum::<u64>()
                + built.len().saturating_sub(1) as u64;
            (
                JsonNode::Array {
                    size,
                    items: built.into_iter().map(|(n, _)| n).collect(),
                },
                size,
            )
        }
        Value::Object(o) => {
            let mut size = 2 + o.len().saturating_sub(1) as u64;
            let mut entries = Vec::with_capacity(o.len());
            for (k, val) in o {
                let (n, s) = build(val);
                size += json_len(k) + 1 + s;
                entries.push((k.clone(), n));
            }
            (JsonNode::Object { size, entries }, size)
        }
    }
}
