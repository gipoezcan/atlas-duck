//! Keychain anchor layouts (§8.5, F.6): `0x01 ‖ JCS(object)`. T07 writes both entries once at
//! first run; the anchor thread, batching and barriers come with T08.

use std::fmt;

use atlas_duck_ipc::jcs::to_jcs_vec;
use serde::Deserialize;
use serde_json::json;

use crate::error::AuditError;

/// Leading layout byte of the `head_anchor` and `first_retained_anchor` entries (F.6).
pub const ANCHOR_LAYOUT: u8 = 1;

/// `{chain_id, record_hash, seq}` (F.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadAnchor {
    pub chain_id: String,
    pub seq: u64,
    pub record_hash: [u8; 32],
}

/// `{chain_id, first_retained_prev_hash, first_retained_seq, genesis_hash}` (F.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstRetainedAnchor {
    pub chain_id: String,
    pub genesis_hash: [u8; 32],
    pub first_retained_seq: u64,
    pub first_retained_prev_hash: [u8; 32],
}

/// A stored anchor entry could not be read (§8.13 version gate on the layout byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorEntryError {
    NewerLayout(u8),
    Malformed,
}

impl fmt::Display for AnchorEntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnchorEntryError::NewerLayout(n) => write!(f, "keychain anchor has newer layout {n}"),
            AnchorEntryError::Malformed => f.write_str("keychain anchor is malformed"),
        }
    }
}

impl std::error::Error for AnchorEntryError {}

fn entry(v: &serde_json::Value) -> Result<Vec<u8>, AuditError> {
    // Only a seq above 2^53 − 1 can fail here; never truncate it.
    let body = to_jcs_vec(v).map_err(|_| AuditError::Invalid("anchor is not encodable as JCS"))?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(ANCHOR_LAYOUT);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Layout byte check, then the JSON body (callers also require the exact JCS bytes).
fn body<'de, T: Deserialize<'de>>(b: &'de [u8]) -> Result<T, AnchorEntryError> {
    match b.first() {
        None | Some(0) => Err(AnchorEntryError::Malformed),
        Some(&n) if n > ANCHOR_LAYOUT => Err(AnchorEntryError::NewerLayout(n)),
        Some(_) => serde_json::from_slice(&b[1..]).map_err(|_| AnchorEntryError::Malformed),
    }
}

fn hash32(s: &str) -> Result<[u8; 32], AnchorEntryError> {
    let v = hex::decode(s).map_err(|_| AnchorEntryError::Malformed)?;
    if s.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err(AnchorEntryError::Malformed);
    }
    v.try_into().map_err(|_| AnchorEntryError::Malformed)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadJson {
    chain_id: String,
    record_hash: String,
    seq: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirstRetainedJson {
    chain_id: String,
    first_retained_prev_hash: String,
    first_retained_seq: u64,
    genesis_hash: String,
}

impl HeadAnchor {
    pub fn to_entry(&self) -> Result<Vec<u8>, AuditError> {
        entry(&json!({
            "chain_id": self.chain_id,
            "record_hash": hex::encode(self.record_hash),
            "seq": self.seq,
        }))
    }

    pub fn from_entry(b: &[u8]) -> Result<HeadAnchor, AnchorEntryError> {
        let j: HeadJson = body(b)?;
        let a = HeadAnchor {
            chain_id: j.chain_id,
            seq: j.seq,
            record_hash: hash32(&j.record_hash)?,
        };
        match a.to_entry() {
            Ok(e) if e == b => Ok(a),
            _ => Err(AnchorEntryError::Malformed),
        }
    }
}

impl FirstRetainedAnchor {
    pub fn to_entry(&self) -> Result<Vec<u8>, AuditError> {
        entry(&json!({
            "chain_id": self.chain_id,
            "first_retained_prev_hash": hex::encode(self.first_retained_prev_hash),
            "first_retained_seq": self.first_retained_seq,
            "genesis_hash": hex::encode(self.genesis_hash),
        }))
    }

    pub fn from_entry(b: &[u8]) -> Result<FirstRetainedAnchor, AnchorEntryError> {
        let j: FirstRetainedJson = body(b)?;
        let a = FirstRetainedAnchor {
            chain_id: j.chain_id,
            genesis_hash: hash32(&j.genesis_hash)?,
            first_retained_seq: j.first_retained_seq,
            first_retained_prev_hash: hash32(&j.first_retained_prev_hash)?,
        };
        match a.to_entry() {
            Ok(e) if e == b => Ok(a),
            _ => Err(AnchorEntryError::Malformed),
        }
    }
}
