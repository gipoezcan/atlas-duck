//! RFC 8785 JSON Canonicalization Scheme, one implementation for the audit payload bytes
//! (§8.4) and `params_sha256` (§4.2, M3).

pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JcsError {
    IntegerOutOfRange,
    Serialize(String),
}

impl std::fmt::Display for JcsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JcsError::IntegerOutOfRange => f.write_str("integer outside the JCS safe range"),
            JcsError::Serialize(m) => write!(f, "JCS serialization failed: {m}"),
        }
    }
}

impl std::error::Error for JcsError {}

/// Canonical bytes of `v`. Integers beyond ±(2^53 − 1) are rejected: RFC 8785 numbers are
/// IEEE-754 doubles, so a larger integer would produce bytes no other implementation reproduces.
pub fn to_jcs_vec(v: &serde_json::Value) -> Result<Vec<u8>, JcsError> {
    check_integers(v)?;
    serde_jcs::to_vec(v).map_err(|e| JcsError::Serialize(e.to_string()))
}

fn check_integers(v: &serde_json::Value) -> Result<(), JcsError> {
    use serde_json::Value::*;
    match v {
        Number(n) => {
            if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > MAX_SAFE_INTEGER as u64 {
                    return Err(JcsError::IntegerOutOfRange);
                }
            } else if n.as_u64().is_some() {
                return Err(JcsError::IntegerOutOfRange); // > i64::MAX
            }
            Ok(())
        }
        Array(a) => a.iter().try_for_each(check_integers),
        Object(o) => o.values().try_for_each(check_integers),
        _ => Ok(()),
    }
}
