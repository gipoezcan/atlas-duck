//! The server anchor chain writer and verifier (SM-6.3, PD-217). Task 12 adds the operational
//! append (`LOGIN_FAILED`); the `HEADS` writer, leaves and `verify` are Task 15's.

use atlas_duck_audit::server_anchor::row_hash;
use serde_json::Value;

use crate::clock::rfc3339;
use crate::store::{AnchorRow, ServerStore, StoreError};

/// `LOGIN_FAILED {username, source_ip, reason}` (SM-2.2 operational log).
pub const KIND_LOGIN_FAILED: &str = "LOGIN_FAILED";

/// Appends one operational row whose body is `body` in JCS; no user heads.
pub fn append_operational(
    store: &dyn ServerStore,
    now: i64,
    kind: &str,
    body: &Value,
) -> Result<AnchorRow, StoreError> {
    let body_jcs =
        serde_jcs::to_vec(body).map_err(|_| StoreError::Db("body not serializable".into()))?;
    let ts = rfc3339(now);
    store.anchor_append(kind, &ts, &body_jcs, &[], &|seq, prev| {
        row_hash(seq, &ts, kind, &body_jcs, prev)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::store::memory::MemoryStore;

    #[test]
    fn operational_rows_chain_with_the_v2_hash() {
        let s = MemoryStore::new();
        let body =
            json!({"username": "alice", "source_ip": "192.0.2.1", "reason": "invalid_credentials"});
        let r1 = append_operational(&s, 1_800_000_000, KIND_LOGIN_FAILED, &body).unwrap();
        let r2 = append_operational(&s, 1_800_000_001, KIND_LOGIN_FAILED, &body).unwrap();
        assert_eq!(
            r1.body_jcs,
            br#"{"reason":"invalid_credentials","source_ip":"192.0.2.1","username":"alice"}"#
        );
        assert_eq!(
            r1.hash,
            row_hash(1, &r1.ts_utc, "LOGIN_FAILED", &r1.body_jcs, &[0; 32])
        );
        assert_eq!(r2.prev_hash, r1.hash);
        assert_eq!(
            r2.hash,
            row_hash(2, &r2.ts_utc, "LOGIN_FAILED", &r2.body_jcs, &r1.hash)
        );
    }
}
