//! The server anchor chain's row hash (M12 PD-217, row format v2 from the start):
//! `SHA-256("atlas-duck/anchor/v2\0" || seq_be || ts_utc || kind || SHA-256(body_jcs) ||
//! prev_hash)`; genesis `prev_hash` is 32 zero bytes. The body is committed by its hash, so an
//! excerpt can carry other rows without their bodies. Leaf hashes and the `HEADS` body are M12
//! Task 15's additions to this module.

use sha2::{Digest, Sha256};

/// Domain separator of the v2 row hash.
pub const ROW_DOMAIN: &[u8] = b"atlas-duck/anchor/v2\0";
/// `prev_hash` of the first row.
pub const GENESIS_PREV: [u8; 32] = [0; 32];

pub fn row_hash(
    seq: u64,
    ts_utc: &str,
    kind: &str,
    body_jcs: &[u8],
    prev_hash: &[u8; 32],
) -> [u8; 32] {
    let body: [u8; 32] = Sha256::digest(body_jcs).into();
    let mut h = Sha256::new();
    h.update(ROW_DOMAIN);
    h.update(seq.to_be_bytes());
    h.update(ts_utc.as_bytes());
    h.update(kind.as_bytes());
    h.update(body);
    h.update(prev_hash);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent recomputation of the formula over its concatenated input.
    #[test]
    fn row_hash_matches_the_formula() {
        let body = br#"{"leaves":[]}"#;
        let prev = [0xab; 32];
        let mut input = ROW_DOMAIN.to_vec();
        input.extend_from_slice(&7u64.to_be_bytes());
        input.extend_from_slice(b"2026-10-26T09:00:00.000Z");
        input.extend_from_slice(b"HEADS");
        input.extend_from_slice(&Sha256::digest(body));
        input.extend_from_slice(&prev);
        let want: [u8; 32] = Sha256::digest(&input).into();
        assert_eq!(
            row_hash(7, "2026-10-26T09:00:00.000Z", "HEADS", body, &prev),
            want
        );
        // Every input moves the hash.
        let base = row_hash(7, "t", "K", b"{}", &GENESIS_PREV);
        assert_ne!(base, row_hash(8, "t", "K", b"{}", &GENESIS_PREV));
        assert_ne!(base, row_hash(7, "u", "K", b"{}", &GENESIS_PREV));
        assert_ne!(base, row_hash(7, "t", "L", b"{}", &GENESIS_PREV));
        assert_ne!(base, row_hash(7, "t", "K", b"[]", &GENESIS_PREV));
        assert_ne!(base, row_hash(7, "t", "K", b"{}", &[1; 32]));
    }
}
