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

/// Domain separator of a user-head leaf.
pub const LEAF_DOMAIN: &[u8] = b"atlas-duck/anchor-leaf/v1\0";

/// A user store head as anchored: `SHA-256("atlas-duck/anchor-leaf/v1\0" || user_id || "\0" ||
/// chain_id || "\0" || seq_be || record_hash)`. The leaf names no user in clear.
pub fn leaf_hash(user_id: &str, chain_id: &str, seq: u64, record_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEAF_DOMAIN);
    h.update(user_id.as_bytes());
    h.update([0u8]);
    h.update(chain_id.as_bytes());
    h.update([0u8]);
    h.update(seq.to_be_bytes());
    h.update(record_hash);
    h.finalize().into()
}

/// A `HEADS` body with the same leaf twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateLeaf;

/// The `HEADS` body `{"leaves": [hex(leaf)...]}`, leaves sorted, as JCS bytes; a repeated leaf is
/// refused.
pub fn heads_body_jcs(leaves: &[[u8; 32]]) -> Result<Vec<u8>, DuplicateLeaf> {
    let mut hex_leaves: Vec<String> = leaves.iter().map(hex::encode).collect();
    hex_leaves.sort();
    if hex_leaves.windows(2).any(|w| w[0] == w[1]) {
        return Err(DuplicateLeaf);
    }
    // Keys and strings need no escaping; this is the JCS form.
    let items: Vec<String> = hex_leaves.iter().map(|l| format!("\"{l}\"")).collect();
    Ok(format!("{{\"leaves\":[{}]}}", items.join(",")).into_bytes())
}

/// The body of a single-leaf row (`RUNTIME_CLOSED`, M13's `USER_DEACTIVATED`): `{"leaf": hex}`.
pub fn leaf_body_jcs(leaf: &[u8; 32]) -> Vec<u8> {
    format!("{{\"leaf\":\"{}\"}}", hex::encode(leaf)).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_hash_matches_the_formula_and_heads_body_is_sorted_jcs() {
        let rh = [0x11; 32];
        let mut input = LEAF_DOMAIN.to_vec();
        input.extend_from_slice(b"u1\0c1\0");
        input.extend_from_slice(&5u64.to_be_bytes());
        input.extend_from_slice(&rh);
        let want: [u8; 32] = Sha256::digest(&input).into();
        assert_eq!(leaf_hash("u1", "c1", 5, &rh), want);
        assert_ne!(leaf_hash("u1", "c1", 6, &rh), want);
        let (a, b) = ([0xbb; 32], [0xaa; 32]);
        let body = heads_body_jcs(&[a, b]).unwrap();
        assert_eq!(
            String::from_utf8(body).unwrap(),
            format!(
                "{{\"leaves\":[\"{}\",\"{}\"]}}",
                hex::encode(b),
                hex::encode(a)
            )
        );
        assert_eq!(heads_body_jcs(&[a, a]), Err(DuplicateLeaf));
        assert_eq!(heads_body_jcs(&[]).unwrap(), b"{\"leaves\":[]}");
        assert_eq!(
            leaf_body_jcs(&[0; 32]),
            format!("{{\"leaf\":\"{}\"}}", "00".repeat(32)).into_bytes()
        );
    }

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
