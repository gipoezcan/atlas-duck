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

/// [`row_hash`] from the body's SHA-256 instead of the body (an opaque excerpt line).
pub fn row_hash_from_body_hash(
    seq: u64,
    ts_utc: &str,
    kind: &str,
    body_sha256: &[u8; 32],
    prev_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ROW_DOMAIN);
    h.update(seq.to_be_bytes());
    h.update(ts_utc.as_bytes());
    h.update(kind.as_bytes());
    h.update(body_sha256);
    h.update(prev_hash);
    h.finalize().into()
}

// ---- M14 PD-253: the anchor-chain excerpt ---------------------------------------------------
//
// `anchor-chain.jsonl`: one JCS line per anchor row of a contiguous span. A **full** line carries
// the row's body (as its JCS text) and a `leaf_entry` naming the exported chain's head; an
// **opaque** line carries neither, and its hash still recomputes from `body_sha256`. The excerpt
// reveals other users' leaf hashes and their count only (L248).

/// The excerpt file's name in an export.
pub const EXCERPT_FILE: &str = "anchor-chain.jsonl";
/// The excerpt manifest's name, beside [`EXCERPT_FILE`].
pub const EXCERPT_MANIFEST_FILE: &str = "anchor-chain.manifest.json";
/// `format` of the excerpt manifest.
pub const EXCERPT_FORMAT: &str = "atlas-duck-anchor-excerpt/1";
/// `v` of every excerpt line.
pub const EXCERPT_LINE_VERSION: u64 = 2;

/// Bounds of one excerpt (PD-259).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExcerptLimits {
    /// The largest line in bytes, its newline excluded.
    pub line: usize,
    /// The most leaves in one body.
    pub leaves: usize,
    /// The most lines.
    pub rows: u64,
    /// The largest file in bytes.
    pub file: u64,
}

impl ExcerptLimits {
    /// PD-259, with the line bound raised to fit a full `HEADS` line of `leaves` leaves (each
    /// leaf is 67 bytes of JSON); 64 KiB would cap a `HEADS` row at about 970 users.
    pub const DEFAULT: ExcerptLimits = ExcerptLimits {
        line: 8 * 1024 * 1024,
        leaves: 100_000,
        rows: 100_000,
        file: 256 * 1024 * 1024,
    };
}

/// The exported chain's head as a full line names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafEntry {
    pub user_id: String,
    pub chain_id: String,
    pub head_seq: u64,
    pub record_hash: [u8; 32],
    /// The leaf's position in the body's sorted `leaves` (0 for a `{"leaf"}` body).
    pub leaf_index: u64,
}

/// One parsed excerpt line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcerptRow {
    pub seq: u64,
    pub ts_utc: String,
    pub kind: String,
    pub body_sha256: [u8; 32],
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
    /// The body's JCS bytes (full lines only).
    pub body: Option<Vec<u8>>,
    pub leaf_entry: Option<LeafEntry>,
}

/// A line that cannot be read as an excerpt line (verdict 22 territory).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExcerptError {
    TooLong,
    NotJson,
    /// A field is missing, unknown, or of the wrong shape.
    Shape,
    UnknownVersion,
    TooManyLeaves,
}

/// A line that reads but contradicts itself (verdict 21 territory).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExcerptMismatch {
    /// `hash` is not the row hash of the line's fields.
    RowHash,
    /// The body does not hash to `body_sha256`.
    BodyHash,
    /// The leaf entry's leaf is not at `leaf_index` of the body.
    LeafNotInBody,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLeafEntry {
    user_id: String,
    chain_id: String,
    head_seq: u64,
    record_hash: String,
    leaf_index: u64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLine {
    v: u64,
    seq: u64,
    ts_utc: String,
    kind: String,
    body_sha256: String,
    prev_hash: String,
    hash: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    leaf_entry: Option<RawLeafEntry>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadsBody {
    leaves: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LeafBody {
    leaf: String,
}

/// 64 lowercase hex digits.
fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// The leaves a row body commits to: a `HEADS` body's sorted leaves or a single-leaf body's leaf.
pub fn body_leaves(body: &[u8], limits: &ExcerptLimits) -> Result<Vec<[u8; 32]>, ExcerptError> {
    if let Ok(h) = serde_json::from_slice::<HeadsBody>(body) {
        if h.leaves.len() > limits.leaves {
            return Err(ExcerptError::TooManyLeaves);
        }
        return h
            .leaves
            .iter()
            .map(|l| hex32(l).ok_or(ExcerptError::Shape))
            .collect();
    }
    let l: LeafBody = serde_json::from_slice(body).map_err(|_| ExcerptError::Shape)?;
    Ok(vec![hex32(&l.leaf).ok_or(ExcerptError::Shape)?])
}

/// Parses one line (without its newline). Bounded: a line longer than `limits.line` is refused
/// before it is parsed, and the typed shape admits no nesting beyond the leaf entry.
pub fn parse_excerpt_line(line: &[u8], limits: &ExcerptLimits) -> Result<ExcerptRow, ExcerptError> {
    if line.len() > limits.line {
        return Err(ExcerptError::TooLong);
    }
    let raw: RawLine = serde_json::from_slice(line).map_err(|e| {
        if e.is_data() {
            ExcerptError::Shape
        } else {
            ExcerptError::NotJson
        }
    })?;
    if raw.v != EXCERPT_LINE_VERSION {
        return Err(ExcerptError::UnknownVersion);
    }
    let h = |s: &str| hex32(s).ok_or(ExcerptError::Shape);
    let leaf_entry = match raw.leaf_entry {
        None => None,
        Some(e) => Some(LeafEntry {
            record_hash: h(&e.record_hash)?,
            user_id: e.user_id,
            chain_id: e.chain_id,
            head_seq: e.head_seq,
            leaf_index: e.leaf_index,
        }),
    };
    // A leaf entry is only checkable against a body.
    if leaf_entry.is_some() && raw.body.is_none() {
        return Err(ExcerptError::Shape);
    }
    let body = raw.body.map(String::into_bytes);
    // A full line's body is a leaf body (`HEADS` or single leaf); anything else is not.
    if let Some(b) = &body {
        body_leaves(b, limits)?;
    }
    Ok(ExcerptRow {
        seq: raw.seq,
        body_sha256: h(&raw.body_sha256)?,
        prev_hash: h(&raw.prev_hash)?,
        hash: h(&raw.hash)?,
        ts_utc: raw.ts_utc,
        kind: raw.kind,
        body,
        leaf_entry,
    })
}

impl ExcerptRow {
    /// The line's own consistency: the row hash, the body hash, the leaf in the body.
    pub fn check(&self, limits: &ExcerptLimits) -> Result<(), ExcerptMismatch> {
        let want = row_hash_from_body_hash(
            self.seq,
            &self.ts_utc,
            &self.kind,
            &self.body_sha256,
            &self.prev_hash,
        );
        if want != self.hash {
            return Err(ExcerptMismatch::RowHash);
        }
        let Some(body) = &self.body else {
            return Ok(());
        };
        let got: [u8; 32] = Sha256::digest(body).into();
        if got != self.body_sha256 {
            return Err(ExcerptMismatch::BodyHash);
        }
        if let Some(e) = &self.leaf_entry {
            let leaf = leaf_hash(&e.user_id, &e.chain_id, e.head_seq, &e.record_hash);
            let leaves = body_leaves(body, limits).map_err(|_| ExcerptMismatch::LeafNotInBody)?;
            let at = usize::try_from(e.leaf_index)
                .ok()
                .and_then(|i| leaves.get(i));
            if at != Some(&leaf) {
                return Err(ExcerptMismatch::LeafNotInBody);
            }
        }
        Ok(())
    }
}

/// A JSON string literal (JCS escaping: `"`, `\`, the short escapes, `\u00xx` below 0x20).
fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned())
}

/// The JCS line of an anchor row (no newline). `full` adds the body and, when given, the leaf
/// entry; keys are in JCS (code-point) order.
pub fn excerpt_line_jcs(
    seq: u64,
    ts_utc: &str,
    kind: &str,
    body_jcs: &[u8],
    prev_hash: &[u8; 32],
    hash: &[u8; 32],
    full: Option<Option<&LeafEntry>>,
) -> Vec<u8> {
    let body_sha: [u8; 32] = Sha256::digest(body_jcs).into();
    let mut s = String::from("{");
    if full.is_some() {
        s.push_str("\"body\":");
        s.push_str(&json_str(&String::from_utf8_lossy(body_jcs)));
        s.push(',');
    }
    s.push_str(&format!(
        "\"body_sha256\":\"{}\",\"hash\":\"{}\",\"kind\":{},",
        hex::encode(body_sha),
        hex::encode(hash),
        json_str(kind)
    ));
    if let Some(Some(e)) = full {
        s.push_str(&format!(
            "\"leaf_entry\":{{\"chain_id\":{},\"head_seq\":{},\"leaf_index\":{},\"record_hash\":\"{}\",\"user_id\":{}}},",
            json_str(&e.chain_id),
            e.head_seq,
            e.leaf_index,
            hex::encode(e.record_hash),
            json_str(&e.user_id)
        ));
    }
    s.push_str(&format!(
        "\"prev_hash\":\"{}\",\"seq\":{seq},\"ts_utc\":{},\"v\":{EXCERPT_LINE_VERSION}}}",
        hex::encode(prev_hash),
        json_str(ts_utc)
    ));
    s.into_bytes()
}

/// `anchor-chain.manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcerptManifest {
    pub format: String,
    pub issuer: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub last_hash: String,
    pub chain_id: String,
}

impl ExcerptManifest {
    /// JCS bytes (keys in code-point order).
    pub fn to_jcs(&self) -> Vec<u8> {
        format!(
            "{{\"chain_id\":{},\"first_seq\":{},\"format\":{},\"issuer\":{},\"last_hash\":{},\"last_seq\":{}}}",
            json_str(&self.chain_id),
            self.first_seq,
            json_str(&self.format),
            json_str(&self.issuer),
            json_str(&self.last_hash),
            self.last_seq
        )
        .into_bytes()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn entry(head_seq: u64, leaf_index: u64) -> LeafEntry {
        LeafEntry {
            user_id: "u1".into(),
            chain_id: "c1".into(),
            head_seq,
            record_hash: [0x22; 32],
            leaf_index,
        }
    }

    /// A `HEADS` row naming u1/c1 at seq 9 among two other leaves, as a full and an opaque line.
    fn heads_lines() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let mine = leaf_hash("u1", "c1", 9, &[0x22; 32]);
        let others = [[0x00; 32], [0xff; 32]];
        let body = heads_body_jcs(&[others[0], mine, others[1]]).unwrap();
        let prev = [0x33; 32];
        let hash = row_hash(5, "2026-10-27T10:00:00.000Z", "HEADS", &body, &prev);
        // Sorted: 00.., mine, ff.. (mine starts neither with 00 nor ff with overwhelming odds;
        // the index is computed, not assumed).
        let leaves = body_leaves(&body, &ExcerptLimits::DEFAULT).unwrap();
        let idx = leaves.iter().position(|l| *l == mine).unwrap() as u64;
        let e = entry(9, idx);
        let full = excerpt_line_jcs(
            5,
            "2026-10-27T10:00:00.000Z",
            "HEADS",
            &body,
            &prev,
            &hash,
            Some(Some(&e)),
        );
        let opaque = excerpt_line_jcs(
            5,
            "2026-10-27T10:00:00.000Z",
            "HEADS",
            &body,
            &prev,
            &hash,
            None,
        );
        (full, opaque, hash)
    }

    #[test]
    fn full_and_opaque_lines_parse_and_check() {
        let (full, opaque, hash) = heads_lines();
        let l = ExcerptLimits::DEFAULT;
        let f = parse_excerpt_line(&full, &l).unwrap();
        assert_eq!(f.hash, hash);
        assert!(f.body.is_some() && f.leaf_entry.is_some());
        f.check(&l).unwrap();
        let o = parse_excerpt_line(&opaque, &l).unwrap();
        assert!(o.body.is_none() && o.leaf_entry.is_none());
        // The opaque line's hash recomputes from body_sha256 alone, equal to M12's row_hash.
        o.check(&l).unwrap();
        assert_eq!(
            (o.seq, o.hash, o.body_sha256),
            (f.seq, f.hash, f.body_sha256)
        );
        // Both are JCS: keys sorted, no whitespace.
        let v: serde_json::Value = serde_json::from_slice(&full).unwrap();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        assert!(!full.contains(&b' ') && !full.contains(&b'\n'));
    }

    #[test]
    fn contradictions_are_found() {
        let (full, _, _) = heads_lines();
        let l = ExcerptLimits::DEFAULT;
        let base = parse_excerpt_line(&full, &l).unwrap();
        let mut r = base.clone();
        r.ts_utc.push('x');
        assert_eq!(r.check(&l), Err(ExcerptMismatch::RowHash));
        let mut r = base.clone();
        if let Some(b) = r.body.as_mut() {
            b.pop();
            b.push(b' ');
        }
        assert_eq!(r.check(&l), Err(ExcerptMismatch::BodyHash));
        let mut r = base.clone();
        if let Some(e) = r.leaf_entry.as_mut() {
            e.record_hash[0] ^= 1;
        }
        assert_eq!(r.check(&l), Err(ExcerptMismatch::LeafNotInBody));
        let mut r = base;
        if let Some(e) = r.leaf_entry.as_mut() {
            e.leaf_index += 1;
        }
        assert_eq!(r.check(&l), Err(ExcerptMismatch::LeafNotInBody));
    }

    #[test]
    fn malformed_lines_are_refused() {
        let l = ExcerptLimits::DEFAULT;
        let (full, opaque, _) = heads_lines();
        let text = String::from_utf8(opaque.clone()).unwrap();
        for (bad, want) in [
            (b"not json".to_vec(), ExcerptError::NotJson),
            (
                text.replace("\"v\":2", "\"v\":3").into_bytes(),
                ExcerptError::UnknownVersion,
            ),
            (
                text.replace("}", ",\"extra\":1}").into_bytes(),
                ExcerptError::Shape,
            ),
            (
                text.replace("\"seq\":5,", "").into_bytes(),
                ExcerptError::Shape,
            ),
            (
                text.replacen("\"hash\":\"", "\"hash\":\"A", 1).into_bytes(),
                ExcerptError::Shape,
            ),
        ] {
            assert_eq!(
                parse_excerpt_line(&bad, &l),
                Err(want),
                "{}",
                String::from_utf8_lossy(&bad)
            );
        }
        // A leaf entry without a body is refused.
        let f = String::from_utf8(full).unwrap();
        let start = f.find("\"body\":").unwrap();
        let end = f.find("\"body_sha256\"").unwrap();
        let no_body = format!("{}{}", &f[..start], &f[end..]);
        assert_eq!(
            parse_excerpt_line(no_body.as_bytes(), &l),
            Err(ExcerptError::Shape)
        );
        // Over-long and over-full lines.
        let small = ExcerptLimits {
            line: opaque.len() - 1,
            ..l
        };
        assert_eq!(
            parse_excerpt_line(&opaque, &small),
            Err(ExcerptError::TooLong)
        );
        let (full, _, _) = heads_lines();
        let few = ExcerptLimits { leaves: 2, ..l };
        assert_eq!(
            parse_excerpt_line(&full, &few),
            Err(ExcerptError::TooManyLeaves)
        );
    }

    #[test]
    fn single_leaf_body_and_manifest() {
        let leaf = leaf_hash("u1", "c1", 3, &[0x22; 32]);
        let body = leaf_body_jcs(&leaf);
        let hash = row_hash(2, "t", "RUNTIME_CLOSED", &body, &GENESIS_PREV);
        let e = entry(3, 0);
        let line = excerpt_line_jcs(
            2,
            "t",
            "RUNTIME_CLOSED",
            &body,
            &GENESIS_PREV,
            &hash,
            Some(Some(&e)),
        );
        let l = ExcerptLimits::DEFAULT;
        parse_excerpt_line(&line, &l).unwrap().check(&l).unwrap();
        let m = ExcerptManifest {
            format: EXCERPT_FORMAT.into(),
            issuer: "https://duck.example.test".into(),
            first_seq: 1,
            last_seq: 2,
            last_hash: hex::encode(hash),
            chain_id: "c1".into(),
        };
        let back: ExcerptManifest = serde_json::from_slice(&m.to_jcs()).unwrap();
        assert_eq!(back, m);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]
        #[test]
        fn parse_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            let _ = parse_excerpt_line(&bytes, &ExcerptLimits::DEFAULT);
        }

        #[test]
        fn mutated_lines_never_panic(pos in 0usize..400, b in proptest::prelude::any::<u8>()) {
            let (full, _, _) = heads_lines();
            let mut m = full.clone();
            let i = pos % m.len();
            m[i] = b;
            let l = ExcerptLimits::DEFAULT;
            if let Ok(r) = parse_excerpt_line(&m, &l) {
                let _ = r.check(&l);
            }
        }
    }

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
