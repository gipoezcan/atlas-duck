//! Canonical encoding `FIELD_LIST[1]`, `record_hash`, the AES-GCM AAD and the prune-log row
//! hash (§8.4, §8.5; plan F.2, F.9). Frozen by `tests/vectors/format_v1.json`: changing any
//! byte produced here is a `format_version` bump.

use sha2::{Digest, Sha256};

use crate::error::AuditError;

pub const FORMAT_VERSION: u64 = 1;
pub const NULL_FRAME: [u8; 5] = [0, 0, 0, 0, 0];
/// `prev_hash` of `GENESIS` and `prev_row_hash` of the first `prune_log` row.
pub const ZERO_HASH: [u8; 32] = [0; 32];

pub const RECORD_DOMAIN_PREFIX: &str = "atlas-duck/audit/v";
pub const AAD_DOMAIN: &[u8] = b"atlas-duck/aad/v1";
pub const PRUNE_LOG_DOMAIN: &[u8] = b"atlas-duck/prune-log/v1";

/// `FIELD_LIST[1]`: every `events` column except `record_hash`, in hashing order, which is
/// also the F.10 column order. `RowFields::from_row` reads a row selected with exactly this
/// list (`SELECT seq, format_version, …, prev_hash`).
pub const FIELD_LIST: [&str; 29] = [
    "seq",
    "format_version",
    "chain_id",
    "ts_utc",
    "epoch",
    "request_id",
    "event_type",
    "op_id",
    "op_class",
    "instance_id",
    "target",
    "agent_name",
    "agent_name_source",
    "client_kind",
    "connection_id",
    "peer_pid",
    "peer_exe",
    "peer_origin_exe",
    "os_user",
    "atlassian_user",
    "atlassian_user_key",
    "decision",
    "flags",
    "payload_len",
    "payload_sha256",
    "key_id",
    "nonce",
    "payload_ct",
    "prev_hash",
];

/// One field of a frame sequence: NULL, an integer (u64 BE) or bytes (UTF-8 text or a BLOB).
#[derive(Clone, Copy)]
pub enum Field<'a> {
    Null,
    Int(u64),
    Bytes(&'a [u8]),
}

impl<'a> Field<'a> {
    fn text(s: Option<&'a str>) -> Field<'a> {
        s.map_or(Field::Null, |s| Field::Bytes(s.as_bytes()))
    }

    fn blob(b: Option<&'a [u8]>) -> Field<'a> {
        b.map_or(Field::Null, Field::Bytes)
    }
}

/// present → `0x01 ‖ u32 BE length ‖ bytes`; NULL → `0x00 ‖ 0x00000000`; integers are 8 bytes.
pub fn push_frame(out: &mut Vec<u8>, f: &Field<'_>) -> Result<(), AuditError> {
    match f {
        Field::Null => out.extend_from_slice(&NULL_FRAME),
        Field::Int(v) => {
            out.push(1);
            out.extend_from_slice(&8u32.to_be_bytes());
            out.extend_from_slice(&v.to_be_bytes());
        }
        Field::Bytes(b) => {
            // > 4 GiB cannot occur (payloads are bounded upstream, §5.2), but never truncate silently.
            let len = u32::try_from(b.len())
                .map_err(|_| AuditError::Invalid("field longer than u32::MAX"))?;
            out.push(1);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(b);
        }
    }
    Ok(())
}

/// Frames `f` straight into a hasher, for the hashes whose signatures are infallible
/// (`request_set_hash` is fixed by C.3). A field longer than `u32::MAX` bytes cannot occur
/// (request bodies are bounded upstream, §5.2/§7.2; prune-row fields are tiny); should one
/// appear it is framed as `0x02 ‖ u64 BE length ‖ bytes`, which no regular frame starts
/// with, so the encoding stays injective instead of truncating the length.
pub(crate) fn hash_frame(h: &mut Sha256, f: &Field<'_>) {
    match f {
        Field::Null => h.update(NULL_FRAME),
        Field::Int(v) => {
            h.update([1u8]);
            h.update(8u32.to_be_bytes());
            h.update(v.to_be_bytes());
        }
        Field::Bytes(b) => match u32::try_from(b.len()) {
            Ok(len) => {
                h.update([1u8]);
                h.update(len.to_be_bytes());
                h.update(b);
            }
            Err(_) => {
                h.update([2u8]);
                h.update((b.len() as u64).to_be_bytes());
                h.update(b);
            }
        },
    }
}

pub fn record_domain(format_version: u64) -> Vec<u8> {
    format!("{RECORD_DOMAIN_PREFIX}{format_version}").into_bytes()
}

/// record_hash = SHA-256(domain ‖ prev_hash ‖ canonical_bytes)  (§8.4)
pub fn record_hash(format_version: u64, prev_hash: &[u8; 32], canonical: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(record_domain(format_version));
    h.update(prev_hash);
    h.update(canonical);
    h.finalize().into()
}

/// The 29 column values of one `events` row, borrowed. Built by the writer before insert and
/// by the verifier from a stored row (`from_row`). No `Debug`: it holds ciphertext.
#[derive(Clone, Copy)]
pub struct RowFields<'a> {
    pub seq: u64,
    pub format_version: u64,
    pub chain_id: &'a str,
    pub ts_utc: &'a str,
    pub epoch: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub event_type: &'a str,
    pub op_id: Option<&'a str>,
    pub op_class: Option<&'a str>,
    pub instance_id: Option<&'a str>,
    pub target: Option<&'a str>,
    pub agent_name: Option<&'a str>,
    pub agent_name_source: Option<&'a str>,
    pub client_kind: Option<&'a str>,
    pub connection_id: Option<&'a str>,
    pub peer_pid: Option<u64>,
    pub peer_exe: Option<&'a [u8]>,
    pub peer_origin_exe: Option<&'a [u8]>,
    pub os_user: Option<&'a str>,
    pub atlassian_user: Option<&'a str>,
    pub atlassian_user_key: Option<&'a str>,
    pub decision: Option<&'a str>,
    pub flags: u64,
    pub payload_len: u64,
    pub payload_sha256: &'a [u8; 32],
    pub key_id: u64,
    pub nonce: &'a [u8; 12],
    pub payload_ct: &'a [u8],
    pub prev_hash: &'a [u8; 32],
}

impl<'a> RowFields<'a> {
    /// The 29 fields in `FIELD_LIST` order.
    pub fn frames(&self) -> [Field<'a>; 29] {
        [
            Field::Int(self.seq),
            Field::Int(self.format_version),
            Field::Bytes(self.chain_id.as_bytes()),
            Field::Bytes(self.ts_utc.as_bytes()),
            Field::text(self.epoch),
            Field::text(self.request_id),
            Field::Bytes(self.event_type.as_bytes()),
            Field::text(self.op_id),
            Field::text(self.op_class),
            Field::text(self.instance_id),
            Field::text(self.target),
            Field::text(self.agent_name),
            Field::text(self.agent_name_source),
            Field::text(self.client_kind),
            Field::text(self.connection_id),
            self.peer_pid.map_or(Field::Null, Field::Int),
            Field::blob(self.peer_exe),
            Field::blob(self.peer_origin_exe),
            Field::text(self.os_user),
            Field::text(self.atlassian_user),
            Field::text(self.atlassian_user_key),
            Field::text(self.decision),
            Field::Int(self.flags),
            Field::Int(self.payload_len),
            Field::Bytes(self.payload_sha256),
            Field::Int(self.key_id),
            Field::Bytes(self.nonce),
            Field::Bytes(self.payload_ct),
            Field::Bytes(self.prev_hash),
        ]
    }

    /// Reads a row selected with the columns of `FIELD_LIST` in that order (indices 0..=28;
    /// anything after them, e.g. `record_hash`, is the caller's). A value of the wrong SQLite
    /// type, a negative integer, non-UTF-8 text or a hash/nonce of the wrong length is
    /// `Invalid` (a verification finding, never a panic).
    pub fn from_row(row: &'a rusqlite::Row<'_>) -> Result<RowFields<'a>, AuditError> {
        use rusqlite::types::ValueRef;

        let get = |i: usize| {
            row.get_ref(i)
                .map_err(|_| AuditError::Invalid("events row is missing a column"))
        };
        let int = |i: usize| -> Result<Option<u64>, AuditError> {
            match get(i)? {
                ValueRef::Null => Ok(None),
                ValueRef::Integer(v) => u64::try_from(v)
                    .map(Some)
                    .map_err(|_| AuditError::Invalid("events integer column is negative")),
                _ => Err(AuditError::Invalid(
                    "events integer column has another type",
                )),
            }
        };
        let text = |i: usize| -> Result<Option<&'a str>, AuditError> {
            match get(i)? {
                ValueRef::Null => Ok(None),
                ValueRef::Text(t) => std::str::from_utf8(t)
                    .map(Some)
                    .map_err(|_| AuditError::Invalid("events text column is not UTF-8")),
                _ => Err(AuditError::Invalid("events text column has another type")),
            }
        };
        let blob = |i: usize| -> Result<Option<&'a [u8]>, AuditError> {
            match get(i)? {
                ValueRef::Null => Ok(None),
                ValueRef::Blob(b) => Ok(Some(b)),
                _ => Err(AuditError::Invalid("events blob column has another type")),
            }
        };
        fn req<T>(v: Option<T>) -> Result<T, AuditError> {
            v.ok_or(AuditError::Invalid("events NOT NULL column is NULL"))
        }
        let hash32 = |v: &'a [u8]| {
            <&[u8; 32]>::try_from(v)
                .map_err(|_| AuditError::Invalid("events hash column is not 32 bytes"))
        };

        Ok(RowFields {
            seq: req(int(0)?)?,
            format_version: req(int(1)?)?,
            chain_id: req(text(2)?)?,
            ts_utc: req(text(3)?)?,
            epoch: text(4)?,
            request_id: text(5)?,
            event_type: req(text(6)?)?,
            op_id: text(7)?,
            op_class: text(8)?,
            instance_id: text(9)?,
            target: text(10)?,
            agent_name: text(11)?,
            agent_name_source: text(12)?,
            client_kind: text(13)?,
            connection_id: text(14)?,
            peer_pid: int(15)?,
            peer_exe: blob(16)?,
            peer_origin_exe: blob(17)?,
            os_user: text(18)?,
            atlassian_user: text(19)?,
            atlassian_user_key: text(20)?,
            decision: text(21)?,
            flags: req(int(22)?)?,
            payload_len: req(int(23)?)?,
            payload_sha256: hash32(req(blob(24)?)?)?,
            key_id: req(int(25)?)?,
            nonce: <&[u8; 12]>::try_from(req(blob(26)?)?)
                .map_err(|_| AuditError::Invalid("events nonce is not 12 bytes"))?,
            payload_ct: req(blob(27)?)?,
            prev_hash: hash32(req(blob(28)?)?)?,
        })
    }
}

/// `canonical_bytes` = the 29 frames of `FIELD_LIST[1]`, concatenated, no count prefix (§8.4).
pub fn canonical_bytes(r: &RowFields<'_>) -> Result<Vec<u8>, AuditError> {
    let mut out = Vec::with_capacity(512 + r.payload_ct.len());
    for f in &r.frames() {
        push_frame(&mut out, f)?;
    }
    Ok(out)
}

/// AAD = "atlas-duck/aad/v1" ‖ frames of [format_version, chain_id, seq, ts_utc, epoch,
/// event_type, request_id, op_id, target, key_id, payload_sha256] in exactly this order (§8.4).
pub fn aad(r: &RowFields<'_>) -> Result<Vec<u8>, AuditError> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(AAD_DOMAIN);
    for f in [
        Field::Int(r.format_version),
        Field::Bytes(r.chain_id.as_bytes()),
        Field::Int(r.seq),
        Field::Bytes(r.ts_utc.as_bytes()),
        Field::text(r.epoch),
        Field::Bytes(r.event_type.as_bytes()),
        Field::text(r.request_id),
        Field::text(r.op_id),
        Field::text(r.target),
        Field::Int(r.key_id),
        Field::Bytes(r.payload_sha256),
    ] {
        push_frame(&mut out, &f)?;
    }
    Ok(out)
}

/// `row_hash = SHA-256("atlas-duck/prune-log/v1" ‖ prev_row_hash ‖ frame(Int prune_seq) ‖
/// frame(Int range_start) ‖ frame(cutoff_epoch) ‖ frame(last_pruned_record_hash) ‖
/// frame(Int first_retained_seq))` (F.9, L51). The first row's `prev_row_hash` is `ZERO_HASH`.
pub fn prune_row_hash(
    prev_row_hash: &[u8; 32],
    prune_seq: u64,
    range_start: u64,
    cutoff_epoch: &str,
    last_pruned_record_hash: &[u8; 32],
    first_retained_seq: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PRUNE_LOG_DOMAIN);
    h.update(prev_row_hash);
    for f in [
        Field::Int(prune_seq),
        Field::Int(range_start),
        Field::Bytes(cutoff_epoch.as_bytes()),
        Field::Bytes(last_pruned_record_hash),
        Field::Int(first_retained_seq),
    ] {
        hash_frame(&mut h, &f);
    }
    h.finalize().into()
}

/// Bytes of an OS path for `peer_exe`/`peer_origin_exe` (§8.4 "lossless WTF-8 for OS paths"):
/// Windows: WTF-8 of the UTF-16 units (a lone surrogate is encoded as its own code point).
#[cfg(windows)]
pub fn os_path_bytes(p: &std::path::Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    let units: Vec<u16> = p.as_os_str().encode_wide().collect();
    let mut out = Vec::with_capacity(units.len() * 3);
    let mut i = 0;
    while i < units.len() {
        let u = units[i] as u32;
        let cp = if (0xD800..0xDC00).contains(&u)
            && i + 1 < units.len()
            && (0xDC00..0xE000).contains(&(units[i + 1] as u32))
        {
            i += 1;
            0x10000 + ((u - 0xD800) << 10) + (units[i] as u32 - 0xDC00)
        } else {
            u // a lone surrogate stays as its own code point (WTF-8)
        };
        // generalized UTF-8 encoding of cp (1–4 bytes), surrogates included
        if cp < 0x80 {
            out.push(cp as u8)
        } else if cp < 0x800 {
            out.push(0xC0 | (cp >> 6) as u8);
            out.push(0x80 | (cp & 0x3F) as u8)
        } else if cp < 0x10000 {
            out.push(0xE0 | (cp >> 12) as u8);
            out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            out.push(0x80 | (cp & 0x3F) as u8)
        } else {
            out.push(0xF0 | (cp >> 18) as u8);
            out.push(0x80 | ((cp >> 12) & 0x3F) as u8);
            out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            out.push(0x80 | (cp & 0x3F) as u8)
        }
        i += 1;
    }
    out
}

/// Unix: the raw path bytes (`OsStrExt::as_bytes`).
#[cfg(unix)]
pub fn os_path_bytes(p: &std::path::Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    p.as_os_str().as_bytes().to_vec()
}
