//! Payload envelope (zstd level 3 → AES-256-GCM), the KEK and DEK types, DEK wrapping and the
//! keyed query tag (§8.2/L38, §8.4, §8.6, §10.1; plan F.3, F.4, F.6, F.7). Frozen by
//! `tests/vectors/format_v1.json` (`rows`, `dek_wraps`, `query_tags`).
//!
//! Keys live in `Zeroizing<[u8; 32]>`, have no `Serialize` and a redacting `Debug`; no error
//! of this module carries key, plaintext or ciphertext bytes.

use std::fmt;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use zeroize::Zeroizing;

use crate::encoding::{Field, push_frame};
use crate::error::AuditError;
use crate::types::QueryKind;

/// Layout byte of the keychain `kek` entry (F.6).
pub const KEK_ENTRY_LAYOUT: u8 = 1;
/// zstd level of the payload envelope (§8.2).
pub const ZSTD_LEVEL: i32 = 3;
/// Upper bound on a stored `payload_len` that `decompress` accepts. Payloads are bounded
/// upstream far below this (§5.2: 24 MiB frame cap); a larger value is a corrupt or crafted
/// row, rejected before the output buffer is allocated.
pub const MAX_PAYLOAD_LEN: u64 = 64 * 1024 * 1024;
/// AAD domain of a wrapped DEK (F.4).
pub const DEK_WRAP_DOMAIN: &[u8] = b"atlas-duck/dek/v1";
/// HKDF info of the query-tag key (F.7, L38).
pub const QUERY_TAG_INFO: &[u8] = b"atlas-duck/query-tag/v1";
/// `nonce(12) ‖ ct(32) ‖ tag(16)` (F.4).
pub const WRAPPED_DEK_LEN: usize = 60;

/// Fills `buf` from the OS CSPRNG. A failure is an error, never a partially filled buffer
/// (§8.6 "random 96-bit nonces only").
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), AuditError> {
    getrandom::fill(buf).map_err(|_| AuditError::Io("OS random source failed".into()))
}

/// Constant-time equality of two keys or hashes (no early exit on the first differing byte).
pub(crate) fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let diff = a
        .iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// The key-encryption key (§8.6): 32 random bytes in the OS keychain.
#[derive(Clone)]
pub struct Kek(Zeroizing<[u8; 32]>);

/// A data-encryption key (§8.6): one per UTC month of `epoch`, plus the uncorroborated DEK.
#[derive(Clone)]
pub struct Dek(Zeroizing<[u8; 32]>);

/// The keychain `kek` entry could not be read (F.6, §8.13 version gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KekEntryError {
    /// Leading layout byte greater than this version knows: `StoreNewer`.
    NewerLayout(u8),
    /// Empty, layout byte `0x00`, or the wrong length for layout 1: `Locked(keychain_lost)`.
    Malformed,
}

impl fmt::Display for KekEntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KekEntryError::NewerLayout(n) => write!(f, "keychain kek entry has newer layout {n}"),
            KekEntryError::Malformed => f.write_str("keychain kek entry is malformed"),
        }
    }
}

impl std::error::Error for KekEntryError {}

/// A wrapped DEK did not open under this KEK, `key_id` and `month`, or has the wrong length.
/// Deliberately carries nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwrapError;

impl fmt::Display for UnwrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cannot unwrap the data key")
    }
}

impl std::error::Error for UnwrapError {}

impl Kek {
    pub fn generate() -> Result<Kek, AuditError> {
        let mut k = Zeroizing::new([0u8; 32]);
        fill_random(k.as_mut())?;
        Ok(Kek(k))
    }

    /// Parses the keychain entry `0x01 ‖ KEK(32)` (F.6). A newer layout byte is reported
    /// before any length check (a newer layout may have another length).
    pub fn from_entry_bytes(b: &[u8]) -> Result<Kek, KekEntryError> {
        match b.first() {
            None | Some(0) => Err(KekEntryError::Malformed),
            Some(&n) if n > KEK_ENTRY_LAYOUT => Err(KekEntryError::NewerLayout(n)),
            Some(_) => {
                let key: &[u8; 32] = b[1..].try_into().map_err(|_| KekEntryError::Malformed)?;
                Ok(Kek(Zeroizing::new(*key)))
            }
        }
    }

    /// `0x01 ‖ KEK(32)` (F.6), 33 bytes.
    pub fn to_entry_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(33));
        v.push(KEK_ENTRY_LAYOUT);
        v.extend_from_slice(self.0.as_ref());
        v
    }

    pub(crate) fn from_key(key: Zeroizing<[u8; 32]>) -> Kek {
        Kek(key)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Dek {
    pub fn generate() -> Result<Dek, AuditError> {
        let mut k = Zeroizing::new([0u8; 32]);
        fill_random(k.as_mut())?;
        Ok(Dek(k))
    }

    /// For fixed test vectors; the caller owns (and should zeroize) its copy of `bytes`.
    pub fn from_bytes(bytes: &[u8; 32]) -> Dek {
        Dek(Zeroizing::new(*bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for Kek {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl Eq for Kek {}

impl PartialEq for Dek {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl Eq for Dek {}

impl fmt::Debug for Kek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kek([REDACTED])")
    }
}

impl fmt::Debug for Dek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Dek([REDACTED])")
    }
}

/// 12 bytes from the OS CSPRNG (F.3 step 4). Nonces are only ever random (§8.6).
pub fn random_nonce() -> Result<[u8; 12], AuditError> {
    let mut n = [0u8; 12];
    fill_random(&mut n)?;
    Ok(n)
}

/// zstd level 3 (F.3 step 3).
pub fn compress(plain: &[u8]) -> Result<Vec<u8>, AuditError> {
    zstd::bulk::compress(plain, ZSTD_LEVEL)
        .map_err(|_| AuditError::AppendFailed("payload compression failed".into()))
}

/// Inverse of `compress`; the output must be exactly `payload_len` bytes. `payload_len` above
/// `MAX_PAYLOAD_LEN` is rejected before allocating. The caller then checks
/// `SHA-256(plain) == payload_sha256` (F.3).
pub fn decompress(compressed: &[u8], payload_len: u64) -> Result<Vec<u8>, AuditError> {
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(AuditError::Invalid("payload_len above 64 MiB"));
    }
    // Lossless: bounded by MAX_PAYLOAD_LEN above.
    let len = payload_len as usize;
    let out = zstd::bulk::decompress(compressed, len)
        .map_err(|_| AuditError::Invalid("payload does not decompress"))?;
    if out.len() != len {
        return Err(AuditError::Invalid(
            "payload length differs from payload_len",
        ));
    }
    Ok(out)
}

fn cipher(key: &[u8; 32]) -> Result<Aes256Gcm, AuditError> {
    Aes256Gcm::new_from_slice(key).map_err(|_| AuditError::Invalid("key length"))
}

/// AES-256-GCM of the zstd frame under the row's DEK, nonce and AAD (F.3 step 5). Returns
/// `ct ‖ tag`.
pub fn seal(dek: &Dek, nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, AuditError> {
    cipher(dek.as_bytes())?
        .encrypt(&Nonce::<Aes256Gcm>::from(*nonce), Payload { msg, aad })
        .map_err(|_| AuditError::AppendFailed("payload encryption failed".into()))
}

/// Inverse of `seal`. Any failure (wrong key, nonce, AAD, tampered or truncated ciphertext)
/// is `Decrypt { seq }`; `seq` is the row being read and only labels the error.
pub fn open(
    dek: &Dek,
    nonce: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
    seq: u64,
) -> Result<Vec<u8>, AuditError> {
    cipher(dek.as_bytes())?
        .decrypt(&Nonce::<Aes256Gcm>::from(*nonce), Payload { msg: ct, aad })
        .map_err(|_| AuditError::Decrypt { seq })
}

/// `b"atlas-duck/dek/v1" ‖ frame(Int key_id) ‖ frame(month or Null)` (F.4).
fn dek_wrap_aad(key_id: u64, month: Option<&str>) -> Result<Vec<u8>, AuditError> {
    let mut a = DEK_WRAP_DOMAIN.to_vec();
    push_frame(&mut a, &Field::Int(key_id))?;
    push_frame(
        &mut a,
        &month.map_or(Field::Null, |m| Field::Bytes(m.as_bytes())),
    )?;
    Ok(a)
}

/// `keys.wrapped_dek` = `nonce(12) ‖ AES-256-GCM(KEK).encrypt(nonce, dek, aad)` (F.4), 60 bytes,
/// with a fresh random nonce.
pub fn wrap_dek(
    kek: &Kek,
    key_id: u64,
    month: Option<&str>,
    dek: &Dek,
) -> Result<Vec<u8>, AuditError> {
    wrap_with(kek, key_id, month, dek, &random_nonce()?)
}

/// `wrap_dek` with a given nonce, for the golden vectors (test builds only). The store always
/// calls `wrap_dek`.
#[cfg(any(test, feature = "testing"))]
pub fn wrap_dek_with_nonce(
    kek: &Kek,
    key_id: u64,
    month: Option<&str>,
    dek: &Dek,
    nonce: &[u8; 12],
) -> Result<Vec<u8>, AuditError> {
    wrap_with(kek, key_id, month, dek, nonce)
}

fn wrap_with(
    kek: &Kek,
    key_id: u64,
    month: Option<&str>,
    dek: &Dek,
    nonce: &[u8; 12],
) -> Result<Vec<u8>, AuditError> {
    let aad = dek_wrap_aad(key_id, month)?;
    let ct = cipher(kek.as_bytes())?
        .encrypt(
            &Nonce::<Aes256Gcm>::from(*nonce),
            Payload {
                msg: dek.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| AuditError::AppendFailed("data key wrapping failed".into()))?;
    let mut out = Vec::with_capacity(WRAPPED_DEK_LEN);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens a `keys.wrapped_dek` for exactly this `key_id` and `month` (F.4).
pub fn unwrap_dek(
    kek: &Kek,
    key_id: u64,
    month: Option<&str>,
    wrapped: &[u8],
) -> Result<Dek, UnwrapError> {
    if wrapped.len() != WRAPPED_DEK_LEN {
        return Err(UnwrapError);
    }
    let (nonce, ct) = wrapped.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| UnwrapError)?;
    let aad = dek_wrap_aad(key_id, month).map_err(|_| UnwrapError)?;
    let plain = Zeroizing::new(
        cipher(kek.as_bytes())
            .map_err(|_| UnwrapError)?
            .decrypt(
                &Nonce::<Aes256Gcm>::from(nonce),
                Payload { msg: ct, aad: &aad },
            )
            .map_err(|_| UnwrapError)?,
    );
    let key: &[u8; 32] = plain.as_slice().try_into().map_err(|_| UnwrapError)?;
    Ok(Dek::from_bytes(key))
}

/// `K_q = HKDF-SHA256(salt = none, ikm = KEK, info = "atlas-duck/query-tag/v1", L = 32)` (F.7).
pub fn query_key(kek: &Kek) -> Zeroizing<[u8; 32]> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, kek.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    // 32 bytes is always a valid HKDF-SHA256 output length (at most 255 · 32).
    let _ = hk.expand(QUERY_TAG_INFO, okm.as_mut());
    okm
}

/// `"jql:"`/`"cql:"` + lowercase hex of `HMAC-SHA256(K_q, NFC(query).trim())` (F.7, L38).
///
/// `trim` is Rust's `str::trim` (Unicode `White_Space`), applied after NFC. JavaScript's
/// `trim()` also strips U+FEFF, which Rust does not, and Rust strips U+0085 (NEL), which
/// JavaScript does not; the golden vectors therefore surround queries only with ASCII spaces,
/// tabs and newlines (the Node checker relies on that).
pub fn query_tag(k_q: &[u8; 32], kind: QueryKind, query: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use unicode_normalization::UnicodeNormalization;

    let normalized: String = query.nfc().collect();
    // HMAC pads a key shorter than its block with zeros (RFC 2104), so the zero-padded key
    // gives the same MAC through the infallible block-size constructor (no error arm).
    let mut key = hmac::digest::Key::<Hmac<sha2::Sha256>>::default();
    key[..k_q.len()].copy_from_slice(k_q);
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new(&key);
    zeroize::Zeroize::zeroize(&mut key[..]);
    mac.update(normalized.trim().as_bytes());
    let tag = hex::encode(mac.finalize().into_bytes());
    match kind {
        QueryKind::Jql => format!("jql:{tag}"),
        QueryKind::Cql => format!("cql:{tag}"),
    }
}
