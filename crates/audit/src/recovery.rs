//! The recovery blob: a second copy of the KEK wrapped under an Argon2id key derived from the
//! recovery passphrase (§8.6; plan F.5). Stored in `recovery(id = 1, blob, created_at)` and
//! copied verbatim into a backup's `recovery.bin`.
//!
//! ```text
//! 0x01 ‖ salt[16] ‖ u32 BE m_kib ‖ u32 BE t ‖ u32 BE p ‖ nonce[12] ‖ ct[48]      (89 bytes)
//! key = Argon2id v0x13(NFC(passphrase) as UTF-8, salt, m, t, p, 32 bytes)
//! ct  = AES-256-GCM(key, nonce, msg = KEK, aad = "atlas-duck/recovery/v1" ‖ bytes 0..29)
//! ```
//!
//! Layout 1 means exactly m = 65536 KiB, t = 3, p = 4: a blob of layout 1 carrying other
//! parameters is `Malformed` before any derivation, so a crafted `recovery.bin` cannot make
//! the app allocate an arbitrary amount of memory. Changing the parameters is a new layout.

use std::fmt;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretString};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::crypto::{Kek, fill_random};
use crate::error::OpenError;

pub const RECOVERY_LAYOUT: u8 = 1;
/// Minimum length of the recovery passphrase in characters (`char`s of its NFC form, §8.6).
pub const MIN_PASSPHRASE_CHARS: usize = 12;
/// Argon2id parameters of layout 1 (§8.6): m = 64 MiB, t = 3, p = 4.
pub const ARGON2_M_KIB: u32 = 65536;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 4;
pub const RECOVERY_AAD_DOMAIN: &[u8] = b"atlas-duck/recovery/v1";
pub const RECOVERY_BLOB_LEN: usize = 89;

/// layout(1) ‖ salt(16) ‖ params(12): the bytes bound into the AAD.
const HEADER_LEN: usize = 29;
const SALT: std::ops::Range<usize> = 1..17;
const PARAMS: std::ops::Range<usize> = 17..29;
const NONCE: std::ops::Range<usize> = 29..41;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    /// The GCM tag did not verify: a wrong passphrase, or a blob altered after sealing (the
    /// two are indistinguishable by design).
    WrongPassphrase,
    /// Layout byte greater than this version knows (§8.13).
    NewerLayout(u8),
    /// Empty, layout byte `0x00`, wrong length, or parameters other than layout 1's.
    Malformed,
    /// The Argon2id derivation itself failed (in practice: the 64 MiB allocation).
    KdfFailed,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoveryError::WrongPassphrase => f.write_str("wrong recovery passphrase"),
            RecoveryError::NewerLayout(n) => {
                write!(f, "recovery blob has newer layout {n}")
            }
            RecoveryError::Malformed => f.write_str("recovery blob is malformed"),
            RecoveryError::KdfFailed => {
                f.write_str("recovery key derivation failed (out of memory?)")
            }
        }
    }
}

impl std::error::Error for RecoveryError {}

/// The layout byte of a stored blob (T04 version gate), or `None` for an empty blob.
pub fn recovery_layout(blob: &[u8]) -> Option<u8> {
    blob.first().copied()
}

/// NFC of the passphrase in a buffer that is zeroized on drop. The capacity covers NFC's
/// maximum UTF-8 expansion (3×), so the buffer is never reallocated (which would leave an
/// unzeroized copy behind).
fn nfc(pass: &SecretString) -> Zeroizing<String> {
    let src = pass.expose_secret();
    let mut s = Zeroizing::new(String::with_capacity(src.len() * 3 + 4));
    s.extend(src.nfc());
    s
}

fn header(salt: &[u8; 16]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0] = RECOVERY_LAYOUT;
    h[SALT].copy_from_slice(salt);
    h[17..21].copy_from_slice(&ARGON2_M_KIB.to_be_bytes());
    h[21..25].copy_from_slice(&ARGON2_T.to_be_bytes());
    h[25..29].copy_from_slice(&ARGON2_P.to_be_bytes());
    h
}

fn aad(header: &[u8]) -> Vec<u8> {
    let mut a = RECOVERY_AAD_DOMAIN.to_vec();
    a.extend_from_slice(header);
    a
}

/// Argon2id v0x13 with the layout-1 parameters.
fn derive(pass_nfc: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, argon2::Error> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(
        pass_nfc.as_bytes(),
        salt,
        key.as_mut(),
    )?;
    Ok(key)
}

fn os_err(what: &'static str) -> OpenError {
    OpenError::Io(std::io::Error::other(what))
}

/// Seals `kek` under `pass` with a fresh random salt and nonce. Enforces the length rule.
pub fn seal_recovery(pass: &SecretString, kek: &Kek) -> Result<Vec<u8>, OpenError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    fill_random(&mut salt).map_err(|_| os_err("OS random source failed"))?;
    fill_random(&mut nonce).map_err(|_| os_err("OS random source failed"))?;
    seal_recovery_with(pass, kek, &salt, &nonce)
}

/// `seal_recovery` with a given salt and nonce, for the golden vectors.
pub fn seal_recovery_with(
    pass: &SecretString,
    kek: &Kek,
    salt: &[u8; 16],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, OpenError> {
    let p = nfc(pass);
    if p.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(OpenError::PassphraseTooShort);
    }
    let h = header(salt);
    let key = derive(&p, salt).map_err(|_| os_err("recovery key derivation failed"))?;
    let ct = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| os_err("recovery key length"))?
        .encrypt(
            &Nonce::<Aes256Gcm>::from(*nonce),
            Payload {
                msg: kek.as_bytes(),
                aad: &aad(&h),
            },
        )
        .map_err(|_| os_err("recovery encryption failed"))?;
    let mut blob = Vec::with_capacity(RECOVERY_BLOB_LEN);
    blob.extend_from_slice(&h);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Opens a recovery blob. Checks, in order: empty or layout `0x00` → `Malformed`; a newer
/// layout → `NewerLayout` (before any length check); layout 1 with another length or other
/// parameters → `Malformed`; a GCM failure → `WrongPassphrase`.
pub fn open_recovery(pass: &SecretString, blob: &[u8]) -> Result<Kek, RecoveryError> {
    match recovery_layout(blob) {
        None | Some(0) => return Err(RecoveryError::Malformed),
        Some(n) if n > RECOVERY_LAYOUT => return Err(RecoveryError::NewerLayout(n)),
        Some(_) => {}
    }
    if blob.len() != RECOVERY_BLOB_LEN {
        return Err(RecoveryError::Malformed);
    }
    let salt: [u8; 16] = blob[SALT]
        .try_into()
        .map_err(|_| RecoveryError::Malformed)?;
    if blob[PARAMS] != header(&salt)[PARAMS] {
        return Err(RecoveryError::Malformed);
    }
    let nonce: [u8; 12] = blob[NONCE]
        .try_into()
        .map_err(|_| RecoveryError::Malformed)?;

    let key = derive(&nfc(pass), &salt).map_err(|_| RecoveryError::KdfFailed)?;
    let plain = Zeroizing::new(
        Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| RecoveryError::Malformed)?
            .decrypt(
                &Nonce::<Aes256Gcm>::from(nonce),
                Payload {
                    msg: &blob[NONCE.end..],
                    aad: &aad(&blob[..HEADER_LEN]),
                },
            )
            .map_err(|_| RecoveryError::WrongPassphrase)?,
    );
    let mut k = Zeroizing::new([0u8; 32]);
    if plain.len() != 32 {
        return Err(RecoveryError::Malformed);
    }
    k.copy_from_slice(&plain);
    Ok(Kek::from_key(k))
}

/// First run and passphrase change (§8.6): enforce the length rule on the first entry, seal
/// with it, open the blob with the second entry and compare the KEK (constant time) before
/// returning; a mismatch returns no blob.
pub fn new_recovery_blob(
    first: &SecretString,
    second: &SecretString,
    kek: &Kek,
) -> Result<Vec<u8>, OpenError> {
    let blob = seal_recovery(first, kek)?;
    match open_recovery(second, &blob) {
        Ok(k) if k == *kek => Ok(blob),
        Ok(_) | Err(RecoveryError::WrongPassphrase) => Err(OpenError::PassphraseMismatch),
        Err(RecoveryError::KdfFailed) => Err(os_err("recovery key derivation failed")),
        Err(RecoveryError::NewerLayout(_) | RecoveryError::Malformed) => Err(OpenError::Integrity(
            "recovery blob self-check failed".into(),
        )),
    }
}
