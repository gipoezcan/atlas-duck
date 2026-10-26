//! The master key file and the data-key wrap (ADR 0002, SM-6.2, PD-208), plus the one AES-256-GCM
//! seal/open pair every server-side secret uses (keystore entries, PATs).
//!
//! The master key exists only in memory, loaded from `ATLAS_DUCK_MASTER_KEY_FILE`
//! (`atlas-duck-master-key/v1 <key_id> <base64 of 32 bytes>`). Each user's 32-byte data key is
//! wrapped under it with AAD `"atlas-duck/data-key/v1\0" || user_id`, so a wrapped key moved to
//! another user's row does not open.

use std::fmt;
use std::path::Path;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{ConfigError, MASTER_KEY_FILE};
use crate::store::Sealed;

const PREFIX: &str = "atlas-duck-master-key/v1";
const DATA_KEY_AAD: &[u8] = b"atlas-duck/data-key/v1\0";
/// `WrappedKey.v` of this build.
pub const WRAP_VERSION: u32 = 1;

/// 32 random bytes; zeroed on drop, never printed.
pub struct SecretKey(Zeroizing<[u8; 32]>);

impl SecretKey {
    fn from_slice(b: &[u8]) -> Option<SecretKey> {
        let arr: [u8; 32] = b.try_into().ok()?;
        Some(SecretKey(Zeroizing::new(arr)))
    }

    /// A fresh random key.
    pub fn random() -> Result<SecretKey, KeyError> {
        let mut k = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *k).map_err(|_| KeyError::NoRandomness)?;
        Ok(SecretKey(k))
    }

    fn cipher(&self) -> Aes256Gcm {
        <Aes256Gcm as KeyInit>::new(&aes_gcm::Key::<Aes256Gcm>::from(*self.0))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([redacted])")
    }
}

/// A user's data key (PD-208).
pub type DataKey = SecretKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// Wrapped under another master key (its id differs from the loaded one).
    WrongMasterKey,
    /// The ciphertext, nonce or AAD does not authenticate.
    Corrupt,
    /// A `WrappedKey.v` this build does not know.
    UnknownVersion,
    NoRandomness,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyError::WrongMasterKey => "wrapped under another master key",
            KeyError::Corrupt => "sealed value does not authenticate",
            KeyError::UnknownVersion => "unknown wrap version",
            KeyError::NoRandomness => "no system randomness",
        })
    }
}

impl std::error::Error for KeyError {}

/// AES-256-GCM with a random 96-bit nonce.
pub fn seal(key: &SecretKey, aad: &[u8], msg: &[u8]) -> Result<Sealed, KeyError> {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| KeyError::NoRandomness)?;
    let ct = key
        .cipher()
        .encrypt(&Nonce::<Aes256Gcm>::from(nonce), Payload { msg, aad })
        .map_err(|_| KeyError::Corrupt)?;
    Ok(Sealed {
        nonce: nonce.to_vec(),
        ct,
    })
}

/// Opens a [`seal`]ed value; any mismatch (key, AAD, nonce, ciphertext) is `Corrupt`.
pub fn open(key: &SecretKey, aad: &[u8], sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let nonce: [u8; 12] = sealed
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| KeyError::Corrupt)?;
    key.cipher()
        .decrypt(
            &Nonce::<Aes256Gcm>::from(nonce),
            Payload {
                msg: &sealed.ct,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| KeyError::Corrupt)
}

/// `users.data_key_wrapped` (PD-208), stored as JSON; `nonce`/`ct` base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKey {
    pub v: u32,
    pub master_key_id: String,
    pub nonce: String,
    pub ct: String,
}

impl WrappedKey {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(s: &str) -> Result<WrappedKey, KeyError> {
        serde_json::from_str(s).map_err(|_| KeyError::Corrupt)
    }
}

/// Configuration table: a key file mode looser than 0600/0400 (any group or other bit; Secret
/// mounts are 0440 unless M13's chart sets `defaultMode`) is a warning, never a stop.
#[cfg(unix)]
fn warn_if_loose_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path)
        && meta.permissions().mode() & 0o077 != 0
    {
        tracing::warn!(
            event = "master_key_file_mode",
            mode = format!("{:o}", meta.permissions().mode() & 0o777)
        );
    }
}

#[cfg(not(unix))]
fn warn_if_loose_mode(_path: &Path) {}

pub struct MasterKey {
    id: String,
    key: SecretKey,
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

fn data_key_aad(user_id: &str) -> Vec<u8> {
    let mut aad = DATA_KEY_AAD.to_vec();
    aad.extend_from_slice(user_id.as_bytes());
    aad
}

fn valid_key_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl MasterKey {
    /// Reads the key file: unreadable → `config/master_key_unreadable`, anything but one valid
    /// line (a trailing newline or CRLF allowed) → `config/master_key_invalid`.
    pub fn load(path: &Path) -> Result<MasterKey, ConfigError> {
        warn_if_loose_mode(path);
        let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|_| ConfigError {
            code: "config/master_key_unreadable",
            key: MASTER_KEY_FILE,
        })?);
        Self::parse(&text).ok_or(ConfigError {
            code: "config/master_key_invalid",
            key: MASTER_KEY_FILE,
        })
    }

    fn parse(text: &str) -> Option<MasterKey> {
        let line = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(text);
        if line.contains(['\n', '\r']) {
            return None;
        }
        let mut parts = line.split(' ');
        let (Some(prefix), Some(id), Some(b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        if prefix != PREFIX || !valid_key_id(id) {
            return None;
        }
        let bytes = Zeroizing::new(STANDARD.decode(b64).ok()?);
        Some(MasterKey {
            id: id.to_owned(),
            key: SecretKey::from_slice(&bytes)?,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Wraps `dk` for `user_id` (PD-208).
    pub fn wrap(&self, user_id: &str, dk: &DataKey) -> Result<WrappedKey, KeyError> {
        let s = seal(&self.key, &data_key_aad(user_id), dk.0.as_slice())?;
        Ok(WrappedKey {
            v: WRAP_VERSION,
            master_key_id: self.id.clone(),
            nonce: STANDARD.encode(&s.nonce),
            ct: STANDARD.encode(&s.ct),
        })
    }

    pub fn unwrap(&self, user_id: &str, w: &WrappedKey) -> Result<DataKey, KeyError> {
        if w.v != WRAP_VERSION {
            return Err(KeyError::UnknownVersion);
        }
        if w.master_key_id != self.id {
            return Err(KeyError::WrongMasterKey);
        }
        let sealed = Sealed {
            nonce: STANDARD.decode(&w.nonce).map_err(|_| KeyError::Corrupt)?,
            ct: STANDARD.decode(&w.ct).map_err(|_| KeyError::Corrupt)?,
        };
        let plain = open(&self.key, &data_key_aad(user_id), &sealed)?;
        SecretKey::from_slice(&plain).ok_or(KeyError::Corrupt)
    }

    /// A master key from raw parts (tests of code above this module).
    #[cfg(any(test, feature = "testing"))]
    pub fn for_tests(id: &str, bytes: [u8; 32]) -> MasterKey {
        MasterKey {
            id: id.to_owned(),
            key: SecretKey(Zeroizing::new(bytes)),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const KEY_A: [u8; 32] = [7; 32];

    fn file_text(id: &str, bytes: &[u8]) -> String {
        format!("{PREFIX} {id} {}", STANDARD.encode(bytes))
    }

    fn load_text(text: &str) -> Result<MasterKey, ConfigError> {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("master-key");
        std::fs::write(&p, text).unwrap();
        MasterKey::load(&p)
    }

    #[test]
    fn key_file_variants() {
        let good = file_text("k1", &KEY_A);
        for ok in [good.clone(), format!("{good}\n"), format!("{good}\r\n")] {
            assert_eq!(load_text(&ok).unwrap().id(), "k1", "{ok:?}");
        }
        let invalid = [
            file_text("k1", &[7; 31]),
            file_text("k1", &[7; 33]),
            file_text("K1", &KEY_A),
            file_text(&"a".repeat(33), &KEY_A),
            good.replace("v1", "v2"),
            format!("{good}\n\n"),
            format!("{good} extra"),
            "k1 BwcH".into(),
            good.replace(' ', "  "),
            String::new(),
        ];
        for bad in invalid {
            assert_eq!(
                load_text(&bad).unwrap_err().code,
                "config/master_key_invalid",
                "{bad:?}"
            );
        }
        let missing = MasterKey::load(Path::new("/no/such/master-key-m12"));
        assert_eq!(missing.unwrap_err().code, "config/master_key_unreadable");
    }

    #[test]
    fn debug_never_shows_key_bytes() {
        let mk = MasterKey::for_tests("k1", KEY_A);
        let shown = format!("{mk:?} {:?}", SecretKey::random().unwrap());
        assert!(!shown.contains("7, 7"), "{shown}");
        assert!(shown.contains("k1"));
    }

    #[test]
    fn wrap_round_trip_and_bindings() {
        let mk = MasterKey::for_tests("k1", KEY_A);
        let dk = SecretKey::random().unwrap();
        let w = mk.wrap("user-a", &dk).unwrap();
        let back = WrappedKey::from_json(&w.to_json()).unwrap();
        assert_eq!(*mk.unwrap("user-a", &back).unwrap().0, *dk.0);
        // AAD binds the user.
        assert_eq!(mk.unwrap("user-b", &w).unwrap_err(), KeyError::Corrupt);
        // Another master key (another id) is told apart; same id, other bytes is Corrupt.
        let other = MasterKey::for_tests("k2", [9; 32]);
        assert_eq!(
            other.unwrap("user-a", &w).unwrap_err(),
            KeyError::WrongMasterKey
        );
        let same_id = MasterKey::for_tests("k1", [9; 32]);
        assert_eq!(same_id.unwrap("user-a", &w).unwrap_err(), KeyError::Corrupt);
        // A flipped ciphertext byte.
        let mut ct = STANDARD.decode(&w.ct).unwrap();
        ct[0] ^= 1;
        let flipped = WrappedKey {
            ct: STANDARD.encode(ct),
            ..w.clone()
        };
        assert_eq!(
            mk.unwrap("user-a", &flipped).unwrap_err(),
            KeyError::Corrupt
        );
        let v2 = WrappedKey { v: 2, ..w };
        assert_eq!(
            mk.unwrap("user-a", &v2).unwrap_err(),
            KeyError::UnknownVersion
        );
    }

    #[test]
    fn seal_uses_a_fresh_nonce() {
        let k = SecretKey::random().unwrap();
        let a = seal(&k, b"aad", b"msg").unwrap();
        let b = seal(&k, b"aad", b"msg").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_eq!(open(&k, b"aad", &a).unwrap().as_slice(), b"msg");
        assert_eq!(open(&k, b"other", &a).unwrap_err(), KeyError::Corrupt);
    }
}
