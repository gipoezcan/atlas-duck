//! `KeychainCredentials`: the PAT of an instance in the OS keychain (PD-05, §7.1, §8.6).
//!
//! One entry per instance (`EntryName::Pat(instance_id)`, install-scoped by the `KeyStore`), the
//! value a UTF-8 JSON blob `{"v":1,"pat":"…","url_hash":"<64 hex>","user":"…","user_key":"…",
//! "expires_at":"YYYY-MM-DD"|null}` that lives only in `Zeroizing` buffers: it is written with
//! `serde_json::to_writer` straight into a `Zeroizing<Vec<u8>>` (the PAT is borrowed, never
//! copied into a `Value`) and read back through a visitor that copies the PAT into a
//! `Zeroizing<String>`. A PAT that contains a JSON escape sequence is unescaped by `serde_json`
//! through a scratch buffer that is not zeroized (real PATs never contain one).

use std::fmt;
use std::sync::Arc;

use atlas_duck_atlassian::{
    CredentialError, CredentialProvider, PatSecret, StoredCredential, StoredIdentity, UrlHash,
};
use atlas_duck_audit::{EntryName, KeyStore, KeyStoreError};
use chrono::NaiveDate;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The blob version this build writes and reads; another `v` is `CredentialError::Corrupt`.
const BLOB_VERSION: u32 = 1;

fn credential_error(e: KeyStoreError) -> CredentialError {
    match e {
        KeyStoreError::Unavailable => CredentialError::Unavailable,
        KeyStoreError::Locked => CredentialError::Locked,
        KeyStoreError::NotLocal => CredentialError::NotLocal,
        KeyStoreError::Corrupt => CredentialError::Corrupt,
        KeyStoreError::Other(m) => CredentialError::Other(m),
    }
}

#[derive(Serialize)]
struct BlobOut<'a> {
    v: u32,
    pat: &'a str,
    url_hash: String,
    user: &'a str,
    user_key: &'a str,
    expires_at: Option<String>,
}

/// A string field read into zeroizing memory.
struct SecretField(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretField {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = SecretField;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<SecretField, E> {
                Ok(SecretField(Zeroizing::new(s.to_owned())))
            }
        }
        d.deserialize_str(V)
    }
}

struct BlobIn {
    v: u32,
    pat: SecretField,
    url_hash: String,
    user: String,
    user_key: String,
    expires_at: Option<String>,
}

impl<'de> Deserialize<'de> for BlobIn {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = BlobIn;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a credential blob")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<BlobIn, A::Error> {
                let (mut v, mut pat, mut url_hash, mut user, mut user_key) =
                    (None, None, None, None, None);
                let mut expires_at: Option<Option<String>> = None;
                while let Some(key) = m.next_key::<String>()? {
                    match key.as_str() {
                        "v" => v = Some(m.next_value::<u32>()?),
                        "pat" => pat = Some(m.next_value::<SecretField>()?),
                        "url_hash" => url_hash = Some(m.next_value::<String>()?),
                        "user" => user = Some(m.next_value::<String>()?),
                        "user_key" => user_key = Some(m.next_value::<String>()?),
                        "expires_at" => expires_at = Some(m.next_value::<Option<String>>()?),
                        _ => {
                            m.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                let missing = |f| de::Error::missing_field(f);
                Ok(BlobIn {
                    v: v.ok_or_else(|| missing("v"))?,
                    pat: pat.ok_or_else(|| missing("pat"))?,
                    url_hash: url_hash.ok_or_else(|| missing("url_hash"))?,
                    user: user.ok_or_else(|| missing("user"))?,
                    user_key: user_key.ok_or_else(|| missing("user_key"))?,
                    expires_at: expires_at.ok_or_else(|| missing("expires_at"))?,
                })
            }
        }
        d.deserialize_map(V)
    }
}

/// Encodes a credential as the PD-05 blob.
pub(crate) fn encode_blob(c: &StoredCredential) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
    let out = BlobOut {
        v: BLOB_VERSION,
        pat: c.pat.expose_secret(),
        url_hash: c.base_url_hash.to_hex(),
        user: &c.identity.atlassian_user,
        user_key: &c.identity.atlassian_user_key,
        expires_at: c.expires_at.map(|d| d.format("%Y-%m-%d").to_string()),
    };
    // Sized up front: a growing `Vec` frees every outgrown copy of the PAT unzeroized (M-4).
    let size = out.pat.len() + out.user.len() + out.user_key.len() + 256;
    let mut buf = Zeroizing::new(Vec::with_capacity(size));
    serde_json::to_writer(&mut *buf, &out).map_err(|_| CredentialError::Corrupt)?;
    Ok(buf)
}

/// Parses the PD-05 blob; an unknown `v` or any malformed field is `Corrupt`.
pub(crate) fn decode_blob(bytes: &[u8]) -> Result<StoredCredential, CredentialError> {
    let b: BlobIn = serde_json::from_slice(bytes).map_err(|_| CredentialError::Corrupt)?;
    if b.v != BLOB_VERSION {
        return Err(CredentialError::Corrupt);
    }
    let base_url_hash = UrlHash::from_hex(&b.url_hash).ok_or(CredentialError::Corrupt)?;
    let expires_at = match b.expires_at {
        Some(s) => {
            Some(NaiveDate::parse_from_str(&s, "%Y-%m-%d").map_err(|_| CredentialError::Corrupt)?)
        }
        None => None,
    };
    Ok(StoredCredential {
        pat: PatSecret::new(b.pat.0.as_str().to_owned()),
        base_url_hash,
        identity: StoredIdentity {
            atlassian_user: b.user,
            atlassian_user_key: b.user_key,
        },
        expires_at,
    })
}

/// The PATs of every instance of this install, in the keychain the audit store also uses.
pub struct KeychainCredentials {
    keys: Arc<dyn KeyStore>,
}

impl KeychainCredentials {
    pub fn new(keys: Arc<dyn KeyStore>) -> KeychainCredentials {
        KeychainCredentials { keys }
    }
}

impl fmt::Debug for KeychainCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeychainCredentials")
    }
}

impl CredentialProvider for KeychainCredentials {
    fn load(&self, instance_id: &str) -> Result<Option<StoredCredential>, CredentialError> {
        let raw = self
            .keys
            .get(&EntryName::Pat(instance_id.to_owned()))
            .map_err(credential_error)?;
        raw.map(|bytes| decode_blob(&bytes)).transpose()
    }

    fn store(&self, instance_id: &str, c: StoredCredential) -> Result<(), CredentialError> {
        let blob = encode_blob(&c)?;
        self.keys
            .set(&EntryName::Pat(instance_id.to_owned()), &blob)
            .map_err(credential_error)
    }

    fn delete(&self, instance_id: &str) -> Result<(), CredentialError> {
        self.keys
            .delete(&EntryName::Pat(instance_id.to_owned()))
            .map_err(credential_error)
    }
}
