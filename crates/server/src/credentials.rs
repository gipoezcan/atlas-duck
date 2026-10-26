//! `ServerCredentials`: one user's PATs (SM-4.2, PD-211). Core's own `KeychainCredentials` (its
//! PD-05 blob codec and `CredentialProvider` contract) runs over [`PatKeyStore`], a `KeyStore`
//! that keeps each `pat/<instance_id>` entry as the user's `user_pats` row of the instance's alias,
//! sealed with the user's data key under AAD `"pat\0" || alias || "\0" || user_id`. The row also
//! holds the identity (no secret) for `GET /api/instances`.

use std::sync::Arc;

use atlas_duck_audit::keystore::{EntryName, KeyStore, KeyStoreError, KeyringLocality};
use atlas_duck_core::KeychainCredentials;
use serde_json::json;
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::instances::alias_for_id;
use crate::master_key::{DataKey, open, seal};
use crate::store::{PatRecord, ServerStore};

/// The credential provider of one user runtime.
pub type ServerCredentials = KeychainCredentials;

pub fn server_credentials(
    store: Arc<dyn ServerStore>,
    user_id: &str,
    dk: DataKey,
    clock: Arc<dyn Clock>,
) -> Arc<ServerCredentials> {
    Arc::new(KeychainCredentials::new(Arc::new(PatKeyStore {
        store,
        user_id: user_id.to_owned(),
        dk,
        clock,
    })))
}

pub struct PatKeyStore {
    store: Arc<dyn ServerStore>,
    user_id: String,
    dk: DataKey,
    clock: Arc<dyn Clock>,
}

pub fn pat_aad(alias: &str, user_id: &str) -> Vec<u8> {
    let mut aad = b"pat\0".to_vec();
    aad.extend_from_slice(alias.as_bytes());
    aad.push(0);
    aad.extend_from_slice(user_id.as_bytes());
    aad
}

fn store_err<E>(_: E) -> KeyStoreError {
    KeyStoreError::Other("server store".into())
}

/// The PD-05 blob's identity fields, read without keeping the PAT field.
fn identity_of(blob: &[u8]) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_slice(blob).unwrap_or_default();
    json!({"user": v.get("user"), "user_key": v.get("user_key")})
}

impl PatKeyStore {
    /// The alias of a `pat/<instance_id>` entry; any other entry is not this store's.
    fn alias(&self, e: &EntryName) -> Result<Option<String>, KeyStoreError> {
        match e {
            EntryName::Pat(id) => Ok(alias_for_id(self.store.as_ref(), id)),
            _ => Err(KeyStoreError::Other("not a PAT entry".into())),
        }
    }
}

impl KeyStore for PatKeyStore {
    fn install_id(&self) -> &str {
        &self.user_id
    }

    fn get(&self, e: &EntryName) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        let Some(alias) = self.alias(e)? else {
            return Ok(None);
        };
        match self
            .store
            .pat_get(&self.user_id, &alias)
            .map_err(store_err)?
        {
            None => Ok(None),
            Some(row) => open(&self.dk, &pat_aad(&alias, &self.user_id), &row.sealed)
                .map(Some)
                .map_err(|_| KeyStoreError::Corrupt),
        }
    }

    fn set(&self, e: &EntryName, v: &[u8]) -> Result<(), KeyStoreError> {
        let Some(alias) = self.alias(e)? else {
            return Err(KeyStoreError::Other("no such instance".into()));
        };
        let sealed = seal(&self.dk, &pat_aad(&alias, &self.user_id), v)
            .map_err(|_| KeyStoreError::Other("seal failed".into()))?;
        self.store
            .pat_put(&PatRecord {
                user_id: self.user_id.clone(),
                alias,
                sealed,
                identity_json: identity_of(v).to_string(),
                checked_at: self.clock.now(),
            })
            .map_err(store_err)
    }

    fn delete(&self, e: &EntryName) -> Result<(), KeyStoreError> {
        let Some(alias) = self.alias(e)? else {
            return Ok(());
        };
        self.store
            .pat_delete(&self.user_id, &alias)
            .map(|_| ())
            .map_err(store_err)
    }

    fn locality(&self) -> KeyringLocality {
        KeyringLocality::Local
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use atlas_duck_atlassian::{
        CredentialProvider, PatSecret, StoredCredential, StoredIdentity, UrlHash,
    };

    use super::*;
    use crate::clock::ManualClock;
    use crate::instances::instance_id_for;
    use crate::master_key::SecretKey;
    use crate::store::memory::MemoryStore;
    use crate::store::{InstanceRecord, UserRecord};

    fn setup() -> Arc<dyn ServerStore> {
        let s: Arc<dyn ServerStore> = Arc::new(MemoryStore::new());
        for u in ["a", "b"] {
            s.upsert_user(&UserRecord {
                user_id: u.into(),
                username: u.into(),
                display_name: None,
                roles: vec![],
                data_key_wrapped: String::new(),
                created_at: 0,
            })
            .unwrap();
        }
        s.instance_put(&InstanceRecord {
            alias: "work".into(),
            product: "jira".into(),
            base_url: "https://jira.example.test".into(),
            proxy: None,
            ca_ref: None,
            is_default: true,
        })
        .unwrap();
        s
    }

    fn cred(pat: &str) -> StoredCredential {
        StoredCredential {
            pat: PatSecret::new(pat.into()),
            base_url_hash: UrlHash::from_hex(&"ab".repeat(32)).unwrap(),
            identity: StoredIdentity {
                atlassian_user: "jdoe".into(),
                atlassian_user_key: "JIRAUSER1".into(),
            },
            expires_at: None,
        }
    }

    #[test]
    fn pats_round_trip_sealed_per_user() {
        let s = setup();
        let clock = ManualClock::at(100);
        let a = server_credentials(s.clone(), "a", SecretKey::random().unwrap(), clock.clone());
        let b = server_credentials(s.clone(), "b", SecretKey::random().unwrap(), clock);
        let id = instance_id_for("work");
        a.store(&id, cred("pat-canary-a1")).unwrap();
        let got = a.load(&id).unwrap().unwrap();
        assert_eq!(got.pat.expose_secret(), "pat-canary-a1");
        assert_eq!(got.identity.atlassian_user, "jdoe");
        assert!(b.load(&id).unwrap().is_none(), "B sees no PAT of A");
        let row = s.pat_get("a", "work").unwrap().unwrap();
        assert!(!row.sealed.ct.windows(13).any(|w| w == b"pat-canary-a1"));
        assert!(!row.identity_json.contains("pat-canary"));
        assert_eq!(
            row.identity_json,
            r#"{"user":"jdoe","user_key":"JIRAUSER1"}"#
        );
        assert_eq!(row.checked_at, 100);
        // A's row copied to B does not open under B's key and AAD.
        s.pat_put(&PatRecord {
            user_id: "b".into(),
            ..row
        })
        .unwrap();
        assert!(b.load(&id).is_err());
        a.delete(&id).unwrap();
        assert!(a.load(&id).unwrap().is_none());
        // An instance id no admin instance has: nothing stored, nothing found.
        assert!(a.load(&instance_id_for("gone")).unwrap().is_none());
        assert!(a.store(&instance_id_for("gone"), cred("x")).is_err());
    }
}
