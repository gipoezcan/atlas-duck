//! `ServerKeyStore`: the audit `KeyStore` of one user (PD-210). Entries live in the server store,
//! sealed with the user's data key under AAD `entry || "\0" || user_id`, so the M2 store's own
//! key hierarchy sits under the data key, which sits under the master key.

use std::sync::Arc;

use atlas_duck_audit::keystore::{EntryName, KeyStore, KeyStoreError, KeyringLocality};
use zeroize::Zeroizing;

use crate::master_key::{DataKey, KeyError, open, seal};
use crate::store::ServerStore;

pub struct ServerKeyStore {
    store: Arc<dyn ServerStore>,
    user_id: String,
    dk: DataKey,
}

impl ServerKeyStore {
    pub fn new(store: Arc<dyn ServerStore>, user_id: &str, dk: DataKey) -> ServerKeyStore {
        ServerKeyStore {
            store,
            user_id: user_id.to_owned(),
            dk,
        }
    }

    fn aad(&self, entry: &str) -> Vec<u8> {
        let mut aad = entry.as_bytes().to_vec();
        aad.push(0);
        aad.extend_from_slice(self.user_id.as_bytes());
        aad
    }
}

fn store_err<E>(_: E) -> KeyStoreError {
    KeyStoreError::Other("server store".into())
}

impl KeyStore for ServerKeyStore {
    fn install_id(&self) -> &str {
        &self.user_id
    }

    fn get(&self, e: &EntryName) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        let entry = e.account();
        match self
            .store
            .ks_get(&self.user_id, &entry)
            .map_err(store_err)?
        {
            None => Ok(None),
            Some(sealed) => match open(&self.dk, &self.aad(&entry), &sealed) {
                Ok(v) => Ok(Some(v)),
                Err(_) => Err(KeyStoreError::Corrupt),
            },
        }
    }

    fn set(&self, e: &EntryName, v: &[u8]) -> Result<(), KeyStoreError> {
        let entry = e.account();
        let sealed = seal(&self.dk, &self.aad(&entry), v).map_err(|e| match e {
            KeyError::NoRandomness => KeyStoreError::Other("no system randomness".into()),
            _ => KeyStoreError::Other("seal failed".into()),
        })?;
        self.store
            .ks_set(&self.user_id, &entry, &sealed)
            .map_err(store_err)
    }

    fn delete(&self, e: &EntryName) -> Result<(), KeyStoreError> {
        self.store
            .ks_delete(&self.user_id, &e.account())
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
    use atlas_duck_audit::keystore::canary_self_test;
    use proptest::prelude::*;

    use super::*;
    use crate::master_key::SecretKey;
    use crate::store::memory::MemoryStore;
    use crate::store::{Sealed, UserRecord};

    fn store_with(users: &[&str]) -> Arc<dyn ServerStore> {
        let s: Arc<dyn ServerStore> = Arc::new(MemoryStore::new());
        for u in users {
            s.upsert_user(&UserRecord {
                user_id: (*u).into(),
                username: (*u).into(),
                display_name: None,
                roles: vec![],
                data_key_wrapped: String::new(),
                created_at: 0,
            })
            .unwrap();
        }
        s
    }

    #[test]
    fn canary_passes() {
        let s = store_with(&["a"]);
        let ks = ServerKeyStore::new(s, "a", SecretKey::random().unwrap());
        canary_self_test(&ks).unwrap();
        assert_eq!(ks.install_id(), "a");
        assert_eq!(ks.locality(), KeyringLocality::Local);
        assert!(ks.for_install("b".repeat(32).as_str()).is_none());
    }

    #[test]
    fn round_trip_delete_and_absent() {
        let s = store_with(&["a"]);
        let ks = ServerKeyStore::new(s.clone(), "a", SecretKey::random().unwrap());
        assert_eq!(ks.get(&EntryName::Kek).unwrap(), None);
        ks.set(&EntryName::Kek, b"kek bytes").unwrap();
        assert_eq!(
            ks.get(&EntryName::Kek).unwrap().unwrap().as_slice(),
            b"kek bytes"
        );
        // Stored sealed: the plaintext is not in the row.
        let raw = s.ks_get("a", "kek").unwrap().unwrap();
        assert!(!raw.ct.windows(9).any(|w| w == b"kek bytes"));
        ks.delete(&EntryName::Kek).unwrap();
        ks.delete(&EntryName::Kek).unwrap();
        assert_eq!(ks.get(&EntryName::Kek).unwrap(), None);
    }

    #[test]
    fn user_a_entries_unreadable_through_b() {
        let s = store_with(&["a", "b"]);
        let a = ServerKeyStore::new(s.clone(), "a", SecretKey::random().unwrap());
        let b = ServerKeyStore::new(s.clone(), "b", SecretKey::random().unwrap());
        a.set(&EntryName::Kek, b"secret of a").unwrap();
        assert_eq!(b.get(&EntryName::Kek).unwrap(), None);
        // Copy A's sealed row under B's name: B's key and AAD refuse it.
        let stolen = s.ks_get("a", "kek").unwrap().unwrap();
        s.ks_set("b", "kek", &stolen).unwrap();
        assert_eq!(b.get(&EntryName::Kek).unwrap_err(), KeyStoreError::Corrupt);
        // A tampered ciphertext is Corrupt, never a silent value.
        let corrupt = Sealed {
            nonce: stolen.nonce.clone(),
            ct: vec![0; stolen.ct.len()],
        };
        s.ks_set("a", "head_anchor", &corrupt).unwrap();
        assert_eq!(
            a.get(&EntryName::HeadAnchor).unwrap_err(),
            KeyStoreError::Corrupt
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn random_entries_round_trip(id in "[a-z0-9_]{1,40}", value in proptest::collection::vec(any::<u8>(), 0..256)) {
            let s = store_with(&["a"]);
            let ks = ServerKeyStore::new(s, "a", SecretKey::random().unwrap());
            let e = EntryName::Pat(id);
            ks.set(&e, &value).unwrap();
            let got = ks.get(&e).unwrap().unwrap();
            prop_assert_eq!(got.as_slice(), value.as_slice());
        }
    }
}
