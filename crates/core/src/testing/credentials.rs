//! `InMemoryCredentials` (C.7 `core::testing`): a `CredentialProvider` over a map, so tests
//! never touch an OS keychain. Task 25 completes what the instance admin needs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use atlas_duck_atlassian::{
    CredentialError, CredentialProvider, PatSecret, StoredCredential, StoredIdentity, UrlHash,
};
use zeroize::Zeroizing;

struct Entry {
    pat: Zeroizing<String>,
    base_url_hash: UrlHash,
    identity: StoredIdentity,
    expires_at: Option<chrono::NaiveDate>,
}

/// PATs by instance id. `Debug` names the ids only.
#[derive(Default)]
pub struct InMemoryCredentials {
    entries: Mutex<HashMap<String, Entry>>,
    fail_store: AtomicBool,
    fail_delete: AtomicBool,
    /// Runs once, at the start of the next `load` (a test holds the caller there).
    on_next_load: Mutex<Option<LoadHook>>,
}

type LoadHook = Box<dyn FnOnce() + Send>;

impl std::fmt::Debug for InMemoryCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryCredentials")
            .field("instances", &self.lock().keys().collect::<Vec<_>>())
            .finish()
    }
}

impl InMemoryCredentials {
    pub fn new() -> InMemoryCredentials {
        InMemoryCredentials::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stores `pat` for `instance_id`, bound to `bound` (the instance's URL hash, §7.1).
    pub fn put(&self, instance_id: &str, pat: &str, bound: UrlHash, user: &str, user_key: &str) {
        self.lock().insert(
            instance_id.to_owned(),
            Entry {
                pat: Zeroizing::new(pat.to_owned()),
                base_url_hash: bound,
                identity: StoredIdentity {
                    atlassian_user: user.to_owned(),
                    atlassian_user_key: user_key.to_owned(),
                },
                expires_at: None,
            },
        );
    }

    /// While on, every `store` fails with `Unavailable` (the keychain write after the audit
    /// record).
    pub fn fail_store(&self, on: bool) {
        self.fail_store.store(on, Ordering::SeqCst);
    }

    /// While on, every `delete` fails with `Unavailable` and keeps the entry (the keychain
    /// delete after the audit record).
    pub fn fail_delete(&self, on: bool) {
        self.fail_delete.store(on, Ordering::SeqCst);
    }

    /// `hook` runs at the start of the next `load`, on the caller's thread, once.
    pub fn on_next_load(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .on_next_load
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(hook));
    }

    pub fn contains(&self, instance_id: &str) -> bool {
        self.lock().contains_key(instance_id)
    }
}

impl CredentialProvider for InMemoryCredentials {
    fn load(&self, instance_id: &str) -> Result<Option<StoredCredential>, CredentialError> {
        let hook = self
            .on_next_load
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(hook) = hook {
            hook();
        }
        Ok(self.lock().get(instance_id).map(|e| StoredCredential {
            pat: PatSecret::new(e.pat.as_str().to_owned()),
            base_url_hash: e.base_url_hash,
            identity: e.identity.clone(),
            expires_at: e.expires_at,
        }))
    }

    fn store(&self, instance_id: &str, c: StoredCredential) -> Result<(), CredentialError> {
        if self.fail_store.load(Ordering::SeqCst) {
            return Err(CredentialError::Unavailable);
        }
        self.lock().insert(
            instance_id.to_owned(),
            Entry {
                pat: Zeroizing::new(c.pat.expose_secret().to_owned()),
                base_url_hash: c.base_url_hash,
                identity: c.identity,
                expires_at: c.expires_at,
            },
        );
        Ok(())
    }

    fn delete(&self, instance_id: &str) -> Result<(), CredentialError> {
        if self.fail_delete.load(Ordering::SeqCst) {
            return Err(CredentialError::Unavailable);
        }
        self.lock().remove(instance_id);
        Ok(())
    }
}
