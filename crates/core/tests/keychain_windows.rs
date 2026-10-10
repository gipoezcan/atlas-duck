#![cfg(windows)]
//! RF-3a, the PAT half (Task 25): a PAT entry written through `KeychainCredentials` lands in the
//! Windows Credential Manager as a generic credential with `CRED_PERSIST_LOCAL_MACHINE`, so it
//! never roams (§8.6). The audit crate owns the same check for its own entries
//! (`audit/tests/os_keystore.rs`); like those, this test touches the real keychain, under a random
//! throwaway install id, and is run in the CI keychain step (`-- --ignored`).

use std::sync::Arc;

use atlas_duck_atlassian::{
    CredentialProvider, PatSecret, StoredCredential, StoredIdentity, UrlHash,
};
use atlas_duck_audit::keystore::credential_persist;
use atlas_duck_audit::{EntryName, KeyStore, OsKeyStore};
use atlas_duck_core::KeychainCredentials;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// `CRED_PERSIST_LOCAL_MACHINE`.
const PERSIST_LOCAL: u32 = 2;

/// Deletes the entry when the test ends, on every path.
struct Cleanup {
    keys: Arc<OsKeyStore>,
    entry: EntryName,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.keys.delete(&self.entry);
    }
}

#[test]
#[ignore = "touches the OS keychain; run in the CI keychain step"]
fn rf3a_pat_entry_persist_local() -> TestResult {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|e| e.to_string())?;
    let install_id = format!("test-{}", hex::encode(random));
    let instance_id = "ins_0123456789abcdef0123456789abcdef";
    let keys = Arc::new(OsKeyStore::new(&install_id).map_err(|e| e.to_string())?);
    let entry = EntryName::Pat(instance_id.to_owned());
    let _cleanup = Cleanup {
        keys: keys.clone(),
        entry: entry.clone(),
    };
    let target = entry.full_name(&install_id);
    assert_eq!(target, format!("atlas-duck/{install_id}/pat/{instance_id}"));
    assert_eq!(
        credential_persist(&target).map_err(|e| e.to_string())?,
        None
    );
    let creds = KeychainCredentials::new(keys);
    let credential = |pat: &str| StoredCredential {
        pat: PatSecret::new(pat.to_owned()),
        base_url_hash: UrlHash([3; 32]),
        identity: StoredIdentity {
            atlassian_user: "jdoe".to_owned(),
            atlassian_user_key: "JIRAUSER1".to_owned(),
        },
        expires_at: None,
    };
    creds
        .store(instance_id, credential("first"))
        .map_err(|e| e.to_string())?;
    assert_eq!(
        credential_persist(&target).map_err(|e| e.to_string())?,
        Some(PERSIST_LOCAL)
    );
    // The update path keeps it local, and the blob reads back.
    creds
        .store(instance_id, credential("second"))
        .map_err(|e| e.to_string())?;
    assert_eq!(
        credential_persist(&target).map_err(|e| e.to_string())?,
        Some(PERSIST_LOCAL)
    );
    let loaded = creds
        .load(instance_id)
        .map_err(|e| e.to_string())?
        .ok_or("no entry")?;
    assert_eq!(loaded.pat.expose_secret(), "second");
    Ok(())
}
