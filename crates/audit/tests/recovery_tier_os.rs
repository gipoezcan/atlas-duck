//! The recovery-tier APIs on the real OS keychain (M10 Task 9): three tests of `recovery_tier.rs`
//! with `OsKeyStore` instead of `MemKeyStore`. Every test is `#[ignore]`d and runs in the CI
//! "recovery-tier OS keystore" step of each leg (Windows Credential Manager, macOS login
//! keychain, Linux Secret Service through `ci/keyring-ci.sh`): `-- --ignored --test-threads=1`.
//! `create_new_store` needs 32-hex install ids, so they are `7e570000` ("test") followed by 24
//! random hex digits, as in `os_keystore.rs`'s U-18, and a guard deletes every entry a test may
//! create under them on drop, also when it fails. The test binary creates and reads its own items
//! only, so macOS shows no cross-executable prompt.

mod common;

use std::path::Path;
use std::sync::Arc;

use atlas_duck_audit::crypto::Kek;
use atlas_duck_audit::keystore::{EntryName, KeyStore, OsKeyStore};
use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::recovery::open_recovery;
use atlas_duck_audit::schema::DB_FILE;
use atlas_duck_audit::types::{Confirmed, EventType, NewEvent, RustChosenPath};
use atlas_duck_audit::{
    ArchivedDb, OpenConfig, Store, archive_and_start_fresh, create_new_store, forget_install,
    new_ids, orphan_installs,
};
use atlas_duck_ipc::paths::LocalDataDir;
use common::*;
use secrecy::SecretString;
use serde_json::json;
use tempfile::TempDir;

const NEW_PASS: &str = "a new recovery passphrase";
const B_PASS: &str = "install b recovery passphrase";
const INSTANCES: [&str; 2] = ["i1", "i2"];

/// `7e570000` ("test") + 24 random hex digits: a valid install id that is visibly a test's.
fn test_install_id() -> String {
    let (random, _) = new_ids().expect("ids");
    format!("7e570000{}", &random[8..])
}

fn pass(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn confirmed() -> Confirmed {
    Confirmed {
        dialog_text_sha256: [7; 32],
    }
}

/// Every entry a test may create under one install, deleted on drop.
struct Cleanup(Arc<OsKeyStore>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let mut all = vec![
            EntryName::Kek,
            EntryName::HeadAnchor,
            EntryName::FirstRetainedAnchor,
            EntryName::Canary,
        ];
        all.extend(INSTANCES.iter().map(|i| EntryName::Pat(i.to_string())));
        for e in all {
            let _ = self.0.delete(&e);
        }
    }
}

fn os_keys(id: &str) -> (Arc<OsKeyStore>, Cleanup) {
    assert!(
        id.starts_with("7e570000"),
        "tests only touch 7e570000 installs"
    );
    let ks = Arc::new(OsKeyStore::new(id).expect("os keystore"));
    (ks.clone(), Cleanup(ks))
}

fn present(ks: &OsKeyStore, e: &EntryName) -> bool {
    ks.get(e).expect("keychain get").is_some()
}

fn instance_event(id: &str) -> NewEvent {
    let mut e = ev(EventType::READ_FETCHED, Some("r1"), json!({ "body": id }));
    e.instance_id = Some(id.to_string());
    e
}

fn recovery_blob(data: &Path) -> Vec<u8> {
    rusqlite::Connection::open(data.join(DB_FILE))
        .expect("db")
        .query_row("SELECT blob FROM recovery WHERE id = 1", [], |r| r.get(0))
        .expect("recovery row")
}

/// Install A (with tokens for `i1`, `i2`) archived, install B started fresh beside it.
struct TwoInstalls {
    live: Store,
    a_id: String,
    a_keys: Arc<OsKeyStore>,
    b_keys: Arc<OsKeyStore>,
    archived: ArchivedDb,
    // Drop order: the stores and the lock before the dir; the keychain cleanup last.
    _lock: InstanceLock,
    data: LocalDataDir,
    dir: TempDir,
    _cleanup: (Cleanup, Cleanup),
}

fn two_installs() -> TwoInstalls {
    let a_id = test_install_id();
    let b_id = test_install_id();
    let (a_keys, a_clean) = os_keys(&a_id);
    let (b_keys, b_clean) = os_keys(&b_id);
    let (dir, data, lock) = tmp_data_dir();
    let clock = fake_clock(START);
    let (_, a_chain) = new_ids().expect("ids");
    let a = create_new_store(
        &data,
        &lock,
        OpenConfig::new(clock.clone(), a_keys.clone()),
        input(&a_id, &a_chain, PASSPHRASE, PASSPHRASE),
    )
    .expect("install A");
    a.append_batch(INSTANCES.iter().map(|i| instance_event(i)).collect())
        .expect("append");
    for i in INSTANCES {
        a_keys
            .set(&EntryName::Pat(i.into()), b"token")
            .expect("pat");
    }
    a.flush_head_anchor().expect("flush");
    a.shutdown();
    let archived = archive_and_start_fresh(&data, &lock, confirmed()).expect("archive");
    let (_, b_chain) = new_ids().expect("ids");
    let mut inp = input(&b_id, &b_chain, B_PASS, B_PASS);
    inp.archived_db = Some(archived.clone());
    let live = create_new_store(&data, &lock, OpenConfig::new(clock, b_keys.clone()), inp)
        .expect("install B");
    TwoInstalls {
        live,
        a_id,
        a_keys,
        b_keys,
        archived,
        _lock: lock,
        data,
        dir,
        _cleanup: (a_clean, b_clean),
    }
}

#[test]
#[ignore = "CI: recovery-tier OS keystore step"]
fn os_change_recovery_passphrase_rewraps_and_logs() {
    let id = test_install_id();
    let (ks, _cleanup) = os_keys(&id);
    let (dir, data, lock) = tmp_data_dir();
    let (_, chain) = new_ids().expect("ids");
    let store = create_new_store(
        &data,
        &lock,
        OpenConfig::new(fake_clock(START), ks.clone()),
        input(&id, &chain, PASSPHRASE, PASSPHRASE),
    )
    .expect("create_new_store");
    store.append_batch(mixed(4)).expect("append");
    let before = recovery_blob(dir.path());
    let c = store
        .change_recovery_passphrase(&pass(NEW_PASS), &pass(NEW_PASS))
        .expect("change");
    let p: serde_json::Value =
        serde_json::from_slice(&store.read_payload(c.seq).expect("payload")).expect("json");
    assert_eq!(p, json!({ "change": "recovery_passphrase" }));
    assert_eq!(store.full_verify(), vec![]);
    store.shutdown();

    let after = recovery_blob(dir.path());
    assert_ne!(after, before);
    let kek = Kek::from_entry_bytes(&ks.get(&EntryName::Kek).expect("get").expect("kek"))
        .expect("kek entry");
    assert!(open_recovery(&pass(NEW_PASS), &after).expect("new passphrase") == kek);
    assert!(open_recovery(&pass(PASSPHRASE), &after).is_err());
    drop(lock);
    drop(dir);
}

#[test]
#[ignore = "CI: recovery-tier OS keystore step"]
fn os_forget_install_deletes_pats_keeps_kek_by_default() {
    let t = two_installs();
    let orphans = orphan_installs(&t.data, &*t.b_keys).expect("orphan_installs");
    assert_eq!(orphans.len(), 1, "{orphans:?}");
    assert_eq!(orphans[0].install_id(), t.a_id);
    assert_eq!(
        orphans[0].archived_files(),
        std::slice::from_ref(&t.archived.file)
    );

    let report = forget_install(&*t.b_keys, &orphans[0], confirmed(), None).expect("forget");
    assert_eq!(report.deleted, ["pat/i1", "pat/i2", "canary"]);
    for i in INSTANCES {
        assert!(!present(&t.a_keys, &EntryName::Pat(i.into())), "{i}");
    }
    for e in [
        EntryName::Kek,
        EntryName::HeadAnchor,
        EntryName::FirstRetainedAnchor,
    ] {
        assert!(present(&t.a_keys, &e), "{e:?} kept");
        assert!(present(&t.b_keys, &e), "{e:?} of the live install");
    }
    t.live.shutdown();
    drop(t);
}

#[test]
#[ignore = "CI: recovery-tier OS keystore step"]
fn os_forget_install_with_keys_deletes_all_and_archive_still_restores_with_passphrase() {
    let t = two_installs();
    let orphans = orphan_installs(&t.data, &*t.b_keys).expect("orphan_installs");
    assert_eq!(orphans.len(), 1, "{orphans:?}");
    let report = forget_install(&*t.b_keys, &orphans[0], confirmed(), Some(confirmed()))
        .expect("forget with keys");
    assert!(report.keys_deleted);
    for e in [
        EntryName::Kek,
        EntryName::HeadAnchor,
        EntryName::FirstRetainedAnchor,
        EntryName::Pat("i1".into()),
        EntryName::Pat("i2".into()),
    ] {
        assert!(!present(&t.a_keys, &e), "{e:?} deleted");
    }
    assert!(present(&t.b_keys, &EntryName::Kek));
    assert_eq!(
        orphan_installs(&t.data, &*t.b_keys).expect("orphan_installs"),
        vec![]
    );
    let rep = t
        .live
        .restore(
            RustChosenPath::from_native_dialog(t.dir.path().join(&t.archived.file)),
            &pass(PASSPHRASE),
            None,
        )
        .expect("restore the archive with its passphrase");
    assert_eq!(rep.source_chain_id, t.archived.chain_id);
    t.live.shutdown();
    drop(t);
}
