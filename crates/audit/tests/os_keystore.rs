//! Real OS keychain. Every test is `#[ignore]`d: run with `-- --ignored --test-threads=1`.
//! Each test uses a fresh random install id (`test-<random>`) and a guard that deletes all
//! entries on drop, so a failure (or panic) leaves nothing behind. The one exception is U-18
//! (module `u18`): `create_new_store` accepts only a 32-hex install id, so it uses
//! `7e57` ("test") followed by `0000` and 24 random hex digits, which a sweep of leftover test
//! entries can match as `atlas-duck/7e570000*`.

use atlas_duck_audit::keystore::{EntryName, KeyStore, OsKeyStore, canary_self_test};

// Top level, so the path is `tests/common/mod.rs` (an inline `mod` would look under `tests/u18/`).
mod common;

const IGNORE: &str = "touches the OS keychain; run in the CI keychain step";

fn kinds() -> Vec<EntryName> {
    vec![
        EntryName::Kek,
        EntryName::HeadAnchor,
        EntryName::FirstRetainedAnchor,
        EntryName::Canary,
        EntryName::Pat("ci".into()),
    ]
}

fn fresh_id() -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).unwrap();
    format!("test-{}", hex::encode(b))
}

struct Guard {
    ks: OsKeyStore,
}

impl Guard {
    fn new() -> Guard {
        Guard::with_id(&fresh_id())
    }
    fn with_id(id: &str) -> Guard {
        assert!(id.starts_with("test-"), "tests only touch test-* installs");
        Guard {
            ks: OsKeyStore::with_keyring_dirs(id, Vec::new()).expect("store"),
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        for k in kinds() {
            let _ = self.ks.delete(&k);
        }
    }
}

fn value(seed: u8, len: usize) -> Vec<u8> {
    let mut v: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7) ^ seed).collect();
    v[0] = 0x00;
    v[1] = 0xFF;
    v
}

#[test]
#[ignore = "touches the OS keychain; run in the CI keychain step"]
fn os_round_trip_all_kinds() {
    let _ = IGNORE;
    let g = Guard::new();
    for (i, k) in kinds().iter().enumerate() {
        let v1 = value(1, 33 + i * 40);
        let v2 = value(2, 200 - i * 30);
        assert_eq!(g.ks.get(k).unwrap(), None);
        g.ks.set(k, &v1).unwrap();
        assert_eq!(g.ks.get(k).unwrap().unwrap().as_slice(), v1.as_slice());
        g.ks.set(k, &v2).unwrap();
        assert_eq!(g.ks.get(k).unwrap().unwrap().as_slice(), v2.as_slice());
        g.ks.delete(k).unwrap();
        assert_eq!(g.ks.get(k).unwrap(), None);
    }
}

#[test]
#[ignore = "touches the OS keychain; run in the CI keychain step"]
fn os_absent_is_none_and_delete_idempotent() {
    let g = Guard::new();
    assert_eq!(g.ks.get(&EntryName::Kek).unwrap(), None);
    g.ks.delete(&EntryName::Kek).unwrap();
    g.ks.delete(&EntryName::Kek).unwrap();
    g.ks.set(&EntryName::Kek, &value(3, 40)).unwrap();
    g.ks.delete(&EntryName::Kek).unwrap();
    g.ks.delete(&EntryName::Kek).unwrap();
    assert_eq!(g.ks.get(&EntryName::Kek).unwrap(), None);
}

#[test]
#[ignore = "touches the OS keychain; run in the CI keychain step"]
fn os_canary_self_test() {
    let g = Guard::new();
    canary_self_test(&g.ks).unwrap();
    assert_eq!(g.ks.get(&EntryName::Canary).unwrap(), None);
}

#[test]
#[ignore = "touches the OS keychain; run in the CI keychain step"]
fn os_two_installs_isolated() {
    let a = Guard::new();
    let b = Guard::new();
    a.ks.set(&EntryName::Kek, &value(4, 40)).unwrap();
    assert_eq!(b.ks.get(&EntryName::Kek).unwrap(), None);
    b.ks.set(&EntryName::Kek, &value(5, 50)).unwrap();
    assert_eq!(
        a.ks.get(&EntryName::Kek).unwrap().unwrap().as_slice(),
        value(4, 40).as_slice()
    );
    assert_eq!(
        b.ks.get(&EntryName::Kek).unwrap().unwrap().as_slice(),
        value(5, 50).as_slice()
    );
    a.ks.delete(&EntryName::Kek).unwrap();
    assert!(b.ks.get(&EntryName::Kek).unwrap().is_some());
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "touches the OS keychain; run in the CI keychain step"]
fn os_entry_visible_under_service_and_account() {
    let g = Guard::new();
    g.ks.set(&EntryName::Kek, &value(9, 40)).unwrap();
    let st = std::process::Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            &format!("atlas-duck/{}", g.ks.install_id()),
            "-a",
            "kek",
        ])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "touches the OS keychain; run in the CI keychain step"]
fn os_secret_service_attributes() {
    let g = Guard::new();
    g.ks.set(&EntryName::Kek, &value(9, 40)).unwrap();
    let service = format!("atlas-duck/{}", g.ks.install_id());
    let st = std::process::Command::new("secret-tool")
        .args(["lookup", "service", &service, "username", "kek"])
        .output()
        .unwrap();
    if !st.status.success() {
        let all = std::process::Command::new("secret-tool")
            .args(["search", "--all", "service", &service])
            .output()
            .unwrap();
        println!("attributes: {}", String::from_utf8_lossy(&all.stdout));
        println!("{}", String::from_utf8_lossy(&all.stderr));
        assert!(
            String::from_utf8_lossy(&all.stdout).contains(&service),
            "service attribute missing"
        );
    }
}

/// U-18 per OS (§13): a store on the real keychain, the keychain wiped (its five entries
/// deleted), `keychain_lost`, then "Recover this log" on the same chain. `create_new_store`
/// needs a 32-hex install id: `7e570000` + random (see the file header), and this guard deletes
/// everything the flow creates under it.
mod u18 {
    use std::sync::Arc;

    use atlas_duck_audit::anchors::HeadAnchor;
    use atlas_duck_audit::error::OpenError;
    use atlas_duck_audit::keystore::{EntryName, KeyStore, OsKeyStore};
    use atlas_duck_audit::types::Confirmed;
    use atlas_duck_audit::{
        LockedReason, OpenConfig, RecoveryOffer, SettingChange, StartupOutcome, create_new_store,
        new_ids, open, recover_this_log,
    };

    /// `7e570000` ("test") + 24 random hex digits: a valid install id that is visibly a test's.
    fn test_install_id() -> String {
        let (random, _) = new_ids().expect("ids");
        format!("7e570000{}", &random[8..])
    }
    use secrecy::SecretString;

    use super::common::*;

    const INSTANCE: &str = "ci";

    fn entries() -> Vec<EntryName> {
        vec![
            EntryName::Kek,
            EntryName::HeadAnchor,
            EntryName::FirstRetainedAnchor,
            EntryName::Canary,
            EntryName::Pat(INSTANCE.into()),
        ]
    }

    struct Wipe(Arc<OsKeyStore>);

    impl Wipe {
        fn now(&self) {
            for e in entries() {
                self.0.delete(&e).expect("delete entry");
            }
        }
    }

    impl Drop for Wipe {
        fn drop(&mut self) {
            for e in entries() {
                let _ = self.0.delete(&e);
            }
        }
    }

    #[test]
    #[ignore = "touches the OS keychain; run in the CI keychain step"]
    fn os_u18_keychain_wiped() {
        let install_id = test_install_id();
        let (_, chain_id) = new_ids().expect("ids");
        let ks = Arc::new(OsKeyStore::new(&install_id).expect("os keystore"));
        let guard = Wipe(ks.clone());
        let (_dir, data, lock) = tmp_data_dir();
        let clock = fake_clock(START);
        let cfg = || OpenConfig::new(clock.clone(), ks.clone());

        let store = create_new_store(
            &data,
            &lock,
            cfg(),
            input(&install_id, &chain_id, PASSPHRASE, PASSPHRASE),
        )
        .expect("create_new_store");
        store
            .apply_setting(
                SettingChange::InstanceOrigin {
                    instance_id: INSTANCE.into(),
                    origin: Some("https://jira.example".into()),
                },
                Some(Confirmed {
                    dialog_text_sha256: [7; 32],
                }),
            )
            .expect("origin");
        ks.set(&EntryName::Pat(INSTANCE.into()), b"token")
            .expect("pat");
        store.append_batch(mixed(12)).expect("append");
        store.flush_head_anchor().expect("flush");
        let (h, _, _) = store.head();
        store.shutdown();

        guard.now();
        match open(&data, &lock, cfg()).expect("open") {
            StartupOutcome::Locked(r) => assert_eq!(
                r,
                LockedReason::KeychainLost {
                    offer: RecoveryOffer::RecoverThisLog
                }
            ),
            other => panic!("expected Locked, got {other:?}"),
        }
        let wrong = SecretString::from("not the passphrase at all".to_string());
        assert!(matches!(
            recover_this_log(&data, &lock, cfg(), &wrong),
            Err(OpenError::WrongPassphrase)
        ));
        assert_eq!(ks.get(&EntryName::Kek).expect("get"), None);

        let right = SecretString::from(PASSPHRASE.to_string());
        let (store, report) = recover_this_log(&data, &lock, cfg(), &right).expect("recover");
        assert_eq!(store.head().2, chain_id);
        assert_eq!(report.verify_seq, h + 1);
        assert_eq!(report.key_recovered_seq, h + 2);
        assert_eq!(report.pats_deleted, vec![INSTANCE.to_string()]);
        assert!(ks.get(&EntryName::Kek).expect("get").is_some());
        let head = ks
            .get(&EntryName::HeadAnchor)
            .expect("get")
            .map(|b| HeadAnchor::from_entry(&b).expect("head anchor"))
            .expect("head anchor rebuilt");
        assert_eq!(head.seq, h + 2);
        assert!(
            ks.get(&EntryName::FirstRetainedAnchor)
                .expect("get")
                .is_some()
        );
        assert_eq!(ks.get(&EntryName::Pat(INSTANCE.into())).expect("get"), None);
        store.shutdown();

        match open(&data, &lock, cfg()).expect("open") {
            StartupOutcome::Ready { store, verify, .. } => {
                assert!(verify.findings.is_empty(), "{:?}", verify.findings);
                assert_eq!(store.open_incidents(), vec![h + 1]);
                store.shutdown();
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use atlas_duck_audit::keystore::credential_persist;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Credentials::{
        CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW, CredWriteW,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Reads `TargetName` back through `CredReadW`.
    fn target_name(target: &str) -> String {
        let w = wide(target);
        let mut p: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `w` is NUL-terminated; `p` is a valid out-pointer.
        let ok = unsafe { CredReadW(w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut p) };
        assert!(ok != 0, "CredReadW failed: {}", unsafe { GetLastError() });
        // SAFETY: success: `p` is a valid CREDENTIALW whose TargetName is NUL-terminated;
        // freed once after the copy.
        unsafe {
            let t = (*p).TargetName;
            let mut n = 0;
            while *t.add(n) != 0 {
                n += 1;
            }
            let s = String::from_utf16(std::slice::from_raw_parts(t, n)).unwrap();
            CredFree(p as *const _);
            s
        }
    }

    #[test]
    #[ignore = "touches the OS keychain; run in the CI keychain step"]
    fn rf3a_keyring_persist_local() {
        let g = Guard::new();
        for k in kinds() {
            let full = k.full_name(g.ks.install_id());
            assert_eq!(credential_persist(&full).unwrap(), None);
            g.ks.set(&k, &value(6, 40)).unwrap();
            assert_eq!(credential_persist(&full).unwrap(), Some(2), "{full}");
            assert_eq!(target_name(&full), full);
            // Second write (update path) keeps it local.
            g.ks.set(&k, &value(7, 41)).unwrap();
            assert_eq!(
                credential_persist(&full).unwrap(),
                Some(2),
                "{full} (update)"
            );
        }
    }

    #[test]
    #[ignore = "touches the OS keychain; run in the CI keychain step"]
    fn rf3a_existing_enterprise_entry_rewritten_local() {
        let g = Guard::new();
        let full = EntryName::Kek.full_name(g.ks.install_id());
        assert!(full.starts_with("atlas-duck/test-"));
        let mut target = wide(&full);
        let mut user = wide("kek");
        let mut blob = [1u8; 33];
        // SAFETY: an all-zero CREDENTIALW is valid (null pointers, zero counts); the used fields
        // are set below and the buffers outlive the call.
        let mut cred: CREDENTIALW = unsafe { std::mem::zeroed() };
        cred.Type = CRED_TYPE_GENERIC;
        cred.TargetName = target.as_mut_ptr();
        cred.UserName = user.as_mut_ptr();
        cred.CredentialBlobSize = blob.len() as u32;
        cred.CredentialBlob = blob.as_mut_ptr();
        cred.Persist = 3; // CRED_PERSIST_ENTERPRISE
        // SAFETY: `cred` points at live buffers for the duration of the call.
        assert!(unsafe { CredWriteW(&cred, 0) } != 0);
        assert_eq!(credential_persist(&full).unwrap(), Some(3));

        let v = value(8, 64);
        g.ks.set(&EntryName::Kek, &v).unwrap();
        assert_eq!(credential_persist(&full).unwrap(), Some(2));
        assert_eq!(
            g.ks.get(&EntryName::Kek).unwrap().unwrap().as_slice(),
            v.as_slice()
        );
    }
}
