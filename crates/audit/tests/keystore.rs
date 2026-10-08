//! KeyStore naming, canary, error mapping, locality and keyring dirs. Runs on every OS.

use std::path::PathBuf;

use atlas_duck_audit::keystore::{
    EntryName, KeyStore, KeyStoreError, KeyringLocality, MappedError, canary_self_test,
    keyring_dirs, keyring_locality, map_keyring_error, service_name,
};
use atlas_duck_audit::testing::{MemKeyStore, MemKeyring};
use keyring_core::Error as E;

const INSTALL: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn entry_names_render_exactly() {
    let p = format!("atlas-duck/{INSTALL}");
    assert_eq!(service_name(INSTALL), p);
    assert_eq!(EntryName::Kek.full_name(INSTALL), format!("{p}/kek"));
    assert_eq!(
        EntryName::HeadAnchor.full_name(INSTALL),
        format!("{p}/head_anchor")
    );
    assert_eq!(
        EntryName::FirstRetainedAnchor.full_name(INSTALL),
        format!("{p}/first_retained_anchor")
    );
    assert_eq!(EntryName::Canary.full_name(INSTALL), format!("{p}/canary"));
    assert_eq!(
        EntryName::Pat("inst-7".into()).full_name(INSTALL),
        format!("{p}/pat/inst-7")
    );
}

#[test]
fn canary_passes_on_mem() {
    let ring = MemKeyring::new();
    let ks = MemKeyStore::new(ring, INSTALL);
    canary_self_test(&ks).expect("canary");
}

#[test]
fn canary_detects_mismatch() {
    let ring = MemKeyring::new();
    let ks = MemKeyStore::new(ring.clone(), INSTALL);
    ring.corrupt_next_gets(1);
    let err = canary_self_test(&ks).expect_err("mismatch must fail");
    assert!(matches!(err, KeyStoreError::Other(_)), "{err:?}");
    assert_eq!(ring.raw_get(&service_name(INSTALL), "canary"), None);
}

#[test]
fn canary_leaves_no_entry() {
    let ring = MemKeyring::new();
    let ks = MemKeyStore::new(ring.clone(), INSTALL);
    canary_self_test(&ks).expect("canary");
    assert_eq!(ring.raw_get(&service_name(INSTALL), "canary"), None);
}

#[test]
fn two_installs_share_one_keyring() {
    let ring = MemKeyring::new();
    let a = MemKeyStore::new(ring.clone(), "install-a");
    let b = MemKeyStore::new(ring, "install-b");
    a.set(&EntryName::Kek, &[7u8; 33]).unwrap();
    assert!(a.get(&EntryName::Kek).unwrap().is_some());
    assert!(b.get(&EntryName::Kek).unwrap().is_none());
    b.delete(&EntryName::Kek).unwrap();
    assert!(a.get(&EntryName::Kek).unwrap().is_some());
}

fn pe() -> keyring_core::error::PlatformError {
    Box::new(std::io::Error::other("x"))
}

fn other(s: &str) -> MappedError {
    MappedError::Error(KeyStoreError::Other(s.into()))
}

/// Every `keyring_core::Error` variant is constructible here (the enum is `#[non_exhaustive]`,
/// so the catch-all arm of the mapping is covered by `BadStoreFormat`/`NotSupportedByStore`).
#[test]
fn error_mapping_table() {
    assert_eq!(map_keyring_error(E::NoEntry), MappedError::Absent);
    assert_eq!(
        map_keyring_error(E::NoStorageAccess(pe())),
        MappedError::Error(KeyStoreError::Locked)
    );
    assert_eq!(
        map_keyring_error(E::PlatformFailure(pe())),
        MappedError::Error(KeyStoreError::Unavailable)
    );
    assert_eq!(
        map_keyring_error(E::NoDefaultStore),
        MappedError::Error(KeyStoreError::Unavailable)
    );
    assert_eq!(
        map_keyring_error(E::Ambiguous(Vec::new())),
        other("ambiguous entry")
    );
    assert_eq!(
        map_keyring_error(E::BadEncoding(vec![0xFF, 1])),
        other("bad data")
    );
    assert_eq!(
        map_keyring_error(E::BadDataFormat(vec![1, 2], pe())),
        other("bad data")
    );
    assert_eq!(
        map_keyring_error(E::TooLong("target".into(), 512)),
        other("target too long (max 512)")
    );
    assert_eq!(
        map_keyring_error(E::Invalid("user".into(), "why".into())),
        other("invalid user")
    );
    assert_eq!(
        map_keyring_error(E::BadStoreFormat("s".into())),
        other("keyring error")
    );
    assert_eq!(
        map_keyring_error(E::NotSupportedByStore("s".into())),
        other("keyring error")
    );
}

#[test]
fn locality_local_tmp() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(
        keyring_locality(&[tmp.path().join("keyrings")]),
        KeyringLocality::Local
    );
    assert_eq!(
        keyring_locality(&[tmp.path().join("a").join("b").join("keyrings")]),
        KeyringLocality::Local
    );
}

#[test]
fn locality_nfs_from_env() {
    let Some(nfs) = std::env::var_os("ATLAS_DUCK_TEST_NFS_DIR") else {
        println!("skipped: ATLAS_DUCK_TEST_NFS_DIR not set");
        return;
    };
    let dir = PathBuf::from(nfs).join("xdg/keyrings");
    assert_eq!(
        keyring_locality(std::slice::from_ref(&dir)),
        KeyringLocality::NotLocal { dir }
    );
}

#[cfg(windows)]
#[test]
fn keyring_dirs_per_os() {
    assert!(keyring_dirs().is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn keyring_dirs_per_os() {
    let home = atlas_duck_ipc::paths::base_dirs().unwrap().home;
    assert_eq!(keyring_dirs(), vec![home.join("Library").join("Keychains")]);
}

/// Linux: the env is set in a child process (this test binary re-run with a filter), so parallel
/// tests never race on `XDG_DATA_HOME`.
#[cfg(target_os = "linux")]
#[test]
fn keyring_dirs_per_os() {
    let exe = std::env::current_exe().unwrap();
    let run = |xdg: Option<&str>| {
        let mut c = std::process::Command::new(&exe);
        c.args([
            "keyring_dirs_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ATLAS_DUCK_KD_CHILD", "1")
        .env_remove("XDG_DATA_HOME");
        if let Some(x) = xdg {
            c.env("XDG_DATA_HOME", x);
        }
        let out = c.output().unwrap();
        assert!(
            out.status.success(),
            "child failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(Some("/xdg-data"));
    run(None);
    run(Some("relative/xdg")); // not absolute: ignored
}

#[cfg(target_os = "linux")]
#[test]
fn keyring_dirs_child() {
    if std::env::var_os("ATLAS_DUCK_KD_CHILD").is_none() {
        return;
    }
    let share = atlas_duck_ipc::paths::base_dirs()
        .unwrap()
        .home
        .join(".local")
        .join("share");
    let tail = vec![share.join("keyrings"), share.join("kwalletd")];
    let got = keyring_dirs();
    match std::env::var("XDG_DATA_HOME").as_deref() {
        Ok("/xdg-data") => {
            let mut want = vec![
                PathBuf::from("/xdg-data/keyrings"),
                PathBuf::from("/xdg-data/kwalletd"),
            ];
            want.extend(tail);
            assert_eq!(got, want);
        }
        _ => assert_eq!(got, tail),
    }
}
