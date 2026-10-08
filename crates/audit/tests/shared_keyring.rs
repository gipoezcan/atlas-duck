//! I-43 (shared home, keyring half) and I-44 (concurrent shared keyring, keyring on a network
//! mount) against a real Secret Service. Linux only, every test `#[ignore]`d: `ci/shared-keyring.sh`
//! runs the phases in order with the daemon restarts between them (§8.6, §13).
//!
//! `ATLAS_DUCK_SHARED_STATE` is a local directory that outlives the test processes: the phases
//! leave their data dirs and `state.json` there. Install ids are random 32-hex ids, so a
//! leftover keyring entry of an aborted run can never be mistaken for another run's.
#![cfg(target_os = "linux")]

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;

use atlas_duck_audit::clock::SystemClock;
use atlas_duck_audit::error::OpenError;
use atlas_duck_audit::keystore::{EntryName, KeyStore, KeyStoreError, KeyringLocality, OsKeyStore};
use atlas_duck_audit::types::EventType;
use atlas_duck_audit::{
    LockedReason, OpenConfig, StartupOutcome, Store, create_new_store, new_ids, open,
};
use atlas_duck_ipc::paths::{
    DataDirResolution, LocalDataDir, PinnedPaths, check_data_dir, read_pinned, write_pinned,
};
use common::*;
use serde_json::{Value, json};

const IGNORE: &str = "needs the Secret Service of ci/shared-keyring.sh";
const HOST: &str = "testhost";

fn shared_state() -> PathBuf {
    let dir = PathBuf::from(
        std::env::var_os("ATLAS_DUCK_SHARED_STATE").expect("ATLAS_DUCK_SHARED_STATE is not set"),
    );
    assert!(
        dir.is_absolute(),
        "ATLAS_DUCK_SHARED_STATE must be absolute"
    );
    std::fs::create_dir_all(&dir).expect("create the shared state dir");
    dir
}

fn local_dir(path: &Path) -> LocalDataDir {
    std::fs::create_dir_all(path).expect("create data dir");
    match check_data_dir(path).expect("check_data_dir") {
        DataDirResolution::Local(d) => d,
        _ => panic!("{} is not a local directory", path.display()),
    }
}

fn config(ks: &Arc<OsKeyStore>, install_id: &str) -> OpenConfig {
    let mut cfg = OpenConfig::new(Arc::new(SystemClock::new()), ks.clone());
    cfg.pinned_install_id = Some(install_id.to_string());
    cfg
}

fn entries() -> Vec<EntryName> {
    vec![
        EntryName::Kek,
        EntryName::HeadAnchor,
        EntryName::FirstRetainedAnchor,
        EntryName::Canary,
        EntryName::Pat("inst-1".into()),
    ]
}

/// Deletes the install's entries when dropped, unless `keep` (phase 1 of I-44 hands them to
/// phase 2).
struct Wipe {
    ks: Arc<OsKeyStore>,
    keep: bool,
}

impl Drop for Wipe {
    fn drop(&mut self) {
        if !self.keep {
            for e in entries() {
                let _ = self.ks.delete(&e);
            }
        }
    }
}

struct Install {
    id: String,
    chain: String,
    data: LocalDataDir,
    lock: atlas_duck_audit::lock::InstanceLock,
    ks: Arc<OsKeyStore>,
}

impl Install {
    fn new(data_path: &Path) -> Install {
        let (id, chain) = new_ids().expect("ids");
        Install::existing(data_path, &id, &chain)
    }

    fn existing(data_path: &Path, id: &str, chain: &str) -> Install {
        let data = local_dir(data_path);
        let lock = atlas_duck_audit::lock::InstanceLock::acquire(&data, HOST).expect("lock");
        let ks = Arc::new(OsKeyStore::new(id).expect("secret service store"));
        Install {
            id: id.to_string(),
            chain: chain.to_string(),
            data,
            lock,
            ks,
        }
    }

    fn create(&self) -> Store {
        create_new_store(
            &self.data,
            &self.lock,
            config(&self.ks, &self.id),
            input(&self.id, &self.chain, PASSPHRASE, PASSPHRASE),
        )
        .expect("create_new_store")
    }

    fn open_ready(&self) -> Store {
        match open(&self.data, &self.lock, config(&self.ks, &self.id)).expect("open") {
            StartupOutcome::Ready { store, verify, .. } => {
                assert!(verify.findings.is_empty(), "{:?}", verify.findings);
                assert!(store.open_incidents().is_empty(), "VERIFY incident");
                store
            }
            // `Locked(KeychainLost)` is the "keychain_lost" this test must never see.
            other => panic!("expected Ready, got {other:?}"),
        }
    }
}

fn append_some(store: &Store, tag: &str, n: usize) {
    for i in 0..n {
        store
            .append(ev(EventType::APP_START, None, json!({ "t": tag, "i": i })))
            .expect("append");
        if i % 10 == 9 {
            store.flush_head_anchor().expect("flush_head_anchor");
        }
    }
    store.flush_head_anchor().expect("flush_head_anchor");
}

fn pat(n: &str) -> Vec<u8> {
    format!("pat-{n}").into_bytes()
}

#[test]
#[ignore = "needs the Secret Service of ci/shared-keyring.sh"]
fn i43_shared_home_sequential() {
    let _ = IGNORE;
    let root = shared_state().join("i43");
    let _ = std::fs::remove_dir_all(&root);
    let config_dir = root.join("config");
    std::fs::create_dir_all(&config_dir).expect("config dir");

    let a = Install::new(&root.join("data-a"));
    let b = Install::new(&root.join("data-b"));
    let _wipe_a = Wipe {
        ks: a.ks.clone(),
        keep: false,
    };
    let _wipe_b = Wipe {
        ks: b.ks.clone(),
        keep: false,
    };
    assert_ne!(a.id, b.id);

    // One shared config dir, one pinned file per host name, each naming only its own install.
    let pin = |host: &str, i: &Install| {
        let path = config_dir.join(format!("paths-{host}.toml"));
        write_pinned(
            &path,
            &PinnedPaths {
                schema_version: 1,
                data_dir: i.data.path().to_path_buf(),
                config_dir: config_dir.clone(),
                install_id: Some(i.id.clone()),
            },
        )
        .expect("write_pinned");
        path
    };
    let pin_a = pin("host-a", &a);
    let pin_b = pin("host-b", &b);

    // First run A, first run B, restart A, restart B.
    let sa = a.create();
    append_some(&sa, "a", 12);
    a.ks.set(&EntryName::Pat("inst-1".into()), &pat("a"))
        .expect("set pat a");
    sa.shutdown();
    let sb = b.create();
    append_some(&sb, "b", 12);
    sb.shutdown();
    let sa = a.open_ready();
    sa.shutdown();
    let sb = b.open_ready();
    sb.shutdown();

    // Each install's entries exist only under its own install_id.
    let kek_a = a.ks.get(&EntryName::Kek).expect("get").expect("kek a");
    let kek_b = b.ks.get(&EntryName::Kek).expect("get").expect("kek b");
    assert_ne!(kek_a.as_slice(), kek_b.as_slice());
    assert_eq!(
        a.ks.get(&EntryName::Pat("inst-1".into()))
            .expect("get")
            .expect("pat a")
            .as_slice(),
        pat("a").as_slice()
    );
    assert_eq!(
        b.ks.get(&EntryName::Pat("inst-1".into())).expect("get"),
        None,
        "a Pat set by A must be absent for B"
    );
    // A third handle for B's id sees the same: the isolation is the entry name, not the handle.
    let b2 = OsKeyStore::new(&b.id).expect("store");
    assert_eq!(b2.get(&EntryName::Pat("inst-1".into())).expect("get"), None);

    for (path, mine, other) in [(&pin_a, &a, &b), (&pin_b, &b, &a)] {
        let text = std::fs::read_to_string(path).expect("pinned file");
        assert!(text.contains(&mine.id), "{text}");
        assert!(!text.contains(&other.id), "{text}");
        let read = read_pinned(path).expect("read_pinned").expect("present");
        assert_eq!(read.install_id.as_deref(), Some(mine.id.as_str()));
        assert_eq!(read.data_dir, mine.data.path());
    }
    println!("i43 ok: {} / {}", a.id, b.id);
}

fn state_json() -> PathBuf {
    shared_state().join("state.json")
}

#[test]
#[ignore = "needs the Secret Service of ci/shared-keyring.sh"]
fn i44_concurrent_phase1() {
    let root = shared_state().join("i44");
    let _ = std::fs::remove_file(state_json());
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("i44 dir");

    let run = |n: u32| {
        let data_path = root.join(format!("data-{n}"));
        thread::spawn(move || {
            let inst = Install::new(&data_path);
            let _keep = Wipe {
                ks: inst.ks.clone(),
                keep: true,
            };
            let store = inst.create();
            for i in 0..200 {
                store
                    .append(ev(EventType::APP_START, None, json!({ "n": n, "i": i })))
                    .expect("append");
                if i % 10 == 9 {
                    store.flush_head_anchor().expect("flush_head_anchor");
                }
                // Interleave the two threads' keyring traffic with their appends.
                if i % 50 == 0 {
                    thread::yield_now();
                }
            }
            store.flush_head_anchor().expect("flush_head_anchor");
            inst.ks
                .set(&EntryName::Pat("inst-1".into()), &pat(&n.to_string()))
                .expect("set pat");
            store.shutdown();
            (inst.id.clone(), inst.chain.clone(), data_path)
        })
    };
    let (t1, t2) = (run(1), run(2));
    let r1 = t1.join().expect("thread 1");
    let r2 = t2.join().expect("thread 2");
    assert_ne!(r1.0, r2.0);
    let state: Vec<Value> = [r1, r2]
        .iter()
        .enumerate()
        .map(|(i, (id, chain, path))| {
            json!({ "n": i + 1, "install_id": id, "chain_id": chain, "data_dir": path })
        })
        .collect();
    std::fs::write(
        state_json(),
        serde_json::to_vec_pretty(&json!({ "installs": state })).expect("json"),
    )
    .expect("write state.json");
}

/// `(n, install_id, chain_id, data_dir)` of the installs of phase 1.
fn read_state() -> Vec<(u64, String, String, PathBuf)> {
    let text = std::fs::read_to_string(state_json()).expect("state.json (run phase 1 first)");
    let v: Value = serde_json::from_str(&text).expect("state.json parses");
    v["installs"]
        .as_array()
        .expect("installs")
        .iter()
        .map(|e| {
            let s = |k: &str| e[k].as_str().expect(k).to_string();
            (
                e["n"].as_u64().expect("n"),
                s("install_id"),
                s("chain_id"),
                PathBuf::from(s("data_dir")),
            )
        })
        .collect()
}

#[test]
#[ignore = "needs the Secret Service of ci/shared-keyring.sh"]
fn i44_concurrent_phase2() {
    let state = read_state();
    assert_eq!(state.len(), 2);
    for (n, id, chain, data_dir) in state {
        let inst = Install::existing(&data_dir, &id, &chain);
        let _wipe = Wipe {
            ks: inst.ks.clone(),
            keep: false,
        };
        let store = inst.open_ready();
        assert_eq!(store.head().2, chain);
        store.shutdown();
        let got = inst
            .ks
            .get(&EntryName::Pat("inst-1".into()))
            .expect("get")
            .expect("pat survived the daemon restart");
        assert_eq!(got.as_slice(), pat(&n.to_string()).as_slice());
        for e in [
            EntryName::Kek,
            EntryName::HeadAnchor,
            EntryName::FirstRetainedAnchor,
        ] {
            assert!(inst.ks.get(&e).expect("get").is_some(), "{e:?} missing");
        }
    }
}

/// Every file and dir under `dir` with size, mtime and content.
type Snapshot = Vec<(String, bool, u64, SystemTime, Vec<u8>)>;

fn snapshot(dir: &Path) -> Snapshot {
    fn walk(base: &Path, dir: &Path, out: &mut Snapshot) {
        let mut names: Vec<PathBuf> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").path())
            .collect();
        names.sort();
        for p in names {
            let md = std::fs::symlink_metadata(&p).expect("metadata");
            let rel = p.strip_prefix(base).expect("prefix").display().to_string();
            let bytes = if md.is_file() {
                std::fs::read(&p).expect("read")
            } else {
                Vec::new()
            };
            out.push((
                rel,
                md.is_dir(),
                md.len(),
                md.modified().expect("mtime"),
                bytes,
            ));
            if md.is_dir() {
                walk(base, &p, out);
            }
        }
    }
    let mut out = Vec::new();
    let md = std::fs::metadata(dir).expect("dir metadata");
    out.push((
        String::new(),
        true,
        md.len(),
        md.modified().expect("mtime"),
        Vec::new(),
    ));
    walk(dir, dir, &mut out);
    out
}

#[test]
#[ignore = "needs ATLAS_DUCK_TEST_NFS_DIR, XDG_DATA_HOME=<nfs>/xdg and the Secret Service of ci/shared-keyring.sh"]
fn i44_keyring_on_nfs_refused() {
    let nfs = PathBuf::from(
        std::env::var_os("ATLAS_DUCK_TEST_NFS_DIR").expect("ATLAS_DUCK_TEST_NFS_DIR is not set"),
    );
    let xdg = nfs.join("xdg");
    assert_eq!(
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from),
        Some(xdg.clone()),
        "XDG_DATA_HOME must be <nfs>/xdg"
    );
    let keyrings = xdg.join("keyrings");
    let before = snapshot(&keyrings);
    assert!(
        before.len() > 1,
        "the script plants a sentinel file in {keyrings:?}"
    );

    // `OsKeyStore::new` talks to the bus once (a daemon with a local XDG_DATA_HOME answers);
    // everything below must be refused on the path check, before any entry is read or written.
    let (id, chain) = new_ids().expect("ids");
    let ks = Arc::new(OsKeyStore::new(&id).expect("secret service store"));
    match ks.locality() {
        KeyringLocality::NotLocal { dir } => assert!(dir.starts_with(&nfs), "{dir:?}"),
        other => panic!("expected NotLocal, got {other:?}"),
    }

    let dir = shared_state().join("i44-nfs");
    let _ = std::fs::remove_dir_all(&dir);
    let data = local_dir(&dir);
    let lock = atlas_duck_audit::lock::InstanceLock::acquire(&data, HOST).expect("lock");
    match create_new_store(
        &data,
        &lock,
        config(&ks, &id),
        input(&id, &chain, PASSPHRASE, PASSPHRASE),
    ) {
        Err(OpenError::KeyStore(KeyStoreError::NotLocal)) => {}
        Ok(_) => panic!("create_new_store succeeded on a keyring on NFS"),
        Err(e) => panic!("expected KeyStore(NotLocal), got {e:?}"),
    }
    drop(lock);

    // The store of phase 1, pinned to a local data dir: open refuses with keyring_not_local.
    let (n, sid, schain, sdata) = read_state().remove(0);
    let inst = Install::existing(&sdata, &sid, &schain);
    // Same install, but the keyring dirs are the ones of this process: <nfs>/xdg/keyrings.
    match open(&inst.data, &inst.lock, config(&inst.ks, &sid)).expect("open") {
        StartupOutcome::Locked(LockedReason::KeyringNotLocal) => {}
        other => panic!("install {n}: expected Locked(KeyringNotLocal), got {other:?}"),
    }

    assert_eq!(snapshot(&keyrings), before, "the NFS keyrings dir changed");
}
