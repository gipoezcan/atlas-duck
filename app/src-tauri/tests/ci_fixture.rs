//! M10 Task 27a (§13 I-45 macOS store half, PD-179): the store half of `ci/install-test-macos.sh
//! --debug-app`, run against a debug `scripted-approver` `.app` installed in `/Applications`.
//!
//! On macOS a keychain item trusts the executable that created it (ACL and partition list by
//! cdhash), so this test binary never touches the keychain itself: every entry call, while the
//! store is created, while the entries are checked and while the store is verified, goes through
//! `<installed app> __test-os-keystore <7e570000... install id>` (`ProxyKeyStore`, the
//! `os_keychain_smoke` pattern of `tests/cli_flows/harness.rs`). The creating, rewriting
//! (`head_anchor`) and reading executable is therefore always the installed debug app, and the
//! reinstall of the same artifact (same cdhash) must keep access.
//!
//! Every test is `#[ignore]`d and runs only in the `install-test-macos-debug` job (e2e-bundle.yml),
//! from the `bundle-macos-e2e-<target>` artifact.
//!
//! Interface (environment):
//! - `ATLAS_DUCK_TEST_HOME`: the canonical test home (required). The proxy gets it as its only
//!   home (it refuses to serve without it); the pinned file is this host's `paths.toml` under it,
//!   written by `ci/pinned-fixture.sh --home` before `ci_fixture_store_macos`.
//! - `ATLAS_DUCK_CI_FIXTURE_APP`: the installed app executable (default
//!   `/Applications/Atlas Duck.app/Contents/MacOS/atlas-duck-app`).
//! - `ATLAS_DUCK_CI_FIXTURE_ANCHOR_DIR`: an existing directory, the store's anchor dir
//!   (`ci_fixture_store_macos` only, required).
//! - `ATLAS_DUCK_CI_FIXTURE_MIN_STARTS`: how many `APP_START` records `ci_fixture_verify_macos`
//!   requires (default 2: the installed app ran before the removal and after the reinstall).
//!
//! Each test prints one `CI_FIXTURE_*` line on stdout (run with `--nocapture`); the script reads it.
#![cfg(all(target_os = "macos", feature = "scripted-approver"))]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use atlas_duck_app_lib::testing::os_keystore_proxy::{self, ProxyKeyStore};
use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::types::RustChosenPath;
use atlas_duck_audit::{
    EntryName, EventType, FirstRunInput, KeyStore, OpenConfig, StartupOutcome, SystemClock,
    create_new_store, new_ids, open,
};
use atlas_duck_ipc::paths::{
    BaseDirs, DataDirResolution, LocalDataDir, PinnedPaths, check_data_dir, host_name, paths_file,
    read_pinned, write_pinned,
};
use secrecy::SecretString;

const ENV_TEST_HOME: &str = "ATLAS_DUCK_TEST_HOME";
const DEFAULT_APP: &str = "/Applications/Atlas Duck.app/Contents/MacOS/atlas-duck-app";
const PASSPHRASE: &str = "correct horse battery";

fn env_path(name: &str) -> PathBuf {
    let v = std::env::var_os(name).unwrap_or_else(|| panic!("{name} is not set"));
    let p = PathBuf::from(v);
    assert!(p.is_absolute(), "{name} must be an absolute path");
    p
}

/// The test home, required to be canonical (`/private/tmp/..`, not `/tmp/..`): the proxy compares
/// it with the home `base_dirs()` resolves.
fn test_home() -> PathBuf {
    let home = env_path(ENV_TEST_HOME);
    let canon = home.canonicalize().expect("canonicalize the test home");
    assert_eq!(home, canon, "{ENV_TEST_HOME} must be canonical");
    home
}

fn app_exe() -> PathBuf {
    let app = std::env::var_os("ATLAS_DUCK_CI_FIXTURE_APP")
        .map_or_else(|| PathBuf::from(DEFAULT_APP), PathBuf::from);
    assert!(app.is_file(), "no installed app at {}", app.display());
    app
}

/// This host's pinned file under the test home (what PD-01's override makes the app read).
fn pinned(home: &Path) -> (PathBuf, PinnedPaths) {
    let base = BaseDirs {
        home: home.to_path_buf(),
        local_app_data: None,
        roaming_app_data: None,
    };
    let host = host_name().expect("host_name");
    let path = paths_file(&base, &host);
    let p = read_pinned(&path)
        .expect("read the pinned paths file")
        .unwrap_or_else(|| panic!("no pinned paths file at {}", path.display()));
    (path, p)
}

fn local(p: &PinnedPaths) -> LocalDataDir {
    match check_data_dir(&p.data_dir).expect("check_data_dir") {
        DataDirResolution::Local(d) => d,
        other => panic!(
            "{} is not a local data dir: {other:?}",
            p.data_dir.display()
        ),
    }
}

/// The lock host the installed app uses, so its own start sees our lock as this host's
/// (released) lock.
fn lock(data: &LocalDataDir) -> InstanceLock {
    let host = host_name().expect("host_name");
    InstanceLock::acquire(data, &host).expect("instance.lock (is the app still running?)")
}

/// The keystore of `install_id`, served by the installed app (cleared environment: the test home
/// and PATH only, working directory the test home).
fn proxy(home: &Path, install_id: &str) -> Arc<ProxyKeyStore> {
    let mut cmd = Command::new(app_exe());
    cmd.args([os_keystore_proxy::MARKER, install_id])
        .env_clear()
        .env(ENV_TEST_HOME, home)
        .current_dir(home);
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    Arc::new(ProxyKeyStore::spawn(cmd, install_id).expect("start the keystore proxy"))
}

fn config(ks: Arc<ProxyKeyStore>, install_id: &str) -> OpenConfig {
    let mut cfg = OpenConfig::new(Arc::new(SystemClock::new()), ks);
    cfg.pinned_install_id = Some(install_id.to_string());
    cfg
}

/// The entries a new store writes, in a fixed order for the printed line.
fn entries() -> [(&'static str, EntryName); 4] {
    [
        ("kek", EntryName::Kek),
        ("head_anchor", EntryName::HeadAnchor),
        ("first_retained_anchor", EntryName::FirstRetainedAnchor),
        ("canary", EntryName::Canary),
    ]
}

/// Creates the store in the pinned data dir under a `7e570000` test install id (the only ids the
/// proxy serves), sets the anchor dir and pins the install id.
#[test]
#[ignore = "CI: macOS debug-app install test"]
fn ci_fixture_store_macos() {
    let home = test_home();
    let (pinned_path, mut p) = pinned(&home);
    assert!(
        p.install_id.is_none(),
        "the pinned file already names an install: run ci/pinned-fixture.sh first"
    );
    assert!(
        p.data_dir.starts_with(&home),
        "the pinned data dir {} is not under the test home",
        p.data_dir.display()
    );
    let anchor_dir = env_path("ATLAS_DUCK_CI_FIXTURE_ANCHOR_DIR");
    assert!(
        anchor_dir.is_dir(),
        "{} is not a directory",
        anchor_dir.display()
    );
    let data = local(&p);
    assert!(
        !data.path().join(atlas_duck_audit::schema::DB_FILE).exists(),
        "the data dir already holds a store"
    );
    let (random, chain) = new_ids().expect("ids");
    let id = format!(
        "{}{}",
        os_keystore_proxy::TEST_INSTALL_ID_PREFIX,
        &random[..24]
    );
    assert!(os_keystore_proxy::is_test_install_id(&id), "{id}");
    let ks = proxy(&home, &id);
    {
        let lock = lock(&data);
        let first = FirstRunInput {
            install_id: id.clone(),
            chain_id: chain,
            passphrase: SecretString::from(PASSPHRASE.to_owned()),
            passphrase_confirm: SecretString::from(PASSPHRASE.to_owned()),
            archived_db: None,
            anchor_dir: Some(RustChosenPath::from_native_dialog(anchor_dir.clone())),
            archive_confirmed: None,
        };
        let store = create_new_store(&data, &lock, config(ks.clone(), &id), first)
            .expect("create_new_store");
        store.flush_head_anchor().expect("flush_head_anchor");
        store.shutdown();
    }
    let kek = ks.get(&EntryName::Kek).expect("read the kek entry");
    assert!(kek.is_some(), "no kek entry after create_new_store");
    p.install_id = Some(id.clone());
    write_pinned(&pinned_path, &p).expect("rewrite the pinned file with the install_id");
    println!(
        "CI_FIXTURE_STORE install_id={id} data_dir={} anchor_dir={} app={}",
        p.data_dir.display(),
        anchor_dir.display(),
        app_exe().display()
    );
}

/// Prints which of the install's keychain entries exist, read through the installed app. The
/// script compares the line from before the removal with the ones after it; the kek must exist.
#[test]
#[ignore = "CI: macOS debug-app install test"]
fn ci_fixture_entries_macos() {
    let home = test_home();
    let (_, p) = pinned(&home);
    let id = p
        .install_id
        .clone()
        .expect("the pinned file names no install_id (ci_fixture_store_macos first)");
    let ks = proxy(&home, &id);
    let mut line = format!("CI_FIXTURE_ENTRIES install_id={id}");
    for (name, entry) in entries() {
        let state = match ks.get(&entry) {
            Ok(Some(_)) => "present",
            Ok(None) => "absent",
            Err(e) => panic!("reading {name}: {e:?}"),
        };
        line.push_str(&format!(" {name}={state}"));
    }
    println!("{line}");
    assert!(line.contains(" kek=present"), "{line}");
}

/// After the removal/reinstall cycle: the store opens Ready through the installed app's keychain
/// access, the full verification passes, no incident is open, and the `APP_START`/`APP_STOP`
/// records alternate and end with a stop.
#[test]
#[ignore = "CI: macOS debug-app install test"]
fn ci_fixture_verify_macos() {
    let home = test_home();
    let (_, p) = pinned(&home);
    let id = p
        .install_id
        .clone()
        .expect("the pinned file names no install_id (ci_fixture_store_macos first)");
    let min_starts: usize = std::env::var("ATLAS_DUCK_CI_FIXTURE_MIN_STARTS")
        .ok()
        .map(|v| {
            v.parse()
                .expect("ATLAS_DUCK_CI_FIXTURE_MIN_STARTS is a number")
        })
        .unwrap_or(2);
    let data = local(&p);
    let lock = lock(&data);
    let ks = proxy(&home, &id);
    let store = match open(&data, &lock, config(ks, &id)).expect("open") {
        StartupOutcome::Ready { store, verify, .. } => {
            assert!(
                verify.findings.is_empty(),
                "startup verification: {:?}",
                verify.findings
            );
            store
        }
        other => panic!("expected Ready, got {other:?}"),
    };
    let incidents = store.open_incidents();
    assert!(incidents.is_empty(), "open incidents: {incidents:?}");
    let findings = store.full_verify();
    assert!(findings.is_empty(), "full verification: {findings:?}");

    let mut headers = store
        .recent_headers(Duration::from_secs(24 * 3600))
        .expect("recent_headers");
    headers.sort_by_key(|h| h.seq);
    let marks: Vec<(u64, EventType)> = headers
        .iter()
        .filter(|h| h.event_type == EventType::APP_START || h.event_type == EventType::APP_STOP)
        .map(|h| (h.seq, h.event_type))
        .collect();
    let starts = marks
        .iter()
        .filter(|(_, t)| *t == EventType::APP_START)
        .count();
    let stops = marks.len() - starts;
    let summary = marks
        .iter()
        .map(|(s, t)| {
            let n = if *t == EventType::APP_START {
                "start"
            } else {
                "stop"
            };
            format!("{s}:{n}")
        })
        .collect::<Vec<_>>()
        .join(",");
    assert!(
        starts >= min_starts,
        "{starts} APP_START records, expected at least {min_starts}: {summary}"
    );
    for (i, (seq, t)) in marks.iter().enumerate() {
        let want = if i.is_multiple_of(2) {
            EventType::APP_START
        } else {
            EventType::APP_STOP
        };
        assert!(
            *t == want,
            "record {seq} breaks the APP_START/APP_STOP pairing: {summary}"
        );
    }
    assert!(
        marks.len().is_multiple_of(2),
        "the last APP_START has no APP_STOP: {summary}"
    );
    let (head_seq, _, _) = store.head();
    store.shutdown();
    println!(
        "CI_FIXTURE_VERIFY ok install_id={id} starts={starts} stops={stops} head_seq={head_seq} findings=0 incidents=0 marks={summary}"
    );
}
