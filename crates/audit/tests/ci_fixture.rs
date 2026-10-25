//! M10 Task 27 (I-45, §12.2, §12.5, PD-179): the store half of the installed-package jobs
//! (`ci/install-test-windows.ps1`, `ci/install-test-linux.sh`). Windows and Linux only: on macOS
//! the release app's keychain items are bound to its own code signature, so a test binary cannot
//! share them (the macOS store half is T27a). Every test is `#[ignore]`d: it writes this host's
//! real OS keystore and the data dir named by the CI pinned paths file, so it runs only in the
//! install-test jobs, from the `ci-fixture-<target>` artifact that `bundle.yml` builds.
//!
//! Interface (environment):
//! - `ATLAS_DUCK_CI_FIXTURE_PINNED`: the pinned paths file `ci/pinned-fixture.*` wrote (required).
//! - `ATLAS_DUCK_CI_FIXTURE_ANCHOR_DIR`: an existing directory, the store's anchor dir
//!   (`ci_fixture_store` only, required).
//! - `ATLAS_DUCK_CI_FIXTURE_MIN_STARTS`: how many `APP_START` records `ci_fixture_verify`
//!   requires (default 2: the installed app ran before the uninstall and after the reinstall).
//!
//! Each test prints one `CI_FIXTURE_*` line on stdout (run with `--nocapture`); the scripts read it.
#![cfg(not(target_os = "macos"))]

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use atlas_duck_audit::clock::SystemClock;
use atlas_duck_audit::keystore::{EntryName, KeyStore, OsKeyStore};
use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::types::{EventType, RustChosenPath};
use atlas_duck_audit::{OpenConfig, StartupOutcome, create_new_store, new_ids, open};
use atlas_duck_ipc::paths::{
    DataDirResolution, LocalDataDir, PinnedPaths, check_data_dir, host_name, read_pinned,
    write_pinned,
};
use common::{PASSPHRASE, input};

fn env_path(name: &str) -> PathBuf {
    let v = std::env::var_os(name).unwrap_or_else(|| panic!("{name} is not set"));
    let p = PathBuf::from(v);
    assert!(p.is_absolute(), "{name} must be an absolute path");
    p
}

fn pinned() -> (PathBuf, PinnedPaths) {
    let path = env_path("ATLAS_DUCK_CI_FIXTURE_PINNED");
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

/// The lock host the installed app uses (`host_name()`), so its own start sees our lock as this
/// host's (released) lock.
fn lock(data: &LocalDataDir) -> InstanceLock {
    let host = host_name().expect("host_name");
    InstanceLock::acquire(data, &host).expect("instance.lock (is the app still running?)")
}

fn config(ks: Arc<OsKeyStore>, install_id: &str) -> OpenConfig {
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

/// Creates the store in the pinned data dir with the real OS keystore, sets the anchor dir and
/// pins the generated `install_id` (the installed app looks its entries up by it).
#[test]
#[ignore = "CI: installed-package jobs (install-tests)"]
fn ci_fixture_store() {
    let (pinned_path, mut p) = pinned();
    assert!(
        p.install_id.is_none(),
        "the pinned file already names an install: run ci/pinned-fixture first"
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
    let (id, chain) = new_ids().expect("ids");
    let ks = Arc::new(OsKeyStore::new(&id).expect("the OS keystore"));
    {
        let lock = lock(&data);
        let mut first = input(&id, &chain, PASSPHRASE, PASSPHRASE);
        first.anchor_dir = Some(RustChosenPath::from_native_dialog(anchor_dir.clone()));
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
        "CI_FIXTURE_STORE install_id={id} data_dir={} anchor_dir={}",
        p.data_dir.display(),
        anchor_dir.display()
    );
}

/// Prints which of the install's keychain entries exist. The scripts compare the line from
/// before the uninstall with the one after it; the kek must exist in both.
#[test]
#[ignore = "CI: installed-package jobs (install-tests)"]
fn ci_fixture_entries() {
    let (_, p) = pinned();
    let id = p
        .install_id
        .clone()
        .expect("the pinned file names no install_id (ci_fixture_store first)");
    let ks = OsKeyStore::new(&id).expect("the OS keystore");
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

/// After the uninstall/reinstall cycles: the store opens Ready from the pinned install, the full
/// verification passes, no incident is open, and the `APP_START`/`APP_STOP` records of the app's
/// runs alternate (every start was followed by an orderly stop before the next one).
#[test]
#[ignore = "CI: installed-package jobs (install-tests)"]
fn ci_fixture_verify() {
    let (_, p) = pinned();
    let id = p
        .install_id
        .clone()
        .expect("the pinned file names no install_id (ci_fixture_store first)");
    let min_starts: usize = std::env::var("ATLAS_DUCK_CI_FIXTURE_MIN_STARTS")
        .ok()
        .map(|v| {
            v.parse()
                .expect("ATLAS_DUCK_CI_FIXTURE_MIN_STARTS is a number")
        })
        .unwrap_or(2);
    let data = local(&p);
    let lock = lock(&data);
    let ks = Arc::new(OsKeyStore::new(&id).expect("the OS keystore"));
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
    let summary: Vec<String> = marks
        .iter()
        .map(|(s, t)| {
            let n = if *t == EventType::APP_START {
                "start"
            } else {
                "stop"
            };
            format!("{s}:{n}")
        })
        .collect();
    let summary = summary.join(",");
    assert!(
        starts >= min_starts,
        "{starts} APP_START records, expected at least {min_starts}: {summary}"
    );
    // Chained: start, stop, start, stop, ...; ends with a stop (the last run quit in order).
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
