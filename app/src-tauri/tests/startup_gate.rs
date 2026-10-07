//! Startup gate (T10): §7.7 data-dir check, §3.1 `instance.lock`, error states.
//!
//! Every test drives `gate_in` with an explicit pinned-file path under a temporary fake
//! home, because `base_dirs()` never follows the test's environment (§7.7 Path stability).
//!
//! `Diag::init()` installs a process-wide subscriber. Exactly one test
//! (`local_pinned_dir_is_ready_and_attach_writes_the_log`) attaches a data dir to it. Every
//! other test passes the buffered `Diag` to `apply_startup_state` and must leave the disk
//! untouched.
//!
//! The NFS/SMB tests are env-gated (`ATLAS_DUCK_TEST_NFS_DIR`, `ATLAS_DUCK_TEST_SMB_DIR`) and
//! run in CI job `locality-mounts`, which sets `ATLAS_DUCK_REQUIRE_MOUNT_TESTS=1` so a
//! missing variable fails there instead of skipping.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use atlas_duck_app_lib::diag::Diag;
use atlas_duck_app_lib::startup::{
    ErrorPresenter, LOG_FIELDS, MSG_DATA_DIR_NOT_FOUND, MSG_DATA_DIR_NOT_LOCAL,
    MSG_DATA_DIR_UNUSABLE, MSG_PINNED_UNREADABLE, MSG_RUNNING_ON_OTHER_HOST, StartupAction,
    StartupState, apply_startup_state, gate, gate_in, render_message, startup_message,
    this_host_pinned_file,
};
use atlas_duck_app_lib::state::StartupSummary;
use atlas_duck_audit::lock::{INSTANCE_LOCK_FILE, InstanceLock};
use atlas_duck_ipc::paths::{
    BaseDirs, DataDirResolution, LocalDataDir, PINNED_SCHEMA_VERSION, PinnedError, PinnedPaths,
    check_data_dir, paths_file, read_pinned, write_pinned,
};

const HOST: &str = "thishost";

/// Test double for the native dialog: records every text it is asked to show.
#[derive(Default)]
struct FakePresenter {
    shown: Mutex<Vec<String>>,
}

impl FakePresenter {
    fn shown(&self) -> Vec<String> {
        self.shown.lock().expect("presenter lock").clone()
    }
}

impl ErrorPresenter for FakePresenter {
    fn show(&self, text: &str) {
        self.shown
            .lock()
            .expect("presenter lock")
            .push(text.to_owned());
    }
}

/// A fake home whose pinned-file location follows the real T05 layout for this OS.
struct FakeHome {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    base: BaseDirs,
}

impl FakeHome {
    fn new() -> FakeHome {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();
        let base = BaseDirs {
            home: root.clone(),
            local_app_data: Some(root.join("AppData").join("Local")),
            roaming_app_data: Some(root.join("AppData").join("Roaming")),
        };
        FakeHome {
            _tmp: tmp,
            root,
            base,
        }
    }

    fn pinned_file(&self) -> PathBuf {
        paths_file(&self.base, HOST)
    }

    /// Writes this host's pinned file (creating its parent folder) and returns its path.
    fn pin(&self, data_dir: &Path) -> PathBuf {
        let file = self.pinned_file();
        std::fs::create_dir_all(file.parent().expect("pinned file has a parent"))
            .expect("create pinned dir");
        let pinned = PinnedPaths {
            schema_version: PINNED_SCHEMA_VERSION,
            data_dir: data_dir.to_path_buf(),
            config_dir: data_dir.to_path_buf(),
            install_id: None,
        };
        write_pinned(&file, &pinned).expect("write_pinned");
        file
    }

    /// Runs the gate the way `setup` does: read this host's pinned file, then gate.
    fn run_gate(&self) -> StartupState {
        let file = self.pinned_file();
        gate_in(&file, read_pinned(&file), HOST)
    }
}

/// Every file and directory below `dir`, relative, `/`-separated, sorted.
fn tree(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("dir entry");
            let rel = entry
                .path()
                .strip_prefix(base)
                .expect("under base")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push(rel);
            if entry.file_type().expect("file type").is_dir() {
                walk(base, &entry.path(), out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

fn local(dir: &Path) -> LocalDataDir {
    match check_data_dir(dir).expect("check_data_dir") {
        DataDirResolution::Local(data) => data,
        _ => panic!("{} is not a local data dir", dir.display()),
    }
}

/// Path from an env var, or `None` with a loud skip. Under
/// ATLAS_DUCK_REQUIRE_MOUNT_TESTS=1 a missing variable is a failure.
#[cfg(unix)]
fn gated_dir(var: &str) -> Option<PathBuf> {
    match std::env::var_os(var) {
        Some(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => {
            let required =
                std::env::var_os("ATLAS_DUCK_REQUIRE_MOUNT_TESTS").is_some_and(|v| v == "1");
            assert!(
                !required,
                "{var} is unset but ATLAS_DUCK_REQUIRE_MOUNT_TESTS=1"
            );
            eprintln!("SKIPPED: {var} is unset; this test runs in CI job `locality-mounts`");
            None
        }
    }
}

fn buffered_diag() -> &'static Diag {
    Diag::init()
}

// ---------- message texts ----------

#[test]
fn message_templates_are_the_spec_texts_and_the_plan_placeholders() {
    assert_eq!(MSG_DATA_DIR_NOT_FOUND, "data directory <path> not found");
    assert_eq!(
        MSG_RUNNING_ON_OTHER_HOST,
        "atlas-duck is running on another machine (<host>) with this data directory"
    );
    // Spec silent: plan placeholders awaiting user confirmation.
    assert_eq!(
        MSG_DATA_DIR_NOT_LOCAL,
        "data directory <path> is not on a local filesystem"
    );
    assert_eq!(
        MSG_PINNED_UNREADABLE,
        "atlas-duck path settings <path> could not be read"
    );
    assert_eq!(
        MSG_DATA_DIR_UNUSABLE,
        "data directory <path> could not be opened"
    );
    assert_eq!(LOG_FIELDS, ["startup_state"]);
}

#[test]
fn render_message_substitutes_once_and_never_rescans_the_value() {
    assert_eq!(
        render_message(MSG_RUNNING_ON_OTHER_HOST, "otherhost"),
        "atlas-duck is running on another machine (otherhost) with this data directory"
    );
    assert_eq!(
        render_message(MSG_DATA_DIR_NOT_FOUND, "/mnt/gone"),
        "data directory /mnt/gone not found"
    );
    // The value contains the other placeholder: it stays literal.
    assert_eq!(
        render_message("a <path> b <host>", "<host>"),
        "a <host> b <host>"
    );
    assert_eq!(render_message("no placeholder", "x"), "no placeholder");
}

// ---------- before first run ----------

#[test]
fn no_pinned_file_is_before_first_run_and_writes_nothing() {
    let home = FakeHome::new();
    let presenter = FakePresenter::default();

    let state = home.run_gate();
    assert!(matches!(state, StartupState::BeforeFirstRun), "{state:?}");
    let action = apply_startup_state(&state, buffered_diag(), &presenter);

    assert_eq!(action, StartupAction::Stay);
    assert!(presenter.shown().is_empty(), "no dialog before first run");
    assert_eq!(
        tree(&home.root),
        Vec::<String>::new(),
        "nothing under the fake home"
    );
    assert_eq!(state.summary(), Some(StartupSummary::BeforeFirstRun));
}

#[test]
fn gate_wrapper_uses_this_hosts_pinned_file_for_the_error_path() {
    // `gate` itself only reads base_dirs(); it writes nothing.
    let state = gate(Ok(None), HOST);
    assert!(matches!(state, StartupState::BeforeFirstRun), "{state:?}");

    let state = gate(Err(PinnedError::Parse), HOST);
    match state {
        StartupState::PinnedUnreadable { path } => assert_eq!(path, this_host_pinned_file(HOST)),
        other => panic!("expected PinnedUnreadable, got {other:?}"),
    }
}

// ---------- missing data dir ----------

#[test]
fn removed_pinned_data_dir_is_missing_and_nothing_is_recreated() {
    let home = FakeHome::new();
    let parent = tempfile::tempdir().expect("tempdir");
    let gone = parent.path().join("gone-data");
    let file = home.pin(&gone);
    let pinned_bytes = std::fs::read(&file).expect("read pinned");
    let presenter = FakePresenter::default();

    let state = home.run_gate();
    match &state {
        StartupState::DataDirMissing { path } => assert_eq!(path, &gone),
        other => panic!("expected DataDirMissing, got {other:?}"),
    }
    let action = apply_startup_state(&state, buffered_diag(), &presenter);

    assert_eq!(action, StartupAction::Stay);
    assert_eq!(
        presenter.shown(),
        vec![format!("data directory {} not found", gone.display())]
    );
    assert!(!gone.exists(), "the data dir must not be recreated");
    assert_eq!(
        tree(parent.path()),
        Vec::<String>::new(),
        "no logs/, webview/ or instance.lock"
    );
    assert_eq!(
        std::fs::read(&file).expect("read pinned"),
        pinned_bytes,
        "pinned file untouched"
    );
    assert_eq!(state.summary(), Some(StartupSummary::DataDirMissing));
}

#[test]
fn pinned_path_that_is_a_file_is_missing_not_ready() {
    let home = FakeHome::new();
    let parent = tempfile::tempdir().expect("tempdir");
    let not_a_dir = parent.path().join("data-is-a-file");
    std::fs::write(&not_a_dir, b"x").expect("write file");
    home.pin(&not_a_dir);

    let state = home.run_gate();
    assert!(
        matches!(state, StartupState::DataDirMissing { .. }),
        "{state:?}"
    );
    assert_eq!(tree(parent.path()), vec!["data-is-a-file".to_owned()]);
}

// ---------- not local ----------

#[cfg(windows)]
#[test]
fn unc_pinned_path_is_not_local_and_nothing_is_written() {
    // The UNC prefix is refused from the path text alone (T06), so this needs no share
    // and never touches the network.
    for unc in [
        r"\\atlas-duck-test-server\share\data",
        r"\\?\UNC\atlas-duck-test-server\share\data",
    ] {
        let home = FakeHome::new();
        let unc = PathBuf::from(unc);
        let file = home.pin(&unc);
        let pinned_bytes = std::fs::read(&file).expect("read pinned");
        let presenter = FakePresenter::default();

        let state = home.run_gate();
        match &state {
            StartupState::DataDirNotLocal { path, .. } => assert_eq!(path, &unc),
            other => panic!(
                "expected DataDirNotLocal for {}, got {other:?}",
                unc.display()
            ),
        }
        let action = apply_startup_state(&state, buffered_diag(), &presenter);

        assert_eq!(action, StartupAction::Stay);
        assert_eq!(
            presenter.shown(),
            vec![format!(
                "data directory {} is not on a local filesystem",
                unc.display()
            )]
        );
        assert_eq!(std::fs::read(&file).expect("read pinned"), pinned_bytes);
        assert_eq!(state.summary(), Some(StartupSummary::DataDirNotLocal));
    }
}

#[cfg(unix)]
#[test]
fn network_mounts_are_refused_without_taking_the_lock_or_writing() {
    for var in ["ATLAS_DUCK_TEST_NFS_DIR", "ATLAS_DUCK_TEST_SMB_DIR"] {
        let Some(mount_dir) = gated_dir(var) else {
            continue;
        };
        let home = FakeHome::new();
        home.pin(&mount_dir);
        let before = tree(&mount_dir);
        let presenter = FakePresenter::default();

        let state = home.run_gate();
        assert!(
            matches!(state, StartupState::DataDirNotLocal { .. }),
            "{var}: expected DataDirNotLocal, got {state:?}"
        );
        let action = apply_startup_state(&state, buffered_diag(), &presenter);

        assert_eq!(action, StartupAction::Stay, "{var}");
        assert_eq!(presenter.shown().len(), 1, "{var}: the error is shown once");
        assert_eq!(
            tree(&mount_dir),
            before,
            "{var}: listing unchanged, no instance.lock"
        );
        assert!(!mount_dir.join(INSTANCE_LOCK_FILE).exists(), "{var}");
        assert!(!mount_dir.join("logs").exists(), "{var}");
    }
}

#[cfg(unix)]
#[test]
fn symlink_into_a_network_mount_is_refused() {
    let Some(mount_dir) = gated_dir("ATLAS_DUCK_TEST_NFS_DIR") else {
        return;
    };
    let home = FakeHome::new();
    let links = tempfile::tempdir().expect("tempdir");
    let link = links.path().join("looks-local");
    std::os::unix::fs::symlink(&mount_dir, &link).expect("symlink");
    home.pin(&link);
    let before = tree(&mount_dir);

    let state = home.run_gate();
    assert!(
        matches!(state, StartupState::DataDirNotLocal { .. }),
        "{state:?}"
    );
    assert_eq!(tree(&mount_dir), before);
}

// ---------- unreadable pinned file ----------

#[test]
fn corrupt_pinned_file_is_unreadable_never_before_first_run() {
    let corrupt: [(&str, &[u8]); 5] = [
        (
            "broken toml",
            b"data_dir = [unterminated\nconfig_dir = = =\n",
        ),
        ("invalid utf-8", &[0x66, 0xff, 0xfe, 0x00, 0x80]),
        // Hand-edited or damaged values that would resolve against the process's current
        // directory. T05 `read_pinned` gives `Err(Parse)`; these are relative on every OS.
        (
            "relative data_dir",
            b"schema_version = 1\ndata_dir = 'atlas-duck-relative-data-dir-probe'\nconfig_dir = 'atlas-duck-relative-data-dir-probe'\n",
        ),
        (
            "empty data_dir",
            b"schema_version = 1\ndata_dir = ''\nconfig_dir = 'atlas-duck-relative-data-dir-probe'\n",
        ),
        (
            "drive-relative data_dir",
            b"schema_version = 1\ndata_dir = 'C:atlas-duck-relative-data-dir-probe'\nconfig_dir = 'C:atlas-duck-relative-data-dir-probe'\n",
        ),
    ];
    // The gate must not resolve a relative pinned dir against the current directory.
    let probe = Path::new("atlas-duck-relative-data-dir-probe");
    assert!(
        !probe.exists(),
        "stale probe folder in the current directory"
    );
    for (name, bytes) in corrupt {
        let home = FakeHome::new();
        let file = home.pinned_file();
        std::fs::create_dir_all(file.parent().expect("parent")).expect("create pinned dir");
        std::fs::write(&file, bytes).expect("write corrupt pinned file");
        let tree_before = tree(&home.root);
        let presenter = FakePresenter::default();

        let state = home.run_gate();
        match &state {
            StartupState::PinnedUnreadable { path } => assert_eq!(path, &file, "{name}"),
            other => panic!("{name}: expected PinnedUnreadable, got {other:?}"),
        }
        let action = apply_startup_state(&state, buffered_diag(), &presenter);

        assert_eq!(action, StartupAction::Stay, "{name}");
        assert_eq!(
            presenter.shown(),
            vec![format!(
                "atlas-duck path settings {} could not be read",
                file.display()
            )],
            "{name}: shown exactly once"
        );
        assert_eq!(
            std::fs::read(&file).expect("read"),
            bytes,
            "{name}: byte-identical"
        );
        assert_eq!(
            tree(&home.root),
            tree_before,
            "{name}: no data dir, logs/ or lock created"
        );
        assert_eq!(
            state.summary(),
            Some(StartupSummary::PinnedUnreadable),
            "{name}"
        );
    }
    assert!(
        !probe.exists(),
        "a relative pinned dir was resolved against the current directory"
    );
}

// ---------- non-UTF-8 paths ----------

#[cfg(unix)]
#[test]
fn non_utf8_data_dir_cannot_be_pinned_and_the_next_start_is_before_first_run() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let home = FakeHome::new();
    let bad = PathBuf::from(OsString::from_vec(b"/data/caf\xe9-\xff".to_vec()));
    let pinned = PinnedPaths {
        schema_version: PINNED_SCHEMA_VERSION,
        data_dir: bad.clone(),
        config_dir: bad.clone(),
        install_id: None,
    };

    // Explicit error, never a lossy conversion; nothing is created, not even the folder.
    match write_pinned(&home.pinned_file(), &pinned) {
        Err(PinnedError::NonUtf8Path(path)) => assert_eq!(path, bad),
        other => panic!("expected NonUtf8Path, got {other:?}"),
    }
    assert_eq!(tree(&home.root), Vec::<String>::new());
    assert!(matches!(home.run_gate(), StartupState::BeforeFirstRun));
}

// ---------- ready ----------

#[test]
fn local_pinned_dir_is_ready_and_attach_writes_the_log() {
    let home = FakeHome::new();
    let data_tmp = tempfile::tempdir().expect("tempdir");
    home.pin(data_tmp.path());
    let presenter = FakePresenter::default();

    let state = home.run_gate();
    assert!(matches!(state, StartupState::Ready { .. }), "{state:?}");

    // The lock file exists and is the only thing written so far. (On Windows the file
    // cannot be opened while this process holds it with share mode 0, so its content is
    // read after the lock is released below.)
    assert!(data_tmp.path().join(INSTANCE_LOCK_FILE).exists());
    assert_eq!(tree(data_tmp.path()), vec![INSTANCE_LOCK_FILE.to_owned()]);

    let action = apply_startup_state(&state, buffered_diag(), &presenter);

    assert_eq!(action, StartupAction::Stay);
    assert!(presenter.shown().is_empty());
    assert_eq!(state.summary(), Some(StartupSummary::Ready));
    let listing = tree(data_tmp.path());
    assert!(listing.contains(&"logs".to_owned()), "{listing:?}");
    assert!(listing.contains(&"logs/diag.log".to_owned()), "{listing:?}");
    assert!(
        !listing.iter().any(|p| p.starts_with("webview")),
        "{listing:?}"
    );
    let log =
        std::fs::read_to_string(data_tmp.path().join("logs").join("diag.log")).expect("diag.log");
    assert!(log.contains("startup_state=ready"), "diag.log was:\n{log}");

    // Releasing the lock makes the record readable on every OS: this host and this pid.
    drop(state);
    let lock_text =
        std::fs::read_to_string(data_tmp.path().join(INSTANCE_LOCK_FILE)).expect("instance.lock");
    assert_eq!(
        lock_text,
        format!("{{\"host\":\"{HOST}\",\"pid\":{}}}\n", std::process::id())
    );
}

#[test]
fn non_ascii_pinned_dir_is_ready() {
    let home = FakeHome::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp
        .path()
        .join("J\u{fc}rgen \u{d6}z \u{30c7}\u{30fc}\u{30bf}");
    std::fs::create_dir(&data).expect("create non-ASCII data dir");
    home.pin(&data);

    let state = home.run_gate();
    match &state {
        StartupState::Ready { data: ready, .. } => assert_eq!(ready.path(), data.as_path()),
        other => panic!("expected Ready, got {other:?}"),
    }
    assert!(data.join(INSTANCE_LOCK_FILE).exists());
}

#[test]
fn pinned_dir_longer_than_260_characters_is_ready() {
    // On Windows this is longer than MAX_PATH; elsewhere it is simply a deep path.
    let home = FakeHome::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp
        .path()
        .join("a".repeat(100))
        .join("b".repeat(100))
        .join("c".repeat(100));
    assert!(
        data.as_os_str().len() > 260,
        "path is only {} long",
        data.as_os_str().len()
    );
    std::fs::create_dir_all(&data).expect("create long data dir");
    home.pin(&data);

    let state = home.run_gate();
    match &state {
        StartupState::Ready { data: ready, .. } => assert_eq!(ready.path(), data.as_path()),
        other => panic!("expected Ready, got {other:?}"),
    }
    assert!(std::fs::metadata(data.join(INSTANCE_LOCK_FILE)).is_ok());
}

// ---------- instance.lock ----------

#[test]
fn second_instance_is_refused_and_names_another_host_where_the_record_is_readable() {
    let home = FakeHome::new();
    let data_tmp = tempfile::tempdir().expect("tempdir");
    home.pin(data_tmp.path());
    let holder = InstanceLock::acquire(&local(data_tmp.path()), "otherhost").expect("holder");
    let tree_before = tree(data_tmp.path());

    let state = home.run_gate();
    let presenter = FakePresenter::default();
    let action = apply_startup_state(&state, buffered_diag(), &presenter);

    assert!(
        presenter.shown().is_empty(),
        "the exit path shows the text, not the presenter"
    );
    assert_eq!(
        tree(data_tmp.path()),
        tree_before,
        "a refused instance writes nothing"
    );
    if cfg!(unix) {
        // Unix: flock leaves the record readable, so the host is known.
        match &state {
            StartupState::AlreadyRunning { other_host } => {
                assert_eq!(other_host.as_deref(), Some("otherhost"));
            }
            other => panic!("expected AlreadyRunning, got {other:?}"),
        }
        let text = "atlas-duck is running on another machine (otherhost) with this data directory";
        assert_eq!(startup_message(&state).as_deref(), Some(text));
        assert_eq!(
            action,
            StartupAction::Exit {
                message: Some(text.to_owned())
            }
        );
        let record =
            std::fs::read_to_string(data_tmp.path().join(INSTANCE_LOCK_FILE)).expect("record");
        assert_eq!(
            record,
            format!(
                "{{\"host\":\"otherhost\",\"pid\":{}}}\n",
                std::process::id()
            )
        );
    } else {
        // Windows: share mode 0 makes the record unreadable (known spec limitation), so
        // the other host cannot be named.
        match &state {
            StartupState::AlreadyRunning { other_host } => assert_eq!(other_host, &None),
            other => panic!("expected AlreadyRunning, got {other:?}"),
        }
        assert_eq!(action, StartupAction::Exit { message: None });
    }
    assert_eq!(state.summary(), None);

    // Releasing the lock lets the next start through.
    drop(holder);
    assert!(matches!(home.run_gate(), StartupState::Ready { .. }));
}

#[test]
fn second_instance_on_the_same_host_exits_without_a_message() {
    let home = FakeHome::new();
    let data_tmp = tempfile::tempdir().expect("tempdir");
    home.pin(data_tmp.path());
    let _holder = InstanceLock::acquire(&local(data_tmp.path()), HOST).expect("holder");

    let state = home.run_gate();
    match &state {
        StartupState::AlreadyRunning { other_host } => assert_eq!(other_host, &None),
        other => panic!("expected AlreadyRunning, got {other:?}"),
    }
    assert_eq!(startup_message(&state), None);
    let action = apply_startup_state(&state, buffered_diag(), &FakePresenter::default());
    assert_eq!(action, StartupAction::Exit { message: None });
}

#[cfg(unix)]
#[test]
fn unwritable_data_dir_is_unusable_and_stays_unchanged() {
    use std::os::unix::fs::PermissionsExt;

    let home = FakeHome::new();
    let data_tmp = tempfile::tempdir().expect("tempdir");
    let data = data_tmp.path().join("readonly-data");
    std::fs::create_dir(&data).expect("create data dir");
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    if std::fs::File::create(data.join("probe")).is_ok() {
        // Running as root: permissions do not apply, so this case cannot be provoked.
        eprintln!("SKIPPED: this user can write to a 0555 directory (root)");
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        return;
    }
    home.pin(&data);
    let presenter = FakePresenter::default();

    let state = home.run_gate();
    let action = apply_startup_state(&state, buffered_diag(), &presenter);
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    match &state {
        StartupState::DataDirUnusable { path } => assert_eq!(path, &data),
        other => panic!("expected DataDirUnusable, got {other:?}"),
    }
    assert_eq!(action, StartupAction::Stay);
    assert_eq!(
        presenter.shown(),
        vec![format!(
            "data directory {} could not be opened",
            data.display()
        )]
    );
    assert_eq!(tree(&data), Vec::<String>::new());
    assert_eq!(state.summary(), Some(StartupSummary::DataDirUnusable));
}
