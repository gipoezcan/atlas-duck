//! §7.7 Panics / §13 Security (Panics): the payload never reaches the
//! diagnostic log or stderr. Child-process cases re-run this test binary
//! with `ATLAS_DUCK_PANIC_CHILD=<mode>` and only the `child_entry` test.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use atlas_duck_app_lib::diag::{self, Diag, LOG_DIR_NAME, PANIC_CATEGORY_APP, scan_logs_for};
use atlas_duck_ipc::paths::{DataDirResolution, LocalDataDir, check_data_dir};

const CHILD_ENV: &str = "ATLAS_DUCK_PANIC_CHILD";
const DATA_ENV: &str = "ATLAS_DUCK_PANIC_DATA";
const SENTINEL: &str = "SENTINEL-PANIC";

fn local(path: &Path) -> LocalDataDir {
    match check_data_dir(path).expect("check_data_dir") {
        DataDirResolution::Local(d) => d,
        _ => panic!("temp dir is not a local data dir"),
    }
}

/// Entry point of the child process. A no-op in a normal test run.
#[test]
fn child_entry() {
    let Ok(mode) = std::env::var(CHILD_ENV) else {
        return;
    };
    let diag = Diag::init();
    diag::install_panic_hook(PANIC_CATEGORY_APP);
    // The test crate's own target is `panic_hook`, which the target filter
    // would drop; log under an atlas_duck target as the app's code does.
    tracing::info!(
        target: "atlas_duck_app_lib::panic_hook_test",
        op_id = "jira.search",
        jql = "SENTINEL-PANIC-JQL",
        "SENTINEL-PANIC-MSG"
    );
    // A dependency's event with allowlisted names: dropped through the real
    // process-wide subscriber (the scan below finds no SENTINEL-PANIC).
    tracing::info!(
        target: "zbus",
        reason = "SENTINEL-PANIC-FOREIGN",
        peer_exe = "SENTINEL-PANIC-FOREIGN-EXE"
    );
    match mode.as_str() {
        "attach" => {
            let data = PathBuf::from(std::env::var_os(DATA_ENV).expect("data dir env"));
            diag.attach_dir(&local(&data)).expect("attach_dir");
        }
        "before_attach" | "init_only" => {}
        _ => std::process::exit(90),
    }
    if mode == "init_only" {
        std::process::exit(0);
    }
    let worker = std::thread::Builder::new()
        .name("worker-x".to_owned())
        .spawn(|| {
            panic!("SENTINEL-PANIC-{}", 42);
        })
        .expect("spawn");
    // Mirror release `panic = "abort"`: the process ends non-zero after the hook ran.
    let code = if worker.join().is_err() { 101 } else { 91 };
    std::process::exit(code);
}

struct ChildDirs {
    _root: tempfile::TempDir,
    root: PathBuf,
    data: PathBuf,
}

fn child_dirs() -> ChildDirs {
    let root_dir = tempfile::tempdir().expect("tempdir");
    let root = root_dir.path().to_path_buf();
    for d in ["data", "home", "cwd", "tmp"] {
        fs::create_dir(root.join(d)).expect("mkdir");
    }
    ChildDirs {
        data: root.join("data"),
        root,
        _root: root_dir,
    }
}

fn run_child(mode: &str, dirs: &ChildDirs) -> Output {
    let home = dirs.root.join("home");
    let tmp = dirs.root.join("tmp");
    let mut cmd = Command::new(std::env::current_exe().expect("current_exe"));
    // `--nocapture`: a payload printed by a broken hook must reach the real stderr.
    cmd.args(["child_entry", "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, mode)
        .env(DATA_ENV, &dirs.data)
        .env("RUST_BACKTRACE", "full")
        .current_dir(dirs.root.join("cwd"));
    for k in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
    ] {
        cmd.env(k, &home);
    }
    for k in ["TMP", "TEMP", "TMPDIR"] {
        cmd.env(k, &tmp);
    }
    cmd.output().expect("run child")
}

/// Every path under `root`, relative, sorted.
fn tree(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).expect("read_dir") {
            let p = e.expect("entry").path();
            out.push(
                p.strip_prefix(root)
                    .expect("prefix")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
            if p.is_dir() {
                stack.push(p);
            }
        }
    }
    out.sort();
    out
}

fn assert_no_sentinel_in_stdio(out: &Output) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains(SENTINEL), "sentinel on stdout:\n{stdout}");
    assert!(!stderr.contains(SENTINEL), "sentinel on stderr:\n{stderr}");
}

#[test]
fn panic_payload_reaches_neither_log_nor_stdio() {
    let dirs = child_dirs();
    let out = run_child("attach", &dirs);
    assert_eq!(
        out.status.code(),
        Some(101),
        "child status {:?}",
        out.status
    );
    assert_no_sentinel_in_stdio(&out);

    let logs = dirs.data.join(LOG_DIR_NAME);
    assert_eq!(
        scan_logs_for(&logs, &[SENTINEL]).expect("scan"),
        Vec::<PathBuf>::new()
    );
    let log = fs::read_to_string(logs.join("diag.log")).expect("diag.log");
    let panic_lines: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("category=app_panic"))
        .collect();
    assert_eq!(panic_lines.len(), 1, "{log}");
    assert!(panic_lines[0].contains("thread=worker-x"), "{log}");
    assert!(panic_lines[0].contains(&format!("{}:", file!())), "{log}");
    assert!(
        log.contains("op_id=jira.search"),
        "buffered line flushed on attach: {log}"
    );
}

#[test]
fn panic_before_attach_creates_nothing() {
    let dirs = child_dirs();
    let out = run_child("before_attach", &dirs);
    assert_eq!(
        out.status.code(),
        Some(101),
        "child status {:?}",
        out.status
    );
    assert_no_sentinel_in_stdio(&out);
    assert_eq!(tree(&dirs.root), ["cwd", "data", "home", "tmp"]);
}

#[test]
fn init_alone_creates_nothing() {
    let dirs = child_dirs();
    let out = run_child("init_only", &dirs);
    assert_eq!(out.status.code(), Some(0), "child status {:?}", out.status);
    assert_eq!(tree(&dirs.root), ["cwd", "data", "home", "tmp"]);
}

#[test]
fn in_process_panic_on_named_thread_logs_location_thread_and_category() {
    let data = tempfile::tempdir().expect("tempdir");
    let diag = Diag::init();
    diag.attach_dir(&local(data.path())).expect("attach_dir");
    diag::install_panic_hook(PANIC_CATEGORY_APP);

    let expected = std::thread::Builder::new()
        .name("worker-x".to_owned())
        .spawn(|| {
            let line = line!() + 2;
            let r = std::panic::catch_unwind(|| {
                panic!("SENTINEL-PANIC-{}", 42);
            });
            assert!(r.is_err());
            format!("{}:{}", file!(), line)
        })
        .expect("spawn")
        .join()
        .expect("join");
    // Restore the default hook for the remaining tests in this binary.
    let _ = std::panic::take_hook();

    let logs = data.path().join(LOG_DIR_NAME);
    let log = fs::read_to_string(logs.join("diag.log")).expect("diag.log");
    let panic_lines: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("category=app_panic"))
        .collect();
    assert_eq!(panic_lines.len(), 1, "{log}");
    assert!(panic_lines[0].contains(&format!(" {expected} ")), "{log}");
    assert!(panic_lines[0].contains("thread=worker-x"), "{log}");
    assert_eq!(
        scan_logs_for(&logs, &[SENTINEL]).expect("scan"),
        Vec::<PathBuf>::new()
    );
}

/// Review focus: the hook and the diagnostic log belong to the GUI path
/// only; `__cli` is dispatched before them and keeps its normal stdio.
#[test]
fn cli_mode_keeps_its_stdio() {
    let out = Command::new(env!("CARGO_BIN_EXE_atlas-duck-app"))
        .args(["__cli", "bogus"])
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .output()
        .expect("run atlas-duck-app __cli");
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(stdout.contains("\"usage\""), "{stdout}");
}
