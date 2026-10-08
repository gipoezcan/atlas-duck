//! T19: the (L)PAC ACE check, grant and start-time re-apply (section 9.4
//! Windows). The tests work on copies of an executable in fresh directories under `target/tmp`, so
//! they change no installed or built file. The copies live under
//! `target/tmp`, never under `%TEMP%`.
//!
//! CI: the `rust` job leg `windows-2022` runs this file with the rest of
//! `cargo test --workspace --locked`; read `test result: ok.` for
//! `aces_windows`.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use atlas_duck_sandbox_host::windows::{
    AceEnsure, AceStatus, WORKER_EXE_NAME, check_aces, dacl_bytes, ensure_aces, grant_aces,
    worker_ace_files, worker_ace_files_for_exe,
};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A fresh directory under `target/tmp` (cargo's `CARGO_TARGET_TMPDIR`), not
/// under `%TEMP%`: security software has blocked executables there. Removed on
/// drop, retrying because a scanner may still hold a freshly copied file.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "t19-aces-{}-{n}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("create the test dir under target/tmp");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        for _ in 0..20 {
            if std::fs::remove_dir_all(&self.0).is_ok() || !self.0.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

/// A copy of this test executable named like the worker. It stands in for
/// `atlas-duck-sandbox.exe`: any PE file has the ACL behaviour under test.
fn worker_copy(dir: &TempDir) -> PathBuf {
    let exe = dir.path().join(WORKER_EXE_NAME);
    std::fs::copy(std::env::current_exe().expect("current exe"), &exe).expect("copy exe");
    exe
}

/// The file's DACL in SDDL text, written by `icacls /save` (an independent
/// reader: `icacls` prints account names in the OS language, `/save` does not).
fn sddl_of(path: &Path) -> String {
    let out = TempDir::new();
    let saved = out.path().join("acl.txt");
    let status = Command::new("icacls")
        .arg(path)
        .arg("/save")
        .arg(&saved)
        .output()
        .expect("run icacls");
    assert!(status.status.success(), "icacls /save failed: {status:?}");
    let bytes = std::fs::read(&saved).expect("read icacls output");
    // `icacls /save` writes UTF-16LE, with or without a byte order mark.
    let body = bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(&bytes);
    if body.len() >= 2 && body[1] == 0 {
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(body).into_owned()
    }
}

/// True if the SDDL has an allow ACE for one of `sids` with read+execute
/// (`0x1200a9`, which SDDL may also spell `FRFX`).
fn has_rx_ace(sddl: &str, sids: &[&str]) -> bool {
    sddl.split('(').skip(1).any(|ace| {
        let ace = ace.split(')').next().unwrap_or("");
        let f: Vec<&str> = ace.split(';').collect();
        f.len() == 6
            && f[0] == "A"
            && sids.contains(&f[5])
            && (f[2].eq_ignore_ascii_case("0x1200a9") || f[2] == "FRFX")
    })
}

fn grant_only_all_app_packages(path: &Path) {
    let out = Command::new("icacls")
        .arg(path)
        .arg("/grant")
        .arg("*S-1-15-2-1:(RX)")
        .output()
        .expect("run icacls");
    assert!(out.status.success(), "icacls /grant failed: {out:?}");
}

#[test]
fn a_fresh_copy_lacks_the_aces_and_grant_adds_both() {
    let dir = TempDir::new();
    let exe = worker_copy(&dir);
    let files = vec![exe.clone()];

    assert_eq!(
        check_aces(&files).expect("check"),
        AceStatus::Missing(vec![exe.clone()])
    );
    let before = sddl_of(&exe);
    assert!(!has_rx_ace(&before, &["AC", "S-1-15-2-1"]), "{before}");
    assert!(!has_rx_ace(&before, &["S-1-15-2-2"]), "{before}");

    grant_aces(&files).expect("grant");

    assert_eq!(
        check_aces(&files).expect("check"),
        AceStatus::AllPresent { lpac_ready: true }
    );
    let after = sddl_of(&exe);
    assert!(has_rx_ace(&after, &["AC", "S-1-15-2-1"]), "{after}");
    assert!(has_rx_ace(&after, &["S-1-15-2-2"]), "{after}");

    // Granting again changes nothing (no duplicate ACEs).
    let bytes = dacl_bytes(&exe).expect("dacl");
    grant_aces(&files).expect("grant again");
    assert_eq!(dacl_bytes(&exe).expect("dacl"), bytes);
}

#[test]
fn only_the_all_app_packages_ace_means_appcontainer_but_not_lpac() {
    let dir = TempDir::new();
    let exe = worker_copy(&dir);
    grant_only_all_app_packages(&exe);
    assert_eq!(
        check_aces(std::slice::from_ref(&exe)).expect("check"),
        AceStatus::AllPresent { lpac_ready: false }
    );
}

#[test]
fn ensure_without_write_dac_changes_nothing_and_with_it_reapplies_once() {
    let dir = TempDir::new();
    let exe = worker_copy(&dir);
    let files = vec![exe.clone()];
    let before = dacl_bytes(&exe).expect("dacl");

    assert_eq!(
        ensure_aces(&files, Some(false)).expect("ensure"),
        AceEnsure::MissingNoWriteDac
    );
    assert_eq!(
        dacl_bytes(&exe).expect("dacl"),
        before,
        "DACL must be untouched"
    );
    assert!(matches!(
        check_aces(&files).expect("check"),
        AceStatus::Missing(_)
    ));

    assert_eq!(
        ensure_aces(&files, Some(true)).expect("ensure"),
        AceEnsure::Reapplied
    );
    assert_eq!(
        check_aces(&files).expect("check"),
        AceStatus::AllPresent { lpac_ready: true }
    );
    assert_eq!(
        ensure_aces(&files, Some(true)).expect("ensure"),
        AceEnsure::Present
    );
}

#[test]
fn ensure_probes_write_dac_on_the_handle_when_not_told() {
    // The owner of a file under target/tmp holds WRITE_DAC, so probing says yes.
    let dir = TempDir::new();
    let exe = worker_copy(&dir);
    let files = vec![exe];
    assert_eq!(
        ensure_aces(&files, None).expect("ensure"),
        AceEnsure::Reapplied
    );
    assert_eq!(
        ensure_aces(&files, None).expect("ensure"),
        AceEnsure::Present
    );
}

#[test]
fn ensure_reapplies_only_the_missing_ace() {
    let dir = TempDir::new();
    let exe = worker_copy(&dir);
    grant_only_all_app_packages(&exe);
    let files = vec![exe];
    assert_eq!(
        ensure_aces(&files, None).expect("ensure"),
        AceEnsure::Reapplied
    );
    assert_eq!(
        check_aces(&files).expect("check"),
        AceStatus::AllPresent { lpac_ready: true }
    );
}

/// `%SystemRoot%\System32`.
fn system32() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot")).join("System32")
}

#[test]
fn worker_ace_files_lists_the_exe_and_the_imported_dlls_next_to_it() {
    let dir = TempDir::new();
    let exe = worker_copy(&dir);

    // Nothing next to the exe: only the exe (system DLLs are not listed).
    assert_eq!(
        worker_ace_files(dir.path()).expect("files"),
        vec![exe.clone()]
    );
    assert_eq!(
        worker_ace_files_for_exe(&exe).expect("files"),
        vec![exe.clone()]
    );

    // Every Rust executable imports KERNEL32.dll. Put a copy next to the exe:
    // it is now a DLL "loaded from the install dir". `winmm.dll` is imported
    // by nothing here, so it must not be listed.
    std::fs::copy(
        system32().join("kernel32.dll"),
        dir.path().join("kernel32.dll"),
    )
    .expect("copy kernel32");
    std::fs::copy(system32().join("winmm.dll"), dir.path().join("winmm.dll")).expect("copy winmm");
    let files = worker_ace_files(dir.path()).expect("files");
    let names: Vec<String> = files
        .iter()
        .map(|f| {
            f.file_name()
                .expect("name")
                .to_string_lossy()
                .to_ascii_lowercase()
        })
        .collect();
    assert_eq!(
        names,
        vec![WORKER_EXE_NAME.to_string(), "kernel32.dll".to_string()]
    );
    assert_eq!(files[0], exe);
}

#[test]
fn worker_ace_files_of_a_missing_worker_is_not_found() {
    let dir = TempDir::new();
    let err = worker_ace_files(dir.path()).expect_err("no worker in the dir");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
