//! §2.5 crash-artifact settings and the M1 part of the §13 process-hardening test (T09).
//!
//! Tests that change process-wide state run in a child: this test binary re-executed with
//! `ATLAS_DUCK_CRASH_CHILD=<role>` and `--exact child_entry --nocapture`.
//!
//! CI: the Linux memory-read test runs in the `rust` job leg `ubuntu-22.04` (read
//! `non_dumpable_child_memory_is_unreadable_by_same_uid_parent ... ok` in its `cargo test` log).
//! The WER test runs in the `windows-2022` leg (`wer_excludes_both_executables_for_current_user`).
//!
//! The WER tests write the registry (HKCU WER `ExcludedApplications`). They run only when
//! `ATLAS_DUCK_RUN_WER_TEST=1` (set by CI); otherwise they print `SKIPPED` and pass without
//! touching the registry. When they do run, they remove only the values they added and leave any
//! pre-existing exclusion in place.

use std::io::Write;
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use atlas_duck_app_lib::startup::crash::{
    CrashSettingsReport, WEBVIEW_DIR_NAME, WER_EXCLUDED_EXES, applied_report,
    apply_process_crash_settings, clear_crashpad_reports, exclude_from_wer,
    redirect_stderr_to_null, set_non_dumpable, webview_data_dir,
};
use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};

const CHILD_ENV: &str = "ATLAS_DUCK_CRASH_CHILD";
const TOKEN_ENV: &str = "ATLAS_DUCK_CRASH_TOKEN";
const WER_TEST_ENV: &str = "ATLAS_DUCK_RUN_WER_TEST";

/// Serializes the tests that add and remove the WER registry values.
static WER_REGISTRY: Mutex<()> = Mutex::new(());

/// True when the tests that write the WER registry values may run.
fn wer_tests_enabled() -> bool {
    std::env::var(WER_TEST_ENV).is_ok_and(|v| v == "1")
}

/// Child roles. Returns immediately in a normal test run.
#[test]
fn child_entry() {
    let Ok(role) = std::env::var(CHILD_ENV) else {
        return;
    };
    match role.as_str() {
        "stderr" => {
            eprintln!("CONTROL-BEFORE-REDIRECT");
            redirect_stderr_to_null().expect("redirect_stderr_to_null");
            eprintln!("SENTINEL-STDERR");
            let _ = std::io::stderr().write_all(b"SENTINEL-STDERR-WRITE-ALL\n");
            raw_fd2_write(b"SENTINEL-STDERR-FD2\n");
            std::process::exit(0);
        }
        "apply" => {
            let report = apply_process_crash_settings();
            assert_eq!(applied_report(), Some(&report));
            eprintln!("SENTINEL-STDERR-AFTER-APPLY");
            // libtest has already printed "test child_entry ... " without a newline, so every
            // marker line starts on a fresh line.
            println!(
                "\nREPORT stderr_null={} wer_excluded={:?} non_dumpable={:?}",
                report.stderr_null, report.wer_excluded, report.non_dumpable
            );
            std::process::exit(0);
        }
        "nondumpable" | "control" => {
            if role == "nondumpable" {
                set_non_dumpable().expect("set_non_dumpable");
            }
            let token = std::env::var(TOKEN_ENV).expect("token env");
            let secret: Box<[u8]> = token.into_bytes().into_boxed_slice();
            println!("\nADDR={:x} LEN={}", secret.as_ptr() as usize, secret.len());
            std::io::stdout().flush().expect("flush");
            // Wait until the parent closes our stdin.
            let mut sink = Vec::new();
            let _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut sink);
            std::hint::black_box(&secret);
            std::process::exit(0);
        }
        other => panic!("unknown child role {other}"),
    }
}

#[cfg(unix)]
fn raw_fd2_write(bytes: &[u8]) {
    // SAFETY: writes a valid buffer to descriptor 2.
    unsafe { libc::write(2, bytes.as_ptr().cast(), bytes.len()) };
}

#[cfg(windows)]
fn raw_fd2_write(bytes: &[u8]) {
    // SAFETY: writes a valid buffer to CRT descriptor 2.
    unsafe { libc::write(2, bytes.as_ptr().cast(), bytes.len() as libc::c_uint) };
}

fn child(role: &str) -> Command {
    let mut cmd = Command::new(std::env::current_exe().expect("current_exe"));
    cmd.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, role);
    cmd
}

#[test]
fn stderr_redirect_reaches_null_device() {
    let out = child("stderr")
        .stdin(Stdio::null())
        .output()
        .expect("spawn child");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "child failed: {stderr}");
    // The control line proves the pipe worked before the redirect; nothing after it arrives.
    assert_eq!(
        stderr.trim_end(),
        "CONTROL-BEFORE-REDIRECT",
        "stderr was: {stderr:?}"
    );
    assert!(!stderr.contains("SENTINEL"));
}

#[test]
fn apply_reports_per_os_and_silences_stderr() {
    // On Windows the child adds the WER registry values, so it runs only where those are wanted.
    if cfg!(windows) && !wer_tests_enabled() {
        eprintln!("SKIPPED: writes the WER registry values; set {WER_TEST_ENV}=1 to run");
        return;
    }
    let _guard = WER_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let _cleanup = WerCleanup::new();
    let out = child("apply")
        .stdin(Stdio::null())
        .output()
        .expect("spawn child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "child failed: {stdout} {stderr}");
    assert!(stderr.is_empty(), "stderr was: {stderr:?}");
    let line = stdout
        .lines()
        .find(|l| l.starts_with("REPORT "))
        .expect("REPORT line");
    let expected = CrashSettingsReport {
        stderr_null: true,
        wer_excluded: if cfg!(windows) { Some(true) } else { None },
        non_dumpable: if cfg!(target_os = "linux") {
            Some(true)
        } else {
            None
        },
    };
    assert_eq!(
        line,
        format!(
            "REPORT stderr_null={} wer_excluded={:?} non_dumpable={:?}",
            expected.stderr_null, expected.wer_excluded, expected.non_dumpable
        )
    );
}

#[test]
fn constants_match_spec() {
    assert_eq!(
        WER_EXCLUDED_EXES,
        ["atlas-duck-app.exe", "atlas-duck-sandbox.exe"]
    );
    assert_eq!(WEBVIEW_DIR_NAME, "webview");
}

#[test]
fn off_platform_calls_are_unsupported() {
    if !cfg!(target_os = "linux") {
        let err = set_non_dumpable().expect_err("not Linux");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
    if !cfg!(windows) {
        let err = exclude_from_wer().expect_err("not Windows");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}

#[test]
fn webview_dir_is_data_join_webview() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let DataDirResolution::Local(local) = check_data_dir(tmp.path()).expect("check") else {
        panic!("temp dir is not local");
    };
    assert_eq!(webview_data_dir(&local), local.path().join("webview"));
}

#[test]
fn crashpad_reports_are_cleared_and_counted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let webview = tmp.path().join("webview");
    let crashpad = webview.join("EBWebView").join("Crashpad");
    let reports = crashpad.join("reports");
    std::fs::create_dir_all(&reports).expect("mkdir");
    std::fs::write(reports.join("a.dmp"), b"MDMP").expect("write dump");
    std::fs::write(crashpad.join("settings.dat"), b"x").expect("write settings");

    assert_eq!(clear_crashpad_reports(&webview).expect("clear"), 1);
    assert!(!reports.join("a.dmp").exists());
    assert!(reports.is_dir(), "the reports folder itself is kept");
    assert!(
        crashpad.join("settings.dat").exists(),
        "only reports/ is cleared"
    );
    assert_eq!(clear_crashpad_reports(&webview).expect("second clear"), 0);
}

#[test]
fn crashpad_clear_on_absent_dirs_creates_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let webview = tmp.path().join("webview");
    assert_eq!(clear_crashpad_reports(&webview).expect("clear"), 0);
    assert!(!webview.exists(), "no webview dir may be created");

    std::fs::create_dir(&webview).expect("mkdir webview");
    assert_eq!(clear_crashpad_reports(&webview).expect("clear"), 0);
    assert!(
        !webview.join("EBWebView").exists(),
        "no EBWebView dir may be created"
    );
}

// ---------------------------------------------------------------- Windows WER

/// §15 V30: the key was confirmed on a Windows 11 dev box on 2026-10-07. The value name is the
/// executable name and the data is `REG_DWORD 0x1`.
#[cfg(windows)]
const WER_KEY: &str =
    r"HKCU\Software\Microsoft\Windows\Windows Error Reporting\ExcludedApplications";

/// Removes the values the test (or the "apply" child) added. Values that existed before the
/// guard was created (a developer's own exclusions) are left alone.
struct WerCleanup {
    /// Names of `WER_EXCLUDED_EXES` that were already excluded when the guard was created.
    #[cfg(windows)]
    pre_existing: Vec<&'static str>,
}

impl WerCleanup {
    fn new() -> WerCleanup {
        WerCleanup {
            #[cfg(windows)]
            pre_existing: WER_EXCLUDED_EXES
                .into_iter()
                .filter(|name| reg_value(name).is_some())
                .collect(),
        }
    }
}

impl Drop for WerCleanup {
    fn drop(&mut self) {
        #[cfg(windows)]
        for name in WER_EXCLUDED_EXES {
            use windows_sys::Win32::System::ErrorReporting::WerRemoveExcludedApplication;
            if self.pre_existing.contains(&name) {
                continue;
            }
            let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: NUL-terminated UTF-16 string that outlives the call.
            unsafe { WerRemoveExcludedApplication(wide.as_ptr(), 0) };
        }
    }
}

#[cfg(windows)]
fn reg_value(name: &str) -> Option<String> {
    let out = Command::new("reg")
        .args(["query", WER_KEY, "/v", name])
        .output()
        .expect("run reg.exe");
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(windows)]
#[test]
fn wer_excludes_both_executables_for_current_user() {
    if !wer_tests_enabled() {
        eprintln!("SKIPPED: writes the WER registry values; set {WER_TEST_ENV}=1 to run");
        return;
    }
    let _guard = WER_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let cleanup = WerCleanup::new();
    let pre_existing = cleanup.pre_existing.clone();
    exclude_from_wer().expect("exclude_from_wer");
    for name in WER_EXCLUDED_EXES {
        let out = reg_value(name).unwrap_or_else(|| panic!("no value {name} under {WER_KEY}"));
        let line = out
            .lines()
            .find(|l| l.trim_start().starts_with(name))
            .unwrap_or_else(|| panic!("value line missing: {out}"));
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields, [name, "REG_DWORD", "0x1"], "reg output: {out}");
    }
    drop(cleanup);
    for name in WER_EXCLUDED_EXES {
        if pre_existing.contains(&name) {
            assert!(
                reg_value(name).is_some(),
                "cleanup removed pre-existing {name}"
            );
        } else {
            assert!(reg_value(name).is_none(), "cleanup left {name}");
        }
    }
}

// ------------------------------------------------- Linux memory-read hardening

#[cfg(target_os = "linux")]
struct MemChild {
    child: std::process::Child,
    addr: usize,
    token: String,
}

#[cfg(target_os = "linux")]
impl MemChild {
    fn spawn(role: &str) -> MemChild {
        let token = format!("ATLAS-DUCK-MEMREAD-{role}-{}", std::process::id());
        let mut child = child(role)
            .env(TOKEN_ENV, &token)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn child");
        let stdout = child.stdout.take().expect("stdout");
        let mut addr = None;
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("read child stdout");
            if let Some(rest) = line.strip_prefix("ADDR=") {
                let hex = rest.split_whitespace().next().expect("addr");
                addr = Some(usize::from_str_radix(hex, 16).expect("hex addr"));
                break;
            }
        }
        MemChild {
            child,
            addr: addr.expect("child printed no ADDR line"),
            token,
        }
    }

    fn pid(&self) -> libc::pid_t {
        libc::pid_t::try_from(self.child.id()).expect("pid fits")
    }

    fn process_vm_read(&self) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.token.len()];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: self.addr as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // SAFETY: `local` describes our own writable buffer; `remote` is only interpreted by the
        // kernel in the child's address space.
        let n = unsafe { libc::process_vm_readv(self.pid(), &local, 1, &remote, 1, 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        buf.truncate(usize::try_from(n).expect("non-negative"));
        Ok(buf)
    }

    fn proc_mem_read(&self) -> std::io::Result<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        let file = std::fs::File::open(format!("/proc/{}/mem", self.pid()))?;
        let mut buf = vec![0u8; self.token.len()];
        file.read_exact_at(&mut buf, self.addr as u64)?;
        Ok(buf)
    }
}

#[cfg(target_os = "linux")]
impl Drop for MemChild {
    fn drop(&mut self) {
        drop(self.child.stdin.take()); // EOF -> the child exits
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "linux")]
fn ptrace_scope() -> String {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "absent".to_owned())
}

/// §13 Security "Process hardening" (M1 part). The parent is a same-uid ancestor of the child, so
/// the Yama `ptrace_scope` default of 1 allows the control read; only the dumpable flag differs.
#[cfg(target_os = "linux")]
#[test]
fn non_dumpable_child_memory_is_unreadable_by_same_uid_parent() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        // Root with CAP_SYS_PTRACE bypasses the dumpable check, so the test would prove nothing.
        eprintln!("SKIPPED: running as root; run this test as an unprivileged user");
        return;
    }
    let scope = ptrace_scope();

    let control = MemChild::spawn("control");
    let read = control.process_vm_read().unwrap_or_else(|e| {
        panic!("control process_vm_readv failed ({e}); yama ptrace_scope={scope}")
    });
    assert_eq!(read, control.token.as_bytes(), "control process_vm_readv");
    let read = control
        .proc_mem_read()
        .unwrap_or_else(|e| panic!("control /proc/<pid>/mem failed ({e}); ptrace_scope={scope}"));
    assert_eq!(read, control.token.as_bytes(), "control /proc/<pid>/mem");
    drop(control);

    let hardened = MemChild::spawn("nondumpable");
    let err = hardened
        .process_vm_read()
        .expect_err("process_vm_readv on a non-dumpable process must fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EPERM),
        "process_vm_readv: {err}"
    );
    let err = hardened
        .proc_mem_read()
        .expect_err("/proc/<pid>/mem on a non-dumpable process must fail");
    assert!(
        matches!(err.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM)),
        "/proc/<pid>/mem: {err}"
    );
}
