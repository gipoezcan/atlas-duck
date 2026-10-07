//! The worker's panic hook: a panic ends the process with `EXIT_PANIC`, from
//! inside the hook. With the release `panic = "abort"` a panic would otherwise
//! call `abort()`, whose `tgkill` the seccomp allowlist (T17) does not allow,
//! and the worker would die by SIGSYS, which T15's `score` reads as `Blocked`.

use std::process::Command;

use atlas_duck_sandbox_worker::{EXIT_PANIC, install_panic_hook};

/// Child body: install the hook, then panic. Ignored in a normal run; the
/// parent tests below start this test binary again and run it.
#[test]
#[ignore = "runs in a child process started by the panic_hook tests"]
fn child_with_hook() {
    install_panic_hook();
    panic!("worker panic");
}

/// Child body of the negative control: the same panic with no hook installed.
#[test]
#[ignore = "runs in a child process started by the panic_hook tests"]
fn child_without_hook() {
    panic!("worker panic");
}

/// Runs one ignored child test; returns its exit code and its stdout.
fn run_child(name: &str) -> (Option<i32>, String) {
    let exe = std::env::current_exe().expect("test binary path");
    let out = Command::new(exe)
        .args(["--ignored", "--exact", name, "--test-threads=1"])
        .output()
        .expect("child");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn a_panic_with_the_hook_exits_with_the_panic_code_before_libtest_reports() {
    assert_eq!(EXIT_PANIC, 101);
    let (code, stdout) = run_child("child_with_hook");
    assert_eq!(code, Some(EXIT_PANIC), "stdout:\n{stdout}");
    assert!(
        !stdout.contains("test result"),
        "the hook must end the process inside the panic; stdout:\n{stdout}"
    );
}

/// Negative control: without the hook the child reaches libtest's summary
/// (and also exits with 101), so the check above is not satisfied by libtest.
#[test]
fn a_panic_without_the_hook_reaches_the_libtest_summary() {
    let (code, stdout) = run_child("child_without_hook");
    assert_eq!(code, Some(101), "stdout:\n{stdout}");
    assert!(stdout.contains("test result: FAILED"), "stdout:\n{stdout}");
}
