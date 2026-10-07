//! Linux confinement of the worker (§9.4), applied by the worker to itself on
//! its main thread before it reads stdin.
//!
//! Order (§9.4): `tzset()` plus one `localtime_r` call, `PR_SET_NO_NEW_PRIVS`,
//! Landlock with no rules, seccomp-bpf in default-kill mode. Before `tzset`
//! the signal mask inherited from the spawner thread is cleared.
//!
//! * Landlock and seccomp filters apply to the calling thread and the threads
//!   it creates later, so [`apply`] refuses to run when the process has more
//!   than one thread (`EBUSY`) and changes nothing in that case. The worker
//!   creates no threads (§9.3), so the check passes in the real worker.
//! * Landlock is an extra layer (§9.4): a kernel without it, or a container
//!   whose seccomp profile hides it, leaves `landlock_abi: None` and is not an
//!   error. Network blocking relies on seccomp, not on Landlock.
//! * seccomp is the floor. The allowlist lives in `seccomp_allowlist.rs`.
//!   `SeccompFilter` has one match action per filter, so three filters are
//!   installed. The kernel runs all of them and takes the most severe verdict
//!   (`KILL_PROCESS` over `ERRNO` over `ALLOW`):
//!   1. `open*` -> `EACCES`, allow everything else,
//!   2. `clone3` -> `ENOSYS`, allow everything else,
//!   3. allow [`ALLOWED`] and the errno names, kill everything else.
//!
//!   The kill filter goes last on purpose: installing a filter takes
//!   `prctl` and `seccomp` calls, which the kill filter does not allow.
//!
//! Crate choice (research.json has no facts on seccomp or Landlock crates):
//! `seccompiler` 0.5.0 (rust-vmm, used by Firecracker; compiles the BPF
//! program in pure Rust), `landlock` 0.4.7 (the Landlock project's own crate,
//! best-effort compatibility across ABIs) and `syscalls` 0.8.1 (name to number
//! tables for x86_64 and aarch64, so the allowlist is written with names and
//! its review test checks both architectures on any build host).

use std::collections::BTreeMap;
use std::io;
use std::str::FromStr;

use atlas_duck_ipc::sandbox::probe::ConfinementReport;
use landlock::{
    ABI, Access, AccessFs, AccessNet, LandlockStatus, Ruleset, RulesetAttr, RulesetStatus, Scope,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch, apply_filter,
};

use super::seccomp_allowlist::{ALLOWED, ARCH_OPTIONAL, ERRNO_EACCES, ERRNO_ENOSYS, Rule};

/// The `mechanism` string when Landlock is enforced as well.
const MECHANISM_SECCOMP_LANDLOCK: &str = "seccomp+landlock";
/// The `mechanism` string when only seccomp is enforced.
const MECHANISM_SECCOMP: &str = "seccomp";
/// The `mechanism` string when nothing was applied.
const MECHANISM_NONE: &str = "none";

fn unapplied() -> ConfinementReport {
    ConfinementReport {
        applied: false,
        mechanism: MECHANISM_NONE.to_owned(),
        no_new_privs: None,
        landlock_abi: None,
        seccomp: None,
        lpac: None,
        os_error: None,
    }
}

fn errno_of(e: &io::Error) -> Option<i64> {
    e.raw_os_error().map(i64::from)
}

/// Applies the §9.4 Linux confinement to the calling thread.
///
/// Never returns an error: a step that fails is reported in the returned
/// [`ConfinementReport`] (`applied: false`, `os_error`) so that the worker
/// still sends `probe.ready` and the host scores the floor as not met.
pub(super) fn apply() -> ConfinementReport {
    let mut report = unapplied();

    match thread_count() {
        Ok(1) => {}
        Ok(_) => {
            report.os_error = Some(i64::from(libc::EBUSY));
            return report;
        }
        Err(e) => {
            report.os_error = errno_of(&e).or(Some(-1));
            return report;
        }
    }

    reset_signal_mask();
    init_time_zone();

    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) takes no pointers.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        report.no_new_privs = Some(false);
        report.os_error = errno_of(&io::Error::last_os_error());
        return report;
    }
    report.no_new_privs = Some(true);

    report.landlock_abi = apply_landlock();

    conclude(report, install_seccomp())
}

/// Folds the seccomp result into the report. `Err` carries the errno of the
/// failed install (`None` when the failure has none, e.g. a filter that does
/// not compile).
fn conclude(mut report: ConfinementReport, seccomp: Result<(), Option<i64>>) -> ConfinementReport {
    match seccomp {
        Ok(()) => {
            report.applied = true;
            report.seccomp = Some(true);
            report.mechanism = if report.landlock_abi.is_some() {
                MECHANISM_SECCOMP_LANDLOCK
            } else {
                MECHANISM_SECCOMP
            }
            .to_owned();
        }
        Err(errno) => {
            report.applied = false;
            report.seccomp = Some(false);
            report.os_error = errno.or(Some(-1));
        }
    }
    report
}

/// Number of threads in this process, from `/proc/self/task`. It is read before
/// anything is confined, because confinement makes `open*` fail.
fn thread_count() -> io::Result<usize> {
    let mut n = 0;
    for entry in std::fs::read_dir("/proc/self/task")? {
        entry?;
        n += 1;
    }
    Ok(n)
}

/// Empties the signal mask of the main thread. The spawner thread of the host
/// (T16) forks the worker, and `execve` keeps the mask of the forking thread,
/// so a mask set there would reach the worker. Best effort: a failure is not
/// worth a failed confinement, because `KILL_PROCESS` ignores the mask.
/// `SIGPIPE` stays ignored: Rust's runtime sets `SIG_IGN` at start-up, so a
/// closed pipe gives `EPIPE` and the worker exits with `EXIT_IO`.
fn reset_signal_mask() {
    // SAFETY: `set` is initialised by `sigemptyset` before `pthread_sigmask`
    // reads it, and the old-set pointer is null.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::pthread_sigmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
    }
}

unsafe extern "C" {
    /// POSIX `tzset`; the `libc` crate does not declare it.
    fn tzset();
}

/// Initialises libc's time-zone state from `TZ=UTC0` before `open*` is blocked
/// (§3.4, §9.4), so QuickJS's local-time `Date` methods never need
/// `/etc/localtime`.
fn init_time_zone() {
    // SAFETY: `tzset` has no preconditions. `localtime_r` writes only into the
    // local `tm`, and `time(NULL)` takes a null pointer.
    unsafe {
        tzset();
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&now, &mut tm);
    }
}

/// Landlock handling every filesystem right of the running ABI, plus the
/// network rights (ABI 4) and the scopes (ABI 6) where the kernel has them,
/// with no rules: nothing is allowed. Best effort. Returns the kernel's ABI
/// version when a ruleset is enforced, `None` otherwise.
fn apply_landlock() -> Option<u32> {
    let abi = ABI::V9;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .ok()?
        .handle_access(AccessNet::from_all(abi))
        .ok()?
        .scope(Scope::from_all(abi))
        .ok()?
        .create()
        .ok()?
        .restrict_self()
        .ok()?;
    let enforced = matches!(
        status.ruleset,
        RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced
    );
    match status.landlock {
        LandlockStatus::Available {
            effective_abi,
            kernel_abi,
        } if enforced => Some(kernel_abi.map_or(effective_abi as u32, |v| v as u32)),
        _ => None,
    }
}

/// The syscall number of `name` on `arch`; `None` for a name in
/// [`ARCH_OPTIONAL`] that this architecture lacks.
fn number(arch: TargetArch, name: &str) -> Result<Option<i64>, String> {
    let found = match arch {
        TargetArch::x86_64 => syscalls::x86_64::Sysno::from_str(name)
            .ok()
            .map(|s| i64::from(s.id())),
        TargetArch::aarch64 => syscalls::aarch64::Sysno::from_str(name)
            .ok()
            .map(|s| i64::from(s.id())),
        other => return Err(format!("no syscall table for {other:?}")),
    };
    match found {
        Some(nr) => Ok(Some(nr)),
        None if ARCH_OPTIONAL.contains(&name) => Ok(None),
        None => Err(format!("unknown syscall `{name}` on {arch:?}")),
    }
}

/// The three BPF programs for `arch`, in installation order: the two errno
/// filters first, the default-kill filter last (see the module comment).
fn build_programs(arch: TargetArch) -> Result<Vec<BpfProgram>, String> {
    fn text<E: ToString>(e: E) -> String {
        e.to_string()
    }

    let mut allow: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for (name, rule) in ALLOWED {
        let Some(nr) = number(arch, name)? else {
            continue;
        };
        let rules = match rule {
            Rule::Any => Vec::new(),
            Rule::Arg0In(fds) => fds
                .iter()
                .map(|fd| {
                    SeccompCondition::new(
                        0,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Eq,
                        u64::from(*fd),
                    )
                    .and_then(|c| SeccompRule::new(vec![c]))
                    .map_err(text)
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        allow.insert(nr, rules);
    }

    let (eacces, eacces_numbers) = errno_program(arch, ERRNO_EACCES, libc::EACCES)?;
    let (enosys, enosys_numbers) = errno_program(arch, ERRNO_ENOSYS, libc::ENOSYS)?;
    // The kill filter lets the errno names through; the errno filters answer them.
    for nr in eacces_numbers.into_iter().chain(enosys_numbers) {
        allow.insert(nr, Vec::new());
    }
    let kill = SeccompFilter::new(
        allow,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        arch,
    )
    .map_err(text)?;
    let kill = BpfProgram::try_from(kill).map_err(text)?;
    Ok(vec![eacces, enosys, kill])
}

/// A filter that allows everything except `names`, which return `errno`.
fn errno_program(
    arch: TargetArch,
    names: &[&str],
    errno: i32,
) -> Result<(BpfProgram, Vec<i64>), String> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let mut numbers = Vec::new();
    for name in names {
        if let Some(nr) = number(arch, name)? {
            rules.insert(nr, Vec::new());
            numbers.push(nr);
        }
    }
    let errno = u32::try_from(errno).map_err(|e| e.to_string())?;
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(errno),
        arch,
    )
    .map_err(|e| e.to_string())?;
    let program = BpfProgram::try_from(filter).map_err(|e| e.to_string())?;
    Ok((program, numbers))
}

/// The build architecture's [`TargetArch`], or an error for any other.
fn host_arch() -> Result<TargetArch, String> {
    TargetArch::try_from(std::env::consts::ARCH).map_err(|e| e.to_string())
}

fn install_seccomp() -> Result<(), Option<i64>> {
    let programs = host_arch()
        .and_then(build_programs)
        .map_err(|_| None::<i64>)?;
    for program in &programs {
        apply_filter(program).map_err(|e| match e {
            seccompiler::Error::Prctl(io) | seccompiler::Error::Seccomp(io) => errno_of(&io),
            _ => None,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn the_filters_compile_for_x86_64_and_aarch64() {
        for arch in [TargetArch::x86_64, TargetArch::aarch64] {
            let programs = build_programs(arch).expect("the allowlist compiles");
            assert_eq!(programs.len(), 3, "{arch:?}");
            assert!(programs.iter().all(|p| !p.is_empty()), "{arch:?}");
        }
        assert!(build_programs(TargetArch::riscv64).is_err());
    }

    #[test]
    fn apply_refuses_a_multithreaded_process_and_confines_nothing() {
        // A second thread that outlives the call: the filters would not cover it.
        let (stop, parked) = std::sync::mpsc::channel::<()>();
        let helper = std::thread::spawn(move || {
            let _ = parked.recv();
        });
        let report = apply();
        stop.send(()).expect("stop the helper thread");
        helper.join().expect("helper thread");

        assert!(!report.applied);
        assert_eq!(report.mechanism, MECHANISM_NONE);
        assert_eq!(report.os_error, Some(i64::from(libc::EBUSY)));
        assert_eq!(report.no_new_privs, None, "nothing was changed");
        assert_eq!(report.seccomp, None);
        assert_eq!(report.landlock_abi, None);
    }

    #[test]
    fn a_failed_seccomp_install_is_reported_as_not_applied() {
        let mut base = unapplied();
        base.no_new_privs = Some(true);
        base.landlock_abi = Some(4);

        let failed = conclude(base.clone(), Err(Some(i64::from(libc::EPERM))));
        assert!(!failed.applied);
        assert_eq!(failed.seccomp, Some(false));
        assert_eq!(failed.os_error, Some(i64::from(libc::EPERM)));
        assert_eq!(failed.mechanism, MECHANISM_NONE);

        let no_errno = conclude(base.clone(), Err(None));
        assert!(!no_errno.applied);
        assert_eq!(no_errno.os_error, Some(-1));

        let with_landlock = conclude(base.clone(), Ok(()));
        assert!(with_landlock.applied);
        assert_eq!(with_landlock.mechanism, MECHANISM_SECCOMP_LANDLOCK);
        assert_eq!(with_landlock.seccomp, Some(true));

        base.landlock_abi = None;
        let seccomp_only = conclude(base, Ok(()));
        assert!(seccomp_only.applied);
        assert_eq!(seccomp_only.mechanism, MECHANISM_SECCOMP);
    }

    const CHILD_ENV: &str = "ATLAS_DUCK_LANDLOCK_CHILD";
    const CHILD_TEST: &str =
        "confine::linux::tests::landlock_alone_denies_open_when_the_kernel_has_it";

    /// Landlock without seccomp, in a child process (Landlock cannot be undone,
    /// and it is per thread, so the child confines only its own test thread).
    /// The child prints one line `landlock abi=<n|none> open=<ok|errno>`.
    #[test]
    fn landlock_alone_denies_open_when_the_kernel_has_it() {
        if std::env::var_os(CHILD_ENV).is_some() {
            let abi = apply_landlock();
            let open = match std::fs::File::open("/etc/passwd") {
                Ok(_) => "ok".to_owned(),
                Err(e) => e
                    .raw_os_error()
                    .map_or("error".to_owned(), |c| c.to_string()),
            };
            let abi = abi.map_or("none".to_owned(), |v| v.to_string());
            // The harness has already printed `test <name> ... ` on this line.
            println!("\nlandlock abi={abi} open={open}");
            return;
        }
        let out = Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, "1")
            .output()
            .expect("run the child");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let line = stdout
            .lines()
            .find(|l| l.starts_with("landlock abi="))
            .unwrap_or_else(|| panic!("no result line in:\n{stdout}"));
        eprintln!("{line}");
        if line.starts_with("landlock abi=none ") {
            assert!(
                line.ends_with("open=ok"),
                "no Landlock, the control open must work: {line}"
            );
        } else {
            assert!(
                line.ends_with(&format!("open={}", libc::EACCES)),
                "Landlock with no rules must deny open with EACCES: {line}"
            );
        }
    }
}
