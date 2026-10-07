//! THE one reviewed seccomp allowlist of the sandbox worker (spec §9.4, Linux).
//!
//! Default action: `SECCOMP_RET_KILL_PROCESS`. Only the syscalls named in
//! [`ALLOWED`] pass. `open`, `openat` and `openat2` return `EACCES`
//! ([`ERRNO_EACCES`]) and `clone3` returns `ENOSYS` ([`ERRNO_ENOSYS`]).
//! Everything else is killed, among others `clone`, `execve(at)`, `socket`,
//! `socketpair`, `ptrace`, `process_vm_*`, `bpf`, `io_uring_*`, `unshare`,
//! `setns` and the keyring calls: none of them appears below.
//!
//! Two kinds of entry, and the comment on each says which it is:
//! * "§9.4 category": named by the spec's list (read on fd 0, write on fds 1
//!   and 2, memory management, futex, clocks, `getrandom`, signal return and
//!   mask, exit). Where the M1 tests do not exercise the entry, the comment
//!   says so: it stays because M8 scripts run under the same filter with much
//!   larger heaps, and M8's full test suite (§15 V11) re-verifies the list.
//! * "beyond the spec": added only because a failing test proved the worker
//!   needs it, with a comment naming the caller (Rust std, glibc, QuickJS).
//!
//! Deliberately absent although glibc or std may call them: `mprotect`,
//! `madvise`, `sched_yield`, `membarrier`, `prlimit64`, `rseq` (registered
//! before the filter), `gettid`, `getpid`, `tgkill`. The M1 tests show the
//! worker does not need them. A worker that aborts therefore dies with
//! SIGSYS, not SIGABRT (`abort` needs `tgkill`). The worker's `run()` avoids
//! that for panics: its panic hook (T14) exits with code 101 before any abort.
//!
//! The unit tests at the bottom enforce the review list: every name resolves
//! in the x86_64 and aarch64 tables, no forbidden name is present, and only
//! `read` and `write` carry a descriptor rule.

/// Extra argument condition on an allowed syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Allowed with any arguments.
    Any,
    /// Allowed only when the first argument (a 32-bit file descriptor) is one
    /// of these.
    Arg0In(&'static [u32]),
}

/// The allowed syscalls (Linux syscall names) and their argument rules.
pub const ALLOWED: &[(&str, Rule)] = &[
    // §9.4 category: I/O. `read` on fd 0 (framed requests), `write` on fds 1
    // and 2 (frames, stderr). Caller: Rust std `Stdin`/`Stdout`/`Stderr`.
    // Proven: without `write` the worker dies before `probe.ready`, without
    // `read` at its first request.
    ("read", Rule::Arg0In(&[0])),
    ("write", Rule::Arg0In(&[1, 2])),
    // §9.4 category: memory management. Caller: glibc `malloc` under QuickJS's
    // allocator. `brk` and `munmap` are proven by `probes_linux` (removing
    // either breaks it), `mmap` and `mremap` by `tests/confined_workload.rs`
    // (a large-heap script is killed without them). `mprotect` and `madvise`
    // are not listed: glibc calls them only for non-main arenas, and the
    // worker has one thread and `MALLOC_ARENA_MAX=1`.
    ("brk", Rule::Any),
    ("mmap", Rule::Any),
    ("munmap", Rule::Any),
    ("mremap", Rule::Any),
    // §9.4 category: futex. Not exercised by the M1 tests. Caller: Rust std
    // `Once`/`OnceLock` and the stdio locks on a contended path.
    ("futex", Rule::Any),
    // §9.4 category: clocks. Not exercised by the M1 tests: normally served by
    // the vDSO, the syscall is the fallback. Caller: QuickJS `Date.now()` and
    // `Math.random()` seeding.
    ("clock_gettime", Rule::Any),
    ("gettimeofday", Rule::Any),
    // §9.4 category: `getrandom`. Not exercised by the M1 tests. Caller: std's
    // `HashMap` hash seeds.
    ("getrandom", Rule::Any),
    // §9.4 category: signal return and mask. Not exercised by the M1 tests.
    ("rt_sigreturn", Rule::Any),
    ("rt_sigprocmask", Rule::Any),
    // Beyond the spec: `sigaltstack`. Caller: Rust std `rt::cleanup`, run by
    // `process::exit` and by returning from `main`, disables the main thread's
    // alternate signal stack with `sigaltstack(SS_DISABLE)`. Proven by
    // `confined_worker_exits_zero_on_stdin_eof`: without it the worker dies
    // with SIGSYS (`Some(Signal(31))`) at its clean exit.
    ("sigaltstack", Rule::Any),
    // §9.4 category: exit. `exit_group` is proven by every probe run (without
    // it the worker cannot end); `exit` is not exercised by the M1 tests.
    ("exit", Rule::Any),
    ("exit_group", Rule::Any),
];

/// `open*` return `EACCES`: a libc path that lazily opens a file fails softly
/// instead of killing the run, and the "open a file in the user profile" probe
/// gets an explicit denial.
pub const ERRNO_EACCES: &[&str] = &["open", "openat", "openat2"];

/// `clone3` returns `ENOSYS`: glibc then falls back to `clone`, which is
/// killed (§9.4).
pub const ERRNO_ENOSYS: &[&str] = &["clone3"];

/// Names that exist only in some architectures' syscall tables (x86_64 has the
/// legacy `open`, aarch64 does not). A name listed here that does not resolve
/// on the build architecture is skipped; any other unresolvable name is an
/// error.
pub const ARCH_OPTIONAL: &[&str] = &["open"];

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Syscalls that must never be allowed or answered with an errno here.
    const FORBIDDEN: &[&str] = &[
        "socket",
        "socketpair",
        "connect",
        "clone",
        "fork",
        "vfork",
        "execve",
        "execveat",
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "bpf",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        "unshare",
        "setns",
        "add_key",
        "request_key",
        "keyctl",
        "kill",
        "tgkill",
        "prctl",
        "seccomp",
        "landlock_create_ruleset",
        "landlock_add_rule",
        "landlock_restrict_self",
    ];

    fn every_name() -> Vec<&'static str> {
        ALLOWED
            .iter()
            .map(|(name, _)| *name)
            .chain(ERRNO_EACCES.iter().copied())
            .chain(ERRNO_ENOSYS.iter().copied())
            .collect()
    }

    #[test]
    fn every_name_resolves_on_x86_64_and_aarch64() {
        for name in every_name() {
            assert!(
                syscalls::x86_64::Sysno::from_str(name).is_ok(),
                "`{name}` is not an x86_64 syscall"
            );
            if !ARCH_OPTIONAL.contains(&name) {
                assert!(
                    syscalls::aarch64::Sysno::from_str(name).is_ok(),
                    "`{name}` is not an aarch64 syscall (add it to ARCH_OPTIONAL only if aarch64 lacks it)"
                );
            }
        }
        for name in ARCH_OPTIONAL {
            assert!(
                syscalls::aarch64::Sysno::from_str(name).is_err(),
                "`{name}` exists on aarch64: drop it from ARCH_OPTIONAL"
            );
        }
    }

    #[test]
    fn no_forbidden_syscall_is_allowed_or_answered_with_an_errno() {
        for name in every_name() {
            assert!(
                !FORBIDDEN.contains(&name),
                "`{name}` must not be in the allowlist file"
            );
        }
    }

    #[test]
    fn the_allowed_set_is_exactly_the_reviewed_set() {
        // Changing the allowlist means changing this list in the same commit,
        // so the reviewer sees every added syscall in one place.
        let mut want = vec![
            "brk",
            "clock_gettime",
            "exit",
            "exit_group",
            "futex",
            "getrandom",
            "gettimeofday",
            "mmap",
            "mremap",
            "munmap",
            "read",
            "rt_sigprocmask",
            "rt_sigreturn",
            "sigaltstack",
            "write",
        ];
        want.sort_unstable();
        let mut got: Vec<&str> = ALLOWED.iter().map(|(name, _)| *name).collect();
        got.sort_unstable();
        assert_eq!(got, want);
    }

    #[test]
    fn names_are_unique_across_all_three_lists() {
        let mut seen = std::collections::BTreeSet::new();
        for name in every_name() {
            assert!(seen.insert(name), "`{name}` is listed twice");
        }
    }

    #[test]
    fn only_read_and_write_carry_an_fd_rule_and_the_stdio_fds_are_exact() {
        for (name, rule) in ALLOWED {
            match (*name, rule) {
                ("read", Rule::Arg0In(fds)) => assert_eq!(*fds, &[0]),
                ("write", Rule::Arg0In(fds)) => assert_eq!(*fds, &[1, 2]),
                (_, Rule::Any) => {}
                (other, rule) => panic!("unexpected rule {rule:?} on `{other}`"),
            }
        }
        assert_eq!(ERRNO_EACCES, &["open", "openat", "openat2"]);
        assert_eq!(ERRNO_ENOSYS, &["clone3"]);
    }
}
