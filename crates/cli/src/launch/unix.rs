//! Unix app launch (PD-23): a double fork that leaves the caller's session and process tree, with
//! no inherited descriptors, stdio on `/dev/null`, cwd `/` and only the allowlisted environment.
//!
//! Between `fork` and `execve` only async-signal-safe calls are made (`setsid`, `fork`, `dup2`,
//! `close_range`/`close`, `chdir`, `sigprocmask`, `signal`, `execve`, `_exit`); every C string, the
//! argv/envp arrays, the `/dev/null` descriptor, the descriptor limit and the signal set are prepared
//! before the first `fork`. `std::process::Command` is used only for the bounded probes
//! (`systemd-run` availability, `launchctl managername`), never for the app itself.

use std::ffi::{CString, OsStr, OsString};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::LaunchError;
#[cfg(target_os = "linux")]
use super::plan::SYSTEMD_RUN;
use super::plan::{ExecPlan, Via, exec_plan};

/// The descriptor sweep's upper bound when `close_range` is unavailable (the soft
/// `RLIMIT_NOFILE`, clamped to this so an unlimited soft limit stays a bounded loop).
const MAX_FD_SWEEP: libc::c_int = 65_536;
/// Exit status of the grandchild when anything before `execve` fails (nobody waits for it).
const EXEC_FAILED: libc::c_int = 127;
/// PD-23: the `systemd-run` probe must answer within 2 s.
const PROBE_LIMIT: Duration = Duration::from_secs(2);

/// Starts `app --background` detached (PD-23): macOS bundles through `open -n -g -a`, Linux
/// through `systemd-run --user --scope` when the user manager answers, else directly.
pub(crate) fn launch_app(app: &Path, env: &[(OsString, OsString)]) -> Result<(), LaunchError> {
    let ExecPlan { program, args } = exec_plan(app, via_for_this_os());
    spawn_detached(&program, &args, env)
}

fn via_for_this_os() -> Via {
    if cfg!(target_os = "macos") {
        Via::MacOpen
    } else if systemd_run_available() {
        Via::SystemdRun
    } else {
        Via::Direct
    }
}

/// Whether `systemd-run --user --scope` works here: `/usr/bin/systemd-run` exists and a probe
/// scope running `/bin/true` succeeds within 2 s. Probed once per process.
pub(crate) fn systemd_run_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(probe_systemd_run)
}

#[cfg(target_os = "linux")]
fn probe_systemd_run() -> bool {
    let systemd_run = Path::new(SYSTEMD_RUN);
    if !systemd_run.is_file() {
        return false;
    }
    let env = super::env::launch_env(std::env::vars_os());
    matches!(
        run_probe(
            systemd_run,
            &["--user", "--scope", "--quiet", "--collect", "/bin/true"],
            &env,
            PROBE_LIMIT,
        ),
        Some((true, _))
    )
}

#[cfg(not(target_os = "linux"))]
fn probe_systemd_run() -> bool {
    false
}

/// Runs a short-lived probe: `env_clear()` + `env`, null stdin/stderr, cwd `/`, stdout captured.
/// Returns `(exited successfully, stdout)`, or `None` when it could not start or did not finish
/// within `limit` (it is then killed and reaped). Output must fit the pipe buffer.
pub(crate) fn run_probe(
    program: &Path,
    args: &[&str],
    env: &[(OsString, OsString)],
    limit: Duration,
) -> Option<(bool, Vec<u8>)> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let until = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let mut out = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_end(&mut out);
    }
    Some((status.success(), out))
}

/// Everything the forked children touch, built before the first `fork`.
struct Prepared {
    program: CString,
    // Owners of the pointers in `argv_ptrs` / `envp_ptrs`; must outlive the fork.
    _argv: Vec<CString>,
    _envp: Vec<CString>,
    argv_ptrs: Vec<*const libc::c_char>,
    envp_ptrs: Vec<*const libc::c_char>,
    fd_limit: libc::c_int,
    empty_mask: libc::sigset_t,
}

fn c_string(s: &OsStr) -> Result<CString, LaunchError> {
    CString::new(s.as_bytes()).map_err(|_| LaunchError::InvalidArgument)
}

/// `NAME=value`; a name that is empty or contains `=` cannot be represented.
fn env_entry(name: &OsStr, value: &OsStr) -> Result<CString, LaunchError> {
    let name = name.as_bytes();
    if name.is_empty() || name.contains(&b'=') {
        return Err(LaunchError::InvalidArgument);
    }
    let mut entry = Vec::with_capacity(name.len() + 1 + value.len());
    entry.extend_from_slice(name);
    entry.push(b'=');
    entry.extend_from_slice(value.as_bytes());
    CString::new(entry).map_err(|_| LaunchError::InvalidArgument)
}

fn prepare(
    program: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
) -> Result<Prepared, LaunchError> {
    let program_c = c_string(program.as_os_str())?;
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(program_c.clone());
    for a in args {
        argv.push(c_string(a)?);
    }
    let envp = env
        .iter()
        .map(|(k, v)| env_entry(k, v))
        .collect::<Result<Vec<_>, _>>()?;
    let argv_ptrs = argv
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs = envp
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    // SAFETY: `sigemptyset` initializes the zeroed set it is given.
    let empty_mask = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        set
    };
    Ok(Prepared {
        program: program_c,
        _argv: argv,
        _envp: envp,
        argv_ptrs,
        envp_ptrs,
        fd_limit: fd_limit(),
        empty_mask,
    })
}

/// The soft descriptor limit, clamped to `3..=MAX_FD_SWEEP`.
fn fd_limit() -> libc::c_int {
    // SAFETY: `getrlimit` writes into the struct it is given.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    let got = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    if got != 0 || rl.rlim_cur == libc::RLIM_INFINITY {
        return MAX_FD_SWEEP;
    }
    libc::c_int::try_from(rl.rlim_cur)
        .unwrap_or(MAX_FD_SWEEP)
        .clamp(3, MAX_FD_SWEEP)
}

/// `/dev/null` opened read-write with `O_CLOEXEC`, moved to a descriptor >= 3 so that `dup2` onto
/// 0/1/2 always makes a fresh (inheritable) copy.
fn open_dev_null() -> io::Result<libc::c_int> {
    // SAFETY: plain syscalls on a static C string and descriptors this function owns.
    unsafe {
        let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        if fd > 2 {
            return Ok(fd);
        }
        let moved = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3);
        let err = io::Error::last_os_error();
        libc::close(fd);
        if moved < 0 { Err(err) } else { Ok(moved) }
    }
}

/// PD-23 double fork: `program args...` runs as an orphan in its own session, stdio on
/// `/dev/null`, every other descriptor closed, cwd `/`, environment exactly `env`. Returns once the
/// intermediate child has exited; whether `execve` itself succeeded is not observable here (the
/// post-launch poll is what tells).
pub(crate) fn spawn_detached(
    program: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
) -> Result<(), LaunchError> {
    let prepared = prepare(program, args, env)?;
    let dev_null = open_dev_null().map_err(LaunchError::Io)?;
    // SAFETY: the child branches only make async-signal-safe calls on memory prepared above and
    // never return (`_exit`/`execve`); the parent branch only closes and waits.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: as above; this is the first child.
        unsafe { first_child(&prepared, dev_null) }
    }
    let fork_err = io::Error::last_os_error();
    // SAFETY: closing the parent's own descriptor.
    unsafe { libc::close(dev_null) };
    if pid < 0 {
        return Err(LaunchError::Io(fork_err));
    }
    match wait_for(pid) {
        Ok(0) => Ok(()),
        Ok(code) => Err(LaunchError::ChildFailed(code)),
        Err(e) => Err(LaunchError::Io(e)),
    }
}

/// The first child: new session, fork the grandchild, exit at once so the grandchild is orphaned.
///
/// # Safety
/// Only to be called in the child right after `fork`.
unsafe fn first_child(p: &Prepared, dev_null: libc::c_int) -> ! {
    unsafe {
        if libc::setsid() < 0 {
            libc::_exit(1);
        }
        match libc::fork() {
            0 => grandchild(p, dev_null),
            pid if pid < 0 => libc::_exit(1),
            _ => libc::_exit(0),
        }
    }
}

/// The grandchild: stdio onto `/dev/null`, close everything else, `chdir("/")`, default signal
/// mask and `SIGPIPE`, then `execve`.
///
/// # Safety
/// Only to be called in the grandchild right after `fork`.
unsafe fn grandchild(p: &Prepared, dev_null: libc::c_int) -> ! {
    unsafe {
        for target in 0..=2 {
            if libc::dup2(dev_null, target) < 0 {
                libc::_exit(EXEC_FAILED);
            }
        }
        close_from_3(p.fd_limit);
        if libc::chdir(c"/".as_ptr()) != 0 {
            libc::_exit(EXEC_FAILED);
        }
        // Rust ignores SIGPIPE in its own processes and the agent may have blocked signals; the
        // app starts from the defaults like a login-started one (std's `Command` does the same).
        libc::sigprocmask(libc::SIG_SETMASK, &p.empty_mask, std::ptr::null_mut());
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        libc::execve(
            p.program.as_ptr(),
            p.argv_ptrs.as_ptr(),
            p.envp_ptrs.as_ptr(),
        );
        libc::_exit(EXEC_FAILED)
    }
}

/// Closes every descriptor >= 3: `close_range` on Linux, else (and as its fallback) one `close` per
/// descriptor below the limit.
///
/// # Safety
/// Only in the grandchild (it closes descriptors it does not own).
unsafe fn close_from_3(fd_limit: libc::c_int) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: raw syscall, no memory arguments.
        let done = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
        if done == 0 {
            return;
        }
    }
    for fd in 3..fd_limit {
        // SAFETY: closing a descriptor number; EBADF for unused ones is ignored.
        unsafe { libc::close(fd) };
    }
}

/// `waitpid` for the intermediate child, retrying on `EINTR`; its exit code, or -1 if it did not
/// exit normally.
fn wait_for(pid: libc::pid_t) -> io::Result<i32> {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: waits for our own child and writes the status it is given.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            break;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else {
        Ok(-1)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn prepared_argv_and_envp_are_null_terminated() {
        let env = vec![
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        ];
        let p = prepare(
            Path::new("/bin/sh"),
            &[OsString::from("-c"), OsString::from("true")],
            &env,
        )
        .unwrap();
        assert_eq!(p.argv_ptrs.len(), 4);
        assert!(p.argv_ptrs[3].is_null());
        assert_eq!(p.envp_ptrs.len(), 3);
        assert!(p.envp_ptrs[2].is_null());
        assert_eq!(p._envp[0].as_bytes(), b"LANG=C");
        assert_eq!(p._argv[0].as_bytes(), b"/bin/sh");
        assert!(p.fd_limit >= 3 && p.fd_limit <= MAX_FD_SWEEP);
    }

    #[test]
    fn unrepresentable_strings_are_refused_before_fork() {
        let nul = OsString::from("a\0b");
        assert!(matches!(
            prepare(Path::new("/bin/sh"), std::slice::from_ref(&nul), &[]),
            Err(LaunchError::InvalidArgument)
        ));
        assert!(matches!(
            prepare(
                Path::new("/bin/sh"),
                &[],
                &[(OsString::from("A=B"), OsString::from("x"))]
            ),
            Err(LaunchError::InvalidArgument)
        ));
        assert!(matches!(
            prepare(Path::new("/bin/sh"), &[], &[(OsString::from("A"), nul)]),
            Err(LaunchError::InvalidArgument)
        ));
    }

    fn wait_for_file(p: &Path) -> String {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(s) = fs::read_to_string(p)
                && s.ends_with('\n')
            {
                return s;
            }
            assert!(Instant::now() < until, "{} never written", p.display());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn sh(script: String) -> Vec<OsString> {
        vec![OsString::from("-c"), OsString::from(script)]
    }

    fn quoted(p: &Path) -> String {
        format!("'{}'", p.display())
    }

    #[test]
    #[ignore = "spawns a detached /bin/sh; run on the T26 Linux/macOS legs with --ignored"]
    fn double_fork_detaches() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");
        let env_out = tmp.path().join("env");
        let env = vec![
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("ATLAS_T"), OsString::from("one two")),
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        ];
        let script = format!(
            "/usr/bin/env > {env_tmp}; mv {env_tmp} {env_out}; echo $PPID $$ $(pwd) > {out}.tmp; \
             mv {out}.tmp {out}; sleep 2",
            env_tmp = quoted(&tmp.path().join("env.tmp")),
            env_out = quoted(&env_out),
            out = quoted(&out),
        );
        spawn_detached(Path::new("/bin/sh"), &sh(script), &env).unwrap();
        let line = wait_for_file(&out);
        let mut parts = line.split_whitespace();
        let ppid: u32 = parts.next().unwrap().parse().unwrap();
        let pid: libc::pid_t = parts.next().unwrap().parse().unwrap();
        assert_eq!(parts.next(), Some("/"), "cwd is /");
        assert_ne!(
            ppid,
            std::process::id(),
            "the test process is not the parent"
        );

        // A different session: getsid(child) differs from ours, or the OS refuses to tell
        // (EPERM is returned exactly for a process in another session).
        // SAFETY: plain syscalls.
        let (ours, theirs) = unsafe { (libc::getsid(0), libc::getsid(pid)) };
        let refused = theirs < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        assert!(
            refused || (theirs >= 0 && theirs != ours),
            "ours={ours} theirs={theirs}"
        );

        let seen = wait_for_file(&env_out);
        let mut names: Vec<&str> = seen
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, _)| k))
            // Variables every shell sets itself.
            .filter(|k| !matches!(*k, "PWD" | "OLDPWD" | "SHLVL" | "_"))
            .collect();
        names.sort_unstable();
        assert_eq!(names, ["ATLAS_T", "LANG", "PATH"]);
        assert!(seen.lines().any(|l| l == "ATLAS_T=one two"));
        assert!(seen.lines().any(|l| l == "PATH=/usr/bin:/bin"));
    }

    /// A pipe left open without `CLOEXEC`, moved to descriptors >= 50 so the probe shell's own
    /// descriptors cannot be mistaken for it.
    fn leaky_pipe() -> [libc::c_int; 2] {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: plain syscalls on descriptors this test owns.
        unsafe {
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
            for fd in &mut fds {
                let moved = libc::fcntl(*fd, libc::F_DUPFD, 50);
                assert!(moved >= 50);
                libc::close(*fd);
                *fd = moved;
            }
        }
        fds
    }

    /// The probe script writes the open descriptor numbers among `fds` to `out`, one per line.
    fn fd_probe(fds: &[libc::c_int], out: &Path) -> String {
        let list = fds
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "for f in {list}; do if [ -e /proc/$$/fd/$f ]; then echo $f; \
             elif [ ! -d /proc/$$ ] && (: <&$f) 2>/dev/null; then echo $f; fi; done > {tmp}; \
             echo end >> {tmp}; mv {tmp} {out}",
            tmp = quoted(&out.with_extension("tmp")),
            out = quoted(out),
        )
    }

    #[test]
    #[ignore = "spawns a detached /bin/sh; run on the T26 Linux/macOS legs with --ignored"]
    fn v12_spawn_closes_inherited_fds() {
        let tmp = tempfile::tempdir().unwrap();
        let fds = leaky_pipe();
        let env = vec![(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))];

        // Control: a plain std child does inherit the pipe, so the probe can see a leak.
        let control_out = tmp.path().join("control");
        let status = Command::new("/bin/sh")
            .args(sh(fd_probe(&fds, &control_out)))
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k, v)))
            .status()
            .unwrap();
        assert!(status.success());
        let control = wait_for_file(&control_out);
        assert_eq!(
            control.lines().filter(|l| *l != "end").count(),
            2,
            "probe cannot see leaked fds: {control:?}"
        );

        let out = tmp.path().join("out");
        spawn_detached(Path::new("/bin/sh"), &sh(fd_probe(&fds, &out)), &env).unwrap();
        let seen = wait_for_file(&out);
        assert_eq!(
            seen, "end\n",
            "inherited fds visible in the launched process"
        );
        // SAFETY: closing this test's own descriptors.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "runs systemd-run; run on the T26 Linux leg with --ignored --nocapture"]
    fn v13_linux_systemd_run_probe() {
        println!("V13 systemd_run_user_scope={}", systemd_run_available());
    }

    #[test]
    #[ignore = "forks before the exec fails; run on the T26 Linux/macOS legs with --ignored"]
    fn probe_of_a_missing_program_is_none() {
        let missing = PathBuf::from("/nonexistent/atlas-duck-probe");
        assert_eq!(run_probe(&missing, &[], &[], Duration::from_secs(1)), None);
    }
}
