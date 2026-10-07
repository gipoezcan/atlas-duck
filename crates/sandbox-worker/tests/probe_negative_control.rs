//! Unconfined negative controls for the §9.4 probes. Every attempt runs
//! in-process, in the test binary, with no confinement. Each must come back
//! `Allowed`, so a probe that always says `Blocked` fails here, and the later
//! confined runs (T17, T18, T19) can trust a `Blocked`.

#[cfg(any(target_os = "linux", windows))]
use std::process::{Child, Command, Stdio};

use atlas_duck_ipc::sandbox::probe::{
    LOOPBACK_PROBE_ADDR, PUBLIC_PROBE_ADDR, ProbeId, ProbeOutcome, ProbeRequest, ProbeResultMsg,
};
use atlas_duck_sandbox_worker::probe::run_probe;

/// An idle child process of this test: dumpable, same user, and a descendant,
/// so Yama `ptrace_scope = 1` and the Windows default DACL both allow reading
/// it. Killed and reaped on drop.
#[cfg(any(target_os = "linux", windows))]
struct IdleChild(Child);

#[cfg(any(target_os = "linux", windows))]
impl IdleChild {
    fn start() -> IdleChild {
        #[cfg(unix)]
        let child = Command::new("sleep")
            .arg("60")
            .stdout(Stdio::null())
            .spawn();
        #[cfg(windows)]
        let child = {
            let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
            Command::new(std::path::Path::new(&root).join("System32").join("cmd.exe"))
                .args(["/C", "ping -n 60 127.0.0.1 > nul"])
                .stdout(Stdio::null())
                .spawn()
        };
        IdleChild(child.expect("start an idle child process"))
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }
}

#[cfg(any(target_os = "linux", windows))]
impl Drop for IdleChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn home() -> String {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var(var).expect("home directory variable")
}

fn request(probe: ProbeId, app_pid: u32) -> ProbeRequest {
    ProbeRequest {
        probe,
        app_pid,
        profile_path: home(),
        public_addr: PUBLIC_PROBE_ADDR.to_owned(),
        loopback_addr: LOOPBACK_PROBE_ADDR.to_owned(),
        handle_value: None,
    }
}

fn run(probe: ProbeId, app_pid: u32) -> ProbeResultMsg {
    let msg = run_probe(&request(probe, app_pid));
    assert_eq!(msg.probe, probe, "the result names the probe that ran");
    msg
}

#[track_caller]
fn assert_allowed(msg: &ProbeResultMsg) {
    assert_eq!(
        msg.outcome,
        ProbeOutcome::Allowed,
        "unconfined {:?} must be Allowed, got {:?} (os_error {:?}, detail {:?})",
        msg.probe,
        msg.outcome,
        msg.os_error,
        msg.detail
    );
}

#[test]
fn file_in_profile_is_allowed() {
    assert_allowed(&run(ProbeId::FileInProfile, 0));
}

#[test]
fn file_in_profile_in_a_missing_directory_is_an_error_not_blocked() {
    let mut req = request(ProbeId::FileInProfile, 0);
    req.profile_path = std::env::temp_dir()
        .join("atlas-duck-probe-no-such-directory")
        .to_string_lossy()
        .into_owned();
    let msg = run_probe(&req);
    assert_eq!(msg.outcome, ProbeOutcome::Error);
}

/// `ECONNREFUSED` (or a connected socket, if something listens on port 9)
/// means the connect reached the network stack.
#[test]
fn connect_loopback_is_allowed() {
    assert_allowed(&run(ProbeId::ConnectLoopback, 0));
}

/// 192.0.2.1 is TEST-NET-1 and goes nowhere: `ENETUNREACH`, or `EINPROGRESS`
/// followed by the 2 s deadline, both count as "not a denial".
#[test]
fn connect_public_is_allowed() {
    assert_allowed(&run(ProbeId::ConnectPublic, 0));
}

#[test]
fn connect_to_an_invalid_address_is_an_error() {
    let mut req = request(ProbeId::ConnectPublic, 0);
    req.public_addr = "not an address".to_owned();
    assert_eq!(run_probe(&req).outcome, ProbeOutcome::Error);
}

#[test]
fn spawn_process_is_allowed() {
    assert_allowed(&run(ProbeId::SpawnProcess, 0));
}

#[test]
fn engine_self_test_is_allowed() {
    assert_allowed(&run(ProbeId::EngineSelfTest, 0));
}

#[test]
fn env_names_returns_the_current_environment_names() {
    let msg = run(ProbeId::EnvNames, 0);
    assert_allowed(&msg);
    let mut expected: Vec<String> = std::env::vars_os()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    expected.sort();
    assert_eq!(msg.env_names, Some(expected));
}

#[test]
fn a_probe_of_another_os_is_an_error_not_blocked() {
    #[cfg(windows)]
    let foreign = ProbeId::RawClone;
    #[cfg(not(windows))]
    let foreign = ProbeId::CredRead;
    assert_eq!(run(foreign, 0).outcome, ProbeOutcome::Error);
}

#[test]
fn details_are_short_and_carry_no_paths() {
    let msg = run(ProbeId::FileInProfile, 0);
    let detail = msg.detail.expect("detail");
    assert!(detail.len() <= 256);
    assert!(
        !detail.contains(&home()),
        "detail must not echo the profile path"
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    #[test]
    fn raw_clone_is_allowed() {
        assert_allowed(&run(ProbeId::RawClone, 0));
    }

    #[test]
    fn clone3_is_allowed() {
        assert_allowed(&run(ProbeId::Clone3, 0));
    }

    #[test]
    fn process_vm_readv_of_a_dumpable_child_is_allowed() {
        let child = IdleChild::start();
        assert_allowed(&run(ProbeId::MemReadProcessVm, child.pid()));
    }

    #[test]
    fn proc_mem_of_a_dumpable_child_is_allowed() {
        let child = IdleChild::start();
        assert_allowed(&run(ProbeId::MemReadProcMem, child.pid()));
    }

    const TOPOLOGY_CHILD_ENV: &str = "ATLAS_DUCK_PROBE_TOPOLOGY_CHILD";
    const TOPOLOGY_CHILD_TEST: &str =
        "linux::mem_reads_of_the_parent_follow_yama_in_the_worker_topology";
    /// `PR_SET_PTRACER` and its "any process" argument (`<sys/prctl.h>`).
    const PR_SET_PTRACER: libc::c_int = 0x5961_6d61;
    const PR_SET_PTRACER_ANY: libc::c_ulong = !0;

    /// `kernel.yama.ptrace_scope`, or `None` without the Yama module.
    fn ptrace_scope() -> Option<u32> {
        std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// Runs this test binary as a child that probes its PARENT (the real
    /// topology: the worker's target is the app that spawned it, which is not
    /// a descendant of the worker). Returns `(process_vm, proc_mem)` as
    /// `(outcome, os_error)`.
    fn parent_probes_from_a_child() -> [(ProbeOutcome, Option<i64>); 2] {
        let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                TOPOLOGY_CHILD_TEST,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(TOPOLOGY_CHILD_ENV, "1")
            .output()
            .expect("run the child");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let line = stdout
            .lines()
            .find_map(|l| l.strip_prefix("topology "))
            .unwrap_or_else(|| {
                panic!(
                    "no topology line in:
{stdout}"
                )
            });
        let cell = |name: &str| -> (ProbeOutcome, Option<i64>) {
            let word = line
                .split_whitespace()
                .find_map(|w| w.strip_prefix(name))
                .unwrap_or_else(|| panic!("no `{name}` in `{line}`"));
            let (outcome, errno) = word.split_once('/').expect("outcome/errno");
            let outcome = match outcome {
                "Allowed" => ProbeOutcome::Allowed,
                "Blocked" => ProbeOutcome::Blocked,
                _ => ProbeOutcome::Error,
            };
            (outcome, errno.parse().ok())
        };
        [cell("vm="), cell("mem=")]
    }

    /// Control with the real topology (preflight carry-forward): the probes
    /// read the PARENT, as the confined worker reads the app. Under Yama
    /// `ptrace_scope = 1` the unconfined child is refused (EPERM/EACCES) until
    /// the parent declares it with `PR_SET_PTRACER`, so a `Blocked` of the two
    /// memory probes proves the sandbox only where this control is `Allowed`.
    /// The real app is non-dumpable on top of that (§2.5): the confined host
    /// test therefore reads the SIGSYS death at `process_vm_readv` and the
    /// `probe-attempt` line, not the errno.
    #[test]
    fn mem_reads_of_the_parent_follow_yama_in_the_worker_topology() {
        if std::env::var_os(TOPOLOGY_CHILD_ENV).is_some() {
            // SAFETY: getppid takes no arguments.
            let parent = unsafe { libc::getppid() } as u32;
            let vm = run(ProbeId::MemReadProcessVm, parent);
            let mem = run(ProbeId::MemReadProcMem, parent);
            println!(
                "
topology vm={:?}/{} mem={:?}/{}",
                vm.outcome,
                vm.os_error.map_or("none".to_owned(), |e| e.to_string()),
                mem.outcome,
                mem.os_error.map_or("none".to_owned(), |e| e.to_string()),
            );
            return;
        }
        let scope = ptrace_scope();
        eprintln!("yama ptrace_scope = {scope:?}");

        // Without a declared tracer: Allowed where Yama is absent or 0,
        // refused with a denial code where it is 1 or higher.
        for (name, (outcome, errno)) in ["process_vm", "proc_mem"]
            .into_iter()
            .zip(parent_probes_from_a_child())
        {
            match scope {
                None | Some(0) => assert_eq!(outcome, ProbeOutcome::Allowed, "{name}"),
                Some(_) => {
                    assert_eq!(outcome, ProbeOutcome::Blocked, "{name}: Yama refuses");
                    assert!(
                        [libc::EPERM, libc::EACCES]
                            .iter()
                            .any(|e| errno == Some(i64::from(*e))),
                        "{name}: {errno:?}"
                    );
                }
            }
        }

        // With the parent naming any process as its tracer, scope 1 allows the
        // read. Scope 2 (admin only) and 3 (no attach) cannot be lifted by the
        // parent: the control does not exist there, say so instead of passing.
        if matches!(scope, Some(2..)) {
            eprintln!("SKIP the Allowed control: ptrace_scope {scope:?} cannot be lifted");
            return;
        }
        // SAFETY: prctl(PR_SET_PTRACER, pid) takes no pointers. A failure
        // (kernel without Yama) is fine: the control then holds without it.
        unsafe { libc::prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) };
        for (name, (outcome, errno)) in ["process_vm", "proc_mem"]
            .into_iter()
            .zip(parent_probes_from_a_child())
        {
            assert_eq!(
                outcome,
                ProbeOutcome::Allowed,
                "{name} of the parent, unconfined, tracer declared (errno {errno:?})"
            );
        }
    }

    #[test]
    fn process_vm_readv_of_a_missing_process_is_an_error_not_blocked() {
        // The first PID above `pid_max` (2^22 on 64-bit Linux) cannot exist.
        let msg = run(ProbeId::MemReadProcessVm, 0x7fff_fff0);
        assert_eq!(msg.outcome, ProbeOutcome::Error);
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    #[test]
    fn mach_lookup_of_securityd_is_allowed() {
        assert_allowed(&run(ProbeId::MachLookupSecurityd, 0));
    }

    /// `task_for_pid` on the calling process itself always succeeds. (Another
    /// process, even a child, needs the debugger entitlement or root, so the
    /// real probe target, the hardened app, is only checked in the confined
    /// run, T18.)
    #[test]
    fn task_for_pid_of_the_own_process_is_allowed() {
        assert_allowed(&run(ProbeId::TaskForPid, std::process::id()));
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::CreateEventW;

    #[test]
    fn open_process_vm_read_of_a_child_is_allowed() {
        let child = IdleChild::start();
        assert_allowed(&run(ProbeId::OpenProcessVmRead, child.pid()));
    }

    #[test]
    fn open_process_of_a_missing_process_is_an_error_not_blocked() {
        let msg = run(ProbeId::OpenProcessVmRead, 0xffff_fff0);
        assert_eq!(msg.outcome, ProbeOutcome::Error);
    }

    /// `CredReadW` of a credential that does not exist: `ERROR_NOT_FOUND`
    /// (1168) means the credential store was consulted.
    #[test]
    fn cred_read_of_a_missing_target_is_allowed() {
        let msg = run(ProbeId::CredRead, 0);
        assert_allowed(&msg);
        assert_eq!(msg.os_error, Some(1168));
    }

    #[test]
    fn open_clipboard_is_allowed() {
        assert_allowed(&run(ProbeId::OpenClipboard, 0));
    }

    #[test]
    fn handle_sentinel_that_the_process_holds_is_allowed() {
        // SAFETY: an unnamed manual-reset event; closed below.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        assert!(!event.is_null());
        let mut req = request(ProbeId::HandleSentinel, 0);
        req.handle_value = Some(event as usize as u64);
        let msg = run_probe(&req);
        // SAFETY: `event` is the handle created above.
        unsafe {
            CloseHandle(event);
        }
        assert_allowed(&msg);
    }

    #[test]
    fn handle_sentinel_that_the_process_lacks_is_blocked() {
        let mut req = request(ProbeId::HandleSentinel, 0);
        // Not 0xffff_fff4: `GetHandleInformation` succeeded for that value on
        // Windows 11 (probably a sign-extended standard-handle pseudo value).
        // 0x00ff_fff0 is far beyond any handle table in this process.
        req.handle_value = Some(0x00ff_fff0);
        let msg = run_probe(&req);
        assert_eq!(msg.outcome, ProbeOutcome::Blocked);
        assert_eq!(msg.os_error, Some(6));
    }

    #[test]
    fn handle_sentinel_without_a_value_is_an_error() {
        let msg = run(ProbeId::HandleSentinel, 0);
        assert_eq!(msg.outcome, ProbeOutcome::Error);
    }
}

/// Classification tables. The Windows and macOS tables are plain constants and
/// run on every OS; the errno tables run on the Unix legs.
mod classification {
    use std::io::ErrorKind;

    use atlas_duck_ipc::sandbox::probe::ProbeOutcome;
    use atlas_duck_sandbox_worker::probe::{classify_connect, macos, windows};

    #[cfg(unix)]
    #[test]
    fn unix_denials_are_blocked_and_unknown_errnos_are_errors() {
        use atlas_duck_sandbox_worker::probe::unix::{classify_denial, is_denial};
        assert!(is_denial(i64::from(libc::EACCES)));
        assert!(is_denial(i64::from(libc::EPERM)));
        assert!(!is_denial(i64::from(libc::ENOENT)));
        assert_eq!(
            classify_denial(i64::from(libc::EACCES)),
            ProbeOutcome::Blocked
        );
        assert_eq!(
            classify_denial(i64::from(libc::EPERM)),
            ProbeOutcome::Blocked
        );
        assert_eq!(
            classify_denial(i64::from(libc::ENOENT)),
            ProbeOutcome::Error
        );
        assert_eq!(
            classify_denial(i64::from(libc::EINVAL)),
            ProbeOutcome::Error
        );
        assert_eq!(classify_denial(9999), ProbeOutcome::Error);
    }

    #[cfg(unix)]
    #[test]
    fn unix_connect_errors() {
        use atlas_duck_sandbox_worker::probe::unix::classify_connect as unix_connect;
        for e in [
            libc::ECONNREFUSED,
            libc::ETIMEDOUT,
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::EINPROGRESS,
        ] {
            assert_eq!(
                unix_connect(i64::from(e)),
                ProbeOutcome::Allowed,
                "errno {e}"
            );
        }
        assert_eq!(unix_connect(i64::from(libc::EACCES)), ProbeOutcome::Blocked);
        assert_eq!(unix_connect(i64::from(libc::EPERM)), ProbeOutcome::Blocked);
        assert_eq!(unix_connect(i64::from(libc::EBADF)), ProbeOutcome::Error);
        assert_eq!(
            unix_connect(i64::from(libc::EAFNOSUPPORT)),
            ProbeOutcome::Error
        );
    }

    #[test]
    fn connect_deadline_without_an_os_code_is_allowed() {
        // `TcpStream::connect_timeout` reports its own deadline as TimedOut with
        // no OS code: EINPROGRESS followed by a timeout.
        assert_eq!(
            classify_connect(None, ErrorKind::TimedOut),
            ProbeOutcome::Allowed
        );
        assert_eq!(
            classify_connect(None, ErrorKind::Other),
            ProbeOutcome::Error
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_clone_and_process_vm_classification() {
        use atlas_duck_sandbox_worker::probe::linux::{classify_clone, classify_process_vm};
        // clone3 -> ENOSYS is the allowlist's answer (§9.4): Blocked.
        assert_eq!(
            classify_clone(i64::from(libc::ENOSYS), true),
            ProbeOutcome::Blocked
        );
        // Raw clone -> ENOSYS is not a denial.
        assert_eq!(
            classify_clone(i64::from(libc::ENOSYS), false),
            ProbeOutcome::Error
        );
        assert_eq!(
            classify_clone(i64::from(libc::EPERM), false),
            ProbeOutcome::Blocked
        );
        assert_eq!(
            classify_clone(i64::from(libc::EACCES), true),
            ProbeOutcome::Blocked
        );
        assert_eq!(
            classify_clone(i64::from(libc::EAGAIN), true),
            ProbeOutcome::Error
        );
        assert_eq!(
            classify_process_vm(i64::from(libc::EPERM)),
            ProbeOutcome::Blocked
        );
        assert_eq!(
            classify_process_vm(i64::from(libc::EACCES)),
            ProbeOutcome::Blocked
        );
        assert_eq!(
            classify_process_vm(i64::from(libc::EFAULT)),
            ProbeOutcome::Allowed
        );
        assert_eq!(
            classify_process_vm(i64::from(libc::ESRCH)),
            ProbeOutcome::Error
        );
        assert_eq!(
            classify_process_vm(i64::from(libc::ENOSYS)),
            ProbeOutcome::Error
        );
    }

    #[test]
    fn windows_connect_table() {
        assert!(windows::is_denial(windows::ERROR_ACCESS_DENIED));
        assert!(windows::is_denial(windows::WSAEACCES));
        assert!(!windows::is_denial(2));
        assert_eq!(
            windows::classify_connect(windows::WSAEACCES),
            ProbeOutcome::Blocked
        );
        assert_eq!(
            windows::classify_connect(windows::ERROR_ACCESS_DENIED),
            ProbeOutcome::Blocked
        );
        assert_eq!(windows::classify_connect(10061), ProbeOutcome::Allowed); // WSAECONNREFUSED
        assert_eq!(windows::classify_connect(10060), ProbeOutcome::Allowed); // WSAETIMEDOUT
        assert_eq!(windows::classify_connect(10035), ProbeOutcome::Allowed); // WSAEWOULDBLOCK
        assert_eq!(windows::classify_connect(10065), ProbeOutcome::Allowed); // WSAEHOSTUNREACH
        assert_eq!(windows::classify_connect(10047), ProbeOutcome::Error); // WSAEAFNOSUPPORT
    }

    #[test]
    fn windows_other_tables() {
        assert_eq!(windows::classify_spawn(5), ProbeOutcome::Blocked);
        assert_eq!(windows::classify_spawn(1816), ProbeOutcome::Blocked);
        assert_eq!(windows::classify_spawn(2), ProbeOutcome::Error);
        assert_eq!(windows::classify_open_process(5), ProbeOutcome::Blocked);
        assert_eq!(windows::classify_open_process(87), ProbeOutcome::Error);
        assert_eq!(windows::classify_cred_read(5), ProbeOutcome::Blocked);
        assert_eq!(windows::classify_cred_read(1168), ProbeOutcome::Allowed);
        assert_eq!(windows::classify_cred_read(1312), ProbeOutcome::Error);
        assert_eq!(windows::classify_open_clipboard(5), ProbeOutcome::Blocked);
        assert_eq!(windows::classify_open_clipboard(1418), ProbeOutcome::Error);
        assert_eq!(windows::classify_handle_sentinel(6), ProbeOutcome::Blocked);
        assert_eq!(windows::classify_handle_sentinel(5), ProbeOutcome::Error);
    }

    #[test]
    fn macos_tables() {
        assert_eq!(macos::classify_task_for_pid(0), ProbeOutcome::Allowed);
        assert_eq!(macos::classify_task_for_pid(5), ProbeOutcome::Blocked);
        assert_eq!(macos::classify_task_for_pid(4), ProbeOutcome::Error);
        assert_eq!(macos::classify_mach_lookup(0), ProbeOutcome::Allowed);
        assert_eq!(macos::classify_mach_lookup(1100), ProbeOutcome::Blocked);
        assert_eq!(macos::classify_mach_lookup(1102), ProbeOutcome::Error);
    }
}
