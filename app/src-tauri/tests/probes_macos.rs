#![cfg(target_os = "macos")]
//! T18: the §9.4 macOS probes against the real `atlas-duck-sandbox` worker
//! under the embedded SBPL profile (`sandbox_init`), spawned with `posix_spawn`.
//!
//! The worker is `CARGO_BIN_EXE_atlas-duck-sandbox`, or the binary named by
//! `ATLAS_DUCK_SANDBOX_BIN` (T21 points it at an installed package).
//! Run with `-- --nocapture`: the `META`, `PROBE`, `TASKFORPID_CONTROL`,
//! `FLOOR_SCOPE` and `V10` lines are the evidence T22 copies into the go/no-go
//! record.
//!
//! `task_for_pid` is only informative when an unconfined process can obtain the
//! target's task port. The test therefore runs a paired unconfined control
//! against the same target (this process, the "app") and asserts `Blocked` only
//! when the control is `Allowed`. A KERN_FAILURE for the unconfined control
//! says nothing about the seatbelt, and the evidence line says so.
//!
//! CI: leg `rust (aarch64-apple-darwin)` and job
//! `rust (x86_64-apple-darwin under Rosetta)` of `.github/workflows/ci.yml`.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::sandbox::WORKER_FRAME_MAX_BYTES;
use atlas_duck_ipc::sandbox::frame::write_frame;
use atlas_duck_ipc::sandbox::probe::{
    LOOPBACK_PROBE_ADDR, M_PROBE_READY, M_PROBE_RESULT, M_PROBE_RUN, PUBLIC_PROBE_ADDR, ProbeId,
    ProbeOutcome, ProbeReady, ProbeRequest, ProbeResultMsg, decode_notification,
    encode_notification,
};
use atlas_duck_sandbox_host::identity::FileId;
use atlas_duck_sandbox_host::macos::{MacSpawner, MacWorker};
use atlas_duck_sandbox_host::platform_spawner;
use atlas_duck_sandbox_host::probe::{
    Evidence, FloorVerdict, ProbeConfig, ProbeReport, run_probes,
};
use atlas_duck_sandbox_host::spawn::{DEFAULT_PROCESS_MB, ExitKind, SpawnSpec, WorkerProcess};

const TIMEOUT: Duration = Duration::from_secs(20);
/// First start of an x86_64 binary under Rosetta includes its translation.
const WARM_UP_TIMEOUT: Duration = Duration::from_secs(120);
const V10_CHILD_ENV: &str = "ATLAS_DUCK_V10_CHILD";
const TFP_CHILD_ENV: &str = "ATLAS_DUCK_TFP_CONTROL_CHILD";

// ------------------------------------------------------------------ helpers

/// One test at a time: probes spawn processes and the Rosetta leg is slow.
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

fn worker_exe() -> PathBuf {
    match std::env::var_os("ATLAS_DUCK_SANDBOX_BIN") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(env!("CARGO_BIN_EXE_atlas-duck-sandbox")),
    }
}

fn sysctl_bytes(name: &str) -> Option<Vec<u8>> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let mut len: libc::size_t = 0;
    // SAFETY: a NULL output buffer only asks for the size.
    let rc = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` is valid for `len` bytes.
    let rc = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(len);
    Some(buf)
}

/// `META` line: architecture, macOS version, and whether this process runs
/// translated by Rosetta (`sysctl.proc_translated`, absent on native Intel).
fn meta_line() -> String {
    let version = sysctl_bytes("kern.osproductversion")
        .map(|b| {
            String::from_utf8_lossy(&b)
                .trim_end_matches('\0')
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());
    let translated = sysctl_bytes("sysctl.proc_translated")
        .and_then(|b| b.first_chunk::<4>().map(|c| i32::from_ne_bytes(*c)))
        .map_or("n/a".to_string(), |v| v.to_string());
    format!(
        "META arch={} macos={version} translated={translated} worker={}",
        std::env::consts::ARCH,
        worker_exe().display()
    )
}

/// A file in the user's home directory: the `FileInProfile` target (§9.4).
struct ProfileFile(PathBuf);

impl ProfileFile {
    fn create() -> ProfileFile {
        let home = std::env::var_os("HOME").expect("HOME is set");
        let path =
            PathBuf::from(home).join(format!(".atlas-duck-t18-probe-{}", std::process::id()));
        std::fs::write(&path, b"profile probe target\n").expect("write the profile probe file");
        ProfileFile(path)
    }
}

impl Drop for ProfileFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The unconfined `task_for_pid` control against this process (the probes'
/// `app_pid`): runs the test binary again as a plain child, which asks for the
/// task port of its parent. Returns the `kern_return_t`.
fn task_for_pid_control() -> i64 {
    let exe = std::env::current_exe().expect("current_exe");
    let out = Command::new(exe)
        .args([
            "--exact",
            "tfp_control_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(TFP_CHILD_ENV, "1")
        .output()
        .expect("spawn the task_for_pid control child");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("TFP_CONTROL kr="))
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or_else(|| {
            panic!(
                "no TFP_CONTROL line from the control child ({:?})\n{stdout}\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )
        })
}

/// The full probe run, once per test binary.
fn report() -> &'static ProbeReport {
    static REPORT: OnceLock<ProbeReport> = OnceLock::new();
    REPORT.get_or_init(|| {
        // Warm-up: under Rosetta the first run of a binary is translated, which
        // can exceed the 10 s per-probe timeout of `run_probes`.
        drop(Session::start_within(WARM_UP_TIMEOUT));
        let profile = ProfileFile::create();
        let cfg = ProbeConfig::new(worker_exe(), std::process::id(), profile.0.clone());
        let spawner = platform_spawner().expect("platform_spawner() on macOS");
        let report = run_probes(spawner.as_ref(), None, &cfg);
        println!("{}", meta_line());
        println!("CONFINEMENT {:?}", report.confinement);
        for r in &report.records {
            println!(
                "PROBE {:?} outcome={:?} evidence={:?}",
                r.probe, r.outcome, r.evidence
            );
        }
        println!("FLOOR {:?}", report.floor);
        println!("{report:#?}");
        report
    })
}

/// One worker held after `probe.ready`, for tests that look at the live process.
struct Session {
    worker: MacWorker,
    ready: ProbeReady,
}

struct Answer {
    msg: ProbeResultMsg,
    exit: Option<ExitKind>,
    stderr: String,
}

impl Session {
    fn start() -> Session {
        Session::start_within(TIMEOUT)
    }

    fn start_within(wait: Duration) -> Session {
        let spec = SpawnSpec {
            exe: worker_exe(),
            process_mb: DEFAULT_PROCESS_MB,
        };
        let mut worker = MacSpawner::new()
            .spawn_mac(&spec)
            .unwrap_or_else(|e| panic!("spawning {}: {e}", spec.exe.display()));
        let frame = match worker.read_frame_timeout(WORKER_FRAME_MAX_BYTES, wait) {
            Ok(Some(bytes)) => bytes,
            other => panic!(
                "no probe.ready ({other:?}); worker stderr: {}",
                worker.stderr_tail()
            ),
        };
        let (method, params) = decode_notification(&frame).expect("probe.ready is JSON-RPC");
        assert_eq!(method, M_PROBE_READY);
        let ready: ProbeReady = serde_json::from_value(params).expect("probe.ready params");
        Session { worker, ready }
    }

    /// Sends one `probe.run`, closes stdin and returns the result and the exit.
    fn ask(mut self, probe: ProbeId, profile_path: &str) -> Answer {
        let request = ProbeRequest {
            probe,
            app_pid: std::process::id(),
            profile_path: profile_path.to_string(),
            public_addr: PUBLIC_PROBE_ADDR.to_string(),
            loopback_addr: LOOPBACK_PROBE_ADDR.to_string(),
            handle_value: None,
        };
        let payload = encode_notification(M_PROBE_RUN, &request);
        {
            let mut stdin = self.worker.stdin();
            write_frame(&mut stdin, &payload).expect("write probe.run");
            std::io::Write::flush(&mut stdin).expect("flush probe.run");
        }
        self.worker.close_stdin();
        let frame = match self
            .worker
            .read_frame_timeout(WORKER_FRAME_MAX_BYTES, TIMEOUT)
        {
            Ok(Some(bytes)) => bytes,
            other => panic!(
                "no probe.result for {probe:?} ({other:?}); worker stderr: {}",
                self.worker.stderr_tail()
            ),
        };
        let (method, params) = decode_notification(&frame).expect("probe.result is JSON-RPC");
        assert_eq!(method, M_PROBE_RESULT);
        let msg: ProbeResultMsg = serde_json::from_value(params).expect("probe.result params");
        let exit = self
            .worker
            .wait_timeout(TIMEOUT)
            .expect("wait for the worker");
        let stderr = self.worker.stderr_tail();
        Answer { msg, exit, stderr }
    }
}

/// File descriptors of a live process (`proc_pidinfo(PROC_PIDLISTFDS)`), sorted.
fn fds_of(pid: u32) -> Vec<i32> {
    let entry = std::mem::size_of::<libc::proc_fdinfo>();
    let mut buf = vec![0u8; entry * 256];
    // SAFETY: `buf` is valid for `buf.len()` bytes.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr().cast(),
            buf.len() as libc::c_int,
        )
    };
    assert!(
        n > 0,
        "PROC_PIDLISTFDS failed: {}",
        std::io::Error::last_os_error()
    );
    let mut fds: Vec<i32> = buf[..n as usize]
        .chunks_exact(entry)
        .filter_map(|c| c.first_chunk::<4>().map(|b| i32::from_ne_bytes(*b)))
        .collect();
    fds.sort_unstable();
    fds
}

/// Working directory of a live process (`PROC_PIDVNODEPATHINFO`).
fn cwd_of(pid: u32) -> String {
    // SAFETY: an all-zero `proc_vnodepathinfo` is a valid out buffer.
    let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is valid for its size.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            (&mut info as *mut libc::proc_vnodepathinfo).cast(),
            std::mem::size_of::<libc::proc_vnodepathinfo>() as libc::c_int,
        )
    };
    assert!(
        n > 0,
        "PROC_PIDVNODEPATHINFO failed: {}",
        std::io::Error::last_os_error()
    );
    let raw: &[libc::c_char] = info.pvi_cdir.vip_path.as_flattened();
    let bytes: Vec<u8> = raw
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

// -------------------------------------------------------------------- tests

#[test]
fn floor_probes_are_blocked_under_the_seatbelt_profile() {
    let _guard = serial();
    let report = report();
    let confinement = report
        .confinement
        .as_ref()
        .unwrap_or_else(|| panic!("no worker sent probe.ready: {report:#?}"));
    assert!(
        confinement.applied,
        "sandbox_init did not apply the profile (os_error {:?}); see the report above",
        confinement.os_error
    );
    assert_eq!(confinement.mechanism, "seatbelt");

    // Paired unconfined control against the same target as the probes' app_pid.
    let control_kr = task_for_pid_control();
    let informative = control_kr == 0;

    for &probe in ProbeId::floor_probes_for_current_os() {
        let record = report
            .records
            .iter()
            .find(|r| r.probe == probe)
            .unwrap_or_else(|| panic!("no record for {probe:?}"));
        if probe == ProbeId::TaskForPid {
            println!(
                "TaskForPid against the test process: {:?} {:?}",
                record.outcome, record.evidence
            );
            println!(
                "TASKFORPID_CONTROL unconfined_kr={control_kr} informative={informative} confined={:?}",
                record.outcome
            );
            // A confined process can never get what an unconfined one cannot.
            assert_ne!(
                record.outcome,
                ProbeOutcome::Allowed,
                "the confined worker obtained a task port: {:?}",
                record.evidence
            );
            if informative {
                assert_eq!(
                    record.outcome,
                    ProbeOutcome::Blocked,
                    "the unconfined control got the task port, so the confined worker must be Blocked: {:?}",
                    record.evidence
                );
            }
            continue;
        }
        assert_eq!(
            record.outcome,
            ProbeOutcome::Blocked,
            "{probe:?} must be Blocked, evidence {:?}",
            record.evidence
        );
    }

    // §9.4: opening a file in the profile fails with EPERM under the profile.
    let file = report
        .records
        .iter()
        .find(|r| r.probe == ProbeId::FileInProfile)
        .expect("FileInProfile record");
    assert_eq!(
        file.evidence,
        Evidence::Reported {
            os_error: Some(i64::from(libc::EPERM))
        }
    );

    // The floor verdict. TaskForPid counts toward the floor in the host, but
    // against a non-hardened test binary a refusal proves nothing about the
    // seatbelt (the unconfined control is refused too), so this test accepts
    // `NotMet { failed: [TaskForPid] }` there and only there. T21 asserts
    // Blocked with the hardened bundled app as the target.
    println!(
        "FLOOR_SCOPE seatbelt_probes=5 task_for_pid_informative={informative} watchdog=M8 (macOS floor Met here means the seatbelt only; the memory watchdog is not wired yet)"
    );
    match &report.floor {
        FloorVerdict::Met => {}
        FloorVerdict::NotMet { failed } => {
            assert!(
                !informative,
                "the floor failed although the control is informative: {:?}",
                report.floor
            );
            assert_eq!(
                failed,
                &vec![ProbeId::TaskForPid],
                "floor: {:?}",
                report.floor
            );
        }
    }
}

/// Runs inside the `task_for_pid` control child only; a no-op in the normal
/// test run. The child is unconfined and asks for its parent's task port.
#[test]
fn tfp_control_child() {
    if std::env::var_os(TFP_CHILD_ENV).is_none() {
        return;
    }
    // libSystem exports these; `libc` declares neither.
    unsafe extern "C" {
        static mach_task_self_: libc::mach_port_t;
        fn task_for_pid(
            target_tport: libc::mach_port_t,
            pid: libc::c_int,
            task: *mut libc::mach_port_t,
        ) -> libc::kern_return_t;
        fn mach_port_deallocate(
            task: libc::mach_port_t,
            name: libc::mach_port_t,
        ) -> libc::kern_return_t;
    }
    // SAFETY: `getppid` takes no arguments.
    let parent = unsafe { libc::getppid() };
    let mut task: libc::mach_port_t = 0;
    // SAFETY: `task` is a valid out pointer; `mach_task_self_` is set by libSystem.
    let kr = unsafe { task_for_pid(mach_task_self_, parent, &mut task) };
    if kr == 0 {
        // SAFETY: releases the send right the successful call returned.
        unsafe { mach_port_deallocate(mach_task_self_, task) };
    }
    println!("TFP_CONTROL kr={kr}");
    std::process::exit(0);
}

#[test]
fn the_binary_identity_and_versions_are_recorded() {
    let _guard = serial();
    let report = report();
    let identity = report.identity.as_ref().expect("identity is recorded");
    assert!(
        matches!(identity.file_id, FileId::DevIno { .. }),
        "{identity:?}"
    );
    assert!(identity.size > 0);
    assert_eq!(
        Some(&identity.embedded_version),
        report.worker_version.as_ref()
    );
    assert!(report.engine_version.is_some());
    if std::env::var_os("ATLAS_DUCK_SANDBOX_BIN").is_none() {
        assert_eq!(report.worker_version.as_deref(), Some(BUILD_ID));
    }
    // Landlock is a Linux layer: nothing is reported on macOS.
    assert!(report.extra_layers.is_empty(), "{:?}", report.extra_layers);
}

#[test]
fn the_engine_self_test_passes_under_the_profile() {
    let _guard = serial();
    let answer = Session::start().ask(ProbeId::EngineSelfTest, "");
    println!(
        "ENGINE_SELFTEST outcome={:?} detail={:?} exit={:?} stderr={:?}",
        answer.msg.outcome, answer.msg.detail, answer.exit, answer.stderr
    );
    assert_eq!(
        answer.msg.outcome,
        ProbeOutcome::Allowed,
        "detail: {:?}",
        answer.msg.detail
    );
    assert_eq!(answer.exit, Some(ExitKind::Code(0)));
}

#[test]
fn the_worker_environment_is_exactly_tz() {
    let _guard = serial();
    let answer = Session::start().ask(ProbeId::EnvNames, "");
    let mut names = answer
        .msg
        .env_names
        .clone()
        .expect("EnvNames returns env_names");
    names.sort();
    println!("ENV_NAMES {names:?}");
    assert_eq!(names, vec!["TZ".to_string()]);
}

#[test]
fn the_worker_has_only_fds_0_1_2_and_cwd_slash_after_ready() {
    let _guard = serial();
    // An inheritable descriptor that must not reach the worker.
    // SAFETY: plain `open` of /dev/null without O_CLOEXEC.
    let leak = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    assert!(leak > 2, "test setup: the leak fd is {leak}");

    let mut session = Session::start();
    assert!(
        session.ready.confinement.applied,
        "{:?}",
        session.ready.confinement
    );
    let pid = session.worker.pid();
    let fds = fds_of(pid);
    let cwd = cwd_of(pid);
    println!("HYGIENE pid={pid} fds={fds:?} cwd={cwd:?} leak_fd_in_host={leak}");
    // SAFETY: `leak` was opened above.
    unsafe { libc::close(leak) };
    assert_eq!(fds, vec![0, 1, 2]);
    assert_eq!(cwd, "/");

    // §3.4: the worker exits on stdin EOF (macOS has no parent-death signal).
    session.worker.close_stdin();
    assert_eq!(
        session.worker.wait_timeout(TIMEOUT).expect("wait"),
        Some(ExitKind::Code(0)),
        "stderr: {}",
        session.worker.stderr_tail()
    );
}

/// §15 V10: `RLIMIT_AS` is a no-op on Darwin, so the memory limit is the M8
/// host-side watchdog. The measurement runs in a child process (the limit
/// cannot be raised again) and is printed for the go/no-go record.
#[test]
fn rlimit_as_is_not_enforced_on_this_macos_image() {
    let _guard = serial();
    let exe = std::env::current_exe().expect("current_exe");
    let out = Command::new(exe)
        .args([
            "--exact",
            "v10_child_body",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(V10_CHILD_ENV, "1")
        .output()
        .expect("spawn the V10 child");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let line = stdout
        .lines()
        .find(|l| l.starts_with("V10 "))
        .unwrap_or("V10 (no line)");
    println!("{line}");
    assert!(
        out.status.success()
            && line.contains("touched=true")
            && line.contains("rlimit_as_enforced=false"),
        "allocating 256 MiB under RLIMIT_AS=64 MiB failed, so RLIMIT_AS looks ENFORCED: {:?}\n{stdout}\n{stderr}",
        out.status
    );
}

/// Runs inside the V10 child only; a no-op in the normal test run. The
/// `rlimit_as_enforced` field is measured (the 256 MiB mapping is refused
/// under an enforced limit), not assumed.
#[test]
fn v10_child_body() {
    if std::env::var_os(V10_CHILD_ENV).is_none() {
        return;
    }
    const MIB: u64 = 1024 * 1024;
    let mut before = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `before` is a valid out pointer.
    let got = unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut before) };
    let limit = libc::rlimit {
        rlim_cur: 64 * MIB,
        rlim_max: before.rlim_max,
    };
    // SAFETY: `limit` is a valid in pointer.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) };
    let errno = if rc == 0 {
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    };
    let mut after = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `after` is a valid out pointer.
    unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut after) };

    // A direct mapping, so that an enforced limit shows up as MAP_FAILED
    // instead of the allocation-failure abort a `Vec` would give.
    let len = (256 * MIB) as usize;
    // SAFETY: an anonymous private mapping; the result is checked below.
    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    let enforced = map == libc::MAP_FAILED;
    let mut touched = false;
    if !enforced {
        let base = map.cast::<u8>();
        let mut pages = 0u64;
        for offset in (0..len).step_by(4096) {
            // SAFETY: `offset < len`, inside the mapping.
            unsafe { base.add(offset).write_volatile(1) };
            pages += 1;
        }
        touched = pages == 256 * MIB / 4096;
        // SAFETY: unmaps the mapping created above.
        unsafe { libc::munmap(map, len) };
    }
    println!(
        "V10 arch={} getrlimit_rc={got} setrlimit_rc={rc} errno={errno} rlim_cur_after={} alloc_mib=256 touched={touched} rlimit_as_enforced={enforced}",
        std::env::consts::ARCH,
        after.rlim_cur,
    );
    std::process::exit(0);
}
