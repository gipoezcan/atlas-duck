//! T15: probe scoring, floor verdict, run_probes against a scripted fake
//! spawner, and the sandbox binary identity. Runs on every OS; the
//! `cfg(target_os = "linux")` arms run in the ubuntu-22.04 leg of the `rust`
//! job in ci.yml.

use std::io::{self, Cursor, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atlas_duck_ipc::sandbox::MAX_FRAME_BYTES;
use atlas_duck_ipc::sandbox::frame::read_frame;
use atlas_duck_ipc::sandbox::probe::{
    ConfinementReport, LOOPBACK_PROBE_ADDR, M_PROBE_READY, M_PROBE_RESULT, M_PROBE_RUN,
    PUBLIC_PROBE_ADDR, ProbeId, ProbeOutcome, ProbeReady, ProbeRequest, ProbeResultMsg,
    decode_notification, encode_notification,
};
use atlas_duck_sandbox_host::identity::{FileId, file_identity};
use atlas_duck_sandbox_host::probe::{
    Evidence, FloorVerdict, ProbeConfig, ProbeReport, run_probes, score,
};
use atlas_duck_sandbox_host::spawn::{
    DEFAULT_PROCESS_MB, ExitKind, SpawnHook, SpawnSpec, ThreadConfinement, WorkerProcess,
    WorkerSpawner,
};

const WORKER_VERSION: &str = "0.1.0+0123456789ab";
const ENGINE_VERSION: &str = "quickjs-ng-test";
const APP_PID: u32 = 4242;

const ALL_PROBES: [ProbeId; 16] = [
    ProbeId::FileInProfile,
    ProbeId::ConnectLoopback,
    ProbeId::ConnectPublic,
    ProbeId::SpawnProcess,
    ProbeId::RawClone,
    ProbeId::Clone3,
    ProbeId::MemReadProcessVm,
    ProbeId::MemReadProcMem,
    ProbeId::TaskForPid,
    ProbeId::OpenProcessVmRead,
    ProbeId::CredRead,
    ProbeId::OpenClipboard,
    ProbeId::MachLookupSecurityd,
    ProbeId::EngineSelfTest,
    ProbeId::EnvNames,
    ProbeId::HandleSentinel,
];

// ---------------------------------------------------------------- helpers

fn result_msg(probe: ProbeId, outcome: ProbeOutcome, os_error: Option<i64>) -> ProbeResultMsg {
    ProbeResultMsg {
        probe,
        outcome,
        os_error,
        detail: None,
        env_names: None,
    }
}

fn confinement(applied: bool, mechanism: &str, landlock_abi: Option<u32>) -> ConfinementReport {
    ConfinementReport {
        applied,
        mechanism: mechanism.to_string(),
        no_new_privs: None,
        landlock_abi,
        seccomp: None,
        lpac: None,
        os_error: None,
    }
}

fn floor() -> Vec<ProbeId> {
    ProbeId::floor_probes_for_current_os().to_vec()
}

fn run_order() -> Vec<ProbeId> {
    let mut v = floor();
    v.push(ProbeId::EngineSelfTest);
    v.push(ProbeId::EnvNames);
    v
}

static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A fresh, unique directory under the OS temp dir.
fn temp_dir() -> PathBuf {
    let n = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("atlas-duck-t15-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// A stand-in worker binary (the fake spawner never executes it).
fn worker_file() -> PathBuf {
    let path = temp_dir().join("atlas-duck-sandbox-fake");
    std::fs::write(&path, b"fake worker binary").expect("write fake worker");
    path
}

fn config(worker: PathBuf, timeout: Duration) -> ProbeConfig {
    ProbeConfig {
        worker,
        app_pid: APP_PID,
        profile_path: PathBuf::from("/home/someone/.profile-probe-target"),
        per_probe_timeout: timeout,
    }
}

fn record_of(report: &ProbeReport, probe: ProbeId) -> (ProbeOutcome, Evidence) {
    let r = report
        .records
        .iter()
        .find(|r| r.probe == probe)
        .unwrap_or_else(|| panic!("no record for {probe:?}"));
    (r.outcome, r.evidence)
}

// ------------------------------------------------------------- fake spawner

#[derive(Clone)]
enum Ready {
    Frame(ConfinementReport),
    Eof,
    Garbage,
    Hang,
}

#[derive(Clone)]
enum Answer {
    Report(ProbeOutcome, Option<i64>),
    WrongProbe,
    Eof,
    Hang,
}

#[derive(Clone)]
struct Script {
    answer: Answer,
    /// `None`: the process never exits by itself.
    exit: Option<ExitKind>,
}

#[derive(Default)]
struct Log {
    spawns: Vec<SpawnSpec>,
    requests: Vec<ProbeRequest>,
    killed: Vec<u32>,
    /// (pid, timeout passed to read_frame_timeout)
    read_timeouts: Vec<(u32, Duration)>,
}

struct FakeSpawner {
    ready: Ready,
    ready_by_spawn: Vec<(usize, Ready)>,
    default: Script,
    by_probe: Vec<(ProbeId, Script)>,
    spawn_error: Option<i32>,
    log: Arc<Mutex<Log>>,
}

impl FakeSpawner {
    /// Every worker confines itself, reports Blocked (EACCES-like 13) and exits 0;
    /// the diagnostics report Allowed.
    fn all_blocked() -> Self {
        Self {
            ready: Ready::Frame(confinement(true, "fake", None)),
            ready_by_spawn: Vec::new(),
            default: Script {
                answer: Answer::Report(ProbeOutcome::Blocked, Some(13)),
                exit: Some(ExitKind::Code(0)),
            },
            by_probe: vec![
                (
                    ProbeId::EngineSelfTest,
                    Script {
                        answer: Answer::Report(ProbeOutcome::Allowed, None),
                        exit: Some(ExitKind::Code(0)),
                    },
                ),
                (
                    ProbeId::EnvNames,
                    Script {
                        answer: Answer::Report(ProbeOutcome::Allowed, None),
                        exit: Some(ExitKind::Code(0)),
                    },
                ),
            ],
            spawn_error: None,
            log: Arc::new(Mutex::new(Log::default())),
        }
    }

    fn with_probe(mut self, probe: ProbeId, answer: Answer, exit: Option<ExitKind>) -> Self {
        self.by_probe.retain(|(p, _)| *p != probe);
        self.by_probe.push((probe, Script { answer, exit }));
        self
    }

    fn with_ready(mut self, ready: Ready) -> Self {
        self.ready = ready;
        self
    }

    fn with_ready_at(mut self, spawn_index: usize, ready: Ready) -> Self {
        self.ready_by_spawn.push((spawn_index, ready));
        self
    }

    fn failing(raw_os_error: i32) -> Self {
        let mut s = Self::all_blocked();
        s.spawn_error = Some(raw_os_error);
        s
    }

    fn log(&self) -> std::sync::MutexGuard<'_, Log> {
        self.log.lock().expect("log lock")
    }
}

impl WorkerSpawner for FakeSpawner {
    fn spawn(&self, spec: &SpawnSpec) -> io::Result<Box<dyn WorkerProcess>> {
        if let Some(code) = self.spawn_error {
            return Err(io::Error::from_raw_os_error(code));
        }
        let mut log = self.log.lock().expect("log lock");
        let index = log.spawns.len();
        log.spawns.push(spec.clone());
        let ready = self
            .ready_by_spawn
            .iter()
            .find(|(i, _)| *i == index)
            .map_or_else(|| self.ready.clone(), |(_, r)| r.clone());
        Ok(Box::new(FakeProcess {
            pid: 1000 + u32::try_from(index).expect("small index"),
            ready,
            default: self.default.clone(),
            by_probe: self.by_probe.clone(),
            stdin: Vec::new(),
            stdin_closed: false,
            stage: 0,
            script: None,
            killed: false,
            log: Arc::clone(&self.log),
        }))
    }
}

struct FakeProcess {
    pid: u32,
    ready: Ready,
    default: Script,
    by_probe: Vec<(ProbeId, Script)>,
    stdin: Vec<u8>,
    stdin_closed: bool,
    stage: u8,
    script: Option<Script>,
    killed: bool,
    log: Arc<Mutex<Log>>,
}

impl FakeProcess {
    fn hang(d: Duration) -> io::Result<Option<Vec<u8>>> {
        std::thread::sleep(d);
        Err(io::Error::new(io::ErrorKind::TimedOut, "fake: no frame"))
    }

    /// Decodes the probe.run frame the runner wrote to stdin.
    fn take_request(&mut self) -> Option<ProbeRequest> {
        let payload = read_frame(&mut Cursor::new(&self.stdin), MAX_FRAME_BYTES).ok()??;
        let (method, params) = decode_notification(&payload).ok()?;
        assert_eq!(method, M_PROBE_RUN);
        let req: ProbeRequest = serde_json::from_value(params).ok()?;
        self.log
            .lock()
            .expect("log lock")
            .requests
            .push(req.clone());
        Some(req)
    }
}

impl WorkerProcess for FakeProcess {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn stdin(&mut self) -> &mut dyn Write {
        &mut self.stdin
    }

    fn read_frame_timeout(&mut self, _max: usize, d: Duration) -> io::Result<Option<Vec<u8>>> {
        self.log
            .lock()
            .expect("log lock")
            .read_timeouts
            .push((self.pid, d));
        self.stage += 1;
        match self.stage {
            1 => match self.ready.clone() {
                Ready::Frame(c) => Ok(Some(encode_notification(
                    M_PROBE_READY,
                    &ProbeReady {
                        worker_version: WORKER_VERSION.to_string(),
                        engine_version: ENGINE_VERSION.to_string(),
                        confinement: c,
                    },
                ))),
                Ready::Eof => Ok(None),
                Ready::Garbage => Ok(Some(b"not json".to_vec())),
                Ready::Hang => Self::hang(d),
            },
            2 => {
                assert!(self.stdin_closed, "runner must close stdin after probe.run");
                let Some(req) = self.take_request() else {
                    return Ok(None);
                };
                let script = self
                    .by_probe
                    .iter()
                    .find(|(p, _)| *p == req.probe)
                    .map_or_else(|| self.default.clone(), |(_, s)| s.clone());
                self.script = Some(script.clone());
                match script.answer {
                    Answer::Report(outcome, os_error) => Ok(Some(encode_notification(
                        M_PROBE_RESULT,
                        &result_msg(req.probe, outcome, os_error),
                    ))),
                    Answer::WrongProbe => {
                        let other = if req.probe == ProbeId::EnvNames {
                            ProbeId::EngineSelfTest
                        } else {
                            ProbeId::EnvNames
                        };
                        Ok(Some(encode_notification(
                            M_PROBE_RESULT,
                            &result_msg(other, ProbeOutcome::Blocked, None),
                        )))
                    }
                    Answer::Eof => Ok(None),
                    Answer::Hang => Self::hang(d),
                }
            }
            _ => Ok(None),
        }
    }

    fn close_stdin(&mut self) {
        self.stdin_closed = true;
    }

    fn wait_timeout(&mut self, d: Duration) -> io::Result<Option<ExitKind>> {
        if self.killed {
            return Ok(Some(ExitKind::Signal(9)));
        }
        match self.script.as_ref().and_then(|s| s.exit) {
            Some(exit) => Ok(Some(exit)),
            None => {
                std::thread::sleep(d);
                Ok(None)
            }
        }
    }

    fn kill(&mut self) -> io::Result<()> {
        self.killed = true;
        self.log.lock().expect("log lock").killed.push(self.pid);
        Ok(())
    }
}

struct FakeHook {
    result: Option<ThreadConfinement>,
    pids: Mutex<Vec<u32>>,
}

impl FakeHook {
    fn new(result: Option<ThreadConfinement>) -> Self {
        Self {
            result,
            pids: Mutex::new(Vec::new()),
        }
    }
}

impl SpawnHook for FakeHook {
    fn after_ready(&self, pid: u32) -> Option<ThreadConfinement> {
        self.pids.lock().expect("hook lock").push(pid);
        self.result
    }
}

const CONFINED: ThreadConfinement = ThreadConfinement {
    tasks: 1,
    all_seccomp_2: true,
    all_no_new_privs_1: true,
};

// ------------------------------------------------------------------ score()

#[test]
fn score_reported_blocked_is_blocked_reported() {
    let msg = result_msg(ProbeId::FileInProfile, ProbeOutcome::Blocked, Some(13));
    assert_eq!(
        score(ProbeId::FileInProfile, Some(&msg), Some(ExitKind::Code(0))),
        (
            ProbeOutcome::Blocked,
            Evidence::Reported { os_error: Some(13) }
        )
    );
}

#[test]
fn score_reported_allowed_and_error_pass_through() {
    let allowed = result_msg(ProbeId::ConnectPublic, ProbeOutcome::Allowed, None);
    assert_eq!(
        score(
            ProbeId::ConnectPublic,
            Some(&allowed),
            Some(ExitKind::Code(0))
        ),
        (ProbeOutcome::Allowed, Evidence::Reported { os_error: None })
    );
    let error = result_msg(ProbeId::ConnectPublic, ProbeOutcome::Error, Some(22));
    assert_eq!(
        score(ProbeId::ConnectPublic, Some(&error), None),
        (
            ProbeOutcome::Error,
            Evidence::Reported { os_error: Some(22) }
        )
    );
}

#[cfg(target_os = "linux")]
#[test]
fn score_sigsys_without_result_is_blocked_on_linux_for_floor_probes_only() {
    assert_eq!(
        score(ProbeId::ConnectPublic, None, Some(ExitKind::Signal(31))),
        (ProbeOutcome::Blocked, Evidence::KilledBySigsys)
    );
    // A diagnostic must never hit a kill rule.
    assert_eq!(
        score(ProbeId::EngineSelfTest, None, Some(ExitKind::Signal(31))),
        (ProbeOutcome::Error, Evidence::KilledBySigsys)
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn score_signal_31_is_an_error_off_linux() {
    assert_eq!(
        score(ProbeId::ConnectPublic, None, Some(ExitKind::Signal(31))),
        (ProbeOutcome::Error, Evidence::Signaled(31))
    );
}

#[test]
fn score_crash_exit_and_timeout_are_errors() {
    assert_eq!(
        score(ProbeId::SpawnProcess, None, Some(ExitKind::Signal(11))),
        (ProbeOutcome::Error, Evidence::Signaled(11))
    );
    assert_eq!(
        score(ProbeId::SpawnProcess, None, Some(ExitKind::Code(0))),
        (ProbeOutcome::Error, Evidence::Exited(0))
    );
    assert_eq!(
        score(ProbeId::SpawnProcess, None, None),
        (ProbeOutcome::Error, Evidence::Timeout)
    );
}

#[test]
fn score_never_turns_a_crash_or_timeout_into_blocked() {
    let mut exits = vec![
        None,
        Some(ExitKind::Code(0)),
        Some(ExitKind::Code(1)),
        Some(ExitKind::Code(3)),
        Some(ExitKind::Code(-1_073_741_819)), // 0xC0000005 access violation
        Some(ExitKind::Signal(6)),
        Some(ExitKind::Signal(9)),
        Some(ExitKind::Signal(11)),
    ];
    if !cfg!(target_os = "linux") {
        exits.push(Some(ExitKind::Signal(31)));
    }
    for probe in ALL_PROBES {
        for exit in &exits {
            let (outcome, _) = score(probe, None, *exit);
            assert_ne!(outcome, ProbeOutcome::Blocked, "{probe:?} {exit:?}");
        }
    }
}

// ------------------------------------------------------------- run_probes()

#[test]
fn every_floor_probe_blocked_and_threads_confined_meets_the_floor() {
    let worker = worker_file();
    let spawner = FakeSpawner::all_blocked();
    let hook = FakeHook::new(Some(CONFINED));
    let report = run_probes(
        &spawner,
        Some(&hook),
        &config(worker, Duration::from_secs(5)),
    );

    assert_eq!(report.floor, FloorVerdict::Met);
    let log = spawner.log();
    // One spawn per floor probe plus one each for EngineSelfTest and EnvNames.
    assert_eq!(log.spawns.len(), floor().len() + 2);
    let asked: Vec<ProbeId> = log.requests.iter().map(|r| r.probe).collect();
    assert_eq!(asked, run_order());
    assert_eq!(
        report.records.iter().map(|r| r.probe).collect::<Vec<_>>(),
        run_order()
    );
    for probe in floor() {
        assert_eq!(
            record_of(&report, probe),
            (
                ProbeOutcome::Blocked,
                Evidence::Reported { os_error: Some(13) }
            )
        );
    }
    // The hook ran once per worker, after its ready frame.
    assert_eq!(hook.pids.lock().expect("hook lock").len(), log.spawns.len());
    assert_eq!(report.threads, Some(CONFINED));
    assert_eq!(report.worker_version.as_deref(), Some(WORKER_VERSION));
    assert_eq!(report.engine_version.as_deref(), Some(ENGINE_VERSION));
    assert_eq!(report.confinement, Some(confinement(true, "fake", None)));
    // Workers that answered and exited were not killed.
    assert!(log.killed.is_empty());
}

#[test]
fn one_allowed_floor_probe_fails_the_floor_with_that_probe() {
    let spawner = FakeSpawner::all_blocked().with_probe(
        ProbeId::ConnectLoopback,
        Answer::Report(ProbeOutcome::Allowed, None),
        Some(ExitKind::Code(0)),
    );
    let hook = FakeHook::new(Some(CONFINED));
    let report = run_probes(
        &spawner,
        Some(&hook),
        &config(worker_file(), Duration::from_secs(5)),
    );
    assert_eq!(
        report.floor,
        FloorVerdict::NotMet {
            failed: vec![ProbeId::ConnectLoopback]
        }
    );
    assert_eq!(
        record_of(&report, ProbeId::ConnectLoopback),
        (ProbeOutcome::Allowed, Evidence::Reported { os_error: None })
    );
}

#[test]
fn a_missing_or_invalid_ready_frame_is_noready_and_fails_the_floor() {
    let spawner = FakeSpawner::all_blocked()
        .with_ready_at(0, Ready::Eof)
        .with_ready_at(1, Ready::Garbage);
    let hook = FakeHook::new(Some(CONFINED));
    let report = run_probes(
        &spawner,
        Some(&hook),
        &config(worker_file(), Duration::from_secs(5)),
    );
    let fl = floor();
    assert_eq!(
        record_of(&report, fl[0]),
        (ProbeOutcome::Error, Evidence::NoReady)
    );
    assert_eq!(
        record_of(&report, fl[1]),
        (ProbeOutcome::Error, Evidence::NoReady)
    );
    assert_eq!(
        report.floor,
        FloorVerdict::NotMet {
            failed: vec![fl[0], fl[1]]
        }
    );
    let log = spawner.log();
    // No request is sent to a worker without a ready frame; it is killed.
    assert!(
        log.requests
            .iter()
            .all(|r| r.probe != fl[0] && r.probe != fl[1])
    );
    assert!(log.killed.contains(&1000) && log.killed.contains(&1001));
}

#[test]
fn unconfined_threads_fail_the_floor() {
    let spawner = FakeSpawner::all_blocked();
    let hook = FakeHook::new(Some(ThreadConfinement {
        tasks: 2,
        all_seccomp_2: false,
        all_no_new_privs_1: true,
    }));
    let report = run_probes(
        &spawner,
        Some(&hook),
        &config(worker_file(), Duration::from_secs(5)),
    );
    assert_eq!(report.floor, FloorVerdict::NotMet { failed: floor() });
    assert_eq!(report.threads.map(|t| t.all_seccomp_2), Some(false));
}

#[test]
fn a_hook_that_cannot_check_fails_the_floor() {
    let spawner = FakeSpawner::all_blocked();
    let hook = FakeHook::new(None);
    let report = run_probes(
        &spawner,
        Some(&hook),
        &config(worker_file(), Duration::from_secs(5)),
    );
    assert_eq!(report.floor, FloorVerdict::NotMet { failed: floor() });
    assert_eq!(report.threads, None);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_without_a_thread_hook_does_not_meet_the_floor() {
    let report = run_probes(
        &FakeSpawner::all_blocked(),
        None,
        &config(worker_file(), Duration::from_secs(5)),
    );
    assert_eq!(report.floor, FloorVerdict::NotMet { failed: floor() });
}

#[cfg(not(target_os = "linux"))]
#[test]
fn without_a_hook_the_floor_rests_on_the_probes_off_linux() {
    let report = run_probes(
        &FakeSpawner::all_blocked(),
        None,
        &config(worker_file(), Duration::from_secs(5)),
    );
    assert_eq!(report.floor, FloorVerdict::Met);
    assert_eq!(report.threads, None);
}

#[test]
fn confinement_not_applied_fails_the_floor_even_if_probes_report_blocked() {
    let spawner =
        FakeSpawner::all_blocked().with_ready(Ready::Frame(confinement(false, "none", None)));
    let hook = FakeHook::new(Some(CONFINED));
    let report = run_probes(
        &spawner,
        Some(&hook),
        &config(worker_file(), Duration::from_secs(5)),
    );
    assert_eq!(report.floor, FloorVerdict::NotMet { failed: floor() });
}

#[test]
fn a_failed_engine_selftest_is_recorded_but_does_not_change_the_floor() {
    let spawner = FakeSpawner::all_blocked().with_probe(
        ProbeId::EngineSelfTest,
        Answer::Report(ProbeOutcome::Error, None),
        Some(ExitKind::Code(0)),
    );
    let hook = FakeHook::new(Some(CONFINED));
    let report = run_probes(
        &spawner,
        Some(&hook),
        &config(worker_file(), Duration::from_secs(5)),
    );
    assert_eq!(
        record_of(&report, ProbeId::EngineSelfTest),
        (ProbeOutcome::Error, Evidence::Reported { os_error: None })
    );
    assert_eq!(report.floor, FloorVerdict::Met);
}

#[test]
fn a_crash_without_result_is_an_error_and_a_wrong_probe_result_is_ignored() {
    let spawner = FakeSpawner::all_blocked()
        .with_probe(
            ProbeId::SpawnProcess,
            Answer::Eof,
            Some(ExitKind::Signal(11)),
        )
        .with_probe(
            ProbeId::ConnectPublic,
            Answer::WrongProbe,
            Some(ExitKind::Code(0)),
        );
    let hook = FakeHook::new(Some(CONFINED));
    let report = run_probes(
        &spawner,
        Some(&hook),
        &config(worker_file(), Duration::from_secs(5)),
    );
    assert_eq!(
        record_of(&report, ProbeId::SpawnProcess),
        (ProbeOutcome::Error, Evidence::Signaled(11))
    );
    assert_eq!(
        record_of(&report, ProbeId::ConnectPublic),
        (ProbeOutcome::Error, Evidence::Exited(0))
    );
    assert_eq!(
        report.floor,
        FloorVerdict::NotMet {
            failed: vec![ProbeId::ConnectPublic, ProbeId::SpawnProcess]
        }
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_sigsys_death_of_a_floor_probe_counts_as_blocked() {
    let spawner = FakeSpawner::all_blocked().with_probe(
        ProbeId::RawClone,
        Answer::Eof,
        Some(ExitKind::Signal(31)),
    );
    let hook = FakeHook::new(Some(CONFINED));
    let report = run_probes(
        &spawner,
        Some(&hook),
        &config(worker_file(), Duration::from_secs(5)),
    );
    assert_eq!(
        record_of(&report, ProbeId::RawClone),
        (ProbeOutcome::Blocked, Evidence::KilledBySigsys)
    );
    assert_eq!(report.floor, FloorVerdict::Met);
}

#[test]
fn a_worker_that_never_answers_times_out_and_is_killed() {
    let timeout = Duration::from_millis(100);
    let spawner = FakeSpawner::all_blocked().with_probe(ProbeId::ConnectPublic, Answer::Hang, None);
    let hook = FakeHook::new(Some(CONFINED));
    let report = run_probes(&spawner, Some(&hook), &config(worker_file(), timeout));

    assert_eq!(
        record_of(&report, ProbeId::ConnectPublic),
        (ProbeOutcome::Error, Evidence::Timeout)
    );
    assert_eq!(
        report.floor,
        FloorVerdict::NotMet {
            failed: vec![ProbeId::ConnectPublic]
        }
    );
    let log = spawner.log();
    let index = run_order()
        .iter()
        .position(|p| *p == ProbeId::ConnectPublic)
        .expect("ConnectPublic runs");
    let pid = 1000 + u32::try_from(index).expect("small index");
    assert!(log.killed.contains(&pid), "the hung worker must be killed");
    assert_eq!(log.killed.len(), 1, "only the hung worker is killed");
    // Every read of that worker was bounded by per_probe_timeout.
    let reads: Vec<Duration> = log
        .read_timeouts
        .iter()
        .filter(|(p, _)| *p == pid)
        .map(|(_, d)| *d)
        .collect();
    assert_eq!(reads.len(), 2);
    assert!(reads.iter().all(|d| *d <= timeout));
}

#[test]
fn a_worker_that_hangs_before_ready_times_out_and_is_killed() {
    let timeout = Duration::from_millis(100);
    let spawner = FakeSpawner::all_blocked().with_ready_at(0, Ready::Hang);
    let hook = FakeHook::new(Some(CONFINED));
    let report = run_probes(&spawner, Some(&hook), &config(worker_file(), timeout));
    assert_eq!(
        record_of(&report, floor()[0]),
        (ProbeOutcome::Error, Evidence::Timeout)
    );
    assert!(spawner.log().killed.contains(&1000));
    assert_eq!(
        report.floor,
        FloorVerdict::NotMet {
            failed: vec![floor()[0]]
        }
    );
}

#[test]
fn a_missing_worker_binary_fails_fast_without_spawning() {
    let missing = temp_dir().join("atlas-duck-sandbox-missing");
    let spawner = FakeSpawner::all_blocked();
    let hook = FakeHook::new(Some(CONFINED));
    let started = Instant::now();
    let report = run_probes(
        &spawner,
        Some(&hook),
        &config(missing, Duration::from_secs(10)),
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "must never block startup"
    );

    assert!(spawner.log().spawns.is_empty());
    assert_eq!(report.records.len(), run_order().len());
    for r in &report.records {
        assert_eq!(r.outcome, ProbeOutcome::Error);
        assert!(matches!(r.evidence, Evidence::SpawnFailed(_)), "{r:?}");
    }
    assert_eq!(report.floor, FloorVerdict::NotMet { failed: floor() });
    assert_eq!(report.identity, None);
    assert_eq!(report.worker_version, None);
}

#[test]
fn a_spawn_error_is_recorded_per_probe_with_its_os_error() {
    let spawner = FakeSpawner::failing(5);
    let report = run_probes(
        &spawner,
        None,
        &config(worker_file(), Duration::from_secs(5)),
    );
    for r in &report.records {
        assert_eq!(
            (r.outcome, r.evidence),
            (ProbeOutcome::Error, Evidence::SpawnFailed(5))
        );
    }
    assert_eq!(report.floor, FloorVerdict::NotMet { failed: floor() });
    assert_eq!(report.identity, None);
}

#[test]
fn every_request_carries_the_config_and_the_probe_addresses() {
    let worker = worker_file();
    let cfg = config(worker.clone(), Duration::from_secs(5));
    let spawner = FakeSpawner::all_blocked();
    let hook = FakeHook::new(Some(CONFINED));
    let _ = run_probes(&spawner, Some(&hook), &cfg);

    let log = spawner.log();
    assert_eq!(log.requests.len(), run_order().len());
    for req in &log.requests {
        assert_eq!(req.app_pid, APP_PID);
        assert_eq!(
            req.profile_path,
            cfg.profile_path.to_str().expect("utf-8 test path")
        );
        assert_eq!(req.public_addr, PUBLIC_PROBE_ADDR);
        assert_eq!(req.loopback_addr, LOOPBACK_PROBE_ADDR);
        assert_eq!(req.handle_value, None);
    }
    for spec in &log.spawns {
        assert_eq!(spec.exe, worker);
        assert_eq!(spec.process_mb, DEFAULT_PROCESS_MB);
    }
    assert_eq!(DEFAULT_PROCESS_MB, 512);
}

#[test]
fn landlock_is_an_extra_layer_that_never_changes_the_floor() {
    let hook = FakeHook::new(Some(CONFINED));
    let with = FakeSpawner::all_blocked().with_ready(Ready::Frame(confinement(
        true,
        "seccomp+landlock",
        Some(4),
    )));
    let report = run_probes(
        &with,
        Some(&hook),
        &config(worker_file(), Duration::from_secs(5)),
    );
    assert_eq!(report.extra_layers, vec![("landlock".to_string(), true)]);
    assert_eq!(report.floor, FloorVerdict::Met);

    let without =
        FakeSpawner::all_blocked().with_ready(Ready::Frame(confinement(true, "seccomp", None)));
    let report = run_probes(
        &without,
        Some(&hook),
        &config(worker_file(), Duration::from_secs(5)),
    );
    assert_eq!(report.extra_layers, vec![("landlock".to_string(), false)]);
    assert_eq!(report.floor, FloorVerdict::Met);

    let other = FakeSpawner::all_blocked();
    let report = run_probes(
        &other,
        Some(&hook),
        &config(worker_file(), Duration::from_secs(5)),
    );
    if cfg!(target_os = "linux") {
        assert_eq!(report.extra_layers, vec![("landlock".to_string(), false)]);
    } else {
        assert!(report.extra_layers.is_empty());
    }
}

// ----------------------------------------------------------------- identity

#[test]
fn file_identity_is_stable_for_an_unchanged_file() {
    let path = worker_file();
    let a = file_identity(&path).expect("identity");
    let b = file_identity(&path).expect("identity");
    assert_eq!(a, b);
    assert_eq!(a.1, b"fake worker binary".len() as u64);
    if cfg!(windows) {
        assert!(matches!(a.0, FileId::FileIndex { .. }));
    } else {
        assert!(matches!(a.0, FileId::DevIno { .. }));
    }
}

#[test]
fn rewriting_the_file_changes_its_identity() {
    let path = worker_file();
    let before = file_identity(&path).expect("identity");
    std::fs::write(&path, b"a replaced, longer fake worker binary").expect("rewrite");
    let after = file_identity(&path).expect("identity");
    assert_ne!(before, after);
    assert_ne!(before.1, after.1, "size differs");
}

#[test]
fn file_identity_of_a_missing_file_is_not_found() {
    let err = file_identity(&temp_dir().join("nope")).expect_err("missing");
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn the_report_identity_takes_the_embedded_version_from_probe_ready() {
    let worker = worker_file();
    let (file_id, size, mtime) = file_identity(&worker).expect("identity");
    let hook = FakeHook::new(Some(CONFINED));
    let report = run_probes(
        &FakeSpawner::all_blocked(),
        Some(&hook),
        &config(worker, Duration::from_secs(5)),
    );
    let identity = report.identity.expect("identity recorded");
    assert_eq!(identity.file_id, file_id);
    assert_eq!(identity.size, size);
    assert_eq!(identity.mtime, mtime);
    assert_eq!(identity.embedded_version, WORKER_VERSION);
}

/// A profile path that is not valid UTF-8 cannot travel in `probe.run`; it must
/// fail closed instead of being converted lossily to another path (T19, A24).
#[cfg(windows)]
#[test]
fn a_profile_path_that_is_not_utf8_fails_every_probe_and_spawns_nothing() {
    use std::os::windows::ffi::OsStringExt;

    let mut cfg = config(worker_file(), Duration::from_secs(5));
    cfg.profile_path = PathBuf::from(std::ffi::OsString::from_wide(&[0x43, 0x3A, 0x5C, 0xD800]));
    let spawner = FakeSpawner::all_blocked();
    let report = run_probes(&spawner, None, &cfg);
    assert!(spawner.log().requests.is_empty());
    assert!(
        report
            .records
            .iter()
            .all(|r| r.evidence == Evidence::SpawnFailed(-1))
    );
    assert!(matches!(report.floor, FloorVerdict::NotMet { .. }));
}
