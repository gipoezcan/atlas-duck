//! Windows scoring (§9.4) through `run_probes` with a scripted fake spawner on
//! every OS: the host's loopback listener, the unconfined control and the
//! host-side re-scoring. The fake "unconfined" worker really connects to the
//! listener it is given (a plain `TcpStream` from the test process), so the
//! arrival evidence is real; the fake "confined" worker connects or not as
//! scripted. The pure rules are unit-tested in `winscore.rs`; the real
//! AppContainer is in `app/src-tauri/tests/probes_windows.rs`.

use std::collections::VecDeque;
use std::io::{self, Cursor, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use atlas_duck_ipc::sandbox::MAX_FRAME_BYTES;
use atlas_duck_ipc::sandbox::frame::read_frame;
use atlas_duck_ipc::sandbox::probe::{
    ConfinementReport, DETAIL_CONNECT_REACHED, DETAIL_CONNECTED, M_PROBE_READY, M_PROBE_RESULT,
    ProbeId, ProbeOutcome, ProbeReady, ProbeRequest, ProbeResultMsg, decode_notification,
    encode_notification, wsastartup_failed_detail,
};
use atlas_duck_sandbox_host::probe::{Evidence, ProbeConfig, ProbeReport, run_probes};
use atlas_duck_sandbox_host::spawn::{ExitKind, SpawnSpec, WorkerProcess, WorkerSpawner};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Confined,
    Control,
}

/// What the confined fake does on `ConnectLoopback`.
#[derive(Clone, Copy)]
enum Loopback {
    /// Never connects; reports a bare timeout (the plain-AppContainer case).
    Timeout,
    /// Connects to the address it was given and reports success.
    Connects,
    /// `WSAStartup` failed with this code (the LPAC case).
    Wsa(i64),
}

#[derive(Clone, Copy)]
struct Behaviour {
    lpac: bool,
    loopback: Loopback,
    /// `CredRead` of the confined worker.
    cred: (ProbeOutcome, i64),
    control_available: bool,
    /// The unconfined worker's `CredRead` code.
    control_cred: i64,
    /// The unconfined worker connects to the listener.
    control_connects: bool,
}

impl Behaviour {
    fn plain() -> Self {
        Self {
            lpac: false,
            loopback: Loopback::Timeout,
            cred: (ProbeOutcome::Blocked, 5),
            control_available: true,
            control_cred: 1168,
            control_connects: true,
        }
    }

    fn lpac() -> Self {
        Self {
            lpac: true,
            loopback: Loopback::Wsa(10107),
            cred: (ProbeOutcome::Error, 1702),
            ..Self::plain()
        }
    }
}

struct Fake(Behaviour);

impl WorkerSpawner for Fake {
    fn spawn(&self, _spec: &SpawnSpec) -> io::Result<Box<dyn WorkerProcess>> {
        Ok(Box::new(Proc::new(Role::Confined, self.0)))
    }

    fn spawn_control(&self, _spec: &SpawnSpec) -> io::Result<Box<dyn WorkerProcess>> {
        if self.0.control_available {
            Ok(Box::new(Proc::new(Role::Control, self.0)))
        } else {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }
}

struct Proc {
    role: Role,
    b: Behaviour,
    frames: VecDeque<Vec<u8>>,
    stdin: Vec<u8>,
    answered: bool,
}

impl Proc {
    fn new(role: Role, b: Behaviour) -> Self {
        let ready = ProbeReady {
            worker_version: "0.1.0+fake".to_owned(),
            engine_version: "fake".to_owned(),
            confinement: ConfinementReport {
                applied: role == Role::Confined,
                mechanism: "appcontainer".to_owned(),
                no_new_privs: None,
                landlock_abi: None,
                seccomp: None,
                lpac: Some(role == Role::Confined && b.lpac),
                os_error: None,
            },
        };
        Self {
            role,
            b,
            frames: VecDeque::from([encode_notification(M_PROBE_READY, &ready)]),
            stdin: Vec::new(),
            answered: false,
        }
    }

    fn answer(&mut self, req: &ProbeRequest) -> ProbeResultMsg {
        let msg = |outcome, os_error, detail: &str| ProbeResultMsg {
            probe: req.probe,
            outcome,
            os_error,
            detail: Some(detail.to_owned()),
            env_names: None,
        };
        match (self.role, req.probe) {
            (Role::Control, ProbeId::ConnectLoopback) => {
                if self.b.control_connects {
                    let s = TcpStream::connect_timeout(
                        &req.loopback_addr.parse().expect("addr"),
                        Duration::from_secs(2),
                    )
                    .expect("the unconfined fake reaches the listener");
                    // keep the connection open until the host accepted it
                    std::mem::forget(s);
                    msg(ProbeOutcome::Allowed, None, DETAIL_CONNECTED)
                } else {
                    msg(
                        ProbeOutcome::Error,
                        Some(10107),
                        &wsastartup_failed_detail(10107),
                    )
                }
            }
            (Role::Control, ProbeId::CredRead) => match self.b.control_cred {
                1168 => msg(
                    ProbeOutcome::Allowed,
                    Some(1168),
                    "CredReadW reached the credential store",
                ),
                code => msg(
                    ProbeOutcome::Error,
                    Some(code),
                    "CredReadW failed unexpectedly",
                ),
            },
            (Role::Confined, ProbeId::ConnectLoopback) => match self.b.loopback {
                Loopback::Timeout => msg(ProbeOutcome::Allowed, None, DETAIL_CONNECT_REACHED),
                Loopback::Connects => {
                    let s = TcpStream::connect_timeout(
                        &req.loopback_addr.parse().expect("addr"),
                        Duration::from_secs(2),
                    )
                    .expect("connect");
                    std::mem::forget(s);
                    msg(ProbeOutcome::Allowed, None, DETAIL_CONNECTED)
                }
                Loopback::Wsa(code) => msg(
                    ProbeOutcome::Error,
                    Some(code),
                    &wsastartup_failed_detail(code),
                ),
            },
            (Role::Confined, ProbeId::ConnectPublic) => match self.b.loopback {
                Loopback::Wsa(code) => msg(
                    ProbeOutcome::Error,
                    Some(code),
                    &wsastartup_failed_detail(code),
                ),
                _ => msg(ProbeOutcome::Blocked, Some(10013), "connect denied"),
            },
            (Role::Confined, ProbeId::CredRead) => {
                msg(self.b.cred.0, Some(self.b.cred.1), "CredReadW")
            }
            _ => msg(ProbeOutcome::Blocked, Some(5), "denied"),
        }
    }

    fn process_stdin(&mut self) {
        if self.answered || self.stdin.is_empty() {
            return;
        }
        self.answered = true;
        let mut cursor = Cursor::new(std::mem::take(&mut self.stdin));
        while let Ok(Some(payload)) = read_frame(&mut cursor, MAX_FRAME_BYTES) {
            let (_, params) = decode_notification(&payload).expect("notification");
            let req: ProbeRequest = serde_json::from_value(params).expect("request");
            let res = self.answer(&req);
            self.frames
                .push_back(encode_notification(M_PROBE_RESULT, &res));
        }
    }
}

impl WorkerProcess for Proc {
    fn pid(&self) -> u32 {
        4000
    }

    fn stdin(&mut self) -> &mut dyn Write {
        &mut self.stdin
    }

    fn read_frame_timeout(&mut self, _max: usize, _d: Duration) -> io::Result<Option<Vec<u8>>> {
        self.process_stdin();
        Ok(self.frames.pop_front())
    }

    fn close_stdin(&mut self) {}

    fn wait_timeout(&mut self, _d: Duration) -> io::Result<Option<ExitKind>> {
        Ok(Some(ExitKind::Code(0)))
    }

    fn kill(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn run(b: Behaviour) -> ProbeReport {
    // `run_probes` needs a worker file it can inspect; the fake never runs it.
    let dir = std::env::temp_dir().join(format!("atlas-duck-winscore-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let worker = dir.join("worker-fake");
    std::fs::write(&worker, b"fake worker").expect("write");
    let mut cfg = ProbeConfig::new(worker, 4242, PathBuf::from("profile"));
    cfg.windows_controls = true;
    cfg.per_probe_timeout = Duration::from_secs(5);
    run_probes(&Fake(b), None, &cfg)
}

/// Probes of the fixed list that exist on this OS's floor (`CredRead` is
/// Windows-only; the runner only runs the current OS's floor).
fn on_this_floor(probes: &[(ProbeId, i64)]) -> Vec<(ProbeId, i64)> {
    probes
        .iter()
        .copied()
        .filter(|(p, _)| ProbeId::floor_probes_for_current_os().contains(p))
        .collect()
}

fn rec(report: &ProbeReport, probe: ProbeId) -> (ProbeOutcome, Evidence) {
    let r = report
        .records
        .iter()
        .find(|r| r.probe == probe)
        .unwrap_or_else(|| panic!("no record for {probe:?}"));
    (r.outcome, r.evidence)
}

#[test]
fn a_timeout_with_no_arrival_and_a_working_control_is_blocked() {
    let report = run(Behaviour::plain());
    let control = report.control.expect("control ran");
    assert!(
        control.listener && control.winsock && control.cred,
        "{control:?}"
    );
    assert_eq!(
        rec(&report, ProbeId::ConnectLoopback),
        (
            ProbeOutcome::Blocked,
            Evidence::ListenerArrival {
                os_error: None,
                arrived: false,
                control_ok: true
            }
        )
    );
}

#[test]
fn a_connection_that_arrives_at_the_listener_is_allowed() {
    let report = run(Behaviour {
        loopback: Loopback::Connects,
        ..Behaviour::plain()
    });
    assert_eq!(
        rec(&report, ProbeId::ConnectLoopback),
        (
            ProbeOutcome::Allowed,
            Evidence::ListenerArrival {
                os_error: None,
                arrived: true,
                control_ok: true
            }
        )
    );
}

#[test]
fn without_a_control_worker_a_timeout_is_an_error_not_blocked() {
    for b in [
        Behaviour {
            control_available: false,
            ..Behaviour::plain()
        },
        Behaviour {
            control_connects: false,
            ..Behaviour::plain()
        },
    ] {
        let report = run(b);
        let control = report.control.expect("control attempted");
        assert!(
            control.listener,
            "the host self-check still works: {control:?}"
        );
        assert!(!control.winsock, "{control:?}");
        assert_eq!(
            rec(&report, ProbeId::ConnectLoopback).0,
            ProbeOutcome::Error
        );
    }
}

#[test]
fn lpac_stack_failures_are_blocked_only_with_the_control() {
    let report = run(Behaviour::lpac());
    for (probe, code) in on_this_floor(&[
        (ProbeId::ConnectLoopback, 10107),
        (ProbeId::ConnectPublic, 10107),
        (ProbeId::CredRead, 1702),
    ]) {
        assert_eq!(
            rec(&report, probe),
            (
                ProbeOutcome::Blocked,
                Evidence::StackUnavailable {
                    os_error: code,
                    control_ok: true
                }
            ),
            "{probe:?}"
        );
    }

    // an unconfined worker that cannot read the credential store normally
    // makes the 1702 an Error (the cred fact is uncontrolled)
    let report = run(Behaviour {
        control_cred: 1722,
        ..Behaviour::lpac()
    });
    if cfg!(windows) {
        assert_eq!(rec(&report, ProbeId::CredRead).0, ProbeOutcome::Error);
    }
    assert_eq!(
        rec(&report, ProbeId::ConnectPublic).0,
        ProbeOutcome::Blocked,
        "the net control is independent of the cred control"
    );

    // no control worker at all
    let report = run(Behaviour {
        control_available: false,
        ..Behaviour::lpac()
    });
    for (probe, _) in on_this_floor(&[
        (ProbeId::ConnectLoopback, 0),
        (ProbeId::ConnectPublic, 0),
        (ProbeId::CredRead, 0),
    ]) {
        assert_eq!(rec(&report, probe).0, ProbeOutcome::Error, "{probe:?}");
    }
}

#[test]
fn without_windows_controls_the_workers_own_scoring_stands() {
    let dir = std::env::temp_dir().join(format!("atlas-duck-winscore-off-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let worker = dir.join("worker-fake");
    std::fs::write(&worker, b"fake worker").expect("write");
    let mut cfg = ProbeConfig::new(worker, 4242, PathBuf::from("profile"));
    cfg.windows_controls = false;
    let report = run_probes(&Fake(Behaviour::lpac()), None, &cfg);
    assert!(report.control.is_none());
    assert_eq!(
        rec(&report, ProbeId::ConnectLoopback).0,
        ProbeOutcome::Error
    );
    assert!(matches!(
        rec(&report, ProbeId::ConnectLoopback).1,
        Evidence::Reported { .. }
    ));
}
