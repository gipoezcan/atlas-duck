//! Host-side scoring of the Windows probes that need a control (§9.4).
//!
//! The worker only reports facts (an error code, a short detail). Three
//! Windows facts say nothing about confinement without a control, so the host
//! scores them here, in one place, from the facts plus evidence it gathered:
//!
//! - `ConnectLoopback` with a host listener: a connection that **arrived** is
//!   `Allowed`. A connect that did not complete is `Blocked` only if no
//!   connection arrived **and** the controls proved the listener reachable
//!   (the host connected to it itself, and an unconfined copy of the worker
//!   connected to it too). A bare timeout is never `Blocked`: a filtered port
//!   times out just the same (measured on the dev box: an unconfined connect to
//!   a closed loopback port hangs).
//! - `ConnectLoopback` / `ConnectPublic` under LPAC when `WSAStartup` fails
//!   with a code from [`LPAC_STACK_CODES`]: the process has no network stack at
//!   all. `Blocked` only if an unconfined worker initialised Winsock fine.
//! - `CredRead` under LPAC when the credential service is unreachable
//!   ([`LPAC_CRED_CODES`]): `Blocked` only if an unconfined worker got the
//!   normal `ERROR_NOT_FOUND` for the same nonexistent target.
//!
//! Without the control the answer is `Error`, never `Blocked` (fail closed).
//! Everything here is plain data and compiles on every OS, so the rules are
//! unit-tested on Linux and macOS as well.

use atlas_duck_ipc::sandbox::probe::{
    DETAIL_CONNECT_REACHED, DETAIL_WSASTARTUP_FAILED, ProbeId, ProbeOutcome, ProbeResultMsg,
};
use serde::Serialize;

use crate::probe::Evidence;

/// `WSASYSCALLFAILURE`: `WSAStartup` under LPAC on Windows 11 (measured on the
/// dev box, build 26200).
pub const WSASYSCALLFAILURE: i64 = 10107;
/// `WSAEPROVIDERFAILEDINIT`: a Winsock provider failed to initialise. Not
/// measured here; it is the other documented way a restricted token cannot
/// bring the stack up.
pub const WSAEPROVIDERFAILEDINIT: i64 = 10106;
/// `WSAStartup` failure codes that mean "this process has no network stack".
pub const LPAC_STACK_CODES: [i64; 2] = [WSASYSCALLFAILURE, WSAEPROVIDERFAILEDINIT];

/// `RPC_S_INVALID_BINDING`: `CredReadW` under LPAC on Windows 11 (measured).
pub const RPC_S_INVALID_BINDING: i64 = 1702;
/// `RPC_S_SERVER_UNAVAILABLE`: the same "credential service unreachable" fact
/// with another spelling. Not measured here.
pub const RPC_S_SERVER_UNAVAILABLE: i64 = 1722;
/// `CredReadW` failure codes that mean "the credential service is unreachable".
pub const LPAC_CRED_CODES: [i64; 2] = [RPC_S_INVALID_BINDING, RPC_S_SERVER_UNAVAILABLE];

/// `ERROR_NOT_FOUND`: what an unconfined `CredReadW` of the probe's
/// nonexistent target returns.
pub const ERROR_NOT_FOUND: i64 = 1168;

/// What the unconfined control found, per fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct WindowsControl {
    /// The host connected to its own loopback listener and accepted.
    pub listener: bool,
    /// An unconfined worker initialised Winsock, connected to the listener
    /// and the connection arrived.
    pub winsock: bool,
    /// An unconfined worker's `CredReadW` of the nonexistent target returned
    /// `ERROR_NOT_FOUND`.
    pub cred: bool,
}

impl WindowsControl {
    /// A control that proved nothing.
    pub const FAILED: WindowsControl = WindowsControl {
        listener: false,
        winsock: false,
        cred: false,
    };

    /// The network facts are controlled.
    pub fn net_ok(&self) -> bool {
        self.listener && self.winsock
    }

    /// Every fact is controlled (the `control_ok` of the log line).
    pub fn ok(&self) -> bool {
        self.net_ok() && self.cred
    }
}

/// What the host knows besides the worker's frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsScoringContext {
    /// `confinement.lpac` of the worker's `probe.ready`.
    pub lpac: Option<bool>,
    /// `None` if no control ran (scoring is then the worker's own).
    pub control: Option<WindowsControl>,
    /// `Some(arrived)` for a `ConnectLoopback` run with a host listener.
    pub loopback_arrived: Option<bool>,
}

fn controlled(ok: bool) -> ProbeOutcome {
    if ok {
        ProbeOutcome::Blocked
    } else {
        ProbeOutcome::Error
    }
}

/// Re-scores one worker result with the host's controls. `None` means the
/// worker's own outcome stands. See the module documentation for the rules.
pub fn rescore(
    probe: ProbeId,
    msg: &ProbeResultMsg,
    ctx: &WindowsScoringContext,
) -> Option<(ProbeOutcome, Evidence)> {
    let control = ctx.control?;
    let code = msg.os_error;
    let detail = msg.detail.as_deref().unwrap_or("");
    match probe {
        ProbeId::ConnectLoopback | ProbeId::ConnectPublic
            if msg.outcome == ProbeOutcome::Error
                && detail.starts_with(DETAIL_WSASTARTUP_FAILED) =>
        {
            let c = code?;
            if ctx.lpac == Some(true) && LPAC_STACK_CODES.contains(&c) {
                Some((
                    controlled(control.net_ok()),
                    Evidence::StackUnavailable {
                        os_error: c,
                        control_ok: control.net_ok(),
                    },
                ))
            } else {
                None
            }
        }
        ProbeId::ConnectLoopback => {
            let arrived = ctx.loopback_arrived?;
            if arrived {
                return Some((
                    ProbeOutcome::Allowed,
                    Evidence::ListenerArrival {
                        os_error: code,
                        arrived,
                        control_ok: control.net_ok(),
                    },
                ));
            }
            // Only a connect that ended without a denial and without success
            // (timeout, stack error) is turned into a controlled absence. An
            // explicit denial (`Blocked`) and a success (`Allowed`, "connected")
            // keep the worker's own scoring; an `Error` (invalid address,
            // unknown code) stays an `Error`.
            if msg.outcome == ProbeOutcome::Allowed && detail == DETAIL_CONNECT_REACHED {
                Some((
                    controlled(control.net_ok()),
                    Evidence::ListenerArrival {
                        os_error: code,
                        arrived,
                        control_ok: control.net_ok(),
                    },
                ))
            } else {
                None
            }
        }
        ProbeId::CredRead => {
            let c = code?;
            if msg.outcome == ProbeOutcome::Error
                && ctx.lpac == Some(true)
                && LPAC_CRED_CODES.contains(&c)
            {
                Some((
                    controlled(control.cred),
                    Evidence::StackUnavailable {
                        os_error: c,
                        control_ok: control.cred,
                    },
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_duck_ipc::sandbox::probe::{DETAIL_CONNECTED, wsastartup_failed_detail};

    fn msg(
        probe: ProbeId,
        outcome: ProbeOutcome,
        os_error: Option<i64>,
        detail: &str,
    ) -> ProbeResultMsg {
        ProbeResultMsg {
            probe,
            outcome,
            os_error,
            detail: Some(detail.to_owned()),
            env_names: None,
        }
    }

    const GOOD: WindowsControl = WindowsControl {
        listener: true,
        winsock: true,
        cred: true,
    };

    fn ctx(
        lpac: bool,
        control: Option<WindowsControl>,
        arrived: Option<bool>,
    ) -> WindowsScoringContext {
        WindowsScoringContext {
            lpac: Some(lpac),
            control,
            loopback_arrived: arrived,
        }
    }

    fn wsa(probe: ProbeId, code: i64) -> ProbeResultMsg {
        msg(
            probe,
            ProbeOutcome::Error,
            Some(code),
            &wsastartup_failed_detail(code),
        )
    }

    #[test]
    fn control_helpers() {
        assert!(GOOD.ok() && GOOD.net_ok());
        assert!(!WindowsControl::FAILED.ok() && !WindowsControl::FAILED.net_ok());
        assert!(
            !WindowsControl {
                cred: false,
                ..GOOD
            }
            .ok()
        );
        assert!(
            WindowsControl {
                cred: false,
                ..GOOD
            }
            .net_ok()
        );
        assert!(
            !WindowsControl {
                listener: false,
                ..GOOD
            }
            .net_ok()
        );
        assert!(
            !WindowsControl {
                winsock: false,
                ..GOOD
            }
            .net_ok()
        );
    }

    #[test]
    fn lpac_wsastartup_codes_are_blocked_with_a_control_and_error_without() {
        for probe in [ProbeId::ConnectLoopback, ProbeId::ConnectPublic] {
            for code in LPAC_STACK_CODES {
                let m = wsa(probe, code);
                let (o, e) = rescore(probe, &m, &ctx(true, Some(GOOD), None)).expect("scored");
                assert_eq!(o, ProbeOutcome::Blocked, "{probe:?} {code}");
                assert_eq!(
                    e,
                    Evidence::StackUnavailable {
                        os_error: code,
                        control_ok: true
                    }
                );
                // control_ok = false -> Error, never Blocked
                for bad in [
                    WindowsControl::FAILED,
                    WindowsControl {
                        winsock: false,
                        ..GOOD
                    },
                    WindowsControl {
                        listener: false,
                        ..GOOD
                    },
                ] {
                    let (o, e) = rescore(probe, &m, &ctx(true, Some(bad), None)).expect("scored");
                    assert_eq!(o, ProbeOutcome::Error);
                    assert!(matches!(
                        e,
                        Evidence::StackUnavailable {
                            control_ok: false,
                            ..
                        }
                    ));
                }
                // no control at all -> the worker's Error stands
                assert!(rescore(probe, &m, &ctx(true, None, None)).is_none());
            }
        }
    }

    #[test]
    fn wsastartup_codes_are_not_blocked_outside_lpac_or_for_unknown_codes() {
        let m = wsa(ProbeId::ConnectPublic, WSASYSCALLFAILURE);
        assert!(rescore(ProbeId::ConnectPublic, &m, &ctx(false, Some(GOOD), None)).is_none());
        let unknown = wsa(ProbeId::ConnectPublic, 10091);
        assert!(
            rescore(
                ProbeId::ConnectPublic,
                &unknown,
                &ctx(true, Some(GOOD), None)
            )
            .is_none()
        );
        // lpac unknown
        let c = WindowsScoringContext {
            lpac: None,
            control: Some(GOOD),
            loopback_arrived: None,
        };
        assert!(rescore(ProbeId::ConnectPublic, &m, &c).is_none());
        // the same code without the WSAStartup detail is not a stack failure
        let other = msg(
            ProbeId::ConnectPublic,
            ProbeOutcome::Error,
            Some(WSASYSCALLFAILURE),
            "connect failed unexpectedly",
        );
        assert!(rescore(ProbeId::ConnectPublic, &other, &ctx(true, Some(GOOD), None)).is_none());
    }

    #[test]
    fn cred_service_unreachable_is_blocked_only_under_lpac_with_a_cred_control() {
        for code in LPAC_CRED_CODES {
            let m = msg(
                ProbeId::CredRead,
                ProbeOutcome::Error,
                Some(code),
                "CredReadW failed unexpectedly",
            );
            let (o, e) = rescore(ProbeId::CredRead, &m, &ctx(true, Some(GOOD), None)).unwrap();
            assert_eq!(o, ProbeOutcome::Blocked);
            assert_eq!(
                e,
                Evidence::StackUnavailable {
                    os_error: code,
                    control_ok: true
                }
            );
            let (o, _) = rescore(
                ProbeId::CredRead,
                &m,
                &ctx(
                    true,
                    Some(WindowsControl {
                        cred: false,
                        ..GOOD
                    }),
                    None,
                ),
            )
            .unwrap();
            assert_eq!(o, ProbeOutcome::Error);
            // the net-only control failing does not matter for the cred fact
            let (o, _) = rescore(
                ProbeId::CredRead,
                &m,
                &ctx(
                    true,
                    Some(WindowsControl {
                        winsock: false,
                        ..GOOD
                    }),
                    None,
                ),
            )
            .unwrap();
            assert_eq!(o, ProbeOutcome::Blocked);
            assert!(rescore(ProbeId::CredRead, &m, &ctx(false, Some(GOOD), None)).is_none());
            assert!(rescore(ProbeId::CredRead, &m, &ctx(true, None, None)).is_none());
        }
        // an unknown code, ERROR_NOT_FOUND and an explicit denial are not rescored
        for (outcome, code) in [
            (ProbeOutcome::Error, 1234),
            (ProbeOutcome::Allowed, ERROR_NOT_FOUND),
            (ProbeOutcome::Blocked, 5),
        ] {
            let m = msg(ProbeId::CredRead, outcome, Some(code), "x");
            assert!(rescore(ProbeId::CredRead, &m, &ctx(true, Some(GOOD), None)).is_none());
        }
    }

    #[test]
    fn a_connection_that_arrived_is_allowed_whatever_the_worker_said() {
        for m in [
            msg(
                ProbeId::ConnectLoopback,
                ProbeOutcome::Allowed,
                None,
                DETAIL_CONNECTED,
            ),
            msg(
                ProbeId::ConnectLoopback,
                ProbeOutcome::Allowed,
                Some(10060),
                DETAIL_CONNECT_REACHED,
            ),
            msg(
                ProbeId::ConnectLoopback,
                ProbeOutcome::Blocked,
                Some(5),
                "connect denied",
            ),
            msg(ProbeId::ConnectLoopback, ProbeOutcome::Error, None, "x"),
        ] {
            let (o, e) = rescore(
                ProbeId::ConnectLoopback,
                &m,
                &ctx(false, Some(GOOD), Some(true)),
            )
            .unwrap();
            assert_eq!(o, ProbeOutcome::Allowed);
            assert!(matches!(e, Evidence::ListenerArrival { arrived: true, .. }));
            // even with no control at all? No: without a control nothing is rescored.
            assert!(rescore(ProbeId::ConnectLoopback, &m, &ctx(false, None, Some(true))).is_none());
        }
    }

    #[test]
    fn a_timeout_is_blocked_only_with_no_arrival_and_a_net_control() {
        let timeout = msg(
            ProbeId::ConnectLoopback,
            ProbeOutcome::Allowed,
            Some(10060),
            DETAIL_CONNECT_REACHED,
        );
        let (o, e) = rescore(
            ProbeId::ConnectLoopback,
            &timeout,
            &ctx(false, Some(GOOD), Some(false)),
        )
        .unwrap();
        assert_eq!(o, ProbeOutcome::Blocked);
        assert_eq!(
            e,
            Evidence::ListenerArrival {
                os_error: Some(10060),
                arrived: false,
                control_ok: true
            }
        );
        // a bare timeout without the listener self-check, or without the
        // unconfined worker's connect, stays an Error
        for bad in [
            WindowsControl {
                listener: false,
                ..GOOD
            },
            WindowsControl {
                winsock: false,
                ..GOOD
            },
            WindowsControl::FAILED,
        ] {
            let (o, e) = rescore(
                ProbeId::ConnectLoopback,
                &timeout,
                &ctx(false, Some(bad), Some(false)),
            )
            .unwrap();
            assert_eq!(o, ProbeOutcome::Error);
            assert!(matches!(
                e,
                Evidence::ListenerArrival {
                    arrived: false,
                    control_ok: false,
                    ..
                }
            ));
        }
        // the cred control is irrelevant to the loopback fact
        let (o, _) = rescore(
            ProbeId::ConnectLoopback,
            &timeout,
            &ctx(
                false,
                Some(WindowsControl {
                    cred: false,
                    ..GOOD
                }),
                Some(false),
            ),
        )
        .unwrap();
        assert_eq!(o, ProbeOutcome::Blocked);
        // no listener at all (arrived unknown) or no control: untouched
        assert!(
            rescore(
                ProbeId::ConnectLoopback,
                &timeout,
                &ctx(false, Some(GOOD), None)
            )
            .is_none()
        );
        assert!(
            rescore(
                ProbeId::ConnectLoopback,
                &timeout,
                &ctx(false, None, Some(false))
            )
            .is_none()
        );
    }

    #[test]
    fn explicit_results_and_worker_errors_keep_the_workers_scoring_without_arrival() {
        // success reported but nothing arrived: the worker's Allowed stands
        let ok = msg(
            ProbeId::ConnectLoopback,
            ProbeOutcome::Allowed,
            None,
            DETAIL_CONNECTED,
        );
        assert!(
            rescore(
                ProbeId::ConnectLoopback,
                &ok,
                &ctx(false, Some(GOOD), Some(false))
            )
            .is_none()
        );
        // explicit denial: the worker's Blocked stands
        let denied = msg(
            ProbeId::ConnectLoopback,
            ProbeOutcome::Blocked,
            Some(10013),
            "connect denied",
        );
        assert!(
            rescore(
                ProbeId::ConnectLoopback,
                &denied,
                &ctx(false, Some(GOOD), Some(false))
            )
            .is_none()
        );
        // an unexpected failure stays an Error
        let bad = msg(
            ProbeId::ConnectLoopback,
            ProbeOutcome::Error,
            None,
            "invalid probe address",
        );
        assert!(
            rescore(
                ProbeId::ConnectLoopback,
                &bad,
                &ctx(false, Some(GOOD), Some(false))
            )
            .is_none()
        );
    }

    #[test]
    fn other_probes_are_never_rescored() {
        for probe in [
            ProbeId::FileInProfile,
            ProbeId::SpawnProcess,
            ProbeId::OpenProcessVmRead,
            ProbeId::OpenClipboard,
            ProbeId::ConnectPublic,
        ] {
            let m = msg(probe, ProbeOutcome::Error, Some(1), "x");
            assert!(
                rescore(probe, &m, &ctx(true, Some(GOOD), Some(false))).is_none(),
                "{probe:?}"
            );
        }
    }
}
