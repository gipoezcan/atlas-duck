//! Probe-protocol types for the §9.4 probe worker.
//!
//! The spec lists what the probe worker attempts (§9.4 "Mandatory floor and
//! probes") but not the protocol; every name here is plan-chosen. Messages are
//! JSON-RPC 2.0 notifications carried in §3.3 frames:
//! worker -> host `probe.ready` ([`ProbeReady`]) once after confinement,
//! host -> worker `probe.run` ([`ProbeRequest`]),
//! worker -> host `probe.result` ([`ProbeResultMsg`]).

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Worker -> host, once, after `confine::apply()` and before the first read.
pub const M_PROBE_READY: &str = "probe.ready";
/// Host -> worker: run one probe.
pub const M_PROBE_RUN: &str = "probe.run";
/// Worker -> host: the outcome of one probe.
pub const M_PROBE_RESULT: &str = "probe.result";

/// §9.4 says "a public IP" without naming one. Plan decision: RFC 5737
/// TEST-NET-1, which is never a real host. Blocked is scored from the denial
/// (errno / SIGSYS / WSAEACCES), not from reachability.
pub const PUBLIC_PROBE_ADDR: &str = "192.0.2.1:443";
/// §9.4 "127.0.0.1"; port 9 (discard) is a plan choice.
pub const LOOPBACK_PROBE_ADDR: &str = "127.0.0.1:9";

/// One probe attempt. Serialized in snake_case (`file_in_profile`, `clone3`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeId {
    /// Open a file in the user profile.
    FileInProfile,
    /// `socket()`/`connect()` to 127.0.0.1.
    ConnectLoopback,
    /// `socket()`/`connect()` to a public IP.
    ConnectPublic,
    /// Spawn a process.
    SpawnProcess,
    /// Linux: raw `clone`.
    RawClone,
    /// Linux: `clone3`.
    Clone3,
    /// Linux: `process_vm_readv` on the app.
    MemReadProcessVm,
    /// Linux: `/proc/<app pid>/mem`.
    MemReadProcMem,
    /// macOS: `task_for_pid` on the app.
    TaskForPid,
    /// Windows: `OpenProcess(PROCESS_VM_READ)` on the app.
    OpenProcessVmRead,
    /// Windows: `CredReadW`.
    CredRead,
    /// Windows: `OpenClipboard`.
    OpenClipboard,
    /// macOS: a securityd `mach-lookup`.
    MachLookupSecurityd,
    /// Diagnostic (not floor): the §9.3 engine self-test inside the confined worker.
    EngineSelfTest,
    /// Diagnostic (not floor): the worker reports its environment variable names.
    EnvNames,
    /// Diagnostic (not floor): Windows handle-inheritance sentinel check.
    HandleSentinel,
}

/// Linux floor probes (§9.4).
pub const LINUX_FLOOR: &[ProbeId] = &[
    ProbeId::FileInProfile,
    ProbeId::ConnectLoopback,
    ProbeId::ConnectPublic,
    ProbeId::SpawnProcess,
    ProbeId::RawClone,
    ProbeId::Clone3,
    ProbeId::MemReadProcessVm,
    ProbeId::MemReadProcMem,
];

/// macOS floor probes (§9.4).
pub const MACOS_FLOOR: &[ProbeId] = &[
    ProbeId::FileInProfile,
    ProbeId::ConnectLoopback,
    ProbeId::ConnectPublic,
    ProbeId::SpawnProcess,
    ProbeId::TaskForPid,
    ProbeId::MachLookupSecurityd,
];

/// Windows floor probes (§9.4).
pub const WINDOWS_FLOOR: &[ProbeId] = &[
    ProbeId::FileInProfile,
    ProbeId::ConnectLoopback,
    ProbeId::ConnectPublic,
    ProbeId::SpawnProcess,
    ProbeId::OpenProcessVmRead,
    ProbeId::CredRead,
    ProbeId::OpenClipboard,
];

impl ProbeId {
    /// The floor probes of the OS this binary was built for; empty elsewhere.
    /// Every one must score `Blocked` for the floor to be met (plan reading of G-6).
    pub fn floor_probes_for_current_os() -> &'static [ProbeId] {
        if cfg!(target_os = "linux") {
            LINUX_FLOOR
        } else if cfg!(target_os = "macos") {
            MACOS_FLOOR
        } else if cfg!(target_os = "windows") {
            WINDOWS_FLOOR
        } else {
            &[]
        }
    }

    /// `true` for the 13 confinement probes (on whichever OS they belong to),
    /// `false` for the diagnostics `EngineSelfTest`, `EnvNames`, `HandleSentinel`.
    pub fn is_floor(self) -> bool {
        !matches!(
            self,
            ProbeId::EngineSelfTest | ProbeId::EnvNames | ProbeId::HandleSentinel
        )
    }
}

/// Host -> worker `probe.run` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    pub probe: ProbeId,
    /// The app's pid, target of the memory-read probes.
    pub app_pid: u32,
    /// The user's profile directory, which the `FileInProfile` probe tries to
    /// open (a directory, not a file; Windows opens it with backup semantics).
    pub profile_path: String,
    /// Normally [`PUBLIC_PROBE_ADDR`].
    pub public_addr: String,
    /// Normally [`LOOPBACK_PROBE_ADDR`].
    pub loopback_addr: String,
    /// `HandleSentinel` only: the raw value of a host handle the worker must not have.
    pub handle_value: Option<u64>,
}

/// What confinement the worker applied to itself (reported in `probe.ready`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfinementReport {
    pub applied: bool,
    /// e.g. `none`, `seccomp+landlock`, `seccomp`, `seatbelt`, `appcontainer`.
    pub mechanism: String,
    pub no_new_privs: Option<bool>,
    pub landlock_abi: Option<u32>,
    pub seccomp: Option<bool>,
    pub lpac: Option<bool>,
    pub os_error: Option<i64>,
}

/// Worker -> host `probe.ready` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeReady {
    /// The worker's embedded `build_info::BUILD_ID` (§3.4 "embedded version").
    pub worker_version: String,
    pub engine_version: String,
    pub confinement: ConfinementReport,
}

/// Result of one probe attempt as the worker saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Blocked,
    Allowed,
    Error,
}

/// Worker -> host `probe.result` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeResultMsg {
    pub probe: ProbeId,
    pub outcome: ProbeOutcome,
    pub os_error: Option<i64>,
    /// Short metadata-only text (never file contents or memory bytes).
    pub detail: Option<String>,
    /// `EnvNames` only: names (not values) of the worker's environment variables.
    pub env_names: Option<Vec<String>>,
}

#[derive(Serialize)]
struct NotificationOut<'a, T: Serialize> {
    jsonrpc: &'static str,
    method: &'a str,
    params: &'a T,
}

/// Encodes a JSON-RPC 2.0 notification `{"jsonrpc":"2.0","method":..,"params":..}`
/// (no `id`). The result is one frame payload for [`super::frame::write_frame`].
///
/// # Panics
/// Only if `T`'s `Serialize` impl fails. The probe types in this module are
/// plain derived structs (strings, integers, bools, options, vectors) and
/// cannot fail.
pub fn encode_notification<T: Serialize>(method: &str, params: &T) -> Vec<u8> {
    let msg = NotificationOut {
        jsonrpc: "2.0",
        method,
        params,
    };
    serde_json::to_vec(&msg).expect("serializing a probe notification cannot fail")
}

/// Why [`decode_notification`] rejected a frame payload.
#[derive(Debug)]
pub enum DecodeError {
    /// Not valid UTF-8 JSON.
    Json(serde_json::Error),
    /// Valid JSON but not an object.
    NotObject,
    /// `jsonrpc` is missing or not `"2.0"`.
    WrongVersion,
    /// `method` is missing or not a string.
    MissingMethod,
    /// The message has an `id`, so it is a request or response, not a notification.
    HasId,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Json(e) => write!(f, "invalid JSON: {e}"),
            DecodeError::NotObject => f.write_str("message is not a JSON object"),
            DecodeError::WrongVersion => f.write_str("jsonrpc is not \"2.0\""),
            DecodeError::MissingMethod => f.write_str("method missing or not a string"),
            DecodeError::HasId => f.write_str("message has an id; expected a notification"),
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DecodeError::Json(e) => Some(e),
            _ => None,
        }
    }
}

/// Decodes one frame payload as a JSON-RPC 2.0 notification and returns
/// `(method, params)`. A missing `params` member yields `Value::Null`. The
/// method name is not checked here; callers reject unknown methods.
pub fn decode_notification(bytes: &[u8]) -> Result<(String, Value), DecodeError> {
    let value: Value = serde_json::from_slice(bytes).map_err(DecodeError::Json)?;
    let Value::Object(mut obj) = value else {
        return Err(DecodeError::NotObject);
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(DecodeError::WrongVersion);
    }
    if obj.contains_key("id") {
        return Err(DecodeError::HasId);
    }
    let method = match obj.remove("method") {
        Some(Value::String(m)) => m,
        _ => return Err(DecodeError::MissingMethod),
    };
    let params = obj.remove("params").unwrap_or(Value::Null);
    Ok((method, params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_info::BUILD_ID;

    /// Every variant with its literal wire name. The exhaustive `match` makes
    /// this test fail to compile when a variant is added without a name here.
    fn expected_name(p: ProbeId) -> &'static str {
        match p {
            ProbeId::FileInProfile => "file_in_profile",
            ProbeId::ConnectLoopback => "connect_loopback",
            ProbeId::ConnectPublic => "connect_public",
            ProbeId::SpawnProcess => "spawn_process",
            ProbeId::RawClone => "raw_clone",
            ProbeId::Clone3 => "clone3",
            ProbeId::MemReadProcessVm => "mem_read_process_vm",
            ProbeId::MemReadProcMem => "mem_read_proc_mem",
            ProbeId::TaskForPid => "task_for_pid",
            ProbeId::OpenProcessVmRead => "open_process_vm_read",
            ProbeId::CredRead => "cred_read",
            ProbeId::OpenClipboard => "open_clipboard",
            ProbeId::MachLookupSecurityd => "mach_lookup_securityd",
            ProbeId::EngineSelfTest => "engine_self_test",
            ProbeId::EnvNames => "env_names",
            ProbeId::HandleSentinel => "handle_sentinel",
        }
    }

    const ALL: [ProbeId; 16] = [
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

    #[test]
    fn probe_id_serde_names_are_literal_snake_case_and_round_trip() {
        for p in ALL {
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, format!("\"{}\"", expected_name(p)), "{p:?}");
            let back: ProbeId = serde_json::from_str(&json).unwrap();
            assert_eq!(back, p);
        }
        assert!(serde_json::from_str::<ProbeId>("\"FileInProfile\"").is_err());
    }

    #[test]
    fn probe_outcome_serde_names() {
        assert_eq!(
            serde_json::to_string(&ProbeOutcome::Blocked).unwrap(),
            "\"blocked\""
        );
        assert_eq!(
            serde_json::to_string(&ProbeOutcome::Allowed).unwrap(),
            "\"allowed\""
        );
        assert_eq!(
            serde_json::to_string(&ProbeOutcome::Error).unwrap(),
            "\"error\""
        );
    }

    #[test]
    fn per_os_floor_lists_are_the_plan_lists() {
        use ProbeId::*;
        assert_eq!(
            LINUX_FLOOR,
            &[
                FileInProfile,
                ConnectLoopback,
                ConnectPublic,
                SpawnProcess,
                RawClone,
                Clone3,
                MemReadProcessVm,
                MemReadProcMem
            ]
        );
        assert_eq!(
            MACOS_FLOOR,
            &[
                FileInProfile,
                ConnectLoopback,
                ConnectPublic,
                SpawnProcess,
                TaskForPid,
                MachLookupSecurityd
            ]
        );
        assert_eq!(
            WINDOWS_FLOOR,
            &[
                FileInProfile,
                ConnectLoopback,
                ConnectPublic,
                SpawnProcess,
                OpenProcessVmRead,
                CredRead,
                OpenClipboard
            ]
        );
    }

    #[test]
    fn floor_probes_for_current_os_selects_by_target_os() {
        let expected: &[ProbeId] = if cfg!(target_os = "linux") {
            LINUX_FLOOR
        } else if cfg!(target_os = "macos") {
            MACOS_FLOOR
        } else if cfg!(target_os = "windows") {
            WINDOWS_FLOOR
        } else {
            &[]
        };
        assert_eq!(ProbeId::floor_probes_for_current_os(), expected);
        if cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        )) {
            assert!(!ProbeId::floor_probes_for_current_os().is_empty());
        }
    }

    #[test]
    fn is_floor_excludes_exactly_the_three_diagnostics() {
        assert!(!ProbeId::EngineSelfTest.is_floor());
        assert!(!ProbeId::EnvNames.is_floor());
        assert!(!ProbeId::HandleSentinel.is_floor());
        assert_eq!(ALL.iter().filter(|p| p.is_floor()).count(), 13);
        for p in LINUX_FLOOR.iter().chain(MACOS_FLOOR).chain(WINDOWS_FLOOR) {
            assert!(p.is_floor(), "{p:?}");
        }
    }

    #[test]
    fn probe_constants_are_the_plan_values() {
        assert_eq!(M_PROBE_READY, "probe.ready");
        assert_eq!(M_PROBE_RUN, "probe.run");
        assert_eq!(M_PROBE_RESULT, "probe.result");
        assert_eq!(PUBLIC_PROBE_ADDR, "192.0.2.1:443");
        assert_eq!(LOOPBACK_PROBE_ADDR, "127.0.0.1:9");
        assert!(PUBLIC_PROBE_ADDR.parse::<std::net::SocketAddr>().is_ok());
        assert!(LOOPBACK_PROBE_ADDR.parse::<std::net::SocketAddr>().is_ok());
    }

    #[test]
    fn notification_round_trip_for_every_message_type() {
        let ready = ProbeReady {
            worker_version: BUILD_ID.to_string(),
            engine_version: "quickjs-ng".to_string(),
            confinement: ConfinementReport {
                applied: true,
                mechanism: "seccomp+landlock".to_string(),
                no_new_privs: Some(true),
                landlock_abi: Some(6),
                seccomp: Some(true),
                lpac: None,
                os_error: None,
            },
        };
        let bytes = encode_notification(M_PROBE_READY, &ready);
        let (method, params) = decode_notification(&bytes).unwrap();
        assert_eq!(method, M_PROBE_READY);
        assert_eq!(serde_json::from_value::<ProbeReady>(params).unwrap(), ready);

        let req = ProbeRequest {
            probe: ProbeId::HandleSentinel,
            app_pid: 4242,
            profile_path: "C:\\Users\\u\\NTUSER.DAT".to_string(),
            public_addr: PUBLIC_PROBE_ADDR.to_string(),
            loopback_addr: LOOPBACK_PROBE_ADDR.to_string(),
            handle_value: Some(0x1f4),
        };
        let bytes = encode_notification(M_PROBE_RUN, &req);
        let (method, params) = decode_notification(&bytes).unwrap();
        assert_eq!(method, M_PROBE_RUN);
        assert_eq!(serde_json::from_value::<ProbeRequest>(params).unwrap(), req);

        let res = ProbeResultMsg {
            probe: ProbeId::EnvNames,
            outcome: ProbeOutcome::Allowed,
            os_error: Some(13),
            detail: Some("EACCES".to_string()),
            env_names: Some(vec!["TZ".to_string(), "MALLOC_ARENA_MAX".to_string()]),
        };
        let bytes = encode_notification(M_PROBE_RESULT, &res);
        let (method, params) = decode_notification(&bytes).unwrap();
        assert_eq!(method, M_PROBE_RESULT);
        assert_eq!(
            serde_json::from_value::<ProbeResultMsg>(params).unwrap(),
            res
        );
    }

    #[test]
    fn encode_notification_wire_shape() {
        let bytes = encode_notification(M_PROBE_RUN, &serde_json::json!({"a": 1}));
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            r#"{"jsonrpc":"2.0","method":"probe.run","params":{"a":1}}"#
        );
    }

    #[test]
    fn decode_notification_rejects_non_notifications() {
        assert!(matches!(
            decode_notification(b"\xff\xfe"),
            Err(DecodeError::Json(_))
        ));
        assert!(matches!(
            decode_notification(b"{"),
            Err(DecodeError::Json(_))
        ));
        assert!(matches!(
            decode_notification(b"[1]"),
            Err(DecodeError::NotObject)
        ));
        assert!(matches!(
            decode_notification(br#"{"method":"probe.run"}"#),
            Err(DecodeError::WrongVersion)
        ));
        assert!(matches!(
            decode_notification(br#"{"jsonrpc":"1.0","method":"probe.run"}"#),
            Err(DecodeError::WrongVersion)
        ));
        assert!(matches!(
            decode_notification(br#"{"jsonrpc":"2.0","id":1,"method":"probe.run"}"#),
            Err(DecodeError::HasId)
        ));
        assert!(matches!(
            decode_notification(br#"{"jsonrpc":"2.0","method":7}"#),
            Err(DecodeError::MissingMethod)
        ));
        let (m, p) = decode_notification(br#"{"jsonrpc":"2.0","method":"probe.ready"}"#).unwrap();
        assert_eq!(m, "probe.ready");
        assert_eq!(p, Value::Null);
    }

    #[test]
    fn worker_messages_reject_unknown_fields() {
        let v = serde_json::json!({
            "probe": "cred_read", "outcome": "blocked", "os_error": 5,
            "detail": null, "env_names": null, "extra": true
        });
        assert!(serde_json::from_value::<ProbeResultMsg>(v).is_err());
    }
}
