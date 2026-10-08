#![cfg(feature = "async")]

use atlas_duck_ipc::envelope::{Envelope, ErrorCode as C, Status as S, exit};
use atlas_duck_ipc::jcs::JcsError;
use atlas_duck_ipc::proto::{
    AgentNameSource, ClientKind, ListState, Meta, ProgressNotification, ProgressSink,
    RequestHandler, busy_envelope, exit_code, new_request_id, params_sha256, params_sha256_hex,
};
use atlas_duck_ipc::sandbox::{HostCall, HostCallResult, ScriptLimits};
use serde_json::json;
use sha2::{Digest, Sha256};

fn failed(code: C) -> Envelope {
    Envelope::failed(code, false, "m")
}

fn with_status(status: S) -> Envelope {
    let mut e = Envelope::failed(C::Internal, false, "m");
    e.status = status;
    e.error = None;
    e
}

fn with_script_error(status: S) -> Envelope {
    let mut e = with_status(status);
    e.data = Some(json!({"script_error": {"message": "boom"}}));
    e
}

#[test]
fn exit_code_matrix_section_4_3() {
    assert_eq!(exit_code(&with_status(S::Pending)), exit::PENDING);
    let mut lost = failed(C::Unreachable);
    lost.status = S::Pending;
    lost.error.as_mut().unwrap().details =
        json!({"reason": "connection_lost"}).as_object().cloned();
    assert_eq!(exit_code(&lost), 4);
    assert_eq!(exit_code(&with_status(S::Executing)), 4);
    assert_eq!(exit_code(&with_status(S::Succeeded)), 0);
    let mut dry = with_script_error(S::Succeeded);
    dry.meta = Some(json!({"dry_run": true}));
    assert_eq!(exit_code(&dry), 8);
    assert_eq!(exit_code(&with_status(S::Released)), 0);
    assert_eq!(exit_code(&with_script_error(S::Released)), 8);
    let mut denied = failed(C::Denied);
    denied.status = S::Denied;
    assert_eq!(exit_code(&denied), 3);
    assert_eq!(exit_code(&with_status(S::Denied)), 3);
    for s in [S::Expired, S::Cancelled, S::Abandoned] {
        assert_eq!(exit_code(&with_status(s)), 7);
    }
    assert_eq!(exit_code(&with_status(S::OutcomeUnknown)), 6);

    // `failed` rows by error.code. denied/expired/cancelled/abandoned/resolution_failed never
    // come with status failed (they carry their own status); the mapping is still total.
    let rows: &[(&[C], i32)] = &[
        (
            &[
                C::Internal,
                C::ProtocolError,
                C::AuditFailure,
                C::AuditStorageLow,
            ],
            1,
        ),
        (
            &[
                C::Usage,
                C::Validation,
                C::MarkdownPlaceholders,
                C::OpUnsupportedByInstance,
                C::UnknownRequest,
            ],
            2,
        ),
        (&[C::Unreachable, C::ProtocolMismatch, C::ServerIdentity], 5),
        (
            &[
                C::UpstreamNetwork,
                C::UpstreamUnavailable,
                C::UpstreamHttp,
                C::ResultTooLarge,
                C::UpstreamUnknownOutcome,
            ],
            6,
        ),
        (&[C::ScriptSyntax, C::ScriptLimit, C::SandboxUnavailable], 8),
        (&[C::Locked, C::NotConfigured, C::NeedsToken], 9),
        (&[C::Busy], 11),
        (&[C::Denied, C::ResolutionFailed], 3),
        (&[C::Expired, C::Cancelled, C::Abandoned], 7),
    ];
    for (codes, want) in rows {
        for c in *codes {
            assert_eq!(exit_code(&failed(*c)), *want, "{c:?}");
        }
    }
    // result_evicted wins over any status.
    for s in [S::Failed, S::Succeeded, S::Released, S::Pending, S::Expired] {
        let mut e = failed(C::ResultEvicted);
        e.status = s;
        assert_eq!(exit_code(&e), 10, "{s:?}");
    }
    // The table plus result_evicted covers every code.
    let covered: usize = rows.iter().map(|(c, _)| c.len()).sum::<usize>() + 1;
    assert_eq!(covered, C::ALL.len());
    // failed without an error object is internal.
    assert_eq!(exit_code(&with_status(S::Failed)), 1);
}

#[test]
fn params_sha256_is_jcs_over_resolved_routing() {
    let a: serde_json::Value =
        serde_json::from_str(r#"{"a":1.0,"b":[1,2],"c":{"x":1,"y":2}}"#).unwrap();
    let b: serde_json::Value =
        serde_json::from_str(r#"{"c":{"y":2,"x":1},"b":[1,2],"a":1}"#).unwrap();
    assert_eq!(
        params_sha256("op.x", Some("ins_a"), &a).unwrap(),
        params_sha256("op.x", Some("ins_a"), &b).unwrap()
    );
    assert_ne!(
        params_sha256("op.x", Some("ins_a"), &a).unwrap(),
        params_sha256("op.x", Some("ins_b"), &a).unwrap()
    );
    let null_form = Sha256::digest(br#"{"instance_id":null,"op_id":"op.x","params":{"k":1}}"#);
    assert_eq!(
        params_sha256("op.x", None, &json!({"k": 1}))
            .unwrap()
            .as_slice(),
        null_form.as_slice()
    );

    let golden = Sha256::digest(
        br#"{"instance_id":"ins_00","op_id":"jira.issue.get","params":{"key":"ABC-1"}}"#,
    );
    let hex: String = golden.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        params_sha256_hex("jira.issue.get", Some("ins_00"), &json!({"key": "ABC-1"})).unwrap(),
        hex
    );
    let big = json!({"n": 9007199254740993u64});
    assert_eq!(
        params_sha256("op.x", None, &big),
        Err(JcsError::IntegerOutOfRange)
    );
    assert_eq!(
        params_sha256_hex("op.x", None, &big),
        Err(JcsError::IntegerOutOfRange)
    );
}

#[test]
fn request_ids_are_unique_and_shaped() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..10_000 {
        let id = new_request_id().unwrap();
        let hex = id.strip_prefix("req_").expect("prefix");
        assert_eq!(hex.len(), 32);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert!(seen.insert(id));
    }
}

#[test]
fn script_limits_defaults_and_unknown_keys() {
    let d = ScriptLimits::default();
    assert_eq!(
        [
            d.timeout_s,
            d.heap_mb,
            d.process_mb,
            d.max_calls,
            d.max_fetch_mb,
            d.max_call_result_mb,
            d.max_result_mb,
            d.max_concurrent_calls
        ],
        [120, 256, 512, 200, 50, 16, 16, 4]
    );
    let p: ScriptLimits = serde_json::from_str(r#"{"timeout_s":60}"#).unwrap();
    assert_eq!(p.timeout_s, 60);
    assert_eq!(p.heap_mb, 256);
    assert!(serde_json::from_str::<ScriptLimits>(r#"{"timeout":60}"#).is_err());
}

#[test]
fn wire_names() {
    assert_eq!(serde_json::to_value(ClientKind::Cli).unwrap(), json!("cli"));
    assert_eq!(serde_json::to_value(ClientKind::Mcp).unwrap(), json!("mcp"));
    for (v, w) in [
        (AgentNameSource::Flag, "flag"),
        (AgentNameSource::Env, "env"),
        (AgentNameSource::McpClientInfo, "mcp-clientInfo"),
        (AgentNameSource::None, "none"),
    ] {
        assert_eq!(serde_json::to_value(v).unwrap(), json!(w));
    }
    assert_eq!(
        serde_json::to_value(ListState::Pending).unwrap(),
        json!("pending")
    );
    assert_eq!(
        serde_json::to_value(ListState::Recent).unwrap(),
        json!("recent")
    );
    assert_eq!(serde_json::to_value(Meta::default()).unwrap(), json!({}));
    assert!(serde_json::from_str::<Meta>(r#"{"bogus":1}"#).is_err());
}

#[test]
fn busy_envelope_shape() {
    let e = busy_envelope(30);
    assert_eq!(e.status, S::Failed);
    assert_eq!(e.request_id, None);
    let err = e.error.as_ref().unwrap();
    assert_eq!(err.code, C::Busy);
    assert!(err.retryable);
    assert_eq!(
        err.details.as_ref().unwrap().get("retry_after_s"),
        Some(&json!(30))
    );
    assert_eq!(exit_code(&e), 11);
}

#[test]
fn host_call_result_wire() {
    let ok = HostCallResult::Ok(json!(1));
    assert_eq!(serde_json::to_value(&ok).unwrap(), json!({"ok": 1}));
    assert_eq!(
        serde_json::from_value::<HostCallResult>(json!({"ok": 1})).unwrap(),
        ok
    );
    let rej = HostCallResult::Rejected {
        class: "validation".into(),
        details: json!({}),
    };
    let wire = json!({"rejected": {"class": "validation", "details": {}}});
    assert_eq!(serde_json::to_value(&rej).unwrap(), wire);
    assert_eq!(serde_json::from_value::<HostCallResult>(wire).unwrap(), rej);

    let c = HostCall {
        id: 1,
        op_id: "a.b".into(),
        params: json!({}),
        instance: None,
        all: false,
    };
    assert_eq!(
        serde_json::from_value::<HostCall>(serde_json::to_value(&c).unwrap()).unwrap(),
        c
    );
}

#[tokio::test]
async fn handler_traits_are_dyn_compatible() {
    struct Sink;
    impl ProgressSink for Sink {
        fn progress(&self, _n: ProgressNotification) {}
    }
    let sink: &dyn ProgressSink = &Sink;
    sink.progress(ProgressNotification {
        request_id: "req_x".into(),
        status: S::Pending,
    });
    fn _assert(_: &dyn RequestHandler) {}
}
