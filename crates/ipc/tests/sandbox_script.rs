//! Script protocol of the sandbox channel (M8 Δ1): encoders, decoder, constants.

use atlas_duck_ipc::sandbox::probe::{decode_notification, encode_notification};
use atlas_duck_ipc::sandbox::script::*;
use atlas_duck_ipc::sandbox::{
    HostCall, HostCallResult, MAX_FRAME_BYTES, ScriptLimits, WORKER_FRAME_MAX_BYTES,
};
use serde_json::json;

fn limits_with_result_mb(max_result_mb: u32) -> ScriptLimits {
    ScriptLimits {
        max_result_mb,
        ..ScriptLimits::default()
    }
}

fn init() -> WorkerInit {
    WorkerInit {
        source: "export default 1".to_string(),
        args: json!({"a": [1, 2]}),
        limits: ScriptLimits::default(),
        read_op_ids: vec!["jira.issue.get".to_string()],
        instances: vec![InstanceInfo {
            alias: "prod".to_string(),
            product: "jira".to_string(),
            is_default: true,
        }],
    }
}

fn host_call(id: u64) -> HostCall {
    HostCall {
        id,
        op_id: "jira.issue.get".to_string(),
        params: json!({"key": "A-1"}),
        instance: None,
        all: false,
    }
}

#[test]
fn worker_init_round_trip_and_unknown_field_rejected() {
    let init = init();
    let bytes = encode_notification(M_SCRIPT_RUN, &init);
    let (method, params) = decode_notification(&bytes).unwrap();
    assert_eq!(method, M_SCRIPT_RUN);
    let back: WorkerInit = serde_json::from_value(params.clone()).unwrap();
    assert_eq!(back, init);

    let mut with_extra = params.clone();
    with_extra["extra"] = json!(1);
    assert!(serde_json::from_value::<WorkerInit>(with_extra).is_err());

    let mut inst_extra = params;
    inst_extra["instances"][0]["url"] = json!("https://x");
    assert!(serde_json::from_value::<WorkerInit>(inst_extra).is_err());

    let req = CompileRequest {
        source: "1+1".to_string(),
    };
    let (_, p) = decode_notification(&encode_notification(M_SCRIPT_COMPILE, &req)).unwrap();
    assert_eq!(serde_json::from_value::<CompileRequest>(p).unwrap(), req);
    assert!(serde_json::from_value::<CompileRequest>(json!({"source": "", "x": 1})).is_err());
}

#[test]
fn host_call_request_and_response_shapes() {
    let call = HostCall {
        id: 7,
        op_id: "jira.issue.get".to_string(),
        params: json!({"key": "A-1"}),
        instance: Some("prod".to_string()),
        all: false,
    };
    assert_eq!(
        String::from_utf8(encode_request(M_HOST_CALL, 7, &call)).unwrap(),
        r#"{"jsonrpc":"2.0","id":7,"method":"host.call","params":{"id":7,"op_id":"jira.issue.get","params":{"key":"A-1"},"instance":"prod","all":false}}"#
    );
    assert_eq!(
        String::from_utf8(encode_response(7, &HostCallResult::Ok(json!({"n": 1})))).unwrap(),
        r#"{"jsonrpc":"2.0","id":7,"result":{"ok":{"n":1}}}"#
    );
    assert_eq!(
        String::from_utf8(encode_response(
            8,
            &HostCallResult::Rejected {
                class: "denied".to_string(),
                details: json!(null),
            }
        ))
        .unwrap(),
        r#"{"jsonrpc":"2.0","id":8,"result":{"rejected":{"class":"denied","details":null}}}"#
    );
    // The worker's own request decodes back to the same call.
    let frame = decode_worker_frame(&encode_request(M_HOST_CALL, 7, &call)).unwrap();
    assert_eq!(frame, WorkerFrame::Call { id: 7, call });
}

#[test]
fn terminal_frame_cap_is_max_result_plus_64k() {
    assert_eq!(
        terminal_frame_max(&limits_with_result_mb(16)),
        16 * 1024 * 1024 + 65_536
    );
    assert_eq!(
        terminal_frame_max(&limits_with_result_mb(1)),
        1024 * 1024 + 65_536
    );
    assert_eq!(HOST_TO_WORKER_MAX, MAX_FRAME_BYTES);
    assert_eq!(WORKER_FRAME_MAX_BYTES, 1024 * 1024);
}

#[test]
fn script_method_names_are_fixed() {
    assert_eq!(M_SCRIPT_RUN, "script.run");
    assert_eq!(M_SCRIPT_COMPILE, "script.compile");
    assert_eq!(M_SCRIPT_COMPILED, "script.compiled");
    assert_eq!(M_SCRIPT_SYNTAX, "script.syntax");
    assert_eq!(M_HOST_CALL, "host.call");
    assert_eq!(M_HOST_LOG, "host.log");
    assert_eq!(M_SCRIPT_RESULT, "script.result");
    assert_eq!(M_SCRIPT_ERROR, "script.error");
}

#[test]
fn compile_reply_shapes() {
    let compiled = encode_notification(M_SCRIPT_COMPILED, &EmptyParams {});
    assert_eq!(
        String::from_utf8(compiled.clone()).unwrap(),
        r#"{"jsonrpc":"2.0","method":"script.compiled","params":{}}"#
    );
    assert_eq!(
        decode_worker_frame(&compiled).unwrap(),
        WorkerFrame::Compiled
    );
    // `params` may be absent for `script.compiled`.
    assert_eq!(
        decode_worker_frame(br#"{"jsonrpc":"2.0","method":"script.compiled"}"#).unwrap(),
        WorkerFrame::Compiled
    );
    assert!(matches!(
        decode_worker_frame(br#"{"jsonrpc":"2.0","method":"script.compiled","params":{"x":1}}"#),
        Err(DecodeError::BadParams { .. })
    ));

    let syntax = encode_notification(
        M_SCRIPT_SYNTAX,
        &SyntaxParams {
            line: 3,
            column: 9,
            message: "unexpected token".to_string(),
        },
    );
    assert_eq!(
        String::from_utf8(syntax.clone()).unwrap(),
        r#"{"jsonrpc":"2.0","method":"script.syntax","params":{"line":3,"column":9,"message":"unexpected token"}}"#
    );
    assert_eq!(
        decode_worker_frame(&syntax).unwrap(),
        WorkerFrame::Syntax {
            line: 3,
            column: 9,
            message: "unexpected token".to_string()
        }
    );

    let log = encode_notification(
        M_HOST_LOG,
        &LogParams {
            line: "hello".to_string(),
        },
    );
    assert_eq!(
        decode_worker_frame(&log).unwrap(),
        WorkerFrame::Log {
            line: "hello".to_string()
        }
    );
    let err = encode_notification(
        M_SCRIPT_ERROR,
        &ErrorParams {
            class: "TypeError".to_string(),
            message: "x is not a function".to_string(),
            stack: "at <eval>:1".to_string(),
        },
    );
    assert_eq!(
        decode_worker_frame(&err).unwrap(),
        WorkerFrame::Error {
            class: "TypeError".to_string(),
            message: "x is not a function".to_string(),
            stack: "at <eval>:1".to_string()
        }
    );
}

#[test]
fn decode_rejects_unknown_method_extra_keys_and_bad_ids() {
    let rej = |s: &str| decode_worker_frame(s.as_bytes()).unwrap_err();
    assert!(matches!(rej("not json"), DecodeError::Json(_)));
    assert!(matches!(rej("[1]"), DecodeError::NotObject));
    assert!(matches!(rej("7"), DecodeError::NotObject));
    assert!(matches!(
        rej(r#"{"jsonrpc":"1.0","method":"host.log","params":{"line":"a"}}"#),
        DecodeError::WrongVersion
    ));
    assert!(matches!(
        rej(r#"{"method":"host.log","params":{"line":"a"}}"#),
        DecodeError::WrongVersion
    ));
    assert!(matches!(
        rej(r#"{"jsonrpc":"2.0"}"#),
        DecodeError::MissingMethod
    ));
    assert!(matches!(
        rej(r#"{"jsonrpc":"2.0","method":7}"#),
        DecodeError::MissingMethod
    ));
    // Unknown, including methods that belong to the other direction or to the probe.
    for m in [
        "bogus",
        "script.run",
        "script.compile",
        "probe.ready",
        "probe.result",
    ] {
        let text = format!(r#"{{"jsonrpc":"2.0","method":"{m}","params":{{}}}}"#);
        assert!(matches!(rej(&text), DecodeError::UnknownMethod(_)), "{m}");
    }
    assert!(matches!(
        rej(r#"{"jsonrpc":"2.0","method":"host.log","params":{"line":"a"},"extra":1}"#),
        DecodeError::ExtraKey(_)
    ));
    assert!(matches!(
        rej(r#"{"jsonrpc":"2.0","method":"host.log","method":"host.log","params":{"line":"a"}}"#),
        DecodeError::DuplicateKey(_)
    ));
    assert!(matches!(
        rej(r#"{"jsonrpc":"2.0","method":"host.log","params":{"line":"a","x":1}}"#),
        DecodeError::BadParams { .. }
    ));
    // A notification must not carry an id.
    assert!(matches!(
        rej(r#"{"jsonrpc":"2.0","id":1,"method":"host.log","params":{"line":"a"}}"#),
        DecodeError::UnexpectedId
    ));

    let call = |id: &str, pid: u64| {
        format!(
            r#"{{"jsonrpc":"2.0"{id},"method":"host.call","params":{{"id":{pid},"op_id":"o","params":null,"instance":null,"all":false}}}}"#
        )
    };
    assert!(matches!(rej(&call("", 1)), DecodeError::BadId));
    for bad in ["0", "-1", "1.5", "\"1\"", "null", "1e2"] {
        let id = format!(r#","id":{bad}"#);
        assert!(matches!(rej(&call(&id, 1)), DecodeError::BadId), "{bad}");
    }
    assert!(matches!(
        rej(r#"{"jsonrpc":"2.0","id":1,"method":"host.call"}"#),
        DecodeError::BadParams { .. }
    ));
    assert!(decode_worker_frame(call(r#","id":1"#, 1).as_bytes()).is_ok());
}

#[test]
fn decode_rejects_jsonrpc_id_differing_from_hostcall_id() {
    let call = host_call(5);
    let bytes = encode_request(M_HOST_CALL, 6, &call);
    assert!(matches!(
        decode_worker_frame(&bytes),
        Err(DecodeError::IdMismatch {
            envelope: 6,
            call: 5
        })
    ));
    assert!(decode_worker_frame(&encode_request(M_HOST_CALL, 5, &call)).is_ok());
}

#[test]
fn worker_sent_jsonrpc_response_is_rejected() {
    for text in [
        r#"{"jsonrpc":"2.0","id":1,"result":{"ok":1}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","result":null}"#,
    ] {
        assert!(
            matches!(
                decode_worker_frame(text.as_bytes()),
                Err(DecodeError::WorkerResponse)
            ),
            "{text}"
        );
    }
    // The host's own response shape is no worker frame either.
    let host_reply = encode_response(1, &HostCallResult::Ok(json!(1)));
    assert!(matches!(
        decode_worker_frame(&host_reply),
        Err(DecodeError::WorkerResponse)
    ));
    // `method` together with `result` is malformed, not a response.
    assert!(matches!(
        decode_worker_frame(br#"{"jsonrpc":"2.0","method":"host.log","result":1}"#),
        Err(DecodeError::ExtraKey(_))
    ));
}

#[test]
fn result_value_kept_as_raw_text() {
    // Spacing, key order and number spelling survive: the decoder builds no `Value`.
    let value = r#"{"b" :  1.0,  "a":[1e2, "x" ]}"#;
    let frame_text =
        format!(r#"{{"jsonrpc":"2.0","method":"script.result","params":{{"value":{value}}}}}"#);
    let frame = decode_worker_frame(frame_text.as_bytes()).unwrap();
    assert!(matches!(&frame, WorkerFrame::Result { value: got } if got.get() == value));

    // A worker-side encode of the same text reproduces the frame payload.
    let raw = RawJsonText::from_string(value.to_string()).unwrap();
    let bytes = encode_notification(M_SCRIPT_RESULT, &ResultParams { value: raw });
    assert_eq!(String::from_utf8(bytes).unwrap(), frame_text);
    assert!(RawJsonText::from_string("{not json".to_string()).is_err());
    assert!(matches!(
        decode_worker_frame(br#"{"jsonrpc":"2.0","method":"script.result","params":{}}"#),
        Err(DecodeError::BadParams { .. })
    ));
}
