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

/// `reads_as_value` accepts exactly what `serde_json::from_str::<Value>` accepts (the core's
/// result type), without building the tree: the 128-level recursion limit (127 nested containers
/// read, 128 do not) and paired surrogate escapes in strings and keys. `RawJsonText::from_string`
/// alone accepts all of these texts.
#[test]
fn result_text_reads_as_value_like_serde_json() {
    let arrays = |depth: usize| format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
    let objects = |depth: usize| format!("{}1{}", r#"{"k":"#.repeat(depth), "}".repeat(depth));
    let texts = [
        "1".to_owned(),
        "null".to_owned(),
        r#""plain""#.to_owned(),
        r#""😀""#.to_owned(),
        r#""\ud800""#.to_owned(),
        r#""\udc00""#.to_owned(),
        r#""\ud800A""#.to_owned(),
        r#""\ud800\n""#.to_owned(),
        r#"{"\ud800":1}"#.to_owned(),
        r#"{"a":["x","\udfff"]}"#.to_owned(),
        r#"{"a":1,"a":2}"#.to_owned(),
        "1e400".to_owned(),
        arrays(127),
        arrays(128),
        arrays(200),
        objects(127),
        objects(128),
        format!("[{}]", objects(126)),
        format!("[{}]", objects(127)),
    ];
    for text in texts {
        let Ok(raw) = RawJsonText::from_string(text.clone()) else {
            // Not even JSON grammar: nothing to compare.
            continue;
        };
        let as_value = serde_json::from_str::<serde_json::Value>(&text).is_ok();
        assert_eq!(raw.reads_as_value(), as_value, "{text:.60}");
    }
    assert!(
        RawJsonText::from_string(arrays(127))
            .unwrap()
            .reads_as_value()
    );
    assert!(
        !RawJsonText::from_string(arrays(128))
            .unwrap()
            .reads_as_value()
    );
    assert!(
        !RawJsonText::from_string(r#""\ud800""#.to_owned())
            .unwrap()
            .reads_as_value()
    );
}

/// An object whose first key is one of serde_json's private tokens is refused: `Value` either
/// fails on it or reads it as a different value (`{"$serde_json::private::RawValue":"[1]"}` is
/// `[1]`). The token as a later key is an ordinary key.
#[test]
fn result_text_with_a_serde_json_token_key_is_refused() {
    let raw_token = r#"{"$serde_json::private::RawValue":"[1]"}"#;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(raw_token).unwrap(),
        json!([1])
    );
    for text in [
        raw_token,
        r#"{"$serde_json::private::RawValue":5}"#,
        r#"{"$serde_json::private::Number":"1"}"#,
        r#"[{"$serde_json::private::RawValue":"1"}]"#,
    ] {
        let raw = RawJsonText::from_string(text.to_owned()).unwrap();
        assert!(!raw.reads_as_value(), "{text}");
    }
    let later =
        RawJsonText::from_string(r#"{"a":1,"$serde_json::private::RawValue":"[1]"}"#.to_owned())
            .unwrap();
    assert!(later.reads_as_value());
}

#[test]
fn decode_rejects_malformed_payloads() {
    let rej = |b: &[u8]| decode_worker_frame(b).unwrap_err();
    let ok = r#"{"jsonrpc":"2.0","method":"host.log","params":{"line":"a"}}"#;
    assert!(decode_worker_frame(ok.as_bytes()).is_ok());

    // Empty and whitespace-only payloads, a truncated frame, trailing bytes.
    assert!(matches!(rej(b""), DecodeError::Json(_)));
    assert!(matches!(rej(b"   "), DecodeError::Json(_)));
    assert!(matches!(
        rej(&ok.as_bytes()[..ok.len() - 1]),
        DecodeError::Json(_)
    ));
    assert!(matches!(
        rej(format!("{ok}garbage").as_bytes()),
        DecodeError::Json(_)
    ));
    assert!(matches!(
        rej(format!("{ok}{ok}").as_bytes()),
        DecodeError::Json(_)
    ));

    // Invalid UTF-8 inside a string and outside any token.
    let mut in_string = ok.as_bytes().to_vec();
    let at = in_string.iter().position(|b| *b == b'a').unwrap();
    in_string[at] = 0xff;
    assert!(matches!(rej(&in_string), DecodeError::Json(_)));
    let mut outside = ok.as_bytes().to_vec();
    outside.push(0xff);
    assert!(matches!(rej(&outside), DecodeError::Json(_)));

    // A UTF-8 BOM is not JSON whitespace.
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(ok.as_bytes());
    assert!(matches!(rej(&bom), DecodeError::Json(_)));

    // `params` that is not an object.
    for params in ["[]", "null", "1", "\"x\""] {
        let text = format!(r#"{{"jsonrpc":"2.0","method":"host.log","params":{params}}}"#);
        assert!(
            matches!(rej(text.as_bytes()), DecodeError::BadParams { .. }),
            "{params}"
        );
    }

    // An id above u64::MAX is no host.call id.
    let call = |id: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"host.call","params":{{"id":1,"op_id":"o","params":null,"instance":null,"all":false}}}}"#
        )
    };
    assert!(matches!(
        rej(call("18446744073709551616").as_bytes()),
        DecodeError::BadId
    ));
    assert!(decode_worker_frame(call("1").as_bytes()).is_ok());

    // `jsonrpc` as a number, or spelled with escapes: only the literal string "2.0" passes.
    for v in ["2.0", "2", "\"2\\u002e0\"", "[\"2.0\"]", "null"] {
        let text = format!(r#"{{"jsonrpc":{v},"method":"host.log","params":{{"line":"a"}}}}"#);
        let r = rej(text.as_bytes());
        assert!(
            matches!(r, DecodeError::WrongVersion | DecodeError::Json(_)),
            "{v}: {r}"
        );
    }
}

#[test]
fn decode_depth_limit_applies_to_host_call_params_not_result_text() {
    // Pins current behavior (serde_json's recursion limit of 128). A `script.result` value is
    // kept as text and skipped without that limit, so even a very deep result decodes (the
    // worker refuses to send one, `RawJsonText::reads_as_value`). A
    // `host.call` `params` is a `Value`: nested 100 deep it decodes, nested 200 deep it is a
    // `BadParams` error. The T4 worker loop must report an over-deep call as a script error,
    // not as a protocol violation.
    let nested = |depth: usize| format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
    let result = |depth: usize| {
        format!(
            r#"{{"jsonrpc":"2.0","method":"script.result","params":{{"value":{}}}}}"#,
            nested(depth)
        )
    };
    for depth in [100, 200, 5000] {
        let frame = decode_worker_frame(result(depth).as_bytes()).unwrap();
        assert!(
            matches!(&frame, WorkerFrame::Result { value } if value.get() == nested(depth)),
            "{depth}"
        );
    }

    let call = |depth: usize| {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"host.call","params":{{"id":1,"op_id":"o","params":{},"instance":null,"all":false}}}}"#,
            nested(depth)
        )
    };
    assert!(decode_worker_frame(call(100).as_bytes()).is_ok());
    assert!(matches!(
        decode_worker_frame(call(200).as_bytes()),
        Err(DecodeError::BadParams { .. } | DecodeError::Json(_))
    ));
}
