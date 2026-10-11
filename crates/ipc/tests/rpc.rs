#![cfg(feature = "async")]
//! §3.3 / PD-28: JSON-RPC messages, method names and async framing.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use atlas_duck_ipc::envelope::{Envelope, ErrorCode};
use atlas_duck_ipc::rpc::frame::{FrameError, read_frame_async, write_frame_async};
use atlas_duck_ipc::rpc::{
    EmptyParams, IdParams, Incoming, OpsDescribeParams, OpsListParams, Request, RequestsListParams,
    Response, ResponseBody, codes, error_response, method, protocol_error,
};
use atlas_duck_ipc::sandbox::MAX_FRAME_BYTES;
use atlas_duck_ipc::sandbox::frame::write_frame;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, ReadBuf};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn methods_are_section_3_3() {
    assert_eq!(
        method::ALL,
        [
            "hello",
            "ops.list",
            "ops.describe",
            "instances.list",
            "request.submit",
            "request.await",
            "request.status",
            "request.cancel",
            "requests.list",
            "script.submit",
            "doctor",
        ]
    );
    assert_eq!(method::REQUEST_PROGRESS, "request.progress");
}

#[test]
fn request_roundtrip_and_version_checked() -> TestResult {
    let req = Request {
        jsonrpc: Default::default(),
        id: 7,
        method: method::OPS_LIST.to_owned(),
        params: json!({ "instance": "a" }),
    };
    let wire = serde_json::to_value(&req)?;
    assert_eq!(
        wire,
        json!({"jsonrpc": "2.0", "id": 7, "method": "ops.list", "params": {"instance": "a"}})
    );
    assert_eq!(serde_json::from_value::<Request>(wire.clone())?, req);
    assert!(matches!(
        serde_json::from_value::<Incoming>(wire)?,
        Incoming::Request(r) if r == req
    ));

    let bad = json!({"jsonrpc": "1.0", "id": 7, "method": "ops.list", "params": {}});
    assert!(serde_json::from_value::<Request>(bad.clone()).is_err());
    assert!(serde_json::from_value::<Incoming>(bad).is_err());
    let missing = json!({"id": 7, "method": "ops.list", "params": {}});
    assert!(serde_json::from_value::<Request>(missing).is_err());
    Ok(())
}

#[test]
fn incoming_tells_the_three_shapes_apart() -> TestResult {
    let n = json!({"jsonrpc": "2.0", "method": "request.progress", "params": {"request_id": "r", "status": "pending"}});
    assert!(matches!(
        serde_json::from_value::<Incoming>(n)?,
        Incoming::Notification(_)
    ));
    let r = json!({"jsonrpc": "2.0", "id": 1, "result": null});
    assert!(matches!(
        serde_json::from_value::<Incoming>(r)?,
        Incoming::Response(Response {
            body: ResponseBody::Result(Value::Null),
            ..
        })
    ));
    Ok(())
}

#[test]
fn response_result_xor_error() -> TestResult {
    let ok = json!({"jsonrpc": "2.0", "id": 3, "result": {"x": 1}});
    let r: Response = serde_json::from_value(ok.clone())?;
    assert_eq!(r.id, Some(3));
    assert_eq!(serde_json::to_value(&r)?, ok);

    let both =
        json!({"jsonrpc": "2.0", "id": 3, "result": 1, "error": {"code": -1, "message": "m"}});
    assert!(serde_json::from_value::<Response>(both).is_err());
    let neither = json!({"jsonrpc": "2.0", "id": 3});
    assert!(serde_json::from_value::<Response>(neither).is_err());
    let wrong_version = json!({"jsonrpc": "1.0", "id": 3, "result": 1});
    assert!(serde_json::from_value::<Response>(wrong_version).is_err());
    Ok(())
}

#[test]
fn error_carries_envelope() -> TestResult {
    let resp = error_response(
        None,
        codes::INVALID_REQUEST,
        protocol_error("hello_required"),
    );
    let wire = serde_json::to_value(&resp)?;
    assert_eq!(wire["id"], Value::Null);
    assert_eq!(wire["error"]["code"], json!(-32600));
    let back: Response = serde_json::from_value(wire)?;
    let ResponseBody::Error(e) = back.body else {
        return Err("not an error response".into());
    };
    let env: Envelope = e.data.ok_or("no data")?;
    let err = env.error.ok_or("no error object")?;
    assert_eq!(err.code, ErrorCode::ProtocolError);
    assert!(!err.retryable);
    assert_eq!(
        err.details.and_then(|d| d.get("reason").cloned()),
        Some(json!("hello_required"))
    );
    assert_eq!(env.request_id, None);
    Ok(())
}

#[test]
fn error_codes_are_pd_28() {
    assert_eq!(codes::PARSE, -32700);
    assert_eq!(codes::INVALID_REQUEST, -32600);
    assert_eq!(codes::METHOD_NOT_FOUND, -32601);
    assert_eq!(codes::INVALID_PARAMS, -32602);
    assert_eq!(codes::APP_REFUSAL, -32000);
}

fn rejects_extra<T: DeserializeOwned>(base: Value) -> bool {
    let ok = serde_json::from_value::<T>(base.clone()).is_ok();
    let mut extra = base;
    if let Some(o) = extra.as_object_mut() {
        o.insert("zzz".to_owned(), json!(1));
    }
    ok && serde_json::from_value::<T>(extra).is_err()
}

#[test]
fn params_deny_unknown_fields() {
    assert!(rejects_extra::<OpsListParams>(json!({})));
    assert!(rejects_extra::<OpsDescribeParams>(json!({"op_id": "x"})));
    assert!(rejects_extra::<IdParams>(json!({"request_id": "r"})));
    assert!(rejects_extra::<RequestsListParams>(json!({})));
    assert!(rejects_extra::<EmptyParams>(json!({})));
}

#[test]
fn optional_params_default() -> TestResult {
    let p: RequestsListParams = serde_json::from_value(json!({"state": "pending"}))?;
    assert_eq!(p.agent, None);
    assert!(p.match_params.is_none());
    let d: OpsDescribeParams = serde_json::from_value(json!({"op_id": "jira.issue.get"}))?;
    assert_eq!(d.instance, None);
    Ok(())
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn async_frame_matches_sync_codec() -> TestResult {
    for len in [0usize, 1, 1024 * 1024] {
        let payload = pattern(len);
        let mut sync_bytes = Vec::new();
        write_frame(&mut sync_bytes, &payload)?;
        let mut async_bytes = Vec::new();
        write_frame_async(&mut async_bytes, &payload).await?;
        assert_eq!(async_bytes, sync_bytes, "{len} bytes");
        let mut r = &async_bytes[..];
        assert_eq!(
            read_frame_async(&mut r, MAX_FRAME_BYTES).await?,
            Some(payload)
        );
    }
    Ok(())
}

#[tokio::test]
async fn oversize_write_is_refused_before_any_byte() {
    let mut out = Vec::new();
    let err = write_frame_async(&mut out, &vec![0u8; MAX_FRAME_BYTES + 1]).await;
    assert!(matches!(err, Err(e) if e.kind() == io::ErrorKind::InvalidInput));
    assert!(out.is_empty());
}

/// Serves `data` and counts the bytes handed out.
struct CountingReader {
    data: Vec<u8>,
    pos: usize,
    served: usize,
}

impl AsyncRead for CountingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = buf.remaining().min(self.data.len() - self.pos);
        let start = self.pos;
        buf.put_slice(&self.data[start..start + n]);
        self.pos += n;
        self.served += n;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn too_large_is_returned_before_the_body_is_read() -> TestResult {
    let announced = u32::try_from(MAX_FRAME_BYTES + 1)?;
    let mut data = announced.to_be_bytes().to_vec();
    data.extend_from_slice(&[0xAA; 64]);
    let mut r = CountingReader {
        data,
        pos: 0,
        served: 0,
    };
    let got = read_frame_async(&mut r, MAX_FRAME_BYTES).await;
    assert!(matches!(
        got,
        Err(FrameError::TooLarge { len }) if len == MAX_FRAME_BYTES as u64 + 1
    ));
    assert_eq!(r.served, 4, "nothing past the header may be read");

    // The caller's smaller limit applies too.
    let mut small = &framed_len(10)[..];
    assert!(matches!(
        read_frame_async(&mut small, 9).await,
        Err(FrameError::TooLarge { len: 10 })
    ));
    Ok(())
}

fn framed_len(len: u32) -> Vec<u8> {
    let mut v = len.to_be_bytes().to_vec();
    v.extend(std::iter::repeat_n(0u8, len as usize));
    v
}

#[tokio::test]
async fn clean_eof_is_none_truncated_is_error() {
    let mut empty: &[u8] = &[];
    assert!(matches!(read_frame_async(&mut empty, 100).await, Ok(None)));
    for cut in [1usize, 3] {
        let mut r = &[0u8, 0, 0, 5][..cut];
        assert!(matches!(
            read_frame_async(&mut r, 100).await,
            Err(FrameError::Truncated)
        ));
    }
    let mut body_cut = &[0u8, 0, 0, 5, 1, 2][..];
    assert!(matches!(
        read_frame_async(&mut body_cut, 100).await,
        Err(FrameError::Truncated)
    ));
}
