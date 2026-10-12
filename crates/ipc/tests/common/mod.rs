//! Shared helpers for the server tests: a recording fake `RequestHandler` with programmable
//! delays, and a raw-frame client (no `IpcClient`).
#![allow(dead_code)]

use std::sync::Mutex;
use std::time::{Duration, Instant};

use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::paths::{DataDirResolution, LocalDataDir, check_data_dir};
use atlas_duck_ipc::proto::{
    AgentNameSource, AwaitParams, ClientKind, ConnectionMeta, Hello, HelloReply, ListState,
    MatchParams, ProgressNotification, ProgressSink, RequestHandler, SubmitParams, SubmitReply,
};
use atlas_duck_ipc::rpc::frame::{FrameError, read_frame_async, write_frame_async};
use atlas_duck_ipc::sandbox::MAX_FRAME_BYTES;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Upper bound for anything a test waits on.
pub const WAIT: Duration = Duration::from_secs(10);

pub const BUILD: &str = "test-build";

// ---------- fake handler ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Hello,
    OpsList,
    OpsDescribe,
    InstancesList,
    Submit,
    SubmitDone,
    ScriptSubmit,
    AwaitStart,
    AwaitDone,
    AwaitDropped,
    Status,
    Cancel,
    RequestsList,
    Doctor,
    Disconnected,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub kind: Kind,
    pub conn: Option<ConnectionMeta>,
    pub at: Instant,
    /// A free-form detail (request id, op id).
    pub detail: Option<String>,
}

/// Records every call; answers with an envelope whose `data.by` names the handler.
pub struct Fake {
    pub name: &'static str,
    events: Mutex<Vec<Event>>,
    /// `Some(env)`: `hello` refuses with it.
    pub hello_refusal: Mutex<Option<Envelope>>,
    pub submit_delay: Duration,
    pub await_delay: Duration,
    /// Progress statuses the await emits before it sleeps.
    pub progress: Vec<Status>,
    /// `doctor` answers with this many bytes of payload (0: a small envelope).
    pub doctor_bytes: usize,
}

impl Fake {
    pub fn new(name: &'static str) -> Fake {
        Fake {
            name,
            events: Mutex::new(Vec::new()),
            hello_refusal: Mutex::new(None),
            submit_delay: Duration::ZERO,
            await_delay: Duration::ZERO,
            progress: Vec::new(),
            doctor_bytes: 0,
        }
    }

    fn record(&self, kind: Kind, conn: Option<&ConnectionMeta>, detail: Option<String>) {
        if let Ok(mut g) = self.events.lock() {
            g.push(Event {
                kind,
                conn: conn.cloned(),
                at: Instant::now(),
                detail,
            });
        }
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn of(&self, kind: Kind) -> Vec<Event> {
        self.events()
            .into_iter()
            .filter(|e| e.kind == kind)
            .collect()
    }

    pub fn count(&self, kind: Kind) -> usize {
        self.of(kind).len()
    }

    /// Polls until `kind` was recorded `n` times; panics after [`WAIT`].
    pub async fn wait_for(&self, kind: Kind, n: usize) -> Vec<Event> {
        let deadline = Instant::now() + WAIT;
        loop {
            let got = self.of(kind);
            if got.len() >= n {
                return got;
            }
            assert!(
                Instant::now() < deadline,
                "{}: {kind:?} seen {} times, expected {n}; events {:?}",
                self.name,
                got.len(),
                self.events().iter().map(|e| e.kind).collect::<Vec<_>>()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn answer(&self, method: &str) -> Envelope {
        Envelope {
            request_id: None,
            op_id: None,
            instance: None,
            status: Status::Succeeded,
            data: Some(json!({"by": self.name, "method": method})),
            edited: false,
            redacted: false,
            redaction_note: None,
            message: None,
            error: None,
            meta: None,
        }
    }
}

/// Records `AwaitDropped` unless disarmed (the await future was dropped mid-wait).
struct DropGuard<'a> {
    fake: &'a Fake,
    conn: ConnectionMeta,
    armed: bool,
}

impl Drop for DropGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.fake.record(Kind::AwaitDropped, Some(&self.conn), None);
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Fake {
    async fn hello(&self, conn: &ConnectionMeta, h: Hello) -> Result<HelloReply, Envelope> {
        self.record(Kind::Hello, Some(conn), Some(h.build_id.clone()));
        let refusal = self.hello_refusal.lock().ok().and_then(|g| g.clone());
        match refusal {
            Some(env) => Err(env),
            None => Ok(HelloReply {
                build_id: BUILD.to_owned(),
            }),
        }
    }

    async fn ops_list(&self, instance: Option<&str>) -> Envelope {
        self.record(Kind::OpsList, None, instance.map(str::to_owned));
        self.answer("ops.list")
    }

    async fn ops_describe(&self, op_id: &str, _instance: Option<&str>) -> Envelope {
        self.record(Kind::OpsDescribe, None, Some(op_id.to_owned()));
        self.answer("ops.describe")
    }

    async fn instances_list(&self) -> Envelope {
        self.record(Kind::InstancesList, None, None);
        self.answer("instances.list")
    }

    async fn submit(&self, conn: &ConnectionMeta, p: SubmitParams) -> SubmitReply {
        self.record(Kind::Submit, Some(conn), Some(p.op_id.clone()));
        tokio::time::sleep(self.submit_delay).await;
        self.record(Kind::SubmitDone, Some(conn), Some(p.op_id));
        let mut envelope = self.answer("request.submit");
        envelope.status = Status::Pending;
        envelope.request_id = Some("req_00000000000000000000000000000001".to_owned());
        SubmitReply {
            envelope,
            params_sha256: Some("00".repeat(32)),
        }
    }

    async fn submit_script(&self, conn: &ConnectionMeta, p: SubmitParams) -> SubmitReply {
        self.record(Kind::ScriptSubmit, Some(conn), Some(p.op_id));
        SubmitReply {
            envelope: self.answer("script.submit"),
            params_sha256: None,
        }
    }

    async fn await_request(
        &self,
        conn: &ConnectionMeta,
        a: AwaitParams,
        progress: &dyn ProgressSink,
    ) -> Envelope {
        self.record(Kind::AwaitStart, Some(conn), Some(a.request_id.clone()));
        let mut guard = DropGuard {
            fake: self,
            conn: conn.clone(),
            armed: true,
        };
        for status in &self.progress {
            progress.progress(ProgressNotification {
                request_id: a.request_id.clone(),
                status: *status,
            });
        }
        tokio::time::sleep(self.await_delay).await;
        guard.armed = false;
        self.record(Kind::AwaitDone, Some(conn), Some(a.request_id));
        self.answer("request.await")
    }

    async fn status(&self, request_id: &str) -> Envelope {
        self.record(Kind::Status, None, Some(request_id.to_owned()));
        self.answer("request.status")
    }

    async fn cancel(&self, request_id: &str) -> Envelope {
        self.record(Kind::Cancel, None, Some(request_id.to_owned()));
        self.answer("request.cancel")
    }

    async fn requests_list(
        &self,
        _agent: Option<&str>,
        _state: Option<ListState>,
        _match_params: Option<MatchParams>,
    ) -> Envelope {
        self.record(Kind::RequestsList, None, None);
        self.answer("requests.list")
    }

    async fn doctor(&self) -> Envelope {
        self.record(Kind::Doctor, None, None);
        let mut env = self.answer("doctor");
        if self.doctor_bytes > 0 {
            env.data = Some(json!({"by": self.name, "blob": "x".repeat(self.doctor_bytes)}));
        }
        env
    }

    async fn disconnected(&self, conn: &ConnectionMeta) {
        self.record(Kind::Disconnected, Some(conn), None);
    }
}

/// `failed` / `protocol_mismatch` with the two builds, as `core::hello_check` builds it.
pub fn mismatch_envelope() -> Envelope {
    let mut env = Envelope::failed(
        ErrorCode::ProtocolMismatch,
        true,
        "client and app builds differ",
    );
    if let Some(err) = env.error.as_mut() {
        err.details = json!({"client_build": "old", "server_build": BUILD})
            .as_object()
            .cloned();
    }
    env
}

// ---------- data dir ----------

pub fn local(dir: &std::path::Path) -> LocalDataDir {
    match check_data_dir(dir).expect("check_data_dir") {
        DataDirResolution::Local(d) => d,
        other => panic!("temp dir is not a local data dir: {other:?}"),
    }
}

// ---------- raw client ----------

pub fn hello_params() -> Value {
    serde_json::to_value(Hello {
        build_id: BUILD.to_owned(),
        client_kind: ClientKind::Cli,
        agent_name: Some("tester".to_owned()),
        agent_name_source: AgentNameSource::Flag,
        cwd_basename: "repo".to_owned(),
    })
    .expect("hello json")
}

pub fn request(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

#[cfg(unix)]
type Stream = tokio::net::UnixStream;
#[cfg(windows)]
type Stream = tokio::net::windows::named_pipe::NamedPipeClient;

/// A client that speaks raw frames.
pub struct Client {
    stream: Stream,
}

impl Client {
    #[cfg(unix)]
    pub async fn connect(name: &str) -> Client {
        let stream = tokio::net::UnixStream::connect(name)
            .await
            .expect("connect");
        Client { stream }
    }

    #[cfg(windows)]
    pub async fn connect(name: &str) -> Client {
        let deadline = Instant::now() + WAIT;
        loop {
            match atlas_duck_ipc::transport::windows::open_client(name) {
                Ok(stream) => return Client { stream },
                // All instances momentarily busy: the server creates the next one.
                Err(e) if e.raw_os_error() == Some(231) && Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => panic!("open_client: {e}"),
            }
        }
    }

    /// Connects and completes `hello`.
    pub async fn hello(name: &str) -> Client {
        let mut c = Client::connect(name).await;
        let reply = c.call(0, "hello", hello_params()).await;
        assert_eq!(reply["result"]["build_id"], json!(BUILD), "{reply}");
        c
    }

    pub async fn send(&mut self, v: &Value) {
        let bytes = serde_json::to_vec(v).expect("encode");
        write_frame_async(&mut self.stream, &bytes)
            .await
            .expect("write frame");
    }

    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.expect("write raw");
        self.stream.flush().await.expect("flush");
    }

    /// The next frame as JSON; `None` once the server closed the connection.
    pub async fn recv(&mut self) -> Option<Value> {
        let got = tokio::time::timeout(WAIT, read_frame_async(&mut self.stream, MAX_FRAME_BYTES))
            .await
            .expect("no frame and no close within WAIT");
        match got {
            Ok(Some(bytes)) => Some(serde_json::from_slice(&bytes).expect("server sent JSON")),
            Ok(None) | Err(FrameError::Io(_)) | Err(FrameError::Truncated) => None,
            Err(e) => panic!("bad frame from server: {e:?}"),
        }
    }

    /// Sends a request and returns the next frame that is not a notification.
    pub async fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(&request(id, method, params)).await;
        loop {
            let v = self
                .recv()
                .await
                .expect("connection closed before the answer");
            if v.get("method").is_none() {
                return v;
            }
        }
    }

    /// True iff the server closes the connection (no further frame) within [`WAIT`].
    pub async fn closed(&mut self) -> bool {
        self.recv().await.is_none()
    }

    pub fn stream(&mut self) -> &mut (impl AsyncRead + AsyncWrite + Unpin) {
        &mut self.stream
    }
}

/// `error.code` and `error.data.error.details.reason` of an error response.
pub fn error_of(v: &Value) -> (i64, Option<String>) {
    let code = v["error"]["code"].as_i64().expect("an error response");
    let reason = v["error"]["data"]["error"]["details"]["reason"]
        .as_str()
        .map(str::to_owned);
    (code, reason)
}
