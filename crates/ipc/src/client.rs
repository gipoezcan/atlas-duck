//! The IPC client (§3.2, §3.3, §4.7, C.2): finds this user's endpoint, connects with the
//! server-owner check before any byte is written (§3.2 (a)), runs the `hello` build match
//! (§3.2 (b), PD-08), then calls methods.
//!
//! Discovery: Unix computes the socket path (`endpoint_location`) and never creates the socket
//! dir; Windows reads `<data>/endpoint` on every connect (the server may have rebound under a
//! fresh name) and accepts only a name with this user's SID prefix.
//!
//! After the hello, one background task per client reads every frame the server sends: a
//! response goes to the waiting call by id, a `request.progress` notification to the active
//! progress callback. A call whose future is dropped leaves the connection usable; its answer
//! is discarded when it arrives. Memory per client is one frame (at most 24 MiB) plus a bounded
//! notification queue.

use std::cmp::Ordering;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Instant;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncWrite, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::envelope::{Envelope, ErrorCode};
use crate::paths::{EndpointLocation, LocalDataDir, endpoint_location};
use crate::proto::{BUSY_RETRY_CONNECTION_S, Hello, HelloReply, ProgressNotification};
use crate::rpc::frame::{FrameError, read_frame_async, write_frame_async};
use crate::rpc::{
    Incoming, Notification, Request, Response, ResponseBody, RpcError, TwoPointZero, codes, method,
};
use crate::sandbox::MAX_FRAME_BYTES;
use crate::transport::Conn;

/// The server-owner check `connect_at` runs before the first byte (§3.2 (a)): Unix
/// `transport::unix::OwnerCheck`, Windows `transport::windows::PipeOwnerProbe`.
#[cfg(unix)]
pub use crate::transport::unix::OwnerCheck as ServerCheck;
/// The server-owner check `connect_at` runs before the first byte (§3.2 (a)): Unix
/// `transport::unix::OwnerCheck`, Windows `transport::windows::PipeOwnerProbe`.
#[cfg(windows)]
pub use crate::transport::windows::PipeOwnerProbe as ServerCheck;

/// The id of the `hello` request; calls count up from the next one.
const HELLO_ID: u64 = 1;
/// Progress notifications queued for the callback; beyond it they are dropped (§4.5: progress
/// is advisory, the answer itself always arrives).
const PROGRESS_QUEUE: usize = 64;
/// Windows: endpoint-file reads per connect. A name whose pipe is gone is read once more, in
/// case the server rebound under a fresh name in between.
#[cfg(windows)]
const ENDPOINT_READS: usize = 3;

const MSG_WRONG_LOCATION: &str = "endpoint location is not for this OS";
const MSG_BAD_HELLO_ANSWER: &str = "the server's answer to hello is not a hello reply";
const MSG_ENCODE: &str = "the request could not be encoded";
const MSG_TOO_LARGE: &str = "the request exceeds the 24 MiB frame limit";
const MSG_TORN: &str = "an earlier call was cancelled while its request was being written";
const MSG_SERVER_REQUEST: &str = "the server sent a request";
const MSG_BAD_MESSAGE: &str = "the server sent a frame that is not a JSON-RPC message";

/// What the CLI needs to reach its server (C.2).
#[derive(Debug, Clone)]
pub struct ClientContext {
    pub data_dir: LocalDataDir,
    /// The sanitized host component (`paths::host_name()`); Unix socket dirs depend on it.
    pub host: String,
    pub hello: Hello,
}

/// Why `connect` gave no client (C.2 + Δ3).
#[derive(Debug)]
// `Hello` carries a whole envelope; boxing it would complicate every match for no gain.
#[allow(clippy::large_enum_variant)]
pub enum ConnectError {
    /// No endpoint (§4.7: launch). Unix: no socket dir, no socket, or nothing listening on it.
    /// Windows: no endpoint file, a file the server never writes, a name without this user's
    /// SID prefix, or no pipe of that name.
    NotRunning,
    /// §3.2 (a) failed and nothing was sent, or the server closed the connection after the
    /// hello frame without an answer (a Windows server does that to a client whose SID it
    /// refuses). Exit 5 `server_identity`.
    ServerIdentity,
    /// CLI-local busy, never a launch: Windows `ERROR_PIPE_BUSY` after the `WaitNamedPipeW`
    /// wait, Unix `EAGAIN` from `connect` (the listen backlog is full). Exit 11 with
    /// `retry_after_s: 5`.
    PipeBusy,
    /// The server's connection limit (PD-27): the hello was refused with `busy`.
    Busy { retry_after_s: u64 },
    /// The deadline passed before the hello round trip completed; nothing was submitted.
    DeadlineExceeded,
    /// `protocol_mismatch` (§3.3): the hello was refused for another build, or the server
    /// answered with a build other than ours. `client_newer` per PD-08.
    BuildMismatch {
        client_newer: bool,
        client_build: String,
        server_build: String,
    },
    /// Any other hello refusal, as the server's envelope: every other `-32000` refusal, and a
    /// protocol error the server answered the hello with.
    Hello(Envelope),
    /// Any other IO error, or an answer that is not a JSON-RPC response to the hello.
    Io(io::Error),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectError::NotRunning => f.write_str("the atlas-duck app is not running"),
            ConnectError::ServerIdentity => f.write_str("server identity check failed"),
            ConnectError::PipeBusy => f.write_str("the endpoint is busy"),
            ConnectError::Busy { retry_after_s } => {
                write!(f, "the server is busy; retry after {retry_after_s} s")
            }
            ConnectError::DeadlineExceeded => f.write_str("the deadline passed while connecting"),
            ConnectError::BuildMismatch {
                client_build,
                server_build,
                ..
            } => write!(
                f,
                "build mismatch: client {client_build}, server {server_build}"
            ),
            ConnectError::Hello(env) => match &env.error {
                Some(e) => write!(f, "hello refused: {}", e.message),
                None => f.write_str("hello refused"),
            },
            ConnectError::Io(e) => write!(f, "connect failed: {e}"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConnectError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Why a call gave no answer.
#[derive(Debug)]
// `Rpc` carries a whole envelope; see `ConnectError`.
#[allow(clippy::large_enum_variant)]
pub enum ClientError {
    /// The server answered with a JSON-RPC error; `data` is its envelope.
    Rpc(RpcError),
    /// The connection closed (EOF or a read/write error) before the answer arrived.
    ConnectionLost,
    /// The server broke the protocol, the answer does not have the expected shape, or an
    /// earlier call was cancelled mid-write (the stream is no longer framed).
    Protocol(String),
    /// For callers that bound a call by a deadline; `call` itself has no deadline.
    DeadlineExceeded,
    /// The request could not be encoded or is over the frame limit (nothing was written), or
    /// another IO error.
    Io(io::Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Rpc(e) => write!(f, "server error {}: {}", e.code, e.message),
            ClientError::ConnectionLost => f.write_str("the connection to the server was lost"),
            ClientError::Protocol(m) => write!(f, "protocol error: {m}"),
            ClientError::DeadlineExceeded => f.write_str("the deadline passed"),
            ClientError::Io(e) => write!(f, "call failed: {e}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// PD-08: compares the version halves (the text before `+`, or the whole string) of two build
/// ids as `major.minor.patch` integers. `None` unless both are exactly three non-empty groups
/// of ASCII digits. `Equal` does not mean the builds match (the commits may differ).
pub fn compare_build_versions(client: &str, server: &str) -> Option<Ordering> {
    Some(version_triple(client)?.cmp(&version_triple(server)?))
}

fn version_triple(build: &str) -> Option<(u64, u64, u64)> {
    let version = build.split_once('+').map_or(build, |(v, _)| v);
    let mut parts = version.split('.');
    let major = version_part(parts.next())?;
    let minor = version_part(parts.next())?;
    let patch = version_part(parts.next())?;
    parts.next().is_none().then_some((major, minor, patch))
}

fn version_part(part: Option<&str>) -> Option<u64> {
    part.filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))?
        .parse()
        .ok()
}

// ---------- the client ----------

/// A connection that passed the owner check and the hello. Calls are sequential (`&mut self`).
pub struct IpcClient {
    writer: WriteHalf<Conn>,
    routes: Arc<Mutex<Routes>>,
    reader: JoinHandle<()>,
    next_id: u64,
    /// Any byte of a non-hello request was written.
    written: bool,
    unusable: Option<Unusable>,
}

/// Why no further call can be made.
#[derive(Debug, Clone, Copy)]
enum Unusable {
    /// A call's future was dropped while its frame was being written.
    Torn,
    /// A write failed.
    Lost,
}

impl fmt::Debug for IpcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IpcClient")
    }
}

impl Drop for IpcClient {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl IpcClient {
    /// Connects to this user's server (§3.2, §4.7): the endpoint (Unix: the socket path from
    /// `endpoint_location`; Windows: the name in `<data>/endpoint`, read now), the owner check
    /// for the current user before any byte, then the `hello` round trip. Everything up to the
    /// hello answer is bounded by `deadline`.
    ///
    /// Must be polled inside a tokio runtime with IO and time enabled.
    pub async fn connect(
        ctx: &ClientContext,
        deadline: Instant,
    ) -> Result<IpcClient, ConnectError> {
        let location = endpoint_location(&ctx.data_dir, &ctx.host).map_err(ConnectError::Io)?;
        #[cfg(unix)]
        let check = crate::transport::unix::SameUser;
        #[cfg(windows)]
        let check = crate::transport::windows::SameUser::current().map_err(ConnectError::Io)?;
        Self::connect_at(&location, &ctx.data_dir, &ctx.hello, &check, deadline).await
    }

    /// `connect` at an explicit location with an explicit owner check (tests: a socket in a
    /// temp dir, check doubles). Production code calls `connect`.
    #[doc(hidden)]
    pub async fn connect_at(
        location: &EndpointLocation,
        data: &LocalDataDir,
        hello: &Hello,
        check: &dyn ServerCheck,
        deadline: Instant,
    ) -> Result<IpcClient, ConnectError> {
        if Instant::now() >= deadline {
            return Err(ConnectError::DeadlineExceeded);
        }
        let at = tokio::time::Instant::from_std(deadline);
        let conn = tokio::time::timeout_at(at, open(location, data, check, deadline))
            .await
            .map_err(|_| ConnectError::DeadlineExceeded)??;
        let (mut rd, mut wr) = conn.split();
        // Not cancel-safe (a frame read): on a timeout the connection is dropped.
        let reply = tokio::time::timeout_at(at, handshake(&mut rd, &mut wr, hello))
            .await
            .map_err(|_| ConnectError::DeadlineExceeded)??;
        if reply.build_id != hello.build_id {
            return Err(mismatch(&hello.build_id, reply.build_id));
        }
        Ok(IpcClient::start(rd, wr))
    }

    fn start(rd: ReadHalf<Conn>, writer: WriteHalf<Conn>) -> IpcClient {
        let routes = Arc::new(Mutex::new(Routes::default()));
        let reader = tokio::spawn(read_loop(rd, routes.clone()));
        IpcClient {
            writer,
            routes,
            reader,
            next_id: HELLO_ID + 1,
            written: false,
            unusable: None,
        }
    }

    /// True once any byte of a request other than `hello` was written on this connection
    /// (PD-16: an interrupt before that point queued nothing).
    pub fn written_request(&self) -> bool {
        self.written
    }

    /// Sends `method` with `params` and waits for its answer. `request.progress` notifications
    /// that arrive meanwhile are dropped. EOF before the answer is `ConnectionLost`.
    pub async fn call<R: DeserializeOwned>(
        &mut self,
        method: &str,
        params: impl Serialize,
    ) -> Result<R, ClientError> {
        self.call_inner(method, params, None).await
    }

    /// `call`, passing every `request.progress` notification that arrives before the answer to
    /// `on_progress`, in order. If the notification queue (64) overflows, the newest are
    /// dropped; the answer always arrives.
    pub async fn call_with_progress<R: DeserializeOwned>(
        &mut self,
        method: &str,
        params: impl Serialize,
        on_progress: &mut (dyn FnMut(ProgressNotification) + Send),
    ) -> Result<R, ClientError> {
        self.call_inner(method, params, Some(on_progress)).await
    }

    async fn call_inner<R: DeserializeOwned>(
        &mut self,
        method: &str,
        params: impl Serialize,
        mut on_progress: Option<&mut (dyn FnMut(ProgressNotification) + Send)>,
    ) -> Result<R, ClientError> {
        match self.unusable {
            Some(Unusable::Torn) => return Err(ClientError::Protocol(MSG_TORN.to_owned())),
            Some(Unusable::Lost) => return Err(ClientError::ConnectionLost),
            None => {}
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let bytes = encode_request(id, method, params).map_err(ClientError::Io)?;

        let (tx, mut answer) = oneshot::channel();
        let (progress_tx, mut progress) = mpsc::channel(PROGRESS_QUEUE);
        {
            let mut r = lock(&self.routes);
            if let Some(closed) = &r.closed {
                return Err(closed.to_error());
            }
            r.waiting = Some((id, tx));
            r.progress = on_progress.is_some().then_some(progress_tx);
        }
        let _unroute = Unroute {
            routes: &self.routes,
            id,
        };

        self.unusable = Some(Unusable::Torn);
        let mut tracked = Tracked {
            inner: &mut self.writer,
            wrote: &mut self.written,
        };
        if let Err(e) = write_frame_async(&mut tracked, &bytes).await {
            self.unusable = Some(Unusable::Lost);
            return Err(if is_gone(&e) {
                ClientError::ConnectionLost
            } else {
                ClientError::Io(e)
            });
        }
        self.unusable = None;

        // The reader queues a notification before the answer that follows it, so `biased`
        // hands every earlier notification over first.
        let got = loop {
            tokio::select! {
                biased;
                Some(n) = progress.recv(), if on_progress.is_some() => {
                    if let Some(f) = on_progress.as_mut() {
                        f(n);
                    }
                }
                got = &mut answer => break got,
            }
        };
        if let Some(f) = on_progress.as_mut() {
            while let Ok(n) = progress.try_recv() {
                f(n);
            }
        }
        let response = match got {
            Ok(r) => r,
            Err(_) => return Err(self.closed_error()),
        };
        match response.body {
            ResponseBody::Result(v) => serde_json::from_value(v)
                .map_err(|e| ClientError::Protocol(format!("unexpected answer to {method}: {e}"))),
            ResponseBody::Error(e) => Err(ClientError::Rpc(e)),
        }
    }

    fn closed_error(&self) -> ClientError {
        lock(&self.routes)
            .closed
            .as_ref()
            .map_or(ClientError::ConnectionLost, Closed::to_error)
    }
}

/// The request frame; `InvalidInput` if it cannot be encoded or is over the frame limit.
fn encode_request(id: u64, method: &str, params: impl Serialize) -> io::Result<Vec<u8>> {
    let encode = |_| io::Error::new(io::ErrorKind::InvalidInput, MSG_ENCODE);
    let req = Request {
        jsonrpc: TwoPointZero,
        id,
        method: method.to_owned(),
        params: serde_json::to_value(params).map_err(encode)?,
    };
    let bytes = serde_json::to_vec(&req).map_err(encode)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, MSG_TOO_LARGE));
    }
    Ok(bytes)
}

/// The peer is gone (as opposed to some other IO failure).
fn is_gone(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}

fn invalid_data(msg: &str) -> ConnectError {
    ConnectError::Io(io::Error::new(io::ErrorKind::InvalidData, msg))
}

// ---------- connect ----------

/// Unix: the owner-checked connect to the socket (`connect_checked` checks the socket dir
/// without creating it).
#[cfg(unix)]
async fn open(
    location: &EndpointLocation,
    _data: &LocalDataDir,
    check: &dyn ServerCheck,
    _deadline: Instant,
) -> Result<Conn, ConnectError> {
    use crate::transport::unix::{ConnectFailure, connect_checked};

    let EndpointLocation::UnixSocket(path) = location else {
        return Err(ConnectError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            MSG_WRONG_LOCATION,
        )));
    };
    connect_checked(path, check).await.map_err(|f| match f {
        ConnectFailure::NotFound | ConnectFailure::Refused => ConnectError::NotRunning,
        ConnectFailure::ServerIdentity => ConnectError::ServerIdentity,
        // A full listen backlog: busy, retry later (never "not running", never a launch).
        ConnectFailure::Io(e) if e.kind() == io::ErrorKind::WouldBlock => ConnectError::PipeBusy,
        ConnectFailure::Io(e) => ConnectError::Io(e),
    })
}

/// Windows: the name in `<data>/endpoint` (read on every attempt), then the owner-checked
/// open. A name without this user's prefix is never opened.
#[cfg(windows)]
async fn open(
    location: &EndpointLocation,
    data: &LocalDataDir,
    check: &dyn ServerCheck,
    deadline: Instant,
) -> Result<Conn, ConnectError> {
    use crate::paths::{pipe_name_has_prefix, read_endpoint_file};
    use crate::transport::windows::{ConnectFailure, connect_checked};

    let EndpointLocation::WindowsPipePrefix(prefix) = location else {
        return Err(ConnectError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            MSG_WRONG_LOCATION,
        )));
    };
    let mut gone: Option<String> = None;
    for _ in 0..ENDPOINT_READS {
        let name = match read_endpoint_file(data) {
            Ok(Some(name)) if pipe_name_has_prefix(&name, prefix) => name,
            // No file, or a name that is not this user's (§3.1).
            Ok(_) => return Err(ConnectError::NotRunning),
            // A file the server never writes (it writes one valid name atomically).
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                return Err(ConnectError::NotRunning);
            }
            Err(e) => return Err(ConnectError::Io(e)),
        };
        if gone.as_deref() == Some(name.as_str()) {
            return Err(ConnectError::NotRunning);
        }
        match connect_checked(&name, check, deadline).await {
            Ok(client) => return Ok(Conn::new(client)),
            Err(ConnectFailure::NotFound) => gone = Some(name),
            Err(ConnectFailure::PipeBusy) => return Err(ConnectError::PipeBusy),
            Err(ConnectFailure::ServerIdentity) => return Err(ConnectError::ServerIdentity),
            Err(ConnectFailure::Io(e)) => return Err(ConnectError::Io(e)),
        }
    }
    Err(ConnectError::NotRunning)
}

/// Writes `hello` and reads its answer. No answer at all (EOF or a read error after the hello
/// frame) is `ServerIdentity`: a server that refuses the client's identity closes unanswered.
async fn handshake(
    rd: &mut ReadHalf<Conn>,
    wr: &mut WriteHalf<Conn>,
    hello: &Hello,
) -> Result<HelloReply, ConnectError> {
    let req = Request {
        jsonrpc: TwoPointZero,
        id: HELLO_ID,
        method: method::HELLO.to_owned(),
        params: serde_json::to_value(hello).map_err(|_| invalid_data(MSG_ENCODE))?,
    };
    let bytes = serde_json::to_vec(&req).map_err(|_| invalid_data(MSG_ENCODE))?;
    if let Err(e) = write_frame_async(wr, &bytes).await {
        return Err(if is_gone(&e) {
            ConnectError::ServerIdentity
        } else {
            ConnectError::Io(e)
        });
    }
    loop {
        let frame = match read_frame_async(rd, MAX_FRAME_BYTES).await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(FrameError::Truncated | FrameError::Io(_)) => {
                return Err(ConnectError::ServerIdentity);
            }
            Err(FrameError::TooLarge { .. }) => return Err(invalid_data(MSG_BAD_HELLO_ANSWER)),
        };
        match serde_json::from_slice::<Incoming>(&frame) {
            Ok(Incoming::Notification(_)) => continue,
            Ok(Incoming::Response(r)) if r.id.is_none() || r.id == Some(HELLO_ID) => {
                return hello_answer(r, hello);
            }
            _ => return Err(invalid_data(MSG_BAD_HELLO_ANSWER)),
        }
    }
}

// The error carries a whole envelope (`ConnectError::Hello`).
#[allow(clippy::result_large_err)]
fn hello_answer(r: Response, hello: &Hello) -> Result<HelloReply, ConnectError> {
    match r.body {
        ResponseBody::Result(v) => {
            serde_json::from_value(v).map_err(|_| invalid_data(MSG_BAD_HELLO_ANSWER))
        }
        ResponseBody::Error(e) => Err(hello_refusal(e, hello)),
    }
}

/// `-32000` + `protocol_mismatch` → `BuildMismatch`; `-32000` + `busy` → `Busy`; any other
/// error with an envelope → `Hello(env)`.
fn hello_refusal(e: RpcError, hello: &Hello) -> ConnectError {
    let Some(env) = e.data else {
        return invalid_data(MSG_BAD_HELLO_ANSWER);
    };
    if e.code != codes::APP_REFUSAL {
        return ConnectError::Hello(env);
    }
    let details = env.error.as_ref().and_then(|x| x.details.as_ref());
    match env.error.as_ref().map(|x| x.code) {
        Some(ErrorCode::ProtocolMismatch) => {
            let server_build = details
                .and_then(|d| d.get("server_build"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            mismatch(&hello.build_id, server_build)
        }
        Some(ErrorCode::Busy) => ConnectError::Busy {
            retry_after_s: details
                .and_then(|d| d.get("retry_after_s"))
                .and_then(|v| v.as_u64())
                .unwrap_or(BUSY_RETRY_CONNECTION_S),
        },
        _ => ConnectError::Hello(env),
    }
}

/// `client_build` is always the build this client sent; the server only reports its own.
fn mismatch(client_build: &str, server_build: String) -> ConnectError {
    ConnectError::BuildMismatch {
        client_newer: compare_build_versions(client_build, &server_build)
            == Some(Ordering::Greater),
        client_build: client_build.to_owned(),
        server_build,
    }
}

// ---------- the reader task ----------

/// Where the reader task delivers what it reads.
#[derive(Default)]
struct Routes {
    /// The call waiting for its answer (calls are sequential, so at most one).
    waiting: Option<(u64, oneshot::Sender<Response>)>,
    /// The active progress callback's queue.
    progress: Option<mpsc::Sender<ProgressNotification>>,
    /// Set once the reader stopped; no answer will arrive.
    closed: Option<Closed>,
}

#[derive(Debug, Clone)]
enum Closed {
    /// EOF or a read error.
    Lost,
    /// The server broke the protocol.
    Protocol(String),
}

impl Closed {
    fn to_error(&self) -> ClientError {
        match self {
            Closed::Lost => ClientError::ConnectionLost,
            Closed::Protocol(m) => ClientError::Protocol(m.clone()),
        }
    }
}

fn lock(routes: &Mutex<Routes>) -> MutexGuard<'_, Routes> {
    routes.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Takes a call's route down when the call ends, answered or dropped.
struct Unroute<'a> {
    routes: &'a Mutex<Routes>,
    id: u64,
}

impl Drop for Unroute<'_> {
    fn drop(&mut self) {
        let mut r = lock(self.routes);
        if r.waiting.as_ref().is_some_and(|(id, _)| *id == self.id) {
            r.waiting = None;
        }
        r.progress = None;
    }
}

/// Reads frames until EOF, an error or a protocol violation, then marks the routes closed
/// (dropping the waiting sender wakes the call). Never blocks on anything but the read.
async fn read_loop(mut rd: ReadHalf<Conn>, routes: Arc<Mutex<Routes>>) {
    let closed = loop {
        let frame = match read_frame_async(&mut rd, MAX_FRAME_BYTES).await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(FrameError::Truncated | FrameError::Io(_)) => break Closed::Lost,
            Err(e @ FrameError::TooLarge { .. }) => break Closed::Protocol(e.to_string()),
        };
        match serde_json::from_slice::<Incoming>(&frame) {
            Ok(Incoming::Response(r)) => deliver(&routes, r),
            Ok(Incoming::Notification(n)) => notify(&routes, n),
            Ok(Incoming::Request(_)) => break Closed::Protocol(MSG_SERVER_REQUEST.to_owned()),
            Err(_) => break Closed::Protocol(MSG_BAD_MESSAGE.to_owned()),
        }
    };
    let mut r = lock(&routes);
    r.closed = Some(closed);
    r.waiting = None;
    r.progress = None;
}

/// Hands a response to the waiting call with its id. A `null` id (the server could not read
/// the request's id) goes to the waiting call if it is an error. Anything else (the answer to
/// a dropped call) is discarded.
fn deliver(routes: &Mutex<Routes>, response: Response) {
    let mut r = lock(routes);
    let ours = match (&r.waiting, response.id) {
        (Some((id, _)), Some(got)) => *id == got,
        (Some(_), None) => matches!(response.body, ResponseBody::Error(_)),
        (None, _) => false,
    };
    if ours && let Some((_, tx)) = r.waiting.take() {
        // The call may have been dropped meanwhile; then nobody wants the answer.
        let _ = tx.send(response);
    }
}

/// Queues a `request.progress` notification for the active callback, if any; other
/// notifications and unreadable params are ignored.
fn notify(routes: &Mutex<Routes>, n: Notification) {
    if n.method != method::REQUEST_PROGRESS {
        return;
    }
    let Ok(p) = serde_json::from_value::<ProgressNotification>(n.params) else {
        return;
    };
    if let Some(tx) = &lock(routes).progress {
        let _ = tx.try_send(p);
    }
}

// ---------- write tracking ----------

/// A writer that records whether any byte went out (PD-16).
struct Tracked<'a> {
    inner: &'a mut WriteHalf<Conn>,
    wrote: &'a mut bool,
}

impl AsyncWrite for Tracked<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let polled = Pin::new(&mut *this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = polled
            && n > 0
        {
            *this.wrote = true;
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}
