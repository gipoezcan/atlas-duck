//! The IPC client (§3.2, §3.3, §4.7, C.2): finds this user's endpoint, connects with the
//! server-owner check before any byte is written (§3.2 (a)), runs the `hello` build match
//! (§3.2 (b), PD-08), then calls methods.
//!
//! Discovery: Unix computes the socket path (`endpoint_location`) and never creates the socket
//! dir; Windows reads `<data>/endpoint` on every connect (the server may have rebound under a
//! fresh name) and accepts only a name with this user's SID prefix.
//!
//! The hello frame is built before anything is opened: `agent_name` and `cwd_basename` cut to
//! 64 characters (§3.3), the whole frame at most [`HELLO_MAX_BYTES`] (the server's first-frame
//! cap), its answer read with the same cap.
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
use std::time::{Duration, Instant};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
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
use crate::server::HELLO_MAX_BYTES;
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
/// §3.3: `agent_name` and `cwd_basename` are at most this many characters.
const HELLO_FIELD_MAX_CHARS: usize = 64;
/// After a write found the server gone, how long the call waits for an answer the server may
/// have sent before it closed (e.g. a `null`-id refusal of the frame). The reader sees the
/// close at once, so this only bounds a peer that stopped reading but kept the connection.
const GONE_ANSWER_WAIT: Duration = Duration::from_millis(500);
/// `server_build` of a `protocol_mismatch` refusal without one (PD-08 texts print it).
pub const UNKNOWN_BUILD: &str = "unknown";

const MSG_WRONG_LOCATION: &str = "endpoint location is not for this OS";
const MSG_BAD_HELLO_ANSWER: &str = "the server's answer to hello is not a hello reply";
const MSG_HELLO_NO_ENVELOPE: &str = "the server refused hello without an envelope";
const MSG_HELLO_WRONG_ID: &str = "the server answered a request other than hello";
const MSG_HELLO_ANSWER_TOO_LARGE: &str = "the server's answer to hello exceeds 64 KiB";
const MSG_HELLO_TOO_LARGE: &str = "the hello exceeds the 64 KiB first-frame limit";
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
    /// CLI-local busy, never a launch: Windows `ERROR_PIPE_BUSY` after the full 5 s
    /// `WaitNamedPipeW` wait, Unix `EAGAIN` from `connect` (the listen backlog is full). Exit
    /// 11 with `retry_after_s: 5`. A Windows connect whose deadline left less than those 5 s
    /// for the wait is `DeadlineExceeded` instead (§4.7).
    PipeBusy,
    /// The server's connection limit (PD-27): the hello was refused with `busy`.
    Busy { retry_after_s: u64 },
    /// The deadline passed before the hello round trip completed; nothing was submitted.
    /// Exit 5 `launch_timeout` (§4.7), never 11.
    DeadlineExceeded,
    /// `protocol_mismatch` (§3.3): the hello was refused for another build, or the server
    /// answered with a build other than ours. `client_newer` per PD-08. `server_build` is
    /// [`UNKNOWN_BUILD`] when the refusal did not name it (then `client_newer` is false).
    BuildMismatch {
        client_newer: bool,
        client_build: String,
        server_build: String,
    },
    /// Any other hello refusal, as the server's envelope: every other `-32000` refusal, and a
    /// protocol error the server answered the hello with (e.g. `frame_too_large`, `null` id).
    Hello(Envelope),
    /// The server's answer to the hello breaks the protocol: an oversize frame, not a JSON-RPC
    /// message, a server request, a response to another id, an error without an envelope, or
    /// a result that is not a hello reply. Exit 1 `protocol_error`, like `ClientError::Protocol`.
    Protocol(String),
    /// The hello could not be encoded or exceeds [`HELLO_MAX_BYTES`] (`InvalidInput`, nothing
    /// was opened), or any other IO error.
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
            ConnectError::Protocol(m) => write!(f, "protocol error: {m}"),
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
    /// A call's future was dropped after the first byte of its frame was written and before
    /// the last.
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
        let frame = hello_frame(hello).map_err(ConnectError::Io)?;
        let at = tokio::time::Instant::from_std(deadline);
        let conn = tokio::time::timeout_at(at, open(location, data, check, deadline))
            .await
            .map_err(|_| ConnectError::DeadlineExceeded)??;
        let (mut rd, mut wr) = conn.split();
        // Not cancel-safe (a frame read): on a timeout the connection is dropped.
        let reply = tokio::time::timeout_at(at, handshake(&mut rd, &mut wr, &frame, hello))
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
    ///
    /// Only notifications for the request named by `params.request_id` (a string; the server
    /// sends progress only for `request.await`) reach `on_progress`: a call dropped earlier
    /// may still be awaiting another request on the server, and its progress is not this
    /// call's. Without a `request_id` param nothing reaches `on_progress`.
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
        let (bytes, progress_of) = encode_request(id, method, params).map_err(ClientError::Io)?;

        let (tx, mut answer) = oneshot::channel();
        let (progress_tx, mut progress) = mpsc::channel(PROGRESS_QUEUE);
        {
            let mut r = lock(&self.routes);
            if let Some(closed) = &r.closed {
                return Err(closed.to_error());
            }
            r.waiting = Some((id, tx));
            r.progress = match (&on_progress, progress_of) {
                (Some(_), Some(request_id)) => Some((request_id, progress_tx)),
                _ => None,
            };
        }
        let _unroute = Unroute {
            routes: &self.routes,
            id,
        };

        // A future dropped after the first byte leaves the stream torn (`Tracked`).
        let mut tracked = Tracked {
            inner: &mut self.writer,
            wrote: &mut self.written,
            unusable: &mut self.unusable,
        };
        if let Err(e) = write_frame_async(&mut tracked, &bytes).await {
            self.unusable = Some(Unusable::Lost);
            return match answer_after_write_error(&e, &mut answer).await {
                Some(response) => answer_of(method, response),
                None if is_gone(&e) => Err(ClientError::ConnectionLost),
                None => Err(ClientError::Io(e)),
            };
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
        match got {
            Ok(response) => answer_of(method, response),
            Err(_) => Err(self.closed_error()),
        }
    }

    fn closed_error(&self) -> ClientError {
        lock(&self.routes)
            .closed
            .as_ref()
            .map_or(ClientError::ConnectionLost, Closed::to_error)
    }
}

/// The request frame and its `params.request_id` (the request whose progress the call may
/// see); `InvalidInput` if it cannot be encoded or is over the frame limit.
fn encode_request(
    id: u64,
    method: &str,
    params: impl Serialize,
) -> io::Result<(Vec<u8>, Option<String>)> {
    let params = serde_json::to_value(params).map_err(|_| encode_error())?;
    let request_id = params
        .get("request_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let req = Request {
        jsonrpc: TwoPointZero,
        id,
        method: method.to_owned(),
        params,
    };
    let bytes = serde_json::to_vec(&req).map_err(|_| encode_error())?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, MSG_TOO_LARGE));
    }
    Ok((bytes, request_id))
}

fn encode_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, MSG_ENCODE)
}

/// After a call's write failed: the answer the server sent before it closed (a `null`-id
/// refusal of a frame it did not read whole), which wins over the write error. A gone peer's
/// answer may still be on its way through the reader, which ends at the close; it is waited
/// for (bounded). Otherwise only an answer already routed counts.
async fn answer_after_write_error(
    e: &io::Error,
    answer: &mut oneshot::Receiver<Response>,
) -> Option<Response> {
    if is_gone(e) {
        tokio::time::timeout(GONE_ANSWER_WAIT, answer)
            .await
            .ok()
            .and_then(Result::ok)
    } else {
        answer.try_recv().ok()
    }
}

/// A call's answer: the result as `R`, or the JSON-RPC error.
// The error carries a whole envelope (`ClientError::Rpc`).
#[allow(clippy::result_large_err)]
fn answer_of<R: DeserializeOwned>(method: &str, response: Response) -> Result<R, ClientError> {
    match response.body {
        ResponseBody::Result(v) => serde_json::from_value(v)
            .map_err(|e| ClientError::Protocol(format!("unexpected answer to {method}: {e}"))),
        ResponseBody::Error(e) => Err(ClientError::Rpc(e)),
    }
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

fn protocol(msg: &str) -> ConnectError {
    ConnectError::Protocol(msg.to_owned())
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
    use crate::transport::windows::{BUSY_WAIT_MAX, ConnectFailure, connect_checked};

    let EndpointLocation::WindowsPipePrefix(prefix) = location else {
        return Err(ConnectError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            MSG_WRONG_LOCATION,
        )));
    };
    // §4.7: busy (exit 11) only after the full busy wait; a wait the deadline cut short is the
    // deadline (exit 5 `launch_timeout`).
    let busy = if deadline.saturating_duration_since(Instant::now()) < BUSY_WAIT_MAX {
        ConnectError::DeadlineExceeded
    } else {
        ConnectError::PipeBusy
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
            Err(ConnectFailure::PipeBusy) => return Err(busy),
            Err(ConnectFailure::ServerIdentity) => return Err(ConnectError::ServerIdentity),
            Err(ConnectFailure::Io(e)) => return Err(ConnectError::Io(e)),
        }
    }
    Err(ConnectError::NotRunning)
}

/// The `hello` request frame: `agent_name` and `cwd_basename` cut to 64 characters (§3.3);
/// `InvalidInput` if it cannot be encoded or exceeds the first-frame cap [`HELLO_MAX_BYTES`]
/// (the server would refuse it with `frame_too_large`).
fn hello_frame(hello: &Hello) -> io::Result<Vec<u8>> {
    let mut hello = hello.clone();
    if let Some(name) = hello.agent_name.as_mut() {
        truncate_chars(name, HELLO_FIELD_MAX_CHARS);
    }
    truncate_chars(&mut hello.cwd_basename, HELLO_FIELD_MAX_CHARS);
    let req = Request {
        jsonrpc: TwoPointZero,
        id: HELLO_ID,
        method: method::HELLO.to_owned(),
        params: serde_json::to_value(&hello).map_err(|_| encode_error())?,
    };
    let bytes = serde_json::to_vec(&req).map_err(|_| encode_error())?;
    if bytes.len() > HELLO_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            MSG_HELLO_TOO_LARGE,
        ));
    }
    Ok(bytes)
}

/// Keeps the first `max` characters of `s`.
fn truncate_chars(s: &mut String, max: usize) {
    if let Some((at, _)) = s.char_indices().nth(max) {
        s.truncate(at);
    }
}

/// Writes the hello `frame` and reads its answer. A write that finds the server gone still
/// reads: a server that refuses the frame (`frame_too_large`) answers and closes without
/// reading all of it. No answer at all (EOF or a read error) is `ServerIdentity`: a server
/// that refuses the client's identity closes unanswered.
async fn handshake<R, W>(
    rd: &mut R,
    wr: &mut W,
    frame: &[u8],
    hello: &Hello,
) -> Result<HelloReply, ConnectError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if let Err(e) = write_frame_async(wr, frame).await
        && !is_gone(&e)
    {
        return Err(ConnectError::Io(e));
    }
    loop {
        let frame = match read_frame_async(rd, HELLO_MAX_BYTES).await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(FrameError::Truncated | FrameError::Io(_)) => {
                return Err(ConnectError::ServerIdentity);
            }
            Err(FrameError::TooLarge { .. }) => return Err(protocol(MSG_HELLO_ANSWER_TOO_LARGE)),
        };
        return match serde_json::from_slice::<Incoming>(&frame) {
            Ok(Incoming::Notification(_)) => continue,
            Ok(Incoming::Response(r)) => hello_answer(r, hello),
            Ok(Incoming::Request(_)) => Err(protocol(MSG_SERVER_REQUEST)),
            Err(_) => Err(protocol(MSG_BAD_MESSAGE)),
        };
    }
}

/// The answer to the hello: a result with id 1, or an error with id 1 or `null` (the server
/// could not read the id). Anything else breaks the protocol.
// The error carries a whole envelope (`ConnectError::Hello`).
#[allow(clippy::result_large_err)]
fn hello_answer(r: Response, hello: &Hello) -> Result<HelloReply, ConnectError> {
    match (r.id, r.body) {
        (Some(HELLO_ID), ResponseBody::Result(v)) => {
            serde_json::from_value(v).map_err(|_| protocol(MSG_BAD_HELLO_ANSWER))
        }
        (Some(HELLO_ID) | None, ResponseBody::Error(e)) => Err(hello_refusal(e, hello)),
        _ => Err(protocol(MSG_HELLO_WRONG_ID)),
    }
}

/// `-32000` + `protocol_mismatch` → `BuildMismatch`; `-32000` + `busy` → `Busy`; any other
/// error with an envelope → `Hello(env)`; an error without one → `Protocol`.
fn hello_refusal(e: RpcError, hello: &Hello) -> ConnectError {
    let Some(env) = e.data else {
        return protocol(MSG_HELLO_NO_ENVELOPE);
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
                .filter(|b| !b.is_empty())
                .unwrap_or(UNKNOWN_BUILD)
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
    /// The active progress callback's queue, and the request whose progress it takes.
    progress: Option<(String, mpsc::Sender<ProgressNotification>)>,
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

/// Queues a `request.progress` notification for the active callback if it is for the
/// callback's request; other notifications and unreadable params are ignored.
fn notify(routes: &Mutex<Routes>, n: Notification) {
    if n.method != method::REQUEST_PROGRESS {
        return;
    }
    let Ok(p) = serde_json::from_value::<ProgressNotification>(n.params) else {
        return;
    };
    if let Some((request_id, tx)) = &lock(routes).progress
        && *request_id == p.request_id
    {
        let _ = tx.try_send(p);
    }
}

// ---------- write tracking ----------

/// A writer that records whether any byte went out (PD-16) and, once one of this call's did,
/// marks the stream torn until the caller clears it after the whole frame: a call dropped
/// before its first byte leaves the stream framed.
struct Tracked<'a, W> {
    inner: &'a mut W,
    wrote: &'a mut bool,
    unusable: &'a mut Option<Unusable>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Tracked<'_, W> {
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
            *this.unusable = Some(Unusable::Torn);
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::proto::{AgentNameSource, ClientKind};
    use crate::rpc::{ProtocolReason, error_response, protocol_error};

    fn hello() -> Hello {
        Hello {
            build_id: "0.1.0+test".to_owned(),
            client_kind: ClientKind::Cli,
            agent_name: Some("tester".to_owned()),
            agent_name_source: AgentNameSource::Flag,
            cwd_basename: "repo".to_owned(),
        }
    }

    /// Every write fails with `kind`.
    struct Fails(io::ErrorKind);

    impl AsyncWrite for Fails {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::from(self.0)))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Takes up to `left` bytes, then never completes a write.
    struct Stalls {
        left: usize,
    }

    impl AsyncWrite for Stalls {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.left == 0 {
                return Poll::Pending;
            }
            let n = buf.len().min(self.left);
            self.left -= n;
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut v = u32::try_from(payload.len())
            .expect("u32")
            .to_be_bytes()
            .to_vec();
        v.extend_from_slice(payload);
        v
    }

    /// The server's answer to an oversize first frame: `null` id, `frame_too_large`.
    fn too_large_refusal() -> Vec<u8> {
        let env = protocol_error(ProtocolReason::FrameTooLarge);
        let r = error_response(None, ProtocolReason::FrameTooLarge.code(), env);
        framed(&serde_json::to_vec(&r).expect("encode"))
    }

    #[tokio::test]
    async fn hello_write_to_a_gone_server_still_reads_its_answer() {
        let frame = hello_frame(&hello()).expect("frame");
        for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::ConnectionReset] {
            let mut rd = Cursor::new(too_large_refusal());
            let got = handshake(&mut rd, &mut Fails(kind), &frame, &hello()).await;
            match got {
                Err(ConnectError::Hello(env)) => {
                    let err = env.error.expect("error");
                    assert_eq!(err.code, ErrorCode::ProtocolError);
                    let reason = err.details.as_ref().and_then(|d| d.get("reason")).cloned();
                    assert_eq!(reason, Some(Value::from("frame_too_large")));
                }
                other => panic!("{kind:?}: expected Hello(env), got {other:?}"),
            }
            // Gone and no answer: the server closed unanswered.
            let mut rd = Cursor::new(Vec::new());
            let got = handshake(&mut rd, &mut Fails(kind), &frame, &hello()).await;
            assert!(matches!(got, Err(ConnectError::ServerIdentity)), "{got:?}");
        }
        // Any other write error is the error.
        let mut rd = Cursor::new(too_large_refusal());
        let got = handshake(&mut rd, &mut Fails(io::ErrorKind::Other), &frame, &hello()).await;
        assert!(matches!(got, Err(ConnectError::Io(_))), "{got:?}");
    }

    #[test]
    fn hello_fields_cut_to_64_chars() {
        let mut h = hello();
        h.agent_name = Some("ä".repeat(100));
        h.cwd_basename = "😀".repeat(65);
        let frame = hello_frame(&h).expect("frame");
        let req: Request = serde_json::from_slice(&frame).expect("request");
        let sent: Hello = serde_json::from_value(req.params).expect("hello");
        assert_eq!(sent.agent_name, Some("ä".repeat(64)));
        assert_eq!(sent.cwd_basename, "😀".repeat(64));
        assert_eq!(sent.build_id, h.build_id);

        // Short fields and no name are left alone.
        let mut h = hello();
        h.agent_name = None;
        let req: Request = serde_json::from_slice(&hello_frame(&h).expect("frame")).expect("req");
        let sent: Hello = serde_json::from_value(req.params).expect("hello");
        assert_eq!(sent, h);
    }

    #[test]
    fn hello_frame_capped_at_64k() {
        let mut h = hello();
        let base = hello_frame(&h).expect("frame").len() - h.build_id.len();
        h.build_id = "b".repeat(HELLO_MAX_BYTES - base);
        assert_eq!(hello_frame(&h).expect("at the cap").len(), HELLO_MAX_BYTES);
        h.build_id.push('b');
        let err = hello_frame(&h).expect_err("over the cap");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn torn_only_after_a_byte_of_the_call() {
        let bytes = [7u8; 16];
        // Dropped before its first byte: still framed.
        let (mut wrote, mut unusable) = (false, None);
        let mut w = Stalls { left: 0 };
        let mut tracked = Tracked {
            inner: &mut w,
            wrote: &mut wrote,
            unusable: &mut unusable,
        };
        let cut = tokio::time::timeout(
            Duration::from_millis(20),
            write_frame_async(&mut tracked, &bytes),
        )
        .await;
        assert!(cut.is_err(), "the stalled write completed");
        assert!(!wrote);
        assert!(unusable.is_none(), "{unusable:?}");

        // Dropped after some bytes: torn.
        let (mut wrote, mut unusable) = (false, None);
        let mut w = Stalls { left: 6 };
        let mut tracked = Tracked {
            inner: &mut w,
            wrote: &mut wrote,
            unusable: &mut unusable,
        };
        let cut = tokio::time::timeout(
            Duration::from_millis(20),
            write_frame_async(&mut tracked, &bytes),
        )
        .await;
        assert!(cut.is_err(), "the stalled write completed");
        assert!(wrote);
        assert!(matches!(unusable, Some(Unusable::Torn)), "{unusable:?}");
    }

    fn null_id_answer() -> Response {
        Response {
            jsonrpc: TwoPointZero,
            id: None,
            body: ResponseBody::Result(Value::Null),
        }
    }

    #[tokio::test]
    async fn answer_after_write_error_waits_only_for_a_gone_peer() {
        let gone = io::Error::from(io::ErrorKind::BrokenPipe);
        let other = io::Error::other("other");

        // Gone: an answer the reader routes a moment later still counts.
        let (tx, mut rx) = oneshot::channel();
        let late = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx.send(null_id_answer());
        });
        assert!(answer_after_write_error(&gone, &mut rx).await.is_some());
        let _ = late.await;

        // Gone, and the reader closed without one: no wait.
        let (tx, mut rx) = oneshot::channel::<Response>();
        drop(tx);
        let t0 = Instant::now();
        assert!(answer_after_write_error(&gone, &mut rx).await.is_none());
        assert!(t0.elapsed() < GONE_ANSWER_WAIT);

        // Another error: only an answer already routed.
        let (tx, mut rx) = oneshot::channel();
        assert!(answer_after_write_error(&other, &mut rx).await.is_none());
        let _ = tx.send(null_id_answer());
        assert!(answer_after_write_error(&other, &mut rx).await.is_some());
    }

    /// §4.7: a busy pipe whose deadline leaves less than the 5 s busy wait is the deadline
    /// (exit 5), not busy (exit 11). `open` alone: `connect_at`'s own timeout races it.
    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn busy_pipe_inside_a_short_deadline_is_deadline_exceeded() {
        use tokio::net::windows::named_pipe::ServerOptions;

        use crate::paths::{DataDirResolution, check_data_dir, write_endpoint_file};
        use crate::transport::windows::{SameUser, new_pipe_name, open_client};

        let tmp = tempfile::tempdir().expect("tempdir");
        let DataDirResolution::Local(data) = check_data_dir(tmp.path()).expect("check") else {
            panic!("temp dir is not a local data dir");
        };
        let location = endpoint_location(&data, "host").expect("location");
        let EndpointLocation::WindowsPipePrefix(prefix) = &location else {
            panic!("not a pipe location");
        };
        let name = new_pipe_name(prefix).expect("name");
        let _only = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .expect("server");
        let _first = open_client(&name).expect("first client takes the only instance");
        write_endpoint_file(&data, &name).expect("endpoint file");
        let check = SameUser::current().expect("own SID");
        let got = open(
            &location,
            &data,
            &check,
            Instant::now() + Duration::from_millis(300),
        )
        .await;
        assert!(
            matches!(got, Err(ConnectError::DeadlineExceeded)),
            "{:?}",
            got.err()
        );
    }
}
