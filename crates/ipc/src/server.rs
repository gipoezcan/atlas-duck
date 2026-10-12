//! The IPC server (§3.3, C.2): binds the endpoint, writes `<data>/endpoint`, accepts
//! connections and serves a swappable [`HandlerCell`] over JSON-RPC frames.
//!
//! Per connection: a `conn_` id (PD-37), the peer's identity and origin chain (§3.1, computed
//! in `spawn_blocking` while the first frame is read), the `hello` frame within the deadline
//! (§3.3; on Windows the client SID is checked after it was read and before anything is
//! answered), the connection limits (PD-27), then one task per request, all answers written by
//! one writer task. On close, `request.await` tasks are dropped, every other task runs to
//! completion (C.2 drive-to-completion), then `disconnected` is called once (Δ2).
//!
//! A swap of the cell is seen from the next request on; before that request the connection's
//! `hello` is replayed on the new handler, so the session survives a gate → core swap.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::envelope::{Envelope, ErrorCode};
use crate::paths::{
    EndpointLocation, LocalDataDir, endpoint_location, remove_endpoint_file, sweep_endpoint_temps,
    write_endpoint_file,
};
use crate::peer::{OsPeerSource, peer_info};
use crate::proto::{
    AwaitParams, BUSY_RETRY_CONNECTION_S, ConnectionMeta, Hello, PeerInfo, ProgressNotification,
    ProgressSink, RequestHandler, SubmitParams, busy_envelope,
};
use crate::rpc::frame::{FrameError, read_frame_async, write_frame_async};
use crate::rpc::{
    EmptyParams, IdParams, Notification, OpsDescribeParams, OpsListParams, ProtocolReason, Request,
    RequestsListParams, Response, TwoPointZero, codes, error_response, method, protocol_error,
};
use crate::sandbox::MAX_FRAME_BYTES;
use crate::transport::{Conn, diag};

/// Concurrent connections (§3.3, PD-27).
pub const MAX_CONNECTIONS: usize = 64;
/// Concurrent connections per limit key (`peer_origin_exe`, else `peer_exe`, else one shared
/// bucket) (§3.3, PD-27).
pub const MAX_PER_ORIGIN: usize = 16;
/// The `hello` frame must arrive within this time after accept (§3.3).
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// Requests one connection may have in flight; the next frame is read only when one of them
/// finishes (backpressure, bounded memory).
pub const MAX_IN_FLIGHT_PER_CONNECTION: usize = 64;
/// On shutdown, in-flight answers get this long to be written (PD-38).
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Encoded frames queued for one connection's writer.
const WRITER_QUEUE: usize = 64;
/// Beyond the grace, how long `serve` waits for connection tasks before aborting them.
const SHUTDOWN_SLACK: Duration = Duration::from_millis(500);
/// After a close, how long the writer may take to flush what is queued.
const CLOSE_DRAIN: Duration = Duration::from_secs(2);
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(10);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);
/// Windows: fresh pipe names tried after the listener failed (§3.1).
#[cfg(windows)]
const REBIND_ATTEMPTS: usize = 5;

const MSG_WRONG_LOCATION: &str = "endpoint location is not for this OS";
#[cfg(unix)]
const MSG_NOT_UTF8: &str = "socket path is not UTF-8";

// ---------- handler cell, shutdown, limits ----------

/// The served handler, swappable without rebinding (C.2): the app replaces the gate handler by
/// the core handler. An open connection sees the new handler from its next request on.
pub struct HandlerCell {
    slot: RwLock<Slot>,
}

struct Slot {
    handler: Arc<dyn RequestHandler>,
    /// Bumped by every `swap`; read together with `handler` under one guard.
    generation: u64,
}

impl HandlerCell {
    pub fn new(h: Arc<dyn RequestHandler>) -> Self {
        HandlerCell {
            slot: RwLock::new(Slot {
                handler: h,
                generation: 0,
            }),
        }
    }

    pub fn swap(&self, h: Arc<dyn RequestHandler>) {
        let mut slot = self.slot.write().unwrap_or_else(PoisonError::into_inner);
        slot.handler = h;
        slot.generation = slot.generation.wrapping_add(1);
    }

    pub fn current(&self) -> Arc<dyn RequestHandler> {
        self.current_with_generation().0
    }

    fn current_with_generation(&self) -> (Arc<dyn RequestHandler>, u64) {
        let slot = self.slot.read().unwrap_or_else(PoisonError::into_inner);
        (slot.handler.clone(), slot.generation)
    }
}

/// Cancelled by `Core::shutdown` and the app's quit path (PD-38): the server stops accepting,
/// writes in-flight answers for up to [`SHUTDOWN_GRACE`], closes and removes `<data>/endpoint`.
#[derive(Debug, Clone, Default)]
pub struct ShutdownSignal(pub CancellationToken);

impl ShutdownSignal {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.cancel();
    }
}

/// Connection limits and the hello deadline (§3.3, PD-27). Tests scale them down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerLimits {
    pub max_connections: usize,
    pub per_origin: usize,
    pub hello_timeout: Duration,
}

impl Default for ServerLimits {
    fn default() -> Self {
        ServerLimits {
            max_connections: MAX_CONNECTIONS,
            per_origin: MAX_PER_ORIGIN,
            hello_timeout: HELLO_TIMEOUT,
        }
    }
}

// ---------- the server ----------

/// A bound endpoint; `serve` runs it.
pub struct IpcServer {
    endpoint: Endpoint,
    name: String,
    data: LocalDataDir,
    limits: ServerLimits,
    /// Windows: the server's user SID, which every client must run as (§3.1).
    #[cfg(windows)]
    sid: String,
}

impl IpcServer {
    /// Binds this user's endpoint (`endpoint_location`; Unix: the socket, after the socket dir
    /// check; Windows: the first instance of a fresh pipe name), removes leftover
    /// `.endpoint.*.tmp` files, then writes `<data>/endpoint` (PD-26). The caller holds
    /// `instance.lock`. Must be called inside a tokio runtime with IO enabled.
    pub fn bind(data: &LocalDataDir, host: &str) -> io::Result<IpcServer> {
        match endpoint_location(data, host) {
            Ok(location) => Self::bind_at(data, location),
            Err(e) => {
                tracing::error!(event = diag::EVENT_BIND_FAILED, "ipc bind failed");
                Err(e)
            }
        }
    }

    /// `bind` at an explicit location (tests: a socket in a temp dir). Production code calls
    /// `bind`, which computes the location.
    #[doc(hidden)]
    pub fn bind_at(data: &LocalDataDir, location: EndpointLocation) -> io::Result<IpcServer> {
        let bound = Self::bind_inner(data, location);
        if bound.is_err() {
            tracing::error!(event = diag::EVENT_BIND_FAILED, "ipc bind failed");
        }
        bound
    }

    fn bind_inner(data: &LocalDataDir, location: EndpointLocation) -> io::Result<IpcServer> {
        let (endpoint, name) = Endpoint::open(location)?;
        #[cfg(windows)]
        let sid = crate::paths::current_user_sid_string()?;
        if sweep_endpoint_temps(data).is_err() {
            // Leftover temp files are harmless; the endpoint file is what matters.
            tracing::warn!(
                event = diag::EVENT_BIND_FAILED,
                "ipc endpoint temp sweep failed"
            );
        }
        write_endpoint_file(data, &name)?;
        Ok(IpcServer {
            endpoint,
            name,
            data: data.clone(),
            limits: ServerLimits::default(),
            #[cfg(windows)]
            sid,
        })
    }

    /// Replaces the limits (tests scale them down).
    pub fn with_limits(mut self, limits: ServerLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The endpoint name written to `<data>/endpoint` (socket path or pipe name).
    pub fn endpoint_name(&self) -> &str {
        &self.name
    }

    /// Accepts and serves connections until `shutdown` is cancelled, then stops accepting,
    /// gives in-flight answers up to [`SHUTDOWN_GRACE`], closes every connection and removes
    /// `<data>/endpoint`.
    ///
    /// Accept errors never end the loop: Unix retries with a capped backoff; on Windows the
    /// failed listener is never used again and a fresh pipe name is bound (and written to
    /// `<data>/endpoint`), at most 5 times; after that the endpoint file is removed and only
    /// the open connections are served until shutdown.
    pub async fn serve(self, handler: Arc<HandlerCell>, shutdown: ShutdownSignal) {
        let IpcServer {
            mut endpoint,
            name: _,
            data,
            limits,
            #[cfg(windows)]
            sid,
        } = self;
        let shared = Arc::new(Shared {
            cell: handler,
            limits,
            slots: Arc::new(Mutex::new(Slots::default())),
            stop: shutdown.0.clone(),
            #[cfg(windows)]
            sid,
        });
        let mut conns = JoinSet::new();
        let mut backoff = ACCEPT_BACKOFF_MIN;
        loop {
            tokio::select! {
                biased;
                () = shutdown.0.cancelled() => break,
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
                accepted = endpoint.accept() => match accepted {
                    Ok(Some(acc)) => {
                        backoff = ACCEPT_BACKOFF_MIN;
                        conns.spawn(connection(shared.clone(), acc));
                    }
                    Ok(None) => {}
                    Err(_) => {
                        tracing::warn!(event = diag::EVENT_ACCEPT_FAILED, "ipc accept failed");
                        if !endpoint.recover(&data, &shutdown.0, &mut backoff).await {
                            break;
                        }
                    }
                },
            }
        }
        drop(endpoint);
        let deadline = Instant::now() + SHUTDOWN_GRACE + SHUTDOWN_SLACK;
        let drained = tokio::time::timeout_at(deadline, async {
            while conns.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            conns.abort_all();
            while conns.join_next().await.is_some() {}
        }
        if remove_endpoint_file(&data).is_err() {
            tracing::warn!(
                event = diag::EVENT_BIND_FAILED,
                "ipc endpoint file removal failed"
            );
        }
    }
}

/// Sleeps `backoff` (doubling it up to the cap) unless `stop` fires first; false on stop.
async fn back_off(stop: &CancellationToken, backoff: &mut Duration) -> bool {
    let wait = *backoff;
    *backoff = (*backoff * 2).min(ACCEPT_BACKOFF_MAX);
    tokio::select! {
        biased;
        () = stop.cancelled() => false,
        () = tokio::time::sleep(wait) => true,
    }
}

/// A freshly accepted connection, peer pid as the transport reported it.
struct Accepted {
    conn: Conn,
    pid: Option<u32>,
    /// Windows: a duplicate of the pipe handle for the impersonation check.
    #[cfg(windows)]
    pipe: std::os::windows::io::OwnedHandle,
}

enum Endpoint {
    #[cfg(unix)]
    Unix(crate::transport::unix::Listener),
    #[cfg(windows)]
    Pipe {
        /// `None` once an accept failed and no fresh name could be bound.
        listener: Option<crate::transport::windows::PipeListener>,
        prefix: String,
    },
}

impl Endpoint {
    #[cfg(unix)]
    fn open(location: EndpointLocation) -> io::Result<(Endpoint, String)> {
        let EndpointLocation::UnixSocket(path) = location else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                MSG_WRONG_LOCATION,
            ));
        };
        let name = path
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, MSG_NOT_UTF8))?
            .to_owned();
        let listener = crate::transport::unix::Listener::bind(&path)?;
        Ok((Endpoint::Unix(listener), name))
    }

    #[cfg(windows)]
    fn open(location: EndpointLocation) -> io::Result<(Endpoint, String)> {
        let EndpointLocation::WindowsPipePrefix(prefix) = location else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                MSG_WRONG_LOCATION,
            ));
        };
        let listener = crate::transport::windows::PipeListener::bind(&prefix)?;
        let name = listener.name().to_owned();
        Ok((
            Endpoint::Pipe {
                listener: Some(listener),
                prefix,
            },
            name,
        ))
    }

    /// The next connection. `Ok(None)`: one was accepted and dropped at once. Cancel-safe.
    #[cfg(unix)]
    async fn accept(&mut self) -> io::Result<Option<Accepted>> {
        let Endpoint::Unix(listener) = self;
        let (conn, cred) = listener.accept().await?;
        Ok(Some(Accepted {
            conn,
            pid: cred.pid,
        }))
    }

    /// The next connection. `Ok(None)`: one was accepted and dropped at once. Pending forever
    /// once the listener is gone. Cancel-safe.
    #[cfg(windows)]
    async fn accept(&mut self) -> io::Result<Option<Accepted>> {
        use std::os::windows::io::AsHandle;

        let Endpoint::Pipe {
            listener: Some(listener),
            ..
        } = self
        else {
            return std::future::pending().await;
        };
        let (pipe, pid) = listener.accept().await?;
        let Ok(dup) = pipe.as_handle().try_clone_to_owned() else {
            tracing::warn!(
                event = diag::EVENT_REJECT,
                reason = diag::REASON_IMPERSONATION,
                peer_pid = pid,
                "ipc connection rejected"
            );
            return Ok(None);
        };
        Ok(Some(Accepted {
            conn: Conn::new(pipe),
            pid,
            pipe: dup,
        }))
    }

    /// After an accept error. False if `stop` fired meanwhile.
    #[cfg(unix)]
    async fn recover(
        &mut self,
        _data: &LocalDataDir,
        stop: &CancellationToken,
        backoff: &mut Duration,
    ) -> bool {
        back_off(stop, backoff).await
    }

    /// After an accept error: the listener is done (its accept would fail forever), so a fresh
    /// pipe name is bound and written to `<data>/endpoint`, at most `REBIND_ATTEMPTS` times.
    /// After that the endpoint file is removed (clients see "not running") and accept stays
    /// pending. False if `stop` fired meanwhile.
    #[cfg(windows)]
    async fn recover(
        &mut self,
        data: &LocalDataDir,
        stop: &CancellationToken,
        backoff: &mut Duration,
    ) -> bool {
        let Endpoint::Pipe { listener, prefix } = self;
        *listener = None;
        for _ in 0..REBIND_ATTEMPTS {
            if !back_off(stop, backoff).await {
                return false;
            }
            match crate::transport::windows::PipeListener::bind(prefix) {
                Ok(fresh) if write_endpoint_file(data, fresh.name()).is_ok() => {
                    *listener = Some(fresh);
                    return true;
                }
                _ => tracing::error!(event = diag::EVENT_BIND_FAILED, "ipc rebind failed"),
            }
        }
        let _ = remove_endpoint_file(data);
        tracing::error!(
            event = diag::EVENT_BIND_FAILED,
            "ipc server stopped accepting"
        );
        true
    }
}

// ---------- per connection ----------

struct Shared {
    cell: Arc<HandlerCell>,
    limits: ServerLimits,
    slots: Arc<Mutex<Slots>>,
    stop: CancellationToken,
    #[cfg(windows)]
    sid: String,
}

/// Open connections, total and per limit key (`None` = the shared "?" bucket).
#[derive(Default)]
struct Slots {
    total: usize,
    per_key: HashMap<Option<PathBuf>, usize>,
}

/// One counted connection; released on drop.
struct SlotGuard {
    slots: Arc<Mutex<Slots>>,
    key: Option<PathBuf>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut s = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        s.total = s.total.saturating_sub(1);
        if let Some(n) = s.per_key.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                s.per_key.remove(&self.key);
            }
        }
    }
}

/// Check and count under one lock, so two connections cannot both take the last slot.
fn try_acquire(shared: &Shared, peer: &PeerInfo) -> Option<SlotGuard> {
    let key = peer
        .peer_origin_exe
        .clone()
        .or_else(|| peer.peer_exe.clone());
    let mut s = shared.slots.lock().unwrap_or_else(PoisonError::into_inner);
    let n = s.per_key.get(&key).copied().unwrap_or(0);
    if s.total >= shared.limits.max_connections || n >= shared.limits.per_origin {
        return None;
    }
    s.total += 1;
    *s.per_key.entry(key.clone()).or_insert(0) += 1;
    Some(SlotGuard {
        slots: shared.slots.clone(),
        key,
    })
}

/// `"conn_"` + 32 lowercase hex from 128 CSPRNG bits (PD-37).
fn new_connection_id() -> Option<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).ok()?;
    Some(format!("conn_{:032x}", u128::from_be_bytes(b)))
}

/// The writer task of one connection and the sending side of its queue.
struct Writer {
    tx: mpsc::Sender<Vec<u8>>,
    task: JoinHandle<()>,
}

impl Writer {
    fn start(wr: WriteHalf<Conn>) -> Writer {
        let (tx, rx) = mpsc::channel(WRITER_QUEUE);
        Writer {
            tx,
            task: tokio::spawn(write_loop(wr, rx)),
        }
    }

    async fn send(&self, resp: Response) {
        if let Some(frame) = encode_response(resp) {
            // A gone writer means a gone client; nothing is left to tell it.
            let _ = self.tx.send(frame).await;
        }
    }

    /// Lets the writer flush what is queued (until `deadline`), then closes the write side.
    /// Every other sender must be gone already.
    async fn close(self, deadline: Instant) {
        let Writer { tx, mut task } = self;
        drop(tx);
        if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
            task.abort();
        }
    }
}

async fn write_loop(mut wr: WriteHalf<Conn>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(frame) = rx.recv().await {
        if write_frame_async(&mut wr, &frame).await.is_err() {
            return;
        }
    }
    let _ = wr.shutdown().await;
}

/// The serialized response; an answer above the frame cap is replaced by `frame_too_large`
/// for the same id.
fn encode_response(resp: Response) -> Option<Vec<u8>> {
    let id = resp.id;
    match serde_json::to_vec(&resp) {
        Ok(bytes) if bytes.len() <= MAX_FRAME_BYTES => Some(bytes),
        Ok(_) => {
            let reason = ProtocolReason::FrameTooLarge;
            serde_json::to_vec(&error_response(id, reason.code(), protocol_error(reason))).ok()
        }
        Err(_) => None,
    }
}

fn log_protocol_error(meta: &ConnectionMeta, reason: ProtocolReason) {
    tracing::warn!(
        event = diag::EVENT_PROTOCOL_ERROR,
        connection_id = %meta.connection_id,
        peer_pid = meta.peer.peer_pid,
        reason = reason.as_str(),
        "ipc protocol error"
    );
}

/// Logs and answers a protocol error.
async fn refuse(writer: &Writer, meta: &ConnectionMeta, reason: ProtocolReason, id: Option<u64>) {
    log_protocol_error(meta, reason);
    writer
        .send(error_response(id, reason.code(), protocol_error(reason)))
        .await;
}

/// A frame that is not a usable request: its reason and the id when one could be read.
struct Refusal {
    reason: ProtocolReason,
    id: Option<u64>,
}

fn decode(bytes: &[u8]) -> Result<Request, Refusal> {
    let v: Value = serde_json::from_slice(bytes).map_err(|_| Refusal {
        reason: ProtocolReason::Parse,
        id: None,
    })?;
    let id = v.get("id").and_then(Value::as_u64);
    serde_json::from_value(v).map_err(|_| Refusal {
        reason: ProtocolReason::InvalidRequest,
        id,
    })
}

/// Method params: an object, or omitted / `null` (= `{}`). Anything else, or an object the
/// param struct refuses, is `invalid_params`.
fn params_of<T: DeserializeOwned>(params: Value) -> Result<T, ProtocolReason> {
    let params = match params {
        Value::Null => Value::Object(Map::new()),
        obj @ Value::Object(_) => obj,
        _ => return Err(ProtocolReason::InvalidParams),
    };
    serde_json::from_value(params).map_err(|_| ProtocolReason::InvalidParams)
}

/// The `hello` of a connection and every handler that accepted it.
struct Session {
    hello: Hello,
    /// The cell generation whose handler last accepted `hello`.
    generation: u64,
    handlers: Vec<Arc<dyn RequestHandler>>,
}

fn same_handler(a: &Arc<dyn RequestHandler>, b: &Arc<dyn RequestHandler>) -> bool {
    std::ptr::addr_eq(Arc::as_ptr(a), Arc::as_ptr(b))
}

impl Session {
    fn accepted_by(&mut self, h: &Arc<dyn RequestHandler>, generation: u64) {
        self.generation = generation;
        if !self.handlers.iter().any(|x| same_handler(x, h)) {
            self.handlers.push(h.clone());
        }
    }

    /// The current handler, then every other handler that accepted the hello.
    fn disconnect_targets(&self, current: Arc<dyn RequestHandler>) -> Vec<Arc<dyn RequestHandler>> {
        let mut out = vec![current];
        for h in &self.handlers {
            if !out.iter().any(|x| same_handler(x, h)) {
                out.push(h.clone());
            }
        }
        out
    }
}

/// Serves one connection from accept to close.
async fn connection(shared: Arc<Shared>, acc: Accepted) {
    let deadline = Instant::now() + shared.limits.hello_timeout;
    let Accepted {
        conn,
        pid,
        #[cfg(windows)]
        pipe,
    } = acc;
    let Some(connection_id) = new_connection_id() else {
        tracing::error!(
            event = diag::EVENT_REJECT,
            peer_pid = pid,
            "ipc connection id unavailable"
        );
        return;
    };
    tracing::info!(
        event = diag::EVENT_ACCEPT,
        connection_id = %connection_id,
        peer_pid = pid,
        "ipc connection accepted"
    );
    let (mut rd, wr) = conn.split();
    let writer = Writer::start(wr);

    // The peer walk (blocking process lookups, a new source per walk: PD-36) runs while the
    // first frame is read. Losing the race to `stop` ends the connection, so the half-read
    // frame is never resumed.
    let walk = tokio::task::spawn_blocking(move || peer_info(pid, &OsPeerSource::default()));
    let read = tokio::time::timeout_at(deadline, read_frame_async(&mut rd, MAX_FRAME_BYTES));
    let (peer, first) = tokio::select! {
        biased;
        () = shared.stop.cancelled() => return,
        both = async { tokio::join!(walk, read) } => both,
    };
    let peer = peer.unwrap_or_else(|_| PeerInfo {
        peer_pid: pid,
        ..PeerInfo::default()
    });
    let meta = Arc::new(ConnectionMeta {
        connection_id,
        peer,
    });

    let first = match first {
        Ok(Ok(Some(bytes))) => Ok(bytes),
        Ok(Err(FrameError::TooLarge { .. })) => Err(ProtocolReason::FrameTooLarge),
        Err(_elapsed) => Err(ProtocolReason::HelloTimeout),
        // Gone before a whole frame: nobody to answer.
        Ok(Ok(None) | Err(_)) => return writer.close(Instant::now()).await,
    };
    // §3.1: data was read, so the client can be impersonated; nothing is answered before its
    // SID matched. A timeout may have read nothing (impersonation would fail); its fixed
    // `hello_timeout` answer is sent without the check.
    #[cfg(windows)]
    if !matches!(first, Err(ProtocolReason::HelloTimeout))
        && !client_sid_ok(pipe, &shared.sid, &meta).await
    {
        return writer.close(Instant::now()).await;
    }

    let Some((mut session, slot)) = handshake(&shared, &meta, &writer, first).await else {
        return writer.close(Instant::now() + CLOSE_DRAIN).await;
    };
    let mut awaits = JoinSet::new();
    let mut others = JoinSet::new();
    let end = request_loop(
        &shared,
        &meta,
        &mut rd,
        &writer,
        &mut session,
        &mut awaits,
        &mut others,
    )
    .await;

    match end {
        End::Stop => {
            let deadline = Instant::now() + SHUTDOWN_GRACE;
            let drained = tokio::time::timeout_at(deadline, async {
                while awaits.join_next().await.is_some() {}
                while others.join_next().await.is_some() {}
            })
            .await;
            if drained.is_err() {
                awaits.abort_all();
                others.abort_all();
                while awaits.join_next().await.is_some() {}
                while others.join_next().await.is_some() {}
            }
            writer.close(deadline).await;
        }
        End::Closed => {
            // Awaits deliver nothing to a gone client; every other request runs to
            // completion (C.2).
            awaits.abort_all();
            while awaits.join_next().await.is_some() {}
            while others.join_next().await.is_some() {}
            writer.close(Instant::now() + CLOSE_DRAIN).await;
        }
    }
    drop(rd);
    drop(slot);
    for h in session.disconnect_targets(shared.cell.current()) {
        h.disconnected(&meta).await;
    }
}

/// Windows: the client's token SID equals the server's (§3.1). Consumes the duplicate pipe
/// handle, so the pipe closes with the connection.
#[cfg(windows)]
async fn client_sid_ok(
    pipe: std::os::windows::io::OwnedHandle,
    sid: &str,
    meta: &ConnectionMeta,
) -> bool {
    use std::os::windows::io::AsHandle;

    let expected = sid.to_owned();
    let checked = tokio::task::spawn_blocking(move || {
        crate::transport::windows::verify_client_sid_blocking(pipe.as_handle(), &expected)
    })
    .await;
    let reason = match checked {
        Ok(Ok(true)) => return true,
        Ok(Ok(false)) => diag::REASON_PEER_SID,
        Ok(Err(_)) | Err(_) => diag::REASON_IMPERSONATION,
    };
    tracing::warn!(
        event = diag::EVENT_REJECT,
        connection_id = %meta.connection_id,
        peer_pid = meta.peer.peer_pid,
        reason,
        "ipc connection rejected"
    );
    false
}

/// The first frame: must be `hello` (PD-28), then the connection limits (PD-27), then the
/// handler's `hello`. `None`: answered with an error, close.
async fn handshake(
    shared: &Shared,
    meta: &ConnectionMeta,
    writer: &Writer,
    first: Result<Vec<u8>, ProtocolReason>,
) -> Option<(Session, SlotGuard)> {
    let req = match first.map_err(|reason| Refusal { reason, id: None }) {
        Ok(bytes) => decode(&bytes),
        Err(r) => Err(r),
    };
    let req = match req {
        Ok(req) => req,
        Err(Refusal { reason, id }) => {
            refuse(writer, meta, reason, id).await;
            return None;
        }
    };
    let id = req.id;
    if req.method != method::HELLO {
        refuse(writer, meta, ProtocolReason::HelloRequired, Some(id)).await;
        return None;
    }
    let Some(slot) = try_acquire(shared, &meta.peer) else {
        tracing::warn!(
            event = diag::EVENT_REJECT,
            connection_id = %meta.connection_id,
            peer_pid = meta.peer.peer_pid,
            reason = diag::REASON_LIMIT,
            "ipc connection rejected"
        );
        writer
            .send(error_response(
                Some(id),
                codes::APP_REFUSAL,
                busy_envelope(BUSY_RETRY_CONNECTION_S),
            ))
            .await;
        return None;
    };
    let hello: Hello = match params_of(req.params) {
        Ok(h) => h,
        Err(reason) => {
            refuse(writer, meta, reason, Some(id)).await;
            return None;
        }
    };
    let (handler, generation) = shared.cell.current_with_generation();
    match handler.hello(meta, hello.clone()).await {
        Ok(reply) => {
            writer.send(Response::result(id, to_json(&reply))).await;
            Some((
                Session {
                    hello,
                    generation,
                    handlers: vec![handler],
                },
                slot,
            ))
        }
        Err(env) => {
            writer
                .send(error_response(Some(id), codes::APP_REFUSAL, env))
                .await;
            None
        }
    }
}

enum End {
    /// EOF, a read error, or a protocol error that closed the connection.
    Closed,
    /// The shutdown signal fired.
    Stop,
}

/// Reads requests after a successful `hello` and spawns one task per request.
async fn request_loop(
    shared: &Shared,
    meta: &Arc<ConnectionMeta>,
    rd: &mut ReadHalf<Conn>,
    writer: &Writer,
    session: &mut Session,
    awaits: &mut JoinSet<()>,
    others: &mut JoinSet<()>,
) -> End {
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT_PER_CONNECTION));
    loop {
        while awaits.try_join_next().is_some() {}
        while others.try_join_next().is_some() {}
        let permit = tokio::select! {
            biased;
            () = shared.stop.cancelled() => return End::Stop,
            p = permits.clone().acquire_owned() => match p {
                Ok(p) => p,
                Err(_) => return End::Closed,
            },
        };
        // Not cancel-safe: losing the race to `stop` ends the connection, so the half-read
        // frame is never resumed.
        let read = tokio::select! {
            biased;
            () = shared.stop.cancelled() => return End::Stop,
            r = read_frame_async(rd, MAX_FRAME_BYTES) => r,
        };
        let bytes = match read {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return End::Closed,
            Err(FrameError::TooLarge { .. }) => {
                refuse(writer, meta, ProtocolReason::FrameTooLarge, None).await;
                return End::Closed;
            }
            Err(_) => return End::Closed,
        };
        let req = match decode(&bytes) {
            Ok(req) => req,
            Err(Refusal { reason, id }) => {
                refuse(writer, meta, reason, id).await;
                return End::Closed;
            }
        };
        let id = req.id;
        if req.method == method::HELLO {
            refuse(writer, meta, ProtocolReason::HelloRepeated, Some(id)).await;
            continue;
        }
        let call = match Call::parse(&req.method, req.params) {
            Ok(call) => call,
            Err(reason) => {
                refuse(writer, meta, reason, Some(id)).await;
                continue;
            }
        };
        // The handler is taken here, at dispatch time; a swap since the last request replays
        // the connection's hello on the new handler first (serially, in this loop).
        let (handler, generation) = shared.cell.current_with_generation();
        if generation != session.generation {
            match handler.hello(meta, session.hello.clone()).await {
                Ok(_) => session.accepted_by(&handler, generation),
                Err(env) => {
                    writer
                        .send(error_response(Some(id), codes::APP_REFUSAL, env))
                        .await;
                    return End::Closed;
                }
            }
        }
        let task = run_call(handler, meta.clone(), id, call, writer.tx.clone(), permit);
        if matches!(task.kind, CallKind::Await) {
            awaits.spawn(task.fut);
        } else {
            others.spawn(task.fut);
        }
    }
}

/// A parsed request.
enum Call {
    OpsList(OpsListParams),
    OpsDescribe(OpsDescribeParams),
    InstancesList,
    Submit(SubmitParams),
    ScriptSubmit(SubmitParams),
    Await(AwaitParams),
    Status(IdParams),
    Cancel(IdParams),
    RequestsList(RequestsListParams),
    Doctor,
}

impl Call {
    fn parse(name: &str, params: Value) -> Result<Call, ProtocolReason> {
        Ok(match name {
            method::OPS_LIST => Call::OpsList(params_of(params)?),
            method::OPS_DESCRIBE => Call::OpsDescribe(params_of(params)?),
            method::INSTANCES_LIST => {
                params_of::<EmptyParams>(params)?;
                Call::InstancesList
            }
            method::REQUEST_SUBMIT => Call::Submit(params_of(params)?),
            method::SCRIPT_SUBMIT => Call::ScriptSubmit(params_of(params)?),
            method::REQUEST_AWAIT => Call::Await(params_of(params)?),
            method::REQUEST_STATUS => Call::Status(params_of(params)?),
            method::REQUEST_CANCEL => Call::Cancel(params_of(params)?),
            method::REQUESTS_LIST => Call::RequestsList(params_of(params)?),
            method::DOCTOR => {
                params_of::<EmptyParams>(params)?;
                Call::Doctor
            }
            _ => return Err(ProtocolReason::UnknownMethod),
        })
    }
}

enum CallKind {
    Await,
    Other,
}

struct Task<F> {
    kind: CallKind,
    fut: F,
}

/// One request's task: runs the call on `handler` and queues the answer.
fn run_call(
    handler: Arc<dyn RequestHandler>,
    meta: Arc<ConnectionMeta>,
    id: u64,
    call: Call,
    tx: mpsc::Sender<Vec<u8>>,
    permit: OwnedSemaphorePermit,
) -> Task<impl std::future::Future<Output = ()> + Send + 'static> {
    let kind = match call {
        Call::Await(_) => CallKind::Await,
        _ => CallKind::Other,
    };
    let fut = async move {
        let progress = ChannelProgress { tx: tx.clone() };
        let value = dispatch(handler.as_ref(), &meta, call, &progress).await;
        if let Some(frame) = encode_response(Response::result(id, value)) {
            let _ = tx.send(frame).await;
        }
        drop(permit);
    };
    Task { kind, fut }
}

async fn dispatch(
    h: &dyn RequestHandler,
    meta: &ConnectionMeta,
    call: Call,
    progress: &dyn ProgressSink,
) -> Value {
    match call {
        Call::OpsList(p) => to_json(&h.ops_list(p.instance.as_deref()).await),
        Call::OpsDescribe(p) => to_json(&h.ops_describe(&p.op_id, p.instance.as_deref()).await),
        Call::InstancesList => to_json(&h.instances_list().await),
        Call::Submit(p) => to_json(&h.submit(meta, p).await),
        Call::ScriptSubmit(p) => to_json(&h.submit_script(meta, p).await),
        Call::Await(p) => to_json(&h.await_request(meta, p, progress).await),
        Call::Status(p) => to_json(&h.status(&p.request_id).await),
        Call::Cancel(p) => to_json(&h.cancel(&p.request_id).await),
        Call::RequestsList(p) => to_json(
            &h.requests_list(p.agent.as_deref(), p.state, p.match_params)
                .await,
        ),
        Call::Doctor => to_json(&h.doctor().await),
    }
}

/// Our own wire types always serialize; the fallback is an `internal` envelope.
fn to_json<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or_else(|_| {
        serde_json::to_value(Envelope::failed(
            ErrorCode::Internal,
            false,
            "internal error",
        ))
        .unwrap_or(Value::Null)
    })
}

/// `request.progress` notifications through the connection's writer (§4.5). The sink is
/// synchronous, so a notification that finds the queue full is dropped; the answer itself
/// still arrives.
struct ChannelProgress {
    tx: mpsc::Sender<Vec<u8>>,
}

impl ProgressSink for ChannelProgress {
    fn progress(&self, n: ProgressNotification) {
        let note = Notification {
            jsonrpc: TwoPointZero,
            method: method::REQUEST_PROGRESS.to_owned(),
            params: to_json(&n),
        };
        if let Ok(frame) = serde_json::to_vec(&note) {
            let _ = self.tx.try_send(frame);
        }
    }
}
