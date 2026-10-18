//! `SharedClient` (C.2 Δ1, PD-115): one connection that serves concurrent calls, for the MCP
//! front end (one long-lived connection per MCP server, §3.3).
//!
//! A writer task owns the write half and writes whole frames from a queue; the reader task of
//! the `IpcClient` it came from keeps reading and routes each answer by id and each
//! `request.progress` to every call awaiting that `request_id`. Each queued frame carries a
//! state (`Queued → Writing | Abandoned`), decided by one compare-and-swap: the writer takes a
//! frame (`Writing`) before its first byte and skips an abandoned one; a call whose deadline
//! passed, or whose future was dropped, abandons its frame if the writer has not taken it.
//! So `Sent::written` is true exactly when the server may have the request (PD-16 per call),
//! and the stream is never torn: a taken frame is always written whole.
//!
//! Slots: a call holds one of [`SHARED_IN_FLIGHT`] permits from before its frame is queued
//! until the server's answer for its id arrives (a late answer to a call that already returned
//! or was dropped included: its route stays as a tombstone that discards the answer), until
//! its frame is abandoned, or until the client closes. So the permits count what the server
//! still holds.
//!
//! The client closes, for good, when: the reader sees EOF or a read error (`ConnectionLost`);
//! the server sends an oversize frame, a request, a frame that is not a JSON-RPC message, or
//! an error with a `null` id, which cannot be attributed with several calls in flight
//! (`Protocol`); a write fails (`ConnectionLost`). Nothing else closes it: an answer for an
//! unknown id or a `null`-id result is discarded, and an answer of the wrong shape fails only
//! its own call. A closed client fails every waiting call and every new one at once.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::AsyncWrite;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::{
    AbortOnDrop, ClientError, Closed, GONE_ANSWER_WAIT, PROGRESS_QUEUE, Routes, answer_of,
    encode_request, is_gone, lock,
};
use crate::proto::ProgressNotification;
use crate::rpc::frame::write_frame_async;
use crate::rpc::{Response, ResponseBody};

/// Requests one `SharedClient` lets the server hold at once; below the server's
/// [`MAX_IN_FLIGHT_PER_CONNECTION`](crate::server::MAX_IN_FLIGHT_PER_CONNECTION) (64), so the
/// server never stops reading this connection.
pub const SHARED_IN_FLIGHT: usize = 48;

/// Frame states (`Frame::state`).
const QUEUED: u8 = 0;
const WRITING: u8 = 1;
const ABANDONED: u8 = 2;

const MSG_NULL_ID: &str = "the server sent an error without a request id";

/// A call's outcome. `written`: the writer took this call's frame, so the server may have the
/// request (PD-16 per call); false means the server never sees it.
#[derive(Debug)]
pub struct Sent<R> {
    pub result: Result<R, ClientError>,
    pub written: bool,
}

impl<R> Sent<R> {
    fn unwritten(e: ClientError) -> Sent<R> {
        Sent {
            result: Err(e),
            written: false,
        }
    }
}

/// A connection that passed the owner check and the hello, shared by concurrent calls
/// (`IpcClient::into_shared`). Clones share the connection; it closes when the last clone is
/// dropped.
#[derive(Clone)]
pub struct SharedClient {
    inner: Arc<Inner>,
}

impl fmt::Debug for SharedClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedClient")
    }
}

struct Inner {
    core: Arc<Core>,
    frames: mpsc::UnboundedSender<Arc<Frame>>,
    next_id: AtomicU64,
    _reader: AbortOnDrop,
    _writer: AbortOnDrop,
}

/// What the reader, the writer and the calls share.
pub(super) struct Core {
    state: Mutex<State>,
    slots: Arc<Semaphore>,
    /// Cancelled on close: the writer takes no further frame.
    stop: CancellationToken,
    /// Unit tests: the writer takes a permit before it takes each frame.
    #[cfg(test)]
    gate: Option<Arc<Semaphore>>,
    /// Unit tests: runs when a call stopped waiting, before it looks at its frame and answer.
    #[cfg(test)]
    after_wait: Option<Arc<dyn Fn(&Core) + Send + Sync>>,
}

#[derive(Default)]
struct State {
    routes: HashMap<u64, Route>,
    /// Per `request_id`, the calls that take its progress (by call id).
    progress: HashMap<String, Vec<(u64, mpsc::Sender<ProgressNotification>)>>,
    closed: Option<Closed>,
}

/// A call waiting for its answer, or (once the call returned or was dropped) a tombstone that
/// discards it. Either way it holds the call's slot until the answer arrives.
struct Route {
    answer: oneshot::Sender<Response>,
    _slot: OwnedSemaphorePermit,
}

/// A queued request frame. The bytes are freed when the frame is abandoned.
struct Frame {
    state: AtomicU8,
    bytes: Mutex<Option<Vec<u8>>>,
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Frame {
    fn new(bytes: Vec<u8>) -> Frame {
        Frame {
            state: AtomicU8::new(QUEUED),
            bytes: Mutex::new(Some(bytes)),
        }
    }

    /// The writer's `Queued → Writing`: the bytes to write, or `None` if the frame was
    /// abandoned.
    fn take(&self) -> Option<Vec<u8>> {
        self.state
            .compare_exchange(QUEUED, WRITING, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        guard(&self.bytes).take()
    }

    /// The caller's `Queued → Abandoned`: true if the frame will never be written.
    fn abandon(&self) -> bool {
        let won = self
            .state
            .compare_exchange(QUEUED, ABANDONED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if won {
            drop(guard(&self.bytes).take());
        }
        won
    }
}

impl Core {
    fn new() -> Core {
        Core {
            state: Mutex::default(),
            slots: Arc::new(Semaphore::new(SHARED_IN_FLIGHT)),
            stop: CancellationToken::new(),
            #[cfg(test)]
            gate: None,
            #[cfg(test)]
            after_wait: None,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        guard(&self.state)
    }

    fn closed(&self) -> Option<Closed> {
        self.lock().closed.clone()
    }

    fn closed_error(&self) -> ClientError {
        self.closed()
            .as_ref()
            .map_or(ClientError::ConnectionLost, Closed::to_error)
    }

    /// The reader's answer: to its route (whose slot it then releases); an error with a
    /// `null` id closes the client; anything else is discarded.
    pub(super) fn deliver(&self, response: Response) {
        match response.id {
            Some(id) => {
                let route = self.lock().routes.remove(&id);
                if let Some(route) = route {
                    // A tombstone's caller is gone; nobody wants the answer.
                    let _ = route.answer.send(response);
                }
            }
            None if matches!(response.body, ResponseBody::Error(_)) => {
                self.close(Closed::Protocol(MSG_NULL_ID.to_owned()));
            }
            None => {}
        }
    }

    /// A `request.progress` notification, to every call that takes that request's progress.
    /// A full queue drops it (§4.5: progress is advisory).
    pub(super) fn notify(&self, p: ProgressNotification) {
        if let Some(subscribers) = self.lock().progress.get(&p.request_id) {
            for (_, tx) in subscribers {
                let _ = tx.try_send(p.clone());
            }
        }
    }

    /// Closes for good (the first reason wins): every route is dropped, which wakes its call
    /// and releases its slot; calls waiting for a slot fail; the writer takes no further frame.
    pub(super) fn close(&self, why: Closed) {
        let (routes, progress) = {
            let mut s = self.lock();
            if s.closed.is_none() {
                s.closed = Some(why);
            }
            (
                std::mem::take(&mut s.routes),
                std::mem::take(&mut s.progress),
            )
        };
        self.slots.close();
        self.stop.cancel();
        drop(routes);
        drop(progress);
    }

    fn unsubscribe(&self, request_id: &str, call: u64) {
        let mut s = self.lock();
        if let Some(subscribers) = s.progress.get_mut(request_id) {
            subscribers.retain(|(id, _)| *id != call);
            if subscribers.is_empty() {
                s.progress.remove(request_id);
            }
        }
    }
}

/// A call between queueing its frame and returning; also its drop guard.
struct Pending<'a> {
    core: &'a Core,
    id: u64,
    frame: Arc<Frame>,
    progress_of: Option<String>,
}

impl Pending<'_> {
    /// `Queued → Abandoned`; on success the route and its slot are released now. False: the
    /// writer took the frame (the route stays until the answer or the close).
    fn abandon(&self) -> bool {
        if !self.frame.abandon() {
            return false;
        }
        let route = self.core.lock().routes.remove(&self.id);
        drop(route);
        true
    }
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.abandon();
        if let Some(request_id) = &self.progress_of {
            self.core.unsubscribe(request_id, self.id);
        }
    }
}

impl SharedClient {
    /// Takes over a connected client's write half and its reader task (`IpcClient::into_shared`).
    pub(super) fn start<W>(
        wr: W,
        routes: &Mutex<Routes>,
        reader: AbortOnDrop,
        next_id: u64,
        closed: Option<Closed>,
    ) -> SharedClient
    where
        W: AsyncWrite + Send + Unpin + 'static,
    {
        Self::start_with(Core::new(), wr, routes, reader, next_id, closed)
    }

    fn start_with<W>(
        core: Core,
        wr: W,
        routes: &Mutex<Routes>,
        reader: AbortOnDrop,
        next_id: u64,
        closed: Option<Closed>,
    ) -> SharedClient
    where
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let core = Arc::new(core);
        let (frames, queue) = mpsc::unbounded_channel();
        let writer = AbortOnDrop(tokio::spawn(write_loop(wr, queue, core.clone())));
        // From here on the reader routes everything to `core`; a reader that already stopped
        // left its reason in `routes`.
        let closed = {
            let mut r = lock(routes);
            r.waiting = None;
            r.progress = None;
            r.shared = Some(core.clone());
            closed.or_else(|| r.closed.clone())
        };
        if let Some(why) = closed {
            core.close(why);
        }
        SharedClient {
            inner: Arc::new(Inner {
                core,
                frames,
                next_id: AtomicU64::new(next_id),
                _reader: reader,
                _writer: writer,
            }),
        }
    }

    /// True once the client closed (see the module doc); every call then fails at once.
    pub fn is_closed(&self) -> bool {
        self.inner.core.lock().closed.is_some()
    }

    /// Sends `method` with `params` and waits for its answer or `at` (`None`: no bound).
    /// `request.progress` notifications are not passed on.
    ///
    /// A call is bounded through `at`, never by dropping its future: at `at` it returns
    /// `DeadlineExceeded` itself, with `written` telling whether the server may have the
    /// request. A dropped future abandons a frame not yet taken and leaves a taken one to be
    /// written whole; its slot is released when the server answers.
    pub async fn call<R: DeserializeOwned>(
        &self,
        method: &str,
        params: impl Serialize,
        at: Option<Instant>,
    ) -> Sent<R> {
        self.call_inner(method, params, at, None).await
    }

    /// `call`, passing every `request.progress` notification for the request named by
    /// `params.request_id` to `on_progress`, in order, until the answer. Every call awaiting
    /// that id gets each notification (the server sends one copy per await). A full queue
    /// (64) drops the newest; the answer always arrives.
    pub async fn call_with_progress<R: DeserializeOwned>(
        &self,
        method: &str,
        params: impl Serialize,
        at: Option<Instant>,
        on_progress: &mut (dyn FnMut(ProgressNotification) + Send),
    ) -> Sent<R> {
        self.call_inner(method, params, at, Some(on_progress)).await
    }

    async fn call_inner<R: DeserializeOwned>(
        &self,
        method: &str,
        params: impl Serialize,
        at: Option<Instant>,
        mut on_progress: Option<&mut (dyn FnMut(ProgressNotification) + Send)>,
    ) -> Sent<R> {
        let core = &*self.inner.core;
        if let Some(closed) = core.closed() {
            return Sent::unwritten(closed.to_error());
        }
        if at.is_some_and(|at| Instant::now() >= at) {
            return Sent::unwritten(ClientError::DeadlineExceeded);
        }
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let (bytes, request_id) = match encode_request(id, method, params) {
            Ok(encoded) => encoded,
            Err(e) => return Sent::unwritten(ClientError::Io(e)),
        };

        // A slot before anything is queued; a close fails the wait.
        let acquire = core.slots.clone().acquire_owned();
        let slot = match at {
            Some(at) => match tokio::time::timeout_at(at.into(), acquire).await {
                Ok(slot) => slot,
                Err(_) => return Sent::unwritten(ClientError::DeadlineExceeded),
            },
            None => acquire.await,
        };
        let Ok(slot) = slot else {
            return Sent::unwritten(core.closed_error());
        };

        let frame = Arc::new(Frame::new(bytes));
        let (tx, mut answer) = oneshot::channel();
        let (progress_tx, mut progress) = mpsc::channel(PROGRESS_QUEUE);
        let progress_of = request_id.filter(|_| on_progress.is_some());
        {
            let mut s = core.lock();
            if let Some(closed) = &s.closed {
                return Sent::unwritten(closed.to_error());
            }
            s.routes.insert(
                id,
                Route {
                    answer: tx,
                    _slot: slot,
                },
            );
            if let Some(request_id) = &progress_of {
                s.progress
                    .entry(request_id.clone())
                    .or_default()
                    .push((id, progress_tx));
            }
        }
        let pending = Pending {
            core,
            id,
            frame: frame.clone(),
            progress_of,
        };
        // Fails only once the writer ended, which a close (that failed this route) precedes.
        let _ = self.inner.frames.send(frame);

        let deadline = async move {
            match at {
                Some(at) => tokio::time::sleep_until(at.into()).await,
                None => std::future::pending().await,
            }
        };
        tokio::pin!(deadline);
        // The reader queues a notification before the answer that follows it, so `biased`
        // hands every earlier notification over first; an answer beats the deadline.
        let end = loop {
            tokio::select! {
                biased;
                Some(n) = progress.recv(), if on_progress.is_some() => {
                    if let Some(f) = on_progress.as_mut() {
                        f(n);
                    }
                }
                got = &mut answer => break got.map_err(|_| core.closed_error()),
                () = &mut deadline => break Err(ClientError::DeadlineExceeded),
            }
        };
        #[cfg(test)]
        if let Some(hook) = &core.after_wait {
            hook(core);
        }
        // An answer routed after the deadline branch won is still this call's answer.
        let end = match end {
            Err(ClientError::DeadlineExceeded) => {
                answer.try_recv().map_err(|_| ClientError::DeadlineExceeded)
            }
            end => end,
        };
        if let Some(f) = on_progress.as_mut() {
            while let Ok(n) = progress.try_recv() {
                f(n);
            }
        }
        // Decided by the same compare-and-swap the writer does: an answered or taken frame
        // stays written; one still queued (a deadline, a close) is abandoned, never written.
        let written = !pending.abandon();
        let result = match end {
            Ok(response) => answer_of(method, response),
            Err(e) => Err(e),
        };
        Sent { result, written }
    }

    /// Unit tests: nothing in flight, every slot free, no progress subscription.
    #[cfg(test)]
    fn idle(&self) -> bool {
        let core = &self.inner.core;
        let s = core.lock();
        s.routes.is_empty()
            && s.progress.is_empty()
            && core.slots.available_permits() == SHARED_IN_FLIGHT
    }
}

/// Writes queued frames whole, one at a time, until the client closes. A failed write closes
/// the client; a gone peer first gets a moment for the reader to route answers it sent before
/// it closed.
async fn write_loop<W: AsyncWrite + Unpin>(
    mut wr: W,
    mut queue: mpsc::UnboundedReceiver<Arc<Frame>>,
    core: Arc<Core>,
) {
    loop {
        let frame = tokio::select! {
            biased;
            () = core.stop.cancelled() => return,
            frame = queue.recv() => match frame {
                Some(frame) => frame,
                None => return,
            },
        };
        #[cfg(test)]
        if let Some(gate) = &core.gate {
            tokio::select! {
                biased;
                () = core.stop.cancelled() => return,
                permit = gate.acquire() => {
                    if let Ok(permit) = permit {
                        permit.forget();
                    }
                }
            }
        }
        if core.stop.is_cancelled() {
            return;
        }
        let Some(bytes) = frame.take() else {
            continue;
        };
        if let Err(e) = write_frame_async(&mut wr, &bytes).await {
            if is_gone(&e) {
                tokio::select! {
                    () = core.stop.cancelled() => {}
                    () = tokio::time::sleep(GONE_ANSWER_WAIT) => {}
                }
            }
            core.close(Closed::Lost);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, DuplexStream, ReadHalf, WriteHalf};

    use super::super::read_loop;
    use super::*;
    use crate::rpc::frame::read_frame_async;
    use crate::sandbox::MAX_FRAME_BYTES;

    const WAIT: Duration = Duration::from_secs(10);
    /// Gate permits that let every later frame through.
    const OPEN: usize = 1 << 20;
    const STATUS: &str = "request.status";

    /// The server's end of the connection: reads the client's frames, writes answers.
    struct Peer {
        rd: ReadHalf<DuplexStream>,
        wr: WriteHalf<DuplexStream>,
    }

    impl Peer {
        async fn next(&mut self) -> Value {
            let frame = tokio::time::timeout(WAIT, read_frame_async(&mut self.rd, MAX_FRAME_BYTES))
                .await
                .expect("no frame within WAIT")
                .expect("a whole frame")
                .expect("not EOF");
            serde_json::from_slice(&frame).expect("a JSON frame")
        }

        /// True if no byte arrives within `d`.
        async fn quiet(&mut self, d: Duration) -> bool {
            let mut byte = [0u8; 1];
            tokio::time::timeout(d, self.rd.read(&mut byte))
                .await
                .is_err()
        }

        async fn send(&mut self, message: Value) {
            let bytes = serde_json::to_vec(&message).expect("encode");
            write_frame_async(&mut self.wr, &bytes)
                .await
                .expect("write frame");
        }

        async fn answer(&mut self, request: &Value, result: Value) {
            let id = request["id"].as_u64().expect("a request id");
            let bytes = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "result": result}))
                .expect("encode");
            write_frame_async(&mut self.wr, &bytes)
                .await
                .expect("write answer");
        }
    }

    /// A client over an in-memory pipe of `capacity` bytes whose writer is held (`held`)
    /// until the test adds gate permits.
    fn pair(held: bool, capacity: usize) -> (SharedClient, Arc<Semaphore>, Peer) {
        let (ours, theirs) = tokio::io::duplex(capacity);
        let (rd, wr) = tokio::io::split(ours);
        let routes = Arc::new(Mutex::new(Routes::default()));
        let reader = AbortOnDrop(tokio::spawn(read_loop(rd, routes.clone())));
        let gate = Arc::new(Semaphore::new(if held { 0 } else { OPEN }));
        let mut core = Core::new();
        core.gate = Some(gate.clone());
        let client = SharedClient::start_with(core, wr, &routes, reader, 2, None);
        let (rd, wr) = tokio::io::split(theirs);
        (client, gate, Peer { rd, wr })
    }

    fn params(request_id: &str) -> Value {
        json!({"request_id": request_id})
    }

    fn after(ms: u64) -> Option<Instant> {
        Some(Instant::now() + Duration::from_millis(ms))
    }

    fn soon() -> Option<Instant> {
        Some(Instant::now() + WAIT)
    }

    /// Waits until the client is idle; panics after [`WAIT`].
    async fn idle(client: &SharedClient) {
        let deadline = Instant::now() + WAIT;
        while !client.idle() {
            assert!(
                Instant::now() < deadline,
                "a route or slot was never released"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn spawn_call(
        client: &SharedClient,
        p: Value,
        at: Option<Instant>,
    ) -> tokio::task::JoinHandle<Sent<Value>> {
        let c = client.clone();
        tokio::spawn(async move { c.call::<Value>(STATUS, p, at).await })
    }

    async fn join(task: tokio::task::JoinHandle<Sent<Value>>) -> Sent<Value> {
        tokio::time::timeout(WAIT, task)
            .await
            .expect("the call did not return within WAIT")
            .expect("the call panicked")
    }

    fn spawn_progress_call(
        client: &SharedClient,
        p: Value,
        at: Option<Instant>,
    ) -> tokio::task::JoinHandle<Sent<Value>> {
        let c = client.clone();
        tokio::spawn(async move {
            let mut on_progress = |_: ProgressNotification| {};
            c.call_with_progress::<Value>(STATUS, p, at, &mut on_progress)
                .await
        })
    }

    /// Progress subscriptions now held, over all request ids.
    fn subscriptions(client: &SharedClient) -> usize {
        client
            .inner
            .core
            .lock()
            .progress
            .values()
            .map(Vec::len)
            .sum()
    }

    /// Waits until `n` progress subscriptions are held; panics after [`WAIT`].
    async fn subscribed(client: &SharedClient, n: usize) {
        let deadline = Instant::now() + WAIT;
        while subscriptions(client) != n {
            assert!(Instant::now() < deadline, "the call never subscribed");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// An `AsyncWrite` whose every write fails with `kind`.
    struct FailingWriter(io::ErrorKind);

    impl AsyncWrite for FailingWriter {
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

    /// A client whose writer is held and whose writes fail with `kind`; the returned stream is
    /// the far end of its reader, kept open so the reader does not end.
    fn failing_writer(kind: io::ErrorKind) -> (SharedClient, Arc<Semaphore>, DuplexStream) {
        let (ours, theirs) = tokio::io::duplex(1024);
        let routes = Arc::new(Mutex::new(Routes::default()));
        let reader = AbortOnDrop(tokio::spawn(read_loop(ours, routes.clone())));
        let gate = Arc::new(Semaphore::new(0));
        let mut core = Core::new();
        core.gate = Some(gate.clone());
        let client = SharedClient::start_with(core, FailingWriter(kind), &routes, reader, 2, None);
        (client, gate, theirs)
    }

    /// Two calls (ids 2 and 3) with their frames queued, in that order, behind a held writer.
    async fn queue_two(
        client: &SharedClient,
    ) -> (
        tokio::task::JoinHandle<Sent<Value>>,
        tokio::task::JoinHandle<Sent<Value>>,
    ) {
        let first = spawn_call(client, params("first"), None);
        routed(client, 1).await;
        let second = spawn_call(client, params("second"), None);
        routed(client, 2).await;
        // Both frames reach the queue right after their routes exist.
        tokio::time::sleep(Duration::from_millis(50)).await;
        (first, second)
    }

    /// Waits until `n` routes exist; panics after [`WAIT`].
    async fn routed(client: &SharedClient, n: usize) {
        let deadline = Instant::now() + WAIT;
        while client.inner.core.lock().routes.len() != n {
            assert!(Instant::now() < deadline, "the call never queued");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_client_dropped_call_leaves_stream_framed() {
        let (client, gate, mut peer) = pair(true, 1024);

        // Before: dropped while its frame waits behind the held writer.
        let cut = tokio::time::timeout(
            Duration::from_millis(100),
            client.call::<Value>(STATUS, params("before"), None),
        )
        .await;
        assert!(cut.is_err(), "answered with the writer held");
        idle(&client).await;
        gate.add_permits(OPEN);

        // During: the frame is larger than the pipe, so the writer is inside it (the peer
        // reads nothing yet) when the future is dropped.
        let pad = "x".repeat(256 * 1024);
        let cut = tokio::time::timeout(
            Duration::from_millis(200),
            client.call::<Value>(STATUS, json!({"request_id": "during", "pad": pad}), None),
        )
        .await;
        assert!(cut.is_err(), "answered before the peer read");
        assert!(
            !client.idle(),
            "a taken frame's slot was released before its answer"
        );
        let req = peer.next().await;
        assert_eq!(
            req["params"]["request_id"], "during",
            "{}",
            req["params"]["request_id"]
        );
        assert_eq!(req["params"]["pad"].as_str().map(str::len), Some(pad.len()));
        peer.answer(&req, json!({"stale": "during"})).await;
        idle(&client).await;

        // After: written whole, dropped before its answer.
        let task = spawn_call(&client, params("after"), None);
        let req = peer.next().await;
        assert_eq!(req["params"]["request_id"], "after");
        task.abort();
        let _ = task.await;
        assert!(
            !client.idle(),
            "the tombstone released its slot before the answer"
        );
        peer.answer(&req, json!({"stale": "after"})).await;
        idle(&client).await;

        // The stream is still framed, and no late answer reached the next call.
        let task = spawn_call(&client, params("next"), soon());
        let req = peer.next().await;
        assert_eq!(req["params"]["request_id"], "next");
        peer.answer(&req, json!({"fresh": true})).await;
        let sent = join(task).await;
        assert!(sent.written);
        assert_eq!(sent.result.expect("answer"), json!({"fresh": true}));
        assert!(!client.is_closed());
        idle(&client).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_client_written_flag_per_call() {
        let (client, gate, mut peer) = pair(true, 64 * 1024);

        // `at` passes while the frame is queued behind the held writer: never written.
        let sent = client
            .call::<Value>(STATUS, params("queued"), after(100))
            .await;
        assert!(!sent.written);
        assert!(
            matches!(sent.result, Err(ClientError::DeadlineExceeded)),
            "{:?}",
            sent.result
        );
        idle(&client).await;
        gate.add_permits(OPEN);

        // `at` passes after the writer took the frame: written, and its slot stays taken
        // until the late answer.
        let task = spawn_call(&client, params("taken"), after(300));
        let req = peer.next().await;
        assert_eq!(
            req["params"]["request_id"], "taken",
            "the abandoned frame was written"
        );
        let sent = join(task).await;
        assert!(sent.written);
        assert!(
            matches!(sent.result, Err(ClientError::DeadlineExceeded)),
            "{:?}",
            sent.result
        );
        assert!(!client.idle());
        peer.answer(&req, json!({"stale": true})).await;
        idle(&client).await;

        // Answered: written.
        let task = spawn_call(&client, params("answered"), soon());
        let req = peer.next().await;
        peer.answer(&req, json!({"ok": true})).await;
        let sent = join(task).await;
        assert!(sent.written);
        assert_eq!(sent.result.expect("answer"), json!({"ok": true}));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_client_abandoned_frame_never_written() {
        let (client, gate, mut peer) = pair(true, 64 * 1024);

        let sent = client
            .call::<Value>(STATUS, params("expired"), after(100))
            .await;
        assert!(!sent.written);
        let cut = tokio::time::timeout(
            Duration::from_millis(100),
            client.call::<Value>(STATUS, params("dropped"), None),
        )
        .await;
        assert!(cut.is_err(), "answered with the writer held");
        idle(&client).await;

        gate.add_permits(OPEN);
        let task = spawn_call(&client, params("next"), soon());
        let req = peer.next().await;
        assert_eq!(req["method"], STATUS);
        assert_eq!(
            req["params"]["request_id"], "next",
            "an abandoned frame was written"
        );
        peer.answer(&req, json!({"ok": true})).await;
        let sent = join(task).await;
        assert!(sent.written);
        assert_eq!(sent.result.expect("answer"), json!({"ok": true}));
        assert!(
            peer.quiet(Duration::from_millis(200)).await,
            "an abandoned frame was written after the next one"
        );
        idle(&client).await;
    }

    /// A frame still queued when the connection closes was never written.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_client_close_with_frame_queued_is_unwritten() {
        let (client, _gate, peer) = pair(true, 64 * 1024);
        let task = spawn_call(&client, params("queued"), None);
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(peer);
        let sent = join(task).await;
        assert!(!sent.written);
        assert!(
            matches!(sent.result, Err(ClientError::ConnectionLost)),
            "{:?}",
            sent.result
        );
        assert!(client.is_closed());
        idle(&client).await;
    }

    /// A progress call's subscription ends with the call: at its deadline, and when its future
    /// is dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_client_unsubscribes_when_a_progress_call_ends() {
        let (client, _gate, _peer) = pair(true, 1024);

        let task = spawn_progress_call(&client, params("deadline"), after(300));
        subscribed(&client, 1).await;
        let sent = join(task).await;
        assert!(!sent.written);
        assert!(
            matches!(sent.result, Err(ClientError::DeadlineExceeded)),
            "{:?}",
            sent.result
        );
        assert_eq!(
            subscriptions(&client),
            0,
            "the deadline kept the subscription"
        );
        assert!(client.idle());

        let task = spawn_progress_call(&client, params("dropped"), None);
        subscribed(&client, 1).await;
        task.abort();
        let _ = task.await;
        assert_eq!(subscriptions(&client), 0, "a drop kept the subscription");
        assert!(client.idle());
    }

    /// The writer's `write` fails with the peer gone: it first gives the reader a moment, so an
    /// answer that was already on its way still reaches its call; then the client closes. The
    /// failing frame's call was written, the one queued behind it was not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_client_write_failure_closes_after_a_moment_for_answers() {
        let (client, gate, _theirs) = failing_writer(io::ErrorKind::BrokenPipe);
        let (first, second) = queue_two(&client).await;
        gate.add_permits(1);

        // The first frame was taken and failed; its answer arrives during the moment.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!client.is_closed(), "closed without waiting for answers");
        client
            .inner
            .core
            .deliver(Response::result(2, json!({"late": true})));
        let first = join(first).await;
        assert!(first.written);
        assert_eq!(first.result.expect("answer"), json!({"late": true}));
        let second = join(second).await;
        assert!(!second.written);
        assert!(
            matches!(second.result, Err(ClientError::ConnectionLost)),
            "{:?}",
            second.result
        );
        assert!(client.is_closed());
        idle(&client).await;
    }

    /// A write failure that does not mean the peer is gone closes at once; the frame that
    /// failed is written, the queued one behind it is not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_client_write_failure_closes_with_failing_frame_written() {
        let (client, gate, _theirs) = failing_writer(io::ErrorKind::Other);
        let (first, second) = queue_two(&client).await;
        gate.add_permits(1);

        let first = join(first).await;
        assert!(first.written);
        assert!(
            matches!(first.result, Err(ClientError::ConnectionLost)),
            "{:?}",
            first.result
        );
        let second = join(second).await;
        assert!(!second.written);
        assert!(
            matches!(second.result, Err(ClientError::ConnectionLost)),
            "{:?}",
            second.result
        );
        assert!(client.is_closed());
        idle(&client).await;
    }

    /// A client started on a reader that already ended is closed with the reader's reason.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_client_start_on_an_ended_reader_is_closed() {
        let (ours, theirs) = tokio::io::duplex(1024);
        let (rd, wr) = tokio::io::split(ours);
        let routes = Arc::new(Mutex::new(Routes::default()));
        let reader = AbortOnDrop(tokio::spawn(read_loop(rd, routes.clone())));
        drop(theirs);
        let deadline = Instant::now() + WAIT;
        while lock(&routes).closed.is_none() {
            assert!(Instant::now() < deadline, "the reader never ended");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let client = SharedClient::start(wr, &routes, reader, 2, None);
        assert!(client.is_closed());
        let sent = client.call::<Value>(STATUS, params("x"), soon()).await;
        assert!(!sent.written);
        assert!(
            matches!(sent.result, Err(ClientError::ConnectionLost)),
            "{:?}",
            sent.result
        );
    }

    /// A close wakes the calls that wait for a slot: they fail at once, unwritten, not at their
    /// deadlines.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_client_close_wakes_calls_waiting_for_a_slot() {
        let (client, _gate, peer) = pair(true, 64 * 1024);
        let held: Vec<_> = (0..SHARED_IN_FLIGHT)
            .map(|i| spawn_call(&client, params(&format!("held{i}")), None))
            .collect();
        let deadline = Instant::now() + WAIT;
        while client.inner.core.slots.available_permits() > 0 {
            assert!(Instant::now() < deadline, "the slots were never taken");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let t0 = Instant::now();
        let waiting = spawn_call(&client, params("waiting"), after(5000));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiting.is_finished(), "the call did not wait for a slot");
        drop(peer);

        let sent = join(waiting).await;
        assert!(!sent.written);
        assert!(
            matches!(sent.result, Err(ClientError::ConnectionLost)),
            "{:?}",
            sent.result
        );
        assert!(t0.elapsed() < Duration::from_secs(4), "{:?}", t0.elapsed());
        for task in held {
            let sent = join(task).await;
            assert!(!sent.written);
            assert!(matches!(sent.result, Err(ClientError::ConnectionLost)));
        }
        idle(&client).await;
    }

    /// An answer for an id nobody waits for, a second answer for an id, and a `null`-id result
    /// are discarded: they close nothing and reach no other call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_client_unknown_and_duplicate_answers_are_discarded() {
        let (client, _gate, mut peer) = pair(false, 64 * 1024);
        let task = spawn_call(&client, params("a"), soon());
        let req = peer.next().await;
        peer.send(json!({"jsonrpc": "2.0", "id": 9999, "result": {"unknown": true}}))
            .await;
        peer.send(json!({"jsonrpc": "2.0", "id": null, "result": {"null_id": true}}))
            .await;
        peer.answer(&req, json!({"first": true})).await;
        peer.answer(&req, json!({"duplicate": true})).await;
        let sent = join(task).await;
        assert!(sent.written);
        assert_eq!(sent.result.expect("answer"), json!({"first": true}));

        // Everything above was read before this call's answer is.
        let task = spawn_call(&client, params("b"), soon());
        let req = peer.next().await;
        peer.answer(&req, json!({"second": true})).await;
        let sent = join(task).await;
        assert_eq!(sent.result.expect("answer"), json!({"second": true}));
        assert!(!client.is_closed());
        idle(&client).await;
    }

    /// An answer routed after the deadline branch won, before the call looks at its frame, is
    /// the call's answer: it is not discarded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_client_answer_landing_after_the_deadline_is_kept() {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let (rd, wr) = tokio::io::split(ours);
        let routes = Arc::new(Mutex::new(Routes::default()));
        let reader = AbortOnDrop(tokio::spawn(read_loop(rd, routes.clone())));
        let mut core = Core::new();
        core.after_wait = Some(Arc::new(|core: &Core| {
            core.deliver(Response::result(2, json!({"late": true})));
        }));
        let client = SharedClient::start_with(core, wr, &routes, reader, 2, None);
        let (rd, wr) = tokio::io::split(theirs);
        let mut peer = Peer { rd, wr };

        let task = spawn_call(&client, params("late"), after(300));
        let req = peer.next().await;
        assert_eq!(req["params"]["request_id"], "late");
        let sent = join(task).await;
        assert!(sent.written);
        assert_eq!(sent.result.expect("the late answer"), json!({"late": true}));
        idle(&client).await;
    }

    /// The MCP layer spawns these futures.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_client_and_its_calls_are_send() {
        fn send<T: Send>(_: &T) {}
        fn shareable<T: Send + Sync + Clone>() {}
        shareable::<SharedClient>();
        let (client, _gate, _peer) = pair(true, 1024);
        let call = client.call::<Value>(STATUS, params("x"), None);
        send(&call);
        drop(call);
        let mut on_progress = |_: ProgressNotification| {};
        let call = client.call_with_progress::<Value>(STATUS, params("x"), None, &mut on_progress);
        send(&call);
        drop(call);
    }
}
