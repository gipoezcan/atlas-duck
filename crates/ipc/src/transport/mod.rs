//! Per-OS transport (§3.1, §3.2): the server listener with its peer check and
//! the client connect with its server-owner check before the first byte.
//!
//! `Conn` is the OS-neutral byte stream both sides hand to the framing layer.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

#[cfg(unix)]
pub mod unix;

/// PD-29 diagnostics: `tracing` event names and reject reasons (closed sets).
pub mod diag {
    /// A connection was accepted.
    pub const EVENT_ACCEPT: &str = "ipc_accept";
    /// A connection was dropped before any byte was written to it.
    pub const EVENT_REJECT: &str = "ipc_reject";
    /// A framing or protocol error closed a connection.
    pub const EVENT_PROTOCOL_ERROR: &str = "ipc_protocol_error";
    /// Binding the endpoint failed.
    pub const EVENT_BIND_FAILED: &str = "ipc_bind_failed";

    /// Unix: the peer's uid is not the server's euid.
    pub const REASON_PEER_UID: &str = "peer_uid";
    /// Windows: the client's token SID is not the server's.
    pub const REASON_PEER_SID: &str = "peer_sid";
    /// Windows: impersonating the client failed.
    pub const REASON_IMPERSONATION: &str = "impersonation";
    /// A connection limit was hit (PD-27).
    pub const REASON_LIMIT: &str = "limit";
}

/// The byte stream behind a `Conn`.
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// A connected, identity-checked byte stream (server side after the peer
/// check, client side after the owner check).
pub struct Conn {
    inner: Box<dyn Stream>,
}

impl Conn {
    /// Wraps a stream. The transport constructs these only after its identity
    /// checks; tests may wrap in-memory streams.
    #[doc(hidden)]
    pub fn new<S>(stream: S) -> Conn
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Conn {
            inner: Box::new(stream),
        }
    }

    /// Read and write halves (`tokio::io::split`).
    pub fn split(self) -> (ReadHalf<Conn>, WriteHalf<Conn>) {
        tokio::io::split(self)
    }
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Conn")
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
