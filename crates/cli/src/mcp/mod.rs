//! `atlas-duck mcp`: the MCP front end (§4.6). A stdio MCP server (`rmcp`) that is one more
//! long-lived client of the app's IPC. stdout carries nothing but `rmcp`'s JSON-RPC frames
//! (§4.6, §13 S-02): nothing in this module prints, and the module denies the print lints.

#![deny(clippy::print_stdout, clippy::print_stderr)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub(crate) mod call;
pub(crate) mod config;
pub(crate) mod result;
pub(crate) mod server;
pub(crate) mod session;
pub(crate) mod tools;

#[cfg(test)]
mod rig;
#[cfg(test)]
mod tests;

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use rmcp::ServiceExt;
use rmcp::service::{QuitReason, ServerInitializeError};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

pub(crate) use config::{McpConfig, ToolSet};

use crate::connected::{Connector, OsConnector};
use server::{AtlasMcp, HEARTBEAT_EVERY};

/// Tokio workers of the server: tool calls are mostly waits; the launch poll runs on a blocking
/// thread of its own.
const WORKERS: usize = 2;

/// Serves MCP on stdio; returns the process exit code (PD-117: 0 on stdin EOF, 1 when the
/// runtime or the transport fails).
pub(crate) fn run(cfg: McpConfig) -> i32 {
    run_on(
        cfg,
        Arc::new(OsConnector),
        tokio::io::stdin(),
        tokio::io::stdout(),
    )
}

/// [`run`] over any reader and writer. The runtime is shut down in the background, as the CLI's
/// connected path does: a launch still polling on its blocking thread and tokio's blocking stdin
/// read must not keep the process alive once `serve` returned (plan review I-6).
pub(crate) fn run_on<R, W>(cfg: McpConfig, connector: Arc<dyn Connector>, read: R, write: W) -> i32
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    run_on_with(AtlasMcp::new(cfg, connector, HEARTBEAT_EVERY), read, write)
}

/// [`run_on`] with a prepared handler (tests: bodies that leave blocking work behind).
pub(crate) fn run_on_with<R, W>(server: AtlasMcp, read: R, write: W) -> i32
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .enable_all()
        .build()
    else {
        return 1;
    };
    let served = runtime.block_on(serve_with(server, read, write));
    runtime.shutdown_background();
    match served {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Serves `server` until stdin EOF (`Ok`) or a transport error (`Err`). Transport-generic: the
/// rig runs it over an in-process duplex pipe (with a short heartbeat period).
pub(crate) async fn serve_with<R, W>(server: AtlasMcp, read: R, write: W) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let ends = Arc::new(Ends::default());
    let transport = (
        Watched::new(read, ends.clone()),
        Watched::new(write, ends.clone()),
    );
    let running = match server.serve(transport).await {
        Ok(running) => running,
        // EOF before (or during) `initialize`: nothing was served, a clean end.
        Err(ServerInitializeError::ConnectionClosed(_)) => return ends.outcome(Ok(())),
        Err(e) => return Err(io::Error::other(e.to_string())),
    };
    // At stdin EOF rmcp would wait up to 5 s for in-flight handlers before it returns (M9 T1
    // item 5). Cancel the service instead: every handler's `context.ct` is a child of the
    // service's token, so waiting tool calls stop at once. Nothing is cancelled at the app.
    let stop = running.cancellation_token();
    let waiting = running.waiting();
    tokio::pin!(waiting);
    let quit = tokio::select! {
        quit = &mut waiting => quit,
        () = ends.wake.notified() => {
            stop.cancel();
            waiting.await
        }
    };
    let quit = match quit {
        Ok(QuitReason::JoinError(e)) | Err(e) => Err(io::Error::other(e)),
        Ok(_) => Ok(()),
    };
    ends.outcome(quit)
}

/// How the stdio transport ended, as the watched reader and writer saw it.
#[derive(Default)]
struct Ends {
    eof: AtomicBool,
    /// A read or write failed before stdin reached EOF.
    failed: AtomicBool,
    wake: Notify,
}

impl Ends {
    fn eof(&self) {
        self.eof.store(true, Ordering::SeqCst);
        self.wake.notify_one();
    }

    fn fail(&self) {
        if !self.eof.load(Ordering::SeqCst) {
            self.failed.store(true, Ordering::SeqCst);
        }
        self.wake.notify_one();
    }

    fn outcome(&self, served: io::Result<()>) -> io::Result<()> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(io::Error::other("the stdio transport failed"));
        }
        served
    }
}

/// A reader or writer that reports EOF and errors to [`Ends`].
struct Watched<T> {
    io: T,
    ends: Arc<Ends>,
}

impl<T> Watched<T> {
    fn new(io: T, ends: Arc<Ends>) -> Watched<T> {
        Watched { io, ends }
    }

    fn watch<V>(&self, polled: Poll<io::Result<V>>) -> Poll<io::Result<V>> {
        if let Poll::Ready(Err(_)) = &polled {
            self.ends.fail();
        }
        polled
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Watched<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let wanted = buf.remaining() > 0;
        let polled = Pin::new(&mut this.io).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &polled
            && wanted
            && buf.filled().len() == before
        {
            this.ends.eof();
        }
        this.watch(polled)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Watched<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.io).poll_write(cx, buf);
        this.watch(polled)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.io).poll_flush(cx);
        this.watch(polled)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.io).poll_shutdown(cx);
        this.watch(polled)
    }
}
