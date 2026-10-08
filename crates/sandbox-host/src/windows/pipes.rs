//! The worker's three stdio pipes and the host-side frame reader (§3.4).
//!
//! The worker gets exactly three handles, each a pipe owned by the host. The
//! child ends are inheritable (and are the only handles named in
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`); the host ends never are, and every
//! handle starts out non-inheritable (no leak window while the pipes are set
//! up).

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::{null, null_mut};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use atlas_duck_ipc::sandbox::WORKER_FRAME_MAX_BYTES;
use atlas_duck_ipc::sandbox::frame::{FrameError, read_frame};
use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows_sys::Win32::System::Pipes::CreatePipe;

/// Pipe buffer size (the default 4 KiB would make a chatty worker block on
/// every few frames).
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

/// How much of the worker's stderr is kept (section 3.4).
pub(crate) const STDERR_CAP_BYTES: usize = 64 * 1024;

/// The ends the worker inherits.
pub(crate) struct ChildEnds {
    pub(crate) stdin: OwnedHandle,
    pub(crate) stdout: OwnedHandle,
    pub(crate) stderr: OwnedHandle,
}

/// The ends the host keeps.
pub(crate) struct HostEnds {
    pub(crate) stdin: File,
    pub(crate) stdout: File,
    pub(crate) stderr: File,
}

/// `(read end, write end)` of a new anonymous pipe. Both ends are created
/// **not inheritable** and are wrapped in `OwnedHandle`s at once, so no handle
/// of ours can leak into another process the app creates in the meantime (an
/// early `?` closes them). Only the worker's own ends are made inheritable,
/// by [`inheritable`], for the one `CreateProcessW` call.
fn pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut r = null_mut();
    let mut w = null_mut();
    // SAFETY: out-pointers are valid; default security attributes (NULL) make
    // the handles non-inheritable.
    if unsafe { CreatePipe(&mut r, &mut w, null(), PIPE_BUFFER_BYTES) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both handles are fresh and owned by us.
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(r as RawHandle),
            OwnedHandle::from_raw_handle(w as RawHandle),
        )
    })
}

/// Marks a handle inheritable (the worker's ends, just before the spawn).
fn inheritable(h: &OwnedHandle) -> io::Result<()> {
    // SAFETY: valid handle owned by `h`.
    if unsafe {
        SetHandleInformation(
            h.as_raw_handle().cast(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Creates the three pipes: host writes the worker's stdin, host reads its
/// stdout and stderr. Call with the spawn lock held and spawn right after:
/// the three returned [`ChildEnds`] are the only inheritable handles.
pub(crate) fn create_stdio_pipes() -> io::Result<(HostEnds, ChildEnds)> {
    let (in_r, in_w) = pipe()?;
    let (out_r, out_w) = pipe()?;
    let (err_r, err_w) = pipe()?;
    inheritable(&in_r)?;
    inheritable(&out_w)?;
    inheritable(&err_w)?;
    Ok((
        HostEnds {
            stdin: File::from(in_w),
            stdout: File::from(out_r),
            stderr: File::from(err_r),
        },
        ChildEnds {
            stdin: in_r,
            stdout: out_w,
            stderr: err_w,
        },
    ))
}

/// Host end of the worker's stdin; writing after `close` is `BrokenPipe`.
pub(crate) struct StdinPipe(Option<File>);

impl StdinPipe {
    pub(crate) fn new(f: File) -> Self {
        Self(Some(f))
    }

    pub(crate) fn close(&mut self) {
        self.0 = None;
    }
}

impl Write for StdinPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.0 {
            Some(f) => f.write(buf),
            None => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

enum FrameEvent {
    Frame(Vec<u8>),
    Eof,
    Invalid,
    Io(io::ErrorKind, String),
}

/// Reads frames from the worker's stdout on one thread, because a pipe read
/// has no timeout on Windows. The worker's frames are bounded by
/// `WORKER_FRAME_MAX_BYTES` (§3.4); a larger `max` passed to
/// [`FrameReader::recv`] is clamped by that bound.
pub(crate) struct FrameReader {
    rx: Receiver<FrameEvent>,
}

impl FrameReader {
    pub(crate) fn start(mut stdout: File) -> io::Result<Self> {
        let (tx, rx) = channel();
        std::thread::Builder::new()
            .name("atlas-duck-sbx-out".into())
            .spawn(move || {
                loop {
                    let event = match read_frame(&mut stdout, WORKER_FRAME_MAX_BYTES) {
                        Ok(Some(payload)) => FrameEvent::Frame(payload),
                        Ok(None) => FrameEvent::Eof,
                        Err(FrameError::TooLarge { .. } | FrameError::Truncated) => {
                            FrameEvent::Invalid
                        }
                        Err(FrameError::Io(e)) => FrameEvent::Io(e.kind(), e.to_string()),
                    };
                    let last = !matches!(event, FrameEvent::Frame(_));
                    if tx.send(event).is_err() || last {
                        break;
                    }
                }
            })?;
        Ok(Self { rx })
    }

    /// The `WorkerProcess::read_frame_timeout` contract: `Ok(Some)` one
    /// frame, `Ok(None)` clean EOF, `TimedOut` nothing within `d`,
    /// `InvalidData` oversize or truncated.
    pub(crate) fn recv(&mut self, max: usize, d: Duration) -> io::Result<Option<Vec<u8>>> {
        match self.rx.recv_timeout(d) {
            Ok(FrameEvent::Frame(p)) if p.len() > max => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "worker frame larger than the allowed maximum",
            )),
            Ok(FrameEvent::Frame(p)) => Ok(Some(p)),
            Ok(FrameEvent::Eof) | Err(RecvTimeoutError::Disconnected) => Ok(None),
            Ok(FrameEvent::Invalid) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversize or truncated worker frame",
            )),
            Ok(FrameEvent::Io(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(RecvTimeoutError::Timeout) => Err(io::ErrorKind::TimedOut.into()),
        }
    }
}

/// Drains the worker's stderr so a chatty worker never blocks on a full
/// pipe. Only the first [`STDERR_CAP_BYTES`] bytes are kept (section 3.4:
/// 64 KiB), the rest is discarded. The kept bytes are for tests and are never
/// written to the diagnostic log.
pub(crate) fn drain_stderr(mut stderr: File) -> io::Result<Arc<Mutex<Vec<u8>>>> {
    let kept = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&kept);
    std::thread::Builder::new()
        .name("atlas-duck-sbx-err".into())
        .spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match stderr.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut kept = sink.lock().unwrap_or_else(|p| p.into_inner());
                        let room = STDERR_CAP_BYTES.saturating_sub(kept.len());
                        kept.extend_from_slice(&chunk[..n.min(room)]);
                    }
                }
            }
        })?;
    Ok(kept)
}
