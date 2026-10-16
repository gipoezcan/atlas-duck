//! The worker's three stdio pipes (§3.4). The host-side reader threads are
//! `crate::drain`'s.
//!
//! The worker gets exactly three handles, each a pipe owned by the host. The
//! child ends are inheritable (and are the only handles named in
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`); the host ends never are, and every
//! handle starts out non-inheritable (no leak window while the pipes are set
//! up).

use std::fs::File;
use std::io::{self, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::{null, null_mut};

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

    /// Moves the pipe out (for `into_parts`), leaving a closed one behind.
    pub(crate) fn take(&mut self) -> StdinPipe {
        StdinPipe(self.0.take())
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
