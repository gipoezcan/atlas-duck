//! The job's I/O completion port (M8 Task 9, §9.4 `process_mb` on Windows, PD-134): the job
//! posts `JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT` when it refuses the worker an allocation above
//! `ProcessMemoryLimit`, and the bridge's memory thread turns that into `Limit("process_mb")`.
//!
//! - The port is associated in [`super::job::Job::create`], before `CreateProcessW` puts the
//!   worker in the job (`PROC_THREAD_ATTRIBUTE_JOB_LIST`), so the worker never runs unwatched and
//!   no message can be missed: the port queues every message until it is read.
//! - The job does not kill at the limit; the allocation fails and the worker's `ExitOnOomAlloc`
//!   exits `EXIT_PROCESS_LIMIT`. The message makes the host's own observation the verdict, and
//!   the bridge kills (§9.5: a limit the host enforces by terminating the run).
//! - Windows does not guarantee delivery of job messages ("intended only as notifications"), so
//!   the port is the host's extra evidence, never the only one: the exit code stands on its own.
//! - The watch ends at `JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO` (the worker is gone) or at the stop
//!   packet the bridge posts at the reap. Packets are dequeued in order, so a memory message the
//!   job posted before the worker exited is handled before the stop. The stop also sets a flag
//!   the watch checks whenever the port stays empty for [`STOP_POLL`], so a stop packet that
//!   could not be posted, with no `ACTIVE_PROCESS_ZERO` either (job messages are not
//!   guaranteed), still ends the watch's thread (T9 review m-6).

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED, PostQueuedCompletionStatus,
};
use windows_sys::Win32::System::JobObjects::{
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JobObjectAssociateCompletionPortInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::SystemServices::{
    JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO, JOB_OBJECT_MSG_JOB_MEMORY_LIMIT,
    JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT,
};

use crate::limits::{MemoryWatch, OsMemorySignal};
use crate::spawn::KillHandle;

/// The completion key of the job's own messages.
const KEY_JOB: usize = 1;
/// The completion key of the bridge's stop packet.
const KEY_STOP: usize = 2;
/// How long the watch waits for a packet before it looks at the stop flag.
pub(crate) const STOP_POLL: Duration = Duration::from_secs(1);

/// What one dequeued packet means for the watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortEvent {
    /// The job refused the worker memory above its limit.
    MemoryLimit,
    /// The job has no process left: the worker is gone.
    Gone,
    /// The bridge stopped the watch (the worker is reaped).
    Stop,
    /// Any other job message (a process exited, a new process): nothing to do.
    Other,
}

/// Maps a packet (`msg` is the bytes-transferred value, which carries the job message id) to its
/// meaning. A packet with an unknown key is ignored.
pub(crate) fn classify(msg: u32, key: usize) -> PortEvent {
    match (key, msg) {
        (KEY_STOP, _) => PortEvent::Stop,
        (KEY_JOB, JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT | JOB_OBJECT_MSG_JOB_MEMORY_LIMIT) => {
            PortEvent::MemoryLimit
        }
        (KEY_JOB, JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO) => PortEvent::Gone,
        _ => PortEvent::Other,
    }
}

/// An I/O completion port for one job's messages.
#[derive(Debug)]
pub(crate) struct JobPort(OwnedHandle);

impl JobPort {
    /// A new port (no file handle, one concurrent thread).
    pub(crate) fn create() -> io::Result<JobPort> {
        // SAFETY: `INVALID_HANDLE_VALUE` with no existing port asks for a new port that is not
        // bound to any file; no pointer is passed.
        let port = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 1) };
        if port.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `port` is a fresh handle that nothing else owns.
        Ok(JobPort(unsafe {
            OwnedHandle::from_raw_handle(port as RawHandle)
        }))
    }

    /// `JobObjectAssociateCompletionPortInformation`: the job posts its messages to this port
    /// with [`KEY_JOB`]. A job takes one port, once.
    pub(crate) fn associate(&self, job: HANDLE) -> io::Result<()> {
        let info = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: KEY_JOB as *mut core::ffi::c_void,
            CompletionPort: self.raw(),
        };
        // SAFETY: `job` is an open job handle the caller owns for the call; `info` is a valid
        // structure of the size passed and outlives the call (the job keeps the port handle
        // value, not the structure).
        let ok = unsafe {
            SetInformationJobObject(
                job,
                JobObjectAssociateCompletionPortInformation,
                (&info as *const JOBOBJECT_ASSOCIATE_COMPLETION_PORT).cast(),
                std::mem::size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The watch of a split worker: two more handles to this port, one to read it, one to post
    /// the stop packet.
    pub(crate) fn watch(&self) -> io::Result<JobPortWatch> {
        Ok(JobPortWatch {
            port: self.0.try_clone()?,
            stop: Some(self.0.try_clone()?),
            stopped: Arc::default(),
            poll: STOP_POLL,
        })
    }

    fn raw(&self) -> HANDLE {
        self.0.as_raw_handle().cast()
    }
}

/// Posts one packet (`msg`, `key`) to `port`.
fn post(port: &OwnedHandle, msg: u32, key: usize) -> io::Result<()> {
    // SAFETY: `port` is an open completion port handle owned by the caller for the call; a null
    // OVERLAPPED is allowed for a posted packet.
    let ok = unsafe { PostQueuedCompletionStatus(port.as_raw_handle().cast(), msg, key, null()) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Waits up to `wait` for the next packet: `(msg, key)`, or `None` when the port stayed empty.
fn next(port: &OwnedHandle, wait: Duration) -> io::Result<Option<(u32, usize)>> {
    let mut msg = 0u32;
    let mut key = 0usize;
    let mut overlapped: *mut OVERLAPPED = null_mut();
    let wait_ms = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX - 1);
    // SAFETY: `port` is an open completion port handle owned by the caller for the call; the
    // three out-pointers refer to locals. For a job message `overlapped` receives the process id
    // (a value, never dereferenced here).
    let ok = unsafe {
        GetQueuedCompletionStatus(
            port.as_raw_handle().cast(),
            &mut msg,
            &mut key,
            &mut overlapped,
            wait_ms,
        )
    };
    if ok == 0 {
        let e = io::Error::last_os_error();
        // No packet within `wait`: FALSE, `WAIT_TIMEOUT`, and no OVERLAPPED.
        if overlapped.is_null() && e.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
            return Ok(None);
        }
        return Err(e);
    }
    Ok(Some((msg, key)))
}

/// The bridge's watch of one worker's job port ([`MemoryWatch`]).
pub(crate) struct JobPortWatch {
    port: OwnedHandle,
    stop: Option<OwnedHandle>,
    /// Set by the stopper before it posts the stop packet.
    stopped: Arc<AtomicBool>,
    /// How long one wait for a packet lasts ([`STOP_POLL`]).
    poll: Duration,
}

impl MemoryWatch for JobPortWatch {
    fn signal(&self) -> OsMemorySignal {
        OsMemorySignal::JobMemoryLimit
    }

    fn stopper(&mut self) -> Box<dyn FnOnce() + Send> {
        let port = self.stop.take();
        let stopped = Arc::clone(&self.stopped);
        Box::new(move || {
            stopped.store(true, Ordering::SeqCst);
            if let Some(port) = port
                && let Err(e) = post(&port, 0, KEY_STOP)
            {
                // The watch then ends at `ACTIVE_PROCESS_ZERO`, or at its next empty wait; the
                // bridge stops waiting for it after its grace.
                eprintln!("sandbox memory watch: posting the stop packet failed: {e}");
            }
        })
    }

    fn run(self: Box<Self>, limit: &dyn KillHandle) -> io::Result<()> {
        loop {
            let Some((msg, key)) = next(&self.port, self.poll)? else {
                // The port is empty, so no memory message is left unread.
                if self.stopped.load(Ordering::SeqCst) {
                    return Ok(());
                }
                continue;
            };
            match classify(msg, key) {
                PortEvent::MemoryLimit => limit.kill(),
                PortEvent::Gone | PortEvent::Stop => return Ok(()),
                PortEvent::Other => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use windows_sys::Win32::System::JobObjects::CreateJobObjectW;
    use windows_sys::Win32::System::SystemServices::JOB_OBJECT_MSG_EXIT_PROCESS;

    use super::*;

    #[derive(Default)]
    struct Counted(AtomicU32);

    impl KillHandle for Counted {
        fn kill(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn packets_map_to_their_meaning() {
        assert_eq!(
            classify(JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT, KEY_JOB),
            PortEvent::MemoryLimit
        );
        assert_eq!(
            classify(JOB_OBJECT_MSG_JOB_MEMORY_LIMIT, KEY_JOB),
            PortEvent::MemoryLimit
        );
        assert_eq!(
            classify(JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO, KEY_JOB),
            PortEvent::Gone
        );
        assert_eq!(
            classify(JOB_OBJECT_MSG_EXIT_PROCESS, KEY_JOB),
            PortEvent::Other
        );
        assert_eq!(classify(0, KEY_STOP), PortEvent::Stop);
        assert_eq!(
            classify(JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT, 99),
            PortEvent::Other,
            "an unknown key is ignored"
        );
    }

    /// A real port (no process is started): the packets queued before the stop are handled in
    /// order, a memory message kills, and the stop ends the watch.
    #[test]
    fn the_watch_kills_on_a_memory_message_and_ends_at_the_stop() -> io::Result<()> {
        let port = JobPort::create()?;
        let mut watch = Box::new(port.watch()?);
        let stop = watch.stopper();
        post(&port.0, JOB_OBJECT_MSG_EXIT_PROCESS, KEY_JOB)?;
        post(&port.0, JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT, KEY_JOB)?;
        post(&port.0, JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT, KEY_JOB)?;
        stop();
        // Queued after the stop: never read.
        post(&port.0, JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT, KEY_JOB)?;
        let kills = Counted::default();
        watch.run(&kills)?;
        assert_eq!(kills.0.load(Ordering::SeqCst), 2);

        // ACTIVE_PROCESS_ZERO ends it as well.
        let port = JobPort::create()?;
        let watch = Box::new(port.watch()?);
        post(&port.0, JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO, KEY_JOB)?;
        let kills = Counted::default();
        watch.run(&kills)?;
        assert_eq!(kills.0.load(Ordering::SeqCst), 0);
        Ok(())
    }

    /// T9 review m-6: a stop whose packet never arrives (here: the stopper has no handle to
    /// post with, as after a failed post) still ends the watch at its next empty wait, after the
    /// memory messages already queued were handled.
    #[test]
    fn a_stop_without_its_packet_still_ends_the_watch() -> io::Result<()> {
        let port = JobPort::create()?;
        let mut watch = Box::new(port.watch()?);
        watch.stop = None;
        watch.poll = Duration::from_millis(50);
        let stop = watch.stopper();
        post(&port.0, JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT, KEY_JOB)?;
        stop();
        let kills = Counted::default();
        let started = std::time::Instant::now();
        watch.run(&kills)?;
        assert!(started.elapsed() < Duration::from_secs(20));
        assert_eq!(
            kills.0.load(Ordering::SeqCst),
            1,
            "the queued message first"
        );

        // An empty wait before the stop is no error and does not end the watch.
        assert_eq!(next(&port.0, Duration::from_millis(1))?, None);
        Ok(())
    }

    /// A fresh job (empty; no process is started) takes the port.
    #[test]
    fn a_job_takes_the_port() -> io::Result<()> {
        // SAFETY: no security attributes, no name.
        let job = unsafe { CreateJobObjectW(null(), null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `job` is a fresh handle that nothing else owns.
        let job = unsafe { OwnedHandle::from_raw_handle(job as RawHandle) };
        let port = JobPort::create()?;
        port.associate(job.as_raw_handle().cast())?;
        Ok(())
    }
}
