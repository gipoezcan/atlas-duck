//! The worker binary's global allocator (plan M8 PD-134): an exhausted process exits
//! [`EXIT_PROCESS_LIMIT`](crate::EXIT_PROCESS_LIMIT) at once.
//!
//! [`ExitOnOomAlloc`] delegates every request to [`System`]. When `System` returns null it ends
//! the process before `handle_alloc_error` could `abort` (whose `tgkill` the Linux seccomp
//! allowlist lacks: the worker would die by SIGSYS and read as `Crashed`): `_exit` on Unix (the
//! `exit_group` syscall, allowlisted), `TerminateProcess` of the current process on Windows (not
//! `ExitProcess`, whose DLL detach callbacks may allocate again). It allocates nothing and runs no
//! Rust code after the failure: never `std::process::exit`, whose atexit handlers, stdio flush and
//! TLS destructors can allocate.
//!
//! The library only exports the type. Only `app/src-tauri/src/bin/atlas-duck-sandbox.rs` and the
//! `confined_scripts` test binary declare it as `#[global_allocator]`: the app library links this
//! crate, so a declaration here would become the allocator of every app binary (checked by
//! `ci/check-workspace.mjs` `GLOBAL_ALLOCATOR_FILES`).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::alloc::{GlobalAlloc, Layout, System};

use crate::EXIT_PROCESS_LIMIT;

/// A [`GlobalAlloc`] over [`System`] that exits [`EXIT_PROCESS_LIMIT`] when the system refuses an
/// allocation.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExitOnOomAlloc;

/// Returns `block` unless it is null, in which case the process ends with
/// [`EXIT_PROCESS_LIMIT`].
#[inline]
fn or_exit(block: *mut u8) -> *mut u8 {
    if block.is_null() {
        exit_process_limit();
    }
    block
}

#[cfg(unix)]
fn exit_process_limit() -> ! {
    // SAFETY: `_exit` ends the process immediately; it touches no Rust state and allocates nothing.
    unsafe { libc::_exit(EXIT_PROCESS_LIMIT) }
}

#[cfg(windows)]
fn exit_process_limit() -> ! {
    use windows_sys::Win32::System::Threading::{ExitProcess, GetCurrentProcess, TerminateProcess};
    // The exit code is a positive constant.
    let code = EXIT_PROCESS_LIMIT.unsigned_abs();
    // SAFETY: `GetCurrentProcess` returns the pseudo handle of this process; terminating it ends
    // every thread at once without running DLL detach code.
    unsafe {
        TerminateProcess(GetCurrentProcess(), code);
    }
    // Not reached: `TerminateProcess` on the current process does not return when it succeeds.
    // SAFETY: as a last resort, `ExitProcess` also ends the process with the same code.
    unsafe { ExitProcess(code) }
}

// SAFETY: every method forwards to `System` with the caller's arguments unchanged and returns its
// pointer unchanged; a null from `System` never returns (the process exits instead).
unsafe impl GlobalAlloc for ExitOnOomAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, forwarded as is.
        or_exit(unsafe { System.alloc(layout) })
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as for `alloc`.
        or_exit(unsafe { System.alloc_zeroed(layout) })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from this allocator, i.e. from `System`, with this `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: as for `dealloc`; on null the old block stays valid, but the process exits.
        or_exit(unsafe { System.realloc(ptr, layout, new_size) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exit_code_is_the_process_limit_code() {
        assert_eq!(EXIT_PROCESS_LIMIT, 103);
        assert_eq!(EXIT_PROCESS_LIMIT.unsigned_abs(), 103);
    }

    /// The pass-through half (the exit half is proved in CI, Task 9's
    /// `linux_rlimit_as_reported_as_process_mb`): blocks come from `System` and round-trip.
    #[test]
    fn allocations_succeed_through_system() -> Result<(), std::alloc::LayoutError> {
        let a = ExitOnOomAlloc;
        let small = Layout::from_size_align(64, 16)?;
        let large = Layout::from_size_align(4096, 16)?;
        // SAFETY: a non-zero layout; the block is written within bounds and freed once with the
        // layout it has after the `realloc`.
        unsafe {
            let p = a.alloc_zeroed(small);
            assert!(!p.is_null());
            assert_eq!(*p.add(63), 0);
            p.write(7);
            let q = a.realloc(p, small, large.size());
            assert_eq!(*q, 7);
            a.dealloc(q, large);
        }
        Ok(())
    }
}
