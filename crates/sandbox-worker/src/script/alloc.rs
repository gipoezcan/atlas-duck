//! The byte-limited QuickJS allocator (spec §9.3, §9.4 `heap_mb`; plan M8 PD-134).
//!
//! QuickJS-NG checks its own `malloc_limit` before it calls a custom allocator, so the runtime's
//! limit stays 0 (unlimited) and this wrapper alone enforces `heap_mb`: its refusal is the only
//! signal. It delegates the memory to an inner allocator (by default rquickjs's
//! [`RustAllocator`], which allocates through the Rust global allocator, so in the worker binary
//! `ExitOnOomAlloc` sees an exhausted process first) and only keeps the count.
//!
//! Block layout: `RustAllocator` puts an 8-byte size header (`usize`, padded to the 8-byte
//! alignment of `u64`) in front of each block and rounds the block up to a multiple of 8; it
//! returns the address after the header. `rquickjs::Allocator::dealloc` carries no size and
//! `usable_size` has no `self`, which is why the header exists. The count adds and removes
//! `usable_size` (the rounded block size); the 8 header bytes of each block are not counted.
//!
//! Two sticky flags, readable through the shared [`LimitState`] by the run loop, the interrupt
//! handler and the panic hook:
//! - `heap_refused`: this wrapper refused a request that would take the count above the limit
//!   (the run ends `EXIT_HEAP_LIMIT`);
//! - `system_null`: the inner allocator returned null below the limit (the process itself is out
//!   of memory; where `ExitOnOomAlloc` is installed it has already exited).

use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rquickjs::allocator::{Allocator, RustAllocator};

/// The count and the flags of one [`LimitAllocator`], shared with the run loop. The worker is
/// single-threaded; atomics only make the handle `Send + Sync` for the panic hook.
#[derive(Debug)]
pub struct LimitState {
    limit: usize,
    in_use: AtomicUsize,
    peak: AtomicUsize,
    heap_refused: AtomicBool,
    system_null: AtomicBool,
}

impl LimitState {
    fn new(limit: usize) -> Self {
        LimitState {
            limit,
            in_use: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            heap_refused: AtomicBool::new(false),
            system_null: AtomicBool::new(false),
        }
    }

    /// The limit in bytes (`heap_mb` MiB).
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Bytes the QuickJS runtime holds now.
    pub fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Relaxed)
    }

    /// The highest [`Self::in_use`] since the start or the last [`Self::reset_peak`].
    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    /// Restarts the peak at the current count (Task 25 measures `k` as the peak during one
    /// `deliver`).
    pub fn reset_peak(&self) {
        self.peak.store(self.in_use(), Ordering::Relaxed);
    }

    /// The wrapper refused a request above the limit (PD-134 → `EXIT_HEAP_LIMIT`).
    pub fn heap_refused(&self) -> bool {
        self.heap_refused.load(Ordering::Relaxed)
    }

    /// The inner allocator returned null below the limit (PD-134 → `EXIT_PROCESS_LIMIT`).
    pub fn system_null(&self) -> bool {
        self.system_null.load(Ordering::Relaxed)
    }

    /// Whether `add` more bytes fit after `remove` bytes leave. A request that does not fit sets
    /// `heap_refused`.
    fn admit(&self, add: usize, remove: usize) -> bool {
        let fits = self
            .in_use()
            .saturating_sub(remove)
            .checked_add(add)
            .is_some_and(|next| next <= self.limit);
        if !fits {
            self.heap_refused.store(true, Ordering::Relaxed);
        }
        fits
    }

    fn added(&self, bytes: usize) {
        let now = self
            .in_use
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes);
        self.peak.fetch_max(now, Ordering::Relaxed);
    }

    fn removed(&self, bytes: usize) {
        // Saturating: a count can never go below zero even if an inner allocator reported sizes
        // inconsistently.
        let _ = self
            .in_use
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(bytes))
            });
    }

    fn null_below_limit(&self) {
        self.system_null.store(true, Ordering::Relaxed);
    }
}

/// The QuickJS allocator of a script runtime, installed with `Runtime::new_with_alloc`.
pub struct LimitAllocator<A: Allocator = RustAllocator> {
    inner: A,
    state: Arc<LimitState>,
}

impl LimitAllocator<RustAllocator> {
    /// A wrapper over the Rust global allocator that refuses anything above `limit` bytes.
    pub fn new(limit: usize) -> (Self, Arc<LimitState>) {
        Self::with_inner(limit, RustAllocator)
    }
}

impl<A: Allocator> LimitAllocator<A> {
    /// A wrapper over `inner` (tests pass an allocator that returns null).
    pub fn with_inner(limit: usize, inner: A) -> (Self, Arc<LimitState>) {
        let state = Arc::new(LimitState::new(limit));
        (
            LimitAllocator {
                inner,
                state: Arc::clone(&state),
            },
            state,
        )
    }

    /// Counts a block the inner allocator handed out, or flags its null.
    fn account_new(&self, block: *mut u8) -> *mut u8 {
        if block.is_null() {
            self.state.null_below_limit();
        } else {
            // SAFETY: `block` was just returned non-null by `self.inner`, so it starts after the
            // inner allocator's size header.
            self.state.added(unsafe { A::usable_size(block) });
        }
        block
    }
}

// SAFETY: every block handed out comes unchanged from the inner allocator, which upholds the
// trait's size and alignment contract; this wrapper only refuses requests (returns null) and
// counts, and frees or resizes only pointers QuickJS got from it.
unsafe impl<A: Allocator> Allocator for LimitAllocator<A> {
    fn alloc(&mut self, size: usize) -> *mut u8 {
        if !self.state.admit(size, 0) {
            return ptr::null_mut();
        }
        let block = self.inner.alloc(size);
        self.account_new(block)
    }

    fn calloc(&mut self, count: usize, size: usize) -> *mut u8 {
        if count == 0 || size == 0 {
            // QuickJS never asks for zero bytes; `RustAllocator::calloc` returns null for them.
            return ptr::null_mut();
        }
        // An overflowing product is above any limit (and `RustAllocator::calloc` would panic).
        let Some(total) = count.checked_mul(size) else {
            self.state.heap_refused.store(true, Ordering::Relaxed);
            return ptr::null_mut();
        };
        if !self.state.admit(total, 0) {
            return ptr::null_mut();
        }
        let block = self.inner.calloc(count, size);
        self.account_new(block)
    }

    unsafe fn dealloc(&mut self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }
        // SAFETY: the caller passes a live block from this allocator, i.e. from `self.inner`.
        let size = unsafe { A::usable_size(ptr) };
        // SAFETY: as above; the block is freed exactly once, by the allocator that made it.
        unsafe { self.inner.dealloc(ptr) };
        self.state.removed(size);
    }

    unsafe fn realloc(&mut self, ptr: *mut u8, new_size: usize) -> *mut u8 {
        if ptr.is_null() {
            // `RustAllocator::realloc` would step back from a null pointer; QuickJS never sends
            // one (its arena layer handles it), but a fresh block is the defined answer.
            return self.alloc(new_size);
        }
        // SAFETY: the caller passes a live block from this allocator, i.e. from `self.inner`.
        let old = unsafe { A::usable_size(ptr) };
        if !self.state.admit(new_size, old) {
            // The old block stays valid, as for a failed `realloc`.
            return ptr::null_mut();
        }
        // SAFETY: as above; on success the inner allocator takes over the old block.
        let block = unsafe { self.inner.realloc(ptr, new_size) };
        if block.is_null() {
            self.state.null_below_limit();
            return block;
        }
        self.state.removed(old);
        // SAFETY: `block` was just returned non-null by `self.inner`.
        self.state.added(unsafe { A::usable_size(block) });
        block
    }

    unsafe fn usable_size(ptr: *mut u8) -> usize {
        // SAFETY: the caller passes a live block from this allocator, i.e. from the inner one.
        unsafe { A::usable_size(ptr) }
    }
}
