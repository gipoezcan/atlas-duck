//! The sandbox worker's exit codes (spec §9.3, plan M8 PD-134). The worker exits with them; the
//! host reads them back (the bridge, M8 Task 7; the limit attribution, M8 Task 9).

/// Exit code: clean end (stdin EOF, or the one reply of a compile or a run was written).
pub const EXIT_OK: i32 = 0;
/// Exit code: stdin or stdout failed (broken pipe, oversized or truncated frame).
pub const EXIT_IO: i32 = 1;
/// Exit code: a first frame that picks no mode, a malformed `probe.run`, or a
/// host frame during a run that is not a response to an outstanding call (or an
/// init frame the shim cannot use). Always a host fault, never the script's doing.
pub const EXIT_PROTOCOL: i32 = 3;
/// Exit code: a panic (the Rust default panic exit code), set by the worker's
/// panic hook; the probe scoring reads it as `Error`. Also an engine failure
/// that is neither the script's nor the host's.
pub const EXIT_PANIC: i32 = 101;
/// Exit code (plan M8 PD-134): the QuickJS allocator refused a request above
/// `heap_mb`. Nothing is written after the refusal (no terminal frame).
pub const EXIT_HEAP_LIMIT: i32 = 102;
/// Exit code (plan M8 PD-134): the process itself is out of memory (the
/// worker binary's exit-on-OOM allocator; in-process, an allocation that
/// failed below `heap_mb`).
pub const EXIT_PROCESS_LIMIT: i32 = 103;
