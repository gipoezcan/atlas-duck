//! The `atlas-duck-sandbox` binary's library (rquickjs) (§2.2).
//!
//! §2.2: depends only on `ipc` (types) + `rquickjs`. §2.1: no HTTP client,
//! keychain or DB code linked.
//!
//! M1 Task 4 stub: drains stdin and exits 0 on EOF ("The worker exits on stdin EOF", §3.4).
//! Task 14 replaces `run` with the probe loop.

use std::io::{ErrorKind, Read};

use atlas_duck_ipc::build_info::BUILD_ID;

/// Runs the worker on the calling (main) thread and returns its exit code.
pub fn run() -> i32 {
    // §3.4: the probe records the worker's embedded version (Task 14 sends BUILD_ID in
    // `probe.ready`). black_box keeps the constant referenced, so the linker cannot drop it.
    let _ = std::hint::black_box(BUILD_ID);
    let mut buf = [0u8; 8192];
    let mut stdin = std::io::stdin().lock();
    loop {
        match stdin.read(&mut buf) {
            Ok(0) => return 0,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return 1,
        }
    }
}
