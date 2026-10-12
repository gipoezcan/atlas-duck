//! Protocol types (JSON-RPC), framing, per-OS transport, peer identity (§2.2).
//!
//! Feature `async` (default) gates the tokio-based codecs; the sandbox worker
//! depends on this crate with `default-features = false`.

// PD-01: the test home override exists only for test builds; a release build must never carry it.
#[cfg(all(feature = "test-paths", not(debug_assertions)))]
compile_error!("test-paths must never reach a release build");

pub mod build_info;
pub mod envelope;
pub mod jcs;
pub mod paths;
#[cfg(feature = "async")]
pub mod proto;
#[cfg(feature = "async")]
pub mod rpc;
pub mod sandbox;
#[cfg(feature = "async")]
pub mod transport;
