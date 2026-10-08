//! Protocol types (JSON-RPC), framing, per-OS transport, peer identity (§2.2).
//!
//! Feature `async` (default) gates the tokio-based codecs; the sandbox worker
//! depends on this crate with `default-features = false`.

pub mod build_info;
pub mod envelope;
pub mod jcs;
pub mod paths;
#[cfg(feature = "async")]
pub mod proto;
pub mod sandbox;
