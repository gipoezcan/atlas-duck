//! Unsupported OS: every lookup fails, so the chain stays empty.

use std::path::PathBuf;

use super::PeerSource;

#[derive(Debug, Default)]
pub struct OsPeerSource {
    _per_walk: (),
}

impl PeerSource for OsPeerSource {
    fn parent(&self, _pid: u32) -> Option<u32> {
        None
    }

    fn start_time(&self, _pid: u32) -> Option<u64> {
        None
    }

    fn exe(&self, _pid: u32) -> Option<PathBuf> {
        None
    }
}
