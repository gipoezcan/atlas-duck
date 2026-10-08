//! The audit guard (§5.1 invariant 1, §7.2): no PAT-bearing request without proof that its
//! start record is committed. The proof can only be minted by `CoverIssuer`, whose probe
//! answers from the in-memory set `core` fills after `AuditPort::append` returned `Ok`.

use std::fmt;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

/// Proof of a committed `REQUEST_RECEIVED` / `SCRIPT_STARTED` / `SYSTEM_FETCH` start record.
///
/// No public fields, no public constructor, not `Default`, not `Deserialize`: the only way to
/// obtain one is `CoverIssuer::for_request` / `for_system_fetch`.
///
/// ```compile_fail,E0451
/// let _ = atlas_duck_atlassian::AuditCover { kind: todo!() };
/// ```
#[derive(Clone)]
pub struct AuditCover {
    kind: CoverKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CoverKind {
    Request(String),
    SystemFetch(String),
}

impl AuditCover {
    pub fn request_id(&self) -> Option<&str> {
        match &self.kind {
            CoverKind::Request(id) => Some(id),
            CoverKind::SystemFetch(_) => None,
        }
    }

    pub fn fetch_id(&self) -> Option<&str> {
        match &self.kind {
            CoverKind::SystemFetch(id) => Some(id),
            CoverKind::Request(_) => None,
        }
    }
}

impl fmt::Debug for AuditCover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            CoverKind::Request(id) => write!(f, "AuditCover(Request({id}))"),
            CoverKind::SystemFetch(id) => write!(f, "AuditCover(SystemFetch({id}))"),
        }
    }
}

/// Answers from the set of ids whose start record `core` has durably committed.
pub trait CommitProbe: Send + Sync {
    fn request_committed(&self, request_id: &str) -> bool;
    fn system_fetch_started(&self, fetch_id: &str) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotCommitted;

impl fmt::Display for NotCommitted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the audit start record is not committed")
    }
}

impl std::error::Error for NotCommitted {}

pub struct CoverIssuer {
    probe: Arc<dyn CommitProbe>,
}

impl CoverIssuer {
    pub fn new(probe: Arc<dyn CommitProbe>) -> Self {
        CoverIssuer { probe }
    }

    pub fn for_request(&self, request_id: &str) -> Result<AuditCover, NotCommitted> {
        if self.probe.request_committed(request_id) {
            Ok(AuditCover {
                kind: CoverKind::Request(request_id.to_owned()),
            })
        } else {
            Err(NotCommitted)
        }
    }

    pub fn for_system_fetch(&self, fetch_id: &str) -> Result<AuditCover, NotCommitted> {
        if self.probe.system_fetch_started(fetch_id) {
            Ok(AuditCover {
                kind: CoverKind::SystemFetch(fetch_id.to_owned()),
            })
        } else {
            Err(NotCommitted)
        }
    }
}

/// Receives the server `Date` of every response that arrived over a verified TLS connection
/// (§8.8 corroboration is `core`'s concern; the client only reports).
pub trait DateObserver: Send + Sync {
    fn observe(&self, instance_id: &str, server_date: SystemTime, at: Instant);
}
