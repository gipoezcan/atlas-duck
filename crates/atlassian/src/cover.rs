//! The audit guard (§5.1 invariant 1, §7.2): no PAT-bearing request without proof that its
//! start record is committed, and no write without proof that its `WRITE_APPROVED` is (Δ6). The
//! proof can only be minted by `CoverIssuer`, whose probe answers from the in-memory set `core`
//! fills after `AuditPort::append` returned `Ok`.

use std::fmt;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use crate::types::ApprovedWrite;

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

/// Proof of a committed `WRITE_APPROVED` for revision `candidate_counter` of the write
/// `request_id` (§5.1 inv. 1 and 3: the execution of a write is gated by its committed record;
/// Δ6, M3 final review M-18). The only proof `send_approved` accepts: a request cover (`AuditCover`)
/// covers the GETs before it, never the write.
///
/// No public fields, no public constructor, not `Clone`, not `Default`, not `Deserialize`: the only
/// way to obtain one is `CoverIssuer::for_write`, whose probe answers `true` only for the latest
/// committed approval of that write. `send_approved` takes it by value (one cover, one send) and
/// sends only the `ApprovedWrite` of the same `request_id` and `candidate_counter` (T20 review m1).
///
/// ```compile_fail,E0451
/// let _ = atlas_duck_atlassian::WriteCover { request_id: String::new(), candidate_counter: 1 };
/// ```
///
/// ```compile_fail,E0277
/// fn cloneable<T: Clone>() {}
/// cloneable::<atlas_duck_atlassian::WriteCover>();
/// ```
pub struct WriteCover {
    request_id: String,
    candidate_counter: u64,
}

impl WriteCover {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn candidate_counter(&self) -> u64 {
        self.candidate_counter
    }

    /// The cover was minted for exactly this write and revision.
    pub(crate) fn covers(&self, w: &ApprovedWrite) -> bool {
        self.request_id == w.request_id && self.candidate_counter == w.candidate_counter
    }
}

impl fmt::Debug for WriteCover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WriteCover({}, {})",
            self.request_id, self.candidate_counter
        )
    }
}

/// Answers from the set of ids whose start record `core` has durably committed, and from the
/// latest committed `WRITE_APPROVED` of each write.
pub trait CommitProbe: Send + Sync {
    fn request_committed(&self, request_id: &str) -> bool;
    fn system_fetch_started(&self, fetch_id: &str) -> bool;
    /// `true` only while revision `candidate_counter` is the latest committed approval of the
    /// write `request_id` (a later approval, a return to the queue or the terminal state ends it).
    fn write_approved(&self, request_id: &str, candidate_counter: u64) -> bool;
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

    /// The cover of one approved write (PD-56: `core::engine::write::execute` is the only
    /// caller, right before the send).
    pub fn for_write(
        &self,
        request_id: &str,
        candidate_counter: u64,
    ) -> Result<WriteCover, NotCommitted> {
        if self.probe.write_approved(request_id, candidate_counter) {
            Ok(WriteCover {
                request_id: request_id.to_owned(),
                candidate_counter,
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
