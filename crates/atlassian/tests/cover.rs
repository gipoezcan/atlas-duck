//! The write-scoped cover (Δ6, M3 final review M-18, PD-56): a `WriteCover` exists only for a
//! committed `WRITE_APPROVED` of exactly that revision of that write (§5.1 inv. 1 and 3).
//!
//! The compile-time half (`request_cover_is_not_a_write_cover`: an `AuditCover` handed to
//! `send_approved` does not compile; `write_cover_is_used_once`: a cover cannot be sent twice; no
//! `WriteCover` literal outside `cover.rs`; not `Clone`) is the `compile_fail` doctests on
//! `InstanceClient::send_approved` and on `WriteCover`. Inside the crate every send target carries
//! the proof of its own kind (`client/send.rs` `Target`); the binding of a cover to the write it
//! sends is `tests/writes.rs` `m18_write_cover_is_bound_to_its_write`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use atlas_duck_atlassian::{CommitProbe, CoverIssuer, NotCommitted};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Committed start records and, per write, the counter of its committed approval.
#[derive(Default)]
struct Probe {
    requests: Mutex<HashSet<String>>,
    approvals: Mutex<HashMap<String, u64>>,
}

impl Probe {
    fn approve(&self, request_id: &str, counter: u64) {
        if let Ok(mut m) = self.approvals.lock() {
            m.insert(request_id.to_owned(), counter);
        }
    }

    fn start(&self, request_id: &str) {
        if let Ok(mut s) = self.requests.lock() {
            s.insert(request_id.to_owned());
        }
    }
}

impl CommitProbe for Probe {
    fn request_committed(&self, request_id: &str) -> bool {
        self.requests
            .lock()
            .map(|s| s.contains(request_id))
            .unwrap_or(false)
    }
    fn system_fetch_started(&self, _: &str) -> bool {
        false
    }
    fn write_approved(&self, request_id: &str, candidate_counter: u64) -> bool {
        self.approvals
            .lock()
            .map(|m| m.get(request_id) == Some(&candidate_counter))
            .unwrap_or(false)
    }
}

#[test]
fn m18_write_cover_requires_committed_approval() -> TestResult {
    let probe = Arc::new(Probe::default());
    let issuer = CoverIssuer::new(probe.clone());
    assert_eq!(issuer.for_write("req_a", 3).err(), Some(NotCommitted));

    // A committed start record is a request cover, never a write cover.
    probe.start("req_a");
    assert!(issuer.for_request("req_a").is_ok());
    assert_eq!(issuer.for_write("req_a", 3).err(), Some(NotCommitted));

    probe.approve("req_a", 3);
    let cover = issuer.for_write("req_a", 3)?;
    assert_eq!(cover.request_id(), "req_a");
    assert_eq!(cover.candidate_counter(), 3);
    assert_eq!(format!("{cover:?}"), "WriteCover(req_a, 3)");
    // An approval covers only its own write.
    assert_eq!(issuer.for_write("req_b", 3).err(), Some(NotCommitted));
    Ok(())
}

#[test]
fn m18_stale_revision_cover_refused() -> TestResult {
    let probe = Arc::new(Probe::default());
    let issuer = CoverIssuer::new(probe.clone());
    probe.start("req_a");
    probe.approve("req_a", 3);
    assert_eq!(issuer.for_write("req_a", 4).err(), Some(NotCommitted));
    assert_eq!(issuer.for_write("req_a", 2).err(), Some(NotCommitted));
    assert!(issuer.for_write("req_a", 3).is_ok());

    // A later approval supersedes the earlier revision's.
    probe.approve("req_a", 5);
    assert_eq!(issuer.for_write("req_a", 3).err(), Some(NotCommitted));
    assert!(issuer.for_write("req_a", 5).is_ok());
    Ok(())
}

/// The probe of every other kind answers `false` for writes it was not told about.
#[test]
fn write_cover_probe_is_separate_from_start_records() -> TestResult {
    struct StartsOnly;
    impl CommitProbe for StartsOnly {
        fn request_committed(&self, _: &str) -> bool {
            true
        }
        fn system_fetch_started(&self, _: &str) -> bool {
            true
        }
        fn write_approved(&self, _: &str, _: u64) -> bool {
            false
        }
    }
    let issuer = CoverIssuer::new(Arc::new(StartsOnly));
    assert!(issuer.for_request("req_a").is_ok());
    assert!(issuer.for_system_fetch("fetch_a").is_ok());
    assert_eq!(issuer.for_write("req_a", 1).err(), Some(NotCommitted));
    Ok(())
}
