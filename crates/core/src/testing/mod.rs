//! `core::testing` (feature `testing`, never in a release build): a real audit store in a temp
//! dir and the append-fault wrapper (X-04), the stub confirmer, in-memory credentials, the
//! capture hook (PD-12), the scripted approver (filled in Tasks 21–23), the converter fault
//! (PD-64) and the `Harness` that starts a `Core` over all of them.

pub mod approver;
pub mod capture;
pub mod confirmer;
pub mod credentials;
pub mod fault;
pub mod flows;
pub mod harness;
pub mod runner;
pub mod store;

pub use approver::ScriptedApprover;
pub use capture::{Capture, Captured, Channel};
pub use confirmer::{ConfirmHook, StubConfirmer};
pub use credentials::InMemoryCredentials;
pub use fault::ConverterFault;
pub use flows::Flow;
pub use harness::{
    AuditRecord, HARNESS_AGENT, Harness, HarnessBuilder, HarnessInstance, InstanceAt, JIRA_FIELDS,
    NoProgress,
};
pub use runner::{FakeScriptRunner, ScriptPlan, host_call};
pub use store::{FaultPlan, FaultyAudit, Freeze, ReadFault, RecordedEvent, TempStore};

/// `audit_port::commit_records` for tests: crate-private outside `testing`, so no code outside
/// `core` can mark a write approval in a committed set (T20 review m3).
pub fn commit_records(
    port: &dyn crate::audit_port::AuditPort,
    set: &crate::audit_port::CommittedSet,
    evs: Vec<atlas_duck_audit::NewEvent>,
) -> Result<Vec<atlas_duck_audit::Committed>, atlas_duck_audit::AuditError> {
    crate::audit_port::commit_records(port, set, evs)
}
