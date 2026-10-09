//! `core::testing` (feature `testing`, never in a release build): a real audit store in a temp
//! dir and the append-fault wrapper (X-04), the stub confirmer, in-memory credentials, the
//! capture hook (PD-12), the scripted approver (filled in Tasks 21–23) and the `Harness` that
//! starts a `Core` over all of them.

pub mod approver;
pub mod capture;
pub mod confirmer;
pub mod credentials;
pub mod harness;
pub mod store;

pub use approver::ScriptedApprover;
pub use capture::{Capture, Captured, Channel};
pub use confirmer::{ConfirmHook, StubConfirmer};
pub use credentials::InMemoryCredentials;
pub use harness::{
    HARNESS_AGENT, Harness, HarnessBuilder, HarnessInstance, InstanceAt, NoProgress,
};
pub use store::{FaultPlan, FaultyAudit, RecordedEvent, TempStore};
