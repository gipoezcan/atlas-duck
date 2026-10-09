//! `core::testing` (feature `testing`, never in a release build): a real audit store in a temp
//! dir and the append-fault wrapper (X-04). Later tasks add the scripted approver, the stub
//! confirmer, credentials, the capture hook and the harness.

pub mod store;

pub use store::{FaultPlan, FaultyAudit, TempStore};
