#![cfg(feature = "scripted-approver")]
//! `jira_flows` (M5 Task 23): the real `atlas-duck` and `atlas-duck-app` binaries on the new Jira
//! paths (the comment body conversion, the create's missing-field edit, the deny hints, the
//! empty `201` of `issuelink`, the 50-issue move limit), over the `cli_flows` harness. Every flow
//! starts with `harness::opted_in(..)` and skips unless `ATLAS_DUCK_CLI_FLOWS=1` (CI).
//! Run with `--test-threads=2`: the GUI processes are heavy.

#[path = "jira_flows/flows.rs"]
mod flows;
#[path = "cli_flows/harness.rs"]
pub mod harness;
