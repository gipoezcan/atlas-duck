#![cfg(feature = "scripted-approver")]
//! `confluence_flows` (M7 Task 24): the real `atlas-duck` and `atlas-duck-app` binaries on the
//! Confluence paths (the Markdown page update sent as storage, the placeholder refusal, the
//! version-conflict and attachment-collision denials, the CQL rewrite, the conversion meta of a
//! page read, the empty `204` of a label removal), over the `cli_flows` harness. Every flow starts
//! with `harness::opted_in(..)` and skips unless `ATLAS_DUCK_CLI_FLOWS=1` (CI).
//! Run with `--test-threads=2`: the GUI processes are heavy.

#[path = "confluence_flows/flows.rs"]
mod flows;
#[path = "cli_flows/harness.rs"]
pub mod harness;
