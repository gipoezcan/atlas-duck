#![cfg(feature = "scripted-approver")]
//! `mcp_flows` (M9 Tasks 13-14): the real `atlas-duck mcp` and `atlas-duck-app` binaries, driven
//! over stdio by an in-house JSON-RPC driver, over the `cli_flows` harness. Every flow starts with
//! `harness::opted_in(..)` and skips unless `ATLAS_DUCK_CLI_FLOWS=1` (CI).
//! Run with `--test-threads=2`: the GUI processes are heavy.

#[path = "mcp_flows/conformance.rs"]
mod conformance;
#[path = "mcp_flows/driver.rs"]
mod driver;
#[path = "mcp_flows/flows.rs"]
mod flows;
#[path = "cli_flows/harness.rs"]
pub mod harness;
// Process facts and Toolhelp/job helpers, shared with `cli_flows` (S-02).
#[path = "cli_flows/procs.rs"]
mod procs;
// Task 16: the S-02 cases for `atlas-duck mcp` (stdout, parent, no console, tree kill; V13).
#[path = "mcp_flows/security.rs"]
mod security;
