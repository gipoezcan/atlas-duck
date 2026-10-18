#![cfg(feature = "scripted-approver")]
//! `script_flows` (M8 Task 26): the real `atlas-duck`, `atlas-duck-app` and `atlas-duck-sandbox`
//! binaries on the script path (dry runs, the opacity of a run to its end, cancel in every phase,
//! the two run slots, the dispatch rule, the call paths of a script, the containment corpus and a
//! replaced worker binary), over the `cli_flows` harness. Every flow starts with
//! `harness::opted_in(..)` and skips unless `ATLAS_DUCK_CLI_FLOWS=1` (CI).
//! Run with `--test-threads=1`: a flow holds worker processes busy on purpose.

#[path = "script_flows/flows.rs"]
mod flows;
#[path = "cli_flows/harness.rs"]
pub mod harness;
