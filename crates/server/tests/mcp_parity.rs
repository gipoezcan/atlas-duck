//! T19 Step 3 (PD-193, PD-215, L224): the server's tool list is M9's catalog, filtered by scope.
//! `read + propose_write` serves `catalog(ToolSet::Full)` minus `script_run`, byte for byte;
//! `read` serves the read op tools and the six read fixed tools.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use atlas_duck_mcp_tools::tools::{catalog, op_for_tool};
use atlas_duck_mcp_tools::toolset::ToolSet;
use atlas_duck_registry::OpClass;
use atlas_duck_server::mcp::tools_for;

fn scopes(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| (*x).to_owned()).collect()
}

#[test]
fn read_and_propose_write_serve_the_full_catalog_without_script_run() {
    let want: Vec<_> = catalog(ToolSet::Full)
        .into_iter()
        .filter(|t| t.name != "script_run")
        .collect();
    let got = tools_for(&scopes(&["read", "propose_write"]));
    assert_eq!(
        serde_json::to_string(&got).unwrap(),
        serde_json::to_string(&want).unwrap()
    );
    // `scripts` lists nothing more before M14.
    let with_scripts = tools_for(&scopes(&["read", "propose_write", "scripts"]));
    assert_eq!(
        serde_json::to_string(&with_scripts).unwrap(),
        serde_json::to_string(&want).unwrap()
    );
}

#[test]
fn read_serves_the_read_subset() {
    let fixed = [
        "request_await",
        "request_status",
        "request_list",
        "ops_list",
        "ops_describe",
        "instances_list",
    ];
    let want: Vec<_> = catalog(ToolSet::Full)
        .into_iter()
        .filter(|t| match op_for_tool(&t.name) {
            Some(spec) => spec.class != OpClass::Write,
            None => fixed.contains(&t.name.as_ref()),
        })
        .collect();
    let got = tools_for(&scopes(&["read"]));
    assert_eq!(
        serde_json::to_string(&got).unwrap(),
        serde_json::to_string(&want).unwrap()
    );
    assert!(!got.iter().any(|t| t.name == "request_cancel"));
}

#[test]
fn no_tool_decides() {
    // SM-3.4: agents never approve; the catalog has no decision tool for any scope set.
    for t in tools_for(&scopes(&["read", "propose_write", "scripts"])) {
        for word in ["decide", "approve", "release", "reject"] {
            assert!(!t.name.contains(word), "{}", t.name);
        }
    }
}
