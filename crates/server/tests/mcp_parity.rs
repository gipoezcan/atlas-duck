//! T19 Step 3 (PD-193, PD-215) and M14 T13 (PD-242, SM-7.1): the server's tool list is M9's
//! `catalog(ToolSet::Full)`, filtered by scope, byte for byte, for every scope set. The rule,
//! written out here independently of the handler: write op tools and `request_cancel` need
//! `propose_write`, `script_run` needs `scripts`, every other tool needs `read`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use atlas_duck_mcp_tools::tools::{catalog, op_for_tool};
use atlas_duck_mcp_tools::toolset::ToolSet;
use atlas_duck_registry::OpClass;
use atlas_duck_server::mcp::tools_for;

fn scopes(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| (*x).to_owned()).collect()
}

/// The documented rule.
fn needs(tool: &str) -> &'static str {
    match tool {
        "script_run" => "scripts",
        "request_cancel" => "propose_write",
        t => match op_for_tool(t) {
            Some(spec) if spec.class == OpClass::Write => "propose_write",
            _ => "read",
        },
    }
}

#[test]
fn every_scope_set_serves_the_catalog_filtered_by_the_rule() {
    let all = ["read", "propose_write", "scripts"];
    for mask in 1u8..8 {
        let set: Vec<&str> = all
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, s)| *s)
            .collect();
        let want: Vec<_> = catalog(ToolSet::Full)
            .into_iter()
            .filter(|t| set.contains(&needs(&t.name)))
            .collect();
        let got = tools_for(&scopes(&set));
        assert_eq!(
            serde_json::to_string(&got).unwrap(),
            serde_json::to_string(&want).unwrap(),
            "{set:?}"
        );
        assert_eq!(
            got.iter().any(|t| t.name == "script_run"),
            set.contains(&"scripts"),
            "{set:?}"
        );
    }
    // All three scopes serve the whole catalog.
    assert_eq!(
        serde_json::to_string(&tools_for(&scopes(&all))).unwrap(),
        serde_json::to_string(&catalog(ToolSet::Full)).unwrap()
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
    assert!(!got.iter().any(|t| t.name == "script_run"));
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
