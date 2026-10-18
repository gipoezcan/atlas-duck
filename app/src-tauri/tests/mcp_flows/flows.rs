//! `mcp_flows` (M9 Task 13): the smoke flow of the real `atlas-duck mcp` over the stdio driver.
//! The end-to-end flows follow in Task 14.
//!
//! Every flow spawns a binary and therefore starts with [`opted_in`]: it skips unless
//! `ATLAS_DUCK_CLI_FLOWS=1` (CI).

use atlas_duck_registry::Product;
use serde_json::json;

use crate::driver::McpChild;
use crate::harness::{PAT_CANARY, Result, World, WorldOpts, opted_in};

/// The number of tools of the full set: one per registry op plus `script_run`, `request_await`,
/// `request_status`, `request_cancel`, `request_list`, `ops_list`, `ops_describe` and
/// `instances_list`.
const FULL_TOOL_COUNT: usize = 54;

/// One Jira instance `jira-main`; the first tool call cold-starts the app through the test home.
async fn jira_world() -> Result<World> {
    let mut world = World::new(WorldOpts::default())?;
    world
        .provision_store(&[("jira-main", Product::Jira)])
        .await?;
    Ok(world)
}

/// Spawns `atlas-duck mcp` and completes the handshake.
async fn mcp_client(world: &World, client_name: &str) -> Result<McpChild> {
    let mut mcp = McpChild::new(world.mcp_spawn(&["mcp"], &[])?)?;
    mcp.initialize(client_name).await?;
    Ok(mcp)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_flows_smoke() -> Result<()> {
    if !opted_in("mcp_flows_smoke") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mut mcp = mcp_client(&world, "mcp-flows").await?;

    let tools = mcp.list_tools().await?;
    assert_eq!(tools.len(), FULL_TOOL_COUNT, "{}", mcp.transcript());

    let call = mcp
        .call(
            "jira_issue_get",
            json!({"key": "ABC-1", "reason": "atlas-test:release"}),
            None,
        )
        .await?;
    assert!(!call.is_error(), "{}", mcp.transcript());
    assert_eq!(
        call.structured()["status"],
        "released",
        "{}",
        mcp.transcript()
    );
    for line in mcp.raw_stdout_lines() {
        assert!(!line.contains(PAT_CANARY), "the PAT canary is on stdout");
    }

    // End of input: the server ends by itself, with success.
    mcp.close_stdin();
    let status = mcp.wait_exit().await?;
    assert!(status.success(), "{status}\n{}", mcp.transcript());
    world.quit_app().await?;
    Ok(())
}
