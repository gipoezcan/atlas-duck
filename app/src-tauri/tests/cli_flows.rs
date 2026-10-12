#![cfg(feature = "scripted-approver")]
//! `cli_flows` (Tasks 22-25): the real `atlas-duck` and `atlas-duck-app` binaries against a store
//! provisioned in the wizard's order, with mock Atlassian servers. Every test that spawns a
//! binary starts with `harness::opted_in(..)` and skips unless `ATLAS_DUCK_CLI_FLOWS=1` (CI).
//! Run with `--test-threads=2`: the GUI processes are heavy.

#[path = "cli_flows/harness.rs"]
pub mod harness;
// Task 23: the end-to-end flows (I-03, I-10, I-15, I-16, I-39, U-05, X-08, S-16 CLI slice).
#[path = "cli_flows/flows.rs"]
mod flows;
// Task 24: cold start and launch hygiene, gate states, data-dir and doctor cases, crash/restart,
// newer config, two instances.
#[path = "cli_flows/flows2.rs"]
mod flows2;
// Task 25: the security cases (S-01 squatter pipe, S-02 launch survival, V13 job close).
#[path = "cli_flows/security.rs"]
mod security;

use atlas_duck_audit::EventType;
use atlas_duck_registry::Product;
use harness::{KeystoreKind, Result, World, WorldOpts, instance_rows, opted_in};
use serde_json::Value;

/// The same flow for both keystores: provision one Jira instance; `atlas-duck instances`
/// cold-starts the app through the test home and lists it; quitting ends with `APP_STOP {quit}`.
async fn smoke(world: &mut World) -> Result<()> {
    world
        .provision_store(&[("jira-main", Product::Jira)])
        .await?;
    let run = world.cli(&["instances"]).await?;
    // A failure shows what the app left behind (data dir, diagnostic log, a hung app's stack).
    assert_eq!(
        run.exit,
        0,
        "stdout: {}
stderr: {}
{}",
        run.stdout,
        run.stderr,
        world.diagnostics()
    );
    let env = run.envelope.ok_or("stdout holds no envelope")?;
    let rows = instance_rows(&env);
    assert_eq!(
        rows.len(),
        1,
        "{rows:?}
{}",
        world.diagnostics()
    );
    assert_eq!(rows[0]["alias"], "jira-main");
    assert_eq!(rows[0]["product"], "jira");
    assert_eq!(rows[0]["is_default"], true);
    assert_eq!(rows[0]["state"], "ok");

    world.quit_app().await?;
    let records = world.audit_records()?;
    let (last, payload) = records.last().ok_or("the audit log is empty")?;
    assert_eq!(*last, EventType::APP_STOP);
    assert_eq!(payload["reason"], Value::from("quit"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn harness_smoke() -> Result<()> {
    if !opted_in("harness_smoke") {
        return Ok(());
    }
    let mut world = World::new(WorldOpts::default())?;
    smoke(&mut world).await
}

/// The same flow against the real OS keychain under a `7e570000` test install id; the world's
/// drop deletes every entry it wrote. CI only. Every entry is written and read by the app
/// executable (the harness provisions through `atlas-duck-app __test-os-keystore`), as in
/// production: on macOS an item another executable created would make the app wait on a
/// confirmation prompt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI: OS keychain step"]
async fn os_keychain_smoke() -> Result<()> {
    if !opted_in("os_keychain_smoke") {
        return Ok(());
    }
    let mut world = World::new(WorldOpts {
        keystore: KeystoreKind::Os,
        ..WorldOpts::default()
    })?;
    smoke(&mut world).await
}
