#![cfg(feature = "scripted-approver")]
//! `script_fixture` (M8 Task 28, CI-04 and CI-07): provisions a test home for the packaged-app
//! script runs of `ci/appimage-smoke.sh --m8`. A shell step cannot do it: the store, one Jira
//! instance and its PAT are created in process, in the wizard's order, by the `cli_flows`
//! harness. The test is `#[ignore]`d (a plain `cargo test` never runs it) and CI runs it by exact
//! name; it is built in the `bundle-linux-e2e` job and shipped with that artifact.
//!
//! `ATLAS_DUCK_FIXTURE_OUT` names the file that receives three lines, `home=<ATLAS_DUCK_TEST_HOME>`,
//! `keys=<ATLAS_DUCK_TEST_KEYSTORE>` and `export=<a no-trust-root export directory>`. Without the
//! variable the test fails (it never skips).
//! The test home is a fresh directory the harness creates under `/tmp` and this test keeps.
//!
//! The Jira mock lives only while this process runs. The instance stays in the store with the
//! mock's (then dead) address: the script runs of the packaged-app section make no Jira call
//! (`return {n: 1 + 1};`), so they need a configured, serving core and nothing else.

#[path = "cli_flows/harness.rs"]
pub mod harness;

use std::time::Duration;

use atlas_duck_audit::testing::{FixtureKind, export_fixture};
use atlas_duck_registry::Product;
use harness::{Result, World, WorldOpts};

/// Provisioning needs well under a minute; the bound keeps a stuck step from hanging CI.
const PROVISION_BOUND: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI fixture for ci/appimage-smoke.sh --m8; needs ATLAS_DUCK_FIXTURE_OUT"]
async fn provision_script_fixture() -> Result<()> {
    let out = std::env::var_os("ATLAS_DUCK_FIXTURE_OUT")
        .filter(|v| !v.is_empty())
        .ok_or(
            "ATLAS_DUCK_FIXTURE_OUT is not set: it names the file that receives home= and keys=",
        )?;
    let mut world = World::new(WorldOpts::default())?;
    tokio::time::timeout(
        PROVISION_BOUND,
        world.provision_store(&[("jira", Product::Jira)]),
    )
    .await
    .map_err(|_| format!("provisioning did not finish within {PROVISION_BOUND:?}"))??;
    if world.instance_ids().len() != 1 {
        return Err(format!(
            "expected one provisioned instance, got {:?}",
            world.instance_ids()
        )
        .into());
    }
    // M10 Task 31 (V14, S-03): a compliance export that verifies only without a trust root, for
    // `appimage-smoke.sh --m10` (`atlas-duck verify-export <dir>` exits 20 on it). Written inside
    // the test home, which the section deletes with the rest.
    let export_parent = world.root().join("export-fixture");
    std::fs::create_dir(&export_parent)?;
    let export = export_fixture(FixtureKind::NoTrustRoot, &export_parent)?;
    if export.expected_exit != 20 {
        return Err(format!(
            "the no-trust-root fixture expects exit {}, not 20",
            export.expected_exit
        )
        .into());
    }
    let text = format!(
        "home={}\nkeys={}\nexport={}\n",
        world.root().display(),
        world.keys_dir().display(),
        export.dir.display()
    );
    std::fs::write(&out, &text)?;
    println!("script_fixture {}", text.replace('\n', " "));
    // Keep the test home: dropping the world would delete the temp root the app is to use.
    std::mem::forget(world);
    Ok(())
}
