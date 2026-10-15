#![cfg(feature = "scripted-approver")]
//! `e2e` (M6 Task 32): the real `atlas-duck-app` debug build (the `scripted-approver` feature) driven
//! through `tauri-driver` (W3C WebDriver, `msedgedriver` on Windows, `WebKitWebDriver` on Linux),
//! with the real `atlas-duck` CLI against it: UI-06, the webview halves of S-06 to S-09, the first
//! screen of P-01 and the Windows `WM_QUERYENDSESSION` run (I-40).
//!
//! Every flow starts with `harness::opted_in(..)` and skips unless `ATLAS_DUCK_CLI_FLOWS=1` (CI
//! only; it is never set on a developer machine, where nothing here spawns a process or opens a
//! socket). The CI job also sets `ATLAS_DUCK_TAURI_DRIVER` (the `tauri-driver` executable) and, on
//! Windows, `ATLAS_DUCK_E2E_NATIVE_DRIVER` (`msedgedriver.exe`). Run with `--test-threads=1`: each
//! flow owns a desktop window or three.
//!
//! The WebDriver "execute script" endpoint is not used anywhere (`webdriver.rs` has no method for
//! it): no script is injected into a webview of the app, even in a test.

#[path = "cli_flows/harness.rs"]
pub mod harness;

#[path = "e2e/flows.rs"]
mod flows;
#[path = "e2e/webdriver.rs"]
mod webdriver;
