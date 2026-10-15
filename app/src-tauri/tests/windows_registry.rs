//! M6 T6 (§2.5, §10.3): the window registry and the run-loop handler under Tauri's mock runtime
//! (no OS window). These live here, not in the lib's unit tests, because only integration-test
//! executables get the Common-Controls v6 manifest the mock runtime needs on Windows (`build.rs`).

type TestResult = Result<(), Box<dyn std::error::Error>>;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use atlas_duck_app_lib::credential::Purpose;
use atlas_duck_app_lib::credential::raise::{raise_window, raise_window_with};
use atlas_duck_app_lib::state::DataDirHold;
use atlas_duck_app_lib::tray::on_run_event;
use atlas_duck_app_lib::windows::{
    Label, NavPolicy, Relaunch, Show, StartupRoute, Unlock, WindowError, WindowRegistry, open,
    open_credential,
};
use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_ipc::paths::{DataDirResolution, LocalDataDir, check_data_dir};
use tauri::test::{MockRuntime, mock_builder};
use tauri::{App, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent};

fn local_data_dir(tmp: &tempfile::TempDir) -> Result<LocalDataDir, Box<dyn std::error::Error>> {
    match check_data_dir(tmp.path())? {
        DataDirResolution::Local(data) => Ok(data),
        _ => Err("the temp dir is not a local data dir".into()),
    }
}

fn app() -> Result<App<MockRuntime>, Box<dyn std::error::Error>> {
    let context = tauri::generate_context!(assets = tauri::test::noop_assets(), test = true);
    Ok(mock_builder().build(context)?)
}

/// `open` builds a window once, under its fixed label, and shows it afterwards; the credential
/// window's purpose is set by Rust.
#[test]
fn open_builds_once_under_the_fixed_label() -> TestResult {
    let app = app()?;
    let handle = app.handle();
    assert_eq!(
        open(handle, Label::Approvals, Show::Focus),
        Err(WindowError::NotRegistered)
    );
    app.manage(WindowRegistry::new(
        NavPolicy::for_this_platform(None),
        StartupRoute::completed(),
    ));
    assert_eq!(open(handle, Label::Settings, Show::Focus), Ok(()));
    assert!(handle.get_webview_window("settings").is_some());
    assert_eq!(
        open(handle, Label::Settings, Show::WithoutActivating),
        Ok(())
    );
    assert_eq!(handle.webview_windows().len(), 1, "built once");
    // The credential window has its own webview data dir: it needs the locked data dir (T6).
    let tmp = tempfile::tempdir()?;
    let data = local_data_dir(&tmp)?;
    let lock = Arc::new(InstanceLock::acquire(&data, "testhost")?);
    app.manage(DataDirHold::new(data, lock));
    assert_eq!(
        open_credential(handle, Unlock::Recover, Show::Focus),
        Ok(())
    );
    assert!(handle.get_webview_window("credential").is_some());
    assert_eq!(
        handle
            .try_state::<WindowRegistry>()
            .and_then(|r| r.credential_purpose()),
        Some(Purpose::RecoverThisLog)
    );
    let labels: Vec<String> = handle.webview_windows().into_keys().collect();
    for label in &labels {
        assert!(
            Label::from_label(label).is_some(),
            "unexpected label {label}"
        );
    }
    Ok(())
}

/// M6 T22 review I-1: the locked / first-run re-raise never shows a window that exists (hidden:
/// on Windows `show()` activates it, and an agent decides when a refused request lands); one that is
/// not built yet is built unfocused. The mock runtime has no visibility to observe, so the test counts
/// the calls that would build or show.
#[test]
fn the_re_raise_never_shows_a_window_that_exists() -> TestResult {
    let app = app()?;
    let handle = app.handle();
    app.manage(WindowRegistry::new(
        NavPolicy::for_this_platform(None),
        StartupRoute::completed(),
    ));
    let calls = std::cell::Cell::new(0);
    // A window that does not exist yet is built.
    raise_window_with(handle, Relaunch::OpenSetup, |_| calls.set(calls.get() + 1));
    assert_eq!(calls.get(), 1);

    assert_eq!(open(handle, Label::Setup, Show::Focus), Ok(()));
    handle
        .get_webview_window("setup")
        .ok_or("the setup window was not built")?
        .hide()?;
    // One that exists (the user closed the wizard: hidden) is not shown again.
    raise_window_with(handle, Relaunch::OpenSetup, |_| calls.set(calls.get() + 1));
    assert_eq!(calls.get(), 1, "a hidden window is not shown again");
    // An action that opens no window touches nothing.
    raise_window_with(handle, Relaunch::Nothing, |_| calls.set(calls.get() + 1));
    assert_eq!(calls.get(), 1);
    // The real builder is the one that builds.
    let tmp = tempfile::tempdir()?;
    let data = local_data_dir(&tmp)?;
    let lock = Arc::new(InstanceLock::acquire(&data, "testhost")?);
    app.manage(DataDirHold::new(data, lock));
    raise_window(handle, Relaunch::OpenCredential(Unlock::Recover));
    assert!(handle.get_webview_window("credential").is_some());
    Ok(())
}

/// Without a locked data dir (before first run) the credential window is refused and no window is
/// built; it never falls back to the default webview folder.
#[test]
fn credential_without_a_data_dir_is_refused() -> TestResult {
    let app = app()?;
    let handle = app.handle();
    app.manage(WindowRegistry::new(
        NavPolicy::for_this_platform(None),
        StartupRoute::completed(),
    ));
    assert_eq!(
        open_credential(handle, Unlock::Recover, Show::Focus),
        Err(WindowError::NoDataDir)
    );
    assert!(handle.get_webview_window("credential").is_none());
    assert!(handle.webview_windows().is_empty(), "no window built");
    Ok(())
}

/// Runs the mock runtime's event loop with `on_run_event` and closes `label`'s window: the trace
/// of what happened and whether the window survived the close.
fn close_under_the_run_loop(
    label: &'static str,
) -> Result<(Vec<&'static str>, bool), Box<dyn std::error::Error>> {
    let app = app()?;
    WebviewWindowBuilder::new(&app, label, WebviewUrl::default()).build()?;
    let trace: Rc<RefCell<Vec<&'static str>>> = Rc::default();
    let survived = Rc::new(RefCell::new(false));
    let (t, s) = (trace.clone(), survived.clone());
    app.run_return(move |handle, event| match event {
        RunEvent::Ready => {
            t.borrow_mut().push("ready");
            if let Some(w) = handle.get_webview_window(label) {
                let _ = w.close();
            }
        }
        event @ RunEvent::WindowEvent { .. } => {
            if matches!(
                &event,
                RunEvent::WindowEvent {
                    event: WindowEvent::CloseRequested { .. },
                    ..
                }
            ) {
                t.borrow_mut().push("close_requested");
            }
            on_run_event(handle, event);
        }
        RunEvent::MainEventsCleared => {
            let mut t = t.borrow_mut();
            if t.last() == Some(&"close_requested") {
                // The close was handled and no exit was requested: the loop goes on. End the run
                // by destroying the (hidden) window.
                t.push("still_running");
                *s.borrow_mut() = handle.get_webview_window(label).is_some();
                if let Some(w) = handle.get_webview_window(label) {
                    let _ = w.destroy();
                }
            }
        }
        // Not forwarded, so the loop can end (`on_run_event` prevents a code-less exit request:
        // `tray::tests::exit_is_prevented_only_without_code`).
        RunEvent::ExitRequested { .. } => t.borrow_mut().push("exit_requested"),
        _ => {}
    });
    let trace = trace.borrow().clone();
    let survived = *survived.borrow();
    Ok((trace, survived))
}

/// §2.5 "Closing windows hides them": closing the only window does not end the run (no exit
/// request follows the close); the credential window is destroyed instead of hidden (§10.1), and
/// the code-less exit request that follows is the one `on_run_event` prevents.
#[test]
fn close_hides_never_exits_under_the_run_loop() -> TestResult {
    let (trace, survived) = close_under_the_run_loop("approvals")?;
    assert_eq!(
        trace,
        [
            "ready",
            "close_requested",
            "still_running",
            "exit_requested"
        ]
    );
    assert!(survived, "the closed window still exists (hidden)");

    let (trace, _) = close_under_the_run_loop("credential")?;
    assert_eq!(trace, ["ready", "close_requested", "exit_requested"]);
    Ok(())
}
