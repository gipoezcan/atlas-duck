//! PD-03 / PD-35: the test build's control dir `<data>/test-control/`, polled every 100 ms.
//!
//! - `quit` (any content): the §2.5 shutdown path with `ShutdownReason::Quit`, once
//!   (`serve::shutdown_then_exit`, which also ends the process).
//! - `env-names.json` (written at start): the sorted **names** of the app's environment
//!   variables, never their values (I-20).
//! - `refused` (written on change): the kept gate handler's refused count (PD-35), or `none`
//!   while `Core` serves or before anything serves.
//! - `delay-startup-ms` (read by `serve::start` before the first `open`): sleep that many
//!   milliseconds, at most 30 000 (I-17's deadline test).
//! - `marker-handle` → `marker` (Windows, V12): the `WaitForSingleObject(handle, 0)` result of
//!   the handle value in `marker-handle`: `signaled`, `invalid` or `other`.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use atlas_duck_core::ShutdownReason;
use atlas_duck_ipc::paths::LocalDataDir;
use atlas_duck_ipc::server::ShutdownSignal;
use tauri::{AppHandle, Manager};
use tokio::task::JoinHandle;

use super::keystore::write_atomic;
use crate::serve;
use crate::state::ServeSlot;

/// `<data>/<CONTROL_DIR>`.
pub const CONTROL_DIR: &str = "test-control";
pub const QUIT_FILE: &str = "quit";
pub const ENV_NAMES_FILE: &str = "env-names.json";
pub const REFUSED_FILE: &str = "refused";
pub const DELAY_STARTUP_FILE: &str = "delay-startup-ms";
pub const MARKER_HANDLE_FILE: &str = "marker-handle";
pub const MARKER_FILE: &str = "marker";

/// The `refused` content while no gate handler serves.
pub const REFUSED_NONE: &str = "none";
/// How often the control dir is read.
pub const POLL: Duration = Duration::from_millis(100);
/// The cap of `delay-startup-ms`.
pub const MAX_STARTUP_DELAY: Duration = Duration::from_secs(30);

pub const LOG_EVENT_CONTROL_FAILED: &str = "test_control_failed";

/// What the control dir acts on; the app's is [`AppControl`], tests count.
pub trait ControlHost: Send + Sync {
    /// PD-35: `ServeState::refused()` of the state being served, `None` without one.
    fn refused(&self) -> Option<u64>;
    /// Runs the shutdown path; called once.
    fn quit(&self);
}

/// The app: the state in the managed `ServeSlot`, and `serve::shutdown_then_exit` (the same
/// single quit run as the tray's Quit).
pub struct AppControl(pub AppHandle);

impl ControlHost for AppControl {
    fn refused(&self) -> Option<u64> {
        let slot = self.0.try_state::<ServeSlot>()?;
        slot.get()?.refused()
    }

    fn quit(&self) {
        serve::shutdown_then_exit(&self.0, ShutdownReason::Quit);
    }
}

pub struct Control;

impl Control {
    /// The app's control dir watcher on the async runtime.
    pub fn spawn(data: LocalDataDir, app: AppHandle) {
        let dir = data.path().join(CONTROL_DIR);
        tauri::async_runtime::spawn(run(dir, Arc::new(AppControl(app)), POLL));
    }

    /// The seam: watches `dir` for `host` every `poll` on the current tokio runtime.
    pub fn spawn_with(dir: PathBuf, host: Arc<dyn ControlHost>, poll: Duration) -> JoinHandle<()> {
        tokio::spawn(run(dir, host, poll))
    }
}

async fn run(dir: PathBuf, host: Arc<dyn ControlHost>, poll: Duration) {
    if fs::create_dir_all(&dir).is_err() || write_env_names(&dir).is_err() {
        tracing::warn!(event = LOG_EVENT_CONTROL_FAILED, reason = "env_names");
    }
    let mut quit_sent = false;
    let mut refused_written: Option<Option<u64>> = None;
    let mut marker_written = false;
    loop {
        if !quit_sent && dir.join(QUIT_FILE).exists() {
            quit_sent = true;
            host.quit();
        }
        let refused = host.refused();
        if refused_written != Some(refused) {
            let text = refused.map_or_else(|| REFUSED_NONE.to_owned(), |n| n.to_string());
            if write_atomic(&dir, REFUSED_FILE, text.as_bytes()).is_ok() {
                refused_written = Some(refused);
            } else {
                tracing::warn!(event = LOG_EVENT_CONTROL_FAILED, reason = "refused");
            }
        }
        if !marker_written && let Some(text) = read_marker_handle(&dir) {
            marker_written = write_atomic(&dir, MARKER_FILE, text.as_bytes()).is_ok();
        }
        tokio::time::sleep(poll).await;
    }
}

/// `env-names.json`: a JSON array of the sorted, distinct variable names (lossy UTF-8).
fn write_env_names(dir: &Path) -> io::Result<()> {
    let names: BTreeSet<String> = std::env::vars_os()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    let json = serde_json::to_vec(&names).map_err(io::Error::other)?;
    write_atomic(dir, ENV_NAMES_FILE, &json)
}

/// The `marker` text for the handle value in `marker-handle`; `None` without a number.
fn read_marker_handle(dir: &Path) -> Option<&'static str> {
    let text = fs::read_to_string(dir.join(MARKER_HANDLE_FILE)).ok()?;
    let value: usize = text.trim().parse().ok()?;
    marker_for(value)
}

/// V12: whether a handle value is open in this process. `WaitForSingleObject` with a zero
/// timeout only queries the object.
#[cfg(windows)]
fn marker_for(value: usize) -> Option<&'static str> {
    use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    let handle = value as HANDLE;
    // SAFETY: a zero-timeout wait never blocks and reads nothing through the value; an invalid
    // handle value fails with `WAIT_FAILED`.
    let r = unsafe { WaitForSingleObject(handle, 0) };
    Some(match r {
        WAIT_OBJECT_0 => "signaled",
        WAIT_FAILED => "invalid",
        _ => "other",
    })
}

/// V12 is a Windows check: elsewhere nothing is written.
#[cfg(not(windows))]
fn marker_for(_value: usize) -> Option<&'static str> {
    None
}

/// The delay `delay-startup-ms` asks for: a decimal number of milliseconds, capped at
/// [`MAX_STARTUP_DELAY`]; anything else is no delay.
pub fn startup_delay_of(text: &str) -> Option<Duration> {
    let ms: u64 = text.trim().parse().ok()?;
    Some(Duration::from_millis(ms).min(MAX_STARTUP_DELAY))
}

/// `serve::start`'s hook: sleeps what `<data>/test-control/delay-startup-ms` asks for, ended
/// early by Quit.
pub async fn startup_delay(data: &LocalDataDir, quit: &ShutdownSignal) {
    let path = data.path().join(CONTROL_DIR).join(DELAY_STARTUP_FILE);
    let Some(delay) = fs::read_to_string(path)
        .ok()
        .and_then(|t| startup_delay_of(&t))
    else {
        return;
    };
    tokio::select! {
        biased;
        () = quit.0.cancelled() => {}
        () = tokio::time::sleep(delay) => {}
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Instant;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const FAST: Duration = Duration::from_millis(10);
    const WAIT: Duration = Duration::from_secs(10);

    #[derive(Default)]
    struct Counting {
        quits: AtomicU32,
        refused: Mutex<Option<u64>>,
    }

    impl ControlHost for Counting {
        fn refused(&self) -> Option<u64> {
            *self.refused.lock().unwrap_or_else(|e| e.into_inner())
        }
        fn quit(&self) {
            self.quits.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn wait_for(what: &str, mut ok: impl FnMut() -> bool) -> TestResult {
        let started = Instant::now();
        while !ok() {
            if started.elapsed() > WAIT {
                return Err(format!("timed out waiting for {what}").into());
            }
            tokio::time::sleep(FAST).await;
        }
        Ok(())
    }

    fn read(dir: &Path, name: &str) -> String {
        fs::read_to_string(dir.join(name)).unwrap_or_default()
    }

    #[tokio::test]
    async fn control_quit_runs_shutdown() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join(CONTROL_DIR);
        let host = Arc::new(Counting::default());
        let task = Control::spawn_with(dir.clone(), host.clone(), FAST);
        wait_for("the control dir", || dir.join(ENV_NAMES_FILE).exists()).await?;
        tokio::time::sleep(FAST * 5).await;
        assert_eq!(
            host.quits.load(Ordering::SeqCst),
            0,
            "no quit file, no quit"
        );

        fs::write(dir.join(QUIT_FILE), b"")?;
        wait_for("quit", || host.quits.load(Ordering::SeqCst) > 0).await?;
        // The file stays; the shutdown path runs once.
        tokio::time::sleep(FAST * 10).await;
        assert_eq!(host.quits.load(Ordering::SeqCst), 1);
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn env_names_are_names_only() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join(CONTROL_DIR);
        let task = Control::spawn_with(dir.clone(), Arc::new(Counting::default()), FAST);
        wait_for("env-names.json", || dir.join(ENV_NAMES_FILE).exists()).await?;
        task.abort();
        let v: serde_json::Value = serde_json::from_str(&read(&dir, ENV_NAMES_FILE))?;
        let names = v.as_array().ok_or("not a JSON array")?;
        let mut strings = Vec::new();
        for n in names {
            let s = n.as_str().ok_or("not a string")?;
            assert!(!s.contains('='), "a value leaked: {s}");
            strings.push(s.to_owned());
        }
        let mut sorted = strings.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(strings, sorted, "sorted and distinct");
        // The test process has a PATH (`Path` on Windows); its value is never written.
        let path_name = std::env::vars_os()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .find(|k| k.eq_ignore_ascii_case("PATH"))
            .ok_or("no PATH")?;
        assert!(strings.contains(&path_name));
        let path_value = std::env::var(&path_name)?;
        if !path_value.is_empty() {
            assert!(!read(&dir, ENV_NAMES_FILE).contains(&path_value));
        }
        Ok(())
    }

    #[tokio::test]
    async fn refused_counter_is_mirrored_on_change() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join(CONTROL_DIR);
        let host = Arc::new(Counting::default());
        let task = Control::spawn_with(dir.clone(), host.clone(), FAST);
        wait_for("refused = none", || {
            read(&dir, REFUSED_FILE) == REFUSED_NONE
        })
        .await?;
        *host.refused.lock().unwrap_or_else(|e| e.into_inner()) = Some(0);
        wait_for("refused = 0", || read(&dir, REFUSED_FILE) == "0").await?;
        *host.refused.lock().unwrap_or_else(|e| e.into_inner()) = Some(3);
        wait_for("refused = 3", || read(&dir, REFUSED_FILE) == "3").await?;
        // Core serves: no gate count.
        *host.refused.lock().unwrap_or_else(|e| e.into_inner()) = None;
        wait_for("refused = none", || {
            read(&dir, REFUSED_FILE) == REFUSED_NONE
        })
        .await?;
        task.abort();
        Ok(())
    }

    #[test]
    fn startup_delay_values() {
        assert_eq!(startup_delay_of("250"), Some(Duration::from_millis(250)));
        assert_eq!(startup_delay_of(" 250\n"), Some(Duration::from_millis(250)));
        assert_eq!(startup_delay_of("0"), Some(Duration::ZERO));
        assert_eq!(startup_delay_of("30000"), Some(MAX_STARTUP_DELAY));
        assert_eq!(startup_delay_of("999999999"), Some(MAX_STARTUP_DELAY));
        for bad in ["", "-5", "1.5", "soon", "250ms"] {
            assert_eq!(startup_delay_of(bad), None, "{bad}");
        }
    }

    fn data_dir(tmp: &tempfile::TempDir) -> Result<LocalDataDir, Box<dyn std::error::Error>> {
        match atlas_duck_ipc::paths::check_data_dir(tmp.path())? {
            atlas_duck_ipc::paths::DataDirResolution::Local(d) => Ok(d),
            _ => Err("the temp dir is not a local data dir".into()),
        }
    }

    #[tokio::test]
    async fn startup_delay_sleeps_and_quit_ends_it() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let data = data_dir(&tmp)?;
        let quit = ShutdownSignal::new();
        // No file: no delay.
        let t = Instant::now();
        startup_delay(&data, &quit).await;
        assert!(t.elapsed() < Duration::from_millis(150));

        fs::create_dir(tmp.path().join(CONTROL_DIR))?;
        let file = tmp.path().join(CONTROL_DIR).join(DELAY_STARTUP_FILE);
        fs::write(&file, "300")?;
        let t = Instant::now();
        startup_delay(&data, &quit).await;
        assert!(t.elapsed() >= Duration::from_millis(300));

        // The cap's worth of delay, ended by Quit.
        fs::write(&file, "30000")?;
        let canceller = quit.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            canceller.cancel();
        });
        let t = Instant::now();
        startup_delay(&data, &quit).await;
        assert!(t.elapsed() < Duration::from_secs(5));
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn marker_reports_the_handle_state() -> TestResult {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::CreateEventW;
        // SAFETY: a manual-reset event created signaled, no name, default security; closed
        // below.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 1, std::ptr::null()) };
        if event.is_null() {
            return Err("CreateEventW failed".into());
        }
        assert_eq!(marker_for(event as usize), Some("signaled"));
        // A value far beyond any handle this test process holds.
        assert_eq!(marker_for(0x7fff_fff1), Some("invalid"));

        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join(CONTROL_DIR);
        fs::create_dir(&dir)?;
        fs::write(dir.join(MARKER_HANDLE_FILE), format!("{}", event as usize))?;
        let task = Control::spawn_with(dir.clone(), Arc::new(Counting::default()), FAST);
        let marker = dir.join(MARKER_FILE);
        wait_for("marker", || marker.exists()).await?;
        task.abort();
        assert_eq!(read(&dir, MARKER_FILE), "signaled");
        // SAFETY: the event created above, closed once.
        unsafe { CloseHandle(event) };
        Ok(())
    }
}
