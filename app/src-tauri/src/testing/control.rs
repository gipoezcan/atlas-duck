//! PD-03 / PD-35: the test build's control dir `<data>/test-control/`, polled every 100 ms.
//!
//! - `quit` (any content): the §2.5 shutdown path with `ShutdownReason::Quit`, once
//!   (`serve::shutdown_then_exit`, which also ends the process).
//! - `env-names.json` (written at start): the sorted **names** of the app's environment
//!   variables, never their values (I-20).
//! - `pid` (written at start): the app's own process id, so a test harness can end an app that
//!   ignored `quit` (never a name-based kill).
//! - `refused` (written on change): the kept gate handler's refused count (PD-35), or `none`
//!   while `Core` serves or before anything serves.
//! - `delay-startup-ms` (read by `serve::start` before the first `open`): sleep that many
//!   milliseconds, at most 30 000 (I-17's deadline test).
//! - `marker-handle` → `marker` (V12): whether a handle the test opened is open in this process.
//!   Windows: `marker-handle` holds the value of an inheritable disk-file handle on line 1 and the
//!   file's full path on line 2; `marker` is `signaled` when that value is a disk-file handle here
//!   (`GetFileType`) whose final path (`GetFinalPathNameByHandleW`, compared without the `\\?\`
//!   prefix and ignoring case) is that file (it leaked into the app), `invalid` when the value is
//!   no handle here, `other` when it is one of the app's own handles (handle values are reused).
//!   The handle is only queried, never read or closed. Linux and macOS: `marker-handle` holds the
//!   descriptor number on line 1 and the file's canonical path on line 2; `marker` is `signaled`
//!   when that descriptor is open here and names that file (it leaked into the app), `invalid`
//!   when it is not open, `other` when the number is one of the app's own descriptors. (The app
//!   cannot be inspected from outside on Linux: it is non-dumpable, so `/proc/<pid>/fd` is
//!   closed to the test.)

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

use super::keystore::{create_private_dir, write_atomic};
use crate::serve;
use crate::state::ServeSlot;

/// `<data>/<CONTROL_DIR>`.
pub const CONTROL_DIR: &str = "test-control";
pub const QUIT_FILE: &str = "quit";
pub const ENV_NAMES_FILE: &str = "env-names.json";
pub const REFUSED_FILE: &str = "refused";
pub const PID_FILE: &str = "pid";
/// Written by the scripted approver (not by the watcher): the queue as a JSON array of
/// `{request_id, class, approvable}`, rewritten on change.
pub const QUEUE_FILE: &str = "queue.json";
pub const DELAY_STARTUP_FILE: &str = "delay-startup-ms";
pub const MARKER_HANDLE_FILE: &str = "marker-handle";
pub const MARKER_FILE: &str = "marker";

/// The `refused` content while no gate handler serves.
pub const REFUSED_NONE: &str = "none";
/// How often the control dir is read.
pub const POLL: Duration = Duration::from_millis(100);
/// The cap of `delay-startup-ms`.
pub const MAX_STARTUP_DELAY: Duration = Duration::from_secs(30);
/// How many failed `refused` writes in a row end the mirror (one warning, no more attempts).
pub const MAX_REFUSED_WRITE_FAILURES: u32 = 50;

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
    if create_private_dir(&dir).is_err() {
        tracing::warn!(event = LOG_EVENT_CONTROL_FAILED, reason = "control_dir");
    } else if write_env_names(&dir).is_err() {
        tracing::warn!(event = LOG_EVENT_CONTROL_FAILED, reason = "env_names");
    } else if write_pid(&dir).is_err() {
        tracing::warn!(event = LOG_EVENT_CONTROL_FAILED, reason = "pid");
    }
    let mut quit_sent = false;
    let mut refused_written: Option<Option<u64>> = None;
    let mut refused_failures = 0u32;
    let mut marker_written = false;
    loop {
        if !quit_sent && dir.join(QUIT_FILE).exists() {
            quit_sent = true;
            host.quit();
        }
        let refused = host.refused();
        if refused_written != Some(refused) && refused_failures < MAX_REFUSED_WRITE_FAILURES {
            let text = refused.map_or_else(|| REFUSED_NONE.to_owned(), |n| n.to_string());
            if write_atomic(&dir, REFUSED_FILE, text.as_bytes()).is_ok() {
                refused_written = Some(refused);
            } else {
                refused_failures += 1;
                // Bounded: after the last attempt one warning, then the mirror stays as it is.
                if refused_failures == MAX_REFUSED_WRITE_FAILURES {
                    tracing::warn!(event = LOG_EVENT_CONTROL_FAILED, reason = "refused");
                }
            }
        }
        if !marker_written && let Some(text) = read_marker_handle(&dir) {
            marker_written = write_atomic(&dir, MARKER_FILE, text.as_bytes()).is_ok();
        }
        tokio::time::sleep(poll).await;
    }
}

/// `pid`: this process's id in decimal.
fn write_pid(dir: &Path) -> io::Result<()> {
    write_atomic(dir, PID_FILE, std::process::id().to_string().as_bytes())
}

/// `env-names.json`: a JSON array of the sorted, distinct variable names (lossy UTF-8).
fn write_env_names(dir: &Path) -> io::Result<()> {
    let names: BTreeSet<String> = std::env::vars_os()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    let json = serde_json::to_vec(&names).map_err(io::Error::other)?;
    write_atomic(dir, ENV_NAMES_FILE, &json)
}

/// The `marker` text for the contents of `marker-handle`; `None` without a usable value.
fn read_marker_handle(dir: &Path) -> Option<&'static str> {
    let text = fs::read_to_string(dir.join(MARKER_HANDLE_FILE)).ok()?;
    marker_for_text(&text)
}

/// V12 (Windows): `<handle value>\n<full path>`; see the module doc.
#[cfg(windows)]
fn marker_for_text(text: &str) -> Option<&'static str> {
    let mut lines = text.lines();
    let value: usize = lines.next()?.trim().parse().ok()?;
    let want = lines.next()?;
    Some(marker_for(value, want))
}

/// The path a final-path name names, without the `\\?\` (or `\\?\UNC\`) prefix, lower-cased.
#[cfg(windows)]
fn normalized_path(path: &str) -> String {
    let path = path.trim();
    let path = match path.strip_prefix(r"\\?\UNC\") {
        Some(rest) => format!(r"\\{rest}"),
        None => path.strip_prefix(r"\\?\").unwrap_or(path).to_owned(),
    };
    path.to_lowercase()
}

/// V12: whether the handle value is an open disk-file handle of this process that names `want`
/// (it was inherited from the test): `signaled`; `invalid` when the value is no handle here;
/// `other` when it is one of this process's own handles (another type or another file). A bare
/// value cannot tell those apart (handle values are small and reused), so the file is checked
/// too.
#[cfg(windows)]
fn marker_for(value: usize, want: &str) -> &'static str {
    use windows_sys::Win32::Foundation::{GetLastError, HANDLE, NO_ERROR};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_TYPE_DISK, FILE_TYPE_UNKNOWN, GetFileType, GetFinalPathNameByHandleW,
    };
    let handle = value as HANDLE;
    // SAFETY: `GetFileType` reads no memory through the value and only queries the object; a
    // value that is no handle fails with `FILE_TYPE_UNKNOWN` and a last error. It never changes
    // the object's state and never blocks on a disk file. The foreign handle is never read,
    // written or closed.
    let kind = unsafe { GetFileType(handle) };
    // SAFETY: reads this thread's last error, no pointers.
    if kind == FILE_TYPE_UNKNOWN && unsafe { GetLastError() } != NO_ERROR {
        return "invalid";
    }
    if kind != FILE_TYPE_DISK {
        return "other";
    }
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: `buf` is valid for `buf.len()` UTF-16 units, which is passed as the capacity;
        // flags 0 is `VOLUME_NAME_DOS | FILE_NAME_NORMALIZED`. The call only queries the handle.
        let n = unsafe { GetFinalPathNameByHandleW(handle, buf.as_mut_ptr(), buf.len() as u32, 0) }
            as usize;
        if n == 0 {
            return "other";
        }
        if n < buf.len() {
            // The path without the terminating NUL.
            let got = String::from_utf16_lossy(&buf[..n]);
            return if normalized_path(&got) == normalized_path(want) {
                "signaled"
            } else {
                "other"
            };
        }
        // Too small: `n` is the size needed including the NUL.
        buf.resize(n + 1, 0);
    }
}

/// V12 (Unix): `<fd>\n<path>`; see the module doc.
#[cfg(unix)]
fn marker_for_text(text: &str) -> Option<&'static str> {
    let mut lines = text.lines();
    let fd: libc::c_int = lines.next()?.trim().parse().ok()?;
    let want = Path::new(lines.next()?);
    // SAFETY: `F_GETFD` takes no pointer and only reads the descriptor table; a closed number
    // fails with `EBADF`.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Some("invalid");
    }
    Some(if fd_target(fd).is_some_and(|t| t == want) {
        "signaled"
    } else {
        "other"
    })
}

/// The file an open descriptor of this process names.
#[cfg(target_os = "linux")]
fn fd_target(fd: libc::c_int) -> Option<PathBuf> {
    fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

#[cfg(target_os = "macos")]
fn fd_target(fd: libc::c_int) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut buf = [0u8; libc::PATH_MAX as usize];
    // SAFETY: `F_GETPATH` writes a NUL-terminated path of at most `MAXPATHLEN` (1024, the length
    // of `PATH_MAX`) bytes into the buffer, which is that long.
    let rc = unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc < 0 {
        return None;
    }
    let len = buf.iter().position(|b| *b == 0)?;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..len])))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn fd_target(_fd: libc::c_int) -> Option<PathBuf> {
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

    /// A `KEY=value` pair. Windows keeps hidden per-drive variables whose
    /// names start with `=` (`=C:`), so only an `=` after the first char counts.
    fn looks_like_assignment(s: &str) -> bool {
        s.chars().skip(1).any(|c| c == '=')
    }

    #[test]
    fn assignment_check_flags_values_not_per_drive_names() {
        assert!(looks_like_assignment("KEY=value"));
        assert!(looks_like_assignment("K="));
        assert!(!looks_like_assignment("=C:"));
        assert!(!looks_like_assignment("PATH"));
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
            assert!(!looks_like_assignment(s), "a value leaked: {s}");
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
    async fn the_own_pid_is_written_at_start() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join(CONTROL_DIR);
        let task = Control::spawn_with(dir.clone(), Arc::new(Counting::default()), FAST);
        wait_for("pid", || dir.join(PID_FILE).exists()).await?;
        task.abort();
        assert_eq!(read(&dir, PID_FILE), std::process::id().to_string());
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

    #[cfg(unix)]
    #[tokio::test]
    async fn marker_reports_the_descriptor_state() -> TestResult {
        use std::os::fd::AsRawFd;
        let tmp = tempfile::tempdir()?;
        let file_path = fs::canonicalize(tmp.path())?.join("held");
        fs::write(&file_path, b"x")?;
        let file = fs::File::open(&file_path)?;
        let fd = file.as_raw_fd();
        let text = |fd: i32, path: &Path| format!("{fd}\n{}", path.display());
        assert_eq!(marker_for_text(&text(fd, &file_path)), Some("signaled"));
        // Open here, but another file: one of the app's own descriptors.
        assert_eq!(
            marker_for_text(&text(fd, &tmp.path().join("other"))),
            Some("other")
        );
        // A number far beyond any descriptor this test process holds.
        assert_eq!(marker_for_text(&text(99_999, &file_path)), Some("invalid"));
        assert_eq!(marker_for_text("not-a-number\n/x"), None);
        assert_eq!(marker_for_text("5"), None);

        let dir = tmp.path().join(CONTROL_DIR);
        fs::create_dir(&dir)?;
        fs::write(dir.join(MARKER_HANDLE_FILE), text(fd, &file_path))?;
        let task = Control::spawn_with(dir.clone(), Arc::new(Counting::default()), FAST);
        wait_for("marker", || dir.join(MARKER_FILE).exists()).await?;
        task.abort();
        assert_eq!(read(&dir, MARKER_FILE), "signaled");
        drop(file);
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn marker_reports_the_handle_state() -> TestResult {
        use std::os::windows::io::AsRawHandle;
        let tmp = tempfile::tempdir()?;
        let file_path = fs::canonicalize(tmp.path())?.join("held");
        fs::write(&file_path, b"x")?;
        let other_path = fs::canonicalize(tmp.path())?.join("other");
        fs::write(&other_path, b"y")?;
        let file = fs::File::open(&file_path)?;
        let value = file.as_raw_handle() as usize;
        let text = |value: usize, path: &Path| format!("{value}\n{}", path.display());
        assert_eq!(marker_for_text(&text(value, &file_path)), Some("signaled"));
        // Case and the `\\?\` prefix do not matter.
        let plain = file_path.display().to_string();
        let plain = plain.strip_prefix(r"\\?\").unwrap_or(&plain).to_uppercase();
        assert_eq!(
            marker_for_text(&format!("{value}\n{plain}")),
            Some("signaled")
        );
        // Open here, but another file: one of the app's own handles.
        assert_eq!(marker_for_text(&text(value, &other_path)), Some("other"));
        // INVALID_HANDLE_VALUE is no handle.
        assert_eq!(
            marker_for_text(&text(usize::MAX, &file_path)),
            Some("invalid")
        );
        // A value far beyond any handle this test process holds.
        assert_eq!(
            marker_for_text(&text(0x7fff_fff0, &file_path)),
            Some("invalid")
        );
        assert_eq!(marker_for_text("not-a-number\nC:\\x"), None);
        assert_eq!(marker_for_text("5"), None);

        let dir = tmp.path().join(CONTROL_DIR);
        fs::create_dir(&dir)?;
        fs::write(dir.join(MARKER_HANDLE_FILE), text(value, &file_path))?;
        let task = Control::spawn_with(dir.clone(), Arc::new(Counting::default()), FAST);
        let marker = dir.join(MARKER_FILE);
        wait_for("marker", || marker.exists()).await?;
        task.abort();
        assert_eq!(read(&dir, MARKER_FILE), "signaled");
        drop(file);
        // Closed: the value is no handle any more (or, if reused, not that file).
        assert_ne!(marker_for_text(&text(value, &file_path)), Some("signaled"));
        Ok(())
    }
}
