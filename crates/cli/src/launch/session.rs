//! Interactive GUI session detection (§4.7, PD-24): without one the CLI never launches the app.
//!
//! Linux (and other non-macOS Unix): `DISPLAY` or `WAYLAND_DISPLAY` non-empty. macOS:
//! `/bin/launchctl managername` prints `Aqua`. Windows: not session 0 and a visible window station
//! (`windows::gui_session`).
// Each OS consumes one rule (display variables, Aqua); every rule compiles everywhere for the tests.

use std::ffi::OsString;

/// The rule for X11/Wayland desktops: either display variable is set and non-empty.
#[cfg_attr(not(all(unix, not(target_os = "macos"))), allow(dead_code))]
pub(crate) fn display_present(env: &dyn Fn(&str) -> Option<OsString>) -> bool {
    ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|k| env(k).is_some_and(|v| !v.is_empty()))
}

/// macOS: `launchctl managername` output names the Aqua (GUI login) session.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn is_aqua(managername_stdout: &[u8]) -> bool {
    std::str::from_utf8(managername_stdout).is_ok_and(|s| s.trim() == "Aqua")
}

/// Whether this process runs in an interactive desktop session (PD-24).
pub(crate) fn gui_session() -> bool {
    #[cfg(target_os = "macos")]
    {
        launchctl_manager().is_some_and(|out| is_aqua(&out))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        display_present(&|k| std::env::var_os(k))
    }
    #[cfg(windows)]
    {
        super::windows::gui_session()
    }
}

/// The raw stdout of `/bin/launchctl managername` (2 s limit, allowlisted environment, null
/// stdin/stderr); `None` when it could not run, timed out or failed.
#[cfg(target_os = "macos")]
pub(crate) fn launchctl_manager() -> Option<Vec<u8>> {
    use std::path::Path;
    use std::time::Duration;

    let env = super::env::launch_env(std::env::vars_os());
    let (ok, out) = super::unix::run_probe(
        Path::new("/bin/launchctl"),
        &["managername"],
        &env,
        Duration::from_secs(2),
    )?;
    ok.then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_rule() {
        let none = |_: &str| None;
        assert!(!display_present(&none));
        let empty = |_: &str| Some(OsString::new());
        assert!(!display_present(&empty));
        let x11 = |k: &str| (k == "DISPLAY").then(|| OsString::from(":0"));
        assert!(display_present(&x11));
        let wayland = |k: &str| (k == "WAYLAND_DISPLAY").then(|| OsString::from("wayland-0"));
        assert!(display_present(&wayland));
        // Lower-case names are other variables.
        let lower = |k: &str| (k == "display").then(|| OsString::from(":0"));
        assert!(!display_present(&lower));
    }

    #[test]
    fn aqua_rule() {
        assert!(is_aqua(b"Aqua\n"));
        assert!(is_aqua(b"Aqua"));
        assert!(!is_aqua(b"Background\n"));
        assert!(!is_aqua(b"LoginWindow\n"));
        assert!(!is_aqua(b"aqua\n"));
        assert!(!is_aqua(b""));
        assert!(!is_aqua(b"\xffAqua"));
    }

    /// PD-24: records what the macOS CI runner reports; asserts nothing. Runs a real process, so
    /// it is ignored by default and run on the macOS leg with `--ignored --nocapture` (Task 26).
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "spawns /bin/launchctl; run on the T26 macOS leg with --ignored --nocapture"]
    fn gui_session_probe() {
        let text = launchctl_manager()
            .map(|o| String::from_utf8_lossy(&o).trim().to_owned())
            .unwrap_or_else(|| "<none>".to_owned());
        println!("V13 launchctl_manager={text}");
    }
}
