//! macOS confinement (§9.4): `sandbox_init` with an embedded deny-by-default
//! SBPL profile, applied by the worker to itself before it reads its first
//! request.
//!
//! `sandbox_init(profile, 0, &err)` with flags 0 (profile text instead of a
//! named profile) is deprecated and undocumented, so this module is verified
//! by the probes (`app/src-tauri/tests/probes_macos.rs`) and by the child
//! process test below, and it is re-verified on each new macOS major (§15).
//!
//! The module compiles on every OS so that the profile text checks run on the
//! Windows dev box; only the FFI is macOS-only.

/// The embedded SBPL profile (`macos_profile.sb`).
pub const SBPL_PROFILE: &str = include_str!("macos_profile.sb");

/// `ConfinementReport::mechanism` of this module.
pub const MECHANISM: &str = "seatbelt";

#[cfg(target_os = "macos")]
pub use apply_impl::{SandboxInitError, apply, apply_profile};

#[cfg(target_os = "macos")]
mod apply_impl {
    use std::ffi::{CStr, CString, c_char, c_int};
    use std::io::{self, Write};
    use std::ptr;

    use atlas_duck_ipc::sandbox::probe::ConfinementReport;

    use super::{MECHANISM, SBPL_PROFILE};

    // `sandbox_init`, `sandbox_free_error` and `tzset` live in libSystem, so no
    // extra link attribute is needed. The `libc` crate binds none of them.
    unsafe extern "C" {
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
        fn sandbox_free_error(errorbuf: *mut c_char);
        fn tzset();
    }

    /// Why `sandbox_init` refused a profile.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SandboxInitError {
        /// The text `sandbox_init` put in its error buffer (for an SBPL syntax
        /// error this names the line), or a note if there was none.
        pub message: String,
        /// `errno` right after the call, if it was set.
        pub errno: Option<i32>,
    }

    /// Applies `profile` (SBPL source text) to this process. Irreversible.
    pub fn apply_profile(profile: &str) -> Result<(), SandboxInitError> {
        let text = CString::new(profile).map_err(|_| SandboxInitError {
            message: "profile contains a NUL byte".to_string(),
            errno: None,
        })?;
        let mut errorbuf: *mut c_char = ptr::null_mut();
        // SAFETY: `text` is a valid NUL-terminated string and `errorbuf` a
        // valid out pointer. Flags 0 means "`profile` is SBPL source".
        let rc = unsafe { sandbox_init(text.as_ptr(), 0, &mut errorbuf) };
        let errno = io::Error::last_os_error()
            .raw_os_error()
            .filter(|&e| e != 0);
        if rc == 0 {
            if !errorbuf.is_null() {
                // SAFETY: `errorbuf` came from `sandbox_init`.
                unsafe { sandbox_free_error(errorbuf) };
            }
            return Ok(());
        }
        let message = if errorbuf.is_null() {
            format!("sandbox_init returned {rc} without an error text")
        } else {
            // SAFETY: on failure `errorbuf` is a NUL-terminated C string owned
            // by libsandbox until `sandbox_free_error`.
            let text = unsafe { CStr::from_ptr(errorbuf) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: `errorbuf` came from `sandbox_init` and is freed once.
            unsafe { sandbox_free_error(errorbuf) };
            text
        };
        Err(SandboxInitError { message, errno })
    }

    /// Initializes libc's time-zone state from `TZ=UTC0` (§3.4) while files
    /// can still be opened. This mirrors the Linux order (§9.4: `tzset()` and
    /// one `localtime_r` first), so `Date` local-time methods never need a file
    /// after the profile is applied. The spec does not say this for macOS: it
    /// is a plan choice, and the `EngineSelfTest` probe checks the result.
    fn warm_time_zone() {
        // SAFETY: `tzset` takes no arguments; `localtime_r` gets valid
        // pointers to a `time_t` and a zeroed `tm`.
        unsafe {
            tzset();
            let now: libc::time_t = 0;
            let mut tm: libc::tm = std::mem::zeroed();
            libc::localtime_r(&now, &mut tm);
        }
    }

    /// Applies the embedded profile and reports the result. A refused profile
    /// is not an error here: the worker still sends `probe.ready`, with
    /// `applied: false`, so the floor verdict is `NotMet` (§9.4: "If the floor
    /// cannot be applied and verified, scripts are disabled"). The
    /// `sandbox_init` error text goes to stderr, which the host keeps.
    pub fn apply() -> ConfinementReport {
        warm_time_zone();
        match apply_profile(SBPL_PROFILE) {
            Ok(()) => report(true, None),
            Err(e) => {
                let _ = writeln!(io::stderr(), "sandbox_init failed: {}", e.message);
                report(false, Some(i64::from(e.errno.unwrap_or(-1))))
            }
        }
    }

    fn report(applied: bool, os_error: Option<i64>) -> ConfinementReport {
        ConfinementReport {
            applied,
            mechanism: MECHANISM.to_string(),
            no_new_privs: None,
            landlock_abi: None,
            seccomp: None,
            lpac: None,
            os_error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SBPL_PROFILE;

    /// The profile without `;` comments, one trimmed line per entry, empty
    /// lines dropped.
    fn rules() -> Vec<String> {
        SBPL_PROFILE
            .lines()
            .map(|l| l.split(';').next().unwrap_or("").trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    }

    /// `rules()` joined with single spaces, runs of white space collapsed.
    fn flat() -> String {
        rules()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn profile_starts_with_version_and_denies_by_default() {
        assert!(
            SBPL_PROFILE.starts_with("(version 1)"),
            "first bytes: {:?}",
            &SBPL_PROFILE[..SBPL_PROFILE.len().min(24)]
        );
        assert!(
            rules().iter().any(|l| l == "(deny default)"),
            "(deny default) must be a rule of its own: {:?}",
            rules()
        );
    }

    #[test]
    fn profile_allows_none_of_the_confined_capabilities() {
        // §9.4: no network, no file access after startup, no fork/exec, no
        // mach-lookup. `task_for_pid` is a floor probe, so task ports stay denied.
        let flat = flat();
        for banned in [
            "(allow default",
            "(allow network",
            "(allow system-socket",
            "(allow file",
            "(allow process-fork",
            "(allow process-exec",
            "(allow process*",
            "(allow mach-lookup",
            "(allow mach*",
            "(allow mach-priv-task-port",
        ] {
            assert!(
                !flat.contains(banned),
                "profile contains `{banned}`: {flat}"
            );
        }
    }

    #[test]
    fn every_allow_rule_has_a_comment_directly_above_it() {
        // "add each only when a test proves it, with a comment" (T18 notes).
        let lines: Vec<&str> = SBPL_PROFILE.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let code = line.split(';').next().unwrap_or("");
            if code.contains("(allow") {
                assert!(
                    i > 0 && lines[i - 1].trim_start().starts_with(';'),
                    "allow rule without a comment above it (line {}): {line}",
                    i + 1
                );
            }
        }
    }

    #[test]
    fn profile_parentheses_are_balanced() {
        // A cheap guard for hand edits: sandbox_init is only reachable on macOS.
        let mut depth: i32 = 0;
        for c in flat().chars() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0, "a ')' closes nothing: {}", flat());
        }
        assert_eq!(depth, 0, "unbalanced parentheses: {}", flat());
    }
}

/// Runs the real `sandbox_init` in a child process (the profile cannot be
/// undone, so the test binary re-runs itself). It needs no worker code, so it
/// isolates "the profile is valid and denies" from "the probes work".
#[cfg(all(test, target_os = "macos"))]
mod seatbelt_child_tests {
    use std::io::{BufRead, Write};
    use std::process::{Command, Stdio};

    use super::{SBPL_PROFILE, apply_profile};

    const CHILD_ENV: &str = "ATLAS_DUCK_T18_SEATBELT_CHILD";
    const CHILD_TEST: &str = "confine::macos::seatbelt_child_tests::child_body";

    fn say(line: &str) {
        println!("SEATBELT_CHILD {line}");
    }

    fn errno_of<T>(r: std::io::Result<T>) -> String {
        match r {
            Ok(_) => "ALLOWED".to_string(),
            Err(e) => e
                .raw_os_error()
                .map_or("none".to_string(), |c| c.to_string()),
        }
    }

    /// Runs inside the child only; a no-op in the normal test run.
    #[test]
    fn child_body() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        if let Err(e) = apply_profile(SBPL_PROFILE) {
            say(&format!(
                "apply=failed errno={:?} message={:?}",
                e.errno, e.message
            ));
            std::process::exit(1);
        }
        say("apply=ok");
        say(&format!(
            "file_open={}",
            errno_of(std::fs::File::open("/etc/hosts"))
        ));
        say(&format!(
            "connect_loopback={}",
            errno_of(std::net::TcpStream::connect("127.0.0.1:9"))
        ));
        say(&format!(
            "spawn={}",
            errno_of(Command::new("/usr/bin/true").status())
        ));
        // Descriptors opened before the profile keep working: read a line from
        // the inherited stdin pipe and echo it.
        let mut line = String::new();
        let n = std::io::stdin().lock().read_line(&mut line);
        say(&format!(
            "stdin_echo={:?} read={}",
            line.trim_end(),
            errno_of(n)
        ));
        let _ = std::io::stdout().flush();
        std::process::exit(0);
    }

    #[test]
    fn profile_applies_and_denies_files_network_and_spawn_in_a_child() {
        if std::env::var_os(CHILD_ENV).is_some() {
            return;
        }
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(exe)
            .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
            .env_clear()
            .env(CHILD_ENV, "1")
            .env("TZ", "UTC0")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the child test process");
        child
            .stdin
            .take()
            .expect("child stdin")
            .write_all(b"ping\n")
            .expect("write to child stdin");
        let out = child.wait_with_output().expect("wait for the child");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        // Printed for the go/no-go record (T22); visible with --nocapture.
        println!("--- child stdout ---\n{stdout}--- child stderr ---\n{stderr}");

        let lines: Vec<&str> = stdout
            .lines()
            .filter_map(|l| l.strip_prefix("SEATBELT_CHILD "))
            .collect();
        assert!(
            out.status.success(),
            "child failed ({:?}); see output above",
            out.status
        );
        assert!(
            lines.contains(&"apply=ok"),
            "sandbox_init refused the profile: {lines:?}"
        );
        for key in ["file_open=", "connect_loopback=", "spawn="] {
            let line = lines.iter().find(|l| l.starts_with(key));
            assert!(
                matches!(line, Some(l) if !l.ends_with("ALLOWED")),
                "{key} must be denied: {lines:?}"
            );
        }
        assert!(
            lines.iter().any(|l| l.starts_with("stdin_echo=\"ping\"")),
            "an inherited stdin pipe must still work: {lines:?}"
        );
    }
}
