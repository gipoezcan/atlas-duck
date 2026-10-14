//! Startup hardening (§2.5 "Startup hardening", P16): before any webview and before any thread.
//!
//! Applied only to GUI and `--background` launches (§2.5 Scope): `main` calls [`apply_early`] first
//! in the GUI branch, before the mmap threshold, the crash settings, `Diag::init` and the Tauri
//! builder. The early-argv modes `__cli` and `__verify-export` keep their environment untouched.
//!
//! - The debug-channel and loader-injection variables of [`SCRUBBED`] are removed from this
//!   process's environment ([`KEPT`] stays). Removing `LD_PRELOAD`, `GTK_MODULES` or
//!   `GIO_EXTRA_MODULES` does not unload anything already in this process: it keeps them away from
//!   what this process starts later (the WebKit web process, the sandbox worker) and from the GTK
//!   initialization that has not run yet. `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` loses only its
//!   remote-debugging tokens ([`scrub_plan`]).
//! - Windows: `SetDefaultDllDirectories` and the applicable `SetProcessMitigationPolicy` settings.
//!   Plan decision (T2): the applicable set is the extension-point and image-load policies only.
//!   No dynamic-code policy (WebView2 loads its client DLL into this process and its loader calls
//!   run here) and no strict-handle-check policy (it turns a benign invalid handle into a crash).
//! - Every failure is recorded by constant name, logged by [`log`] once the diagnostic log exists,
//!   and never stops startup.
//!
//! The values of scrubbed variables are never logged or kept beyond the rewrite.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::Ordering;

use crate::early_argv::EarlyMode;

/// The WebView2 browser-arguments variable; only its remote-debugging tokens are removed (§2.5).
pub const WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: &str = "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS";

/// §2.5 (verbatim): "Remove debug-channel and loader-injection variables from the app's own
/// environment and log a warning: `--remote-debugging*` inside
/// `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`, `WEBVIEW2_USER_DATA_FOLDER`, `WEBKIT_INSPECTOR_SERVER`,
/// `WEBKIT_INSPECTOR_HTTP_SERVER`, `LD_PRELOAD`, `GTK_MODULES`, `GIO_EXTRA_MODULES`."
pub const SCRUBBED: [&str; 7] = [
    WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS,
    "WEBVIEW2_USER_DATA_FOLDER",
    "WEBKIT_INSPECTOR_SERVER",
    "WEBKIT_INSPECTOR_HTTP_SERVER",
    "LD_PRELOAD",
    "GTK_MODULES",
    "GIO_EXTRA_MODULES",
];

/// §2.5 (verbatim): "`WEBVIEW2_BROWSER_EXECUTABLE_FOLDER` is kept for fixed-version enterprise
/// deployments."
pub const KEPT: &str = "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER";

/// A browser-arguments token naming this text, in any ASCII case, is dropped. Plan decision (T2):
/// broader than the spec's `--remote-debugging*`, because Chromium on Windows also takes `-` and
/// `/` as switch prefixes and compares switch names case-insensitively.
pub const REMOTE_DEBUGGING: &str = "remote-debugging";

/// Whether this build may open webview devtools (§2.5 "Release builds disable devtools and remote
/// debugging"): debug builds only. The window builder (T6) passes it to
/// `WebviewWindowBuilder::devtools`.
pub const DEVTOOLS_ALLOWED: bool = cfg!(debug_assertions);

#[cfg(not(debug_assertions))]
const _: () = assert!(
    !DEVTOOLS_ALLOWED,
    "release builds never allow devtools (§2.5)"
);

/// `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR)`.
pub const MITIGATION_DLL_DIRECTORIES: &str = "SetDefaultDllDirectories";
/// `SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, {DisableExtensionPoints})`.
pub const MITIGATION_EXTENSION_POINTS: &str = "ProcessExtensionPointDisablePolicy";
/// `SetProcessMitigationPolicy(ProcessImageLoadPolicy, {NoRemoteImages,
/// NoLowMandatoryLabelImages, PreferSystem32Images})`.
pub const MITIGATION_IMAGE_LOAD: &str = "ProcessImageLoadPolicy";

/// One warning line per scrubbed variable name (field `removed_var`).
pub const LOG_EVENT_ENV_SCRUBBED: &str = "startup_env_scrubbed";
/// One warning line per failed mitigation (field `reason` = its constant name).
pub const LOG_EVENT_MITIGATION_FAILED: &str = "startup_mitigation_failed";

/// What [`apply_early`] did. Names only: no variable value is ever kept here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hardening {
    /// The [`SCRUBBED`] names that were removed or rewritten, in [`SCRUBBED`] order.
    pub removed: Vec<&'static str>,
    /// The constant names (`MITIGATION_*`) of the Windows mitigations that failed. Empty when all
    /// applied and on other OSes.
    pub mitigations: Vec<&'static str>,
}

/// What happens to one variable.
#[derive(Clone, PartialEq, Eq)]
pub enum EnvAction {
    Remove,
    /// The new value (`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` without its debugging tokens).
    Rewrite(OsString),
}

/// Never prints a rewritten value.
impl fmt::Debug for EnvAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvAction::Remove => f.write_str("Remove"),
            EnvAction::Rewrite(_) => f.write_str("Rewrite(..)"),
        }
    }
}

/// The environment changes [`apply_early`] makes, computed by [`scrub_plan`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScrubPlan {
    pub actions: Vec<(&'static str, EnvAction)>,
}

impl ScrubPlan {
    /// The names to log, one warning line each. Names only, never values.
    pub fn log_names(&self) -> Vec<&'static str> {
        self.actions.iter().map(|(name, _)| *name).collect()
    }
}

/// Pure: which [`SCRUBBED`] variables `env` holds and what happens to each. A present variable is
/// removed (even when empty), except `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`, which is left alone
/// when no token names [`REMOTE_DEBUGGING`], rewritten without those tokens otherwise, and removed
/// when nothing is left or the value cannot be rewritten safely (quoted, or not Unicode).
pub fn scrub_plan(env: &dyn Fn(&str) -> Option<OsString>) -> ScrubPlan {
    let mut actions = Vec::new();
    for name in SCRUBBED {
        let Some(value) = env(name) else {
            continue;
        };
        if name == WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS {
            if let Some(action) = browser_args_action(&value) {
                actions.push((name, action));
            }
        } else {
            actions.push((name, EnvAction::Remove));
        }
    }
    ScrubPlan { actions }
}

fn names_remote_debugging(text: &str) -> bool {
    text.to_ascii_lowercase().contains(REMOTE_DEBUGGING)
}

fn browser_args_action(value: &OsStr) -> Option<EnvAction> {
    let Some(text) = value.to_str() else {
        // Not Unicode: no token-level rewrite; removed whole when it may name the switch.
        return names_remote_debugging(&value.to_string_lossy()).then_some(EnvAction::Remove);
    };
    let tokens: Vec<&str> = text.split_whitespace().collect();
    if !tokens.iter().any(|t| names_remote_debugging(t)) {
        return None;
    }
    // A quoted argument may span tokens; dropping one token could unbalance the quoting and turn
    // the rest into something else, so the whole variable goes.
    if text.contains('"') {
        return Some(EnvAction::Remove);
    }
    let kept: Vec<&str> = tokens
        .into_iter()
        .filter(|t| !names_remote_debugging(t))
        .collect();
    if kept.is_empty() {
        Some(EnvAction::Remove)
    } else {
        Some(EnvAction::Rewrite(OsString::from(kept.join(" "))))
    }
}

/// Whether startup hardening applies to this launch mode: GUI and `--background` only (§2.5
/// Scope). `main` calls [`apply_early`] in exactly the [`EarlyMode::Gui`] branch.
pub fn applies_to(mode: &EarlyMode) -> bool {
    matches!(mode, EarlyMode::Gui { .. })
}

static APPLIED: OnceLock<Hardening> = OnceLock::new();

/// Applies the §2.5 startup hardening: Windows DLL search order, the environment scrub, the
/// Windows mitigation policies. Never fails; the result is also kept for [`applied`] (the first
/// call wins).
///
/// Precondition: called first in the GUI branch of `main`, while this is the only thread.
pub fn apply_early() -> Hardening {
    // Only the Windows branches push; elsewhere the vector stays empty.
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut mitigations = Vec::new();
    #[cfg(windows)]
    if !set_default_dll_directories() {
        mitigations.push(MITIGATION_DLL_DIRECTORIES);
    }

    let plan = scrub_plan(&|name| std::env::var_os(name));
    apply_env(&plan);

    #[cfg(windows)]
    mitigations.extend(set_mitigation_policies());

    let hardening = Hardening {
        removed: plan.log_names(),
        mitigations,
    };
    let _ = APPLIED.set(hardening.clone());
    hardening
}

/// The result of the first [`apply_early`] call in this process, for `run_gui` to [`log`].
pub fn applied() -> Option<&'static Hardening> {
    APPLIED.get()
}

/// Writes one warning line per removed variable (field `removed_var`, never the value) and one
/// per failed mitigation (field `reason`, its constant name). Called after `Diag::init`; the lines
/// wait in the memory buffer until a data dir is attached.
pub fn log(h: &Hardening) {
    for name in &h.removed {
        tracing::warn!(event = LOG_EVENT_ENV_SCRUBBED, removed_var = *name);
    }
    for name in &h.mitigations {
        tracing::warn!(event = LOG_EVENT_MITIGATION_FAILED, reason = *name);
    }
}

/// The only place this crate writes its own environment.
fn apply_env(plan: &ScrubPlan) {
    debug_assert!(
        !crate::diag::STARTED.load(Ordering::SeqCst),
        "startup hardening must run before Diag::init, while main is the only thread"
    );
    for (name, action) in &plan.actions {
        match action {
            // SAFETY: single-thread precondition. `apply_early` is called first in the GUI branch
            // of `main`, before `Diag::init`, the mmap threshold, the crash settings and the Tauri
            // builder, so no other thread exists that could read the environment concurrently
            // (the debug assertion above checks that `Diag::init` has not run yet).
            EnvAction::Remove => unsafe { std::env::remove_var(name) },
            // SAFETY: as above.
            EnvAction::Rewrite(value) => unsafe { std::env::set_var(name, value) },
        }
    }
}

/// `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR)`:
/// later `LoadLibrary` calls without an explicit search path look only in System32 and the
/// application directory (no current directory, no `PATH`).
#[cfg(windows)]
fn set_default_dll_directories() -> bool {
    use windows_sys::Win32::System::LibraryLoader::{
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
    };

    // SAFETY: takes a flags value only; no pointers.
    let ok = unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR)
    };
    ok != 0
}

/// `PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY.Flags` (winnt.h bitfield, LSB first):
/// bit 0 `DisableExtensionPoints` (AppInit DLLs, legacy IMEs, Winsock LSPs, global window hooks).
#[cfg(windows)]
const EXTENSION_POINT_DISABLE_FLAGS: u32 = 1 << 0;

/// `PROCESS_MITIGATION_IMAGE_LOAD_POLICY.Flags` (winnt.h bitfield, LSB first): bit 0
/// `NoRemoteImages`, bit 1 `NoLowMandatoryLabelImages`, bit 2 `PreferSystem32Images`; the audit
/// bits 3 and 4 stay clear.
#[cfg(windows)]
const IMAGE_LOAD_FLAGS: u32 = (1 << 0) | (1 << 1) | (1 << 2);

/// Sets each applicable mitigation policy; returns the constant names of those that failed.
#[cfg(windows)]
fn set_mitigation_policies() -> Vec<&'static str> {
    use windows_sys::Win32::System::Threading::{
        ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
    };

    let mut failed = Vec::new();
    for (policy, flags, name) in [
        (
            ProcessExtensionPointDisablePolicy,
            EXTENSION_POINT_DISABLE_FLAGS,
            MITIGATION_EXTENSION_POINTS,
        ),
        (
            ProcessImageLoadPolicy,
            IMAGE_LOAD_FLAGS,
            MITIGATION_IMAGE_LOAD,
        ),
    ] {
        if !set_mitigation_policy(policy, flags) {
            failed.push(name);
        }
    }
    failed
}

/// Both policy structures are a union of one `DWORD Flags` with its bitfield, so the buffer is
/// that `u32` and the length its size.
#[cfg(windows)]
fn set_mitigation_policy(
    policy: windows_sys::Win32::System::Threading::PROCESS_MITIGATION_POLICY,
    flags: u32,
) -> bool {
    use windows_sys::Win32::System::Threading::SetProcessMitigationPolicy;

    // SAFETY: the buffer points at `flags`, which lives across the call, and the length is its
    // size (4 bytes, the size of both policy structures).
    let ok = unsafe {
        SetProcessMitigationPolicy(
            policy,
            std::ptr::from_ref(&flags).cast(),
            std::mem::size_of::<u32>(),
        )
    };
    ok != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::Registry;
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt as _;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn rewrite(value: &str) -> ScrubPlan {
        let env = env_of(&[(WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS, value)]);
        scrub_plan(&env)
    }

    #[test]
    fn scrubbed_list_is_the_spec_list() {
        assert_eq!(
            SCRUBBED,
            [
                "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
                "WEBVIEW2_USER_DATA_FOLDER",
                "WEBKIT_INSPECTOR_SERVER",
                "WEBKIT_INSPECTOR_HTTP_SERVER",
                "LD_PRELOAD",
                "GTK_MODULES",
                "GIO_EXTRA_MODULES",
            ]
        );
        assert!(!SCRUBBED.contains(&KEPT));
    }

    #[test]
    fn scrub_removes_listed_vars_keeps_browser_folder() {
        let mut pairs: Vec<(&str, &str)> = SCRUBBED.iter().map(|n| (*n, "x")).collect();
        pairs[0].1 = "--remote-debugging-port=9222";
        pairs.push((KEPT, r"C:\fixed\webview2"));
        pairs.push(("PATH", "/usr/bin"));
        let plan = scrub_plan(&env_of(&pairs));
        let expected: Vec<(&'static str, EnvAction)> =
            SCRUBBED.iter().map(|n| (*n, EnvAction::Remove)).collect();
        assert_eq!(plan.actions, expected);
        assert!(!plan.log_names().contains(&KEPT));
        assert!(!plan.log_names().contains(&"PATH"));
    }

    #[test]
    fn empty_value_counts_as_present() {
        let plan = scrub_plan(&env_of(&[("LD_PRELOAD", "")]));
        assert_eq!(plan.actions, [("LD_PRELOAD", EnvAction::Remove)]);
    }

    #[test]
    fn nothing_set_means_nothing_to_do() {
        let plan = scrub_plan(&env_of(&[(KEPT, "x")]));
        assert_eq!(plan, ScrubPlan::default());
    }

    #[test]
    fn webview2_args_lose_only_remote_debugging_tokens() {
        assert_eq!(
            rewrite("--foo --remote-debugging-port=9222 --remote-debugging-pipe --bar").actions,
            [(
                WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS,
                EnvAction::Rewrite(OsString::from("--foo --bar"))
            )]
        );
        // A value that becomes empty is removed.
        assert_eq!(
            rewrite(" --remote-debugging-port=9222\t--remote-debugging-pipe ").actions,
            [(WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS, EnvAction::Remove)]
        );
        // No debugging token: the variable is left as it is.
        assert!(rewrite("--foo --bar=1").actions.is_empty());
        assert!(rewrite("").actions.is_empty());
    }

    #[test]
    fn webview2_args_switch_prefix_and_case_variants_are_dropped() {
        assert_eq!(
            rewrite(
                "-remote-debugging-port=1 /Remote-Debugging-Port=2 --REMOTE-DEBUGGING-PIPE --a"
            )
            .actions,
            [(
                WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS,
                EnvAction::Rewrite(OsString::from("--a"))
            )]
        );
    }

    #[test]
    fn webview2_args_with_quotes_and_a_debugging_token_are_removed_whole() {
        assert_eq!(
            rewrite(r#"--foo="a b" --remote-debugging-port=9222"#).actions,
            [(WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS, EnvAction::Remove)]
        );
        // Quotes without a debugging token are left alone.
        assert!(rewrite(r#"--foo="a b""#).actions.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn non_unicode_webview2_args_are_removed_whole_when_they_name_the_switch() {
        use std::os::windows::ffi::OsStringExt;
        let mut wide: Vec<u16> = "--remote-debugging-port=1 ".encode_utf16().collect();
        wide.push(0xD800);
        let value = OsString::from_wide(&wide);
        let plan = scrub_plan(&move |name: &str| {
            (name == WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS).then(|| value.clone())
        });
        assert_eq!(
            plan.actions,
            [(WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS, EnvAction::Remove)]
        );
        let clean = OsString::from_wide(&[0x61, 0xD800]);
        let plan = scrub_plan(&move |name: &str| {
            (name == WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS).then(|| clean.clone())
        });
        assert!(plan.actions.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_webview2_args_are_removed_whole_when_they_name_the_switch() {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = b"--remote-debugging-port=1 ".to_vec();
        bytes.push(0xff);
        let value = OsString::from_vec(bytes);
        let plan = scrub_plan(&move |name: &str| {
            (name == WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS).then(|| value.clone())
        });
        assert_eq!(
            plan.actions,
            [(WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS, EnvAction::Remove)]
        );
        let clean = OsString::from_vec(vec![b'a', 0xff]);
        let plan = scrub_plan(&move |name: &str| {
            (name == WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS).then(|| clean.clone())
        });
        assert!(plan.actions.is_empty());
    }

    const SENTINEL: &str = "SENTINEL-VALUE-5c1e";

    #[test]
    fn scrub_plan_never_reads_values_into_log() {
        let args = format!("--{SENTINEL} --remote-debugging-port=9222");
        let mut pairs: Vec<(&str, &str)> = SCRUBBED.iter().map(|n| (*n, SENTINEL)).collect();
        pairs[0].1 = &args;
        let plan = scrub_plan(&env_of(&pairs));
        assert_eq!(plan.log_names(), SCRUBBED);
        for name in plan.log_names() {
            assert!(!name.contains(SENTINEL), "{name}");
        }
        // The rewrite keeps the non-debugging token, but no Debug output shows it.
        assert_eq!(
            plan.actions[0].1,
            EnvAction::Rewrite(OsString::from(format!("--{SENTINEL}")))
        );
        let debug = format!("{plan:?}");
        assert!(!debug.contains(SENTINEL), "{debug}");
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Capture {
            self.clone()
        }
    }

    #[test]
    fn log_writes_one_warning_per_name_and_nothing_else() {
        let cap = Capture::default();
        let subscriber =
            Registry::default().with(crate::diag::fields::allowlist_layer(cap.clone()));
        let h = Hardening {
            removed: vec!["LD_PRELOAD", WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS],
            mitigations: vec![MITIGATION_IMAGE_LOAD],
        };
        tracing::subscriber::with_default(subscriber, || log(&h));
        let out = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out}");
        assert!(lines.iter().all(|l| l.contains(" WARN ")), "{out}");
        assert!(
            lines[0].contains("event=startup_env_scrubbed removed_var=LD_PRELOAD dropped_fields=0"),
            "{out}"
        );
        assert!(
            lines[1].contains("removed_var=WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS dropped_fields=0"),
            "{out}"
        );
        assert!(
            lines[2].contains(
                "event=startup_mitigation_failed reason=ProcessImageLoadPolicy dropped_fields=0"
            ),
            "{out}"
        );
    }

    #[test]
    fn hardening_applies_to_gui_launches_only() {
        assert!(applies_to(&EarlyMode::Gui { background: false }));
        assert!(applies_to(&EarlyMode::Gui { background: true }));
        assert!(!applies_to(&EarlyMode::Cli(vec![OsString::from("x")])));
        assert!(!applies_to(&EarlyMode::VerifyExport(vec![])));
    }

    #[test]
    fn devtools_follow_the_build_profile() {
        assert_eq!(DEVTOOLS_ALLOWED, cfg!(debug_assertions));
    }

    #[cfg(windows)]
    #[test]
    fn mitigation_flags_match_winnt_h() {
        assert_eq!(EXTENSION_POINT_DISABLE_FLAGS, 0b1);
        assert_eq!(IMAGE_LOAD_FLAGS, 0b111);
    }
}
