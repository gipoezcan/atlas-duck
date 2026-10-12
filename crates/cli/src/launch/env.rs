//! The launched app's environment (§4.7 "How to launch"): rebuilt from an explicit allowlist, never
//! inherited. The caller's `PATH` is replaced by the system path and every proxy variable is dropped
//! by construction (nothing outside the allowlist is ever copied), so a CLI-launched app behaves
//! like a login-started one and never routes PAT-bearing traffic through the agent's proxy.

use std::ffi::OsString;

/// Variable names copied verbatim when present (§4.7). `LC_*` is matched as a prefix.
const KEEP: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "HOME",
    "USERPROFILE",
    "LANG",
    "TMP",
    "TEMP",
    "TMPDIR",
    "SystemRoot",
];

/// Test builds only (feature `test-env`, locked out of release builds in `lib.rs`): the test home
/// and keystore overrides reach the launched app. Nothing else is ever added.
#[cfg(feature = "test-env")]
const TEST_KEEP: &[&str] = &["ATLAS_DUCK_TEST_HOME", "ATLAS_DUCK_TEST_KEYSTORE"];
#[cfg(not(feature = "test-env"))]
const TEST_KEEP: &[&str] = &[];

const LC_PREFIX: &str = "LC_";

/// Unix system `PATH` (macOS); Linux appends the sbin directories.
const UNIX_SYSTEM_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
const LINUX_SYSTEM_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
/// Used for the Windows system `PATH` when the caller has no `SystemRoot`.
const WINDOWS_DEFAULT_ROOT: &str = r"C:\Windows";

/// Which OS's naming rules apply. Only `CURRENT` is used outside tests; the others let every rule
/// be tested on every host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvOs {
    Windows,
    Linux,
    MacOs,
}

impl EnvOs {
    pub(crate) const CURRENT: EnvOs = if cfg!(windows) {
        EnvOs::Windows
    } else if cfg!(target_os = "macos") {
        EnvOs::MacOs
    } else {
        EnvOs::Linux
    };

    /// Windows variable names are case-insensitive; everywhere else they are exact.
    fn same_name(self, a: &str, b: &str) -> bool {
        match self {
            EnvOs::Windows => a.eq_ignore_ascii_case(b),
            EnvOs::Linux | EnvOs::MacOs => a == b,
        }
    }

    fn has_lc_prefix(self, name: &str) -> bool {
        name.len() > LC_PREFIX.len()
            && name
                .get(..LC_PREFIX.len())
                .is_some_and(|p| self.same_name(p, LC_PREFIX))
    }
}

/// The environment for the launched app on this OS: see `launch_env_for`.
pub(crate) fn launch_env(
    current: impl Iterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    launch_env_for(current, EnvOs::CURRENT)
}

/// Keeps exactly the allowlisted names (first occurrence wins; on Windows the allowlist spelling is
/// used, so `home` and `HOME` become one `HOME`), then appends `PATH` set to the system path. A name
/// that is not valid Unicode, is empty or contains `=` or NUL is never on the allowlist; a value
/// with NUL is dropped too (it cannot be passed to the OS).
pub(crate) fn launch_env_for(
    current: impl Iterator<Item = (OsString, OsString)>,
    os: EnvOs,
) -> Vec<(OsString, OsString)> {
    let mut out: Vec<(OsString, OsString)> = Vec::new();
    for (name, value) in current {
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(kept) = allowed_name(name, os) else {
            continue;
        };
        if contains_nul(&value) {
            continue;
        }
        let dup = out
            .iter()
            .any(|(k, _)| k.to_str().is_some_and(|k| os.same_name(k, &kept)));
        if !dup {
            out.push((OsString::from(kept), value));
        }
    }
    let path = system_path(&out, os);
    out.push((OsString::from("PATH"), path));
    out
}

/// The spelling to emit for an allowlisted `name`, or `None` when it is not allowlisted.
fn allowed_name(name: &str, os: EnvOs) -> Option<String> {
    if name.contains('=') || name.contains('\0') {
        return None;
    }
    if let Some(k) = KEEP
        .iter()
        .chain(TEST_KEEP.iter())
        .find(|k| os.same_name(name, k))
    {
        return Some((*k).to_owned());
    }
    // `LC_ALL`, `LC_CTYPE`, ...: kept as spelled (Windows dedups case-insensitively).
    os.has_lc_prefix(name).then(|| name.to_owned())
}

fn contains_nul(v: &OsString) -> bool {
    v.as_encoded_bytes().contains(&0)
}

/// Unix: fixed. Windows: `%SystemRoot%\System32;%SystemRoot%;%SystemRoot%\System32\Wbem`, from the
/// kept `SystemRoot` or `C:\Windows` when there is none.
fn system_path(kept: &[(OsString, OsString)], os: EnvOs) -> OsString {
    match os {
        EnvOs::Linux => OsString::from(LINUX_SYSTEM_PATH),
        EnvOs::MacOs => OsString::from(UNIX_SYSTEM_PATH),
        EnvOs::Windows => {
            let root = kept
                .iter()
                .find(|(k, v)| k == "SystemRoot" && !v.is_empty())
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| OsString::from(WINDOWS_DEFAULT_ROOT));
            let mut path = root.clone();
            path.push(r"\System32;");
            path.push(&root);
            path.push(";");
            path.push(&root);
            path.push(r"\System32\Wbem");
            path
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn input(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }

    fn as_map(v: &[(OsString, OsString)]) -> BTreeMap<String, String> {
        v.iter()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
            .collect()
    }

    const HOSTILE: &[(&str, &str)] = &[
        ("HTTP_PROXY", "http://agent-proxy:3128"),
        ("https_proxy", "http://agent-proxy:3128"),
        ("All_Proxy", "socks5://agent-proxy:1080"),
        ("no_proxy", "localhost"),
        ("HTTPS_PROXY", "http://agent-proxy:3128"),
        ("http_proxy", "http://agent-proxy:3128"),
        ("ALL_PROXY", "socks5://agent-proxy:1080"),
        ("NO_PROXY", "*"),
        ("PATH", "/evil"),
        ("LD_PRELOAD", "/evil/x.so"),
        ("DYLD_INSERT_LIBRARIES", "/evil/x.dylib"),
        ("ATLAS_DUCK_AGENT", "agent-x"),
        ("ATLAS_DUCK_TEST_HOME", "/tmp/test-home"),
        ("ATLAS_DUCK_TEST_KEYSTORE", "mock"),
        ("LC_ALL", "C.UTF-8"),
        ("LANG", "en_US.UTF-8"),
        ("DISPLAY", ":0"),
    ];

    /// What survives besides the test-only names when `test-env` is on.
    fn with_test_names(mut m: BTreeMap<String, String>) -> BTreeMap<String, String> {
        if cfg!(feature = "test-env") {
            m.insert("ATLAS_DUCK_TEST_HOME".into(), "/tmp/test-home".into());
            m.insert("ATLAS_DUCK_TEST_KEYSTORE".into(), "mock".into());
        }
        m
    }

    #[test]
    fn env_allowlist_table() {
        for (os, path) in [
            (EnvOs::Linux, LINUX_SYSTEM_PATH),
            (EnvOs::MacOs, UNIX_SYSTEM_PATH),
        ] {
            let out = launch_env_for(input(HOSTILE).into_iter(), os);
            let expected = with_test_names(as_map(&input(&[
                ("LC_ALL", "C.UTF-8"),
                ("LANG", "en_US.UTF-8"),
                ("DISPLAY", ":0"),
                ("PATH", path),
            ])));
            assert_eq!(as_map(&out), expected, "{os:?}");
            assert_eq!(out.len(), expected.len(), "{os:?}: duplicate names");
        }

        // Windows: `Path` and `PATH` both go; one system PATH built from SystemRoot.
        let mut win = input(HOSTILE);
        win.extend(input(&[
            ("Path", r"C:\evil"),
            ("SystemRoot", r"C:\Windows"),
        ]));
        let out = launch_env_for(win.into_iter(), EnvOs::Windows);
        let expected = with_test_names(as_map(&input(&[
            ("LC_ALL", "C.UTF-8"),
            ("LANG", "en_US.UTF-8"),
            ("DISPLAY", ":0"),
            ("SystemRoot", r"C:\Windows"),
            (
                "PATH",
                r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem",
            ),
        ])));
        assert_eq!(as_map(&out), expected);
        assert_eq!(out.len(), expected.len());
        assert_eq!(
            out.iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("path"))
                .count(),
            1
        );
    }

    #[test]
    fn every_allowlisted_name_is_kept_and_nothing_else() {
        let mut pairs: Vec<(String, String)> = KEEP
            .iter()
            .map(|k| ((*k).to_owned(), format!("v-{k}")))
            .collect();
        pairs.push(("LC_CTYPE".into(), "C".into()));
        pairs.push(("LC_".into(), "bare prefix".into()));
        pairs.push(("LCX".into(), "no".into()));
        pairs.push(("SSH_AUTH_SOCK".into(), "/agent".into()));
        pairs.push(("ATLAS_DUCK_PAT".into(), "secret".into()));
        pairs.push(("ATLAS_DUCK_MCP_TIMEOUT".into(), "50".into()));
        let pairs: Vec<(OsString, OsString)> = pairs
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        let out = as_map(&launch_env_for(pairs.into_iter(), EnvOs::Linux));
        let mut names: Vec<&str> = out.keys().map(String::as_str).collect();
        names.sort_unstable();
        let mut expected: Vec<&str> = KEEP.to_vec();
        expected.extend(["LC_CTYPE", "PATH"]);
        expected.sort_unstable();
        assert_eq!(names, expected);
    }

    #[test]
    fn names_match_exactly_on_unix_and_case_insensitively_on_windows() {
        let pairs = input(&[
            ("display", ":1"),
            ("Home", "/h"),
            ("lc_all", "C"),
            ("systemroot", r"D:\Win"),
            ("HOME", "/second"),
        ]);
        let unix = as_map(&launch_env_for(pairs.clone().into_iter(), EnvOs::Linux));
        assert_eq!(
            unix.keys().map(String::as_str).collect::<Vec<_>>(),
            ["HOME", "PATH"]
        );
        assert_eq!(unix["HOME"], "/second");

        let win = launch_env_for(pairs.into_iter(), EnvOs::Windows);
        let m = as_map(&win);
        // Allowlist spelling, first occurrence wins.
        assert_eq!(m["DISPLAY"], ":1");
        assert_eq!(m["HOME"], "/h");
        assert_eq!(m["lc_all"], "C");
        assert_eq!(m["SystemRoot"], r"D:\Win");
        assert_eq!(m["PATH"], r"D:\Win\System32;D:\Win;D:\Win\System32\Wbem");
        assert_eq!(win.len(), 5);
    }

    #[test]
    fn windows_path_without_system_root_uses_the_default() {
        let out = as_map(&launch_env_for(
            input(&[("PATH", r"C:\evil")]).into_iter(),
            EnvOs::Windows,
        ));
        assert_eq!(
            out["PATH"],
            r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem"
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn unpassable_entries_are_dropped() {
        let out = launch_env_for(
            input(&[("DISPLAY", ":0\0x"), ("LANG=x", "C"), ("LANG", "C")]).into_iter(),
            EnvOs::Linux,
        );
        assert_eq!(
            as_map(&out),
            as_map(&input(&[("LANG", "C"), ("PATH", LINUX_SYSTEM_PATH)]))
        );
    }

    #[test]
    fn current_os_is_the_build_os() {
        let out = as_map(&launch_env(input(&[("PATH", "/evil")]).into_iter()));
        let expected = match EnvOs::CURRENT {
            EnvOs::Linux => LINUX_SYSTEM_PATH,
            EnvOs::MacOs => UNIX_SYSTEM_PATH,
            EnvOs::Windows => r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem",
        };
        assert_eq!(out["PATH"], expected);
        assert_eq!(cfg!(windows), EnvOs::CURRENT == EnvOs::Windows);
        assert_eq!(cfg!(target_os = "macos"), EnvOs::CURRENT == EnvOs::MacOs);
    }
}
