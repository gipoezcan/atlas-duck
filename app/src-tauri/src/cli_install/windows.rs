//! Windows (§12.3): the install dir joins `HKCU\Environment\Path` (stored as `REG_EXPAND_SZ`, no
//! duplicate, compared case-insensitively) and `WM_SETTINGCHANGE` tells running shells. The PATH
//! text logic is pure and tested everywhere; [`registry`] is the real registry code (Windows only;
//! its one test is `#[ignore]`d and runs on the CI Windows leg).
//!
//! The value is read and written unexpanded: a `%USERPROFILE%\bin` entry stays exactly that.
//! `uninstall` removes every segment equal to the install dir and keeps the others verbatim, in
//! order; the only text it can change besides the removed segment is a trailing `;` that
//! `install` swallowed when it appended.

use super::{Artifact, InstallError, Kind, PlatformOps, Report, registry_error};

/// `Some(dir)` of a Windows layout, as the PATH entry text: no trailing separator, and nothing a
/// PATH list cannot carry (`;`, `"`, control characters), no empty path.
fn entry(kind: &Kind) -> Result<String, InstallError> {
    let Kind::Windows { install_dir } = kind else {
        return Err(InstallError::Unsupported);
    };
    let text = install_dir.to_str().ok_or(InstallError::UnsafePath)?;
    let text = text.trim_end_matches(['\\', '/']);
    if text.is_empty() || text.chars().any(|c| c.is_control() || c == ';' || c == '"') {
        return Err(InstallError::UnsafePath);
    }
    // `C:` alone is the current directory of drive C: a drive root keeps its separator.
    if text.ends_with(':') {
        return Ok(format!("{text}\\"));
    }
    Ok(text.to_owned())
}

/// The longest user PATH (UTF-16 units) install writes. The registry value holds 32767 units, and a
/// longer one is cut or ignored when new processes read it. The user and system PATH expand and
/// join in each process; that sum cannot be checked here.
pub const MAX_PATH_UNITS: usize = 32_000;

/// Resolve-time check that the install dir can be a PATH entry.
pub fn check_install_dir(kind: &Kind) -> Result<(), InstallError> {
    entry(kind).map(|_| ())
}

/// The comparison form of one PATH segment: no surrounding blanks or quotes, no trailing
/// separator, lower case (Windows file names are case-insensitive).
fn normalized(segment: &str) -> String {
    segment
        .trim()
        .trim_matches('"')
        .trim_end_matches(['\\', '/'])
        .to_lowercase()
}

/// True when some segment of `path` is `dir`.
pub fn path_contains(path: &str, dir: &str) -> bool {
    let want = normalized(dir);
    path.split(';').any(|s| normalized(s) == want)
}

/// `dir` appended to `current`, or `None` when it is already there (no write, no broadcast).
pub fn path_append(current: Option<&str>, dir: &str) -> Option<String> {
    match current {
        None => Some(dir.to_owned()),
        Some(path) if path_contains(path, dir) => None,
        Some("") => Some(dir.to_owned()),
        Some(path) if path.ends_with(';') => Some(format!("{path}{dir}")),
        Some(path) => Some(format!("{path};{dir}")),
    }
}

/// `current` without the segments equal to `dir`, or `None` when none is.
pub fn path_remove(current: &str, dir: &str) -> Option<String> {
    if !path_contains(current, dir) {
        return None;
    }
    let want = normalized(dir);
    let kept: Vec<&str> = current
        .split(';')
        .filter(|s| normalized(s) != want)
        .collect();
    Some(kept.join(";"))
}

pub fn install(ops: &dyn PlatformOps, kind: &Kind, done: &mut Report) -> Result<(), InstallError> {
    let dir = entry(kind)?;
    let current = ops.user_path_get().map_err(|e| registry_error(&e))?;
    if let Some(next) = path_append(current.as_deref(), &dir) {
        if next.encode_utf16().count() > MAX_PATH_UNITS {
            return Err(InstallError::PathTooLong);
        }
        ops.user_path_set(&next).map_err(|e| registry_error(&e))?;
        done.changed.push(Artifact::PathEntry);
        ops.broadcast_setting_change();
    }
    Ok(())
}

pub fn uninstall(
    ops: &dyn PlatformOps,
    kind: &Kind,
    wanted: impl Fn(Artifact) -> bool,
    removed: &mut Vec<Artifact>,
) -> Result<(), InstallError> {
    if !wanted(Artifact::PathEntry) {
        return Ok(());
    }
    let dir = entry(kind)?;
    let current = ops.user_path_get().map_err(|e| registry_error(&e))?;
    if let Some(next) = current.as_deref().and_then(|c| path_remove(c, &dir)) {
        // Nothing else was in the value: it goes, as it was absent before install created it.
        if next.is_empty() {
            ops.user_path_remove().map_err(|e| registry_error(&e))?;
        } else {
            ops.user_path_set(&next).map_err(|e| registry_error(&e))?;
        }
        removed.push(Artifact::PathEntry);
        ops.broadcast_setting_change();
    }
    Ok(())
}

/// The PATH names the install dir (a failed read counts as absent).
pub fn present(ops: &dyn PlatformOps, kind: &Kind) -> bool {
    let Ok(dir) = entry(kind) else {
        return false;
    };
    matches!(ops.user_path_get(), Ok(Some(p)) if path_contains(&p, &dir))
}

/// The real registry (Windows only). The key is a parameter so the CI round trip runs against a
/// scratch key; the app itself only ever uses [`RegistryOps::user`].
#[cfg(windows)]
pub mod registry {
    use std::io;

    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_EXPAND_SZ,
        REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteValueW,
        RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
    };

    /// The subkey of the user PATH.
    pub const ENVIRONMENT: &str = "Environment";
    const VALUE_NAME: &str = "Path";
    /// `SendMessageTimeoutW`'s per-window wait: a hung window must not hang Settings.
    const BROADCAST_TIMEOUT_MS: u32 = 5000;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn win32(code: u32) -> io::Error {
        io::Error::from_raw_os_error(code as i32)
    }

    /// An open key, closed on drop.
    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a key this struct opened and has not closed.
            unsafe { RegCloseKey(self.0) };
        }
    }

    /// The user PATH value of one key under `HKEY_CURRENT_USER`.
    #[derive(Debug, Clone)]
    pub struct RegistryOps {
        subkey: Vec<u16>,
    }

    impl RegistryOps {
        /// `HKCU\Environment`: the real user PATH.
        pub fn user() -> RegistryOps {
            RegistryOps::with_subkey(ENVIRONMENT)
        }

        /// Another key under HKCU (the CI test's scratch key).
        pub fn with_subkey(subkey: &str) -> RegistryOps {
            RegistryOps {
                subkey: wide(subkey),
            }
        }

        fn open(&self, access: u32) -> io::Result<Option<Key>> {
            let mut key: HKEY = std::ptr::null_mut();
            // SAFETY: `subkey` is NUL-terminated and outlives the call; `key` is a valid out pointer.
            let rc = unsafe {
                RegOpenKeyExW(HKEY_CURRENT_USER, self.subkey.as_ptr(), 0, access, &mut key)
            };
            match rc {
                ERROR_SUCCESS => Ok(Some(Key(key))),
                ERROR_FILE_NOT_FOUND => Ok(None),
                other => Err(win32(other)),
            }
        }

        /// `Path` as stored (REG_SZ or REG_EXPAND_SZ, never expanded); `None` when the key or the
        /// value does not exist; `InvalidData` for another type or text that is not UTF-16.
        pub fn path_get(&self) -> io::Result<Option<String>> {
            let Some(key) = self.open(KEY_QUERY_VALUE)? else {
                return Ok(None);
            };
            let name = wide(VALUE_NAME);
            // The value can grow between the size query and the read: retry a few times.
            for _ in 0..4 {
                let mut kind = 0u32;
                let mut size = 0u32;
                // SAFETY: a size query (null data); every pointer is valid for the call.
                let rc = unsafe {
                    RegQueryValueExW(
                        key.0,
                        name.as_ptr(),
                        std::ptr::null(),
                        &mut kind,
                        std::ptr::null_mut(),
                        &mut size,
                    )
                };
                match rc {
                    ERROR_SUCCESS => {}
                    ERROR_FILE_NOT_FOUND => return Ok(None),
                    other => return Err(win32(other)),
                }
                if kind != REG_SZ && kind != REG_EXPAND_SZ {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
                let mut cap = (buf.len() * 2) as u32;
                // SAFETY: `buf` holds `cap` bytes; the other pointers are valid for the call.
                let rc = unsafe {
                    RegQueryValueExW(
                        key.0,
                        name.as_ptr(),
                        std::ptr::null(),
                        &mut kind,
                        buf.as_mut_ptr().cast::<u8>(),
                        &mut cap,
                    )
                };
                match rc {
                    ERROR_SUCCESS => {}
                    ERROR_MORE_DATA => continue,
                    other => return Err(win32(other)),
                }
                buf.truncate((cap as usize / 2).min(buf.len()));
                while buf.last() == Some(&0) {
                    buf.pop();
                }
                return String::from_utf16(&buf)
                    .map(Some)
                    .map_err(|_| io::ErrorKind::InvalidData.into());
            }
            Err(io::ErrorKind::InvalidData.into())
        }

        /// Writes `Path` as `REG_EXPAND_SZ`, creating the key when it is absent.
        pub fn path_set(&self, value: &str) -> io::Result<()> {
            let mut key: HKEY = std::ptr::null_mut();
            // SAFETY: `subkey` is NUL-terminated; the optional pointers are null; `key` is valid.
            let rc = unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    self.subkey.as_ptr(),
                    0,
                    std::ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE,
                    std::ptr::null(),
                    &mut key,
                    std::ptr::null_mut(),
                )
            };
            if rc != ERROR_SUCCESS {
                return Err(win32(rc));
            }
            let key = Key(key);
            let name = wide(VALUE_NAME);
            let data = wide(value);
            let bytes = u32::try_from(data.len() * 2).map_err(|_| io::ErrorKind::InvalidInput)?;
            // SAFETY: `data` holds `bytes` bytes (with the terminating NUL), `name` is NUL-terminated.
            let rc = unsafe {
                RegSetValueExW(
                    key.0,
                    name.as_ptr(),
                    0,
                    REG_EXPAND_SZ,
                    data.as_ptr().cast::<u8>(),
                    bytes,
                )
            };
            if rc == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(win32(rc))
            }
        }

        /// Deletes the `Path` value; a missing key or value is `Ok`.
        pub fn path_remove(&self) -> io::Result<()> {
            let Some(key) = self.open(KEY_SET_VALUE)? else {
                return Ok(());
            };
            let name = wide(VALUE_NAME);
            // SAFETY: `key` is open with KEY_SET_VALUE and `name` is NUL-terminated.
            match unsafe { RegDeleteValueW(key.0, name.as_ptr()) } {
                ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
                other => Err(win32(other)),
            }
        }

        /// The registry type of `Path` (the CI test checks `REG_EXPAND_SZ` survives).
        pub fn path_type(&self) -> io::Result<Option<u32>> {
            let Some(key) = self.open(KEY_QUERY_VALUE)? else {
                return Ok(None);
            };
            let name = wide(VALUE_NAME);
            let mut kind = 0u32;
            let mut size = 0u32;
            // SAFETY: a size query (null data); every pointer is valid for the call.
            let rc = unsafe {
                RegQueryValueExW(
                    key.0,
                    name.as_ptr(),
                    std::ptr::null(),
                    &mut kind,
                    std::ptr::null_mut(),
                    &mut size,
                )
            };
            match rc {
                ERROR_SUCCESS => Ok(Some(kind)),
                ERROR_FILE_NOT_FOUND => Ok(None),
                other => Err(win32(other)),
            }
        }
    }

    /// `WM_SETTINGCHANGE` with `"Environment"` to every top-level window (a hung one is skipped
    /// after [`BROADCAST_TIMEOUT_MS`]); the answers are ignored, like Explorer's own broadcast.
    pub fn broadcast_environment_change() {
        let text = wide(ENVIRONMENT);
        let mut result = 0usize;
        // SAFETY: `text` is NUL-terminated and outlives the synchronous call; `result` is valid.
        unsafe {
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                text.as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                BROADCAST_TIMEOUT_MS,
                &mut result,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cli_install::fake::{FakeOps, State};
    use crate::cli_install::{Layout, install, is_installed, uninstall};

    const DIR: &str = r"C:\Program Files\atlas-duck";

    fn layout() -> Layout {
        Layout {
            kind: Kind::Windows {
                install_dir: PathBuf::from(DIR),
            },
            app_path: PathBuf::from(r"C:\Program Files\atlas-duck\atlas-duck-app.exe"),
            cli_toml: PathBuf::from(r"C:\Users\u\AppData\Local\atlas-duck\cli.toml"),
        }
    }

    #[test]
    fn windows_path_append_idempotent_case_insensitive() {
        // Appended once, with one separator.
        assert_eq!(
            path_append(Some(r"C:\Windows;C:\Tools"), DIR).as_deref(),
            Some(r"C:\Windows;C:\Tools;C:\Program Files\atlas-duck")
        );
        assert_eq!(path_append(None, DIR).as_deref(), Some(DIR));
        assert_eq!(path_append(Some(""), DIR).as_deref(), Some(DIR));
        assert_eq!(
            path_append(Some(r"C:\Windows;"), DIR).as_deref(),
            Some(r"C:\Windows;C:\Program Files\atlas-duck")
        );
        // Already there: no change, whatever the case, trailing separator or quoting.
        for present in [
            r"C:\Windows;C:\Program Files\atlas-duck",
            r"C:\Windows;C:\PROGRAM FILES\ATLAS-DUCK\",
            r"c:\program files\atlas-duck\;C:\Windows",
            r#"C:\Windows;"C:\Program Files\atlas-duck""#,
            r"C:\Windows; C:\Program Files\atlas-duck ",
        ] {
            assert_eq!(path_append(Some(present), DIR), None, "{present}");
        }
        // A prefix or a sibling is another directory.
        assert!(path_append(Some(r"C:\Program Files\atlas-duck-old"), DIR).is_some());
        assert!(path_append(Some(r"C:\Program Files"), DIR).is_some());

        // Through the ops: the second install writes and broadcasts nothing, and the value keeps
        // an unexpanded variable and its order byte for byte.
        let original = r"%USERPROFILE%\bin;C:\Windows;%SystemRoot%\System32";
        let ops = FakeOps::with_path(original);
        let first = install(&ops, &layout()).expect("install");
        assert_eq!(first.changed, [Artifact::PathEntry, Artifact::CliToml]);
        assert_eq!(
            ops.state().path.as_deref(),
            Some(format!("{original};{DIR}").as_str())
        );
        let second = install(&ops, &layout()).expect("second install");
        assert!(second.changed.is_empty(), "{second:?}");
        assert_eq!((ops.path_sets(), ops.broadcasts()), (1, 1));
        // Any case in the stored value is recognised too.
        let upper = FakeOps::with_path(&DIR.to_uppercase());
        install(&upper, &layout()).expect("install");
        assert_eq!(upper.path_sets(), 0);
        assert_eq!(upper.broadcasts(), 0);
    }

    #[test]
    fn path_remove_keeps_the_other_segments_verbatim() {
        assert_eq!(
            path_remove(&format!(r"%A%;{DIR};C:\x;"), DIR).as_deref(),
            Some(r"%A%;C:\x;")
        );
        assert_eq!(
            path_remove(&format!(r"{DIR};{}\;C:\x", DIR.to_uppercase()), DIR).as_deref(),
            Some(r"C:\x")
        );
        assert_eq!(path_remove(r"C:\x;C:\y", DIR), None);
        // The round trip is exact unless the original ended in a `;` that the append swallowed.
        for original in [r"C:\a;C:\b", r"%X%\bin", r"C:\a;;C:\b"] {
            let appended = path_append(Some(original), DIR).expect("appended");
            assert_eq!(path_remove(&appended, DIR).as_deref(), Some(original));
        }
    }

    #[test]
    fn the_dir_is_a_safe_path_entry() {
        for bad in ["", r"C:\a;b", "C:\\a\"b", "C:\\a\nb", r"\\", "/"] {
            let kind = Kind::Windows {
                install_dir: PathBuf::from(bad),
            };
            assert_eq!(
                check_install_dir(&kind),
                Err(InstallError::UnsafePath),
                "{bad:?}"
            );
        }
        let trailing = Kind::Windows {
            install_dir: PathBuf::from(r"C:\Program Files\atlas-duck\"),
        };
        assert_eq!(entry(&trailing).as_deref(), Ok(DIR));
    }

    /// `C:\` stays `C:\` (`C:` is the current directory of drive C).
    #[test]
    fn a_drive_root_keeps_its_separator() {
        for root in [r"C:\", "C:", "d:/"] {
            let kind = Kind::Windows {
                install_dir: PathBuf::from(root),
            };
            let want = format!("{}:\\", &root[..1]);
            assert_eq!(entry(&kind).as_deref(), Ok(want.as_str()), "{root}");
        }
    }

    /// No `Path` value before install means none after uninstall (not an empty one); a value with
    /// other entries is written back with them.
    #[test]
    fn a_missing_path_value_stays_missing_after_uninstall() {
        let ops = FakeOps::new();
        install(&ops, &layout()).expect("install");
        assert_eq!(ops.state().path.as_deref(), Some(DIR));
        uninstall(&ops, &layout()).expect("uninstall");
        assert_eq!(ops.state(), State::default(), "no empty value is left");
        assert_eq!(ops.path_removes(), 1);
    }

    /// A PATH that would pass the registry value's size is refused with its own kind; nothing is
    /// written or broadcast and the value is as it was. One that just fits is written.
    #[test]
    fn a_path_that_grows_too_long_is_refused() {
        let room = MAX_PATH_UNITS - DIR.len() - 1;
        let fits = "a".repeat(room);
        let ops = FakeOps::with_path(&fits);
        install(&ops, &layout()).expect("just fits");
        assert_eq!(ops.path_sets(), 1);

        let long = "a".repeat(room + 1);
        let ops = FakeOps::with_path(&long);
        assert_eq!(install(&ops, &layout()), Err(InstallError::PathTooLong));
        assert_eq!(
            (ops.path_sets(), ops.broadcasts()),
            (0, 0),
            "nothing written"
        );
        assert_eq!(ops.state().path.as_deref(), Some(long.as_str()));
        assert_eq!(ops.state().cli_tomls.len(), 0);
    }

    #[test]
    fn install_state_and_removal_follow_the_path() {
        let ops = FakeOps::with_path(r"C:\Windows");
        assert!(!is_installed(&ops, &layout()));
        install(&ops, &layout()).expect("install");
        assert!(is_installed(&ops, &layout()));
        let gone = uninstall(&ops, &layout()).expect("uninstall");
        assert_eq!(gone.changed, [Artifact::PathEntry, Artifact::CliToml]);
        assert_eq!(
            ops.state(),
            State {
                path: Some(r"C:\Windows".into()),
                ..State::default()
            }
        );
        assert!(!is_installed(&ops, &layout()));
        // Nothing left to remove: no write, no broadcast.
        let sets = (ops.path_sets(), ops.broadcasts());
        assert!(
            uninstall(&ops, &layout())
                .expect("again")
                .changed
                .is_empty()
        );
        assert_eq!((ops.path_sets(), ops.broadcasts()), sets);
    }

    /// CI only (the Windows leg): the real registry, against a scratch key under HKCU so the
    /// runner's own PATH is never touched. Reads, appends, removes and checks the stored type.
    #[cfg(windows)]
    #[test]
    #[ignore = "CI: windows leg, registry write"]
    fn real_registry_round_trip() {
        use std::io;
        use std::path::Path;

        use atlas_duck_ipc::paths::{CliToml, PinnedError};
        use windows_sys::Win32::System::Registry::{
            HKEY_CURRENT_USER, REG_EXPAND_SZ, RegDeleteTreeW,
        };

        use super::registry::{RegistryOps, broadcast_environment_change};
        use crate::cli_install::{PlatformOps, SystemOps};

        /// The real registry for the PATH, the real machine for the rest.
        struct Scratch(RegistryOps);

        impl PlatformOps for Scratch {
            fn user_path_get(&self) -> io::Result<Option<String>> {
                self.0.path_get()
            }
            fn user_path_set(&self, v: &str) -> io::Result<()> {
                self.0.path_set(v)
            }
            fn user_path_remove(&self) -> io::Result<()> {
                self.0.path_remove()
            }
            fn broadcast_setting_change(&self) {
                // The scratch key is nobody's environment; the real broadcast is smoke-tested below.
            }
            fn symlink(&self, s: &Path, d: &Path) -> io::Result<()> {
                SystemOps.symlink(s, d)
            }
            fn write_file(&self, p: &Path, b: &[u8], m: u32) -> io::Result<()> {
                SystemOps.write_file(p, b, m)
            }
            fn remove(&self, p: &Path) -> io::Result<()> {
                SystemOps.remove(p)
            }
            fn read_file(&self, p: &Path) -> io::Result<Option<Vec<u8>>> {
                SystemOps.read_file(p)
            }
            fn read_link(&self, p: &Path) -> io::Result<Option<PathBuf>> {
                SystemOps.read_link(p)
            }
            fn write_cli_toml(&self, p: &Path, c: &CliToml) -> Result<(), PinnedError> {
                SystemOps.write_cli_toml(p, c)
            }
            fn read_cli_toml(&self, p: &Path) -> Result<Option<CliToml>, PinnedError> {
                SystemOps.read_cli_toml(p)
            }
        }

        /// Deletes the scratch key even when an assertion fails.
        struct Cleanup(Vec<u16>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                // SAFETY: `self.0` is a NUL-terminated key name.
                unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, self.0.as_ptr()) };
            }
        }

        let subkey = format!(
            r"Software\atlas-duck-test\cli-install-{}",
            std::process::id()
        );
        let _cleanup = Cleanup(subkey.encode_utf16().chain(Some(0)).collect());
        let reg = RegistryOps::with_subkey(&subkey);
        assert_eq!(
            reg.path_get().expect("get"),
            None,
            "scratch key must not exist"
        );

        // A PATH with an unexpanded variable, stored as REG_EXPAND_SZ.
        let original = r"%USERPROFILE%\bin;C:\Windows";
        reg.path_set(original).expect("seed");
        assert_eq!(reg.path_type().expect("type"), Some(REG_EXPAND_SZ));
        assert_eq!(reg.path_get().expect("get").as_deref(), Some(original));

        let tmp = tempfile::tempdir().expect("tempdir");
        let layout = Layout {
            kind: Kind::Windows {
                install_dir: PathBuf::from(r"C:\Program Files\atlas-duck-ci"),
            },
            app_path: PathBuf::from(r"C:\Program Files\atlas-duck-ci\atlas-duck-app.exe"),
            cli_toml: tmp.path().join("cli.toml"),
        };
        let ops = Scratch(reg.clone());
        install(&ops, &layout).expect("install");
        assert_eq!(
            reg.path_get().expect("get").as_deref(),
            Some(format!(r"{original};C:\Program Files\atlas-duck-ci").as_str()),
            "the variable stays unexpanded"
        );
        assert_eq!(reg.path_type().expect("type"), Some(REG_EXPAND_SZ));
        assert!(is_installed(&ops, &layout));
        // Idempotent in the real registry too.
        assert!(install(&ops, &layout).expect("again").changed.is_empty());

        uninstall(&ops, &layout).expect("uninstall");
        assert_eq!(reg.path_get().expect("get").as_deref(), Some(original));
        assert_eq!(reg.path_type().expect("type"), Some(REG_EXPAND_SZ));
        assert!(!is_installed(&ops, &layout));

        // No `Path` value at all: install creates it, uninstall deletes it again.
        reg.path_remove().expect("delete");
        assert_eq!(reg.path_get().expect("get"), None);
        install(&ops, &layout).expect("install from nothing");
        assert_eq!(
            reg.path_get().expect("get").as_deref(),
            Some(r"C:\Program Files\atlas-duck-ci")
        );
        uninstall(&ops, &layout).expect("uninstall");
        assert_eq!(
            reg.path_get().expect("get"),
            None,
            "the value stays missing"
        );
        assert_eq!(reg.path_type().expect("type"), None);

        // The broadcast call itself (every top-level window; hung ones time out).
        broadcast_environment_change();
    }
}
