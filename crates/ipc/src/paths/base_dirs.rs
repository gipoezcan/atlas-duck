//! Base folders from OS known-folder APIs (Windows) or the passwd home
//! directory (macOS/Linux), never from per-session environment (§7.7 Path
//! stability).

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use super::APP_DIR_NAME;

/// Per-user base folders of the current user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseDirs {
    /// Windows: `FOLDERID_Profile`. macOS/Linux: `pw_dir` of the effective uid.
    pub home: PathBuf,
    /// Windows: `FOLDERID_LocalAppData`. `None` on macOS/Linux.
    pub local_app_data: Option<PathBuf>,
    /// Windows: `FOLDERID_RoamingAppData`. `None` on macOS/Linux.
    pub roaming_app_data: Option<PathBuf>,
}

/// Default data and config dirs offered at first run (§7.7 Data dir, Config).
/// The wizard (M6) pins the chosen values in this host's `paths.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstRunDefaults {
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
}

impl BaseDirs {
    /// `local_app_data`, or `<home>\AppData\Local` for a hand-built value
    /// without it. `base_dirs()` always sets it on Windows.
    #[cfg(windows)]
    pub(crate) fn local_app_data_or_default(&self) -> PathBuf {
        self.local_app_data
            .clone()
            .unwrap_or_else(|| self.home.join("AppData").join("Local"))
    }

    /// `roaming_app_data`, or `<home>\AppData\Roaming` for a hand-built value
    /// without it. `base_dirs()` always sets it on Windows.
    #[cfg(windows)]
    pub(crate) fn roaming_app_data_or_default(&self) -> PathBuf {
        self.roaming_app_data
            .clone()
            .unwrap_or_else(|| self.home.join("AppData").join("Roaming"))
    }
}

/// Resolves the current user's base folders. Reads no environment variable.
///
/// The known-folder values in the registry are `REG_EXPAND_SZ` strings such as
/// `%USERPROFILE%\AppData\Local`. An explicit process token makes the shell
/// resolve the folders for the token's user instead of for whatever the
/// calling session's environment says. Measured on Windows 11: a null token
/// also returned the right folders under a bogus `USERPROFILE`, so the token
/// is defence in depth. `path_stability_ignores_session_environment` asserts
/// the outcome either way.
#[cfg(windows)]
pub fn base_dirs() -> io::Result<BaseDirs> {
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_LocalAppData, FOLDERID_Profile, FOLDERID_RoamingAppData,
    };
    let token = ProcessToken::open()?;
    Ok(BaseDirs {
        home: known_folder(&FOLDERID_Profile, &token)?,
        local_app_data: Some(known_folder(&FOLDERID_LocalAppData, &token)?),
        roaming_app_data: Some(known_folder(&FOLDERID_RoamingAppData, &token)?),
    })
}

/// The current process's primary token, opened with the rights
/// `SHGetKnownFolderPath` documents for its `hToken` argument.
#[cfg(windows)]
struct ProcessToken(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl ProcessToken {
    fn open() -> io::Result<Self> {
        use windows_sys::Win32::Security::{TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let mut handle: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
        // closing; `handle` is a valid out-pointer.
        let ok = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE,
                &mut handle,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }
}

#[cfg(windows)]
impl Drop for ProcessToken {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcessToken and is closed once.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(windows)]
fn known_folder(id: &windows_sys::core::GUID, token: &ProcessToken) -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{KF_FLAG_DEFAULT, SHGetKnownFolderPath};

    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `id` points to a valid GUID, `token.0` is an open token handle,
    // and `raw` receives a CoTaskMemAlloc'ed NUL-terminated string.
    let hr = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT as u32, token.0, &mut raw) };
    let result = if hr >= 0 && !raw.is_null() {
        let mut len = 0usize;
        // SAFETY: on success `raw` is NUL-terminated.
        while unsafe { *raw.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `raw` is valid for `len` u16 reads.
        let wide = unsafe { std::slice::from_raw_parts(raw, len) };
        Ok(PathBuf::from(OsString::from_wide(wide)))
    } else {
        Err(io::Error::from_raw_os_error(hr))
    };
    // SAFETY: the caller frees the buffer whether the call succeeded or not
    // (SHGetKnownFolderPath docs); CoTaskMemFree(NULL) is a no-op.
    unsafe { CoTaskMemFree(raw as *const core::ffi::c_void) };
    result
}

/// Resolves the current user's base folders from the passwd database
/// (`getpwuid_r(geteuid())`). Reads no environment variable.
#[cfg(unix)]
pub fn base_dirs() -> io::Result<BaseDirs> {
    Ok(BaseDirs {
        home: passwd_home()?,
        local_app_data: None,
        roaming_app_data: None,
    })
}

#[cfg(unix)]
fn passwd_home() -> io::Result<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    // SAFETY: sysconf has no preconditions.
    let hint = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buf_len = usize::try_from(hint)
        .ok()
        .filter(|n| *n > 0)
        .unwrap_or(1024);
    loop {
        let mut buf = vec![0 as libc::c_char; buf_len];
        // SAFETY: an all-zero passwd is a valid value for an out-parameter.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: all pointers are valid; `buf` is writable for `buf.len()`.
        let rc =
            unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found) };
        if rc == libc::ERANGE && buf_len < (1 << 20) {
            buf_len *= 2;
            continue;
        }
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        if found.is_null() || pwd.pw_dir.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no passwd entry for the effective uid",
            ));
        }
        // SAFETY: `pw_dir` points into `buf`, NUL-terminated, alive here.
        let dir = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
        if dir.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "passwd entry has an empty home directory",
            ));
        }
        return Ok(PathBuf::from(OsStr::from_bytes(dir)));
    }
}

/// First-run defaults (§7.7). `env` is consulted only on Linux, only for
/// `XDG_DATA_HOME` and `XDG_CONFIG_HOME`, and only here: the result is pinned
/// in `paths.toml` and later starts never read XDG again (§7.7 Path
/// stability). A relative or empty XDG value is ignored, as the XDG Base
/// Directory specification requires. Callers pass
/// `&|name| std::env::var_os(name)`; tests inject values.
#[cfg(windows)]
pub fn first_run_defaults(
    b: &BaseDirs,
    _env: &dyn Fn(&str) -> Option<OsString>,
) -> FirstRunDefaults {
    FirstRunDefaults {
        data_dir: b.local_app_data_or_default().join(APP_DIR_NAME),
        config_dir: b.roaming_app_data_or_default().join(APP_DIR_NAME),
    }
}

/// First-run defaults (§7.7). On macOS the data dir and the config dir are
/// both `<home>/Library/Application Support/atlas-duck`; `env` is not read.
#[cfg(target_os = "macos")]
pub fn first_run_defaults(
    b: &BaseDirs,
    _env: &dyn Fn(&str) -> Option<OsString>,
) -> FirstRunDefaults {
    let dir = b
        .home
        .join("Library")
        .join("Application Support")
        .join(APP_DIR_NAME);
    FirstRunDefaults {
        data_dir: dir.clone(),
        config_dir: dir,
    }
}

/// First-run defaults (§7.7): data `$XDG_DATA_HOME/atlas-duck`, else
/// `<home>/.local/share/atlas-duck`; config `$XDG_CONFIG_HOME/atlas-duck`,
/// else `<home>/.config/atlas-duck`.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn first_run_defaults(
    b: &BaseDirs,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> FirstRunDefaults {
    let xdg = |name: &str, fallback: &[&str]| -> PathBuf {
        env(name)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| fallback.iter().fold(b.home.clone(), |p, part| p.join(part)))
    };
    FirstRunDefaults {
        data_dir: xdg("XDG_DATA_HOME", &[".local", "share"]).join(APP_DIR_NAME),
        config_dir: xdg("XDG_CONFIG_HOME", &[".config"]).join(APP_DIR_NAME),
    }
}
