//! The AppContainer profile (§9.4): one per Windows user, zero capabilities.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::FreeSid;
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
    DeriveAppContainerSidFromAppContainerName, GetAppContainerFolderPath,
};
use windows_sys::Win32::Security::PSID;
use windows_sys::Win32::System::Com::CoTaskMemFree;

use super::{from_wide_ptr, hresult_error, wide};

/// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)`.
const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00B7_u32 as i32;

/// `HRESULT_FROM_WIN32(ERROR_NOT_FOUND)`: no such profile.
const HRESULT_NOT_FOUND: i32 = 0x8007_0490_u32 as i32;

/// Name of the folder (inside the container's `AC` folder) that holds the
/// per-run working directories.
const RUN_ROOT_NAME: &str = "atlas-duck-run";

/// Deletes the AppContainer profile `name` of the current Windows user (its
/// registry mapping and its `%LOCALAPPDATA%\Packages\<name>` folder). A profile
/// that does not exist is not an error. M1 never calls this from the app (the
/// uninstall hook is M10); the T19 tests use it to leave no profile behind.
pub fn delete_appcontainer_profile(name: &str) -> io::Result<()> {
    let wname = wide(OsStr::new(name));
    // SAFETY: `wname` is NUL-terminated.
    let hr = unsafe { DeleteAppContainerProfile(wname.as_ptr()) };
    if hr >= 0 || hr == HRESULT_NOT_FOUND {
        Ok(())
    } else {
        Err(hresult_error(hr))
    }
}

/// Serialises profile creation inside this process.
static OPEN_LOCK: Mutex<()> = Mutex::new(());

/// The container's SID and its storage folder.
pub(crate) struct AppContainer {
    sid: PSID,
    sid_string: String,
    local_app_data: PathBuf,
    run_root: PathBuf,
}

// SAFETY: the SID is immutable after creation and only read or freed on drop.
unsafe impl Send for AppContainer {}
// SAFETY: see above; no interior mutability.
unsafe impl Sync for AppContainer {}

impl AppContainer {
    /// Creates the profile `name` or, when it exists already (every start
    /// after the first), derives its SID. Fails when profile creation is
    /// blocked (policy): there is no weaker fallback here (M8).
    pub(crate) fn open(name: &str) -> io::Result<Self> {
        // Measured: two threads creating the profile at the same time (first
        // start, nothing exists yet) make some `CreateAppContainerProfile`
        // calls fail with an error other than ALREADY_EXISTS. One at a time.
        let _guard = OPEN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let wname = wide(OsStr::new(name));
        let mut sid: PSID = null_mut();
        // SAFETY: `wname` is NUL-terminated; zero capabilities are given as
        // (NULL, 0); `sid` is a valid out-pointer.
        let hr = unsafe {
            CreateAppContainerProfile(
                wname.as_ptr(),
                wname.as_ptr(),
                wname.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        if hr == HRESULT_ALREADY_EXISTS {
            // SAFETY: as above.
            let hr = unsafe { DeriveAppContainerSidFromAppContainerName(wname.as_ptr(), &mut sid) };
            if hr < 0 {
                return Err(hresult_error(hr));
            }
        } else if hr < 0 {
            return Err(hresult_error(hr));
        }

        let mut container = Self {
            sid,
            sid_string: String::new(),
            local_app_data: PathBuf::new(),
            run_root: PathBuf::new(),
        };
        container.sid_string = container.sid_to_string()?;
        let ac = container.folder()?;
        // Measured on Windows 11: the folder is `<LOCALAPPDATA>\Packages\<name>\AC`.
        // The container's `LOCALAPPDATA` is that folder, and `CreateProcessW`
        // derives it from the `LOCALAPPDATA` it is given, so the host passes
        // the matching parent (see `spawner::environment_block`).
        container.local_app_data = ac
            .ancestors()
            .nth(3)
            .filter(|_| ac.file_name().is_some_and(|n| n.eq_ignore_ascii_case("AC")))
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                io::Error::other(format!(
                    "unexpected AppContainer folder layout: {}",
                    ac.display()
                ))
            })?;
        container.run_root = ac.join(RUN_ROOT_NAME);
        Ok(container)
    }

    pub(crate) fn sid(&self) -> PSID {
        self.sid
    }

    pub(crate) fn sid_string(&self) -> &str {
        &self.sid_string
    }

    /// The `LOCALAPPDATA` that yields this container's own `LOCALAPPDATA`
    /// (`<this>\Packages\<name>\AC`) and `TEMP`/`TMP` (`...\AC\Temp`).
    pub(crate) fn local_app_data(&self) -> &Path {
        &self.local_app_data
    }

    /// Parent of the per-run directories.
    pub(crate) fn run_root(&self) -> &Path {
        &self.run_root
    }

    fn sid_to_string(&self) -> io::Result<String> {
        let mut p: *mut u16 = null_mut();
        // SAFETY: `sid` is a valid SID; `p` is a valid out-pointer.
        if unsafe { ConvertSidToStringSidW(self.sid, &mut p) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `p` is a NUL-terminated string allocated by the call above.
        let s = unsafe { from_wide_ptr(p) };
        // SAFETY: allocated by ConvertSidToStringSidW, freed once.
        unsafe { LocalFree(p.cast()) };
        Ok(s)
    }

    /// The container's own folder, `%LOCALAPPDATA%\Packages\<name>\AC`, which
    /// it can always use (LPAC or not).
    fn folder(&self) -> io::Result<PathBuf> {
        let wsid = wide(OsStr::new(&self.sid_string));
        let mut p: *mut u16 = null_mut();
        // SAFETY: `wsid` is NUL-terminated; `p` is a valid out-pointer.
        let hr = unsafe { GetAppContainerFolderPath(wsid.as_ptr(), &mut p) };
        if hr < 0 {
            return Err(hresult_error(hr));
        }
        // SAFETY: `p` is a NUL-terminated string allocated by the call above.
        let s = unsafe { from_wide_ptr(p) };
        // SAFETY: allocated with CoTaskMemAlloc, freed once.
        unsafe { CoTaskMemFree(p.cast()) };
        Ok(PathBuf::from(s))
    }
}

impl Drop for AppContainer {
    fn drop(&mut self) {
        // SAFETY: the SID came from CreateAppContainerProfile or
        // DeriveAppContainerSidFromAppContainerName, which document FreeSid.
        unsafe { FreeSid(self.sid) };
    }
}
