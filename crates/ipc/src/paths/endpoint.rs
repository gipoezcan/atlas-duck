//! Endpoint location, the `<data>/endpoint` file and the Unix socket dir
//! (§3.1 Endpoint discovery, Windows, Linux, macOS; PD-01, PD-26).
//!
//! `endpoint_location` is the one shared function the app and the CLI use.
//! Unix: the socket path in the per-user socket dir. Windows: the pipe-name
//! prefix `\\.\pipe\atlas-duck-<first 16 hex of SHA-256(user SID)>-`, to which
//! the server appends 32 random hex digits on every start.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::LocalDataDir;

/// File name of the endpoint file in the data dir (§3.1, PD-26).
pub const ENDPOINT_FILE: &str = "endpoint";
/// File name of the Unix socket in the socket dir.
pub const SOCKET_FILE_NAME: &str = "atlas-duck.sock";
/// Longest endpoint name, in bytes, the endpoint file may hold.
pub const MAX_ENDPOINT_NAME_LEN: usize = 512;

/// Head of every pipe name; the SID hash and a `-` follow.
#[cfg(any(windows, test))]
const PIPE_NAME_HEAD: &str = r"\\.\pipe\atlas-duck-";
/// Number of random lowercase hex digits after the pipe-name prefix.
const PIPE_SUFFIX_HEX_LEN: usize = 32;

const MSG_BAD_NAME: &str = "endpoint name is empty, over 512 bytes or contains a control character";
const MSG_BAD_FILE: &str =
    "endpoint file is empty, over 512 bytes, not UTF-8 or contains a control character";

/// Where the endpoint lives (master plan C.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointLocation {
    /// Unix: the absolute socket path.
    UnixSocket(PathBuf),
    /// Windows: the pipe-name prefix, ending in `-`.
    WindowsPipePrefix(String),
}

/// The endpoint location for this user (§3.1 Endpoint discovery): Unix
/// `socket_dir(host)?/atlas-duck.sock`. The data dir is part of the shared
/// signature (C.2) but does not enter the location.
#[cfg(unix)]
pub fn endpoint_location(_data: &LocalDataDir, host: &str) -> io::Result<EndpointLocation> {
    Ok(EndpointLocation::UnixSocket(
        socket_dir(host)?.join(SOCKET_FILE_NAME),
    ))
}

/// The endpoint location for this user (§3.1 Endpoint discovery): Windows
/// the pipe-name prefix derived from the process token's user SID. Neither
/// the data dir nor the host enters it.
#[cfg(windows)]
pub fn endpoint_location(_data: &LocalDataDir, _host: &str) -> io::Result<EndpointLocation> {
    Ok(EndpointLocation::WindowsPipePrefix(pipe_prefix_for_sid(
        &current_user_sid_string()?,
    )))
}

/// `\\.\pipe\atlas-duck-<first 16 hex of SHA-256(UTF-8 of sid)>-`.
#[cfg(any(windows, test))]
fn pipe_prefix_for_sid(sid: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(sid.as_bytes());
    let head = digest.get(..8).unwrap_or_default();
    format!("{PIPE_NAME_HEAD}{}-", hex_lower(head))
}

#[cfg(any(windows, test))]
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing into a String cannot fail.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// True iff `name` is `prefix` followed by exactly 32 lowercase hex digits
/// and nothing else (§3.1: a pipe name in the endpoint file that does not
/// carry the user's SID-derived prefix means "not running"). An empty
/// `prefix` matches nothing.
pub fn pipe_name_has_prefix(name: &str, prefix: &str) -> bool {
    !prefix.is_empty()
        && name.strip_prefix(prefix).is_some_and(|rest| {
            rest.len() == PIPE_SUFFIX_HEX_LEN
                && rest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// The current process token's user SID in `ConvertSidToStringSidW` form
/// (`S-1-5-21-…`).
#[cfg(windows)]
pub fn current_user_sid_string() -> io::Result<String> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_USER, TokenUser};

    let token = super::base_dirs::ProcessToken::open()?;
    let mut needed = 0u32;
    // SAFETY: a size probe: null buffer of length 0, `needed` is a valid out-pointer.
    let ok = unsafe {
        GetTokenInformation(
            token.handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if ok == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(err);
        }
    }
    let len = usize::try_from(needed).unwrap_or(0);
    if len < std::mem::size_of::<TOKEN_USER>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TokenUser size probe returned too small a size",
        ));
    }
    // u64 elements keep the buffer aligned for TOKEN_USER.
    let mut buf = vec![0u64; len.div_ceil(8)];
    // SAFETY: `buf` is writable for at least `needed` bytes.
    let ok = unsafe {
        GetTokenInformation(
            token.handle(),
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success the buffer starts with an initialized, aligned TOKEN_USER
    // whose SID points into `buf`, which stays alive below.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID; `raw` receives a LocalAlloc'ed string.
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 || raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut n = 0usize;
    // SAFETY: on success `raw` is NUL-terminated.
    while unsafe { *raw.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: `raw` is valid for `n` u16 reads.
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, n) });
    // SAFETY: `raw` came from ConvertSidToStringSidW, which documents LocalFree.
    unsafe { LocalFree(raw as HLOCAL) };
    text.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SID string is not UTF-16"))
}

// ---------- Unix socket dir ----------

#[cfg(any(unix, test))]
const MSG_DIR_SYMLINK: &str = "socket dir check failed: it is a symlink";
#[cfg(any(unix, test))]
const MSG_DIR_OWNER: &str = "socket dir check failed: not owned by the effective uid";
#[cfg(any(unix, test))]
const MSG_DIR_MODE: &str = "socket dir check failed: mode is not exactly 0700";
#[cfg(unix)]
const MSG_DIR_NOT_DIR: &str = "socket dir check failed: not a directory";
#[cfg(unix)]
const MSG_BAD_HOST: &str = "host is not a sanitized host component";

/// The §3.1 owner/mode/symlink check on `lstat` values: not a symlink,
/// owner == `euid`, permission bits (incl. setuid, setgid, sticky) exactly
/// 0700. The file type bits of `mode` are ignored.
#[cfg(any(unix, test))]
fn check_dir_meta(uid: u32, mode: u32, is_symlink: bool, euid: u32) -> io::Result<()> {
    if is_symlink {
        return Err(denied(MSG_DIR_SYMLINK));
    }
    if uid != euid {
        return Err(denied(MSG_DIR_OWNER));
    }
    if mode & 0o7777 != 0o700 {
        return Err(denied(MSG_DIR_MODE));
    }
    Ok(())
}

#[cfg(any(unix, test))]
fn denied(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg)
}

#[cfg(unix)]
fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

/// The socket dir for this user (§3.1). Computes only; `ensure_socket_dir`
/// creates and checks it. `host` must be a sanitized host component
/// (`host_name()`), else `InvalidInput`.
///
/// Linux: `/run/user/<euid>/atlas-duck/` iff `/run/user/<euid>` is a
/// directory (`lstat`, not a symlink) owned by the euid with mode exactly
/// 0700; else `<passwd home>/.local/state/atlas-duck/run-<host>/`.
/// `$XDG_RUNTIME_DIR` is never read.
///
/// macOS: `confstr(_CS_DARWIN_USER_TEMP_DIR)` + `atlas-duck/` when the
/// socket path in it is under 104 bytes, else
/// `<passwd home>/Library/Caches/atlas-duck/`. Never `$TMPDIR`, never `/tmp`.
///
/// Feature `test-paths` (PD-01): `<ATLAS_DUCK_TEST_HOME>/s/` when the
/// variable is set.
#[cfg(unix)]
pub fn socket_dir(host: &str) -> io::Result<PathBuf> {
    if super::sanitize_host_component(host) != host {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, MSG_BAD_HOST));
    }
    #[cfg(feature = "test-paths")]
    if let Some(home) = super::base_dirs::test_home()? {
        return Ok(home.join("s"));
    }
    os_socket_dir(host)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn os_socket_dir(host: &str) -> io::Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let uid = euid();
    let run = PathBuf::from(format!("/run/user/{uid}"));
    let run_ok = fs::symlink_metadata(&run).is_ok_and(|m| {
        m.file_type().is_dir()
            && check_dir_meta(m.uid(), m.mode(), m.file_type().is_symlink(), uid).is_ok()
    });
    if run_ok {
        return Ok(run.join(super::APP_DIR_NAME));
    }
    Ok(super::base_dirs()?
        .home
        .join(".local")
        .join("state")
        .join(super::APP_DIR_NAME)
        .join(format!("run-{host}")))
}

/// `sun_path` size on macOS, including the terminating NUL.
#[cfg(target_os = "macos")]
const SUN_PATH_LEN: usize = 104;

#[cfg(target_os = "macos")]
fn os_socket_dir(_host: &str) -> io::Result<PathBuf> {
    let fits = |dir: &Path| dir.join(SOCKET_FILE_NAME).as_os_str().len() < SUN_PATH_LEN;
    if let Some(temp) = darwin_user_temp_dir() {
        let dir = temp.join(super::APP_DIR_NAME);
        if fits(&dir) {
            return Ok(dir);
        }
    }
    let dir = super::base_dirs()?
        .home
        .join("Library")
        .join("Caches")
        .join(super::APP_DIR_NAME);
    if fits(&dir) {
        Ok(dir)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path is 104 bytes or longer",
        ))
    }
}

/// `confstr(_CS_DARWIN_USER_TEMP_DIR)`, or `None` when it fails or is not an
/// absolute path.
#[cfg(target_os = "macos")]
fn darwin_user_temp_dir() -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: a null buffer of length 0 asks for the size including the NUL.
    let needed = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, std::ptr::null_mut(), 0) };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u8; needed];
    // SAFETY: `buf` is writable for `buf.len()` bytes.
    let written = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
        )
    };
    if written == 0 || written > buf.len() {
        return None;
    }
    let bytes = CStr::from_bytes_until_nul(&buf).ok()?.to_bytes();
    let path = PathBuf::from(OsStr::from_bytes(bytes));
    path.is_absolute().then_some(path)
}

/// Creates `dir` if missing and checks it (§3.1). Missing parents and `dir`
/// itself are created with mode 0700; existing directories are never
/// changed. Then `lstat(dir)` must show a directory, not a symlink, owned by
/// the euid with mode exactly 0700, else `PermissionDenied` naming the check.
#[cfg(unix)]
pub fn ensure_socket_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    create_private_dirs(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    check_dir_meta(
        meta.uid(),
        meta.mode(),
        meta.file_type().is_symlink(),
        euid(),
    )?;
    if !meta.file_type().is_dir() {
        return Err(denied(MSG_DIR_NOT_DIR));
    }
    Ok(())
}

/// Creates the missing directories of `dir`, outermost first, each with mode
/// 0700 regardless of the umask. Directories that already exist (or that
/// appear concurrently) are left alone.
#[cfg(unix)]
fn create_private_dirs(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let mut missing = Vec::new();
    let mut cur = dir;
    loop {
        match fs::symlink_metadata(cur) {
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                missing.push(cur);
                match cur.parent() {
                    Some(p) if !p.as_os_str().is_empty() => cur = p,
                    _ => break,
                }
            }
            Err(e) => return Err(e),
        }
    }
    for d in missing.into_iter().rev() {
        match fs::DirBuilder::new().mode(0o700).create(d) {
            Ok(()) => fs::set_permissions(d, fs::Permissions::from_mode(0o700))?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ---------- endpoint file ----------

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn valid_endpoint_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_ENDPOINT_NAME_LEN && !name.chars().any(char::is_control)
}

/// Writes `name` as the whole content of `<data>/endpoint` (PD-26): a temp
/// file in the data dir, flushed, then renamed over the old file, so a
/// reader sees the old or the new name, never a partial one. Unix mode 0600.
/// Never creates the data dir. A name that `read_endpoint_file` would refuse
/// is `InvalidInput`.
pub fn write_endpoint_file(data: &LocalDataDir, name: &str) -> io::Result<()> {
    if !valid_endpoint_name(name) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, MSG_BAD_NAME));
    }
    let dir = data.path();
    let tmp = dir.join(format!(
        ".{ENDPOINT_FILE}.{}.{}.tmp",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = create_endpoint_temp(&tmp)?;
    let written = (|| -> io::Result<()> {
        file.write_all(name.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, dir.join(ENDPOINT_FILE))
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    if let Ok(d) = fs::File::open(dir) {
        // Best effort: persist the rename itself.
        let _ = d.sync_all();
    }
    Ok(())
}

/// Creates the temp file exclusively with mode 0600 (set again after the
/// open, so the umask cannot widen or narrow it).
#[cfg(unix)]
fn create_endpoint_temp(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Creates the temp file exclusively.
#[cfg(windows)]
fn create_endpoint_temp(path: &Path) -> io::Result<fs::File> {
    // Task 6: create with the owner-only descriptor of
    // `transport::windows::security::owner_only_attributes()` (PD-26). Until
    // then the file inherits the data dir's default ACL.
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Reads `<data>/endpoint`. Missing file → `None`. Empty, over 512 bytes,
/// not UTF-8 or containing a control character (incl. a trailing newline)
/// → `InvalidData`. Reads at most 513 bytes.
pub fn read_endpoint_file(data: &LocalDataDir) -> io::Result<Option<String>> {
    let file = match fs::File::open(data.path().join(ENDPOINT_FILE)) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::with_capacity(MAX_ENDPOINT_NAME_LEN + 1);
    file.take(MAX_ENDPOINT_NAME_LEN as u64 + 1)
        .read_to_end(&mut bytes)?;
    match String::from_utf8(bytes) {
        Ok(name) if valid_endpoint_name(&name) => Ok(Some(name)),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, MSG_BAD_FILE)),
    }
}

/// Removes `<data>/endpoint`; a missing file is not an error.
pub fn remove_endpoint_file(data: &LocalDataDir) -> io::Result<()> {
    match fs::remove_file(data.path().join(ENDPOINT_FILE)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_dir_meta_owner_mode_symlink() {
        assert!(check_dir_meta(1000, 0o700, false, 1000).is_ok());
        // File type bits (S_IFDIR) are ignored.
        assert!(check_dir_meta(1000, 0o40700, false, 1000).is_ok());

        let fails = |uid, mode, link, euid, msg: &str| {
            let err = check_dir_meta(uid, mode, link, euid).expect_err("accepted");
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(err.to_string(), msg);
        };
        // Wrong owner, including root-owned for a non-root euid and vice versa.
        fails(1001, 0o700, false, 1000, MSG_DIR_OWNER);
        fails(0, 0o700, false, 1000, MSG_DIR_OWNER);
        fails(1000, 0o700, false, 0, MSG_DIR_OWNER);
        // Mode not exactly 0700.
        for mode in [0o755, 0o750, 0o701, 0o600, 0o1700, 0o2700, 0o4700, 0o777] {
            fails(1000, mode, false, 1000, MSG_DIR_MODE);
        }
        // A symlink fails first, whatever else holds.
        fails(1000, 0o700, true, 1000, MSG_DIR_SYMLINK);
        fails(1001, 0o777, true, 1000, MSG_DIR_SYMLINK);
    }

    #[test]
    fn pipe_prefix_golden() {
        // SHA-256("S-1-5-18") starts 593347bdfcc9bfa7; SHA-256("S-1-5-21-1-2-3-1001") c169ebe52e9c0ba4.
        assert_eq!(
            pipe_prefix_for_sid("S-1-5-18"),
            r"\\.\pipe\atlas-duck-593347bdfcc9bfa7-"
        );
        assert_eq!(
            pipe_prefix_for_sid("S-1-5-21-1-2-3-1001"),
            r"\\.\pipe\atlas-duck-c169ebe52e9c0ba4-"
        );
    }

    #[test]
    fn empty_prefix_matches_nothing() {
        assert!(!pipe_name_has_prefix(
            "0123456789abcdef0123456789abcdef",
            ""
        ));
    }
}
