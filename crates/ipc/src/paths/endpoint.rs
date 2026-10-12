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
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
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
    crate::win_security::Sid::current_user()?.to_string_sid()
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

/// The output shape of `sanitize_host_component`: 1 to 240 bytes of
/// `[a-z0-9._-]`, no `..`, no leading or trailing `.`. Not idempotence:
/// `sanitize` escapes `_`, so a sanitized name with an escape in it is not
/// its own sanitization.
#[cfg(any(unix, test))]
fn is_host_component(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= super::MAX_HOST_COMPONENT_LEN
        && host
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
        && !host.contains("..")
        && !host.starts_with('.')
        && !host.ends_with('.')
}

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
pub(crate) fn euid() -> u32 {
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
    if !is_host_component(host) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, MSG_BAD_HOST));
    }
    #[cfg(feature = "test-paths")]
    if let Some(home) = super::base_dirs::test_home()? {
        return test_socket_dir(&home);
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
#[cfg(any(target_os = "macos", test))]
const SUN_PATH_LEN: usize = 104;

/// True iff the socket path in `dir` is under `SUN_PATH_LEN` bytes.
#[cfg(any(target_os = "macos", test))]
fn socket_path_fits(dir: &Path) -> bool {
    dir.join(SOCKET_FILE_NAME).as_os_str().len() < SUN_PATH_LEN
}

/// `<home>/s`, refused when the socket path in it would not fit `sun_path` on macOS.
#[cfg(all(unix, feature = "test-paths"))]
fn test_socket_dir(home: &Path) -> io::Result<PathBuf> {
    let dir = home.join("s");
    #[cfg(target_os = "macos")]
    if !socket_path_fits(&dir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path is 104 bytes or longer",
        ));
    }
    Ok(dir)
}

#[cfg(target_os = "macos")]
fn os_socket_dir(_host: &str) -> io::Result<PathBuf> {
    let fits = socket_path_fits;
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
    create_private_dirs(dir)?;
    check_socket_dir(dir)
}

/// The check half of `ensure_socket_dir`, for the CLI (§3.1 "before
/// connecting"): never creates anything. A missing `dir` is `NotFound` (the
/// app is not running); a failed check is `PermissionDenied`.
#[cfg(unix)]
pub fn check_socket_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
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
const TMP_ATTEMPTS: usize = 8;

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
    let (tmp, mut file) = create_unique_temp(dir)?;
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

/// Creates a fresh temp file in `dir`; a name that already exists is skipped
/// (next counter value), at most `TMP_ATTEMPTS` times.
fn create_unique_temp(dir: &Path) -> io::Result<(PathBuf, fs::File)> {
    let mut last = None;
    for _ in 0..TMP_ATTEMPTS {
        let tmp = dir.join(format!(
            ".{ENDPOINT_FILE}.{}.{}.tmp",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        match create_endpoint_temp(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists)))
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

/// Creates the temp file exclusively with the owner-only descriptor
/// (`owner_only_attributes`: owner and only ACE = the user SID, DACL
/// protected, PD-26). A same-volume rename keeps the descriptor.
#[cfg(windows)]
fn create_endpoint_temp(path: &Path) -> io::Result<fs::File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if wide.iter().take(wide.len() - 1).any(|&c| c == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL",
        ));
    }
    let security = crate::win_security::owner_only_attributes()?;
    let attrs = security.attributes();
    // SAFETY: `wide` is NUL-terminated; `attrs` points at a descriptor that
    // `security` keeps alive for the call; no template handle.
    let h = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attrs,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh file handle that nothing else owns.
    Ok(unsafe { fs::File::from_raw_handle(h as _) })
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

/// Removes the temp files a crashed `write_endpoint_file` left in the data dir
/// (`.endpoint.*.tmp`, regular files only, symlinks not followed). The server
/// calls it at bind, under `instance.lock`, so no writer is live. Returns how
/// many were removed.
pub fn sweep_endpoint_temps(data: &LocalDataDir) -> io::Result<usize> {
    let prefix = format!(".{ENDPOINT_FILE}.");
    let mut removed = 0;
    for entry in fs::read_dir(data.path())? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !(name.starts_with(&prefix) && name.ends_with(".tmp")) {
            continue;
        }
        if !fs::symlink_metadata(entry.path())?.is_file() {
            continue;
        }
        match fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
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
    fn host_component_shape() {
        use super::super::sanitize_host_component as sanitize;
        let long = sanitize(&"h".repeat(300));
        for ok in [
            "build-01",
            "mymac.local",
            "_empty",
            "a_5fb",
            sanitize("build_01").as_str(),
            sanitize("jürgen-mbp").as_str(),
            sanitize("").as_str(),
            sanitize("../../evil").as_str(),
            long.as_str(),
        ] {
            assert!(is_host_component(ok), "{ok:?} refused");
        }
        let too_long = "h".repeat(241);
        for bad in [
            "",
            "../evil",
            "a/b",
            "A",
            ".a",
            "a.",
            "a..b",
            "a b",
            "ü",
            too_long.as_str(),
        ] {
            assert!(!is_host_component(bad), "{bad:?} accepted");
        }
    }

    #[test]
    fn socket_path_fit_boundary() {
        // "/" + SOCKET_FILE_NAME is joined onto the dir; under 104 bytes fits.
        let base = SUN_PATH_LEN - 1 - SOCKET_FILE_NAME.len() - 1;
        let fits = format!("/{}", "a".repeat(base - 1));
        let too_long = format!("/{}", "a".repeat(base));
        assert!(socket_path_fits(Path::new(&fits)));
        assert!(!socket_path_fits(Path::new(&too_long)));
    }

    #[test]
    fn temp_name_collision_takes_next_counter() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let next = TMP_COUNTER.load(Ordering::Relaxed);
        // Pre-create the names the next attempts would pick (other tests may
        // advance the counter, so cover a window).
        for i in next..next + 3 {
            let name = format!(".{ENDPOINT_FILE}.{}.{i}.tmp", std::process::id());
            fs::write(tmp.path().join(name), b"x").expect("precreate");
        }
        let (path, _file) = create_unique_temp(tmp.path()).expect("unique temp");
        assert!(path.exists());
        assert_eq!(fs::read(&path).expect("read"), b"");
    }

    #[test]
    fn empty_prefix_matches_nothing() {
        assert!(!pipe_name_has_prefix(
            "0123456789abcdef0123456789abcdef",
            ""
        ));
    }
}
