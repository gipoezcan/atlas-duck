//! Host name for the host-qualified pinned files and the §3.1 socket-dir
//! fallback. Source per OS (plan decision; §15 V28 is open):
//! - macOS: `LocalHostName` (`SCDynamicStoreCopyLocalHostName`), else the
//!   `gethostname()` short name (the text before the first `.`).
//! - Linux: the static host name (first non-comment line of `/etc/hostname`),
//!   else `gethostname()`.
//! - Windows: `GetComputerNameExW(ComputerNamePhysicalDnsHostname)`. It is
//!   used only for the `instance.lock` holder record, because Windows pinned
//!   files are not host-qualified.

use std::fmt::Write as _;
use std::io;

/// Upper bound for the length of a sanitized host component, in bytes.
pub const MAX_HOST_COMPONENT_LEN: usize = 240;

/// Marker that introduces the hash suffix of an over-long component. `h` is
/// not a hex digit, so no escaped byte (`_xx`) can produce this sequence.
const HASH_MARK: &str = "_h";
/// Component used for an empty host name. `m` is not a hex digit either.
const EMPTY_COMPONENT: &str = "_empty";

/// This host's name as a filename-safe component:
/// `sanitize_host_component(raw_host_name()?)`.
pub fn host_name() -> io::Result<String> {
    Ok(sanitize_host_component(&raw_host_name()?))
}

/// Maps any host name to a deterministic component that matches
/// `^[a-z0-9._-]{1,240}$`, contains no `..` and neither starts nor ends with
/// `.`.
///
/// ASCII letters are lower-cased first (host names are case-insensitive).
/// `a-z`, `0-9` and `-` stay as they are. `.` stays when it is neither the
/// first nor the last byte and does not follow another literal `.`. Every
/// other byte (including `_` and each UTF-8 byte of a non-ASCII character)
/// becomes `_` plus two lowercase hex digits, so the mapping is injective on
/// the lower-cased input. A result longer than 240 bytes is cut at an escape
/// boundary to at most 222 bytes and suffixed with `_h` plus the
/// 16-hex-digit FNV-1a-64 hash of the whole lower-cased input.
///
/// The mapping is a stable contract: changing it renames every host's pinned
/// files and sends those hosts back to the first-run wizard.
pub fn sanitize_host_component(raw: &str) -> String {
    let lower: Vec<u8> = raw.bytes().map(|b| b.to_ascii_lowercase()).collect();
    if lower.is_empty() {
        return EMPTY_COMPONENT.to_owned();
    }
    let mut out = String::with_capacity(lower.len());
    // Byte offsets in `out` at which an encoded unit ends.
    let mut unit_ends = Vec::with_capacity(lower.len());
    let last = lower.len() - 1;
    for (i, &b) in lower.iter().enumerate() {
        let literal = match b {
            b'a'..=b'z' | b'0'..=b'9' | b'-' => true,
            b'.' => i != 0 && i != last && !out.ends_with('.'),
            _ => false,
        };
        if literal {
            out.push(char::from(b));
        } else {
            // Writing into a String cannot fail.
            let _ = write!(out, "_{b:02x}");
        }
        unit_ends.push(out.len());
    }
    if out.len() <= MAX_HOST_COMPONENT_LEN {
        return out;
    }
    let budget = MAX_HOST_COMPONENT_LEN - HASH_MARK.len() - 16;
    let cut = unit_ends
        .iter()
        .copied()
        .take_while(|&end| end <= budget)
        .last()
        .unwrap_or(0);
    format!("{}{HASH_MARK}{:016x}", &out[..cut], fnv1a64(&lower))
}

/// FNV-1a, 64 bit. Fixed by its definition, unlike
/// `std::hash::DefaultHasher`, whose output may change between Rust releases.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// The unsanitized host name from the per-OS source in the module docs.
#[cfg(target_os = "linux")]
pub fn raw_host_name() -> io::Result<String> {
    if let Ok(text) = std::fs::read_to_string("/etc/hostname")
        && let Some(name) = static_host_name(&text)
    {
        return Ok(name.to_owned());
    }
    unix_gethostname()
}

/// First non-empty line of `/etc/hostname` that is not a `#` comment,
/// trimmed (hostname(5)).
#[cfg(target_os = "linux")]
fn static_host_name(text: &str) -> Option<&str> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
}

/// The unsanitized host name from the per-OS source in the module docs.
#[cfg(target_os = "macos")]
pub fn raw_host_name() -> io::Result<String> {
    if let Some(name) = mac_local_host_name() {
        return Ok(name);
    }
    let full = unix_gethostname()?;
    let short = full.split('.').next().unwrap_or_default();
    if short.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "empty host name"));
    }
    Ok(short.to_owned())
}

#[cfg(target_os = "macos")]
fn mac_local_host_name() -> Option<String> {
    use core_foundation::base::TCFType;
    use core_foundation::string::{CFString, CFStringRef};
    use system_configuration_sys::dynamic_store_copy_specific::SCDynamicStoreCopyLocalHostName;

    // SAFETY: Apple documents NULL as a valid store argument (a temporary
    // session is used). The function returns NULL or a CFString that the
    // caller owns (Copy rule).
    let raw: CFStringRef = unsafe { SCDynamicStoreCopyLocalHostName(std::ptr::null()) };
    if raw.is_null() {
        return None;
    }
    // SAFETY: `raw` is non-null and owned by us; the wrapper releases it once.
    let name = unsafe { CFString::wrap_under_create_rule(raw) }.to_string();
    (!name.is_empty()).then_some(name)
}

#[cfg(unix)]
fn unix_gethostname() -> io::Result<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is valid for writes of `buf.len()` bytes.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    if end == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "empty host name"));
    }
    // Lossy is acceptable: the result is only ever sanitized into a
    // component, and the mapping stays deterministic.
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// The unsanitized host name from the per-OS source in the module docs.
#[cfg(windows)]
pub fn raw_host_name() -> io::Result<String> {
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNamePhysicalDnsHostname, GetComputerNameExW,
    };

    let mut len: u32 = 0;
    // SAFETY: a null buffer with size 0 asks for the required size (including
    // the terminating NUL); the call fails with ERROR_MORE_DATA and sets `len`.
    unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            std::ptr::null_mut(),
            &mut len,
        )
    };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: `buf` holds `len` u16 elements, which is the size passed in.
    let ok =
        unsafe { GetComputerNameExW(ComputerNamePhysicalDnsHostname, buf.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // On success `len` is the number of characters without the NUL.
    buf.truncate(len as usize);
    if buf.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "empty host name"));
    }
    Ok(String::from_utf16_lossy(&buf))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::static_host_name;

    #[test]
    fn static_host_name_skips_comments_and_blank_lines() {
        assert_eq!(
            static_host_name("# managed\n\n  build-01 \n"),
            Some("build-01")
        );
        assert_eq!(static_host_name("\n# only a comment\n"), None);
        assert_eq!(static_host_name(""), None);
    }
}
