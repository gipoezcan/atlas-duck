//! Windows: the per-user WinINet settings that browsers and the Settings app write, under
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`. WinHTTP's machine-wide
//! `WinHttpSettings` blob is not read: its layout is only partly documented, and the per-user
//! value is what users configure (V17). The parsers and `read_with` are plain code so tests run
//! them against a fake registry on every OS.

use super::OsProxy;

/// The registry values this reader needs. `subkey` is `""` (Internet Settings itself) or
/// `"Connections"`.
pub trait RegistryReader {
    fn dword(&self, subkey: &str, name: &str) -> Option<u32>;
    fn string(&self, subkey: &str, name: &str) -> Option<String>;
    fn binary(&self, subkey: &str, name: &str) -> Option<Vec<u8>>;
}

/// `DefaultConnectionSettings` flag byte (offset 8): `0x08` is "automatically detect settings"
/// (WPAD); `0x04` is "use automatic configuration script", which `AutoConfigURL` also shows.
const CONN_FLAGS_OFFSET: usize = 8;
const FLAG_AUTO_DETECT: u8 = 0x08;
const FLAG_AUTO_SCRIPT: u8 = 0x04;

pub fn read_with(reg: &dyn RegistryReader) -> OsProxy {
    let enabled = reg.dword("", "ProxyEnable").is_some_and(|v| v != 0);
    let server = reg.string("", "ProxyServer").unwrap_or_default();
    let https = if enabled {
        parse_proxy_server(&server)
    } else {
        None
    };
    let bypass = reg
        .string("", "ProxyOverride")
        .map(|s| parse_proxy_override(&s))
        .unwrap_or_default();
    let auto_url = reg
        .string("", "AutoConfigURL")
        .is_some_and(|s| !s.trim().is_empty());
    let flags = reg
        .binary("Connections", "DefaultConnectionSettings")
        .and_then(|b| b.get(CONN_FLAGS_OFFSET).copied())
        .unwrap_or(0);
    OsProxy {
        https,
        bypass,
        pac_configured: auto_url || flags & (FLAG_AUTO_DETECT | FLAG_AUTO_SCRIPT) != 0,
    }
}

/// `host:port` (applies to every scheme) or `http=h:p;https=h:p;ftp=...`: the `https=` entry,
/// else the bare form. A scheme prefix on the value is dropped. No match is `None`, so a
/// per-scheme list without `https=` means HTTPS goes direct, as in WinINet.
pub fn parse_proxy_server(s: &str) -> Option<(String, u16)> {
    let entries: Vec<&str> = s
        .split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect();
    let https = entries.iter().find_map(|e| {
        let (scheme, value) = e.split_once('=')?;
        scheme.trim().eq_ignore_ascii_case("https").then_some(value)
    });
    let bare = entries.iter().find(|e| !e.contains('='));
    let value = https.or(bare.copied())?;
    let value = value.trim();
    let value = value
        .split_once("://")
        .map_or(value, |(_, rest)| rest)
        .trim_end_matches('/');
    super::split_host_port(value)
}

/// `ProxyOverride`: `;`-separated, may contain `<local>`.
pub fn parse_proxy_override(s: &str) -> Vec<String> {
    s.split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The real registry (HKCU).
#[cfg(windows)]
pub struct WinInetRegistry;

#[cfg(windows)]
impl WinInetRegistry {
    const BASE: &'static str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    fn raw(&self, subkey: &str, name: &str, flags: u32) -> Option<Vec<u8>> {
        use std::ptr::null_mut;
        use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
        use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RegGetValueW};

        let path = if subkey.is_empty() {
            Self::BASE.to_owned()
        } else {
            format!(r"{}\{subkey}", Self::BASE)
        };
        let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
        let (path, name) = (wide(&path), wide(name));
        let mut len: u32 = 0;
        // SAFETY: `path` and `name` are NUL-terminated and outlive the call; a null data
        // pointer asks only for the size.
        let rc = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                name.as_ptr(),
                flags,
                null_mut(),
                null_mut(),
                &mut len,
            )
        };
        if rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        // SAFETY: `buf` holds `len` bytes, which `len` tells the call.
        let rc = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                name.as_ptr(),
                flags,
                null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        buf.truncate(len as usize);
        Some(buf)
    }
}

#[cfg(windows)]
impl RegistryReader for WinInetRegistry {
    fn dword(&self, subkey: &str, name: &str) -> Option<u32> {
        use windows_sys::Win32::System::Registry::RRF_RT_REG_DWORD;
        let b = self.raw(subkey, name, RRF_RT_REG_DWORD)?;
        Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
    }

    fn string(&self, subkey: &str, name: &str) -> Option<String> {
        // REG_SZ only: expanding `REG_EXPAND_SZ` would consult the process environment.
        use windows_sys::Win32::System::Registry::RRF_RT_REG_SZ;
        let b = self.raw(subkey, name, RRF_RT_REG_SZ)?;
        let units: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|u| *u != 0)
            .collect();
        Some(String::from_utf16_lossy(&units))
    }

    fn binary(&self, subkey: &str, name: &str) -> Option<Vec<u8>> {
        use windows_sys::Win32::System::Registry::RRF_RT_REG_BINARY;
        self.raw(subkey, name, RRF_RT_REG_BINARY)
    }
}
