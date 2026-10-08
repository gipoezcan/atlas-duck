//! The (L)PAC ACE set (§9.4 Windows).
//!
//! Both NSIS install modes grant `ALL APPLICATION PACKAGES` (S-1-15-2-1) and
//! `ALL RESTRICTED APPLICATION PACKAGES` (S-1-15-2-2) read+execute on the
//! worker binary and every DLL it loads. At each start the app checks them
//! and re-applies missing ones when it holds `WRITE_DAC` on the files
//! ([`ensure_aces`]).
//!
//! Meaning of the two ACEs here (plan reading of §9.4, "Less-Privileged
//! AppContainer where all needed ACEs exist"):
//! - `S-1-15-2-1` on a file is what a plain AppContainer needs to load it. A
//!   file without it is reported by [`check_aces`] as missing.
//! - `S-1-15-2-2` on every file additionally allows the LPAC opt-out
//!   (`AceStatus::AllPresent { lpac_ready: true }`).

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_SUCCESS, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
    NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID,
    TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, INHERIT_ONLY_ACE,
    NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, WRITE_DAC,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

use super::{SID_ALL_APP_PACKAGES, SID_ALL_RESTRICTED_APP_PACKAGES, wide};

/// File name of the worker binary in the install dir (§12.1).
pub const WORKER_EXE_NAME: &str = "atlas-duck-sandbox.exe";

/// Read+execute, what `icacls` prints as `(RX)`.
const RX_MASK: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

/// Result of [`check_aces`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AceStatus {
    /// Every file has the `S-1-15-2-1` read+execute ACE. `lpac_ready` is true
    /// when every file also has the `S-1-15-2-2` one.
    AllPresent { lpac_ready: bool },
    /// These files lack the `S-1-15-2-1` read+execute ACE.
    Missing(Vec<PathBuf>),
}

/// Result of [`ensure_aces`] (T20 logs it as
/// `ace=present|reapplied|missing_no_write_dac`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceEnsure {
    /// Both ACEs were on every file already.
    Present,
    /// At least one ACE was missing and has been re-applied.
    Reapplied,
    /// At least one ACE is missing and the app holds no `WRITE_DAC` on the
    /// files (per-machine install: needs a repair install). Nothing changed.
    MissingNoWriteDac,
}

/// A SID parsed from its string form, freed with `LocalFree`.
struct LocalSid(PSID);

impl LocalSid {
    fn parse(s: &str) -> io::Result<Self> {
        let w = wide(std::ffi::OsStr::new(s));
        let mut sid: PSID = null_mut();
        // SAFETY: `w` is NUL-terminated and `sid` is a valid out-pointer.
        if unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sid))
    }
}

impl Drop for LocalSid {
    fn drop(&mut self) {
        // SAFETY: allocated by `ConvertStringSidToSidW`, freed once.
        unsafe { LocalFree(self.0) };
    }
}

/// A DACL read with `GetNamedSecurityInfoW`; the security descriptor owns the
/// ACL memory and is freed on drop.
struct Dacl {
    sd: PSECURITY_DESCRIPTOR,
    acl: *mut ACL,
}

impl Dacl {
    fn read(path: &Path) -> io::Result<Self> {
        let w = wide(path.as_os_str());
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let mut acl: *mut ACL = null_mut();
        // SAFETY: `w` is NUL-terminated; the out-pointers are valid.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut acl,
                null_mut(),
                &mut sd,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        Ok(Self { sd, acl })
    }

    fn size_info(&self) -> io::Result<ACL_SIZE_INFORMATION> {
        let mut info = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        // SAFETY: `acl` is a valid ACL kept alive by `self.sd`; `info` is a
        // writable ACL_SIZE_INFORMATION of the size passed.
        let ok = unsafe {
            GetAclInformation(
                self.acl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }

    /// True if an allow ACE for `sid` with at least `mask` applies to the
    /// object itself. A NULL DACL grants everyone everything.
    fn grants(&self, sid: PSID, mask: u32) -> io::Result<bool> {
        if self.acl.is_null() {
            return Ok(true);
        }
        let info = self.size_info()?;
        for i in 0..info.AceCount {
            let mut ace: *mut core::ffi::c_void = null_mut();
            // SAFETY: `i` is below the ACE count of a valid ACL.
            if unsafe { GetAce(self.acl, i, &mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: GetAce returned a pointer to an ACE inside the ACL.
            let header = unsafe { &*(ace as *const ACE_HEADER) };
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
                || u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
            {
                continue;
            }
            // SAFETY: an ACCESS_ALLOWED_ACE_TYPE ACE has the layout of
            // ACCESS_ALLOWED_ACE; its SID starts at `SidStart`.
            let allowed = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
            let ace_sid: PSID = (&allowed.SidStart as *const u32).cast_mut().cast();
            // SAFETY: both pointers are valid SIDs.
            if unsafe { EqualSid(ace_sid, sid) } != 0 && allowed.Mask & mask == mask {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The ACL's bytes in use (header and ACEs).
    fn bytes(&self) -> io::Result<Vec<u8>> {
        if self.acl.is_null() {
            return Ok(Vec::new());
        }
        let info = self.size_info()?;
        // SAFETY: the ACL occupies `AclBytesInUse` bytes from its start.
        let slice = unsafe {
            std::slice::from_raw_parts(self.acl.cast::<u8>(), info.AclBytesInUse as usize)
        };
        Ok(slice.to_vec())
    }
}

impl Drop for Dacl {
    fn drop(&mut self) {
        // SAFETY: allocated by `GetNamedSecurityInfoW`, freed once.
        unsafe { LocalFree(self.sd) };
    }
}

/// The DACL of `path` as raw bytes (tests use it to prove that a refused
/// re-apply changed nothing).
pub fn dacl_bytes(path: &Path) -> io::Result<Vec<u8>> {
    Dacl::read(path)?.bytes()
}

/// Which of the two ACEs one file has.
struct FileAces {
    all_app_packages: bool,
    all_restricted: bool,
}

fn file_aces(path: &Path, aap: &LocalSid, rap: &LocalSid) -> io::Result<FileAces> {
    let dacl = Dacl::read(path)?;
    Ok(FileAces {
        all_app_packages: dacl.grants(aap.0, RX_MASK)?,
        all_restricted: dacl.grants(rap.0, RX_MASK)?,
    })
}

fn sids() -> io::Result<(LocalSid, LocalSid)> {
    Ok((
        LocalSid::parse(SID_ALL_APP_PACKAGES)?,
        LocalSid::parse(SID_ALL_RESTRICTED_APP_PACKAGES)?,
    ))
}

/// Checks the ACEs on `files` (see [`AceStatus`]).
pub fn check_aces(files: &[PathBuf]) -> io::Result<AceStatus> {
    let (aap, rap) = sids()?;
    let mut missing = Vec::new();
    let mut lpac_ready = true;
    for f in files {
        let aces = file_aces(f, &aap, &rap)?;
        if !aces.all_app_packages {
            missing.push(f.clone());
        }
        lpac_ready &= aces.all_restricted;
    }
    if missing.is_empty() {
        Ok(AceStatus::AllPresent { lpac_ready })
    } else {
        Ok(AceStatus::Missing(missing))
    }
}

/// Adds the read+execute ACE for each of the two SIDs that a file lacks.
/// Existing ACEs are kept; a file that has both is not touched.
pub fn grant_aces(files: &[PathBuf]) -> io::Result<()> {
    let (aap, rap) = sids()?;
    for f in files {
        let aces = file_aces(f, &aap, &rap)?;
        let mut entries: Vec<EXPLICIT_ACCESS_W> = Vec::new();
        for (present, sid) in [(aces.all_app_packages, &aap), (aces.all_restricted, &rap)] {
            if !present {
                entries.push(EXPLICIT_ACCESS_W {
                    grfAccessPermissions: RX_MASK,
                    grfAccessMode: GRANT_ACCESS,
                    grfInheritance: NO_INHERITANCE,
                    Trustee: TRUSTEE_W {
                        pMultipleTrustee: null_mut(),
                        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                        TrusteeForm: TRUSTEE_IS_SID,
                        TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                        ptstrName: sid.0.cast(),
                    },
                });
            }
        }
        if entries.is_empty() {
            continue;
        }
        let old = Dacl::read(f)?;
        let mut new_acl: *mut ACL = null_mut();
        // SAFETY: `entries` holds valid EXPLICIT_ACCESS_W values whose
        // trustee SIDs outlive the call; `old.acl` is a valid ACL (or NULL).
        let rc = unsafe {
            SetEntriesInAclW(
                entries.len() as u32,
                entries.as_ptr(),
                old.acl,
                &mut new_acl,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let w = wide(f.as_os_str());
        // SAFETY: `w` is NUL-terminated, `new_acl` was just built.
        let rc = unsafe {
            SetNamedSecurityInfoW(
                w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                new_acl,
                null(),
            )
        };
        // SAFETY: allocated by `SetEntriesInAclW`, freed once.
        unsafe { LocalFree(new_acl.cast()) };
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
    }
    Ok(())
}

/// Whether the process can open `path` with `WRITE_DAC` (normally true for
/// the owner, so in a per-user install).
fn can_write_dac(path: &Path) -> io::Result<bool> {
    let w = wide(path.as_os_str());
    // SAFETY: `w` is NUL-terminated; no security attributes or template.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            Ok(false)
        } else {
            Err(e)
        };
    }
    // SAFETY: `h` is a valid handle opened above.
    unsafe { CloseHandle(h) };
    Ok(true)
}

/// Start-time ACE check (§9.4): if either ACE is missing on any file,
/// re-apply it when the app can write the DACL.
///
/// `can_write_dac_override`: `Some(b)` fixes the answer (tests); `None` probes
/// by opening every file that lacks an ACE with `WRITE_DAC`. A grant that
/// fails with `ERROR_ACCESS_DENIED` is also reported as `MissingNoWriteDac`.
pub fn ensure_aces(
    files: &[PathBuf],
    can_write_dac_override: Option<bool>,
) -> io::Result<AceEnsure> {
    let (aap, rap) = sids()?;
    let mut lacking: Vec<&PathBuf> = Vec::new();
    for f in files {
        let aces = file_aces(f, &aap, &rap)?;
        if !(aces.all_app_packages && aces.all_restricted) {
            lacking.push(f);
        }
    }
    if lacking.is_empty() {
        return Ok(AceEnsure::Present);
    }
    let writable = match can_write_dac_override {
        Some(b) => b,
        None => {
            let mut all = true;
            for f in &lacking {
                all &= can_write_dac(f)?;
            }
            all
        }
    };
    if !writable {
        return Ok(AceEnsure::MissingNoWriteDac);
    }
    match grant_aces(files) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
            return Ok(AceEnsure::MissingNoWriteDac);
        }
        Err(e) => return Err(e),
    }
    match check_aces(files)? {
        AceStatus::AllPresent { lpac_ready: true } => Ok(AceEnsure::Reapplied),
        _ => Err(io::Error::other(
            "ACEs still missing after re-applying them",
        )),
    }
}

/// The worker binary plus every DLL it imports that sits next to it
/// (transitively). System DLLs (resolved from `System32`, API sets) already
/// carry the (L)PAC ACEs and are not listed.
pub fn worker_ace_files(install_dir: &Path) -> io::Result<Vec<PathBuf>> {
    worker_ace_files_for_exe(&install_dir.join(WORKER_EXE_NAME))
}

/// Like [`worker_ace_files`] for an executable that may have another name
/// (the spawner calls this with `SpawnSpec::exe`).
pub fn worker_ace_files_for_exe(exe: &Path) -> io::Result<Vec<PathBuf>> {
    let dir = exe
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "worker path has no parent"))?;
    if !exe.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "sandbox worker not found",
        ));
    }
    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(lower_name(exe));
    let mut queue = vec![exe.to_path_buf()];
    let mut dlls: Vec<PathBuf> = Vec::new();
    while let Some(next) = queue.pop() {
        let bytes = std::fs::read(&next)?;
        for name in pe_import_names(&bytes)? {
            let lower = name.to_ascii_lowercase();
            if lower.starts_with("api-ms-win-") || lower.starts_with("ext-ms-") {
                continue;
            }
            let candidate = dir.join(&name);
            if candidate.is_file() && seen.insert(lower) {
                dlls.push(candidate.clone());
                queue.push(candidate);
            }
        }
    }
    dlls.sort();
    let mut files = vec![exe.to_path_buf()];
    files.extend(dlls);
    Ok(files)
}

fn lower_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn u16_at(b: &[u8], o: usize) -> io::Result<u16> {
    let s = b.get(o..o + 2).ok_or_else(|| bad("truncated PE file"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], o: usize) -> io::Result<u32> {
    let s = b.get(o..o + 4).ok_or_else(|| bad("truncated PE file"))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Names of the DLLs a PE file imports (import table and delay-load table),
/// the same list `dumpbin /dependents` prints.
pub fn pe_import_names(b: &[u8]) -> io::Result<Vec<String>> {
    if b.get(0..2) != Some(b"MZ".as_slice()) {
        return Err(bad("not a PE file"));
    }
    let pe = u32_at(b, 0x3C)? as usize;
    if b.get(pe..pe + 4) != Some(b"PE\0\0".as_slice()) {
        return Err(bad("missing PE signature"));
    }
    let sections = u16_at(b, pe + 6)? as usize;
    let opt_size = u16_at(b, pe + 20)? as usize;
    let opt = pe + 24;
    let dirs = match u16_at(b, opt)? {
        0x10B => opt + 96,
        0x20B => opt + 112,
        _ => return Err(bad("unknown optional header")),
    };
    let table = opt + opt_size;
    let rva_to_off = |rva: u32| -> io::Result<usize> {
        for i in 0..sections {
            let s = table + i * 40;
            let virt_size = u32_at(b, s + 8)?;
            let virt_addr = u32_at(b, s + 12)?;
            let raw_size = u32_at(b, s + 16)?;
            let raw_ptr = u32_at(b, s + 20)?;
            if rva >= virt_addr && rva < virt_addr + virt_size.max(raw_size) {
                return Ok((rva - virt_addr + raw_ptr) as usize);
            }
        }
        Err(bad("RVA outside every section"))
    };
    let cstr = |off: usize| -> io::Result<String> {
        let tail = b.get(off..).ok_or_else(|| bad("name outside file"))?;
        let end = tail
            .iter()
            .position(|&c| c == 0)
            .ok_or_else(|| bad("unterminated name"))?;
        Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
    };
    let mut names = Vec::new();
    // Import directory (index 1): 20-byte descriptors, name RVA at +12.
    let import_rva = u32_at(b, dirs + 8)?;
    if import_rva != 0 {
        let mut d = rva_to_off(import_rva)?;
        loop {
            let name_rva = u32_at(b, d + 12)?;
            let first_thunk = u32_at(b, d + 16)?;
            if name_rva == 0 && first_thunk == 0 {
                break;
            }
            names.push(cstr(rva_to_off(name_rva)?)?);
            d += 20;
        }
    }
    // Delay-load directory (index 13): 32-byte descriptors, name RVA at +4.
    let delay_rva = u32_at(b, dirs + 13 * 8)?;
    if delay_rva != 0 {
        let mut d = rva_to_off(delay_rva)?;
        loop {
            let name_rva = u32_at(b, d + 4)?;
            if name_rva == 0 {
                break;
            }
            names.push(cstr(rva_to_off(name_rva)?)?);
            d += 32;
        }
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_imports_of_a_real_executable_include_kernel32() {
        let exe = std::env::current_exe().expect("current exe");
        let names = pe_import_names(&std::fs::read(exe).expect("read exe")).expect("parse PE");
        assert!(
            names.iter().any(|n| n.eq_ignore_ascii_case("kernel32.dll")),
            "{names:?}"
        );
    }

    #[test]
    fn pe_parser_rejects_garbage_and_truncated_files() {
        assert!(pe_import_names(b"not a pe file").is_err());
        let exe = std::fs::read(std::env::current_exe().expect("current exe")).expect("read exe");
        // Cut inside the section table: must be an error, never a panic.
        assert!(pe_import_names(&exe[..0x200]).is_err());
        assert!(pe_import_names(&[]).is_err());
    }
}
