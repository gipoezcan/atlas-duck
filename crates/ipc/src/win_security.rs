//! Windows security primitives shared by the endpoint file (PD-26) and the
//! named-pipe transport (§3.1): owned SID copies, token user SIDs, and
//! absolute security descriptors with a protected single-ACE DACL.
//!
//! Not behind the `async` feature: the endpoint file is written with the
//! owner-only descriptor in every build. `transport::windows::security`
//! re-exports the public parts.

use std::fmt;
use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce, CopySid, GetLengthSid,
    GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor, IsValidSid, PSID,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const MSG_BAD_SID: &str = "not a valid SID";
const MSG_TOKEN_USER_SIZE: &str = "TokenUser size probe returned too small a size";
const MSG_NO_SID_STRING: &str = "SID string conversion returned no string";
const MSG_SID_UTF16: &str = "SID string is not UTF-16";

/// A heap-held copy of a SID. The buffer is never reallocated, so a pointer
/// from `as_psid` stays valid as long as the `Sid` lives, even when the
/// `Sid` itself is moved.
pub(crate) struct Sid {
    // u64 elements keep the SID aligned (a SID needs 4-byte alignment).
    buf: Box<[u64]>,
}

impl Sid {
    /// Copies the SID at `sid`.
    ///
    /// # Safety
    /// `sid` must point to a SID that stays valid for the duration of the call.
    pub(crate) unsafe fn copy_from(sid: PSID) -> io::Result<Sid> {
        // SAFETY: the caller guarantees `sid` points to a SID; IsValidSid reads it.
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, MSG_BAD_SID));
        }
        // SAFETY: `sid` is a valid SID.
        let len = unsafe { GetLengthSid(sid) };
        let mut buf = vec![0u64; usize_of(len).div_ceil(8)].into_boxed_slice();
        // SAFETY: `buf` is writable for at least `len` bytes; `sid` is valid.
        if unsafe { CopySid(len, buf.as_mut_ptr().cast(), sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Sid { buf })
    }

    /// The user SID of `token` (opened with `TOKEN_QUERY`).
    pub(crate) fn of_token(token: BorrowedHandle<'_>) -> io::Result<Sid> {
        let h = token.as_raw_handle() as HANDLE;
        let mut needed = 0u32;
        // SAFETY: a size probe: null buffer of length 0, `needed` is a valid out-pointer.
        let ok = unsafe { GetTokenInformation(h, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        if ok == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                return Err(err);
            }
        }
        if usize_of(needed) < std::mem::size_of::<TOKEN_USER>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                MSG_TOKEN_USER_SIZE,
            ));
        }
        // u64 elements keep the buffer aligned for TOKEN_USER.
        let mut buf = vec![0u64; usize_of(needed).div_ceil(8)];
        // SAFETY: `buf` is writable for at least `needed` bytes.
        let ok = unsafe {
            GetTokenInformation(h, TokenUser, buf.as_mut_ptr().cast(), needed, &mut needed)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: on success the buffer starts with an initialized, aligned
        // TOKEN_USER whose SID points into `buf`, which is alive here.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        // SAFETY: `sid` points into `buf`, alive for the call.
        unsafe { Sid::copy_from(sid) }
    }

    /// The user SID of this process's token.
    pub(crate) fn current_user() -> io::Result<Sid> {
        let mut h: HANDLE = std::ptr::null_mut();
        // SAFETY: the current-process pseudo handle; `h` is a valid out-pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh token handle that nothing else owns.
        let token = unsafe { OwnedHandle::from_raw_handle(h as _) };
        Sid::of_token(token.as_handle())
    }

    /// A pointer for APIs that read the SID. Never written through.
    pub(crate) fn as_psid(&self) -> PSID {
        self.buf.as_ptr() as PSID
    }

    /// `ConvertSidToStringSidW` form (`S-1-5-21-…`).
    pub(crate) fn to_string_sid(&self) -> io::Result<String> {
        // SAFETY: `self` holds a valid SID for the call.
        unsafe { sid_to_string(self.as_psid()) }
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sid")
    }
}

/// `ConvertSidToStringSidW` of `sid`.
///
/// # Safety
/// `sid` must point to a valid SID for the duration of the call.
pub(crate) unsafe fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: the caller guarantees `sid`; `raw` receives a LocalAlloc'ed string.
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if raw.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            MSG_NO_SID_STRING,
        ));
    }
    let _free = LocalFreeOnDrop(raw.cast());
    let mut n = 0usize;
    // SAFETY: on success `raw` is NUL-terminated.
    while unsafe { *raw.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: `raw` is valid for `n` u16 reads.
    String::from_utf16(unsafe { std::slice::from_raw_parts(raw, n) })
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, MSG_SID_UTF16))
}

/// Frees a `LocalAlloc`ed block (from `ConvertSidToStringSidW`,
/// `GetSecurityInfo`) on drop.
pub(crate) struct LocalFreeOnDrop(pub(crate) *mut core::ffi::c_void);

impl Drop for LocalFreeOnDrop {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API documented to need LocalFree
            // and is freed exactly once.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

/// An absolute security descriptor: owner = `sid`, DACL with exactly one
/// `ACCESS_ALLOWED_ACE` (`sid`, `mask`), `SE_DACL_PROTECTED` set (no
/// inherited ACEs), no group, no SACL.
///
/// The descriptor points into the SID and ACL buffers; all three are heap
/// allocations that are never touched again after `new`, so the struct may
/// move freely.
pub(crate) struct ProtectedSd {
    sd: Box<SECURITY_DESCRIPTOR>,
    _dacl: Box<[u64]>,
    // The descriptor's owner and ACE point here; without `async` nothing
    // else reads it.
    #[cfg_attr(not(feature = "async"), allow(dead_code))]
    sid: Sid,
}

// SAFETY: the raw pointers inside `sd` point only into `_dacl` and `sid`,
// which this struct owns; nothing mutates any of them after `new`, so shared
// and cross-thread access only ever reads immutable memory.
unsafe impl Send for ProtectedSd {}
// SAFETY: as above.
unsafe impl Sync for ProtectedSd {}

impl ProtectedSd {
    pub(crate) fn new(sid: Sid, mask: u32) -> io::Result<ProtectedSd> {
        let psid = sid.as_psid();
        // SAFETY: `sid` holds a valid SID.
        let sid_len = usize_of(unsafe { GetLengthSid(psid) });
        // ACL header + ACE (whose SidStart u32 overlaps the SID), DWORD aligned.
        let acl_len = (std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            - std::mem::size_of::<u32>()
            + sid_len)
            .next_multiple_of(4);
        let acl_len_u32 = u32::try_from(acl_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, MSG_BAD_SID))?;
        let mut dacl = vec![0u64; acl_len.div_ceil(8)].into_boxed_slice();
        let pacl: *mut ACL = dacl.as_mut_ptr().cast();
        // SAFETY: `pacl` is writable and 8-byte aligned for `acl_len` bytes.
        if unsafe { InitializeAcl(pacl, acl_len_u32, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `pacl` was initialized with room for this one ACE; `psid` is valid.
        if unsafe { AddAccessAllowedAce(pacl, ACL_REVISION, mask, psid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut sd = Box::new(SECURITY_DESCRIPTOR::default());
        let psd: *mut SECURITY_DESCRIPTOR = &mut *sd;
        // SAFETY: `psd` is a writable SECURITY_DESCRIPTOR.
        if unsafe { InitializeSecurityDescriptor(psd.cast(), SECURITY_DESCRIPTOR_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor keeps `psid`, which lives in `sid` (moved into
        // the returned struct; its heap buffer does not move).
        if unsafe { SetSecurityDescriptorOwner(psd.cast(), psid, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: present = TRUE with a non-null, initialized DACL (never a null
        // DACL, which would grant everyone); `dacl` moves into the struct.
        if unsafe { SetSecurityDescriptorDacl(psd.cast(), 1, pacl, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `psd` is an initialized descriptor.
        if unsafe { SetSecurityDescriptorControl(psd.cast(), SE_DACL_PROTECTED, SE_DACL_PROTECTED) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(ProtectedSd {
            sd,
            _dacl: dacl,
            sid,
        })
    }

    /// `SECURITY_ATTRIBUTES` pointing at this descriptor, `bInheritHandle =
    /// FALSE`. Valid only while `self` lives; the APIs that take it copy the
    /// descriptor and never write through the pointer.
    pub(crate) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (&*self.sd as *const SECURITY_DESCRIPTOR).cast_mut().cast(),
            bInheritHandle: 0,
        }
    }

    #[cfg(feature = "async")]
    pub(crate) fn sid(&self) -> &Sid {
        &self.sid
    }
}

impl fmt::Debug for ProtectedSd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProtectedSd")
    }
}

/// The descriptor for the `<data>/endpoint` file (PD-26): owner and only
/// ACE = the current user SID with `FILE_ALL_ACCESS`, DACL protected.
#[derive(Debug)]
pub struct OwnerOnlySecurity {
    sd: ProtectedSd,
}

impl OwnerOnlySecurity {
    /// `SECURITY_ATTRIBUTES` for `CreateFileW`; valid while `self` lives.
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        self.sd.attributes()
    }
}

/// Builds the owner-only descriptor for the current user.
pub fn owner_only_attributes() -> io::Result<OwnerOnlySecurity> {
    Ok(OwnerOnlySecurity {
        sd: ProtectedSd::new(Sid::current_user()?, FILE_ALL_ACCESS)?,
    })
}

/// `u32` → `usize`; Windows targets are at least 32-bit.
fn usize_of(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}
