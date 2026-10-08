//! Windows Credential Manager readback (RF-3a): the persistence of a stored credential.

use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
use windows_sys::Win32::Security::Credentials::{
    CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
};

use super::KeyStoreError;

/// `CRED_PERSIST_LOCAL_MACHINE`.
pub(super) const PERSIST_LOCAL: u32 = 2;

/// `CredReadW` the generic credential `target` and return its `Persist`; `None` if it does not
/// exist.
pub fn credential_persist(target: &str) -> Result<Option<u32>, KeyStoreError> {
    let wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
    let mut p: *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and outlives the call; `p` is a valid out-pointer.
    let ok = unsafe { CredReadW(wide.as_ptr(), CRED_TYPE_GENERIC, 0, &mut p) };
    if ok == 0 {
        // SAFETY: plain thread-local error read right after the failing call.
        let code = unsafe { GetLastError() };
        return if code == ERROR_NOT_FOUND {
            Ok(None)
        } else {
            Err(KeyStoreError::Other(format!("CredReadW failed ({code})")))
        };
    }
    // SAFETY: on success `p` points to a CREDENTIALW allocated by the API; it is read once and
    // freed with `CredFree`, and not used afterwards.
    let persist = unsafe {
        let persist = (*p).Persist;
        CredFree(p as *const _);
        persist
    };
    Ok(Some(persist))
}
