//! Pipe and endpoint-file security descriptors (§3.1 Windows, PD-26).
//!
//! Every pipe instance is created with the same descriptor: owner = the user
//! SID, a protected DACL with exactly one `ACCESS_ALLOWED_ACE` granting the
//! user SID `FILE_GENERIC_READ | FILE_GENERIC_WRITE`, nothing else (no
//! Everyone, no Anonymous, no inherited ACEs). `FILE_GENERIC_WRITE` includes
//! `FILE_CREATE_PIPE_INSTANCE` on purpose: the server needs it for its second
//! and later instances.

use std::io;

use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};

pub use crate::win_security::{OwnerOnlySecurity, owner_only_attributes};
use crate::win_security::{ProtectedSd, Sid};

/// The descriptor shared by every instance of the server's pipe. Owns the
/// `SECURITY_DESCRIPTOR`, the DACL buffer and the user SID.
#[derive(Debug)]
pub struct PipeSecurity {
    sd: ProtectedSd,
}

impl PipeSecurity {
    /// The descriptor for the process token's user SID.
    pub fn for_current_user() -> io::Result<PipeSecurity> {
        Ok(PipeSecurity {
            sd: ProtectedSd::new(Sid::current_user()?, FILE_GENERIC_READ | FILE_GENERIC_WRITE)?,
        })
    }

    /// `SECURITY_ATTRIBUTES` for `CreateNamedPipeW`, `bInheritHandle =
    /// FALSE`. The pointer inside is valid only while `self` lives.
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        self.sd.attributes()
    }

    /// The user SID the descriptor grants, as `S-1-5-…`.
    pub fn user_sid_string(&self) -> io::Result<String> {
        self.sd.sid().to_string_sid()
    }
}
