//! Endpoint file ACL: protected single-ACE DACL, owner is the current user
//! (§3.1, §15 V01, PD-26). Runs with and without the `async` feature.
#![cfg(windows)]

use std::os::windows::ffi::OsStrExt;

use atlas_duck_ipc::paths::{
    DataDirResolution, ENDPOINT_FILE, LocalDataDir, check_data_dir, current_user_sid_string,
    write_endpoint_file,
};
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce,
    GetSecurityDescriptorControl, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

fn local(dir: &std::path::Path) -> LocalDataDir {
    match check_data_dir(dir).expect("check_data_dir") {
        DataDirResolution::Local(d) => d,
        other => panic!("temp dir is not a local data dir: {other:?}"),
    }
}

fn sid_to_string(sid: PSID) -> String {
    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID; `raw` receives a LocalAlloc'ed string.
    assert_ne!(unsafe { ConvertSidToStringSidW(sid, &mut raw) }, 0);
    let mut n = 0usize;
    // SAFETY: `raw` is NUL-terminated.
    while unsafe { *raw.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: `raw` is valid for `n` u16 reads.
    let s = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, n) }).expect("utf16");
    // SAFETY: allocated by ConvertSidToStringSidW.
    unsafe { LocalFree(raw as HLOCAL) };
    s
}

/// One ACE of a DACL: (type, mask, SID string).
fn ace(dacl: *const ACL, index: u32) -> (u8, u32, String) {
    let mut p: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `dacl` is a valid ACL with more than `index` ACEs.
    assert_ne!(unsafe { GetAce(dacl, index, &mut p) }, 0, "GetAce");
    // SAFETY: every ACE starts with an ACE_HEADER.
    let header = unsafe { *(p as *const ACE_HEADER) };
    assert_eq!(u32::from(header.AceType), ACCESS_ALLOWED_ACE_TYPE);
    let allowed = p as *const ACCESS_ALLOWED_ACE;
    // SAFETY: an ACCESS_ALLOWED_ACE; its SID starts at SidStart.
    let mask = unsafe { (*allowed).Mask };
    // SAFETY: as above.
    let sid = unsafe { std::ptr::addr_of!((*allowed).SidStart) } as PSID;
    (header.AceType, mask, sid_to_string(sid))
}

/// Control bits, ACE list and owner SID of a descriptor from
/// `GetNamedSecurityInfoW`; frees it.
fn read_sd(
    owner: PSID,
    dacl: *mut ACL,
    sd: PSECURITY_DESCRIPTOR,
) -> (u16, Vec<(u8, u32, String)>, String) {
    let mut control = 0u16;
    let mut rev = 0u32;
    // SAFETY: `sd` is the descriptor GetSecurityInfo returned.
    assert_ne!(
        unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut rev) },
        0
    );
    assert!(!dacl.is_null(), "no DACL (null DACL = everyone)");
    // SAFETY: `dacl` points into `sd`.
    let count = unsafe { (*dacl).AceCount };
    let aces = (0..u32::from(count)).map(|i| ace(dacl, i)).collect();
    let owner = sid_to_string(owner);
    // SAFETY: allocated by GetSecurityInfo / GetNamedSecurityInfoW.
    unsafe { LocalFree(sd as HLOCAL) };
    (control, aces, owner)
}

fn file_sd(path: &std::path::Path) -> (u16, Vec<(u8, u32, String)>, String) {
    let w: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `w` is NUL-terminated; out-pointers are valid.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    assert_eq!(rc, 0, "GetNamedSecurityInfoW");
    read_sd(owner, dacl, sd)
}

#[test]
fn endpoint_file_acl_owner_only() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = local(tmp.path());
    let sid = current_user_sid_string().expect("current user SID");
    for i in 0..2 {
        let name = format!(r"\\.\pipe\atlas-duck-0123456789abcdef-{i:032x}");
        write_endpoint_file(&data, &name).expect("write");
        let (control, aces, owner) = file_sd(&tmp.path().join(ENDPOINT_FILE));
        assert_ne!(
            control & SE_DACL_PROTECTED,
            0,
            "DACL not protected: {control:#x}"
        );
        assert_eq!(
            aces,
            vec![(ACCESS_ALLOWED_ACE_TYPE as u8, FILE_ALL_ACCESS, sid.clone())]
        );
        assert_eq!(owner, sid);
    }
    println!("V01 endpoint_file_acl=owner_only");
}
