//! Windows named-pipe transport: protected single-ACE DACL, first-instance
//! flag, instance loop, impersonation check, client SQOS, server-owner check
//! before the first byte, `ERROR_PIPE_BUSY` wait, endpoint file ACL (§3.1,
//! §3.2 (a), §4.7, §15 V01, PD-26).
#![cfg(all(windows, feature = "async"))]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use atlas_duck_ipc::paths::{
    DataDirResolution, LocalDataDir, check_data_dir, current_user_sid_string, pipe_name_has_prefix,
};
use atlas_duck_ipc::transport::windows::security::PipeSecurity;
use atlas_duck_ipc::transport::windows::{
    ConnectFailure, PipeListener, PipeOwnerProbe, SameUser, bind_with_names, connect_checked,
    new_pipe_name, open_client, server_owner_ok, verify_client_sid, verify_client_sid_blocking,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, ServerOptions};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_NO_TOKEN, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce,
    GetSecurityDescriptorControl, GetTokenInformation, ImpersonateAnonymousToken,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SE_DACL_PROTECTED,
    SECURITY_IMPERSONATION_LEVEL, SecurityIdentification, TOKEN_QUERY, TokenImpersonationLevel,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING, SECURITY_ANONYMOUS,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

const WAIT: Duration = Duration::from_secs(10);

// ---------- helpers ----------

fn my_sid() -> String {
    current_user_sid_string().expect("current user SID")
}

fn prefix() -> String {
    match atlas_duck_ipc::paths::endpoint_location(&dummy_data(), "host").expect("location") {
        atlas_duck_ipc::paths::EndpointLocation::WindowsPipePrefix(p) => p,
        other => panic!("not a pipe prefix: {other:?}"),
    }
}

/// A data dir for `endpoint_location` (which ignores it on Windows).
fn dummy_data() -> LocalDataDir {
    let dir = std::env::temp_dir();
    local(&dir)
}

fn local(dir: &std::path::Path) -> LocalDataDir {
    match check_data_dir(dir).expect("check_data_dir") {
        DataDirResolution::Local(d) => d,
        other => panic!("temp dir is not a local data dir: {other:?}"),
    }
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
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

/// Control bits, ACE list and owner SID of a security descriptor that came
/// from `Get(Named)SecurityInfo`; frees it.
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

fn handle_sd(h: BorrowedHandle<'_>) -> (u16, Vec<(u8, u32, String)>, String) {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `h` is a live handle; out-pointers are valid.
    let rc = unsafe {
        GetSecurityInfo(
            h.as_raw_handle() as HANDLE,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    assert_eq!(rc, 0, "GetSecurityInfo");
    read_sd(owner, dacl, sd)
}

/// True iff the calling thread has no impersonation token.
fn thread_has_no_token() -> bool {
    let mut tok: HANDLE = std::ptr::null_mut();
    // SAFETY: the current-thread pseudo handle; `tok` is a valid out-pointer.
    let ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut tok) };
    if ok != 0 {
        // SAFETY: a real token handle we own.
        drop(unsafe { OwnedHandle::from_raw_handle(tok as _) });
        return false;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(ERROR_NO_TOKEN as i32)
}

/// `CreateFileW(name, GENERIC_READ | GENERIC_WRITE)` on this thread; the raw
/// error code on failure.
fn raw_open(name: &str) -> Result<OwnedHandle, i32> {
    let w = wide(name);
    // SAFETY: `w` is NUL-terminated; no security attributes, no template.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
    } else {
        // SAFETY: a fresh handle we own.
        Ok(unsafe { OwnedHandle::from_raw_handle(h as _) })
    }
}

/// Reverts the calling thread on drop.
struct Revert;
impl Drop for Revert {
    fn drop(&mut self) {
        // SAFETY: no preconditions.
        assert_ne!(unsafe { RevertToSelf() }, 0, "RevertToSelf");
    }
}

/// The impersonation level the server sees for its client, on a fresh std
/// thread (impersonation is thread-scoped).
fn client_level(server: BorrowedHandle<'_>) -> SECURITY_IMPERSONATION_LEVEL {
    let dup = server.try_clone_to_owned().expect("dup");
    std::thread::spawn(move || {
        // SAFETY: `dup` is a server pipe handle on which data was read.
        assert_ne!(
            unsafe { ImpersonateNamedPipeClient(dup.as_raw_handle() as HANDLE) },
            0,
            "ImpersonateNamedPipeClient"
        );
        let _r = Revert;
        let mut tok: HANDLE = std::ptr::null_mut();
        // SAFETY: as in thread_has_no_token.
        assert_ne!(
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut tok) },
            0,
            "OpenThreadToken"
        );
        // SAFETY: a fresh token handle we own.
        let tok = unsafe { OwnedHandle::from_raw_handle(tok as _) };
        let mut level: SECURITY_IMPERSONATION_LEVEL = -1;
        let mut len = 0u32;
        // SAFETY: `level` is writable for its size.
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    tok.as_raw_handle() as HANDLE,
                    TokenImpersonationLevel,
                    (&mut level as *mut SECURITY_IMPERSONATION_LEVEL).cast(),
                    std::mem::size_of::<SECURITY_IMPERSONATION_LEVEL>() as u32,
                    &mut len,
                )
            },
            0,
            "GetTokenInformation"
        );
        level
    })
    .join()
    .expect("level thread")
}

struct Always(bool);
impl PipeOwnerProbe for Always {
    fn owner_ok(&self, _client: &NamedPipeClient) -> bool {
        self.0
    }
}

/// `connect_checked` with retries on `PipeBusy` (concurrent clients race for
/// the single listening instance).
async fn connect_retrying(name: &str, probe: &dyn PipeOwnerProbe) -> NamedPipeClient {
    let until = Instant::now() + WAIT;
    loop {
        match connect_checked(name, probe, Instant::now() + Duration::from_secs(2)).await {
            Ok(c) => return c,
            Err(ConnectFailure::PipeBusy) if Instant::now() < until => continue,
            Err(e) => panic!("connect_checked: {e}"),
        }
    }
}

// ---------- names and bind ----------

#[test]
fn new_pipe_name_shape() {
    let p = prefix();
    let a = new_pipe_name(&p).expect("name");
    let b = new_pipe_name(&p).expect("name");
    assert!(pipe_name_has_prefix(&a, &p), "{a}");
    assert!(pipe_name_has_prefix(&b, &p), "{b}");
    assert_ne!(a, b);
}

#[test]
fn bind_outside_runtime_is_error() {
    let err = PipeListener::bind(&prefix()).expect_err("bound without a runtime");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
}

#[test]
fn pipe_security_is_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<PipeSecurity>();
    check::<PipeListener>();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v01_dacl_single_ace_protected() {
    let listener = PipeListener::bind(&prefix()).expect("bind");
    let client = open_client(listener.name()).expect("open");
    let (control, aces, owner) = handle_sd(client.as_handle());
    let sid = my_sid();
    assert_ne!(
        control & SE_DACL_PROTECTED,
        0,
        "DACL not protected: {control:#x}"
    );
    assert_eq!(
        aces,
        vec![(
            ACCESS_ALLOWED_ACE_TYPE as u8,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            sid.clone()
        )]
    );
    assert_eq!(owner, sid);
    println!("V01 pipe_dacl=protected aces=1 owner=user");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v01_first_instance_flag_refuses_squatter() {
    let p = prefix();
    let squatted = new_pipe_name(&p).expect("name");
    let fresh = new_pipe_name(&p).expect("name");
    // A squatter (default DACL, no first-instance flag) holds the name first.
    let _squatter = ServerOptions::new().create(&squatted).expect("squatter");

    let mut names = vec![fresh.clone(), squatted.clone()];
    let listener = bind_with_names(&p, &mut || {
        names.pop().ok_or_else(|| std::io::Error::other("out"))
    })
    .expect("bind");
    assert_eq!(listener.name(), fresh, "bind did not regenerate the suffix");

    // A source that always yields the squatted name: bind never becomes a
    // second instance of it and gives up after at most 5 attempts.
    let calls = AtomicUsize::new(0);
    let err = bind_with_names(&p, &mut || {
        calls.fetch_add(1, Ordering::Relaxed);
        Ok(squatted.clone())
    })
    .expect_err("bound as a second instance of a squatted name");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(calls.load(Ordering::Relaxed), 5);

    // A name without the prefix is refused before any pipe is created.
    let err =
        bind_with_names(&p, &mut || Ok(r"\\.\pipe\other".to_owned())).expect_err("foreign name");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

/// Accepts forever; every connection gets `b"pong"` for each byte read.
fn spawn_echo_server(mut listener: PipeListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (mut pipe, _pid) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => panic!("accept: {e}"),
            };
            tokio::spawn(async move {
                let mut b = [0u8; 1];
                while let Ok(1) = pipe.read(&mut b).await {
                    if pipe.write_all(b"pong").await.is_err() {
                        break;
                    }
                }
            });
        }
    })
}

async fn ping(client: &mut NamedPipeClient) {
    client.write_all(b"p").await.expect("write");
    let mut buf = [0u8; 4];
    tokio::time::timeout(WAIT, client.read_exact(&mut buf))
        .await
        .expect("pong timeout")
        .expect("read");
    assert_eq!(&buf, b"pong");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v01_second_instance_created() {
    let listener = PipeListener::bind(&prefix()).expect("bind");
    let name = listener.name().to_owned();
    let server = spawn_echo_server(listener);
    let mut a = connect_retrying(&name, &Always(true)).await;
    let mut b = connect_retrying(&name, &Always(true)).await;
    // Both connected at once, both served.
    ping(&mut b).await;
    ping(&mut a).await;
    ping(&mut b).await;
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accept_loop_always_listening() {
    let listener = PipeListener::bind(&prefix()).expect("bind");
    let name = listener.name().to_owned();
    let server = spawn_echo_server(listener);
    let mut open = Vec::new();
    for i in 0..50 {
        let mut c = match open_client(&name) {
            Ok(c) => c,
            Err(e) => panic!("connect {i}: {e} (raw {:?})", e.raw_os_error()),
        };
        ping(&mut c).await;
        // Keep half of them open so the instance count grows.
        if i % 2 == 0 {
            open.push(c);
        }
    }
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accept_survives_clients_that_open_and_close() {
    let mut listener = PipeListener::bind(&prefix()).expect("bind");
    let name = listener.name().to_owned();
    for i in 0..20 {
        if i % 2 == 0 {
            // Opened and closed before the server waits.
            drop(open_client(&name).expect("open"));
            listener.accept().await.expect("accept after open+close");
        } else {
            // Opened and closed while the server waits.
            let name = name.clone();
            let opener = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(5)).await;
                drop(open_client(&name).expect("open"));
            });
            tokio::time::timeout(WAIT, listener.accept())
                .await
                .expect("accept timeout")
                .expect("accept while open+close");
            opener.await.expect("opener");
        }
    }
    // Still serving.
    let server = spawn_echo_server(listener);
    let mut c = open_client(&name).expect("open");
    ping(&mut c).await;
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v01_same_user_open_ok() {
    let listener = PipeListener::bind(&prefix()).expect("bind");
    let name = listener.name().to_owned();
    let server = spawn_echo_server(listener);
    let probe = SameUser::current().expect("SameUser");
    let mut c = connect_checked(&name, &probe, Instant::now() + WAIT)
        .await
        .expect("connect_checked");
    assert!(server_owner_ok(&c, &my_sid()));
    assert!(!server_owner_ok(&c, "S-1-5-21-1-2-3-1001"));
    ping(&mut c).await;
    // A raw same-user open with GENERIC_READ | GENERIC_WRITE works too.
    raw_open(&name).expect("raw same-user open");
    println!("V01 same_user_open=ok");
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v01_anonymous_open_denied() {
    let listener = PipeListener::bind(&prefix()).expect("bind");
    let name = listener.name().to_owned();
    let res = std::thread::spawn(move || {
        // SAFETY: the current-thread pseudo handle.
        assert_ne!(
            unsafe { ImpersonateAnonymousToken(GetCurrentThread()) },
            0,
            "ImpersonateAnonymousToken"
        );
        let _r = Revert;
        raw_open(&name).map(drop)
    })
    .join()
    .expect("anonymous thread");
    assert_eq!(res, Err(ERROR_ACCESS_DENIED as i32));
    println!("V01 anonymous_open=denied");
    drop(listener);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "CI: second local account"]
async fn v01_other_user_open_denied() {
    use windows_sys::Win32::Security::{
        ImpersonateLoggedOnUser, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LogonUserW,
    };
    let user = std::env::var("ATLAS_DUCK_TEST_OTHER_USER").expect("ATLAS_DUCK_TEST_OTHER_USER");
    let password =
        std::env::var("ATLAS_DUCK_TEST_OTHER_PASSWORD").expect("ATLAS_DUCK_TEST_OTHER_PASSWORD");
    let listener = PipeListener::bind(&prefix()).expect("bind");
    let name = listener.name().to_owned();
    let res = std::thread::spawn(move || {
        let (u, d, p) = (wide(&user), wide("."), wide(&password));
        let mut tok: HANDLE = std::ptr::null_mut();
        // SAFETY: NUL-terminated strings; `tok` is a valid out-pointer.
        let ok = unsafe {
            LogonUserW(
                u.as_ptr(),
                d.as_ptr(),
                p.as_ptr(),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &mut tok,
            )
        };
        assert_ne!(ok, 0, "LogonUserW: {}", std::io::Error::last_os_error());
        // SAFETY: a fresh token handle we own.
        let tok = unsafe { OwnedHandle::from_raw_handle(tok as _) };
        // SAFETY: `tok` is a primary token of the other user.
        assert_ne!(
            unsafe { ImpersonateLoggedOnUser(tok.as_raw_handle() as HANDLE) },
            0,
            "ImpersonateLoggedOnUser"
        );
        let _r = Revert;
        raw_open(&name).map(drop)
    })
    .join()
    .expect("other-user thread");
    assert_eq!(res, Err(ERROR_ACCESS_DENIED as i32));
    println!("V01 other_user_open=denied");
    drop(listener);
}

// ---------- impersonation ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v01_impersonation_yields_client_sid_multithread() {
    const CLIENTS: usize = 100;
    let mut listener = PipeListener::bind(&prefix()).expect("bind");
    let name = listener.name().to_owned();
    let sid = Arc::new(my_sid());
    let verified = Arc::new(AtomicUsize::new(0));

    let server = {
        let sid = sid.clone();
        let verified = verified.clone();
        tokio::spawn(async move {
            let mut conns = Vec::new();
            for i in 0..CLIENTS {
                let (mut pipe, pid) = listener.accept().await.expect("accept");
                assert_eq!(pid, Some(std::process::id()));
                let sid = sid.clone();
                let verified = verified.clone();
                conns.push(tokio::spawn(async move {
                    // Impersonation needs data read first (the `hello` frame).
                    let mut b = [0u8; 1];
                    pipe.read_exact(&mut b).await.expect("read hello");
                    if i % 2 == 0 {
                        let ok = verify_client_sid(&pipe, &sid).await.expect("verify");
                        assert!(ok, "client SID mismatch");
                    } else {
                        // The blocking variant, checked on the very thread it ran on.
                        let dup = pipe.as_handle().try_clone_to_owned().expect("dup");
                        let sid = sid.clone();
                        let (ok, clean) = tokio::task::spawn_blocking(move || {
                            let ok = verify_client_sid_blocking(dup.as_handle(), &sid);
                            (ok, thread_has_no_token())
                        })
                        .await
                        .expect("join");
                        assert!(ok.expect("verify"), "client SID mismatch");
                        assert!(clean, "blocking thread kept a token");
                    }
                    verified.fetch_add(1, Ordering::Relaxed);
                    pipe.write_all(b"k").await.expect("write");
                }));
            }
            for c in conns {
                c.await.expect("connection task");
            }
        })
    };

    let mut clients = Vec::new();
    for _ in 0..CLIENTS {
        let name = name.clone();
        clients.push(tokio::spawn(async move {
            let mut c = connect_retrying(&name, &Always(true)).await;
            c.write_all(b"h").await.expect("write");
            let mut b = [0u8; 1];
            c.read_exact(&mut b).await.expect("read");
        }));
    }
    for c in clients {
        tokio::time::timeout(WAIT, c)
            .await
            .expect("client timeout")
            .expect("client");
    }
    tokio::time::timeout(WAIT, server)
        .await
        .expect("server timeout")
        .expect("server");
    assert_eq!(verified.load(Ordering::Relaxed), CLIENTS);

    // Blocking-pool threads are reused: none of them kept a token.
    let mut checks = Vec::new();
    for _ in 0..32 {
        checks.push(tokio::task::spawn_blocking(thread_has_no_token));
    }
    for c in checks {
        assert!(c.await.expect("join"), "a pool thread kept a token");
    }
    println!("V01 impersonation_clients={CLIENTS} all_sid_match=true reverted=true");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v01_client_sqos_identification() {
    let mut listener = PipeListener::bind(&prefix()).expect("bind");
    let name = listener.name().to_owned();
    let mut client = open_client(&name).expect("open");
    let (mut pipe, _) = listener.accept().await.expect("accept");
    client.write_all(b"h").await.expect("write");
    let mut b = [0u8; 1];
    pipe.read_exact(&mut b).await.expect("read");
    assert_eq!(client_level(pipe.as_handle()), SecurityIdentification);
    assert!(verify_client_sid(&pipe, &my_sid()).await.expect("verify"));
    assert!(
        !verify_client_sid(&pipe, "S-1-5-21-1-2-3-1001")
            .await
            .expect("verify")
    );
    println!("V01 client_sqos=identification");

    // A client asking for anonymous impersonation is not verified.
    let mut anon = ClientOptions::new()
        .security_qos_flags(SECURITY_ANONYMOUS)
        .open(&name)
        .expect("open anonymous-level");
    let (mut pipe, _) = listener.accept().await.expect("accept");
    anon.write_all(b"h").await.expect("write");
    pipe.read_exact(&mut b).await.expect("read");
    assert!(
        !verify_client_sid(&pipe, &my_sid())
            .await
            .expect("verify anonymous")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn impersonation_before_read_never_wrong() {
    let mut listener = PipeListener::bind(&prefix()).expect("bind");
    let _client = open_client(listener.name()).expect("open");
    let (pipe, _) = listener.accept().await.expect("accept");
    // Nothing read yet. The docs say impersonation fails here; Windows 11
    // allows it. Either way the answer is an error or the true one, and no
    // thread keeps a token. (The server calls it after `hello` regardless.)
    let mine = verify_client_sid(&pipe, &my_sid()).await;
    assert!(matches!(mine, Ok(true) | Err(_)), "{mine:?}");
    let other = verify_client_sid(&pipe, "S-1-5-21-1-2-3-1001").await;
    assert!(matches!(other, Ok(false) | Err(_)), "{other:?}");
    assert!(thread_has_no_token());
    println!(
        "V01 impersonation_before_read={}",
        if mine.is_ok() { "allowed" } else { "refused" }
    );
}

// ---------- client side ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s01_squatter_pipe_cli_sends_nothing() {
    let p = prefix();
    let name = new_pipe_name(&p).expect("name");
    // The squatter: a plain pipe with a default descriptor.
    let squatter = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .expect("squatter");
    let err = connect_checked(&name, &Always(false), Instant::now() + WAIT)
        .await
        .expect_err("connected to a squatter");
    assert!(matches!(err, ConnectFailure::ServerIdentity), "{err}");
    let mut squatter = squatter;
    squatter.connect().await.expect("squatter connect");
    let mut buf = Vec::new();
    match tokio::time::timeout(WAIT, squatter.read_to_end(&mut buf))
        .await
        .expect("read timeout")
    {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(e) => panic!("squatter read: {e}"),
    }
    assert!(buf.is_empty(), "the CLI sent {} bytes", buf.len());
    println!("S01 squatter_bytes_received=0");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_probe_rejects_pipe_owned_by_someone_else() {
    let listener = PipeListener::bind(&prefix()).expect("bind");
    let name = listener.name().to_owned();
    let other = SameUser::with_sid("S-1-5-21-1-2-3-1001".to_owned());
    let err = connect_checked(&name, &other, Instant::now() + WAIT)
        .await
        .expect_err("owner check passed for a foreign SID");
    assert!(matches!(err, ConnectFailure::ServerIdentity), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn not_found_maps() {
    let name = new_pipe_name(&prefix()).expect("name");
    let err = connect_checked(&name, &Always(true), Instant::now() + WAIT)
        .await
        .expect_err("connected to nothing");
    assert!(matches!(err, ConnectFailure::NotFound), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn busy_wait_bounded() {
    let name = new_pipe_name(&prefix()).expect("name");
    let _only = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .expect("server");
    let _first = open_client(&name).expect("first client takes the only instance");

    let start = Instant::now();
    let err = connect_checked(&name, &Always(true), start + Duration::from_millis(600))
        .await
        .expect_err("connected to a busy pipe");
    let took = start.elapsed();
    assert!(matches!(err, ConnectFailure::PipeBusy), "{err}");
    assert!(took >= Duration::from_millis(400), "did not wait: {took:?}");
    assert!(
        took < Duration::from_millis(1500),
        "waited too long: {took:?}"
    );

    // A deadline already past: no wait at all (a 0 ms WaitNamedPipeW would
    // mean the pipe's default timeout).
    let start = Instant::now();
    let err = connect_checked(&name, &Always(true), start)
        .await
        .expect_err("connected to a busy pipe");
    assert!(matches!(err, ConnectFailure::PipeBusy), "{err}");
    assert!(
        start.elapsed() < Duration::from_millis(200),
        "{:?}",
        start.elapsed()
    );
    println!("V01 busy_wait_ms={}", took.as_millis());
}
