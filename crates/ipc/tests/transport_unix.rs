//! Unix socket transport: stale-socket handling, socket mode, peer uid check
//! on accept, client owner check before the first byte (§3.1, §3.2 (a), §4.7,
//! PD-25, PD-29).
#![cfg(all(unix, feature = "async"))]

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use atlas_duck_ipc::paths::ensure_socket_dir;
use atlas_duck_ipc::transport::unix::{
    ConnectFailure, Listener, OwnerCheck, PeerCred, SameUser, bind_expecting_uid, connect_checked,
    touch_socket,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WAIT: Duration = Duration::from_secs(5);

// ---------- helpers ----------

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

/// A fresh 0700 socket dir `<tmp>/s` (short, for macOS `sun_path`).
fn sock_dir(tmp: &tempfile::TempDir) -> PathBuf {
    let dir = tmp.path().join("s");
    ensure_socket_dir(&dir).expect("ensure_socket_dir");
    dir
}

/// Leaves a socket file at `path` with nothing listening on it.
fn stale_socket(path: &Path) {
    let l = std::os::unix::net::UnixListener::bind(path).expect("std bind");
    drop(l);
    let m = std::fs::symlink_metadata(path).expect("lstat stale");
    assert!(
        m.file_type().is_socket(),
        "stale socket was not left behind"
    );
}

/// Answers false and remembers the peer it was asked about.
#[derive(Default)]
struct Never {
    asked: Mutex<Option<PeerCred>>,
}

impl OwnerCheck for Never {
    fn server_ok(&self, peer: &PeerCred) -> bool {
        if let Ok(mut g) = self.asked.lock() {
            *g = Some(*peer);
        }
        false
    }
}

async fn wait_for_rejects(listener: &Listener, n: u64) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while listener.rejected_count() < n {
        assert!(
            tokio::time::Instant::now() < deadline,
            "listener saw {} rejects, expected {n}",
            listener.rejected_count()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------- bind ----------

/// A stale socket owned by us is unlinked and replaced.
#[tokio::test]
async fn bind_replaces_stale_own_socket() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = sock_dir(&tmp);
    let stale = dir.join("a.sock");
    stale_socket(&stale);
    let listener = Listener::bind(&stale).expect("bind over stale socket");
    let client = tokio::spawn({
        let stale = stale.clone();
        async move { connect_checked(&stale, &SameUser).await.map(|_| ()) }
    });
    let accepted = tokio::time::timeout(WAIT, listener.accept()).await;
    assert!(
        matches!(accepted, Ok(Ok(_))),
        "rebound socket does not accept"
    );
    assert!(matches!(client.await, Ok(Ok(()))));
}

/// A regular file is never removed.
#[tokio::test]
async fn bind_keeps_regular_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = sock_dir(&tmp).join("a.sock");
    std::fs::write(&file, b"keep").expect("write");
    let err = Listener::bind(&file).expect_err("bind over a regular file");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&file).expect("read"), b"keep");
}

/// A symlink (even to a stale socket) is refused; link and target stay.
#[tokio::test]
async fn bind_refuses_symlink() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = sock_dir(&tmp);
    let target = dir.join("c.sock");
    stale_socket(&target);
    let link = dir.join("d.sock");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let err = Listener::bind(&link).expect_err("bind over a symlink");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("lstat link")
            .file_type()
            .is_symlink()
    );
    assert!(
        std::fs::symlink_metadata(&target)
            .expect("lstat target")
            .file_type()
            .is_socket()
    );
}

/// A directory is refused.
#[tokio::test]
async fn bind_refuses_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sub = sock_dir(&tmp).join("e.sock");
    std::fs::create_dir(&sub).expect("mkdir");
    let err = Listener::bind(&sub).expect_err("bind over a dir");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(sub.is_dir());
}

/// The socket dir must pass the §3.1 check: a 0755 dir is refused, nothing bound.
#[tokio::test]
async fn bind_refuses_open_socket_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let open = tmp.path().join("o");
    std::fs::create_dir(&open).expect("mkdir");
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let err = Listener::bind(&open.join("a.sock")).expect_err("bind in a 0755 dir");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(!open.join("a.sock").exists());
}

/// A missing socket dir is created 0700 by the server.
#[tokio::test]
async fn bind_creates_missing_socket_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fresh = tmp.path().join("f").join("a.sock");
    let _l = Listener::bind(&fresh).expect("bind with a missing dir");
    let mode = std::fs::symlink_metadata(tmp.path().join("f"))
        .expect("lstat")
        .mode();
    assert_eq!(mode & 0o7777, 0o700, "dir mode {mode:o}");
}

#[tokio::test]
async fn socket_mode_and_sticky() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = sock_dir(&tmp);
    let path = dir.join("a.sock");
    let _listener = Listener::bind(&path).expect("bind");

    let meta = std::fs::symlink_metadata(&path).expect("lstat");
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.uid(), euid());
    let mode = meta.mode() & 0o7777;
    // PD-25: 0600 plus the sticky bit. Darwin refuses S_ISVTX on a
    // non-directory for non-root users, so there the bind falls back to 0600.
    #[cfg(target_os = "linux")]
    assert_eq!(mode, 0o1600, "socket mode {mode:o}");
    #[cfg(not(target_os = "linux"))]
    assert_eq!(mode & 0o777, 0o600, "socket mode {mode:o}");

    // The sticky bit never goes on the dir (check_dir_meta wants exactly 0700).
    let dmode = std::fs::symlink_metadata(&dir).expect("lstat dir").mode() & 0o7777;
    assert_eq!(dmode, 0o700, "dir mode {dmode:o}");
}

#[tokio::test]
async fn touch_socket_updates_socket_and_dir_mtime() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = sock_dir(&tmp);
    let path = dir.join("a.sock");
    let _listener = Listener::bind(&path).expect("bind");

    let old = libc::timespec {
        tv_sec: 1_000_000,
        tv_nsec: 0,
    };
    for p in [&path, &dir] {
        let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).expect("cstring");
        let times = [old, old];
        // SAFETY: `c` is NUL-terminated and `times` holds two timespecs.
        let rc = unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                c.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        assert_eq!(rc, 0, "backdating {}", p.display());
        assert_eq!(
            std::fs::symlink_metadata(p).expect("lstat").mtime(),
            1_000_000
        );
    }

    touch_socket(&path).expect("touch_socket");
    for p in [&path, &dir] {
        let mtime = std::fs::symlink_metadata(p).expect("lstat").mtime();
        assert!(mtime > 1_000_000, "{} not touched", p.display());
    }
    // Touching never changes the mode.
    let mode = std::fs::symlink_metadata(&path).expect("lstat").mode() & 0o777;
    assert_eq!(mode, 0o600);
}

// ---------- accept ----------

#[tokio::test]
async fn accept_reports_peer_uid_and_pid() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = sock_dir(&tmp).join("a.sock");
    let listener = Listener::bind(&path).expect("bind");

    let client = tokio::spawn({
        let path = path.clone();
        async move {
            let conn = connect_checked(&path, &SameUser).await.expect("connect");
            let (mut r, mut w) = conn.split();
            w.write_all(b"ping").await.expect("client write");
            let mut buf = [0u8; 4];
            r.read_exact(&mut buf).await.expect("client read");
            buf
        }
    });

    let (conn, peer) = tokio::time::timeout(WAIT, listener.accept())
        .await
        .expect("accept timed out")
        .expect("accept");
    assert_eq!(peer.uid, euid());
    assert_eq!(peer.pid, Some(std::process::id()));
    assert_eq!(listener.rejected_count(), 0);

    let (mut r, mut w) = conn.split();
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).await.expect("server read");
    assert_eq!(&buf, b"ping");
    w.write_all(b"pong").await.expect("server write");
    let got = tokio::time::timeout(WAIT, client)
        .await
        .expect("client timed out")
        .expect("client task");
    assert_eq!(&got, b"pong");
}

#[tokio::test]
async fn s01_server_rejects_other_uid_peer() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = sock_dir(&tmp).join("a.sock");
    // Production `bind` is `bind_expecting_uid(path, geteuid())`; here the
    // listener expects a different uid, so this process is "another user".
    let listener =
        Arc::new(bind_expecting_uid(&path, euid().wrapping_add(1)).expect("bind_expecting_uid"));

    let server = tokio::spawn({
        let listener = listener.clone();
        async move { listener.accept().await.map(|(_, peer)| peer) }
    });

    let mut stream = tokio::net::UnixStream::connect(&path)
        .await
        .expect("raw connect");
    let mut got = Vec::new();
    let n = tokio::time::timeout(WAIT, stream.read_to_end(&mut got))
        .await
        .expect("server never closed the rejected stream")
        .expect("read_to_end");
    assert_eq!(n, 0, "server wrote to a rejected peer");

    wait_for_rejects(&listener, 1).await;
    // `accept` never handed the rejected stream out.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!server.is_finished(), "accept returned a rejected peer");
    server.abort();
}

// ---------- connect ----------

#[tokio::test]
async fn client_owner_mismatch_sends_no_byte() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = sock_dir(&tmp).join("a.sock");
    let listener = Listener::bind(&path).expect("bind");

    let server = tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.expect("accept");
        let mut got = Vec::new();
        conn.read_to_end(&mut got)
            .await
            .expect("server read_to_end");
        got.len()
    });

    let check = Never::default();
    let res = connect_checked(&path, &check).await;
    assert!(
        matches!(res, Err(ConnectFailure::ServerIdentity)),
        "owner mismatch not reported as ServerIdentity: {res:?}"
    );
    let asked = check.asked.lock().expect("lock").take();
    assert_eq!(
        asked.map(|p| p.uid),
        Some(euid()),
        "check never saw the server"
    );

    let n = tokio::time::timeout(WAIT, server)
        .await
        .expect("server timed out")
        .expect("server task");
    assert_eq!(n, 0, "the client wrote {n} bytes before the owner check");
}

#[tokio::test]
async fn not_found_and_refused_map() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = sock_dir(&tmp);

    // No socket file → NotFound.
    let res = connect_checked(&dir.join("a.sock"), &SameUser).await;
    assert!(matches!(res, Err(ConnectFailure::NotFound)), "{res:?}");

    // A leftover socket of a dropped listener → Refused.
    let path = dir.join("b.sock");
    drop(Listener::bind(&path).expect("bind"));
    assert!(
        std::fs::symlink_metadata(&path)
            .expect("socket left behind")
            .file_type()
            .is_socket()
    );
    let res = connect_checked(&path, &SameUser).await;
    assert!(matches!(res, Err(ConnectFailure::Refused)), "{res:?}");
}

/// The CLI never creates the socket dir: a missing dir means "not running".
#[tokio::test]
async fn client_dir_check_is_check_only() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let missing = tmp.path().join("m");
    let res = connect_checked(&missing.join("a.sock"), &SameUser).await;
    assert!(matches!(res, Err(ConnectFailure::NotFound)), "{res:?}");
    assert!(!missing.exists(), "connect_checked created the socket dir");

    // A dir that fails the §3.1 check is a server-identity failure (§3.2 (a)),
    // even with a live listener behind it; the mode is left alone.
    let dir = sock_dir(&tmp);
    let path = dir.join("a.sock");
    let listener = Listener::bind(&path).expect("bind");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o711)).expect("chmod");
    let res = connect_checked(&path, &SameUser).await;
    assert!(
        matches!(res, Err(ConnectFailure::ServerIdentity)),
        "{res:?}"
    );
    let mode = std::fs::symlink_metadata(&dir).expect("lstat").mode() & 0o7777;
    assert_eq!(mode, 0o711);
    // Nothing reached the listener.
    let accepted = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
    assert!(
        accepted.is_err(),
        "connect_checked connected through a bad dir"
    );

    // A symlinked socket dir is refused the same way.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let link = tmp.path().join("l");
    std::os::unix::fs::symlink(&dir, &link).expect("symlink");
    let res = connect_checked(&link.join("a.sock"), &SameUser).await;
    assert!(
        matches!(res, Err(ConnectFailure::ServerIdentity)),
        "{res:?}"
    );
}

#[tokio::test]
async fn relative_path_is_refused() {
    let res = connect_checked(Path::new("a.sock"), &SameUser).await;
    assert!(
        matches!(&res, Err(ConnectFailure::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput),
        "{res:?}"
    );
    let err = Listener::bind(Path::new("a.sock")).expect_err("relative bind");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

// ---------- S01: a real second user (CI only) ----------

const ENV_OTHER_USER: &str = "ATLAS_DUCK_TEST_OTHER_USER";
const ENV_SOCKET: &str = "ATLAS_DUCK_TEST_SOCKET";
const ENV_PROBE_EXPECT: &str = "ATLAS_DUCK_TEST_PROBE_EXPECT";
const EXPECT_EACCES: &str = "eacces";
const EXPECT_CLOSED: &str = "closed";

/// Runs this test binary's `s01_other_user_probe` as `user` against `socket`.
fn run_probe_as(user: &str, socket: &Path, expect: &str) -> std::process::Output {
    let exe = std::env::current_exe().expect("current_exe");
    std::process::Command::new("sudo")
        .arg("-n")
        .arg("-u")
        .arg(user)
        .arg("env")
        .arg(format!("{ENV_SOCKET}={}", socket.display()))
        .arg(format!("{ENV_PROBE_EXPECT}={expect}"))
        .arg(exe)
        .args([
            "--exact",
            "s01_other_user_probe",
            "--ignored",
            "--test-threads=1",
        ])
        .output()
        .expect("sudo")
}

/// S01: another local user cannot reach the socket (dir 0700 → `EACCES`);
/// with the dir (and, test-only, the socket) opened up, the server still
/// rejects the peer on uid and writes nothing.
#[ignore = "CI: second Linux user"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s01_other_user_connection_rejected() {
    let Ok(user) = std::env::var(ENV_OTHER_USER) else {
        eprintln!("skipping s01_other_user_connection_rejected: {ENV_OTHER_USER} is not set");
        return;
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    // The other user must be able to traverse the temp dir to reach `s/`.
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o711)).expect("chmod");
    let path = sock_dir(&tmp).join("a.sock");
    let listener = Arc::new(Listener::bind(&path).expect("bind"));
    let accepted = Arc::new(AtomicU32::new(0));
    let server = tokio::spawn({
        let listener = listener.clone();
        let accepted = accepted.clone();
        async move {
            while listener.accept().await.is_ok() {
                accepted.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    // Round 1: dir 0700 → the other user's connect fails with EACCES.
    let out = tokio::task::spawn_blocking({
        let (user, path) = (user.clone(), path.clone());
        move || run_probe_as(&user, &path, EXPECT_EACCES)
    })
    .await
    .expect("probe task");
    assert!(
        out.status.success(),
        "round 1 probe failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(listener.rejected_count(), 0, "round 1 reached the listener");

    // Round 2 (test-only): dir 0711 and socket 0666, so the connect reaches
    // the listener, which must reject the uid and write nothing.
    let dir = path.parent().expect("parent");
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711)).expect("chmod dir");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod sock");
    let out = tokio::task::spawn_blocking({
        let (user, path) = (user.clone(), path.clone());
        move || run_probe_as(&user, &path, EXPECT_CLOSED)
    })
    .await
    .expect("probe task");
    assert!(
        out.status.success(),
        "round 2 probe failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    wait_for_rejects(&listener, 1).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "accept returned the other user"
    );
    server.abort();
}

/// Helper for `s01_other_user_connection_rejected`; runs as the other user.
/// Does nothing without `ATLAS_DUCK_TEST_SOCKET`.
#[ignore = "CI: second Linux user (probe)"]
#[test]
fn s01_other_user_probe() {
    use std::io::Read;
    let Some(socket) = std::env::var_os(ENV_SOCKET) else {
        return;
    };
    let expect = std::env::var(ENV_PROBE_EXPECT).unwrap_or_default();
    let res = std::os::unix::net::UnixStream::connect(&socket);
    match expect.as_str() {
        EXPECT_EACCES => {
            let err = res.expect_err("the other user reached the socket");
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        }
        EXPECT_CLOSED => {
            let mut stream = res.expect("connect in round 2");
            stream
                .set_read_timeout(Some(WAIT))
                .expect("set_read_timeout");
            let mut got = Vec::new();
            let n = stream
                .read_to_end(&mut got)
                .expect("the server did not close the stream");
            assert_eq!(n, 0, "the server wrote {n} bytes to another user");
        }
        other => panic!("unknown {ENV_PROBE_EXPECT}: {other:?}"),
    }
}
