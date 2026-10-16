#![cfg(feature = "async")]
//! L83 hardening of `IpcServer` (§3.3, §3.1): the cap on pre-`hello` peer walks, the per-frame
//! body timeout after `hello`, and (Windows) the `hello_timeout` answer written only after the
//! SID check. In-process server and raw-frame clients only.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_duck_ipc::proto::RequestHandler;
use atlas_duck_ipc::server::{HandlerCell, IpcServer, ServerLimits, ShutdownSignal};
use common::{Client, Fake, Kind, WAIT};
use serde_json::json;
use tokio::task::JoinHandle;

// ---------- harness ----------

struct Running {
    name: String,
    shutdown: ShutdownSignal,
    task: JoinHandle<()>,
    _tmp: tempfile::TempDir,
}

impl Running {
    async fn stop(self) {
        self.shutdown.0.cancel();
        tokio::time::timeout(WAIT, self.task)
            .await
            .expect("serve did not return after shutdown")
            .expect("serve panicked");
    }
}

#[cfg(unix)]
fn location(tmp: &tempfile::TempDir) -> atlas_duck_ipc::paths::EndpointLocation {
    let dir = tmp.path().join("s");
    atlas_duck_ipc::paths::ensure_socket_dir(&dir).expect("socket dir");
    atlas_duck_ipc::paths::EndpointLocation::UnixSocket(dir.join("atlas-duck.sock"))
}

#[cfg(windows)]
fn location(_tmp: &tempfile::TempDir) -> atlas_duck_ipc::paths::EndpointLocation {
    let tmp = tempfile::tempdir().expect("tempdir");
    atlas_duck_ipc::paths::endpoint_location(&common::local(tmp.path()), "host").expect("location")
}

fn bind(tmp: &tempfile::TempDir, limits: ServerLimits) -> IpcServer {
    let data_dir = tmp.path().join("data");
    std::fs::create_dir(&data_dir).expect("data dir");
    let data = common::local(&data_dir);
    IpcServer::bind_at(&data, location(tmp))
        .expect("bind")
        .with_limits(limits)
}

fn run(server: IpcServer, handler: Arc<dyn RequestHandler>, tmp: tempfile::TempDir) -> Running {
    let name = server.endpoint_name().to_owned();
    let shutdown = ShutdownSignal::default();
    let task = tokio::spawn(server.serve(Arc::new(HandlerCell::new(handler)), shutdown.clone()));
    Running {
        name,
        shutdown,
        task,
        _tmp: tmp,
    }
}

async fn start_with(fake: &Arc<Fake>, limits: ServerLimits) -> Running {
    let tmp = tempfile::tempdir().expect("tempdir");
    let server = bind(&tmp, limits);
    run(server, fake.clone(), tmp)
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(150)).await;
}

// ---------- the hello-phase semaphore ----------

#[cfg(feature = "test-paths")]
mod walks {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use atlas_duck_ipc::proto::PeerInfo;

    use super::*;

    /// A peer walk that counts itself and blocks until `open`.
    #[derive(Default)]
    pub struct Gate {
        pub started: AtomicUsize,
        current: AtomicUsize,
        pub max: AtomicUsize,
        pub open: AtomicBool,
    }

    /// Opens the gate when a test ends, also by a failed assertion: held walks would keep
    /// their blocking threads, and so the test runtime's shutdown, forever.
    pub struct OpenOnDrop(pub Arc<Gate>);

    impl Drop for OpenOnDrop {
        fn drop(&mut self) {
            self.0.open.store(true, Ordering::SeqCst);
        }
    }

    impl Gate {
        pub fn walk(&self, pid: Option<u32>) -> PeerInfo {
            self.started.fetch_add(1, Ordering::SeqCst);
            let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            self.max.fetch_max(now, Ordering::SeqCst);
            while !self.open.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            self.current.fetch_sub(1, Ordering::SeqCst);
            PeerInfo {
                peer_pid: pid,
                ..PeerInfo::default()
            }
        }
    }

    pub async fn start_gated(fake: &Arc<Fake>, limits: ServerLimits, gate: &Arc<Gate>) -> Running {
        let tmp = tempfile::tempdir().expect("tempdir");
        let g = gate.clone();
        let server = bind(&tmp, limits).with_peer_walker(move |pid| g.walk(pid));
        run(server, fake.clone(), tmp)
    }

    pub async fn until(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// L83: no more than `hello_walks` peer walks run at once; the other connections wait for a
/// permit and are served when one frees up.
#[cfg(feature = "test-paths")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l83_hello_phase_semaphore_caps_peer_walks() {
    use std::sync::atomic::Ordering;

    use walks::{Gate, OpenOnDrop, start_gated, until};

    let fake = Arc::new(Fake::new("A"));
    let gate = Arc::new(Gate::default());
    let _opener = OpenOnDrop(gate.clone());
    let limits = ServerLimits {
        hello_walks: 2,
        ..ServerLimits::default()
    };
    let srv = start_gated(&fake, limits, &gate).await;
    let mut clients = Vec::new();
    for i in 0..5 {
        let mut c = Client::connect(&srv.name).await;
        c.send(&common::request(i, "hello", common::hello_params()))
            .await;
        clients.push(c);
    }
    until("two walks to start", || {
        gate.started.load(Ordering::SeqCst) >= 2
    })
    .await;
    settle().await;
    assert_eq!(
        gate.started.load(Ordering::SeqCst),
        2,
        "walks beyond the cap ran"
    );
    assert_eq!(
        fake.count(Kind::Hello),
        0,
        "a hello was answered while walks were held"
    );

    gate.open.store(true, Ordering::SeqCst);
    for (i, c) in clients.iter_mut().enumerate() {
        let v = c.recv().await.expect("a hello answer");
        assert_eq!(v["id"], json!(i), "{v}");
        assert!(v["result"]["build_id"].is_string(), "{v}");
    }
    assert_eq!(gate.started.load(Ordering::SeqCst), 5);
    assert_eq!(
        gate.max.load(Ordering::SeqCst),
        2,
        "more than two walks overlapped"
    );
    srv.stop().await;
}

/// L83: a connection that waits for a walk permit is still bound by the hello deadline: it
/// proceeds then with the peer's pid only, and leaves no queued walk behind.
#[cfg(feature = "test-paths")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l83_waiting_for_a_walk_ends_at_the_hello_deadline() {
    use std::sync::atomic::Ordering;

    use walks::{Gate, OpenOnDrop, start_gated, until};

    let fake = Arc::new(Fake::new("A"));
    let gate = Arc::new(Gate::default());
    let _opener = OpenOnDrop(gate.clone());
    let limits = ServerLimits {
        hello_walks: 1,
        hello_timeout: Duration::from_millis(400),
        ..ServerLimits::default()
    };
    let srv = start_gated(&fake, limits, &gate).await;
    let mut a = Client::connect(&srv.name).await;
    a.send(&common::request(1, "hello", common::hello_params()))
        .await;
    until("the first walk", || {
        gate.started.load(Ordering::SeqCst) == 1
    })
    .await;
    let mut b = Client::connect(&srv.name).await;
    let t0 = Instant::now();
    b.send(&common::request(2, "hello", common::hello_params()))
        .await;
    let v = b.recv().await.expect("a hello answer");
    let waited = t0.elapsed();
    assert!(v["result"]["build_id"].is_string(), "{v}");
    assert!(
        waited >= Duration::from_millis(250),
        "answered after {waited:?}"
    );
    assert!(waited < Duration::from_secs(3), "answered after {waited:?}");
    // The walk of `b` never started, even now that the first one is released.
    gate.open.store(true, Ordering::SeqCst);
    settle().await;
    assert_eq!(gate.started.load(Ordering::SeqCst), 1);
    assert_eq!(gate.max.load(Ordering::SeqCst), 1);
    let _ = a.recv().await;
    srv.stop().await;
}

// ---------- the per-frame body timeout ----------

/// L83: after `hello`, a frame whose last byte does not arrive within `frame_body_timeout` of
/// its first closes the connection (unanswered, `disconnected` once); an idle connection and
/// the other connections are not affected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l83_frame_body_timeout_after_hello() {
    let fake = Arc::new(Fake::new("A"));
    let limits = ServerLimits {
        frame_body_timeout: Duration::from_millis(300),
        ..ServerLimits::default()
    };
    let srv = start_with(&fake, limits).await;
    let mut other = Client::hello(&srv.name).await;

    // Idle longer than the bound, then a request: served.
    let mut idle = Client::hello(&srv.name).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    let v = idle.call(1, "ops.list", json!({})).await;
    assert!(v.get("result").is_some(), "{v}");

    // A stall inside the length prefix, and inside the body.
    for partial in [&[0u8, 0][..], &[0, 0, 0, 100, b'{', b'"'][..]] {
        let mut c = Client::hello(&srv.name).await;
        let t0 = Instant::now();
        c.send_raw(partial).await;
        assert!(c.closed().await, "connection stayed open");
        let waited = t0.elapsed();
        assert!(
            waited >= Duration::from_millis(250),
            "closed after {waited:?}"
        );
        assert!(waited < Duration::from_secs(5), "closed after {waited:?}");
    }
    // Both closed connections were disconnected once each; the others stay up.
    let gone = fake.wait_for(Kind::Disconnected, 2).await;
    assert_eq!(gone.len(), 2);
    settle().await;
    assert_eq!(fake.count(Kind::Disconnected), 2);
    let v = other.call(2, "ops.list", json!({})).await;
    assert!(v.get("result").is_some(), "{v}");
    let v = idle.call(3, "ops.list", json!({})).await;
    assert!(v.get("result").is_some(), "{v}");
    // The default is the specified 5 s.
    assert_eq!(
        ServerLimits::default().frame_body_timeout,
        Duration::from_secs(5)
    );
    assert_eq!(ServerLimits::default().hello_walks, 128);
    srv.stop().await;
}

// ---------- Windows: the hello_timeout answer follows the SID check ----------

/// §3.1 / L83: the `hello_timeout` answer is written only to a client whose SID was checked.
/// A client that allows only anonymous impersonation is closed unanswered when the deadline
/// passes, silent or stalled after a byte; a verified client gets the answer in both cases.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l83_windows_hello_timeout_after_sid_check() {
    use atlas_duck_ipc::rpc::frame::read_frame_async;
    use atlas_duck_ipc::sandbox::MAX_FRAME_BYTES;
    use tokio::io::AsyncWriteExt;
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Storage::FileSystem::SECURITY_ANONYMOUS;

    let fake = Arc::new(Fake::new("A"));
    let limits = ServerLimits {
        hello_timeout: Duration::from_millis(300),
        ..ServerLimits::default()
    };
    let srv = start_with(&fake, limits).await;

    // Unverified (anonymous level), silent and after one byte: no answer.
    for byte in [false, true] {
        let mut anon = ClientOptions::new()
            .security_qos_flags(SECURITY_ANONYMOUS)
            .open(&srv.name)
            .expect("open anonymous-level");
        if byte {
            anon.write_all(&[0u8]).await.expect("write");
        }
        let got = tokio::time::timeout(WAIT, read_frame_async(&mut anon, MAX_FRAME_BYTES))
            .await
            .expect("closed within WAIT");
        assert!(
            matches!(got, Ok(None) | Err(_)),
            "an unverified client got an answer (byte sent: {byte}): {got:?}"
        );
    }

    // Verified, silent and after one byte: the answer.
    for byte in [false, true] {
        let mut c = Client::connect(&srv.name).await;
        if byte {
            c.send_raw(&[0u8]).await;
        }
        let v = c.recv().await.expect("a hello_timeout answer");
        assert_eq!(
            common::error_of(&v),
            (-32600, Some("hello_timeout".to_owned())),
            "byte sent: {byte}"
        );
        assert!(c.closed().await);
    }

    settle().await;
    assert!(fake.events().is_empty(), "handler saw {:?}", fake.events());
    srv.stop().await;
}
