//! The secret sweep (T24; SM-8.3, SM-9.2, Global Constraints "Secrets"): the exit flow runs with
//! canaries for the password, the PAT, the API key, the master key and the session cookie; no
//! canary appears in the captured logs (the server's own JSON format, every atlas-duck crate at
//! `trace`), in any HTTP response body, tool result or SSE frame (except the one create-key
//! answer, which is not recorded), or in the raw bytes of `server.db` and its WAL. A grep test
//! keeps TLS verification switches out of `crates/server/src`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use atlas_duck_server::api_keys;
use base64::Engine;
use futures::StreamExt as _;
use support::*;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

const PAT_CANARY: &str = "pat-canary-6b1e0c94f2";

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buf {
    type Writer = Buf;
    fn make_writer(&'a self) -> Buf {
        self.clone()
    }
}

/// The process-wide capture (one subscriber per test binary).
fn logs() -> &'static Buf {
    static LOGS: OnceLock<Buf> = OnceLock::new();
    LOGS.get_or_init(|| {
        let buf = Buf::default();
        let filter: Targets = "info,atlas_duck_server=trace,atlas_duck_core=trace,atlas_duck_audit=trace,atlas_duck_atlassian=trace,atlas_duck_ipc=trace,atlas_duck_mcp_tools=trace"
            .parse()
            .unwrap();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .event_format(atlas_duck_server::log::JsonLine)
            .finish()
            .with(filter);
        tracing::subscriber::set_global_default(subscriber).unwrap();
        buf
    })
}

fn bytes_of(path: &Path) -> Vec<u8> {
    let mut out = std::fs::read(path).unwrap_or_default();
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    out.extend(std::fs::read(Path::new(&wal)).unwrap_or_default());
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Everything the sweep reads: logs, answers, SSE frames, server.db and every user's audit.db.
struct Sweep {
    logs: Vec<u8>,
    transcript: Vec<u8>,
    sse: Vec<u8>,
    server_db: Vec<u8>,
    user_dbs: Vec<(String, Vec<u8>)>,
}

impl Sweep {
    fn take(s: &TestServer, frames: &Mutex<Vec<u8>>) -> Sweep {
        let data = s.dir.path().join("data");
        let mut user_dbs = Vec::new();
        for entry in std::fs::read_dir(data.join("users")).unwrap() {
            let dir = entry.unwrap().path();
            user_dbs.push((
                dir.file_name().unwrap().to_string_lossy().into_owned(),
                bytes_of(&dir.join("audit.db")),
            ));
        }
        Sweep {
            logs: logs().0.lock().unwrap().clone(),
            transcript: s.transcript.lock().unwrap().join("\n").into_bytes(),
            sse: frames.lock().unwrap().clone(),
            server_db: bytes_of(&data.join("server").join("server.db")),
            user_dbs,
        }
    }

    /// Where `needle` occurs.
    fn find(&self, needle: &[u8]) -> Vec<String> {
        let mut at = Vec::new();
        for (name, hay) in [
            ("logs", &self.logs),
            ("answers", &self.transcript),
            ("sse", &self.sse),
            ("server.db", &self.server_db),
        ] {
            if contains(hay, needle) {
                at.push(name.to_owned());
            }
        }
        for (user, hay) in &self.user_dbs {
            if contains(hay, needle) {
                at.push(format!("users/{user}/audit.db"));
            }
        }
        at
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_secret_reaches_logs_answers_or_the_stores() {
    let _ = logs();
    let s = TestServer::start().await;
    // Alice's event stream records every frame of the run.
    let frames: Arc<Mutex<Vec<u8>>> = Arc::default();
    let alice_probe = s.login(ALICE).await;
    let res = s
        .http
        .get(s.url("/api/events"))
        .header("cookie", format!("{COOKIE}={}", alice_probe.cookie))
        .send()
        .await
        .unwrap();
    let sink = frames.clone();
    let sse = tokio::spawn(async move {
        let mut stream = res.bytes_stream();
        while let Some(Ok(chunk)) = stream.next().await {
            sink.lock().unwrap().extend_from_slice(&chunk);
        }
    });

    let flow = exit_flow(&s, PAT_CANARY).await;
    // Let the last frames arrive (bounded) before the stream goes.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    sse.abort();

    let b64 = base64::engine::general_purpose::STANDARD;
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    // `adk_<prefix>_<secret>`: the secret is everything after the known prefix (it may hold `_`).
    let secret = flow
        .key
        .strip_prefix("adk_")
        .and_then(|r| r.get(api_keys::PREFIX_LEN + 1..))
        .unwrap()
        .to_owned();
    assert_eq!(secret.len(), api_keys::SECRET_B64_LEN);
    let canaries: Vec<(&str, Vec<u8>)> = vec![
        ("password", ALICE.1.as_bytes().to_vec()),
        ("pat", PAT_CANARY.as_bytes().to_vec()),
        ("api_key", flow.key.as_bytes().to_vec()),
        ("api_key_secret", secret.into_bytes()),
        ("master_key_raw", MASTER_BYTES.to_vec()),
        ("master_key_hex", hex::encode(MASTER_BYTES).into_bytes()),
        ("master_key_b64", b64.encode(MASTER_BYTES).into_bytes()),
        (
            "master_key_b64url",
            b64url.encode(MASTER_BYTES).into_bytes(),
        ),
        ("session_cookie", flow.alice.cookie.as_bytes().to_vec()),
        (
            "session_cookie_probe",
            alice_probe.cookie.as_bytes().to_vec(),
        ),
    ];

    let sweep = Sweep::take(&s, &frames);
    // Batch-4b review I5: the capture holds the server's own lines, the run's answers, frames and
    // both kinds of store.
    assert!(
        contains(&sweep.logs, b"\"event\":\"login_succeeded\""),
        "server log lines are captured"
    );
    assert!(
        contains(&sweep.transcript, b"ABC-1"),
        "the transcript holds the run"
    );
    assert!(
        contains(&sweep.sse, b"event: queue_changed"),
        "the stream holds the run"
    );
    assert!(!sweep.server_db.is_empty());
    assert!(
        sweep.user_dbs.iter().any(|(_, b)| !b.is_empty()),
        "the users' stores are read"
    );
    for (what, canary) in &canaries {
        let at = sweep.find(canary);
        assert!(at.is_empty(), "{what} found in {at:?}");
    }

    // Self-test: a known leak in a server log line, an answer, a frame and the server store is
    // found in each, so the sweep above can fail.
    const LEAK: &str = "leak-canary-0d9a7e";
    tracing::warn!(target: "atlas_duck_server::login", event = "selftest", secret = LEAK);
    s.record(&format!("{{\"leak\":\"{LEAK}\"}}"));
    frames
        .lock()
        .unwrap()
        .extend_from_slice(format!("data: {LEAK}\n\n").as_bytes());
    s.store
        .instance_put(&atlas_duck_server::store::InstanceRecord {
            alias: "leak".into(),
            product: "jira".into(),
            base_url: format!("https://{LEAK}.example.test"),
            proxy: None,
            ca_ref: None,
            is_default: false,
        })
        .unwrap();
    let at = Sweep::take(&s, &frames).find(LEAK.as_bytes());
    assert_eq!(
        at,
        ["logs", "answers", "sse", "server.db"],
        "the sweep sees every channel"
    );
}
/// Every `.rs` file under `dir`.
fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn tls_verification_is_never_switched_off() {
    // SM-9.2. The needles are split so this file does not match itself if it is ever scanned.
    let needles = [
        ["danger", "ous("].concat(),
        ["danger_", "accept_invalid"].concat(),
        ["set_no_", "tls_verify"].concat(),
        ["NoCertificate", "Verification"].concat(),
    ];
    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(files.len() > 20);
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        for n in &needles {
            assert!(!text.contains(n.as_str()), "{} contains {n}", f.display());
        }
    }
}
