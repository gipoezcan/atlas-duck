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

fn contains(hay: &[u8], needle: &str) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_secret_reaches_logs_answers_or_the_server_store() {
    let logs = logs();
    tracing::info!(event = "capture_started");
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
    sse.abort();

    let master_b64 = base64::engine::general_purpose::STANDARD.encode(MASTER_BYTES);
    let master_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(MASTER_BYTES);
    let canaries: Vec<(&str, String)> = vec![
        ("password", ALICE.1.to_owned()),
        ("pat", PAT_CANARY.to_owned()),
        ("api_key", flow.key.clone()),
        (
            "api_key_secret",
            flow.key.rsplit('_').next().unwrap().to_owned(),
        ),
        ("master_key_b64", master_b64),
        ("master_key_b64url", master_b64url),
        ("session_cookie", flow.alice.cookie.clone()),
        ("session_cookie_probe", alice_probe.cookie.clone()),
    ];

    let log_bytes = logs.0.lock().unwrap().clone();
    assert!(contains(&log_bytes, "capture_started"), "the capture works");
    let transcript = s.transcript.lock().unwrap().join("\n");
    assert!(transcript.contains("ABC-1"), "the transcript holds the run");
    let sse_bytes = frames.lock().unwrap().clone();
    let db = bytes_of(&s.dir.path().join("data").join("server").join("server.db"));
    assert!(!db.is_empty());
    for (what, canary) in &canaries {
        assert!(!contains(&log_bytes, canary), "{what} in the logs");
        assert!(!transcript.contains(canary.as_str()), "{what} in an answer");
        assert!(!contains(&sse_bytes, canary), "{what} in an SSE frame");
        assert!(!contains(&db, canary), "{what} in server.db");
    }
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
