//! The three bins of the Tauri package (§12.1): the CLI usage envelope (§4.2, §4.3), the early-argv
//! dispatch before any Tauri/GTK code (§2.5 Scope), the verify-export stub (§12.1), the sandbox stub
//! (§3.4), the embedded BUILD_ID (§3.3, §3.4) and, on Windows, the worker's PE header (§9.3).

use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};

const APP: &str = env!("CARGO_BIN_EXE_atlas-duck-app");
const CLI: &str = env!("CARGO_BIN_EXE_atlas-duck");
const SANDBOX: &str = env!("CARGO_BIN_EXE_atlas-duck-sandbox");

struct Run {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Spawns `cmd` with piped stdout/stderr, waits at most `limit` and kills the child on expiry.
fn run_with_timeout(mut cmd: Command, limit: Duration) -> Run {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    // No display: anything that initialized GTK/Tauri before the early-argv dispatch would fail
    // here (Linux CI), so a pass proves the dispatch comes first.
    cmd.env_remove("DISPLAY").env_remove("WAYLAND_DISPLAY");
    let mut child = cmd.spawn().expect("spawn");
    let mut out = child.stdout.take().expect("stdout");
    let mut err = child.stderr.take().expect("stderr");
    let out_t = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let err_t = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err.read_to_end(&mut v);
        v
    });
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{cmd:?} did not exit within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Run {
        status,
        stdout: out_t.join().expect("stdout thread"),
        stderr: err_t.join().expect("stderr thread"),
    }
}

fn cmd(exe: &str, args: &[&str]) -> Command {
    let mut c = Command::new(exe);
    c.args(args).stdin(Stdio::null());
    c
}

fn assert_usage_envelope(stdout: &[u8]) {
    let text = std::str::from_utf8(stdout).expect("stdout is UTF-8");
    assert!(
        text.ends_with('\n'),
        "stdout must end with a newline: {text:?}"
    );
    assert_eq!(text.matches('\n').count(), 1, "exactly one line: {text:?}");
    let value: serde_json::Value = serde_json::from_str(text.trim_end()).expect("stdout is JSON");
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("envelope is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "data",
            "edited",
            "error",
            "instance",
            "message",
            "meta",
            "op_id",
            "redacted",
            "redaction_note",
            "request_id",
            "status"
        ]
    );
    let env: Envelope = serde_json::from_value(value).expect("stdout parses as Envelope");
    assert_eq!(env.status, Status::Failed);
    assert_eq!(env.request_id, None);
    let error = env.error.expect("error is set");
    assert_eq!(error.code, ErrorCode::Usage);
    assert!(!error.retryable);
}

#[test]
fn cli_bogus_prints_one_usage_envelope_and_exits_2() {
    let run = run_with_timeout(cmd(CLI, &["bogus"]), Duration::from_secs(5));
    assert_eq!(run.status.code(), Some(2));
    assert_usage_envelope(&run.stdout);
}

#[test]
fn cli_without_arguments_is_a_usage_error_too() {
    let run = run_with_timeout(cmd(CLI, &[]), Duration::from_secs(5));
    assert_eq!(run.status.code(), Some(2));
    assert_usage_envelope(&run.stdout);
}

#[test]
fn app_cli_marker_is_byte_identical_to_the_cli_bin() {
    let direct = run_with_timeout(cmd(CLI, &["bogus"]), Duration::from_secs(5));
    let via_app = run_with_timeout(cmd(APP, &["__cli", "bogus"]), Duration::from_secs(5));
    assert_eq!(via_app.status.code(), direct.status.code());
    assert_eq!(via_app.stdout, direct.stdout);
    assert_eq!(via_app.stderr, direct.stderr);
    assert_usage_envelope(&via_app.stdout);
}

#[test]
fn app_verify_export_marker_and_alias_exit_22() {
    for marker in ["__verify-export", "--verify-export"] {
        let run = run_with_timeout(cmd(APP, &[marker, "x"]), Duration::from_secs(5));
        assert_eq!(run.status.code(), Some(22), "{marker}");
        assert!(run.stdout.is_empty(), "{marker}: stdout must stay empty");
    }
}

#[test]
fn sandbox_exits_0_on_stdin_eof() {
    let mut c = Command::new(SANDBOX);
    c.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().expect("spawn sandbox");
    drop(child.stdin.take()); // close stdin
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("sandbox did not exit within 2 s of stdin EOF");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(0));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn build_id_is_embedded_in_every_binary() {
    assert!(BUILD_ID.starts_with("0.1.0+"), "{BUILD_ID}");
    for exe in [APP, CLI, SANDBOX] {
        let bytes = std::fs::read(exe).expect("read executable");
        assert!(
            contains(&bytes, BUILD_ID.as_bytes()),
            "{BUILD_ID} not found in {exe}"
        );
    }
}

/// §2.1: the CLI and the sandbox link no webview, HTTP/TLS, DB or keyring code. The linkage scripts
/// check the dynamic imports; this test checks the statically linked crates, which never show up
/// there (on Windows WebView2Loader is linked statically). Debug builds embed `<crate>-<version>`
/// source paths in panic locations, so a crate that is linked in leaves its name in the executable.
#[test]
fn cli_and_sandbox_embed_no_webview_tls_db_or_keyring_crates() {
    const FORBIDDEN: [&str; 9] = [
        "tauri-2.",
        "tauri-runtime-",
        "wry-0.",
        "webview2-com",
        "reqwest-",
        "rustls-",
        "rusqlite-",
        "libsqlite3-sys",
        "keyring-",
    ];
    // Control: the app links Tauri, so the needles provably match in this build profile.
    let app = std::fs::read(APP).expect("read app executable");
    assert!(
        contains(&app, b"tauri-2."),
        "control: the app executable must name the tauri crate"
    );
    for exe in [CLI, SANDBOX] {
        let bytes = std::fs::read(exe).expect("read executable");
        for needle in FORBIDDEN {
            assert!(
                !contains(&bytes, needle.as_bytes()),
                "{exe} embeds {needle:?}"
            );
        }
    }
}

/// Reads (Subsystem, SizeOfStackReserve) from a PE32+ image.
#[cfg(windows)]
fn pe_subsystem_and_stack_reserve(path: &str) -> (u16, u64) {
    let b = std::fs::read(path).expect("read PE");
    let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    assert_eq!(&b[0..2], b"MZ");
    let pe = u32_at(0x3c) as usize;
    assert_eq!(&b[pe..pe + 4], b"PE\0\0");
    let opt = pe + 4 + 20; // PE signature + COFF file header
    assert_eq!(u16_at(opt), 0x20b, "PE32+ optional header");
    let subsystem = u16_at(opt + 68);
    let reserve = u64::from_le_bytes(b[opt + 72..opt + 80].try_into().expect("8 bytes"));
    (subsystem, reserve)
}

#[cfg(windows)]
#[test]
fn sandbox_has_8_mib_stack_reserve_and_console_bins_are_console() {
    const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
    let (sub, reserve) = pe_subsystem_and_stack_reserve(SANDBOX);
    assert_eq!(reserve, 8_388_608, "§9.3 /STACK:8388608");
    assert_eq!(sub, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    let (sub, reserve) = pe_subsystem_and_stack_reserve(CLI);
    assert_eq!(sub, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    assert_ne!(
        reserve, 8_388_608,
        "the /STACK arg must apply to the sandbox bin only"
    );
}

/// T09 / §2.5 Scope: the early-argv modes are dispatched before the crash settings, so they keep
/// their stdio. If `apply_process_crash_settings` ran first, stderr would be the null device.
#[test]
fn early_argv_modes_keep_their_stdio() {
    let cli = run_with_timeout(cmd(APP, &["__cli", "bogus"]), Duration::from_secs(5));
    assert_eq!(cli.status.code(), Some(2));
    assert_usage_envelope(&cli.stdout);

    let verify = run_with_timeout(cmd(APP, &["__verify-export", "x"]), Duration::from_secs(5));
    assert_eq!(verify.status.code(), Some(22));
    assert!(
        !verify.stderr.is_empty(),
        "the verify-export stub's stderr line must reach the parent, not the null device"
    );
}
