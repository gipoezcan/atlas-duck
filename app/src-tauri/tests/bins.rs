//! The three bins of the Tauri package (§12.1): the CLI usage envelope (§4.2, §4.3), the early-argv
//! dispatch before any Tauri/GTK code (§2.5 Scope), the verify-export mode (§12.1), the sandbox stub
//! (§3.4), the embedded BUILD_ID (§3.3, §3.4) and, on Windows, the worker's PE header (§9.3).

use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};

const APP: &str = env!("CARGO_BIN_EXE_atlas-duck-app");
const CLI: &str = env!("CARGO_BIN_EXE_atlas-duck");
const SANDBOX: &str = env!("CARGO_BIN_EXE_atlas-duck-sandbox");

/// The per-process limit of `run_with_timeout`: only a hang detector. Under Rosetta (the x86_64
/// macOS leg) the first start of the large app binary is a cold translation, and other tests run in
/// parallel: it exceeded 5 s there, so the limit is generous on every OS.
const LIMIT: Duration = Duration::from_secs(60);

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
    let run = run_with_timeout(cmd(CLI, &["bogus"]), LIMIT);
    assert_eq!(run.status.code(), Some(2));
    assert_usage_envelope(&run.stdout);
}

#[test]
fn cli_without_arguments_is_a_usage_error_too() {
    let run = run_with_timeout(cmd(CLI, &[]), LIMIT);
    assert_eq!(run.status.code(), Some(2));
    assert_usage_envelope(&run.stdout);
}

#[test]
fn app_cli_marker_is_byte_identical_to_the_cli_bin() {
    let direct = run_with_timeout(cmd(CLI, &["bogus"]), LIMIT);
    let via_app = run_with_timeout(cmd(APP, &["__cli", "bogus"]), LIMIT);
    assert_eq!(via_app.status.code(), direct.status.code());
    assert_eq!(via_app.stdout, direct.stdout);
    assert_eq!(via_app.stderr, direct.stderr);
    assert_usage_envelope(&via_app.stdout);
}

/// §12.1: the marker and its alias run the real verifier; a directory that is not an export is a
/// usage or I/O error (22) whose report goes to stdout, a missing directory argument is a usage
/// error (22) whose reason and usage line go to stderr.
#[test]
fn app_verify_export_marker_and_alias_report_usage_error_on_missing_dir() {
    for marker in ["__verify-export", "--verify-export"] {
        let missing = run_with_timeout(cmd(APP, &[marker, "no-such-export-directory"]), LIMIT);
        assert_eq!(missing.status.code(), Some(22), "{marker}");
        let stdout = String::from_utf8_lossy(&missing.stdout);
        assert!(stdout.contains("cannot verify:"), "{marker}: {stdout}");

        let usage = run_with_timeout(cmd(APP, &[marker]), LIMIT);
        assert_eq!(usage.status.code(), Some(22), "{marker}");
        assert!(usage.stdout.is_empty(), "{marker}: stdout must stay empty");
        let stderr = String::from_utf8_lossy(&usage.stderr);
        assert!(
            stderr.contains("usage: verify-export <dir>"),
            "{marker}: {stderr}"
        );
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// §12.1, C.9: `atlas-duck verify-export` finds the app next to the CLI, runs `__verify-export`
/// with this process's stdio and exits with its code, printing no envelope. The exports come from
/// the audit crate's fixture writer (an honest one, a tampered one).
#[test]
fn cli_verify_export_passes_report_and_exit_code_through() {
    use atlas_duck_audit::testing::{FixtureKind, export_fixture};

    let tmp = tempfile::tempdir().expect("tempdir");
    let mut seen = Vec::new();
    for (kind, with_root, last_line) in [
        (
            FixtureKind::Pass,
            true,
            "verified against the manifest SHA-256",
        ),
        (FixtureKind::Tamper, true, "TAMPERED:"),
        (
            FixtureKind::NoTrustRoot,
            false,
            "internally consistent; trust root NOT verified",
        ),
    ] {
        let out = tmp.path().join(format!("{kind:?}"));
        std::fs::create_dir(&out).expect("fixture dir");
        let info = export_fixture(kind, &out).expect("fixture");
        let dir = info.dir.to_str().expect("UTF-8 path").to_owned();
        let root = hex(&info.manifest_sha256);
        let mut args = vec!["verify-export", dir.as_str()];
        if with_root {
            args.extend(["--manifest-sha256", root.as_str()]);
        }
        let run = run_with_timeout(cmd(CLI, &args), LIMIT);
        assert_eq!(
            run.status.code(),
            Some(i32::from(info.expected_exit)),
            "{kind:?}"
        );
        let stdout = String::from_utf8(run.stdout).expect("UTF-8 report");
        let last = stdout.lines().last().unwrap_or_default();
        assert!(last.starts_with(last_line), "{kind:?}: {stdout}");
        assert!(
            !stdout.trim_start().starts_with('{'),
            "{kind:?}: the CLI prints no envelope: {stdout}"
        );
        assert!(run.stderr.is_empty(), "{kind:?}: {:?}", run.stderr);
        seen.push(info.expected_exit);
    }
    assert_eq!(seen, [0, 21, 20]);

    // A directory that is no export: the app's own report on stdout, exit 22 from the child.
    let run = run_with_timeout(
        cmd(CLI, &["verify-export", "no-such-export-directory"]),
        LIMIT,
    );
    assert_eq!(run.status.code(), Some(22));
    assert!(String::from_utf8_lossy(&run.stdout).contains("cannot verify:"));

    // A usage error is the app's too: its reason on stderr, nothing on stdout, exit 22.
    let run = run_with_timeout(cmd(CLI, &["verify-export", "d", "--pubkey", "k"]), LIMIT);
    assert_eq!(run.status.code(), Some(22));
    assert!(run.stdout.is_empty());
    assert!(String::from_utf8_lossy(&run.stderr).contains("--pubkey"));
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

/// M6 T2 / §2.5 Scope: the `__cli` and `__verify-export` early modes are not hardened, so their
/// environment (`LD_PRELOAD`-style variables included) stays as the caller set it; only the GUI
/// branch runs `startup::hardening::apply_early`. Checked on the dispatch helper, no process spawn.
#[test]
fn cli_mode_is_not_hardened() {
    use std::ffi::OsString;

    use atlas_duck_app_lib::early_argv::classify_argv;
    use atlas_duck_app_lib::startup::hardening::applies_to;

    let argv = |items: &[&str]| -> Vec<OsString> { items.iter().map(OsString::from).collect() };
    for args in [
        argv(&["atlas-duck-app", "__cli", "bogus"]),
        argv(&["atlas-duck-app", "__cli", "--background"]),
        argv(&["atlas-duck-app", "__verify-export", "x"]),
        argv(&["atlas-duck-app", "--verify-export", "x"]),
    ] {
        assert!(!applies_to(&classify_argv(&args)), "{args:?}");
    }
    for args in [
        argv(&["atlas-duck-app"]),
        argv(&["atlas-duck-app", "--background"]),
    ] {
        assert!(applies_to(&classify_argv(&args)), "{args:?}");
    }
}

/// T09 / §2.5 Scope: the early-argv modes are dispatched before the crash settings, so they keep
/// their stdio. If `apply_process_crash_settings` ran first, stderr would be the null device.
#[test]
fn early_argv_modes_keep_their_stdio() {
    let cli = run_with_timeout(cmd(APP, &["__cli", "bogus"]), LIMIT);
    assert_eq!(cli.status.code(), Some(2));
    assert_usage_envelope(&cli.stdout);

    // Still 22, now from the real body: "x" is not an export directory. The report reaches the
    // parent's stdout and a usage error reaches its stderr (not the null device).
    let verify = run_with_timeout(cmd(APP, &["__verify-export", "x"]), LIMIT);
    assert_eq!(verify.status.code(), Some(22));
    assert!(
        String::from_utf8_lossy(&verify.stdout).contains("cannot verify:"),
        "the verifier's report must reach the parent"
    );
    let usage = run_with_timeout(cmd(APP, &["__verify-export", "x", "--bogus"]), LIMIT);
    assert_eq!(usage.status.code(), Some(22));
    assert!(
        !usage.stderr.is_empty(),
        "the usage error must reach the parent's stderr, not the null device"
    );
}
