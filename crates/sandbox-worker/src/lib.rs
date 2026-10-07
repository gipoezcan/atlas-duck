//! The atlas-duck sandbox worker (§9.3, §9.4, §3.4).
//!
//! A single-threaded process: it confines itself, announces `probe.ready`, then
//! answers `probe.run` frames on stdin/stdout until stdin reaches EOF. It links
//! no HTTP client, keychain or database code (§2.1) and never starts a thread
//! or an async runtime: on Linux the seccomp filter kills `clone` after setup.
//! A panic ends the process with `EXIT_PANIC` from inside a panic hook, so a
//! panicking worker never dies by SIGSYS (`abort()` needs `tgkill`, which the
//! allowlist lacks) and is never scored `Blocked`.

pub mod confine;
pub mod engine;
pub mod probe;

use std::io::{self, Read, Write};

use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::sandbox::frame::{read_frame, write_frame};
use atlas_duck_ipc::sandbox::probe::{
    ConfinementReport, M_PROBE_READY, M_PROBE_RESULT, M_PROBE_RUN, ProbeReady, ProbeRequest,
    decode_notification, encode_notification,
};
use atlas_duck_ipc::sandbox::{MAX_FRAME_BYTES, WORKER_FRAME_MAX_BYTES};

/// Exit code: clean end (stdin EOF).
pub const EXIT_OK: i32 = 0;
/// Exit code: stdin or stdout failed (broken pipe, oversized or truncated frame).
pub const EXIT_IO: i32 = 1;
/// Exit code: a frame that is not a well-formed `probe.run` notification.
pub const EXIT_PROTOCOL: i32 = 3;
/// Exit code: a panic (the Rust default panic exit code). Set by the hook
/// from [`install_panic_hook`]; T15's `score` reads it as `Error`.
pub const EXIT_PANIC: i32 = 101;

/// Replaces the panic hook with one that ends the process with
/// [`EXIT_PANIC`] and prints nothing.
///
/// With the release `panic = "abort"` a panic would call `abort()`, whose
/// `tgkill` the Linux seccomp allowlist does not allow (T17): the worker would
/// die by SIGSYS, and a panic before a probe's forbidden call would be scored
/// `Blocked`. `exit_group` is allowed, so the exit code stays visible to the
/// host. `process::exit` only tries the stdout lock, so the hook is safe while
/// [`run`] holds it.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_info| std::process::exit(EXIT_PANIC)));
}

/// The worker entry point. Runs on the process's main thread.
///
/// The panic hook is installed first, and confinement is applied before the
/// first stdin read (§9.4). Neither happens inside [`run_with`]: the unit tests
/// call `run_with` in the test process, which must never confine itself and
/// must keep its normal panic reporting.
pub fn run() -> i32 {
    install_panic_hook();
    // A failed confinement is not fatal: the worker still reports
    // `applied: false`, so that the host scores the floor as not met.
    let confinement = match confine::apply() {
        Ok(report) => report,
        Err(e) => ConfinementReport {
            applied: false,
            mechanism: e.mechanism.to_owned(),
            no_new_privs: None,
            landlock_abi: None,
            seccomp: None,
            lpac: None,
            os_error: e.os_error,
        },
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_with(confinement, &mut stdin.lock(), &mut stdout.lock())
}

/// The worker loop over any reader and writer: the `probe.ready` frame
/// carrying `confinement`, then one `probe.result` per `probe.run`, until EOF.
pub fn run_with<R: Read, W: Write>(
    confinement: ConfinementReport,
    input: &mut R,
    output: &mut W,
) -> i32 {
    let ready = ProbeReady {
        worker_version: BUILD_ID.to_owned(),
        engine_version: engine::ENGINE_VERSION.to_owned(),
        confinement,
    };
    if send(output, &encode_notification(M_PROBE_READY, &ready)).is_err() {
        return EXIT_IO;
    }

    loop {
        let frame = match read_frame(input, MAX_FRAME_BYTES) {
            Ok(Some(frame)) => frame,
            Ok(None) => return EXIT_OK,
            Err(_) => return EXIT_IO,
        };
        let Ok((method, params)) = decode_notification(&frame) else {
            return EXIT_PROTOCOL;
        };
        if method != M_PROBE_RUN {
            return EXIT_PROTOCOL;
        }
        let Ok(request) = serde_json::from_value::<ProbeRequest>(params) else {
            return EXIT_PROTOCOL;
        };
        let reply = probe::run_probe(&request);
        if send(output, &encode_notification(M_PROBE_RESULT, &reply)).is_err() {
            return EXIT_IO;
        }
    }
}

/// Writes one frame, refusing a payload above the worker-to-host limit (§3.4).
fn send<W: Write>(output: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > WORKER_FRAME_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "worker frame above the 1 MiB limit",
        ));
    }
    write_frame(output, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_duck_ipc::sandbox::probe::{
        ConfinementReport, ProbeId, ProbeOutcome, ProbeResultMsg,
    };

    fn fake_confinement() -> ConfinementReport {
        ConfinementReport {
            applied: true,
            mechanism: "test-fake".to_owned(),
            no_new_privs: Some(true),
            landlock_abi: Some(7),
            seccomp: None,
            lpac: None,
            os_error: None,
        }
    }

    fn run_frame(probe: ProbeId) -> Vec<u8> {
        let req = ProbeRequest {
            probe,
            app_pid: std::process::id(),
            profile_path: String::new(),
            public_addr: String::new(),
            loopback_addr: String::new(),
            handle_value: None,
        };
        encode_notification(M_PROBE_RUN, &req)
    }

    fn input_of(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = Vec::new();
        for f in frames {
            write_frame(&mut buf, f).expect("write");
        }
        buf
    }

    fn frames_of(mut bytes: &[u8]) -> Vec<(String, serde_json::Value)> {
        let mut out = Vec::new();
        while let Some(f) = read_frame(&mut bytes, MAX_FRAME_BYTES).expect("frame") {
            out.push(decode_notification(&f).expect("notification"));
        }
        out
    }

    #[test]
    fn ready_then_one_result_per_run_then_exit_on_eof() {
        let input = input_of(&[
            run_frame(ProbeId::EnvNames),
            run_frame(ProbeId::EngineSelfTest),
        ]);
        let mut output = Vec::new();
        let code = run_with(fake_confinement(), &mut input.as_slice(), &mut output);
        assert_eq!(code, EXIT_OK);
        let frames = frames_of(&output);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].0, M_PROBE_READY);
        let ready: ProbeReady = serde_json::from_value(frames[0].1.clone()).expect("ready");
        assert_eq!(ready.worker_version, BUILD_ID);
        assert_eq!(ready.engine_version, engine::ENGINE_VERSION);
        // The report passed to `run_with` is sent unchanged.
        assert_eq!(ready.confinement, fake_confinement());
        assert_eq!(frames[1].0, M_PROBE_RESULT);
        let first: ProbeResultMsg = serde_json::from_value(frames[1].1.clone()).expect("result");
        assert_eq!(first.probe, ProbeId::EnvNames);
        let second: ProbeResultMsg = serde_json::from_value(frames[2].1.clone()).expect("result");
        assert_eq!(second.probe, ProbeId::EngineSelfTest);
        assert_eq!(second.outcome, ProbeOutcome::Allowed);
    }

    #[test]
    fn eof_before_any_run_still_sends_ready_and_exits_zero() {
        let mut output = Vec::new();
        assert_eq!(
            run_with(fake_confinement(), &mut &b""[..], &mut output),
            EXIT_OK
        );
        assert_eq!(frames_of(&output).len(), 1);
    }

    #[test]
    fn unknown_method_exits_3_without_a_result() {
        let frame = encode_notification("probe.other", &serde_json::json!({}));
        let mut output = Vec::new();
        let code = run_with(
            fake_confinement(),
            &mut input_of(&[frame]).as_slice(),
            &mut output,
        );
        assert_eq!(code, EXIT_PROTOCOL);
        assert_eq!(frames_of(&output).len(), 1);
    }

    #[test]
    fn malformed_frames_exit_3() {
        let mut output = Vec::new();
        let code = run_with(
            fake_confinement(),
            &mut input_of(&[b"not json".to_vec()]).as_slice(),
            &mut output,
        );
        assert_eq!(code, EXIT_PROTOCOL);
        let bad_params = encode_notification(M_PROBE_RUN, &serde_json::json!({"probe": "nope"}));
        let code = run_with(
            fake_confinement(),
            &mut input_of(&[bad_params]).as_slice(),
            &mut Vec::new(),
        );
        assert_eq!(code, EXIT_PROTOCOL);
    }

    #[test]
    fn truncated_frame_is_an_io_exit() {
        let mut bytes = input_of(&[run_frame(ProbeId::EnvNames)]);
        bytes.truncate(bytes.len() - 3);
        assert_eq!(
            run_with(fake_confinement(), &mut bytes.as_slice(), &mut Vec::new()),
            EXIT_IO
        );
    }
}
