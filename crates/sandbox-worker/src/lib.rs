//! The atlas-duck sandbox worker (§9.3, §9.4, §3.4).
//!
//! A single-threaded process: it confines itself, announces `probe.ready`, and
//! the host's first frame picks the mode (plan M8 PD-132): `probe.run` (answer
//! probes until stdin reaches EOF), `script.compile` (compile only, one reply)
//! or `script.run` (one script run, [`script`]). It links no HTTP client,
//! keychain or database code (§2.1) and never starts a thread or an async
//! runtime: on Linux the seccomp filter kills `clone` after setup
//! (`ci/check-no-panic-macros.mjs` also refuses `thread::spawn` in `src/`). A
//! panic ends the process with `EXIT_PANIC` from inside a panic hook, so a
//! panicking worker never dies by SIGSYS (`abort()` needs `tgkill`, which the
//! allowlist lacks) and is never scored `Blocked`.

pub mod confine;
pub mod engine;
mod oom;
pub mod probe;
pub mod script;

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, PoisonError, TryLockError};

use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::sandbox::frame::{read_frame, write_frame};
use atlas_duck_ipc::sandbox::probe::{
    ConfinementReport, M_PROBE_READY, M_PROBE_RESULT, M_PROBE_RUN, ProbeReady, ProbeRequest,
    decode_notification, encode_notification,
};
use atlas_duck_ipc::sandbox::script::{CompileRequest, M_SCRIPT_COMPILE, M_SCRIPT_RUN, WorkerInit};
use atlas_duck_ipc::sandbox::{MAX_FRAME_BYTES, WORKER_FRAME_MAX_BYTES};

pub use oom::ExitOnOomAlloc;
pub use script::loop_::{
    FIELD_TRUNCATED, LINE_TRUNCATED, RESULT_NOT_REPRESENTABLE, RESULT_TOO_LARGE_CLASS,
    SCRIPT_DEADLINE, SCRIPT_DEADLINE_MESSAGE, SCRIPT_OP_BUDGET, SCRIPT_OP_BUDGET_MESSAGE,
    SCRIPT_STALLED, SCRIPT_STALLED_MESSAGE, SYNTAX_ERROR_CLASS,
};

use script::alloc::LimitState;

/// The exit codes live in `ipc::sandbox` (M8 T7 fix I-2), where the host reads them too. A panic
/// exits [`EXIT_PANIC`] through the hook from [`install_panic_hook`]; [`ExitOnOomAlloc`] exits
/// [`EXIT_PROCESS_LIMIT`].
pub use atlas_duck_ipc::sandbox::{
    EXIT_HEAP_LIMIT, EXIT_IO, EXIT_OK, EXIT_PANIC, EXIT_PROCESS_LIMIT, EXIT_PROTOCOL,
};

/// The allocator state of the current run, for the panic hook (PD-134). The
/// worker runs one script (or one compile) per process; the engine and
/// compile mode register their meter as soon as their runtime exists.
static RUN_METER: Mutex<Option<Arc<LimitState>>> = Mutex::new(None);

/// Registers the run's allocator state with the panic hook.
pub(crate) fn set_run_meter(meter: Arc<LimitState>) {
    *RUN_METER.lock().unwrap_or_else(PoisonError::into_inner) = Some(meter);
}

/// The exit code of a panic: [`EXIT_HEAP_LIMIT`] while the run's heap limit
/// was hit (a Rust panic on a failed allocation inside rquickjs must not hide
/// the limit), [`EXIT_PROCESS_LIMIT`] after a failed allocation below it,
/// else [`EXIT_PANIC`].
fn panic_exit_code(meter: Option<&LimitState>) -> i32 {
    match meter {
        Some(meter) if meter.heap_refused() => EXIT_HEAP_LIMIT,
        Some(meter) if meter.system_null() => EXIT_PROCESS_LIMIT,
        _ => EXIT_PANIC,
    }
}

/// Replaces the panic hook with one that ends the process with
/// [`EXIT_PANIC`] (or a limit code, [`panic_exit_code`]) and prints nothing.
///
/// With the release `panic = "abort"` a panic would call `abort()`, whose
/// `tgkill` the Linux seccomp allowlist does not allow (T17): the worker would
/// die by SIGSYS, and a panic before a probe's forbidden call would be scored
/// `Blocked`. `exit_group` is allowed, so the exit code stays visible to the
/// host. `process::exit` only tries the stdout lock, so the hook is safe while
/// [`run`] holds it; the hook only tries the run-meter lock too.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_info| {
        let code = match RUN_METER.try_lock() {
            Ok(meter) => panic_exit_code(meter.as_deref()),
            Err(TryLockError::Poisoned(meter)) => panic_exit_code(meter.get_ref().as_deref()),
            Err(TryLockError::WouldBlock) => EXIT_PANIC,
        };
        std::process::exit(code)
    }));
}

/// The worker entry point. Runs on the process's main thread.
///
/// The panic hook is installed first, and confinement is applied before the
/// first stdin read (§9.4). Neither happens inside [`run_script_with`] or
/// [`run_with`]: the tests call them in the test process, which must never
/// confine itself and must keep its normal panic reporting.
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
    run_script_with(confinement, &mut stdin.lock(), io::stdout().lock())
}

/// The worker over any reader and writer (PD-132): the `probe.ready` frame
/// carrying `confinement`, then the host's first frame picks the mode:
/// - `probe.run`: the probe loop of [`run_with`], from that frame on;
/// - `script.compile`: `script.compiled` or `script.syntax`, then exit;
/// - `script.run`: one run (PD-131), then exit;
/// - stdin EOF: exit 0; anything else: [`EXIT_PROTOCOL`].
///
/// The writer is owned and `'static` because the script engine's host port
/// must be (its natives are `'static`); `io::stdout().lock()` is.
pub fn run_script_with<R: Read, W: Write + 'static>(
    confinement: ConfinementReport,
    input: &mut R,
    mut output: W,
) -> i32 {
    if send_ready(confinement, &mut output).is_err() {
        return EXIT_IO;
    }
    let frame = match read_frame(input, MAX_FRAME_BYTES) {
        Ok(Some(frame)) => frame,
        Ok(None) => return EXIT_OK,
        Err(_) => return EXIT_IO,
    };
    let Ok((method, params)) = decode_notification(&frame) else {
        return EXIT_PROTOCOL;
    };
    drop(frame);
    match method.as_str() {
        M_PROBE_RUN => match serde_json::from_value::<ProbeRequest>(params) {
            Ok(request) => probe_loop(Some(request), input, &mut output),
            Err(_) => EXIT_PROTOCOL,
        },
        M_SCRIPT_COMPILE => match serde_json::from_value::<CompileRequest>(params) {
            Ok(request) => script::loop_::compile_mode(&request, &mut output),
            Err(_) => EXIT_PROTOCOL,
        },
        M_SCRIPT_RUN => match serde_json::from_value::<WorkerInit>(params) {
            Ok(init) => script::loop_::run_script(init, input, output),
            Err(_) => EXIT_PROTOCOL,
        },
        _ => EXIT_PROTOCOL,
    }
}

/// The M1 probe loop over any reader and writer: the `probe.ready` frame
/// carrying `confinement`, then one `probe.result` per `probe.run`, until EOF.
/// It runs no scripts (any other frame is [`EXIT_PROTOCOL`]).
pub fn run_with<R: Read, W: Write>(
    confinement: ConfinementReport,
    input: &mut R,
    output: &mut W,
) -> i32 {
    if send_ready(confinement, output).is_err() {
        return EXIT_IO;
    }
    probe_loop(None, input, output)
}

/// `probe.ready`, sent before anything is read in every mode (PD-132).
fn send_ready<W: Write>(confinement: ConfinementReport, output: &mut W) -> io::Result<()> {
    let ready = ProbeReady {
        worker_version: BUILD_ID.to_owned(),
        engine_version: engine::ENGINE_VERSION.to_owned(),
        confinement,
    };
    send(output, &encode_notification(M_PROBE_READY, &ready))
}

/// Answers `first` (a request already read) and then one `probe.run` per
/// frame until EOF.
fn probe_loop<R: Read, W: Write>(
    mut first: Option<ProbeRequest>,
    input: &mut R,
    output: &mut W,
) -> i32 {
    loop {
        let request = match first.take() {
            Some(request) => request,
            None => {
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
                request
            }
        };
        let reply = probe::run_probe(&request);
        if send(output, &encode_notification(M_PROBE_RESULT, &reply)).is_err() {
            return EXIT_IO;
        }
    }
}

/// Writes one frame, refusing a payload above the worker-to-host limit (§3.4).
/// The terminal frame of a run is written by the run loop against its own cap.
pub(crate) fn send<W: Write>(output: &mut W, payload: &[u8]) -> io::Result<()> {
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

    /// PD-134: a panic after a heap refusal exits `EXIT_HEAP_LIMIT`, after a
    /// failed allocation below the limit `EXIT_PROCESS_LIMIT`, else `EXIT_PANIC`.
    #[test]
    fn panic_exit_code_follows_the_run_meter() {
        use rquickjs::allocator::Allocator;
        use script::alloc::LimitAllocator;

        assert_eq!(panic_exit_code(None), EXIT_PANIC);
        let (_, untouched) = LimitAllocator::new(1024);
        assert_eq!(panic_exit_code(Some(&untouched)), EXIT_PANIC);

        let (mut refusing, refused) = LimitAllocator::new(0);
        assert!(refusing.alloc(64).is_null());
        assert!(refused.heap_refused());
        assert_eq!(panic_exit_code(Some(&refused)), EXIT_HEAP_LIMIT);

        struct NullInner;
        // SAFETY: never hands out a block, so there is nothing to free or size.
        unsafe impl Allocator for NullInner {
            fn alloc(&mut self, _size: usize) -> *mut u8 {
                std::ptr::null_mut()
            }
            fn calloc(&mut self, _count: usize, _size: usize) -> *mut u8 {
                std::ptr::null_mut()
            }
            unsafe fn dealloc(&mut self, _ptr: *mut u8) {}
            unsafe fn realloc(&mut self, _ptr: *mut u8, _new_size: usize) -> *mut u8 {
                std::ptr::null_mut()
            }
            unsafe fn usable_size(_ptr: *mut u8) -> usize {
                0
            }
        }
        let (mut failing, exhausted) = LimitAllocator::with_inner(1024, NullInner);
        assert!(failing.alloc(64).is_null());
        assert!(exhausted.system_null() && !exhausted.heap_refused());
        assert_eq!(panic_exit_code(Some(&exhausted)), EXIT_PROCESS_LIMIT);
    }

    /// M-1: the engine and compile mode register their meter with the panic hook as soon as
    /// their runtime exists, so a panic right after a heap refusal while the engine is built or
    /// the source compiled exits `EXIT_HEAP_LIMIT`, not `EXIT_PANIC`. The only lib test that
    /// builds an engine or compiles (`RUN_METER` is process-wide).
    #[test]
    fn engine_and_compile_register_their_meter_with_the_panic_hook() {
        use atlas_duck_ipc::sandbox::HostCall;
        use atlas_duck_ipc::sandbox::ScriptLimits;
        use script::alloc::LimitAllocator;
        use script::{Engine, HostPort, compile};

        struct NoHost;
        impl HostPort for NoHost {
            fn send_call(&mut self, _id: u64, _call: &HostCall) -> io::Result<()> {
                Ok(())
            }
            fn send_log(&mut self, _line: &str) -> io::Result<()> {
                Ok(())
            }
        }
        let registered = || {
            RUN_METER
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        };

        let (_, sentinel) = LimitAllocator::new(1024);
        set_run_meter(Arc::clone(&sentinel));
        compile("return 1;").expect("compiles");
        let after_compile = registered().expect("a meter");
        assert!(!Arc::ptr_eq(&after_compile, &sentinel));

        let init = WorkerInit {
            source: "return 1;".to_owned(),
            args: serde_json::json!({}),
            limits: ScriptLimits::default(),
            read_op_ids: Vec::new(),
            instances: Vec::new(),
        };
        let engine = Engine::new(&init, NoHost).expect("an engine");
        let after_engine = registered().expect("a meter");
        assert!(Arc::ptr_eq(&after_engine, engine.meter()));
        assert!(!Arc::ptr_eq(&after_engine, &after_compile));
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
