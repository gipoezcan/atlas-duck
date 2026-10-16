//! The run loop and the compile mode of a script worker (spec §3.4, §9.1 steps 3 and 5, §9.3;
//! plan M8 PD-131, PD-132, PD-134, PD-136).
//!
//! One thread, blocking reads of stdin and writes of stdout (PD-131, V15). [`run_script`] builds
//! the [`Engine`], calls `main`, and then repeats:
//! 1. drain the QuickJS job queue ([`Engine::drain_jobs`]);
//! 2. if `main` settled, write the one terminal frame (`script.result` or `script.error`) and exit
//!    0;
//! 3. else, if host calls are outstanding, block on one host frame and hand its text to
//!    [`Engine::deliver`] (the shim sends locally queued calls as earlier ones settle);
//! 4. else the script can never settle: `script.error` [`SCRIPT_STALLED`].
//!
//! `host.call` and `host.log` frames are written by the [`HostPort`] during the JS call that makes
//! them; the host always drains, so this cannot deadlock (§3.4). Every frame except the terminal
//! one is at most 1 MiB (a longer log line is cut to fit, [`LINE_TRUNCATED`]); the terminal frame
//! is at most `terminal_frame_max(limits)` (PD-136).
//!
//! Heap-limit discipline (PD-134): the engine checks `heap_refused` after every entry into
//! QuickJS, the port checks it before every write, and the loop checks it again before the
//! terminal frame. Once it is set nothing more is written and the worker exits
//! [`EXIT_HEAP_LIMIT`], so a script that catches `InternalError: out of memory` cannot turn the
//! run into a result or an error.
//!
//! Exit codes: 0 after the terminal frame (or on stdin EOF); [`EXIT_IO`] when stdin or stdout
//! fails; [`EXIT_PROTOCOL`] on a host frame that is not a response to an outstanding call (or an
//! init frame the shim cannot use); [`EXIT_HEAP_LIMIT`]; [`EXIT_PROCESS_LIMIT`]; [`EXIT_PANIC`]
//! for an engine failure that is neither the script's nor the host's (unreachable from script
//! code). The worker's own backstop deadline and op budget end the run as runtime
//! `script.error`s ([`SCRIPT_DEADLINE`], [`SCRIPT_OP_BUDGET`]), never as limit exits (PD-135).

#![deny(clippy::unwrap_used, clippy::expect_used, unsafe_code)]

use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::rc::Rc;
use std::sync::Arc;

use atlas_duck_ipc::sandbox::frame::{read_frame, write_frame};
use atlas_duck_ipc::sandbox::probe::encode_notification;
use atlas_duck_ipc::sandbox::script::{
    CompileRequest, EmptyParams, ErrorParams, HOST_TO_WORKER_MAX, LogParams, M_HOST_CALL,
    M_HOST_LOG, M_SCRIPT_COMPILED, M_SCRIPT_ERROR, M_SCRIPT_RESULT, M_SCRIPT_SYNTAX, RawJsonText,
    ResultParams, SyntaxParams, WorkerInit, encode_request, terminal_frame_max,
};
use atlas_duck_ipc::sandbox::{HostCall, MAX_FRAME_BYTES, WORKER_FRAME_MAX_BYTES};

use super::alloc::LimitState;
use super::{
    CompileError, Engine, EngineError, Halt, HostPort, RESULT_TOO_LARGE, ScriptError, Settled,
    SyntaxPos, compile,
};
use crate::{
    EXIT_HEAP_LIMIT, EXIT_IO, EXIT_OK, EXIT_PANIC, EXIT_PROCESS_LIMIT, EXIT_PROTOCOL, send,
    set_run_meter,
};

/// Plan text (PD-131): the class of the error sent when the script awaits a promise nothing can
/// settle (no host call outstanding, no job pending).
pub const SCRIPT_STALLED: &str = "ScriptStalled";
/// Plan text (PD-131).
pub const SCRIPT_STALLED_MESSAGE: &str = "the script awaited a promise that can never settle";

/// Plan text (PD-135, T4): the class of the runtime error sent when the worker's backstop deadline
/// (`timeout_s + 2 s`) stops the script. The host's own timer normally kills the worker first.
pub const SCRIPT_DEADLINE: &str = "ScriptDeadline";
/// Plan text (PD-135, T4).
pub const SCRIPT_DEADLINE_MESSAGE: &str = "the script ran past the worker's deadline";

/// Plan text (PD-135, T4): the class of the runtime error sent when the run used up its op budget.
pub const SCRIPT_OP_BUDGET: &str = "ScriptOpBudget";
/// Plan text (PD-135, T4).
pub const SCRIPT_OP_BUDGET_MESSAGE: &str = "the script used up its op budget";

/// Plan text (PD-136): the class of the error sent instead of a result that does not fit.
pub const RESULT_TOO_LARGE_CLASS: &str = "ResultTooLarge";

/// The class of the error sent when the source does not compile in run mode.
pub const SYNTAX_ERROR_CLASS: &str = "SyntaxError";

/// Plan text (T4): the marker that ends a `host.log` line cut to fit the 1 MiB frame cap.
pub const LINE_TRUNCATED: &str = "[line truncated]";

/// Plan value (T4): the marker that ends a `script.error` or `script.syntax` field cut to fit its
/// frame cap.
pub const FIELD_TRUNCATED: &str = "[truncated]";

/// The worker's stdout, shared by the host port (during the run) and the loop (the terminal
/// frame, written after the engine is dropped).
type Out<W> = Rc<RefCell<W>>;

/// The [`HostPort`] of a run: writes `host.call` and `host.log` frames to stdout.
struct StreamPort<W> {
    out: Out<W>,
    /// Set right after the engine is built; before that no script code can reach the port.
    meter: Option<Arc<LimitState>>,
}

impl<W: Write> StreamPort<W> {
    /// Refuses every write once a memory limit was hit (PD-134).
    fn write(&self, payload: &[u8]) -> io::Result<()> {
        if self
            .meter
            .as_ref()
            .is_some_and(|m| m.heap_refused() || m.system_null())
        {
            return Err(io::Error::other("the run hit a memory limit"));
        }
        let mut out = self
            .out
            .try_borrow_mut()
            .map_err(|_| io::Error::other("stdout is in use"))?;
        send(&mut *out, payload)
    }
}

impl<W: Write> HostPort for StreamPort<W> {
    fn send_call(&mut self, id: u64, call: &HostCall) -> io::Result<()> {
        self.write(&encode_request(M_HOST_CALL, id, call))
    }

    fn send_log(&mut self, line: &str) -> io::Result<()> {
        self.write(&log_frame(line))
    }
}

/// How a run ends when it does not end by an exit code.
enum Terminal {
    Result(String),
    Error(ScriptError),
}

/// Script mode (PD-132 `script.run`): one run of `init`, then exit. The returned value is the
/// process exit code.
pub(crate) fn run_script<R: Read, W: Write + 'static>(
    init: WorkerInit,
    input: &mut R,
    output: W,
) -> i32 {
    let out: Out<W> = Rc::new(RefCell::new(output));
    // `write_frame` refuses anything above the channel's general cap whatever `max_result_mb` says.
    let cap = terminal_frame_max(&init.limits).min(MAX_FRAME_BYTES);
    let port = StreamPort {
        out: Rc::clone(&out),
        meter: None,
    };
    let built = Engine::new(&init, port);
    // The engine holds what it needs; the source and args are not kept twice.
    drop(init);
    let mut engine = match built {
        Ok(engine) => engine,
        Err(EngineError::Syntax(pos)) => {
            return write_terminal(&out, cap, None, Terminal::Error(syntax_error(&pos)));
        }
        Err(EngineError::Halted(halt)) => {
            return match halt_end(halt) {
                Ok(error) => write_terminal(&out, cap, None, Terminal::Error(error)),
                Err(code) => code,
            };
        }
        // The init data does not fit the shim (an op id that cannot be placed under `atlas`).
        Err(EngineError::Init(_)) => return EXIT_PROTOCOL,
    };
    let meter = Arc::clone(engine.meter());
    engine.host_mut().meter = Some(Arc::clone(&meter));
    set_run_meter(Arc::clone(&meter));

    let mut settled = match engine.start() {
        Ok(()) => engine.drain_jobs(),
        Err(halt) => Settled::Halted(halt),
    };
    let terminal = loop {
        match settled {
            Settled::Pending { outstanding: 0 } => {
                break Terminal::Error(ScriptError {
                    class: SCRIPT_STALLED.to_owned(),
                    message: SCRIPT_STALLED_MESSAGE.to_owned(),
                    stack: String::new(),
                });
            }
            Settled::Pending { .. } => {
                let frame = match read_frame(input, HOST_TO_WORKER_MAX) {
                    Ok(Some(frame)) => frame,
                    // §3.4: the worker exits on stdin EOF (the host gave up on the run).
                    Ok(None) => return EXIT_OK,
                    Err(_) => return EXIT_IO,
                };
                let Ok(text) = String::from_utf8(frame) else {
                    return EXIT_PROTOCOL;
                };
                settled = match engine.deliver(&text) {
                    Ok(()) => engine.drain_jobs(),
                    Err(halt) => Settled::Halted(halt),
                };
            }
            Settled::Result(text) => break Terminal::Result(text),
            Settled::Error(error) => break Terminal::Error(error),
            Settled::Halted(halt) => match halt_end(halt) {
                Ok(error) => break Terminal::Error(error),
                Err(code) => return code,
            },
        }
    };
    // Frees the QuickJS heap and the port before a frame of up to `max_result_mb` is built.
    drop(engine);
    write_terminal(&out, cap, Some(&meter), terminal)
}

/// Compile mode (PD-132 `script.compile`): `script.compiled` or `script.syntax`, then exit.
///
/// A compile that stops without a verdict (the worker's 12 s backstop or its op budget; the
/// host's own 10 s deadline normally kills the worker first) writes nothing and exits
/// [`EXIT_PANIC`]: it must never read as `script_syntax` (PD-135).
pub(crate) fn compile_mode<W: Write>(request: &CompileRequest, output: &mut W) -> i32 {
    let frame = match compile(&request.source) {
        Ok(()) => encode_notification(M_SCRIPT_COMPILED, &EmptyParams {}),
        Err(CompileError::Syntax(pos)) => syntax_frame(&pos),
        Err(CompileError::Halted(halt)) => {
            return match halt_end(halt) {
                Ok(_) => EXIT_PANIC,
                Err(code) => code,
            };
        }
    };
    match send(output, &frame) {
        Ok(()) => EXIT_OK,
        Err(_) => EXIT_IO,
    }
}

/// What a halt means for the run: a runtime error to report (`Ok`), or an exit code with nothing
/// more written (`Err`).
fn halt_end(halt: Halt) -> Result<ScriptError, i32> {
    let (class, message) = match halt {
        Halt::HeapLimit => return Err(EXIT_HEAP_LIMIT),
        Halt::ProcessLimit => return Err(EXIT_PROCESS_LIMIT),
        Halt::Io(_) => return Err(EXIT_IO),
        Halt::Protocol(_) => return Err(EXIT_PROTOCOL),
        Halt::Engine(_) => return Err(EXIT_PANIC),
        Halt::Deadline => (SCRIPT_DEADLINE, SCRIPT_DEADLINE_MESSAGE),
        Halt::OpBudget => (SCRIPT_OP_BUDGET, SCRIPT_OP_BUDGET_MESSAGE),
    };
    Ok(ScriptError {
        class: class.to_owned(),
        message: message.to_owned(),
        stack: String::new(),
    })
}

/// A run-mode compile failure as a script error; the position (in the agent's source) goes into
/// the stack in QuickJS's `at <file>:<line>:<column>` form.
fn syntax_error(pos: &SyntaxPos) -> ScriptError {
    ScriptError {
        class: SYNTAX_ERROR_CLASS.to_owned(),
        message: pos.message.clone(),
        stack: format!("    at <source>:{}:{}", pos.line, pos.column),
    }
}

/// Writes the terminal frame, unless a memory limit was hit since the engine's last report.
fn write_terminal<W: Write>(
    out: &Out<W>,
    cap: usize,
    meter: Option<&LimitState>,
    terminal: Terminal,
) -> i32 {
    if let Some(meter) = meter {
        if meter.heap_refused() {
            return EXIT_HEAP_LIMIT;
        }
        if meter.system_null() {
            return EXIT_PROCESS_LIMIT;
        }
    }
    let frame = match terminal {
        Terminal::Result(text) => {
            // `JSON.stringify` output made well-formed; a parse failure here is an engine fault.
            let Ok(value) = RawJsonText::from_string(text) else {
                return EXIT_PANIC;
            };
            let frame = encode_notification(M_SCRIPT_RESULT, &ResultParams { value });
            if frame.len() <= cap {
                frame
            } else {
                // The engine checked the text against `terminal_frame_max - 64 KiB`; this catches
                // a `max_result_mb` whose frame is above the channel's general cap.
                error_frame(
                    &ScriptError {
                        class: RESULT_TOO_LARGE_CLASS.to_owned(),
                        message: RESULT_TOO_LARGE.to_owned(),
                        stack: String::new(),
                    },
                    cap,
                )
            }
        }
        Terminal::Error(error) => error_frame(&error, cap),
    };
    let Ok(mut out) = out.try_borrow_mut() else {
        return EXIT_PANIC;
    };
    match write_frame(&mut *out, &frame) {
        Ok(()) => EXIT_OK,
        Err(_) => EXIT_IO,
    }
}

/// `script.error` within `cap`: the stack is cut first, then the message, then the class.
fn error_frame(error: &ScriptError, cap: usize) -> Vec<u8> {
    let fields = [
        error.stack.as_str(),
        error.message.as_str(),
        error.class.as_str(),
    ];
    fit_frame(&fields, FIELD_TRUNCATED, cap, |texts| {
        let [stack, message, class] = texts;
        encode_notification(
            M_SCRIPT_ERROR,
            &ErrorParams {
                class,
                message,
                stack,
            },
        )
    })
}

/// `host.log` within the 1 MiB cap.
fn log_frame(line: &str) -> Vec<u8> {
    fit_frame(&[line], LINE_TRUNCATED, WORKER_FRAME_MAX_BYTES, |[line]| {
        encode_notification(M_HOST_LOG, &LogParams { line })
    })
}

/// `script.syntax` within the 1 MiB cap.
fn syntax_frame(pos: &SyntaxPos) -> Vec<u8> {
    fit_frame(
        &[pos.message.as_str()],
        FIELD_TRUNCATED,
        WORKER_FRAME_MAX_BYTES,
        |[message]| {
            encode_notification(
                M_SCRIPT_SYNTAX,
                &SyntaxParams {
                    line: pos.line,
                    column: pos.column,
                    message,
                },
            )
        },
    )
}

/// Encodes `fields` with `encode` and, while the frame is above `cap`, cuts them in order (the
/// first field first) at a character boundary, ending each cut field with `marker`. The cut is
/// computed from the JSON-escaped length (escaping can make a character 6 bytes), so the frame
/// ends up just within the cap. Returns the last encoding if even empty fields do not fit.
fn fit_frame<const N: usize>(
    fields: &[&str; N],
    marker: &str,
    cap: usize,
    encode: impl Fn([String; N]) -> Vec<u8>,
) -> Vec<u8> {
    // No field can keep more raw bytes than the cap: it would not fit even unescaped.
    let mut keep: [usize; N] = fields.map(|f| floor_boundary(f, f.len().min(cap)));
    loop {
        let texts: [String; N] = std::array::from_fn(|i| {
            if keep[i] == fields[i].len() {
                fields[i].to_owned()
            } else {
                format!("{}{marker}", &fields[i][..keep[i]])
            }
        });
        let frame = encode(texts);
        if frame.len() <= cap {
            return frame;
        }
        let over = frame.len() - cap;
        let Some(i) = (0..N).find(|&i| keep[i] > 0) else {
            return frame;
        };
        let field = fields[i];
        // Cutting a whole field adds the marker.
        let marker_cost = if keep[i] == field.len() {
            escaped_len(marker)
        } else {
            0
        };
        let budget = escaped_len(&field[..keep[i]])
            .saturating_sub(over)
            .saturating_sub(marker_cost);
        keep[i] = prefix_within(&field[..keep[i]], budget);
    }
}

/// The largest char boundary of `s` at or below `at`.
fn floor_boundary(s: &str, at: usize) -> usize {
    let mut at = at.min(s.len());
    while !s.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// The bytes `c` takes inside a JSON string as serde_json writes it.
fn escaped_char_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
        c if u32::from(c) < 0x20 => 6,
        c => c.len_utf8(),
    }
}

fn escaped_len(s: &str) -> usize {
    s.chars().map(escaped_char_len).sum()
}

/// The byte length of the longest prefix of `s` whose escaped length is at most `budget`.
fn prefix_within(s: &str, budget: usize) -> usize {
    let mut used = 0;
    for (at, c) in s.char_indices() {
        used += escaped_char_len(c);
        if used > budget {
            return at;
        }
    }
    s.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_lengths_match_serde_json() -> serde_json::Result<()> {
        let samples = [
            "plain",
            "quote \" backslash \\",
            "\u{8}\u{c}\n\r\t",
            "\u{0}\u{1}\u{1f}\u{7f}",
            "é€😀",
            "",
        ];
        for s in samples {
            // The JSON text minus its two quotes.
            assert_eq!(escaped_len(s), serde_json::to_string(s)?.len() - 2, "{s:?}");
        }
        Ok(())
    }

    #[test]
    fn fit_frame_keeps_short_fields_and_cuts_in_order() {
        let encode = |[a, b]: [String; 2]| format!("{a}|{b}").into_bytes();
        assert_eq!(fit_frame(&["ab", "cd"], "~", 10, encode), b"ab|cd");
        // Over by 3: the first field is cut first (to 2 bytes + the marker).
        assert_eq!(fit_frame(&["abcdef", "gh"], "~", 6, encode), b"ab~|gh");
        // The first field gone entirely, then the second is cut.
        assert_eq!(fit_frame(&["abcdef", "ghij"], "~", 5, encode), b"~|gh~");
        // Nothing fits: the last attempt comes back.
        assert_eq!(fit_frame(&["abc", "def"], "~", 2, encode), b"~|~");
    }

    #[test]
    fn cuts_land_on_char_boundaries() {
        assert_eq!(floor_boundary("aé", 2), 1);
        assert_eq!(floor_boundary("aé", 3), 3);
        // "é" takes 2 bytes, U+0001 6 (escaped), "x" 1.
        assert_eq!(prefix_within("é\u{1}x", 2), 2);
        assert_eq!(prefix_within("é\u{1}x", 7), 2);
        assert_eq!(prefix_within("é\u{1}x", 8), 3);
        assert_eq!(prefix_within("é\u{1}x", 9), 4);
    }
}
