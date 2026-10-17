//! The per-run state machine of the sandbox channel (§3.4 "Per-run state machine", "Violations",
//! "Logs"). Pure: no I/O, no clock, no lock. The bridge holds it behind its run lock, feeds it
//! every decoded frame, and acts on the [`Step`] it returns after the lock is released.
//!
//! Rules:
//! - `host.call` ids strictly increase (the decoder already refuses id 0 and an envelope id that
//!   differs from `HostCall.id`). A call is outstanding from its frame until its result is queued
//!   for writing ([`RunState::complete_call`]); a call that arrives while `max_concurrent_calls`
//!   are outstanding is a violation.
//! - Exactly one terminal frame (`script.result` / `script.error`) decides the run. After it,
//!   frames are ignored, except a second terminal frame, which is a violation (§3.4 lists both).
//! - The first host cause (a violation, the run timer, a kill from the caller) decides the run
//!   unless a terminal frame decided it first. After a cause, every frame is ignored.
//! - Frame caps: 1 MiB for every frame, `terminal_frame_max(limits)` for a terminal frame. The
//!   reader cannot know the method before it read the body, so the check runs after decoding.
//! - Logs: 1 MiB and 10 000 lines per run; past either cap every line is discarded and counted.
//!
//! Every step is cheap: the one costly check, whether a result reads as a `Value` (a parse of up
//! to `max_result_mb` + 64 KiB), runs in [`Incoming::from`] on the reader thread before the run
//! lock is taken (review I-1: a kill never waits for it).
//!
//! The run's verdict from these facts and the worker's exit is [`RunState::verdict`]; M8 Task 9
//! replaces it with the host-measured attribution (`attribute`, PD-134).

use atlas_duck_ipc::sandbox::script::{DecodeError, WorkerFrame};
use atlas_duck_ipc::sandbox::{
    EXIT_PROTOCOL, HostCall, ScriptLimits, WORKER_FRAME_MAX_BYTES, terminal_frame_max,
};

use super::{HostVerdict, KillCause, LOG_CAP_BYTES, LOG_CAP_LINES, RESULT_NOT_REPRESENTABLE};
use super::{WorkerEnd, log_truncated_marker};
use crate::spawn::ExitKind;

/// Why the host ended a run as a `protocol_violation` (§3.4 "Violations").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    /// A frame above its cap (1 MiB, or `max_result_mb` + 64 KiB for a terminal frame).
    Oversize,
    /// Not UTF-8, not JSON, not a JSON-RPC 2.0 message of the script protocol, or bad params.
    Malformed,
    /// A method the worker may not send.
    UnknownMethod,
    /// A JSON-RPC response from the worker: an answer to an id the host never issued.
    WorkerResponse,
    /// A `host.call` whose envelope id differs from `HostCall.id`.
    IdMismatch,
    /// A `host.call` id that is not above the previous one (duplicate or decreasing).
    IdNotIncreasing,
    /// A `host.call` while `max_concurrent_calls` calls are outstanding.
    TooManyCalls,
    /// A second terminal frame.
    SecondTerminal,
    /// A frame of the other mode (`script.compiled` / `script.syntax` during a run).
    UnexpectedFrame,
    /// The worker left more call results unread than [`super::unread_results_cap`] allows: it
    /// kept calling without reading its stdin. The shim reads every answer before it sends the
    /// call that replaces it, so it never has more than `max_concurrent_calls` unread (T8
    /// finding 1).
    UnreadResults,
}

/// What the host itself did to end the run, first one wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostCause {
    /// The run timer (`timeout_s`, PD-135).
    Timeout,
    /// The bridge killed the worker for a channel violation.
    Violation(ViolationKind),
    /// The caller killed the run ([`super::RunHandleImpl::kill`]).
    Killed(KillCause),
}

/// What the bridge must do after a frame, outside the run lock.
#[derive(Debug, PartialEq)]
pub(crate) enum Step {
    /// Nothing (a counted or discarded log line, an ignored frame).
    Nothing,
    /// A log line within the caps, for [`super::HostCallSink::log`].
    Log(String),
    /// A call to hand to [`super::HostCallSink::call`].
    Call(HostCall),
    /// The terminal frame decided the run: stop writing, kill (no cause). The timer stays armed
    /// until the reap.
    Terminal,
    /// A violation decided the run: stop writing, kill, discard the rest.
    Violation,
}

/// A decoded worker frame, its terminal payload already classified.
#[derive(Debug)]
pub(crate) enum Incoming {
    Call {
        id: u64,
        call: HostCall,
    },
    Log {
        line: String,
    },
    /// `script.result` or `script.error`, as the payload the run reports.
    Terminal(WorkerEnd),
    /// `script.compiled` / `script.syntax`: frames of the compile mode.
    CompileReply,
}

impl From<WorkerFrame> for Incoming {
    /// Runs on the reader thread, outside the run lock: for a `script.result` it parses the whole
    /// value (T4 fix I-1, binding fallback: a result the core cannot read into a `Value` is a
    /// worker-reported runtime error, never a violation or a crash).
    fn from(frame: WorkerFrame) -> Incoming {
        match frame {
            WorkerFrame::Call { id, call } => Incoming::Call { id, call },
            WorkerFrame::Log { line } => Incoming::Log { line },
            WorkerFrame::Result { value } if value.reads_as_value() => {
                Incoming::Terminal(WorkerEnd::Result { value_json: value })
            }
            WorkerFrame::Result { .. } => Incoming::Terminal(WorkerEnd::Error {
                class: "TypeError".to_owned(),
                message: RESULT_NOT_REPRESENTABLE.to_owned(),
                stack: String::new(),
            }),
            WorkerFrame::Error {
                class,
                message,
                stack,
            } => Incoming::Terminal(WorkerEnd::Error {
                class,
                message,
                stack,
            }),
            WorkerFrame::Compiled | WorkerFrame::Syntax { .. } => Incoming::CompileReply,
        }
    }
}

/// Log lines kept within the per-run caps.
#[derive(Debug, Default)]
struct Logs {
    lines: Vec<String>,
    bytes: usize,
    /// Bytes of the lines discarded past the caps.
    discarded: u64,
    truncated: bool,
}

impl Logs {
    /// Keeps `line` if it fits both caps and nothing was discarded yet.
    fn push(&mut self, line: &str) -> bool {
        if self.truncated
            || self.lines.len() >= LOG_CAP_LINES
            || self.bytes.saturating_add(line.len()) > LOG_CAP_BYTES
        {
            self.truncated = true;
            self.discarded = self.discarded.saturating_add(line.len() as u64);
            return false;
        }
        self.bytes += line.len();
        self.lines.push(line.to_owned());
        true
    }

    /// The kept lines, plus the marker when any line was discarded.
    fn take(&mut self) -> (Vec<String>, Option<u64>) {
        let mut lines = std::mem::take(&mut self.lines);
        if !self.truncated {
            return (lines, None);
        }
        lines.push(log_truncated_marker(self.discarded));
        (lines, Some(self.discarded))
    }
}

/// One run's channel state (see the module documentation).
#[derive(Debug)]
pub(crate) struct RunState {
    max_concurrent_calls: u32,
    terminal_cap: usize,
    last_call_id: u64,
    outstanding: u32,
    terminal: bool,
    end: WorkerEnd,
    cause: Option<HostCause>,
    logs: Logs,
}

impl RunState {
    pub(crate) fn new(limits: &ScriptLimits) -> RunState {
        RunState {
            max_concurrent_calls: limits.max_concurrent_calls,
            terminal_cap: terminal_frame_max(limits),
            last_call_id: 0,
            outstanding: 0,
            terminal: false,
            end: WorkerEnd::None,
            cause: None,
            logs: Logs::default(),
        }
    }

    /// The largest frame the reader may read whole: the terminal cap, or 1 MiB if that is lower.
    pub(crate) fn read_cap(limits: &ScriptLimits) -> usize {
        terminal_frame_max(limits).max(WORKER_FRAME_MAX_BYTES)
    }

    /// A terminal frame or a host cause decided the run.
    pub(crate) fn decided(&self) -> bool {
        self.terminal || self.cause.is_some()
    }

    /// The host killed the worker for a violation: the reader discards the rest of the stream.
    pub(crate) fn violated(&self) -> bool {
        matches!(self.cause, Some(HostCause::Violation(_)))
    }

    /// One frame of `len` payload bytes, as the decoder read it and [`Incoming::from`] classified
    /// it. No parse and no copy of the payload happens here.
    pub(crate) fn on_frame(&mut self, len: usize, frame: Result<Incoming, DecodeError>) -> Step {
        if self.cause.is_some() {
            return Step::Nothing;
        }
        if self.terminal {
            // Frames after the terminal are ignored; a second terminal is a violation.
            return match frame {
                Ok(Incoming::Terminal(_)) => self.violate(ViolationKind::SecondTerminal),
                _ => Step::Nothing,
            };
        }
        let frame = match frame {
            Ok(frame) => frame,
            Err(e) => return self.violate(violation_of(&e)),
        };
        let cap = match frame {
            Incoming::Terminal(_) => self.terminal_cap,
            _ => WORKER_FRAME_MAX_BYTES,
        };
        if len > cap {
            return self.violate(ViolationKind::Oversize);
        }
        match frame {
            Incoming::Call { id, call } => {
                if id <= self.last_call_id {
                    return self.violate(ViolationKind::IdNotIncreasing);
                }
                if self.outstanding >= self.max_concurrent_calls {
                    return self.violate(ViolationKind::TooManyCalls);
                }
                self.last_call_id = id;
                self.outstanding += 1;
                Step::Call(call)
            }
            Incoming::Log { line } => {
                if self.logs.push(&line) {
                    Step::Log(line)
                } else {
                    Step::Nothing
                }
            }
            Incoming::Terminal(end) => {
                self.terminal = true;
                self.end = end;
                Step::Terminal
            }
            Incoming::CompileReply => self.violate(ViolationKind::UnexpectedFrame),
        }
    }

    /// A frame header announced more than [`RunState::read_cap`]; its body was not read, so the
    /// stream cannot be read further. A violation unless the run is already decided.
    pub(crate) fn on_oversize_header(&mut self) -> Step {
        if self.decided() {
            return Step::Nothing;
        }
        self.violate(ViolationKind::Oversize)
    }

    /// The run timer expired. True if this decided the run.
    pub(crate) fn on_timeout(&mut self) -> bool {
        self.decide_by(HostCause::Timeout)
    }

    /// The caller killed the run. True if this decided the run.
    pub(crate) fn on_kill(&mut self, cause: KillCause) -> bool {
        self.decide_by(HostCause::Killed(cause))
    }

    /// A call's result would take the bytes queued for the worker above the cap. True if this
    /// decided the run (as a violation).
    pub(crate) fn on_unread_results(&mut self) -> bool {
        self.decide_by(HostCause::Violation(ViolationKind::UnreadResults))
    }

    /// A call's result is ready. True if it is to be queued for the worker (the run is not
    /// decided); the call stops counting as outstanding in the same step.
    pub(crate) fn complete_call(&mut self) -> bool {
        if self.decided() {
            return false;
        }
        self.outstanding = self.outstanding.saturating_sub(1);
        true
    }

    /// The kept log lines (with the marker) and the discarded byte count.
    pub(crate) fn take_logs(&mut self) -> (Vec<String>, Option<u64>) {
        self.logs.take()
    }

    /// The worker's terminal payload, if a terminal frame was accepted.
    pub(crate) fn take_end(&mut self) -> WorkerEnd {
        std::mem::replace(&mut self.end, WorkerEnd::None)
    }

    /// Whether a terminal frame was accepted.
    pub(crate) fn terminal(&self) -> bool {
        self.terminal
    }

    /// The host's verdict: its own cause first, then an accepted terminal frame (the exit no
    /// longer matters), then `EXIT_PROTOCOL` (the worker could not read what the host sent: a
    /// host fault, T4), else the exit without a terminal frame, `Code(0)` included, is a crash
    /// (T4: stdin EOF exits 0 with no frame). `exit` is `None` when it is unknown (the reap
    /// failed).
    ///
    /// M8 Task 9 replaces this with `attribute` (heap / process limits from the exit, the
    /// Windows job message, the macOS watchdog).
    pub(crate) fn verdict(&self, exit: Option<ExitKind>) -> HostVerdict {
        match &self.cause {
            Some(HostCause::Timeout) => HostVerdict::Limit("timeout_s"),
            Some(HostCause::Violation(kind)) => HostVerdict::Violation(*kind),
            Some(HostCause::Killed(cause)) => HostVerdict::Killed(cause.clone()),
            None if self.terminal => HostVerdict::None,
            None if exit == Some(ExitKind::Code(EXIT_PROTOCOL)) => HostVerdict::HostFault,
            None => HostVerdict::Crashed(exit),
        }
    }

    fn decide_by(&mut self, cause: HostCause) -> bool {
        if self.decided() {
            return false;
        }
        self.cause = Some(cause);
        true
    }

    fn violate(&mut self, kind: ViolationKind) -> Step {
        if self.cause.is_none() {
            self.cause = Some(HostCause::Violation(kind));
        }
        Step::Violation
    }
}

fn violation_of(e: &DecodeError) -> ViolationKind {
    match e {
        DecodeError::UnknownMethod(_) => ViolationKind::UnknownMethod,
        DecodeError::WorkerResponse => ViolationKind::WorkerResponse,
        DecodeError::IdMismatch { .. } => ViolationKind::IdMismatch,
        DecodeError::Json(_)
        | DecodeError::NotObject
        | DecodeError::WrongVersion
        | DecodeError::MissingMethod
        | DecodeError::ExtraKey(_)
        | DecodeError::DuplicateKey(_)
        | DecodeError::BadId
        | DecodeError::UnexpectedId
        | DecodeError::BadParams { .. } => ViolationKind::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use atlas_duck_ipc::sandbox::script::{RawJsonText, decode_worker_frame};

    use super::*;

    fn frame(text: &str) -> (usize, Result<Incoming, DecodeError>) {
        (
            text.len(),
            decode_worker_frame(text.as_bytes()).map(Incoming::from),
        )
    }

    fn call(id: u64) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"host.call","params":{{"id":{id},"op_id":"a.b","params":{{}},"instance":null,"all":false}}}}"#
        )
    }

    const RESULT: &str = r#"{"jsonrpc":"2.0","method":"script.result","params":{"value":[1]}}"#;
    const ERROR: &str = r#"{"jsonrpc":"2.0","method":"script.error","params":{"class":"E","message":"m","stack":""}}"#;

    fn feed(state: &mut RunState, text: &str) -> Step {
        let (len, f) = frame(text);
        state.on_frame(len, f)
    }

    fn state(max_concurrent_calls: u32) -> RunState {
        RunState::new(&ScriptLimits {
            max_concurrent_calls,
            ..ScriptLimits::default()
        })
    }

    #[test]
    fn calls_count_until_completed_and_ids_increase() {
        let mut s = state(2);
        assert!(matches!(feed(&mut s, &call(1)), Step::Call(c) if c.id == 1));
        assert!(matches!(feed(&mut s, &call(3)), Step::Call(c) if c.id == 3));
        assert!(s.complete_call());
        assert!(matches!(feed(&mut s, &call(4)), Step::Call(_)));
        assert_eq!(feed(&mut s, &call(5)), Step::Violation);
        assert_eq!(
            s.verdict(None),
            HostVerdict::Violation(ViolationKind::TooManyCalls)
        );
        // Decided: a late result is not queued, later frames are ignored.
        assert!(!s.complete_call());
        assert_eq!(feed(&mut s, RESULT), Step::Nothing);

        let mut s = state(4);
        assert!(matches!(feed(&mut s, &call(2)), Step::Call(_)));
        assert_eq!(feed(&mut s, &call(2)), Step::Violation);
        assert_eq!(
            s.verdict(None),
            HostVerdict::Violation(ViolationKind::IdNotIncreasing)
        );
    }

    #[test]
    fn the_first_decision_wins() {
        let mut s = state(4);
        assert_eq!(feed(&mut s, RESULT), Step::Terminal);
        assert!(!s.on_timeout());
        assert!(!s.on_kill(KillCause::User));
        assert_eq!(s.verdict(Some(ExitKind::Signal(9))), HostVerdict::None);
        assert_eq!(
            feed(&mut s, &call(1)),
            Step::Nothing,
            "ignored after the terminal"
        );
        assert_eq!(feed(&mut s, "garbage"), Step::Nothing);
        assert_eq!(s.on_oversize_header(), Step::Nothing);
        assert_eq!(feed(&mut s, ERROR), Step::Violation, "second terminal");
        assert_eq!(
            s.verdict(None),
            HostVerdict::Violation(ViolationKind::SecondTerminal)
        );
        assert!(matches!(s.take_end(), WorkerEnd::Result { .. }));

        let mut s = state(4);
        assert!(s.on_kill(KillCause::Shutdown));
        assert!(!s.on_timeout());
        assert_eq!(feed(&mut s, RESULT), Step::Nothing);
        assert_eq!(
            s.verdict(Some(ExitKind::Code(0))),
            HostVerdict::Killed(KillCause::Shutdown)
        );
        assert_eq!(s.take_end(), WorkerEnd::None);

        let mut s = state(4);
        assert!(s.on_timeout());
        assert_eq!(s.verdict(None), HostVerdict::Limit("timeout_s"));
    }

    #[test]
    fn without_terminal_or_cause_every_exit_is_a_crash() {
        let s = state(4);
        assert_eq!(
            s.verdict(Some(ExitKind::Code(0))),
            HostVerdict::Crashed(Some(ExitKind::Code(0)))
        );
        assert_eq!(
            s.verdict(Some(ExitKind::Signal(31))),
            HostVerdict::Crashed(Some(ExitKind::Signal(31)))
        );
        assert_eq!(s.verdict(None), HostVerdict::Crashed(None), "exit unknown");
        // -1 is a legal Windows exit code, distinct from an unknown exit.
        assert_eq!(
            s.verdict(Some(ExitKind::Code(-1))),
            HostVerdict::Crashed(Some(ExitKind::Code(-1)))
        );
    }

    #[test]
    fn unread_results_decide_only_an_undecided_run() {
        let mut s = state(4);
        assert!(matches!(feed(&mut s, &call(1)), Step::Call(_)));
        assert!(s.on_unread_results());
        assert!(s.decided() && s.violated());
        assert_eq!(
            s.verdict(Some(ExitKind::Signal(9))),
            HostVerdict::Violation(ViolationKind::UnreadResults)
        );
        assert!(!s.complete_call(), "nothing is queued after the decision");

        let mut s = state(4);
        assert_eq!(feed(&mut s, RESULT), Step::Terminal);
        assert!(!s.on_unread_results());
        assert_eq!(s.verdict(None), HostVerdict::None);
    }

    /// T4 hand-off: `EXIT_PROTOCOL` without a terminal is the host's fault; a host cause and an
    /// accepted terminal still come first.
    #[test]
    fn exit_protocol_is_a_host_fault_unless_decided() {
        let protocol = Some(ExitKind::Code(EXIT_PROTOCOL));
        assert_eq!(state(4).verdict(protocol), HostVerdict::HostFault);
        assert!(!state(4).terminal());

        let mut s = state(4);
        assert_eq!(feed(&mut s, RESULT), Step::Terminal);
        assert!(s.terminal());
        assert_eq!(s.verdict(protocol), HostVerdict::None);

        let mut s = state(4);
        assert!(s.on_kill(KillCause::User));
        assert_eq!(s.verdict(protocol), HostVerdict::Killed(KillCause::User));
    }

    #[test]
    fn caps_apply_per_kind_after_decoding() {
        let limits = ScriptLimits {
            max_result_mb: 2,
            ..ScriptLimits::default()
        };
        let mut s = RunState::new(&limits);
        let (_, f) = frame(r#"{"jsonrpc":"2.0","method":"host.log","params":{"line":"x"}}"#);
        assert_eq!(s.on_frame(WORKER_FRAME_MAX_BYTES + 1, f), Step::Violation);
        assert_eq!(
            s.verdict(None),
            HostVerdict::Violation(ViolationKind::Oversize)
        );

        let mut s = RunState::new(&limits);
        let (_, f) = frame(RESULT);
        assert_eq!(s.on_frame(terminal_frame_max(&limits), f), Step::Terminal);
        let mut s = RunState::new(&limits);
        let (_, f) = frame(RESULT);
        assert_eq!(
            s.on_frame(terminal_frame_max(&limits) + 1, f),
            Step::Violation
        );

        assert_eq!(RunState::read_cap(&limits), 2 * 1024 * 1024 + 64 * 1024);
        let tiny = ScriptLimits {
            max_result_mb: 0,
            ..ScriptLimits::default()
        };
        assert_eq!(RunState::read_cap(&tiny), WORKER_FRAME_MAX_BYTES);
    }

    #[test]
    fn decode_errors_map_to_their_violation() {
        let cases = [
            ("{", ViolationKind::Malformed),
            (
                r#"{"jsonrpc":"2.0","method":"x.y","params":{}}"#,
                ViolationKind::UnknownMethod,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"result":1}"#,
                ViolationKind::WorkerResponse,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"host.call","params":{"id":2,"op_id":"a.b","params":{},"instance":null,"all":false}}"#,
                ViolationKind::IdMismatch,
            ),
            (
                r#"{"jsonrpc":"2.0","method":"script.compiled","params":{}}"#,
                ViolationKind::UnexpectedFrame,
            ),
        ];
        for (text, kind) in cases {
            let mut s = state(4);
            assert_eq!(feed(&mut s, text), Step::Violation, "{text}");
            assert_eq!(s.verdict(None), HostVerdict::Violation(kind), "{text}");
            assert!(s.violated());
        }
    }

    #[test]
    fn logs_keep_1mib_and_10000_lines_then_one_marker() {
        let mut logs = Logs::default();
        for _ in 0..LOG_CAP_LINES {
            assert!(logs.push(""));
        }
        assert!(!logs.push("abc"));
        assert!(!logs.push(""));
        let (lines, n) = logs.take();
        assert_eq!(lines.len(), LOG_CAP_LINES + 1);
        assert_eq!(n, Some(3));
        assert_eq!(
            lines.last().map(String::as_str),
            Some("[log truncated: 3 bytes]")
        );

        let mut logs = Logs::default();
        let half = "h".repeat(LOG_CAP_BYTES / 2);
        assert!(logs.push(&half));
        assert!(logs.push(&half), "exactly at the cap");
        assert!(!logs.push("x"));
        assert_eq!(logs.take().1, Some(1));
    }

    #[test]
    fn a_result_the_core_cannot_read_is_a_type_error() -> Result<(), String> {
        let mut s = state(4);
        let text = r#"{"jsonrpc":"2.0","method":"script.result","params":{"value":"\ud800"}}"#;
        assert_eq!(feed(&mut s, text), Step::Terminal);
        assert_eq!(
            s.take_end(),
            WorkerEnd::Error {
                class: "TypeError".to_owned(),
                message: RESULT_NOT_REPRESENTABLE.to_owned(),
                stack: String::new(),
            }
        );
        assert_eq!(s.verdict(None), HostVerdict::None);

        let mut s = state(4);
        assert_eq!(feed(&mut s, RESULT), Step::Terminal);
        let expected = RawJsonText::from_string("[1]".to_owned()).map_err(|e| e.to_string())?;
        assert_eq!(
            s.take_end(),
            WorkerEnd::Result {
                value_json: Box::new(expected)
            }
        );
        Ok(())
    }
}
