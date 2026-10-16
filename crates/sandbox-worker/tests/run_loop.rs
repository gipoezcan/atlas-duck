//! Worker run loop and modes (plan M8 Task 4; spec §3.4, §9.1 steps 3 and 5, §9.2, §9.3; PD-131,
//! PD-132, PD-134, PD-136). In-process only: `run_script_with` runs on an 8 MiB thread (the
//! worker's main-thread stack) over in-memory pipes; `confine::apply` and `run()` are never called
//! and no child process is started.
//!
//! Most tests feed the worker a scripted host: the host frames are fixed up front (the shim numbers
//! calls 1, 2, 3, ... in call order, so the answers are known), and one event log records when the
//! worker starts reading each host frame and every frame it writes. The interleaving in that log is
//! what the loop did, without timing. One test drives the worker over `std::io::pipe` with a host
//! that answers each call as it arrives.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use atlas_duck_ipc::sandbox::frame::{read_frame, write_frame};
use atlas_duck_ipc::sandbox::probe::{
    ConfinementReport, M_PROBE_READY, M_PROBE_RESULT, M_PROBE_RUN, ProbeId, ProbeReady,
    ProbeRequest, decode_notification, encode_notification,
};
use atlas_duck_ipc::sandbox::script::{
    CompileRequest, InstanceInfo, M_SCRIPT_COMPILE, M_SCRIPT_RUN, WorkerFrame, WorkerInit,
    decode_worker_frame, encode_response, terminal_frame_max,
};
use atlas_duck_ipc::sandbox::{
    HostCallResult, MAX_FRAME_BYTES, ScriptLimits, WORKER_FRAME_MAX_BYTES,
};
use atlas_duck_sandbox_worker::script::RESULT_TOO_LARGE;
use atlas_duck_sandbox_worker::{
    EXIT_HEAP_LIMIT, EXIT_IO, EXIT_OK, EXIT_PANIC, EXIT_PROCESS_LIMIT, EXIT_PROTOCOL,
    FIELD_TRUNCATED, LINE_TRUNCATED, SCRIPT_DEADLINE, SCRIPT_DEADLINE_MESSAGE, SCRIPT_STALLED,
    SCRIPT_STALLED_MESSAGE, run_script_with, run_with,
};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MIB: usize = 1024 * 1024;

fn fake_confinement() -> ConfinementReport {
    ConfinementReport {
        applied: true,
        mechanism: "test-fake".to_owned(),
        no_new_privs: Some(true),
        landlock_abi: None,
        seccomp: None,
        lpac: None,
        os_error: None,
    }
}

/// One step of a run as the scripted host saw it.
#[derive(Debug, Clone, PartialEq)]
enum Event {
    /// The worker started reading host frame number `n` (0-based).
    HostFrame(usize),
    /// The worker wrote one whole frame (the payload).
    Worker(Vec<u8>),
}

#[derive(Clone, Default)]
struct EventLog(Arc<Mutex<Vec<Event>>>);

impl EventLog {
    fn push(&self, event: Event) {
        if let Ok(mut events) = self.0.lock() {
            events.push(event);
        }
    }

    fn take(&self) -> Result<Vec<Event>, String> {
        self.0
            .lock()
            .map(|events| events.clone())
            .map_err(|_| "the event log is poisoned".to_owned())
    }
}

/// The worker's stdin: fixed chunks (normally one length-prefixed frame each), then EOF.
struct ScriptedInput {
    chunks: VecDeque<Vec<u8>>,
    current: Vec<u8>,
    pos: usize,
    next: usize,
    log: EventLog,
}

impl Read for ScriptedInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos == self.current.len() {
            match self.chunks.pop_front() {
                None => return Ok(0),
                Some(chunk) => {
                    self.log.push(Event::HostFrame(self.next));
                    self.next += 1;
                    self.current = chunk;
                    self.pos = 0;
                }
            }
        }
        let n = buf.len().min(self.current.len() - self.pos);
        buf[..n].copy_from_slice(&self.current[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// The worker's stdout: logs each whole frame as it completes.
struct RecordingOutput {
    pending: Vec<u8>,
    log: EventLog,
}

impl Write for RecordingOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);
        while self.pending.len() >= 4 {
            let len = u32::from_be_bytes([
                self.pending[0],
                self.pending[1],
                self.pending[2],
                self.pending[3],
            ]) as usize;
            if self.pending.len() < 4 + len {
                break;
            }
            let payload = self.pending[4..4 + len].to_vec();
            self.pending.drain(..4 + len);
            self.log.push(Event::Worker(payload));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A length-prefixed frame.
fn framed(payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    write_frame(&mut out, payload).map_err(|e| e.to_string())?;
    Ok(out)
}

fn run_frame(init: &WorkerInit) -> Result<Vec<u8>, String> {
    framed(&encode_notification(M_SCRIPT_RUN, init))
}

fn compile_frame(source: &str) -> Result<Vec<u8>, String> {
    framed(&encode_notification(
        M_SCRIPT_COMPILE,
        &CompileRequest {
            source: source.to_owned(),
        },
    ))
}

fn answer(id: u64, value: Value) -> Result<Vec<u8>, String> {
    framed(&encode_response(id, &HostCallResult::Ok(value)))
}

fn reject(id: u64, class: &str) -> Result<Vec<u8>, String> {
    framed(&encode_response(
        id,
        &HostCallResult::Rejected {
            class: class.to_owned(),
            details: json!({"why": "test"}),
        },
    ))
}

fn probe_frame(probe: ProbeId) -> Result<Vec<u8>, String> {
    let req = ProbeRequest {
        probe,
        app_pid: std::process::id(),
        profile_path: String::new(),
        public_addr: String::new(),
        loopback_addr: String::new(),
        handle_value: None,
    };
    framed(&encode_notification(M_PROBE_RUN, &req))
}

fn init_with(source: &str, args: Value, limits: ScriptLimits) -> WorkerInit {
    WorkerInit {
        source: source.to_owned(),
        args,
        limits,
        read_op_ids: vec!["jira.issue.get".to_owned(), "jira.search".to_owned()],
        instances: vec![InstanceInfo {
            alias: "prod".to_owned(),
            product: "jira".to_owned(),
            is_default: true,
        }],
    }
}

fn init(source: &str) -> WorkerInit {
    init_with(source, json!({}), ScriptLimits::default())
}

/// The worker's exit code and the event log of one run over the scripted host.
struct Run {
    code: i32,
    events: Vec<Event>,
}

impl Run {
    /// The frames the worker wrote after `probe.ready` (which must come first).
    fn frames(&self) -> Result<Vec<WorkerFrame>, String> {
        let mut written = self.events.iter().filter_map(|event| match event {
            Event::Worker(payload) => Some(payload),
            Event::HostFrame(_) => None,
        });
        let ready = written.next().ok_or("the worker wrote nothing")?;
        let (method, params) = decode_notification(ready).map_err(|e| e.to_string())?;
        if method != M_PROBE_READY {
            return Err(format!("first frame {method}, not probe.ready"));
        }
        let ready: ProbeReady = serde_json::from_value(params).map_err(|e| e.to_string())?;
        if ready.confinement != fake_confinement() {
            return Err("the ready frame changed the confinement report".to_owned());
        }
        written
            .map(|payload| decode_worker_frame(payload).map_err(|e| e.to_string()))
            .collect()
    }

    /// The run as short labels: `host#n`, `call n`, `log <line>`, `result <json>`,
    /// `error <class>`, `compiled`, `syntax`; `ready` for the first worker frame.
    fn trace(&self) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        let mut seen_ready = false;
        for event in &self.events {
            match event {
                Event::HostFrame(n) => out.push(format!("host#{n}")),
                Event::Worker(_) if !seen_ready => {
                    seen_ready = true;
                    out.push("ready".to_owned());
                }
                Event::Worker(payload) => {
                    let frame = decode_worker_frame(payload).map_err(|e| e.to_string())?;
                    out.push(match frame {
                        WorkerFrame::Call { id, .. } => format!("call {id}"),
                        WorkerFrame::Log { line } => format!("log {line}"),
                        WorkerFrame::Result { value } => format!("result {}", value.get()),
                        WorkerFrame::Error { class, .. } => format!("error {class}"),
                        WorkerFrame::Compiled => "compiled".to_owned(),
                        WorkerFrame::Syntax { .. } => "syntax".to_owned(),
                    });
                }
            }
        }
        Ok(out)
    }

    /// The one terminal frame, which must be the last frame.
    fn terminal(&self) -> Result<WorkerFrame, String> {
        let frames = self.frames()?;
        let last = frames.last().cloned().ok_or("no frame after ready")?;
        let terminals = frames
            .iter()
            .filter(|f| matches!(f, WorkerFrame::Result { .. } | WorkerFrame::Error { .. }))
            .count();
        if terminals != 1 || !matches!(last, WorkerFrame::Result { .. } | WorkerFrame::Error { .. })
        {
            return Err(format!(
                "expected one terminal frame at the end: {frames:?}"
            ));
        }
        Ok(last)
    }

    fn result(&self) -> Result<Value, String> {
        match self.terminal()? {
            WorkerFrame::Result { value } => {
                serde_json::from_str(value.get()).map_err(|e| e.to_string())
            }
            other => Err(format!("expected a result, got {other:?}")),
        }
    }

    fn error(&self) -> Result<(String, String, String), String> {
        match self.terminal()? {
            WorkerFrame::Error {
                class,
                message,
                stack,
            } => Ok((class, message, stack)),
            other => Err(format!("expected an error, got {other:?}")),
        }
    }

    fn expect_code(&self, code: i32) -> Result<(), String> {
        if self.code == code {
            Ok(())
        } else {
            Err(format!(
                "exit {} instead of {code}; trace {:?}",
                self.code,
                self.trace()
            ))
        }
    }
}

/// Runs `run_script_with` on an 8 MiB thread against the scripted host chunks.
fn run_worker(chunks: Vec<Vec<u8>>) -> Result<Run, String> {
    let log = EventLog::default();
    let mut input = ScriptedInput {
        chunks: chunks.into(),
        current: Vec::new(),
        pos: 0,
        next: 0,
        log: log.clone(),
    };
    let output = RecordingOutput {
        pending: Vec::new(),
        log: log.clone(),
    };
    let worker = std::thread::Builder::new()
        .stack_size(8 * MIB)
        .spawn(move || run_script_with(fake_confinement(), &mut input, output))
        .map_err(|e| e.to_string())?;
    let code = worker
        .join()
        .map_err(|_| "the worker panicked".to_owned())?;
    Ok(Run {
        code,
        events: log.take()?,
    })
}

/// Runs the source as a script with the given host answers.
fn run_script(init: &WorkerInit, answers: Vec<Vec<u8>>) -> Result<Run, String> {
    let mut chunks = vec![run_frame(init)?];
    chunks.extend(answers);
    run_worker(chunks)
}

fn strs(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

/// The full protocol over real in-memory pipes, with a host thread that answers each call as it
/// arrives: `probe.ready`, then `script.run`, a call, a log line, the result, exit 0, stdout closed.
#[test]
fn ready_then_init_then_result_then_exit() -> TestResult {
    let (mut worker_in, mut host_out) = io::pipe()?;
    let (mut host_in, worker_out) = io::pipe()?;
    let worker = std::thread::Builder::new()
        .stack_size(8 * MIB)
        .spawn(move || run_script_with(fake_confinement(), &mut worker_in, worker_out))?;

    let ready = read_frame(&mut host_in, MAX_FRAME_BYTES)?.ok_or("no ready frame")?;
    let (method, params) = decode_notification(&ready)?;
    assert_eq!(method, M_PROBE_READY);
    let ready: ProbeReady = serde_json::from_value(params)?;
    assert_eq!(ready.confinement, fake_confinement());

    let source = "const issue = await atlas.jira.issue.get({key: args.key});\n\
                  atlas.log('got', issue.key);\n\
                  return {key: issue.key, n: args.n};";
    let init = init_with(
        source,
        json!({"key": "ABC-1", "n": 7}),
        ScriptLimits::default(),
    );
    write_frame(&mut host_out, &encode_notification(M_SCRIPT_RUN, &init))?;

    let mut seen = Vec::new();
    loop {
        let frame = read_frame(&mut host_in, MAX_FRAME_BYTES)?.ok_or("stdout closed early")?;
        match decode_worker_frame(&frame)? {
            WorkerFrame::Call { id, call } => {
                assert_eq!(call.op_id, "jira.issue.get");
                seen.push(format!("call {id}"));
                let key = call.params.get("key").cloned().unwrap_or(Value::Null);
                write_frame(
                    &mut host_out,
                    &encode_response(id, &HostCallResult::Ok(json!({"key": key}))),
                )?;
            }
            WorkerFrame::Log { line } => seen.push(format!("log {line}")),
            WorkerFrame::Result { value } => {
                let value: Value = serde_json::from_str(value.get())?;
                assert_eq!(value, json!({"key": "ABC-1", "n": 7}));
                seen.push("result".to_owned());
                break;
            }
            other => return Err(format!("unexpected frame {other:?}").into()),
        }
    }
    assert_eq!(seen, strs(&["call 1", "log got ABC-1", "result"]));
    // After the terminal frame the worker exits and its stdout closes.
    assert!(read_frame(&mut host_in, MAX_FRAME_BYTES)?.is_none());
    drop(host_out);
    let code = worker.join().map_err(|_| "the worker panicked")?;
    assert_eq!(code, EXIT_OK);
    Ok(())
}

#[test]
fn compile_mode_reports_ok_and_syntax() -> TestResult {
    // A body that would throw if it ran: compile mode never runs it.
    let ok = run_worker(vec![compile_frame("throw new Error('ran');")?])?;
    ok.expect_code(EXIT_OK)?;
    assert_eq!(ok.frames()?, vec![WorkerFrame::Compiled]);

    let bad = run_worker(vec![compile_frame("const a = 1;\nconst b = 2;\n    )\n")?])?;
    bad.expect_code(EXIT_OK)?;
    match bad.frames()?.as_slice() {
        [WorkerFrame::Syntax { line, column, .. }] => assert_eq!((*line, *column), (3, 5)),
        other => return Err(format!("unexpected frames {other:?}").into()),
    }

    // Compile mode exits after its one reply: a second frame is never read.
    let once = run_worker(vec![
        compile_frame("return 1;")?,
        compile_frame("return 2;")?,
    ])?;
    once.expect_code(EXIT_OK)?;
    assert_eq!(once.trace()?, strs(&["ready", "host#0", "compiled"]));
    Ok(())
}

/// Results arrive 3, 1, 2; each settles its own promise.
#[test]
fn host_calls_resolve_in_any_order() -> TestResult {
    let source = "const ps = [1, 2, 3].map(n => atlas.call('jira.issue.get', {key: 'K-' + n}));\n\
                  return await Promise.all(ps);";
    let run = run_script(
        &init(source),
        vec![
            answer(3, json!("third"))?,
            answer(1, json!("first"))?,
            answer(2, json!("second"))?,
        ],
    )?;
    run.expect_code(EXIT_OK)?;
    assert_eq!(run.result()?, json!(["first", "second", "third"]));
    assert_eq!(
        run.trace()?,
        strs(&[
            "ready",
            "host#0",
            "call 1",
            "call 2",
            "call 3",
            "host#1",
            "host#2",
            "host#3",
            r#"result ["first","second","third"]"#,
        ])
    );
    Ok(())
}

/// Eight calls with `max_concurrent_calls = 3`: at no point are more than three sent and not
/// answered, and each answer lets exactly one queued call out.
#[test]
fn never_more_than_max_concurrent_outstanding() -> TestResult {
    let source = "const ps = [];\n\
                  for (let n = 1; n <= 8; n++) ps.push(atlas.call('jira.search', {n}));\n\
                  return (await Promise.all(ps)).reduce((a, b) => a + b, 0);";
    let limits = ScriptLimits {
        max_concurrent_calls: 3,
        ..ScriptLimits::default()
    };
    let answers = (1..=8)
        .map(|id| answer(id, json!(id)))
        .collect::<Result<Vec<_>, _>>()?;
    let run = run_script(&init_with(source, json!({}), limits), answers)?;
    run.expect_code(EXIT_OK)?;
    assert_eq!(run.result()?, json!(36));

    let mut outstanding = 0usize;
    let mut peak = 0usize;
    let mut sent = 0usize;
    for label in run.trace()? {
        if label.starts_with("call ") {
            outstanding += 1;
            sent += 1;
        } else if label.starts_with("host#") && label != "host#0" {
            outstanding = outstanding
                .checked_sub(1)
                .ok_or("an answer before its call")?;
        }
        peak = peak.max(outstanding);
    }
    assert_eq!(sent, 8);
    assert_eq!(peak, 3);
    let trace = run.trace()?;
    // The first three go out before the first answer is read; then one per answer.
    assert_eq!(
        &trace[..9],
        &strs(&[
            "ready", "host#0", "call 1", "call 2", "call 3", "host#1", "call 4", "host#2", "call 5"
        ])[..]
    );
    Ok(())
}

#[test]
fn unsettled_promise_with_nothing_outstanding_is_script_stalled() -> TestResult {
    let run = run_script(&init("await new Promise(() => {});\nreturn 1;"), vec![])?;
    run.expect_code(EXIT_OK)?;
    let (class, message, _) = run.error()?;
    assert_eq!(class, SCRIPT_STALLED);
    assert_eq!(message, SCRIPT_STALLED_MESSAGE);
    assert_eq!(SCRIPT_STALLED, "ScriptStalled");
    assert_eq!(
        SCRIPT_STALLED_MESSAGE,
        "the script awaited a promise that can never settle"
    );

    // Also after host calls: the last answer leaves a promise nobody can settle.
    let run = run_script(
        &init("await atlas.call('jira.search', {});\nawait new Promise(() => {});"),
        vec![answer(1, json!(null))?],
    )?;
    run.expect_code(EXIT_OK)?;
    assert_eq!(run.error()?.0, SCRIPT_STALLED);
    Ok(())
}

/// PD-136: a result whose JSON text does not fit `terminal_frame_max - 64 KiB` becomes a
/// `ResultTooLarge` error, and the frame that carries it fits the terminal cap.
#[test]
fn terminal_frame_over_cap_becomes_result_too_large_error() -> TestResult {
    let limits = ScriptLimits {
        max_result_mb: 1,
        ..ScriptLimits::default()
    };
    let over = run_script(
        // One byte over: the JSON text (with its quotes) is `max_result_mb` MiB + 1.
        &init_with("return 'x'.repeat(1024 * 1024 - 1);", json!({}), limits),
        vec![],
    )?;
    over.expect_code(EXIT_OK)?;
    let (class, message, _) = over.error()?;
    assert_eq!(class, "ResultTooLarge");
    assert_eq!(message, RESULT_TOO_LARGE);

    // A result whose JSON text is exactly the budget (`max_result_mb` MiB, quotes included) is
    // sent as one terminal frame above the 1 MiB cap of the other frames.
    let under = run_script(
        &init_with("return 'y'.repeat(1024 * 1024 - 2);", json!({}), limits),
        vec![],
    )?;
    under.expect_code(EXIT_OK)?;
    let frame_len = under
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Worker(p) => Some(p.len()),
            Event::HostFrame(_) => None,
        })
        .max()
        .ok_or("no frame")?;
    assert!(frame_len > WORKER_FRAME_MAX_BYTES);
    assert!(frame_len <= terminal_frame_max(&limits));
    match under.result()? {
        Value::String(s) => assert_eq!(s.len(), MIB - 2),
        other => return Err(format!("unexpected result {other:?}").into()),
    }
    Ok(())
}

/// `host.log` frames go out during the JS call that makes them (before the next host frame is
/// read), and a line whose frame would pass 1 MiB is cut to fit with the plan marker, also when
/// JSON escaping inflates it.
#[test]
fn log_frames_written_synchronously_and_long_lines_cut() -> TestResult {
    let source = "atlas.log('a');\n\
                  const p = atlas.call('jira.search', {});\n\
                  atlas.log('b', 1, null, {}.x);\n\
                  await p;\n\
                  atlas.log('c');\n\
                  atlas.log('z'.repeat(2 * 1024 * 1024));\n\
                  atlas.log('\\u0001'.repeat(300000));\n\
                  atlas.log('\\u00e9'.repeat(700000));\n\
                  return 'done';";
    let run = run_script(&init(source), vec![answer(1, json!(true))?])?;
    run.expect_code(EXIT_OK)?;
    let trace = run.trace()?;
    assert_eq!(
        &trace[..7],
        &strs(&[
            "ready",
            "host#0",
            "log a",
            "call 1",
            "log b 1 null undefined",
            "host#1",
            "log c"
        ])[..]
    );
    assert_eq!(LINE_TRUNCATED, "[line truncated]");
    let frames = run.frames()?;
    let payloads: Vec<&Vec<u8>> = run
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Worker(p) => Some(p),
            Event::HostFrame(_) => None,
        })
        .collect();
    for payload in &payloads {
        assert!(
            payload.len() <= WORKER_FRAME_MAX_BYTES || payload == payloads.last().ok_or("none")?
        );
    }
    let long: Vec<&String> = frames
        .iter()
        .filter_map(|f| match f {
            WorkerFrame::Log { line } if line.len() > 100 => Some(line),
            _ => None,
        })
        .collect();
    assert_eq!(long.len(), 3);
    let expected_head = ['z', '\u{1}', '\u{e9}'];
    for (line, head) in long.iter().zip(expected_head) {
        assert!(line.ends_with(LINE_TRUNCATED), "not marked");
        let body = &line[..line.len() - LINE_TRUNCATED.len()];
        assert!(body.chars().all(|c| c == head), "the kept part changed");
        // Cut close to the cap, not far below it.
        let encoded = serde_json::to_string(line)?.len();
        assert!(
            encoded > WORKER_FRAME_MAX_BYTES - 64 * 1024,
            "cut too short: {encoded}"
        );
    }
    assert_eq!(run.result()?, json!("done"));
    Ok(())
}

#[test]
fn stdin_eof_exits_ok_before_init() -> TestResult {
    let run = run_worker(vec![])?;
    run.expect_code(EXIT_OK)?;
    assert_eq!(run.trace()?, strs(&["ready"]));
    Ok(())
}

#[test]
fn unknown_first_frame_exits_protocol() -> TestResult {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "unknown method",
            framed(&encode_notification("script.other", &json!({})))?,
        ),
        ("not json", framed(b"not json")?),
        (
            "a host.call request",
            framed(br#"{"jsonrpc":"2.0","id":1,"method":"script.run","params":{}}"#)?,
        ),
        (
            "script.run with an unknown field",
            framed(&encode_notification(
                M_SCRIPT_RUN,
                &json!({"source": "return 1", "args": {}, "limits": {}, "read_op_ids": [],
                        "instances": [], "extra": 1}),
            ))?,
        ),
        (
            "script.compile without params",
            framed(br#"{"jsonrpc":"2.0","method":"script.compile"}"#)?,
        ),
        (
            "a worker frame",
            framed(&encode_notification("script.result", &json!({"value": 1})))?,
        ),
    ];
    for (name, frame) in cases {
        let run = run_worker(vec![frame])?;
        run.expect_code(EXIT_PROTOCOL)
            .map_err(|e| format!("{name}: {e}"))?;
        assert_eq!(run.trace()?, strs(&["ready", "host#0"]), "{name}");
    }
    // A first frame that does not frame (truncated) is an I/O exit, like the probe loop's.
    let mut truncated = run_frame(&init("return 1;"))?;
    truncated.truncate(truncated.len() - 2);
    run_worker(vec![truncated])?.expect_code(EXIT_IO)?;
    Ok(())
}

/// Host frames during a run: anything that is not a response to an outstanding call is a
/// protocol exit; a truncated frame is an I/O exit; stdin EOF while calls are outstanding ends the
/// worker with 0 and no terminal frame (§3.4 "The worker exits on stdin EOF").
#[test]
fn host_frames_during_a_run() -> TestResult {
    let source = "return await atlas.call('jira.search', {});";
    let bad_frames: Vec<(&str, Vec<u8>)> = vec![
        ("not utf-8", framed(&[0xff, 0xfe, 0x22])?),
        ("not json", framed(b"{")?),
        ("unknown id", answer(9, json!(1))?),
        (
            "a notification",
            framed(&encode_notification("script.run", &json!({})))?,
        ),
    ];
    for (name, frame) in bad_frames {
        let run = run_script(&init(source), vec![frame])?;
        run.expect_code(EXIT_PROTOCOL)
            .map_err(|e| format!("{name}: {e}"))?;
        assert_eq!(
            run.trace()?,
            strs(&["ready", "host#0", "call 1", "host#1"]),
            "{name}"
        );
    }

    let mut truncated = answer(1, json!(1))?;
    truncated.truncate(truncated.len() - 1);
    run_script(&init(source), vec![truncated])?.expect_code(EXIT_IO)?;

    let eof = run_script(&init(source), vec![])?;
    eof.expect_code(EXIT_OK)?;
    assert_eq!(eof.trace()?, strs(&["ready", "host#0", "call 1"]));
    Ok(())
}

const BOMB: &str =
    "function bomb() { const a = []; for (;;) a.push(new Array(65536).fill(1.5)); }\n";

fn small_heap() -> ScriptLimits {
    ScriptLimits {
        heap_mb: 8,
        ..ScriptLimits::default()
    }
}

#[test]
fn heap_limit_exits_with_exit_heap_limit() -> TestResult {
    assert_eq!(EXIT_HEAP_LIMIT, 102);
    assert_eq!(EXIT_PROCESS_LIMIT, 103);
    let source = format!("{BOMB}atlas.log('before');\nbomb();\nreturn 1;");
    let run = run_script(&init_with(&source, json!({}), small_heap()), vec![])?;
    run.expect_code(EXIT_HEAP_LIMIT)?;
    assert_eq!(run.trace()?, strs(&["ready", "host#0", "log before"]));
    Ok(())
}

/// PD-134: catching the out-of-memory error and returning does not turn the run into a result.
#[test]
fn oom_then_catch_and_return_still_exits_heap_limit() -> TestResult {
    let source = format!("{BOMB}try {{ bomb(); }} catch (e) {{ return 1; }}");
    let run = run_script(&init_with(&source, json!({}), small_heap()), vec![])?;
    run.expect_code(EXIT_HEAP_LIMIT)?;
    assert_eq!(run.trace()?, strs(&["ready", "host#0"]));

    // Also when the heap is hit after a host call was answered (in `deliver`'s continuation).
    let source = format!(
        "{BOMB}await atlas.call('jira.search', {{}});\ntry {{ bomb(); }} catch (e) {{}}\nthrow new Error('after');"
    );
    let run = run_script(
        &init_with(&source, json!({}), small_heap()),
        vec![answer(1, json!(1))?],
    )?;
    run.expect_code(EXIT_HEAP_LIMIT)?;
    assert_eq!(run.trace()?, strs(&["ready", "host#0", "call 1", "host#1"]));
    Ok(())
}

/// PD-134: after the refusal, neither `atlas.call` nor `atlas.log` writes a frame.
#[test]
fn oom_then_catch_and_atlas_call_sends_nothing() -> TestResult {
    let source = format!(
        "{BOMB}try {{ bomb(); }} catch (e) {{ await atlas.call('jira.search', {{}}); atlas.log('x'); }}\nreturn 2;"
    );
    let run = run_script(
        &init_with(&source, json!({}), small_heap()),
        vec![answer(1, json!(1))?],
    )?;
    run.expect_code(EXIT_HEAP_LIMIT)?;
    assert_eq!(run.trace()?, strs(&["ready", "host#0"]));
    Ok(())
}

#[test]
fn thrown_error_reports_class_message_stack() -> TestResult {
    let source = "function inner() { throw new RangeError('boom ' + args.n); }\ninner();";
    let run = run_script(
        &init_with(source, json!({"n": 3}), ScriptLimits::default()),
        vec![],
    )?;
    run.expect_code(EXIT_OK)?;
    let (class, message, stack) = run.error()?;
    assert_eq!(class, "RangeError");
    assert_eq!(message, "boom 3");
    assert!(stack.contains("inner"), "stack {stack:?}");

    // A thrown non-Error value.
    let run = run_script(&init("throw 'plain';"), vec![])?;
    assert_eq!(
        run.error()?,
        ("Error".to_owned(), "plain".to_owned(), String::new())
    );
    Ok(())
}

/// A message and stack that would not fit the terminal frame are cut to fit, with the marker.
#[test]
fn oversized_error_fields_are_cut_to_the_terminal_cap() -> TestResult {
    let limits = ScriptLimits {
        max_result_mb: 1,
        ..ScriptLimits::default()
    };
    let source = "const e = new Error('m'.repeat(900 * 1024));\n\
                  e.stack = '\\u0002'.repeat(400 * 1024);\n\
                  throw e;";
    let run = run_script(&init_with(source, json!({}), limits), vec![])?;
    run.expect_code(EXIT_OK)?;
    let (class, message, stack) = run.error()?;
    assert_eq!(class, "Error");
    assert_eq!(FIELD_TRUNCATED, "[truncated]");
    let terminal = run
        .events
        .iter()
        .rev()
        .find_map(|e| match e {
            Event::Worker(p) => Some(p.len()),
            Event::HostFrame(_) => None,
        })
        .ok_or("no frame")?;
    assert!(terminal <= terminal_frame_max(&limits), "{terminal}");
    // Cut to the cap, not far below it (the escaping is counted, not guessed).
    assert!(terminal > terminal_frame_max(&limits) - 1024, "{terminal}");
    assert!(stack.ends_with(FIELD_TRUNCATED), "the stack is cut first");
    let kept = stack.trim_end_matches(FIELD_TRUNCATED);
    assert!(kept.len() > 1000 && kept.chars().all(|c| c == '\u{2}'));
    assert!(
        message.chars().all(|c| c == 'm'),
        "the message is kept whole"
    );
    assert_eq!(message.len(), 900 * 1024);

    // A message alone above the cap is cut too.
    let run = run_script(
        &init_with(
            "throw new TypeError('\"'.repeat(2 * 1024 * 1024));",
            json!({}),
            limits,
        ),
        vec![],
    )?;
    let (class, message, _) = run.error()?;
    assert_eq!(class, "TypeError");
    assert!(message.ends_with(FIELD_TRUNCATED));
    assert!(
        message
            .trim_end_matches(FIELD_TRUNCATED)
            .chars()
            .all(|c| c == '"')
    );
    Ok(())
}

#[test]
fn rejection_object_is_catchable() -> TestResult {
    let source = "let caught;\n\
                  try { await atlas.jira.issue.get({key: 'A-1'}); }\n\
                  catch (e) { caught = [e.name, e.class, e.details.why, e instanceof Error]; }\n\
                  const after = await atlas.call('jira.search', {});\n\
                  return {caught, after};";
    let run = run_script(
        &init(source),
        vec![reject(1, "validation")?, answer(2, json!("ok"))?],
    )?;
    run.expect_code(EXIT_OK)?;
    assert_eq!(
        run.result()?,
        json!({"caught": ["AtlasError", "validation", "test", true], "after": "ok"})
    );
    Ok(())
}

/// JSON semantics of the result (plan rule): `undefined` is `null`; a top-level value
/// `JSON.stringify` cannot encode is a `TypeError`; nested functions are dropped.
#[test]
fn result_undefined_is_null() -> TestResult {
    let run = run_script(&init("return;"), vec![])?;
    run.expect_code(EXIT_OK)?;
    assert_eq!(run.result()?, Value::Null);
    let run = run_script(
        &init("return {a: undefined, f() {}, b: [undefined]};"),
        vec![],
    )?;
    assert_eq!(run.result()?, json!({"b": [null]}));
    // A result nested deeper than serde_json's `Value` limit still leaves as one result frame
    // (the frame keeps it as raw text, T2); whoever parses it later bounds the depth.
    let run = run_script(
        &init("let v = []; for (let i = 0; i < 300; i++) v = [v]; return v;"),
        vec![],
    )?;
    run.expect_code(EXIT_OK)?;
    match run.terminal()? {
        WorkerFrame::Result { value } => {
            assert_eq!(value.get().len(), 602);
            assert!(value.get().starts_with("[[[["));
        }
        other => return Err(format!("unexpected {other:?}").into()),
    }
    Ok(())
}

#[test]
fn result_with_function_is_type_error() -> TestResult {
    let run = run_script(&init("return () => 1;"), vec![])?;
    run.expect_code(EXIT_OK)?;
    assert_eq!(run.error()?.0, "TypeError");
    // A value `JSON.stringify` throws on (a cycle) is a TypeError too.
    let run = run_script(&init("const a = {}; a.self = a; return a;"), vec![])?;
    assert_eq!(run.error()?.0, "TypeError");
    Ok(())
}

/// A source that does not compile in run mode (the submit-time check passed, so a runtime
/// outcome) is a `SyntaxError` terminal frame; nothing of the body runs.
#[test]
fn run_mode_syntax_error_is_a_script_error() -> TestResult {
    let run = run_script(&init("atlas.log('x');\n  )"), vec![])?;
    run.expect_code(EXIT_OK)?;
    let (class, _, stack) = run.error()?;
    assert_eq!(class, "SyntaxError");
    assert!(stack.contains("2:3"), "position {stack:?}");
    assert_eq!(
        run.trace()?,
        strs(&["ready", "host#0", "error SyntaxError"])
    );
    Ok(())
}

/// PD-135: the worker's own deadline (`timeout_s + 2 s`, a backstop behind the host's timer) ends
/// a CPU loop as a runtime error, never as a limit exit.
#[test]
fn worker_deadline_is_a_runtime_script_error() -> TestResult {
    let limits = ScriptLimits {
        timeout_s: 0,
        ..ScriptLimits::default()
    };
    let run = run_script(
        &init_with(
            "try { for (;;) {} } catch (e) {}\nreturn 1;",
            json!({}),
            limits,
        ),
        vec![],
    )?;
    run.expect_code(EXIT_OK)?;
    let (class, message, _) = run.error()?;
    assert_eq!(class, SCRIPT_DEADLINE);
    assert_eq!(message, SCRIPT_DEADLINE_MESSAGE);
    Ok(())
}

/// A first `probe.run` keeps the M1 probe loop: one `probe.result` per frame until EOF, and a
/// later non-probe frame is a protocol exit. The M1 `run_with` loop is unchanged.
#[test]
fn probe_mode_unchanged() -> TestResult {
    let run = run_worker(vec![
        probe_frame(ProbeId::EnvNames)?,
        probe_frame(ProbeId::EngineSelfTest)?,
    ])?;
    run.expect_code(EXIT_OK)?;
    let written: Vec<(String, Value)> = run
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Worker(p) => decode_notification(p).ok(),
            Event::HostFrame(_) => None,
        })
        .collect();
    let methods: Vec<&str> = written.iter().map(|(m, _)| m.as_str()).collect();
    assert_eq!(methods, [M_PROBE_READY, M_PROBE_RESULT, M_PROBE_RESULT]);

    // The same frames through the M1 entry point give the same frames.
    let mut input = Vec::new();
    input.extend(probe_frame(ProbeId::EnvNames)?);
    input.extend(probe_frame(ProbeId::EngineSelfTest)?);
    let mut output = Vec::new();
    assert_eq!(
        run_with(fake_confinement(), &mut input.as_slice(), &mut output),
        EXIT_OK
    );
    let mut bytes = output.as_slice();
    let mut m1 = Vec::new();
    while let Some(frame) = read_frame(&mut bytes, MAX_FRAME_BYTES)? {
        m1.push(decode_notification(&frame)?.0);
    }
    assert_eq!(m1, methods);

    // A script frame after a probe frame is no mode switch.
    let run = run_worker(vec![
        probe_frame(ProbeId::EnvNames)?,
        run_frame(&init("return 1;"))?,
    ])?;
    run.expect_code(EXIT_PROTOCOL)?;
    // The M1 entry point never runs scripts.
    let mut output = Vec::new();
    let input = run_frame(&init("return 1;"))?;
    assert_eq!(
        run_with(fake_confinement(), &mut input.as_slice(), &mut output),
        EXIT_PROTOCOL
    );
    Ok(())
}

/// The exit codes the host classifies (T7): unchanged M1 codes plus the two limit codes.
#[test]
fn exit_codes_are_the_plan_values() {
    assert_eq!(EXIT_OK, 0);
    assert_eq!(EXIT_IO, 1);
    assert_eq!(EXIT_PROTOCOL, 3);
    assert_eq!(EXIT_PANIC, 101);
    assert_eq!(EXIT_HEAP_LIMIT, 102);
    assert_eq!(EXIT_PROCESS_LIMIT, 103);
}
