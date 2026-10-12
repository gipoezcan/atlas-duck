//! Input rules (§4.1 "Stdin and input encoding"): stdin is read only for an argument that is
//! exactly `-`, at most once per invocation; text input must be UTF-8 with an optional leading
//! BOM; file arguments are read by the CLI (the app never reads agent-specified paths). Every read
//! is bounded, so an oversized input never fills memory.
//!
//! File paths arrive as UTF-8 strings: `argv` refuses non-UTF-8 arguments on every platform, so a
//! path that is not valid UTF-8 (possible on Unix) cannot be named at all.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::sync::mpsc;
use std::time::Instant;

use atlas_duck_ipc::sandbox::MAX_FRAME_BYTES;
use serde_json::Value;

use crate::argv::{ParseError, clip};
use crate::deadline::Deadline;

/// Largest text input (stdin or file) the CLI will hold: nothing bigger fits one IPC frame.
pub(crate) const MAX_INPUT_BYTES: usize = MAX_FRAME_BYTES;

/// The invocation's stdin and whether an argument has claimed it.
///
/// A read of stdin is bounded by the `--timeout` deadline (§4.1: wall-clock from process start), so
/// it runs on a helper thread; on expiry the thread is abandoned (it dies with the process).
pub(crate) struct Inputs<'a> {
    pub dash_used: bool,
    start: Instant,
    deadline: Deadline,
    stdin: Option<Box<dyn Read + Send>>,
    _scope: PhantomData<&'a ()>,
}

impl<'a> Inputs<'a> {
    pub(crate) fn new(stdin: impl Read + Send + 'static) -> Inputs<'a> {
        let start = Instant::now();
        Inputs {
            dash_used: false,
            start,
            deadline: Deadline::new(start, None),
            stdin: Some(Box::new(stdin)),
            _scope: PhantomData,
        }
    }

    /// The process's real stdin; nothing is read until an argument is `-`.
    pub(crate) fn process() -> Inputs<'static> {
        Inputs::new(std::io::stdin())
    }

    /// The instant `--timeout` counts from (process start).
    pub(crate) fn set_start(&mut self, start: Instant) {
        self.start = start;
        self.deadline = Deadline::new(start, self.deadline.total);
    }

    /// Applies `--timeout` (seconds as parsed) to later stdin reads.
    pub(crate) fn set_timeout(&mut self, timeout_s: Option<u64>) {
        self.deadline = Deadline::from_timeout(self.start, timeout_s);
    }

    /// Reads stdin (at most `cap` bytes) within the deadline. `--timeout 0` is unbounded.
    fn read_stdin(&mut self, cap: usize) -> Result<Vec<u8>, ParseError> {
        let Some(mut reader) = self.stdin.take() else {
            return Err(ParseError::new("stdin is no longer available"));
        };
        let Some(left) = self.deadline.remaining() else {
            return read_capped(&mut reader, cap, "stdin");
        };
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("stdin-reader".into())
            .spawn(move || {
                let _ = tx.send(read_capped(&mut reader, cap, "stdin"));
            })
            .map_err(|e| ParseError::new(format!("cannot read stdin: {}", e.kind())))?;
        match rx.recv_timeout(left) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(ParseError::deadline("stdin")),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(ParseError::new("cannot read stdin: reader stopped"))
            }
        }
    }
}

/// `bytes` as text: a leading UTF-8 BOM is dropped; invalid UTF-8 is a `usage` failure whose
/// `details.byte_offset` is the first bad byte (counted after the BOM).
pub(crate) fn decode_utf8(bytes: Vec<u8>) -> Result<String, ParseError> {
    let mut bytes = bytes;
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        // In place: no second copy of a buffer that can be a whole frame.
        bytes.drain(..3);
    }
    String::from_utf8(bytes).map_err(|e| {
        let offset = e.utf8_error().valid_up_to();
        ParseError::new(format!("input is not valid UTF-8 (byte offset {offset})"))
            .with("byte_offset", offset)
    })
}

/// Reads at most `cap` bytes from `reader`; one byte more is a `usage` failure.
fn read_capped(reader: &mut dyn Read, cap: usize, what: &str) -> Result<Vec<u8>, ParseError> {
    let mut out = Vec::new();
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    reader
        .take(limit)
        .read_to_end(&mut out)
        .map_err(|e| ParseError::new(format!("cannot read {what}: {}", e.kind())))?;
    if out.len() > cap {
        return Err(
            ParseError::new(format!("{what} is larger than {cap} bytes")).with("limit_bytes", cap),
        );
    }
    Ok(out)
}

/// The bytes of an argument source: `-` is stdin (once per invocation), anything else a file path.
pub(crate) fn read_arg_bytes(
    src: &OsStr,
    inputs: &mut Inputs<'_>,
    cap: usize,
) -> Result<Vec<u8>, ParseError> {
    if src == "-" {
        if inputs.dash_used {
            return Err(ParseError::new(
                "stdin (-) can be used by at most one argument",
            ));
        }
        inputs.dash_used = true;
        return inputs.read_stdin(cap);
    }
    let shown = clip(&src.to_string_lossy());
    // Stat before opening: opening a FIFO or device can block forever, and `/dev/stdin` would
    // sidestep the single-`-` rule. Only regular files are read.
    let meta = std::fs::metadata(src).map_err(|e| {
        ParseError::new(format!("cannot open {shown}: {}", e.kind())).with("path", shown.clone())
    })?;
    if !meta.is_file() {
        return Err(
            ParseError::new(format!("{shown} is not a regular file")).with("path", shown.clone())
        );
    }
    let mut file = File::open(src).map_err(|e| {
        ParseError::new(format!("cannot open {shown}: {}", e.kind())).with("path", shown.clone())
    })?;
    read_capped(&mut file, cap, &format!("file {shown}"))
}

/// The text of an argument source (see `read_arg_bytes`), BOM stripped, UTF-8 checked.
pub(crate) fn read_arg_source(src: &OsStr, inputs: &mut Inputs<'_>) -> Result<String, ParseError> {
    decode_utf8(read_arg_bytes(src, inputs, MAX_INPUT_BYTES)?)
}

/// A JSON document from an argument source.
pub(crate) fn read_arg_json(src: &OsStr, inputs: &mut Inputs<'_>) -> Result<Value, ParseError> {
    parse_json(&read_arg_source(src, inputs)?)
}

/// Parses JSON as serde_json reads it: an integer above `u64::MAX` is rounded to a float, and a
/// duplicate object key keeps the last value (`--params`, `--args`, files, `-` all alike).
pub(crate) fn parse_json(text: &str) -> Result<Value, ParseError> {
    serde_json::from_str(text).map_err(|e| {
        ParseError::new(format!("invalid JSON: {e}"))
            .with("line", e.line())
            .with("column", e.column())
    })
}

/// Standard base64 with padding.
pub(crate) fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let sextet = |shift: u32| {
            let index = usize::try_from((n >> shift) & 63).unwrap_or(0);
            char::from(ALPHABET.get(index).copied().unwrap_or(b'A'))
        };
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io::Cursor;
    use std::time::Duration;

    use super::*;

    /// A stdin that fails the test if anything reads it.
    struct NoRead;

    impl Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("stdin was read");
        }
    }

    #[test]
    fn x08_bom_stripped() {
        assert_eq!(
            decode_utf8(b"\xEF\xBB\xBFhi".to_vec()).ok().as_deref(),
            Some("hi")
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bom.txt");
        std::fs::write(&path, b"\xEF\xBB\xBFfrom file").expect("write");
        let mut inputs = Inputs::new(NoRead);
        assert_eq!(
            read_arg_source(path.as_os_str(), &mut inputs)
                .ok()
                .as_deref(),
            Some("from file")
        );
        let mut inputs = Inputs::new(Cursor::new(b"\xEF\xBB\xBFfrom stdin".to_vec()));
        assert_eq!(
            read_arg_source(OsStr::new("-"), &mut inputs)
                .ok()
                .as_deref(),
            Some("from stdin")
        );
    }

    #[test]
    fn x08_invalid_utf8_offset() {
        let e = decode_utf8(b"ab\xffcd".to_vec()).expect_err("invalid");
        assert_eq!(e.details.get("byte_offset"), Some(&Value::from(2)));
    }

    #[test]
    fn stdin_never_read_without_dash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a.txt");
        std::fs::write(&path, "x").expect("write");
        let mut inputs = Inputs::new(NoRead);
        assert!(read_arg_source(path.as_os_str(), &mut inputs).is_ok());
        assert!(!inputs.dash_used);
        // A missing file is a usage error and still leaves stdin alone.
        assert!(read_arg_source(OsStr::new("no-such-file"), &mut inputs).is_err());
    }

    #[test]
    fn dash_is_single_use() {
        let mut inputs = Inputs::new(Cursor::new(b"one".to_vec()));
        assert_eq!(
            read_arg_source(OsStr::new("-"), &mut inputs)
                .ok()
                .as_deref(),
            Some("one")
        );
        assert!(inputs.dash_used);
        let e = read_arg_source(OsStr::new("-"), &mut inputs).expect_err("second dash");
        assert!(e.message.contains("at most one"));
    }

    #[test]
    fn reads_are_capped() {
        let mut inputs = Inputs::new(Cursor::new(vec![b'a'; 11]));
        let e = read_arg_bytes(OsStr::new("-"), &mut inputs, 10).expect_err("over cap");
        assert_eq!(e.details.get("limit_bytes"), Some(&Value::from(10)));
        let mut inputs = Inputs::new(Cursor::new(vec![b'a'; 10]));
        assert_eq!(
            read_arg_bytes(OsStr::new("-"), &mut inputs, 10)
                .map(|v| v.len())
                .ok(),
            Some(10)
        );
        // The reader is never drained past cap + 1.
        let mut source = Cursor::new(vec![b'a'; 1000]);
        assert!(read_capped(&mut source, 10, "x").is_err());
        assert_eq!(source.position(), 11);
    }

    #[test]
    fn missing_file_names_the_path_clipped() {
        let long = OsString::from("n".repeat(500));
        let mut inputs = Inputs::new(NoRead);
        let e = read_arg_source(&long, &mut inputs).expect_err("missing");
        let shown = e
            .details
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(shown.chars().count() <= 83);
    }

    #[test]
    fn only_regular_files_are_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut inputs = Inputs::new(NoRead);
        let e = read_arg_source(dir.path().as_os_str(), &mut inputs).expect_err("directory");
        assert!(e.message.contains("not a regular file"), "{}", e.message);
        assert!(e.details.contains_key("path"));
        assert!(!inputs.dash_used);
        // The echoed path is clipped like every other echo.
        let long = dir.path().join("d".repeat(200));
        std::fs::create_dir(&long).expect("mkdir");
        let e = read_arg_source(long.as_os_str(), &mut inputs).expect_err("directory");
        let shown = e.details.get("path").and_then(Value::as_str);
        assert!(shown.is_some_and(|p| p.chars().count() <= 83));
    }

    /// A stdin that blocks until its sender is dropped.
    struct Blocked(std::sync::mpsc::Receiver<()>);

    impl Read for Blocked {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }

    #[test]
    fn stdin_read_hits_the_deadline() {
        let (hold, rx) = std::sync::mpsc::channel::<()>();
        let mut inputs = Inputs::new(Blocked(rx));
        inputs.deadline = Deadline::new(Instant::now(), Some(Duration::from_millis(50)));
        let e = read_arg_bytes(OsStr::new("-"), &mut inputs, 10).expect_err("deadline");
        assert!(e.deadline_expired);
        assert!(inputs.dash_used);
        // The CLI reports it as exit 5 unreachable / launch_timeout, nothing queued.
        let env = crate::local::parse_error(e);
        let err = env.error.clone().expect("error");
        assert_eq!(err.code, atlas_duck_ipc::envelope::ErrorCode::Unreachable);
        assert_eq!(
            err.details.and_then(|d| d.get("reason").cloned()),
            Some(Value::from("launch_timeout"))
        );
        assert_eq!(atlas_duck_ipc::proto::exit_code(&env), 5);
        drop(hold);
    }

    #[test]
    fn stdin_within_the_deadline_or_unbounded_reads_normally() {
        let mut inputs = Inputs::new(Cursor::new(b"abc".to_vec()));
        inputs.set_timeout(Some(30));
        assert_eq!(
            read_arg_bytes(OsStr::new("-"), &mut inputs, 10).ok(),
            Some(b"abc".to_vec())
        );
        // `--timeout 0` is no limit: read on the calling thread.
        let mut inputs = Inputs::new(Cursor::new(b"xyz".to_vec()));
        inputs.set_timeout(Some(0));
        assert_eq!(
            read_arg_bytes(OsStr::new("-"), &mut inputs, 10).ok(),
            Some(b"xyz".to_vec())
        );
        // An over-cap read still reports the cap, not a deadline.
        let mut inputs = Inputs::new(Cursor::new(vec![b'a'; 11]));
        inputs.set_timeout(Some(30));
        let e = read_arg_bytes(OsStr::new("-"), &mut inputs, 10).expect_err("over cap");
        assert!(!e.deadline_expired);
        assert_eq!(e.details.get("limit_bytes"), Some(&Value::from(10)));
    }

    #[test]
    fn base64_vectors() {
        for (input, expected) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"hello world", "aGVsbG8gd29ybGQ="),
            (&[0xFB, 0xFF, 0xBF][..], "+/+/"),
        ] {
            assert_eq!(base64(input), expected);
        }
    }
}
