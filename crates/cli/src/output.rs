//! Printing the envelope (§4.1 `--output`, §4.2, PD-15, PD-16).
//!
//! json: exactly one envelope line on stdout. text: a human rendering of `data` on stdout and the
//! envelope with `data: null` as one JSON line on stderr. A failed stdout write ends the process
//! with exit 4 and never cancels anything (PD-16).

use std::io::{self, Write};

use atlas_duck_ipc::envelope::{Envelope, exit};
use serde::Serialize;
use serde_json::Value;

use crate::argv::{GlobalOpts, OutputMode};

/// Prints `env` and returns `exit_code`, unless `out` cannot be written: then `exit::PENDING` (4).
pub(crate) fn emit_to(
    out: &mut dyn Write,
    err: &mut dyn Write,
    env: &Envelope,
    opts: &GlobalOpts,
    exit_code: i32,
    cli_help: bool,
) -> i32 {
    let written = match opts.output {
        OutputMode::Json => out
            .write_all(env.to_json_line().as_bytes())
            .and_then(|()| out.flush()),
        OutputMode::Text => {
            let body = render_text(env, cli_help);
            let stdout_result = if body.is_empty() {
                Ok(())
            } else {
                out.write_all(body.as_bytes()).and_then(|()| out.flush())
            };
            let mut meta = env.clone();
            meta.data = None;
            // stderr is best effort: only a stdout failure changes the exit code.
            let _ = err
                .write_all(meta.to_json_line().as_bytes())
                .and_then(|()| err.flush());
            stdout_result
        }
    };
    match written {
        Ok(()) => exit_code,
        Err(_) => exit::PENDING,
    }
}

/// PD-15: `data.help` raw, only for the CLI's own help envelope (`cli_help`); else `data.result`
/// pretty; else `data` pretty; nothing for null data. Pretty output has terminal-active characters
/// escaped: it can carry text from the app and the services behind it.
fn render_text(env: &Envelope, cli_help: bool) -> String {
    let Some(data) = &env.data else {
        return String::new();
    };
    if data.is_null() {
        return String::new();
    }
    let help = if cli_help {
        data.get("help").and_then(Value::as_str)
    } else {
        None
    };
    let mut text = match help {
        Some(help) => help.to_owned(),
        None => {
            let shown = data.get("result").unwrap_or(data);
            escape_terminal(
                &serde_json::to_string_pretty(shown).unwrap_or_else(|_| shown.to_string()),
            )
        }
    };
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// JSON escapes only U+0000 to U+001F: C1 controls (U+009B is CSI) and bidi controls would reach
/// the terminal raw. They become `\u{..}` text; the layout newlines stay.
fn escape_terminal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let bidi = matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        );
        if (c.is_control() && c != '\n') || bidi {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// §4.1 submission notice (PD-19): one flushed stderr line, written right after the server
/// accepted the request and before any wait.
pub(crate) fn write_notice(request_id: &str, params_sha256: Option<&str>) -> io::Result<()> {
    write_notice_to(&mut io::stderr().lock(), request_id, params_sha256)
}

#[derive(Serialize)]
struct Notice<'a> {
    event: &'static str,
    request_id: &'a str,
    params_sha256: Option<&'a str>,
    status: &'static str,
}

pub(crate) fn write_notice_to(
    w: &mut dyn Write,
    request_id: &str,
    params_sha256: Option<&str>,
) -> io::Result<()> {
    let notice = Notice {
        event: "submitted",
        request_id,
        params_sha256,
        status: "pending",
    };
    let line = serde_json::to_string(&notice).map_err(io::Error::other)?;
    w.write_all(format!("{line}\n").as_bytes())?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use atlas_duck_ipc::envelope::{ErrorCode, Status};
    use atlas_duck_ipc::proto::AgentNameSource;
    use serde_json::json;

    use super::*;

    fn opts(output: OutputMode) -> GlobalOpts {
        GlobalOpts {
            agent: None,
            agent_source: AgentNameSource::None,
            reason: None,
            timeout: None,
            instance: None,
            output,
            help: false,
        }
    }

    fn with_data(data: Value) -> Envelope {
        let mut env = Envelope::failed(ErrorCode::Internal, false, "x");
        env.status = Status::Succeeded;
        env.error = None;
        env.data = Some(data);
        env
    }

    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    fn run(env: &Envelope, mode: OutputMode, code: i32) -> (i32, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let exit = emit_to(&mut out, &mut err, env, &opts(mode), code, true);
        (
            exit,
            String::from_utf8(out).unwrap_or_default(),
            String::from_utf8(err).unwrap_or_default(),
        )
    }

    #[test]
    fn json_is_one_envelope_line_on_stdout() {
        let env = with_data(json!({"a": 1}));
        let (code, out, err) = run(&env, OutputMode::Json, 0);
        assert_eq!(code, 0);
        assert_eq!(out, env.to_json_line());
        assert_eq!(out.matches('\n').count(), 1);
        assert!(err.is_empty());
    }

    #[test]
    fn output_text_split() {
        let env = with_data(json!({"result": {"key": "ABC-1", "n": [1, 2]}, "other": true}));
        let (code, out, err) = run(&env, OutputMode::Text, 0);
        assert_eq!(code, 0);
        assert_eq!(
            out,
            "{\n  \"key\": \"ABC-1\",\n  \"n\": [\n    1,\n    2\n  ]\n}\n"
        );
        assert_eq!(err.matches('\n').count(), 1);
        let parsed: Value = serde_json::from_str(&err).unwrap_or(Value::Null);
        assert_eq!(parsed["data"], Value::Null);
        assert_eq!(parsed["status"], "succeeded");
    }

    #[test]
    fn text_prefers_help_then_result_then_data_and_skips_null() {
        let (_, out, _) = run(
            &with_data(json!({"help": "usage text"})),
            OutputMode::Text,
            0,
        );
        assert_eq!(out, "usage text\n");
        let (_, out, _) = run(&with_data(json!({"ops": []})), OutputMode::Text, 0);
        assert_eq!(out, "{\n  \"ops\": []\n}\n");
        let mut none = with_data(Value::Null);
        none.data = None;
        let (_, out, err) = run(&none, OutputMode::Text, 0);
        assert!(out.is_empty());
        assert!(!err.is_empty());
    }

    #[test]
    fn a_server_supplied_help_string_is_not_printed_raw() {
        let env = with_data(json!({"help": "\u{1b}[2Jowned"}));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        emit_to(&mut out, &mut err, &env, &opts(OutputMode::Text), 0, false);
        let out = String::from_utf8(out).unwrap_or_default();
        assert!(out.contains("\"help\""), "{out}");
        assert!(!out.contains('\u{1b}'));
    }

    #[test]
    fn text_escapes_c1_and_bidi_controls_but_not_json_output() {
        let nasty = "a\u{9b}31m b\u{202e}c\u{2066}d\u{200f}e\u{61c}f\u{7f}g";
        let env = with_data(json!({"result": {"k": nasty}}));
        let (_, out, _) = run(&env, OutputMode::Text, 0);
        assert!(out.contains("\\u{9b}"), "{out}");
        assert!(out.contains("\\u{202e}"));
        assert!(out.contains("\\u{2066}"));
        assert!(out.contains("\\u{200f}"));
        assert!(out.contains("\\u{61c}"));
        assert!(out.contains("\\u{7f}"));
        assert!(!out.chars().any(|c| c.is_control() && c != '\n'));
        assert!(!out.contains('\u{202e}'));
        // Layout newlines and ordinary text stay.
        assert!(out.starts_with("{\n  \"k\": \"a"));
        // JSON mode is machine output and unchanged.
        let (_, json_out, _) = run(&env, OutputMode::Json, 0);
        assert_eq!(json_out, env.to_json_line());
    }

    #[test]
    fn stdout_write_failure_exit_4() {
        let env = with_data(json!({}));
        for mode in [OutputMode::Json, OutputMode::Text] {
            let mut err = Vec::new();
            let code = emit_to(&mut Broken, &mut err, &env, &opts(mode), 0, false);
            assert_eq!(code, 4, "{mode:?}");
        }
        // A broken stderr does not change the exit code.
        let mut out = Vec::new();
        assert_eq!(
            emit_to(
                &mut out,
                &mut Broken,
                &with_data(json!({"result": 1})),
                &opts(OutputMode::Text),
                0,
                false
            ),
            0
        );
    }

    #[test]
    fn notice_is_one_line_with_the_documented_keys() {
        let mut buf = Vec::new();
        assert!(write_notice_to(&mut buf, "req_1", Some("abc")).is_ok());
        let line = String::from_utf8(buf).unwrap_or_default();
        assert_eq!(
            line,
            "{\"event\":\"submitted\",\"request_id\":\"req_1\",\"params_sha256\":\"abc\",\"status\":\"pending\"}\n"
        );
        let parsed: Value = serde_json::from_str(line.trim_end()).unwrap_or(Value::Null);
        assert_eq!(parsed["event"], "submitted");
        assert_eq!(parsed["request_id"], "req_1");
        assert_eq!(parsed["params_sha256"], "abc");
        assert_eq!(parsed["status"], "pending");
        assert_eq!(line.matches('\n').count(), 1);
    }
}
