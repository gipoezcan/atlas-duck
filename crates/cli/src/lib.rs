//! The `atlas-duck` binary's library: CLI + MCP server (§2.2).
//!
//! §2.2: depends only on `ipc` + `registry`. §2.1: never touches keychain or DB.
//! C.9: the crate exposes only `run`; everything else is `pub(crate)`.
//!
//! Local commands (argv errors, `--help`, `ops list`/`ops describe` without `--instance`,
//! `mcp`/`verify-export` in this build) are answered here and never connect to the app or build
//! the tokio runtime (§4.1 "Local parsing"). Connected commands go through a `Connector` (Task 16
//! provides the real one).

// §4.7: the launched app's test-only environment names exist only in test builds; a release build
// must never carry them.
#[cfg(all(feature = "test-env", not(debug_assertions)))]
compile_error!("test-env must never reach a release build");

mod argv;
mod binding;
mod busy;
mod deadline;
mod discover;
mod exit;
mod help;
mod input;
mod launch;
mod local;
mod output;

use std::ffi::OsString;
use std::time::Instant;

use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::envelope::{Envelope, ErrorCode};

use crate::argv::{Command, GlobalOpts, OutputMode};
use crate::deadline::Deadline;
use crate::input::Inputs;

/// How a connected command reaches the app. Task 16 replaces this placeholder with the real
/// connect/launch/hello sequence (and the async calls that follow); local commands never see it.
pub(crate) trait Connector {
    /// Connects within `deadline`; the envelope is the failure to print.
    fn connect(&self, deadline: &Deadline) -> Result<(), Box<Envelope>>;
}

/// Until Task 16: every connected command fails with `internal`.
struct Unwired;

impl Connector for Unwired {
    fn connect(&self, _deadline: &Deadline) -> Result<(), Box<Envelope>> {
        Err(Box::new(Envelope::failed(
            ErrorCode::Internal,
            false,
            "connected commands are not available in this build yet",
        )))
    }
}

/// What a run prints and returns.
pub(crate) struct Outcome {
    pub env: Envelope,
    pub opts: GlobalOpts,
    pub exit: i32,
}

/// Parses `args` and runs the command; prints nothing.
pub(crate) fn execute(
    start: Instant,
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    inputs: &mut Inputs<'_>,
    connector: &dyn Connector,
) -> Outcome {
    // Reading stdin during parsing counts against `--timeout` (argv sets the limit).
    inputs.set_start(start);
    let (opts, command) = match argv::parse(args, env, inputs) {
        Ok(parsed) => parsed,
        Err(e) => return failure(local::parse_error(e)),
    };
    let deadline = Deadline::from_timeout(start, opts.timeout);
    let envelope = match &command {
        Command::Help { path } => local::help(path),
        Command::OpsList { instance: None } => local::ops_list(),
        Command::OpsDescribe {
            op_id,
            instance: None,
        } => local::ops_describe(op_id),
        Command::NotInThisBuild(name) => local::not_in_this_build(name),
        _ => execute_connected(&deadline, connector),
    };
    let exit = exit::exit_for(&command, &envelope);
    Outcome {
        env: envelope,
        opts,
        exit,
    }
}

/// An argv failure happens before the global flags are known to be valid: print as json.
fn failure(env: Envelope) -> Outcome {
    let exit = atlas_duck_ipc::proto::exit_code(&env);
    Outcome {
        env,
        opts: GlobalOpts {
            agent: None,
            reason: None,
            timeout: None,
            instance: None,
            output: OutputMode::Json,
            help: false,
        },
        exit,
    }
}

fn execute_connected(deadline: &Deadline, connector: &dyn Connector) -> Envelope {
    match connector.connect(deadline) {
        Err(env) => *env,
        // Task 16 submits / awaits / lists here.
        Ok(()) => Envelope::failed(
            ErrorCode::Internal,
            false,
            "connected commands are not available in this build yet",
        ),
    }
}

/// Runs the CLI. `args` excludes the program name (and, under the app's `__cli` dispatch, the
/// marker). Prints the §4.2 envelope (see `output`) and returns the process exit code (§4.3).
pub fn run(args: Vec<OsString>) -> i32 {
    // §4.1: the deadline is wall-clock from process start; this is the closest we can get.
    let start = Instant::now();
    // PD-21: the internal breakaway stub, before argv parsing; it prints nothing.
    if let Some((first, rest)) = args.split_first()
        && first == launch::stub::STUB_COMMAND
    {
        return launch::stub::run_stub(rest);
    }
    // §3.3: build_id is compiled into every binary (M4's `hello` sends it). black_box keeps the
    // constant referenced, so the linker cannot drop it from the executable.
    let _ = std::hint::black_box(BUILD_ID);
    let outcome = execute(
        start,
        &args,
        &|k| std::env::var_os(k),
        &mut Inputs::process(),
        &Unwired,
    );
    output::emit_with_exit(&outcome.env, &outcome.opts, outcome.exit)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use atlas_duck_ipc::envelope::Status;
    use serde_json::Value;

    use super::*;

    struct Recording(Cell<u32>);

    impl Connector for Recording {
        fn connect(&self, _deadline: &Deadline) -> Result<(), Box<Envelope>> {
            self.0.set(self.0.get() + 1);
            Err(Box::new(Envelope::failed(
                ErrorCode::Unreachable,
                false,
                "double",
            )))
        }
    }

    fn go(list: &[&str]) -> (Outcome, u32) {
        let connector = Recording(Cell::new(0));
        let args: Vec<OsString> = list.iter().map(OsString::from).collect();
        let outcome = execute(
            Instant::now(),
            &args,
            &|_| None,
            &mut Inputs::new(std::io::empty()),
            &connector,
        );
        (outcome, connector.0.get())
    }

    fn code(o: &Outcome) -> Option<ErrorCode> {
        o.env.error.as_ref().map(|e| e.code)
    }

    #[test]
    fn no_args_is_usage_exit_2() {
        let (o, calls) = go(&[]);
        assert_eq!(calls, 0);
        assert_eq!(o.exit, 2);
        assert_eq!(o.env.status, Status::Failed);
        assert_eq!(code(&o), Some(ErrorCode::Usage));
        assert_eq!(o.env.request_id, None);
        assert_eq!(
            o.env.error.map(|e| e.message).as_deref(),
            Some("no command given")
        );
    }

    #[test]
    fn help_succeeds_exit_0() {
        let cases: [(&[&str], &str); 4] = [
            (&["--help"], "ops list"),
            (&["help"], "ops list"),
            (&["jira", "--help"], "atlas-duck jira issue get"),
            (
                &["jira", "issue", "get", "--help"],
                "atlas-duck jira issue get <",
            ),
        ];
        for (args, needle) in cases {
            let (o, calls) = go(args);
            assert_eq!(calls, 0, "{args:?}");
            assert_eq!(o.exit, 0, "{args:?}");
            assert_eq!(o.env.status, Status::Succeeded, "{args:?}");
            assert_eq!(o.env.request_id, None);
            let help = o
                .env
                .data
                .as_ref()
                .and_then(|d| d["help"].as_str())
                .unwrap_or_default();
            assert!(!help.is_empty(), "{args:?}");
            assert!(help.contains(needle), "{args:?}: {help}");
        }
        // The full op path carries the op's describe usage line verbatim.
        let (o, _) = go(&["jira", "issue", "get", "--help"]);
        let usage = local::ops_describe("jira.issue.get")
            .data
            .and_then(|d| d["cli"]["usage"].as_str().map(str::to_owned))
            .unwrap_or_default();
        let help = o
            .env
            .data
            .as_ref()
            .and_then(|d| d["help"].as_str())
            .unwrap_or_default();
        assert!(help.contains(&usage));
    }

    #[test]
    fn mistyped_flag_usage() {
        let (o, calls) = go(&["ops", "list", "--bogus"]);
        assert_eq!(calls, 0);
        assert_eq!(o.exit, 2);
        assert_eq!(code(&o), Some(ErrorCode::Usage));
        let details = o.env.error.and_then(|e| e.details).unwrap_or_default();
        assert_eq!(details.get("arg"), Some(&Value::from("--bogus")));
    }

    #[test]
    fn local_commands_never_connect() {
        for args in [
            &["ops", "list"][..],
            &["ops", "describe", "jira.issue.get"],
            &["ops", "describe", "jira.nope"],
            &["--help"],
            &["jira", "issue", "get", "--help"],
            &["mcp"],
            &["verify-export", "dir"],
            &["bogus"],
            &["--timeout", "x", "instances"],
        ] {
            let (_, calls) = go(args);
            assert_eq!(calls, 0, "{args:?}");
        }
        // With --instance the availability comes from the app, so those do connect.
        for args in [
            &["ops", "list", "--instance", "x"][..],
            &["ops", "describe", "jira.issue.get", "--instance", "x"],
            &["instances"],
            &["status", "req_1"],
            &["doctor"],
        ] {
            let (o, calls) = go(args);
            assert_eq!(calls, 1, "{args:?}");
            assert_eq!(code(&o), Some(ErrorCode::Unreachable));
            assert_eq!(o.exit, 5);
        }
    }

    #[test]
    fn ops_list_and_describe_run_locally() {
        let (o, _) = go(&["ops", "list"]);
        assert_eq!(o.exit, 0);
        assert_eq!(o.env, local::ops_list());
        let (o, _) = go(&["ops", "describe", "jira.nope"]);
        assert_eq!(o.exit, 2);
        assert_eq!(code(&o), Some(ErrorCode::Usage));
    }

    #[test]
    fn mcp_and_verify_export_not_in_this_build() {
        for args in [&["mcp"][..], &["verify-export", "dir"]] {
            let (o, calls) = go(args);
            assert_eq!(calls, 0);
            assert_eq!(o.exit, 2);
            assert_eq!(code(&o), Some(ErrorCode::Usage));
            assert_eq!(
                o.env.error.map(|e| e.message).as_deref(),
                Some("not available in this build")
            );
        }
    }

    #[test]
    fn launch_stub_is_not_an_argv_command() {
        // `run` dispatches it before `execute`; through argv it is an unknown command.
        let (o, calls) = go(&["__launch-stub"]);
        assert_eq!(calls, 0);
        assert_eq!(o.exit, 2);
        assert_eq!(code(&o), Some(ErrorCode::Usage));
    }

    #[test]
    fn global_flags_anywhere_give_the_same_outcome() {
        let (a, _) = go(&["--output", "text", "ops", "list"]);
        let (b, _) = go(&["ops", "list", "--output", "text"]);
        assert_eq!(a.env, b.env);
        assert_eq!(a.opts, b.opts);
        assert_eq!(a.opts.output, OutputMode::Text);
    }
}
