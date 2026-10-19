//! The `atlas-duck` binary's library: CLI + MCP server (§2.2).
//!
//! §2.2: depends only on `ipc` + `registry`. §2.1: never touches keychain or DB.
//! C.9: the crate exposes only `run`; everything else is `pub(crate)`.
//!
//! Local commands (argv errors, `--help`, `ops list`/`ops describe` without `--instance`) are
//! answered here and never connect to the app or build the tokio runtime (§4.1 "Local parsing").
//! Connected commands (`connected`) build a current-thread runtime of their own and reach the app
//! through a `Connector`. `mcp` is neither: `run` hands it to the `mcp` module once argv and the
//! environment are valid. `verify-export` is neither either: `run` starts the app's verifier as a
//! child process before argv parsing and prints no envelope (§12.1, C.9).

// §4.7: the launched app's test-only environment names exist only in test builds; a release build
// must never carry them.
#[cfg(all(feature = "test-env", not(debug_assertions)))]
compile_error!("test-env must never reach a release build");

mod argv;
mod binding;
mod busy;
mod connected;
mod deadline;
mod discover;
mod doctor;
mod exit;
mod flow;
mod help;
mod input;
mod interrupt;
mod launch;
mod local;
mod mcp;
mod output;
#[cfg(test)]
mod test_support;
mod verify_export;

use std::ffi::OsString;
use std::io::Write;
use std::time::Instant;

use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::envelope::{Envelope, ErrorCode};
use atlas_duck_ipc::proto::AgentNameSource;

use crate::argv::{Command, GlobalOpts, OutputMode};
use crate::connected::{Connector, OsConnector};
use crate::deadline::Deadline;
use crate::input::Inputs;
use crate::mcp::McpConfig;

/// What a run prints and returns.
pub(crate) struct Outcome {
    pub env: Envelope,
    pub opts: GlobalOpts,
    pub exit: i32,
    /// The envelope is the CLI's own `help` answer (its text may print raw).
    pub cli_help: bool,
    /// PD-117: print the envelope on stderr, stdout stays empty (a usage failure of `mcp`).
    pub stderr_only: bool,
    /// `mcp` with valid argv and environment: `run` serves it instead of printing `env`.
    pub serve: Option<McpConfig>,
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
        Err(e) => {
            let stderr_only = e.stderr_only;
            return failure(local::parse_error(e), stderr_only);
        }
    };
    let deadline = Deadline::from_timeout(start, opts.timeout);
    let mut serve = None;
    let envelope = match &command {
        Command::Mcp {
            tools,
            instance,
            agent_given,
        } => match McpConfig::from_env(&opts, *tools, instance.clone(), *agent_given, env) {
            Ok(cfg) => {
                serve = Some(cfg);
                local::mcp_serving()
            }
            Err(e) => {
                let stderr_only = e.stderr_only;
                return failure(local::parse_error(e), stderr_only);
            }
        },
        Command::Help { path } => local::help(path),
        Command::OpsList { instance: None } => local::ops_list(),
        Command::OpsDescribe {
            op_id,
            instance: None,
        } => local::ops_describe(op_id),
        Command::VerifyExport => local::verify_export_misplaced(),
        _ => execute_connected(&command, &opts, &deadline, connector),
    };
    let exit = exit::exit_for(&command, &envelope);
    let cli_help = matches!(command, Command::Help { .. })
        && envelope.status == atlas_duck_ipc::envelope::Status::Succeeded;
    Outcome {
        env: envelope,
        opts,
        exit,
        cli_help,
        stderr_only: false,
        serve,
    }
}

/// An argv failure happens before the global flags are known to be valid: print as json.
fn failure(env: Envelope, stderr_only: bool) -> Outcome {
    let exit = atlas_duck_ipc::proto::exit_code(&env);
    Outcome {
        env,
        opts: GlobalOpts {
            agent: None,
            agent_source: AgentNameSource::None,
            reason: None,
            timeout: None,
            instance: None,
            output: OutputMode::Json,
            help: false,
        },
        exit,
        cli_help: false,
        stderr_only,
        serve: None,
    }
}

/// Prints an outcome's envelope: on `err` alone for a `stderr_only` failure, else as `output`
/// says. Returns the exit code.
fn print_outcome(out: &mut dyn Write, err: &mut dyn Write, outcome: &Outcome) -> i32 {
    if outcome.stderr_only {
        // The failure is json by construction; nothing may reach `out`.
        return output::emit_to(
            err,
            &mut std::io::sink(),
            &outcome.env,
            &outcome.opts,
            outcome.exit,
            outcome.cli_help,
        );
    }
    output::emit_to(
        out,
        err,
        &outcome.env,
        &outcome.opts,
        outcome.exit,
        outcome.cli_help,
    )
}

/// Runs a connected command on a runtime built for it (local commands never get here).
fn execute_connected(
    command: &Command,
    opts: &GlobalOpts,
    deadline: &Deadline,
    connector: &dyn Connector,
) -> Envelope {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            return Envelope::failed(
                ErrorCode::Internal,
                false,
                "the async runtime did not start",
            );
        }
    };
    let envelope = runtime.block_on(connected::execute(command, opts, deadline, connector));
    // An interrupted launch may leave its blocking thread polling: do not wait for it.
    runtime.shutdown_background();
    envelope
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
    // §12.1: `verify-export` hands its arguments to the app's verifier untouched and prints no
    // envelope; its exit code (0, 20, 21, 22) is the child's.
    if verify_export::is_call(&args) {
        return verify_export::run(args.get(1..).unwrap_or_default());
    }
    // §3.3: build_id is compiled into every binary (M4's `hello` sends it). black_box keeps the
    // constant referenced, so the linker cannot drop it from the executable.
    let _ = std::hint::black_box(BUILD_ID);
    let mut outcome = execute(
        start,
        &args,
        &|k| std::env::var_os(k),
        &mut Inputs::process(),
        &OsConnector,
    );
    if let Some(cfg) = outcome.serve.take() {
        // PD-117: nothing on stdout before serving.
        return mcp::run(cfg);
    }
    print_outcome(
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
        &outcome,
    )
}

#[cfg(test)]
mod tests {
    use atlas_duck_ipc::client::ConnectError;
    use atlas_duck_ipc::envelope::Status;
    use serde_json::Value;

    use super::*;
    use crate::test_support::TestConnector;

    /// A connector whose connect fails with `server_identity` (exit 5) and counts the attempts.
    fn double() -> TestConnector {
        TestConnector::failing(|| ConnectError::ServerIdentity)
    }

    fn go(list: &[&str]) -> (Outcome, usize) {
        let connector = double();
        let args: Vec<OsString> = list.iter().map(OsString::from).collect();
        let outcome = execute(
            Instant::now(),
            &args,
            &|_| None,
            &mut Inputs::new(std::io::empty()),
            &connector,
        );
        (outcome, connector.connect_count())
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
            &["mcp", "--help"],
            // `verify-export` as the first argument never reaches `execute` (`run` spawns the app
            // from `verify_export::is_call`; that path is covered in `verify_export`'s tests), so
            // the entry here is the form that does reach it: after a global flag it is refused
            // locally.
            &["--output", "text", "verify-export", "dir"],
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
        ] {
            let (o, calls) = go(args);
            assert_eq!(calls, 1, "{args:?}");
            assert_eq!(code(&o), Some(ErrorCode::ServerIdentity));
            assert_eq!(o.exit, 5);
        }
    }

    #[test]
    fn doctor_exits_0_with_the_local_checks_when_the_app_is_unreachable() {
        let (o, calls) = go(&["doctor"]);
        assert_eq!(calls, 1);
        assert_eq!(o.exit, 0);
        assert_eq!(o.env.status, Status::Succeeded);
        let data = o.env.data.unwrap_or(Value::Null);
        assert!(data["local"].is_object());
        assert_eq!(data["app"], Value::Null);
        assert_eq!(data["app_unavailable"]["code"], "server_identity");
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
    fn verify_export_after_a_global_flag_is_a_usage_failure() {
        // `run` starts `verify-export` only as the first argument; argv parsing never runs it.
        let (o, calls) = go(&["--output", "text", "verify-export", "dir"]);
        assert_eq!(calls, 0);
        assert_eq!(o.exit, 2);
        assert_eq!(code(&o), Some(ErrorCode::Usage));
        let message = o.env.error.map(|e| e.message).unwrap_or_default();
        assert!(message.contains("must be the first argument"), "{message}");
    }

    #[test]
    fn verify_export_help_is_local_and_documents_its_flags() {
        for args in [&["verify-export", "--help"][..], &["help", "verify-export"]] {
            let (o, calls) = go(args);
            assert_eq!(calls, 0, "{args:?}");
            assert_eq!(o.exit, 0, "{args:?}");
            let help = o
                .env
                .data
                .as_ref()
                .and_then(|d| d["help"].as_str())
                .unwrap_or_default();
            for needle in [
                "atlas-duck verify-export <dir>",
                "--anchor-dir",
                "--manifest-sha256",
                "20",
                "21",
                "22",
            ] {
                assert!(help.contains(needle), "{args:?} {needle}: {help}");
            }
        }
    }

    /// `execute` + `print_outcome` over captured writers: (outcome, stdout, stderr, exit).
    fn printed(list: &[&str], timeout_env: Option<&str>) -> (Outcome, String, String, i32) {
        let connector = double();
        let args: Vec<OsString> = list.iter().map(OsString::from).collect();
        let env = |k: &str| {
            (k == "ATLAS_DUCK_MCP_TIMEOUT")
                .then(|| timeout_env.map(OsString::from))
                .flatten()
        };
        let o = execute(
            Instant::now(),
            &args,
            &env,
            &mut Inputs::new(std::io::empty()),
            &connector,
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let exit = print_outcome(&mut out, &mut err, &o);
        let text = |b: Vec<u8>| String::from_utf8(b).unwrap_or_default();
        (o, text(out), text(err), exit)
    }

    #[test]
    fn mcp_usage_error_goes_to_stderr_only() {
        for (list, timeout_env) in [
            (&["mcp", "--tools", "x"][..], None),
            (&["mcp", "--timeout", "5"][..], None),
            (&["mcp", "extra"][..], None),
            (&["mcp"][..], Some("x")),
            (&["mcp"][..], Some("")),
            (&["mcp", "--output", "text"][..], None),
        ] {
            let (o, stdout, stderr, exit) = printed(list, timeout_env);
            assert_eq!(exit, 2, "{list:?} {timeout_env:?}");
            assert_eq!(code(&o), Some(ErrorCode::Usage), "{list:?}");
            assert!(o.serve.is_none(), "{list:?}");
            assert_eq!(stdout, "", "{list:?} {timeout_env:?}");
            assert_eq!(stderr.lines().count(), 1, "{list:?}: {stderr:?}");
            assert!(stderr.ends_with('\n'), "{list:?}: {stderr:?}");
            let line: Value = serde_json::from_str(&stderr).unwrap_or(Value::Null);
            assert_eq!(line["status"], "failed", "{stderr}");
            assert_eq!(line["error"]["code"], "usage", "{stderr}");
        }
        // The variable is named in its own error.
        let (_, _, stderr, _) = printed(&["mcp"], Some("1.5"));
        assert!(stderr.contains("ATLAS_DUCK_MCP_TIMEOUT"), "{stderr}");
        // Before `mcp` was classified it is an ordinary usage error, on stdout.
        let (o, stdout, stderr, exit) = printed(&["--bogus", "mcp"], None);
        assert_eq!(exit, 2);
        assert_eq!(code(&o), Some(ErrorCode::Usage));
        assert_eq!(stderr, "");
        assert_eq!(stdout.lines().count(), 1, "{stdout:?}");
        assert!(stdout.contains("unknown flag: --bogus"), "{stdout}");
    }

    #[test]
    fn valid_mcp_hands_over_to_the_server_and_prints_nothing_itself() {
        let (o, stdout, stderr, exit) = printed(&["mcp", "--tools", "generic"], Some("7"));
        assert_eq!(
            o.serve,
            Some(McpConfig {
                tools: crate::mcp::ToolSet::Generic,
                instance: None,
                agent: None,
                agent_source: AgentNameSource::None,
                agent_given: false,
                timeout: Some(std::time::Duration::from_secs(7)),
            })
        );
        // `run` takes `serve` before it prints, so this harness (which prints the outcome anyway)
        // shows only what the placeholder would say if a caller bypassed `serve`: a success.
        assert_eq!(stderr, "");
        assert!(!o.stderr_only);
        assert_eq!(exit, 0, "{stdout}");
        assert_eq!(o.exit, 0);
        assert_eq!(o.env.status, atlas_duck_ipc::envelope::Status::Succeeded);
        assert!(o.env.error.is_none(), "{:?}", o.env.error);
    }

    #[test]
    fn mcp_help_prints_help_on_stdout() {
        let (o, stdout, stderr, exit) = printed(&["mcp", "--help"], None);
        assert_eq!(exit, 0);
        assert!(o.serve.is_none());
        assert_eq!(stderr, "");
        let line: Value = serde_json::from_str(&stdout).unwrap_or(Value::Null);
        let help = line["data"]["help"].as_str().unwrap_or_default();
        assert!(help.contains("atlas-duck mcp"), "{help}");
        for banned in ["--timeout", "--reason", "--output"] {
            assert!(
                !help.lines().any(|l| l.trim_start().starts_with(banned)),
                "{banned}: {help}"
            );
        }
        assert!(help.contains("ATLAS_DUCK_MCP_TIMEOUT"), "{help}");
        assert!(help.contains("restart the MCP server"), "{help}");
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
