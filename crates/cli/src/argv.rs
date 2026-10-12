//! Argv grammar (PD-13): global flags anywhere before `--`, the generic and local commands, and
//! the command path of a registry op. Tokenized by `lexopt`; nothing here reads a file or stdin
//! (Task 12 binds op flags and reads inputs), and nothing validates params (§4.1: the app does).

use std::ffi::OsString;

use atlas_duck_registry::{OperationSpec, all};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputMode {
    Json,
    Text,
}

/// The §4.1 global flags. `agent` already includes the `ATLAS_DUCK_AGENT` fallback.
// Task 16 (connected commands) reads `agent` and `reason`.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobalOpts {
    pub agent: Option<String>,
    pub reason: Option<String>,
    /// Seconds; `None` = default, `Some(0)` = submit and return pending.
    pub timeout: Option<u64>,
    pub instance: Option<String>,
    pub output: OutputMode,
    pub help: bool,
}

/// Where a JSON input comes from; read by Task 12's `input` module.
// Task 12 (inputs) reads the sources.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParamsSource {
    Inline(String),
    /// A path, or `-` for stdin.
    File(String),
}

// Task 16 (connected commands) sends it.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DryRun {
    Full,
    Sparse,
}

// Task 12 constructs `Op`; Task 16 reads the connected commands' fields.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Command {
    Help {
        path: Vec<String>,
    },
    OpsList {
        instance: Option<String>,
    },
    OpsDescribe {
        op_id: String,
        instance: Option<String>,
    },
    Op {
        op_id: String,
        params: Value,
    },
    Call {
        op_id: String,
        params: ParamsSource,
    },
    ScriptRun {
        /// A path, or `-` for stdin.
        source: String,
        args: Option<String>,
        limits: Option<String>,
        dry_run: Option<DryRun>,
    },
    Instances,
    Await {
        id: String,
    },
    Status {
        id: String,
    },
    Cancel {
        id: String,
    },
    RequestsList {
        agent: Option<String>,
        state: Option<String>,
        match_params: Option<ParamsSource>,
    },
    Doctor,
    /// `mcp`, `verify-export` (M9, M10): a `usage` failure in this build.
    NotInThisBuild(&'static str),
}

/// A `usage` failure: becomes `failed` / `usage` / exit 2 with `details` when non-empty.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ParseError {
    pub message: String,
    pub details: Map<String, Value>,
}

impl ParseError {
    fn new(message: impl Into<String>) -> ParseError {
        ParseError {
            message: message.into(),
            details: Map::new(),
        }
    }

    fn with(mut self, key: &str, value: impl Into<Value>) -> ParseError {
        self.details.insert(key.to_owned(), value.into());
        self
    }

    fn arg(message: impl Into<String>, arg: &str) -> ParseError {
        ParseError::new(message).with("arg", arg)
    }
}

/// What the positionals seen so far name.
#[derive(Clone, Copy)]
enum Kind {
    Empty,
    Help,
    OpsList,
    OpsDescribe,
    Call,
    ScriptRun,
    Instances,
    Await,
    Status,
    Cancel,
    RequestsList,
    Doctor,
    NotInBuild(&'static str),
    Op(&'static OperationSpec),
    /// A proper prefix of a command path (`jira issue`, `ops`).
    Incomplete,
    Unknown,
}

/// The kind of `pos` and how many leading positionals form the command path.
fn classify(pos: &[String]) -> (Kind, usize) {
    let word = |i: usize| pos.get(i).map(String::as_str);
    match word(0) {
        None => return (Kind::Empty, 0),
        Some("help") => return (Kind::Help, 1),
        Some("call") => return (Kind::Call, 1),
        Some("instances") => return (Kind::Instances, 1),
        Some("await") => return (Kind::Await, 1),
        Some("status") => return (Kind::Status, 1),
        Some("cancel") => return (Kind::Cancel, 1),
        Some("doctor") => return (Kind::Doctor, 1),
        Some("mcp") => return (Kind::NotInBuild("mcp"), 1),
        Some("verify-export") => return (Kind::NotInBuild("verify-export"), 1),
        Some("ops") => {
            return match word(1) {
                None => (Kind::Incomplete, 1),
                Some("list") => (Kind::OpsList, 2),
                Some("describe") => (Kind::OpsDescribe, 2),
                Some(_) => (Kind::Unknown, 0),
            };
        }
        Some("script") => {
            return match word(1) {
                None => (Kind::Incomplete, 1),
                Some("run") => (Kind::ScriptRun, 2),
                Some(_) => (Kind::Unknown, 0),
            };
        }
        Some("requests") => {
            return match word(1) {
                None => (Kind::Incomplete, 1),
                Some("list") => (Kind::RequestsList, 2),
                Some(_) => (Kind::Unknown, 0),
            };
        }
        Some(_) => {}
    }
    let matches_path =
        |path: &[&str]| path.len() <= pos.len() && path.iter().zip(pos).all(|(a, b)| a == b);
    let best = all()
        .iter()
        .filter(|spec| matches_path(spec.cli.noun_path))
        .max_by_key(|spec| spec.cli.noun_path.len());
    if let Some(spec) = best {
        return (Kind::Op(spec), spec.cli.noun_path.len());
    }
    let is_prefix = all().iter().any(|spec| {
        let path = spec.cli.noun_path;
        pos.len() < path.len() && path.iter().zip(pos).all(|(a, b)| a == b)
    });
    if is_prefix {
        (Kind::Incomplete, pos.len())
    } else {
        (Kind::Unknown, 0)
    }
}

/// How a non-global flag is read under the command the positionals name so far.
enum Arity {
    Value,
    OptionalValue,
    /// Accepted and ignored here: op flags are bound by Task 12; `mcp`/`verify-export` fail
    /// anyway.
    Skip,
}

fn flag_arity(kind: Kind, flag: &str) -> Option<Arity> {
    match (kind, flag) {
        (Kind::Call, "--params" | "--params-file") => Some(Arity::Value),
        (Kind::ScriptRun, "--args" | "--limits") => Some(Arity::Value),
        (Kind::ScriptRun, "--dry-run") => Some(Arity::OptionalValue),
        (Kind::RequestsList, "--state" | "--match-params-file") => Some(Arity::Value),
        (Kind::Op(_) | Kind::NotInBuild(_), _) => Some(Arity::Skip),
        _ => None,
    }
}

fn lex_error(e: lexopt::Error) -> ParseError {
    match e {
        lexopt::Error::MissingValue {
            option: Some(option),
        } => ParseError::arg(format!("missing value for {option}"), &option),
        lexopt::Error::UnexpectedValue { option, .. } => {
            ParseError::arg(format!("{option} takes no value"), &option)
        }
        other => ParseError::new(other.to_string()),
    }
}

fn text(value: OsString) -> Result<String, ParseError> {
    value
        .into_string()
        .map_err(|_| ParseError::new("argument is not valid UTF-8"))
}

/// Invalid UTF-8 in any argument is a `usage` failure naming its index, never a panic.
fn check_utf8(args: &[OsString]) -> Result<(), ParseError> {
    match args.iter().position(|a| a.to_str().is_none()) {
        Some(i) => Err(
            ParseError::new(format!("argument {} is not valid UTF-8", i + 1))
                .with("arg_index", i + 1),
        ),
        None => Ok(()),
    }
}

#[derive(Default)]
struct Flags {
    params: Option<String>,
    params_file: Option<String>,
    args: Option<String>,
    limits: Option<String>,
    dry_run: Option<DryRun>,
    state: Option<String>,
    match_params_file: Option<String>,
}

/// Stores a once-only flag value.
fn set_once<T>(slot: &mut Option<T>, flag: &str, value: T) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError::arg(
            format!("{flag} given more than once"),
            flag,
        ));
    }
    *slot = Some(value);
    Ok(())
}

pub(crate) fn parse(
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<(GlobalOpts, Command), ParseError> {
    check_utf8(args)?;
    let mut opts = GlobalOpts {
        agent: None,
        reason: None,
        timeout: None,
        instance: None,
        output: OutputMode::Json,
        help: false,
    };
    let mut flags = Flags::default();
    // `requests list --agent` filters by the explicit flag only, not the environment fallback.
    let mut agent_flag: Option<String> = None;
    let mut pos: Vec<String> = Vec::new();
    let mut parser = lexopt::Parser::from_args(args.iter().cloned());
    while let Some(arg) = parser.next().map_err(lex_error)? {
        match arg {
            lexopt::Arg::Value(v) => pos.push(text(v)?),
            lexopt::Arg::Short(c) => {
                return Err(ParseError::arg(
                    format!("unknown flag: -{c}"),
                    &format!("-{c}"),
                ));
            }
            lexopt::Arg::Long(name) => {
                let flag = format!("--{name}");
                match name {
                    "help" => {
                        no_value(&mut parser, &flag)?;
                        opts.help = true;
                    }
                    "agent" => {
                        let v = value(&mut parser)?;
                        agent_flag = Some(v.clone());
                        opts.agent = Some(v);
                    }
                    "reason" => opts.reason = Some(value(&mut parser)?),
                    "instance" => opts.instance = Some(value(&mut parser)?),
                    "timeout" => {
                        let raw = value(&mut parser)?;
                        let secs = raw.parse::<u64>().map_err(|_| {
                            ParseError::arg(
                                "--timeout must be a non-negative whole number of seconds",
                                "--timeout",
                            )
                        })?;
                        opts.timeout = Some(secs);
                    }
                    "output" => {
                        opts.output = match value(&mut parser)?.as_str() {
                            "json" => OutputMode::Json,
                            "text" => OutputMode::Text,
                            _ => {
                                return Err(ParseError::arg(
                                    "--output must be json or text",
                                    "--output",
                                ));
                            }
                        };
                    }
                    _ => {
                        let (kind, _) = classify(&pos);
                        let Some(arity) = flag_arity(kind, &flag) else {
                            return Err(ParseError::arg(format!("unknown flag: {flag}"), &flag));
                        };
                        match arity {
                            Arity::Skip => {
                                let _ = parser.optional_value();
                            }
                            Arity::Value => {
                                let v = value(&mut parser)?;
                                match flag.as_str() {
                                    "--params" => set_once(&mut flags.params, &flag, v)?,
                                    "--params-file" => set_once(&mut flags.params_file, &flag, v)?,
                                    "--args" => set_once(&mut flags.args, &flag, v)?,
                                    "--limits" => set_once(&mut flags.limits, &flag, v)?,
                                    "--state" => set_once(&mut flags.state, &flag, v)?,
                                    _ => set_once(&mut flags.match_params_file, &flag, v)?,
                                }
                            }
                            Arity::OptionalValue => {
                                let mode = match parser.optional_value().map(text).transpose()? {
                                    None => DryRun::Full,
                                    Some(v) if v == "full" => DryRun::Full,
                                    Some(v) if v == "sparse" => DryRun::Sparse,
                                    Some(_) => {
                                        return Err(ParseError::arg(
                                            "--dry-run takes full or sparse",
                                            &flag,
                                        ));
                                    }
                                };
                                set_once(&mut flags.dry_run, &flag, mode)?;
                            }
                        }
                    }
                }
            }
        }
    }
    if opts.agent.is_none() {
        opts.agent = env("ATLAS_DUCK_AGENT")
            .map(text)
            .transpose()
            .map_err(|_| ParseError::new("ATLAS_DUCK_AGENT is not valid UTF-8"))?
            .filter(|s| !s.is_empty());
    }
    let (kind, path_len) = classify(&pos);
    if opts.help {
        let path = match kind {
            Kind::Help => pos.get(1..).unwrap_or_default().to_vec(),
            Kind::Empty | Kind::Incomplete | Kind::Unknown => pos,
            _ => pos.get(..path_len).unwrap_or_default().to_vec(),
        };
        return Ok((opts, Command::Help { path }));
    }
    let rest = pos.get(path_len..).unwrap_or_default();
    let command = build(kind, &pos, rest, flags, &opts, agent_flag)?;
    Ok((opts, command))
}

fn value(parser: &mut lexopt::Parser) -> Result<String, ParseError> {
    text(parser.value().map_err(lex_error)?)
}

fn no_value(parser: &mut lexopt::Parser, flag: &str) -> Result<(), ParseError> {
    match parser.optional_value() {
        None => Ok(()),
        Some(_) => Err(ParseError::arg(format!("{flag} takes no value"), flag)),
    }
}

/// Exactly `n` positionals after the command path.
fn exactly<'a>(rest: &'a [String], names: &[&str]) -> Result<&'a [String], ParseError> {
    if let Some(name) = names.get(rest.len()) {
        return Err(ParseError::new(format!("missing <{name}>")).with("missing", *name));
    }
    if let Some(extra) = rest.get(names.len()) {
        return Err(ParseError::arg(
            format!("unexpected argument: {extra}"),
            extra,
        ));
    }
    Ok(rest)
}

fn build(
    kind: Kind,
    pos: &[String],
    rest: &[String],
    flags: Flags,
    opts: &GlobalOpts,
    explicit_agent: Option<String>,
) -> Result<Command, ParseError> {
    let id_of = |rest: &[String]| rest.first().cloned().unwrap_or_default();
    match kind {
        Kind::Empty => Err(ParseError::new("no command given")),
        Kind::Incomplete => Err(ParseError::new(format!(
            "incomplete command: {}; try `atlas-duck {} --help`",
            pos.join(" "),
            pos.join(" ")
        ))
        .with("command", pos.join(" "))),
        Kind::Unknown => Err(
            ParseError::new(format!("unknown command: {}", pos.join(" ")))
                .with("command", pos.join(" ")),
        ),
        Kind::Help => Ok(Command::Help {
            path: rest.to_vec(),
        }),
        Kind::NotInBuild(name) => Ok(Command::NotInThisBuild(name)),
        Kind::OpsList => {
            exactly(rest, &[])?;
            Ok(Command::OpsList {
                instance: opts.instance.clone(),
            })
        }
        Kind::OpsDescribe => {
            let rest = exactly(rest, &["op-id"])?;
            Ok(Command::OpsDescribe {
                op_id: id_of(rest),
                instance: opts.instance.clone(),
            })
        }
        Kind::Call => {
            let rest = exactly(rest, &["op-id"])?;
            let params = match (flags.params, flags.params_file) {
                (Some(inline), None) => ParamsSource::Inline(inline),
                (None, Some(file)) => ParamsSource::File(file),
                (Some(_), Some(_)) => {
                    return Err(ParseError::new("give --params or --params-file, not both"));
                }
                (None, None) => {
                    return Err(ParseError::new("call needs --params or --params-file"));
                }
            };
            Ok(Command::Call {
                op_id: id_of(rest),
                params,
            })
        }
        Kind::ScriptRun => {
            let rest = exactly(rest, &["file"])?;
            Ok(Command::ScriptRun {
                source: id_of(rest),
                args: flags.args,
                limits: flags.limits,
                dry_run: flags.dry_run,
            })
        }
        Kind::Instances => {
            exactly(rest, &[])?;
            Ok(Command::Instances)
        }
        Kind::Doctor => {
            exactly(rest, &[])?;
            Ok(Command::Doctor)
        }
        Kind::Await => Ok(Command::Await {
            id: id_of(exactly(rest, &["id"])?),
        }),
        Kind::Status => Ok(Command::Status {
            id: id_of(exactly(rest, &["id"])?),
        }),
        Kind::Cancel => Ok(Command::Cancel {
            id: id_of(exactly(rest, &["id"])?),
        }),
        Kind::RequestsList => {
            exactly(rest, &[])?;
            if let Some(state) = &flags.state
                && state != "pending"
                && state != "recent"
            {
                return Err(ParseError::arg(
                    "--state must be pending or recent",
                    "--state",
                ));
            }
            Ok(Command::RequestsList {
                agent: explicit_agent,
                state: flags.state,
                match_params: flags.match_params_file.map(ParamsSource::File),
            })
        }
        // Task 12 binds the op's flags and positional into `Command::Op`.
        Kind::Op(spec) => Err(ParseError::new(format!(
            "operation {} is not yet bound in this build",
            spec.id
        ))
        .with("op_id", spec.id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn no_env(_: &str) -> Option<OsString> {
        None
    }

    fn ok(list: &[&str]) -> (GlobalOpts, Command) {
        match parse(&args(list), &no_env) {
            Ok(v) => v,
            Err(e) => panic!("parse {list:?} failed: {}", e.message),
        }
    }

    fn err(list: &[&str]) -> ParseError {
        match parse(&args(list), &no_env) {
            Ok(v) => panic!("parse {list:?} should fail, got {v:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn global_flags_anywhere() {
        let a = ok(&["--output", "text", "ops", "list"]);
        let b = ok(&["ops", "list", "--output", "text"]);
        let c = ok(&["ops", "--output=text", "list"]);
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a.0.output, OutputMode::Text);
        assert_eq!(a.1, Command::OpsList { instance: None });
    }

    #[test]
    fn global_flag_values() {
        let (o, c) = ok(&[
            "--agent",
            "bot",
            "--reason",
            "why",
            "--timeout",
            "5",
            "--instance",
            "jira-main",
            "ops",
            "describe",
            "jira.issue.get",
        ]);
        assert_eq!(o.agent.as_deref(), Some("bot"));
        assert_eq!(o.reason.as_deref(), Some("why"));
        assert_eq!(o.timeout, Some(5));
        assert_eq!(o.instance.as_deref(), Some("jira-main"));
        assert_eq!(
            c,
            Command::OpsDescribe {
                op_id: "jira.issue.get".into(),
                instance: Some("jira-main".into())
            }
        );
    }

    fn ok_env(list: &[&str], env: &dyn Fn(&str) -> Option<OsString>) -> (GlobalOpts, Command) {
        match parse(&args(list), env) {
            Ok(v) => v,
            Err(e) => panic!("parse {list:?} failed: {}", e.message),
        }
    }

    #[test]
    fn agent_falls_back_to_env() {
        let env = |k: &str| (k == "ATLAS_DUCK_AGENT").then(|| OsString::from("from-env"));
        assert_eq!(
            ok_env(&["instances"], &env).0.agent.as_deref(),
            Some("from-env")
        );
        let (o, _) = ok_env(&["--agent", "flag", "instances"], &env);
        assert_eq!(o.agent.as_deref(), Some("flag"));
    }

    #[test]
    fn timeout_parse() {
        assert_eq!(ok(&["--timeout", "0", "instances"]).0.timeout, Some(0));
        assert_eq!(ok(&["--timeout", "100", "instances"]).0.timeout, Some(100));
        for bad in ["-1", "x", "1.5", ""] {
            let e = err(&["--timeout", bad, "instances"]);
            assert_eq!(
                e.details.get("arg"),
                Some(&Value::from("--timeout")),
                "{bad}"
            );
        }
        let e = err(&["instances", "--timeout"]);
        assert_eq!(e.details.get("arg"), Some(&Value::from("--timeout")));
    }

    #[test]
    fn output_must_be_json_or_text() {
        let e = err(&["--output", "xml", "instances"]);
        assert_eq!(e.details.get("arg"), Some(&Value::from("--output")));
    }

    #[test]
    fn no_args_is_no_command() {
        assert_eq!(err(&[]).message, "no command given");
        assert_eq!(err(&["--output", "text"]).message, "no command given");
    }

    #[test]
    fn mistyped_flag_names_the_argument() {
        let e = err(&["ops", "list", "--bogus"]);
        assert_eq!(e.details.get("arg"), Some(&Value::from("--bogus")));
        let e = err(&["ops", "list", "-x"]);
        assert_eq!(e.details.get("arg"), Some(&Value::from("-x")));
        // A flag that exists for another command is still unknown here.
        let e = err(&["instances", "--params", "{}"]);
        assert_eq!(e.details.get("arg"), Some(&Value::from("--params")));
    }

    #[test]
    fn help_forms() {
        assert_eq!(ok(&["--help"]).1, Command::Help { path: vec![] });
        assert_eq!(ok(&["help"]).1, Command::Help { path: vec![] });
        assert_eq!(
            ok(&["help", "jira", "issue"]).1,
            Command::Help {
                path: vec!["jira".into(), "issue".into()]
            }
        );
        assert_eq!(
            ok(&["jira", "--help"]).1,
            Command::Help {
                path: vec!["jira".into()]
            }
        );
        let full = Command::Help {
            path: vec!["jira".into(), "issue".into(), "get".into()],
        };
        assert_eq!(ok(&["jira", "issue", "get", "--help"]).1, full);
        // Op flags are not bound yet; --help still wins, and positionals past the path drop out.
        assert_eq!(
            ok(&["jira", "issue", "get", "ABC-1", "--comments", "--help"]).1,
            full
        );
        assert!(ok(&["ops", "list", "--help"]).0.help);
        assert!(err(&["--help=x"]).details.contains_key("arg"));
    }

    #[test]
    fn generic_commands() {
        assert_eq!(ok(&["instances"]).1, Command::Instances);
        assert_eq!(ok(&["doctor"]).1, Command::Doctor);
        assert_eq!(
            ok(&["await", "req_1"]).1,
            Command::Await { id: "req_1".into() }
        );
        assert_eq!(
            ok(&["status", "req_1"]).1,
            Command::Status { id: "req_1".into() }
        );
        assert_eq!(
            ok(&["cancel", "req_1"]).1,
            Command::Cancel { id: "req_1".into() }
        );
        assert_eq!(
            ok(&["call", "jira.myself", "--params", "{}"]).1,
            Command::Call {
                op_id: "jira.myself".into(),
                params: ParamsSource::Inline("{}".into())
            }
        );
        assert_eq!(
            ok(&["call", "jira.myself", "--params-file", "-"]).1,
            Command::Call {
                op_id: "jira.myself".into(),
                params: ParamsSource::File("-".into())
            }
        );
        assert_eq!(
            ok(&[
                "script",
                "run",
                "a.js",
                "--args",
                "{}",
                "--limits",
                "{}",
                "--dry-run"
            ])
            .1,
            Command::ScriptRun {
                source: "a.js".into(),
                args: Some("{}".into()),
                limits: Some("{}".into()),
                dry_run: Some(DryRun::Full)
            }
        );
        assert!(matches!(
            ok(&["script", "run", "-", "--dry-run=sparse"]).1,
            Command::ScriptRun {
                dry_run: Some(DryRun::Sparse),
                ..
            }
        ));
        assert_eq!(
            ok(&[
                "requests",
                "list",
                "--agent",
                "bot",
                "--state",
                "pending",
                "--match-params-file",
                "-"
            ])
            .1,
            Command::RequestsList {
                agent: Some("bot".into()),
                state: Some("pending".into()),
                match_params: Some(ParamsSource::File("-".into()))
            }
        );
    }

    #[test]
    fn generic_command_errors() {
        assert!(err(&["call", "jira.myself"]).message.contains("--params"));
        assert!(
            err(&["call", "x", "--params", "{}", "--params-file", "f"])
                .message
                .contains("not both")
        );
        assert!(err(&["call", "--params", "{}"]).message.contains("op-id"));
        assert!(err(&["await"]).message.contains("<id>"));
        assert!(err(&["await", "a", "b"]).message.contains("unexpected"));
        assert!(
            err(&["requests", "list", "--state", "old"])
                .message
                .contains("pending")
        );
        assert!(
            err(&["script", "run", "a.js", "--dry-run=huge"])
                .message
                .contains("full or sparse")
        );
        assert!(
            err(&["call", "x", "--params", "{}", "--params", "{}"])
                .message
                .contains("more than once")
        );
        assert!(err(&["ops"]).message.starts_with("incomplete command"));
        assert!(err(&["ops", "nope"]).message.starts_with("unknown command"));
        assert!(err(&["nope"]).message.starts_with("unknown command"));
        assert!(
            err(&["jira", "issue"])
                .message
                .starts_with("incomplete command")
        );
    }

    #[test]
    fn requests_list_agent_ignores_env_fallback() {
        let env = |k: &str| (k == "ATLAS_DUCK_AGENT").then(|| OsString::from("from-env"));
        let (o, c) = ok_env(&["requests", "list"], &env);
        assert_eq!(o.agent.as_deref(), Some("from-env"));
        assert_eq!(
            c,
            Command::RequestsList {
                agent: None,
                state: None,
                match_params: None
            }
        );
    }

    #[test]
    fn mcp_and_verify_export_parse_to_not_in_this_build() {
        assert_eq!(
            ok(&["mcp", "--tools", "full"]).1,
            Command::NotInThisBuild("mcp")
        );
        assert_eq!(
            ok(&["verify-export", "dir", "--anchor-dir", "x"]).1,
            Command::NotInThisBuild("verify-export")
        );
    }

    #[test]
    fn op_paths_are_not_bound_until_task_12() {
        let e = err(&["jira", "issue", "get", "ABC-1", "--bogus"]);
        assert!(e.message.contains("not yet bound"));
        assert_eq!(e.details.get("op_id"), Some(&Value::from("jira.issue.get")));
    }

    #[test]
    fn double_dash_ends_flags() {
        let (_, c) = ok(&["await", "--", "--weird"]);
        assert_eq!(
            c,
            Command::Await {
                id: "--weird".into()
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn invalid_utf8_is_usage_with_the_index() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![0x66, 0xff]);
        let e = match parse(&[OsString::from("instances"), bad], &no_env) {
            Ok(_) => panic!("must fail"),
            Err(e) => e,
        };
        assert_eq!(e.details.get("arg_index"), Some(&Value::from(2)));
    }

    #[cfg(windows)]
    #[test]
    fn invalid_utf16_is_usage_with_the_index() {
        use std::os::windows::ffi::OsStringExt;
        let bad = OsString::from_wide(&[0x66, 0xD800]);
        let e = match parse(&[OsString::from("instances"), bad], &no_env) {
            Ok(_) => panic!("must fail"),
            Err(e) => e,
        };
        assert_eq!(e.details.get("arg_index"), Some(&Value::from(2)));
    }
}
