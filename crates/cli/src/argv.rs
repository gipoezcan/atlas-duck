//! Argv grammar (PD-13): global flags anywhere before `--`, the generic and local commands, and
//! the command path of a registry op. Tokenized by `lexopt`; op flags are bound by `binding` and
//! file/stdin inputs are read through `input` (only for a `-` or `--*-file` argument). Nothing
//! validates params (§4.1: the app does).

use std::ffi::{OsStr, OsString};

use atlas_duck_ipc::proto::AgentNameSource;
use atlas_duck_registry::OperationSpec;
use serde_json::{Map, Value, json};

use crate::binding::{bind, find_op, flag_takes_value, is_noun_prefix, nearest_children};
use crate::input::{Inputs, parse_json, read_arg_json, read_arg_source};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputMode {
    Json,
    Text,
}

/// The §4.1 global flags. `agent` already includes the `ATLAS_DUCK_AGENT` fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobalOpts {
    pub agent: Option<String>,
    /// Where `agent` came from (the hello's `agent_name_source`): `--agent`, the environment
    /// fallback, or nowhere.
    pub agent_source: AgentNameSource,
    pub reason: Option<String>,
    /// Seconds; `None` = default, `Some(0)` = submit and return pending.
    pub timeout: Option<u64>,
    pub instance: Option<String>,
    pub output: OutputMode,
    pub help: bool,
}

/// The `requests list --match-params-file` document: the request to look for.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MatchParams {
    pub op_id: String,
    pub params: Value,
    pub instance: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DryRun {
    Full,
    Sparse,
}

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
        params: Value,
    },
    ScriptRun {
        /// The script text (read from the file or stdin by the CLI).
        source: String,
        /// Defaults to `{}`.
        args: Value,
        /// A JSON object; the app validates its keys.
        limits: Option<Value>,
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
        match_params: Option<MatchParams>,
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
    /// The `--timeout` deadline ran out while reading input: not a `usage` failure but exit 5
    /// `unreachable` / `launch_timeout` (§4.1: expiry before submission, nothing queued).
    pub deadline_expired: bool,
}

impl ParseError {
    pub(crate) fn new(message: impl Into<String>) -> ParseError {
        ParseError {
            message: message.into(),
            details: Map::new(),
            deadline_expired: false,
        }
    }

    /// The `--timeout` deadline expired while waiting for `what`.
    pub(crate) fn deadline(what: &str) -> ParseError {
        ParseError {
            deadline_expired: true,
            ..ParseError::new(format!(
                "the --timeout deadline expired while reading {what}"
            ))
        }
    }

    pub(crate) fn with(mut self, key: &str, value: impl Into<Value>) -> ParseError {
        self.details.insert(key.to_owned(), value.into());
        self
    }

    pub(crate) fn arg(message: impl Into<String>, arg: &str) -> ParseError {
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
    if let Some((spec, used)) = find_op(pos) {
        return (Kind::Op(spec), used);
    }
    if is_noun_prefix(pos) {
        (Kind::Incomplete, pos.len())
    } else {
        (Kind::Unknown, 0)
    }
}

/// How a non-global flag is read under the command the positionals name so far.
enum Arity {
    Value,
    OptionalValue,
    /// Accepted and ignored: `mcp`/`verify-export` fail anyway.
    Skip,
}

fn flag_arity(kind: Kind, flag: &str) -> Option<Arity> {
    match (kind, flag) {
        (Kind::Call, "--params" | "--params-file") => Some(Arity::Value),
        (Kind::ScriptRun, "--args" | "--limits") => Some(Arity::Value),
        (Kind::ScriptRun, "--dry-run") => Some(Arity::OptionalValue),
        (Kind::RequestsList, "--state" | "--match-params-file") => Some(Arity::Value),
        (Kind::NotInBuild(_), _) => Some(Arity::Skip),
        _ => None,
    }
}

fn unknown_flag(flag: &str) -> ParseError {
    ParseError::arg(format!("unknown flag: {}", clip(flag)), &clip(flag))
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

/// Longest echo of user text in an error message or detail.
const CLIP_CHARS: usize = 80;

/// `s` cut to `CLIP_CHARS` characters (never mid-character), with `...` when cut. Keeps a huge
/// argument from being echoed whole into an error envelope.
pub(crate) fn clip(s: &str) -> String {
    match s.char_indices().nth(CLIP_CHARS) {
        Some((cut, _)) => format!("{}...", &s[..cut]),
        None => s.to_string(),
    }
}

pub(crate) fn parse(
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    inputs: &mut Inputs<'_>,
) -> Result<(GlobalOpts, Command), ParseError> {
    check_utf8(args)?;
    let mut opts = GlobalOpts {
        agent: None,
        agent_source: AgentNameSource::None,
        reason: None,
        timeout: None,
        instance: None,
        output: OutputMode::Json,
        help: false,
    };
    let mut flags = Flags::default();
    // `requests list --agent` filters by the explicit flag only, not the environment fallback.
    let mut agent_flag: Option<String> = None;
    let mut agent_given = false;
    let mut output_flag: Option<OutputMode> = None;
    let mut pos: Vec<String> = Vec::new();
    // The first unknown flag: reported after the loop unless `--help` is also present, so
    // `--help` wins over a bad flag wherever it appears.
    let mut unknown: Option<ParseError> = None;
    // Op flags, re-spelled `--flag=value` for `binding::bind`.
    let mut op_flags: Vec<OsString> = Vec::new();
    let mut parser = lexopt::Parser::from_args(args.iter().cloned());
    while let Some(arg) = parser.next().map_err(lex_error)? {
        match arg {
            lexopt::Arg::Value(v) => pos.push(text(v)?),
            lexopt::Arg::Short('h') => opts.help = true,
            lexopt::Arg::Short(c) => {
                unknown.get_or_insert_with(|| {
                    ParseError::arg(format!("unknown flag: -{c}"), &format!("-{c}"))
                });
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
                        set_once(&mut agent_flag, &flag, v.clone())?;
                        // L83: `--agent ""` is no name (as an empty `ATLAS_DUCK_AGENT` is),
                        // sent as `None`; it still counts as given, so the environment does
                        // not fill the gap.
                        agent_given = true;
                        if !v.is_empty() {
                            opts.agent = Some(v);
                            opts.agent_source = AgentNameSource::Flag;
                        }
                    }
                    "reason" => set_once(&mut opts.reason, &flag, value(&mut parser)?)?,
                    "instance" => set_once(&mut opts.instance, &flag, value(&mut parser)?)?,
                    "timeout" => {
                        let raw = value(&mut parser)?;
                        let secs = raw.parse::<u64>().map_err(|_| {
                            ParseError::arg(
                                "--timeout must be a non-negative whole number of seconds",
                                "--timeout",
                            )
                        })?;
                        set_once(&mut opts.timeout, &flag, secs)?;
                    }
                    "output" => {
                        let mode = match value(&mut parser)?.as_str() {
                            "json" => OutputMode::Json,
                            "text" => OutputMode::Text,
                            _ => {
                                return Err(ParseError::arg(
                                    "--output must be json or text",
                                    "--output",
                                ));
                            }
                        };
                        set_once(&mut output_flag, &flag, mode)?;
                    }
                    _ => {
                        let (kind, _) = classify(&pos);
                        if let Kind::Op(spec) = kind {
                            match flag_takes_value(spec, &flag) {
                                None => {
                                    unknown.get_or_insert_with(|| unknown_flag(&flag));
                                    let _ = parser.optional_value();
                                }
                                Some(true) => {
                                    let v = value(&mut parser)?;
                                    op_flags.push(format!("{flag}={v}").into());
                                }
                                Some(false) => match parser.optional_value() {
                                    None => op_flags.push(flag.into()),
                                    Some(v) => {
                                        op_flags.push(format!("{flag}={}", text(v)?).into());
                                    }
                                },
                            }
                            continue;
                        }
                        let Some(arity) = flag_arity(kind, &flag) else {
                            unknown.get_or_insert_with(|| unknown_flag(&flag));
                            let _ = parser.optional_value();
                            continue;
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
    if let Some(mode) = output_flag {
        opts.output = mode;
    }
    if !agent_given {
        opts.agent = env("ATLAS_DUCK_AGENT")
            .map(text)
            .transpose()
            .map_err(|_| ParseError::new("ATLAS_DUCK_AGENT is not valid UTF-8"))?
            .filter(|s| !s.is_empty());
        if opts.agent.is_some() {
            opts.agent_source = AgentNameSource::Env;
        }
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
    if let Some(e) = unknown {
        return Err(e);
    }
    inputs.set_timeout(opts.timeout);
    let rest = pos.get(path_len..).unwrap_or_default();
    let ctx = Ctx {
        opts: &opts,
        explicit_agent: agent_flag.filter(|a| !a.is_empty()),
        op_flags,
    };
    let command = build(kind, &pos, rest, flags, ctx, inputs)?;
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

/// `e` with `details.arg` set when the reader did not name one.
fn with_arg(mut e: ParseError, arg: &str) -> ParseError {
    e.details
        .entry("arg".to_owned())
        .or_insert_with(|| Value::from(arg));
    e
}

/// Exactly `n` positionals after the command path.
fn exactly<'a>(rest: &'a [String], names: &[&str]) -> Result<&'a [String], ParseError> {
    if let Some(name) = names.get(rest.len()) {
        return Err(ParseError::new(format!("missing <{name}>")).with("missing", *name));
    }
    if let Some(extra) = rest.get(names.len()) {
        return Err(ParseError::arg(
            format!("unexpected argument: {}", clip(extra)),
            &clip(extra),
        ));
    }
    Ok(rest)
}

/// What `build` needs besides the positionals and the generic flags.
struct Ctx<'a> {
    opts: &'a GlobalOpts,
    explicit_agent: Option<String>,
    op_flags: Vec<OsString>,
}

/// A JSON document that is a JSON object.
fn json_object(value: Value, flag: &str) -> Result<Value, ParseError> {
    if value.is_object() {
        Ok(value)
    } else {
        Err(ParseError::arg(
            format!("{flag} must be a JSON object"),
            flag,
        ))
    }
}

fn inline_json(raw: &str, flag: &str) -> Result<Value, ParseError> {
    parse_json(raw).map_err(|e| {
        ParseError {
            message: format!("{flag}: {}", e.message),
            ..e
        }
        .with("arg", flag)
    })
}

fn match_params(doc: Value) -> Result<MatchParams, ParseError> {
    let bad = |m: &str| ParseError::arg(format!("--match-params-file: {m}"), "--match-params-file");
    let Value::Object(mut map) = doc else {
        return Err(bad("must be a JSON object"));
    };
    let op_id = match map.remove("op_id") {
        Some(Value::String(s)) => s,
        _ => return Err(bad("op_id (string) is required")),
    };
    let params = map
        .remove("params")
        .ok_or_else(|| bad("params is required"))?;
    let instance = match map.remove("instance") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s),
        Some(_) => return Err(bad("instance must be a string")),
    };
    if let Some(extra) = map.keys().next() {
        return Err(bad(&format!("unknown key {}", clip(extra))));
    }
    Ok(MatchParams {
        op_id,
        params,
        instance,
    })
}

/// A suffix for `incomplete`/`unknown command` messages naming what can follow.
fn children_hint(pos: &[String]) -> (String, Vec<&'static str>) {
    let children = nearest_children(pos);
    if children.is_empty() {
        return (String::new(), children);
    }
    (
        format!("; expected one of: {}", children.join(", ")),
        children,
    )
}

fn build(
    kind: Kind,
    pos: &[String],
    rest: &[String],
    flags: Flags,
    ctx: Ctx<'_>,
    inputs: &mut Inputs<'_>,
) -> Result<Command, ParseError> {
    let Ctx {
        opts,
        explicit_agent,
        op_flags,
    } = ctx;
    let id_of = |rest: &[String]| rest.first().cloned().unwrap_or_default();
    match kind {
        Kind::Empty => Err(ParseError::new("no command given")),
        Kind::Incomplete => {
            let command = clip(&pos.join(" "));
            let (hint, children) = children_hint(pos);
            Err(ParseError::new(format!(
                "incomplete command: {command}{hint}; try `atlas-duck {command} --help`"
            ))
            .with("command", command)
            .with("children", json!(children)))
        }
        Kind::Unknown => {
            let command = clip(&pos.join(" "));
            let (hint, children) = children_hint(pos);
            let mut e = ParseError::new(format!("unknown command: {command}{hint}"))
                .with("command", command);
            if !children.is_empty() {
                e = e.with("children", json!(children));
            }
            Err(e)
        }
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
                (Some(inline), None) => inline_json(&inline, "--params")?,
                (None, Some(file)) => read_arg_json(OsStr::new(&file), inputs)
                    .map_err(|e| with_arg(e, "--params-file"))?,
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
            let args = match flags.args {
                Some(raw) => inline_json(&raw, "--args")?,
                None => json!({}),
            };
            let limits = flags
                .limits
                .map(|raw| json_object(inline_json(&raw, "--limits")?, "--limits"))
                .transpose()?;
            let source = read_arg_source(OsStr::new(&id_of(rest)), inputs)
                .map_err(|e| with_arg(e, "<file>"))?;
            Ok(Command::ScriptRun {
                source,
                args,
                limits,
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
            let match_params = flags
                .match_params_file
                .map(|file| {
                    read_arg_json(OsStr::new(&file), inputs)
                        .map_err(|e| with_arg(e, "--match-params-file"))
                        .and_then(match_params)
                })
                .transpose()?;
            Ok(Command::RequestsList {
                agent: explicit_agent,
                state: flags.state,
                match_params,
            })
        }
        Kind::Op(spec) => {
            // Flags first, then the positionals after `--`, so a positional that looks like a
            // flag stays a positional.
            let mut tokens = op_flags;
            if !rest.is_empty() {
                tokens.push("--".into());
                tokens.extend(rest.iter().map(OsString::from));
            }
            let params = bind(spec, &tokens, inputs)?;
            Ok(Command::Op {
                op_id: spec.id.to_owned(),
                params,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    /// A stdin that fails the test if anything reads it.
    struct NoRead;

    impl Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("stdin was read");
        }
    }

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn no_env(_: &str) -> Option<OsString> {
        None
    }

    fn ok(list: &[&str]) -> (GlobalOpts, Command) {
        match parse(&args(list), &no_env, &mut Inputs::new(NoRead)) {
            Ok(v) => v,
            Err(e) => panic!("parse {list:?} failed: {}", e.message),
        }
    }

    fn ok_stdin(list: &[&str], stdin: &str) -> (GlobalOpts, Command) {
        let mut inputs = Inputs::new(Cursor::new(stdin.as_bytes().to_vec()));
        match parse(&args(list), &no_env, &mut inputs) {
            Ok(v) => v,
            Err(e) => panic!("parse {list:?} failed: {}", e.message),
        }
    }

    fn err(list: &[&str]) -> ParseError {
        match parse(&args(list), &no_env, &mut Inputs::new(NoRead)) {
            Ok(v) => panic!("parse {list:?} should fail, got {v:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn repeated_global_flags_are_usage_errors() {
        for (list, flag) in [
            (
                &["--agent", "a", "--agent", "b", "ops", "list"][..],
                "--agent",
            ),
            (
                &["--reason", "a", "--reason", "b", "ops", "list"][..],
                "--reason",
            ),
            (
                &["--instance", "a", "--instance", "b", "ops", "list"][..],
                "--instance",
            ),
            (
                &["--timeout", "5", "--timeout", "6", "ops", "list"][..],
                "--timeout",
            ),
            (
                &["--output", "json", "--output", "text", "ops", "list"][..],
                "--output",
            ),
        ] {
            let e = err(list);
            assert_eq!(
                e.message,
                format!("{flag} given more than once"),
                "{list:?}"
            );
            assert_eq!(e.details.get("arg"), Some(&json!(flag)), "{list:?}");
        }
    }

    #[test]
    fn short_h_is_help() {
        assert!(ok(&["-h"]).0.help);
        assert_eq!(
            ok(&["ops", "list", "-h"]).1,
            Command::Help {
                path: vec!["ops".into(), "list".into()]
            }
        );
    }

    #[test]
    fn huge_timeout_parses_without_overflow() {
        let (opts, _) = ok(&["--timeout", "18446744073709551615", "instances"]);
        assert_eq!(opts.timeout, Some(u64::MAX));
    }

    #[test]
    fn clip_is_char_safe_and_bounded() {
        assert_eq!(clip("short"), "short");
        assert_eq!(clip(&"a".repeat(80)), "a".repeat(80));
        let clipped = clip(&"é".repeat(100));
        assert_eq!(clipped, format!("{}...", "é".repeat(80)));
    }

    #[test]
    fn echoed_argv_text_is_clipped() {
        let long = "x".repeat(10_000);
        let flag = format!("--{long}");
        for list in [
            vec!["ops", "list", long.as_str()],
            vec!["ops", "list", flag.as_str()],
            vec![long.as_str()],
        ] {
            let e = err(&list);
            assert!(
                e.message.chars().count() <= 120,
                "message: {}",
                e.message.len()
            );
            for value in e.details.values().filter_map(Value::as_str) {
                assert!(value.chars().count() <= 83, "detail not clipped");
            }
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
        match parse(&args(list), env, &mut Inputs::new(NoRead)) {
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
    fn agent_source_follows_where_the_name_came_from() {
        let env = |k: &str| (k == "ATLAS_DUCK_AGENT").then(|| OsString::from("from-env"));
        let source =
            |args: &[&str], e: &dyn Fn(&str) -> Option<OsString>| ok_env(args, e).0.agent_source;
        assert_eq!(source(&["instances"], &env), AgentNameSource::Env);
        assert_eq!(
            source(&["--agent", "flag", "instances"], &env),
            AgentNameSource::Flag
        );
        assert_eq!(source(&["instances"], &|_| None), AgentNameSource::None);
        // An empty environment value is no name at all.
        let empty = |k: &str| (k == "ATLAS_DUCK_AGENT").then(|| OsString::from(""));
        assert_eq!(source(&["instances"], &empty), AgentNameSource::None);
    }

    /// L83: an empty `--agent` is no name: the hello carries `None` and the source is `None`,
    /// even with `ATLAS_DUCK_AGENT` set; `requests list --agent ""` adds no filter.
    #[test]
    fn empty_agent_flag_sent_as_none() {
        let env = |k: &str| (k == "ATLAS_DUCK_AGENT").then(|| OsString::from("from-env"));
        for e in [&env as &dyn Fn(&str) -> Option<OsString>, &|_| None] {
            let (o, _) = ok_env(&["--agent", "", "instances"], e);
            assert_eq!(o.agent, None);
            assert_eq!(o.agent_source, AgentNameSource::None);
            let (o, _) = ok_env(&["--agent=", "instances"], e);
            assert_eq!(o.agent, None);
            assert_eq!(o.agent_source, AgentNameSource::None);
            let (o, c) = ok_env(&["--agent", "", "requests", "list"], e);
            assert_eq!(o.agent, None);
            assert!(
                matches!(c, Command::RequestsList { agent: None, .. }),
                "{c:?}"
            );
        }
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
        // --help wins over the op's own flags, and positionals past the path drop out.
        assert_eq!(
            ok(&["jira", "issue", "get", "ABC-1", "--comments", "--help"]).1,
            full
        );
        assert!(ok(&["ops", "list", "--help"]).0.help);
        assert!(err(&["--help=x"]).details.contains_key("arg"));
    }

    #[test]
    fn help_wins_over_a_bad_flag_and_never_reads_stdin() {
        let jira_search = Command::Help {
            path: vec!["jira".into(), "search".into()],
        };
        for list in [
            &["jira", "search", "--bogus", "--help"][..],
            &["jira", "search", "--help", "--bogus"],
            &["jira", "search", "--bogus=x", "--help"],
            &["jira", "search", "-x", "--help"],
        ] {
            assert_eq!(ok(list).1, jira_search, "{list:?}");
        }
        // Without --help the same flag is still a usage error.
        assert!(
            err(&["jira", "search", "--bogus"])
                .details
                .contains_key("arg")
        );
        assert_eq!(
            ok(&["call", "x", "--bogus", "--help"]).1,
            Command::Help {
                path: vec!["call".into()]
            }
        );
        // A `-` source is not read when --help is asked for (NoRead panics on a read).
        assert_eq!(
            ok(&["script", "run", "-", "--help"]).1,
            Command::Help {
                path: vec!["script".into(), "run".into()]
            }
        );
        assert_eq!(
            ok(&["requests", "list", "--match-params-file", "-", "--help"]).1,
            Command::Help {
                path: vec!["requests".into(), "list".into()]
            }
        );
        assert!(matches!(
            ok(&[
                "jira",
                "issue",
                "create",
                "--description-file",
                "-",
                "--help"
            ])
            .1,
            Command::Help { .. }
        ));
    }

    /// A stdin that never produces a byte until it is dropped.
    struct Blocked(std::sync::mpsc::Receiver<()>);

    impl Read for Blocked {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }

    #[test]
    fn stdin_read_is_bounded_by_the_timeout() {
        let (hold, rx) = std::sync::mpsc::channel::<()>();
        let mut inputs = Inputs::new(Blocked(rx));
        let started = std::time::Instant::now();
        let e = match parse(
            &args(&["script", "run", "-", "--timeout", "1"]),
            &no_env,
            &mut inputs,
        ) {
            Ok(_) => panic!("a stdin that never answers must hit the deadline"),
            Err(e) => e,
        };
        assert!(e.deadline_expired, "{}", e.message);
        assert!(started.elapsed() < std::time::Duration::from_secs(30));
        drop(hold);
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
                params: json!({})
            }
        );
        assert_eq!(
            ok_stdin(
                &["call", "jira.myself", "--params-file", "-"],
                "\u{feff}{\"a\":1}"
            )
            .1,
            Command::Call {
                op_id: "jira.myself".into(),
                params: json!({"a": 1})
            }
        );
        assert_eq!(
            ok_stdin(
                &[
                    "script",
                    "run",
                    "-",
                    "--args",
                    "{\"p\":1}",
                    "--limits",
                    "{\"timeout_s\":60}",
                    "--dry-run"
                ],
                "1+1"
            )
            .1,
            Command::ScriptRun {
                source: "1+1".into(),
                args: json!({"p": 1}),
                limits: Some(json!({"timeout_s": 60})),
                dry_run: Some(DryRun::Full)
            }
        );
        assert_eq!(
            ok_stdin(
                &[
                    "requests",
                    "list",
                    "--agent",
                    "bot",
                    "--state",
                    "pending",
                    "--match-params-file",
                    "-"
                ],
                r#"{"op_id":"jira.search","params":{"jql":"a"},"instance":"j"}"#
            )
            .1,
            Command::RequestsList {
                agent: Some("bot".into()),
                state: Some("pending".into()),
                match_params: Some(MatchParams {
                    op_id: "jira.search".into(),
                    params: json!({"jql": "a"}),
                    instance: Some("j".into())
                })
            }
        );
    }

    #[test]
    fn call_params_exactly_one() {
        assert!(err(&["call", "x"]).message.contains("--params"));
        assert!(
            err(&["call", "x", "--params", "{}", "--params-file", "-"])
                .message
                .contains("not both")
        );
        let e = err(&["call", "x", "--params", "{"]);
        assert_eq!(e.details.get("arg"), Some(&json!("--params")));
    }

    #[test]
    fn large_integer_passed_through() {
        let (_, c) = ok(&[
            "call",
            "jira.issue.get",
            "--params",
            r#"{"key":"A-1","x":9007199254740993}"#,
        ]);
        let Command::Call { params, .. } = c else {
            panic!("not a call");
        };
        assert_eq!(params.to_string(), r#"{"key":"A-1","x":9007199254740993}"#);
    }

    #[test]
    fn script_run_dry_run_forms() {
        let dry = |list: &[&str]| match ok_stdin(list, "s").1 {
            Command::ScriptRun { dry_run, .. } => dry_run,
            other => panic!("not a script run: {other:?}"),
        };
        assert_eq!(dry(&["script", "run", "-"]), None);
        assert_eq!(
            dry(&["script", "run", "-", "--dry-run"]),
            Some(DryRun::Full)
        );
        assert_eq!(
            dry(&["script", "run", "-", "--dry-run=full"]),
            Some(DryRun::Full)
        );
        assert_eq!(
            dry(&["script", "run", "-", "--dry-run=sparse"]),
            Some(DryRun::Sparse)
        );
        assert!(
            err(&["script", "run", "-", "--dry-run=x"])
                .details
                .contains_key("arg")
        );
        // --limits must be an object; --args may be any JSON.
        assert!(
            err(&["script", "run", "-", "--limits", "[1]"])
                .message
                .contains("JSON object")
        );
    }

    #[test]
    fn match_params_shape_is_checked() {
        for (doc, needle) in [
            ("[]", "JSON object"),
            (r#"{"params":{}}"#, "op_id"),
            (r#"{"op_id":"x"}"#, "params"),
            (r#"{"op_id":"x","params":{},"instance":1}"#, "instance"),
            (r#"{"op_id":"x","params":{},"zzz":1}"#, "unknown key"),
        ] {
            let mut inputs = Inputs::new(Cursor::new(doc.as_bytes().to_vec()));
            let list = args(&["requests", "list", "--match-params-file", "-"]);
            let Err(e) = parse(&list, &no_env, &mut inputs) else {
                panic!("{doc} should fail");
            };
            assert!(e.message.contains(needle), "{doc}: {}", e.message);
        }
    }

    #[test]
    fn stdin_is_not_read_without_dash() {
        // `NoRead` panics if touched.
        ok(&["call", "jira.myself", "--params", "{}"]);
        ok(&["jira", "issue", "get", "ABC-1", "--comments"]);
        ok(&["requests", "list"]);
    }

    #[test]
    fn op_subcommands_bind_flags_and_positional() {
        let (_, c) = ok(&[
            "jira",
            "issue",
            "get",
            "ABC-1",
            "--comments",
            "--fields",
            "a,b",
        ]);
        assert_eq!(
            c,
            Command::Op {
                op_id: "jira.issue.get".into(),
                params: json!({"key": "ABC-1", "comments": true, "fields": ["a", "b"]})
            }
        );
        // Flags before the positional, `=` form, globals interleaved.
        let (o, c2) = ok(&[
            "jira",
            "issue",
            "get",
            "--fields=a,b",
            "--output",
            "text",
            "--comments",
            "ABC-1",
        ]);
        assert_eq!(o.output, OutputMode::Text);
        assert_eq!(c, c2);
        // A flag value is consumed by flag kind: it is not a positional.
        let (_, c) = ok(&["jira", "search", "--max", "5", "project=A"]);
        assert_eq!(
            c,
            Command::Op {
                op_id: "jira.search".into(),
                params: json!({"jql": "project=A", "max": 5})
            }
        );
        // A positional that looks like a flag, after `--`.
        let (_, c) = ok(&["jira", "search", "--", "--odd"]);
        assert!(matches!(c, Command::Op { params, .. } if params["jql"] == "--odd"));
        // Unknown flag for this op, and a bool given a value.
        assert_eq!(
            err(&["jira", "issue", "get", "ABC-1", "--bogus"])
                .details
                .get("arg"),
            Some(&json!("--bogus"))
        );
        assert!(
            err(&["jira", "issue", "get", "ABC-1", "--comments=true"])
                .message
                .contains("takes no value")
        );
        // Repeated flags are errors, as for the generic commands.
        assert!(
            err(&["jira", "search", "p", "--max", "1", "--max", "2"])
                .message
                .contains("more than once")
        );
        assert!(
            err(&["jira", "search", "p", "--max"])
                .message
                .contains("missing value")
        );
        // A wrong op path lists the children of the nearest noun.
        let e = err(&["jira", "nope"]);
        assert!(e.message.contains("issue"), "{}", e.message);
        assert!(e.details.contains_key("children"));
        assert!(err(&["jira", "issue"]).message.contains("get"));
    }

    #[test]
    fn command_flags_must_follow_the_command_path() {
        // The command is classified from the positionals seen so far, so a command-specific flag
        // before its command path is an unknown flag; globals work anywhere.
        let e = err(&["--state", "x", "requests", "list"]);
        assert_eq!(e.details.get("arg"), Some(&json!("--state")));
        let e = err(&["--max", "5", "jira", "search", "p"]);
        assert_eq!(e.details.get("arg"), Some(&json!("--max")));
        ok(&["requests", "list", "--state", "pending"]);
    }

    #[test]
    fn generic_command_errors() {
        assert!(err(&["call", "jira.myself"]).message.contains("--params"));
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
        let e = match parse(
            &[OsString::from("instances"), bad],
            &no_env,
            &mut Inputs::new(NoRead),
        ) {
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
        let e = match parse(
            &[OsString::from("instances"), bad],
            &no_env,
            &mut Inputs::new(NoRead),
        ) {
            Ok(_) => panic!("must fail"),
            Err(e) => e,
        };
        assert_eq!(e.details.get("arg_index"), Some(&Value::from(2)));
    }
}
