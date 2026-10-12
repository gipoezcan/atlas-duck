//! Registry-driven op subcommands (§4.1, §2.3 `CliBinding`): finds the op for a command path and
//! binds its positional and flags (and `--<param>-file` variants) into the params object. No
//! schema validation happens here (§4.1: the app validates); the schema is only consulted for
//! whether a positional is required and whether a string-bound param is an integer.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};

use atlas_duck_registry::{FlagKind, OperationSpec, all};
use serde_json::{Map, Value};

use crate::argv::{ParseError, clip};
use crate::input::{Inputs, base64, parse_json, read_arg_bytes, read_arg_source};

/// The op whose noun path is the longest prefix of `path`, and how many tokens that path uses.
pub(crate) fn find_op(path: &[String]) -> Option<(&'static OperationSpec, usize)> {
    all()
        .iter()
        .filter(|spec| {
            let noun = spec.cli.noun_path;
            noun.len() <= path.len() && noun.iter().zip(path).all(|(a, b)| *a == b.as_str())
        })
        .max_by_key(|spec| spec.cli.noun_path.len())
        .map(|spec| (spec, spec.cli.noun_path.len()))
}

/// Whether `prefix` is a proper prefix of some op's noun path.
pub(crate) fn is_noun_prefix(prefix: &[String]) -> bool {
    all().iter().any(|spec| {
        let noun = spec.cli.noun_path;
        prefix.len() < noun.len() && noun.iter().zip(prefix).all(|(a, b)| *a == b.as_str())
    })
}

/// The words that can follow the longest known noun prefix of `path` (empty when even the first
/// word is unknown), for the "unknown command" hint.
pub(crate) fn nearest_children(path: &[String]) -> Vec<&'static str> {
    let mut depth = path.len();
    while depth > 0 {
        let prefix = path.get(..depth).unwrap_or_default();
        let children: BTreeSet<&'static str> = all()
            .iter()
            .filter_map(|spec| {
                let noun = spec.cli.noun_path;
                (noun.len() > depth && noun.iter().zip(prefix).all(|(a, b)| *a == b.as_str()))
                    .then(|| noun.get(depth).copied())
                    .flatten()
            })
            .collect();
        if !children.is_empty() {
            return children.into_iter().collect();
        }
        depth -= 1;
    }
    Vec::new()
}

/// One flag an op accepts, with its `--<name>-file` spellings.
struct Flag {
    name: String,
    param: &'static str,
    kind: FlagKind,
    file_names: Vec<String>,
}

fn kebab(param: &str) -> String {
    param.replace('_', "-")
}

/// The registry flags, plus `--<positional>` as an alias when the positional param has no flag.
fn flag_table(spec: &OperationSpec) -> Vec<Flag> {
    let mut table: Vec<Flag> = spec
        .cli
        .flags
        .iter()
        .map(|f| {
            let mut file_names = Vec::new();
            if f.file_variant && f.kind != FlagKind::Bool {
                file_names.push(format!("{}-file", f.flag));
                let by_param = format!("--{}-file", kebab(f.param));
                if !file_names.contains(&by_param) {
                    file_names.push(by_param);
                }
            }
            Flag {
                name: f.flag.to_owned(),
                param: f.param,
                kind: f.kind,
                file_names,
            }
        })
        .collect();
    if let Some(p) = spec.cli.positional
        && !table.iter().any(|f| f.param == p)
    {
        table.push(Flag {
            name: format!("--{}", kebab(p)),
            param: p,
            kind: FlagKind::Str,
            file_names: Vec::new(),
        });
    }
    table
}

/// `Some(true)` if `flag` (a long flag with its `--`) takes a value for `spec`, `Some(false)` if
/// it is a plain switch, `None` if the op has no such flag.
pub(crate) fn flag_takes_value(spec: &OperationSpec, flag: &str) -> Option<bool> {
    flag_table(spec).iter().find_map(|f| {
        if f.name == flag {
            Some(f.kind != FlagKind::Bool)
        } else if f.file_names.iter().any(|n| n == flag) {
            Some(true)
        } else {
            None
        }
    })
}

#[derive(Debug, Clone, PartialEq)]
enum Source {
    Switch,
    Inline(String),
    File(String),
}

fn unknown_flag(flag: &str) -> ParseError {
    ParseError::arg(format!("unknown flag: {}", clip(flag)), &clip(flag))
}

fn invalid(e: ParseError, flag: &str) -> ParseError {
    ParseError {
        message: format!("{flag}: {}", e.message),
        details: e.details,
    }
    .with("arg", flag)
}

fn int_param(schema: &Value, param: &str) -> bool {
    schema["properties"][param]["type"] == "integer"
}

fn required_param(schema: &Value, param: &str) -> bool {
    schema["required"]
        .as_array()
        .is_some_and(|r| r.iter().any(|v| v == param))
}

fn parse_int(text: &str, flag: &str) -> Result<Value, ParseError> {
    text.trim()
        .parse::<i64>()
        .map(Value::from)
        .map_err(|_| ParseError::arg(format!("{flag} takes a whole number"), flag))
}

fn csv_list(text: &str) -> Value {
    Value::Array(
        text.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| Value::String(s.to_owned()))
            .collect(),
    )
}

/// A flag value in text form (inline, or the content of a file variant) as the param's JSON.
fn from_text(kind: FlagKind, as_int: bool, flag: &str, text: &str) -> Result<Value, ParseError> {
    match kind {
        FlagKind::Str if as_int => parse_int(text, flag),
        FlagKind::Str => Ok(Value::String(text.to_owned())),
        FlagKind::Int => parse_int(text, flag),
        FlagKind::Json => parse_json(text).map_err(|e| invalid(e, flag)),
        FlagKind::CsvList => Ok(csv_list(text)),
        FlagKind::Bool | FlagKind::KeyJsonPairs => Ok(Value::Bool(true)),
    }
}

fn merge_pair(map: &mut Map<String, Value>, flag: &str, pair: &str) -> Result<(), ParseError> {
    let Some((id, json)) = pair.split_once('=') else {
        return Err(ParseError::arg(format!("{flag} takes <id>=<json>"), flag));
    };
    if id.is_empty() {
        return Err(ParseError::arg(
            format!("{flag} needs a non-empty id"),
            flag,
        ));
    }
    let value = parse_json(json).map_err(|e| invalid(e, flag))?;
    if map.insert(id.to_owned(), value).is_some() {
        return Err(
            ParseError::arg(format!("{flag}: duplicate id {}", clip(id)), flag)
                .with("id", clip(id)),
        );
    }
    Ok(())
}

/// Binds the tokens after the command path into the op's params object. `rest` is flags and the
/// positional in any order; everything after a bare `--` is positional. Stdin is read only for
/// `-` file arguments, and two of those fail before anything is read.
pub(crate) fn bind(
    spec: &OperationSpec,
    rest: &[OsString],
    inputs: &mut Inputs<'_>,
) -> Result<Value, ParseError> {
    let table = flag_table(spec);
    let schema = spec.params_schema_json();
    let mut positionals: Vec<String> = Vec::new();
    let mut given: Vec<Vec<Source>> = table.iter().map(|_| Vec::new()).collect();

    let mut tokens = rest.iter().map(OsString::as_os_str);
    let mut only_positional = false;
    while let Some(token) = tokens.next() {
        let token = token
            .to_str()
            .ok_or_else(|| ParseError::new("argument is not valid UTF-8"))?;
        if only_positional || token == "-" || !token.starts_with('-') {
            positionals.push(token.to_owned());
            continue;
        }
        if token == "--" {
            only_positional = true;
            continue;
        }
        let Some(long) = token.strip_prefix("--") else {
            return Err(unknown_flag(token));
        };
        let (name, inline) = match long.split_once('=') {
            Some((n, v)) => (format!("--{n}"), Some(v.to_owned())),
            None => (token.to_owned(), None),
        };
        let Some((idx, flag, is_file)) = table.iter().enumerate().find_map(|(i, f)| {
            if f.name == name {
                Some((i, f, false))
            } else {
                f.file_names.contains(&name).then_some((i, f, true))
            }
        }) else {
            return Err(unknown_flag(&name));
        };
        let source = if !is_file && flag.kind == FlagKind::Bool {
            if inline.is_some() {
                return Err(ParseError::arg(format!("{name} takes no value"), &name));
            }
            Source::Switch
        } else {
            let value = match inline {
                Some(v) => v,
                None => take_value(&mut tokens, &name)?,
            };
            if is_file {
                Source::File(value)
            } else {
                Source::Inline(value)
            }
        };
        if let Some(slot) = given.get_mut(idx) {
            slot.push(source);
        }
    }

    // Shape checks first, so no usage error can follow a read of stdin or a file.
    for (flag, sources) in table.iter().zip(&given) {
        check_repeats(flag, sources)?;
    }
    let dashes = given
        .iter()
        .flatten()
        .filter(|s| matches!(s, Source::File(p) if p == "-"))
        .count();
    if dashes > 1 {
        return Err(ParseError::new(
            "stdin (-) can be used by at most one argument",
        ));
    }
    let positional = take_positional(spec, positionals)?;

    let mut params = Map::new();
    let mut default_filename = None;
    for (flag, sources) in table.iter().zip(given) {
        for source in sources {
            resolve(
                spec,
                &schema,
                flag,
                source,
                inputs,
                &mut params,
                &mut default_filename,
            )?;
        }
    }
    if let Some((param, text)) = positional {
        if params.contains_key(param) {
            return Err(
                ParseError::new(format!("give <{param}> or --{}, not both", kebab(param)))
                    .with("param", param),
            );
        }
        let value = if int_param(&schema, param) {
            parse_int(&text, &format!("<{param}>"))?
        } else {
            Value::String(text)
        };
        params.insert(param.to_owned(), value);
    } else if let Some(p) = spec.cli.positional
        && !params.contains_key(p)
        && required_param(&schema, p)
    {
        return Err(
            ParseError::new(format!("missing <{p}> (or --{})", kebab(p))).with("missing", p),
        );
    }
    if let Some(name) = default_filename
        && !params.contains_key("filename")
    {
        params.insert("filename".to_owned(), Value::String(name));
    }
    Ok(Value::Object(params))
}

fn take_value<'a>(
    tokens: &mut impl Iterator<Item = &'a OsStr>,
    flag: &str,
) -> Result<String, ParseError> {
    let value = tokens
        .next()
        .ok_or_else(|| ParseError::arg(format!("missing value for {flag}"), flag))?;
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| ParseError::new("argument is not valid UTF-8"))
}

fn check_repeats(flag: &Flag, sources: &[Source]) -> Result<(), ParseError> {
    let files = sources
        .iter()
        .filter(|s| matches!(s, Source::File(_)))
        .count();
    let inline = sources.len() - files;
    if files > 0 && inline > 0 {
        let file_name = flag.file_names.first().map_or("", String::as_str);
        return Err(ParseError::arg(
            format!("give {} or {file_name}, not both", flag.name),
            &flag.name,
        ));
    }
    let repeatable_inline = flag.kind == FlagKind::KeyJsonPairs;
    if files > 1 || (inline > 1 && !repeatable_inline) {
        return Err(ParseError::arg(
            format!("{} given more than once", flag.name),
            &flag.name,
        ));
    }
    Ok(())
}

/// The positional value with its param name, or `None` when none was given.
fn take_positional(
    spec: &OperationSpec,
    positionals: Vec<String>,
) -> Result<Option<(&'static str, String)>, ParseError> {
    let allowed = usize::from(spec.cli.positional.is_some());
    if let Some(extra) = positionals.get(allowed) {
        return Err(ParseError::arg(
            format!("unexpected argument: {}", clip(extra)),
            &clip(extra),
        ));
    }
    Ok(spec.cli.positional.zip(positionals.into_iter().next()))
}

fn resolve(
    spec: &OperationSpec,
    schema: &Value,
    flag: &Flag,
    source: Source,
    inputs: &mut Inputs<'_>,
    params: &mut Map<String, Value>,
    default_filename: &mut Option<String>,
) -> Result<(), ParseError> {
    let name = flag.name.as_str();
    let as_int = int_param(schema, flag.param);
    let value = match (source, flag.kind) {
        (Source::Switch, _) => Value::Bool(true),
        (Source::Inline(text), FlagKind::KeyJsonPairs) => {
            let entry = params
                .entry(flag.param.to_owned())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(map) = entry {
                merge_pair(map, name, &text)?;
            }
            return Ok(());
        }
        (Source::Inline(text), kind) => from_text(kind, as_int, name, &text)?,
        (Source::File(path), kind) => {
            let is_upload = flag.param == "content_base64" && spec.caps.upload_max_bytes.is_some();
            if is_upload {
                let cap = spec
                    .caps
                    .upload_max_bytes
                    .and_then(|c| usize::try_from(c).ok())
                    .unwrap_or(0);
                let bytes =
                    read_arg_bytes(OsStr::new(&path), inputs, cap).map_err(|e| invalid(e, name))?;
                if path != "-" {
                    *default_filename = std::path::Path::new(&path)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned());
                }
                Value::String(base64(&bytes))
            } else {
                let text =
                    read_arg_source(OsStr::new(&path), inputs).map_err(|e| invalid(e, name))?;
                match kind {
                    FlagKind::KeyJsonPairs => {
                        match parse_json(&text).map_err(|e| invalid(e, name))? {
                            Value::Object(map) => Value::Object(map),
                            _ => {
                                return Err(ParseError::arg(
                                    format!("{name}: the file must hold a JSON object"),
                                    name,
                                ));
                            }
                        }
                    }
                    other => from_text(other, as_int, name, &text)?,
                }
            }
        }
    };
    params.insert(flag.param.to_owned(), value);
    Ok(())
}

/// Test helper: the argv (noun path, flags, then `--` and the positional) that `bind` turns back
/// into `params`; `false` booleans are dropped (a switch is absent, never false). `None` when
/// `params` has a key the binding cannot express.
#[cfg(test)]
pub(crate) fn render_argv(spec: &OperationSpec, params: &Value) -> Option<Vec<String>> {
    let table = flag_table(spec);
    let schema = spec.params_schema_json();
    let mut argv: Vec<String> = spec.cli.noun_path.iter().map(|s| (*s).to_owned()).collect();
    let mut positional = None;
    for (key, value) in params.as_object()? {
        let text = |v: &Value| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) if int_param(&schema, key) => Some(n.to_string()),
            _ => None,
        };
        if Some(key.as_str()) == spec.cli.positional {
            positional = Some(text(value)?);
            continue;
        }
        let flag = table.iter().find(|f| f.param == key)?;
        let name = &flag.name;
        match flag.kind {
            FlagKind::Bool => match value {
                Value::Bool(true) => argv.push(name.clone()),
                Value::Bool(false) => {}
                _ => return None,
            },
            FlagKind::Int => argv.push(format!("{name}={}", value.as_i64()?)),
            FlagKind::Str => argv.push(format!("{name}={}", text(value)?)),
            FlagKind::Json => argv.push(format!("{name}={value}")),
            FlagKind::CsvList => {
                let items: Option<Vec<&str>> = value
                    .as_array()?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .filter(|s| !s.is_empty() && !s.contains(',') && s.trim() == *s)
                    })
                    .collect();
                argv.push(format!("{name}={}", items?.join(",")));
            }
            FlagKind::KeyJsonPairs => {
                let object = value.as_object().filter(|o| !o.is_empty())?;
                for (id, v) in object {
                    if id.is_empty() || id.contains('=') {
                        return None;
                    }
                    argv.push(format!("{name}={id}={v}"));
                }
            }
        }
    }
    if let Some(p) = positional {
        argv.push("--".to_owned());
        argv.push(p);
    }
    Some(argv)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use atlas_duck_registry::get;
    use serde_json::json;

    use super::*;
    use crate::input::MAX_INPUT_BYTES;

    struct NoRead;

    impl std::io::Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("stdin was read");
        }
    }

    fn spec(id: &str) -> &'static OperationSpec {
        get(id).unwrap_or_else(|| panic!("no op {id}"))
    }

    fn os(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn bound(id: &str, list: &[&str]) -> Result<Value, ParseError> {
        bind(spec(id), &os(list), &mut Inputs::new(NoRead))
    }

    fn ok(id: &str, list: &[&str]) -> Value {
        match bound(id, list) {
            Ok(v) => v,
            Err(e) => panic!("bind {list:?} failed: {}", e.message),
        }
    }

    fn err(id: &str, list: &[&str]) -> ParseError {
        match bound(id, list) {
            Ok(v) => panic!("bind {list:?} should fail, got {v}"),
            Err(e) => e,
        }
    }

    fn strip_false(v: &Value) -> Value {
        match v {
            Value::Object(m) => Value::Object(
                m.iter()
                    .filter(|(_, v)| **v != Value::Bool(false))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    #[test]
    fn u33_every_op_roundtrips_example_through_argv() {
        assert_eq!(all().len(), 46);
        for spec in all() {
            let example = spec.params_schema_json()["examples"][0].clone();
            let Some(argv) = render_argv(spec, &example) else {
                panic!("{}: example {example} is not expressible as argv", spec.id);
            };
            let Some((found, used)) = find_op(&argv) else {
                panic!("{}: find_op failed for {argv:?}", spec.id);
            };
            assert_eq!(found.id, spec.id, "{argv:?}");
            let rest: Vec<OsString> = argv.iter().skip(used).map(OsString::from).collect();
            let got = bind(found, &rest, &mut Inputs::new(NoRead))
                .unwrap_or_else(|e| panic!("{}: bind {argv:?}: {}", spec.id, e.message));
            assert_eq!(got, strip_false(&example), "{}: {argv:?}", spec.id);
        }
    }

    #[test]
    fn u33_flag_kinds_parse() {
        let v = ok("jira.search", &["--jql=p", "--max", "50"]);
        assert_eq!(v["max"], json!(50));
        assert_eq!(
            err("jira.search", &["--max=5x", "p"]).details["arg"],
            json!("--max")
        );
        assert_eq!(
            ok("jira.issue.get", &["--comments", "ABC-1"])["comments"],
            json!(true)
        );
        assert_eq!(
            err("jira.issue.get", &["--comments=true", "ABC-1"]).details["arg"],
            json!("--comments")
        );
        let v = ok(
            "jira.issue.edit",
            &["ABC-1", "--update", r#"{"labels":[{"add":"x"}]}"#],
        );
        assert_eq!(v["update"], json!({"labels":[{"add":"x"}]}));
        let v = ok(
            "jira.issue.create",
            &[
                "--field",
                r#"customfield_10200={"value":"Platform"}"#,
                "--field=customfield_1={\"a\":1}",
            ],
        );
        assert_eq!(
            v["fields"],
            json!({"customfield_10200":{"value":"Platform"},"customfield_1":{"a":1}})
        );
        let v = ok("jira.search", &["--fields", "a, b,,c", "p"]);
        assert_eq!(v["fields"], json!(["a", "b", "c"]));
        let e = err("jira.issue.create", &["--field", "x=1", "--field", "x=2"]);
        assert!(e.message.contains("duplicate id"));
        assert!(
            err("jira.issue.create", &["--field", "nojson"])
                .message
                .contains("<id>=<json>")
        );
        assert!(
            err("jira.issue.create", &["--field", "x={"])
                .message
                .contains("invalid JSON")
        );
        // A value may itself start with dashes.
        let v = ok("jira.issue.create", &["--summary", "--not-a-flag"]);
        assert_eq!(v["summary"], json!("--not-a-flag"));
        // Positional-only tokens after `--`.
        assert_eq!(
            ok("jira.issue.get", &["--", "ABC-1"])["key"],
            json!("ABC-1")
        );
    }

    #[test]
    fn integer_positional_is_a_number() {
        let v = ok("jira.sprint.issues", &["42"]);
        assert_eq!(v["id"], json!(42));
        assert!(
            err("jira.sprint.issues", &["x"])
                .message
                .contains("whole number")
        );
    }

    #[test]
    fn u33_positional_or_flag_not_both() {
        assert_eq!(
            ok("jira.search", &["project=A"]),
            ok("jira.search", &["--jql", "project=A"])
        );
        let e = err("jira.search", &["--jql", "a", "b"]);
        assert!(e.message.contains("not both"), "{}", e.message);
        let e = err("jira.search", &[]);
        assert_eq!(e.details.get("missing"), Some(&json!("jql")));
        assert!(e.message.contains("jql"));
        assert!(
            err("jira.search", &["a", "b"])
                .message
                .contains("unexpected")
        );
        assert!(err("jira.myself", &["x"]).message.contains("unexpected"));
        assert!(
            err("jira.search", &["--nope", "a"])
                .details
                .contains_key("arg")
        );
        assert!(err("jira.search", &["a", "-x"]).details.contains_key("arg"));
        assert!(
            err("jira.search", &["--max"])
                .message
                .contains("missing value")
        );
        assert!(
            err("jira.search", &["a", "--max", "1", "--max", "2"])
                .message
                .contains("more than once")
        );
    }

    fn with_files(
        stdin: &'static [u8],
        files: &[(&str, &[u8])],
        id: &str,
        args: impl FnOnce(&std::path::Path) -> Vec<String>,
    ) -> (Result<Value, ParseError>, bool) {
        let dir = tempfile::tempdir().expect("tempdir");
        for (name, content) in files {
            std::fs::write(dir.path().join(name), content).expect("write");
        }
        let list = args(dir.path());
        let rest: Vec<OsString> = list.iter().map(OsString::from).collect();
        let mut inputs = Inputs::new(Cursor::new(stdin));
        let result = bind(spec(id), &rest, &mut inputs);
        (result, inputs.dash_used)
    }

    fn path(dir: &std::path::Path, name: &str) -> String {
        dir.join(name).to_string_lossy().into_owned()
    }

    #[test]
    fn u33_file_variants_read_content() {
        let (v, used) = with_files(
            b"",
            &[
                ("d.md", b"# Title\nbody"),
                ("f.json", br#"{"labels":["a"]}"#),
            ],
            "jira.issue.create",
            |d| {
                vec![
                    "--description-file".into(),
                    path(d, "d.md"),
                    "--fields-file".into(),
                    path(d, "f.json"),
                ]
            },
        );
        let v = v.expect("bound");
        assert_eq!(v["description"], json!("# Title\nbody"));
        assert_eq!(v["fields"], json!({"labels":["a"]}));
        assert!(!used);
        // The registry's own spelling works too.
        let (v, _) = with_files(
            b"",
            &[("f.json", br#"{"a":1}"#)],
            "jira.issue.create",
            |d| vec!["--field-file".into(), path(d, "f.json")],
        );
        assert_eq!(v.expect("bound")["fields"], json!({"a":1}));
        // A Json-kind file is parsed.
        let (v, _) = with_files(
            b"",
            &[("u.json", br#"{"x":[1]}"#)],
            "jira.issue.edit",
            |d| vec!["ABC-1".into(), "--update-file".into(), path(d, "u.json")],
        );
        assert_eq!(v.expect("bound")["update"], json!({"x":[1]}));
        // Inline and file together, and a fields file that is not an object.
        let (v, _) = with_files(b"", &[("d.md", b"x")], "jira.issue.create", |d| {
            vec![
                "--description".into(),
                "a".into(),
                "--description-file".into(),
                path(d, "d.md"),
            ]
        });
        assert!(v.expect_err("both").message.contains("not both"));
        let (v, _) = with_files(b"", &[("f.json", b"[1]")], "jira.issue.create", |d| {
            vec!["--fields-file".into(), path(d, "f.json")]
        });
        assert!(v.expect_err("array").message.contains("JSON object"));
        let (v, _) = with_files(
            b"",
            &[("f.json", br#"{"a":1}"#)],
            "jira.issue.create",
            |d| {
                vec![
                    "--field".into(),
                    "b=1".into(),
                    "--fields-file".into(),
                    path(d, "f.json"),
                ]
            },
        );
        assert!(v.expect_err("both").message.contains("not both"));
    }

    #[test]
    fn x08_single_dash_only() {
        let (v, used) = with_files(b"data", &[], "jira.issue.create", |_| {
            vec![
                "--description-file".into(),
                "-".into(),
                "--fields-file".into(),
                "-".into(),
            ]
        });
        assert!(v.expect_err("two dashes").message.contains("at most one"));
        assert!(!used, "stdin must not be read");
        // One dash reads stdin.
        let (v, used) = with_files(b"\xEF\xBB\xBFfrom stdin", &[], "jira.issue.create", |_| {
            vec!["--description-file".into(), "-".into()]
        });
        assert_eq!(v.expect("bound")["description"], json!("from stdin"));
        assert!(used);
    }

    #[test]
    fn stdin_never_read_without_dash() {
        // `NoRead` panics if touched.
        ok(
            "jira.issue.create",
            &["--summary", "s", "--description", "d"],
        );
    }

    #[test]
    fn invalid_utf8_file_is_usage_with_offset() {
        let (v, _) = with_files(b"", &[("d.md", b"ab\xffcd")], "jira.issue.create", |d| {
            vec!["--description-file".into(), path(d, "d.md")]
        });
        let e = v.expect_err("invalid");
        assert_eq!(e.details.get("byte_offset"), Some(&json!(2)));
        assert_eq!(e.details.get("arg"), Some(&json!("--description")));
    }

    #[test]
    fn large_integer_passed_through() {
        let text = r#"{"key":"A-1","x":9007199254740993}"#;
        let parsed = parse_json(text).expect("json");
        assert_eq!(parsed.to_string(), text);
        let v = ok(
            "jira.issue.edit",
            &["A-1", "--update", r#"{"n":9007199254740993}"#],
        );
        assert!(v.to_string().contains("9007199254740993"));
    }

    #[test]
    fn attachment_upload_reads_bytes_base64() {
        let id = "confluence.attachment.upload";
        let (v, _) = with_files(b"", &[("x.bin", &[0u8, 1, 2, 255, 254])], id, |d| {
            vec![
                "123".into(),
                "--content-base64-file".into(),
                path(d, "x.bin"),
            ]
        });
        let v = v.expect("bound");
        assert_eq!(v["content_base64"], json!(base64(&[0, 1, 2, 255, 254])));
        assert_eq!(v["filename"], json!("x.bin"));
        assert_eq!(v["id"], json!("123"));
        // An explicit filename wins.
        let (v, _) = with_files(b"", &[("x.bin", b"a")], id, |d| {
            vec![
                "123".into(),
                "--filename".into(),
                "n.txt".into(),
                "--content-base64-file".into(),
                path(d, "x.bin"),
            ]
        });
        assert_eq!(v.expect("bound")["filename"], json!("n.txt"));
        // Over 10 MiB is a usage error and the file is not read past the cap + 1.
        let cap = 10 * 1024 * 1024;
        let (v, _) = with_files(b"", &[], id, |d| {
            let p = d.join("big.bin");
            std::fs::write(&p, vec![7u8; cap + 1]).expect("write");
            vec![
                "123".into(),
                "--content-base64-file".into(),
                p.to_string_lossy().into_owned(),
            ]
        });
        let e = v.expect_err("too big");
        assert_eq!(e.details.get("limit_bytes"), Some(&json!(cap)));
        // Exactly at the cap is fine.
        let (v, _) = with_files(b"", &[], id, |d| {
            let p = d.join("ok.bin");
            std::fs::write(&p, vec![7u8; cap]).expect("write");
            vec![
                "123".into(),
                "--content-base64-file".into(),
                p.to_string_lossy().into_owned(),
            ]
        });
        assert!(v.is_ok());
        assert!(MAX_INPUT_BYTES > cap);
    }

    #[test]
    fn nearest_children_lists_the_next_level() {
        let children = nearest_children(&["jira".to_owned(), "nope".to_owned()]);
        assert!(
            children.contains(&"issue") && children.contains(&"search"),
            "{children:?}"
        );
        assert!(nearest_children(&["nope".to_owned()]).is_empty());
        let issue = nearest_children(&["jira".to_owned(), "issue".to_owned(), "x".to_owned()]);
        assert!(
            issue.contains(&"get") && issue.contains(&"create"),
            "{issue:?}"
        );
    }
}
