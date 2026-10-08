//! Static params validation (§2.3 "Validation is static", §5.2 step 1, §5.4 step 1).
//!
//! The first gate on agent-supplied input: nothing is coerced, defaults are never applied
//! (`Validated.params` is the agent's value), and no error echoes more than a bounded,
//! display-escaped excerpt of what the agent sent. The only inputs are the registry spec, the
//! params, the instance's version and the configured caps, so the same call always gives the
//! same answer.

mod caps;
mod field_rules;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

use atlas_duck_ipc::envelope::ErrorCode;
use atlas_duck_ipc::sandbox::ScriptLimits;
use atlas_duck_preview::invisible;
use atlas_duck_registry::{OperationSpec, Version};
use jsonschema::Validator;
use serde::Serialize;
use serde_json::{Map, Value};

pub use field_rules::JIRA_SYSTEM_FIELDS;

/// §7.3 (verbatim): the hint of the move-limit validation error.
pub const MOVE_LIMIT_HINT: &str =
    "split into requests of ≤ 50 issues; moves of disjoint issues can be batch-approved";

/// §9.1 step 2: the largest script source.
pub const MAX_SCRIPT_SOURCE_BYTES: usize = 256 * 1024;
/// §9.1 step 2: the largest `--args` JSON (compact form).
pub const MAX_SCRIPT_ARGS_BYTES: usize = 1024 * 1024;

/// At most this many characters of an agent string are echoed in an error.
const ECHO_MAX_CHARS: usize = 64;

/// What validation may look at besides the params. There is no field that can carry fetched
/// content: validation is static.
#[derive(Debug, Clone, Copy)]
pub struct ValidateCtx<'a> {
    /// `None` = not known yet; the op is treated as available (every v1 `min_version` is at or
    /// below the PAT floor, §7.1).
    pub instance_version: Option<Version>,
    pub caps: &'a EffectiveCaps,
    /// Inside a script an over-cap `max` is an error instead of a clamp (§7.5).
    pub for_script: bool,
}

/// Configured hard caps by op id (Settings, M6); an op without an entry uses the registry default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveCaps {
    pub hard_caps: BTreeMap<&'static str, u32>,
}

#[derive(Clone, PartialEq)]
pub struct Validated {
    /// The agent's params, unchanged.
    pub params: Value,
    /// `Some` for ops with a `max` cap: the value the executor uses.
    pub effective_max: Option<u32>,
    /// The agent asked for more than the hard cap and got the cap (the engine sets
    /// `meta.page.truncated`, §7.5).
    pub truncated_by_clamp: bool,
}

impl fmt::Debug for Validated {
    /// Params never reach a log through `Debug` (§7.7).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Validated")
            .field("params_bytes", &self.params.to_string().len())
            .field("effective_max", &self.effective_max)
            .field("truncated_by_clamp", &self.truncated_by_clamp)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ValidationError {
    pub code: ErrorCode,
    pub message: String,
    pub details: Map<String, Value>,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ValidationError {}

/// An agent string cut to [`ECHO_MAX_CHARS`] and display-escaped (`⟨U+202E⟩`), so an error never
/// carries a bidi control or an unbounded value.
pub(crate) fn echo(text: &str) -> String {
    let mut cut: String = text
        .chars()
        .take(ECHO_MAX_CHARS)
        .map(|c| {
            if matches!(c, '\t' | '\n' | '\r') {
                ' '
            } else {
                c
            }
        })
        .collect();
    if text.chars().nth(ECHO_MAX_CHARS).is_some() {
        cut.push('…');
    }
    invisible::escape_for_display(&cut)
}

/// A `validation` error: `details: {param, message[, value]}`.
pub(crate) fn invalid(param: &str, message: &str, value: Option<&str>) -> ValidationError {
    let mut details = Map::new();
    details.insert("param".to_owned(), Value::from(param));
    if let Some(value) = value {
        details.insert("value".to_owned(), Value::from(echo(value)));
    } else {
        details.insert("message".to_owned(), Value::from(message));
    }
    ValidationError {
        code: ErrorCode::Validation,
        message: if param.is_empty() {
            format!("params: {message}")
        } else {
            format!("params/{param}: {message}")
        },
        details,
    }
}

struct Compiled {
    validator: Validator,
    /// The params schema declares `body_format` (a write that carries a body).
    has_body_format: bool,
}

fn compiled(spec: &OperationSpec) -> Result<&'static Compiled, ValidationError> {
    static CACHE: OnceLock<BTreeMap<&'static str, Result<Compiled, ()>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| {
        atlas_duck_registry::all()
            .iter()
            .map(|op| (op.id, compile(op)))
            .collect()
    });
    match cache.get(spec.id) {
        Some(Ok(compiled)) => Ok(compiled),
        _ => Err(ValidationError {
            code: ErrorCode::Internal,
            message: "operation parameters cannot be validated".to_owned(),
            details: Map::new(),
        }),
    }
}

fn compile(spec: &OperationSpec) -> Result<Compiled, ()> {
    let schema = spec.params_schema_json();
    let validator = jsonschema::validator_for(&schema).map_err(|_| ())?;
    let has_body_format = schema
        .get("properties")
        .and_then(|p| p.get("body_format"))
        .is_some();
    Ok(Compiled {
        validator,
        has_body_format,
    })
}

/// First schema violation as `params/<path>: <keyword>`; never the offending value.
fn schema_error(compiled: &Compiled, params: &Value) -> Option<ValidationError> {
    let error = compiled.validator.validate(params).err()?;
    let keyword = error.kind().keyword();
    let location = error.instance_path().to_string();
    let mut segments = location.split('/').filter(|s| !s.is_empty());
    let mut param = segments.next().map(echo).unwrap_or_default();
    // A missing or unexpected property sits one level below the instance path.
    match error.kind() {
        jsonschema::error::ValidationErrorKind::Required { property } if param.is_empty() => {
            param = property.as_str().map(echo).unwrap_or_default();
        }
        jsonschema::error::ValidationErrorKind::AdditionalProperties { unexpected }
            if param.is_empty() =>
        {
            param = unexpected.first().map(|k| echo(k)).unwrap_or_default();
        }
        _ => {}
    }
    let path = if location.is_empty() {
        param.clone()
    } else {
        echo(location.trim_start_matches('/'))
    };
    let mut details = Map::new();
    if !param.is_empty() {
        details.insert("param".to_owned(), Value::from(param));
    }
    Some(ValidationError {
        code: ErrorCode::Validation,
        message: if path.is_empty() {
            format!("params: {keyword}")
        } else {
            format!("params/{path}: {keyword}")
        },
        details,
    })
}

/// §7.1: below `min_version` the op does not exist; the error carries the registry's version,
/// never the instance's.
fn check_min_version(spec: &OperationSpec, ctx: &ValidateCtx<'_>) -> Result<(), ValidationError> {
    let (Some(min), Some(have)) = (spec.min_version, ctx.instance_version) else {
        return Ok(());
    };
    if have >= min {
        return Ok(());
    }
    let mut details = Map::new();
    details.insert(
        "min_version".to_owned(),
        Value::from(format!("{}.{}.{}", min.major, min.minor, min.patch)),
    );
    Err(ValidationError {
        code: ErrorCode::OpUnsupportedByInstance,
        message: "operation is not supported by this instance".to_owned(),
        details,
    })
}

/// PD-09: markdown conversion is not in this build; an absent `body_format` is `markdown`.
fn check_body_format(
    spec: &OperationSpec,
    compiled: &Compiled,
    params: &Value,
) -> Result<(), ValidationError> {
    if spec.class != atlas_duck_registry::OpClass::Write || !compiled.has_body_format {
        return Ok(());
    }
    let markdown = match params.get("body_format") {
        None => true,
        Some(value) => value.as_str() == Some("markdown"),
    };
    if markdown {
        return Err(invalid(
            "body_format",
            "markdown conversion is not available in this build",
            None,
        ));
    }
    Ok(())
}

/// Validate agent `params` for `spec` (§5.2 step 1 / §5.4 step 1).
pub fn validate(
    spec: &OperationSpec,
    params: &Value,
    ctx: &ValidateCtx<'_>,
) -> Result<Validated, ValidationError> {
    // The move-limit hint is the contract; the schema's `maxItems` only bounds parsing.
    caps::move_limit(spec, params)?;
    let compiled = compiled(spec)?;
    if let Some(error) = schema_error(compiled, params) {
        return Err(error);
    }
    check_min_version(spec, ctx)?;
    field_rules::check(spec, params)?;
    check_body_format(spec, compiled, params)?;
    caps::upload_size(spec, params)?;
    let (effective_max, truncated_by_clamp) = caps::effective_max(spec, params, ctx)?;
    Ok(Validated {
        params: params.clone(),
        effective_max,
        truncated_by_clamp,
    })
}

/// §9.1 step 2, the static part: source ≤ 256 KiB, args ≤ 1 MiB, limits per §9.4.
pub fn validate_script_submit(
    source: &str,
    args: &Value,
    limits: &Value,
) -> Result<ScriptLimits, ValidationError> {
    if source.len() > MAX_SCRIPT_SOURCE_BYTES {
        return Err(invalid("source", "script source is above 256 KiB", None));
    }
    let args_len = serde_json::to_vec(args).map_or(usize::MAX, |bytes| bytes.len());
    if args_len > MAX_SCRIPT_ARGS_BYTES {
        return Err(invalid("args", "script args are above 1 MiB", None));
    }
    validate_script_limits(limits, &ScriptLimits::default())
}

/// `--limits`: known keys, positive integers, never above `ceiling` (the configured defaults,
/// §9.4: agents may only lower). Absent keys keep the ceiling's value.
pub fn validate_script_limits(
    limits: &Value,
    ceiling: &ScriptLimits,
) -> Result<ScriptLimits, ValidationError> {
    let mut out = *ceiling;
    let map = match limits {
        Value::Null => return Ok(out),
        Value::Object(map) => map,
        _ => return Err(invalid("limits", "must be an object", None)),
    };
    for (key, value) in map {
        let (slot, max) = match key.as_str() {
            "timeout_s" => (&mut out.timeout_s, ceiling.timeout_s),
            "heap_mb" => (&mut out.heap_mb, ceiling.heap_mb),
            "process_mb" => (&mut out.process_mb, ceiling.process_mb),
            "max_calls" => (&mut out.max_calls, ceiling.max_calls),
            "max_fetch_mb" => (&mut out.max_fetch_mb, ceiling.max_fetch_mb),
            "max_call_result_mb" => (&mut out.max_call_result_mb, ceiling.max_call_result_mb),
            "max_result_mb" => (&mut out.max_result_mb, ceiling.max_result_mb),
            "max_concurrent_calls" => (&mut out.max_concurrent_calls, ceiling.max_concurrent_calls),
            _ => return Err(invalid("limits", "unknown limits key", None)),
        };
        let param = format!("limits.{key}");
        let Some(wanted) = value.as_u64().filter(|n| *n >= 1) else {
            return Err(invalid(&param, "must be a positive integer", None));
        };
        if wanted > u64::from(max) {
            return Err(invalid(&param, "agents may only lower limits", None));
        }
        *slot = u32::try_from(wanted).unwrap_or(max);
    }
    Ok(out)
}
