//! §7.5 `max` caps, the §7.3 move limit and the attachment size cap.

use atlas_duck_registry::OperationSpec;
use serde_json::Value;

use super::{MOVE_LIMIT_HINT, ValidateCtx, ValidationError, invalid};

/// Decoded size of a base64 string (padding ignored): three bytes per four data characters.
fn decoded_len(encoded: &str) -> u64 {
    let data = encoded.trim_end_matches('=').len() as u64;
    data / 4 * 3 + (data % 4) * 3 / 4
}

/// The `issues` param of a move op; a size check only, the schema owns the shape.
pub(super) fn move_limit(spec: &OperationSpec, params: &Value) -> Result<(), ValidationError> {
    let Some(limit) = spec.caps.move_limit else {
        return Ok(());
    };
    let count = params
        .get("issues")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if count as u64 > u64::from(limit) {
        let mut err = invalid("issues", MOVE_LIMIT_HINT, None);
        err.details.insert("limit".to_owned(), Value::from(limit));
        return Err(err);
    }
    Ok(())
}

pub(super) fn upload_size(spec: &OperationSpec, params: &Value) -> Result<(), ValidationError> {
    let Some(limit) = spec.caps.upload_max_bytes else {
        return Ok(());
    };
    let size = params
        .get("content_base64")
        .and_then(Value::as_str)
        .map_or(0, decoded_len);
    if size > limit {
        let mut err = invalid("content_base64", "attachment is above the size limit", None);
        err.details
            .insert("limit_bytes".to_owned(), Value::from(limit));
        return Err(err);
    }
    Ok(())
}

/// `(effective max, clamped)`. An absent `max` takes the op default (itself bounded by the hard
/// cap); a larger one is clamped for CLI/MCP and rejected inside scripts (§7.5).
pub(super) fn effective_max(
    spec: &OperationSpec,
    params: &Value,
    ctx: &ValidateCtx<'_>,
) -> Result<(Option<u32>, bool), ValidationError> {
    let Some(cap) = spec.caps.max else {
        return Ok((None, false));
    };
    let hard = if cap.configurable {
        ctx.caps
            .hard_caps
            .get(spec.id)
            .copied()
            .unwrap_or(cap.hard_cap_default)
    } else {
        cap.hard_cap_default
    };
    let Some(raw) = params.get(cap.param) else {
        return Ok((Some(cap.default.min(hard)), false));
    };
    let Some(requested) = positive_integer(raw) else {
        return Err(invalid(cap.param, "must be a positive integer", None));
    };
    if let Ok(within) = u32::try_from(requested)
        && within <= hard
    {
        return Ok((Some(within), false));
    }
    if ctx.for_script {
        let mut err = invalid(cap.param, "above the hard cap", None);
        err.details.insert("cap".to_owned(), Value::from(hard));
        return Err(err);
    }
    Ok((Some(hard), true))
}

fn positive_integer(value: &Value) -> Option<u64> {
    let number = value.as_number()?;
    if let Some(n) = number.as_u64() {
        return (n >= 1).then_some(n);
    }
    // `5.0` is an integer for JSON Schema; everything else (negative, fractional) is rejected.
    let f = number.as_f64()?;
    (f >= 1.0 && f.fract() == 0.0 && f < 1.8e19).then_some(f as u64)
}
