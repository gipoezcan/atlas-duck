//! Front matter of a guide page (PD-322): flat `key: value` lines between two `---` lines.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Desktop,
    Server,
    Both,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontMatter {
    pub id: String,
    pub title: String,
    pub mode: Mode,
    pub order: i64,
}

/// `[a-z0-9]+(-[a-z0-9]+)*`: page ids and heading anchors.
pub fn is_kebab(s: &str) -> bool {
    !s.is_empty()
        && s.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// Splits `text` into its front matter and the Markdown body (everything after the closing `---`
/// line). Unknown, duplicate and missing keys are errors.
pub fn parse(text: &str) -> Result<(FrontMatter, &str), String> {
    let Some(rest) = text.strip_prefix("---\n") else {
        return Err("the file does not start with a `---` front matter line".into());
    };
    let mut offset = 0;
    let mut close = None;
    for line in rest.split_inclusive('\n') {
        if line.trim_end_matches('\n') == "---" {
            close = Some((offset, offset + line.len()));
            break;
        }
        offset += line.len();
    }
    let Some((head_end, body_start)) = close else {
        return Err("the front matter has no closing `---` line".into());
    };

    let (mut id, mut title, mut mode, mut order) = (None, None, None, None);
    for line in rest[..head_end].lines() {
        let Some((key, value)) = line.split_once(':') else {
            return Err(format!("front matter line `{line}` is not `key: value`"));
        };
        let value = value.trim();
        let slot_taken = match key {
            "id" => id.replace(value.to_string()).is_some(),
            "title" => title.replace(value.to_string()).is_some(),
            "mode" => mode.replace(value.to_string()).is_some(),
            "order" => order.replace(value.to_string()).is_some(),
            _ => return Err(format!("unknown front matter key `{key}`")),
        };
        if slot_taken {
            return Err(format!("front matter key `{key}` appears twice"));
        }
    }
    let need = |v: Option<String>, key: &str| match v {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("front matter key `{key}` is missing or empty")),
    };
    let id = need(id, "id")?;
    if !is_kebab(&id) {
        return Err(format!(
            "front matter id `{id}` is not kebab-case ([a-z0-9-])"
        ));
    }
    let mode = match need(mode, "mode")?.as_str() {
        "desktop" => Mode::Desktop,
        "server" => Mode::Server,
        "both" => Mode::Both,
        other => {
            return Err(format!(
                "front matter mode `{other}` is not desktop, server or both"
            ));
        }
    };
    let order_text = need(order, "order")?;
    let order = order_text
        .parse::<i64>()
        .map_err(|_| format!("front matter order `{order_text}` is not an integer"))?;
    let fm = FrontMatter {
        id,
        title: need(title, "title")?,
        mode,
        order,
    };
    Ok((fm, &rest[body_start..]))
}
