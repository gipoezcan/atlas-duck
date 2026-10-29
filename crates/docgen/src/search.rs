//! `search-index.js` and the JSON text helpers (no serde: the crate depends on pulldown-cmark only).

use std::fmt::Write;

/// One searchable section: a page's lead text or the text under one heading.
pub struct Entry {
    pub page: String,
    pub anchor: String,
    pub title: String,
    pub heading: String,
    pub text: String,
    pub href: String,
}

/// A string literal valid as JSON and as a JavaScript string: `"`, `\`, control characters,
/// U+2028/U+2029 (line terminators in older JavaScript) and `<` are escaped.
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' || c == '\u{2028}' || c == '\u{2029}' || c == '<' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `window.ATLAS_HELP_INDEX = [...]` (PD-324): a script, because the desktop CSP forbids `fetch`.
pub fn index_js(entries: &[Entry]) -> String {
    let mut out = String::from("window.ATLAS_HELP_INDEX = [\n");
    for (i, e) in entries.iter().enumerate() {
        let _ = write!(
            out,
            "{{\"page\": {}, \"anchor\": {}, \"title\": {}, \"heading\": {}, \"text\": {}, \"href\": {}}}",
            json_str(&e.page),
            json_str(&e.anchor),
            json_str(&e.title),
            json_str(&e.heading),
            json_str(&e.text),
            json_str(&e.href),
        );
        out.push_str(if i + 1 < entries.len() { ",\n" } else { "\n" });
    }
    out.push_str("];\n");
    out
}

/// The searchable text of a section: whitespace collapsed, cut to about 200 characters.
pub fn snippet(text: &str) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed
        .chars()
        .take(200)
        .collect::<String>()
        .trim_end()
        .to_string()
}
