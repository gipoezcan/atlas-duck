//! Escaping for Confluence storage (XHTML) output (spec §7.6, plan PD-96).
//!
//! Only `&`, `<` and `>` are escaped in text, and `"` as well in attribute values, each as a
//! predefined XML entity; no numeric reference and no named HTML entity is ever written.
//! `>` is escaped although XML allows it raw, so text can never hold `]]>` (which XML forbids
//! outside CDATA). Characters XML 1.0 forbids (U+0000–U+001F except TAB, LF and CR, U+FFFE,
//! U+FFFF; lone surrogates cannot occur in a `&str`) become U+FFFD everywhere, CDATA included,
//! so the output is always well-formed storage.

/// The replacement for a character XML 1.0 forbids.
const REPLACEMENT: char = '\u{FFFD}';

/// Whether `c` is allowed in XML 1.0 (the `Char` production).
pub(crate) fn xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

/// `c`, or U+FFFD when XML 1.0 forbids it.
pub(crate) fn valid(c: char) -> char {
    if xml_char(c) { c } else { REPLACEMENT }
}

/// `s` as XML text content.
pub(crate) fn text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    push_text(&mut out, s);
    out
}

/// `s` as a double-quoted XML attribute value.
pub(crate) fn attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("&quot;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(valid(c)),
        }
    }
    out
}

/// Appends `s` as XML text content.
pub(crate) fn push_text(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(valid(c)),
        }
    }
}

/// Appends `body` as one or more CDATA sections: every `]]>` is split as `]]]]><![CDATA[>`
/// (§7.6), and forbidden characters become U+FFFD.
pub(crate) fn push_cdata(out: &mut String, body: &str) {
    out.push_str("<![CDATA[");
    let clean: String = body.chars().map(valid).collect();
    out.push_str(&clean.replace("]]>", "]]]]><![CDATA[>"));
    out.push_str("]]>");
}
