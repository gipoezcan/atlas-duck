//! The Audit window's payload view (M10 Δ-M10-3, Task 12; §8.10, S-06): a decrypted audit payload
//! as the `srcdoc` of the window's `<iframe sandbox="">`, under the same rules as the preview
//! document (module docs of [`super`]): every key and value is text (display-escaped, whitespace
//! made visible, in `<bdi>`, escapes marked), the PD-67 caps apply ([`DOC_MAX_ROWS`] items per list,
//! [`DOC_MAX_BYTES`] for the body), and the document is [`iframe_document`].
//!
//! A payload of at most [`AUDIT_TREE_MAX_BYTES`] that parses as JSON is a tree (the store writes
//! JCS); anything else, and every page of a larger payload, is the PD-68 Raw display text the
//! command layer projected, in one `<pre>`. A larger payload is never parsed here.

use serde_json::Value;

use super::{DOC_MAX_ROWS, Doc, Frame, Platform, len_u64, raw};
use crate::sanitize::iframe_document;

/// Most bytes of a payload the document shows as a JSON tree: one page of the Audit window's
/// payload view (`audit::PAYLOAD_PAGE_BYTES`; the app asserts the two are equal at compile time);
/// a larger payload is paged as Raw text.
pub const AUDIT_TREE_MAX_BYTES: usize = 256 << 10;

/// What a cap of the payload document left out (the PD-67 note for this window: the Raw text of
/// the payload holds every byte).
pub fn more_in_raw_text(n: u64, unit: &str) -> String {
    format!("{n} more {unit} not shown here; see the Raw text")
}

/// The whole document of one payload of at most [`AUDIT_TREE_MAX_BYTES`]: the JSON tree, or, for
/// bytes that are no JSON (or more than the cap), their display text.
pub fn audit_payload_document(json: &[u8], platform: Platform) -> String {
    let mut doc = Doc::default();
    let parsed = (json.len() <= AUDIT_TREE_MAX_BYTES)
        .then(|| serde_json::from_slice::<Value>(json).ok())
        .flatten();
    match parsed {
        Some(v) => {
            doc.open("ul");
            node(&mut doc, None, &v);
            doc.close("ul");
        }
        None => text_block(&mut doc, &raw::raw_display_last(json, &[]).text),
    }
    finish(doc, platform)
}

/// The document of one page of a payload: `display` is the page's PD-68 projection
/// ([`raw::raw_display`] / [`raw::raw_display_last`]), shown as text.
pub fn audit_payload_page_document(display: &str, platform: Platform) -> String {
    let mut doc = Doc::default();
    text_block(&mut doc, display);
    finish(doc, platform)
}

/// Display text that is already projected (escapes and visible whitespace), in `<pre><code>`.
fn text_block(doc: &mut Doc, shown: &str) {
    doc.open("pre");
    doc.value(shown, Frame::Code);
    doc.close("pre");
}

/// The note for a text cut at the byte budget, then the sandboxed document.
fn finish(mut doc: Doc, platform: Platform) -> String {
    if doc.cut_text > 0 {
        let note = more_in_raw_text(doc.cut_text, "bytes");
        doc.open("p");
        doc.fixed(&note);
        doc.close("p");
    }
    iframe_document(&doc.out, platform)
}

#[derive(Clone, Copy)]
enum Key<'a> {
    Name(&'a str),
    Index(usize),
}

/// One `<li>`: the key (or index), the value or its kind and size, the children in a `<ul>`, at
/// most [`DOC_MAX_ROWS`] of them and none once the budget is used up. The depth is bounded by the
/// JSON parser's recursion limit.
fn node(doc: &mut Doc, key: Option<Key<'_>>, v: &Value) {
    doc.open("li");
    match key {
        Some(Key::Name(k)) => {
            doc.raw_code_text(k);
            doc.fixed(": ");
        }
        Some(Key::Index(i)) => doc.fixed(&format!("[{i}]: ")),
        None => {}
    }
    match v {
        Value::Null => doc.el("code", "null"),
        Value::Bool(b) => doc.el("code", if *b { "true" } else { "false" }),
        Value::Number(n) => doc.raw_code_text(&n.to_string()),
        Value::String(s) => doc.raw_quoted(s),
        Value::Array(items) => {
            doc.fixed(&format!("array, {} items", items.len()));
            if !items.is_empty() {
                doc.open("ul");
                for (i, item) in items.iter().enumerate() {
                    if i >= DOC_MAX_ROWS || doc.full() {
                        more(doc, items.len() - i);
                        break;
                    }
                    node(doc, Some(Key::Index(i)), item);
                }
                doc.close("ul");
            }
        }
        Value::Object(entries) => {
            doc.fixed(&format!("object, {} keys", entries.len()));
            if !entries.is_empty() {
                doc.open("ul");
                for (i, (k, item)) in entries.iter().enumerate() {
                    if i >= DOC_MAX_ROWS || doc.full() {
                        more(doc, entries.len() - i);
                        break;
                    }
                    node(doc, Some(Key::Name(k)), item);
                }
                doc.close("ul");
            }
        }
    }
    doc.close("li");
}

fn more(doc: &mut Doc, n: usize) {
    doc.open("li");
    doc.fixed(&more_in_raw_text(len_u64(n), "items"));
    doc.close("li");
}
