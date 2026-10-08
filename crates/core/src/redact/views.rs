//! §5.3 canonical match form: the one definition used for every-occurrence masking, for "also
//! appears in" and for the release-blocking check.
//!
//! `views` and `canonical_hit` are the plan's code. Plan additions (over-match only, so they can
//! only add hits, never hide one): two more decoders in the same fixpoint, the §6.4 invisible
//! characters removed (`preview::invisible::is_flagged`, context-free) and HTML character
//! references as browsers also read them without the trailing `;` (`&uuml`, `&#252`); a needle
//! is also compared without its invisible characters. JSON escapes are already decoded (the
//! candidate is a parsed `Value`); NFKC and case folding are not part of the form (§5.3).
//!
//! Masking (§5.3 rule 3) works on span-mapped views: every view also records which raw byte
//! range each part of it came from, so a match is replaced by `[REDACTED]` in the raw string and
//! everything around it keeps its original encoding. A match whose ends fall inside one decoded
//! unit (an entity, an escape run, an NFC chunk) cannot be mapped and is never guessed.
//!
//! Inside the engine a value is matched part by part between `[REDACTED]` placeholders
//! ([`Segments`]): the placeholder text is public, so masking a codename `RED` converges. The
//! public `canonical_hit` keeps the plan's whole-value semantics.

use std::collections::BTreeSet;
use std::ops::Range;

use atlas_duck_preview::invisible;
use percent_encoding::percent_decode_str;

use super::REDACTED;

const MAX_ROUNDS: usize = 3;
/// Bound on nested mask passes over one part of a value (each pass masks every match of one view).
const MAX_MASK_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Views {
    pub forms: Vec<String>,
    pub unstable: bool,
}

pub(crate) fn nfc(s: &str) -> String {
    icu_normalizer::ComposingNormalizerBorrowed::new_nfc()
        .normalize(s)
        .into_owned()
}

/// The decoders of §5.3 rule 1 (HTML/XML character references; percent-decoding as UTF-8;
/// percent-decoding with `+` read as a space, a view *within* percent-decoding), then the two plan
/// additions (semicolonless references, invisible characters removed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decoder {
    Html,
    Pct,
    Plus,
    HtmlLenient,
    Invisible,
}

const DECODERS: [Decoder; 5] = [
    Decoder::Html,
    Decoder::Pct,
    Decoder::Plus,
    Decoder::HtmlLenient,
    Decoder::Invisible,
];

fn decode(d: Decoder, v: &str) -> String {
    match d {
        Decoder::Html => html_escape::decode_html_entities(v).into_owned(),
        Decoder::Pct => percent_decode_str(v).decode_utf8_lossy().into_owned(),
        Decoder::Plus => percent_decode_str(&v.replace('+', " "))
            .decode_utf8_lossy()
            .into_owned(),
        Decoder::HtmlLenient => output(v, &html_tokens(v, true)),
        Decoder::Invisible => v.chars().filter(|&c| !flagged(c)).collect(),
    }
}

/// `invisible::is_flagged` with the ASCII answer inlined: C0 controls except `\t`, `\n`, `\r`,
/// and DEL (all `Cc`).
fn flagged(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_control() && !matches!(c, '\t' | '\n' | '\r');
    }
    invisible::is_flagged(c)
}

fn decoders(v: &str) -> [String; 5] {
    DECODERS.map(|d| decode(d, v))
}

/// No decoder changes it and it is already NFC: printable ASCII (plus `\t\n\r`) without `%`,
/// `&` or `+`.
fn is_plain(s: &str) -> bool {
    s.bytes().all(|b| {
        matches!(b, b'\t' | b'\n' | b'\r')
            || ((0x20..0x7f).contains(&b) && !matches!(b, b'%' | b'&' | b'+'))
    })
}

/// Raw form, every decoded view and their NFC forms, iterated to a fixpoint for at most 3 rounds.
/// `unstable` = some view still changes under a decoder after round 3 (fail closed, §5.3).
pub fn views(raw: &str) -> Views {
    if is_plain(raw) {
        return Views {
            forms: vec![raw.to_owned()],
            unstable: false,
        };
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    seen.insert(raw.to_owned());
    seen.insert(nfc(raw));
    let mut frontier: Vec<String> = seen.iter().cloned().collect();
    for _round in 0..MAX_ROUNDS {
        let mut next = Vec::new();
        for v in &frontier {
            for d in decoders(v) {
                if d != *v {
                    for x in [nfc(&d), d] {
                        if seen.insert(x.clone()) {
                            next.push(x);
                        }
                    }
                }
            }
        }
        if next.is_empty() {
            return Views {
                forms: seen.into_iter().collect(),
                unstable: false,
            };
        }
        frontier = next;
    }
    let unstable = frontier.iter().any(|v| decoders(v).iter().any(|d| d != v));
    Views {
        forms: seen.into_iter().collect(),
        unstable,
    }
}

/// True if `needle` (compared in NFC) occurs in the raw value or in any canonical view.
pub fn canonical_hit(value: &str, needle: &str) -> bool {
    match Needle::new(needle) {
        Some(n) => n.hit(value, &views(value)),
        None => false,
    }
}

/// A selected string in the forms it is compared in: raw, NFC, and NFC without invisible
/// characters (plan addition); non-empty and distinct.
#[derive(Clone)]
pub(crate) struct Needle {
    forms: Vec<String>,
}

impl Needle {
    pub(crate) fn new(text: &str) -> Option<Needle> {
        if text.is_empty() {
            return None;
        }
        let n = nfc(text);
        let stripped = decode(Decoder::Invisible, &n);
        let mut forms: Vec<String> = Vec::new();
        for f in [text.to_owned(), n, stripped] {
            if !f.is_empty() && !forms.contains(&f) {
                forms.push(f);
            }
        }
        Some(Needle { forms })
    }

    /// `views` must be `views(value)`.
    fn hit(&self, value: &str, views: &Views) -> bool {
        self.forms.iter().any(|n| value.contains(n.as_str()))
            || views
                .forms
                .iter()
                .any(|f| self.forms.iter().any(|n| f.contains(n.as_str())))
    }

    /// A hit in any part of the value between placeholders (see [`Segments`]).
    pub(crate) fn hit_in(&self, segs: &Segments<'_>) -> bool {
        segs.0.iter().any(|(s, v)| self.hit(s, v))
    }

    /// Occurrences in one value: per part between placeholders, the raw matches of the first
    /// form that has any, else 1 for a canonical hit.
    pub(crate) fn count(&self, value: &str) -> u64 {
        Segments::of(value)
            .0
            .iter()
            .map(|(s, v)| {
                self.forms
                    .iter()
                    .map(|n| s.matches(n.as_str()).count() as u64)
                    .find(|&c| c > 0)
                    .unwrap_or_else(|| u64::from(self.hit(s, v)))
            })
            .sum()
    }
}

/// The parts of a value between `[REDACTED]` placeholders, each with its views. The placeholder
/// text is public, so a needle inside it (a codename `RED`) is no hit and a mask converges.
pub(crate) struct Segments<'a>(Vec<(&'a str, Views)>);

impl<'a> Segments<'a> {
    pub(crate) fn of(value: &'a str) -> Segments<'a> {
        Segments(value.split(REDACTED).map(|s| (s, views(s))).collect())
    }

    pub(crate) fn unstable(&self) -> bool {
        self.0.iter().any(|(_, v)| v.unstable)
    }
}

// ---- span-mapped views ----

/// One decoder output piece over the input: a literal run (copied byte for byte) or a
/// replacement (an escape, a reference, an NFC chunk, a removed invisible character).
enum Tok {
    Lit(Range<usize>),
    Rep(Range<usize>, String),
}

fn output(v: &str, toks: &[Tok]) -> String {
    let mut s = String::with_capacity(v.len());
    for t in toks {
        match t {
            Tok::Lit(r) => s.push_str(&v[r.clone()]),
            Tok::Rep(_, x) => s.push_str(x),
        }
    }
    s
}

fn push_lit(toks: &mut Vec<Tok>, r: Range<usize>) {
    if r.is_empty() {
        return;
    }
    if let Some(Tok::Lit(prev)) = toks.last_mut()
        && prev.end == r.start
    {
        prev.end = r.end;
        return;
    }
    toks.push(Tok::Lit(r));
}

/// HTML character references (`lenient`: also without the trailing `;`, and named references
/// by longest known prefix, as browsers read text).
fn html_tokens(v: &str, lenient: bool) -> Vec<Tok> {
    let b = v.as_bytes();
    let mut toks = Vec::new();
    let mut lit = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'&'
            && let Some((end, s)) = html_ref_at(v, i, lenient)
        {
            push_lit(&mut toks, lit..i);
            toks.push(Tok::Rep(i..end, s));
            i = end;
            lit = end;
            continue;
        }
        i += 1;
    }
    push_lit(&mut toks, lit..b.len());
    toks
}

/// html-escape 0.2.15 keeps only the first code point of the WHATWG entities that expand to two
/// (`&fjlig;` gives `f`, not `fj`). The lenient view decodes the one of them whose expansion is
/// plain text as browsers do; the others add a combining mark to a symbol.
fn named_entity_lenient(name: &[u8]) -> Option<&'static str> {
    if name == b"fjlig" {
        return Some("fj");
    }
    named_entity(name)
}

fn named_entity(name: &[u8]) -> Option<&'static str> {
    html_escape::NAMED_ENTITIES
        .binary_search_by(|(n, _)| (*n).cmp(name))
        .ok()
        .and_then(|i| html_escape::NAMED_ENTITIES.get(i))
        .map(|(_, s)| *s)
}

/// html-escape's numeric rule: a scalar value, C0 controls other than whitespace refused.
fn numeric_char(n: u32) -> Option<char> {
    let c = char::from_u32(n)?;
    match c {
        '\t' | '\n' | '\u{000C}' | '\r' => Some(c),
        '\0'..='\u{001F}' => None,
        _ => Some(c),
    }
}

fn html_ref_at(v: &str, amp: usize, lenient: bool) -> Option<(usize, String)> {
    let b = v.as_bytes();
    let mut p = amp + 1;
    if b.get(p) == Some(&b'#') {
        p += 1;
        let hex = matches!(b.get(p), Some(b'x' | b'X'));
        if hex {
            p += 1;
        }
        let digits = p;
        while p < b.len()
            && (if hex {
                b[p].is_ascii_hexdigit()
            } else {
                b[p].is_ascii_digit()
            })
        {
            p += 1;
        }
        if p == digits {
            return None;
        }
        let semi = b.get(p) == Some(&b';');
        if !semi && !lenient {
            return None;
        }
        let n = u32::from_str_radix(&v[digits..p], if hex { 16 } else { 10 }).ok()?;
        let c = numeric_char(n)?;
        return Some((if semi { p + 1 } else { p }, c.to_string()));
    }
    let name = p;
    while p < b.len() && b[p].is_ascii_alphanumeric() {
        p += 1;
    }
    if p == name {
        return None;
    }
    let lookup = if lenient {
        named_entity_lenient
    } else {
        named_entity
    };
    if b.get(p) == Some(&b';')
        && let Some(s) = lookup(&b[name..p])
    {
        return Some((p + 1, s.to_owned()));
    }
    if !lenient {
        return None;
    }
    (name + 1..=p)
        .rev()
        .find_map(|end| lookup(&b[name..end]).map(|s| (end, s.to_owned())))
}

/// Percent escapes (runs of `%XX` decoded as UTF-8, invalid sequences as U+FFFD exactly as
/// `decode_utf8_lossy` does); `plus`: `+` read as a space.
fn pct_tokens(v: &str, plus: bool) -> Vec<Tok> {
    let b = v.as_bytes();
    let hex = |x: u8| char::from(x).to_digit(16);
    let mut toks = Vec::new();
    let mut lit = 0;
    let mut i = 0;
    while i < b.len() {
        if plus && b[i] == b'+' {
            push_lit(&mut toks, lit..i);
            toks.push(Tok::Rep(i..i + 1, " ".into()));
            i += 1;
            lit = i;
            continue;
        }
        let escape_at = |i: usize| -> Option<u8> {
            if b.get(i) != Some(&b'%') {
                return None;
            }
            let hi = hex(*b.get(i + 1)?)?;
            let lo = hex(*b.get(i + 2)?)?;
            u8::try_from(hi * 16 + lo).ok()
        };
        if escape_at(i).is_none() {
            i += 1;
            continue;
        }
        push_lit(&mut toks, lit..i);
        let run = i;
        let mut bytes = Vec::new();
        while let Some(x) = escape_at(i) {
            bytes.push(x);
            i += 3;
        }
        let mut k = 0;
        for chunk in bytes.utf8_chunks() {
            for c in chunk.valid().chars() {
                let n = c.len_utf8();
                toks.push(Tok::Rep(run + 3 * k..run + 3 * (k + n), c.to_string()));
                k += n;
            }
            let n = chunk.invalid().len();
            if n > 0 {
                toks.push(Tok::Rep(run + 3 * k..run + 3 * (k + n), "\u{FFFD}".into()));
                k += n;
            }
        }
        lit = i;
    }
    push_lit(&mut toks, lit..b.len());
    toks
}

fn invisible_tokens(v: &str) -> Vec<Tok> {
    let mut toks = Vec::new();
    let mut lit = 0;
    for (i, c) in v.char_indices() {
        if flagged(c) {
            push_lit(&mut toks, lit..i);
            toks.push(Tok::Rep(i..i + c.len_utf8(), String::new()));
            lit = i + c.len_utf8();
        }
    }
    push_lit(&mut toks, lit..v.len());
    toks
}

/// NFC per chunk, a chunk ending before every ASCII character: an ASCII character is a starter
/// that no canonical composition takes as its second part, so NFC never crosses that boundary.
/// The caller checks the result against NFC of the whole value.
fn nfc_tokens(v: &str) -> Vec<Tok> {
    let mut toks = Vec::new();
    let mut start = 0;
    let chunk = |toks: &mut Vec<Tok>, r: Range<usize>| {
        let s = &v[r.clone()];
        let n = nfc(s);
        if n == s {
            push_lit(toks, r);
        } else {
            toks.push(Tok::Rep(r, n));
        }
    };
    for (i, c) in v.char_indices() {
        if c.is_ascii() && i > start {
            chunk(&mut toks, start..i);
            start = i;
        }
    }
    if start < v.len() {
        chunk(&mut toks, start..v.len());
    }
    toks
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Xform {
    Dec(Decoder),
    Nfc,
}

fn run(x: Xform, v: &str) -> String {
    match x {
        Xform::Dec(d) => decode(d, v),
        Xform::Nfc => nfc(v),
    }
}

/// Tokens for `x`, or `None` when they do not reproduce the decoder's own output (never guess).
fn tokens(x: Xform, v: &str) -> Option<Vec<Tok>> {
    let toks = match x {
        Xform::Dec(Decoder::Html) => html_tokens(v, false),
        Xform::Dec(Decoder::HtmlLenient) => html_tokens(v, true),
        Xform::Dec(Decoder::Pct) => pct_tokens(v, false),
        Xform::Dec(Decoder::Plus) => pct_tokens(v, true),
        Xform::Dec(Decoder::Invisible) => invisible_tokens(v),
        Xform::Nfc => nfc_tokens(v),
    };
    (output(v, &toks) == run(x, v)).then_some(toks)
}

/// A piece of a view and the raw byte range it came from (`None`: not attributable).
#[derive(Clone)]
struct Piece {
    dec: Range<usize>,
    orig: Option<Range<usize>>,
    /// Byte-for-byte copy of `orig`: every char boundary inside maps linearly.
    copy: bool,
}

/// A view with its map back to the raw value. Pieces are non-empty and tile `text`.
#[derive(Clone)]
struct Mapped {
    text: String,
    pieces: Vec<Piece>,
    chain: Vec<Xform>,
}

impl Mapped {
    fn root(raw: &str) -> Mapped {
        let pieces = if raw.is_empty() {
            Vec::new()
        } else {
            vec![Piece {
                dec: 0..raw.len(),
                orig: Some(0..raw.len()),
                copy: true,
            }]
        };
        Mapped {
            text: raw.to_owned(),
            pieces,
            chain: Vec::new(),
        }
    }

    /// Raw position of a match start at `pos`.
    fn map_start(&self, pos: usize) -> Option<usize> {
        let i = self.pieces.partition_point(|p| p.dec.end <= pos);
        let p = self.pieces.get(i)?;
        let o = p.orig.as_ref()?;
        if p.dec.start == pos {
            Some(o.start)
        } else if p.copy {
            Some(o.start + (pos - p.dec.start))
        } else {
            None
        }
    }

    /// Raw position of a match end at `pos`.
    fn map_end(&self, pos: usize) -> Option<usize> {
        let i = self.pieces.partition_point(|p| p.dec.end < pos);
        let p = self.pieces.get(i)?;
        let o = p.orig.as_ref()?;
        if p.dec.end == pos {
            Some(o.end)
        } else if p.copy && p.dec.start < pos {
            Some(o.start + (pos - p.dec.start))
        } else {
            None
        }
    }

    /// This view with `x` applied, or `None` if `x` changes nothing or cannot be tokenized.
    fn then(&self, x: Xform) -> Option<Mapped> {
        let toks = tokens(x, &self.text)?;
        let mut text = String::new();
        let mut pieces = Vec::new();
        for t in &toks {
            match t {
                Tok::Lit(r) => {
                    let first = self.pieces.partition_point(|p| p.dec.end <= r.start);
                    for p in self.pieces[first..]
                        .iter()
                        .take_while(|p| p.dec.start < r.end)
                    {
                        let (a, b) = (r.start.max(p.dec.start), r.end.min(p.dec.end));
                        let whole = a == p.dec.start && b == p.dec.end;
                        let orig = match (&p.orig, p.copy) {
                            (Some(o), true) => {
                                Some(o.start + (a - p.dec.start)..o.start + (b - p.dec.start))
                            }
                            (Some(o), false) if whole => Some(o.clone()),
                            _ => None,
                        };
                        let start = text.len();
                        text.push_str(&self.text[a..b]);
                        pieces.push(Piece {
                            dec: start..text.len(),
                            orig,
                            copy: p.copy,
                        });
                    }
                }
                Tok::Rep(r, s) => {
                    if s.is_empty() {
                        continue;
                    }
                    let orig = match (self.map_start(r.start), self.map_end(r.end)) {
                        (Some(a), Some(b)) if a <= b => Some(a..b),
                        _ => None,
                    };
                    let start = text.len();
                    text.push_str(s);
                    pieces.push(Piece {
                        dec: start..text.len(),
                        orig,
                        copy: false,
                    });
                }
            }
        }
        if text == self.text {
            return None;
        }
        let mut chain = self.chain.clone();
        chain.push(x);
        Some(Mapped {
            text,
            pieces,
            chain,
        })
    }
}

/// The mapped views of `raw` in the order of `views` (raw, NFC, then per round each decoder
/// and its NFC), visited until `f` returns a result.
fn first_mapped<T>(raw: &str, mut f: impl FnMut(&Mapped) -> Option<T>) -> Option<T> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let root = Mapped::root(raw);
    seen.insert(root.text.clone());
    if let Some(t) = f(&root) {
        return Some(t);
    }
    let mut frontier = vec![root.clone()];
    if let Some(n) = root.then(Xform::Nfc)
        && seen.insert(n.text.clone())
    {
        if let Some(t) = f(&n) {
            return Some(t);
        }
        frontier.push(n);
    }
    for _round in 0..MAX_ROUNDS {
        let mut next = Vec::new();
        for v in &frontier {
            for d in DECODERS {
                let Some(m) = v.then(Xform::Dec(d)) else {
                    continue;
                };
                let n = m.then(Xform::Nfc);
                for x in [Some(m), n].into_iter().flatten() {
                    if seen.insert(x.text.clone()) {
                        if let Some(t) = f(&x) {
                            return Some(t);
                        }
                        next.push(x);
                    }
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    None
}

/// Masks the matches of the first view (in `views` order) whose matches all map back to the raw
/// value; the replacement is accepted only if the view of the result is the masked view.
fn mask_once(value: &str, needle: &Needle, first_only: bool) -> Option<(String, u64)> {
    first_mapped(value, |m| {
        for n in &needle.forms {
            let mut found: Vec<Range<usize>> = m
                .text
                .match_indices(n.as_str())
                .map(|(i, s)| i..i + s.len())
                .collect();
            if first_only {
                found.truncate(1);
            }
            if found.is_empty() {
                continue;
            }
            let Some(spans) = found
                .iter()
                .map(|r| match (m.map_start(r.start), m.map_end(r.end)) {
                    (Some(a), Some(b)) if a < b => Some(a..b),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            if spans.windows(2).any(|w| w[0].end > w[1].start) {
                continue;
            }
            let mut out = String::with_capacity(value.len());
            let mut want = String::with_capacity(m.text.len());
            let (mut o, mut d) = (0, 0);
            for (span, r) in spans.iter().zip(&found) {
                out.push_str(&value[o..span.start]);
                out.push_str(REDACTED);
                o = span.end;
                want.push_str(&m.text[d..r.start]);
                want.push_str(REDACTED);
                d = r.end;
            }
            out.push_str(&value[o..]);
            want.push_str(&m.text[d..]);
            let replayed = m.chain.iter().fold(out.clone(), |s, x| run(*x, &s));
            if replayed == want {
                return Some((out, spans.len() as u64));
            }
        }
        None
    })
}

pub(crate) enum Masked {
    /// No canonical hit (or nothing selected to mask).
    NoHit,
    /// Every hit masked (or, `first_only`, the first one).
    Done { value: String, spans: u64 },
    /// A hit remains that no view could mask cleanly; `value` has what could be masked.
    Ambiguous { value: String, spans: u64 },
}

/// §5.3 rule 2/3 for one non-URL string value.
pub(crate) fn mask_value(value: &str, needle: &Needle, first_only: bool) -> Masked {
    let mut spans = 0;
    let mut ambiguous = false;
    let mut parts = Vec::new();
    for seg in value.split(REDACTED) {
        if first_only && (spans > 0 || ambiguous) {
            parts.push(seg.to_owned());
            continue;
        }
        let (v, n, amb) = mask_segment(seg, needle, first_only, MAX_MASK_DEPTH);
        spans += n;
        ambiguous |= amb;
        parts.push(v);
    }
    let value = parts.join(REDACTED);
    if ambiguous {
        Masked::Ambiguous { value, spans }
    } else if spans == 0 {
        Masked::NoHit
    } else {
        Masked::Done { value, spans }
    }
}

/// One part between placeholders: mask the first view that maps, then each new part again.
/// Returns (value, spans, a hit remains that no view could mask).
fn mask_segment(seg: &str, needle: &Needle, first_only: bool, depth: usize) -> (String, u64, bool) {
    if !needle.hit(seg, &views(seg)) {
        return (seg.to_owned(), 0, false);
    }
    if depth == 0 {
        return (seg.to_owned(), 0, true);
    }
    match mask_once(seg, needle, first_only) {
        None => (seg.to_owned(), 0, true),
        Some((m, n)) if first_only => (m, n, false),
        Some((m, n)) => {
            let mut spans = n;
            let mut ambiguous = false;
            let parts: Vec<String> = m
                .split(REDACTED)
                .map(|p| {
                    let (v, k, a) = mask_segment(p, needle, false, depth - 1);
                    spans += k;
                    ambiguous |= a;
                    v
                })
                .collect();
            (parts.join(REDACTED), spans, ambiguous)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_shortcut_agrees_with_the_classifier() {
        for b in 0u8..=0x7f {
            let c = char::from(b);
            assert_eq!(flagged(c), invisible::is_flagged(c), "U+{b:04X}");
        }
    }
}
