//! §5.3 canonical match form: the one definition used for every-occurrence masking, for "also
//! appears in" and for the release-blocking check.
//!
//! `views` and `canonical_hit` follow the plan's code. Plan additions (over-match only, so they
//! can only add hits, never hide one): two more decoders in the same fixpoint, the §6.4 invisible
//! characters removed (`preview::invisible::is_flagged`, context-free) and HTML character
//! references as browsers read them (without the trailing `;`, all two-code-point entities, the
//! windows-1252 remap of `&#128;`..`&#159;`); a needle is also compared without its invisible
//! characters. JSON escapes are already decoded (the candidate is a parsed `Value`); NFKC and
//! case folding are not part of the form (§5.3).
//!
//! Masking (§5.3 rule 3) works on span-mapped views: every view also records which raw byte
//! range each part of it came from, so a match is replaced by `[REDACTED]` in the raw string and
//! everything around it keeps its original encoding. A match whose ends fall inside one decoded
//! unit (an entity, an escape run, an NFC chunk) cannot be mapped and is never guessed.
//!
//! Inside the engine a value is matched part by part between `[REDACTED]` placeholders
//! ([`inspect`]): the placeholder text is public, so masking a codename `RED` converges. The
//! public `canonical_hit` keeps the plan's whole-value semantics.
//!
//! **Work budget** (review T14 I-1, N-1, N-2). Crafted content can multiply a value into
//! hundreds of forms. Every byte the canonical form allocates (forms kept, decoder outputs that
//! turn out to be duplicates, span maps, replay copies) is charged before it is allocated, to two
//! meters: one per text (at most [`TEXT_FACTOR`] × its length, at least [`TEXT_FLOOR`], at most
//! [`TEXT_CEIL`], and at most [`MAX_FORMS`] forms), which bounds the peak memory of one text's
//! expansion, and one per [`super::apply`] call ([`Budget`]: [`APPLY_FACTOR`] × the candidate's
//! text bytes, at least [`APPLY_FLOOR`], at most [`APPLY_CEIL`]), which bounds the total work.
//! A text whose expansion does not fit is `over_budget`: it is not masked and blocks whenever any
//! mask is active (fail closed, with its path, so the user can drop it). Printable ASCII without
//! `%&+` is exact without any expansion and never counts.

use std::cell::Cell;
use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::ops::Range;

use atlas_duck_preview::invisible;
use percent_encoding::percent_decode_str;

use super::{REDACTED, entities};

const MAX_ROUNDS: usize = 3;
/// Bound on nested mask passes over one part of a value (each pass masks every match of one view).
const MAX_MASK_DEPTH: usize = 16;
/// Per text: work (and so peak memory) of one expansion, in bytes, relative to the text.
pub const TEXT_FACTOR: usize = 32;
pub const TEXT_FLOOR: usize = 1 << 20;
pub const TEXT_CEIL: usize = 256 << 20;
pub const MAX_FORMS: usize = 512;
/// Per `apply`: total work over all texts, relative to the candidate's text bytes.
pub const APPLY_FACTOR: usize = 64;
pub const APPLY_FLOOR: usize = 4 << 20;
pub const APPLY_CEIL: usize = 1 << 30;

/// The work budget shared by every text of one `apply` call.
pub(crate) struct Budget {
    left: Cell<usize>,
}

impl Budget {
    /// For a candidate whose strings, number texts and keys total `text_bytes`.
    pub(crate) fn for_apply(text_bytes: usize) -> Budget {
        Budget {
            left: Cell::new(
                text_bytes
                    .saturating_mul(APPLY_FACTOR)
                    .clamp(APPLY_FLOOR, APPLY_CEIL),
            ),
        }
    }

    /// For a standalone call (`views`, `canonical_hit`): only the per-text limits apply.
    fn standalone() -> Budget {
        Budget {
            left: Cell::new(usize::MAX),
        }
    }

    /// Once one charge does not fit, nothing more does.
    fn take(&self, n: usize) -> bool {
        let left = self.left.get();
        if n > left {
            self.left.set(0);
            false
        } else {
            self.left.set(left - n);
            true
        }
    }
}

/// One text's share of the budget.
struct Meter<'a> {
    shared: &'a Budget,
    left: Cell<usize>,
    over: Cell<bool>,
}

impl<'a> Meter<'a> {
    fn new(shared: &'a Budget, len: usize) -> Meter<'a> {
        Meter {
            shared,
            left: Cell::new(len.saturating_mul(TEXT_FACTOR).clamp(TEXT_FLOOR, TEXT_CEIL)),
            over: Cell::new(false),
        }
    }

    /// Call before allocating `n` bytes; `false` (and from then on always `false`) when they do
    /// not fit.
    fn charge(&self, n: usize) -> bool {
        if self.over.get() {
            return false;
        }
        let left = self.left.get();
        if n > left || !self.shared.take(n) {
            self.over.set(true);
            return false;
        }
        self.left.set(left - n);
        true
    }

    fn over(&self) -> bool {
        self.over.get()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Views {
    pub forms: Vec<String>,
    /// Still changing after round 3, or `over_budget`.
    pub unstable: bool,
    /// Plan addition: the expansion did not fit the work budget, so `forms` is incomplete. Any
    /// mask blocks such a value (`UnstableEncoding`).
    pub over_budget: bool,
}

/// Redacting `Debug` (§7.7): the forms are decoded content.
impl std::fmt::Debug for Views {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Views {{ forms: <{} forms>, unstable: {}, over_budget: {} }}",
            self.forms.len(),
            self.unstable,
            self.over_budget
        )
    }
}

fn nfc_normalizer() -> icu_normalizer::ComposingNormalizerBorrowed<'static> {
    icu_normalizer::ComposingNormalizerBorrowed::new_nfc()
}

pub(crate) fn nfc(s: &str) -> String {
    nfc_normalizer().normalize(s).into_owned()
}

/// NFC grows UTF-8 by at most 3× (Unicode's stated expansion bound).
const NFC_GROWTH: usize = 3;

/// NFC of `s` if it differs, charged first.
fn nfc_metered(s: &str, m: &Meter<'_>) -> Option<String> {
    let n = nfc_normalizer();
    if n.is_normalized(s) || !m.charge(s.len().saturating_mul(NFC_GROWTH)) {
        return None;
    }
    Some(n.normalize(s).into_owned())
}

/// The decoders of §5.3 rule 1 (HTML/XML character references; percent-decoding as UTF-8;
/// percent-decoding with `+` read as a space, a view *within* percent-decoding), then the two plan
/// additions (browser-style references, invisible characters removed).
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
        Decoder::HtmlLenient | Decoder::Invisible => tokens_output(Xform::Dec(d), v),
    }
}

/// `decode(d, v)` if it can change `v` and the budget allows, else `None`. Decoders never make a
/// value longer, so the charge is its length (twice for `Plus`, which copies first).
fn decode_metered(d: Decoder, v: &str, m: &Meter<'_>) -> Option<String> {
    if !may_change(Xform::Dec(d), v) || !m.charge(run_cost(Xform::Dec(d), v)) {
        return None;
    }
    let out = decode(d, v);
    (out != v).then_some(out)
}

/// `false` when `x` certainly leaves `v` as it is (checked without allocating).
fn may_change(x: Xform, v: &str) -> bool {
    match x {
        Xform::Dec(Decoder::Html | Decoder::HtmlLenient) => v.contains('&'),
        Xform::Dec(Decoder::Pct) => v.contains('%'),
        // Without a `+` it is the `Pct` view.
        Xform::Dec(Decoder::Plus) => v.contains('+'),
        Xform::Dec(Decoder::Invisible) => v.bytes().any(|b| {
            !b.is_ascii() || (b.is_ascii_control() && !matches!(b, b'\t' | b'\n' | b'\r'))
        }),
        Xform::Nfc => !nfc_normalizer().is_normalized(v),
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

/// No decoder changes it and it is already NFC: printable ASCII (plus `\t\n\r`) without `%`,
/// `&` or `+`.
fn is_plain(s: &str) -> bool {
    s.bytes().all(|b| {
        matches!(b, b'\t' | b'\n' | b'\r')
            || ((0x20..0x7f).contains(&b) && !matches!(b, b'%' | b'&' | b'+'))
    })
}

/// Exact string dedup by hash buckets (no second copy of a form is kept).
struct Seen {
    state: RandomState,
    buckets: HashMap<u64, Vec<usize>>,
}

impl Seen {
    fn new() -> Seen {
        Seen {
            state: RandomState::new(),
            buckets: HashMap::new(),
        }
    }

    /// `true` if `s` is new; `at` is where it will be stored in `store`.
    fn insert(&mut self, s: &str, store: &[impl AsRef<str>], at: usize) -> bool {
        let bucket = self.buckets.entry(self.state.hash_one(s)).or_default();
        if bucket
            .iter()
            .any(|&i| store.get(i).is_some_and(|x| x.as_ref() == s))
        {
            return false;
        }
        bucket.push(at);
        true
    }
}

/// Raw form, every decoded view and their NFC forms, iterated to a fixpoint for at most 3 rounds.
/// `unstable` = some view still changes under a decoder after round 3 (fail closed, §5.3), or
/// the expansion went over its work budget (`over_budget`, plan addition).
pub fn views(raw: &str) -> Views {
    let budget = Budget::standalone();
    expand(raw, &Meter::new(&budget, raw.len()))
}

fn over(forms: Vec<String>) -> Views {
    Views {
        forms,
        unstable: true,
        over_budget: true,
    }
}

fn expand(raw: &str, m: &Meter<'_>) -> Views {
    if is_plain(raw) {
        return Views {
            forms: vec![raw.to_owned()],
            unstable: false,
            over_budget: false,
        };
    }
    let mut forms: Vec<String> = Vec::new();
    let mut seen = Seen::new();
    if !m.charge(raw.len()) {
        return over(forms);
    }
    seen.insert(raw, &forms, 0);
    forms.push(raw.to_owned());
    if let Some(n) = nfc_metered(raw, m)
        && seen.insert(&n, &forms, forms.len())
    {
        forms.push(n);
    }
    if m.over() {
        return over(forms);
    }
    let mut frontier: Vec<usize> = (0..forms.len()).collect();
    for _round in 0..MAX_ROUNDS {
        let mut next = Vec::new();
        for &fi in &frontier {
            for d in DECODERS {
                let Some(dv) = forms.get(fi).and_then(|v| decode_metered(d, v, m)) else {
                    if m.over() {
                        return over(forms);
                    }
                    continue;
                };
                let n = nfc_metered(&dv, m);
                if m.over() {
                    return over(forms);
                }
                for x in [n, Some(dv)].into_iter().flatten() {
                    if seen.insert(&x, &forms, forms.len()) {
                        if forms.len() >= MAX_FORMS {
                            return over(forms);
                        }
                        next.push(forms.len());
                        forms.push(x);
                    }
                }
            }
        }
        if next.is_empty() {
            return Views {
                forms,
                unstable: false,
                over_budget: false,
            };
        }
        frontier = next;
    }
    let mut unstable = false;
    for &fi in &frontier {
        for d in DECODERS {
            if forms
                .get(fi)
                .and_then(|v| decode_metered(d, v, m))
                .is_some()
            {
                unstable = true;
            }
            if m.over() {
                return over(forms);
            }
        }
    }
    Views {
        forms,
        unstable,
        over_budget: false,
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

    /// `views` must be the views of `value`.
    fn hit(&self, value: &str, views: &Views) -> bool {
        any_in(&self.forms, value, views)
    }

    /// Forms that can match across a placeholder edge: they hold a bracket and are not part of
    /// the placeholder text themselves (`x [REDACTED] y`, `ED] y`).
    fn crossing_forms(&self) -> Vec<String> {
        self.forms
            .iter()
            .filter(|f| f.contains(['[', ']']) && !REDACTED.contains(f.as_str()))
            .cloned()
            .collect()
    }

    /// Occurrences in one value: per part between placeholders, the raw matches of the first
    /// form that has any, else 1 for a canonical hit (a part over budget counts 1); plus raw
    /// matches across a placeholder.
    pub(crate) fn count(&self, value: &str, budget: &Budget) -> u64 {
        let parts: u64 = value
            .split(REDACTED)
            .map(|s| {
                self.forms
                    .iter()
                    .map(|n| s.matches(n.as_str()).count() as u64)
                    .find(|&c| c > 0)
                    .unwrap_or_else(|| {
                        let v = expand(s, &Meter::new(budget, s.len()));
                        u64::from(v.over_budget || self.hit(s, &v))
                    })
            })
            .sum();
        parts + crossing_matches(value, &self.crossing_forms()).len() as u64
    }
}

fn any_in(forms: &[String], value: &str, views: &Views) -> bool {
    forms.iter().any(|n| value.contains(n.as_str()))
        || views
            .forms
            .iter()
            .any(|f| forms.iter().any(|n| f.contains(n.as_str())))
}

/// What the engine needs to know about one text (a string value, a number's text, an object
/// key, a dropped field name), for every needle at once.
///
/// A value is matched part by part between `[REDACTED]` placeholders: the placeholder text is
/// public, so a needle inside it (a codename `RED`) is no hit and a mask converges. A needle
/// that holds a bracket is also matched against the whole value, so a match across a
/// placeholder (`x [REDACTED] y`) is a hit (review T14 I-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TextInfo {
    /// Per needle, in the order given.
    pub(crate) hits: Vec<bool>,
    pub(crate) unstable: bool,
    pub(crate) over_budget: bool,
}

pub(crate) fn inspect(text: &str, needles: &[Needle], budget: &Budget) -> TextInfo {
    let mut info = TextInfo {
        hits: vec![false; needles.len()],
        unstable: false,
        over_budget: false,
    };
    for part in text.split(REDACTED) {
        let v = expand(part, &Meter::new(budget, part.len()));
        info.unstable |= v.unstable;
        info.over_budget |= v.over_budget;
        for (h, n) in info.hits.iter_mut().zip(needles) {
            *h = *h || n.hit(part, &v);
        }
    }
    if text.contains(REDACTED) {
        let crossing: Vec<Vec<String>> = needles.iter().map(Needle::crossing_forms).collect();
        if crossing
            .iter()
            .zip(&info.hits)
            .any(|(c, h)| !c.is_empty() && !h)
        {
            let whole = expand(text, &Meter::new(budget, text.len()));
            info.unstable |= whole.over_budget;
            info.over_budget |= whole.over_budget;
            for (h, c) in info.hits.iter_mut().zip(&crossing) {
                *h = *h || (!c.is_empty() && any_in(c, text, &whole));
            }
        }
    }
    info
}

/// Raw matches of `forms` in `value` that overlap a placeholder, each widened to the whole of
/// every placeholder it touches (review T14 N-3: no `[REDACT` fragments are left as text);
/// overlapping results are merged; in order.
fn crossing_matches(value: &str, forms: &[String]) -> Vec<Range<usize>> {
    let placeholders: Vec<Range<usize>> = value
        .match_indices(REDACTED)
        .map(|(i, s)| i..i + s.len())
        .collect();
    if placeholders.is_empty() {
        return Vec::new();
    }
    let touches = |a: &Range<usize>, b: &Range<usize>| a.start < b.end && b.start < a.end;
    let mut found: Vec<Range<usize>> = Vec::new();
    for f in forms {
        for (i, s) in value.match_indices(f.as_str()) {
            let mut r = i..i + s.len();
            if !placeholders.iter().any(|p| touches(p, &r)) {
                continue;
            }
            // Placeholders do not overlap each other, so one pass in order widens fully.
            for p in &placeholders {
                if touches(p, &r) {
                    r = r.start.min(p.start)..r.end.max(p.end);
                }
            }
            found.push(r);
        }
    }
    found.sort_by_key(|r| r.start);
    let mut out: Vec<Range<usize>> = Vec::new();
    for r in found {
        match out.last_mut() {
            Some(last) if r.start < last.end => last.end = last.end.max(r.end),
            _ => out.push(r),
        }
    }
    out
}

// ---- span-mapped views ----

/// What a decoder makes of one piece of its input: `None` = copied literally, `Some(s)` =
/// replaced by `s` (an escape, a reference, an NFC chunk, a removed invisible character).
type Emit<'e> = dyn FnMut(Range<usize>, Option<&str>) + 'e;

/// Decoded text of a reference: a static entity expansion or one character.
enum Ref {
    Static(&'static str),
    Char(char),
}

fn emit_ref(emit: &mut Emit<'_>, r: Range<usize>, x: &Ref) {
    match x {
        Ref::Static(s) => emit(r, Some(s)),
        Ref::Char(c) => {
            let mut buf = [0u8; 4];
            emit(r, Some(c.encode_utf8(&mut buf)));
        }
    }
}

/// HTML character references (`lenient`: also without the trailing `;`, named references by
/// longest known prefix, every two-code-point entity in full, the windows-1252 remap; as
/// browsers read text).
fn html_tokens(v: &str, lenient: bool, emit: &mut Emit<'_>) {
    let b = v.as_bytes();
    let mut lit = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'&'
            && let Some((end, x)) = html_ref_at(v, i, lenient)
        {
            if lit < i {
                emit(lit..i, None);
            }
            emit_ref(emit, i..end, &x);
            i = end;
            lit = end;
            continue;
        }
        i += 1;
    }
    if lit < b.len() {
        emit(lit..b.len(), None);
    }
}

/// html-escape 0.2.15 keeps only the first code point of the WHATWG entities that expand to two
/// (`&fjlig;` gives `f`, not `fj`); the lenient view decodes all of them as browsers do.
fn named_entity_lenient(name: &[u8]) -> Option<&'static str> {
    entities::MULTI_CODE_POINT
        .binary_search_by(|(n, _)| (*n).cmp(name))
        .ok()
        .and_then(|i| entities::MULTI_CODE_POINT.get(i))
        .map(|(_, s)| *s)
        .or_else(|| named_entity(name))
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

fn html_ref_at(v: &str, amp: usize, lenient: bool) -> Option<(usize, Ref)> {
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
        // Lenient: the WHATWG windows-1252 remap of 0x80..0x9F (`&#146;` is `’`).
        let c = match entities::c1_remap(n) {
            Some(c) if lenient => c,
            _ => numeric_char(n)?,
        };
        return Some((if semi { p + 1 } else { p }, Ref::Char(c)));
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
        return Some((p + 1, Ref::Static(s)));
    }
    if !lenient {
        return None;
    }
    (name + 1..=p)
        .rev()
        .find_map(|end| lookup(&b[name..end]).map(|s| (end, Ref::Static(s))))
}

/// Percent escapes (runs of `%XX` decoded as UTF-8, invalid sequences as U+FFFD exactly as
/// `decode_utf8_lossy` does); `plus`: `+` read as a space.
fn pct_tokens(v: &str, plus: bool, emit: &mut Emit<'_>) {
    let b = v.as_bytes();
    let hex = |x: u8| char::from(x).to_digit(16);
    let escape_at = |i: usize| -> Option<u8> {
        if b.get(i) != Some(&b'%') {
            return None;
        }
        let hi = hex(*b.get(i + 1)?)?;
        let lo = hex(*b.get(i + 2)?)?;
        u8::try_from(hi * 16 + lo).ok()
    };
    let mut lit = 0;
    let mut i = 0;
    let mut bytes = Vec::new();
    while i < b.len() {
        if plus && b[i] == b'+' {
            if lit < i {
                emit(lit..i, None);
            }
            emit(i..i + 1, Some(" "));
            i += 1;
            lit = i;
            continue;
        }
        if escape_at(i).is_none() {
            i += 1;
            continue;
        }
        if lit < i {
            emit(lit..i, None);
        }
        let run = i;
        bytes.clear();
        while let Some(x) = escape_at(i) {
            bytes.push(x);
            i += 3;
        }
        let mut k = 0;
        for chunk in bytes.utf8_chunks() {
            for c in chunk.valid().chars() {
                let n = c.len_utf8();
                emit_ref(emit, run + 3 * k..run + 3 * (k + n), &Ref::Char(c));
                k += n;
            }
            let n = chunk.invalid().len();
            if n > 0 {
                emit(run + 3 * k..run + 3 * (k + n), Some("\u{FFFD}"));
                k += n;
            }
        }
        lit = i;
    }
    if lit < b.len() {
        emit(lit..b.len(), None);
    }
}

fn invisible_tokens(v: &str, emit: &mut Emit<'_>) {
    let mut lit = 0;
    for (i, c) in v.char_indices() {
        if flagged(c) {
            if lit < i {
                emit(lit..i, None);
            }
            emit(i..i + c.len_utf8(), Some(""));
            lit = i + c.len_utf8();
        }
    }
    if lit < v.len() {
        emit(lit..v.len(), None);
    }
}

/// NFC per chunk, a chunk ending before every ASCII character: an ASCII character is a starter
/// that no canonical composition takes as its second part, so NFC never crosses that boundary.
/// The caller checks the result against NFC of the whole value.
fn nfc_tokens(v: &str, emit: &mut Emit<'_>) {
    let n = nfc_normalizer();
    let chunk = |emit: &mut Emit<'_>, r: Range<usize>| {
        let s = &v[r.clone()];
        match n.normalize(s) {
            std::borrow::Cow::Borrowed(_) => emit(r, None),
            std::borrow::Cow::Owned(x) => emit(r, Some(&x)),
        }
    };
    let mut start = 0;
    for (i, c) in v.char_indices() {
        if c.is_ascii() && i > start {
            chunk(emit, start..i);
            start = i;
        }
    }
    if start < v.len() {
        chunk(emit, start..v.len());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Xform {
    Dec(Decoder),
    Nfc,
}

fn tokenize(x: Xform, v: &str, emit: &mut Emit<'_>) {
    match x {
        Xform::Dec(Decoder::Html) => html_tokens(v, false, emit),
        Xform::Dec(Decoder::HtmlLenient) => html_tokens(v, true, emit),
        Xform::Dec(Decoder::Pct) => pct_tokens(v, false, emit),
        Xform::Dec(Decoder::Plus) => pct_tokens(v, true, emit),
        Xform::Dec(Decoder::Invisible) => invisible_tokens(v, emit),
        Xform::Nfc => nfc_tokens(v, emit),
    }
}

/// The text the tokens of `x` make of `v` (the definition of the two plan decoders).
fn tokens_output(x: Xform, v: &str) -> String {
    let mut s = String::with_capacity(v.len());
    tokenize(x, v, &mut |r, o| match o {
        None => s.push_str(&v[r]),
        Some(o) => s.push_str(o),
    });
    s
}

fn run(x: Xform, v: &str) -> String {
    match x {
        Xform::Dec(d) => decode(d, v),
        Xform::Nfc => nfc(v),
    }
}

/// Bytes `run(x, v)` may allocate.
fn run_cost(x: Xform, v: &str) -> usize {
    match x {
        Xform::Dec(Decoder::Plus) => 2 * v.len(),
        Xform::Dec(_) => v.len(),
        Xform::Nfc => NFC_GROWTH * v.len(),
    }
}

/// A piece of a view and the raw byte range it came from. Offsets are `u32` (values above
/// 4 GiB are refused), so a piece is 20 bytes.
#[derive(Clone, Copy)]
struct Piece {
    dec_start: u32,
    dec_end: u32,
    orig_start: u32,
    orig_end: u32,
    /// `MAPPED`: `orig` is valid. `COPY`: byte-for-byte copy of `orig` (every char boundary
    /// inside maps linearly).
    flags: u8,
}

const MAPPED: u8 = 1;
const COPY: u8 = 2;
/// Charged per piece: its size twice, for `Vec` growth.
const PIECE_COST: usize = 2 * size_of::<Piece>();

impl Piece {
    fn dec(&self) -> Range<usize> {
        self.dec_start as usize..self.dec_end as usize
    }

    fn orig(&self) -> Option<Range<usize>> {
        (self.flags & MAPPED != 0).then_some(self.orig_start as usize..self.orig_end as usize)
    }

    fn copy(&self) -> bool {
        self.flags & COPY != 0
    }

    fn new(dec: Range<usize>, orig: Option<Range<usize>>, copy: bool) -> Option<Piece> {
        let (o, mapped) = match orig {
            Some(o) => (o, MAPPED),
            None => (0..0, 0),
        };
        Some(Piece {
            dec_start: u32::try_from(dec.start).ok()?,
            dec_end: u32::try_from(dec.end).ok()?,
            orig_start: u32::try_from(o.start).ok()?,
            orig_end: u32::try_from(o.end).ok()?,
            flags: mapped | if copy { COPY } else { 0 },
        })
    }
}

/// A view with its map back to the raw value. Pieces are non-empty and tile `text`.
struct Mapped {
    text: String,
    pieces: Vec<Piece>,
    chain: Vec<Xform>,
}

impl AsRef<str> for Mapped {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

impl Mapped {
    fn root(raw: &str, m: &Meter<'_>) -> Option<Mapped> {
        if !m.charge(raw.len() + PIECE_COST) {
            return None;
        }
        let pieces = if raw.is_empty() {
            Vec::new()
        } else {
            vec![Piece::new(0..raw.len(), Some(0..raw.len()), true)?]
        };
        Some(Mapped {
            text: raw.to_owned(),
            pieces,
            chain: Vec::new(),
        })
    }

    /// Raw position of a match start at `pos`.
    fn map_start(&self, pos: usize) -> Option<usize> {
        let i = self.pieces.partition_point(|p| p.dec().end <= pos);
        let p = self.pieces.get(i)?;
        let o = p.orig()?;
        if p.dec().start == pos {
            Some(o.start)
        } else if p.copy() {
            Some(o.start + (pos - p.dec().start))
        } else {
            None
        }
    }

    /// Raw position of a match end at `pos`.
    fn map_end(&self, pos: usize) -> Option<usize> {
        let i = self.pieces.partition_point(|p| p.dec().end < pos);
        let p = self.pieces.get(i)?;
        let o = p.orig()?;
        if p.dec().end == pos {
            Some(o.end)
        } else if p.copy() && p.dec().start < pos {
            Some(o.start + (pos - p.dec().start))
        } else {
            None
        }
    }

    /// This view with `x` applied, or `None` if `x` changes nothing, its tokens do not
    /// reproduce the decoder's own output (never guess), or the budget runs out.
    fn then(&self, x: Xform, m: &Meter<'_>) -> Option<Mapped> {
        if !may_change(x, &self.text) || !m.charge(run_cost(x, &self.text)) {
            return None;
        }
        let mut text = String::with_capacity(self.text.len());
        let mut pieces: Vec<Piece> = Vec::new();
        let mut bad = false;
        let mut push = |pieces: &mut Vec<Piece>, p: Option<Piece>| match p {
            // A literal run that continues the previous one (in the view and in the raw value)
            // extends it: a piece per token would cost far more than the value.
            Some(p)
                if p.copy()
                    && pieces.last().is_some_and(|l| {
                        l.copy()
                            && l.orig().is_some()
                            && p.orig().is_some()
                            && l.dec_end == p.dec_start
                            && l.orig_end == p.orig_start
                    }) =>
            {
                if let Some(l) = pieces.last_mut() {
                    l.dec_end = p.dec_end;
                    l.orig_end = p.orig_end;
                }
            }
            Some(p) if m.charge(PIECE_COST) => pieces.push(p),
            _ => bad = true,
        };
        tokenize(x, &self.text, &mut |r, out| {
            if m.over() {
                return;
            }
            match out {
                None => {
                    let first = self.pieces.partition_point(|p| p.dec().end <= r.start);
                    for p in self.pieces[first..]
                        .iter()
                        .take_while(|p| p.dec().start < r.end)
                    {
                        let pd = p.dec();
                        let (a, b) = (r.start.max(pd.start), r.end.min(pd.end));
                        let whole = a == pd.start && b == pd.end;
                        let orig = match (p.orig(), p.copy()) {
                            (Some(o), true) => {
                                Some(o.start + (a - pd.start)..o.start + (b - pd.start))
                            }
                            (Some(o), false) if whole => Some(o),
                            _ => None,
                        };
                        let start = text.len();
                        text.push_str(&self.text[a..b]);
                        push(&mut pieces, Piece::new(start..text.len(), orig, p.copy()));
                    }
                }
                Some("") => {}
                Some(s) => {
                    let orig = match (self.map_start(r.start), self.map_end(r.end)) {
                        (Some(a), Some(b)) if a <= b => Some(a..b),
                        _ => None,
                    };
                    let start = text.len();
                    text.push_str(s);
                    push(&mut pieces, Piece::new(start..text.len(), orig, false));
                }
            }
        });
        if bad || m.over() || text == self.text {
            return None;
        }
        // The decoder's own output, so a tokenizer slip can never pass for a view.
        if !m.charge(run_cost(x, &self.text)) || run(x, &self.text) != text {
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
/// and its NFC), visited until `f` returns a result. `None` also when the work budget runs out
/// (the caller then treats the value as not maskable: fail closed).
fn first_mapped<T>(raw: &str, m: &Meter<'_>, mut f: impl FnMut(&Mapped) -> Option<T>) -> Option<T> {
    /// Stores `x` if its text is new and the form cap allows; its index.
    fn admit(store: &mut Vec<Mapped>, seen: &mut Seen, x: Mapped) -> Option<usize> {
        let at = store.len();
        if at >= MAX_FORMS || !seen.insert(&x.text, store, at) {
            return None;
        }
        store.push(x);
        Some(at)
    }
    let mut store: Vec<Mapped> = Vec::new();
    let mut seen = Seen::new();
    let root = Mapped::root(raw, m)?;
    if let Some(t) = f(&root) {
        return Some(t);
    }
    let mut frontier: Vec<usize> = Vec::new();
    if let Some(at) = admit(&mut store, &mut seen, root) {
        frontier.push(at);
    }
    if let Some(n) = store.first().and_then(|r| r.then(Xform::Nfc, m))
        && let Some(at) = admit(&mut store, &mut seen, n)
    {
        if let Some(t) = store.get(at).and_then(&mut f) {
            return Some(t);
        }
        frontier.push(at);
    }
    for _round in 0..MAX_ROUNDS {
        let mut next = Vec::new();
        for &vi in &frontier {
            for d in DECODERS {
                if m.over() {
                    return None;
                }
                let Some(dm) = store.get(vi).and_then(|v| v.then(Xform::Dec(d), m)) else {
                    continue;
                };
                let n = dm.then(Xform::Nfc, m);
                for x in [Some(dm), n].into_iter().flatten() {
                    if let Some(at) = admit(&mut store, &mut seen, x) {
                        if let Some(t) = store.get(at).and_then(&mut f) {
                            return Some(t);
                        }
                        next.push(at);
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
fn mask_once(
    value: &str,
    needle: &Needle,
    first_only: bool,
    m: &Meter<'_>,
) -> Option<(String, u64)> {
    first_mapped(value, m, |mp| {
        for n in &needle.forms {
            let mut found: Vec<Range<usize>> = mp
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
                .map(|r| match (mp.map_start(r.start), mp.map_end(r.end)) {
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
            let grown = found.len().saturating_mul(REDACTED.len());
            if !m.charge(
                value
                    .len()
                    .saturating_add(mp.text.len())
                    .saturating_add(2 * grown),
            ) {
                return None;
            }
            let mut out = String::with_capacity(value.len() + grown);
            let mut want = String::with_capacity(mp.text.len() + grown);
            let (mut o, mut d) = (0, 0);
            for (span, r) in spans.iter().zip(&found) {
                out.push_str(&value[o..span.start]);
                out.push_str(REDACTED);
                o = span.end;
                want.push_str(&mp.text[d..r.start]);
                want.push_str(REDACTED);
                d = r.end;
            }
            out.push_str(&value[o..]);
            want.push_str(&mp.text[d..]);
            let mut replayed = out.clone();
            for x in &mp.chain {
                if !m.charge(run_cost(*x, &replayed)) {
                    return None;
                }
                replayed = run(*x, &replayed);
            }
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

/// §5.3 rule 2/3 for one non-URL string value. A raw match across a placeholder
/// (`x [REDACTED] y`) is replaced together with the placeholders it touches; an encoded one
/// stays a hit, so the caller's final pass blocks it.
pub(crate) fn mask_value(
    value: &str,
    needle: &Needle,
    first_only: bool,
    budget: &Budget,
) -> Masked {
    let mut spans = 0;
    let mut ambiguous = false;
    let mut value = value.to_owned();
    let crossing = crossing_matches(&value, &needle.crossing_forms());
    if !crossing.is_empty() {
        let take = if first_only { 1 } else { crossing.len() };
        let mut out = String::with_capacity(value.len());
        let mut o = 0;
        for r in crossing.iter().take(take) {
            out.push_str(&value[o..r.start]);
            out.push_str(REDACTED);
            o = r.end;
            spans += 1;
        }
        out.push_str(&value[o..]);
        value = out;
        if first_only {
            return Masked::Done { value, spans };
        }
    }
    let mut parts = Vec::new();
    for seg in value.split(REDACTED) {
        if first_only && (spans > 0 || ambiguous) {
            parts.push(seg.to_owned());
            continue;
        }
        let (v, n, amb) = mask_segment(seg, needle, first_only, MAX_MASK_DEPTH, budget);
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
/// Returns (value, spans, a hit remains that no view could mask). A part whose views do not fit
/// the work budget is not masked at all (its hits cannot be known).
fn mask_segment(
    seg: &str,
    needle: &Needle,
    first_only: bool,
    depth: usize,
    budget: &Budget,
) -> (String, u64, bool) {
    let v = expand(seg, &Meter::new(budget, seg.len()));
    if v.over_budget {
        return (seg.to_owned(), 0, true);
    }
    if !needle.hit(seg, &v) {
        return (seg.to_owned(), 0, false);
    }
    drop(v);
    if depth == 0 {
        return (seg.to_owned(), 0, true);
    }
    match mask_once(seg, needle, first_only, &Meter::new(budget, seg.len())) {
        None => (seg.to_owned(), 0, true),
        Some((m, n)) if first_only => (m, n, false),
        Some((m, n)) => {
            let mut spans = n;
            let mut ambiguous = false;
            let parts: Vec<String> = m
                .split(REDACTED)
                .map(|p| {
                    let (v, k, a) = mask_segment(p, needle, false, depth - 1, budget);
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

    #[test]
    fn plan_decoders_agree_with_their_tokens() {
        // The tokenizers of the plan's decoders must reproduce the libraries' outputs on the
        // shapes they are used for (the mapped view checks this per value too).
        for v in ["a&amp;b&lt;", "x%20y%C3%BC%zz", "p+q%2B", "u\u{308}x"] {
            assert_eq!(
                tokens_output(Xform::Dec(Decoder::Html), v),
                decode(Decoder::Html, v)
            );
            assert_eq!(
                tokens_output(Xform::Dec(Decoder::Pct), v),
                decode(Decoder::Pct, v)
            );
            assert_eq!(
                tokens_output(Xform::Dec(Decoder::Plus), v),
                decode(Decoder::Plus, v)
            );
            assert_eq!(tokens_output(Xform::Nfc, v), nfc(v));
        }
    }
}
