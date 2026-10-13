//! Block and inline parsing over the lexer's tokens.
//!
//! Blocks are line-based; `{code}`/`{noformat}` tokens always form their own block (they cut
//! a line), `{quote}`/`{panel}` and paired body macros that start a line are containers whose
//! closing tag may sit on any later line. Inline parsing runs in two passes: constructs
//! (macros, links, mentions, images, attachments, monospace, URLs) become atoms first, then
//! emphasis is matched around them, so a delimiter can never split a construct.
//!
//! Nesting is bounded by [`MAX_DEPTH`]: deeper containers and emphasis are not opened, but
//! their content is still scanned at the same level, so nothing goes unreported. Link, image
//! and monospace content recursion is bounded by construction (link content holds no `[`,
//! image content no `!`, monospace content no `{{`), so it may run at the bound.

use std::collections::HashMap;

use super::lexer::{Sp, Tok, TokKind, char_at, char_before, lex};
use super::{
    Block, CodeKind, ConstructKind, ConstructSpan, Inline, SpanKind, TableCell, TableRow, WikiDoc,
};

/// Nesting bound for containers and emphasis (plan Task 2).
pub(crate) const MAX_DEPTH: usize = 32;

/// Container macros whose content is parsed as blocks.
const QUOTE: &str = "quote";
const PANEL: &str = "panel";

/// Tags never paired into a body macro: inline styling (its content stays ordinary inlines)
/// and includes (no body).
const UNPAIRED: [&str; 3] = ["color", "include", "excerpt-include"];

/// Tags reported as [`ConstructKind::Include`].
const INCLUDES: [&str; 2] = ["include", "excerpt-include"];

pub(crate) fn parse_doc(src: &str) -> WikiDoc {
    let toks = lex(src);
    let closers = index_closers(src, &toks);
    let mut p = Parser {
        src,
        toks: &toks,
        closers,
        spans: Vec::new(),
    };
    let blocks = p.blocks(0, toks.len(), 0);
    let mut spans = p.spans;
    spans.sort_by_key(|s| s.range.start);
    WikiDoc { blocks, spans }
}

/// Token indices of the parameterless tags, per ASCII-lowercased name, ascending.
fn index_closers(src: &str, toks: &[Tok]) -> HashMap<String, Vec<usize>> {
    let mut map: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, t) in toks.iter().enumerate() {
        if let TokKind::Tag { name, params: None } = t.kind {
            let key = src.get(name.range()).unwrap_or("").to_ascii_lowercase();
            map.entry(key).or_default().push(i);
        }
    }
    map
}

fn is_include(name: &str) -> bool {
    INCLUDES.iter().any(|n| n.eq_ignore_ascii_case(name))
}

/// One classified line (or virtual line after a code token / closing tag).
enum Line {
    /// Whitespace only; `next` is the index after it.
    Blank { next: usize },
    /// First token is a `{code}`/`{noformat}` token.
    Code(usize),
    /// First token is a macro tag.
    Tag(usize),
    /// Anything else: `f` = first non-blank token, `cut` = the newline or code token ending
    /// it (or `hi`), `next` = where the following line starts.
    Content {
        f: usize,
        cut: usize,
        next: usize,
        kind: LineKind,
    },
}

enum LineKind {
    /// Content starts at the byte offset (after the marker).
    Heading(u8, usize),
    Bq(usize),
    Rule,
    ListItem {
        depth: u8,
        ordered: bool,
        at: usize,
    },
    TableRow,
    Text,
}

/// Blocks being collected across lines.
enum Pending {
    None,
    Para(usize, usize),
    List {
        ordered: bool,
        items: Vec<(u8, Vec<Inline>)>,
    },
    Table(Vec<TableRow>),
}

/// Inline pass-1 output: a resolved construct or a token left for emphasis matching.
#[derive(Clone)]
enum Unit {
    Atom(Inline),
    Tok(Tok),
}

struct Parser<'a> {
    src: &'a str,
    toks: &'a [Tok],
    closers: HashMap<String, Vec<usize>>,
    spans: Vec<ConstructSpan>,
}

impl<'a> Parser<'a> {
    fn text(&self, sp: Sp) -> &'a str {
        self.src.get(sp.range()).unwrap_or("")
    }

    fn kind_at(&self, i: usize) -> Option<TokKind> {
        self.toks.get(i).map(|t| t.kind)
    }

    fn is_blank(&self, t: &Tok) -> bool {
        t.kind == TokKind::Text && self.text(t.sp).trim().is_empty()
    }

    fn record(&mut self, kind: SpanKind, sp: Sp, label: String) {
        self.spans.push(ConstructSpan {
            kind,
            range: sp.range(),
            label,
        });
    }

    /// Records a macro tag (or include) span.
    fn record_tag(&mut self, name: &str, params: Option<Sp>, sp: Sp) {
        if is_include(name) {
            let label = params.map_or("", |p| self.text(p)).trim().to_owned();
            self.record(SpanKind::Construct(ConstructKind::Include), sp, label);
        } else {
            self.record(
                SpanKind::Construct(ConstructKind::Macro),
                sp,
                name.to_owned(),
            );
        }
    }

    /// The first parameterless tag named `name` in `(after, hi)`.
    fn closer(&self, name: &str, after: usize, hi: usize) -> Option<usize> {
        let list = self.closers.get(&name.to_ascii_lowercase())?;
        let idx = list.partition_point(|&x| x <= after);
        list.get(idx).copied().filter(|&c| c < hi)
    }

    // ---------------------------------------------------------------- blocks

    fn blocks(&mut self, lo: usize, hi: usize, depth: usize) -> Vec<Block> {
        let hi = hi.min(self.toks.len());
        let mut out = Vec::new();
        let mut pending = Pending::None;
        let mut i = lo;
        while i < hi {
            match self.classify(i, hi) {
                Line::Blank { next } => {
                    self.flush(&mut pending, &mut out, depth);
                    i = next;
                }
                Line::Code(f) => {
                    self.flush(&mut pending, &mut out, depth);
                    if let Some(b) = self.code_block(f) {
                        out.push(b);
                    }
                    i = f + 1;
                }
                Line::Tag(f) => match self.tag_block(f, hi, depth) {
                    Some((block, next)) => {
                        self.flush(&mut pending, &mut out, depth);
                        out.push(block);
                        i = next;
                    }
                    None => {
                        let (cut, next) = self.cut(f, hi);
                        self.para_line(&mut pending, &mut out, depth, f, cut);
                        i = next;
                    }
                },
                Line::Content { f, cut, next, kind } => {
                    match kind {
                        LineKind::Heading(level, at) => {
                            self.flush(&mut pending, &mut out, depth);
                            let toks = self.slice_from(f, cut, at);
                            let inlines = trim(self.inlines(&toks, depth, false));
                            out.push(Block::Heading { level, inlines });
                        }
                        LineKind::Bq(at) => {
                            self.flush(&mut pending, &mut out, depth);
                            let toks = self.slice_from(f, cut, at);
                            let inlines = trim(self.inlines(&toks, depth, false));
                            let inner = if inlines.is_empty() {
                                Vec::new()
                            } else {
                                vec![Block::Paragraph(inlines)]
                            };
                            out.push(Block::Quote(inner));
                        }
                        LineKind::Rule => {
                            self.flush(&mut pending, &mut out, depth);
                            out.push(Block::Rule);
                        }
                        LineKind::ListItem {
                            depth: d,
                            ordered,
                            at,
                        } => {
                            if !matches!(pending, Pending::List { .. }) {
                                self.flush(&mut pending, &mut out, depth);
                                pending = Pending::List {
                                    ordered,
                                    items: Vec::new(),
                                };
                            }
                            let toks = self.slice_from(f, cut, at);
                            let inlines = trim(self.inlines(&toks, depth, false));
                            if let Pending::List { items, .. } = &mut pending {
                                items.push((d, inlines));
                            }
                        }
                        LineKind::TableRow => {
                            if !matches!(pending, Pending::Table(_)) {
                                self.flush(&mut pending, &mut out, depth);
                                pending = Pending::Table(Vec::new());
                            }
                            let row = self.table_row(f, cut, depth);
                            if let Pending::Table(rows) = &mut pending {
                                rows.push(row);
                            }
                        }
                        LineKind::Text => self.para_line(&mut pending, &mut out, depth, f, cut),
                    }
                    i = next;
                }
            }
        }
        self.flush(&mut pending, &mut out, depth);
        out
    }

    /// Adds the tokens `[f, cut)` to the open paragraph (opening one if needed).
    fn para_line(
        &mut self,
        pending: &mut Pending,
        out: &mut Vec<Block>,
        depth: usize,
        f: usize,
        cut: usize,
    ) {
        match pending {
            Pending::Para(_, end) => *end = cut,
            _ => {
                self.flush(pending, out, depth);
                *pending = Pending::Para(f, cut);
            }
        }
    }

    fn flush(&mut self, pending: &mut Pending, out: &mut Vec<Block>, depth: usize) {
        match std::mem::replace(pending, Pending::None) {
            Pending::None => {}
            Pending::Para(lo, hi) => {
                let toks: &'a [Tok] = self.toks;
                let slice = toks.get(lo..hi).unwrap_or(&[]);
                let inlines = trim(self.inlines(slice, depth, false));
                if !inlines.is_empty() {
                    out.push(Block::Paragraph(inlines));
                }
            }
            Pending::List { ordered, items } => out.push(Block::List { ordered, items }),
            Pending::Table(rows) => out.push(Block::Table { rows }),
        }
    }

    /// The newline or code token ending the line that contains `f` (or `hi`), and where the
    /// next line starts.
    fn cut(&self, f: usize, hi: usize) -> (usize, usize) {
        let mut j = f;
        while j < hi {
            match self.kind_at(j) {
                Some(TokKind::Newline) => return (j, j + 1),
                Some(TokKind::Code { .. }) | None => return (j, j),
                Some(_) => j += 1,
            }
        }
        (hi, hi)
    }

    fn classify(&self, i: usize, hi: usize) -> Line {
        let mut j = i;
        let f = loop {
            let Some(t) = self.toks.get(j).filter(|_| j < hi) else {
                return Line::Blank { next: hi };
            };
            match t.kind {
                TokKind::Newline => return Line::Blank { next: j + 1 },
                _ if self.is_blank(t) => j += 1,
                _ => break j,
            }
        };
        match self.kind_at(f) {
            Some(TokKind::Code { .. }) => return Line::Code(f),
            Some(TokKind::Tag { .. }) => return Line::Tag(f),
            _ => {}
        }
        let (cut, next) = self.cut(f, hi);
        let start = self.toks.get(f).map_or(self.src.len(), |t| t.sp.start);
        let end = self.toks.get(cut).map_or(self.src.len(), |t| t.sp.start);
        let line = self.src.get(start..end).unwrap_or("");
        let kind = line_kind(line, start);
        Line::Content { f, cut, next, kind }
    }

    /// The tokens `[f, cut)` from byte `at` on: tokens ending at or before `at` are dropped,
    /// a text token straddling it is trimmed.
    fn slice_from(&self, f: usize, cut: usize, at: usize) -> Vec<Tok> {
        let slice = self.toks.get(f..cut).unwrap_or(&[]);
        slice
            .iter()
            .filter(|t| t.sp.end > at)
            .map(|t| {
                if t.sp.start < at && t.kind == TokKind::Text {
                    Tok {
                        kind: TokKind::Text,
                        sp: Sp {
                            start: at,
                            end: t.sp.end,
                        },
                    }
                } else {
                    *t
                }
            })
            .collect()
    }

    fn code_block(&mut self, f: usize) -> Option<Block> {
        let t = *self.toks.get(f)?;
        let TokKind::Code { kind, params, body } = t.kind else {
            return None;
        };
        let (label, lang) = match kind {
            CodeKind::Code => ("code", params.and_then(|p| code_lang(self.text(p)))),
            CodeKind::Noformat => ("noformat", None),
        };
        self.record(
            SpanKind::Construct(ConstructKind::Macro),
            t.sp,
            label.to_owned(),
        );
        Some(Block::Code {
            kind,
            lang,
            body: self.text(body).to_owned(),
            byte_range: t.sp.range(),
        })
    }

    /// A tag that starts a line: a container, a paired body macro, or a tag alone on its
    /// line. `None` = it is part of a paragraph line.
    fn tag_block(&mut self, f: usize, hi: usize, depth: usize) -> Option<(Block, usize)> {
        let t = *self.toks.get(f)?;
        let TokKind::Tag {
            name: name_sp,
            params,
        } = t.kind
        else {
            return None;
        };
        let name = self.text(name_sp);
        let lname = name.to_ascii_lowercase();
        let params_text = params.map_or("", |p| self.text(p)).to_owned();
        if depth < MAX_DEPTH
            && !UNPAIRED.contains(&lname.as_str())
            && let Some(c) = self.closer(&lname, f, hi)
        {
            let close = *self.toks.get(c)?;
            let sp = Sp {
                start: t.sp.start,
                end: close.sp.end,
            };
            self.record(
                SpanKind::Construct(ConstructKind::Macro),
                sp,
                name.to_owned(),
            );
            let inner = self.blocks(f + 1, c, depth + 1);
            let block = match lname.as_str() {
                QUOTE => Block::Quote(inner),
                PANEL => Block::Panel {
                    title: panel_title(&params_text),
                    blocks: inner,
                },
                _ => {
                    // The parsed blocks are dropped (their spans are kept); the body is raw.
                    let body = self
                        .src
                        .get(t.sp.end..close.sp.start)
                        .unwrap_or("")
                        .to_owned();
                    Block::Macro {
                        name: name.to_owned(),
                        params: params_text,
                        body: Some(body),
                        byte_range: sp.range(),
                    }
                }
            };
            return Some((block, c + 1));
        }
        let (cut, next) = self.cut(f + 1, hi);
        let alone = self
            .toks
            .get(f + 1..cut)
            .unwrap_or(&[])
            .iter()
            .all(|x| self.is_blank(x));
        if !alone {
            return None;
        }
        self.record_tag(name, params, t.sp);
        let block = Block::Macro {
            name: name.to_owned(),
            params: params_text,
            body: None,
            byte_range: t.sp.range(),
        };
        Some((block, next))
    }

    fn table_row(&mut self, f: usize, cut: usize, depth: usize) -> TableRow {
        let toks: &'a [Tok] = self.toks;
        let row = toks.get(f..cut).unwrap_or(&[]);
        let mut cells = Vec::new();
        let mut k = 0;
        while k < row.len() {
            let mut header = false;
            if is_punct(row, k, '|') {
                if is_punct(row, k + 1, '|') {
                    header = true;
                    k += 2;
                } else {
                    k += 1;
                }
            }
            let start = k;
            while k < row.len() && !is_punct(row, k, '|') {
                k = self.skip_construct(row, k).unwrap_or(k + 1);
            }
            let cell = row.get(start..k).unwrap_or(&[]);
            if k >= row.len() && cell.iter().all(|t| self.is_blank(t)) {
                break;
            }
            let inlines = trim(self.inlines(cell, depth, false));
            cells.push(TableCell { header, inlines });
        }
        TableRow { cells }
    }

    // ---------------------------------------------------------------- inline pass 1

    /// Parses inline tokens. `in_link`: inside link, image or mention content, where bare URLs
    /// are plain text (the enclosing construct is the link).
    fn inlines(&mut self, toks: &[Tok], depth: usize, in_link: bool) -> Vec<Inline> {
        let inner = (depth + 1).min(MAX_DEPTH);
        let mut units: Vec<Unit> = Vec::with_capacity(toks.len());
        let mut k = 0;
        while let Some(&t) = toks.get(k) {
            match t.kind {
                TokKind::Tag { name, params } => {
                    let name = self.text(name);
                    self.record_tag(name, params, t.sp);
                    units.push(Unit::Atom(Inline::Macro {
                        name: name.to_owned(),
                        params: params.map_or("", |p| self.text(p)).to_owned(),
                        byte_range: t.sp.range(),
                    }));
                }
                TokKind::Code { kind, params, .. } => {
                    // Blocks cut lines at code tokens; kept here only as a fail-closed fallback.
                    let name = match kind {
                        CodeKind::Code => "code",
                        CodeKind::Noformat => "noformat",
                    };
                    self.record(
                        SpanKind::Construct(ConstructKind::Macro),
                        t.sp,
                        name.to_owned(),
                    );
                    units.push(Unit::Atom(Inline::Macro {
                        name: name.to_owned(),
                        params: params.map_or("", |p| self.text(p)).to_owned(),
                        byte_range: t.sp.range(),
                    }));
                }
                TokKind::Url if !in_link => {
                    let target = self.text(t.sp).to_owned();
                    self.record(SpanKind::Link, t.sp, target.clone());
                    units.push(Unit::Atom(Inline::Link { text: None, target }));
                }
                TokKind::Break => units.push(Unit::Atom(Inline::LineBreak)),
                TokKind::Punct('[') => {
                    if let Some(m) = bracket_close(toks, k) {
                        let content = toks.get(k + 1..m).unwrap_or(&[]);
                        let end = toks.get(m).map_or(t.sp.end, |x| x.sp.end);
                        let sp = Sp {
                            start: t.sp.start,
                            end,
                        };
                        if self.bracket(content, sp, inner, &mut units) {
                            k = m + 1;
                            continue;
                        }
                    }
                    units.push(Unit::Tok(t));
                }
                TokKind::Punct('!') => {
                    if let Some(m) = self.image_close(toks, k) {
                        let content = toks.get(k + 1..m).unwrap_or(&[]);
                        let end = toks.get(m).map_or(t.sp.end, |x| x.sp.end);
                        let sp = Sp {
                            start: t.sp.start,
                            end,
                        };
                        if self.image(content, sp, inner, &mut units) {
                            k = m + 1;
                            continue;
                        }
                    }
                    units.push(Unit::Tok(t));
                }
                TokKind::MonoOpen => {
                    if let Some(m) = mono_close(toks, k) {
                        let content = toks.get(k + 1..m).unwrap_or(&[]);
                        self.mono(content, inner, &mut units);
                        k = m + 1;
                        continue;
                    }
                    units.push(Unit::Tok(t));
                }
                _ => units.push(Unit::Tok(t)),
            }
            k += 1;
        }
        self.emphasis(&units, depth)
    }

    /// `[…]` content: a mention, attachment or link; constructs inside the brackets follow
    /// it as siblings. `false` = not a construct (`[]`, `[x|]`); decided before any content
    /// is parsed, so a rejected bracket records nothing.
    fn bracket(&mut self, content: &[Tok], sp: Sp, depth: usize, units: &mut Vec<Unit>) -> bool {
        let pipe = content.iter().position(|t| t.kind == TokKind::Punct('|'));
        let (text_toks, target_toks) = match pipe {
            Some(p) => (
                content.get(..p).unwrap_or(&[]),
                content.get(p + 1..).unwrap_or(&[]),
            ),
            None => (&[][..], content),
        };
        let whole = self.flatten(content);
        let whole = whole.trim();
        let target = self.flatten(target_toks);
        let target = target.trim();
        let main = if let Some(rest) = whole.strip_prefix('~') {
            self.user_or_file(ConstructKind::Mention, rest, sp)
        } else if let Some(rest) = whole.strip_prefix('^') {
            self.user_or_file(ConstructKind::Attachment, rest, sp)
        } else if target.is_empty() {
            return false;
        } else if let Some(rest) = target.strip_prefix('~') {
            self.user_or_file(ConstructKind::Mention, rest, sp)
        } else if let Some(rest) = target.strip_prefix('^') {
            self.user_or_file(ConstructKind::Attachment, rest, sp)
        } else {
            self.record(SpanKind::Link, sp, target.to_owned());
            Inline::Link {
                text: None,
                target: target.to_owned(),
            }
        };
        let text_inl = self.inlines(text_toks, depth, true);
        let target_inl = self.inlines(target_toks, depth, true);
        let main = match main {
            Inline::Link { target, .. } if pipe.is_some() => Inline::Link {
                text: Some(plain(&text_inl)),
                target,
            },
            other => other,
        };
        units.push(Unit::Atom(main));
        let mut extra = Vec::new();
        constructs(&text_inl, &mut extra);
        constructs(&target_inl, &mut extra);
        units.extend(extra.into_iter().map(Unit::Atom));
        true
    }

    /// A mention or attachment from the text after `~`/`^` (up to a `|`).
    fn user_or_file(&mut self, kind: ConstructKind, rest: &str, sp: Sp) -> Inline {
        let value = rest.split('|').next().unwrap_or("").trim().to_owned();
        self.record(SpanKind::Construct(kind), sp, value.clone());
        match kind {
            ConstructKind::Mention => Inline::Mention(value),
            _ => Inline::Attachment(value),
        }
    }

    /// `!…!` content. `false` = empty target.
    fn image(&mut self, content: &[Tok], sp: Sp, depth: usize, units: &mut Vec<Unit>) -> bool {
        let pipe = content.iter().position(|t| t.kind == TokKind::Punct('|'));
        let target_toks = pipe.map_or(content, |p| content.get(..p).unwrap_or(&[]));
        let flat = self.flatten(target_toks);
        let target = flat.trim();
        if target.is_empty() {
            return false;
        }
        self.record(
            SpanKind::Construct(ConstructKind::Image),
            sp,
            target.to_owned(),
        );
        units.push(Unit::Atom(Inline::Image(target.to_owned())));
        let inl = self.inlines(content, depth, true);
        let mut extra = Vec::new();
        constructs(&inl, &mut extra);
        units.extend(extra.into_iter().map(Unit::Atom));
        true
    }

    /// `{{…}}` content: text runs become `Monospace` segments, constructs stay in between.
    fn mono(&mut self, content: &[Tok], depth: usize, units: &mut Vec<Unit>) {
        let inl = self.inlines(content, depth, false);
        let mut buf = String::new();
        let mut parts = Vec::new();
        split_mono(&inl, &mut buf, &mut parts);
        if !buf.is_empty() {
            parts.push(Inline::Monospace(buf));
        }
        units.extend(parts.into_iter().map(Unit::Atom));
    }

    /// The unescaped source text of `toks` (for labels and targets).
    fn flatten(&self, toks: &[Tok]) -> String {
        let mut s = String::new();
        for t in toks {
            match t.kind {
                TokKind::Esc(c) | TokKind::Punct(c) => s.push(c),
                _ => s.push_str(self.text(t.sp)),
            }
        }
        s
    }

    /// The index of the `!` closing an image opened at `k`.
    fn image_close(&self, toks: &[Tok], k: usize) -> Option<usize> {
        let open = toks.get(k)?;
        if char_at(self.src, open.sp.end).is_none_or(char::is_whitespace) {
            return None;
        }
        let mut m = k + 1;
        loop {
            match toks.get(m)?.kind {
                TokKind::Newline => return None,
                TokKind::Punct('!') => break,
                _ => m += 1,
            }
        }
        let close = toks.get(m)?;
        let before_ok = char_before(self.src, close.sp.start).is_some_and(|c| !c.is_whitespace());
        (m > k + 1 && before_ok).then_some(m)
    }

    /// Skips a bracket, image or monospace construct starting at `k` (table cell splitting).
    fn skip_construct(&self, toks: &[Tok], k: usize) -> Option<usize> {
        let m = match toks.get(k)?.kind {
            TokKind::Punct('[') => bracket_close(toks, k)?,
            TokKind::Punct('!') => self.image_close(toks, k)?,
            TokKind::MonoOpen => mono_close(toks, k)?,
            _ => return None,
        };
        Some(m + 1)
    }

    // ---------------------------------------------------------------- inline pass 2

    fn is_opener(&self, t: &Tok) -> bool {
        char_before(self.src, t.sp.start).is_none_or(|c| !c.is_alphanumeric())
            && char_at(self.src, t.sp.end).is_some_and(|c| !c.is_whitespace())
    }

    fn is_closer(&self, t: &Tok) -> bool {
        char_before(self.src, t.sp.start).is_some_and(|c| !c.is_whitespace())
            && char_at(self.src, t.sp.end).is_none_or(|c| !c.is_alphanumeric())
    }

    /// Matches `*strong*`, `_emphasis_` and `-strike-` around the atoms of pass 1. A span
    /// closes at the first eligible closer of its delimiter on the same line.
    fn emphasis(&self, units: &[Unit], depth: usize) -> Vec<Inline> {
        let mut out = InlineBuf::default();
        if depth >= MAX_DEPTH {
            units.iter().for_each(|u| out.push_unit(self, u));
            return out.finish();
        }
        let n = units.len();
        let mut next_nl = vec![n; n + 1];
        for k in (0..n).rev() {
            let nl = matches!(units.get(k), Some(Unit::Tok(t)) if t.kind == TokKind::Newline);
            let after = next_nl.get(k + 1).copied().unwrap_or(n);
            if let Some(slot) = next_nl.get_mut(k) {
                *slot = if nl { k } else { after };
            }
        }
        let mut closers: [Vec<usize>; 3] = Default::default();
        for (k, u) in units.iter().enumerate() {
            if let Unit::Tok(t) = u
                && let Some(d) = delim(t)
                && self.is_closer(t)
                && let Some(list) = closers.get_mut(d)
            {
                list.push(k);
            }
        }
        let mut ptr = [0usize; 3];
        let mut k = 0;
        while let Some(u) = units.get(k) {
            if let Unit::Tok(t) = u
                && let Some(d) = delim(t)
                && self.is_opener(t)
                && let (Some(list), Some(p)) = (closers.get(d), ptr.get_mut(d))
            {
                while list.get(*p).is_some_and(|&c| c < k + 2) {
                    *p += 1;
                }
                let line_end = next_nl.get(k).copied().unwrap_or(n);
                if let Some(&c) = list.get(*p).filter(|&&c| c < line_end) {
                    let inner = self.emphasis(units.get(k + 1..c).unwrap_or(&[]), depth + 1);
                    out.push(match d {
                        0 => Inline::Strong(inner),
                        1 => Inline::Emphasis(inner),
                        _ => Inline::Strike(inner),
                    });
                    k = c + 1;
                    continue;
                }
            }
            out.push_unit(self, u);
            k += 1;
        }
        out.finish()
    }
}

/// Emphasis delimiter index: `*` strong, `_` emphasis, `-` strike.
fn delim(t: &Tok) -> Option<usize> {
    match t.kind {
        TokKind::Punct('*') => Some(0),
        TokKind::Punct('_') => Some(1),
        TokKind::Punct('-') => Some(2),
        _ => None,
    }
}

fn is_punct(toks: &[Tok], k: usize, c: char) -> bool {
    toks.get(k).is_some_and(|t| t.kind == TokKind::Punct(c))
}

/// The `]` closing the `[` at `k`: the innermost pair on the line (another `[` first means
/// this one is literal).
fn bracket_close(toks: &[Tok], k: usize) -> Option<usize> {
    let mut m = k + 1;
    loop {
        match toks.get(m)?.kind {
            TokKind::Punct(']') => return Some(m),
            TokKind::Punct('[') | TokKind::Newline => return None,
            _ => m += 1,
        }
    }
}

/// The `}}` closing the `{{` at `k`, with non-empty content and no `{{` or newline between.
fn mono_close(toks: &[Tok], k: usize) -> Option<usize> {
    let mut m = k + 1;
    loop {
        match toks.get(m)?.kind {
            TokKind::MonoClose => return (m > k + 1).then_some(m),
            TokKind::MonoOpen | TokKind::Newline => return None,
            _ => m += 1,
        }
    }
}

/// Classifies a line by its leading marker; `start` is the line's byte offset.
fn line_kind(line: &str, start: usize) -> LineKind {
    let b = line.as_bytes();
    let ws_or_end = |i: usize| b.get(i).is_none_or(|c| c.is_ascii_whitespace());
    if let (Some(&b'h'), Some(&d @ b'1'..=b'6'), Some(&b'.')) = (b.first(), b.get(1), b.get(2))
        && ws_or_end(3)
    {
        return LineKind::Heading(d - b'0', start + 3);
    }
    if line.starts_with("bq.") && ws_or_end(3) {
        return LineKind::Bq(start + 3);
    }
    if line.trim_end() == "----" {
        return LineKind::Rule;
    }
    let run = b.iter().take_while(|c| matches!(c, b'*' | b'#')).count();
    if run > 0 && b.get(run).is_some_and(|c| matches!(c, b' ' | b'\t')) {
        let ordered = b.get(run - 1) == Some(&b'#');
        let depth = u8::try_from(run).unwrap_or(u8::MAX);
        return LineKind::ListItem {
            depth,
            ordered,
            at: start + run,
        };
    }
    if b.first() == Some(&b'-') && b.get(1).is_some_and(|c| matches!(c, b' ' | b'\t')) {
        return LineKind::ListItem {
            depth: 1,
            ordered: false,
            at: start + 1,
        };
    }
    if b.first() == Some(&b'|') {
        return LineKind::TableRow;
    }
    LineKind::Text
}

/// `{code:java}` / `{code:language=java|title=x}` → `java`.
fn code_lang(params: &str) -> Option<String> {
    let first = params.split('|').next().unwrap_or("").trim();
    let lang = if first.contains('=') {
        params.split('|').find_map(|p| {
            let (k, v) = p.split_once('=')?;
            matches!(k.trim(), "language" | "lang").then(|| v.trim())
        })?
    } else {
        first
    };
    (!lang.is_empty()).then(|| lang.to_owned())
}

/// `{panel:title=Note|borderStyle=solid}` → `Note`.
fn panel_title(params: &str) -> Option<String> {
    params.split('|').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k.trim() == "title").then(|| v.trim().to_owned())
    })
}

/// The plain text of link text (constructs are siblings, so they are left out).
fn plain(inlines: &[Inline]) -> String {
    let mut s = String::new();
    for i in inlines {
        match i {
            Inline::Text(t) | Inline::Monospace(t) => s.push_str(t),
            Inline::Strong(c) | Inline::Emphasis(c) | Inline::Strike(c) => s.push_str(&plain(c)),
            Inline::LineBreak => s.push(' '),
            _ => {}
        }
    }
    s.trim().to_owned()
}

/// Every construct (macro, mention, image, attachment, link) inside `inlines`.
fn constructs(inlines: &[Inline], out: &mut Vec<Inline>) {
    for i in inlines {
        match i {
            Inline::Strong(c) | Inline::Emphasis(c) | Inline::Strike(c) => constructs(c, out),
            Inline::Macro { .. }
            | Inline::Mention(_)
            | Inline::Image(_)
            | Inline::Attachment(_)
            | Inline::Link { .. } => out.push(i.clone()),
            Inline::Text(_) | Inline::Monospace(_) | Inline::LineBreak => {}
        }
    }
}

/// Flattens monospace content: text into `buf`, everything else between segments.
fn split_mono(inlines: &[Inline], buf: &mut String, parts: &mut Vec<Inline>) {
    for i in inlines {
        match i {
            Inline::Text(t) | Inline::Monospace(t) => buf.push_str(t),
            Inline::Strong(c) | Inline::Emphasis(c) | Inline::Strike(c) => {
                split_mono(c, buf, parts);
            }
            other => {
                if !buf.is_empty() {
                    parts.push(Inline::Monospace(std::mem::take(buf)));
                }
                parts.push(other.clone());
            }
        }
    }
}

/// Trims leading and trailing whitespace of a block's inlines.
fn trim(mut v: Vec<Inline>) -> Vec<Inline> {
    if let Some(Inline::Text(t)) = v.first_mut() {
        *t = t.trim_start().to_owned();
    }
    if let Some(Inline::Text(t)) = v.last_mut() {
        *t = t.trim_end().to_owned();
    }
    v.retain(|i| !matches!(i, Inline::Text(t) if t.is_empty()));
    v
}

/// Collects inlines, merging adjacent text.
#[derive(Default)]
struct InlineBuf {
    out: Vec<Inline>,
}

impl InlineBuf {
    fn push_text(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        if let Some(Inline::Text(t)) = self.out.last_mut() {
            t.push_str(s);
        } else {
            self.out.push(Inline::Text(s.to_owned()));
        }
    }

    fn push(&mut self, i: Inline) {
        match i {
            Inline::Text(t) => self.push_text(&t),
            other => self.out.push(other),
        }
    }

    fn push_unit(&mut self, p: &Parser<'_>, u: &Unit) {
        match u {
            Unit::Atom(i) => self.push(i.clone()),
            Unit::Tok(t) => match t.kind {
                TokKind::Esc(c) | TokKind::Punct(c) => {
                    let mut b = [0u8; 4];
                    self.push_text(c.encode_utf8(&mut b));
                }
                TokKind::Newline | TokKind::Break => self.out.push(Inline::LineBreak),
                _ => self.push_text(p.text(t.sp)),
            },
        }
    }

    fn finish(self) -> Vec<Inline> {
        self.out
    }
}
