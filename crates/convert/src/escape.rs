//! Text escaping for Jira wiki markup (spec §7.6), written against the grammar of
//! [`crate::wiki`] so that escaped text always parses back as literal text:
//!
//! - `{ } [ ] | ! + ~ ^` always get a backslash (`\{`). As the first non-blank char of link
//!   text, `~`/`^` become `&#126;`/`&#94;` instead: the parser (like Jira) classifies
//!   `[\~x|…]` as a mention by its unescaped text.
//! - `* _ -` get a backslash unless both neighbours are alphanumeric (then they can neither
//!   open nor close emphasis); `?` gets one next to another `?` (`??` citation).
//! - At a line start (only whitespace before it on the line): `#` gets a backslash, and the
//!   `h` of `h1.`–`h6.` and the `b` of `bq.` become `&#104;`/`&#98;` (neither `h`, `b`, `q`
//!   nor `.` is escapable).
//! - `\` is always `&#92;`: `\\` is a forced line break and `\` before an escapable char an
//!   escape, so a literal backslash has no backslash form.
//! - `&` before something entity-like (`&name;`, `&#n;`) becomes `&#38;`, so text never turns
//!   into a character reference.
//! - A bare URL (as the parser finds one) is copied unchanged apart from the `&` rule, so it
//!   stays one link. When what the output writes next would extend it (an emphasis `_`/`-`
//!   delimiter, a character reference such as `&#92;`), it is written as `[url|url]` instead,
//!   so the link target ends where the source URL ended.
//!
//! Character references survive Jira's renderer (it keeps existing entities), so every
//! replacement above renders as the original char.

use crate::wiki::lexer::{URL_STOP, URL_TRAIL, bare_url_end};

/// Escapes `s` as wiki text at the start of a line; newlines are kept (each new line is a
/// line start again).
pub fn wiki_text(s: &str) -> String {
    let mut out = Out::para();
    out.text(s);
    out.into_string()
}

/// Where emphasis content starts in an [`Out`], with the state before its opening delimiter.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SpanMark {
    /// Byte offset just after the opening delimiter.
    start: usize,
    line_blank: bool,
    link_lead: bool,
}

/// An output buffer that knows the context the escaping depends on.
#[derive(Debug)]
pub(crate) struct Out {
    s: String,
    /// The char before `s` in the final output (used while `s` is empty).
    before: Option<char>,
    /// Only whitespace since the last line start.
    line_blank: bool,
    /// Link text with only whitespace so far.
    link_lead: bool,
    /// Newlines may be written (paragraphs); otherwise they become spaces.
    multiline: bool,
    /// Open emphasis spans; no newline is written inside one (Jira emphasis is one line).
    spans: usize,
    /// Link text: the parser finds no bare URLs in it.
    link: bool,
    /// The last bare URL written (`start..end` in `s`) while nothing but URL-trailing
    /// punctuation follows it.
    url: Option<(usize, usize)>,
}

impl Out {
    fn new(before: Option<char>, line_blank: bool, link_lead: bool, multiline: bool) -> Out {
        Out {
            s: String::new(),
            before,
            line_blank,
            link_lead,
            multiline,
            spans: 0,
            link: false,
            url: None,
        }
    }

    /// A paragraph: starts a line, newlines kept.
    pub(crate) fn para() -> Out {
        Out::new(None, true, false, true)
    }

    /// One-line content written after `before` (a heading, list item, table cell, …).
    pub(crate) fn inline(before: char) -> Out {
        Out::new(Some(before), false, false, false)
    }

    /// Link text, written after its `[`.
    pub(crate) fn link() -> Out {
        Out {
            link: true,
            ..Out::new(Some('['), false, true, false)
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.s
    }

    pub(crate) fn into_string(self) -> String {
        self.s
    }

    pub(crate) fn is_blank(&self) -> bool {
        self.s.trim().is_empty()
    }

    fn prev(&self) -> Option<char> {
        self.s.chars().next_back().or(self.before)
    }

    fn breaks_lines(&self) -> bool {
        self.multiline && self.spans == 0
    }

    fn push(&mut self, c: char) {
        if let Some(span) = self.url.take() {
            if c.is_whitespace() || URL_STOP.contains(&c) {
                // The URL ends here for the parser as well.
            } else if URL_TRAIL.contains(&c) {
                self.url = Some(span);
            } else {
                self.link_url(span);
            }
        }
        self.s.push(c);
        if c == '\n' {
            self.line_blank = true;
        } else if !c.is_whitespace() {
            self.line_blank = false;
            self.link_lead = false;
        }
    }

    /// Markup written as is.
    pub(crate) fn raw(&mut self, markup: &str) {
        markup.chars().for_each(|c| self.push(c));
    }

    fn escaped(&mut self, c: char) {
        self.push('\\');
        self.push(c);
    }

    fn newline(&mut self) {
        if self.breaks_lines() {
            self.push('\n');
        } else {
            self.push(' ');
        }
    }

    pub(crate) fn soft_break(&mut self) {
        self.newline();
    }

    pub(crate) fn hard_break(&mut self) {
        if self.breaks_lines() {
            self.push('\n');
        } else {
            self.raw("\\\\");
        }
    }

    /// Escaped text on one line (newlines become spaces), e.g. inline code.
    pub(crate) fn text_one_line(&mut self, t: &str) {
        let multiline = self.multiline;
        self.multiline = false;
        self.text(t);
        self.multiline = multiline;
    }

    /// Escaped text.
    pub(crate) fn text(&mut self, t: &str) {
        let mut i = 0;
        while let Some(c) = t.get(i..).and_then(|r| r.chars().next()) {
            let next_i = i + c.len_utf8();
            let rest = t.get(next_i..).unwrap_or("");
            let next = rest.chars().next();
            let prev = self.prev();
            if !prev.is_some_and(char::is_alphanumeric)
                && let Some(end) = bare_url_end(t, i)
            {
                self.url(t, i, end);
                i = end;
                continue;
            }
            let alnum_both =
                prev.is_some_and(char::is_alphanumeric) && next.is_some_and(char::is_alphanumeric);
            match c {
                '\r' => {
                    self.newline();
                    if next == Some('\n') {
                        i = next_i + 1;
                        continue;
                    }
                }
                '\n' => self.newline(),
                '\\' => self.raw("&#92;"),
                '&' if entity_like(rest) => self.raw("&#38;"),
                '{' | '}' | '[' | ']' | '|' | '!' | '+' => self.escaped(c),
                '~' if self.link_lead => self.raw("&#126;"),
                '^' if self.link_lead => self.raw("&#94;"),
                '~' | '^' => self.escaped(c),
                '*' | '_' | '-' if !alnum_both => self.escaped(c),
                '?' if prev == Some('?') || next == Some('?') => self.escaped(c),
                '#' if self.line_blank => self.escaped(c),
                'h' if self.line_blank && heading_marker(rest) => self.raw("&#104;"),
                'b' if self.line_blank && quote_marker(rest) => self.raw("&#98;"),
                _ => self.push(c),
            }
            i = next_i;
        }
    }

    /// The bare URL `t[start..end]`: unchanged except for entity-like `&` (judged on the
    /// whole rest of `t`: a trailing `;` is not part of the URL but still ends an entity).
    fn url(&mut self, t: &str, start: usize, end: usize) {
        let Some(url) = t.get(start..end) else {
            return;
        };
        // Its first char would extend a URL written just before.
        if let Some(span) = self.url.take() {
            self.link_url(span);
        }
        let from = self.s.len();
        for (j, c) in url.char_indices() {
            let after = t.get(start + j + 1..).unwrap_or("");
            match c {
                '&' if entity_like(after) => self.raw("&#38;"),
                _ => self.push(c),
            }
        }
        if !self.link {
            self.url = Some((from, self.s.len()));
        }
    }

    /// Rewrites the bare URL at `span` as `[url|url]` (text escaped, target as is), keeping
    /// the trailing punctuation that follows it.
    fn link_url(&mut self, (start, end): (usize, usize)) {
        let (Some(url), Some(tail)) = (self.s.get(start..end), self.s.get(end..)) else {
            return;
        };
        let (url, tail) = (url.to_owned(), tail.to_owned());
        let mut text = String::with_capacity(url.len() + 8);
        let mut prev: Option<char> = None;
        let mut chars = url.chars().peekable();
        while let Some(c) = chars.next() {
            let next = chars.peek().copied();
            let both =
                prev.is_some_and(char::is_alphanumeric) && next.is_some_and(char::is_alphanumeric);
            match c {
                '_' | '-' if both => text.push(c),
                '?' if prev == Some('?') || next == Some('?') => {
                    text.push('\\');
                    text.push(c);
                }
                '_' | '-' | '+' | '~' | '^' => {
                    text.push('\\');
                    text.push(c);
                }
                _ => text.push(c),
            }
            prev = Some(c);
        }
        self.s.truncate(start);
        self.s.push('[');
        self.s.push_str(&text);
        self.s.push('|');
        self.s.push_str(&url);
        self.s.push(']');
        self.s.push_str(&tail);
    }

    /// Writes an emphasis delimiter and returns where its content starts.
    pub(crate) fn open_span(&mut self, delim: char) -> SpanMark {
        let (line_blank, link_lead) = (self.line_blank, self.link_lead);
        self.push(delim);
        self.spans += 1;
        SpanMark {
            start: self.s.len(),
            line_blank,
            link_lead,
        }
    }

    /// Closes the span opened at `mark`. Edge whitespace moves outside the delimiters (a
    /// delimiter next to whitespace opens or closes nothing); a blank span loses its opener.
    pub(crate) fn close_span(&mut self, mark: SpanMark, delim: char) {
        self.spans = self.spans.saturating_sub(1);
        let Some(opener) = mark.start.checked_sub(1) else {
            return;
        };
        let Some(content) = self.s.get(mark.start..) else {
            return;
        };
        if content.trim().is_empty() {
            if self.s.get(opener..mark.start).is_some() {
                self.s.replace_range(opener..mark.start, "");
                self.line_blank = mark.line_blank;
                self.link_lead = mark.link_lead;
            }
            return;
        }
        let lead = content.len() - content.trim_start().len();
        let trail = content.len() - content.trim_end().len();
        if lead > 0
            && self.s.get(opener..mark.start + lead).is_some()
            && let Some(ws) = self.s.get(mark.start..mark.start + lead)
        {
            let mut moved = ws.to_owned();
            moved.push(delim);
            self.s.replace_range(opener..mark.start + lead, &moved);
        }
        let cut = self.s.len() - trail;
        let Some(tail) = self.s.get(cut..).map(str::to_owned) else {
            return;
        };
        self.s.truncate(cut);
        self.push(delim);
        self.s.push_str(&tail);
    }
}

// The lookaheads below see the rest of the text only, so a text must not be split where
// markup does not follow (the converter joins consecutive text events first).

/// `&` + optional `#` + alphanumerics + `;`, the shape of a character reference (`after_amp` is
/// the text after the `&`). Shared with `md_to_wiki::link_target` (M5 final review M-4).
pub(crate) fn entity_like(after_amp: &str) -> bool {
    let body = after_amp.strip_prefix('#').unwrap_or(after_amp);
    let n = body.bytes().take_while(u8::is_ascii_alphanumeric).count();
    n > 0 && body.as_bytes().get(n) == Some(&b';')
}

/// `1.`–`6.` after an `h`.
fn heading_marker(after_h: &str) -> bool {
    matches!(after_h.as_bytes(), [b'1'..=b'6', b'.', ..])
}

/// `q.` after a `b`.
fn quote_marker(after_b: &str) -> bool {
    after_b.starts_with("q.")
}
