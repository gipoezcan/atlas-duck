//! One pass over the input (`char_indices` order) into tokens with byte spans.
//!
//! The lexer settles everything that must be decided globally before line structure:
//! backslash escapes, macro tags, the opaque `{code}`/`{noformat}` bodies (which may span
//! lines), `{{`/`}}` and bare URLs. Every span starts and ends on a char boundary.

use super::CodeKind;

/// Chars a backslash makes literal (Jira wiki's own escape).
pub(crate) const ESCAPABLE: [char; 14] = [
    '{', '}', '[', ']', '|', '!', '~', '*', '_', '^', '-', '+', '?', '#',
];

/// Chars that become [`TokKind::Punct`] tokens.
const PUNCT: [char; 11] = ['[', ']', '|', '!', '*', '_', '-', '+', '^', '~', '?'];

/// Bare-URL schemes (ASCII case-insensitive).
const SCHEMES: [&str; 5] = ["http://", "https://", "ftp://", "file://", "mailto:"];

/// Chars that end a bare URL.
pub(crate) const URL_STOP: [char; 11] = ['[', ']', '{', '}', '|', '!', '\\', '"', '<', '>', '*'];

/// Trailing chars dropped from a bare URL (sentence punctuation).
pub(crate) const URL_TRAIL: [char; 7] = ['.', ',', ';', ':', ')', '?', '\''];

/// A byte span of the source (`Copy`, unlike `Range`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sp {
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl Sp {
    pub(crate) fn range(self) -> std::ops::Range<usize> {
        self.start..self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokKind {
    /// Literal text (no newline).
    Text,
    /// `\` + an [`ESCAPABLE`] char: that char, literally.
    Esc(char),
    /// `\\`.
    Break,
    /// `\n`, `\r\n` or `\r`.
    Newline,
    Punct(char),
    /// `{{` with an unescaped `}}` later on the line.
    MonoOpen,
    /// `}}`.
    MonoClose,
    /// A bare URL.
    Url,
    /// `{name}` / `{name:params}`; `name` is trimmed.
    Tag {
        name: Sp,
        params: Option<Sp>,
    },
    /// `{code…}…{code}` / `{noformat…}…{noformat}` as one opaque token.
    Code {
        kind: CodeKind,
        params: Option<Sp>,
        body: Sp,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tok {
    pub(crate) kind: TokKind,
    pub(crate) sp: Sp,
}

pub(crate) fn char_at(src: &str, pos: usize) -> Option<char> {
    src.get(pos..).and_then(|s| s.chars().next())
}

pub(crate) fn char_before(src: &str, pos: usize) -> Option<char> {
    src.get(..pos).and_then(|s| s.chars().next_back())
}

/// A scanned macro tag.
struct TagScan {
    name: Sp,
    params: Option<Sp>,
    /// Offset just past the closing `}`.
    end: usize,
    /// No whitespace around the name.
    exact: bool,
}

fn is_name_char(c: char) -> bool {
    c.is_alphanumeric() || c == '-' || c == '_' || c == '.'
}

/// Scans a macro tag at `pos` (which must hold `{`). Escape-aware: an escaped `}` does not
/// close the tag. Fails at a newline, an unescaped `{` or the end of the input.
fn scan_tag(src: &str, pos: usize) -> Option<TagScan> {
    if char_at(src, pos) != Some('{') {
        return None;
    }
    let content_start = pos + 1;
    let mut i = content_start;
    let mut colon: Option<usize> = None;
    let close = loop {
        let c = char_at(src, i)?;
        match c {
            '}' => break i,
            '{' | '\n' | '\r' => return None,
            '\\' => match char_at(src, i + 1) {
                Some(n) if n == '\\' || ESCAPABLE.contains(&n) => i += 1 + n.len_utf8(),
                _ => i += 1,
            },
            ':' => {
                if colon.is_none() {
                    colon = Some(i);
                }
                i += 1;
            }
            _ => i += c.len_utf8(),
        }
    };
    let name_end = colon.unwrap_or(close);
    let raw = src.get(content_start..name_end)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.chars().all(is_name_char) {
        return None;
    }
    let lead = raw.len() - raw.trim_start().len();
    let name = Sp {
        start: content_start + lead,
        end: content_start + lead + trimmed.len(),
    };
    let params = colon.map(|c| Sp {
        start: c + 1,
        end: close,
    });
    Some(TagScan {
        name,
        params,
        end: close + 1,
        exact: trimmed.len() == raw.len(),
    })
}

/// Result of the escape-aware search for a `}}` on the rest of a line, cached so that a line
/// full of `{{` stays linear.
#[derive(Clone, Copy)]
struct MonoScan {
    from: usize,
    /// Where the scan stopped: the `}}` found, or the line end.
    stop: usize,
    found: bool,
}

struct Lexer<'a> {
    src: &'a str,
    pos: usize,
    toks: Vec<Tok>,
    text_start: Option<usize>,
    mono: Option<MonoScan>,
}

pub(crate) fn lex(src: &str) -> Vec<Tok> {
    let mut lx = Lexer {
        src,
        pos: 0,
        toks: Vec::new(),
        text_start: None,
        mono: None,
    };
    lx.run();
    lx.toks
}

impl Lexer<'_> {
    fn run(&mut self) {
        while let Some(c) = char_at(self.src, self.pos) {
            match c {
                '\\' => self.backslash(),
                '\n' => self.emit(TokKind::Newline, 1),
                '\r' => {
                    let len = if char_at(self.src, self.pos + 1) == Some('\n') {
                        2
                    } else {
                        1
                    };
                    self.emit(TokKind::Newline, len);
                }
                '{' => self.open_brace(),
                '}' if char_at(self.src, self.pos + 1) == Some('}') => {
                    self.emit(TokKind::MonoClose, 2);
                }
                c if PUNCT.contains(&c) => self.emit(TokKind::Punct(c), 1),
                c => {
                    if let Some(end) = self.url_end(c) {
                        let len = end - self.pos;
                        self.emit(TokKind::Url, len);
                    } else {
                        self.literal(c.len_utf8());
                    }
                }
            }
        }
        self.flush_text();
    }

    /// Extends the current text run by `len` bytes.
    fn literal(&mut self, len: usize) {
        if self.text_start.is_none() {
            self.text_start = Some(self.pos);
        }
        self.pos += len;
    }

    fn flush_text(&mut self) {
        if let Some(start) = self.text_start.take()
            && start < self.pos
        {
            self.toks.push(Tok {
                kind: TokKind::Text,
                sp: Sp {
                    start,
                    end: self.pos,
                },
            });
        }
    }

    fn emit(&mut self, kind: TokKind, len: usize) {
        self.flush_text();
        let start = self.pos;
        self.pos += len;
        self.toks.push(Tok {
            kind,
            sp: Sp {
                start,
                end: self.pos,
            },
        });
    }

    fn backslash(&mut self) {
        match char_at(self.src, self.pos + 1) {
            Some('\\') => self.emit(TokKind::Break, 2),
            Some(n) if ESCAPABLE.contains(&n) => self.emit(TokKind::Esc(n), 1 + n.len_utf8()),
            _ => self.literal(1),
        }
    }

    fn open_brace(&mut self) {
        let pos = self.pos;
        if char_at(self.src, pos + 1) == Some('{') {
            // `{{x} y}}`: the tag at the second brace wins (fail closed); `{{x}}` is monospace.
            if let Some(t) = scan_tag(self.src, pos + 1)
                && char_at(self.src, t.end) != Some('}')
            {
                self.literal(1);
                return;
            }
            if self.mono_closes(pos + 2) {
                self.emit(TokKind::MonoOpen, 2);
            } else {
                // Unclosed: the second brace is lexed on its own (it may open a tag).
                self.literal(1);
            }
            return;
        }
        let Some(t) = scan_tag(self.src, pos) else {
            self.literal(1);
            return;
        };
        let kind = match self.src.get(t.name.start..t.name.end) {
            Some("code") if t.exact => Some(CodeKind::Code),
            Some("noformat") if t.exact => Some(CodeKind::Noformat),
            _ => None,
        };
        match kind {
            Some(kind) => self.code(kind, t),
            None => {
                let len = t.end - pos;
                self.emit(
                    TokKind::Tag {
                        name: t.name,
                        params: t.params,
                    },
                    len,
                );
            }
        }
    }

    /// An opaque body up to the next literal closing tag (escapes are not honoured inside the
    /// body), or to the end of the input.
    fn code(&mut self, kind: CodeKind, t: TagScan) {
        let closer = match kind {
            CodeKind::Code => "{code}",
            CodeKind::Noformat => "{noformat}",
        };
        let rest = self.src.get(t.end..).unwrap_or("");
        let (body_end, end) = match rest.find(closer) {
            Some(off) => (t.end + off, t.end + off + closer.len()),
            None => (self.src.len(), self.src.len()),
        };
        let body = Sp {
            start: t.end,
            end: body_end,
        };
        let len = end - self.pos;
        self.emit(
            TokKind::Code {
                kind,
                params: t.params,
                body,
            },
            len,
        );
    }

    /// Whether an unescaped `}}` follows `from` on the same line.
    fn mono_closes(&mut self, from: usize) -> bool {
        if let Some(m) = self.mono
            && from >= m.from
            && from <= m.stop
        {
            return m.found;
        }
        let mut i = from;
        let found = loop {
            match char_at(self.src, i) {
                None | Some('\n') | Some('\r') => break false,
                Some('\\') => match char_at(self.src, i + 1) {
                    Some(n) if n == '\\' || ESCAPABLE.contains(&n) => i += 1 + n.len_utf8(),
                    _ => i += 1,
                },
                Some('}') if char_at(self.src, i + 1) == Some('}') => break true,
                Some(c) => i += c.len_utf8(),
            }
        };
        self.mono = Some(MonoScan {
            from,
            stop: i,
            found,
        });
        found
    }

    /// End of a bare URL starting at the current position, if one starts here.
    fn url_end(&self, c: char) -> Option<usize> {
        if !matches!(c, 'h' | 'H' | 'f' | 'F' | 'm' | 'M') {
            return None;
        }
        if char_before(self.src, self.pos).is_some_and(char::is_alphanumeric) {
            return None;
        }
        bare_url_end(self.src, self.pos)
    }
}

/// End of a bare URL starting at `pos` of `src`, if one starts there (the caller checks that
/// the char before `pos` is not alphanumeric). Shared with the converter's escaping, which
/// copies such URLs unchanged so that they stay links.
pub(crate) fn bare_url_end(src: &str, pos: usize) -> Option<usize> {
    let scheme = SCHEMES.iter().find(|s| {
        src.get(pos..pos + s.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(s))
    })?;
    let rest = src.get(pos..)?;
    let mut end = rest
        .char_indices()
        .find(|&(_, ch)| ch.is_whitespace() || URL_STOP.contains(&ch))
        .map_or(rest.len(), |(i, _)| i);
    while let Some(last) = rest.get(..end).and_then(|s| s.chars().next_back()) {
        if !URL_TRAIL.contains(&last) {
            break;
        }
        end -= last.len_utf8();
    }
    (end > scheme.len()).then_some(pos + end)
}
