//! Markdown to HTML for one page and one set.
//!
//! The workspace pins pulldown-cmark without its HTML renderer, and the generator needs its own
//! anyway: raw HTML is an error (no inline script, style or handler can reach the output), every
//! heading needs an explicit `{#anchor}` (so both languages share their anchors), and links are
//! restricted to `page-id[#anchor]`, `#anchor` and `http(s)://`.

use std::collections::BTreeSet;
use std::fmt::Write;

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};

use crate::frontmatter::{Mode, is_kebab};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Set {
    Desktop,
    Server,
}

impl Set {
    fn name(self) -> &'static str {
        match self {
            Set::Desktop => "desktop",
            Set::Server => "server",
        }
    }
}

/// Where a page is rendered: its set decides the link style, `page` is the page id (the target of
/// a `#anchor` link).
pub struct Ctx<'a> {
    pub set: Set,
    pub lang: &'a str,
    pub page: &'a str,
}

pub struct Heading {
    pub level: u8,
    pub id: String,
    pub text: String,
}

/// An internal link, checked against the set's manifest after every page is rendered.
pub struct Link {
    pub page: String,
    pub anchor: Option<String>,
}

/// The text under one heading (the lead has an empty anchor and heading), for the search index.
pub struct Section {
    pub anchor: String,
    pub heading: String,
    pub text: String,
}

pub struct Rendered {
    pub html: String,
    pub headings: Vec<Heading>,
    pub links: Vec<Link>,
    pub sections: Vec<Section>,
}

/// The href of page `page` (and `anchor`) for `lang` in `set`: `page.html#a` for the desktop set,
/// `/docs/<lang>/page#a` for the server set (the index page is `/docs/<lang>/`).
pub fn page_href(set: Set, lang: &str, page: &str, anchor: Option<&str>) -> String {
    let mut href = match set {
        Set::Desktop => format!("{page}.html"),
        Set::Server if page == "index" => format!("/docs/{lang}/"),
        Set::Server => format!("/docs/{lang}/{page}"),
    };
    if let Some(a) = anchor {
        href.push('#');
        href.push_str(a);
    }
    href
}

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// Keeps the lines of `::: desktop` / `::: server` blocks that belong to `set` and drops the
/// others (PD-323). Marker lines and dropped lines become blank lines. A marker inside a fenced
/// code block is text. Blocks are only allowed in a `both` page; they do not nest.
pub fn strip_modes(body: &str, page_mode: Mode, set: Set) -> Result<String, String> {
    let mut out = String::with_capacity(body.len());
    let mut open: Option<&str> = None;
    let mut fence: Option<char> = None;
    for (n, line) in body.lines().enumerate() {
        let n = n + 1;
        let trimmed = line.trim_start();
        let fence_char = ['`', '~']
            .into_iter()
            .find(|c| trimmed.starts_with(&c.to_string().repeat(3)));
        if let Some(c) = fence_char {
            match fence {
                None => fence = Some(c),
                Some(f) if f == c => fence = None,
                Some(_) => {}
            }
        }
        let marker =
            fence.is_none() && fence_char.is_none() && (line == ":::" || line.starts_with("::: "));
        if marker {
            if page_mode != Mode::Both {
                return Err(format!(
                    "line {n}: mode blocks are only allowed in a `mode: both` page"
                ));
            }
            if line == ":::" {
                if open.take().is_none() {
                    return Err(format!("line {n}: `:::` closes no block"));
                }
            } else {
                let name = line["::: ".len()..].trim();
                if open.is_some() {
                    return Err(format!("line {n}: mode blocks do not nest"));
                }
                match name {
                    "desktop" | "server" => open = Some(name),
                    other => return Err(format!("line {n}: unknown mode block `{other}`")),
                }
            }
            out.push('\n');
            continue;
        }
        if open.is_none_or(|b| b == set.name()) {
            out.push_str(line);
        }
        out.push('\n');
    }
    if open.is_some() {
        return Err("a mode block is not closed".into());
    }
    Ok(out)
}

/// Resolves a link destination to its href, the internal target (if any) and whether it is external.
fn link_target(dest: &str, ctx: &Ctx) -> Result<(String, Option<Link>, bool), String> {
    if dest.starts_with("http://") || dest.starts_with("https://") {
        return Ok((dest.to_string(), None, true));
    }
    let (page, anchor) = match dest.split_once('#') {
        Some((p, a)) => (p, Some(a)),
        None => (dest, None),
    };
    let page_ok = page.is_empty() && anchor.is_some() || is_kebab(page);
    let anchor_ok = anchor.is_none_or(is_kebab);
    if !page_ok || !anchor_ok {
        return Err(format!(
            "link `{dest}`: only `page-id`, `page-id#anchor`, `#anchor` and http(s) links are allowed"
        ));
    }
    let link = Link {
        page: if page.is_empty() {
            ctx.page.to_string()
        } else {
            page.to_string()
        },
        anchor: anchor.map(str::to_string),
    };
    let href = if page.is_empty() {
        format!("#{}", anchor.unwrap_or_default())
    } else {
        page_href(ctx.set, ctx.lang, page, anchor)
    };
    Ok((href, Some(link), false))
}

fn level_number(level: HeadingLevel) -> u8 {
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

struct Open {
    level: u8,
    id: String,
    text: String,
}

pub fn render_body(md: &str, ctx: &Ctx) -> Result<Rendered, String> {
    let mut html = String::new();
    let mut headings: Vec<Heading> = Vec::new();
    let mut links = Vec::new();
    let mut ids = BTreeSet::new();
    let mut sections = vec![Section {
        anchor: String::new(),
        heading: String::new(),
        text: String::new(),
    }];
    let mut heading: Option<Open> = None;
    let mut in_table_head = false;
    let parser = Parser::new_ext(
        md,
        Options::ENABLE_HEADING_ATTRIBUTES | Options::ENABLE_TABLES,
    );

    // The plain text of the current heading or section, for the TOC and the search index.
    fn plain(sections: &mut [Section], heading: &mut Option<Open>, text: &str) {
        match heading {
            Some(h) => h.text.push_str(text),
            None => {
                if let Some(s) = sections.last_mut() {
                    s.text.push_str(text);
                }
            }
        }
    }

    for event in parser {
        match event {
            Event::Html(_) | Event::InlineHtml(_) => {
                return Err("raw HTML is not allowed in the guide".into());
            }
            Event::Text(t) => {
                html.push_str(&escape(&t));
                plain(&mut sections, &mut heading, &t);
            }
            Event::Code(c) => {
                let _ = write!(html, "<code>{}</code>", escape(&c));
                plain(&mut sections, &mut heading, &c);
            }
            Event::SoftBreak => {
                html.push('\n');
                plain(&mut sections, &mut heading, " ");
            }
            Event::HardBreak => {
                html.push_str("<br>\n");
                plain(&mut sections, &mut heading, " ");
            }
            Event::Rule => html.push_str("<hr>\n"),
            Event::Start(tag) => match tag {
                Tag::Paragraph => html.push_str("<p>"),
                Tag::Heading {
                    level,
                    id,
                    classes,
                    attrs,
                } => {
                    let level = level_number(level);
                    if level == 1 {
                        return Err(
                            "level-1 heading: the page title comes from the front matter".into(),
                        );
                    }
                    if !classes.is_empty() || !attrs.is_empty() {
                        return Err("a heading takes only an `{#anchor}` attribute".into());
                    }
                    let Some(id) = id else {
                        return Err("a heading without an explicit `{#anchor}`".into());
                    };
                    if !is_kebab(&id) {
                        return Err(format!(
                            "heading anchor `{id}` is not kebab-case ([a-z0-9-])"
                        ));
                    }
                    if !ids.insert(id.to_string()) {
                        return Err(format!("heading anchor `{id}` appears twice in one page"));
                    }
                    let _ = write!(html, "<h{level} id=\"{id}\">");
                    heading = Some(Open {
                        level,
                        id: id.to_string(),
                        text: String::new(),
                    });
                }
                Tag::BlockQuote(_) => html.push_str("<blockquote>\n"),
                Tag::CodeBlock(kind) => {
                    html.push_str("<pre><code");
                    if let CodeBlockKind::Fenced(info) = kind
                        && let Some(lang) = info.split_whitespace().next()
                    {
                        let _ = write!(html, " class=\"language-{}\"", escape(lang));
                    }
                    html.push('>');
                }
                Tag::List(None) => html.push_str("<ul>\n"),
                Tag::List(Some(1)) => html.push_str("<ol>\n"),
                Tag::List(Some(n)) => {
                    let _ = writeln!(html, "<ol start=\"{n}\">");
                }
                Tag::Item => html.push_str("<li>"),
                Tag::Table(_) => html.push_str("<table>\n"),
                Tag::TableHead => {
                    in_table_head = true;
                    html.push_str("<thead><tr>");
                }
                Tag::TableRow => html.push_str("<tr>"),
                Tag::TableCell => html.push_str(if in_table_head { "<th>" } else { "<td>" }),
                Tag::Emphasis => html.push_str("<em>"),
                Tag::Strong => html.push_str("<strong>"),
                Tag::Link { dest_url, .. } => {
                    let (href, link, external) = link_target(&dest_url, ctx)?;
                    links.extend(link);
                    let _ = write!(html, "<a href=\"{}\"", escape(&href));
                    if external {
                        html.push_str(" rel=\"noreferrer\"");
                    }
                    html.push('>');
                }
                Tag::Image { .. } => return Err("images are not supported (PD-330)".into()),
                other => return Err(format!("unsupported Markdown construct {other:?}")),
            },
            Event::End(tag) => match tag {
                TagEnd::Paragraph => {
                    html.push_str("</p>\n");
                    plain(&mut sections, &mut heading, " ");
                }
                TagEnd::Heading(_) => {
                    let Some(h) = heading.take() else {
                        return Err("heading end without a start".into());
                    };
                    let _ = writeln!(html, "</h{}>", h.level);
                    sections.push(Section {
                        anchor: h.id.clone(),
                        heading: h.text.clone(),
                        text: String::new(),
                    });
                    headings.push(Heading {
                        level: h.level,
                        id: h.id,
                        text: h.text,
                    });
                }
                TagEnd::BlockQuote(_) => html.push_str("</blockquote>\n"),
                TagEnd::CodeBlock => {
                    html.push_str("</code></pre>\n");
                    plain(&mut sections, &mut heading, " ");
                }
                TagEnd::List(ordered) => html.push_str(if ordered { "</ol>\n" } else { "</ul>\n" }),
                TagEnd::Item => {
                    html.push_str("</li>\n");
                    plain(&mut sections, &mut heading, " ");
                }
                TagEnd::Table => html.push_str("</tbody></table>\n"),
                TagEnd::TableHead => {
                    in_table_head = false;
                    html.push_str("</tr></thead>\n<tbody>\n");
                }
                TagEnd::TableRow => html.push_str("</tr>\n"),
                TagEnd::TableCell => {
                    html.push_str(if in_table_head { "</th>" } else { "</td>" });
                    plain(&mut sections, &mut heading, " ");
                }
                TagEnd::Emphasis => html.push_str("</em>"),
                TagEnd::Strong => html.push_str("</strong>"),
                TagEnd::Link => html.push_str("</a>"),
                other => return Err(format!("unsupported Markdown construct {other:?}")),
            },
            other => return Err(format!("unsupported Markdown construct {other:?}")),
        }
    }
    Ok(Rendered {
        html,
        headings,
        links,
        sections,
    })
}
