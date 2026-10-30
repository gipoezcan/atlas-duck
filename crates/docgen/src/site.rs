//! The whole output of one set: pages, manifests, search indexes, copied assets.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::fs;
use std::path::Path;

use crate::frontmatter::{self, FrontMatter, Mode};
use crate::render::{self, Ctx, Rendered, Set, escape, page_href};
use crate::search::{self, Entry, json_str};

/// Output path (relative to the set's output directory, `/`-separated) -> bytes.
pub type Files = BTreeMap<String, Vec<u8>>;

pub const LANGS: [&str; 2] = ["en", "de"];

pub struct SourcePage {
    pub fm: FrontMatter,
    pub body: String,
}

pub struct Sources {
    /// language -> pages sorted by id
    pub langs: BTreeMap<String, Vec<SourcePage>>,
    pub css: String,
    pub js: String,
}

fn read(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(text.replace("\r\n", "\n"))
}

/// Reads `<src>/{en,de}/*.md` and `<src>/assets/{help.css,help.js}`.
pub fn load(src: &Path) -> Result<Sources, String> {
    let mut langs = BTreeMap::new();
    for lang in LANGS {
        let dir = src.join(lang);
        let mut files: Vec<_> = fs::read_dir(&dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .map(|entry| {
                entry
                    .map(|e| e.path())
                    .map_err(|e| format!("{}: {e}", dir.display()))
            })
            .collect::<Result<_, _>>()?;
        files.sort();
        let mut pages: Vec<SourcePage> = Vec::new();
        for path in files
            .into_iter()
            .filter(|p| p.extension().is_some_and(|x| x == "md"))
        {
            let text = read(&path)?;
            let (fm, body) =
                frontmatter::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if fm.id != stem {
                return Err(format!(
                    "{}: front matter id `{}` is not the file stem",
                    path.display(),
                    fm.id
                ));
            }
            pages.push(SourcePage {
                fm,
                body: body.to_string(),
            });
        }
        langs.insert(lang.to_string(), pages);
    }
    Ok(Sources {
        langs,
        css: read(&src.join("assets/help.css"))?,
        js: read(&src.join("assets/help.js"))?,
    })
}

struct Text {
    brand: &'static str,
    search: &'static str,
    no_results: &'static str,
    contents: &'static str,
    /// The name of the other language, in that language.
    other: &'static str,
}

fn text(lang: &str) -> Text {
    if lang == "de" {
        Text {
            brand: "Atlas Duck Hilfe",
            search: "Hilfe durchsuchen",
            no_results: "Keine Treffer",
            contents: "Inhalt",
            other: "English",
        }
    } else {
        Text {
            brand: "Atlas Duck Help",
            search: "Search help",
            no_results: "No results",
            contents: "Contents",
            other: "Deutsch",
        }
    }
}

fn other_lang(lang: &str) -> &'static str {
    if lang == "de" { "en" } else { "de" }
}

fn in_set(mode: Mode, set: Set) -> bool {
    matches!(
        (mode, set),
        (Mode::Both, _) | (Mode::Desktop, Set::Desktop) | (Mode::Server, Set::Server)
    )
}

struct Built<'a> {
    src: &'a SourcePage,
    rendered: Rendered,
}

fn page_html(set: Set, lang: &str, all: &[Built], current: &Built) -> String {
    let t = text(lang);
    let other = other_lang(lang);
    let id = &current.src.fm.id;
    let title = escape(&current.src.fm.title);
    let mut h = String::new();
    let _ = write!(
        h,
        "<!doctype html>\n<html lang=\"{lang}\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title} - {brand}</title>\n\
         <link rel=\"stylesheet\" href=\"assets/help.css\">\n\
         <script src=\"assets/search-index.js\" defer></script>\n\
         <script src=\"assets/help.js\" defer></script>\n</head>\n<body>\n",
        brand = t.brand,
    );
    let _ = write!(
        h,
        "<header class=\"bar\">\n<a class=\"brand\" href=\"{index}\">{brand}</a>\n\
         <div class=\"search\" hidden>\n<label class=\"visually-hidden\" for=\"help-search\">{search}</label>\n\
         <input id=\"help-search\" type=\"search\" placeholder=\"{search}\" autocomplete=\"off\" data-empty=\"{empty}\">\n\
         <ul id=\"help-results\" hidden></ul>\n</div>\n\
         <a class=\"lang-switch\" lang=\"{other}\" hreflang=\"{other}\" href=\"{switch}\">{other_name}</a>\n</header>\n",
        index = page_href(set, lang, "index", None),
        brand = t.brand,
        search = t.search,
        empty = t.no_results,
        switch = match set {
            Set::Desktop => format!("../{other}/{id}.html"),
            Set::Server => page_href(set, other, id, None),
        },
        other_name = t.other,
    );
    let _ = writeln!(
        h,
        "<div class=\"layout\">\n<nav class=\"toc\" aria-label=\"{}\">\n<ul>",
        t.contents
    );
    for b in all {
        let current_page = b.src.fm.id == *id;
        let _ = write!(
            h,
            "<li><a href=\"{}\"{}>{}</a>",
            page_href(set, lang, &b.src.fm.id, None),
            if current_page {
                " aria-current=\"page\""
            } else {
                ""
            },
            escape(&b.src.fm.title),
        );
        if current_page {
            h.push_str("\n<ul>\n");
            for sub in b.rendered.headings.iter().filter(|s| s.level == 2) {
                let _ = writeln!(
                    h,
                    "<li><a href=\"#{}\">{}</a></li>",
                    sub.id,
                    escape(&sub.text)
                );
            }
            h.push_str("</ul>\n");
        }
        h.push_str("</li>\n");
    }
    let _ = write!(
        h,
        "</ul>\n</nav>\n<main>\n<h1>{title}</h1>\n{}</main>\n</div>\n</body>\n</html>\n",
        current.rendered.html
    );
    h
}

fn manifest(set: Set, lang: &str, all: &[Built]) -> String {
    let mut out = format!(
        "{{\n  \"lang\": {},\n  \"set\": {},\n  \"pages\": [\n",
        json_str(lang),
        json_str(if set == Set::Desktop {
            "desktop"
        } else {
            "server"
        })
    );
    for (i, b) in all.iter().enumerate() {
        let anchors: Vec<String> = b
            .rendered
            .headings
            .iter()
            .map(|h| json_str(&h.id))
            .collect();
        let _ = write!(
            out,
            "    {{\"id\": {}, \"title\": {}, \"file\": {}, \"anchors\": [{}]}}",
            json_str(&b.src.fm.id),
            json_str(&b.src.fm.title),
            json_str(&format!("{}.html", b.src.fm.id)),
            anchors.join(", "),
        );
        out.push_str(if i + 1 < all.len() { ",\n" } else { "\n" });
    }
    out.push_str("  ]\n}\n");
    out
}

fn entries(set: Set, lang: &str, all: &[Built]) -> Vec<Entry> {
    let mut out = Vec::new();
    for b in all {
        let id = &b.src.fm.id;
        for s in &b.rendered.sections {
            let lead = s.anchor.is_empty();
            out.push(Entry {
                page: id.clone(),
                anchor: s.anchor.clone(),
                title: b.src.fm.title.clone(),
                heading: if lead {
                    b.src.fm.title.clone()
                } else {
                    s.heading.clone()
                },
                text: search::snippet(&s.text),
                href: page_href(set, lang, id, (!lead).then_some(s.anchor.as_str())),
            });
        }
    }
    out
}

/// The files of `set`: for each language `<lang>/<page>.html`, `manifest.json`, `assets/help.css`,
/// `assets/help.js` and `assets/search-index.js`. Fails on a dangling internal link, a page that
/// exists in one language only, or a set without an `index` page.
pub fn generate(sources: &Sources, set: Set) -> Result<Files, String> {
    let mut files = Files::new();
    let mut ids_by_lang: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();

    for (lang, pages) in &sources.langs {
        let mut chosen: Vec<&SourcePage> =
            pages.iter().filter(|p| in_set(p.fm.mode, set)).collect();
        chosen.sort_by(|a, b| (a.fm.order, &a.fm.id).cmp(&(b.fm.order, &b.fm.id)));
        if !chosen.iter().any(|p| p.fm.id == "index") {
            return Err(format!("{lang}: the set has no `index` page"));
        }
        ids_by_lang.insert(lang, chosen.iter().map(|p| p.fm.id.as_str()).collect());

        let mut built = Vec::new();
        for src in chosen {
            let id = &src.fm.id;
            let ctx = Ctx {
                set,
                lang,
                page: id,
            };
            let body = render::strip_modes(&src.body, src.fm.mode, set)
                .map_err(|e| format!("{lang}/{id}: {e}"))?;
            let rendered =
                render::render_body(&body, &ctx).map_err(|e| format!("{lang}/{id}: {e}"))?;
            built.push(Built { src, rendered });
        }

        let anchors: BTreeMap<&str, BTreeSet<&str>> = built
            .iter()
            .map(|b| {
                (
                    b.src.fm.id.as_str(),
                    b.rendered.headings.iter().map(|h| h.id.as_str()).collect(),
                )
            })
            .collect();
        for b in &built {
            for link in &b.rendered.links {
                let Some(target) = anchors.get(link.page.as_str()) else {
                    return Err(format!(
                        "{lang}/{}: links to page `{}`, which is not in the {set:?} set",
                        b.src.fm.id, link.page
                    ));
                };
                if let Some(a) = &link.anchor
                    && !target.contains(a.as_str())
                {
                    return Err(format!(
                        "{lang}/{}: links to `{}#{a}`, which does not exist",
                        b.src.fm.id, link.page
                    ));
                }
            }
        }

        for b in &built {
            files.insert(
                format!("{lang}/{}.html", b.src.fm.id),
                page_html(set, lang, &built, b).into_bytes(),
            );
        }
        files.insert(
            format!("{lang}/manifest.json"),
            manifest(set, lang, &built).into_bytes(),
        );
        files.insert(
            format!("{lang}/assets/help.css"),
            sources.css.clone().into_bytes(),
        );
        files.insert(
            format!("{lang}/assets/help.js"),
            sources.js.clone().into_bytes(),
        );
        files.insert(
            format!("{lang}/assets/search-index.js"),
            search::index_js(&entries(set, lang, &built)).into_bytes(),
        );
    }

    let mut sets = ids_by_lang.values();
    if let Some(first) = sets.next()
        && sets.any(|s| s != first)
    {
        return Err(format!(
            "the languages have different pages in the {set:?} set: {ids_by_lang:?}"
        ));
    }
    Ok(files)
}
