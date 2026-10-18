//! Seeded Jira `fields=*all` search answers (M8 Task 25, V16 Jira half).
//!
//! The shape of what `atlas.all('jira.search', ..)` returns: the first page's object with the
//! issues of every page concatenated under `issues`. Each issue carries what a `fields=*all`
//! search with `expand=renderedFields` returns: 50 custom fields (nulls, numbers, options,
//! users, nested sprint history), nested objects (project, status, avatar URLs), long
//! descriptions and comments, and their rendered HTML. The text is a seeded mix of ASCII, Latin-1
//! umlauts, CJK and emoji, because QuickJS keeps a string with a character above U+00FF in 16-bit
//! units and the host frame's text is a QuickJS string while `JSON.parse` runs (PD-131).
//!
//! This generator lives in the worker's tests, not in `atlassian::testing`: a dev-dependency on
//! `atlas-duck-atlassian` would pull the HTTP stack into the worker's test build.
#![allow(dead_code)]

use serde_json::{Map, Value, json};

pub const MIB: usize = 1024 * 1024;

/// How much of the text is not ASCII.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextMix {
    /// ASCII only (QuickJS's 8-bit strings).
    Ascii,
    /// Mostly ASCII with umlauts, CJK and emoji: the realistic mix.
    Mixed,
    /// ASCII with about 2 % of the words non-Latin-1, and at least one wide character in every
    /// text (every string `text` builds, short or long): those strings and the whole frame become
    /// 16-bit although the text is almost all ASCII. Fixed strings (URLs, dates, ids, labels) stay
    /// 8-bit.
    Sparse,
    /// Mostly CJK, the worst case for 16-bit strings.
    Wide,
}

impl TextMix {
    pub const ALL: [TextMix; 4] = [
        TextMix::Ascii,
        TextMix::Mixed,
        TextMix::Sparse,
        TextMix::Wide,
    ];

    pub fn name(self) -> &'static str {
        match self {
            TextMix::Ascii => "ascii",
            TextMix::Mixed => "mixed",
            TextMix::Sparse => "sparse",
            TextMix::Wide => "wide",
        }
    }

    /// Percent of words drawn from (ASCII, umlauts, CJK); the rest are emoji.
    fn weights(self) -> (u64, u64, u64) {
        match self {
            TextMix::Ascii => (100, 0, 0),
            TextMix::Mixed => (70, 15, 10),
            TextMix::Sparse => (97, 1, 1),
            TextMix::Wide => (20, 5, 65),
        }
    }
}

const ASCII_WORDS: &[&str] = &[
    "project",
    "release",
    "backlog",
    "sprint",
    "customer",
    "payment",
    "service",
    "timeout",
    "migration",
    "pipeline",
    "deploy",
    "review",
    "regression",
    "feature",
    "database",
    "export",
    "report",
    "invoice",
    "account",
    "session",
    "token",
    "gateway",
    "cache",
    "queue",
];
const UMLAUT_WORDS: &[&str] = &[
    "Fälligkeit",
    "Übergabe",
    "Größe",
    "Änderung",
    "schön",
    "Qualitätssicherung",
    "Prüfung",
    "möglich",
    "Straße",
    "über",
];
const CJK_WORDS: &[&str] = &[
    "数据库迁移",
    "需求变更",
    "用户界面",
    "日本語のテキスト",
    "検証済み",
    "한국어문서",
    "缺陷修复",
    "性能优化",
    "接口文档",
];
const EMOJI: &[&str] = &["🚀", "🐛", "✅", "🔥", "📦", "👍🏽", "🎉"];

/// splitmix64: small, seeded, the same on every platform.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn between(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }

    fn pick<'a>(&mut self, words: &[&'a str]) -> &'a str {
        words[self.below(words.len())]
    }
}

/// A sentence-like run of `words` words.
fn text(rng: &mut Rng, mix: TextMix, words: usize) -> String {
    let (ascii, umlaut, cjk) = mix.weights();
    let mut out = String::new();
    for i in 0..words {
        if i > 0 {
            out.push(' ');
        }
        let roll = rng.next() % 100;
        let word = if roll < ascii {
            rng.pick(ASCII_WORDS)
        } else if roll < ascii + umlaut {
            rng.pick(UMLAUT_WORDS)
        } else if roll < ascii + umlaut + cjk {
            rng.pick(CJK_WORDS)
        } else {
            rng.pick(EMOJI)
        };
        out.push_str(word);
    }
    // The sparse mix promises a character above U+00FF in every text, however short or lucky.
    if mix == TextMix::Sparse && !out.chars().any(|c| c > '\u{ff}') {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(rng.pick(CJK_WORDS));
    }
    out
}

fn user(rng: &mut Rng, mix: TextMix, n: usize) -> Value {
    json!({
        "self": format!("https://jira.example.invalid/rest/api/2/user?username=user{n}"),
        "name": format!("user{n}"),
        "key": format!("JIRAUSER{}", 10000 + n),
        "emailAddress": format!("user{n}@example.invalid"),
        "avatarUrls": {
            "48x48": format!("https://jira.example.invalid/secure/useravatar?ownerId=user{n}&avatarId=10122"),
            "24x24": format!("https://jira.example.invalid/secure/useravatar?size=small&ownerId=user{n}&avatarId=10122"),
            "16x16": format!("https://jira.example.invalid/secure/useravatar?size=xsmall&ownerId=user{n}&avatarId=10122"),
            "32x32": format!("https://jira.example.invalid/secure/useravatar?size=medium&ownerId=user{n}&avatarId=10122"),
        },
        "displayName": text(rng, mix, 2),
        "active": true,
        "timeZone": "Europe/Berlin",
    })
}

fn option(rng: &mut Rng, mix: TextMix, n: usize) -> Value {
    json!({
        "self": format!("https://jira.example.invalid/rest/api/2/customFieldOption/{}", 10000 + n),
        "value": text(rng, mix, 2),
        "id": (10000 + n).to_string(),
        "disabled": false,
    })
}

fn custom_field(rng: &mut Rng, mix: TextMix, i: usize) -> Value {
    match i % 7 {
        0 => Value::Null,
        1 => {
            let words = rng.between(1, 6);
            Value::String(text(rng, mix, words))
        }
        2 => json!(rng.below(100_000) as f64 / 8.0),
        3 => option(rng, mix, i),
        4 => Value::Array(
            (0..rng.between(2, 3))
                .map(|j| option(rng, mix, i + j))
                .collect(),
        ),
        5 => user(rng, mix, i),
        _ => Value::Array(
            (0..rng.between(1, 3))
                .map(|j| {
                    json!({
                        "id": 100 + j,
                        "name": text(rng, mix, 2),
                        "state": "closed",
                        "boardId": 7,
                        "goal": text(rng, mix, 5),
                        "startDate": "2026-09-01T07:00:00.000Z",
                        "endDate": "2026-09-14T15:00:00.000Z",
                    })
                })
                .collect(),
        ),
    }
}

fn issue(rng: &mut Rng, mix: TextMix, n: usize) -> Value {
    let description_words = rng.between(150, 400);
    let description = text(rng, mix, description_words);
    let comments: Vec<(String, Value)> = (0..rng.between(3, 6))
        .map(|j| {
            let body_words = rng.between(40, 120);
            let body = text(rng, mix, body_words);
            let comment = json!({
                "self": format!("https://jira.example.invalid/rest/api/2/issue/{}/comment/{}", 10000 + n, j),
                "id": (500_000 + n * 10 + j).to_string(),
                "author": user(rng, mix, j),
                "body": body,
                "updateAuthor": user(rng, mix, j + 1),
                "created": "2026-10-01T09:30:12.345+0200",
                "updated": "2026-10-02T11:02:44.101+0200",
            });
            (body, comment)
        })
        .collect();
    let rendered_comments: Vec<Value> = comments
        .iter()
        .map(
            |(body, _)| json!({ "body": format!("<p>{body}</p>"), "created": "01/Oct/26 9:30 AM" }),
        )
        .collect();
    let comment_count = comments.len();
    let comments: Vec<Value> = comments.into_iter().map(|(_, c)| c).collect();

    let mut fields = Map::new();
    fields.insert("summary".into(), json!(text(rng, mix, 8)));
    fields.insert("description".into(), json!(description));
    fields.insert(
        "issuetype".into(),
        json!({ "self": "https://jira.example.invalid/rest/api/2/issuetype/1", "id": "1",
                "description": text(rng, mix, 6), "iconUrl": "https://jira.example.invalid/images/icons/bug.gif",
                "name": "Bug", "subtask": false, "avatarId": 10303 }),
    );
    fields.insert(
        "project".into(),
        json!({ "self": "https://jira.example.invalid/rest/api/2/project/10000", "id": "10000", "key": "KFAC",
                "name": text(rng, mix, 3),
                "projectCategory": { "id": "10000", "name": text(rng, mix, 2) },
                "avatarUrls": { "48x48": "https://jira.example.invalid/secure/projectavatar?avatarId=10324" } }),
    );
    fields.insert(
        "status".into(),
        json!({ "self": "https://jira.example.invalid/rest/api/2/status/3", "description": text(rng, mix, 5),
                "name": "In Progress", "id": "3",
                "statusCategory": { "id": 4, "key": "indeterminate", "colorName": "yellow", "name": "In Progress" } }),
    );
    fields.insert(
        "priority".into(),
        json!({ "self": "https://jira.example.invalid/rest/api/2/priority/3", "name": "Medium", "id": "3" }),
    );
    fields.insert("assignee".into(), user(rng, mix, n));
    fields.insert("reporter".into(), user(rng, mix, n + 1));
    fields.insert(
        "labels".into(),
        Value::Array(
            (0..rng.between(0, 4))
                .map(|_| json!(rng.pick(ASCII_WORDS)))
                .collect(),
        ),
    );
    fields.insert(
        "components".into(),
        Value::Array(
            (0..rng.between(1, 3))
                .map(|j| json!({ "self": "https://jira.example.invalid/rest/api/2/component/1", "id": (10 + j).to_string(), "name": text(rng, mix, 2) }))
                .collect(),
        ),
    );
    fields.insert("created".into(), json!("2026-09-28T08:15:00.000+0200"));
    fields.insert("updated".into(), json!("2026-10-05T16:40:21.987+0200"));
    fields.insert(
        "comment".into(),
        json!({ "comments": comments, "maxResults": comment_count, "total": comment_count, "startAt": 0 }),
    );
    for i in 0..50 {
        fields.insert(
            format!("customfield_{}", 10000 + i),
            custom_field(rng, mix, i),
        );
    }

    json!({
        "expand": "renderedFields,names,schema,operations,editmeta,changelog,versionedRepresentations",
        "id": (10000 + n).to_string(),
        "self": format!("https://jira.example.invalid/rest/api/2/issue/{}", 10000 + n),
        "key": format!("KFAC-{}", n + 1),
        "fields": Value::Object(fields),
        "renderedFields": {
            "description": format!("<p>{description}</p>"),
            "created": "28/Sep/26 8:15 AM",
            "updated": "05/Oct/26 4:40 PM",
            "comment": { "comments": rendered_comments },
        },
    })
}

/// A compact user reference, as changelog and worklog entries carry it.
fn small_user(rng: &mut Rng, mix: TextMix, n: usize) -> Value {
    json!({ "name": format!("user{n}"), "key": format!("JIRAUSER{}", 10000 + n),
            "displayName": text(rng, mix, 2), "active": true })
}

/// One changelog history: a few `{field, from, to, ..}` items, some with null sides.
fn history(rng: &mut Rng, mix: TextMix, n: usize) -> Value {
    const FIELDS: &[&str] = &[
        "status",
        "assignee",
        "priority",
        "resolution",
        "Sprint",
        "labels",
    ];
    let items: Vec<Value> = (0..rng.between(1, 3))
        .map(|_| {
            let field = FIELDS[rng.below(FIELDS.len())];
            let (from, to) = (rng.below(12), rng.below(12));
            let null_side = rng.below(4);
            json!({
                "field": field,
                "fieldtype": "jira",
                "from": if null_side == 0 { Value::Null } else { json!(from.to_string()) },
                "fromString": if null_side == 0 { Value::Null } else { json!(rng.pick(ASCII_WORDS)) },
                "to": if null_side == 1 { Value::Null } else { json!(to.to_string()) },
                "toString": if null_side == 1 { Value::Null } else { json!(text(rng, mix, 1)) },
            })
        })
        .collect();
    json!({ "id": (700_000 + n).to_string(), "author": small_user(rng, mix, n % 9),
            "created": "2026-09-30T10:11:12.131+0200", "items": items })
}

/// A Jira issue of many small values: a long changelog, issuelinks, worklogs, arrays of ids and
/// small numbers, and null-heavy custom fields. Little long text, many tiny strings and numbers.
fn dense_issue(rng: &mut Rng, mix: TextMix, n: usize) -> Value {
    let histories: Vec<Value> = (0..rng.between(30, 80))
        .map(|j| history(rng, mix, j))
        .collect();
    let history_count = histories.len();
    let links: Vec<Value> = (0..rng.between(5, 15))
        .map(|j| {
            json!({
                "id": (800_000 + n * 20 + j).to_string(),
                "type": { "id": "10003", "name": "Relates", "inward": "relates to", "outward": "relates to" },
                "outwardIssue": {
                    "id": (20_000 + j).to_string(), "key": format!("KFAC-{}", 900 + j),
                    "self": format!("https://jira.example.invalid/rest/api/2/issue/{}", 20_000 + j),
                    "fields": { "summary": text(rng, mix, 4),
                                "status": { "id": "3", "name": "In Progress" },
                                "priority": { "id": "3", "name": "Medium" } },
                },
            })
        })
        .collect();
    let worklogs: Vec<Value> = (0..rng.between(10, 30))
        .map(|j| {
            let seconds = 900 * rng.between(1, 16);
            json!({
                "id": (900_000 + n * 40 + j).to_string(), "author": small_user(rng, mix, j % 9),
                "started": "2026-10-02T08:00:00.000+0200", "timeSpent": format!("{}m", seconds / 60),
                "timeSpentSeconds": seconds, "comment": text(rng, mix, 3),
            })
        })
        .collect();
    let ids = |rng: &mut Rng, count: usize, range: usize| -> Vec<Value> {
        (0..count).map(|_| json!(rng.below(range))).collect()
    };
    let mut fields = Map::new();
    fields.insert("summary".into(), json!(text(rng, mix, 6)));
    fields.insert(
        "status".into(),
        json!({ "id": "3", "name": "In Progress", "statusCategory": { "id": 4, "key": "indeterminate" } }),
    );
    fields.insert("issuelinks".into(), Value::Array(links));
    fields.insert(
        "worklog".into(),
        json!({ "startAt": 0, "maxResults": worklogs.len(), "total": worklogs.len(), "worklogs": worklogs }),
    );
    fields.insert("fixVersionIds".into(), Value::Array(ids(rng, 60, 500)));
    fields.insert("watcherIds".into(), Value::Array(ids(rng, 100, 10)));
    fields.insert(
        "estimates".into(),
        Value::Array((0..120).map(|_| json!(rng.below(9) as f64 / 2.0)).collect()),
    );
    fields.insert(
        "idStrings".into(),
        Value::Array((0..80).map(|_| json!(rng.below(100).to_string())).collect()),
    );
    // Null-heavy: three in four custom fields are null, the rest small numbers or booleans.
    for i in 0..60 {
        let value = match rng.below(8) {
            0 => json!(rng.below(10)),
            1 => json!(rng.below(2) == 0),
            _ => Value::Null,
        };
        fields.insert(format!("customfield_{}", 10000 + i), value);
    }
    json!({
        "id": (10000 + n).to_string(),
        "key": format!("KFAC-{}", n + 1),
        "fields": Value::Object(fields),
        "changelog": { "startAt": 0, "maxResults": history_count, "total": history_count,
                       "histories": histories },
    })
}

/// The envelope without issues, as `total` and `maxResults` of `count` issues serialize.
fn envelope_len(count: usize) -> usize {
    json!({ "startAt": 0, "maxResults": count, "total": count, "issues": [] })
        .to_string()
        .len()
}

/// A `fields=*all` search answer whose JSON text is at most `target_bytes` long and within one
/// issue of it. The same `(seed, mix, target_bytes)` always gives the same value.
pub fn jira_star_all_search(seed: u64, mix: TextMix, target_bytes: usize) -> Value {
    search_of(seed, mix, target_bytes, issue)
}

/// The same envelope around dense small-object issues (`expand=changelog`, issuelinks, worklogs,
/// numeric and id arrays, nulls): the shapes with the most QuickJS values per JSON byte.
pub fn jira_dense_search(seed: u64, mix: TextMix, target_bytes: usize) -> Value {
    search_of(seed ^ 0xd3_45e, mix, target_bytes, dense_issue)
}

fn search_of(
    seed: u64,
    mix: TextMix,
    target_bytes: usize,
    make: fn(&mut Rng, TextMix, usize) -> Value,
) -> Value {
    let mut rng = Rng(seed ^ ((mix as u64) << 56));
    let mut issues: Vec<Value> = Vec::new();
    // The issues' own text, plus one comma between neighbours.
    let mut body = 0usize;
    loop {
        let next = make(&mut rng, mix, issues.len());
        let next_len = next.to_string().len();
        let comma = usize::from(!issues.is_empty());
        if envelope_len(issues.len() + 1) + body + comma + next_len > target_bytes {
            break;
        }
        body += comma + next_len;
        issues.push(next);
    }
    let count = issues.len();
    json!({ "startAt": 0, "maxResults": count, "total": count, "issues": issues })
}

// Confluence (M8 Task 33, V16 closure). A page is a list of blocks (headings, paragraphs with
// links, lists, tables, macros, code, images) rendered as storage-format XHTML, the string
// `body.storage.value` carries, or as the Markdown the host's conversion returns. Pages of about
// 5,000 words are tens of KiB each; a search or page list holds many of them.

/// One block of a page; `storage` and `markdown` render the same content.
enum Block {
    Heading(String),
    Para {
        text: String,
        label: String,
        id: usize,
    },
    Bullets(Vec<String>),
    Numbered(Vec<String>),
    Table(Vec<Vec<String>>),
    Info(String),
    Code(Vec<String>),
    Image(usize),
    Toc,
}

fn blocks(rng: &mut Rng, mix: TextMix, words: usize) -> Vec<Block> {
    let mut out = Vec::new();
    let mut used = 0usize;
    while used < words {
        let roll = rng.below(100);
        out.push(match roll {
            0..=7 => {
                let n = rng.between(2, 6);
                used += n;
                Block::Heading(text(rng, mix, n))
            }
            8..=47 => {
                let n = rng.between(40, 120);
                used += n + 4;
                Block::Para {
                    text: text(rng, mix, n),
                    label: text(rng, mix, 2),
                    id: rng.below(900_000),
                }
            }
            48..=67 => {
                let items: Vec<String> = (0..rng.between(3, 9))
                    .map(|_| {
                        let n = rng.between(4, 14);
                        used += n;
                        text(rng, mix, n)
                    })
                    .collect();
                if roll < 60 {
                    Block::Bullets(items)
                } else {
                    Block::Numbered(items)
                }
            }
            68..=79 => {
                let cols = rng.between(3, 5);
                let rows = rng.between(3, 8);
                Block::Table(
                    (0..rows)
                        .map(|_| {
                            (0..cols)
                                .map(|_| {
                                    let n = rng.between(1, 8);
                                    used += n;
                                    text(rng, mix, n)
                                })
                                .collect()
                        })
                        .collect(),
                )
            }
            80..=87 => {
                let n = rng.between(15, 50);
                used += n;
                Block::Info(text(rng, mix, n))
            }
            88..=92 => {
                // Code is ASCII whatever the mix.
                let lines = (0..rng.between(3, 10))
                    .map(|i| {
                        format!(
                            "String v{i} = service.call(\"{}\", {});",
                            rng.pick(ASCII_WORDS),
                            rng.below(1000)
                        )
                    })
                    .collect::<Vec<_>>();
                used += lines.len() * 5;
                Block::Code(lines)
            }
            93..=96 => Block::Image(rng.below(100)),
            _ => Block::Toc,
        });
    }
    out
}

/// A deterministic macro id (the shape Confluence writes: a UUID).
fn macro_id(n: usize) -> String {
    let n = n as u64;
    format!(
        "{:08x}-4e1c-4b7a-9d3f-{:012x}",
        n * 2_654_435_761 % 0xffff_ffff,
        n * 7919
    )
}

impl Block {
    fn storage(&self, n: usize) -> String {
        match self {
            Block::Heading(t) => format!("<h2>{t}</h2>"),
            Block::Para { text, label, id } => format!(
                "<p><strong>{label}</strong> {text} <a href=\"https://confluence.example.invalid/confluence/pages/viewpage.action?pageId={id}\">{label}</a> \
                 <ac:link><ri:page ri:content-title=\"{label}\" ri:space-key=\"KB\" /><ac:plain-text-link-body><![CDATA[{label}]]></ac:plain-text-link-body></ac:link>.</p>"
            ),
            Block::Bullets(items) => list_storage("ul", items),
            Block::Numbered(items) => list_storage("ol", items),
            Block::Table(rows) => {
                let cols = rows.first().map_or(0, Vec::len);
                let mut s = String::from("<table data-layout=\"default\"><colgroup>");
                s.push_str(&"<col />".repeat(cols));
                s.push_str("</colgroup><tbody>");
                for (i, row) in rows.iter().enumerate() {
                    let tag = if i == 0 { "th" } else { "td" };
                    s.push_str("<tr>");
                    for cell in row {
                        s.push_str(&format!("<{tag}><p>{cell}</p></{tag}>"));
                    }
                    s.push_str("</tr>");
                }
                s.push_str("</tbody></table>");
                s
            }
            Block::Info(t) => format!(
                "<ac:structured-macro ac:name=\"info\" ac:schema-version=\"1\" ac:macro-id=\"{}\"><ac:rich-text-body><p>{t}</p></ac:rich-text-body></ac:structured-macro>",
                macro_id(n)
            ),
            Block::Code(lines) => format!(
                "<ac:structured-macro ac:name=\"code\" ac:schema-version=\"1\" ac:macro-id=\"{}\"><ac:parameter ac:name=\"language\">java</ac:parameter><ac:plain-text-body><![CDATA[{}]]></ac:plain-text-body></ac:structured-macro>",
                macro_id(n),
                lines.join("\n")
            ),
            Block::Image(i) => format!(
                "<p><ac:image ac:width=\"600\" ac:alt=\"diagram-{i}\"><ri:attachment ri:filename=\"diagram-{i}.png\" /></ac:image></p>"
            ),
            Block::Toc => format!(
                "<p><ac:structured-macro ac:name=\"toc\" ac:schema-version=\"1\" ac:macro-id=\"{}\"><ac:parameter ac:name=\"maxLevel\">3</ac:parameter></ac:structured-macro></p>",
                macro_id(n)
            ),
        }
    }

    fn markdown(&self) -> String {
        match self {
            Block::Heading(t) => format!("## {t}"),
            Block::Para { text, label, id } => format!(
                "**{label}** {text} [{label}](https://confluence.example.invalid/confluence/pages/viewpage.action?pageId={id}) [{label}](confluence:KB/{label})."
            ),
            Block::Bullets(items) => items
                .iter()
                .map(|i| format!("- {i}"))
                .collect::<Vec<_>>()
                .join("\n"),
            Block::Numbered(items) => items
                .iter()
                .enumerate()
                .map(|(i, t)| format!("{}. {t}", i + 1))
                .collect::<Vec<_>>()
                .join("\n"),
            Block::Table(rows) => {
                let cols = rows.first().map_or(0, Vec::len);
                let mut lines = Vec::new();
                for (i, row) in rows.iter().enumerate() {
                    lines.push(format!("| {} |", row.join(" | ")));
                    if i == 0 {
                        lines.push(format!("|{}", " --- |".repeat(cols)));
                    }
                }
                lines.join("\n")
            }
            Block::Info(t) => format!("> **Info:** {t}"),
            Block::Code(lines) => format!("```java\n{}\n```", lines.join("\n")),
            Block::Image(i) => format!("![diagram-{i}](attachments/diagram-{i}.png)"),
            Block::Toc => "[TOC]".to_owned(),
        }
    }
}

fn list_storage(tag: &str, items: &[String]) -> String {
    let inner: String = items
        .iter()
        .map(|i| format!("<li><p>{i}</p></li>"))
        .collect();
    format!("<{tag}>{inner}</{tag}>")
}

/// How a page's content is carried.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    /// `body.storage.value`: what `confluence.page.get` returns for `body_format = storage`.
    Storage,
    /// The page after the host's storage-to-Markdown conversion.
    Markdown,
}

fn confluence_user(rng: &mut Rng, mix: TextMix, n: usize) -> Value {
    json!({
        "type": "known",
        "username": format!("user{n}"),
        "userKey": format!("8a7f{:012x}", n),
        "profilePicture": { "path": "/confluence/images/icons/profilepics/default.svg", "width": 48,
                            "height": 48, "isDefault": true },
        "displayName": text(rng, mix, 2),
    })
}

/// One page: metadata of an expanded `content` object plus the body in `form`.
fn confluence_page(rng: &mut Rng, mix: TextMix, n: usize, words: usize, form: Form) -> Value {
    let id = (100_000 + n).to_string();
    let page_blocks = blocks(rng, mix, words);
    let body = match form {
        Form::Storage => {
            let value: String = page_blocks
                .iter()
                .enumerate()
                .map(|(i, b)| b.storage(i))
                .collect();
            json!({ "storage": { "value": value, "representation": "storage",
                                 "_expandable": { "content": format!("/rest/api/content/{id}") } },
                    "_expandable": { "editor": "", "view": "", "export_view": "", "styled_view": "" } })
        }
        Form::Markdown => {
            let value = page_blocks
                .iter()
                .map(Block::markdown)
                .collect::<Vec<_>>()
                .join("\n\n");
            json!({ "markdown": value })
        }
    };
    let labels: Vec<Value> = (0..rng.between(0, 4))
        .map(|j| json!({ "prefix": "global", "name": rng.pick(ASCII_WORDS), "id": (5000 + j).to_string() }))
        .collect();
    let ancestors: Vec<Value> = (0..rng.between(1, 3))
        .map(|j| {
            json!({ "id": (90_000 + j).to_string(), "type": "page", "status": "current",
                         "title": text(rng, mix, 3) })
        })
        .collect();
    json!({
        "id": id,
        "type": "page",
        "status": "current",
        "title": text(rng, mix, 5),
        "space": { "id": 65_538, "key": "KB", "name": text(rng, mix, 2), "type": "global",
                   "status": "current", "_links": { "webui": "/spaces/KB" } },
        "history": { "latest": true, "createdBy": confluence_user(rng, mix, n % 9),
                     "createdDate": "2026-03-02T09:12:45.321+01:00" },
        "version": { "by": confluence_user(rng, mix, (n + 1) % 9), "when": "2026-10-05T16:40:21.987+02:00",
                     "message": text(rng, mix, 3), "number": 1 + n % 40, "minorEdit": false,
                     "hidden": false },
        "ancestors": ancestors,
        "metadata": { "labels": { "results": labels, "size": 0, "start": 0, "limit": 200 } },
        "body": body,
        "_links": { "webui": format!("/spaces/KB/pages/{id}"), "tinyui": "/x/AbCdEf",
                    "self": format!("https://confluence.example.invalid/confluence/rest/api/content/{id}"),
                    "edit": format!("/pages/resumedraft.action?draftId={id}") },
        "_expandable": { "container": "/rest/api/space/KB", "operations": "", "children": "",
                         "restrictions": "", "descendants": "" },
    })
}

/// A page list answer's envelope around `results`.
fn confluence_envelope(results: Vec<Value>) -> Value {
    let count = results.len();
    json!({ "results": results, "start": 0, "limit": count, "size": count,
            "_links": { "base": "https://confluence.example.invalid/confluence", "context": "/confluence",
                        "self": "https://confluence.example.invalid/confluence/rest/api/content?limit=25" } })
}

/// The `page.get` answer of one page of about 5,000 words, storage body.
pub fn confluence_page_get(seed: u64, mix: TextMix) -> Value {
    let mut rng = Rng(seed ^ 0xc0_ffee ^ ((mix as u64) << 56));
    confluence_page(&mut rng, mix, 0, 5000, Form::Storage)
}

/// A page list of `pages` pages of about 5,000 words each, storage bodies (25 for the plan's list).
pub fn confluence_page_list(seed: u64, mix: TextMix, pages: usize) -> Value {
    let mut rng = Rng(seed ^ 0xc0_ffee_1157 ^ ((mix as u64) << 56));
    confluence_envelope(
        (0..pages)
            .map(|n| confluence_page(&mut rng, mix, n, 5000, Form::Storage))
            .collect(),
    )
}

/// A page list of storage-body pages whose JSON text is at most `target_bytes` long and within one
/// page of it.
pub fn confluence_storage_search(seed: u64, mix: TextMix, target_bytes: usize) -> Value {
    confluence_sized(seed ^ 0x5702, mix, target_bytes, Form::Storage)
}

/// The same pages after conversion: the Markdown form, sized the same way.
pub fn confluence_markdown_search(seed: u64, mix: TextMix, target_bytes: usize) -> Value {
    confluence_sized(seed ^ 0x3d, mix, target_bytes, Form::Markdown)
}

fn confluence_sized(seed: u64, mix: TextMix, target_bytes: usize, form: Form) -> Value {
    let mut rng = Rng(seed ^ ((mix as u64) << 56));
    let envelope = confluence_envelope(Vec::new()).to_string().len();
    let mut pages: Vec<Value> = Vec::new();
    let mut body = 0usize;
    loop {
        let words = rng.between(4500, 5500);
        let next = confluence_page(&mut rng, mix, pages.len(), words, form);
        let next_len = next.to_string().len();
        let comma = usize::from(!pages.is_empty());
        // Digits of limit and size grow with the count; eight spare bytes cover them.
        if envelope + 8 + body + comma + next_len > target_bytes {
            break;
        }
        body += comma + next_len;
        pages.push(next);
    }
    confluence_envelope(pages)
}
