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
    /// ASCII with a few non-Latin-1 characters per text: nearly every long string and the whole
    /// frame become 16-bit although the text is almost all ASCII (the worst case for `k`).
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

/// The envelope without issues, as `total` and `maxResults` of `count` issues serialize.
fn envelope_len(count: usize) -> usize {
    json!({ "startAt": 0, "maxResults": count, "total": count, "issues": [] })
        .to_string()
        .len()
}

/// A `fields=*all` search answer whose JSON text is at most `target_bytes` long and within one
/// issue of it. The same `(seed, mix, target_bytes)` always gives the same value.
pub fn jira_star_all_search(seed: u64, mix: TextMix, target_bytes: usize) -> Value {
    let mut rng = Rng(seed ^ ((mix as u64) << 56));
    let mut issues: Vec<Value> = Vec::new();
    // The issues' own text, plus one comma between neighbours.
    let mut body = 0usize;
    loop {
        let next = issue(&mut rng, mix, issues.len());
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
