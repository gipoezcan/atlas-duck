//! U-26 (redaction engine, copies, mirrors, mask everywhere), U-28 (canonical match form, the
//! "Falcon Müller Plan" fixture), U-29 core half (drops never look empty, upstream `null`s stay).

use atlas_duck_core::redact::views::{canonical_hit, views};
use atlas_duck_core::redact::{
    BlockReason, DropScope, RedactionOp, RedactionOutcome, RedactionPreset, UrlMode,
    also_appears_in, apply,
};
use atlas_duck_registry::RedactionRules;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use serde_json::{Map, Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const NO_RULES: RedactionRules = RedactionRules {
    copies: &[],
    mirrors: &[],
    url_fields: &[],
};

fn rules(op_id: &str) -> Result<&'static RedactionRules, String> {
    atlas_duck_registry::get(op_id)
        .map(|op| &op.redaction_rules)
        .ok_or_else(|| format!("no op {op_id}"))
}

fn mask(text: &str) -> RedactionOp {
    RedactionOp::MaskText {
        text: text.into(),
        every_occurrence: true,
        at: None,
    }
}

fn drop_field(path: &str, scope: DropScope) -> RedactionOp {
    RedactionOp::DropField {
        path: path.into(),
        scope,
    }
}

/// Every string value and object key of `v` with its JSON path.
fn strings(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => out.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            Value::Object(o) => {
                for (k, x) in o {
                    out.push(k.clone());
                    walk(x, out);
                }
            }
            _ => {}
        }
    }
    walk(v, &mut out);
    out
}

fn has_block(out: &RedactionOutcome, want: &BlockReason) -> bool {
    out.blocked.iter().any(|b| b == want)
}

/// A `jira.issue.get --expand renderedFields,names,schema,editmeta,changelog` candidate.
fn issue_fixture() -> Value {
    json!({
        "id": "10001",
        "key": "ABC-1",
        "self": "https://jira.example/rest/api/2/issue/10001",
        "fields": {
            "summary": "Quarterly plan",
            "assignee": null,
            "customfield_1": "secret value",
            "customfield_2": "keep me",
            "comment": {
                "comments": [
                    {"id": "5", "body": "first comment"},
                    {"id": "6", "body": "second comment"}
                ],
                "total": 2
            }
        },
        "renderedFields": {
            "summary": "Quarterly plan",
            "customfield_1": "<p>secret value</p>",
            "customfield_2": "<p>keep me</p>",
            "comment": {
                "comments": [
                    {"id": "5", "body": "<p>first comment</p>"},
                    {"id": "6", "body": "<p>second comment</p>"}
                ]
            }
        },
        "names": {"summary": "Summary", "customfield_1": "Secret Field", "customfield_2": "Other"},
        "schema": {
            "summary": {"type": "string"},
            "customfield_1": {"type": "string"},
            "customfield_2": {"type": "string"}
        },
        "editmeta": {"fields": {"summary": {"required": true}, "customfield_1": {"required": false}}},
        "changelog": {
            "histories": [
                {"id": "100", "items": [
                    {"field": "Secret Field", "fieldtype": "custom", "fieldId": "customfield_1",
                     "fromString": "a", "toString": "secret value"}
                ]},
                {"id": "101", "items": [
                    {"field": "summary", "fieldtype": "jira", "fieldId": "summary",
                     "fromString": "draft", "toString": "Quarterly plan"},
                    {"field": "Secret Field", "fieldtype": "custom", "fieldId": "customfield_1",
                     "toString": "b"}
                ]},
                {"id": "102", "items": [
                    {"field": "customfield_1", "fieldtype": "custom", "toString": "c"}
                ]}
            ]
        }
    })
}

#[test]
fn u26_drop_field_removes_copies() -> TestResult {
    let out = apply(
        &issue_fixture(),
        rules("jira.issue.get")?,
        None,
        &[drop_field("fields.customfield_1", DropScope::AllItems)],
    );
    let r = &out.released;
    for copy in ["fields", "renderedFields", "names", "schema"] {
        assert!(
            r[copy].get("customfield_1").is_none(),
            "{copy} still has it"
        );
        assert!(
            r[copy].get("customfield_2").is_some(),
            "{copy} lost an undropped field"
        );
    }
    assert!(r["editmeta"]["fields"].get("customfield_1").is_none());
    assert_eq!(
        r["editmeta"]["fields"]["summary"],
        json!({"required": true})
    );
    // 100 and 102 had only customfield_1 items: removed whole (an empty `items` would look empty).
    assert_eq!(
        r["changelog"]["histories"],
        json!([{"id": "101", "items": [
            {"field": "summary", "fieldtype": "jira", "fieldId": "summary",
             "fromString": "draft", "toString": "Quarterly plan"}
        ]}])
    );
    assert_eq!(out.meta.fields_dropped, vec!["customfield_1".to_owned()]);
    assert_eq!(out.meta.items_dropped, 0);
    assert_eq!(out.meta.spans_masked, 0);
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert_eq!(r["fields"]["assignee"], Value::Null);
    Ok(())
}

fn search_fixture() -> Value {
    let issue = |key: &str, id: &str| {
        json!({
            "key": key,
            "fields": {"summary": format!("{key} summary"), "customfield_1": format!("{key} secret"),
                       "comment": {"comments": [{"id": id, "body": "c"}]}},
            "renderedFields": {"customfield_1": format!("<p>{key} secret</p>"),
                               "comment": {"comments": [{"id": id, "body": "<p>c</p>"}]}}
        })
    };
    json!({
        "startAt": 0, "maxResults": 50, "total": 2,
        "names": {"summary": "Summary", "customfield_1": "Secret Field"},
        "schema": {"summary": {"type": "string"}, "customfield_1": {"type": "string"}},
        "issues": [issue("ABC-1", "11"), issue("ABC-2", "21")]
    })
}

#[test]
fn u26_search_copies_are_item_relative() -> TestResult {
    let r = rules("jira.search")?;
    // Per item: only ABC-1 and its rendered copy; the response-level maps stay.
    let out = apply(
        &search_fixture(),
        r,
        Some("issues"),
        &[drop_field(
            "issues[key=ABC-1].fields.customfield_1",
            DropScope::PerItem,
        )],
    );
    let issues = &out.released["issues"];
    assert!(issues[0]["fields"].get("customfield_1").is_none());
    assert!(issues[0]["renderedFields"].get("customfield_1").is_none());
    assert_eq!(issues[1]["fields"]["customfield_1"], "ABC-2 secret");
    assert_eq!(
        issues[1]["renderedFields"]["customfield_1"],
        "<p>ABC-2 secret</p>"
    );
    assert!(out.released["names"].get("customfield_1").is_some());
    assert_eq!(out.meta.fields_dropped, vec!["customfield_1".to_owned()]);

    // All items: every issue plus the document-root `names`/`schema` copies.
    let out = apply(
        &search_fixture(),
        r,
        Some("issues"),
        &[drop_field(
            "issues[].fields.customfield_1",
            DropScope::AllItems,
        )],
    );
    for i in 0..2 {
        assert!(
            out.released["issues"][i]["fields"]
                .get("customfield_1")
                .is_none()
        );
        assert!(
            out.released["issues"][i]["renderedFields"]
                .get("customfield_1")
                .is_none()
        );
    }
    assert!(out.released["names"].get("customfield_1").is_none());
    assert!(out.released["schema"].get("customfield_1").is_none());
    assert_eq!(out.released["names"]["summary"], "Summary");
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);

    // Item drops count only elements of `items_key`; server totals are never rewritten.
    let out = apply(
        &search_fixture(),
        r,
        Some("issues"),
        &[
            RedactionOp::DropItem {
                array_path: "issues".into(),
                key: "key".into(),
                value: json!("ABC-2"),
            },
            RedactionOp::DropItem {
                array_path: "issues[].fields.comment.comments".into(),
                key: "id".into(),
                value: json!("11"),
            },
        ],
    );
    assert_eq!(out.meta.items_dropped, 1);
    assert_eq!(out.released["total"], 2);
    let issues = out.released["issues"].as_array().ok_or("issues")?;
    assert_eq!(issues.len(), 1);
    // The mirror is item-relative: the rendered comment 11 of ABC-1 went with it.
    assert_eq!(issues[0]["fields"]["comment"]["comments"], json!([]));
    assert_eq!(
        issues[0]["renderedFields"]["comment"]["comments"],
        json!([])
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    Ok(())
}

#[test]
fn u26_mask_every_occurrence() -> TestResult {
    let candidate = json!({
        "fields": {
            "summary": "ACME-SECRET and again ACME-SECRET",
            "description": "see ACME%2DSECRET%2Fdocs",
            "environment": "ACME\u{200B}-SECRET",
            "labels": ["ACME-SECRET", "other"],
            "comment": {"comments": [{"id": "5", "body": "mentions ACME-SECRET once"}]}
        },
        "renderedFields": {
            "description": "<p>see ACME&#45;SECRET&#x2F;docs</p>",
            "comment": {"comments": [{"id": "5", "body": "<p>mentions ACME&#x2d;SECRET once</p>"}]}
        }
    });
    let out = apply(
        &candidate,
        rules("jira.issue.get")?,
        None,
        &[mask("ACME-SECRET")],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    for s in strings(&out.released) {
        assert!(!canonical_hit(&s, "ACME-SECRET"), "still in {s:?}");
    }
    let f = &out.released["fields"];
    assert_eq!(f["summary"], "[REDACTED] and again [REDACTED]");
    // Re-encoded in the original encoding: the rest of the value keeps its escapes.
    assert_eq!(f["description"], "see [REDACTED]%2Fdocs");
    assert_eq!(f["environment"], "[REDACTED]");
    assert_eq!(f["labels"], json!(["[REDACTED]", "other"]));
    assert_eq!(
        out.released["renderedFields"]["description"],
        "<p>see [REDACTED]&#x2F;docs</p>"
    );
    assert_eq!(out.meta.spans_masked, 8);
    assert!(out.meta.fields_dropped.is_empty());
    assert!(out.needs_confirmation.is_empty());
    assert_eq!(out.also_appears_in.len(), 7, "{:?}", out.also_appears_in);
    Ok(())
}

#[test]
fn u26_single_occurrence_mask_needs_confirmation() -> TestResult {
    let candidate = json!({
        "a": "Falcon one",
        "b": {"c": "two Falcon"},
        "d": ["x", "Falcon three"]
    });
    let single = |at: Option<&str>| RedactionOp::MaskText {
        text: "Falcon".into(),
        every_occurrence: false,
        at: at.map(str::to_owned),
    };
    let out = apply(&candidate, &NO_RULES, None, &[single(None)]);
    assert_eq!(out.released["a"], "[REDACTED] one");
    assert_eq!(out.released["b"]["c"], "two Falcon");
    assert_eq!(
        out.needs_confirmation,
        vec!["2 other occurrences remain".to_owned()]
    );
    assert_eq!(out.meta.spans_masked, 1);
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert_eq!(out.also_appears_in, vec!["a", "b.c", "d[1]"]);

    let out = apply(&candidate, &NO_RULES, None, &[single(Some("d[1]"))]);
    assert_eq!(out.released["d"][1], "[REDACTED] three");
    assert_eq!(out.released["a"], "Falcon one");
    assert_eq!(
        out.needs_confirmation,
        vec!["2 other occurrences remain".to_owned()]
    );

    // A selection that is not there fails closed instead of releasing the text.
    let out = apply(&candidate, &NO_RULES, None, &[single(Some("d[0]"))]);
    assert!(has_block(
        &out,
        &BlockReason::MaskTargetMissing {
            path: "d[0]".into()
        }
    ));
    Ok(())
}

#[test]
fn u26_mirror_check_blocks_orphan() -> TestResult {
    let r = rules("jira.issue.get")?;
    let mut orphan = issue_fixture();
    if let Some(a) = orphan["renderedFields"]["comment"]["comments"].as_array_mut() {
        a.push(json!({"id": "7", "body": "<p>rendered only</p>"}));
    }
    let out = apply(&orphan, r, None, &[]);
    assert!(has_block(
        &out,
        &BlockReason::MirrorOrphan {
            path: "renderedFields.comment.comments[2]".into()
        }
    ));

    let out = apply(
        &issue_fixture(),
        r,
        None,
        &[RedactionOp::DropItem {
            array_path: "fields.comment.comments".into(),
            key: "id".into(),
            value: json!("5"),
        }],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert_eq!(
        out.released["fields"]["comment"]["comments"],
        json!([{"id": "6", "body": "second comment"}])
    );
    assert_eq!(
        out.released["renderedFields"]["comment"]["comments"],
        json!([{"id": "6", "body": "<p>second comment</p>"}])
    );
    assert_eq!(out.meta.items_dropped, 1);

    // Dropping on the rendered side removes the source entry too.
    let out = apply(
        &issue_fixture(),
        r,
        None,
        &[RedactionOp::DropItem {
            array_path: "renderedFields.comment.comments".into(),
            key: "id".into(),
            value: json!("6"),
        }],
    );
    assert_eq!(
        out.released["fields"]["comment"]["comments"],
        json!([{"id": "5", "body": "first comment"}])
    );

    // A per-item field drop removes the same key on the mirrored entry.
    let out = apply(
        &issue_fixture(),
        r,
        None,
        &[drop_field(
            "fields.comment.comments[id=6].body",
            DropScope::PerItem,
        )],
    );
    assert_eq!(
        out.released["renderedFields"]["comment"]["comments"][1],
        json!({"id": "6"})
    );
    assert_eq!(
        out.released["fields"]["comment"]["comments"][1],
        json!({"id": "6"})
    );
    assert_eq!(out.meta.fields_dropped, vec!["body".to_owned()]);
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);

    // A per-item mask applies to the mirrored entry (in its own encoding).
    let mut c = issue_fixture();
    c["fields"]["comment"]["comments"][0]["body"] = json!("call Müller");
    c["renderedFields"]["comment"]["comments"][0]["body"] = json!("<p>call M&uuml;ller</p>");
    let out = apply(
        &c,
        r,
        None,
        &[RedactionOp::MaskText {
            text: "Müller".into(),
            every_occurrence: false,
            at: Some("fields.comment.comments[0].body".into()),
        }],
    );
    assert_eq!(
        out.released["fields"]["comment"]["comments"][0]["body"],
        "call [REDACTED]"
    );
    assert_eq!(
        out.released["renderedFields"]["comment"]["comments"][0]["body"],
        "<p>call [REDACTED]</p>"
    );
    assert!(
        out.needs_confirmation.is_empty(),
        "{:?}",
        out.needs_confirmation
    );

    // Keyless entries: matched by position only when both arrays have the same length.
    let keyless = json!({
        "fields": {"comment": {"comments": [{"body": "a"}, {"body": "b"}]}},
        "renderedFields": {"comment": {"comments": [{"body": "<p>a</p>"}]}}
    });
    let out = apply(
        &keyless,
        r,
        None,
        &[drop_field("fields.comment.comments[0]", DropScope::PerItem)],
    );
    assert!(has_block(
        &out,
        &BlockReason::MirrorUnmatchable {
            path: "fields.comment.comments[0]".into()
        }
    ));
    // A rendered array without a source array at all: every entry is an orphan.
    let only_rendered = json!({"renderedFields": {"attachment": [{"id": "9", "filename": "x"}]}});
    let out = apply(&only_rendered, r, None, &[]);
    assert!(has_block(
        &out,
        &BlockReason::MirrorOrphan {
            path: "renderedFields.attachment[0]".into()
        }
    ));
    Ok(())
}

/// §13 U-28 verbatim fixture, as a `confluence.search` result.
fn falcon_fixture() -> Value {
    json!({
        "results": [{
            "title": "Falcon Müller Plan",
            "url": "/display/LEGAL/Falcon+M%C3%BCller+Plan",
            "excerpt": "Falcon%20M%c3%bcller%20Plan",
            "content": {"title": "Falcon M&#252;ller Plan", "_links": {"webui": "/pages/1"}},
            "resultGlobalContainer": {"title": "Falcon M&uuml;ller Plan", "displayUrl": "/display/LEGAL"},
            "lastModified": "Falcon Mu\u{308}ller Plan",
            "entityType": "content",
            "breadcrumbs": "x Falcon%20M%C3%BCller%20Plan%2Fv2 and Falcon M&uuml;ller Plan&amp;co"
        }],
        "start": 0, "limit": 25, "size": 1,
        "_links": {"base": "https://confluence.example"}
    })
}

const FALCON_PATHS: [&str; 7] = [
    "results[0].breadcrumbs",
    "results[0].content.title",
    "results[0].excerpt",
    "results[0].lastModified",
    "results[0].resultGlobalContainer.title",
    "results[0].title",
    "results[0].url",
];

#[test]
fn u28_falcon_mueller_canonical_match() -> TestResult {
    let r = rules("confluence.search")?;
    let title = "Falcon Müller Plan";
    let fixture = falcon_fixture();
    let mut listed = also_appears_in(&fixture, title);
    listed.sort();
    assert_eq!(listed, FALCON_PATHS);

    let out = apply(
        &fixture,
        r,
        Some("results"),
        &[
            mask(title),
            RedactionOp::UrlField {
                mode: UrlMode::ReplaceWhole,
            },
        ],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    let res = &out.released["results"][0];
    assert_eq!(res["title"], "[REDACTED]");
    assert_eq!(res["url"], "[REDACTED]");
    assert_eq!(res["excerpt"], "[REDACTED]");
    assert_eq!(res["content"]["title"], "[REDACTED]");
    assert_eq!(res["resultGlobalContainer"]["title"], "[REDACTED]");
    assert_eq!(res["lastModified"], "[REDACTED]");
    assert_eq!(
        res["breadcrumbs"],
        "x [REDACTED]%2Fv2 and [REDACTED]&amp;co"
    );
    assert_eq!(res["entityType"], "content");
    let mut listed = out.also_appears_in.clone();
    listed.sort();
    assert_eq!(listed, FALCON_PATHS);
    for s in strings(&out.released) {
        assert!(!canonical_hit(&s, title), "still in {s:?}");
    }

    // The user's other choice for a URL field: drop it and say so.
    let out = apply(
        &fixture,
        r,
        Some("results"),
        &[
            mask(title),
            RedactionOp::UrlField {
                mode: UrlMode::Drop,
            },
        ],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert!(out.released["results"][0].get("url").is_none());
    assert_eq!(out.meta.fields_dropped, vec!["url".to_owned()]);

    // No URL choice made: the URL still carries the title, so release stays blocked.
    let out = apply(&fixture, r, Some("results"), &[mask(title)]);
    assert!(has_block(
        &out,
        &BlockReason::MaskStillOccurs {
            path: "results[0].url".into()
        }
    ));
    assert!(out.also_appears_in.iter().any(|p| p == "results[0].url"));
    Ok(())
}

#[test]
fn views_fixpoint_three_rounds() -> TestResult {
    assert!(views("%2525252541").unstable);
    let three = views("%252541");
    assert!(!three.unstable);
    assert!(three.forms.iter().any(|f| f == "A"));
    // The `+` view always applies, with or without a `%` in the value.
    assert!(views("a+b").forms.iter().any(|f| f == "a b"));
    // NFC of each view; hex matched case-insensitively.
    assert!(canonical_hit("M%c3%bcller", "Müller"));
    assert!(canonical_hit("Mu\u{308}ller", "Müller"));
    assert!(canonical_hit("M&#xFC;ller", "Mu\u{308}ller"));
    assert!(!canonical_hit("Mueller", "Müller"));
    assert!(!canonical_hit("anything", ""));
    Ok(())
}

#[test]
fn canonical_form_extra_views() -> TestResult {
    // Plan additions (fail closed, over-match only): invisible characters (§6.4 classifier) and
    // semicolonless character references as browsers decode them.
    assert!(canonical_hit("ACME\u{200B}-SEC\u{2060}RET", "ACME-SECRET"));
    assert!(canonical_hit("M&uumlller", "Müller"));
    assert!(canonical_hit("M&#252ller", "Müller"));
    // html-escape decodes `&fjlig;` to `f` only; the lenient view reads `fj`.
    assert!(canonical_hit("&fjlig;ord", "fjord"));
    // Composed encodings: an entity-encoded percent sequence.
    assert!(canonical_hit("M&#37;C3&#37;BCller", "Müller"));
    Ok(())
}

#[test]
fn composed_encodings_are_masked_in_place() -> TestResult {
    let candidate = json!({
        "double": "a%2520M%25C3%25BCller%2520b",
        "entity_pct": "a M&#37;C3&#37;BCller b",
        "lenient": "a M&uumlller b"
    });
    let out = apply(&candidate, &NO_RULES, None, &[mask("Müller")]);
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert_eq!(out.released["double"], "a%2520[REDACTED]%2520b");
    assert_eq!(out.released["entity_pct"], "a [REDACTED] b");
    assert_eq!(out.released["lenient"], "a [REDACTED] b");
    Ok(())
}

#[test]
fn ambiguous_unstable_keys_and_numbers_block() -> TestResult {
    // NFC turns `e`, U+20D2, U+0301 into `é`, U+20D2: a match starting at U+20D2 begins inside
    // what NFC rebuilt from three raw characters, so it cannot be re-encoded.
    let out = apply(
        &json!({"v": "e\u{20D2}\u{301}X"}),
        &NO_RULES,
        None,
        &[mask("\u{20D2}X")],
    );
    assert!(has_block(
        &out,
        &BlockReason::ReencodeAmbiguous { path: "v".into() }
    ));
    assert_eq!(out.also_appears_in, vec!["v"]);

    // Four levels of percent encoding: still changing after round 3 (fail closed).
    let out = apply(
        &json!({"v": "%2525252541", "w": "fine"}),
        &NO_RULES,
        None,
        &[mask("zzz")],
    );
    assert!(has_block(
        &out,
        &BlockReason::UnstableEncoding { path: "v".into() }
    ));
    assert!(out.also_appears_in.iter().any(|p| p == "v"));
    // No every-occurrence mask: an unstable value alone does not block.
    let out = apply(&json!({"v": "%2525252541"}), &NO_RULES, None, &[]);
    assert!(out.blocked.is_empty());

    // Keys are never rewritten, so a key hit blocks; so does a number's text.
    let out = apply(
        &json!({"o": {"ACME-SECRET": 1}, "n": 47110}),
        &NO_RULES,
        None,
        &[mask("ACME-SECRET"), mask("4711")],
    );
    assert!(has_block(
        &out,
        &BlockReason::MaskStillOccurs {
            path: "o.ACME-SECRET".into()
        }
    ));
    assert!(has_block(
        &out,
        &BlockReason::MaskStillOccurs { path: "n".into() }
    ));
    Ok(())
}

#[test]
fn u29_upstream_null_survives() -> TestResult {
    let candidate = json!({
        "fields": {"assignee": null, "customfield_1": "x", "duedate": null,
                   "labels": [null, "ACME"], "parent": {"fields": {"summary": null}}}
    });
    let out = apply(
        &candidate,
        rules("jira.issue.get")?,
        None,
        &[
            drop_field("fields.customfield_1", DropScope::AllItems),
            mask("ACME"),
        ],
    );
    let f = &out.released["fields"];
    assert_eq!(f.get("assignee"), Some(&Value::Null));
    assert_eq!(f.get("duedate"), Some(&Value::Null));
    assert_eq!(f["labels"], json!([null, "[REDACTED]"]));
    assert_eq!(f["parent"]["fields"].get("summary"), Some(&Value::Null));
    assert!(f.get("customfield_1").is_none());
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    Ok(())
}

#[test]
fn presets_status_only_and_error_class_only() -> TestResult {
    let upstream = json!({"status": 404, "error_messages": ["Issue does not exist"]});
    let out = apply(
        &upstream,
        &NO_RULES,
        None,
        &[RedactionOp::Preset(RedactionPreset::StatusOnly)],
    );
    assert_eq!(out.released, json!({"status": 404}));
    assert_eq!(out.meta.fields_dropped, vec!["error_messages".to_owned()]);
    assert!(out.blocked.is_empty());
    // Allowlist: whatever else an error candidate carries goes too.
    let out = apply(
        &json!({"status": 400, "error_messages": [], "errors": {"summary": "x"}}),
        &NO_RULES,
        None,
        &[RedactionOp::Preset(RedactionPreset::StatusOnly)],
    );
    assert_eq!(out.released, json!({"status": 400}));
    assert_eq!(
        out.meta.fields_dropped,
        vec!["error_messages".to_owned(), "errors".to_owned()]
    );

    let script = json!({"script_error": {
        "class": "TypeError", "message": "x is null", "stack": "at main:3", "logs": ["l"],
        "elapsed": 1200, "stderr": "boom"
    }});
    let out = apply(
        &script,
        &NO_RULES,
        None,
        &[RedactionOp::Preset(RedactionPreset::ErrorClassOnly)],
    );
    assert_eq!(
        out.released,
        json!({"script_error": {"class": "TypeError"}})
    );
    assert_eq!(
        out.meta.fields_dropped,
        ["elapsed", "logs", "message", "stack", "stderr"]
            .map(str::to_owned)
            .to_vec()
    );
    Ok(())
}

#[test]
fn debug_is_redacted() -> TestResult {
    const S: &str = "SENTINEL-4711";
    let ops = vec![
        RedactionOp::MaskText {
            text: S.into(),
            every_occurrence: true,
            at: Some(S.into()),
        },
        RedactionOp::DropItem {
            array_path: S.into(),
            key: S.into(),
            value: json!(S),
        },
        RedactionOp::DropField {
            path: S.into(),
            scope: DropScope::PerItem,
        },
    ];
    let out = apply(&json!({"a": S, "b": [S]}), &NO_RULES, None, &[]);
    let dumps = [
        format!("{ops:?}"),
        format!("{out:?}"),
        format!("{:?}", out.meta),
    ];
    for d in dumps {
        assert!(!d.contains(S), "{d}");
    }
    Ok(())
}

#[test]
fn ops_roundtrip_through_serde() -> TestResult {
    let ops = vec![
        mask("x"),
        drop_field("fields.customfield_1", DropScope::AllItems),
        RedactionOp::DropItem {
            array_path: "issues".into(),
            key: "key".into(),
            value: json!("A-1"),
        },
        RedactionOp::UrlField {
            mode: UrlMode::Drop,
        },
        RedactionOp::Preset(RedactionPreset::StatusOnly),
    ];
    let text = serde_json::to_string(&ops)?;
    let back: Vec<RedactionOp> = serde_json::from_str(&text)?;
    assert_eq!(back, ops);
    let meta = serde_json::to_value(apply(&json!({"a": 1}), &NO_RULES, None, &[]).meta)?;
    assert_eq!(
        meta,
        json!({"items_dropped": 0, "fields_dropped": [], "spans_masked": 0})
    );
    Ok(())
}

// ---- U-29 property test ----

/// A random object (depth ≤ 4). Arrays hold objects with a unique `id`, so a path can address an
/// element stably (`[id=…]`) across index shifts.
fn arb_value(depth: u32) -> BoxedStrategy<Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        Just(json!("")),
        "[a-z]{1,6}".prop_map(Value::from),
        any::<i32>().prop_map(Value::from),
        any::<bool>().prop_map(Value::from),
    ];
    if depth == 0 {
        return leaf.boxed();
    }
    let obj = prop::collection::btree_map("[a-e]", arb_value(depth - 1), 0..4)
        .prop_map(|m| Value::Object(m.into_iter().collect::<Map<String, Value>>()));
    let arr = prop::collection::vec(
        prop::collection::btree_map("[a-e]", arb_value(depth - 1), 0..3),
        0..4,
    )
    .prop_map(|items| {
        Value::Array(
            items
                .into_iter()
                .enumerate()
                .map(|(i, m)| {
                    let mut o: Map<String, Value> = m.into_iter().collect();
                    o.insert("id".into(), json!(format!("i{i}")));
                    Value::Object(o)
                })
                .collect(),
        )
    });
    prop_oneof![2 => leaf, 2 => obj, 1 => arr].boxed()
}

fn arb_root() -> impl Strategy<Value = Value> {
    prop::collection::btree_map("[a-e]", arb_value(3), 1..5)
        .prop_map(|m| Value::Object(m.into_iter().collect::<Map<String, Value>>()))
}

/// Every addressable node: (grammar path, is an array element, value).
fn nodes(v: &Value, prefix: &str, out: &mut Vec<(String, bool, Value)>) {
    if let Value::Object(o) = v {
        // `id` is what element paths select by; dropping it is not what this property is about.
        for (k, x) in o.iter().filter(|(k, _)| k.as_str() != "id") {
            let p = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            out.push((p.clone(), false, x.clone()));
            if let Value::Array(a) = x {
                for e in a {
                    if let Some(id) = e.get("id").and_then(Value::as_str) {
                        let ep = format!("{p}[id={id}]");
                        out.push((ep.clone(), true, e.clone()));
                        nodes(e, &ep, out);
                    }
                }
            } else {
                nodes(x, &p, out);
            }
        }
    }
}

/// Values at a grammar path (only `name` and `name[id=…]` segments are generated).
fn lookup<'a>(v: &'a Value, path: &str) -> Vec<&'a Value> {
    let mut cur = vec![v];
    for seg in path.split('.') {
        let (name, sel) = match seg.find('[') {
            Some(i) => (
                &seg[..i],
                Some(seg[i + 1..seg.len() - 1].trim_start_matches("id=")),
            ),
            None => (seg, None),
        };
        let mut next = Vec::new();
        for c in cur {
            if let Some(x) = c.get(name) {
                match sel {
                    None => next.push(x),
                    Some(id) => next.extend(
                        x.as_array()
                            .into_iter()
                            .flatten()
                            .filter(|e| e.get("id").and_then(Value::as_str) == Some(id)),
                    ),
                }
            }
        }
        cur = next;
    }
    cur
}

fn looks_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn u29_drops_never_look_empty(doc in arb_root(), picks in prop::collection::vec((any::<prop::sample::Index>(), any::<bool>()), 1..4)) {
        let mut all = Vec::new();
        nodes(&doc, "", &mut all);
        prop_assume!(!all.is_empty());
        let mut ops = Vec::new();
        let mut targeted: Vec<String> = Vec::new();
        for (ix, per_item) in &picks {
            let (path, is_elem, _) = &all[ix.index(all.len())];
            targeted.push(path.clone());
            if *is_elem {
                let (array_path, id) = path.rsplit_once("[id=")
                    .ok_or_else(|| TestCaseError::fail("element path"))?;
                ops.push(RedactionOp::DropItem {
                    array_path: array_path.to_owned(),
                    key: "id".into(),
                    value: json!(id.trim_end_matches(']')),
                });
            } else {
                let scope = if *per_item { DropScope::PerItem } else { DropScope::AllItems };
                ops.push(RedactionOp::DropField { path: path.clone(), scope });
            }
        }
        let out = apply(&doc, &NO_RULES, None, &ops);
        for t in &targeted {
            for v in lookup(&out.released, t) {
                prop_assert!(!looks_empty(v), "{t} looks empty: {v}");
            }
        }
        // A `PerItem` drop of a plain path and every `DropItem` target only what was named, so
        // every `null` outside a targeted subtree is still there.
        let widened = ops.iter().any(|o| matches!(o, RedactionOp::DropField { scope: DropScope::AllItems, .. }));
        for (path, _, v) in &all {
            if v.is_null() && !targeted.iter().any(|t| path == t || path.starts_with(&format!("{t}.")) || path.starts_with(&format!("{t}["))) {
                let now = lookup(&out.released, path);
                if !widened {
                    prop_assert_eq!(now, vec![&Value::Null], "untargeted null at {}", path);
                } else {
                    prop_assert!(now.iter().all(|x| x.is_null()), "null changed at {}", path);
                }
            }
        }
        prop_assert!(out.blocked.is_empty());
    }
}

#[test]
fn needle_inside_the_placeholder_converges() -> TestResult {
    // A codename that is part of `[REDACTED]` itself: the placeholder text is public.
    let candidate = json!({"a": "Project RED and RED%20team", "b": "R&#69;D"});
    let out = apply(&candidate, &NO_RULES, None, &[mask("RED")]);
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert_eq!(
        out.released["a"],
        "Project [REDACTED] and [REDACTED]%20team"
    );
    assert_eq!(out.released["b"], "[REDACTED]");
    assert_eq!(out.meta.spans_masked, 3);
    Ok(())
}

/// One encoding of `s` a value may carry it in.
fn encode(s: &str, how: u8) -> String {
    let bytes = |f: &dyn Fn(u8) -> String| s.bytes().map(f).collect::<String>();
    match how % 9 {
        0 => s.to_owned(),
        1 => bytes(&|b| format!("%{b:02X}")),
        2 => bytes(&|b| format!("%{b:02x}")),
        3 => s.chars().map(|c| format!("&#{};", c as u32)).collect(),
        4 => s.chars().map(|c| format!("&#x{:x};", c as u32)).collect(),
        5 => s
            .chars()
            .map(|c| match c {
                'ä' => "a\u{308}".to_owned(),
                'ö' => "o\u{308}".to_owned(),
                'ü' => "u\u{308}".to_owned(),
                c => c.to_string(),
            })
            .collect(),
        6 => s
            .chars()
            .map(|c| format!("{c}\u{200B}"))
            .collect::<String>()
            .trim_end_matches('\u{200B}')
            .to_owned(),
        7 => bytes(&|b| format!("%25{b:02X}")),
        _ => bytes(&|b| format!("&#37;{b:02X}")),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Every supported encoding of a masked string is masked in place, and nothing that still
    /// matches is ever released unblocked.
    #[test]
    fn mask_every_occurrence_is_sound(
        needle in "[a-zäöü]{3,8}",
        parts in prop::collection::vec(("[a-z ]{0,4}", any::<u8>(), "[a-z ]{0,4}"), 1..5),
    ) {
        let mut doc = Map::new();
        for (i, (pre, how, post)) in parts.iter().enumerate() {
            doc.insert(format!("k{i}"), json!(format!("{pre}{}{post}", encode(&needle, *how))));
        }
        let out = apply(&Value::Object(doc), &NO_RULES, None, &[mask(&needle)]);
        prop_assert!(out.blocked.is_empty(), "{:?} for {:?}", out.blocked, parts);
        for s in strings(&out.released) {
            prop_assert!(!canonical_hit(&s, &needle), "{s:?} still matches {needle:?}");
        }
        prop_assert!(out.meta.spans_masked >= parts.len() as u64);
    }
}

#[test]
fn all_items_widens_only_the_items_before_the_field() -> TestResult {
    let r = rules("jira.search")?;
    let mut doc = search_fixture();
    // ABC-2 has a rendered copy and a changelog entry but no `fields.customfield_1` itself.
    if let Some(f) = doc["issues"][1]["fields"].as_object_mut() {
        f.remove("customfield_1");
    }
    doc["issues"][1]["changelog"] = json!({"histories": [
        {"id": "7", "items": [{"field": "Secret Field", "fieldId": "customfield_1", "toString": "s"}]}
    ]});
    let out = apply(
        &doc,
        r,
        Some("issues"),
        &[drop_field(
            "issues[key=ABC-1].fields.customfield_1",
            DropScope::AllItems,
        )],
    );
    let issues = &out.released["issues"];
    assert!(issues[1]["renderedFields"].get("customfield_1").is_none());
    assert!(
        issues[1]["changelog"]["histories"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    assert!(out.released["names"].get("customfield_1").is_none());
    assert_eq!(out.meta.fields_dropped, vec!["customfield_1".to_owned()]);

    // The last segment keeps its selector: "this issue", not "every issue".
    let out = apply(
        &search_fixture(),
        r,
        Some("issues"),
        &[drop_field("issues[key=ABC-1]", DropScope::AllItems)],
    );
    let issues = out.released["issues"].as_array().ok_or("issues")?;
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0]["key"], "ABC-2");
    assert_eq!(out.meta.items_dropped, 1);
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    Ok(())
}
