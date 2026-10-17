//! U-26 (redaction engine, copies, mirrors, mask everywhere), U-28 (canonical match form, the
//! "Falcon Müller Plan" fixture), U-29 core half (drops never look empty, upstream `null`s stay).

use atlas_duck_core::engine::script::SCRIPT_SPEC;
use atlas_duck_core::redact::views::{canonical_hit, views};
use atlas_duck_core::redact::{
    BlockReason, DropScope, REDACTED, RedactionOp, RedactionOutcome, RedactionPreset, UrlMode,
    also_appears_in, apply, invalid_rule_paths,
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
        &BlockReason::OpTargetMissing {
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
        mask(S),
        RedactionOp::DropField {
            path: format!("p.{S}"),
            scope: DropScope::PerItem,
        },
        RedactionOp::DropItem {
            array_path: "b".into(),
            key: "id".into(),
            value: json!(S),
        },
        RedactionOp::MaskText {
            text: S.into(),
            every_occurrence: false,
            at: Some(format!("o.{S}")),
        },
    ];
    let candidate = json!({
        "a": format!("x {S}"),
        "b": [{"id": S}, {"id": "2", "v": S}],
        "o": {S: 1},
        "p": {S: 2}
    });
    let out = apply(&candidate, &NO_RULES, None, &ops);
    // The secret key under `o` blocks (keys are never rewritten); the dropped one is withheld.
    assert!(!out.blocked.is_empty());
    assert_eq!(out.meta.fields_dropped, vec![REDACTED.to_owned()]);
    let dumps = [
        format!("{ops:?}"),
        format!("{out:?}"),
        format!("{:?}", out.meta),
        format!("{:?}", out.blocked),
        format!("{:?}", views(&format!("a%20{S}"))),
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

/// The U-29 property over `candidate`, whose addressable nodes are those of `root` below
/// `prefix` (`""`: `root` is the candidate): whatever drops are applied, no dropped path holds
/// `null`, `""`, `[]` or `{}` afterwards, and an `null` the drops did not target is still there.
fn drops_never_look_empty(
    candidate: &Value,
    root: &Value,
    prefix: &str,
    rules: &RedactionRules,
    picks: &[(prop::sample::Index, bool)],
) -> Result<(), TestCaseError> {
    let mut all = Vec::new();
    nodes(root, prefix, &mut all);
    prop_assume!(!all.is_empty());
    let mut ops = Vec::new();
    let mut targeted: Vec<String> = Vec::new();
    for (ix, per_item) in picks {
        let (path, is_elem, _) = &all[ix.index(all.len())];
        targeted.push(path.clone());
        if *is_elem {
            let (array_path, id) = path
                .rsplit_once("[id=")
                .ok_or_else(|| TestCaseError::fail("element path"))?;
            ops.push(RedactionOp::DropItem {
                array_path: array_path.to_owned(),
                key: "id".into(),
                value: json!(id.trim_end_matches(']')),
            });
        } else {
            let scope = if *per_item {
                DropScope::PerItem
            } else {
                DropScope::AllItems
            };
            ops.push(RedactionOp::DropField {
                path: path.clone(),
                scope,
            });
        }
    }
    let out = apply(candidate, rules, None, &ops);
    for t in &targeted {
        for v in lookup(&out.released, t) {
            prop_assert!(!looks_empty(v), "{t} looks empty: {v}");
        }
    }
    // A `PerItem` drop of a plain path and every `DropItem` target only what was named, so
    // every `null` outside a targeted subtree is still there.
    let widened = ops.iter().any(|o| {
        matches!(
            o,
            RedactionOp::DropField {
                scope: DropScope::AllItems,
                ..
            }
        )
    });
    for (path, _, v) in &all {
        let inside = |t: &String| {
            path == t || path.starts_with(&format!("{t}.")) || path.starts_with(&format!("{t}["))
        };
        if v.is_null() && !targeted.iter().any(inside) {
            let now = lookup(&out.released, path);
            if !widened {
                prop_assert_eq!(now, vec![&Value::Null], "untargeted null at {}", path);
            } else {
                prop_assert!(now.iter().all(|x| x.is_null()), "null changed at {}", path);
            }
        }
    }
    prop_assert!(out.blocked.is_empty());
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn u29_drops_never_look_empty(doc in arb_root(), picks in prop::collection::vec((any::<prop::sample::Index>(), any::<bool>()), 1..4)) {
        drops_never_look_empty(&doc, &doc, "", &NO_RULES, &picks)?;
    }

    /// A script's candidate is `{result: <anything the script returned>}` (§9.3): the same
    /// property below `result`, with the rules of `script.run` (U-29, script results).
    #[test]
    fn u29_script_result_drops_never_empty(result in arb_root(), picks in prop::collection::vec((any::<prop::sample::Index>(), any::<bool>()), 1..4)) {
        let candidate = json!({ "result": result });
        drops_never_look_empty(&candidate, &result, "result", &SCRIPT_SPEC.redaction_rules, &picks)?;
    }
}

/// U-29 (script results): an upstream `null` in a script's result survives drops and masks, and so
/// does a result that is `null` itself.
#[test]
fn u29_script_result_upstream_null_survives() -> TestResult {
    let rules = &SCRIPT_SPEC.redaction_rules;
    let candidate = json!({"result": {
        "assignee": null, "secret": "x", "duedate": null,
        "labels": [null, "ACME"], "parent": {"summary": null}
    }});
    let out = apply(
        &candidate,
        rules,
        None,
        &[
            drop_field("result.secret", DropScope::AllItems),
            mask("ACME"),
        ],
    );
    let r = &out.released["result"];
    assert_eq!(r.get("assignee"), Some(&Value::Null));
    assert_eq!(r.get("duedate"), Some(&Value::Null));
    assert_eq!(r["labels"], json!([null, "[REDACTED]"]));
    assert_eq!(r["parent"].get("summary"), Some(&Value::Null));
    assert!(r.get("secret").is_none());
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    // A script that returned `null`: nothing to drop or mask, and the `null` is not touched.
    let out = apply(&json!({"result": null}), rules, None, &[mask("ACME")]);
    assert_eq!(out.released, json!({"result": null}));
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    // A drop of the result itself is not `null`: nothing of it stays (or the drop is refused).
    let out = apply(
        &json!({"result": {"a": 1}}),
        rules,
        None,
        &[drop_field("result", DropScope::PerItem)],
    );
    if let Some(r) = out.released.get("result") {
        assert!(!looks_empty(r), "{r}");
    }
    Ok(())
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
    let pct = |c: char| {
        let mut b = [0u8; 4];
        c.encode_utf8(&mut b)
            .bytes()
            .map(|x| format!("%{x:02X}"))
            .collect::<String>()
    };
    match how % 11 {
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
        8 => bytes(&|b| format!("&#37;{b:02X}")),
        // Form encoding: spaces as `+`, everything but ASCII alphanumerics escaped.
        9 => s
            .chars()
            .map(|c| match c {
                ' ' => "+".to_owned(),
                c if c.is_ascii_alphanumeric() => c.to_string(),
                c => pct(c),
            })
            .collect(),
        // Mixed inside one needle: every other character percent-encoded, the rest as entities.
        _ => s
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    pct(c)
                } else {
                    format!("&#{};", c as u32)
                }
            })
            .collect(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Every supported encoding of a masked string is masked in place, and nothing that still
    /// matches is ever released unblocked.
    #[test]
    fn mask_every_occurrence_is_sound(
        needle in r"[a-zäöü][a-zäöü +%&\[\]]{1,6}[a-zäöü]",
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

/// The 64-byte unit from the T14 review that expands to about 112 forms per `views` call.
const BLOWUP: &str = "%E2%80%8B&&amp%253B%%32%35u\u{308}\u{200b}&uuml&amp;%41+&#43;&#x200B;&uuml";

#[test]
fn i1_crafted_expansion_is_bounded_and_blocks() -> TestResult {
    // One unit alone is fine.
    assert!(!views(BLOWUP).over_budget);
    let big = BLOWUP.repeat(4096);
    let started = std::time::Instant::now();
    let v = views(&big);
    assert!(v.over_budget && v.unstable);
    let held: usize = v.forms.iter().map(String::len).sum();
    assert!(
        held <= 32 * big.len(),
        "{held} bytes held for {} bytes",
        big.len()
    );
    let candidate = json!({"v": big, "w": "fine"});
    for op in [
        mask("zzz"),
        RedactionOp::MaskText {
            text: "zzz".into(),
            every_occurrence: false,
            at: None,
        },
    ] {
        let out = apply(&candidate, &NO_RULES, None, &[op]);
        assert!(has_block(
            &out,
            &BlockReason::UnstableEncoding { path: "v".into() }
        ));
        assert_eq!(out.released["v"], candidate["v"]);
    }
    // Generous: the budget bounds the work, this only catches a lost bound.
    assert!(started.elapsed() < std::time::Duration::from_secs(120));
    Ok(())
}

#[test]
fn i2_dropped_key_name_is_withheld() -> TestResult {
    let candidate = json!({"o": {"ACME-SECRET": 3, "other": 1}, "p": {"x ACME%2DSECRET": 1}});
    // A key hit alone blocks: keys are never rewritten.
    let out = apply(&candidate, &NO_RULES, None, &[mask("ACME-SECRET")]);
    assert!(has_block(
        &out,
        &BlockReason::MaskStillOccurs {
            path: "o.ACME-SECRET".into()
        }
    ));
    // The remedy is to drop it; its name then reaches the agent only as a placeholder.
    let out = apply(
        &candidate,
        &NO_RULES,
        None,
        &[
            drop_field("o.ACME-SECRET", DropScope::PerItem),
            drop_field("p.x ACME%2DSECRET", DropScope::PerItem),
            mask("ACME-SECRET"),
        ],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert_eq!(out.meta.fields_dropped, vec![REDACTED.to_owned(); 2]);
    assert!(!serde_json::to_string(&out.meta)?.contains("ACME"));
    assert_eq!(out.released["o"], json!({"other": 1}));
    // A single-occurrence mask counts a dropped name among the others that remain.
    let out = apply(
        &json!({"a": "ACME-SECRET", "o": {"ACME-SECRET": 3}}),
        &NO_RULES,
        None,
        &[
            drop_field("o.ACME-SECRET", DropScope::PerItem),
            RedactionOp::MaskText {
                text: "ACME-SECRET".into(),
                every_occurrence: false,
                at: None,
            },
        ],
    );
    assert_eq!(out.needs_confirmation, vec!["1 other occurrence remains"]);
    Ok(())
}

#[test]
fn i3_needle_across_a_placeholder() -> TestResult {
    let needle = "x [REDACTED] y";
    let candidate = json!({
        "a": "pre x [REDACTED] y post",
        "b": "x%20[REDACTED]%20y",
        "c": "x [REDACTED] y"
    });
    let out = apply(&candidate, &NO_RULES, None, &[mask(needle)]);
    assert_eq!(out.released["a"], "pre [REDACTED] post");
    assert_eq!(out.released["c"], "[REDACTED]");
    // Encoded across a placeholder: not maskable in place, so it blocks.
    assert!(has_block(
        &out,
        &BlockReason::MaskStillOccurs { path: "b".into() }
    ));
    assert_eq!(out.also_appears_in, vec!["a", "b", "c"]);

    // A partial overlap takes the whole placeholder with it: no `[REDACT` fragment is left as
    // text (review N-3), so a codename mask on the same value still converges.
    for ops in [vec![mask("ED] y")], vec![mask("RED"), mask("ED] y")]] {
        let out = apply(&json!({"v": "x [REDACTED] y"}), &NO_RULES, None, &ops);
        assert!(out.blocked.is_empty(), "{:?}", out.blocked);
        assert_eq!(out.released["v"], "x [REDACTED]");
    }
    let out = apply(
        &json!({"v": "[REDACTED]x and [REDACTED][REDACTED]x"}),
        &NO_RULES,
        None,
        &[mask("RED"), mask("]x")],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert_eq!(out.released["v"], "[REDACTED] and [REDACTED][REDACTED]");

    // Single occurrence: the first one, the other is counted.
    let out = apply(
        &json!({"a": "x [REDACTED] y", "b": "x [REDACTED] y"}),
        &NO_RULES,
        None,
        &[RedactionOp::MaskText {
            text: needle.into(),
            every_occurrence: false,
            at: None,
        }],
    );
    assert_eq!(out.released["a"], "[REDACTED]");
    assert_eq!(out.needs_confirmation, vec!["1 other occurrence remains"]);
    Ok(())
}

#[test]
fn ops_that_match_nothing_block() -> TestResult {
    let candidate = json!({"user.email": "a@b", "items": [{"id": "1"}]});
    // A key holding `.` cannot be addressed: the drop must not pass silently.
    let out = apply(
        &candidate,
        &NO_RULES,
        None,
        &[drop_field("user.email", DropScope::PerItem)],
    );
    assert!(has_block(
        &out,
        &BlockReason::OpTargetMissing {
            path: "user.email".into()
        }
    ));
    assert_eq!(out.released["user.email"], "a@b");
    let out = apply(
        &candidate,
        &NO_RULES,
        None,
        &[RedactionOp::DropItem {
            array_path: "items".into(),
            key: "id".into(),
            value: json!("9"),
        }],
    );
    assert!(has_block(
        &out,
        &BlockReason::OpTargetMissing {
            path: "items".into()
        }
    ));
    // Presets on a candidate of another shape.
    let out = apply(
        &json!({"class": "TypeError", "message": "m"}),
        &NO_RULES,
        None,
        &[RedactionOp::Preset(RedactionPreset::ErrorClassOnly)],
    );
    assert!(has_block(
        &out,
        &BlockReason::OpTargetMissing {
            path: "script_error.class".into()
        }
    ));
    let out = apply(
        &json!({"error_messages": ["x"]}),
        &NO_RULES,
        None,
        &[RedactionOp::Preset(RedactionPreset::StatusOnly)],
    );
    assert!(has_block(
        &out,
        &BlockReason::OpTargetMissing {
            path: "status".into()
        }
    ));
    // "Keep error class only" keeps nothing else at the root either.
    let out = apply(
        &json!({"script_error": {"class": "E", "message": "m"}, "logs": ["l"]}),
        &NO_RULES,
        None,
        &[RedactionOp::Preset(RedactionPreset::ErrorClassOnly)],
    );
    assert_eq!(out.released, json!({"script_error": {"class": "E"}}));
    assert_eq!(out.meta.fields_dropped, vec!["logs", "message"]);
    assert!(out.blocked.is_empty());
    // Removed by an earlier op of the same set: not a mismatch.
    let out = apply(
        &search_fixture(),
        rules("jira.search")?,
        Some("issues"),
        &[
            RedactionOp::DropItem {
                array_path: "issues".into(),
                key: "key".into(),
                value: json!("ABC-1"),
            },
            drop_field("issues[key=ABC-1].fields.customfield_1", DropScope::PerItem),
        ],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    Ok(())
}

/// A list whose `[3]` has no `x` while the `[4]` after it has one: once `[2]` is dropped, the
/// shown `[3]` is the source's `[4]`.
fn shifted_list() -> Value {
    json!({"list": [
        {"id": 0, "x": "a0"},
        {"id": 1},
        {"id": 2, "x": "a2"},
        {"id": 3},
        {"id": 4, "x": "a4"}
    ]})
}

fn drop_id(array_path: &str, id: Value) -> RedactionOp {
    RedactionOp::DropItem {
        array_path: array_path.into(),
        key: "id".into(),
        value: id,
    }
}

/// M8 T19c (L123, L217): a drop appended after earlier drops of the same revision is checked for
/// existence against the source **or** the document the earlier drops left, and acts on that
/// document (the index semantics of the shown candidate): the set gives what applying the ops one
/// by one to the shown candidate gives.
#[test]
fn drop_after_earlier_drops_checks_existence_against_current_doc() -> TestResult {
    let source = shifted_list();
    let tail = drop_field("list[3].x", DropScope::PerItem);
    for first in [
        drop_field("list[2]", DropScope::PerItem),
        drop_id("list", json!(2)),
    ] {
        let shown = apply(&source, &NO_RULES, None, std::slice::from_ref(&first));
        assert!(shown.blocked.is_empty(), "{:?}", shown.blocked);
        let one_by_one = apply(
            &shown.released,
            &NO_RULES,
            None,
            std::slice::from_ref(&tail),
        );
        assert!(one_by_one.blocked.is_empty(), "{:?}", one_by_one.blocked);
        let out = apply(&source, &NO_RULES, None, &[first.clone(), tail.clone()]);
        assert!(out.blocked.is_empty(), "{first:?}: {:?}", out.blocked);
        assert_eq!(out.released, one_by_one.released, "{first:?}");
        assert_eq!(
            out.released,
            json!({"list": [
                {"id": 0, "x": "a0"}, {"id": 1}, {"id": 3}, {"id": 4}
            ]})
        );
        assert_eq!(out.meta.items_dropped, 1);
        assert_eq!(out.meta.fields_dropped, vec!["x"]);
    }
    // An item drop whose array is named past a shifted index: the source's `groups[1].items` has
    // no `c`, the shown one (the source's `groups[2]`) has.
    let groups = json!({"groups": [
        {"g": 0, "items": [{"id": "a"}]},
        {"g": 1, "items": [{"id": "b"}]},
        {"g": 2, "items": [{"id": "c"}, {"id": "d"}]}
    ]});
    let ops = [
        drop_field("groups[0]", DropScope::PerItem),
        drop_id("groups[1].items", json!("c")),
    ];
    let shown = apply(&groups, &NO_RULES, None, &ops[..1]);
    let one_by_one = apply(&shown.released, &NO_RULES, None, &ops[1..]);
    let out = apply(&groups, &NO_RULES, None, &ops);
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert_eq!(out.released, one_by_one.released);
    assert_eq!(
        out.released,
        json!({"groups": [
            {"g": 1, "items": [{"id": "b"}]},
            {"g": 2, "items": [{"id": "d"}]}
        ]})
    );
    Ok(())
}

/// M8 T19c: fail closed. A drop that names nothing in the source **and** nothing in the document
/// the earlier drops left is refused (`OpTargetMissing`); one the earlier ops already removed (it
/// named something in the source) is not a mismatch.
#[test]
fn drop_absent_in_original_and_current_doc_is_refused() -> TestResult {
    let source = shifted_list();
    let first = drop_field("list[2]", DropScope::PerItem);
    for (op, at) in [
        // `[1]` has no `x` in either document.
        (drop_field("list[1].x", DropScope::PerItem), "list[1].x"),
        // Past the end of both.
        (drop_field("list[7]", DropScope::PerItem), "list[7]"),
        (drop_field("list[].y", DropScope::AllItems), "list[].y"),
        // No element with that key value in either.
        (drop_id("list", json!(9)), "list"),
        (drop_id("list[3].sub", json!(1)), "list[3].sub"),
    ] {
        let out = apply(&source, &NO_RULES, None, &[first.clone(), op.clone()]);
        assert!(
            has_block(&out, &BlockReason::OpTargetMissing { path: at.into() }),
            "{op:?}: {:?}",
            out.blocked
        );
    }
    // Control: a repeat of an earlier drop names something in the source; the earlier op
    // removed it, nothing more goes and nothing blocks.
    for repeat in [
        drop_id("list", json!(2)),
        drop_field("list[2].x", DropScope::PerItem),
    ] {
        let ops = [
            drop_id("list", json!(2)),
            drop_field("list[].x", DropScope::AllItems),
            repeat,
        ];
        let out = apply(&source, &NO_RULES, None, &ops);
        assert!(out.blocked.is_empty(), "{:?}", out.blocked);
        assert_eq!(
            out.released,
            json!({"list": [{"id": 0}, {"id": 1}, {"id": 3}, {"id": 4}]})
        );
    }
    Ok(())
}

// ---- §5.3 mirror pairing cannot be spoofed (M8 T19c review I-1) ----------------------------------

const RENDERED: &str = "renderedFields.comment.comments";

/// The comment mirror with `src` and `dst` entries.
fn mirrored(src: Value, dst: Value) -> Value {
    json!({
        "fields": {"comment": {"comments": src}},
        "renderedFields": {"comment": {"comments": dst}}
    })
}

/// Arrays of the same length; the rendered `[1]` (id 9, restricted) has no source counterpart,
/// the source's id 8 has no rendered one.
fn one_orphan() -> Value {
    mirrored(
        json!([{"id": "7", "body": "plain"}, {"id": "8", "body": "other"}]),
        json!([
            {"id": "7", "body": "<p>plain</p>"},
            {"id": "9", "body": "<p>orphan secret</p>", "visibility": {"type": "role", "value": "Administrators"}}
        ]),
    )
}

/// The rendered `[1]` (id 9) and `[3]` (id 11) have no source counterpart.
fn two_orphans() -> Value {
    mirrored(
        json!([{"id": "7", "body": "plain"}, {"id": "8", "body": "other"}]),
        json!([
            {"id": "7", "body": "<p>plain</p>"},
            {"id": "9", "body": "<p>orphan secret</p>"},
            {"id": "8", "body": "<p>other</p>"},
            {"id": "11", "body": "<p>second orphan</p>"}
        ]),
    )
}

fn rendered_orphan(i: usize) -> BlockReason {
    BlockReason::MirrorOrphan {
        path: format!("{RENDERED}[{i}]"),
    }
}

fn single_at(text: &str, at: &str) -> RedactionOp {
    RedactionOp::MaskText {
        text: text.into(),
        every_occurrence: false,
        at: Some(at.into()),
    }
}

/// Review T19c I-1 (a), the probe flow: in arrays of the same length a keyless rendered entry
/// pairs by position, so dropping only the orphan's mirror key made it look paired and the
/// restricted body was released. Every way of dropping that key alone (by index, by
/// `[key=value]`, across all items, after the source's keys went) blocks; the entry is still
/// there.
#[test]
fn a_dropped_mirror_key_does_not_pair_an_orphan() -> TestResult {
    let r = rules("jira.issue.get")?;
    let source = one_orphan();
    let out = apply(&source, r, None, &[]);
    assert_eq!(out.blocked, vec![rendered_orphan(1)]);
    for ops in [
        vec![drop_field(
            "renderedFields.comment.comments[1].id",
            DropScope::PerItem,
        )],
        vec![drop_field(
            "renderedFields.comment.comments[id=9].id",
            DropScope::PerItem,
        )],
        vec![drop_field(
            "renderedFields.comment.comments[].id",
            DropScope::AllItems,
        )],
        vec![
            drop_field("fields.comment.comments[].id", DropScope::AllItems),
            drop_field("renderedFields.comment.comments[1].id", DropScope::PerItem),
        ],
    ] {
        let out = apply(&source, r, None, &ops);
        assert!(
            has_block(&out, &rendered_orphan(1)),
            "{ops:?}: {:?}",
            out.blocked
        );
        assert!(
            out.blocked
                .iter()
                .all(|b| matches!(b, BlockReason::MirrorOrphan { .. })),
            "{ops:?}: {:?}",
            out.blocked
        );
    }
    Ok(())
}

/// Review T19c I-1 (b), the probe flow: masks that turn the orphan's id and a source-only id
/// into the same text (whole, as a partial pattern, every occurrence or single) made the orphan
/// "find" a counterpart, as the check ran after the masks. The pairing is decided after the drops
/// and before any mask, on the keys as the source shows them.
#[test]
fn masks_do_not_pair_an_orphan() -> TestResult {
    let r = rules("jira.issue.get")?;
    let partial = mirrored(
        json!([{"id": "7", "body": "plain"}, {"id": "18", "body": "other"}]),
        json!([
            {"id": "7", "body": "<p>plain</p>"},
            {"id": "19", "body": "<p>orphan secret</p>"}
        ]),
    );
    for (source, ops) in [
        (
            one_orphan(),
            vec![
                mask("9"),
                mask("8"),
                RedactionOp::UrlField {
                    mode: UrlMode::ReplaceWhole,
                },
            ],
        ),
        // Partial pattern: "1[REDACTED]" on both sides.
        (partial, vec![mask("9"), mask("8")]),
        // Single occurrences at the two ids.
        (
            one_orphan(),
            vec![
                single_at("9", "renderedFields.comment.comments[1].id"),
                single_at("8", "fields.comment.comments[1].id"),
            ],
        ),
    ] {
        let out = apply(&source, r, None, &ops);
        assert!(
            has_block(&out, &rendered_orphan(1)),
            "{ops:?}: {:?}",
            out.blocked
        );
    }
    Ok(())
}

/// The pairing a drop breaks is checked before the masks too, not only a source orphan's: a
/// duplicate rendered entry dropped takes its source counterpart with it (§5.3), which leaves the
/// other duplicate without one; masks of both ids must not hide that.
#[test]
fn a_pairing_a_drop_breaks_is_checked_before_the_masks() -> TestResult {
    let r = rules("jira.issue.get")?;
    let source = mirrored(
        json!([{"id": "1", "body": "a"}, {"id": "2", "body": "b"}]),
        json!([
            {"id": "1", "body": "<p>a</p>"},
            {"id": "1", "body": "<p>a again</p>"},
            {"id": "2", "body": "<p>b</p>"}
        ]),
    );
    assert!(apply(&source, r, None, &[]).blocked.is_empty());
    let dropped = drop_field("renderedFields.comment.comments[1]", DropScope::PerItem);
    let out = apply(&source, r, None, std::slice::from_ref(&dropped));
    assert_eq!(out.blocked, vec![rendered_orphan(0)]);
    let out = apply(&source, r, None, &[dropped, mask("1"), mask("2")]);
    assert!(has_block(&out, &rendered_orphan(0)), "{:?}", out.blocked);
    Ok(())
}

/// A bare drop of the mirror key of a rendered entry that has no source counterpart at that
/// point blocks, also where the drops made it one (not flagged in the source) and the arrays are
/// of the same length again afterwards.
#[test]
fn dropping_the_mirror_key_of_an_unpaired_entry_blocks() -> TestResult {
    let r = rules("jira.issue.get")?;
    let source = mirrored(
        json!([{"id": "1", "body": "a"}, {"id": "2", "body": "b"}, {"id": "3", "body": "c"}]),
        json!([
            {"id": "1", "body": "<p>a</p>"},
            {"id": "1", "body": "<p>a again</p>"},
            {"id": "2", "body": "<p>b</p>"}
        ]),
    );
    assert!(apply(&source, r, None, &[]).blocked.is_empty());
    let ops = [
        drop_field("renderedFields.comment.comments[1]", DropScope::PerItem),
        drop_field("renderedFields.comment.comments[0].id", DropScope::PerItem),
    ];
    let out = apply(&source, r, None, &ops);
    assert!(has_block(&out, &rendered_orphan(0)), "{:?}", out.blocked);
    Ok(())
}

/// The ruling's "unless the whole flagged entry is dropped": an entry the source's check flags
/// blocks for as long as it is in the result, whatever the drops did around it. Here keyless
/// rendered entries in arrays of different lengths, made the same length by dropping a keyed
/// source entry that has no rendered counterpart.
#[test]
fn a_flagged_entry_blocks_until_it_is_dropped_whole() -> TestResult {
    let r = rules("jira.issue.get")?;
    let source = mirrored(
        json!([{"id": "1", "body": "a"}, {"body": "b"}, {"body": "c"}]),
        json!([{"body": "<p>b</p>"}, {"body": "<p>restricted</p>"}]),
    );
    let unmatchable = |i: usize| BlockReason::MirrorUnmatchable {
        path: format!("{RENDERED}[{i}]"),
    };
    assert_eq!(
        apply(&source, r, None, &[]).blocked,
        vec![unmatchable(0), unmatchable(1)]
    );
    for ops in [
        vec![drop_id("fields.comment.comments", json!("1"))],
        vec![drop_field("fields.comment.comments[0]", DropScope::PerItem)],
    ] {
        let out = apply(&source, r, None, &ops);
        assert_eq!(out.blocked, vec![unmatchable(0), unmatchable(1)], "{ops:?}");
    }
    // The way out: the whole mirrored array (its source array goes with it).
    let out = apply(
        &source,
        r,
        None,
        &[drop_field(RENDERED, DropScope::PerItem)],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert!(
        out.released["renderedFields"]["comment"]
            .get("comments")
            .is_none()
    );
    Ok(())
}

/// Controls: dropping the flagged entries makes the candidate releasable, by identity or by index
/// on the document the earlier drops left (also after a drop shifted them), with masks of other
/// fields, a mask that hits paired ids, and the key drop of a paired entry. A round appended to
/// ops that dropped one orphan still has to drop the other whole.
#[test]
fn dropping_the_flagged_entries_passes_and_nothing_else_does() -> TestResult {
    let r = rules("jira.issue.get")?;
    let source = two_orphans();
    let at = |i: usize| drop_field(&format!("{RENDERED}[{i}]"), DropScope::PerItem);
    let rest = json!([
        {"id": "7", "body": "<p>plain</p>"},
        {"id": "8", "body": "<p>other</p>"}
    ]);
    for ops in [
        vec![
            drop_id(RENDERED, json!("9")),
            drop_id(RENDERED, json!("11")),
        ],
        vec![at(3), at(1)],
        vec![drop_id(RENDERED, json!("11")), at(1)],
        vec![
            drop_field("renderedFields.comment.comments[id=9]", DropScope::PerItem),
            at(2),
        ],
    ] {
        let out = apply(&source, r, None, &ops);
        assert!(out.blocked.is_empty(), "{ops:?}: {:?}", out.blocked);
        assert_eq!(out.released["renderedFields"]["comment"]["comments"], rest);
    }
    // A paired entry dropped first shifts both orphans; the index drops name them where they are.
    let out = apply(
        &source,
        r,
        None,
        &[drop_id(RENDERED, json!("7")), at(2), at(0)],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert_eq!(
        out.released["renderedFields"]["comment"]["comments"],
        json!([{"id": "8", "body": "<p>other</p>"}])
    );
    // ...and a stale index drops another entry: the orphans stay and block where they now are.
    let out = apply(&source, r, None, &[drop_id(RENDERED, json!("7")), at(1)]);
    assert_eq!(out.blocked, vec![rendered_orphan(0), rendered_orphan(1)]);
    // Masks and key drops on the rest, after the flagged entries are gone.
    let drops = [at(3), at(1)];
    for extra in [
        vec![mask("plain")],
        vec![mask("7")],
        vec![drop_field(
            "renderedFields.comment.comments[0].id",
            DropScope::PerItem,
        )],
        vec![drop_field(
            "fields.comment.comments[].id",
            DropScope::AllItems,
        )],
    ] {
        let ops: Vec<RedactionOp> = drops.iter().cloned().chain(extra.clone()).collect();
        let out = apply(&source, r, None, &ops);
        assert!(out.blocked.is_empty(), "{extra:?}: {:?}", out.blocked);
    }
    // Rounds: one orphan dropped earlier, the other's key (or a mask of it) now.
    for round in [
        vec![drop_field(
            "renderedFields.comment.comments[1].id",
            DropScope::PerItem,
        )],
        vec![mask("9"), mask("8")],
    ] {
        let ops: Vec<RedactionOp> = std::iter::once(at(3)).chain(round.clone()).collect();
        let out = apply(&source, r, None, &ops);
        assert!(
            has_block(&out, &rendered_orphan(1)),
            "{round:?}: {:?}",
            out.blocked
        );
    }
    Ok(())
}

// ---- identity ops after a drop of the identity key (M8 T19c review I-1') -------------------------

const SOURCE: &str = "fields.comment.comments";

/// Two paired comments; 7's body is what the approver drops.
fn two_comments() -> Value {
    mirrored(
        json!([{"id": "7", "body": "plain secret"}, {"id": "8", "body": "other"}]),
        json!([
            {"id": "7", "body": "<p>plain secret</p>"},
            {"id": "8", "body": "<p>other</p>"}
        ]),
    )
}

/// Whether any string value or key of the released candidate contains `text`.
fn released_text(out: &RedactionOutcome, text: &str) -> bool {
    strings(&out.released).iter().any(|s| s.contains(text))
}

/// Review T19c I-1', the probe flows: an identity drop (`DropItem id=7`, `drop_field [id=7]`)
/// after a drop of the same element's identity key (the rendered or the source key, by identity
/// or by index; the §5.3 mirror takes the other side's key with it) was a silent no-op: "absent
/// now, present in the source" read as "removed already", and comment 7 was released raw and
/// rendered with `blocked []`. Identity is the source's: the element is still there and goes,
/// with its mirrored entry.
#[test]
fn an_identity_drop_after_its_key_drop_removes_the_element() -> TestResult {
    let r = rules("jira.issue.get")?;
    let source = two_comments();
    let rest = mirrored(
        json!([{"id": "8", "body": "other"}]),
        json!([{"id": "8", "body": "<p>other</p>"}]),
    );
    for key in [
        format!("{RENDERED}[id=7].id"),
        format!("{SOURCE}[id=7].id"),
        format!("{RENDERED}[0].id"),
        format!("{SOURCE}[0].id"),
    ] {
        for element in [
            drop_id(RENDERED, json!("7")),
            drop_id(SOURCE, json!("7")),
            drop_field(&format!("{RENDERED}[id=7]"), DropScope::PerItem),
            drop_field(&format!("{SOURCE}[id=7]"), DropScope::PerItem),
        ] {
            let ops = [drop_field(&key, DropScope::PerItem), element];
            let out = apply(&source, r, None, &ops);
            assert!(out.blocked.is_empty(), "{ops:?}: {:?}", out.blocked);
            assert_eq!(out.released, rest, "{ops:?}");
        }
    }
    // A field of the element named by identity after the key drop: both bodies go.
    let ops = [
        drop_field(&format!("{RENDERED}[id=7].id"), DropScope::PerItem),
        drop_field(&format!("{RENDERED}[id=7].body"), DropScope::PerItem),
    ];
    let out = apply(&source, r, None, &ops);
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert!(!released_text(&out, "plain secret"), "{}", out.released);
    Ok(())
}

/// The element is found where the earlier drops left it, and its mirrored entry by the source's
/// key, not by position: the rendered order is the reverse of the source's, or an earlier drop
/// shifted both arrays.
#[test]
fn an_identity_drop_after_its_key_drop_pairs_by_the_source_key_across_shifts() -> TestResult {
    let r = rules("jira.issue.get")?;
    let reversed = mirrored(
        json!([
            {"id": "7", "body": "plain secret"},
            {"id": "8", "body": "other"},
            {"id": "9", "body": "third"}
        ]),
        json!([
            {"id": "9", "body": "<p>third</p>"},
            {"id": "8", "body": "<p>other</p>"},
            {"id": "7", "body": "<p>plain secret</p>"}
        ]),
    );
    let ops = [
        drop_field(&format!("{RENDERED}[id=7].id"), DropScope::PerItem),
        drop_id(RENDERED, json!("7")),
    ];
    let out = apply(&reversed, r, None, &ops);
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert_eq!(
        out.released,
        mirrored(
            json!([{"id": "8", "body": "other"}, {"id": "9", "body": "third"}]),
            json!([{"id": "9", "body": "<p>third</p>"}, {"id": "8", "body": "<p>other</p>"}]),
        )
    );
    let shifted = mirrored(
        json!([
            {"id": "6", "body": "first"},
            {"id": "7", "body": "plain secret"},
            {"id": "8", "body": "other"}
        ]),
        json!([
            {"id": "6", "body": "<p>first</p>"},
            {"id": "7", "body": "<p>plain secret</p>"},
            {"id": "8", "body": "<p>other</p>"}
        ]),
    );
    for ops in [
        vec![
            drop_field(&format!("{RENDERED}[0]"), DropScope::PerItem),
            drop_field(&format!("{RENDERED}[0].id"), DropScope::PerItem),
            drop_id(RENDERED, json!("7")),
        ],
        vec![
            drop_id(SOURCE, json!("6")),
            drop_field(&format!("{SOURCE}[id=7].id"), DropScope::PerItem),
            drop_field(&format!("{RENDERED}[id=7]"), DropScope::PerItem),
        ],
    ] {
        let out = apply(&shifted, r, None, &ops);
        assert!(out.blocked.is_empty(), "{ops:?}: {:?}", out.blocked);
        assert_eq!(
            out.released,
            mirrored(
                json!([{"id": "8", "body": "other"}]),
                json!([{"id": "8", "body": "<p>other</p>"}]),
            ),
            "{ops:?}"
        );
    }
    Ok(())
}

/// The same at item level (`jira.search`): the issue's `key` dropped, then the issue, one of its
/// fields (with the rendered copy) or one of its comments named by that key.
#[test]
fn search_identity_drops_after_the_key_drop() -> TestResult {
    let r = rules("jira.search")?;
    let key_drop = drop_field("issues[key=ABC-1].key", DropScope::PerItem);
    let out = apply(
        &search_fixture(),
        r,
        Some("issues"),
        &[
            key_drop.clone(),
            RedactionOp::DropItem {
                array_path: "issues".into(),
                key: "key".into(),
                value: json!("ABC-1"),
            },
        ],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert_eq!(out.released["issues"].as_array().map(Vec::len), Some(1));
    assert_eq!(out.released["issues"][0]["key"], "ABC-2");
    assert_eq!(out.meta.items_dropped, 1);

    let out = apply(
        &search_fixture(),
        r,
        Some("issues"),
        &[
            key_drop.clone(),
            drop_field("issues[key=ABC-1].fields.customfield_1", DropScope::PerItem),
        ],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert!(!released_text(&out, "ABC-1 secret"), "{}", out.released);
    assert_eq!(
        out.released["issues"][1]["renderedFields"]["customfield_1"],
        "<p>ABC-2 secret</p>"
    );

    let comments = "issues[key=ABC-1].renderedFields.comment.comments";
    let out = apply(
        &search_fixture(),
        r,
        Some("issues"),
        &[
            key_drop,
            drop_field(&format!("{comments}[id=11].id"), DropScope::PerItem),
            drop_id(comments, json!("11")),
        ],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    let first = &out.released["issues"][0];
    assert_eq!(first["fields"]["comment"]["comments"], json!([]));
    assert_eq!(first["renderedFields"]["comment"]["comments"], json!([]));
    Ok(())
}

/// A registry copy is found by identity too: a changelog item whose `fieldId` was dropped is
/// still the field's history and goes with the field.
#[test]
fn a_changelog_copy_goes_after_its_key_field_drop() -> TestResult {
    let out = apply(
        &issue_fixture(),
        rules("jira.issue.get")?,
        None,
        &[
            drop_field(
                "changelog.histories[0].items[0].fieldId",
                DropScope::PerItem,
            ),
            drop_field("fields.customfield_1", DropScope::AllItems),
        ],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert!(!released_text(&out, "secret value"), "{}", out.released);
    assert_eq!(
        out.released["changelog"]["histories"],
        json!([{"id": "101", "items": [
            {"field": "summary", "fieldtype": "jira", "fieldId": "summary",
             "fromString": "draft", "toString": "Quarterly plan"}
        ]}])
    );
    Ok(())
}

/// Fail closed (review T19c I-1'): an identity op that matches nothing where the earlier drops left
/// the document is a no-op only when tracking shows that every element it names in the source
/// went whole. One still there (here named past a shifted index) is refused, not skipped.
#[test]
fn an_identity_op_is_a_no_op_only_when_its_elements_went() -> TestResult {
    let groups = json!({"groups": [
        {"g": 0, "items": [{"id": "a"}]},
        {"g": 1, "items": [{"id": "b"}]},
        {"g": 2, "items": [{"id": "c"}, {"id": "d"}]}
    ]});
    // The shown `groups[1]` is the source's `groups[2]`; the source's `b` is still there.
    for (op, at) in [
        (drop_id("groups[1].items", json!("b")), "groups[1].items"),
        (
            drop_field("groups[1].items[id=b]", DropScope::PerItem),
            "groups[1].items[id=b]",
        ),
        (
            drop_field("groups[1].items[id=b].id", DropScope::PerItem),
            "groups[1].items[id=b].id",
        ),
    ] {
        let ops = [drop_field("groups[0]", DropScope::PerItem), op];
        let out = apply(&groups, &NO_RULES, None, &ops);
        assert!(
            has_block(&out, &BlockReason::OpTargetMissing { path: at.into() }),
            "{ops:?}: {:?}",
            out.blocked
        );
    }
    // Controls: the element went whole earlier (by identity, by index, with a parent).
    let r = rules("jira.issue.get")?;
    for first in [
        drop_id(RENDERED, json!("7")),
        drop_field(&format!("{RENDERED}[0]"), DropScope::PerItem),
        drop_field(&format!("{SOURCE}[id=7]"), DropScope::PerItem),
        drop_field("renderedFields.comment", DropScope::PerItem),
        drop_field("renderedFields", DropScope::PerItem),
    ] {
        for again in [
            drop_id(RENDERED, json!("7")),
            drop_field(&format!("{RENDERED}[id=7]"), DropScope::PerItem),
            drop_field(&format!("{RENDERED}[id=7].body"), DropScope::PerItem),
        ] {
            let ops = [first.clone(), again];
            let out = apply(&two_comments(), r, None, &ops);
            assert!(out.blocked.is_empty(), "{ops:?}: {:?}", out.blocked);
        }
    }
    Ok(())
}

/// Review T19c fix m-1: a single-occurrence mask of a paired entry's mirror key masks the mirrored
/// entry's key too (§5.3: a per-item mask also applies to the mirrored entry). The counterpart was
/// looked up after the key was rewritten, found none, and the other side's id stayed with "1 other
/// occurrence remains".
#[test]
fn a_single_mask_of_a_mirror_key_masks_the_mirrored_key() -> TestResult {
    let r = rules("jira.issue.get")?;
    for at in [format!("{SOURCE}[1].id"), format!("{RENDERED}[1].id")] {
        let ops = [
            drop_id(RENDERED, json!("9")),
            drop_id(RENDERED, json!("11")),
            single_at("8", &at),
        ];
        let out = apply(&two_orphans(), r, None, &ops);
        assert!(out.blocked.is_empty(), "{at}: {:?}", out.blocked);
        assert!(
            out.needs_confirmation.is_empty(),
            "{at}: {:?}",
            out.needs_confirmation
        );
        assert_eq!(
            out.released["fields"]["comment"]["comments"][1]["id"], REDACTED,
            "{at}"
        );
        assert_eq!(
            out.released["renderedFields"]["comment"]["comments"][1]["id"], REDACTED,
            "{at}"
        );
    }
    // The orphan's key is still not paired by a single mask (it has no counterpart to mask).
    let out = apply(
        &one_orphan(),
        r,
        None,
        &[single_at("9", &format!("{RENDERED}[1].id"))],
    );
    assert!(has_block(&out, &rendered_orphan(1)), "{:?}", out.blocked);
    Ok(())
}

/// Review T19c fix m-6: the flagged-entry tracking follows an item-level shift (`jira.search`):
/// an orphan in the second issue is reported where it is after the first issue's drop.
#[test]
fn a_flagged_entry_follows_an_item_level_shift() -> TestResult {
    let r = rules("jira.search")?;
    let mut source = search_fixture();
    if let Some(a) = source["issues"][1]["renderedFields"]["comment"]["comments"].as_array_mut() {
        a.push(json!({"id": "99", "body": "<p>orphan secret</p>"}));
    }
    let orphan = |i: usize| BlockReason::MirrorOrphan {
        path: format!("issues[{i}].renderedFields.comment.comments[1]"),
    };
    assert_eq!(
        apply(&source, r, Some("issues"), &[]).blocked,
        vec![orphan(1)]
    );
    for first in [
        drop_field("issues[0]", DropScope::PerItem),
        RedactionOp::DropItem {
            array_path: "issues".into(),
            key: "key".into(),
            value: json!("ABC-1"),
        },
    ] {
        let out = apply(&source, r, Some("issues"), std::slice::from_ref(&first));
        assert_eq!(out.blocked, vec![orphan(0)], "{first:?}");
    }
    // The orphan named where it now is: nothing blocks, and it is gone.
    let out = apply(
        &source,
        r,
        Some("issues"),
        &[
            drop_field("issues[0]", DropScope::PerItem),
            drop_field(
                "issues[0].renderedFields.comment.comments[1]",
                DropScope::PerItem,
            ),
        ],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert!(!released_text(&out, "orphan secret"), "{}", out.released);
    Ok(())
}

#[test]
fn whatwg_reference_details() -> TestResult {
    // windows-1252 remap of numeric references 0x80-0x9F.
    assert!(canonical_hit("O&#146;Brien", "O\u{2019}Brien"));
    assert!(canonical_hit("&#x80;100", "\u{20AC}100"));
    // Entities that expand to two code points (html-escape keeps only the first).
    assert!(canonical_hit("a&nvlt;b", "a<\u{20D2}b"));
    assert!(canonical_hit("x&ThickSpace;y", "x\u{205F}\u{200A}y"));
    let out = apply(
        &json!({"v": "Mr O&#146;Brien said"}),
        &NO_RULES,
        None,
        &[mask("O\u{2019}Brien")],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert_eq!(out.released["v"], "Mr [REDACTED] said");
    Ok(())
}

#[test]
fn plus_encoded_needle_in_a_plain_field() -> TestResult {
    let out = apply(
        &json!({"q": "search?q=Falcon+M%C3%BCller+Plan&x=1"}),
        &NO_RULES,
        None,
        &[mask("Falcon Müller Plan")],
    );
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    assert_eq!(out.released["q"], "search?q=[REDACTED]&x=1");
    Ok(())
}

#[test]
fn registry_rule_paths_parse() -> TestResult {
    for op in atlas_duck_registry::all() {
        let bad = invalid_rule_paths(&op.redaction_rules);
        assert!(bad.is_empty(), "{}: {bad:?}", op.id);
    }
    Ok(())
}

fn keyed<T>(keys: &[String], f: impl Fn(&str) -> T) -> Map<String, Value>
where
    T: Into<Value>,
{
    keys.iter().map(|k| (k.clone(), f(k).into())).collect()
}

/// An issue-shaped candidate with every copy and the comment mirror, consistent by construction.
fn arb_issue() -> impl Strategy<Value = (Value, Vec<String>, Vec<String>)> {
    let field_value = prop_oneof![
        Just(Value::Null),
        Just(json!("")),
        "[a-z]{1,5}".prop_map(Value::from)
    ];
    (
        prop::collection::btree_map("customfield_[1-5]", field_value, 1..5),
        prop::collection::btree_set("[1-6]", 0..4),
        any::<bool>(),
    )
        .prop_map(|(fields, comment_ids, changelog)| {
            let names: Vec<String> = fields.keys().cloned().collect();
            let ids: Vec<String> = comment_ids.into_iter().collect();
            let comments = |body: &str| -> Value {
                let list: Vec<Value> = ids
                    .iter()
                    .map(|id| json!({"id": id, "body": body}))
                    .collect();
                json!({ "comments": list })
            };
            let mut f: Map<String, Value> = fields.clone().into_iter().collect();
            f.insert("comment".into(), comments("c"));
            let mut rf: Map<String, Value> = fields
                .iter()
                .map(|(k, v)| {
                    let r = match v {
                        Value::String(s) => json!(format!("<p>{s}</p>")),
                        other => other.clone(),
                    };
                    (k.clone(), r)
                })
                .collect();
            rf.insert("comment".into(), comments("<p>c</p>"));
            let mut histories: Vec<Value> = Vec::new();
            if changelog {
                for (i, k) in names.iter().enumerate() {
                    histories.push(
                        json!({"id": i.to_string(), "items": [{"fieldId": k, "toString": "x"}]}),
                    );
                }
                let both: Vec<Value> = names
                    .iter()
                    .take(2)
                    .map(|k| json!({"field": k, "toString": "y"}))
                    .collect();
                histories.push(json!({"id": "both", "items": both}));
            }
            let doc = json!({
                "key": "ABC-1",
                "fields": f,
                "renderedFields": rf,
                "names": keyed(&names, |k| format!("Name {k}")),
                "schema": keyed(&names, |_| json!({"type": "string"})),
                "editmeta": {"fields": keyed(&names, |_| json!({"required": false}))},
                "changelog": {"histories": histories}
            });
            (doc, names, ids)
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// U-29 with the `jira.issue.get` rules: copies, changelog items and the comment mirror go
    /// with every drop, nothing left behind looks empty, untouched fields (and their `null`s)
    /// stay as they were.
    #[test]
    fn u29_drops_with_issue_rules(
        (doc, fields, comments) in arb_issue(),
        picks in prop::collection::vec((any::<prop::sample::Index>(), any::<bool>()), 1..3),
        comment_picks in prop::collection::vec(any::<prop::sample::Index>(), 0..3),
    ) {
        let r = rules("jira.issue.get").map_err(TestCaseError::fail)?;
        let mut ops = Vec::new();
        let mut dropped: Vec<String> = Vec::new();
        for (ix, all) in &picks {
            let f = ix.get(&fields).clone();
            let scope = if *all { DropScope::AllItems } else { DropScope::PerItem };
            ops.push(drop_field(&format!("fields.{f}"), scope));
            dropped.push(f);
        }
        let mut gone_comments: Vec<String> = Vec::new();
        if !comments.is_empty() {
            for ix in &comment_picks {
                let id = ix.get(&comments).clone();
                ops.push(RedactionOp::DropItem {
                    array_path: "fields.comment.comments".into(),
                    key: "id".into(),
                    value: json!(id),
                });
                gone_comments.push(id);
            }
        }
        let out = apply(&doc, r, None, &ops);
        prop_assert!(out.blocked.is_empty(), "{:?}", out.blocked);
        let rel = &out.released;
        for f in &dropped {
            for copy in ["fields", "renderedFields", "names", "schema"] {
                prop_assert!(rel[copy].get(f).is_none(), "{}.{} left", copy, f);
            }
            prop_assert!(rel["editmeta"]["fields"].get(f).is_none());
        }
        for h in rel["changelog"]["histories"].as_array().into_iter().flatten() {
            let items = h["items"].as_array().ok_or_else(|| TestCaseError::fail("items"))?;
            prop_assert!(!items.is_empty(), "emptied history {}", h);
            for it in items {
                for k in ["field", "fieldId"] {
                    if let Some(v) = it.get(k).and_then(Value::as_str) {
                        prop_assert!(!dropped.iter().any(|d| d == v), "changelog item for {}", v);
                    }
                }
            }
        }
        for side in ["fields", "renderedFields"] {
            for c in rel[side]["comment"]["comments"].as_array().into_iter().flatten() {
                let id = c["id"].as_str().unwrap_or_default();
                prop_assert!(!gone_comments.iter().any(|g| g == id), "{} comment {} left", side, id);
            }
        }
        for f in fields.iter().filter(|f| !dropped.contains(f)) {
            prop_assert_eq!(&rel["fields"][f], &doc["fields"][f]);
            prop_assert_eq!(&rel["renderedFields"][f], &doc["renderedFields"][f]);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Masks mixed with drops on issue-shaped candidates: dropped fields and their copies are
    /// gone whatever the masks do; a release that is not blocked has no hit of a masked string
    /// anywhere (values, keys, dropped names); nulls of untouched fields stay.
    #[test]
    fn u29_masks_mixed_with_drops(
        (doc, fields, _comments) in arb_issue(),
        drops in prop::collection::vec((any::<prop::sample::Index>(), any::<bool>()), 0..3),
        masks in prop::collection::vec((any::<prop::sample::Index>(), any::<bool>()), 1..3),
    ) {
        let r = rules("jira.issue.get").map_err(TestCaseError::fail)?;
        let mut ops = Vec::new();
        let mut dropped: Vec<String> = Vec::new();
        for (ix, all) in &drops {
            let f = ix.get(&fields).clone();
            let scope = if *all { DropScope::AllItems } else { DropScope::PerItem };
            ops.push(drop_field(&format!("fields.{f}"), scope));
            dropped.push(f);
        }
        let mut needles: Vec<String> = Vec::new();
        for (ix, every) in &masks {
            let f = ix.get(&fields);
            let Some(text) = doc["fields"][f].as_str().filter(|s| !s.is_empty()) else {
                continue;
            };
            needles.push(text.to_owned());
            ops.push(RedactionOp::MaskText {
                text: text.to_owned(),
                every_occurrence: *every,
                at: None,
            });
            if !*every {
                needles.pop();
            }
        }
        let out = apply(&doc, r, None, &ops);
        let rel = &out.released;
        for f in &dropped {
            for copy in ["fields", "renderedFields", "names", "schema"] {
                prop_assert!(rel[copy].get(f).is_none(), "{}.{} left", copy, f);
            }
        }
        if out.blocked.is_empty() {
            for s in strings(rel).iter().chain(&out.meta.fields_dropped) {
                for n in &needles {
                    prop_assert!(!canonical_hit(s, n), "{:?} still holds {:?}", s, n);
                }
            }
        }
        for f in fields.iter().filter(|f| !dropped.contains(f)) {
            if doc["fields"][f].is_null() {
                prop_assert_eq!(&rel["fields"][f], &Value::Null);
            }
        }
    }
}
