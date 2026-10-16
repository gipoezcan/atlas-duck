use atlas_duck_preview::diff::{DiffLine, DiffOp};
use atlas_duck_preview::{
    BodyView, CommentView, ConstructList, FieldRow, IssueCard, ItemCount, PreviewBody, RequestView,
};
use serde_json::{Value, json};

fn req() -> RequestView {
    RequestView {
        index: 0,
        method: "POST".to_owned(),
        resolved_url: "https://j.example/rest/api/2/issue".to_owned(),
        content_type: Some("application/json".to_owned()),
        body: BodyView::Text("{}".to_owned()),
    }
}

fn bodies() -> Vec<PreviewBody> {
    vec![
        PreviewBody::JiraIssue {
            card: IssueCard {
                key: "ABC-1".to_owned(),
                summary: "s".to_owned(),
                issue_type: "Bug".to_owned(),
                status: "Open".to_owned(),
                priority: Some("High".to_owned()),
                assignee: None,
                reporter: Some("jdoe".to_owned()),
            },
            fields: vec![FieldRow {
                id: "customfield_1".to_owned(),
                name: "customfield_1 (unknown field)".to_owned(),
                value_text: "x".to_owned(),
                restricted: false,
            }],
            description_html: Some("<p>d</p>".to_owned()),
            comments: vec![CommentView {
                id: "10".to_owned(),
                author: Some("a".to_owned()),
                created: None,
                body_html: "<p>c</p>".to_owned(),
                restricted: true,
            }],
        },
        PreviewBody::Table {
            columns: vec!["Key".to_owned()],
            rows: vec![vec!["ABC-1".to_owned()]],
            count: Some(ItemCount {
                shown: 1,
                total: Some(1),
                more_available: false,
            }),
        },
        PreviewBody::WriteSummary {
            sentence: "comment on ABC-1".to_owned(),
            rows: vec![("Visibility".to_owned(), "none".to_owned())],
            constructs: Some(ConstructList {
                macros: vec!["toc".to_owned()],
                mentions: vec!["jdoe".to_owned()],
                ..ConstructList::default()
            }),
            requests: vec![req()],
        },
        PreviewBody::EditDiff {
            rendered: vec![DiffLine {
                op: DiffOp::Add,
                text: "x".to_owned(),
            }],
            raw: vec![DiffLine {
                op: DiffOp::Same,
                text: "y".to_owned(),
            }],
            raw_only_changes: 1,
            constructs: None,
            requests: vec![req()],
        },
        PreviewBody::Transition {
            transition: "Done (31)".to_owned(),
            from: "Open".to_owned(),
            to: "Done".to_owned(),
            fields: vec![("resolution".to_owned(), "Fixed".to_owned())],
            constructs: Some(ConstructList {
                links: vec!["https://x".to_owned()],
                ..ConstructList::default()
            }),
            requests: vec![req()],
        },
    ]
}

#[test]
fn jira_bodies_serialize_with_kind_tags() -> Result<(), serde_json::Error> {
    let tags = [
        "jira_issue",
        "table",
        "write_summary",
        "edit_diff",
        "transition",
    ];
    let all = bodies();
    // a variant added to `bodies()` without a tag (or the reverse) fails here, not silently
    assert_eq!(all.len(), tags.len());
    for (b, tag) in all.iter().zip(tags) {
        assert_eq!(serde_json::to_value(b)?["kind"], tag);
    }
    let v = serde_json::to_value(&all[0])?;
    assert_eq!(v["card"]["key"], "ABC-1");
    assert_eq!(v["card"]["assignee"], Value::Null);
    assert_eq!(v["fields"][0]["name"], "customfield_1 (unknown field)");
    assert_eq!(v["comments"][0]["restricted"], true);
    assert_eq!(v["description_html"], "<p>d</p>");
    let v = serde_json::to_value(&all[2])?;
    assert_eq!(
        v["constructs"],
        json!({"macros": ["toc"], "mentions": ["jdoe"], "includes": [], "links": [],
               "images": [], "attachments": []})
    );
    assert_eq!(v["rows"], json!([["Visibility", "none"]]));
    let v = serde_json::to_value(&all[3])?;
    assert_eq!(v["rendered"], json!([{"op": "add", "text": "x"}]));
    assert_eq!(v["raw"], json!([{"op": "same", "text": "y"}]));
    assert_eq!(v["raw_only_changes"], 1);
    let v = serde_json::to_value(&all[4])?;
    assert_eq!(v["transition"], "Done (31)");
    assert_eq!(
        v["constructs"],
        json!({"macros": [], "mentions": [], "includes": [], "links": ["https://x"],
               "images": [], "attachments": []})
    );
    assert_eq!(v["fields"], json!([["resolution", "Fixed"]]));
    Ok(())
}

#[test]
fn write_bodies_always_carry_requests() -> Result<(), serde_json::Error> {
    // The three Jira write variants (§5.1 inv. 4) each hold `requests`; the field accesses below
    // stop compiling if one loses it.
    for b in bodies() {
        let count = match &b {
            PreviewBody::WriteSummary { requests, .. }
            | PreviewBody::EditDiff { requests, .. }
            | PreviewBody::Transition { requests, .. } => Some(requests.len()),
            _ => None,
        };
        let v = serde_json::to_value(&b)?;
        match count {
            Some(n) => {
                assert_eq!(n, 1);
                assert_eq!(v["requests"].as_array().map(Vec::len), Some(1));
                assert_eq!(v["requests"][0]["method"], "POST");
            }
            None => assert!(v.get("requests").is_none()),
        }
    }
    Ok(())
}
