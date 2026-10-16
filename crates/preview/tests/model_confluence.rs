//! M7 Task 8 (Δ2): the Confluence preview bodies on the wire.

type TestResult = Result<(), Box<dyn std::error::Error>>;

use atlas_duck_preview::diff::{DiffLine, DiffOp};
use atlas_duck_preview::{
    BodyView, ConfluenceComment, ConstructList, ConversionFacts, ItemCount, PreviewBody,
    RequestView,
};
use serde_json::{Value, json};

fn req() -> RequestView {
    RequestView {
        index: 0,
        method: "POST".to_owned(),
        resolved_url: "https://c.example/wiki/rest/api/content".to_owned(),
        content_type: Some("application/json".to_owned()),
        body: BodyView::Text("{}".to_owned()),
    }
}

fn digest_req() -> RequestView {
    RequestView {
        index: 0,
        method: "POST".to_owned(),
        resolved_url: "https://c.example/wiki/rest/api/content/1/child/attachment".to_owned(),
        content_type: Some("multipart/form-data; boundary=b".to_owned()),
        body: BodyView::Digest {
            bytes: 2_000_000,
            sha256: "ab".repeat(32),
        },
    }
}

fn bodies() -> Vec<PreviewBody> {
    vec![
        PreviewBody::ConfluencePage {
            title: "Plan".to_owned(),
            space: "Development (DEV)".to_owned(),
            version: Some(7),
            ancestors: vec!["Home".to_owned(), "Projects".to_owned()],
            format: "markdown".to_owned(),
            body_html: "<p>b</p>".to_owned(),
            conversion: Some(ConversionFacts {
                lossy: true,
                macros: 1,
                images: 0,
                links: 2,
                layouts: 0,
                unresolved_users: 1,
                fallback: false,
            }),
        },
        PreviewBody::ConfluenceComments {
            comments: vec![ConfluenceComment {
                id: "11".to_owned(),
                author: Some("jdoe".to_owned()),
                created: None,
                location: Some("inline".to_owned()),
                depth: 1,
                parent_id: Some("10".to_owned()),
                body_html: "<p>c</p>".to_owned(),
            }],
            count: Some(ItemCount {
                shown: 1,
                total: Some(1),
                more_available: false,
            }),
        },
        PreviewBody::ContentWrite {
            sentence: "Create page 'Plan' in Development (DEV)".to_owned(),
            rows: vec![("space".to_owned(), "DEV".to_owned())],
            body_html: Some("<p>b</p>".to_owned()),
            constructs: Some(ConstructList {
                links: vec!["https://x".to_owned()],
                ..ConstructList::default()
            }),
            requests: vec![req()],
        },
        PreviewBody::PageMove {
            page: "Plan".to_owned(),
            from_path: vec!["Home".to_owned(), "Plan".to_owned()],
            to_path: vec!["Home".to_owned(), "Archive".to_owned(), "Plan".to_owned()],
            requests: vec![req()],
        },
        PreviewBody::AttachmentUpload {
            filename: "a.png".to_owned(),
            size: 3,
            mime: "image/png".to_owned(),
            sha256: "cd".repeat(32),
            thumbnail_data_uri: Some("data:image/png;base64,AAAA".to_owned()),
            replaces_version: Some(2),
            existing: None,
            comment: None,
            requests: vec![digest_req()],
        },
    ]
}

#[test]
fn confluence_bodies_serialize_with_kind_tags() -> TestResult {
    let tags = [
        "confluence_page",
        "confluence_comments",
        "content_write",
        "page_move",
        "attachment_upload",
    ];
    let all = bodies();
    // a variant added to `bodies()` without a tag (or the reverse) fails here, not silently
    assert_eq!(all.len(), tags.len());
    for (b, tag) in all.iter().zip(tags) {
        assert_eq!(serde_json::to_value(b)?["kind"], tag);
    }
    let v = serde_json::to_value(&all[0])?;
    assert_eq!(v["version"], 7);
    assert_eq!(v["ancestors"], json!(["Home", "Projects"]));
    assert_eq!(v["format"], "markdown");
    assert_eq!(
        v["conversion"],
        json!({"lossy": true, "macros": 1, "images": 0, "links": 2, "layouts": 0,
               "unresolved_users": 1, "fallback": false})
    );
    let v = serde_json::to_value(&all[1])?;
    assert_eq!(
        v["comments"][0],
        json!({"id": "11", "author": "jdoe", "created": null, "location": "inline", "depth": 1,
               "parent_id": "10", "body_html": "<p>c</p>"})
    );
    assert_eq!(v["count"]["shown"], 1);
    let v = serde_json::to_value(&all[2])?;
    assert_eq!(v["rows"], json!([["space", "DEV"]]));
    assert_eq!(v["body_html"], "<p>b</p>");
    assert_eq!(v["constructs"]["links"], json!(["https://x"]));
    let v = serde_json::to_value(&all[3])?;
    assert_eq!(v["page"], "Plan");
    assert_eq!(v["from_path"], json!(["Home", "Plan"]));
    assert_eq!(v["to_path"], json!(["Home", "Archive", "Plan"]));
    let v = serde_json::to_value(&all[4])?;
    assert_eq!(v["filename"], "a.png");
    assert_eq!(v["size"], 3);
    assert_eq!(v["mime"], "image/png");
    assert_eq!(v["thumbnail_data_uri"], "data:image/png;base64,AAAA");
    assert_eq!(v["replaces_version"], 2);
    assert_eq!(v["existing"], Value::Null);
    assert_eq!(v["comment"], Value::Null);
    // Δ2: a request body shown as its size and digest only; the bytes are not in the DTO.
    assert_eq!(
        v["requests"][0]["body"],
        json!({"kind": "digest", "data": {"bytes": 2_000_000, "sha256": "ab".repeat(32)}})
    );
    Ok(())
}

#[test]
fn conflict_serializes_its_diffs_and_requests() -> TestResult {
    let line = |op, text: &str| DiffLine {
        op,
        text: text.to_owned(),
    };
    let b = PreviewBody::Conflict {
        summary: "conflict: page changed since the agent read it (v5 → v6)".to_owned(),
        diff_text: "base version v5, current version v6".to_owned(),
        base_to_current: vec![line(DiffOp::Del, "a\n"), line(DiffOp::Add, "b\n")],
        intended: vec![line(DiffOp::Add, "c\n")],
        requests: vec![req()],
    };
    let v = serde_json::to_value(&b)?;
    assert_eq!(v["kind"], "conflict");
    assert_eq!(
        v["base_to_current"],
        json!([{"op": "del", "text": "a\n"}, {"op": "add", "text": "b\n"}])
    );
    assert_eq!(v["intended"], json!([{"op": "add", "text": "c\n"}]));
    assert_eq!(v["requests"][0]["method"], "POST");
    Ok(())
}

#[test]
fn write_bodies_always_carry_requests() -> TestResult {
    // The Confluence write variants (§5.1 inv. 4) each hold `requests`; the field accesses below
    // stop compiling if one loses it.
    let mut writes = 0;
    for b in bodies() {
        let count = match &b {
            PreviewBody::ContentWrite { requests, .. }
            | PreviewBody::PageMove { requests, .. }
            | PreviewBody::AttachmentUpload { requests, .. }
            | PreviewBody::Conflict { requests, .. } => Some(requests.len()),
            _ => None,
        };
        let v = serde_json::to_value(&b)?;
        match count {
            Some(n) => {
                writes += 1;
                assert_eq!(n, 1);
                assert_eq!(v["requests"].as_array().map(Vec::len), Some(1));
                assert_eq!(v["requests"][0]["method"], "POST");
            }
            None => assert!(v.get("requests").is_none()),
        }
    }
    assert_eq!(writes, 3);
    Ok(())
}

#[test]
fn digest_line_is_the_plan_text() {
    assert_eq!(
        atlas_duck_preview::body_digest_line(12, "ab12"),
        "12 bytes, SHA-256 ab12 (not shown)"
    );
}
