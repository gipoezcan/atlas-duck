//! PD-74: one representative value of every command response type, serialized into
//! `app/ui/src/shared/ipc/fixtures/<type>.json` (a JSON array per type); the UI's
//! `fixtures.test.ts` (Task 5) parses each into its TypeScript type. `UPDATE_FIXTURES=1` rewrites
//! the files; otherwise a difference fails. Later tasks add their response types here.

type TestResult = Result<(), Box<dyn std::error::Error>>;

use std::path::PathBuf;

use atlas_duck_app_lib::commands::CommandError;
use atlas_duck_app_lib::commands::dto::{StatusLevel, StatusLineDto};
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::{
    AdminError, BatchFailure, BatchOutcome, CandidateRev, DecisionError, DecisionOutcome,
    QueueItem, SessionKey,
};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::diff::{DiffLine, DiffOp};
use atlas_duck_preview::form::{AllowedValues, EditForm, EditInput, InputKind};
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_preview::{
    BodyView, CommentView, ConstructList, FieldRow, IssueCard, ItemCount, OutcomeKind,
    PREVIEW_BUILDER_VERSION, Preview, PreviewBody, PreviewHeader, RawPager, RequestView, json_tree,
};
use serde::Serialize;
use serde_json::{Value, json};

const REQ: &str = "req_0123456789abcdefghij";
const REQ_2: &str = "req_abcdefghij0123456789";

fn rev() -> CandidateRev {
    CandidateRev {
        counter: 2,
        candidate_hash: [0xab; 32],
    }
}

fn queue_items() -> Vec<QueueItem> {
    vec![QueueItem {
        request_id: REQ.into(),
        op_id: "jira.issue.get".into(),
        class: "read",
        instance_alias: "work".into(),
        target_display: "PROJ-1".into(),
        agent_name: Some("claude-code".into()),
        agent_unverified: true,
        reason_excerpt: Some("look up the ticket".into()),
        unusual: false,
        age_s: 12,
        stale: false,
        caution_count: 1,
        possible_duplicate_of: Some(REQ_2.into()),
        similar_to: None,
        // Δ2 (Task 7) stops serializing the session (`session_id` / `session_label` instead).
        session: SessionKey {
            agent_name: Some("claude-code".into()),
            peer_origin_exe: None,
            connection_id: None,
            cwd_basename: "atlas-duck".into(),
        },
        opened: false,
        approvable: true,
        candidate_rev: rev(),
    }]
}

fn header(class: &str) -> PreviewHeader {
    PreviewHeader {
        instance_alias: "work".into(),
        op_id: "jira.issue.get".into(),
        class: class.into(),
        item_count: Some(ItemCount {
            shown: 1,
            total: Some(3),
            more_available: true,
        }),
        byte_size: 2048,
        fields_included: vec!["summary".into(), "status".into()],
        hidden_in_preview_bytes: 0,
        bidi_controls: 0,
        other_invisible: 1,
        executes_as: Some("jdoe".into()),
        receipt_fields: vec!["key".into()],
        query: None,
    }
}

fn requests() -> Vec<RequestView> {
    vec![
        RequestView {
            index: 0,
            method: "POST".into(),
            resolved_url: "https://jira.example.com/rest/api/2/issue".into(),
            content_type: Some("application/json".into()),
            body: BodyView::Text("{\"fields\":{}}".into()),
        },
        RequestView {
            index: 1,
            method: "PUT".into(),
            resolved_url: "https://jira.example.com/rest/api/2/issue/PROJ-1".into(),
            content_type: None,
            body: BodyView::Base64("AAEC".into()),
        },
        RequestView {
            index: 2,
            method: "DELETE".into(),
            resolved_url: "https://jira.example.com/rest/api/2/issue/PROJ-2".into(),
            content_type: None,
            body: BodyView::None,
        },
    ]
}

fn constructs() -> ConstructList {
    ConstructList {
        macros: vec!["code".into()],
        mentions: vec!["jdoe".into()],
        includes: vec![],
        links: vec!["https://example.com".into()],
        images: vec![],
        attachments: vec!["a.txt".into()],
    }
}

fn bodies() -> Vec<PreviewBody> {
    vec![
        PreviewBody::JsonTree {
            tree: json_tree(&json!({"key": "PROJ-1", "n": 2, "ok": true, "list": [null, 1.5]})),
        },
        PreviewBody::WriteRequests {
            requests: requests(),
        },
        PreviewBody::upstream_error(400, "Field 'summary' is required."),
        PreviewBody::Outcome {
            outcome: OutcomeKind::ReleaseCap16,
            size_or_pages: "17 MiB".into(),
            query: "project = PROJ".into(),
        },
        PreviewBody::enrichment_error(Some(404), "Issue does not exist", None),
        PreviewBody::UnresolvedName {
            param: "assignee".into(),
            value: "J. Doe".into(),
            matches: 2,
            candidates: vec!["jdoe".into(), "jdoe2".into()],
        },
        PreviewBody::Conflict {
            summary: "the issue changed since the preview".into(),
            diff_text: "- old\n+ new\n".into(),
        },
        PreviewBody::CouldNotRecheck {
            class: "network".into(),
            requests: requests(),
        },
        PreviewBody::JiraIssue {
            card: IssueCard {
                key: "PROJ-1".into(),
                summary: "Fix the thing".into(),
                issue_type: "Bug".into(),
                status: "Open".into(),
                priority: Some("High".into()),
                assignee: None,
                reporter: Some("jdoe".into()),
            },
            fields: vec![FieldRow {
                id: "customfield_10001".into(),
                name: "customfield_10001 (unknown field)".into(),
                value_text: "42".into(),
                restricted: false,
            }],
            description_html: Some("<p>sanitized</p>".into()),
            comments: vec![CommentView {
                id: "10000".into(),
                author: Some("jdoe".into()),
                created: Some("2026-10-14T10:00:00.000+0000".into()),
                body_html: "<p>a comment</p>".into(),
                restricted: true,
            }],
        },
        PreviewBody::Table {
            columns: vec!["Key".into(), "Summary".into()],
            rows: vec![vec!["PROJ-1".into(), "Fix the thing".into()]],
            count: Some(ItemCount {
                shown: 1,
                total: None,
                more_available: false,
            }),
        },
        PreviewBody::WriteSummary {
            sentence: "Create a Bug in PROJ".into(),
            rows: vec![("Summary".into(), "Fix the thing".into())],
            constructs: Some(constructs()),
            requests: requests(),
        },
        PreviewBody::EditDiff {
            rendered: vec![
                DiffLine {
                    op: DiffOp::Field,
                    text: "Description".into(),
                },
                DiffLine {
                    op: DiffOp::Same,
                    text: "same\n".into(),
                },
                DiffLine {
                    op: DiffOp::Del,
                    text: "old \r\n".into(),
                },
                DiffLine {
                    op: DiffOp::Add,
                    text: "new".into(),
                },
            ],
            raw: vec![DiffLine {
                op: DiffOp::Add,
                text: "h1. new".into(),
            }],
            raw_only_changes: 1,
            requests: requests(),
        },
        PreviewBody::Transition {
            transition: "Resolve (5)".into(),
            from: "Open".into(),
            to: "Resolved".into(),
            fields: vec![("Resolution".into(), "Fixed".into())],
            constructs: None,
            requests: requests(),
        },
    ]
}

fn previews() -> Vec<Preview> {
    bodies()
        .into_iter()
        .enumerate()
        .map(|(i, body)| {
            let write = !matches!(
                body,
                PreviewBody::JsonTree { .. }
                    | PreviewBody::Outcome { .. }
                    | PreviewBody::UpstreamError { .. }
                    | PreviewBody::JiraIssue { .. }
                    | PreviewBody::Table { .. }
            );
            Preview {
                candidate_rev: rev(),
                approvable: i % 2 == 0,
                header: header(if write { "write" } else { "read" }),
                warnings: vec![
                    Warning::new(
                        WarningId::PossibleDuplicate,
                        warning::possible_duplicate(REQ_2),
                    ),
                    Warning::new(WarningId::CustomFields, warning::custom_fields(1)),
                ],
                body,
                raw: RawPager::for_total(300 * 1024),
                also_appears_in: vec!["fields.description".into()],
                preview_builder_version: PREVIEW_BUILDER_VERSION.into(),
                edit_form: write.then(|| EditForm {
                    inputs: vec![
                        EditInput {
                            path: "summary".into(),
                            label: "Summary".into(),
                            kind: InputKind::Text,
                            read_only: false,
                            required: true,
                            pre_added: false,
                            value: json!("Fix the thing"),
                        },
                        EditInput {
                            path: "fields.priority".into(),
                            label: "Priority".into(),
                            kind: InputKind::Choice(AllowedValues::new(vec![
                                "High".into(),
                                "Low".into(),
                            ])),
                            read_only: false,
                            required: false,
                            pre_added: true,
                            value: Value::Null,
                        },
                        EditInput {
                            path: "issue_key".into(),
                            label: "Issue".into(),
                            kind: InputKind::Text,
                            read_only: true,
                            required: true,
                            pre_added: false,
                            value: json!("PROJ-1"),
                        },
                    ],
                }),
            }
        })
        .collect()
}

fn decision_outcomes() -> Vec<DecisionOutcome> {
    vec![
        DecisionOutcome {
            request_id: REQ.into(),
            status: Status::Released,
        },
        DecisionOutcome {
            request_id: REQ_2.into(),
            status: Status::Pending,
        },
    ]
}

fn batch_outcomes() -> Vec<BatchOutcome> {
    vec![BatchOutcome {
        batch_id: "batch_0123456789abcdefghij".into(),
        items: decision_outcomes(),
    }]
}

fn command_errors() -> Vec<CommandError> {
    vec![
        CommandError::InvalidArgument { field: "reason" },
        CommandError::NotFound,
        CommandError::NotReady,
        CommandError::Decision(DecisionError::Stale { current: rev() }),
        CommandError::Decision(DecisionError::Invalid(InvalidReason::NotOpened)),
        CommandError::Decision(DecisionError::BatchRejected {
            failed: vec![(REQ.into(), BatchFailure::Stale)],
        }),
        CommandError::Decision(DecisionError::Cancelled),
        CommandError::Decision(DecisionError::NotDecidable),
        CommandError::Admin(AdminError::NotFound),
        CommandError::Admin(AdminError::Cancelled),
        CommandError::Internal,
    ]
}

fn status_lines() -> Vec<StatusLineDto> {
    vec![
        StatusLineDto {
            id: "locked_refused",
            text: "Locked — 3 requests refused".into(),
            level: StatusLevel::Caution,
        },
        StatusLineDto {
            id: "needs_attention",
            text: "2 need attention".into(),
            level: StatusLevel::Info,
        },
    ]
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ui/src/shared/ipc/fixtures")
}

fn value<T: Serialize>(items: &[T]) -> Result<Value, serde_json::Error> {
    serde_json::to_value(items)
}

/// Every fixture: file name (without `.json`) and its value.
fn all() -> Result<Vec<(&'static str, Value)>, serde_json::Error> {
    Ok(vec![
        ("batch_outcome", value(&batch_outcomes())?),
        ("command_error", value(&command_errors())?),
        ("decision_outcome", value(&decision_outcomes())?),
        ("preview", value(&previews())?),
        ("queue_item", value(&queue_items())?),
        ("status_line", value(&status_lines())?),
    ])
}

#[test]
fn every_preview_body_variant_has_a_fixture() -> TestResult {
    let kinds: Vec<String> = value(&previews())?
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p["body"]["kind"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let unique: std::collections::BTreeSet<&String> = kinds.iter().collect();
    // Thirteen `PreviewBody` variants (C.6), one fixture each; a new one must get a fixture.
    assert_eq!(kinds.len(), 13, "{kinds:?}");
    assert_eq!(unique.len(), 13, "{kinds:?}");
    Ok(())
}

#[test]
fn dto_fixtures_up_to_date() -> TestResult {
    let dir = fixtures_dir();
    let update = std::env::var_os("UPDATE_FIXTURES").is_some_and(|v| v == "1");
    if update {
        std::fs::create_dir_all(&dir)?;
    }
    let mut stale = Vec::new();
    for (name, v) in all()? {
        let path = dir.join(format!("{name}.json"));
        if update {
            std::fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&v)?))?;
            continue;
        }
        // Compared as JSON values: a checkout's line endings do not matter.
        let on_disk = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok());
        if on_disk.as_ref() != Some(&v) {
            stale.push(name);
        }
    }
    assert!(
        stale.is_empty(),
        "fixtures out of date: {stale:?}; run with UPDATE_FIXTURES=1 and commit the result"
    );
    Ok(())
}
