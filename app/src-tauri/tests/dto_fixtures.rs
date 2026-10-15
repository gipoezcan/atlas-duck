//! PD-74: one representative value of every command response type, serialized into
//! `app/ui/src/shared/ipc/fixtures/<type>.json` (a JSON array per type); the UI's
//! `fixtures.test.ts` (Task 5) parses each into its TypeScript type. `UPDATE_FIXTURES=1` rewrites
//! the files; otherwise a difference fails. Later tasks add their response types here.

type TestResult = Result<(), Box<dyn std::error::Error>>;

use std::path::{Path, PathBuf};

use atlas_duck_app_lib::commands::CommandError;
use atlas_duck_app_lib::commands::approvals::{
    DenyCount, QueueDetail, RawPageDto, RedactionContextDto,
};
use atlas_duck_app_lib::commands::credential::{
    ArchiveOutcome, CLASS_CONTEXT_CHANGED, Connected, CredentialContextDto, NoteSaved,
    RetryStarted, SubmitFailure, SubmitOutcome, connection_failure, context_dto,
};
use atlas_duck_app_lib::commands::dto::{StatusLevel, StatusLineDto};
use atlas_duck_app_lib::commands::settings::{
    ConfinementDto, ExtraLayerDto, RetestOutcome, SettingsGet,
};
use atlas_duck_app_lib::credential::{PatTarget, Purpose};
use atlas_duck_atlassian::ConnClass;
use atlas_duck_audit::AuditError;
use atlas_duck_core::engine::write::CONFLICT_DENY_PREFILL;
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::redact::{BlockReason, DropScope, RedactionPreset};
use atlas_duck_core::validate::ValidationError;
use atlas_duck_core::{
    AdminError, AttentionMode, BatchFailure, BatchOutcome, CandidateRev, ConfigBanner,
    ConnectionFailure, DecisionError, DecisionOutcome, InstanceView, LimitsView, Product,
    PruneReport, QueueItem, RELEASE_BLOCKED_INTERNAL, RecentItem, RedactionContext, RedactionOp,
    RedactionReport, RequestDetail, SessionKey, SettingsError, SettingsView, StoreHealthView,
    UrlMode,
};
use atlas_duck_ipc::envelope::{ErrorCode, Status};
use atlas_duck_preview::diff::{DiffLine, DiffOp};
use atlas_duck_preview::form::{AllowedValues, EditForm, EditInput, InputKind};
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_preview::{
    BodyView, CommentView, ConstructList, DenyOffer, DenyOfferKind, FieldRow, IssueCard, ItemCount,
    OutcomeKind, PREVIEW_BUILDER_VERSION, Preview, PreviewBody, PreviewHeader, RawPager,
    RequestView, json_tree,
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

/// An editable, optional, params-own input.
fn form_input(path: &str, kind: InputKind, value: Value) -> EditInput {
    EditInput {
        path: path.into(),
        label: path.into(),
        kind,
        read_only: false,
        required: false,
        pre_added: false,
        value,
    }
}

fn queue_items() -> Vec<QueueItem> {
    // Never serialized (PD-86); only its id and label reach the wire.
    let session = SessionKey {
        agent_name: Some("claude-code".into()),
        peer_origin_exe: None,
        connection_id: None,
        cwd_basename: "atlas-duck".into(),
    };
    // An agent that sent no name and no reason: every `Option<String>` is null (T13 review).
    let unnamed = SessionKey {
        agent_name: None,
        peer_origin_exe: None,
        connection_id: None,
        cwd_basename: "atlas-duck".into(),
    };
    vec![
        QueueItem {
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
            session_id: session.id(),
            session_label: session.label(),
            session,
            opened: false,
            approvable: true,
            candidate_rev: rev(),
        },
        QueueItem {
            request_id: "req_nullnullnullnullnull".into(),
            op_id: "jira.issue.create".into(),
            class: "write",
            instance_alias: "work".into(),
            target_display: "PROJ".into(),
            agent_name: None,
            agent_unverified: true,
            reason_excerpt: None,
            unusual: false,
            age_s: 3,
            stale: false,
            caution_count: 0,
            possible_duplicate_of: None,
            similar_to: None,
            session_id: unnamed.id(),
            session_label: unnamed.label(),
            session: unnamed,
            opened: false,
            approvable: true,
            candidate_rev: CandidateRev {
                counter: 1,
                candidate_hash: [0xab; 32],
            },
        },
    ]
}

fn queue_details() -> Vec<QueueDetail> {
    let mut items = queue_items().into_iter();
    let (full, nulls) = (items.next().unwrap(), items.next().unwrap());
    vec![
        QueueDetail {
            item: full,
            request: RequestDetail {
                params: json!({ "key": "PROJ-1", "fields": ["summary", "status"] }),
                params_sha256: "cd".repeat(32),
                reason: Some("look up the ticket".into()),
                submitted_at: "2026-10-14T09:30:00.000Z".into(),
                client_kind: Some("cli".into()),
                agent_name: Some("claude-code".into()),
                agent_name_source: Some("flag".into()),
                cwd_basename: "atlas-duck".into(),
                connection_id: Some("conn-0001".into()),
                peer_pid: Some(4242),
                peer_exe: Some("/usr/bin/atlas".into()),
                peer_origin_exe: Some("/usr/bin/zsh".into()),
                peer_chain: vec!["4242 /usr/bin/atlas".into(), "4100 /usr/bin/zsh".into()],
            },
        },
        // Every `Option` is `None`: the null branches of `isRequestDetail`.
        QueueDetail {
            item: nulls,
            request: RequestDetail {
                params: serde_json::Value::Null,
                params_sha256: "ef".repeat(32),
                reason: None,
                submitted_at: "2026-10-14T09:31:00.000Z".into(),
                client_kind: None,
                agent_name: None,
                agent_name_source: None,
                cwd_basename: "atlas-duck".into(),
                connection_id: None,
                peer_pid: None,
                peer_exe: None,
                peer_origin_exe: None,
                peer_chain: vec![],
            },
        },
    ]
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
        release_blocked: None,
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
            let mut header = header(if write { "write" } else { "read" });
            // M5 M-11: a read whose rebuild failed shows the banner and cannot be approved.
            let blocked = matches!(body, PreviewBody::JsonTree { .. });
            if blocked {
                header.release_blocked = Some(RELEASE_BLOCKED_INTERNAL);
            }
            // Every offer kind once, with and without an optional detail.
            let offer = |kind, has_optional_detail| DenyOffer {
                kind,
                has_optional_detail,
            };
            let deny_offers = match body {
                PreviewBody::WriteRequests { .. } => vec![
                    offer(DenyOfferKind::UpstreamHttp, true),
                    offer(DenyOfferKind::OutcomeHint, false),
                ],
                PreviewBody::UnresolvedName { .. } => {
                    vec![offer(DenyOfferKind::ResolutionFailed, true)]
                }
                PreviewBody::WriteSummary { .. } => {
                    vec![offer(DenyOfferKind::MissingFields, false)]
                }
                _ => vec![],
            };
            let deny_prefill = matches!(body, PreviewBody::Conflict { .. })
                .then(|| CONFLICT_DENY_PREFILL.to_owned());
            Preview {
                candidate_rev: rev(),
                approvable: i % 2 == 0 && !blocked,
                header,
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
                        // T16: one input of every other kind (the UI validates the whole form),
                        // the multi-pick (M-12) and an optional that is null.
                        form_input("description", InputKind::LongText, json!("A\nB")),
                        form_input("max_results", InputKind::Integer, json!(50)),
                        form_input("ratio", InputKind::Number, Value::Null),
                        form_input("notify", InputKind::Boolean, json!(true)),
                        form_input("update", InputKind::Json, json!({"labels": ["x"]})),
                        EditInput {
                            path: "fields.customfield_10300".into(),
                            label: "Areas (customfield_10300)".into(),
                            kind: InputKind::multi_choice_with_wire(vec![
                                ("UI".into(), Some(json!([{"id": "1"}]))),
                                ("API".into(), Some(json!([{"id": "2"}]))),
                            ]),
                            read_only: false,
                            required: true,
                            pre_added: true,
                            value: Value::Null,
                        },
                    ],
                }),
                deny_offers,
                deny_prefill,
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
        // The one variant carrying text: an app-generated message that can echo bounded agent values.
        CommandError::Decision(DecisionError::EditRejected(ValidationError {
            code: ErrorCode::Validation,
            message: "summary: must be a string (got 3)".into(),
            details: serde_json::Map::from_iter([("path".to_owned(), json!("summary"))]),
        })),
        // An AuditError is reduced to its kind on the wire.
        CommandError::Decision(DecisionError::Audit(AuditError::StorageLow)),
        CommandError::Admin(AdminError::NotFound),
        CommandError::Admin(AdminError::Cancelled),
        CommandError::Admin(AdminError::ConnectionFailed(ConnectionFailure::Http401)),
        CommandError::Admin(AdminError::ConnectionFailed(ConnectionFailure::Tls(
            ConnClass::TlsUnknownIssuer,
        ))),
        CommandError::Admin(AdminError::ConnectionFailed(ConnectionFailure::Network(
            ConnClass::ConnectTimeout,
        ))),
        // M3 M-4 / T9: an admin call after the shutdown began.
        CommandError::Admin(AdminError::ShuttingDown),
        // M6 T25: the SettingsAdmin refusals (kind, key and banner only) and a busy credential window.
        CommandError::Settings(SettingsError::Invalid {
            key: "jira_comments_cap",
        }),
        CommandError::Settings(SettingsError::Cancelled),
        CommandError::Settings(SettingsError::ConfigReadOnly(ConfigBanner {
            kind: "read_only",
            text: "config written by v9.9.0; settings read-only until you upgrade".into(),
        })),
        CommandError::Settings(SettingsError::NoConfigFile),
        CommandError::Settings(SettingsError::Conflict),
        CommandError::Settings(SettingsError::ConfigWrite),
        CommandError::Settings(SettingsError::Audit(AuditError::StorageLow)),
        CommandError::Settings(SettingsError::ShuttingDown),
        CommandError::Admin(AdminError::InsecureScheme),
        CommandError::Admin(AdminError::Unconfirmed),
        CommandError::Busy,
        // The T7 review H1 banner: its text is the core constant, put on the wire by Rust.
        CommandError::ReleaseBlocked,
        CommandError::Internal,
    ]
}

fn recent_items() -> Vec<RecentItem> {
    vec![
        RecentItem {
            request_id: REQ.into(),
            op_id: "jira.comment.add".into(),
            class: "write",
            instance_alias: "work".into(),
            target_display: "PROJ-1".into(),
            status: Status::Failed,
            decided_at: "2026-10-14T09:30:00.000Z".into(),
            error_text: Some("HTTP 403: no permission".into()),
            needs_attention: true,
            acknowledged: false,
        },
        RecentItem {
            request_id: REQ_2.into(),
            op_id: "jira.issue.get".into(),
            class: "read",
            instance_alias: "work".into(),
            target_display: "PROJ-2".into(),
            status: Status::Released,
            decided_at: "2026-10-14T09:31:00.000Z".into(),
            error_text: None,
            needs_attention: false,
            acknowledged: false,
        },
    ]
}

fn redaction_reports() -> Vec<RedactionReport> {
    vec![
        RedactionReport {
            blocked: vec![BlockReason::MaskStillOccurs {
                path: "fields.summary".into(),
            }],
            also_appears_in: vec!["fields.description".into(), "comment[2]".into()],
            other_occurrences: 3,
            released_bytes: 1_024,
        },
        RedactionReport {
            blocked: vec![],
            also_appears_in: vec![],
            other_occurrences: 0,
            released_bytes: 512,
        },
        // Every other reason the UI labels (M6 T17).
        RedactionReport {
            blocked: vec![
                BlockReason::UnstableEncoding {
                    path: "fields.description".into(),
                },
                BlockReason::ReencodeAmbiguous {
                    path: "self".into(),
                },
                BlockReason::MirrorOrphan {
                    path: "renderedFields.comment.comments[1]".into(),
                },
                BlockReason::MirrorUnmatchable {
                    path: "renderedFields.worklog.worklogs[0]".into(),
                },
                BlockReason::OpTargetMissing {
                    path: "fields.user.email".into(),
                },
                BlockReason::OverReleaseCap {
                    path: String::new(),
                },
            ],
            also_appears_in: vec![],
            other_occurrences: 0,
            released_bytes: 16_777_217,
        },
    ]
}

/// `preview_fetch`'s `redaction` (M6 T17): a first revision, and one with every op kind.
fn redaction_contexts() -> Vec<RedactionContextDto> {
    let ops = vec![
        RedactionOp::DropItem {
            array_path: "fields.comment.comments".into(),
            key: "id".into(),
            value: json!("10001"),
        },
        RedactionOp::DropField {
            path: "issues[key=ABC-1].fields.summary".into(),
            scope: DropScope::PerItem,
        },
        RedactionOp::DropField {
            path: "issues[key=ABC-1].fields.labels".into(),
            scope: DropScope::AllItems,
        },
        RedactionOp::MaskText {
            text: "Falcon".into(),
            every_occurrence: true,
            at: None,
        },
        RedactionOp::MaskText {
            text: "Falcon".into(),
            every_occurrence: false,
            at: Some("fields.description".into()),
        },
        RedactionOp::UrlField {
            mode: UrlMode::ReplaceWhole,
        },
        RedactionOp::UrlField {
            mode: UrlMode::Drop,
        },
        RedactionOp::Preset(RedactionPreset::StatusOnly),
        RedactionOp::Preset(RedactionPreset::ErrorClassOnly),
    ];
    [
        RedactionContext {
            ops: Vec::new(),
            url_fields: vec!["self", "fields.attachment[].content"],
        },
        RedactionContext {
            ops,
            url_fields: Vec::new(),
        },
    ]
    .iter()
    .map(RedactionContextDto::from)
    .collect()
}

fn deny_counts() -> Vec<DenyCount> {
    vec![DenyCount { denied: 0 }, DenyCount { denied: 3 }]
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

fn raw_pages() -> Vec<RawPageDto> {
    vec![
        RawPageDto {
            page: 0,
            page_count: 2,
            total_bytes: 262_150,
            bytes_b64: "YQ0KYv8=".into(),
            display: "a⟨U+000D⟩\nb⟨0xFF⟩".into(),
        },
        RawPageDto {
            page: 1,
            page_count: 2,
            total_bytes: 262_150,
            bytes_b64: String::new(),
            display: String::new(),
        },
    ]
}

/// `credential_context` (M6 T20): a PAT purpose, a locked one, the first-run one after `GENESIS`.
fn credential_contexts() -> Vec<CredentialContextDto> {
    let target = PatTarget {
        alias: "work".into(),
        product: "jira",
        origin: "https://jira.example/jira".into(),
    };
    vec![
        context_dto(&Purpose::ReplacePat(target), None, false),
        context_dto(&Purpose::RecoverThisLog, Some(3), false),
        context_dto(&Purpose::Unlock, Some(0), false),
        context_dto(&Purpose::RecoveryPassphrase, Some(1), true),
    ]
}

/// `submit_secret` (M6 T20): every outcome shape; never a secret.
fn submit_outcomes() -> Vec<SubmitOutcome> {
    vec![
        SubmitOutcome::Ok(Connected {
            atlassian_user: "alice".into(),
            product: "jira",
            version: "9.4.0".into(),
            warnings: vec!["Jira 9.12 or newer is recommended; this server reports 9.4.0.".into()],
        }),
        SubmitOutcome::Accepted {},
        SubmitOutcome::Unlocked {},
        SubmitOutcome::Failed(connection_failure(&ConnectionFailure::Tls(
            ConnClass::TlsUnknownIssuer,
        ))),
        SubmitOutcome::Failed(connection_failure(
            &ConnectionFailure::IdentityHeaderMissing,
        )),
        SubmitOutcome::Failed(SubmitFailure::class("wrong_passphrase")),
        SubmitOutcome::Failed(SubmitFailure::class("passphrase_mismatch")),
        SubmitOutcome::Failed(SubmitFailure::class(CLASS_CONTEXT_CHANGED)),
    ]
}

/// `archive_and_start_fresh` (M6 T20).
fn archive_outcomes() -> Vec<ArchiveOutcome> {
    vec![
        ArchiveOutcome::Archived {
            archived_file:
                "archived/audit-0123456789abcdef0123456789abcdef-42-20261015T093000123Z.db".into(),
        },
        ArchiveOutcome::Failed(SubmitFailure::class("cancelled")),
    ]
}

/// `save_recovery_note` (M6 T20): saved, or the save dialog was cancelled.
fn note_saved() -> Vec<NoteSaved> {
    vec![NoteSaved { saved: true }, NoteSaved { saved: false }]
}

/// `retry_keychain` (M6 T20, T22): a retry started, or one is still running.
fn retry_started() -> Vec<RetryStarted> {
    vec![
        RetryStarted { started: true },
        RetryStarted { started: false },
    ]
}

fn instance_views() -> Vec<InstanceView> {
    vec![
        InstanceView {
            alias: "work".into(),
            product: Product::Jira,
            origin: Some("https://jira.example/jira".into()),
            state: "ok",
            executes_as: Some("alice".into()),
            expires_at: Some("2027-01-31".into()),
            pac_configured: true,
            proxy_effective: Some("proxy.corp:3128".into()),
            pending_url_change: Some("https://jira.example/moved".into()),
            note: Some("token now resolves to bob".into()),
            expiry_warning: Some(7),
            days_left: Some(5),
        },
        // Every `Option` null: a hand-added instance nobody confirmed yet.
        InstanceView {
            alias: "wiki".into(),
            product: Product::Confluence,
            origin: None,
            state: "instance_unconfirmed",
            executes_as: None,
            expires_at: None,
            pac_configured: false,
            proxy_effective: None,
            pending_url_change: None,
            note: None,
            expiry_warning: None,
            days_left: None,
        },
    ]
}

fn settings_views() -> Vec<SettingsView> {
    let health = |low: bool, behind: Option<&str>| StoreHealthView {
        storage_low: low,
        anchor_write_failing: false,
        anchor_thread_dead: false,
        anchors_blocked: false,
        open_incidents: 0,
        prune_backlog_days: u32::from(behind.is_some()) * 12,
        prune_backlog: behind.map(str::to_owned),
        last_prune_failed: false,
        shred_checkpoint_pending: false,
        settings_unreadable: false,
    };
    vec![
        SettingsView {
            limits: LimitsView {
                jira_comments_cap: 50,
                candidate_cache_mb: 256,
                max_pending_bytes_mb: Some(512),
                expiry_hours: 24,
            },
            attention_mode: AttentionMode::BadgeOnly,
            retention_days: 365,
            legal_hold: true,
            anchor_dir: Some("anchors".into()),
            health: health(true, Some("pruning is 12 days behind")),
            config_read_only: Some(ConfigBanner {
                kind: "read_only",
                text: "config written by v9.9.0; settings read-only until you upgrade".into(),
            }),
            restart_pending: vec!["candidate_cache_mb"],
        },
        // Every `Option` null.
        SettingsView {
            limits: LimitsView {
                jira_comments_cap: 50,
                candidate_cache_mb: 256,
                max_pending_bytes_mb: None,
                expiry_hours: 24,
            },
            attention_mode: AttentionMode::default(),
            retention_days: 100,
            legal_hold: false,
            anchor_dir: None,
            health: health(false, None),
            config_read_only: None,
            restart_pending: vec![],
        },
    ]
}

/// `settings_get` (M6 T25): the view, the instances, the probe verdict in its three shapes, the CLI
/// state.
fn settings_gets() -> Vec<SettingsGet> {
    let mut views = settings_views().into_iter();
    let mut insts = instance_views();
    let met = ConfinementDto {
        state: "met",
        failed: vec![],
        mode: "lpac",
        extra_layers: vec![ExtraLayerDto {
            name: "landlock".into(),
            on: true,
        }],
    };
    let not_met = ConfinementDto {
        state: "not_met",
        failed: vec!["connect_loopback", "cred_read"],
        mode: "appcontainer",
        extra_layers: vec![],
    };
    vec![
        SettingsGet {
            settings: views.next().unwrap_or_else(|| unreachable!()),
            instances: insts.clone(),
            confinement: met,
            cli_installed: true,
        },
        SettingsGet {
            settings: views.next().unwrap_or_else(|| unreachable!()),
            instances: insts.split_off(1),
            confinement: not_met,
            cli_installed: false,
        },
        SettingsGet {
            settings: settings_views().remove(1),
            instances: vec![],
            confinement: ConfinementDto::pending(),
            cli_installed: false,
        },
    ]
}

/// `retest_token` (M6 T25): connected, or a fixed failure class.
fn retest_outcomes() -> Vec<RetestOutcome> {
    vec![
        RetestOutcome::Ok(Connected {
            atlassian_user: "alice".into(),
            product: "jira",
            version: "9.12.0".into(),
            warnings: vec![],
        }),
        RetestOutcome::Failed(connection_failure(&ConnectionFailure::OtherUser)),
        RetestOutcome::Failed(connection_failure(&ConnectionFailure::Network(
            ConnClass::ConnectTimeout,
        ))),
    ]
}

/// `prune_backlog_now` (M6 T25).
fn prune_reports() -> Vec<PruneReport> {
    vec![
        PruneReport::Pruned {
            count: 42,
            cutoff: "2026-07-15".into(),
            clamped: false,
        },
        PruneReport::Skipped {
            reason: "legal_hold",
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
        ("archive_outcome", value(&archive_outcomes())?),
        ("batch_outcome", value(&batch_outcomes())?),
        ("command_error", value(&command_errors())?),
        ("credential_context", value(&credential_contexts())?),
        ("decision_outcome", value(&decision_outcomes())?),
        ("deny_count", value(&deny_counts())?),
        ("instance_view", value(&instance_views())?),
        ("note_saved", value(&note_saved())?),
        ("preview", value(&previews())?),
        ("prune_report", value(&prune_reports())?),
        ("queue_detail", value(&queue_details())?),
        ("queue_item", value(&queue_items())?),
        ("raw_page", value(&raw_pages())?),
        ("recent_item", value(&recent_items())?),
        ("redaction_context", value(&redaction_contexts())?),
        ("redaction_report", value(&redaction_reports())?),
        ("retest_outcome", value(&retest_outcomes())?),
        ("retry_started", value(&retry_started())?),
        ("settings_get", value(&settings_gets())?),
        ("status_line", value(&status_lines())?),
        ("submit_outcome", value(&submit_outcomes())?),
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

/// The fixtures of `dir` that differ from `fixtures` (compared as JSON values: a checkout's line
/// endings do not matter), a missing or unparsable file included, and any `.json` file in `dir`
/// no fixture owns.
fn stale(dir: &Path, fixtures: &[(&str, Value)]) -> std::io::Result<Vec<String>> {
    let mut stale = Vec::new();
    for (name, v) in fixtures {
        let on_disk = std::fs::read_to_string(dir.join(format!("{name}.json")))
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok());
        if on_disk.as_ref() != Some(v) {
            stale.push((*name).to_owned());
        }
    }
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let stem = path.file_stem().and_then(|s| s.to_str());
            if path.extension().is_some_and(|e| e == "json")
                && let Some(stem) = stem
                && !fixtures.iter().any(|(name, _)| *name == stem)
            {
                stale.push(format!("{stem} (no longer emitted)"));
            }
        }
    }
    Ok(stale)
}

#[test]
fn dto_fixtures_up_to_date() -> TestResult {
    let dir = fixtures_dir();
    let fixtures = all()?;
    if std::env::var_os("UPDATE_FIXTURES").is_some_and(|v| v == "1") {
        std::fs::create_dir_all(&dir)?;
        for (name, v) in &fixtures {
            let text = format!("{}\n", serde_json::to_string_pretty(v)?);
            std::fs::write(dir.join(format!("{name}.json")), text)?;
        }
        // Never a pass: a leaked variable must not let CI go green on whatever was written.
        panic!("fixtures rewritten; commit them and rerun without UPDATE_FIXTURES");
    }
    let stale = stale(&dir, &fixtures)?;
    assert!(
        stale.is_empty(),
        "fixtures out of date: {stale:?}; run with UPDATE_FIXTURES=1 and commit the result"
    );
    Ok(())
}

/// The comparison itself is not vacuous: a changed, a missing and a leftover file are each found.
#[test]
fn stale_detects_differences() -> TestResult {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("dto_fixtures_stale");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let fixtures = vec![("a", json!([1])), ("b", json!([2])), ("c", json!([3]))];
    std::fs::write(dir.join("a.json"), "[1]\r\n")?;
    std::fs::write(dir.join("b.json"), "[9]\n")?;
    std::fs::write(dir.join("old.json"), "[]\n")?;
    assert_eq!(
        stale(&dir, &fixtures)?,
        ["b", "c", "old (no longer emitted)"]
    );
    std::fs::write(dir.join("b.json"), "[2]")?;
    std::fs::write(dir.join("c.json"), "[3]")?;
    std::fs::remove_file(dir.join("old.json"))?;
    assert!(stale(&dir, &fixtures)?.is_empty());
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
