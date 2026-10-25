//! PD-74: one representative value of every command response type, serialized into
//! `app/ui/src/shared/ipc/fixtures/<type>.json` (a JSON array per type); the UI's
//! `fixtures.test.ts` (Task 5) parses each into its TypeScript type. `UPDATE_FIXTURES=1` rewrites
//! the files; otherwise a difference fails. Later tasks add their response types here.

type TestResult = Result<(), Box<dyn std::error::Error>>;

use std::path::{Path, PathBuf};

use atlas_duck_app_lib::cli_install::InstallError;
use atlas_duck_app_lib::commands::approvals::{
    DenyCount, QueueDetail, RawPageDto, RedactionContextDto, preview_fetch_response,
};
use atlas_duck_app_lib::commands::audit::{
    AcknowledgedDto, AuditPageDto, AuditPayloadDto, AuditStatusDto, AuditTrailDto,
    CredentialChangeFailure, CursorDto, DeliveriesDto, EventHeaderDto, ExportCancelDto,
    ExportDoneDto, IncidentDto,
};
use atlas_duck_app_lib::commands::credential::{
    ArchiveOutcome, CLASS_CONTEXT_CHANGED, CLASS_PASSPHRASE_NOT_CHANGED, Connected,
    CredentialContextDto, NoteSaved, RetryStarted, SubmitFailure, SubmitOutcome,
    connection_failure, context_dto,
};
use atlas_duck_app_lib::commands::dto::{StatusLevel, StatusLineDto};
use atlas_duck_app_lib::commands::onboarding::{OnboardingSectionDto, OnboardingTextDto};
use atlas_duck_app_lib::commands::running::KillAnswer;
use atlas_duck_app_lib::commands::settings::{
    CliInstallAnswer, ConfinementDto, ExtraLayerDto, OUTCOME_ALREADY_INSTALLED,
    OUTCOME_ALREADY_ON_PATH, OUTCOME_INSTALLED, OUTCOME_INSTALLED_LOCAL_BIN,
    OUTCOME_INSTALLED_LOCAL_BIN_ON_PATH, OUTCOME_REMOVED, OUTCOME_REPLACED_STALE_ENTRY,
    RestoreCancelDto, RestoreDoneDto, RetestOutcome, SettingsGet,
};
use atlas_duck_app_lib::commands::{
    AnchorDirFailure, AuditReadFailure, CommandError, ExportFailure, ForgetFailure,
    ReAnchorFailure, RestoreFailure,
};
use atlas_duck_app_lib::credential::{PatTarget, Purpose};
use atlas_duck_app_lib::recovery_tier::{
    AnchorDirDto, ForgottenDto, OrphanInstallDto, ReAnchoredDto,
};
use atlas_duck_app_lib::removal::{
    BackupAnswer, Choice, FinishAnswer, ItemDto, RemovalDto, RemovalError,
};
use atlas_duck_app_lib::ui_sink::audit_job_payload;
use atlas_duck_app_lib::wizard::{
    MSG_NEEDS_SECRET_SERVICE, MSG_PIN_WRITE_FAILED, MSG_PREVIOUS_CHAIN_FOUND, WizardError,
    WizardState, WizardStep,
};
use atlas_duck_atlassian::ConnClass;
use atlas_duck_audit::{Actor, AuditError, DecisionColumn, EventFlags, EventHeader, EventType};
use atlas_duck_core::engine::write::CONFLICT_DENY_PREFILL;
use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::redact::{BlockReason, DropScope, RedactionPreset};
use atlas_duck_core::running::{KillAnswer as CoreKillAnswer, RunningScriptView};
use atlas_duck_core::validate::ValidationError;
use atlas_duck_core::{
    AdminError, AttentionMode, BatchFailure, BatchOutcome, CandidateRev, ConfigBanner,
    ConnectionFailure, DecisionError, DecisionOutcome, InstanceView, LimitsView, PreviewDelivery,
    Product, PruneReport, QueueItem, RELEASE_BLOCKED_INTERNAL, RecentItem, RedactionContext,
    RedactionOp, RedactionReport, RequestDetail, SessionKey, SettingsError, SettingsView,
    StoreHealthView, UrlMode, VerifyNow,
};
use atlas_duck_ipc::envelope::{ErrorCode, Status};
use atlas_duck_ipc::sandbox::ScriptLimits;
use atlas_duck_preview::diff::{DiffLine, DiffOp};
use atlas_duck_preview::form::{AllowedValues, EditForm, EditInput, InputKind};
use atlas_duck_preview::render;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use atlas_duck_preview::{
    BodyView, CommentView, ConfluenceComment, ConstructList, ConversionFacts, DenyOffer,
    DenyOfferKind, FieldRow, IssueCard, ItemCount, OutcomeKind, PREVIEW_BUILDER_VERSION, Platform,
    Preselect, Preview, PreviewBody, PreviewHeader, ProvenanceRow, RawPager, RequestView,
    ScriptItemKind, json_tree,
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
            // M7 Δ2: the base → current diff, the agent's intended change and the requests.
            base_to_current: vec![
                DiffLine {
                    op: DiffOp::Del,
                    text: "old\n".into(),
                },
                DiffLine {
                    op: DiffOp::Add,
                    text: "current\n".into(),
                },
            ],
            intended: vec![DiffLine {
                op: DiffOp::Add,
                text: "new".into(),
            }],
            requests: requests(),
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
            constructs: None,
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
        // M7 Δ2: the Confluence bodies.
        PreviewBody::ConfluencePage {
            title: "Release plan".into(),
            space: "Development (DEV)".into(),
            version: Some(7),
            ancestors: vec!["Home".into(), "Projects".into()],
            format: "markdown".into(),
            body_html: "<p>sanitized</p>".into(),
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
            comments: vec![
                ConfluenceComment {
                    id: "11".into(),
                    author: Some("jdoe".into()),
                    created: Some("2026-10-16T10:00:00.000Z".into()),
                    location: Some("footer".into()),
                    depth: 0,
                    parent_id: None,
                    body_html: "<p>a comment</p>".into(),
                },
                // Every `Option` null: no author, date or location reported.
                ConfluenceComment {
                    id: "12".into(),
                    author: None,
                    created: None,
                    location: None,
                    depth: 1,
                    parent_id: Some("11".into()),
                    body_html: "<p>a reply</p>".into(),
                },
            ],
            count: None,
        },
        PreviewBody::ContentWrite {
            sentence: "Create page 'Release plan' in Development (DEV)".into(),
            rows: vec![("title".into(), "Release plan".into())],
            body_html: Some("<p>sanitized</p>".into()),
            constructs: Some(constructs()),
            requests: requests(),
        },
        PreviewBody::PageMove {
            page: "Release plan".into(),
            from_path: vec!["Home".into(), "Release plan".into()],
            to_path: vec!["Home".into(), "Archive".into(), "Release plan".into()],
            requests: requests(),
        },
        PreviewBody::AttachmentUpload {
            filename: "logo.png".into(),
            size: 70,
            mime: "image/png".into(),
            sha256: "5a".repeat(32),
            thumbnail_data_uri: Some("data:image/png;base64,AAAA".into()),
            replaces_version: Some(3),
            existing: Some("attachment att9001, version 2".into()),
            comment: None,
            notes: vec!["extension and content type differ".into()],
            // The digest-only body view (M7 Δ2).
            requests: vec![RequestView {
                index: 0,
                method: "POST".into(),
                resolved_url: "https://wiki.example.com/wiki/rest/api/content/1/child/attachment"
                    .into(),
                content_type: Some("multipart/form-data; boundary=atlas-duck-5a".into()),
                body: BodyView::Digest {
                    bytes: 2_000_000,
                    sha256: "5a".repeat(32),
                },
            }],
        },
        // M8 T17 (Δ5): a script's error-details item with every section.
        PreviewBody::Script {
            item: ScriptItemKind::ErrorDetails,
            view: Box::new(PreviewBody::JsonTree {
                tree: json_tree(&json!({"script_error": {"class": "TypeError", "elapsed": 12}})),
            }),
            source: "const r = await atlas.call('jira.issue.get', {key: 'PROJ-1'});\nreturn r;"
                .into(),
            provenance: vec![
                ProvenanceRow {
                    call_id: 1,
                    op_id: "jira.issue.get".into(),
                    instance: "work".into(),
                    target_display: "PROJ-1".into(),
                    outcome: "ok".into(),
                },
                ProvenanceRow {
                    call_id: 2,
                    op_id: "jira.search".into(),
                    instance: "work".into(),
                    target_display: "project = PROJ".into(),
                    outcome: "rejected:upstream_http".into(),
                },
                ProvenanceRow {
                    call_id: 3,
                    op_id: "jira.issue.get".into(),
                    instance: "work".into(),
                    target_display: "PROJ-2".into(),
                    outcome: "cancelled_in_flight".into(),
                },
            ],
            logs: vec!["step 1".into(), "step 2".into()],
            logs_note: Some("output was cut at its size bound".into()),
            stderr: "warning: slow".into(),
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
                    | PreviewBody::ConfluencePage { .. }
                    | PreviewBody::ConfluenceComments { .. }
                    | PreviewBody::Script { .. }
            );
            let script = matches!(body, PreviewBody::Script { .. });
            let mut header = header(if write {
                "write"
            } else if script {
                "script"
            } else {
                "read"
            });
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
                preselect: script.then_some(Preselect::ErrorClassOnly),
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
        // M6 T27: "Install CLI to PATH" failures, the kind only (no path, no OS text).
        CommandError::CliInstall(InstallError::NoStablePath),
        CommandError::CliInstall(InstallError::UnsafePath),
        CommandError::CliInstall(InstallError::Occupied),
        CommandError::CliInstall(InstallError::Unsupported),
        CommandError::CliInstall(InstallError::Registry),
        CommandError::CliInstall(InstallError::PathTooLong),
        CommandError::CliInstall(InstallError::Io),
        CommandError::CliInstall(InstallError::CliToml),
        // M10 T19 (PD-177): a wrapper or launcher a newer atlas-duck wrote.
        CommandError::CliInstall(InstallError::NewerVersion),
        // M6 T28: "Prepare for removal" refusals, the kind only.
        CommandError::Removal(RemovalError::NoProcedure),
        CommandError::Removal(RemovalError::Unticked),
        CommandError::Removal(RemovalError::TokenStored),
        CommandError::Removal(RemovalError::Autostart),
        CommandError::Removal(RemovalError::Recorded),
        // M10 T16 (T28 m-8): another removal call runs.
        CommandError::Removal(RemovalError::Running),
        // The T7 review H1 banner: its text is the core constant, put on the wire by Rust.
        CommandError::ReleaseBlocked,
        // M10 T12: the Audit window's kinds (a name, never a path; no error text).
        CommandError::Cancelled,
        CommandError::Export(ExportFailure::EmptyRange),
        CommandError::Export(ExportFailure::Exists),
        CommandError::Export(ExportFailure::Leftover {
            dir_name: format!("atlas-duck-export-{CHAIN}-1-40-20261019T120000Z.partial"),
        }),
        CommandError::Export(ExportFailure::NotRenamed {
            manifest_sha256: "5e".repeat(32),
            dir_name: format!("atlas-duck-export-{CHAIN}-1-40-20261019T120000Z.partial"),
            rows: 40,
        }),
        CommandError::Export(ExportFailure::Failed),
        CommandError::Backup,
        CommandError::Audit(AuditReadFailure::Unreadable { seq: 17 }),
        CommandError::Audit(AuditReadFailure::Failed),
        // M10 T13 (PD-168): a refused or failed restore, by kind.
        CommandError::Restore(RestoreFailure::WrongPassphrase),
        CommandError::Restore(RestoreFailure::NotABackup),
        CommandError::Restore(RestoreFailure::Newer),
        CommandError::Restore(RestoreFailure::Broken),
        CommandError::Restore(RestoreFailure::AnchorDirMismatch),
        CommandError::Restore(RestoreFailure::CommittedIncomplete),
        CommandError::Restore(RestoreFailure::Keychain),
        CommandError::Restore(RestoreFailure::Failed),
        // M10 T14 (PD-166, PD-170): the anchor directory, re-anchor and "Forget old install".
        CommandError::AnchorDir(AnchorDirFailure::NotWritable),
        CommandError::AnchorDir(AnchorDirFailure::WriterBusy),
        CommandError::AnchorDir(AnchorDirFailure::Unchanged),
        CommandError::AnchorDir(AnchorDirFailure::NotSet),
        CommandError::AnchorDir(AnchorDirFailure::Failed),
        CommandError::ReAnchor(ReAnchorFailure::NothingMissing),
        CommandError::ReAnchor(ReAnchorFailure::Held),
        CommandError::ReAnchor(ReAnchorFailure::DoesNotVerify),
        CommandError::ReAnchor(ReAnchorFailure::Restored),
        CommandError::ReAnchor(ReAnchorFailure::Keychain),
        CommandError::ReAnchor(ReAnchorFailure::Failed),
        CommandError::Forget(ForgetFailure::Unreadable),
        CommandError::Forget(ForgetFailure::Keychain {
            deleted: vec!["pat/0b9d3f62-4c1a-4f0e-9a51-7f2a6c3e8d11".into()],
            not_deleted: vec![
                "pat/0b9d3f62-4c1a-4f0e-9a51-7f2a6c3e8d12".into(),
                "canary".into(),
            ],
        }),
        CommandError::Forget(ForgetFailure::Failed),
        CommandError::Internal,
    ]
}

/// `anchor_dir_set` / `anchor_dir_remove` (M10 T14): a directory in force (a share, display
/// text), and none.
fn anchor_dir_answers() -> Vec<AnchorDirDto> {
    vec![
        AnchorDirDto {
            anchor_dir: Some("\\\\nas\\audit\\anchors".into()),
        },
        AnchorDirDto { anchor_dir: None },
    ]
}

/// `re_anchor` (M10 T14, PD-170): the `re_anchored` incident's seq.
fn re_anchoreds() -> Vec<ReAnchoredDto> {
    vec![ReAnchoredDto { verify_seq: 58 }]
}

/// `orphan_installs` (M10 T14, PD-170): an install with tokens and keys left, named by two
/// archives (one instance id with an invisible character, display-escaped by Rust); one with its
/// keys only.
fn orphan_installs() -> Vec<OrphanInstallDto> {
    vec![
        OrphanInstallDto {
            install_id: "0123456789abcdef0123456789abcdef".into(),
            archived_files: vec![
                format!("archived/audit-{CHAIN}-42-20261015T093000123Z.db"),
                format!("archived/audit-{CHAIN}-97-20261018T101500000Z.db"),
            ],
            entries: vec![
                "first_retained_anchor".into(),
                "head_anchor".into(),
                "kek".into(),
                "pat/0b9d3f62-4c1a-4f0e-9a51-7f2a6c3e8d11".into(),
                "pat/old\u{27E8}U+202E\u{27E9}".into(),
            ],
        },
        OrphanInstallDto {
            install_id: "fedcba9876543210fedcba9876543210".into(),
            archived_files: vec![format!("archived/audit-{CHAIN}-3-20260901T080000000Z.db")],
            entries: vec!["kek".into()],
        },
    ]
}

/// `forget_install` (M10 T14, PD-170): the tokens only (keys kept), and everything.
fn forgottens() -> Vec<ForgottenDto> {
    vec![
        ForgottenDto {
            install_id: "0123456789abcdef0123456789abcdef".into(),
            deleted: vec![
                "pat/0b9d3f62-4c1a-4f0e-9a51-7f2a6c3e8d11".into(),
                "canary".into(),
            ],
            keys_deleted: false,
        },
        ForgottenDto {
            install_id: "fedcba9876543210fedcba9876543210".into(),
            deleted: vec![
                "canary".into(),
                "first_retained_anchor".into(),
                "head_anchor".into(),
                "kek".into(),
            ],
            keys_deleted: true,
        },
    ]
}

/// A chain id in the shape the store writes (a lowercase UUID).
const CHAIN: &str = "0b9d3f62-4c1a-4f0e-9a51-7f2a6c3e8d10";

/// One header per kind of column the Audit window shows: an agent's request with every actor
/// column (and an invisible character in the target, display-escaped by Rust), a store-owned
/// record with flags and no request.
fn event_headers() -> Vec<EventHeaderDto> {
    let read = EventHeader {
        seq: 41,
        ts_utc: "2026-10-19T08:30:00.125Z".into(),
        epoch: Some("2026-10-19".into()),
        chain_id: CHAIN.into(),
        event_type: EventType::READ_RELEASED,
        request_id: Some(REQ.into()),
        op_id: Some("jira.issue.get".into()),
        op_class: Some("read".into()),
        instance_id: Some("0b9d3f62-4c1a-4f0e-9a51-7f2a6c3e8d11".into()),
        target: Some("PROJ-7\u{202E}".into()),
        decision: Some(DecisionColumn::ReleaseRedacted),
        flags: EventFlags::REDACTED,
        actor: Actor {
            agent_name: Some("claude-code-billing-api".into()),
            agent_name_source: Some("flag".into()),
            client_kind: Some("cli".into()),
            connection_id: Some("c-7".into()),
            peer_pid: Some(4242),
            peer_exe: Some(PathBuf::from("C:\\Tools\\atlas-duck.exe")),
            peer_origin_exe: Some(PathBuf::from("C:\\Tools\\agent.exe")),
            os_user: Some("alice".into()),
            atlassian_user: Some("jdoe".into()),
            atlassian_user_key: Some("JIRAUSER10100".into()),
        },
        payload_len: 1834,
        key_id: 3,
    };
    let verify = EventHeader {
        seq: 42,
        ts_utc: "2026-10-19T08:31:00.000Z".into(),
        epoch: None,
        chain_id: CHAIN.into(),
        event_type: EventType::VERIFY,
        request_id: None,
        op_id: None,
        op_class: None,
        instance_id: None,
        target: None,
        decision: None,
        flags: EventFlags::INTEGRITY_INCIDENT | EventFlags::BEHIND,
        actor: Actor::default(),
        payload_len: 211,
        key_id: 3,
    };
    vec![EventHeaderDto::of(&read), EventHeaderDto::of(&verify)]
}

/// `audit_query` (M10 T12): a full page with its next cursor, and the last (empty) page.
fn audit_pages() -> Vec<AuditPageDto> {
    vec![
        AuditPageDto {
            rows: event_headers(),
            next: Some(CursorDto {
                before_seq: Some(41),
                limit: 2,
            }),
            scanned: 3,
        },
        AuditPageDto {
            rows: vec![],
            next: None,
            scanned: 0,
        },
    ]
}

/// `audit_trail` (M10 T12): a request with a delivery to another program, and an empty trail.
fn audit_trails() -> Vec<AuditTrailDto> {
    vec![
        AuditTrailDto {
            headers: event_headers().into_iter().take(1).collect(),
            deliveries: DeliveriesDto {
                count: 2,
                to_other_peer: true,
            },
        },
        AuditTrailDto {
            headers: vec![],
            deliveries: DeliveriesDto {
                count: 0,
                to_other_peer: false,
            },
        },
    ]
}

/// `audit_payload` (M10 T12): a one-page payload as a tree, and the second page of a long one;
/// first and last (T20, L126) the two `CREDENTIAL_CHANGED` records with a failed keychain step.
fn audit_payloads() -> Vec<AuditPayloadDto> {
    let json = br#"{"body":"<b>x</b>","n":1}"#;
    let page = render::raw_display_last("aé\u{200B}".as_bytes(), &[]).text;
    let credential = |change: &str, failure| {
        let json = format!(
            r#"{{"change":"{change}","expires_at":null,"new_user_key":"JIRAUSER10100","old_user_key":null}}"#
        );
        AuditPayloadDto {
            srcdoc: render::audit_payload_document(json.as_bytes(), Platform::MacOsLinux),
            page: 0,
            page_count: 1,
            total_bytes: json.len() as u64,
            display: render::raw_display_last(json.as_bytes(), &[]).text,
            credential_change: Some(failure),
        }
    };
    vec![
        credential("store_failed", CredentialChangeFailure::StoreFailed),
        AuditPayloadDto {
            srcdoc: render::audit_payload_document(json, Platform::MacOsLinux),
            page: 0,
            page_count: 1,
            total_bytes: 25,
            display: render::raw_display_last(json, &[]).text,
            credential_change: None,
        },
        AuditPayloadDto {
            srcdoc: render::audit_payload_page_document(&page, Platform::MacOsLinux),
            page: 1,
            page_count: 2,
            total_bytes: 262_150,
            display: page,
            credential_change: None,
        },
        credential("delete_failed", CredentialChangeFailure::DeleteFailed),
    ]
}

/// `audit_status` (M10 T12): two open incidents (one whose record cannot be read), a failing
/// anchor directory; and a quiet store without one.
fn audit_statuses() -> Vec<AuditStatusDto> {
    let health = |incidents: u64, failing: bool| StoreHealthView {
        storage_low: false,
        anchor_write_failing: false,
        anchor_thread_dead: false,
        anchors_blocked: failing,
        open_incidents: incidents,
        prune_backlog_days: 0,
        prune_backlog: None,
        last_prune_failed: false,
        shred_checkpoint_pending: false,
        settings_unreadable: false,
        anchor_dir_write_failing: failing,
        anchor_dir_lines_pending: u32::from(failing) * 12,
        // M10 T14: a missing head anchor held by a barrier: named, not offered.
        anchors_missing: failing.then_some("head"),
        re_anchor_offered: false,
    };
    vec![
        AuditStatusDto {
            open_incidents: vec![
                IncidentDto {
                    verify_seq: 42,
                    result: Some("anchor_missing".into()),
                    detected_at: Some("2026-10-19T08:31:00.000Z".into()),
                },
                IncidentDto {
                    verify_seq: 7,
                    result: None,
                    detected_at: None,
                },
            ],
            incident_count: 2,
            health: health(2, true),
            anchor_dir: Some("\\\\nas\\audit\\anchors".into()),
        },
        AuditStatusDto {
            open_incidents: vec![],
            incident_count: 0,
            health: health(0, false),
            anchor_dir: None,
        },
    ]
}

fn acknowledged() -> Vec<AcknowledgedDto> {
    vec![AcknowledgedDto {
        verify_seq: 42,
        ack_seq: 57,
    }]
}

fn export_dones() -> Vec<ExportDoneDto> {
    vec![ExportDoneDto {
        manifest_sha256: "5e".repeat(32),
        dir_name: format!("atlas-duck-export-{CHAIN}-1-40-20261019T120000Z"),
        rows: 40,
    }]
}

fn export_cancels() -> Vec<ExportCancelDto> {
    vec![
        ExportCancelDto { cancelled: true },
        ExportCancelDto { cancelled: false },
    ]
}

/// The `audit_job` event payloads (Δ-M10-3): every phase of an export, and a backup's.
fn audit_jobs() -> Vec<Value> {
    use atlas_duck_app_lib::serve::AuditJobKind::{Backup, Export, Restore};
    let mut all: Vec<Value> = [
        (Export, "started", None),
        (Export, "progress", Some((10_000, 25_000))),
        (Export, "done", None),
        (Export, "failed", None),
        (Export, "cancelled", None),
        (Backup, "started", None),
        (Backup, "done", None),
        (Backup, "failed", None),
        // M10 T13: a restore is indeterminate too.
        (Restore, "started", None),
        (Restore, "done", None),
        (Restore, "failed", None),
        (Restore, "cancelled", None),
    ]
    .into_iter()
    .map(|(job, phase, rows)| audit_job_payload(job, phase, rows))
    .collect();
    all.dedup();
    all
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
        // `flagged` (M8 T19c) is not on the wire yet: the UI half is M8 Task 24.
        RedactionContext {
            ops: Vec::new(),
            url_fields: vec!["self", "fields.attachment[].content"],
            flagged: Vec::new(),
        },
        RedactionContext {
            ops,
            url_fields: Vec::new(),
            flagged: Vec::new(),
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
        StatusLineDto {
            id: "anchor_dir_write_failing",
            text: "Writing to the anchor directory fails; 3 lines wait and will be retried.".into(),
            level: StatusLevel::Caution,
        },
        StatusLineDto {
            id: "anchor_dir_lines_pending",
            text: "1 line waits to be written to the anchor directory.".into(),
            level: StatusLevel::Caution,
        },
        StatusLineDto {
            id: "anchors_missing",
            text: "The head anchor entry is missing from the keychain.".into(),
            level: StatusLevel::Caution,
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
        // M10 T13: "Restore a backup instead" on a locked store whose records cannot be read.
        SubmitOutcome::Failed(SubmitFailure::class("archive_first")),
        // T13 review M-2: the chosen backup, not the locked log, failed its check.
        SubmitOutcome::Failed(SubmitFailure::class("broken")),
        SubmitOutcome::Failed(SubmitFailure::class("anchor_dir_mismatch")),
        // M10 T14: a recovery-passphrase change the store refused (not the two entries).
        SubmitOutcome::Failed(SubmitFailure::class(CLASS_PASSPHRASE_NOT_CHANGED)),
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
        // M10 T12: the anchor directory's write state; both ends in the fixtures.
        anchor_dir_write_failing: low,
        anchor_dir_lines_pending: u32::from(low) * 3,
        // M10 T14 (PD-170): a missing anchor entry and the "Re-anchor" offer; both ends.
        anchors_missing: low.then_some("first_retained"),
        re_anchor_offered: low,
    };
    vec![
        SettingsView {
            limits: LimitsView {
                jira_comments_cap: 50,
                candidate_cache_mb: 256,
                max_pending_bytes_mb: Some(512),
                expiry_hours: 24,
                // M8 T23: every limit off its default, inside its PD-139 bound and both invariants.
                script: ScriptLimits {
                    timeout_s: 300,
                    heap_mb: 512,
                    process_mb: 1024,
                    max_calls: 400,
                    max_fetch_mb: 100,
                    max_call_result_mb: 8,
                    max_result_mb: 12,
                    max_concurrent_calls: 2,
                },
            },
            attention_mode: AttentionMode::BadgeOnly,
            retention_days: 365,
            legal_hold: true,
            anchor_dir: Some("anchors".into()),
            allow_degraded_scripts: true,
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
                script: ScriptLimits::default(),
            },
            attention_mode: AttentionMode::default(),
            retention_days: 100,
            legal_hold: false,
            anchor_dir: None,
            allow_degraded_scripts: false,
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
        // Floor met with the degraded setting on (`allow_degraded_scripts` of the first view):
        // scripts run confined, the setting is not in use.
        scripts: "enabled",
        degraded_allowed: true,
    };
    // Floor not met with the setting on: scripts run degraded (the persistent caution).
    let degraded = ConfinementDto {
        state: "not_met",
        failed: vec!["open_process_vm_read"],
        mode: "n/a",
        extra_layers: vec![],
        scripts: "degraded",
        degraded_allowed: true,
    };
    let not_met = ConfinementDto {
        state: "not_met",
        failed: vec!["connect_loopback", "cred_read"],
        mode: "appcontainer",
        extra_layers: vec![],
        scripts: "disabled",
        degraded_allowed: false,
    };
    vec![
        SettingsGet {
            settings: views.next().unwrap_or_else(|| unreachable!()),
            instances: insts.clone(),
            confinement: met,
            cli_installed: true,
            cli_removable: true,
        },
        SettingsGet {
            settings: views.next().unwrap_or_else(|| unreachable!()),
            instances: insts.split_off(1),
            confinement: not_met,
            cli_installed: false,
            cli_removable: true,
        },
        // deb/rpm: the CLI is in `/usr/bin` and nothing can be removed.
        SettingsGet {
            settings: settings_views().remove(1),
            instances: vec![],
            confinement: ConfinementDto::pending(),
            cli_installed: true,
            cli_removable: false,
        },
        // The degraded state: the setting on (the first view) and an unmet floor.
        SettingsGet {
            settings: settings_views().remove(0),
            instances: vec![],
            confinement: degraded,
            cli_installed: true,
            cli_removable: true,
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

/// `verify_now` (M6 T30, PD-82): the three outcomes.
fn verify_nows() -> Vec<VerifyNow> {
    vec![
        VerifyNow::Verified,
        VerifyNow::DidNotComplete,
        VerifyNow::Incident { count: 3 },
    ]
}

/// `running_list` (M6 T30, PD-81): a named run and one whose agent sent no name.
fn running_scripts() -> Vec<RunningScriptView> {
    vec![
        RunningScriptView {
            request_id: REQ.into(),
            agent_name: Some("claude-code-billing-api".into()),
            instances: vec!["jira-main".into(), "wiki".into()],
            started_at: "2026-10-15T08:30:00.000Z".into(),
            elapsed_ms: 93_500,
            host_calls: 4,
            bytes_fetched: 182_400,
        },
        RunningScriptView {
            request_id: REQ_2.into(),
            agent_name: None,
            instances: Vec::new(),
            started_at: "2026-10-15T08:31:12.250Z".into(),
            elapsed_ms: 0,
            host_calls: 0,
            bytes_fetched: 0,
        },
    ]
}

/// `running_kill` (M6 T30, M8 T22): the three answers.
fn kill_answers() -> Vec<KillAnswer> {
    [
        CoreKillAnswer::Killed,
        CoreKillAnswer::NotRunning,
        CoreKillAnswer::AlreadyStopping,
    ]
    .map(|answer| KillAnswer { answer })
    .to_vec()
}

/// `running_kill` (M8 T22, Δ8, PD-143): the answer is one object with one `answer` tag, the three
/// outcomes of core's `KillAnswer` in snake_case.
#[test]
fn running_kill_answer_shape() -> Result<(), Box<dyn std::error::Error>> {
    for (answer, tag) in [
        (CoreKillAnswer::Killed, "killed"),
        (CoreKillAnswer::NotRunning, "not_running"),
        (CoreKillAnswer::AlreadyStopping, "already_stopping"),
    ] {
        assert_eq!(
            serde_json::to_value(KillAnswer { answer })?,
            serde_json::json!({ "answer": tag })
        );
    }
    Ok(())
}

/// `onboarding_text` (M6 T30): a short sample; the real text is generated from the registry.
fn onboarding_texts() -> Vec<OnboardingTextDto> {
    let section = |id: &str, title: &str, text: &str| OnboardingSectionDto {
        id: id.into(),
        title: title.into(),
        text: text.into(),
    };
    vec![OnboardingTextDto {
        sections: vec![
            section("commands", "Commands", "- `atlas-duck ops list`\n"),
            section(
                "exit_matrix",
                "Exit codes",
                "- exit 0: `succeeded`, `released`\n",
            ),
        ],
    }]
}

/// `cli_install` / `cli_uninstall` (M6 T27): every outcome word.
fn cli_install_answers() -> Vec<CliInstallAnswer> {
    [
        OUTCOME_INSTALLED,
        OUTCOME_INSTALLED_LOCAL_BIN,
        OUTCOME_INSTALLED_LOCAL_BIN_ON_PATH,
        OUTCOME_REPLACED_STALE_ENTRY,
        OUTCOME_ALREADY_INSTALLED,
        OUTCOME_REMOVED,
        OUTCOME_ALREADY_ON_PATH,
    ]
    .into_iter()
    .map(|outcome| CliInstallAnswer { outcome })
    .collect()
}

/// `removal_state` (M6 T28): before `begin` (M10 T16: the newest record's remaining days; none
/// under a legal hold), and a checklist with every answer and a failed delete, recorded (PD-176).
fn removal_states() -> Vec<RemovalDto> {
    let idle = RemovalDto {
        active: false,
        recorded: false,
        backup_made: false,
        retention_days: 92,
        legal_hold: false,
        retention_left_days: Some(92),
        instances: vec![],
    };
    let item =
        |alias: &str, product, identity: Option<&str>, deleted, error: Option<&str>, choice| {
            ItemDto {
                alias: alias.into(),
                product,
                origin: Some(format!("https://{alias}.example/{product}")),
                identity: identity.map(str::to_owned),
                token_deleted: deleted,
                error: error.map(str::to_owned),
                choice,
            }
        };
    vec![
        idle.clone(),
        RemovalDto {
            backup_made: true,
            retention_days: 365,
            legal_hold: true,
            retention_left_days: None,
            ..idle.clone()
        },
        RemovalDto {
            active: true,
            recorded: true,
            backup_made: true,
            retention_left_days: Some(80),
            instances: vec![
                item("work", "jira", Some("jdoe"), true, None, Choice::Pending),
                item(
                    "wiki",
                    "confluence",
                    Some("asmith"),
                    true,
                    None,
                    Choice::Done,
                ),
                item("old", "jira", None, true, None, Choice::Skipped),
                item(
                    "stuck",
                    "jira",
                    Some("jdoe"),
                    false,
                    Some("keychain"),
                    Choice::Pending,
                ),
            ],
            ..idle
        },
    ]
}

/// `restore_begin` (M10 T13): a restore that gave up records, one that gave up none, and one
/// whose follow-up (`Core::after_restore`) failed (T13 review I-4).
fn restore_dones() -> Vec<RestoreDoneDto> {
    vec![
        RestoreDoneDto {
            restore_seq: 51,
            records_lost: 22,
            tokens_deleted: 2,
            offer_passphrase_change: true,
            after_restore_failed: false,
        },
        RestoreDoneDto {
            restore_seq: 9,
            records_lost: 0,
            tokens_deleted: 0,
            offer_passphrase_change: true,
            after_restore_failed: false,
        },
        RestoreDoneDto {
            restore_seq: 12,
            records_lost: 0,
            tokens_deleted: 1,
            offer_passphrase_change: true,
            after_restore_failed: true,
        },
    ]
}

/// `restore_cancel` (M10 T13).
fn restore_cancels() -> Vec<RestoreCancelDto> {
    vec![
        RestoreCancelDto { cancelled: true },
        RestoreCancelDto { cancelled: false },
    ]
}

fn removal_backup_answers() -> Vec<BackupAnswer> {
    vec![BackupAnswer { saved: true }, BackupAnswer { saved: false }]
}

fn removal_finish_answers() -> Vec<FinishAnswer> {
    let mut all = Vec::new();
    for cli in ["removed", "already_on_path", "not_found"] {
        for autostart in ["removed", "was_off"] {
            all.push(FinishAnswer {
                cli,
                cli_reason: None,
                autostart,
            });
        }
    }
    // The CLI step could not name the layout: its kind goes with the word.
    for reason in ["no_stable_path", "unsafe_path", "unsupported", "io"] {
        all.push(FinishAnswer {
            cli: "not_removed",
            cli_reason: Some(reason),
            autostart: "removed",
        });
    }
    all
}

/// `wizard_state` (M6 T23): a fresh start, a refused folder, the passphrase window, the instance
/// step with an unconfirmed instance, the Secret Service stop; M10 T15 (appended, the setup tests
/// take the first five by position): the anchor-dir step with a folder, a refused anchor dir, the
/// restore, the pin retry, the instance step after a previous chain was found.
fn wizard_states() -> Vec<WizardState> {
    let base = WizardState {
        step: WizardStep::DataDir.as_str(),
        stopped_text: None,
        data_dir: None,
        default_dir: "C:\\Users\\alice\\AppData\\Local\\atlas-duck".into(),
        refused_count: None,
        existing_store: false,
        secret_service: "n/a",
        passphrase_window: false,
        error: None,
        instances: vec![],
        anchor_dir: None,
        step_text: None,
        notice: None,
    };
    let data_dir = Some("C:\\Users\\alice\\AppData\\Local\\atlas-duck".to_owned());
    vec![
        base.clone(),
        WizardState {
            error: Some(WizardError {
                class: "not_local",
                text: Some(
                    "data directory \\\\nas\\home\\atlas is not on a local filesystem".into(),
                ),
            }),
            ..base.clone()
        },
        WizardState {
            step: WizardStep::Passphrase.as_str(),
            data_dir: data_dir.clone(),
            refused_count: Some(3),
            secret_service: "ok",
            passphrase_window: true,
            ..base.clone()
        },
        WizardState {
            step: WizardStep::Instances.as_str(),
            data_dir: data_dir.clone(),
            instances: instance_views().into_iter().take(1).collect(),
            ..base.clone()
        },
        WizardState {
            step: WizardStep::Stopped(MSG_NEEDS_SECRET_SERVICE).as_str(),
            stopped_text: Some(MSG_NEEDS_SECRET_SERVICE),
            data_dir: data_dir.clone(),
            refused_count: Some(0),
            secret_service: "missing",
            ..base.clone()
        },
        WizardState {
            step: WizardStep::AnchorDir.as_str(),
            data_dir: data_dir.clone(),
            refused_count: Some(1),
            anchor_dir: Some("\\\\nas\\audit-anchors".into()),
            ..base.clone()
        },
        WizardState {
            step: WizardStep::AnchorDir.as_str(),
            data_dir: data_dir.clone(),
            refused_count: Some(0),
            anchor_dir: Some("\\\\nas\\audit-anchors".into()),
            error: Some(WizardError {
                class: "anchor_dir",
                text: Some(atlas_duck_audit::FIRST_RUN_ANCHOR_DIR_REFUSALS[5].into()),
            }),
            ..base.clone()
        },
        WizardState {
            step: WizardStep::Restore.as_str(),
            data_dir: data_dir.clone(),
            refused_count: Some(0),
            ..base.clone()
        },
        WizardState {
            step: WizardStep::PinRetry.as_str(),
            data_dir: data_dir.clone(),
            step_text: Some(MSG_PIN_WRITE_FAILED),
            error: Some(WizardError {
                class: "pinned_write",
                text: None,
            }),
            ..base.clone()
        },
        WizardState {
            step: WizardStep::Instances.as_str(),
            data_dir,
            notice: Some(MSG_PREVIOUS_CHAIN_FOUND),
            ..base
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
        ("acknowledged", value(&acknowledged())?),
        ("anchor_dir_answer", value(&anchor_dir_answers())?),
        ("archive_outcome", value(&archive_outcomes())?),
        ("audit_job", value(&audit_jobs())?),
        ("audit_page", value(&audit_pages())?),
        ("audit_payload", value(&audit_payloads())?),
        ("audit_status", value(&audit_statuses())?),
        ("audit_trail", value(&audit_trails())?),
        ("batch_outcome", value(&batch_outcomes())?),
        ("cli_install_answer", value(&cli_install_answers())?),
        ("command_error", value(&command_errors())?),
        ("credential_context", value(&credential_contexts())?),
        ("decision_outcome", value(&decision_outcomes())?),
        ("deny_count", value(&deny_counts())?),
        ("export_cancel", value(&export_cancels())?),
        ("export_done", value(&export_dones())?),
        ("forgotten", value(&forgottens())?),
        ("instance_view", value(&instance_views())?),
        ("kill_answer", value(&kill_answers())?),
        ("note_saved", value(&note_saved())?),
        ("onboarding_text", value(&onboarding_texts())?),
        ("orphan_install", value(&orphan_installs())?),
        ("preview", value(&previews())?),
        ("prune_report", value(&prune_reports())?),
        ("queue_detail", value(&queue_details())?),
        ("queue_item", value(&queue_items())?),
        ("raw_page", value(&raw_pages())?),
        ("re_anchored", value(&re_anchoreds())?),
        ("recent_item", value(&recent_items())?),
        ("redaction_context", value(&redaction_contexts())?),
        ("redaction_report", value(&redaction_reports())?),
        ("removal_backup_answer", value(&removal_backup_answers())?),
        ("removal_finish_answer", value(&removal_finish_answers())?),
        ("removal_state", value(&removal_states())?),
        ("restore_cancel", value(&restore_cancels())?),
        ("restore_done", value(&restore_dones())?),
        ("retest_outcome", value(&retest_outcomes())?),
        ("retry_started", value(&retry_started())?),
        ("running_script", value(&running_scripts())?),
        ("settings_get", value(&settings_gets())?),
        ("status_line", value(&status_lines())?),
        ("submit_outcome", value(&submit_outcomes())?),
        ("verify_now", value(&verify_nows())?),
        ("wizard_state", value(&wizard_states())?),
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
    // Nineteen `PreviewBody` variants (C.6, M7 Δ2, M8 Δ5 `script`), one fixture each; a new one
    // must get a fixture.
    assert_eq!(kinds.len(), 19, "{kinds:?}");
    assert_eq!(unique.len(), 19, "{kinds:?}");
    Ok(())
}

/// T20b review m-1: the attachment thumbnail reaches the screen only through the `srcdoc` (no UI
/// code reads `thumbnail_data_uri`), so `preview_fetch` sends it once: in the document, never in
/// the preview DTO beside it. Everything else in the preview is sent as core built it.
#[test]
fn preview_fetch_sends_the_thumbnail_in_the_srcdoc_only() -> TestResult {
    let uri = "data:image/png;base64,AAAA";
    for preview in previews() {
        let upload = matches!(preview.body, PreviewBody::AttachmentUpload { .. });
        let mut want = preview.clone();
        if let PreviewBody::AttachmentUpload {
            thumbnail_data_uri, ..
        } = &mut want.body
        {
            assert_eq!(thumbnail_data_uri.as_deref(), Some(uri));
            *thumbnail_data_uri = None;
        }
        let r = preview_fetch_response(PreviewDelivery {
            preview,
            redaction: None,
        });
        assert_eq!(r.preview, want);
        assert_eq!(
            r.srcdoc.contains(&format!("<img src=\"{uri}\"")),
            upload,
            "the document shows the thumbnail"
        );
        assert!(!serde_json::to_string(&r.preview)?.contains(uri));
    }
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
