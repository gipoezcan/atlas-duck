//! M6 T3 (§2.4, §10.3, S-09 mock-runtime half, S-16 Tauri half): the command layer over Tauri's
//! mock runtime. The context is the app's generated one (`generate_context!`: the app manifest
//! `build.rs` derives from `COMMANDS`, the seven capability files of `tauri.conf.json` (T4)), with
//! no assets, so the grants under test are the shipped ones. The mock runtime opens no OS window.
//!
//! Tauri checks the ACL of an app command only when the context carries an app manifest
//! (`webview/mod.rs`, `has_app_acl_manifest`): `tauri::test::mock_context` has none, so these
//! tests use the generated context, where a command outside a window's grant is refused.

type TestResult = Result<(), Box<dyn std::error::Error>>;

use atlas_duck_app_lib::commands::{self, COMMANDS};
use serde_json::{Value, json};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{INVOKE_KEY, MockRuntime, get_ipc_response, mock_builder};
use tauri::webview::InvokeRequest;
use tauri::{App, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

fn app() -> Result<App<MockRuntime>, Box<dyn std::error::Error>> {
    let context = tauri::generate_context!(assets = tauri::test::noop_assets(), test = true);
    Ok(commands::register(mock_builder()).build(context)?)
}

fn window(app: &App<MockRuntime>, label: &str) -> tauri::Result<WebviewWindow<MockRuntime>> {
    WebviewWindowBuilder::new(app, label, WebviewUrl::default()).build()
}

/// One invoke from `w` (its own, local URL); `Err` is what the webview's promise rejects with.
fn invoke(w: &WebviewWindow<MockRuntime>, cmd: &str, body: Value) -> Result<Value, Value> {
    let url = w.url().map_err(|e| json!(e.to_string()))?;
    let request = InvokeRequest {
        cmd: cmd.into(),
        callback: CallbackFn(0),
        error: CallbackFn(1),
        url,
        body: InvokeBody::Json(body),
        headers: Default::default(),
        invoke_key: INVOKE_KEY.to_string(),
    };
    get_ipc_response(w, request).map(|b| b.deserialize::<Value>().unwrap_or(Value::Null))
}

#[test]
fn command_list_is_sorted_and_unique() {
    let mut sorted = COMMANDS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted, COMMANDS,
        "names.rs must stay sorted, one entry per command"
    );
}

#[test]
fn invoke_app_status_round_trips() -> TestResult {
    let app = app()?;
    let w = window(&app, "approvals")?;
    // No status model before Task 12: no lines.
    assert_eq!(invoke(&w, "app_status", json!({})), Ok(json!([])));
    Ok(())
}

/// The V34-adjacent answer for Task 31: under the mock runtime, with the generated context, the
/// ACL is enforced for app commands per window label. `app_status` is granted to `approvals` and
/// `settings` (Δ1) and to no other window.
#[test]
fn app_status_outside_grant_rejected() -> TestResult {
    let app = app()?;
    let granted = window(&app, "approvals")?;
    assert_eq!(
        invoke(&window(&app, "settings")?, "app_status", json!({})),
        Ok(json!([]))
    );
    for label in [
        "audit",
        "running_scripts",
        "onboarding",
        "credential",
        "setup",
        "unknown",
    ] {
        let w = window(&app, label)?;
        let refused = invoke(&w, "app_status", json!({}));
        assert!(refused.is_err(), "{label}: {refused:?}");
        // Refused by the ACL, not by the command layer (that answers a `{kind}` object).
        assert!(
            refused
                .as_ref()
                .err()
                .is_some_and(|e| e.get("kind").is_none()),
            "{label}: {refused:?}"
        );
    }
    // A command the app manifest does not list is refused too, also in the granted window.
    assert!(invoke(&granted, "no_such_command", json!({})).is_err());
    assert_eq!(invoke(&granted, "app_status", json!({})), Ok(json!([])));
    Ok(())
}

#[test]
fn unknown_field_rejected_before_handler() -> TestResult {
    let app = app()?;
    #[cfg(feature = "scripted-approver")]
    let cap = {
        let cap = commands::capture::bounded();
        commands::capture::install(app.handle(), cap.clone());
        cap
    };
    let w = window(&app, "approvals")?;
    let refused = json!({"kind": "invalid_argument", "field": "payload"});
    // The whole body is the argument struct: any key it does not name is refused, the
    // conventional `{"args": ..}` wrapper included; so is a body that is not an object.
    for body in [json!({"x": 1}), json!({"args": {}}), json!([]), json!(null)] {
        assert_eq!(
            invoke(&w, "app_status", body.clone()),
            Err(refused.clone()),
            "{body}"
        );
    }
    // The handler never ran: every recorded response is a refusal (the handler records `[]`).
    #[cfg(feature = "scripted-approver")]
    {
        use atlas_duck_core::testing::capture::Channel;
        let recorded = cap.on(Channel::TauriCommand);
        assert_eq!(recorded.len(), 4);
        assert!(recorded.iter().all(|c| c.json.contains("invalid_argument")));
        assert_eq!(invoke(&w, "app_status", json!({})), Ok(json!([])));
        assert_eq!(cap.on(Channel::TauriCommand).len(), 5);
        assert_eq!(cap.dropped(Channel::TauriCommand), 0);
    }
    Ok(())
}

/// M6 T6 (Δ1): `open_window` is granted to `approvals` only and opens one of four windows, built
/// under its fixed label; `quit` is granted to `approvals`, `credential` and `setup` only. (A
/// granted `quit` would end the test process, so only its refusals are invoked.)
#[test]
fn open_window_and_quit_follow_their_grants() -> TestResult {
    use atlas_duck_app_lib::windows::{NavPolicy, StartupRoute, WindowRegistry};
    let app = app()?;
    app.manage(WindowRegistry::new(
        NavPolicy::for_this_platform(None),
        StartupRoute::completed(),
    ));
    let approvals = window(&app, "approvals")?;
    assert_eq!(
        invoke(&approvals, "open_window", json!({"window": "settings"})),
        Ok(Value::Null)
    );
    assert!(app.get_webview_window("settings").is_some());
    let refused_window = json!({"kind": "invalid_argument", "field": "window"});
    let before = app.webview_windows().len();
    for bad in ["approvals", "credential", "setup", "main"] {
        assert_eq!(
            invoke(&approvals, "open_window", json!({ "window": bad })),
            Err(refused_window.clone()),
            "{bad}"
        );
    }
    assert_eq!(
        app.webview_windows().len(),
        before,
        "a refused window was opened"
    );
    assert!(app.get_webview_window("credential").is_none());
    assert_eq!(
        invoke(
            &approvals,
            "open_window",
            json!({"window": "audit", "url": "https://evil.example/"})
        ),
        Err(json!({"kind": "invalid_argument", "field": "payload"}))
    );

    let acl_refused =
        |r: &Result<Value, Value>| r.as_ref().err().is_some_and(|e| e.get("kind").is_none());
    for label in [
        "settings",
        "audit",
        "running_scripts",
        "onboarding",
        "credential",
        "setup",
    ] {
        let w = app
            .get_webview_window(label)
            .map_or_else(|| window(&app, label), Ok)?;
        let r = invoke(&w, "open_window", json!({"window": "audit"}));
        assert!(acl_refused(&r), "{label}: open_window {r:?}");
    }
    for label in ["settings", "audit", "running_scripts", "onboarding"] {
        let w = app
            .get_webview_window(label)
            .map_or_else(|| window(&app, label), Ok)?;
        let r = invoke(&w, "quit", json!({}));
        assert!(acl_refused(&r), "{label}: quit {r:?}");
    }
    // Granted, but the body is checked before the handler (which would quit) runs.
    for label in ["approvals", "credential", "setup"] {
        let w = app
            .get_webview_window(label)
            .map_or_else(|| window(&app, label), Ok)?;
        assert_eq!(
            invoke(&w, "quit", json!({"now": true})),
            Err(json!({"kind": "invalid_argument", "field": "payload"})),
            "{label}"
        );
    }
    Ok(())
}

#[test]
fn not_ready_without_a_serving_core() -> TestResult {
    let app = app()?;
    assert!(matches!(
        commands::core(app.handle()),
        Err(commands::CommandError::NotReady)
    ));
    app.manage(atlas_duck_app_lib::state::ServeSlot::default());
    assert!(matches!(
        commands::core(app.handle()),
        Err(commands::CommandError::NotReady)
    ));
    Ok(())
}

/// The DTO bounds (PD-66): a refused value names its field; the handler-facing types are only
/// built from values inside the bounds.
#[test]
fn dto_bounds() -> TestResult {
    use atlas_duck_app_lib::commands::dto::{
        CandidateRevDto, REASON_MAX_CHARS, Reason, RequestId, bounded_json, parse,
    };
    use commands::CommandError;

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Probe {
        request_id: RequestId,
        reason: Option<Reason>,
        candidate_rev: Option<CandidateRevDto>,
    }

    let id = "req_0123456789abcdefABCDEF_-";
    let hash = "00".repeat(32);
    let field = |body: Value| match parse::<Probe>(&body) {
        Err(CommandError::InvalidArgument { field }) => field,
        other => panic!("not refused: {other:?}"),
    };

    let ok = parse::<Probe>(&json!({
        "request_id": id,
        "reason": "x".repeat(REASON_MAX_CHARS),
        "candidate_rev": {"counter": 3, "candidate_hash": hash},
    }))?;
    assert_eq!(ok.request_id.as_str(), id);

    let long = "x".repeat(REASON_MAX_CHARS + 1);
    assert_eq!(field(json!({"request_id": id, "reason": long})), "reason");
    assert_eq!(
        field(json!({"request_id": id, "reason": "a\u{0}b"})),
        "reason"
    );
    assert_eq!(field(json!({"request_id": "req_1"})), "request_id");
    assert_eq!(
        field(json!({"request_id": "../../etc/passwd"})),
        "request_id"
    );
    let bad_hex = "0G".repeat(32);
    for rev in [
        json!({"counter": 3, "candidate_hash": bad_hex}),
        json!({"counter": 3, "candidate_hash": "AB".repeat(32)}),
        json!({"counter": 3, "candidate_hash": "00".repeat(31)}),
        json!({"counter": 3, "candidate_hash": hash, "more": 1}),
    ] {
        assert_eq!(
            field(json!({"request_id": id, "candidate_rev": rev})),
            "candidate_rev"
        );
    }
    assert_eq!(field(json!({"request_id": id, "unknown": 1})), "payload");

    let edits = json!({"summary": "x".repeat(1024)});
    assert!(bounded_json(&edits, 1 << 20));
    assert!(!bounded_json(&edits, 1024));
    Ok(())
}

/// S-16 Tauri half: one command and one emitted `queue_changed` are two records, one on each new
/// channel, holding exactly what the webview receives.
#[cfg(feature = "scripted-approver")]
#[test]
fn s16_tauri_capture_records_every_response_and_event() -> TestResult {
    use atlas_duck_app_lib::ui_sink::TauriUiSink;
    use atlas_duck_core::testing::capture::Channel;
    use atlas_duck_core::{UiEvent, UiSink};

    let app = app()?;
    // The recorder the test-build app installs: the sweep below is only meaningful if it dropped nothing.
    let cap = commands::capture::bounded();
    assert!(commands::capture::install(app.handle(), cap.clone()));
    let w = window(&app, "approvals")?;

    assert_eq!(invoke(&w, "app_status", json!({})), Ok(json!([])));
    let id = "req_0123456789abcdefghij";
    TauriUiSink::new(app.handle().clone(), None).emit(UiEvent::QueueChanged {
        request_ids: vec![id.into()],
    });

    let commands = cap.on(Channel::TauriCommand);
    let events = cap.on(Channel::TauriEvent);
    assert_eq!(commands.len(), 1, "{commands:?}");
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(serde_json::from_str::<Value>(&commands[0].json)?, json!([]));
    assert_eq!(
        serde_json::from_str::<Value>(&events[0].json)?,
        json!({"event": "queue_changed", "payload": {"request_ids": [id]}})
    );
    assert_eq!(cap.records().len(), 2);
    assert_eq!(cap.dropped(Channel::TauriCommand), 0);
    assert_eq!(cap.dropped(Channel::TauriEvent), 0);
    Ok(())
}

/// M6 T10 (Δ1): `preview_fetch` is granted to `approvals` only; its body is checked before the
/// handler, and without a serving core it answers `not_ready`.
#[test]
fn preview_fetch_granted_to_approvals_only() -> TestResult {
    let app = app()?;
    let id = format!("req_{}", "a".repeat(24));
    let approvals = window(&app, "approvals")?;
    assert_eq!(
        invoke(&approvals, "preview_fetch", json!({ "request_id": id })),
        Err(json!({"kind": "not_ready"}))
    );
    assert_eq!(
        invoke(
            &approvals,
            "preview_fetch",
            json!({ "request_id": "req_x" })
        ),
        Err(json!({"kind": "invalid_argument", "field": "request_id"}))
    );
    for label in [
        "settings",
        "audit",
        "running_scripts",
        "onboarding",
        "credential",
        "setup",
    ] {
        let refused = invoke(
            &window(&app, label)?,
            "preview_fetch",
            json!({ "request_id": id }),
        );
        assert!(
            refused
                .as_ref()
                .err()
                .is_some_and(|e| e.get("kind").is_none()),
            "{label}: {refused:?}"
        );
    }
    Ok(())
}

/// M6 T11 (Δ1, PD-68): `raw_page` is granted to `approvals` only; its body is checked before the
/// handler, and without a serving core it answers `not_ready`.
#[test]
fn raw_page_granted_to_approvals_only() -> TestResult {
    let app = app()?;
    let id = format!("req_{}", "a".repeat(24));
    let rev = json!({"counter": 1, "candidate_hash": "ab".repeat(32)});
    let body = json!({"request_id": id, "candidate_rev": rev, "page": 0});
    let approvals = window(&app, "approvals")?;
    assert_eq!(
        invoke(&approvals, "raw_page", body.clone()),
        Err(json!({"kind": "not_ready"}))
    );
    // The carry is derived in Rust: a body that names one is refused.
    let mut with_carry = body.clone();
    with_carry["carry"] = json!("");
    assert_eq!(
        invoke(&approvals, "raw_page", with_carry),
        Err(json!({"kind": "invalid_argument", "field": "payload"}))
    );
    for label in [
        "settings",
        "audit",
        "running_scripts",
        "onboarding",
        "credential",
        "setup",
    ] {
        let refused = invoke(&window(&app, label)?, "raw_page", body.clone());
        assert!(
            refused
                .as_ref()
                .err()
                .is_some_and(|e| e.get("kind").is_none()),
            "{label}: {refused:?}"
        );
    }
    Ok(())
}

/// The refusal of the ACL itself: Tauri answers a plain string, the command layer an object with
/// a `kind`.
fn acl_refused(r: &Result<Value, Value>) -> bool {
    r.as_ref().err().is_some_and(|e| e.get("kind").is_none())
}

const REQ: &str = "req_0123456789abcdefghij";

fn rev_body() -> Value {
    json!({"counter": 1, "candidate_hash": "ab".repeat(32)})
}

/// A valid body of every approvals command added by T12 (Δ1).
fn approvals_bodies() -> Vec<(&'static str, Value)> {
    vec![
        ("queue_list", json!({})),
        ("queue_get", json!({ "request_id": REQ })),
        (
            "decide",
            json!({"request_id": REQ, "decision": "release", "candidate_rev": rev_body()}),
        ),
        (
            "decide_batch",
            json!({"items": [{"request_id": REQ, "candidate_rev": rev_body()}]}),
        ),
        (
            "deny_batch",
            json!({"request_ids": [REQ], "reason": "not now"}),
        ),
        (
            "deny_session",
            json!({"session_id": "ab".repeat(32), "reason": "not now"}),
        ),
        ("acknowledge_attention", json!({"request_ids": [REQ]})),
        ("recent_list", json!({})),
        (
            "redaction_preview",
            json!({"request_id": REQ, "candidate_rev": rev_body(), "ops": []}),
        ),
    ]
}

/// M6 T12 (Δ1): every approvals command is granted to `approvals` only; with a valid body it
/// reaches its handler (which answers `not_ready` without a serving core), in every other window
/// Tauri's ACL refuses it before the command layer sees it.
#[test]
fn approvals_commands_granted_to_approvals_only() -> TestResult {
    let app = app()?;
    let approvals = window(&app, "approvals")?;
    let others = [
        "settings",
        "audit",
        "running_scripts",
        "onboarding",
        "credential",
        "setup",
    ]
    .map(|label| window(&app, label).map(|w| (label, w)))
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    for (cmd, body) in approvals_bodies() {
        assert!(COMMANDS.contains(&cmd), "{cmd} is not in COMMANDS");
        assert_eq!(
            invoke(&approvals, cmd, body.clone()),
            Err(json!({"kind": "not_ready"})),
            "{cmd}"
        );
        for (label, w) in &others {
            let refused = invoke(w, cmd, body.clone());
            assert!(acl_refused(&refused), "{label}: {cmd} {refused:?}");
        }
    }
    Ok(())
}

/// M6 T12 (PD-66): a body is checked before any handler: an unknown key is `payload`, a refused
/// value names its field, and nothing reaches core (the answer is never `not_ready`).
#[test]
fn approvals_command_bodies_are_checked_before_the_handler() -> TestResult {
    let app = app()?;
    let w = window(&app, "approvals")?;
    let field = |f: &str| Err(json!({"kind": "invalid_argument", "field": f}));
    let long = "x".repeat(atlas_duck_app_lib::commands::dto::REASON_MAX_CHARS + 1);
    let rev = rev_body();
    let too_many_ids: Vec<String> = (0..1001).map(|_| REQ.to_owned()).collect();
    let too_many_ops: Vec<Value> = (0..1001)
        .map(|_| json!({"url_field": {"mode": "drop"}}))
        .collect();
    let big_edit = json!({"set": {"summary": "x".repeat(1 << 20)}, "remove": []});
    let decide = |extra: Value| {
        let mut b = json!({"request_id": REQ, "decision": "deny", "candidate_rev": rev});
        if let (Some(m), Some(e)) = (b.as_object_mut(), extra.as_object()) {
            m.extend(e.clone());
        }
        b
    };
    let cases: Vec<(&str, Value, &str)> = vec![
        ("queue_list", json!({"x": 1}), "payload"),
        ("queue_get", json!({"request_id": "req_x"}), "request_id"),
        ("decide", decide(json!({"x": 1})), "payload"),
        (
            "decide",
            decide(json!({"decision": "obliterate"})),
            "decision",
        ),
        (
            "decide",
            decide(json!({"edits": {"set": {}, "extra": 1}})),
            "edits",
        ),
        ("decide", decide(json!({"edits": big_edit})), "edits"),
        ("decide", decide(json!({"edits": {"remove": [1]}})), "edits"),
        (
            "decide",
            decide(json!({"redactions": [{"nope": {}}]})),
            "redactions",
        ),
        (
            "decide",
            decide(
                json!({"redactions": [{"mask_text": {"text": "a", "every_occurrence": true, "more": 1}}]}),
            ),
            "redactions",
        ),
        (
            "decide",
            decide(json!({"redactions": too_many_ops})),
            "redactions",
        ),
        (
            "decide",
            decide(
                json!({"redactions": [{"mask_text": {"text": "x".repeat(65537), "every_occurrence": true, "at": null}}]}),
            ),
            "redactions",
        ),
        (
            "decide",
            decide(json!({"deny_details": {"upstream_http": {"include_messages": true, "x": 1}}})),
            "deny_details",
        ),
        (
            "decide",
            decide(json!({"deny_details": "everything"})),
            "deny_details",
        ),
        ("decide", decide(json!({"reason": long})), "reason"),
        ("decide_batch", json!({"items": []}), "items"),
        (
            "decide_batch",
            json!({"items": [{"request_id": REQ, "candidate_rev": rev, "edits": {}}]}),
            "items",
        ),
        (
            "deny_batch",
            json!({"request_ids": [], "reason": ""}),
            "request_ids",
        ),
        (
            "deny_batch",
            json!({"request_ids": too_many_ids, "reason": ""}),
            "request_ids",
        ),
        (
            "deny_batch",
            json!({"request_ids": ["../etc"], "reason": ""}),
            "request_ids",
        ),
        (
            "deny_session",
            json!({"session_id": "AB".repeat(32), "reason": ""}),
            "session_id",
        ),
        (
            "deny_session",
            json!({"session_id": "C:\\Users\\x\\claude.exe", "reason": ""}),
            "session_id",
        ),
        (
            "acknowledge_attention",
            json!({"request_ids": [1]}),
            "request_ids",
        ),
        ("recent_list", json!([]), "payload"),
        (
            "redaction_preview",
            json!({"request_id": REQ, "candidate_rev": rev, "ops": [{"preset": "everything"}]}),
            "ops",
        ),
        (
            "redaction_preview",
            json!({"request_id": REQ, "candidate_rev": rev, "redactions": []}),
            "payload",
        ),
    ];
    for (cmd, body, want) in cases {
        let got = invoke(&w, cmd, body.clone());
        assert_eq!(got, field(want), "{cmd} {}", {
            let s = body.to_string();
            s.chars().take(160).collect::<String>()
        });
    }
    Ok(())
}

/// M6 T12 (PD-66, PD-20): `decide`'s body maps field for field to core's `Decision`, for each of
/// the five kinds and for every optional part; a part a kind does not take is passed on as sent
/// (core refuses it), never dropped here.
#[test]
fn decide_maps_every_kind() -> TestResult {
    use atlas_duck_app_lib::commands::approvals::DecideArgs;
    use atlas_duck_app_lib::commands::dto::parse;
    use atlas_duck_core::{
        CandidateRev, Decision, DecisionKind, DenyDetails, DropScope, Edits, RedactionOp,
        RedactionPreset, UrlMode,
    };

    let rev = CandidateRev {
        counter: 1,
        candidate_hash: [0xab; 32],
    };
    let decision = |kind| Decision {
        request_id: REQ.to_owned(),
        decision: kind,
        candidate_rev: rev,
        edits: None,
        redactions: None,
        reason: None,
        deny_details: None,
    };
    let body = |kind: &str, extra: Value| {
        let mut b = json!({"request_id": REQ, "decision": kind, "candidate_rev": rev_body()});
        if let (Some(m), Some(e)) = (b.as_object_mut(), extra.as_object()) {
            m.extend(e.clone());
        }
        b
    };
    let map = |b: Value| -> Result<Decision, Box<dyn std::error::Error>> {
        Ok(parse::<DecideArgs>(&b)
            .map_err(|e| format!("{e:?}"))?
            .into_decision())
    };

    for (wire, kind) in [
        ("approve", DecisionKind::Approve),
        ("approve_edited", DecisionKind::ApproveEdited),
        ("release", DecisionKind::Release),
        ("release_redacted", DecisionKind::ReleaseRedacted),
        ("deny", DecisionKind::Deny),
    ] {
        assert_eq!(map(body(wire, json!({})))?, decision(kind), "{wire}");
    }

    let mut set = serde_json::Map::new();
    set.insert("summary".into(), json!("new"));
    assert_eq!(
        map(body(
            "approve_edited",
            json!({"edits": {"set": {"summary": "new"}, "remove": ["labels"]}})
        ))?,
        Decision {
            edits: Some(Edits {
                set: set.clone(),
                remove: vec!["labels".into()]
            }),
            ..decision(DecisionKind::ApproveEdited)
        }
    );
    // A missing half of the edits is empty; `null` is no edits at all.
    assert_eq!(
        map(body(
            "approve_edited",
            json!({"edits": {"set": {"summary": "new"}}})
        ))?
        .edits,
        Some(Edits {
            set,
            remove: vec![]
        })
    );
    assert_eq!(map(body("approve", json!({"edits": null})))?.edits, None);

    let ops = json!([
        {"drop_item": {"array_path": "issues", "key": "key", "value": "A-1"}},
        {"drop_field": {"path": "fields.summary", "scope": "all_items"}},
        {"mask_text": {"text": "secret", "every_occurrence": false, "at": "name[3]"}},
        {"mask_text": {"text": "secret", "every_occurrence": true}},
        {"url_field": {"mode": "replace_whole"}},
        {"url_field": {"mode": "drop"}},
        {"preset": "status_only"},
        {"preset": "error_class_only"},
    ]);
    assert_eq!(
        map(body("release_redacted", json!({ "redactions": ops })))?.redactions,
        Some(vec![
            RedactionOp::DropItem {
                array_path: "issues".into(),
                key: "key".into(),
                value: json!("A-1")
            },
            RedactionOp::DropField {
                path: "fields.summary".into(),
                scope: DropScope::AllItems
            },
            RedactionOp::MaskText {
                text: "secret".into(),
                every_occurrence: false,
                at: Some("name[3]".into())
            },
            RedactionOp::MaskText {
                text: "secret".into(),
                every_occurrence: true,
                at: None
            },
            RedactionOp::UrlField {
                mode: UrlMode::ReplaceWhole
            },
            RedactionOp::UrlField {
                mode: UrlMode::Drop
            },
            RedactionOp::Preset(RedactionPreset::StatusOnly),
            RedactionOp::Preset(RedactionPreset::ErrorClassOnly),
        ])
    );

    for (wire, want) in [
        (
            json!({"upstream_http": {"include_messages": true}}),
            DenyDetails::UpstreamHttp {
                include_messages: true,
            },
        ),
        (json!("outcome_hint"), DenyDetails::OutcomeHint),
        (
            json!({"resolution_failed": {"include_candidates": false}}),
            DenyDetails::ResolutionFailed {
                include_candidates: false,
            },
        ),
        (
            json!({"missing_fields": {"include_allowed_values": true}}),
            DenyDetails::MissingFields {
                include_allowed_values: true,
            },
        ),
    ] {
        let d = map(body("deny", json!({"reason": "no", "deny_details": wire})))?;
        assert_eq!(d.deny_details, Some(want));
        assert_eq!(d.reason.as_deref(), Some("no"));
    }
    Ok(())
}

#[cfg(feature = "scripted-approver")]
mod approvals_commands {
    use atlas_duck_app_lib::commands::CommandError;
    use atlas_duck_app_lib::commands::approvals::{
        DecideArgs, DenyCount, decide_batch_dto, decide_dto, deny_batch_dto, deny_session_dto,
        preview_fetch_dto, queue_detail_dto, queue_get_dto, redaction_preview_dto,
    };
    use atlas_duck_app_lib::commands::dto::{BatchItems, Reason, RequestIds, SessionId, parse};
    use atlas_duck_atlassian::testing::{TEST_USER, TEST_USER_KEY, XAuser, fixtures};
    use atlas_duck_audit::EventType;
    use atlas_duck_core::payloads::InvalidReason;
    use atlas_duck_core::testing::Harness;
    use atlas_duck_core::{CandidateRev, Confirm, DecisionError};
    use atlas_duck_ipc::envelope::{ErrorCode, Status};
    use atlas_duck_ipc::proto::exit_code;
    use atlas_duck_preview::PreviewBody;
    use serde_json::{Value, json};

    use super::TestResult;

    const ISSUE: &str = "jira.issue.get";
    const COMMENT: &str = "jira.comment.add";

    type Boxed = Box<dyn std::error::Error>;

    /// A Jira harness with issues `ABC-1`/`ABC-2` and a comment endpoint, native answers `answers`.
    async fn rig(answers: Vec<Confirm>) -> Result<Harness, Boxed> {
        let h = Harness::builder()
            .jira("jira-main")
            .confirm(answers)
            .start()
            .await?;
        let mock = h.mock("jira-main").ok_or("no jira mock")?;
        mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
            .await;
        mock.jira_server_info("9.12.0").await;
        for key in ["ABC-1", "ABC-2"] {
            mock.json(
                &format!("/rest/api/2/issue/{key}"),
                200,
                fixtures::JIRA_ISSUE,
            )
            .await;
        }
        mock.json(
            "/rest/api/2/issue/ABC-1/comment",
            201,
            fixtures::JIRA_COMMENT,
        )
        .await;
        Ok(h)
    }

    async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, Boxed> {
        let env = h.submit(op, params).await;
        let id = env.request_id.clone().ok_or("no request id")?;
        h.queued(&id, 10_000).await.ok_or("never queued")?;
        Ok(id)
    }

    fn comment() -> Value {
        json!({ "key": "ABC-1", "body": "Seen.", "body_format": "wiki" })
    }

    fn rev_wire(rev: CandidateRev) -> Value {
        json!({"counter": rev.counter, "candidate_hash": hex(&rev.candidate_hash)})
    }

    fn hex(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The wire body of one decision, parsed like the command layer parses it.
    fn decide_args(
        id: &str,
        kind: &str,
        rev: CandidateRev,
        extra: Value,
    ) -> Result<DecideArgs, Boxed> {
        let mut b = json!({"request_id": id, "decision": kind, "candidate_rev": rev_wire(rev)});
        if let (Some(m), Some(e)) = (b.as_object_mut(), extra.as_object()) {
            m.extend(e.clone());
        }
        parse::<DecideArgs>(&b).map_err(|e| format!("{e:?}").into())
    }

    async fn count(h: &Harness, t: EventType) -> Result<usize, Boxed> {
        Ok(h.events_of(t).await?.len())
    }

    /// Writes the instance received (POST/PUT/DELETE).
    async fn sent_writes(h: &Harness) -> Result<usize, Boxed> {
        Ok(h.mock("jira-main")
            .ok_or("no jira mock")?
            .received()
            .await
            .iter()
            .filter(|r| r.method.as_str() != "GET")
            .count())
    }

    /// `queue_get` carries the Request tab's facts (T14): the params as the agent sent them, their
    /// hash, the connection; a request that left the queue (unknown id) is `not_found`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn queue_get_carries_the_request_tab_facts() -> TestResult {
        let h = rig(vec![]).await?;
        let d = h.decisions();
        let params = comment();
        let id = queued(&h, COMMENT, params.clone()).await?;
        let got = queue_detail_dto(&*d, &id)?;
        assert_eq!(got.item.request_id, id);
        assert_eq!(got.request.params, params);
        assert_eq!(got.request.params_sha256.len(), 64);
        assert!(
            got.request
                .params_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert!(got.request.submitted_at.ends_with('Z'), "{got:?}");
        assert_eq!(got.request.agent_name.as_deref(), Some("test-agent"));
        assert_eq!(got.request.cwd_basename, "workdir");
        assert_eq!(
            queue_detail_dto(&*d, "req_0000000000000000none"),
            Err(CommandError::NotFound)
        );
        Ok(())
    }

    /// `decide` of a kind the item does not take is refused and changes nothing; an approve of a
    /// revision nobody opened is refused as `not_opened`, with no record and nothing sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn decide_maps_every_kind_through_core() -> TestResult {
        let h = rig(vec![]).await?;
        let d = h.decisions();
        let write = queued(&h, COMMENT, comment()).await?;
        let rev = queue_get_dto(&*d, &write)?.candidate_rev;

        // A release of a write is not a decision it takes.
        let release = decide_dto(&*d, decide_args(&write, "release", rev, json!({}))?);
        assert_eq!(
            release,
            Err(CommandError::Decision(DecisionError::NotDecidable))
        );

        // Approve of the unopened revision: refused, and the negative control of audit-before-
        // effect: no approval record exists, nothing was sent, the item is exactly as it was.
        let before = queue_get_dto(&*d, &write)?;
        let approve = decide_dto(&*d, decide_args(&write, "approve", rev, json!({}))?);
        assert_eq!(
            approve,
            Err(CommandError::Decision(DecisionError::Invalid(
                InvalidReason::NotOpened
            )))
        );
        assert_eq!(count(&h, EventType::WRITE_APPROVED).await?, 0);
        assert_eq!(sent_writes(&h).await?, 0);
        let after = queue_get_dto(&*d, &write)?;
        assert_eq!(
            (after.opened, after.candidate_rev),
            (before.opened, before.candidate_rev)
        );
        assert!(!after.opened);
        assert_eq!(h.status(&write).await.status, Status::Pending);

        // A stale revision is refused as such, also without a record of approval.
        let stale = CandidateRev {
            counter: rev.counter,
            candidate_hash: [9; 32],
        };
        let r = decide_dto(&*d, decide_args(&write, "approve", stale, json!({}))?);
        assert!(
            matches!(r, Err(CommandError::Decision(DecisionError::Stale { .. }))),
            "{r:?}"
        );
        assert_eq!(count(&h, EventType::WRITE_APPROVED).await?, 0);

        // An unknown request is not decidable.
        let r = decide_dto(
            &*d,
            decide_args(
                "req_aaaaaaaaaaaaaaaaaaaaaa",
                "deny",
                rev,
                json!({"reason": "x"}),
            )?,
        );
        assert_eq!(r, Err(CommandError::Decision(DecisionError::NotDecidable)));
        Ok(())
    }

    /// U-32 through the commands: a positive decision is accepted only on a revision whose preview
    /// the same command layer delivered, and every positive record is preceded by a
    /// `PREVIEW_SHOWN` of the same revision. What the approver is shown is what is sent: the
    /// request the preview lists is the request the instance receives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn u32_ui_path_preview_shown_before_decide() -> TestResult {
        let h = rig(vec![]).await?;
        let d = h.decisions();
        let read = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
        let write = queued(&h, COMMENT, comment()).await?;

        let mut shown_requests = Vec::new();
        for (id, kind, positive) in [
            (&read, "release", EventType::READ_RELEASED),
            (&write, "approve", EventType::WRITE_APPROVED),
        ] {
            let rev = queue_get_dto(&*d, id)?.candidate_rev;
            // Negative control: without the preview the same decision is refused.
            let refused = decide_dto(&*d, decide_args(id, kind, rev, json!({}))?);
            assert!(
                matches!(
                    refused,
                    Err(CommandError::Decision(DecisionError::Invalid(
                        InvalidReason::NotOpened
                    )))
                ),
                "{refused:?}"
            );
            assert_eq!(
                count(&h, positive).await?,
                0,
                "{kind} recorded without a preview"
            );

            let fetched = preview_fetch_dto(&*d, id, Some(rev))?;
            assert_eq!(fetched.preview.candidate_rev, rev);
            assert!(
                fetched.srcdoc.contains("<html")
                    || fetched.srcdoc.contains("<!DOCTYPE")
                    || !fetched.srcdoc.is_empty()
            );
            if let PreviewBody::WriteSummary { requests, .. }
            | PreviewBody::WriteRequests { requests } = &fetched.preview.body
            {
                shown_requests = requests.clone();
            }
            let out = decide_dto(&*d, decide_args(id, kind, rev, json!({}))?)?;
            assert_eq!(&out.request_id, id);
        }
        let env = h.await_(&write, 15_000).await;
        assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
        let env = h.await_(&read, 15_000).await;
        assert_eq!(env.status, Status::Released, "{}", env.to_json_line());

        // Audit property: each positive decision has a PREVIEW_SHOWN of the same revision before it.
        for (id, positive) in [
            (&read, EventType::READ_RELEASED),
            (&write, EventType::WRITE_APPROVED),
        ] {
            let events = h.events(id).await?;
            let at = events
                .iter()
                .position(|(t, _)| *t == positive)
                .ok_or("no positive record")?;
            let rev = events[at].1["candidate_rev"].clone();
            assert!(
                events[..at]
                    .iter()
                    .any(|(t, p)| *t == EventType::PREVIEW_SHOWN && p["candidate_rev"] == rev),
                "{id}: no PREVIEW_SHOWN of {rev} before {positive:?}"
            );
        }

        // What was shown is what was sent.
        let mock = h.mock("jira-main").ok_or("no jira mock")?;
        let sent: Vec<_> = mock
            .received()
            .await
            .into_iter()
            .filter(|r| r.method.as_str() == "POST")
            .collect();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            shown_requests.len(),
            1,
            "the write preview lists its request"
        );
        let shown = &shown_requests[0];
        assert_eq!(shown.method, "POST");
        assert!(
            shown
                .resolved_url
                .ends_with("/rest/api/2/issue/ABC-1/comment"),
            "{}",
            shown.resolved_url
        );
        assert_eq!(
            sent[0].url.path(),
            mock.path("/rest/api/2/issue/ABC-1/comment")
        );
        let atlas_duck_preview::BodyView::Text(text) = &shown.body else {
            return Err("the shown request body is not text".into());
        };
        assert_eq!(
            serde_json::from_str::<Value>(text)?,
            serde_json::from_slice::<Value>(&sent[0].body)?
        );
        Ok(())
    }

    /// I-38 through the command layer: "Release status only" is three commands, as the UI sends
    /// them: `release_redacted` with the preset opens a new revision, which is shown
    /// (`preview_fetch`) and released with the same ops; the agent gets `failed`, exit 6,
    /// `upstream_http {status}` and `redacted: true`, and not the server's messages.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn i38_release_status_only_through_command() -> TestResult {
        let h = rig(vec![]).await?;
        h.mock("jira-main")
            .ok_or("no jira mock")?
            .json(
                "/rest/api/2/issue/NOPE-1",
                404,
                r#"{"errorMessages":["Issue does not exist"],"errors":{}}"#,
            )
            .await;
        let d = h.decisions();
        let id = queued(&h, ISSUE, json!({ "key": "NOPE-1" })).await?;
        let ops = json!({"redactions": [{"preset": "status_only"}]});

        let rev1 = queue_get_dto(&*d, &id)?.candidate_rev;
        let shown = preview_fetch_dto(&*d, &id, Some(rev1))?;
        assert!(matches!(
            shown.preview.body,
            PreviewBody::UpstreamError { status: 404, .. }
        ));

        // The ops make a new revision; it is not a release.
        let pending = decide_dto(
            &*d,
            decide_args(&id, "release_redacted", rev1, ops.clone())?,
        )?;
        assert_eq!(pending.status, Status::Pending);
        let rev2 = queue_get_dto(&*d, &id)?.candidate_rev;
        assert_ne!(rev1, rev2);
        // It is released only once it was shown.
        let unopened = decide_dto(
            &*d,
            decide_args(&id, "release_redacted", rev2, ops.clone())?,
        );
        assert!(
            matches!(
                unopened,
                Err(CommandError::Decision(DecisionError::Invalid(
                    InvalidReason::NotOpened
                )))
            ),
            "{unopened:?}"
        );
        preview_fetch_dto(&*d, &id, Some(rev2))?;
        let out = decide_dto(&*d, decide_args(&id, "release_redacted", rev2, ops)?)?;
        assert_eq!(out.status, Status::Failed);

        let env = h.await_(&id, 5_000).await;
        assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
        assert_eq!(exit_code(&env), 6);
        assert_eq!(
            env.error.as_ref().map(|e| e.code),
            Some(ErrorCode::UpstreamHttp)
        );
        let details = env
            .error
            .as_ref()
            .and_then(|e| e.details.clone())
            .ok_or("no details")?;
        assert_eq!(Value::Object(details), json!({ "status": 404 }));
        assert!(env.redacted);
        assert!(!env.to_json_line().contains("Issue does not exist"));
        Ok(())
    }

    /// `redaction_preview` reports what the ops do and logs nothing; an unopened revision is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn redaction_preview_is_ui_only() -> TestResult {
        let h = rig(vec![]).await?;
        let d = h.decisions();
        let id = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
        let rev = queue_get_dto(&*d, &id)?.candidate_rev;
        let args = |ops: Value| {
            parse::<atlas_duck_app_lib::commands::approvals::RedactionPreviewArgs>(&json!({
                "request_id": id, "candidate_rev": rev_wire(rev), "ops": ops
            }))
            .map_err(|e| format!("{e:?}"))
        };
        let mask = json!([{"mask_text": {"text": "Login page", "every_occurrence": true}}]);
        let unopened = redaction_preview_dto(&*d, &args(mask.clone())?);
        assert!(
            matches!(
                unopened,
                Err(CommandError::Decision(DecisionError::Invalid(
                    InvalidReason::NotOpened
                )))
            ),
            "{unopened:?}"
        );
        preview_fetch_dto(&*d, &id, Some(rev))?;
        let events_before = h.events(&id).await?.len();
        let report = redaction_preview_dto(&*d, &args(mask)?)?;
        assert!(report.blocked.is_empty(), "{report:?}");
        assert!(report.released_bytes > 0);
        // Nothing logged, the revision is unchanged.
        assert_eq!(h.events(&id).await?.len(), events_before);
        assert_eq!(queue_get_dto(&*d, &id)?.candidate_rev, rev);
        Ok(())
    }

    /// PD-86: a session is denied by its opaque id; an id no queued item carries is `not_found`
    /// and denies nothing, also a well-formed forged one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn deny_session_by_session_id() -> TestResult {
        let h = rig(vec![]).await?;
        let d = h.decisions();
        let a = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
        let b = queued(&h, ISSUE, json!({ "key": "ABC-2" })).await?;
        let session = queue_get_dto(&*d, &a)?.session_id;
        assert_eq!(queue_get_dto(&*d, &b)?.session_id, session, "one session");
        let reason = parse_reason("not now")?;

        let unknown: SessionId = serde_json::from_value(json!("0".repeat(64)))?;
        assert_eq!(
            deny_session_dto(&*d, &unknown, &reason),
            Err(CommandError::NotFound)
        );
        assert_eq!(d.queue_list().len(), 2, "nothing was denied");

        let known: SessionId = serde_json::from_value(json!(session))?;
        assert_eq!(
            deny_session_dto(&*d, &known, &reason),
            Ok(DenyCount { denied: 2 })
        );
        assert!(d.queue_list().is_empty());
        for id in [&a, &b] {
            let env = h.await_(id, 5_000).await;
            assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
        }
        // The id is gone with the items.
        assert_eq!(
            deny_session_dto(&*d, &known, &reason),
            Err(CommandError::NotFound)
        );
        Ok(())
    }

    fn parse_reason(s: &str) -> Result<Reason, Boxed> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct R {
            reason: Reason,
        }
        let r: R = serde_json::from_value(json!({ "reason": s }))?;
        Ok(r.reason)
    }

    /// `deny_batch` is per item without a dialog.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn deny_batch_denies_each_listed_item() -> TestResult {
        let h = rig(vec![]).await?;
        let d = h.decisions();
        let a = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
        let b = queued(&h, ISSUE, json!({ "key": "ABC-2" })).await?;
        let ids: RequestIds = serde_json::from_value(json!([a]))?;
        assert_eq!(
            deny_batch_dto(&*d, &ids, &parse_reason("")?),
            Ok(DenyCount { denied: 1 })
        );
        assert_eq!(h.await_(&a, 5_000).await.status, Status::Denied);
        assert_eq!(h.status(&b).await.status, Status::Pending);
        assert_eq!(h.confirmer().texts().len(), 0, "no dialog for a deny");
        Ok(())
    }

    /// L43, U-32: a batch whose native confirmation is cancelled decides nothing: no record of
    /// the batch or of any item, nothing sent, every item still pending and unopened-state intact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn decide_batch_cancel_changes_nothing() -> TestResult {
        let h = rig(vec![Confirm::Cancel]).await?;
        let d = h.decisions();
        let read = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
        let write = queued(&h, COMMENT, comment()).await?;
        let mut items = Vec::new();
        for id in [&read, &write] {
            let rev = queue_get_dto(&*d, id)?.candidate_rev;
            preview_fetch_dto(&*d, id, Some(rev))?;
            items.push(json!({"request_id": id, "candidate_rev": rev_wire(rev)}));
        }
        let batch: BatchItems = {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct B {
                items: BatchItems,
            }
            serde_json::from_value::<B>(json!({ "items": items }))?.items
        };
        let events_before = h.events_of(EventType::BATCH_CONFIRMED).await?.len();
        let res = decide_batch_dto(&*d, batch);
        assert_eq!(res, Err(CommandError::Decision(DecisionError::Cancelled)));
        assert_eq!(h.confirmer().texts().len(), 1, "the dialog was shown once");
        assert_eq!(count(&h, EventType::BATCH_CONFIRMED).await?, events_before);
        assert_eq!(count(&h, EventType::READ_RELEASED).await?, 0);
        assert_eq!(count(&h, EventType::WRITE_APPROVED).await?, 0);
        assert_eq!(sent_writes(&h).await?, 0);
        for id in [&read, &write] {
            assert_eq!(h.status(id).await.status, Status::Pending);
            assert!(
                queue_get_dto(&*d, id)?.opened,
                "the opened state is untouched"
            );
        }
        Ok(())
    }
}

#[cfg(feature = "scripted-approver")]
mod raw_pages {
    use atlas_duck_app_lib::commands::CommandError;
    use atlas_duck_app_lib::commands::approvals::raw_page_dto;
    use atlas_duck_atlassian::testing::fixtures;
    use atlas_duck_core::payloads::{InvalidReason, body_json, sha256_hex};
    use atlas_duck_core::testing::Harness;
    use atlas_duck_core::{CandidateRev, DecisionError};
    use atlas_duck_preview::RAW_PAGE_BYTES;
    use atlas_duck_preview::render::raw::{incomplete_tail, raw_display_last};
    use base64::Engine;
    use serde_json::{Value, json};

    use super::TestResult;

    const ISSUE: &str = "jira.issue.get";

    fn b64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        base64::engine::general_purpose::STANDARD.decode(s)
    }

    /// Submits a read of `body`, waits for the queue and opens it; its id and revision.
    async fn opened(
        h: &Harness,
        body: &str,
    ) -> Result<(String, CandidateRev), Box<dyn std::error::Error>> {
        h.mock("jira-main")
            .ok_or("no jira mock")?
            .json("/rest/api/2/issue/ABC-1", 200, body)
            .await;
        let env = h.submit(ISSUE, json!({ "key": "ABC-1" })).await;
        let id = env.request_id.clone().ok_or("no request id")?;
        h.queued(&id, 120_000).await.ok_or("never queued")?;
        let preview = h
            .approver()
            .open(&id)
            .map_err(|e| format!("{e:?}"))?
            .preview;
        Ok((id, preview.candidate_rev))
    }

    /// X-07: the Raw pages' bytes, concatenated, are the bytes the agent receives as `result`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn x07_raw_pages_concat_equal_released_bytes() -> TestResult {
        let h = Harness::jira().await?;
        // Two pages and a bit; multi-byte text so a page boundary can cut a character. No space,
        // tab, CR, ZWJ or VS: those are marked page-locally, so the concatenated pages would not
        // have to equal the display of the whole candidate.
        let summary = "日本語😀résumé".repeat(25_000);
        let body = json!({ "key": "ABC-1", "fields": { "summary": summary } }).to_string();
        let (id, rev) = opened(&h, &body).await?;
        let decisions = h.decisions();

        let first = raw_page_dto(&*decisions, &id, rev, 0)?;
        assert!(first.page_count >= 3, "{}", first.page_count);
        let mut bytes = Vec::new();
        let mut shown = String::new();
        let mut cut_boundaries = 0;
        for page in 0..first.page_count {
            let p = raw_page_dto(&*decisions, &id, rev, page)?;
            assert_eq!(
                (p.page, p.page_count, p.total_bytes),
                (page, first.page_count, first.total_bytes)
            );
            let page_bytes = b64(&p.bytes_b64)?;
            if page + 1 < first.page_count && !incomplete_tail(&page_bytes).is_empty() {
                cut_boundaries += 1;
            }
            bytes.extend(page_bytes);
            shown.push_str(&p.display);
        }
        assert_eq!(bytes.len() as u64, first.total_bytes);
        // The test proves something only if a boundary really cuts a character.
        assert!(
            cut_boundaries >= 1,
            "no page boundary cuts a multi-byte character"
        );
        // The pages' display, concatenated, is the display of the whole candidate: a carry that
        // is dropped, or the wrong last-page function, shows as `⟨0x..⟩` bytes.
        assert_eq!(shown, raw_display_last(&bytes, &[]).text);
        assert!(!shown.contains("⟨0x"), "no byte is shown as invalid");

        decisions
            .decide(atlas_duck_core::Decision {
                request_id: id.clone(),
                decision: atlas_duck_core::DecisionKind::Release,
                candidate_rev: rev,
                edits: None,
                redactions: None,
                reason: None,
                deny_details: None,
            })
            .map_err(|e| format!("{e:?}"))?;
        let env = h.await_(&id, 15_000).await;
        let data: Value = env.data.clone().ok_or("no data")?;
        let released = serde_json::to_vec(&data["result"])?;
        assert_eq!(bytes, released);
        // READ_RELEASED records the same bytes it released.
        let events = h.events(&id).await?;
        let recorded: Vec<&Value> = events
            .iter()
            .filter(|(t, _)| *t == atlas_duck_audit::EventType::READ_RELEASED)
            .map(|(_, p)| p)
            .collect();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0]["released_sha256"], json!(sha256_hex(&bytes)));
        assert_eq!(recorded[0]["released"], body_json(&bytes));
        Ok(())
    }

    /// P-02 (Rust half): a candidate just under 16 MiB pages into 64 pages, the last shorter; the
    /// counts are over the full candidate; a page past the last is an invalid argument.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn p02_16mib_raw_paging_counts() -> TestResult {
        let h = Harness::jira().await?;
        let summary = "m".repeat(16 * 1024 * 1024 - 4096);
        let body = json!({ "key": "ABC-1", "fields": { "summary": summary } }).to_string();
        let (id, rev) = opened(&h, &body).await?;
        let decisions = h.decisions();

        let header = decisions
            .preview_fetch(&id, Some(rev))
            .map_err(|e| format!("{e:?}"))?
            .preview
            .raw;
        assert_eq!(header.page_count, 64);
        let mut sum = 0u64;
        let mut last_len = 0u64;
        for page in 0..64 {
            let p = raw_page_dto(&*decisions, &id, rev, page)?;
            assert_eq!(
                (p.page, p.page_count, p.total_bytes),
                (page, 64, header.total_bytes)
            );
            let len = b64(&p.bytes_b64)?.len() as u64;
            sum += len;
            last_len = len;
            if page < 63 {
                assert_eq!(len, RAW_PAGE_BYTES, "page {page}");
            }
        }
        assert_eq!(sum, header.total_bytes);
        assert!(
            last_len < RAW_PAGE_BYTES,
            "the last page is shorter: {last_len}"
        );
        assert!(header.total_bytes > 16 * 1024 * 1024 - 4096);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn raw_page_out_of_range_is_invalid_argument() -> TestResult {
        let h = Harness::jira().await?;
        let (id, rev) = opened(&h, fixtures::JIRA_ISSUE).await?;
        let decisions = h.decisions();
        let only = raw_page_dto(&*decisions, &id, rev, 0)?;
        assert_eq!(only.page_count, 1);
        for page in [1, 2, u64::MAX] {
            assert_eq!(
                raw_page_dto(&*decisions, &id, rev, page),
                Err(CommandError::InvalidArgument { field: "page" }),
                "{page}"
            );
        }
        // The refusals of core pass through: a stale revision, an unknown request.
        let stale = CandidateRev {
            counter: rev.counter,
            candidate_hash: [1; 32],
        };
        assert!(matches!(
            raw_page_dto(&*decisions, &id, stale, 0),
            Err(CommandError::Decision(DecisionError::Stale { .. }))
        ));
        assert!(matches!(
            raw_page_dto(&*decisions, "req_0123456789abcdefghij", rev, 0),
            Err(CommandError::Decision(DecisionError::NotDecidable))
        ));
        // An unopened revision shows nothing.
        let (id2, rev2) = {
            let env = h.submit(ISSUE, json!({ "key": "ABC-1" })).await;
            let id2 = env.request_id.clone().ok_or("no request id")?;
            let item = h.queued(&id2, 10_000).await.ok_or("never queued")?;
            (id2, item.candidate_rev)
        };
        assert!(matches!(
            raw_page_dto(&*decisions, &id2, rev2, 0),
            Err(CommandError::Decision(DecisionError::Invalid(
                InvalidReason::NotOpened
            )))
        ));
        Ok(())
    }
}
