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
