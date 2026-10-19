//! The `UiSink` over Tauri events (C.10). Payloads carry ids and counts only, never an agent
//! string, a param or a fetched value (§5.6, §10.1). No window listens before M6; an event
//! nobody listens to is harmless.

use std::sync::Arc;

use atlas_duck_core::{AttentionKind, UiEvent, UiSink};
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Runtime};

/// The seam between the sink and Tauri: tests record instead of emitting.
pub trait EventOut: Send + Sync {
    fn emit(&self, name: &str, payload: Value);
}

impl<R: Runtime> EventOut for AppHandle<R> {
    fn emit(&self, name: &str, payload: Value) {
        // S-16 (test build only): every payload the webviews could receive is recorded.
        #[cfg(feature = "scripted-approver")]
        crate::commands::capture::event(self, name, &payload);
        // A failed emit (no webview, app closing) must not disturb the core.
        let _ = Emitter::emit(self, name, payload);
    }
}

/// The event the Approvals page starts its inert periods on (PD-75).
pub const EVENT_WINDOW_FOCUS: &str = "window_focus";

/// The payload of `window_focus`: exactly `{requested: bool}`; the page treats anything else as an
/// unrequested focus.
pub fn window_focus_payload(requested: bool) -> Value {
    json!({ "requested": requested })
}

/// Tells window `label` (and no other: never a broadcast) that it is about to get the focus, and
/// whether the user asked for it (`requested`: a relaunch, the tray, the header, the user's own
/// click) or the attention engine did ("show and focus"). Recorded like every payload a webview
/// can receive (S-16).
pub fn emit_window_focus<R: Runtime>(app: &AppHandle<R>, label: &str, requested: bool) {
    let payload = window_focus_payload(requested);
    #[cfg(feature = "scripted-approver")]
    crate::commands::capture::event(app, EVENT_WINDOW_FOCUS, &payload);
    // A failed emit (no webview yet, app closing) must not disturb the caller.
    let _ = Emitter::emit_to(app, label, EVENT_WINDOW_FOCUS, payload);
}

/// The event the Settings window (and the wizard's instance step) re-read on (Δ1, M6 T25): a
/// setting, an instance or a token changed. App-owned, not a core event; no payload.
pub const EVENT_SETTINGS_CHANGED: &str = "settings_changed";

/// Tells every listening window that settings or instances changed (no payload: the windows read
/// `settings_get` again). Recorded like every payload a webview can receive (S-16).
pub fn emit_settings_changed<R: Runtime>(app: &AppHandle<R>) {
    EventOut::emit(app, EVENT_SETTINGS_CHANGED, Value::Null);
}

/// The event the setup page re-reads `wizard_state` on (Δ1, M6 T23): a step ended, the serving
/// state changed, a request was refused (the header's count), the credential window went. App-owned,
/// not a core event; no payload.
pub const EVENT_WIZARD_CHANGED: &str = "wizard_changed";

/// Tells every listening window that the wizard's state changed (no payload). Recorded like every
/// payload a webview can receive (S-16).
pub fn emit_wizard_changed<R: Runtime>(app: &AppHandle<R>) {
    EventOut::emit(app, EVENT_WIZARD_CHANGED, Value::Null);
}

/// The event of an Audit-window job (Δ-M10-3, PD-181): `{job, phase, done?, total?}`. App-owned,
/// not a core event; counts only.
pub const EVENT_AUDIT_JOB: &str = "audit_job";
/// The event the Audit window re-reads its status and list on (Δ-M10-3): the window appended a
/// record (an acknowledgement, an export, a backup). No payload.
pub const EVENT_AUDIT_CHANGED: &str = "audit_changed";

/// `audit_job`'s `job` (`export|backup`; `restore` is Task 13's).
pub fn audit_job_name(kind: crate::serve::AuditJobKind) -> &'static str {
    match kind {
        crate::serve::AuditJobKind::Export => "export",
        crate::serve::AuditJobKind::Backup => "backup",
    }
}

/// The payload of `audit_job`: `phase` is `started|progress|done|failed|cancelled`; `done` and
/// `total` (row counts) only with `progress`.
pub fn audit_job_payload(
    kind: crate::serve::AuditJobKind,
    phase: &'static str,
    rows: Option<(u64, u64)>,
) -> Value {
    let mut v = json!({ "job": audit_job_name(kind), "phase": phase });
    if let (Some((done, total)), Some(m)) = (rows, v.as_object_mut()) {
        m.insert("done".into(), json!(done));
        m.insert("total".into(), json!(total));
    }
    v
}

/// Tells every listening window how an Audit-window job goes (recorded like every payload, S-16).
pub fn emit_audit_job(
    out: &dyn EventOut,
    kind: crate::serve::AuditJobKind,
    phase: &'static str,
    rows: Option<(u64, u64)>,
) {
    out.emit(EVENT_AUDIT_JOB, audit_job_payload(kind, phase, rows));
}

/// Tells every listening window that the Audit window appended a record (no payload).
pub fn emit_audit_changed(out: &dyn EventOut) {
    out.emit(EVENT_AUDIT_CHANGED, Value::Null);
}

/// Tells every listening window that a status line may have changed (`status_banner`, no line
/// named): the header reads `app_status` again. For the lines the app derives itself
/// (`scripts_degraded` when the probe report lands or the degraded setting flips,
/// `updated_restart` when the glue finds the sandbox binary replaced); core's own lines go through
/// its `UiSink`.
pub fn emit_status_changed(out: &dyn EventOut) {
    let (name, payload) = wire(&UiEvent::StatusBanner {
        line_ids: Vec::new(),
    });
    out.emit(name, payload);
}

/// The C.10 event name and payload of a core event.
pub fn wire(e: &UiEvent) -> (&'static str, Value) {
    match e {
        UiEvent::QueueChanged { request_ids } => {
            ("queue_changed", json!({ "request_ids": request_ids }))
        }
        UiEvent::Attention { kind, count } => (
            "attention",
            json!({ "kind": attention_kind(*kind), "count": count }),
        ),
        UiEvent::StatusBanner { line_ids } => ("status_banner", json!({ "line_ids": line_ids })),
        UiEvent::NeedsAttentionChanged { count } => {
            ("needs_attention_changed", json!({ "count": count }))
        }
        UiEvent::RunningScriptsChanged => ("running_scripts_changed", Value::Null),
        UiEvent::CredentialContextChanged => ("credential_context_changed", Value::Null),
    }
}

fn attention_kind(k: AttentionKind) -> &'static str {
    match k {
        AttentionKind::New => "new",
        AttentionKind::Stale => "stale",
        AttentionKind::Failed => "failed",
        AttentionKind::OutcomeUnknown => "outcome_unknown",
    }
}

/// Emits every core event as a Tauri event and forwards it to `tee` (the scripted approver of
/// the test build, Task 21).
pub struct TauriUiSink {
    out: Arc<dyn EventOut>,
    tee: Option<Arc<dyn UiSink>>,
    /// The attention engine's feed (Task 19): it only queues the event, never blocks the core.
    attention: Option<Arc<dyn UiSink>>,
    /// The locked-mode raise gate (Task 22): a refused request is `credential_context_changed`.
    raise: Option<Arc<dyn UiSink>>,
}

impl TauriUiSink {
    pub fn new<R: Runtime>(app: AppHandle<R>, tee: Option<Arc<dyn UiSink>>) -> TauriUiSink {
        TauriUiSink::with_out(Arc::new(app), tee)
    }

    pub fn with_out(out: Arc<dyn EventOut>, tee: Option<Arc<dyn UiSink>>) -> TauriUiSink {
        TauriUiSink {
            out,
            tee,
            attention: None,
            raise: None,
        }
    }

    /// Also forwards every event to the attention engine's feed.
    pub fn with_attention(mut self, feed: Arc<dyn UiSink>) -> TauriUiSink {
        self.attention = Some(feed);
        self
    }

    /// Also forwards every event to the locked-mode raise gate (it reacts to
    /// `CredentialContextChanged` only and never blocks).
    pub fn with_raise(mut self, gate: Arc<dyn UiSink>) -> TauriUiSink {
        self.raise = Some(gate);
        self
    }
}

impl UiSink for TauriUiSink {
    fn emit(&self, e: UiEvent) {
        let (name, payload) = wire(&e);
        self.out.emit(name, payload);
        if let Some(feed) = &self.attention {
            feed.emit(e.clone());
        }
        if let Some(gate) = &self.raise {
            gate.emit(e.clone());
        }
        if let Some(tee) = &self.tee {
            tee.emit(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(String, Value)>>);

    impl EventOut for Recorder {
        fn emit(&self, name: &str, payload: Value) {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((name.to_owned(), payload));
        }
    }

    #[derive(Default)]
    struct Tee(Mutex<Vec<UiEvent>>);

    impl UiSink for Tee {
        fn emit(&self, e: UiEvent) {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).push(e);
        }
    }

    fn all_events() -> Vec<UiEvent> {
        let mut v = vec![
            UiEvent::QueueChanged {
                request_ids: vec!["req_1".into(), "req_2".into()],
            },
            UiEvent::StatusBanner {
                line_ids: vec!["check_target".into()],
            },
            UiEvent::NeedsAttentionChanged { count: 3 },
            UiEvent::RunningScriptsChanged,
            UiEvent::CredentialContextChanged,
        ];
        for kind in [
            AttentionKind::New,
            AttentionKind::Stale,
            AttentionKind::Failed,
            AttentionKind::OutcomeUnknown,
        ] {
            v.push(UiEvent::Attention { kind, count: 2 });
        }
        v
    }

    /// The app's own status lines ask the header to re-read through the event it already
    /// listens to, with no line named and nothing else in the payload.
    #[test]
    fn status_changed_is_the_status_banner_event_without_a_line() {
        let out = Recorder::default();
        emit_status_changed(&out);
        let got = out.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            got,
            vec![("status_banner".to_owned(), json!({ "line_ids": [] }))]
        );
    }

    #[test]
    fn events_named_per_c10() {
        let out = Arc::new(Recorder::default());
        let tee = Arc::new(Tee::default());
        let sink = TauriUiSink::with_out(out.clone(), Some(tee.clone()));
        for e in all_events() {
            sink.emit(e);
        }
        let got = out.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "queue_changed",
                "status_banner",
                "needs_attention_changed",
                "running_scripts_changed",
                "credential_context_changed",
                "attention",
                "attention",
                "attention",
                "attention",
            ]
        );
        assert_eq!(
            got[0].1,
            json!({ "request_ids": ["req_1", "req_2"] }),
            "queue_changed payload"
        );
        assert_eq!(got[1].1, json!({ "line_ids": ["check_target"] }));
        assert_eq!(got[2].1, json!({ "count": 3 }));
        assert_eq!(got[3].1, Value::Null);
        assert_eq!(got[4].1, Value::Null);
        let kinds: Vec<&str> = got[5..]
            .iter()
            .filter_map(|(_, p)| p["kind"].as_str())
            .collect();
        assert_eq!(kinds, ["new", "stale", "failed", "outcome_unknown"]);
        assert!(got[5..].iter().all(|(_, p)| p["count"] == 2));
        // Ids and counts only: every payload key is one of C.10's.
        for (_, p) in &got {
            if let Some(map) = p.as_object() {
                assert!(
                    map.keys()
                        .all(|k| ["request_ids", "kind", "count", "line_ids"].contains(&k.as_str()))
                );
            }
        }
        // The tee saw every event, in order.
        let teed = tee.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(teed, all_events());
    }

    #[test]
    fn the_attention_feed_sees_every_event_in_order_and_the_tee_still_does() {
        let out = Arc::new(Recorder::default());
        let tee = Arc::new(Tee::default());
        let feed = Arc::new(Tee::default());
        let sink =
            TauriUiSink::with_out(out.clone(), Some(tee.clone())).with_attention(feed.clone());
        for e in all_events() {
            sink.emit(e);
        }
        assert_eq!(
            *feed.0.lock().unwrap_or_else(|e| e.into_inner()),
            all_events()
        );
        assert_eq!(
            *tee.0.lock().unwrap_or_else(|e| e.into_inner()),
            all_events()
        );
        assert_eq!(out.0.lock().unwrap_or_else(|e| e.into_inner()).len(), 9);
    }

    /// Δ-M10-3: `audit_job` carries the job, the phase and, for `progress` only, row counts;
    /// `audit_changed` carries nothing. Ids and counts only.
    #[test]
    fn audit_events_carry_counts_only() {
        use crate::serve::AuditJobKind;
        let out = Recorder::default();
        emit_audit_job(&out, AuditJobKind::Export, "started", None);
        emit_audit_job(&out, AuditJobKind::Export, "progress", Some((10, 40)));
        emit_audit_job(&out, AuditJobKind::Backup, "done", None);
        emit_audit_changed(&out);
        let got = out.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            got,
            vec![
                (
                    "audit_job".to_owned(),
                    json!({"job": "export", "phase": "started"})
                ),
                (
                    "audit_job".to_owned(),
                    json!({"job": "export", "phase": "progress", "done": 10, "total": 40})
                ),
                (
                    "audit_job".to_owned(),
                    json!({"job": "backup", "phase": "done"})
                ),
                ("audit_changed".to_owned(), Value::Null),
            ]
        );
    }

    #[test]
    fn window_focus_payload_is_exactly_requested() {
        assert_eq!(window_focus_payload(true), json!({ "requested": true }));
        assert_eq!(window_focus_payload(false), json!({ "requested": false }));
    }
}
