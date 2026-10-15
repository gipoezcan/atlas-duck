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
        }
    }

    /// Also forwards every event to the attention engine's feed.
    pub fn with_attention(mut self, feed: Arc<dyn UiSink>) -> TauriUiSink {
        self.attention = Some(feed);
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

    #[test]
    fn window_focus_payload_is_exactly_requested() {
        assert_eq!(window_focus_payload(true), json!({ "requested": true }));
        assert_eq!(window_focus_payload(false), json!({ "requested": false }));
    }
}
