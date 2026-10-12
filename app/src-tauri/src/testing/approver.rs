//! PD-03: the headless approver of the test build. It reads the queue through the real
//! `DecisionApi` (C.7: "the scripted approver calls this") on every `QueueChanged` the UI sink
//! tees to it and every 50 ms, and acts on items whose reason starts with `atlas-test:`, once per
//! `(request_id, candidate_rev)`. The directive names fit the 60-character reason excerpt.
//! `DecisionApi` is synchronous: every tick runs on a blocking thread.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use atlas_duck_core::testing::ScriptedApprover;
use atlas_duck_core::{
    CandidateRev, Core, DecisionApi, DecisionError, DenyDetails, QueueItem, UiEvent, UiSink,
};
use tauri::{AppHandle, Manager};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::state::ServeSlot;

/// The reason prefix that carries a directive.
pub const DIRECTIVE_PREFIX: &str = "atlas-test:";
/// The deny reason the approver gives.
pub const DENY_REASON: &str = "denied by test";
/// The fallback tick (PD-03: "and every 50 ms").
pub const TICK: Duration = Duration::from_millis(50);
/// Failed attempts on one revision before the approver gives it up (an error is retried on the
/// next tick; this keeps a refusal that never clears from logging a decision every tick forever).
pub const MAX_ATTEMPTS: u32 = 100;

/// The diag line of a failed action: `reason` is one of the static `kind` names below.
pub const LOG_EVENT_APPROVER_ERROR: &str = "scripted_approver_error";
pub const LOG_EVENT_APPROVER_GAVE_UP: &str = "scripted_approver_gave_up";

/// What a reason asks the approver to do. Anything that is not a known directive is `Hold`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Directive {
    /// A read: open + release.
    Release,
    /// A read with an upstream error: §5.2 step 6 "Release status only".
    ReleaseStatusOnly,
    /// Open + deny with [`DENY_REASON`].
    Deny,
    /// Open + deny with `DenyDetails::UpstreamHttp { include_messages: true }` where the item
    /// has the data for it, else a plain deny.
    DenyDetails,
    /// A write or a script: open + approve.
    Approve,
    /// Nothing (also the default without a directive).
    Hold,
}

/// The directive of a reason excerpt: `atlas-test:<name>`, the name ending at the first
/// whitespace (`atlas-test:deny please` is `Deny`).
pub fn directive(reason_excerpt: Option<&str>) -> Directive {
    let Some(rest) = reason_excerpt.and_then(|r| r.trim_start().strip_prefix(DIRECTIVE_PREFIX))
    else {
        return Directive::Hold;
    };
    match rest.split(char::is_whitespace).next().unwrap_or_default() {
        "release" => Directive::Release,
        "release-status-only" => Directive::ReleaseStatusOnly,
        "deny" => Directive::Deny,
        "deny-details" => Directive::DenyDetails,
        "approve" => Directive::Approve,
        _ => Directive::Hold,
    }
}

/// Wakes the approver on queue changes. The app's UI sink forwards every core event here.
#[derive(Default)]
pub struct Wake {
    notify: Notify,
}

impl UiSink for Wake {
    fn emit(&self, e: UiEvent) {
        if matches!(e, UiEvent::QueueChanged { .. }) {
            self.notify.notify_one();
        }
    }
}

/// The one wake of the app process: `serve::start` tees the UI sink into it and
/// [`ScriptedApp::spawn_for_app`] waits on it.
fn app_wake() -> Arc<Wake> {
    static WAKE: OnceLock<Arc<Wake>> = OnceLock::new();
    WAKE.get_or_init(Arc::default).clone()
}

/// The tee `serve::start` passes to `TauriUiSink`.
pub fn ui_tee() -> Arc<dyn UiSink> {
    app_wake()
}

/// Where the approver finds the decision API; `None` while no `Core` serves.
pub type DecisionSource = Arc<dyn Fn() -> Option<Arc<dyn DecisionApi>> + Send + Sync>;

/// The approver task.
pub struct ScriptedApp;

impl ScriptedApp {
    /// The approver over one core, woken by `wake`.
    pub fn spawn(core: Arc<Core>, wake: Arc<Wake>) -> JoinHandle<()> {
        let decisions = core.decisions();
        ScriptedApp::spawn_with(Arc::new(move || Some(decisions.clone())), wake)
    }

    /// The approver of the app: the core is the one the managed `ServeSlot` serves, whenever
    /// it serves one (at start or after a keychain retry).
    pub fn spawn_for_app(app: AppHandle) {
        let source: DecisionSource = Arc::new(move || {
            let slot = app.try_state::<ServeSlot>()?;
            let core = slot.get()?.core.get()?.clone();
            Some(core.decisions())
        });
        tauri::async_runtime::spawn(run(source, app_wake()));
    }

    /// The seam both use: ticks on `wake` and every [`TICK`].
    pub fn spawn_with(source: DecisionSource, wake: Arc<Wake>) -> JoinHandle<()> {
        tokio::spawn(run(source, wake))
    }
}

/// What the approver remembers per request: the revision it acted on (or gave up), and the one
/// that keeps failing with its count.
#[derive(Default)]
struct Memory {
    acted: HashMap<String, CandidateRev>,
    failures: HashMap<String, (CandidateRev, u32)>,
}

impl Memory {
    /// Requests that left the queue are forgotten (bounded memory).
    fn keep_only(&mut self, items: &[QueueItem]) {
        let queued = |id: &String| items.iter().any(|i| &i.request_id == id);
        self.acted.retain(|id, _| queued(id));
        self.failures.retain(|id, _| queued(id));
    }

    /// False once this revision was acted on (or given up).
    fn due(&self, id: &str, rev: CandidateRev) -> bool {
        self.acted.get(id) != Some(&rev)
    }

    fn succeeded(&mut self, id: &str, rev: CandidateRev) {
        self.failures.remove(id);
        self.acted.insert(id.to_owned(), rev);
    }

    /// Counts a failure on `rev` (a new revision starts at zero). True when this revision is
    /// given up.
    fn failed(&mut self, id: &str, rev: CandidateRev) -> bool {
        let entry = self.failures.entry(id.to_owned()).or_insert((rev, 0));
        if entry.0 != rev {
            *entry = (rev, 0);
        }
        entry.1 += 1;
        if entry.1 < MAX_ATTEMPTS {
            return false;
        }
        self.failures.remove(id);
        self.acted.insert(id.to_owned(), rev);
        true
    }
}

async fn run(source: DecisionSource, wake: Arc<Wake>) {
    let mut memory = Memory::default();
    loop {
        tokio::select! {
            () = wake.notify.notified() => {}
            () = tokio::time::sleep(TICK) => {}
        }
        let Some(api) = source() else { continue };
        let ticked = tokio::task::spawn_blocking(move || {
            tick(api, &mut memory);
            memory
        })
        .await;
        // A panic in a tick loses what was acted on; acting twice on a revision is refused by
        // the core (it is no longer decidable), so start over.
        memory = ticked.unwrap_or_default();
    }
}

/// One pass over the queue.
fn tick(api: Arc<dyn DecisionApi>, memory: &mut Memory) {
    let items = api.queue_list();
    memory.keep_only(&items);
    let approver = ScriptedApprover::new(api);
    for item in &items {
        let d = directive(item.reason_excerpt.as_deref());
        let (id, rev) = (item.request_id.as_str(), item.candidate_rev);
        if !fits(d, item) || !memory.due(id, rev) {
            continue;
        }
        match act(&approver, d, item) {
            Ok(()) => memory.succeeded(id, rev),
            // Retried on the next tick; after `Stale` that tick sees the new revision.
            Err(e) => {
                tracing::warn!(event = LOG_EVENT_APPROVER_ERROR, reason = kind(&e));
                if memory.failed(id, rev) {
                    tracing::warn!(event = LOG_EVENT_APPROVER_GAVE_UP);
                }
            }
        }
    }
}

/// Whether the directive applies to the item now. A release or an approve waits while the item
/// is not approvable (the core would refuse it and log a `DECISION_INVALID` every tick); a
/// directive for another class is a hold.
fn fits(d: Directive, item: &QueueItem) -> bool {
    match d {
        Directive::Hold => false,
        Directive::Release | Directive::ReleaseStatusOnly => {
            item.class == "read" && item.approvable
        }
        Directive::Approve => matches!(item.class, "write" | "script") && item.approvable,
        Directive::Deny | Directive::DenyDetails => true,
    }
}

fn act(approver: &ScriptedApprover, d: Directive, item: &QueueItem) -> Result<(), DecisionError> {
    let id = item.request_id.as_str();
    match d {
        Directive::Release => approver.release(id).map(drop),
        Directive::ReleaseStatusOnly => approver.release_status_only(id).map(drop),
        Directive::Deny => approver.deny(id, DENY_REASON).map(drop),
        Directive::DenyDetails => {
            let details = DenyDetails::UpstreamHttp {
                include_messages: true,
            };
            match approver.deny_with(id, DENY_REASON, details) {
                // The item has no upstream error card: no hint to attach, a plain deny.
                Err(DecisionError::EditRejected(_)) => {
                    approver.deny_unopened(id, DENY_REASON).map(drop)
                }
                other => other.map(drop),
            }
        }
        Directive::Approve => approver.approve(id).map(drop),
        Directive::Hold => Ok(()),
    }
}

/// The static log name of an error (never its text).
fn kind(e: &DecisionError) -> &'static str {
    match e {
        DecisionError::Stale { .. } => "stale",
        DecisionError::Invalid(_) => "invalid",
        DecisionError::EditRejected(_) => "edit_rejected",
        DecisionError::Audit(_) => "audit",
        DecisionError::BatchRejected { .. } => "batch_rejected",
        DecisionError::Cancelled => "cancelled",
        DecisionError::NotDecidable => "not_decidable",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use atlas_duck_atlassian::testing::{TEST_USER, TEST_USER_KEY, XAuser, fixtures};
    use atlas_duck_core::testing::Harness;
    use atlas_duck_ipc::envelope::{Envelope, Status};
    use atlas_duck_ipc::proto::SubmitParams;
    use serde_json::{Value, json};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn directive_parsing_table() {
        let table: &[(Option<&str>, Directive)] = &[
            (Some("atlas-test:release"), Directive::Release),
            (
                Some("atlas-test:release-status-only"),
                Directive::ReleaseStatusOnly,
            ),
            (Some("atlas-test:deny"), Directive::Deny),
            (Some("atlas-test:deny please"), Directive::Deny),
            (Some("atlas-test:deny-details"), Directive::DenyDetails),
            (Some("atlas-test:approve"), Directive::Approve),
            (Some("atlas-test:approve\nsecond line"), Directive::Approve),
            (Some("atlas-test:hold"), Directive::Hold),
            (Some("  atlas-test:release"), Directive::Release),
            // Unknown directive, no prefix, no reason: hold.
            (Some("atlas-test:launch-missiles"), Directive::Hold),
            (Some("atlas-test:releasex"), Directive::Hold),
            (Some("atlas-test:"), Directive::Hold),
            (Some("atlas-test: release"), Directive::Hold),
            (Some("ATLAS-TEST:release"), Directive::Hold),
            (Some("release"), Directive::Hold),
            (Some("please atlas-test:release"), Directive::Hold),
            (Some(""), Directive::Hold),
            (None, Directive::Hold),
        ];
        for (reason, want) in table {
            assert_eq!(directive(*reason), *want, "{reason:?}");
        }
        // Every directive fits the 60-character excerpt.
        for name in [
            "release",
            "release-status-only",
            "deny",
            "deny-details",
            "approve",
            "hold",
        ] {
            assert!(DIRECTIVE_PREFIX.len() + name.len() <= 60, "{name}");
        }
    }

    #[test]
    fn only_queue_changes_wake_the_approver() {
        let wake = Wake::default();
        wake.emit(UiEvent::NeedsAttentionChanged { count: 1 });
        assert!(
            futures_now(wake.notify.notified()).is_none(),
            "no permit stored"
        );
        wake.emit(UiEvent::QueueChanged {
            request_ids: vec!["req_1".into()],
        });
        assert!(futures_now(wake.notify.notified()).is_some());
    }

    /// Polls `f` once without a runtime.
    fn futures_now<F: std::future::Future>(f: F) -> Option<F::Output> {
        let mut f = std::pin::pin!(f);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        match f.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => Some(v),
            std::task::Poll::Pending => None,
        }
    }

    fn request_id(env: &Envelope) -> Result<String, Box<dyn std::error::Error>> {
        env.request_id.clone().ok_or_else(|| {
            format!(
                "no request id: {}",
                serde_json::to_string(env).unwrap_or_default()
            )
            .into()
        })
    }

    async fn submit(
        h: &Harness,
        op_id: &str,
        params: Value,
        reason: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let reply = h
            .handler()
            .submit(
                h.default_conn(),
                SubmitParams {
                    op_id: op_id.to_owned(),
                    params,
                    instance: None,
                    reason: Some(reason.to_owned()),
                },
            )
            .await;
        request_id(&reply.envelope)
    }

    /// Waits until `request_id` reached a terminal status.
    async fn final_status(h: &Harness, request_id: &str) -> Status {
        h.await_(request_id, 15_000).await.status
    }

    /// PD-03 over the core harness: the approver's decisions go through the real
    /// `DecisionApi`, once per revision.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn approver_acts_once_per_revision() -> TestResult {
        let h = Harness::jira().await?;
        let mock = h.mock("jira-main").ok_or("no jira mock")?;
        mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
            .await;
        mock.json(
            "/rest/api/2/issue/ABC-1/comment",
            201,
            fixtures::JIRA_COMMENT,
        )
        .await;
        // The write's stale check before it executes.
        mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
            .await;
        mock.jira_server_info("9.12.0").await;
        let wake = Arc::new(Wake::default());
        let decisions = h.decisions();
        let app = ScriptedApp::spawn_with(Arc::new(move || Some(decisions.clone())), wake);

        // A held read first: it must stay pending while the others are decided.
        let held = submit(
            &h,
            "jira.issue.get",
            json!({ "key": "ABC-1" }),
            "atlas-test:hold",
        )
        .await?;
        let plain = submit(
            &h,
            "jira.issue.get",
            json!({ "key": "ABC-1" }),
            "just looking",
        )
        .await?;
        let read = submit(
            &h,
            "jira.issue.get",
            json!({ "key": "ABC-1" }),
            "atlas-test:release",
        )
        .await?;
        let write = submit(
            &h,
            "jira.comment.add",
            json!({ "key": "ABC-1", "body": "Seen on staging.", "body_format": "wiki" }),
            "atlas-test:approve",
        )
        .await?;
        let denied = submit(
            &h,
            "jira.issue.get",
            json!({ "key": "ABC-1" }),
            "atlas-test:deny please",
        )
        .await?;

        // No upstream error card to attach: a plain deny.
        let denied_details = submit(
            &h,
            "jira.issue.get",
            json!({ "key": "ABC-1" }),
            "atlas-test:deny-details",
        )
        .await?;

        assert_eq!(final_status(&h, &read).await, Status::Released);
        assert_eq!(final_status(&h, &denied_details).await, Status::Denied);
        assert_eq!(final_status(&h, &write).await, Status::Succeeded);
        assert_eq!(final_status(&h, &denied).await, Status::Denied);

        // Held for a second: still pending, still in the queue, never opened.
        let since = Instant::now();
        h.queued(&held, 10_000)
            .await
            .ok_or("held item never queued")?;
        tokio::time::sleep(Duration::from_secs(1).saturating_sub(since.elapsed())).await;
        for id in [&held, &plain] {
            assert_eq!(h.status(id).await.status, Status::Pending, "{id}");
            let item = h.approver().item(id).ok_or("held item left the queue")?;
            assert!(!item.opened, "a held item is never opened");
        }

        // Once per revision: exactly one positive decision record per acted request.
        use atlas_duck_audit::EventType;
        let count = |events: &[(EventType, Value)], t: EventType| {
            events.iter().filter(|(e, _)| *e == t).count()
        };
        let read_events = h.events(&read).await?;
        assert_eq!(count(&read_events, EventType::READ_RELEASED), 1);
        assert_eq!(count(&read_events, EventType::PREVIEW_SHOWN), 1);
        let write_events = h.events(&write).await?;
        assert_eq!(count(&write_events, EventType::WRITE_APPROVED), 1);
        let held_events = h.events(&held).await?;
        assert_eq!(count(&held_events, EventType::PREVIEW_SHOWN), 0);
        for events in [&read_events, &write_events, &held_events] {
            assert_eq!(count(events, EventType::DECISION_INVALID), 0);
        }
        app.abort();
        Ok(())
    }

    fn rev(counter: u64) -> CandidateRev {
        CandidateRev {
            counter,
            candidate_hash: [7; 32],
        }
    }

    /// An error is retried on the next tick; a revision that keeps failing is given up after
    /// [`MAX_ATTEMPTS`]; a new revision (`Stale`) is due again at once.
    #[test]
    fn failures_are_retried_then_given_up_per_revision() {
        let mut m = Memory::default();
        assert!(m.due("req_1", rev(1)));
        for _ in 1..MAX_ATTEMPTS {
            assert!(!m.failed("req_1", rev(1)));
            assert!(m.due("req_1", rev(1)), "retried on the next tick");
        }
        assert!(m.failed("req_1", rev(1)), "given up");
        assert!(!m.due("req_1", rev(1)));
        // A new revision is acted on again, its failures counted from zero.
        assert!(m.due("req_1", rev(2)));
        assert!(!m.failed("req_1", rev(2)));
        m.succeeded("req_1", rev(2));
        assert!(!m.due("req_1", rev(2)), "once per revision");
        assert!(m.due("req_1", rev(3)));
        // Failures on one revision do not carry over to the next.
        let mut m = Memory::default();
        for _ in 1..MAX_ATTEMPTS {
            assert!(!m.failed("req_2", rev(1)));
        }
        assert!(!m.failed("req_2", rev(2)));
        assert!(m.due("req_2", rev(2)));
        // Requests that left the queue are forgotten.
        m.succeeded("req_3", rev(1));
        m.keep_only(&[]);
        assert!(m.acted.is_empty() && m.failures.is_empty());
    }
}
