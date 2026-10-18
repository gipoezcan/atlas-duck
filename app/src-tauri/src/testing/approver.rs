//! PD-03: the headless approver of the test build. It reads the queue through the real
//! `DecisionApi` (C.7: "the scripted approver calls this") on every `QueueChanged` the UI sink
//! tees to it and every 50 ms, and acts on items whose reason starts with `atlas-test:`, once per
//! `(request_id, candidate_rev)`. The directive names fit the 60-character reason excerpt.
//! `DecisionApi` is synchronous: every tick runs on a blocking thread.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use atlas_duck_core::testing::ScriptedApprover;
use atlas_duck_core::{
    CandidateRev, Core, DecisionApi, DecisionError, DenyDetails, DropScope, QueueItem, RedactionOp,
    UiEvent, UiSink,
};
use tauri::{AppHandle, Manager};
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::control::QUEUE_FILE;
use super::keystore::{create_private_dir, write_atomic};
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    /// A read or a script (both are release-gated): open + release.
    Release,
    /// A read with an upstream error: §5.2 step 6 "Release status only".
    ReleaseStatusOnly,
    /// PD-129 (a): a read: open, drop the field at `path` (`DropField`, per item), open the
    /// redacted revision and release it. `atlas-test:release-redacted fields.description`.
    ReleaseRedacted { path: String },
    /// PD-129 (a): the expiry path (`Core::expire_now`) of a pending item of any class.
    Expire,
    /// Open + deny with [`DENY_REASON`].
    Deny,
    /// Open + deny with `DenyDetails::UpstreamHttp { include_messages: true }` where the item
    /// has the data for it, else a plain deny.
    DenyDetails,
    /// A write: open + approve (a script item is released, never approved).
    Approve,
    /// A write with missing required fields (PD-49): open, fill every pre-added `fields.<id>`
    /// input with its first allowed value (else `"x"`), submit the edit, open the new revision
    /// and approve it.
    EditPreadded,
    /// Open + deny with [`DENY_REASON`] and the hint the hold has the data for (no candidates,
    /// allowed values or messages), else a plain deny.
    DenyHint,
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
    let mut words = rest.split(char::is_whitespace);
    match words.next().unwrap_or_default() {
        "release" => Directive::Release,
        // The path is the next word; without one the directive is a plain hold.
        "release-redacted" => match words.find(|w| !w.is_empty()) {
            Some(path) => Directive::ReleaseRedacted {
                path: path.to_owned(),
            },
            None => Directive::Hold,
        },
        "expire" => Directive::Expire,
        "release-status-only" => Directive::ReleaseStatusOnly,
        "deny" => Directive::Deny,
        "deny-details" => Directive::DenyDetails,
        "approve" => Directive::Approve,
        "edit-preadded" => Directive::EditPreadded,
        "deny-hint" => Directive::DenyHint,
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

/// What the approver acts through while a `Core` serves.
#[derive(Clone)]
pub struct Served {
    pub decisions: Arc<dyn DecisionApi>,
    /// PD-129 (a): the expiry path of a request now (`Core::expire_now`); `false` if it did not
    /// end. Called on the blocking tick thread, so it may `block_on` an async call.
    pub expire: Arc<dyn Fn(&str) -> bool + Send + Sync>,
}

impl Served {
    /// The approver's view of `core`. Call it inside the runtime: the expiry path runs on that
    /// runtime's handle.
    pub fn of_core(core: Arc<Core>) -> Served {
        let decisions = core.decisions();
        let handle = Handle::current();
        Served {
            decisions,
            expire: Arc::new(move |id| handle.block_on(core.expire_now(id))),
        }
    }
}

/// Where the approver finds what it acts through; `None` while no `Core` serves.
pub type DecisionSource = Arc<dyn Fn() -> Option<Served> + Send + Sync>;

/// The approver task.
pub struct ScriptedApp;

impl ScriptedApp {
    /// The approver over one core, woken by `wake`.
    pub fn spawn(core: Arc<Core>, wake: Arc<Wake>) -> JoinHandle<()> {
        ScriptedApp::spawn_with(Arc::new(move || Some(Served::of_core(core.clone()))), wake)
    }

    /// The approver of the app: the core is the one the managed `ServeSlot` serves, whenever
    /// it serves one (at start or after a keychain retry).
    ///
    /// The queue is mirrored to `<control_dir>/queue.json` (the items waiting for a decision:
    /// request id, class, approvable), so a flow can wait for "this run ended and waits on its
    /// release item" instead of sleeping: only an ended run is in the queue.
    pub fn spawn_for_app(app: AppHandle, control_dir: PathBuf) {
        let source: DecisionSource = Arc::new(move || {
            let slot = app.try_state::<ServeSlot>()?;
            let core = slot.get()?.core.get()?.clone();
            Some(Served::of_core(core))
        });
        tauri::async_runtime::spawn(run(source, app_wake(), Some(control_dir)));
    }

    /// The seam both use: ticks on `wake` and every [`TICK`].
    pub fn spawn_with(source: DecisionSource, wake: Arc<Wake>) -> JoinHandle<()> {
        tokio::spawn(run(source, wake, None))
    }
}

/// What the approver remembers per request: the revision it acted on (or gave up), and the one
/// that keeps failing with its count; and the text of the queue mirror it last wrote.
#[derive(Default)]
struct Memory {
    acted: HashMap<String, CandidateRev>,
    failures: HashMap<String, (CandidateRev, u32)>,
    mirrored: Option<String>,
}

impl Memory {
    /// Writes the queue mirror when the queue changed since the last successful write. A failed
    /// write (the control dir is not there yet, a reader holds the file on Windows) is tried
    /// again on the next tick; it never fails the tick.
    fn mirror(&mut self, dir: &Path, items: &[QueueItem]) {
        let rows: Vec<serde_json::Value> = items
            .iter()
            .map(|i| {
                serde_json::json!({
                    "request_id": i.request_id,
                    "class": i.class,
                    "approvable": i.approvable,
                })
            })
            .collect();
        let Ok(text) = serde_json::to_string(&rows) else {
            return;
        };
        if self.mirrored.as_deref() == Some(text.as_str()) {
            return;
        }
        if create_private_dir(dir).is_ok() && write_atomic(dir, QUEUE_FILE, text.as_bytes()).is_ok()
        {
            self.mirrored = Some(text);
        }
    }

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

async fn run(source: DecisionSource, wake: Arc<Wake>, mirror: Option<PathBuf>) {
    let mut memory = Memory::default();
    loop {
        tokio::select! {
            () = wake.notify.notified() => {}
            () = tokio::time::sleep(TICK) => {}
        }
        let Some(served) = source() else { continue };
        let dir = mirror.clone();
        let ticked = tokio::task::spawn_blocking(move || {
            tick(&served, &mut memory, dir.as_deref());
            memory
        })
        .await;
        // A panic in a tick loses what was acted on; acting twice on a revision is refused by
        // the core (it is no longer decidable), so start over.
        memory = ticked.unwrap_or_default();
    }
}

/// One pass over the queue.
fn tick(served: &Served, memory: &mut Memory, mirror: Option<&Path>) {
    let items = served.decisions.queue_list();
    memory.keep_only(&items);
    if let Some(dir) = mirror {
        memory.mirror(dir, &items);
    }
    let approver = ScriptedApprover::new(served.decisions.clone());
    for item in &items {
        let d = directive(item.reason_excerpt.as_deref());
        let (id, rev) = (item.request_id.as_str(), item.candidate_rev);
        if !fits(&d, item) || !memory.due(id, rev) {
            continue;
        }
        match act(&approver, served.expire.as_ref(), &d, item) {
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
fn fits(d: &Directive, item: &QueueItem) -> bool {
    fits_class(d, item.class, item.approvable)
}

/// [`fits`] over the two fields it reads. A script item is release-gated like a read (core's
/// `decide` answers an approve for a script `NotDecidable`), so `Release` fits it; the
/// status-only preset is a read-outcome card and does not.
fn fits_class(d: &Directive, class: &str, approvable: bool) -> bool {
    match d {
        Directive::Hold => false,
        // Any class: an item in the queue is pending, a decided one is not in it.
        Directive::Expire => true,
        Directive::ReleaseRedacted { .. } => class == "read" && approvable,
        Directive::Release => matches!(class, "read" | "script") && approvable,
        Directive::ReleaseStatusOnly => class == "read" && approvable,
        Directive::Approve | Directive::EditPreadded => class == "write" && approvable,
        Directive::Deny | Directive::DenyDetails | Directive::DenyHint => true,
    }
}

fn act(
    approver: &ScriptedApprover,
    expire: &(dyn Fn(&str) -> bool + Send + Sync),
    d: &Directive,
    item: &QueueItem,
) -> Result<(), DecisionError> {
    let id = item.request_id.as_str();
    match d {
        Directive::ReleaseRedacted { path } => {
            let op = RedactionOp::DropField {
                path: path.clone(),
                scope: DropScope::PerItem,
            };
            approver.release_redacted(id, vec![op]).map(drop)
        }
        // A request whose phase cannot expire yet is retried on the next tick.
        Directive::Expire if expire(id) => Ok(()),
        Directive::Expire => Err(DecisionError::NotDecidable),
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
        Directive::EditPreadded => {
            // The edit makes a new revision; one with nothing left to fill is approved. An
            // approve that cannot happen yet (enrichment runs again) is retried on the next tick.
            if approver.edit_all_preadded(id)? {
                approver.approve(id).map(drop)
            } else {
                approver.approve_unopened(id).map(drop)
            }
        }
        Directive::DenyHint => deny_with_hint(approver, id),
        Directive::Hold => Ok(()),
    }
}

/// A deny with the first hint the hold accepts, each without its optional lists; a plain deny
/// when none applies. A refused hint logs nothing itself; each try opens the revision first,
/// so the open is repeated per refused hint.
fn deny_with_hint(approver: &ScriptedApprover, id: &str) -> Result<(), DecisionError> {
    let hints = [
        DenyDetails::ResolutionFailed {
            include_candidates: false,
        },
        DenyDetails::MissingFields {
            include_allowed_values: false,
        },
        DenyDetails::OutcomeHint,
        DenyDetails::UpstreamHttp {
            include_messages: false,
        },
    ];
    for details in hints {
        match approver.deny_with(id, DENY_REASON, details) {
            Err(DecisionError::EditRejected(_)) => {}
            other => return other.map(drop),
        }
    }
    approver.deny_unopened(id, DENY_REASON).map(drop)
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
        let redacted = |path: &str| Directive::ReleaseRedacted { path: path.into() };
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
            (Some("atlas-test:edit-preadded"), Directive::EditPreadded),
            (Some("atlas-test:deny-hint"), Directive::DenyHint),
            (Some("atlas-test:deny-hint please"), Directive::DenyHint),
            (Some("atlas-test:edit-preadded2"), Directive::Hold),
            (Some("atlas-test:approve\nsecond line"), Directive::Approve),
            (Some("atlas-test:hold"), Directive::Hold),
            (Some("atlas-test:expire"), Directive::Expire),
            (Some("atlas-test:expire now"), Directive::Expire),
            (Some("atlas-test:expire2"), Directive::Hold),
            (
                Some("atlas-test:release-redacted fields.description"),
                redacted("fields.description"),
            ),
            (
                Some("atlas-test:release-redacted   fields.description trailing"),
                redacted("fields.description"),
            ),
            // No path: a plain hold.
            (Some("atlas-test:release-redacted"), Directive::Hold),
            (Some("atlas-test:release-redacted "), Directive::Hold),
            (Some("atlas-test:release-redactedx a"), Directive::Hold),
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
            assert_eq!(&directive(*reason), want, "{reason:?}");
        }
        // Every directive fits the 60-character excerpt.
        for name in [
            "release",
            "release-status-only",
            "deny",
            "deny-details",
            "approve",
            "edit-preadded",
            "deny-hint",
            "hold",
            "expire",
        ] {
            assert!(DIRECTIVE_PREFIX.len() + name.len() <= 60, "{name}");
        }
        // The path directive too, with the longest path the flows use.
        let reason = "atlas-test:release-redacted fields.description";
        assert!(reason.len() <= 60, "{reason}");
    }

    /// M8 T26: a release decides a read or a script, an approve a write only (core refuses an
    /// approve of a script), a hold nothing, and a deny anything.
    #[test]
    fn directives_fit_the_classes_core_can_decide() {
        let table: &[(Directive, &str, bool)] = &[
            (Directive::Release, "read", true),
            (Directive::Release, "script", true),
            (Directive::Release, "write", false),
            (Directive::ReleaseStatusOnly, "read", true),
            (Directive::ReleaseStatusOnly, "script", false),
            (Directive::Approve, "write", true),
            (Directive::Approve, "script", false),
            (Directive::Approve, "read", false),
            (Directive::EditPreadded, "write", true),
            (Directive::EditPreadded, "script", false),
            (Directive::Hold, "read", false),
            (Directive::Hold, "script", false),
            (Directive::Deny, "script", true),
            (Directive::DenyDetails, "read", true),
            (Directive::DenyHint, "write", true),
        ];
        for (d, class, want) in table {
            assert_eq!(fits_class(d, class, true), *want, "{d:?} on {class}");
        }
        // Not approvable yet: a release or an approve waits; a deny does not.
        assert!(!fits_class(&Directive::Release, "script", false));
        assert!(!fits_class(&Directive::Approve, "write", false));
        assert!(fits_class(&Directive::Deny, "script", false));
    }

    /// PD-129 (a): an expire fits every class while the item is pending (a decided item is not in
    /// the queue the approver reads; `expire_directive_expires_pending_read` pins that).
    #[test]
    fn expire_fits_pending_items_of_every_class() {
        for class in ["read", "write", "script"] {
            for approvable in [true, false] {
                assert!(fits_class(&Directive::Expire, class, approvable), "{class}");
            }
        }
        // A redacted release is a read-only directive and waits for an approvable item.
        let redacted = Directive::ReleaseRedacted { path: "a".into() };
        assert!(fits_class(&redacted, "read", true));
        assert!(!fits_class(&redacted, "read", false));
        assert!(!fits_class(&redacted, "write", true));
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
        let app = ScriptedApp::spawn_with(
            Arc::new(move || {
                Some(Served {
                    decisions: decisions.clone(),
                    expire: Arc::new(|_| false),
                })
            }),
            wake,
        );

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

        // An upstream-error read: "Release status only" (§5.2 step 6) ends it `failed` with the
        // status alone.
        mock.json(
            "/rest/api/2/issue/ERR-1",
            404,
            r#"{"errorMessages":["Issue does not exist"],"errors":{}}"#,
        )
        .await;
        let status_only = submit(
            &h,
            "jira.issue.get",
            json!({ "key": "ERR-1" }),
            "atlas-test:release-status-only",
        )
        .await?;
        let env = h.await_(&status_only, 15_000).await;
        assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
        assert!(env.redacted);
        assert!(!env.to_json_line().contains("Issue does not exist"));
        // A write held on an upstream error (its enrichment GET answered 404): the deny carries
        // the hint with the messages.
        mock.json(
            "/rest/api/2/issue/ERR-1/transitions",
            404,
            r#"{"errorMessages":["Issue does not exist"],"errors":{}}"#,
        )
        .await;
        let held_write = submit(
            &h,
            "jira.issue.transition",
            json!({ "key": "ERR-1", "transition": "Done" }),
            "atlas-test:deny-details",
        )
        .await?;
        let env = h.await_(&held_write, 15_000).await;
        assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
        let error = env.error.as_ref().ok_or("no error")?;
        assert_eq!(serde_json::to_value(error.code)?, json!("upstream_http"));
        let details = error.details.clone().ok_or("no details")?;
        assert_eq!(details.get("status"), Some(&json!(404)));
        assert_eq!(
            details.get("error_messages"),
            Some(&json!("Issue does not exist"))
        );

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
        // T21 review m-4: a deny never hits an invalid state either.
        let denied_events = h.events(&denied).await?;
        let denied_details_events = h.events(&denied_details).await?;
        let held_write_events = h.events(&held_write).await?;
        for events in [
            &read_events,
            &write_events,
            &held_events,
            &denied_events,
            &denied_details_events,
            &held_write_events,
        ] {
            assert_eq!(count(events, EventType::DECISION_INVALID), 0);
        }
        app.abort();
        Ok(())
    }

    /// The approver over a started harness, with the expiry path of its core.
    fn approver_over(h: &Arc<Harness>) -> JoinHandle<()> {
        let h = h.clone();
        ScriptedApp::spawn_with(
            Arc::new(move || {
                let core = h.clone();
                let handle = Handle::current();
                Some(Served {
                    decisions: h.decisions(),
                    expire: Arc::new(move |id| handle.block_on(core.expire_now(id))),
                })
            }),
            Arc::new(Wake::default()),
        )
    }

    /// PD-129 (a): `atlas-test:expire` runs the expiry path of a pending read: it ends `expired`
    /// with an `EXPIRED` record and leaves the queue. Every wait is bounded, so a regression
    /// fails by assertion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn expire_directive_expires_pending_read() -> TestResult {
        let h = Arc::new(Harness::jira().await?);
        let mock = h.mock("jira-main").ok_or("no jira mock")?;
        mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
            .await;
        let app = approver_over(&h);
        let held = submit(
            &h,
            "jira.issue.get",
            json!({ "key": "ABC-1" }),
            "atlas-test:hold",
        )
        .await?;
        let id = submit(
            &h,
            "jira.issue.get",
            json!({ "key": "ABC-1" }),
            "atlas-test:expire",
        )
        .await?;
        let env = h.await_(&id, 15_000).await;
        assert_eq!(env.status, Status::Expired, "{}", env.to_json_line());
        assert!(
            h.event_types(&id)
                .await?
                .contains(&atlas_duck_audit::EventType::EXPIRED)
        );
        assert!(
            h.approver().item(&id).is_none(),
            "an expired item left the queue"
        );
        // A held request is untouched.
        assert_eq!(h.status(&held).await.status, Status::Pending);
        app.abort();
        Ok(())
    }

    /// PD-129 (a): `atlas-test:release-redacted <path>` drops the field at the path and releases
    /// the redacted revision.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn release_redacted_directive_redacts() -> TestResult {
        let h = Arc::new(Harness::jira().await?);
        let mock = h.mock("jira-main").ok_or("no jira mock")?;
        mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
            .await;
        let app = approver_over(&h);
        let id = submit(
            &h,
            "jira.issue.get",
            json!({ "key": "ABC-1" }),
            "atlas-test:release-redacted fields.description",
        )
        .await?;
        let env = h.await_(&id, 15_000).await;
        assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
        assert!(env.redacted, "{}", env.to_json_line());
        let text = env.to_json_line();
        assert!(
            !text.contains("Steps to reproduce"),
            "description survived: {text}"
        );
        assert!(
            text.contains("Login page times out"),
            "only the path is dropped: {text}"
        );
        let value = serde_json::to_value(&env)?;
        let dropped = value["meta"]["redactions"]["fields_dropped"]
            .as_array()
            .ok_or_else(|| format!("no fields_dropped: {text}"))?;
        assert!(!dropped.is_empty(), "{text}");
        app.abort();
        Ok(())
    }

    /// A missing path is a plain hold: the item stays pending and unopened.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn release_redacted_without_a_path_holds() -> TestResult {
        let h = Arc::new(Harness::jira().await?);
        let mock = h.mock("jira-main").ok_or("no jira mock")?;
        mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
            .await;
        let app = approver_over(&h);
        let id = submit(
            &h,
            "jira.issue.get",
            json!({ "key": "ABC-1" }),
            "atlas-test:release-redacted",
        )
        .await?;
        h.queued(&id, 10_000).await.ok_or("never queued")?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(h.status(&id).await.status, Status::Pending);
        let item = h.approver().item(&id).ok_or("item left the queue")?;
        assert!(!item.opened);
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
