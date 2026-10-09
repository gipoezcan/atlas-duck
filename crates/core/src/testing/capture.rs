//! The capture hook (PD-12, S-16 core half): every `Envelope` the `RequestHandler` returns, every
//! `ProgressNotification`, every `UiEvent` and every value `DecisionApi` / `InstanceAdmin` return
//! is recorded as the JSON the outside world would get, so canary sweeps can search one place.
//! M6 wraps its Tauri command layer around the same recorder.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use atlas_duck_ipc::envelope::Envelope;
use atlas_duck_ipc::proto::{
    AwaitParams, ConnectionMeta, Hello, HelloReply, ListState, MatchParams, ProgressNotification,
    ProgressSink, RequestHandler, SubmitParams,
};
use atlas_duck_preview::CandidateRev;
use serde::Serialize;

use crate::decision::{
    BatchItem, BatchOutcome, Decision, DecisionApi, DecisionError, DecisionOutcome,
    PreviewDelivery, QueueItem, RawPage, SessionKey,
};
use crate::gate::{UiEvent, UiSink};
use crate::instances::{AddInstance, AdminError, ConnectionReport, InstanceAdmin, InstanceView};
use crate::proxy::ProxySetting;

/// Which boundary a record crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Channel {
    Envelope,
    Progress,
    UiEvent,
    Decision,
    Instance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    pub channel: Channel,
    pub json: String,
}

#[derive(Debug, Default)]
pub struct Capture {
    records: Mutex<Vec<Captured>>,
}

impl Capture {
    pub fn new() -> Arc<Capture> {
        Arc::new(Capture::default())
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Captured>> {
        self.records.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records `value` as compact JSON (a value that does not serialize is recorded as `""`,
    /// which a sweep then sees as an empty record rather than missing it).
    pub fn record<T: Serialize + ?Sized>(&self, channel: Channel, value: &T) {
        let json = serde_json::to_string(value).unwrap_or_default();
        self.lock().push(Captured { channel, json });
    }

    pub fn records(&self) -> Vec<Captured> {
        self.lock().clone()
    }

    pub fn on(&self, channel: Channel) -> Vec<Captured> {
        self.lock()
            .iter()
            .filter(|c| c.channel == channel)
            .cloned()
            .collect()
    }
}

/// The `RequestHandler` the harness hands out.
pub struct CapturingHandler {
    inner: Arc<dyn RequestHandler>,
    cap: Arc<Capture>,
}

impl CapturingHandler {
    pub fn wrap(inner: Arc<dyn RequestHandler>, cap: Arc<Capture>) -> Arc<CapturingHandler> {
        Arc::new(CapturingHandler { inner, cap })
    }

    fn env(&self, e: Envelope) -> Envelope {
        self.cap.record(Channel::Envelope, &e);
        e
    }
}

/// Records every notification before passing it on.
struct CapturingSink<'a> {
    inner: &'a dyn ProgressSink,
    cap: &'a Capture,
}

impl ProgressSink for CapturingSink<'_> {
    fn progress(&self, n: ProgressNotification) {
        self.cap.record(Channel::Progress, &n);
        self.inner.progress(n);
    }
}

#[async_trait::async_trait]
impl RequestHandler for CapturingHandler {
    async fn hello(&self, conn: &ConnectionMeta, h: Hello) -> Result<HelloReply, Envelope> {
        let r = self.inner.hello(conn, h).await;
        if let Err(e) = &r {
            self.cap.record(Channel::Envelope, e);
        }
        r
    }
    async fn ops_list(&self, instance: Option<&str>) -> Envelope {
        self.env(self.inner.ops_list(instance).await)
    }
    async fn ops_describe(&self, op_id: &str, instance: Option<&str>) -> Envelope {
        self.env(self.inner.ops_describe(op_id, instance).await)
    }
    async fn instances_list(&self) -> Envelope {
        self.env(self.inner.instances_list().await)
    }
    async fn submit(&self, conn: &ConnectionMeta, p: SubmitParams) -> Envelope {
        self.env(self.inner.submit(conn, p).await)
    }
    async fn submit_script(&self, conn: &ConnectionMeta, p: SubmitParams) -> Envelope {
        self.env(self.inner.submit_script(conn, p).await)
    }
    async fn await_request(
        &self,
        conn: &ConnectionMeta,
        a: AwaitParams,
        progress: &dyn ProgressSink,
    ) -> Envelope {
        let sink = CapturingSink {
            inner: progress,
            cap: &self.cap,
        };
        self.env(self.inner.await_request(conn, a, &sink).await)
    }
    async fn status(&self, request_id: &str) -> Envelope {
        self.env(self.inner.status(request_id).await)
    }
    async fn cancel(&self, request_id: &str) -> Envelope {
        self.env(self.inner.cancel(request_id).await)
    }
    async fn requests_list(
        &self,
        agent: Option<&str>,
        state: Option<ListState>,
        match_params: Option<MatchParams>,
    ) -> Envelope {
        self.env(self.inner.requests_list(agent, state, match_params).await)
    }
    async fn doctor(&self) -> Envelope {
        self.env(self.inner.doctor().await)
    }
}

/// The `UiSink` the harness gives the core.
pub struct CapturingUi {
    inner: Arc<dyn UiSink>,
    cap: Arc<Capture>,
}

impl CapturingUi {
    pub fn wrap(inner: Arc<dyn UiSink>, cap: Arc<Capture>) -> Arc<CapturingUi> {
        Arc::new(CapturingUi { inner, cap })
    }
}

impl UiSink for CapturingUi {
    fn emit(&self, e: UiEvent) {
        self.cap.record(Channel::UiEvent, &e);
        self.inner.emit(e);
    }
}

/// A sink that drops everything (the inner end of the harness's `CapturingUi`).
pub struct NullUi;

impl UiSink for NullUi {
    fn emit(&self, _e: UiEvent) {}
}

/// The `DecisionApi` the harness hands out.
pub struct CapturingDecisions {
    inner: Arc<dyn DecisionApi>,
    cap: Arc<Capture>,
}

impl CapturingDecisions {
    pub fn wrap(inner: Arc<dyn DecisionApi>, cap: Arc<Capture>) -> Arc<CapturingDecisions> {
        Arc::new(CapturingDecisions { inner, cap })
    }

    fn rec<T: Serialize>(&self, v: T) -> T {
        self.cap.record(Channel::Decision, &v);
        v
    }
}

impl DecisionApi for CapturingDecisions {
    fn queue_list(&self) -> Vec<QueueItem> {
        self.rec(self.inner.queue_list())
    }
    fn queue_get(&self, request_id: &str) -> Option<QueueItem> {
        self.rec(self.inner.queue_get(request_id))
    }
    fn preview_fetch(
        &self,
        request_id: &str,
        rev: Option<CandidateRev>,
    ) -> Result<PreviewDelivery, DecisionError> {
        self.rec(self.inner.preview_fetch(request_id, rev))
    }
    fn raw_page(
        &self,
        request_id: &str,
        rev: CandidateRev,
        page: u64,
    ) -> Result<RawPage, DecisionError> {
        self.rec(self.inner.raw_page(request_id, rev, page))
    }
    fn decide(&self, d: Decision) -> Result<DecisionOutcome, DecisionError> {
        self.rec(self.inner.decide(d))
    }
    fn decide_batch(&self, items: Vec<BatchItem>) -> Result<BatchOutcome, DecisionError> {
        self.rec(self.inner.decide_batch(items))
    }
    fn deny_batch(&self, request_ids: &[String], reason: &str) -> Result<usize, DecisionError> {
        self.rec(self.inner.deny_batch(request_ids, reason))
    }
    fn deny_session(&self, session: SessionKey, reason: &str) -> Result<usize, DecisionError> {
        self.rec(self.inner.deny_session(session, reason))
    }
    fn acknowledge_attention(&self, request_ids: &[String]) {
        self.inner.acknowledge_attention(request_ids);
    }
}

/// The `InstanceAdmin` the harness hands out.
pub struct CapturingInstances {
    inner: Arc<dyn InstanceAdmin>,
    cap: Arc<Capture>,
}

impl CapturingInstances {
    pub fn wrap(inner: Arc<dyn InstanceAdmin>, cap: Arc<Capture>) -> Arc<CapturingInstances> {
        Arc::new(CapturingInstances { inner, cap })
    }

    fn rec<T: Serialize>(&self, v: T) -> T {
        self.cap.record(Channel::Instance, &v);
        v
    }
}

#[async_trait::async_trait]
impl InstanceAdmin for CapturingInstances {
    fn list(&self) -> Vec<InstanceView> {
        self.rec(self.inner.list())
    }
    fn add(&self, req: AddInstance) -> Result<InstanceView, AdminError> {
        self.rec(self.inner.add(req))
    }
    fn confirm_config_instance(&self, alias: &str) -> Result<InstanceView, AdminError> {
        self.rec(self.inner.confirm_config_instance(alias))
    }
    fn accept_config_url_change(&self, alias: &str) -> Result<InstanceView, AdminError> {
        self.rec(self.inner.accept_config_url_change(alias))
    }
    fn change_base_url(&self, alias: &str, new_url: &str) -> Result<InstanceView, AdminError> {
        self.rec(self.inner.change_base_url(alias, new_url))
    }
    fn set_proxy(&self, alias: &str, proxy: ProxySetting) -> Result<InstanceView, AdminError> {
        self.rec(self.inner.set_proxy(alias, proxy))
    }
    async fn set_token(
        &self,
        alias: &str,
        pat: secrecy::SecretString,
        expires_at: Option<chrono::NaiveDate>,
    ) -> Result<ConnectionReport, AdminError> {
        let r = self.inner.set_token(alias, pat, expires_at).await;
        self.rec(r)
    }
    async fn retest_token(&self, alias: &str) -> Result<ConnectionReport, AdminError> {
        let r = self.inner.retest_token(alias).await;
        self.rec(r)
    }
}
