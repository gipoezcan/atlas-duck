//! The core's `RequestHandler` (C.2, C.7): what `IpcServer` serves once a store is open.
//!
//! `submit` (§5.2 step 1 / §5.4 step 1): shutdown check, hello session, op lookup, routing
//! (PD-01…PD-03), admission (Task 20), `params_sha256` (PD-27), `REQUEST_RECEIVED` through
//! `commit_request_received` (§5.1 inv. 1), static validation and the dry executor call (PD-09),
//! then the pending envelope. Everything refused before `REQUEST_RECEIVED` is answered with
//! `request_id: null` and logs nothing. Dispatch to the read/write/script flows is Tasks
//! 21/22/27.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use atlas_duck_audit::{EventHeader, EventType, QueryKind, is_terminal};
use atlas_duck_ipc::envelope::{Envelope, ErrorCode};
use atlas_duck_ipc::proto::{
    AwaitParams, ConnectionMeta, Hello, HelloReply, ListState, MatchParams, ProgressNotification,
    ProgressSink, RequestHandler, RequestRow, SubmitParams, params_sha256, params_sha256_hex,
};
use atlas_duck_ipc::sandbox::ScriptLimits;
use atlas_duck_registry::{
    DescribeEnv, LimitsSource, OperationSpec, Product, TargetDisplay, Version, describe,
    target_display,
};
use serde_json::{Map, Value, json};

use super::envelope::{self, OpenStatus};
use super::{
    Engine, NewEntry, RequestEntry, RequestHead, Session, TerminalError, TransitionError,
    audit_failure_retryable, class_str, kind_of, payload_json,
};
use crate::audit_port::commit_request_received;
use crate::config::instances::product_str;
use crate::gate::{GateState, hello_check, ops_describe_local, ops_list_local};
use crate::ids::RequestId;
use crate::instances::{InstanceRuntime, InstanceState, RouteError};
use crate::lifecycle::model::{Event, Model, Rejection, step};
use crate::normalize::{normalize_agent_name, normalize_hello, normalize_reason};
use crate::ops::{ExecCtx, ExecError, NOT_IN_THIS_BUILD_MESSAGE, op_table};
use crate::payloads::{self, EventCtx};
use crate::validate::{EffectiveCaps, ValidateCtx, ValidationError, validate};

/// §4.1: the CLI's default wait, used when an `await` names none.
pub const DEFAULT_AWAIT_MS: u64 = 100_000;
/// How much of a normalized `reason` a queue row shows (plan decision).
const REASON_EXCERPT_CHARS: usize = 120;
/// `requests list` looks back this far (§4.4).
const RECENT_WINDOW: Duration = Duration::from_secs(24 * 3600);

pub struct CoreHandler {
    engine: Arc<Engine>,
}

impl CoreHandler {
    pub fn new(engine: Arc<Engine>) -> CoreHandler {
        CoreHandler { engine }
    }
}

/// What routing chose: the instance's id, alias and base URL (PD-01…PD-03 passed).
struct Routed {
    id: String,
    alias: String,
    base: atlas_duck_atlassian::NormalizedBaseUrl,
    version: Option<Version>,
}

fn route_refusal(e: RouteError, product: Product, alias: Option<&str>) -> Envelope {
    match e {
        RouteError::ConfigUnreadable => {
            envelope::not_configured(crate::config::REASON_CONFIG_UNREADABLE)
        }
        RouteError::UnknownAlias | RouteError::WrongProduct => {
            envelope::unknown_instance(alias.unwrap_or_default())
        }
        RouteError::NoInstance => envelope::no_instance(product),
    }
}

/// PD-03: refusals by instance state, before `REQUEST_RECEIVED`, nothing logged.
fn state_refusal(i: &InstanceRuntime) -> Option<Envelope> {
    match i.state {
        InstanceState::Ok => None,
        InstanceState::InsecureScheme | InstanceState::InstanceUnconfirmed => {
            Some(envelope::not_configured(i.state.as_str()))
        }
        InstanceState::NeedsToken => Some(envelope::needs_token()),
        InstanceState::IdentityHeaderMissing | InstanceState::IdentityHeaderMismatch => {
            Some(envelope::identity_header(i.state.as_str()))
        }
    }
}

/// The plaintext `target` column (§8.2): a query never appears in clear, only its keyed tag
/// (L38); other ops show their `target_display` key.
fn target_column(
    port: &dyn crate::audit_port::AuditPort,
    spec: &OperationSpec,
    params: &Value,
) -> Option<String> {
    match spec.target_display {
        TargetDisplay::Query { param } => {
            let kind = match spec.product {
                Product::Jira => QueryKind::Jql,
                Product::Confluence => QueryKind::Cql,
            };
            params
                .get(param)
                .and_then(Value::as_str)
                .map(|q| port.query_tag(kind, q))
        }
        TargetDisplay::None => None,
        _ => Some(target_display(spec, params)),
    }
}

fn excerpt(s: &str) -> String {
    match s.char_indices().nth(REASON_EXCERPT_CHARS) {
        Some((cut, _)) => format!("{}…", &s[..cut]),
        None => s.to_owned(),
    }
}

/// `min_version` against the cached server version; unknown → available (§2.3).
fn available(spec: &OperationSpec, version: Option<Version>) -> bool {
    match (spec.min_version, version) {
        (Some(min), Some(have)) => have >= min,
        _ => true,
    }
}

fn describe_env(available: bool) -> DescribeEnv {
    DescribeEnv {
        limits_source: LimitsSource::Effective,
        available: Some(available),
        // The configured hard caps are the registry defaults until Settings exist (M6).
        caps: Value::Null,
        script_limits: serde_json::to_value(ScriptLimits::default()).unwrap_or(Value::Null),
    }
}

/// One `requests list` row with the fields the filters need.
struct ListRow {
    row: RequestRow,
    agent_name: Option<String>,
    instance_id: Option<String>,
}

impl CoreHandler {
    fn route(&self, spec: &OperationSpec, alias: Option<&str>) -> Result<Routed, Box<Envelope>> {
        let table = self.engine.instances();
        let inst = table
            .resolve(spec.product, alias)
            .map_err(|e| Box::new(route_refusal(e, spec.product, alias)))?;
        if let Some(refusal) = state_refusal(inst) {
            return Err(Box::new(refusal));
        }
        match (&inst.id, &inst.base) {
            (Some(id), Some(base)) => Ok(Routed {
                id: id.clone(),
                alias: inst.alias.clone(),
                base: base.clone(),
                version: inst.version,
            }),
            // Never `Ok` without both (state.rs); refuse rather than log a partial request.
            _ => Err(Box::new(envelope::not_configured(
                InstanceState::InstanceUnconfirmed.as_str(),
            ))),
        }
    }

    /// Steps 7–8 failure: `REQUEST_REJECTED {code, message, details}` (decision `reject`), then
    /// `failed` with the request id. The id is never cover-ready again.
    async fn reject(&self, new: NewEntry, err: ValidationError) -> Envelope {
        let ev = payloads::request_rejected(
            &new.ctx,
            err.code,
            &err.message,
            &Value::Object(err.details.clone()),
        );
        let head = new.head.clone();
        let kind = kind_of(new.spec);
        let appended = self.engine.blocking(move |p| p.append(ev)).await;
        self.engine.committed().forget_request(&head.request_id);
        match appended {
            Ok(_) => {
                envelope::failed_request(&head, err.code, false, &err.message, Some(err.details))
            }
            Err(_) => {
                // The log knows the request but not its end: keep the failure in memory.
                let retryable = audit_failure_retryable(kind);
                let mut model = new.model.clone();
                let _ = step(&mut model, Event::AuditFailure);
                self.engine.insert(NewEntry {
                    model,
                    unlogged_terminal: Some(TerminalError {
                        code: ErrorCode::AuditFailure,
                        retryable,
                        message: envelope::MSG_AUDIT_FAILURE.to_owned(),
                    }),
                    ..new
                });
                envelope::failed_request(
                    &head,
                    ErrorCode::AuditFailure,
                    retryable,
                    envelope::MSG_AUDIT_FAILURE,
                    None,
                )
            }
        }
    }

    /// The envelope of an in-memory entry: open → pending/executing; an unlogged terminal from
    /// memory; a recorded terminal from the log.
    async fn entry_answer(&self, entry: &Arc<RequestEntry>, reduced: bool) -> Envelope {
        let (status, unlogged) = {
            let st = entry.state();
            (
                crate::lifecycle::model::agent_status(&st.model),
                st.unlogged_terminal.clone(),
            )
        };
        if let Some(open) = OpenStatus::of(status) {
            return envelope::pending_envelope(
                &entry.head.request_id,
                &entry.head.op_id,
                &entry.head.instance,
                open,
            );
        }
        if let Some(e) = unlogged {
            return envelope::unlogged_envelope(&entry.head, status, &e, reduced);
        }
        self.records_answer(&entry.head.request_id, reduced).await
    }

    /// `status`/`await` for an id answered from the committed records.
    async fn records_answer(&self, request_id: &str, reduced: bool) -> Envelope {
        match self.engine.status_from_records(request_id).await {
            Ok(Some(rs)) if reduced => envelope::status_envelope(&rs),
            Ok(Some(rs)) => envelope::await_envelope(&rs),
            Ok(None) => envelope::unknown_request(),
            Err(_) => envelope::audit_unreadable(),
        }
    }

    fn pending_rows(&self) -> Vec<ListRow> {
        self.engine
            .pending_entries()
            .iter()
            .map(|e| {
                let st = e.state();
                ListRow {
                    row: RequestRow {
                        request_id: e.head.request_id.clone(),
                        op_id: e.head.op_id.clone(),
                        instance: Some(e.head.instance.clone()),
                        target_display: e.target_display.clone(),
                        params_sha256: e.params_sha256.clone(),
                        status: crate::lifecycle::model::agent_status(&st.model),
                        submitted_at: e.submitted_at.clone(),
                    },
                    agent_name: e.agent_name.clone(),
                    instance_id: Some(e.instance_id.clone()),
                }
            })
            .collect()
    }

    /// Requests decided within 24 h that memory no longer holds: one `recent_headers` scan (a
    /// full scan of `events`, M2 handoff), then per row only the start record is decrypted (its
    /// payload has `params_sha256` and the params `target_display` comes from). Cheap header
    /// filters run first. Row status comes from the terminal record's type (a released outcome
    /// item reads `released` here; `status` decrypts it, Task 21).
    async fn recent_rows(
        &self,
        skip: HashSet<String>,
        agent: Option<String>,
        matcher: Option<(String, String)>,
    ) -> Result<Vec<ListRow>, atlas_duck_audit::AuditError> {
        let alias_of: HashMap<String, String> = self
            .engine
            .instances()
            .list()
            .iter()
            .filter_map(|i| Some((i.id.clone()?, i.alias.clone())))
            .collect();
        self.engine
            .blocking(move |p| {
                let headers = p.recent_headers(RECENT_WINDOW)?;
                let mut by_request: BTreeMap<String, Vec<&EventHeader>> = BTreeMap::new();
                for h in &headers {
                    if let Some(id) = &h.request_id {
                        by_request.entry(id.clone()).or_default().push(h);
                    }
                }
                let mut rows = Vec::new();
                for (id, hs) in by_request {
                    if skip.contains(&id) {
                        continue;
                    }
                    let Some(terminal) = hs.iter().find(|h| {
                        let flags = if h.event_type == EventType::SCRIPT_FAILED {
                            payload_json(p, h.seq).map(|v| atlas_duck_audit::ScriptFailedFlags {
                                direct: v.get("direct").and_then(Value::as_bool).unwrap_or(false),
                                reason: v
                                    .get("reason")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            })
                        } else {
                            None
                        };
                        is_terminal(h, flags.as_ref())
                    }) else {
                        continue;
                    };
                    // A start record older than the window is fetched by id.
                    let start: EventHeader = match hs.iter().find(|h| {
                        matches!(
                            h.event_type,
                            EventType::REQUEST_RECEIVED | EventType::SCRIPT_STARTED
                        )
                    }) {
                        Some(h) => (*h).clone(),
                        None => match p.headers_for_request(&id)?.into_iter().find(|h| {
                            matches!(
                                h.event_type,
                                EventType::REQUEST_RECEIVED | EventType::SCRIPT_STARTED
                            )
                        }) {
                            Some(h) => h,
                            None => continue,
                        },
                    };
                    if let Some(a) = &agent
                        && start.actor.agent_name.as_ref() != Some(a)
                    {
                        continue;
                    }
                    if let Some((op_id, instance_id)) = &matcher
                        && (start.op_id.as_ref() != Some(op_id)
                            || start.instance_id.as_ref() != Some(instance_id))
                    {
                        continue;
                    }
                    let payload = payload_json(p, start.seq);
                    let params_sha256 = payload
                        .as_ref()
                        .and_then(|v| v.get("params_sha256"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let op_id = start.op_id.clone().unwrap_or_default();
                    let target = match (
                        atlas_duck_registry::get(&op_id),
                        payload.as_ref().and_then(|v| v.get("params")),
                    ) {
                        (Some(spec), Some(params)) => target_display(spec, params),
                        _ => op_id.clone(),
                    };
                    let (status, _) = envelope::record_status(
                        terminal.event_type,
                        None,
                        start.op_class.as_deref(),
                    );
                    rows.push(ListRow {
                        row: RequestRow {
                            request_id: id,
                            op_id,
                            instance: start
                                .instance_id
                                .as_ref()
                                .and_then(|i| alias_of.get(i).cloned()),
                            target_display: target,
                            params_sha256,
                            status,
                            submitted_at: start.ts_utc.clone(),
                        },
                        agent_name: start.actor.agent_name.clone(),
                        instance_id: start.instance_id.clone(),
                    });
                }
                Ok(rows)
            })
            .await
    }

    /// `--match-params-file`: the hash under the same instance resolution as `submit` (§4.4).
    /// `None` = nothing can match (unknown op or alias, no instance, an integer JCS rejects).
    fn match_key(&self, m: &MatchParams) -> Option<(String, String, String)> {
        let spec = atlas_duck_registry::get(&m.op_id)?;
        let table = self.engine.instances();
        let inst = table.resolve(spec.product, m.instance.as_deref()).ok()?;
        let id = inst.id.clone()?;
        let hash = params_sha256_hex(spec.id, Some(&id), &m.params).ok()?;
        Some((spec.id.to_owned(), id, hash))
    }
}

#[async_trait::async_trait]
impl RequestHandler for CoreHandler {
    async fn hello(&self, conn: &ConnectionMeta, h: Hello) -> Result<HelloReply, Envelope> {
        let reply = hello_check(&h)?;
        let normalized = normalize_hello(&h);
        self.engine.remember_session(
            &conn.connection_id,
            Session {
                hello: h,
                normalized,
            },
        );
        Ok(reply)
    }

    async fn ops_list(&self, instance: Option<&str>) -> Envelope {
        let Some(alias) = instance else {
            return ops_list_local();
        };
        let table = self.engine.instances();
        if table.config_unreadable() {
            return envelope::not_configured(crate::config::REASON_CONFIG_UNREADABLE);
        }
        let Some(inst) = table.by_alias(alias) else {
            return envelope::unknown_instance(alias);
        };
        let ops: Vec<Value> = atlas_duck_registry::all()
            .iter()
            .filter(|spec| spec.product == inst.product)
            .map(|spec| {
                let d = describe(spec, &describe_env(available(spec, inst.version)));
                json!({
                    "op_id": d["op_id"],
                    "class": d["class"],
                    "approval": d["approval"],
                    "description": d["description"],
                    "available": d["available"],
                })
            })
            .collect();
        envelope::succeeded(json!({ "ops": ops }))
    }

    async fn ops_describe(&self, op_id: &str, instance: Option<&str>) -> Envelope {
        let Some(alias) = instance else {
            return ops_describe_local(op_id);
        };
        let Some(spec) = atlas_duck_registry::get(op_id) else {
            return envelope::unknown_op(op_id);
        };
        let table = self.engine.instances();
        match table.resolve(spec.product, Some(alias)) {
            Ok(inst) => {
                envelope::succeeded(describe(spec, &describe_env(available(spec, inst.version))))
            }
            Err(e) => route_refusal(e, spec.product, Some(alias)),
        }
    }

    async fn instances_list(&self) -> Envelope {
        let table = self.engine.instances();
        if table.config_unreadable() {
            return envelope::not_configured(crate::config::REASON_CONFIG_UNREADABLE);
        }
        // §3.3: alias, product, is_default, state only; never URLs, usernames or tokens.
        let rows: Vec<atlas_duck_ipc::proto::InstanceRow> = table
            .list()
            .iter()
            .map(|i| atlas_duck_ipc::proto::InstanceRow {
                alias: i.alias.clone(),
                product: product_str(i.product).to_owned(),
                is_default: i.is_default,
                state: i.state.as_str().to_owned(),
            })
            .collect();
        envelope::succeeded(json!({ "instances": rows }))
    }

    async fn submit(&self, conn: &ConnectionMeta, p: SubmitParams) -> Envelope {
        let engine = &self.engine;
        // 1. §2.5 step 1.
        if engine.is_shutting_down() {
            return GateState::ShuttingDown.envelope();
        }
        // 2. The hello of this connection.
        let Some(session) = engine.session(&conn.connection_id) else {
            return envelope::protocol_error();
        };
        // 3. The op (`script.run` is not a registry op: `script.submit` only).
        let Some(spec) = atlas_duck_registry::get(&p.op_id) else {
            return envelope::unknown_op(&p.op_id);
        };
        // 4. Routing (PD-01…PD-03).
        let routed = match self.route(spec, p.instance.as_deref()) {
            Ok(r) => r,
            Err(env) => return *env,
        };
        // 5. Admission: Task 20 (storage-low, pending limits, `max_pending_bytes`).
        // 6. `params_sha256` (PD-27), the id, `REQUEST_RECEIVED` (§5.1 inv. 1).
        let Ok(sha) = params_sha256(spec.id, Some(&routed.id), &p.params) else {
            return envelope::integer_out_of_range();
        };
        let Ok(request_id) = RequestId::new() else {
            return envelope::internal("no request id could be generated");
        };
        let kind = kind_of(spec);
        let ctx = EventCtx {
            request_id: Some(request_id.0.clone()),
            op_id: Some(spec.id.to_owned()),
            op_class: Some(class_str(spec).to_owned()),
            instance_id: Some(routed.id.clone()),
            target: None,
            actor: Default::default(),
        };
        let committed = {
            let (mut ctx, params, hello, conn2, reason, set) = (
                ctx.clone(),
                p.params.clone(),
                session.hello.clone(),
                conn.clone(),
                p.reason.clone(),
                engine.committed().clone(),
            );
            engine
                .blocking(move |port| {
                    ctx.target = target_column(port, spec, &params);
                    let ev = payloads::request_received(
                        &ctx,
                        &params,
                        &sha,
                        &hello,
                        &conn2,
                        reason.as_deref(),
                    );
                    commit_request_received(port, &set, ev).map(|_| ctx)
                })
                .await
        };
        let ctx = match committed {
            Ok(ctx) => ctx,
            Err(_) => return envelope::audit_failure(audit_failure_retryable(kind)),
        };
        let head = RequestHead {
            request_id: request_id.0.clone(),
            op_id: spec.id.to_owned(),
            instance: routed.alias.clone(),
        };
        let (reason_excerpt, reason_unusual) = match p.reason.as_deref().map(normalize_reason) {
            Some((r, u)) => ((!r.is_empty()).then(|| excerpt(&r)), u),
            None => (None, false),
        };
        let mut new = NewEntry {
            head,
            spec,
            instance_id: routed.id.clone(),
            params_sha256: hex::encode(sha),
            target_display: target_display(spec, &p.params),
            agent_name: session.normalized.agent_name.clone(),
            reason_excerpt,
            unusual: session.normalized.unusual || reason_unusual,
            session: session.key(conn),
            validated: None,
            ctx,
            model: Model::new(kind),
            unlogged_terminal: None,
        };
        // 7. Static validation (T13).
        let vctx = ValidateCtx {
            instance_version: routed.version,
            caps: &EffectiveCaps::default(),
            for_script: false,
        };
        let validated = match validate(spec, &p.params, &vctx) {
            Ok(v) => v,
            Err(err) => {
                let _ = step(&mut new.model, Event::ValidationFailed);
                return self.reject(new, err).await;
            }
        };
        // 8. The dry executor call: op-owned static checks (CQL) and PD-09.
        let dry = match op_table().get(spec.id) {
            Some(op) => (op.executor)(&ExecCtx {
                spec,
                params: &validated.params,
                base: &routed.base,
                enrichment: None,
                effective_max: validated.effective_max,
            })
            .map(|_| ()),
            None => Err(ExecError::NotInThisBuild),
        };
        match dry {
            Ok(()) | Err(ExecError::EnrichmentRequired) => {}
            Err(ExecError::NotInThisBuild) => {
                let _ = step(&mut new.model, Event::ValidationFailed);
                let err = ValidationError {
                    code: ErrorCode::Internal,
                    message: NOT_IN_THIS_BUILD_MESSAGE.to_owned(),
                    details: Map::new(),
                };
                return self.reject(new, err).await;
            }
            Err(ExecError::Invalid(err)) => {
                let _ = step(&mut new.model, Event::ValidationFailed);
                return self.reject(new, err).await;
            }
        }
        // 9. Into the map, then dispatch (Tasks 21/22/27; the request waits in `Validated`).
        if step(&mut new.model, Event::ValidationPassed).is_err() {
            return envelope::internal("request state error");
        }
        new.validated = Some(validated);
        let entry = engine.insert(new);
        // 10. §4.5: nothing but the four routing fields.
        envelope::pending_envelope(
            &entry.head.request_id,
            &entry.head.op_id,
            &entry.head.instance,
            OpenStatus::Pending,
        )
    }

    async fn submit_script(&self, _conn: &ConnectionMeta, _p: SubmitParams) -> Envelope {
        if self.engine.is_shutting_down() {
            return GateState::ShuttingDown.envelope();
        }
        // Task 27: the script lifecycle against the `ScriptRunner` seam.
        envelope::internal(NOT_IN_THIS_BUILD_MESSAGE)
    }

    async fn await_request(
        &self,
        _conn: &ConnectionMeta,
        a: AwaitParams,
        progress: &dyn ProgressSink,
    ) -> Envelope {
        let Some(entry) = self.engine.entry(&a.request_id) else {
            // After a restart (or once terminal): from the records (Task 21 adds delivery).
            return self.records_answer(&a.request_id, false).await;
        };
        let wait = Duration::from_millis(a.timeout_ms.unwrap_or(DEFAULT_AWAIT_MS));
        let deadline = tokio::time::Instant::now() + wait;
        let mut rx = entry.subscribe();
        let mut last = *rx.borrow_and_update();
        // §4.5: a notification only when the agent-visible status changes.
        while OpenStatus::of(last).is_some() && !wait.is_zero() {
            match tokio::time::timeout_at(deadline, rx.changed()).await {
                Ok(Ok(())) => {
                    let now = *rx.borrow_and_update();
                    if now != last {
                        last = now;
                        progress.progress(ProgressNotification {
                            request_id: entry.head.request_id.clone(),
                            status: now,
                        });
                    }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }
        self.entry_answer(&entry, false).await
    }

    async fn status(&self, request_id: &str) -> Envelope {
        match self.engine.entry(request_id) {
            Some(entry) => self.entry_answer(&entry, true).await,
            None => self.records_answer(request_id, true).await,
        }
    }

    async fn cancel(&self, request_id: &str) -> Envelope {
        match self.engine.cancel_by_client(request_id).await {
            None => self.records_answer(request_id, false).await,
            Some(Ok(_)) => self.records_answer(request_id, false).await,
            Some(Err(TransitionError::Rejected(Rejection::NotCancellable)))
            | Some(Err(TransitionError::Raced(_)))
            | Some(Err(TransitionError::Rejected(_)))
            | Some(Err(TransitionError::Audit(_))) => match self.engine.entry(request_id) {
                Some(entry) => self.entry_answer(&entry, false).await,
                None => self.records_answer(request_id, false).await,
            },
        }
    }

    async fn requests_list(
        &self,
        agent: Option<&str>,
        state: Option<ListState>,
        match_params: Option<MatchParams>,
    ) -> Envelope {
        let agent = agent.map(|a| normalize_agent_name(a).0);
        let matcher = match &match_params {
            Some(m) => match self.match_key(m) {
                Some(k) => Some(k),
                None => return envelope::succeeded(json!({ "requests": [] })),
            },
            None => None,
        };
        let keep = |r: &ListRow| {
            agent
                .as_ref()
                .is_none_or(|a| r.agent_name.as_ref() == Some(a))
                && matcher.as_ref().is_none_or(|(op, inst, hash)| {
                    &r.row.op_id == op
                        && r.instance_id.as_ref() == Some(inst)
                        && &r.row.params_sha256 == hash
                })
        };
        let in_memory = self.pending_rows();
        let mut rows: Vec<RequestRow> = Vec::new();
        for r in &in_memory {
            let open = OpenStatus::of(r.row.status).is_some();
            let wanted = match state {
                Some(ListState::Pending) => open,
                Some(ListState::Recent) => !open,
                None => true,
            };
            if wanted && keep(r) {
                rows.push(r.row.clone());
            }
        }
        if state != Some(ListState::Pending) {
            let skip: HashSet<String> =
                in_memory.iter().map(|r| r.row.request_id.clone()).collect();
            let header_matcher = matcher
                .as_ref()
                .map(|(op, inst, _)| (op.clone(), inst.clone()));
            match self.recent_rows(skip, agent.clone(), header_matcher).await {
                Ok(recent) => rows.extend(recent.into_iter().filter(|r| keep(r)).map(|r| r.row)),
                Err(_) => return envelope::audit_unreadable(),
            }
        }
        rows.sort_by(|a, b| {
            a.submitted_at
                .cmp(&b.submitted_at)
                .then_with(|| a.request_id.cmp(&b.request_id))
        });
        envelope::succeeded(json!({ "requests": rows }))
    }

    async fn doctor(&self) -> Envelope {
        let http = self.engine.http().clone();
        let pac_configured = tokio::task::spawn_blocking(move || http.pac_configured())
            .await
            .unwrap_or(false);
        let table = self.engine.instances();
        let mut instances = Map::new();
        for i in table.list() {
            let config_error = match i.state {
                InstanceState::InsecureScheme | InstanceState::InstanceUnconfirmed => {
                    Value::String(i.state.as_str().to_owned())
                }
                _ => Value::Null,
            };
            let identity_header = match (i.product, i.state) {
                (Product::Jira, InstanceState::IdentityHeaderMissing) => json!("missing"),
                (Product::Jira, InstanceState::IdentityHeaderMismatch) => json!("mismatch"),
                _ => Value::Null,
            };
            // PD-11 from cached state only; reachability, TLS, proxy and version are known
            // after a connection test or a request (Tasks 25/26), until then `null`.
            instances.insert(
                i.alias.clone(),
                json!({
                    "configured": config_error.is_null(),
                    "config_error": config_error,
                    "reachable": null,
                    "needs_token": i.state == InstanceState::NeedsToken,
                    "locked": false,
                    "tls_error": null,
                    "proxy_error": null,
                    "identity_header": identity_header,
                    "version_supported": null,
                }),
            );
        }
        envelope::succeeded(json!({
            "instances": instances,
            "config_unreadable": table.config_unreadable(),
            "pac_configured": pac_configured,
        }))
    }
}
