//! Identity checks on Atlassian answers (Task 26, §7.1 *401 handling*, *Token identity*,
//! *Username rename*; §7.2 *Identity check on responses*, *Header lost*).
//!
//! The client checks `X-AUSERNAME` on every Jira JSON answer and hands a failed check back as
//! `FetchFailure::IdentityCheckFailed`; a JSON 401 is the other trigger. Both run the **token
//! re-check** ([`recheck`]): one `GET /rest/api/2/myself` (Jira) or `GET /rest/api/user/current`
//! (Confluence) with the stored PAT, logged as `SYSTEM_FETCH {purpose: token_recheck}`. Its
//! [`RecheckResult`] decides the instance state ([`on_result`] applies it) and, through
//! [`effect`], what the triggering call becomes; each driver (read, enrichment, stale check,
//! write response) maps the [`Effect`] onto its own failure shape.
//!
//! * At most one re-check is in flight per instance: later triggers await the same result
//!   (`OnceCell` per epoch). A re-check that changed the instance bumps the instance's epoch;
//!   a trigger whose call started before that (`seen < epoch`) is answered with that result
//!   without a new call, so the 10th of ten concurrent failures still sees the rename.
//! * An instance already in `needs_token` or an identity-header state answers from its state.
//! * A re-check that is not a parsed JSON 2xx (or a JSON 401) is [`RecheckResult::Inconclusive`]:
//!   it changes no state. The §7.1 branches do not name this case (a rate-limited `/myself`);
//!   it is decided here: the original call is `upstream_unavailable`, the token state unchanged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use atlas_duck_atlassian::{
    FetchFailure, FetchOutcome, GetCall, IdentityObserved, StoredIdentity, UpstreamResponse,
    username_matches,
};
use atlas_duck_registry::Product;
use serde_json::{Map, Value};
use tokio::sync::OnceCell;

use crate::audit_port::commit_system_fetch_start;
use crate::engine::Engine;
use crate::engine::write::{InstanceChange, identity_call, system_get_record};
use crate::ids::FetchId;
use crate::instances::InstanceState;
use crate::payloads::{self, SystemFetchPurpose};

/// What triggered the re-check: how the original call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The Jira `X-AUSERNAME` check failed (missing, `anonymous`, another name).
    HeaderCheck,
    /// A JSON 401 (Jira's arrives as a failed header check with `response.status == 401`).
    Json401,
}

/// The re-check's verdict (§7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecheckResult {
    /// Same key, header present and matching: the token is fine.
    IdentityMatch,
    /// Same key, another name, and the answer's own header carries the new name.
    Renamed {
        old: String,
        new: String,
        user_key: String,
    },
    /// Same key, no `X-AUSERNAME` on the re-check's `/myself` either.
    HeaderMissing,
    /// Same key, a header that does not match the name in the body.
    HeaderMismatch,
    /// A parsed JSON answer that is not this token's user (a JSON 401, `anonymous`, another key).
    TokenFailure { other_user: Option<String> },
    /// Not a parsed JSON 2xx (network, 429, 5xx, non-JSON, redirect): nothing is concluded.
    Inconclusive,
}

impl RecheckResult {
    /// Whether the result changes the instance (and bumps its epoch).
    fn changes_state(&self) -> bool {
        !matches!(self, Self::IdentityMatch | Self::Inconclusive)
    }
}

/// Which flow the trigger came from (the one decision table, [`effect`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    DirectRead,
    Enrichment,
    /// A stale check or a refresh.
    StaleOrRefresh,
    /// A write's own answer: never retried, the outcome stays `outcome_unknown`.
    WriteResponse,
}

/// The two identity-header states (§7.2 *Header lost*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lost {
    Missing,
    Mismatch,
}

impl Lost {
    /// `details.reason` / the state's wire name.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Missing => "identity_header_missing",
            Self::Mismatch => "identity_header_mismatch",
        }
    }

    pub fn state(self) -> InstanceState {
        match self {
            Self::Missing => InstanceState::IdentityHeaderMissing,
            Self::Mismatch => InstanceState::IdentityHeaderMismatch,
        }
    }
}

/// What the triggering call becomes (the columns of the §7.1 decision table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// A JSON 401 after a passing re-check: an ordinary 4xx answer.
    Ordinary,
    /// A rename: fetch (or run the stale check) once more.
    Refetch,
    /// A failed header check after a passing re-check: `upstream_unavailable`, retryable.
    HeaderCheckFailed,
    /// The re-check concluded nothing: `upstream_unavailable` / `recheck_failed`.
    Inconclusive,
    /// The instance entered an identity-header state.
    HeaderLost(Lost),
    /// A confirmed token failure: `needs_token`.
    NeedsToken,
}

/// The decision table of Task 26, in one place.
pub fn effect(path: Path, trigger: Trigger, result: &RecheckResult) -> Effect {
    match result {
        RecheckResult::IdentityMatch => match trigger {
            Trigger::Json401 => Effect::Ordinary,
            Trigger::HeaderCheck => Effect::HeaderCheckFailed,
        },
        // A write response is never retried (§7.1): it stays `outcome_unknown`.
        RecheckResult::Renamed { .. } if path == Path::WriteResponse => Effect::HeaderCheckFailed,
        RecheckResult::Renamed { .. } => Effect::Refetch,
        RecheckResult::HeaderMissing => Effect::HeaderLost(Lost::Missing),
        RecheckResult::HeaderMismatch => Effect::HeaderLost(Lost::Mismatch),
        RecheckResult::TokenFailure { .. } => Effect::NeedsToken,
        RecheckResult::Inconclusive => Effect::Inconclusive,
    }
}

/// The trigger of a GET outcome, if it is one (§7.1): a failed Jira header check, or a JSON 401
/// (a `Response` with status 401 is JSON by construction; a non-JSON 401 never gets here).
pub fn trigger(outcome: &FetchOutcome) -> Option<Trigger> {
    match outcome {
        FetchOutcome::Failed(f) => failure_trigger(f),
        FetchOutcome::Response(r) if r.status == 401 => Some(Trigger::Json401),
        FetchOutcome::Response(_) => None,
    }
}

/// [`trigger`] for a failure.
pub fn failure_trigger(f: &FetchFailure) -> Option<Trigger> {
    match f {
        // The Jira JSON 401 carries `X-AUSERNAME: anonymous`: check the status first.
        FetchFailure::IdentityCheckFailed { response, .. } if response.status == 401 => {
            Some(Trigger::Json401)
        }
        FetchFailure::IdentityCheckFailed { .. } => Some(Trigger::HeaderCheck),
        _ => None,
    }
}

/// The outcome as the ordinary answer it is once a re-check passed on a JSON 401: a Jira 401
/// that failed the header check is the plain `Response` again.
pub fn as_response(outcome: FetchOutcome) -> FetchOutcome {
    match outcome {
        FetchOutcome::Failed(FetchFailure::IdentityCheckFailed { response, .. })
            if response.status == 401 =>
        {
            FetchOutcome::Response(response)
        }
        other => other,
    }
}

/// The answer behind a trigger (for the audit-only record of the original call).
pub fn answer_of(outcome: &FetchOutcome) -> Option<&UpstreamResponse> {
    match outcome {
        FetchOutcome::Failed(FetchFailure::IdentityCheckFailed { response, .. }) => Some(response),
        FetchOutcome::Response(r) => Some(r),
        FetchOutcome::Failed(_) => None,
    }
}

// ---- judging the re-check's answer ---------------------------------------------------------------

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// The verdict on the re-check's answer, against the stored identity (§7.1).
///
/// Jira: the client already compared `X-AUSERNAME` with the stored name, so an answer that
/// arrives as a `Response` carries the stored name, and a rename or a header problem arrives as
/// `IdentityCheckFailed` with the whole answer: both are read here.
pub fn judge(product: Product, outcome: &FetchOutcome, stored: &StoredIdentity) -> RecheckResult {
    match product {
        Product::Jira => judge_jira(outcome, stored),
        Product::Confluence => judge_confluence(outcome, stored),
    }
}

fn judge_jira(outcome: &FetchOutcome, stored: &StoredIdentity) -> RecheckResult {
    let (observed, response) = match outcome {
        FetchOutcome::Response(r) => (IdentityObserved::Other(stored.atlassian_user.clone()), r),
        FetchOutcome::Failed(FetchFailure::IdentityCheckFailed { observed, response }) => {
            (observed.clone(), response)
        }
        FetchOutcome::Failed(_) => return RecheckResult::Inconclusive,
    };
    // A JSON 401 is the token verdict, whatever the header says.
    if response.status == 401 {
        return RecheckResult::TokenFailure { other_user: None };
    }
    if response.status != 200 {
        return RecheckResult::Inconclusive;
    }
    // A server that calls us `anonymous` does not know the token.
    if observed == IdentityObserved::Anonymous {
        return RecheckResult::TokenFailure { other_user: None };
    }
    let Ok(body) = serde_json::from_slice::<Value>(&response.body) else {
        return RecheckResult::Inconclusive;
    };
    let (Some(name), Some(key)) = (str_field(&body, "name"), str_field(&body, "key")) else {
        return RecheckResult::Inconclusive;
    };
    if key != stored.atlassian_user_key {
        return RecheckResult::TokenFailure {
            other_user: Some(name),
        };
    }
    match observed {
        IdentityObserved::Missing => RecheckResult::HeaderMissing,
        IdentityObserved::Anonymous => RecheckResult::TokenFailure { other_user: None },
        IdentityObserved::Other(header) => {
            if !username_matches(&header, &name) {
                RecheckResult::HeaderMismatch
            } else if username_matches(&name, &stored.atlassian_user) {
                RecheckResult::IdentityMatch
            } else {
                RecheckResult::Renamed {
                    old: stored.atlassian_user.clone(),
                    new: name,
                    user_key: key,
                }
            }
        }
    }
}

fn judge_confluence(outcome: &FetchOutcome, stored: &StoredIdentity) -> RecheckResult {
    let FetchOutcome::Response(r) = outcome else {
        return RecheckResult::Inconclusive;
    };
    if r.status == 401 {
        return RecheckResult::TokenFailure { other_user: None };
    }
    if r.status != 200 {
        return RecheckResult::Inconclusive;
    }
    let Ok(body) = serde_json::from_slice::<Value>(&r.body) else {
        return RecheckResult::Inconclusive;
    };
    if body.get("type").and_then(Value::as_str) != Some("known") {
        return RecheckResult::TokenFailure { other_user: None };
    }
    let (Some(name), Some(key)) = (str_field(&body, "username"), str_field(&body, "userKey"))
    else {
        return RecheckResult::TokenFailure { other_user: None };
    };
    if key != stored.atlassian_user_key {
        return RecheckResult::TokenFailure {
            other_user: Some(name),
        };
    }
    if username_matches(&name, &stored.atlassian_user) {
        RecheckResult::IdentityMatch
    } else {
        RecheckResult::Renamed {
            old: stored.atlassian_user.clone(),
            new: name,
            user_key: key,
        }
    }
}

// ---- one re-check in flight per instance ---------------------------------------------------------

#[derive(Default)]
struct Gate {
    /// Bumped whenever a re-check changed the instance.
    epoch: u64,
    /// The result that last bumped `epoch`, with the epoch it produced.
    last_change: Option<(u64, RecheckResult)>,
    in_flight: Option<Arc<OnceCell<RecheckResult>>>,
}

/// The per-instance gates of [`recheck`].
#[derive(Default)]
pub(crate) struct Gates {
    map: Mutex<HashMap<String, Gate>>,
}

impl Gates {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Gate>> {
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The instance's epoch: a caller reads it before its fetch and passes it to [`recheck`].
    pub(crate) fn epoch(&self, instance_id: &str) -> u64 {
        self.lock().get(instance_id).map_or(0, |g| g.epoch)
    }
}

/// An instance that is already known to be bad answers from its state (no call is sent).
fn known_state(engine: &Engine, instance_id: &str) -> Option<RecheckResult> {
    let state = engine.instances().by_id(instance_id).map(|i| i.state)?;
    match state {
        InstanceState::Ok => None,
        InstanceState::NeedsToken => Some(RecheckResult::TokenFailure { other_user: None }),
        InstanceState::IdentityHeaderMissing => Some(RecheckResult::HeaderMissing),
        InstanceState::IdentityHeaderMismatch => Some(RecheckResult::HeaderMismatch),
        InstanceState::InsecureScheme | InstanceState::InstanceUnconfirmed => {
            Some(RecheckResult::Inconclusive)
        }
    }
}

/// The token re-check of `instance_id` (§7.1), once per instance at a time. `seen` is the
/// instance's epoch ([`Engine::identity_epoch`]) read before the failed call started.
pub async fn recheck(engine: &Arc<Engine>, instance_id: &str, seen: u64) -> RecheckResult {
    if let Some(known) = known_state(engine, instance_id) {
        return known;
    }
    let cell = {
        let mut gates = engine.identity_gates().lock();
        let gate = gates.entry(instance_id.to_owned()).or_default();
        if let Some((epoch, result)) = &gate.last_change
            && seen < *epoch
        {
            return result.clone();
        }
        gate.in_flight
            .get_or_insert_with(|| Arc::new(OnceCell::new()))
            .clone()
    };
    cell.get_or_init(|| async {
        let result = run(engine, instance_id).await;
        on_result(engine, instance_id, &result).await;
        let mut gates = engine.identity_gates().lock();
        let gate = gates.entry(instance_id.to_owned()).or_default();
        gate.in_flight = None;
        if result.changes_state() {
            gate.epoch += 1;
            gate.last_change = Some((gate.epoch, result.clone()));
        }
        result
    })
    .await
    .clone()
}

/// The re-check's own call, under `SYSTEM_FETCH {purpose: token_recheck}`: the start record
/// commits before the request leaves, the result record carries every byte received.
async fn run(engine: &Arc<Engine>, instance_id: &str) -> RecheckResult {
    let Some(product) = engine.instances().by_id(instance_id).map(|i| i.product) else {
        return RecheckResult::Inconclusive;
    };
    let stored = {
        let (creds, id) = (engine.credentials().clone(), instance_id.to_owned());
        tokio::task::spawn_blocking(move || creds.load(&id))
            .await
            .ok()
            .and_then(Result::ok)
            .flatten()
            .map(|c| c.identity)
    };
    let Some(stored) = stored else {
        return RecheckResult::Inconclusive;
    };
    let Ok(http) = engine.client(instance_id).await else {
        return RecheckResult::Inconclusive;
    };
    let Ok(fetch_id) = FetchId::new().map(|f| f.0) else {
        return RecheckResult::Inconclusive;
    };
    let call: GetCall = identity_call(product);
    let purpose = SystemFetchPurpose::TokenRecheck;
    let start = payloads::system_fetch_start(
        purpose,
        instance_id,
        &fetch_id,
        &[("GET", &call.endpoint_template)],
    );
    let (committed, fid) = (engine.committed().clone(), fetch_id.clone());
    let started = engine
        .blocking(move |p| commit_system_fetch_start(p, &committed, start, &fid).map(|_| ()))
        .await;
    if started.is_err() {
        return RecheckResult::Inconclusive;
    }
    let result = match engine.covers().for_system_fetch(&fetch_id) {
        Ok(cover) => {
            let outcome = http.client.get(&cover, &call).await;
            let record = system_get_record(
                purpose,
                instance_id,
                &fetch_id,
                http.client.base(),
                &call,
                &outcome,
            );
            match engine.blocking(move |p| p.append(record).map(|_| ())).await {
                Ok(()) => judge(product, &outcome, &stored),
                // Audit before effect: an unrecorded answer concludes nothing.
                Err(_) => RecheckResult::Inconclusive,
            }
        }
        Err(_) => RecheckResult::Inconclusive,
    };
    engine.committed().forget_fetch(&fetch_id);
    result
}

// ---- applying a result ---------------------------------------------------------------------------

/// The settings-window note of an instance that needs its token again.
fn token_note(other_user: Option<&str>) -> Option<String> {
    other_user.map(|u| format!("token now resolves to {u}"))
}

/// Applies a re-check result to the instance (§7.1, §7.2): the `INSTANCE_STATE_CHANGED` record
/// commits first (audit before effect), then the runtime table and, for a rename, the stored
/// identity change; queued writes follow ([`Engine::instance_changed`]). A result that changes
/// nothing (`IdentityMatch`, `Inconclusive`) does nothing.
pub async fn on_result(engine: &Arc<Engine>, instance_id: &str, result: &RecheckResult) {
    match result {
        RecheckResult::IdentityMatch | RecheckResult::Inconclusive => {}
        RecheckResult::Renamed { old, new, user_key } => {
            apply_rename(engine, instance_id, old, new, user_key).await
        }
        RecheckResult::HeaderMissing => {
            let note = Some(crate::engine::envelope::MSG_IDENTITY_HEADER.to_owned());
            apply_state(engine, instance_id, Lost::Missing.state(), None, note).await;
        }
        RecheckResult::HeaderMismatch => {
            let note = Some(crate::engine::envelope::MSG_IDENTITY_HEADER.to_owned());
            apply_state(engine, instance_id, Lost::Mismatch.state(), None, note).await;
        }
        RecheckResult::TokenFailure { other_user } => {
            let note = token_note(other_user.as_deref());
            apply_state(
                engine,
                instance_id,
                InstanceState::NeedsToken,
                other_user.as_deref(),
                note,
            )
            .await;
        }
    }
}

async fn apply_state(
    engine: &Arc<Engine>,
    instance_id: &str,
    state: InstanceState,
    resolves_to: Option<&str>,
    note: Option<String>,
) {
    // Only a working instance moves; an unconfirmed or refused one stays what it is.
    let current = engine.instances().by_id(instance_id).map(|i| i.state);
    if current != Some(InstanceState::Ok) {
        return;
    }
    let mut details = Map::new();
    details.insert("reason".into(), "token_recheck".into());
    if let Some(user) = resolves_to {
        details.insert("resolves_to".into(), user.into());
    }
    let record = payloads::instance_state_changed(instance_id, state.as_str(), &details);
    if engine
        .blocking(move |p| p.append(record).map(|_| ()))
        .await
        .is_err()
    {
        return;
    }
    engine.update_instance(instance_id, |rt| {
        rt.state = state;
        rt.note = note;
    });
    engine
        .instance_changed(instance_id, InstanceChange::StateChanged)
        .await;
}

/// `INSTANCE_STATE_CHANGED {user_renamed: {old, new, user_key}}` and, in the same step, the new
/// name in the stored credential and the runtime table; then every queued write of the instance
/// is refreshed (`WRITE_STALE {user_renamed}`). Token and key are unchanged: no
/// `CREDENTIAL_CHANGED`.
pub async fn apply_rename(
    engine: &Arc<Engine>,
    instance_id: &str,
    old: &str,
    new: &str,
    user_key: &str,
) {
    let mut details = Map::new();
    details.insert("old".into(), old.into());
    details.insert("new".into(), new.into());
    details.insert("user_key".into(), user_key.into());
    let record = payloads::instance_state_changed(instance_id, "user_renamed", &details);
    if engine
        .blocking(move |p| p.append(record).map(|_| ()))
        .await
        .is_err()
    {
        return;
    }
    let (creds, id, name) = (
        engine.credentials().clone(),
        instance_id.to_owned(),
        new.to_owned(),
    );
    // A keychain that cannot be written leaves the old name stored: the next answer under the
    // new name runs the re-check again and lands here again.
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(Some(mut cred)) = creds.load(&id) {
            cred.identity.atlassian_user = name;
            let _ = creds.store(&id, cred);
        }
    })
    .await;
    let name = new.to_owned();
    engine.update_instance(instance_id, |rt| {
        if let Some(identity) = rt.identity.as_mut() {
            identity.atlassian_user = name;
        }
    });
    engine
        .instance_changed(
            instance_id,
            InstanceChange::UserRenamed {
                old: old.to_owned(),
                new: new.to_owned(),
            },
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_duck_atlassian::{IdentityObserved as Obs, UpstreamResponse};

    fn stored() -> StoredIdentity {
        StoredIdentity {
            atlassian_user: "jdoe".into(),
            atlassian_user_key: "JIRAUSER1".into(),
        }
    }

    fn resp(status: u16, body: &str) -> UpstreamResponse {
        UpstreamResponse {
            status,
            content_type: Some("application/json".into()),
            body: body.as_bytes().to_vec(),
        }
    }

    fn myself(name: &str, key: &str) -> String {
        format!(r#"{{"name":"{name}","key":"{key}"}}"#)
    }

    fn failed(observed: Obs, status: u16, body: &str) -> FetchOutcome {
        FetchOutcome::Failed(FetchFailure::IdentityCheckFailed {
            observed,
            response: resp(status, body),
        })
    }

    #[test]
    fn jira_verdicts() {
        let s = stored();
        let ok = FetchOutcome::Response(resp(200, &myself("jdoe", "JIRAUSER1")));
        assert_eq!(judge(Product::Jira, &ok, &s), RecheckResult::IdentityMatch);
        // A rename: the header carries the new name, the key is the stored one.
        let renamed = failed(
            Obs::Other("jdoe2".into()),
            200,
            &myself("jdoe2", "JIRAUSER1"),
        );
        assert_eq!(
            judge(Product::Jira, &renamed, &s),
            RecheckResult::Renamed {
                old: "jdoe".into(),
                new: "jdoe2".into(),
                user_key: "JIRAUSER1".into()
            }
        );
        let lost = failed(Obs::Missing, 200, &myself("jdoe", "JIRAUSER1"));
        assert_eq!(
            judge(Product::Jira, &lost, &s),
            RecheckResult::HeaderMissing
        );
        let odd = failed(
            Obs::Other("mallory".into()),
            200,
            &myself("jdoe", "JIRAUSER1"),
        );
        assert_eq!(
            judge(Product::Jira, &odd, &s),
            RecheckResult::HeaderMismatch
        );
        // Another user's key, or `anonymous`, or a JSON 401: a confirmed token failure.
        let other = failed(Obs::Other("bob".into()), 200, &myself("bob", "JIRAUSER9"));
        assert_eq!(
            judge(Product::Jira, &other, &s),
            RecheckResult::TokenFailure {
                other_user: Some("bob".into())
            }
        );
        let anon = failed(Obs::Anonymous, 200, &myself("jdoe", "JIRAUSER1"));
        assert_eq!(
            judge(Product::Jira, &anon, &s),
            RecheckResult::TokenFailure { other_user: None }
        );
        let json401 = failed(Obs::Anonymous, 401, "{}");
        assert_eq!(
            judge(Product::Jira, &json401, &s),
            RecheckResult::TokenFailure { other_user: None }
        );
    }

    #[test]
    fn a_recheck_that_is_not_a_parsed_2xx_concludes_nothing() {
        let s = stored();
        for outcome in [
            failed(Obs::Missing, 429, "{}"),
            failed(Obs::Missing, 503, "{}"),
            FetchOutcome::Response(resp(200, "not json")),
            FetchOutcome::Response(resp(200, "{}")),
            FetchOutcome::Failed(FetchFailure::BudgetExpiredBeforeSend),
            FetchOutcome::Failed(FetchFailure::NeedsToken),
        ] {
            assert_eq!(
                judge(Product::Jira, &outcome, &s),
                RecheckResult::Inconclusive,
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn confluence_verdicts() {
        let s = stored();
        let known = |name: &str, key: &str| {
            FetchOutcome::Response(resp(
                200,
                &format!(r#"{{"type":"known","username":"{name}","userKey":"{key}"}}"#),
            ))
        };
        assert_eq!(
            judge(Product::Confluence, &known("jdoe", "JIRAUSER1"), &s),
            RecheckResult::IdentityMatch
        );
        assert_eq!(
            judge(Product::Confluence, &known("jdoe2", "JIRAUSER1"), &s),
            RecheckResult::Renamed {
                old: "jdoe".into(),
                new: "jdoe2".into(),
                user_key: "JIRAUSER1".into()
            }
        );
        assert_eq!(
            judge(Product::Confluence, &known("bob", "K2"), &s),
            RecheckResult::TokenFailure {
                other_user: Some("bob".into())
            }
        );
        let anon = FetchOutcome::Response(resp(200, r#"{"type":"anonymous"}"#));
        assert_eq!(
            judge(Product::Confluence, &anon, &s),
            RecheckResult::TokenFailure { other_user: None }
        );
        assert_eq!(
            judge(
                Product::Confluence,
                &FetchOutcome::Response(resp(401, "{}")),
                &s
            ),
            RecheckResult::TokenFailure { other_user: None }
        );
    }

    #[test]
    fn the_decision_table() {
        use Effect as E;
        use Trigger::{HeaderCheck, Json401};
        let renamed = RecheckResult::Renamed {
            old: "a".into(),
            new: "b".into(),
            user_key: "k".into(),
        };
        let fail = RecheckResult::TokenFailure { other_user: None };
        for path in [Path::DirectRead, Path::Enrichment, Path::StaleOrRefresh] {
            assert_eq!(
                effect(path, HeaderCheck, &RecheckResult::IdentityMatch),
                E::HeaderCheckFailed
            );
            assert_eq!(
                effect(path, Json401, &RecheckResult::IdentityMatch),
                E::Ordinary
            );
            assert_eq!(effect(path, HeaderCheck, &renamed), E::Refetch);
            assert_eq!(effect(path, Json401, &renamed), E::Refetch);
            assert_eq!(effect(path, HeaderCheck, &fail), E::NeedsToken);
            assert_eq!(
                effect(path, Json401, &RecheckResult::Inconclusive),
                E::Inconclusive
            );
            assert_eq!(
                effect(path, HeaderCheck, &RecheckResult::HeaderMissing),
                E::HeaderLost(Lost::Missing)
            );
            assert_eq!(
                effect(path, HeaderCheck, &RecheckResult::HeaderMismatch),
                E::HeaderLost(Lost::Mismatch)
            );
        }
        // A write's answer is never retried.
        assert_eq!(
            effect(Path::WriteResponse, HeaderCheck, &renamed),
            E::HeaderCheckFailed
        );
    }

    #[test]
    fn triggers() {
        assert_eq!(
            trigger(&failed(Obs::Anonymous, 401, "{}")),
            Some(Trigger::Json401)
        );
        assert_eq!(
            trigger(&failed(Obs::Missing, 429, "{}")),
            Some(Trigger::HeaderCheck)
        );
        assert_eq!(
            trigger(&FetchOutcome::Response(resp(401, "{}"))),
            Some(Trigger::Json401)
        );
        assert_eq!(trigger(&FetchOutcome::Response(resp(404, "{}"))), None);
        assert_eq!(
            trigger(&FetchOutcome::Failed(FetchFailure::NeedsToken)),
            None
        );
    }
}
