//! The per-instance Jira field-name cache (PD-46, §7.3 "Unknown custom ids are flagged in the
//! preview (via the cached `/rest/api/2/field`…)", §6.3 "custom field names resolved via
//! `/rest/api/2/field`").
//!
//! Every fill is `SYSTEM_FETCH {purpose: metadata_cache, phase: start}` → `GET /rest/api/2/field`
//! → `{phase: result}`, never under a request id: the start record commits before the request
//! leaves (§5.1 inv. 1), the result record carries every byte received, and only a recorded answer
//! is used. The GET goes through the instance's client, so the instance limiter, the method guard
//! and the M3 per-response identity check apply; an identity failure runs the M3 token re-check.
//!
//! Fills run in the background on the core's runtime and at most one per instance at a time:
//! at `Core::start` for every `ok` Jira instance, after a passing connection test (`set_token`,
//! `retest_token`), and when a Jira read preview is built while the last fill started at least
//! [`FIELD_CACHE_TTL`] ago. A preview never waits: it shows what is cached. A 2xx JSON array
//! replaces the map; anything else keeps the old one and logs the constant event
//! `metadata_cache_failed`. The map is display-only: nothing in validation reads it (§2.3).

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use atlas_duck_atlassian::{FetchOutcome, GetCall};
use atlas_duck_audit::UtcInstant;
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_registry::Product;
use serde_json::{Map, Value};

use crate::audit_port::commit_system_fetch_start;
use crate::engine::Engine;
use crate::engine::write::system_get_record;
use crate::identity;
use crate::ids::FetchId;
use crate::instances::InstanceState;
use crate::payloads::{self, SystemFetchPurpose};

/// PD-46: a map is refreshed once its last fill started this long ago.
pub const FIELD_CACHE_TTL: Duration = Duration::from_secs(3600);
/// plan text (PD-46): how a `customfield_N` id the cache does not know is shown.
pub const UNKNOWN_FIELD_SUFFIX: &str = " (unknown field)";
const FIELD_PATH: &str = "/rest/api/2/field";
/// The diagnostic event of a fill that left the map as it was (constant, ids only).
const FAILED_EVENT: &str = "metadata_cache_failed";

/// The `/rest/api/2/field` id → name map of one Jira instance.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct FieldNames(BTreeMap<String, String>);

/// Redacting `Debug` (§7.7): field names are Atlassian data.
impl fmt::Debug for FieldNames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldNames({} fields)", self.0.len())
    }
}

impl From<BTreeMap<String, String>> for FieldNames {
    fn from(map: BTreeMap<String, String>) -> FieldNames {
        FieldNames(map)
    }
}

impl FieldNames {
    /// The raw name of field `id` (display-escape it before showing it: [`field_label`]).
    pub fn get(&self, id: &str) -> Option<&str> {
        self.0.get(id).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The `/rest/api/2/field` answer: a JSON array of `{id, name, …}`. Elements without a
    /// non-empty string `id` and `name` are skipped; `None` when the body is not a JSON array.
    pub fn parse(body: &[u8]) -> Option<FieldNames> {
        let Ok(Value::Array(items)) = serde_json::from_slice::<Value>(body) else {
            return None;
        };
        let text = |v: &Value, key: &str| {
            v.get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        Some(FieldNames(
            items
                .iter()
                .filter_map(|v| Some((text(v, "id")?, text(v, "name")?)))
                .collect(),
        ))
    }
}

/// How a field id is shown (display-escaped): its cached name; a `customfield_N` id the map does
/// not know (or no map) as "customfield_N (unknown field)" (plan text, PD-46); any other id as is.
pub fn field_label(names: Option<&FieldNames>, id: &str) -> String {
    match names.and_then(|n| n.get(id)) {
        Some(name) => escape_for_display(name),
        None if id.starts_with("customfield_") => {
            format!("{}{UNKNOWN_FIELD_SUFFIX}", escape_for_display(id))
        }
        None => escape_for_display(id),
    }
}

/// One instance's cache state.
#[derive(Default)]
struct Entry {
    /// The map of the last successful fill and when it arrived.
    names: Option<(Arc<FieldNames>, UtcInstant)>,
    /// When the last fill started, successful or not: the TTL counts from here, so a failing
    /// endpoint is asked once per TTL, not once per preview.
    attempted: Option<UtcInstant>,
    /// A fill of this instance is running.
    filling: bool,
    /// A start or token fill was asked for while one ran: one more runs right after it.
    again: bool,
    /// Fills that ended in `metadata_cache_failed`.
    failures: u64,
}

/// The per-instance cache (`Engine::field_cache`). The lock is held for map operations only,
/// never across an `.await`.
#[derive(Default)]
pub(crate) struct FieldCache {
    map: Mutex<HashMap<String, Entry>>,
}

impl FieldCache {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What is cached for `instance_id` now (never waits, never fetches).
    pub(crate) fn snapshot(&self, instance_id: &str) -> Option<Arc<FieldNames>> {
        self.lock()
            .get(instance_id)
            .and_then(|e| e.names.as_ref())
            .map(|(names, _)| names.clone())
    }

    /// No fill is running for any instance (`Harness::field_cache_filled`).
    #[cfg(feature = "testing")]
    pub(crate) fn idle(&self) -> bool {
        !self.lock().values().any(|e| e.filling)
    }

    /// Fills of `instance_id` that ended in `metadata_cache_failed` (the tests' view of the
    /// diagnostic event).
    #[cfg(feature = "testing")]
    pub(crate) fn failures(&self, instance_id: &str) -> u64 {
        self.lock().get(instance_id).map_or(0, |e| e.failures)
    }

    /// Fills `instance_id` in the background (start, a passing connection test). A fill that is
    /// running already gets one more run after it instead of a second one beside it.
    pub(crate) fn spawn_fill(engine: &Arc<Engine>, instance_id: &str) {
        if disabled(engine) {
            return;
        }
        let now = engine.clock().now_utc();
        let start = {
            let mut map = engine.field_cache().lock();
            let entry = map.entry(instance_id.to_owned()).or_default();
            if entry.filling {
                entry.again = true;
                false
            } else {
                entry.filling = true;
                entry.attempted = Some(now);
                true
            }
        };
        if start {
            spawn(engine, instance_id);
        }
    }

    /// A Jira read preview of `instance_id` is being built: a background fill when the last one
    /// started at least [`FIELD_CACHE_TTL`] ago (or never), unless one is running. The preview
    /// itself uses [`FieldCache::snapshot`] as it is.
    pub(crate) fn refresh_if_stale(engine: &Arc<Engine>, instance_id: &str) {
        if disabled(engine) {
            return;
        }
        let now = engine.clock().now_utc();
        let start = {
            let mut map = engine.field_cache().lock();
            let entry = map.entry(instance_id.to_owned()).or_default();
            let due = entry.attempted.is_none_or(|t| older_than_ttl(t, now));
            if entry.filling || !due {
                false
            } else {
                entry.filling = true;
                entry.attempted = Some(now);
                true
            }
        };
        if start {
            spawn(engine, instance_id);
        }
    }

    /// After a run: `true` (and the next run marked started) when another was asked for;
    /// otherwise the instance is no longer filling, decided under one lock so that a request
    /// arriving now starts a fill of its own instead of being lost.
    fn run_again(&self, instance_id: &str, now: UtcInstant) -> bool {
        let mut map = self.lock();
        let Some(entry) = map.get_mut(instance_id) else {
            return false;
        };
        if !entry.again {
            entry.filling = false;
            return false;
        }
        entry.again = false;
        entry.attempted = Some(now);
        true
    }

    fn store(&self, instance_id: &str, names: FieldNames, at: UtcInstant) {
        self.lock().entry(instance_id.to_owned()).or_default().names = Some((Arc::new(names), at));
    }

    fn failed(&self, instance_id: &str) {
        self.lock()
            .entry(instance_id.to_owned())
            .or_default()
            .failures += 1;
    }

    /// A fill task was dropped or panicked before [`FieldCache::run_again`] ended it: the
    /// instance may fill again.
    fn finish(&self, instance_id: &str) {
        if let Some(entry) = self.lock().get_mut(instance_id) {
            entry.filling = false;
            entry.again = false;
        }
    }
}

/// `now` is at least the TTL after `then`; a wall clock that went backwards counts as stale too.
fn older_than_ttl(then: UtcInstant, now: UtcInstant) -> bool {
    let ttl = i64::try_from(FIELD_CACHE_TTL.as_millis()).unwrap_or(i64::MAX);
    now.0 < then.0 || now.0.saturating_sub(then.0) >= ttl
}

#[cfg(feature = "testing")]
fn disabled(engine: &Engine) -> bool {
    engine.hooks().no_field_cache
}

#[cfg(not(feature = "testing"))]
fn disabled(_: &Engine) -> bool {
    false
}

/// A running fill task. It ends through [`FieldCache::run_again`], which clears the running flag
/// under the same lock that answers "no further run"; a task dropped or panicking before that
/// clears it here (no other fill can have started meanwhile: the flag was still set).
struct Running {
    engine: Arc<Engine>,
    instance_id: String,
    ended: bool,
}

impl Running {
    /// `run_again` cleared the flag: nothing left for `drop`.
    fn end(&mut self) {
        self.ended = true;
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.ended {
            self.engine.field_cache().finish(&self.instance_id);
        }
    }
}

fn spawn(engine: &Arc<Engine>, instance_id: &str) {
    let mut running = Running {
        engine: engine.clone(),
        instance_id: instance_id.to_owned(),
        ended: false,
    };
    engine.spawn_detached(async move {
        loop {
            fill(&running.engine, &running.instance_id).await;
            let now = running.engine.clock().now_utc();
            if !running
                .engine
                .field_cache()
                .run_again(&running.instance_id, now)
            {
                running.end();
                break;
            }
        }
    });
}

/// What one fill came to.
enum Filled {
    Names(FieldNames),
    /// Not a Jira instance in state `ok` (any more): nothing was sent or recorded.
    Skipped,
    Failed,
}

async fn fill(engine: &Arc<Engine>, instance_id: &str) {
    match fetch(engine, instance_id).await {
        Filled::Names(names) => {
            engine
                .field_cache()
                .store(instance_id, names, engine.clock().now_utc());
        }
        Filled::Skipped => {}
        Filled::Failed => {
            tracing::warn!(event = FAILED_EVENT);
            engine.field_cache().failed(instance_id);
        }
    }
}

/// The fill's one GET under `SYSTEM_FETCH {purpose: metadata_cache}` (as `identity::run` does
/// for `token_recheck`).
async fn fetch(engine: &Arc<Engine>, instance_id: &str) -> Filled {
    let usable = engine
        .instances()
        .by_id(instance_id)
        .is_some_and(|i| i.product == Product::Jira && i.state == InstanceState::Ok);
    if !usable {
        return Filled::Skipped;
    }
    let seen = engine.identity_epoch(instance_id);
    let Ok(http) = engine.client(instance_id).await else {
        return Filled::Failed;
    };
    let Ok(fetch_id) = FetchId::new().map(|f| f.0) else {
        return Filled::Failed;
    };
    let call = GetCall {
        endpoint_template: FIELD_PATH.to_owned(),
        params: Value::Object(Map::new()),
        query: Vec::new(),
    };
    let purpose = SystemFetchPurpose::MetadataCache;
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
        return Filled::Failed;
    }
    let outcome = match engine.covers().for_system_fetch(&fetch_id) {
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
                Ok(()) => Some(outcome),
                // Audit before effect: an unrecorded answer is not used.
                Err(_) => None,
            }
        }
        Err(_) => None,
    };
    engine.committed().forget_fetch(&fetch_id);
    let Some(outcome) = outcome else {
        return Filled::Failed;
    };
    // The M3 per-response identity check failed (or a JSON 401): the token re-check decides
    // the instance; the map stays as it was.
    if identity::trigger(&outcome).is_some() {
        let _ = identity::recheck(engine, instance_id, seen).await;
        return Filled::Failed;
    }
    match outcome {
        FetchOutcome::Response(r) if (200..300).contains(&r.status) => {
            FieldNames::parse(&r.body).map_or(Filled::Failed, Filled::Names)
        }
        _ => Filled::Failed,
    }
}
