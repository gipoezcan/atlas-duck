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
//! [`FIELD_CACHE_TTL`] ago ([`FIELD_CACHE_RETRY`] after a failed one). A preview never waits: it
//! shows what is cached. A 2xx JSON array replaces the map (capped: [`MAX_FIELDS`],
//! [`MAX_NAME_CHARS`]); anything else keeps the old one and logs the constant event
//! `metadata_cache_failed`. The map is display-only: nothing in validation reads it (§2.3).
//!
//! §2.5 step 5 (T8 review I-1): once the shutdown began no fill starts, and the shutdown cancels
//! the running ones ([`FieldCache::cancel_all`], never waits) and lets them end
//! ([`FieldCache::idle`]) before `APP_STOP`: a fill cancelled before its start record records
//! nothing, one cancelled after it records its result (`class: cancelled`).

use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Write as _};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use atlas_duck_atlassian::{FetchControl, FetchOutcome, GetCall};
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

/// PD-46: a map is refreshed once the successful fill that brought it started this long ago.
pub const FIELD_CACHE_TTL: Duration = Duration::from_secs(3600);
/// PD-46 (lead ruling, T8 review M-4): a failed fill is retried once it started this long ago,
/// so a start fill that ran before the network was up does not leave names unknown for the hour.
pub const FIELD_CACHE_RETRY: Duration = Duration::from_secs(300);
/// T8 review I-2: the most fields one map keeps (the first ones of the answer).
pub const MAX_FIELDS: usize = 20_000;
/// T8 review I-2: a longer name is cut to this many chars (the last one `…`); an entry with a
/// longer id is dropped.
pub const MAX_NAME_CHARS: usize = 256;
/// plan text (PD-46): how a `customfield_N` id the cache does not know is shown.
pub const UNKNOWN_FIELD_SUFFIX: &str = " (unknown field)";
const FIELD_PATH: &str = "/rest/api/2/field";
/// The diagnostic event of a fill that left the map as it was (constant, ids only).
const FAILED_EVENT: &str = "metadata_cache_failed";
/// The diagnostic event of a map the caps cut (constant, plus a count).
const CAPPED_EVENT: &str = "metadata_cache_capped";

/// The `/rest/api/2/field` id → name map of one Jira instance.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct FieldNames {
    map: BTreeMap<String, String>,
    /// Entries dropped and names cut by the caps.
    capped: usize,
}

/// Redacting `Debug` (§7.7): field names are Atlassian data.
impl fmt::Debug for FieldNames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FieldNames({} fields, {} capped)",
            self.map.len(),
            self.capped
        )
    }
}

/// The caps apply here too.
impl From<BTreeMap<String, String>> for FieldNames {
    fn from(map: BTreeMap<String, String>) -> FieldNames {
        FieldNames::capped_from(map)
    }
}

impl FieldNames {
    /// The raw name of field `id` (display-escape it before showing it: [`field_label`]).
    pub fn get(&self, id: &str) -> Option<&str> {
        self.map.get(id).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// How many entries the caps dropped or cut (the count of the `metadata_cache_capped` note).
    pub fn capped(&self) -> usize {
        self.capped
    }

    /// The `/rest/api/2/field` answer: a JSON array of `{id, name, …}`. Elements without a
    /// non-empty string `id` and `name` are skipped; `None` when the body is not a JSON array.
    /// The answer is untrusted: [`MAX_FIELDS`] and [`MAX_NAME_CHARS`] bound what is kept. Up to
    /// 32 MiB of JSON: callers on the runtime run it on a blocking thread.
    pub fn parse(body: &[u8]) -> Option<FieldNames> {
        let Ok(Value::Array(items)) = serde_json::from_slice::<Value>(body) else {
            return None;
        };
        let text = |v: &mut Value, key: &str| match v.get_mut(key) {
            Some(Value::String(s)) if !s.is_empty() => Some(std::mem::take(s)),
            _ => None,
        };
        Some(FieldNames::capped_from(items.into_iter().filter_map(
            |mut v| Some((text(&mut v, "id")?, text(&mut v, "name")?)),
        )))
    }

    /// The pairs in order, the caps applied and counted.
    fn capped_from(pairs: impl IntoIterator<Item = (String, String)>) -> FieldNames {
        let mut out = FieldNames::default();
        for (id, name) in pairs {
            let full = out.map.len() >= MAX_FIELDS && !out.map.contains_key(&id);
            if full || longer_than_cap(&id) {
                out.capped += 1;
                continue;
            }
            let name = if longer_than_cap(&name) {
                out.capped += 1;
                let mut cut: String = name.chars().take(MAX_NAME_CHARS - 1).collect();
                cut.push('…');
                cut
            } else {
                name
            };
            out.map.insert(id, name);
        }
        out
    }
}

/// More than [`MAX_NAME_CHARS`] chars (without counting all of a long string).
fn longer_than_cap(s: &str) -> bool {
    s.chars().nth(MAX_NAME_CHARS).is_some()
}

/// How a field id is shown (display-escaped, one line): its cached name; a `customfield_N` id the
/// map does not know (or no map) as "customfield_N (unknown field)" (plan text, PD-46); any other
/// id as is.
pub fn field_label(names: Option<&FieldNames>, id: &str) -> String {
    one_line(match names.and_then(|n| n.get(id)) {
        Some(name) => escape_for_display(name),
        None if id.starts_with("customfield_") => {
            format!("{}{UNKNOWN_FIELD_SUFFIX}", escape_for_display(id))
        }
        None => escape_for_display(id),
    })
}

/// `\t`, `\n` and `\r`, which [`escape_for_display`] keeps for multi-line text, as the same
/// `⟨U+XXXX⟩` escapes (T8 review M-1): a label is one line. Applied after `escape_for_display`,
/// which escapes a literal `⟨`, so the encoding stays injective.
pub(crate) fn one_line(s: String) -> String {
    if !s.contains(['\t', '\n', '\r']) {
        return s;
    }
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        if matches!(c, '\t' | '\n' | '\r') {
            let _ = write!(out, "⟨U+{:04X}⟩", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// One instance's cache state.
#[derive(Default)]
struct Entry {
    /// The map of the last successful fill and when it arrived.
    names: Option<(Arc<FieldNames>, UtcInstant)>,
    /// When the last fill that was not skipped started, and how long a stale preview build waits
    /// after it: [`FIELD_CACHE_TTL`] after a success, [`FIELD_CACHE_RETRY`] after a failure. A
    /// fill that was skipped (not an `ok` Jira instance) or cancelled leaves it as it was.
    attempted: Option<(UtcInstant, Duration)>,
    /// A fill of this instance is running.
    filling: bool,
    /// A start or token fill was asked for while one ran: one more runs right after it.
    again: bool,
    /// Fills that ended in `metadata_cache_failed`.
    failures: u64,
    /// The running fill's cancel handle (the shutdown cancels it).
    ctl: Option<FetchControl>,
    /// Bumped by an origin change: a fill that started before it keeps nothing.
    generation: u64,
}

impl Entry {
    /// A stale-preview refresh may start at `now`.
    fn due(&self, now: UtcInstant) -> bool {
        !self.filling
            && self
                .attempted
                .is_none_or(|(then, wait)| waited(then, now, wait))
    }

    /// A fill starts: its cancel handle.
    fn begin(&mut self) -> FetchControl {
        self.filling = true;
        let ctl = FetchControl::new();
        self.ctl = Some(ctl.clone());
        ctl
    }

    /// What a fill of `generation` that started at `started` came to. Returns the map it
    /// replaced, to be dropped outside the lock.
    fn ended(
        &mut self,
        generation: u64,
        started: UtcInstant,
        filled: Filled,
        now: UtcInstant,
    ) -> Option<(Arc<FieldNames>, UtcInstant)> {
        if generation != self.generation {
            return None;
        }
        match filled {
            Filled::Names(names) => {
                self.attempted = Some((started, FIELD_CACHE_TTL));
                self.names.replace((Arc::new(names), now))
            }
            Filled::Failed => {
                self.failures += 1;
                self.attempted = Some((started, FIELD_CACHE_RETRY));
                None
            }
            Filled::Skipped | Filled::Cancelled => None,
        }
    }

    /// The run ended: `Some` (the next run started) when another was asked for and the
    /// shutdown did not begin; otherwise the instance is no longer filling.
    fn run_ended(&mut self, shutting_down: bool) -> Option<FetchControl> {
        if self.again && !shutting_down {
            self.again = false;
            return Some(self.begin());
        }
        self.filling = false;
        self.again = false;
        self.ctl = None;
        None
    }
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

    /// No fill is running for any instance (the shutdown waits for this, as does
    /// `Harness::field_cache_filled`).
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
    /// running already gets one more run after it instead of a second one beside it. Nothing
    /// starts once the shutdown began.
    pub(crate) fn spawn_fill(engine: &Arc<Engine>, instance_id: &str) {
        if disabled(engine) {
            return;
        }
        let ctl = {
            let mut map = engine.field_cache().lock();
            // Read under the lock `cancel_all` takes: a fill either starts before the shutdown's
            // cancel (and is cancelled by it) or not at all.
            if engine.is_shutting_down() {
                return;
            }
            let entry = map.entry(instance_id.to_owned()).or_default();
            if entry.filling {
                entry.again = true;
                return;
            }
            entry.begin()
        };
        spawn(engine, instance_id, ctl);
    }

    /// A Jira read preview of `instance_id` is being built: a background fill when the last one
    /// started at least [`FIELD_CACHE_TTL`] ago ([`FIELD_CACHE_RETRY`] after a failure) or never,
    /// unless one is running or the shutdown began. The preview itself uses
    /// [`FieldCache::snapshot`] as it is.
    pub(crate) fn refresh_if_stale(engine: &Arc<Engine>, instance_id: &str) {
        if disabled(engine) {
            return;
        }
        let now = engine.clock().now_utc();
        let ctl = {
            let mut map = engine.field_cache().lock();
            if engine.is_shutting_down() {
                return;
            }
            let entry = map.entry(instance_id.to_owned()).or_default();
            if !entry.due(now) {
                return;
            }
            entry.begin()
        };
        spawn(engine, instance_id, ctl);
    }

    /// §2.5: the shutdown began (no fill starts any more): every running fill is cancelled and
    /// none runs again. Never waits; [`FieldCache::idle`] says when they ended.
    pub(crate) fn cancel_all(&self) {
        for entry in self.lock().values_mut() {
            entry.again = false;
            if let Some(ctl) = &entry.ctl {
                ctl.cancel();
            }
        }
    }

    /// `instance_id` moved to another origin (T8 review M-5): the old server's names are dropped,
    /// a fill running now keeps nothing, and the next preview build may fill at once.
    pub(crate) fn forget(&self, instance_id: &str) {
        let old = self.lock().get_mut(instance_id).and_then(|e| {
            e.generation = e.generation.wrapping_add(1);
            e.attempted = None;
            e.names.take()
        });
        drop(old);
    }

    fn generation(&self, instance_id: &str) -> u64 {
        self.lock().get(instance_id).map_or(0, |e| e.generation)
    }

    fn ended(
        &self,
        instance_id: &str,
        generation: u64,
        started: UtcInstant,
        filled: Filled,
        now: UtcInstant,
    ) {
        let old = self
            .lock()
            .get_mut(instance_id)
            .and_then(|e| e.ended(generation, started, filled, now));
        drop(old);
    }

    /// After a run: the next run's cancel handle when another was asked for; otherwise the
    /// instance is no longer filling, decided under one lock so that a request arriving now
    /// starts a fill of its own instead of being lost.
    fn run_again(&self, engine: &Engine, instance_id: &str) -> Option<FetchControl> {
        let mut map = self.lock();
        let shutting_down = engine.is_shutting_down();
        map.get_mut(instance_id)
            .and_then(|e| e.run_ended(shutting_down))
    }

    /// A fill task was dropped or panicked before [`FieldCache::run_again`] ended it: the
    /// instance may fill again.
    fn finish(&self, instance_id: &str) {
        if let Some(entry) = self.lock().get_mut(instance_id) {
            entry.filling = false;
            entry.again = false;
            entry.ctl = None;
        }
    }
}

/// `now` is at least `wait` after `then`; a wall clock that went backwards counts as waited too.
fn waited(then: UtcInstant, now: UtcInstant, wait: Duration) -> bool {
    let wait = i64::try_from(wait.as_millis()).unwrap_or(i64::MAX);
    now.0 < then.0 || now.0.saturating_sub(then.0) >= wait
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

fn spawn(engine: &Arc<Engine>, instance_id: &str, ctl: FetchControl) {
    let mut running = Running {
        engine: engine.clone(),
        instance_id: instance_id.to_owned(),
        ended: false,
    };
    engine.spawn_detached(async move {
        let mut ctl = ctl;
        loop {
            fill(&running.engine, &running.instance_id, &ctl).await;
            let next = running
                .engine
                .field_cache()
                .run_again(&running.engine, &running.instance_id);
            match next {
                Some(next) => ctl = next,
                None => {
                    running.end();
                    break;
                }
            }
        }
    });
}

/// What one fill came to.
enum Filled {
    Names(FieldNames),
    /// Not a Jira instance in state `ok` (any more): nothing was sent or recorded.
    Skipped,
    /// The shutdown cancelled it: before its start record nothing was recorded; after it the
    /// result record says `class: cancelled`.
    Cancelled,
    Failed,
}

async fn fill(engine: &Arc<Engine>, instance_id: &str, ctl: &FetchControl) {
    let cache = engine.field_cache();
    let generation = cache.generation(instance_id);
    let started = engine.clock().now_utc();
    let filled = fetch(engine, instance_id, ctl).await;
    match &filled {
        Filled::Failed => tracing::warn!(event = FAILED_EVENT),
        Filled::Names(names) if names.capped() > 0 => {
            tracing::warn!(event = CAPPED_EVENT, capped = names.capped());
        }
        _ => {}
    }
    cache.ended(
        instance_id,
        generation,
        started,
        filled,
        engine.clock().now_utc(),
    );
}

/// The fill's one GET under `SYSTEM_FETCH {purpose: metadata_cache}` (as `identity::run` does
/// for `token_recheck`).
async fn fetch(engine: &Arc<Engine>, instance_id: &str, ctl: &FetchControl) -> Filled {
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
    // Cancelled by the shutdown before the start record: nothing is recorded or sent.
    if ctl.is_cancelled() {
        return Filled::Cancelled;
    }
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
            // A cancel (the shutdown) ends the GET at its next await point, before it is sent if
            // it comes first; the result record below is written all the same.
            let outcome = http.client.get_ctl(&cover, &call, ctl).await;
            #[cfg(feature = "testing")]
            if let Some(p) = engine.hooks().pause_before_cache_result.clone() {
                p.hold().await;
            }
            let (base, iid, fid) = (
                http.client.base().clone(),
                instance_id.to_owned(),
                fetch_id.clone(),
            );
            // The record carries up to 32 MiB: it is built on a blocking thread (review I-2).
            // Audit before effect: an unrecorded answer is not used.
            engine
                .blocking(move |p| {
                    let record = system_get_record(purpose, &iid, &fid, &base, &call, &outcome);
                    p.append(record).map(|_| outcome)
                })
                .await
                .ok()
        }
        Err(_) => None,
    };
    engine.committed().forget_fetch(&fetch_id);
    let Some(outcome) = outcome else {
        return Filled::Failed;
    };
    if ctl.is_cancelled() {
        return Filled::Cancelled;
    }
    // The M3 per-response identity check failed (or a JSON 401): the token re-check decides
    // the instance; the map stays as it was. Not once the shutdown began: the re-check's own
    // records would follow `APP_STOP`.
    if identity::trigger(&outcome).is_some() {
        if !engine.is_shutting_down() {
            let _ = identity::recheck(engine, instance_id, seen).await;
        }
        return Filled::Failed;
    }
    match outcome {
        FetchOutcome::Response(r) if (200..300).contains(&r.status) => {
            // Up to 32 MiB of JSON is CPU work (review I-2).
            tokio::task::spawn_blocking(move || FieldNames::parse(&r.body))
                .await
                .ok()
                .flatten()
                .map_or(Filled::Failed, Filled::Names)
        }
        _ => Filled::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: UtcInstant = UtcInstant(1_000_000);

    fn at(secs: u64) -> UtcInstant {
        UtcInstant(T0.0 + i64::try_from(secs * 1000).unwrap_or(i64::MAX))
    }

    /// A run of `filled` that started at `T0`, ended through `run_ended`.
    fn run(entry: &mut Entry, filled: Filled) {
        let _ctl = entry.begin();
        entry.ended(entry.generation, T0, filled, T0);
        assert!(entry.run_ended(false).is_none());
    }

    /// T8 review M-3: a skipped fill (the instance is not an `ok` Jira instance) spends nothing:
    /// once the instance is usable the next preview build fills at once.
    #[test]
    fn a_skipped_fill_spends_no_ttl() {
        let mut never = Entry::default();
        run(&mut never, Filled::Skipped);
        assert!(never.due(T0));
        let mut filled = Entry::default();
        run(&mut filled, Filled::Names(FieldNames::default()));
        run(&mut filled, Filled::Skipped);
        // Still the success's hour, not a new one from the skipped run.
        assert!(!filled.due(at(3599)));
        assert!(filled.due(at(3600)));
    }

    /// Lead ruling (T8 review M-4): 5 min after a failure, 1 h after a success.
    #[test]
    fn failure_backoff_is_five_minutes() {
        let mut e = Entry::default();
        run(&mut e, Filled::Failed);
        assert!(!e.due(at(299)));
        assert!(e.due(at(300)));
        run(&mut e, Filled::Names(FieldNames::default()));
        assert!(!e.due(at(300)));
        assert!(e.due(at(3600)));
        // A cancelled fill (the shutdown) changes nothing either.
        run(&mut e, Filled::Cancelled);
        assert!(!e.due(at(300)));
        assert_eq!(e.failures, 1);
    }

    /// An origin change between a fill's start and its end: the old server's answer is not kept.
    #[test]
    fn a_fill_across_an_origin_change_keeps_nothing() {
        let mut e = Entry::default();
        let _ctl = e.begin();
        let generation = e.generation;
        e.generation += 1;
        let names = FieldNames::from(BTreeMap::from([("a".to_owned(), "A".to_owned())]));
        e.ended(generation, T0, Filled::Names(names), T0);
        assert!(e.run_ended(false).is_none());
        assert!(e.names.is_none());
        assert!(e.due(T0), "the schedule stays as the origin change left it");
    }

    #[test]
    fn a_shutdown_ends_the_run_instead_of_running_again() {
        let mut e = Entry::default();
        let _ctl = e.begin();
        e.again = true;
        assert!(e.run_ended(true).is_none());
        assert!(!e.filling && !e.again && e.ctl.is_none());
        let _ctl = e.begin();
        e.again = true;
        assert!(e.run_ended(false).is_some());
        assert!(e.filling);
    }
}
