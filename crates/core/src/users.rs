//! Confluence user resolution (§7.6, PD-99, Task 11): the per-instance user cache and the lookup
//! pass of a Markdown page read.
//!
//! A `ri:user` mention of a page body read as Markdown names a user key. Before the read's
//! `READ_FETCHED` (or a host call's `SCRIPT_CALL`) is committed, every key of the body is
//! resolved: from the [`UserCache`] first, then for misses by `GET /rest/api/user?key=<key>`
//! under the request's cover, through the instance client (limiter, method guard) and the read's
//! own `FetchControl`. The lookups are **sequential**: each one's `PREVIEW_FETCH {purpose:
//! resolve}` is committed before the next GET leaves, as in the staged enrichment driver, so at
//! most one is in flight; a cancel or a quit records that one (`cancelled_in_flight`). At most
//! [`MAX_LOOKUPS`] fresh lookups run per read, none once fewer than [`LOOKUP_RESERVE`] of the read
//! budget remain or once another answer of [`MAX_LOOKUP_BYTES`] could pass the read's byte cap,
//! and a key longer than [`MAX_KEY_CHARS`] or holding a control character is never looked up:
//! those keys, and every answer that is not a 2xx JSON object for the key asked with a usable
//! `username`, become `null` (display only: a lookup never fails the read). Each answer is cut at
//! [`MAX_LOOKUP_BYTES`] and at the read's deadline (T11 review I-2), so the read ends within its
//! budget.
//!
//! The map the pass returns is the one committed and the one the normalization converts with
//! (`read::normalize`); the cache is never read again for that candidate, so a cache change after
//! the fetch changes no candidate (§5.2, I-37). The cache is display-only: nothing in validation
//! reads it (§2.3), and it holds no request data.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use atlas_duck_atlassian::{
    AuditCover, FetchControl, FetchFailure, FetchOutcome, GetCall, InstanceClient,
};
use atlas_duck_audit::{NewEvent, UtcInstant};
use atlas_duck_convert::UserResolutions;
use serde_json::Value;
use tokio::time::Instant;

use crate::engine::script::RunShared;
use crate::engine::write::{call_path, get_record, park};
use crate::engine::{Engine, InFlight, RequestEntry};
use crate::payloads::{EventCtx, PreviewFetchPurpose};

/// PD-99: an entry is used for this long after the answer it came from.
pub const USER_CACHE_TTL: Duration = Duration::from_secs(3600);
/// PD-99: the most entries one instance's cache keeps (least recently used out first).
pub const USER_CACHE_MAX: usize = 10_000;
/// PD-99: fresh lookups per read (the further keys become `null`).
pub const MAX_LOOKUPS: usize = 50;
/// PD-99: no lookup starts once less than this much of the read budget remains.
pub const LOOKUP_RESERVE: Duration = Duration::from_secs(20);
/// PD-99: a longer key is not looked up (nor is one holding a control character).
pub const MAX_KEY_CHARS: usize = 255;
/// The most bytes of one lookup answer received (T11 review I-2): a Confluence DC user object is
/// about 1 KiB. A longer answer is cut there (`too_large`), recorded with what arrived, and the
/// key is `null`.
pub const MAX_LOOKUP_BYTES: u64 = 64 * 1024;
/// The longest username kept, the converter's own limit for a rendered mention (PD-95).
const MAX_USERNAME_CHARS: usize = 255;
/// `GET /rest/api/user?key=` (§7.6).
const USER_PATH: &str = "/rest/api/user";

/// A direct read's content (at most the 32 MiB response cap) and all its lookups fit in the
/// 50 MiB read byte cap, so the byte rule never closes a direct read's pass early by default.
const _: () =
    assert!(32 * 1024 * 1024 + MAX_LOOKUPS as u64 * (MAX_LOOKUP_BYTES + 1) <= 50 * 1024 * 1024);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One cached answer: the username (`None`: no such user), when it arrived, its LRU tick.
struct Cached {
    name: Option<String>,
    at: UtcInstant,
    tick: u64,
}

/// One instance's entries in least-recently-used order.
#[derive(Default)]
struct InstanceUsers {
    map: HashMap<String, Cached>,
    /// tick → key; the first entry is the least recently used.
    order: BTreeMap<u64, String>,
    tick: u64,
    /// Bumped by every [`UserCache::clear`]: an answer of a pass that began before the clear is
    /// not stored (T11 review m-1).
    generation: u64,
}

impl InstanceUsers {
    fn touch(&mut self, key: &str) {
        self.tick += 1;
        let tick = self.tick;
        if let Some(c) = self.map.get_mut(key) {
            self.order.remove(&c.tick);
            c.tick = tick;
            self.order.insert(tick, key.to_owned());
        }
    }

    fn remove(&mut self, key: &str) {
        if let Some(c) = self.map.remove(key) {
            self.order.remove(&c.tick);
        }
    }

    /// The cached answer for `key` (an expired one is dropped), refreshing its LRU position.
    fn hit(&mut self, key: &str, now: UtcInstant) -> Option<Option<String>> {
        let at = self.map.get(key)?.at;
        if expired(at, now) {
            self.remove(key);
            return None;
        }
        self.touch(key);
        self.map.get(key).map(|c| c.name.clone())
    }
}

/// PD-99 (Δ3): the per-instance `user key → Option<username>` cache, crate-private. Every method
/// takes the lock, changes the map and drops it: nothing here awaits, and no lock is held across
/// an `.await` by any caller.
#[derive(Default)]
pub(crate) struct UserCache {
    inner: Mutex<HashMap<String, InstanceUsers>>,
}

/// Counts only (§7.7): keys and usernames are Atlassian data.
impl fmt::Debug for UserCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let g = lock(&self.inner);
        f.debug_struct("UserCache")
            .field("instances", &g.len())
            .field("entries", &g.values().map(|u| u.map.len()).sum::<usize>())
            .finish()
    }
}

/// `at` is at least [`USER_CACHE_TTL`] before `now`.
fn expired(at: UtcInstant, now: UtcInstant) -> bool {
    let ttl = i64::try_from(USER_CACHE_TTL.as_millis()).unwrap_or(i64::MAX);
    now.0.saturating_sub(at.0) >= ttl
}

impl UserCache {
    /// The cached answer for `key` of `instance_id` (`Some(None)`: the user does not exist), or
    /// `None` when nothing usable is cached. Never awaits. Tests only: a pass reads through
    /// [`UserCache::snapshot`].
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn get(
        &self,
        instance_id: &str,
        key: &str,
        now: UtcInstant,
    ) -> Option<Option<String>> {
        lock(&self.inner).get_mut(instance_id)?.hit(key, now)
    }

    /// The start of a pass, under one lock (T11 review m-6): the instance's current generation
    /// and the cached answer of every key of `keys` that has one.
    pub(crate) fn snapshot(
        &self,
        instance_id: &str,
        keys: &BTreeSet<String>,
        now: UtcInstant,
    ) -> (u64, BTreeMap<String, Option<String>>) {
        let mut g = lock(&self.inner);
        let Some(users) = g.get_mut(instance_id) else {
            return (0, BTreeMap::new());
        };
        let hits = keys
            .iter()
            .filter_map(|k| users.hit(k, now).map(|hit| (k.clone(), hit)))
            .collect();
        (users.generation, hits)
    }

    /// The instance's current generation (what a pass starting now would read). Tests only.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn generation(&self, instance_id: &str) -> u64 {
        lock(&self.inner)
            .get(instance_id)
            .map_or(0, |u| u.generation)
    }

    /// Stores the answer for `key` that arrived at `now`, evicting the least recently used entry
    /// beyond [`USER_CACHE_MAX`]. Dropped when the instance was cleared since `generation` was
    /// read: the answer came under the old PAT or origin (T11 review m-1).
    pub(crate) fn put(
        &self,
        instance_id: &str,
        generation: u64,
        key: &str,
        name: Option<String>,
        now: UtcInstant,
    ) {
        let mut g = lock(&self.inner);
        let users = g.entry(instance_id.to_owned()).or_default();
        if users.generation != generation {
            return;
        }
        users.remove(key);
        users.tick += 1;
        let tick = users.tick;
        users.map.insert(
            key.to_owned(),
            Cached {
                name,
                at: now,
                tick,
            },
        );
        users.order.insert(tick, key.to_owned());
        while users.map.len() > USER_CACHE_MAX {
            let Some((_, oldest)) = users.order.pop_first() else {
                break;
            };
            users.map.remove(&oldest);
        }
    }

    /// PD-99: forgets every entry of `instance_id` (its PAT or its origin changed) and starts a
    /// new generation, so a lookup still in flight from before stores nothing. The (then empty)
    /// entry stays for the life of the process: removing it would reset the generation to 0 and
    /// let a stale lookup store its answer (ABA).
    pub(crate) fn clear(&self, instance_id: &str) {
        let mut g = lock(&self.inner);
        let users = g.entry(instance_id.to_owned()).or_default();
        users.map.clear();
        users.order.clear();
        users.generation += 1;
    }
}

/// A key the pass may send (PD-99): at most [`MAX_KEY_CHARS`] chars, no control character.
fn lookable(key: &str) -> bool {
    key.chars().nth(MAX_KEY_CHARS).is_none() && !key.chars().any(char::is_control)
}

/// What a lookup answer says about `key`.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    /// A 2xx JSON object for `key` whose `username` the converter would render (non-empty, at
    /// most 255 chars, no control character): cached.
    Name(String),
    /// A definitive "no usable name": a JSON 404, or a 2xx JSON object for `key` without a usable
    /// `username` (T11 review m-3). Cached as `None`, so such a page does not cost its lookups on
    /// every read.
    NoUser,
    /// Anything else (a timeout, a cut answer, a 5xx, a 401, a 404 without JSON, an object for
    /// another key, T11 review m-2): `null`, not cached, so a transient failure does not hide a
    /// user for an hour.
    Unknown,
}

impl Answer {
    fn name(&self) -> Option<String> {
        match self {
            Answer::Name(n) => Some(n.clone()),
            Answer::NoUser | Answer::Unknown => None,
        }
    }
}

fn answer(outcome: &FetchOutcome, key: &str) -> Answer {
    let FetchOutcome::Response(r) = outcome else {
        return Answer::Unknown;
    };
    if !is_json(r) {
        return Answer::Unknown;
    }
    if r.status == 404 {
        return Answer::NoUser;
    }
    if !(200..300).contains(&r.status) {
        return Answer::Unknown;
    }
    let Ok(v) = serde_json::from_slice::<Value>(&r.body) else {
        return Answer::Unknown;
    };
    if v.get("userKey").and_then(Value::as_str) != Some(key) {
        return Answer::Unknown;
    }
    let usable = |name: &&str| {
        !name.is_empty()
            && name.chars().nth(MAX_USERNAME_CHARS).is_none()
            && !name.chars().any(char::is_control)
    };
    match v.get("username").and_then(Value::as_str).filter(usable) {
        Some(name) => Answer::Name(name.to_owned()),
        None => Answer::NoUser,
    }
}

fn is_json(r: &atlas_duck_atlassian::UpstreamResponse) -> bool {
    r.content_type
        .as_deref()
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("json"))
}

/// The bytes of the answer a lookup received (what its record holds), for the byte rule.
fn received_bytes(outcome: &FetchOutcome) -> u64 {
    let n = match outcome {
        FetchOutcome::Response(r) => r.body.len(),
        FetchOutcome::Failed(f) => match f {
            FetchFailure::StatusHeaderDecided { response, .. }
            | FetchFailure::BodyDecided { response, .. }
            | FetchFailure::IdentityCheckFailed { response, .. } => response.body.len(),
            FetchFailure::PostSend { received, .. } => received.len(),
            FetchFailure::CancelledInFlight { bytes_received } => bytes_received.len(),
            FetchFailure::PreSendConnection(_)
            | FetchFailure::OriginGuardRefused
            | FetchFailure::CancelledBeforeSend
            | FetchFailure::BudgetExpiredBeforeSend
            | FetchFailure::NeedsToken
            | FetchFailure::MethodGuardRefused => 0,
        },
    };
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Where the pass runs, and so where its in-flight lookup and its records go.
pub(crate) enum Site<'a> {
    /// A direct read in `Fetching`: the entry's in-flight slot and parked record, appended while
    /// the request is pending (`Engine::append_pending`).
    Read(&'a Arc<RequestEntry>),
    /// A script's host call: the run's in-flight table entry of the call, appended while the
    /// run is `Running`.
    Script {
        entry: &'a Arc<RequestEntry>,
        shared: &'a Arc<RunShared>,
        call_id: u64,
        ctx: &'a EventCtx,
    },
}

impl Site<'_> {
    fn ctx(&self) -> &EventCtx {
        match self {
            Site::Read(entry) => &entry.ctx,
            Site::Script { ctx, .. } => ctx,
        }
    }

    fn in_flight(&self, f: Option<InFlight>) {
        match self {
            Site::Read(entry) => entry.set_in_flight(f),
            Site::Script {
                shared, call_id, ..
            } => shared.set_lookup(*call_id, f),
        }
    }

    /// The record of a finished lookup, kept until an append commits it (a cancel or the end of
    /// the run in between commits it itself). `TestHooks::pause_after_get` holds here, after the
    /// park, at both sites.
    async fn park(&self, engine: &Arc<Engine>, record: &NewEvent) {
        match self {
            Site::Read(entry) => park(engine, entry, record).await,
            Site::Script {
                shared, call_id, ..
            } => {
                shared.park_lookup(*call_id, record);
                #[cfg(feature = "testing")]
                if let Some(pause) = engine.hooks().pause_after_get.clone() {
                    pause.hold().await;
                }
            }
        }
    }

    /// Commits the parked record; `false`: the request (or the run) ended meanwhile.
    async fn commit(&self, engine: &Arc<Engine>, record: NewEvent) -> bool {
        match self {
            Site::Read(entry) => engine.append_pending(entry, vec![record], None).await,
            Site::Script {
                entry,
                shared,
                call_id,
                ..
            } => crate::engine::script::append_lookup(engine, entry, shared, *call_id).await,
        }
    }
}

/// The read the pass runs in.
pub(crate) struct Pass<'a> {
    pub engine: &'a Arc<Engine>,
    pub site: Site<'a>,
    pub instance_id: &'a str,
    pub client: &'a InstanceClient,
    pub cover: &'a AuditCover,
    /// The read's own control (a cancel aborts the lookup with the read).
    pub ctl: &'a FetchControl,
    /// The end of the read budget.
    pub deadline: Instant,
    /// The bytes the lookups may receive in all: the read's byte cap less its content (a direct
    /// read: the 50 MiB read cap; a host call: what is left of the run's `max_fetch_mb`).
    pub max_bytes: u64,
}

/// What a pass gives: the map to commit and the bytes its lookups received.
pub(crate) struct Resolved {
    pub users: UserResolutions,
    pub bytes: u64,
}

/// The request ended (a cancel, an expiry, a quit, an append that failed) while the pass ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cancelled;

/// PD-99: resolves every key of `keys` (in their order), cache hits first; see the module doc.
pub(crate) async fn resolve_users(
    p: &Pass<'_>,
    keys: &BTreeSet<String>,
) -> Result<Resolved, Cancelled> {
    let (generation, mut hits) =
        p.engine
            .user_cache()
            .snapshot(p.instance_id, keys, p.engine.clock().now_utc());
    let mut map = UserResolutions::new();
    let mut sent = 0usize;
    let mut used = 0u64;
    // Once closed (the cap, the budget's reserve, the byte cap), no lookup starts again in this
    // read.
    let mut open = true;
    let reserve = lookup_reserve(p);
    for key in keys {
        if let Some(hit) = hits.remove(key) {
            map.insert(key.clone(), hit);
            continue;
        }
        if open
            && (sent >= MAX_LOOKUPS
                || used.saturating_add(MAX_LOOKUP_BYTES + 1) > p.max_bytes
                || p.deadline.saturating_duration_since(Instant::now()) < reserve)
        {
            open = false;
        }
        if !open || !lookable(key) {
            map.insert(key.clone(), None);
            continue;
        }
        sent += 1;
        let (name, bytes) = lookup(p, generation, key).await?;
        used = used.saturating_add(bytes);
        map.insert(key.clone(), name);
    }
    #[cfg(feature = "testing")]
    if let Some(pause) = p.engine.hooks().pause_after_lookups.clone() {
        pause.hold().await;
    }
    Ok(Resolved {
        users: map,
        bytes: used,
    })
}

/// [`LOOKUP_RESERVE`]; a test hook shortens it (T11 fix review m-4).
fn lookup_reserve(p: &Pass<'_>) -> Duration {
    #[cfg(feature = "testing")]
    if let Some(r) = p.engine.hooks().lookup_reserve {
        return r;
    }
    let _ = p;
    LOOKUP_RESERVE
}

/// One `GET /rest/api/user?key=<key>`, recorded and committed before the pass goes on; gives the
/// name and the bytes received.
async fn lookup(
    p: &Pass<'_>,
    generation: u64,
    key: &str,
) -> Result<(Option<String>, u64), Cancelled> {
    let call = GetCall {
        endpoint_template: USER_PATH.to_owned(),
        params: Value::Null,
        query: vec![("key".to_owned(), key.to_owned())],
    };
    let base = p.client.base();
    p.site.in_flight(Some(InFlight {
        purpose: PreviewFetchPurpose::Resolve,
        path: call_path(base, &call),
    }));
    let outcome = p
        .client
        .get_bounded_ctl(p.cover, &call, p.ctl, MAX_LOOKUP_BYTES, p.deadline)
        .await;
    if matches!(
        outcome,
        FetchOutcome::Failed(
            FetchFailure::CancelledInFlight { .. } | FetchFailure::CancelledBeforeSend
        )
    ) {
        // The cancel took the control in its gated section and recorded this GET. The in-flight
        // mark stays: the request is ending (its terminal control drop clears it).
        return Err(Cancelled);
    }
    let record = get_record(
        p.site.ctx(),
        PreviewFetchPurpose::Resolve,
        base,
        &call,
        &outcome,
    );
    #[cfg(feature = "testing")]
    if let Some(pause) = p.engine.hooks().pause_before_lookup_park.clone() {
        pause.hold().await;
    }
    // T11 review I-1: the in-flight mark is cleared only once the record is parked, so a cancel
    // at any point records this GET once: before the park as in flight, after it from the parked
    // record (which then skips the in-flight one). Never after the commit: the commit takes the
    // parked record, and a cancel then would record the GET again from a stale mark.
    p.site.park(p.engine, &record).await;
    p.site.in_flight(None);
    if !p.site.commit(p.engine, record).await {
        return Err(Cancelled);
    }
    let answer = answer(&outcome, key);
    let name = answer.name();
    if answer != Answer::Unknown {
        let now = p.engine.clock().now_utc();
        p.engine
            .user_cache()
            .put(p.instance_id, generation, key, name.clone(), now);
    }
    Ok((name, received_bytes(&outcome)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const I: &str = "inst-a";

    fn at(ms: i64) -> UtcInstant {
        UtcInstant(ms)
    }

    #[test]
    fn get_put_ttl_and_clear() {
        let c = UserCache::default();
        assert_eq!(c.get(I, "k", at(0)), None);
        c.put(I, 0, "k", Some("jdoe".into()), at(0));
        c.put(I, 0, "gone", None, at(0));
        assert_eq!(c.get(I, "k", at(1)), Some(Some("jdoe".into())));
        assert_eq!(c.get(I, "gone", at(1)), Some(None));
        assert_eq!(c.get("inst-b", "k", at(1)), None, "per instance");
        let ttl = i64::try_from(USER_CACHE_TTL.as_millis()).unwrap_or(i64::MAX);
        assert_eq!(c.get(I, "k", at(ttl - 1)), Some(Some("jdoe".into())));
        assert_eq!(
            c.get(I, "k", at(ttl)),
            None,
            "expired one hour after the answer"
        );
        c.clear(I);
        assert_eq!(c.get(I, "gone", at(1)), None);
    }

    /// T11 review m-1: an answer of a pass that began before a clear is not stored.
    #[test]
    fn put_after_a_clear_is_dropped() {
        let c = UserCache::default();
        let g0 = c.generation(I);
        c.put(I, g0, "k", Some("old".into()), at(0));
        c.clear(I);
        c.put(I, g0, "k", Some("old".into()), at(1));
        c.put(I, g0, "k2", None, at(1));
        assert_eq!(c.get(I, "k", at(1)), None);
        assert_eq!(c.get(I, "k2", at(1)), None);
        let g1 = c.generation(I);
        assert_ne!(g1, g0);
        c.put(I, g1, "k", Some("new".into()), at(1));
        assert_eq!(c.get(I, "k", at(1)), Some(Some("new".into())));
        // Another instance's clear changes nothing here.
        c.clear("inst-b");
        assert_eq!(c.generation(I), g1);
    }

    #[test]
    fn snapshot_is_the_hits_and_the_generation() {
        let c = UserCache::default();
        let keys: BTreeSet<String> = ["a", "b", "c"].iter().map(|k| (*k).to_owned()).collect();
        assert_eq!(c.snapshot(I, &keys, at(0)), (0, BTreeMap::new()));
        c.put(I, 0, "a", Some("x".into()), at(0));
        c.put(I, 0, "c", None, at(0));
        c.put(I, 0, "z", Some("z".into()), at(0));
        c.clear("inst-b");
        let (g, hits) = c.snapshot(I, &keys, at(1));
        assert_eq!(g, 0);
        let want: BTreeMap<String, Option<String>> = [
            ("a".to_owned(), Some("x".to_owned())),
            ("c".to_owned(), None),
        ]
        .into_iter()
        .collect();
        assert_eq!(hits, want);
        c.clear(I);
        assert_eq!(c.snapshot(I, &keys, at(1)), (1, BTreeMap::new()));
    }

    #[test]
    fn least_recently_used_goes_first() {
        let c = UserCache::default();
        for n in 0..USER_CACHE_MAX {
            c.put(I, 0, &format!("k{n}"), None, at(0));
        }
        // `k0` is used again, so `k1` is now the oldest.
        assert_eq!(c.get(I, "k0", at(0)), Some(None));
        c.put(I, 0, "new", None, at(0));
        assert_eq!(c.get(I, "k0", at(0)), Some(None));
        assert_eq!(c.get(I, "k1", at(0)), None);
        assert_eq!(c.get(I, "new", at(0)), Some(None));
        let g = lock(&c.inner);
        let users = g.get(I).map(|u| (u.map.len(), u.order.len()));
        assert_eq!(users, Some((USER_CACHE_MAX, USER_CACHE_MAX)));
    }

    #[test]
    fn lookable_keys() {
        assert!(lookable("8a7f808a1"));
        assert!(lookable("a&b#c/d e"));
        assert!(lookable(&"k".repeat(MAX_KEY_CHARS)));
        assert!(!lookable(&"k".repeat(MAX_KEY_CHARS + 1)));
        assert!(!lookable("a\u{1}b"));
        assert!(!lookable("a\u{7f}b"));
        assert!(!lookable("a\tb"));
    }

    #[test]
    fn answers() {
        let reply = |status: u16, ct: Option<&str>, body: &str| {
            FetchOutcome::Response(atlas_duck_atlassian::UpstreamResponse {
                status,
                content_type: ct.map(str::to_owned),
                body: body.as_bytes().to_vec(),
            })
        };
        let json = Some("application/json;charset=UTF-8");
        let k = "key-1";
        let name = |n: &str| Answer::Name(n.to_owned());
        assert_eq!(
            answer(
                &reply(200, json, r#"{"username":"jdoe","userKey":"key-1"}"#),
                k
            ),
            name("jdoe")
        );
        assert_eq!(
            answer(
                &reply(200, None, r#"{"username":"jdoe","userKey":"key-1"}"#),
                k
            ),
            Answer::Unknown
        );
        // m-2: an object for another key (or for no key) is never taken for this one.
        assert_eq!(
            answer(
                &reply(200, json, r#"{"username":"x","userKey":"other"}"#),
                k
            ),
            Answer::Unknown
        );
        assert_eq!(
            answer(&reply(200, json, r#"{"username":"jdoe"}"#), k),
            Answer::Unknown
        );
        assert_eq!(
            answer(&reply(200, json, r#"{"username":"jdoe","userKey":7}"#), k),
            Answer::Unknown
        );
        // m-3: an object for this key without a usable username is definitive.
        for body in [
            r#"{"username":"","userKey":"key-1"}"#,
            r#"{"username":7,"userKey":"key-1"}"#,
            r#"{"name":"jdoe","userKey":"key-1"}"#,
            r#"{"username":"a\u0007b","userKey":"key-1"}"#,
        ] {
            assert_eq!(answer(&reply(200, json, body), k), Answer::NoUser, "{body}");
        }
        let long = format!(
            r#"{{"username":"{}","userKey":"key-1"}}"#,
            "n".repeat(MAX_USERNAME_CHARS + 1)
        );
        assert_eq!(answer(&reply(200, json, &long), k), Answer::NoUser);
        assert_eq!(answer(&reply(200, json, "{"), k), Answer::Unknown);
        assert_eq!(answer(&reply(404, json, "{}"), k), Answer::NoUser);
        assert_eq!(
            answer(
                &reply(404, json, r#"{"username":"jdoe","userKey":"key-1"}"#),
                k
            ),
            Answer::NoUser
        );
        assert_eq!(answer(&reply(404, None, ""), k), Answer::Unknown);
        assert_eq!(answer(&reply(503, json, "{}"), k), Answer::Unknown);
        assert_eq!(answer(&reply(401, json, "{}"), k), Answer::Unknown);
        let cut = FetchOutcome::Failed(FetchFailure::PostSend {
            kind: atlas_duck_atlassian::PostSendKind::ResponseCap32MiB,
            received: vec![b' '; 10],
        });
        assert_eq!(answer(&cut, k), Answer::Unknown);
        assert_eq!(received_bytes(&cut), 10);
        assert_eq!(received_bytes(&reply(200, json, "{}")), 2);
        assert_eq!(
            received_bytes(&FetchOutcome::Failed(FetchFailure::BudgetExpiredBeforeSend)),
            0
        );
    }
}
