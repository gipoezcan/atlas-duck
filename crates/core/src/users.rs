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
//! budget remain, and a key longer than [`MAX_KEY_CHARS`] or holding a control character is never
//! looked up: those keys, and every answer that is not a 2xx JSON object with a usable
//! `username`, become `null` (display only: a lookup never fails the read).
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
/// The longest username kept, the converter's own limit for a rendered mention (PD-95).
const MAX_USERNAME_CHARS: usize = 255;
/// `GET /rest/api/user?key=` (§7.6).
const USER_PATH: &str = "/rest/api/user";

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
    /// `None` when nothing usable is cached. Never awaits.
    pub(crate) fn get(
        &self,
        instance_id: &str,
        key: &str,
        now: UtcInstant,
    ) -> Option<Option<String>> {
        let mut g = lock(&self.inner);
        let users = g.get_mut(instance_id)?;
        let at = users.map.get(key)?.at;
        if expired(at, now) {
            users.remove(key);
            return None;
        }
        users.touch(key);
        users.map.get(key).map(|c| c.name.clone())
    }

    /// Stores the answer for `key` that arrived at `now`, evicting the least recently used entry
    /// beyond [`USER_CACHE_MAX`].
    pub(crate) fn put(&self, instance_id: &str, key: &str, name: Option<String>, now: UtcInstant) {
        let mut g = lock(&self.inner);
        let users = g.entry(instance_id.to_owned()).or_default();
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

    /// PD-99: forgets every entry of `instance_id` (its PAT or its origin changed).
    pub(crate) fn clear(&self, instance_id: &str) {
        lock(&self.inner).remove(instance_id);
    }
}

/// A key the pass may send (PD-99): at most [`MAX_KEY_CHARS`] chars, no control character.
fn lookable(key: &str) -> bool {
    key.chars().nth(MAX_KEY_CHARS).is_none() && !key.chars().any(char::is_control)
}

/// The username of a lookup answer: a 2xx JSON object whose `username` is a string the converter
/// would render (non-empty, at most 255 chars, no control character); anything else is `None`.
fn username(outcome: &FetchOutcome) -> Option<String> {
    let FetchOutcome::Response(r) = outcome else {
        return None;
    };
    if !(200..300).contains(&r.status) || !is_json(r) {
        return None;
    }
    let v: Value = serde_json::from_slice(&r.body).ok()?;
    let name = v.get("username")?.as_str()?;
    let usable = !name.is_empty()
        && name.chars().nth(MAX_USERNAME_CHARS).is_none()
        && !name.chars().any(char::is_control);
    usable.then(|| name.to_owned())
}

fn is_json(r: &atlas_duck_atlassian::UpstreamResponse) -> bool {
    r.content_type
        .as_deref()
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("json"))
}

/// The answer is a definitive "no such user" (a JSON 404), cached as `None`; a failure that may
/// pass (a timeout, a 5xx, a 401, a 404 without JSON) is not cached.
fn not_found(outcome: &FetchOutcome) -> bool {
    matches!(outcome, FetchOutcome::Response(r) if r.status == 404 && is_json(r))
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
    /// the run in between commits it itself).
    async fn park(&self, engine: &Arc<Engine>, record: &NewEvent) {
        match self {
            Site::Read(entry) => park(engine, entry, record).await,
            Site::Script {
                shared, call_id, ..
            } => shared.park_lookup(*call_id, record),
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
}

/// The request ended (a cancel, an expiry, a quit, an append that failed) while the pass ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cancelled;

/// PD-99: resolves every key of `keys` (in their order), cache hits first; see the module doc.
pub(crate) async fn resolve_users(
    p: &Pass<'_>,
    keys: &BTreeSet<String>,
) -> Result<UserResolutions, Cancelled> {
    let cache = p.engine.user_cache();
    let mut map = UserResolutions::new();
    let mut sent = 0usize;
    // Once closed (the cap, the budget's reserve), no lookup starts again in this read.
    let mut open = true;
    for key in keys {
        if let Some(hit) = cache.get(p.instance_id, key, p.engine.clock().now_utc()) {
            map.insert(key.clone(), hit);
            continue;
        }
        if open
            && (sent >= MAX_LOOKUPS
                || p.deadline.saturating_duration_since(Instant::now()) < LOOKUP_RESERVE)
        {
            open = false;
        }
        if !open || !lookable(key) {
            map.insert(key.clone(), None);
            continue;
        }
        sent += 1;
        let name = lookup(p, key).await?;
        map.insert(key.clone(), name);
    }
    Ok(map)
}

/// One `GET /rest/api/user?key=<key>`, recorded and committed before the pass goes on.
async fn lookup(p: &Pass<'_>, key: &str) -> Result<Option<String>, Cancelled> {
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
    let outcome = p.client.get_ctl(p.cover, &call, p.ctl).await;
    p.site.in_flight(None);
    if matches!(
        outcome,
        FetchOutcome::Failed(
            FetchFailure::CancelledInFlight { .. } | FetchFailure::CancelledBeforeSend
        )
    ) {
        // The cancel took the control in its gated section and recorded this GET.
        return Err(Cancelled);
    }
    let record = get_record(
        p.site.ctx(),
        PreviewFetchPurpose::Resolve,
        base,
        &call,
        &outcome,
    );
    p.site.park(p.engine, &record).await;
    if !p.site.commit(p.engine, record).await {
        return Err(Cancelled);
    }
    let name = username(&outcome);
    let now = p.engine.clock().now_utc();
    if name.is_some() || not_found(&outcome) {
        p.engine
            .user_cache()
            .put(p.instance_id, key, name.clone(), now);
    }
    Ok(name)
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
        c.put(I, "k", Some("jdoe".into()), at(0));
        c.put(I, "gone", None, at(0));
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

    #[test]
    fn least_recently_used_goes_first() {
        let c = UserCache::default();
        for n in 0..USER_CACHE_MAX {
            c.put(I, &format!("k{n}"), None, at(0));
        }
        // `k0` is used again, so `k1` is now the oldest.
        assert_eq!(c.get(I, "k0", at(0)), Some(None));
        c.put(I, "new", None, at(0));
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
    fn usable_usernames_only() {
        let answer = |status: u16, ct: Option<&str>, body: &str| {
            FetchOutcome::Response(atlas_duck_atlassian::UpstreamResponse {
                status,
                content_type: ct.map(str::to_owned),
                body: body.as_bytes().to_vec(),
            })
        };
        let json = Some("application/json;charset=UTF-8");
        assert_eq!(
            username(&answer(200, json, r#"{"username":"jdoe"}"#)),
            Some("jdoe".to_owned())
        );
        assert_eq!(username(&answer(200, None, r#"{"username":"jdoe"}"#)), None);
        assert_eq!(username(&answer(404, json, r#"{"username":"jdoe"}"#)), None);
        assert_eq!(username(&answer(200, json, r#"{"username":""}"#)), None);
        assert_eq!(username(&answer(200, json, r#"{"username":7}"#)), None);
        assert_eq!(username(&answer(200, json, r#"{"name":"jdoe"}"#)), None);
        assert_eq!(username(&answer(200, json, "{")), None);
        let long = format!(r#"{{"username":"{}"}}"#, "n".repeat(MAX_USERNAME_CHARS + 1));
        assert_eq!(username(&answer(200, json, &long)), None);
        assert_eq!(
            username(&answer(200, json, r#"{"username":"a\u0007b"}"#)),
            None
        );
        assert!(not_found(&answer(404, json, "{}")));
        assert!(!not_found(&answer(404, None, "")));
        assert!(!not_found(&answer(503, json, "{}")));
    }
}
