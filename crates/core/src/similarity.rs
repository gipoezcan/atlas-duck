//! The "possible duplicate" and "similar request" flags (§5.6, L45, RF-4): an in-memory index of
//! recent requests' similarity keys, kept current from submits and terminal states and seeded
//! once at startup from the last 24 h of the log.
//!
//! - **Possible duplicate**: any other *open* request with the same `params_sha256` (§4.4; it
//!   covers op id, instance and params), regardless of session.
//! - **Similar request**: another request of the same op id and instance whose key matches under
//!   the op's `similarity` rule (§2.3, §7.3/§7.4) and that is open, or was decided or executed in
//!   the last 24 h, regardless of `params_sha256` and agent. Exact value match after the stated
//!   normalization only.
//!
//! Nothing here reaches an agent: hits become queue-row fields and Caution warnings of the
//! approvals UI (PD-17), never envelope content.
//!
//! **`Target` keys come from the `target` column's text (plan decision).** Seeding reads
//! `Target` ops from the plaintext `target` column only (§5.6: no decrypt), which holds the
//! op's `target_display`; a live request's key is built from the same text
//! (`target_display(spec, params)`), so live and seeded keys agree by construction. The text
//! is split back into the `target_params` it names (`Param`, `Pair`); `target_display`
//! sanitizes and cuts at 80 scalars, which leaves keys, ids and labels unchanged.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use atlas_duck_audit::{AuditError, Clock, EventHeader, EventType, UtcInstant};
use atlas_duck_preview::warning;
use atlas_duck_registry::{OperationSpec, Product, Similarity, TargetDisplay, target_display};
use serde_json::Value;

use crate::audit_port::AuditPort;
use crate::engine::payload_json;

/// The look-back of "decided or executed" hits and of seeding (§5.6).
pub const SIMILARITY_WINDOW: Duration = Duration::from_secs(24 * 3600);
const WINDOW_MS: i64 = 24 * 3600 * 1000;

/// What two requests of one op and instance are compared by (§5.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SimKey {
    /// The `target_params` values, as the `target` column shows them (module doc).
    Target(Vec<(String, String)>),
    /// Project or space, issue type or parent, and the normalized summary or title.
    Create {
        container: String,
        kind_or_parent: String,
        title_norm: String,
    },
    /// The sprint (`None` for a backlog move) and the moved issue keys.
    MoveIssues {
        sprint: Option<String>,
        issues: BTreeSet<String>,
    },
}

impl SimKey {
    /// `MoveIssues` matches on any shared issue key (and the same sprint); the others on
    /// equality.
    pub fn matches(&self, other: &SimKey) -> bool {
        match (self, other) {
            (
                SimKey::MoveIssues {
                    sprint: a,
                    issues: x,
                },
                SimKey::MoveIssues {
                    sprint: b,
                    issues: y,
                },
            ) => a == b && !x.is_disjoint(y),
            _ => self == other,
        }
    }
}

/// §5.6: trimmed, Unicode full case folding, whitespace runs collapsed to one space.
pub fn normalize_title(s: &str) -> String {
    let folded = icu_casemap::CaseMapperBorrowed::new().fold_string(s);
    folded.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A param as one string: a string as is, anything else compact JSON; absent `""`.
fn scalar(params: &Value, key: &str) -> String {
    match params.get(key) {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// The `Target` key of a `target` column text (module doc).
fn target_key(spec: &OperationSpec, text: &str) -> SimKey {
    let pairs = match spec.target_display {
        TargetDisplay::Param(p) => vec![(p.to_owned(), text.to_owned())],
        TargetDisplay::Pair(a, b) => match text.split_once(" → ") {
            Some((x, y)) => vec![(a.to_owned(), x.to_owned()), (b.to_owned(), y.to_owned())],
            None => vec![("target".to_owned(), text.to_owned())],
        },
        _ => vec![("target".to_owned(), text.to_owned())],
    };
    SimKey::Target(pairs)
}

/// The key of a request of `spec` with `params`; `None` for ops that are never "similar"
/// (searches, ops without `target_params`, scripts).
pub fn sim_key(spec: &OperationSpec, params: &Value) -> Option<SimKey> {
    match spec.similarity {
        Similarity::None => None,
        Similarity::Target => Some(target_key(spec, &target_display(spec, params))),
        Similarity::Create => {
            let (container, kind, title) = match spec.product {
                Product::Jira => ("project", "issuetype", "summary"),
                Product::Confluence => ("space", "parent", "title"),
            };
            Some(SimKey::Create {
                container: scalar(params, container),
                kind_or_parent: scalar(params, kind),
                title_norm: normalize_title(&scalar(params, title)),
            })
        }
        Similarity::MoveIssues => {
            let TargetDisplay::MoveInto {
                sprint_param,
                issues_param,
            } = spec.target_display
            else {
                return None;
            };
            let issues = params
                .get(issues_param)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(|v| match v {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(SimKey::MoveIssues {
                sprint: sprint_param.map(|p| scalar(params, p)),
                issues,
            })
        }
    }
}

/// How a request ended, as far as "similar" cares (§5.6: "decided or executed"). The engine maps
/// its terminal states, seeding the terminal record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimOutcome {
    Released,
    Denied,
    Executed,
    /// A write that failed after its approval (it was decided).
    Failed,
    OutcomeUnknown,
    /// Never decided (rejected, expired, cancelled, abandoned, a direct failure): no longer a
    /// hit, removed.
    Gone,
}

/// A request the index knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimRecord {
    pub request_id: String,
    pub op_id: String,
    pub instance_id: String,
    /// Lowercase hex; `None` for a seeded `Target` request (its payload is not decrypted).
    pub params_sha256: Option<String>,
    pub key: Option<SimKey>,
}

/// The other request a "similar request" flag names, and its state for the Caution text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimHit {
    pub request_id: String,
    /// `"pending"`, `"executed 14:02"`, `"denied 14:02"`, `"released 14:02"`,
    /// `"failed 14:02"` or `"outcome unknown"` (PD-17).
    pub when: String,
}

impl SimHit {
    /// The §6.2 Caution text: "similar to req_… executed 14:02".
    pub fn text(&self) -> String {
        warning::similar_request(&self.request_id, &self.when)
    }
}

#[derive(Debug, Clone)]
struct Entry {
    rec: SimRecord,
    /// `None` while open.
    outcome: Option<(SimOutcome, UtcInstant)>,
}

#[derive(Debug, Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    /// Request ids per (op id, instance id).
    by_scope: HashMap<(String, String), BTreeSet<String>>,
}

impl Inner {
    fn insert(&mut self, rec: SimRecord, outcome: Option<(SimOutcome, UtcInstant)>) {
        if rec.key.is_some() {
            self.by_scope
                .entry((rec.op_id.clone(), rec.instance_id.clone()))
                .or_default()
                .insert(rec.request_id.clone());
        }
        let id = rec.request_id.clone();
        self.entries.insert(id, Entry { rec, outcome });
    }

    fn remove(&mut self, id: &str) {
        if let Some(e) = self.entries.remove(id) {
            let scope = (e.rec.op_id, e.rec.instance_id);
            if let Some(ids) = self.by_scope.get_mut(&scope) {
                ids.remove(id);
                if ids.is_empty() {
                    self.by_scope.remove(&scope);
                }
            }
        }
    }

    /// Drops what left the 24 h window.
    fn prune(&mut self, now: UtcInstant) {
        let old: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.outcome.is_some_and(|(_, at)| !within(at, now)))
            .map(|(id, _)| id.clone())
            .collect();
        for id in old {
            self.remove(&id);
        }
    }
}

fn within(at: UtcInstant, now: UtcInstant) -> bool {
    now.0.saturating_sub(at.0) <= WINDOW_MS
}

/// `HH:MM` of `at` shifted by `offset_min`; with no known offset, in UTC and marked so.
fn hh_mm(at: UtcInstant, offset_min: Option<i32>) -> String {
    let minutes = at.0.div_euclid(60_000) + i64::from(offset_min.unwrap_or(0));
    let of_day = minutes.rem_euclid(24 * 60);
    let text = format!("{:02}:{:02}", of_day / 60, of_day % 60);
    match offset_min {
        Some(_) => text,
        None => format!("{text} UTC"),
    }
}

fn lock(m: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The index (one per `Core`). Cheap to share; every method takes its own short lock.
pub struct SimilarityIndex {
    inner: Mutex<Inner>,
    clock: Arc<dyn Clock>,
    /// Minutes east of UTC of the app's local time zone, for the `HH:MM` of the Caution text
    /// (PD-17); `None` until the app sets it (then the text says `UTC`).
    utc_offset_min: Mutex<Option<i32>>,
    /// `REQUEST_RECEIVED` payloads seeding could not decrypt or parse (§5.6: counted for the
    /// diagnostic log, the count only).
    seed_skipped: u64,
}

impl SimilarityIndex {
    /// An empty index (no seeding).
    pub fn new(clock: Arc<dyn Clock>) -> SimilarityIndex {
        SimilarityIndex {
            inner: Mutex::new(Inner::default()),
            clock,
            utc_offset_min: Mutex::new(None),
            seed_skipped: 0,
        }
    }

    /// The app's local UTC offset for the `HH:MM` texts (PD-17).
    pub fn set_utc_offset(&self, minutes: Option<i32>) {
        *self
            .utc_offset_min
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = minutes;
    }

    /// RF-4 / L45 (Task 28, startup step 5, after reconciliation): one `recent_headers(24 h)`
    /// scan. `Target` keys from the plaintext `target` column; `Create` / `MoveIssues` keys from
    /// the decrypted `REQUEST_RECEIVED` params (a payload that cannot be decrypted or parsed is
    /// skipped and counted, [`SimilarityIndex::seed_skipped`]); each request's state from its
    /// first terminal record's type. Never re-seeded afterwards.
    pub fn seed(
        port: &dyn AuditPort,
        clock: Arc<dyn Clock>,
    ) -> Result<SimilarityIndex, AuditError> {
        let headers = port.recent_headers(SIMILARITY_WINDOW)?;
        let mut index = SimilarityIndex::new(clock);
        let mut started: Vec<&EventHeader> = Vec::new();
        let mut ended: HashMap<&str, &EventHeader> = HashMap::new();
        for h in &headers {
            let Some(id) = h.request_id.as_deref() else {
                continue;
            };
            if h.event_type == EventType::REQUEST_RECEIVED {
                started.push(h);
            } else if seeded_outcome(h.event_type).is_some() {
                ended.entry(id).or_insert(h);
            }
        }
        let mut skipped = 0u64;
        let inner = index
            .inner
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        for start in started {
            let (Some(id), Some(op_id), Some(instance_id)) = (
                start.request_id.as_deref(),
                start.op_id.as_deref(),
                start.instance_id.as_deref(),
            ) else {
                continue;
            };
            let Some(spec) = atlas_duck_registry::get(op_id) else {
                continue;
            };
            let outcome = match ended.get(id) {
                None => None,
                Some(h) => match seeded_outcome(h.event_type) {
                    Some(SimOutcome::Gone) | None => continue,
                    Some(o) => {
                        let at = UtcInstant::parse_rfc3339_ms(&h.ts_utc).unwrap_or(UtcInstant(0));
                        Some((o, at))
                    }
                },
            };
            let (key, sha) = match spec.similarity {
                Similarity::None => continue,
                Similarity::Target => match start.target.as_deref() {
                    Some(t) => (target_key(spec, t), None),
                    None => continue,
                },
                Similarity::Create | Similarity::MoveIssues => {
                    let payload = payload_json(port, start.seq);
                    let parsed = payload.as_ref().and_then(|p| {
                        let key = sim_key(spec, p.get("params")?)?;
                        let sha = p
                            .get("params_sha256")
                            .and_then(Value::as_str)
                            .map(str::to_owned);
                        Some((key, sha))
                    });
                    match parsed {
                        Some(k) => k,
                        None => {
                            skipped += 1;
                            continue;
                        }
                    }
                }
            };
            let rec = SimRecord {
                request_id: id.to_owned(),
                op_id: op_id.to_owned(),
                instance_id: instance_id.to_owned(),
                params_sha256: sha,
                key: Some(key),
            };
            inner.insert(rec, outcome);
        }
        index.seed_skipped = skipped;
        Ok(index)
    }

    /// How many payloads seeding skipped (Task 28 writes `similarity_seed_skipped` with it).
    pub fn seed_skipped(&self) -> u64 {
        self.seed_skipped
    }

    /// A request entered the queue's lifecycle (validation passed); open until `on_status`.
    pub fn on_submit(&self, rec: SimRecord) {
        let now = self.clock.now_utc();
        let mut inner = lock(&self.inner);
        inner.prune(now);
        inner.insert(rec, None);
    }

    /// A request reached a terminal state at `at`. Only the first terminal state counts.
    pub fn on_status(&self, request_id: &str, outcome: SimOutcome, at: UtcInstant) {
        let mut inner = lock(&self.inner);
        if outcome == SimOutcome::Gone {
            inner.remove(request_id);
            return;
        }
        if let Some(e) = inner.entries.get_mut(request_id)
            && e.outcome.is_none()
        {
            e.outcome = Some((outcome, at));
        }
    }

    /// The record of an open or recent request.
    pub fn record(&self, request_id: &str) -> Option<SimRecord> {
        lock(&self.inner)
            .entries
            .get(request_id)
            .map(|e| e.rec.clone())
    }

    /// Another request of the same op and instance that `rec` is similar to: open ones first
    /// (the oldest), then the most recently decided one within 24 h.
    pub fn similar_to(&self, rec: &SimRecord) -> Option<SimHit> {
        let key = rec.key.as_ref()?;
        let now = self.clock.now_utc();
        let offset = *self
            .utc_offset_min
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let inner = lock(&self.inner);
        let ids = inner
            .by_scope
            .get(&(rec.op_id.clone(), rec.instance_id.clone()))?;
        let mut open: Vec<&str> = Vec::new();
        let mut decided: Vec<(UtcInstant, &str, SimOutcome)> = Vec::new();
        for id in ids {
            if *id == rec.request_id {
                continue;
            }
            let Some(e) = inner.entries.get(id) else {
                continue;
            };
            if !e.rec.key.as_ref().is_some_and(|k| k.matches(key)) {
                continue;
            }
            match e.outcome {
                None => open.push(id),
                Some((o, at)) if within(at, now) => decided.push((at, id, o)),
                Some(_) => {}
            }
        }
        if let Some(id) = open.first() {
            return Some(SimHit {
                request_id: (*id).to_owned(),
                when: "pending".to_owned(),
            });
        }
        decided.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
        let (at, id, o) = decided.first()?;
        let when = match o {
            SimOutcome::OutcomeUnknown => "outcome unknown".to_owned(),
            SimOutcome::Executed => format!("executed {}", hh_mm(*at, offset)),
            SimOutcome::Denied => format!("denied {}", hh_mm(*at, offset)),
            SimOutcome::Released => format!("released {}", hh_mm(*at, offset)),
            SimOutcome::Failed => format!("failed {}", hh_mm(*at, offset)),
            SimOutcome::Gone => return None,
        };
        Some(SimHit {
            request_id: (*id).to_owned(),
            when,
        })
    }

    /// Every other open request with this `params_sha256` (sorted): "possible duplicate"
    /// (§5.6), regardless of session.
    pub fn duplicates(&self, params_sha256: &str, exclude: &str) -> Vec<String> {
        let inner = lock(&self.inner);
        let mut ids: Vec<String> = inner
            .entries
            .values()
            .filter(|e| {
                e.outcome.is_none()
                    && e.rec.request_id != exclude
                    && e.rec.params_sha256.as_deref() == Some(params_sha256)
            })
            .map(|e| e.rec.request_id.clone())
            .collect();
        ids.sort();
        ids
    }
}

/// The state a terminal record type leaves for "similar" (§5.6); `None` = not terminal here.
fn seeded_outcome(t: EventType) -> Option<SimOutcome> {
    Some(match t {
        EventType::READ_RELEASED => SimOutcome::Released,
        EventType::READ_DENIED | EventType::WRITE_DENIED => SimOutcome::Denied,
        EventType::WRITE_EXECUTED => SimOutcome::Executed,
        EventType::WRITE_FAILED => SimOutcome::Failed,
        EventType::WRITE_OUTCOME_UNKNOWN => SimOutcome::OutcomeUnknown,
        EventType::REQUEST_REJECTED
        | EventType::REQUEST_FAILED
        | EventType::READ_FAILED
        | EventType::EXPIRED
        | EventType::CANCELLED
        | EventType::ABANDONED => SimOutcome::Gone,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A settable wall clock (the audit crate's `FakeClock` needs its `testing` feature).
    struct TestClock(Mutex<UtcInstant>);

    impl TestClock {
        fn advance(&self, d: Duration) {
            let mut now = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            *now = UtcInstant(now.0 + i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        }
    }

    impl Clock for TestClock {
        fn now_utc(&self) -> UtcInstant {
            *self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn suspend_aware_elapsed(&self) -> Duration {
            Duration::ZERO
        }
    }

    fn spec(id: &str) -> Result<&'static OperationSpec, Box<dyn std::error::Error>> {
        atlas_duck_registry::get(id).ok_or_else(|| format!("no op {id}").into())
    }

    fn clock() -> Result<Arc<TestClock>, Box<dyn std::error::Error>> {
        let start =
            UtcInstant::parse_rfc3339_ms("2026-10-08T12:00:00.000Z").ok_or("bad instant")?;
        Ok(Arc::new(TestClock(Mutex::new(start))))
    }

    fn rec(id: &str, op: &str, key: Option<SimKey>) -> SimRecord {
        SimRecord {
            request_id: id.to_owned(),
            op_id: op.to_owned(),
            instance_id: "ins_1".to_owned(),
            params_sha256: Some(format!("sha-{id}")),
            key,
        }
    }

    #[test]
    fn normalize_title_folds_trims_and_collapses() {
        assert_eq!(normalize_title("  Fix \t Login\n "), "fix login");
        assert_eq!(normalize_title("STRASSE"), normalize_title("straße"));
        assert_eq!(normalize_title("ΣΊΣΥΦΟΣ"), normalize_title("σίσυφος"));
    }

    #[test]
    fn target_keys_split_pairs() -> TestResult {
        let link = spec("confluence.label.remove")?;
        let k = sim_key(link, &json!({ "id": "42", "label": "x" }));
        assert_eq!(
            k,
            Some(SimKey::Target(vec![
                ("id".into(), "42".into()),
                ("label".into(), "x".into())
            ]))
        );
        // The seeded key from the `target` column equals the live one.
        assert_eq!(k, Some(target_key(link, "42 → x")));
        assert_eq!(sim_key(spec("jira.search")?, &json!({ "jql": "a" })), None);
        Ok(())
    }

    #[test]
    fn move_keys_match_on_shared_issue() -> TestResult {
        let s = spec("jira.sprint.move_issues")?;
        let a = sim_key(s, &json!({ "id": 5, "issues": ["A-1", "A-2"] })).ok_or("no key")?;
        let b = sim_key(s, &json!({ "id": 5, "issues": ["A-2"] })).ok_or("no key")?;
        let c = sim_key(s, &json!({ "id": 5, "issues": ["A-3"] })).ok_or("no key")?;
        let d = sim_key(s, &json!({ "id": 6, "issues": ["A-2"] })).ok_or("no key")?;
        assert!(a.matches(&b) && b.matches(&a));
        assert!(!a.matches(&c));
        assert!(!b.matches(&d));
        Ok(())
    }

    #[test]
    fn decided_hits_expire_after_24h_open_ones_do_not() -> TestResult {
        let clock = clock()?;
        let index = SimilarityIndex::new(clock.clone());
        let key = Some(SimKey::Target(vec![("key".into(), "ABC-1".into())]));
        index.on_submit(rec("req_a", "jira.issue.get", key.clone()));
        index.on_submit(rec("req_b", "jira.issue.get", key.clone()));
        let probe = rec("req_c", "jira.issue.get", key.clone());
        let hit = index.similar_to(&probe).ok_or("no hit")?;
        assert_eq!(
            (hit.request_id.as_str(), hit.when.as_str()),
            ("req_a", "pending")
        );
        index.on_status("req_a", SimOutcome::Executed, clock.now_utc());
        index.on_status("req_b", SimOutcome::Gone, clock.now_utc());
        let hit = index.similar_to(&probe).ok_or("no hit")?;
        assert_eq!(hit.when, "executed 12:00 UTC");
        index.set_utc_offset(Some(120));
        assert_eq!(
            index.similar_to(&probe).ok_or("no hit")?.when,
            "executed 14:00"
        );
        clock.advance(Duration::from_secs(24 * 3600 + 60));
        assert_eq!(index.similar_to(&probe), None);
        // Another op or instance never matches.
        index.on_submit(rec("req_d", "jira.comment.list", key.clone()));
        assert_eq!(index.similar_to(&probe), None);
        Ok(())
    }

    #[test]
    fn duplicates_are_open_only() -> TestResult {
        let index = SimilarityIndex::new(clock()?);
        let mut a = rec("req_a", "jira.search", None);
        let mut b = rec("req_b", "jira.search", None);
        a.params_sha256 = Some("same".into());
        b.params_sha256 = Some("same".into());
        index.on_submit(a);
        index.on_submit(b);
        assert_eq!(index.duplicates("same", "req_a"), ["req_b"]);
        index.on_status("req_b", SimOutcome::Released, UtcInstant(0));
        assert!(index.duplicates("same", "req_a").is_empty());
        assert_eq!(
            index.similar_to(&rec("req_c", "jira.search", None)),
            None,
            "a `None` op is never similar"
        );
        Ok(())
    }
}
