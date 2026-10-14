//! The core's `SettingsAdmin` (M6 Δ3, PD-76; §5.7, §7.7, §8.7, §8.8, §10.3): the Settings
//! window's limits, attention mode, retention and legal hold, "Prune backlog now" and "Verify
//! now".
//!
//! * **Where a value lives.** Retention and legal hold are audit-authoritative (§8.8): they change
//!   only through `Store::apply_setting`, which logs `CONFIG_CHANGED` / `LEGAL_HOLD_CHANGED
//!   {source: app}` itself. The limits and the attention mode live in `config.toml` (`[limits]`,
//!   `[requests]`, `[ui]`, M6 Δ6); a change of them is logged `CONFIG_CHANGED {source: app}`
//!   here **before** the file is written (audit before effect: a failed append changes nothing).
//! * **When it applies (PD-76).** `jira_comments_cap` and the attention mode apply at once;
//!   `candidate_cache_mb`, `max_pending_bytes_mb` and `expiry_hours` at the next start (the view
//!   lists them in `restart_pending` while the file differs from what runs).
//! * **What needs the native confirmation (§10.3).** Raising any limit, lowering retention,
//!   lifting the legal hold and "Prune backlog now"; every `Confirm::Ok` becomes an
//!   `audit::Confirmed` over the dialog text. Lowering a limit, raising retention, setting the
//!   hold and changing the attention mode are plain records. A `Cancel` of any dialog of one
//!   `apply` applies none of its changes. No setting here can turn off the audit log, the
//!   envelope's opacity or a confirmation.
//! * **Read-only config (§7.7).** A newer-schema or unreadable `config.toml` refuses every
//!   file-backed change with the banner text; retention and legal hold still work.
//! * **Shutdown (§2.5, M3 M-4).** Every call that can write runs as an admin job: refused once the
//!   shutdown began, checked again after each dialog, and drained by `Core::shutdown` before
//!   `APP_STOP`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use atlas_duck_audit::{
    AuditError, Confirmed, NewEvent, PruneOutcome, PruneSkip, SettingChange, Store, StoreHealth,
};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use toml_edit::{DocumentMut, Item, Table};

use crate::config::limits::{
    COMMENTS_CAP_RANGE, KEY_CANDIDATE_CACHE_MB, KEY_JIRA_COMMENTS_CAP, KEY_LIMITS,
    KEY_MAX_PENDING_BYTES_MB, MAX_LIMIT_MB, limits_config,
};
use crate::config::requests::{
    DEFAULT_EXPIRY_HOURS, EXPIRY_HOURS_RANGE, KEY_EXPIRY_HOURS, KEY_REQUESTS, expiry_hours,
};
use crate::config::ui::{AttentionMode, KEY_ATTENTION_MODE, KEY_UI, attention_mode};
use crate::config::{ConfigReadOnly, ConfigState, ConfigWriteError, load_config, update_config};
use crate::core::Confirm;
use crate::engine::Engine;
use crate::engine::queue::{CANDIDATE_CACHE_MB, MIB};
use crate::instances::work::{AdminWork, Job};
use crate::payloads::{self, ConfigSource};
use crate::reconcile::{KEY_AUDIT, KEY_LEGAL_HOLD, KEY_RETENTION_DAYS};

/// plan text (PD-76): the tail of every limit-raise dialog.
const RAISE_TAIL: &str = "Higher limits let agents fetch more data before you review it.";
/// plan text (PD-76).
pub const LIFT_HOLD_TEXT: &str = "Lift the legal hold? Pruning and key destruction resume.";
/// plan text (PD-76, L37).
pub const PRUNE_BACKLOG_TEXT: &str =
    "Prune the backlog now? Records beyond the retention period are deleted in one run.";
/// plan text (PD-82).
pub const VERIFIED_TEXT: &str = "verified";
/// plan text (PD-82).
pub const DID_NOT_COMPLETE_TEXT: &str = "verification did not complete";
/// plan text (PD-82).
pub const INCIDENT_TEXT: &str = "integrity incident: see Audit";

/// The largest retention Settings accepts (100 years): a bound, not a policy (§8.8 sets only the
/// minimum).
pub const MAX_RETENTION_DAYS: u32 = 36_500;
/// The most changes one `apply` takes (one per key).
pub const MAX_CHANGES: usize = 7;
/// The longest key `record_app_change` accepts.
const MAX_APP_KEY_CHARS: usize = 64;
/// The largest serialized `old` / `new` of `record_app_change`.
const MAX_APP_VALUE_BYTES: usize = 64 * 1024;

/// One Settings change (Δ3). JSON: `{"key": "<name>", "value": <value>}`; the bounds are checked
/// by [`SettingChangeReq::validate`] before anything else happens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "key",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SettingChangeReq {
    /// `[limits] jira_comments_cap`, 1–1000 (PD-63); applies at once.
    JiraCommentsCap(u32),
    /// `[limits] candidate_cache_mb`, 1–1048576; applies at the next start.
    CandidateCacheMb(u64),
    /// `[limits] max_pending_bytes_mb`, 1–1048576 or `null` (off); applies at the next start.
    MaxPendingBytesMb(Option<u64>),
    /// `[requests] expiry_hours`, 1–168; applies at the next start.
    ExpiryHours(u32),
    /// `[ui] attention_mode`; applies at once.
    AttentionMode(AttentionMode),
    /// The audit retention, 92–36500 days (§8.8).
    RetentionDays(u32),
    LegalHold(bool),
}

impl SettingChangeReq {
    /// The setting's name: the `key` of its JSON, its `CONFIG_CHANGED.key` and its field name in
    /// the view.
    pub fn key(&self) -> &'static str {
        match self {
            Self::JiraCommentsCap(_) => KEY_JIRA_COMMENTS_CAP,
            Self::CandidateCacheMb(_) => KEY_CANDIDATE_CACHE_MB,
            Self::MaxPendingBytesMb(_) => KEY_MAX_PENDING_BYTES_MB,
            Self::ExpiryHours(_) => KEY_EXPIRY_HOURS,
            Self::AttentionMode(_) => KEY_ATTENTION_MODE,
            Self::RetentionDays(_) => KEY_RETENTION_DAYS,
            Self::LegalHold(_) => KEY_LEGAL_HOLD,
        }
    }

    /// The value is in its range (`Invalid` names the key, never the value).
    pub fn validate(&self) -> Result<(), SettingsError> {
        let mb = |n: u64| (1..=MAX_LIMIT_MB).contains(&n);
        let ok = match self {
            Self::JiraCommentsCap(n) => COMMENTS_CAP_RANGE.contains(n),
            Self::CandidateCacheMb(n) => mb(*n),
            Self::MaxPendingBytesMb(n) => n.is_none_or(mb),
            Self::ExpiryHours(h) => EXPIRY_HOURS_RANGE.contains(&u64::from(*h)),
            Self::RetentionDays(d) => {
                (atlas_duck_audit::RETENTION_MIN..=MAX_RETENTION_DAYS).contains(d)
            }
            Self::AttentionMode(_) | Self::LegalHold(_) => true,
        };
        if ok {
            Ok(())
        } else {
            Err(SettingsError::Invalid { key: self.key() })
        }
    }

    /// Lives in `config.toml` (the rest are audit-authoritative).
    fn file_backed(&self) -> bool {
        !matches!(self, Self::RetentionDays(_) | Self::LegalHold(_))
    }
}

/// Every key a `SettingChangeReq` can name (`record_app_change` refuses them).
const SETTING_KEYS: [&str; 7] = [
    KEY_JIRA_COMMENTS_CAP,
    KEY_CANDIDATE_CACHE_MB,
    KEY_MAX_PENDING_BYTES_MB,
    KEY_EXPIRY_HOURS,
    KEY_ATTENTION_MODE,
    KEY_RETENTION_DAYS,
    KEY_LEGAL_HOLD,
];

/// The limits as Settings shows them: the comments cap in force, and for the three that apply at
/// the next start the value `config.toml` holds (defaults when absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LimitsView {
    pub jira_comments_cap: u32,
    pub candidate_cache_mb: u64,
    pub max_pending_bytes_mb: Option<u64>,
    pub expiry_hours: u32,
}

/// The §7.7 banner of a `config.toml` this binary does not write. `kind`: `read_only` (a newer
/// schema) or `unreadable`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigBanner {
    pub kind: &'static str,
    pub text: String,
}

/// The store health Settings and the tray show (§8.1, §8.5, §8.8). No error text: an
/// `AuditError` message can name paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreHealthView {
    pub storage_low: bool,
    pub anchor_write_failing: bool,
    pub anchor_thread_dead: bool,
    pub anchors_blocked: bool,
    pub open_incidents: u64,
    pub prune_backlog_days: u32,
    /// §8.8 "pruning is N days behind", while it is (then Settings offers "Prune backlog now").
    pub prune_backlog: Option<String>,
    pub last_prune_failed: bool,
    pub shred_checkpoint_pending: bool,
    /// A settings row of the log could not be read: prune and setting changes are refused.
    pub settings_unreadable: bool,
}

/// What the Settings window shows (Δ3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsView {
    pub limits: LimitsView,
    pub attention_mode: AttentionMode,
    pub retention_days: u32,
    pub legal_hold: bool,
    /// Display only (M10 changes it).
    pub anchor_dir: Option<String>,
    pub health: StoreHealthView,
    pub config_read_only: Option<ConfigBanner>,
    /// The keys whose `config.toml` value applies at the next start and differs from the running
    /// one ("applies after restart", plan text PD-76).
    pub restart_pending: Vec<&'static str>,
}

/// One "Prune backlog now" run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum PruneReport {
    Pruned {
        count: u64,
        /// `YYYY-MM-DD`.
        cutoff: String,
        clamped: bool,
    },
    /// Nothing written; `reason` is the guard's name.
    Skipped { reason: &'static str },
}

fn skip_reason(s: PruneSkip) -> &'static str {
    match s {
        PruneSkip::NotCorroborated => "not_corroborated",
        PruneSkip::HeadEpochNull => "head_epoch_null",
        PruneSkip::LegalHold => "legal_hold",
        PruneSkip::AlreadyRanThisEpoch => "already_ran_this_epoch",
        PruneSkip::ClockBeforeHead => "clock_before_head",
        PruneSkip::ClockBeforeLastPrune => "clock_before_last_prune",
        PruneSkip::NothingToAdvance => "nothing_to_advance",
        PruneSkip::ConfigNotReconciled => "config_not_reconciled",
        PruneSkip::ClockBehind => "clock_behind",
    }
}

impl From<PruneOutcome> for PruneReport {
    fn from(o: PruneOutcome) -> PruneReport {
        match o {
            PruneOutcome::Pruned {
                count,
                cutoff,
                clamped,
                ..
            } => PruneReport::Pruned {
                count,
                cutoff: cutoff.format("%Y-%m-%d").to_string(),
                clamped,
            },
            PruneOutcome::Skipped(s) => PruneReport::Skipped {
                reason: skip_reason(s),
            },
        }
    }
}

/// "Verify now" (§8.7, PD-82, M2 handoff): a run that could not complete is never a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyNow {
    Verified,
    DidNotComplete,
    /// `count` incident findings (informational ones alone are `Verified`).
    Incident {
        count: u64,
    },
}

impl VerifyNow {
    /// The PD-82 result text.
    pub fn text(self) -> &'static str {
        match self {
            Self::Verified => VERIFIED_TEXT,
            Self::DidNotComplete => DID_NOT_COMPLETE_TEXT,
            Self::Incident { .. } => INCIDENT_TEXT,
        }
    }
}

/// `{result, count?, text}`.
impl Serialize for VerifyNow {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        let result = match self {
            Self::Verified => "verified",
            Self::DidNotComplete => "did_not_complete",
            Self::Incident { .. } => "incident",
        };
        m.serialize_entry("result", result)?;
        if let Self::Incident { count } = self {
            m.serialize_entry("count", count)?;
        }
        m.serialize_entry("text", self.text())?;
        m.end()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SettingsError {
    /// Out of bounds, a key named twice, too many changes, or a key `record_app_change` may not
    /// use. Nothing happened.
    Invalid {
        key: &'static str,
    },
    /// A confirmation dialog was cancelled: none of the call's changes happened.
    Cancelled,
    /// §7.7: `config.toml` is read-only or unreadable; file-backed changes are refused.
    ConfigReadOnly(ConfigBanner),
    /// The core runs without a `config.toml` path; file-backed changes are refused.
    NoConfigFile,
    /// A value changed while the dialog was open (it showed another change): nothing happened.
    Conflict,
    /// `config.toml` could not be written after its records committed; a second record says the
    /// change was not applied.
    ConfigWrite,
    Audit(AuditError),
    /// The shutdown began (§2.5): the call did nothing.
    ShuttingDown,
}

impl SettingsError {
    fn kind(&self) -> &'static str {
        match self {
            Self::Invalid { .. } => "invalid",
            Self::Cancelled => "cancelled",
            Self::ConfigReadOnly(_) => "config_read_only",
            Self::NoConfigFile => "no_config_file",
            Self::Conflict => "conflict",
            Self::ConfigWrite => "config_write_failed",
            Self::Audit(_) => "audit",
            Self::ShuttingDown => "shutting_down",
        }
    }
}

/// The kind only: an `AuditError` message can name paths.
impl std::fmt::Display for SettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind())
    }
}

impl std::error::Error for SettingsError {}

/// `{kind, key?, banner?}`: no error text.
impl Serialize for SettingsError {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("kind", self.kind())?;
        match self {
            Self::Invalid { key } => m.serialize_entry("key", key)?,
            Self::ConfigReadOnly(b) => m.serialize_entry("banner", b)?,
            _ => {}
        }
        m.end()
    }
}

/// C.7 (M6 Δ3): what the Settings and Audit windows change. Sync like `DecisionApi`: the app
/// calls it from `spawn_blocking` (a native dialog may be open meanwhile).
pub trait SettingsAdmin: Send + Sync {
    fn view(&self) -> SettingsView;
    /// Each change confirmed natively when it is security-weakening (PD-76); all dialogs come
    /// first, in request order, so a `Cancel` applies nothing. Validation, the read-only check
    /// and the dialogs happen before any record. Then the audit-authoritative changes commit (one
    /// store record each), then the file-backed ones (their records in one transaction, then one
    /// file write); a record that fails stops the call there.
    fn apply(&self, changes: Vec<SettingChangeReq>) -> Result<SettingsView, SettingsError>;
    /// "Prune backlog now" (§8.8, L37): one prune run with the clamp lifted, after the native
    /// confirmation.
    fn prune_backlog_now(&self) -> Result<PruneReport, SettingsError>;
    /// `Store::try_full_verify`; an error is `DidNotComplete` (M2 handoff), never a pass.
    fn verify_now(&self) -> VerifyNow;
    /// An app-owned setting changed (attention mode from the tray, CLI install, "Prepare for
    /// removal"): one `CONFIG_CHANGED {source: app, key, old, new, applied: true}`. `Ok` once it
    /// committed (the app acts after it: audit before effect).
    fn record_app_change(&self, key: &str, old: Value, new: Value) -> Result<(), SettingsError>;
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn confirmed(text: &str) -> Confirmed {
    Confirmed {
        dialog_text_sha256: Sha256::digest(text.as_bytes()).into(),
    }
}

/// The version a banner names: only the characters of a version string, at most 32 (the file is
/// writable by any same-user process, the banner text is app-generated).
fn shown_version(info: &ConfigReadOnly) -> String {
    let ok = info.written_by.as_deref().filter(|v| {
        !v.is_empty()
            && v.len() <= 32
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
    });
    match ok {
        Some(v) => format!("v{}", v.strip_prefix('v').unwrap_or(v)),
        None => "a newer atlas-duck".to_owned(),
    }
}

/// §7.7 (verbatim, with `vX` from `written_by`).
fn banner(cfg: &ConfigState) -> Option<ConfigBanner> {
    match cfg {
        ConfigState::ReadOnly { info, .. } => Some(ConfigBanner {
            kind: "read_only",
            text: format!(
                "config written by {}; settings read-only until you upgrade",
                shown_version(info)
            ),
        }),
        ConfigState::Unreadable { info } => Some(ConfigBanner {
            kind: "unreadable",
            text: format!(
                "config written by {} could not be read; upgrade atlas-duck",
                shown_version(info)
            ),
        }),
        ConfigState::Absent | ConfigState::Writable(_) => None,
    }
}

/// The values a change is compared against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Current {
    /// In force (live).
    comments_cap: u32,
    /// The file's values (defaults when absent or malformed).
    candidate_cache_mb: u64,
    max_pending_bytes_mb: Option<u64>,
    expiry_hours: u32,
    /// In force (live).
    attention_mode: AttentionMode,
    /// The audit settings.
    retention_days: u32,
    legal_hold: bool,
}

/// One change that does something.
struct Planned {
    req: SettingChangeReq,
    old: Value,
    new: Value,
    /// The native confirmation's text, when the change needs one.
    dialog: Option<String>,
}

fn opt_mb(v: Option<u64>) -> String {
    v.map_or_else(|| "no cap".to_owned(), |n| n.to_string())
}

fn raise_text(name: &str, old: &str, new: &str) -> String {
    format!("Raise {name} from {old} to {new}? {RAISE_TAIL}")
}

/// What `req` changes, or `None` when the setting already has the value.
fn plan(req: SettingChangeReq, cur: &Current) -> Option<Planned> {
    let p = |old: Value, new: Value, dialog: Option<String>| {
        Some(Planned {
            req: req.clone(),
            old,
            new,
            dialog,
        })
    };
    match &req {
        SettingChangeReq::JiraCommentsCap(n) => {
            let old = cur.comments_cap;
            if *n == old {
                return None;
            }
            let d = (*n > old)
                .then(|| raise_text("the Jira comments cap", &old.to_string(), &n.to_string()));
            p(json!(old), json!(n), d)
        }
        SettingChangeReq::CandidateCacheMb(n) => {
            let old = cur.candidate_cache_mb;
            if *n == old {
                return None;
            }
            let d = (*n > old).then(|| {
                raise_text(
                    "the candidate cache (MiB)",
                    &old.to_string(),
                    &n.to_string(),
                )
            });
            p(json!(old), json!(n), d)
        }
        SettingChangeReq::MaxPendingBytesMb(n) => {
            let old = cur.max_pending_bytes_mb;
            if *n == old {
                return None;
            }
            // `None` is no cap: removing the cap or making it larger raises it.
            let raise = match (old, n) {
                (_, None) => true,
                (None, Some(_)) => false,
                (Some(o), Some(n)) => *n > o,
            };
            let d =
                raise.then(|| raise_text("the pending-bytes cap (MiB)", &opt_mb(old), &opt_mb(*n)));
            p(json!(old), json!(n), d)
        }
        SettingChangeReq::ExpiryHours(h) => {
            let old = cur.expiry_hours;
            if *h == old {
                return None;
            }
            let d = (*h > old).then(|| {
                raise_text(
                    "the request expiry (hours)",
                    &old.to_string(),
                    &h.to_string(),
                )
            });
            p(json!(old), json!(h), d)
        }
        SettingChangeReq::AttentionMode(m) => {
            let old = cur.attention_mode;
            if *m == old {
                return None;
            }
            // §10.3: not security-weakening.
            p(json!(old.as_str()), json!(m.as_str()), None)
        }
        SettingChangeReq::RetentionDays(d) => {
            let old = cur.retention_days;
            if *d == old {
                return None;
            }
            let dialog = (*d < old).then(|| {
                format!(
                    "Lower audit retention from {old} to {d} days? Records older than {d} days will be pruned."
                )
            });
            p(json!(old), json!(d), dialog)
        }
        SettingChangeReq::LegalHold(on) => {
            if *on == cur.legal_hold {
                return None;
            }
            let dialog = (!on).then(|| LIFT_HOLD_TEXT.to_owned());
            p(json!(cur.legal_hold), json!(on), dialog)
        }
    }
}

fn int(n: u64) -> toml_edit::Value {
    toml_edit::Value::from(i64::try_from(n).unwrap_or(i64::MAX))
}

/// The file value of a file-backed change; `None` removes the key.
fn file_value(req: &SettingChangeReq) -> Option<(&'static str, Option<toml_edit::Value>)> {
    Some(match req {
        SettingChangeReq::JiraCommentsCap(n) => (KEY_LIMITS, Some(int(u64::from(*n)))),
        SettingChangeReq::CandidateCacheMb(n) => (KEY_LIMITS, Some(int(*n))),
        SettingChangeReq::MaxPendingBytesMb(n) => (KEY_LIMITS, n.map(int)),
        SettingChangeReq::ExpiryHours(h) => (KEY_REQUESTS, Some(int(u64::from(*h)))),
        SettingChangeReq::AttentionMode(m) => (KEY_UI, Some(toml_edit::Value::from(m.as_str()))),
        SettingChangeReq::RetentionDays(_) | SettingChangeReq::LegalHold(_) => return None,
    })
}

/// Sets (or removes) `table.key`, creating the table; `false` when `table` is not a table (the
/// file is then left as it is).
fn set_key(doc: &mut DocumentMut, table: &str, key: &str, v: Option<toml_edit::Value>) -> bool {
    if doc.get(table).is_none() {
        if v.is_none() {
            return true;
        }
        doc.insert(table, Item::Table(Table::new()));
    }
    let Some(t) = doc.get_mut(table).and_then(Item::as_table_like_mut) else {
        return false;
    };
    match v {
        Some(v) => {
            t.insert(key, Item::Value(v));
        }
        None => {
            t.remove(key);
        }
    }
    true
}

/// The `CONFIG_CHANGED {source: app}` of a file-backed change, with the confirmation's dialog hash
/// like the store's own settings records.
fn record(p: &Planned, confirmed: Option<&Confirmed>, applied: bool) -> NewEvent {
    let mut ev = payloads::config_changed(ConfigSource::App, p.req.key(), &p.old, &p.new, applied);
    if let Value::Object(o) = &mut ev.payload {
        o.insert(
            "confirmed".into(),
            confirmed.map_or(
                Value::Null,
                |c| json!({ "dialog_text_sha256": hex::encode(c.dialog_text_sha256) }),
            ),
        );
    }
    ev
}

/// The store-backed change a request asks for.
fn store_change(req: &SettingChangeReq) -> Option<SettingChange> {
    match req {
        SettingChangeReq::RetentionDays(d) => Some(SettingChange::RetentionDays(*d)),
        SettingChangeReq::LegalHold(on) => Some(SettingChange::LegalHold(*on)),
        _ => None,
    }
}

fn health_view(h: &StoreHealth) -> StoreHealthView {
    StoreHealthView {
        storage_low: h.storage_low,
        anchor_write_failing: h.anchor_write_failing,
        anchor_thread_dead: h.anchor_thread_dead,
        anchors_blocked: h.anchors_blocked.is_some(),
        open_incidents: u64::try_from(h.open_incidents).unwrap_or(u64::MAX),
        prune_backlog_days: h.prune_backlog_days,
        prune_backlog: (h.prune_backlog_days > 0)
            .then(|| format!("pruning is {} days behind", h.prune_backlog_days)),
        last_prune_failed: h.last_prune_error.is_some(),
        shred_checkpoint_pending: h.shred_checkpoint_pending,
        settings_unreadable: h.settings_unreadable,
    }
}

/// The core's `SettingsAdmin`.
pub struct CoreSettings {
    engine: Arc<Engine>,
    /// For what `AuditPort` does not carry: health, prune, full verification.
    store: Store,
    config_path: Option<PathBuf>,
    /// The calls that can write, drained by the shutdown (M3 M-4).
    work: Arc<AdminWork>,
    /// The attention mode in force (PD-76: applies at once; the app's attention engine reads it).
    attention: Mutex<AttentionMode>,
    /// Serializes the effect half of `apply`; never held across a dialog (PD-13).
    effects: Mutex<()>,
}

impl CoreSettings {
    pub(crate) fn new(
        engine: Arc<Engine>,
        store: Store,
        config_path: Option<PathBuf>,
        config: &ConfigState,
    ) -> CoreSettings {
        CoreSettings {
            engine,
            store,
            config_path,
            work: Arc::new(AdminWork::default()),
            attention: Mutex::new(attention_mode(config)),
            effects: Mutex::new(()),
        }
    }

    /// The admin work the shutdown closes and waits for (M3 M-4).
    pub(crate) fn work(&self) -> &AdminWork {
        &self.work
    }

    fn enter(&self) -> Result<Job, SettingsError> {
        self.work
            .enter(&self.engine)
            .map_err(|_| SettingsError::ShuttingDown)
    }

    /// Checked after a dialog (a user can answer one long after the shutdown's bounded wait).
    fn still_running(&self) -> Result<(), SettingsError> {
        if self.engine.is_shutting_down() {
            return Err(SettingsError::ShuttingDown);
        }
        Ok(())
    }

    /// The native dialog on the caller's (blocking-pool) thread, no lock held (PD-13); an OK
    /// given after the shutdown began changes nothing.
    fn confirm(&self, text: &str) -> Result<Confirmed, SettingsError> {
        match self.engine.confirmer().confirm(text) {
            Confirm::Ok => self.still_running().map(|()| confirmed(text)),
            Confirm::Cancel => Err(SettingsError::Cancelled),
        }
    }

    /// `config.toml` as it is now; one that cannot be read is `Unreadable`, no path is `Absent`.
    fn load(&self) -> ConfigState {
        let Some(path) = &self.config_path else {
            return ConfigState::Absent;
        };
        load_config(path).unwrap_or(ConfigState::Unreadable {
            info: ConfigReadOnly {
                schema_version: None,
                parsed: false,
                written_by: None,
            },
        })
    }

    /// File-backed changes need a path and a file this binary writes (§7.7).
    fn require_writable(&self, cfg: &ConfigState) -> Result<&PathBuf, SettingsError> {
        let path = self
            .config_path
            .as_ref()
            .ok_or(SettingsError::NoConfigFile)?;
        match banner(cfg) {
            Some(b) => Err(SettingsError::ConfigReadOnly(b)),
            None => Ok(path),
        }
    }

    fn current(&self, cfg: &ConfigState) -> Current {
        let limits = limits_config(cfg).unwrap_or_default();
        let settings = self.engine.port().settings();
        Current {
            comments_cap: self.comments_cap(),
            candidate_cache_mb: limits.candidate_cache_mb.unwrap_or(CANDIDATE_CACHE_MB),
            max_pending_bytes_mb: limits.max_pending_bytes_mb,
            expiry_hours: expiry_hours(cfg)
                .ok()
                .flatten()
                .and_then(|h| u32::try_from(h).ok())
                .unwrap_or(DEFAULT_EXPIRY_HOURS as u32),
            attention_mode: *lock(&self.attention),
            retention_days: settings.retention_days,
            legal_hold: settings.legal_hold,
        }
    }

    /// The comments cap in force: the configured one, else the registry's (PD-63).
    fn comments_cap(&self) -> u32 {
        self.engine.admission().comments_cap().unwrap_or_else(|| {
            atlas_duck_registry::get("jira.issue.get")
                .and_then(|s| s.caps.comments_cap)
                .unwrap_or(100)
        })
    }

    /// The keys whose file value differs from the one this run started with (PD-76).
    fn restart_pending(&self, cur: &Current) -> Vec<&'static str> {
        let running = self.engine.limits();
        let mut out = Vec::new();
        if cur.candidate_cache_mb.saturating_mul(MIB) != running.candidate_cache_bytes {
            out.push(KEY_CANDIDATE_CACHE_MB);
        }
        if cur.max_pending_bytes_mb.map(|n| n.saturating_mul(MIB)) != running.max_pending_bytes {
            out.push(KEY_MAX_PENDING_BYTES_MB);
        }
        if u64::from(cur.expiry_hours) * 3600 != self.engine.expiry().as_secs() {
            out.push(KEY_EXPIRY_HOURS);
        }
        out
    }

    /// The `[audit]` key of a store-backed change follows the store when the file already names
    /// it (and is writable): the next start's reconciliation (§8.8, X-01) then finds no
    /// difference, so a lowered retention or a lifted hold is not raised or set again from the
    /// file. Best effort, after the store's record (the store is authoritative either way).
    fn follow_in_file(&self, req: &SettingChangeReq) {
        let (key, v) = match req {
            SettingChangeReq::RetentionDays(d) => (KEY_RETENTION_DAYS, int(u64::from(*d))),
            SettingChangeReq::LegalHold(on) => (KEY_LEGAL_HOLD, toml_edit::Value::from(*on)),
            _ => return,
        };
        let Some(path) = &self.config_path else {
            return;
        };
        let named = matches!(self.load(), ConfigState::Writable(c) if c
            .document()
            .get(KEY_AUDIT)
            .and_then(Item::as_table_like)
            .is_some_and(|t| t.contains_key(key)));
        if !named {
            return;
        }
        let written = update_config(path, |doc| {
            if set_key(doc, KEY_AUDIT, key, Some(v)) {
                Ok(())
            } else {
                Err(())
            }
        });
        if !matches!(written, Ok(Ok(()))) {
            tracing::warn!("config.toml [audit] could not follow a settings change");
        }
    }

    /// The effect half of `apply`, under `effects`.
    fn apply_planned(
        &self,
        planned: &[Planned],
        confirmations: &[Option<Confirmed>],
    ) -> Result<(), SettingsError> {
        let port = self.engine.port().clone();
        // Audit-authoritative values: the store logs each change itself (`source: app`).
        for (p, c) in planned.iter().zip(confirmations) {
            if let Some(change) = store_change(&p.req) {
                port.apply_setting(change, *c)
                    .map_err(SettingsError::Audit)?;
                self.follow_in_file(&p.req);
            }
        }
        let file: Vec<(&Planned, Option<&Confirmed>)> = planned
            .iter()
            .zip(confirmations)
            .filter(|(p, _)| p.req.file_backed())
            .map(|(p, c)| (p, c.as_ref()))
            .collect();
        if file.is_empty() {
            return Ok(());
        }
        let path = self.require_writable(&self.load())?;
        // Audit before effect: the records commit, then the file is written.
        let records = file.iter().map(|(p, c)| record(p, *c, true)).collect();
        port.append_batch(records).map_err(SettingsError::Audit)?;
        let written = update_config(path, |doc| {
            for (p, _) in &file {
                if let Some((table, v)) = file_value(&p.req)
                    && !set_key(doc, table, p.req.key(), v)
                {
                    return Err(SettingsError::Invalid { key: p.req.key() });
                }
            }
            Ok(())
        });
        let failed = match written {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e),
            Err(ConfigWriteError::ReadOnly | ConfigWriteError::Unreadable) => Some(
                banner(&self.load())
                    .map_or(SettingsError::ConfigWrite, SettingsError::ConfigReadOnly),
            ),
            Err(ConfigWriteError::Io(_)) => Some(SettingsError::ConfigWrite),
        };
        if let Some(e) = failed {
            // The records above said the change applied; it did not: say so (best effort).
            let undo = file.iter().map(|(p, c)| record(p, *c, false)).collect();
            if port.append_batch(undo).is_err() {
                tracing::warn!("a failed config.toml write could not be recorded");
            }
            return Err(e);
        }
        // PD-76: these two apply at once; the rest at the next start.
        for (p, _) in &file {
            match p.req {
                SettingChangeReq::JiraCommentsCap(n) => {
                    self.engine.admission().set_comments_cap(Some(n));
                }
                SettingChangeReq::AttentionMode(m) => *lock(&self.attention) = m,
                _ => {}
            }
        }
        Ok(())
    }
}

impl SettingsAdmin for CoreSettings {
    fn view(&self) -> SettingsView {
        let cfg = self.load();
        let cur = self.current(&cfg);
        let settings = self.engine.port().settings();
        SettingsView {
            limits: LimitsView {
                jira_comments_cap: cur.comments_cap,
                candidate_cache_mb: cur.candidate_cache_mb,
                max_pending_bytes_mb: cur.max_pending_bytes_mb,
                expiry_hours: cur.expiry_hours,
            },
            attention_mode: cur.attention_mode,
            retention_days: settings.retention_days,
            legal_hold: settings.legal_hold,
            anchor_dir: settings.anchor_dir,
            health: health_view(&self.store.health()),
            config_read_only: banner(&cfg),
            restart_pending: self.restart_pending(&cur),
        }
    }

    fn apply(&self, changes: Vec<SettingChangeReq>) -> Result<SettingsView, SettingsError> {
        if changes.len() > MAX_CHANGES {
            return Err(SettingsError::Invalid { key: "changes" });
        }
        for (i, c) in changes.iter().enumerate() {
            c.validate()?;
            if changes[..i].iter().any(|o| o.key() == c.key()) {
                return Err(SettingsError::Invalid { key: c.key() });
            }
        }
        let _job = self.enter()?;
        let cfg = self.load();
        if changes.iter().any(SettingChangeReq::file_backed) {
            self.require_writable(&cfg)?;
        }
        let cur = self.current(&cfg);
        let planned: Vec<Planned> = changes.into_iter().filter_map(|c| plan(c, &cur)).collect();
        // Every dialog first, with no lock held: one `Cancel` applies nothing.
        let mut confirmations = Vec::with_capacity(planned.len());
        for p in &planned {
            confirmations.push(match &p.dialog {
                Some(text) => Some(self.confirm(text)?),
                None => None,
            });
        }
        {
            let _effects = lock(&self.effects);
            self.still_running()?;
            // What the dialogs showed must still be what changes.
            if self.current(&self.load()) != cur {
                return Err(SettingsError::Conflict);
            }
            self.apply_planned(&planned, &confirmations)?;
        }
        Ok(self.view())
    }

    fn prune_backlog_now(&self) -> Result<PruneReport, SettingsError> {
        let _job = self.enter()?;
        let c = self.confirm(PRUNE_BACKLOG_TEXT)?;
        self.store
            .prune(Some(c))
            .map(PruneReport::from)
            .map_err(SettingsError::Audit)
    }

    fn verify_now(&self) -> VerifyNow {
        // It appends `VERIFY`: not once the shutdown began.
        let Ok(_job) = self.enter() else {
            return VerifyNow::DidNotComplete;
        };
        match self.store.try_full_verify() {
            Err(_) => VerifyNow::DidNotComplete,
            Ok(out) => {
                let count = out.findings.iter().filter(|f| f.kind.is_incident()).count();
                if count == 0 {
                    VerifyNow::Verified
                } else {
                    VerifyNow::Incident {
                        count: u64::try_from(count).unwrap_or(u64::MAX),
                    }
                }
            }
        }
    }

    fn record_app_change(&self, key: &str, old: Value, new: Value) -> Result<(), SettingsError> {
        let well_formed = !key.is_empty()
            && key.len() <= MAX_APP_KEY_CHARS
            && key.starts_with(|c: char| c.is_ascii_lowercase())
            && key
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.'));
        // A Settings key changes only through `apply`, an audit-policy key only through the store.
        let reserved = SETTING_KEYS.contains(&key)
            || key == crate::reconcile::KEY_ANCHOR_DIR
            || key.starts_with("instance.");
        if !well_formed || reserved {
            return Err(SettingsError::Invalid { key: "key" });
        }
        let size = |v: &Value| serde_json::to_vec(v).map_or(usize::MAX, |b| b.len());
        if size(&old) > MAX_APP_VALUE_BYTES || size(&new) > MAX_APP_VALUE_BYTES {
            return Err(SettingsError::Invalid { key: "value" });
        }
        let _job = self.enter()?;
        let ev = payloads::config_changed(ConfigSource::App, key, &old, &new, true);
        self.engine
            .port()
            .append(ev)
            .map(drop)
            .map_err(SettingsError::Audit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_requests_are_tagged_and_strict() {
        let parse = |s: &str| serde_json::from_str::<SettingChangeReq>(s);
        assert_eq!(
            parse(r#"{"key":"jira_comments_cap","value":250}"#).ok(),
            Some(SettingChangeReq::JiraCommentsCap(250))
        );
        assert_eq!(
            parse(r#"{"key":"max_pending_bytes_mb","value":null}"#).ok(),
            Some(SettingChangeReq::MaxPendingBytesMb(None))
        );
        assert_eq!(
            parse(r#"{"key":"attention_mode","value":"badge_only"}"#).ok(),
            Some(SettingChangeReq::AttentionMode(AttentionMode::BadgeOnly))
        );
        // Unknown fields, unknown keys and wrong types are refused.
        assert!(parse(r#"{"key":"legal_hold","value":true,"extra":1}"#).is_err());
        assert!(parse(r#"{"key":"audit_enabled","value":false}"#).is_err());
        assert!(parse(r#"{"key":"retention_days","value":"92"}"#).is_err());
        assert!(parse(r#"{"key":"attention_mode","value":"steal_focus"}"#).is_err());
    }

    #[test]
    fn bounds_name_the_key_only() {
        for (req, key) in [
            (SettingChangeReq::JiraCommentsCap(0), "jira_comments_cap"),
            (SettingChangeReq::JiraCommentsCap(1001), "jira_comments_cap"),
            (SettingChangeReq::CandidateCacheMb(0), "candidate_cache_mb"),
            (
                SettingChangeReq::MaxPendingBytesMb(Some(MAX_LIMIT_MB + 1)),
                "max_pending_bytes_mb",
            ),
            (SettingChangeReq::ExpiryHours(0), "expiry_hours"),
            (SettingChangeReq::ExpiryHours(169), "expiry_hours"),
            (SettingChangeReq::RetentionDays(91), "retention_days"),
            (SettingChangeReq::RetentionDays(36_501), "retention_days"),
        ] {
            assert_eq!(req.validate(), Err(SettingsError::Invalid { key }));
        }
        assert_eq!(SettingChangeReq::MaxPendingBytesMb(None).validate(), Ok(()));
        assert_eq!(SettingChangeReq::RetentionDays(92).validate(), Ok(()));
    }

    #[test]
    fn banner_texts_are_verbatim_and_never_echo_odd_versions() {
        let info = |w: Option<&str>| ConfigReadOnly {
            schema_version: Some(9),
            parsed: true,
            written_by: w.map(str::to_owned),
        };
        let ro = |w| {
            banner(&ConfigState::Unreadable { info: info(w) })
                .map(|b| b.text)
                .unwrap_or_default()
        };
        assert_eq!(
            ro(Some("1.4.0")),
            "config written by v1.4.0 could not be read; upgrade atlas-duck"
        );
        assert_eq!(
            ro(Some("x\u{202E}; settings fine")),
            "config written by a newer atlas-duck could not be read; upgrade atlas-duck"
        );
    }

    #[test]
    fn raising_texts_and_none_as_no_cap() {
        let cur = Current {
            comments_cap: 100,
            candidate_cache_mb: 512,
            max_pending_bytes_mb: Some(64),
            expiry_hours: 24,
            attention_mode: AttentionMode::ShowWithoutActivating,
            retention_days: 100,
            legal_hold: true,
        };
        let dialog = |r| plan(r, &cur).and_then(|p| p.dialog);
        assert_eq!(
            dialog(SettingChangeReq::MaxPendingBytesMb(None)).as_deref(),
            Some(
                "Raise the pending-bytes cap (MiB) from 64 to no cap? Higher limits let agents \
                 fetch more data before you review it."
            )
        );
        assert_eq!(dialog(SettingChangeReq::MaxPendingBytesMb(Some(32))), None);
        assert_eq!(dialog(SettingChangeReq::ExpiryHours(12)), None);
        assert!(dialog(SettingChangeReq::ExpiryHours(48)).is_some());
        assert_eq!(
            dialog(SettingChangeReq::LegalHold(false)).as_deref(),
            Some(LIFT_HOLD_TEXT)
        );
        assert_eq!(dialog(SettingChangeReq::RetentionDays(200)), None);
        // An unchanged value plans nothing.
        assert!(plan(SettingChangeReq::JiraCommentsCap(100), &cur).is_none());
    }
}
