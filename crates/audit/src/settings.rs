//! The audit-authoritative settings (§8.8, §7.7, L32, P5): retention, legal hold, anchor
//! directory and the per-instance policy (confirmed origin, CA fingerprint, proxy).
//!
//! They live in the audit log, not in a table. The view is the `settings` snapshot of the
//! latest retained `PRUNE` (defaults before the first prune) overlaid, in `seq` order, with
//! every later policy `CONFIG_CHANGED` and `LEGAL_HOLD_CHANGED` whose payload says
//! `applied: true`. Every `PRUNE` embeds the snapshot ([`Settings::to_json`]), so pruning the
//! events that set a value never loses it. The writer builds the view when it opens the store
//! (decrypting only those rows) and keeps it; it changes only through
//! [`crate::Store::apply_setting`] and [`crate::Store::reconcile_config_file`], and a caller
//! cannot append a policy `CONFIG_CHANGED` itself (the writer refuses it).
//!
//! The store keeps instance strings verbatim; validation and normalisation are `core`'s.

use std::collections::BTreeMap;

use rusqlite::Connection;
use serde_json::{Map, Value, json};

use crate::crypto::Kek;
use crate::encoding::{FIELD_LIST, RowFields};
use crate::error::{AuditError, OpenError};
use crate::types::{Confirmed, EventType};
use crate::verify::Deks;
use crate::writer::{PreparedEvent, Writer};

/// `retention_days` default and minimum (§8.8, L09).
pub const RETENTION_DEFAULT: u32 = 100;
pub const RETENTION_MIN: u32 = 92;

/// One instance's audit-authoritative policy (C.3), keyed by `instance_id` (never alias).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstancePolicy {
    /// `Some`: the confirmed origin (L32); `None`: unconfirmed or removed.
    pub origin: Option<String>,
    pub ca_fingerprint: Option<String>,
    /// `None`: no per-instance setting (the OS static proxy applies, L42); `Some("direct")`:
    /// direct; `Some("host:port")`: an explicit proxy.
    pub proxy: Option<String>,
}

impl InstancePolicy {
    fn is_empty(&self) -> bool {
        self.origin.is_none() && self.ca_fingerprint.is_none() && self.proxy.is_none()
    }
}

/// The audit-authoritative settings (C.3 `Settings`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub retention_days: u32,
    pub legal_hold: bool,
    pub anchor_dir: Option<String>,
    /// Instances without any policy value are absent.
    pub instances: BTreeMap<String, InstancePolicy>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            retention_days: RETENTION_DEFAULT,
            legal_hold: false,
            anchor_dir: None,
            instances: BTreeMap::new(),
        }
    }
}

const BAD_SNAPSHOT: AuditError = AuditError::Invalid("settings snapshot is malformed");

fn opt_string(v: &Value) -> Result<Option<String>, AuditError> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) if !s.is_empty() => Ok(Some(s.clone())),
        _ => Err(BAD_SNAPSHOT),
    }
}

fn retention_of(v: &Value) -> Result<u32, AuditError> {
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n >= RETENTION_MIN)
        .ok_or(BAD_SNAPSHOT)
}

impl Settings {
    /// `{anchor_dir, instances: {<id>: {ca_fingerprint, origin, proxy}}, legal_hold,
    /// retention_days}` (JCS sorts the keys).
    pub fn to_json(&self) -> Value {
        let instances: Map<String, Value> = self
            .instances
            .iter()
            .map(|(id, p)| {
                (
                    id.clone(),
                    json!({
                        "ca_fingerprint": p.ca_fingerprint,
                        "origin": p.origin,
                        "proxy": p.proxy,
                    }),
                )
            })
            .collect();
        json!({
            "anchor_dir": self.anchor_dir,
            "instances": instances,
            "legal_hold": self.legal_hold,
            "retention_days": self.retention_days,
        })
    }

    /// The inverse of [`Settings::to_json`]. Strict: exactly those four keys, a retention of
    /// at least 92, string-or-null values; anything else is `Invalid` (the caller fails
    /// closed rather than guess a policy).
    pub fn from_json(v: &Value) -> Result<Settings, AuditError> {
        let o = v.as_object().ok_or(BAD_SNAPSHOT)?;
        if o.len() != 4 {
            return Err(BAD_SNAPSHOT);
        }
        let get = |k: &str| o.get(k).ok_or(BAD_SNAPSHOT);
        let mut instances = BTreeMap::new();
        for (id, p) in get("instances")?.as_object().ok_or(BAD_SNAPSHOT)? {
            let p = p.as_object().filter(|p| p.len() == 3).ok_or(BAD_SNAPSHOT)?;
            let field = |k: &str| opt_string(p.get(k).ok_or(BAD_SNAPSHOT)?);
            let policy = InstancePolicy {
                origin: field("origin")?,
                ca_fingerprint: field("ca_fingerprint")?,
                proxy: field("proxy")?,
            };
            if id.is_empty() {
                return Err(BAD_SNAPSHOT);
            }
            if !policy.is_empty() {
                instances.insert(id.clone(), policy);
            }
        }
        Ok(Settings {
            retention_days: retention_of(get("retention_days")?)?,
            legal_hold: get("legal_hold")?.as_bool().ok_or(BAD_SNAPSHOT)?,
            anchor_dir: opt_string(get("anchor_dir")?)?,
            instances,
        })
    }
}

/// One settings change a caller asks for (`Store::apply_setting`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingChange {
    RetentionDays(u32),
    LegalHold(bool),
    AnchorDir(Option<String>),
    InstanceOrigin {
        instance_id: String,
        origin: Option<String>,
    },
    InstanceCaFingerprint {
        instance_id: String,
        fingerprint: Option<String>,
    },
    InstanceProxy {
        instance_id: String,
        proxy: Option<String>,
    },
}

/// What the config file asks for; `None` = the file does not mention the value. `anchor_dir`:
/// `Some(None)` = the file asks for no anchor directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilePolicy {
    pub retention_days: Option<u32>,
    pub legal_hold: Option<bool>,
    pub anchor_dir: Option<Option<String>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Origin,
    CaFingerprint,
    Proxy,
}

enum PolicyKey<'a> {
    Retention,
    AnchorDir,
    Instance(&'a str, Field),
}

/// The `CONFIG_CHANGED.key` values that are policy: `retention_days`, `anchor_dir`,
/// `instance.<id>.origin`, `instance.<id>.ca_fingerprint`, `instance.<id>.proxy`.
fn parse_key(key: &str) -> Option<PolicyKey<'_>> {
    match key {
        "retention_days" => return Some(PolicyKey::Retention),
        "anchor_dir" => return Some(PolicyKey::AnchorDir),
        _ => {}
    }
    let rest = key.strip_prefix("instance.")?;
    for (suffix, field) in [
        (".origin", Field::Origin),
        (".ca_fingerprint", Field::CaFingerprint),
        (".proxy", Field::Proxy),
    ] {
        if let Some(id) = rest.strip_suffix(suffix) {
            return (!id.is_empty()).then_some(PolicyKey::Instance(id, field));
        }
    }
    None
}

/// Whether `key` names a policy value (callers may append such a `CONFIG_CHANGED` only as a
/// record of a file difference that was not applied: `source: "file"`, `applied: false`).
pub(crate) fn is_policy_key(key: &str) -> bool {
    parse_key(key).is_some()
}

fn key_of(id: &str, f: Field) -> String {
    let suffix = match f {
        Field::Origin => "origin",
        Field::CaFingerprint => "ca_fingerprint",
        Field::Proxy => "proxy",
    };
    format!("instance.{id}.{suffix}")
}

/// The one function that changes a view, used for live changes and for the replay at open, so
/// the two cannot differ. Applies only rows with `applied: true`; `CONFIG_CHANGED` rows with a
/// non-policy key are not the view's business. A policy row that cannot be read is an error.
pub(crate) fn apply_event(
    s: &mut Settings,
    event_type: EventType,
    p: &Value,
) -> Result<(), AuditError> {
    // A `CONFIG_CHANGED` a caller appended may have any payload shape: without a policy key
    // it is not the view's business and must never poison it.
    if event_type == EventType::CONFIG_CHANGED
        && p.get("key")
            .and_then(Value::as_str)
            .and_then(parse_key)
            .is_none()
    {
        return Ok(());
    }
    let o = p.as_object().ok_or(BAD_SNAPSHOT)?;
    match event_type {
        EventType::LEGAL_HOLD_CHANGED => {
            if o.get("applied")
                .and_then(Value::as_bool)
                .ok_or(BAD_SNAPSHOT)?
            {
                s.legal_hold = o.get("new").and_then(Value::as_bool).ok_or(BAD_SNAPSHOT)?;
            }
            Ok(())
        }
        EventType::CONFIG_CHANGED => {
            let Some(key) = o.get("key").and_then(Value::as_str).and_then(parse_key) else {
                return Ok(());
            };
            if !o
                .get("applied")
                .and_then(Value::as_bool)
                .ok_or(BAD_SNAPSHOT)?
            {
                return Ok(());
            }
            let new = o.get("new").ok_or(BAD_SNAPSHOT)?;
            match key {
                PolicyKey::Retention => s.retention_days = retention_of(new)?,
                PolicyKey::AnchorDir => s.anchor_dir = opt_string(new)?,
                PolicyKey::Instance(id, field) => {
                    let v = opt_string(new)?;
                    let e = s.instances.entry(id.to_string()).or_default();
                    match field {
                        Field::Origin => e.origin = v,
                        Field::CaFingerprint => e.ca_fingerprint = v,
                        Field::Proxy => e.proxy = v,
                    }
                    if e.is_empty() {
                        s.instances.remove(id);
                    }
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Builds the view from the log. Only a database error is an `Err`. A settings row that cannot
/// be read (key, hash, JSON, shape) makes the view untrusted (`false`): whoever reads a policy
/// from it must then fail closed, because a lost legal hold or retention would let prune
/// destroy records. The settings returned in that case are a best effort.
pub(crate) fn load_view(conn: &Connection, kek: &Kek) -> Result<(Settings, bool), OpenError> {
    let sqlite = |e: rusqlite::Error| OpenError::Sqlite(e.to_string());
    let mut deks = Deks::new(kek);
    let mut trusted = true;
    let mut view = Settings::default();
    let mut from_seq = 0u64;
    {
        let sql = format!(
            "SELECT {} FROM events WHERE event_type = 'PRUNE' ORDER BY seq DESC LIMIT 1",
            FIELD_LIST.join(", ")
        );
        let mut stmt = conn.prepare(&sql).map_err(sqlite)?;
        let mut rows = stmt.query([]).map_err(sqlite)?;
        if let Some(r) = rows.next().map_err(sqlite)? {
            match RowFields::from_row(r) {
                Ok(f) => {
                    from_seq = f.seq;
                    let snapshot = match deks.decrypt_json(conn, &f).map_err(sqlite)? {
                        Ok(Some(p)) => p
                            .get("settings")
                            .map(Settings::from_json)
                            .and_then(Result::ok),
                        _ => None,
                    };
                    match snapshot {
                        Some(s) => view = s,
                        None => trusted = false,
                    }
                }
                Err(_) => trusted = false,
            }
        }
    }
    let sql = format!(
        "SELECT {} FROM events WHERE seq > ?1 \
         AND event_type IN ('CONFIG_CHANGED', 'LEGAL_HOLD_CHANGED') ORDER BY seq",
        FIELD_LIST.join(", ")
    );
    let mut stmt = conn.prepare(&sql).map_err(sqlite)?;
    let mut rows = stmt
        .query([i64::try_from(from_seq).unwrap_or(i64::MAX)])
        .map_err(sqlite)?;
    while let Some(r) = rows.next().map_err(sqlite)? {
        let Ok(f) = RowFields::from_row(r) else {
            trusted = false;
            continue;
        };
        let Some(event_type) = EventType::parse(f.event_type) else {
            trusted = false;
            continue;
        };
        match deks.decrypt_json(conn, &f).map_err(sqlite)? {
            Ok(Some(p)) => {
                if apply_event(&mut view, event_type, &p).is_err() {
                    trusted = false;
                }
            }
            _ => trusted = false,
        }
    }
    Ok((view, trusted))
}

/// `{dialog_text_sha256: <hex>}` or null.
fn confirmed_json(c: Option<&Confirmed>) -> Value {
    c.map_or(
        Value::Null,
        |c| json!({ "dialog_text_sha256": hex::encode(c.dialog_text_sha256) }),
    )
}

/// One change as the writer will log it.
struct Planned {
    event_type: EventType,
    key: Option<String>,
    instance_id: Option<String>,
    old: Value,
    requested: Value,
    new: Value,
    applied: bool,
    /// The `NeedsConfirmation` name when the change needs a confirmation.
    needs_confirmation: Option<&'static str>,
}

fn str_value(s: &Option<String>) -> Value {
    s.as_ref().map_or(Value::Null, |s| json!(s))
}

fn check_text(s: &Option<String>) -> Result<(), AuditError> {
    match s {
        Some(s) if s.is_empty() => Err(AuditError::Invalid("an empty value")),
        _ => Ok(()),
    }
}

/// What `change` does to `s`, and what it needs. A change that leaves the value as it is is
/// `Invalid` (nothing to log).
fn plan(s: &Settings, change: &SettingChange) -> Result<Planned, AuditError> {
    let unchanged = AuditError::Invalid("the setting already has this value");
    let instance_change =
        |id: &str, field: Field, old: Option<&String>, new: &Option<String>, confirm: bool| {
            if id.is_empty() {
                return Err(AuditError::Invalid("an empty instance_id"));
            }
            check_text(new)?;
            if old == new.as_ref() {
                return Err(AuditError::Invalid("the setting already has this value"));
            }
            Ok(Planned {
                event_type: EventType::CONFIG_CHANGED,
                key: Some(key_of(id, field)),
                instance_id: Some(id.to_string()),
                old: old.map_or(Value::Null, |o| json!(o)),
                requested: str_value(new),
                new: str_value(new),
                applied: true,
                needs_confirmation: confirm.then_some(match field {
                    Field::Origin => "instance_origin",
                    Field::CaFingerprint => "instance_ca_fingerprint",
                    Field::Proxy => "instance_proxy",
                }),
            })
        };
    let current = |id: &str| s.instances.get(id).cloned().unwrap_or_default();
    match change {
        SettingChange::RetentionDays(n) => {
            if *n < RETENTION_MIN {
                return Err(AuditError::Invalid("retention below the 92-day minimum"));
            }
            if *n == s.retention_days {
                return Err(unchanged);
            }
            Ok(Planned {
                event_type: EventType::CONFIG_CHANGED,
                key: Some("retention_days".into()),
                instance_id: None,
                old: json!(s.retention_days),
                requested: json!(n),
                new: json!(n),
                applied: true,
                needs_confirmation: (*n < s.retention_days).then_some("retention_days"),
            })
        }
        SettingChange::LegalHold(on) => {
            if *on == s.legal_hold {
                return Err(unchanged);
            }
            Ok(Planned {
                event_type: EventType::LEGAL_HOLD_CHANGED,
                key: None,
                instance_id: None,
                old: json!(s.legal_hold),
                requested: json!(on),
                new: json!(on),
                applied: true,
                needs_confirmation: (!on).then_some("legal_hold"),
            })
        }
        SettingChange::AnchorDir(dir) => {
            check_text(dir)?;
            if *dir == s.anchor_dir {
                return Err(unchanged);
            }
            Ok(Planned {
                event_type: EventType::CONFIG_CHANGED,
                key: Some("anchor_dir".into()),
                instance_id: None,
                old: str_value(&s.anchor_dir),
                requested: str_value(dir),
                new: str_value(dir),
                applied: true,
                needs_confirmation: Some("anchor_dir"),
            })
        }
        SettingChange::InstanceOrigin {
            instance_id,
            origin,
        } => instance_change(
            instance_id,
            Field::Origin,
            current(instance_id).origin.as_ref(),
            origin,
            true,
        ),
        SettingChange::InstanceCaFingerprint {
            instance_id,
            fingerprint,
        } => instance_change(
            instance_id,
            Field::CaFingerprint,
            current(instance_id).ca_fingerprint.as_ref(),
            fingerprint,
            // Removing a pinned CA is stricter; setting or changing one is on the §10.3 list.
            fingerprint.is_some(),
        ),
        SettingChange::InstanceProxy { instance_id, proxy } => instance_change(
            instance_id,
            Field::Proxy,
            current(instance_id).proxy.as_ref(),
            proxy,
            false,
        ),
    }
}

impl Planned {
    /// The payload as the view's replay reads it.
    fn payload(&self, source: &str, confirmed: Option<&Confirmed>) -> Value {
        let mut o = Map::new();
        o.insert("source".into(), json!(source));
        if let Some(k) = &self.key {
            o.insert("key".into(), json!(k));
            o.insert("requested".into(), self.requested.clone());
        }
        o.insert("old".into(), self.old.clone());
        o.insert("new".into(), self.new.clone());
        o.insert("applied".into(), json!(self.applied));
        o.insert("confirmed".into(), confirmed_json(confirmed));
        Value::Object(o)
    }

    fn event(&self, payload: &Value) -> Result<PreparedEvent, AuditError> {
        let mut p = PreparedEvent::system(self.event_type, payload)?;
        p.instance_id = self.instance_id.clone();
        Ok(p)
    }
}

fn untrusted() -> AuditError {
    AuditError::AppendFailed("the settings view could not be rebuilt from the audit log".into())
}

impl Writer {
    /// Makes `s` the view (writer thread) and publishes it for `Store::settings`.
    pub(crate) fn set_view(&mut self, s: Settings) {
        *crate::writer::lock(&self.st.shared.settings) = s.clone();
        self.st.settings = s;
    }

    /// Logs the planned changes in one transaction, then applies them to the view; the view
    /// changes only if the commit succeeded.
    fn log_settings(
        &mut self,
        changes: &[(&Planned, Value)],
    ) -> Result<Vec<crate::types::Committed>, AuditError> {
        let mut next = self.st.settings.clone();
        let mut events = Vec::with_capacity(changes.len());
        for (p, payload) in changes {
            apply_event(&mut next, p.event_type, payload)?;
            events.push(p.event(payload)?);
        }
        let rows = self.append_tx(events)?;
        self.set_view(next);
        Ok(rows)
    }

    /// `Store::apply_setting` (C.3, §8.8, §10.3): the confirmation rules, then one
    /// `CONFIG_CHANGED` / `LEGAL_HOLD_CHANGED` row with `source: "app"`.
    pub(crate) fn apply_setting_run(
        &mut self,
        change: SettingChange,
        confirmed: Option<Confirmed>,
    ) -> Result<crate::types::Committed, AuditError> {
        if !self.st.settings_trusted {
            return Err(untrusted());
        }
        let planned = plan(&self.st.settings, &change)?;
        if let Some(name) = planned.needs_confirmation
            && confirmed.is_none()
        {
            return Err(AuditError::NeedsConfirmation(name));
        }
        let payload = planned.payload("app", confirmed.as_ref());
        let mut rows = self.log_settings(&[(&planned, payload)])?;
        rows.pop()
            .ok_or_else(|| AuditError::AppendFailed("the writer returned no row".into()))
    }

    /// `Store::reconcile_config_file` (X-01, §8.8): every file value that differs from the view
    /// is logged with `source: "file"` in one transaction, before any prune; then prune may
    /// run in this process. A file may raise the retention and set the legal hold; it never
    /// lowers the retention, lifts the hold or touches the anchor directory (those are logged
    /// with `applied: false`).
    pub(crate) fn reconcile_run(
        &mut self,
        file: &FilePolicy,
    ) -> Result<Vec<crate::types::Committed>, AuditError> {
        if !self.st.settings_trusted {
            return Err(untrusted());
        }
        let s = self.st.settings.clone();
        let mut planned: Vec<Planned> = Vec::new();
        if let Some(requested) = file.retention_days {
            let new = requested.max(RETENTION_MIN);
            // The file value itself is compared: a lowering the clamp hides is still logged.
            if requested != s.retention_days {
                planned.push(Planned {
                    event_type: EventType::CONFIG_CHANGED,
                    key: Some("retention_days".into()),
                    instance_id: None,
                    old: json!(s.retention_days),
                    requested: json!(requested),
                    new: json!(new),
                    applied: new > s.retention_days,
                    needs_confirmation: None,
                });
            }
        }
        if let Some(on) = file.legal_hold
            && on != s.legal_hold
        {
            planned.push(Planned {
                event_type: EventType::LEGAL_HOLD_CHANGED,
                key: None,
                instance_id: None,
                old: json!(s.legal_hold),
                requested: json!(on),
                new: json!(on),
                applied: on,
                needs_confirmation: None,
            });
        }
        if let Some(dir) = &file.anchor_dir {
            check_text(dir)?;
            if *dir != s.anchor_dir {
                planned.push(Planned {
                    event_type: EventType::CONFIG_CHANGED,
                    key: Some("anchor_dir".into()),
                    instance_id: None,
                    old: str_value(&s.anchor_dir),
                    requested: str_value(dir),
                    new: str_value(dir),
                    applied: false,
                    needs_confirmation: None,
                });
            }
        }
        let rows = if planned.is_empty() {
            Vec::new()
        } else {
            let changes: Vec<(&Planned, Value)> = planned
                .iter()
                .map(|p| (p, p.payload("file", None)))
                .collect();
            self.log_settings(&changes)?
        };
        self.st.config_reconciled = true;
        Ok(rows)
    }
}
