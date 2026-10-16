//! The core's `InstanceAdmin` (C.7, §7.1, §10.3): adding instances, confirming and changing
//! origins through the native confirmation, the proxy, and the credential window's token set and
//! re-test. Every security-weakening change goes through [`NativeConfirmer`] with a dialog text
//! built here, and the audit settings record the confirmation (`Confirmed`, Q5): `config.toml`
//! proposes, the audit log decides (I-31).

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use atlas_duck_atlassian::{
    BaseUrlError, CredentialError, NormalizedBaseUrl, PatSecret, StoredCredential, StoredIdentity,
    url_hash, username_matches,
};
use atlas_duck_audit::{AuditError, Confirmed, SettingChange, Settings, UtcInstant};
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::mixed_script::is_mixed_script;
use atlas_duck_registry::Product;
use sha2::{Digest, Sha256};

use super::connection_test::{self, Target};
use super::state::{CaBundle, DeriveCtx, InstanceRuntime, InstanceState, InstanceTable, parse_ca};
use super::work::{AdminWork, Job};
use super::{
    AddInstance, AdminError, ConnectionFailure, ConnectionReport, InstanceAdmin, InstanceView,
};
use crate::config::instances::{
    InstanceConfig, add_instance, instances, is_valid_alias, set_base_url, set_proxy_setting,
};
use crate::config::{ConfigState, ConfigWriteError, load_config};
use crate::core::{Confirm, NativeConfirmer};
use crate::engine::Engine;
use crate::engine::write::InstanceChange;
use crate::identity::{self, RecheckResult};
use crate::ids::InstanceId;
use crate::metadata::FieldCache;
use crate::payloads::{self, CredentialChange};
use crate::proxy::ProxySetting;

/// §7.1 verbatim.
const TOKEN_OWNER_CHANGE: &str = "This token belongs to ";

/// The thread the token-owner dialog runs on (PD-13, PD-25, M3 M-6).
pub const OWNER_CONFIRM_THREAD: &str = "atlas-duck-owner-confirm";

/// The core's `InstanceAdmin`.
pub struct CoreInstances {
    engine: Arc<Engine>,
    config_path: Option<PathBuf>,
    /// The calls that can write or send, drained by the shutdown (M3 M-4).
    work: Arc<AdminWork>,
    /// Minutes east of UTC of the app's local time zone (`Core::set_utc_offset`): the local date
    /// the expiry warnings count from (PD-84); `None` is UTC.
    utc_offset_min: Mutex<Option<i32>>,
    /// One table rebuild at a time, from its snapshot to its swap: a rebuild never swaps in a
    /// table older than the one before it (M6 T9 review I-2).
    reload_lock: Mutex<()>,
}

fn audit(msg: &'static str) -> AdminError {
    AdminError::Audit(AuditError::Invalid(msg))
}

fn config_write_error(e: ConfigWriteError) -> AdminError {
    match e {
        ConfigWriteError::ReadOnly | ConfigWriteError::Unreadable => AdminError::ConfigReadOnly,
        ConfigWriteError::Io(_) => audit("config.toml could not be written"),
    }
}

fn confirmed(text: &str) -> Confirmed {
    Confirmed {
        dialog_text_sha256: Sha256::digest(text.as_bytes()).into(),
    }
}

fn product_name(p: Product) -> &'static str {
    match p {
        Product::Jira => "Jira",
        Product::Confluence => "Confluence",
    }
}

/// `Warning: <host> is a loopback address.` / `... an IP address.` (§7.1).
fn host_warnings(host: &str) -> Option<String> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(ip) if ip.is_loopback() => Some(format!("Warning: {host} is a loopback address.")),
        Err(_) if bare.eq_ignore_ascii_case("localhost") => {
            Some(format!("Warning: {host} is a loopback address."))
        }
        Ok(_) => Some(format!("Warning: {host} is an IP address.")),
        Err(_) => None,
    }
}

/// §10.3: the text of the add dialog. The warnings come first: the URL is attacker-sized (a long
/// percent-encoded path) and a native message box cuts what does not fit (M6 T25 review I-2).
pub(crate) fn add_text(product: Product, alias: &str, origin: &NormalizedBaseUrl) -> String {
    let mut text = String::new();
    if let Some(w) = host_warnings(origin.host()) {
        text.push_str(&w);
        text.push('\n');
    }
    text.push_str(&format!(
        "Add {} instance \"{alias}\" at {}?",
        product_name(product),
        origin.as_str()
    ));
    text
}

/// §10.3: the text of the URL-change dialog; the warnings come first (see [`add_text`]).
pub(crate) fn change_text(alias: &str, old: &NormalizedBaseUrl, new: &NormalizedBaseUrl) -> String {
    let mut text = String::new();
    if let Some(w) = host_warnings(new.host()) {
        text.push_str(&w);
        text.push('\n');
    }
    if old.host() != new.host() {
        text.push_str(&format!(
            "Warning: the host changes from {} to {}.\n",
            old.host(),
            new.host()
        ));
    }
    text.push_str(&format!(
        "Change \"{alias}\" from {} to {}? The stored token will be deleted.",
        old.as_str(),
        new.as_str()
    ));
    text
}

/// A server- or file-supplied name as a native dialog may show it (review I-6): every invisible
/// or bidi character, and the line breaks and tabs the display escape keeps, as `⟨U+XXXX⟩`;
/// capped; a mixed-script name is flagged (§6.4).
pub(crate) fn shown(s: &str) -> String {
    const CAP: usize = 200;
    let mut out = String::new();
    for (n, c) in escape_for_display(s).chars().enumerate() {
        if n == CAP {
            out.push('…');
            break;
        }
        match c {
            '\n' | '\r' | '\t' => out.push_str(&format!("⟨U+{:04X}⟩", c as u32)),
            _ => out.push(c),
        }
    }
    if is_mixed_script(s) {
        out.push_str(" [mixed scripts]");
    }
    out
}

/// PD-84 (§7.1): the days from the local date to a token's expiry date: `0` on the expiry day,
/// negative once it passed.
pub(crate) fn days_left(expires: chrono::NaiveDate, today: chrono::NaiveDate) -> i64 {
    (expires - today).num_days()
}

/// PD-84 (§7.1): the tightest of the 14, 7 and 1 day warnings for a token `days_left` days from
/// its expiry; the expiry day itself and every later day are `1`.
pub(crate) fn expiry_warning(days_left: i64) -> Option<u8> {
    match days_left {
        ..=1 => Some(1),
        2..=7 => Some(7),
        8..=14 => Some(14),
        _ => None,
    }
}

/// PD-84: the local date at `now`, `offset_min` minutes east of UTC (`None` is UTC).
fn local_date(now: UtcInstant, offset_min: Option<i32>) -> chrono::NaiveDate {
    let shift = i64::from(offset_min.unwrap_or(0)) * 60_000;
    UtcInstant(now.0.saturating_add(shift)).date()
}

/// The stored token goes (audit before effect): after an origin change (it is bound to the old
/// origin) or on request (`delete_token`). The delete is attempted even when the old token could
/// not be read, and `CREDENTIAL_CHANGED {deleted}` commits first; a failed append
/// (`AdminError::Audit`) leaves the token in place, where the origin hash keeps it unused (review
/// I-4, ruling 13). A failed keychain delete leaves it in place too, and a corrective
/// `CREDENTIAL_CHANGED {delete_failed}` says so (M6 T9 review I-1). `on_request`: refused
/// `ShuttingDown` before the append once the shutdown began (the keychain read can outlast its
/// wait, review I-3); an origin change is committed already and goes on. `Ok(false)`: nothing was
/// stored, nothing logged. Blocking (store, keychain).
fn delete_stored(engine: &Engine, id: &str, on_request: bool) -> Result<bool, AdminError> {
    let creds = engine.credentials().clone();
    let old_key = match creds.load(id) {
        Ok(Some(c)) => Some(c.identity.atlassian_user_key.clone()),
        Ok(None) => return Ok(false),
        Err(_) => None,
    };
    if on_request && engine.is_shutting_down() {
        return Err(AdminError::ShuttingDown);
    }
    let ev = payloads::credential_changed(
        id,
        CredentialChange::Deleted,
        old_key.as_deref(),
        None,
        None,
    );
    engine.port().append(ev).map_err(AdminError::Audit)?;
    if let Err(e) = creds.delete(id) {
        // The record above said the token went; it did not: say so (as `set_token`'s
        // `store_failed`).
        let failed = payloads::credential_changed(
            id,
            CredentialChange::DeleteFailed,
            old_key.as_deref(),
            None,
            None,
        );
        let _ = engine.port().append(failed);
        return Err(AdminError::Keychain(e));
    }
    Ok(true)
}

/// The token-owner dialog on a dedicated OS thread, never on a tokio worker or the blocking pool
/// (PD-13, PD-25, M3 M-6; as `decision::batch`); the async caller waits for it off the workers,
/// one blocking-pool thread joining it while the dialog is open.
async fn confirm_on_own_thread(confirmer: Arc<dyn NativeConfirmer>, text: String) -> Confirm {
    tokio::task::spawn_blocking(move || {
        std::thread::Builder::new()
            .name(OWNER_CONFIRM_THREAD.into())
            .spawn(move || confirmer.confirm(&text))
            .map(|t| t.join().unwrap_or(Confirm::Cancel))
            .unwrap_or(Confirm::Cancel)
    })
    .await
    .unwrap_or(Confirm::Cancel)
}

/// The most certificates the CA dialog lists one by one; the bundle fingerprint covers the rest.
const CA_LISTED: usize = 5;

/// §10.3: the text of the custom-CA dialog: the bundle fingerprint, then for each certificate
/// its subject, issuer, validity and own SHA-256 (review I-5).
pub(crate) fn ca_text(alias: &str, bundle: &CaBundle) -> String {
    let n = bundle.certs.len();
    let mut text = format!(
        "Trust the custom CA for \"{alias}\"? {n} certificate{}, bundle SHA-256 {}.",
        if n == 1 { "" } else { "s" },
        bundle.fingerprint
    );
    for (i, c) in bundle.certs.iter().take(CA_LISTED).enumerate() {
        text.push_str(&format!(
            "\nCertificate {} of {n}\n  Subject: {}\n  Issuer: {}\n  Valid: {} to {}\n  SHA-256: {}",
            i + 1,
            shown(&c.subject),
            shown(&c.issuer),
            c.not_before,
            c.not_after,
            c.sha256
        ));
    }
    if n > CA_LISTED {
        text.push_str(&format!("\n... and {} more certificates.", n - CA_LISTED));
    }
    text
}

impl CoreInstances {
    pub(crate) fn new(engine: Arc<Engine>, config_path: Option<PathBuf>) -> CoreInstances {
        CoreInstances {
            engine,
            config_path,
            work: Arc::new(AdminWork::default()),
            utc_offset_min: Mutex::new(None),
            reload_lock: Mutex::new(()),
        }
    }

    /// The admin work the shutdown closes and waits for (M3 M-4).
    pub(crate) fn work(&self) -> &AdminWork {
        &self.work
    }

    pub(crate) fn set_utc_offset(&self, minutes: Option<i32>) {
        *self
            .utc_offset_min
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = minutes;
    }

    /// A call that can write or send: refused once the shutdown began (M3 M-4).
    fn enter(&self) -> Result<Job, AdminError> {
        self.work.enter(&self.engine)
    }

    /// Refuses to go on once the shutdown began: checked after a dialog (a user can answer one
    /// long after the shutdown's bounded wait) and before a step that writes.
    fn still_running(&self) -> Result<(), AdminError> {
        if self.engine.is_shutting_down() {
            return Err(AdminError::ShuttingDown);
        }
        Ok(())
    }

    /// The local date (PD-84): the engine's clock moved by the app's UTC offset.
    fn local_today(&self) -> chrono::NaiveDate {
        let offset = *self
            .utc_offset_min
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        local_date(self.engine.clock().now_utc(), offset)
    }

    fn path(&self) -> Result<&PathBuf, AdminError> {
        self.config_path.as_ref().ok_or(AdminError::ConfigReadOnly)
    }

    fn find(&self, alias: &str) -> Result<InstanceRuntime, AdminError> {
        self.engine
            .instances()
            .by_alias(alias)
            .cloned()
            .ok_or(AdminError::NotFound)
    }

    fn settings(&self) -> Settings {
        self.engine.port().settings()
    }

    /// The dialog of a synchronous call (on the caller's blocking-pool thread, PD-13); an OK
    /// given after the shutdown began changes nothing.
    fn confirm(&self, text: &str) -> Result<(), AdminError> {
        match self.engine.confirmer().confirm(text) {
            Confirm::Ok => self.still_running(),
            Confirm::Cancel => Err(AdminError::Cancelled),
        }
    }

    /// Applies a setting unless the audit settings already say so (an unchanged value is
    /// `AuditError::Invalid` in the store); `text` is the confirmation dialog shown for it.
    fn apply(&self, change: SettingChange, text: Option<&str>) -> Result<(), AdminError> {
        let settings = self.settings();
        let (id, current, new) = match &change {
            SettingChange::InstanceOrigin {
                instance_id,
                origin,
            } => (
                instance_id,
                settings
                    .instances
                    .get(instance_id)
                    .and_then(|p| p.origin.clone()),
                origin.clone(),
            ),
            SettingChange::InstanceCaFingerprint {
                instance_id,
                fingerprint,
            } => (
                instance_id,
                settings
                    .instances
                    .get(instance_id)
                    .and_then(|p| p.ca_fingerprint.clone()),
                fingerprint.clone(),
            ),
            SettingChange::InstanceProxy { instance_id, proxy } => (
                instance_id,
                settings
                    .instances
                    .get(instance_id)
                    .and_then(|p| p.proxy.clone()),
                proxy.clone(),
            ),
            _ => return Err(audit("not an instance setting")),
        };
        let _ = id;
        if current == new {
            return Ok(());
        }
        self.engine
            .port()
            .apply_setting(change, text.map(confirmed))
            .map(|_| ())
            .map_err(AdminError::Audit)
    }

    /// `config.toml` as it is now (`Absent` without a path or when it cannot be read): what
    /// `Core::after_restore` reconciles the audit policy against.
    pub(crate) async fn current_config(self: &Arc<Self>) -> ConfigState {
        let path = self.config_path.clone();
        tokio::task::spawn_blocking(move || {
            path.and_then(|p| load_config(&p).ok())
                .unwrap_or(ConfigState::Absent)
        })
        .await
        .unwrap_or(ConfigState::Absent)
    }

    /// [`CoreInstances::reload`] off the runtime (`Core::after_restore`: a restore deleted
    /// PATs, so the table must be derived again).
    pub(crate) async fn reload_now(self: &Arc<Self>) {
        let this = self.clone();
        let _ = tokio::task::spawn_blocking(move || this.reload()).await;
    }

    /// PD-22: rebuilds the runtime table from `config.toml`, the audit settings and the
    /// keychain. The file-side records are logged at start only. The derivation runs on a
    /// snapshot without the table lock (keychain I/O); a change made to an instance meanwhile
    /// (a re-check's `needs_token`) is kept at the swap, under the lock (M3 M-14). Rebuilds run
    /// one at a time (`reload_lock`, review I-2). Blocking.
    fn reload(&self) -> Result<(), AdminError> {
        let _one = self
            .reload_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let path = self.path()?;
        let cfg = load_config(path).map_err(|_| AdminError::ConfigReadOnly)?;
        let settings = self.settings();
        let previous = self.engine.instances().clone();
        let (mut table, _file_side) = InstanceTable::derive(
            &cfg,
            &DeriveCtx {
                settings: &settings,
                creds: &**self.engine.credentials(),
                allow_http: self.engine.allow_http(),
                previous: Some(&previous),
            },
        );
        #[cfg(feature = "testing")]
        if let Some(p) = self.engine.hooks().pause_in_reload.clone() {
            let _ = self.engine.run_sync(async move { p.hold().await });
        }
        self.engine.swap_instances(move |current| {
            table.keep_newer(current);
            table
        });
        Ok(())
    }

    fn view(&self, alias: &str) -> Result<InstanceView, AdminError> {
        let rt = self.find(alias)?;
        Ok(self.view_of(&rt))
    }

    fn view_of(&self, i: &InstanceRuntime) -> InstanceView {
        let host = i.base.as_ref().map_or("", NormalizedBaseUrl::host);
        let resolved = self.engine.http().resolve(&i.proxy, host);
        let left = i.expires_at.map(|d| days_left(d, self.local_today()));
        InstanceView {
            alias: i.alias.clone(),
            product: i.product,
            origin: i.base.as_ref().map(NormalizedBaseUrl::as_str),
            state: i.state.as_str(),
            executes_as: i.identity.as_ref().map(|id| shown(&id.atlassian_user)),
            expires_at: i.expires_at.map(|d| d.format("%Y-%m-%d").to_string()),
            pac_configured: resolved.uses_os && resolved.pac_configured,
            proxy_effective: Some(resolved.effective),
            pending_url_change: i.pending_url_change.clone(),
            note: i.note.clone(),
            expiry_warning: left.and_then(expiry_warning),
            days_left: left,
        }
    }

    /// The origin of an instance a token can be set for: confirmed, https.
    fn usable(rt: &InstanceRuntime) -> Result<(String, NormalizedBaseUrl), AdminError> {
        match rt.state {
            InstanceState::InsecureScheme => return Err(AdminError::InsecureScheme),
            InstanceState::InstanceUnconfirmed => return Err(AdminError::Unconfirmed),
            _ => {}
        }
        match (&rt.id, &rt.base) {
            (Some(id), Some(base)) => Ok((id.clone(), base.clone())),
            _ => Err(AdminError::Unconfirmed),
        }
    }

    /// The stored credential of `id`, read off the async runtime; unreadable counts as none.
    async fn stored(&self, id: &str) -> Option<StoredCredential> {
        let (creds, id) = (self.engine.credentials().clone(), id.to_owned());
        tokio::task::spawn_blocking(move || creds.load(&id))
            .await
            .ok()
            .and_then(Result::ok)
            .flatten()
    }

    /// The CA of an instance whose file names one that the settings do not confirm: shows its
    /// fingerprint and records the confirmation.
    fn confirm_file_ca(&self, rt: &InstanceRuntime, id: &str) -> Result<(), AdminError> {
        let path = self.path()?;
        let cfg = load_config(path).map_err(|_| AdminError::ConfigReadOnly)?;
        let Some(c) = instances(&cfg)
            .unwrap_or_default()
            .into_iter()
            .find(|c| c.id.as_deref() == Some(id))
        else {
            return Ok(());
        };
        let Some(file) = c.ca_bundle else {
            return Ok(());
        };
        // The file is read once; the dialog shows, and the setting records, what those bytes
        // are. The table derived afterwards pins the bytes again against that fingerprint
        // (review I-1), so a swap in between is not trusted. The path is chosen by the file
        // (an agent can write it): the dialog is the only gate (spec §10.3).
        let Some(bundle) = std::fs::read(file).ok().and_then(|p| parse_ca(&p)) else {
            return Ok(());
        };
        let stored = self
            .settings()
            .instances
            .get(id)
            .and_then(|p| p.ca_fingerprint.clone());
        if stored.as_deref() == Some(bundle.fingerprint.as_str()) {
            return Ok(());
        }
        let text = ca_text(&rt.alias, &bundle);
        self.confirm(&text)?;
        self.apply(
            SettingChange::InstanceCaFingerprint {
                instance_id: id.to_owned(),
                fingerprint: Some(bundle.fingerprint),
            },
            Some(&text),
        )
    }

    /// Confirms and applies a new origin for a confirmed instance: the URL-change dialog, the
    /// origin setting, the PAT deleted, the instance `needs_token`, its writes `instance_changed`
    /// (§7.1, I-31). `file_url`: written to `config.toml` first (not for a change the file
    /// already asks for).
    fn change_origin(
        &self,
        rt: &InstanceRuntime,
        new: NormalizedBaseUrl,
        file_url: Option<&str>,
        job: &Job,
    ) -> Result<(), AdminError> {
        let (id, old) = Self::usable(rt)?;
        if old == new {
            return Ok(());
        }
        let text = change_text(&rt.alias, &old, &new);
        self.confirm(&text)?;
        if let Some(url) = file_url {
            let path = self.path()?;
            match set_base_url(path, &id, url) {
                Ok(true) => {}
                Ok(false) => return Err(AdminError::NotFound),
                Err(e) => return Err(config_write_error(e)),
            }
        }
        self.apply(
            SettingChange::InstanceOrigin {
                instance_id: id.clone(),
                origin: Some(new.as_str()),
            },
            Some(&text),
        )?;
        // The origin is committed from here on: the runtime follows it whatever else fails
        // (review I-4), and the first error is reported afterwards.
        let deleted = delete_stored(&self.engine, &id, false);
        self.engine.invalidate_client(&id);
        // Another server's field names (PD-46, T8 review M-5) and users (PD-99:
        // `instance_changed`).
        self.engine.field_cache().forget(&id);
        self.engine.user_cache().clear(&id);
        let reloaded = self.reload();
        if reloaded.is_err() {
            // The table could not be rebuilt: the instance still moves to the confirmed origin,
            // without a token (the deleted or hash-mismatched PAT is not usable there).
            let origin = new.clone();
            self.engine.update_instance(&id, move |rt| {
                rt.base = Some(origin);
                rt.state = InstanceState::NeedsToken;
                rt.identity = None;
                rt.expires_at = None;
                rt.pending_url_change = None;
            });
        }
        self.follow_writes(
            id,
            InstanceChange::OriginChanged {
                old: old.as_str(),
                new: new.as_str(),
            },
            job,
        );
        deleted?;
        reloaded
    }

    /// Carries a change to the instance's queued writes. `run_sync` refuses a current-thread
    /// caller (it must not block); the follow-up then runs detached instead of being dropped,
    /// under a fork of `job` (the shutdown waits for it, M3 M-4).
    fn follow_writes(&self, id: String, change: InstanceChange, job: &Job) {
        let eng = self.engine.clone();
        let (e2, id2, c2) = (eng.clone(), id.clone(), change.clone());
        if self
            .engine
            .run_sync(async move { e2.instance_changed(&id2, c2).await })
            .is_none()
        {
            let forked = job.fork();
            self.engine.spawn_detached(async move {
                eng.instance_changed(&id, change).await;
                drop(forked);
            });
        }
    }

    /// The runtime of `id` after a PAT was stored: `ok`, with the identity and expiry.
    fn pat_stored(
        &self,
        id: &str,
        identity: StoredIdentity,
        expires_at: Option<chrono::NaiveDate>,
        version: Option<atlas_duck_registry::Version>,
    ) {
        self.engine.update_instance(id, |rt| {
            rt.state = InstanceState::Ok;
            rt.note = None;
            rt.identity = Some(identity);
            rt.expires_at = expires_at;
            if version.is_some() {
                rt.version = version;
            }
        });
    }

    /// PD-46: after a passing connection test a Jira instance's field-name cache fills in the
    /// background.
    fn fill_field_cache(&self, rt: &InstanceRuntime, id: &str) {
        if rt.product == Product::Jira {
            FieldCache::spawn_fill(&self.engine, id);
        }
    }

    /// A connection test the shutdown cancelled failed because of the shutdown, not the server.
    fn tested(
        result: Result<connection_test::Tested, AdminError>,
        job: &Job,
    ) -> Result<connection_test::Tested, AdminError> {
        match result {
            Err(AdminError::ConnectionFailed(_)) if job.cancelled() => {
                Err(AdminError::ShuttingDown)
            }
            other => other,
        }
    }

    fn target(rt: &InstanceRuntime, id: String, origin: NormalizedBaseUrl) -> Target {
        Target {
            id,
            product: rt.product,
            origin,
            proxy: rt.proxy.clone(),
            ca_pem: rt.ca.as_ref().map(|c| c.pem().to_vec()),
        }
    }
}

#[async_trait::async_trait]
impl InstanceAdmin for CoreInstances {
    fn list(&self) -> Vec<InstanceView> {
        let table = self.engine.instances().clone();
        table.list().iter().map(|i| self.view_of(i)).collect()
    }

    fn add(&self, req: AddInstance) -> Result<InstanceView, AdminError> {
        let _job = self.enter()?;
        let origin = self
            .engine
            .normalize_origin(&req.base_url)
            .map_err(|e| match e {
                BaseUrlError::InsecureScheme => AdminError::InsecureScheme,
                BaseUrlError::Invalid(_) => AdminError::InvalidUrl,
            })?;
        let path = self.path()?.clone();
        let cfg = load_config(&path).map_err(|_| AdminError::ConfigReadOnly)?;
        if matches!(
            cfg,
            ConfigState::ReadOnly { .. } | ConfigState::Unreadable { .. }
        ) {
            return Err(AdminError::ConfigReadOnly);
        }
        if !is_valid_alias(&req.alias) {
            return Err(audit(
                "the alias must be 1-64 characters of A-Z a-z 0-9 . _ -",
            ));
        }
        let existing = instances(&cfg).map_err(|_| audit("config.toml instances are malformed"))?;
        if existing.iter().any(|c| c.alias == req.alias) {
            return Err(audit("the alias is already used"));
        }
        if req.is_default
            && existing
                .iter()
                .any(|c| c.is_default && c.product == req.product)
        {
            return Err(audit("the product already has a default instance"));
        }
        let ca = match &req.ca_pem {
            Some(pem) => Some((
                parse_ca(pem).ok_or(audit("no certificate in the CA bundle"))?,
                pem,
            )),
            None => None,
        };
        let text = add_text(req.product, &req.alias, &origin);
        self.confirm(&text)?;
        let ca_dialog = match &ca {
            Some((bundle, _)) => {
                let t = ca_text(&req.alias, bundle);
                self.confirm(&t)?;
                Some(t)
            }
            None => None,
        };
        let id = InstanceId::new().map_err(|_| audit("no randomness"))?.0;
        let ca_bundle = match &ca {
            Some((_, pem)) => {
                let dir = path
                    .parent()
                    .map_or_else(|| PathBuf::from("ca"), |p| p.join("ca"));
                std::fs::create_dir_all(&dir)
                    .map_err(|_| audit("the CA file could not be written"))?;
                let file = dir.join(format!("{id}.pem"));
                std::fs::write(&file, pem)
                    .map_err(|_| audit("the CA file could not be written"))?;
                Some(file)
            }
            None => None,
        };
        self.apply(
            SettingChange::InstanceOrigin {
                instance_id: id.clone(),
                origin: Some(origin.as_str()),
            },
            Some(&text),
        )?;
        if let (Some((bundle, _)), Some(t)) = (&ca, &ca_dialog) {
            self.apply(
                SettingChange::InstanceCaFingerprint {
                    instance_id: id.clone(),
                    fingerprint: Some(bundle.fingerprint.clone()),
                },
                Some(t),
            )?;
        }
        if req.proxy != ProxySetting::Os {
            self.apply(
                SettingChange::InstanceProxy {
                    instance_id: id.clone(),
                    proxy: Some(req.proxy.as_config_str()),
                },
                None,
            )?;
        }
        add_instance(
            &path,
            &InstanceConfig {
                id: Some(id),
                alias: req.alias.clone(),
                product: req.product,
                base_url_raw: origin.as_str(),
                ca_bundle,
                proxy: req.proxy.clone(),
                is_default: req.is_default,
            },
        )
        .map_err(config_write_error)?;
        self.reload()?;
        self.view(&req.alias)
    }

    fn confirm_config_instance(&self, alias: &str) -> Result<InstanceView, AdminError> {
        let _job = self.enter()?;
        let rt = self.find(alias)?;
        match rt.state {
            InstanceState::InstanceUnconfirmed => {}
            InstanceState::InsecureScheme => return Err(AdminError::InsecureScheme),
            _ => return self.view(alias),
        }
        // No id (the file was not writable when it was read) or an unusable URL: nothing to
        // confirm.
        let (Some(id), Some(origin)) = (rt.id.clone(), rt.base.clone()) else {
            return Err(AdminError::ConfigReadOnly);
        };
        let text = add_text(rt.product, &rt.alias, &origin);
        self.confirm(&text)?;
        self.apply(
            SettingChange::InstanceOrigin {
                instance_id: id.clone(),
                origin: Some(origin.as_str()),
            },
            Some(&text),
        )?;
        // The origin is committed: the table follows it even when the CA dialog is cancelled
        // (the unconfirmed CA then stays untrusted, review I-4).
        let ca = self.confirm_file_ca(&rt, &id);
        self.reload()?;
        ca?;
        self.view(alias)
    }

    fn accept_config_url_change(&self, alias: &str) -> Result<InstanceView, AdminError> {
        let job = self.enter()?;
        let rt = self.find(alias)?;
        let Some(url) = rt.pending_url_change.clone() else {
            return Err(AdminError::NotFound);
        };
        let new = self.engine.normalize_origin(&url).map_err(|e| match e {
            BaseUrlError::InsecureScheme => AdminError::InsecureScheme,
            BaseUrlError::Invalid(_) => AdminError::InvalidUrl,
        })?;
        self.change_origin(&rt, new, None, &job)?;
        self.view(alias)
    }

    fn change_base_url(&self, alias: &str, new_url: &str) -> Result<InstanceView, AdminError> {
        let job = self.enter()?;
        let rt = self.find(alias)?;
        let new = self.engine.normalize_origin(new_url).map_err(|e| match e {
            BaseUrlError::InsecureScheme => AdminError::InsecureScheme,
            BaseUrlError::Invalid(_) => AdminError::InvalidUrl,
        })?;
        let new_raw = new.as_str();
        self.change_origin(&rt, new, Some(&new_raw), &job)?;
        self.view(alias)
    }

    fn set_proxy(&self, alias: &str, proxy: ProxySetting) -> Result<InstanceView, AdminError> {
        let _job = self.enter()?;
        let rt = self.find(alias)?;
        let id = rt.id.clone().ok_or(AdminError::Unconfirmed)?;
        let path = self.path()?;
        // Core validates the string the setting stores (L42).
        let stored = (proxy != ProxySetting::Os).then(|| proxy.as_config_str());
        if let Some(s) = &stored
            && ProxySetting::parse(s).is_err()
        {
            return Err(audit("the proxy setting is malformed"));
        }
        match set_proxy_setting(path, &id, &proxy) {
            Ok(true) => {}
            Ok(false) => return Err(AdminError::NotFound),
            Err(e) => return Err(config_write_error(e)),
        }
        self.apply(
            SettingChange::InstanceProxy {
                instance_id: id.clone(),
                proxy: stored,
            },
            None,
        )?;
        self.engine.invalidate_client(&id);
        self.reload()?;
        self.view(alias)
    }

    async fn set_token(
        &self,
        alias: &str,
        pat: secrecy::SecretString,
        expires_at: Option<chrono::NaiveDate>,
    ) -> Result<ConnectionReport, AdminError> {
        let job = self.enter()?;
        let rt = self.find(alias)?;
        let (id, origin) = Self::usable(&rt)?;
        let target = Self::target(&rt, id.clone(), origin.clone());
        let tested = Self::tested(
            connection_test::run(&self.engine, &target, &pat, &job).await,
            &job,
        )?;
        let bound = url_hash(&origin);
        // A stored token bound to another origin belongs to no one here.
        let old = self.stored(&id).await.filter(|c| c.base_url_hash == bound);
        let other_user = old
            .as_ref()
            .is_some_and(|o| o.identity.atlassian_user_key != tested.user_key);
        if let (true, Some(o)) = (other_user, &old) {
            // Both names come from servers: escaped like any text an approver reads (I-6).
            let text = format!(
                "{TOKEN_OWNER_CHANGE}{}, previously {}",
                shown(&tested.user),
                shown(&o.identity.atlassian_user)
            );
            let confirmer = self.engine.confirmer().clone();
            if confirm_on_own_thread(confirmer, text).await == Confirm::Cancel {
                return Err(AdminError::Cancelled);
            }
        }
        // Nothing is written once the shutdown began (the dialog can outlast its wait).
        self.still_running()?;
        let expires = expires_at.map(|d| d.format("%Y-%m-%d").to_string());
        let ev = payloads::credential_changed(
            &id,
            if old.is_some() {
                CredentialChange::Replaced
            } else {
                CredentialChange::Added
            },
            old.as_ref().map(|o| o.identity.atlassian_user_key.as_str()),
            Some(&tested.user_key),
            expires.as_deref(),
        );
        // Audit before effect: the record commits first; a failed store leaves the old token.
        self.engine
            .blocking(move |p| p.append(ev).map(|_| ()))
            .await
            .map_err(AdminError::Audit)?;
        let identity = StoredIdentity {
            atlassian_user: tested.user.clone(),
            atlassian_user_key: tested.user_key.clone(),
        };
        let cred = StoredCredential {
            pat: PatSecret::from(pat),
            base_url_hash: bound,
            identity: identity.clone(),
            expires_at,
        };
        let (creds, store_id) = (self.engine.credentials().clone(), id.clone());
        let stored = tokio::task::spawn_blocking(move || creds.store(&store_id, cred))
            .await
            .map_err(|_| AdminError::Keychain(CredentialError::Unavailable))
            .and_then(|r| r.map_err(AdminError::Keychain));
        if let Err(e) = stored {
            // The record above said the token changed; it did not (review M-1): say so.
            let failed = payloads::credential_changed(
                &id,
                CredentialChange::StoreFailed,
                old.as_ref().map(|o| o.identity.atlassian_user_key.as_str()),
                Some(&tested.user_key),
                expires.as_deref(),
            );
            let _ = self
                .engine
                .blocking(move |p| p.append(failed).map(|_| ()))
                .await;
            return Err(e);
        }
        // PD-99: users are looked up again under the new token (`credential_changed`); cleared
        // before the instance is `ok` with it.
        self.engine.user_cache().clear(&id);
        self.pat_stored(&id, identity, expires_at, tested.version);
        let change = if other_user {
            InstanceChange::TokenReplaced
        } else {
            InstanceChange::TokenStored
        };
        self.engine.instance_changed(&id, change).await;
        self.fill_field_cache(&rt, &id);
        Ok(tested.report)
    }

    async fn retest_token(&self, alias: &str) -> Result<ConnectionReport, AdminError> {
        let job = self.enter()?;
        let rt = self.find(alias)?;
        let (id, origin) = Self::usable(&rt)?;
        let stored = self
            .stored(&id)
            .await
            .filter(|c| c.base_url_hash == url_hash(&origin))
            .ok_or(AdminError::Keychain(CredentialError::Unavailable))?;
        let pat = secrecy::SecretString::from(stored.pat.expose_secret().to_owned());
        let target = Self::target(&rt, id.clone(), origin);
        let tested = Self::tested(
            connection_test::run(&self.engine, &target, &pat, &job).await,
            &job,
        )?;
        // The result is in the log; the instance is not changed once the shutdown began.
        self.still_running()?;
        if tested.user_key != stored.identity.atlassian_user_key {
            // The token resolves to someone else now (§7.1): a confirmed token failure.
            let result = RecheckResult::TokenFailure {
                other_user: Some(tested.user.clone()),
            };
            identity::on_result(&self.engine, &id, &result).await;
            return Err(AdminError::ConnectionFailed(ConnectionFailure::OtherUser));
        }
        // Same key, another name: a rename (§7.1 *Username rename*), no `CREDENTIAL_CHANGED`.
        let renamed = !username_matches(&tested.user, &stored.identity.atlassian_user);
        let old = stored.identity.atlassian_user.clone();
        self.pat_stored(&id, stored.identity, stored.expires_at, tested.version);
        if renamed {
            identity::apply_rename(&self.engine, &id, &old, &tested.user, &tested.user_key).await;
        }
        self.engine
            .instance_changed(&id, InstanceChange::TokenStored)
            .await;
        self.fill_field_cache(&rt, &id);
        Ok(tested.report)
    }

    async fn delete_token(&self, alias: &str) -> Result<InstanceView, AdminError> {
        let _job = self.enter()?;
        let rt = self.find(alias)?;
        // No id: no keychain entry can belong to the instance.
        let Some(id) = rt.id.clone() else {
            return self.view(alias);
        };
        let (engine, del_id) = (self.engine.clone(), id.clone());
        let deleted =
            tokio::task::spawn_blocking(move || delete_stored(&engine, &del_id, true)).await;
        let failed = match deleted {
            Ok(Ok(false)) => return self.view(alias),
            Ok(Ok(true)) => None,
            // Nothing was deleted, and the log says so (no record, or a corrective one after a
            // failed keychain delete, review I-1), or the shutdown began: nothing changes.
            Ok(Err(e)) => return Err(e),
            // Whether the record committed is unknown: fail closed.
            Err(_) => Some(AdminError::Keychain(CredentialError::Unavailable)),
        };
        // Deleted: the instance uses no token from now on, and its queued writes are no longer
        // approvable.
        self.engine.invalidate_client(&id);
        self.engine.update_instance(&id, |rt| {
            if matches!(
                rt.state,
                InstanceState::Ok
                    | InstanceState::IdentityHeaderMissing
                    | InstanceState::IdentityHeaderMismatch
            ) {
                rt.state = InstanceState::NeedsToken;
            }
            rt.identity = None;
            rt.expires_at = None;
            rt.note = None;
        });
        self.engine
            .instance_changed(&id, InstanceChange::StateChanged)
            .await;
        if let Some(e) = failed {
            return Err(e);
        }
        self.view(alias)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instances::state::CaCert;

    fn cert(subject: &str) -> CaCert {
        CaCert {
            sha256: "ab".repeat(32),
            subject: subject.to_owned(),
            issuer: "CN=Issuer".to_owned(),
            not_before: "2026-01-01".to_owned(),
            not_after: "2027-01-01".to_owned(),
        }
    }

    #[test]
    fn expiry_warnings_take_the_tightest_threshold() {
        let expires = chrono::NaiveDate::from_ymd_opt(2026, 3, 31).unwrap_or_default();
        // `today` is `left` days before the expiry date.
        let warning = |left: i64| {
            let today = expires - chrono::TimeDelta::days(left);
            assert_eq!(days_left(expires, today), left);
            expiry_warning(days_left(expires, today))
        };
        let got: Vec<Option<u8>> = [30, 15, 14, 13, 8, 7, 2, 1, 0, -1, -400]
            .into_iter()
            .map(warning)
            .collect();
        assert_eq!(
            got,
            [
                None,
                None,
                Some(14),
                Some(14),
                Some(14),
                Some(7),
                Some(7),
                Some(1),
                Some(1),
                Some(1),
                Some(1)
            ]
        );
    }

    /// Review M-3: the UTC offset moves the local date the warnings count from.
    #[test]
    fn local_date_follows_the_utc_offset() {
        // 2026-03-30 23:30 UTC.
        let day = chrono::NaiveDate::from_ymd_opt(2026, 3, 30).unwrap_or_default();
        let ms = day
            .and_hms_opt(23, 30, 0)
            .unwrap_or_default()
            .and_utc()
            .timestamp_millis();
        let now = UtcInstant(ms);
        assert_eq!(local_date(now, None), day);
        assert_eq!(local_date(now, Some(-600)), day);
        assert_eq!(local_date(now, Some(60)), day + chrono::Days::new(1));
    }

    #[test]
    fn dialog_names_are_escaped_capped_and_flagged() {
        assert_eq!(shown("alice"), "alice");
        // Line breaks, tabs, bidi and zero-width characters never reach the dialog raw.
        assert_eq!(shown("a\nb\tc\r"), "a⟨U+000A⟩b⟨U+0009⟩c⟨U+000D⟩");
        assert_eq!(shown("x\u{202E}y\u{200B}"), "x⟨U+202E⟩y⟨U+200B⟩");
        assert!(shown(&"a".repeat(500)).chars().count() <= 201);
        // Latin with a Cyrillic look-alike is flagged.
        assert!(shown("p\u{430}ypal").ends_with("[mixed scripts]"));
    }

    #[test]
    fn ca_dialog_lists_subjects_and_caps_the_listing() {
        let bundle = CaBundle {
            certs: (0..7).map(|i| cert(&format!("CN=Root {i}"))).collect(),
            fingerprint: "cd".repeat(32),
        };
        let text = ca_text("corp", &bundle);
        assert!(text.starts_with("Trust the custom CA for \"corp\"? 7 certificates"));
        assert!(text.contains(&"cd".repeat(32)));
        assert!(text.contains("Subject: CN=Root 0") && text.contains("Subject: CN=Root 4"));
        assert!(!text.contains("CN=Root 5"));
        assert!(text.ends_with("... and 2 more certificates."));
        // A hostile subject cannot add a line of its own.
        let hostile = CaBundle {
            certs: vec![cert("CN=x\nSubject: CN=Trusted Corp")],
            fingerprint: "cd".repeat(32),
        };
        let text = ca_text("corp", &hostile);
        let lines = text
            .lines()
            .filter(|l| l.trim_start().starts_with("Subject:"));
        assert_eq!(lines.count(), 1, "{text}");
    }
}
