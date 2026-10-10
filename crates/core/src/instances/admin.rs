//! The core's `InstanceAdmin` (C.7, §7.1, §10.3): adding instances, confirming and changing
//! origins through the native confirmation, the proxy, and the credential window's token set and
//! re-test. Every security-weakening change goes through [`NativeConfirmer`] with a dialog text
//! built here, and the audit settings record the confirmation (`Confirmed`, Q5): `config.toml`
//! proposes, the audit log decides (I-31).

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use atlas_duck_atlassian::{
    BaseUrlError, CredentialError, NormalizedBaseUrl, PatSecret, StoredCredential, StoredIdentity,
    url_hash, username_matches,
};
use atlas_duck_audit::{AuditError, Confirmed, SettingChange, Settings};
use atlas_duck_registry::Product;
use sha2::{Digest, Sha256};

use super::connection_test::{self, Target};
use super::state::{DeriveCtx, InstanceRuntime, InstanceState, InstanceTable, ca_fingerprint};
use super::{
    AddInstance, AdminError, ConnectionFailure, ConnectionReport, InstanceAdmin, InstanceView,
};
use crate::config::instances::{
    InstanceConfig, add_instance, instances, is_valid_alias, set_base_url, set_proxy_setting,
};
use crate::config::{ConfigState, ConfigWriteError, load_config};
use crate::core::Confirm;
use crate::engine::Engine;
use crate::engine::write::InstanceChange;
use crate::identity::{self, RecheckResult};
use crate::ids::InstanceId;
use crate::payloads::{self, CredentialChange};
use crate::proxy::ProxySetting;

/// §7.1 verbatim.
const TOKEN_OWNER_CHANGE: &str = "This token belongs to ";

/// The core's `InstanceAdmin`.
pub struct CoreInstances {
    engine: Arc<Engine>,
    config_path: Option<PathBuf>,
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

/// §10.3: the text of the add dialog.
pub(crate) fn add_text(product: Product, alias: &str, origin: &NormalizedBaseUrl) -> String {
    let mut text = format!(
        "Add {} instance \"{alias}\" at {}?",
        product_name(product),
        origin.as_str()
    );
    if let Some(w) = host_warnings(origin.host()) {
        text.push('\n');
        text.push_str(&w);
    }
    text
}

/// §10.3: the text of the URL-change dialog.
pub(crate) fn change_text(alias: &str, old: &NormalizedBaseUrl, new: &NormalizedBaseUrl) -> String {
    let mut text = format!(
        "Change \"{alias}\" from {} to {}? The stored token will be deleted.",
        old.as_str(),
        new.as_str()
    );
    if let Some(w) = host_warnings(new.host()) {
        text.push('\n');
        text.push_str(&w);
    }
    if old.host() != new.host() {
        text.push_str(&format!(
            "\nWarning: the host changes from {} to {}.",
            old.host(),
            new.host()
        ));
    }
    text
}

fn ca_text(alias: &str, fingerprint: &str) -> String {
    format!("Trust the custom CA with fingerprint {fingerprint} for \"{alias}\"?")
}

impl CoreInstances {
    pub(crate) fn new(engine: Arc<Engine>, config_path: Option<PathBuf>) -> CoreInstances {
        CoreInstances {
            engine,
            config_path,
        }
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

    fn confirm(&self, text: &str) -> Result<(), AdminError> {
        match self.engine.confirmer().confirm(text) {
            Confirm::Ok => Ok(()),
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

    /// PD-22: rebuilds the runtime table from `config.toml`, the audit settings and the
    /// keychain. The file-side records are logged at start only.
    fn reload(&self) -> Result<(), AdminError> {
        let path = self.path()?;
        let cfg = load_config(path).map_err(|_| AdminError::ConfigReadOnly)?;
        let settings = self.settings();
        let previous = self.engine.instances().clone();
        let (table, _file_side) = InstanceTable::derive(
            &cfg,
            &DeriveCtx {
                settings: &settings,
                creds: &**self.engine.credentials(),
                allow_http: self.engine.allow_http(),
                previous: Some(&previous),
            },
        );
        self.engine.replace_instances(table);
        Ok(())
    }

    fn view(&self, alias: &str) -> Result<InstanceView, AdminError> {
        let rt = self.find(alias)?;
        Ok(self.view_of(&rt))
    }

    fn view_of(&self, i: &InstanceRuntime) -> InstanceView {
        let host = i.base.as_ref().map_or("", NormalizedBaseUrl::host);
        let resolved = self.engine.http().resolve(&i.proxy, host);
        InstanceView {
            alias: i.alias.clone(),
            product: i.product,
            origin: i.base.as_ref().map(NormalizedBaseUrl::as_str),
            state: i.state.as_str(),
            executes_as: i.identity.as_ref().map(|id| id.atlassian_user.clone()),
            expires_at: i.expires_at.map(|d| d.format("%Y-%m-%d").to_string()),
            pac_configured: resolved.uses_os && resolved.pac_configured,
            proxy_effective: Some(resolved.effective),
            pending_url_change: i.pending_url_change.clone(),
            note: i.note.clone(),
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
        let Some(fp) = std::fs::read(file).ok().and_then(|p| ca_fingerprint(&p)) else {
            return Ok(());
        };
        let stored = self
            .settings()
            .instances
            .get(id)
            .and_then(|p| p.ca_fingerprint.clone());
        if stored.as_deref() == Some(fp.as_str()) {
            return Ok(());
        }
        let text = ca_text(&rt.alias, &fp);
        self.confirm(&text)?;
        self.apply(
            SettingChange::InstanceCaFingerprint {
                instance_id: id.to_owned(),
                fingerprint: Some(fp),
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
        // The token is bound to the old origin: it goes (audit before effect).
        let engine = self.engine.clone();
        let old_key = {
            let (creds, id) = (engine.credentials().clone(), id.clone());
            creds
                .load(&id)
                .ok()
                .flatten()
                .map(|c| c.identity.atlassian_user_key)
        };
        if let Some(key) = old_key {
            let ev = payloads::credential_changed(
                &id,
                CredentialChange::Deleted,
                Some(&key),
                None,
                None,
            );
            self.engine.port().append(ev).map_err(AdminError::Audit)?;
            self.engine
                .credentials()
                .delete(&id)
                .map_err(AdminError::Keychain)?;
        }
        self.engine.invalidate_client(&id);
        self.reload()?;
        let (change, eng, inst) = (
            InstanceChange::OriginChanged {
                old: old.as_str(),
                new: new.as_str(),
            },
            self.engine.clone(),
            id,
        );
        let _ = self
            .engine
            .run_sync(async move { eng.instance_changed(&inst, change).await });
        Ok(())
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

    fn target(rt: &InstanceRuntime, id: String, origin: NormalizedBaseUrl) -> Target {
        Target {
            id,
            product: rt.product,
            origin,
            proxy: rt.proxy.clone(),
            ca_bundle: rt.ca_bundle.clone(),
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
                ca_fingerprint(pem).ok_or(audit("no certificate in the CA bundle"))?,
                pem,
            )),
            None => None,
        };
        let text = add_text(req.product, &req.alias, &origin);
        self.confirm(&text)?;
        let ca_dialog = match &ca {
            Some((fp, _)) => {
                let t = ca_text(&req.alias, fp);
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
        if let (Some((fp, _)), Some(t)) = (&ca, &ca_dialog) {
            self.apply(
                SettingChange::InstanceCaFingerprint {
                    instance_id: id.clone(),
                    fingerprint: Some(fp.clone()),
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
        self.confirm_file_ca(&rt, &id)?;
        self.reload()?;
        self.view(alias)
    }

    fn accept_config_url_change(&self, alias: &str) -> Result<InstanceView, AdminError> {
        let rt = self.find(alias)?;
        let Some(url) = rt.pending_url_change.clone() else {
            return Err(AdminError::NotFound);
        };
        let new = self.engine.normalize_origin(&url).map_err(|e| match e {
            BaseUrlError::InsecureScheme => AdminError::InsecureScheme,
            BaseUrlError::Invalid(_) => AdminError::InvalidUrl,
        })?;
        self.change_origin(&rt, new, None)?;
        self.view(alias)
    }

    fn change_base_url(&self, alias: &str, new_url: &str) -> Result<InstanceView, AdminError> {
        let rt = self.find(alias)?;
        let new = self.engine.normalize_origin(new_url).map_err(|e| match e {
            BaseUrlError::InsecureScheme => AdminError::InsecureScheme,
            BaseUrlError::Invalid(_) => AdminError::InvalidUrl,
        })?;
        let new_raw = new.as_str();
        self.change_origin(&rt, new, Some(&new_raw))?;
        self.view(alias)
    }

    fn set_proxy(&self, alias: &str, proxy: ProxySetting) -> Result<InstanceView, AdminError> {
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
        let rt = self.find(alias)?;
        let (id, origin) = Self::usable(&rt)?;
        let tested = connection_test::run(
            &self.engine,
            &Self::target(&rt, id.clone(), origin.clone()),
            &pat,
        )
        .await?;
        let bound = url_hash(&origin);
        // A stored token bound to another origin belongs to no one here.
        let old = self.stored(&id).await.filter(|c| c.base_url_hash == bound);
        let other_user = old
            .as_ref()
            .is_some_and(|o| o.identity.atlassian_user_key != tested.user_key);
        if let (true, Some(o)) = (other_user, &old) {
            let text = format!(
                "{TOKEN_OWNER_CHANGE}{}, previously {}",
                tested.user, o.identity.atlassian_user
            );
            let confirmer = self.engine.confirmer().clone();
            let answer = tokio::task::spawn_blocking(move || confirmer.confirm(&text))
                .await
                .unwrap_or(Confirm::Cancel);
            if answer == Confirm::Cancel {
                return Err(AdminError::Cancelled);
            }
        }
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
        tokio::task::spawn_blocking(move || creds.store(&store_id, cred))
            .await
            .map_err(|_| AdminError::Keychain(CredentialError::Unavailable))?
            .map_err(AdminError::Keychain)?;
        self.pat_stored(&id, identity, expires_at, tested.version);
        let change = if other_user {
            InstanceChange::TokenReplaced
        } else {
            InstanceChange::TokenStored
        };
        self.engine.instance_changed(&id, change).await;
        Ok(tested.report)
    }

    async fn retest_token(&self, alias: &str) -> Result<ConnectionReport, AdminError> {
        let rt = self.find(alias)?;
        let (id, origin) = Self::usable(&rt)?;
        let stored = self
            .stored(&id)
            .await
            .filter(|c| c.base_url_hash == url_hash(&origin))
            .ok_or(AdminError::Keychain(CredentialError::Unavailable))?;
        let pat = secrecy::SecretString::from(stored.pat.expose_secret().to_owned());
        let tested =
            connection_test::run(&self.engine, &Self::target(&rt, id.clone(), origin), &pat)
                .await?;
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
        Ok(tested.report)
    }
}
