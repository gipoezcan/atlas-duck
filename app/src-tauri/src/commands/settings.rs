//! The Settings window's commands (C.10 + Δ1, §5.7, §7.1, §10.3; M6 T25): `settings_get`,
//! `settings_apply`, the four instance commands the setup wizard shares (`instance_add`,
//! `instance_change_url`, `instance_confirm_config`, `instance_accept_url_change`),
//! `instance_set_proxy`, `credential_window_open`, `retest_token` and `prune_backlog_now`. Granted
//! to `settings` (and, for the four shared ones, `setup`); the wizard's own commands are Task 23's.
//!
//! Core decides, this layer maps. Every change that weakens a security property, every new
//! instance and every origin change is confirmed in a native dialog the core draws itself
//! (`NativeConfirmer`, I-31): a `Cancel` is `Cancelled` and nothing was logged or written, whatever
//! the webview sends. Nothing a webview sends is a path or a certificate: `instance_add
//! {use_custom_ca: true}` makes *Rust* open a native file dialog, read the chosen file (at most
//! [`CA_MAX_BYTES`]) and hand the bytes to `AddInstance::ca_pem`, whose subject and fingerprint
//! core shows in its own confirmation (§10.3, M3 review I-5). The synchronous core calls run on
//! the blocking pool (a native dialog may be open meanwhile, M3 PD-13); `retest_token` is async.
//! Core's errors pass through nested (`CommandError::Admin` / `Settings`), logged by kind only.
//!
//! M10 adds "Back up now" and "Restore backup…" (T13) and the recovery tier and the anchor
//! directory (T14: `recovery_passphrase_change`, `anchor_dir_set`, `anchor_dir_remove`,
//! `re_anchor`, `orphan_installs`, `forget_install`; the flows are `recovery_tier`'s, the dialogs
//! Rust's, no path or secret comes in) and "Prepare for removal"'s compliance export (T16:
//! `removal_export`, the Audit window's export flow over the full range).

use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use atlas_duck_core::config::instances::MAX_ALIAS_CHARS;
use atlas_duck_core::config::scripts::{SCRIPT_KEYS, bound as script_bound};
use atlas_duck_core::proxy::ProxySetting;
use atlas_duck_core::settings::{KEY_SCRIPT_LIMITS, MAX_CHANGES};
use atlas_duck_core::{
    AddInstance, AdminError, InstanceAdmin, InstanceView, Product, PruneReport, ScriptLimitsReq,
    SettingChangeReq, SettingsAdmin, SettingsError, SettingsView,
};
use atlas_duck_sandbox_host::probe::{FloorVerdict, ProbeReport};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Manager, Runtime};

use super::credential::{Connected, SubmitFailure, connection_failure};
use super::dto::{Args, refuse};
use super::{CommandError, blocking, core, finish};
use crate::cli_install::{
    self, APP_CHANGE_KEY, Artifact, Inputs, InstallError, Kind, Layout, PlatformOps, SystemOps,
};
use crate::credential::{self, PatOpenError};
use crate::recovery_tier;
use crate::removal::{
    self, BackupAnswer, Choice, FinishAnswer, PluginAutostart, RemovalDto, RemovalError,
    RemovalState, Retention,
};
use crate::restore_flow;
use crate::sandbox_probe::{floor_label, mode_label, probe_id_name, scripts_state};
use crate::serve::{JobRefused, RestoreCancel, StoreCall};
use crate::state::{AppState, ServeSlot};
use crate::ui_sink::{emit_settings_changed, emit_status_changed};
use crate::windows::{Show, WindowError};

/// §7.1 (verbatim): the fixed hint beside an `http://` base URL. Core refuses the URL
/// (`insecure_scheme`) and never sends a PAT; the page shows this text for that kind.
pub const HTTPS_REQUIRED_HINT: &str = "atlas-duck requires https; if your server uses an internal CA, add it as the instance's custom CA";

/// plan text (T25): the custom CA file is at most 1 MiB (a PEM bundle of a few certificates is a
/// few KiB); core parses it and shows every certificate before anything is trusted.
pub const CA_MAX_BYTES: usize = 1 << 20;
/// plan text (T25): the file dialog's title and filter.
const CA_DIALOG_TITLE: &str = "Choose the custom CA certificate file (PEM)";
const CA_FILTER: &str = "Certificates (PEM)";
const CA_EXTENSIONS: &[&str] = &["pem", "crt", "cer"];

/// plan text (T25): a base URL is at most 2 048 bytes (core normalizes and rejects the rest).
pub const BASE_URL_MAX_BYTES: usize = 2048;
/// A proxy setting is `""`, `direct` or `host:port` (a DNS name is at most 253 bytes).
pub const PROXY_MAX_BYTES: usize = 300;

/// A diagnostic-log event of a refused or failed settings call (`event`, `error_class` = the
/// error's kind; never a message, a path or a value).
pub const LOG_EVENT_SETTINGS_FAILED: &str = "settings_failed";

/// The fields this module's lines add to the diagnostic allowlist (M10 T36, M6 M-1): the inner kind
/// of a failed call (`error_kind`, an error's `Display`: no message, path or value).
pub const LOG_FIELDS: &[&str] = &["error_kind"];

// ---------- argument newtypes ----------

fn text<'de, D: Deserializer<'de>>(d: D, field: &'static str) -> Result<String, D::Error> {
    String::deserialize(d).map_err(|_| refuse::<D::Error>(field))
}

/// An instance alias: 1 to [`MAX_ALIAS_CHARS`] of `A-Z a-z 0-9 . _ -` (core's own rule, checked
/// again there).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias(String);

impl Alias {
    pub fn is_valid(s: &str) -> bool {
        (1..=MAX_ALIAS_CHARS).contains(&s.chars().count())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Alias {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = text(d, "alias")?;
        if Alias::is_valid(&s) {
            Ok(Alias(s))
        } else {
            Err(refuse("alias"))
        }
    }
}

fn url_text<'de, D: Deserializer<'de>>(d: D, field: &'static str) -> Result<String, D::Error> {
    let s = text(d, field)?;
    if s.len() > BASE_URL_MAX_BYTES || s.chars().any(char::is_control) {
        return Err(refuse(field));
    }
    Ok(s)
}

/// `base_url`: bounded text; core normalizes it and refuses `http://` (§7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseUrl(String);

impl<'de> Deserialize<'de> for BaseUrl {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        url_text(d, "base_url").map(BaseUrl)
    }
}

/// `new_url`: as [`BaseUrl`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUrl(String);

impl<'de> Deserialize<'de> for NewUrl {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        url_text(d, "new_url").map(NewUrl)
    }
}

/// `product`: `jira` or `confluence`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductDto(pub Product);

impl<'de> Deserialize<'de> for ProductDto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match text(d, "product")?.as_str() {
            "jira" => Ok(ProductDto(Product::Jira)),
            "confluence" => Ok(ProductDto(Product::Confluence)),
            _ => Err(refuse("product")),
        }
    }
}

/// `proxy`: `""` (the OS setting), `direct` or `host:port`; no user name or password (L42).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyDto(pub ProxySetting);

impl<'de> Deserialize<'de> for ProxyDto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = text(d, "proxy")?;
        // A proxy host is a DNS name or an IP literal: ASCII, no control or bidi character (core's
        // parser bans whitespace and URL delimiters only, and what it accepts is written to the
        // config file, the audit record and the Settings page).
        if s.len() > PROXY_MAX_BYTES || !s.is_ascii() || s.chars().any(char::is_control) {
            return Err(refuse("proxy"));
        }
        ProxySetting::parse(&s)
            .map(ProxyDto)
            .map_err(|_| refuse("proxy"))
    }
}

/// `purpose` of `credential_window_open`: `add_pat` or `replace_pat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatPurposeDto {
    pub replace: bool,
}

impl<'de> Deserialize<'de> for PatPurposeDto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match text(d, "purpose")?.as_str() {
            "add_pat" => Ok(PatPurposeDto { replace: false }),
            "replace_pat" => Ok(PatPurposeDto { replace: true }),
            _ => Err(refuse("purpose")),
        }
    }
}

/// `changes`: one to [`MAX_CHANGES`] `{key, value}` settings in `SettingChangeReq`'s own closed
/// form. Ranges are core's to check (`SettingsError::Invalid {key}`, before anything happens),
/// except the eight script limits (M8 Δ6, PD-139): each is bounded here too, before core is called,
/// and a refused one is `InvalidArgument` naming the limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingChanges(pub Vec<SettingChangeReq>);

/// The name of the first limit of `req` outside its PD-139 bound (core's own table). A limit is
/// found by the wire key `ScriptLimitsReq` serializes, which skips the unchanged ones.
fn script_limit_out_of_bounds(req: &ScriptLimitsReq) -> Option<&'static str> {
    let Ok(Value::Object(set)) = serde_json::to_value(req) else {
        return Some(KEY_SCRIPT_LIMITS);
    };
    SCRIPT_KEYS.into_iter().find(|key| {
        set.get(*key).is_some_and(|v| {
            !v.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .zip(script_bound(key))
                .is_some_and(|(n, bound)| bound.contains(&n))
        })
    })
}

impl<'de> Deserialize<'de> for SettingChanges {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bad = || refuse::<D::Error>("changes");
        let Value::Array(items) = Value::deserialize(d).map_err(|_| bad())? else {
            return Err(bad());
        };
        if !(1..=MAX_CHANGES).contains(&items.len()) {
            return Err(bad());
        }
        // A limit past `u32` is a whole number too, but `ScriptLimitsReq` cannot hold it: name it
        // here, before the typed parse turns it into a malformed `changes`.
        for item in &items {
            if item.get("key").and_then(Value::as_str) == Some(KEY_SCRIPT_LIMITS)
                && let Some(set) = item.get("value").and_then(Value::as_object)
                && let Some(key) = SCRIPT_KEYS.into_iter().find(|key| {
                    set.get(*key)
                        .and_then(Value::as_u64)
                        .is_some_and(|n| u32::try_from(n).is_err())
                })
            {
                return Err(refuse(key));
            }
        }
        let changes = items
            .into_iter()
            .map(|v| SettingChangeReq::deserialize(v).map_err(|_| bad()))
            .collect::<Result<Vec<_>, _>>()?;
        for change in &changes {
            if let SettingChangeReq::ScriptLimits(req) = change
                && let Some(key) = script_limit_out_of_bounds(req)
            {
                return Err(refuse(key));
            }
        }
        Ok(SettingChanges(changes))
    }
}

// ---------- argument structs ----------

/// `settings_get {}` (read-only).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsGetArgs {}

/// `settings_apply {changes}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsApplyArgs {
    pub changes: SettingChanges,
}

/// `instance_add {alias, product, base_url, proxy, use_custom_ca, is_default}`. There is no CA
/// field: `use_custom_ca` only asks Rust to open its own file dialog.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceAddArgs {
    pub alias: Alias,
    pub product: ProductDto,
    pub base_url: BaseUrl,
    pub proxy: ProxyDto,
    pub use_custom_ca: bool,
    pub is_default: bool,
}

/// `instance_change_url {alias, new_url}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceChangeUrlArgs {
    pub alias: Alias,
    pub new_url: NewUrl,
}

/// `instance_confirm_config {alias}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceConfirmConfigArgs {
    pub alias: Alias,
}

/// `instance_accept_url_change {alias}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceAcceptUrlChangeArgs {
    pub alias: Alias,
}

/// `instance_set_proxy {alias, proxy}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceSetProxyArgs {
    pub alias: Alias,
    pub proxy: ProxyDto,
}

/// `credential_window_open {alias, purpose}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialWindowOpenArgs {
    pub alias: Alias,
    pub purpose: PatPurposeDto,
}

/// `retest_token {alias}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetestTokenArgs {
    pub alias: Alias,
}

/// `prune_backlog_now {}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PruneBacklogNowArgs {}

/// `cli_install {}`: no key. Rust decides where (known folders, `$APPIMAGE`, the running binary);
/// the webview names no path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliInstallArgs {}

/// `cli_uninstall {}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliUninstallArgs {}

/// `choice` of `removal_mark`: `pending`, `done` or `skipped`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChoiceDto(pub Choice);

impl<'de> Deserialize<'de> for ChoiceDto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match text(d, "choice")?.as_str() {
            "pending" => Ok(ChoiceDto(Choice::Pending)),
            "done" => Ok(ChoiceDto(Choice::Done)),
            "skipped" => Ok(ChoiceDto(Choice::Skipped)),
            _ => Err(refuse("choice")),
        }
    }
}

/// `removal_state {}` (read-only).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalStateArgs {}

/// `removal_backup {}`: no key. Rust opens its own folder dialog; the webview names no path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalBackupArgs {}

/// `removal_begin {}`: no key (Rust confirms natively, then deletes the stored tokens).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalBeginArgs {}

/// `removal_mark {alias, choice}`: the answer for one instance's revoke step.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalMarkArgs {
    pub alias: Alias,
    pub choice: ChoiceDto,
}

/// `removal_finish {}`: no key (Rust confirms natively, records, then removes).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalFinishArgs {}

/// `removal_export {}` (M10 T16, PD-176): no key. The range is the full one; Rust shows the PD-161
/// warning and its own folder dialog; the webview names no path and no range.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalExportArgs {}

// ---------- responses ----------

/// One extra confinement layer the probe saw (`landlock`, ...): its name and whether it is on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtraLayerDto {
    pub name: String,
    pub on: bool,
}

/// The §9.4 probe verdict as Settings shows it (§5.7 "confinement status"): no path, no identity.
/// `state` is `pending` until the startup probe finished, then `met` or `not_met` (scripts are
/// disabled unless `met`); `failed` names the floor probes that failed; `mode` is `lpac`,
/// `appcontainer` or `n/a`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfinementDto {
    pub state: &'static str,
    pub failed: Vec<&'static str>,
    pub mode: &'static str,
    pub extra_layers: Vec<ExtraLayerDto>,
    /// Whether scripts run (Δ8, PD-141): `enabled` under a met floor, `degraded` under an unmet one
    /// with degraded confinement allowed, `disabled` otherwise and while the probe is pending.
    pub scripts: &'static str,
    /// "Allow scripts with degraded confinement" as core's run policy holds it now (Δ8).
    pub degraded_allowed: bool,
}

impl ConfinementDto {
    pub fn pending() -> ConfinementDto {
        ConfinementDto::of_probe(None, false)
    }

    /// The report as Settings shows it, degraded confinement not allowed.
    pub fn of(report: &ProbeReport) -> ConfinementDto {
        ConfinementDto::of_probe(Some(report), false)
    }

    /// What `settings_get` answers: the startup probe's report (`None` while it is pending) and
    /// the degraded-confinement setting (Δ8). `failed` names every failed floor probe, so a memory
    /// read that got through (S-05: `open_process_vm_read`, `task_for_pid`, ...) is shown here.
    pub fn of_probe(report: Option<&ProbeReport>, degraded_allowed: bool) -> ConfinementDto {
        let scripts = scripts_state(report, degraded_allowed);
        let Some(report) = report else {
            return ConfinementDto {
                state: "pending",
                failed: Vec::new(),
                mode: "n/a",
                extra_layers: Vec::new(),
                scripts,
                degraded_allowed,
            };
        };
        let failed = match &report.floor {
            FloorVerdict::Met => Vec::new(),
            FloorVerdict::NotMet { failed } => failed.iter().map(|p| probe_id_name(*p)).collect(),
        };
        ConfinementDto {
            state: floor_label(&report.floor),
            failed,
            mode: mode_label(report),
            extra_layers: report
                .extra_layers
                .iter()
                .map(|(name, on)| ExtraLayerDto {
                    name: name.clone(),
                    on: *on,
                })
                .collect(),
            scripts,
            degraded_allowed,
        }
    }
}

/// `settings_get`'s answer: everything the Settings window shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsGet {
    pub settings: SettingsView,
    pub instances: Vec<InstanceView>,
    pub confinement: ConfinementDto,
    pub cli_installed: bool,
    /// "Remove CLI from PATH" does something here: false for deb/rpm (the CLI is in `/usr/bin`; the
    /// package owns it), where Settings shows no removal button.
    pub cli_removable: bool,
}

/// `retest_token`'s answer: "Connected as <user>" or a fixed failure class (§10.3); the instance
/// state it left behind is in the next `settings_get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetestOutcome {
    Ok(Connected),
    Failed(SubmitFailure),
}

/// `cli_install` / `cli_uninstall`'s answer (§12.3): what happened, as a fixed word the page maps
/// to its own text: `installed`, `installed_local_bin`, `installed_local_bin_on_path`,
/// `replaced_stale_entry`, `already_installed`, `removed`, or `already_on_path` (deb/rpm have the
/// CLI in `/usr/bin`; nothing is installed or removed).
/// `installed_local_bin` is the answer where the CLI went to `~/.local/bin` (macOS, AppImage) and
/// that directory is not on this process's PATH (it is not on every default PATH: macOS has none,
/// Ubuntu adds it at login only when it existed), so the text says what to check; with the
/// directory on the PATH the word is `installed_local_bin_on_path` (PD-177; the PATH is read only
/// for this hint, §7.7). `replaced_stale_entry` is a Windows install that also removed the PATH
/// entry of an earlier, since moved, install folder of this app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliInstallAnswer {
    pub outcome: &'static str,
}

pub const OUTCOME_INSTALLED: &str = "installed";
pub const OUTCOME_INSTALLED_LOCAL_BIN: &str = "installed_local_bin";
pub const OUTCOME_INSTALLED_LOCAL_BIN_ON_PATH: &str = "installed_local_bin_on_path";
pub const OUTCOME_REPLACED_STALE_ENTRY: &str = "replaced_stale_entry";
pub const OUTCOME_ALREADY_INSTALLED: &str = "already_installed";
pub const OUTCOME_REMOVED: &str = "removed";
pub const OUTCOME_ALREADY_ON_PATH: &str = "already_on_path";

/// The layout of this machine: known folders, `$APPIMAGE`, the running binary.
pub fn this_machine() -> Result<Layout, InstallError> {
    Layout::resolve(&Inputs::detect()?)
}

/// [`this_machine`] for "Prepare for removal": the layout (or why there is none) and, when the
/// machine could be read at all, the removal-only layout of what sits at fixed paths.
fn machine_for_removal() -> (Result<Layout, InstallError>, Option<Layout>) {
    match Inputs::detect() {
        Ok(inputs) => (Layout::resolve(&inputs), Some(Layout::for_removal(&inputs))),
        Err(e) => (Err(e), None),
    }
}

/// `(installed, removable)` of the CLI on this machine (§12.3). `installed`: the CLI is on the PATH
/// as this installation wants it; a machine whose layout cannot be resolved (no stable path) counts
/// as not installed. `removable`: removal changes something, which it does not for deb/rpm.
pub fn cli_state() -> (bool, bool) {
    match this_machine() {
        Ok(layout) => (
            cli_install::is_installed(&SystemOps, &layout),
            !matches!(layout.kind, Kind::Packaged),
        ),
        Err(_) => (false, true),
    }
}

// ---------- the pure parts the tests drive ----------

/// `settings_get` over core. `cli_installed` and `cli_removable` are [`cli_state`] (the caller
/// reads the OS).
pub fn settings_get_dto(
    settings: &dyn SettingsAdmin,
    instances: &dyn InstanceAdmin,
    confinement: ConfinementDto,
    cli_installed: bool,
    cli_removable: bool,
) -> SettingsGet {
    SettingsGet {
        settings: settings.view(),
        instances: instances.list(),
        confinement,
        cli_installed,
        cli_removable,
    }
}

/// The `old` / `new` of the `cli_install` record: `{"installed": bool}`.
fn installed(on: bool) -> Value {
    serde_json::json!({ "installed": on })
}

/// A second `record_app_change` that undoes the first after the effect failed (`SettingsAdmin`: "an
/// app effect that fails afterwards appends a second call with `new = old`"). Its own failure cannot
/// improve the answer; it is logged by kind.
fn record_undo(settings: &dyn SettingsAdmin, old: bool, new: bool) {
    if let Err(e) = settings.record_app_change(APP_CHANGE_KEY, installed(new), installed(old)) {
        tracing::warn!(
            event = LOG_EVENT_SETTINGS_FAILED,
            error_class = "settings",
            error_kind = e.to_string().as_str()
        );
    }
}

/// `cli_install` (§12.3): `CONFIG_CHANGED {source: app, key: cli_install, old, new: true}` first
/// (audit before effect, `?`: a record that cannot be written stops the call), then the install. A
/// failed install is answered with its kind and a second record puts the old value back. deb/rpm
/// (`Packaged`) and an installation that is already complete change nothing and record nothing.
///
/// T23 HOOK (first-run wizard): the setup window holds `cli_install` too (Δ1), through this same
/// command: it answers `not_ready` until the core serves, so the wizard runs its CLI step after
/// `wizard_begin` has started serving. If T23 needs another route it calls this function with its
/// own `settings` handle; the install, the record and the errors stay in one place.
pub fn cli_install_dto(
    settings: &dyn SettingsAdmin,
    ops: &dyn PlatformOps,
    layout: Result<Layout, InstallError>,
) -> Result<CliInstallAnswer, CommandError> {
    let layout = layout?;
    if matches!(layout.kind, Kind::Packaged) {
        return Ok(CliInstallAnswer {
            outcome: OUTCOME_ALREADY_ON_PATH,
        });
    }
    if cli_install::is_installed(ops, &layout) {
        return Ok(CliInstallAnswer {
            outcome: OUTCOME_ALREADY_INSTALLED,
        });
    }
    settings.record_app_change(APP_CHANGE_KEY, installed(false), installed(true))?;
    match cli_install::install(ops, &layout) {
        Ok(report) => Ok(CliInstallAnswer {
            outcome: match layout.kind {
                Kind::Macos { .. } | Kind::AppImage { .. } => {
                    if cli_install::cli_dir_on_path(ops, &layout) == Some(true) {
                        OUTCOME_INSTALLED_LOCAL_BIN_ON_PATH
                    } else {
                        OUTCOME_INSTALLED_LOCAL_BIN
                    }
                }
                Kind::Windows { .. } if report.changed.contains(&Artifact::StaleEntry) => {
                    OUTCOME_REPLACED_STALE_ENTRY
                }
                Kind::Windows { .. } | Kind::Packaged => OUTCOME_INSTALLED,
            },
        }),
        Err(e) => {
            record_undo(settings, false, true);
            Err(CommandError::CliInstall(e))
        }
    }
}

/// `cli_uninstall` (§12.3, §12.5 step 3): the record first (`old` is whether the CLI was installed),
/// then everything `install` writes is removed (and `cli.toml`); what is not ours is left. A failure
/// is answered with its kind and a second record puts the old value back.
pub fn cli_uninstall_dto(
    settings: &dyn SettingsAdmin,
    ops: &dyn PlatformOps,
    layout: Result<Layout, InstallError>,
) -> Result<CliInstallAnswer, CommandError> {
    let layout = layout?;
    if matches!(layout.kind, Kind::Packaged) {
        return Ok(CliInstallAnswer {
            outcome: OUTCOME_ALREADY_ON_PATH,
        });
    }
    let old = cli_install::is_installed(ops, &layout);
    settings.record_app_change(APP_CHANGE_KEY, installed(old), installed(false))?;
    match cli_install::uninstall(ops, &layout) {
        Ok(_) => Ok(CliInstallAnswer {
            outcome: OUTCOME_REMOVED,
        }),
        Err(e) => {
            record_undo(settings, old, false);
            Err(CommandError::CliInstall(e))
        }
    }
}

/// `settings_apply`: core confirms each security-weakening change natively, in request order (a
/// `Cancel` applies none), writes the audit records first and the file last.
pub fn settings_apply_dto(
    settings: &dyn SettingsAdmin,
    changes: SettingChanges,
) -> Result<SettingsView, CommandError> {
    Ok(settings.apply(changes.0)?)
}

/// Runs `apply` and says whether "allow scripts with degraded confinement" (as `read` reports it)
/// differs after it. The header's `scripts_degraded` line follows that setting, so a flip must be
/// announced (`status_banner`); a failed apply that changed nothing is not one.
pub fn apply_noting_degraded<T>(read: impl Fn() -> bool, apply: impl FnOnce() -> T) -> (T, bool) {
    let before = read();
    let result = apply();
    (result, read() != before)
}

/// The CA file as Rust read it: a regular file of 1 to [`CA_MAX_BYTES`] bytes. A file the user
/// chose that is too large, empty, no regular file or unreadable is refused with `use_custom_ca`
/// (the page says to choose another one); nothing is parsed here, core does and shows what it found.
pub fn read_ca_bounded(path: &Path) -> Result<Vec<u8>, CommandError> {
    let refused = || CommandError::InvalidArgument {
        field: "use_custom_ca",
    };
    // The type check comes before the open: opening a FIFO blocks until a writer appears, and this
    // runs on a blocking-pool thread. The check on the open handle below is the one the read
    // relies on (the same file is checked and read).
    if !std::fs::metadata(path).map_err(|_| refused())?.is_file() {
        return Err(refused());
    }
    let file = std::fs::File::open(path).map_err(|_| refused())?;
    if !file.metadata().map_err(|_| refused())?.is_file() {
        return Err(refused());
    }
    let mut bytes = Vec::new();
    file.take(CA_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refused())?;
    if bytes.is_empty() || bytes.len() > CA_MAX_BYTES {
        return Err(refused());
    }
    Ok(bytes)
}

/// `instance_add`. `pick_ca` runs only for `use_custom_ca`, after core's `check_add` passed, and is the one source of the CA bytes
/// (the command passes Rust's file dialog; the webview has no way to supply any): a `Cancel` of
/// the file dialog is `Cancelled`.
pub fn instance_add_dto(
    admin: &dyn InstanceAdmin,
    args: InstanceAddArgs,
    pick_ca: impl FnOnce() -> Result<Vec<u8>, CommandError>,
) -> Result<InstanceView, CommandError> {
    let InstanceAddArgs {
        alias,
        product,
        base_url,
        proxy,
        use_custom_ca,
        is_default,
    } = args;
    let mut req = AddInstance {
        alias: alias.0,
        product: product.0,
        base_url: base_url.0,
        proxy: proxy.0,
        ca_pem: None,
        is_default,
    };
    // M10 T36 (L217): core's own checks (URL, alias, default) come first, so a request core
    // refuses never opens the file dialog.
    admin.check_add(&req)?;
    if use_custom_ca {
        req.ca_pem = Some(pick_ca()?);
    }
    Ok(admin.add(req)?)
}

pub fn instance_change_url_dto(
    admin: &dyn InstanceAdmin,
    args: InstanceChangeUrlArgs,
) -> Result<InstanceView, CommandError> {
    Ok(admin.change_base_url(args.alias.as_str(), &args.new_url.0)?)
}

pub fn instance_confirm_config_dto(
    admin: &dyn InstanceAdmin,
    args: InstanceConfirmConfigArgs,
) -> Result<InstanceView, CommandError> {
    Ok(admin.confirm_config_instance(args.alias.as_str())?)
}

pub fn instance_accept_url_change_dto(
    admin: &dyn InstanceAdmin,
    args: InstanceAcceptUrlChangeArgs,
) -> Result<InstanceView, CommandError> {
    Ok(admin.accept_config_url_change(args.alias.as_str())?)
}

pub fn instance_set_proxy_dto(
    admin: &dyn InstanceAdmin,
    args: InstanceSetProxyArgs,
) -> Result<InstanceView, CommandError> {
    Ok(admin.set_proxy(args.alias.as_str(), args.proxy.0)?)
}

/// `retest_token`: the §7.1 identity re-test of the stored token. A failed test is an answer
/// (the instance may have gone to `needs_token`), everything else passes through as an error.
pub async fn retest_token_dto(
    admin: Arc<dyn InstanceAdmin>,
    alias: &Alias,
) -> Result<RetestOutcome, CommandError> {
    match admin.retest_token(alias.as_str()).await {
        Ok(report) => Ok(RetestOutcome::Ok(Connected::from(report))),
        Err(AdminError::ConnectionFailed(f)) => Ok(RetestOutcome::Failed(connection_failure(&f))),
        Err(e) => Err(CommandError::Admin(e)),
    }
}

pub fn prune_backlog_now_dto(settings: &dyn SettingsAdmin) -> Result<PruneReport, CommandError> {
    Ok(settings.prune_backlog_now()?)
}

/// Why the credential window did not open for the PAT: the instance's refusal as it is
/// (`insecure_scheme`, `unconfirmed`, `not_found`), `Busy` while the window is open for something
/// else, and `Internal` for a window that could not be built.
pub fn pat_open_error(e: PatOpenError) -> CommandError {
    match e {
        PatOpenError::Instance(e) => CommandError::Admin(e),
        PatOpenError::Window(WindowError::Busy) => CommandError::Busy,
        PatOpenError::Window(_) => CommandError::Internal,
    }
}

// ---------- the commands ----------

/// What a failed call logs, or `None` when it is not logged: the outer kind (`admin`, `settings`,
/// `busy`, ...) and, for core's errors, the inner kind too (`config_read_only`, `keychain`, ...).
/// Both are the errors' `Display`, which never holds a message, a path or a value. A declined
/// dialog is the user's own answer and `not_ready` is the state before the core serves: neither
/// is a failure.
pub fn failure_class(e: &CommandError) -> Option<(String, Option<String>)> {
    let inner = match e {
        CommandError::Admin(AdminError::Cancelled)
        | CommandError::Settings(SettingsError::Cancelled)
        | CommandError::Cancelled
        | CommandError::NotReady => return None,
        CommandError::Admin(a) => Some(a.to_string()),
        CommandError::Settings(s) => Some(s.to_string()),
        CommandError::CliInstall(c) => Some(c.to_string()),
        CommandError::Removal(r) => Some(r.to_string()),
        CommandError::Restore(r) => Some(r.kind().to_owned()),
        CommandError::AnchorDir(a) => Some(a.kind().to_owned()),
        CommandError::ReAnchor(r) => Some(r.kind().to_owned()),
        CommandError::Forget(f) => Some(f.kind().to_owned()),
        _ => None,
    };
    Some((e.to_string(), inner))
}

fn note_failure<T>(result: &Result<T, CommandError>) {
    let Err(e) = result else { return };
    if let Some((class, inner)) = failure_class(e) {
        tracing::warn!(
            event = LOG_EVENT_SETTINGS_FAILED,
            error_class = class.as_str(),
            error_kind = inner.as_deref().unwrap_or("")
        );
    }
}

/// The end of every instance command: logs a failure by kind, tells the windows that settings
/// changed, and answers. The event follows *whatever* core answered: core can commit and then
/// answer an error (a declined CA dialog after the origin was confirmed, a failed token delete or
/// table reload after an origin change), and the windows must re-read `settings_get` either way
/// (M6 T25 review I-1). A call that changed nothing costs one harmless re-read.
pub fn conclude_instance_call<R: Runtime>(
    app: &AppHandle<R>,
    response: Result<InstanceView, CommandError>,
) -> Result<InstanceView, CommandError> {
    note_failure(&response);
    emit_settings_changed(app);
    finish(app, response)
}

/// Runs `f` over the serving core's `InstanceAdmin` on the blocking pool, then
/// [`conclude_instance_call`].
async fn with_instances<R, F>(app: &AppHandle<R>, f: F) -> Result<InstanceView, CommandError>
where
    R: Runtime,
    F: FnOnce(&dyn InstanceAdmin) -> Result<InstanceView, CommandError> + Send + 'static,
{
    let response = match core(app) {
        Ok(core) => {
            let admin = core.instances();
            blocking(move || f(&*admin)).await
        }
        Err(e) => Err(e),
    };
    conclude_instance_call(app, response)
}

/// `settings_get {}` (Δ1): the view, the instances, the confinement verdict, the CLI state.
#[tauri::command]
pub async fn settings_get<R: Runtime>(
    app: AppHandle<R>,
    args: Args<SettingsGetArgs>,
) -> Result<SettingsGet, CommandError> {
    let Args(SettingsGetArgs {}) = args;
    // The report is set once and never changes: a copy is the verdict at this call (pending while
    // the probe has not finished, or without an `AppState`).
    let report = app
        .try_state::<AppState>()
        .and_then(|s| s.probe_report().cloned());
    let response = match core(&app) {
        Ok(core) => {
            let (settings, instances) = (core.settings(), core.instances());
            // Reads the registry or the file system, and the settings view: the blocking pool.
            blocking(move || {
                let (installed, removable) = cli_state();
                // Δ8: the setting is core's run policy as the glue reads it at each call.
                let confinement =
                    ConfinementDto::of_probe(report.as_ref(), core.script_policy().allow_degraded);
                Ok(settings_get_dto(
                    &*settings,
                    &*instances,
                    confinement,
                    installed,
                    removable,
                ))
            })
            .await
        }
        Err(e) => Err(e),
    };
    finish(&app, response)
}

/// `settings_apply {changes}` (Δ1, PD-76): the new view. Core's native confirmations run on the
/// blocking pool; the windows re-read afterwards (`settings_changed`).
#[tauri::command]
pub async fn settings_apply<R: Runtime>(
    app: AppHandle<R>,
    args: Args<SettingsApplyArgs>,
) -> Result<SettingsView, CommandError> {
    let Args(SettingsApplyArgs { changes }) = args;
    let mut flipped = false;
    let response = match core(&app) {
        Ok(core) => {
            let settings = core.settings();
            blocking(move || {
                // The header's `scripts_degraded` line follows this setting (T21 review I-2).
                Ok(apply_noting_degraded(
                    || settings.view().allow_degraded_scripts,
                    || settings_apply_dto(&*settings, changes),
                ))
            })
            .await
            // If the blocking task itself fails (a join error) after core committed a flip, `flipped`
            // stays false and no `status_banner` follows: accepted (T23 review m-5), the header
            // re-reads `app_status` on its next refresh and `settings_changed` is still emitted.
            .and_then(|(applied, flip)| {
                flipped = flip;
                applied
            })
        }
        Err(e) => Err(e),
    };
    conclude_settings_apply(&app, response, flipped)
}

/// The end of `settings_apply`: logs a failure by kind, tells the windows that settings changed
/// (whatever core answered: it can commit and then fail) and, when "allow scripts with degraded
/// confinement" flipped, that the status changed (`status_banner`, T21 review I-2: the header's
/// `scripts_degraded` line follows that setting), then answers.
pub fn conclude_settings_apply<R: Runtime>(
    app: &AppHandle<R>,
    response: Result<SettingsView, CommandError>,
    flipped: bool,
) -> Result<SettingsView, CommandError> {
    note_failure(&response);
    emit_settings_changed(app);
    if flipped {
        crate::ui_sink::emit_status_changed(app);
    }
    finish(app, response)
}

/// Rust's file dialog for the custom CA, then [`read_ca_bounded`]. Blocks until the user answers:
/// the blocking pool only. The path never leaves this function.
fn pick_ca_file<R: Runtime>(app: &AppHandle<R>) -> Result<Vec<u8>, CommandError> {
    use tauri_plugin_dialog::DialogExt;
    let Some(chosen) = app
        .dialog()
        .file()
        .set_title(CA_DIALOG_TITLE)
        .add_filter(CA_FILTER, CA_EXTENSIONS)
        .blocking_pick_file()
    else {
        return Err(CommandError::Admin(AdminError::Cancelled));
    };
    let path = chosen.into_path().map_err(|_| CommandError::Internal)?;
    read_ca_bounded(&path)
}

/// `instance_add {alias, product, base_url, proxy, use_custom_ca, is_default}` (Δ1, §7.1): the new
/// instance stays unconfirmed until core's native dialog (alias and normalized origin, then the CA's
/// subject and fingerprint) is accepted.
#[tauri::command]
pub async fn instance_add<R: Runtime>(
    app: AppHandle<R>,
    args: Args<InstanceAddArgs>,
) -> Result<InstanceView, CommandError> {
    let Args(args) = args;
    let handle = app.clone();
    with_instances(&app, move |admin| {
        instance_add_dto(admin, args, || pick_ca_file(&handle))
    })
    .await
}

/// `instance_change_url {alias, new_url}` (Δ1): applied after core's native confirmation of the old
/// and new origin; a confirmed change invalidates the stored PAT (§7.1).
#[tauri::command]
pub async fn instance_change_url<R: Runtime>(
    app: AppHandle<R>,
    args: Args<InstanceChangeUrlArgs>,
) -> Result<InstanceView, CommandError> {
    let Args(args) = args;
    with_instances(&app, move |admin| instance_change_url_dto(admin, args)).await
}

/// `instance_confirm_config {alias}` (Δ1, I-31): confirms an instance added in `config.toml`.
#[tauri::command]
pub async fn instance_confirm_config<R: Runtime>(
    app: AppHandle<R>,
    args: Args<InstanceConfirmConfigArgs>,
) -> Result<InstanceView, CommandError> {
    let Args(args) = args;
    with_instances(&app, move |admin| instance_confirm_config_dto(admin, args)).await
}

/// `instance_accept_url_change {alias}` (Δ1, §7.1): accepts the URL change `config.toml` requested,
/// after core's native confirmation.
#[tauri::command]
pub async fn instance_accept_url_change<R: Runtime>(
    app: AppHandle<R>,
    args: Args<InstanceAcceptUrlChangeArgs>,
) -> Result<InstanceView, CommandError> {
    let Args(args) = args;
    with_instances(&app, move |admin| {
        instance_accept_url_change_dto(admin, args)
    })
    .await
}

/// `instance_set_proxy {alias, proxy}` (Δ1, L42): `""`, `direct` or `host:port`.
#[tauri::command]
pub async fn instance_set_proxy<R: Runtime>(
    app: AppHandle<R>,
    args: Args<InstanceSetProxyArgs>,
) -> Result<InstanceView, CommandError> {
    let Args(args) = args;
    with_instances(&app, move |admin| instance_set_proxy_dto(admin, args)).await
}

/// `credential_window_open {alias, purpose}` (Δ1, §10.3): Rust reads the instance table and opens
/// the credential window for that instance; it never takes the origin, product or state from the
/// webview. Refused for an unknown alias, `insecure_scheme` and `unconfirmed` instances (the
/// instance's own error) and `busy` while the window is open for something else.
#[tauri::command]
pub async fn credential_window_open<R: Runtime>(
    app: AppHandle<R>,
    args: Args<CredentialWindowOpenArgs>,
) -> Result<(), CommandError> {
    let Args(CredentialWindowOpenArgs { alias, purpose }) = args;
    // T28 (T20 m-9): not while a removal call deletes tokens (a token entered then would outlive
    // the delete; `removal_finish` looks again before it removes anything). No window is open
    // then: the answer says a removal step runs (T28 m-8).
    if app.try_state::<RemovalState>().is_some_and(|r| r.busy()) {
        let response = Err(CommandError::Removal(RemovalError::Running));
        note_failure(&response);
        return finish(&app, response);
    }
    let response = match core(&app) {
        Ok(core) => {
            let (admin, handle) = (core.instances(), app.clone());
            blocking(move || {
                let views = admin.list();
                credential::open_for_pat(&handle, &views, alias.as_str(), purpose.replace)
                    .map_err(pat_open_error)
            })
            .await
        }
        Err(e) => Err(e),
    };
    note_failure(&response);
    finish(&app, response)
}

/// `retest_token {alias}` (Δ1, §7.1 "Re-test stored token"): a `token_recheck` that restores the
/// instance only on an identity match. The windows re-read afterwards: the state may have changed
/// either way.
#[tauri::command]
pub async fn retest_token<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RetestTokenArgs>,
) -> Result<RetestOutcome, CommandError> {
    let Args(RetestTokenArgs { alias }) = args;
    let response = match core(&app) {
        Ok(core) => retest_token_dto(core.instances(), &alias).await,
        Err(e) => Err(e),
    };
    note_failure(&response);
    emit_settings_changed(&app);
    finish(&app, response)
}

/// `cli_install {}` (Δ1, §12.3): puts the CLI on the PATH for this installation (Windows user PATH,
/// macOS link, AppImage wrapper and launcher; deb/rpm have it already). Also granted to `setup` (the
/// wizard's CLI step, T23 hook at [`cli_install_dto`]). The registry and the file system are touched
/// on the blocking pool; the windows re-read afterwards (`settings_changed`), whatever the answer.
#[tauri::command]
pub async fn cli_install<R: Runtime>(
    app: AppHandle<R>,
    args: Args<CliInstallArgs>,
) -> Result<CliInstallAnswer, CommandError> {
    let Args(CliInstallArgs {}) = args;
    let response = match core(&app) {
        Ok(core) => {
            let settings = core.settings();
            blocking(move || cli_install_dto(&*settings, &SystemOps, this_machine())).await
        }
        Err(e) => Err(e),
    };
    note_failure(&response);
    emit_settings_changed(&app);
    finish(&app, response)
}

/// `cli_uninstall {}` (Δ1, §12.3): removes what `cli_install` wrote and `cli.toml`.
#[tauri::command]
pub async fn cli_uninstall<R: Runtime>(
    app: AppHandle<R>,
    args: Args<CliUninstallArgs>,
) -> Result<CliInstallAnswer, CommandError> {
    let Args(CliUninstallArgs {}) = args;
    let response = match core(&app) {
        Ok(core) => {
            let settings = core.settings();
            blocking(move || cli_uninstall_dto(&*settings, &SystemOps, this_machine())).await
        }
        Err(e) => Err(e),
    };
    note_failure(&response);
    emit_settings_changed(&app);
    finish(&app, response)
}

/// `prune_backlog_now {}` (Δ1, L37): one prune run after core's native confirmation.
#[tauri::command]
pub async fn prune_backlog_now<R: Runtime>(
    app: AppHandle<R>,
    args: Args<PruneBacklogNowArgs>,
) -> Result<PruneReport, CommandError> {
    let Args(PruneBacklogNowArgs {}) = args;
    let response = match core(&app) {
        Ok(core) => {
            let settings = core.settings();
            blocking(move || prune_backlog_now_dto(&*settings)).await
        }
        Err(e) => Err(e),
    };
    note_failure(&response);
    emit_settings_changed(&app);
    finish(&app, response)
}

// ---------- "Prepare for removal" (§12.5, M6 T28) ----------

/// plan text (T28): the title of the folder dialog the backup bundle is written into.
const BACKUP_DIALOG_TITLE: &str = "Choose the folder for the atlas-duck backup";

/// What the removal commands need of the serving core.
struct Served {
    instances: Arc<dyn InstanceAdmin>,
    settings: Arc<dyn SettingsAdmin>,
    confirmer: Arc<dyn atlas_duck_core::NativeConfirmer>,
    /// The open store: the newest record's epoch and the procedure's records (PD-176).
    store: atlas_duck_audit::Store,
    /// The serving state: its job slot holds `removal_begin` and `removal_finish` off (M10 T16
    /// review M-6).
    serving: Arc<crate::serve::ServeState>,
}

fn served<R: Runtime>(app: &AppHandle<R>) -> Result<Served, CommandError> {
    let state = app
        .try_state::<ServeSlot>()
        .and_then(|slot| slot.get().cloned())
        .ok_or(CommandError::NotReady)?;
    let core = state.core.get().cloned().ok_or(CommandError::NotReady)?;
    let confirmer = state.confirmer().ok_or(CommandError::NotReady)?;
    let store = state.open_store().ok_or(CommandError::NotReady)?;
    Ok(Served {
        instances: core.instances(),
        settings: core.settings(),
        confirmer,
        store,
        serving: state,
    })
}

/// The retention facts beside the backup offer (§12.5 step 1, PD-176): the setting, and the
/// newest record's remaining days from its `epoch` and today's UTC date (display only: a head that
/// cannot be read shows the setting, [`removal::retention_shown`]).
async fn retention_of(served: &Served) -> Result<Retention, CommandError> {
    let (settings, store) = (served.settings.clone(), served.store.clone());
    blocking(move || {
        use atlas_duck_audit::Clock as _;
        let view = settings.view();
        Ok(removal::retention_shown(
            view.retention_days,
            view.legal_hold,
            removal::newest_epoch(&store),
            atlas_duck_audit::SystemClock::new().now_utc(),
        ))
    })
    .await
}

/// PD-176: before the first removal call of a process, the audit log is read back for an open
/// procedure ([`RemovalState::hydrate_from`]: a closed store is `not_ready`; a log that cannot be
/// read resumes nothing).
async fn hydrate(state: &RemovalState, served: &Served) -> Result<(), CommandError> {
    if !state.needs_log() {
        return Ok(());
    }
    let (store, admin) = (served.store.clone(), served.instances.clone());
    let (read, views) = blocking(move || Ok((removal::read_log(&store), admin.list()))).await?;
    state.hydrate_from(read, &views)
}

/// The credential window is open for a token (add or replace).
fn pat_window_open<R: Runtime>(app: &AppHandle<R>) -> bool {
    credential::current_purpose(app).is_some_and(|p| p.pat_target().is_some())
}

/// What holds `removal_begin` and `removal_finish` off (`busy`): the credential window open for a
/// token, or the serving state's job slot held (an export, a backup, a restore, a recovery-tier
/// flow; M10 T16 review M-6: a restore could take the choices record back after the effects ran).
fn removal_held_off<R: Runtime>(app: &AppHandle<R>, serving: &crate::serve::ServeState) -> bool {
    pat_window_open(app) || serving.job_running()
}

/// The end of every removal call: logs a failure by kind and answers.
fn conclude_removal<R: Runtime, T: Serialize>(
    app: &AppHandle<R>,
    response: Result<T, CommandError>,
    changed: bool,
) -> Result<T, CommandError> {
    note_failure(&response);
    if changed {
        // Whatever the answer: tokens may be deleted and the table has changed (T25 I-1).
        emit_settings_changed(app);
    }
    finish(app, response)
}

/// `removal_state {}` (§12.5, PD-176): the procedure under way (`active: false` before `begin`),
/// also one the audit log records from before a restart.
#[tauri::command]
pub async fn removal_state<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RemovalStateArgs>,
) -> Result<RemovalDto, CommandError> {
    let Args(RemovalStateArgs {}) = args;
    let response = async {
        let served = served(&app)?;
        let retention = retention_of(&served).await?;
        let state = app
            .try_state::<RemovalState>()
            .ok_or(CommandError::NotReady)?;
        hydrate(&state, &served).await?;
        Ok::<_, CommandError>(state.dto(retention))
    }
    .await;
    conclude_removal(&app, response, false)
}

/// `removal_export {}` (§12.5 step 1, PD-176): the compliance export the procedure offers, the
/// Audit window's export flow (M10 T12) over the full range: the PD-161 warning and the folder
/// dialog in Rust, then the export as the serving state's one job (`busy` while another runs;
/// `export_cancel` and Quit cancel it, PD-181), `audit_job` progress; answers the recipient's facts.
#[tauri::command]
pub async fn removal_export<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RemovalExportArgs>,
) -> Result<super::audit::ExportDoneDto, CommandError> {
    let Args(RemovalExportArgs {}) = args;
    let response = async {
        let state = app
            .try_state::<ServeSlot>()
            .and_then(|slot| slot.get().cloned())
            .ok_or(CommandError::NotReady)?;
        let store = state.open_store().ok_or(CommandError::NotReady)?;
        let confirmer = state.confirmer().ok_or(CommandError::NotReady)?;
        let handle = app.clone();
        let rx = state
            .spawn_audit_job(crate::serve::AuditJobKind::Export, move |cancel| {
                removal::export(
                    &store,
                    &*confirmer,
                    || super::audit::pick_export_folder(&handle),
                    &cancel,
                    &handle,
                )
            })
            .map_err(super::audit::job_refused)?;
        rx.await.map_err(|_| CommandError::Internal)?
    }
    .await;
    conclude_removal(&app, response, false)
}

/// `removal_backup {}` (§12.5 step 1): the Audit window's `backup_trigger` (M10 T16 review I-2, one
/// body for both): Rust's folder dialog, then `Store::backup` into a new bundle directory there (no
/// token in it, §8.10; the store logs `BACKUP`), as the serving state's one job (`busy` while
/// another holds the slot; Quit waits for it, and a Quit while the dialog was open backs up
/// nothing). A cancelled dialog is `saved: false`. The webview supplies no path.
#[tauri::command]
pub async fn removal_backup<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RemovalBackupArgs>,
) -> Result<BackupAnswer, CommandError> {
    let Args(RemovalBackupArgs {}) = args;
    let response = super::audit::backup_job(&app).await;
    conclude_removal(&app, response, false)
}

/// Rust's folder dialog for a backup bundle (§12.5 step 1, and the Audit window's `backup_trigger`,
/// M10 T12); `None` when cancelled. Blocks until the user answers: the blocking pool only.
pub(crate) fn pick_backup_folder<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<Option<atlas_duck_audit::types::RustChosenPath>, CommandError> {
    use atlas_duck_audit::types::RustChosenPath;
    use tauri_plugin_dialog::DialogExt;
    let Some(chosen) = app
        .dialog()
        .file()
        .set_title(BACKUP_DIALOG_TITLE)
        .blocking_pick_folder()
    else {
        return Ok(None);
    };
    let path = chosen.into_path().map_err(|_| CommandError::Internal)?;
    Ok(Some(RustChosenPath::from_native_dialog(path)))
}

/// `removal_begin {}` (§12.5 step 2): native confirmation, then the stored tokens are deleted
/// (`CREDENTIAL_CHANGED` per instance, before each keychain delete); answers the checklist.
#[tauri::command]
pub async fn removal_begin<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RemovalBeginArgs>,
) -> Result<RemovalDto, CommandError> {
    let Args(RemovalBeginArgs {}) = args;
    let response = async {
        let served = served(&app)?;
        let retention = retention_of(&served).await?;
        let state = app
            .try_state::<RemovalState>()
            .ok_or(CommandError::NotReady)?;
        hydrate(&state, &served).await?;
        let serving = served.serving;
        removal::begin(
            &state,
            served.instances,
            served.confirmer,
            || removal_held_off(&app, &serving),
            retention,
        )
        .await
    }
    .await;
    conclude_removal(&app, response, true)
}

/// `removal_mark {alias, choice}` (§12.5 step 2): ticks an instance as revoked or marks it skipped.
#[tauri::command]
pub async fn removal_mark<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RemovalMarkArgs>,
) -> Result<RemovalDto, CommandError> {
    let Args(RemovalMarkArgs { alias, choice }) = args;
    let response = async {
        let served = served(&app)?;
        let retention = retention_of(&served).await?;
        let state = app
            .try_state::<RemovalState>()
            .ok_or(CommandError::NotReady)?;
        hydrate(&state, &served).await?;
        removal::mark(&state, alias.as_str(), choice.0, retention)
    }
    .await;
    conclude_removal(&app, response, false)
}

/// `removal_finish {}` (§12.5 steps 3 and 4): refused until every instance is ticked or skipped;
/// native confirmation; one `CONFIG_CHANGED` with the choices; then autostart, the PATH entry, link
/// or wrapper, launcher and `cli.toml` go. The KEK, the anchors and the DB stay.
#[tauri::command]
pub async fn removal_finish<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RemovalFinishArgs>,
) -> Result<FinishAnswer, CommandError> {
    let Args(RemovalFinishArgs {}) = args;
    let response = async {
        let served = served(&app)?;
        let (layout, fallback) = blocking(|| Ok(machine_for_removal())).await?;
        let state = app
            .try_state::<RemovalState>()
            .ok_or(CommandError::NotReady)?;
        hydrate(&state, &served).await?;
        let serving = served.serving;
        removal::finish(
            &state,
            served.instances,
            served.settings,
            served.confirmer,
            Arc::new(PluginAutostart(app.clone())),
            Arc::new(SystemOps),
            layout,
            fallback,
            || removal_held_off(&app, &serving),
        )
        .await
    }
    .await;
    conclude_removal(&app, response, true)
}

// ---------- "Restore backup…" (M10 T13; §8.11, §10.3, PD-168, PD-181) ----------

/// `restore_begin {}`: Rust draws every dialog and opens the credential window itself; no path and
/// no secret come in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreBeginArgs {}

/// `restore_cancel {}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreCancelArgs {}

/// `restore_begin`'s answer after a completed restore (counts only). `tokens_deleted` instances
/// need their token again (§8.11 step 3); `offer_passphrase_change` is always true: the backup's
/// recovery passphrase is this log's now, and §8.11 step 2 offers a change right after.
/// `after_restore_failed`: the restore is complete, but its follow-up (`Core::after_restore`: the
/// config file reconciled again, `needs_token` per deleted token) failed; the instance list was
/// read again all the same, and prune stays blocked until a restart reconciles the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestoreDoneDto {
    pub restore_seq: u64,
    pub records_lost: u64,
    pub tokens_deleted: u64,
    pub offer_passphrase_change: bool,
    pub after_restore_failed: bool,
}

impl RestoreDoneDto {
    pub fn of(r: &atlas_duck_audit::RestoreReport, after_restore_failed: bool) -> RestoreDoneDto {
        RestoreDoneDto {
            restore_seq: r.restore_seq,
            records_lost: r.records_lost,
            tokens_deleted: r.pats_deleted.len() as u64,
            offer_passphrase_change: true,
            after_restore_failed,
        }
    }
}

/// The answer after a completed restore and its follow-up `followed` (`Core::after_restore`): a
/// failed follow-up is logged and named in the answer (T13 review I-4), never a plain success.
fn restore_done(
    report: &atlas_duck_audit::RestoreReport,
    followed: Result<(), atlas_duck_audit::AuditError>,
) -> RestoreDoneDto {
    if followed.is_err() {
        tracing::warn!(
            event = LOG_EVENT_SETTINGS_FAILED,
            error_class = "restore",
            error_kind = "after_restore"
        );
    }
    RestoreDoneDto::of(report, followed.is_err())
}

/// `restore_cancel`'s answer: true when the restore ended while no store call ran (before it, or
/// in the rollback dialog after a first call that changed nothing); false when none ran. While a
/// store call runs the answer is the error `busy` (PD-181).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RestoreCancelDto {
    pub cancelled: bool,
}

/// `restore_begin {}` (§8.11, PD-168, PD-181): the Settings restore as the serving state's one audit
/// job (`busy` while an export, backup or restore runs; `busy` too while the credential window is
/// open for something else): `restore_flow::run_live_restore` (the native "Restore backup"
/// confirmation, Rust's file dialog, the passphrase through the credential window, the rollback
/// confirmation when the store asks, `Store::restore`), then `Core::after_restore` inside the job
/// (the config file reconciled again, `needs_token` per deleted PAT; Quit waits for the job before
/// the core's shutdown, so they precede `APP_STOP`), then `settings_changed` and `status_banner`.
#[tauri::command]
pub async fn restore_begin<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RestoreBeginArgs>,
) -> Result<RestoreDoneDto, CommandError> {
    let Args(RestoreBeginArgs {}) = args;
    let response = async {
        let state = app
            .try_state::<ServeSlot>()
            .and_then(|slot| slot.get().cloned())
            .ok_or(CommandError::NotReady)?;
        let core = state.core.get().cloned().ok_or(CommandError::NotReady)?;
        let store = state.open_store().ok_or(CommandError::NotReady)?;
        let confirmer = state.confirmer().ok_or(CommandError::NotReady)?;
        if credential::current_purpose(&app).is_some() {
            return Err(CommandError::Busy);
        }
        let handle = app.clone();
        let rx = state
            .spawn_restore_job(move |cancel, call| {
                restore_job(&handle, &core, &store, &*confirmer, &call, &cancel)
            })
            .map_err(|e| match e {
                JobRefused::Busy => CommandError::Busy,
                JobRefused::ShuttingDown => CommandError::NotReady,
            })?;
        rx.await.map_err(|_| CommandError::Internal)?
    }
    .await;
    note_failure(&response);
    finish(&app, response)
}

/// The job of `restore_begin`, on its blocking thread.
fn restore_job<R: Runtime>(
    app: &AppHandle<R>,
    core: &Arc<atlas_duck_core::Core>,
    store: &atlas_duck_audit::Store,
    confirmer: &dyn atlas_duck_core::NativeConfirmer,
    call: &StoreCall,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<RestoreDoneDto, CommandError> {
    // Read again now that the job holds the slot (T14 review I-2): a recovery-passphrase change
    // window opened since the check in `restore_begin` would otherwise run beside the restore.
    if credential::current_purpose(app).is_some() {
        return Err(CommandError::Busy);
    }
    let report = restore_flow::run_live_restore(
        store,
        confirmer,
        || restore_flow::pick_restore_source(app),
        |stop| restore_passphrase(app, stop),
        call,
        cancel,
        app,
    )?;
    // M2 handoff (T16): the restored view must be reconciled with the config file before prune
    // runs again, and every PAT the restore deleted is logged `needs_token` (PD-28).
    let followed = tauri::async_runtime::block_on(core.after_restore(&report));
    emit_settings_changed(app);
    emit_status_changed(app);
    Ok(restore_done(&report, followed))
}

/// The backup's passphrase: the credential window opened for `restore_backup` and the one entry its
/// `submit_secret` hands over (never a command response). A window that goes without a submit, or
/// `stop` (restore cancel, Quit), is `Cancelled`; the window is closed then. `Busy` when the
/// window is open for something else (it may have opened while the native dialogs were up).
fn restore_passphrase<R: Runtime>(
    app: &AppHandle<R>,
    stop: &dyn Fn() -> bool,
) -> Result<secrecy::SecretString, restore_flow::NotAsked> {
    let request =
        credential::request_restore_passphrase(app, Show::Focus).map_err(|e| match e {
            WindowError::Busy => restore_flow::NotAsked::Busy,
            _ => restore_flow::NotAsked::NoWindow,
        })?;
    let entered = restore_flow::wait_passphrase(&request.rx, stop);
    if entered.is_err() {
        credential::close_if(app, request.generation);
    }
    entered
}

/// `restore_cancel {}` (PD-181): a Settings restore ends while no store call runs (`{cancelled:
/// true}`: no further store call, no `RESTORE`, the credential window closes; also while the
/// rollback confirmation is up, T13 review I-1); while `Store::restore` runs it cannot be
/// cancelled (`busy`). `{cancelled: false}` when no restore runs.
#[tauri::command]
pub async fn restore_cancel<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RestoreCancelArgs>,
) -> Result<RestoreCancelDto, CommandError> {
    let Args(RestoreCancelArgs {}) = args;
    let response = match app.try_state::<ServeSlot>().and_then(|s| s.get().cloned()) {
        None => Ok(RestoreCancelDto { cancelled: false }),
        Some(state) => match state.cancel_restore() {
            RestoreCancel::Cancelled(cancelled) => Ok(RestoreCancelDto { cancelled }),
            RestoreCancel::Running => Err(CommandError::Busy),
        },
    };
    finish(&app, response)
}

// ---------- the recovery tier and the anchor directory (M10 T14; PD-166, PD-169, PD-170) ----------

/// `recovery_passphrase_change {}`: Rust opens the credential window; the passphrase enters there.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPassphraseChangeArgs {}

/// `anchor_dir_set {}`: Rust confirms natively and opens its own folder dialog; no path comes in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorDirSetArgs {}

/// `anchor_dir_remove {}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorDirRemoveArgs {}

/// `re_anchor {}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReAnchorArgs {}

/// `orphan_installs {}` (read-only).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrphanInstallsArgs {}

/// `install_id` of `forget_install`: 32 lowercase hex digits (the audit store's id form). Which
/// install it names is checked against a fresh `orphan_installs` list in Rust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallIdDto(pub String);

impl<'de> Deserialize<'de> for InstallIdDto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = text(d, "install_id")?;
        if atlas_duck_audit::open::is_id(&s) {
            Ok(InstallIdDto(s))
        } else {
            Err(refuse("install_id"))
        }
    }
}

/// `forget_install {install_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgetInstallArgs {
    pub install_id: InstallIdDto,
}

/// What the recovery-tier commands need of the serving state: the state (its freeze), the open
/// store and the native confirmer.
type RecoveryInputs = (
    Arc<crate::serve::ServeState>,
    atlas_duck_audit::Store,
    Arc<dyn atlas_duck_core::NativeConfirmer>,
);

/// [`RecoveryInputs`]; `not_ready` while no store is open.
fn recovery_inputs<R: Runtime>(app: &AppHandle<R>) -> Result<RecoveryInputs, CommandError> {
    let state = app
        .try_state::<ServeSlot>()
        .and_then(|slot| slot.get().cloned())
        .ok_or(CommandError::NotReady)?;
    let store = state.open_store().ok_or(CommandError::NotReady)?;
    let confirmer = state.confirmer().ok_or(CommandError::NotReady)?;
    Ok((state, store, confirmer))
}

/// Runs a recovery-tier `flow` (its dialogs and its store call) as the serving state's one job
/// (T14 review I-2, `ServeState::spawn_recovery_job`): `busy` while an export, a backup, a restore
/// or another flow holds the slot, or while the credential window is open (as `restore_begin`);
/// `not_ready` once the quit path began. The slot is claimed first and the credential window read
/// second (its open for a passphrase change reads the slot under its own lock), so a flow and that
/// window never run side by side. `flow` gets its `stop`: the quit path's freeze or the job's
/// cancel flag, which the quit path sets before it waits for the flow.
async fn recovery_job<R, T, F>(app: &AppHandle<R>, flow: F) -> Result<T, CommandError>
where
    R: Runtime,
    T: Send + 'static,
    F: FnOnce(&AppHandle<R>, &RecoveryInputs, &dyn Fn() -> bool) -> Result<T, CommandError>
        + Send
        + 'static,
{
    let inputs = recovery_inputs(app)?;
    if credential::current_purpose(app).is_some() {
        return Err(CommandError::Busy);
    }
    let handle = app.clone();
    let state = inputs.0.clone();
    let rx = state
        .spawn_recovery_job(move |cancel| {
            if credential::current_purpose(&handle).is_some() {
                return Err(CommandError::Busy);
            }
            let stop =
                || cancel.load(std::sync::atomic::Ordering::SeqCst) || inputs.0.shutting_down();
            flow(&handle, &inputs, &stop)
        })
        .map_err(|e| match e {
            JobRefused::Busy => CommandError::Busy,
            JobRefused::ShuttingDown => CommandError::NotReady,
        })?;
    rx.await.map_err(|_| CommandError::Internal)?
}

/// Rust's folder dialog for the anchor directory (§8.5: no §7.7 local-filesystem check, a share is
/// what it is for); `None` when cancelled, or when the answer names no filesystem path. Blocks
/// until the user answers: the blocking pool only.
fn pick_anchor_folder<R: Runtime>(
    app: &AppHandle<R>,
) -> Option<atlas_duck_audit::types::RustChosenPath> {
    use atlas_duck_audit::types::RustChosenPath;
    use tauri_plugin_dialog::DialogExt;
    let chosen = app
        .dialog()
        .file()
        .set_title(recovery_tier::ANCHOR_DIR_DIALOG_TITLE)
        .blocking_pick_folder()?;
    let folder = chosen.into_path().ok()?;
    Some(RustChosenPath::from_native_dialog(folder))
}

/// `recovery_passphrase_change {}` (§8.6, PD-169; also the offer after a restore, §8.11 step 2):
/// opens the credential window for `change_recovery_passphrase` (`busy` while it is open for
/// anything else or while the job slot is held: a recovery-tier flow, an export, a backup or a
/// restore, T14 review I-2; `not_ready` while no store is open or once the quit path began, M-7).
/// The new passphrase, entered twice, enters there only (`submit_secret`); the window then offers
/// the recovery note.
#[tauri::command]
pub async fn recovery_passphrase_change<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RecoveryPassphraseChangeArgs>,
) -> Result<(), CommandError> {
    let Args(RecoveryPassphraseChangeArgs {}) = args;
    let response = match recovery_inputs(&app) {
        Ok((state, _, _)) if state.shutting_down() => Err(CommandError::NotReady),
        Ok(_) => {
            let handle = app.clone();
            blocking(move || {
                credential::open_for_passphrase_change(&handle).map_err(|e| match e {
                    WindowError::Busy => CommandError::Busy,
                    _ => CommandError::Internal,
                })
            })
            .await
        }
        Err(e) => Err(e),
    };
    note_failure(&response);
    finish(&app, response)
}

/// `anchor_dir_set {}` (§8.5, PD-166): Rust's folder dialog, then its native confirmation naming
/// the folder chosen, then `Store::change_anchor_dir` (its writability check: `anchor_dir
/// {not_writable}` is "This folder cannot be written"), as the serving state's one job. See
/// `recovery_tier::set_anchor_dir`.
#[tauri::command]
pub async fn anchor_dir_set<R: Runtime>(
    app: AppHandle<R>,
    args: Args<AnchorDirSetArgs>,
) -> Result<recovery_tier::AnchorDirDto, CommandError> {
    let Args(AnchorDirSetArgs {}) = args;
    let response = recovery_job(&app, |handle, (_, store, confirmer), stop| {
        recovery_tier::set_anchor_dir(
            store,
            &**confirmer,
            || pick_anchor_folder(handle),
            stop,
            handle,
        )
    })
    .await;
    note_failure(&response);
    finish(&app, response)
}

/// `anchor_dir_remove {}` (§8.5, PD-166): Rust's native confirmation, then
/// `Store::change_anchor_dir(None)`, as the serving state's one job. See
/// `recovery_tier::remove_anchor_dir`.
#[tauri::command]
pub async fn anchor_dir_remove<R: Runtime>(
    app: AppHandle<R>,
    args: Args<AnchorDirRemoveArgs>,
) -> Result<recovery_tier::AnchorDirDto, CommandError> {
    let Args(AnchorDirRemoveArgs {}) = args;
    let response = recovery_job(&app, |handle, (_, store, confirmer), stop| {
        recovery_tier::remove_anchor_dir(store, &**confirmer, stop, handle)
    })
    .await;
    note_failure(&response);
    finish(&app, response)
}

/// `re_anchor {}` (§8.7, PD-170): only while Settings offers it (a keychain anchor entry missing,
/// no barrier); Rust's native confirmation, then `Store::re_anchor` (an integrity incident), as
/// the serving state's one job. See `recovery_tier::re_anchor`.
#[tauri::command]
pub async fn re_anchor<R: Runtime>(
    app: AppHandle<R>,
    args: Args<ReAnchorArgs>,
) -> Result<recovery_tier::ReAnchoredDto, CommandError> {
    let Args(ReAnchorArgs {}) = args;
    let response = recovery_job(&app, |handle, (_, store, confirmer), stop| {
        recovery_tier::re_anchor(store, &**confirmer, stop, handle)
    })
    .await;
    note_failure(&response);
    finish(&app, response)
}

/// The data dir and the live keystore of the serving store (`forget {unreadable}` when the
/// keychain cannot be reached).
fn live_keys<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<
    (
        atlas_duck_ipc::paths::LocalDataDir,
        Arc<dyn atlas_duck_audit::KeyStore>,
    ),
    CommandError,
> {
    let (state, _, _) = recovery_inputs(app)?;
    let (data, keys) = state.live_keys().ok_or(CommandError::NotReady)?;
    let keys =
        keys.map_err(|_| CommandError::Forget(crate::commands::ForgetFailure::Unreadable))?;
    Ok((data, keys))
}

/// `orphan_installs {}` (PD-170, L116, T20 m-9): the installs only archived stores name, with the
/// keychain entries they still have (reading them may raise a macOS keychain prompt for items an
/// older or re-signed build wrote). See `recovery_tier::orphans`.
#[tauri::command]
pub async fn orphan_installs<R: Runtime>(
    app: AppHandle<R>,
    args: Args<OrphanInstallsArgs>,
) -> Result<Vec<recovery_tier::OrphanInstallDto>, CommandError> {
    let Args(OrphanInstallsArgs {}) = args;
    let response = match live_keys(&app) {
        Ok((data, keys)) => blocking(move || recovery_tier::orphans(&data, &*keys)).await,
        Err(e) => Err(e),
    };
    note_failure(&response);
    finish(&app, response)
}

/// `forget_install {install_id}` (PD-170): only an install of a fresh `orphan_installs` list; two
/// native dialogs (the tokens, then the archived log's keys); `CONFIG_CHANGED {key:
/// forget_install}` through core before anything is deleted; as the serving state's one job. See
/// `recovery_tier::forget`.
#[tauri::command]
pub async fn forget_install<R: Runtime>(
    app: AppHandle<R>,
    args: Args<ForgetInstallArgs>,
) -> Result<recovery_tier::ForgottenDto, CommandError> {
    let Args(ForgetInstallArgs { install_id }) = args;
    let response = match (live_keys(&app), core(&app)) {
        (Ok((data, keys)), Ok(core)) => {
            let settings = core.settings();
            recovery_job(&app, move |handle, (_, _, confirmer), stop| {
                recovery_tier::forget(
                    &data,
                    &*keys,
                    &|key, old, new| settings.record_app_change(key, old, new),
                    &**confirmer,
                    &install_id.0,
                    stop,
                    handle,
                )
            })
            .await
        }
        (Err(e), _) | (_, Err(e)) => Err(e),
    };
    note_failure(&response);
    finish(&app, response)
}

#[cfg(test)]
mod tests {
    /// M10 T36 (M6 M-1): a failed call's line carries `error_kind` through the allowlist (it was
    /// counted as dropped), for core's admin and settings errors.
    #[test]
    fn diag_lines_carry_error_kind_settings() {
        assert_eq!(
            LOG_FIELDS,
            ["error_kind"],
            "the allowlist is shared: pin this module's own"
        );
        let log = |e: CommandError| {
            crate::diag::fields::test_support::lines_after_extending(LOG_FIELDS, || {
                note_failure::<()>(&Err(e))
            })
        };
        let out = log(CommandError::Admin(AdminError::ConfigReadOnly));
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(
            out.contains(
                "event=settings_failed error_class=admin error_kind=config_read_only dropped_fields=0"
            ),
            "{out}"
        );
        let out = log(CommandError::Settings(SettingsError::Conflict));
        assert!(
            out.contains("error_class=settings error_kind=conflict dropped_fields=0"),
            "{out}"
        );
    }

    use serde_json::json;

    use super::*;
    use crate::commands::dto::{FIELD_PAYLOAD, parse};

    fn field<T: serde::de::DeserializeOwned>(body: Value) -> Option<&'static str> {
        match parse::<T>(&body) {
            Err(CommandError::InvalidArgument { field }) => Some(field),
            _ => None,
        }
    }

    fn add_body() -> Value {
        json!({"alias": "work", "product": "jira", "base_url": "https://jira.example/jira",
               "proxy": "", "use_custom_ca": false, "is_default": true})
    }

    /// The hint reaches the page through the page's own copy (`shared/strings.ts`, shown for
    /// `admin/insecure_scheme`; the wire carries only the kind). The Rust constant, that copy and
    /// the spec's §7.1 text must be one string: each is read from its file, none is compared with
    /// itself.
    #[test]
    fn the_https_hint_is_the_spec_sentence_and_the_pages_copy() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let read = |rel: &str| {
            std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
        };
        let spec = read("docs/superpowers/specs/2026-10-07-atlas-duck-design.md");
        assert!(spec.contains(HTTPS_REQUIRED_HINT), "the spec (7.1) differs");
        let page = read("app/ui/src/shared/strings.ts");
        assert!(
            page.contains(&format!("'{HTTPS_REQUIRED_HINT}'"))
                || page.contains(&format!("\"{HTTPS_REQUIRED_HINT}\"")),
            "the page's copy differs"
        );
    }

    /// T21 review I-2: a change of the degraded-confinement setting is noted, in either direction;
    /// a call that leaves it as it was (including one that failed) is not.
    #[test]
    fn a_flip_of_the_degraded_setting_is_noted() {
        use std::cell::Cell;

        let on = Cell::new(false);
        let (answer, flipped) = apply_noting_degraded(
            || on.get(),
            || {
                on.set(true);
                7
            },
        );
        assert_eq!((answer, flipped), (7, true), "turned on");
        let (_, flipped) = apply_noting_degraded(|| on.get(), || on.set(true));
        assert!(!flipped, "set again to the value it had");
        let (_, flipped) = apply_noting_degraded(|| on.get(), || on.set(false));
        assert!(flipped, "turned off");
        let (_, flipped) = apply_noting_degraded(|| on.get(), || ());
        assert!(!flipped, "nothing changed");
    }

    #[test]
    fn instance_add_args_parse_and_name_the_refused_field() {
        let ok = parse::<InstanceAddArgs>(&add_body()).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(ok.alias.as_str(), "work");
        assert_eq!(ok.product, ProductDto(Product::Jira));
        assert_eq!(ok.proxy, ProxyDto(ProxySetting::Os));
        assert!(!ok.use_custom_ca && ok.is_default);
        let with = |k: &str, v: Value| {
            let mut b = add_body();
            if let Some(m) = b.as_object_mut() {
                m.insert(k.into(), v);
            }
            b
        };
        for (key, bad) in [
            ("alias", json!("")),
            ("alias", json!("a b")),
            ("alias", json!("é")),
            ("alias", json!("a".repeat(MAX_ALIAS_CHARS + 1))),
            ("alias", json!(7)),
            ("product", json!("bitbucket")),
            ("product", json!("Jira")),
            ("base_url", json!("x".repeat(BASE_URL_MAX_BYTES + 1))),
            ("base_url", json!("https://a\u{0}b")),
            ("base_url", json!("https://a\nb")),
            ("base_url", json!(null)),
            ("proxy", json!("user:pw@proxy:8080")),
            ("proxy", json!("proxy")),
            ("proxy", json!("proxy:0")),
            ("proxy", json!("http://proxy:8080")),
            ("proxy", json!("p".repeat(PROXY_MAX_BYTES + 1))),
            ("proxy", json!("a\u{202E}b:8080")),
            ("proxy", json!("a\u{0}b:80")),
            ("proxy", json!("pro\txy:80")),
            ("proxy", json!("pr\u{f8}xy:80")),
            ("proxy", json!("[\u{ff1a}\u{ff1a}1]:80")),
        ] {
            assert_eq!(
                field::<InstanceAddArgs>(with(key, bad.clone())),
                Some(key),
                "{key} {bad}"
            );
        }
        for good in ["", "direct", "DIRECT", "proxy.corp:3128", "[::1]:8080"] {
            assert!(
                parse::<InstanceAddArgs>(&with("proxy", json!(good))).is_ok(),
                "{good}"
            );
        }
        // The booleans are plain fields: a wrong type is a payload refusal.
        assert_eq!(
            field::<InstanceAddArgs>(with("use_custom_ca", json!("yes"))),
            Some(FIELD_PAYLOAD)
        );
    }

    /// The DTO has no CA, certificate or path key: the webview cannot supply one (§10.3, M3 review
    /// I-5). Each is refused as an unknown key before any handler runs.
    #[test]
    fn ca_never_from_webview_the_dto_takes_no_ca_key() {
        for key in [
            "ca_pem",
            "ca_path",
            "ca_bundle",
            "ca",
            "pem",
            "cert",
            "certificate",
            "path",
            "file",
        ] {
            let mut b = add_body();
            if let Some(m) = b.as_object_mut() {
                m.insert(key.into(), json!("-----BEGIN CERTIFICATE-----"));
            }
            assert_eq!(field::<InstanceAddArgs>(b), Some(FIELD_PAYLOAD), "{key}");
        }
        // Not even `use_custom_ca: true` carries bytes: it is a bare bool.
        assert!(
            parse::<InstanceAddArgs>(&json!({"alias": "a", "product": "jira",
                "base_url": "https://j", "proxy": "", "use_custom_ca": ["x"], "is_default": false}))
            .is_err()
        );
    }

    #[test]
    fn the_other_argument_structs_are_closed_and_bounded() {
        assert_eq!(
            parse::<InstanceChangeUrlArgs>(&json!({"alias": "w", "new_url": "https://n.example"}))
                .map(|a| a.new_url),
            Ok(NewUrl("https://n.example".into()))
        );
        assert_eq!(
            field::<InstanceChangeUrlArgs>(json!({"alias": "w", "new_url": "x\u{7}"})),
            Some("new_url")
        );
        for body in [
            json!({"alias": "w", "path": "/x"}),
            json!({"alias": "w", "extra": 1}),
        ] {
            assert_eq!(
                field::<InstanceConfirmConfigArgs>(body.clone()),
                Some(FIELD_PAYLOAD)
            );
            assert_eq!(
                field::<InstanceAcceptUrlChangeArgs>(body.clone()),
                Some(FIELD_PAYLOAD)
            );
            assert_eq!(field::<RetestTokenArgs>(body), Some(FIELD_PAYLOAD));
        }
        assert_eq!(
            field::<RetestTokenArgs>(json!({"alias": "../x"})),
            Some("alias")
        );
        assert_eq!(field::<RetestTokenArgs>(json!({})), Some("alias"));
        assert_eq!(
            parse::<InstanceSetProxyArgs>(&json!({"alias": "w", "proxy": "direct"}))
                .map(|a| a.proxy),
            Ok(ProxyDto(ProxySetting::Direct))
        );
        assert_eq!(
            field::<InstanceSetProxyArgs>(json!({"alias": "w", "proxy": "a@b:1"})),
            Some("proxy")
        );
        assert_eq!(
            parse::<CredentialWindowOpenArgs>(&json!({"alias": "w", "purpose": "replace_pat"}))
                .map(|a| a.purpose),
            Ok(PatPurposeDto { replace: true })
        );
        assert_eq!(
            parse::<CredentialWindowOpenArgs>(&json!({"alias": "w", "purpose": "add_pat"}))
                .map(|a| a.purpose),
            Ok(PatPurposeDto { replace: false })
        );
        for purpose in [
            "unlock",
            "recover_this_log",
            "recovery_passphrase",
            "restore_backup",
            "change_recovery_passphrase",
            "",
            "Add_pat",
        ] {
            assert_eq!(
                field::<CredentialWindowOpenArgs>(json!({"alias": "w", "purpose": purpose})),
                Some("purpose"),
                "{purpose}"
            );
        }
        // An origin, a product or a state from the webview is not a key of the trigger.
        assert_eq!(
            field::<CredentialWindowOpenArgs>(
                json!({"alias": "w", "purpose": "add_pat", "base_url": "https://evil"})
            ),
            Some(FIELD_PAYLOAD)
        );
        for (name, body) in [
            ("settings_get", field::<SettingsGetArgs>(json!({"x": 1}))),
            (
                "prune",
                field::<PruneBacklogNowArgs>(json!({"force": true})),
            ),
        ] {
            assert_eq!(body, Some(FIELD_PAYLOAD), "{name}");
        }
        assert_eq!(parse::<SettingsGetArgs>(&json!({})), Ok(SettingsGetArgs {}));
        assert_eq!(
            parse::<PruneBacklogNowArgs>(&json!({})),
            Ok(PruneBacklogNowArgs {})
        );
    }

    /// The CLI commands take no key at all: where the CLI goes is Rust's decision (known folders,
    /// `$APPIMAGE`, the running binary), never a path from the webview (§10.3).
    #[test]
    fn the_cli_commands_take_no_arguments() {
        assert_eq!(parse::<CliInstallArgs>(&json!({})), Ok(CliInstallArgs {}));
        assert_eq!(
            parse::<CliUninstallArgs>(&json!({})),
            Ok(CliUninstallArgs {})
        );
        for key in ["path", "app_path", "dir", "force", "appimage", "x"] {
            let body = json!({ key: "/tmp/x" });
            assert_eq!(
                field::<CliInstallArgs>(body.clone()),
                Some(FIELD_PAYLOAD),
                "{key}"
            );
            assert_eq!(
                field::<CliUninstallArgs>(body),
                Some(FIELD_PAYLOAD),
                "{key}"
            );
        }
    }

    #[test]
    fn settings_changes_are_bounded_and_in_the_core_form() {
        let ok = parse::<SettingsApplyArgs>(&json!({"changes": [
            {"key": "jira_comments_cap", "value": 50},
            {"key": "max_pending_bytes_mb", "value": null},
            {"key": "attention_mode", "value": "badge_only"},
            {"key": "legal_hold", "value": true},
        ]}))
        .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(ok.changes.0.len(), 4);
        assert_eq!(ok.changes.0[0], SettingChangeReq::JiraCommentsCap(50));
        assert_eq!(ok.changes.0[1], SettingChangeReq::MaxPendingBytesMb(None));
        let seven: Vec<Value> = (0..MAX_CHANGES)
            .map(|_| json!({"key": "legal_hold", "value": false}))
            .collect();
        assert!(parse::<SettingsApplyArgs>(&json!({ "changes": seven })).is_ok());
        let eight: Vec<Value> = (0..=MAX_CHANGES)
            .map(|_| json!({"key": "legal_hold", "value": false}))
            .collect();
        for bad in [
            json!(eight),
            json!([]),
            json!("jira_comments_cap"),
            json!([{"key": "jira_comments_cap"}]),
            json!([{"key": "jira_comments_cap", "value": -1}]),
            json!([{"key": "jira_comments_cap", "value": "5"}]),
            json!([{"key": "unknown_key", "value": 1}]),
            json!([{"key": "legal_hold", "value": true, "extra": 1}]),
            json!([{"key": "attention_mode", "value": "sometimes"}]),
            // presentation_mode is not a persisted setting (T19 ruling): refused as a key.
            json!([{"key": "presentation_mode", "value": true}]),
            json!([{"key": "presentation_mode", "value": "on"}]),
            json!([7]),
            json!(null),
        ] {
            assert_eq!(
                field::<SettingsApplyArgs>(json!({ "changes": bad.clone() })),
                Some("changes"),
                "{bad}"
            );
        }
        assert_eq!(
            field::<SettingsApplyArgs>(
                json!({"changes": [{"key": "legal_hold", "value": true}], "force": true})
            ),
            Some(FIELD_PAYLOAD)
        );
    }

    #[test]
    fn a_window_that_cannot_open_maps_to_busy_or_internal() {
        assert_eq!(
            pat_open_error(PatOpenError::Window(WindowError::Busy)),
            CommandError::Busy
        );
        for e in [
            WindowError::NotRegistered,
            WindowError::Build,
            WindowError::Show,
        ] {
            assert_eq!(
                pat_open_error(PatOpenError::Window(e)),
                CommandError::Internal
            );
        }
        assert_eq!(
            pat_open_error(PatOpenError::Instance(AdminError::Unconfirmed)),
            CommandError::Admin(AdminError::Unconfirmed)
        );
    }

    /// The log line names the inner kind of core's errors (kind-only), skips a declined dialog
    /// and `not_ready`, and never takes a value: the inner text is `Display`, which is the kind.
    #[test]
    fn failures_log_the_outer_and_inner_kind_only() {
        let class = |e: CommandError| failure_class(&e);
        assert_eq!(
            class(CommandError::Admin(AdminError::ConfigReadOnly)),
            Some(("admin".into(), Some("config_read_only".into())))
        );
        assert_eq!(
            class(CommandError::Settings(SettingsError::Invalid {
                key: "jira_comments_cap"
            })),
            Some(("settings".into(), Some("invalid".into())))
        );
        assert_eq!(
            class(CommandError::Busy),
            Some(("busy".to_owned(), None::<String>))
        );
        assert_eq!(
            class(CommandError::InvalidArgument { field: "proxy" }),
            Some(("invalid_argument (proxy)".to_owned(), None))
        );
        assert_eq!(
            class(CommandError::CliInstall(InstallError::Occupied)),
            Some(("cli_install".into(), Some("occupied".into())))
        );
        assert_eq!(class(CommandError::Admin(AdminError::Cancelled)), None);
        assert_eq!(
            class(CommandError::Settings(SettingsError::Cancelled)),
            None
        );
        assert_eq!(class(CommandError::NotReady), None);
    }

    /// Δ8 / PD-141: `scripts` is `enabled` only under a met floor, `degraded` only under an unmet
    /// one with the setting on, `disabled` otherwise (and while the probe is pending); the setting
    /// is passed through; the failed probes are named (S-05).
    #[test]
    fn confinement_dto_scripts_follow_the_floor_and_the_setting() {
        use atlas_duck_ipc::sandbox::probe::ProbeId;

        let report = |floor| ProbeReport {
            worker_version: None,
            engine_version: None,
            identity: None,
            confinement: None,
            threads: None,
            records: Vec::new(),
            floor,
            extra_layers: Vec::new(),
            control: None,
            lpac_failed: None,
        };
        let met = report(FloorVerdict::Met);
        let unmet = report(FloorVerdict::NotMet {
            failed: vec![ProbeId::TaskForPid],
        });
        let got = |r: Option<&ProbeReport>, allowed: bool| {
            let dto = ConfinementDto::of_probe(r, allowed);
            (dto.state, dto.scripts, dto.degraded_allowed, dto.failed)
        };
        assert_eq!(got(None, false), ("pending", "disabled", false, vec![]));
        assert_eq!(got(None, true), ("pending", "disabled", true, vec![]));
        assert_eq!(got(Some(&met), false), ("met", "enabled", false, vec![]));
        assert_eq!(got(Some(&met), true), ("met", "enabled", true, vec![]));
        assert_eq!(
            got(Some(&unmet), false),
            ("not_met", "disabled", false, vec!["task_for_pid"])
        );
        assert_eq!(
            got(Some(&unmet), true),
            ("not_met", "degraded", true, vec!["task_for_pid"])
        );
        // The old constructors: no degraded confinement allowed.
        assert_eq!(ConfinementDto::of(&unmet).scripts, "disabled");
        assert_eq!(ConfinementDto::pending().scripts, "disabled");
    }

    #[test]
    fn the_cli_state_and_confinement_have_stable_shapes() {
        assert_eq!(
            serde_json::to_value(CliInstallAnswer {
                outcome: OUTCOME_INSTALLED
            })
            .unwrap_or_default(),
            json!({"outcome": "installed"})
        );
        let pending = ConfinementDto::pending();
        assert_eq!(
            serde_json::to_value(&pending).unwrap_or_default(),
            json!({
                "state": "pending", "failed": [], "mode": "n/a", "extra_layers": [],
                "scripts": "disabled", "degraded_allowed": false
            })
        );
        // Δ8 (on the wire since M8 T23): the scripts state and the policy the core runs under.
        let degraded = ConfinementDto::of_probe(None, true);
        assert_eq!(
            serde_json::to_value(&degraded).unwrap_or_default(),
            json!({
                "state": "pending", "failed": [], "mode": "n/a", "extra_layers": [],
                "scripts": "disabled", "degraded_allowed": true
            })
        );
        let retest = RetestOutcome::Failed(connection_failure(
            &atlas_duck_core::ConnectionFailure::OtherUser,
        ));
        assert_eq!(
            serde_json::to_value(&retest).unwrap_or_default(),
            json!({"failed": {"class": "other_user"}})
        );
    }

    /// M10 T14 (§10.3): the recovery-tier commands take no path, no passphrase and no flag: an
    /// empty body, or for `forget_install` an install id in the store's id form only.
    #[test]
    fn recovery_tier_args_take_nothing_but_an_install_id() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            parse::<ForgetInstallArgs>(&json!({ "install_id": id })).map(|a| a.install_id),
            Ok(InstallIdDto(id.into()))
        );
        for bad in [
            json!(""),
            json!("0123456789ABCDEF0123456789ABCDEF"),
            json!("0123456789abcdef0123456789abcde"),
            json!("0123456789abcdef0123456789abcdef0"),
            json!("../../0123456789abcdef0123456789"),
            json!(7),
            json!(null),
        ] {
            assert_eq!(
                field::<ForgetInstallArgs>(json!({ "install_id": bad.clone() })),
                Some("install_id"),
                "{bad}"
            );
        }
        for body in [
            json!({"install_id": id, "with_keys": true}),
            json!({"install_id": id, "entries": ["kek"]}),
        ] {
            assert_eq!(field::<ForgetInstallArgs>(body), Some(FIELD_PAYLOAD));
        }
        for body in [
            json!({"path": "/tmp/anchors"}),
            json!({"passphrase": "x"}),
            json!({"dir": null}),
        ] {
            assert_eq!(field::<AnchorDirSetArgs>(body.clone()), Some(FIELD_PAYLOAD));
            assert_eq!(
                field::<AnchorDirRemoveArgs>(body.clone()),
                Some(FIELD_PAYLOAD)
            );
            assert_eq!(field::<ReAnchorArgs>(body.clone()), Some(FIELD_PAYLOAD));
            assert_eq!(
                field::<OrphanInstallsArgs>(body.clone()),
                Some(FIELD_PAYLOAD)
            );
            assert_eq!(
                field::<RecoveryPassphraseChangeArgs>(body),
                Some(FIELD_PAYLOAD)
            );
        }
        assert_eq!(
            parse::<AnchorDirSetArgs>(&json!({})),
            Ok(AnchorDirSetArgs {})
        );
        assert_eq!(parse::<ReAnchorArgs>(&json!({})), Ok(ReAnchorArgs {}));
    }

    /// T13 review I-4: a failed `Core::after_restore` is never answered as a plain success: the
    /// answer names it (`after_restore_failed`); a follow-up that ran does not.
    #[test]
    fn restore_done_names_a_failed_follow_up() {
        let report = atlas_duck_audit::RestoreReport {
            restore_seq: 12,
            new_chain_id: "chain".into(),
            source_install_id: String::new(),
            source_chain_id: "source".into(),
            replaced_db: None,
            records_lost: 0,
            pats_lost: true,
            pats_deleted: vec!["inst-1".into()],
            confirmation_seq: Some(13),
        };
        let done = restore_done(&report, Ok(()));
        assert!(!done.after_restore_failed);
        assert_eq!(done.tokens_deleted, 1);
        let failed = restore_done(&report, Err(atlas_duck_audit::AuditError::Closed));
        assert!(failed.after_restore_failed);
        assert_eq!(
            RestoreDoneDto {
                after_restore_failed: false,
                ..failed
            },
            done
        );
    }
}
