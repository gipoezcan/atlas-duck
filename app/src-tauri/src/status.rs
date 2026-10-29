//! The status-line model (PD-90, §5.6): the lines the tray tooltip, the header banner and
//! `app_status` show. [`lines`] is pure over [`StatusInputs`]; [`gather`] fills the inputs from the
//! serving state. Every text is app-generated: the inputs hold counts, flags, instance aliases
//! (app configuration) and core-built texts, never a string an agent or a request supplied, so no
//! line can carry one (§5.6 "Toast, tray and header-banner text is app-generated only").

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::sync::Arc;

use atlas_duck_core::reconcile::LINE_CHECK_TARGET;
use atlas_duck_core::{ConfigBanner, Core, GateState, RunPolicy, StoreHealthView};
use atlas_duck_preview::invisible::escape_for_display;
use tauri::{AppHandle, Manager, Runtime};

use crate::commands::dto::{StatusLevel, StatusLineDto};
use crate::i18n::{Lang, T, count};
use crate::sandbox_probe::{SCRIPTS_DEGRADED, scripts_state};
use crate::state::{AppState, ServeSlot};

/// Every line id in the order [`lines`] emits them (PD-90).
pub const IDS: [&str; 20] = [
    "locked_refused",
    "setup_refused",
    "waiting_keyring",
    "updated_restart",
    "scripts_degraded",
    "store_newer",
    "needs_attention",
    "token_expiry",
    "storage_low",
    "anchor_write_failing",
    "anchor_dir_write_failing",
    "anchor_dir_lines_pending",
    "anchors_missing",
    "integrity_incident",
    "prune_backlog",
    LINE_CHECK_TARGET,
    "config_read_only",
    "config_unreadable",
    "ipc_not_accepting",
    "keychain_prompt",
];

/// §8.7 (verbatim).
pub const TEXT_WAITING_KEYRING: T = T::new("Waiting for keyring", "Warte auf den Schlüsselbund");
/// §12.2 (verbatim); the trigger is the script glue's identity check (`StatusInputs::update_pending`,
/// PD-133).
pub const TEXT_UPDATED_RESTART: T = T::new(
    "Updated — restart to apply",
    "Aktualisiert — zum Übernehmen neu starten",
);
/// plan text (PD-141, M8 Task 21): `scripts_degraded`, a caution while the sandbox floor is not met
/// and the user allowed degraded confinement, so scripts do run.
pub const TEXT_SCRIPTS_DEGRADED: T = T::new(
    "scripts run with degraded confinement",
    "Skripte laufen mit eingeschränkter Isolierung",
);
/// plan text (PD-90): `ipc_not_accepting` (M4 T19 bind failure).
pub const TEXT_IPC_NOT_ACCEPTING: T = T::new(
    "not accepting agent requests; see doctor",
    "Nimmt keine Anfragen von Agenten an; siehe doctor",
);
/// plan text (PD-90, L78): `keychain_prompt`.
pub const TEXT_KEYCHAIN_PROMPT: T = T::new(
    "waiting for keychain authorization",
    "Warte auf die Autorisierung im Schlüsselbund",
);
/// plan text (PD-90): `storage_low`, after §8.1 "new agent requests are refused".
pub const TEXT_STORAGE_LOW: T = T::new(
    "audit storage is low: new requests are refused",
    "Der Speicher für das Audit-Protokoll wird knapp: Neue Anfragen werden abgewiesen",
);
/// plan text (PD-90): `anchor_write_failing`, after §8.5/§8.8/§8.11 (retried, never an incident).
pub const TEXT_ANCHOR_WRITE_FAILING: T = T::new(
    "audit anchor could not be written; retrying",
    "Der Audit-Anker konnte nicht geschrieben werden; neuer Versuch folgt",
);
/// plan text (PD-90): `integrity_incident`, the §8.7 banner; the PD-82 wording.
pub const TEXT_INTEGRITY_INCIDENT: T = T::new(
    "integrity incident: see Audit",
    "Integritätsvorfall: siehe Audit-Protokoll",
);
/// plan text (PD-90): `store_newer`, generic on purpose: the gate keeps no writer version, so the
/// text cannot name one (§8.13 words it "audit data was written by atlas-duck vX; install vX or
/// newer"; naming the version needs the gate to keep it).
pub const TEXT_STORE_NEWER: T = T::new(
    "audit data was written by a newer atlas-duck; install that version or newer",
    "Die Audit-Daten wurden von einem neueren atlas-duck geschrieben; installieren Sie diese oder eine neuere Version",
);
/// §8.7 (the fallback of an unknown `anchors_missing` name).
pub const TEXT_ANCHOR_MISSING: T = T::new(
    "An anchor entry is missing from the keychain.",
    "Ein Anker-Eintrag fehlt im Schlüsselbund.",
);
/// T21b, PD-170: the `anchors_missing` texts by the view's wire name, the Settings wording.
pub const TEXT_ANCHORS_MISSING_HEAD: T = T::new(
    "The head anchor entry is missing from the keychain.",
    "Der Kopf-Anker-Eintrag fehlt im Schlüsselbund.",
);
pub const TEXT_ANCHORS_MISSING_FIRST: T = T::new(
    "The first-retained anchor entry is missing from the keychain.",
    "Der Eintrag des ersten aufbewahrten Ankers fehlt im Schlüsselbund.",
);
pub const TEXT_ANCHORS_MISSING_BOTH: T = T::new(
    "The head anchor and the first-retained anchor entries are missing from the keychain.",
    "Die Einträge des Kopf-Ankers und des ersten aufbewahrten Ankers fehlen im Schlüsselbund.",
);

/// The texts of this module, for [`crate::i18n::all`].
pub const TEXTS: &[&T] = &[
    &TEXT_WAITING_KEYRING,
    &TEXT_UPDATED_RESTART,
    &TEXT_SCRIPTS_DEGRADED,
    &TEXT_IPC_NOT_ACCEPTING,
    &TEXT_KEYCHAIN_PROMPT,
    &TEXT_STORAGE_LOW,
    &TEXT_ANCHOR_WRITE_FAILING,
    &TEXT_INTEGRITY_INCIDENT,
    &TEXT_STORE_NEWER,
    &TEXT_ANCHOR_MISSING,
    &TEXT_ANCHORS_MISSING_HEAD,
    &TEXT_ANCHORS_MISSING_FIRST,
    &TEXT_ANCHORS_MISSING_BOTH,
];
/// One instance whose token expiry is within the PD-84 warning window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenExpiry {
    /// The instance alias: app configuration, never agent text.
    pub alias: String,
    /// Days from the local date to `expires_at`: `0` today, negative once expired.
    pub days_left: i64,
    /// `YYYY-MM-DD`.
    pub expires_at: String,
}

/// What the lines are computed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusInputs {
    /// The gate serving now; `None` while `Core` serves or before anything does.
    pub gate: Option<GateState>,
    /// The gate's refused-request count (§2.5).
    pub refused: u64,
    /// The keychain retry schedule is running (§8.7).
    pub keychain_retrying: bool,
    /// The store health, while `Core` serves.
    pub health: Option<StoreHealthView>,
    /// The §7.7 banner of a `config.toml` this binary does not write.
    pub config_banner: Option<ConfigBanner>,
    /// Unacknowledged "Needs attention" requests (§5.6).
    pub needs_attention: u64,
    /// Tokens inside the PD-84 warning window.
    pub expiries: Vec<TokenExpiry>,
    /// Writes the crash reconciliation of this start closed as `outcome_unknown` (§11.3).
    pub startup_notice: u64,
    /// The IPC endpoint is bound and served (M4 T19).
    pub ipc_accepting: bool,
    /// `open` has waited on a keychain authorization prompt past 10 s (L78): `serve` sets the
    /// flag the `ServeSlot` holds while a first or retried `open` blocks that long.
    pub keychain_prompt: bool,
    /// The installed app was replaced under the running one (§12.2): the script glue found the
    /// sandbox binary changed since the probe (PD-133); `AppState` holds the flag.
    pub update_pending: bool,
    /// Scripts run with degraded confinement (PD-141): the startup probe did not meet the floor and
    /// the user allowed degraded confinement. Needs the core (the setting), so only [`gather`]
    /// fills it; false means nothing is degraded or it is not known.
    pub scripts_degraded: bool,
    /// M15 T10: the language the lines are written in (`AppState`'s; English without one).
    pub lang: Lang,
}

impl Default for StatusInputs {
    /// Nothing to report.
    fn default() -> Self {
        StatusInputs {
            gate: None,
            refused: 0,
            keychain_retrying: false,
            health: None,
            config_banner: None,
            needs_attention: 0,
            expiries: Vec::new(),
            startup_notice: 0,
            ipc_accepting: true,
            keychain_prompt: false,
            update_pending: false,
            scripts_degraded: false,
            lang: Lang::En,
        }
    }
}

fn line(id: &'static str, level: StatusLevel, text: String) -> StatusLineDto {
    StatusLineDto { id, text, level }
}

/// A `YYYY-MM-DD` date as the language writes it (German `DD.MM.YYYY`); anything else unchanged.
fn shown_date(lang: Lang, iso: &str) -> String {
    let parts: Vec<&str> = iso.split('-').collect();
    match (lang, parts.as_slice()) {
        (Lang::De, [y, m, d])
            if y.len() == 4
                && m.len() == 2
                && d.len() == 2
                && iso.bytes().all(|b| b.is_ascii_digit() || b == b'-') =>
        {
            format!("{d}.{m}.{y}")
        }
        _ => iso.to_owned(),
    }
}

/// plan text (PD-84): the token lines.
fn expiry_text(lang: Lang, e: &TokenExpiry) -> String {
    let alias = escape_for_display(&e.alias);
    let date = escape_for_display(&shown_date(lang, &e.expires_at));
    match (lang, e.days_left) {
        (Lang::En, d) if d < 0 => format!("token for {alias} expired on {date}"),
        (Lang::En, 0) => format!("token for {alias} expires today"),
        (Lang::En, 1) => format!("token for {alias} expires in 1 day"),
        (Lang::En, d) => format!("token for {alias} expires in {d} days"),
        (Lang::De, d) if d < 0 => format!("Token für {alias} ist am {date} abgelaufen"),
        (Lang::De, 0) => format!("Token für {alias} läuft heute ab"),
        (Lang::De, 1) => format!("Token für {alias} läuft in 1 Tag ab"),
        (Lang::De, d) => format!("Token für {alias} läuft in {d} Tagen ab"),
    }
}

/// Plan text (written by the plan, not the spec): the startup "check target" notice, with the
/// spec's §4/§11 wording "check the target before retrying".
fn check_target_text(lang: Lang, n: u64) -> String {
    match (lang, n) {
        (Lang::En, 1) => "1 write has an unknown outcome: check its target before retrying".to_owned(),
        (Lang::En, n) => {
            format!("{n} writes have an unknown outcome: check their targets before retrying")
        }
        (Lang::De, 1) => "1 Schreibvorgang hat ein unbekanntes Ergebnis: Prüfen Sie sein Ziel, bevor Sie ihn wiederholen".to_owned(),
        (Lang::De, n) => format!(
            "{} Schreibvorgänge haben ein unbekanntes Ergebnis: Prüfen Sie ihre Ziele, bevor Sie sie wiederholen",
            count(lang, n)
        ),
    }
}

/// T21b, §8.5 (a failing anchor-directory append is shown in Settings and the tray, never as an
/// incident): `anchor_dir_write_failing`. The wording is the Settings window's
/// (`audit.anchor_dir_failing` in the UI dictionary).
fn anchor_dir_failing_text(lang: Lang, pending: u32) -> String {
    let one = pending == 1;
    match lang {
        Lang::En => format!(
            "Writing to the anchor directory fails; {pending} {} and will be retried.",
            if one { "line waits" } else { "lines wait" }
        ),
        Lang::De => format!(
            "Das Schreiben in das Anker-Verzeichnis schlägt fehl; {} {} und {} erneut versucht.",
            count(lang, u64::from(pending)),
            if one { "Zeile wartet" } else { "Zeilen warten" },
            if one { "wird" } else { "werden" }
        ),
    }
}

/// T21b, PD-156: `anchor_dir_lines_pending`, the Settings wording (`anchor_dir_pending`).
fn anchor_dir_pending_text(lang: Lang, pending: u32) -> String {
    let one = pending == 1;
    match lang {
        Lang::En => format!(
            "{pending} {} to be written to the anchor directory.",
            if one { "line waits" } else { "lines wait" }
        ),
        Lang::De => format!(
            "{} {} darauf, in das Anker-Verzeichnis geschrieben zu werden.",
            count(lang, u64::from(pending)),
            if one { "Zeile wartet" } else { "Zeilen warten" }
        ),
    }
}

/// T21b, PD-170: `anchors_missing`, the Settings wording (`anchors_missing`) by the view's wire
/// name (`head`, `first_retained`, `both`).
fn anchors_missing_text(lang: Lang, missing: &str) -> &'static str {
    match missing {
        "head" => TEXT_ANCHORS_MISSING_HEAD.get(lang),
        "first_retained" => TEXT_ANCHORS_MISSING_FIRST.get(lang),
        "both" => TEXT_ANCHORS_MISSING_BOTH.get(lang),
        _ => TEXT_ANCHOR_MISSING.get(lang),
    }
}

/// §8.8 "pruning is N days behind": core's own text in English; German by the day count.
fn prune_backlog_text(lang: Lang, core_text: &str, days: u32) -> String {
    match (lang, days) {
        (Lang::En, _) => core_text.to_owned(),
        (Lang::De, 1) => "Die Bereinigung ist 1 Tag im Rückstand".to_owned(),
        (Lang::De, d) => format!(
            "Die Bereinigung ist {} Tage im Rückstand",
            count(lang, u64::from(d))
        ),
    }
}

/// "Locked — N requests refused" / "Setup required — N requests refused" (§2.5 verbatim in
/// English, "1 requests" for one, L128); German with its plural.
fn refused_text(lang: Lang, setup: bool, n: u64) -> String {
    match lang {
        Lang::En => format!(
            "{} — {n} requests refused",
            if setup { "Setup required" } else { "Locked" }
        ),
        Lang::De => format!(
            "{} — {} {} abgewiesen",
            if setup {
                "Einrichtung erforderlich"
            } else {
                "Gesperrt"
            },
            count(lang, n),
            if n == 1 { "Anfrage" } else { "Anfragen" }
        ),
    }
}

/// PD-90 `needs_attention`, plan text (L114).
fn needs_attention_text(lang: Lang, n: u64) -> String {
    match (lang, n) {
        (Lang::En, n) => format!("{n} need attention"),
        (Lang::De, 1) => "1 braucht Aufmerksamkeit".to_owned(),
        (Lang::De, n) => format!("{} brauchen Aufmerksamkeit", count(lang, n)),
    }
}

/// §7.7: the config banner. English is core's own text; German is built from the banner's facts
/// (`version` and `parsed`, M15 T10).
pub fn config_banner_text(lang: Lang, b: &ConfigBanner) -> String {
    if lang == Lang::En {
        return b.text.clone();
    }
    let by = b.version.as_deref().map_or_else(
        || "einer neueren atlas-duck-Version".to_owned(),
        |v| format!("atlas-duck {v}"),
    );
    match (b.kind, b.parsed) {
        ("unreadable", false) => {
            "Die Konfiguration konnte nicht gelesen werden; die Einstellungen sind nicht verfügbar, bis sie lesbar ist".to_owned()
        }
        ("unreadable", true) => format!(
            "Die Konfiguration von {by} konnte nicht gelesen werden; aktualisieren Sie atlas-duck"
        ),
        _ => format!(
            "Die Konfiguration wurde von {by} geschrieben; die Einstellungen sind schreibgeschützt, bis Sie aktualisieren"
        ),
    }
}
/// The status lines, in the order of [`IDS`] (a token line per instance). One input gives one line;
/// nothing here reads a request.
pub fn lines(i: &StatusInputs) -> Vec<StatusLineDto> {
    use StatusLevel::{Caution, Info};
    let lang = i.lang;
    let mut out = Vec::new();
    match i.gate {
        // PD-90 `locked_refused`; §2.5 verbatim "Locked — N requests refused" (app-generated; the
        // count is the current gate state's only, L74; "1 requests" for one, L128).
        Some(GateState::Locked(_)) => out.push(line(
            "locked_refused",
            Caution,
            refused_text(lang, false, i.refused),
        )),
        // PD-90 `setup_refused`; §2.5 verbatim "Setup required — N requests refused" (spec fix G1,
        // L46; app-generated, the current gate state's count only, L74).
        Some(GateState::FirstRun) => out.push(line(
            "setup_refused",
            Caution,
            refused_text(lang, true, i.refused),
        )),
        _ => {}
    }
    if matches!(
        i.gate,
        Some(GateState::Locked(
            atlas_duck_audit::LockedReason::KeychainUnavailable
        ))
    ) && i.keychain_retrying
    {
        out.push(line(
            "waiting_keyring",
            Caution,
            TEXT_WAITING_KEYRING.get(lang).to_owned(),
        ));
    }
    if i.update_pending {
        out.push(line(
            "updated_restart",
            Info,
            TEXT_UPDATED_RESTART.get(lang).to_owned(),
        ));
    }
    if i.scripts_degraded {
        out.push(line(
            "scripts_degraded",
            Caution,
            TEXT_SCRIPTS_DEGRADED.get(lang).to_owned(),
        ));
    }
    if i.gate == Some(GateState::StoreNewer) {
        out.push(line(
            "store_newer",
            Caution,
            TEXT_STORE_NEWER.get(lang).to_owned(),
        ));
    }
    // PD-90 `needs_attention`, plan text (L114): "N need attention" is in no spec sentence.
    if i.needs_attention > 0 {
        out.push(line(
            "needs_attention",
            Caution,
            needs_attention_text(lang, i.needs_attention),
        ));
    }
    for e in &i.expiries {
        let level = if e.days_left <= 7 { Caution } else { Info };
        out.push(line("token_expiry", level, expiry_text(lang, e)));
    }
    if let Some(h) = &i.health {
        if h.storage_low {
            out.push(line(
                "storage_low",
                Caution,
                TEXT_STORAGE_LOW.get(lang).to_owned(),
            ));
        }
        if h.anchor_write_failing || h.anchor_thread_dead {
            out.push(line(
                "anchor_write_failing",
                Caution,
                TEXT_ANCHOR_WRITE_FAILING.get(lang).to_owned(),
            ));
        }
        // T21b: the same `StoreHealthView` Settings reads. The failing line's text carries the
        // pending count, so the pending line shows only while nothing is failing (as in Settings).
        if h.anchor_dir_write_failing {
            out.push(line(
                "anchor_dir_write_failing",
                Caution,
                anchor_dir_failing_text(lang, h.anchor_dir_lines_pending),
            ));
        } else if h.anchor_dir_lines_pending > 0 {
            out.push(line(
                "anchor_dir_lines_pending",
                Caution,
                anchor_dir_pending_text(lang, h.anchor_dir_lines_pending),
            ));
        }
        if let Some(missing) = h.anchors_missing {
            out.push(line(
                "anchors_missing",
                Caution,
                anchors_missing_text(lang, missing).to_owned(),
            ));
        }
        if h.open_incidents > 0 {
            out.push(line(
                "integrity_incident",
                Caution,
                TEXT_INTEGRITY_INCIDENT.get(lang).to_owned(),
            ));
        }
        if let Some(text) = &h.prune_backlog {
            out.push(line(
                "prune_backlog",
                Caution,
                prune_backlog_text(lang, text, h.prune_backlog_days),
            ));
        }
    }
    if i.startup_notice > 0 {
        out.push(line(
            LINE_CHECK_TARGET,
            Caution,
            check_target_text(lang, i.startup_notice),
        ));
    }
    if let Some(b) = &i.config_banner {
        // §7.7 (verbatim, built by core): a newer file keeps requests working (info), one that
        // cannot be read leaves the app with no instances from it (caution).
        let (id, level) = match b.kind {
            "unreadable" => ("config_unreadable", Caution),
            _ => ("config_read_only", Info),
        };
        out.push(line(id, level, config_banner_text(lang, b)));
    }
    if !i.ipc_accepting {
        out.push(line(
            "ipc_not_accepting",
            Caution,
            TEXT_IPC_NOT_ACCEPTING.get(lang).to_owned(),
        ));
    }
    if i.keychain_prompt {
        out.push(line(
            "keychain_prompt",
            Info,
            TEXT_KEYCHAIN_PROMPT.get(lang).to_owned(),
        ));
    }
    out
}

/// The inputs from the serving state. Synchronous core calls (`view`, `list`, the queue): call it
/// on the blocking pool (M3 PD-13). Without a serving state (before first run, starting, quitting)
/// there is nothing to report.
pub fn gather<R: Runtime>(app: &AppHandle<R>) -> StatusInputs {
    let mut i = gather_gate(app);
    if let Some(core) = serving_core(app) {
        gather_core(&mut i, &core);
        // The header's read is the freshest one there is: the tray follows it.
        note_health(app, i.health.clone());
        if let Some(state) = app.try_state::<AppState>() {
            // Reads the core's settings view: [`gather`] runs on the blocking pool.
            gather_scripts(&mut i, &state, core.script_policy());
        }
    } else {
        // No serving core (locked, starting, quitting): there is no health to show, and the
        // snapshot of an earlier core is not it.
        i.health = None;
        note_health(app, None);
    }
    i
}

/// Records the store health the app just read from the core (`None`: no core serves) in the
/// snapshot the tray shows ([`AppState::health`]). When it differs from the one before, the tray
/// rebuilds (menu and tooltip); true then. Takes the view the caller already holds: nothing here
/// reads the store.
pub fn note_health<R: Runtime>(app: &AppHandle<R>, health: Option<StoreHealthView>) -> bool {
    let Some(state) = app.try_state::<AppState>() else {
        return false;
    };
    let changed = state.set_health(health);
    if changed {
        state.refresh_tray();
    }
    changed
}

/// The serving `Core`, if there is one and the app is not quitting.
fn serving_core<R: Runtime>(app: &AppHandle<R>) -> Option<Arc<Core>> {
    app.try_state::<ServeSlot>().and_then(|slot| {
        if slot.quit().0.is_cancelled() {
            return None;
        }
        slot.get().and_then(|s| s.core.get().cloned())
    })
}

/// Reads the store health from the serving core (`None` when none serves) into the tray's
/// snapshot ([`note_health`]). Synchronous core call: the blocking pool.
pub fn refresh_health<R: Runtime>(app: &AppHandle<R>) {
    let health = serving_core(app).map(|core| core.settings().view().health);
    note_health(app, health);
}

/// How often the app re-reads the store health for the tray while it runs.
pub const HEALTH_TICK: std::time::Duration = std::time::Duration::from_secs(30);

/// Nothing in a window tells the tray the store's health changed (an anchor write that starts
/// failing, storage running low), so this re-reads it at once and then every `period` on the
/// blocking pool, until the quit signal. The tray thread never waits on the store: it only reads the snapshot.
pub fn spawn_health_ticker<R: Runtime>(
    app: AppHandle<R>,
    period: std::time::Duration,
) -> tauri::async_runtime::JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
        let Some(quit) = app.try_state::<ServeSlot>().map(|s| s.quit().0.clone()) else {
            return;
        };
        // A first read at once (serving just started), then one per period.
        loop {
            let tick = app.clone();
            let _ = tauri::async_runtime::spawn_blocking(move || refresh_health(&tick)).await;
            tokio::select! {
                () = quit.cancelled() => return,
                () = tokio::time::sleep(period) => {}
            }
        }
    })
}

/// The part of [`gather_gate`] that reads `AppState`: the flag the script glue sets when it finds
/// the sandbox binary replaced since the probe (PD-133, `updated_restart`). A flag, no core.
pub fn gather_app_state(i: &mut StatusInputs, state: &AppState) {
    i.lang = state.lang();
    i.update_pending = state.update_pending();
    // T36b: the tray's store-health lines come from the snapshot [`note_health`] keeps (no core,
    // no store read); [`gather`] replaces it with the core's own read.
    i.health = state.health();
}

/// `scripts_degraded` (PD-141): the startup probe's report is `NotMet` and the run policy allows
/// degraded confinement, the two things the glue admits a degraded run on ([`gather`] passes
/// `Core::script_policy`, the very read the runner takes at each call). No report yet is not
/// degraded: scripts are refused then.
pub fn gather_scripts(i: &mut StatusInputs, state: &AppState, policy: RunPolicy) {
    i.scripts_degraded =
        scripts_state(state.probe_report(), policy.allow_degraded) == SCRIPTS_DEGRADED;
}

/// The half of [`gather`] that reads no `Core`: the gate, its refused count, the retry, the
/// endpoint and the keychain prompt hint. Only flags and counters, so the tray (which rebuilds on
/// the main thread, M6 T22) can call it.
pub fn gather_gate<R: Runtime>(app: &AppHandle<R>) -> StatusInputs {
    let mut i = StatusInputs::default();
    // PD-133: the glue's flag lives in `AppState`, not in the serving state.
    if let Some(state) = app.try_state::<AppState>() {
        gather_app_state(&mut i, &state);
    }
    let Some(slot) = app.try_state::<ServeSlot>() else {
        return i;
    };
    // L78: the first `open` blocks before any serving state exists, so the flag is the slot's.
    i.keychain_prompt = slot.keychain_prompt();
    let Some(state) = slot.get() else {
        return i;
    };
    if slot.quit().0.is_cancelled() {
        return i;
    }
    i.ipc_accepting = state.serving();
    i.gate = state.gate_state();
    i.refused = state.refused().unwrap_or(0);
    i.keychain_retrying = state.keychain_retrying();
    i
}

/// The half of [`gather`] that reads `Core`: no `AppHandle`, so a test can run it against a
/// harness. Only counts, flags, aliases and core-built texts are taken from what it reads.
pub fn gather_core(i: &mut StatusInputs, core: &Core) {
    let view = core.settings().view();
    i.health = Some(view.health);
    i.config_banner = view.config_read_only;
    i.needs_attention = u64::try_from(core.decisions().needs_attention().len()).unwrap_or(u64::MAX);
    i.startup_notice = u64::try_from(core.startup_notice().len()).unwrap_or(u64::MAX);
    i.expiries = core
        .instances()
        .list()
        .into_iter()
        .filter(|v| v.expiry_warning.is_some())
        .filter_map(|v| {
            Some(TokenExpiry {
                alias: v.alias,
                days_left: v.days_left?,
                expires_at: v.expires_at?,
            })
        })
        .collect();
}

#[cfg(test)]
mod tests {
    use atlas_duck_audit::LockedReason;

    use super::*;

    fn health() -> StoreHealthView {
        StoreHealthView {
            storage_low: false,
            anchor_write_failing: false,
            anchor_thread_dead: false,
            anchors_blocked: false,
            open_incidents: 0,
            prune_backlog_days: 0,
            prune_backlog: None,
            last_prune_failed: false,
            shred_checkpoint_pending: false,
            settings_unreadable: false,
            anchor_dir_write_failing: false,
            anchor_dir_lines_pending: 0,
            anchors_missing: None,
            re_anchor_offered: false,
        }
    }

    fn banner(kind: &'static str, text: &str) -> Option<ConfigBanner> {
        Some(ConfigBanner {
            kind,
            text: text.to_owned(),
            version: Some("v9.9.0".into()),
            parsed: true,
        })
    }

    fn expiry(alias: &str, days_left: i64) -> TokenExpiry {
        TokenExpiry {
            alias: alias.to_owned(),
            days_left,
            expires_at: "2026-11-01".to_owned(),
        }
    }

    fn only(i: StatusInputs) -> Vec<(&'static str, String, StatusLevel)> {
        lines(&i)
            .into_iter()
            .map(|l| (l.id, l.text, l.level))
            .collect()
    }

    /// One input, one line, every PD-90 id, every text verbatim.
    #[test]
    fn status_lines_table() {
        use StatusLevel::{Caution, Info};
        let locked = Some(GateState::Locked(LockedReason::KeychainUnavailable));
        type Row = (&'static str, &'static str, StatusLevel);
        let table: Vec<(StatusInputs, Vec<Row>)> = vec![
            (
                StatusInputs {
                    gate: locked,
                    refused: 3,
                    ..StatusInputs::default()
                },
                vec![("locked_refused", "Locked — 3 requests refused", Caution)],
            ),
            (
                StatusInputs {
                    gate: Some(GateState::FirstRun),
                    refused: 2,
                    ..StatusInputs::default()
                },
                vec![(
                    "setup_refused",
                    "Setup required — 2 requests refused",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    gate: locked,
                    keychain_retrying: true,
                    ..StatusInputs::default()
                },
                vec![
                    ("locked_refused", "Locked — 0 requests refused", Caution),
                    ("waiting_keyring", "Waiting for keyring", Caution),
                ],
            ),
            (
                StatusInputs {
                    update_pending: true,
                    ..StatusInputs::default()
                },
                vec![("updated_restart", "Updated — restart to apply", Info)],
            ),
            (
                StatusInputs {
                    scripts_degraded: true,
                    ..StatusInputs::default()
                },
                vec![(
                    "scripts_degraded",
                    "scripts run with degraded confinement",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    gate: Some(GateState::StoreNewer),
                    ..StatusInputs::default()
                },
                vec![("store_newer", TEXT_STORE_NEWER.en, Caution)],
            ),
            (
                StatusInputs {
                    needs_attention: 4,
                    ..StatusInputs::default()
                },
                vec![("needs_attention", "4 need attention", Caution)],
            ),
            (
                StatusInputs {
                    expiries: vec![
                        expiry("work", 14),
                        expiry("work", 7),
                        expiry("docs", 1),
                        expiry("docs", 0),
                        expiry("old", -3),
                    ],
                    ..StatusInputs::default()
                },
                vec![
                    ("token_expiry", "token for work expires in 14 days", Info),
                    ("token_expiry", "token for work expires in 7 days", Caution),
                    ("token_expiry", "token for docs expires in 1 day", Caution),
                    ("token_expiry", "token for docs expires today", Caution),
                    (
                        "token_expiry",
                        "token for old expired on 2026-11-01",
                        Caution,
                    ),
                ],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        storage_low: true,
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![("storage_low", TEXT_STORAGE_LOW.en, Caution)],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        anchor_write_failing: true,
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![(
                    "anchor_write_failing",
                    TEXT_ANCHOR_WRITE_FAILING.en,
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        anchor_thread_dead: true,
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![(
                    "anchor_write_failing",
                    TEXT_ANCHOR_WRITE_FAILING.en,
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        anchor_dir_write_failing: true,
                        anchor_dir_lines_pending: 3,
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![(
                    "anchor_dir_write_failing",
                    "Writing to the anchor directory fails; 3 lines wait and will be retried.",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        anchor_dir_write_failing: true,
                        anchor_dir_lines_pending: 1,
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![(
                    "anchor_dir_write_failing",
                    "Writing to the anchor directory fails; 1 line waits and will be retried.",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        anchor_dir_lines_pending: 1,
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![(
                    "anchor_dir_lines_pending",
                    "1 line waits to be written to the anchor directory.",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        anchor_dir_lines_pending: 12,
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![(
                    "anchor_dir_lines_pending",
                    "12 lines wait to be written to the anchor directory.",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        anchors_missing: Some("head"),
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![(
                    "anchors_missing",
                    "The head anchor entry is missing from the keychain.",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        anchors_missing: Some("first_retained"),
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![(
                    "anchors_missing",
                    "The first-retained anchor entry is missing from the keychain.",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        anchors_missing: Some("both"),
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![(
                    "anchors_missing",
                    "The head anchor and the first-retained anchor entries are missing from the keychain.",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        open_incidents: 2,
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![(
                    "integrity_incident",
                    "integrity incident: see Audit",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        prune_backlog_days: 9,
                        prune_backlog: Some("pruning is 9 days behind".to_owned()),
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![("prune_backlog", "pruning is 9 days behind", Caution)],
            ),
            (
                StatusInputs {
                    startup_notice: 1,
                    ..StatusInputs::default()
                },
                vec![(
                    "check_target",
                    "1 write has an unknown outcome: check its target before retrying",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    startup_notice: 2,
                    ..StatusInputs::default()
                },
                vec![(
                    "check_target",
                    "2 writes have an unknown outcome: check their targets before retrying",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    config_banner: banner(
                        "read_only",
                        "config written by v9; settings read-only until you upgrade",
                    ),
                    ..StatusInputs::default()
                },
                vec![(
                    "config_read_only",
                    "config written by v9; settings read-only until you upgrade",
                    Info,
                )],
            ),
            (
                StatusInputs {
                    config_banner: banner(
                        "unreadable",
                        "config written by v9 could not be read; upgrade atlas-duck",
                    ),
                    ..StatusInputs::default()
                },
                vec![(
                    "config_unreadable",
                    "config written by v9 could not be read; upgrade atlas-duck",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    ipc_accepting: false,
                    ..StatusInputs::default()
                },
                vec![(
                    "ipc_not_accepting",
                    "not accepting agent requests; see doctor",
                    Caution,
                )],
            ),
            (
                StatusInputs {
                    keychain_prompt: true,
                    ..StatusInputs::default()
                },
                vec![(
                    "keychain_prompt",
                    "waiting for keychain authorization",
                    Info,
                )],
            ),
            (StatusInputs::default(), vec![]),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (inputs, expected) in table {
            let got = only(inputs.clone());
            let want: Vec<(&str, String, StatusLevel)> = expected
                .into_iter()
                .map(|(id, text, level)| (id, text.to_owned(), level))
                .collect();
            assert_eq!(got, want, "{inputs:?}");
            seen.extend(got.iter().map(|(id, _, _)| *id));
        }
        assert_eq!(
            seen.into_iter().collect::<Vec<_>>(),
            {
                let mut ids = IDS.to_vec();
                ids.sort_unstable();
                ids
            },
            "every PD-90 id has a row"
        );
    }

    /// Without the retry schedule running, or for another locked reason, there is no "Waiting for
    /// keyring" (§8.7: only while the keychain is being retried); a Ready core has no gate line.
    #[test]
    fn waiting_keyring_needs_the_retry_and_the_unavailable_reason() {
        let ids = |i: StatusInputs| only(i).into_iter().map(|l| l.0).collect::<Vec<_>>();
        assert_eq!(
            ids(StatusInputs {
                gate: Some(GateState::Locked(LockedReason::KeychainUnavailable)),
                keychain_retrying: false,
                ..StatusInputs::default()
            }),
            ["locked_refused"]
        );
        assert_eq!(
            ids(StatusInputs {
                gate: Some(GateState::Locked(LockedReason::KeyringNotLocal)),
                keychain_retrying: true,
                ..StatusInputs::default()
            }),
            ["locked_refused"]
        );
        assert!(
            ids(StatusInputs {
                gate: Some(GateState::ShuttingDown),
                ..StatusInputs::default()
            })
            .is_empty()
        );
    }

    /// M15 T10: the lines keep their ids, levels and order in German; only the text changes.
    #[test]
    fn status_lines_keep_ids_across_languages() {
        let mut i = StatusInputs {
            gate: Some(GateState::Locked(LockedReason::KeychainUnavailable)),
            refused: 1234,
            keychain_retrying: true,
            health: Some(StoreHealthView {
                storage_low: true,
                anchor_write_failing: true,
                anchor_dir_write_failing: true,
                anchor_dir_lines_pending: 1,
                anchors_missing: Some("both"),
                open_incidents: 1,
                prune_backlog_days: 12,
                prune_backlog: Some("pruning is 12 days behind".into()),
                ..health()
            }),
            config_banner: banner(
                "read_only",
                "config written by v9.9.0; settings read-only until you upgrade",
            ),
            needs_attention: 1,
            expiries: vec![expiry("a", 2), expiry("b", -1)],
            startup_notice: 2,
            ipc_accepting: false,
            keychain_prompt: true,
            update_pending: true,
            scripts_degraded: true,
            lang: Lang::En,
        };
        let en = lines(&i);
        i.lang = Lang::De;
        let de = lines(&i);
        let shape = |v: &[StatusLineDto]| v.iter().map(|l| (l.id, l.level)).collect::<Vec<_>>();
        assert_eq!(shape(&en), shape(&de));
        for (a, b) in en.iter().zip(&de) {
            assert_ne!(a.text, b.text, "{}", a.id);
        }
        let text = |id: &str| {
            de.iter()
                .find(|l| l.id == id)
                .map(|l| l.text.clone())
                .unwrap_or_default()
        };
        assert_eq!(
            text("locked_refused"),
            "Gesperrt — 1.234 Anfragen abgewiesen"
        );
        assert_eq!(text("needs_attention"), "1 braucht Aufmerksamkeit");
        assert_eq!(
            text("prune_backlog"),
            "Die Bereinigung ist 12 Tage im Rückstand"
        );
        assert_eq!(
            text("anchor_dir_write_failing"),
            "Das Schreiben in das Anker-Verzeichnis schlägt fehl; 1 Zeile wartet und wird erneut versucht."
        );
        assert_eq!(
            text(LINE_CHECK_TARGET),
            "2 Schreibvorgänge haben ein unbekanntes Ergebnis: Prüfen Sie ihre Ziele, bevor Sie sie wiederholen"
        );
        assert_eq!(
            text("config_read_only"),
            "Die Konfiguration wurde von atlas-duck v9.9.0 geschrieben; die Einstellungen sind schreibgeschützt, bis Sie aktualisieren"
        );
        let tokens: Vec<String> = de
            .iter()
            .filter(|l| l.id == "token_expiry")
            .map(|l| l.text.clone())
            .collect();
        assert_eq!(tokens.len(), 2);
        assert!(tokens[0].ends_with("läuft in 2 Tagen ab"), "{tokens:?}");
        assert!(tokens[1].contains("abgelaufen"), "{tokens:?}");
        // The setup gate's plural.
        i.gate = Some(GateState::FirstRun);
        i.refused = 1;
        assert_eq!(
            lines(&i)[0].text,
            "Einrichtung erforderlich — 1 Anfrage abgewiesen"
        );
    }
    /// Order follows [`IDS`] whatever mix is set.
    #[test]
    fn lines_follow_the_id_order() {
        let all = StatusInputs {
            gate: Some(GateState::Locked(LockedReason::KeychainUnavailable)),
            refused: 1,
            keychain_retrying: true,
            health: Some(StoreHealthView {
                storage_low: true,
                anchor_write_failing: true,
                anchor_dir_write_failing: true,
                anchors_missing: Some("both"),
                open_incidents: 1,
                prune_backlog: Some("pruning is 1 days behind".into()),
                ..health()
            }),
            config_banner: banner("read_only", "config written by v9; x"),
            needs_attention: 1,
            expiries: vec![expiry("a", 2)],
            startup_notice: 1,
            ipc_accepting: false,
            keychain_prompt: true,
            update_pending: true,
            scripts_degraded: true,
            lang: Lang::En,
        };
        let ids: Vec<&str> = only(all).into_iter().map(|l| l.0).collect();
        let positions: Vec<usize> = ids
            .iter()
            .filter_map(|id| IDS.iter().position(|x| x == id))
            .collect();
        assert_eq!(positions.len(), ids.len());
        assert!(positions.windows(2).all(|w| w[0] <= w[1]), "{ids:?}");
    }

    /// The anchor-directory and keychain-anchor lines come from the same `StoreHealthView` the
    /// Settings window reads, each only while its condition holds (clearing it removes the line),
    /// and the pending line gives way to the failing line (whose text carries the count).
    #[test]
    fn anchor_lines_follow_the_health_view_and_clear() {
        let ids = |h: StoreHealthView| {
            only(StatusInputs {
                health: Some(h),
                ..StatusInputs::default()
            })
            .into_iter()
            .map(|l| l.0)
            .collect::<Vec<_>>()
        };
        assert!(ids(health()).is_empty());
        let failing = StoreHealthView {
            anchor_dir_write_failing: true,
            anchor_dir_lines_pending: 4,
            ..health()
        };
        assert_eq!(ids(failing.clone()), ["anchor_dir_write_failing"]);
        assert!(
            ids(StoreHealthView {
                anchor_dir_write_failing: false,
                anchor_dir_lines_pending: 0,
                ..failing
            })
            .is_empty()
        );
        let pending = StoreHealthView {
            anchor_dir_lines_pending: 2,
            ..health()
        };
        assert_eq!(ids(pending.clone()), ["anchor_dir_lines_pending"]);
        assert!(
            ids(StoreHealthView {
                anchor_dir_lines_pending: 0,
                ..pending
            })
            .is_empty()
        );
        let missing = StoreHealthView {
            anchors_missing: Some("both"),
            ..health()
        };
        assert_eq!(ids(missing.clone()), ["anchors_missing"]);
        assert!(
            ids(StoreHealthView {
                anchors_missing: None,
                ..missing
            })
            .is_empty()
        );
        // The three are independent of each other and of the keychain-side `anchor_write_failing`.
        assert_eq!(
            ids(StoreHealthView {
                anchor_write_failing: true,
                anchor_dir_write_failing: true,
                anchors_missing: Some("head"),
                ..health()
            }),
            [
                "anchor_write_failing",
                "anchor_dir_write_failing",
                "anchors_missing"
            ]
        );
    }

    /// Decision (T21b): the spec gives no order for these, so they sit with the other audit-anchor
    /// health lines, after `anchor_write_failing` and before `integrity_incident`, i.e. below the
    /// credential and locked states and above the informational lines.
    #[test]
    fn the_new_ids_sit_between_the_anchor_line_and_the_incident() {
        let pos = |id: &str| IDS.iter().position(|x| *x == id);
        let a = pos("anchor_write_failing");
        assert!(a.is_some());
        let chain = [
            "anchor_write_failing",
            "anchor_dir_write_failing",
            "anchor_dir_lines_pending",
            "anchors_missing",
            "integrity_incident",
        ];
        let at: Vec<Option<usize>> = chain.iter().map(|id| pos(id)).collect();
        assert!(at.iter().all(Option::is_some), "{at:?}");
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{at:?}");
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A probe report with the given floor and no identity.
    fn bare_report(
        floor: atlas_duck_sandbox_host::probe::FloorVerdict,
    ) -> atlas_duck_sandbox_host::probe::ProbeReport {
        atlas_duck_sandbox_host::probe::ProbeReport {
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
        }
    }

    /// PD-133, §12.2: after the glue found the sandbox binary replaced since the probe, the status
    /// line `updated_restart` is due, through the flag the glue and the state share (not before,
    /// and it stays). The glue is the real one over the state's own script inputs; the binary is a
    /// scratch file the probe's identity was read from, so nothing is spawned.
    #[tokio::test]
    async fn updated_restart_after_identity_mismatch() -> TestResult {
        use atlas_duck_core::ScriptRunner;
        use atlas_duck_sandbox_host::identity::{SandboxBinaryIdentity, file_identity};
        use atlas_duck_sandbox_host::probe::FloorVerdict;

        use std::sync::Arc;

        use crate::script_glue::{HostBridge, ScriptGlue};
        use crate::state::StartupSummary;

        let dir = tempfile::tempdir()?;
        let worker = dir.path().join("atlas-duck-sandbox");
        std::fs::write(&worker, b"worker, first build")?;
        let (file_id, size, mtime) = file_identity(&worker)?;
        let state = AppState::new(StartupSummary::Ready, None);
        assert!(
            state
                .probe
                .set(atlas_duck_sandbox_host::probe::ProbeReport {
                    identity: Some(SandboxBinaryIdentity {
                        file_id,
                        size,
                        mtime,
                        embedded_version: "v1".to_owned(),
                    }),
                    ..bare_report(FloorVerdict::Met)
                })
        );
        let glue = ScriptGlue::with_port(
            Arc::new(HostBridge::default()),
            Some(worker.clone()),
            state.script_inputs(),
        );
        let due = |state: &AppState| {
            let mut i = StatusInputs::default();
            gather_app_state(&mut i, state);
            only(i)
        };
        let bound = std::time::Duration::from_secs(60);

        // The binary is the probe's: scripts are admitted and no line is due.
        assert!(
            tokio::time::timeout(bound, glue.check_available(RunPolicy::default()))
                .await?
                .is_ok()
        );
        assert!(!state.update_pending());
        assert!(due(&state).is_empty());

        // An upgrade replaced the binary: the run is refused and the line is due.
        std::fs::write(&worker, b"worker, the build of an upgrade")?;
        assert!(
            tokio::time::timeout(bound, glue.check_available(RunPolicy::default()))
                .await?
                .is_err()
        );
        assert!(state.update_pending());
        assert_eq!(
            due(&state),
            [(
                "updated_restart",
                "Updated \u{2014} restart to apply".to_owned(),
                StatusLevel::Info
            )]
        );
        // Sticky: refused until restart, the line stays.
        assert!(
            tokio::time::timeout(bound, glue.check_available(RunPolicy::default()))
                .await?
                .is_err()
        );
        assert_eq!(due(&state).len(), 1);
        Ok(())
    }

    /// PD-141: `scripts_degraded` only while the probe's floor is not met AND degraded confinement
    /// is allowed: each alone, a met floor, or no report yet shows nothing.
    #[test]
    fn status_scripts_degraded_line() {
        use atlas_duck_ipc::sandbox::probe::ProbeId;
        use atlas_duck_sandbox_host::probe::FloorVerdict;

        use crate::state::StartupSummary;

        let unmet = || FloorVerdict::NotMet {
            failed: vec![ProbeId::FileInProfile],
        };
        let allowed = RunPolicy {
            allow_degraded: true,
        };
        let refused = RunPolicy {
            allow_degraded: false,
        };
        let ids = |floor: Option<FloorVerdict>, policy: RunPolicy| {
            let state = AppState::new(StartupSummary::Ready, None);
            if let Some(floor) = floor {
                assert!(state.probe.set(bare_report(floor)));
            }
            let mut i = StatusInputs::default();
            gather_scripts(&mut i, &state, policy);
            only(i)
        };
        assert_eq!(
            ids(Some(unmet()), allowed),
            [(
                "scripts_degraded",
                TEXT_SCRIPTS_DEGRADED.en.to_owned(),
                StatusLevel::Caution
            )]
        );
        assert_eq!(
            TEXT_SCRIPTS_DEGRADED.en,
            "scripts run with degraded confinement"
        );
        assert!(ids(Some(unmet()), refused).is_empty());
        assert!(ids(Some(FloorVerdict::Met), allowed).is_empty());
        assert!(ids(Some(FloorVerdict::Met), refused).is_empty());
        assert!(ids(None, allowed).is_empty());
        assert!(ids(None, refused).is_empty());
    }

    /// `update_pending` and `scripts_degraded` are separate lines in id order, and neither needs
    /// the other.
    #[test]
    fn the_script_lines_are_independent_and_ordered() {
        let both = only(StatusInputs {
            update_pending: true,
            scripts_degraded: true,
            ..StatusInputs::default()
        });
        assert_eq!(
            both.iter().map(|l| l.0).collect::<Vec<_>>(),
            ["updated_restart", "scripts_degraded"]
        );
        assert_eq!(
            only(StatusInputs {
                update_pending: true,
                ..StatusInputs::default()
            })
            .len(),
            1
        );
    }

    #[test]
    fn an_alias_is_display_escaped() {
        let got = only(StatusInputs {
            expiries: vec![expiry("a\u{202e}b", 3)],
            ..StatusInputs::default()
        });
        assert_eq!(got.len(), 1);
        assert!(!got[0].1.contains('\u{202e}'), "{}", got[0].1);
    }
}
