//! The status-line model (PD-90, §5.6): the lines the tray tooltip, the header banner and
//! `app_status` show. [`lines`] is pure over [`StatusInputs`]; [`gather`] fills the inputs from the
//! serving state. Every text is app-generated: the inputs hold counts, flags, instance aliases
//! (app configuration) and core-built texts, never a string an agent or a request supplied, so no
//! line can carry one (§5.6 "Toast, tray and header-banner text is app-generated only").

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use atlas_duck_core::reconcile::LINE_CHECK_TARGET;
use atlas_duck_core::{ConfigBanner, Core, GateState, StoreHealthView};
use atlas_duck_preview::invisible::escape_for_display;
use tauri::{AppHandle, Manager, Runtime};

use crate::commands::dto::{StatusLevel, StatusLineDto};
use crate::state::ServeSlot;

/// Every line id in the order [`lines`] emits them (PD-90).
pub const IDS: [&str; 16] = [
    "locked_refused",
    "setup_refused",
    "waiting_keyring",
    "updated_restart",
    "store_newer",
    "needs_attention",
    "token_expiry",
    "storage_low",
    "anchor_write_failing",
    "integrity_incident",
    "prune_backlog",
    LINE_CHECK_TARGET,
    "config_read_only",
    "config_unreadable",
    "ipc_not_accepting",
    "keychain_prompt",
];

/// §8.7 (verbatim).
pub const TEXT_WAITING_KEYRING: &str = "Waiting for keyring";
/// §12.2 (verbatim); the trigger is M8's (`StatusInputs::update_pending`).
pub const TEXT_UPDATED_RESTART: &str = "Updated — restart to apply";
/// plan text (PD-90): `ipc_not_accepting` (M4 T19 bind failure).
pub const TEXT_IPC_NOT_ACCEPTING: &str = "not accepting agent requests; see doctor";
/// plan text (PD-90, L78): `keychain_prompt`.
pub const TEXT_KEYCHAIN_PROMPT: &str = "waiting for keychain authorization";
/// plan text (PD-90): `storage_low`, after §8.1 "new agent requests are refused".
pub const TEXT_STORAGE_LOW: &str = "audit storage is low: new requests are refused";
/// plan text (PD-90): `anchor_write_failing`, after §8.5/§8.8/§8.11 (retried, never an incident).
pub const TEXT_ANCHOR_WRITE_FAILING: &str = "audit anchor could not be written; retrying";
/// plan text (PD-90): `integrity_incident`, the §8.7 banner; the PD-82 wording.
pub const TEXT_INTEGRITY_INCIDENT: &str = "integrity incident: see Audit";
/// plan text (PD-90): `store_newer`, generic on purpose: the gate keeps no writer version, so the
/// text cannot name one (§8.13 words it "audit data was written by atlas-duck vX; install vX or
/// newer"; naming the version needs the gate to keep it).
pub const TEXT_STORE_NEWER: &str =
    "audit data was written by a newer atlas-duck; install that version or newer";

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
    /// The installed app was replaced under the running one (§12.2); M8 sets it.
    pub update_pending: bool,
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
        }
    }
}

fn line(id: &'static str, level: StatusLevel, text: String) -> StatusLineDto {
    StatusLineDto { id, text, level }
}

/// plan text (PD-84): the token lines.
fn expiry_text(e: &TokenExpiry) -> String {
    let alias = escape_for_display(&e.alias);
    match e.days_left {
        d if d < 0 => format!(
            "token for {alias} expired on {}",
            escape_for_display(&e.expires_at)
        ),
        0 => format!("token for {alias} expires today"),
        1 => format!("token for {alias} expires in 1 day"),
        d => format!("token for {alias} expires in {d} days"),
    }
}

/// Plan text (written by the plan, not the spec): the startup "check target" notice, with the
/// spec's §4/§11 wording "check the target before retrying".
fn check_target_text(n: u64) -> String {
    if n == 1 {
        "1 write has an unknown outcome: check its target before retrying".to_owned()
    } else {
        format!("{n} writes have an unknown outcome: check their targets before retrying")
    }
}

/// The status lines, in the order of [`IDS`] (a token line per instance). One input gives one line;
/// nothing here reads a request.
pub fn lines(i: &StatusInputs) -> Vec<StatusLineDto> {
    use StatusLevel::{Caution, Info};
    let mut out = Vec::new();
    match i.gate {
        // §2.5 (verbatim).
        Some(GateState::Locked(_)) => out.push(line(
            "locked_refused",
            Caution,
            format!("Locked — {} requests refused", i.refused),
        )),
        // §2.5 (verbatim).
        Some(GateState::FirstRun) => out.push(line(
            "setup_refused",
            Caution,
            format!("Setup required — {} requests refused", i.refused),
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
            TEXT_WAITING_KEYRING.to_owned(),
        ));
    }
    if i.update_pending {
        out.push(line(
            "updated_restart",
            Info,
            TEXT_UPDATED_RESTART.to_owned(),
        ));
    }
    if i.gate == Some(GateState::StoreNewer) {
        out.push(line("store_newer", Caution, TEXT_STORE_NEWER.to_owned()));
    }
    if i.needs_attention > 0 {
        out.push(line(
            "needs_attention",
            Caution,
            format!("{} need attention", i.needs_attention),
        ));
    }
    for e in &i.expiries {
        let level = if e.days_left <= 7 { Caution } else { Info };
        out.push(line("token_expiry", level, expiry_text(e)));
    }
    if let Some(h) = &i.health {
        if h.storage_low {
            out.push(line("storage_low", Caution, TEXT_STORAGE_LOW.to_owned()));
        }
        if h.anchor_write_failing || h.anchor_thread_dead {
            out.push(line(
                "anchor_write_failing",
                Caution,
                TEXT_ANCHOR_WRITE_FAILING.to_owned(),
            ));
        }
        if h.open_incidents > 0 {
            out.push(line(
                "integrity_incident",
                Caution,
                TEXT_INTEGRITY_INCIDENT.to_owned(),
            ));
        }
        if let Some(text) = &h.prune_backlog {
            out.push(line("prune_backlog", Caution, text.clone()));
        }
    }
    if i.startup_notice > 0 {
        out.push(line(
            LINE_CHECK_TARGET,
            Caution,
            check_target_text(i.startup_notice),
        ));
    }
    if let Some(b) = &i.config_banner {
        // §7.7 (verbatim, built by core): a newer file keeps requests working (info), one that
        // cannot be read leaves the app with no instances from it (caution).
        let (id, level) = match b.kind {
            "unreadable" => ("config_unreadable", Caution),
            _ => ("config_read_only", Info),
        };
        out.push(line(id, level, b.text.clone()));
    }
    if !i.ipc_accepting {
        out.push(line(
            "ipc_not_accepting",
            Caution,
            TEXT_IPC_NOT_ACCEPTING.to_owned(),
        ));
    }
    if i.keychain_prompt {
        out.push(line(
            "keychain_prompt",
            Info,
            TEXT_KEYCHAIN_PROMPT.to_owned(),
        ));
    }
    out
}

/// The inputs from the serving state. Synchronous core calls (`view`, `list`, the queue): call it
/// on the blocking pool (M3 PD-13). Without a serving state (before first run, starting, quitting)
/// there is nothing to report.
pub fn gather<R: Runtime>(app: &AppHandle<R>) -> StatusInputs {
    let mut i = gather_gate(app);
    let core = app.try_state::<ServeSlot>().and_then(|slot| {
        if slot.quit().0.is_cancelled() {
            return None;
        }
        slot.get().and_then(|s| s.core.get().cloned())
    });
    if let Some(core) = core {
        gather_core(&mut i, &core);
    }
    i
}

/// The half of [`gather`] that reads no `Core`: the gate, its refused count, the retry, the
/// endpoint and the keychain prompt hint. Only flags and counters, so the tray (which rebuilds on
/// the main thread, M6 T22) can call it.
pub fn gather_gate<R: Runtime>(app: &AppHandle<R>) -> StatusInputs {
    let mut i = StatusInputs::default();
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
        }
    }

    fn banner(kind: &'static str, text: &str) -> Option<ConfigBanner> {
        Some(ConfigBanner {
            kind,
            text: text.to_owned(),
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
                    gate: Some(GateState::StoreNewer),
                    ..StatusInputs::default()
                },
                vec![("store_newer", TEXT_STORE_NEWER, Caution)],
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
                vec![("storage_low", TEXT_STORAGE_LOW, Caution)],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        anchor_write_failing: true,
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![("anchor_write_failing", TEXT_ANCHOR_WRITE_FAILING, Caution)],
            ),
            (
                StatusInputs {
                    health: Some(StoreHealthView {
                        anchor_thread_dead: true,
                        ..health()
                    }),
                    ..StatusInputs::default()
                },
                vec![("anchor_write_failing", TEXT_ANCHOR_WRITE_FAILING, Caution)],
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
        };
        let ids: Vec<&str> = only(all).into_iter().map(|l| l.0).collect();
        let positions: Vec<usize> = ids
            .iter()
            .filter_map(|id| IDS.iter().position(|x| x == id))
            .collect();
        assert_eq!(positions.len(), ids.len());
        assert!(positions.windows(2).all(|w| w[0] <= w[1]), "{ids:?}");
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
