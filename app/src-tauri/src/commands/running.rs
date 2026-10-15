//! The Running-scripts window's commands (C.10 + Δ1, PD-81, §9.6; M6 T30): `running_list {}` and
//! `running_kill {request_id}`. Granted to `running_scripts` only. M8 completes the columns and the
//! release-item behaviour; M6 only wires what core has.
//!
//! The kill is `Core::kill_script`: it asks the run's worker to die and returns; the run's own
//! path then records `SCRIPT_FAILED {killed_by_user}` and turns the request into a release item
//! (audit before effect stays with that path, nothing here appends or releases). A request that is
//! not a live real run is `{killed: false}`, not an error: the list the page showed was a moment
//! old and the page re-reads it.

use atlas_duck_core::running::RunningScriptView;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime};

use super::dto::{Args, RequestId};
use super::{CommandError, blocking, core, finish};

/// `running_list {}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunningListArgs {}

/// `running_kill {request_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunningKillArgs {
    pub request_id: RequestId,
}

/// `running_kill` answer: whether a kill was asked for (`false` = no such live run, or a kill was
/// already on its way).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct KillAnswer {
    pub killed: bool,
}

/// `running_list {}` (Δ1, PD-81): the live real script runs, oldest first.
#[tauri::command]
pub async fn running_list<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RunningListArgs>,
) -> Result<Vec<RunningScriptView>, CommandError> {
    let Args(RunningListArgs {}) = args;
    let response = match core(&app) {
        Ok(core) => blocking(move || Ok(core.running_scripts())).await,
        Err(e) => Err(e),
    };
    finish(&app, response)
}

/// `running_kill {request_id}` (Δ1, §9.6): asks for the run's death through core; the run's own
/// audited path does the rest.
#[tauri::command]
pub async fn running_kill<R: Runtime>(
    app: AppHandle<R>,
    args: Args<RunningKillArgs>,
) -> Result<KillAnswer, CommandError> {
    let Args(RunningKillArgs { request_id }) = args;
    let response = match core(&app) {
        Ok(core) => {
            blocking(move || {
                Ok(KillAnswer {
                    killed: core.kill_script(request_id.as_str()),
                })
            })
            .await
        }
        Err(e) => Err(e),
    };
    finish(&app, response)
}
