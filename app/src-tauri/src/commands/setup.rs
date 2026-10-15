//! The setup window's own commands (C.10 + Δ1, PD-72, PD-77; M6 T23): `wizard_state`,
//! `wizard_use_default_dir`, `wizard_choose_dir`, `wizard_begin`, `wizard_skip_instances`,
//! `wizard_finish`. Granted to the `setup` window only; it also holds the four instance commands
//! and `cli_install` (`commands::settings`) and `quit`.
//!
//! None takes a value but the two that move on (`wizard_skip_instances`, `wizard_finish`), which take
//! the step the page showed: the data dir is the §7.7 default or what Rust's own folder dialog returns,
//! the recovery passphrase goes to the credential window (never here), and every answer is the
//! wizard's whole state ([`WizardState`]), so the page renders what Rust decided and skips nothing
//! itself. The rules live in `crate::wizard`.

use serde::Deserialize;
use tauri::{AppHandle, Runtime};

use super::dto::{Args, StepName};
use super::{CommandError, finish};
use crate::wizard::{self, DirChoice, WizardState};

/// `wizard_state {}` (read-only).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WizardStateArgs {}

/// `wizard_use_default_dir {}`: step (0) with the §7.7 default data dir.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WizardUseDefaultDirArgs {}

/// `wizard_choose_dir {}`: step (0) with a folder Rust's own dialog returns (no path argument).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WizardChooseDirArgs {}

/// `wizard_begin {}`: (1b) the recovery passphrase, or (1a) the existing store's window again.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WizardBeginArgs {}

/// `wizard_skip_instances {step}`: leaves the instance step. `step` is the step the page showed
/// (`WizardState::step`); Rust answers `wrong_step` for any other, so a repeated click or a stale
/// page moves nothing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WizardSkipInstancesArgs {
    pub step: StepName,
}

/// `wizard_finish {step}`: the recovery note, the CLI step or the onboarding snippet is done.
/// `step` as for `wizard_skip_instances`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WizardFinishArgs {
    pub step: StepName,
}

/// `wizard_state {}` (Δ1): the step, the data dir, the refused count, the Secret Service answer,
/// the instances; `not_ready` without a wizard (any start that is not a first run).
#[tauri::command]
pub async fn wizard_state<R: Runtime>(
    app: AppHandle<R>,
    args: Args<WizardStateArgs>,
) -> Result<WizardState, CommandError> {
    let Args(WizardStateArgs {}) = args;
    let response = wizard::state(&app).await;
    finish(&app, response)
}

/// `wizard_use_default_dir {}` (Δ1, §2.5 (0)): checks, creates, locks and pins the default data dir
/// and serves the first-run gate in-process; a refused folder is the answer's `error`.
#[tauri::command]
pub async fn wizard_use_default_dir<R: Runtime>(
    app: AppHandle<R>,
    args: Args<WizardUseDefaultDirArgs>,
) -> Result<WizardState, CommandError> {
    let Args(WizardUseDefaultDirArgs {}) = args;
    let response = wizard::use_dir(&app, DirChoice::Default).await;
    finish(&app, response)
}

/// `wizard_choose_dir {}` (Δ1, §7.7 "advanced override"): Rust's folder dialog, then as
/// `wizard_use_default_dir`; a non-local folder is refused with the §7.7 text.
#[tauri::command]
pub async fn wizard_choose_dir<R: Runtime>(
    app: AppHandle<R>,
    args: Args<WizardChooseDirArgs>,
) -> Result<WizardState, CommandError> {
    let Args(WizardChooseDirArgs {}) = args;
    let response = wizard::use_dir(&app, DirChoice::Pick).await;
    finish(&app, response)
}

/// `wizard_begin {}` (Δ1, PD-77 (1a)/(1b)).
#[tauri::command]
pub async fn wizard_begin<R: Runtime>(
    app: AppHandle<R>,
    args: Args<WizardBeginArgs>,
) -> Result<WizardState, CommandError> {
    let Args(WizardBeginArgs {}) = args;
    let response = wizard::begin(&app).await;
    finish(&app, response)
}

/// `wizard_skip_instances {}` (Δ1).
#[tauri::command]
pub async fn wizard_skip_instances<R: Runtime>(
    app: AppHandle<R>,
    args: Args<WizardSkipInstancesArgs>,
) -> Result<WizardState, CommandError> {
    let Args(WizardSkipInstancesArgs { step }) = args;
    let response = wizard::skip_instances(&app, step.as_str()).await;
    finish(&app, response)
}

/// `wizard_finish {}` (Δ1).
#[tauri::command]
pub async fn wizard_finish<R: Runtime>(
    app: AppHandle<R>,
    args: Args<WizardFinishArgs>,
) -> Result<WizardState, CommandError> {
    let Args(WizardFinishArgs { step }) = args;
    let response = wizard::finish(&app, step.as_str()).await;
    finish(&app, response)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::commands::dto::{FIELD_PAYLOAD, parse};

    /// No wizard command takes a key: a path, a passphrase or anything else is refused before the
    /// handler (the data dir is Rust's choice, the passphrase the credential window's).
    fn refused<T>() -> Result<T, CommandError> {
        Err(CommandError::InvalidArgument {
            field: FIELD_PAYLOAD,
        })
    }

    #[test]
    fn wizard_commands_take_nothing() {
        for body in [
            json!({"path": "C:\\evil"}),
            json!({"data_dir": "/mnt/nfs"}),
            json!({"secret": "canary-passphrase"}),
            json!([]),
        ] {
            assert_eq!(parse::<WizardStateArgs>(&body), refused(), "{body}");
            assert_eq!(parse::<WizardUseDefaultDirArgs>(&body), refused());
            assert_eq!(parse::<WizardChooseDirArgs>(&body), refused());
            assert_eq!(parse::<WizardBeginArgs>(&body), refused());
            assert_eq!(parse::<WizardSkipInstancesArgs>(&body), refused());
            assert_eq!(parse::<WizardFinishArgs>(&body), refused());
        }
        assert_eq!(
            parse::<WizardChooseDirArgs>(&json!({})),
            Ok(WizardChooseDirArgs {})
        );
    }

    /// `wizard_finish` and `wizard_skip_instances` take the step the page showed, and only that:
    /// a step that is not one of the wizard's names (of any length) is `invalid_argument` with
    /// `field: "step"`, and so is no step, nor is another key next to it (a path, a passphrase).
    #[test]
    fn finish_and_skip_take_only_the_step() {
        assert_eq!(
            parse::<WizardFinishArgs>(&json!({"step": "cli"})),
            Ok(WizardFinishArgs {
                step: StepName::new("cli").unwrap()
            })
        );
        assert_eq!(
            parse::<WizardSkipInstancesArgs>(&json!({"step": "instances"})),
            Ok(WizardSkipInstancesArgs {
                step: StepName::new("instances").unwrap()
            })
        );
        for name in wizard::STEP_NAMES {
            assert!(
                parse::<WizardFinishArgs>(&json!({"step": name})).is_ok(),
                "{name}"
            );
        }
        fn bad_step<T>() -> Result<T, CommandError> {
            Err(CommandError::InvalidArgument { field: "step" })
        }
        for body in [
            json!({}),
            json!({"step": 3}),
            json!({"step": null}),
            json!({"step": "unknown"}),
            json!({"step": "CLI"}),
            json!({"step": ""}),
            json!({"step": "x".repeat(1 << 20)}),
        ] {
            assert_eq!(parse::<WizardFinishArgs>(&body), bad_step(), "{body:.40}");
            assert_eq!(
                parse::<WizardSkipInstancesArgs>(&body),
                bad_step(),
                "{body:.40}"
            );
        }
        for body in [
            json!({"step": "cli", "path": "C:\\evil"}),
            json!({"step": "cli", "secret": "canary-passphrase"}),
        ] {
            assert_eq!(parse::<WizardFinishArgs>(&body), refused(), "{body}");
            assert_eq!(parse::<WizardSkipInstancesArgs>(&body), refused(), "{body}");
        }
    }
}
