//! The onboarding text (C.10 + Δ1, §12.4, PD-80; M6 T30): `onboarding_text {}`. Granted to
//! `onboarding` and `setup` (the wizard's last step shows the same snippet).
//!
//! Generated from the registry in core, so it needs no serving `Core` and carries nothing the
//! user's data holds: every command and every sentence is the program's own.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime};

use super::dto::Args;
use super::{CommandError, finish};

/// `onboarding_text {}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingTextArgs {}

/// The snippet the user copies into an agent's instruction file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OnboardingTextDto {
    pub text: String,
}

/// `onboarding_text {}` (Δ1, PD-80).
#[tauri::command]
pub async fn onboarding_text<R: Runtime>(
    app: AppHandle<R>,
    args: Args<OnboardingTextArgs>,
) -> Result<OnboardingTextDto, CommandError> {
    let Args(OnboardingTextArgs {}) = args;
    let response = Ok(OnboardingTextDto {
        text: atlas_duck_core::onboarding::text(),
    });
    finish(&app, response)
}
