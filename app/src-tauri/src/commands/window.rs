//! `open_window` and `quit` (C.10 + Δ1; §2.5, §5.6 Approvals header; M6 T6).
//!
//! `open_window` is granted to `approvals` only: the header reaches every other window through
//! it. It never opens `approvals` itself, the credential window (Rust opens that with a fixed
//! purpose, §10.3) or `setup`. `quit` (approvals, credential, setup) runs the one shutdown path.

use atlas_duck_core::ShutdownReason;
use serde::{Deserialize, Deserializer};
use tauri::{AppHandle, Runtime};

use super::dto::{Args, refuse};
use super::{CommandError, blocking, finish};
use crate::serve;
use crate::windows::{self, Label, Show};

/// The windows `open_window` may open (Δ1).
pub const OPEN_WINDOW_TARGETS: [Label; 4] = [
    Label::Settings,
    Label::Audit,
    Label::RunningScripts,
    Label::Onboarding,
];

/// `window`: one of [`OPEN_WINDOW_TARGETS`] by its label; anything else is refused with
/// `field: "window"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowTarget(pub Label);

impl<'de> Deserialize<'de> for WindowTarget {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d).map_err(|_| refuse::<D::Error>("window"))?;
        OPEN_WINDOW_TARGETS
            .into_iter()
            .find(|l| l.as_str() == s)
            .map(WindowTarget)
            .ok_or_else(|| refuse("window"))
    }
}

/// `open_window {window}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenWindowArgs {
    pub window: WindowTarget,
}

/// `quit {}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuitArgs {}

/// `open_window {window: settings|audit|running_scripts|onboarding}` (Δ1): builds the window
/// once, then shows and focuses it. The build waits for the main thread, so it runs on the
/// blocking pool.
#[tauri::command]
pub async fn open_window<R: Runtime>(
    app: AppHandle<R>,
    args: Args<OpenWindowArgs>,
) -> Result<(), CommandError> {
    let Args(OpenWindowArgs {
        window: WindowTarget(label),
    }) = args;
    let handle = app.clone();
    let opened = blocking(move || {
        windows::open(&handle, label, Show::Focus).map_err(|_| CommandError::Internal)
    })
    .await;
    finish(&app, opened)
}

/// `quit {}` (Δ1, §2.5): the shutdown path, then exit. Answers before the app exits.
#[tauri::command]
pub async fn quit<R: Runtime>(app: AppHandle<R>, args: Args<QuitArgs>) -> Result<(), CommandError> {
    let Args(QuitArgs {}) = args;
    serve::shutdown_then_exit(&app, ShutdownReason::Quit);
    finish(&app, Ok(()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::commands::dto::{FIELD_PAYLOAD, parse};

    #[test]
    fn open_window_takes_one_of_four_windows() {
        for (name, label) in [
            ("settings", Label::Settings),
            ("audit", Label::Audit),
            ("running_scripts", Label::RunningScripts),
            ("onboarding", Label::Onboarding),
        ] {
            assert_eq!(
                parse::<OpenWindowArgs>(&json!({ "window": name })),
                Ok(OpenWindowArgs {
                    window: WindowTarget(label)
                })
            );
        }
        let window = Err(CommandError::InvalidArgument { field: "window" });
        for bad in [
            json!({"window": "approvals"}),
            json!({"window": "credential"}),
            json!({"window": "setup"}),
            json!({"window": "Settings"}),
            json!({"window": ""}),
            json!({"window": 1}),
            json!({"window": null}),
            json!({}),
        ] {
            assert_eq!(parse::<OpenWindowArgs>(&bad), window, "{bad}");
        }
        let payload = Err(CommandError::InvalidArgument {
            field: FIELD_PAYLOAD,
        });
        assert_eq!(
            parse::<OpenWindowArgs>(&json!({"window": "settings", "url": "https://x"})),
            payload
        );
        assert_eq!(parse::<OpenWindowArgs>(&json!(["settings"])), payload);
    }

    #[test]
    fn quit_takes_nothing() {
        assert_eq!(parse::<QuitArgs>(&json!({})), Ok(QuitArgs {}));
        assert_eq!(
            parse::<QuitArgs>(&json!({"reason": "x"})),
            Err(CommandError::InvalidArgument {
                field: FIELD_PAYLOAD
            })
        );
    }
}
