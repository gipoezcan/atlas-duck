//! The status-line model (PD-90): the lines the tray tooltip, the header banner and `app_status`
//! show. Task 12 builds the model; until then there are no lines (nothing reports one yet).

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use crate::commands::dto::StatusLineDto;

/// The current status lines (none before Task 12).
pub fn lines() -> Vec<StatusLineDto> {
    Vec::new()
}
