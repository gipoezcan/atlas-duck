//! GUI / `--background` startup: crash-artifact settings (T09), the data-dir gate (T10) and the
//! startup hardening (M6 T2).

pub mod crash;
pub mod gate;
pub mod hardening;

pub use gate::{
    DialogPresenter, ErrorPresenter, LOG_FIELDS, MSG_DATA_DIR_NOT_FOUND, MSG_DATA_DIR_NOT_LOCAL,
    MSG_DATA_DIR_UNUSABLE, MSG_PINNED_UNREADABLE, MSG_RUNNING_ON_OTHER_HOST, StartupAction,
    StartupState, apply_startup_state, gate, gate_in, read_this_host_pinned, render_message,
    startup_message, this_host_pinned_file,
};
