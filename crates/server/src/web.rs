//! The axum router and the web API.

use crate::config::Config;

/// Runs the server until shutdown and answers the process exit code. The listener, router and
/// runtimes arrive with Task 14; until then `serve` stops after a valid configuration.
pub fn serve(_config: Config) -> u8 {
    tracing::error!(
        event = "serve_not_built",
        "the HTTP server is not built yet (M12 T14)"
    );
    crate::cli::EXIT_RUNTIME
}
