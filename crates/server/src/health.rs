//! `/healthz` and `/readyz` (SM-8.2). `/healthz` answers while the process serves; `/readyz`
//! answers 200 only while the server store answers, the master key is loaded and the directory
//! probe succeeded (cached 30 s), else 503 with the failing checks. No detail beyond booleans.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::sync::Mutex;

use crate::directory::Directory;
use crate::store::ServerStore;

pub const PROBE_CACHE: Duration = Duration::from_secs(30);

pub struct Health {
    store: Arc<dyn ServerStore>,
    directory: Arc<dyn Directory>,
    master_key_loaded: bool,
    probe: Mutex<Option<(Instant, bool)>>,
    /// M14 PD-248: the script state; reported, never a reason for 503.
    scripts: Option<Arc<crate::scripts::ServerScripts>>,
}

impl Health {
    pub fn new(
        store: Arc<dyn ServerStore>,
        directory: Arc<dyn Directory>,
        master_key_loaded: bool,
    ) -> Health {
        Health {
            store,
            directory,
            master_key_loaded,
            probe: Mutex::new(None),
            scripts: None,
        }
    }

    /// The script state `/readyz` reports (`disabled` without one).
    pub fn with_scripts(mut self, scripts: Option<Arc<crate::scripts::ServerScripts>>) -> Health {
        self.scripts = scripts;
        self
    }

    /// `met`, `not_met`, `probing` or `disabled` (PD-248).
    pub fn scripts_state(&self) -> &'static str {
        self.scripts.as_ref().map_or("disabled", |s| s.state())
    }

    async fn directory_ok(&self) -> bool {
        let mut cached = self.probe.lock().await;
        if let Some((at, ok)) = *cached
            && at.elapsed() < PROBE_CACHE
        {
            return ok;
        }
        let ok = self.directory.probe().await.is_ok();
        *cached = Some((Instant::now(), ok));
        ok
    }

    pub async fn readyz(&self) -> Response {
        let store = self.store.instance_list().is_ok();
        let directory = self.directory_ok().await;
        let ok = store && self.master_key_loaded && directory;
        let body = json!({
            "checks": {"store": store, "master_key": self.master_key_loaded, "directory": directory},
            "directory": self.directory.kind(),
            "scripts": self.scripts_state(),
        });
        let status = if ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        (status, Json(body)).into_response()
    }
}

pub async fn healthz() -> &'static str {
    "ok"
}
