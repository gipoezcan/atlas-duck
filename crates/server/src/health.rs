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
use crate::master_key::{MasterKey, WrappedKey};
use crate::store::ServerStore;

pub const PROBE_CACHE: Duration = Duration::from_secs(30);

pub struct Health {
    store: Arc<dyn ServerStore>,
    directory: Arc<dyn Directory>,
    master_key_loaded: bool,
    /// M13 T7: the loaded keys, checked against the key ids the users' data keys carry.
    master: Option<Arc<MasterKey>>,
    /// M13 T9: `manual`, `directory` or `stub` (how offboarding happens).
    offboarding: Option<&'static str>,
    probe: Mutex<Option<(Instant, bool)>>,
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
            master: None,
            offboarding: None,
            probe: Mutex::new(None),
        }
    }

    /// Reports how offboarding happens (a field, never a reason for 503).
    pub fn with_offboarding(mut self, mode: &'static str) -> Health {
        self.offboarding = Some(mode);
        self
    }

    /// Also checks that every user's data key is wrapped under a loaded master key.
    pub fn with_master(mut self, master: Arc<MasterKey>) -> Health {
        self.master = Some(master);
        self
    }

    /// "master_key_mismatch" when some user's data key is wrapped under a key id that is not
    /// loaded (for example the old key mounted again after a completed rotation).
    fn master_key_reason(&self) -> Option<&'static str> {
        let master = self.master.as_ref()?;
        let users = self.store.users_all().ok()?;
        users
            .iter()
            .filter_map(|(u, _)| WrappedKey::from_json(&u.data_key_wrapped).ok())
            .any(|w| !master.knows(&w.master_key_id))
            .then_some("master_key_mismatch")
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
        let key_reason = self.master_key_reason();
        let master_key = self.master_key_loaded && key_reason.is_none();
        let ok = store && master_key && directory;
        let mut body = json!({
            "checks": {"store": store, "master_key": master_key, "directory": directory},
            "directory": self.directory.kind(),
        });
        if let Some(mode) = self.offboarding {
            body["offboarding"] = json!(mode);
        }
        if let Some(r) = key_reason {
            body["reasons"] = json!([r]);
        }
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
