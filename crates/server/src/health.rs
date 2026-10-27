//! `/healthz`, `/readyz` and `/metrics` (SM-8.2, SM-8.3).
//!
//! `/healthz` answers while the process serves, without touching any dependency. `/readyz`
//! answers 503 with reason codes when the server store does not answer (`store_unavailable`),
//! the master key is not loaded (`master_key_missing`) or a user's data key is wrapped under a key
//! id that is not loaded (`master_key_mismatch`); the web layer adds `maintenance` (M13 T6). The
//! directory probe (TCP + TLS, cached 30 s) is reported but never makes the pod unready
//! (PD-M13-13): a domain-controller blip must not take approvals of logged-in users down, so it is
//! a `degraded` entry (`directory_unreachable`) on a 200. Bodies carry codes and booleans only.
//!
//! `/metrics` is Prometheus text with no user data: every label value comes from a fixed set
//! (methods, status classes, job names) or is the non-secret master key id (M12 PD-208). It is
//! not served to requests that came through a proxy (any `X-Forwarded-For`), so the ingress never
//! exposes it (M13 T3/T10 decision).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::sync::Mutex;

use crate::directory::Directory;
use crate::master_key::{MasterKey, WrappedKey};
use crate::runtime::Registry;
use crate::scheduler::{JOB_OFFBOARDING, JOB_RETENTION};
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
    /// M13 T10: the open runtimes (approvals pending).
    registry: Option<Arc<Registry>>,
    probe: Mutex<Option<(Instant, bool)>>,
    /// Batch-2 review M6: the key-id scan of every user, cached like the directory probe.
    key_check: std::sync::Mutex<Option<(Instant, Option<&'static str>)>>,
    /// `(method, status class)` → requests answered.
    requests: std::sync::Mutex<BTreeMap<(&'static str, &'static str), u64>>,
}

/// A method as a fixed label value.
fn method_label(m: &Method) -> &'static str {
    match *m {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        _ => "other",
    }
}

fn status_label(s: StatusCode) -> &'static str {
    match s.as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
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
            registry: None,
            probe: Mutex::new(None),
            key_check: std::sync::Mutex::new(None),
            requests: std::sync::Mutex::new(BTreeMap::new()),
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

    /// Counts pending approvals of the open runtimes in `/metrics`.
    pub fn with_registry(mut self, registry: Arc<Registry>) -> Health {
        self.registry = Some(registry);
        self
    }

    /// One answered request (the web layer calls it for every request).
    pub fn count(&self, method: &Method, status: StatusCode) {
        let mut m = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        *m.entry((method_label(method), status_label(status)))
            .or_insert(0) += 1;
    }

    /// "master_key_mismatch" when some user's data key is wrapped under a key id that is not
    /// loaded (for example the old key mounted again after a completed rotation).
    fn master_key_reason(&self) -> Option<&'static str> {
        let mut cached = self.key_check.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, r)) = *cached
            && at.elapsed() < PROBE_CACHE
        {
            return r;
        }
        let r = self.scan_key_ids();
        *cached = Some((Instant::now(), r));
        r
    }

    fn scan_key_ids(&self) -> Option<&'static str> {
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
        let mut reasons: Vec<&str> = Vec::new();
        if !store {
            reasons.push("store_unavailable");
        }
        if !self.master_key_loaded {
            reasons.push("master_key_missing");
        } else if let Some(r) = key_reason {
            reasons.push(r);
        }
        let degraded: Vec<&str> = if directory {
            Vec::new()
        } else {
            vec!["directory_unreachable"]
        };
        let mut body = json!({
            "ready": reasons.is_empty(),
            "reasons": reasons,
            "degraded": degraded,
            "checks": {"store": store, "master_key": master_key, "directory": directory},
            "directory": self.directory.kind(),
        });
        if let Some(mode) = self.offboarding {
            body["offboarding"] = json!(mode);
        }
        let status = if reasons.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        (status, Json(body)).into_response()
    }

    /// The Prometheus exposition (text format 0.0.4).
    pub async fn metrics(&self) -> String {
        let mut out = String::new();
        let mut gauge = |name: &str, help: &str, kind: &str, lines: &[(String, String)]| {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} {kind}");
            for (labels, value) in lines {
                let _ = writeln!(out, "{name}{labels} {value}");
            }
        };
        let requests: Vec<(String, String)> = self
            .requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|((m, s), n)| (format!("{{method=\"{m}\",status=\"{s}\"}}"), n.to_string()))
            .collect();
        gauge(
            "atlas_duck_requests_total",
            "HTTP requests answered, by method and status class.",
            "counter",
            &requests,
        );
        let pending = match &self.registry {
            Some(r) => {
                let mut n = 0usize;
                for rt in r.open_runtimes().await {
                    n += rt.decisions().queue_list().len();
                }
                n
            }
            None => 0,
        };
        gauge(
            "atlas_duck_approvals_pending",
            "Requests waiting for their user's approval (open runtimes).",
            "gauge",
            &[(String::new(), pending.to_string())],
        );
        let open = match &self.registry {
            Some(r) => r.open_runtimes().await.len(),
            None => 0,
        };
        gauge(
            "atlas_duck_open_runtimes",
            "User runtimes open now.",
            "gauge",
            &[(String::new(), open.to_string())],
        );
        let mut last = Vec::new();
        for job in [JOB_OFFBOARDING, JOB_RETENTION] {
            if let Some(at) = self
                .store
                .scheduler_get(job)
                .ok()
                .and_then(|s| s.last_success_at)
            {
                last.push((format!("{{job=\"{job}\"}}"), at.to_string()));
            }
        }
        gauge(
            "atlas_duck_scheduler_last_success_seconds",
            "Unix time of each scheduler job's last successful run.",
            "gauge",
            &last,
        );
        let flag = |b: bool| if b { "1" } else { "0" }.to_owned();
        gauge(
            "atlas_duck_offboarding_enabled",
            "1 when the daily offboarding check has a directory lookup, 0 when it is manual.",
            "gauge",
            &[(
                String::new(),
                flag(self.offboarding.is_some_and(|m| m != "manual")),
            )],
        );
        gauge(
            "atlas_duck_test_directory_enabled",
            "1 when logins use the test directory (never in production).",
            "gauge",
            &[(String::new(), flag(self.directory.kind() == "stub"))],
        );
        let keys: Vec<(String, String)> = match &self.master {
            Some(m) => m
                .ids()
                .into_iter()
                .enumerate()
                .map(|(i, id)| {
                    let role = if i == 0 { "primary" } else { "accepted" };
                    (format!("{{key_id=\"{id}\",role=\"{role}\"}}"), "1".into())
                })
                .collect(),
            None => Vec::new(),
        };
        gauge(
            "atlas_duck_master_key_info",
            "The loaded master key ids (ids only, never key material).",
            "gauge",
            &keys,
        );
        gauge(
            "atlas_duck_build_info",
            "The server version.",
            "gauge",
            &[(
                format!("{{version=\"{}\"}}", env!("CARGO_PKG_VERSION")),
                "1".into(),
            )],
        );
        out
    }
}

pub async fn healthz() -> &'static str {
    "ok"
}
