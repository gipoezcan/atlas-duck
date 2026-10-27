//! Scripts in server mode (SM-7.1, M14 PD-246..PD-249) on the M8 sandbox of `atlas-duck-script-glue`.
//!
//! One startup probe per process ([`ServerScripts::start`], `ATLAS_DUCK_SANDBOX_BIN`), one
//! [`ServerScriptRunner`] per user core over that core's own glue, and two process-wide pools
//! ([`SharedSlots`]) every core's runs take on top of their own §9.4 slots: a run queues for the
//! server-wide pool exactly as it queues for its user's slots (`queued` in `SCRIPT_STARTED`,
//! cancellable), so the two concurrent runs per user come from core and the server cap from here.
//!
//! Fail closed (PD-248): every call goes to the glue with a strict policy, whatever the user's
//! degraded-confinement setting says; a `NotMet` floor refuses every script with
//! `sandbox_unavailable` and shows in `/readyz` (`scripts: "not_met"`) without failing it.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use atlas_duck_core::{
    CompileFailure, HostCalls, RunConfinement, RunHandle, RunPolicy, RunSpec, RunnerError,
    ScriptRunner, SharedSlots,
};
use atlas_duck_ipc::sandbox::ScriptLimits;
use atlas_duck_sandbox_host::probe::{FloorVerdict, ProbeReport};
use atlas_duck_script_glue::probe::{
    PROBE_THREAD_NAME, ProbeHolder, failed_label, floor_label, log_probe_report, run_probe_for,
    spawn_marked,
};
use atlas_duck_script_glue::{HostBridge, InstanceSource, ScriptGlue, ScriptInputs};
use serde_json::{Value, json};
use tokio::sync::Semaphore;

/// The script settings (plan "Configuration").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptsConfig {
    pub enabled: bool,
    pub sandbox_bin: PathBuf,
    pub runs_max: usize,
    pub dry_runs_max: usize,
}

impl ScriptsConfig {
    pub const DEFAULT_BIN: &'static str = "/app/atlas-duck-sandbox";

    pub fn defaults() -> ScriptsConfig {
        ScriptsConfig {
            enabled: true,
            sandbox_bin: PathBuf::from(Self::DEFAULT_BIN),
            runs_max: 4,
            dry_runs_max: 4,
        }
    }
}

/// `serve` start (T12 Step 1): the worker must be an absolute path to a regular, executable file
/// (else exit 78 `config/sandbox_bin_invalid`). Checked only when scripts are enabled.
pub fn sandbox_bin_ok(path: &Path) -> bool {
    if !path.has_root() {
        return false;
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// `/readyz` `scripts` and the floor metric's `state` label (fixed set).
pub fn state_label(enabled: bool, report: Option<&ProbeReport>) -> &'static str {
    match (enabled, report.map(|r| &r.floor)) {
        (false, _) => "disabled",
        (true, None) => "probing",
        (true, Some(FloorVerdict::Met)) => "met",
        (true, Some(FloorVerdict::NotMet { .. })) => "not_met",
    }
}

/// The probe report as `atlas-duck-server sandbox-probe --json` prints it (T12 Step 4, T14's CI
/// evidence): no path, no identity.
pub fn report_json(report: &ProbeReport) -> Value {
    let threads = report.threads.as_ref();
    json!({
        "floor": floor_label(&report.floor),
        "failed": failed_label(&report.floor),
        "mechanism": report.confinement.as_ref().map(|c| c.mechanism.clone()),
        "landlock_abi": report.confinement.as_ref().and_then(|c| c.landlock_abi),
        "seccomp": report.confinement.as_ref().and_then(|c| c.seccomp),
        "no_new_privs": report.confinement.as_ref().and_then(|c| c.no_new_privs),
        "thread_tasks": threads.map(|t| t.tasks),
        "all_seccomp_2": threads.map(|t| t.all_seccomp_2),
        "all_no_new_privs_1": threads.map(|t| t.all_no_new_privs_1),
        "extra_layers": report.extra_layers.iter()
            .map(|(name, on)| json!({"name": name, "on": on}))
            .collect::<Vec<_>>(),
        "worker_version": report.worker_version,
        "engine_version": report.engine_version,
        "kernel": kernel_release(),
    })
}

/// `/proc/sys/kernel/osrelease` on Linux (evidence only), `None` elsewhere.
fn kernel_release() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|s| s.trim().to_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The process-wide script state: the probe holder, the worker path, the shared pools.
pub struct ServerScripts {
    pub cfg: ScriptsConfig,
    pub probe: Arc<ProbeHolder>,
    pools: SharedSlots,
    degraded_logged: Arc<AtomicBool>,
    /// Tests: every core's runner wraps this one (core's `FakeScriptRunner`) instead of a glue.
    #[cfg(any(test, feature = "testing"))]
    inner: Option<Arc<dyn ScriptRunner>>,
}

impl ServerScripts {
    /// The state without a probe started (tests set the report through `probe`).
    pub fn new(cfg: ScriptsConfig) -> ServerScripts {
        ServerScripts {
            probe: Arc::new(ProbeHolder::for_worker(Some(cfg.sandbox_bin.clone()))),
            pools: SharedSlots {
                runs: Arc::new(Semaphore::new(cfg.runs_max)),
                dry: Arc::new(Semaphore::new(cfg.dry_runs_max)),
            },
            degraded_logged: Arc::new(AtomicBool::new(false)),
            #[cfg(any(test, feature = "testing"))]
            inner: None,
            cfg,
        }
    }

    /// Tests: every user core runs scripts on `inner` behind the server's policy and pools.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_runner(cfg: ScriptsConfig, inner: Arc<dyn ScriptRunner>) -> ServerScripts {
        ServerScripts {
            inner: Some(inner),
            ..ServerScripts::new(cfg)
        }
    }

    /// `serve` start: the state and its probe thread (once per process, PD-249). The probe's
    /// "profile" is the data dir (no home in the container): a worker must not read it either.
    /// Readiness does not wait for the report.
    pub fn start(cfg: ScriptsConfig, data_dir: &Path) -> ServerScripts {
        let s = ServerScripts::new(cfg);
        let holder = s.probe.clone();
        let worker = s.cfg.sandbox_bin.clone();
        let profile = data_dir.to_path_buf();
        let spawned = spawn_marked(Some(&s.probe), || {
            std::thread::Builder::new()
                .name(PROBE_THREAD_NAME.to_owned())
                .spawn(move || {
                    let report = run_probe_for(&worker, std::process::id(), &profile);
                    log_probe_report(&report, None);
                    let _ = holder.set(report);
                })
        });
        if spawned.is_err() {
            tracing::error!(event = "sandbox_probe", reason = "thread_spawn_failed");
            s.probe.abandon();
        }
        s
    }

    /// The probe report, if it is there.
    pub fn report(&self) -> Option<&ProbeReport> {
        self.probe.get()
    }

    pub fn state(&self) -> &'static str {
        state_label(self.cfg.enabled, self.report())
    }

    /// Real runs in progress server-wide.
    pub fn runs_active(&self) -> usize {
        self.cfg.runs_max - self.pools.runs.available_permits()
    }

    pub fn dry_active(&self) -> usize {
        self.cfg.dry_runs_max - self.pools.dry.available_permits()
    }

    /// A user core's runner over its own glue (instances read through `instances`), the shared
    /// probe and pools.
    pub fn runner(&self, instances: InstanceSource) -> Arc<dyn ScriptRunner> {
        #[cfg(any(test, feature = "testing"))]
        if let Some(inner) = &self.inner {
            return self.wrap(inner.clone());
        }
        let glue = ScriptGlue::with_port(
            Arc::new(HostBridge::default()),
            Some(self.cfg.sandbox_bin.clone()),
            ScriptInputs {
                probe: self.probe.clone(),
                instances,
                ..ScriptInputs::default()
            },
        );
        self.wrap(Arc::new(glue))
    }

    /// `inner` behind the server's strict policy and shared pools (tests wrap core's fake).
    pub fn wrap(&self, inner: Arc<dyn ScriptRunner>) -> Arc<dyn ScriptRunner> {
        Arc::new(ServerScriptRunner {
            inner,
            pools: self.pools.clone(),
            degraded_logged: self.degraded_logged.clone(),
        })
    }
}

/// One user core's runner (PD-246, PD-248).
pub struct ServerScriptRunner {
    inner: Arc<dyn ScriptRunner>,
    pools: SharedSlots,
    degraded_logged: Arc<AtomicBool>,
}

impl ServerScriptRunner {
    /// PD-248: never degraded in server mode; a degraded policy is replaced (logged once).
    fn strict(&self, policy: RunPolicy) -> RunPolicy {
        if policy.allow_degraded && !self.degraded_logged.swap(true, Ordering::SeqCst) {
            tracing::warn!(event = "degraded_policy_ignored");
        }
        RunPolicy {
            allow_degraded: false,
        }
    }
}

#[async_trait]
impl ScriptRunner for ServerScriptRunner {
    async fn check_available(&self, policy: RunPolicy) -> Result<(), RunnerError> {
        self.inner.check_available(self.strict(policy)).await
    }

    async fn compile_check(
        &self,
        source: &str,
        limits: &ScriptLimits,
        policy: RunPolicy,
    ) -> Result<(), CompileFailure> {
        self.inner
            .compile_check(source, limits, self.strict(policy))
            .await
    }

    fn confinement(&self, policy: RunPolicy) -> Option<RunConfinement> {
        self.inner.confinement(self.strict(policy))
    }

    async fn start(
        &self,
        mut run: RunSpec,
        calls: Arc<dyn HostCalls>,
    ) -> Result<Arc<dyn RunHandle>, RunnerError> {
        run.policy = self.strict(run.policy);
        self.inner.start(run, calls).await
    }

    fn shared_slots(&self) -> Option<SharedSlots> {
        Some(self.pools.clone())
    }
}

#[cfg(test)]
#[path = "tests/scripts.rs"]
mod tests;
