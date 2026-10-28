//! `serve`: config → logging (done by `cli`) → master key → server store (under its lock) →
//! directory → registry → anchor rows → listen; on SIGTERM / Ctrl-C stop accepting, close every
//! runtime (`APP_STOP` in each chain), append `SERVER_STOP`, exit 0.

use std::future::IntoFuture;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_ipc::paths::{DataDirResolution, LocalDataDir};
use serde_json::json;

use crate::admin::AdminCtx;
use crate::anchor::AnchorWriter;
use crate::cli::{EXIT_CONFIG, EXIT_OK, EXIT_RUNTIME, config_error_fields};
use crate::clock::{Clock, SystemClock};
use crate::config::{Config, ConfigError, DirectoryConfig};
use crate::directory::Directory;
use crate::directory::account::AccountLookup;
use crate::directory::ldap::{LdapDirectory, LdapServiceLookup};
use crate::directory::stub::StubDirectory;
use crate::directory::tls::client_config;
use crate::health::Health;
use crate::login::LoginService;
use crate::master_key::MasterKey;
use crate::ratelimit::LoginLimiter;
use crate::runtime::{Registry, RegistrySink, RuntimeDeps};
use crate::scheduler::Scheduler;
use crate::session::SessionTable;
use crate::static_files::WebDir;
use crate::store::sqlite::SqliteStore;
use crate::store::{ServerStore, StoreError};
use crate::web::{AppInner, AppState, router};

const LOCK_HOST: &str = "atlas-duck-server";

/// Why `<data>/server` cannot be used: the check that failed, the path, and the I/O error kind
/// (with its OS error number) or the locality verdict. Never a file's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirRefusal {
    pub check: &'static str,
    pub path: PathBuf,
    pub reason: String,
}

fn io_reason(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => format!("{:?} (os error {n})", e.kind()),
        None => format!("{:?}", e.kind()),
    }
}

/// `uid:gid mode` of `path` (Unix), for a refusal's log line; `unknown` when it cannot be read.
pub(crate) fn owner_of(path: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if let Ok(m) = std::fs::metadata(path) {
            return format!(
                "{}:{} {:o}",
                m.uid(),
                m.gid(),
                m.permissions().mode() & 0o7777
            );
        }
    }
    let _ = path;
    "unknown".into()
}

/// Creates (or reuses) `<data>/server`, closes it to everyone else (0700, Unix), checks that it
/// can be written and that it passes the data-dir check of the journal mode (ADR 0004).
pub(crate) fn prepare_server_dir(
    data: &Path,
    journal: atlas_duck_audit::JournalMode,
) -> Result<LocalDataDir, DirRefusal> {
    let dir = data.join("server");
    let refuse = |check: &'static str, reason: String| DirRefusal {
        check,
        path: dir.clone(),
        reason,
    };
    std::fs::create_dir_all(&dir).map_err(|e| refuse("create", io_reason(&e)))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| refuse("mode", io_reason(&e)))?;
    }
    let probe = dir.join(".write-probe");
    std::fs::write(&probe, b"")
        .and_then(|()| std::fs::remove_file(&probe))
        .map_err(|e| refuse("write", io_reason(&e)))?;
    match crate::config::check_dir(&dir, journal) {
        Ok(DataDirResolution::Local(l)) => Ok(l),
        Ok(DataDirResolution::NotLocal { kind, .. }) => {
            Err(refuse("locality", format!("{kind:?}")))
        }
        Ok(other) => Err(refuse("exists", format!("{other:?}"))),
        Err(e) => Err(refuse("locality", io_reason(&e))),
    }
}

/// A startup or runtime refusal with the reason it happened (an error kind or message, never a
/// secret).
fn fail_why(event: &'static str, reason: impl std::fmt::Display) -> u8 {
    tracing::error!(event, reason = %reason);
    EXIT_RUNTIME
}

fn fail(event: &'static str) -> u8 {
    tracing::error!(event);
    EXIT_RUNTIME
}

/// Runs the server until shutdown; answers the process exit code.
pub fn serve(config: Config) -> u8 {
    // ADR 0004: the data volume's group is the process's own (gid 0 on NFS), so nothing the
    // server creates is group or other accessible.
    let _ = atlas_duck_ipc::paths::restrict_umask();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail_why("runtime_start_failed", io_reason(&e)),
    };
    rt.block_on(run(config))
}

async fn run(config: Config) -> u8 {
    let master = match MasterKey::load(&config.master_key_file) {
        Ok(m) => Arc::new(m),
        Err(e) => {
            crate::log::stderr_line("error", config_error_fields(&e));
            return EXIT_CONFIG;
        }
    };
    // M13 T7: during a rotation the next key is accepted too, so a restart mid-way still opens
    // every user (rows already re-wrapped carry the next key's id).
    let mut next_id = None;
    if let Some(next) = &config.master_key_next_file {
        let accepted = MasterKey::load(next).ok().map(|k| {
            next_id = Some(k.id());
            master.accept(k).is_ok()
        });
        if accepted != Some(true) {
            crate::log::stderr_line(
                "error",
                config_error_fields(&ConfigError {
                    code: "config/master_key_next_invalid",
                    key: crate::config::MASTER_KEY_NEXT_FILE,
                }),
            );
            return EXIT_CONFIG;
        }
    }
    let data = config.data_dir.path().to_path_buf();
    let server_dir = data.join("server");
    let local = match prepare_server_dir(&data, config.sqlite_journal) {
        Ok(l) => l,
        Err(r) => {
            tracing::error!(
                event = "server_dir_unusable",
                check = r.check,
                path = %r.path.display(),
                reason = %r.reason,
                data_dir_owner = %owner_of(&data),
            );
            return EXIT_RUNTIME;
        }
    };
    // ADR 0003: one process per data volume.
    let _lock = match InstanceLock::acquire(&local, LOCK_HOST) {
        Ok(l) => l,
        Err(e) => return fail_why("server_running", format!("{e:?}")),
    };
    let store: Arc<dyn ServerStore> =
        match SqliteStore::open_with(&server_dir.join("server.db"), config.sqlite_journal) {
            Ok(s) => Arc::new(s),
            Err(StoreError::Migration { from, to }) => {
                // M13 Δ-M13-3: the file stays at `from`; an older build can still open it.
                tracing::error!(event = "store/migration_failed", from, to);
                return EXIT_RUNTIME;
            }
            Err(e) => return fail_why("server_store_unavailable", e),
        };
    // Batch-2 review I1: a rotation under way (the next key already wraps rows) keeps the next key
    // as the primary across restarts, so no new data key goes under the key about to retire.
    if let Some(id) = &next_id {
        match crate::admin::rotate::promote_next_if_in_use(&master, store.as_ref(), id) {
            Ok(true) => tracing::warn!(event = "rotation_in_progress", primary = %id),
            Ok(false) => {}
            Err(e) => return fail_why("server_store_unavailable", e),
        }
    }
    // The login directory, and the offboarding check's account lookup (M13 T9, PD-M13-14): the
    // LDAP service bind when configured, the test directory's file, else none (manual).
    let (directory, lookup): (Arc<dyn Directory>, Option<Arc<dyn AccountLookup>>) =
        match &config.directory {
            DirectoryConfig::Ldap {
                url,
                upn_suffix,
                base_dn,
            } => {
                let tls = match client_config(config.ca_bundle_file.as_deref()) {
                    Ok(t) => t,
                    Err(e) => return fail_why("ca_bundle_unusable", format!("{e:?}")),
                };
                let lookup: Option<Arc<dyn AccountLookup>> = match &config.service_bind {
                    None => None,
                    Some(bind) => {
                        let Some(password) = read_secret_file(&bind.password_file) else {
                            crate::log::stderr_line(
                                "error",
                                config_error_fields(&ConfigError {
                                    code: "config/service_bind_password_unreadable",
                                    key: crate::config::SERVICE_BIND_PASSWORD_FILE,
                                }),
                            );
                            return EXIT_CONFIG;
                        };
                        Some(Arc::new(LdapServiceLookup::new(
                            url.clone(),
                            upn_suffix.clone(),
                            base_dn.clone(),
                            tls.clone(),
                            bind.dn.clone(),
                            password,
                        )))
                    }
                };
                let dir = Arc::new(LdapDirectory::new(
                    url.clone(),
                    upn_suffix.clone(),
                    base_dn.clone(),
                    tls,
                ));
                (dir, lookup)
            }
            DirectoryConfig::Stub { file } => match StubDirectory::from_file(file) {
                Ok(d) => {
                    tracing::warn!(event = "test_directory_active", users = d.user_count());
                    let d = Arc::new(d);
                    (d.clone(), Some(d))
                }
                Err(e) => return fail_why("test_directory_unusable", format!("{e:?}")),
            },
        };
    let offboarding = match (&lookup, &config.directory) {
        (None, _) => "manual",
        (Some(_), DirectoryConfig::Stub { .. }) => "stub",
        (Some(_), DirectoryConfig::Ldap { .. }) => "directory",
    };
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    // M14 PD-246..PD-249: the worker must exist before listening; the probe runs in the
    // background (readiness does not wait for it).
    let scripts = if config.scripts.enabled {
        if !crate::scripts::sandbox_bin_ok(&config.scripts.sandbox_bin) {
            crate::log::stderr_line(
                "error",
                config_error_fields(&crate::config::ConfigError {
                    code: "config/sandbox_bin_invalid",
                    key: crate::config::SANDBOX_BIN,
                }),
            );
            return EXIT_CONFIG;
        }
        Some(Arc::new(crate::scripts::ServerScripts::start(
            config.scripts.clone(),
            &data,
        )))
    } else {
        tracing::warn!(event = "scripts_disabled");
        None
    };
    let registry = Arc::new(Registry::new(
        RuntimeDeps {
            data_dir: data,
            store: store.clone(),
            master: master.clone(),
            org_ca: config.ca_bundle_file.clone(),
            clock: clock.clone(),
            allow_http: false,
            sse_capacity: crate::runtime::SSE_CAPACITY,
            scripts: scripts.clone(),
            journal: config.sqlite_journal,
        },
        config.max_open_users,
    ));
    let ip_key = master.derive(crate::oauth::IP_KEY_LABEL);
    let sessions = match SessionTable::new(
        store.clone(),
        clock.clone(),
        config.session_absolute.as_secs(),
        config.session_idle.as_secs(),
    ) {
        Ok(s) => Arc::new(s),
        Err(e) => return fail_why("server_store_unavailable", e),
    };
    let sweeper = sessions.spawn_sweeper();
    let login = LoginService {
        store: store.clone(),
        master: master.clone(),
        directory: directory.clone(),
        limiter: Arc::new(LoginLimiter::new(
            config.login_limit_user,
            config.login_limit_ip,
            config.login_window.as_secs(),
        )),
        sessions: sessions.clone(),
        groups: config.groups.clone(),
        clock: clock.clone(),
        sink: Arc::new(RegistrySink(registry.clone())),
    };
    let api_keys = match crate::api_keys::ApiKeys::new(
        store.clone(),
        clock.clone(),
        crate::api_keys::ApiKeyParams::PRODUCTION,
    ) {
        Ok(k) => Arc::new(k),
        Err(e) => return fail_why("api_keys_unusable", format!("{e:?}")),
    };
    let writer = Arc::new(AnchorWriter::new(
        store.clone(),
        registry.clone(),
        clock.clone(),
    ));
    let oauth = Arc::new(crate::oauth::OAuth::new(
        config.oauth,
        &config.public_origin(),
        ip_key,
    ));
    // M14 PD-254: export jobs under <data>/exports; the TTL sweep runs now and hourly.
    let exports = Arc::new(crate::export_job::ExportJobs::new(
        store.clone(),
        registry.clone(),
        writer.clone(),
        clock.clone(),
        config.data_dir.path(),
        &config.public_origin(),
        config.exports,
    ));
    let swept = exports.sweep(true);
    if swept > 0 {
        tracing::info!(event = "export_ttl", removed = swept);
    }
    let state = AppState(Arc::new(AppInner {
        public_origin: config.public_origin(),
        cookie_secure: config.cookie_secure(),
        trusted_proxy_hops: config.trusted_proxy_hops,
        store: store.clone(),
        sessions,
        login,
        registry: registry.clone(),
        web: WebDir(config.web_dir.clone()),
        health: Arc::new(
            Health::new(store.clone(), directory, true)
                .with_master(master.clone())
                .with_offboarding(offboarding)
                .with_registry(registry.clone())
                .with_scripts(scripts.clone()),
        ),
        api_keys,
        mcp_sessions: Arc::new(crate::mcp::McpSessions::new()),
        clock: clock.clone(),
        anchor: writer.clone(),
        oauth,
        exports: exports.clone(),
    }));
    let started = json!({"version": env!("CARGO_PKG_VERSION"), "mode": format!("{:?}", config.mode).to_lowercase()});
    if let Err(e) = writer.start(&started) {
        return fail_why("anchor_append_failed", format!("{e:?}"));
    }
    let anchor_timer = writer.spawn(config.anchor_interval);
    // Batch-1 review I-1: a restore interrupted by a crash keeps the server in maintenance.
    if crate::admin::restore::interrupted(config.data_dir.path()) {
        registry.set_maintenance(true);
        tracing::error!(
            event = "store/restore_interrupted",
            recover = "admin restore --resume (finish) or admin restore <data>/backups/pre-restore-* (go back), then admin maintenance off"
        );
    }
    let admin = Arc::new(
        AdminCtx::new(
            store.clone(),
            registry.clone(),
            state.sessions.clone(),
            state.api_keys.clone(),
            writer.clone(),
            clock.clone(),
            config.retention_days,
        )
        .with_max_stream_bytes(config.max_restore_bytes)
        .with_scheduled_backups(config.backup_dir.clone(), config.backup_keep),
    );
    let scheduler = Arc::new(Scheduler::new(admin.clone(), lookup, config.offboarding_at));
    let scheduler_task = scheduler.spawn();
    let Some(admin_task) = start_admin_socket(&config, admin) else {
        return fail("admin_socket_unusable");
    };
    // M14 PD-240: the daily `oauth_purge` job (an interval task: M13's scheduler runs daily slots only).
    let purge_store = store.clone();
    let purge_clock = clock.clone();
    let oauth_purge = tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_secs(86_400));
        loop {
            t.tick().await;
            let (s, now) = (purge_store.clone(), purge_clock.now());
            let _ = tokio::task::spawn_blocking(move || crate::oauth::purge(s.as_ref(), now)).await;
        }
    });
    // M14 PD-257: auditors' store views close after 5 minutes idle.
    let views_registry = registry.clone();
    let idle_views = tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            t.tick().await;
            views_registry.close_idle_views().await;
        }
    });
    // M14 PD-254: the hourly `export_ttl` job (an interval task: M13's scheduler runs daily slots only).
    let ttl_exports = exports.clone();
    let export_ttl = tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            t.tick().await;
            let e = ttl_exports.clone();
            let _ = tokio::task::spawn_blocking(move || e.sweep(false)).await;
        }
    });
    let listener = match tokio::net::TcpListener::bind(config.listen).await {
        Ok(l) => l,
        Err(e) => return fail_why("listen_failed", io_reason(&e)),
    };
    tracing::info!(event = "listening", addr = %config.listen);
    // M13 T10: /metrics on a listener of its own, which the Ingress never routes.
    let metrics_task = match config.metrics_listen {
        None => None,
        Some(addr) => match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                tracing::info!(event = "metrics_listening", addr = %addr);
                let router = crate::web::metrics_router(state.clone());
                Some(tokio::spawn(async move {
                    if axum::serve(l, router).await.is_err() {
                        tracing::error!(event = "metrics_serve_failed");
                    }
                }))
            }
            Err(e) => return fail_why("metrics_listen_failed", io_reason(&e)),
        },
    };
    let served = serve_until(listener, state, &writer, shutdown_signal(), DRAIN).await;
    sweeper.abort();
    anchor_timer.abort();
    oauth_purge.abort();
    idle_views.abort();
    export_ttl.abort();
    admin_task.abort();
    scheduler_task.abort();
    if let Some(m) = metrics_task {
        m.abort();
    }
    let _ = std::fs::remove_file(&config.admin_socket);
    match served {
        Ok(()) => {
            tracing::info!(event = "stopped");
            EXIT_OK
        }
        Err(e) => fail_why("serve_failed", format!("{e:?}")),
    }
}

/// A secret file's content without its trailing newline (the service-bind password, M13 T9).
/// Never logged; `None` when unreadable or empty.
pub fn read_secret_file(path: &std::path::Path) -> Option<secrecy::SecretString> {
    let text = zeroize::Zeroizing::new(std::fs::read_to_string(path).ok()?);
    let line = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    (!line.is_empty()).then(|| secrecy::SecretString::from(line.to_owned()))
}

/// Binds the admin socket (M13 PD-M13-1) and serves it; `None` when it cannot be bound (the
/// server does not start without its admin interface).
#[cfg(unix)]
fn start_admin_socket(config: &Config, ctx: Arc<AdminCtx>) -> Option<tokio::task::JoinHandle<()>> {
    let (listener, uid) = match crate::admin::socket::bind(&config.admin_socket) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(event = "admin_socket_bind_failed", error = %e);
            return None;
        }
    };
    tracing::info!(event = "admin_socket_listening");
    Some(tokio::spawn(crate::admin::socket::serve(
        listener, uid, ctx,
    )))
}

/// No Unix sockets here: the admin CLI is unavailable (the server image is Linux only).
#[cfg(not(unix))]
fn start_admin_socket(
    _config: &Config,
    _ctx: Arc<AdminCtx>,
) -> Option<tokio::task::JoinHandle<()>> {
    tracing::warn!(event = "admin_socket_unsupported");
    Some(tokio::spawn(async {}))
}

/// How long open connections may drain after the shutdown signal. SSE streams never end on their
/// own, so the wait is bounded: drain plus closing the runtimes stays inside the chart's 30 s
/// `terminationGracePeriodSeconds` (M13 A-13).
pub const DRAIN: Duration = Duration::from_secs(10);

/// Serves `state` on `listener` until `signal`, lets connections drain for at most `drain`, then
/// closes every runtime and appends the final heads and `SERVER_STOP`.
pub async fn serve_until(
    listener: tokio::net::TcpListener,
    state: AppState,
    writer: &AnchorWriter,
    signal: impl Future<Output = ()> + Send + 'static,
    drain: Duration,
) -> std::io::Result<()> {
    let exports = state.0.exports.clone();
    let (fired_tx, fired_rx) = tokio::sync::oneshot::channel::<()>();
    let serve = axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        signal.await;
        let _ = fired_tx.send(());
    });
    let drained = async move {
        if fired_rx.await.is_ok() {
            tokio::time::sleep(drain).await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    let served = tokio::select! {
        r = serve.into_future() => r,
        () = drained => {
            tracing::warn!(event = "shutdown_drain_elapsed");
            Ok(())
        }
    };
    // M14 PD-254: running exports are cancelled and awaited before the stores close.
    exports.shutdown().await;
    // Final heads (RUNTIME_CLOSED per runtime, after its APP_STOP) and SERVER_STOP.
    if writer.shutdown().await.is_err() {
        tracing::error!(event = "anchor_append_failed", kind = "SERVER_STOP");
    }
    served
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod dir_tests {
    use atlas_duck_audit::JournalMode;

    use super::*;

    #[test]
    fn the_server_dir_is_created_writable_and_private() {
        let data = tempfile::tempdir().unwrap();
        let local = prepare_server_dir(data.path(), JournalMode::Delete).unwrap();
        assert_eq!(local.path(), data.path().join("server"));
        assert!(!data.path().join("server").join(".write-probe").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(data.path().join("server"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        // Again on the existing directory.
        assert!(prepare_server_dir(data.path(), JournalMode::Wal).is_ok());
    }

    #[test]
    fn a_refusal_names_the_check_the_path_and_the_reason() {
        let data = tempfile::tempdir().unwrap();
        std::fs::write(data.path().join("server"), b"not a dir").unwrap();
        let r = prepare_server_dir(data.path(), JournalMode::Delete).unwrap_err();
        assert_eq!(r.check, "create");
        assert_eq!(r.path, data.path().join("server"));
        assert!(
            r.reason.contains("AlreadyExists") || r.reason.contains("NotADirectory"),
            "{}",
            r.reason
        );
        assert!(r.reason.contains("os error"), "{}", r.reason);
    }

    #[cfg(unix)]
    #[test]
    fn a_data_dir_this_user_cannot_write_is_refused_at_create() {
        use std::os::unix::fs::PermissionsExt;
        let data = tempfile::tempdir().unwrap();
        std::fs::set_permissions(data.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let r = prepare_server_dir(data.path(), JournalMode::Delete);
        std::fs::set_permissions(data.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // Root writes anyway; everyone else gets the reason.
        if let Err(r) = r {
            assert_eq!(r.check, "create");
            assert!(r.reason.contains("PermissionDenied"), "{}", r.reason);
            assert!(owner_of(data.path()).contains(' '));
        }
    }
}
