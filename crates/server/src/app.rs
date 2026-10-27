//! `serve`: config → logging (done by `cli`) → master key → server store (under its lock) →
//! directory → registry → anchor rows → listen; on SIGTERM / Ctrl-C stop accepting, close every
//! runtime (`APP_STOP` in each chain), append `SERVER_STOP`, exit 0.

use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};
use serde_json::json;

use crate::anchor::AnchorWriter;
use crate::cli::{EXIT_CONFIG, EXIT_OK, EXIT_RUNTIME, config_error_fields};
use crate::clock::{Clock, SystemClock};
use crate::config::{Config, DirectoryConfig};
use crate::directory::Directory;
use crate::directory::ldap::LdapDirectory;
use crate::directory::stub::StubDirectory;
use crate::directory::tls::client_config;
use crate::health::Health;
use crate::login::LoginService;
use crate::master_key::MasterKey;
use crate::ratelimit::LoginLimiter;
use crate::runtime::{Registry, RegistrySink, RuntimeDeps};
use crate::session::SessionTable;
use crate::static_files::WebDir;
use crate::store::ServerStore;
use crate::store::sqlite::SqliteStore;
use crate::web::{AppInner, AppState, router};

const LOCK_HOST: &str = "atlas-duck-server";

fn fail(event: &'static str) -> u8 {
    tracing::error!(event);
    EXIT_RUNTIME
}

/// Runs the server until shutdown; answers the process exit code.
pub fn serve(config: Config) -> u8 {
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return fail("runtime_start_failed");
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
    let data = config.data_dir.path().to_path_buf();
    let server_dir = data.join("server");
    if std::fs::create_dir_all(&server_dir).is_err() {
        return fail("server_dir_unusable");
    }
    let Ok(DataDirResolution::Local(local)) = check_data_dir(&server_dir) else {
        return fail("server_dir_unusable");
    };
    // ADR 0003: one process per data volume.
    let Ok(_lock) = InstanceLock::acquire(&local, LOCK_HOST) else {
        return fail("server_running");
    };
    let store: Arc<dyn ServerStore> = match SqliteStore::open(&server_dir.join("server.db")) {
        Ok(s) => Arc::new(s),
        Err(_) => return fail("server_store_unavailable"),
    };
    let directory: Arc<dyn Directory> = match &config.directory {
        DirectoryConfig::Ldap {
            url,
            upn_suffix,
            base_dn,
        } => match client_config(config.ca_bundle_file.as_deref()) {
            Ok(tls) => Arc::new(LdapDirectory::new(
                url.clone(),
                upn_suffix.clone(),
                base_dn.clone(),
                tls,
            )),
            Err(_) => return fail("ca_bundle_unusable"),
        },
        DirectoryConfig::Stub { file } => match StubDirectory::from_file(file) {
            Ok(d) => {
                tracing::warn!(event = "test_directory_active", users = d.user_count());
                Arc::new(d)
            }
            Err(_) => return fail("test_directory_unusable"),
        },
    };
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let registry = Arc::new(Registry::new(
        RuntimeDeps {
            data_dir: data,
            store: store.clone(),
            master: master.clone(),
            org_ca: config.ca_bundle_file.clone(),
            clock: clock.clone(),
            allow_http: false,
            sse_capacity: crate::runtime::SSE_CAPACITY,
        },
        config.max_open_users,
    ));
    let sessions = match SessionTable::new(
        store.clone(),
        clock.clone(),
        config.session_absolute.as_secs(),
        config.session_idle.as_secs(),
    ) {
        Ok(s) => Arc::new(s),
        Err(_) => return fail("server_store_unavailable"),
    };
    let sweeper = sessions.spawn_sweeper();
    let login = LoginService {
        store: store.clone(),
        master,
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
        Err(_) => return fail("api_keys_unusable"),
    };
    let state = AppState(Arc::new(AppInner {
        public_origin: config.public_origin(),
        cookie_secure: config.cookie_secure(),
        trusted_proxy_hops: config.trusted_proxy_hops,
        store: store.clone(),
        sessions,
        login,
        registry: registry.clone(),
        web: WebDir(config.web_dir.clone()),
        health: Arc::new(Health::new(store.clone(), directory, true)),
        api_keys,
        mcp_sessions: Arc::new(crate::mcp::McpSessions::new()),
    }));
    let started = json!({"version": env!("CARGO_PKG_VERSION"), "mode": format!("{:?}", config.mode).to_lowercase()});
    let writer = Arc::new(AnchorWriter::new(
        store.clone(),
        registry.clone(),
        clock.clone(),
    ));
    if writer.start(&started).is_err() {
        return fail("anchor_append_failed");
    }
    let anchor_timer = writer.spawn(config.anchor_interval);
    let Ok(listener) = tokio::net::TcpListener::bind(config.listen).await else {
        return fail("listen_failed");
    };
    tracing::info!(event = "listening", addr = %config.listen);
    let served = serve_until(listener, state, &writer, shutdown_signal(), DRAIN).await;
    sweeper.abort();
    anchor_timer.abort();
    match served {
        Ok(()) => {
            tracing::info!(event = "stopped");
            EXIT_OK
        }
        Err(_) => fail("serve_failed"),
    }
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
