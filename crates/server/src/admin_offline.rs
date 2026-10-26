//! Transitional hidden `atlas-duck-server admin instances add|list|remove` (PD-212, L223): opens
//! the server store directly so the CI smoke test can seed an instance without an admin login,
//! and refuses while a `serve` process holds `<data>/server/instance.lock` (`admin/server_running`,
//! exit 1). It calls the same `instances` functions as the routes; M13 T5 replaces this module
//! with the admin socket client and deletes it.

use std::io::Write;
use std::sync::Arc;

use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};
use serde_json::{Map, Value};

use crate::cli::{EXIT_CONFIG, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, config_error_fields};
use crate::clock::SystemClock;
use crate::config::Config;
use crate::instances::{self, CA_REF_ORG, InstanceSpec};
use crate::master_key::MasterKey;
use crate::runtime::{Registry, RuntimeDeps};
use crate::store::ServerStore;
use crate::store::sqlite::SqliteStore;

const LOCK_HOST: &str = "atlas-duck-server-admin";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminCmd {
    List,
    Add(InstanceSpec),
    Remove(String),
}

/// `instances add --alias A --product jira --url U [--default] [--ca-org] [--proxy P]`,
/// `instances list`, `instances remove --alias A`.
pub fn parse(args: &[String]) -> Option<AdminCmd> {
    let (first, rest) = args.split_first()?;
    if first != "instances" {
        return None;
    }
    let (sub, flags) = rest.split_first()?;
    let mut alias = None;
    let mut product = None;
    let mut url = None;
    let mut proxy = None;
    let mut is_default = false;
    let mut ca_org = false;
    let mut it = flags.iter();
    while let Some(f) = it.next() {
        match f.as_str() {
            "--alias" => alias = Some(it.next()?.clone()),
            "--product" => product = Some(it.next()?.clone()),
            "--url" => url = Some(it.next()?.clone()),
            "--proxy" => proxy = Some(it.next()?.clone()),
            "--default" => is_default = true,
            "--ca-org" => ca_org = true,
            _ => return None,
        }
    }
    match sub.as_str() {
        "list" if flags.is_empty() => Some(AdminCmd::List),
        "remove" if product.is_none() && url.is_none() => Some(AdminCmd::Remove(alias?)),
        "add" => Some(AdminCmd::Add(InstanceSpec {
            alias: alias?,
            product: product?,
            base_url: url?,
            proxy,
            ca_ref: ca_org.then(|| CA_REF_ORG.to_owned()),
            is_default,
        })),
        _ => None,
    }
}

fn error_line(code: &'static str) {
    let mut m = Map::new();
    m.insert("event".into(), Value::from("admin_error"));
    m.insert("code".into(), Value::from(code));
    crate::log::stderr_line("error", m);
}

pub fn run(args: &[String]) -> u8 {
    let Some(cmd) = parse(args) else {
        let _ = std::io::stderr().write_all(
            b"usage: atlas-duck-server admin instances <list|add --alias A --product P --url U [--default] [--ca-org] [--proxy P]|remove --alias A>\n",
        );
        return EXIT_USAGE;
    };
    let config = match Config::from_env(&|k| std::env::var(k).ok(), &|| {
        std::env::vars_os()
            .filter_map(|(k, _)| k.into_string().ok())
            .collect()
    }) {
        Ok(c) => c,
        Err(e) => {
            crate::log::stderr_line("error", config_error_fields(&e));
            return EXIT_CONFIG;
        }
    };
    let master = match MasterKey::load(&config.master_key_file) {
        Ok(m) => Arc::new(m),
        Err(e) => {
            crate::log::stderr_line("error", config_error_fields(&e));
            return EXIT_CONFIG;
        }
    };
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return EXIT_RUNTIME;
    };
    rt.block_on(execute(cmd, &config, master))
}

/// Runs `cmd` against the server store of `config`'s data dir, refusing while it is locked.
pub async fn execute(cmd: AdminCmd, config: &Config, master: Arc<MasterKey>) -> u8 {
    let data = config.data_dir.path().to_path_buf();
    let server_dir = data.join("server");
    if std::fs::create_dir_all(&server_dir).is_err() {
        error_line("admin/server_dir_unusable");
        return EXIT_RUNTIME;
    }
    let Ok(DataDirResolution::Local(local)) = check_data_dir(&server_dir) else {
        error_line("admin/server_dir_unusable");
        return EXIT_RUNTIME;
    };
    let Ok(_lock) = InstanceLock::acquire(&local, LOCK_HOST) else {
        error_line("admin/server_running");
        return EXIT_RUNTIME;
    };
    let store: Arc<dyn ServerStore> = match SqliteStore::open(&server_dir.join("server.db")) {
        Ok(s) => Arc::new(s),
        Err(_) => {
            error_line("store/unavailable");
            return EXIT_RUNTIME;
        }
    };
    let registry = Registry::new(
        RuntimeDeps {
            data_dir: data,
            store: store.clone(),
            master,
            org_ca: config.ca_bundle_file.clone(),
            clock: Arc::new(SystemClock),
            allow_http: false,
        },
        config.max_open_users,
    );
    let out = match cmd {
        AdminCmd::List => instances::list(store.as_ref()).map(|views| {
            let mut stdout = std::io::stdout();
            for v in views {
                let _ = writeln!(stdout, "{}", serde_json::to_string(&v).unwrap_or_default());
            }
        }),
        AdminCmd::Add(spec) => instances::add(store.as_ref(), &registry, spec)
            .await
            .map(drop),
        AdminCmd::Remove(alias) => instances::remove(store.as_ref(), &registry, &alias).await,
    };
    registry.close_all().await;
    match out {
        Ok(()) => EXIT_OK,
        Err(e) => {
            error_line(e.code);
            EXIT_RUNTIME
        }
    }
}
