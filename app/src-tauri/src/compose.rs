//! The composition root of the app side: what `Core::start` needs, assembled from the pieces the
//! app owns (the store, the keychain, the dialog, the UI sink), plus the local UTC offset that
//! the similarity notice text uses (PD-32) and the glibc allocator setting (PD-33).

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use atlas_duck_audit::{KeyStore, Store, SystemClock};
use atlas_duck_core::audit_port::DateBridge;
use atlas_duck_core::config::{CONFIG_FILE_NAME, load_config};
use atlas_duck_core::http_factory::HttpFactory;
use atlas_duck_core::proxy::SystemProxySource;
use atlas_duck_core::{Core, CoreDeps, KeychainCredentials, NativeConfirmer, StartError, UiSink};
use atlas_duck_sandbox_worker::engine::ENGINE_VERSION;
use serde_json::{Map, Value};

use crate::tray_host::TrayHost;

/// Everything the app hands to the core at start.
pub struct CoreInputs {
    pub store: Store,
    pub keys: Arc<dyn KeyStore>,
    pub config_dir: PathBuf,
    /// Instance ids whose PAT a restore or recovery deleted (PD-28).
    pub pats_deleted: Vec<String>,
    pub ui: Arc<dyn UiSink>,
    pub confirmer: Arc<dyn NativeConfirmer>,
    /// `None` off Linux (no check there).
    pub tray_host: Option<TrayHost>,
}

/// PD-34: the app's part of the `APP_START` payload. The probe report and the sandbox binary
/// identity are M8's (the probe finishes after `APP_START`).
fn app_start_extra(tray_host: Option<TrayHost>) -> Map<String, Value> {
    let mut extra = Map::new();
    if let Some(t) = tray_host {
        extra.insert("tray_host".to_owned(), Value::String(t.as_str().to_owned()));
    }
    extra.insert(
        "engine_version".to_owned(),
        Value::String(ENGINE_VERSION.to_owned()),
    );
    extra
}

/// `CoreDeps` from the app's pieces. Fails when `config.toml` exists and cannot be read.
pub fn core_deps(i: CoreInputs) -> io::Result<CoreDeps> {
    let config_path = i.config_dir.join(CONFIG_FILE_NAME);
    let config = load_config(&config_path)?;
    let credentials = Arc::new(KeychainCredentials::new(i.keys));
    let http = HttpFactory::new(
        Arc::new(SystemProxySource::new()),
        credentials.clone(),
        Arc::new(DateBridge(Arc::new(i.store.clone()))),
    );
    Ok(CoreDeps {
        audit: i.store,
        clock: Arc::new(SystemClock::new()),
        credentials,
        confirmer: i.confirmer,
        ui: i.ui,
        config,
        config_path: Some(config_path),
        http,
        app_start_extra: app_start_extra(i.tray_host),
        pats_deleted: i.pats_deleted,
        // M8: scripts answer `sandbox_unavailable`, exit 8.
        scripts: None,
    })
}

/// Why the core did not start.
#[derive(Debug)]
pub enum ComposeError {
    Config(io::Error),
    Start(StartError),
}

impl std::fmt::Display for ComposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComposeError::Config(e) => write!(f, "config.toml: {e}"),
            ComposeError::Start(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ComposeError {}

/// Assembles the deps and starts the core. Task 21 adds the `scripted-approver` branch.
pub async fn start_core(i: CoreInputs) -> Result<Core, ComposeError> {
    let deps = core_deps(i).map_err(ComposeError::Config)?;
    Core::start(deps).await.map_err(ComposeError::Start)
}

/// The UTC offset of the local time zone in minutes east of UTC, `None` when the OS cannot say
/// (the notice text then falls back to UTC).
pub fn local_utc_offset_minutes() -> Option<i32> {
    #[cfg(unix)]
    {
        // SAFETY: `time(NULL)` has no preconditions; `localtime_r` writes only to the zeroed
        // `tm` it is given and reads the `time_t` by pointer.
        unsafe {
            let now = libc::time(std::ptr::null_mut());
            let mut tm: libc::tm = std::mem::zeroed();
            if libc::localtime_r(&now, &mut tm).is_null() {
                return None;
            }
            i32::try_from(tm.tm_gmtoff / 60).ok()
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
        // SAFETY: an all-zero TIME_ZONE_INFORMATION is a valid out-value for the call.
        let (id, tzi) = unsafe {
            let mut tzi: TIME_ZONE_INFORMATION = std::mem::zeroed();
            (GetTimeZoneInformation(&mut tzi), tzi)
        };
        windows_offset(id, tzi.Bias, tzi.StandardBias, tzi.DaylightBias)
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

#[cfg(any(windows, test))]
const TIME_ZONE_ID_UNKNOWN: u32 = 0;
#[cfg(any(windows, test))]
const TIME_ZONE_ID_STANDARD: u32 = 1;
#[cfg(any(windows, test))]
const TIME_ZONE_ID_DAYLIGHT: u32 = 2;

/// Windows reports `UTC = local + bias` (minutes, west positive), with an extra bias while
/// standard or daylight time is active. The local offset east of UTC is the negation.
#[cfg(any(windows, test))]
fn windows_offset(id: u32, bias: i32, standard_bias: i32, daylight_bias: i32) -> Option<i32> {
    let extra = match id {
        TIME_ZONE_ID_UNKNOWN => 0,
        TIME_ZONE_ID_STANDARD => standard_bias,
        TIME_ZONE_ID_DAYLIGHT => daylight_bias,
        _ => return None,
    };
    Some(-(bias + extra))
}

/// How often the offset is read again (DST changes while the app runs).
pub const OFFSET_REFRESH: Duration = Duration::from_secs(3600);

/// Sets the offset now and then every hour (PD-32). The thread holds the core weakly: it ends
/// at the first wake-up after the core is gone.
pub fn spawn_offset_updater(core: Arc<Core>) {
    core.set_utc_offset(local_utc_offset_minutes());
    let weak: Weak<Core> = Arc::downgrade(&core);
    drop(core);
    let spawned = std::thread::Builder::new()
        .name("atlas-duck-utc-offset".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(OFFSET_REFRESH);
                match weak.upgrade() {
                    Some(core) => core.set_utc_offset(local_utc_offset_minutes()),
                    None => return,
                }
            }
        });
    if spawned.is_err() {
        tracing::warn!("the UTC offset refresh thread did not start; the offset stays as set");
    }
}

/// PD-33: glibc raises its mmap threshold (up to 32 MiB) the first time a large mapped block is
/// freed, after which the 16-32 MiB read buffers stay resident. Fixing it at 1 MiB keeps them
/// mapped, so `free` returns them. Call before any other thread exists (GUI and `--background`
/// only; `__cli` keeps the default). No effect off linux-gnu.
pub fn set_mmap_threshold() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: `mallopt` only sets an allocator parameter; it is called at process start.
        unsafe {
            libc::mallopt(libc::M_MMAP_THRESHOLD, MMAP_THRESHOLD_BYTES);
        }
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const MMAP_THRESHOLD_BYTES: libc::c_int = 1 << 20;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use atlas_duck_audit::lock::InstanceLock;
    use atlas_duck_audit::testing::{FakeClock, FreeSpaceStub, MemKeyStore, MemKeyring};
    use atlas_duck_audit::{FirstRunInput, OpenConfig, UtcInstant, create_new_store, new_ids};
    use atlas_duck_core::{Confirm, UiEvent};
    use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};
    use secrecy::SecretString;

    use super::*;

    struct NoUi;
    impl UiSink for NoUi {
        fn emit(&self, _: UiEvent) {}
    }

    struct NoConfirm;
    impl NativeConfirmer for NoConfirm {
        fn confirm(&self, _: &str) -> Confirm {
            Confirm::Cancel
        }
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A first-run store in a temp data dir, with the same pieces `core::testing::TempStore`
    /// uses.
    fn temp_inputs(
        tray_host: Option<TrayHost>,
    ) -> Result<(tempfile::TempDir, InstanceLock, CoreInputs), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let data = match check_data_dir(dir.path())? {
            DataDirResolution::Local(d) => d,
            _ => return Err("the temp dir is not a local data dir".into()),
        };
        let lock = InstanceLock::acquire(&data, "testhost")?;
        let start = UtcInstant::parse_rfc3339_ms("2026-10-08T12:00:00.000Z").ok_or("bad start")?;
        let (install_id, chain_id) = new_ids()?;
        let ring = MemKeyring::new();
        let keys: Arc<dyn KeyStore> = Arc::new(MemKeyStore::new(ring, &install_id));
        let mut cfg = OpenConfig::new(Arc::new(FakeClock::new(start)), keys.clone());
        cfg.free_space = Some(FreeSpaceStub::new(u64::MAX));
        let pass = "correct horse battery";
        let store = create_new_store(
            &data,
            &lock,
            cfg,
            FirstRunInput {
                install_id,
                chain_id,
                passphrase: SecretString::from(pass.to_owned()),
                passphrase_confirm: SecretString::from(pass.to_owned()),
                archived_db: None,
            },
        )?;
        let inputs = CoreInputs {
            store,
            keys,
            config_dir: dir.path().to_owned(),
            pats_deleted: Vec::new(),
            ui: Arc::new(NoUi),
            confirmer: Arc::new(NoConfirm),
            tray_host,
        };
        Ok((dir, lock, inputs))
    }

    #[test]
    fn core_deps_from_inputs() -> TestResult {
        let (dir, lock, inputs) = temp_inputs(None)?;
        let deps = core_deps(inputs)?;
        assert_eq!(
            deps.config_path.as_deref(),
            Some(dir.path().join("config.toml").as_path())
        );
        assert!(deps.scripts.is_none());
        assert_eq!(
            deps.app_start_extra.get("engine_version"),
            Some(&Value::String(ENGINE_VERSION.to_owned()))
        );
        assert!(!deps.app_start_extra.contains_key("tray_host"));
        deps.audit.shutdown();

        let (dir2, lock2, inputs) = temp_inputs(Some(TrayHost::Missing))?;
        let deps = core_deps(inputs)?;
        assert_eq!(
            deps.app_start_extra.get("tray_host"),
            Some(&Value::String("missing".to_owned()))
        );
        deps.audit.shutdown();
        drop((lock, lock2, dir, dir2));
        Ok(())
    }

    #[test]
    fn core_deps_refuses_an_unreadable_config() -> TestResult {
        let (dir, _lock, inputs) = temp_inputs(None)?;
        // A directory where the file should be cannot be read as a config.
        std::fs::create_dir(dir.path().join("config.toml"))?;
        let inputs_store = inputs.store.clone();
        assert!(core_deps(inputs).is_err());
        inputs_store.shutdown();
        Ok(())
    }

    #[test]
    fn local_utc_offset_sane() {
        if let Some(m) = local_utc_offset_minutes() {
            assert!((-14 * 60..=14 * 60).contains(&m), "{m}");
        }
    }

    #[test]
    fn windows_bias_maps_to_the_offset_east_of_utc() {
        // Central Europe: bias -60, daylight bias -60 in summer, standard bias 0 in winter.
        assert_eq!(windows_offset(TIME_ZONE_ID_STANDARD, -60, 0, -60), Some(60));
        assert_eq!(
            windows_offset(TIME_ZONE_ID_DAYLIGHT, -60, 0, -60),
            Some(120)
        );
        // US Pacific: bias 480, daylight bias -60.
        assert_eq!(
            windows_offset(TIME_ZONE_ID_DAYLIGHT, 480, 0, -60),
            Some(-420)
        );
        assert_eq!(windows_offset(TIME_ZONE_ID_UNKNOWN, 0, 0, 0), Some(0));
        // TIME_ZONE_ID_INVALID
        assert_eq!(windows_offset(u32::MAX, -60, 0, -60), None);
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn mmap_threshold_set() -> TestResult {
        fn vm_rss_kib() -> Result<u64, Box<dyn std::error::Error>> {
            let status = std::fs::read_to_string("/proc/self/status")?;
            let line = status
                .lines()
                .find(|l| l.starts_with("VmRSS:"))
                .ok_or("no VmRSS")?;
            Ok(line
                .split_whitespace()
                .nth(1)
                .ok_or("no VmRSS value")?
                .parse()?)
        }
        set_mmap_threshold();
        let before = vm_rss_kib()?;
        for _ in 0..64 {
            let mut v = vec![0u8; 2 << 20];
            // Touch the pages so they count towards RSS while allocated.
            for b in v.iter_mut().step_by(4096) {
                *b = 1;
            }
            std::hint::black_box(&v);
        }
        let after = vm_rss_kib()?;
        assert!(
            after.saturating_sub(before) < 32 * 1024,
            "RSS grew from {before} to {after} KiB"
        );
        Ok(())
    }
}
