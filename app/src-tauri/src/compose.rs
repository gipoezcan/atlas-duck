//! The composition root of the app side: what `Core::start` needs, assembled from the pieces the
//! app owns (the store, the keychain, the dialog, the UI sink), plus the local UTC offset that
//! the similarity notice text uses (PD-32) and the glibc allocator setting (PD-33).

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use atlas_duck_audit::{KeyStore, Store, SystemClock};
use atlas_duck_core::audit_port::DateBridge;
use atlas_duck_core::config::{CONFIG_FILE_NAME, ConfigReadOnly, ConfigState, load_config};
use atlas_duck_core::http_factory::HttpFactory;
use atlas_duck_core::proxy::SystemProxySource;
use atlas_duck_core::{Core, CoreDeps, KeychainCredentials, NativeConfirmer, StartError, UiSink};
use atlas_duck_sandbox_worker::engine::ENGINE_VERSION;
use serde_json::{Map, Value};

use crate::script_glue::{ScriptGlue, ScriptInputs};
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
    /// M8 Task 20: what the script glue takes from the app (the startup probe's holder, the
    /// update flag, the core's instance list).
    pub scripts: ScriptInputs,
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

/// `CoreDeps` from the app's pieces. A `config.toml` that exists but cannot be read (permissions,
/// a directory at that path, a sharing violation) does not stop the app: it is composed as
/// `Unreadable`, so requests keep working and answer `not_configured`, and the file stays untouched.
pub fn core_deps(i: CoreInputs) -> io::Result<CoreDeps> {
    let config_path = i.config_dir.join(CONFIG_FILE_NAME);
    let config = load_config(&config_path).unwrap_or_else(|_| {
        // Fixed text only: the path and the OS error stay out of the log (opacity).
        tracing::warn!("config_read_failed");
        ConfigState::Unreadable {
            info: ConfigReadOnly {
                schema_version: None,
                parsed: false,
                written_by: None,
            },
        }
    });
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
        // C.0: the real `ScriptRunner` (M8 Task 20). It creates no spawner until a script runs.
        scripts: Some(Arc::new(ScriptGlue::new(i.scripts))),
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

/// Assembles the deps and starts the core.
#[cfg(not(feature = "scripted-approver"))]
pub async fn start_core(i: CoreInputs) -> Result<Core, ComposeError> {
    let deps = core_deps(i).map_err(ComposeError::Config)?;
    Core::start(deps).await.map_err(ComposeError::Start)
}

/// Assembles the deps and starts the core. The test build accepts the mock's plain `http://`
/// origins (§13: "plain http to the mock only through a test-only cargo feature"); `allow_http`
/// exists only under `core/testing`.
#[cfg(feature = "scripted-approver")]
pub async fn start_core(i: CoreInputs) -> Result<Core, ComposeError> {
    use atlas_duck_core::TestHooks;
    let port = Arc::new(i.store.clone());
    let deps = core_deps(i).map_err(ComposeError::Config)?;
    let hooks = TestHooks {
        allow_http: true,
        ..TestHooks::none()
    };
    Core::start_with_port(deps, port, hooks)
        .await
        .map_err(ComposeError::Start)
}

/// The UTC offset of the local time zone in minutes east of UTC, `None` when the OS cannot say
/// (the notice text then falls back to UTC).
pub fn local_utc_offset_minutes() -> Option<i32> {
    read_utc_offset(false)
}

#[cfg(unix)]
unsafe extern "C" {
    /// POSIX `tzset`; the `libc` crate does not declare it.
    fn tzset();
}

/// `refresh` re-reads the zone setting first (Unix only: glibc's `localtime_r` does not re-read
/// it on each call). Only the offset updater thread passes `true`: `tzset` races with `setenv`
/// elsewhere, so it must not run from any other thread.
fn read_utc_offset(refresh: bool) -> Option<i32> {
    #[cfg(unix)]
    {
        // SAFETY: `tzset` takes no arguments (see the single-thread caveat above); `time(NULL)`
        // has no preconditions; `localtime_r` writes only to the zeroed `tm` it is given and
        // reads the `time_t` by pointer.
        unsafe {
            if refresh {
                tzset();
            }
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
        let _ = refresh;
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
        let _ = refresh;
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

/// The offset to hand to the core for a new reading, `None` when nothing is to be set: a failed
/// reading keeps the previous offset, an unchanged one needs no call.
fn offset_to_apply(last: Option<i32>, reading: Option<i32>) -> Option<i32> {
    reading.filter(|v| Some(*v) != last)
}

/// Sets the offset now and then every hour (PD-32). The thread holds the core weakly: it ends
/// at the first wake-up after the core is gone. A failed reading never replaces a good offset.
pub fn spawn_offset_updater(core: Arc<Core>) {
    let mut last = local_utc_offset_minutes();
    core.set_utc_offset(last);
    let weak: Weak<Core> = Arc::downgrade(&core);
    drop(core);
    let spawned = std::thread::Builder::new()
        .name("atlas-duck-utc-offset".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(OFFSET_REFRESH);
                let Some(core) = weak.upgrade() else { return };
                let reading = read_utc_offset(true);
                if let Some(v) = offset_to_apply(last, reading) {
                    core.set_utc_offset(Some(v));
                    last = Some(v);
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
pub fn set_mmap_threshold() -> bool {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: `mallopt` only sets an allocator parameter; it is called at process start.
        unsafe { libc::mallopt(libc::M_MMAP_THRESHOLD, MMAP_THRESHOLD_BYTES) == 1 }
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        false
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
            scripts: ScriptInputs::default(),
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
        assert!(deps.scripts.is_some());
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

    /// C.0 (M8 Task 20): the core gets the real runner, over the app's probe holder: what the
    /// startup probe reports there is what the runner admits runs under. Composing it spawns
    /// nothing and creates no spawner.
    #[test]
    fn compose_wires_scripts_some() -> TestResult {
        use atlas_duck_core::{ConfinementMode, RunPolicy};
        use atlas_duck_ipc::sandbox::probe::ConfinementReport;
        use atlas_duck_sandbox_host::identity::{SandboxBinaryIdentity, file_identity};
        use atlas_duck_sandbox_host::probe::{FloorVerdict, ProbeReport};

        let (_dir, _lock, mut inputs) = temp_inputs(None)?;
        let scripts = ScriptInputs::default();
        inputs.scripts = scripts.clone();
        let deps = core_deps(inputs)?;
        let runner = deps.scripts.clone().ok_or("no script runner")?;
        // No probe report yet: the runner states no confinement.
        assert!(runner.confinement(RunPolicy::default()).is_none());
        let (file_id, size, mtime) =
            file_identity(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))?;
        let report = ConfinementReport {
            applied: true,
            mechanism: "probe".to_owned(),
            no_new_privs: None,
            landlock_abi: None,
            seccomp: None,
            lpac: None,
            os_error: None,
        };
        let _ = scripts.probe.set(ProbeReport {
            worker_version: Some("v1".to_owned()),
            engine_version: None,
            identity: Some(SandboxBinaryIdentity {
                file_id,
                size,
                mtime,
                embedded_version: "v1".to_owned(),
            }),
            confinement: Some(report.clone()),
            threads: None,
            records: Vec::new(),
            floor: FloorVerdict::Met,
            extra_layers: Vec::new(),
            control: None,
            lpac_failed: None,
        });
        let admitted = runner
            .confinement(RunPolicy::default())
            .ok_or("the probe report did not reach the runner")?;
        assert_eq!(admitted.mode, ConfinementMode::Floor);
        assert_eq!(admitted.worker_version, "v1");
        assert_eq!(admitted.probe_report, Some(report));
        deps.audit.shutdown();
        Ok(())
    }

    #[test]
    fn core_deps_composes_an_unreadable_config_as_unreadable() -> TestResult {
        let (dir, _lock, inputs) = temp_inputs(None)?;
        // A directory where the file should be cannot be read as a config.
        std::fs::create_dir(dir.path().join("config.toml"))?;
        let inputs_store = inputs.store.clone();
        let deps = core_deps(inputs)?;
        assert!(matches!(deps.config, ConfigState::Unreadable { .. }));
        // Left untouched: still a directory.
        assert!(dir.path().join("config.toml").is_dir());
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
    fn offset_update_decision() {
        // A failed reading keeps the previous offset, whatever it was.
        assert_eq!(offset_to_apply(Some(60), None), None);
        assert_eq!(offset_to_apply(None, None), None);
        // The same value needs no call.
        assert_eq!(offset_to_apply(Some(60), Some(60)), None);
        // A changed value, or a first good one, is applied.
        assert_eq!(offset_to_apply(Some(60), Some(120)), Some(120));
        assert_eq!(offset_to_apply(None, Some(0)), Some(0));
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
        // Not VmRSS: the other tests of this process run in parallel and allocate, so process RSS
        // is noise. `hblkhd` (bytes in mmapped blocks) grows by the block size while an allocation
        // above the threshold is held; a heap-served block never moves it. A concurrent test
        // freeing a mapped block can mask one attempt, so each attempt holds sixteen blocks at once
        // (masking needs fifteen concurrent frees) and one clean attempt of eight suffices.
        fn mapped_bytes() -> usize {
            // SAFETY: `mallinfo2` only reads allocator statistics.
            unsafe { libc::mallinfo2() }.hblkhd
        }
        assert!(set_mmap_threshold(), "mallopt(M_MMAP_THRESHOLD) failed");
        let grew = (0..8).any(|_| {
            let before = mapped_bytes();
            let held: Vec<Vec<u8>> = (0..16).map(|_| vec![1u8; 2 << 20]).collect();
            std::hint::black_box(&held);
            mapped_bytes().saturating_sub(before) >= 2 << 20
        });
        assert!(grew, "a 2 MiB block was not served by mmap");
        Ok(())
    }
}
