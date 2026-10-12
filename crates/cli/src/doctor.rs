//! `doctor` (§4.7, PD-31): the CLI's own install checks merged with the app's answer.
//!
//! The local checks are computed here, without the app, so they are reported even when the app
//! refused to start (§7.7) or cannot be reached. The envelope is always `succeeded` (exit 0, the
//! local checks ran): `data = {local, app, app_unavailable}`, where `app` is the app's `doctor`
//! data passed through unchanged, or `null` with `app_unavailable = {code, reason}` taken from the
//! envelope that stopped the CLI. A refused data dir never launches the app; every other state
//! connects like any app command (the launch rules apply).

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};

use atlas_duck_ipc::build_info::{APP_VERSION, BUILD_ID};
use atlas_duck_ipc::envelope::{Envelope, ErrorCode, Status};
use atlas_duck_ipc::paths::keyring::{KeyringLocality, keyring_dirs_for, keyring_locality};
use atlas_duck_ipc::paths::{
    BaseDirs, EndpointLocation, LocalDataDir, REASON_DATA_DIR_NOT_LOCAL, base_dirs,
    endpoint_location, paths_file, read_pinned,
};
use atlas_duck_ipc::rpc::{EmptyParams, method};
use serde_json::{Map, Value, json};

use crate::argv::GlobalOpts;
use crate::connected::{Connector, reach, short_call};
use crate::deadline::Deadline;
use crate::discover::{AppLocation, DataState, Discovery};
use crate::interrupt::Interrupts;
use crate::launch::{LaunchSys, OsLaunchSys};

/// §4.7, verbatim.
pub(crate) const WSL_WARNING: &str = "running inside WSL: call the Windows `atlas-duck.exe` through interop and do not install the Linux package here";

#[cfg(windows)]
const CLI_FILE_NAME: &str = "atlas-duck.exe";
#[cfg(not(windows))]
const CLI_FILE_NAME: &str = "atlas-duck";

/// The machine questions `local_checks` asks, so tests can answer them.
pub(crate) trait DoctorSys {
    fn env(&self, key: &str) -> Option<OsString>;
    /// This executable, canonical.
    fn exe(&self) -> Option<PathBuf>;
    /// The data dir `paths.toml` pins, when the file is readable (the refused states keep no path).
    fn pinned_data_dir(&self, host: &str) -> Option<PathBuf>;
    /// The endpoint location (Unix socket path, Windows pipe-name prefix).
    fn endpoint(&self, data: &LocalDataDir, host: &str) -> Option<String>;
    fn endpoint_present(&self, data: &LocalDataDir, host: &str) -> bool;
    /// `true` local, `false` not local, `None` unknown (and Windows).
    fn keyring_local(&self) -> Option<bool>;
    /// Windows only: `None` elsewhere and when the query failed.
    fn job_blocks_breakaway(&self) -> Option<bool>;
    /// Linux only: `None` elsewhere.
    fn wsl(&self) -> Option<bool>;
}

/// The real machine.
pub(crate) struct OsDoctorSys;

impl DoctorSys for OsDoctorSys {
    fn env(&self, key: &str) -> Option<OsString> {
        std::env::var_os(key)
    }

    fn exe(&self) -> Option<PathBuf> {
        std::env::current_exe().and_then(|p| p.canonicalize()).ok()
    }

    fn pinned_data_dir(&self, host: &str) -> Option<PathBuf> {
        let base: BaseDirs = base_dirs().ok()?;
        read_pinned(&paths_file(&base, host))
            .ok()
            .flatten()
            .map(|p| p.data_dir)
    }

    fn endpoint(&self, data: &LocalDataDir, host: &str) -> Option<String> {
        match endpoint_location(data, host).ok()? {
            EndpointLocation::UnixSocket(path) => Some(path.display().to_string()),
            EndpointLocation::WindowsPipePrefix(prefix) => Some(prefix),
        }
    }

    fn endpoint_present(&self, data: &LocalDataDir, host: &str) -> bool {
        // The launch step's own check, so `doctor` and a launch agree (Unix: with the liveness
        // probe, Windows: the pipe exists).
        LaunchSys::endpoint_present(&OsLaunchSys, data, host)
    }

    fn keyring_local(&self) -> Option<bool> {
        keyring_local_for(std::env::var_os("XDG_DATA_HOME"))
    }

    #[cfg(windows)]
    fn job_blocks_breakaway(&self) -> Option<bool> {
        crate::launch::windows::job_blocks_breakaway()
    }

    #[cfg(not(windows))]
    fn job_blocks_breakaway(&self) -> Option<bool> {
        None
    }

    #[cfg(target_os = "linux")]
    fn wsl(&self) -> Option<bool> {
        Some(Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists())
    }

    #[cfg(not(target_os = "linux"))]
    fn wsl(&self) -> Option<bool> {
        None
    }
}

/// `keyring_local` for this OS with `XDG_DATA_HOME` as given (§8.6): Windows has no keyring dirs
/// to check (`null`); an unresolvable or unexaminable dir is `null` too, never `true`.
pub(crate) fn keyring_local_for(xdg_data_home: Option<OsString>) -> Option<bool> {
    if cfg!(windows) {
        return None;
    }
    keyring_answer(
        keyring_dirs_for(
            atlas_duck_ipc::paths::keyring::DirsOs::CURRENT,
            xdg_data_home,
            &|| base_dirs().map(|b| b.home),
        ),
        &keyring_locality,
    )
}

/// The mapping of `keyring_local_for`, with the dirs and the locality check injected.
fn keyring_answer(
    dirs: io::Result<Vec<PathBuf>>,
    locality: &dyn Fn(&[PathBuf]) -> KeyringLocality,
) -> Option<bool> {
    let dirs = dirs.ok()?;
    match locality(&dirs) {
        KeyringLocality::Local => Some(true),
        KeyringLocality::NotLocal { .. } => Some(false),
        KeyringLocality::Unknown { .. } => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Os {
    Windows,
    Macos,
    Linux,
}

impl Os {
    pub(crate) const CURRENT: Os = if cfg!(windows) {
        Os::Windows
    } else if cfg!(target_os = "macos") {
        Os::Macos
    } else {
        Os::Linux
    };
}

/// A path as text for comparison on any host: no `\\?\` prefix, `/` separators, lower case.
fn normalized(p: &Path) -> String {
    let s = p.to_string_lossy();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    s.replace('\\', "/").to_lowercase()
}

/// A path as printed: without the `\\?\` prefix `canonicalize` adds on Windows.
fn shown(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_owned()
}

/// §4.7 install mode of the located app (the table in the Task 17 brief). `program_files` are the
/// `%ProgramFiles%` roots (a `Program Files` directory elsewhere, say under a user profile, is not
/// a per-machine install).
pub(crate) fn install_mode(
    os: Os,
    app: Option<&Path>,
    appimage: Option<&OsStr>,
    local_app_data: Option<&Path>,
    program_files: &[PathBuf],
) -> &'static str {
    let Some(app) = app else {
        return "dev";
    };
    match os {
        Os::Windows => {
            let n = normalized(app);
            let per_user = local_app_data
                .map(|l| format!("{}/programs/", normalized(l).trim_end_matches('/')))
                .is_some_and(|prefix| n.starts_with(&prefix));
            if per_user {
                "windows_per_user"
            } else if program_files.iter().any(|pf| {
                let root = normalized(pf);
                let root = root.trim_end_matches('/');
                !root.is_empty() && n.starts_with(&format!("{root}/"))
            }) {
                "windows_per_machine"
            } else {
                "dev"
            }
        }
        Os::Macos => {
            let in_bundle = app
                .components()
                .any(|c| c.as_os_str().to_string_lossy().ends_with(".app"));
            if in_bundle { "macos_bundle" } else { "dev" }
        }
        Os::Linux => {
            if appimage.is_some_and(|image| Path::new(image) == app) {
                "appimage"
            } else if app.starts_with("/usr/bin") || app.starts_with("/opt") {
                "linux_package"
            } else {
                "dev"
            }
        }
    }
}

/// Whether the CLI is reachable as `atlas-duck`: its own canonical dir is on `PATH`, or an
/// `atlas-duck` on `PATH` canonicalizes to it. Relative entries (including the empty one) are the
/// working directory, not an install: ignored.
pub(crate) fn on_path(path: Option<&OsStr>, exe: Option<&Path>) -> bool {
    let (Some(path), Some(exe)) = (path, exe) else {
        return false;
    };
    let own_dir = exe.parent();
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .any(|dir| {
            // The Unix symlink layout puts the real binary (`atlas-duck-app`) next to nothing named
            // `atlas-duck`: the dir alone proves nothing.
            let same_dir = dir.join(CLI_FILE_NAME).exists()
                && dir
                    .canonicalize()
                    .is_ok_and(|c| Some(c.as_path()) == own_dir);
            same_dir
                || dir
                    .join(CLI_FILE_NAME)
                    .canonicalize()
                    .is_ok_and(|c| c == exe)
        })
}

fn text(s: Option<String>) -> Value {
    s.map_or(Value::Null, Value::from)
}

fn tri(b: Option<bool>) -> Value {
    b.map_or(Value::Null, Value::from)
}

/// The PD-31 `local` object: exactly these keys, no usernames, URLs or server data.
pub(crate) fn local_checks(d: &Discovery, sys: &dyn DoctorSys) -> Map<String, Value> {
    let app = match &d.app {
        AppLocation::Found(p) => Some(p.as_path()),
        AppLocation::NotFound => None,
    };
    let local_data = match &d.data {
        DataState::Local(dir) => Some(dir),
        _ => None,
    };
    let refusal = match &d.data {
        DataState::Refused(env) => env
            .error
            .as_ref()
            .and_then(|e| e.details.as_ref())
            .and_then(|m| m.get("reason"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    };
    let data_dir = match &d.data {
        DataState::Local(dir) => Some(shown(dir.path())),
        DataState::Refused(_) => sys.pinned_data_dir(&d.host).map(|p| shown(&p)),
        DataState::BeforeFirstRun => None,
    };
    // Locality is known only when it was decided: a missing dir or an unreadable file leaves it
    // open (`null`), the reason says which.
    let data_dir_local = match (&d.data, refusal.as_deref()) {
        (DataState::Local(_), _) => Some(true),
        (_, Some(REASON_DATA_DIR_NOT_LOCAL)) => Some(false),
        _ => None,
    };
    let wsl = sys.wsl();
    let exe = sys.exe();
    let local_app_data = sys.env("LOCALAPPDATA").map(PathBuf::from);
    let appimage = sys.env("APPIMAGE");
    let program_files: Vec<PathBuf> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .iter()
        .filter_map(|k| sys.env(k).map(PathBuf::from))
        .collect();

    let mut m = Map::new();
    m.insert("cli_version".to_owned(), json!(APP_VERSION));
    m.insert("build_id".to_owned(), json!(BUILD_ID));
    m.insert(
        "install_mode".to_owned(),
        json!(install_mode(
            Os::CURRENT,
            app,
            appimage.as_deref(),
            local_app_data.as_deref(),
            &program_files
        )),
    );
    m.insert("app_path".to_owned(), text(app.map(shown)));
    m.insert("app_path_found".to_owned(), json!(app.is_some()));
    m.insert(
        "on_path".to_owned(),
        json!(on_path(sys.env("PATH").as_deref(), exe.as_deref())),
    );
    m.insert(
        "endpoint".to_owned(),
        text(local_data.and_then(|dir| sys.endpoint(dir, &d.host))),
    );
    m.insert(
        "endpoint_exists".to_owned(),
        json!(local_data.is_some_and(|dir| sys.endpoint_present(dir, &d.host))),
    );
    m.insert("data_dir".to_owned(), text(data_dir));
    m.insert("data_dir_local".to_owned(), tri(data_dir_local));
    m.insert("data_dir_reason".to_owned(), text(refusal));
    m.insert("keyring_local".to_owned(), tri(sys.keyring_local()));
    m.insert(
        "job_blocks_breakaway".to_owned(),
        tri(sys.job_blocks_breakaway()),
    );
    m.insert("wsl".to_owned(), tri(wsl));
    m.insert(
        "wsl_warning".to_owned(),
        if wsl == Some(true) {
            json!(WSL_WARNING)
        } else {
            Value::Null
        },
    );
    m
}

/// `{code, reason}` of the envelope that stopped the CLI from getting the app's answer.
fn unavailable(env: &Envelope) -> Value {
    let (code, reason) = match &env.error {
        Some(e) => (
            serde_json::to_value(e.code).unwrap_or(Value::Null),
            e.details
                .as_ref()
                .and_then(|m| m.get("reason"))
                .cloned()
                .unwrap_or(Value::Null),
        ),
        None => (
            serde_json::to_value(ErrorCode::ProtocolError).unwrap_or(Value::Null),
            Value::Null,
        ),
    };
    json!({ "code": code, "reason": reason })
}

/// The PD-31 envelope: `succeeded`, exit 0, whatever the app said.
pub(crate) fn merge(local: Map<String, Value>, app: Result<Value, Box<Envelope>>) -> Envelope {
    let (app, app_unavailable) = match app {
        Ok(data) => (data, Value::Null),
        Err(env) => (Value::Null, unavailable(&env)),
    };
    Envelope {
        request_id: None,
        op_id: None,
        instance: None,
        status: Status::Succeeded,
        data: Some(json!({
            "local": local,
            "app": app,
            "app_unavailable": app_unavailable,
        })),
        edited: false,
        redacted: false,
        redaction_note: None,
        message: None,
        error: None,
        meta: None,
    }
}

/// `doctor` on the real machine.
pub(crate) async fn execute(
    opts: &GlobalOpts,
    deadline: &Deadline,
    connector: &dyn Connector,
) -> Envelope {
    execute_with(opts, deadline, connector, &OsDoctorSys).await
}

pub(crate) async fn execute_with(
    opts: &GlobalOpts,
    deadline: &Deadline,
    connector: &dyn Connector,
    sys: &dyn DoctorSys,
) -> Envelope {
    let d = connector.discover();
    let local = local_checks(&d, sys);
    // Registered before connecting, like every command that may launch the app and wait.
    let intr = connector.interrupts();
    merge(local, app_answer(&d, opts, deadline, connector, intr).await)
}

/// The app's `doctor` data, or the envelope that says why there is none.
async fn app_answer(
    d: &Discovery,
    opts: &GlobalOpts,
    deadline: &Deadline,
    connector: &dyn Connector,
    mut intr: Box<dyn Interrupts>,
) -> Result<Value, Box<Envelope>> {
    if let DataState::Refused(env) = &d.data {
        return Err(env.clone());
    }
    let mut client = reach(connector, opts, deadline, &mut *intr).await?;
    // The short call has no interrupt handling: release the handlers so Ctrl-C keeps its default.
    drop(intr);
    let env = short_call(&mut client, method::DOCTOR, EmptyParams {}, deadline).await;
    match (env.status, env.data.clone()) {
        (Status::Succeeded, Some(data)) => Ok(data),
        _ => Err(Box::new(env)),
    }
}

#[cfg(test)]
mod tests;
