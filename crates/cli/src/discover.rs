//! App discovery (§3.2 "App location", §7.7 "CLI-side data-dir check", §4.7 "When to launch"):
//! what the CLI learns from the machine-local pinned files before it connects or launches.
//!
//! The CLI never creates a directory or a file here. A data dir that is missing or not local is
//! refused with `not_configured` (exit 9) and nothing is launched (I-42); an app that cannot be
//! located is `unreachable {not_running}` (exit 5). Task 16 consumes `Discovery`.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use atlas_duck_ipc::envelope::{Envelope, ErrorCode};
use atlas_duck_ipc::paths::{
    BaseDirs, DataDirResolution, EndpointLocation, LocalDataDir, REASON_DATA_DIR_MISSING,
    REASON_DATA_DIR_NOT_LOCAL, base_dirs, cli_file, endpoint_location, host_name, paths_file,
    pipe_name_has_prefix, read_cli_toml, read_endpoint_file, read_pinned, resolve_data_dir,
};
use serde_json::{Map, Value};

/// `not_configured` reasons the CLI adds to the two M1 ones (PD-07).
pub(crate) const REASON_PATHS_UNREADABLE: &str = "paths_unreadable";
pub(crate) const REASON_DATA_DIR_UNUSABLE: &str = "data_dir_unusable";
/// `unreachable` reason when no app file can be found (§3.2).
pub(crate) const REASON_NOT_RUNNING: &str = "not_running";
/// §3.2, verbatim.
pub(crate) const MSG_APP_NOT_FOUND: &str =
    "atlas-duck app not found; reinstall or re-run Install CLI to PATH";

#[cfg(windows)]
pub(crate) const APP_FILE_NAME: &str = "atlas-duck-app.exe";
#[cfg(not(windows))]
pub(crate) const APP_FILE_NAME: &str = "atlas-duck-app";

/// What discovery found on this machine.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Discovery {
    pub host: String,
    pub data: DataState,
    pub app: AppLocation,
}

/// The CLI-side view of the data dir (§7.7).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DataState {
    /// No `paths.toml` for this host: the app has never run here (wizard not done).
    BeforeFirstRun,
    /// Pinned, present and on a local volume.
    Local(LocalDataDir),
    /// Pinned but unusable: the `not_configured` failure to print. Nothing is launched.
    Refused(Box<Envelope>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AppLocation {
    Found(PathBuf),
    NotFound,
}

/// `not_configured {reason}`: exit 9, `retryable: true` (the user can fix it and retry).
pub(crate) fn refusal(reason: &str) -> Envelope {
    let mut env = Envelope::failed(
        ErrorCode::NotConfigured,
        true,
        &format!("atlas-duck is not configured ({reason})"),
    );
    set_reason(&mut env, reason);
    env
}

/// `unreachable {not_running}` for an app that cannot be located: `retryable: true` like every
/// `unreachable` (§4.3 exit 5; only `server_identity` is not).
pub(crate) fn app_not_found() -> Envelope {
    let mut env = Envelope::failed(ErrorCode::Unreachable, true, MSG_APP_NOT_FOUND);
    set_reason(&mut env, REASON_NOT_RUNNING);
    env
}

fn set_reason(env: &mut Envelope, reason: &str) {
    if let Some(err) = env.error.as_mut() {
        let mut details = Map::new();
        details.insert("reason".to_owned(), Value::from(reason));
        err.details = Some(details);
    }
}

/// Discovery for this process: real base dirs, host name and executable.
pub(crate) fn discover(env: &dyn Fn(&str) -> Option<OsString>) -> Discovery {
    let host = host_name().unwrap_or_default();
    let exe = std::env::current_exe().and_then(|p| p.canonicalize()).ok();
    match base_dirs() {
        Ok(base) => discover_with(&base, &host, env, exe.as_deref()),
        // Without base folders nothing is pinned or findable (PD-07: unreadable).
        Err(_) => Discovery {
            host,
            data: DataState::Refused(Box::new(refusal(REASON_PATHS_UNREADABLE))),
            app: locate_app(None, env, exe.as_deref()),
        },
    }
}

/// `discover` with the base folders, host and canonical executable injected (tests use temp dirs).
pub(crate) fn discover_with(
    base: &BaseDirs,
    host: &str,
    env: &dyn Fn(&str) -> Option<OsString>,
    exe: Option<&Path>,
) -> Discovery {
    Discovery {
        host: host.to_owned(),
        data: data_state(base, host),
        app: locate_app(Some((base, host)), env, exe),
    }
}

fn data_state(base: &BaseDirs, host: &str) -> DataState {
    let pinned = match read_pinned(&paths_file(base, host)) {
        Ok(None) => return DataState::BeforeFirstRun,
        Ok(Some(p)) => p,
        Err(_) => return DataState::Refused(Box::new(refusal(REASON_PATHS_UNREADABLE))),
    };
    resolution_state(resolve_data_dir(Some(&pinned)))
}

/// The pure mapping from a resolution to what the CLI does with it.
fn resolution_state(resolution: io::Result<DataDirResolution>) -> DataState {
    match resolution {
        Ok(DataDirResolution::Local(dir)) => DataState::Local(dir),
        Ok(DataDirResolution::BeforeFirstRun) => DataState::BeforeFirstRun,
        Ok(DataDirResolution::Missing { .. }) => {
            DataState::Refused(Box::new(refusal(REASON_DATA_DIR_MISSING)))
        }
        Ok(DataDirResolution::NotLocal { .. }) => {
            DataState::Refused(Box::new(refusal(REASON_DATA_DIR_NOT_LOCAL)))
        }
        Err(_) => DataState::Refused(Box::new(refusal(REASON_DATA_DIR_UNUSABLE))),
    }
}

/// §3.2 order: `$APPIMAGE` (Linux), the app next to the CLI, `cli.toml`'s `app_path`.
fn locate_app(
    base_host: Option<(&BaseDirs, &str)>,
    env: &dyn Fn(&str) -> Option<OsString>,
    exe: Option<&Path>,
) -> AppLocation {
    if let Some(image) = appimage(env, exe) {
        return AppLocation::Found(image);
    }
    if let Some(next_to) = exe
        .and_then(Path::parent)
        .map(|dir| dir.join(APP_FILE_NAME))
        && next_to.is_file()
    {
        return AppLocation::Found(next_to);
    }
    // An unreadable or malformed cli.toml is the same as none: the app is not found.
    if let Some((base, host)) = base_host
        && let Ok(Some(cli)) = read_cli_toml(&cli_file(base, host))
        && let Some(app) = cli.app_path
        && app.is_absolute()
        && app.is_file()
    {
        return AppLocation::Found(app);
    }
    AppLocation::NotFound
}

/// `$APPIMAGE` when it names an existing file by absolute path and this CLI really runs from an
/// AppImage (M6 final review I-3). Children of any AppImage inherit the variable (an AppImage
/// terminal or editor, then a deb or rpm `atlas-duck` run by an agent in it), so it only counts
/// when the CLI binary is under a `.mount_*` point or a non-root `$APPDIR`: the rule the app's
/// `cli_install` uses (`atlas_duck_ipc::paths::runs_from_appimage`). AppImages exist only on
/// Linux; elsewhere the variable (which an agent can set) never chooses what the CLI launches.
#[cfg(target_os = "linux")]
fn appimage(env: &dyn Fn(&str) -> Option<OsString>, exe: Option<&Path>) -> Option<PathBuf> {
    let appdir = env("APPDIR").filter(|v| !v.is_empty()).map(PathBuf::from);
    if !exe.is_some_and(|exe| atlas_duck_ipc::paths::runs_from_appimage(exe, appdir.as_deref())) {
        return None;
    }
    env("APPIMAGE")
        .map(PathBuf::from)
        .filter(|image| image.is_absolute() && image.is_file())
}

#[cfg(not(target_os = "linux"))]
fn appimage(_env: &dyn Fn(&str) -> Option<OsString>, _exe: Option<&Path>) -> Option<PathBuf> {
    None
}

/// Whether this user's endpoint is present: Unix the socket file exists (no connect, no
/// symlink follow; `launch::unix::endpoint_answers` adds the liveness probe); Windows the endpoint
/// file names a pipe under this user's SID prefix (§3.1) and that pipe exists (§4.7: a stale file
/// a crashed app left behind is absent). An unreadable location or endpoint file reads as not
/// present, so the caller falls through to launching; a failed pipe probe reads as present.
pub(crate) fn endpoint_present(data: &LocalDataDir, host: &str) -> bool {
    let Ok(location) = endpoint_location(data, host) else {
        return false;
    };
    match location {
        EndpointLocation::UnixSocket(path) => std::fs::symlink_metadata(path).is_ok(),
        EndpointLocation::WindowsPipePrefix(prefix) => {
            pipe_endpoint_present(read_endpoint_file(data), &prefix, &pipe_exists)
        }
    }
}

/// The Windows rule over the endpoint file's contents: only a name under this user's local prefix
/// is handed to `probe`, so a tampered file can never aim it at a `\\server\pipe\…` name (whose
/// probe would authenticate to that server).
fn pipe_endpoint_present(
    file: io::Result<Option<String>>,
    prefix: &str,
    probe: &dyn Fn(&str) -> bool,
) -> bool {
    match file {
        Ok(Some(name)) if pipe_name_has_prefix(&name, prefix) => probe(&name),
        _ => false,
    }
}

/// `WaitNamedPipeW`-based existence check. Its only error is a NUL in the name, which the prefix
/// check (a 32-hex suffix) already excluded; it would read as present like every probe failure.
#[cfg(windows)]
fn pipe_exists(name: &str) -> bool {
    atlas_duck_ipc::transport::windows::pipe_exists(name).unwrap_or(true)
}

/// No named pipes off Windows (`endpoint_location` never yields a pipe prefix there).
#[cfg(not(windows))]
fn pipe_exists(_name: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::fs;

    use atlas_duck_ipc::paths::{
        CliToml, NotLocalKind, PinnedPaths, check_data_dir, write_cli_toml, write_pinned,
    };

    use super::*;

    const HOST: &str = "testhost";

    fn base(dir: &Path) -> BaseDirs {
        BaseDirs {
            home: dir.to_path_buf(),
            local_app_data: Some(dir.join("AppData").join("Local")),
            roaming_app_data: Some(dir.join("AppData").join("Roaming")),
        }
    }

    fn pin(b: &BaseDirs, data_dir: &Path) {
        let p = PinnedPaths {
            schema_version: 1,
            data_dir: data_dir.to_path_buf(),
            config_dir: data_dir.join("config"),
            install_id: None,
        };
        write_pinned(&paths_file(b, HOST), &p).unwrap();
    }

    fn no_env(_: &str) -> Option<OsString> {
        None
    }

    fn reason(d: &Discovery) -> Option<String> {
        match &d.data {
            DataState::Refused(env) => env
                .error
                .as_ref()
                .and_then(|e| e.details.as_ref())
                .and_then(|m| m.get("reason"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            _ => None,
        }
    }

    fn assert_exit_9(d: &Discovery) {
        let DataState::Refused(env) = &d.data else {
            panic!("not refused: {:?}", d.data);
        };
        let e = env.error.as_ref().unwrap();
        assert_eq!(e.code, ErrorCode::NotConfigured);
        assert!(e.retryable);
        assert_eq!(atlas_duck_ipc::proto::exit_code(env), 9);
    }

    #[test]
    fn i42_cli_data_dir_states() {
        let tmp = tempfile::tempdir().unwrap();
        let b = base(tmp.path());
        let d = discover_with(&b, HOST, &no_env, None);
        assert_eq!(d.data, DataState::BeforeFirstRun);
        assert!(
            !tmp.path().join("AppData").exists(),
            "discovery created dirs"
        );

        // Pinned to a dir that does not exist.
        let gone = tmp.path().join("gone");
        pin(&b, &gone);
        let d = discover_with(&b, HOST, &no_env, None);
        assert_exit_9(&d);
        assert_eq!(reason(&d).as_deref(), Some("data_dir_missing"));
        assert!(!gone.exists());

        // Pinned to an existing local dir.
        let there = tmp.path().join("there");
        fs::create_dir(&there).unwrap();
        pin(&b, &there);
        assert!(matches!(
            discover_with(&b, HOST, &no_env, None).data,
            DataState::Local(_)
        ));

        // Corrupt pinned file.
        fs::write(paths_file(&b, HOST), b"not = [toml").unwrap();
        let d = discover_with(&b, HOST, &no_env, None);
        assert_exit_9(&d);
        assert_eq!(reason(&d).as_deref(), Some("paths_unreadable"));
    }

    #[cfg(windows)]
    #[test]
    fn unc_data_dir_is_not_local_without_filesystem_access() {
        let tmp = tempfile::tempdir().unwrap();
        let b = base(tmp.path());
        pin(&b, Path::new(r"\\server\share\x"));
        let d = discover_with(&b, HOST, &no_env, None);
        assert_exit_9(&d);
        assert_eq!(reason(&d).as_deref(), Some("data_dir_not_local"));
    }

    #[test]
    fn unusable_data_dir_refusal_shape() {
        // `resolve_data_dir` errors are OS-specific and hard to provoke; the mapping's output is
        // what is pinned here.
        let env = refusal(REASON_DATA_DIR_UNUSABLE);
        assert_eq!(atlas_duck_ipc::proto::exit_code(&env), 9);
        let details = env.error.and_then(|e| e.details).unwrap();
        assert_eq!(
            details.get("reason"),
            Some(&Value::from("data_dir_unusable"))
        );
    }

    fn touch(p: &Path) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b"x").unwrap();
    }

    #[test]
    fn app_location_order() {
        let tmp = tempfile::tempdir().unwrap();
        let b = base(tmp.path());
        let bin = tmp.path().join("bin");
        let exe = bin.join("atlas-duck-cli-link");
        let next_to = bin.join(APP_FILE_NAME);
        let image = tmp.path().join("App.AppImage");
        let listed = tmp.path().join("listed").join("app");

        // cli.toml pointing at a missing file: NotFound.
        write_cli_toml(
            &cli_file(&b, HOST),
            &CliToml {
                app_path: Some(listed.clone()),
            },
        )
        .unwrap();
        let with_image = |_: &str| Some(image.clone().into_os_string());
        assert_eq!(
            discover_with(&b, HOST, &no_env, Some(&exe)).app,
            AppLocation::NotFound
        );

        // cli.toml wins when the file exists.
        touch(&listed);
        assert_eq!(
            discover_with(&b, HOST, &no_env, Some(&exe)).app,
            AppLocation::Found(listed.clone())
        );

        // Next-to beats cli.toml.
        touch(&next_to);
        assert_eq!(
            discover_with(&b, HOST, &no_env, Some(&exe)).app,
            AppLocation::Found(next_to.clone())
        );

        // $APPIMAGE that is not an existing file is ignored.
        assert_eq!(
            discover_with(&b, HOST, &with_image, Some(&exe)).app,
            AppLocation::Found(next_to.clone())
        );
        touch(&image);
        // Final review I-3: a leaked $APPIMAGE (this CLI is not inside an AppImage: no mount
        // point, no $APPDIR around it) never chooses the app, on any platform.
        assert_eq!(
            discover_with(&b, HOST, &with_image, Some(&exe)).app,
            AppLocation::Found(next_to.clone())
        );
        let leaked_with_appdir = |k: &str| match k {
            "APPIMAGE" => Some(image.clone().into_os_string()),
            "APPDIR" => Some(tmp.path().join("other-appimage-root").into_os_string()),
            _ => None,
        };
        assert_eq!(
            discover_with(&b, HOST, &leaked_with_appdir, Some(&exe)).app,
            AppLocation::Found(next_to.clone())
        );
        // On Linux a CLI that does run from an AppImage (under its mount point, or under the
        // extracted $APPDIR) launches that image, ahead of the app next to it; elsewhere never.
        let mounted = tmp.path().join(".mount_atlasXYZ/usr/bin/atlas-duck");
        let appdir = tmp.path().join("squashfs-root");
        let extracted = appdir.join("usr/bin/atlas-duck");
        let with_appdir = |k: &str| match k {
            "APPIMAGE" => Some(image.clone().into_os_string()),
            "APPDIR" => Some(appdir.clone().into_os_string()),
            _ => None,
        };
        // Off Linux nothing sits next to those binaries, so cli.toml's listed app is what is left.
        let expected = if cfg!(target_os = "linux") {
            image.clone()
        } else {
            listed.clone()
        };
        for (env, exe) in [
            (&with_image as &dyn Fn(&str) -> Option<OsString>, &mounted),
            (&with_appdir, &extracted),
        ] {
            assert_eq!(
                discover_with(&b, HOST, env, Some(exe)).app,
                AppLocation::Found(expected.clone()),
                "{exe:?}"
            );
        }
        // A relative $APPIMAGE is ignored, even inside an AppImage.
        let relative = |_: &str| Some(OsString::from("App.AppImage"));
        assert_eq!(
            discover_with(&b, HOST, &relative, Some(&exe)).app,
            AppLocation::Found(next_to)
        );
        assert_eq!(
            discover_with(&b, HOST, &relative, Some(&mounted)).app,
            AppLocation::Found(listed)
        );
    }

    #[test]
    fn not_found_message_verbatim() {
        let env = app_not_found();
        let e = env.error.as_ref().unwrap();
        assert_eq!(e.code, ErrorCode::Unreachable);
        assert_eq!(
            e.message,
            "atlas-duck app not found; reinstall or re-run Install CLI to PATH"
        );
        assert_eq!(
            e.details.as_ref().and_then(|m| m.get("reason")),
            Some(&Value::from("not_running"))
        );
        assert!(e.retryable);
        assert_eq!(atlas_duck_ipc::proto::exit_code(&env), 5);
    }

    fn refused_reason(state: &DataState) -> Option<String> {
        reason(&Discovery {
            host: String::new(),
            data: state.clone(),
            app: AppLocation::NotFound,
        })
    }

    #[test]
    fn resolution_state_maps_every_arm() {
        let tmp = tempfile::tempdir().unwrap();
        let local = check_data_dir(tmp.path()).unwrap();
        assert!(matches!(local, DataDirResolution::Local(_)));
        assert!(matches!(resolution_state(Ok(local)), DataState::Local(_)));
        assert_eq!(
            resolution_state(Ok(DataDirResolution::BeforeFirstRun)),
            DataState::BeforeFirstRun
        );
        let missing = resolution_state(Ok(DataDirResolution::Missing {
            path: tmp.path().join("gone"),
        }));
        assert_eq!(
            refused_reason(&missing).as_deref(),
            Some("data_dir_missing")
        );
        let not_local = resolution_state(Ok(DataDirResolution::NotLocal {
            path: tmp.path().join("share"),
            kind: NotLocalKind::Unc,
        }));
        assert_eq!(
            refused_reason(&not_local).as_deref(),
            Some("data_dir_not_local")
        );
        let unusable = resolution_state(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
        assert_eq!(
            refused_reason(&unusable).as_deref(),
            Some("data_dir_unusable")
        );
        for state in [&missing, &not_local, &unusable] {
            let DataState::Refused(env) = state else {
                panic!("not refused");
            };
            assert_eq!(atlas_duck_ipc::proto::exit_code(env), 9);
        }
    }

    #[test]
    fn refusal_message_text() {
        let env = refusal("data_dir_missing");
        let e = env.error.unwrap();
        assert_eq!(e.message, "atlas-duck is not configured (data_dir_missing)");
        assert!(e.retryable);
    }

    #[test]
    fn pinned_to_a_regular_file_is_data_dir_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let b = base(tmp.path());
        let file = tmp.path().join("a-file");
        fs::write(&file, b"x").unwrap();
        pin(&b, &file);
        let d = discover_with(&b, HOST, &no_env, None);
        assert_exit_9(&d);
        assert_eq!(reason(&d).as_deref(), Some("data_dir_missing"));
        let DataState::Refused(env) = &d.data else {
            panic!("not refused");
        };
        assert_eq!(
            env.error.as_ref().unwrap().message,
            "atlas-duck is not configured (data_dir_missing)"
        );
    }

    #[test]
    fn app_path_must_be_absolute_and_non_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let b = base(tmp.path());
        // Cargo runs unit tests with the package root as the current directory, so this
        // relative path names a file that exists there.
        assert!(Path::new("Cargo.toml").is_file());
        for relative in ["Cargo.toml", "./Cargo.toml", ""] {
            write_cli_toml(
                &cli_file(&b, HOST),
                &CliToml {
                    app_path: Some(PathBuf::from(relative)),
                },
            )
            .unwrap();
            assert_eq!(
                discover_with(&b, HOST, &no_env, None).app,
                AppLocation::NotFound,
                "app_path {relative:?}"
            );
        }
    }

    #[test]
    fn corrupt_cli_toml_is_app_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let b = base(tmp.path());
        fs::create_dir_all(cli_file(&b, HOST).parent().unwrap()).unwrap();
        fs::write(cli_file(&b, HOST), b"app_path = [").unwrap();
        assert_eq!(
            discover_with(&b, HOST, &no_env, None).app,
            AppLocation::NotFound
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn endpoint_present_windows_prefix() {
        use atlas_duck_ipc::paths::write_endpoint_file;
        use atlas_duck_ipc::transport::windows::PipeListener;

        let tmp = tempfile::tempdir().unwrap();
        let DataDirResolution::Local(data) = check_data_dir(tmp.path()).unwrap() else {
            panic!("temp dir is not local");
        };
        assert!(!endpoint_present(&data, HOST));
        let EndpointLocation::WindowsPipePrefix(prefix) = endpoint_location(&data, HOST).unwrap()
        else {
            panic!("not a pipe prefix");
        };
        // Another user's SID prefix is not present.
        let other = format!("atlas-duck-{}-{}", "0".repeat(16), "a".repeat(32));
        write_endpoint_file(&data, &other).unwrap();
        assert!(!endpoint_present(&data, HOST));
        // Our prefix and the 32-hex suffix, but no pipe (a crashed app's file): absent.
        write_endpoint_file(&data, &format!("{prefix}{}", "a".repeat(32))).unwrap();
        assert!(!endpoint_present(&data, HOST));
        // A listening pipe named in the file: present.
        let listener = PipeListener::bind(&prefix).unwrap();
        write_endpoint_file(&data, listener.name()).unwrap();
        assert!(endpoint_present(&data, HOST));
        drop(listener);
        assert!(!endpoint_present(&data, HOST), "listener gone");
    }

    #[test]
    fn only_a_prefixed_pipe_name_is_probed() {
        let prefix = r"\\.\pipe\atlas-duck-0123456789abcdef-";
        let ours = format!("{prefix}{}", "b".repeat(32));
        let probed = std::cell::RefCell::new(Vec::<String>::new());
        let probe = |name: &str| {
            probed.borrow_mut().push(name.to_owned());
            true
        };
        let foreign = [
            r"\\attacker\pipe\x".to_owned(),
            format!(
                r"\\attacker\pipe\atlas-duck-0123456789abcdef-{}",
                "b".repeat(32)
            ),
            format!(r"\\.\pipe\atlas-duck-{}-{}", "0".repeat(16), "b".repeat(32)),
            format!("{prefix}{}", "B".repeat(32)),
            format!("{prefix}{}", "b".repeat(31)),
            String::new(),
        ];
        for name in foreign {
            assert!(
                !pipe_endpoint_present(Ok(Some(name.clone())), prefix, &probe),
                "{name}"
            );
        }
        assert!(!pipe_endpoint_present(Ok(None), prefix, &probe));
        assert!(!pipe_endpoint_present(
            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            prefix,
            &probe
        ));
        assert!(probed.borrow().is_empty(), "probed {:?}", probed.borrow());

        // Our name reaches the probe, whose answer is the result.
        assert!(pipe_endpoint_present(
            Ok(Some(ours.clone())),
            prefix,
            &probe
        ));
        assert!(!pipe_endpoint_present(
            Ok(Some(ours.clone())),
            prefix,
            &|_| false
        ));
        assert_eq!(*probed.borrow(), [ours]);
    }
}
