//! Tests for the endpoint location, the `<data>/endpoint` file, the socket
//! dir and the `test-paths` override (§3.1, §7.7, §15 V28, PD-01, PD-26).

use std::path::Path;

use atlas_duck_ipc::paths::{
    DataDirResolution, ENDPOINT_FILE, LocalDataDir, check_data_dir, pipe_name_has_prefix,
    read_endpoint_file, remove_endpoint_file, write_endpoint_file,
};

// ---------- helpers ----------

fn local(dir: &Path) -> LocalDataDir {
    match check_data_dir(dir).expect("check_data_dir") {
        DataDirResolution::Local(d) => d,
        other => panic!("temp dir is not a local data dir: {other:?}"),
    }
}

fn sample_name(i: usize) -> String {
    if cfg!(windows) {
        format!(r"\\.\pipe\atlas-duck-0123456789abcdef-{i:032x}")
    } else {
        format!("/run/user/1000/atlas-duck/atlas-duck.sock.{i}")
    }
}

// ---------- endpoint file ----------

#[test]
fn endpoint_file_roundtrip_and_mode() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = local(tmp.path());
    let name = sample_name(0);
    write_endpoint_file(&data, &name).expect("write");
    assert_eq!(read_endpoint_file(&data).expect("read"), Some(name.clone()));
    // Exactly the name: no trailing newline, nothing else.
    let raw = std::fs::read(tmp.path().join(ENDPOINT_FILE)).expect("raw read");
    assert_eq!(raw, name.as_bytes());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(tmp.path().join(ENDPOINT_FILE))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o600, "mode {mode:o}");
    }

    // Replace is atomic: a concurrent reader never sees an empty or partial file.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = {
        let stop = stop.clone();
        let data = data.clone();
        std::thread::spawn(move || {
            let mut seen = 0usize;
            loop {
                match read_endpoint_file(&data) {
                    Ok(Some(v)) => {
                        assert!(
                            (0..=200).any(|i| sample_name(i) == v),
                            "reader saw an unexpected value: {v:?}"
                        );
                        seen += 1;
                    }
                    // Windows: opening the file in the instant of the replace
                    // can fail transiently (sharing violation, delete pending).
                    Ok(None) | Err(_) if cfg!(windows) => {}
                    other => panic!("reader saw {other:?}"),
                }
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
            }
            seen
        })
    };
    for i in 1..=200 {
        write_endpoint_file(&data, &sample_name(i)).expect("rewrite");
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let seen = reader.join().expect("reader thread");
    assert!(seen > 0, "reader never read the file");
    assert_eq!(
        read_endpoint_file(&data).expect("read"),
        Some(sample_name(200))
    );
    // No temp files are left behind.
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name())
        .filter(|n| n != ENDPOINT_FILE)
        .collect();
    assert!(leftovers.is_empty(), "leftover files: {leftovers:?}");
}

#[test]
fn endpoint_file_rejects_garbage() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = local(tmp.path());
    let path = tmp.path().join(ENDPOINT_FILE);
    let invalid = |bytes: &[u8]| {
        std::fs::write(&path, bytes).expect("write raw");
        let err = read_endpoint_file(&data).expect_err("garbage accepted");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{bytes:?}");
    };
    invalid(&[b'a'; 600]);
    invalid(&[b'a'; 513]);
    invalid(b"name\n");
    invalid(b"a\nb");
    invalid(b"tab\there");
    invalid(b"del\x7f");
    invalid(b"");
    invalid(&[0xff, 0xfe]);
    // 512 bytes is the limit, not over it.
    std::fs::write(&path, [b'a'; 512]).expect("write raw");
    assert_eq!(
        read_endpoint_file(&data).expect("512 bytes"),
        Some("a".repeat(512))
    );

    // The writer refuses what the reader would refuse.
    for bad in ["", "a\nb", "x\r", &"a".repeat(513)] {
        let err = write_endpoint_file(&data, bad).expect_err("bad name written");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{bad:?}");
    }
}

#[test]
fn missing_endpoint_file_is_none() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = local(tmp.path());
    assert_eq!(read_endpoint_file(&data).expect("read"), None);
    remove_endpoint_file(&data).expect("remove missing");
    write_endpoint_file(&data, &sample_name(1)).expect("write");
    remove_endpoint_file(&data).expect("remove");
    assert!(!tmp.path().join(ENDPOINT_FILE).exists());
    assert_eq!(read_endpoint_file(&data).expect("read"), None);
}

#[test]
fn write_endpoint_file_never_creates_the_data_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    std::fs::create_dir(&dir).expect("mkdir");
    let data = local(&dir);
    std::fs::remove_dir(&dir).expect("rmdir");
    assert!(write_endpoint_file(&data, &sample_name(1)).is_err());
    assert!(!dir.exists());
}

// ---------- pipe names ----------

#[test]
fn pipe_name_has_prefix_exact_shape() {
    let prefix = r"\\.\pipe\atlas-duck-0123456789abcdef-";
    let hex32 = "0123456789abcdef0123456789abcdef";
    assert!(pipe_name_has_prefix(&format!("{prefix}{hex32}"), prefix));
    assert!(!pipe_name_has_prefix(
        &format!("{prefix}{}", &hex32[..31]),
        prefix
    ));
    assert!(!pipe_name_has_prefix(&format!("{prefix}{hex32}0"), prefix));
    assert!(!pipe_name_has_prefix(
        &format!("{prefix}{}", hex32.to_ascii_uppercase()),
        prefix
    ));
    assert!(!pipe_name_has_prefix(
        &format!("{prefix}{}g", &hex32[..31]),
        prefix
    ));
    assert!(!pipe_name_has_prefix(
        &format!(r"\\.\pipe\atlas-duck-fedcba9876543210-{hex32}"),
        prefix
    ));
    assert!(!pipe_name_has_prefix(&format!("{prefix}{hex32}\0"), prefix));
    assert!(!pipe_name_has_prefix(hex32, prefix));
    assert!(!pipe_name_has_prefix("", prefix));
}

#[cfg(windows)]
#[test]
fn pipe_prefix_from_sid() {
    use atlas_duck_ipc::paths::{EndpointLocation, current_user_sid_string, endpoint_location};

    let sid = current_user_sid_string().expect("sid");
    assert!(sid.starts_with("S-1-"), "{sid}");
    assert_eq!(sid, current_user_sid_string().expect("sid again"));

    let tmp = tempfile::tempdir().expect("tempdir");
    let data = local(tmp.path());
    let prefix = match endpoint_location(&data, "host").expect("endpoint_location") {
        EndpointLocation::WindowsPipePrefix(p) => p,
        other => panic!("expected a pipe prefix, got {other:?}"),
    };
    let head = r"\\.\pipe\atlas-duck-";
    let hex = prefix
        .strip_prefix(head)
        .and_then(|rest| rest.strip_suffix('-'))
        .unwrap_or_else(|| panic!("bad prefix shape: {prefix}"));
    assert_eq!(hex.len(), 16, "{prefix}");
    assert!(
        hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "{prefix}"
    );
    // Stable across calls and independent of the host argument.
    let again = endpoint_location(&data, "other-host").expect("endpoint_location");
    assert_eq!(again, EndpointLocation::WindowsPipePrefix(prefix.clone()));

    let hex32 = "00112233445566778899aabbccddeeff";
    assert!(pipe_name_has_prefix(&format!("{prefix}{hex32}"), &prefix));
    assert!(!pipe_name_has_prefix(
        &format!("{prefix}{}", &hex32[..31]),
        &prefix
    ));
    assert!(!pipe_name_has_prefix(&format!("{prefix}{hex32}a"), &prefix));
    assert!(!pipe_name_has_prefix(
        &format!("{prefix}{}", hex32.to_ascii_uppercase()),
        &prefix
    ));
    assert!(!pipe_name_has_prefix(
        &format!(r"\\.\pipe\atlas-duck-ffffffffffffffff-{hex32}"),
        &prefix
    ));
}

// ---------- socket dir (Unix) ----------

#[cfg(unix)]
#[test]
fn ensure_socket_dir_refuses_symlink_wrong_mode_wrong_owner() {
    use atlas_duck_ipc::paths::ensure_socket_dir;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let tmp = tempfile::tempdir().expect("tempdir");

    // Missing dir and missing parents: created 0700.
    let fresh = tmp.path().join("a").join("b").join("sock");
    ensure_socket_dir(&fresh).expect("fresh dir");
    for d in [tmp.path().join("a"), tmp.path().join("a/b"), fresh.clone()] {
        let mode = std::fs::symlink_metadata(&d)
            .expect("lstat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o700, "{} mode {mode:o}", d.display());
    }
    // Existing correct dir: Ok again.
    ensure_socket_dir(&fresh).expect("existing dir");

    // A symlink to a correct dir is refused (lstat, not stat).
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&fresh, &link).expect("symlink");
    let err = ensure_socket_dir(&link).expect_err("symlink accepted");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

    // An existing 0755 dir is refused and left as it is.
    let open = tmp.path().join("open");
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(&open)
        .expect("mkdir");
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let err = ensure_socket_dir(&open).expect_err("0755 accepted");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    let mode = std::fs::metadata(&open).expect("stat").permissions().mode();
    assert_eq!(mode & 0o7777, 0o755);

    // Sticky or setgid bits are not "exactly 0700".
    let sticky = tmp.path().join("sticky");
    std::fs::create_dir(&sticky).expect("mkdir");
    std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1700)).expect("chmod");
    let err = ensure_socket_dir(&sticky).expect_err("01700 accepted");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

    // A regular file is refused.
    let file = tmp.path().join("file");
    std::fs::write(&file, b"x").expect("write");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let err = ensure_socket_dir(&file).expect_err("file accepted");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    // The wrong-owner case is the `check_dir_meta` unit test in src/paths/endpoint.rs.
}

#[cfg(target_os = "linux")]
#[test]
fn v28_socket_dir_choice_linux() {
    use atlas_duck_ipc::paths::{
        EndpointLocation, base_dirs, endpoint_location, host_name, socket_dir,
    };
    use std::os::unix::fs::MetadataExt;

    let host = host_name().expect("host_name");
    let dir = socket_dir(&host).expect("socket_dir");
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let run = std::path::PathBuf::from(format!("/run/user/{uid}"));
    let run_ok = std::fs::symlink_metadata(&run)
        .map(|m| m.file_type().is_dir() && m.uid() == uid && m.mode() & 0o7777 == 0o700)
        .unwrap_or(false);
    let source = if run_ok { "run_user" } else { "state_fallback" };
    println!("V28 socket_dir={} source={source}", dir.display());
    if run_ok {
        assert_eq!(dir, run.join("atlas-duck"));
    } else {
        let home = base_dirs().expect("base_dirs").home;
        assert_eq!(
            dir,
            home.join(".local")
                .join("state")
                .join("atlas-duck")
                .join(format!("run-{host}"))
        );
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let data = local(tmp.path());
    assert_eq!(
        endpoint_location(&data, &host).expect("endpoint_location"),
        EndpointLocation::UnixSocket(dir.join("atlas-duck.sock"))
    );
    // A host argument that is not a sanitized component is refused.
    assert!(socket_dir("../evil").is_err());
    // A sanitized name with escapes in it (`_` -> `_5f`) is accepted.
    let escaped = atlas_duck_ipc::paths::sanitize_host_component("my_pc");
    assert_eq!(
        socket_dir(&escaped).expect("escaped host"),
        if run_ok {
            run.join("atlas-duck")
        } else {
            base_dirs()
                .expect("base_dirs")
                .home
                .join(".local/state/atlas-duck")
                .join(format!("run-{escaped}"))
        }
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_socket_path_under_104_bytes() {
    use atlas_duck_ipc::paths::{EndpointLocation, endpoint_location, host_name, socket_dir};

    let host = host_name().expect("host_name");
    let dir = socket_dir(&host).expect("socket_dir");
    println!("V28 socket_dir={}", dir.display());
    assert!(dir.ends_with("atlas-duck"), "{}", dir.display());
    assert!(!dir.starts_with("/tmp"), "{}", dir.display());
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = local(tmp.path());
    let path = match endpoint_location(&data, &host).expect("endpoint_location") {
        EndpointLocation::UnixSocket(p) => p,
        other => panic!("expected a socket path, got {other:?}"),
    };
    assert_eq!(path, dir.join("atlas-duck.sock"));
    assert!(path.as_os_str().len() < 104, "{}", path.display());
}

// ---------- test-paths override (PD-01) ----------

#[cfg(feature = "test-paths")]
const CHILD_ENV: &str = "ATLAS_DUCK_ENDPOINT_CHILD";
#[cfg(feature = "test-paths")]
const CHILD_PREFIX: &str = "ATLAS_DUCK_TEST_HOME_REPORT ";

#[cfg(feature = "test-paths")]
fn test_home_report() -> String {
    let base = match atlas_duck_ipc::paths::base_dirs() {
        Ok(b) => format!(
            "{}|{}|{}",
            b.home.display(),
            b.local_app_data
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            b.roaming_app_data
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ),
        Err(e) => format!("err:{:?}", e.kind()),
    };
    #[cfg(unix)]
    let sock = match atlas_duck_ipc::paths::socket_dir("host") {
        Ok(p) => p.display().to_string(),
        Err(e) => format!("err:{:?}", e.kind()),
    };
    #[cfg(not(unix))]
    let sock = String::new();
    format!("{CHILD_PREFIX}{base}|{sock}")
}

/// Child half of `test_home_overrides_base_dirs`; a no-op in a normal run.
#[cfg(feature = "test-paths")]
#[test]
fn child_print_test_home() {
    if std::env::var_os(CHILD_ENV).is_some() {
        println!("{}", test_home_report());
    }
}

/// Runs `child_print_test_home` in a child process with `ATLAS_DUCK_TEST_HOME`
/// set to `home` (or removed), so this process never mutates its own
/// environment.
#[cfg(feature = "test-paths")]
fn child_report(home: Option<&std::ffi::OsStr>) -> String {
    let mut cmd = std::process::Command::new(std::env::current_exe().expect("current_exe"));
    cmd.args([
        "--exact",
        "child_print_test_home",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(CHILD_ENV, "1");
    match home {
        Some(h) => cmd.env("ATLAS_DUCK_TEST_HOME", h),
        None => cmd.env_remove("ATLAS_DUCK_TEST_HOME"),
    };
    let out = cmd.output().expect("spawn child test process");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "child failed: {stdout}");
    let start = stdout
        .find(CHILD_PREFIX)
        .unwrap_or_else(|| panic!("child printed no report: {stdout}"));
    stdout[start..]
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned()
}

#[cfg(feature = "test-paths")]
#[test]
fn test_home_overrides_base_dirs() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let h = tmp.path();
    let report = child_report(Some(h.as_os_str()));
    let sock = if cfg!(unix) {
        h.join("s").display().to_string()
    } else {
        String::new()
    };
    assert_eq!(
        report,
        format!(
            "{CHILD_PREFIX}{}|{}|{}|{sock}",
            h.display(),
            h.join("AppData").join("Local").display(),
            h.join("AppData").join("Roaming").display(),
        )
    );

    // Unset: two children with the variable removed agree, and neither uses `h`.
    let real = child_report(None);
    assert_eq!(child_report(None), real);
    assert!(!real.contains(&h.display().to_string()));

    // Set but relative, or not an existing directory: refused, never the real home.
    let refused = |value: &std::ffi::OsStr| {
        let r = child_report(Some(value));
        assert!(
            r.starts_with(&format!("{CHILD_PREFIX}err:InvalidInput|")),
            "{value:?}: {r}"
        );
        if cfg!(unix) {
            assert!(r.ends_with("|err:InvalidInput"), "{value:?}: {r}");
        }
    };
    refused(std::ffi::OsStr::new("relative/home"));
    refused(h.join("missing").as_os_str());
    let file = h.join("file");
    std::fs::write(&file, b"x").expect("write");
    refused(file.as_os_str());
    refused(std::ffi::OsStr::new(""));
}
