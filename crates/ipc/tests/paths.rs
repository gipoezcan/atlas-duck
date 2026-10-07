//! Tests for the shared path API (§3.1, §7.7, §13 Integration, §15 V28).

use atlas_duck_ipc::paths::{host_name, raw_host_name, sanitize_host_component};

// ---------- helpers ----------

/// `^[a-z0-9._-]{1,240}$`, no `..`, no leading or trailing `.`.
fn assert_safe_component(c: &str) {
    assert!(
        !c.is_empty() && c.len() <= 240,
        "length out of range: {c:?}"
    );
    assert!(
        c.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-')),
        "unexpected character in {c:?}"
    );
    assert!(!c.contains(".."), "contains '..': {c:?}");
    assert!(
        !c.starts_with('.') && !c.ends_with('.'),
        "leading/trailing dot: {c:?}"
    );
}

// ---------- host name ----------

#[test]
fn sanitize_lowercases_clean_names_unchanged_otherwise() {
    assert_eq!(sanitize_host_component("MyMac.local"), "mymac.local");
    assert_eq!(
        sanitize_host_component("MyMac"),
        sanitize_host_component("mymac")
    );
    assert_eq!(sanitize_host_component("build-01"), "build-01");
    // A clean component maps to itself, so a sanitized name stays stable.
    assert_eq!(sanitize_host_component("mymac.local"), "mymac.local");
}

#[test]
fn sanitize_hostile_names_pinned_values() {
    // Pinned outputs: the mapping is a stable contract (renaming a host's
    // pinned file sends that host back to the first-run wizard).
    assert_eq!(sanitize_host_component("a/b"), "a_2fb");
    assert_eq!(sanitize_host_component(".."), "_2e_2e");
    assert_eq!(sanitize_host_component("x\\y"), "x_5cy");
    assert_eq!(sanitize_host_component("jürgen-mbp"), "j_c3_bcrgen-mbp");
    assert_eq!(sanitize_host_component("a_b"), "a_5fb");
    assert_eq!(sanitize_host_component("a..b"), "a._2eb");
    assert_eq!(sanitize_host_component("host."), "host_2e");
    assert_eq!(sanitize_host_component(""), "_empty");
    assert_eq!(sanitize_host_component("../../evil"), "_2e._2f._2e_2fevil");
    // Over 240 bytes: 222-byte prefix cut at an escape boundary + `_h` + FNV-1a-64.
    assert_eq!(
        sanitize_host_component(&"h".repeat(300)),
        format!("{}_h0e8934f306ff03d5", "h".repeat(222))
    );
    assert_eq!(
        sanitize_host_component(&"ü".repeat(150)),
        format!("{}_hc96cd02e8bf8f9f5", "_c3_bc".repeat(37))
    );
}

#[test]
fn sanitize_is_safe_deterministic_and_distinct() {
    let long_ascii = "h".repeat(300);
    let long_upper = "H".repeat(300);
    let long_umlaut = "ü".repeat(150);
    let inputs = [
        "a/b",
        "..",
        "x\\y",
        "jürgen-mbp",
        "a_b",
        ".",
        "a.",
        ".a",
        "a..b",
        "C:",
        "../../etc",
        "with space",
        "tab\tname",
        long_ascii.as_str(),
        long_umlaut.as_str(),
        "",
    ];
    for input in inputs {
        let first = sanitize_host_component(input);
        assert_safe_component(&first);
        assert_eq!(
            first,
            sanitize_host_component(input),
            "not deterministic: {input:?}"
        );
    }
    assert_ne!(
        sanitize_host_component("a_b"),
        sanitize_host_component("a/b")
    );
    assert_ne!(
        sanitize_host_component("_empty"),
        sanitize_host_component("")
    );
    // Over-long names: cut + `_h` + 16 hex digits; case-insensitive.
    let long = sanitize_host_component(&long_ascii);
    assert!(long.len() <= 240, "{}", long.len());
    let (_, hash) = long.rsplit_once("_h").expect("hash marker");
    assert_eq!(hash.len(), 16);
    assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(long, sanitize_host_component(&long_upper));
    // Same 222-byte prefix, different tail -> different component.
    let other = format!("{}x", "h".repeat(299));
    assert_ne!(long, sanitize_host_component(&other));
}

#[test]
fn host_name_is_the_sanitized_raw_name() {
    let raw = raw_host_name().expect("raw_host_name");
    assert!(!raw.is_empty());
    let host = host_name().expect("host_name");
    assert_safe_component(&host);
    assert_eq!(host, sanitize_host_component(&raw));
    println!("V28 raw_host_name={raw:?} host_name={host:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn linux_raw_host_name_is_the_static_host_name() {
    let Ok(text) = std::fs::read_to_string("/etc/hostname") else {
        eprintln!("SKIP: /etc/hostname not readable on this runner");
        return;
    };
    let Some(expected) = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
    else {
        eprintln!("SKIP: /etc/hostname has no host name line");
        return;
    };
    assert_eq!(raw_host_name().expect("raw_host_name"), expected);
}

use std::path::{Path, PathBuf};

use atlas_duck_ipc::paths::{
    APP_DIR_NAME, BaseDirs, base_dirs, cli_file, first_run_defaults, paths_file, pinned_dir,
};

/// Base dirs rooted in a temp dir, so tests never touch the real pinned files.
fn fake_base(root: &Path) -> BaseDirs {
    BaseDirs {
        home: root.join("home"),
        local_app_data: cfg!(windows).then(|| root.join("local")),
        roaming_app_data: cfg!(windows).then(|| root.join("roaming")),
    }
}

// ---------- locations ----------

#[cfg(windows)]
#[test]
fn windows_pinned_files_live_in_local_app_data() {
    let b = base_dirs().expect("base_dirs");
    let local = b.local_app_data.clone().expect("FOLDERID_LocalAppData");
    assert!(b.roaming_app_data.is_some());
    // §13: "on Windows paths.toml/cli.toml are written under %LOCALAPPDATA%".
    if let Some(env_local) = std::env::var_os("LOCALAPPDATA") {
        assert_eq!(local, PathBuf::from(env_local));
    }
    assert_eq!(pinned_dir(&b), local.join(APP_DIR_NAME));
    assert_eq!(
        paths_file(&b, "anyhost"),
        local.join(APP_DIR_NAME).join("paths.toml")
    );
    assert_eq!(
        cli_file(&b, "anyhost"),
        local.join(APP_DIR_NAME).join("cli.toml")
    );
    // Not host-qualified on Windows, and never under roaming %APPDATA%.
    assert_eq!(paths_file(&b, "a"), paths_file(&b, "b"));
    let roaming = b.roaming_app_data.clone().expect("roaming");
    assert!(!paths_file(&b, "a").starts_with(&roaming));
}

#[cfg(unix)]
#[test]
fn unix_pinned_files_are_host_qualified() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let b = fake_base(tmp.path());
    let expected_dir = if cfg!(target_os = "macos") {
        b.home
            .join("Library")
            .join("Application Support")
            .join(APP_DIR_NAME)
    } else {
        b.home.join(".config").join(APP_DIR_NAME)
    };
    assert_eq!(pinned_dir(&b), expected_dir);
    assert_eq!(
        paths_file(&b, "hosta"),
        expected_dir.join("paths-hosta.toml")
    );
    assert_eq!(cli_file(&b, "hosta"), expected_dir.join("cli-hosta.toml"));
    // A host value that is not a safe component never escapes pinned_dir.
    let hostile = paths_file(&b, "../../evil");
    assert_eq!(hostile.parent(), Some(expected_dir.as_path()));
    assert_eq!(hostile, expected_dir.join("paths-_2e._2f._2e_2fevil.toml"));
}

#[cfg(unix)]
#[test]
fn unix_base_dirs_use_the_passwd_home() {
    let b = base_dirs().expect("base_dirs");
    assert!(b.home.is_absolute());
    assert_eq!(b.local_app_data, None);
    assert_eq!(b.roaming_app_data, None);
}

// ---------- path stability: same answers under a bogus environment ----------

const CHILD_ENV: &str = "ATLAS_DUCK_PATHS_CHILD";
const CHILD_PREFIX: &str = "ATLAS_DUCK_PATHS_REPORT ";

fn paths_report() -> String {
    let b = base_dirs().expect("base_dirs");
    let host = host_name().expect("host_name");
    format!(
        "{CHILD_PREFIX}{:?}|{:?}|{:?}|{:?}|{host}",
        b,
        pinned_dir(&b),
        paths_file(&b, &host),
        cli_file(&b, &host)
    )
}

/// Child half of `path_stability_ignores_session_environment`; a no-op in a
/// normal test run.
#[test]
fn child_print_paths() {
    if std::env::var_os(CHILD_ENV).is_some() {
        println!("{}", paths_report());
    }
}

#[test]
fn path_stability_ignores_session_environment() {
    let bogus_dir = if cfg!(windows) {
        r"C:\atlas-duck-bogus"
    } else {
        "/atlas-duck-bogus"
    };
    let out = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args([
            "--exact",
            "child_print_paths",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .env("HOME", bogus_dir)
        .env("USERPROFILE", bogus_dir)
        .env("LOCALAPPDATA", bogus_dir)
        .env("APPDATA", bogus_dir)
        .env("XDG_CONFIG_HOME", bogus_dir)
        .env("XDG_DATA_HOME", bogus_dir)
        .env("HOSTNAME", "bogus-host")
        .env("COMPUTERNAME", "BOGUS-HOST")
        .output()
        .expect("spawn child test process");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "child failed: {stdout}");
    // libtest prints "test child_print_paths ... " before the captured line.
    let start = stdout
        .find(CHILD_PREFIX)
        .unwrap_or_else(|| panic!("child printed no report: {stdout}"));
    let child_line = stdout[start..].lines().next().unwrap_or_default();
    assert_eq!(child_line, paths_report());
    assert!(!child_line.contains("atlas-duck-bogus"));
}

// ---------- first-run defaults ----------

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn linux_first_run_defaults_honour_xdg_only_here() {
    use std::ffi::OsString;
    let b = BaseDirs {
        home: PathBuf::from("/home/u"),
        local_app_data: None,
        roaming_app_data: None,
    };
    let xdg = |k: &str| match k {
        "XDG_DATA_HOME" => Some(OsString::from("/x")),
        "XDG_CONFIG_HOME" => Some(OsString::from("/y")),
        _ => None,
    };
    let d = first_run_defaults(&b, &xdg);
    assert_eq!(d.data_dir, PathBuf::from("/x/atlas-duck"));
    assert_eq!(d.config_dir, PathBuf::from("/y/atlas-duck"));
    let d = first_run_defaults(&b, &|_| None);
    assert_eq!(d.data_dir, PathBuf::from("/home/u/.local/share/atlas-duck"));
    assert_eq!(d.config_dir, PathBuf::from("/home/u/.config/atlas-duck"));
    // Relative or empty XDG values are invalid per the XDG spec and ignored.
    let d = first_run_defaults(&b, &|_| Some(OsString::from("relative")));
    assert_eq!(d.data_dir, PathBuf::from("/home/u/.local/share/atlas-duck"));
    let d = first_run_defaults(&b, &|_| Some(OsString::new()));
    assert_eq!(d.config_dir, PathBuf::from("/home/u/.config/atlas-duck"));
    // The pinned files stay at the passwd-home default regardless of XDG.
    assert_eq!(pinned_dir(&b), PathBuf::from("/home/u/.config/atlas-duck"));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_first_run_defaults() {
    let b = BaseDirs {
        home: PathBuf::from("/Users/u"),
        local_app_data: None,
        roaming_app_data: None,
    };
    let d = first_run_defaults(&b, &|_| Some(std::ffi::OsString::from("/ignored")));
    let expected = PathBuf::from("/Users/u/Library/Application Support/atlas-duck");
    assert_eq!(d.data_dir, expected);
    assert_eq!(d.config_dir, expected);
}

#[cfg(windows)]
#[test]
fn windows_first_run_defaults() {
    let b = BaseDirs {
        home: PathBuf::from(r"C:\Users\u"),
        local_app_data: Some(PathBuf::from(r"C:\Users\u\AppData\Local")),
        roaming_app_data: Some(PathBuf::from(r"C:\Users\u\AppData\Roaming")),
    };
    let d = first_run_defaults(&b, &|_| Some(std::ffi::OsString::from(r"D:\ignored")));
    assert_eq!(
        d.data_dir,
        PathBuf::from(r"C:\Users\u\AppData\Local\atlas-duck")
    );
    assert_eq!(
        d.config_dir,
        PathBuf::from(r"C:\Users\u\AppData\Roaming\atlas-duck")
    );
    let real = base_dirs().expect("base_dirs");
    let d = first_run_defaults(&real, &|_| None);
    assert_eq!(d.data_dir.parent(), real.local_app_data.as_deref());
    assert_eq!(d.config_dir.parent(), real.roaming_app_data.as_deref());
}

use std::fs;
use std::io::Read as _;
use std::time::SystemTime;

use atlas_duck_ipc::paths::{
    CliToml, PINNED_SCHEMA_VERSION, PinnedError, PinnedPaths, read_cli_toml, read_pinned,
    write_cli_toml, write_pinned,
};

/// An absolute path on the host OS, built component by component: `C:\a\b` on
/// Windows, `/a/b` elsewhere. `Path::is_absolute` needs a drive on Windows, so a
/// bare `/data` would be refused there.
fn abs_native(parts: &[&str]) -> PathBuf {
    let mut p = PathBuf::from(if cfg!(windows) { r"C:\" } else { "/" });
    for part in parts {
        p.push(part);
    }
    p
}

/// The same, as text with forward slashes (`C:/tail` on Windows, `/tail` elsewhere):
/// valid inside a TOML string without escaping, and absolute on both OS families.
fn abs_fwd(tail: &str) -> String {
    format!("{}{tail}", if cfg!(windows) { "C:/" } else { "/" })
}

fn sample_pinned() -> PinnedPaths {
    PinnedPaths {
        schema_version: PINNED_SCHEMA_VERSION,
        data_dir: abs_native(&["data", "atlas-duck"]),
        config_dir: abs_native(&["config", "atlas-duck"]),
        install_id: Some("0f3c2a9e-1b7d-4c55-9a51-6c1f0e2d8b44".to_owned()),
    }
}

fn snapshot(p: &Path) -> (Vec<u8>, SystemTime) {
    let bytes = fs::read(p).expect("read snapshot");
    let mtime = fs::metadata(p).and_then(|m| m.modified()).expect("mtime");
    (bytes, mtime)
}

fn dir_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ---------- writing the pinned files ----------

#[cfg(windows)]
#[test]
fn windows_writes_create_the_pinned_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let b = fake_base(tmp.path());
    let paths = paths_file(&b, "ignored");
    let cli = cli_file(&b, "ignored");
    assert!(!pinned_dir(&b).exists());
    write_pinned(&paths, &sample_pinned()).expect("write_pinned");
    write_cli_toml(
        &cli,
        &CliToml {
            app_path: Some(PathBuf::from(r"C:\Apps\atlas-duck-app.exe")),
        },
    )
    .expect("write_cli_toml");
    assert_eq!(
        paths,
        tmp.path()
            .join("local")
            .join(APP_DIR_NAME)
            .join("paths.toml")
    );
    assert_eq!(
        cli,
        tmp.path().join("local").join(APP_DIR_NAME).join("cli.toml")
    );
    assert!(paths.is_file() && cli.is_file());
}

// ---------- shared home / renamed host (macOS, Linux) ----------

#[cfg(unix)]
#[test]
fn shared_home_other_hosts_files_are_never_read_or_touched() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let b = fake_base(tmp.path());
    let other_paths = paths_file(&b, "otherhost");
    let other_cli = cli_file(&b, "otherhost");
    fs::create_dir_all(pinned_dir(&b)).expect("mkdir");
    fs::write(&other_paths, "schema_version = 1\ndata_dir = \"/other/data\"\nconfig_dir = \"/other/config\"\ninstall_id = \"other\"\n")
        .expect("seed other paths");
    fs::write(
        &other_cli,
        "schema_version = 1\napp_path = \"/other/app\"\n",
    )
    .expect("seed other cli");
    let before_paths = snapshot(&other_paths);
    let before_cli = snapshot(&other_cli);

    // This host has no pinned file of its own: before first run.
    let mine = paths_file(&b, "thishost");
    assert!(matches!(read_pinned(&mine), Ok(None)));
    assert!(matches!(read_cli_toml(&cli_file(&b, "thishost")), Ok(None)));

    write_pinned(&mine, &sample_pinned()).expect("write own paths");
    write_cli_toml(
        &cli_file(&b, "thishost"),
        &CliToml {
            app_path: Some(PathBuf::from("/opt/a")),
        },
    )
    .expect("write own cli");

    assert_eq!(snapshot(&other_paths), before_paths);
    assert_eq!(snapshot(&other_cli), before_cli);
    assert_eq!(
        read_pinned(&mine).expect("read own").expect("present"),
        sample_pinned()
    );
}

#[cfg(unix)]
#[test]
fn renamed_host_is_before_first_run_even_next_to_a_corrupt_old_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let b = fake_base(tmp.path());
    fs::create_dir_all(pinned_dir(&b)).expect("mkdir");
    // The old name's file is corrupt: a lookup for the new name must not read it.
    let old = paths_file(&b, &sanitize_host_component("Old-Name.local"));
    fs::write(&old, "data_dir = [unterminated").expect("seed old");
    let before = snapshot(&old);
    let new = paths_file(&b, &sanitize_host_component("New-Name"));
    assert_ne!(old, new);
    assert!(matches!(read_pinned(&new), Ok(None)));
    write_pinned(&new, &sample_pinned()).expect("write new");
    assert_eq!(snapshot(&old), before);
    assert_eq!(
        dir_names(&pinned_dir(&b)),
        ["paths-new-name.toml", "paths-old-name.local.toml"]
    );
}

// ---------- read / write semantics ----------

#[test]
fn missing_files_are_before_first_run() {
    let tmp = tempfile::tempdir().expect("tempdir");
    assert!(matches!(
        read_pinned(&tmp.path().join("paths.toml")),
        Ok(None)
    ));
    assert!(matches!(
        read_cli_toml(&tmp.path().join("cli.toml")),
        Ok(None)
    ));
}

#[test]
fn round_trip_non_ascii_and_long_paths() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Absolute on the host OS (`C:\Users\Jürgen Öz\...` on Windows, `/Users/...`
    // elsewhere): both pinned dirs must be absolute (see
    // `relative_pinned_dirs_are_refused_on_read_and_write`).
    let long_dir = abs_native(&["Users", "Jürgen Öz", &"ä".repeat(270), "atlas-duck"]);
    assert!(long_dir.to_string_lossy().chars().count() > 260);
    let cases = [
        PinnedPaths {
            schema_version: PINNED_SCHEMA_VERSION,
            data_dir: abs_native(&["Users", "Jürgen Öz", "AppData", "Local", "atlas-duck"]),
            config_dir: abs_native(&["Users", "Jürgen Öz", "AppData", "Roaming", "atlas-duck"]),
            install_id: Some("id-1".to_owned()),
        },
        PinnedPaths {
            schema_version: PINNED_SCHEMA_VERSION,
            data_dir: abs_native(&["home", "jürgen", ".local", "share", "atlas-duck"]),
            config_dir: abs_native(&["home", "jürgen", ".config", "atlas-duck"]),
            install_id: None,
        },
        PinnedPaths {
            schema_version: PINNED_SCHEMA_VERSION,
            data_dir: long_dir,
            config_dir: abs_native(&["home", "jürgen", "\"quoted\"", "atlas-duck"]),
            install_id: None,
        },
    ];
    for (i, p) in cases.iter().enumerate() {
        let file = tmp.path().join(format!("paths-{i}.toml"));
        write_pinned(&file, p).expect("write_pinned");
        assert_eq!(read_pinned(&file).expect("read").expect("present"), *p);
    }
    for (i, app) in [
        None,
        Some(r"C:\Users\Jürgen Öz\Apps\atlas-duck-app.exe"),
        Some("/home/jürgen/Apps/Atlas Duck.AppImage"),
    ]
    .into_iter()
    .enumerate()
    {
        let file = tmp.path().join(format!("cli-{i}.toml"));
        let c = CliToml {
            app_path: app.map(PathBuf::from),
        };
        write_cli_toml(&file, &c).expect("write_cli_toml");
        assert_eq!(read_cli_toml(&file).expect("read").expect("present"), c);
    }
}

#[test]
fn written_file_has_the_documented_format() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = tmp.path().join("paths.toml");
    // Forward slashes: absolute on every OS and nothing for TOML to escape.
    let (d, c) = (abs_fwd("d"), abs_fwd("c"));
    write_pinned(
        &file,
        &PinnedPaths {
            schema_version: 1,
            data_dir: PathBuf::from(&d),
            config_dir: PathBuf::from(&c),
            install_id: Some("abc".to_owned()),
        },
    )
    .expect("write");
    assert_eq!(
        fs::read_to_string(&file).expect("read"),
        format!(
            "schema_version = 1\ndata_dir = \"{d}\"\nconfig_dir = \"{c}\"\ninstall_id = \"abc\"\n"
        )
    );
}

#[cfg(unix)]
#[test]
fn unix_non_utf8_path_is_refused_and_nothing_is_written() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("pinned");
    let file = dir.join("paths-h.toml");
    let bad = PathBuf::from(OsStr::from_bytes(&[0x66, 0xff]));
    let p = PinnedPaths {
        data_dir: bad.clone(),
        ..sample_pinned()
    };
    assert!(matches!(write_pinned(&file, &p), Err(PinnedError::NonUtf8Path(ref x)) if *x == bad));
    let c = CliToml {
        app_path: Some(bad.clone()),
    };
    assert!(matches!(
        write_cli_toml(&dir.join("cli-h.toml"), &c),
        Err(PinnedError::NonUtf8Path(_))
    ));
    assert!(!dir.exists(), "nothing may be created");
}

#[cfg(windows)]
#[test]
fn windows_unpaired_surrogate_is_refused_and_nothing_is_written() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("pinned");
    let file = dir.join("paths.toml");
    let bad = PathBuf::from(OsString::from_wide(&[
        u16::from(b'C'),
        u16::from(b':'),
        0xD800,
    ]));
    let p = PinnedPaths {
        config_dir: bad.clone(),
        ..sample_pinned()
    };
    assert!(matches!(write_pinned(&file, &p), Err(PinnedError::NonUtf8Path(ref x)) if *x == bad));
    let c = CliToml {
        app_path: Some(bad),
    };
    assert!(matches!(
        write_cli_toml(&dir.join("cli.toml"), &c),
        Err(PinnedError::NonUtf8Path(_))
    ));
    assert!(!dir.exists(), "nothing may be created");
}

#[test]
fn newer_schema_is_read_additively_and_never_rewritten() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = tmp.path().join("paths.toml");
    let (d2, c2) = (abs_fwd("d2"), abs_fwd("c2"));
    fs::write(
        &file,
        format!(
            "schema_version = 2\ndata_dir = \"{d2}\"\nconfig_dir = \"{c2}\"\ninstall_id = \"id2\"\nfuture_key = \"x\"\n\n[future_table]\nk = 1\n"
        ),
    )
    .expect("seed");
    let before = snapshot(&file);
    let read = read_pinned(&file).expect("additive read").expect("present");
    assert_eq!(
        read,
        PinnedPaths {
            schema_version: 2,
            data_dir: PathBuf::from(&d2),
            config_dir: PathBuf::from(&c2),
            install_id: Some("id2".to_owned()),
        }
    );
    assert!(matches!(
        write_pinned(&file, &sample_pinned()),
        Err(PinnedError::NewerSchema { schema_version: 2 })
    ));
    assert_eq!(snapshot(&file), before);

    let cli = tmp.path().join("cli.toml");
    fs::write(&cli, "schema_version = 7\napp_path = \"/a\"\nnew = true\n").expect("seed cli");
    let before_cli = snapshot(&cli);
    assert_eq!(
        read_cli_toml(&cli).expect("read").expect("present"),
        CliToml {
            app_path: Some(PathBuf::from("/a"))
        }
    );
    assert!(matches!(
        write_cli_toml(&cli, &CliToml::default()),
        Err(PinnedError::NewerSchema { schema_version: 7 })
    ));
    assert_eq!(snapshot(&cli), before_cli);
}

#[test]
fn corrupt_files_are_parse_errors_never_absent_and_stay_untouched() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let secret = "SENTINEL-do-not-echo";
    // Absolute paths, so each case is corrupt for exactly the reason in its comment.
    let (d, c) = (abs_fwd("d"), abs_fwd("c"));
    let cases: [Vec<u8>; 7] = [
        b"data_dir = [unterminated SENTINEL-do-not-echo".to_vec(),
        format!("schema_version = 1\ndata_dir = \"{d}\"\n").into_bytes(), // config_dir missing
        format!("data_dir = \"{d}\"\nconfig_dir = \"{c}\"\n").into_bytes(), // schema_version missing
        format!("schema_version = \"1\"\ndata_dir = \"{d}\"\nconfig_dir = \"{c}\"\n").into_bytes(), // wrong type
        format!("schema_version = 0\ndata_dir = \"{d}\"\nconfig_dir = \"{c}\"\n").into_bytes(), // out of range
        format!("schema_version = 1\ndata_dir = 5\nconfig_dir = \"{c}\"\n").into_bytes(), // wrong type
        [
            format!("schema_version = 1\ndata_dir = \"{d}").into_bytes(),
            vec![0xff], // not UTF-8
            format!("\"\nconfig_dir = \"{c}\"\n").into_bytes(),
        ]
        .concat(),
    ];
    for (i, bytes) in cases.iter().enumerate() {
        let file = tmp.path().join(format!("paths-{i}.toml"));
        fs::write(&file, bytes).expect("seed");
        let before = snapshot(&file);
        let err = read_pinned(&file).expect_err("must be an error");
        assert!(matches!(err, PinnedError::Parse), "case {i}: {err:?}");
        assert!(!err.to_string().contains(secret) && !format!("{err:?}").contains(secret));
        assert!(
            matches!(
                write_pinned(&file, &sample_pinned()),
                Err(PinnedError::Parse)
            ),
            "case {i}"
        );
        assert_eq!(snapshot(&file), before, "case {i} modified");
    }
    let cli = tmp.path().join("cli.toml");
    fs::write(&cli, "app_path = ").expect("seed cli");
    assert!(matches!(read_cli_toml(&cli), Err(PinnedError::Parse)));
}

#[test]
fn relative_pinned_dirs_are_refused_on_read_and_write() {
    // A relative value would resolve against the process's current directory and
    // break §7.7 path stability. `Path::is_absolute` on Windows also rejects
    // drive-relative (`C:foo`) and root-relative (`\data`) paths; the first four
    // are relative on every OS.
    let mut relative = vec!["data", "", "C:foo", "./data"];
    if cfg!(windows) {
        relative.push(r"\data");
    }
    let abs = abs_fwd("ok");
    let tmp = tempfile::tempdir().expect("tempdir");
    for (i, rel) in relative.iter().enumerate() {
        // Read: data_dir relative, then config_dir relative. TOML literal strings
        // (single quotes) keep the backslash of `\data` as it is.
        for (key, text) in [
            (
                "data_dir",
                format!("schema_version = 1\ndata_dir = '{rel}'\nconfig_dir = '{abs}'\n"),
            ),
            (
                "config_dir",
                format!("schema_version = 1\ndata_dir = '{abs}'\nconfig_dir = '{rel}'\n"),
            ),
        ] {
            let file = tmp.path().join(format!("paths-{i}-{key}.toml"));
            fs::write(&file, &text).expect("seed");
            let before = snapshot(&file);
            assert!(
                matches!(read_pinned(&file), Err(PinnedError::Parse)),
                "{key} = {rel:?}"
            );
            assert_eq!(snapshot(&file), before, "{key} = {rel:?} modified");
            // The same file with absolute values reads fine: the path alone decides.
            let ok = text.replace(&format!("'{rel}'"), &format!("'{abs}'"));
            fs::write(&file, ok).expect("reseed");
            assert!(
                matches!(read_pinned(&file), Ok(Some(_))),
                "{key}: absolute control"
            );
        }
        // Write: refused with the offending path; nothing is created.
        let dir = tmp.path().join(format!("pinned-{i}"));
        let file = dir.join("paths.toml");
        for p in [
            PinnedPaths {
                data_dir: PathBuf::from(rel),
                ..sample_pinned()
            },
            PinnedPaths {
                config_dir: PathBuf::from(rel),
                ..sample_pinned()
            },
        ] {
            assert!(
                matches!(write_pinned(&file, &p), Err(PinnedError::NotAbsolutePath(ref x)) if x == Path::new(rel)),
                "write {rel:?}"
            );
        }
        assert!(!dir.exists(), "{rel:?}: nothing may be created");
    }
    // A refused write leaves an existing valid file byte-identical.
    let file = tmp.path().join("existing.toml");
    write_pinned(&file, &sample_pinned()).expect("seed write");
    let before = snapshot(&file);
    let bad = PinnedPaths {
        data_dir: PathBuf::from("data"),
        ..sample_pinned()
    };
    assert!(matches!(
        write_pinned(&file, &bad),
        Err(PinnedError::NotAbsolutePath(_))
    ));
    assert_eq!(snapshot(&file), before);
    // Not Unicode and relative: the Unicode check comes first.
    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let both = PinnedPaths {
            data_dir: PathBuf::from(OsStr::from_bytes(&[0x66, 0xff])),
            ..sample_pinned()
        };
        assert!(matches!(
            write_pinned(&file, &both),
            Err(PinnedError::NonUtf8Path(_))
        ));
    }
}

#[test]
fn write_replaces_the_file_atomically() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = tmp.path().join("paths.toml");
    let first = PinnedPaths {
        install_id: Some("first".to_owned()),
        ..sample_pinned()
    };
    write_pinned(&file, &first).expect("first write");
    let old_bytes = fs::read(&file).expect("read");
    // A handle opened before the rewrite still sees the old content: the
    // rewrite produced a new file and renamed it over the old one instead of
    // truncating the old file in place.
    let mut old_handle = fs::File::open(&file).expect("open old");
    let second = PinnedPaths {
        install_id: Some("second".to_owned()),
        ..sample_pinned()
    };
    write_pinned(&file, &second).expect("second write");
    let mut seen = Vec::new();
    old_handle.read_to_end(&mut seen).expect("read old handle");
    assert_eq!(seen, old_bytes);
    assert_eq!(read_pinned(&file).expect("read").expect("present"), second);
    // No temp file is left behind.
    assert_eq!(dir_names(tmp.path()), ["paths.toml"]);
}
