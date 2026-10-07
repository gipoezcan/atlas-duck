//! §7.7 local-filesystem check and data-dir resolution (T06).
//!
//! Env-gated mount tests (NFS/SMB on Ubuntu, mapped/subst drives and a UNC
//! symlink on Windows) run in the CI job `locality-mounts`, which sets
//! ATLAS_DUCK_REQUIRE_MOUNT_TESTS=1 so an unset variable fails instead of
//! skipping.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use atlas_duck_ipc::paths::{
    DataDirResolution, Locality, NotLocalKind, PinnedPaths, REASON_DATA_DIR_MISSING,
    REASON_DATA_DIR_NOT_LOCAL, check_data_dir, check_locality, classify_linux_f_type,
    classify_macos_mnt_flags, classify_windows_drive_type, resolve_data_dir, win_drive_type,
};

fn listing(dir: &Path) -> Vec<OsString> {
    let mut names: Vec<OsString> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    names
}

fn pinned(data_dir: PathBuf) -> PinnedPaths {
    PinnedPaths {
        schema_version: 1,
        config_dir: data_dir.clone(),
        data_dir,
        install_id: None,
    }
}

/// Path from an env var, or `None` with a loud skip. Under
/// ATLAS_DUCK_REQUIRE_MOUNT_TESTS=1 a missing variable is a failure.
#[cfg(any(target_os = "linux", windows))]
fn gated_path(var: &str) -> Option<PathBuf> {
    match std::env::var_os(var) {
        Some(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => {
            let required =
                std::env::var_os("ATLAS_DUCK_REQUIRE_MOUNT_TESTS").is_some_and(|v| v == "1");
            assert!(
                !required,
                "{var} is unset but ATLAS_DUCK_REQUIRE_MOUNT_TESTS=1"
            );
            eprintln!("SKIPPED: {var} is unset; this test runs in CI job `locality-mounts`");
            None
        }
    }
}

// ---------- pure classifiers (every OS) ----------

#[test]
fn linux_f_type_table() {
    let not_local_network = [
        ("NFS", 0x6969_u64),
        ("SMB", 0x517B),
        ("CIFS", 0xFF53_4D42),
        ("SMB2", 0xFE53_4D42),
        ("AFS", 0x5346_414F),
        ("CEPH", 0x00C3_6400),
        ("9P", 0x0102_1997),
    ];
    for (name, magic) in not_local_network {
        assert_eq!(
            classify_linux_f_type(magic),
            Locality::NotLocal(NotLocalKind::NetworkFs { f_type: magic }),
            "{name}"
        );
    }
    assert_eq!(
        classify_linux_f_type(0x6573_5546),
        Locality::NotLocal(NotLocalKind::Fuse),
        "FUSE"
    );
    let local = [
        ("EXT4", 0xEF53_u64),
        ("XFS", 0x5846_5342),
        ("BTRFS", 0x9123_683E),
        ("TMPFS", 0x0102_1994),
        ("OVERLAYFS", 0x794C_7630),
        ("unknown", 0x1234_5678),
    ];
    for (name, magic) in local {
        assert_eq!(classify_linux_f_type(magic), Locality::Local, "{name}");
    }
    // A 32-bit target hands CIFS over as a sign-extended negative i32.
    assert_eq!(
        classify_linux_f_type(0xFFFF_FFFF_FF53_4D42),
        Locality::NotLocal(NotLocalKind::NetworkFs {
            f_type: 0xFF53_4D42
        })
    );
}

#[test]
fn windows_drive_type_table() {
    use win_drive_type::*;
    assert_eq!(
        classify_windows_drive_type(DRIVE_REMOTE),
        Locality::NotLocal(NotLocalKind::RemoteDrive)
    );
    for t in [DRIVE_NO_ROOT_DIR, DRIVE_UNKNOWN, 7, u32::MAX] {
        assert_eq!(
            classify_windows_drive_type(t),
            Locality::NotLocal(NotLocalKind::UnknownDrive),
            "drive type {t}"
        );
    }
    for t in [DRIVE_FIXED, DRIVE_REMOVABLE] {
        assert_eq!(
            classify_windows_drive_type(t),
            Locality::Local,
            "drive type {t}"
        );
    }
}

#[test]
fn macos_mnt_local_flags() {
    const MNT_RDONLY: u64 = 0x1;
    const MNT_LOCAL: u64 = 0x1000;
    assert_eq!(classify_macos_mnt_flags(MNT_LOCAL), Locality::Local);
    assert_eq!(
        classify_macos_mnt_flags(MNT_LOCAL | MNT_RDONLY),
        Locality::Local
    );
    assert_eq!(
        classify_macos_mnt_flags(0),
        Locality::NotLocal(NotLocalKind::NotMntLocal)
    );
    assert_eq!(
        classify_macos_mnt_flags(MNT_RDONLY),
        Locality::NotLocal(NotLocalKind::NotMntLocal)
    );
}

// ---------- data-dir check and resolution (every OS) ----------

#[test]
fn nonexistent_path_is_missing_and_nothing_is_created() {
    let base = tempfile::tempdir().unwrap();
    let before = listing(base.path());
    let path = base.path().join("data");
    assert_eq!(
        check_data_dir(&path).unwrap(),
        DataDirResolution::Missing { path: path.clone() }
    );
    assert!(!path.exists());
    assert_eq!(listing(base.path()), before);
}

#[test]
fn regular_file_is_missing() {
    let base = tempfile::tempdir().unwrap();
    let path = base.path().join("data");
    std::fs::write(&path, b"not a dir").unwrap();
    let before = listing(base.path());
    assert_eq!(
        check_data_dir(&path).unwrap(),
        DataDirResolution::Missing { path: path.clone() }
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"not a dir");
    assert_eq!(listing(base.path()), before);
}

#[test]
fn local_temp_dir_is_local_and_path_is_unchanged() {
    let base = tempfile::tempdir().unwrap();
    let path = base.path().join("data");
    std::fs::create_dir(&path).unwrap();
    let before_parent = listing(base.path());
    let before_dir = listing(&path);
    match check_data_dir(&path).unwrap() {
        DataDirResolution::Local(dir) => assert_eq!(dir.path(), path.as_path()),
        other => panic!("expected Local, got {other:?}"),
    }
    assert_eq!(check_locality(&path).unwrap(), Locality::Local);
    assert_eq!(listing(base.path()), before_parent);
    assert_eq!(listing(&path), before_dir);
}

#[test]
fn check_locality_of_a_missing_path_is_an_error() {
    let base = tempfile::tempdir().unwrap();
    assert!(check_locality(&base.path().join("absent")).is_err());
}

#[test]
fn resolve_without_pinned_file_is_before_first_run() {
    assert_eq!(
        resolve_data_dir(None).unwrap(),
        DataDirResolution::BeforeFirstRun
    );
}

#[test]
fn resolve_removed_pinned_dir_is_missing_and_not_recreated() {
    let base = tempfile::tempdir().unwrap();
    let path = base.path().join("data");
    std::fs::create_dir(&path).unwrap();
    std::fs::remove_dir(&path).unwrap();
    let p = pinned(path.clone());
    let got = resolve_data_dir(Some(&p)).unwrap();
    assert_eq!(got, DataDirResolution::Missing { path: path.clone() });
    assert_eq!(got.reason(), Some(REASON_DATA_DIR_MISSING));
    assert!(!path.exists());
}

#[test]
fn resolve_local_pinned_dir_is_local() {
    let base = tempfile::tempdir().unwrap();
    let p = pinned(base.path().to_path_buf());
    match resolve_data_dir(Some(&p)).unwrap() {
        DataDirResolution::Local(dir) => assert_eq!(dir.path(), base.path()),
        other => panic!("expected Local, got {other:?}"),
    }
}

#[test]
fn reason_strings_are_the_spec_values() {
    assert_eq!(REASON_DATA_DIR_MISSING, "data_dir_missing");
    assert_eq!(REASON_DATA_DIR_NOT_LOCAL, "data_dir_not_local");
    let not_local = DataDirResolution::NotLocal {
        path: PathBuf::from("x"),
        kind: NotLocalKind::Unc,
    };
    assert_eq!(not_local.reason(), Some(REASON_DATA_DIR_NOT_LOCAL));
    assert_eq!(DataDirResolution::BeforeFirstRun.reason(), None);
}

// ---------- Windows ----------

#[cfg(windows)]
#[test]
fn unc_paths_are_refused_without_an_os_call() {
    // `\\localhost\C$\Windows` exists; if GetDriveTypeW ran it would report
    // DRIVE_REMOTE (RemoteDrive). `Unc` proves the string-only branch.
    for p in [
        r"\\server\share\x",
        r"\\?\UNC\server\share\x",
        r"\\localhost\C$\Windows",
        r"//server/share/x",
        r"\\.\UNC\server\share\x",
    ] {
        let path = Path::new(p);
        assert_eq!(
            check_locality(path).unwrap(),
            Locality::NotLocal(NotLocalKind::Unc),
            "{p}"
        );
        // Not `Missing`: the prefix check runs before the existence check.
        assert_eq!(
            check_data_dir(path).unwrap(),
            DataDirResolution::NotLocal {
                path: path.to_path_buf(),
                kind: NotLocalKind::Unc
            },
            "{p}"
        );
    }
}

#[cfg(windows)]
#[test]
fn device_namespace_path_is_not_local() {
    assert_eq!(
        check_locality(Path::new(r"\\.\C:\Windows")).unwrap(),
        Locality::NotLocal(NotLocalKind::UnknownDrive)
    );
}

#[cfg(windows)]
#[test]
fn temp_dir_on_c_is_local() {
    assert_eq!(check_locality(Path::new(r"C:\")).unwrap(), Locality::Local);
    let base = tempfile::tempdir().unwrap();
    assert_eq!(check_locality(base.path()).unwrap(), Locality::Local);
}

#[cfg(windows)]
#[test]
fn unmounted_drive_letter_is_missing() {
    // Find a drive letter with no volume behind it.
    let free = (b'D'..=b'Z')
        .rev()
        .map(|l| format!("{}:\\", l as char))
        .find(|root| !Path::new(root).exists())
        .expect("no free drive letter");
    let path = PathBuf::from(format!("{free}atlas-duck"));
    assert_eq!(
        check_data_dir(&path).unwrap(),
        DataDirResolution::Missing { path }
    );
}

#[cfg(windows)]
#[test]
fn non_ascii_dir_longer_than_260_chars_is_local() {
    use std::os::windows::ffi::OsStrExt;
    let base = tempfile::tempdir().unwrap();
    let mut path = base.path().to_path_buf();
    while path.as_os_str().encode_wide().count() <= 300 {
        path.push("Jürgen-Öz-日本語-ğüşiöç");
    }
    std::fs::create_dir_all(&path).unwrap();
    assert_eq!(check_locality(&path).unwrap(), Locality::Local);
    match check_data_dir(&path).unwrap() {
        DataDirResolution::Local(dir) => assert_eq!(dir.path(), path.as_path()),
        other => panic!("expected Local, got {other:?}"),
    }
}

#[cfg(windows)]
#[test]
fn mapped_network_drive_is_remote() {
    let Some(path) = gated_path("ATLAS_DUCK_TEST_MAPPED_DRIVE") else {
        return;
    };
    let got = check_locality(&path).unwrap();
    eprintln!("V29 mapped drive {}: {got:?}", path.display());
    assert_eq!(got, Locality::NotLocal(NotLocalKind::RemoteDrive));
    assert_eq!(
        check_data_dir(&path).unwrap(),
        DataDirResolution::NotLocal {
            path: path.clone(),
            kind: NotLocalKind::RemoteDrive
        }
    );
}

#[cfg(windows)]
#[test]
fn subst_drive_over_local_dir_is_local() {
    let Some(path) = gated_path("ATLAS_DUCK_TEST_SUBST_DRIVE") else {
        return;
    };
    let got = check_locality(&path).unwrap();
    eprintln!("V29 subst drive {}: {got:?}", path.display());
    assert_eq!(got, Locality::Local);
}

#[cfg(windows)]
#[test]
fn local_symlink_to_unc_share_is_unc() {
    let Some(path) = gated_path("ATLAS_DUCK_TEST_UNC_SYMLINK") else {
        return;
    };
    let got = check_locality(&path).unwrap();
    eprintln!("V29 symlink to UNC {}: {got:?}", path.display());
    assert_eq!(got, Locality::NotLocal(NotLocalKind::Unc));
}

// ---------- Linux ----------

#[cfg(target_os = "linux")]
#[test]
fn nfs_mount_is_not_local() {
    let Some(path) = gated_path("ATLAS_DUCK_TEST_NFS_DIR") else {
        return;
    };
    let expected = Locality::NotLocal(NotLocalKind::NetworkFs { f_type: 0x6969 });
    assert_eq!(check_locality(&path).unwrap(), expected);
    assert_eq!(
        check_data_dir(&path).unwrap(),
        DataDirResolution::NotLocal {
            path: path.clone(),
            kind: NotLocalKind::NetworkFs { f_type: 0x6969 },
        }
    );
}

#[cfg(target_os = "linux")]
#[test]
fn smb_mount_is_not_local() {
    let Some(path) = gated_path("ATLAS_DUCK_TEST_SMB_DIR") else {
        return;
    };
    let got = check_locality(&path).unwrap();
    eprintln!("V29 cifs mount {}: {got:?}", path.display());
    match got {
        Locality::NotLocal(NotLocalKind::NetworkFs { f_type }) => {
            assert!(
                [0x517B, 0xFF53_4D42, 0xFE53_4D42].contains(&f_type),
                "{f_type:#x}"
            );
        }
        other => panic!("expected NetworkFs, got {other:?}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn local_symlink_into_nfs_is_not_local() {
    let Some(nfs) = gated_path("ATLAS_DUCK_TEST_NFS_DIR") else {
        return;
    };
    let base = tempfile::tempdir().unwrap();
    let link = base.path().join("data");
    std::os::unix::fs::symlink(&nfs, &link).unwrap();
    assert_eq!(
        check_data_dir(&link).unwrap(),
        DataDirResolution::NotLocal {
            path: link.clone(),
            kind: NotLocalKind::NetworkFs { f_type: 0x6969 },
        }
    );
}

// ---------- macOS ----------

#[cfg(target_os = "macos")]
#[test]
fn macos_root_and_temp_dir_are_local() {
    assert_eq!(check_locality(Path::new("/")).unwrap(), Locality::Local);
    let base = tempfile::tempdir().unwrap();
    assert_eq!(check_locality(base.path()).unwrap(), Locality::Local);
}
