//! Rename durability (M2 final review M-2; §8.11 step 5, §8.7 archive): the restore commit,
//! first-run and archive renames go through `durable_rename` (Windows: `MoveFileExW` with
//! `MOVEFILE_WRITE_THROUGH`), and `sync_dir` flushes the directory on every OS (Windows:
//! `FlushFileBuffers` on a handle opened with `FILE_FLAG_BACKUP_SEMANTICS`).

mod common;

use std::path::{Path, PathBuf};

use atlas_duck_audit::schema::DB_FILE;
use atlas_duck_audit::testing::{MemKeyring, durable_rename, durable_renames_into};
use atlas_duck_audit::types::{Confirmed, RustChosenPath};
use atlas_duck_audit::{archive_and_start_fresh, restore_from_source};
use common::*;
use rusqlite::Connection;
use secrecy::SecretString;

fn chosen(p: &Path) -> RustChosenPath {
    RustChosenPath::from_native_dialog(p.to_path_buf())
}

fn confirmed() -> Confirmed {
    Confirmed {
        dialog_text_sha256: [7; 32],
    }
}

fn pass(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

/// A SQLite file at `path` holding one row `note`.
fn db_with(path: &Path, note: &str) {
    let c = Connection::open(path).expect("open");
    c.execute_batch("CREATE TABLE t (note TEXT NOT NULL)")
        .expect("create");
    c.execute("INSERT INTO t (note) VALUES (?1)", [note])
        .expect("insert");
}

fn note_of(path: &Path) -> String {
    Connection::open(path)
        .expect("reopen")
        .query_row("SELECT note FROM t", [], |r| r.get(0))
        .expect("row")
}

#[test]
fn durable_rename_replaces_and_survives_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("store.db");
    let staged = dir.path().join("store.db.new");
    db_with(&target, "old");
    db_with(&staged, "new");

    durable_rename(&staged, &target).expect("replace an existing file");
    assert!(!staged.exists(), "the source name is gone");
    assert_eq!(
        note_of(&target),
        "new",
        "a fresh connection sees the new file"
    );

    // Onto a missing name, and across directories (the archive move).
    let sub = dir.path().join("archived");
    std::fs::create_dir(&sub).expect("subdir");
    let moved = sub.join("store-1.db");
    durable_rename(&target, &moved).expect("move into a subdirectory");
    assert!(!target.exists());
    assert_eq!(note_of(&moved), "new");

    // A missing source fails and leaves the target as it was.
    let e = durable_rename(&dir.path().join("absent"), &moved).expect_err("no source");
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    assert_eq!(note_of(&moved), "new");

    // An interior NUL never reaches the OS (it would name another file).
    let e = durable_rename(&moved, &dir.path().join("x\0y")).expect_err("NUL");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
    assert_eq!(note_of(&moved), "new");
}

/// `FILE_FLAG_BACKUP_SEMANTICS` (the test crate has no `windows-sys`).
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

#[cfg(windows)]
#[test]
fn windows_sync_dir_flushes_directory_handle() {
    use std::sync::Mutex;

    use atlas_duck_audit::testing::{open_dir_handle, sync_dir_with};

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("f"), b"x").expect("file");
    let seen: Mutex<Vec<(PathBuf, u32)>> = Mutex::new(Vec::new());
    sync_dir_with(dir.path(), &|p: &Path, flags: u32| {
        seen.lock().expect("lock").push((p.to_path_buf(), flags));
        open_dir_handle(p, flags)
    })
    .expect("the directory handle is flushed");
    let seen = seen.into_inner().expect("lock");
    assert_eq!(seen.len(), 1, "one handle per flush: {seen:?}");
    assert_eq!(seen[0].0, dir.path());
    assert_ne!(
        seen[0].1 & FILE_FLAG_BACKUP_SEMANTICS,
        0,
        "a directory handle needs backup semantics: {:#x}",
        seen[0].1
    );
    // The flag is load-bearing: without it a directory does not open at all.
    assert!(open_dir_handle(dir.path(), 0).is_err());
    // So is the opener's write access: a read-only directory handle is not flushed.
    {
        use std::os::windows::fs::OpenOptionsExt;
        let ro = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir.path())
            .expect("read-only directory handle");
        assert!(
            ro.sync_all().is_err(),
            "FlushFileBuffers needs write access"
        );
    }
    // An opener error is the flush's error.
    let e = sync_dir_with(dir.path(), &|_: &Path, _: u32| {
        Err(std::io::Error::other("injected open failure"))
    })
    .expect_err("opener fails");
    assert_eq!(e.to_string(), "injected open failure");
}

/// The `MoveFileExW` flags (the test crate has no `windows-sys`).
#[cfg(windows)]
#[test]
fn windows_rename_asks_for_replace_and_write_through() {
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let flags = atlas_duck_audit::testing::durable_move_flags();
    assert_eq!(
        flags,
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        "{flags:#x}"
    );
}

/// A bundle directory that cannot be flushed (FAT, a share, a drop folder) is still a complete
/// backup: the flush is best effort, the manifest-last rename is the completeness contract.
#[test]
fn backup_succeeds_when_the_bundle_dir_flush_fails() {
    let (a, _fa) = new_store(fake_clock(START), MemKeyring::new());
    a.append_batch(mixed(4)).expect("append_batch");
    a.flush_head_anchor().expect("flush");
    let out = tempfile::tempdir().expect("out dir");
    atlas_duck_audit::testing::fail_sync_dir_under(out.path());
    let bundle = a
        .backup(chosen(out.path()))
        .expect("a failing directory flush does not fail the backup");
    assert!(bundle.bundle_dir.join("manifest.json").is_file());
    assert!(
        bundle.backup_seq > bundle.head_seq,
        "the BACKUP record was appended"
    );
}

fn renamed(from: &Path, to: &Path) -> (PathBuf, PathBuf) {
    (from.to_path_buf(), to.to_path_buf())
}

#[test]
fn restore_commit_uses_durable_rename() {
    let (a, _fa) = new_store(fake_clock(START), MemKeyring::new());
    a.append_batch(mixed(6)).expect("append_batch");
    a.flush_head_anchor().expect("flush");
    let out = tempfile::tempdir().expect("out dir");
    let bundle = a.backup(chosen(out.path())).expect("backup");

    // No store yet (wizard restore): the staging file is renamed to `audit.db`.
    let fb = fixture(fake_clock(START), MemKeyring::new());
    let (b, _) = restore_from_source(
        &fb.data,
        &fb.lock,
        fb.config(),
        chosen(&bundle.bundle_dir),
        &pass(PASSPHRASE),
        confirmed(),
        None,
    )
    .expect("restore from source");
    let db = fb.data.path().join(DB_FILE);
    let staging = fb.data.path().join("audit.db.restoring");
    assert_eq!(
        durable_renames_into(fb.data.path()),
        vec![renamed(&staging, &db)]
    );
    b.shutdown();

    // A live store: the same commit, after the replaced store was linked into `archived/`.
    let (c, fc) = new_store(fake_clock(START), MemKeyring::new());
    let first_run = durable_renames_into(fc.data.path());
    c.restore(
        chosen(&bundle.bundle_dir),
        &pass(PASSPHRASE),
        confirmed(),
        None,
    )
    .expect("live restore");
    let db = fc.data.path().join(DB_FILE);
    let staging = fc.data.path().join("audit.db.restoring");
    let mut expected = first_run;
    expected.push(renamed(&staging, &db));
    assert_eq!(durable_renames_into(fc.data.path()), expected);
}

#[test]
fn first_run_and_archive_use_durable_rename() {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    let db = f.data.path().join(DB_FILE);
    assert_eq!(
        durable_renames_into(f.data.path()),
        vec![renamed(&f.data.path().join("audit.db.new"), &db)]
    );
    store.append_batch(mixed(3)).expect("append_batch");
    store.flush_head_anchor().expect("flush");
    store.shutdown();

    let a = archive_and_start_fresh(&f.data, &f.lock, confirmed()).expect("archive");
    let target = f.data.path().join(&a.file);
    let log = durable_renames_into(f.data.path());
    assert_eq!(log[1], renamed(&db, &target), "{log:?}");
    // The WAL (when the store left one) moves with it; nothing else is renamed.
    for r in &log[2..] {
        assert_eq!(
            *r,
            renamed(
                &f.data.path().join("audit.db-wal"),
                &f.data.path().join(format!("{}-wal", a.file))
            )
        );
    }
    assert!(log.len() <= 3, "{log:?}");
}
