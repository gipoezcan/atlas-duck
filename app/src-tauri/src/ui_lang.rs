//! The desktop language preference (M15 T3, PD-294): one word (`auto`, `en`, `de`) in
//! `<local data dir>/ui-lang`. App-side, outside the audit store and not audited: the gate
//! dialogs, "Waiting for keyring" and the no-tray message show while core is locked, and the
//! language is not a security setting.

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::i18n::LangPref;

/// The file in the local data dir.
pub const FILE_NAME: &str = "ui-lang";

/// The longest file [`load`] reads; anything longer is garbage.
const MAX_BYTES: u64 = 16;

static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);

/// The stored preference; a missing, unreadable or garbled file is `Auto`.
pub fn load(dir: &Path) -> LangPref {
    let path = dir.join(FILE_NAME);
    match fs::metadata(&path) {
        Ok(m) if m.is_file() && m.len() <= MAX_BYTES => {}
        _ => return LangPref::Auto,
    }
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| LangPref::parse(s.trim()))
        .unwrap_or_default()
}

/// Writes `pref` atomically: a new temp file next to it, flushed, renamed over the old one, and
/// (Unix, best effort) the rename itself flushed, as `ipc::paths`'s atomic writes do. A temp file
/// a crashed earlier write left behind is removed first.
pub fn store(dir: &Path, pref: LangPref) -> io::Result<()> {
    sweep_temps(dir);
    let tmp = dir.join(format!(
        ".{FILE_NAME}.{}.{}.tmp",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| -> io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(pref.as_str().as_bytes())?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, dir.join(FILE_NAME))
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
        return written;
    }
    #[cfg(unix)]
    if let Ok(d) = fs::File::open(dir) {
        // Best effort: persist the rename itself.
        let _ = d.sync_all();
    }
    Ok(())
}

/// Removes the `.ui-lang.*.tmp` regular files in `dir` (symlinks are not followed). Best effort:
/// the language is a preference, a temp file that stays is harmless.
fn sweep_temps(dir: &Path) {
    let prefix = format!(".{FILE_NAME}.");
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(&prefix)
            && name.ends_with(".tmp")
            && fs::symlink_metadata(entry.path()).is_ok_and(|m| m.is_file())
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn load_missing_is_auto() -> TestResult {
        let dir = tempfile::tempdir()?;
        assert_eq!(load(dir.path()), LangPref::Auto);
        assert_eq!(load(&dir.path().join("absent")), LangPref::Auto);
        Ok(())
    }

    #[test]
    fn load_garbage_is_auto() -> TestResult {
        let dir = tempfile::tempdir()?;
        for garbage in [
            "",
            "DE",
            "fr",
            "de en",
            "\u{feff}de",
            "dededededededededede",
        ] {
            fs::write(dir.path().join(FILE_NAME), garbage)?;
            assert_eq!(load(dir.path()), LangPref::Auto, "{garbage:?}");
        }
        // A directory in the file's place.
        let other = tempfile::tempdir()?;
        fs::create_dir(other.path().join(FILE_NAME))?;
        assert_eq!(load(other.path()), LangPref::Auto);
        Ok(())
    }

    #[test]
    fn store_then_load_roundtrips() -> TestResult {
        let dir = tempfile::tempdir()?;
        for pref in [LangPref::De, LangPref::En, LangPref::Auto, LangPref::De] {
            store(dir.path(), pref)?;
            assert_eq!(load(dir.path()), pref);
        }
        assert_eq!(fs::read_to_string(dir.path().join(FILE_NAME))?, "de");
        // No temp file is left behind.
        let names: Vec<_> = fs::read_dir(dir.path())?
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(FILE_NAME)]);
        // Trailing whitespace (a hand edit) is accepted.
        fs::write(dir.path().join(FILE_NAME), "en\n")?;
        assert_eq!(load(dir.path()), LangPref::En);
        Ok(())
    }

    /// Review m-6: a temp file a crashed write left behind is gone after the next write; other
    /// files are kept.
    #[test]
    fn store_sweeps_stale_temp_files() -> TestResult {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join(".ui-lang.999.3.tmp"), "de")?;
        fs::write(dir.path().join("audit.db"), "x")?;
        fs::write(dir.path().join(".endpoint.1.1.tmp"), "x")?;
        store(dir.path(), LangPref::En)?;
        let mut names: Vec<_> = fs::read_dir(dir.path())?
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        names.sort();
        assert_eq!(names, [".endpoint.1.1.tmp", "audit.db", FILE_NAME]);
        assert_eq!(load(dir.path()), LangPref::En);
        Ok(())
    }

    #[test]
    fn store_into_a_missing_dir_fails_and_leaves_nothing() -> TestResult {
        let dir = tempfile::tempdir()?;
        let missing = dir.path().join("gone");
        assert!(store(&missing, LangPref::De).is_err());
        assert!(!missing.exists());
        Ok(())
    }
}
