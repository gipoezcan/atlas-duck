//! PD-02: the test build's keystore. One file per entry, `<dir>/<hex(full_name)>`, holding the
//! value as lowercase hex; a `mode` file (`ok|unavailable|locked|not_local`, read on every call)
//! lets a test provoke each `locked` reason without an OS keychain. The test harness
//! (`tests/cli_flows`) provisions stores through [`provision`], so both sides agree on the
//! format. Never in a release build (the feature's lock in `lib.rs`).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use atlas_duck_audit::{EntryName, KeyStore, KeyStoreError, KeyringLocality};
use zeroize::Zeroizing;

/// The mode file in the keystore dir. Missing: `ok`.
pub const MODE_FILE: &str = "mode";

/// The contents of [`MODE_FILE`].
pub const MODE_OK: &str = "ok";
/// Every call fails `KeyStoreError::Unavailable` (→ `locked {keychain_unavailable}`).
pub const MODE_UNAVAILABLE: &str = "unavailable";
/// Every call fails `KeyStoreError::Locked`.
pub const MODE_LOCKED: &str = "locked";
/// Calls work; `locality()` is `NotLocal { dir }` (→ `locked {keyring_not_local}`).
pub const MODE_NOT_LOCAL: &str = "not_local";

const MSG_UNKNOWN_MODE: &str = "unknown test keystore mode";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Ok,
    Unavailable,
    Locked,
    NotLocal,
}

/// The file keystore of one install id.
#[derive(Debug, Clone)]
pub struct FileKeyStore {
    dir: PathBuf,
    install_id: String,
}

/// Creates `dir` (0700 on Unix) with `mode` = `ok` unless a mode file exists, and returns the
/// keystore for `install_id` in it. What the test harness and the app share.
pub fn provision(dir: &Path, install_id: &str) -> io::Result<FileKeyStore> {
    create_private_dir(dir)?;
    if !dir.join(MODE_FILE).try_exists()? {
        write_atomic(dir, MODE_FILE, MODE_OK.as_bytes())?;
    }
    Ok(FileKeyStore::open(dir, install_id))
}

/// Replaces the mode file (`ok|unavailable|locked|not_local`) atomically.
pub fn set_mode(dir: &Path, mode: &str) -> io::Result<()> {
    write_atomic(dir, MODE_FILE, mode.as_bytes())
}

impl FileKeyStore {
    /// Opens nothing yet: every call reads `dir` afresh.
    pub fn open(dir: &Path, install_id: &str) -> FileKeyStore {
        FileKeyStore {
            dir: dir.to_owned(),
            install_id: install_id.to_owned(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The file name of an entry: lowercase hex of `EntryName::full_name` (it contains `/`).
    pub fn file_name(&self, e: &EntryName) -> String {
        hex_encode(e.full_name(&self.install_id).as_bytes())
    }

    fn mode(&self) -> Result<Mode, KeyStoreError> {
        let text = match fs::read_to_string(self.dir.join(MODE_FILE)) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Mode::Ok),
            Err(_) => return Err(KeyStoreError::Unavailable),
        };
        match text.trim() {
            MODE_OK => Ok(Mode::Ok),
            MODE_UNAVAILABLE => Ok(Mode::Unavailable),
            MODE_LOCKED => Ok(Mode::Locked),
            MODE_NOT_LOCAL => Ok(Mode::NotLocal),
            _ => Err(KeyStoreError::Other(MSG_UNKNOWN_MODE.to_owned())),
        }
    }

    /// The gate every entry call passes: `unavailable` and `locked` refuse it.
    fn usable(&self) -> Result<(), KeyStoreError> {
        match self.mode()? {
            Mode::Ok | Mode::NotLocal => Ok(()),
            Mode::Unavailable => Err(KeyStoreError::Unavailable),
            Mode::Locked => Err(KeyStoreError::Locked),
        }
    }
}

impl KeyStore for FileKeyStore {
    fn install_id(&self) -> &str {
        &self.install_id
    }

    fn get(&self, e: &EntryName) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        self.usable()?;
        let text = match fs::read_to_string(self.dir.join(self.file_name(e))) {
            Ok(t) => Zeroizing::new(t),
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(KeyStoreError::Unavailable),
        };
        hex_decode(text.trim())
            .map(|v| Some(Zeroizing::new(v)))
            .ok_or(KeyStoreError::Corrupt)
    }

    fn set(&self, e: &EntryName, v: &[u8]) -> Result<(), KeyStoreError> {
        self.usable()?;
        let text = Zeroizing::new(hex_encode(v));
        write_atomic(&self.dir, &self.file_name(e), text.as_bytes())
            .map_err(|_| KeyStoreError::Unavailable)
    }

    fn delete(&self, e: &EntryName) -> Result<(), KeyStoreError> {
        self.usable()?;
        match fs::remove_file(self.dir.join(self.file_name(e))) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(KeyStoreError::Unavailable),
        }
    }

    fn locality(&self) -> KeyringLocality {
        match self.mode() {
            Ok(Mode::NotLocal) => KeyringLocality::NotLocal {
                dir: self.dir.clone(),
            },
            // `unavailable`/`locked` refuse every call; the entries themselves are local.
            Ok(_) => KeyringLocality::Local,
            Err(_) => KeyringLocality::Unknown {
                reason: MSG_UNKNOWN_MODE.to_owned(),
            },
        }
    }

    /// As `OsKeyStore` (M10 T14, "Forget old install"): the same dir and mode file under another
    /// install's names; `None` for anything but an install id (32 lowercase hex).
    fn for_install(&self, install_id: &str) -> Option<Box<dyn KeyStore>> {
        atlas_duck_audit::open::is_id(install_id)
            .then(|| Box::new(FileKeyStore::open(&self.dir, install_id)) as Box<dyn KeyStore>)
    }
}

#[cfg(unix)]
pub(super) fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
pub(super) fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

/// Writes `<dir>/<name>` through a temp file in `dir` and a rename, so a reader in another
/// process sees the old or the new content, never a part.
pub(super) fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{name}.{}.{n}.tmp", std::process::id()));
    let written = (|| {
        let mut f = new_private_file(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, dir.join(name))
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

#[cfg(unix)]
fn new_private_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn new_private_file(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing into a String cannot fail.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Lowercase or uppercase hex of even length; anything else is `None`.
pub(super) fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| match pair {
            [hi, lo] => Some(digit(*hi)? << 4 | digit(*lo)?),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use atlas_duck_audit::keystore::canary_self_test;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const ID: &str = "7e570000aaaabbbbccccddddeeeeffff";

    #[test]
    fn file_keystore_roundtrip_and_modes() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("keys");
        let ks = provision(&dir, ID)?;
        assert_eq!(fs::read_to_string(dir.join(MODE_FILE))?, MODE_OK);
        assert_eq!(ks.install_id(), ID);

        // set / get / delete.
        assert_eq!(ks.get(&EntryName::Kek)?, None);
        ks.set(&EntryName::Kek, &[0x00, 0x7f, 0xff, 0x10])?;
        let got = ks.get(&EntryName::Kek)?.ok_or("kek missing")?;
        assert_eq!(got.as_slice(), &[0x00, 0x7f, 0xff, 0x10]);
        // The format the harness relies on: `<dir>/<hex(full_name)>` holding hex.
        let name = hex_encode(EntryName::Kek.full_name(ID).as_bytes());
        assert_eq!(ks.file_name(&EntryName::Kek), name);
        assert_eq!(fs::read_to_string(dir.join(&name))?, "007fff10");
        ks.set(&EntryName::Kek, b"second")?;
        assert_eq!(
            ks.get(&EntryName::Kek)?.ok_or("kek missing")?.as_slice(),
            b"second"
        );
        let pat = EntryName::Pat("inst_1".into());
        ks.set(&pat, b"PATCANARY")?;
        ks.delete(&EntryName::Kek)?;
        assert_eq!(ks.get(&EntryName::Kek)?, None);
        // Deleting an absent entry is fine; other entries stay.
        ks.delete(&EntryName::Kek)?;
        assert_eq!(ks.get(&pat)?.ok_or("pat missing")?.as_slice(), b"PATCANARY");
        // Another install id sees none of these entries.
        assert_eq!(FileKeyStore::open(&dir, "other").get(&pat)?, None);
        // No temp file is left behind.
        let leftovers: Vec<_> = fs::read_dir(&dir)?
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());

        // §8.6 canary through the trait object, as `audit::open` runs it.
        canary_self_test(&ks)?;
        assert_eq!(ks.locality(), KeyringLocality::Local);

        // `unavailable`: every call, read on each call (no restart needed).
        set_mode(&dir, MODE_UNAVAILABLE)?;
        assert_eq!(ks.get(&pat), Err(KeyStoreError::Unavailable));
        assert_eq!(ks.set(&pat, b"x"), Err(KeyStoreError::Unavailable));
        assert_eq!(ks.delete(&pat), Err(KeyStoreError::Unavailable));
        assert_eq!(canary_self_test(&ks), Err(KeyStoreError::Unavailable));
        assert_eq!(ks.locality(), KeyringLocality::Local);

        set_mode(&dir, MODE_LOCKED)?;
        assert_eq!(ks.get(&pat), Err(KeyStoreError::Locked));
        assert_eq!(ks.set(&pat, b"x"), Err(KeyStoreError::Locked));
        assert_eq!(ks.delete(&pat), Err(KeyStoreError::Locked));

        // `not_local`: the entries work, the locality says where they are.
        set_mode(&dir, MODE_NOT_LOCAL)?;
        assert_eq!(
            ks.locality(),
            KeyringLocality::NotLocal { dir: dir.clone() }
        );
        assert_eq!(ks.get(&pat)?.ok_or("pat missing")?.as_slice(), b"PATCANARY");

        // Back to `ok`: the value survived the modes. An unknown mode fails closed.
        set_mode(&dir, MODE_OK)?;
        assert_eq!(ks.get(&pat)?.ok_or("pat missing")?.as_slice(), b"PATCANARY");
        set_mode(&dir, "sideways")?;
        assert!(matches!(ks.get(&pat), Err(KeyStoreError::Other(_))));
        assert!(matches!(ks.locality(), KeyringLocality::Unknown { .. }));
        // A missing mode file is `ok`.
        fs::remove_file(dir.join(MODE_FILE))?;
        assert!(ks.get(&pat)?.is_some());
        Ok(())
    }

    /// M10 T14 (T9 handoff): another install's entries in the same dir, its own names, the same
    /// mode file; anything but an install id addresses nothing.
    #[test]
    fn for_install_addresses_install_ids_only() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("keys");
        let ks = provision(&dir, ID)?;
        let other_id = "0123456789abcdef0123456789abcdef";
        let other = ks
            .for_install(other_id)
            .ok_or("no keystore for an install id")?;
        assert_eq!(other.install_id(), other_id);
        other.set(&EntryName::Kek, b"other kek")?;
        assert_eq!(ks.get(&EntryName::Kek)?, None, "not this install's entry");
        assert_eq!(
            FileKeyStore::open(&dir, other_id)
                .get(&EntryName::Kek)?
                .as_deref()
                .map(Vec::as_slice),
            Some(&b"other kek"[..])
        );
        set_mode(&dir, MODE_LOCKED)?;
        assert_eq!(other.get(&EntryName::Kek), Err(KeyStoreError::Locked));
        for bad in [
            "",
            "other",
            "../x",
            "0123456789ABCDEF0123456789ABCDEF",
            &"a".repeat(33),
        ] {
            assert!(ks.for_install(bad).is_none(), "{bad}");
        }
        Ok(())
    }

    #[test]
    fn provision_keeps_an_existing_mode() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("keys");
        fs::create_dir(&dir)?;
        set_mode(&dir, MODE_LOCKED)?;
        let ks = provision(&dir, ID)?;
        assert_eq!(ks.get(&EntryName::Kek), Err(KeyStoreError::Locked));
        Ok(())
    }

    #[test]
    fn a_damaged_value_is_corrupt() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let ks = provision(tmp.path(), ID)?;
        for bad in ["abc", "zz", "0g"] {
            fs::write(tmp.path().join(ks.file_name(&EntryName::Kek)), bad)?;
            assert_eq!(
                ks.get(&EntryName::Kek),
                Err(KeyStoreError::Corrupt),
                "{bad}"
            );
        }
        Ok(())
    }

    #[test]
    fn hex_roundtrip() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(hex_decode(&hex_encode(&all)), Some(all));
        assert_eq!(hex_decode("ABcd"), Some(vec![0xab, 0xcd]));
        assert_eq!(hex_decode(""), Some(Vec::new()));
    }

    #[cfg(unix)]
    #[test]
    fn provisioned_dir_and_values_are_private() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("keys");
        let ks = provision(&dir, ID)?;
        ks.set(&EntryName::Kek, b"k")?;
        assert_eq!(fs::metadata(&dir)?.permissions().mode() & 0o777, 0o700);
        let file = dir.join(ks.file_name(&EntryName::Kek));
        assert_eq!(fs::metadata(file)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }
}
