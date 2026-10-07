//! Size-rolling log writer for `<data>/logs` (§7.7: 10 MiB x 5, <= 7 days).
//!
//! Files: `diag.log` (current), `diag.1.log` .. `diag.<max_files-1>.log` (older).
//! Rotation happens before a line that would push `diag.log` past
//! `max_bytes`; a single line is never split. Files older than `max_age`
//! (by mtime) are deleted at `open`, after every rotation, and at most once
//! per `PRUNE_INTERVAL` while writing.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use super::{LOG_FILE_STEM, LOG_MAX_AGE, LOG_MAX_BYTES, LOG_MAX_FILES};

/// How often a long-running writer re-checks file ages between rotations.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollLimits {
    pub max_bytes: u64,
    pub max_files: usize,
    pub max_age: Duration,
}

impl Default for RollLimits {
    fn default() -> Self {
        RollLimits {
            max_bytes: LOG_MAX_BYTES,
            max_files: LOG_MAX_FILES,
            max_age: LOG_MAX_AGE,
        }
    }
}

#[derive(Debug)]
pub struct RollingWriter {
    dir: PathBuf,
    limits: RollLimits,
    file: Option<File>,
    size: u64,
    last_prune: Instant,
}

/// `diag.log` for index 0, `diag.<n>.log` otherwise.
pub(crate) fn file_name(index: usize) -> String {
    if index == 0 {
        format!("{LOG_FILE_STEM}.log")
    } else {
        format!("{LOG_FILE_STEM}.{index}.log")
    }
}

/// Parses `diag.log` -> Some(0), `diag.<n>.log` -> Some(n), anything else -> None.
fn parse_index(name: &str) -> Option<usize> {
    let rest = name.strip_prefix(LOG_FILE_STEM)?.strip_suffix(".log")?;
    if rest.is_empty() {
        return Some(0);
    }
    let digits = rest.strip_prefix('.')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

impl RollingWriter {
    /// Opens (appending) `<dir>/diag.log`. `dir` must already exist; this
    /// function never creates directories. Expired and surplus log files
    /// are deleted first.
    pub fn open(dir: &Path, limits: RollLimits) -> io::Result<RollingWriter> {
        if !dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "log directory does not exist",
            ));
        }
        let mut w = RollingWriter {
            dir: dir.to_path_buf(),
            limits: RollLimits {
                max_files: limits.max_files.max(1),
                ..limits
            },
            file: None,
            size: 0,
            last_prune: Instant::now(),
        };
        w.prune()?;
        w.reopen()?;
        Ok(w)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Writes one complete line (the caller includes the trailing `\n`).
    pub fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        if self.last_prune.elapsed() >= PRUNE_INTERVAL {
            self.prune()?;
            if self.file.is_none() {
                self.reopen()?;
            }
        }
        if self.size > 0 && self.size + line.len() as u64 > self.limits.max_bytes {
            self.rotate()?;
        }
        if self.file.is_none() {
            self.reopen()?;
        }
        match self.file.as_mut() {
            Some(f) => {
                f.write_all(line)?;
                self.size += line.len() as u64;
                Ok(())
            }
            None => Err(io::Error::other("log file not open")),
        }
    }

    fn reopen(&mut self) -> io::Result<()> {
        let path = self.dir.join(file_name(0));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        self.size = file.metadata()?.len();
        self.file = Some(file);
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        // Close the current file first: renaming an open file is unreliable on Windows.
        self.file = None;
        let last = self.limits.max_files - 1;
        if last == 0 {
            remove_if_exists(&self.dir.join(file_name(0)))?;
        } else {
            remove_if_exists(&self.dir.join(file_name(last)))?;
            for i in (0..last).rev() {
                let from = self.dir.join(file_name(i));
                let to = self.dir.join(file_name(i + 1));
                match fs::rename(&from, &to) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => {
                        // Keep logging into the existing file rather than losing lines.
                        self.reopen()?;
                        return Err(e);
                    }
                }
            }
        }
        self.prune()?;
        self.reopen()
    }

    /// Deletes `diag*.log` files older than `max_age` and any index >= `max_files`.
    fn prune(&mut self) -> io::Result<()> {
        self.last_prune = Instant::now();
        let now = SystemTime::now();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(index) = name.to_str().and_then(parse_index) else {
                continue;
            };
            let meta = entry.metadata()?;
            if !meta.is_file() {
                continue;
            }
            let expired = match meta.modified() {
                Ok(mtime) => now
                    .duration_since(mtime)
                    .map(|age| age > self.limits.max_age)
                    .unwrap_or(false),
                Err(_) => false,
            };
            if expired || index >= self.limits.max_files {
                if index == 0 {
                    self.file = None;
                }
                remove_if_exists(&entry.path())?;
            }
        }
        Ok(())
    }
}

impl Write for RollingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_line(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use filetime::{FileTime, set_file_mtime};

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    fn small() -> RollLimits {
        RollLimits {
            max_bytes: 1024,
            max_files: 5,
            max_age: 7 * DAY,
        }
    }

    /// 100-byte line: "line-0042 " + 89 x 'x' + '\n'.
    fn line(n: usize) -> Vec<u8> {
        let mut s = format!("line-{n:04} ");
        while s.len() < 99 {
            s.push('x');
        }
        s.push('\n');
        s.into_bytes()
    }

    fn log_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<(String, Vec<u8>)> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.file_type().unwrap().is_file())
            .map(|e| {
                (
                    e.file_name().into_string().unwrap(),
                    fs::read(e.path()).unwrap(),
                )
            })
            .collect();
        v.sort();
        v
    }

    fn contains(hay: &[u8], needle: &str) -> bool {
        hay.windows(needle.len()).any(|w| w == needle.as_bytes())
    }

    fn set_age(path: &Path, age: Duration) {
        let t = SystemTime::now() - age;
        set_file_mtime(path, FileTime::from_system_time(t)).unwrap();
    }

    #[test]
    fn constants_match_spec() {
        assert_eq!(LOG_MAX_BYTES, 10 * 1024 * 1024);
        assert_eq!(LOG_MAX_FILES, 5);
        assert_eq!(LOG_MAX_AGE, Duration::from_secs(7 * 24 * 60 * 60));
        assert_eq!(super::super::LOG_DIR_NAME, "logs");
        assert_eq!(LOG_FILE_STEM, "diag");
        assert_eq!(RollLimits::default().max_bytes, LOG_MAX_BYTES);
        assert_eq!(RollLimits::default().max_files, LOG_MAX_FILES);
        assert_eq!(RollLimits::default().max_age, LOG_MAX_AGE);
    }

    #[test]
    fn rolls_by_size_and_drops_oldest() {
        let tmp = tempfile::tempdir().unwrap();
        let mut w = RollingWriter::open(tmp.path(), small()).unwrap();
        for n in 0..60 {
            w.write_line(&line(n)).unwrap(); // 60 x 100 B = 6000 B
        }
        drop(w);
        let files = log_files(tmp.path());
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "diag.1.log",
                "diag.2.log",
                "diag.3.log",
                "diag.4.log",
                "diag.log"
            ]
        );
        for (name, bytes) in &files {
            assert!(
                bytes.len() <= 1024 + 100,
                "{name} has {} bytes",
                bytes.len()
            );
        }
        let get = |n: &str| &files.iter().find(|(f, _)| f == n).unwrap().1;
        assert!(contains(get("diag.log"), "line-0059"));
        assert!(contains(get("diag.4.log"), "line-0010"));
        for (_, bytes) in &files {
            assert!(!contains(bytes, "line-0000"), "oldest line must be dropped");
            assert!(!contains(bytes, "line-0009"), "oldest file must be dropped");
        }
    }

    #[test]
    fn open_never_creates_the_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("logs");
        assert!(RollingWriter::open(&missing, small()).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn expired_files_are_deleted_at_open_and_at_rotation() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        for name in ["diag.1.log", "diag.2.log", "diag.3.log"] {
            fs::write(dir.join(name), b"old\n").unwrap();
        }
        fs::write(dir.join("other.txt"), b"keep\n").unwrap();
        set_age(&dir.join("diag.1.log"), 8 * DAY);
        set_age(&dir.join("diag.2.log"), 8 * DAY);
        set_age(&dir.join("diag.3.log"), 6 * DAY);
        set_age(&dir.join("other.txt"), 30 * DAY);

        let mut w = RollingWriter::open(dir, small()).unwrap();
        assert!(
            !dir.join("diag.1.log").exists(),
            "8 days old: deleted at open"
        );
        assert!(
            !dir.join("diag.2.log").exists(),
            "8 days old: deleted at open"
        );
        assert!(dir.join("diag.3.log").exists(), "6 days old: kept");
        assert!(
            dir.join("other.txt").exists(),
            "non-log files are never touched"
        );

        // diag.3.log ages past the limit; the next rotation renames it to
        // diag.4.log (mtime unchanged) and the post-rotation sweep deletes it.
        set_age(&dir.join("diag.3.log"), 8 * DAY);
        for n in 0..11 {
            w.write_line(&line(n)).unwrap(); // the 11th line triggers a rotation
        }
        drop(w);
        assert!(dir.join("diag.1.log").exists());
        assert!(
            !dir.join("diag.4.log").exists(),
            "expired file deleted at rotation"
        );
        assert!(!dir.join("diag.3.log").exists());
        assert!(dir.join("diag.log").exists());
    }

    #[test]
    fn surplus_indices_are_deleted_at_open() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("diag.7.log"), b"x\n").unwrap();
        fs::write(tmp.path().join("diag.4.log"), b"x\n").unwrap();
        let _w = RollingWriter::open(tmp.path(), small()).unwrap();
        assert!(!tmp.path().join("diag.7.log").exists());
        assert!(tmp.path().join("diag.4.log").exists());
    }

    #[test]
    fn parse_index_accepts_only_log_names() {
        assert_eq!(parse_index("diag.log"), Some(0));
        assert_eq!(parse_index("diag.3.log"), Some(3));
        assert_eq!(parse_index("diag..log"), None);
        assert_eq!(parse_index("diag.x.log"), None);
        assert_eq!(parse_index("diag.log.bak"), None);
        assert_eq!(parse_index("other.log"), None);
    }
}
