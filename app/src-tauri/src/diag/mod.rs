//! Diagnostic log (§7.7): `tracing`, rolling files under `<data>/logs`,
//! 10 MiB x 5, <= 7 days, metadata only. Nothing touches the disk until a
//! checked `LocalDataDir` is attached; earlier lines wait in a bounded
//! in-memory buffer and are lost if no data dir is ever attached.

pub mod fields;
mod panic;
mod writer;

use std::cell::Cell;
use std::collections::VecDeque;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use atlas_duck_ipc::paths::LocalDataDir;
use tracing_subscriber::Layer as _;
use tracing_subscriber::Registry;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;

pub use fields::ALLOWED_FIELDS;
pub use panic::{PANIC_CATEGORY_APP, install_panic_hook};
pub use writer::{RollLimits, RollingWriter};

pub const LOG_DIR_NAME: &str = "logs";
pub const LOG_FILE_STEM: &str = "diag";
pub const LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;
pub const LOG_MAX_FILES: usize = 5;
pub const LOG_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Lines kept in memory before a data dir is attached (oldest dropped first).
pub const BUFFER_MAX_LINES: usize = 1000;

/// Most verbose level the process-wide subscriber records (plan decision).
const GLOBAL_LEVEL: LevelFilter = LevelFilter::INFO;

enum Sink {
    Buffer {
        lines: VecDeque<String>,
        dropped: u64,
    },
    File(RollingWriter),
}

pub struct Diag {
    sink: Mutex<Sink>,
}

static GLOBAL: OnceLock<Diag> = OnceLock::new();

thread_local! {
    /// Set while this thread holds the sink lock, so a panic raised inside
    /// the sink (whose hook writes to the sink) never self-deadlocks.
    static IN_SINK: Cell<bool> = const { Cell::new(false) };
}

struct SinkGuard;

impl Drop for SinkGuard {
    fn drop(&mut self) {
        let _ = IN_SINK.try_with(|c| c.set(false));
    }
}

impl Diag {
    fn new() -> Diag {
        Diag {
            sink: Mutex::new(Sink::Buffer {
                lines: VecDeque::new(),
                dropped: 0,
            }),
        }
    }

    /// Creates the process-wide `Diag` and installs it as the global
    /// `tracing` subscriber (first call only), recording INFO and above from
    /// `atlas_duck*` targets only (`fields::ALLOWED_TARGET_PREFIX`, enforced
    /// by the allowlist layer): third-party events never reach the log.
    /// Creates no file or directory.
    pub fn init() -> &'static Diag {
        let mut created = false;
        let diag = GLOBAL.get_or_init(|| {
            created = true;
            Diag::new()
        });
        if created {
            // Fails only if another global subscriber was set first; then
            // this process logs through that one and `Diag` stays unused.
            let _ = tracing::subscriber::set_global_default(diag.subscriber());
        }
        diag
    }

    /// The process-wide `Diag`, if `init` ran.
    pub(crate) fn get() -> Option<&'static Diag> {
        GLOBAL.get()
    }

    fn subscriber(&'static self) -> impl tracing::Subscriber + Send + Sync + 'static {
        Registry::default().with(
            fields::AllowlistLayer {
                writer: DiagMakeWriter(self),
            }
            .with_filter(GLOBAL_LEVEL),
        )
    }

    /// Creates `<data>/logs` (one level, never the data dir itself), opens
    /// `diag.log`, writes a counter line if buffered lines were dropped,
    /// then the buffered lines, and switches to file output. A second call
    /// switches to the new directory.
    pub fn attach_dir(&self, data: &LocalDataDir) -> io::Result<()> {
        let logs = data.path().join(LOG_DIR_NAME);
        match fs::create_dir(&logs) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let mut writer = RollingWriter::open(&logs, RollLimits::default())?;
        self.with_sink(move |sink| {
            if let Sink::Buffer { lines, dropped } = sink {
                if *dropped > 0 {
                    let line = fields::format_line(
                        "WARN",
                        module_path!(),
                        &format!("{}:{}", file!(), line!()),
                        &format!("event=diag_buffer_overflow dropped_lines={dropped}"),
                    );
                    let _ = writer.write_line(line.as_bytes());
                }
                for line in lines.drain(..) {
                    let _ = writer.write_line(line.as_bytes());
                }
            }
            *sink = Sink::File(writer);
        })
        .ok_or_else(|| io::Error::other("diagnostic log sink is busy on this thread"))
    }

    /// Adds field names later tasks may log (each task names its fields).
    pub fn extend_allowed_fields(&self, fields: &'static [&'static str]) {
        fields::extend_allowed(fields);
    }

    /// Appends one complete line. Dropped silently if this thread is
    /// already inside the sink (a panic raised while writing).
    pub(crate) fn push_line(&self, line: String) {
        let _ = self.with_sink(move |sink| match sink {
            Sink::Buffer { lines, dropped } => {
                if lines.len() >= BUFFER_MAX_LINES {
                    lines.pop_front();
                    *dropped += 1;
                }
                lines.push_back(line);
            }
            Sink::File(w) => {
                let _ = w.write_line(line.as_bytes());
            }
        });
    }

    fn with_sink<R>(&self, f: impl FnOnce(&mut Sink) -> R) -> Option<R> {
        let already = IN_SINK.try_with(|c| c.replace(true)).unwrap_or(false);
        if already {
            return None;
        }
        let _guard = SinkGuard;
        let mut sink = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        Some(f(&mut sink))
    }
}

#[derive(Clone, Copy)]
struct DiagMakeWriter(&'static Diag);

impl<'a> MakeWriter<'a> for DiagMakeWriter {
    type Writer = DiagLineWriter;

    fn make_writer(&'a self) -> DiagLineWriter {
        DiagLineWriter {
            diag: self.0,
            buf: Vec::new(),
        }
    }
}

/// Collects one formatted event and hands it to the sink as one line on drop.
struct DiagLineWriter {
    diag: &'static Diag,
    buf: Vec<u8>,
}

impl Write for DiagLineWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for DiagLineWriter {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            let bytes = std::mem::take(&mut self.buf);
            self.diag
                .push_line(String::from_utf8_lossy(&bytes).into_owned());
        }
    }
}

/// SC4 grep harness: every regular file under `dir` (recursively) whose
/// bytes contain any of `needles`, sorted.
pub fn scan_logs_for(dir: &Path, needles: &[&str]) -> io::Result<Vec<PathBuf>> {
    let mut hits = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            if ty.is_dir() {
                stack.push(entry.path());
            } else if ty.is_file() {
                let bytes = fs::read(entry.path())?;
                let found = needles
                    .iter()
                    .any(|n| !n.is_empty() && bytes.windows(n.len()).any(|w| w == n.as_bytes()));
                if found {
                    hits.push(entry.path());
                }
            }
        }
    }
    hits.sort();
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_duck_ipc::paths::{DataDirResolution, check_data_dir};

    fn local(path: &Path) -> LocalDataDir {
        match check_data_dir(path).unwrap() {
            DataDirResolution::Local(d) => d,
            _ => panic!("temp dir is not a local data dir"),
        }
    }

    /// A private `Diag` with a scoped (non-global) subscriber.
    fn scoped_diag() -> &'static Diag {
        Box::leak(Box::new(Diag::new()))
    }

    #[test]
    fn buffered_lines_are_flushed_on_attach() {
        let diag = scoped_diag();
        tracing::subscriber::with_default(diag.subscriber(), || {
            tracing::info!(op_id = "jira.search", "SENTINEL-BUF");
            tracing::debug!(op_id = "below.global.level");
        });
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            fs::read_dir(tmp.path()).unwrap().count(),
            0,
            "nothing before attach"
        );
        diag.attach_dir(&local(tmp.path())).unwrap();
        tracing::subscriber::with_default(diag.subscriber(), || {
            tracing::info!(op_id = "after.attach");
        });
        let log = fs::read_to_string(tmp.path().join("logs").join("diag.log")).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 2, "{log}");
        assert!(lines[0].contains("op_id=jira.search"), "{log}");
        assert!(lines[1].contains("op_id=after.attach"), "{log}");
        assert!(!log.contains("SENTINEL-BUF"));
        assert!(
            !log.contains("below.global.level"),
            "DEBUG is below the global level"
        );
    }

    #[test]
    fn buffer_overflow_drops_oldest_and_writes_counter() {
        let diag = scoped_diag();
        tracing::subscriber::with_default(diag.subscriber(), || {
            for i in 0..(BUFFER_MAX_LINES as u64 + 5) {
                tracing::info!(request_id = i);
            }
        });
        let tmp = tempfile::tempdir().unwrap();
        diag.attach_dir(&local(tmp.path())).unwrap();
        let log = fs::read_to_string(tmp.path().join("logs").join("diag.log")).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(
            lines.len(),
            BUFFER_MAX_LINES + 1,
            "counter line + 1000 lines"
        );
        assert!(
            lines[0].contains("event=diag_buffer_overflow dropped_lines=5"),
            "{}",
            lines[0]
        );
        assert!(lines[1].contains("request_id=5 "), "{}", lines[1]);
        assert!(lines[BUFFER_MAX_LINES].contains("request_id=1004 "));
        assert!(!log.contains("request_id=4 "));
    }

    /// A dependency's event with allowlisted field names must leave nothing in
    /// the log, neither through the buffer nor after attach.
    #[test]
    fn foreign_target_events_never_reach_the_log() {
        let diag = scoped_diag();
        tracing::subscriber::with_default(diag.subscriber(), || {
            tracing::info!(target: "zbus", reason = "SENTINEL-ZBUS", peer_exe = "SENTINEL-EXE");
            tracing::error!(target: "tauri::app", event = "SENTINEL-TAURI", "SENTINEL-MSG");
            tracing::info!(op_id = "kept.before.attach");
        });
        let tmp = tempfile::tempdir().unwrap();
        diag.attach_dir(&local(tmp.path())).unwrap();
        tracing::subscriber::with_default(diag.subscriber(), || {
            tracing::warn!(target: "zbus", reason = "SENTINEL-ZBUS-2");
            tracing::info!(op_id = "kept.after.attach");
        });
        let logs = tmp.path().join("logs");
        let log = fs::read_to_string(logs.join("diag.log")).unwrap();
        assert_eq!(log.lines().count(), 2, "{log}");
        assert!(log.contains("op_id=kept.before.attach"), "{log}");
        assert!(log.contains("op_id=kept.after.attach"), "{log}");
        assert!(
            scan_logs_for(&logs, &["SENTINEL"]).unwrap().is_empty(),
            "{log}"
        );
    }

    #[test]
    fn attach_creates_only_the_logs_dir() {
        let diag = scoped_diag();
        let tmp = tempfile::tempdir().unwrap();
        diag.attach_dir(&local(tmp.path())).unwrap();
        let names: Vec<String> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["logs"]);
        let logs: Vec<String> = fs::read_dir(tmp.path().join("logs"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(logs, ["diag.log"]);
    }

    /// A13: a second `attach_dir` switches to the new directory (T10 treats
    /// attach as one-shot; this task's behaviour is switch).
    #[test]
    fn second_attach_switches_directory() {
        let diag = scoped_diag();
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        tracing::subscriber::with_default(diag.subscriber(), || {
            tracing::info!(op_id = "buffered");
        });
        diag.attach_dir(&local(a.path())).unwrap();
        diag.attach_dir(&local(b.path())).unwrap();
        tracing::subscriber::with_default(diag.subscriber(), || {
            tracing::info!(op_id = "after.switch");
        });
        let log_a = fs::read_to_string(a.path().join("logs").join("diag.log")).unwrap();
        let log_b = fs::read_to_string(b.path().join("logs").join("diag.log")).unwrap();
        assert!(log_a.contains("op_id=buffered") && !log_a.contains("after.switch"));
        assert!(log_b.contains("op_id=after.switch") && !log_b.contains("buffered"));
    }

    #[test]
    fn scan_logs_for_finds_needles_recursively() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("sub")).unwrap();
        fs::write(tmp.path().join("a.log"), b"clean\n").unwrap();
        fs::write(tmp.path().join("sub").join("b.log"), b"xx NEEDLE-1 yy\n").unwrap();
        let hits = scan_logs_for(tmp.path(), &["NEEDLE-1", "NEEDLE-2"]).unwrap();
        assert_eq!(hits, [tmp.path().join("sub").join("b.log")]);
        assert!(scan_logs_for(tmp.path(), &["absent"]).unwrap().is_empty());
    }
}
