//! The anchor-directory writer (§8.5; PD-156, PD-157). The writer thread classifies every
//! committed row ([`Classifier`]) and hands the lines it asks for to the `audit-anchor-dir`
//! thread ([`run`]), which appends them to `<anchor_dir>/<chain_id>.jsonl` once startup
//! verification called `enable` (§8.7 "No anchor writes before verification"). A chain file is
//! only ever created with create-new, header first, then fsynced together with its directory;
//! after that it is only appended to and fsynced: the writer never rewrites, truncates or
//! deletes a byte. A failing file is retried with its own backoff, never holding back another
//! file's lines (the order is kept per file), and shown in `StoreHealth`, never an incident
//! (§8.5 "a write failure is shown in Settings and the tray").
//!
//! Which records get which line (PD-157, L185):
//! - a daily `Record` line for the first committed record whose non-NULL `epoch` is a date with
//!   no `Record` line yet in the file, and only while that date is not past the date
//!   corroborated in this process (§8.8; L36: never for a NULL epoch);
//! - a `Record` line for the first unflagged record after any `clock_behind` record (M2
//!   handoff: the verifier judges pruned `clock_behind` lines by it);
//! - a `Record` line for every `APP_STOP` (`Store::shutdown` drains the queue, bounded; a line
//!   still pending then is written at the next start, see `Writer::open`);
//! - an `Immediate` line for `PRUNE`, `RESTORE`, `LEGAL_HOLD_CHANGED`, `INTEGRITY_ACK`,
//!   `CLOCK_ANOMALY` and the `CONFIG_CHANGED` records of an audit-policy key, and a `Prune` line
//!   for a `PRUNE`.
//!
//! `Record` lines carry `clock_behind: true` exactly when the record has the flag.
//!
//! Besides the commit lines (Task 5): `RESTORE`'s `Record` and `Immediate` lines and the
//! `ANCHOR_DETACHED` line of an anchor-dir change come through the same queue (the store pushes
//! them), and every integrity-incident `VERIFY` gets its incident file
//! `<chain_id>.incident-<verify_seq>.json` beside the chain file (PD-164), created once with
//! create-new. A chain file whose last line was torn by a crash is closed with a newline and a
//! `Record` line for the head before anything else is appended to it (PD-165).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use atlas_duck_ipc::jcs::to_jcs_vec;
use chrono::NaiveDate;
use serde_json::json;

use super::{AnchorLine, IMMEDIATE_TYPES, MAX_FILE_BYTES, MAX_LINE_BYTES, file_name, is_id};
use super::{parse_line, resolve, to_line};
use crate::anchors::backoff;
use crate::clock::{Clock, epoch_text, parse_epoch};
use crate::settings;
use crate::types::{EventFlags, EventType};
use crate::verify::VerifyFinding;

/// Queued lines beyond which only the newest daily line is kept with every other line (PD-156).
pub(crate) const MAX_PENDING: usize = 100_000;

/// How long `Store::shutdown` waits for the queue to drain (PD-157, inside the PD-38 budget).
pub(crate) const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

/// Longest idle wait of the thread.
const MAX_WAIT: Duration = Duration::from_secs(1);

/// An attempt still running after this long (a hung share or a blocking special file) is shown
/// as failing; the thread itself cannot be interrupted (`Store::shutdown` leaves it behind).
const STUCK_AFTER: Duration = Duration::from_secs(30);

/// `host` and `os_user` of a header are cut to this many characters (the line must stay below
/// `MAX_LINE_BYTES` even when every character is escaped).
const MAX_HEADER_TEXT_CHARS: usize = 200;

/// How long `change_anchor_dir` waits for the file lock (the thread may hold it while stuck on
/// a hung share: the switch away from that share must not hang with it).
const FILE_LOCK_WAIT: Duration = Duration::from_secs(5);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether a committed record of `event_type` gets an immediate line (§8.5): the six types, a
/// `CONFIG_CHANGED` only with an audit-policy `key` (L185; the one key list of `settings.rs`).
pub fn gets_immediate_line(event_type: &str, config_key: Option<&str>) -> bool {
    IMMEDIATE_TYPES.contains(&event_type)
        && (event_type != EventType::CONFIG_CHANGED.as_str()
            || config_key.is_some_and(settings::is_audit_policy_key))
}

// ---------------------------------------------------------------------------------------
// What the writer thread hands over

/// One committed row, as the writer thread stamped it.
pub(crate) struct RowNote {
    pub(crate) seq: u64,
    pub(crate) record_hash: [u8; 32],
    pub(crate) epoch: Option<NaiveDate>,
    pub(crate) flags: EventFlags,
    pub(crate) event_type: EventType,
    /// [`gets_immediate_line`] of the row (decided while its payload was still plaintext).
    pub(crate) immediate: bool,
    /// The date corroborated in this process when the row was stamped.
    pub(crate) corroborated: Option<NaiveDate>,
    /// An integrity-incident `VERIFY`: what its incident file says (PD-164).
    pub(crate) incident: Option<IncidentDraft>,
}

impl RowNote {
    /// The `Record` line naming this row.
    pub(crate) fn record_line(&self) -> AnchorLine {
        AnchorLine::Record {
            seq: self.seq,
            record_hash: self.record_hash,
            epoch: self.epoch.map(epoch_text),
            clock_behind: self.flags.contains(EventFlags::BEHIND),
        }
    }
}

/// The incident file of an integrity-incident `VERIFY` (§8.7 "an incident JSON is written
/// there", PD-164): its `result` and the first incident finding's expected/observed values, as
/// the `VERIFY` payload names them. The record's `seq`, `record_hash` and `chain_id` are added
/// once it committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IncidentDraft {
    result: &'static str,
    expected_seq: Option<u64>,
    expected_hash: Option<[u8; 32]>,
    observed_seq: Option<u64>,
    observed_hash: Option<[u8; 32]>,
    detected_at: String,
}

impl IncidentDraft {
    /// `None` when no finding is an incident (no incident file then).
    pub(crate) fn of(findings: &[VerifyFinding], detected_at: &str) -> Option<IncidentDraft> {
        let f = findings.iter().find(|f| f.kind.is_incident())?;
        Some(IncidentDraft {
            result: f.kind.as_str(),
            expected_seq: f.expected_seq,
            expected_hash: f.expected_hash,
            observed_seq: f.observed_seq,
            observed_hash: f.observed_hash,
            detected_at: detected_at.to_owned(),
        })
    }

    /// The file's JCS text: `{chain_id, verify_seq, record_hash, result, expected_seq,
    /// expected_hash, observed_seq, observed_hash, detected_at}`.
    fn text(&self, chain_id: &str, verify_seq: u64, record_hash: &[u8; 32]) -> String {
        let v = json!({
            "chain_id": chain_id,
            "verify_seq": verify_seq,
            "record_hash": hex::encode(record_hash),
            "result": self.result,
            "expected_seq": self.expected_seq,
            "expected_hash": self.expected_hash.map(hex::encode),
            "observed_seq": self.observed_seq,
            "observed_hash": self.observed_hash.map(hex::encode),
            "detected_at": self.detected_at,
        });
        // As `to_line`: JCS fails only for an integer beyond 2^53 − 1, which no seq reaches.
        to_jcs_vec(&v)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| v.to_string())
    }
}

/// `"<chain_id>.incident-<verify_seq>.json"`: not a `*.jsonl` name, so no reader of chain files
/// ever parses it.
pub(crate) fn incident_file_name(chain_id: &str, verify_seq: u64) -> String {
    format!("{chain_id}.incident-{verify_seq}.json")
}

/// The `prune_log` values of a committed `PRUNE` (its `Prune` line).
pub(crate) struct PruneNote {
    pub(crate) seq: u64,
    pub(crate) first_retained_seq: u64,
    pub(crate) first_retained_prev_hash: [u8; 32],
    pub(crate) cutoff_epoch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Item {
    Line(AnchorLine),
    /// The chain file must exist (with its header), even if no line is due (M2 handoff: a
    /// missing current-chain file is created at the next start).
    EnsureFile,
    /// The incident file of `VERIFY` `verify_seq` beside the chain file, with its text.
    Incident {
        verify_seq: u64,
        text: String,
    },
}

/// How a queued line is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Keep {
    /// A daily line: skipped when the file already has a `Record` line of its date; beyond
    /// [`MAX_PENDING`] only the newest one is kept.
    Daily,
    /// Every other line of a commit.
    Always,
    /// A line a crash may have lost (startup): skipped when the file already holds it.
    CatchUp,
}

/// One line for `<dir>/<chain_id>.jsonl`. `dir` is the store's `anchor_dir` setting in force
/// when the record committed (the thread resolves it like verification does).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pending {
    pub(crate) dir: Option<String>,
    pub(crate) chain_id: String,
    pub(crate) item: Item,
    pub(crate) keep: Keep,
}

impl Pending {
    pub(crate) fn catch_up(dir: Option<String>, chain_id: &str, line: AnchorLine) -> Pending {
        Pending {
            dir,
            chain_id: chain_id.to_owned(),
            item: Item::Line(line),
            keep: Keep::CatchUp,
        }
    }

    pub(crate) fn ensure_file(dir: Option<String>, chain_id: &str) -> Pending {
        Pending {
            dir,
            chain_id: chain_id.to_owned(),
            item: Item::EnsureFile,
            keep: Keep::Always,
        }
    }

    /// A line every commit path must write (`ANCHOR_DETACHED`, the new dir's line).
    pub(crate) fn always(dir: Option<String>, chain_id: &str, line: AnchorLine) -> Pending {
        Pending {
            dir,
            chain_id: chain_id.to_owned(),
            item: Item::Line(line),
            keep: Keep::Always,
        }
    }

    /// The incident files of `rows`' integrity-incident `VERIFY`s.
    pub(crate) fn incidents(
        dir: &Option<String>,
        chain_id: &str,
        rows: &[RowNote],
    ) -> Vec<Pending> {
        rows.iter()
            .filter_map(|r| {
                let d = r.incident.as_ref()?;
                Some(Pending {
                    dir: dir.clone(),
                    chain_id: chain_id.to_owned(),
                    item: Item::Incident {
                        verify_seq: r.seq,
                        text: d.text(chain_id, r.seq, &r.record_hash),
                    },
                    keep: Keep::Always,
                })
            })
            .collect()
    }
}

/// The writer thread's per-process line state (PD-157).
pub(crate) struct Classifier {
    /// The latest daily date asked for, and the file it was asked for.
    daily: Option<(Option<String>, String, NaiveDate)>,
    /// A `clock_behind` record committed and no unflagged record got a `Record` line since.
    behind: bool,
}

impl Classifier {
    /// `head_behind`: the head record at open carries `clock_behind`, so the first unflagged
    /// record of this process is the witness of that run.
    pub(crate) fn new(head_behind: bool) -> Classifier {
        Classifier {
            daily: None,
            behind: head_behind,
        }
    }

    /// The lines of one commit's rows, in seq order.
    pub(crate) fn lines(
        &mut self,
        dir: &Option<String>,
        chain_id: &str,
        rows: Vec<RowNote>,
        prune: Option<PruneNote>,
    ) -> Vec<Pending> {
        let mut out = Vec::new();
        let mut push = |line: AnchorLine, keep: Keep| {
            out.push(Pending {
                dir: dir.clone(),
                chain_id: chain_id.to_owned(),
                item: Item::Line(line),
                keep,
            });
        };
        for r in rows {
            let flagged = r.flags.contains(EventFlags::BEHIND);
            let daily = match (r.epoch, r.corroborated) {
                (Some(e), Some(cd)) if e <= cd => {
                    let done = matches!(&self.daily,
                        Some((d, c, last)) if d == dir && c == chain_id && *last >= e);
                    (!done).then_some(e)
                }
                _ => None,
            };
            let witness = !flagged && self.behind;
            let app_stop = r.event_type == EventType::APP_STOP;
            if daily.is_some() || witness || app_stop {
                if let Some(e) = daily {
                    self.daily = Some((dir.clone(), chain_id.to_owned(), e));
                }
                let keep = if witness || app_stop {
                    Keep::Always
                } else {
                    Keep::Daily
                };
                push(
                    AnchorLine::Record {
                        seq: r.seq,
                        record_hash: r.record_hash,
                        epoch: r.epoch.map(epoch_text),
                        clock_behind: flagged,
                    },
                    keep,
                );
                if !flagged {
                    self.behind = false;
                }
            }
            if flagged {
                self.behind = true;
            }
            if r.immediate {
                if let Some(p) = prune.as_ref().filter(|p| p.seq == r.seq) {
                    push(
                        AnchorLine::Prune {
                            first_retained_seq: p.first_retained_seq,
                            first_retained_prev_hash: p.first_retained_prev_hash,
                            cutoff_epoch: p.cutoff_epoch.clone(),
                        },
                        Keep::Always,
                    );
                }
                push(
                    AnchorLine::Immediate {
                        seq: r.seq,
                        record_hash: r.record_hash,
                        epoch: r.epoch.map(epoch_text),
                        event_type: r.event_type.as_str().to_owned(),
                    },
                    Keep::Always,
                );
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------------------
// The shared queue

/// One chain file: the resolved anchor dir and the chain id.
type FileKey = (PathBuf, String);

/// A file whose last attempt failed: the failures in a row, and when it is tried again.
#[derive(Clone, Copy)]
struct Retry {
    failures: u32,
    next: Instant,
}

struct DirState {
    /// Startup verification passed (the same gate as the keychain anchor thread).
    enabled: bool,
    /// `OpenConfig.anchor_dir`, used while the store's setting names none (as verification).
    fallback: Option<PathBuf>,
    /// The committed head's chain and `Record` line: what follows a torn last line (PD-165).
    head: Option<(String, AnchorLine)>,
    queue: VecDeque<Pending>,
    /// `Keep::Daily` lines in `queue`.
    daily_queued: usize,
    /// Lines were queued since the thread last took the queue: they are tried now, whatever
    /// another file's backoff says.
    fresh: bool,
    /// Lines the thread took and is writing now.
    in_flight: usize,
    /// When the running attempt began.
    attempt_started: Option<Instant>,
    /// The files whose lines are queued because their last attempt failed (each retried with
    /// its own backoff, so one failing file never holds back another's lines).
    failing: HashMap<FileKey, Retry>,
    /// Divides the retry backoff (tests only).
    scale_div: u32,
    /// One attempt now, whatever the backoff says (`Store::shutdown`, tests).
    drain: bool,
    /// Forced attempts finished.
    forced: u64,
    stop: bool,
    /// The thread panicked: nothing will be written again.
    dead: bool,
    exited: bool,
}

/// The state shared by the writer thread (producer), the `Store` handles and the
/// `audit-anchor-dir` thread. Files are only touched with the state lock released.
pub(crate) struct AnchorDirShared {
    state: Mutex<DirState>,
    cv: Condvar,
    /// Held while a chain file is created or appended to: whoever creates a file writes its one
    /// header (create-new), and nobody else writes to it meanwhile.
    pub(crate) file_lock: Mutex<()>,
}

/// What `Store::health` reports about the anchor dir.
pub(crate) struct DirHealth {
    pub(crate) write_failing: bool,
    pub(crate) lines_pending: u32,
}

impl AnchorDirShared {
    pub(crate) fn new() -> AnchorDirShared {
        AnchorDirShared {
            state: Mutex::new(DirState {
                enabled: false,
                fallback: None,
                head: None,
                queue: VecDeque::new(),
                daily_queued: 0,
                fresh: false,
                in_flight: 0,
                attempt_started: None,
                failing: HashMap::new(),
                scale_div: 1,
                drain: false,
                forced: 0,
                stop: false,
                dead: false,
                exited: false,
            }),
            cv: Condvar::new(),
            file_lock: Mutex::new(()),
        }
    }

    /// Before the writer starts (first run commits `GENESIS` inside its start).
    pub(crate) fn set_fallback(&self, dir: Option<PathBuf>) {
        lock(&self.state).fallback = dir;
    }

    /// `OpenConfig.anchor_dir`.
    pub(crate) fn fallback(&self) -> Option<PathBuf> {
        lock(&self.state).fallback.clone()
    }

    /// The committed head (writer thread, after each commit and at open), as its `Record` line.
    pub(crate) fn set_head(&self, chain_id: &str, line: AnchorLine) {
        lock(&self.state).head = Some((chain_id.to_owned(), line));
    }

    /// The new dir's chain file opened first (PD-166, also the writability check): created with
    /// create-new and its header, or found (an existing file gets no second header; an empty
    /// one gets its header). Never deletes, truncates or rewrites anything. Takes the file lock
    /// like the thread (the one header), waiting for it at most [`FILE_LOCK_WAIT`].
    pub(crate) fn ensure_chain_file(
        &self,
        header: &HeaderFacts,
        dir: &Path,
        chain_id: &str,
    ) -> io::Result<()> {
        if !dir.is_absolute() || !is_id(chain_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not an absolute anchor directory or not a chain id",
            ));
        }
        if !std::fs::metadata(dir)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the anchor directory is not a directory",
            ));
        }
        let _g = self.file_lock_within(FILE_LOCK_WAIT)?;
        open_chain_file(dir, &dir.join(file_name(chain_id)), || {
            header.line(chain_id)
        })
        .map(drop)
    }

    fn file_lock_within(&self, wait: Duration) -> io::Result<MutexGuard<'_, ()>> {
        let end = Instant::now() + wait;
        loop {
            match self.file_lock.try_lock() {
                Ok(g) => return Ok(g),
                Err(TryLockError::Poisoned(e)) => return Ok(e.into_inner()),
                Err(TryLockError::WouldBlock) if Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the anchor-dir writer is busy",
                    ));
                }
            }
        }
    }

    /// Once the writer is ready; lines queued before are kept.
    pub(crate) fn init(&self, enabled: bool, scale_div: u32) {
        let mut st = lock(&self.state);
        st.enabled = enabled;
        st.scale_div = scale_div.max(1);
        drop(st);
        self.cv.notify_all();
    }

    /// Queues lines (writer thread; never blocks on a file). Lines for a store without any
    /// anchor dir are dropped here.
    pub(crate) fn push(&self, lines: Vec<Pending>) {
        if lines.is_empty() {
            return;
        }
        let mut st = lock(&self.state);
        let no_fallback = st.fallback.is_none();
        for p in lines {
            if p.dir.is_none() && no_fallback {
                continue;
            }
            if p.keep == Keep::Daily {
                st.daily_queued += 1;
            }
            st.queue.push_back(p);
            st.fresh = true;
        }
        compact(&mut st);
        drop(st);
        self.cv.notify_all();
    }

    /// Startup verification passed: lines may be written.
    pub(crate) fn enable(&self) {
        lock(&self.state).enabled = true;
        self.cv.notify_all();
    }

    /// Nothing is written until the next `enable` (tests).
    pub(crate) fn disable(&self) {
        lock(&self.state).enabled = false;
    }

    pub(crate) fn health(&self) -> DirHealth {
        let st = lock(&self.state);
        let stuck = st
            .attempt_started
            .is_some_and(|t| t.elapsed() >= STUCK_AFTER);
        DirHealth {
            write_failing: !st.failing.is_empty() || st.dead || stuck,
            lines_pending: u32::try_from(st.queue.len() + st.in_flight).unwrap_or(u32::MAX),
        }
    }

    /// Asks for one attempt now and waits (at most `timeout`) until the queue is empty or that
    /// attempt ended. `true`: nothing is pending. Nothing is written while disabled.
    pub(crate) fn drain(&self, timeout: Duration) -> bool {
        let end = Instant::now() + timeout;
        let mut st = lock(&self.state);
        let empty = |st: &DirState| st.queue.is_empty() && st.in_flight == 0;
        if !st.enabled || st.dead || st.exited {
            return empty(&st);
        }
        let before = st.forced;
        st.drain = true;
        self.cv.notify_all();
        loop {
            if empty(&st) {
                return true;
            }
            if st.forced > before || st.exited {
                return false;
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            st = self
                .cv
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// `Store::shutdown`: one last attempt for the queued lines, then the thread stops; both
    /// within `budget`. `false`: the thread did not leave in time (a hung share) and is left
    /// behind. Lines still queued are lost here; the `APP_STOP` one is written at the next start.
    /// A second call (`Drop` after `Store::shutdown`) returns at once: the first one waited.
    pub(crate) fn drain_and_stop(&self, budget: Duration) -> bool {
        {
            let st = lock(&self.state);
            if st.stop {
                return st.exited;
            }
        }
        let end = Instant::now() + budget;
        self.drain(budget);
        let mut st = lock(&self.state);
        st.stop = true;
        self.cv.notify_all();
        while !st.exited {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            st = self
                .cv
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        true
    }
}

/// Beyond [`MAX_PENDING`] queued lines only the newest daily line stays (PD-156); every other
/// line is kept. Runs only while more than one daily line is queued, so a queue of lines that
/// must all be kept does not pay a scan per push.
fn compact(st: &mut DirState) {
    if st.queue.len() <= MAX_PENDING || st.daily_queued <= 1 {
        return;
    }
    let total = st.daily_queued;
    let mut seen = 0usize;
    st.queue.retain(|p| {
        if p.keep != Keep::Daily {
            return true;
        }
        seen += 1;
        seen == total
    });
    st.daily_queued = 1;
}

// ---------------------------------------------------------------------------------------
// The thread

/// The header facts of this install (§8.5 header line).
#[derive(Clone)]
pub(crate) struct HeaderFacts {
    install_id: String,
    host: String,
    os_user: String,
    clock: Arc<dyn Clock>,
}

fn bounded(s: String) -> String {
    let s: String = s.chars().take(MAX_HEADER_TEXT_CHARS).collect();
    if s.is_empty() {
        "unknown".to_owned()
    } else {
        s
    }
}

/// The OS user as the recovery note names it (the first non-empty of `USERNAME`, `USER`,
/// `LOGNAME`): the same rule as the app's `credential::os_user`. Task 6's previous-chain
/// detection (RF-3) matches a header's `host` and `os_user` exactly, so the two must never
/// drift (one shared helper, never a third copy), and it compares against the value as written
/// here, after [`bounded`] (cut to 200 characters, empty -> `unknown`).
fn os_user() -> String {
    ["USERNAME", "USER", "LOGNAME"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .unwrap_or_default()
}

impl HeaderFacts {
    pub(crate) fn new(install_id: String, clock: Arc<dyn Clock>) -> HeaderFacts {
        HeaderFacts {
            install_id,
            host: bounded(atlas_duck_ipc::paths::raw_host_name().unwrap_or_default()),
            os_user: bounded(os_user()),
            clock,
        }
    }

    fn line(&self, chain_id: &str) -> io::Result<String> {
        let created_at = self
            .clock
            .now_utc()
            .try_to_rfc3339_ms()
            .ok_or_else(|| io::Error::other("wall clock outside years 0000..=9999"))?;
        Ok(to_line(&AnchorLine::Header {
            chain_id: chain_id.to_owned(),
            install_id: self.install_id.clone(),
            host: self.host.clone(),
            os_user: self.os_user.clone(),
            created_at,
        }))
    }
}

/// The `audit-anchor-dir` thread. A panic (defence in depth: release builds abort) marks the
/// state dead, which `health()` reports.
pub(crate) fn run(shared: Arc<AnchorDirShared>, header: HeaderFacts) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_loop(&shared, &header);
    }));
    let mut st = lock(&shared.state);
    if r.is_err() {
        st.dead = true;
    }
    st.exited = true;
    drop(st);
    shared.cv.notify_all();
}

/// Per file: the newest date with a `Record` line in it, once read.
type Files = HashMap<FileKey, Option<NaiveDate>>;

/// What one attempt needs besides the lines.
struct Attempt<'a> {
    fallback: Option<&'a Path>,
    /// Also try the files whose backoff has not run out (`drain`).
    forced: bool,
    scale_div: u32,
    /// The committed head's chain and `Record` line when the attempt began.
    head: Option<(String, AnchorLine)>,
}

fn run_loop(shared: &AnchorDirShared, header: &HeaderFacts) {
    let mut files: Files = HashMap::new();
    let mut st = lock(&shared.state);
    loop {
        if st.stop {
            break;
        }
        let now = Instant::now();
        let work = st.enabled && !st.queue.is_empty();
        // Newly queued lines are tried at once; a failing file's lines wait for its backoff.
        let next_retry = st.failing.values().map(|r| r.next).min();
        let due = work && (st.drain || st.fresh || next_retry.is_none_or(|t| now >= t));
        if !due {
            if st.drain {
                // Nothing to write now (empty, or disabled): the forced attempt is over.
                st.drain = false;
                st.forced += 1;
                shared.cv.notify_all();
                continue;
            }
            let wait = match (work, next_retry) {
                (true, Some(t)) => t.saturating_duration_since(now).min(MAX_WAIT),
                _ => MAX_WAIT,
            };
            st = shared
                .cv
                .wait_timeout(st, wait)
                .unwrap_or_else(|e| e.into_inner())
                .0;
            continue;
        }
        let forced = std::mem::take(&mut st.drain);
        st.fresh = false;
        let batch: Vec<Pending> = st.queue.drain(..).collect();
        st.daily_queued = 0;
        st.in_flight = batch.len();
        st.attempt_started = Some(now);
        let fallback = st.fallback.clone();
        let attempt = Attempt {
            fallback: fallback.as_deref(),
            forced,
            scale_div: st.scale_div,
            head: st.head.clone(),
        };
        // Health keeps showing the failing files while this attempt runs.
        let mut failing = st.failing.clone();
        drop(st);
        let kept = write_batch(shared, header, &attempt, &batch, &mut failing, &mut files);
        st = lock(&shared.state);
        // What was not written goes back in front of what arrived meanwhile, in order.
        for p in kept.into_iter().rev() {
            st.queue.push_front(p);
        }
        st.daily_queued = st.queue.iter().filter(|p| p.keep == Keep::Daily).count();
        st.in_flight = 0;
        st.attempt_started = None;
        st.failing = failing;
        if forced {
            st.forced += 1;
        }
        shared.cv.notify_all();
    }
}

/// Writes `batch`, one append per run of lines for the same file. The order is kept per file
/// only: once a file fails, its later lines in the batch are not tried, but every other file's
/// lines are. A file in backoff is not tried unless the attempt is forced. Updates `failing`
/// (a file that succeeded, or has no line left, is no longer failing) and returns the lines
/// not written, in their order.
fn write_batch(
    shared: &AnchorDirShared,
    header: &HeaderFacts,
    attempt: &Attempt<'_>,
    batch: &[Pending],
    failing: &mut HashMap<FileKey, Retry>,
    files: &mut Files,
) -> Vec<Pending> {
    let now = Instant::now();
    let mut failed_now: HashSet<FileKey> = HashSet::new();
    let mut kept_files: HashSet<FileKey> = HashSet::new();
    let mut kept = Vec::new();
    let mut i = 0;
    while i < batch.len() {
        let (dir, chain_id) = (&batch[i].dir, &batch[i].chain_id);
        let mut j = i + 1;
        while j < batch.len() && batch[j].dir == *dir && batch[j].chain_id == *chain_id {
            j += 1;
        }
        let group = &batch[i..j];
        i = j;
        // No anchor dir: nothing to write. A chain id that is not an id never becomes a path
        // component (the verifier reports such a store).
        let Some(path) = resolve(dir.as_deref(), attempt.fallback).filter(|_| is_id(chain_id))
        else {
            continue;
        };
        let key: FileKey = (path, chain_id.clone());
        let waiting = failed_now.contains(&key)
            || (!attempt.forced && failing.get(&key).is_some_and(|r| now < r.next));
        let head = attempt
            .head
            .as_ref()
            .filter(|(c, _)| c == chain_id)
            .map(|(_, l)| l);
        let result = if waiting {
            None
        } else {
            Some(append_group(
                shared, header, &key.0, chain_id, group, head, files,
            ))
        };
        match result {
            Some(Ok(())) => {
                failing.remove(&key);
            }
            Some(Err(_)) => {
                let failures = failing
                    .get(&key)
                    .map_or(0, |r| r.failures)
                    .saturating_add(1);
                let next = Instant::now() + backoff(failures) / attempt.scale_div;
                failing.insert(key.clone(), Retry { failures, next });
                failed_now.insert(key.clone());
                kept.extend_from_slice(group);
                kept_files.insert(key);
            }
            None => {
                kept.extend_from_slice(group);
                kept_files.insert(key);
            }
        }
    }
    failing.retain(|k, _| kept_files.contains(k));
    kept
}

/// One group: the chain file opened (or created with its header), the group's incident files
/// created, a torn last line closed (PD-165: a newline, then `head`'s `Record` line), then the
/// lines appended in one write and fsynced. A failed write forgets what was known of the file,
/// so the next attempt reads it again (and finds a line the failure tore).
fn append_group(
    shared: &AnchorDirShared,
    header: &HeaderFacts,
    dir: &Path,
    chain_id: &str,
    group: &[Pending],
    head: Option<&AnchorLine>,
    files: &mut Files,
) -> io::Result<()> {
    if !dir.is_absolute() {
        // It would resolve against the working directory of the process.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the anchor directory is not an absolute path",
        ));
    }
    let path = dir.join(file_name(chain_id));
    let key = (dir.to_path_buf(), chain_id.to_owned());
    // The lock guards the header (whoever creates the file writes it); only this thread appends.
    let (mut file, fresh) = {
        let _g = lock(&shared.file_lock);
        open_chain_file(dir, &path, || header.line(chain_id))?
    };
    if fresh {
        files.insert(key.clone(), None);
    }
    for p in group {
        if let Item::Incident { verify_seq, text } = &p.item {
            write_incident(dir, &incident_file_name(chain_id, *verify_seq), text)?;
        }
    }
    let r = append_lines(&mut file, &path, &key, group, head, fresh, files);
    if r.is_err() {
        files.remove(&key);
    }
    r
}

fn append_lines(
    file: &mut File,
    path: &Path,
    key: &FileKey,
    group: &[Pending],
    head: Option<&AnchorLine>,
    fresh: bool,
    files: &mut Files,
) -> io::Result<()> {
    let catch_up: Vec<String> = group
        .iter()
        .filter(|p| p.keep == Keep::CatchUp)
        .filter_map(|p| match &p.item {
            Item::Line(l) => Some(to_line(l)),
            Item::EnsureFile | Item::Incident { .. } => None,
        })
        .collect();
    let mut present = HashSet::new();
    if !files.contains_key(key) || !catch_up.is_empty() {
        let (last, found) = scan(path, &catch_up)?;
        present = found;
        let known = files.get(key).copied().flatten();
        files.insert(key.clone(), last.max(known));
    }
    let mut last = files.get(key).copied().flatten();
    let mut buf = String::new();
    // Checked before every append: a crash (or a failed write) may have torn the last line.
    if !fresh && ends_torn(path)? {
        buf.push('\n');
        if let Some(h) = head {
            let text = to_line(h);
            buf.push_str(&text);
            buf.push('\n');
            last = last.max(record_date(h));
            present.insert(text);
        }
    }
    for p in group {
        let Item::Line(l) = &p.item else { continue };
        let text = to_line(l);
        if p.keep == Keep::CatchUp && present.contains(&text) {
            continue;
        }
        let date = record_date(l);
        if p.keep == Keep::Daily && date.is_some() && last >= date {
            continue;
        }
        last = last.max(date);
        buf.push_str(&text);
        buf.push('\n');
        // A catch-up line behind the same line in this group is written once.
        if !catch_up.is_empty() {
            present.insert(text);
        }
    }
    if !buf.is_empty() {
        file.write_all(buf.as_bytes())?;
        file.sync_all()?;
        record_sync(path);
    }
    files.insert(key.clone(), last);
    Ok(())
}

/// Whether the file's last byte is not a newline (a crash tore its last line). An empty file is
/// not torn.
fn ends_torn(path: &Path) -> io::Result<bool> {
    let mut f = File::open(path)?;
    if f.metadata()?.len() == 0 {
        return Ok(false);
    }
    f.seek(SeekFrom::End(-1))?;
    let mut b = [0u8; 1];
    f.read_exact(&mut b)?;
    Ok(b != [b'\n'])
}

/// An incident file, created once with create-new and fsynced with its directory entry; one
/// that exists already (written before, or put there by someone else) is left as it is.
fn write_incident(dir: &Path, name: &str, text: &str) -> io::Result<()> {
    let path = dir.join(name);
    match OpenOptions::new().append(true).create_new(true).open(&path) {
        Ok(mut f) => {
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            record_sync(&path);
            sync_dir_of(dir)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// The date of a `Record` line with a non-NULL epoch.
fn record_date(l: &AnchorLine) -> Option<NaiveDate> {
    match l {
        AnchorLine::Record { epoch: Some(e), .. } => parse_epoch(e),
        _ => None,
    }
}

/// Opens the chain file for appending; a missing one is created with create-new and its
/// header, fsynced, and its directory entry flushed. `true`: this call wrote the header. An
/// existing empty file (a crash between its creation and its header) gets the header too; an
/// existing file with content never gets a second one.
fn open_chain_file(
    dir: &Path,
    path: &Path,
    header: impl Fn() -> io::Result<String>,
) -> io::Result<(File, bool)> {
    let write_header = |f: &mut File| -> io::Result<()> {
        let mut h = header()?;
        h.push('\n');
        f.write_all(h.as_bytes())?;
        f.sync_all()?;
        record_sync(path);
        Ok(())
    };
    // Only a regular file is appended to: a FIFO would block the open for good, a symlink would
    // send the lines elsewhere (planting either needs write access to the dir; checked, then
    // opened, so not race-free).
    if let Ok(m) = std::fs::symlink_metadata(path)
        && !m.file_type().is_file()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the chain file is not a regular file",
        ));
    }
    match OpenOptions::new().append(true).open(path) {
        Ok(mut f) => {
            if f.metadata()?.len() == 0 {
                write_header(&mut f)?;
                return Ok((f, true));
            }
            Ok((f, false))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            match OpenOptions::new().append(true).create_new(true).open(path) {
                Ok(mut f) => {
                    write_header(&mut f)?;
                    sync_dir_of(dir)?;
                    Ok((f, true))
                }
                // Created meanwhile by someone else (who wrote its header).
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    Ok((OpenOptions::new().append(true).open(path)?, false))
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// The new directory entry made durable. Unix: an error fails the attempt. Windows: best effort
/// (`FlushFileBuffers` on a directory needs write access, which an append-only share may refuse;
/// NTFS and SMB journal the entry themselves), so such a share stays writable.
fn sync_dir_of(dir: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        if crate::open::sync_dir(dir).is_ok() {
            record_sync(dir);
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        crate::open::sync_dir(dir)?;
        record_sync(dir);
        Ok(())
    }
}

/// Reads the file once (bounded like the verifier's reads): the newest date of its `Record`
/// lines and which of `wanted` (canonical line texts) it holds. Unparseable lines are skipped.
fn scan(path: &Path, wanted: &[String]) -> io::Result<(Option<NaiveDate>, HashSet<String>)> {
    let f = File::open(path)?;
    let mut r = BufReader::new(f.take(MAX_FILE_BYTES));
    let mut buf = Vec::new();
    let mut last = None;
    let mut found = HashSet::new();
    loop {
        buf.clear();
        if r.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        let raw = buf.strip_suffix(b"\n").unwrap_or(&buf);
        if raw.len() > MAX_LINE_BYTES {
            continue;
        }
        let Ok(s) = std::str::from_utf8(raw) else {
            continue;
        };
        if wanted.iter().any(|w| w == s) {
            found.insert(s.to_owned());
        }
        if let Ok(l) = parse_line(s) {
            last = last.max(record_date(&l));
        }
    }
    Ok((last, found))
}

// ---------------------------------------------------------------------------------------
// fsync record (feature `testing`)

#[cfg(any(test, feature = "testing"))]
static SYNCED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

fn record_sync(_p: &Path) {
    #[cfg(any(test, feature = "testing"))]
    lock(&SYNCED).push(_p.to_path_buf());
}

/// Every file and directory the writer fsynced under `dir`, in order (feature `testing`; one
/// process runs many tests, so each test reads its own dir).
#[cfg(any(test, feature = "testing"))]
pub fn testing_synced_under(dir: &Path) -> Vec<PathBuf> {
    lock(&SYNCED)
        .iter()
        .filter(|p| p.starts_with(dir))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(seq: u64, keep: Keep) -> Pending {
        Pending {
            dir: Some("/a".into()),
            chain_id: "c".into(),
            item: Item::Line(AnchorLine::Record {
                seq,
                record_hash: [0; 32],
                epoch: None,
                clock_behind: false,
            }),
            keep,
        }
    }

    #[test]
    fn beyond_the_bound_only_the_newest_daily_line_stays() {
        let s = AnchorDirShared::new();
        s.push(
            (0..MAX_PENDING as u64)
                .map(|i| line(i, Keep::Always))
                .collect(),
        );
        s.push(vec![
            line(1_000_001, Keep::Daily),
            line(1_000_002, Keep::Always),
        ]);
        s.push(vec![line(1_000_003, Keep::Daily)]);
        let st = lock(&s.state);
        assert_eq!(st.daily_queued, 1);
        assert_eq!(st.queue.len(), MAX_PENDING + 2);
        let dailies: Vec<&Pending> = st.queue.iter().filter(|p| p.keep == Keep::Daily).collect();
        assert_eq!(dailies, vec![&line(1_000_003, Keep::Daily)]);
    }

    #[test]
    fn lines_without_any_anchor_dir_are_not_queued() {
        let s = AnchorDirShared::new();
        let mut p = line(1, Keep::Always);
        p.dir = None;
        s.push(vec![p.clone()]);
        assert_eq!(s.health().lines_pending, 0);
        s.set_fallback(Some(PathBuf::from("/fallback")));
        s.push(vec![p]);
        assert_eq!(s.health().lines_pending, 1);
    }

    #[test]
    fn an_attempt_stuck_past_the_bound_shows_as_failing() {
        let s = AnchorDirShared::new();
        s.push(vec![line(1, Keep::Always)]);
        let mut st = lock(&s.state);
        st.in_flight = 1;
        st.attempt_started = Some(Instant::now());
        drop(st);
        assert!(
            !s.health().write_failing,
            "a running attempt is not a failure"
        );
        let long_ago = Instant::now().checked_sub(STUCK_AFTER + Duration::from_secs(1));
        lock(&s.state).attempt_started = long_ago;
        assert!(s.health().write_failing, "a stuck attempt is shown");
    }

    #[test]
    fn a_second_stop_does_not_wait_again_for_a_stuck_thread() {
        // Nobody serves the queue: like a thread stuck on a hung share.
        let s = AnchorDirShared::new();
        s.init(true, 1);
        s.push(vec![line(1, Keep::Always)]);
        let budget = Duration::from_millis(300);
        let t = Instant::now();
        assert!(!s.drain_and_stop(budget));
        assert!(t.elapsed() >= budget);
        let t = Instant::now();
        assert!(!s.drain_and_stop(budget));
        assert!(t.elapsed() < budget / 3, "{:?}", t.elapsed());
    }

    fn note(seq: u64, epoch: Option<&str>, cd: Option<&str>, flags: EventFlags) -> RowNote {
        RowNote {
            seq,
            record_hash: [seq as u8; 32],
            epoch: epoch.and_then(parse_epoch),
            flags,
            event_type: EventType::APP_START,
            immediate: false,
            corroborated: cd.and_then(parse_epoch),
            incident: None,
        }
    }

    fn record_seqs(v: &[Pending]) -> Vec<(u64, bool)> {
        v.iter()
            .filter_map(|p| match &p.item {
                Item::Line(AnchorLine::Record {
                    seq, clock_behind, ..
                }) => Some((*seq, *clock_behind)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn daily_rule_per_file_and_never_past_the_corroborated_date() {
        let mut c = Classifier::new(false);
        let d = Some("/a".to_string());
        let b = EventFlags::default();
        let v = c.lines(
            &d,
            "c",
            vec![
                note(1, None, None, b),
                note(2, Some("2026-10-08"), None, b),
                note(3, Some("2026-10-09"), Some("2026-10-08"), b),
                note(4, Some("2026-10-08"), Some("2026-10-08"), b),
                note(5, Some("2026-10-08"), Some("2026-10-09"), b),
            ],
            None,
        );
        assert_eq!(record_seqs(&v), vec![(4, false)]);
        // Another file of the same day gets its own line.
        let v = c.lines(
            &Some("/b".to_string()),
            "c",
            vec![note(6, Some("2026-10-08"), Some("2026-10-08"), b)],
            None,
        );
        assert_eq!(record_seqs(&v), vec![(6, false)]);
    }

    #[test]
    fn witness_after_a_flagged_run_also_from_the_head_at_open() {
        let mut c = Classifier::new(true);
        let d = Some("/a".to_string());
        let behind = EventFlags::BEHIND;
        let v = c.lines(
            &d,
            "c",
            vec![
                note(1, Some("2026-10-08"), None, EventFlags::default()),
                note(2, Some("2026-10-08"), None, EventFlags::default()),
                note(3, Some("2026-10-08"), None, behind),
                note(4, Some("2026-10-08"), None, EventFlags::default()),
            ],
            None,
        );
        assert_eq!(record_seqs(&v), vec![(1, false), (4, false)]);
    }
}
