//! The external anchor directory (§8.5). Each chain has `<anchor_dir>/<chain_id>.jsonl`: a
//! header line, then unsigned, append-only JSON lines (daily, `APP_STOP` and `RESTORE` lines,
//! immediate lines, prune lines, `ANCHOR_DETACHED`). [`parse_line`] and [`to_line`] are the one
//! line format both sides use; [`writer`] appends the lines (M10), [`load`] reads the files of
//! the store's chains (only `<chain_id>.jsonl` names: the incident files
//! `<chain_id>.incident-<verify_seq>.json` beside them never reach the parser, PD-164) and
//! [`check`] compares them with the store (§8.7). A line torn by a crash is tolerated on both
//! sides (PD-165, see `parse_file`). At a first run, `previous_chains` finds the chain files of
//! this host and OS user the chosen dir already holds (§8.5, PD-167).
//!
//! Lines are JCS text (sorted keys, no whitespace); a line that is not exactly what
//! [`to_line`] produces for its content is rejected. Hashes are 64 lowercase hex characters,
//! ids 32. Every hash comparison is constant-time. Line discrimination (plan decision):
//! `first_retained_seq` → `Prune`; `event_type == "ANCHOR_DETACHED"` → `Detached`; another
//! `event_type` → `Immediate`; `install_id` and `host` → `Header`; else `Record`. Unknown keys
//! are rejected.
//!
//! Every line that names a record carries that record's `epoch` (`null` for a NULL-epoch
//! record, L36), and a `Record` line carries `clock_behind: true` exactly when the record has
//! the flag; both are compared with the record while it is retained.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use atlas_duck_ipc::jcs::{MAX_SAFE_INTEGER, to_jcs_vec};
use chrono::NaiveDate;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Map, Value, json};

use crate::clock::{UtcInstant, parse_epoch};
use crate::crypto::ct_eq;
use crate::error::OpenError;
use crate::types::EventFlags;
use crate::verify::{FindingKind, PruneLogRow, VerifyFinding, hex32};

pub mod writer;

/// Longer lines are rejected before JSON parsing (a header with long host and user names is
/// far below it).
pub const MAX_LINE_BYTES: usize = 4096;

/// A larger anchor file is not read (a finding): decades of daily and immediate lines stay
/// far below it.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Lines read per file; the rest is not read (a finding). It bounds the per-line lookups a
/// verification run makes (decades of daily and immediate lines stay far below it).
pub const MAX_LINES: usize = 1_000_000;

/// Unparseable lines reported one by one per file; the rest is counted in one summary.
pub const MAX_BAD_LINES_REPORTED: usize = 16;

/// Chain files (`<chain_id>.jsonl`) a first run reads to find previous chains (PD-167, the same
/// bound as the export verifier's, PD-162); an anchor dir holding more is refused.
pub const MAX_FIRST_RUN_CHAIN_FILES: usize = 256;

/// What a first run reads of a chain file before it knows whose it is: the header, also after a
/// run of torn lines (each at most [`MAX_LINE_BYTES`]), lies far inside it.
const HEADER_PROBE_BYTES: u64 = 64 * 1024;

/// The end of a chain file a first run did not parse to the end, read for its last anchored
/// line.
const TAIL_BYTES: u64 = 64 * 1024;

/// The event types written as immediate lines (§8.5).
const IMMEDIATE_TYPES: [&str; 6] = [
    "PRUNE",
    "RESTORE",
    "LEGAL_HOLD_CHANGED",
    "CONFIG_CHANGED",
    "INTEGRITY_ACK",
    "CLOCK_ANOMALY",
];

const DETACHED: &str = "ANCHOR_DETACHED";

/// One line of an anchor file (§8.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorLine {
    /// The first line of each file.
    Header {
        chain_id: String,
        install_id: String,
        host: String,
        os_user: String,
        created_at: String,
    },
    /// Daily, `APP_STOP` and `RESTORE` lines; `clock_behind` is written only when true.
    Record {
        seq: u64,
        record_hash: [u8; 32],
        epoch: Option<String>,
        clock_behind: bool,
    },
    /// `PRUNE`, `RESTORE`, `LEGAL_HOLD_CHANGED`, policy `CONFIG_CHANGED`, `INTEGRITY_ACK`,
    /// `CLOCK_ANOMALY`, right after the commit.
    Immediate {
        seq: u64,
        record_hash: [u8; 32],
        epoch: Option<String>,
        event_type: String,
    },
    /// On `PRUNE`: the prune's `prune_log` values.
    Prune {
        first_retained_seq: u64,
        first_retained_prev_hash: [u8; 32],
        cutoff_epoch: String,
    },
    /// `{"event_type": "ANCHOR_DETACHED", …}`: the last line before the dir is switched.
    Detached {
        seq: u64,
        record_hash: [u8; 32],
        epoch: Option<String>,
        detached_at: String,
    },
}

/// Why a line is not a valid anchor line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorLineError {
    TooLong,
    NotJson,
    NotObject,
    UnknownKey(String),
    MissingKey(&'static str),
    BadValue(&'static str),
    /// Valid content, but not the canonical text (whitespace, key order, duplicate keys).
    NotCanonical,
}

impl fmt::Display for AnchorLineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnchorLineError::TooLong => write!(f, "longer than {MAX_LINE_BYTES} bytes"),
            AnchorLineError::NotJson => f.write_str("not JSON"),
            AnchorLineError::NotObject => f.write_str("not a JSON object"),
            // Key names come from the line: shown only when they look like a key.
            AnchorLineError::UnknownKey(k) if k.len() <= 64 && k.bytes().all(is_key_byte) => {
                write!(f, "unknown key {k}")
            }
            AnchorLineError::UnknownKey(_) => f.write_str("unknown key"),
            AnchorLineError::MissingKey(k) => write!(f, "missing key {k}"),
            AnchorLineError::BadValue(k) => write!(f, "invalid {k}"),
            AnchorLineError::NotCanonical => f.write_str("not in canonical form"),
        }
    }
}

impl std::error::Error for AnchorLineError {}

fn is_key_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
}

/// `"<chain_id>.jsonl"`.
pub fn file_name(chain_id: &str) -> String {
    format!("{chain_id}.jsonl")
}

/// 32 lowercase hex characters (F.1 ids).
fn is_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn epoch_json(e: &Option<String>) -> Value {
    e.as_ref().map_or(Value::Null, |e| json!(e))
}

fn to_value(l: &AnchorLine) -> Value {
    match l {
        AnchorLine::Header {
            chain_id,
            install_id,
            host,
            os_user,
            created_at,
        } => json!({
            "chain_id": chain_id,
            "created_at": created_at,
            "host": host,
            "install_id": install_id,
            "os_user": os_user,
        }),
        AnchorLine::Record {
            seq,
            record_hash,
            epoch,
            clock_behind,
        } => {
            let mut v = json!({
                "seq": seq,
                "record_hash": hex::encode(record_hash),
                "epoch": epoch_json(epoch),
            });
            if *clock_behind {
                v["clock_behind"] = json!(true);
            }
            v
        }
        AnchorLine::Immediate {
            seq,
            record_hash,
            epoch,
            event_type,
        } => json!({
            "seq": seq,
            "record_hash": hex::encode(record_hash),
            "epoch": epoch_json(epoch),
            "event_type": event_type,
        }),
        AnchorLine::Prune {
            first_retained_seq,
            first_retained_prev_hash,
            cutoff_epoch,
        } => json!({
            "first_retained_seq": first_retained_seq,
            "first_retained_prev_hash": hex::encode(first_retained_prev_hash),
            "cutoff_epoch": cutoff_epoch,
        }),
        AnchorLine::Detached {
            seq,
            record_hash,
            epoch,
            detached_at,
        } => json!({
            "event_type": DETACHED,
            "seq": seq,
            "record_hash": hex::encode(record_hash),
            "epoch": epoch_json(epoch),
            "detached_at": detached_at,
        }),
    }
}

/// The JCS text of `l`, without a trailing newline (M10's writer appends `"\n"`).
pub fn to_line(l: &AnchorLine) -> String {
    let v = to_value(l);
    // JCS fails only for an integer beyond 2^53 − 1, which `parse_line` never yields and no
    // store reaches; serde_json's compact text with sorted keys is the same text otherwise.
    to_jcs_vec(&v)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| v.to_string())
}

/// The keys of one line kind: what must be present, and what else may be.
struct Keys<'a> {
    o: &'a Map<String, Value>,
}

impl<'a> Keys<'a> {
    /// Rejects keys outside `allowed`, then requires each of `required`.
    fn only(
        o: &'a Map<String, Value>,
        required: &[&'static str],
        optional: &[&str],
    ) -> Result<Keys<'a>, AnchorLineError> {
        if let Some(k) = o
            .keys()
            .find(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str()))
        {
            return Err(AnchorLineError::UnknownKey(k.clone()));
        }
        if let Some(k) = required.iter().find(|k| !o.contains_key(**k)) {
            return Err(AnchorLineError::MissingKey(k));
        }
        Ok(Keys { o })
    }

    fn get(&self, k: &'static str) -> Result<&'a Value, AnchorLineError> {
        self.o.get(k).ok_or(AnchorLineError::MissingKey(k))
    }

    /// A seq: 1..=2^53 − 1.
    fn seq(&self, k: &'static str) -> Result<u64, AnchorLineError> {
        self.get(k)?
            .as_u64()
            .filter(|s| (1..=MAX_SAFE_INTEGER as u64).contains(s))
            .ok_or(AnchorLineError::BadValue(k))
    }

    fn hash(&self, k: &'static str) -> Result<[u8; 32], AnchorLineError> {
        self.get(k)?
            .as_str()
            .filter(|s| s.len() == 64)
            .and_then(hex32)
            .ok_or(AnchorLineError::BadValue(k))
    }

    fn id(&self, k: &'static str) -> Result<String, AnchorLineError> {
        self.get(k)?
            .as_str()
            .filter(|s| is_id(s))
            .map(str::to_owned)
            .ok_or(AnchorLineError::BadValue(k))
    }

    fn text(&self, k: &'static str) -> Result<String, AnchorLineError> {
        self.get(k)?
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or(AnchorLineError::BadValue(k))
    }

    /// An RFC 3339 instant as the store writes them (`…T…:…:….mmmZ`).
    fn instant(&self, k: &'static str) -> Result<String, AnchorLineError> {
        self.get(k)?
            .as_str()
            .filter(|s| UtcInstant::parse_rfc3339_ms(s).is_some())
            .map(str::to_owned)
            .ok_or(AnchorLineError::BadValue(k))
    }

    /// A `YYYY-MM-DD` date.
    fn date(&self, k: &'static str) -> Result<String, AnchorLineError> {
        self.get(k)?
            .as_str()
            .filter(|s| parse_epoch(s).is_some())
            .map(str::to_owned)
            .ok_or(AnchorLineError::BadValue(k))
    }

    fn epoch(&self) -> Result<Option<String>, AnchorLineError> {
        match self.get("epoch")? {
            Value::Null => Ok(None),
            _ => self.date("epoch").map(Some),
        }
    }
}

/// Parses one line (without its newline). Exact errors come from explicit key checks, not
/// from an untagged enum; the text must be canonical ([`to_line`] of the result).
pub fn parse_line(s: &str) -> Result<AnchorLine, AnchorLineError> {
    if s.len() > MAX_LINE_BYTES {
        return Err(AnchorLineError::TooLong);
    }
    let v: Value = serde_json::from_str(s).map_err(|_| AnchorLineError::NotJson)?;
    let o = v.as_object().ok_or(AnchorLineError::NotObject)?;
    let line = if o.contains_key("first_retained_seq") {
        let k = Keys::only(
            o,
            &[
                "first_retained_seq",
                "first_retained_prev_hash",
                "cutoff_epoch",
            ],
            &[],
        )?;
        AnchorLine::Prune {
            first_retained_seq: k.seq("first_retained_seq")?,
            first_retained_prev_hash: k.hash("first_retained_prev_hash")?,
            cutoff_epoch: k.date("cutoff_epoch")?,
        }
    } else if let Some(t) = o.get("event_type") {
        if t.as_str() == Some(DETACHED) {
            let k = Keys::only(
                o,
                &["event_type", "seq", "record_hash", "epoch", "detached_at"],
                &[],
            )?;
            AnchorLine::Detached {
                seq: k.seq("seq")?,
                record_hash: k.hash("record_hash")?,
                epoch: k.epoch()?,
                detached_at: k.instant("detached_at")?,
            }
        } else {
            let k = Keys::only(o, &["event_type", "seq", "record_hash", "epoch"], &[])?;
            let event_type = t
                .as_str()
                .filter(|t| IMMEDIATE_TYPES.contains(t))
                .ok_or(AnchorLineError::BadValue("event_type"))?;
            AnchorLine::Immediate {
                seq: k.seq("seq")?,
                record_hash: k.hash("record_hash")?,
                epoch: k.epoch()?,
                event_type: event_type.to_owned(),
            }
        }
    } else if o.contains_key("install_id") && o.contains_key("host") {
        let k = Keys::only(
            o,
            &["chain_id", "install_id", "host", "os_user", "created_at"],
            &[],
        )?;
        AnchorLine::Header {
            chain_id: k.id("chain_id")?,
            install_id: k.id("install_id")?,
            host: k.text("host")?,
            os_user: k.text("os_user")?,
            created_at: k.instant("created_at")?,
        }
    } else {
        let k = Keys::only(o, &["seq", "record_hash", "epoch"], &["clock_behind"])?;
        let clock_behind = match o.get("clock_behind") {
            None => false,
            // Written only when true (§8.5).
            Some(Value::Bool(true)) => true,
            Some(_) => return Err(AnchorLineError::BadValue("clock_behind")),
        };
        AnchorLine::Record {
            seq: k.seq("seq")?,
            record_hash: k.hash("record_hash")?,
            epoch: k.epoch()?,
            clock_behind,
        }
    };
    if to_line(&line) != s {
        return Err(AnchorLineError::NotCanonical);
    }
    Ok(line)
}

// ---------------------------------------------------------------------------------------
// Reading the anchor dir

/// The anchor dir as read for one verification run.
#[derive(Debug, Default)]
pub(crate) struct AnchorDirLines {
    /// Per `chain_id`, the parsed lines of `<chain_id>.jsonl` with their 1-based line numbers.
    pub(crate) chains: BTreeMap<String, Vec<(usize, AnchorLine)>>,
    /// What could not be read: the dir, a file, a line. Each is an `AnchorDirMismatch`, never
    /// a clean pass, but none contradicts the store (it defers, not refuses, a reconciliation).
    /// Bounded: at most a few per file.
    pub(crate) problems: Vec<VerifyFinding>,
    /// Informational findings (`AnchorDirTornLine`, PD-165): neither a mismatch nor a reason to
    /// defer anything. Bounded like `problems`.
    pub(crate) notes: Vec<VerifyFinding>,
    /// Store `chain_id`s that are not valid ids (their files were not read): a store defect,
    /// reported by [`check`].
    pub(crate) invalid_chain_ids: usize,
}

impl AnchorDirLines {
    /// The settings view could not be rebuilt from the log, so whether (and which) anchor dir
    /// is configured is unknown: recorded, never treated as "no anchor dir".
    pub(crate) fn note_setting_unreadable(lines: &mut Option<AnchorDirLines>) {
        lines
            .get_or_insert_with(AnchorDirLines::default)
            .problems
            .push(problem(
                "the anchor_dir setting could not be read from the audit log",
            ));
    }
}

/// The anchor dir verification reads (plan decision): the store's `anchor_dir` setting, which
/// is authoritative, else `OpenConfig.anchor_dir` when the store names none.
pub(crate) fn resolve(setting: Option<&str>, configured: Option<&Path>) -> Option<PathBuf> {
    setting
        .map(PathBuf::from)
        .or_else(|| configured.map(Path::to_path_buf))
}

/// Whether two anchor dirs name the same directory as far as their text tells: trailing
/// separators do not count, and on Windows neither does ASCII case nor `/` against `\`
/// (`C:\Anchors` and `c:\anchors\` are one dir there). No file system access.
pub(crate) fn same_dir(a: Option<&Path>, b: Option<&Path>) -> bool {
    fn norm(p: &Path) -> String {
        let s = p.to_string_lossy();
        let s = if cfg!(windows) {
            s.replace('/', "\\").to_ascii_lowercase()
        } else {
            s.into_owned()
        };
        let t = s.trim_end_matches(['/', '\\']);
        if t.is_empty() { s } else { t.to_owned() }
    }
    match (a, b) {
        (Some(a), Some(b)) => norm(a) == norm(b),
        (None, None) => true,
        _ => false,
    }
}

fn problem(detail: impl Into<String>) -> VerifyFinding {
    VerifyFinding::new(FindingKind::AnchorDirMismatch, detail)
}

/// The chains whose records the store holds: the first and the newest record's, and each
/// `RESTORE`'s and its predecessor's (`chain_id` changes only at a `RESTORE`, §8.11, which
/// the chain walk checks). Uses the `event_type` index rather than a table scan.
/// A `chain_id` that is not text reads as `None`.
fn store_chains(conn: &Connection) -> rusqlite::Result<BTreeSet<Option<String>>> {
    let mut stmt = conn.prepare(
        "SELECT chain_id FROM events WHERE seq = (SELECT min(seq) FROM events) \
         UNION SELECT chain_id FROM events WHERE seq = (SELECT max(seq) FROM events) \
         UNION SELECT chain_id FROM events WHERE event_type = 'RESTORE' \
         UNION SELECT e.chain_id FROM events e JOIN events r ON e.seq = r.seq - 1 \
               WHERE r.event_type = 'RESTORE'",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = BTreeSet::new();
    while let Some(r) = rows.next()? {
        out.insert(match r.get_ref(0)? {
            ValueRef::Text(t) => Some(String::from_utf8_lossy(t).into_owned()),
            _ => None,
        });
    }
    Ok(out)
}

/// Reads `<chain_id>.jsonl` for every chain of the store from `dir` (`None`: no anchor dir is
/// configured, nothing to compare). A dir that is not absolute or cannot be read, a file that
/// cannot be read, is empty or too long, and a line that does not parse are problems
/// (findings). A missing file is not (a chain with no line yet; the writer creates the current
/// chain's file at the next start or line). Only a database error is an `Err`.
pub(crate) fn load(
    dir: Option<&Path>,
    conn: &Connection,
) -> Result<Option<AnchorDirLines>, OpenError> {
    let Some(dir) = dir else {
        return Ok(None);
    };
    let chains = store_chains(conn).map_err(|e| OpenError::Sqlite(e.to_string()))?;
    let mut out = AnchorDirLines::default();
    if !dir.is_absolute() {
        // It would resolve against the working directory of the process.
        out.problems
            .push(problem("the anchor directory is not an absolute path"));
        return Ok(Some(out));
    }
    match std::fs::metadata(dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            out.problems
                .push(problem("the anchor directory is not a directory"));
            return Ok(Some(out));
        }
        Err(e) => {
            out.problems.push(problem(format!(
                "the anchor directory could not be read ({:?})",
                e.kind()
            )));
            return Ok(Some(out));
        }
    }
    for chain in chains {
        // Never a path component unless it is an id: a tampered one could name another file.
        let Some(chain) = chain.filter(|c| is_id(c)) else {
            out.invalid_chain_ids += 1;
            continue;
        };
        let name = file_name(&chain);
        match read_file(&dir.join(&name)) {
            Ok(None) => {}
            Ok(Some(bytes)) if bytes.is_empty() => {
                out.problems
                    .push(problem(format!("{name} is empty: it has no header line")));
            }
            Ok(Some(bytes)) => {
                let lines = parse_file(&name, &chain, &bytes, &mut out.problems, &mut out.notes);
                out.chains.insert(chain, lines);
            }
            Err(what) => out.problems.push(problem(format!("{name}: {what}"))),
        }
    }
    Ok(Some(out))
}

/// The file's bytes; `Ok(None)` when it does not exist.
fn read_file(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("could not be read ({:?})", e.kind())),
    };
    if !meta.is_file() {
        return Err("is not a regular file".into());
    }
    let too_large = || format!("is larger than {MAX_FILE_BYTES} bytes");
    if meta.len() > MAX_FILE_BYTES {
        return Err(too_large());
    }
    let unreadable = |e: std::io::Error| format!("could not be read ({:?})", e.kind());
    // The handle is checked again (a FIFO swapped in after the check above does not block).
    let file = open_regular(path)
        .map_err(unreadable)?
        .ok_or_else(|| "is not a regular file".to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(too_large());
    }
    Ok(Some(bytes))
}

fn parse_raw(raw: &[u8]) -> Result<AnchorLine, AnchorLineError> {
    std::str::from_utf8(raw)
        .map_err(|_| AnchorLineError::NotJson)
        .and_then(parse_line)
}

/// A line a crash cut off while it was appended (PD-165): at most [`MAX_LINE_BYTES`], starting
/// like every line (`{"`), and an unfinished JSON text (the parser runs out of input, which a
/// complete line, however wrong, never does). A cut inside a multi-byte character counts too.
fn is_torn(raw: &[u8]) -> bool {
    if raw.len() > MAX_LINE_BYTES || !raw.starts_with(b"{\"") {
        return false;
    }
    let text = match std::str::from_utf8(raw) {
        Ok(t) => t,
        Err(e) if e.error_len().is_none() => match raw.get(..e.valid_up_to()) {
            Some(valid) => match std::str::from_utf8(valid) {
                Ok(t) => t,
                Err(_) => return false,
            },
            None => return false,
        },
        Err(_) => return false,
    };
    matches!(serde_json::from_str::<Value>(text), Err(e) if e.is_eof())
}

/// The bad and torn lines of one file, each reported one by one up to
/// [`MAX_BAD_LINES_REPORTED`], the rest counted.
struct Tally<'a> {
    name: &'a str,
    bad: usize,
    torn: usize,
}

impl Tally<'_> {
    fn bad(&mut self, problems: &mut Vec<VerifyFinding>, n: usize, e: &AnchorLineError) {
        self.bad += 1;
        if self.bad <= MAX_BAD_LINES_REPORTED {
            problems.push(problem(format!(
                "{} line {n} is not a valid anchor line: {e}",
                self.name
            )));
        }
    }

    fn torn(&mut self, notes: &mut Vec<VerifyFinding>, n: usize) {
        self.torn += 1;
        if self.torn <= MAX_BAD_LINES_REPORTED {
            notes.push(VerifyFinding::new(
                FindingKind::AnchorDirTornLine,
                format!(
                    "{} line {n} is a torn line (an interrupted append)",
                    self.name
                ),
            ));
        }
    }
}

/// Consecutive torn-looking lines not judged yet: the first one's number, how many, and the
/// first errors (reported should the run turn out bad).
#[derive(Default)]
struct TornRun {
    start: usize,
    len: usize,
    errors: Vec<AnchorLineError>,
}

impl TornRun {
    fn push(&mut self, n: usize, e: AnchorLineError) {
        if self.len == 0 {
            self.start = n;
        }
        self.len += 1;
        if self.errors.len() < MAX_BAD_LINES_REPORTED {
            self.errors.push(e);
        }
    }

    /// Judges the run (`torn`: tolerated) and empties it.
    fn settle(
        &mut self,
        torn: bool,
        t: &mut Tally<'_>,
        problems: &mut Vec<VerifyFinding>,
        notes: &mut Vec<VerifyFinding>,
    ) {
        let lines = self.start..self.start + self.len;
        if torn {
            lines.for_each(|n| t.torn(notes, n));
        } else {
            let errors = std::mem::take(&mut self.errors);
            for (n, e) in lines.zip(&errors) {
                t.bad(problems, n, e);
            }
            // Beyond the reported ones: counted only (the first ones already reached the bound).
            t.bad += self.len - errors.len();
        }
        *self = TornRun::default();
    }
}

/// Lines separated by `\n`, split lazily; the empty remainder after a final newline is not a
/// line. Every other line must parse (an empty one does not), except torn lines (PD-165,
/// [`is_torn`]). A run of consecutive torn lines (two crashes in a row leave two) is tolerated
/// when it ends the file or is followed by a valid line: the writer closes a torn last line with
/// a newline (and a `Record` line for the head) before its next append. A run that starts at
/// line 1 (a crash while the header was written) is tolerated only when the line after it is a
/// header naming `chain`, which the writer then appends; a file of torn lines only has no
/// header, like an empty file (a problem). A tolerated torn line is an informational
/// `AnchorDirTornLine` in `notes` and never a line: a record whose line was torn is unanchored,
/// as if the line had never been written. A run that is not tolerated is bad lines like any
/// other. At most [`MAX_BAD_LINES_REPORTED`] bad (and torn) lines are reported one by one, the
/// rest in one summary, and at most [`MAX_LINES`] lines are read, so a file of garbage costs
/// bounded memory and time.
fn parse_file(
    name: &str,
    chain: &str,
    bytes: &[u8],
    problems: &mut Vec<VerifyFinding>,
    notes: &mut Vec<VerifyFinding>,
) -> Vec<(usize, AnchorLine)> {
    let mut lines = Vec::new();
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let mut t = Tally {
        name,
        bad: 0,
        torn: 0,
    };
    let mut run = TornRun::default();
    for (i, raw) in body.split(|b| *b == b'\n').enumerate() {
        let n = i + 1;
        if n > MAX_LINES {
            problems.push(problem(format!(
                "{name} has more than {MAX_LINES} lines; the rest was not read"
            )));
            break;
        }
        match parse_raw(raw) {
            Ok(l) => {
                if run.len > 0 {
                    let ok = run.start != 1
                        || matches!(&l, AnchorLine::Header { chain_id, .. } if chain_id == chain);
                    run.settle(ok, &mut t, problems, notes);
                }
                lines.push((n, l));
            }
            Err(e) if is_torn(raw) => run.push(n, e),
            Err(e) => {
                run.settle(false, &mut t, problems, notes);
                t.bad(problems, n, &e);
            }
        }
    }
    if run.len > 0 {
        if run.start == 1 {
            problems.push(problem(format!(
                "{name} holds only torn lines: it has no header line"
            )));
        } else {
            run.settle(true, &mut t, problems, notes);
        }
    }
    if t.bad > MAX_BAD_LINES_REPORTED {
        problems.push(problem(format!(
            "{name}: {} more lines are not valid anchor lines",
            t.bad - MAX_BAD_LINES_REPORTED
        )));
    }
    if t.torn > MAX_BAD_LINES_REPORTED {
        notes.push(VerifyFinding::new(
            FindingKind::AnchorDirTornLine,
            format!(
                "{name}: {} more torn lines",
                t.torn - MAX_BAD_LINES_REPORTED
            ),
        ));
    }
    lines
}

// ---------------------------------------------------------------------------------------
// Previous chains at a first run (§8.5 "First run against a used anchor dir", PD-167)

/// A chain file of this host and OS user that a first run found in its anchor dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreviousChain {
    /// The file's `<chain_id>`.
    pub(crate) chain_id: String,
    /// The last line in file order that names a record: `(seq, record_hash, epoch)`. Of a file
    /// not parsed to its end (beyond [`MAX_FILE_BYTES`] or [`MAX_LINES`]), the last one within
    /// its final [`TAIL_BYTES`], else the parsed part's.
    pub(crate) last: Option<Anchored>,
    pub(crate) mtime: Option<SystemTime>,
    /// What the file witnesses, kept only for the chain asked for and only when the whole file
    /// was read and every line parsed (torn lines aside). `None`: no complete witness, so no
    /// archive can be shown to cover it.
    pub(crate) witness: Option<Witness>,
}

/// `(seq, record_hash, epoch)` of a line that names a record.
pub(crate) type Anchored = (u64, [u8; 32], Option<String>);

/// The lines of a previous chain's file an archive must agree with to cover it (PD-167).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Witness {
    /// Every `(seq, record_hash)` the lines name.
    pub(crate) named: Vec<(u64, [u8; 32])>,
    /// Every `Prune` line: `(first_retained_seq, first_retained_prev_hash, cutoff_epoch)`.
    pub(crate) prunes: Vec<(u64, [u8; 32], String)>,
}

impl PreviousChain {
    /// "Newest" (PD-167): the last line's `epoch` (a dated line after an undated one, `None`
    /// lowest), then the file's mtime, then the id (deterministic).
    fn newness(&self) -> (Option<&str>, Option<SystemTime>, &str) {
        (
            self.last.as_ref().and_then(|l| l.2.as_deref()),
            self.mtime,
            &self.chain_id,
        )
    }
}

/// The chains of this `host` and `os_user` in `dir` (headers compared exactly, after the
/// writer's bounds; RF-3), newest first, for a first run whose own chain is `own_chain`. Only
/// regular files named `<chain_id>.jsonl` are read (never an incident file; the opened handle
/// is checked, and on Unix a FIFO does not block the open), each with the bounds and the
/// torn-line rule of [`load`] (a header after a torn line 1 counts), and nothing is written. A
/// file whose first readable line is a header of this host and user is a previous chain,
/// whatever else it holds; a file of anyone else is read no further than
/// [`HEADER_PROBE_BYTES`]. The [`Witness`] is kept for `keep_named` only.
///
/// Refused (`Invalid`), so that a first run never starts over a dir it could not check: a dir
/// that is not absolute, not a directory or cannot be listed; more than
/// [`MAX_FIRST_RUN_CHAIN_FILES`] chain files; a chain file that cannot be read.
pub(crate) fn previous_chains(
    dir: &Path,
    host: &str,
    os_user: &str,
    own_chain: &str,
    keep_named: Option<&str>,
) -> Result<Vec<PreviousChain>, OpenError> {
    previous_chains_with(dir, host, os_user, own_chain, keep_named, MAX_FILE_BYTES)
}

/// [`previous_chains`] with the per-file bound as a parameter (tests use a small one).
fn previous_chains_with(
    dir: &Path,
    host: &str,
    os_user: &str,
    own_chain: &str,
    keep_named: Option<&str>,
    max_bytes: u64,
) -> Result<Vec<PreviousChain>, OpenError> {
    let unreadable = || OpenError::Invalid("the anchor directory cannot be read");
    if !dir.is_absolute() {
        return Err(OpenError::Invalid(
            "the anchor directory is not an absolute path",
        ));
    }
    match std::fs::metadata(dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(OpenError::Invalid(
                "the anchor directory is not a directory",
            ));
        }
        Err(_) => return Err(unreadable()),
    }
    let mut chains = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|_| unreadable())? {
        let entry = entry.map_err(|_| unreadable())?;
        let name = entry.file_name();
        let Some(chain) = name
            .to_str()
            .and_then(|n| n.strip_suffix(".jsonl"))
            .filter(|c| is_id(c) && *c != own_chain)
        else {
            continue;
        };
        chains.push(chain.to_owned());
        if chains.len() > MAX_FIRST_RUN_CHAIN_FILES {
            return Err(OpenError::Invalid(
                "the anchor directory holds more chain files than a first run reads",
            ));
        }
    }
    chains.sort();
    let mut out = Vec::new();
    for chain in chains {
        let name = file_name(&chain);
        let path = dir.join(&name);
        let unreadable_file =
            || OpenError::Invalid("a chain file in the anchor directory cannot be read");
        // Only a regular file is a chain (a directory is not); one gone since the listing is not
        // one. The handle is checked again: that check is the one a swap cannot get past.
        match std::fs::metadata(&path) {
            Ok(m) if m.is_file() => {}
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(unreadable_file()),
        }
        let file = match open_regular(&path) {
            Ok(Some(f)) => f,
            Ok(None) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(unreadable_file()),
        };
        let keep = keep_named == Some(chain.as_str());
        let found = read_if_ours(file, &name, &chain, (host, os_user), keep, max_bytes)
            .map_err(|_| unreadable_file())?;
        out.extend(found);
    }
    out.sort_by(|a, b| b.newness().cmp(&a.newness()));
    Ok(out)
}

/// The previous chain in `file` (`<chain>.jsonl`, `name`) when its first readable line is a
/// header of `owner` (host, OS user), else `None`. Only the first [`HEADER_PROBE_BYTES`] are
/// read to tell, so another user's file is never read further (T6 review M-4); a file of this
/// user is then read on from the same handle, up to `max_bytes` (a longer one is cut after its
/// last complete line). `keep`: keep its [`Witness`] when the file was read whole and every
/// line parsed.
fn read_if_ours(
    mut file: std::fs::File,
    name: &str,
    chain: &str,
    (host, os_user): (&str, &str),
    keep: bool,
    max_bytes: u64,
) -> std::io::Result<Option<PreviousChain>> {
    let mut bytes = Vec::new();
    let probe = HEADER_PROBE_BYTES.min(max_bytes.saturating_add(1));
    file.by_ref().take(probe).read_to_end(&mut bytes)?;
    // A probe that filled may end inside a line: only its complete lines are judged.
    let head = if (bytes.len() as u64) < probe {
        &bytes[..]
    } else {
        complete_lines(&bytes)
    };
    let (mut problems, mut notes) = (Vec::new(), Vec::new());
    let ours = matches!(parse_file(name, chain, head, &mut problems, &mut notes).first(),
        Some((_, AnchorLine::Header { host: h, os_user: u, .. })) if h == host && u == os_user);
    if !ours {
        return Ok(None);
    }
    let rest = max_bytes
        .saturating_add(1)
        .saturating_sub(bytes.len() as u64);
    file.by_ref().take(rest).read_to_end(&mut bytes)?;
    let whole = bytes.len() as u64 <= max_bytes;
    if !whole {
        // The partial last line is dropped from the buffer (the file itself is only read).
        let keep = complete_lines(&bytes).len();
        drop(bytes.split_off(keep));
    }
    let (mut problems, mut notes) = (Vec::new(), Vec::new());
    let lines = parse_file(name, chain, &bytes, &mut problems, &mut notes);
    let complete = whole && problems.is_empty();
    let mut last = lines.iter().rev().find_map(|(_, l)| named(l)).map(anchor);
    if !complete && let Some(at_end) = last_named_in_tail(&mut file)? {
        // The lines past what was parsed (beyond the bound or `MAX_LINES`) name the later
        // records: the newest is read from the file's end (T6 review M-3).
        last = Some(at_end);
    }
    let witness = (complete && keep).then(|| Witness {
        named: lines
            .iter()
            .filter_map(|(_, l)| named(l).map(|n| (n.seq, *n.record_hash)))
            .collect(),
        prunes: lines
            .iter()
            .filter_map(|(_, l)| match l {
                AnchorLine::Prune {
                    first_retained_seq,
                    first_retained_prev_hash,
                    cutoff_epoch,
                } => Some((
                    *first_retained_seq,
                    *first_retained_prev_hash,
                    cutoff_epoch.clone(),
                )),
                _ => None,
            })
            .collect(),
    });
    Ok(Some(PreviousChain {
        chain_id: chain.to_owned(),
        last,
        mtime: file.metadata().and_then(|m| m.modified()).ok(),
        witness,
    }))
}

fn anchor(n: Named<'_>) -> Anchored {
    (n.seq, *n.record_hash, n.epoch.clone())
}

/// The last line naming a record within the final [`TAIL_BYTES`] of `file` (the window's first,
/// cut line aside).
fn last_named_in_tail(file: &mut std::fs::File) -> std::io::Result<Option<Anchored>> {
    let start = file.metadata()?.len().saturating_sub(TAIL_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut tail = Vec::new();
    file.by_ref().take(TAIL_BYTES).read_to_end(&mut tail)?;
    let body = match start {
        0 => &tail[..],
        _ => tail
            .iter()
            .position(|b| *b == b'\n')
            .and_then(|i| tail.get(i + 1..))
            .unwrap_or_default(),
    };
    Ok(body
        .split(|b| *b == b'\n')
        .rev()
        .find_map(|raw| parse_raw(raw).ok().as_ref().and_then(named).map(anchor)))
}

/// `bytes` up to and including its last newline (empty without one).
fn complete_lines(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .and_then(|i| bytes.get(..=i))
        .unwrap_or_default()
}

/// Opens `path` for reading and checks the handle, not the path, so that nothing swapped in
/// after an earlier check is read: `Ok(None)` when it is not a regular file. On Unix the open
/// does not block on a FIFO (`O_NONBLOCK`, which a regular file ignores). T6 review M-5.
fn open_regular(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK);
    }
    let file = opts.open(path)?;
    Ok(file.metadata()?.is_file().then_some(file))
}

// ---------------------------------------------------------------------------------------
// Checks (§8.7 full verification "With an anchor directory", "Anchor-dir lines")

/// What the checks compare the lines with: one read snapshot of the store.
pub(crate) struct VerifyCtx<'a> {
    pub(crate) conn: &'a Connection,
    /// The latest `prune_log` row's `first_retained_seq` (1 before any prune).
    pub(crate) first_retained_seq: u64,
    /// `max(seq)`.
    pub(crate) head: Option<u64>,
    /// The readable `prune_log` rows by `prune_seq`.
    pub(crate) prune_log: &'a [PruneLogRow],
    /// Seqs of superseded chains that same-machine rollbacks gave up.
    pub(crate) lost: &'a [LostSpan],
}

/// Records of a superseded chain that an authorised same-machine rollback gave up (§8.11:
/// "anchored lines of the source chain beyond `source_head_seq` must be accounted for by
/// `records_lost`"): seqs `after + 1 ..= up_to` of `chain_id`. A line of that chain's file
/// naming one of them, where the store now holds a record of another chain or nothing, is
/// accounted for instead of contradicting the store. Nothing else is relaxed: the rest of
/// that file is checked as before, and a line beyond `up_to` is still a contradiction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LostSpan {
    pub(crate) chain_id: String,
    pub(crate) after: u64,
    pub(crate) up_to: u64,
}

impl LostSpan {
    /// The span a `RESTORE` accounts for: only a same-machine rollback, i.e. its
    /// `prior_keychain_anchor` names its source chain beyond its source head, with
    /// `records_lost > 0`; bounded by both the prior anchor's seq and `records_lost`.
    pub(crate) fn of(
        source_chain_id: &str,
        source_head_seq: u64,
        prior: Option<(&str, u64)>,
        records_lost: u64,
    ) -> Option<LostSpan> {
        let (chain, prior_seq) = prior?;
        if records_lost == 0 || chain != source_chain_id || prior_seq <= source_head_seq {
            return None;
        }
        Some(LostSpan {
            chain_id: source_chain_id.to_owned(),
            after: source_head_seq,
            up_to: prior_seq.min(source_head_seq.saturating_add(records_lost)),
        })
    }

    fn covers(&self, chain: &str, seq: u64) -> bool {
        self.chain_id == chain && seq > self.after && seq <= self.up_to
    }
}

/// One retained record as the checks see it; a malformed column reads as `None`.
struct Row {
    record_hash: Option<[u8; 32]>,
    chain_id: Option<String>,
    event_type: Option<String>,
    /// `None`: not text or NULL; `Some(None)`: NULL.
    epoch: Option<Option<String>>,
    flags: Option<u64>,
    ts_utc: Option<String>,
}

fn text(v: ValueRef<'_>) -> Option<String> {
    match v {
        ValueRef::Text(t) => std::str::from_utf8(t).ok().map(str::to_owned),
        _ => None,
    }
}

fn row(conn: &Connection, seq: u64) -> rusqlite::Result<Option<Row>> {
    let Ok(seq) = i64::try_from(seq) else {
        return Ok(None);
    };
    conn.prepare_cached(
        "SELECT record_hash, chain_id, event_type, epoch, flags, ts_utc FROM events \
         WHERE seq = ?1",
    )?
    .query_row([seq], |r| {
        Ok(Row {
            record_hash: match r.get_ref(0)? {
                ValueRef::Blob(b) => <[u8; 32]>::try_from(b).ok(),
                _ => None,
            },
            chain_id: text(r.get_ref(1)?),
            event_type: text(r.get_ref(2)?),
            epoch: match r.get_ref(3)? {
                ValueRef::Null => Some(None),
                v => text(v).map(Some),
            },
            flags: match r.get_ref(4)? {
                ValueRef::Integer(i) => u64::try_from(i).ok(),
                _ => None,
            },
            ts_utc: text(r.get_ref(5)?),
        })
    })
    .optional()
}

/// The fields every line that names a record has.
struct Named<'l> {
    seq: u64,
    record_hash: &'l [u8; 32],
    epoch: &'l Option<String>,
}

fn named(l: &AnchorLine) -> Option<Named<'_>> {
    match l {
        AnchorLine::Record {
            seq,
            record_hash,
            epoch,
            ..
        }
        | AnchorLine::Immediate {
            seq,
            record_hash,
            epoch,
            ..
        }
        | AnchorLine::Detached {
            seq,
            record_hash,
            epoch,
            ..
        } => Some(Named {
            seq: *seq,
            record_hash,
            epoch,
        }),
        AnchorLine::Header { .. } | AnchorLine::Prune { .. } => None,
    }
}

/// Compares every line with the store (§8.7): a line naming a retained seq (≥ the latest
/// `first_retained_seq`) must match that record (`AnchorDirMismatch`); a line naming a pruned
/// seq is judged against the `prune_log` row whose range covers it
/// (`AnchoredRecordPrunedEarly`); a `Prune` line must match a `prune_log` row; a header must
/// open its file and name its chain. Every finding is a line contradicting the store (or an
/// invalid store `chain_id`); the load problems in `lines.problems` are not repeated.
pub(crate) fn check(
    lines: &AnchorDirLines,
    ctx: &VerifyCtx<'_>,
) -> rusqlite::Result<Vec<VerifyFinding>> {
    let mut out = Vec::new();
    if lines.invalid_chain_ids > 0 {
        out.push(problem(format!(
            "{} chain_id(s) of the store are not valid ids; their anchor files were not read",
            lines.invalid_chain_ids
        )));
    }
    for (chain, file) in &lines.chains {
        let name = file_name(chain);
        // `Record` lines without `clock_behind`: the witnesses of the clock_behind rule.
        let unflagged: BTreeSet<u64> = file
            .iter()
            .filter_map(|(_, l)| match l {
                AnchorLine::Record {
                    seq,
                    clock_behind: false,
                    ..
                } => Some(*seq),
                _ => None,
            })
            .collect();
        // An unreadable line 1 is already a load problem.
        if let Some((1, l)) = file.first()
            && !matches!(l, AnchorLine::Header { .. })
        {
            out.push(problem(format!("{name} does not start with a header line")));
        }
        for (i, (n, l)) in file.iter().enumerate() {
            let at = |what: &str| format!("{name} line {n}: {what}");
            match l {
                // The first line read: line 1, or the header after a torn first line (which
                // `parse_file` tolerates only before a header naming this chain) or after an
                // unreadable one (already a load problem).
                AnchorLine::Header { chain_id, .. } => {
                    if i != 0 {
                        out.push(problem(at("a header line after line 1")));
                    } else if chain_id != chain {
                        out.push(problem(at("the header names another chain")));
                    }
                }
                AnchorLine::Prune {
                    first_retained_seq,
                    first_retained_prev_hash,
                    cutoff_epoch,
                } => {
                    let found = ctx.prune_log.iter().any(|r| {
                        r.first_retained_seq == *first_retained_seq
                            && ct_eq(&r.last_pruned, first_retained_prev_hash)
                            && r.cutoff_epoch == *cutoff_epoch
                    });
                    if !found {
                        out.push(
                            problem(at("the prune line matches no prune_log row")).expected(
                                Some(*first_retained_seq),
                                Some(*first_retained_prev_hash),
                            ),
                        );
                    }
                }
                _ => {
                    let Some(nl) = named(l) else { continue };
                    if nl.seq >= ctx.first_retained_seq {
                        check_retained(ctx, chain, l, &nl, &at, &mut out)?;
                    } else {
                        check_pruned(ctx, l, &nl, &unflagged, &at, &mut out)?;
                    }
                }
            }
        }
    }
    Ok(out)
}

/// A line naming a retained seq: the record exists, is of this chain, and has the line's
/// `record_hash`, `epoch`, `clock_behind` flag and (immediate lines) `event_type`.
fn check_retained(
    ctx: &VerifyCtx<'_>,
    chain: &str,
    l: &AnchorLine,
    nl: &Named<'_>,
    at: &dyn Fn(&str) -> String,
    out: &mut Vec<VerifyFinding>,
) -> rusqlite::Result<()> {
    let mismatch = |what: &str, observed: Option<[u8; 32]>| {
        problem(at(what))
            .expected(Some(nl.seq), Some(*nl.record_hash))
            .observed(Some(nl.seq), observed)
    };
    let lost = ctx.lost.iter().any(|s| s.covers(chain, nl.seq));
    let Some(r) = row(ctx.conn, nl.seq)? else {
        if lost {
            return Ok(());
        }
        out.push(if ctx.head.is_none_or(|h| nl.seq > h) {
            mismatch("the anchored seq is beyond the store's head", None)
        } else {
            mismatch("the anchored record is missing", None)
        });
        return Ok(());
    };
    let observed = r.record_hash;
    if r.chain_id.as_deref() != Some(chain) {
        if lost {
            return Ok(());
        }
        out.push(mismatch(
            "the anchored record belongs to another chain",
            observed,
        ));
    } else if !observed.is_some_and(|h| ct_eq(&h, nl.record_hash)) {
        out.push(mismatch(
            "the anchored record has another record_hash",
            observed,
        ));
    } else if r.epoch.as_ref() != Some(nl.epoch) {
        out.push(mismatch("the anchored record has another epoch", observed));
    } else {
        let behind = r
            .flags
            .map(|f| EventFlags::from_bits(f).contains(EventFlags::BEHIND));
        match l {
            AnchorLine::Record { clock_behind, .. } if behind != Some(*clock_behind) => {
                out.push(mismatch(
                    "the anchored record's clock_behind flag differs",
                    observed,
                ));
            }
            AnchorLine::Immediate { event_type, .. }
                if r.event_type.as_deref() != Some(event_type.as_str()) =>
            {
                out.push(mismatch(
                    "the anchored record has another event_type",
                    observed,
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// A line naming a pruned seq, judged by the §8.8 rule the prune that removed it had to obey:
/// its effective epoch older than the cutoff of the `prune_log` row whose range covers it, and
/// (for a `clock_behind` record, whose own `ts_utc` never counts) the first later unflagged
/// record dated before that cutoff.
///
/// - A non-NULL `epoch` is the record's effective epoch (L36): `epoch >= cutoff` is early.
/// - `clock_behind: true`: the first later unflagged record is located by the first later
///   `Record` line without `clock_behind` in the same file (plan decision: M10's writer must
///   write one for the first unflagged record after a flagged one, else an unanchored
///   unflagged record between them could make a lawful prune look early). If that record is
///   pruned too, there is no
///   judgement ("while that record is retained", §8.7); if it is retained and its
///   `date(ts_utc)` is not older than the cutoff, the prune was early. No such line: no
///   judgement.
/// - `epoch: null` (L36): the effective epoch is not known from the line, so the epoch rule
///   does not apply (a `clock_behind` line is still judged by its witness).
fn check_pruned(
    ctx: &VerifyCtx<'_>,
    l: &AnchorLine,
    nl: &Named<'_>,
    unflagged: &BTreeSet<u64>,
    at: &dyn Fn(&str) -> String,
    out: &mut Vec<VerifyFinding>,
) -> rusqlite::Result<()> {
    let early = |what: String| {
        VerifyFinding::new(FindingKind::AnchoredRecordPrunedEarly, at(&what))
            .expected(Some(nl.seq), Some(*nl.record_hash))
    };
    let Some(cover) = ctx
        .prune_log
        .iter()
        .find(|r| r.range_start <= nl.seq && nl.seq < r.first_retained_seq)
    else {
        out.push(
            problem(at(
                "the anchored record was removed without a covering prune_log row",
            ))
            .expected(Some(nl.seq), Some(*nl.record_hash)),
        );
        return Ok(());
    };
    let Some(cutoff) = parse_epoch(&cover.cutoff_epoch) else {
        out.push(early(format!(
            "the cutoff of the prune at seq {} is unreadable",
            cover.prune_seq
        )));
        return Ok(());
    };
    if let Some(e) = nl.epoch.as_deref().and_then(parse_epoch)
        && e >= cutoff
    {
        out.push(early(format!(
            "pruned by the prune at seq {} with cutoff {cutoff} although its epoch {e} was \
             inside retention",
            cover.prune_seq
        )));
        return Ok(());
    }
    if let AnchorLine::Record {
        clock_behind: true, ..
    } = l
        && let Some(w) = unflagged.range(nl.seq + 1..).next().copied()
        && w >= ctx.first_retained_seq
        && let Some(d) = row(ctx.conn, w)?.and_then(|r| ts_date(r.ts_utc.as_deref()))
        && d >= cutoff
    {
        out.push(early(format!(
            "clock_behind record pruned by the prune at seq {} with cutoff {cutoff} although \
             the first later unflagged record (seq {w}) is dated {d}",
            cover.prune_seq
        )));
    }
    Ok(())
}

fn ts_date(ts: Option<&str>) -> Option<NaiveDate> {
    ts.and_then(UtcInstant::parse_rfc3339_ms)
        .map(UtcInstant::date)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(a: &str, b: &str) -> bool {
        same_dir(Some(Path::new(a)), Some(Path::new(b)))
    }

    #[test]
    fn same_dir_ignores_trailing_separators_and_windows_case() {
        assert!(same("/srv/anchors", "/srv/anchors/"));
        assert!(same("/srv/anchors//", "/srv/anchors"));
        assert!(!same("/srv/anchors", "/srv/anchors2"));
        assert!(same("/", "/"));
        assert!(same_dir(None, None));
        assert!(!same_dir(Some(Path::new("/srv/anchors")), None));
        assert_eq!(same(r"C:\Anchors", r"c:\anchors\"), cfg!(windows));
        assert_eq!(same("/srv/Anchors", "/srv/anchors"), cfg!(windows));
        assert_eq!(same(r"C:\Anchors", "C:/Anchors"), cfg!(windows));
    }

    const CHAIN: &str = "0123456789abcdef0123456789abcdef";
    const OWN: &str = "ffffffffffffffffffffffffffffffff";

    /// A chain file of host `h` and user `u`: the header, then `Record` lines for seqs 1..=n.
    fn chain_text(n: u64) -> String {
        let mut s = to_line(&AnchorLine::Header {
            chain_id: CHAIN.into(),
            install_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            host: "h".into(),
            os_user: "u".into(),
            created_at: "2026-10-01T00:00:00.000Z".into(),
        });
        s.push('\n');
        for seq in 1..=n {
            s += &to_line(&AnchorLine::Record {
                seq,
                record_hash: [seq as u8; 32],
                epoch: Some("2026-10-01".into()),
                clock_behind: false,
            });
            s.push('\n');
        }
        s
    }

    #[test]
    fn oversized_chain_file_names_its_real_last_line_and_witnesses_nothing() {
        let dir = tempfile::tempdir().expect("dir");
        let text = chain_text(40);
        // Created the way the writer creates one (this module asks for no plain write).
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(dir.path().join(file_name(CHAIN)))
            .expect("chain file");
        std::io::Write::write_all(&mut file, text.as_bytes()).expect("lines");
        drop(file);
        let read =
            |max| previous_chains_with(dir.path(), "h", "u", OWN, Some(CHAIN), max).expect("read");

        let whole = read(MAX_FILE_BYTES);
        assert_eq!(whole.len(), 1);
        assert_eq!(whole[0].last.as_ref().map(|l| l.0), Some(40));
        assert_eq!(whole[0].witness.as_ref().map(|w| w.named.len()), Some(40));

        // Beyond the bound only a prefix is parsed: still this user's chain, never a witness,
        // and its last anchored line is the file's real last one, not the prefix's.
        let part = read(text.len() as u64 / 3);
        assert_eq!(part.len(), 1, "attributed by its header");
        assert_eq!(part[0].witness, None);
        assert_eq!(
            part[0].last.as_ref().map(|l| (l.0, l.1)),
            Some((40, [40; 32]))
        );
    }
}
