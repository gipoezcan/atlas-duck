//! Export verification (§8.10 `verify-export`, §8.11, §12.1; PD-162, PD-163, L187): checks an
//! export directory written by `Store::export` against the trust roots its recipient supplies.
//! It reads that directory and the anchor dir only, through [`FsRead`], and nothing else: no
//! store, no keychain, no data key, no webview. Payloads are checked from `payload_b64` alone and
//! every `record_hash` is recomputed from the line's columns, so the verifier never needs a key.
//!
//! **Steps.** (1) `manifest.json` (at most [`MAX_EXPORT_MANIFEST_BYTES`], JCS, depth at most
//! [`MAX_JSON_DEPTH`]): its SHA-256 against `--manifest-sha256` before anything else, then its
//! claims. (2) The anchor dir, when given: `<chain_id>.jsonl` of the manifest's `chain_ids` (ids
//! only ever become file names), plus every other chain file whose header names the manifest's
//! `install` (fork candidates); of the rest only the header is read; more than
//! [`MAX_ANCHOR_FILES`] `*.jsonl` names is refused. Lines are parsed by `anchor_dir::parse_file`
//! (the torn-line rule of PD-165 included); only lines naming seqs in `[first_seq - 1, last_seq]`
//! are kept. (3) `prune_log.jsonl` (at most [`MAX_PRUNE_LOG_BYTES`] and [`MAX_PRUNE_LOG_ROWS`]):
//! the row-hash chain and contiguity (`check_prune_log`), and the anchor dir's `Prune` lines.
//! (4) `events.jsonl`, one pass, one line at a time (at most [`MAX_EXPORT_LINE_BYTES`]): the
//! strict column set, `record_hash` and the chain from `boundary_prev_hash`, `payload_len` and
//! `payload_sha256` of `payload_b64`, `payload` byte for byte against the plaintext (absent only
//! where the exporter writes none, `export::payload_field_shown`), the `unanchored` marks against
//! the manifest, `request_set_hash` of each
//! `WRITE_APPROVED`, the `RESTORE` boundaries (§8.11), each `PRUNE` against its `prune_log` row and
//! its settings snapshot (the store's parser), and the range-aware anchor comparison (a line naming
//! a row must match it; lines outside the range are skipped; the line at `first_seq - 1` must name
//! `boundary_prev_hash`). Every file is opened once and hashed as it is read, so the bytes judged
//! are the bytes hashed; reading goes on to the end of a file after a bad line.
//!
//! `prune_log.jsonl` is read by the exporter after the events (T7 review M-1), so it may hold
//! prunes committed during or after the export: rows with a `prune_seq` beyond `last_seq` never
//! judge an exported row, and the export's `first_seq` is not compared with any
//! `first_retained_seq`. A `Prune` line that matches no row is a contradiction only when its prune
//! cannot postdate the export (its `PRUNE` at or before `last_seq`, or older than the newest row).
//!
//! **Verdicts** (PD-162 step 5, PD-163), the first that applies: the manifest is not the one
//! `--manifest-sha256` names → 21; a file differs from what a verified manifest names → 21; an
//! anchor line contradicts a row → 21 (`FORK` when it is a fork, §8.11); the input cannot be read
//! as an export (a missing or unreadable file, a `.partial` directory, a bound exceeded, a line
//! that is not an export line, a record `format_version` or a settings-snapshot key of another
//! version) → 22; the export contradicts itself → 21; then the manifest hash
//! binds the whole export → 0; the anchor dir alone binds the rows up to its last in-range
//! anchored row `L`, so 0 only when `L` is the last row, else 20; neither → 20 ("internally
//! consistent; trust root NOT verified", §8.10). Both trust roots given: both must hold, and the
//! last line names the anchor dir only when one of its lines names a row of the export. Entries
//! of the export directory beside its three files are named in the report, never verified.
//!
//! **Bounds.** No total cap on `events.jsonl` (streamed). Column by column: hashes, nonce, ids,
//! integers (at most 2^53 − 1) and the two base64 columns (at most their decoded bounds,
//! [`MAX_EXPORT_CT_LEN`] and `MAX_PAYLOAD_LEN`) have exact limits; the other columns (`target`,
//! `agent_name`, the hex OS paths `peer_exe`/`peer_origin_exe`, …) have no bound of their own in
//! the store, so only the line bound limits them, which never refuses a line the exporter wrote
//! (T7 lead ruling 3). Parsed plaintexts (`WRITE_APPROVED`, `RESTORE`, `PRUNE`) and the manifest
//! are checked for depth first; a `PRUNE` payload is parsed into a value tree only up to 1 MiB.
//!
//! **Working set.** One line buffer (at most [`MAX_EXPORT_LINE_BYTES`], about 258 MiB). The hex
//! and base64 columns are borrowed from it; `payload_ct` and `payload_b64` are decoded in 48 KiB
//! pieces straight into the hashes. What is copied out of the line is never longer than the part
//! of the line it comes from: the text columns, the decoded OS paths and the plaintext, which is
//! held whole only when a check parses it or it is at most `MAX_EXPORT_PAYLOAD_FIELD_BYTES` (the
//! `payload` check), and what that check parses out of it. A JSON string with an escape costs
//! serde_json a scratch copy of the decoded text, which `Vec` doubling may make twice its length,
//! before the owned copy (T8 review I-2): a text column, or a string in a parsed plaintext, as
//! long as the line costs the line again three times. So a row needs at most
//! 4 × `MAX_EXPORT_LINE_BYTES`, plus one value tree of a JSON text of at most 1 MiB (a `PRUNE`'s
//! settings snapshot, or the JCS check of a plaintext whose line has no `payload`; at most 32
//! bytes per byte of text, so 32 MiB), plus fixed buffers (under 128 KiB). Measured: an escaped
//! text column as long as the line 4.0 × the line; the largest honest row (a 96 MiB plaintext)
//! about 244 MB, one line. Besides: the anchor map (the in-range lines of the files read, each file
//! at most `anchor_dir::MAX_FILE_BYTES` while it is parsed) and the `prune_log` rows. A growing
//! buffer may be copied once by the allocator, and the buffers are zeroized on drop but not their
//! earlier copies (nor serde_json's scratch). No allocation is sized by a number the input claims.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use atlas_duck_ipc::jcs::{MAX_SAFE_INTEGER, to_jcs_vec};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::Days;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::anchor_dir::{self, AnchorLine, LostSpan};
use crate::clock::parse_epoch;
use crate::crypto::{MAX_PAYLOAD_LEN, ct_eq};
use crate::encoding::{FORMAT_VERSION, Field, RecordHasher, RowFields, ZERO_HASH, hash_frame};
use crate::export::{
    EVENTS_FILE, EXPORT_FORMAT, MANIFEST_FILE, MAX_EXPORT_CT_LEN, MAX_EXPORT_LINE_BYTES,
    MAX_EXPORT_MANIFEST_BYTES, MAX_EXPORT_PAYLOAD_FIELD_BYTES, PARTIAL_SUFFIX, PRUNE_LOG_FILE,
    payload_field_shown,
};
use crate::open::is_id;
use crate::request_set::REQUEST_SET_DOMAIN;
use crate::settings::{Settings, snapshot_has_unknown_key};
use crate::types::{EventFlags, EventType, ExportVerdict};
use crate::verify::{Findings, PruneLogRow, check_prune_log, hex32};

/// `prune_log.jsonl` is at most this long (PD-162).
pub const MAX_PRUNE_LOG_BYTES: u64 = 64 * 1024 * 1024;

/// `prune_log.jsonl` holds at most this many rows (PD-162).
pub const MAX_PRUNE_LOG_ROWS: usize = 1_000_000;

/// A `prune_log.jsonl` line: seven short columns (an honest line is about 330 bytes).
pub const MAX_PRUNE_LOG_LINE_BYTES: u64 = 4096;

/// Arrays and objects nest at most this deep in any JSON the verifier parses (PD-162).
pub const MAX_JSON_DEPTH: usize = 64;

/// `*.jsonl` names in the anchor dir (the bound of a first run, PD-167).
pub const MAX_ANCHOR_FILES: usize = anchor_dir::MAX_FIRST_RUN_CHAIN_FILES;

/// A `PRUNE` payload is parsed into a value tree (for its settings snapshot) only up to this
/// size; an honest one is a few hundred bytes.
const MAX_TREE_PLAINTEXT: usize = 1024 * 1024;

/// Base64 decoded in pieces of this many characters (a multiple of 4).
const B64_CHUNK: usize = 64 * 1024;

/// Chain ids named in the report's first line.
const MAX_CHAINS_SHOWN: usize = 8;

/// `payload_ct`'s position in `FIELD_LIST`.
const PAYLOAD_CT_FRAME: usize = 27;

const MANIFEST_OK: &str = "verified against the manifest SHA-256";
const ANCHOR_OK: &str = "verified against the anchor dir";
const BOTH_OK: &str = "verified against the manifest SHA-256 and the anchor dir";
/// §8.10 verbatim.
const NO_ROOT: &str = "internally consistent; trust root NOT verified";

// ---------------------------------------------------------------------------------------
// File access

/// Every file system access of the verifier (a seam: a test records the paths).
pub trait FsRead {
    /// Metadata, following links (the directories given).
    fn metadata(&self, path: &Path) -> io::Result<Metadata>;
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf>;
    /// Calls `each` with every entry name of the directory until it returns `false`.
    fn read_dir(&self, path: &Path, each: &mut dyn FnMut(OsString) -> bool) -> io::Result<()>;
    /// Opens for reading without following a link in the last component (on Unix also without
    /// blocking on a FIFO); the caller checks what the handle names.
    fn open(&self, path: &Path) -> io::Result<File>;
}

/// The real file system.
pub struct OsFs;

impl FsRead for OsFs {
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        std::fs::metadata(path)
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::canonicalize(path)
    }

    fn read_dir(&self, path: &Path, each: &mut dyn FnMut(OsString) -> bool) -> io::Result<()> {
        for e in std::fs::read_dir(path)? {
            if !each(e?.file_name()) {
                break;
            }
        }
        Ok(())
    }

    fn open(&self, path: &Path) -> io::Result<File> {
        let mut o = std::fs::OpenOptions::new();
        o.read(true);
        // A link is opened as itself (Unix refuses it with ELOOP), so the handle check of
        // `open_regular` sees it: no window between a path check and the open (T8 review M-4).
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            o.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
        }
        o.open(path)
    }
}

/// The bounds the verifier enforces (the defaults are the PD-159/PD-162 constants; tests lower
/// them to reach the over-long paths with small inputs).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// An `events.jsonl` line, without its newline.
    pub line: u64,
    pub manifest: u64,
    pub prune_log: u64,
    pub prune_log_rows: usize,
    pub prune_log_line: u64,
    /// One anchor-dir chain file.
    pub anchor_file: u64,
    /// `*.jsonl` names in the anchor dir.
    pub anchor_files: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            line: MAX_EXPORT_LINE_BYTES,
            manifest: MAX_EXPORT_MANIFEST_BYTES,
            prune_log: MAX_PRUNE_LOG_BYTES,
            prune_log_rows: MAX_PRUNE_LOG_ROWS,
            prune_log_line: MAX_PRUNE_LOG_LINE_BYTES,
            anchor_file: anchor_dir::MAX_FILE_BYTES,
            anchor_files: MAX_ANCHOR_FILES,
        }
    }
}

/// Verifies the export in `dir` (C.3, §12.1): against the anchor dir and the manifest hash when
/// given. Read-only; the report is in the verdict.
pub fn verify_export(
    dir: &Path,
    anchor_dir: Option<&Path>,
    manifest_sha256: Option<[u8; 32]>,
) -> ExportVerdict {
    run(&OsFs, &Limits::default(), dir, anchor_dir, manifest_sha256)
}

/// [`verify_export`] through another file access and with other bounds (tests).
#[cfg(any(test, feature = "testing"))]
pub fn verify_export_with(
    fs: &dyn FsRead,
    limits: Limits,
    dir: &Path,
    anchor_dir: Option<&Path>,
    manifest_sha256: Option<[u8; 32]>,
) -> ExportVerdict {
    run(fs, &limits, dir, anchor_dir, manifest_sha256)
}

/// The input cannot be read as an export (exit 22). Fixed text, file names and numbers only.
struct Unreadable(String);

fn unreadable(why: impl Into<String>) -> Unreadable {
    Unreadable(why.into())
}

fn kind(e: &io::Error) -> String {
    format!("{:?}", e.kind())
}

/// Opens a file of the export or the anchor dir: a regular file, never a link, judged on the
/// open handle (a link is opened as itself, [`FsRead::open`]). On Windows only name-surrogate
/// reparse points (symbolic links, junctions) are links: a cloud-file placeholder (OneDrive) is
/// a reparse point too and stays a regular file. `Ok(None)`: it does not exist.
fn open_regular(fs: &dyn FsRead, path: &Path) -> Result<Option<File>, String> {
    let not_regular = || "is not a regular file".to_string();
    let f = match fs.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(not_regular()),
        Err(e) => return Err(format!("cannot be read ({})", kind(&e))),
    };
    match f.metadata() {
        Ok(m) if m.is_file() && !m.file_type().is_symlink() => Ok(Some(f)),
        _ => Err(not_regular()),
    }
}

/// The whole file, at most `cap` bytes; `Ok(None)` when it does not exist.
fn read_capped(fs: &dyn FsRead, path: &Path, cap: u64) -> Result<Option<Vec<u8>>, String> {
    let Some(f) = open_regular(fs, path)? else {
        return Ok(None);
    };
    read_rest(f, Vec::new(), cap).map(Some)
}

/// `head` (already read from `f`) and the rest of `f`, at most `cap` bytes in all.
fn read_rest(f: File, mut bytes: Vec<u8>, cap: u64) -> Result<Vec<u8>, String> {
    let too_long = || format!("is longer than {cap} bytes");
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len > cap {
        return Err(too_long());
    }
    bytes.reserve_exact(
        usize::try_from(len)
            .unwrap_or(0)
            .saturating_sub(bytes.len()),
    );
    let room = cap.saturating_add(1).saturating_sub(bytes.len() as u64);
    f.take(room)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot be read ({})", kind(&e)))?;
    if bytes.len() as u64 > cap {
        return Err(too_long());
    }
    Ok(bytes)
}

/// One file read once, line by line, hashed as it is read.
struct LineReader {
    r: BufReader<File>,
    hash: Sha256,
    /// The current line without its newline (it may hold plaintext: zeroized on drop).
    buf: Zeroizing<Vec<u8>>,
    cap: usize,
    /// Bytes read so far.
    read: u64,
}

enum Next {
    /// A line ended by `\n` is in `buf`.
    Line,
    /// The file ends inside a line (in `buf`).
    Unterminated,
    /// A line longer than the bound (`buf` holds a prefix).
    TooLong,
    Eof,
}

impl LineReader {
    fn new(f: File, cap: u64) -> LineReader {
        LineReader {
            r: BufReader::new(f),
            hash: Sha256::new(),
            buf: Zeroizing::new(Vec::new()),
            cap: usize::try_from(cap).unwrap_or(usize::MAX),
            read: 0,
        }
    }

    fn next(&mut self) -> io::Result<Next> {
        self.buf.clear();
        let (mut any, mut too_long) = (false, false);
        loop {
            let avail = self.r.fill_buf()?;
            if avail.is_empty() {
                return Ok(match (any, too_long) {
                    (false, _) => Next::Eof,
                    (true, true) => Next::TooLong,
                    (true, false) => Next::Unterminated,
                });
            }
            any = true;
            let (part, done) = match avail.iter().position(|b| *b == b'\n') {
                Some(i) => (i, true),
                None => (avail.len(), false),
            };
            let body = avail.get(..part).unwrap_or_default();
            if !too_long {
                if self.buf.len().saturating_add(part) > self.cap {
                    too_long = true;
                } else {
                    grow(&mut self.buf, part, self.cap);
                    self.buf.extend_from_slice(body);
                }
            }
            let used = if done { part + 1 } else { part };
            self.hash.update(avail.get(..used).unwrap_or_default());
            self.read = self.read.saturating_add(used as u64);
            self.r.consume(used);
            if done {
                return Ok(if too_long { Next::TooLong } else { Next::Line });
            }
        }
    }

    /// Reads and hashes the rest of the file.
    fn drain(&mut self) -> io::Result<()> {
        loop {
            let avail = self.r.fill_buf()?;
            let n = avail.len();
            if n == 0 {
                return Ok(());
            }
            self.hash.update(avail);
            self.read = self.read.saturating_add(n as u64);
            self.r.consume(n);
        }
    }

    fn finish(self) -> [u8; 32] {
        self.hash.finalize().into()
    }
}

/// Room for `extra` more bytes: doubling, but never beyond `cap` (a line at the bound must not
/// reserve twice the bound).
fn grow(buf: &mut Vec<u8>, extra: usize, cap: usize) {
    let need = buf.len().saturating_add(extra);
    if need > buf.capacity() {
        let target = need.max(buf.capacity().saturating_mul(2).min(cap));
        buf.reserve_exact(target - buf.len());
    }
}

// ---------------------------------------------------------------------------------------
// JSON helpers

/// Whether the JSON text `b` nests arrays and objects at most `max` deep (strings skipped; text
/// that is not JSON is left to the parser).
pub(crate) fn depth_ok(b: &[u8], max: usize) -> bool {
    let (mut depth, mut in_str, mut esc) = (0usize, false, false);
    for &c in b {
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > max {
                    return false;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

/// The byte range of the value of the top-level key `key` in the object text `b` (a line that
/// already parsed): from after its `:` to the `,` or `}` that ends it.
fn top_level_value(b: &[u8], key: &[u8]) -> Option<(usize, usize)> {
    let (mut depth, mut in_str, mut esc) = (0usize, false, false);
    let (mut expect_key, mut want) = (false, false);
    let mut key_start: Option<usize> = None;
    let mut value: Option<usize> = None;
    for (i, &c) in b.iter().enumerate() {
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
                if let Some(s) = key_start.take() {
                    want = b.get(s + 1..i) == Some(key);
                }
            }
            continue;
        }
        match c {
            b'"' => {
                in_str = true;
                if depth == 1 && expect_key {
                    key_start = Some(i);
                    expect_key = false;
                }
            }
            b'{' | b'[' => {
                depth += 1;
                if depth == 1 {
                    expect_key = true;
                }
            }
            b'}' | b']' => {
                if depth == 1
                    && let Some(s) = value.take()
                {
                    return Some((s, i));
                }
                depth = depth.saturating_sub(1);
            }
            b',' if depth == 1 => {
                if let Some(s) = value.take() {
                    return Some((s, i));
                }
                expect_key = true;
            }
            b':' if depth == 1 && want => {
                value = Some(i + 1);
                want = false;
            }
            _ => {}
        }
    }
    None
}

/// A key that must be present, its value possibly `null`.
fn nullable<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

/// `unanchored` is written only as `true`.
fn only_true<'de, D: Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    match bool::deserialize(d)? {
        true => Ok(Some(true)),
        false => Err(de::Error::custom("unanchored is only ever true")),
    }
}

/// A key that may be absent; when present its value (possibly `null`) is kept as given.
fn present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

/// One `events.jsonl` line (PD-159): the 29 columns (every key present), `payload_b64`, and the
/// optional `payload` and `unanchored`. Unknown and duplicate keys are refused. The hex and
/// base64 columns are borrowed from the line (their text never needs an escape; one that has
/// one is no export line), so the line's largest columns are never copied.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportLine<'a> {
    seq: u64,
    format_version: u64,
    chain_id: String,
    ts_utc: String,
    #[serde(deserialize_with = "nullable")]
    epoch: Option<String>,
    #[serde(deserialize_with = "nullable")]
    request_id: Option<String>,
    event_type: String,
    #[serde(deserialize_with = "nullable")]
    op_id: Option<String>,
    #[serde(deserialize_with = "nullable")]
    op_class: Option<String>,
    #[serde(deserialize_with = "nullable")]
    instance_id: Option<String>,
    #[serde(deserialize_with = "nullable")]
    target: Option<String>,
    #[serde(deserialize_with = "nullable")]
    agent_name: Option<String>,
    #[serde(deserialize_with = "nullable")]
    agent_name_source: Option<String>,
    #[serde(deserialize_with = "nullable")]
    client_kind: Option<String>,
    #[serde(deserialize_with = "nullable")]
    connection_id: Option<String>,
    #[serde(deserialize_with = "nullable")]
    peer_pid: Option<u64>,
    #[serde(borrow, deserialize_with = "nullable")]
    peer_exe: Option<&'a str>,
    #[serde(borrow, deserialize_with = "nullable")]
    peer_origin_exe: Option<&'a str>,
    #[serde(deserialize_with = "nullable")]
    os_user: Option<String>,
    #[serde(deserialize_with = "nullable")]
    atlassian_user: Option<String>,
    #[serde(deserialize_with = "nullable")]
    atlassian_user_key: Option<String>,
    #[serde(deserialize_with = "nullable")]
    decision: Option<String>,
    flags: u64,
    payload_len: u64,
    payload_sha256: &'a str,
    key_id: u64,
    nonce: &'a str,
    payload_ct: &'a str,
    prev_hash: &'a str,
    payload_b64: &'a str,
    #[serde(default)]
    payload: Option<IgnoredAny>,
    #[serde(default, deserialize_with = "only_true")]
    unanchored: Option<bool>,
}

fn safe(n: u64) -> bool {
    n <= MAX_SAFE_INTEGER as u64
}

const fn base64_len(n: u64) -> u64 {
    n.div_ceil(3) * 4
}

/// The decoded length of padded base64 text of a valid length.
fn b64_decoded_len(b64: &[u8]) -> u64 {
    let pad = b64.iter().rev().take(2).filter(|c| **c == b'=').count();
    (b64.len() as u64 / 4) * 3 - pad as u64
}

/// Decodes padded standard base64 in pieces into `sink`; `false` when it is not canonical
/// base64 (padding only at the very end).
fn b64_pieces(b64: &[u8], sink: &mut dyn FnMut(&[u8])) -> bool {
    if !b64.len().is_multiple_of(4) {
        return false;
    }
    let mut out = Zeroizing::new(vec![0u8; B64_CHUNK / 4 * 3]);
    let mut pieces = b64.chunks(B64_CHUNK).peekable();
    while let Some(piece) = pieces.next() {
        if pieces.peek().is_some() && piece.contains(&b'=') {
            return false;
        }
        match STANDARD.decode_slice(piece, &mut out[..]) {
            Ok(n) => sink(out.get(..n).unwrap_or_default()),
            Err(_) => return false,
        }
    }
    true
}

/// Lowercase hex of exactly `N` bytes.
fn hex_n<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.bytes().any(|c| c.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// Lowercase hex of any length.
fn hex_any(s: &str) -> Option<Vec<u8>> {
    if s.bytes().any(|c| c.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(s).ok()
}

// ---------------------------------------------------------------------------------------
// The manifest

struct Manifest {
    first_seq: u64,
    last_seq: u64,
    rows: u64,
    boundary_prev_hash: [u8; 32],
    head_seq: u64,
    head_hash: [u8; 32],
    chain_ids: Vec<String>,
    restore_records: Vec<u64>,
    key_recovered_records: Vec<u64>,
    anchor_dir_configured: bool,
    last_anchored_seq: Option<u64>,
    events_sha256: [u8; 32],
    prune_log_sha256: [u8; 32],
    install_id: String,
    host: String,
    os_user: String,
}

const MANIFEST_KEYS: [&str; 19] = [
    "accountability",
    "anchor_dir_configured",
    "app_version",
    "boundary_prev_hash",
    "build_id",
    "chain_ids",
    "events_sha256",
    "exported_at",
    "first_seq",
    "format",
    "head",
    "install",
    "key_recovered_records",
    "last_anchored_seq",
    "last_seq",
    "prune_log_sha256",
    "requested_range",
    "restore_records",
    "rows",
];

/// Exactly `keys` (no other, none missing).
fn exact_keys<'v>(v: &'v Value, keys: &[&str]) -> Result<&'v Map<String, Value>, &'static str> {
    let o = v.as_object().ok_or("not an object")?;
    if o.len() != keys.len() || !keys.iter().all(|k| o.contains_key(*k)) {
        return Err("its keys are not the export manifest's");
    }
    Ok(o)
}

fn seq_value(v: &Value) -> Option<u64> {
    v.as_u64()
        .filter(|s| (1..=MAX_SAFE_INTEGER as u64).contains(s))
}

fn seq_list(v: &Value) -> Option<Vec<u64>> {
    v.as_array()?.iter().map(seq_value).collect()
}

fn text(v: &Value) -> Option<&str> {
    v.as_str()
}

impl Manifest {
    /// The manifest's shape (22 when wrong); its claims are checked against the files later.
    fn parse(bytes: &[u8]) -> Result<Manifest, &'static str> {
        if !depth_ok(bytes, MAX_JSON_DEPTH) {
            return Err("it nests deeper than 64");
        }
        let v: Value = serde_json::from_slice(bytes).map_err(|_| "it is not JSON")?;
        // JCS, byte for byte: no duplicate key, no other spelling of the same values.
        if to_jcs_vec(&v).ok().as_deref() != Some(bytes) {
            return Err("it is not in canonical (JCS) form");
        }
        let o = exact_keys(&v, &MANIFEST_KEYS)?;
        let get = |k: &str| o.get(k).ok_or("a key is missing");
        if text(get("format")?) != Some(EXPORT_FORMAT) {
            return Err("its format is not atlas-duck-export/1");
        }
        for k in ["app_version", "build_id", "exported_at", "accountability"] {
            text(get(k)?).ok_or("a text field is not text")?;
        }
        let range = exact_keys(get("requested_range")?, &["from_utc", "to_utc"])?;
        if !range.values().all(|v| v.is_string()) {
            return Err("requested_range is malformed");
        }
        let install = exact_keys(get("install")?, &["host", "install_id", "os_user"])?;
        let install_text = |k: &str| {
            install
                .get(k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .ok_or("install is malformed")
        };
        let install_id = install_text("install_id")?;
        if !is_id(&install_id) {
            return Err("install is malformed");
        }
        let head = exact_keys(get("head")?, &["record_hash", "seq"])?;
        let hash = |v: Option<&Value>| v.and_then(Value::as_str).and_then(hex32);
        let seq = |k: &str| get(k).ok().and_then(seq_value).ok_or("a seq is malformed");
        let first_seq = seq("first_seq")?;
        let last_seq = seq("last_seq")?;
        if first_seq > last_seq {
            return Err("first_seq lies after last_seq");
        }
        let chain_ids: Vec<String> = get("chain_ids")?
            .as_array()
            .ok_or("chain_ids is not a list")?
            .iter()
            .map(|c| c.as_str().filter(|c| is_id(c)).map(str::to_owned))
            .collect::<Option<_>>()
            .ok_or("chain_ids holds a value that is not a chain id")?;
        if chain_ids.is_empty() {
            return Err("chain_ids is empty");
        }
        let last_anchored_seq = match get("last_anchored_seq")? {
            Value::Null => None,
            v => Some(seq_value(v).ok_or("last_anchored_seq is malformed")?),
        };
        Ok(Manifest {
            first_seq,
            last_seq,
            rows: get("rows")?
                .as_u64()
                .filter(|n| safe(*n))
                .ok_or("rows is malformed")?,
            boundary_prev_hash: hash(o.get("boundary_prev_hash"))
                .ok_or("boundary_prev_hash is malformed")?,
            head_seq: head
                .get("seq")
                .and_then(seq_value)
                .ok_or("head is malformed")?,
            head_hash: hash(head.get("record_hash")).ok_or("head is malformed")?,
            chain_ids,
            restore_records: seq_list(get("restore_records")?)
                .ok_or("restore_records is malformed")?,
            key_recovered_records: seq_list(get("key_recovered_records")?)
                .ok_or("key_recovered_records is malformed")?,
            anchor_dir_configured: get("anchor_dir_configured")?
                .as_bool()
                .ok_or("anchor_dir_configured is malformed")?,
            last_anchored_seq,
            events_sha256: hash(o.get("events_sha256")).ok_or("events_sha256 is malformed")?,
            prune_log_sha256: hash(o.get("prune_log_sha256"))
                .ok_or("prune_log_sha256 is malformed")?,
            install_id,
            host: install_text("host")?,
            os_user: install_text("os_user")?,
        })
    }

    /// Whether the exporter marked row `seq` `unanchored`.
    fn unanchored(&self, seq: u64) -> bool {
        self.anchor_dir_configured && self.last_anchored_seq.is_none_or(|l| seq > l)
    }
}

// ---------------------------------------------------------------------------------------
// The anchor dir

/// What kind of record line, with what it says beyond `seq`, `record_hash` and `epoch`.
enum Kind {
    Record { clock_behind: bool },
    Immediate(String),
    Detached,
}

/// A line naming a seq in `[first_seq - 1, last_seq]`.
struct Named {
    /// Index into `Anchors::files`.
    file: usize,
    record_hash: [u8; 32],
    epoch: Option<String>,
    kind: Kind,
}

struct ChainFile {
    chain: String,
    /// One of the export's chains (else a fork candidate of the same installation).
    export: bool,
}

/// A `Prune` line of one of the export's chains; `paired`: the seq of the `PRUNE` immediate line
/// right after it (the writer writes the two together).
struct PruneLine {
    first_retained_seq: u64,
    prev_hash: [u8; 32],
    cutoff_epoch: String,
    paired: Option<u64>,
}

struct Anchors {
    files: Vec<ChainFile>,
    by_seq: BTreeMap<u64, Vec<Named>>,
    prunes: Vec<PruneLine>,
}

fn named_line(l: &AnchorLine) -> Option<(u64, [u8; 32], Option<String>, Kind)> {
    match l {
        AnchorLine::Record {
            seq,
            record_hash,
            epoch,
            clock_behind,
        } => Some((
            *seq,
            *record_hash,
            epoch.clone(),
            Kind::Record {
                clock_behind: *clock_behind,
            },
        )),
        AnchorLine::Immediate {
            seq,
            record_hash,
            epoch,
            event_type,
        } => Some((
            *seq,
            *record_hash,
            epoch.clone(),
            Kind::Immediate(event_type.clone()),
        )),
        AnchorLine::Detached {
            seq,
            record_hash,
            epoch,
            ..
        } => Some((*seq, *record_hash, epoch.clone(), Kind::Detached)),
        AnchorLine::Header { .. } | AnchorLine::Prune { .. } => None,
    }
}

fn read_anchor_dir(
    fs: &dyn FsRead,
    lim: &Limits,
    dir: &Path,
    m: &Manifest,
) -> Result<Anchors, Unreadable> {
    match fs.metadata(dir) {
        Ok(md) if md.is_dir() => {}
        Ok(_) => return Err(unreadable("the anchor dir is not a directory")),
        Err(e) => {
            return Err(unreadable(format!(
                "the anchor dir cannot be read ({})",
                kind(&e)
            )));
        }
    }
    let mut jsonl = 0usize;
    let mut ids = BTreeSet::new();
    fs.read_dir(dir, &mut |name| {
        let name = name.to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".jsonl") {
            jsonl += 1;
            if is_id(stem) {
                ids.insert(stem.to_owned());
            }
        }
        jsonl <= lim.anchor_files
    })
    .map_err(|e| unreadable(format!("the anchor dir cannot be listed ({})", kind(&e))))?;
    if jsonl > lim.anchor_files {
        return Err(unreadable(format!(
            "anchor dir has too many files (more than {} *.jsonl)",
            lim.anchor_files
        )));
    }
    let lo = m.first_seq.saturating_sub(1).max(1);
    let mut a = Anchors {
        files: Vec::new(),
        by_seq: BTreeMap::new(),
        prunes: Vec::new(),
    };
    let ours: BTreeSet<&str> = m.chain_ids.iter().map(String::as_str).collect();
    for chain in &ours {
        let name = anchor_dir::file_name(chain);
        let bytes = match read_capped(fs, &dir.join(&name), lim.anchor_file) {
            Ok(None) => continue,
            Ok(Some(b)) if b.is_empty() => {
                return Err(unreadable(format!(
                    "anchor dir: {name} is empty: it has no header line"
                )));
            }
            Ok(Some(b)) => b,
            Err(why) => return Err(unreadable(format!("anchor dir: {name} {why}"))),
        };
        let (mut problems, mut notes) = (Vec::new(), Vec::new());
        let lines = anchor_dir::parse_file(&name, chain, &bytes, &mut problems, &mut notes);
        drop(bytes);
        if let Some(p) = problems.first() {
            return Err(unreadable(format!("anchor dir: {}", p.detail)));
        }
        match lines.first() {
            Some((_, AnchorLine::Header { chain_id, .. })) if chain_id.as_str() == *chain => {}
            _ => {
                return Err(unreadable(format!(
                    "anchor dir: {name} does not start with its header line"
                )));
            }
        }
        if lines
            .iter()
            .skip(1)
            .any(|(_, l)| matches!(l, AnchorLine::Header { .. }))
        {
            return Err(unreadable(format!(
                "anchor dir: {name} has a header line after line 1"
            )));
        }
        let file = a.files.len();
        a.files.push(ChainFile {
            chain: (*chain).to_owned(),
            export: true,
        });
        for (i, (_, l)) in lines.iter().enumerate() {
            if let AnchorLine::Prune {
                first_retained_seq,
                first_retained_prev_hash,
                cutoff_epoch,
            } = l
            {
                let paired = match lines.get(i + 1) {
                    Some((
                        _,
                        AnchorLine::Immediate {
                            seq, event_type, ..
                        },
                    )) if event_type == EventType::PRUNE.as_str() => Some(*seq),
                    _ => None,
                };
                a.prunes.push(PruneLine {
                    first_retained_seq: *first_retained_seq,
                    prev_hash: *first_retained_prev_hash,
                    cutoff_epoch: cutoff_epoch.clone(),
                    paired,
                });
            }
        }
        keep_in_range(&mut a, file, &lines, lo, m.last_seq);
    }
    // Fork candidates (PD-163 (b)): other chains whose header names this installation. A file
    // that cannot be read or is not one is no candidate.
    for chain in ids.iter().filter(|c| !ours.contains(c.as_str())) {
        let name = anchor_dir::file_name(chain);
        let path = dir.join(&name);
        let Ok(Some(mut f)) = open_regular(fs, &path) else {
            continue;
        };
        let mut head = Vec::new();
        let probe = anchor_dir::HEADER_PROBE_BYTES;
        if (&mut f).take(probe).read_to_end(&mut head).is_err() {
            continue;
        }
        let probed = if (head.len() as u64) < probe {
            &head[..]
        } else {
            anchor_dir::complete_lines(&head)
        };
        let (mut problems, mut notes) = (Vec::new(), Vec::new());
        let same = matches!(
            anchor_dir::parse_file(&name, chain, probed, &mut problems, &mut notes).first(),
            Some((_, AnchorLine::Header { install_id, host, os_user, .. }))
                if *install_id == m.install_id && *host == m.host && *os_user == m.os_user
        );
        if !same {
            continue;
        }
        // The rest from the same handle: the header judged is the file's.
        let Ok(bytes) = read_rest(f, head, lim.anchor_file) else {
            continue;
        };
        let (mut problems, mut notes) = (Vec::new(), Vec::new());
        let lines = anchor_dir::parse_file(&name, chain, &bytes, &mut problems, &mut notes);
        let file = a.files.len();
        a.files.push(ChainFile {
            chain: chain.clone(),
            export: false,
        });
        keep_in_range(&mut a, file, &lines, lo, m.last_seq);
    }
    Ok(a)
}

fn keep_in_range(a: &mut Anchors, file: usize, lines: &[(usize, AnchorLine)], lo: u64, hi: u64) {
    for (_, l) in lines {
        if let Some((seq, record_hash, epoch, kind)) = named_line(l)
            && (lo..=hi).contains(&seq)
        {
            a.by_seq.entry(seq).or_default().push(Named {
                file,
                record_hash,
                epoch,
                kind,
            });
        }
    }
}

// ---------------------------------------------------------------------------------------
// Payload checks

/// `{"requests": [...], "request_set_hash": "..."}`: the claimed hash and the record count.
struct Counted(u64);

impl<'de> Deserialize<'de> for Counted {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Counted, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Counted;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a list")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Counted, A::Error> {
                let mut n = 0u64;
                while s.next_element::<IgnoredAny>()?.is_some() {
                    n += 1;
                }
                Ok(Counted(n))
            }
        }
        d.deserialize_seq(V)
    }
}

#[derive(Deserialize)]
struct ApprovedCount {
    request_set_hash: String,
    requests: Counted,
}

/// One record of `requests` (F.8): exactly the five keys, `content_type` explicit; `body_b64`
/// borrowed from the plaintext (base64 never needs an escape).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestJson<'a> {
    index: u32,
    method: String,
    url: String,
    #[serde(deserialize_with = "nullable")]
    content_type: Option<String>,
    body_b64: &'a str,
}

/// Hashes the records of `requests` one by one (F.8 frames), never holding them all.
struct HashRequests<'h>(&'h mut Sha256);

impl<'de> DeserializeSeed<'de> for HashRequests<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for HashRequests<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of requests")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<(), A::Error> {
        while let Some(r) = s.next_element::<RequestJson<'de>>()? {
            let body = Zeroizing::new(
                STANDARD
                    .decode(r.body_b64)
                    .map_err(|_| de::Error::custom("body_b64 is not padded base64"))?,
            );
            for f in [
                Field::Int(u64::from(r.index)),
                Field::Bytes(r.method.as_bytes()),
                Field::Bytes(r.url.as_bytes()),
                r.content_type
                    .as_deref()
                    .map_or(Field::Null, |c| Field::Bytes(c.as_bytes())),
                Field::Bytes(&body),
            ] {
                hash_frame(self.0, &f);
            }
        }
        Ok(())
    }
}

/// The payload object, feeding `requests` to [`HashRequests`] and skipping the rest.
struct HashApproved<'h>(&'h mut Sha256);

impl<'de> DeserializeSeed<'de> for HashApproved<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for HashApproved<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a WRITE_APPROVED payload")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<(), A::Error> {
        while let Some(k) = m.next_key::<String>()? {
            if k == "requests" {
                m.next_value_seed(HashRequests(&mut *self.0))?;
            } else {
                m.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

/// A `WRITE_APPROVED` plaintext's `request_set_hash` against its `requests` (§8.10), computed as
/// `request_set_hash` (F.8) does but record by record: one pass counts them (the count comes
/// first in the hash), the next hashes them. `false` when either is unreadable, as in the full
/// verification.
fn request_set_ok(plain: &[u8]) -> bool {
    if !depth_ok(plain, MAX_JSON_DEPTH) {
        return false;
    }
    let Ok(c) = serde_json::from_slice::<ApprovedCount>(plain) else {
        return false;
    };
    let Some(claimed) = hex32(&c.request_set_hash) else {
        return false;
    };
    let mut h = Sha256::new();
    h.update(REQUEST_SET_DOMAIN);
    h.update(
        u32::try_from(c.requests.0)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    let mut d = serde_json::Deserializer::from_slice(plain);
    if HashApproved(&mut h).deserialize(&mut d).is_err() || d.end().is_err() {
        return false;
    }
    let got: [u8; 32] = h.finalize().into();
    ct_eq(&got, &claimed)
}

#[derive(Deserialize)]
struct Prior {
    chain_id: String,
    seq: u64,
}

/// What the §8.11 boundary rule reads of a `RESTORE` payload (other keys are skipped).
#[derive(Deserialize)]
struct RestorePayload {
    source_head_seq: Option<u64>,
    source_head_hash: Option<String>,
    new_chain_id: Option<String>,
    source_chain_id: Option<String>,
    records_lost: Option<u64>,
    #[serde(default, deserialize_with = "present")]
    prior_keychain_anchor: Option<Option<Prior>>,
}

/// What the `prune_log` rule (F.11, L51) and the retention judgement (L52) read of a `PRUNE`.
#[derive(Deserialize)]
struct PrunePayload {
    prune_log_row_hash: Option<String>,
    range: Option<(u64, u64)>,
    cutoff: Option<String>,
    settings: Option<Value>,
}

/// A `RESTORE` seen in the walk.
struct Restore {
    seq: u64,
    source_chain: Option<String>,
    source_head_seq: Option<u64>,
    lost: Option<LostSpan>,
}

// ---------------------------------------------------------------------------------------
// The outcome and the report

#[derive(Default, PartialEq, Eq, Clone, Copy)]
enum Root {
    #[default]
    NotGiven,
    Match,
    Mismatch,
}

#[derive(Default)]
struct Outcome {
    manifest: Root,
    anchor_given: bool,
    /// The input cannot be read as an export (22).
    unreadable: Option<String>,
    /// A file differs from what the verified manifest names.
    file_tamper: Option<String>,
    /// An anchor line contradicts the export.
    anchor_mismatch: Option<String>,
    fork: Option<String>,
    /// The export contradicts itself.
    tamper: Option<String>,
    chain: Option<u64>,
    payloads: Option<u64>,
    writes: Option<u64>,
    prune: Option<String>,
    restore: Option<u64>,
    rows: u64,
    first: Option<u64>,
    last: Option<u64>,
    chains: Vec<String>,
    more_chains: usize,
    /// `events.jsonl` was walked to its end.
    walked: bool,
    last_anchored: Option<u64>,
    range: Option<(u64, u64)>,
    /// The report line naming entries of the export directory beside its three files.
    others: Option<String>,
}

impl Outcome {
    fn unreadable(&mut self, why: impl Into<String>) {
        if self.unreadable.is_none() {
            self.unreadable = Some(why.into());
        }
    }

    fn tamper(&mut self, why: impl Into<String>) {
        if self.tamper.is_none() {
            self.tamper = Some(why.into());
        }
    }

    fn anchor_mismatch(&mut self, why: impl Into<String>) {
        if self.anchor_mismatch.is_none() {
            self.anchor_mismatch = Some(why.into());
        }
    }

    fn fork(&mut self, why: impl Into<String>) {
        if self.fork.is_none() {
            self.fork = Some(why.into());
        }
    }

    fn chain(&mut self, seq: u64, why: &str) {
        self.chain.get_or_insert(seq);
        self.tamper(format!("chain broken at seq {seq}: {why}"));
    }

    fn payload(&mut self, seq: u64, why: &str) {
        self.payloads.get_or_insert(seq);
        self.tamper(format!("payload mismatch at seq {seq}: {why}"));
    }

    fn prune(&mut self, why: String) {
        if self.prune.is_none() {
            self.prune = Some(why.clone());
        }
        self.tamper(format!("prune_log: {why}"));
    }

    fn restore(&mut self, seq: u64, why: &str) {
        self.restore.get_or_insert(seq);
        self.tamper(format!("restore boundary mismatch at seq {seq}: {why}"));
    }

    /// A file's hash against the manifest's claim.
    fn file_hash(&mut self, file: &str, got: &[u8; 32], claimed: &[u8; 32]) {
        if ct_eq(got, claimed) {
            return;
        }
        let why = format!("{file} is not the file the manifest names");
        if self.manifest == Root::Match {
            if self.file_tamper.is_none() {
                self.file_tamper = Some(why);
            }
        } else {
            self.tamper(why);
        }
    }

    fn anchor_line(&self) -> String {
        if !self.anchor_given {
            return "anchor dir: not checked".into();
        }
        if let Some(f) = &self.fork {
            return format!("anchor dir: fork: {f}");
        }
        if let Some(a) = &self.anchor_mismatch {
            return format!("anchor dir: mismatch: {a}");
        }
        let Some((first, last)) = self.range else {
            return "anchor dir: not checked".into();
        };
        let tail = if self.manifest == Root::Match {
            "covered by the manifest SHA-256 only"
        } else {
            "unanchored, not covered by a trust root; give --manifest-sha256"
        };
        match self.last_anchored {
            Some(l) if l >= last => "anchor dir: ok".into(),
            Some(l) => format!(
                "anchor dir: ok up to seq {l}; rows {}..{last} {tail}",
                l + 1
            ),
            None => format!(
                "anchor dir: no line names a row of this export; rows {first}..{last} {tail}"
            ),
        }
    }

    fn verdict(self) -> ExportVerdict {
        if self.manifest == Root::Mismatch {
            return ExportVerdict::TamperOrFork {
                report: vec![
                    "manifest: mismatch".into(),
                    "TAMPERED: manifest.json is not the manifest the given SHA-256 names".into(),
                ],
            };
        }
        let mut report = vec![self.rows_line()];
        report.push(match self.chain {
            None => "chain: ok".into(),
            Some(s) => format!("chain: broken at seq {s}"),
        });
        report.push(match self.payloads {
            None => "payloads: ok".into(),
            Some(s) => format!("payloads: mismatch at seq {s}"),
        });
        report.push(match self.writes {
            None => "writes: ok".into(),
            Some(s) => format!("writes: request_set_hash mismatch at seq {s}"),
        });
        report.push(match &self.prune {
            None => "prune_log: ok".into(),
            Some(p) => format!("prune_log: {p}"),
        });
        report.push(match self.restore {
            None => "restore boundaries: ok".into(),
            Some(s) => format!("restore boundaries: mismatch at seq {s}"),
        });
        report.push(
            match self.manifest {
                Root::NotGiven => "manifest: not checked",
                Root::Match => "manifest: ok",
                Root::Mismatch => "manifest: mismatch",
            }
            .into(),
        );
        report.push(self.anchor_line());
        if let Some(others) = &self.others {
            report.push(others.clone());
        }
        let tampered = |t: &str| format!("TAMPERED: {t}");
        let found = if let Some(t) = &self.file_tamper {
            Some(tampered(t))
        } else if let Some(f) = &self.fork {
            match &self.tamper {
                Some(t) => {
                    report.push(format!("fork: {f}"));
                    Some(tampered(t))
                }
                None => Some(format!("FORK: {f}")),
            }
        } else {
            self.anchor_mismatch.as_deref().map(tampered)
        };
        if let Some(last) = found {
            report.push(last);
            return ExportVerdict::TamperOrFork { report };
        }
        if let Some(u) = &self.unreadable {
            report.push(format!("cannot verify: {u}"));
            return ExportVerdict::UsageOrIo { report };
        }
        if let Some(t) = &self.tamper {
            report.push(tampered(t));
            return ExportVerdict::TamperOrFork { report };
        }
        if !self.walked {
            report.push("cannot verify: events.jsonl was not read to its end".into());
            return ExportVerdict::UsageOrIo { report };
        }
        let anchored_all =
            matches!((self.last_anchored, self.range), (Some(l), Some((_, last))) if l >= last);
        match (self.manifest == Root::Match, self.anchor_given) {
            // The anchor dir is named only when one of its lines names a row of the export
            // (rows after its last such line are the manifest's alone, the anchor line says
            // so); an anchor dir naming none verified nothing (T8 review I-3).
            (true, true) if self.last_anchored.is_some() => report.push(BOTH_OK.into()),
            (true, _) => report.push(MANIFEST_OK.into()),
            (false, true) if anchored_all => report.push(ANCHOR_OK.into()),
            _ => {
                report.push(NO_ROOT.into());
                return ExportVerdict::NoTrustRoot { report };
            }
        }
        ExportVerdict::Verified { report }
    }

    fn rows_line(&self) -> String {
        match (self.first, self.last) {
            (Some(a), Some(b)) => {
                let mut chains = self.chains.join(", ");
                if self.more_chains > 0 {
                    chains.push_str(&format!(" and {} more", self.more_chains));
                }
                format!("rows {} from seq {a} to {b}, chains {chains}", self.rows)
            }
            _ => format!("rows {}", self.rows),
        }
    }
}

// ---------------------------------------------------------------------------------------
// The run

fn run(
    fs: &dyn FsRead,
    lim: &Limits,
    dir: &Path,
    anchor: Option<&Path>,
    given: Option<[u8; 32]>,
) -> ExportVerdict {
    let mut o = Outcome {
        anchor_given: anchor.is_some(),
        ..Outcome::default()
    };
    match check(fs, lim, dir, anchor, given, &mut o) {
        Ok(()) => o.verdict(),
        Err(Unreadable(why)) => ExportVerdict::UsageOrIo {
            report: vec![format!("cannot verify: {why}")],
        },
    }
}

fn check(
    fs: &dyn FsRead,
    lim: &Limits,
    dir: &Path,
    anchor: Option<&Path>,
    given: Option<[u8; 32]>,
    o: &mut Outcome,
) -> Result<(), Unreadable> {
    match fs.metadata(dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Err(unreadable("the export directory is not a directory")),
        Err(e) => {
            return Err(unreadable(format!(
                "the export directory cannot be read ({})",
                kind(&e)
            )));
        }
    }
    // The name as given (`.` and `..` resolved without the file system) and, where the file
    // system resolves it (links included), the real one.
    let partial = |p: &Path| {
        p.file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with(PARTIAL_SUFFIX))
    };
    let given_name = std::path::absolute(dir)
        .ok()
        .filter(|p| p.file_name().is_some());
    let real = fs.canonicalize(dir).ok();
    if given_name.is_none() && real.is_none() {
        return Err(unreadable("the export directory's name cannot be resolved"));
    }
    if given_name.as_deref().is_some_and(partial) || real.as_deref().is_some_and(partial) {
        return Err(unreadable(
            "the directory's name ends in .partial: an incomplete or failed export (or one \
             that was never renamed), never a valid one",
        ));
    }
    o.others = other_entries(fs, dir);

    // (1) The manifest: its hash first, then its shape.
    let bytes = match read_capped(fs, &dir.join(MANIFEST_FILE), lim.manifest) {
        Ok(Some(b)) => b,
        Ok(None) => {
            return Err(unreadable(
                "manifest.json is missing: a directory without one is never an export",
            ));
        }
        Err(why) => return Err(unreadable(format!("manifest.json {why}"))),
    };
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    o.manifest = match given {
        None => Root::NotGiven,
        Some(h) if ct_eq(&h, &digest) => Root::Match,
        Some(_) => {
            o.manifest = Root::Mismatch;
            return Ok(());
        }
    };
    let m = Manifest::parse(&bytes)
        .map_err(|why| unreadable(format!("manifest.json is not an export manifest: {why}")))?;
    drop(bytes);
    o.range = Some((m.first_seq, m.last_seq));
    if m.last_seq - m.first_seq + 1 != m.rows {
        o.tamper("the manifest's row count does not match its seq range");
    }
    if m.head_seq != m.last_seq {
        o.tamper("the manifest's head is not its last seq");
    }
    if m.last_anchored_seq
        .is_some_and(|l| !m.anchor_dir_configured || l < m.first_seq || l > m.last_seq)
    {
        o.tamper("the manifest's last_anchored_seq contradicts its range");
    }

    // (2) The anchor dir.
    let anchors = match anchor {
        Some(a) => Some(read_anchor_dir(fs, lim, a, &m)?),
        None => None,
    };

    // (3) prune_log.jsonl.
    let prune = read_prune_log(fs, lim, dir, &m, o)?;
    if let (Some(a), Some(rows)) = (&anchors, &prune) {
        check_prune_lines(a, rows, &m, o);
    }

    // (4) events.jsonl.
    let f = match open_regular(fs, &dir.join(EVENTS_FILE)) {
        Ok(Some(f)) => f,
        Ok(None) => return Err(unreadable("events.jsonl is missing")),
        Err(why) => return Err(unreadable(format!("events.jsonl {why}"))),
    };
    let mut r = LineReader::new(f, lim.line);
    let mut w = Walk::new(&m, anchors.as_ref(), prune.as_deref().unwrap_or_default());
    let mut n = 0u64;
    let mut walking = true;
    loop {
        let next = r
            .next()
            .map_err(|e| unreadable(format!("events.jsonl cannot be read ({})", kind(&e))))?;
        n += 1;
        let problem = match next {
            Next::Eof => break,
            Next::Line if walking => match w.row(&r.buf, n, o) {
                Ok(true) => None,
                Ok(false) => {
                    walking = false;
                    None
                }
                Err(why) => Some(why),
            },
            Next::Line => None,
            Next::Unterminated => Some(format!("events.jsonl ends inside line {n}")),
            Next::TooLong => Some(format!(
                "events.jsonl line {n} is longer than {} bytes",
                lim.line
            )),
        };
        if let Some(why) = problem {
            o.unreadable(why);
            walking = false;
        }
    }
    let read_to_end = walking;
    let events = r.finish();
    o.file_hash("events.jsonl", &events, &m.events_sha256);
    if read_to_end {
        w.end(o);
        o.walked = o.unreadable.is_none();
    }
    o.last_anchored = w.last_anchored;
    Ok(())
}

/// Names shown of the other entries of the export directory.
const MAX_OTHERS_SHOWN: usize = 8;

/// The report line naming the entries of the export directory beside its three files (T8
/// review M-5): a recipient must not take them for part of the verified export. Names are input,
/// so only short plain-ASCII ones are printed (the first few in byte order); the rest are counted.
fn other_entries(fs: &dyn FsRead, dir: &Path) -> Option<String> {
    let (mut count, mut shown) = (0usize, BTreeSet::new());
    let listed = fs.read_dir(dir, &mut |name| {
        let name = name.to_string_lossy();
        if [EVENTS_FILE, PRUNE_LOG_FILE, MANIFEST_FILE].contains(&name.as_ref()) {
            return true;
        }
        count += 1;
        let plain = name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        if plain {
            shown.insert(name.into_owned());
            if shown.len() > MAX_OTHERS_SHOWN {
                shown.pop_last();
            }
        }
        true
    });
    if listed.is_err() {
        return Some("export dir: its entries cannot be listed".into());
    }
    if count == 0 {
        return None;
    }
    let mut line = format!(
        "export dir: {count} other {}, not part of the export and not verified",
        if count == 1 { "entry" } else { "entries" }
    );
    if !shown.is_empty() {
        let names: Vec<String> = shown.into_iter().collect();
        line.push_str(": ");
        line.push_str(&names.join(", "));
        if count > names.len() {
            line.push_str(&format!(" and {} more", count - names.len()));
        }
    }
    Some(line)
}

/// Reads `prune_log.jsonl` (hashed to its end); `None` when a row could not be read (the rows
/// then judge nothing).
fn read_prune_log(
    fs: &dyn FsRead,
    lim: &Limits,
    dir: &Path,
    m: &Manifest,
    o: &mut Outcome,
) -> Result<Option<Vec<PruneLogRow>>, Unreadable> {
    let f = match open_regular(fs, &dir.join(PRUNE_LOG_FILE)) {
        Ok(Some(f)) => f,
        Ok(None) => return Err(unreadable("prune_log.jsonl is missing")),
        Err(why) => return Err(unreadable(format!("prune_log.jsonl {why}"))),
    };
    let mut r = LineReader::new(f, lim.prune_log_line);
    let mut rows: Option<Vec<PruneLogRow>> = Some(Vec::new());
    let mut n = 0usize;
    loop {
        let next = r
            .next()
            .map_err(|e| unreadable(format!("prune_log.jsonl cannot be read ({})", kind(&e))))?;
        n += 1;
        let problem = match next {
            Next::Eof => break,
            _ if r.read > lim.prune_log => Some(format!(
                "prune_log.jsonl is longer than {} bytes",
                lim.prune_log
            )),
            _ if n > lim.prune_log_rows => Some(format!(
                "prune_log.jsonl holds more than {} rows",
                lim.prune_log_rows
            )),
            Next::Line => match (&mut rows, prune_row(&r.buf)) {
                (Some(rs), Some(row)) => {
                    if rs.last().is_some_and(|p| p.prune_seq >= row.prune_seq) {
                        o.prune(format!("rows out of order at prune_seq {}", row.prune_seq));
                    }
                    rs.push(row);
                    None
                }
                (Some(_), None) => Some(format!("prune_log.jsonl line {n} is not a prune_log row")),
                (None, _) => None,
            },
            Next::Unterminated => Some(format!("prune_log.jsonl ends inside line {n}")),
            Next::TooLong => Some(format!(
                "prune_log.jsonl line {n} is longer than {} bytes",
                lim.prune_log_line
            )),
        };
        if let Some(why) = problem {
            o.unreadable(why);
            rows = None;
            r.drain().map_err(|e| {
                unreadable(format!("prune_log.jsonl cannot be read ({})", kind(&e)))
            })?;
            if r.read > lim.prune_log {
                break;
            }
        }
    }
    o.file_hash("prune_log.jsonl", &r.finish(), &m.prune_log_sha256);
    if let Some(rs) = &rows {
        let mut f = Findings::default();
        check_prune_log(rs, &mut f);
        if let Some(first) = f.finish().first() {
            o.prune(format!(
                "{} (prune_seq {})",
                first.detail,
                first
                    .observed_seq
                    .or(first.expected_seq)
                    .map_or_else(|| "?".into(), |s| s.to_string())
            ));
        }
    }
    Ok(rows)
}

/// One `prune_log.jsonl` line: JCS with exactly the seven columns.
fn prune_row(line: &[u8]) -> Option<PruneLogRow> {
    if !depth_ok(line, MAX_JSON_DEPTH) {
        return None;
    }
    let v: Value = serde_json::from_slice(line).ok()?;
    if to_jcs_vec(&v).ok()?.as_slice() != line {
        return None;
    }
    let o = exact_keys(
        &v,
        &[
            "cutoff_epoch",
            "first_retained_seq",
            "last_pruned_record_hash",
            "prev_row_hash",
            "prune_seq",
            "range_start",
            "row_hash",
        ],
    )
    .ok()?;
    let int = |k: &str| o.get(k).and_then(Value::as_u64).filter(|n| safe(*n));
    let hash = |k: &str| o.get(k).and_then(Value::as_str).and_then(hex32);
    Some(PruneLogRow {
        prune_seq: int("prune_seq")?,
        range_start: int("range_start")?,
        cutoff_epoch: o.get("cutoff_epoch")?.as_str()?.to_owned(),
        last_pruned: hash("last_pruned_record_hash")?,
        first_retained_seq: int("first_retained_seq")?,
        prev_row_hash: hash("prev_row_hash")?,
        row_hash: hash("row_hash")?,
    })
}

/// The anchor dir's `Prune` lines against `prune_log.jsonl` (PD-162 step 4): a line that
/// matches no row contradicts the export unless its prune may postdate it.
fn check_prune_lines(a: &Anchors, rows: &[PruneLogRow], m: &Manifest, o: &mut Outcome) {
    let newest = rows.last().map_or(1, |r| r.first_retained_seq);
    for p in &a.prunes {
        let matched = rows.iter().any(|r| {
            r.first_retained_seq == p.first_retained_seq
                && ct_eq(&r.last_pruned, &p.prev_hash)
                && r.cutoff_epoch == p.cutoff_epoch
        });
        if matched {
            continue;
        }
        let contradicts = match p.paired {
            Some(s) => s <= m.last_seq || rows.iter().any(|r| r.prune_seq == s),
            None => p.first_retained_seq < newest,
        };
        if contradicts {
            o.anchor_mismatch(format!(
                "a Prune line (first_retained_seq {}) matches no prune_log row",
                p.first_retained_seq
            ));
        }
    }
}

/// What the walk carries from row to row.
struct Prev {
    seq: u64,
    /// `None`: the row could not be hashed (an unsupported `format_version`).
    hash: Option<[u8; 32]>,
    chain: String,
}

/// A `PRUNE` waiting for its effective epoch (L36).
struct Pending {
    seq: u64,
    retention: u32,
    cutoff: String,
}

struct Walk<'a> {
    m: &'a Manifest,
    anchors: Option<&'a Anchors>,
    prune_rows: &'a [PruneLogRow],
    prev: Option<Prev>,
    rows: u64,
    chain_at: usize,
    restore_at: usize,
    key_at: usize,
    restores: Vec<Restore>,
    pending: Vec<Pending>,
    last_anchored: Option<u64>,
    /// Fork candidates (by file) and the highest export row their lines name.
    shares: BTreeMap<usize, u64>,
}

impl<'a> Walk<'a> {
    fn new(m: &'a Manifest, anchors: Option<&'a Anchors>, prune_rows: &'a [PruneLogRow]) -> Self {
        Walk {
            m,
            anchors,
            prune_rows,
            prev: None,
            rows: 0,
            chain_at: 0,
            restore_at: 0,
            key_at: 0,
            restores: Vec::new(),
            pending: Vec::new(),
            last_anchored: None,
            shares: BTreeMap::new(),
        }
    }

    fn prune_row(&self, seq: u64) -> Option<&'a PruneLogRow> {
        let rows: &'a [PruneLogRow] = self.prune_rows;
        rows.binary_search_by_key(&seq, |r| r.prune_seq)
            .ok()
            .and_then(|i| rows.get(i))
    }

    /// One line: `Ok(true)` to go on, `Ok(false)` to stop walking (more rows than the manifest
    /// claims), `Err` when it is not an export line.
    fn row(&mut self, raw: &[u8], n: u64, o: &mut Outcome) -> Result<bool, String> {
        let bad = |what: &str| format!("events.jsonl line {n} {what}");
        if !depth_ok(raw, MAX_JSON_DEPTH) {
            return Err(bad("nests deeper than 64"));
        }
        let l: ExportLine<'_> =
            serde_json::from_slice(raw).map_err(|_| bad("is not an export line"))?;
        let ints = [l.seq, l.format_version, l.flags, l.payload_len, l.key_id];
        if l.seq == 0 || !ints.iter().all(|i| safe(*i)) || !l.peer_pid.is_none_or(safe) {
            return Err(bad("has an integer outside 1..2^53"));
        }
        if !is_id(&l.chain_id) {
            return Err(bad("has a chain_id that is not an id"));
        }
        let (Some(payload_sha256), Some(prev_hash), Some(nonce)) = (
            hex32(l.payload_sha256),
            hex32(l.prev_hash),
            hex_n::<12>(l.nonce),
        ) else {
            return Err(bad("has a malformed hash or nonce"));
        };
        let peer_exe = match l.peer_exe.map(hex_any) {
            Some(None) => return Err(bad("has a malformed peer_exe")),
            p => p.flatten(),
        };
        let peer_origin_exe = match l.peer_origin_exe.map(hex_any) {
            Some(None) => return Err(bad("has a malformed peer_origin_exe")),
            p => p.flatten(),
        };
        let (ct, b64) = (l.payload_ct.as_bytes(), l.payload_b64.as_bytes());
        if !ct.len().is_multiple_of(4) || ct.len() as u64 > base64_len(MAX_EXPORT_CT_LEN) {
            return Err(bad(
                "has a payload_ct that is not base64 of a payload ciphertext",
            ));
        }
        if !b64.len().is_multiple_of(4) || b64.len() as u64 > base64_len(MAX_PAYLOAD_LEN) {
            return Err(bad("has a payload_b64 that is not base64 of a payload"));
        }
        let seq = l.seq;

        // Count and order.
        self.rows += 1;
        if self.rows > self.m.rows {
            o.tamper("events.jsonl holds more rows than the manifest claims");
            return Ok(false);
        }
        o.rows = self.rows;
        o.first.get_or_insert(seq);
        o.last = Some(seq);
        let expected = self.prev.as_ref().map_or(self.m.first_seq, |p| p.seq + 1);
        let contiguous = seq == expected;
        if !contiguous {
            o.chain(seq, "the seq does not follow the row before it");
        }

        // record_hash, with payload_ct streamed from its base64 text.
        let f = RowFields {
            seq,
            format_version: l.format_version,
            chain_id: &l.chain_id,
            ts_utc: &l.ts_utc,
            epoch: l.epoch.as_deref(),
            request_id: l.request_id.as_deref(),
            event_type: &l.event_type,
            op_id: l.op_id.as_deref(),
            op_class: l.op_class.as_deref(),
            instance_id: l.instance_id.as_deref(),
            target: l.target.as_deref(),
            agent_name: l.agent_name.as_deref(),
            agent_name_source: l.agent_name_source.as_deref(),
            client_kind: l.client_kind.as_deref(),
            connection_id: l.connection_id.as_deref(),
            peer_pid: l.peer_pid,
            peer_exe: peer_exe.as_deref(),
            peer_origin_exe: peer_origin_exe.as_deref(),
            os_user: l.os_user.as_deref(),
            atlassian_user: l.atlassian_user.as_deref(),
            atlassian_user_key: l.atlassian_user_key.as_deref(),
            decision: l.decision.as_deref(),
            flags: l.flags,
            payload_len: l.payload_len,
            payload_sha256: &payload_sha256,
            key_id: l.key_id,
            nonce: &nonce,
            payload_ct: &[],
            prev_hash: &prev_hash,
        };
        let hash = if l.format_version != FORMAT_VERSION {
            // Another version's record cannot be judged (T8 review M-6); the walk goes on.
            o.unreadable(format!(
                "events.jsonl line {n} is a record of format_version {}, which this verifier \
                 does not read (an export of another version?)",
                l.format_version
            ));
            None
        } else {
            let mut h = RecordHasher::new(f.format_version, f.prev_hash);
            let mut framed = true;
            for (i, frame) in f.frames().iter().enumerate() {
                let ok = if i == PAYLOAD_CT_FRAME {
                    h.bytes_header(b64_decoded_len(ct)).is_ok()
                        && b64_pieces(ct, &mut |piece| h.bytes(piece))
                } else {
                    h.frame(frame).is_ok()
                };
                framed &= ok;
            }
            if !framed {
                return Err(bad("has a payload_ct that is not canonical base64"));
            }
            Some(h.finish())
        };

        // Links: the boundary, GENESIS, the row before.
        if self.rows == 1 && !ct_eq(&prev_hash, &self.m.boundary_prev_hash) {
            o.tamper("the first row's prev_hash is not the manifest's boundary_prev_hash");
        }
        let genesis = l.event_type == EventType::GENESIS.as_str();
        if (seq == 1) != genesis || (genesis && !ct_eq(&prev_hash, &ZERO_HASH)) {
            o.chain(seq, "GENESIS is not the first record of the log");
        }
        // A row of another format has no hash to link to (that is a 22 already).
        if let Some(p) = &self.prev
            && contiguous
            && p.hash.is_some_and(|h| !ct_eq(&h, &prev_hash))
        {
            o.chain(seq, "prev_hash does not link to the row before it");
        }

        // Chains and the manifest's lists.
        let restore = l.event_type == EventType::RESTORE.as_str();
        if let Some(p) = &self.prev
            && p.chain != l.chain_id
            && !restore
        {
            o.restore(seq, "the chain_id changes without a RESTORE");
        }
        if self.prev.as_ref().is_none_or(|p| p.chain != l.chain_id) {
            if self.m.chain_ids.get(self.chain_at) != Some(&l.chain_id) {
                o.tamper(format!(
                    "the chains of the rows (seq {seq}) are not the manifest's chain_ids"
                ));
            }
            self.chain_at += 1;
            if o.chains.len() < MAX_CHAINS_SHOWN {
                o.chains.push(l.chain_id.clone());
            } else {
                o.more_chains += 1;
            }
        }
        if restore {
            if self.m.restore_records.get(self.restore_at) != Some(&seq) {
                o.tamper(format!(
                    "RESTORE at seq {seq} is not in the manifest's restore_records"
                ));
            }
            self.restore_at += 1;
        }
        if l.event_type == EventType::KEY_RECOVERED.as_str() {
            if self.m.key_recovered_records.get(self.key_at) != Some(&seq) {
                o.tamper(format!(
                    "KEY_RECOVERED at seq {seq} is not in the manifest's key_recovered_records"
                ));
            }
            self.key_at += 1;
        }
        if l.unanchored.is_some() != self.m.unanchored(seq) {
            o.tamper(format!(
                "the unanchored mark of seq {seq} contradicts the manifest"
            ));
        }

        // The payload: length and hash of payload_b64; the plaintext kept only when a check
        // parses it or it may have a `payload` field (present or absent, both are judged).
        let parse = restore
            || l.event_type == EventType::PRUNE.as_str()
            || l.event_type == EventType::WRITE_APPROVED.as_str();
        let len = b64_decoded_len(b64);
        let keep = parse || len <= MAX_EXPORT_PAYLOAD_FIELD_BYTES;
        let mut plain = Zeroizing::new(Vec::new());
        if keep {
            plain.reserve_exact(usize::try_from(len).unwrap_or(0));
        }
        let mut sha = Sha256::new();
        if !b64_pieces(b64, &mut |piece| {
            sha.update(piece);
            if keep {
                plain.extend_from_slice(piece);
            }
        }) {
            return Err(bad("has a payload_b64 that is not canonical base64"));
        }
        let digest: [u8; 32] = sha.finalize().into();
        if len != l.payload_len {
            o.payload(seq, "payload_len is not the length of payload_b64");
        } else if !ct_eq(&digest, &payload_sha256) {
            o.payload(seq, "payload_sha256 is not the hash of payload_b64");
        }
        // `payload` byte for byte when present; absent only where the exporter writes none (too
        // long, too deep or not JCS: `payload_field_shown`, T8 review I-1).
        if l.payload.is_some() {
            let shown = top_level_value(raw, b"payload").and_then(|(s, e)| raw.get(s..e));
            if !keep || shown != Some(&plain[..]) {
                o.payload(seq, "the payload field is not the payload");
            }
        } else if keep && payload_field_shown(&plain) {
            o.payload(seq, "the payload field is missing");
        }
        if l.event_type == EventType::WRITE_APPROVED.as_str() && !request_set_ok(&plain) {
            o.writes.get_or_insert(seq);
            o.tamper(format!("request_set_hash mismatch at seq {seq}"));
        }

        // RESTORE, PRUNE and the prunes waiting for an epoch.
        let mut boundary_chain = l.chain_id.clone();
        if restore {
            let r = self.restore_row(&l, seq, &prev_hash, &plain, o);
            if self.rows == 1
                && let Some(c) = &r.source_chain
            {
                boundary_chain = c.clone();
            }
            if self.restores.len() <= self.m.restore_records.len() {
                self.restores.push(r);
            }
        }
        if let Some(e) = l.epoch.as_deref().and_then(parse_epoch) {
            for p in std::mem::take(&mut self.pending) {
                judge(p.seq, p.retention, &p.cutoff, e, o);
            }
        }
        if l.event_type == EventType::PRUNE.as_str() {
            self.prune_record(&l, seq, &plain, o);
        } else if self.prune_row(seq).is_some() {
            o.prune(format!(
                "the prune_log row of prune_seq {seq} names a record that is not a PRUNE"
            ));
        }
        drop(plain);

        // The anchor dir.
        if let (Some(a), Some(hash)) = (self.anchors, hash) {
            if self.rows == 1 && seq > 1 {
                self.boundary(a, seq - 1, &boundary_chain, o);
            }
            self.anchored(a, &l, seq, &hash, o);
        }

        self.prev = Some(Prev {
            seq,
            hash,
            chain: l.chain_id,
        });
        Ok(true)
    }

    /// §8.11: `source_head_seq`/`source_head_hash` name the row before, the new chain is this
    /// row's, the row before is of `source_chain_id`.
    fn restore_row(
        &self,
        l: &ExportLine<'_>,
        seq: u64,
        prev_hash: &[u8; 32],
        plain: &[u8],
        o: &mut Outcome,
    ) -> Restore {
        let p = depth_ok(plain, MAX_JSON_DEPTH)
            .then(|| serde_json::from_slice::<RestorePayload>(plain).ok())
            .flatten();
        let Some(p) = p else {
            o.restore(seq, "the RESTORE payload is not readable");
            return Restore {
                seq,
                source_chain: None,
                source_head_seq: None,
                lost: None,
            };
        };
        if p.source_head_seq != seq.checked_sub(1) {
            o.restore(seq, "source_head_seq is not the record before RESTORE");
        }
        if !p
            .source_head_hash
            .as_deref()
            .and_then(hex32)
            .is_some_and(|h| ct_eq(&h, prev_hash))
        {
            o.restore(seq, "source_head_hash is not RESTORE's prev_hash");
        }
        if p.new_chain_id.as_deref() != Some(l.chain_id.as_str()) {
            o.restore(seq, "RESTORE's chain_id is not its new_chain_id");
        }
        if let Some(prev) = &self.prev
            && Some(prev.seq) == seq.checked_sub(1)
            && p.source_chain_id.as_deref() != Some(prev.chain.as_str())
        {
            o.restore(
                seq,
                "the record before RESTORE is not of its source_chain_id",
            );
        }
        let lost = match (&p.source_chain_id, p.source_head_seq, p.records_lost) {
            (Some(c), Some(head), Some(lost)) => match &p.prior_keychain_anchor {
                Some(prior) => LostSpan::of(
                    c,
                    head,
                    prior.as_ref().map(|a| (a.chain_id.as_str(), a.seq)),
                    lost,
                ),
                None => None,
            },
            _ => None,
        };
        Restore {
            seq,
            source_chain: p.source_chain_id.filter(|c| is_id(c)),
            source_head_seq: p.source_head_seq,
            lost,
        }
    }

    /// A `PRUNE` against its `prune_log` row (F.11, L51) and its settings snapshot (L52, read
    /// with the store's parser, M8 Δ7's `allow_degraded_scripts` included).
    fn prune_record(&mut self, l: &ExportLine<'_>, seq: u64, plain: &[u8], o: &mut Outcome) {
        let Some(row) = self.prune_row(seq) else {
            o.prune(format!("the PRUNE at seq {seq} has no prune_log row"));
            return;
        };
        let p = (plain.len() <= MAX_TREE_PLAINTEXT && depth_ok(plain, MAX_JSON_DEPTH))
            .then(|| serde_json::from_slice::<PrunePayload>(plain).ok())
            .flatten();
        let Some(p) = p else {
            o.prune(format!("the PRUNE payload at seq {seq} is not readable"));
            return;
        };
        if !p
            .prune_log_row_hash
            .as_deref()
            .and_then(hex32)
            .is_some_and(|h| ct_eq(&h, &row.row_hash))
        {
            o.prune(format!(
                "the PRUNE at seq {seq} does not name its prune_log row's row_hash"
            ));
        }
        if p.range != Some((row.range_start, row.first_retained_seq))
            || p.cutoff.as_deref() != Some(row.cutoff_epoch.as_str())
        {
            o.prune(format!(
                "the PRUNE at seq {seq} has another range or cutoff than its prune_log row"
            ));
        }
        let Some(settings) = p
            .settings
            .as_ref()
            .and_then(|s| Settings::from_json(s).ok())
        else {
            if p.settings.as_ref().is_some_and(snapshot_has_unknown_key) {
                o.unreadable(format!(
                    "the settings snapshot of the PRUNE at seq {seq} has a key this verifier \
                     does not know (an export of a newer version?)"
                ));
            } else {
                o.prune(format!(
                    "the settings snapshot of the PRUNE at seq {seq} is malformed"
                ));
            }
            return;
        };
        if settings.legal_hold {
            o.prune(format!(
                "the PRUNE at seq {seq} pruned while legal hold was on"
            ));
        }
        let cutoff = p.cutoff.unwrap_or_default();
        match l.epoch.as_deref() {
            Some(e) => match parse_epoch(e) {
                Some(e) => judge(seq, settings.retention_days, &cutoff, e, o),
                None => o.prune(format!("the epoch of the PRUNE at seq {seq} is unreadable")),
            },
            // Judged by the next record with an epoch; one beyond the export is not judged.
            None => self.pending.push(Pending {
                seq,
                retention: settings.retention_days,
                cutoff,
            }),
        }
    }

    /// The line at `first_seq - 1` names `boundary_prev_hash` (PD-162 step 4).
    fn boundary(&self, a: &Anchors, b: u64, chain: &str, o: &mut Outcome) {
        let Some(lines) = a.by_seq.get(&b) else {
            return;
        };
        let own: Vec<&Named> = lines
            .iter()
            .filter(|l| a.files.get(l.file).is_some_and(|f| f.chain == chain))
            .collect();
        let hit = own
            .iter()
            .any(|l| ct_eq(&l.record_hash, &self.m.boundary_prev_hash));
        let miss = own
            .iter()
            .any(|l| !ct_eq(&l.record_hash, &self.m.boundary_prev_hash));
        match (hit, miss) {
            (true, true) => o.fork(format!(
                "two lines name seq {b} with different record hashes"
            )),
            (false, true) => o.anchor_mismatch(format!(
                "the line naming seq {b} contradicts the export's boundary_prev_hash"
            )),
            _ => {}
        }
    }

    /// The range-aware comparison of the lines naming `seq` (PD-162 step 4, PD-163).
    fn anchored(
        &mut self,
        a: &Anchors,
        l: &ExportLine<'_>,
        seq: u64,
        hash: &[u8; 32],
        o: &mut Outcome,
    ) {
        let Some(lines) = a.by_seq.get(&seq) else {
            return;
        };
        let behind = l.flags & EventFlags::BEHIND.bits() != 0;
        // `other_hash`: a line naming another record hash (fork evidence beside a hit);
        // `other_fields`: the row's hash with another epoch or kind (only a mismatch).
        let (mut hit, mut other_hash, mut other_fields) = (false, false, false);
        for n in lines {
            let Some(file) = a.files.get(n.file) else {
                continue;
            };
            if file.chain == l.chain_id {
                let same_hash = ct_eq(&n.record_hash, hash);
                let same = same_hash
                    && n.epoch == l.epoch
                    && match &n.kind {
                        Kind::Record { clock_behind } => *clock_behind == behind,
                        Kind::Immediate(t) => *t == l.event_type,
                        Kind::Detached => true,
                    };
                if same {
                    hit = true;
                } else if same_hash {
                    other_fields = true;
                } else {
                    other_hash = true;
                }
            } else if file.export {
                // A line of another chain of the export: only a RESTORE's source chain may name
                // seqs beyond its source head, and only those its records_lost covers (§8.11).
                let restored = self.restores.iter().find(|r| {
                    r.source_chain.as_deref() == Some(file.chain.as_str())
                        && r.source_head_seq.is_some_and(|h| seq > h)
                });
                match restored {
                    Some(r) if r.lost.as_ref().is_some_and(|s| s.covers(&file.chain, seq)) => {}
                    Some(r) => o.fork(format!(
                        "chain {} has anchored lines beyond the source head of the RESTORE at \
                         seq {} that records_lost does not cover (seq {seq})",
                        file.chain, r.seq
                    )),
                    None => o.anchor_mismatch(format!(
                        "a line of chain {} names seq {seq}, a row of another chain",
                        file.chain
                    )),
                }
            } else if ct_eq(&n.record_hash, hash) {
                let at = self.shares.entry(n.file).or_insert(seq);
                *at = (*at).max(seq);
            }
        }
        if other_fields {
            o.anchor_mismatch(format!(
                "the line naming seq {seq} has the row's record hash but another epoch or kind"
            ));
        }
        match (hit, other_hash) {
            (true, true) => o.fork(format!(
                "two lines name seq {seq} with different record hashes"
            )),
            (false, true) => {
                o.anchor_mismatch(format!("the line naming seq {seq} contradicts the row"))
            }
            (true, false) if !other_fields => self.last_anchored = Some(seq),
            _ => {}
        }
    }

    /// After the last line: the manifest's claims about the whole file, and the fork
    /// candidates.
    fn end(&self, o: &mut Outcome) {
        if self.rows < self.m.rows {
            o.tamper("events.jsonl holds fewer rows than the manifest claims");
        }
        match &self.prev {
            Some(p)
                if p.seq == self.m.last_seq
                    && p.hash.is_some_and(|h| ct_eq(&h, &self.m.head_hash)) => {}
            _ => o.tamper("the last row is not the manifest's head"),
        }
        if self.chain_at != self.m.chain_ids.len()
            || self.restore_at != self.m.restore_records.len()
            || self.key_at != self.m.key_recovered_records.len()
        {
            o.tamper("the manifest's chain_ids, restore_records or key_recovered_records list rows the export does not hold");
        }
        // A candidate names a row by its exact record hash only when its file holds lines of
        // the export's chain: a writer only ever writes a record's line into its own chain's
        // file (a RESTORE's lines included), so a RESTORE of the export accounts for none
        // (T8 review M-7).
        if let Some(a) = self.anchors {
            for (file, at) in &self.shares {
                if let Some(f) = a.files.get(*file) {
                    o.fork(format!(
                        "chain {} of this installation shares rows up to seq {at} with the export \
                         and continues under another chain_id without a RESTORE",
                        f.chain
                    ));
                }
            }
        }
    }
}

/// The retention judgement of a `PRUNE` (L52): its cutoff not inside the retention counted back
/// from its effective epoch.
fn judge(seq: u64, retention: u32, cutoff: &str, epoch: chrono::NaiveDate, o: &mut Outcome) {
    let Some(cutoff) = parse_epoch(cutoff) else {
        o.prune(format!(
            "the cutoff of the PRUNE at seq {seq} is unreadable"
        ));
        return;
    };
    let limit = epoch.checked_sub_days(Days::new(u64::from(retention)));
    if limit.is_none_or(|l| cutoff > l) {
        o.prune(format!(
            "the PRUNE at seq {seq} has a cutoff inside its {retention}-day retention"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_set::{RequestRecord, request_set_hash, requests_to_json};
    use serde_json::json;

    #[test]
    fn request_set_ok_matches_request_set_hash() {
        let reqs = vec![
            RequestRecord {
                index: 0,
                method: "POST".into(),
                resolved_url: "https://jira.example/rest/api/2/issue".into(),
                content_type: Some("application/json".into()),
                body_bytes: b"{\"a\":1}".to_vec(),
            },
            RequestRecord {
                index: 1,
                method: "PUT".into(),
                resolved_url: "https://jira.example/x".into(),
                content_type: None,
                body_bytes: Vec::new(),
            },
        ];
        let payload = |hash: [u8; 32]| {
            to_jcs_vec(&json!({
                "candidate_rev": 1,
                "request_set_hash": hex::encode(hash),
                "requests": requests_to_json(&reqs),
            }))
            .expect("jcs")
        };
        assert!(request_set_ok(&payload(request_set_hash(&reqs))));
        assert!(!request_set_ok(&payload(request_set_hash(&reqs[..1]))));
        assert!(!request_set_ok(
            b"{\"requests\":[],\"request_set_hash\":\"00\"}"
        ));
        // A record with a sixth key, or content_type missing, is unreadable.
        let mut v: Value = serde_json::from_slice(&payload(request_set_hash(&reqs))).unwrap();
        v["requests"][0]["extra"] = json!(1);
        assert!(!request_set_ok(&to_jcs_vec(&v).unwrap()));
        let mut v: Value = serde_json::from_slice(&payload(request_set_hash(&reqs))).unwrap();
        v["requests"][1]
            .as_object_mut()
            .unwrap()
            .remove("content_type");
        assert!(!request_set_ok(&to_jcs_vec(&v).unwrap()));
    }

    #[test]
    fn depth_and_top_level_value() {
        assert!(depth_ok(b"[[[]]]", 3));
        assert!(!depth_ok(b"[[[[]]]]", 3));
        assert!(depth_ok(br#"{"a":"[[[[[[["}"#, 1));
        let line = br#"{"a":1,"payload":{"payload":[1,{"x":"}"}],"b":2},"payload_b64":"x"}"#;
        let (s, e) = top_level_value(line, b"payload").unwrap();
        assert_eq!(&line[s..e], br#"{"payload":[1,{"x":"}"}],"b":2}"#);
        assert_eq!(top_level_value(br#"{"a":1}"#, b"payload"), None);
        let (s, e) = top_level_value(br#"{"payload":"\"x"}"#, b"payload").unwrap();
        assert_eq!(&br#"{"payload":"\"x"}"#[s..e], br#""\"x""#);
    }

    #[test]
    fn b64_pieces_refuses_inner_padding_and_counts_exactly() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
        let text = STANDARD.encode(&data);
        let mut got = Vec::new();
        assert!(b64_pieces(text.as_bytes(), &mut |p| got.extend_from_slice(p)));
        assert_eq!(got, data);
        assert_eq!(b64_decoded_len(text.as_bytes()), data.len() as u64);
        // Padding inside the text (a padded quantum at a piece end) is refused.
        let mut bad = STANDARD.encode(&data[..B64_CHUNK / 4 * 3 - 1]);
        bad.push_str(&STANDARD.encode(b"abc"));
        assert!(!b64_pieces(bad.as_bytes(), &mut |_| {}));
        assert!(!b64_pieces(b"QQ=", &mut |_| {}));
    }

    #[test]
    fn limits_default_to_the_plan_bounds() {
        let l = Limits::default();
        assert_eq!(l.line, MAX_EXPORT_LINE_BYTES);
        assert_eq!(l.manifest, 1024 * 1024);
        assert_eq!(l.prune_log, 64 * 1024 * 1024);
        assert_eq!(l.prune_log_rows, 1_000_000);
        assert_eq!(l.anchor_file, anchor_dir::MAX_FILE_BYTES);
        assert_eq!(l.anchor_files, 256);
    }
}
