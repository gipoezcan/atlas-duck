//! Compliance export (§8.10, PD-159..PD-161, PD-181): a time range of the log, decrypted, in a
//! new directory `<chosen>/atlas-duck-export-<chain_id>-<first_seq>-<last_seq>-<utc stamp>/`
//! (`chain_id` of the first exported row; created `0700` on Unix, every file `0600` and
//! create-new; on Windows the files inherit the chosen folder's ACL). The directory is written
//! under the staging name `<name>.partial` and gets its final name only after the `EXPORT`
//! record is logged (below). Its files:
//!
//! - `events.jsonl`: one JCS line per row, `first_seq..=last_seq`, each ending in `\n`. Keys:
//!   the 29 `FIELD_LIST` columns under their §8.2 names, every one present (`null` for NULL;
//!   integers as JSON numbers; `nonce`, `payload_sha256`, `prev_hash`, `peer_exe` and
//!   `peer_origin_exe` (the stored WTF-8 bytes) as lowercase hex; `payload_ct` as base64), plus
//!   `payload_b64` (the decrypted plaintext bytes, base64), `payload` (the same plaintext as JSON
//!   text, only when it is at most [`MAX_EXPORT_PAYLOAD_FIELD_BYTES`] and parses) and
//!   `unanchored: true` (only when an anchor dir is configured and the row comes after the last
//!   anchored row of the range). There is no `record_hash` key: the verifier recomputes it. Base64
//!   is RFC 4648 standard with padding. A line is at most [`MAX_EXPORT_LINE_BYTES`] (without its
//!   newline).
//! - `prune_log.jsonl`: every `prune_log` row when the events are written, read in its own
//!   transaction after them (so a prune committed during the export is in it, with a
//!   `prune_seq` beyond `last_seq`), one JCS line each, keys `prune_seq`, `range_start`,
//!   `cutoff_epoch`, `last_pruned_record_hash`, `first_retained_seq`, `prev_row_hash`, `row_hash`
//!   (hashes as lowercase hex). Empty when the store was never pruned.
//! - `manifest.json`, written last (JCS): `format`, `app_version`, `build_id`, `exported_at`,
//!   `install {install_id, host, os_user}`, `requested_range {from_utc, to_utc}`, `first_seq`,
//!   `last_seq`, `rows`, `boundary_prev_hash` (`prev_hash` of the first row), `head {seq,
//!   record_hash}` (the last exported row), `chain_ids` (in seq order), `restore_records` and
//!   `key_recovered_records` (seqs in the range), `anchor_dir_configured`, `last_anchored_seq`
//!   (or `null`), `events_sha256`, `prune_log_sha256` (SHA-256 of the two files' bytes, so the
//!   manifest's hash binds every byte of the export) and `accountability` (§2.4).
//!
//! `manifest.json` is written as `manifest.json.tmp`, fsynced and renamed, so a manifest that
//! exists is complete. Then `EXPORT {manifest_sha256, first_seq, last_seq, rows}` is appended
//! (store-owned) and only then the directory is renamed from `<name>.partial` to `<name>`.
//!
//! **Failures (L186).** Every failure before the rename (a cancel, a failed append included)
//! unlinks `manifest.json` first (a directory without one is never an export, even if the
//! removal is interrupted) and then removes the staging directory; if that removal fails, the
//! export returns [`AuditError::ExportLeftover`] naming it. A process that dies while the export
//! runs (crash, kill, power loss, an app exit that did not wait for `Store::export` to return)
//! leaves the `.partial` directory with whatever was written, decrypted `events.jsonl`
//! included, and no `EXPORT`: nothing cleans it up later (the store does not keep the path).
//! It never carries the final name, so it never looks like a complete export. If the rename
//! itself fails after the `EXPORT` was logged, the export is complete under the staging name:
//! [`AuditError::ExportNotRenamed`]. Names are checked before anything is created and again
//! before the rename: an existing entry of the final or the staging name is never written,
//! renamed over or removed (a same-user race between the check and the rename is outside
//! §2.4, as is a swap between `mkdir` and the file creation).
//!
//! The export reads through its own read-only connection and data-key cache, as a full
//! verification does, in batches of [`EXPORT_BATCH_ROWS`] rows, each in its own read
//! transaction (a long snapshot would hold back the WAL truncation after a prune), so it never
//! blocks an append; only the final `EXPORT` goes through the writer. Between batches it checks
//! that the store still holds what it already wrote.
//!
//! **Working set.** For one row of the largest size the export holds at once: the `payload_ct`
//! blob of the SQLite row (at most [`MAX_EXPORT_CT_LEN`], about 97 MiB), the decrypted
//! plaintext (at most `MAX_PAYLOAD_LEN`, 96 MiB, zeroized on drop), the line buffer (at most
//! [`MAX_EXPORT_LINE_BYTES`], about 258 MiB, zeroized on drop) and, briefly, the decompression
//! input: about 450 MiB in all. Rows below 1 MiB add the JCS check of `payload` (a parsed copy
//! and its re-encoding, at most a few MiB). Known limits: the 8 KiB `BufWriter` of a file and
//! serde_json's scratch buffers keep fragments of plaintext that are not zeroized (the same
//! bytes are on disk).

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use atlas_duck_ipc::build_info::{APP_VERSION, BUILD_ID};
use atlas_duck_ipc::jcs::{MAX_SAFE_INTEGER, to_jcs_vec};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::anchor_dir::{self, AnchorLine};
use crate::backup::compact_stamp;
use crate::clock::UtcInstant;
use crate::crypto::{Kek, MAX_PAYLOAD_LEN, ct_eq};
use crate::encoding::{FIELD_LIST, RowFields};
use crate::error::AuditError;
use crate::open::sync_dir;
use crate::schema;
use crate::store::Store;
use crate::types::{EventType, ExportControl, ExportReceipt, RustChosenPath, TimeRange};
use crate::verify::{DecryptError, Deks};
use crate::writer::{PreparedEvent, ts_text};

/// Rows per batch, each read in its own read transaction (PD-181).
pub const EXPORT_BATCH_ROWS: u64 = 10_000;

/// `manifest.json`'s `format`.
pub const EXPORT_FORMAT: &str = "atlas-duck-export/1";

pub const EVENTS_FILE: &str = "events.jsonl";
pub const PRUNE_LOG_FILE: &str = "prune_log.jsonl";
pub const MANIFEST_FILE: &str = "manifest.json";
/// `manifest.json` while it is written; renamed once complete and fsynced.
const MANIFEST_TMP_FILE: &str = "manifest.json.tmp";

/// The suffix of the export directory's name until the `EXPORT` record is logged.
pub const PARTIAL_SUFFIX: &str = ".partial";

/// Attempts of the final rename (a scanner may hold a just-closed file of the directory for a
/// moment, which makes Windows refuse to rename the directory), [`RENAME_RETRY_PAUSE`] apart.
const RENAME_ATTEMPTS: u32 = 5;
const RENAME_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_millis(200);

/// A manifest is at most this long (the verifier's bound, PD-162).
pub const MAX_EXPORT_MANIFEST_BYTES: u64 = 1024 * 1024;

/// The AES-GCM tag after the zstd frame in `payload_ct` (F.3).
const AEAD_TAG_LEN: u64 = 16;

/// The largest `payload_ct` of a plaintext of at most [`MAX_PAYLOAD_LEN`]: zstd's worst-case
/// frame (`ZSTD_COMPRESSBOUND`: `n + n/256`, plus at most 64 bytes below 128 KiB) and the tag.
pub const MAX_EXPORT_CT_LEN: u64 = MAX_PAYLOAD_LEN + (MAX_PAYLOAD_LEN >> 8) + 64 + AEAD_TAG_LEN;

/// `payload` (the parsed copy for human readers) only for plaintexts up to this size.
pub const MAX_EXPORT_PAYLOAD_FIELD_BYTES: u64 = 1024 * 1024;

/// The share of [`MAX_EXPORT_LINE_BYTES`] for every column but the two base64 fields and
/// `payload`, with the JSON framing of the line. The exporter asserts only the total line
/// length; whether the verifier also caps this share is the verifier's rule (T8).
pub const MAX_EXPORT_OTHER_BYTES: u64 = 64 * 1024;

const fn base64_len(n: u64) -> u64 {
    n.div_ceil(3) * 4
}

/// The longest `events.jsonl` line (without its `\n`): base64 of the largest `payload_ct` and
/// of the largest plaintext, the `payload` field and every other column (about 257 MiB).
pub const MAX_EXPORT_LINE_BYTES: u64 = base64_len(MAX_EXPORT_CT_LEN)
    + base64_len(MAX_PAYLOAD_LEN)
    + MAX_EXPORT_PAYLOAD_FIELD_BYTES
    + MAX_EXPORT_OTHER_BYTES;

/// §2.4 (verbatim): the manifest's accountability statement (§8.10).
pub const ACCOUNTABILITY: &str = "Accountable principal: for every approved write and released \
read, the accountable principal is the approving OS user, acting as the owner of the instance \
PAT (§5.6 approver identity). Agent and peer fields are advisory attribution only.";

/// What `Store::export` reads of the store handle.
pub(crate) struct Parts {
    pub(crate) db_path: PathBuf,
    pub(crate) kek: Kek,
    pub(crate) generation: u64,
    /// The anchor dir in force (the store's setting, else `OpenConfig.anchor_dir`).
    pub(crate) anchor_dir: Option<PathBuf>,
    /// The settings view could not be read: whether an anchor dir is configured is unknown.
    pub(crate) anchor_dir_unknown: bool,
    pub(crate) install_id: String,
    pub(crate) host: String,
    pub(crate) os_user: String,
    pub(crate) now: UtcInstant,
    pub(crate) batch_rows: u64,
}

fn sql(e: rusqlite::Error) -> AuditError {
    AuditError::Io(format!("database error: {e}"))
}

fn io(e: io::Error) -> AuditError {
    AuditError::Io(e.to_string())
}

/// The seq interval a time range resolves to (PD-160), and what the rows need before the walk.
struct Plan {
    first_seq: u64,
    last_seq: u64,
    /// The first exported row's `chain_id` (the directory name).
    first_chain: String,
    anchor_dir_configured: bool,
    /// The last row of the range that a line of the anchor dir names with its `record_hash`.
    last_anchored: Option<u64>,
}

impl Plan {
    fn rows(&self) -> u64 {
        self.last_seq - self.first_seq + 1
    }

    fn unanchored(&self, seq: u64) -> bool {
        self.anchor_dir_configured && self.last_anchored.is_none_or(|l| seq > l)
    }

    fn unanchored_from(&self) -> Option<u64> {
        if !self.anchor_dir_configured {
            return None;
        }
        match self.last_anchored {
            None => Some(self.first_seq),
            Some(l) if l < self.last_seq => Some(l + 1),
            Some(_) => None,
        }
    }
}

/// 32 lowercase hex characters (F.1 ids): only such a `chain_id` becomes part of a path.
fn is_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn seq_param(seq: u64) -> Result<i64, AuditError> {
    i64::try_from(seq).map_err(|_| AuditError::Invalid("seq beyond the SQLite range"))
}

fn seq_of(v: Option<i64>) -> Result<Option<u64>, AuditError> {
    v.map(|s| {
        u64::try_from(s).map_err(|_| AuditError::InvalidRecord {
            seq: 0,
            what: "negative seq",
        })
    })
    .transpose()
}

/// Resolves the range on one snapshot: the first record with `ts_utc >= from` to the last with
/// `ts_utc <= to` (PD-160; `ts_utc` is not monotonic, so rows outside the times may lie in
/// between and are exported), then the last anchored row of that interval.
fn resolve_range(
    conn: &Connection,
    from: &str,
    to: &str,
    parts: &Parts,
) -> Result<Plan, AuditError> {
    let tx = conn.unchecked_transaction().map_err(sql)?;
    let first: Option<i64> = tx
        .query_row(
            "SELECT min(seq) FROM events WHERE ts_utc >= ?1",
            [from],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let last: Option<i64> = tx
        .query_row(
            "SELECT max(seq) FROM events WHERE ts_utc <= ?1",
            [to],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let (Some(first_seq), Some(last_seq)) = (seq_of(first)?, seq_of(last)?) else {
        return Err(AuditError::Invalid(
            "no records in the requested time range",
        ));
    };
    if first_seq > last_seq {
        return Err(AuditError::Invalid(
            "no records in the requested time range",
        ));
    }
    let first_chain: String = tx
        .query_row(
            "SELECT chain_id FROM events WHERE seq = ?1",
            [seq_param(first_seq)?],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !is_id(&first_chain) {
        return Err(AuditError::InvalidRecord {
            seq: first_seq,
            what: "chain_id is not an id",
        });
    }
    let configured = parts.anchor_dir.is_some() || parts.anchor_dir_unknown;
    let last_anchored = match &parts.anchor_dir {
        // Never claim anchoring that was not seen: an unknown setting anchors nothing.
        Some(dir) if !parts.anchor_dir_unknown => last_anchored(&tx, dir, first_seq, last_seq)?,
        _ => None,
    };
    Ok(Plan {
        first_seq,
        last_seq,
        first_chain,
        anchor_dir_configured: configured,
        last_anchored,
    })
}

/// The highest seq in `first..=last` that a `Record`, `Immediate` or `ANCHOR_DETACHED` line of
/// its own chain's file names with the row's `record_hash`. A dir or file that cannot be read
/// gives no lines (every row then reads unanchored); a line that does not match the store
/// anchors nothing.
fn last_anchored(
    conn: &Connection,
    dir: &Path,
    first: u64,
    last: u64,
) -> Result<Option<u64>, AuditError> {
    let Some(lines) =
        anchor_dir::load(Some(dir), conn).map_err(|e| AuditError::Io(e.to_string()))?
    else {
        return Ok(None);
    };
    let mut named: Vec<(u64, &str, [u8; 32])> = lines
        .chains
        .iter()
        .flat_map(|(chain, ls)| {
            ls.iter().filter_map(move |(_, l)| match l {
                AnchorLine::Record {
                    seq, record_hash, ..
                }
                | AnchorLine::Immediate {
                    seq, record_hash, ..
                }
                | AnchorLine::Detached {
                    seq, record_hash, ..
                } => Some((*seq, chain.as_str(), *record_hash)),
                _ => None,
            })
        })
        .filter(|(seq, _, _)| (first..=last).contains(seq))
        .collect();
    named.sort_unstable_by_key(|(seq, _, _)| std::cmp::Reverse(*seq));
    let mut stmt = conn
        .prepare("SELECT chain_id, record_hash FROM events WHERE seq = ?1")
        .map_err(sql)?;
    for (seq, chain, hash) in named {
        let row: Option<(Option<String>, Option<Vec<u8>>)> = stmt
            .query_row([seq_param(seq)?], |r| Ok((r.get(0).ok(), r.get(1).ok())))
            .optional()
            .map_err(sql)?;
        if let Some((Some(c), Some(h))) = row
            && c == chain
            && <[u8; 32]>::try_from(h.as_slice()).is_ok_and(|h| ct_eq(&h, &hash))
        {
            return Ok(Some(seq));
        }
    }
    Ok(None)
}

/// A new file, `0600` on Unix, never an existing one.
fn create_private(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// A new directory, `0700` on Unix; an existing name is `AlreadyExists`.
fn create_private_dir(path: &Path) -> io::Result<()> {
    #[allow(unused_mut)]
    let mut b = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
}

/// Whether `path` names an entry of any kind (a dangling link or junction counts).
fn entry_exists(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Removes a failed export's staging directory: `manifest.json` (and its temporary file) first,
/// so that an interrupted removal never leaves a directory with a manifest; then the rest.
fn remove_staging(dir: &Path) -> io::Result<()> {
    for f in [MANIFEST_FILE, MANIFEST_TMP_FILE] {
        match std::fs::remove_file(dir.join(f)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    let _ = sync_dir(dir);
    #[cfg(any(test, feature = "testing"))]
    if crate::testing::remove_dir_fault(dir) {
        return Err(io::Error::other("injected removal failure"));
    }
    std::fs::remove_dir_all(dir)
}

/// Renames the logged export from its staging name to `final_dir`, never over an existing
/// entry: the name is checked before every attempt (`rename(2)` would replace an empty
/// directory). A refused rename is tried again a few times (a scanner holding a file).
fn publish(dir: &Path, final_dir: &Path) -> io::Result<()> {
    let mut attempt = 1;
    loop {
        if entry_exists(final_dir)? {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        match std::fs::rename(dir, final_dir) {
            Ok(()) => return Ok(()),
            Err(e) if attempt >= RENAME_ATTEMPTS => return Err(e),
            Err(_) => {
                attempt += 1;
                std::thread::sleep(RENAME_RETRY_PAUSE);
            }
        }
    }
}

/// A file written once, hashed as written.
struct HashedFile {
    w: BufWriter<File>,
    hash: Sha256,
}

impl HashedFile {
    fn create(path: &Path) -> io::Result<HashedFile> {
        Ok(HashedFile {
            w: BufWriter::new(create_private(path)?),
            hash: Sha256::new(),
        })
    }

    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        self.hash.update(line);
        self.hash.update(b"\n");
        self.w.write_all(line)?;
        self.w.write_all(b"\n")
    }

    /// Flushes and fsyncs; the SHA-256 of every byte written.
    fn finish(self) -> io::Result<[u8; 32]> {
        let f = self.w.into_inner().map_err(|e| e.into_error())?;
        f.sync_all()?;
        Ok(self.hash.finalize().into())
    }
}

/// One value of a line, in its JSON text.
enum Val<'a> {
    Text(Vec<u8>),
    /// Base64 of these bytes (no JSON escaping needed).
    B64(&'a [u8]),
    /// JSON text taken as is (the plaintext, which the store wrote as JCS).
    Json(&'a [u8]),
}

impl Val<'_> {
    fn len(&self) -> Result<usize, AuditError> {
        match self {
            Val::Text(v) => Ok(v.len()),
            Val::B64(b) => base64::encoded_len(b.len(), true)
                .and_then(|n| n.checked_add(2))
                .ok_or(AuditError::Invalid("export field too long")),
            Val::Json(b) => Ok(b.len()),
        }
    }
}

fn null() -> Val<'static> {
    Val::Text(b"null".to_vec())
}

fn jcs_text(s: &str) -> Result<Val<'static>, AuditError> {
    to_jcs_vec(&Value::String(s.to_owned()))
        .map(Val::Text)
        .map_err(|_| AuditError::Invalid("export text is not encodable"))
}

fn opt_text(s: Option<&str>) -> Result<Val<'static>, AuditError> {
    s.map_or(Ok(null()), jcs_text)
}

fn hex_val(b: &[u8]) -> Val<'static> {
    Val::Text(format!("\"{}\"", hex::encode(b)).into_bytes())
}

fn opt_hex(b: Option<&[u8]>) -> Val<'static> {
    b.map_or_else(null, hex_val)
}

/// An integer column; JCS numbers are exact only up to 2^53 − 1.
fn int_val(seq: u64, v: u64) -> Result<Val<'static>, AuditError> {
    if v > MAX_SAFE_INTEGER as u64 {
        return Err(AuditError::InvalidRecord {
            seq,
            what: "integer column beyond the JSON-safe range",
        });
    }
    Ok(Val::Text(v.to_string().into_bytes()))
}

/// Whether `plain` is JSON text in its JCS form, so it can be embedded in a line as is: the
/// store writes every payload through `to_jcs_vec`, but a line must never depend on that (a raw
/// newline would split the line, unsorted keys would break its JCS form).
fn is_jcs(plain: &[u8]) -> bool {
    serde_json::from_slice::<Value>(plain)
        .ok()
        .and_then(|v| to_jcs_vec(&v).ok())
        .map(Zeroizing::new)
        .is_some_and(|j| j.as_slice() == plain)
}

/// The `events.jsonl` line of one row (without its newline): JCS, keys in byte order (all keys
/// are ASCII, so that is RFC 8785's UTF-16 order). Built in one buffer of its exact size, which
/// is zeroized on drop (it holds the plaintext).
fn event_line(
    f: &RowFields<'_>,
    plain: &[u8],
    unanchored: bool,
) -> Result<Zeroizing<Vec<u8>>, AuditError> {
    let seq = f.seq;
    let mut parts: Vec<(&'static str, Val<'_>)> = vec![
        ("seq", int_val(seq, f.seq)?),
        ("format_version", int_val(seq, f.format_version)?),
        ("chain_id", jcs_text(f.chain_id)?),
        ("ts_utc", jcs_text(f.ts_utc)?),
        ("epoch", opt_text(f.epoch)?),
        ("request_id", opt_text(f.request_id)?),
        ("event_type", jcs_text(f.event_type)?),
        ("op_id", opt_text(f.op_id)?),
        ("op_class", opt_text(f.op_class)?),
        ("instance_id", opt_text(f.instance_id)?),
        ("target", opt_text(f.target)?),
        ("agent_name", opt_text(f.agent_name)?),
        ("agent_name_source", opt_text(f.agent_name_source)?),
        ("client_kind", opt_text(f.client_kind)?),
        ("connection_id", opt_text(f.connection_id)?),
        (
            "peer_pid",
            f.peer_pid.map_or(Ok(null()), |p| int_val(seq, p))?,
        ),
        ("peer_exe", opt_hex(f.peer_exe)),
        ("peer_origin_exe", opt_hex(f.peer_origin_exe)),
        ("os_user", opt_text(f.os_user)?),
        ("atlassian_user", opt_text(f.atlassian_user)?),
        ("atlassian_user_key", opt_text(f.atlassian_user_key)?),
        ("decision", opt_text(f.decision)?),
        ("flags", int_val(seq, f.flags)?),
        ("payload_len", int_val(seq, f.payload_len)?),
        ("payload_sha256", hex_val(f.payload_sha256)),
        ("key_id", int_val(seq, f.key_id)?),
        ("nonce", hex_val(f.nonce)),
        ("payload_ct", Val::B64(f.payload_ct)),
        ("prev_hash", hex_val(f.prev_hash)),
        ("payload_b64", Val::B64(plain)),
    ];
    if plain.len() as u64 <= MAX_EXPORT_PAYLOAD_FIELD_BYTES && is_jcs(plain) {
        parts.push(("payload", Val::Json(plain)));
    }
    if unanchored {
        parts.push(("unanchored", Val::Text(b"true".to_vec())));
    }
    parts.sort_unstable_by_key(|(k, _)| *k);
    // `{` `}`, a comma between parts, `"key":` per part.
    let mut len = 2 + parts.len().saturating_sub(1);
    for (k, v) in &parts {
        len += k.len() + 3 + v.len()?;
    }
    if len as u64 > MAX_EXPORT_LINE_BYTES {
        return Err(AuditError::InvalidRecord {
            seq,
            what: "the export line is longer than MAX_EXPORT_LINE_BYTES",
        });
    }
    let mut line = Zeroizing::new(Vec::with_capacity(len));
    line.push(b'{');
    for (i, (k, v)) in parts.iter().enumerate() {
        if i > 0 {
            line.push(b',');
        }
        line.push(b'"');
        line.extend_from_slice(k.as_bytes());
        line.extend_from_slice(b"\":");
        match v {
            Val::Text(t) => line.extend_from_slice(t),
            Val::Json(j) => line.extend_from_slice(j),
            Val::B64(b) => {
                line.push(b'"');
                let start = line.len();
                line.resize(start + v.len()? - 2, 0);
                STANDARD
                    .encode_slice(b, &mut line[start..])
                    .map_err(|_| AuditError::Invalid("export field too long"))?;
                line.push(b'"');
            }
        }
    }
    line.push(b'}');
    if line.len() != len {
        return Err(AuditError::Invalid("export line length miscounted"));
    }
    Ok(line)
}

/// What the walk carries from row to row.
struct Walk {
    next: u64,
    /// The last written row's `record_hash`.
    last_hash: Option<[u8; 32]>,
    boundary_prev_hash: Option<[u8; 32]>,
    chain_ids: Vec<String>,
    restore_records: Vec<u64>,
    key_recovered_records: Vec<u64>,
}

/// A row as selected: `FIELD_LIST` and the stored `record_hash`.
fn select_rows() -> String {
    format!(
        "SELECT {}, record_hash FROM events WHERE seq >= ?1 AND seq <= ?2 ORDER BY seq LIMIT ?3",
        FIELD_LIST.join(", ")
    )
}

fn decrypt_error(seq: u64, e: &DecryptError) -> AuditError {
    match e {
        DecryptError::PayloadHash => AuditError::PayloadHash { seq },
        _ => AuditError::Decrypt { seq },
    }
}

/// One batch in its own read transaction: the rows already written must still be the store's
/// (the batch boundary's `record_hash`, when that row is still retained) and the next one must
/// be there (a prune between batches that removed rows of the range ends the export). The cancel
/// flag is also checked before each row: a batch of large payloads can take far longer than the
/// shutdown path waits for the store (PD-181 quit).
#[allow(clippy::too_many_arguments)]
fn batch(
    store: &Store,
    conn: &Connection,
    deks: &mut Deks<'_>,
    plan: &Plan,
    limit: u64,
    w: &mut Walk,
    out: &mut HashedFile,
    ctl: &ExportControl<'_>,
) -> Result<(), AuditError> {
    #[cfg(not(any(test, feature = "testing")))]
    let _ = store;
    let tx = conn.unchecked_transaction().map_err(sql)?;
    if let Some(last) = w.last_hash {
        let boundary: Option<Option<Vec<u8>>> = tx
            .query_row(
                "SELECT record_hash FROM events WHERE seq = ?1",
                [seq_param(w.next - 1)?],
                |r| Ok(r.get::<_, Vec<u8>>(0).ok()),
            )
            .optional()
            .map_err(sql)?;
        if let Some(stored) = boundary
            && !stored
                .as_deref()
                .and_then(|h| <[u8; 32]>::try_from(h).ok())
                .is_some_and(|h| ct_eq(&h, &last))
        {
            return Err(AuditError::Invalid(
                "the exported records changed during the export",
            ));
        }
    }
    let mut stmt = tx.prepare(&select_rows()).map_err(sql)?;
    let mut rows = stmt
        .query([
            seq_param(w.next)?,
            seq_param(plan.last_seq)?,
            i64::try_from(limit).unwrap_or(i64::MAX),
        ])
        .map_err(sql)?;
    let mut first = true;
    while let Some(row) = rows.next().map_err(sql)? {
        #[cfg(any(test, feature = "testing"))]
        store.fault(crate::testing::FaultPoint::ExportRow)?;
        check_cancel(ctl)?;
        let expected = w.next;
        let f = RowFields::from_row(row).map_err(|_| AuditError::InvalidRecord {
            seq: expected,
            what: "the record's columns are unreadable",
        })?;
        if f.seq != expected {
            // At a batch start this is a prune of not-yet-exported rows during the export, or a
            // hole that was always there; the export cannot tell them apart.
            return Err(if first {
                AuditError::Invalid(MISSING_RECORD)
            } else {
                AuditError::InvalidRecord {
                    seq: expected,
                    what: "the record is missing",
                }
            });
        }
        first = false;
        let stored: [u8; 32] = match row.get_ref(FIELD_LIST.len()) {
            Ok(ValueRef::Blob(b)) => <[u8; 32]>::try_from(b).ok(),
            _ => None,
        }
        .ok_or(AuditError::InvalidRecord {
            seq: f.seq,
            what: "record_hash is not 32 bytes",
        })?;
        let plain = deks
            .decrypt(&tx, &f)
            .map_err(sql)?
            .map_err(|e| decrypt_error(f.seq, &e))?;
        let line = event_line(&f, &plain, plan.unanchored(f.seq))?;
        out.write_line(&line).map_err(io)?;
        if w.boundary_prev_hash.is_none() {
            w.boundary_prev_hash = Some(*f.prev_hash);
        }
        if w.chain_ids.last().map(String::as_str) != Some(f.chain_id) {
            w.chain_ids.push(f.chain_id.to_owned());
        }
        if f.event_type == EventType::RESTORE.as_str() {
            w.restore_records.push(f.seq);
        } else if f.event_type == EventType::KEY_RECOVERED.as_str() {
            w.key_recovered_records.push(f.seq);
        }
        w.last_hash = Some(stored);
        w.next = f.seq + 1;
    }
    if first {
        return Err(AuditError::Invalid(MISSING_RECORD));
    }
    Ok(())
}

/// A batch found the first record it expected missing.
const MISSING_RECORD: &str = "a record of the export range is missing";

/// Every `prune_log` row, all columns, one JCS line each.
fn write_prune_log(conn: &Connection, out: &mut HashedFile) -> Result<(), AuditError> {
    let tx = conn.unchecked_transaction().map_err(sql)?;
    let mut stmt = tx
        .prepare(
            "SELECT prune_seq, range_start, cutoff_epoch, last_pruned_record_hash, \
             first_retained_seq, prev_row_hash, row_hash FROM prune_log ORDER BY prune_seq",
        )
        .map_err(sql)?;
    let mut rows = stmt.query([]).map_err(sql)?;
    let bad = AuditError::Invalid("a prune_log row is unreadable");
    while let Some(r) = rows.next().map_err(sql)? {
        let int = |i: usize| -> Result<u64, AuditError> {
            r.get::<_, i64>(i)
                .ok()
                .and_then(|v| u64::try_from(v).ok())
                .ok_or(bad.clone())
        };
        let blob = |i: usize| -> Result<String, AuditError> {
            r.get::<_, Vec<u8>>(i)
                .map(hex::encode)
                .map_err(|_| bad.clone())
        };
        let line = to_jcs_vec(&json!({
            "prune_seq": int(0)?,
            "range_start": int(1)?,
            "cutoff_epoch": r.get::<_, String>(2).map_err(|_| bad.clone())?,
            "last_pruned_record_hash": blob(3)?,
            "first_retained_seq": int(4)?,
            "prev_row_hash": blob(5)?,
            "row_hash": blob(6)?,
        }))
        .map_err(|_| bad.clone())?;
        out.write_line(&line).map_err(io)?;
    }
    Ok(())
}

fn check_cancel(ctl: &ExportControl<'_>) -> Result<(), AuditError> {
    if ctl.cancel.load(Ordering::SeqCst) {
        return Err(AuditError::Cancelled);
    }
    Ok(())
}

impl Store {
    /// Compliance export (C.3, §8.10, PD-159..PD-161, PD-181) of `range` into a new subdirectory
    /// of `out` (see the module documentation for the format). The range resolves to the
    /// contiguous seqs from the first record with `ts_utc >= from` to the last with `ts_utc <=
    /// to`; [`TimeRange::all`] exports the first retained record to the head. `Invalid` when the
    /// range holds no record or `out` is not an absolute directory, or when an entry of the
    /// export's final or staging (`.partial`) name exists (nothing is written into it). Every
    /// row must decrypt (else `Decrypt` / `PayloadHash`, and no export): an export cannot omit a
    /// payload.
    ///
    /// `ctl.progress` runs after each batch; a set `ctl.cancel` ends the export before the next
    /// row (between batches too) or before the manifest with `Cancelled`. A prune that removes
    /// not-yet-exported rows, a restore, `shutdown()` and a failed `EXPORT` append also end it.
    /// On every `Err` but [`AuditError::ExportNotRenamed`] no `EXPORT` is logged and the staging
    /// directory is removed, or, when that fails, the error is [`AuditError::ExportLeftover`].
    /// A caller that quits the process must set `ctl.cancel` and wait for this call to return
    /// (PD-181): a process that exits while it runs leaves the staging directory behind.
    pub fn export(
        &self,
        range: TimeRange,
        out: RustChosenPath,
        ctl: &ExportControl<'_>,
    ) -> Result<ExportReceipt, AuditError> {
        let parts = self.export_parts()?;
        let out = out.path();
        if !out.is_absolute() {
            return Err(AuditError::Invalid(
                "the export location is not an absolute path",
            ));
        }
        if !out.is_dir() {
            return Err(AuditError::Invalid(
                "the export location is not a directory",
            ));
        }
        let from = range.from_utc.to_rfc3339_ms();
        let to = range.to_utc.to_rfc3339_ms();
        if from > to {
            return Err(AuditError::Invalid(
                "the export range ends before it starts",
            ));
        }
        let conn = schema::open_ro(&parts.db_path).map_err(|e| AuditError::Io(e.to_string()))?;
        let plan = resolve_range(&conn, &from, &to, &parts)?;
        let exported_at = ts_text(parts.now)?;
        let name = format!(
            "atlas-duck-export-{}-{}-{}-{}",
            plan.first_chain,
            plan.first_seq,
            plan.last_seq,
            compact_stamp(&exported_at)
        );
        let final_dir = out.join(&name);
        let staging_name = format!("{name}{PARTIAL_SUFFIX}");
        let dir = out.join(&staging_name);
        if entry_exists(&final_dir).map_err(io)? {
            return Err(AuditError::Invalid(
                "an export directory of this name already exists",
            ));
        }
        create_private_dir(&dir).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                AuditError::Invalid("an export directory of this name already exists")
            } else {
                io(e)
            }
        })?;
        // Best effort, like the backup's (T2 ruling): the new entry in the chosen folder.
        let _ = sync_dir(out);
        let r = self.export_into(
            &conn,
            &parts,
            &plan,
            &dir,
            &name,
            (from, to),
            exported_at,
            ctl,
        );
        drop(conn);
        let receipt = match r {
            Ok(receipt) => receipt,
            // Every file of the export is closed by now (Windows cannot remove an open one).
            Err(e) => {
                return Err(match remove_staging(&dir) {
                    Ok(()) => e,
                    Err(_) => AuditError::ExportLeftover {
                        dir_name: staging_name,
                        cause: Box::new(e),
                    },
                });
            }
        };
        // The `EXPORT` is logged: only now does the directory get its final name.
        if publish(&dir, &final_dir).is_err() {
            return Err(AuditError::ExportNotRenamed(Box::new(ExportReceipt {
                dir_name: staging_name,
                ..receipt
            })));
        }
        // Best effort, as above.
        let _ = sync_dir(out);
        Ok(receipt)
    }

    #[allow(clippy::too_many_arguments)]
    fn export_into(
        &self,
        conn: &Connection,
        parts: &Parts,
        plan: &Plan,
        dir: &Path,
        name: &str,
        (from, to): (String, String),
        exported_at: String,
        ctl: &ExportControl<'_>,
    ) -> Result<ExportReceipt, AuditError> {
        let total = plan.rows();
        let mut deks = Deks::new(&parts.kek);
        let mut events = HashedFile::create(&dir.join(EVENTS_FILE)).map_err(io)?;
        let mut w = Walk {
            next: plan.first_seq,
            last_hash: None,
            boundary_prev_hash: None,
            chain_ids: Vec::new(),
            restore_records: Vec::new(),
            key_recovered_records: Vec::new(),
        };
        while w.next <= plan.last_seq {
            check_cancel(ctl)?;
            self.serving(parts.generation)?;
            batch(
                self,
                conn,
                &mut deks,
                plan,
                parts.batch_rows,
                &mut w,
                &mut events,
                ctl,
            )?;
            (ctl.progress)(w.next - plan.first_seq, total);
        }
        let events_sha256 = events.finish().map_err(io)?;
        let mut prune_log = HashedFile::create(&dir.join(PRUNE_LOG_FILE)).map_err(io)?;
        write_prune_log(conn, &mut prune_log)?;
        let prune_log_sha256 = prune_log.finish().map_err(io)?;
        check_cancel(ctl)?;
        self.serving(parts.generation)?;
        let (Some(head_hash), Some(boundary)) = (w.last_hash, w.boundary_prev_hash) else {
            return Err(AuditError::Invalid("the export holds no record"));
        };
        let manifest = to_jcs_vec(&json!({
            "format": EXPORT_FORMAT,
            "app_version": APP_VERSION,
            "build_id": BUILD_ID,
            "exported_at": exported_at,
            "install": {
                "install_id": parts.install_id,
                "host": parts.host,
                "os_user": parts.os_user,
            },
            "requested_range": { "from_utc": from, "to_utc": to },
            "first_seq": plan.first_seq,
            "last_seq": plan.last_seq,
            "rows": total,
            "boundary_prev_hash": hex::encode(boundary),
            "head": { "seq": plan.last_seq, "record_hash": hex::encode(head_hash) },
            "chain_ids": w.chain_ids,
            "restore_records": w.restore_records,
            "key_recovered_records": w.key_recovered_records,
            "anchor_dir_configured": plan.anchor_dir_configured,
            "last_anchored_seq": plan.last_anchored,
            "events_sha256": hex::encode(events_sha256),
            "prune_log_sha256": hex::encode(prune_log_sha256),
            "accountability": ACCOUNTABILITY,
        }))
        .map_err(|_| AuditError::Invalid("the manifest is not encodable"))?;
        if manifest.len() as u64 > MAX_EXPORT_MANIFEST_BYTES {
            return Err(AuditError::Invalid("the manifest is longer than 1 MiB"));
        }
        // Written aside and renamed, as a backup bundle's: a `manifest.json` that exists is whole.
        let tmp = dir.join(MANIFEST_TMP_FILE);
        let mut f = create_private(&tmp).map_err(io)?;
        f.write_all(&manifest).map_err(io)?;
        f.sync_all().map_err(io)?;
        drop(f);
        std::fs::rename(&tmp, dir.join(MANIFEST_FILE)).map_err(io)?;
        // Best effort, as for a backup bundle (T2 ruling): every file is written and fsynced, and
        // a share or FAT target that cannot flush a directory must not fail the export.
        let _ = sync_dir(dir);
        let manifest_sha256: [u8; 32] = Sha256::digest(&manifest).into();
        #[cfg(any(test, feature = "testing"))]
        self.fault(crate::testing::FaultPoint::ExportBeforeAppend)?;
        let p = PreparedEvent::system(
            EventType::EXPORT,
            &json!({
                "manifest_sha256": hex::encode(manifest_sha256),
                "first_seq": plan.first_seq,
                "last_seq": plan.last_seq,
                "rows": total,
            }),
        )?;
        let c = self.append_for_generation(p, parts.generation)?;
        Ok(ExportReceipt {
            dir_name: name.to_owned(),
            manifest_sha256,
            first_seq: plan.first_seq,
            last_seq: plan.last_seq,
            rows: total,
            chain_ids: w.chain_ids,
            unanchored_from: plan.unanchored_from(),
            export_seq: c.seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_bound_covers_the_zstd_worst_case() {
        let worst = zstd::zstd_safe::compress_bound(MAX_PAYLOAD_LEN as usize) as u64 + AEAD_TAG_LEN;
        assert!(MAX_EXPORT_CT_LEN >= worst, "{MAX_EXPORT_CT_LEN} < {worst}");
        // Smaller plaintexts have smaller bounds (the 64-byte term only below 128 KiB).
        for n in [0usize, 1, 1000, 128 * 1024 - 1, 1 << 20] {
            assert!(zstd::zstd_safe::compress_bound(n) as u64 + AEAD_TAG_LEN <= MAX_EXPORT_CT_LEN);
        }
    }

    #[test]
    fn line_cap_is_about_257_mib() {
        let mib = MAX_EXPORT_LINE_BYTES / (1024 * 1024);
        assert!((257..=258).contains(&mib), "{mib} MiB");
    }

    /// M-2: a plaintext that is JSON but not JCS (a raw newline, unsorted keys, spaces) gets no
    /// `payload` field; the line stays one JCS line and `payload_b64` carries the bytes.
    #[test]
    fn payload_field_only_for_jcs_plaintext() {
        let (hash, nonce) = ([1u8; 32], [2u8; 12]);
        let f = RowFields {
            seq: 7,
            format_version: 1,
            chain_id: "0123456789abcdef0123456789abcdef",
            ts_utc: "2026-10-08T12:00:00.000Z",
            epoch: None,
            request_id: None,
            event_type: "APP_START",
            op_id: None,
            op_class: None,
            instance_id: None,
            target: None,
            agent_name: None,
            agent_name_source: None,
            client_kind: None,
            connection_id: None,
            peer_pid: None,
            peer_exe: None,
            peer_origin_exe: None,
            os_user: None,
            atlassian_user: None,
            atlassian_user_key: None,
            decision: None,
            flags: 0,
            payload_len: 0,
            payload_sha256: &hash,
            key_id: 1,
            nonce: &nonce,
            payload_ct: b"ct",
            prev_hash: &hash,
        };
        let line = |plain: &[u8]| -> Value {
            let l = event_line(&f, plain, false).expect("line");
            assert!(!l.contains(&b'\n'), "one line");
            let v: Value = serde_json::from_slice(&l).expect("JSON");
            assert_eq!(to_jcs_vec(&v).expect("jcs"), l.to_vec(), "the line is JCS");
            v
        };
        let jcs = br#"{"a":1,"b":[true,null,"x"]}"#;
        assert_eq!(
            line(jcs)["payload"],
            json!({"a": 1, "b": [true, null, "x"]})
        );
        for bad in [
            &b"{\"a\":1}\n"[..],
            b"\n{\"a\":1}",
            b"{\"b\":1,\"a\":2}",
            b"{ \"a\":1}",
            b"not json",
        ] {
            let v = line(bad);
            assert!(
                v.get("payload").is_none(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
            assert_eq!(v["payload_b64"], STANDARD.encode(bad));
        }
    }

    #[test]
    fn ids_only_become_path_components() {
        assert!(is_id("0123456789abcdef0123456789abcdef"));
        for bad in [
            "",
            "0123456789ABCDEF0123456789abcdef",
            "../../../../../../../../../../etc",
            "0123456789abcdef0123456789abcde/",
        ] {
            assert!(!is_id(bad), "{bad}");
        }
    }
}
