//! Full backup (§8.10): a bundle directory `<chosen>/atlas-duck-backup-<ts>-<chain8>/` with a
//! `VACUUM INTO` snapshot (`audit.db`), the recovery blob (`recovery.bin`) and `manifest.json`
//! naming the snapshot head (F.1, F.11). The bundle never carries a credential (I-46, L39): the
//! snapshot is opened, any `vault` table is dropped and the file is vacuumed again with
//! `secure_delete` on, so no wrapped token survives in a free page; the manifest is written
//! last. The backup runs on the writer between commands, so no append interleaves, and is
//! logged as `BACKUP` after the snapshot head.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use atlas_duck_ipc::build_info::APP_VERSION;
use atlas_duck_ipc::jcs::to_jcs_vec;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::encoding::ZERO_HASH;
use crate::error::{AuditError, RestoreError};
use crate::open::sync_dir;
use crate::types::EventType;
use crate::verify::{self, hex32};
use crate::writer::{PreparedEvent, Writer, sql, ts_text};

/// The bundle's files (F.1).
pub(crate) const SNAPSHOT_FILE: &str = "audit.db";
pub(crate) const RECOVERY_FILE: &str = "recovery.bin";
pub(crate) const MANIFEST_FILE: &str = "manifest.json";
const MANIFEST_TMP: &str = "manifest.json.tmp";

/// `manifest.json`'s `format` (F.11).
pub(crate) const BUNDLE_FORMAT_PREFIX: &str = "atlas-duck-backup/v";
pub(crate) const BUNDLE_FORMAT_VERSION: u64 = 1;

/// A manifest larger than this is not one this build wrote.
pub(crate) const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

/// What a backup produced (C.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReceipt {
    pub bundle_dir: PathBuf,
    /// The snapshot head (also the manifest's `head`).
    pub head_seq: u64,
    pub head_hash: [u8; 32],
    /// SHA-256 of the `manifest.json` bytes; also in the `BACKUP` record, so the recipient can
    /// compare it out of band.
    pub manifest_sha256: [u8; 32],
    /// The `BACKUP` record.
    pub backup_seq: u64,
}

/// `manifest.json` (F.11, plan decision), written as JCS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub(crate) created_at: String,
    pub(crate) app_version: String,
    pub(crate) install_id: String,
    pub(crate) chain_id: String,
    pub(crate) head_seq: u64,
    pub(crate) head_hash: [u8; 32],
    pub(crate) first_retained_seq: u64,
    pub(crate) first_retained_prev_hash: [u8; 32],
    pub(crate) genesis_hash: [u8; 32],
    pub(crate) user_version: u32,
    pub(crate) snapshot_sha256: [u8; 32],
    pub(crate) recovery_sha256: [u8; 32],
}

impl Manifest {
    fn to_json(&self) -> Value {
        json!({
            "format": format!("{BUNDLE_FORMAT_PREFIX}{BUNDLE_FORMAT_VERSION}"),
            "created_at": self.created_at,
            "app_version": self.app_version,
            "install_id": self.install_id,
            "chain_id": self.chain_id,
            "head": { "seq": self.head_seq, "record_hash": hex::encode(self.head_hash) },
            "first_retained": {
                "seq": self.first_retained_seq,
                "prev_hash": hex::encode(self.first_retained_prev_hash),
            },
            "genesis_hash": hex::encode(self.genesis_hash),
            "user_version": self.user_version,
            "snapshot_sha256": hex::encode(self.snapshot_sha256),
            "recovery_sha256": hex::encode(self.recovery_sha256),
        })
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, AuditError> {
        to_jcs_vec(&self.to_json()).map_err(|_| AuditError::Invalid("manifest is not encodable"))
    }

    /// Parses a manifest of this format, exactly the keys it writes. A later format version
    /// is `SnapshotNewer`; anything else that is not such a manifest is `NotABundle`.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Manifest, RestoreError> {
        let bad = || RestoreError::NotABundle;
        let v: Value = serde_json::from_slice(bytes).map_err(|_| bad())?;
        let o = v.as_object().ok_or_else(bad)?;
        let format = o.get("format").and_then(Value::as_str).ok_or_else(bad)?;
        let version = format
            .strip_prefix(BUNDLE_FORMAT_PREFIX)
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or_else(bad)?;
        if version > BUNDLE_FORMAT_VERSION {
            return Err(RestoreError::SnapshotNewer {
                found: format!("backup format {version}"),
            });
        }
        if version != BUNDLE_FORMAT_VERSION {
            return Err(bad());
        }
        const KEYS: [&str; 11] = [
            "app_version",
            "chain_id",
            "created_at",
            "first_retained",
            "format",
            "genesis_hash",
            "head",
            "install_id",
            "recovery_sha256",
            "snapshot_sha256",
            "user_version",
        ];
        if o.len() != KEYS.len() || !KEYS.iter().all(|k| o.contains_key(*k)) {
            return Err(bad());
        }
        let text = |m: &Map<String, Value>, k: &str| {
            m.get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(bad)
        };
        let hash = |m: &Map<String, Value>, k: &str| {
            m.get(k)
                .and_then(Value::as_str)
                .and_then(hex32)
                .ok_or_else(bad)
        };
        let int =
            |m: &Map<String, Value>, k: &str| m.get(k).and_then(Value::as_u64).ok_or_else(bad);
        let pair = |k: &str, a: &str, b: &str| {
            let m = o.get(k).and_then(Value::as_object).ok_or_else(bad)?;
            if m.len() != 2 {
                return Err(bad());
            }
            Ok((int(m, a)?, hash(m, b)?))
        };
        let (head_seq, head_hash) = pair("head", "seq", "record_hash")?;
        let (first_retained_seq, first_retained_prev_hash) =
            pair("first_retained", "seq", "prev_hash")?;
        Ok(Manifest {
            created_at: text(o, "created_at")?,
            app_version: text(o, "app_version")?,
            install_id: text(o, "install_id")?,
            chain_id: text(o, "chain_id")?,
            head_seq,
            head_hash,
            first_retained_seq,
            first_retained_prev_hash,
            genesis_hash: hash(o, "genesis_hash")?,
            user_version: u32::try_from(int(o, "user_version")?).map_err(|_| bad())?,
            snapshot_sha256: hash(o, "snapshot_sha256")?,
            recovery_sha256: hash(o, "recovery_sha256")?,
        })
    }

    /// Reads `manifest.json` of `bundle` (bounded).
    pub(crate) fn read(bundle: &Path) -> Result<Manifest, RestoreError> {
        let f = std::fs::File::open(bundle.join(MANIFEST_FILE))
            .map_err(|_| RestoreError::NotABundle)?;
        let mut bytes = Vec::new();
        f.take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RestoreError::NotABundle)?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(RestoreError::NotABundle);
        }
        Manifest::parse(&bytes)
    }
}

pub(crate) fn io(e: std::io::Error) -> AuditError {
    AuditError::Io(e.to_string())
}

/// SHA-256 of a file's bytes, streamed.
pub(crate) fn file_sha256(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

/// `path` as an SQL string literal (`'` doubled), for `VACUUM INTO`.
pub(crate) fn sql_literal(path: &Path) -> Result<String, AuditError> {
    let s = path
        .to_str()
        .ok_or(AuditError::Invalid("the path is not valid UTF-8"))?;
    if s.contains('\0') {
        return Err(AuditError::Invalid("the path contains a NUL character"));
    }
    Ok(format!("'{}'", s.replace('\'', "''")))
}

/// Writes `bytes` to a new file and fsyncs it (never overwrites).
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Drops any `vault` table of a snapshot and vacuums it with `secure_delete` on, in rollback
/// journal mode, so the closed file is self-contained and holds no freed page of it (§8.10).
pub(crate) fn strip_snapshot(path: &Path) -> Result<(), AuditError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sql)?;
    let mode: String = conn
        .pragma_update_and_check(None, "journal_mode", "DELETE", |r| r.get(0))
        .map_err(sql)?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(AuditError::Io(format!("snapshot journal_mode {mode}")));
    }
    conn.execute_batch("PRAGMA secure_delete = ON; DROP TABLE IF EXISTS vault; VACUUM;")
        .map_err(sql)?;
    conn.close().map_err(|(_, e)| sql(e))?;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .and_then(|f| f.sync_all())
        .map_err(io)
}

/// `YYYYMMDDTHHMMSSZ` of an RFC 3339 `ts_utc` text (F.1 bundle name; no `:` on Windows).
fn compact_stamp(ts: &str) -> String {
    let secs = ts.split('.').next().unwrap_or(ts);
    let mut s: String = secs
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'T')
        .collect();
    s.push('Z');
    s
}

impl Writer {
    /// `Store::backup` (§8.10) on the writer thread. On any failure the partial bundle
    /// directory is removed (best effort; a bundle without `manifest.json` is never valid)
    /// and nothing is logged.
    pub(crate) fn backup_run(
        &mut self,
        out: &Path,
        install_id: &str,
    ) -> Result<BackupReceipt, AuditError> {
        let head = self.st.head.clone();
        if head.seq == 0 {
            return Err(AuditError::Invalid("the store has no records"));
        }
        if !out.is_dir() {
            return Err(AuditError::Io(
                "the backup location is not a directory".into(),
            ));
        }
        let created_at = ts_text(self.st.clock.now_utc())?;
        let chain8: String = head.chain_id.chars().take(8).collect();
        let name = format!("atlas-duck-backup-{}-{chain8}", compact_stamp(&created_at));
        let dir = out.join(&name);
        std::fs::create_dir(&dir).map_err(io)?;
        let r = self.write_bundle(&dir, &name, &head, created_at, install_id);
        if r.is_err() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        r
    }

    fn write_bundle(
        &mut self,
        dir: &Path,
        name: &str,
        head: &crate::writer::Head,
        created_at: String,
        install_id: &str,
    ) -> Result<BackupReceipt, AuditError> {
        let snapshot = dir.join(SNAPSHOT_FILE);
        self.conn
            .execute_batch(&format!("VACUUM INTO {}", sql_literal(&snapshot)?))
            .map_err(sql)?;
        strip_snapshot(&snapshot)?;
        // The snapshot is the store at `head`, nothing more.
        let snap_head: Option<(i64, Vec<u8>)> = Connection::open_with_flags(
            &snapshot,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .and_then(|c| {
            c.query_row(
                "SELECT seq, record_hash FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
        })
        .map_err(sql)?;
        if snap_head != Some((crate::writer::int(head.seq)?, head.hash.to_vec())) {
            return Err(AuditError::Io(
                "the snapshot does not end at the store head".into(),
            ));
        }
        let blob: Vec<u8> = self
            .conn
            .query_row("SELECT blob FROM recovery WHERE id = 1", [], |r| r.get(0))
            .map_err(sql)?;
        write_new(&dir.join(RECOVERY_FILE), &blob).map_err(io)?;
        let user_version: u32 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(sql)?;
        let (first_retained_seq, first_retained_prev_hash) =
            verify::latest_prune_values(&self.conn).map_err(sql)?;
        let manifest = Manifest {
            created_at,
            app_version: APP_VERSION.to_string(),
            install_id: install_id.to_string(),
            chain_id: head.chain_id.clone(),
            head_seq: head.seq,
            head_hash: head.hash,
            first_retained_seq,
            first_retained_prev_hash,
            genesis_hash: self.st.genesis_hash.unwrap_or(ZERO_HASH),
            user_version,
            snapshot_sha256: file_sha256(&snapshot).map_err(io)?,
            recovery_sha256: file_sha256(&dir.join(RECOVERY_FILE)).map_err(io)?,
        };
        let bytes = manifest.to_bytes()?;
        // Last, and atomically: a bundle with a manifest is complete.
        let tmp = dir.join(MANIFEST_TMP);
        write_new(&tmp, &bytes).map_err(io)?;
        std::fs::rename(&tmp, dir.join(MANIFEST_FILE)).map_err(io)?;
        sync_dir(dir).map_err(io)?;
        let manifest_sha256: [u8; 32] = Sha256::digest(&bytes).into();
        let p = PreparedEvent::system(
            EventType::BACKUP,
            &json!({
                "bundle_dir_name": name,
                "head": { "seq": head.seq, "record_hash": hex::encode(head.hash) },
                "manifest_sha256": hex::encode(manifest_sha256),
            }),
        )?;
        let c = self
            .append_tx(vec![p])?
            .pop()
            .ok_or_else(|| AuditError::AppendFailed("the writer returned no row".into()))?;
        Ok(BackupReceipt {
            bundle_dir: dir.to_path_buf(),
            head_seq: head.seq,
            head_hash: head.hash,
            manifest_sha256,
            backup_seq: c.seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_stamp_drops_separators_and_millis() {
        assert_eq!(
            compact_stamp("2026-10-08T12:34:56.789Z"),
            "20261008T123456Z"
        );
    }

    #[test]
    fn sql_literal_doubles_quotes() {
        assert_eq!(sql_literal(Path::new("a'b")).expect("literal"), "'a''b'");
    }
}
