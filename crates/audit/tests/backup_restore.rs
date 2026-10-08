//! Backup bundle (§8.10), restore-as-continuation (§8.11), interrupted restore and "Finish
//! restore" (§8.7): the bundle never carries a credential (I-46), a restore verifies the
//! snapshot before anything is written, keeps this install's `install_id`, starts a new
//! `chain_id` and survives a crash between its commit, the KEK re-seal and the anchor reset
//! (U-15, U-16, U-22 restore half).

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use atlas_duck_audit::keystore::{EntryName, KeyStore};
use atlas_duck_audit::testing::MemKeyring;
use atlas_duck_audit::types::{Confirmed, RustChosenPath};
use atlas_duck_audit::{SettingChange, Store};
use base64::Engine;
use common::*;
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------------------
// helpers

const INSTANCES: [&str; 2] = ["i1", "i2"];

fn confirmed() -> Confirmed {
    Confirmed {
        dialog_text_sha256: [7; 32],
    }
}

fn chosen(p: &Path) -> RustChosenPath {
    RustChosenPath::from_native_dialog(p.to_path_buf())
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn payload(store: &Store, seq: u64) -> Value {
    serde_json::from_slice(&store.read_payload(seq).expect("read_payload")).expect("json")
}

fn ro(path: &Path) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).expect("read-only open")
}

fn files_in(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect()
}

fn tables(c: &Connection) -> BTreeSet<String> {
    let mut st = c
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .expect("prepare");
    st.query_map([], |r| r.get::<_, String>(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

/// Instance origins for both instances (confirmed) and a PAT entry for each.
fn with_instances(store: &Store, f: &Fixture, pat: &dyn Fn(&str) -> Vec<u8>) {
    for id in INSTANCES {
        store
            .apply_setting(
                SettingChange::InstanceOrigin {
                    instance_id: id.into(),
                    origin: Some(format!("https://{id}.example")),
                },
                Some(confirmed()),
            )
            .expect("origin");
        f.keys()
            .set(&EntryName::Pat(id.into()), &pat(id))
            .expect("pat");
    }
}

fn random_canary() -> String {
    let mut b = [0u8; 12];
    getrandom::fill(&mut b).expect("random");
    format!("PAT-CANARY-{}", hex::encode(b))
}

/// The base64 characters that encode `secret` wherever it sits in a larger blob: for each of
/// the three byte alignments, the run of 4-character groups that depend on `secret` alone.
fn base64_cores(secret: &[u8]) -> Vec<String> {
    let engines = [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::URL_SAFE,
    ];
    let mut out = Vec::new();
    for e in engines {
        out.push(e.encode(secret));
        out.push(e.encode(secret).trim_end_matches('=').to_string());
        for k in 0..3usize {
            let mut buf = vec![b'x'; k];
            buf.extend_from_slice(secret);
            let enc = e.encode(&buf);
            let start = 4 * k.div_ceil(3);
            let end = 4 * ((k + secret.len()) / 3);
            out.push(enc[start..end].to_string());
        }
    }
    out
}

/// `secret` in none of the encodings I-46 names: raw, base64 (standard and URL-safe, with and
/// without padding, at every alignment) and percent-encoded (every byte, both cases).
fn assert_absent(name: &str, bytes: &[u8], secret: &str) {
    let mut needles: Vec<Vec<u8>> = vec![secret.as_bytes().to_vec()];
    needles.extend(
        base64_cores(secret.as_bytes())
            .into_iter()
            .map(String::into_bytes),
    );
    let pct_upper: String = secret.bytes().map(|b| format!("%{b:02X}")).collect();
    needles.push(pct_upper.to_lowercase().into_bytes());
    needles.push(pct_upper.into_bytes());
    for n in needles {
        assert!(
            !bytes.windows(n.len()).any(|w| w == n.as_slice()),
            "{name} contains the canary ({})",
            String::from_utf8_lossy(&n)
        );
    }
}

/// A store with `n` mixed records after `GENESIS`, the head anchored.
fn store_with(n: usize) -> (Store, Fixture) {
    let (store, f) = new_store(fake_clock(START), MemKeyring::new());
    if n > 0 {
        store.append_batch(mixed(n)).expect("append_batch");
    }
    store.flush_head_anchor().expect("flush");
    (store, f)
}

fn backup_into(store: &Store, out: &Path) -> atlas_duck_audit::BackupReceipt {
    store.backup(chosen(out)).expect("backup")
}

fn bundle_file(bundle: &Path, name: &str) -> PathBuf {
    bundle.join(name)
}

// ---------------------------------------------------------------------------------------
// Backup (§8.10)

#[test]
fn backup_bundle_contents() {
    let (store, f) = store_with(30);
    let (head_seq, head_hash, chain_id) = store.head();
    let out = tempfile::tempdir().expect("out dir");
    let r = backup_into(&store, out.path());

    assert_eq!(r.bundle_dir.parent(), Some(out.path()));
    let name = r
        .bundle_dir
        .file_name()
        .expect("name")
        .to_string_lossy()
        .into_owned();
    assert!(
        name.starts_with("atlas-duck-backup-20261008T120000Z-"),
        "{name}"
    );
    assert!(name.ends_with(&chain_id[..8]), "{name}");
    assert_eq!((r.head_seq, r.head_hash), (head_seq, head_hash));
    assert_eq!(
        files_in(&r.bundle_dir),
        ["audit.db", "manifest.json", "recovery.bin"]
            .into_iter()
            .map(String::from)
            .collect()
    );

    // recovery.bin is the store's recovery row.
    let live_blob: Vec<u8> = raw_conn(&f)
        .query_row("SELECT blob FROM recovery WHERE id = 1", [], |r| r.get(0))
        .expect("recovery row");
    let recovery = std::fs::read(bundle_file(&r.bundle_dir, "recovery.bin")).expect("recovery");
    assert_eq!(recovery, live_blob);

    // The manifest (F.11), written as JCS.
    let manifest_bytes =
        std::fs::read(bundle_file(&r.bundle_dir, "manifest.json")).expect("manifest");
    let m: Value = serde_json::from_slice(&manifest_bytes).expect("manifest json");
    assert_eq!(
        atlas_duck_ipc::jcs::to_jcs_vec(&m).expect("jcs"),
        manifest_bytes,
        "manifest.json is JCS"
    );
    let keys: BTreeSet<&str> = m
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
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
        ]
        .into_iter()
        .collect()
    );
    let snapshot = std::fs::read(bundle_file(&r.bundle_dir, "audit.db")).expect("snapshot");
    let rows = dump_rows(&f);
    assert_eq!(m["format"], "atlas-duck-backup/v1");
    assert_eq!(m["created_at"], START);
    assert_eq!(m["install_id"], f.install_id.as_str());
    assert_eq!(m["chain_id"], chain_id.as_str());
    assert_eq!(m["head"]["seq"], head_seq);
    assert_eq!(m["head"]["record_hash"], hex::encode(head_hash));
    assert_eq!(m["first_retained"]["seq"], 1);
    assert_eq!(m["first_retained"]["prev_hash"], hex::encode([0u8; 32]));
    assert_eq!(m["genesis_hash"], hex::encode(rows[0].record_hash));
    assert_eq!(m["user_version"], 1);
    assert_eq!(m["snapshot_sha256"], hex::encode(sha(&snapshot)));
    assert_eq!(m["recovery_sha256"], hex::encode(sha(&recovery)));

    // The snapshot holds the chain up to the manifest head and no vault table.
    let c = ro(&bundle_file(&r.bundle_dir, "audit.db"));
    assert!(!tables(&c).contains("vault"));
    let snap_rows = dump_conn(&c);
    assert_eq!(snap_rows.len() as u64, head_seq);
    assert_eq!(snap_rows.last().expect("rows").record_hash, head_hash);
    drop(c);

    // BACKUP is appended after the snapshot head, not inside the snapshot.
    assert_eq!(r.backup_seq, head_seq + 1);
    assert_eq!(store.head().0, head_seq + 1);
    assert_eq!(rows.last().expect("rows").seq, head_seq + 1);
    assert_eq!(rows.last().expect("rows").event_type, "BACKUP");
    let p = payload(&store, r.backup_seq);
    assert_eq!(p["bundle_dir_name"], name.as_str());
    assert_eq!(p["head"]["seq"], head_seq);
    assert_eq!(p["head"]["record_hash"], hex::encode(head_hash));
    assert_eq!(p["manifest_sha256"], hex::encode(sha(&manifest_bytes)));
    assert_eq!(r.manifest_sha256, sha(&manifest_bytes));

    assert!(store.full_verify().is_empty());
}

#[test]
fn backup_drops_a_vault_table_of_the_live_store() {
    let (store, f) = store_with(5);
    let canary = random_canary();
    {
        // A table v1 never has (passphrase mode is v1.1, L39): still never copied.
        let c = raw_conn(&f);
        c.execute_batch("CREATE TABLE vault (instance_id TEXT, ct BLOB)")
            .expect("vault");
        c.execute(
            "INSERT INTO vault VALUES ('i1', ?1)",
            [canary.as_bytes().repeat(50)],
        )
        .expect("vault row");
    }
    let out = tempfile::tempdir().expect("out dir");
    let r = backup_into(&store, out.path());
    let c = ro(&bundle_file(&r.bundle_dir, "audit.db"));
    assert!(!tables(&c).contains("vault"));
    drop(c);
    for name in files_in(&r.bundle_dir) {
        let bytes = std::fs::read(r.bundle_dir.join(&name)).expect("read");
        assert_absent(&name, &bytes, &canary);
    }
}

#[test]
fn i46_backup_has_no_credentials() {
    let (store, f) = store_with(0);
    let canaries: Vec<String> = INSTANCES.iter().map(|_| random_canary()).collect();
    let by_id = |id: &str| {
        let i = INSTANCES.iter().position(|x| *x == id).expect("instance");
        canaries[i].clone().into_bytes()
    };
    with_instances(&store, &f, &by_id);
    store.append_batch(mixed(20)).expect("append_batch");
    let out = tempfile::tempdir().expect("out dir");
    let r = backup_into(&store, out.path());
    let names = files_in(&r.bundle_dir);
    assert_eq!(names.len(), 3, "{names:?}");
    for name in names {
        let bytes = std::fs::read(r.bundle_dir.join(&name)).expect("read");
        for c in &canaries {
            assert_absent(&name, &bytes, c);
        }
    }
}

#[test]
fn backup_into_a_missing_dir_leaves_nothing() {
    let (store, f) = store_with(3);
    let out = tempfile::tempdir().expect("out dir");
    let missing = out.path().join("nope");
    assert!(store.backup(chosen(&missing)).is_err());
    assert!(!missing.exists());
    assert_eq!(files_in(out.path()).len(), 0);
    let head = store.head().0;
    // Nothing logged either.
    assert_eq!(dump_rows(&f).last().expect("rows").seq, head);
}
