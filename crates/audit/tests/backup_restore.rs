//! Backup bundle (§8.10), restore-as-continuation (§8.11), interrupted restore and "Finish
//! restore" (§8.7): the bundle never carries a credential (I-46), a restore verifies the
//! snapshot before anything is written, keeps this install's `install_id`, starts a new
//! `chain_id` and survives a crash between its commit, the KEK re-seal and the anchor reset
//! (U-15, U-16, U-22 restore half).

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atlas_duck_audit::anchors::{BarrierKind, FirstRetainedAnchor, HeadAnchor};
use atlas_duck_audit::crypto::{self, Kek};
use atlas_duck_audit::error::{AuditError, OpenError, RestoreError};
use atlas_duck_audit::keystore::{
    EntryName, KeyStore, KeyStoreError, KeyringLocality, service_name,
};
use atlas_duck_audit::schema::{DB_FILE, Migration};
use atlas_duck_audit::testing::{
    FakePrune, FaultPoint, Faults, KeyOpKind, MemKeyStore, MemKeyring, insert_fake_prune,
};
use atlas_duck_audit::types::{Confirmed, EventFlags, EventType, QueryKind, RustChosenPath};
use atlas_duck_audit::{
    ArchivedDb, FindingKind, LockedReason, OpenConfig, RecoveryOffer, RestoreReport, SettingChange,
    StartupOutcome, Store, VerifyFinding, VerifyOutcome, archive_and_start_fresh, create_new_store,
    finish_restore, new_ids, open, restore_from_source,
};
use base64::Engine;
use common::*;
use rusqlite::{Connection, OpenFlags, Transaction};
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

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

// ---------------------------------------------------------------------------------------
// Restore helpers

fn pass(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn raw_entry(ring: &MemKeyring, install_id: &str, account: &str) -> Option<Vec<u8>> {
    ring.raw_get(&service_name(install_id), account)
}

fn keychain_head(ring: &MemKeyring, install_id: &str) -> Option<HeadAnchor> {
    raw_entry(ring, install_id, "head_anchor")
        .map(|b| HeadAnchor::from_entry(&b).expect("head anchor"))
}

fn keychain_first_retained(ring: &MemKeyring, install_id: &str) -> Option<FirstRetainedAnchor> {
    raw_entry(ring, install_id, "first_retained_anchor")
        .map(|b| FirstRetainedAnchor::from_entry(&b).expect("first-retained anchor"))
}

/// The keychain entries a restore may change, as stored.
fn keychain_entries(ring: &MemKeyring, install_id: &str) -> Vec<Option<Vec<u8>>> {
    [
        "kek",
        "head_anchor",
        "first_retained_anchor",
        "pat/i1",
        "pat/i2",
        "pat/i3",
    ]
    .into_iter()
    .map(|a| raw_entry(ring, install_id, a))
    .collect()
}

/// Keychain writes and deletes since op `from`, the canary self-test aside.
fn writes_since(ring: &MemKeyring, from: usize) -> Vec<String> {
    ring.ops()[from..]
        .iter()
        .filter(|o| o.kind != KeyOpKind::Get)
        .map(|o| o.full_name.clone())
        .filter(|n| !n.ends_with("/canary"))
        .collect()
}

/// Bytes of `audit.db` and `audit.db-wal` (`None` if absent).
fn db_files(dir: &Path) -> Vec<Option<Vec<u8>>> {
    [DB_FILE, "audit.db-wal"]
        .into_iter()
        .map(|n| std::fs::read(dir.join(n)).ok())
        .collect()
}

fn ready(o: StartupOutcome) -> (Store, VerifyOutcome) {
    match o {
        StartupOutcome::Ready { store, verify, .. } => (store, verify),
        other => panic!("expected Ready, got {other:?}"),
    }
}

/// `ready` plus the instance ids whose tokens the start deleted.
fn ready_pats(o: StartupOutcome) -> (Store, VerifyOutcome, Vec<String>) {
    match o {
        StartupOutcome::Ready {
            store,
            verify,
            pats_deleted,
        } => (store, verify, pats_deleted),
        other => panic!("expected Ready, got {other:?}"),
    }
}

fn restored_instances() -> Vec<String> {
    INSTANCES.map(String::from).to_vec()
}

fn kinds(f: &[VerifyFinding]) -> Vec<FindingKind> {
    f.iter().map(|x| x.kind).collect()
}

fn hex_anchor(a: &HeadAnchor) -> Value {
    json!({ "chain_id": a.chain_id, "seq": a.seq, "record_hash": hex::encode(a.record_hash) })
}

fn hex_archived(a: &ArchivedDb) -> Value {
    json!({
        "file": a.file,
        "chain_id": a.chain_id,
        "head_seq": a.head_seq,
        "head_hash": hex::encode(a.head_hash),
    })
}

/// `(seq, record_hash, chain_id)` of a closed store file's newest record.
fn file_head(path: &Path) -> (u64, [u8; 32], String) {
    let c = ro(path);
    c.query_row(
        "SELECT seq, record_hash, chain_id FROM events ORDER BY seq DESC LIMIT 1",
        [],
        |r| {
            let h: Vec<u8> = r.get(1)?;
            Ok((
                r.get::<_, i64>(0)? as u64,
                h.try_into().expect("32 bytes"),
                r.get(2)?,
            ))
        },
    )
    .expect("head")
}

fn user_version(path: &Path) -> u32 {
    ro(path)
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .expect("user_version")
}

/// Machine A: records in two months, one prune (records 1..=9 gone), more records, both
/// anchors written; instances i1 and i2 confirmed.
fn machine_a() -> (Store, Fixture) {
    let clock = fake_clock(START);
    let (a, f) = new_store(clock.clone(), MemKeyring::new());
    for id in INSTANCES {
        a.apply_setting(
            SettingChange::InstanceOrigin {
                instance_id: id.into(),
                origin: Some(format!("https://{id}.example")),
            },
            Some(confirmed()),
        )
        .expect("origin");
    }
    corroborate(&a);
    a.append_batch(mixed(20)).expect("append_batch");
    clock.advance(DAY * 35);
    corroborate_now(&a, &clock);
    a.append_batch(mixed(20)).expect("append_batch");
    sync_writer(&a);
    insert_fake_prune(
        &a,
        FakePrune {
            first_retained_seq: 10,
            cutoff: "2026-06-01".into(),
            // The real snapshot: the view's instances survive the prune of their events.
            settings: a.settings().to_json(),
            update_first_retained: true,
        },
    )
    .expect("prune");
    a.append_batch(mixed(5)).expect("append_batch");
    a.flush_head_anchor().expect("flush");
    assert!(a.full_verify().is_empty());
    (a, f)
}

/// A live store of its own install (machine B), `n` records after `GENESIS`, with instance i3
/// and its PAT entry, the head anchored; `faults` armed in its hooks.
fn machine_b(n: usize, faults: &Arc<Faults>) -> (Store, Fixture) {
    let (b, f) = new_store_with(fake_clock(START), MemKeyring::new(), |cfg| {
        cfg.hooks.faults = Some(faults.clone());
        cfg.hooks.fast_anchor_backoff = true;
    });
    b.apply_setting(
        SettingChange::InstanceOrigin {
            instance_id: "i3".into(),
            origin: Some("https://i3.example".into()),
        },
        Some(confirmed()),
    )
    .expect("origin");
    f.keys()
        .set(&EntryName::Pat("i3".into()), b"token")
        .expect("pat");
    if n > 0 {
        b.append_batch(mixed(n)).expect("append_batch");
    }
    b.flush_head_anchor().expect("flush");
    (b, f)
}

fn restore_on(
    f: &Fixture,
    cfg: OpenConfig,
    source: &Path,
    passphrase: &str,
) -> Result<(Store, RestoreReport), OpenError> {
    restore_from_source(
        &f.data,
        &f.lock,
        cfg,
        chosen(source),
        &pass(passphrase),
        None,
    )
}

/// Rewrites `manifest.json` of a bundle as JCS (what an attacker with the bundle can do).
fn write_manifest(bundle: &Path, m: &Value) {
    std::fs::write(
        bundle.join("manifest.json"),
        atlas_duck_ipc::jcs::to_jcs_vec(m).expect("jcs"),
    )
    .expect("manifest");
}

fn read_manifest(bundle: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(bundle.join("manifest.json")).expect("manifest"))
        .expect("json")
}

/// Seqs after `seq` carrying the `integrity_incident` flag.
fn incident_rows_after(f: &Fixture, seq: u64) -> Vec<u64> {
    dump_rows(f)
        .into_iter()
        .filter(|r| r.seq > seq && r.flags & EventFlags::INTEGRITY_INCIDENT.bits() != 0)
        .map(|r| r.seq)
        .collect()
}

// ---------------------------------------------------------------------------------------
// Restore (§8.11)

#[test]
fn backup_restore_roundtrip() {
    let (a, fa) = machine_a();
    let a_kek = raw_entry(&fa.ring, &fa.install_id, "kek").expect("kek");
    let a_first_retained = keychain_first_retained(&fa.ring, &fa.install_id).expect("anchor");
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let manifest = read_manifest(&bundle.bundle_dir);
    let a_rows = dump_rows(&fa);

    // Machine B: a new install, no store yet.
    let fb = fixture(fake_clock("2026-12-01T09:00:00.000Z"), MemKeyring::new());
    let (b, rep) = restore_on(&fb, fb.config(), &bundle.bundle_dir, PASSPHRASE).expect("restore");
    assert_eq!(rep.restore_seq, bundle.head_seq + 1);
    assert_eq!(rep.source_install_id, fa.install_id);
    assert_eq!(rep.source_chain_id, fa.chain_id);
    assert_ne!(rep.new_chain_id, fa.chain_id);
    assert_eq!(rep.new_chain_id.len(), 32);
    assert_eq!(rep.replaced_db, None);
    assert_eq!(rep.records_lost, 0);
    assert!(rep.pats_lost);
    assert_eq!(rep.pats_deleted, vec!["i1".to_string(), "i2".to_string()]);

    // RESTORE per F.11, chained to the snapshot head.
    assert_eq!(
        payload(&b, rep.restore_seq),
        json!({
            "install_id": fb.install_id,
            "source_install_id": fa.install_id,
            "source_chain_id": fa.chain_id,
            "source_head_seq": bundle.head_seq,
            "source_head_hash": hex::encode(bundle.head_hash),
            "new_chain_id": rep.new_chain_id,
            "backup_created_at": manifest["created_at"],
            "prior_keychain_anchor": null,
            "replaced_db": null,
            "records_lost": 0,
            "pats_lost": true,
        })
    );
    let rows = dump_rows(&fb);
    let restore = rows
        .iter()
        .find(|r| r.seq == rep.restore_seq)
        .expect("RESTORE");
    assert_eq!(restore.event_type, "RESTORE");
    assert_eq!(restore.target.as_deref(), Some(fb.install_id.as_str()));
    assert_eq!(restore.chain_id, rep.new_chain_id);
    assert_eq!(restore.prev_hash, bundle.head_hash);
    assert_eq!(
        rows[0].seq, 10,
        "the restored store keeps its first retained record"
    );
    for r in rows.iter().filter(|r| r.seq < rep.restore_seq) {
        let src = a_rows.iter().find(|x| x.seq == r.seq).expect("source row");
        assert_eq!(
            r.record_hash, src.record_hash,
            "seq {} is the source's",
            r.seq
        );
        assert_eq!(r.chain_id, fa.chain_id);
    }
    // A new DEK for the month of the snapshot head's epoch.
    let keys = key_rows(&fb);
    assert_eq!(keys.len(), key_rows(&fa).len() + 1);
    let (newest, month, _) = keys.last().expect("keys").clone();
    assert_eq!(restore.key_id, newest);
    assert_eq!(month.as_deref(), Some("2026-11"));

    // Every retained payload decrypts; the segment boundary verifies.
    for r in &rows {
        b.read_payload(r.seq).expect("payload decrypts");
    }
    assert_eq!(b.full_verify(), vec![]);

    // B's keychain holds A's KEK and anchors of the new chain.
    assert_eq!(
        raw_entry(&fb.ring, &fb.install_id, "kek").as_deref(),
        Some(a_kek.as_slice())
    );
    b.flush_head_anchor().expect("flush");
    let (seq, hash, chain) = b.head();
    assert_eq!(chain, rep.new_chain_id);
    assert_eq!(
        keychain_head(&fb.ring, &fb.install_id),
        Some(HeadAnchor {
            chain_id: chain.clone(),
            seq,
            record_hash: hash,
        })
    );
    assert_eq!(
        keychain_first_retained(&fb.ring, &fb.install_id),
        Some(FirstRetainedAnchor {
            chain_id: rep.new_chain_id.clone(),
            genesis_hash: a_first_retained.genesis_hash,
            first_retained_seq: 10,
            first_retained_prev_hash: a_first_retained.first_retained_prev_hash,
        })
    );

    // Appends continue on the new chain (after full_verify's VERIFY); the store reopens clean.
    let before = b.head().0;
    let c = b
        .append(ev(
            EventType::APP_START,
            None,
            json!({ "after": "restore" }),
        ))
        .expect("append");
    assert_eq!(c.seq, before + 1);
    assert_eq!(b.head().2, rep.new_chain_id);
    assert_eq!(b.full_verify(), vec![]);
    b.flush_head_anchor().expect("flush");
    b.shutdown();
    // The restored file is laid out as F.10 requires (prune's incremental vacuum needs it).
    {
        let c = ro(&fb.db_path());
        let pragma = |name: &str| -> String {
            c.query_row(&format!("PRAGMA {name}"), [], |r| {
                r.get::<_, rusqlite::types::Value>(0)
            })
            .map(|v| match v {
                rusqlite::types::Value::Integer(i) => i.to_string(),
                rusqlite::types::Value::Text(t) => t,
                other => format!("{other:?}"),
            })
            .expect("pragma")
        };
        assert_eq!(pragma("journal_mode"), "wal");
        assert_eq!(pragma("page_size"), "8192");
        assert_eq!(pragma("auto_vacuum"), "2", "incremental");
    }
    let (b, v) = ready(open(&fb.data, &fb.lock, fb.config()).expect("open"));
    assert_eq!(v.findings, vec![]);
    assert_eq!(b.head().2, rep.new_chain_id);
    assert!(!fb.dir.path().join("audit.db.restoring").exists());
}

#[test]
fn store_restore_cross_machine_replaces_the_live_store() {
    let (a, fa) = machine_a();
    let a_kek = raw_entry(&fa.ring, &fa.install_id, "kek").expect("kek");
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());

    let faults = Faults::new();
    let (b, fb) = machine_b(30, &faults);
    let (b_seq, b_hash, b_chain) = b.head();
    let b_anchor = keychain_head(&fb.ring, &fb.install_id).expect("head anchor");

    let rep = b
        .restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None)
        .expect("restore");
    // Live and restored instances lose their tokens.
    assert_eq!(
        rep.pats_deleted,
        vec!["i1".to_string(), "i2".to_string(), "i3".to_string()]
    );
    for id in ["i1", "i2", "i3"] {
        assert_eq!(
            raw_entry(&fb.ring, &fb.install_id, &format!("pat/{id}")),
            None
        );
    }
    // B's store is kept under archived/ and recorded.
    let replaced = rep.replaced_db.clone().expect("replaced_db");
    assert!(
        replaced
            .file
            .starts_with(&format!("archived/audit-{b_chain}-{b_seq}-")),
        "{}",
        replaced.file
    );
    assert_eq!(
        (
            replaced.chain_id.as_str(),
            replaced.head_seq,
            replaced.head_hash
        ),
        (b_chain.as_str(), b_seq, b_hash)
    );
    let archived = fb.dir.path().join(&replaced.file);
    assert_eq!(file_head(&archived), (b_seq, b_hash, b_chain.clone()));

    // This handle now serves the restored store, with A's KEK.
    assert_eq!(b.head().0, rep.restore_seq);
    assert_eq!(b.head().2, rep.new_chain_id);
    b.read_payload(rep.restore_seq).expect("RESTORE decrypts");
    b.read_payload(12).expect("a record of A decrypts");
    let a_kek_key = Kek::from_entry_bytes(&a_kek).expect("kek");
    assert_eq!(
        b.query_tag(QueryKind::Jql, "project = X"),
        crypto::query_tag(
            &crypto::query_key(&a_kek_key),
            QueryKind::Jql,
            "project = X"
        )
    );
    assert_eq!(
        b.settings().instances.keys().cloned().collect::<Vec<_>>(),
        vec!["i1".to_string(), "i2".to_string()]
    );
    let p = payload(&b, rep.restore_seq);
    assert_eq!(p["install_id"], fb.install_id.as_str());
    assert_eq!(p["prior_keychain_anchor"], hex_anchor(&b_anchor));
    assert_eq!(p["replaced_db"], hex_archived(&replaced));
    assert_eq!(
        raw_entry(&fb.ring, &fb.install_id, "kek").as_deref(),
        Some(a_kek.as_slice())
    );
    let h = b.health();
    assert_eq!(h.anchors_blocked, None);
    assert!(!h.anchor_write_failing);
    assert_eq!(h.open_incidents, 0);
    assert_eq!(
        keychain_head(&fb.ring, &fb.install_id).map(|a| a.chain_id),
        Some(rep.new_chain_id.clone())
    );
    b.append(ev(EventType::APP_START, None, json!({})))
        .expect("append");
    assert_eq!(b.full_verify(), vec![]);
    b.flush_head_anchor().expect("flush");
    b.shutdown();
    let (_b, v) = ready(open(&fb.data, &fb.lock, fb.config()).expect("open"));
    assert_eq!(v.findings, vec![]);
}

#[test]
fn i46_crafted_snapshot_with_vault_rows() {
    let (a, _fa) = machine_a();
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let canary = random_canary();
    let snapshot = bundle.bundle_dir.join("audit.db");
    {
        let c = Connection::open(&snapshot).expect("snapshot");
        c.execute_batch("CREATE TABLE vault (instance_id TEXT, ct BLOB)")
            .expect("vault");
        for id in INSTANCES {
            c.execute(
                "INSERT INTO vault VALUES (?1, ?2)",
                rusqlite::params![id, canary.as_bytes().repeat(40)],
            )
            .expect("vault row");
        }
    }
    let mut m = read_manifest(&bundle.bundle_dir);
    m["snapshot_sha256"] = json!(hex::encode(sha(&std::fs::read(&snapshot).expect("read"))));
    write_manifest(&bundle.bundle_dir, &m);

    let fb = fixture(fake_clock(START), MemKeyring::new());
    let (b, rep) = restore_on(&fb, fb.config(), &bundle.bundle_dir, PASSPHRASE).expect("restore");
    assert!(rep.pats_lost);
    assert_eq!(payload(&b, rep.restore_seq)["pats_lost"], true);
    assert_eq!(rep.pats_deleted, vec!["i1".to_string(), "i2".to_string()]);
    b.shutdown();
    let c = ro(&fb.db_path());
    assert!(!tables(&c).contains("vault"));
    drop(c);
    for name in [DB_FILE, "audit.db-wal"] {
        if let Ok(bytes) = std::fs::read(fb.dir.path().join(name)) {
            assert_absent(name, &bytes, &canary);
        }
    }
}

#[test]
fn u16_cross_machine_restore_crash_between_reseal_and_anchor_reset() {
    let (a, fa) = machine_a();
    let a_kek = raw_entry(&fa.ring, &fa.install_id, "kek").expect("kek");
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());

    let faults = Faults::new();
    let (b, fb) = machine_b(29, &faults);
    let (b_seq, b_hash, b_chain) = b.head();
    let b_anchor = keychain_head(&fb.ring, &fb.install_id).expect("head anchor");
    faults.fail(FaultPoint::AfterKekReseal, 1);
    let e = b
        .restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None)
        .expect_err("crash");
    assert_eq!(committed_incomplete(&e), Some(bundle.head_seq + 1), "{e:?}");
    drop(b);
    // The crash: A's KEK sealed, the anchors still B's.
    assert_eq!(
        raw_entry(&fb.ring, &fb.install_id, "kek").as_deref(),
        Some(a_kek.as_slice())
    );
    assert_eq!(
        keychain_head(&fb.ring, &fb.install_id),
        Some(b_anchor.clone())
    );

    let mut cfg = fb.config();
    cfg.pinned_install_id = Some(fb.install_id.clone());
    let (s, v) = ready(open(&fb.data, &fb.lock, cfg).expect("open"));
    assert_eq!(
        kinds(&v.findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    let vs = v.verify_seq.expect("VERIFY");
    assert_eq!(payload(&s, vs)["result"], "interrupted_restore_reconciled");
    assert_eq!(incident_rows_after(&fb, 0), Vec::<u64>::new());
    assert!(s.open_incidents().is_empty());

    // The anchors were reset to the new chain.
    let restore_seq = bundle.head_seq + 1;
    let p = payload(&s, restore_seq);
    let new_chain = p["new_chain_id"]
        .as_str()
        .expect("new_chain_id")
        .to_string();
    assert_eq!(s.head().2, new_chain);
    assert_eq!(
        keychain_head(&fb.ring, &fb.install_id).map(|a| a.chain_id),
        Some(new_chain.clone())
    );
    assert_eq!(
        keychain_first_retained(&fb.ring, &fb.install_id)
            .map(|a| (a.chain_id, a.first_retained_seq)),
        Some((new_chain.clone(), 10))
    );
    // B keeps its install_id; its old store is archived and recorded.
    let rows = dump_rows(&fb);
    let restore = rows.iter().find(|r| r.seq == restore_seq).expect("RESTORE");
    assert_eq!(restore.target.as_deref(), Some(fb.install_id.as_str()));
    assert_eq!(p["install_id"], fb.install_id.as_str());
    assert_eq!(p["source_install_id"], fa.install_id.as_str());
    assert_eq!(p["prior_keychain_anchor"], hex_anchor(&b_anchor));
    let file = p["replaced_db"]["file"].as_str().expect("file").to_string();
    assert_eq!(p["replaced_db"]["chain_id"], b_chain.as_str());
    assert_eq!(p["replaced_db"]["head_seq"], b_seq);
    assert_eq!(p["replaced_db"]["head_hash"], hex::encode(b_hash));
    assert_eq!(
        file_head(&fb.dir.path().join(&file)),
        (b_seq, b_hash, b_chain)
    );
    assert_eq!(s.full_verify(), vec![]);
}

#[test]
fn u16_archived_db_restored_same_machine() {
    let clock = fake_clock(START);
    let ring = MemKeyring::new();
    let (x, fx) = new_store(clock.clone(), ring.clone());
    x.append_batch(mixed(15)).expect("append_batch");
    x.flush_head_anchor().expect("flush");
    let (x_seq, x_hash, x_chain) = x.head();
    x.shutdown();
    let archived = archive_and_start_fresh(&fx.data, &fx.lock, confirmed()).expect("archive");
    let archived_path = fx.dir.path().join(&archived.file);
    let archived_bytes = std::fs::read(&archived_path).expect("archived");

    // The wizard starts fresh beside it: new ids, another passphrase.
    let other_pass = "another recovery passphrase";
    let (i2, c2) = new_ids().expect("ids");
    let keys2 = Arc::new(MemKeyStore::new(ring.clone(), &i2));
    let faults = Faults::new();
    let mut cfg = OpenConfig::new(clock.clone(), keys2.clone());
    cfg.hooks.faults = Some(faults.clone());
    let mut inp = input(&i2, &c2, other_pass, other_pass);
    inp.archived_db = Some(archived.clone());
    let y = create_new_store(&fx.data, &fx.lock, cfg, inp).expect("new store");
    y.append_batch(mixed(10)).expect("append_batch");
    y.flush_head_anchor().expect("flush");
    let (y_seq, y_hash, y_chain) = y.head();
    let y_anchor = keychain_head(&ring, &i2).expect("head anchor");

    // Restore the archived store with its own passphrase; crash before the anchor reset.
    faults.fail(FaultPoint::AfterKekReseal, 1);
    assert!(
        y.restore(chosen(&archived_path), &pass(PASSPHRASE), None)
            .is_err()
    );
    drop(y);
    assert_eq!(
        std::fs::read(&archived_path).expect("archived"),
        archived_bytes
    );

    let mut cfg = OpenConfig::new(clock, keys2);
    cfg.pinned_install_id = Some(i2.clone());
    let (s, v) = ready(open(&fx.data, &fx.lock, cfg).expect("open"));
    assert_eq!(
        kinds(&v.findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    assert!(s.open_incidents().is_empty());
    let restore_seq = x_seq + 1;
    let p = payload(&s, restore_seq);
    assert_eq!(p["install_id"], i2.as_str());
    assert_eq!(p["source_install_id"], fx.install_id.as_str());
    assert_eq!(p["source_chain_id"], x_chain.as_str());
    assert_eq!(p["source_head_hash"], hex::encode(x_hash));
    assert_eq!(p["backup_created_at"], Value::Null);
    assert_eq!(p["prior_keychain_anchor"], hex_anchor(&y_anchor));
    assert_eq!(p["replaced_db"]["chain_id"], y_chain.as_str());
    assert_eq!(p["replaced_db"]["head_seq"], y_seq);
    assert_eq!(p["replaced_db"]["head_hash"], hex::encode(y_hash));
    let new_chain = p["new_chain_id"].as_str().expect("new_chain_id");
    assert_eq!(
        keychain_head(&ring, &i2).map(|a| a.chain_id),
        Some(new_chain.to_string())
    );
    assert_eq!(s.full_verify(), vec![]);
}

#[test]
fn finish_restore_after_crash_before_reseal() {
    let (a, fa) = machine_a();
    let a_kek = raw_entry(&fa.ring, &fa.install_id, "kek").expect("kek");
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());

    let faults = Faults::new();
    let (b, fb) = machine_b(9, &faults);
    let b_kek = raw_entry(&fb.ring, &fb.install_id, "kek").expect("kek");
    faults.fail(FaultPoint::AfterRestoreCommit, 1);
    assert!(
        b.restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None)
            .is_err()
    );
    drop(b);
    assert_eq!(
        raw_entry(&fb.ring, &fb.install_id, "kek").as_deref(),
        Some(b_kek.as_slice())
    );
    match open(&fb.data, &fb.lock, fb.config()).expect("open") {
        StartupOutcome::Locked(LockedReason::KeychainLost {
            offer: RecoveryOffer::FinishRestore,
        }) => {}
        other => panic!("expected Locked(KeychainLost(FinishRestore)), got {other:?}"),
    }

    // A wrong passphrase writes nothing.
    let files = db_files(fb.dir.path());
    let baseline = fb.ring.ops().len();
    match finish_restore(
        &fb.data,
        &fb.lock,
        fb.config(),
        &pass("not the passphrase at all"),
    ) {
        Err(OpenError::WrongPassphrase) => {}
        other => panic!("expected WrongPassphrase, got {other:?}"),
    }
    assert_eq!(db_files(fb.dir.path()), files);
    assert_eq!(writes_since(&fb.ring, baseline), Vec::<String>::new());

    let (s, v, _) =
        finish_restore(&fb.data, &fb.lock, fb.config(), &pass(PASSPHRASE)).expect("finish");
    assert_eq!(
        kinds(&v.findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    let vs = v.verify_seq.expect("VERIFY");
    assert_eq!(payload(&s, vs)["result"], "interrupted_restore_reconciled");
    assert!(s.open_incidents().is_empty());
    assert_eq!(incident_rows_after(&fb, 0), Vec::<u64>::new());
    assert_eq!(
        raw_entry(&fb.ring, &fb.install_id, "kek").as_deref(),
        Some(a_kek.as_slice())
    );
    let chain = s.head().2;
    assert_eq!(
        keychain_head(&fb.ring, &fb.install_id).map(|a| a.chain_id),
        Some(chain.clone())
    );
    assert_eq!(
        keychain_first_retained(&fb.ring, &fb.install_id).map(|a| a.chain_id),
        Some(chain)
    );
    assert_eq!(s.full_verify(), vec![]);
    s.flush_head_anchor().expect("flush");
    s.shutdown();
    let (_s, v) = ready(open(&fb.data, &fb.lock, fb.config()).expect("open"));
    assert_eq!(v.findings, vec![]);
}

/// A keystore that remembers every head anchor it was asked to write.
struct RecordingKeys {
    inner: MemKeyStore,
    heads: Mutex<Vec<HeadAnchor>>,
}

impl KeyStore for RecordingKeys {
    fn install_id(&self) -> &str {
        self.inner.install_id()
    }

    fn get(&self, e: &EntryName) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        self.inner.get(e)
    }

    fn set(&self, e: &EntryName, v: &[u8]) -> Result<(), KeyStoreError> {
        if *e == EntryName::HeadAnchor {
            self.heads
                .lock()
                .expect("heads")
                .push(HeadAnchor::from_entry(v).expect("head anchor"));
        }
        self.inner.set(e, v)
    }

    fn delete(&self, e: &EntryName) -> Result<(), KeyStoreError> {
        self.inner.delete(e)
    }

    fn locality(&self) -> KeyringLocality {
        self.inner.locality()
    }
}

#[test]
fn u22_restore_keychain_write_failure_retried() {
    let (a, _fa) = machine_a();
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let fb = fixture(fake_clock(START), MemKeyring::new());
    let keys = Arc::new(RecordingKeys {
        inner: MemKeyStore::new(fb.ring.clone(), &fb.install_id),
        heads: Mutex::new(Vec::new()),
    });
    let mut cfg = OpenConfig::new(fb.clock.clone(), keys.clone());
    cfg.hooks.fast_anchor_backoff = true;
    fb.ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::HeadAnchor),
        KeyStoreError::Unavailable,
        3,
    );
    let (b, rep) = restore_on(&fb, cfg, &bundle.bundle_dir, PASSPHRASE).expect("restore");
    let h = b.health();
    assert!(h.anchor_write_failing);
    assert_eq!(h.anchors_blocked, Some(BarrierKind::Restore));
    assert_eq!(h.open_incidents, 0);

    let deadline = Instant::now() + Duration::from_secs(10);
    while keychain_head(&fb.ring, &fb.install_id).map(|a| a.chain_id)
        != Some(rep.new_chain_id.clone())
    {
        assert!(Instant::now() < deadline, "the reset was never retried");
        std::thread::sleep(Duration::from_millis(20));
    }
    let h = b.health();
    assert!(!h.anchor_write_failing);
    assert_eq!(h.anchors_blocked, None);
    let heads = keys.heads.lock().expect("heads").clone();
    assert!(heads.len() >= 4, "{heads:?}");
    for a in &heads {
        assert_eq!(
            a.chain_id, rep.new_chain_id,
            "a head anchor from before the RESTORE"
        );
        assert!(a.seq >= rep.restore_seq);
    }
    assert!(b.open_incidents().is_empty());
    assert!(
        dump_rows(&fb)
            .iter()
            .all(|r| r.seq <= rep.restore_seq || r.event_type != "VERIFY"),
        "no VERIFY after the restore"
    );
}

#[test]
fn same_machine_rollback_needs_confirmation() {
    let (a, fa) = store_with(49);
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    assert_eq!(bundle.head_seq, 50);
    a.append_batch(mixed(20)).expect("append_batch");
    a.flush_head_anchor().expect("flush");
    assert_eq!(a.head().0, 71);

    let files = db_files(fa.dir.path());
    let entries = keychain_entries(&fa.ring, &fa.install_id);
    let baseline = fa.ring.ops().len();
    match a.restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None) {
        Err(AuditError::Restore(RestoreError::RollbackNeedsConfirmation { records_lost })) => {
            assert_eq!(records_lost, 21)
        }
        other => panic!("expected RollbackNeedsConfirmation, got {other:?}"),
    }
    assert_eq!(db_files(fa.dir.path()), files, "live DB unchanged");
    assert_eq!(keychain_entries(&fa.ring, &fa.install_id), entries);
    assert_eq!(writes_since(&fa.ring, baseline), Vec::<String>::new());
    assert!(!fa.dir.path().join("audit.db.restoring").exists());
    assert_eq!(a.health().anchors_blocked, None);

    // The store goes on; a confirmed restore then rolls back.
    a.append(ev(EventType::APP_START, None, json!({})))
        .expect("append");
    a.flush_head_anchor().expect("flush");
    let anchor = keychain_head(&fa.ring, &fa.install_id).expect("anchor");
    assert_eq!(anchor.seq, 72);
    let rep = a
        .restore(
            chosen(&bundle.bundle_dir),
            &pass(PASSPHRASE),
            Some(confirmed()),
        )
        .expect("restore");
    assert_eq!(rep.records_lost, 22);
    assert_eq!(rep.restore_seq, 51);
    let p = payload(&a, 51);
    assert_eq!(p["records_lost"], 22);
    assert_eq!(p["prior_keychain_anchor"], hex_anchor(&anchor));
    assert_eq!(p["source_chain_id"], fa.chain_id.as_str());
    assert_eq!(p["replaced_db"]["chain_id"], fa.chain_id.as_str());
    assert_eq!(p["replaced_db"]["head_seq"], 72);
    assert_eq!(a.head().0, 51);
    assert_eq!(a.head().2, rep.new_chain_id);
    assert_eq!(a.full_verify(), vec![]);
}

#[test]
fn u15_restore_segments_verify() {
    let (a, fa) = store_with(20);
    let out1 = tempfile::tempdir().expect("out dir");
    let b1 = backup_into(&a, out1.path());
    let r1 = a
        .restore(chosen(&b1.bundle_dir), &pass(PASSPHRASE), Some(confirmed()))
        .expect("restore 1");
    assert_eq!(r1.restore_seq, 22);
    assert_eq!(r1.records_lost, 1, "the BACKUP record itself");
    a.append_batch(mixed(10)).expect("append_batch");
    a.flush_head_anchor().expect("flush");
    let out2 = tempfile::tempdir().expect("out dir");
    let b2 = backup_into(&a, out2.path());
    assert_eq!(b2.head_seq, 32);
    let r2 = a
        .restore(chosen(&b2.bundle_dir), &pass(PASSPHRASE), Some(confirmed()))
        .expect("restore 2");
    assert_eq!(r2.restore_seq, 33);
    a.append_batch(mixed(5)).expect("append_batch");
    a.flush_head_anchor().expect("flush");
    assert_eq!(a.full_verify(), vec![]);

    let rows = dump_rows(&fa);
    for r in &rows {
        let want = match r.seq {
            ..=21 => &fa.chain_id,
            22..=32 => &r1.new_chain_id,
            _ => &r2.new_chain_id,
        };
        assert_eq!(&r.chain_id, want, "chain of seq {}", r.seq);
    }
    assert_eq!(payload(&a, 33)["source_chain_id"], r1.new_chain_id.as_str());
    a.shutdown();

    // Tamper the second boundary: RESTORE's prev_hash (an attacker without the KEK rehashes).
    let c = raw_conn(&fa);
    let mut r = rows[32].clone();
    assert_eq!((r.seq, r.event_type.as_str()), (33, "RESTORE"));
    r.prev_hash = [0x5a; 32];
    r.record_hash = r.recompute();
    write_row(&c, &r);
    drop(c);
    let head = rehash_from(&fa, 34);
    set_keychain_head(&fa, &head);
    let (s, _v) = ready(open(&fa.data, &fa.lock, fa.config()).expect("open"));
    let found = kinds(&s.full_verify());
    assert!(
        found.contains(&FindingKind::RestoreBoundaryMismatch)
            || found.contains(&FindingKind::ChainBroken),
        "{found:?}"
    );
}

#[test]
fn restore_refuses_newer_snapshot() {
    let (a, _fa) = store_with(10);
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let snapshot = bundle.bundle_dir.join("audit.db");
    Connection::open(&snapshot)
        .expect("snapshot")
        .pragma_update(None, "user_version", 2)
        .expect("user_version");
    let mut m = read_manifest(&bundle.bundle_dir);
    m["snapshot_sha256"] = json!(hex::encode(sha(&std::fs::read(&snapshot).expect("read"))));
    write_manifest(&bundle.bundle_dir, &m);

    let faults = Faults::new();
    let (b, fb) = machine_b(5, &faults);
    let files = db_files(fb.dir.path());
    let entries = keychain_entries(&fb.ring, &fb.install_id);
    let baseline = fb.ring.ops().len();
    match b.restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None) {
        Err(AuditError::Restore(RestoreError::SnapshotNewer { found })) => {
            assert!(found.contains("user_version 2"), "{found}")
        }
        other => panic!("expected SnapshotNewer, got {other:?}"),
    }
    assert!(!fb.dir.path().join("audit.db.restoring").exists());
    assert_eq!(db_files(fb.dir.path()), files);
    assert_eq!(keychain_entries(&fb.ring, &fb.install_id), entries);
    assert_eq!(writes_since(&fb.ring, baseline), Vec::<String>::new());

    // The manifest may say so as well: refused before anything is copied.
    m["user_version"] = json!(2);
    write_manifest(&bundle.bundle_dir, &m);
    let fc = fixture(fake_clock(START), MemKeyring::new());
    match restore_on(&fc, fc.config(), &bundle.bundle_dir, PASSPHRASE) {
        Err(OpenError::Restore(RestoreError::SnapshotNewer { found })) => {
            assert!(found.contains("user_version 2"), "{found}")
        }
        other => panic!("expected SnapshotNewer, got {other:?}"),
    }
    assert!(!fc.db_path().exists());
    assert!(!fc.dir.path().join("audit.db.restoring").exists());
    assert!(fc.ring.ops().is_empty());
}

fn migrate_v2(tx: &Transaction) -> rusqlite::Result<()> {
    tx.execute_batch("CREATE TABLE v2_extra (id INTEGER PRIMARY KEY, note TEXT)")
}

fn with_migration(cfg: &mut OpenConfig) {
    cfg.hooks.extra_migrations = vec![Migration {
        from: 1,
        to: 2,
        apply: migrate_v2,
    }];
}

fn schema_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/schema/v1.db")
}

#[test]
fn restore_migrates_older_snapshot_after_verify() {
    let src = tempfile::tempdir().expect("source dir");
    let old = src.path().join("old.db");
    std::fs::copy(schema_fixture(), &old).expect("copy fixture");
    let (old_head, _, old_chain) = file_head(&old);

    let fb = fixture(fake_clock("2026-10-09T08:00:00.000Z"), MemKeyring::new());
    let mut cfg = fb.config();
    with_migration(&mut cfg);
    let (b, rep) = restore_on(&fb, cfg, &old, PASSPHRASE).expect("restore");
    assert_eq!(rep.restore_seq, old_head + 1);
    assert_eq!(rep.source_chain_id, old_chain);
    let rows = dump_rows(&fb);
    let tail: Vec<(u64, String)> = rows
        .iter()
        .filter(|r| r.seq > old_head)
        .map(|r| (r.seq, r.event_type.clone()))
        .collect();
    assert_eq!(
        tail,
        vec![
            (old_head + 1, "RESTORE".to_string()),
            (old_head + 2, "SCHEMA_MIGRATED".to_string()),
        ]
    );
    let m = payload(&b, old_head + 2);
    assert_eq!((m["from"].clone(), m["to"].clone()), (json!(1), json!(2)));
    assert_eq!(b.full_verify(), vec![]);
    b.shutdown();
    assert_eq!(user_version(&fb.db_path()), 2);
    assert!(tables(&ro(&fb.db_path())).contains("v2_extra"));
    // The source itself is untouched.
    assert_eq!(user_version(&old), 1);
    assert!(!tables(&ro(&old)).contains("v2_extra"));

    // A tampered source verifies first: refused, and no migration ran anywhere.
    let bad = src.path().join("bad.db");
    std::fs::copy(schema_fixture(), &bad).expect("copy fixture");
    Connection::open(&bad)
        .expect("bad")
        .execute("UPDATE events SET agent_name = 'mallory' WHERE seq = 5", [])
        .expect("tamper");
    let fc = fixture(fake_clock("2026-10-09T08:00:00.000Z"), MemKeyring::new());
    let mut cfg = fc.config();
    with_migration(&mut cfg);
    match restore_on(&fc, cfg, &bad, PASSPHRASE) {
        Err(OpenError::Restore(RestoreError::ChainBroken(_))) => {}
        other => panic!("expected ChainBroken, got {other:?}"),
    }
    assert!(!fc.db_path().exists());
    assert!(!fc.dir.path().join("audit.db.restoring").exists());
    assert_eq!(user_version(&bad), 1);
    assert!(!tables(&ro(&bad)).contains("v2_extra"));
}

#[test]
fn restore_wrong_passphrase_writes_nothing() {
    let (a, _fa) = store_with(10);
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());

    let faults = Faults::new();
    let (b, fb) = machine_b(5, &faults);
    let files = db_files(fb.dir.path());
    let entries = keychain_entries(&fb.ring, &fb.install_id);
    let baseline = fb.ring.ops().len();
    let head = b.head();
    match b.restore(
        chosen(&bundle.bundle_dir),
        &pass("not the right passphrase"),
        None,
    ) {
        Err(AuditError::Restore(RestoreError::WrongPassphrase)) => {}
        other => panic!("expected WrongPassphrase, got {other:?}"),
    }
    assert_eq!(db_files(fb.dir.path()), files);
    assert_eq!(keychain_entries(&fb.ring, &fb.install_id), entries);
    assert_eq!(fb.ring.ops().len(), baseline, "no keychain access at all");
    assert!(!fb.dir.path().join("audit.db.restoring").exists());
    assert_eq!(b.head(), head);
    b.append(ev(EventType::APP_START, None, json!({})))
        .expect("still serving");

    let fc = fixture(fake_clock(START), MemKeyring::new());
    match restore_on(
        &fc,
        fc.config(),
        &bundle.bundle_dir,
        "not the right passphrase",
    ) {
        Err(OpenError::Restore(RestoreError::WrongPassphrase)) => {}
        other => panic!("expected WrongPassphrase, got {other:?}"),
    }
    assert!(fc.ring.ops().is_empty());
    assert!(!fc.db_path().exists());
    assert!(!fc.dir.path().join("audit.db.restoring").exists());
}

#[test]
fn bundle_tampering_is_refused() {
    let (a, _fa) = store_with(10);
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let dir = &bundle.bundle_dir;
    let fc = fixture(fake_clock(START), MemKeyring::new());
    let expect = |want: RestoreError| {
        match restore_on(&fc, fc.config(), dir, PASSPHRASE) {
            Err(OpenError::Restore(e)) => assert_eq!(e, want),
            other => panic!("expected {want:?}, got {other:?}"),
        }
        assert!(!fc.db_path().exists());
        assert!(!fc.dir.path().join("audit.db.restoring").exists());
    };
    // The recovery blob is not the manifest's.
    let rec = dir.join("recovery.bin");
    let orig = std::fs::read(&rec).expect("recovery");
    let mut bad = orig.clone();
    bad[40] ^= 1;
    std::fs::write(&rec, &bad).expect("write");
    expect(RestoreError::ManifestMismatch);
    std::fs::write(&rec, &orig).expect("write");
    // The snapshot is not the manifest's.
    let snap = dir.join("audit.db");
    let orig = std::fs::read(&snap).expect("snapshot");
    Connection::open(&snap)
        .expect("snapshot")
        .execute("UPDATE events SET agent_name = 'x' WHERE seq = 3", [])
        .expect("tamper");
    expect(RestoreError::ManifestMismatch);
    std::fs::write(&snap, &orig).expect("write");
    // A manifest that is not one, then none at all.
    let mpath = dir.join("manifest.json");
    let morig = std::fs::read(&mpath).expect("manifest");
    std::fs::write(&mpath, b"{}").expect("write");
    expect(RestoreError::NotABundle);
    std::fs::remove_file(&mpath).expect("remove");
    expect(RestoreError::NotABundle);
    std::fs::write(&mpath, &morig).expect("write");
    // Not a database file.
    let junk = out.path().join("junk.db");
    std::fs::write(&junk, b"not a database at all, just some bytes".repeat(200)).expect("junk");
    match restore_on(&fc, fc.config(), &junk, PASSPHRASE) {
        Err(OpenError::Restore(RestoreError::NotABundle)) => {}
        other => panic!("expected NotABundle, got {other:?}"),
    }
    // And the intact bundle still restores.
    restore_on(&fc, fc.config(), dir, PASSPHRASE).expect("restore");
}

#[test]
fn restore_from_source_replaces_a_locked_store() {
    let (a, _fa) = machine_a();
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let faults = Faults::new();
    let (b, fb) = machine_b(7, &faults);
    let (b_seq, b_hash, b_chain) = b.head();
    b.shutdown();
    fb.ring.wipe_install(&fb.install_id);
    match open(&fb.data, &fb.lock, fb.config()).expect("open") {
        StartupOutcome::Locked(LockedReason::KeychainLost { .. }) => {}
        other => panic!("expected Locked, got {other:?}"),
    }
    let (s, rep) = restore_on(&fb, fb.config(), &bundle.bundle_dir, PASSPHRASE).expect("restore");
    let replaced = rep.replaced_db.clone().expect("replaced_db");
    assert_eq!(
        (
            replaced.chain_id.clone(),
            replaced.head_seq,
            replaced.head_hash
        ),
        (b_chain.clone(), b_seq, b_hash)
    );
    assert_eq!(
        file_head(&fb.dir.path().join(&replaced.file)),
        (b_seq, b_hash, b_chain)
    );
    assert_eq!(
        payload(&s, rep.restore_seq)["prior_keychain_anchor"],
        Value::Null
    );
    assert_eq!(s.full_verify(), vec![]);
}

// ---------------------------------------------------------------------------------------
// Interrupted restore across sessions (T14 re-review N-1)

#[test]
fn interrupted_restore_reconciles_after_a_session_whose_completion_failed() {
    let (a, _fa) = machine_a();
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let faults = Faults::new();
    let (b, fb) = machine_b(5, &faults);
    let b_anchor = keychain_head(&fb.ring, &fb.install_id).expect("anchor");
    faults.fail(FaultPoint::AfterKekReseal, 1);
    assert!(
        b.restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None)
            .is_err()
    );
    drop(b);

    // A start whose completion keeps failing: Ready, the reset retried in the background.
    fb.ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::HeadAnchor),
        KeyStoreError::Unavailable,
        u32::MAX,
    );
    let (s, v, deleted) = ready_pats(open(&fb.data, &fb.lock, fb.config()).expect("open"));
    assert_eq!(
        kinds(&v.findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    // The `RESTORE` was the newest record: its view's tokens are (again) deleted and reported.
    assert_eq!(deleted, restored_instances());
    assert!(s.health().anchor_write_failing);
    assert_eq!(s.health().anchors_blocked, Some(BarrierKind::Restore));
    // M3 appends APP_START, the user enters a token again, and the session goes on.
    s.append(ev(EventType::APP_START, None, json!({})))
        .expect("append");
    fb.keys()
        .set(&EntryName::Pat("i1".into()), b"entered again")
        .expect("pat");
    s.append_batch(mixed(3)).expect("append_batch");
    s.shutdown();
    assert_eq!(keychain_head(&fb.ring, &fb.install_id), Some(b_anchor));

    // Still unfinished at the next start, but records follow the `RESTORE`: the token entered
    // since is kept and nothing is reported.
    fb.ring.clear_faults();
    let (s, v, deleted) = ready_pats(open(&fb.data, &fb.lock, fb.config()).expect("open"));
    assert_eq!(
        kinds(&v.findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    assert_eq!(deleted, Vec::<String>::new());
    assert_eq!(
        raw_entry(&fb.ring, &fb.install_id, "pat/i1").as_deref(),
        Some(b"entered again".as_slice())
    );
    assert_eq!(incident_rows_after(&fb, 0), Vec::<u64>::new());
    assert_eq!(
        keychain_head(&fb.ring, &fb.install_id).map(|a| a.chain_id),
        Some(s.head().2)
    );
    assert_eq!(s.full_verify(), vec![]);
}

#[test]
fn deferred_restore_reconciles_at_a_later_start() {
    let (a, _fa) = machine_a();
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let faults = Faults::new();
    let (b, fb) = machine_b(5, &faults);
    let b_anchor = keychain_head(&fb.ring, &fb.install_id).expect("anchor");
    faults.fail(FaultPoint::AfterKekReseal, 1);
    assert!(
        b.restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None)
            .is_err()
    );
    drop(b);

    // The anchor dir is offline: the reconciliation is deferred, the anchors held still.
    let anchor_dir = fb.dir.path().join("anchors");
    let mut cfg = fb.config();
    cfg.anchor_dir = Some(anchor_dir.clone());
    let (s, v, deleted) = ready_pats(open(&fb.data, &fb.lock, cfg).expect("open"));
    let found = kinds(&v.findings);
    assert!(
        !found.contains(&FindingKind::InterruptedRestoreReconciled),
        "{found:?}"
    );
    assert!(found.contains(&FindingKind::AnchorDirMismatch), "{found:?}");
    assert_eq!(s.health().anchors_blocked, Some(BarrierKind::Restore));
    assert_eq!(deleted, restored_instances());
    s.append(ev(EventType::APP_START, None, json!({})))
        .expect("append");
    fb.keys()
        .set(&EntryName::Pat("i2".into()), b"entered again")
        .expect("pat");
    s.flush_head_anchor().expect("nothing to write");
    s.shutdown();
    assert_eq!(keychain_head(&fb.ring, &fb.install_id), Some(b_anchor));

    // Still offline: deferred again, and the token entered in the last session is kept.
    let mut cfg = fb.config();
    cfg.anchor_dir = Some(anchor_dir.clone());
    let (s, v, deleted) = ready_pats(open(&fb.data, &fb.lock, cfg).expect("open"));
    assert!(kinds(&v.findings).contains(&FindingKind::AnchorDirMismatch));
    assert_eq!(s.health().anchors_blocked, Some(BarrierKind::Restore));
    assert_eq!(deleted, Vec::<String>::new());
    assert!(raw_entry(&fb.ring, &fb.install_id, "pat/i2").is_some());
    let before = incident_rows_after(&fb, 0);
    s.append(ev(EventType::APP_START, None, json!({})))
        .expect("append");
    s.shutdown();

    // Readable again: reconciled at the next start, without a new incident or deletion.
    std::fs::create_dir(&anchor_dir).expect("anchor dir");
    let mut cfg = fb.config();
    cfg.anchor_dir = Some(anchor_dir);
    let (s, v, deleted) = ready_pats(open(&fb.data, &fb.lock, cfg).expect("open"));
    assert_eq!(
        kinds(&v.findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    assert_eq!(deleted, Vec::<String>::new());
    assert!(raw_entry(&fb.ring, &fb.install_id, "pat/i2").is_some());
    assert_eq!(incident_rows_after(&fb, 0), before);
    assert_eq!(
        keychain_head(&fb.ring, &fb.install_id).map(|a| a.chain_id),
        Some(s.head().2)
    );
}

#[test]
fn refused_restore_puts_back_the_barrier_it_held() {
    let (a, fa) = store_with(20);
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    a.append_batch(mixed(5)).expect("append_batch");
    a.flush_head_anchor().expect("flush");
    // A prune's first-retained update that keeps failing holds the head anchor back.
    fa.ring.fail_next(
        KeyOpKind::Set,
        Some(EntryName::FirstRetainedAnchor),
        KeyStoreError::Unavailable,
        u32::MAX,
    );
    let (seq, record_hash, chain_id) = a.head();
    let first_retained = keychain_first_retained(&fa.ring, &fa.install_id).expect("anchor");
    a.testing_prune_barrier(
        seq,
        record_hash,
        FirstRetainedAnchor {
            chain_id,
            ..first_retained
        },
    )
    .expect("barrier")
    .complete();
    assert_eq!(a.health().anchors_blocked, Some(BarrierKind::Prune));

    // The restore holds the anchors still, then is refused: the prune barrier is back.
    match a.restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None) {
        Err(AuditError::Restore(RestoreError::RollbackNeedsConfirmation { .. })) => {}
        other => panic!("expected RollbackNeedsConfirmation, got {other:?}"),
    }
    assert_eq!(a.health().anchors_blocked, Some(BarrierKind::Prune));
    assert!(a.health().first_retained_update_pending);

    // A confirmed restore replaces it with its own, which the reset lifts.
    fa.ring.clear_faults();
    let rep = a
        .restore(
            chosen(&bundle.bundle_dir),
            &pass(PASSPHRASE),
            Some(confirmed()),
        )
        .expect("restore");
    assert_eq!(a.health().anchors_blocked, None);
    assert_eq!(
        keychain_head(&fa.ring, &fa.install_id).map(|h| h.chain_id),
        Some(rep.new_chain_id)
    );
    // The snapshot head's epoch is NULL (never corroborated): the new DEK has month NULL.
    let rows = dump_rows(&fa);
    let restore = rows
        .iter()
        .find(|r| r.seq == rep.restore_seq)
        .expect("RESTORE");
    assert_eq!(restore.epoch, None);
    let (newest, month, _) = key_rows(&fa).last().expect("keys").clone();
    assert_eq!((restore.key_id, month), (newest, None));
    assert!(newest > 1);
    assert_eq!(a.full_verify(), vec![]);
}

// ---------------------------------------------------------------------------------------
// Anchor-dir lines of a superseded chain (§8.11: accounted for by `records_lost`)

fn record_line(r: &RawRow) -> atlas_duck_audit::AnchorLine {
    atlas_duck_audit::AnchorLine::Record {
        seq: r.seq,
        record_hash: r.record_hash,
        epoch: r.epoch.clone(),
        clock_behind: false,
    }
}

fn write_anchor_lines(dir: &Path, chain_id: &str, lines: &[atlas_duck_audit::AnchorLine]) {
    let text: String = lines
        .iter()
        .map(|l| atlas_duck_audit::anchor_dir::to_line(l) + "\n")
        .collect();
    std::fs::write(dir.join(format!("{chain_id}.jsonl")), text).expect("anchor file");
}

#[test]
fn superseded_chain_lines_are_accounted_for_by_records_lost() {
    let (a, fa) = store_with(0);
    let dir = tempfile::tempdir().expect("anchor dir");
    a.apply_setting(
        SettingChange::AnchorDir(Some(dir.path().to_string_lossy().into_owned())),
        Some(confirmed()),
    )
    .expect("anchor dir");
    a.append_batch(mixed(20)).expect("append_batch");
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    a.append_batch(mixed(10)).expect("append_batch");
    a.flush_head_anchor().expect("flush");
    let rows = dump_rows(&fa);
    let (h, head) = (bundle.head_seq, a.head().0);
    let row = |seq: u64| &rows[seq as usize - 1];
    // What M10 wrote for chain A: a record the snapshot keeps and two the rollback gives up.
    let header = atlas_duck_audit::AnchorLine::Header {
        chain_id: fa.chain_id.clone(),
        install_id: fa.install_id.clone(),
        host: "testhost".into(),
        os_user: "alice".into(),
        created_at: START.into(),
    };
    let mut lines = vec![
        header,
        record_line(row(6)),
        record_line(row(h + 2)),
        record_line(row(head)),
    ];
    write_anchor_lines(dir.path(), &fa.chain_id, &lines);

    let rep = a
        .restore(
            chosen(&bundle.bundle_dir),
            &pass(PASSPHRASE),
            Some(confirmed()),
        )
        .expect("restore");
    assert_eq!(rep.records_lost, head - h);
    assert_eq!(a.full_verify(), vec![]);
    a.flush_head_anchor().expect("flush");
    a.shutdown();
    let (s, v) = ready(open(&fa.data, &fa.lock, fa.config()).expect("open"));
    assert_eq!(v.findings, vec![]);

    // A line of chain A beyond what the rollback gave up is still a contradiction.
    lines.push(atlas_duck_audit::AnchorLine::Record {
        seq: head + 3,
        record_hash: [7; 32],
        epoch: None,
        clock_behind: false,
    });
    write_anchor_lines(dir.path(), &fa.chain_id, &lines);
    assert!(
        kinds(&s.full_verify()).contains(&FindingKind::AnchorDirMismatch),
        "a line past the prior anchor is not accounted for"
    );
}

#[test]
fn full_verify_that_raced_a_restore_appends_nothing() {
    let (a, _fa) = machine_a();
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let faults = Faults::new();
    let (b, fb) = machine_b(5, &faults);
    // The run reads the old store; the restore replaces it before the VERIFY is appended.
    let (findings, generation) = b.testing_full_verify_run().expect("run");
    assert_eq!(findings, vec![]);
    let rep = b
        .restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None)
        .expect("restore");
    let head = b.head();
    match b.testing_full_verify_append(&findings, generation) {
        Err(AuditError::Invalid(_)) => {}
        other => panic!("expected Invalid, got {other:?}"),
    }
    assert_eq!(b.head(), head, "nothing appended to the restored chain");
    assert!(
        dump_rows(&fb)
            .iter()
            .all(|r| r.seq <= rep.restore_seq || r.event_type != "VERIFY")
    );
    // A run over the restored store appends as usual.
    let (findings, generation) = b.testing_full_verify_run().expect("run");
    b.testing_full_verify_append(&findings, generation)
        .expect("append");
}

// ---------------------------------------------------------------------------------------
// Review round 1

fn committed_incomplete(e: &AuditError) -> Option<u64> {
    match e {
        AuditError::Restore(RestoreError::CommittedIncomplete { restore_seq, .. }) => {
            Some(*restore_seq)
        }
        _ => None,
    }
}

/// I-1/I-3: a failure after the commit rename is a committed restore that did not complete:
/// the writer stops (it never goes on with the replaced store's state on the restored file),
/// and the next start finishes it.
#[test]
fn failure_after_the_commit_rename_is_committed_incomplete() {
    let (a, fa) = machine_a();
    let a_kek = raw_entry(&fa.ring, &fa.install_id, "kek").expect("kek");
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let faults = Faults::new();
    let (b, fb) = machine_b(9, &faults);
    faults.fail(FaultPoint::CommitDirSync, 1);
    let e = b
        .restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None)
        .expect_err("dir sync fails");
    assert_eq!(committed_incomplete(&e), Some(bundle.head_seq + 1), "{e:?}");
    // The handle does not go on: no append lands anywhere.
    assert_eq!(
        b.append(ev(EventType::APP_START, None, json!({}))),
        Err(AuditError::Closed)
    );
    drop(b);
    // audit.db is the restored store; the next start finishes it.
    let (seq, _, chain) = file_head(&fb.db_path());
    assert_eq!(seq, bundle.head_seq + 1);
    assert_ne!(chain, fa.chain_id);
    match open(&fb.data, &fb.lock, fb.config()).expect("open") {
        StartupOutcome::Locked(LockedReason::KeychainLost {
            offer: RecoveryOffer::FinishRestore,
        }) => {}
        other => panic!("expected FinishRestore, got {other:?}"),
    }
    let (s, v, _) =
        finish_restore(&fb.data, &fb.lock, fb.config(), &pass(PASSPHRASE)).expect("finish");
    assert_eq!(
        kinds(&v.findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    assert_eq!(
        raw_entry(&fb.ring, &fb.install_id, "kek").as_deref(),
        Some(a_kek.as_slice())
    );
    assert_eq!(s.full_verify(), vec![]);
}

#[test]
fn restore_from_source_reports_a_committed_restore() {
    let (a, _fa) = machine_a();
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let fb = fixture(fake_clock(START), MemKeyring::new());
    let faults = Faults::new();
    let mut cfg = fb.config();
    cfg.hooks.faults = Some(faults.clone());
    faults.fail(FaultPoint::AfterKekReseal, 1);
    match restore_on(&fb, cfg, &bundle.bundle_dir, PASSPHRASE) {
        Err(OpenError::Restore(RestoreError::CommittedIncomplete { restore_seq, .. })) => {
            assert_eq!(restore_seq, bundle.head_seq + 1)
        }
        other => panic!("expected CommittedIncomplete, got {other:?}"),
    }
    // Refused before the commit: nothing changed, and the error says nothing was committed.
    let fc = fixture(fake_clock(START), MemKeyring::new());
    match restore_on(&fc, fc.config(), &bundle.bundle_dir, "a wrong passphrase") {
        Err(OpenError::Restore(RestoreError::WrongPassphrase)) => {}
        other => panic!("expected WrongPassphrase, got {other:?}"),
    }
}

/// Adds `sql` to a bundle's snapshot and fixes the manifest hash (an attacker can).
fn craft_snapshot(bundle: &Path, sql: &str) {
    let snapshot = bundle.join("audit.db");
    Connection::open(&snapshot)
        .expect("snapshot")
        .execute_batch(sql)
        .expect("craft");
    let mut m = read_manifest(bundle);
    m["snapshot_sha256"] = json!(hex::encode(sha(&std::fs::read(&snapshot).expect("read"))));
    write_manifest(bundle, &m);
}

/// I-2: a crafted snapshot's schema objects never become part of the live store.
#[test]
fn crafted_schema_objects_are_refused() {
    let crafted = [
        (
            "drop_requests",
            "CREATE TRIGGER drop_requests BEFORE INSERT ON events \
             BEGIN SELECT RAISE(IGNORE); END;",
        ),
        (
            "flood",
            "CREATE TRIGGER flood AFTER INSERT ON keys BEGIN DELETE FROM keys; END;",
        ),
        (
            "events_view",
            "CREATE VIEW events_view AS SELECT seq FROM events;",
        ),
        ("extra", "CREATE TABLE extra (x);"),
        (
            "events_extra",
            "CREATE INDEX events_extra ON events(agent_name);",
        ),
        (
            "vault",
            "CREATE VIEW vault AS SELECT 1 AS instance_id, x'00' AS ct;",
        ),
    ];
    for (name, sql) in crafted {
        let (a, _fa) = store_with(5);
        let out = tempfile::tempdir().expect("out dir");
        let bundle = backup_into(&a, out.path());
        craft_snapshot(&bundle.bundle_dir, sql);
        let fc = fixture(fake_clock(START), MemKeyring::new());
        match restore_on(&fc, fc.config(), &bundle.bundle_dir, PASSPHRASE) {
            Err(OpenError::Restore(RestoreError::ChainBroken(m))) => {
                assert!(m.contains(name), "{name}: {m}")
            }
            other => panic!("{name}: expected ChainBroken, got {other:?}"),
        }
        assert!(!fc.db_path().exists());
        assert!(!fc.dir.path().join("audit.db.restoring").exists());
        assert!(fc.ring.ops().is_empty(), "{name}: no keychain access");
    }
    // A vault table (and its index) is what restore drops itself.
    let (a, _fa) = store_with(5);
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    craft_snapshot(
        &bundle.bundle_dir,
        "CREATE TABLE vault (instance_id TEXT, ct BLOB); \
         CREATE INDEX vault_i ON vault(instance_id);",
    );
    let fc = fixture(fake_clock(START), MemKeyring::new());
    let (s, _) = restore_on(&fc, fc.config(), &bundle.bundle_dir, PASSPHRASE).expect("restore");
    s.shutdown();
    assert!(!tables(&ro(&fc.db_path())).contains("vault"));
}

/// I-2, defence in depth: the writer checks that each record really was stored.
#[test]
fn an_insert_that_stores_nothing_fails_the_append() {
    let (a, fa) = store_with(3);
    let head = a.head();
    raw_conn(&fa)
        .execute_batch(
            "CREATE TRIGGER swallow BEFORE INSERT ON events BEGIN SELECT RAISE(IGNORE); END;",
        )
        .expect("trigger");
    match a.append(ev(EventType::APP_START, None, json!({}))) {
        Err(AuditError::AppendFailed(_)) => {}
        other => panic!("expected AppendFailed, got {other:?}"),
    }
    assert_eq!(a.head(), head);
}

/// I-4: a restore that migrated an older snapshot ends with `SCHEMA_MIGRATED` after its
/// `RESTORE` (L50); a crash before the re-seal still offers "Finish restore".
#[test]
fn migrated_restore_crash_before_reseal_offers_finish_restore() {
    let src = tempfile::tempdir().expect("source dir");
    let old = src.path().join("old.db");
    std::fs::copy(schema_fixture(), &old).expect("copy fixture");
    let (old_head, _, _) = file_head(&old);
    let fb = fixture(fake_clock("2026-10-09T08:00:00.000Z"), MemKeyring::new());
    let faults = Faults::new();
    let mut cfg = fb.config();
    with_migration(&mut cfg);
    cfg.hooks.faults = Some(faults.clone());
    faults.fail(FaultPoint::AfterRestoreCommit, 1);
    assert!(restore_on(&fb, cfg, &old, PASSPHRASE).is_err());
    let rows = dump_rows(&fb);
    assert_eq!(
        rows.last().map(|r| (r.seq, r.event_type.clone())),
        Some((old_head + 2, "SCHEMA_MIGRATED".to_string()))
    );
    let mut cfg = fb.config();
    with_migration(&mut cfg);
    match open(&fb.data, &fb.lock, cfg).expect("open") {
        StartupOutcome::Locked(LockedReason::KeychainLost {
            offer: RecoveryOffer::FinishRestore,
        }) => {}
        other => panic!("expected FinishRestore, got {other:?}"),
    }
    let mut cfg = fb.config();
    with_migration(&mut cfg);
    let (s, v, _) = finish_restore(&fb.data, &fb.lock, cfg, &pass(PASSPHRASE)).expect("finish");
    assert_eq!(
        kinds(&v.findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    assert_eq!(s.full_verify(), vec![]);
}

/// I-5: the source is opened as a plain read-only file: a path that is no valid URI path
/// works, and nothing is created beside the source.
#[test]
fn restore_from_a_path_with_unusual_characters() {
    let (a, _fa) = machine_a();
    let parent = tempfile::tempdir().expect("out dir");
    let out = parent.path().join("it's #1 %20 ü dir");
    std::fs::create_dir(&out).expect("odd dir");
    let bundle = backup_into(&a, &out);
    let before = files_in(&bundle.bundle_dir);
    let fb = fixture(fake_clock(START), MemKeyring::new());
    let (s, _) = restore_on(&fb, fb.config(), &bundle.bundle_dir, PASSPHRASE).expect("restore");
    assert_eq!(s.full_verify(), vec![]);
    assert_eq!(
        files_in(&bundle.bundle_dir),
        before,
        "no sidecar beside the source"
    );

    // An archived store (WAL mode, no -wal) is read without leaving sidecars either.
    let (x, fx) = store_with(5);
    x.shutdown();
    let archived = archive_and_start_fresh(&fx.data, &fx.lock, confirmed()).expect("archive");
    let archived_dir = fx.dir.path().join("archived");
    let before = files_in(&archived_dir);
    let fc = fixture(fake_clock(START), MemKeyring::new());
    restore_on(
        &fc,
        fc.config(),
        &fx.dir.path().join(&archived.file),
        PASSPHRASE,
    )
    .expect("restore");
    assert_eq!(files_in(&archived_dir), before);
}

/// M-6: bundle files are bounded regular files.
#[test]
fn oversized_recovery_file_is_refused() {
    let (a, _fa) = store_with(3);
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let rec = bundle.bundle_dir.join("recovery.bin");
    let big = vec![1u8; 1 << 20];
    std::fs::write(&rec, &big).expect("write");
    let mut m = read_manifest(&bundle.bundle_dir);
    m["recovery_sha256"] = json!(hex::encode(sha(&big)));
    write_manifest(&bundle.bundle_dir, &m);
    let fc = fixture(fake_clock(START), MemKeyring::new());
    match restore_on(&fc, fc.config(), &bundle.bundle_dir, PASSPHRASE) {
        Err(OpenError::Restore(RestoreError::NotABundle)) => {}
        other => panic!("expected NotABundle, got {other:?}"),
    }
    assert!(!fc.db_path().exists());
}

/// M-2: the PAT entries go only once the restore has committed; "Finish restore" deletes those
/// of the restored view before it re-seals the KEK.
#[test]
fn pats_are_deleted_after_the_commit_and_by_finish_restore() {
    let (a, _fa) = machine_a();
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let faults = Faults::new();
    let (b, fb) = machine_b(4, &faults);
    for id in ["i1", "i2"] {
        fb.keys()
            .set(&EntryName::Pat(id.into()), b"token")
            .expect("pat");
    }
    // Refused before the commit: every token is still there.
    match b.restore(
        chosen(&bundle.bundle_dir),
        &pass("not the right passphrase"),
        None,
    ) {
        Err(AuditError::Restore(RestoreError::WrongPassphrase)) => {}
        other => panic!("expected WrongPassphrase, got {other:?}"),
    }
    for id in ["i1", "i2", "i3"] {
        assert!(raw_entry(&fb.ring, &fb.install_id, &format!("pat/{id}")).is_some());
    }
    // A crash right after the commit: the tokens are still there, but the store does not
    // open without "Finish restore", which deletes the restored view's tokens first.
    faults.fail(FaultPoint::AfterRestoreCommit, 1);
    let e = b
        .restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None)
        .expect_err("crash");
    assert!(committed_incomplete(&e).is_some(), "{e:?}");
    drop(b);
    let (_s, _v, deleted) =
        finish_restore(&fb.data, &fb.lock, fb.config(), &pass(PASSPHRASE)).expect("finish");
    // Reported for M3's `INSTANCE_STATE_CHANGED {needs_token}` (PD-28).
    assert_eq!(deleted, INSTANCES.map(String::from).to_vec());
    for id in ["i1", "i2"] {
        assert_eq!(
            raw_entry(&fb.ring, &fb.install_id, &format!("pat/{id}")),
            None
        );
    }
}

/// M-2/N-4 on Windows: another process holding `audit.db` open without delete sharing (as
/// SQLite and some scanners do) would make the commit rename fail, and the hard link made
/// before it could not be removed either. The restore checks for that before it links, so it
/// is refused before the commit: tokens, live store and `archived/` are untouched.
#[cfg(windows)]
#[test]
fn rename_refused_by_an_open_reader_changes_nothing() {
    use std::os::windows::fs::OpenOptionsExt;
    let (a, _fa) = machine_a();
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let faults = Faults::new();
    let (b, fb) = machine_b(4, &faults);
    const FILE_SHARE_READ: u32 = 1;
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | 2)
        .open(fb.db_path())
        .expect("a handle without delete sharing");
    let head = b.head();
    let e = b
        .restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None)
        .expect_err("rename refused");
    assert_eq!(committed_incomplete(&e), None, "{e:?}");
    // Refused by the check before the link, not by the rename after it.
    assert!(e.to_string().contains("open in another process"), "{e}");
    drop(reader);
    assert!(raw_entry(&fb.ring, &fb.install_id, "pat/i3").is_some());
    assert_eq!(b.head(), head);
    b.append(ev(EventType::APP_START, None, json!({})))
        .expect("still serving the live store");
    assert_eq!(b.head().2, head.2);
    let stray = std::fs::read_dir(fb.dir.path().join("archived"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(stray, 0, "no stray archive link");
}

// ---------------------------------------------------------------------------------------
// Review round 2

/// N-1: a same-machine restore re-uses the keychain KEK, so after a stop between its commit
/// and its PAT deletion the next `open()` serves the store: the reconciliation deletes the
/// restored view's tokens first, and a keychain that refuses that keeps the store locked.
#[test]
fn same_kek_restore_stopped_before_its_pat_deletion_opens_without_tokens() {
    let faults = Faults::new();
    let (a, fa) = new_store_with(fake_clock(START), MemKeyring::new(), |cfg| {
        cfg.hooks.faults = Some(faults.clone());
    });
    a.apply_setting(
        SettingChange::InstanceOrigin {
            instance_id: "i1".into(),
            origin: Some("https://i1.example".into()),
        },
        Some(confirmed()),
    )
    .expect("origin");
    a.append_batch(mixed(5)).expect("append_batch");
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    fa.keys()
        .set(&EntryName::Pat("i1".into()), b"token")
        .expect("pat");
    a.flush_head_anchor().expect("flush");
    faults.fail(FaultPoint::AfterRestoreCommit, 1);
    let e = a
        .restore(
            chosen(&bundle.bundle_dir),
            &pass(PASSPHRASE),
            Some(confirmed()),
        )
        .expect_err("stop after the commit");
    assert!(committed_incomplete(&e).is_some(), "{e:?}");
    drop(a);
    assert!(raw_entry(&fa.ring, &fa.install_id, "pat/i1").is_some());
    let rows_before = dump_rows(&fa).len();

    // The keychain refuses the deletion: locked, nothing written, the token still there.
    fa.ring.fail_next(
        KeyOpKind::Delete,
        Some(EntryName::Pat("i1".into())),
        KeyStoreError::Unavailable,
        1,
    );
    match open(&fa.data, &fa.lock, fa.config()).expect("open") {
        StartupOutcome::Locked(LockedReason::KeychainUnavailable) => {}
        other => panic!("expected Locked(KeychainUnavailable), got {other:?}"),
    }
    assert_eq!(dump_rows(&fa).len(), rows_before);

    let (s, v, deleted) = ready_pats(open(&fa.data, &fa.lock, fa.config()).expect("open"));
    assert_eq!(
        kinds(&v.findings),
        vec![FindingKind::InterruptedRestoreReconciled]
    );
    assert_eq!(raw_entry(&fa.ring, &fa.install_id, "pat/i1"), None);
    assert_eq!(deleted, vec!["i1".to_string()]);
    assert_eq!(s.full_verify(), vec![]);
}

/// N-2: a schema version below the first is never adopted.
#[test]
fn snapshot_below_the_first_schema_version_is_refused() {
    let (a, _fa) = store_with(5);
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    craft_snapshot(&bundle.bundle_dir, "PRAGMA user_version = 0;");
    let mut m = read_manifest(&bundle.bundle_dir);
    m["user_version"] = json!(0);
    write_manifest(&bundle.bundle_dir, &m);
    let fc = fixture(fake_clock(START), MemKeyring::new());
    match restore_on(&fc, fc.config(), &bundle.bundle_dir, PASSPHRASE) {
        Err(OpenError::Restore(RestoreError::ChainBroken(m))) => {
            assert!(m.contains("schema version 0"), "{m}")
        }
        other => panic!("expected ChainBroken, got {other:?}"),
    }
    assert!(!fc.db_path().exists());
}

/// N-3: nothing of the copy is queried before its schema is checked: an `events` view over
/// an endless recursive CTE is refused at once, not evaluated.
#[test]
fn endless_events_view_is_refused_without_evaluating_it() {
    let (a, _fa) = store_with(5);
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    craft_snapshot(
        &bundle.bundle_dir,
        "ALTER TABLE events RENAME TO events_t; \
         CREATE VIEW events AS WITH RECURSIVE c(x) AS \
         (SELECT 1 UNION ALL SELECT x + 1 FROM c) \
         SELECT x AS seq, 1 AS format_version, '' AS chain_id FROM c;",
    );
    let dir = bundle.bundle_dir.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let fc = fixture(fake_clock(START), MemKeyring::new());
        let r = restore_on(&fc, fc.config(), &dir, PASSPHRASE).map(|_| ());
        let _ = tx.send((r, fc.db_path().exists()));
    });
    let (r, db_exists) = rx
        .recv_timeout(Duration::from_secs(120))
        .expect("the restore must not evaluate the crafted view");
    match r {
        Err(OpenError::Restore(RestoreError::ChainBroken(m))) => {
            assert!(m.contains("events"), "{m}")
        }
        other => panic!("expected ChainBroken, got {other:?}"),
    }
    assert!(!db_exists);
}

/// N-8: after `CommittedIncomplete` the handle reads nothing either (it would read the
/// restored file with the replaced store's keys and head).
#[test]
fn committed_incomplete_handle_reads_nothing() {
    let (a, _fa) = machine_a();
    let out = tempfile::tempdir().expect("out dir");
    let bundle = backup_into(&a, out.path());
    let faults = Faults::new();
    let (b, _fb) = machine_b(4, &faults);
    faults.fail(FaultPoint::AfterKekReseal, 1);
    let e = b
        .restore(chosen(&bundle.bundle_dir), &pass(PASSPHRASE), None)
        .expect_err("stop");
    assert!(committed_incomplete(&e).is_some(), "{e:?}");
    assert_eq!(b.read_payload(2), Err(AuditError::Closed));
    assert_eq!(
        b.append(ev(EventType::APP_START, None, json!({}))),
        Err(AuditError::Closed)
    );
    match b.try_full_verify() {
        Err(AuditError::Closed) => {}
        other => panic!("expected Closed, got {other:?}"),
    }
}
