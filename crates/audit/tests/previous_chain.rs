//! First run against a used anchor dir (§8.5, PD-167, PD-171; U-06 first-run clause): a chain
//! file whose header names this host and OS user is a previous chain. `GENESIS` records the
//! newest one, and a `VERIFY {result: previous_chain_found}` flagged `integrity_incident`
//! follows, unless the chain is the `archived_db` chain of the same `GENESIS` and the archived
//! file covers every anchor of it. The archive's native confirmation is recorded as
//! `CONFIG_CHANGED {key: archive_and_start_fresh}`. Every first-run row is written before the
//! store file appears, so a crash never leaves a store without its incident.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use atlas_duck_audit::anchor_dir::{AnchorLine, file_name, parse_line, to_line};
use atlas_duck_audit::encoding::{ZERO_HASH, prune_row_hash};
use atlas_duck_audit::error::OpenError;
use atlas_duck_audit::keystore::{EntryName, KeyStore};
use atlas_duck_audit::testing::{self, FakePrune, MemKeyStore, MemKeyring};
use atlas_duck_audit::types::{Confirmed, EventFlags, RustChosenPath};
use atlas_duck_audit::verify::FindingKind;
use atlas_duck_audit::{
    ArchivedDb, FirstRunInput, OpenConfig, Settings, StartupOutcome, Store,
    archive_and_start_fresh, create_new_store, new_ids, open,
};
use common::*;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------------------
// helpers

const LATER: &str = "2026-10-12T12:00:00.000Z";

fn chosen(p: &Path) -> RustChosenPath {
    RustChosenPath::from_native_dialog(p.to_path_buf())
}

fn confirmed(b: u8) -> Confirmed {
    Confirmed {
        dialog_text_sha256: [b; 32],
    }
}

fn dir_text(dir: &Path) -> String {
    dir.to_string_lossy().into_owned()
}

/// The wizard's input with `dir` as the anchor dir it chose.
fn wizard_input(install_id: &str, chain_id: &str, dir: Option<&Path>) -> FirstRunInput {
    let mut inp = input(install_id, chain_id, PASSPHRASE, PASSPHRASE);
    inp.anchor_dir = dir.map(chosen);
    inp
}

fn first_run(f: &Fixture, dir: Option<&Path>) -> Result<Store, OpenError> {
    create_new_store(
        &f.data,
        &f.lock,
        f.config(),
        wizard_input(&f.install_id, &f.chain_id, dir),
    )
}

fn drain(store: &Store) {
    assert!(
        store.testing_anchor_dir_drain(),
        "anchor-dir queue not drained"
    );
}

fn payload(store: &Store, seq: u64) -> Value {
    serde_json::from_slice(&store.read_payload(seq).expect("read_payload")).expect("json")
}

fn types(f: &Fixture) -> Vec<String> {
    dump_rows(f).into_iter().map(|r| r.event_type).collect()
}

fn chain_file(dir: &Path, chain_id: &str) -> PathBuf {
    dir.join(file_name(chain_id))
}

/// Every line of a chain file, parsed (each must be valid).
fn lines(dir: &Path, chain_id: &str) -> Vec<AnchorLine> {
    let text = std::fs::read_to_string(chain_file(dir, chain_id)).expect("chain file");
    text.lines()
        .map(|l| parse_line(l).unwrap_or_else(|e| panic!("bad line {l:?}: {e}")))
        .collect()
}

/// `(seq, record_hash, epoch)` of the last line naming a record.
type Anchor = (u64, [u8; 32], Option<String>);

fn last_anchor(dir: &Path, chain_id: &str) -> Anchor {
    lines(dir, chain_id)
        .into_iter()
        .filter_map(|l| match l {
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
            } => Some((seq, record_hash, epoch)),
            _ => None,
        })
        .next_back()
        .expect("an anchored line")
}

fn anchor_json(a: &Anchor) -> Value {
    json!({ "seq": a.0, "record_hash": hex::encode(a.1), "epoch": a.2 })
}

fn chain_json(chain_id: &str, a: &Anchor) -> Value {
    json!({ "chain_id": chain_id, "last_seq": a.0, "last_record_hash": hex::encode(a.1) })
}

/// A chain this host and user left in `dir`: a first run whose wizard chose `dir`, a corroborated
/// day of events at `ts` (a daily line), then shut down. Returns the fixture (its data dir
/// holds the closed store) and the chain's last anchored line.
fn used_chain(dir: &Path, ts: &str) -> (Fixture, Anchor) {
    let f = fixture(fake_clock(ts), MemKeyring::new());
    let store = first_run(&f, Some(dir)).expect("first run of the earlier chain");
    corroborate_now(&store, &f.clock);
    store.append_batch(day_events(2)).expect("append");
    drain(&store);
    store.shutdown();
    let last = last_anchor(dir, &f.chain_id);
    (f, last)
}

/// `host` and `os_user` as this process writes them into a header.
fn this_host_and_user() -> (String, String) {
    let probe = tempfile::tempdir().expect("probe dir");
    let (f, _) = used_chain(probe.path(), START);
    match lines(probe.path(), &f.chain_id).first() {
        Some(AnchorLine::Header { host, os_user, .. }) => (host.clone(), os_user.clone()),
        other => panic!("no header: {other:?}"),
    }
}

/// A chain file written by hand: a header with `host`/`os_user`, then one `Record` line.
fn forge_chain(dir: &Path, host: &str, os_user: &str, last: &Anchor) -> String {
    let (install_id, chain_id) = new_ids().expect("ids");
    let header = AnchorLine::Header {
        chain_id: chain_id.clone(),
        install_id,
        host: host.to_owned(),
        os_user: os_user.to_owned(),
        created_at: START.to_owned(),
    };
    let record = AnchorLine::Record {
        seq: last.0,
        record_hash: last.1,
        epoch: last.2.clone(),
        clock_behind: false,
    };
    let text = format!("{}\n{}\n", to_line(&header), to_line(&record));
    std::fs::write(chain_file(dir, &chain_id), text).expect("forge chain file");
    chain_id
}

/// Every file of `dir` with its bytes.
fn dir_bytes(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| {
            let e = e.expect("entry");
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).expect("read"),
            )
        })
        .collect()
}

fn flags(f: &Fixture, seq: u64) -> EventFlags {
    let r = dump_rows(f)
        .into_iter()
        .find(|r| r.seq == seq)
        .expect("row");
    EventFlags::from_bits(r.flags)
}

fn open_ready(f: &Fixture) -> (Store, Vec<atlas_duck_audit::VerifyFinding>) {
    open_ready_with(f, f.config())
}

fn open_ready_with(f: &Fixture, cfg: OpenConfig) -> (Store, Vec<atlas_duck_audit::VerifyFinding>) {
    match open(&f.data, &f.lock, cfg).expect("open") {
        StartupOutcome::Ready { store, verify, .. } => (store, verify.findings),
        other => panic!("not ready: {other:?}"),
    }
}

/// The archived store of `a` and new ids beside it: the first-run input and the config of a
/// keystore under the new install id (same keyring).
fn after_archive(a: &Fixture, dir: Option<&Path>) -> (ArchivedDb, FirstRunInput, OpenConfig) {
    let archived = archive_and_start_fresh(&a.data, &a.lock, confirmed(3)).expect("archive");
    let (install_id, chain_id) = new_ids().expect("ids");
    let keys = Arc::new(MemKeyStore::new(a.ring.clone(), &install_id));
    let mut inp = wizard_input(&install_id, &chain_id, dir);
    inp.archived_db = Some(archived.clone());
    (archived, inp, OpenConfig::new(a.clock.clone(), keys))
}

/// The config of the store a first run after [`after_archive`] created (its own install id).
fn config_of(a: &Fixture, install_id: &str) -> OpenConfig {
    OpenConfig::new(
        a.clock.clone(),
        Arc::new(MemKeyStore::new(a.ring.clone(), install_id)),
    )
}

/// [`used_chain`] with a prune: the records below seq 3 are gone from the store, and the chain
/// file holds the prune's `Prune` line.
fn used_pruned_chain(dir: &Path) -> (Fixture, Anchor) {
    let f = fixture(fake_clock(START), MemKeyring::new());
    let store = first_run(&f, Some(dir)).expect("first run of the earlier chain");
    corroborate_now(&store, &f.clock);
    store.append_batch(day_events(2)).expect("append");
    testing::insert_fake_prune(
        &store,
        FakePrune {
            first_retained_seq: 3,
            cutoff: "2026-06-01".into(),
            // Keeps the anchor dir in the view once its CONFIG_CHANGED (seq 2) is pruned.
            settings: Settings {
                retention_days: 92,
                anchor_dir: Some(dir_text(dir)),
                ..Settings::default()
            }
            .to_json(),
            update_first_retained: true,
        },
    )
    .expect("fake prune");
    store.flush_head_anchor().expect("flush");
    drain(&store);
    store.shutdown();
    assert!(
        lines(dir, &f.chain_id)
            .iter()
            .any(|l| matches!(l, AnchorLine::Prune { .. })),
        "the chain file holds the Prune line"
    );
    let last = last_anchor(dir, &f.chain_id);
    (f, last)
}

/// One well-formed `prune_log` row (`prev_row_hash` `ZERO_HASH`, range from 1, its own
/// `row_hash`) written into the archive at `path`.
fn forge_prune_row(path: &Path, prune_seq: u64, first_retained_seq: u64, last_pruned: [u8; 32]) {
    let cutoff = "2026-10-01";
    let row_hash = prune_row_hash(
        &ZERO_HASH,
        prune_seq,
        1,
        cutoff,
        &last_pruned,
        first_retained_seq,
    );
    let c = rusqlite::Connection::open(path).expect("open archive");
    c.execute(
        "INSERT INTO prune_log (prune_seq, range_start, cutoff_epoch, last_pruned_record_hash, \
         first_retained_seq, prev_row_hash, row_hash) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            prune_seq as i64,
            cutoff,
            &last_pruned[..],
            first_retained_seq as i64,
            &ZERO_HASH[..],
            &row_hash[..]
        ],
    )
    .expect("forge prune_log row");
}

/// Keeps a file unreadable to this process while it lives: Windows holds it open without
/// sharing; Unix clears its permission bits and restores them on drop.
#[cfg(windows)]
struct Denied {
    _held: std::fs::File,
}

#[cfg(windows)]
fn deny_reads(path: &Path) -> Option<Denied> {
    use std::os::windows::fs::OpenOptionsExt;
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(path)
        .expect("exclusive handle");
    Some(Denied { _held: held })
}

#[cfg(unix)]
struct Denied(PathBuf);

#[cfg(unix)]
impl Drop for Denied {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o644));
    }
}

/// `None` when the process reads the file anyway (root).
#[cfg(unix)]
fn deny_reads(path: &Path) -> Option<Denied> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
    let denied = Denied(path.to_path_buf());
    std::fs::File::open(path).is_err().then_some(denied)
}

// ---------------------------------------------------------------------------------------
// detection

#[test]
fn u06_first_run_previous_chain_incident() {
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a, last) = used_chain(dir.path(), START);
    let before = std::fs::read(chain_file(dir.path(), &a.chain_id)).expect("old chain file");

    let b = fixture(fake_clock(LATER), MemKeyring::new());
    let store = first_run(&b, Some(dir.path())).expect("first run");

    // GENESIS names the previous chain and its last anchored line.
    let genesis = payload(&store, 1);
    assert_eq!(genesis["previous_chain_id"], json!(a.chain_id));
    assert_eq!(genesis["previous_last_anchor"], anchor_json(&last));
    // seq 2: the wizard's anchor dir as a setting; seq 3: the incident.
    assert_eq!(types(&b), ["GENESIS", "CONFIG_CHANGED", "VERIFY"]);
    let setting = payload(&store, 2);
    assert_eq!(setting["key"], "anchor_dir");
    assert_eq!(setting["source"], "app");
    assert_eq!(setting["old"], Value::Null);
    assert_eq!(setting["new"], json!(dir_text(dir.path())));
    assert_eq!(setting["applied"], json!(true));
    assert_eq!(setting["confirmed"], Value::Null, "nothing is weakened");
    assert_eq!(
        store.settings().anchor_dir,
        Some(dir_text(dir.path())),
        "the store's own setting"
    );
    let v = payload(&store, 3);
    assert_eq!(v["result"], "previous_chain_found");
    assert_eq!(v["scope"], "first_run");
    assert_eq!(v["chains"], json!([chain_json(&a.chain_id, &last)]));
    assert_eq!(v["findings"][0]["kind"], "previous_chain_found");
    assert_eq!(v["findings"][0]["expected_seq"], json!(last.0));
    assert!(flags(&b, 3).contains(EventFlags::INTEGRITY_INCIDENT));
    assert_eq!(store.open_incidents(), vec![3]);

    // The new chain's file: the header first, then the setting's immediate line; the incident
    // file beside it; the old chain's file untouched.
    drain(&store);
    let ls = lines(dir.path(), &b.chain_id);
    assert!(
        matches!(&ls[0], AnchorLine::Header { chain_id, .. } if *chain_id == b.chain_id),
        "{ls:?}"
    );
    assert!(
        ls.iter().any(|l| matches!(l,
            AnchorLine::Immediate { seq: 2, event_type, .. } if event_type == "CONFIG_CHANGED")),
        "{ls:?}"
    );
    let incident: Value = serde_json::from_slice(
        &std::fs::read(dir.path().join(format!("{}.incident-3.json", b.chain_id)))
            .expect("incident file"),
    )
    .expect("incident json");
    assert_eq!(incident["result"], "previous_chain_found");
    assert_eq!(incident["expected_seq"], json!(last.0));
    assert_eq!(incident["expected_hash"], json!(hex::encode(last.1)));
    assert_eq!(
        std::fs::read(chain_file(dir.path(), &a.chain_id)).expect("old chain file"),
        before,
        "detection never writes into another chain's file"
    );
    store.shutdown();

    // The keychain head anchor names the last first-run row, so the next start is clean and
    // the incident stays open until acknowledged.
    let (store, findings) = open_ready(&b);
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(store.open_incidents(), vec![3]);
    store.shutdown();
}

#[test]
fn configured_anchor_dir_is_checked_too() {
    // `OpenConfig.anchor_dir` (no wizard dir): no setting row, the incident follows GENESIS and
    // its file goes to the configured dir.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a, last) = used_chain(dir.path(), START);
    let (store, b) = new_store_with(fake_clock(LATER), MemKeyring::new(), |cfg| {
        cfg.anchor_dir = Some(dir.path().to_path_buf());
    });
    assert_eq!(payload(&store, 1)["previous_chain_id"], json!(a.chain_id));
    assert_eq!(types(&b), ["GENESIS", "VERIFY"]);
    assert_eq!(
        payload(&store, 2)["chains"],
        json!([chain_json(&a.chain_id, &last)])
    );
    assert_eq!(store.open_incidents(), vec![2]);
    assert_eq!(store.settings().anchor_dir, None, "the fallback stays one");
    drain(&store);
    assert!(
        dir.path()
            .join(format!("{}.incident-2.json", b.chain_id))
            .is_file()
    );
    assert!(matches!(
        lines(dir.path(), &b.chain_id).first(),
        Some(AnchorLine::Header { .. })
    ));
    store.shutdown();
}

#[test]
fn other_host_or_user_chain_ignored() {
    let (host, os_user) = this_host_and_user();
    let dir = tempfile::tempdir().expect("anchor dir");
    let a: Anchor = (5, [0x5a; 32], Some("2026-10-07".into()));
    forge_chain(dir.path(), &format!("{host}-other"), &os_user, &a);
    forge_chain(dir.path(), &host, &format!("{os_user}-other"), &a);
    // Matching is exact (RF-3): another spelling of the user is another user.
    let upper = os_user.to_uppercase();
    if upper != os_user {
        forge_chain(dir.path(), &host, &upper, &a);
    }
    // Neither an incident file nor a file whose name is not `<chain_id>.jsonl` is a chain.
    let (_, stray) = new_ids().expect("ids");
    let header = AnchorLine::Header {
        chain_id: stray.clone(),
        install_id: stray.clone(),
        host: host.clone(),
        os_user: os_user.clone(),
        created_at: START.to_owned(),
    };
    std::fs::write(dir.path().join("notes.jsonl"), to_line(&header) + "\n").expect("stray");
    std::fs::write(
        dir.path().join(format!("{stray}.incident-3.json")),
        to_line(&header) + "\n",
    )
    .expect("incident-looking file");

    let b = fixture(fake_clock(LATER), MemKeyring::new());
    let store = first_run(&b, Some(dir.path())).expect("first run");
    let genesis = payload(&store, 1);
    assert_eq!(genesis["previous_chain_id"], Value::Null);
    assert_eq!(genesis["previous_last_anchor"], Value::Null);
    assert_eq!(types(&b), ["GENESIS", "CONFIG_CHANGED"]);
    assert!(store.open_incidents().is_empty());
    store.shutdown();
}

#[test]
fn header_after_torn_first_line_is_a_previous_chain() {
    // A crash while the header was written leaves a torn line 1; the writer then appends the
    // header on line 2 (T5 fix-g I-1). Such a file is still attributed by its header.
    let (host, os_user) = this_host_and_user();
    let dir = tempfile::tempdir().expect("anchor dir");
    let (install_id, chain_id) = new_ids().expect("ids");
    let header = to_line(&AnchorLine::Header {
        chain_id: chain_id.clone(),
        install_id,
        host,
        os_user,
        created_at: START.to_owned(),
    });
    let torn = &header[..header.len() / 2];
    std::fs::write(
        chain_file(dir.path(), &chain_id),
        format!("{torn}\n{header}\n"),
    )
    .expect("torn file");

    let b = fixture(fake_clock(LATER), MemKeyring::new());
    let store = first_run(&b, Some(dir.path())).expect("first run");
    assert_eq!(payload(&store, 1)["previous_chain_id"], json!(chain_id));
    assert_eq!(payload(&store, 1)["previous_last_anchor"], Value::Null);
    assert_eq!(types(&b), ["GENESIS", "CONFIG_CHANGED", "VERIFY"]);
    assert_eq!(
        payload(&store, 3)["chains"],
        json!([{ "chain_id": chain_id, "last_seq": null, "last_record_hash": null }])
    );
    store.shutdown();
}

#[test]
fn several_previous_chains_one_incident() {
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a1, last1) = used_chain(dir.path(), START);
    // A later epoch: the newest chain is the one GENESIS names.
    let (a2, last2) = used_chain(dir.path(), LATER);
    assert!(last2.2 > last1.2, "{last1:?} {last2:?}");

    let b = fixture(fake_clock("2026-10-14T12:00:00.000Z"), MemKeyring::new());
    let store = first_run(&b, Some(dir.path())).expect("first run");
    let genesis = payload(&store, 1);
    assert_eq!(genesis["previous_chain_id"], json!(a2.chain_id));
    assert_eq!(genesis["previous_last_anchor"], anchor_json(&last2));
    let rows = types(&b);
    assert_eq!(
        rows.iter().filter(|t| *t == "VERIFY").count(),
        1,
        "{rows:?}"
    );
    assert_eq!(rows, ["GENESIS", "CONFIG_CHANGED", "VERIFY"]);
    let v = payload(&store, 3);
    assert_eq!(v["result"], "previous_chain_found");
    // Newest first.
    assert_eq!(
        v["chains"],
        json!([
            chain_json(&a2.chain_id, &last2),
            chain_json(&a1.chain_id, &last1)
        ])
    );
    assert_eq!(store.open_incidents(), vec![3]);
    store.shutdown();
}

#[test]
fn previous_chain_found_is_incident_not_chain_kind() {
    assert_eq!(
        FindingKind::PreviousChainFound.as_str(),
        "previous_chain_found"
    );
    assert!(FindingKind::PreviousChainFound.is_incident());

    // It is a fact about the anchor dir at first run, not about the new store's chain: full
    // verification of that store finds nothing, and no later start raises it again.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (_a, _) = used_chain(dir.path(), START);
    let b = fixture(fake_clock(LATER), MemKeyring::new());
    let store = first_run(&b, Some(dir.path())).expect("first run");
    drain(&store);
    store.shutdown();
    let (s, findings) = open_ready(&b);
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(s.open_incidents(), vec![3]);
    s.shutdown();
    let s = testing::open_existing(&b.data, &b.lock, b.config()).expect("open_existing");
    let fs = s.full_verify();
    s.shutdown();
    assert!(fs.is_empty(), "{fs:?}");
}

// ---------------------------------------------------------------------------------------
// the archive exemption

#[test]
fn u06_archived_chain_exempt_only_if_covering() {
    // Covering: the archived file holds every anchored record of its chain.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a, last) = used_chain(dir.path(), START);
    let (archived, inp, cfg) = after_archive(&a, Some(dir.path()));
    let store = create_new_store(&a.data, &a.lock, cfg, inp).expect("first run");
    let genesis = payload(&store, 1);
    assert_eq!(
        genesis["previous_chain_id"],
        json!(a.chain_id),
        "still recorded"
    );
    assert_eq!(genesis["previous_last_anchor"], anchor_json(&last));
    assert_eq!(genesis["archived_db"]["chain_id"], json!(archived.chain_id));
    assert_eq!(types(&a), ["GENESIS", "CONFIG_CHANGED"], "no incident");
    assert!(store.open_incidents().is_empty());
    store.shutdown();

    // Not covering: the anchor dir names a record beyond the archived head.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a, _) = used_chain(dir.path(), START);
    let head = dump_rows(&a).pop().expect("head");
    let beyond: Anchor = (head.seq + 1, [0x77; 32], last.2.clone());
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(chain_file(dir.path(), &a.chain_id))
        .expect("chain file");
    std::io::Write::write_all(
        &mut file,
        format!(
            "{}\n",
            to_line(&AnchorLine::Record {
                seq: beyond.0,
                record_hash: beyond.1,
                epoch: beyond.2.clone(),
                clock_behind: false,
            })
        )
        .as_bytes(),
    )
    .expect("append line");
    drop(file);
    let (_, inp, cfg) = after_archive(&a, Some(dir.path()));
    let store = create_new_store(&a.data, &a.lock, cfg, inp).expect("first run");
    assert_eq!(types(&a), ["GENESIS", "CONFIG_CHANGED", "VERIFY"]);
    let v = payload(&store, 3);
    assert_eq!(v["result"], "previous_chain_found");
    assert_eq!(v["chains"], json!([chain_json(&a.chain_id, &beyond)]));
    assert_eq!(store.open_incidents(), vec![3]);
    store.shutdown();
}

#[test]
fn substituted_archive_not_covering_anchors_raises_incident() {
    // (a) A re-derived archive: the old store cut back before its last anchored record, filed
    // under a name and an `ArchivedDb` that match its own (shorter) head.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a, last) = used_chain(dir.path(), START);
    let (archived, inp, cfg) = after_archive(&a, Some(dir.path()));
    let real = a.data.path().join(&archived.file);
    let cut = last.0 - 1;
    let name = format!("archived/audit-{}-{cut}-20261009T000000000Z.db", a.chain_id);
    let path = a.data.path().join(&name);
    std::fs::copy(&real, &path).expect("copy archive");
    let head_hash = {
        let c = rusqlite::Connection::open(&path).expect("open copy");
        c.execute("DELETE FROM events WHERE seq > ?1", [cut as i64])
            .expect("cut");
        let rows = dump_conn(&c);
        rows.last().expect("head").record_hash
    };
    let mut inp = inp;
    inp.archived_db = Some(ArchivedDb {
        file: name,
        chain_id: a.chain_id.clone(),
        head_seq: cut,
        head_hash,
    });
    let store = create_new_store(&a.data, &a.lock, cfg, inp).expect("first run");
    assert_eq!(types(&a), ["GENESIS", "CONFIG_CHANGED", "VERIFY"]);
    assert_eq!(payload(&store, 3)["result"], "previous_chain_found");
    assert_eq!(
        payload(&store, 3)["chains"],
        json!([chain_json(&a.chain_id, &last)])
    );
    assert_eq!(payload(&store, 1)["archived_db"]["head_seq"], json!(cut));
    store.shutdown();

    // (b) The real archive with an anchored record altered under its old `record_hash`: the
    // stored hash still equals the line, the row no longer hashes to it.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a, last) = used_chain(dir.path(), START);
    let (archived, inp, cfg) = after_archive(&a, Some(dir.path()));
    {
        let c = rusqlite::Connection::open(a.data.path().join(&archived.file)).expect("open");
        let n = c
            .execute(
                "UPDATE events SET target = 'TAMPERED' WHERE seq = ?1",
                [last.0 as i64],
            )
            .expect("tamper");
        assert_eq!(n, 1);
    }
    assert!(archived.head_seq > last.0, "the head itself is untouched");
    let store = create_new_store(&a.data, &a.lock, cfg, inp).expect("first run");
    assert_eq!(types(&a), ["GENESIS", "CONFIG_CHANGED", "VERIFY"]);
    assert_eq!(
        payload(&store, 3)["chains"],
        json!([chain_json(&a.chain_id, &last)])
    );
    store.shutdown();

    // (c) An `ArchivedDb` naming a file outside `archived/`: never opened, never exempt.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a, _) = used_chain(dir.path(), START);
    let (mut archived, mut inp, cfg) = after_archive(&a, Some(dir.path()));
    archived.file = format!("archived/../{}", archived.file);
    inp.archived_db = Some(archived);
    let store = create_new_store(&a.data, &a.lock, cfg, inp).expect("first run");
    assert_eq!(types(&a), ["GENESIS", "CONFIG_CHANGED", "VERIFY"]);
    store.shutdown();
}

#[test]
fn forged_prune_log_row_raises_incident() {
    // The archive's `prune_log` is bound to the chain file's `Prune` lines (none here: nothing
    // was pruned), so a row claiming that the anchored records were pruned covers nothing
    // (T6 review C-1).
    // 0: every record kept, a row claiming all of them pruned (first retained = head + 1);
    // 1: only the head kept, with a row that agrees with it (the head's prev_hash is its
    //    last_pruned): the archive's own checks pass, only the binding catches it;
    // 2: a row naming nothing pruned (1, ZERO_HASH): a prune the file does not name.
    for case in 0..3 {
        let dir = tempfile::tempdir().expect("anchor dir");
        let (a, last) = used_chain(dir.path(), START);
        let (archived, inp, cfg) = after_archive(&a, Some(dir.path()));
        let path = a.data.path().join(&archived.file);
        let head = archived.head_seq;
        assert!(head > last.0, "the head itself is not anchored");
        match case {
            0 => forge_prune_row(&path, head + 1, head + 1, archived.head_hash),
            1 => {
                let c = rusqlite::Connection::open(&path).expect("open archive");
                let prev: Vec<u8> = c
                    .query_row(
                        "SELECT prev_hash FROM events WHERE seq = ?1",
                        [head as i64],
                        |r| r.get(0),
                    )
                    .expect("head prev_hash");
                c.execute("DELETE FROM events WHERE seq < ?1", [head as i64])
                    .expect("keep the head only");
                drop(c);
                forge_prune_row(&path, head, head, prev.try_into().expect("32 bytes"));
            }
            _ => forge_prune_row(&path, head, 1, ZERO_HASH),
        }
        let store = create_new_store(&a.data, &a.lock, cfg, inp).expect("first run");
        assert_eq!(
            types(&a),
            ["GENESIS", "CONFIG_CHANGED", "VERIFY"],
            "case {case}"
        );
        assert_eq!(
            payload(&store, 3)["chains"],
            json!([chain_json(&a.chain_id, &last)]),
            "case {case}"
        );
        store.shutdown();
    }
}

#[test]
fn pruned_archive_covers_only_with_its_prune_line() {
    // Honest: the archive's latest prune_log row is the chain file's Prune line.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a, _) = used_pruned_chain(dir.path());
    let (_, inp, cfg) = after_archive(&a, Some(dir.path()));
    let store = create_new_store(&a.data, &a.lock, cfg, inp).expect("first run");
    assert_eq!(types(&a), ["GENESIS", "CONFIG_CHANGED"], "no incident");
    store.shutdown();

    // The dir missed the prune (its Prune line is not in the file): the archive's prune_log
    // cannot be bound to the file, so the exemption fails closed.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a, last) = used_pruned_chain(dir.path());
    let path = chain_file(dir.path(), &a.chain_id);
    let kept: String = std::fs::read_to_string(&path)
        .expect("chain file")
        .lines()
        .filter(|l| !matches!(parse_line(l), Ok(AnchorLine::Prune { .. })))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&path, kept).expect("drop the Prune line");
    let (_, inp, cfg) = after_archive(&a, Some(dir.path()));
    let store = create_new_store(&a.data, &a.lock, cfg, inp).expect("first run");
    assert_eq!(types(&a), ["GENESIS", "CONFIG_CHANGED", "VERIFY"]);
    assert_eq!(
        payload(&store, 3)["chains"],
        json!([chain_json(&a.chain_id, &last)])
    );
    store.shutdown();

    // The archive's prune_log row agrees with the Prune line but its row_hash does not hash the
    // row: the prune_log's own chain is checked too.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a, last) = used_pruned_chain(dir.path());
    let (archived, inp, cfg) = after_archive(&a, Some(dir.path()));
    {
        let c = rusqlite::Connection::open(a.data.path().join(&archived.file)).expect("open");
        let n = c
            .execute("UPDATE prune_log SET row_hash = zeroblob(32)", [])
            .expect("tamper");
        assert_eq!(n, 1);
    }
    let store = create_new_store(&a.data, &a.lock, cfg, inp).expect("first run");
    assert_eq!(types(&a), ["GENESIS", "CONFIG_CHANGED", "VERIFY"]);
    assert_eq!(
        payload(&store, 3)["chains"],
        json!([chain_json(&a.chain_id, &last)])
    );
    store.shutdown();
}

#[test]
fn exempt_archived_chain_among_other_previous_chains() {
    // The archived chain is the newest: GENESIS still names it, the incident names only the
    // other one.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a1, last1) = used_chain(dir.path(), START);
    let (a2, last2) = used_chain(dir.path(), LATER);
    let (_, inp, cfg) = after_archive(&a2, Some(dir.path()));
    let store = create_new_store(&a2.data, &a2.lock, cfg, inp).expect("first run");
    let genesis = payload(&store, 1);
    assert_eq!(genesis["previous_chain_id"], json!(a2.chain_id));
    assert_eq!(genesis["previous_last_anchor"], anchor_json(&last2));
    assert_eq!(types(&a2), ["GENESIS", "CONFIG_CHANGED", "VERIFY"]);
    assert_eq!(
        payload(&store, 3)["chains"],
        json!([chain_json(&a1.chain_id, &last1)])
    );
    store.shutdown();

    // The archived chain is the older one: GENESIS names the newer, which alone raises it.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a1, _) = used_chain(dir.path(), START);
    let (a2, last2) = used_chain(dir.path(), LATER);
    let (_, inp, cfg) = after_archive(&a1, Some(dir.path()));
    let store = create_new_store(&a1.data, &a1.lock, cfg, inp).expect("first run");
    assert_eq!(payload(&store, 1)["previous_chain_id"], json!(a2.chain_id));
    assert_eq!(types(&a1), ["GENESIS", "CONFIG_CHANGED", "VERIFY"]);
    assert_eq!(
        payload(&store, 3)["chains"],
        json!([chain_json(&a2.chain_id, &last2)])
    );
    store.shutdown();
}

// ---------------------------------------------------------------------------------------
// the archive confirmation (PD-171)

#[test]
fn archive_confirmation_recorded_after_genesis() {
    let dir = tempfile::tempdir().expect("anchor dir");
    let (store, a) = new_store(fake_clock(START), MemKeyring::new());
    store.shutdown();
    let (archived, mut inp, cfg) = after_archive(&a, Some(dir.path()));
    inp.archive_confirmed = Some(confirmed(0x11));
    let install_id = inp.install_id.clone();
    let new_cfg = || config_of(&a, &install_id);
    let store = create_new_store(&a.data, &a.lock, cfg, inp).expect("first run");
    // GENESIS, the anchor dir setting, then the archive's confirmation.
    assert_eq!(types(&a), ["GENESIS", "CONFIG_CHANGED", "CONFIG_CHANGED"]);
    assert_eq!(
        payload(&store, 3),
        json!({
            "source": "app",
            "key": "archive_and_start_fresh",
            "archived_db_file": archived.file,
            "dialog_text_sha256": hex::encode([0x11; 32]),
        })
    );
    assert_eq!(
        payload(&store, 1)["archived_db"]["file"],
        json!(archived.file)
    );
    // Not a policy key: the settings view keeps only the anchor dir, and the anchor dir gets no
    // immediate line for it.
    assert_eq!(store.settings().anchor_dir, Some(dir_text(dir.path())));
    drain(&store);
    let immediates: Vec<u64> = lines(dir.path(), &store.head().2)
        .into_iter()
        .filter_map(|l| match l {
            AnchorLine::Immediate { seq, .. } => Some(seq),
            _ => None,
        })
        .collect();
    assert_eq!(immediates, [2]);
    store.shutdown();

    // The record is not a setting the next start or a full verification trips over.
    let (store, findings) = open_ready_with(&a, new_cfg());
    assert!(findings.is_empty(), "{findings:?}");
    assert!(store.open_incidents().is_empty());
    store.shutdown();
    let s = testing::open_existing(&a.data, &a.lock, new_cfg()).expect("open_existing");
    let fs = s.full_verify();
    s.shutdown();
    assert!(fs.is_empty(), "{fs:?}");
}

#[test]
fn archive_confirmation_without_archived_db_is_refused() {
    let dir = tempfile::tempdir().expect("anchor dir");
    let f = fixture(fake_clock(START), MemKeyring::new());
    let mut inp = wizard_input(&f.install_id, &f.chain_id, Some(dir.path()));
    inp.archive_confirmed = Some(confirmed(0x11));
    let err = create_new_store(&f.data, &f.lock, f.config(), inp).expect_err("refused");
    assert!(matches!(err, OpenError::Invalid(_)), "{err:?}");
    assert!(!f.db_path().exists());
    assert_eq!(f.keys().get(&EntryName::Kek).expect("keystore"), None);
    assert!(dir_bytes(dir.path()).is_empty());
}

// ---------------------------------------------------------------------------------------
// refusals: nothing is written

#[test]
fn wizard_existing_db_path_untouched() {
    // I-34 still holds: an existing store is refused before the anchor dir is even read.
    let dir = tempfile::tempdir().expect("anchor dir");
    let (a, _) = used_chain(dir.path(), START);
    let db = std::fs::read(a.db_path()).expect("db");
    let anchors = dir_bytes(dir.path());
    let (install_id, chain_id) = new_ids().expect("ids");
    let keys = Arc::new(MemKeyStore::new(a.ring.clone(), &install_id));
    let err = create_new_store(
        &a.data,
        &a.lock,
        OpenConfig::new(a.clock.clone(), keys.clone()),
        wizard_input(&install_id, &chain_id, Some(dir.path())),
    )
    .expect_err("an existing store");
    assert!(matches!(err, OpenError::AlreadyExists), "{err:?}");
    assert_eq!(std::fs::read(a.db_path()).expect("db"), db);
    assert_eq!(dir_bytes(dir.path()), anchors);
    assert_eq!(keys.get(&EntryName::Kek).expect("keystore"), None);
}

#[test]
fn unusable_anchor_dir_writes_nothing() {
    let base = tempfile::tempdir().expect("base");
    let missing = base.path().join("missing");
    let file = base.path().join("file");
    std::fs::write(&file, b"x").expect("file");
    for dir in [missing.as_path(), file.as_path(), Path::new("relative")] {
        let f = fixture(fake_clock(START), MemKeyring::new());
        let err = first_run(&f, Some(dir)).expect_err("refused");
        assert!(matches!(err, OpenError::Invalid(_)), "{dir:?}: {err:?}");
        assert!(!f.db_path().exists());
        assert_eq!(f.keys().get(&EntryName::Kek).expect("keystore"), None);
    }
    assert!(!missing.exists());
}

#[test]
fn too_many_chain_files_refused() {
    let dir = tempfile::tempdir().expect("anchor dir");
    let a: Anchor = (1, [1; 32], None);
    for _ in 0..=atlas_duck_audit::anchor_dir::MAX_FIRST_RUN_CHAIN_FILES {
        forge_chain(dir.path(), "elsewhere", "someone", &a);
    }
    let before = dir_bytes(dir.path());
    let f = fixture(fake_clock(START), MemKeyring::new());
    let err = first_run(&f, Some(dir.path())).expect_err("refused");
    assert!(matches!(err, OpenError::Invalid(_)), "{err:?}");
    assert!(!f.db_path().exists());
    assert_eq!(dir_bytes(dir.path()), before);
}

#[test]
fn exactly_the_chain_file_bound_is_read() {
    let dir = tempfile::tempdir().expect("anchor dir");
    let a: Anchor = (1, [1; 32], None);
    for _ in 0..atlas_duck_audit::anchor_dir::MAX_FIRST_RUN_CHAIN_FILES {
        forge_chain(dir.path(), "elsewhere", "someone", &a);
    }
    let f = fixture(fake_clock(START), MemKeyring::new());
    let store = first_run(&f, Some(dir.path())).expect("256 chain files are read");
    assert_eq!(types(&f), ["GENESIS", "CONFIG_CHANGED"]);
    store.shutdown();
}

#[test]
fn unreadable_chain_file_refused() {
    // Another user's file the first run cannot read: it cannot tell whose it is, so it does not
    // start over the dir (fail closed), and writes nothing.
    let dir = tempfile::tempdir().expect("anchor dir");
    let a: Anchor = (1, [1; 32], None);
    let chain = forge_chain(dir.path(), "elsewhere", "someone", &a);
    let before = dir_bytes(dir.path());
    let Some(denied) = deny_reads(&chain_file(dir.path(), &chain)) else {
        eprintln!("skipped: this process reads a file without read permission");
        return;
    };
    let f = fixture(fake_clock(START), MemKeyring::new());
    let res = first_run(&f, Some(dir.path()));
    drop(denied);
    let err = res.map(|s| s.shutdown()).expect_err("refused");
    assert!(matches!(err, OpenError::Invalid(_)), "{err:?}");
    assert!(!f.db_path().exists());
    assert_eq!(f.keys().get(&EntryName::Kek).expect("keystore"), None);
    assert_eq!(dir_bytes(dir.path()), before);
}
