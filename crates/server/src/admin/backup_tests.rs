//! `admin backup`, `maintenance` and `restore` (M13 T6) over a SQLite server store and real
//! per-user stores in a temp data dir.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use atlas_duck_audit::EventType;
use base64::Engine;
use secrecy::ExposeSecret;
use serde_json::{Value, json};

use super::backup::{MANIFEST, Manifest, sha256_file};
use super::*;
use crate::anchor::{KIND_BACKUP_TAKEN, KIND_MAINTENANCE, KIND_RESTORED, verify};
use crate::api_keys::ApiKeyParams;
use crate::audit_kinds::api_key_created;
use crate::clock::ManualClock;
use crate::master_key::{MasterKey, WrappedKey};
use crate::runtime::{RuntimeDeps, UserCtx};
use crate::store::InstanceRecord;
use crate::store::sqlite::SqliteStore;
use crate::users::ensure_user;

const LIMIT: Duration = Duration::from_secs(120);
const KEY_A: [u8; 32] = [0x5a; 32];

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIMIT, f).await.expect("timed out")
}

struct S {
    _dir: tempfile::TempDir,
    data: PathBuf,
    ctx: Arc<AdminCtx>,
    clock: Arc<ManualClock>,
}

fn sqlite_harness(key_id: &str, key: [u8; 32]) -> S {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(data.join("server")).unwrap();
    let store: Arc<dyn ServerStore> =
        Arc::new(SqliteStore::open(&data.join("server").join("server.db")).unwrap());
    store
        .instance_put(&InstanceRecord {
            alias: "work".into(),
            product: "jira".into(),
            base_url: "https://jira.example.test".into(),
            proxy: Some("direct".into()),
            ca_ref: None,
            is_default: true,
        })
        .unwrap();
    let clock = ManualClock::at(1_800_000_000);
    let registry = Arc::new(Registry::new(
        RuntimeDeps {
            data_dir: data.clone(),
            store: store.clone(),
            master: Arc::new(MasterKey::for_tests(key_id, key)),
            org_ca: None,
            clock: clock.clone(),
            allow_http: true,
            sse_capacity: crate::runtime::SSE_CAPACITY,
        },
        10,
    ));
    let sessions =
        Arc::new(SessionTable::new(store.clone(), clock.clone(), 28_800, 1_800).unwrap());
    let api_keys =
        Arc::new(ApiKeys::new(store.clone(), clock.clone(), ApiKeyParams::TEST).unwrap());
    let writer = Arc::new(AnchorWriter::new(
        store.clone(),
        registry.clone(),
        clock.clone(),
    ));
    writer.start(&json!({})).unwrap();
    let ctx = Arc::new(AdminCtx::new(
        store,
        registry,
        sessions,
        api_keys,
        writer,
        clock.clone(),
        DEFAULT_RETENTION_DAYS,
    ));
    S {
        _dir: dir,
        data,
        ctx,
        clock,
    }
}

impl S {
    fn store(&self) -> &dyn ServerStore {
        self.ctx.store.as_ref()
    }

    /// A user with an open store and one record of its own.
    async fn user(&self, name: &str) -> String {
        let master = self.ctx.registry.deps().master.clone();
        let (u, _) =
            ensure_user(self.store(), &master, name, None, vec!["user".into()], 0).unwrap();
        self.activity(&u.user_id).await;
        u.user_id
    }

    async fn activity(&self, uid: &str) {
        let rt = within(self.ctx.registry.open_user(uid)).await.unwrap();
        rt.append_server_record(
            EventType::API_KEY_CREATED,
            api_key_created(
                "key_x",
                "n",
                "abcd1234",
                &["read"],
                "2030-01-01T00:00:00.000Z",
            ),
        )
        .await
        .unwrap();
    }

    async fn call(&self, req: Request) -> Response {
        within(handle(&self.ctx, req)).await
    }

    async fn backup(&self, dir: &Path) -> Value {
        let r = self
            .call(Request::Backup(DirArg {
                dir: dir.display().to_string(),
            }))
            .await;
        assert!(r.ok, "{r:?}");
        r.data.unwrap()
    }

    async fn restore(&self, bundle: &str) -> Response {
        self.call(Request::Restore(DirArg {
            dir: bundle.to_owned(),
        }))
        .await
    }

    async fn maintenance(&self, on: bool) {
        assert!(self.call(Request::Maintenance(SwitchArg { on })).await.ok);
    }

    fn backups(&self) -> PathBuf {
        self.data.join("backups")
    }
}

fn manifest(bundle: &str) -> Manifest {
    serde_json::from_slice(&std::fs::read(Path::new(bundle).join(MANIFEST)).unwrap()).unwrap()
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(root).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push(p);
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_is_consistent_under_concurrent_writes() {
    let s = sqlite_harness("k1", KEY_A);
    let a = s.user("alice").await;
    let b = s.user("bob").await;
    let ctx = s.ctx.clone();
    let (ua, ub) = (a.clone(), b.clone());
    // Writers on the server store and on both user chains while the backup runs.
    let writer = tokio::spawn(async move {
        for i in 0..40 {
            let _ = ctx.sessions.create(&ua, vec!["user".into()]);
            let _ = ctx.api_keys.create(
                &UserCtx::from_authenticated(&ub),
                &format!("k{i}"),
                &["read".to_owned()],
                None,
            );
            for uid in [&ua, &ub] {
                if let Ok(rt) = ctx.registry.open_user(uid).await {
                    let _ = rt
                        .append_server_record(
                            EventType::API_KEY_CREATED,
                            api_key_created(
                                "key_y",
                                "n",
                                "abcd1234",
                                &["read"],
                                "2030-01-01T00:00:00.000Z",
                            ),
                        )
                        .await;
                }
            }
            tokio::task::yield_now().await;
        }
    });
    let report = s.backup(&s.backups()).await;
    within(writer).await.unwrap();
    let bundle = report["bundle"].as_str().unwrap().to_owned();
    let m = manifest(&bundle);
    for f in &m.files {
        let p = Path::new(&bundle).join(&f.path);
        assert_eq!(
            hex::encode(sha256_file(&p).unwrap()),
            f.sha256,
            "{}",
            f.path
        );
    }
    assert_eq!(m.users.len(), 2);
    // The bundle is self-consistent: a fresh server with the same key restores it, which checks
    // the hashes, the anchor chain and every user chain against the manifest.
    let fresh = sqlite_harness("k1", KEY_A);
    let copied = fresh.backups().join("from-s");
    copy_dir(Path::new(&bundle), &copied);
    fresh.maintenance(true).await;
    let r = fresh.restore(&copied.display().to_string()).await;
    assert!(r.ok, "{r:?}");
    within(s.ctx.registry.close_all()).await;
    within(fresh.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_contains_no_master_key_and_wrapped_data_keys_only() {
    let s = sqlite_harness("k1", KEY_A);
    let a = s.user("alice").await;
    let report = s.backup(&s.backups()).await;
    let bundle = PathBuf::from(report["bundle"].as_str().unwrap());
    let b64 = base64::engine::general_purpose::STANDARD.encode(KEY_A);
    for f in files_under(&bundle) {
        let bytes = std::fs::read(&f).unwrap();
        assert!(
            !contains(&bytes, &KEY_A),
            "raw master key in {}",
            f.display()
        );
        assert!(
            !contains(&bytes, b64.as_bytes()),
            "master key in {}",
            f.display()
        );
    }
    let snap = SqliteStore::open(&bundle.join("server.db")).unwrap();
    let u = snap.user(&a).unwrap().unwrap();
    let w = WrappedKey::from_json(&u.data_key_wrapped).unwrap();
    assert_eq!(w.master_key_id, "k1");
    assert_eq!(manifest(&bundle.display().to_string()).master_key_id, "k1");
    within(s.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_manifest_written_last() {
    let s = sqlite_harness("k1", KEY_A);
    s.user("alice").await;
    let report = s.backup(&s.backups()).await;
    let written: Vec<&str> = report["written"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(written.first(), Some(&"server.db"));
    assert_eq!(written.last(), Some(&MANIFEST));
    assert_eq!(written.iter().filter(|w| **w == MANIFEST).count(), 1);
    assert!(
        written.iter().any(|w| w.starts_with("users/")),
        "{written:?}"
    );
    // The manifest lists every other file written, and nothing else.
    let m = manifest(report["bundle"].as_str().unwrap());
    let listed: Vec<&str> = m.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(listed, written[..written.len() - 1]);
    // A target outside the allowed roots is refused.
    let r = s
        .call(Request::Backup(DirArg {
            dir: s.data.join("server").display().to_string(),
        }))
        .await;
    assert_eq!(r.error.as_deref(), Some("backup/target_not_allowed"));
    within(s.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_records_backup_taken_in_anchor_chain() {
    let s = sqlite_harness("k1", KEY_A);
    s.user("alice").await;
    let report = s.backup(&s.backups()).await;
    let bundle = PathBuf::from(report["bundle"].as_str().unwrap());
    let last = s.store().anchor_last().unwrap().unwrap();
    assert_eq!(last.kind, KIND_BACKUP_TAKEN);
    assert_eq!(report["anchor_seq"], last.seq);
    let body: Value = serde_json::from_slice(&last.body_jcs).unwrap();
    let sha = hex::encode(sha256_file(&bundle.join(MANIFEST)).unwrap());
    assert_eq!(body["manifest_sha256"], sha);
    assert_eq!(report["manifest_sha256"], sha);
    // The manifest's anchor head is the snapshot's, before BACKUP_TAKEN.
    assert!(manifest(&bundle.display().to_string()).anchor_head.seq < last.seq);
    verify(s.store()).unwrap();
    within(s.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_refuses_while_serving() {
    let s = sqlite_harness("k1", KEY_A);
    s.user("alice").await;
    let report = s.backup(&s.backups()).await;
    let bundle = report["bundle"].as_str().unwrap().to_owned();
    let r = s.restore(&bundle).await;
    assert_eq!(r.error.as_deref(), Some("admin/maintenance_required"));
    // Maintenance switches are anchored and reported by the registry.
    s.maintenance(true).await;
    assert!(s.ctx.registry.maintenance());
    assert_eq!(
        s.store().anchor_last().unwrap().unwrap().kind,
        KIND_MAINTENANCE
    );
    s.maintenance(false).await;
    assert!(!s.ctx.registry.maintenance());
    within(s.ctx.registry.close_all()).await;
}

/// Rewrites one manifest entry's hash to the file's current one (a tamper that keeps the
/// manifest consistent, so only the deeper checks can catch it).
fn rehash(bundle: &str, rel: &str) {
    let mut m = manifest(bundle);
    let p = Path::new(bundle).join(rel);
    for f in m.files.iter_mut().filter(|f| f.path == rel) {
        f.sha256 = hex::encode(sha256_file(&p).unwrap());
        f.size = std::fs::metadata(&p).unwrap().len();
    }
    std::fs::write(
        Path::new(bundle).join(MANIFEST),
        serde_json::to_vec_pretty(&m).unwrap(),
    )
    .unwrap();
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        if e.path().is_dir() {
            copy_dir(&e.path(), &dst.join(e.file_name()));
        } else {
            std::fs::copy(e.path(), dst.join(e.file_name())).unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_verifies_manifest_hashes_and_every_chain_before_swap() {
    let s = sqlite_harness("k1", KEY_A);
    let a = s.user("alice").await;
    let report = s.backup(&s.backups()).await;
    let good = report["bundle"].as_str().unwrap().to_owned();
    let users_rel = format!("users/{a}");
    let db_rel = files_under(&Path::new(&good).join(&users_rel))
        .into_iter()
        .find(|p| p.extension().is_some_and(|x| x == "db"))
        .unwrap()
        .strip_prefix(&good)
        .unwrap()
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/");
    s.user("carol").await;
    s.maintenance(true).await;
    let before = s.store().anchor_all().unwrap();
    let variant = |name: &str| {
        let dir = s.backups().join(name);
        copy_dir(Path::new(&good), &dir);
        dir.display().to_string()
    };

    // (a) A file that does not match its manifest hash.
    let bad = variant("hash");
    let p = Path::new(&bad).join(&db_rel);
    let mut bytes = std::fs::read(&p).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    std::fs::write(&p, &bytes).unwrap();
    assert_eq!(
        s.restore(&bad).await.error.as_deref(),
        Some("restore/hash_mismatch")
    );

    // (b) An anchor-chain row changed in the backed-up server.db, manifest hash kept consistent.
    let bad = variant("anchor");
    let db = Path::new(&bad).join("server.db");
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(
            "DROP TRIGGER anchor_chain_no_update;
             UPDATE anchor_chain SET kind = 'TAMPERED' WHERE seq = 1;",
        )
        .unwrap();
    }
    rehash(&bad, "server.db");
    assert_eq!(
        s.restore(&bad).await.error.as_deref(),
        Some("restore/anchor_chain_invalid")
    );

    // (c) A user chain missing from the bundle (and from its manifest).
    let bad = variant("chain");
    std::fs::remove_dir_all(Path::new(&bad).join(&users_rel)).unwrap();
    let mut m = manifest(&bad);
    m.files.retain(|f| !f.path.starts_with(&users_rel));
    std::fs::write(
        Path::new(&bad).join(MANIFEST),
        serde_json::to_vec_pretty(&m).unwrap(),
    )
    .unwrap();
    assert_eq!(
        s.restore(&bad).await.error.as_deref(),
        Some("restore/chain_invalid")
    );

    // Nothing live changed: carol (after the backup) is still there, no staging dir is left.
    assert!(s.store().user_by_name("carol").unwrap().is_some());
    assert_eq!(s.store().anchor_all().unwrap(), before);
    let leftovers: Vec<String> = std::fs::read_dir(&s.data)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("restore-staging") || n.starts_with("pre-restore"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    // The untouched bundle still restores.
    assert!(s.restore(&good).await.ok);
    within(s.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_refuses_backup_wrapped_by_unknown_master_key_version() {
    let s = sqlite_harness("k1", KEY_A);
    s.user("alice").await;
    let report = s.backup(&s.backups()).await;
    let bundle = report["bundle"].as_str().unwrap().to_owned();
    // A server whose master key is another one (id k2), with the bundle copied to its backups.
    let other = sqlite_harness("k2", [0x33; 32]);
    let copied = other.backups().join("from-k1");
    copy_dir(Path::new(&bundle), &copied);
    let bundle = copied.display().to_string();
    other.maintenance(true).await;
    assert_eq!(
        other.restore(&bundle).await.error.as_deref(),
        Some("restore/unknown_master_key")
    );
    // A manifest that claims k2 does not help: the wrapped data keys say k1.
    let mut m = manifest(&bundle);
    m.master_key_id = "k2".into();
    std::fs::write(
        Path::new(&bundle).join(MANIFEST),
        serde_json::to_vec_pretty(&m).unwrap(),
    )
    .unwrap();
    assert_eq!(
        other.restore(&bundle).await.error.as_deref(),
        Some("restore/unknown_master_key")
    );
    assert!(
        other.store().users_all().unwrap().is_empty(),
        "nothing restored"
    );
    within(s.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_swaps_atomically_and_appends_restored() {
    let s = sqlite_harness("k1", KEY_A);
    let a = s.user("alice").await;
    let report = s.backup(&s.backups()).await;
    let bundle = report["bundle"].as_str().unwrap().to_owned();
    let m = manifest(&bundle);
    // After the backup: a new user, a session and an API key that the restore must drop.
    let c = s.user("carol").await;
    let session = s.ctx.sessions.create(&c, vec!["user".into()]).unwrap();
    let key = s
        .ctx
        .api_keys
        .create(
            &UserCtx::from_authenticated(&c),
            "late",
            &["read".to_owned()],
            None,
        )
        .unwrap();
    assert!(s.ctx.api_keys.authenticate(key.key.expose_secret()).is_ok());
    s.clock.advance(10);
    s.maintenance(true).await;
    let r = s.restore(&bundle).await;
    assert!(r.ok, "{r:?}");

    assert!(s.store().user_by_name("carol").unwrap().is_none());
    assert!(s.store().user(&a).unwrap().is_some());
    assert!(
        s.ctx
            .sessions
            .lookup(session.cookie_id.expose_secret())
            .is_err()
    );
    assert!(
        s.ctx
            .api_keys
            .authenticate(key.key.expose_secret())
            .is_err()
    );
    assert!(!crate::users::user_dir(&s.data, &c).exists());
    // The restored anchor chain continues: the backup's head, then RESTORED, and it verifies.
    let rows = s.store().anchor_all().unwrap();
    assert_eq!(rows.last().unwrap().kind, KIND_RESTORED);
    assert_eq!(
        hex::encode(rows[m.anchor_head.seq as usize - 1].hash),
        m.anchor_head.hash
    );
    verify(s.store()).unwrap();
    // Alice's restored chain opens and keeps working after maintenance.
    s.maintenance(false).await;
    s.activity(&a).await;
    within(s.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_keeps_previous_data_as_dated_dir_until_admin_prunes() {
    let s = sqlite_harness("k1", KEY_A);
    s.user("alice").await;
    let report = s.backup(&s.backups()).await;
    let bundle = report["bundle"].as_str().unwrap().to_owned();
    let c = s.user("carol").await;
    s.maintenance(true).await;
    let r = s.restore(&bundle).await;
    assert!(r.ok, "{r:?}");
    let previous = PathBuf::from(r.data.unwrap()["previous"].as_str().unwrap());
    assert!(
        previous
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("pre-restore-20270115T")
    );
    // Batch-1 review I-1: the copy of what was live is a full bundle in <data>/backups, so going
    // back is an ordinary restore of it.
    assert_eq!(previous.parent().unwrap(), s.backups());
    assert!(previous.join(MANIFEST).is_file());
    assert!(crate::users::user_dir(&previous, &c).is_dir());
    assert!(!super::restore::interrupted(&s.data));
    let r = s.restore(&previous.display().to_string()).await;
    assert!(r.ok, "{r:?}");
    assert!(
        s.store().user_by_name("carol").unwrap().is_some(),
        "carol is back"
    );
    // Restores keep every previous copy until an admin deletes it.
    assert!(previous.exists());
    let kept = std::fs::read_dir(s.backups())
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("pre-restore-")
        })
        .count();
    assert_eq!(kept, 2);
    within(s.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_and_restore_after_retention_keep_the_tombstone() {
    let s = sqlite_harness("k1", KEY_A);
    let a = s.user("alice").await;
    s.user("carol").await;
    // Alice was deactivated long ago and retention deleted her chain.
    s.store().user_deactivate(&a, 0, "admin", 0).unwrap();
    let r = crate::admin::retention::run(&s.ctx, false).await.unwrap();
    assert_eq!(r.deleted, 1);
    let report = s.backup(&s.backups()).await;
    let bundle = report["bundle"].as_str().unwrap().to_owned();
    s.maintenance(true).await;
    let r = s.restore(&bundle).await;
    assert!(r.ok, "{r:?}");
    let st = s.store().user_state(&a).unwrap().unwrap();
    assert!(st.chain_deleted_at.is_some() && st.deactivated_at.is_some());
    assert_eq!(s.store().user(&a).unwrap().unwrap().data_key_wrapped, "");
    verify(s.store()).unwrap();
    within(s.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_mid_restore_keeps_maintenance_and_resume_finishes_it() {
    let s = sqlite_harness("k1", KEY_A);
    let a = s.user("alice").await;
    let report = s.backup(&s.backups()).await;
    let bundle = report["bundle"].as_str().unwrap().to_owned();
    s.user("carol").await;
    s.maintenance(true).await;
    let r = within(super::restore::run_inner(
        &s.ctx,
        &bundle,
        super::restore::CrashAt::AfterUsersMoved,
    ))
    .await;
    assert_eq!(r.unwrap_err(), "restore/interrupted");
    // The journal is on disk; maintenance cannot be switched off until it is resolved.
    assert!(super::restore::interrupted(&s.data));
    let off = s.call(Request::Maintenance(SwitchArg { on: false })).await;
    assert_eq!(off.error.as_deref(), Some("restore/interrupted"));
    let r = s.call(Request::RestoreResume(NoArgs {})).await;
    assert!(r.ok, "{r:?}");
    assert!(!super::restore::interrupted(&s.data));
    assert!(s.store().user_by_name("carol").unwrap().is_none());
    assert_eq!(
        s.store().anchor_last().unwrap().unwrap().kind,
        KIND_RESTORED
    );
    verify(s.store()).unwrap();
    s.maintenance(false).await;
    s.activity(&a).await;
    within(s.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_mid_restore_can_go_back_to_the_pre_restore_bundle() {
    let s = sqlite_harness("k1", KEY_A);
    s.user("alice").await;
    let report = s.backup(&s.backups()).await;
    let bundle = report["bundle"].as_str().unwrap().to_owned();
    s.user("carol").await;
    s.maintenance(true).await;
    let r = within(super::restore::run_inner(
        &s.ctx,
        &bundle,
        super::restore::CrashAt::AfterUsersMoved,
    ))
    .await;
    assert_eq!(r.unwrap_err(), "restore/interrupted");
    s.ctx.registry.resume();
    let pre = std::fs::read_dir(s.backups())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("pre-restore-")
        })
        .unwrap();
    let r = s.restore(&pre.display().to_string()).await;
    assert!(r.ok, "{r:?}");
    assert!(!super::restore::interrupted(&s.data));
    assert!(
        s.store().user_by_name("carol").unwrap().is_some(),
        "back to before"
    );
    let leftovers: Vec<String> = std::fs::read_dir(&s.data)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("restore-staging") || n.starts_with("users-replaced"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    s.maintenance(false).await;
    within(s.ctx.registry.close_all()).await;
}

/// Batch-1 review M-5: a bundle from a v1 server is migrated on its staged copy (after the hash
/// checks), and the live v2 database then takes the migrated content.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_upgrades_a_v1_bundle() {
    let s = sqlite_harness("k1", KEY_A);
    s.user("alice").await;
    let report = s.backup(&s.backups()).await;
    let bundle = report["bundle"].as_str().unwrap().to_owned();
    {
        let c = rusqlite::Connection::open(Path::new(&bundle).join("server.db")).unwrap();
        c.execute_batch(
            "ALTER TABLE users DROP COLUMN deactivated_at;
             ALTER TABLE users DROP COLUMN deactivated_by;
             ALTER TABLE users DROP COLUMN last_login_at;
             ALTER TABLE users DROP COLUMN retention_until;
             ALTER TABLE users DROP COLUMN chain_deleted_at;
             DROP TABLE scheduler_state;
             DROP TABLE offboarding_gone;
             PRAGMA user_version = 1;",
        )
        .unwrap();
    }
    rehash(&bundle, "server.db");
    s.maintenance(true).await;
    let r = s.restore(&bundle).await;
    assert!(r.ok, "{r:?}");
    assert!(s.store().user_by_name("alice").unwrap().is_some());
    assert!(
        s.store().scheduler_get("retention").is_ok(),
        "v2 tables exist"
    );
    s.maintenance(false).await;
    within(s.ctx.registry.close_all()).await;
}

/// Lead decision after batch 3: `backup --stdout` streams a bundle as tar after its answer line,
/// keeps nothing on the volume, and `restore --stdin` restores that stream on another server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_streams_as_tar_and_restore_reads_the_stream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let s = sqlite_harness("k1", KEY_A);
    s.user("alice").await;
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let ctx = s.ctx.clone();
    let task = tokio::spawn(async move { serve_conn(&ctx, server).await });
    client
        .write_all(b"{\"op\":\"backup_stream\"}\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    within(client.read_to_end(&mut out)).await.unwrap();
    within(task).await.unwrap().unwrap();
    let nl = out.iter().position(|&b| b == b'\n').unwrap();
    let head: Response = serde_json::from_slice(&out[..nl]).unwrap();
    assert!(head.ok, "{head:?}");
    let tar = out[nl + 1..].to_vec();
    assert_eq!(tar.len() % 512, 0);
    let left: Vec<_> = std::fs::read_dir(s.backups()).unwrap().collect();
    assert!(
        left.is_empty(),
        "the streamed bundle is not kept on the volume"
    );

    let other = sqlite_harness("k1", KEY_A);
    // Not in maintenance: refused.
    let refused = stream_restore(&other, &tar).await;
    assert_eq!(refused.error.as_deref(), Some("admin/maintenance_required"));
    other.maintenance(true).await;
    let r = stream_restore(&other, &tar).await;
    assert!(r.ok, "{r:?}");
    assert!(other.store().user_by_name("alice").unwrap().is_some());
    let uploads = std::fs::read_dir(other.backups())
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("upload-")
        })
        .count();
    assert_eq!(uploads, 0, "the upload is removed");
    // A damaged stream is refused before anything live changes.
    let mut bad = tar.clone();
    let mid = 512 * 3 + 10;
    bad[mid] ^= 0xff;
    let r = stream_restore(&other, &bad).await;
    assert!(!r.ok);
    within(s.ctx.registry.close_all()).await;
    within(other.ctx.registry.close_all()).await;
}

async fn stream_restore(s: &S, tar: &[u8]) -> Response {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let ctx = s.ctx.clone();
    let task = tokio::spawn(async move { serve_conn(&ctx, server).await });
    let body = tar.to_vec();
    let writer = tokio::spawn(async move {
        // The server may answer (a refusal) before it reads the stream: write errors are fine.
        let _ = client.write_all(b"{\"op\":\"restore_stream\"}\n").await;
        let _ = client.write_all(&body).await;
        let _ = client.shutdown().await;
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        out
    });
    let out = within(writer).await.unwrap();
    within(task).await.unwrap().unwrap();
    serde_json::from_slice(&out).unwrap()
}

/// The stream reader refuses paths that leave the upload directory.
#[tokio::test]
async fn a_tar_stream_with_an_escaping_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["../evil", "/abs/evil", "bundle/../../evil"] {
        let mut tar = super::tarball::header(name, 3, false).unwrap().to_vec();
        tar.extend_from_slice(b"abc");
        tar.resize(1024, 0);
        tar.extend_from_slice(&[0u8; 1024]);
        let dest = dir.path().join(format!("u{}", name.len()));
        let r = super::tarball::read_into(&mut tar.as_slice(), &dest, 1 << 20).await;
        assert_eq!(r.unwrap_err(), "restore/stream_invalid", "{name}");
        assert!(!dir.path().join("evil").exists());
    }
}
