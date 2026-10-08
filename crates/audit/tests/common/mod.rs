//! Helpers shared by the store-level integration tests.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use atlas_duck_audit::clock::{Clock, UtcInstant, parse_epoch};
use atlas_duck_audit::encoding::{FIELD_LIST, RowFields, ZERO_HASH};
use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::request_set::{RequestRecord, request_set_hash, requests_to_json};
use atlas_duck_audit::schema::DB_FILE;
use atlas_duck_audit::testing::{FakeClock, MemKeyStore, MemKeyring};
use atlas_duck_audit::types::{Actor, EventType, NewEvent};
use atlas_duck_audit::{
    FilePolicy, FirstRunInput, Hooks, OpenConfig, Settings, StartupOutcome, Store,
    create_new_store, new_ids, open,
};
use atlas_duck_ipc::paths::{DataDirResolution, LocalDataDir, check_data_dir};
use chrono::{Datelike, NaiveDate};
use rusqlite::Connection;
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;

/// 21 characters: above the 12-character minimum.
pub const PASSPHRASE: &str = "correct horse battery";
pub const START: &str = "2026-10-08T12:00:00.000Z";

pub fn at(ts: &str) -> UtcInstant {
    UtcInstant::parse_rfc3339_ms(ts).expect("test timestamp")
}

pub fn fake_clock(ts: &str) -> Arc<FakeClock> {
    Arc::new(FakeClock::new(at(ts)))
}

/// A fresh temp dir that passed the §7.7 local check, with `instance.lock` held.
pub fn tmp_data_dir() -> (TempDir, LocalDataDir, InstanceLock) {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = match check_data_dir(dir.path()).expect("check_data_dir") {
        DataDirResolution::Local(d) => d,
        _ => panic!("temp dir is not local"),
    };
    let lock = InstanceLock::acquire(&data, "testhost").expect("instance.lock");
    (dir, data, lock)
}

pub struct Fixture {
    pub dir: TempDir,
    pub data: LocalDataDir,
    pub lock: InstanceLock,
    pub ring: Arc<MemKeyring>,
    pub clock: Arc<FakeClock>,
    pub install_id: String,
    pub chain_id: String,
}

impl Fixture {
    pub fn db_path(&self) -> PathBuf {
        self.dir.path().join(DB_FILE)
    }

    pub fn keys(&self) -> Arc<MemKeyStore> {
        Arc::new(MemKeyStore::new(self.ring.clone(), &self.install_id))
    }

    pub fn config(&self) -> OpenConfig {
        OpenConfig::new(self.clock.clone(), self.keys())
    }
}

pub fn input(install_id: &str, chain_id: &str, pass: &str, confirm: &str) -> FirstRunInput {
    FirstRunInput {
        install_id: install_id.to_string(),
        chain_id: chain_id.to_string(),
        passphrase: SecretString::from(pass.to_string()),
        passphrase_confirm: SecretString::from(confirm.to_string()),
        archived_db: None,
    }
}

/// A data dir and ids without a store yet.
pub fn fixture(clock: Arc<FakeClock>, ring: Arc<MemKeyring>) -> Fixture {
    let (dir, data, lock) = tmp_data_dir();
    let (install_id, chain_id) = new_ids().expect("ids");
    Fixture {
        dir,
        data,
        lock,
        ring,
        clock,
        install_id,
        chain_id,
    }
}

pub fn new_store_with(
    clock: Arc<FakeClock>,
    ring: Arc<MemKeyring>,
    tweak: impl FnOnce(&mut OpenConfig),
) -> (Store, Fixture) {
    let f = fixture(clock, ring);
    let mut cfg = f.config();
    tweak(&mut cfg);
    let store = create_new_store(
        &f.data,
        &f.lock,
        cfg,
        input(&f.install_id, &f.chain_id, PASSPHRASE, PASSPHRASE),
    )
    .expect("create_new_store");
    (store, f)
}

/// `create_new_store` with the fixed passphrase.
pub fn new_store(clock: Arc<FakeClock>, ring: Arc<MemKeyring>) -> (Store, Fixture) {
    new_store_with(clock, ring, |_| {})
}

pub fn ev(t: EventType, request_id: Option<&str>, payload: serde_json::Value) -> NewEvent {
    NewEvent {
        event_type: t,
        request_id: request_id.map(str::to_string),
        op_id: None,
        op_class: None,
        instance_id: None,
        target: None,
        actor: Default::default(),
        decision: None,
        flags: Default::default(),
        payload,
    }
}

pub fn server_time(ts: &str) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(at(ts).0 as u64)
}

/// The next records get a non-NULL epoch (the server agrees with the local clock).
pub fn corroborate(store: &Store) {
    store.observe_server_date("i1", server_time(START), Instant::now());
}

pub const DAY: Duration = Duration::from_secs(86_400);

/// A server `Date` equal to the fake wall clock now (the local clock is right).
pub fn corroborate_now(store: &Store, clock: &FakeClock) {
    let now = clock.now_utc();
    store.observe_server_date(
        "i1",
        UNIX_EPOCH + Duration::from_millis(now.0 as u64),
        Instant::now(),
    );
}

/// What prune needs: the retention in force (set without a log row, so seqs stay exact) and
/// the config file reconciled (an empty file policy).
pub fn prune_ready(store: &Store, retention_days: u32) {
    store
        .testing_set_settings(Settings {
            retention_days,
            ..Settings::default()
        })
        .expect("settings");
    store
        .reconcile_config_file(&FilePolicy::default())
        .expect("config reconciled");
}

/// Returns once the writer handled every command queued so far and the prune attempt they
/// queued (attempts run on the writer between commands).
pub fn sync_writer(store: &Store) {
    store
        .testing_pragma("user_version")
        .expect("writer round-trip");
}

pub fn day_events(n: usize) -> Vec<NewEvent> {
    (0..n)
        .map(|i| ev(EventType::APP_START, None, json!({ "i": i })))
        .collect()
}

/// One simulated day: wall and monotonic clock +24 h, a server `Date` agreeing with the local
/// clock, `n` events, the prune attempt they queued, then both anchors written.
pub fn day(store: &Store, clock: &FakeClock, n: usize) {
    clock.advance(DAY);
    corroborate_now(store, clock);
    if n > 0 {
        store.append_batch(day_events(n)).expect("append_batch");
    }
    sync_writer(store);
    store.flush_head_anchor().expect("flush");
}

/// `n` events of several kinds and column shapes (no store-owned type).
pub fn mixed(n: usize) -> Vec<NewEvent> {
    (0..n)
        .map(|i| {
            let mut e = match i % 6 {
                0 => ev(EventType::REQUEST_RECEIVED, Some("r1"), json!({ "i": i })),
                1 => ev(
                    EventType::READ_FETCHED,
                    Some("r1"),
                    json!({ "body": "x".repeat(i) }),
                ),
                2 => ev(
                    EventType::DELIVERED,
                    Some("r1"),
                    json!({ "i": i, "ok": true }),
                ),
                3 => ev(
                    EventType::CONFIG_CHANGED,
                    None,
                    json!({ "key": "k", "i": i }),
                ),
                4 => write_approved(i, true),
                _ => ev(EventType::APP_START, None, json!({ "i": i })),
            };
            if i % 2 == 0 {
                e.target = Some(format!("PROJ-{i}"));
                e.actor = Actor {
                    agent_name: Some("agent".into()),
                    os_user: Some("alice".into()),
                    peer_pid: Some(4242),
                    ..Actor::default()
                };
            }
            e
        })
        .collect()
}

pub fn requests(i: usize) -> Vec<RequestRecord> {
    vec![RequestRecord {
        index: 0,
        method: "POST".into(),
        resolved_url: format!("https://jira.example/rest/api/2/issue/{i}"),
        content_type: Some("application/json".into()),
        body_bytes: format!("{{\"n\":{i}}}").into_bytes(),
    }]
}

/// A `WRITE_APPROVED` whose `request_set_hash` matches its `requests` (or not).
pub fn write_approved(i: usize, correct: bool) -> NewEvent {
    let reqs = requests(i);
    let hash = if correct {
        request_set_hash(&reqs)
    } else {
        request_set_hash(&requests(i + 1))
    };
    ev(
        EventType::WRITE_APPROVED,
        Some("w1"),
        json!({
            "candidate_rev": 1,
            "request_set_hash": hex::encode(hash),
            "requests": requests_to_json(&reqs),
        }),
    )
}

/// A plain read-write connection for inspection and tampering.
pub fn raw_conn(f: &Fixture) -> Connection {
    let c = Connection::open(f.db_path()).expect("raw connection");
    c.busy_timeout(std::time::Duration::from_secs(5))
        .expect("busy_timeout");
    c
}

/// One `events` row, owned.
#[derive(Clone)]
pub struct RawRow {
    pub seq: u64,
    pub format_version: u64,
    pub chain_id: String,
    pub ts_utc: String,
    pub epoch: Option<String>,
    pub request_id: Option<String>,
    pub event_type: String,
    pub op_id: Option<String>,
    pub op_class: Option<String>,
    pub instance_id: Option<String>,
    pub target: Option<String>,
    pub agent_name: Option<String>,
    pub agent_name_source: Option<String>,
    pub client_kind: Option<String>,
    pub connection_id: Option<String>,
    pub peer_pid: Option<u64>,
    pub peer_exe: Option<Vec<u8>>,
    pub peer_origin_exe: Option<Vec<u8>>,
    pub os_user: Option<String>,
    pub atlassian_user: Option<String>,
    pub atlassian_user_key: Option<String>,
    pub decision: Option<String>,
    pub flags: u64,
    pub payload_len: u64,
    pub payload_sha256: [u8; 32],
    pub key_id: u64,
    pub nonce: [u8; 12],
    pub payload_ct: Vec<u8>,
    pub prev_hash: [u8; 32],
    pub record_hash: [u8; 32],
}

impl RawRow {
    pub fn fields(&self) -> RowFields<'_> {
        RowFields {
            seq: self.seq,
            format_version: self.format_version,
            chain_id: &self.chain_id,
            ts_utc: &self.ts_utc,
            epoch: self.epoch.as_deref(),
            request_id: self.request_id.as_deref(),
            event_type: &self.event_type,
            op_id: self.op_id.as_deref(),
            op_class: self.op_class.as_deref(),
            instance_id: self.instance_id.as_deref(),
            target: self.target.as_deref(),
            agent_name: self.agent_name.as_deref(),
            agent_name_source: self.agent_name_source.as_deref(),
            client_kind: self.client_kind.as_deref(),
            connection_id: self.connection_id.as_deref(),
            peer_pid: self.peer_pid,
            peer_exe: self.peer_exe.as_deref(),
            peer_origin_exe: self.peer_origin_exe.as_deref(),
            os_user: self.os_user.as_deref(),
            atlassian_user: self.atlassian_user.as_deref(),
            atlassian_user_key: self.atlassian_user_key.as_deref(),
            decision: self.decision.as_deref(),
            flags: self.flags,
            payload_len: self.payload_len,
            payload_sha256: &self.payload_sha256,
            key_id: self.key_id,
            nonce: &self.nonce,
            payload_ct: &self.payload_ct,
            prev_hash: &self.prev_hash,
        }
    }

    pub fn recompute(&self) -> [u8; 32] {
        self.fields().record_hash().expect("record_hash")
    }
}

pub fn dump_conn(c: &Connection) -> Vec<RawRow> {
    let sql = format!(
        "SELECT {}, record_hash FROM events ORDER BY seq",
        FIELD_LIST.join(", ")
    );
    let mut st = c.prepare(&sql).expect("prepare");
    let mut rows = st.query([]).expect("query");
    let mut out = Vec::new();
    while let Some(r) = rows.next().expect("row") {
        let f = RowFields::from_row(r).expect("from_row");
        let rh: Vec<u8> = r.get(FIELD_LIST.len()).expect("record_hash");
        out.push(RawRow {
            seq: f.seq,
            format_version: f.format_version,
            chain_id: f.chain_id.into(),
            ts_utc: f.ts_utc.into(),
            epoch: f.epoch.map(Into::into),
            request_id: f.request_id.map(Into::into),
            event_type: f.event_type.into(),
            op_id: f.op_id.map(Into::into),
            op_class: f.op_class.map(Into::into),
            instance_id: f.instance_id.map(Into::into),
            target: f.target.map(Into::into),
            agent_name: f.agent_name.map(Into::into),
            agent_name_source: f.agent_name_source.map(Into::into),
            client_kind: f.client_kind.map(Into::into),
            connection_id: f.connection_id.map(Into::into),
            peer_pid: f.peer_pid,
            peer_exe: f.peer_exe.map(<[u8]>::to_vec),
            peer_origin_exe: f.peer_origin_exe.map(<[u8]>::to_vec),
            os_user: f.os_user.map(Into::into),
            atlassian_user: f.atlassian_user.map(Into::into),
            atlassian_user_key: f.atlassian_user_key.map(Into::into),
            decision: f.decision.map(Into::into),
            flags: f.flags,
            payload_len: f.payload_len,
            payload_sha256: *f.payload_sha256,
            key_id: f.key_id,
            nonce: *f.nonce,
            payload_ct: f.payload_ct.to_vec(),
            prev_hash: *f.prev_hash,
            record_hash: rh.try_into().expect("32-byte record_hash"),
        });
    }
    out
}

pub fn dump_rows(f: &Fixture) -> Vec<RawRow> {
    dump_conn(&raw_conn(f))
}

/// Seqs contiguous from 1, `GENESIS` first with a zero `prev_hash`, every link and every
/// `record_hash` recomputed with the T02 functions.
pub fn assert_chain(rows: &[RawRow]) {
    assert!(!rows.is_empty());
    assert_eq!(rows[0].seq, 1);
    assert_eq!(rows[0].event_type, "GENESIS");
    assert_eq!(rows[0].prev_hash, ZERO_HASH);
    for (i, r) in rows.iter().enumerate() {
        assert_eq!(r.seq, i as u64 + 1, "seq gap");
        assert_eq!(r.format_version, 1);
        assert_eq!(r.recompute(), r.record_hash, "record_hash of seq {}", r.seq);
        if i > 0 {
            assert_eq!(
                r.prev_hash,
                rows[i - 1].record_hash,
                "link at seq {}",
                r.seq
            );
        }
    }
}

/// `(key_id, month, created_at)` of every `keys` row.
pub fn key_rows(f: &Fixture) -> Vec<(u64, Option<String>, String)> {
    let c = raw_conn(f);
    let mut st = c
        .prepare("SELECT key_id, month, created_at FROM keys ORDER BY key_id")
        .expect("prepare");
    st.query_map([], |r| {
        Ok((r.get::<_, i64>(0)? as u64, r.get(1)?, r.get(2)?))
    })
    .expect("query")
    .map(|r| r.expect("row"))
    .collect()
}

// ---------------------------------------------------------------------------------------
// The clock scenario driver (T13)

/// A store living through simulated months. `real` is the true time; the fake clock's wall
/// time is `real + offset` (a wrong local clock) and its monotonic time moves with `real`
/// except during a suspend. The server `Date` is always `real`.
///
/// After every operation the driver reads the database and remembers, per record, the real
/// time it first appeared, which rows disappeared (and when), the anomaly payloads, and any
/// `epoch` or DEK month ahead of the real date at the time it was written.
pub struct Sim {
    pub store: Store,
    pub f: Fixture,
    hooks: Hooks,
    pub retention: u32,
    pub real: UtcInstant,
    offset_ms: i64,
    /// `seq` -> real instant first seen.
    written: BTreeMap<u64, UtcInstant>,
    /// `(seq, written, deleted by a prune at)`.
    deleted: Vec<(u64, UtcInstant, UtcInstant)>,
    keys_seen: BTreeSet<u64>,
    anomalies: Vec<Value>,
    violations: Vec<String>,
}

impl Sim {
    /// A first run at real time `real_start` whose local clock is `wall_offset_days` off,
    /// prune-ready (retention in force, config file reconciled), nothing corroborated yet.
    /// Runs with `synchronous=NORMAL`.
    pub fn new(real_start: &str, retention: u32, wall_offset_days: i64) -> Sim {
        let real = at(real_start);
        let offset_ms = wall_offset_days * 86_400_000;
        let mut hooks = Hooks::default();
        let (store, f) = new_store_with(
            fake_clock(&UtcInstant(real.0 + offset_ms).to_rfc3339_ms()),
            MemKeyring::new(),
            |cfg| {
                cfg.hooks.synchronous_normal = true;
                hooks = cfg.hooks.clone();
            },
        );
        prune_ready(&store, retention);
        let mut sim = Sim {
            store,
            f,
            hooks,
            retention,
            real,
            offset_ms,
            written: BTreeMap::new(),
            deleted: Vec::new(),
            keys_seen: BTreeSet::new(),
            anomalies: Vec::new(),
            violations: Vec::new(),
        };
        sim.track();
        sim
    }

    pub fn real_date(&self) -> NaiveDate {
        self.real.date()
    }

    pub fn wall_date(&self) -> NaiveDate {
        self.f.clock.now_utc().date()
    }

    fn sync_wall(&self) {
        self.f
            .clock
            .set_wall(UtcInstant(self.real.0 + self.offset_ms));
    }

    /// Real time +`d`; the wall clock follows (with its offset), the monotonic clock only
    /// when `mono` is set.
    fn advance(&mut self, d: Duration, mono: bool) {
        self.real.0 += d.as_millis() as i64;
        self.sync_wall();
        if mono {
            self.f.clock.advance_mono_only(d);
        }
    }

    /// One real day passes (all clocks), without a server response or records.
    pub fn tick(&mut self) {
        self.advance(DAY, true);
    }

    /// The local clock is wrong by `days` from now on (0 corrects it).
    pub fn set_wall_offset_days(&mut self, days: i64) {
        self.offset_ms = days * 86_400_000;
        self.sync_wall();
    }

    /// A successful response with a `Date` header of the real time.
    pub fn server_date(&self) {
        self.store.observe_server_date(
            "i1",
            server_time(&self.real.to_rfc3339_ms()),
            Instant::now(),
        );
    }

    /// `n` events now, the prune attempt they queued, both anchors, then the bookkeeping.
    pub fn append(&mut self, n: usize) {
        if n > 0 {
            self.store
                .append_batch(day_events(n))
                .expect("append_batch");
        }
        self.settle();
    }

    pub fn settle(&mut self) {
        sync_writer(&self.store);
        self.store.flush_head_anchor().expect("flush");
        self.track();
    }

    /// One simulated day: real +24 h on every clock, a server response, `n` events.
    pub fn day(&mut self, n: usize) {
        self.tick();
        self.server_date();
        self.append(n);
    }

    pub fn days(&mut self, k: usize, n: usize) {
        for _ in 0..k {
            self.day(n);
        }
    }

    /// The machine sleeps: real and wall time advance, the monotonic clock does not, no
    /// server response arrives.
    pub fn suspend(&mut self, d: Duration) {
        self.advance(d, false);
    }

    fn reopen(&mut self) {
        let mut cfg = self.f.config();
        cfg.hooks = self.hooks.clone();
        match open(&self.f.data, &self.f.lock, cfg).expect("open") {
            StartupOutcome::Ready { store, .. } => self.store = store,
            other => panic!("not ready: {other:?}"),
        }
        prune_ready(&self.store, self.retention);
    }

    /// Shutdown and start again at the same time (nothing corroborated yet).
    pub fn restart(&mut self) {
        self.store.shutdown();
        self.reopen();
        self.settle();
    }

    /// The app is not running for `days`: every clock advances, then it starts again and
    /// reconciles its config file.
    pub fn off(&mut self, days: u64) {
        self.store.shutdown();
        self.advance(DAY * days as u32, true);
        self.reopen();
        self.settle();
    }

    /// Reads the database after an operation. A row seen for the first time was written at
    /// `real`; a row that disappeared was deleted by a prune at `real`.
    fn track(&mut self) {
        let c = raw_conn(&self.f);
        let mut st = c
            .prepare("SELECT seq, epoch, event_type FROM events ORDER BY seq")
            .expect("prepare");
        let rows: Vec<(u64, Option<String>, String)> = st
            .query_map([], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get(1)?, r.get(2)?))
            })
            .expect("query")
            .map(|r| r.expect("row"))
            .collect();
        let now: BTreeSet<u64> = rows.iter().map(|r| r.0).collect();
        let gone: Vec<u64> = self
            .written
            .keys()
            .filter(|s| !now.contains(s))
            .copied()
            .collect();
        for seq in gone {
            let w = self.written.remove(&seq).expect("tracked");
            self.deleted.push((seq, w, self.real));
        }
        for (seq, epoch, event_type) in rows {
            if self.written.contains_key(&seq) {
                continue;
            }
            self.written.insert(seq, self.real);
            if let Some(e) = epoch
                && parse_epoch(&e).expect("epoch text") > self.real_date()
            {
                self.violations.push(format!(
                    "seq {seq} has epoch {e} on real {}",
                    self.real_date()
                ));
            }
            if event_type == "CLOCK_ANOMALY" {
                let p = self.store.read_payload(seq).expect("read_payload");
                self.anomalies
                    .push(serde_json::from_slice(&p).expect("json"));
            }
        }
        let today = self.real_date();
        for (key_id, month, _) in key_rows(&self.f) {
            if !self.keys_seen.insert(key_id) {
                continue;
            }
            if let Some(m) = month {
                let (y, mo) = m.split_once('-').expect("YYYY-MM");
                let key = (
                    y.parse::<i32>().expect("year"),
                    mo.parse::<u32>().expect("month"),
                );
                if key > (today.year(), today.month()) {
                    self.violations
                        .push(format!("key {key_id} for month {m} on real {today}"));
                }
            }
        }
    }

    /// Every row deleted so far was written at least `retention` real days (by date) before
    /// the real time of the prune that deleted it.
    pub fn assert_no_early_prune(&self, retention: u32) {
        for (seq, written, deleted_at) in &self.deleted {
            let age = (deleted_at.date() - written.date()).num_days();
            assert!(
                age >= i64::from(retention),
                "seq {seq} written {} was pruned {} ({age} real days)",
                written.date(),
                deleted_at.date()
            );
        }
    }

    /// No `epoch` and no DEK month was ever ahead of the real date of the time it appeared.
    pub fn assert_no_future_epoch_or_dek(&self) {
        assert!(self.violations.is_empty(), "{:?}", self.violations);
    }

    /// How many rows were deleted so far.
    pub fn deleted_count(&self) -> usize {
        self.deleted.len()
    }

    /// The payload of every `CLOCK_ANOMALY` row seen so far (also the pruned ones).
    pub fn anomalies(&self) -> Vec<Value> {
        self.anomalies.clone()
    }

    /// The `local_ahead` / `local_behind` anomalies (not the `prune_skipped` ones).
    pub fn episode_anomalies(&self, kind: &str) -> Vec<Value> {
        self.anomalies
            .iter()
            .filter(|a| a["kind"] == kind)
            .cloned()
            .collect()
    }
}
