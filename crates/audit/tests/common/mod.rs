//! Helpers shared by the store-level integration tests.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use atlas_duck_audit::clock::UtcInstant;
use atlas_duck_audit::encoding::{FIELD_LIST, RowFields, ZERO_HASH};
use atlas_duck_audit::lock::InstanceLock;
use atlas_duck_audit::request_set::{RequestRecord, request_set_hash, requests_to_json};
use atlas_duck_audit::schema::DB_FILE;
use atlas_duck_audit::testing::{FakeClock, MemKeyStore, MemKeyring};
use atlas_duck_audit::types::{Actor, EventType, NewEvent};
use atlas_duck_audit::{FirstRunInput, OpenConfig, Store, create_new_store, new_ids};
use atlas_duck_ipc::paths::{DataDirResolution, LocalDataDir, check_data_dir};
use rusqlite::Connection;
use secrecy::SecretString;
use serde_json::json;
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
