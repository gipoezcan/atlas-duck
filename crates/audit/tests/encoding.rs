//! Canonical encoding `FIELD_LIST[1]`, `record_hash`, AAD, `request_set_hash` and the
//! prune-log row hash (§8.4, §5.1 inv. 3, plan F.2/F.8/F.9).

use atlas_duck_audit::encoding::{
    FIELD_LIST, Field, RowFields, ZERO_HASH, aad, canonical_bytes, prune_row_hash, push_frame,
    record_hash,
};
use atlas_duck_audit::error::AuditError;
use atlas_duck_audit::request_set::{requests_from_json, requests_to_json};
use atlas_duck_audit::{RequestRecord, request_set_hash};
use proptest::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

/// An owned row, so tests and proptest can build and mutate rows; `fields()` borrows it.
#[derive(Clone, Debug, PartialEq)]
struct Row {
    seq: u64,
    format_version: u64,
    chain_id: String,
    ts_utc: String,
    epoch: Option<String>,
    request_id: Option<String>,
    event_type: String,
    op_id: Option<String>,
    op_class: Option<String>,
    instance_id: Option<String>,
    target: Option<String>,
    agent_name: Option<String>,
    agent_name_source: Option<String>,
    client_kind: Option<String>,
    connection_id: Option<String>,
    peer_pid: Option<u64>,
    peer_exe: Option<Vec<u8>>,
    peer_origin_exe: Option<Vec<u8>>,
    os_user: Option<String>,
    atlassian_user: Option<String>,
    atlassian_user_key: Option<String>,
    decision: Option<String>,
    flags: u64,
    payload_len: u64,
    payload_sha256: [u8; 32],
    key_id: u64,
    nonce: [u8; 12],
    payload_ct: Vec<u8>,
    prev_hash: [u8; 32],
}

impl Row {
    fn fields(&self) -> RowFields<'_> {
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

    /// Copies field `i` (0-based F.2 index) from `o`.
    fn copy_field(&mut self, o: &Row, i: usize) {
        match i {
            0 => self.seq = o.seq,
            1 => self.format_version = o.format_version,
            2 => self.chain_id = o.chain_id.clone(),
            3 => self.ts_utc = o.ts_utc.clone(),
            4 => self.epoch = o.epoch.clone(),
            5 => self.request_id = o.request_id.clone(),
            6 => self.event_type = o.event_type.clone(),
            7 => self.op_id = o.op_id.clone(),
            8 => self.op_class = o.op_class.clone(),
            9 => self.instance_id = o.instance_id.clone(),
            10 => self.target = o.target.clone(),
            11 => self.agent_name = o.agent_name.clone(),
            12 => self.agent_name_source = o.agent_name_source.clone(),
            13 => self.client_kind = o.client_kind.clone(),
            14 => self.connection_id = o.connection_id.clone(),
            15 => self.peer_pid = o.peer_pid,
            16 => self.peer_exe = o.peer_exe.clone(),
            17 => self.peer_origin_exe = o.peer_origin_exe.clone(),
            18 => self.os_user = o.os_user.clone(),
            19 => self.atlassian_user = o.atlassian_user.clone(),
            20 => self.atlassian_user_key = o.atlassian_user_key.clone(),
            21 => self.decision = o.decision.clone(),
            22 => self.flags = o.flags,
            23 => self.payload_len = o.payload_len,
            24 => self.payload_sha256 = o.payload_sha256,
            25 => self.key_id = o.key_id,
            26 => self.nonce = o.nonce,
            27 => self.payload_ct = o.payload_ct.clone(),
            28 => self.prev_hash = o.prev_hash,
            _ => panic!("no field {i}"),
        }
    }
}

fn minimal_row() -> Row {
    // GENESIS before any corroboration: epoch NULL and flags 0 (L36, L47).
    Row {
        seq: 1,
        format_version: 1,
        chain_id: "c".into(),
        ts_utc: "1970-01-01T00:00:00.000Z".into(),
        epoch: None,
        request_id: None,
        event_type: "GENESIS".into(),
        op_id: None,
        op_class: None,
        instance_id: None,
        target: Some("i".into()),
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
        payload_len: 2,
        payload_sha256: [0xAA; 32],
        key_id: 1,
        nonce: [0x11; 12],
        payload_ct: vec![0x22; 3],
        prev_hash: [0; 32],
    }
}

/// Every column present, every value different from `full_row_b`.
fn full_row_a() -> Row {
    Row {
        seq: 7,
        format_version: 1,
        chain_id: "chain-a".into(),
        ts_utc: "2026-10-08T12:00:00.123Z".into(),
        epoch: Some("2026-10-08".into()),
        request_id: Some("req-a".into()),
        event_type: "REQUEST_RECEIVED".into(),
        op_id: Some("jira.issue.get".into()),
        op_class: Some("read".into()),
        instance_id: Some("inst-a".into()),
        target: Some("PROJ-1".into()),
        agent_name: Some("agent-a".into()),
        agent_name_source: Some("flag".into()),
        client_kind: Some("cli".into()),
        connection_id: Some("conn-a".into()),
        peer_pid: Some(100),
        peer_exe: Some(b"/bin/a".to_vec()),
        peer_origin_exe: Some(b"/bin/sh".to_vec()),
        os_user: Some("alice".into()),
        atlassian_user: Some("alice.a".into()),
        atlassian_user_key: Some("JIRAUSER1".into()),
        decision: Some("approve".into()),
        flags: 1,
        payload_len: 10,
        payload_sha256: [0x01; 32],
        key_id: 2,
        nonce: [0x02; 12],
        payload_ct: vec![0x03; 20],
        prev_hash: [0x04; 32],
    }
}

fn full_row_b() -> Row {
    Row {
        seq: 8,
        format_version: 2,
        chain_id: "chain-b".into(),
        ts_utc: "2026-10-08T12:00:00.124Z".into(),
        epoch: Some("2026-10-09".into()),
        request_id: Some("req-b".into()),
        event_type: "READ_RELEASED".into(),
        op_id: Some("jira.issue.search".into()),
        op_class: Some("write".into()),
        instance_id: Some("inst-b".into()),
        target: Some("PROJ-2".into()),
        agent_name: Some("agent-b".into()),
        agent_name_source: Some("env".into()),
        client_kind: Some("mcp".into()),
        connection_id: Some("conn-b".into()),
        peer_pid: Some(101),
        peer_exe: Some(b"/bin/b".to_vec()),
        peer_origin_exe: Some(b"/bin/zsh".to_vec()),
        os_user: Some("bob".into()),
        atlassian_user: Some("bob.b".into()),
        atlassian_user_key: Some("JIRAUSER2".into()),
        decision: Some("deny".into()),
        flags: 2,
        payload_len: 11,
        payload_sha256: [0x11; 32],
        key_id: 3,
        nonce: [0x12; 12],
        payload_ct: vec![0x13; 20],
        prev_hash: [0x14; 32],
    }
}

fn frame(f: Field<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    push_frame(&mut out, &f).unwrap();
    out
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

const NULL: [u8; 5] = [0x00, 0x00, 0x00, 0x00, 0x00];
const INT_1: [u8; 13] = [
    0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

#[test]
fn null_and_empty_differ() {
    assert_eq!(frame(Field::Null), [0x00, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(frame(Field::Bytes(b"")), [0x01, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(frame(Field::Int(1)), INT_1);
    assert_eq!(
        frame(Field::Int(0x0102_0304_0506_0708)),
        [
            0x01, 0x00, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        ]
    );
    assert_eq!(
        frame(Field::Bytes(b"ab")),
        [0x01, 0x00, 0x00, 0x00, 0x02, b'a', b'b']
    );
}

#[test]
fn field_list_is_the_events_columns_in_order() {
    assert_eq!(
        FIELD_LIST,
        [
            "seq",
            "format_version",
            "chain_id",
            "ts_utc",
            "epoch",
            "request_id",
            "event_type",
            "op_id",
            "op_class",
            "instance_id",
            "target",
            "agent_name",
            "agent_name_source",
            "client_kind",
            "connection_id",
            "peer_pid",
            "peer_exe",
            "peer_origin_exe",
            "os_user",
            "atlassian_user",
            "atlassian_user_key",
            "decision",
            "flags",
            "payload_len",
            "payload_sha256",
            "key_id",
            "nonce",
            "payload_ct",
            "prev_hash",
        ]
    );
}

#[test]
fn canonical_layout_minimal_row() {
    let row = minimal_row();
    let got = canonical_bytes(&row.fields()).unwrap();

    let int2: [u8; 13] = [
        0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ];
    let int0: [u8; 13] = [
        0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut sha = vec![0x01, 0x00, 0x00, 0x00, 0x20];
    sha.extend_from_slice(&[0xAA; 32]);
    let mut nonce = vec![0x01, 0x00, 0x00, 0x00, 0x0C];
    nonce.extend_from_slice(&[0x11; 12]);
    let mut prev = vec![0x01, 0x00, 0x00, 0x00, 0x20];
    prev.extend_from_slice(&[0x00; 32]);

    let frames: [&[u8]; 29] = [
        &INT_1,                                                                // 1 seq
        &INT_1,                                                                // 2 format_version
        &[0x01, 0x00, 0x00, 0x00, 0x01, b'c'],                                 // 3 chain_id
        &cat(&[&[0x01, 0x00, 0x00, 0x00, 0x18], b"1970-01-01T00:00:00.000Z"]), // 4 ts_utc
        &NULL,                                                                 // 5 epoch
        &NULL,                                                                 // 6 request_id
        &cat(&[&[0x01, 0x00, 0x00, 0x00, 0x07], b"GENESIS"]),                  // 7 event_type
        &NULL,                                                                 // 8 op_id
        &NULL,                                                                 // 9 op_class
        &NULL,                                                                 // 10 instance_id
        &[0x01, 0x00, 0x00, 0x00, 0x01, b'i'],                                 // 11 target
        &NULL,                                                                 // 12 agent_name
        &NULL,                                             // 13 agent_name_source
        &NULL,                                             // 14 client_kind
        &NULL,                                             // 15 connection_id
        &NULL,                                             // 16 peer_pid
        &NULL,                                             // 17 peer_exe
        &NULL,                                             // 18 peer_origin_exe
        &NULL,                                             // 19 os_user
        &NULL,                                             // 20 atlassian_user
        &NULL,                                             // 21 atlassian_user_key
        &NULL,                                             // 22 decision
        &int0,                                             // 23 flags
        &int2,                                             // 24 payload_len
        &sha,                                              // 25 payload_sha256
        &INT_1,                                            // 26 key_id
        &nonce,                                            // 27 nonce
        &[0x01, 0x00, 0x00, 0x00, 0x03, 0x22, 0x22, 0x22], // 28 payload_ct
        &prev,                                             // 29 prev_hash
    ];
    let expected = frames.concat();
    assert_eq!(got.len(), 297);
    assert_eq!(got, expected);
}

#[test]
fn record_hash_domain() {
    let got = record_hash(1, &ZERO_HASH, b"x");
    let mut input = b"atlas-duck/audit/v1".to_vec();
    input.extend_from_slice(&[0u8; 32]);
    input.extend_from_slice(b"x");
    let want: [u8; 32] = Sha256::digest(&input).into();
    assert_eq!(got, want);
    assert_eq!(ZERO_HASH, [0u8; 32]);
    // The version number is part of the domain, with no terminator.
    let mut v2 = b"atlas-duck/audit/v2".to_vec();
    v2.extend_from_slice(&[0u8; 32]);
    v2.extend_from_slice(b"x");
    let want2: [u8; 32] = Sha256::digest(&v2).into();
    assert_eq!(record_hash(2, &ZERO_HASH, b"x"), want2);
}

/// 0-based F.2 indices of the 11 AAD fields (§8.4).
const AAD_FIELDS: [usize; 11] = [1, 2, 0, 3, 4, 6, 5, 7, 10, 25, 24];

#[test]
fn aad_field_order() {
    let a = full_row_a();
    let b = full_row_b();
    let base = aad(&a.fields()).unwrap();
    assert!(base.starts_with(b"atlas-duck/aad/v1\x01"));
    for (i, name) in FIELD_LIST.iter().enumerate() {
        let mut m = a.clone();
        m.copy_field(&b, i);
        let changed = aad(&m.fields()).unwrap() != base;
        assert_eq!(
            changed,
            AAD_FIELDS.contains(&i),
            "field {i} ({name}) changed aad: {changed}"
        );
    }

    // Exact layout: domain, then [format_version, chain_id, seq, ts_utc, epoch, event_type,
    // request_id, op_id, target, key_id, payload_sha256].
    let r = minimal_row();
    let mut sha = vec![0x01, 0x00, 0x00, 0x00, 0x20];
    sha.extend_from_slice(&[0xAA; 32]);
    let expected: Vec<u8> = [
        &b"atlas-duck/aad/v1"[..],
        &INT_1,                                // format_version
        &[0x01, 0x00, 0x00, 0x00, 0x01, b'c'], // chain_id
        &INT_1,                                // seq
        &cat(&[&[0x01, 0x00, 0x00, 0x00, 0x18], b"1970-01-01T00:00:00.000Z"]), // ts_utc
        &NULL,                                 // epoch
        &cat(&[&[0x01, 0x00, 0x00, 0x00, 0x07], b"GENESIS"]), // event_type
        &NULL,                                 // request_id
        &NULL,                                 // op_id
        &[0x01, 0x00, 0x00, 0x00, 0x01, b'i'], // target
        &INT_1,                                // key_id
        &sha,                                  // payload_sha256
    ]
    .concat();
    assert_eq!(aad(&r.fields()).unwrap(), expected);

    // NULL and empty epoch differ in the AAD too.
    let mut e = r.clone();
    e.epoch = Some(String::new());
    assert_ne!(aad(&e.fields()).unwrap(), expected);
}

#[test]
fn every_field_is_hashed_fixed_rows() {
    let a = full_row_a();
    let b = full_row_b();
    let base = canonical_bytes(&a.fields()).unwrap();
    for (i, name) in FIELD_LIST.iter().enumerate() {
        let mut m = a.clone();
        m.copy_field(&b, i);
        assert_ne!(
            canonical_bytes(&m.fields()).unwrap(),
            base,
            "field {i} ({name}) not hashed"
        );
        // NULL vs present (where NULL is allowed) also changes the bytes.
        let mut n = a.clone();
        if set_null(&mut n, i) {
            assert_ne!(
                canonical_bytes(&n.fields()).unwrap(),
                base,
                "NULL field {i}"
            );
        }
    }
}

/// Sets nullable field `i` to NULL; false for NOT NULL columns.
fn set_null(r: &mut Row, i: usize) -> bool {
    match i {
        4 => r.epoch = None,
        5 => r.request_id = None,
        7 => r.op_id = None,
        8 => r.op_class = None,
        9 => r.instance_id = None,
        10 => r.target = None,
        11 => r.agent_name = None,
        12 => r.agent_name_source = None,
        13 => r.client_kind = None,
        14 => r.connection_id = None,
        15 => r.peer_pid = None,
        16 => r.peer_exe = None,
        17 => r.peer_origin_exe = None,
        18 => r.os_user = None,
        19 => r.atlassian_user = None,
        20 => r.atlassian_user_key = None,
        21 => r.decision = None,
        _ => return false,
    }
    true
}

fn text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 äß€😀]{0,6}"
}

fn opt_text() -> impl Strategy<Value = Option<String>> {
    proptest::option::of(text())
}

fn opt_blob() -> impl Strategy<Value = Option<Vec<u8>>> {
    proptest::option::of(proptest::collection::vec(any::<u8>(), 0..6))
}

prop_compose! {
    fn arb_row()(
        (seq, format_version, chain_id, ts_utc, epoch, request_id, event_type, op_id) in
            (any::<u64>(), any::<u64>(), text(), text(), opt_text(), opt_text(), text(), opt_text()),
        (op_class, instance_id, target, agent_name, agent_name_source, client_kind, connection_id) in
            (opt_text(), opt_text(), opt_text(), opt_text(), opt_text(), opt_text(), opt_text()),
        (peer_pid, peer_exe, peer_origin_exe, os_user, atlassian_user, atlassian_user_key, decision) in
            (proptest::option::of(any::<u64>()), opt_blob(), opt_blob(), opt_text(), opt_text(), opt_text(), opt_text()),
        (flags, payload_len, payload_sha256, key_id, nonce, payload_ct, prev_hash) in
            (any::<u64>(), any::<u64>(), any::<[u8; 32]>(), any::<u64>(), any::<[u8; 12]>(),
             proptest::collection::vec(any::<u8>(), 0..24), any::<[u8; 32]>()),
    ) -> Row {
        Row {
            seq, format_version, chain_id, ts_utc, epoch, request_id, event_type, op_id,
            op_class, instance_id, target, agent_name, agent_name_source, client_kind, connection_id,
            peer_pid, peer_exe, peer_origin_exe, os_user, atlassian_user, atlassian_user_key, decision,
            flags, payload_len, payload_sha256, key_id, nonce, payload_ct, prev_hash,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Two rows differing in exactly one field never produce equal bytes.
    #[test]
    fn every_field_is_hashed(a in arb_row(), b in arb_row(), i in 0usize..29) {
        let mut m = a.clone();
        m.copy_field(&b, i);
        prop_assume!(m != a);
        prop_assert_ne!(canonical_bytes(&m.fields()).unwrap(), canonical_bytes(&a.fields()).unwrap());
    }

    /// Any two different rows produce different bytes (the frame encoding is injective).
    #[test]
    fn canonical_injective(a in arb_row(), b in arb_row()) {
        prop_assume!(a != b);
        prop_assert_ne!(canonical_bytes(&a.fields()).unwrap(), canonical_bytes(&b.fields()).unwrap());
    }
}

#[test]
fn canonical_injective_on_boundaries() {
    let mut a = full_row_a();
    a.agent_name = Some("ab".into());
    a.os_user = Some("c".into());
    let mut b = a.clone();
    b.agent_name = Some("a".into());
    b.os_user = Some("bc".into());
    assert_ne!(
        canonical_bytes(&a.fields()).unwrap(),
        canonical_bytes(&b.fields()).unwrap()
    );
    // NULL next to an empty string.
    let mut c = a.clone();
    c.agent_name = None;
    c.agent_name_source = Some(String::new());
    let mut d = a.clone();
    d.agent_name = Some(String::new());
    d.agent_name_source = None;
    assert_ne!(
        canonical_bytes(&c.fields()).unwrap(),
        canonical_bytes(&d.fields()).unwrap()
    );
}

#[cfg(windows)]
#[test]
fn wtf8_paths() {
    use atlas_duck_audit::encoding::os_path_bytes;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;

    // 'a', U+1F600 as a surrogate pair, a lone high surrogate, 'b'.
    let p = PathBuf::from(OsString::from_wide(&[
        0x0061, 0xD83D, 0xDE00, 0xD800, 0x0062,
    ]));
    assert_eq!(
        os_path_bytes(&p),
        [0x61, 0xF0, 0x9F, 0x98, 0x80, 0xED, 0xA0, 0x80, 0x62]
    );
    // A lone low surrogate, and a high surrogate at the very end.
    let q = PathBuf::from(OsString::from_wide(&[0xDC00, 0x0041, 0xDBFF]));
    assert_eq!(
        os_path_bytes(&q),
        [0xED, 0xB0, 0x80, 0x41, 0xED, 0xAF, 0xBF]
    );
    // Plain UTF-8 paths encode as their UTF-8 bytes.
    let r = PathBuf::from(r"C:\Users\jürgen\€.exe");
    assert_eq!(os_path_bytes(&r), r"C:\Users\jürgen\€.exe".as_bytes());
}

#[cfg(unix)]
#[test]
fn wtf8_paths() {
    use atlas_duck_audit::encoding::os_path_bytes;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    let p = Path::new(OsStr::from_bytes(b"/tmp/\xff"));
    assert_eq!(os_path_bytes(p), b"/tmp/\xff");
}

fn rec(index: u32, method: &str, url: &str, ct: Option<&str>, body: &[u8]) -> RequestRecord {
    RequestRecord {
        index,
        method: method.into(),
        resolved_url: url.into(),
        content_type: ct.map(Into::into),
        body_bytes: body.to_vec(),
    }
}

#[test]
fn request_set_hash_vector() {
    let one = [rec(
        0,
        "POST",
        "https://h/rest/api/2/issue",
        Some("application/json"),
        b"{}",
    )];
    assert_eq!("https://h/rest/api/2/issue".len(), 0x1A);
    let input: Vec<u8> = [
        &b"atlas-duck/request-set/v1"[..],
        &[0x00, 0x00, 0x00, 0x01],                               // count
        &[0x01, 0x00, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0], // index 0
        &[0x01, 0x00, 0x00, 0x00, 0x04],
        b"POST",
        &[0x01, 0x00, 0x00, 0x00, 0x1A],
        b"https://h/rest/api/2/issue",
        &[0x01, 0x00, 0x00, 0x00, 0x10],
        b"application/json",
        &[0x01, 0x00, 0x00, 0x00, 0x02],
        b"{}",
    ]
    .concat();
    let want: [u8; 32] = Sha256::digest(&input).into();
    assert_eq!(request_set_hash(&one), want);

    // The empty set is the domain plus a zero count.
    let empty: [u8; 32] = Sha256::digest(b"atlas-duck/request-set/v1\x00\x00\x00\x00").into();
    assert_eq!(request_set_hash(&[]), empty);

    // Order matters.
    let a = rec(0, "PUT", "https://h/a", Some("application/json"), b"1");
    let b = rec(1, "PUT", "https://h/b", Some("application/json"), b"2");
    assert_ne!(
        request_set_hash(&[a.clone(), b.clone()]),
        request_set_hash(&[b, a])
    );

    // A missing Content-Type differs from an empty one.
    let none = rec(0, "DELETE", "https://h/x", None, b"");
    let empty_ct = rec(0, "DELETE", "https://h/x", Some(""), b"");
    assert_ne!(request_set_hash(&[none]), request_set_hash(&[empty_ct]));

    // Field boundaries cannot shift between method and URL.
    let x = rec(0, "GE", "Thttps://h", None, b"");
    let y = rec(0, "GET", "https://h", None, b"");
    assert_ne!(request_set_hash(&[x]), request_set_hash(&[y]));
}

#[test]
fn requests_json_round_trip() {
    let r = vec![
        rec(
            0,
            "POST",
            "https://h/rest/api/2/issue",
            Some("application/json"),
            b"{}",
        ),
        rec(1, "PUT", "https://h/x", None, &[0xFF, 0x00, 0xFE, 0x80]),
        rec(2, "DELETE", "https://h/y", Some(""), b""),
    ];
    let j = requests_to_json(&r);
    assert_eq!(
        j,
        json!([
            {"index": 0, "method": "POST", "url": "https://h/rest/api/2/issue",
             "content_type": "application/json", "body_b64": "e30="},
            {"index": 1, "method": "PUT", "url": "https://h/x",
             "content_type": null, "body_b64": "/wD+gA=="},
            {"index": 2, "method": "DELETE", "url": "https://h/y",
             "content_type": "", "body_b64": ""},
        ])
    );
    assert_eq!(requests_from_json(&j).unwrap(), r);

    let invalid = |v: serde_json::Value| {
        assert!(
            matches!(requests_from_json(&v), Err(AuditError::Invalid(_))),
            "accepted {v}"
        );
    };
    // Missing body_b64.
    invalid(json!([{"index": 0, "method": "GET", "url": "u", "content_type": null}]));
    // Missing content_type (null must be explicit).
    invalid(json!([{"index": 0, "method": "GET", "url": "u", "body_b64": ""}]));
    // Unpadded base64.
    invalid(
        json!([{"index": 0, "method": "GET", "url": "u", "content_type": null, "body_b64": "/wD+gA"}]),
    );
    // Non-canonical trailing bits.
    invalid(
        json!([{"index": 0, "method": "GET", "url": "u", "content_type": null, "body_b64": "/x=="}]),
    );
    // Unknown field.
    invalid(
        json!([{"index": 0, "method": "GET", "url": "u", "content_type": null,
                    "body_b64": "", "extra": 1}]),
    );
    // Wrong types and ranges.
    invalid(
        json!([{"index": -1, "method": "GET", "url": "u", "content_type": null, "body_b64": ""}]),
    );
    invalid(json!([{"index": 4294967296u64, "method": "GET", "url": "u",
                    "content_type": null, "body_b64": ""}]));
    invalid(
        json!([{"index": 1.5, "method": "GET", "url": "u", "content_type": null, "body_b64": ""}]),
    );
    invalid(json!([{"index": 0, "method": 1, "url": "u", "content_type": null, "body_b64": ""}]));
    invalid(json!([{"index": 0, "method": "GET", "url": "u", "content_type": 5, "body_b64": ""}]));
    invalid(json!({"index": 0}));
    invalid(json!(["x"]));
}

#[test]
fn request_record_debug_hides_body() {
    let r = rec(0, "POST", "https://h/secret-path", None, b"top-secret-body");
    let d = format!("{r:?}");
    assert!(
        !d.contains("top-secret-body") && !d.contains("116, 111, 112"),
        "{d}"
    );
}

#[test]
fn prune_row_hash_chain() {
    let lprh = [0x5A; 32];
    let first = prune_row_hash(&ZERO_HASH, 9, 1, "2026-01-10", &lprh, 9);
    let input: Vec<u8> = [
        &b"atlas-duck/prune-log/v1"[..],
        &[0u8; 32],
        &[0x01, 0x00, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 9], // prune_seq
        &INT_1,                                                  // range_start
        &[0x01, 0x00, 0x00, 0x00, 0x0A],
        b"2026-01-10",
        &[0x01, 0x00, 0x00, 0x00, 0x20],
        &lprh,
        &[0x01, 0x00, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 9], // first_retained_seq
    ]
    .concat();
    let want: [u8; 32] = Sha256::digest(&input).into();
    assert_eq!(first, want);

    assert_ne!(
        prune_row_hash(&ZERO_HASH, 9, 1, "2026-01-11", &lprh, 9),
        first
    );
    assert_ne!(
        prune_row_hash(&ZERO_HASH, 9, 1, "2026-01-10", &lprh, 8),
        first
    );
    // The second row chains to the first.
    let second = prune_row_hash(&first, 20, 9, "2026-01-11", &[0x6B; 32], 15);
    assert_ne!(
        second,
        prune_row_hash(&ZERO_HASH, 20, 9, "2026-01-11", &[0x6B; 32], 15)
    );
}

#[test]
fn from_row_reads_the_f10_column_order() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE events (
          seq INTEGER PRIMARY KEY, format_version INTEGER NOT NULL, chain_id TEXT NOT NULL,
          ts_utc TEXT NOT NULL, epoch TEXT, request_id TEXT, event_type TEXT NOT NULL, op_id TEXT,
          op_class TEXT, instance_id TEXT, target TEXT, agent_name TEXT, agent_name_source TEXT,
          client_kind TEXT, connection_id TEXT, peer_pid INTEGER, peer_exe BLOB,
          peer_origin_exe BLOB, os_user TEXT, atlassian_user TEXT, atlassian_user_key TEXT,
          decision TEXT, flags INTEGER NOT NULL, payload_len INTEGER NOT NULL,
          payload_sha256 BLOB NOT NULL, key_id INTEGER NOT NULL, nonce BLOB NOT NULL,
          payload_ct BLOB NOT NULL, prev_hash BLOB NOT NULL, record_hash BLOB NOT NULL);",
    )
    .unwrap();
    let a = full_row_a();
    let mut m = minimal_row();
    m.seq = 8;
    let insert = |r: &Row| {
        let f = r.fields();
        let cols = FIELD_LIST.join(", ");
        conn.execute(
            &format!("INSERT INTO events ({cols}, record_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, x'00')"),
            rusqlite::params![
                f.seq as i64, f.format_version as i64, f.chain_id, f.ts_utc, f.epoch, f.request_id,
                f.event_type, f.op_id, f.op_class, f.instance_id, f.target, f.agent_name,
                f.agent_name_source, f.client_kind, f.connection_id, f.peer_pid.map(|p| p as i64),
                f.peer_exe, f.peer_origin_exe, f.os_user, f.atlassian_user, f.atlassian_user_key,
                f.decision, f.flags as i64, f.payload_len as i64, &f.payload_sha256[..],
                f.key_id as i64, &f.nonce[..], f.payload_ct, &f.prev_hash[..],
            ],
        )
        .unwrap();
    };
    insert(&a);
    insert(&m);

    let sql = format!("SELECT {} FROM events ORDER BY seq", FIELD_LIST.join(", "));
    let mut stmt = conn.prepare(&sql).unwrap();
    let mut rows = stmt.query([]).unwrap();
    for want in [&a, &m] {
        let row = rows.next().unwrap().unwrap();
        let got = RowFields::from_row(row).unwrap();
        assert_eq!(
            canonical_bytes(&got).unwrap(),
            canonical_bytes(&want.fields()).unwrap()
        );
        assert_eq!(aad(&got).unwrap(), aad(&want.fields()).unwrap());
    }

    // Malformed values (a tampered file) are errors, never panics: substitute one column of
    // the select list at a time.
    for (col, expr) in [
        ("payload_sha256", "x'00'"),
        ("nonce", "zeroblob(13)"),
        ("flags", "-1"),
        ("seq", "'7'"),
        ("chain_id", "x'ff'"),
        ("ts_utc", "NULL"),
        ("epoch", "x'323032362d31302d3038'"),
        ("peer_exe", "'text'"),
        ("payload_ct", "NULL"),
        ("key_id", "1.5"),
    ] {
        let list: Vec<&str> = FIELD_LIST
            .iter()
            .map(|c| if *c == col { expr } else { *c })
            .collect();
        let sql = format!("SELECT {} FROM events WHERE seq = 7", list.join(", "));
        let mut stmt = conn.prepare(&sql).unwrap();
        let mut rows = stmt.query([]).unwrap();
        let row = rows.next().unwrap().unwrap();
        assert!(
            matches!(RowFields::from_row(row), Err(AuditError::Invalid(_))),
            "accepted {col} = {expr}"
        );
    }
}
