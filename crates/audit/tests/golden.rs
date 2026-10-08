//! Golden vectors for `FIELD_LIST[1]`, `record_hash`, AAD, the payload envelope, the request
//! set hash, the prune-log row hash and JCS (§8.4, §13 "canonical-encoding golden vectors"),
//! plus DEK wrapping, the recovery blob and the query tag (§8.6, L38; plan F.4, F.5, F.7).
//!
//! `golden_vectors_match` rebuilds `tests/vectors/format_v1.json` from the inputs below and
//! compares it with the committed file. With `ATLAS_DUCK_REGEN_VECTORS=1` it writes the file
//! instead. The file is frozen after M2: a diff here is a format break, not a test update.
//! `ci/check-audit-vectors.mjs` recomputes the same file independently with Node's crypto,
//! except `recovery` (Node 22 has no Argon2), which only Rust checks.

use atlas_duck_audit::crypto::{
    self, Dek, Kek, query_key, query_tag, unwrap_dek, wrap_dek_with_nonce,
};
use atlas_duck_audit::encoding::{
    RowFields, ZERO_HASH, aad, canonical_bytes, prune_row_hash, record_hash,
};
use atlas_duck_audit::recovery::{open_recovery, seal_recovery_with};
use atlas_duck_audit::request_set::requests_to_json;
use atlas_duck_audit::types::QueryKind;
use atlas_duck_audit::{RequestRecord, request_set_hash};
use atlas_duck_ipc::jcs::to_jcs_vec;
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const INSTALL_ID: &str = "5e0c7a1f9b3d4e2a8c6b0d1f3e5a7c9b";
const CHAIN_ID: &str = "a4c1e9d27b3f4056b8e1c3a5d7f90b2e";
const REQUEST_ID: &str = "0192f1a4-7c2e-7b3d-9a10-6f5e4d3c2b1a";
/// A second, long-running chain for the row with a seq above 2^32.
const CHAIN_ID_2: &str = "e7d3b1a9c5f24068aa1c3e5f7b9d0c2e";
/// 0x0000_0123_4567_89AB: between 2^32 and 2^53, every high byte of the u64 frame distinct.
const LARGE_SEQ: u64 = 0x0123_4567_89AB;

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/format_v1.json")
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// DEK of `key_id` 1 (the uncorroborated DEK, month NULL), 2 (month 2026-10) and 7 (month
/// 2027-03 of the second chain).
fn dek(key_id: u64) -> [u8; 32] {
    let base: u8 = match key_id {
        1 => 0x00,
        2 => 0x80,
        7 => 0x40,
        _ => panic!("no test DEK {key_id}"),
    };
    std::array::from_fn(|i| base + i as u8)
}

fn nonce(seq: u64) -> [u8; 12] {
    std::array::from_fn(|i| (seq as u8) << 4 | i as u8)
}

/// The plaintext columns of one row; payload-derived columns are computed in `build_row`.
struct Spec {
    name: &'static str,
    seq: u64,
    chain_id: &'static str,
    /// `None`: the previous row's `record_hash` (the rows of `CHAIN_ID` form one chain).
    prev_hash: Option<[u8; 32]>,
    ts_utc: &'static str,
    epoch: Option<&'static str>,
    request_id: Option<&'static str>,
    event_type: &'static str,
    op_id: Option<&'static str>,
    op_class: Option<&'static str>,
    instance_id: Option<&'static str>,
    target: Option<&'static str>,
    agent_name: Option<&'static str>,
    agent_name_source: Option<&'static str>,
    client_kind: Option<&'static str>,
    connection_id: Option<&'static str>,
    peer_pid: Option<u64>,
    peer_exe: Option<&'static [u8]>,
    peer_origin_exe: Option<&'static [u8]>,
    os_user: Option<&'static str>,
    atlassian_user: Option<&'static str>,
    atlassian_user_key: Option<&'static str>,
    decision: Option<&'static str>,
    flags: u64,
    key_id: u64,
    payload: Value,
}

impl Spec {
    fn empty(name: &'static str, seq: u64, ts_utc: &'static str, event_type: &'static str) -> Spec {
        Spec {
            name,
            seq,
            chain_id: CHAIN_ID,
            prev_hash: None,
            ts_utc,
            epoch: None,
            request_id: None,
            event_type,
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
            key_id: 1,
            payload: json!({}),
        }
    }
}

fn write_approved_set() -> Vec<RequestRecord> {
    vec![RequestRecord {
        index: 0,
        method: "POST".into(),
        resolved_url: "https://jira.example.test/rest/api/2/issue".into(),
        content_type: Some("application/json".into()),
        body_bytes: r#"{"fields":{"issuetype":{"name":"Task"},"project":{"key":"PROJ"},"summary":"Grüße aus Köln (edited)"}}"#
            .as_bytes()
            .to_vec(),
    }]
}

fn row_specs() -> Vec<Spec> {
    let params = json!({"fields": {"issuetype": {"name": "Task"}, "project": {"key": "PROJ"},
                                   "summary": "Grüße aus Köln"}});
    let params_sha256 = hex::encode(sha256(&to_jcs_vec(&params).unwrap()));
    let set = write_approved_set();

    vec![
        // GENESIS before any corroboration: epoch NULL, flags 0 (L36, L47), uncorroborated DEK.
        Spec {
            target: Some(INSTALL_ID),
            payload: json!({
                "archived_db": null, "chain_id": CHAIN_ID, "created_at": "2026-10-08T09:15:00.000Z",
                "install_id": INSTALL_ID, "previous_chain_id": null, "previous_last_anchor": null,
            }),
            ..Spec::empty(
                "genesis_null_epoch",
                1,
                "2026-10-08T09:15:00.000Z",
                "GENESIS",
            )
        },
        // Every column present; agent_name present-empty; non-ASCII path bytes; pid u32::MAX.
        Spec {
            epoch: Some("2026-10-08"),
            request_id: Some(REQUEST_ID),
            op_id: Some("jira.issue.create"),
            op_class: Some("write"),
            instance_id: Some("jira-prod"),
            target: Some("PROJ"),
            agent_name: Some(""),
            agent_name_source: Some("flag"),
            client_kind: Some("cli"),
            connection_id: Some("conn-0001"),
            peer_pid: Some(4_294_967_295),
            peer_exe: Some("/home/jürgen/bin/agent".as_bytes()),
            peer_origin_exe: Some(b"/usr/bin/bash"),
            os_user: Some("jürgen"),
            atlassian_user: Some("jdoe"),
            atlassian_user_key: Some("JIRAUSER10100"),
            decision: Some("approve"),
            flags: 0,
            key_id: 2,
            payload: json!({
                "cwd_basename": "work",
                "limits": {"ratio": 0.5, "timeout_s": 30},
                "params": params,
                "params_sha256": params_sha256,
                "peer_chain": [{"exe": "/home/jürgen/bin/agent", "pid": 4_294_967_295u64},
                               {"exe": "/sbin/init", "pid": 1}],
            }),
            ..Spec::empty(
                "request_received_all_columns",
                2,
                "2026-10-08T09:16:30.250Z",
                "REQUEST_RECEIVED",
            )
        },
        // edited | batch | clock_backwards: ts_utc is earlier than the predecessor's.
        Spec {
            epoch: Some("2026-10-08"),
            request_id: Some(REQUEST_ID),
            op_id: Some("jira.issue.create"),
            op_class: Some("write"),
            instance_id: Some("jira-prod"),
            target: Some("PROJ"),
            os_user: Some("jürgen"),
            atlassian_user: Some("jdoe"),
            atlassian_user_key: Some("JIRAUSER10100"),
            decision: Some("approve_edited"),
            flags: 1 | 4 | 16,
            key_id: 2,
            payload: json!({
                "candidate_rev": 2,
                "request_set_hash": hex::encode(request_set_hash(&set)),
                "requests": requests_to_json(&set),
            }),
            ..Spec::empty(
                "decision_and_flags",
                3,
                "2026-10-08T09:16:29.000Z",
                "WRITE_APPROVED",
            )
        },
        // JCS key order inside a hashed record: UTF-16 puts U+1F600 before U+FB33.
        Spec {
            epoch: Some("2026-10-09"),
            request_id: Some("0192f1a4-7c2e-7b3d-9a10-6f5e4d3c2b1b"),
            key_id: 2,
            payload: json!({
                "result": {"\u{FB33}": "dalet with dagesh", "\u{1F600}": "grinning face",
                           "\u{F6}": 1e21, "\u{80}": [0.1, -1.5, 100], "1": null, "\r": "cr"},
                "logs": [],
            }),
            ..Spec::empty(
                "utf16_order_payload",
                4,
                "2026-10-09T00:00:01.000Z",
                "SCRIPT_FINISHED",
            )
        },
        // A seq above 2^32 (pins the high bytes of u64 frames) on another chain, and peer_exe
        // bytes that are not UTF-8: a Unix 0xFF byte and the WTF-8 of a lone surrogate D800.
        Spec {
            chain_id: CHAIN_ID_2,
            prev_hash: Some(sha256(b"record 1250999896490")),
            epoch: Some("2027-03-01"),
            request_id: Some("0192f1a4-7c2e-7b3d-9a10-6f5e4d3c2b1c"),
            agent_name: Some("codex"),
            agent_name_source: Some("client_info"),
            client_kind: Some("mcp"),
            connection_id: Some("conn-0002"),
            peer_pid: Some(4242),
            peer_exe: Some(b"/tmp/\xff\xed\xa0\x80agent"),
            key_id: 7,
            payload: json!({"client_kind": "mcp", "connection_id": "conn-0002", "peer_pid": 4242}),
            ..Spec::empty(
                "large_seq_non_utf8_path",
                LARGE_SEQ,
                "2027-03-01T08:00:00.000Z",
                "DELIVERED",
            )
        },
    ]
}

fn opt<T: Into<Value>>(v: Option<T>) -> Value {
    v.map_or(Value::Null, Into::into)
}

fn opt_hex(v: Option<&[u8]>) -> Value {
    v.map_or(Value::Null, |b| Value::String(hex::encode(b)))
}

/// Builds one row's vector entry. `compressed` supplies the zstd frame of the plaintext.
fn build_row(
    s: &Spec,
    prev_hash: &[u8; 32],
    compressed: &dyn Fn(&str, &[u8]) -> Vec<u8>,
) -> (Value, [u8; 32]) {
    let plain = to_jcs_vec(&s.payload).unwrap();
    let payload_sha256 = sha256(&plain);
    let z = compressed(s.name, &plain);
    let key = dek(s.key_id);
    let n = nonce(s.seq);

    let mut f = RowFields {
        seq: s.seq,
        format_version: 1,
        chain_id: s.chain_id,
        ts_utc: s.ts_utc,
        epoch: s.epoch,
        request_id: s.request_id,
        event_type: s.event_type,
        op_id: s.op_id,
        op_class: s.op_class,
        instance_id: s.instance_id,
        target: s.target,
        agent_name: s.agent_name,
        agent_name_source: s.agent_name_source,
        client_kind: s.client_kind,
        connection_id: s.connection_id,
        peer_pid: s.peer_pid,
        peer_exe: s.peer_exe,
        peer_origin_exe: s.peer_origin_exe,
        os_user: s.os_user,
        atlassian_user: s.atlassian_user,
        atlassian_user_key: s.atlassian_user_key,
        decision: s.decision,
        flags: s.flags,
        payload_len: plain.len() as u64,
        payload_sha256: &payload_sha256,
        key_id: s.key_id,
        nonce: &n,
        payload_ct: &[],
        prev_hash,
    };
    let aad_bytes = aad(&f).unwrap();
    let ct = crypto::seal(&Dek::from_bytes(&key), &n, &aad_bytes, &z).unwrap();
    f.payload_ct = &ct;
    let canonical = canonical_bytes(&f).unwrap();
    let rh = record_hash(1, prev_hash, &canonical);
    assert_eq!(f.record_hash().unwrap(), rh);

    let fields = json!({
        "seq": f.seq,
        "format_version": f.format_version,
        "chain_id": f.chain_id,
        "ts_utc": f.ts_utc,
        "epoch": opt(f.epoch),
        "request_id": opt(f.request_id),
        "event_type": f.event_type,
        "op_id": opt(f.op_id),
        "op_class": opt(f.op_class),
        "instance_id": opt(f.instance_id),
        "target": opt(f.target),
        "agent_name": opt(f.agent_name),
        "agent_name_source": opt(f.agent_name_source),
        "client_kind": opt(f.client_kind),
        "connection_id": opt(f.connection_id),
        "peer_pid": opt(f.peer_pid),
        "peer_exe": opt_hex(f.peer_exe),
        "peer_origin_exe": opt_hex(f.peer_origin_exe),
        "os_user": opt(f.os_user),
        "atlassian_user": opt(f.atlassian_user),
        "atlassian_user_key": opt(f.atlassian_user_key),
        "decision": opt(f.decision),
        "flags": f.flags,
        "payload_len": f.payload_len,
        "payload_sha256": hex::encode(f.payload_sha256),
        "key_id": f.key_id,
        "nonce": hex::encode(f.nonce),
        "payload_ct": hex::encode(f.payload_ct),
        "prev_hash": hex::encode(f.prev_hash),
    });
    let entry = json!({
        "name": s.name,
        "fields": fields,
        "dek": hex::encode(key),
        "plaintext_jcs": String::from_utf8(plain).unwrap(),
        "compressed": hex::encode(&z),
        "canonical": hex::encode(&canonical),
        "aad": hex::encode(&aad_bytes),
        "record_hash": hex::encode(rh),
    });
    (entry, rh)
}

fn request_sets() -> Vec<Vec<RequestRecord>> {
    let r = |index, method: &str, url: &str, ct: Option<&str>, body: &[u8]| RequestRecord {
        index,
        method: method.into(),
        resolved_url: url.into(),
        content_type: ct.map(Into::into),
        body_bytes: body.to_vec(),
    };
    vec![
        vec![r(
            0,
            "POST",
            "https://h/rest/api/2/issue",
            Some("application/json"),
            b"{}",
        )],
        write_approved_set(),
        vec![
            r(
                0,
                "PUT",
                "https://h/rest/api/2/issue/PROJ-1",
                Some("application/json"),
                br#"{"fields":{}}"#,
            ),
            r(
                1,
                "DELETE",
                "https://h/rest/api/2/issue/PROJ-2/watchers?username=j%C3%BCrgen",
                None,
                &[0xFF, 0x00, 0xFE],
            ),
            r(2, "POST", "https://h/x", Some(""), b""),
        ],
        vec![],
    ]
}

fn prune_rows() -> Value {
    let lp1 = sha256(b"record 8");
    let lp2 = sha256(b"record 14");
    // (prune_seq, range_start, cutoff_epoch, last_pruned_record_hash, first_retained_seq);
    // the third row is an empty-range prune (L48): it repeats the previous row's values.
    let rows = [
        (9u64, 1u64, "2026-01-10", lp1, 9u64),
        (20, 9, "2026-01-11", lp2, 15),
        (31, 15, "2026-01-12", lp2, 15),
    ];
    let mut prev = ZERO_HASH;
    let mut out = Vec::new();
    for (prune_seq, range_start, cutoff, lp, frs) in rows {
        let h = prune_row_hash(&prev, prune_seq, range_start, cutoff, &lp, frs);
        out.push(json!({
            "prev_row_hash": hex::encode(prev),
            "prune_seq": prune_seq,
            "range_start": range_start,
            "cutoff_epoch": cutoff,
            "last_pruned_record_hash": hex::encode(lp),
            "first_retained_seq": frs,
            "row_hash": hex::encode(h),
        }));
        prev = h;
    }
    Value::Array(out)
}

/// JCS inputs (JSON text). Outputs come from `ipc::jcs`; the Node checker recomputes them.
const JCS_INPUTS: [&str; 5] = [
    // RFC 8785 §3.2.2 example
    r#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}"#,
    // RFC 8785 §3.2.3 sorting example
    r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}"#,
    // BMP edge: U+10000 (surrogates D800 DC00) sorts before U+FFFF
    r#"{"\uffff":"bmp-max","\ud800\udc00":"U+10000"}"#,
    // number formatting (ECMAScript Number::toString)
    r#"[0,-0.0,1e21,1e20,5e-324,1.7976931348623157e308,0.000001,1e-7,-1.5,9007199254740991]"#,
    // escapes: control characters, quote, backslash, solidus, U+2028, DEL; nested empties
    r#"{"b":[true,false,null,{"y":"\u001f\"\\/\b\f\n\r\t","x":"\u2028\u007f"}],"a":{},"c":[]}"#,
];

/// The fixed KEK of the `dek_wraps`, `recovery` and `query_tags` vectors.
fn vector_kek_bytes(base: u8) -> [u8; 32] {
    std::array::from_fn(|i| base ^ i as u8)
}

fn kek(bytes: &[u8; 32]) -> Kek {
    let mut entry = vec![1u8];
    entry.extend_from_slice(bytes);
    Kek::from_entry_bytes(&entry).unwrap()
}

/// F.4: the three DEKs of `rows`, wrapped under the vector KEK with their key_id and month.
fn dek_wraps() -> Value {
    let kek_bytes = vector_kek_bytes(0xC0);
    let entries = [(1u64, None), (2, Some("2026-10")), (7, Some("2027-03"))];
    let out = entries
        .iter()
        .map(|&(key_id, month)| {
            let n: [u8; 12] = std::array::from_fn(|i| 0xA0 ^ (key_id as u8) << 4 ^ i as u8);
            let wrapped = wrap_dek_with_nonce(
                &kek(&kek_bytes),
                key_id,
                month,
                &Dek::from_bytes(&dek(key_id)),
                &n,
            )
            .unwrap();
            json!({
                "kek": hex::encode(kek_bytes),
                "key_id": key_id,
                "month": month,
                "dek": hex::encode(dek(key_id)),
                "nonce": hex::encode(n),
                "wrapped": hex::encode(wrapped),
            })
        })
        .collect();
    Value::Array(out)
}

const RECOVERY_PASSPHRASE: &str = "correct horse battery";

/// F.5, Rust-only (Node 22 has no Argon2): Argon2id at the real layout-1 parameters.
fn recovery_vector() -> Value {
    let kek_bytes = vector_kek_bytes(0xC0);
    let salt: [u8; 16] = std::array::from_fn(|i| 0x30 + i as u8);
    let n: [u8; 12] = std::array::from_fn(|i| 0x50 + i as u8);
    let blob = seal_recovery_with(
        &SecretString::from(RECOVERY_PASSPHRASE),
        &kek(&kek_bytes),
        &salt,
        &n,
    )
    .unwrap();
    json!({
        "passphrase": RECOVERY_PASSPHRASE,
        "salt": hex::encode(salt),
        "nonce": hex::encode(n),
        "kek": hex::encode(kek_bytes),
        "blob": hex::encode(blob),
    })
}

/// F.7 inputs: (KEK base, kind, query). Queries are surrounded only by ASCII spaces, tabs and
/// newlines: JavaScript's `trim()` also strips U+FEFF, Rust's `str::trim` does not, so a
/// U+FEFF here would make the Node checker disagree for a reason outside the format.
/// Entries 0/1 and 2/3 must give the same tag (trim; NFC of a decomposed `Müller`).
const QUERY_TAG_INPUTS: [(u8, QueryKind, &str); 7] = [
    (0xC0, QueryKind::Jql, "project = ABC"),
    (0xC0, QueryKind::Jql, "  project = ABC \n"),
    (
        0xC0,
        QueryKind::Jql,
        "assignee = \"M\u{FC}ller\" ORDER BY created DESC",
    ),
    (
        0xC0,
        QueryKind::Jql,
        "\tassignee = \"Mu\u{308}ller\" ORDER BY created DESC\r\n",
    ),
    (
        0xC0,
        QueryKind::Cql,
        "space = DOC AND text ~ \"Grüße \u{1F600}\"",
    ),
    (0xC0, QueryKind::Cql, " \n"),
    // Another KEK: another tag for the same query.
    (0x3C, QueryKind::Jql, "project = ABC"),
];

fn query_tags() -> Value {
    let out = QUERY_TAG_INPUTS
        .iter()
        .map(|&(base, kind, query)| {
            let kek_bytes = vector_kek_bytes(base);
            let k_q = query_key(&kek(&kek_bytes));
            json!({
                "kek": hex::encode(kek_bytes),
                "k_q": hex::encode(*k_q),
                "kind": match kind { QueryKind::Jql => "jql", QueryKind::Cql => "cql" },
                "query": query,
                "tag": query_tag(&k_q, kind, query),
            })
        })
        .collect();
    Value::Array(out)
}

fn build(compressed: &dyn Fn(&str, &[u8]) -> Vec<u8>) -> Value {
    let mut prev = ZERO_HASH;
    let mut rows = Vec::new();
    for s in row_specs() {
        let (entry, rh) = build_row(&s, &s.prev_hash.unwrap_or(prev), compressed);
        rows.push(entry);
        prev = rh;
    }
    let sets: Vec<Value> = request_sets()
        .iter()
        .map(|set| {
            let records: Vec<Value> = set
                .iter()
                .map(|r| {
                    json!({
                        "index": r.index,
                        "method": r.method,
                        "url": r.resolved_url,
                        "content_type": r.content_type,
                        "body": hex::encode(&r.body_bytes),
                    })
                })
                .collect();
            json!({"records": records, "hash": hex::encode(request_set_hash(set))})
        })
        .collect();
    let jcs: Vec<Value> = JCS_INPUTS
        .iter()
        .map(|input| {
            let v: Value = serde_json::from_str(input).unwrap();
            let out = String::from_utf8(to_jcs_vec(&v).unwrap()).unwrap();
            json!({"input": input, "output": out})
        })
        .collect();
    json!({
        "format_version": 1,
        "rows": rows,
        "request_sets": sets,
        "prune_rows": prune_rows(),
        "jcs": jcs,
        "dek_wraps": dek_wraps(),
        "recovery": recovery_vector(),
        "query_tags": query_tags(),
    })
}

fn zstd3(plain: &[u8]) -> Vec<u8> {
    crypto::compress(plain).unwrap()
}

fn regen() -> bool {
    let on = std::env::var_os("ATLAS_DUCK_REGEN_VECTORS").is_some_and(|v| v == "1");
    // The vectors are frozen: CI must only ever check them, never rewrite them.
    assert!(
        !(on && std::env::var_os("CI").is_some()),
        "ATLAS_DUCK_REGEN_VECTORS=1 is refused when CI is set: format_v1.json is frozen"
    );
    on
}

fn load() -> Value {
    let text = std::fs::read_to_string(vectors_path())
        .expect("tests/vectors/format_v1.json missing: run with ATLAS_DUCK_REGEN_VECTORS=1 once");
    serde_json::from_str(&text).unwrap()
}

#[test]
fn golden_vectors_match() {
    if regen() {
        let mut doc = build(&|_, plain| zstd3(plain));
        doc.sort_all_objects();
        let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
        std::fs::create_dir_all(vectors_path().parent().unwrap()).unwrap();
        std::fs::write(vectors_path(), text).unwrap();
        return;
    }

    let file = load();
    // The committed zstd frames are inputs here (checked by decompression), so a zstd
    // library change cannot masquerade as a format break; `zstd_level3_reproduces_frames`
    // checks that the pinned zstd still produces them.
    let committed = |name: &str, plain: &[u8]| -> Vec<u8> {
        let row = file["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap_or_else(|| panic!("row {name} missing from the vectors file"));
        let z = hex::decode(row["compressed"].as_str().unwrap()).unwrap();
        assert_eq!(
            zstd::bulk::decompress(&z, plain.len()).unwrap(),
            plain,
            "{name}"
        );
        z
    };
    let built = build(&committed);
    for (key, v) in built.as_object().unwrap() {
        assert_eq!(&file[key], v, "vectors differ in {key:?}: a format break");
    }
    assert_eq!(built, file);

    // Hand check of row 1 (GENESIS): seq frame, format_version frame, NULL epoch frame.
    let c = hex::decode(file["rows"][0]["canonical"].as_str().unwrap()).unwrap();
    assert_eq!(c[0..10], [0x01, 0x00, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0]);
    assert_eq!(
        c[13..26],
        [0x01, 0x00, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0x01]
    );
    // 13 (seq) + 13 (format_version) + 5+32 (chain_id) + 5+24 (ts_utc) = 92
    assert_eq!(c[92..97], [0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn zstd_level3_reproduces_frames() {
    if regen() {
        return; // the file is being rewritten by golden_vectors_match
    }
    let file = load();
    for row in file["rows"].as_array().unwrap() {
        let plain = row["plaintext_jcs"].as_str().unwrap().as_bytes();
        assert_eq!(
            hex::encode(zstd3(plain)),
            row["compressed"].as_str().unwrap(),
            "{}",
            row["name"]
        );
    }
}

#[test]
fn vectors_cover_the_brief() {
    if regen() {
        return;
    }
    let file = load();
    let rows = file["rows"].as_array().unwrap();
    let names: Vec<&str> = rows.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "genesis_null_epoch",
            "request_received_all_columns",
            "decision_and_flags",
            "utf16_order_payload",
            "large_seq_non_utf8_path"
        ]
    );
    assert!(rows[0]["fields"]["epoch"].is_null());
    assert_eq!(rows[0]["fields"]["flags"], 0);
    assert_eq!(rows[0]["fields"]["prev_hash"], hex::encode(ZERO_HASH));
    let all = rows[1]["fields"].as_object().unwrap();
    assert_eq!(all.len(), 29);
    assert!(
        all.values().all(|v| !v.is_null()),
        "row 2 has a NULL column"
    );
    assert_eq!(all["agent_name"], "");
    assert_eq!(all["peer_pid"], 4_294_967_295u64);
    assert_eq!(rows[2]["fields"]["flags"], 21);
    assert_eq!(rows[2]["fields"]["decision"], "approve_edited");
    let p = rows[3]["plaintext_jcs"].as_str().unwrap();
    assert!(p.find('\u{1F600}').unwrap() < p.find('\u{FB33}').unwrap());
}

/// T02 froze the row ciphertexts before `crypto` existed; the store's own envelope functions
/// must reproduce them from the vector inputs (F.3).
#[test]
fn crypto_reproduces_row_envelopes() {
    if regen() {
        return;
    }
    let file = load();
    for row in file["rows"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let hexf = |v: &Value| hex::decode(v.as_str().unwrap()).unwrap();
        let plain = row["plaintext_jcs"].as_str().unwrap().as_bytes();
        let compressed = hexf(&row["compressed"]);
        let key: [u8; 32] = hexf(&row["dek"]).try_into().unwrap();
        let n: [u8; 12] = hexf(&row["fields"]["nonce"]).try_into().unwrap();
        let aad_bytes = hexf(&row["aad"]);
        let seq = row["fields"]["seq"].as_u64().unwrap();
        let dek = Dek::from_bytes(&key);

        assert_eq!(crypto::compress(plain).unwrap(), compressed, "{name}");
        let ct = crypto::seal(&dek, &n, &aad_bytes, &compressed).unwrap();
        assert_eq!(hex::encode(&ct), row["fields"]["payload_ct"], "{name}");
        assert_eq!(
            crypto::open(&dek, &n, &aad_bytes, &ct, seq).unwrap(),
            compressed
        );
        let payload_len = row["fields"]["payload_len"].as_u64().unwrap();
        assert_eq!(
            crypto::decompress(&compressed, payload_len).unwrap(),
            plain,
            "{name}"
        );
        let sha: [u8; 32] = Sha256::digest(plain).into();
        assert_eq!(hex::encode(sha), row["fields"]["payload_sha256"], "{name}");
    }
}

#[test]
fn key_vectors_open() {
    if regen() {
        return;
    }
    let file = load();
    for w in file["dek_wraps"].as_array().unwrap() {
        let kek_bytes: [u8; 32] = hex::decode(w["kek"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let dek_bytes: [u8; 32] = hex::decode(w["dek"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let wrapped = hex::decode(w["wrapped"].as_str().unwrap()).unwrap();
        assert_eq!(wrapped.len(), 60);
        assert_eq!(hex::encode(&wrapped[..12]), w["nonce"]);
        let month = w["month"].as_str();
        let key_id = w["key_id"].as_u64().unwrap();
        assert_eq!(
            unwrap_dek(&kek(&kek_bytes), key_id, month, &wrapped).unwrap(),
            Dek::from_bytes(&dek_bytes)
        );
    }
    assert!(file["dek_wraps"][0]["month"].is_null());

    let r = &file["recovery"];
    let blob = hex::decode(r["blob"].as_str().unwrap()).unwrap();
    assert_eq!(blob.len(), 89);
    assert_eq!(blob[0], 1);
    assert_eq!(hex::encode(&blob[1..17]), r["salt"]);
    assert_eq!(
        blob[17..29],
        [0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 4],
        "m = 65536 KiB, t = 3, p = 4"
    );
    assert_eq!(hex::encode(&blob[29..41]), r["nonce"]);
    let kek_bytes: [u8; 32] = hex::decode(r["kek"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let pass = SecretString::from(r["passphrase"].as_str().unwrap());
    assert_eq!(open_recovery(&pass, &blob).unwrap(), kek(&kek_bytes));

    let tags = file["query_tags"].as_array().unwrap();
    assert_eq!(tags[0]["tag"], tags[1]["tag"], "trim");
    assert_eq!(tags[2]["tag"], tags[3]["tag"], "NFC");
    assert_ne!(tags[0]["query"], tags[1]["query"]);
    assert_ne!(tags[2]["query"], tags[3]["query"]);
    assert_ne!(tags[0]["tag"], tags[6]["tag"], "another KEK");
    assert!(tags[4]["tag"].as_str().unwrap().starts_with("cql:"));
}
