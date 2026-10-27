//! The `ServerStore` contract, run against the SQLite and the in-memory store, plus the
//! SQLite-only checks (triggers, reopen, schema version).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::memory::MemoryStore;
use super::sqlite::SqliteStore;
use super::*;

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn stores() -> Vec<(&'static str, Box<dyn ServerStore>)> {
    vec![
        ("sqlite", Box::new(SqliteStore::open_in_memory().unwrap())),
        ("memory", Box::new(MemoryStore::new())),
    ]
}

fn user(id: &str, name: &str) -> UserRecord {
    UserRecord {
        user_id: id.into(),
        username: name.into(),
        display_name: Some(format!("{name} display")),
        roles: vec!["user".into()],
        data_key_wrapped: format!("{{\"v\":1,\"of\":\"{name}\"}}"),
        created_at: 100,
    }
}

fn sealed(tag: u8) -> Sealed {
    Sealed {
        nonce: vec![tag; 12],
        ct: vec![tag, tag, tag],
    }
}

fn with_users(s: &dyn ServerStore) {
    s.upsert_user(&user(A, "alice")).unwrap();
    s.upsert_user(&user(B, "bob")).unwrap();
}

fn pat(uid: &str, alias: &str, tag: u8) -> PatRecord {
    PatRecord {
        user_id: uid.into(),
        alias: alias.into(),
        sealed: sealed(tag),
        identity_json: format!("{{\"user\":\"{uid}\"}}"),
        checked_at: 5,
    }
}

fn session(tag: u8, uid: &str) -> SessionRecord {
    SessionRecord {
        id_hash: [tag; 32],
        user_id: uid.into(),
        roles: vec!["user".into(), "admin".into()],
        csrf_token: format!("csrf-{tag}"),
        created_at: 10,
        last_seen: 10,
        absolute_expiry: 1000,
        idle_expiry: 500,
    }
}

fn key(id: &str, uid: &str, prefix: &str) -> ApiKeyRecord {
    ApiKeyRecord {
        id: id.into(),
        user_id: uid.into(),
        name: format!("key {id}"),
        prefix: prefix.into(),
        hash: "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA".into(),
        scopes: vec!["read".into()],
        created_at: 10,
        expires_at: 1000,
        last_used_at: None,
        revoked_at: None,
    }
}

fn head(uid: &str, chain: &str, seq: u64) -> AnchorHead {
    AnchorHead {
        user_id: uid.into(),
        chain_id: chain.into(),
        head_seq: seq,
        record_hash: [seq as u8; 32],
    }
}

/// A stand-in row hash: seq and prev folded in (the real one is Task 15's).
fn fake_hash(seq: u64, prev: &[u8; 32]) -> [u8; 32] {
    let mut h = *prev;
    h[0] = h[0].wrapping_add(seq as u8).wrapping_add(1);
    h
}

#[test]
fn users_crud() {
    for (name, s) in stores() {
        let s = s.as_ref();
        with_users(s);
        assert_eq!(s.user(A).unwrap(), Some(user(A, "alice")), "{name}");
        assert_eq!(
            s.user_by_name("bob").unwrap(),
            Some(user(B, "bob")),
            "{name}"
        );
        assert_eq!(s.user("missing").unwrap(), None, "{name}");
        // Upsert updates roles and the wrapped key, keeps username and created_at.
        let mut changed = user(A, "alice");
        changed.roles = vec!["user".into(), "auditor".into()];
        changed.data_key_wrapped = "rewrapped".into();
        changed.created_at = 999;
        s.upsert_user(&changed).unwrap();
        let got = s.user(A).unwrap().unwrap();
        assert_eq!(got.roles, changed.roles, "{name}");
        assert_eq!(got.data_key_wrapped, "rewrapped", "{name}");
        assert_eq!(got.created_at, 100, "{name}");
    }
}

#[test]
fn keystore_crud_is_per_user() {
    for (name, s) in stores() {
        let s = s.as_ref();
        with_users(s);
        s.ks_set(A, "kek", &sealed(1)).unwrap();
        s.ks_set(B, "kek", &sealed(2)).unwrap();
        assert_eq!(s.ks_get(A, "kek").unwrap(), Some(sealed(1)), "{name}");
        assert_eq!(s.ks_get(B, "kek").unwrap(), Some(sealed(2)), "{name}");
        s.ks_set(A, "kek", &sealed(3)).unwrap();
        assert_eq!(s.ks_get(A, "kek").unwrap(), Some(sealed(3)), "{name}");
        assert!(s.ks_delete(A, "kek").unwrap(), "{name}");
        assert!(!s.ks_delete(A, "kek").unwrap(), "{name}");
        assert_eq!(s.ks_get(A, "kek").unwrap(), None, "{name}");
        assert_eq!(s.ks_get(B, "kek").unwrap(), Some(sealed(2)), "{name}");
    }
}

#[test]
fn pats_crud_is_per_user() {
    for (name, s) in stores() {
        let s = s.as_ref();
        with_users(s);
        s.pat_put(&pat(A, "work", 1)).unwrap();
        s.pat_put(&pat(A, "wiki", 2)).unwrap();
        s.pat_put(&pat(B, "work", 3)).unwrap();
        assert_eq!(
            s.pat_get(A, "work").unwrap(),
            Some(pat(A, "work", 1)),
            "{name}"
        );
        assert_eq!(s.pat_get(B, "wiki").unwrap(), None, "{name}");
        let a: Vec<String> = s
            .pat_list(A)
            .unwrap()
            .into_iter()
            .map(|p| p.alias)
            .collect();
        assert_eq!(a, ["wiki", "work"], "{name}");
        assert!(
            s.pat_list(B).unwrap().iter().all(|p| p.user_id == B),
            "{name}"
        );
        s.pat_put(&pat(A, "work", 9)).unwrap();
        assert_eq!(
            s.pat_get(A, "work").unwrap().unwrap().sealed,
            sealed(9),
            "{name}"
        );
        let owners: Vec<String> = s
            .pats_for_alias("work")
            .unwrap()
            .into_iter()
            .map(|p| p.user_id)
            .collect();
        assert_eq!(owners, [A, B], "{name}");
        assert!(s.pat_delete(A, "work").unwrap(), "{name}");
        assert!(!s.pat_delete(A, "work").unwrap(), "{name}");
        assert!(s.pat_get(B, "work").unwrap().is_some(), "{name}");
    }
}

#[test]
fn sessions_crud_and_expiry() {
    for (name, s) in stores() {
        let s = s.as_ref();
        with_users(s);
        s.session_put(&session(1, A)).unwrap();
        s.session_put(&session(2, B)).unwrap();
        assert_eq!(
            s.session_get(&[1; 32]).unwrap(),
            Some(session(1, A)),
            "{name}"
        );
        s.session_touch(&[1; 32], 50, 600).unwrap();
        let t = s.session_get(&[1; 32]).unwrap().unwrap();
        assert_eq!((t.last_seen, t.idle_expiry), (50, 600), "{name}");
        // Session 2 is idle-expired at 500; session 1 now lives to 600.
        assert_eq!(s.session_delete_expired(500).unwrap(), 1, "{name}");
        assert_eq!(s.session_get(&[2; 32]).unwrap(), None, "{name}");
        assert_eq!(s.sessions_all().unwrap().len(), 1, "{name}");
        assert!(s.session_delete(&[1; 32]).unwrap(), "{name}");
        assert!(!s.session_delete(&[1; 32]).unwrap(), "{name}");
        assert!(s.sessions_all().unwrap().is_empty(), "{name}");
    }
}

#[test]
fn api_keys_crud_is_per_user() {
    for (name, s) in stores() {
        let s = s.as_ref();
        with_users(s);
        s.api_key_insert(&key("k1", A, "aaaa1111")).unwrap();
        s.api_key_insert(&key("k2", A, "aaaa2222")).unwrap();
        s.api_key_insert(&key("k3", B, "bbbb3333")).unwrap();
        assert_eq!(
            s.api_key_insert(&key("k4", B, "aaaa1111")),
            Err(StoreError::Duplicate),
            "{name}"
        );
        assert_eq!(
            s.api_key_by_prefix("bbbb3333").unwrap().unwrap().user_id,
            B,
            "{name}"
        );
        assert_eq!(s.api_key_list(A).unwrap().len(), 2, "{name}");
        assert_eq!(s.api_key_count_active(A, 50).unwrap(), 2, "{name}");
        assert_eq!(
            s.api_key_count_active(A, 1000).unwrap(),
            0,
            "expired at 1000: {name}"
        );
        // B cannot revoke or touch A's key.
        assert!(!s.api_key_revoke(B, "k1", 60).unwrap(), "{name}");
        s.api_key_touch_last_used(B, "k1", 61).unwrap();
        assert_eq!(
            s.api_key_by_prefix("aaaa1111")
                .unwrap()
                .unwrap()
                .last_used_at,
            None,
            "{name}"
        );
        assert!(s.api_key_revoke(A, "k1", 60).unwrap(), "{name}");
        assert!(!s.api_key_revoke(A, "k1", 70).unwrap(), "{name}");
        s.api_key_touch_last_used(A, "k2", 62).unwrap();
        let k1 = s.api_key_by_prefix("aaaa1111").unwrap().unwrap();
        let k2 = s.api_key_by_prefix("aaaa2222").unwrap().unwrap();
        assert_eq!(k1.revoked_at, Some(60), "{name}");
        assert_eq!(k2.last_used_at, Some(62), "{name}");
        assert_eq!(s.api_key_count_active(A, 50).unwrap(), 1, "{name}");
        assert_eq!(s.api_key_count_active(B, 50).unwrap(), 1, "{name}");
    }
}

#[test]
fn instances_crud() {
    for (name, s) in stores() {
        let s = s.as_ref();
        let i = InstanceRecord {
            alias: "work".into(),
            product: "jira".into(),
            base_url: "https://jira.example.test".into(),
            proxy: None,
            ca_ref: Some("org".into()),
            is_default: true,
        };
        s.instance_put(&i).unwrap();
        assert_eq!(s.instance_put(&i), Err(StoreError::Duplicate), "{name}");
        assert_eq!(s.instance_list().unwrap(), vec![i.clone()], "{name}");
        assert!(s.instance_delete("work").unwrap(), "{name}");
        assert!(!s.instance_delete("work").unwrap(), "{name}");
        assert!(s.instance_list().unwrap().is_empty(), "{name}");
    }
}

#[test]
fn anchor_append_links_rows_and_heads() {
    for (name, s) in stores() {
        let s = s.as_ref();
        assert_eq!(s.anchor_last().unwrap(), None, "{name}");
        let r1 = s
            .anchor_append("ANCHOR_GENESIS", "t1", b"{}", &[], &fake_hash)
            .unwrap();
        assert_eq!((r1.seq, r1.prev_hash), (1, [0; 32]), "{name}");
        let heads = [head(A, "ca", 7), head(B, "cb", 3)];
        let r2 = s
            .anchor_append("HEADS", "t2", b"{\"leaves\":[]}", &heads, &fake_hash)
            .unwrap();
        assert_eq!((r2.seq, r2.prev_hash), (2, r1.hash), "{name}");
        assert_eq!(r2.hash, fake_hash(2, &r1.hash), "{name}");
        s.anchor_append("HEADS", "t3", b"{}", &[head(A, "ca", 9)], &fake_hash)
            .unwrap();
        assert_eq!(s.anchor_all().unwrap().len(), 3, "{name}");
        assert_eq!(s.anchor_last().unwrap().unwrap().seq, 3, "{name}");
        assert_eq!(s.anchor_heads_for(2).unwrap(), heads.to_vec(), "{name}");
        assert_eq!(
            s.anchor_heads_for_chain("ca", 8).unwrap(),
            vec![(2, head(A, "ca", 7))],
            "{name}"
        );
        assert_eq!(
            s.anchor_heads_for_chain("ca", 9).unwrap().len(),
            2,
            "{name}"
        );
    }
}

/// Every per-user getter answers only the asked user's rows.
#[test]
fn per_user_methods_never_return_another_users_rows() {
    for (name, s) in stores() {
        let s = s.as_ref();
        with_users(s);
        s.ks_set(A, "e", &sealed(1)).unwrap();
        s.pat_put(&pat(A, "work", 1)).unwrap();
        s.api_key_insert(&key("k1", A, "aaaa1111")).unwrap();
        s.session_put(&session(1, A)).unwrap();
        assert_eq!(s.ks_get(B, "e").unwrap(), None, "{name}");
        assert_eq!(s.pat_get(B, "work").unwrap(), None, "{name}");
        assert!(s.pat_list(B).unwrap().is_empty(), "{name}");
        assert!(s.api_key_list(B).unwrap().is_empty(), "{name}");
        assert_eq!(s.api_key_count_active(B, 0).unwrap(), 0, "{name}");
        assert!(!s.ks_delete(B, "e").unwrap(), "{name}");
        assert!(!s.pat_delete(B, "work").unwrap(), "{name}");
        assert!(s.ks_get(A, "e").unwrap().is_some(), "{name}");
        assert!(s.pat_get(A, "work").unwrap().is_some(), "{name}");
    }
}

// ---- SQLite only --------------------------------------------------------------------------

#[test]
fn anchor_tables_are_append_only() {
    let s = SqliteStore::open_in_memory().unwrap();
    s.anchor_append("HEADS", "t", b"{}", &[head(A, "ca", 1)], &fake_hash)
        .unwrap();
    let c = s.raw();
    for sql in [
        "UPDATE anchor_chain SET kind = 'X'",
        "DELETE FROM anchor_chain",
        "UPDATE anchor_heads SET head_seq = 99",
        "DELETE FROM anchor_heads",
    ] {
        let e = c.execute(sql, []).unwrap_err().to_string();
        assert!(e.contains("append-only"), "{sql}: {e}");
    }
}

#[test]
fn reopen_keeps_sessions_and_newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.db");
    {
        let s = SqliteStore::open(&path).unwrap();
        s.upsert_user(&user(A, "alice")).unwrap();
        s.session_put(&session(7, A)).unwrap();
    }
    let s = SqliteStore::open(&path).unwrap();
    assert_eq!(s.session_get(&[7; 32]).unwrap(), Some(session(7, A)));
    s.raw().execute_batch("PRAGMA user_version = 2;").unwrap();
    drop(s);
    assert!(matches!(
        SqliteStore::open(&path),
        Err(StoreError::Newer(2))
    ));
}

#[test]
fn sqlite_file_uses_wal_and_foreign_keys() {
    let dir = tempfile::tempdir().unwrap();
    let s = SqliteStore::open(&dir.path().join("server.db")).unwrap();
    let c = s.raw();
    let mode: String = c
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    let fk: i64 = c
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!((mode.as_str(), fk), ("wal", 1));
    drop(c);
    // A PAT of a user that does not exist is refused.
    assert!(matches!(
        s.pat_put(&pat("nobody", "work", 1)),
        Err(StoreError::Db(_))
    ));
}

// ---- M14: OAuth and export jobs (both stores) -----------------------------------------------

fn client(id: &str, created_at: i64) -> OAuthClientRecord {
    OAuthClientRecord {
        client_id: id.into(),
        name: format!("client {id}"),
        redirect_uris: vec!["http://127.0.0.1/cb".into()],
        created_at,
        source_ip_hash: "00".repeat(32),
    }
}

fn grant(id: &str, uid: &str, client_id: &str, created_at: i64, expires_at: i64) -> GrantRecord {
    GrantRecord {
        grant_id: id.into(),
        user_id: uid.into(),
        client_id: client_id.into(),
        scopes: vec!["read".into()],
        resource: "https://duck.example.test/mcp".into(),
        created_at,
        expires_at,
        last_used_at: None,
        revoked_at: None,
        revoke_reason: None,
    }
}

fn consent(tag: u8, session: u8) -> ConsentRequestRecord {
    ConsentRequestRecord {
        id_hash: [tag; 32],
        session_hash: [session; 32],
        user_id: A.into(),
        client_id: "adc_x".into(),
        redirect_uri: "http://127.0.0.1/cb".into(),
        scopes: vec!["read".into()],
        code_challenge: "c".repeat(43),
        state: "st".into(),
        resource: "https://duck.example.test/mcp".into(),
        created_at: 10,
        expires_at: 610,
    }
}

fn code(tag: u8, grant_id: &str, expires_at: i64) -> CodeRecord {
    CodeRecord {
        hash: [tag; 32],
        grant_id: grant_id.into(),
        client_id: "adc_x".into(),
        redirect_uri: "http://127.0.0.1/cb".into(),
        code_challenge: "c".repeat(43),
        expires_at,
        redeemed_at: None,
    }
}

fn refresh(tag: u8, grant_id: &str, at: i64) -> RefreshRecord {
    RefreshRecord {
        hash: [tag; 32],
        grant_id: grant_id.into(),
        created_at: at,
        last_used_at: at,
        rotated_at: None,
    }
}

fn job(id: &str, requester: &str, target: &str, state: &str, expires_at: i64) -> ExportJobRecord {
    ExportJobRecord {
        job_id: id.into(),
        requester_user_id: requester.into(),
        target_user_id: target.into(),
        state: state.into(),
        created_at: 10,
        expires_at,
        manifest_sha256: None,
        size: None,
        file_name: None,
    }
}

#[test]
fn oauth_clients_insert_get_count() {
    for (name, s) in stores() {
        s.oauth_client_insert(&client("adc_1", 10)).unwrap();
        assert_eq!(
            s.oauth_client_get("adc_1").unwrap(),
            Some(client("adc_1", 10)),
            "{name}"
        );
        assert_eq!(s.oauth_client_get("adc_2").unwrap(), None, "{name}");
        assert_eq!(
            s.oauth_client_insert(&client("adc_1", 11)),
            Err(StoreError::Duplicate),
            "{name}"
        );
        assert_eq!(s.oauth_client_count().unwrap(), 1, "{name}");
    }
}

#[test]
fn consent_request_is_bound_to_its_session() {
    for (name, s) in stores() {
        s.consent_put(&consent(1, 7)).unwrap();
        // Another session neither sees nor consumes it.
        assert_eq!(s.consent_get(&[1; 32], &[8; 32]).unwrap(), None, "{name}");
        assert_eq!(s.consent_take(&[1; 32], &[8; 32]).unwrap(), None, "{name}");
        assert_eq!(
            s.consent_get(&[1; 32], &[7; 32]).unwrap(),
            Some(consent(1, 7)),
            "{name}"
        );
        assert_eq!(
            s.consent_take(&[1; 32], &[7; 32]).unwrap(),
            Some(consent(1, 7)),
            "{name}"
        );
        // Consumed: a second take finds nothing.
        assert_eq!(s.consent_take(&[1; 32], &[7; 32]).unwrap(), None, "{name}");
    }
}

#[test]
fn code_redeem_twice_second_is_reused() {
    for (name, s) in stores() {
        s.grant_insert(&grant("g1", A, "adc_x", 10, 10_000))
            .unwrap();
        s.code_insert(&code(1, "g1", 70)).unwrap();
        let (c, g) = s.code_redeem(&[1; 32], 20).unwrap();
        assert_eq!(
            (c.redeemed_at, g.grant_id.as_str()),
            (Some(20), "g1"),
            "{name}"
        );
        assert_eq!(
            s.code_redeem(&[1; 32], 21).unwrap_err(),
            Redeem::Reused("g1".into()),
            "{name}"
        );
        assert_eq!(
            s.code_redeem(&[9; 32], 21).unwrap_err(),
            Redeem::Unknown,
            "{name}"
        );
        // An expired code is refused and burned: the next attempt is a reuse.
        s.code_insert(&code(2, "g1", 70)).unwrap();
        assert_eq!(
            s.code_redeem(&[2; 32], 70).unwrap_err(),
            Redeem::Expired,
            "{name}"
        );
        assert_eq!(
            s.code_redeem(&[2; 32], 71).unwrap_err(),
            Redeem::Reused("g1".into()),
            "{name}"
        );
    }
}

#[test]
fn refresh_rotate_reuse_idle_and_revoked() {
    for (name, s) in stores() {
        s.grant_insert(&grant("g1", A, "adc_x", 10, 10_000))
            .unwrap();
        s.refresh_insert(&refresh(1, "g1", 10)).unwrap();
        let g = s
            .refresh_rotate(&[1; 32], &refresh(2, "g1", 20), 20, 100)
            .unwrap();
        assert_eq!(g.grant_id, "g1", "{name}");
        assert_eq!(
            s.refresh_rotate(&[1; 32], &refresh(3, "g1", 21), 21, 100)
                .unwrap_err(),
            Rotate::Reused("g1".into()),
            "{name}"
        );
        // Idle: last used at 20, idle limit 100.
        assert_eq!(
            s.refresh_rotate(&[2; 32], &refresh(4, "g1", 120), 120, 100)
                .unwrap_err(),
            Rotate::Expired,
            "{name}"
        );
        // A revoked grant's refresh token is refused.
        s.grant_insert(&grant("g2", A, "adc_x", 10, 10_000))
            .unwrap();
        s.refresh_insert(&refresh(5, "g2", 10)).unwrap();
        assert!(s.grant_revoke("g2", "user", 11).unwrap(), "{name}");
        assert!(!s.grant_revoke("g2", "user", 12).unwrap(), "{name}");
        assert_eq!(
            s.refresh_rotate(&[5; 32], &refresh(6, "g2", 13), 13, 100)
                .unwrap_err(),
            Rotate::Expired,
            "{name}"
        );
        assert_eq!(
            s.refresh_grant(&[5; 32]).unwrap().as_deref(),
            Some("g2"),
            "{name}"
        );
        assert_eq!(
            s.refresh_rotate(&[7; 32], &refresh(8, "g1", 13), 13, 100)
                .unwrap_err(),
            Rotate::Unknown,
            "{name}"
        );
    }
}

#[test]
fn concurrent_refresh_rotation_succeeds_exactly_once() {
    for (name, s) in stores() {
        s.grant_insert(&grant("g1", A, "adc_x", 10, 10_000))
            .unwrap();
        s.refresh_insert(&refresh(1, "g1", 10)).unwrap();
        let s: &dyn ServerStore = s.as_ref();
        let results: Vec<Result<GrantRecord, Rotate>> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..8u8)
                .map(|i| {
                    sc.spawn(move || {
                        s.refresh_rotate(&[1; 32], &refresh(100 + i, "g1", 20), 20, 100)
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let ok = results.iter().filter(|r| r.is_ok()).count();
        let reused = results
            .iter()
            .filter(|r| matches!(r, Err(Rotate::Reused(g)) if g == "g1"))
            .count();
        assert_eq!((ok, reused), (1, 7), "{name}");
    }
}

#[test]
fn grants_are_listed_per_user_and_revoked_all() {
    for (name, s) in stores() {
        s.grant_insert(&grant("ga1", A, "adc_x", 10, 10_000))
            .unwrap();
        s.grant_insert(&grant("ga2", A, "adc_y", 20, 10_000))
            .unwrap();
        s.grant_insert(&grant("gb1", B, "adc_x", 15, 10_000))
            .unwrap();
        let ids = |v: Vec<GrantRecord>| v.into_iter().map(|g| g.grant_id).collect::<Vec<_>>();
        assert_eq!(ids(s.grant_list(A).unwrap()), ["ga2", "ga1"], "{name}");
        assert_eq!(ids(s.grant_list(B).unwrap()), ["gb1"], "{name}");
        s.grant_touch("ga1", 50).unwrap();
        assert_eq!(
            s.grant_get("ga1").unwrap().unwrap().last_used_at,
            Some(50),
            "{name}"
        );
        assert!(s.grant_revoke("ga1", "user", 30).unwrap(), "{name}");
        let revoked = s.grant_revoke_all(A, "deactivation", 40).unwrap();
        assert_eq!(ids(revoked.clone()), ["ga2"], "{name}");
        assert_eq!(
            revoked[0].revoke_reason.as_deref(),
            Some("deactivation"),
            "{name}"
        );
        let ga1 = s.grant_get("ga1").unwrap().unwrap();
        assert_eq!(
            (ga1.revoked_at, ga1.revoke_reason.as_deref()),
            (Some(30), Some("user"))
        );
        assert!(s.grant_get("gb1").unwrap().unwrap().live(41), "{name}");
    }
}

#[test]
fn purge_removes_stale_clients_and_expired_rows() {
    const DAY: i64 = 86_400;
    for (name, s) in stores() {
        let now = 100 * DAY;
        // No grant, registered 25 h ago: purged. Registered 23 h ago: kept.
        s.oauth_client_insert(&client("old", now - 25 * 3600))
            .unwrap();
        s.oauth_client_insert(&client("new", now - 23 * 3600))
            .unwrap();
        // Last grant revoked 31 days ago: purged with its grant and tokens.
        s.oauth_client_insert(&client("ended", now - 60 * DAY))
            .unwrap();
        s.grant_insert(&grant("ge", A, "ended", now - 60 * DAY, now + DAY))
            .unwrap();
        s.grant_revoke("ge", "user", now - 31 * DAY).unwrap();
        s.refresh_insert(&refresh(1, "ge", now - 60 * DAY)).unwrap();
        // A live grant keeps its client.
        s.oauth_client_insert(&client("live", now - 60 * DAY))
            .unwrap();
        s.grant_insert(&grant("gl", A, "live", now - 60 * DAY, now + DAY))
            .unwrap();
        s.refresh_insert(&refresh(2, "gl", now)).unwrap();
        s.consent_put(&ConsentRequestRecord {
            expires_at: now - 1,
            ..consent(3, 7)
        })
        .unwrap();
        s.code_insert(&code(4, "gl", now - 1)).unwrap();
        s.access_insert(&AccessRecord {
            hash: [5; 32],
            grant_id: "gl".into(),
            expires_at: now - 1,
        })
        .unwrap();
        assert_eq!(s.oauth_purge(now).unwrap(), 2, "{name}");
        for (id, kept) in [
            ("old", false),
            ("new", true),
            ("ended", false),
            ("live", true),
        ] {
            assert_eq!(
                s.oauth_client_get(id).unwrap().is_some(),
                kept,
                "{name} {id}"
            );
        }
        assert_eq!(s.grant_get("ge").unwrap(), None, "{name}");
        assert_eq!(s.refresh_grant(&[1; 32]).unwrap(), None, "{name}");
        assert_eq!(
            s.refresh_grant(&[2; 32]).unwrap().as_deref(),
            Some("gl"),
            "{name}"
        );
        assert_eq!(s.consent_get(&[3; 32], &[7; 32]).unwrap(), None, "{name}");
        assert_eq!(
            s.code_redeem(&[4; 32], now).unwrap_err(),
            Redeem::Unknown,
            "{name}"
        );
        assert_eq!(s.access_get(&[5; 32]).unwrap(), None, "{name}");
    }
}

#[test]
fn export_jobs_round_trip() {
    for (name, s) in stores() {
        s.export_job_insert(&job("j1", A, B, "running", 100))
            .unwrap();
        s.export_job_insert(&job("j2", A, A, "done", 50)).unwrap();
        assert_eq!(
            s.export_job_insert(&job("j1", A, B, "running", 100)),
            Err(StoreError::Duplicate),
            "{name}"
        );
        let ids = |v: Vec<ExportJobRecord>| v.into_iter().map(|j| j.job_id).collect::<Vec<_>>();
        assert_eq!(ids(s.export_jobs_running().unwrap()), ["j1"], "{name}");
        assert_eq!(ids(s.export_jobs_expired(60).unwrap()), ["j2"], "{name}");
        let done = ExportJobRecord {
            state: "done".into(),
            manifest_sha256: Some("ab".repeat(32)),
            size: Some(4096),
            file_name: Some("x.tar".into()),
            ..job("j1", A, B, "running", 200)
        };
        s.export_job_update(&done).unwrap();
        assert_eq!(s.export_job_get("j1").unwrap(), Some(done), "{name}");
        assert!(s.export_jobs_running().unwrap().is_empty(), "{name}");
        assert!(s.export_job_delete("j1").unwrap(), "{name}");
        assert!(!s.export_job_delete("j1").unwrap(), "{name}");
    }
}

// ---- M14: the additive table step (SQLite only) ---------------------------------------------

fn v1_db_with_rows(path: &std::path::Path) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch(super::schema::V1).unwrap();
    c.execute_batch("PRAGMA user_version = 1;").unwrap();
    c.execute(
        "INSERT INTO users (user_id, username, display_name, roles, data_key_wrapped, created_at)
         VALUES (?1, 'alice', NULL, '[\"user\"]', '{}', 1)",
        [A],
    )
    .unwrap();
    c.execute(
        "INSERT INTO sessions VALUES (?1, ?2, '[\"user\"]', 'csrf', 1, 1, 1000, 500)",
        rusqlite::params![[7u8; 32].as_slice(), A],
    )
    .unwrap();
}

fn has_table(c: &rusqlite::Connection, name: &str) -> bool {
    c.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |r| r.get::<_, i64>(0),
    )
    .unwrap()
        > 0
}

#[test]
fn m14_tables_are_added_to_an_m12_database_keeping_its_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.db");
    v1_db_with_rows(&path);
    let s = SqliteStore::open(&path).unwrap();
    assert_eq!(s.user(A).unwrap().unwrap().username, "alice");
    assert_eq!(s.session_get(&[7; 32]).unwrap().unwrap().user_id, A);
    let c = s.raw();
    for t in [
        "oauth_clients",
        "oauth_consent_requests",
        "oauth_grants",
        "oauth_codes",
        "oauth_access",
        "oauth_refresh",
        "export_jobs",
    ] {
        assert!(has_table(&c, t), "{t}");
    }
    let v: u32 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 1, "M14 bumps no version (v2 is M13's)");
    drop(c);
    drop(s);
    // Reopening is a no-op.
    let s = SqliteStore::open(&path).unwrap();
    s.oauth_client_insert(&client("adc_1", 1)).unwrap();
}

#[test]
fn a_failed_table_step_leaves_the_database_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.db");
    v1_db_with_rows(&path);
    let c = rusqlite::Connection::open(&path).unwrap();
    let broken = format!("{}\nCREATE TABLE broken (;", super::schema::M14_TABLES);
    assert!(super::sqlite::add_tables(&c, &broken).is_err());
    assert!(!has_table(&c, "oauth_clients"));
    assert!(!has_table(&c, "export_jobs"));
    let users: i64 = c
        .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
        .unwrap();
    assert_eq!(users, 1);
}
