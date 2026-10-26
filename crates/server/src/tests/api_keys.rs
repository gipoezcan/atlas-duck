//! API keys (T18): format, hashing, limits, cache, revocation, expiry, the dummy verify.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use super::*;
use crate::clock::ManualClock;
use crate::store::UserRecord;
use crate::store::memory::MemoryStore;

const T0: i64 = 1_800_000_000;

fn setup() -> (
    ApiKeys,
    Arc<dyn ServerStore>,
    Arc<ManualClock>,
    UserCtx,
    UserCtx,
) {
    let store: Arc<dyn ServerStore> = Arc::new(MemoryStore::new());
    for u in ["a", "b"] {
        store
            .upsert_user(&UserRecord {
                user_id: u.into(),
                username: u.into(),
                display_name: None,
                roles: vec![],
                data_key_wrapped: String::new(),
                created_at: 0,
            })
            .unwrap();
    }
    let clock = ManualClock::at(T0);
    let keys = ApiKeys::new(store.clone(), clock.clone(), ApiKeyParams::TEST).unwrap();
    (
        keys,
        store,
        clock,
        UserCtx::from_authenticated("a"),
        UserCtx::from_authenticated("b"),
    )
}

fn scopes(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| (*x).to_owned()).collect()
}

#[test]
fn production_parameters() {
    assert_eq!(
        ApiKeyParams::PRODUCTION,
        ApiKeyParams {
            m_kib: 19_456,
            t: 2,
            p: 1
        }
    );
}

#[test]
fn a_created_key_authenticates_and_has_the_format() {
    let (keys, store, _, a, _) = setup();
    let c = keys.create(&a, "laptop", &scopes(&["read"]), None).unwrap();
    let k = c.key.expose_secret();
    let (prefix, secret) = split_key(k).unwrap();
    assert_eq!(prefix, c.view.prefix);
    assert_eq!(secret.len(), 43);
    assert_eq!(c.view.expires_at, T0 + 30 * 86_400);
    let ctx = keys.authenticate(k).unwrap();
    assert_eq!(ctx.user, a);
    assert_eq!(ctx.scopes, ["read"]);
    // The store never holds the key string.
    let rec = store.api_key_by_prefix(prefix).unwrap().unwrap();
    assert!(!rec.hash.contains(secret));
    assert!(rec.hash.starts_with("$argon2id$v=19$m=8,t=1,p=1$"));
    // The list carries no key and no hash.
    let listed = serde_json::to_string(&keys.list(&a).unwrap()).unwrap();
    assert!(!listed.contains(secret) && !listed.contains("argon2"));
}

#[test]
fn a_tampered_key_is_invalid() {
    let (keys, _, _, a, _) = setup();
    let c = keys.create(&a, "k", &scopes(&["read"]), None).unwrap();
    let mut k = c.key.expose_secret().to_owned();
    let last = k.pop().unwrap();
    k.push(if last == 'A' { 'B' } else { 'A' });
    assert_eq!(keys.authenticate(&k), Err(AuthFail::Invalid));
}

#[test]
fn unknown_prefix_and_malformed_keys_run_the_dummy_verify() {
    let (keys, _, _, _, _) = setup();
    let before = keys.dummy_verifies();
    let unknown = format!("adk_zzzzzzzz_{}", "A".repeat(43));
    assert_eq!(keys.authenticate(&unknown), Err(AuthFail::Invalid));
    assert_eq!(keys.authenticate("not a key"), Err(AuthFail::Invalid));
    assert_eq!(keys.dummy_verifies(), before + 2);
}

#[test]
fn revoked_is_refused_at_once_even_when_cached() {
    let (keys, _, _, a, _) = setup();
    let c = keys.create(&a, "k", &scopes(&["read"]), None).unwrap();
    let k = c.key.expose_secret();
    keys.authenticate(k).unwrap(); // cached now
    assert!(keys.revoke(&a, &c.id).unwrap().is_some());
    match keys.authenticate(k) {
        Err(AuthFail::Refused {
            reason, user_id, ..
        }) => {
            assert_eq!((reason, user_id.as_str()), ("revoked", "a"));
        }
        other => panic!("{other:?}"),
    }
    assert!(keys.revoke(&a, &c.id).unwrap().is_none(), "already revoked");
}

#[test]
fn expired_is_refused() {
    let (keys, _, clock, a, _) = setup();
    let c = keys.create(&a, "k", &scopes(&["read"]), Some(30)).unwrap();
    let k = c.key.expose_secret();
    keys.authenticate(k).unwrap();
    clock.advance(31 * 86_400);
    assert!(matches!(
        keys.authenticate(k),
        Err(AuthFail::Refused {
            reason: "expired",
            ..
        })
    ));
}

#[test]
fn limits_and_validation() {
    let (keys, _, _, a, b) = setup();
    for (name, sc, days, want) in [
        (
            "x",
            vec!["read"],
            Some(0),
            ApiError::API_KEY_EXPIRY_OUT_OF_RANGE,
        ),
        (
            "x",
            vec!["read"],
            Some(91),
            ApiError::API_KEY_EXPIRY_OUT_OF_RANGE,
        ),
        ("x", vec![], None, ApiError::API_KEY_SCOPE_INVALID),
        ("x", vec!["admin"], None, ApiError::API_KEY_SCOPE_INVALID),
        (
            "x",
            vec!["read", "read"],
            None,
            ApiError::API_KEY_SCOPE_INVALID,
        ),
        ("a\nb", vec!["read"], None, ApiError::API_KEY_NAME_INVALID),
        ("", vec!["read"], None, ApiError::API_KEY_NAME_INVALID),
    ] {
        assert_eq!(
            keys.create(&a, name, &scopes(&sc), days).err(),
            Some(want),
            "{name:?} {sc:?} {days:?}"
        );
    }
    assert_eq!(
        keys.create(&a, &"n".repeat(65), &scopes(&["read"]), None)
            .err(),
        Some(ApiError::API_KEY_NAME_INVALID)
    );
    for i in 0..25 {
        keys.create(
            &a,
            &format!("k{i}"),
            &scopes(&["read", "propose_write", "scripts"]),
            Some(90),
        )
        .unwrap();
    }
    assert_eq!(
        keys.create(&a, "26th", &scopes(&["read"]), None).err(),
        Some(ApiError::API_KEY_LIMIT_REACHED)
    );
    // B's list excludes A's keys; B's own limit is untouched.
    assert!(keys.list(&b).unwrap().is_empty());
    keys.create(&b, "b1", &scopes(&["read"]), None).unwrap();
    assert_eq!(keys.list(&a).unwrap().len(), 25);
    // B cannot revoke A's key.
    let a_key = keys.list(&a).unwrap()[0].id.clone();
    assert!(keys.revoke(&b, &a_key).unwrap().is_none());
}

#[test]
fn last_used_is_written_at_most_every_minute() {
    let (keys, store, clock, a, _) = setup();
    let c = keys.create(&a, "k", &scopes(&["read"]), None).unwrap();
    let k = c.key.expose_secret();
    keys.authenticate(k).unwrap();
    let first = store
        .api_key_by_prefix(&c.view.prefix)
        .unwrap()
        .unwrap()
        .last_used_at;
    assert_eq!(first, Some(T0));
    clock.advance(30);
    keys.authenticate(k).unwrap();
    assert_eq!(
        store
            .api_key_by_prefix(&c.view.prefix)
            .unwrap()
            .unwrap()
            .last_used_at,
        Some(T0)
    );
    clock.advance(31);
    keys.authenticate(k).unwrap();
    assert_eq!(
        store
            .api_key_by_prefix(&c.view.prefix)
            .unwrap()
            .unwrap()
            .last_used_at,
        Some(T0 + 61)
    );
}
