//! Admin instances (T13): validation, add/remove across user runtimes. The admin CLI's tests are
//! `admin::tests` (M13 T5).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use super::*;
use crate::runtime::tests::Env;
use crate::store::{PatRecord, Sealed};

const LIMIT: Duration = Duration::from_secs(60);

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIMIT, f).await.expect("timed out")
}

fn spec(alias: &str, product: &str, url: &str, default: bool) -> InstanceSpec {
    InstanceSpec {
        alias: alias.into(),
        product: product.into(),
        base_url: url.into(),
        proxy: None,
        ca_ref: None,
        is_default: default,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validation_errors_are_instance_invalid_and_duplicates_409() {
    let env = Env::new();
    let mut deps = env.deps();
    deps.allow_http = false;
    let reg = Registry::new(deps, 10);
    let s = env.store.as_ref();
    for bad in [
        spec("a b", "jira", "https://x.example.test", false),
        spec("x", "bitbucket", "https://x.example.test", false),
        spec("x", "jira", "http://x.example.test", false),
        spec("x", "jira", "not a url", false),
        // `work` (jira) is already the default.
        spec("x", "jira", "https://x.example.test", true),
        InstanceSpec {
            ca_ref: Some("other".into()),
            ..spec("x", "jira", "https://x.example.test", false)
        },
    ] {
        assert_eq!(
            within(add(s, &reg, bad.clone())).await.unwrap_err(),
            ApiError::INSTANCE_INVALID,
            "{bad:?}"
        );
    }
    assert_eq!(
        within(add(
            s,
            &reg,
            spec("work", "jira", "https://y.example.test", false)
        ))
        .await
        .unwrap_err(),
        ApiError::INSTANCE_EXISTS
    );
    let ok = within(add(
        s,
        &reg,
        spec("wiki", "confluence", "https://wiki.example.test", true),
    ))
    .await
    .unwrap();
    assert_eq!(ok.alias, "wiki");
    assert_eq!(list(s).unwrap().len(), 2);
    assert_eq!(
        within(remove(s, &reg, "nope")).await.unwrap_err(),
        ApiError::INSTANCE_UNKNOWN
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn added_instances_reach_open_runtimes() {
    let env = Env::new();
    let uid = env.user("alice");
    let reg = Registry::new(env.deps(), 10);
    let rt = within(reg.open_user(&uid)).await.unwrap();
    let before = serde_json::to_string(&within(rt.handler().instances_list()).await).unwrap();
    assert!(!before.contains("\"wiki\""));
    within(add(
        env.store.as_ref(),
        &reg,
        spec("wiki", "confluence", "https://wiki.example.test", true),
    ))
    .await
    .unwrap();
    let after = serde_json::to_string(&within(rt.handler().instances_list()).await).unwrap();
    assert!(after.contains("\"wiki\""), "{after}");
    within(remove(env.store.as_ref(), &reg, "wiki"))
        .await
        .unwrap();
    let gone = serde_json::to_string(&within(rt.handler().instances_list()).await).unwrap();
    assert!(!gone.contains("\"wiki\""), "{gone}");
    within(reg.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removal_deletes_every_users_pat_with_a_record_in_each_chain() {
    let env = Env::new();
    let (a, b, c) = (env.user("alice"), env.user("bob"), env.user("carol"));
    for uid in [&a, &b] {
        env.store
            .pat_put(&PatRecord {
                user_id: uid.clone(),
                alias: "work".into(),
                sealed: Sealed {
                    nonce: vec![0; 12],
                    ct: vec![1, 2, 3],
                },
                identity_json: "{}".into(),
                checked_at: 0,
            })
            .unwrap();
    }
    let reg = Registry::new(env.deps(), 10);
    // A is open, B is closed (its runtime opens for the record), C has no PAT.
    let ra = within(reg.open_user(&a)).await.unwrap();
    let seq_a = ra.head().1;
    let rc = within(reg.open_user(&c)).await.unwrap();
    let seq_c = rc.head().1;
    within(remove(env.store.as_ref(), &reg, "work"))
        .await
        .unwrap();
    assert!(env.store.pats_for_alias("work").unwrap().is_empty());
    assert_eq!(
        ra.head().1,
        seq_a + 1,
        "one CREDENTIAL_CHANGED in A's chain"
    );
    assert_eq!(rc.head().1, seq_c, "nothing in C's chain");
    let rb = within(reg.open_user(&b)).await.unwrap();
    assert!(rb.head().1 > 0);
    assert!(env.store.instance_list().unwrap().is_empty());
    within(reg.close_all()).await;
}

fn pat(uid: &str, alias: &str) -> PatRecord {
    PatRecord {
        user_id: uid.to_owned(),
        alias: alias.into(),
        sealed: Sealed {
            nonce: vec![0; 12],
            ct: vec![1, 2, 3],
        },
        identity_json: "{}".into(),
        checked_at: 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_removal_keeps_the_row_and_can_be_retried() {
    // Batch-3 review I1: the row goes last, so a PAT whose owner cannot be opened keeps the
    // instance listed; once the PAT is gone the retry succeeds.
    let env = Env::new();
    let a = env.user("alice");
    env.store.pat_put(&pat(&a, "work")).unwrap();
    env.store.pat_put(&pat("usr_nobody", "work")).unwrap();
    let reg = Registry::new(env.deps(), 10);
    assert!(
        within(remove(env.store.as_ref(), &reg, "work"))
            .await
            .is_err()
    );
    assert_eq!(env.store.instance_list().unwrap().len(), 1, "row kept");
    env.store.pat_delete("usr_nobody", "work").unwrap();
    within(remove(env.store.as_ref(), &reg, "work"))
        .await
        .unwrap();
    assert!(env.store.pats_for_alias("work").unwrap().is_empty());
    assert!(env.store.instance_list().unwrap().is_empty());
    let kinds: Vec<String> = env
        .store
        .anchor_all()
        .unwrap()
        .into_iter()
        .map(|r| r.kind)
        .collect();
    assert!(kinds.iter().any(|k| k == "INSTANCE_REMOVED"), "{kinds:?}");
    within(reg.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_re_added_alias_never_sees_a_leftover_pat() {
    let env = Env::new();
    let a = env.user("alice");
    env.store.pat_put(&pat(&a, "wiki")).unwrap();
    let reg = Registry::new(env.deps(), 10);
    within(add(
        env.store.as_ref(),
        &reg,
        spec("wiki", "confluence", "https://other.example.test", false),
    ))
    .await
    .unwrap();
    assert!(env.store.pats_for_alias("wiki").unwrap().is_empty());
    within(reg.close_all()).await;
}
