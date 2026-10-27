//! Admin socket protocol, instances and users over the connection handler (M13 T5). The
//! connection handler runs over in-memory streams everywhere; the socket file's mode and the
//! peer-UID check run on Unix only.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::client::{Parsed, parse};
use super::*;
use crate::anchor::{KIND_USER_DEACTIVATED, verify};
use crate::api_keys::ApiKeyParams;
use crate::clock::ManualClock;
use crate::errors::ApiError;
use crate::runtime::UserCtx;
use crate::runtime::tests::Env;
use crate::store::{PatRecord, Sealed};

const LIMIT: Duration = Duration::from_secs(60);

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIMIT, f).await.expect("timed out")
}

struct T {
    env: Env,
    ctx: Arc<AdminCtx>,
    clock: Arc<ManualClock>,
}

fn harness() -> T {
    let env = Env::new();
    let clock = ManualClock::at(1_800_000_000);
    let mut deps = env.deps();
    deps.clock = clock.clone();
    let registry = Arc::new(Registry::new(deps, 10));
    let sessions =
        Arc::new(SessionTable::new(env.store.clone(), clock.clone(), 28_800, 1_800).unwrap());
    let api_keys =
        Arc::new(ApiKeys::new(env.store.clone(), clock.clone(), ApiKeyParams::TEST).unwrap());
    let writer = Arc::new(AnchorWriter::new(
        env.store.clone(),
        registry.clone(),
        clock.clone(),
    ));
    writer.start(&json!({})).unwrap();
    let ctx = Arc::new(AdminCtx::new(
        env.store.clone(),
        registry,
        sessions,
        api_keys,
        writer,
        clock.clone(),
        DEFAULT_RETENTION_DAYS,
    ));
    T { env, ctx, clock }
}

/// One request line through the connection handler; the answer line parsed.
async fn call_raw(ctx: &Arc<AdminCtx>, line: &[u8]) -> Response {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let c = ctx.clone();
    let task = tokio::spawn(async move { serve_conn(&c, server).await });
    client.write_all(line).await.unwrap();
    client.write_all(b"\n").await.unwrap();
    let mut out = Vec::new();
    within(client.read_to_end(&mut out)).await.unwrap();
    within(task).await.unwrap().unwrap();
    assert_eq!(out.last(), Some(&b'\n'), "one line");
    serde_json::from_slice(&out).unwrap()
}

async fn call(ctx: &Arc<AdminCtx>, req: Value) -> Response {
    call_raw(ctx, req.to_string().as_bytes()).await
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
async fn admin_request_dto_rejects_unknown_fields() {
    let t = harness();
    for bad in [
        json!({"op": "users_list", "x": 1}),
        json!({"op": "users_deactivate", "username": "alice", "force": true}),
        json!({"op": "instances_remove", "alias": "work", "user": "alice"}),
        json!({"op": "instances_add", "alias": "a", "product": "jira",
               "url": "https://a.example.test", "token": "x"}),
        json!({"op": "users_drop"}),
        json!({"username": "alice"}),
    ] {
        let r = call(&t.ctx, bad.clone()).await;
        assert_eq!(r, Response::err("admin/bad_request"), "{bad}");
    }
    let r = call_raw(&t.ctx, b"not json").await;
    assert_eq!(r.error.as_deref(), Some("admin/bad_request"));
    let huge = vec![b'x'; MAX_LINE + 10];
    let r = call_raw(&t.ctx, &huge).await;
    assert_eq!(r.error.as_deref(), Some("admin/request_too_large"));
    // The known shapes parse.
    assert!(call(&t.ctx, json!({"op": "users_list"})).await.ok);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn instances_add_list_remove_via_socket() {
    let t = harness();
    let a = t.env.user("alice");
    t.env.store.pat_put(&pat(&a, "work")).unwrap();
    let rt = within(t.ctx.registry.open_user(&a)).await.unwrap();

    let added = call(
        &t.ctx,
        json!({"op": "instances_add", "alias": "wiki", "product": "confluence",
               "url": "https://wiki.example.test"}),
    )
    .await;
    assert!(added.ok, "{added:?}");
    let listed = call(&t.ctx, json!({"op": "instances_list"})).await;
    let aliases: Vec<&str> = listed
        .data
        .as_ref()
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["alias"].as_str().unwrap())
        .collect();
    assert_eq!(aliases, ["wiki", "work"]);
    // Duplicate and unknown answer the instance codes.
    let dup = call(
        &t.ctx,
        json!({"op": "instances_add", "alias": "wiki", "product": "confluence",
               "url": "https://wiki.example.test"}),
    )
    .await;
    assert_eq!(dup.error.as_deref(), Some(ApiError::INSTANCE_EXISTS.code));
    let unknown = call(&t.ctx, json!({"op": "instances_remove", "alias": "nope"})).await;
    assert_eq!(
        unknown.error.as_deref(),
        Some(ApiError::INSTANCE_UNKNOWN.code)
    );

    // Removal deletes every user's PAT with a CREDENTIAL_CHANGED in that user's chain.
    let seq = rt.head().1;
    let removed = call(&t.ctx, json!({"op": "instances_remove", "alias": "work"})).await;
    assert!(removed.ok, "{removed:?}");
    assert!(t.env.store.pats_for_alias("work").unwrap().is_empty());
    assert_eq!(rt.head().1, seq + 1);
    let listed = call(&t.ctx, json!({"op": "instances_list"})).await;
    assert_eq!(listed.data.unwrap().as_array().unwrap().len(), 1);
    within(t.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn users_list_shows_name_roles_last_login_state_no_secrets() {
    let t = harness();
    let a = t.env.user("alice");
    let b = t.env.user("bob");
    t.env.store.user_set_last_login(&a, 1_800_000_000).unwrap();
    t.env
        .store
        .user_deactivate(&b, 1_800_000_100, "admin", 1_900_000_000)
        .unwrap();
    let r = call(&t.ctx, json!({"op": "users_list"})).await;
    assert!(r.ok);
    let data = r.data.unwrap();
    assert_eq!(
        data,
        json!([
            {"username": "alice", "display_name": null, "roles": ["user"],
             "last_login_at": "2027-01-15T08:00:00.000Z", "state": "active",
             "deactivated_at": null, "deactivated_by": null},
            {"username": "bob", "display_name": null, "roles": ["user"],
             "last_login_at": null, "state": "deactivated",
             "deactivated_at": "2027-01-15T08:01:40.000Z", "deactivated_by": "admin"}
        ])
    );
    let text = data.to_string();
    let wrapped = t.env.store.user(&a).unwrap().unwrap().data_key_wrapped;
    let ct = serde_json::from_str::<Value>(&wrapped).unwrap()["ct"]
        .as_str()
        .unwrap()
        .to_owned();
    for secret in [ct.as_str(), a.as_str(), b.as_str(), "data_key"] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deactivate_revokes_pats_and_api_keys_and_ends_sessions_immediately() {
    let t = harness();
    let a = t.env.user("alice");
    let b = t.env.user("bob");
    let ctx_a = UserCtx::from_authenticated(&a);
    let key = t
        .ctx
        .api_keys
        .create(&ctx_a, "agent", &["read".to_owned()], None)
        .unwrap();
    // Cached once, so the revocation must evict the cache too.
    assert!(t.ctx.api_keys.authenticate(key.key.expose_secret()).is_ok());
    let session = t.ctx.sessions.create(&a, vec!["user".into()]).unwrap();
    let other = t.ctx.sessions.create(&b, vec!["user".into()]).unwrap();
    t.env.store.pat_put(&pat(&a, "work")).unwrap();
    t.env.store.pat_put(&pat(&b, "work")).unwrap();

    let r = call(
        &t.ctx,
        json!({"op": "users_deactivate", "username": "Alice"}),
    )
    .await;
    assert!(r.ok, "{r:?}");
    let report = r.data.unwrap();
    assert_eq!(report["newly_deactivated"], true);
    assert_eq!(report["sessions_ended"], 1);
    assert_eq!(report["api_keys_revoked"], 1);
    assert_eq!(report["pats_deleted"], 1);

    assert_eq!(
        t.ctx
            .sessions
            .lookup(session.cookie_id.expose_secret())
            .unwrap_err(),
        ApiError::NO_SESSION
    );
    assert!(
        t.env
            .store
            .sessions_all()
            .unwrap()
            .iter()
            .all(|s| s.user_id != a)
    );
    assert!(
        t.ctx
            .api_keys
            .authenticate(key.key.expose_secret())
            .is_err()
    );
    assert!(
        t.env
            .store
            .api_key_list(&a)
            .unwrap()
            .iter()
            .all(|k| k.revoked_at.is_some())
    );
    assert!(t.env.store.pat_list(&a).unwrap().is_empty());
    let st = t.env.store.user_state(&a).unwrap().unwrap();
    assert_eq!(st.deactivated_at, Some(t.clock.now()));
    assert_eq!(st.deactivated_by.as_deref(), Some("admin"));
    assert_eq!(st.retention_until, Some(t.clock.now() + 365 * 86_400));
    // Bob keeps everything.
    assert!(
        t.ctx
            .sessions
            .lookup(other.cookie_id.expose_secret())
            .is_ok()
    );
    assert_eq!(t.env.store.pat_list(&b).unwrap().len(), 1);
    let unknown = call(
        &t.ctx,
        json!({"op": "users_deactivate", "username": "nobody"}),
    )
    .await;
    assert_eq!(unknown.error.as_deref(), Some("admin/user_unknown"));
    within(t.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deactivate_appends_anchor_head_and_user_deactivated() {
    let t = harness();
    let a = t.env.user("alice");
    t.env.store.pat_put(&pat(&a, "work")).unwrap();
    let r = call(
        &t.ctx,
        json!({"op": "users_deactivate", "username": "alice"}),
    )
    .await;
    assert!(r.ok, "{r:?}");
    let rt = within(t.ctx.registry.open_user(&a)).await.unwrap();
    let (chain, seq, hash) = rt.head();
    let last = t.env.store.anchor_last().unwrap().unwrap();
    assert_eq!(last.kind, KIND_USER_DEACTIVATED);
    assert_eq!(r.data.unwrap()["anchor_seq"], last.seq);
    let heads = t.env.store.anchor_heads_for(last.seq).unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].user_id, a);
    assert_eq!(heads[0].chain_id, chain);
    assert_eq!((heads[0].head_seq, heads[0].record_hash), (seq, hash));
    let leaf = atlas_duck_audit::server_anchor::leaf_hash(&a, &chain, seq, &hash);
    assert_eq!(
        last.body_jcs,
        atlas_duck_audit::server_anchor::leaf_body_jcs(&leaf)
    );
    // The body names no user in clear, and the chain verifies with the new kind.
    assert!(!String::from_utf8_lossy(&last.body_jcs).contains("alice"));
    verify(t.env.store.as_ref()).unwrap();
    within(t.ctx.registry.close_all()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deactivate_is_idempotent() {
    let t = harness();
    let a = t.env.user("alice");
    t.env.store.pat_put(&pat(&a, "work")).unwrap();
    let first = call(
        &t.ctx,
        json!({"op": "users_deactivate", "username": "alice"}),
    )
    .await;
    assert!(first.ok);
    let rows = t.env.store.anchor_all().unwrap().len();
    let head = within(t.ctx.registry.open_user(&a)).await.unwrap().head();
    t.clock.advance(60);
    let second = call(
        &t.ctx,
        json!({"op": "users_deactivate", "username": "alice"}),
    )
    .await;
    assert!(second.ok);
    assert_eq!(
        second.data.unwrap(),
        json!({"username": "alice", "newly_deactivated": false, "sessions_ended": 0,
               "api_keys_revoked": 0, "pats_deleted": 0, "anchor_seq": null})
    );
    assert_eq!(t.env.store.anchor_all().unwrap().len(), rows);
    assert_eq!(
        within(t.ctx.registry.open_user(&a)).await.unwrap().head(),
        head
    );
    let st = t.env.store.user_state(&a).unwrap().unwrap();
    assert_eq!(
        st.deactivated_at,
        Some(1_800_000_000),
        "the first time is kept"
    );
    within(t.ctx.registry.close_all()).await;
}

#[test]
fn cli_argument_table() {
    let a = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let run = |v: &[&str]| match parse(&a(v)) {
        Some(Parsed::Run(r)) => Some(r),
        _ => None,
    };
    assert_eq!(parse(&a(&["--help"])), Some(Parsed::Help));
    assert_eq!(
        run(&["instances", "list"]),
        Some(Request::InstancesList(NoArgs {}))
    );
    assert_eq!(
        run(&[
            "instances",
            "add",
            "--alias",
            "work",
            "--product",
            "jira",
            "--url",
            "https://j.example.test",
            "--default",
            "--ca-org"
        ]),
        Some(Request::InstancesAdd(InstanceArgs {
            alias: "work".into(),
            product: "jira".into(),
            url: "https://j.example.test".into(),
            default: true,
            ca_org: true,
            proxy: None,
        }))
    );
    assert_eq!(
        run(&["instances", "remove", "--alias", "work"]),
        Some(Request::InstancesRemove(AliasArg {
            alias: "work".into()
        }))
    );
    assert_eq!(run(&["users", "list"]), Some(Request::UsersList(NoArgs {})));
    assert_eq!(
        run(&["users", "deactivate", "alice"]),
        Some(Request::UsersDeactivate(UsernameArg {
            username: "alice".into()
        }))
    );
    for bad in [
        &["instances"][..],
        &["instances", "add", "--alias", "x"],
        &[
            "instances",
            "add",
            "--alias",
            "x",
            "--alias",
            "y",
            "--product",
            "jira",
            "--url",
            "u",
        ],
        &["instances", "list", "--x"],
        &["instances", "remove"],
        &["users", "deactivate"],
        &["users", "deactivate", "--all"],
        &["users", "deactivate", "a", "b"],
        &[],
    ] {
        assert_eq!(parse(&a(bad)), None, "{bad:?}");
    }
    // What the client sends is what the server parses.
    let req = Request::UsersDeactivate(UsernameArg {
        username: "alice".into(),
    });
    let line = serde_json::to_vec(&req).unwrap();
    assert_eq!(parse_line(&line), Ok(req));
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn socket_file_mode_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run").join("admin.sock");
        let (_listener, uid) = socket::bind(&path).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(uid, meta.uid());
        // A stale socket is replaced; a regular file at the path is refused.
        drop(_listener);
        assert!(socket::bind(&path).is_ok());
        let file = dir.path().join("plain");
        std::fs::write(&file, "x").unwrap();
        assert!(socket::bind(&file).is_err());
    }

    async fn exchange(path: &std::path::Path) -> Vec<u8> {
        let mut s = tokio::net::UnixStream::connect(path).await.unwrap();
        s.write_all(b"{\"op\":\"users_list\"}\n").await.unwrap();
        let mut out = Vec::new();
        let _ = within(s.read_to_end(&mut out)).await;
        out
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn socket_refuses_peer_with_other_uid() {
        let t = harness();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.sock");
        let (listener, uid) = socket::bind(&path).unwrap();
        // The server allows only another UID than this test's: the connection closes unanswered.
        let refusing = tokio::spawn(socket::serve(listener, uid.wrapping_add(1), t.ctx.clone()));
        assert!(exchange(&path).await.is_empty());
        refusing.abort();
        // The same peer is answered when its UID is the allowed one.
        let (listener, uid) = socket::bind(&path).unwrap();
        let serving = tokio::spawn(socket::serve(listener, uid, t.ctx.clone()));
        let out = exchange(&path).await;
        let r: Response = serde_json::from_slice(&out).unwrap();
        assert!(r.ok);
        // The CLI's own transport reaches it too.
        let p = path.clone();
        let sent =
            tokio::task::spawn_blocking(move || client::send(&p, &Request::UsersList(NoArgs {})))
                .await
                .unwrap()
                .unwrap();
        assert!(sent.ok);
        serving.abort();
    }
}
