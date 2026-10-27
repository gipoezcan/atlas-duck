//! M14 T18 (SM-6.3, SM-6.4; PD-253..PD-256, PD-258): export jobs, the anchor-chain excerpt, the
//! tar download and the TTL sweep. The archive is read back by the hand-written ustar reader of
//! `tar::tests` and verified offline by `verify_export_full`.

use super::*;
use crate::clock::Clock as _;
use crate::export_job::{ARCHIVE_FILES, STATE_DONE, STATE_DOWNLOADED, STATE_FAILED};
use crate::runtime::UserCtx;
use atlas_duck_audit::server_anchor::{EXCERPT_FILE, EXCERPT_MANIFEST_FILE};
use atlas_duck_audit::verify_export::{AnchorChain, MANIFEST_AND_CHAIN_OK};

impl H {
    async fn get_raw(&self, (c, _): &(String, String), path: &str) -> Response {
        self.send(
            Request::builder()
                .uri(path)
                .header(header::COOKIE, format!("__Host-atlas_duck_session={c}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn post_json(&self, (c, t): &(String, String), path: &str, body: Value) -> Response {
        self.send(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::COOKIE, format!("__Host-atlas_duck_session={c}"))
                .header("x-csrf-token", t)
                .header(header::ORIGIN, ORIGIN)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    /// `(kind, payload)` of `name`'s chain, newest first (opens the runtime).
    async fn kinds_of_user(&self, name: &str) -> Vec<(atlas_duck_audit::EventType, Value)> {
        let rt = self
            .registry
            .runtime(&UserCtx::from_authenticated(&user_id_for(name)))
            .await
            .unwrap();
        self.chain_kinds(&rt)
    }

    /// Starts an export at `path` and waits for the job to end: its final status. (The stub
    /// login of these tests creates no store; `kinds_of_user` opens the runtime first.)
    async fn export_done(&self, s: &(String, String), path: &str) -> Value {
        let res = self.post_json(s, path, json!({})).await;
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let job = json_body(res).await;
        assert_eq!(job["state"], "running");
        self.state.exports.wait_idle().await;
        let id = job["job_id"].as_str().unwrap();
        let res = self.get_raw(s, &format!("{path}/{id}")).await;
        assert_eq!(res.status(), StatusCode::OK);
        json_body(res).await
    }
}

async fn bytes_of(res: Response) -> Vec<u8> {
    axum::body::to_bytes(res.into_body(), 1 << 26)
        .await
        .unwrap()
        .to_vec()
}

fn hex32(v: &Value) -> [u8; 32] {
    let mut h = [0u8; 32];
    hex::decode_to_slice(v.as_str().unwrap(), &mut h).unwrap();
    h
}

/// Extracts the archive's members into `into` (their names are `<dir>/<file>`).
fn extract(archive: &[u8], into: &std::path::Path) -> std::path::PathBuf {
    let members = crate::tar::tests::read(archive);
    let mut dir = None;
    for (name, mode, _, _, data) in members {
        assert_eq!(mode, 0o600);
        let (d, f) = name.split_once('/').unwrap();
        std::fs::create_dir_all(into.join(d)).unwrap();
        std::fs::write(into.join(d).join(f), data).unwrap();
        dir = Some(into.join(d));
    }
    dir.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_own_export_downloads_as_a_tar_that_verifies_against_the_anchor_chain() {
    let h = H::new();
    let alice = h.session("alice", PW_CANARY).await;
    h.kinds_of_user("alice").await;
    // A failed login of another user: its anchor row never reaches alice's excerpt with a body.
    let _ = h.login("carol", "wrong-password-xyz").await;
    let done = h.export_done(&alice, "/api/me/audit/exports").await;
    assert_eq!(done["state"], STATE_DONE, "{done}");
    let id = done["job_id"].as_str().unwrap().to_owned();
    let manifest = hex32(&done["manifest_sha256"]);
    let pin = (
        done["anchor_head"]["seq"].as_u64().unwrap(),
        hex32(&done["anchor_head"]["hash"]),
    );
    let cmd = done["verify_command"].as_str().unwrap();
    assert!(cmd.contains("--anchor-chain-head") && cmd.contains(&hex::encode(manifest)));
    // The archive: Content-Length, the manifest header, six members.
    let res = h
        .get_raw(&alice, &format!("/api/me/audit/exports/{id}/download"))
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "application/x-tar");
    assert_eq!(
        res.headers()["x-atlas-duck-manifest-sha256"],
        hex::encode(manifest).as_str()
    );
    let cd = res.headers()[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        cd.starts_with("attachment; filename=\"atlas-duck-export-alice-1-"),
        "{cd}"
    );
    let len: usize = res.headers()[header::CONTENT_LENGTH]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let archive = bytes_of(res).await;
    assert_eq!(archive.len(), len);
    assert_eq!(done["size"].as_u64().unwrap() as usize, len);
    let members = crate::tar::tests::read(&archive);
    let names: Vec<&str> = members
        .iter()
        .map(|m| m.0.split_once('/').unwrap().1)
        .collect();
    assert_eq!(names, ARCHIVE_FILES);
    // Offline verification with both roots.
    let out = tempfile::tempdir().unwrap();
    let dir = extract(&archive, out.path());
    let v = atlas_duck_audit::verify_export_full(
        &dir,
        None,
        Some(AnchorChain {
            excerpt: &dir.join(EXCERPT_FILE),
            head: Some(pin),
        }),
        Some(manifest),
    );
    assert_eq!(v.exit_code(), 0, "{:#?}", v.report());
    assert_eq!(v.report().last().unwrap(), MANIFEST_AND_CHAIN_OK);
    // The pin alone binds the whole export (the forced HEADS names its last row).
    let v = atlas_duck_audit::verify_export_full(
        &dir,
        None,
        Some(AnchorChain {
            excerpt: &dir.join(EXCERPT_FILE),
            head: Some(pin),
        }),
        None,
    );
    assert_eq!(v.exit_code(), 0, "{:#?}", v.report());
    // The excerpt's last row is the pin and its leaf names alice's exported head.
    let em: Value =
        serde_json::from_slice(&std::fs::read(dir.join(EXCERPT_MANIFEST_FILE)).unwrap()).unwrap();
    assert_eq!(em["last_seq"], pin.0);
    let m: Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let text = std::fs::read_to_string(dir.join(EXCERPT_FILE)).unwrap();
    let last: Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert_eq!(last["leaf_entry"]["head_seq"], m["last_seq"]);
    assert_eq!(last["leaf_entry"]["record_hash"], m["head"]["record_hash"]);
    // No other user and no LOGIN_FAILED body in the excerpt.
    let alice_id = user_id_for("alice");
    for line in text.lines() {
        let v: Value = serde_json::from_str(line).unwrap();
        if let Some(u) = v["leaf_entry"]["user_id"].as_str() {
            assert_eq!(u, alice_id);
        }
        if v["kind"] != "HEADS" && v["kind"] != "RUNTIME_CLOSED" {
            assert!(v.get("body").is_none(), "{line}");
        }
    }
    assert!(!text.contains("carol"));
    // README names every file's hash and the exact command.
    let readme = std::fs::read_to_string(dir.join("README.txt")).unwrap();
    assert!(readme.contains(cmd), "{readme}");
    // Downloaded: the directory is gone and the job answers 410.
    assert!(!h.state.exports.job_dir(&id).exists());
    let (job, _) = h.state.exports.get(&alice_id, &id).unwrap();
    assert_eq!(job.state, STATE_DOWNLOADED);
    let res = h
        .get_raw(&alice, &format!("/api/me/audit/exports/{id}/download"))
        .await;
    assert_eq!(
        code(res).await,
        (StatusCode::GONE, "audit/export_expired".into())
    );
    // The own export left an EXPORT record in alice's chain.
    let rt = h
        .registry
        .runtime(&UserCtx::from_authenticated(&alice_id))
        .await
        .unwrap();
    assert!(
        h.chain_kinds(&rt)
            .iter()
            .any(|(k, _)| *k == atlas_duck_audit::EventType::EXPORT)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_auditor_export_is_recorded_and_only_the_auditor_can_poll_it() {
    let h = H::new();
    let vera = h.session("vera", "pw-vera").await;
    let alice = h.session("alice", PW_CANARY).await;
    h.kinds_of_user("alice").await;
    let alice_id = user_id_for("alice");
    // Alice's runtime closed: the auditor export goes through a view without a core.
    h.registry.close_all().await;
    let base = format!("/api/auditor/users/{alice_id}/exports");
    let done = h.export_done(&vera, &base).await;
    assert_eq!(done["state"], STATE_DONE, "{done}");
    let id = done["job_id"].as_str().unwrap().to_owned();
    // Vera's chain: AUDITOR_READ {action: export, job_id}; the anchor op-log has its row.
    let reads: Vec<Value> = h
        .kinds_of_user("vera")
        .await
        .into_iter()
        .filter(|(k, _)| *k == atlas_duck_audit::EventType::AUDITOR_READ)
        .map(|(_, p)| p)
        .collect();
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert_eq!(reads[0]["action"], "export");
    assert_eq!(reads[0]["job_id"], id.as_str());
    assert_eq!(reads[0]["target_user_id"], alice_id.as_str());
    assert!(
        h.store
            .anchor_all()
            .unwrap()
            .iter()
            .any(|r| r.kind == "AUDITOR_READ")
    );
    // Alice's chain gained the EXPORT.
    let kinds = h.kinds_of_user("alice").await;
    assert!(
        kinds
            .iter()
            .any(|(k, _)| *k == atlas_duck_audit::EventType::EXPORT)
    );
    // Alice cannot poll or download the auditor's job, by either route.
    for path in [
        format!("/api/me/audit/exports/{id}"),
        format!("/api/me/audit/exports/{id}/download"),
    ] {
        let res = h.get_raw(&alice, &path).await;
        assert_eq!(
            code(res).await,
            (StatusCode::NOT_FOUND, "audit/export_unknown".into())
        );
    }
    let res = h.get_raw(&alice, &format!("{base}/{id}")).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    // The auditor's job is not reachable under another target.
    let other = format!("/api/auditor/users/{}/exports/{id}", user_id_for("carol"));
    let res = h.get_raw(&vera, &other).await;
    assert_eq!(
        code(res).await,
        (StatusCode::NOT_FOUND, "audit/export_unknown".into())
    );
    // Unknown and malformed ids.
    for bad in ["0".repeat(32), "nope".into(), "../x".into()] {
        let res = h.get_raw(&vera, &format!("{base}/{bad}")).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{bad}");
    }
    // Final review m1: the download is an auditor read too, recorded before the bytes.
    let res = h.get_raw(&vera, &format!("{base}/{id}/download")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let reads: Vec<Value> = h
        .kinds_of_user("vera")
        .await
        .into_iter()
        .filter(|(k, _)| *k == atlas_duck_audit::EventType::AUDITOR_READ)
        .map(|(_, p)| p)
        .collect();
    assert_eq!(reads.len(), 2, "{reads:?}");
    assert_eq!(reads[1]["action"], "export");
    assert_eq!(reads[1]["job_id"], id.as_str());
    // Final review m1: without the auditor role (a session after it was withdrawn) the job is
    // out of reach by every route.
    use secrecy::ExposeSecret;
    let plain = h
        .state
        .0
        .sessions
        .create(&user_id_for("vera"), vec!["user".into()])
        .unwrap();
    let plain = (
        plain.cookie_id.expose_secret().to_owned(),
        plain.session.csrf_token.expose_secret().to_owned(),
    );
    for path in [
        format!("/api/me/audit/exports/{id}"),
        format!("/api/me/audit/exports/{id}/download"),
        format!("{base}/{id}"),
        format!("{base}/{id}/download"),
    ] {
        let res = h.get_raw(&plain, &path).await;
        assert!(
            matches!(res.status(), StatusCode::FORBIDDEN | StatusCode::NOT_FOUND),
            "{path}: {}",
            res.status()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrency_is_capped_per_target_and_server_wide() {
    let h = H::new();
    let alice = h.session("alice", PW_CANARY).await;
    h.kinds_of_user("alice").await;
    let alice_id = user_id_for("alice");
    let held = h.state.exports.reserve(&alice_id, &alice_id).unwrap();
    let res = h
        .post_json(&alice, "/api/me/audit/exports", json!({}))
        .await;
    assert_eq!(
        code(res).await,
        (StatusCode::CONFLICT, "audit/export_busy".into())
    );
    // A second slot (another target) fills the default cap of 2.
    let other = h.state.exports.reserve(&alice_id, "x").unwrap();
    let vera = h.session("vera", "pw-vera").await;
    let res = h
        .post_json(
            &vera,
            &format!("/api/auditor/users/{alice_id}/exports"),
            json!({}),
        )
        .await;
    assert_eq!(
        code(res).await,
        (StatusCode::CONFLICT, "audit/export_busy".into())
    );
    // Refused before anything was recorded.
    assert!(
        !h.kinds_of_user("vera")
            .await
            .iter()
            .any(|(k, _)| *k == atlas_duck_audit::EventType::AUDITOR_READ)
    );
    drop((held, other));
    assert_eq!(h.state.exports.running_count(), 0);
    // A bad body is refused.
    for bad in [
        json!({"to_utc": "x"}),
        json!({"from_utc": "yesterday"}),
        json!([1]),
    ] {
        let res = h.post_json(&alice, "/api/me/audit/exports", bad).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_ttl_sweep_removes_expired_jobs_and_leftovers() {
    let h = H::new();
    let alice = h.session("alice", PW_CANARY).await;
    h.kinds_of_user("alice").await;
    let alice_id = user_id_for("alice");
    let done = h.export_done(&alice, "/api/me/audit/exports").await;
    let id = done["job_id"].as_str().unwrap().to_owned();
    let dir = h.state.exports.job_dir(&id);
    assert!(dir.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let inner = dir.join(done["file_name"].as_str().unwrap());
        for f in ARCHIVE_FILES {
            let mode = std::fs::metadata(inner.join(f))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{f}");
        }
    }
    // Within the TTL nothing goes; an orphan directory does.
    let orphan = dir.parent().unwrap().join("f".repeat(32));
    std::fs::create_dir_all(&orphan).unwrap();
    assert_eq!(h.state.exports.sweep(false), 1);
    assert!(dir.is_dir() && !orphan.exists());
    // After the TTL the job and its directory go.
    h.clock
        .advance(crate::export_job::ExportConfig::DEFAULT.ttl_secs);
    h.state.exports.sweep(false);
    assert!(!dir.exists());
    // (The session expired with the TTL; the job is asked for directly.)
    assert_eq!(
        h.state.exports.get(&alice_id, &id).unwrap_err(),
        ApiError::EXPORT_UNKNOWN
    );
    // A job a previous process left running fails at start-up and its directory goes.
    let left = crate::store::ExportJobRecord {
        job_id: "e".repeat(32),
        requester_user_id: alice_id.clone(),
        target_user_id: alice_id.clone(),
        state: "running".into(),
        created_at: h.clock.now(),
        expires_at: h.clock.now() + 3600,
        manifest_sha256: None,
        size: None,
        file_name: None,
        anchor_seq: None,
        anchor_hash: None,
    };
    h.store.export_job_insert(&left).unwrap();
    std::fs::create_dir_all(h.state.exports.job_dir(&left.job_id)).unwrap();
    assert_eq!(h.state.exports.sweep(true), 1);
    let (job, _) = h.state.exports.get(&alice_id, &left.job_id).unwrap();
    assert_eq!(job.state, STATE_FAILED);
    assert!(!h.state.exports.job_dir(&left.job_id).exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_anchor_head_route_answers_the_last_row() {
    let h = H::new();
    let alice = h.session("alice", PW_CANARY).await;
    h.kinds_of_user("alice").await;
    let done = h.export_done(&alice, "/api/me/audit/exports").await;
    let res = h.get_raw(&alice, "/api/anchor/head").await;
    assert_eq!(res.status(), StatusCode::OK);
    let v = json_body(res).await;
    let (seq, hash) = crate::anchor::head(h.store.as_ref()).unwrap().unwrap();
    assert_eq!(v, json!({"seq": seq, "hash": hex::encode(hash)}));
    assert!(seq >= done["anchor_head"]["seq"].as_u64().unwrap());
    // No session: 401; a bearer: refused.
    let res = h
        .send(
            Request::builder()
                .uri("/api/anchor/head")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = h
        .send(
            Request::builder()
                .uri("/api/anchor/head")
                .header(header::AUTHORIZATION, "Bearer adk_x")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        code(res).await,
        (StatusCode::FORBIDDEN, "auth/bearer_not_accepted".into())
    );
}
