#![cfg(feature = "testing")]
//! Credentials and instances (Task 25): https only (I-02), origin confirmation (I-31), the
//! connection test (X-10, I-30 setup half), install-scoped PAT entries (I-43 PAT half), the
//! PD-05 blob, and a base-URL change reaching queued writes.

mod common;

use std::sync::Arc;
use std::time::Duration;

use atlas_duck_atlassian::testing::{
    MockDc, TEST_PAT, TEST_USER, TEST_USER_KEY, TestTlsServer, XAuser, fixtures, generate_ca_pem,
};
use atlas_duck_atlassian::{
    CredentialError, CredentialProvider, PatSecret, StoredCredential, StoredIdentity, UrlHash,
    normalize_base_url,
};
use atlas_duck_audit::testing::{MemKeyStore, MemKeyring};
use atlas_duck_audit::{Confirmed, EntryName, EventType, KeyStore, SettingChange};
use atlas_duck_core::audit_port::DateBridge;
use atlas_duck_core::config::load_config;
use atlas_duck_core::instances::state::ca_fingerprint;
use atlas_duck_core::proxy::{OsProxy, ProxySetting, SystemProxySource};
use atlas_duck_core::testing::capture::NullUi;
use atlas_duck_core::testing::{Harness, InstanceAt, StubConfirmer, TempStore};
use atlas_duck_core::{
    AddInstance, AdminError, Confirm, ConnectionFailure, Core, CoreDeps, KeychainCredentials,
    TestHooks,
};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_registry::Product;
use common::{TestResult, code, detail, exit, json, request_id};
use secrecy::SecretString;
use serde_json::{Map, Value, json as j};

fn pat(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn atl(p: Product) -> atlas_duck_atlassian::Product {
    match p {
        Product::Jira => atlas_duck_atlassian::Product::Jira,
        Product::Confluence => atlas_duck_atlassian::Product::Confluence,
    }
}

fn add(alias: &str, base_url: &str) -> AddInstance {
    AddInstance {
        alias: alias.to_owned(),
        product: Product::Jira,
        base_url: base_url.to_owned(),
        proxy: ProxySetting::Os,
        ca_pem: None,
        is_default: false,
    }
}

/// A Jira mock that answers the connection test as `user`.
async fn jira_answers(mock: &MockDc, user: &str, key: &str, version: &str) {
    mock.jira_myself(user, key, XAuser::Same).await;
    mock.jira_server_info(version).await;
}

fn instance_id(h: &Harness, alias: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(h.instance(alias).ok_or("no instance")?.id.clone())
}

fn state_of(h: &Harness, alias: &str) -> Result<String, Box<dyn std::error::Error>> {
    h.instances()
        .list()
        .into_iter()
        .find(|i| i.alias == alias)
        .map(|i| i.state.to_owned())
        .ok_or_else(|| "no such alias".into())
}

/// The `CONFIG_CHANGED {source: file}` records, in order.
async fn file_side(h: &Harness) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    Ok(h.events_of(EventType::CONFIG_CHANGED)
        .await?
        .into_iter()
        .filter(|e| e["source"] == "file")
        .collect())
}

async fn no_traffic(mock: &MockDc) -> bool {
    mock.received().await.is_empty()
}

// ---- I-02: https only ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i02_add_http_instance_refused() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .strict_https()
        .start()
        .await?;
    let mock = h.mock("jira-main").ok_or("mock")?;
    let before = h.events_of(EventType::CONFIG_CHANGED).await?.len();
    let res = h.instances().add(add("second", &mock.base_url()));
    assert_eq!(res.err(), Some(AdminError::InsecureScheme));
    assert!(h.confirmer().texts().is_empty(), "no dialog for http");
    assert_eq!(h.events_of(EventType::CONFIG_CHANGED).await?.len(), before);
    assert_eq!(h.instances().list().len(), 1);
    assert!(no_traffic(mock).await);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i02_config_http_instance_insecure_scheme() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .strict_https()
        .start()
        .await?;
    let list = json(&h.handler().instances_list().await)?;
    assert_eq!(list["data"]["instances"][0]["state"], "insecure_scheme");
    let env = h.submit("jira.issue.get", j!({ "key": "ABC-1" })).await;
    assert_eq!(env.status, Status::Failed);
    assert_eq!(exit(&env), 9);
    assert_eq!(code(&env), "not_configured");
    assert_eq!(detail(&env, "reason"), j!("insecure_scheme"));
    let file = file_side(&h).await?;
    assert_eq!(file.len(), 1, "{file:?}");
    let id = instance_id(&h, "jira-main")?;
    assert_eq!(file[0]["applied"], false);
    assert_eq!(file[0]["key"], j!(format!("instance.{id}.origin")));
    assert_eq!(file[0]["old"], Value::Null);
    let mock = h.mock("jira-main").ok_or("mock")?;
    assert!(no_traffic(mock).await);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i02_connection_test_refuses_http() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .strict_https()
        .start()
        .await?;
    let res = h
        .instances()
        .set_token("jira-main", pat(TEST_PAT), None)
        .await;
    assert_eq!(res.err(), Some(AdminError::InsecureScheme));
    assert!(no_traffic(h.mock("jira-main").ok_or("mock")?).await);
    Ok(())
}

// ---- I-31: the audit log decides what an instance is ----------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_config_url_edit_not_applied() -> TestResult {
    let mut h = Harness::jira().await?;
    let id = instance_id(&h, "jira-main")?;
    let first = h.mock("jira-main").ok_or("mock")?;
    first
        .json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    let first_url = first.base_url();
    let second = MockDc::start(atl(Product::Jira), "/jira").await;
    let path = h.config_path();
    let text = std::fs::read_to_string(&path)?;
    std::fs::write(&path, text.replace(&first_url, &second.base_url()))?;
    h.restart().await?;
    // Requests still go to the first mock; the PAT and the state are unchanged.
    assert_eq!(state_of(&h, "jira-main")?, "ok");
    assert!(h.credentials().contains(&id));
    let env = h.submit("jira.issue.get", j!({ "key": "ABC-1" })).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let rid = request_id(&env)?;
    h.queued(&rid, 10_000).await.ok_or("never queued")?;
    assert!(
        !h.mock("jira-main")
            .ok_or("mock")?
            .received()
            .await
            .is_empty()
    );
    assert!(no_traffic(&second).await);
    // The edit is logged, not applied; the window says what the file asks for.
    let file = file_side(&h).await?;
    assert_eq!(file.len(), 1, "{file:?}");
    assert_eq!(file[0]["applied"], false);
    assert_eq!(file[0]["key"], j!(format!("instance.{id}.origin")));
    assert_eq!(file[0]["old"], j!(first_url));
    assert_eq!(file[0]["new"], j!(second.base_url()));
    let view = h.instances().list().remove(0);
    assert_eq!(view.pending_url_change, Some(second.base_url()));
    assert_eq!(view.origin, Some(first_url));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_config_only_instance_unconfirmed() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .unconfirmed()
        .start()
        .await?;
    assert_eq!(state_of(&h, "jira-main")?, "instance_unconfirmed");
    let res = h
        .instances()
        .set_token("jira-main", pat(TEST_PAT), None)
        .await;
    assert_eq!(res.err(), Some(AdminError::Unconfirmed));
    assert!(no_traffic(h.mock("jira-main").ok_or("mock")?).await);
    // Confirming it through the native dialog makes it usable.
    h.confirmer().push(Confirm::Ok);
    let view = h.instances().confirm_config_instance("jira-main")?;
    // The harness keychain holds a token for it: confirmed, it is usable.
    assert_eq!(view.state, "ok");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_add_requires_confirmation() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Cancel])
        .start()
        .await?;
    let second = MockDc::start(atl(Product::Jira), "/other").await;
    let before = std::fs::read_to_string(h.config_path())?;
    let res = h.instances().add(add("second", &second.base_url()));
    assert_eq!(res.err(), Some(AdminError::Cancelled));
    assert_eq!(std::fs::read_to_string(h.config_path())?, before);
    assert_eq!(h.instances().list().len(), 1);
    h.confirmer().push(Confirm::Ok);
    let view = h.instances().add(add("second", &second.base_url()))?;
    assert_eq!(view.alias, "second");
    assert_eq!(view.state, "needs_token");
    assert_eq!(view.origin, Some(second.base_url()));
    let texts = h.confirmer().texts();
    let text = texts.last().ok_or("no dialog")?;
    assert!(
        text.contains("\"second\"") && text.contains(&second.base_url()),
        "{text}"
    );
    assert!(text.starts_with("Add Jira instance"), "{text}");
    assert_eq!(h.instances().list().len(), 2);
    assert!(std::fs::read_to_string(h.config_path())?.contains("second"));
    // The origin is confirmed in the audit settings, not only in the file.
    let cfg = load_config(&h.config_path())?;
    assert_eq!(
        atlas_duck_core::config::instances::instances(&cfg)?.len(),
        2
    );
    let settings = h.store().settings();
    assert!(
        settings
            .instances
            .values()
            .any(|p| p.origin.as_deref() == Some(second.base_url().as_str())),
        "{settings:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_url_change_requires_confirmation() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Cancel])
        .start()
        .await?;
    let id = instance_id(&h, "jira-main")?;
    let first = h.mock("jira-main").ok_or("mock")?.base_url();
    let second = MockDc::start(atl(Product::Jira), "/moved").await;
    let res = h
        .instances()
        .change_base_url("jira-main", &second.base_url());
    assert_eq!(res.err(), Some(AdminError::Cancelled));
    assert_eq!(state_of(&h, "jira-main")?, "ok");
    assert!(h.credentials().contains(&id));
    assert_eq!(h.instances().list()[0].origin, Some(first.clone()));
    h.confirmer().push(Confirm::Ok);
    let view = h
        .instances()
        .change_base_url("jira-main", &second.base_url())?;
    assert_eq!(view.state, "needs_token");
    assert_eq!(view.origin, Some(second.base_url()));
    assert!(!h.credentials().contains(&id));
    let text = h.confirmer().texts().last().cloned().ok_or("no dialog")?;
    assert!(
        text.starts_with(&format!(
            "Change \"jira-main\" from {first} to {}? The stored token will be deleted.",
            second.base_url()
        )),
        "{text}"
    );
    assert!(text.contains("is a loopback address"), "{text}");
    let changed = h.events_of(EventType::CREDENTIAL_CHANGED).await?;
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0]["change"], "deleted");
    assert_eq!(changed[0]["old_user_key"], TEST_USER_KEY);
    assert_eq!(changed[0]["new_user_key"], Value::Null);
    Ok(())
}

// ---- X-10, I-30 (setup half): the connection test ---------------------------------------------

async fn jira_without_pat() -> Result<Harness, Box<dyn std::error::Error>> {
    let h = Harness::jira().await?;
    let id = instance_id(&h, "jira-main")?;
    h.credentials().delete(&id)?;
    Ok(h)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x10_jira_below_8_14_refused() -> TestResult {
    let h = jira_without_pat().await?;
    jira_answers(
        h.mock("jira-main").ok_or("mock")?,
        TEST_USER,
        TEST_USER_KEY,
        "8.13.0",
    )
    .await;
    let res = h
        .instances()
        .set_token("jira-main", pat(TEST_PAT), None)
        .await;
    assert_eq!(
        res.err(),
        Some(AdminError::ConnectionFailed(
            ConnectionFailure::VersionBelowFloor
        ))
    );
    let id = instance_id(&h, "jira-main")?;
    assert!(!h.credentials().contains(&id));
    assert!(h.events_of(EventType::CREDENTIAL_CHANGED).await?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x10_confluence_below_7_9_refused() -> TestResult {
    let h = Harness::confluence().await?;
    let id = instance_id(&h, "wiki")?;
    h.credentials().delete(&id)?;
    let mock = h.mock("wiki").ok_or("mock")?;
    mock.confluence_user_current(
        atlas_duck_atlassian::testing::UserKind::Known,
        TEST_USER,
        TEST_USER_KEY,
    )
    .await;
    mock.applinks_manifest("7.8.0").await;
    let res = h.instances().set_token("wiki", pat(TEST_PAT), None).await;
    assert_eq!(
        res.err(),
        Some(AdminError::ConnectionFailed(
            ConnectionFailure::VersionBelowFloor
        ))
    );
    assert!(!h.credentials().contains(&id));
    assert!(h.events_of(EventType::CREDENTIAL_CHANGED).await?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confluence_manifest_not_json_is_version_unknown() -> TestResult {
    let h = Harness::confluence().await?;
    let id = instance_id(&h, "wiki")?;
    h.credentials().delete(&id)?;
    let mock = h.mock("wiki").ok_or("mock")?;
    mock.confluence_user_current(
        atlas_duck_atlassian::testing::UserKind::Known,
        TEST_USER,
        TEST_USER_KEY,
    )
    .await;
    mock.html("/rest/applinks/1.0/manifest", 200).await;
    let report = h.instances().set_token("wiki", pat(TEST_PAT), None).await?;
    assert_eq!(report.atlassian_user, TEST_USER);
    assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    assert!(h.credentials().contains(&id));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i30_header_stripped_at_setup_no_token_stored() -> TestResult {
    let h = jira_without_pat().await?;
    let mock = h.mock("jira-main").ok_or("mock")?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Missing)
        .await;
    mock.jira_server_info("9.12.0").await;
    let res = h
        .instances()
        .set_token("jira-main", pat(TEST_PAT), None)
        .await;
    assert_eq!(
        res.err(),
        Some(AdminError::ConnectionFailed(
            ConnectionFailure::IdentityHeaderMissing
        ))
    );
    let id = instance_id(&h, "jira-main")?;
    assert!(!h.credentials().contains(&id));
    assert!(h.events_of(EventType::CREDENTIAL_CHANGED).await?.is_empty());
    // A header naming someone else is a mismatch.
    mock.server().reset().await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Other("mallory".into()))
        .await;
    let res = h
        .instances()
        .set_token("jira-main", pat(TEST_PAT), None)
        .await;
    assert_eq!(
        res.err(),
        Some(AdminError::ConnectionFailed(
            ConnectionFailure::IdentityHeaderMismatch
        ))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_test_logs_system_fetch() -> TestResult {
    let h = jira_without_pat().await?;
    let mock = h.mock("jira-main").ok_or("mock")?;
    jira_answers(mock, TEST_USER, TEST_USER_KEY, "9.12.0").await;
    let report = h
        .instances()
        .set_token("jira-main", pat("fresh-pat"), None)
        .await?;
    assert_eq!(report.atlassian_user, TEST_USER);
    assert_eq!(report.version, "9.12.0");
    assert!(report.warnings.is_empty());
    let fetches = h.events_of(EventType::SYSTEM_FETCH).await?;
    let phases: Vec<&str> = fetches.iter().filter_map(|f| f["phase"].as_str()).collect();
    assert_eq!(phases, ["start", "result", "result"], "{fetches:?}");
    assert!(fetches.iter().all(|f| f["purpose"] == "connection_test"));
    assert_eq!(fetches[0]["planned"].as_array().map(Vec::len), Some(2));
    let paths: Vec<&str> = fetches[1..]
        .iter()
        .filter_map(|f| f["path"].as_str())
        .collect();
    assert!(
        paths[0].ends_with("/rest/api/2/myself") && paths[1].ends_with("/rest/api/2/serverInfo")
    );
    let changed = h.events_of(EventType::CREDENTIAL_CHANGED).await?;
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0]["change"], "added");
    assert_eq!(changed[0]["new_user_key"], TEST_USER_KEY);
    // The token is stored, bound to the origin, with the identity the test found.
    let id = instance_id(&h, "jira-main")?;
    let stored = h.credentials().load(&id)?.ok_or("not stored")?;
    assert_eq!(stored.pat.expose_secret(), "fresh-pat");
    assert_eq!(stored.identity.atlassian_user_key, TEST_USER_KEY);
    assert_eq!(state_of(&h, "jira-main")?, "ok");
    // The start record commits before the first request: with that append failing, nothing is
    // sent at all.
    let h = jira_without_pat().await?;
    let mock = h.mock("jira-main").ok_or("mock")?;
    jira_answers(mock, TEST_USER, TEST_USER_KEY, "9.12.0").await;
    h.plan().fail_nth(EventType::SYSTEM_FETCH, 1);
    let res = h
        .instances()
        .set_token("jira-main", pat("fresh-pat"), None)
        .await;
    assert!(matches!(res, Err(AdminError::Audit(_))), "{res:?}");
    assert!(no_traffic(mock).await);
    Ok(())
}

// ---- I-43 (PAT half): entries are scoped by install -------------------------------------------

/// One install: its own store and audit settings, a `KeychainCredentials` over the shared ring.
struct Install {
    core: Core,
    keys: Arc<MemKeyStore>,
    _store: TempStore,
}

async fn install(
    ring: &Arc<MemKeyring>,
    config_path: &std::path::Path,
    id: &str,
    origin: &str,
) -> Result<Install, Box<dyn std::error::Error>> {
    let store = TempStore::with_ring(ring.clone())?;
    let keys = Arc::new(MemKeyStore::new(ring.clone(), store.install_id()));
    store.store().apply_setting(
        SettingChange::InstanceOrigin {
            instance_id: id.to_owned(),
            origin: Some(
                normalize_base_url(origin)
                    .map_err(|e| format!("{e:?}"))?
                    .as_str(),
            ),
        },
        Some(Confirmed {
            dialog_text_sha256: [1; 32],
        }),
    )?;
    let creds = Arc::new(KeychainCredentials::new(keys.clone()));
    let port = store.port();
    let http = atlas_duck_core::http_factory::HttpFactory::new(
        Arc::new(SystemProxySource::with_reader(Box::new(OsProxy::default))),
        creds.clone(),
        Arc::new(DateBridge(port.clone())),
    );
    let deps = CoreDeps {
        audit: store.store(),
        clock: store.clock().clone(),
        credentials: creds,
        confirmer: Arc::new(StubConfirmer::new(Vec::new())),
        ui: Arc::new(NullUi),
        config: load_config(config_path)?,
        config_path: Some(config_path.to_owned()),
        http,
        app_start_extra: Map::new(),
        pats_deleted: Vec::new(),
    };
    let hooks = TestHooks {
        allow_http: true,
        ..TestHooks::none()
    };
    let core = Core::start_with_port(deps, port, hooks).await?;
    Ok(Install {
        core,
        keys,
        _store: store,
    })
}

fn state_in(i: &Install) -> Result<String, Box<dyn std::error::Error>> {
    i.core
        .instances()
        .list()
        .into_iter()
        .next()
        .map(|v| v.state.to_owned())
        .ok_or_else(|| "no instance".into())
}

const SHARED_ID: &str = "ins_0123456789abcdef0123456789abcdef";

async fn shared_setup()
-> Result<(Arc<MemKeyring>, MockDc, tempfile::TempDir), Box<dyn std::error::Error>> {
    let ring = MemKeyring::new();
    let mock = MockDc::start(atl(Product::Jira), "/jira").await;
    jira_answers(&mock, TEST_USER, TEST_USER_KEY, "9.12.0").await;
    let dir = tempfile::tempdir()?;
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "schema_version = 1\n\n[[instances]]\nid = \"{SHARED_ID}\"\nalias = \"j\"\nproduct = \"jira\"\nbase_url = \"{}\"\ndefault = true\n",
            mock.base_url()
        ),
    )?;
    Ok((ring, mock, dir))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i43_pat_entries_install_scoped() -> TestResult {
    let (ring, mock, dir) = shared_setup().await?;
    let path = dir.path().join("config.toml");
    let a = install(&ring, &path, SHARED_ID, &mock.base_url()).await?;
    assert_eq!(state_in(&a)?, "needs_token");
    a.core
        .instances()
        .set_token("j", pat("pat-of-a"), None)
        .await?;
    assert_eq!(state_in(&a)?, "ok");
    let entry = EntryName::Pat(SHARED_ID.to_owned());
    let a_blob = a.keys.get(&entry)?.ok_or("A has no entry")?;
    // A second install on the same keychain and the same config file: its entry is its own.
    let b = install(&ring, &path, SHARED_ID, &mock.base_url()).await?;
    assert_eq!(state_in(&b)?, "needs_token");
    assert!(
        b.keys.get(&entry)?.is_none(),
        "B's keychain has no PAT of A's"
    );
    b.core
        .instances()
        .set_token("j", pat("pat-of-b"), None)
        .await?;
    assert_eq!(state_in(&b)?, "ok");
    let a_after = a.keys.get(&entry)?.ok_or("A lost its entry")?;
    assert_eq!(*a_blob, *a_after, "setting B's PAT leaves A's unchanged");
    assert_ne!(*a_after, *b.keys.get(&entry)?.ok_or("B has no entry")?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i43_pat_on_one_install_leaves_other_needs_token() -> TestResult {
    let (ring, mock, dir) = shared_setup().await?;
    let path = dir.path().join("config.toml");
    let a = install(&ring, &path, SHARED_ID, &mock.base_url()).await?;
    a.core
        .instances()
        .set_token("j", pat("pat-of-a"), None)
        .await?;
    let b = install(&ring, &path, SHARED_ID, &mock.base_url()).await?;
    assert_eq!(state_in(&a)?, "ok");
    assert_eq!(state_in(&b)?, "needs_token");
    Ok(())
}

// ---- PD-05 ---------------------------------------------------------------------------------

#[test]
fn blob_roundtrip_and_redaction() -> TestResult {
    let ring = MemKeyring::new();
    let keys = Arc::new(MemKeyStore::new(ring, "inst-a"));
    let creds = KeychainCredentials::new(keys.clone());
    let canary = "PATCANARY-0123456789";
    let expires = chrono::NaiveDate::from_ymd_opt(2027, 1, 31).ok_or("date")?;
    creds.store(
        "ins_x",
        StoredCredential {
            pat: PatSecret::new(canary.to_owned()),
            base_url_hash: UrlHash([7; 32]),
            identity: StoredIdentity {
                atlassian_user: "jdoe".to_owned(),
                atlassian_user_key: "JIRAUSER1".to_owned(),
            },
            expires_at: Some(expires),
        },
    )?;
    // The raw blob is the keychain's: it holds the PAT and the PD-05 fields.
    let raw = keys
        .get(&EntryName::Pat("ins_x".into()))?
        .ok_or("no entry")?;
    let text = std::str::from_utf8(&raw)?;
    assert!(text.contains(canary));
    let blob: Value = serde_json::from_str(text)?;
    assert_eq!(blob["v"], 1);
    assert_eq!(blob["expires_at"], "2027-01-31");
    assert_eq!(blob["url_hash"], UrlHash([7; 32]).to_hex());
    let loaded = creds.load("ins_x")?.ok_or("not loaded")?;
    assert_eq!(loaded.pat.expose_secret(), canary);
    assert_eq!(loaded.base_url_hash, UrlHash([7; 32]));
    assert_eq!(loaded.identity.atlassian_user, "jdoe");
    assert_eq!(loaded.identity.atlassian_user_key, "JIRAUSER1");
    assert_eq!(loaded.expires_at, Some(expires));
    // No Debug output of a loaded value names the PAT, the user or the key.
    for dbg in [
        format!("{loaded:?}"),
        format!("{:?}", loaded.pat),
        format!("{:?}", loaded.identity),
        format!("{creds:?}"),
    ] {
        assert!(
            !dbg.contains(canary) && !dbg.contains("jdoe") && !dbg.contains("JIRAUSER1"),
            "{dbg}"
        );
    }
    // An unknown version, a bad hash and an absent entry.
    keys.set(
        &EntryName::Pat("ins_y".into()),
        br#"{"v":2,"pat":"p","url_hash":"00","user":"u","user_key":"k","expires_at":null}"#,
    )?;
    assert!(matches!(creds.load("ins_y"), Err(CredentialError::Corrupt)));
    assert!(creds.load("ins_absent")?.is_none());
    creds.delete("ins_x")?;
    assert!(creds.load("ins_x")?.is_none());
    Ok(())
}

// ---- a base-URL change reaches queued writes (§7.1, I-31) -------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_url_change_marks_writes_then_new_token_refreshes() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let first = h.mock("jira-main").ok_or("mock")?;
    first
        .jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    let params = j!({ "key": "ABC-1", "body": "Reproduced.", "body_format": "wiki" });
    let env = h.submit("jira.comment.add", params).await;
    let id = request_id(&env)?;
    let item = h.queued(&id, 10_000).await.ok_or("never queued")?;
    assert!(item.approvable);
    let rev1 = item.candidate_rev.counter;
    let second = MockDc::start(atl(Product::Jira), "/moved").await;
    jira_answers(&second, TEST_USER, TEST_USER_KEY, "9.12.0").await;
    second
        .json(
            "/rest/api/2/issue/ABC-1/comment",
            201,
            fixtures::JIRA_COMMENT,
        )
        .await;
    h.instances()
        .change_base_url("jira-main", &second.base_url())?;
    let item = wait_rev_after(&h, &id, rev1).await?;
    assert!(!item.approvable, "not approvable until a PAT exists");
    let stale = h
        .events(&id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::WRITE_STALE)
        .map(|(_, p)| p["reason"].clone())
        .collect::<Vec<_>>();
    assert_eq!(stale, [j!("instance_changed")]);
    let preview = h.approver().open(&id).map_err(common::de)?.preview;
    let caution = preview
        .warnings
        .iter()
        .find(|w| format!("{:?}", w.id) == "InstanceUrlChanged")
        .ok_or("no instance_url_changed caution")?;
    assert_eq!(
        caution.text,
        format!(
            "instance URL changed: {} → {}",
            first.base_url(),
            second.base_url()
        )
    );
    // The new PAT is stored: the deferred refresh runs under it, then the write is approvable.
    h.instances()
        .set_token("jira-main", pat("new-pat"), None)
        .await?;
    let mut approvable = false;
    for _ in 0..200 {
        approvable = h.approver().item(&id).is_some_and(|i| i.approvable);
        if approvable {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(approvable, "refreshed under the new PAT");
    let item = h.approver().item(&id).ok_or("left the queue")?;
    assert!(item.candidate_rev.counter > rev1 && !item.opened);
    h.approver().approve(&id).map_err(common::de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let posts = second
        .received()
        .await
        .iter()
        .filter(|r| r.method.as_str() == "POST")
        .count();
    assert_eq!(posts, 1, "the write ran against the new origin");
    Ok(())
}

async fn wait_rev_after(
    h: &Harness,
    id: &str,
    after: u64,
) -> Result<atlas_duck_core::QueueItem, Box<dyn std::error::Error>> {
    for _ in 0..400 {
        if let Some(item) = h.approver().item(id)
            && item.candidate_rev.counter > after
        {
            return Ok(item);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err("the revision never advanced".into())
}

// ---- Task 25 fix round: pinned CA, fail-closed start, failure paths, dialog texts -------------

/// The `ca_bundle` path the harness wrote into `config.toml`.
fn ca_path_in(config: &std::path::Path) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(config)?;
    let line = text
        .lines()
        .find_map(|l| l.strip_prefix("ca_bundle = '"))
        .ok_or("no ca_bundle line")?;
    Ok(std::path::PathBuf::from(line.trim_end_matches('\'')))
}

/// One Jira instance at a TLS server, trusting `ca` (the server's own CA unless given).
async fn tls_harness(
    ca: Option<String>,
) -> Result<(Harness, TestTlsServer), Box<dyn std::error::Error>> {
    let tls = TestTlsServer::start().await?;
    let pem = ca.unwrap_or_else(|| tls.ca_pem().to_owned());
    let h = Harness::builder()
        .instance_at(
            "tls",
            Product::Jira,
            InstanceAt {
                base_url: tls.base_url(),
                proxy: None,
                ca_pem: Some(pem),
            },
        )
        .start()
        .await?;
    Ok((h, tls))
}

/// Submits a read and waits until the TLS server saw a handshake or the request settled (a read
/// that got through waits for its release, a refused one fails).
async fn read_settles(h: &Harness, tls: &TestTlsServer) -> TestResult {
    let env = h.submit("jira.issue.get", j!({ "key": "ABC-1" })).await;
    let id = request_id(&env)?;
    for _ in 0..400 {
        if tls.handshakes() > 0 || h.settled(&id, 25).await {
            return Ok(());
        }
    }
    Err("neither a handshake nor a result".into())
}

fn setting_of(h: &Harness, id: &str) -> Option<atlas_duck_audit::InstancePolicy> {
    h.store().settings().instances.get(id).cloned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_ca_swapped_after_start_uses_the_confirmed_bytes() -> TestResult {
    let (h, tls) = tls_harness(None).await?;
    // The file is replaced by another CA after the table was derived and before the client is
    // built (clients are built lazily, on the first request).
    std::fs::write(ca_path_in(&h.config_path())?, generate_ca_pem()?)?;
    read_settles(&h, &tls).await?;
    assert!(
        tls.handshakes() >= 1,
        "the confirmed CA bytes must still be trusted"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_ca_swapped_before_start_is_not_trusted() -> TestResult {
    let (mut h, tls) = tls_harness(None).await?;
    let id = instance_id(&h, "tls")?;
    let confirmed = setting_of(&h, &id)
        .and_then(|p| p.ca_fingerprint)
        .ok_or("no confirmed CA fingerprint")?;
    let other = generate_ca_pem()?;
    std::fs::write(ca_path_in(&h.config_path())?, &other)?;
    h.restart().await?;
    read_settles(&h, &tls).await?;
    assert_eq!(tls.handshakes(), 0, "an unconfirmed CA must not be trusted");
    let changes = file_side(&h).await?;
    let change = changes
        .iter()
        .find(|c| c["key"] == j!(format!("instance.{id}.ca_fingerprint")))
        .ok_or("no file-side CA record")?;
    assert_eq!(change["applied"], false);
    assert_eq!(change["old"], j!(confirmed));
    assert_eq!(change["new"], j!(ca_fingerprint(other.as_bytes())));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_ca_unreadable_at_start_is_never_trusted_later() -> TestResult {
    // The file names a CA that is not a certificate: nothing is confirmed for the instance.
    let tls = TestTlsServer::start().await?;
    let h = Harness::builder()
        .instance_at(
            "tls",
            Product::Jira,
            InstanceAt {
                base_url: tls.base_url(),
                proxy: None,
                ca_pem: Some("not a certificate".to_owned()),
            },
        )
        .start()
        .await?;
    let id = instance_id(&h, "tls")?;
    assert!(setting_of(&h, &id).is_none_or(|p| p.ca_fingerprint.is_none()));
    // The file becomes a valid CA (the server's own) after the start.
    std::fs::write(ca_path_in(&h.config_path())?, tls.ca_pem())?;
    read_settles(&h, &tls).await?;
    assert_eq!(tls.handshakes(), 0, "never confirmed, never trusted");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_file_side_ca_and_proxy_edits_not_applied() -> TestResult {
    let (mut h, tls) = tls_harness(None).await?;
    let id = instance_id(&h, "tls")?;
    let fp = setting_of(&h, &id)
        .and_then(|p| p.ca_fingerprint)
        .ok_or("no confirmed CA fingerprint")?;
    let config = h.config_path();
    let old_path = ca_path_in(&config)?;
    let other = generate_ca_pem()?;
    let other_path = old_path.with_file_name("other.pem");
    std::fs::write(&other_path, &other)?;
    let text = std::fs::read_to_string(&config)?
        .replace(
            old_path.to_string_lossy().as_ref(),
            other_path.to_string_lossy().as_ref(),
        )
        .replace("[[instances]]", "[[instances]]\nproxy = \"127.0.0.1:9\"");
    std::fs::write(&config, text)?;
    h.restart().await?;
    let changes = file_side(&h).await?;
    let ca = changes
        .iter()
        .find(|c| c["key"] == j!(format!("instance.{id}.ca_fingerprint")))
        .ok_or("no file-side CA record")?;
    assert_eq!((&ca["old"], &ca["applied"]), (&j!(fp), &j!(false)));
    assert_eq!(ca["new"], j!(ca_fingerprint(other.as_bytes())));
    let proxy = changes
        .iter()
        .find(|c| c["key"] == j!(format!("instance.{id}.proxy")))
        .ok_or("no file-side proxy record")?;
    assert_eq!(
        (&proxy["old"], &proxy["new"]),
        (&Value::Null, &j!("127.0.0.1:9"))
    );
    assert_eq!(proxy["applied"], false);
    // Not applied: the proxy in force is still the confirmed one, and the other CA is no trust.
    let view = h.instances().list().remove(0);
    assert_ne!(view.proxy_effective.as_deref(), Some("127.0.0.1:9"));
    read_settles(&h, &tls).await?;
    assert_eq!(tls.handshakes(), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_add_with_custom_ca_shows_subject_and_fingerprint() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok, Confirm::Ok])
        .start()
        .await?;
    let second = MockDc::start(atl(Product::Jira), "/other").await;
    let pem = generate_ca_pem()?;
    let fp = ca_fingerprint(pem.as_bytes()).ok_or("no fingerprint")?;
    let mut req = add("second", &second.base_url());
    req.ca_pem = Some(pem.clone().into_bytes());
    let view = h.instances().add(req)?;
    assert_eq!(view.state, "needs_token");
    let texts = h.confirmer().texts();
    let ca_dialog = texts.last().ok_or("no CA dialog")?;
    assert!(
        ca_dialog.starts_with("Trust the custom CA for \"second\""),
        "{ca_dialog}"
    );
    assert!(ca_dialog.contains(&fp), "{ca_dialog}");
    assert!(ca_dialog.contains("Subject: ") && ca_dialog.contains("atlas-duck other test CA"));
    assert!(
        ca_dialog.contains("Issuer: ") && ca_dialog.contains("Valid: "),
        "{ca_dialog}"
    );
    // Recorded as confirmed, and the file holds exactly the bytes that were confirmed.
    let id = h
        .store()
        .settings()
        .instances
        .iter()
        .find(|(_, p)| p.ca_fingerprint.is_some())
        .map(|(id, _)| id.clone())
        .ok_or("no CA setting")?;
    assert_eq!(setting_of(&h, &id).and_then(|p| p.ca_fingerprint), Some(fp));
    let file = h
        .config_path()
        .with_file_name("ca")
        .join(format!("{id}.pem"));
    assert_eq!(std::fs::read(file)?, pem.as_bytes());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_add_with_custom_ca_cancelled_or_invalid_changes_nothing() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok, Confirm::Cancel])
        .start()
        .await?;
    let second = MockDc::start(atl(Product::Jira), "/other").await;
    let before = std::fs::read_to_string(h.config_path())?;
    let mut req = add("second", &second.base_url());
    req.ca_pem = Some(generate_ca_pem()?.into_bytes());
    assert_eq!(h.instances().add(req).err(), Some(AdminError::Cancelled));
    assert_eq!(std::fs::read_to_string(h.config_path())?, before);
    assert!(
        h.store()
            .settings()
            .instances
            .values()
            .all(|p| p.ca_fingerprint.is_none())
    );
    // A bundle that is no certificate never reaches a dialog.
    let dialogs = h.confirmer().texts().len();
    let mut req = add("third", &second.base_url());
    req.ca_pem = Some(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_vec());
    assert!(matches!(h.instances().add(req), Err(AdminError::Audit(_))));
    assert_eq!(h.confirmer().texts().len(), dialogs);
    Ok(())
}

/// A hand-added instance at a TLS server whose file names the server's CA.
async fn unconfirmed_tls(
    answers: Vec<Confirm>,
) -> Result<(Harness, TestTlsServer, String), Box<dyn std::error::Error>> {
    let tls = TestTlsServer::start().await?;
    let h = Harness::builder()
        .instance_at(
            "tls",
            Product::Jira,
            InstanceAt {
                base_url: tls.base_url(),
                proxy: None,
                ca_pem: Some(tls.ca_pem().to_owned()),
            },
        )
        .unconfirmed()
        .confirm(answers)
        .start()
        .await?;
    let fp = ca_fingerprint(tls.ca_pem().as_bytes()).ok_or("no fingerprint")?;
    Ok((h, tls, fp))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_confirm_config_instance_confirms_the_file_ca() -> TestResult {
    let (h, tls, fp) = unconfirmed_tls(vec![Confirm::Ok, Confirm::Ok]).await?;
    let id = instance_id(&h, "tls")?;
    let view = h.instances().confirm_config_instance("tls")?;
    assert_eq!(view.state, "ok");
    assert_eq!(
        setting_of(&h, &id).and_then(|p| p.ca_fingerprint),
        Some(fp.clone())
    );
    let texts = h.confirmer().texts();
    assert!(texts.last().ok_or("no dialog")?.contains(&fp));
    // The confirmed CA is in force: the first request completes a handshake.
    read_settles(&h, &tls).await?;
    assert!(tls.handshakes() >= 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_confirm_config_instance_ca_cancelled_keeps_origin_and_trusts_no_ca() -> TestResult {
    let (h, tls, _) = unconfirmed_tls(vec![Confirm::Ok, Confirm::Cancel]).await?;
    let id = instance_id(&h, "tls")?;
    let res = h.instances().confirm_config_instance("tls");
    assert_eq!(res.err(), Some(AdminError::Cancelled));
    // The origin was confirmed and the table follows it; the CA stays unconfirmed.
    assert!(setting_of(&h, &id).is_some_and(|p| p.origin.is_some() && p.ca_fingerprint.is_none()));
    assert_eq!(state_of(&h, "tls")?, "ok");
    read_settles(&h, &tls).await?;
    assert_eq!(tls.handshakes(), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_set_proxy_writes_file_and_setting_without_a_dialog() -> TestResult {
    let h = Harness::jira().await?;
    let id = instance_id(&h, "jira-main")?;
    let view = h
        .instances()
        .set_proxy("jira-main", ProxySetting::parse("127.0.0.1:9")?)?;
    assert_eq!(view.proxy_effective.as_deref(), Some("127.0.0.1:9"));
    assert!(std::fs::read_to_string(h.config_path())?.contains("proxy = \"127.0.0.1:9\""));
    assert_eq!(
        setting_of(&h, &id).and_then(|p| p.proxy),
        Some("127.0.0.1:9".to_owned())
    );
    assert!(
        h.confirmer().texts().is_empty(),
        "a proxy is a plain setting"
    );
    let changed = h.events_of(EventType::CONFIG_CHANGED).await?;
    assert!(
        changed
            .iter()
            .any(|e| e["key"] == j!(format!("instance.{id}.proxy")) && e["applied"] == true),
        "{changed:?}"
    );
    // Back to direct, then to the OS setting.
    let view = h.instances().set_proxy("jira-main", ProxySetting::Direct)?;
    assert_eq!(view.proxy_effective.as_deref(), Some("direct"));
    assert_eq!(
        setting_of(&h, &id).and_then(|p| p.proxy),
        Some("direct".to_owned())
    );
    h.instances().set_proxy("jira-main", ProxySetting::Os)?;
    assert_eq!(setting_of(&h, &id).and_then(|p| p.proxy), None);
    assert!(!std::fs::read_to_string(h.config_path())?.contains("proxy ="));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i31_accept_config_url_change_applies_through_the_dialog() -> TestResult {
    let mut h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Cancel])
        .start()
        .await?;
    let id = instance_id(&h, "jira-main")?;
    let first = h.mock("jira-main").ok_or("mock")?.base_url();
    // Nothing is pending yet.
    assert_eq!(
        h.instances().accept_config_url_change("jira-main").err(),
        Some(AdminError::NotFound)
    );
    let second = MockDc::start(atl(Product::Jira), "/moved").await;
    let path = h.config_path();
    std::fs::write(
        &path,
        std::fs::read_to_string(&path)?.replace(&first, &second.base_url()),
    )?;
    h.restart().await?;
    assert_eq!(
        h.instances().list()[0].pending_url_change,
        Some(second.base_url())
    );
    // Cancel: nothing changes.
    assert_eq!(
        h.instances().accept_config_url_change("jira-main").err(),
        Some(AdminError::Cancelled)
    );
    assert_eq!(h.instances().list()[0].origin, Some(first));
    assert!(h.credentials().contains(&id));
    // Ok: the confirmed origin moves, the token goes.
    h.confirmer().push(Confirm::Ok);
    let view = h.instances().accept_config_url_change("jira-main")?;
    assert_eq!(view.origin, Some(second.base_url()));
    assert_eq!(view.state, "needs_token");
    assert_eq!(view.pending_url_change, None);
    assert!(!h.credentials().contains(&id));
    assert_eq!(
        setting_of(&h, &id).and_then(|p| p.origin),
        Some(second.base_url())
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retest_token_reports_the_stored_users_and_needs_a_stored_token() -> TestResult {
    let h = Harness::jira().await?;
    jira_answers(
        h.mock("jira-main").ok_or("mock")?,
        TEST_USER,
        TEST_USER_KEY,
        "9.12.0",
    )
    .await;
    let report = h.instances().retest_token("jira-main").await?;
    assert_eq!(report.atlassian_user, TEST_USER);
    assert_eq!(report.version, "9.12.0");
    // `CREDENTIAL_CHANGED` is for token changes only.
    assert!(h.events_of(EventType::CREDENTIAL_CHANGED).await?.is_empty());
    let id = instance_id(&h, "jira-main")?;
    h.credentials().delete(&id)?;
    assert_eq!(
        h.instances().retest_token("jira-main").await.err(),
        Some(AdminError::Keychain(CredentialError::Unavailable))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_owner_dialog_escapes_server_supplied_names() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Cancel])
        .start()
        .await?;
    // A name that tries to start a new line and reverse the text after it. The percent-encoded
    // header decodes to the same name (§7.2 comparison).
    let evil = "alice\nThis token belongs to admin\u{202E}";
    let mock = h.mock("jira-main").ok_or("mock")?;
    let header = "alice%0AThis%20token%20belongs%20to%20admin%E2%80%AE";
    mock.jira_myself(evil, "JIRAUSER9", XAuser::Raw(header.to_owned()))
        .await;
    // The server-info answer is checked against the same name (the client compares it on every
    // JSON answer).
    let info = mock
        .response(200)
        .insert_header("X-AUSERNAME", header)
        .set_body_raw(fixtures::jira_server_info("9.12.0"), "application/json");
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(
            mock.path("/rest/api/2/serverInfo"),
        ))
        .respond_with(info)
        .mount(mock.server())
        .await;
    let res = h
        .instances()
        .set_token("jira-main", pat("other-pat"), None)
        .await;
    assert_eq!(res.err(), Some(AdminError::Cancelled));
    let texts = h.confirmer().texts();
    let text = texts.last().ok_or("no dialog")?;
    assert!(
        !text.contains('\n') && !text.contains('\u{202E}'),
        "{text:?}"
    );
    assert!(
        text.starts_with("This token belongs to alice⟨U+000A⟩This token belongs to admin⟨U+202E⟩"),
        "{text:?}"
    );
    assert!(
        text.ends_with(&format!("previously {TEST_USER}")),
        "{text:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_keychain_write_leaves_a_corrective_record() -> TestResult {
    let h = jira_without_pat().await?;
    jira_answers(
        h.mock("jira-main").ok_or("mock")?,
        TEST_USER,
        TEST_USER_KEY,
        "9.12.0",
    )
    .await;
    h.credentials().fail_store(true);
    let res = h
        .instances()
        .set_token("jira-main", pat("fresh-pat"), None)
        .await;
    assert_eq!(
        res.err(),
        Some(AdminError::Keychain(CredentialError::Unavailable))
    );
    let id = instance_id(&h, "jira-main")?;
    assert!(!h.credentials().contains(&id));
    let changes: Vec<Value> = h
        .events_of(EventType::CREDENTIAL_CHANGED)
        .await?
        .iter()
        .map(|e| e["change"].clone())
        .collect();
    assert_eq!(changes, [j!("added"), j!("store_failed")]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn origin_change_with_a_failing_record_still_moves_the_runtime_and_the_writes() -> TestResult
{
    let h = Harness::builder()
        .jira("jira-main")
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let id = instance_id(&h, "jira-main")?;
    let first = h.mock("jira-main").ok_or("mock")?;
    first
        .jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    let params = j!({ "key": "ABC-1", "body": "Reproduced.", "body_format": "wiki" });
    let env = h.submit("jira.comment.add", params).await;
    let rid = request_id(&env)?;
    let item = h.queued(&rid, 10_000).await.ok_or("never queued")?;
    assert!(item.approvable);
    let second = MockDc::start(atl(Product::Jira), "/moved").await;
    // The record of the token deletion cannot be written, after the origin was committed.
    h.plan().fail_nth(EventType::CREDENTIAL_CHANGED, 1);
    let res = h
        .instances()
        .change_base_url("jira-main", &second.base_url());
    assert!(matches!(res, Err(AdminError::Audit(_))), "{res:?}");
    // The runtime follows the confirmed origin all the same: no token is used there, and the
    // queued write is not approvable (it waits for a new token).
    let view = h.instances().list().remove(0);
    assert_eq!(view.origin, Some(second.base_url()));
    assert_eq!(view.state, "needs_token");
    assert_eq!(
        setting_of(&h, &id).and_then(|p| p.origin),
        Some(second.base_url())
    );
    let item = wait_rev_after(&h, &rid, item.candidate_rev.counter).await?;
    assert!(!item.approvable);
    let stale: Vec<Value> = h
        .events(&rid)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::WRITE_STALE)
        .map(|(_, p)| p["reason"].clone())
        .collect();
    assert_eq!(stale, [j!("instance_changed")]);
    Ok(())
}

/// A keychain that panics on every read: the derivation of the table dies.
struct PanickingCreds;

impl CredentialProvider for PanickingCreds {
    fn load(&self, _: &str) -> Result<Option<StoredCredential>, CredentialError> {
        panic!("the credential backend failed")
    }
    fn store(&self, _: &str, _: StoredCredential) -> Result<(), CredentialError> {
        Err(CredentialError::Unavailable)
    }
    fn delete(&self, _: &str) -> Result<(), CredentialError> {
        Err(CredentialError::Unavailable)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_fails_closed_when_the_derivation_panics() -> TestResult {
    let (_ring, mock, dir) = shared_setup().await?;
    let path = dir.path().join("config.toml");
    let store = TempStore::new()?;
    store.store().apply_setting(
        SettingChange::InstanceOrigin {
            instance_id: SHARED_ID.to_owned(),
            origin: Some(
                normalize_base_url(&mock.base_url())
                    .map_err(|e| format!("{e:?}"))?
                    .as_str(),
            ),
        },
        Some(Confirmed {
            dialog_text_sha256: [1; 32],
        }),
    )?;
    let creds: Arc<dyn CredentialProvider> = Arc::new(PanickingCreds);
    let port = store.port();
    let http = atlas_duck_core::http_factory::HttpFactory::new(
        Arc::new(SystemProxySource::with_reader(Box::new(OsProxy::default))),
        creds.clone(),
        Arc::new(DateBridge(port.clone())),
    );
    let deps = CoreDeps {
        audit: store.store(),
        clock: store.clock().clone(),
        credentials: creds,
        confirmer: Arc::new(StubConfirmer::new(Vec::new())),
        ui: Arc::new(NullUi),
        config: load_config(&path)?,
        config_path: Some(path),
        http,
        app_start_extra: Map::new(),
        pats_deleted: Vec::new(),
    };
    let hooks = TestHooks {
        allow_http: true,
        ..TestHooks::none()
    };
    let core = Core::start_with_port(deps, port, hooks).await?;
    let view = core.instances().list().remove(0);
    assert_eq!(view.state, "instance_unconfirmed");
    assert_eq!(view.origin, None, "no origin is routable");
    assert_eq!(view.executes_as, None);
    assert!(no_traffic(&mock).await);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn url_password_in_config_toml_never_reaches_the_audit_log() -> TestResult {
    let mut h = Harness::jira().await?;
    let first = h.mock("jira-main").ok_or("mock")?.base_url();
    let path = h.config_path();
    std::fs::write(
        &path,
        std::fs::read_to_string(&path)?.replace(
            &first,
            "https://user:hunter2@jira.example/jira?token=hunter3#hunter4",
        ),
    )?;
    h.restart().await?;
    let file = file_side(&h).await?;
    assert_eq!(file.len(), 1, "{file:?}");
    let text = file[0].to_string();
    assert!(!text.contains("hunter"), "{text}");
    assert_eq!(file[0]["new"], j!("https://jira.example/jira"));
    // An address that cannot be accepted is not offered for acceptance either.
    assert_eq!(h.instances().list()[0].pending_url_change, None);
    let all = h.events_of(EventType::CONFIG_CHANGED).await?;
    assert!(
        all.iter().all(|e| !e.to_string().contains("hunter")),
        "{all:?}"
    );
    Ok(())
}
