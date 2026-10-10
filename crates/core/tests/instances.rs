#![cfg(feature = "testing")]
//! Credentials and instances (Task 25): https only (I-02), origin confirmation (I-31), the
//! connection test (X-10, I-30 setup half), install-scoped PAT entries (I-43 PAT half), the
//! PD-05 blob, and a base-URL change reaching queued writes.

mod common;

use std::sync::Arc;
use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, TEST_PAT, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use atlas_duck_atlassian::{
    CredentialError, CredentialProvider, PatSecret, StoredCredential, StoredIdentity, UrlHash,
    normalize_base_url,
};
use atlas_duck_audit::testing::{MemKeyStore, MemKeyring};
use atlas_duck_audit::{Confirmed, EntryName, EventType, KeyStore, SettingChange};
use atlas_duck_core::audit_port::DateBridge;
use atlas_duck_core::config::load_config;
use atlas_duck_core::proxy::{OsProxy, ProxySetting, SystemProxySource};
use atlas_duck_core::testing::capture::NullUi;
use atlas_duck_core::testing::{Harness, StubConfirmer, TempStore};
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
    assert_eq!(atlas_duck_core::config::instances::instances(&cfg)?.len(), 2);
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
