//! The connection test of the credential window (§7.1, §10.3, X-10, I-30 setup half).
//!
//! Two GETs under a `SYSTEM_FETCH {purpose: connection_test}` cover: the identity call (Jira
//! `GET /rest/api/2/myself`, Confluence `GET /rest/api/user/current`) and the version call (Jira
//! `GET /rest/api/2/serverInfo`, Confluence `GET /rest/applinks/1.0/manifest`). The start record
//! lists both and commits before the first request (audit before effect); every call gets its
//! own result record. A temporary `InstanceClient` holds the entered PAT in a provider of its
//! own, bound to the confirmed origin; nothing is stored here.
//!
//! Jira's client checks `X-AUSERNAME` against a stored name on every JSON answer, and the name
//! of the entered token is not known yet. The first call therefore runs with an empty stored
//! name, which the client always reports as `IdentityCheckFailed` carrying the whole answer; the
//! header is then compared here with the `name` of the body (`username_matches`). The second
//! call runs with the name found, so the client's own check applies to it.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use atlas_duck_atlassian::{
    CredentialError, CredentialProvider, FetchFailure, FetchOutcome, GetCall, IdentityObserved,
    NormalizedBaseUrl, PatSecret, StoredCredential, StoredIdentity, UnavailableReason,
    UpstreamResponse, UrlHash, url_hash, username_matches,
};
use atlas_duck_registry::{Product, Version};
use secrecy::ExposeSecret;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::{AdminError, ConnectionFailure, ConnectionReport};
use crate::audit_port::commit_system_fetch_start;
use crate::engine::Engine;
use crate::engine::write::system_get_record;
use crate::http_factory::InstanceHttpSpec;
use crate::ids::FetchId;
use crate::payloads::{self, SystemFetchPurpose};
use crate::proxy::ProxySetting;

/// §7.1 / X-10: the oldest supported server, and the first one that needs no warning.
const JIRA_FLOOR: Version = version(8, 14);
const JIRA_RECOMMENDED: Version = version(9, 12);
const CONFLUENCE_FLOOR: Version = version(7, 9);
const CONFLUENCE_RECOMMENDED: Version = version(8, 5);

const fn version(major: u32, minor: u32) -> Version {
    Version {
        major,
        minor,
        patch: 0,
    }
}

/// `"9.12.3"`, `"8.14"`, `"9.12.0-m0001"`: the leading numeric parts.
pub(crate) fn parse_version(s: &str) -> Option<Version> {
    let mut parts = s.trim().split('.');
    let number = |p: Option<&str>| -> Option<u32> {
        let p = p?;
        let digits: String = p.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    };
    let major = number(parts.next())?;
    let minor = number(parts.next())?;
    let patch = number(parts.next()).unwrap_or(0);
    Some(Version {
        major,
        minor,
        patch,
    })
}

/// What a connection test needs to know about the instance.
pub(crate) struct Target {
    pub id: String,
    pub product: Product,
    pub origin: NormalizedBaseUrl,
    pub proxy: ProxySetting,
    pub ca_bundle: Option<PathBuf>,
}

/// A passed test.
pub(crate) struct Tested {
    pub user: String,
    pub user_key: String,
    pub version: Option<Version>,
    pub report: ConnectionReport,
}

/// The entered PAT for one instance id; read-only.
struct OneEntry {
    id: String,
    pat: Zeroizing<String>,
    bound: UrlHash,
    identity: Mutex<StoredIdentity>,
}

impl CredentialProvider for OneEntry {
    fn load(&self, instance_id: &str) -> Result<Option<StoredCredential>, CredentialError> {
        if instance_id != self.id {
            return Ok(None);
        }
        let identity = self
            .identity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Ok(Some(StoredCredential {
            pat: PatSecret::new(self.pat.as_str().to_owned()),
            base_url_hash: self.bound,
            identity,
            expires_at: None,
        }))
    }

    fn store(&self, _: &str, _: StoredCredential) -> Result<(), CredentialError> {
        Err(CredentialError::Unavailable)
    }

    fn delete(&self, _: &str) -> Result<(), CredentialError> {
        Err(CredentialError::Unavailable)
    }
}

fn atlassian_product(p: Product) -> atlas_duck_atlassian::Product {
    match p {
        Product::Jira => atlas_duck_atlassian::Product::Jira,
        Product::Confluence => atlas_duck_atlassian::Product::Confluence,
    }
}

fn get(template: &str) -> GetCall {
    GetCall {
        endpoint_template: template.to_owned(),
        params: Value::Object(Map::new()),
        query: Vec::new(),
    }
}

fn json_of(r: &UpstreamResponse) -> Option<Value> {
    serde_json::from_slice(&r.body).ok()
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// The failure of a call that never produced a usable answer.
fn failure_of(f: &FetchFailure) -> ConnectionFailure {
    match f {
        FetchFailure::PreSendConnection(c) => {
            use atlas_duck_atlassian::ConnClass as C;
            match c {
                C::TlsHandshake | C::TlsUnknownIssuer | C::TlsCertificate => {
                    ConnectionFailure::Tls(*c)
                }
                C::ProxyConnect | C::ProxyConnect407 => ConnectionFailure::Proxy(*c),
                C::Dns | C::Connect | C::ConnectTimeout => ConnectionFailure::Network(*c),
            }
        }
        FetchFailure::StatusHeaderDecided {
            reason: UnavailableReason::NonJson401,
            ..
        } => ConnectionFailure::Http401,
        FetchFailure::IdentityCheckFailed { response, .. } if response.status == 401 => {
            ConnectionFailure::Http401
        }
        _ => ConnectionFailure::Unavailable,
    }
}

/// Jira's `/myself` answer: the user and the key, after the header check (I-30).
fn jira_identity(outcome: &FetchOutcome) -> Result<(String, String), ConnectionFailure> {
    let (observed, response) = match outcome {
        FetchOutcome::Failed(FetchFailure::IdentityCheckFailed { observed, response }) => {
            (observed, response)
        }
        FetchOutcome::Failed(f) => return Err(failure_of(f)),
        FetchOutcome::Response(r) if r.status == 401 => return Err(ConnectionFailure::Http401),
        // The client checks every JSON answer: one that got through cannot have matched an
        // empty stored name, so this is not a usable identity answer.
        FetchOutcome::Response(_) => return Err(ConnectionFailure::Unavailable),
    };
    if response.status == 401 {
        return Err(ConnectionFailure::Http401);
    }
    if response.status != 200 {
        return Err(ConnectionFailure::Unavailable);
    }
    let header = match observed {
        IdentityObserved::Missing => return Err(ConnectionFailure::IdentityHeaderMissing),
        IdentityObserved::Anonymous => return Err(ConnectionFailure::IdentityHeaderMismatch),
        IdentityObserved::Other(h) => h,
    };
    let body = json_of(response).ok_or(ConnectionFailure::Unavailable)?;
    let (Some(name), Some(key)) = (str_field(&body, "name"), str_field(&body, "key")) else {
        return Err(ConnectionFailure::Unavailable);
    };
    if username_matches(header, &name) {
        Ok((name, key))
    } else {
        Err(ConnectionFailure::IdentityHeaderMismatch)
    }
}

/// Confluence's `/user/current` answer: a known user, with its name and key.
fn confluence_identity(outcome: &FetchOutcome) -> Result<(String, String), ConnectionFailure> {
    let response = match outcome {
        FetchOutcome::Response(r) if r.status == 401 => return Err(ConnectionFailure::Http401),
        FetchOutcome::Response(r) if r.status == 200 => r,
        FetchOutcome::Response(_) => return Err(ConnectionFailure::Unavailable),
        FetchOutcome::Failed(f) => return Err(failure_of(f)),
    };
    let body = json_of(response).ok_or(ConnectionFailure::Unavailable)?;
    if body.get("type").and_then(Value::as_str) != Some("known") {
        return Err(ConnectionFailure::NotKnownUser);
    }
    match (str_field(&body, "username"), str_field(&body, "userKey")) {
        (Some(name), Some(key)) => Ok((name, key)),
        _ => Err(ConnectionFailure::NotKnownUser),
    }
}

/// The server version of the second call; `Ok(None)` for a manifest that is not JSON.
fn server_version(
    product: Product,
    outcome: &FetchOutcome,
) -> Result<Option<String>, ConnectionFailure> {
    match (product, outcome) {
        (
            Product::Confluence,
            FetchOutcome::Failed(FetchFailure::StatusHeaderDecided { reason, response }),
        ) if *reason == UnavailableReason::NonJson2xx && response.status == 200 => Ok(None),
        (_, FetchOutcome::Response(r)) if r.status == 200 => {
            let body = json_of(r).ok_or(ConnectionFailure::Unavailable)?;
            Ok(str_field(&body, "version"))
        }
        (_, FetchOutcome::Response(r)) if r.status == 401 => Err(ConnectionFailure::Http401),
        (_, FetchOutcome::Failed(f)) => Err(failure_of(f)),
        _ => Err(ConnectionFailure::Unavailable),
    }
}

/// §7.1 / X-10: below the floor refuses; below the recommended version warns.
fn judge_version(
    product: Product,
    text: Option<&str>,
) -> Result<(Option<Version>, Vec<String>), ConnectionFailure> {
    let (name, floor, recommended) = match product {
        Product::Jira => ("Jira", JIRA_FLOOR, JIRA_RECOMMENDED),
        Product::Confluence => ("Confluence", CONFLUENCE_FLOOR, CONFLUENCE_RECOMMENDED),
    };
    let Some(text) = text else {
        return Ok((
            None,
            vec![format!(
                "The {name} version could not be read; every operation stays available."
            )],
        ));
    };
    let Some(v) = parse_version(text) else {
        return Ok((
            None,
            vec![format!(
                "The {name} version \"{text}\" could not be read; every operation stays available."
            )],
        ));
    };
    if v < floor {
        return Err(ConnectionFailure::VersionBelowFloor);
    }
    let mut warnings = Vec::new();
    if v < recommended {
        warnings.push(format!(
            "{name} {}.{} or newer is recommended; this server reports {text}.",
            recommended.major, recommended.minor
        ));
    }
    Ok((Some(v), warnings))
}

/// Runs the test. `Err(AdminError::ConnectionFailed(..))` for a failed test, `Audit` when the
/// start record could not be committed (then nothing was sent).
pub(crate) async fn run(
    engine: &Arc<Engine>,
    target: &Target,
    pat: &secrecy::SecretString,
) -> Result<Tested, AdminError> {
    let (identity_path, version_path) = match target.product {
        Product::Jira => ("/rest/api/2/myself", "/rest/api/2/serverInfo"),
        Product::Confluence => ("/rest/api/user/current", "/rest/applinks/1.0/manifest"),
    };
    let fail = |f| AdminError::ConnectionFailed(f);
    let fetch_id = FetchId::new()
        .map_err(|_| AdminError::Audit(atlas_duck_audit::AuditError::Invalid("no randomness")))?
        .0;
    let purpose = SystemFetchPurpose::ConnectionTest;
    let planned = [("GET", identity_path), ("GET", version_path)];
    let start = payloads::system_fetch_start(purpose, &target.id, &fetch_id, &planned);
    let committed = engine.committed().clone();
    let fid = fetch_id.clone();
    engine
        .blocking(move |p| commit_system_fetch_start(p, &committed, start, &fid).map(|_| ()))
        .await
        .map_err(AdminError::Audit)?;
    let outcome = run_calls(engine, target, pat, &fetch_id, identity_path, version_path).await;
    engine.committed().forget_fetch(&fetch_id);
    match outcome? {
        Ok(tested) => Ok(tested),
        Err(f) => Err(fail(f)),
    }
}

/// The calls of the test; the outer `Err` is a store failure, the inner one the test's verdict.
async fn run_calls(
    engine: &Arc<Engine>,
    target: &Target,
    pat: &secrecy::SecretString,
    fetch_id: &str,
    identity_path: &str,
    version_path: &str,
) -> Result<Result<Tested, ConnectionFailure>, AdminError> {
    let purpose = SystemFetchPurpose::ConnectionTest;
    let covers_err = || AdminError::Audit(atlas_duck_audit::AuditError::Invalid("no audit cover"));
    let cover = engine
        .covers()
        .for_system_fetch(fetch_id)
        .map_err(|_| covers_err())?;
    let creds = Arc::new(OneEntry {
        id: target.id.clone(),
        pat: Zeroizing::new(pat.expose_secret().to_owned()),
        bound: url_hash(&target.origin),
        identity: Mutex::new(StoredIdentity {
            atlassian_user: String::new(),
            atlassian_user_key: String::new(),
        }),
    });
    // The proxy decision and the CA file read can block (T11 handoff).
    let spec = {
        let (path, proxy) = (target.ca_bundle.clone(), target.proxy.clone());
        let ca_pem = tokio::task::spawn_blocking(move || path.map(std::fs::read).transpose())
            .await
            .ok()
            .and_then(Result::ok);
        let Some(ca_pem) = ca_pem else {
            return Ok(Err(ConnectionFailure::Unavailable));
        };
        InstanceHttpSpec {
            instance_id: target.id.clone(),
            product: atlassian_product(target.product),
            base: target.origin.clone(),
            ca_pem,
            proxy,
        }
    };
    let built = {
        let (eng, creds) = (engine.clone(), creds.clone());
        tokio::task::spawn_blocking(move || eng.http().build_with(&spec, creds))
            .await
            .ok()
            .and_then(Result::ok)
    };
    let Some((client, _)) = built else {
        return Ok(Err(ConnectionFailure::Unavailable));
    };
    let append = |ev| async {
        engine
            .blocking(move |p| p.append(ev).map(|_| ()))
            .await
            .map_err(AdminError::Audit)
    };

    let call = get(identity_path);
    let outcome = client.get(&cover, &call).await;
    append(system_get_record(
        purpose,
        &target.id,
        fetch_id,
        &target.origin,
        &call,
        &outcome,
    ))
    .await?;
    let who = match target.product {
        Product::Jira => jira_identity(&outcome),
        Product::Confluence => confluence_identity(&outcome),
    };
    let (user, user_key) = match who {
        Ok(w) => w,
        Err(f) => return Ok(Err(f)),
    };
    *creds
        .identity
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = StoredIdentity {
        atlassian_user: user.clone(),
        atlassian_user_key: user_key.clone(),
    };

    let call = get(version_path);
    let outcome = client.get(&cover, &call).await;
    append(system_get_record(
        purpose,
        &target.id,
        fetch_id,
        &target.origin,
        &call,
        &outcome,
    ))
    .await?;
    let text = match server_version(target.product, &outcome) {
        Ok(t) => t,
        Err(f) => return Ok(Err(f)),
    };
    let (version, warnings) = match judge_version(target.product, text.as_deref()) {
        Ok(v) => v,
        Err(f) => return Ok(Err(f)),
    };
    let report = ConnectionReport {
        atlassian_user: user.clone(),
        product: target.product,
        version: text.unwrap_or_default(),
        warnings,
    };
    Ok(Ok(Tested {
        user,
        user_key,
        version,
        report,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_with_suffixes_and_missing_parts() {
        assert_eq!(parse_version("9.12.3"), Some(version_of(9, 12, 3)));
        assert_eq!(parse_version("8.14"), Some(version_of(8, 14, 0)));
        assert_eq!(parse_version("9.12.0-m0001"), Some(version_of(9, 12, 0)));
        assert_eq!(parse_version("nine"), None);
    }

    fn version_of(major: u32, minor: u32, patch: u32) -> Version {
        Version {
            major,
            minor,
            patch,
        }
    }

    #[test]
    fn the_floors_refuse_and_the_recommended_versions_warn() {
        assert!(judge_version(Product::Jira, Some("8.13.9")).is_err());
        let (v, w) = judge_version(Product::Jira, Some("8.14.0")).unwrap_or_default();
        assert!(v.is_some() && w.len() == 1);
        let (_, w) = judge_version(Product::Jira, Some("9.12.0")).unwrap_or_default();
        assert!(w.is_empty());
        assert!(judge_version(Product::Confluence, Some("7.8.0")).is_err());
        let (_, w) = judge_version(Product::Confluence, None).unwrap_or_default();
        assert_eq!(w.len(), 1);
    }
}
