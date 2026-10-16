#![cfg(feature = "testing")]
//! L-01 (Jira/Confluence DC): the env-gated live probe for V26, M6 Task 35. It is manual: no CI
//! leg runs it, no agent may run it, and it is `#[ignore]`.
//!
//! Question (spec §15 V26): does the DC PAT REST resource (`GET /rest/pat/latest/tokens`) let a PAT
//! read its own expiry date, so the optional manual "token expires on" entry (§7.1) could be
//! prefilled (M10)?
//!
//! A run needs `ATLAS_DUCK_LIVE_JIRA_URL` (https) and `ATLAS_DUCK_LIVE_JIRA_PAT`, the same
//! variables as `live_jira.rs`. Without them the test prints `skipped: live env not set` and
//! returns `Ok(())`. The probe is read-only: one GET, nothing is written.
//!
//! Run by hand with output shown:
//! `cargo test -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing
//! --test live_pat_resource -- --ignored --nocapture --test-threads=1`.
//!
//! Every finding is a printed `V26 ...` line for the lead to turn into a spec and ledger entry. The
//! PAT is never printed, and neither are the names or ids of the listed tokens (they identify the
//! user's other tokens); usernames appear only as `<configured user>` or `<other>`. Field names
//! and the expiry timestamps are printed; server text appears escaped (`{:?}`) and capped.

mod common;

use std::sync::Arc;

use atlas_duck_atlassian::testing::{RecordingDates, test_cover};
use atlas_duck_atlassian::{
    ClientConfig, CredentialProvider, FetchFailure, FetchOutcome, GetCall, IdentityObserved,
    InstanceClient, Product as WireProduct, ProxyChoice, Timeouts, normalize_base_url,
};
use atlas_duck_core::testing::{Harness, LIVE_ALIAS};
use common::TestResult;
use serde_json::{Value, json};

const SKIPPED: &str = "skipped: live env not set";
/// Free text of a server shown in a finding line is cut here.
const SHOWN: usize = 400;
/// The endpoint under test.
const TOKENS: &str = "/rest/pat/latest/tokens";
/// Field names that may hold an expiry, as DC spells them (V26 decides which one is real).
const EXPIRY_KEYS: [&str; 4] = ["expiringAt", "expiresAt", "expirationDate", "expiry"];

/// The PD-60 variables this probe needs. No `Debug`: the PAT is in it.
struct Env {
    url: String,
    pat: String,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

impl Env {
    fn read() -> Option<Env> {
        Some(Env {
            url: var("ATLAS_DUCK_LIVE_JIRA_URL")?,
            pat: var("ATLAS_DUCK_LIVE_JIRA_PAT")?,
        })
    }
}

/// A server's text, escaped and capped.
fn shown(s: &str) -> String {
    let cut: String = s.chars().take(SHOWN).collect();
    format!("{cut:?}")
}

/// The sorted field names of a JSON object (names only, never values).
fn key_names(v: &Value) -> Vec<String> {
    let mut names: Vec<String> = v
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    names.sort();
    names
}

/// The JSON type of `v`, without its content.
fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// What the identity check made of `X-AUSERNAME`, without any name.
fn observed(o: &IdentityObserved, user: &str) -> &'static str {
    match o {
        IdentityObserved::Missing => "X-AUSERNAME missing",
        IdentityObserved::Anonymous => "X-AUSERNAME anonymous",
        IdentityObserved::Other(n) if n == user => "X-AUSERNAME <configured user> (exact bytes)",
        IdentityObserved::Other(n) if n.eq_ignore_ascii_case(user) => {
            "X-AUSERNAME <configured user> (case differs)"
        }
        IdentityObserved::Other(_) => "X-AUSERNAME <other>",
    }
}

/// One `V26` line per token entry: which expiry-like fields it has, their type and value (a
/// timestamp, not a secret), and the field names it carries. Names and ids are left out.
fn report_entry(index: usize, entry: &Value) {
    let found: Vec<String> = EXPIRY_KEYS
        .iter()
        .filter(|k| entry.get(**k).is_some())
        .map(|k| format!("{k}:{}={}", kind(&entry[*k]), shown(&entry[*k].to_string())))
        .collect();
    println!(
        "V26 token[{index}] fields={:?} expiry_fields={found:?}",
        key_names(entry)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run against a real Jira/Confluence DC (L-01)"]
async fn v26_pat_resource_reads_own_expiry() -> TestResult {
    let Some(env) = Env::read() else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let h = Harness::builder().live(&env.url, &env.pat).start().await?;
    let report = h
        .instances()
        .retest_token(LIVE_ALIAS)
        .await
        .map_err(|e| format!("live connection test failed: {e:?}"))?;
    println!(
        "V26 connected, product={:?} version={}",
        report.product, report.version
    );
    let user = report.atlassian_user;

    // The same client and PAT as the app's own reads; the resource is Jira-shaped on both products
    // (`/rest/pat/latest`), so the Jira product is used for the wire probe.
    let inst = h.instance(LIVE_ALIAS).ok_or("no such instance")?;
    let cfg = ClientConfig {
        instance_id: inst.id.clone(),
        product: WireProduct::Jira,
        base: normalize_base_url(&env.url).map_err(|e| format!("{e:?}"))?,
        custom_ca_pem: None,
        proxy: ProxyChoice::Direct,
        user_agent: format!("atlas-duck-live-probe/{}", env!("CARGO_PKG_VERSION")),
        timeouts: Timeouts::default(),
    };
    let creds: Arc<dyn CredentialProvider> = h.credentials().clone();
    let client = InstanceClient::build(cfg, creds, Arc::new(RecordingDates::default()))?;
    let call = GetCall {
        endpoint_template: TOKENS.to_owned(),
        params: json!({}),
        query: Vec::new(),
    };
    let cover = test_cover().map_err(|e| format!("{e:?}"))?;

    let response = match client.get(&cover, &call).await {
        FetchOutcome::Response(r) => r,
        FetchOutcome::Failed(FetchFailure::IdentityCheckFailed {
            observed: o,
            response,
        }) => {
            println!(
                "V26 GET {TOKENS}: status={} content_type={:?} identity check failed: {}; \
                 expiry readable=unknown",
                response.status,
                response.content_type,
                observed(&o, &user)
            );
            return Ok(());
        }
        FetchOutcome::Failed(FetchFailure::StatusHeaderDecided { reason, response }) => {
            println!(
                "V26 GET {TOKENS}: status={} content_type={:?} classified {reason:?}; \
                 expiry readable=no (resource not usable with this PAT)",
                response.status, response.content_type
            );
            return Ok(());
        }
        FetchOutcome::Failed(FetchFailure::BodyDecided {
            kind: class,
            response,
        }) => {
            println!(
                "V26 GET {TOKENS}: status={} content_type={:?} classified {class:?} (body decided); \
                 expiry readable=no",
                response.status, response.content_type
            );
            return Ok(());
        }
        FetchOutcome::Failed(f) => {
            println!("V26 GET {TOKENS}: failed: {f:?}; expiry readable=unknown");
            return Ok(());
        }
    };
    println!(
        "V26 GET {TOKENS}: status={} content_type={:?} body_len={} identity check passed \
         (X-AUSERNAME present, <configured user>, exact bytes)",
        response.status,
        response.content_type,
        response.body.len()
    );

    let body: Value = match serde_json::from_slice(&response.body) {
        Ok(v) => v,
        Err(e) => {
            println!("V26 body is not JSON ({e}); expiry readable=no");
            return Ok(());
        }
    };
    // DC answers a bare array of token entries; a wrapper object is reported, not assumed.
    let entries: Vec<Value> = match &body {
        Value::Array(a) => a.clone(),
        other => {
            println!(
                "V26 body is {} (not an array), fields={:?}",
                kind(other),
                key_names(other)
            );
            for key in ["values", "tokens", "results"] {
                if let Some(a) = other.get(key).and_then(Value::as_array) {
                    println!("V26 entries found under {key:?}");
                    return report_entries(a);
                }
            }
            println!("V26 expiry readable=no (no entry list found)");
            return Ok(());
        }
    };
    report_entries(&entries)
}

/// The entry lines and the verdict. The resource lists the user's tokens; which one is the PAT in
/// use is not named by the server, so a prefill is possible only if exactly one entry can be
/// told to be the configured PAT (for example the only entry with a recent last-use time).
fn report_entries(entries: &[Value]) -> TestResult {
    println!("V26 entries={}", entries.len());
    for (i, e) in entries.iter().enumerate() {
        report_entry(i, e);
    }
    let with_expiry = entries
        .iter()
        .filter(|e| {
            EXPIRY_KEYS
                .iter()
                .any(|k| e.get(*k).is_some_and(|v| !v.is_null()))
        })
        .count();
    let fields: Vec<String> = EXPIRY_KEYS
        .iter()
        .filter(|k| entries.iter().any(|e| e.get(**k).is_some()))
        .map(|k| (*k).to_owned())
        .collect();
    println!(
        "V26 expiry readable={} entries_with_expiry={with_expiry} expiry_field_names={fields:?}; \
         whether the entry of the configured PAT can be identified from the listing is a manual \
         finding (names and ids are not printed)",
        with_expiry > 0
    );
    Ok(())
}
