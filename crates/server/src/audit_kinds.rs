//! Payload builders of the server-mode audit kinds (SM-6.3, PD-216): `LOGIN`, `API_KEY_CREATED`,
//! `API_KEY_REVOKED`, `AUDITOR_READ`. Each returns the record payload as a JSON object; the audit
//! store serializes it as JCS like every other payload. The key sets are the plan's (L227),
//! including what only M14 writes (`oauth`, `grant_id`, the auditor actions), so M14 needs no
//! payload change. No builder takes a secret: key ids and the public 8-character prefix only.

use serde_json::{Map, Value};

/// `LOGIN.method`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginMethod {
    Password,
    ApiKey,
    /// Written by M14 only (PD-243).
    Oauth,
}

impl LoginMethod {
    fn as_str(self) -> &'static str {
        match self {
            LoginMethod::Password => "password",
            LoginMethod::ApiKey => "api_key",
            LoginMethod::Oauth => "oauth",
        }
    }
}

/// `LOGIN.outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginOutcome {
    Success,
    Refused,
}

impl LoginOutcome {
    fn as_str(self) -> &'static str {
        match self {
            LoginOutcome::Success => "success",
            LoginOutcome::Refused => "refused",
        }
    }
}

/// `LOGIN.directory`: the LDAPS directory or the test stub (PD-198).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryKind {
    Ldap,
    Stub,
}

impl DirectoryKind {
    fn as_str(self) -> &'static str {
        match self {
            DirectoryKind::Ldap => "ldap",
            DirectoryKind::Stub => "stub",
        }
    }
}

/// One `LOGIN` record: `{method, outcome, reason?, roles?, source_ip, directory, key_id?, prefix?,
/// grant_id?}`. An absent option is an absent key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login<'a> {
    pub method: LoginMethod,
    pub outcome: LoginOutcome,
    /// A fixed reason code (`revoked`, `expired`, ...), never caller text.
    pub reason: Option<&'a str>,
    pub roles: Option<&'a [&'a str]>,
    pub source_ip: &'a str,
    pub directory: DirectoryKind,
    pub key_id: Option<&'a str>,
    pub prefix: Option<&'a str>,
    /// Written by M14 only (PD-243).
    pub grant_id: Option<&'a str>,
}

pub fn login(l: &Login<'_>) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("method".into(), l.method.as_str().into());
    m.insert("outcome".into(), l.outcome.as_str().into());
    put_str(&mut m, "reason", l.reason);
    if let Some(roles) = l.roles {
        m.insert("roles".into(), strings(roles));
    }
    m.insert("source_ip".into(), l.source_ip.into());
    m.insert("directory".into(), l.directory.as_str().into());
    put_str(&mut m, "key_id", l.key_id);
    put_str(&mut m, "prefix", l.prefix);
    put_str(&mut m, "grant_id", l.grant_id);
    m
}

/// `API_KEY_CREATED {key_id, name, prefix, scopes, expires_at}`.
pub fn api_key_created(
    key_id: &str,
    name: &str,
    prefix: &str,
    scopes: &[&str],
    expires_at: &str,
) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("key_id".into(), key_id.into());
    m.insert("name".into(), name.into());
    m.insert("prefix".into(), prefix.into());
    m.insert("scopes".into(), strings(scopes));
    m.insert("expires_at".into(), expires_at.into());
    m
}

/// `API_KEY_REVOKED.by`: the user, or the user's deactivation (M13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokedBy {
    User,
    Deactivation,
}

/// `API_KEY_REVOKED {key_id, prefix, by}`.
pub fn api_key_revoked(key_id: &str, prefix: &str, by: RevokedBy) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("key_id".into(), key_id.into());
    m.insert("prefix".into(), prefix.into());
    m.insert(
        "by".into(),
        match by {
            RevokedBy::User => "user",
            RevokedBy::Deactivation => "deactivation",
        }
        .into(),
    );
    m
}

/// What an auditor read about one user (M14 PD-258).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserReadAction {
    Query,
    Trail,
    Payload,
    Export,
}

/// `AUDITOR_READ`'s action and target: `list_users` has no target user, every other action has
/// one (the type makes the plan's rule impossible to break).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditorScope<'a> {
    ListUsers,
    User {
        target_user_id: &'a str,
        action: UserReadAction,
    },
}

/// One `AUDITOR_READ` record: `{target_user_id?, action, range?, request_id?, seq?, page?,
/// job_id?}`.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditorRead<'a> {
    pub scope: AuditorScope<'a>,
    pub range: Option<&'a Value>,
    pub request_id: Option<&'a str>,
    pub seq: Option<u64>,
    pub page: Option<u64>,
    pub job_id: Option<&'a str>,
}

pub fn auditor_read(r: &AuditorRead<'_>) -> Map<String, Value> {
    let mut m = Map::new();
    let action = match r.scope {
        AuditorScope::ListUsers => "list_users",
        AuditorScope::User {
            target_user_id,
            action,
        } => {
            m.insert("target_user_id".into(), target_user_id.into());
            match action {
                UserReadAction::Query => "query",
                UserReadAction::Trail => "trail",
                UserReadAction::Payload => "payload",
                UserReadAction::Export => "export",
            }
        }
    };
    m.insert("action".into(), action.into());
    if let Some(range) = r.range {
        m.insert("range".into(), range.clone());
    }
    put_str(&mut m, "request_id", r.request_id);
    if let Some(seq) = r.seq {
        m.insert("seq".into(), seq.into());
    }
    if let Some(page) = r.page {
        m.insert("page".into(), page.into());
    }
    put_str(&mut m, "job_id", r.job_id);
    m
}

fn put_str(m: &mut Map<String, Value>, key: &str, v: Option<&str>) {
    if let Some(v) = v {
        m.insert(key.into(), v.into());
    }
}

fn strings(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::from(*s)).collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use serde_json::json;

    use super::*;

    fn keys(m: &Map<String, Value>) -> Vec<&str> {
        let mut k: Vec<&str> = m.keys().map(String::as_str).collect();
        k.sort_unstable();
        k
    }

    const LOGIN_KEYS: [&str; 9] = [
        "directory",
        "grant_id",
        "key_id",
        "method",
        "outcome",
        "prefix",
        "reason",
        "roles",
        "source_ip",
    ];

    #[test]
    fn login_password_success() {
        let m = login(&Login {
            method: LoginMethod::Password,
            outcome: LoginOutcome::Success,
            reason: None,
            roles: Some(&["user", "admin"]),
            source_ip: "192.0.2.1",
            directory: DirectoryKind::Stub,
            key_id: None,
            prefix: None,
            grant_id: None,
        });
        assert_eq!(
            Value::Object(m),
            json!({"method": "password", "outcome": "success", "roles": ["user", "admin"],
                   "source_ip": "192.0.2.1", "directory": "stub"})
        );
    }

    #[test]
    fn login_every_key_and_value() {
        let full = login(&Login {
            method: LoginMethod::Oauth,
            outcome: LoginOutcome::Refused,
            reason: Some("expired"),
            roles: Some(&[]),
            source_ip: "2001:db8::1",
            directory: DirectoryKind::Ldap,
            key_id: Some("key-1"),
            prefix: Some("abcd1234"),
            grant_id: Some("grant-1"),
        });
        assert_eq!(keys(&full), LOGIN_KEYS);
        assert_eq!(full["method"], "oauth");
        assert_eq!(full["outcome"], "refused");
        assert_eq!(full["directory"], "ldap");
        // PD-214: a refused API key, as the owner's chain records it.
        let api = login(&Login {
            method: LoginMethod::ApiKey,
            outcome: LoginOutcome::Refused,
            reason: Some("revoked"),
            roles: None,
            source_ip: "192.0.2.9",
            directory: DirectoryKind::Ldap,
            key_id: Some("key-2"),
            prefix: Some("zz99zz99"),
            grant_id: None,
        });
        assert_eq!(
            keys(&api),
            [
                "directory",
                "key_id",
                "method",
                "outcome",
                "prefix",
                "reason",
                "source_ip"
            ]
        );
        assert_eq!(api["method"], "api_key");
    }

    #[test]
    fn api_key_created_exact_keys() {
        let m = api_key_created(
            "key-1",
            "laptop",
            "abcd1234",
            &["read", "propose_write"],
            "2026-11-25T09:00:00.000Z",
        );
        assert_eq!(
            Value::Object(m),
            json!({"key_id": "key-1", "name": "laptop", "prefix": "abcd1234",
                   "scopes": ["read", "propose_write"], "expires_at": "2026-11-25T09:00:00.000Z"})
        );
    }

    #[test]
    fn api_key_revoked_exact_keys() {
        assert_eq!(
            Value::Object(api_key_revoked("key-1", "abcd1234", RevokedBy::User)),
            json!({"key_id": "key-1", "prefix": "abcd1234", "by": "user"})
        );
        assert_eq!(
            api_key_revoked("key-1", "abcd1234", RevokedBy::Deactivation)["by"],
            "deactivation"
        );
    }

    #[test]
    fn auditor_read_list_users_has_no_target() {
        let m = auditor_read(&AuditorRead {
            scope: AuditorScope::ListUsers,
            range: None,
            request_id: None,
            seq: None,
            page: None,
            job_id: None,
        });
        assert_eq!(Value::Object(m), json!({"action": "list_users"}));
    }

    #[test]
    fn auditor_read_every_action_and_key() {
        let range = json!({"from": "2026-10-01", "to": "2026-10-26"});
        for (action, name) in [
            (UserReadAction::Query, "query"),
            (UserReadAction::Trail, "trail"),
            (UserReadAction::Payload, "payload"),
            (UserReadAction::Export, "export"),
        ] {
            let m = auditor_read(&AuditorRead {
                scope: AuditorScope::User {
                    target_user_id: "0123456789abcdef0123456789abcdef",
                    action,
                },
                range: Some(&range),
                request_id: Some("req_0123456789abcdefghij"),
                seq: Some(7),
                page: Some(2),
                job_id: Some("job-1"),
            });
            assert_eq!(
                keys(&m),
                [
                    "action",
                    "job_id",
                    "page",
                    "range",
                    "request_id",
                    "seq",
                    "target_user_id"
                ]
            );
            assert_eq!(m["action"], name);
            assert_eq!(m["target_user_id"], "0123456789abcdef0123456789abcdef");
            assert_eq!(m["range"], range);
        }
    }
}
