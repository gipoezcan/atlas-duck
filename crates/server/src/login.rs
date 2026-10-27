//! Domain login (SM-2.1–SM-2.3, PD-199, PD-201): the order is fixed and every step before the
//! bind is cheap:
//! 1. username shape (PD-199) → else `auth/invalid_credentials`, counted, no bind;
//! 2. empty password → `auth/empty_password` 400, not counted, no bind;
//! 3. the rate limiter → `auth/rate_limited` 429, no bind;
//! 4. the directory bind (the password is dropped right after);
//! 5. roles from the groups (`GROUP_USERS` required, others additive; disabled → not permitted);
//! 6. the user row (data key on first login), the session, the `LOGIN` record.
//!
//! Failures `invalid_credentials`, `not_permitted` and `directory_unavailable` append
//! `LOGIN_FAILED {username, source_ip, reason}` to the server anchor chain (SM-2.2). The user's
//! own chain and store live behind [`LoginSink`] (the user runtimes, Task 14).

use std::sync::Arc;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Map, Value, json};

use crate::anchor::{KIND_LOGIN_FAILED, append_operational};
use crate::audit_kinds::{self, DirectoryKind, Login, LoginMethod, LoginOutcome};
use crate::clock::Clock;
use crate::config::Groups;
use crate::directory::{Directory, DirectoryError};
use crate::errors::ApiError;
use crate::master_key::MasterKey;
use crate::ratelimit::LoginLimiter;
use crate::session::{Created, SessionTable};
use crate::store::{ServerStore, UserRecord};
use crate::users::{EnsureError, canonical, ensure_user, valid_username};

pub const ROLE_USER: &str = "user";
pub const ROLE_AUDITOR: &str = "auditor";
pub const ROLE_ADMIN: &str = "admin";

/// What the login needs from the per-user side (the user runtimes, Task 14).
#[async_trait]
pub trait LoginSink: Send + Sync {
    /// First login of `user_id`: create the user's M2 store.
    async fn user_created(&self, user_id: &str) -> Result<(), ApiError>;
    /// Appends `LOGIN` with `payload` to the user's own chain.
    async fn login_recorded(
        &self,
        user_id: &str,
        payload: Map<String, Value>,
    ) -> Result<(), ApiError>;
}

pub struct LoginService {
    pub store: Arc<dyn ServerStore>,
    pub master: Arc<MasterKey>,
    pub directory: Arc<dyn Directory>,
    pub limiter: Arc<LoginLimiter>,
    pub sessions: Arc<SessionTable>,
    pub groups: Groups,
    pub clock: Arc<dyn Clock>,
    pub sink: Arc<dyn LoginSink>,
}

pub struct LoginOk {
    pub user: UserRecord,
    pub created: Created,
}

/// SM-2.3: `user` needs `GROUP_USERS`; `auditor` and `admin` are added by their groups. DN match
/// is exact and case-insensitive; nested groups are not expanded (L221).
pub fn roles_for(groups: &Groups, member_of: &[String]) -> Vec<String> {
    let has = |dn: &str| member_of.iter().any(|g| g.eq_ignore_ascii_case(dn));
    let mut roles = Vec::new();
    if has(&groups.users) {
        roles.push(ROLE_USER.to_owned());
    }
    if groups.auditors.as_deref().is_some_and(has) {
        roles.push(ROLE_AUDITOR.to_owned());
    }
    if groups.admins.as_deref().is_some_and(has) {
        roles.push(ROLE_ADMIN.to_owned());
    }
    roles
}

/// The username as `LOGIN_FAILED` records it: at most 64 characters of what was sent.
fn recorded_name(username: &str) -> String {
    username.chars().take(64).collect()
}

/// The limiter key of a username: lowercased and clipped to 64 characters, so an invalid name
/// of any length (up to the 64 KiB body) costs a bounded key (PD-201's key cap assumes it).
pub fn limiter_key(username: &str) -> String {
    canonical(&recorded_name(username))
}

impl LoginService {
    fn directory_kind(&self) -> DirectoryKind {
        if self.directory.kind() == "stub" {
            DirectoryKind::Stub
        } else {
            DirectoryKind::Ldap
        }
    }

    fn failed(&self, username: &str, ip: &str, reason: &str) {
        tracing::warn!(event = "login_failed", reason, source_ip = ip);
        let body = json!({"username": recorded_name(username), "source_ip": ip, "reason": reason});
        if append_operational(
            self.store.as_ref(),
            self.clock.now(),
            KIND_LOGIN_FAILED,
            &body,
        )
        .is_err()
        {
            tracing::error!(event = "anchor_append_failed", kind = KIND_LOGIN_FAILED);
        }
    }

    /// A counted failure: the reserved attempt stays in the windows; LOGIN_FAILED is appended.
    fn refuse(&self, username: &str, ip: &str, reason: &str, err: ApiError) -> ApiError {
        self.failed(username, ip, reason);
        err
    }

    pub async fn login(
        &self,
        username: &str,
        password: SecretString,
        ip: &str,
    ) -> Result<LoginOk, ApiError> {
        let now = self.clock.now();
        if !valid_username(username) {
            if let Err(wait) = self.limiter.reserve(&limiter_key(username), ip, now) {
                return Err(ApiError::rate_limited(wait.0));
            }
            return Err(self.refuse(
                username,
                ip,
                "invalid_credentials",
                ApiError::INVALID_CREDENTIALS,
            ));
        }
        if password.expose_secret().is_empty() {
            return Err(ApiError::EMPTY_PASSWORD);
        }
        let name = canonical(username);
        // Review I1: the attempt is counted before the bind, under the limiter's lock, and taken
        // back only on success or when the directory could not answer.
        if let Err(wait) = self.limiter.reserve(&name, ip, now) {
            return Err(ApiError::rate_limited(wait.0));
        }
        let outcome = self.directory.authenticate(&name, &password).await;
        drop(password);
        let user = match outcome {
            Ok(u) => u,
            Err(DirectoryError::InvalidCredentials) => {
                return Err(self.refuse(
                    &name,
                    ip,
                    "invalid_credentials",
                    ApiError::INVALID_CREDENTIALS,
                ));
            }
            Err(DirectoryError::NotFound) => {
                return Err(self.refuse(&name, ip, "not_permitted", ApiError::NOT_PERMITTED));
            }
            Err(DirectoryError::Unavailable) => {
                self.limiter.release(&name, ip, now);
                self.failed(&name, ip, "directory_unavailable");
                return Err(ApiError::DIRECTORY_UNAVAILABLE);
            }
        };
        let roles = roles_for(&self.groups, &user.groups);
        if user.disabled || !roles.iter().any(|r| r == ROLE_USER) {
            return Err(self.refuse(&name, ip, "not_permitted", ApiError::NOT_PERMITTED));
        }
        let (record, created) = ensure_user(
            self.store.as_ref(),
            &self.master,
            &name,
            user.display_name,
            roles.clone(),
            now,
        )
        .map_err(|e| match e {
            EnsureError::Store(_) => ApiError::STORE_UNAVAILABLE,
            EnsureError::Key => ApiError::INTERNAL,
        })?;
        if created {
            self.sink.user_created(&record.user_id).await?;
        }
        self.limiter.release(&name, ip, now);
        self.limiter.record_success(&name);
        tracing::info!(event = "login_succeeded", user_id = %record.user_id, source_ip = ip);
        let session = self.sessions.create(&record.user_id, roles.clone())?;
        let role_refs: Vec<&str> = roles.iter().map(String::as_str).collect();
        let payload = audit_kinds::login(&Login {
            method: LoginMethod::Password,
            outcome: LoginOutcome::Success,
            reason: None,
            roles: Some(&role_refs),
            source_ip: ip,
            directory: self.directory_kind(),
            key_id: None,
            prefix: None,
            grant_id: None,
        });
        self.sink.login_recorded(&record.user_id, payload).await?;
        Ok(LoginOk {
            user: record,
            created: session,
        })
    }
}
