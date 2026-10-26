//! The LDAPS directory (SM-2.1, SM-2.3, PD-200): simple bind as `<username><LDAP_UPN_SUFFIX>`
//! over TLS verified against the configured roots, then a subtree search of `LDAP_BASE_DN` for
//! the user's entry (`memberOf`, `userAccountControl`, `displayName`), then unbind. 10 s connect
//! and 10 s per operation. Result 49 is a wrong password; every other failure is `Unavailable`,
//! logged with the result code only.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use secrecy::{ExposeSecret, SecretString};
use tokio::net::TcpStream;
use url::Url;

use super::escape::filter_value;
use super::{Directory, DirectoryError, DirectoryUser};

/// PD-200: connect and operation timeouts.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const OP_TIMEOUT: Duration = Duration::from_secs(10);
/// LDAP result code `invalidCredentials`.
const RC_INVALID_CREDENTIALS: u32 = 49;
/// `userAccountControl` ACCOUNTDISABLE.
const UAC_DISABLED: u64 = 0x2;

/// Maps any failure of `step` to `Unavailable`, logging the step only (never the error text,
/// which may echo a DN).
fn unavailable<E>(step: &'static str) -> impl FnOnce(E) -> DirectoryError {
    move |_| {
        tracing::warn!(event = "directory_unavailable", step);
        DirectoryError::Unavailable
    }
}

pub struct LdapDirectory {
    url: Url,
    upn_suffix: String,
    base_dn: String,
    tls: Arc<ClientConfig>,
}

impl LdapDirectory {
    /// `url` must be `ldaps://` (the configuration refuses anything else).
    pub fn new(url: Url, upn_suffix: String, base_dn: String, tls: Arc<ClientConfig>) -> Self {
        LdapDirectory {
            url,
            upn_suffix,
            base_dn,
            tls,
        }
    }

    fn settings(&self) -> LdapConnSettings {
        LdapConnSettings::new()
            .set_config(self.tls.clone())
            .set_conn_timeout(CONNECT_TIMEOUT)
    }

    async fn bind_and_search(
        &self,
        username: &str,
        password: &SecretString,
    ) -> Result<DirectoryUser, DirectoryError> {
        let (conn, mut ldap) = tokio::time::timeout(
            CONNECT_TIMEOUT + Duration::from_secs(1),
            LdapConnAsync::with_settings(self.settings(), self.url.as_str()),
        )
        .await
        .map_err(unavailable("connect_timeout"))?
        .map_err(unavailable("connect"))?;
        let driver = tokio::spawn(async move {
            let _ = conn.drive().await;
        });
        let upn = format!("{username}{}", self.upn_suffix);
        let bind = ldap
            .with_timeout(OP_TIMEOUT)
            .simple_bind(&upn, password.expose_secret())
            .await
            .map_err(unavailable("bind"))?;
        let outcome = if bind.rc == RC_INVALID_CREDENTIALS {
            Err(DirectoryError::InvalidCredentials)
        } else if bind.rc != 0 {
            tracing::warn!(event = "directory_unavailable", step = "bind", rc = bind.rc);
            Err(DirectoryError::Unavailable)
        } else {
            self.search(&mut ldap, username, &upn).await
        };
        let _ = ldap.with_timeout(OP_TIMEOUT).unbind().await;
        driver.abort();
        outcome
    }

    async fn search(
        &self,
        ldap: &mut ldap3::Ldap,
        username: &str,
        upn: &str,
    ) -> Result<DirectoryUser, DirectoryError> {
        let filter = format!(
            "(&(objectClass=user)(userPrincipalName={}))",
            filter_value(upn)
        );
        let res = ldap
            .with_timeout(OP_TIMEOUT)
            .search(
                &self.base_dn,
                Scope::Subtree,
                &filter,
                vec!["memberOf", "userAccountControl", "displayName"],
            )
            .await
            .map_err(|_| DirectoryError::Unavailable)?;
        let (entries, done) = res.success().map_err(|e| {
            if let ldap3::LdapError::LdapResult { result } = &e {
                tracing::warn!(
                    event = "directory_unavailable",
                    step = "search",
                    rc = result.rc
                );
            }
            DirectoryError::Unavailable
        })?;
        let entry = entries
            .into_iter()
            .next()
            .map(SearchEntry::construct)
            .ok_or(DirectoryError::NotFound)?;
        let _ = done;
        let first = |k: &str| entry.attrs.get(k).and_then(|v| v.first()).cloned();
        let uac: u64 = first("userAccountControl")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        Ok(DirectoryUser {
            username: username.to_owned(),
            display_name: first("displayName"),
            groups: entry.attrs.get("memberOf").cloned().unwrap_or_default(),
            disabled: uac & UAC_DISABLED != 0,
        })
    }
}

#[async_trait]
impl Directory for LdapDirectory {
    async fn authenticate(
        &self,
        username: &str,
        password: &SecretString,
    ) -> Result<DirectoryUser, DirectoryError> {
        // Defence in depth: an empty password would be an unauthenticated bind (RFC 4513 5.1.2).
        if password.expose_secret().is_empty() {
            return Err(DirectoryError::InvalidCredentials);
        }
        tokio::time::timeout(
            CONNECT_TIMEOUT + 3 * OP_TIMEOUT,
            self.bind_and_search(username, password),
        )
        .await
        .unwrap_or(Err(DirectoryError::Unavailable))
    }

    async fn probe(&self) -> Result<(), DirectoryError> {
        let host = self.url.host_str().ok_or(DirectoryError::Unavailable)?;
        let port = self.url.port().unwrap_or(636);
        let name =
            ServerName::try_from(host.to_owned()).map_err(|_| DirectoryError::Unavailable)?;
        let handshake = async {
            let tcp = TcpStream::connect((host, port))
                .await
                .map_err(|_| DirectoryError::Unavailable)?;
            tokio_rustls::TlsConnector::from(self.tls.clone())
                .connect(name, tcp)
                .await
                .map(|_| ())
                .map_err(|_| DirectoryError::Unavailable)
        };
        tokio::time::timeout(CONNECT_TIMEOUT, handshake)
            .await
            .unwrap_or(Err(DirectoryError::Unavailable))
    }

    fn kind(&self) -> &'static str {
        "ldap"
    }
}
