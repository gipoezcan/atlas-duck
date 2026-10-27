//! Server configuration from the environment, read once at startup (plan "Configuration", T8).
//!
//! `Config::from_env` takes the lookup and the variable list as functions, so tests drive every
//! row of the table without touching the process environment. Key material never comes from
//! here: only the master key's file path does (ADR 0002), and any other `*MASTER_KEY` variable is
//! a startup error.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use atlas_duck_ipc::paths::{DataDirResolution, LocalDataDir, check_data_dir};
use url::Url;

/// The one production switch of every server-mode plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Production,
    Review,
    Dev,
}

/// Where logins are checked: the LDAPS directory or the test stub (PD-198).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryConfig {
    Ldap {
        url: Url,
        upn_suffix: String,
        base_dn: String,
    },
    Stub {
        file: PathBuf,
    },
}

/// The optional read-only directory service account of the daily offboarding check (M13 T9,
/// PD-M13-14): its DN, and the file its password is read from (a mounted Secret, never env).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBind {
    pub dn: String,
    pub password_file: PathBuf,
}

/// The group DNs that grant the roles (SM-2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groups {
    pub users: String,
    pub auditors: Option<String>,
    pub admins: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    /// `scheme://host[:port]`, no path.
    pub public_url: Url,
    pub listen: SocketAddr,
    pub data_dir: LocalDataDir,
    pub master_key_file: PathBuf,
    /// During a rotation only (M13 T7): the next key, accepted for unwrapping alongside.
    pub master_key_next_file: Option<PathBuf>,
    pub ca_bundle_file: Option<PathBuf>,
    pub web_dir: PathBuf,
    pub trusted_proxy_hops: u32,
    pub max_open_users: usize,
    pub directory: DirectoryConfig,
    pub groups: Groups,
    pub login_limit_user: u32,
    pub login_limit_ip: u32,
    pub login_window: Duration,
    pub session_absolute: Duration,
    pub session_idle: Duration,
    pub anchor_interval: Duration,
    pub rust_log: String,
    /// M14 PD-233..PD-245.
    pub oauth: crate::oauth::OAuthConfig,
    /// M14 PD-246..PD-249.
    pub scripts: crate::scripts::ScriptsConfig,
    /// M14 PD-254: export job lifetime and the server-wide cap.
    pub exports: crate::export_job::ExportConfig,
    /// The admin CLI's Unix socket (M13 PD-M13-1).
    pub admin_socket: PathBuf,
    /// Daily offboarding and retention time, UTC `(hour, minute)` (M13 T9).
    pub offboarding_at: (u32, u32),
    /// SM-6.5 retention period of a deactivated user's chain.
    pub retention_days: u32,
    pub service_bind: Option<ServiceBind>,
    /// Final review M4: the most file data `admin restore --stdin` accepts.
    pub max_restore_bytes: u64,
    /// ADR 0004: the daily scheduled backup target (a second volume) and how many bundles stay.
    pub backup_dir: Option<PathBuf>,
    pub backup_keep: u32,
}

/// A refused configuration: a fixed code and the key it concerns. Never carries a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigError {
    pub code: &'static str,
    pub key: &'static str,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.code, self.key)
    }
}

impl std::error::Error for ConfigError {}

pub const MODE: &str = "ATLAS_DUCK_MODE";
pub const PUBLIC_URL: &str = "ATLAS_DUCK_PUBLIC_URL";
pub const LISTEN: &str = "ATLAS_DUCK_LISTEN";
pub const DATA_DIR: &str = "ATLAS_DUCK_DATA_DIR";
pub const MASTER_KEY_FILE: &str = "ATLAS_DUCK_MASTER_KEY_FILE";
pub const MASTER_KEY_NEXT_FILE: &str = "ATLAS_DUCK_MASTER_KEY_NEXT_FILE";
pub const CA_BUNDLE_FILE: &str = "ATLAS_DUCK_CA_BUNDLE_FILE";
pub const WEB_DIR: &str = "ATLAS_DUCK_WEB_DIR";
pub const TRUSTED_PROXY_HOPS: &str = "ATLAS_DUCK_TRUSTED_PROXY_HOPS";
pub const MAX_OPEN_USERS: &str = "ATLAS_DUCK_MAX_OPEN_USERS";
pub const TEST_DIRECTORY_FILE: &str = "ATLAS_DUCK_TEST_DIRECTORY_FILE";
pub const LDAP_URL: &str = "LDAP_URL";
pub const LDAP_UPN_SUFFIX: &str = "LDAP_UPN_SUFFIX";
pub const LDAP_BASE_DN: &str = "LDAP_BASE_DN";
pub const GROUP_USERS: &str = "GROUP_USERS";
pub const GROUP_AUDITORS: &str = "GROUP_AUDITORS";
pub const GROUP_ADMINS: &str = "GROUP_ADMINS";
pub const LOGIN_LIMIT_USER: &str = "ATLAS_DUCK_LOGIN_LIMIT_USER";
pub const LOGIN_LIMIT_IP: &str = "ATLAS_DUCK_LOGIN_LIMIT_IP";
pub const LOGIN_WINDOW_SECS: &str = "ATLAS_DUCK_LOGIN_WINDOW_SECS";
pub const SESSION_ABSOLUTE_SECS: &str = "ATLAS_DUCK_SESSION_ABSOLUTE_SECS";
pub const SESSION_IDLE_SECS: &str = "ATLAS_DUCK_SESSION_IDLE_SECS";
pub const ANCHOR_INTERVAL_SECS: &str = "ATLAS_DUCK_ANCHOR_INTERVAL_SECS";
pub const RUST_LOG: &str = "RUST_LOG";
pub const OAUTH: &str = "ATLAS_DUCK_OAUTH";
pub const OAUTH_ACCESS_TTL_SECS: &str = "ATLAS_DUCK_OAUTH_ACCESS_TTL_SECS";
pub const OAUTH_REFRESH_IDLE_DAYS: &str = "ATLAS_DUCK_OAUTH_REFRESH_IDLE_DAYS";
pub const OAUTH_GRANT_MAX_DAYS: &str = "ATLAS_DUCK_OAUTH_GRANT_MAX_DAYS";
pub const OAUTH_REGISTER_PER_IP_HOUR: &str = "ATLAS_DUCK_OAUTH_REGISTER_PER_IP_HOUR";
pub const OAUTH_MAX_CLIENTS: &str = "ATLAS_DUCK_OAUTH_MAX_CLIENTS";
pub const SCRIPTS: &str = "ATLAS_DUCK_SCRIPTS";
pub const SANDBOX_BIN: &str = "ATLAS_DUCK_SANDBOX_BIN";
pub const SCRIPT_RUNS_MAX: &str = "ATLAS_DUCK_SCRIPT_RUNS_MAX";
pub const SCRIPT_DRY_RUNS_MAX: &str = "ATLAS_DUCK_SCRIPT_DRY_RUNS_MAX";
pub const EXPORT_TTL_HOURS: &str = "ATLAS_DUCK_EXPORT_TTL_HOURS";
pub const EXPORT_MAX_CONCURRENT: &str = "ATLAS_DUCK_EXPORT_MAX_CONCURRENT";
pub const ADMIN_SOCKET: &str = "ATLAS_DUCK_ADMIN_SOCKET";
pub const OFFBOARDING_AT: &str = "ATLAS_DUCK_OFFBOARDING_AT";
pub const MAX_RESTORE_BYTES: &str = "ATLAS_DUCK_MAX_RESTORE_BYTES";
pub const BACKUP_DIR: &str = "ATLAS_DUCK_BACKUP_DIR";
pub const BACKUP_KEEP: &str = "ATLAS_DUCK_BACKUP_KEEP";
pub const DEFAULT_BACKUP_KEEP: u32 = 14;
/// 8 GiB: above the production volume's data, far below a filled disk.
pub const DEFAULT_MAX_RESTORE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const RETENTION_DAYS: &str = "ATLAS_DUCK_RETENTION_DAYS";
pub const SERVICE_BIND_DN: &str = "ATLAS_DUCK_LDAP_SERVICE_BIND_DN";
pub const SERVICE_BIND_PASSWORD_FILE: &str = "ATLAS_DUCK_LDAP_SERVICE_BIND_PASSWORD_FILE";
/// The longest retention period accepted (100 years).
pub const MAX_RETENTION_DAYS: u64 = 36_500;

/// Where the admin socket lives unless ATLAS_DUCK_ADMIN_SOCKET says otherwise (the chart's
/// in-memory emptyDir).
pub const DEFAULT_ADMIN_SOCKET: &str = "/run/atlas-duck/admin.sock";

/// SM-6.3 "at least every 15 minutes".
pub const MAX_ANCHOR_INTERVAL_SECS: u64 = 900;

fn err(code: &'static str, key: &'static str) -> ConfigError {
    ConfigError { code, key }
}

impl Config {
    /// Reads every key of the table. `get` looks one key up (an empty value counts as unset);
    /// `vars` lists every variable name of the environment (the `*MASTER_KEY` scan).
    pub fn from_env(
        get: &dyn Fn(&str) -> Option<String>,
        vars: &dyn Fn() -> Vec<String>,
    ) -> Result<Config, ConfigError> {
        let get = |k: &str| get(k).filter(|v| !v.is_empty());
        // ADR 0002: no key material outside the file. The variable's name is not echoed.
        if vars()
            .iter()
            .any(|n| n.to_ascii_uppercase().ends_with("MASTER_KEY"))
        {
            return Err(err("config/master_key_in_env", MASTER_KEY_FILE));
        }
        // PD-248: no degraded scripts in server mode; a key that asks for them is refused.
        if vars()
            .iter()
            .any(|n| n.to_ascii_uppercase().contains("ALLOW_DEGRADED"))
        {
            return Err(err("config/degraded_scripts_refused", SCRIPTS));
        }
        let required = |k: &'static str| get(k).ok_or(err("config/missing_key", k));

        let mode = match required(MODE)?.as_str() {
            "production" => Mode::Production,
            "review" => Mode::Review,
            "dev" => Mode::Dev,
            _ => return Err(err("config/invalid_mode", MODE)),
        };
        let public_url = public_url(&required(PUBLIC_URL)?, mode)?;
        let listen = match get(LISTEN) {
            None => SocketAddr::from(([0, 0, 0, 0], 8080)),
            Some(v) => v.parse().map_err(|_| err("config/invalid_value", LISTEN))?,
        };
        let data_dir = match check_data_dir(&PathBuf::from(required(DATA_DIR)?)) {
            Ok(DataDirResolution::Local(d)) => d,
            _ => return Err(err("config/data_dir_invalid", DATA_DIR)),
        };
        let master_key_file = PathBuf::from(required(MASTER_KEY_FILE)?);
        let master_key_next_file = get(MASTER_KEY_NEXT_FILE).map(PathBuf::from);
        let ca_bundle_file = get(CA_BUNDLE_FILE).map(PathBuf::from);
        let web_dir = PathBuf::from(get(WEB_DIR).unwrap_or_else(|| "/app/web".into()));
        let num = |k: &'static str, default: u64| -> Result<u64, ConfigError> {
            match get(k) {
                None => Ok(default),
                Some(v) => v.parse().map_err(|_| err("config/invalid_value", k)),
            }
        };
        let positive = |k: &'static str, default: u64| -> Result<u64, ConfigError> {
            match num(k, default)? {
                0 => Err(err("config/invalid_value", k)),
                n => Ok(n),
            }
        };
        let small =
            |k: &'static str, v: u64| u32::try_from(v).map_err(|_| err("config/invalid_value", k));
        let trusted_proxy_hops = small(TRUSTED_PROXY_HOPS, num(TRUSTED_PROXY_HOPS, 1)?)?;
        let max_open_users = usize::try_from(positive(MAX_OPEN_USERS, 200)?)
            .map_err(|_| err("config/invalid_value", MAX_OPEN_USERS))?;

        let directory = match get(TEST_DIRECTORY_FILE) {
            Some(_) if mode == Mode::Production => {
                return Err(err(
                    "config/test_directory_in_production",
                    TEST_DIRECTORY_FILE,
                ));
            }
            Some(file) => DirectoryConfig::Stub {
                file: PathBuf::from(file),
            },
            None => {
                let raw = required(LDAP_URL)?;
                let url =
                    Url::parse(&raw).map_err(|_| err("config/ldap_url_not_ldaps", LDAP_URL))?;
                if url.scheme() != "ldaps" || url.host_str().is_none() {
                    return Err(err("config/ldap_url_not_ldaps", LDAP_URL));
                }
                let upn_suffix = required(LDAP_UPN_SUFFIX)?;
                if !upn_suffix.starts_with('@') || upn_suffix.len() < 2 {
                    return Err(err("config/invalid_value", LDAP_UPN_SUFFIX));
                }
                DirectoryConfig::Ldap {
                    url,
                    upn_suffix,
                    base_dn: required(LDAP_BASE_DN)?,
                }
            }
        };
        let groups = Groups {
            users: required(GROUP_USERS)?,
            auditors: get(GROUP_AUDITORS),
            admins: get(GROUP_ADMINS),
        };
        let offboarding_at = match get(OFFBOARDING_AT) {
            None => (2, 0),
            Some(v) => hh_mm(&v).ok_or(err("config/invalid_value", OFFBOARDING_AT))?,
        };
        let retention_days = match positive(RETENTION_DAYS, 365)? {
            n if n > MAX_RETENTION_DAYS => return Err(err("config/invalid_value", RETENTION_DAYS)),
            n => small(RETENTION_DAYS, n)?,
        };
        let service_bind = match (get(SERVICE_BIND_DN), get(SERVICE_BIND_PASSWORD_FILE)) {
            (None, None) => None,
            (Some(dn), Some(file)) => Some(ServiceBind {
                dn,
                password_file: PathBuf::from(file),
            }),
            (Some(_), None) => {
                return Err(err(
                    "config/service_bind_incomplete",
                    SERVICE_BIND_PASSWORD_FILE,
                ));
            }
            (None, Some(_)) => return Err(err("config/service_bind_incomplete", SERVICE_BIND_DN)),
        };
        let anchor = positive(ANCHOR_INTERVAL_SECS, MAX_ANCHOR_INTERVAL_SECS)?;
        let oauth = oauth_config(&get, &num)?;
        let scripts = scripts_config(&get, &num)?;
        let in_range = |k: &'static str, default: u64, lo: u64, hi: u64| match num(k, default)? {
            v if (lo..=hi).contains(&v) => Ok(v),
            _ => Err(err("config/invalid_value", k)),
        };
        let exports = crate::export_job::ExportConfig {
            ttl_secs: i64::try_from(in_range(EXPORT_TTL_HOURS, 24, 1, 168)? * 3600)
                .unwrap_or(i64::MAX),
            max_concurrent: usize::try_from(in_range(EXPORT_MAX_CONCURRENT, 2, 1, 8)?).unwrap_or(1),
        };
        if anchor > MAX_ANCHOR_INTERVAL_SECS {
            return Err(err("config/anchor_interval_too_long", ANCHOR_INTERVAL_SECS));
        }
        Ok(Config {
            mode,
            public_url,
            listen,
            data_dir,
            master_key_file,
            master_key_next_file,
            ca_bundle_file,
            web_dir,
            trusted_proxy_hops,
            max_open_users,
            directory,
            groups,
            login_limit_user: small(LOGIN_LIMIT_USER, positive(LOGIN_LIMIT_USER, 5)?)?,
            login_limit_ip: small(LOGIN_LIMIT_IP, positive(LOGIN_LIMIT_IP, 20)?)?,
            login_window: Duration::from_secs(positive(LOGIN_WINDOW_SECS, 900)?),
            session_absolute: Duration::from_secs(positive(SESSION_ABSOLUTE_SECS, 28_800)?),
            session_idle: Duration::from_secs(positive(SESSION_IDLE_SECS, 1_800)?),
            anchor_interval: Duration::from_secs(anchor),
            rust_log: get(RUST_LOG).unwrap_or_else(|| "info".into()),
            oauth,
            scripts,
            exports,
            offboarding_at,
            retention_days,
            max_restore_bytes: positive(MAX_RESTORE_BYTES, DEFAULT_MAX_RESTORE_BYTES)?,
            backup_dir: get(BACKUP_DIR).map(PathBuf::from),
            backup_keep: small(
                BACKUP_KEEP,
                positive(BACKUP_KEEP, u64::from(DEFAULT_BACKUP_KEEP))?,
            )?,
            service_bind,
            admin_socket: PathBuf::from(
                get(ADMIN_SOCKET).unwrap_or_else(|| DEFAULT_ADMIN_SOCKET.into()),
            ),
        })
    }

    /// `scheme://host[:port]` of the public URL, the value every `Origin` must equal.
    pub fn public_origin(&self) -> String {
        self.public_url.origin().ascii_serialization()
    }

    /// PD-203: the cookie drops `Secure` only for a `dev` server on plain-HTTP localhost.
    pub fn cookie_secure(&self) -> bool {
        !(self.mode == Mode::Dev && self.public_url.scheme() == "http")
    }
}

/// The M14 OAuth keys (plan "Configuration"): ranges per key, `ATLAS_DUCK_OAUTH` is
/// `enabled|disabled`. The three lifetimes refuse with `config/oauth_ttl_out_of_range`, the two
/// registration limits with `config/invalid_value`.
fn oauth_config(
    get: &dyn Fn(&str) -> Option<String>,
    num: &dyn Fn(&'static str, u64) -> Result<u64, ConfigError>,
) -> Result<crate::oauth::OAuthConfig, ConfigError> {
    let enabled = match get(OAUTH).as_deref() {
        None | Some("enabled") => true,
        Some("disabled") => false,
        Some(_) => return Err(err("config/invalid_value", OAUTH)),
    };
    let ranged = |k: &'static str, default: u64, lo: u64, hi: u64, code: &'static str| {
        let v = num(k, default)?;
        if (lo..=hi).contains(&v) {
            Ok(i64::try_from(v).unwrap_or(i64::MAX))
        } else {
            Err(err(code, k))
        }
    };
    let ttl = "config/oauth_ttl_out_of_range";
    let bad = "config/invalid_value";
    Ok(crate::oauth::OAuthConfig {
        enabled,
        access_ttl_secs: ranged(OAUTH_ACCESS_TTL_SECS, 900, 60, 3600, ttl)?,
        refresh_idle_secs: ranged(OAUTH_REFRESH_IDLE_DAYS, 14, 1, 30, ttl)? * 86_400,
        grant_max_secs: ranged(OAUTH_GRANT_MAX_DAYS, 90, 1, 90, ttl)? * 86_400,
        register_per_ip_hour: u32::try_from(ranged(OAUTH_REGISTER_PER_IP_HOUR, 10, 1, 100, bad)?)
            .unwrap_or(100),
        max_clients: u64::try_from(ranged(OAUTH_MAX_CLIENTS, 1000, 10, 100_000, bad)?)
            .unwrap_or(100_000),
    })
}

/// The M14 script keys: `ATLAS_DUCK_SCRIPTS` `enabled|disabled`, an absolute
/// `ATLAS_DUCK_SANDBOX_BIN` (its file is checked at serve start), the two server-wide pools
/// 1..=32 (`config/script_limits_out_of_range`).
fn scripts_config(
    get: &dyn Fn(&str) -> Option<String>,
    num: &dyn Fn(&'static str, u64) -> Result<u64, ConfigError>,
) -> Result<crate::scripts::ScriptsConfig, ConfigError> {
    let enabled = match get(SCRIPTS).as_deref() {
        None | Some("enabled") => true,
        Some("disabled") => false,
        Some(_) => return Err(err("config/invalid_value", SCRIPTS)),
    };
    let sandbox_bin = PathBuf::from(
        get(SANDBOX_BIN).unwrap_or_else(|| crate::scripts::ScriptsConfig::DEFAULT_BIN.into()),
    );
    if !sandbox_bin.has_root() {
        return Err(err("config/sandbox_bin_invalid", SANDBOX_BIN));
    }
    let pool = |k: &'static str| -> Result<usize, ConfigError> {
        let v = num(k, 4)?;
        if (1..=32).contains(&v) {
            usize::try_from(v).map_err(|_| err("config/script_limits_out_of_range", k))
        } else {
            Err(err("config/script_limits_out_of_range", k))
        }
    };
    Ok(crate::scripts::ScriptsConfig {
        enabled,
        sandbox_bin,
        runs_max: pool(SCRIPT_RUNS_MAX)?,
        dry_runs_max: pool(SCRIPT_DRY_RUNS_MAX)?,
    })
}

/// `HH:MM` (24 h) as `(hour, minute)`.
fn hh_mm(v: &str) -> Option<(u32, u32)> {
    let (h, m) = v.split_once(':')?;
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    let (h, m): (u32, u32) = (h.parse().ok()?, m.parse().ok()?);
    (h < 24 && m < 60).then_some((h, m))
}

/// `https://host[:port]` without path or query; `dev` also allows plain HTTP on localhost.
fn public_url(raw: &str, mode: Mode) -> Result<Url, ConfigError> {
    let bad = || err("config/public_url_invalid", PUBLIC_URL);
    let url = Url::parse(raw).map_err(|_| bad())?;
    let host = url.host_str().ok_or_else(bad)?;
    let bare = (url.path() == "/" || url.path().is_empty())
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    if !bare {
        return Err(bad());
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if mode == Mode::Dev && (host == "localhost" || host == "127.0.0.1") => Ok(url),
        _ => Err(bad()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct Env {
        vars: HashMap<String, String>,
        _dir: tempfile::TempDir,
    }

    impl Env {
        /// A complete LDAP configuration over a real temp data dir.
        fn ok() -> Env {
            let dir = tempfile::tempdir().unwrap();
            let mut vars = HashMap::new();
            for (k, v) in [
                (MODE, "production"),
                (PUBLIC_URL, "https://duck.example.test"),
                (MASTER_KEY_FILE, "/run/secrets/master-key"),
                (LDAP_URL, "ldaps://dc.example.test:636"),
                (LDAP_UPN_SUFFIX, "@example.test"),
                (LDAP_BASE_DN, "dc=example,dc=test"),
                (GROUP_USERS, "cn=duck-users,dc=example,dc=test"),
            ] {
                vars.insert(k.to_owned(), v.to_owned());
            }
            vars.insert(DATA_DIR.to_owned(), dir.path().display().to_string());
            Env { vars, _dir: dir }
        }

        fn set(mut self, k: &str, v: &str) -> Env {
            self.vars.insert(k.to_owned(), v.to_owned());
            self
        }

        fn unset(mut self, k: &str) -> Env {
            self.vars.remove(k);
            self
        }

        fn load(&self) -> Result<Config, ConfigError> {
            Config::from_env(&|k| self.vars.get(k).cloned(), &|| {
                self.vars.keys().cloned().collect()
            })
        }
    }

    fn code(e: Env) -> (&'static str, &'static str) {
        let err = e.load().unwrap_err();
        (err.code, err.key)
    }

    #[test]
    fn defaults_applied() {
        let c = Env::ok().load().unwrap();
        assert_eq!(c.mode, Mode::Production);
        assert_eq!(c.listen, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(c.web_dir, PathBuf::from("/app/web"));
        assert_eq!(c.trusted_proxy_hops, 1);
        assert_eq!(c.max_open_users, 200);
        assert_eq!((c.login_limit_user, c.login_limit_ip), (5, 20));
        assert_eq!(c.login_window, Duration::from_secs(900));
        assert_eq!(c.session_absolute, Duration::from_secs(28_800));
        assert_eq!(c.session_idle, Duration::from_secs(1_800));
        assert_eq!(c.anchor_interval, Duration::from_secs(900));
        assert_eq!(c.rust_log, "info");
        assert_eq!(c.admin_socket, PathBuf::from("/run/atlas-duck/admin.sock"));
        assert_eq!(c.ca_bundle_file, None);
        assert_eq!(c.master_key_next_file, None);
        assert_eq!(c.offboarding_at, (2, 0));
        assert_eq!(c.retention_days, 365);
        assert_eq!(c.service_bind, None);
        assert_eq!(c.groups.auditors, None);
        assert_eq!(c.public_origin(), "https://duck.example.test");
        assert!(c.cookie_secure());
        assert!(matches!(c.directory, DirectoryConfig::Ldap { .. }));
    }

    #[test]
    fn each_required_key_missing_names_it() {
        for k in [
            MODE,
            PUBLIC_URL,
            DATA_DIR,
            MASTER_KEY_FILE,
            LDAP_URL,
            LDAP_UPN_SUFFIX,
            LDAP_BASE_DN,
            GROUP_USERS,
        ] {
            assert_eq!(code(Env::ok().unset(k)), ("config/missing_key", k), "{k}");
            // An empty value is the same as unset.
            assert_eq!(code(Env::ok().set(k, "")), ("config/missing_key", k), "{k}");
        }
    }

    #[test]
    fn ldap_keys_not_needed_with_the_stub() {
        let c = Env::ok()
            .set(MODE, "review")
            .set(TEST_DIRECTORY_FILE, "/etc/duck/users.json")
            .unset(LDAP_URL)
            .unset(LDAP_UPN_SUFFIX)
            .unset(LDAP_BASE_DN)
            .load()
            .unwrap();
        assert_eq!(
            c.directory,
            DirectoryConfig::Stub {
                file: PathBuf::from("/etc/duck/users.json")
            }
        );
    }

    #[test]
    fn refusals_table() {
        let cases: Vec<(Env, (&str, &str))> = vec![
            (Env::ok().set(MODE, "prod"), ("config/invalid_mode", MODE)),
            (
                Env::ok().set(LDAP_URL, "ldap://dc.example.test"),
                ("config/ldap_url_not_ldaps", LDAP_URL),
            ),
            (
                Env::ok().set(TEST_DIRECTORY_FILE, "/x.json"),
                ("config/test_directory_in_production", TEST_DIRECTORY_FILE),
            ),
            (
                Env::ok().set("ATLAS_DUCK_MASTER_KEY", "x"),
                ("config/master_key_in_env", MASTER_KEY_FILE),
            ),
            (
                Env::ok().set("OTHER_master_key", "x"),
                ("config/master_key_in_env", MASTER_KEY_FILE),
            ),
            (
                Env::ok().set(ANCHOR_INTERVAL_SECS, "901"),
                ("config/anchor_interval_too_long", ANCHOR_INTERVAL_SECS),
            ),
            (
                Env::ok()
                    .set(MODE, "review")
                    .set(PUBLIC_URL, "http://duck.example.test"),
                ("config/public_url_invalid", PUBLIC_URL),
            ),
            (
                Env::ok().set(PUBLIC_URL, "https://duck.example.test/app"),
                ("config/public_url_invalid", PUBLIC_URL),
            ),
            (
                Env::ok().set(PUBLIC_URL, "https://duck.example.test/?q=1"),
                ("config/public_url_invalid", PUBLIC_URL),
            ),
            (
                Env::ok()
                    .set(MODE, "dev")
                    .set(PUBLIC_URL, "http://duck.example.test:8080"),
                ("config/public_url_invalid", PUBLIC_URL),
            ),
            (
                Env::ok().set(DATA_DIR, "/no/such/dir/for/m12"),
                ("config/data_dir_invalid", DATA_DIR),
            ),
            (
                Env::ok().set(LDAP_UPN_SUFFIX, "example.test"),
                ("config/invalid_value", LDAP_UPN_SUFFIX),
            ),
            (
                Env::ok().set(LISTEN, "nope"),
                ("config/invalid_value", LISTEN),
            ),
            (
                Env::ok().set(SESSION_IDLE_SECS, "0"),
                ("config/invalid_value", SESSION_IDLE_SECS),
            ),
        ];
        for (env, want) in cases {
            assert_eq!(code(env), want);
        }
    }

    #[test]
    fn oauth_keys_defaults_and_ranges() {
        let c = Env::ok().load().unwrap();
        assert_eq!(c.oauth, crate::oauth::OAuthConfig::DEFAULT);
        let c = Env::ok()
            .set(OAUTH, "disabled")
            .set(OAUTH_ACCESS_TTL_SECS, "60")
            .set(OAUTH_REFRESH_IDLE_DAYS, "30")
            .set(OAUTH_GRANT_MAX_DAYS, "1")
            .set(OAUTH_REGISTER_PER_IP_HOUR, "100")
            .set(OAUTH_MAX_CLIENTS, "10")
            .load()
            .unwrap();
        assert!(!c.oauth.enabled);
        assert_eq!(
            (
                c.oauth.access_ttl_secs,
                c.oauth.refresh_idle_secs,
                c.oauth.grant_max_secs
            ),
            (60, 30 * 86_400, 86_400)
        );
        assert_eq!(
            (c.oauth.register_per_ip_hour, c.oauth.max_clients),
            (100, 10)
        );
        for (k, v, want) in [
            (OAUTH, "on", "config/invalid_value"),
            (OAUTH_ACCESS_TTL_SECS, "59", "config/oauth_ttl_out_of_range"),
            (
                OAUTH_ACCESS_TTL_SECS,
                "3601",
                "config/oauth_ttl_out_of_range",
            ),
            (
                OAUTH_REFRESH_IDLE_DAYS,
                "0",
                "config/oauth_ttl_out_of_range",
            ),
            (
                OAUTH_REFRESH_IDLE_DAYS,
                "31",
                "config/oauth_ttl_out_of_range",
            ),
            (OAUTH_GRANT_MAX_DAYS, "91", "config/oauth_ttl_out_of_range"),
            (OAUTH_REGISTER_PER_IP_HOUR, "101", "config/invalid_value"),
            (OAUTH_MAX_CLIENTS, "9", "config/invalid_value"),
            (OAUTH_MAX_CLIENTS, "x", "config/invalid_value"),
        ] {
            assert_eq!(code(Env::ok().set(k, v)), (want, k), "{k}={v}");
        }
    }

    #[test]
    fn script_keys_defaults_ranges_and_the_degraded_refusal() {
        let c = Env::ok().load().unwrap();
        assert_eq!(c.scripts, crate::scripts::ScriptsConfig::defaults());
        assert_eq!(
            c.scripts.sandbox_bin,
            PathBuf::from("/app/atlas-duck-sandbox")
        );
        let c = Env::ok()
            .set(SCRIPTS, "disabled")
            .set(SANDBOX_BIN, "/opt/worker")
            .set(SCRIPT_RUNS_MAX, "32")
            .set(SCRIPT_DRY_RUNS_MAX, "1")
            .load()
            .unwrap();
        assert!(!c.scripts.enabled);
        assert_eq!(c.scripts.sandbox_bin, PathBuf::from("/opt/worker"));
        assert_eq!((c.scripts.runs_max, c.scripts.dry_runs_max), (32, 1));
        // M14 PD-254: the export keys.
        let d = Env::ok().load().unwrap();
        assert_eq!((d.exports.ttl_secs, d.exports.max_concurrent), (86_400, 2));
        let e = Env::ok()
            .set(EXPORT_TTL_HOURS, "168")
            .set(EXPORT_MAX_CONCURRENT, "8")
            .load()
            .unwrap();
        assert_eq!(
            (e.exports.ttl_secs, e.exports.max_concurrent),
            (168 * 3600, 8)
        );
        for (k, v) in [
            (EXPORT_TTL_HOURS, "0"),
            (EXPORT_TTL_HOURS, "169"),
            (EXPORT_MAX_CONCURRENT, "0"),
            (EXPORT_MAX_CONCURRENT, "9"),
            (EXPORT_MAX_CONCURRENT, "x"),
        ] {
            assert_eq!(
                Env::ok().set(k, v).load().unwrap_err(),
                ConfigError {
                    code: "config/invalid_value",
                    key: k
                },
                "{k}={v}"
            );
        }
        for (k, v, want) in [
            (SCRIPTS, "on", "config/invalid_value"),
            (SANDBOX_BIN, "relative/worker", "config/sandbox_bin_invalid"),
            (SCRIPT_RUNS_MAX, "0", "config/script_limits_out_of_range"),
            (SCRIPT_RUNS_MAX, "33", "config/script_limits_out_of_range"),
            (
                SCRIPT_DRY_RUNS_MAX,
                "40",
                "config/script_limits_out_of_range",
            ),
            (
                "ATLAS_DUCK_ALLOW_DEGRADED_SCRIPTS",
                "1",
                "config/degraded_scripts_refused",
            ),
            ("my_allow_degraded", "x", "config/degraded_scripts_refused"),
        ] {
            let got = code(Env::ok().set(k, v));
            assert_eq!(got.0, want, "{k}={v}");
        }
    }

    #[test]
    fn dev_localhost_http_accepted_without_secure_cookie() {
        for url in ["http://localhost:8080", "http://127.0.0.1:8080"] {
            let c = Env::ok()
                .set(MODE, "dev")
                .set(PUBLIC_URL, url)
                .load()
                .unwrap();
            assert!(!c.cookie_secure(), "{url}");
            assert_eq!(c.public_origin(), url);
        }
        // `dev` with https keeps Secure.
        let c = Env::ok().set(MODE, "dev").load().unwrap();
        assert!(c.cookie_secure());
    }

    #[test]
    fn config_error_shows_code_and_key_only() {
        let e = Env::ok()
            .set("ATLAS_DUCK_MASTER_KEY", "c2VjcmV0LWtleS1tYXRlcmlhbA==")
            .load()
            .unwrap_err();
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains("c2VjcmV0"), "{shown}");
        assert_eq!(
            e.to_string(),
            "config/master_key_in_env ATLAS_DUCK_MASTER_KEY_FILE"
        );
    }

    #[test]
    fn service_bind_dn_without_password_file_is_config_error() {
        let dn = "cn=svc,dc=example,dc=test";
        assert_eq!(
            code(Env::ok().set(SERVICE_BIND_DN, dn)),
            ("config/service_bind_incomplete", SERVICE_BIND_PASSWORD_FILE)
        );
        assert_eq!(
            code(Env::ok().set(SERVICE_BIND_PASSWORD_FILE, "/run/secrets/p")),
            ("config/service_bind_incomplete", SERVICE_BIND_DN)
        );
        let c = Env::ok()
            .set(SERVICE_BIND_DN, dn)
            .set(SERVICE_BIND_PASSWORD_FILE, "/run/secrets/p")
            .load()
            .unwrap();
        assert_eq!(
            c.service_bind,
            Some(ServiceBind {
                dn: dn.into(),
                password_file: PathBuf::from("/run/secrets/p"),
            })
        );
    }

    #[test]
    fn offboarding_time_and_retention_days() {
        let c = Env::ok()
            .set(OFFBOARDING_AT, "23:59")
            .set(RETENTION_DAYS, "30")
            .load()
            .unwrap();
        assert_eq!((c.offboarding_at, c.retention_days), ((23, 59), 30));
        for bad in ["24:00", "2:00", "02:60", "0200", "ab:cd", "02:00:00"] {
            assert_eq!(
                code(Env::ok().set(OFFBOARDING_AT, bad)),
                ("config/invalid_value", OFFBOARDING_AT),
                "{bad}"
            );
        }
        for bad in ["0", "36501", "-1", "x"] {
            assert_eq!(
                code(Env::ok().set(RETENTION_DAYS, bad)),
                ("config/invalid_value", RETENTION_DAYS),
                "{bad}"
            );
        }
    }
}
