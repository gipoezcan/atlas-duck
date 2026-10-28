//! Server configuration from the environment, read once at startup (plan "Configuration", T8).
//!
//! `Config::from_env` takes the lookup and the variable list as functions, so tests drive every
//! row of the table without touching the process environment. Key material never comes from
//! here: only the master key's file path does (ADR 0002), and any other `*MASTER_KEY` variable is
//! a startup error.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use atlas_duck_audit::JournalMode;
use atlas_duck_ipc::paths::{
    DataDirResolution, LocalDataDir, check_data_dir, check_data_dir_allowing_network,
};
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
    /// M13 T10: where `/metrics` is served, a listener of its own (`None`: not served).
    pub metrics_listen: Option<SocketAddr>,
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
    /// ADR 0004: the journal mode of `server.db` and every user store. `Delete` (the default)
    /// for a data volume on NFS, which shares no WAL index between hosts.
    pub sqlite_journal: JournalMode,
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
pub const METRICS_LISTEN: &str = "ATLAS_DUCK_METRICS_LISTEN";
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
pub const ADMIN_SOCKET: &str = "ATLAS_DUCK_ADMIN_SOCKET";
pub const OFFBOARDING_AT: &str = "ATLAS_DUCK_OFFBOARDING_AT";
pub const MAX_RESTORE_BYTES: &str = "ATLAS_DUCK_MAX_RESTORE_BYTES";
pub const BACKUP_DIR: &str = "ATLAS_DUCK_BACKUP_DIR";
pub const BACKUP_KEEP: &str = "ATLAS_DUCK_BACKUP_KEEP";
pub const DEFAULT_BACKUP_KEEP: u32 = 14;
pub const SQLITE_JOURNAL: &str = "ATLAS_DUCK_SQLITE_JOURNAL";
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

/// The locality check of every server data directory (ADR 0004): a network filesystem is accepted
/// only with the rollback journal; with WAL the directory must be local, as on the desktop.
pub fn check_dir(path: &Path, journal: JournalMode) -> std::io::Result<DataDirResolution> {
    match journal {
        JournalMode::Delete => check_data_dir_allowing_network(path),
        JournalMode::Wal => check_data_dir(path),
    }
}

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
        let sqlite_journal = match get(SQLITE_JOURNAL).as_deref() {
            None | Some("delete") => JournalMode::Delete,
            Some("wal") => JournalMode::Wal,
            Some(_) => return Err(err("config/invalid_value", SQLITE_JOURNAL)),
        };
        // Unset: no metrics listener (the chart sets 0.0.0.0:9090).
        let metrics_listen = match get(METRICS_LISTEN) {
            None => None,
            Some(v) => Some(
                v.parse()
                    .map_err(|_| err("config/invalid_value", METRICS_LISTEN))?,
            ),
        };
        let data_dir = match check_dir(&PathBuf::from(required(DATA_DIR)?), sqlite_journal) {
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
        if anchor > MAX_ANCHOR_INTERVAL_SECS {
            return Err(err("config/anchor_interval_too_long", ANCHOR_INTERVAL_SECS));
        }
        Ok(Config {
            mode,
            public_url,
            listen,
            metrics_listen,
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
            offboarding_at,
            retention_days,
            max_restore_bytes: positive(MAX_RESTORE_BYTES, DEFAULT_MAX_RESTORE_BYTES)?,
            backup_dir: get(BACKUP_DIR).map(PathBuf::from),
            backup_keep: small(
                BACKUP_KEEP,
                positive(BACKUP_KEEP, u64::from(DEFAULT_BACKUP_KEEP))?,
            )?,
            sqlite_journal,
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
        assert_eq!(c.metrics_listen, None);
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
        assert_eq!(c.sqlite_journal, JournalMode::Delete);
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

    #[test]
    fn metrics_listen_is_off_unless_set() {
        let c = Env::ok()
            .set(METRICS_LISTEN, "0.0.0.0:9090")
            .load()
            .unwrap();
        assert_eq!(c.metrics_listen, Some("0.0.0.0:9090".parse().unwrap()));
        assert_eq!(
            code(Env::ok().set(METRICS_LISTEN, "9090")),
            ("config/invalid_value", METRICS_LISTEN)
        );
    }

    #[test]
    fn sqlite_journal_is_delete_unless_wal_is_asked_for() {
        let c = Env::ok().set(SQLITE_JOURNAL, "wal").load().unwrap();
        assert_eq!(c.sqlite_journal, JournalMode::Wal);
        let c = Env::ok().set(SQLITE_JOURNAL, "delete").load().unwrap();
        assert_eq!(c.sqlite_journal, JournalMode::Delete);
        for bad in ["WAL", "truncate", "memory", "off"] {
            assert_eq!(
                code(Env::ok().set(SQLITE_JOURNAL, bad)),
                ("config/invalid_value", SQLITE_JOURNAL),
                "{bad}"
            );
        }
    }
}
