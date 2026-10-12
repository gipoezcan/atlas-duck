//! Linux Secret Service check for `doctor` (PD-30, L39, §4.7).
//!
//! `secret_service: ok|missing|locked` on Linux, `null` elsewhere. The probe asks the session bus
//! whether `org.freedesktop.secrets` has an owner (no owner: `missing`; the name is never
//! activated), then reads the `Locked` property of the collection behind the `default` alias
//! (`true`: `locked`); every other answer is `ok` (PD-30). No session bus, a bus that cannot be
//! reached and a probe that does not finish within [`PROBE_TIMEOUT`] are `missing`. A result is
//! reused for [`CACHE_TTL`].

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The `secret_service` value of `doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretService {
    Ok,
    Missing,
    Locked,
}

impl SecretService {
    /// The wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            SecretService::Ok => "ok",
            SecretService::Missing => "missing",
            SecretService::Locked => "locked",
        }
    }
}

/// Upper bound of one probe (connect, `NameHasOwner`, `ReadAlias`, `Locked`).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a probe result is reused.
pub const CACHE_TTL: Duration = Duration::from_secs(60);

/// The D-Bus name of the Secret Service.
pub const SECRETS_NAME: &str = "org.freedesktop.secrets";

/// Name of the short-lived thread that runs one probe.
#[cfg(target_os = "linux")]
const PROBE_THREAD_NAME: &str = "atlas-duck-secret-service";

/// What `doctor` asks; tests replace it.
pub trait SecretServiceCheck: Send + Sync {
    /// `None` off Linux. May block up to [`PROBE_TIMEOUT`]; callers run it off the async
    /// threads.
    fn check(&self) -> Option<SecretService>;
}

/// The production check: the Linux probe behind a [`CACHE_TTL`] cache; `None` elsewhere.
pub struct CachedSecretService {
    probe: fn() -> Option<SecretService>,
    ttl: Duration,
    cache: Mutex<Option<(Instant, Option<SecretService>)>>,
}

impl CachedSecretService {
    pub fn new() -> CachedSecretService {
        CachedSecretService::with_probe(probe_this_session, CACHE_TTL)
    }

    /// The cache over another probe (tests).
    pub fn with_probe(probe: fn() -> Option<SecretService>, ttl: Duration) -> CachedSecretService {
        CachedSecretService {
            probe,
            ttl,
            cache: Mutex::new(None),
        }
    }
}

impl Default for CachedSecretService {
    fn default() -> Self {
        CachedSecretService::new()
    }
}

impl SecretServiceCheck for CachedSecretService {
    fn check(&self) -> Option<SecretService> {
        // One probe at a time: a second caller waits for the first one's result (at most
        // `PROBE_TIMEOUT`) instead of starting another probe.
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, value)) = *cache
            && at.elapsed() < self.ttl
        {
            return value;
        }
        let value = (self.probe)();
        *cache = Some((Instant::now(), value));
        value
    }
}

/// The probe for this process's session bus: `Some(..)` on Linux, `None` elsewhere.
pub fn probe_this_session() -> Option<SecretService> {
    #[cfg(target_os = "linux")]
    {
        let address = crate::tray_host::session_bus_address_from(&|name| std::env::var_os(name));
        Some(probe_on(address.as_deref(), PROBE_TIMEOUT))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Probes the bus at `bus_address`, bounded by `timeout`. The query runs on its own thread, so
/// this returns within `timeout` even if the bus never answers; such a thread is left detached
/// (the cache keeps the next one at least [`CACHE_TTL`] away).
#[cfg(target_os = "linux")]
pub fn probe_on(bus_address: Option<&str>, timeout: Duration) -> SecretService {
    let Some(address) = bus_address else {
        return SecretService::Missing;
    };
    let address = address.to_owned();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let spawned = std::thread::Builder::new()
        .name(PROBE_THREAD_NAME.to_owned())
        .spawn(move || {
            let _ = tx.send(query(&address, timeout));
        });
    if spawned.is_err() {
        return SecretService::Missing;
    }
    match rx.recv_timeout(timeout) {
        Ok(Ok(value)) => value,
        _ => SecretService::Missing,
    }
}

/// `Err` only when the bus cannot be used or `NameHasOwner` fails (`missing`); once the service
/// has an owner every further failure is `ok` (PD-30: "else ok").
#[cfg(target_os = "linux")]
fn query(address: &str, timeout: Duration) -> zbus::Result<SecretService> {
    let connection = zbus::blocking::connection::Builder::address(address)?
        .method_timeout(timeout)
        .build()?;
    let bus = zbus::blocking::fdo::DBusProxy::new(&connection)?;
    let name = zbus::names::BusName::try_from(SECRETS_NAME)?;
    if !bus.name_has_owner(name)? {
        return Ok(SecretService::Missing);
    }
    Ok(match default_collection_locked(&connection) {
        Ok(true) => SecretService::Locked,
        Ok(false) | Err(_) => SecretService::Ok,
    })
}

/// The `Locked` property of the collection the `default` alias names; `false` when there is
/// no default collection (`ReadAlias` answers `/`).
#[cfg(target_os = "linux")]
fn default_collection_locked(connection: &zbus::blocking::Connection) -> zbus::Result<bool> {
    use zbus::blocking::proxy::Builder;
    use zbus::proxy::CacheProperties;

    let service: zbus::blocking::Proxy<'_> = Builder::<zbus::blocking::Proxy<'_>>::new(connection)
        .destination(SECRETS_NAME)?
        .path("/org/freedesktop/secrets")?
        .interface("org.freedesktop.Secret.Service")?
        .cache_properties(CacheProperties::No)
        .build()?;
    let alias: zbus::zvariant::OwnedObjectPath = service.call("ReadAlias", &("default",))?;
    if alias.as_str() == "/" {
        return Ok(false);
    }
    let collection: zbus::blocking::Proxy<'_> =
        Builder::<zbus::blocking::Proxy<'_>>::new(connection)
            .destination(SECRETS_NAME)?
            .path(alias.as_str())?
            .interface("org.freedesktop.Secret.Collection")?
            .cache_properties(CacheProperties::No)
            .build()?;
    collection.get_property::<bool>("Locked")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[test]
    fn wire_values() {
        assert_eq!(SecretService::Ok.as_str(), "ok");
        assert_eq!(SecretService::Missing.as_str(), "missing");
        assert_eq!(SecretService::Locked.as_str(), "locked");
        assert_eq!(PROBE_TIMEOUT, Duration::from_secs(2));
        assert_eq!(CACHE_TTL, Duration::from_secs(60));
    }

    static CALLS: AtomicU32 = AtomicU32::new(0);

    fn counting_probe() -> Option<SecretService> {
        CALLS.fetch_add(1, Ordering::SeqCst);
        Some(SecretService::Locked)
    }

    #[test]
    fn results_are_cached_for_the_ttl() {
        let cached = CachedSecretService::with_probe(counting_probe, Duration::from_secs(60));
        assert_eq!(cached.check(), Some(SecretService::Locked));
        assert_eq!(cached.check(), Some(SecretService::Locked));
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        let expired = CachedSecretService::with_probe(counting_probe, Duration::ZERO);
        expired.check();
        expired.check();
        assert_eq!(CALLS.load(Ordering::SeqCst), 3);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn null_off_linux() {
        assert_eq!(probe_this_session(), None);
        assert_eq!(CachedSecretService::new().check(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_bus_is_missing() {
        assert_eq!(probe_on(None, PROBE_TIMEOUT), SecretService::Missing);
        // An address nobody listens on.
        let gone = "unix:path=/nonexistent/atlas-duck-test-bus";
        assert_eq!(
            probe_on(Some(gone), Duration::from_millis(500)),
            SecretService::Missing
        );
    }
}
