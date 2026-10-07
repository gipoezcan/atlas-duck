//! Linux tray-host check (§2.5 "Tray host check").
//!
//! At startup the app asks the session bus whether `org.kde.StatusNotifierWatcher`
//! has an owner. The result is held in `AppState` for `APP_START` (§8.3, M2) and
//! `doctor` (§4.7, M4). Off Linux there is no check and the value is `None`
//! (`doctor` reports `null` there, §4.7).

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// `tray_host: present|missing` (§2.5, §4.7, §8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrayHost {
    Present,
    Missing,
}

impl TrayHost {
    /// The spec's wire value, also used for the `tray_host` log field.
    pub const fn as_str(self) -> &'static str {
        match self {
            TrayHost::Present => "present",
            TrayHost::Missing => "missing",
        }
    }
}

/// The D-Bus name whose owner makes a tray host "present" (§2.5).
pub const STATUS_NOTIFIER_WATCHER: &str = "org.kde.StatusNotifierWatcher";

/// Upper bound for the whole check (connect + `NameHasOwner`).
pub const TRAY_HOST_TIMEOUT: Duration = Duration::from_secs(2);

/// Name of the short-lived thread that runs the D-Bus query.
pub const TRAY_HOST_THREAD_NAME: &str = "atlas-duck-tray-host";

/// Log event for the one diagnostic line that carries the result.
pub const LOG_EVENT_TRAY_HOST: &str = "tray_host_checked";

/// Runs the startup check for this process: `Some(..)` on Linux, `None` elsewhere.
pub fn check_tray_host() -> Option<TrayHost> {
    #[cfg(target_os = "linux")]
    {
        let address = session_bus_address_from(&|name| std::env::var_os(name));
        Some(check_tray_host_on(address.as_deref(), TRAY_HOST_TIMEOUT))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Writes the single `event=tray_host_checked tray_host=<present|missing>` line.
/// Nothing is logged off Linux, where there is no check.
pub fn log_tray_host(tray_host: Option<TrayHost>) {
    if let Some(value) = tray_host {
        tracing::info!(event = LOG_EVENT_TRAY_HOST, tray_host = value.as_str());
    }
}

/// The session bus address, resolved like sd-bus does: `DBUS_SESSION_BUS_ADDRESS`
/// if set and non-empty, else `$XDG_RUNTIME_DIR/bus` if that socket exists, else `None`.
#[cfg(target_os = "linux")]
pub fn session_bus_address_from(
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<String> {
    if let Some(value) = env("DBUS_SESSION_BUS_ADDRESS")
        && let Ok(address) = value.into_string()
        && !address.is_empty()
    {
        return Some(address);
    }
    let runtime_dir = env("XDG_RUNTIME_DIR")?;
    if runtime_dir.is_empty() {
        return None;
    }
    let socket = std::path::PathBuf::from(runtime_dir).join("bus");
    if !socket.exists() {
        return None;
    }
    let socket = socket.into_os_string().into_string().ok()?;
    Some(format!("unix:path={}", escape_address_value(&socket)))
}

/// D-Bus address value escaping: bytes outside `[-0-9A-Za-z_/.*]` become `%xx`.
#[cfg(target_os = "linux")]
fn escape_address_value(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.' | b'*') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02x}");
        }
    }
    out
}

/// Asks the bus at `bus_address` whether `org.kde.StatusNotifierWatcher` has an owner.
///
/// `None` (no session bus address at all), a bus that cannot be reached, any D-Bus
/// error and a query that does not answer within `timeout` all yield `Missing`. The
/// query runs on its own thread, so this function returns within `timeout` even if
/// the peer accepts the connection and never answers; such a thread is left detached.
#[cfg(target_os = "linux")]
pub fn check_tray_host_on(bus_address: Option<&str>, timeout: Duration) -> TrayHost {
    let Some(address) = bus_address else {
        return TrayHost::Missing;
    };
    let address = address.to_owned();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let spawned = std::thread::Builder::new()
        .name(TRAY_HOST_THREAD_NAME.to_owned())
        .spawn(move || {
            let _ = tx.send(watcher_has_owner(&address, timeout));
        });
    if spawned.is_err() {
        return TrayHost::Missing;
    }
    match rx.recv_timeout(timeout) {
        Ok(Ok(true)) => TrayHost::Present,
        _ => TrayHost::Missing,
    }
}

#[cfg(target_os = "linux")]
fn watcher_has_owner(address: &str, timeout: Duration) -> zbus::Result<bool> {
    let connection = zbus::blocking::connection::Builder::address(address)?
        .method_timeout(timeout)
        .build()?;
    let bus = zbus::blocking::fdo::DBusProxy::new(&connection)?;
    let name = zbus::names::BusName::try_from(STATUS_NOTIFIER_WATCHER)?;
    Ok(bus.name_has_owner(name)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_host_serializes_as_spec_values() {
        assert_eq!(
            serde_json::to_string(&TrayHost::Present).unwrap(),
            "\"present\""
        );
        assert_eq!(
            serde_json::to_string(&TrayHost::Missing).unwrap(),
            "\"missing\""
        );
        assert_eq!(TrayHost::Present.as_str(), "present");
        assert_eq!(TrayHost::Missing.as_str(), "missing");
    }

    #[test]
    fn constants_match_spec() {
        assert_eq!(STATUS_NOTIFIER_WATCHER, "org.kde.StatusNotifierWatcher");
        assert_eq!(TRAY_HOST_TIMEOUT, Duration::from_secs(2));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn no_check_off_linux() {
        assert_eq!(check_tray_host(), None);
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::super::*;
        use std::ffi::OsString;
        use std::io::{BufRead, BufReader};
        use std::path::PathBuf;
        use std::process::{Child, Command, Stdio};
        use std::time::Instant;

        fn unique_temp_dir(tag: &str) -> PathBuf {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir()
                .join(format!("atlas-duck-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        /// A private `dbus-daemon --session` on its own socket, so the test never
        /// sees a real desktop's watcher and needs no `dbus-run-session` wrapper.
        struct PrivateBus {
            child: Child,
            address: String,
            dir: PathBuf,
        }

        impl PrivateBus {
            fn start() -> PrivateBus {
                let dir = unique_temp_dir("bus");
                let listen = format!("--address=unix:path={}", dir.join("bus").display());
                let mut child = Command::new("dbus-daemon")
                    .args([
                        "--session",
                        "--nofork",
                        "--nopidfile",
                        "--print-address",
                        &listen,
                    ])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("dbus-daemon must be installed (Ubuntu/Fedora package `dbus`)");
                let stdout = child.stdout.take().unwrap();
                let mut line = String::new();
                BufReader::new(stdout).read_line(&mut line).unwrap();
                let address = line.trim().to_owned();
                assert!(
                    address.starts_with("unix:"),
                    "unexpected dbus-daemon address {address:?}"
                );
                PrivateBus {
                    child,
                    address,
                    dir,
                }
            }
        }

        impl Drop for PrivateBus {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }

        #[test]
        fn missing_then_present_then_missing_on_a_private_bus() {
            let bus = PrivateBus::start();
            assert_eq!(
                check_tray_host_on(Some(&bus.address), TRAY_HOST_TIMEOUT),
                TrayHost::Missing
            );

            let watcher = zbus::blocking::connection::Builder::address(bus.address.as_str())
                .unwrap()
                .name(STATUS_NOTIFIER_WATCHER)
                .unwrap()
                .build()
                .unwrap();
            assert_eq!(
                check_tray_host_on(Some(&bus.address), TRAY_HOST_TIMEOUT),
                TrayHost::Present
            );

            drop(watcher);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let now = check_tray_host_on(Some(&bus.address), TRAY_HOST_TIMEOUT);
                if now == TrayHost::Missing {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "name still owned 5 s after the owner disconnected"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        #[test]
        fn unreachable_bus_is_missing_within_bound() {
            let started = Instant::now();
            let result = check_tray_host_on(Some("unix:path=/nonexistent"), TRAY_HOST_TIMEOUT);
            assert_eq!(result, TrayHost::Missing);
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "took {:?}",
                started.elapsed()
            );
        }

        #[test]
        fn silent_peer_is_missing_within_bound() {
            // A socket that accepts and never speaks D-Bus: the handshake would block forever.
            let dir = unique_temp_dir("silent");
            let path = dir.join("bus");
            let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            let _accepting = std::thread::spawn(move || {
                let held: Vec<_> = listener.incoming().take(1).collect();
                std::thread::sleep(Duration::from_secs(30));
                drop(held);
            });
            let address = format!("unix:path={}", path.display());
            let started = Instant::now();
            assert_eq!(
                check_tray_host_on(Some(&address), TRAY_HOST_TIMEOUT),
                TrayHost::Missing
            );
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "took {:?}",
                started.elapsed()
            );
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn no_address_is_missing() {
            assert_eq!(
                check_tray_host_on(None, TRAY_HOST_TIMEOUT),
                TrayHost::Missing
            );
            assert_eq!(session_bus_address_from(&|_| None), None);
        }

        #[test]
        fn address_resolution_follows_sd_bus() {
            let env_addr = |name: &str| {
                (name == "DBUS_SESSION_BUS_ADDRESS").then(|| OsString::from("unix:path=/run/x/bus"))
            };
            assert_eq!(
                session_bus_address_from(&env_addr).as_deref(),
                Some("unix:path=/run/x/bus")
            );

            let runtime = unique_temp_dir("runtime");
            let runtime_for_env = runtime.clone();
            let env_rt = move |name: &str| {
                (name == "XDG_RUNTIME_DIR").then(|| runtime_for_env.clone().into_os_string())
            };
            assert_eq!(
                session_bus_address_from(&env_rt),
                None,
                "no bus socket in XDG_RUNTIME_DIR"
            );

            std::fs::write(runtime.join("bus"), b"").unwrap();
            let expected = format!("unix:path={}/bus", runtime.display());
            assert_eq!(session_bus_address_from(&env_rt), Some(expected));

            let env_blank =
                |name: &str| (name == "DBUS_SESSION_BUS_ADDRESS").then(|| OsString::from(""));
            assert_eq!(session_bus_address_from(&env_blank), None);
            let _ = std::fs::remove_dir_all(&runtime);
        }

        #[test]
        fn check_tray_host_is_some_on_linux() {
            assert!(check_tray_host().is_some());
        }
    }
}
