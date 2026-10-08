//! Linux: GNOME through `gsettings`, KDE through `~/.config/kioslaverc`. GNOME wins when both
//! are configured. The process environment is never a proxy source (L42, I-20): `gsettings` runs
//! with a cleared environment, the passwd home as `HOME` and the two session-bus variables it
//! needs, and the home directory comes from the passwd database. Everything but the process
//! spawn is plain code so tests cover it on every OS.

use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::OsProxy;

const GSETTINGS_TIMEOUT: Duration = Duration::from_secs(2);
const GSETTINGS_PATHS: [&str; 3] = [
    "/usr/bin/gsettings",
    "/bin/gsettings",
    "/usr/local/bin/gsettings",
];
const SCHEMA_PROXY: &str = "org.gnome.system.proxy";
const SCHEMA_HTTPS: &str = "org.gnome.system.proxy.https";

/// What `gsettings get <schema> <key>` gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GsOutcome {
    /// The raw GVariant text.
    Value(String),
    /// No `gsettings` binary, or it exited non-zero (schema or key not installed): GNOME
    /// proxy settings do not exist here.
    Missing,
    /// Spawn or wait failed, or the 2 s timeout hit: the setting may exist but was not read.
    Failed,
}

pub trait Gsettings {
    fn get(&self, schema: &str, key: &str) -> GsOutcome;
}

/// The variables the `gsettings` child gets, and nothing else. `HOME` is the passwd home, never
/// the process's: GLib locates the dconf user database from it, so an agent that launched the
/// app could otherwise pick the proxy (§4.7, §7.2). The two session-bus variables only help
/// dconf reach its service; they select no proxy.
pub fn child_env(
    passwd_home: &Path,
    ambient: &dyn Fn(&str) -> Option<OsString>,
) -> Vec<(&'static str, OsString)> {
    let mut env = vec![("HOME", passwd_home.as_os_str().to_owned())];
    for var in ["DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"] {
        if let Some(v) = ambient(var) {
            env.push((var, v));
        }
    }
    env
}

/// The `gsettings get` command line with its cleared environment.
pub fn gsettings_command(
    exe: &Path,
    passwd_home: &Path,
    ambient: &dyn Fn(&str) -> Option<OsString>,
    schema: &str,
    key: &str,
) -> Command {
    let mut cmd = Command::new(exe);
    cmd.args(["get", schema, key])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in child_env(passwd_home, ambient) {
        cmd.env(k, v);
    }
    cmd
}

/// The real binary, with a 2 s timeout.
pub struct GsettingsBinary {
    /// The passwd home (`base_dirs().home`).
    pub home: PathBuf,
}

impl Gsettings for GsettingsBinary {
    fn get(&self, schema: &str, key: &str) -> GsOutcome {
        let Some(exe) = GSETTINGS_PATHS.iter().find(|p| Path::new(p).is_file()) else {
            return GsOutcome::Missing;
        };
        let ambient = |k: &str| std::env::var_os(k);
        let mut cmd = gsettings_command(Path::new(exe), &self.home, &ambient, schema, key);
        let Ok(mut child) = cmd.spawn() else {
            return GsOutcome::Failed;
        };
        let deadline = Instant::now() + GSETTINGS_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return GsOutcome::Missing;
                    }
                    let mut out = String::new();
                    let read = child
                        .stdout
                        .take()
                        .map(|mut o| o.read_to_string(&mut out).is_ok());
                    return match read {
                        Some(true) => GsOutcome::Value(out.trim().to_owned()),
                        _ => GsOutcome::Failed,
                    };
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return GsOutcome::Failed;
                }
            }
        }
    }
}

/// The real machine: `gsettings` and `kioslaverc` under the passwd home. Without a passwd home
/// nothing is read and the result says so.
pub fn read() -> OsProxy {
    match atlas_duck_ipc::paths::base_dirs() {
        Ok(d) => read_with(
            &GsettingsBinary {
                home: d.home.clone(),
            },
            Some(&kioslaverc_path(&d.home)),
        ),
        Err(_) => OsProxy {
            read_failed: true,
            ..OsProxy::default()
        },
    }
}

pub fn read_with(gs: &dyn Gsettings, kioslaverc: Option<&Path>) -> OsProxy {
    let (gnome, failed) = read_gnome(gs);
    let mut r = gnome
        .or_else(|| {
            kioslaverc
                .and_then(|p| std::fs::read_to_string(p).ok())
                .map(|text| parse_kioslaverc(&text))
        })
        .unwrap_or_default();
    // A failed `gsettings` call that left nothing configured may hide a proxy.
    r.read_failed = failed && r.https.is_none() && !r.pac_configured;
    r
}

/// The GNOME reading (`None`: nothing configured) and whether any `gsettings` call failed.
fn read_gnome(gs: &dyn Gsettings) -> (Option<OsProxy>, bool) {
    let mut failed = false;
    let mut get = |schema: &str, key: &str| match gs.get(schema, key) {
        GsOutcome::Value(v) => Some(v),
        GsOutcome::Missing => None,
        GsOutcome::Failed => {
            failed = true;
            None
        }
    };
    let mode = get(SCHEMA_PROXY, "mode").map(|s| unquote(&s));
    let r = match mode.as_deref() {
        Some("auto") => Some(OsProxy {
            pac_configured: true,
            ..OsProxy::default()
        }),
        Some("manual") => {
            let host = get(SCHEMA_HTTPS, "host")
                .map(|s| unquote(&s))
                .unwrap_or_default();
            let port = get(SCHEMA_HTTPS, "port")
                .and_then(|s| s.trim().trim_start_matches("uint32 ").parse::<u16>().ok())
                .unwrap_or(0);
            // No fallback to the `http` proxy when the https host is empty: not confirmed
            // against glib-networking (plan handoff), so the conservative reading is direct.
            let https = super::split_host_port(&format!("{host}:{port}"));
            let bypass = get(SCHEMA_PROXY, "ignore-hosts")
                .map(|s| parse_gvariant_strings(&s))
                .unwrap_or_default();
            Some(OsProxy {
                https,
                bypass,
                ..OsProxy::default()
            })
        }
        _ => None,
    };
    (r, failed)
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    for q in ['\'', '"'] {
        if let Some(inner) = s.strip_prefix(q).and_then(|r| r.strip_suffix(q)) {
            return inner.to_owned();
        }
    }
    s.to_owned()
}

/// The string items of a GVariant array text such as `['localhost', '*.corp']` (`@as []` is
/// empty).
pub fn parse_gvariant_strings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\'' && c != '"' {
            continue;
        }
        let mut item = String::new();
        while let Some(d) = chars.next() {
            match d {
                '\\' => item.extend(chars.next()),
                d if d == c => break,
                d => item.push(d),
            }
        }
        out.push(item);
    }
    out
}

/// `[Proxy Settings]` of `kioslaverc`: `ProxyType=1` is manual (`httpsProxy` is `http://h:p` or
/// `h p`), `NoProxyFor` a comma list; `2` (script) and `3` (auto-detect) set `pac_configured`.
/// Kiosk markers (`[Proxy Settings][$i]`, `httpsProxy[$i]`) are accepted; `/etc/xdg/kioslaverc`
/// system defaults are not read.
pub fn parse_kioslaverc(text: &str) -> OsProxy {
    let mut in_section = false;
    let (mut proxy_type, mut https, mut no_proxy) = (0u32, None::<String>, String::new());
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('[') {
            let name = name.split(']').next().unwrap_or_default();
            in_section = name == "Proxy Settings";
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k.trim().split('[').next().unwrap_or_default() {
            "ProxyType" => proxy_type = v.trim().parse().unwrap_or(0),
            "httpsProxy" => https = Some(v.trim().to_owned()),
            "NoProxyFor" => no_proxy = v.trim().to_owned(),
            _ => {}
        }
    }
    match proxy_type {
        1 => OsProxy {
            https: https.and_then(|v| parse_kde_proxy(&v)),
            bypass: no_proxy
                .split(',')
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .map(str::to_owned)
                .collect(),
            ..OsProxy::default()
        },
        2 | 3 => OsProxy {
            pac_configured: true,
            ..OsProxy::default()
        },
        _ => OsProxy::default(),
    }
}

fn parse_kde_proxy(v: &str) -> Option<(String, u16)> {
    let v = v.split_once("://").map_or(v, |(_, rest)| rest);
    let v = v.trim().trim_end_matches('/').replace(' ', ":");
    super::split_host_port(&v)
}

/// Where `read` looks for KDE's file.
pub fn kioslaverc_path(home: &Path) -> PathBuf {
    home.join(".config").join("kioslaverc")
}
