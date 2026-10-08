//! Linux: GNOME through `gsettings`, KDE through `~/.config/kioslaverc`. GNOME wins when both
//! are configured. The process environment is never a proxy source (L42, I-20): `gsettings` runs
//! with a cleared environment plus the three variables it needs to reach the session bus, and
//! the home directory comes from the passwd database. Everything but the process spawn is plain
//! code so tests cover it on every OS.

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

/// `gsettings get <schema> <key>`: the raw GVariant text, `None` when unavailable.
pub trait Gsettings {
    fn get(&self, schema: &str, key: &str) -> Option<String>;
}

/// The real binary, with a 2 s timeout.
pub struct GsettingsBinary;

impl Gsettings for GsettingsBinary {
    fn get(&self, schema: &str, key: &str) -> Option<String> {
        let exe = GSETTINGS_PATHS.iter().find(|p| Path::new(p).is_file())?;
        let mut cmd = Command::new(exe);
        cmd.args(["get", schema, key])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for var in ["HOME", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"] {
            if let Some(v) = std::env::var_os(var) {
                cmd.env(var, v);
            }
        }
        let mut child = cmd.spawn().ok()?;
        let deadline = Instant::now() + GSETTINGS_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return None;
                    }
                    let mut out = String::new();
                    child.stdout.take()?.read_to_string(&mut out).ok()?;
                    return Some(out.trim().to_owned());
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
    }
}

/// The real machine: `gsettings` and the passwd home.
pub fn read() -> OsProxy {
    let kde = atlas_duck_ipc::paths::base_dirs()
        .ok()
        .map(|d| kioslaverc_path(&d.home));
    read_with(&GsettingsBinary, kde.as_deref())
}

pub fn read_with(gs: &dyn Gsettings, kioslaverc: Option<&Path>) -> OsProxy {
    if let Some(gnome) = read_gnome(gs) {
        return gnome;
    }
    kioslaverc
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|text| parse_kioslaverc(&text))
        .unwrap_or_default()
}

/// `None` when GNOME has no proxy configured (mode absent or `none`).
fn read_gnome(gs: &dyn Gsettings) -> Option<OsProxy> {
    let mode = unquote(&gs.get(SCHEMA_PROXY, "mode")?);
    match mode.as_str() {
        "auto" => Some(OsProxy {
            pac_configured: true,
            ..OsProxy::default()
        }),
        "manual" => {
            let host = gs
                .get(SCHEMA_HTTPS, "host")
                .map(|s| unquote(&s))
                .unwrap_or_default();
            let port = gs
                .get(SCHEMA_HTTPS, "port")
                .and_then(|s| s.trim().trim_start_matches("uint32 ").parse::<u16>().ok())
                .filter(|p| *p != 0);
            let https = match (host.is_empty(), port) {
                (false, Some(p)) => Some((host, p)),
                _ => None,
            };
            let bypass = gs
                .get(SCHEMA_PROXY, "ignore-hosts")
                .map(|s| parse_gvariant_strings(&s))
                .unwrap_or_default();
            Some(OsProxy {
                https,
                bypass,
                pac_configured: false,
            })
        }
        _ => None,
    }
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
pub fn parse_kioslaverc(text: &str) -> OsProxy {
    let mut in_section = false;
    let (mut proxy_type, mut https, mut no_proxy) = (0u32, None::<String>, String::new());
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_section = name == "Proxy Settings";
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k.trim() {
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
            pac_configured: false,
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

/// Where `read` looks for KDE's file, for the report and tests.
pub fn kioslaverc_path(home: &Path) -> PathBuf {
    home.join(".config").join("kioslaverc")
}
