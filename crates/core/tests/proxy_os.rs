//! V17: the per-OS readers' parsing and mapping, against literal strings, fake registries and
//! temp files. Nothing here reads the machine's real proxy settings.

use std::collections::HashMap;

use atlas_duck_core::proxy::OsProxy;
use atlas_duck_core::proxy::os_linux::{
    GsOutcome, Gsettings, child_env, gsettings_command, parse_gvariant_strings, parse_kioslaverc,
    read_with,
};
use atlas_duck_core::proxy::os_macos::{MacSettings, from_settings};
use atlas_duck_core::proxy::os_windows::{
    RegistryReader, parse_proxy_override, parse_proxy_server, read_with as read_windows,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct FakeRegistry {
    dwords: HashMap<&'static str, u32>,
    strings: HashMap<&'static str, &'static str>,
    conn: Option<Vec<u8>>,
}

impl RegistryReader for FakeRegistry {
    fn dword(&self, _: &str, name: &str) -> Option<u32> {
        self.dwords.get(name).copied()
    }
    fn string(&self, _: &str, name: &str) -> Option<String> {
        self.strings.get(name).map(|s| (*s).to_owned())
    }
    fn binary(&self, _: &str, name: &str) -> Option<Vec<u8>> {
        if name == "DefaultConnectionSettings" {
            self.conn.clone()
        } else {
            None
        }
    }
}

#[test]
fn v17_windows_registry_reader() {
    assert_eq!(
        parse_proxy_server("http=a:1;https=b:2"),
        Some(("b".to_owned(), 2))
    );
    assert_eq!(parse_proxy_server("c:3"), Some(("c".to_owned(), 3)));
    assert_eq!(
        parse_proxy_server("http=a:1;https=https://b:2/"),
        Some(("b".to_owned(), 2))
    );
    assert_eq!(parse_proxy_server("http=a:1;ftp=f:3"), None);
    assert_eq!(parse_proxy_server(""), None);
    assert_eq!(
        parse_proxy_override("*.corp;<local>"),
        ["*.corp", "<local>"]
    );

    let mut reg = FakeRegistry::default();
    reg.dwords.insert("ProxyEnable", 1);
    reg.strings.insert("ProxyServer", "http=a:1;https=b:2");
    reg.strings.insert("ProxyOverride", "*.corp;<local>");
    let r = read_windows(&reg);
    assert_eq!(r.https, Some(("b".to_owned(), 2)));
    assert_eq!(r.bypass.len(), 2);
    assert!(!r.pac_configured);

    // A disabled proxy server is ignored.
    reg.dwords.insert("ProxyEnable", 0);
    assert_eq!(read_windows(&reg).https, None);

    // AutoConfigURL, or the WPAD bit in DefaultConnectionSettings byte 8.
    let mut pac = FakeRegistry::default();
    pac.strings.insert("AutoConfigURL", "http://wpad/proxy.pac");
    assert!(read_windows(&pac).pac_configured);
    let mut wpad = FakeRegistry {
        conn: Some(vec![0x46, 0, 0, 0, 1, 0, 0, 0, 0x09, 0, 0, 0]),
        ..FakeRegistry::default()
    };
    assert!(read_windows(&wpad).pac_configured);
    wpad.conn = Some(vec![0x46, 0, 0, 0, 1, 0, 0, 0, 0x01, 0, 0, 0]);
    assert!(!read_windows(&wpad).pac_configured);
    assert_eq!(read_windows(&FakeRegistry::default()), OsProxy::default());
}

#[test]
fn v17_macos_scdynamicstore_reader() {
    let s = MacSettings {
        https_enable: true,
        https_proxy: Some("p.corp".into()),
        https_port: Some(3128),
        exceptions: vec!["*.local".into(), "169.254/16".into()],
        exclude_simple_hostnames: true,
        ..MacSettings::default()
    };
    let r = from_settings(&s);
    assert_eq!(r.https, Some(("p.corp".to_owned(), 3128)));
    assert_eq!(r.bypass, ["*.local", "169.254/16", "<local>"]);
    assert!(!r.pac_configured);
    let off = MacSettings {
        https_enable: false,
        auto_discovery_enable: true,
        ..s
    };
    let r = from_settings(&off);
    assert_eq!(r.https, None);
    assert!(r.pac_configured);
}

struct FakeGsettings(HashMap<(&'static str, &'static str), &'static str>);

impl Gsettings for FakeGsettings {
    fn get(&self, schema: &str, key: &str) -> GsOutcome {
        self.0
            .iter()
            .find(|((s, k), _)| *s == schema && *k == key)
            .map_or(GsOutcome::Missing, |(_, v)| match *v {
                "FAIL" => GsOutcome::Failed,
                v => GsOutcome::Value(v.to_owned()),
            })
    }
}

fn gnome(mode: &'static str) -> FakeGsettings {
    FakeGsettings(HashMap::from([
        (("org.gnome.system.proxy", "mode"), mode),
        (("org.gnome.system.proxy.https", "host"), "'g.corp'"),
        (("org.gnome.system.proxy.https", "port"), "3128"),
        (
            ("org.gnome.system.proxy", "ignore-hosts"),
            "['localhost', '*.corp']",
        ),
    ]))
}

#[test]
fn v17_linux_gnome_kde_reader() -> TestResult {
    assert_eq!(
        parse_gvariant_strings("['localhost', '*.corp']"),
        ["localhost", "*.corp"]
    );
    assert!(parse_gvariant_strings("@as []").is_empty());

    let kde = "[Other]\nProxyType=3\n[Proxy Settings]\nProxyType=1\nhttpsProxy=http://k.corp:8080\nNoProxyFor=localhost, .corp\n";
    let r = parse_kioslaverc(kde);
    assert_eq!(r.https, Some(("k.corp".to_owned(), 8080)));
    assert_eq!(r.bypass, ["localhost", ".corp"]);
    assert_eq!(
        parse_kioslaverc("[Proxy Settings]\nProxyType=1\nhttpsProxy=k.corp 8080\n").https,
        Some(("k.corp".to_owned(), 8080))
    );
    assert!(parse_kioslaverc("[Proxy Settings]\nProxyType=2\n").pac_configured);
    assert_eq!(
        parse_kioslaverc("[Proxy Settings]\nProxyType=0\n"),
        OsProxy::default()
    );

    let dir = tempfile::tempdir()?;
    let path = dir.path().join("kioslaverc");
    std::fs::write(&path, kde)?;
    let none = FakeGsettings(HashMap::new());
    let kde_proxy = Some(("k.corp".to_owned(), 8080));
    // No gsettings: KDE. A manual GNOME setting wins over KDE.
    assert_eq!(read_with(&none, Some(&path)).https, kde_proxy);
    let r = read_with(&gnome("'manual'"), Some(&path));
    assert_eq!(r.https, Some(("g.corp".to_owned(), 3128)));
    assert_eq!(r.bypass, ["localhost", "*.corp"]);
    assert!(read_with(&gnome("'auto'"), Some(&path)).pac_configured);
    // GNOME mode none falls through to KDE.
    assert_eq!(read_with(&gnome("'none'"), Some(&path)).https, kde_proxy);
    // Nothing anywhere.
    assert_eq!(read_with(&none, None), OsProxy::default());
    let absent = dir.path().join("absent");
    assert_eq!(read_with(&none, Some(&absent)), OsProxy::default());
    Ok(())
}

#[test]
fn v17_gsettings_child_env_uses_passwd_home() {
    use std::ffi::OsString;
    use std::path::Path;
    let ambient = |k: &str| match k {
        "HOME" => Some(OsString::from("/tmp/agent-home")),
        "DBUS_SESSION_BUS_ADDRESS" => Some(OsString::from("unix:path=/run/bus")),
        "XDG_RUNTIME_DIR" => Some(OsString::from("/run/user/1000")),
        "XDG_CONFIG_HOME" => Some(OsString::from("/tmp/agent-cfg")),
        "HTTPS_PROXY" => Some(OsString::from("http://agent:1")),
        _ => None,
    };
    let home = Path::new("/home/real");
    let env = child_env(home, &ambient);
    let names: Vec<&str> = env.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        names,
        ["HOME", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"]
    );
    assert_eq!(env[0].1, OsString::from("/home/real"));

    let cmd = gsettings_command(Path::new("/usr/bin/gsettings"), home, &ambient, "s", "k");
    let set: Vec<(String, String)> = cmd
        .get_envs()
        .filter_map(|(k, v)| Some((k.to_str()?.to_owned(), v?.to_str()?.to_owned())))
        .collect();
    assert_eq!(set.len(), 3);
    assert!(set.contains(&("HOME".to_owned(), "/home/real".to_owned())));
    let args: Vec<_> = cmd.get_args().collect();
    assert_eq!(args, ["get", "s", "k"]);
}

#[test]
fn v17_failed_gsettings_is_flagged_not_cached_as_no_proxy() -> TestResult {
    // A timed-out `mode` read leaves nothing configured: flagged, so it is not cached.
    let failing = FakeGsettings(HashMap::from([(
        ("org.gnome.system.proxy", "mode"),
        "FAIL",
    )]));
    let r = read_with(&failing, None);
    assert!(r.read_failed);
    assert_eq!(r.https, None);
    // A missing schema is a clean "not configured".
    let r = read_with(&FakeGsettings(HashMap::new()), None);
    assert!(!r.read_failed);
    // A failed read does not hide a proxy that KDE did give.
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("kioslaverc");
    std::fs::write(
        &path,
        "[Proxy Settings]\nProxyType=1\nhttpsProxy=k.corp:1\n",
    )?;
    let r = read_with(&failing, Some(&path));
    assert!(!r.read_failed);
    assert_eq!(r.https, Some(("k.corp".to_owned(), 1)));
    Ok(())
}

#[test]
fn v17_kde_kiosk_markers_and_hostile_hosts() {
    let r = parse_kioslaverc(
        "[Proxy Settings][$i]\nProxyType[$i]=1\nhttpsProxy[$i]=http://k.corp:8080\n",
    );
    assert_eq!(r.https, Some(("k.corp".to_owned(), 8080)));
    // Userinfo or a path in an OS-supplied host is refused, not passed on.
    let r = parse_kioslaverc("[Proxy Settings]\nProxyType=1\nhttpsProxy=u@k.corp:8080\n");
    assert_eq!(r.https, None);
    assert_eq!(
        atlas_duck_core::proxy::os_windows::parse_proxy_server("user@p:8080"),
        None
    );
}

#[cfg(target_os = "macos")]
#[test]
fn v17_macos_scdynamicstore_reader_runs() {
    use atlas_duck_core::proxy::{OsProxySource, SystemProxySource, os_macos};
    // Read-only smoke: the FFI returns and the result is internally consistent. It asserts no
    // machine configuration.
    for r in [os_macos::read(), SystemProxySource::new().read()] {
        if let Some((host, port)) = r.https {
            assert!(!host.is_empty() && port != 0);
        }
    }
}
