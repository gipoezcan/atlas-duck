//! `os_keychain_smoke`: the OS keychain entries of a test store are written and read by the
//! `atlas-duck-app` executable only. On macOS a file-keychain item trusts the executable that
//! created it (its ACL and, from 10.12, its partition list by cdhash); another executable that
//! reads it gets the "wants to use your confidential information" prompt, which nobody answers on
//! a CI runner, so an app reading entries the test binary had written blocked in `audit::open`
//! and never bound its endpoint (`launch_timeout`). In production the app is the only process
//! that touches the keychain; this proxy keeps it so in the smoke.
//!
//! `atlas-duck-app __test-os-keystore <install_id>` ([`run_if_requested`], called first in
//! `main`) serves `OsKeyStore` over stdin/stdout, one line per request and per reply:
//!
//! - `get <account>` -> `some <hex>` | `none` | `err <error>`
//! - `set <account> <hex>` -> `ok` | `err <error>`
//! - `delete <account>` -> `ok` | `err <error>`
//! - `locality` -> `local` | `not_local <dir>` | `unknown <reason>`
//!
//! `<account>` is `EntryName::account()`, `<error>` is `unavailable|locked|not_local|corrupt` or
//! `other <text>`. The test harness's [`ProxyKeyStore`] is the client. The serving side refuses
//! anything but a `7e570000` test install id under the test home.

use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use atlas_duck_audit::{EntryName, KeyStore, KeyStoreError, KeyringLocality, OsKeyStore};
use zeroize::Zeroizing;

use super::keystore::{hex_decode, hex_encode};
use super::{ENV_TEST_HOME, test_home_problem};

/// `args[1]` of the proxy mode.
pub const MARKER: &str = "__test-os-keystore";
/// The prefix of every install id the proxy serves (the `os_keystore.rs` test convention).
pub const TEST_INSTALL_ID_PREFIX: &str = "7e570000";
/// How long the client waits for one reply: a keychain prompt fails the call, never hangs it.
pub const REPLY_WAIT: Duration = Duration::from_secs(30);
/// How long the client's drop waits for the proxy to end after closing its stdin.
pub const EXIT_WAIT: Duration = Duration::from_secs(5);

const MSG_USAGE: &str = "atlas-duck-app: usage: __test-os-keystore <7e570000... install id>";
const MSG_BAD_REQUEST: &str = "bad request";
const MSG_BAD_REPLY: &str = "bad keystore proxy reply";
const MSG_ENDED: &str = "the keystore proxy ended (see its stderr)";
const MSG_TIMED_OUT: &str = "the keystore proxy did not reply within 30 s (a keychain prompt?)";

// ---- serving side (the app executable) -------------------------------------------------------

/// `Some(exit code)` when `args[1]` is [`MARKER`]: serves stdin to its end. `None` otherwise.
pub fn run_if_requested(args: &[OsString]) -> Option<i32> {
    if args.get(1).map(OsString::as_os_str) != Some(OsStr::new(MARKER)) {
        return None;
    }
    Some(run(args.get(2..).unwrap_or_default()))
}

fn run(rest: &[OsString]) -> i32 {
    let env = std::env::var_os(ENV_TEST_HOME);
    let home = atlas_duck_ipc::paths::base_dirs().ok().map(|b| b.home);
    if let Some(msg) = test_home_problem(env.as_deref(), home.as_deref()) {
        eprintln!("{msg}");
        return 2;
    }
    let [id] = rest else {
        eprintln!("{MSG_USAGE}");
        return 2;
    };
    let Some(id) = id.to_str().filter(|i| is_test_install_id(i)) else {
        eprintln!("{MSG_USAGE}");
        return 2;
    };
    let ks = match OsKeyStore::new(id) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("atlas-duck-app: __test-os-keystore: OsKeyStore::new: {e}");
            return 1;
        }
    };
    match serve(io::stdin().lock(), io::stdout().lock(), &ks) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// `7e570000` followed by 24 hex digits.
pub fn is_test_install_id(id: &str) -> bool {
    id.len() == 32
        && id.starts_with(TEST_INSTALL_ID_PREFIX)
        && id.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Answers every request line of `input` on `out` until EOF.
pub fn serve<R: BufRead, W: Write>(input: R, mut out: W, ks: &dyn KeyStore) -> io::Result<()> {
    for line in input.lines() {
        let line = Zeroizing::new(line?);
        let reply = Zeroizing::new(handle_line(&line, ks));
        writeln!(out, "{}", reply.as_str())?;
        out.flush()?;
    }
    Ok(())
}

/// The reply to one request line.
pub fn handle_line(line: &str, ks: &dyn KeyStore) -> String {
    let mut parts = line.trim_end_matches('\r').splitn(3, ' ');
    let op = parts.next().unwrap_or_default();
    let entry = parts.next().map(entry_from_account);
    let value = parts.next();
    let bad = || err_reply(&KeyStoreError::Other(MSG_BAD_REQUEST.to_owned()));
    match (op, entry, value) {
        ("locality", None, None) => encode_locality(&ks.locality()),
        ("get", Some(Some(e)), None) => match ks.get(&e) {
            Ok(Some(v)) => format!("some {}", Zeroizing::new(hex_encode(&v)).as_str()),
            Ok(None) => "none".to_owned(),
            Err(err) => err_reply(&err),
        },
        ("set", Some(Some(e)), Some(hex)) => match hex_decode(hex).map(Zeroizing::new) {
            Some(v) => unit_reply(ks.set(&e, &v)),
            None => bad(),
        },
        ("delete", Some(Some(e)), None) => unit_reply(ks.delete(&e)),
        _ => bad(),
    }
}

/// The inverse of `EntryName::account()`.
pub fn entry_from_account(account: &str) -> Option<EntryName> {
    match account {
        "kek" => Some(EntryName::Kek),
        "head_anchor" => Some(EntryName::HeadAnchor),
        "first_retained_anchor" => Some(EntryName::FirstRetainedAnchor),
        "canary" => Some(EntryName::Canary),
        _ => account
            .strip_prefix("pat/")
            .filter(|id| !id.is_empty() && !id.contains(char::is_whitespace))
            .map(|id| EntryName::Pat(id.to_owned())),
    }
}

fn one_line(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}

fn unit_reply(r: Result<(), KeyStoreError>) -> String {
    match r {
        Ok(()) => "ok".to_owned(),
        Err(e) => err_reply(&e),
    }
}

fn err_reply(e: &KeyStoreError) -> String {
    format!("err {}", encode_error(e))
}

pub fn encode_error(e: &KeyStoreError) -> String {
    match e {
        KeyStoreError::Unavailable => "unavailable".to_owned(),
        KeyStoreError::Locked => "locked".to_owned(),
        KeyStoreError::NotLocal => "not_local".to_owned(),
        KeyStoreError::Corrupt => "corrupt".to_owned(),
        KeyStoreError::Other(m) => format!("other {}", one_line(m)),
    }
}

pub fn decode_error(text: &str) -> KeyStoreError {
    match text {
        "unavailable" => KeyStoreError::Unavailable,
        "locked" => KeyStoreError::Locked,
        "not_local" => KeyStoreError::NotLocal,
        "corrupt" => KeyStoreError::Corrupt,
        _ => KeyStoreError::Other(text.strip_prefix("other ").unwrap_or(text).to_owned()),
    }
}

pub fn encode_locality(l: &KeyringLocality) -> String {
    match l {
        KeyringLocality::Local => "local".to_owned(),
        KeyringLocality::NotLocal { dir } => {
            format!("not_local {}", one_line(&dir.to_string_lossy()))
        }
        KeyringLocality::Unknown { reason } => format!("unknown {}", one_line(reason)),
    }
}

/// A reply that is not a locality is `Unknown` (fail closed).
pub fn decode_locality(reply: &str) -> KeyringLocality {
    if reply == "local" {
        return KeyringLocality::Local;
    }
    if let Some(dir) = reply.strip_prefix("not_local ") {
        return KeyringLocality::NotLocal {
            dir: PathBuf::from(dir),
        };
    }
    KeyringLocality::Unknown {
        reason: reply.strip_prefix("unknown ").unwrap_or(reply).to_owned(),
    }
}

pub fn decode_get(reply: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
    if reply == "none" {
        return Ok(None);
    }
    if let Some(hex) = reply.strip_prefix("some ") {
        return hex_decode(hex)
            .map(|v| Some(Zeroizing::new(v)))
            .ok_or_else(|| KeyStoreError::Other(MSG_BAD_REPLY.to_owned()));
    }
    Err(decode_err_reply(reply))
}

pub fn decode_unit(reply: &str) -> Result<(), KeyStoreError> {
    if reply == "ok" {
        return Ok(());
    }
    Err(decode_err_reply(reply))
}

fn decode_err_reply(reply: &str) -> KeyStoreError {
    match reply.strip_prefix("err ") {
        Some(e) => decode_error(e),
        None => KeyStoreError::Other(MSG_BAD_REPLY.to_owned()),
    }
}

// ---- client side (the test harness) ----------------------------------------------------------

struct Proxy {
    child: Child,
    stdin: Option<ChildStdin>,
    replies: Receiver<String>,
    /// A write failed, the proxy ended or a reply timed out: every later call fails.
    broken: bool,
}

/// A `KeyStore` whose every call is served by an `atlas-duck-app __test-os-keystore` process.
pub struct ProxyKeyStore {
    install_id: String,
    inner: Mutex<Proxy>,
}

impl ProxyKeyStore {
    /// Spawns `cmd` (the app executable with [`MARKER`] and `install_id` as its arguments and the
    /// test environment) with piped stdin and stdout; its stderr is inherited.
    pub fn spawn(mut cmd: Command, install_id: &str) -> io::Result<ProxyKeyStore> {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take();
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("the keystore proxy has no stdout pipe"));
        };
        let (tx, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(ProxyKeyStore {
            install_id: install_id.to_owned(),
            inner: Mutex::new(Proxy {
                child,
                stdin,
                replies,
                broken: false,
            }),
        })
    }

    fn call(&self, request: &str) -> Result<Zeroizing<String>, KeyStoreError> {
        let mut p = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if p.broken {
            return Err(KeyStoreError::Other(MSG_ENDED.to_owned()));
        }
        let sent = p
            .stdin
            .as_mut()
            .map(|s| writeln!(s, "{request}").and_then(|()| s.flush()));
        if !matches!(sent, Some(Ok(()))) {
            p.broken = true;
            return Err(KeyStoreError::Other(MSG_ENDED.to_owned()));
        }
        match p.replies.recv_timeout(REPLY_WAIT) {
            Ok(line) => Ok(Zeroizing::new(line)),
            Err(RecvTimeoutError::Timeout) => {
                p.broken = true;
                let _ = p.child.kill();
                Err(KeyStoreError::Other(MSG_TIMED_OUT.to_owned()))
            }
            Err(RecvTimeoutError::Disconnected) => {
                p.broken = true;
                Err(KeyStoreError::Other(MSG_ENDED.to_owned()))
            }
        }
    }
}

impl KeyStore for ProxyKeyStore {
    fn install_id(&self) -> &str {
        &self.install_id
    }

    fn get(&self, e: &EntryName) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        decode_get(&self.call(&format!("get {}", e.account()))?)
    }

    fn set(&self, e: &EntryName, v: &[u8]) -> Result<(), KeyStoreError> {
        let hex = Zeroizing::new(hex_encode(v));
        let request = Zeroizing::new(format!("set {} {}", e.account(), hex.as_str()));
        decode_unit(&self.call(&request)?)
    }

    fn delete(&self, e: &EntryName) -> Result<(), KeyStoreError> {
        decode_unit(&self.call(&format!("delete {}", e.account()))?)
    }

    fn locality(&self) -> KeyringLocality {
        match self.call("locality") {
            Ok(reply) => decode_locality(&reply),
            Err(e) => KeyringLocality::Unknown {
                reason: e.to_string(),
            },
        }
    }
}

impl Drop for ProxyKeyStore {
    /// Closes the proxy's stdin (it ends at EOF), then kills it after [`EXIT_WAIT`].
    fn drop(&mut self) {
        let p = self.inner.get_mut().unwrap_or_else(PoisonError::into_inner);
        drop(p.stdin.take());
        let start = Instant::now();
        while start.elapsed() < EXIT_WAIT {
            if matches!(p.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = p.child.kill();
        let _ = p.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::keystore::{MODE_LOCKED, MODE_NOT_LOCAL, provision, set_mode};

    const ID: &str = "7e5700000123456789abcdef01234567";

    #[test]
    fn only_the_marker_selects_the_proxy() {
        let os = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(run_if_requested(&os(&["atlas-duck-app"])), None);
        assert_eq!(
            run_if_requested(&os(&["atlas-duck-app", "--background"])),
            None
        );
        assert_eq!(
            run_if_requested(&os(&["atlas-duck-app", "__cli", MARKER])),
            None
        );
    }

    #[test]
    fn only_test_install_ids_are_served() {
        assert!(is_test_install_id(ID));
        assert!(!is_test_install_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_test_install_id("7e570000"));
        assert!(!is_test_install_id("7e5700000123456789abcdef0123456z"));
    }

    #[test]
    fn accounts_round_trip() {
        for e in [
            EntryName::Kek,
            EntryName::HeadAnchor,
            EntryName::FirstRetainedAnchor,
            EntryName::Canary,
            EntryName::Pat("0f0e0d0c".to_owned()),
        ] {
            assert_eq!(entry_from_account(&e.account()), Some(e));
        }
        for bad in ["", "pat/", "pat/a b", "KEK", "other"] {
            assert_eq!(entry_from_account(bad), None, "{bad}");
        }
    }

    /// `serve` over a file keystore: what the client decodes is what the store holds.
    #[test]
    fn requests_and_replies_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let ks = provision(dir.path(), ID)?;
        let pat = EntryName::Pat("abc".to_owned());
        let value = [0u8, 1, 0xfe, 0xff, b' ', b'\n'];

        assert_eq!(decode_get(&handle_line("get pat/abc", &ks)), Ok(None));
        let set = format!("set pat/abc {}", hex_encode(&value));
        assert_eq!(decode_unit(&handle_line(&set, &ks)), Ok(()));
        assert_eq!(
            ks.get(&pat)?.as_deref().map(Vec::as_slice),
            Some(&value[..])
        );
        let got = decode_get(&handle_line("get pat/abc", &ks))?;
        assert_eq!(got.as_deref().map(Vec::as_slice), Some(&value[..]));
        assert_eq!(decode_unit(&handle_line("delete pat/abc", &ks)), Ok(()));
        assert_eq!(ks.get(&pat)?, None);
        // Deleting an absent entry is fine.
        assert_eq!(decode_unit(&handle_line("delete pat/abc", &ks)), Ok(()));
        assert_eq!(
            decode_locality(&handle_line("locality", &ks)),
            KeyringLocality::Local
        );

        // The whole loop, as the proxy process runs it.
        let input = format!("{set}\nget pat/abc\r\nlocality\n");
        let mut out = Vec::new();
        serve(input.as_bytes(), &mut out, &ks)?;
        let replies: Vec<&str> = std::str::from_utf8(&out)?.lines().collect();
        assert_eq!(replies.len(), 3, "{replies:?}");
        assert_eq!(decode_unit(replies[0]), Ok(()));
        let got = decode_get(replies[1])?;
        assert_eq!(got.as_deref().map(Vec::as_slice), Some(&value[..]));
        assert_eq!(decode_locality(replies[2]), KeyringLocality::Local);
        Ok(())
    }

    #[test]
    fn errors_and_localities_cross_the_pipe() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let ks = provision(dir.path(), ID)?;
        set_mode(dir.path(), MODE_LOCKED)?;
        assert_eq!(
            decode_get(&handle_line("get kek", &ks)),
            Err(KeyStoreError::Locked)
        );
        assert_eq!(
            decode_unit(&handle_line("set kek 00", &ks)),
            Err(KeyStoreError::Locked)
        );
        set_mode(dir.path(), MODE_NOT_LOCAL)?;
        assert_eq!(
            decode_locality(&handle_line("locality", &ks)),
            KeyringLocality::NotLocal {
                dir: dir.path().to_owned()
            }
        );
        for e in [
            KeyStoreError::Unavailable,
            KeyStoreError::Locked,
            KeyStoreError::NotLocal,
            KeyStoreError::Corrupt,
            KeyStoreError::Other("two\nlines".to_owned()),
        ] {
            let back = decode_err_reply(&err_reply(&e));
            match e {
                KeyStoreError::Other(_) => {
                    assert_eq!(back, KeyStoreError::Other("two lines".to_owned()));
                }
                _ => assert_eq!(back, e),
            }
        }
        assert_eq!(
            decode_locality("unknown no dirs"),
            KeyringLocality::Unknown {
                reason: "no dirs".to_owned()
            }
        );
        Ok(())
    }

    #[test]
    fn malformed_requests_and_replies_are_errors() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let ks = provision(dir.path(), ID)?;
        for line in [
            "",
            "get",
            "get nope",
            "set kek",
            "set kek zz",
            "set kek 0",
            "delete",
            "locality now",
            "drop kek",
        ] {
            assert_eq!(
                decode_unit(&handle_line(line, &ks)),
                Err(KeyStoreError::Other(MSG_BAD_REQUEST.to_owned())),
                "{line:?}"
            );
        }
        let bad = Err(KeyStoreError::Other(MSG_BAD_REPLY.to_owned()));
        assert_eq!(decode_unit(""), bad);
        assert_eq!(decode_unit("okay"), bad);
        assert!(decode_get("some 0").is_err());
        assert!(decode_get("yes").is_err());
        assert!(matches!(
            decode_locality("remote"),
            KeyringLocality::Unknown { .. }
        ));
        Ok(())
    }
}
