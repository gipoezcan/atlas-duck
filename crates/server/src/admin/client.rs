//! `atlas-duck-server admin …` (SM-3.5, SM-8.1): parses the arguments into one [`Request`], sends
//! it over the admin socket of the running server and prints the answer. It reads no
//! configuration but `ATLAS_DUCK_ADMIN_SOCKET` and never opens a store or the master key.
//!
//! Exit codes: 0 done, 1 the operation failed (`admin_error` line with the code on stderr),
//! 2 usage, 3 the server is unreachable.

use std::io::Write;

use serde_json::{Map, Value};

use super::{
    AliasArg, DirArg, InstanceArgs, KeyFileArg, NoArgs, Request, Response, SwitchArg, UsernameArg,
};
use crate::cli::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
use crate::config::{ADMIN_SOCKET, DEFAULT_ADMIN_SOCKET};

pub const EXIT_UNREACHABLE: u8 = 3;

pub const USAGE: &str = "usage: atlas-duck-server admin <command>
  instances list
  instances add --alias A --product jira|confluence --url U [--default] [--ca-org] [--proxy P]
  instances remove --alias A
  users list
  users deactivate <username>
  maintenance on|off
  backup <dir>          (under <data>/backups or the temp directory)
  restore <bundle-dir>  (maintenance on first)
  rotate-master-key --new-key-file <path>
";

/// What argv asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Help,
    Run(Request),
}

/// Parses the arguments after `admin`; `None` is a usage error.
pub fn parse(args: &[String]) -> Option<Parsed> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["--help"] | ["-h"] | ["help"] => Some(Parsed::Help),
        ["instances", "list"] => Some(Parsed::Run(Request::InstancesList(NoArgs {}))),
        ["instances", "remove", "--alias", alias] => {
            Some(Parsed::Run(Request::InstancesRemove(AliasArg {
                alias: (*alias).to_owned(),
            })))
        }
        ["instances", "add", flags @ ..] => parse_add(flags).map(Parsed::Run),
        ["users", "list"] => Some(Parsed::Run(Request::UsersList(NoArgs {}))),
        ["users", "deactivate", name] if !name.starts_with('-') => {
            Some(Parsed::Run(Request::UsersDeactivate(UsernameArg {
                username: (*name).to_owned(),
            })))
        }
        ["maintenance", "on"] => Some(Parsed::Run(Request::Maintenance(SwitchArg { on: true }))),
        ["maintenance", "off"] => Some(Parsed::Run(Request::Maintenance(SwitchArg { on: false }))),
        ["backup", dir] if !dir.starts_with('-') => Some(Parsed::Run(Request::Backup(DirArg {
            dir: (*dir).to_owned(),
        }))),
        ["restore", dir] if !dir.starts_with('-') => Some(Parsed::Run(Request::Restore(DirArg {
            dir: (*dir).to_owned(),
        }))),
        ["rotate-master-key", "--new-key-file", path] if !path.starts_with('-') => {
            Some(Parsed::Run(Request::RotateMasterKey(KeyFileArg {
                new_key_file: (*path).to_owned(),
            })))
        }
        _ => None,
    }
}

fn parse_add(flags: &[&str]) -> Option<Request> {
    let (mut alias, mut product, mut url, mut proxy) = (None, None, None, None);
    let (mut default, mut ca_org) = (false, false);
    let mut it = flags.iter();
    while let Some(f) = it.next() {
        let mut value = || it.next().map(|v| (*v).to_owned());
        match *f {
            "--alias" if alias.is_none() => alias = Some(value()?),
            "--product" if product.is_none() => product = Some(value()?),
            "--url" if url.is_none() => url = Some(value()?),
            "--proxy" if proxy.is_none() => proxy = Some(value()?),
            "--default" => default = true,
            "--ca-org" => ca_org = true,
            _ => return None,
        }
    }
    Some(Request::InstancesAdd(InstanceArgs {
        alias: alias?,
        product: product?,
        url: url?,
        default,
        ca_org,
        proxy,
    }))
}

fn error_line(code: &str) {
    let mut m = Map::new();
    m.insert("event".into(), Value::from("admin_error"));
    m.insert("code".into(), Value::from(code));
    crate::log::stderr_line("error", m);
}

/// Prints an answer's data: a list one JSON line per element, anything else one line.
pub fn print_data(out: &mut dyn Write, data: &Value) {
    match data {
        Value::Array(items) => {
            for v in items {
                let _ = writeln!(out, "{v}");
            }
        }
        v => {
            let _ = writeln!(out, "{v}");
        }
    }
}

/// The exit code of an answer (printing its data or its error).
pub fn finish(resp: &Response) -> u8 {
    if resp.ok {
        if let Some(d) = &resp.data {
            print_data(&mut std::io::stdout(), d);
        }
        EXIT_OK
    } else {
        error_line(resp.error.as_deref().unwrap_or("admin/failed"));
        EXIT_RUNTIME
    }
}

/// Entry point of `atlas-duck-server admin …`.
pub fn run(args: &[String]) -> u8 {
    let req = match parse(args) {
        Some(Parsed::Run(r)) => r,
        Some(Parsed::Help) => {
            let _ = std::io::stdout().write_all(USAGE.as_bytes());
            return EXIT_OK;
        }
        None => {
            let _ = std::io::stderr().write_all(USAGE.as_bytes());
            return EXIT_USAGE;
        }
    };
    let path = std::env::var(ADMIN_SOCKET)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_ADMIN_SOCKET.to_owned());
    match send(std::path::Path::new(&path), &req) {
        Ok(resp) => finish(&resp),
        Err(code) => {
            error_line(code);
            EXIT_UNREACHABLE
        }
    }
}

/// One request over the socket at `path`.
#[cfg(unix)]
pub fn send(path: &std::path::Path, req: &Request) -> Result<Response, &'static str> {
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let mut s = UnixStream::connect(path).map_err(|_| "admin/server_unreachable")?;
    // Backups and rotations take a while; the server answers once the operation is done.
    let _ = s.set_read_timeout(Some(Duration::from_secs(3600)));
    let mut line = serde_json::to_vec(req).map_err(|_| "admin/internal")?;
    line.push(b'\n');
    s.write_all(&line).map_err(|_| "admin/server_unreachable")?;
    let mut buf = Vec::new();
    s.take(16 * 1024 * 1024)
        .read_to_end(&mut buf)
        .map_err(|_| "admin/server_unreachable")?;
    serde_json::from_slice(&buf).map_err(|_| "admin/bad_response")
}

/// No Unix socket on this platform: the admin CLI runs only inside the server's container.
#[cfg(not(unix))]
pub fn send(_path: &std::path::Path, _req: &Request) -> Result<Response, &'static str> {
    Err("admin/unsupported_platform")
}
