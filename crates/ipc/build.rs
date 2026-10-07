//! Computes the commit half of `BUILD_ID` (§3.3: "release version + commit, compiled into every binary").
//!
//! Source order: env `ATLAS_DUCK_COMMIT` (CI or a source tarball build may set it), then
//! `git rev-parse HEAD` in this crate's directory, else `unknown`. The result is exactly 12 lowercase
//! hex digits or the word `unknown`; a candidate that is not at least 12 hex digits is ignored.

use std::path::{Path, PathBuf};
use std::process::Command;

const COMMIT_LEN: usize = 12;

fn normalize(candidate: &str) -> Option<String> {
    let c = candidate.trim();
    if c.len() >= COMMIT_LEN && c.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(c[..COMMIT_LEN].to_ascii_lowercase())
    } else {
        None
    }
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_owned())
    }
}

/// Absolute path of a file inside the git dir (`git rev-parse --git-path` may print a relative path).
fn git_path(dir: &Path, name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(git(dir, &["rev-parse", "--git-path", name])?);
    Some(if p.is_absolute() { p } else { dir.join(p) })
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=ATLAS_DUCK_COMMIT");

    let dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());

    // Rebuild when HEAD moves: HEAD itself (checkout, detached CI checkouts), the branch ref, packed
    // refs and refs/heads (first commit on a branch). Only existing paths are watched; a missing path
    // would make cargo rerun this script on every build.
    let mut watch: Vec<PathBuf> = ["HEAD", "packed-refs", "refs/heads"]
        .iter()
        .filter_map(|n| git_path(&dir, n))
        .collect();
    if let Some(head_ref) = git(&dir, &["symbolic-ref", "-q", "HEAD"])
        && let Some(p) = git_path(&dir, &head_ref)
    {
        watch.push(p);
    }
    for p in watch.iter().filter(|p| p.exists()) {
        println!("cargo:rerun-if-changed={}", p.display());
    }

    let commit = std::env::var("ATLAS_DUCK_COMMIT")
        .ok()
        .and_then(|v| normalize(&v))
        .or_else(|| git(&dir, &["rev-parse", "HEAD"]).and_then(|v| normalize(&v)))
        .unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=ATLAS_DUCK_BUILD_COMMIT={commit}");
}
