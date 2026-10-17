//! V21 (M8 Task 10, §3.4 "Binary identity re-check", PD-133, §15 V21): a worker binary that was
//! replaced after the probe is detected before the next spawn, per OS.
//!
//! The "install dir" is a scratch directory with a copy of the built worker; the identity is
//! recorded from it as the probe does (file id, size, mtime, embedded version), the copy is
//! replaced, and `start_run` / `compile_run` must answer `IdentityMismatch` with nothing spawned
//! (the spawner here counts its calls and never starts anything: no execution is needed for the
//! file checks). Cases:
//!
//! - `copy_over` (every OS): the copy gets one appended zero byte, the same file with other
//!   bytes (`via=size`);
//! - `rename_over` (every OS): a new file renamed into place, a new inode / file index
//!   (`via=file_id`);
//! - macOS only, inside a copied `.app` bundle: `app_bundle_copy_over` (the worker file in the
//!   bundle is overwritten, `via=size`) and `app_bundle_rename_over` (a real upgrade's shape: the
//!   old bundle is moved aside and a new bundle renamed into its place, `via=file_id`).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::sandbox::script::WorkerInit;
use atlas_duck_ipc::sandbox::{HostCall, HostCallResult, ScriptLimits};
use atlas_duck_sandbox_host::bridge::{
    ExpectedWorker, HostCallSink, StartRunError, compile_run, start_run,
};
use atlas_duck_sandbox_host::identity::{IdentityPart, SandboxBinaryIdentity, file_identity};
use atlas_duck_sandbox_host::spawn::{SpawnSpec, WorkerProcess, WorkerSpawner};
use serde_json::json;

use super::*;

/// Counts spawn calls and never starts a process.
#[derive(Default)]
struct NeverSpawns {
    calls: AtomicU32,
}

impl WorkerSpawner for NeverSpawns {
    fn spawn(&self, _spec: &SpawnSpec) -> io::Result<Box<dyn WorkerProcess>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("V21: the spawner must not be reached"))
    }
}

struct NoCalls;

#[async_trait]
impl HostCallSink for NoCalls {
    async fn call(&self, _run_id: &str, _c: HostCall) -> HostCallResult {
        HostCallResult::Ok(json!(null))
    }

    fn log(&self, _run_id: &str, _line: &str) {}
}

/// A scratch directory under cargo's test tmp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(case: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("v21-{}-{case}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        Ok(Scratch(dir))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn via(part: IdentityPart) -> &'static str {
    match part {
        IdentityPart::FileId => "file_id",
        IdentityPart::Size => "size",
        IdentityPart::Mtime => "mtime",
        IdentityPart::Missing => "missing",
        IdentityPart::EmbeddedVersion => "embedded_version",
    }
}

fn recorded(exe: &Path) -> Result<ExpectedWorker, Box<dyn std::error::Error>> {
    let (file_id, size, mtime) = file_identity(exe)?;
    Ok(ExpectedWorker {
        identity: SandboxBinaryIdentity {
            file_id,
            size,
            mtime,
            embedded_version: BUILD_ID.to_owned(),
        },
        accept_unconfined: false,
    })
}

/// The next `start_run` and the next `compile_run` on `exe` against `expect` must both refuse
/// with an identity mismatch and spawn nothing. Returns the part that differed.
fn assert_refused(
    exe: &Path,
    expect: &ExpectedWorker,
) -> Result<IdentityPart, Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;
    let spawner = NeverSpawns::default();
    let spec = SpawnSpec {
        exe: exe.to_path_buf(),
        process_mb: DEFAULT_PROCESS_MB,
    };
    let init = WorkerInit {
        source: "async function main() { return 1; }".to_owned(),
        args: json!({}),
        limits: ScriptLimits::default(),
        read_op_ids: Vec::new(),
        instances: Vec::new(),
    };
    let run = start_run(
        &spawner,
        &spec,
        expect,
        init,
        Arc::new(NoCalls),
        rt.handle().clone(),
    );
    let what = match run {
        Err(StartRunError::IdentityMismatch { what }) => what,
        Err(other) => return Err(format!("start_run: {other:?}, not an identity mismatch").into()),
        Ok(_) => return Err("start_run accepted a replaced binary".into()),
    };
    let compiled = compile_run(
        &spawner,
        &spec,
        expect,
        "async function main() { return 1; }",
        WAIT,
    );
    assert_eq!(
        compiled,
        Err(StartRunError::IdentityMismatch { what }),
        "compile_run must refuse the same way"
    );
    assert_eq!(spawner.calls.load(Ordering::SeqCst), 0, "nothing spawned");
    Ok(what)
}

fn report(case: &str, what: IdentityPart) {
    println!(
        "V21 os={} case={case} detected=true via={}",
        std::env::consts::OS,
        via(what)
    );
}

/// A copy of the built worker as `dir/<name>`.
fn install_copy(dir: &Path, name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    fs::create_dir_all(dir)?;
    let path = dir.join(name);
    fs::copy(worker_exe(), &path)?;
    Ok(path)
}

fn append_zero(path: &Path) -> io::Result<()> {
    fs::OpenOptions::new()
        .append(true)
        .open(path)?
        .write_all(&[0])
}

fn worker_name() -> String {
    worker_exe()
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "atlas-duck-sandbox".to_owned())
}

#[test]
fn v21_replaced_binary_detected_per_os() -> TestResult {
    if !harness::opted_in("v21_replaced_binary_detected_per_os") {
        return Ok(());
    }
    let name = worker_name();

    // The control: the untouched copy passes the check.
    {
        let scratch = Scratch::new("control")?;
        let exe = install_copy(&scratch.0, &name)?;
        let expect = recorded(&exe)?;
        atlas_duck_sandbox_host::identity::recheck(&expect.identity, &exe)
            .map_err(|m| format!("the untouched copy was refused: {m}"))?;
    }

    {
        let scratch = Scratch::new("copy-over")?;
        let exe = install_copy(&scratch.0, &name)?;
        let expect = recorded(&exe)?;
        append_zero(&exe)?;
        let what = assert_refused(&exe, &expect)?;
        assert_eq!(what, IdentityPart::Size);
        report("copy_over", what);
    }

    {
        let scratch = Scratch::new("rename-over")?;
        let exe = install_copy(&scratch.0, &name)?;
        let expect = recorded(&exe)?;
        let next = install_copy(&scratch.0.join("next"), &name)?;
        append_zero(&next)?;
        fs::rename(&next, &exe)?;
        let what = assert_refused(&exe, &expect)?;
        assert_eq!(what, IdentityPart::FileId);
        report("rename_over", what);
    }

    #[cfg(target_os = "macos")]
    {
        let bundle_dir = |root: &Path| root.join("Atlas Duck.app/Contents/MacOS");

        let scratch = Scratch::new("bundle-copy-over")?;
        let exe = install_copy(&bundle_dir(&scratch.0), &name)?;
        let expect = recorded(&exe)?;
        append_zero(&exe)?;
        let what = assert_refused(&exe, &expect)?;
        assert_eq!(what, IdentityPart::Size);
        report("app_bundle_copy_over", what);

        let scratch = Scratch::new("bundle-rename-over")?;
        let exe = install_copy(&bundle_dir(&scratch.0), &name)?;
        let expect = recorded(&exe)?;
        // A real upgrade: the new bundle is built next to the old one, the old one is moved
        // aside (a non-empty directory cannot be renamed over) and the new one takes its place.
        let new_root = scratch.0.join("new");
        let new_exe = install_copy(&bundle_dir(&new_root), &name)?;
        append_zero(&new_exe)?;
        fs::rename(
            scratch.0.join("Atlas Duck.app"),
            scratch.0.join("Atlas Duck.app.old"),
        )?;
        fs::rename(
            new_root.join("Atlas Duck.app"),
            scratch.0.join("Atlas Duck.app"),
        )?;
        let what = assert_refused(&exe, &expect)?;
        assert_eq!(what, IdentityPart::FileId);
        report("app_bundle_rename_over", what);
    }
    Ok(())
}
