//! S-03 (§13, §12.1): `atlas-duck verify-export` against a running scripted-approver app. The
//! export fixtures come from `audit::testing::export_fixture` (an honest export with its manifest
//! hash, a tampered one, an honest one without a trust root). Each case runs through the CLI; the
//! report is on stdout, the exit code is 0 / 21 / 20, and the running app is untouched: its diag
//! log shows neither a forwarded launch nor a window open between the run's start and end, and
//! `audit.db` and `audit.db-wal` hash the same before and after. On Windows every case also runs
//! as `powershell -NoProfile -Command "& '<cli>' verify-export ...; exit $LASTEXITCODE"` and the
//! PowerShell process's own exit code is asserted (the §13 `$LASTEXITCODE` clause).
//!
//! The app has no window-count query (`testing/control.rs` has none and none is added): the diag
//! log is the only evidence, so the check is "no `forwarded_launch` line (the single-instance
//! forward, `tray.rs`) and no `window_open*` line (`windows.rs` logs `window_opened` on a
//! successful open and `window_open_failed` on a failed one)". Before each run the test waits
//! until the app is idle (two equal hash reads) and its log is live (`serve_started` present).
//! The PassWithAnchorDir case (T36b, T28 M-4) passes the fixture's anchor dir with
//! `--anchor-dir` as well as `--manifest-sha256`: exit 0 and the both-roots verdict line.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use atlas_duck_app_lib::diag::LOG_DIR_NAME;
use atlas_duck_audit::DB_FILE;
use atlas_duck_audit::testing::{FixtureInfo, FixtureKind, export_fixture};
use atlas_duck_registry::Product;
use sha2::{Digest, Sha256};

use crate::harness::{CLI_EXE, Result, World, WorldOpts, opted_in};

/// The report line each fixture ends with (`bins.rs` pins the same lines).
const LAST_PASS: &str = "verified against the manifest SHA-256";
const LAST_BOTH: &str = "verified against the manifest SHA-256 and the anchor dir";
const LAST_TAMPER: &str = "TAMPERED:";
const LAST_NO_ROOT: &str = "internally consistent; trust root NOT verified";

/// The log writer is buffered: how long a log read waits for the app's lines to land.
const LOG_SETTLE: Duration = Duration::from_millis(600);
const RUN_TIMEOUT: Duration = Duration::from_secs(60);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One fixture case: its kind, whether the run passes `--manifest-sha256` (it also passes the
/// fixture's anchor dir, when it has one), the report's last line.
struct Case {
    kind: FixtureKind,
    with_root: bool,
    last_line: &'static str,
}

const CASES: [Case; 4] = [
    Case {
        kind: FixtureKind::Pass,
        with_root: true,
        last_line: LAST_PASS,
    },
    Case {
        kind: FixtureKind::PassWithAnchorDir,
        with_root: true,
        last_line: LAST_BOTH,
    },
    Case {
        kind: FixtureKind::Tamper,
        with_root: true,
        last_line: LAST_TAMPER,
    },
    Case {
        kind: FixtureKind::NoTrustRoot,
        with_root: false,
        last_line: LAST_NO_ROOT,
    },
];

/// SHA-256 of a file, `None` when it does not exist (the `-wal` file may be absent).
fn file_hash(path: &Path) -> Result<Option<String>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(hex(&Sha256::digest(&bytes)))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The hashes of the live `audit.db` and its `-wal`.
fn live_hashes(world: &World) -> Result<[Option<String>; 2]> {
    let db = world.data_dir().join(DB_FILE);
    let wal = world.data_dir().join(format!("{DB_FILE}-wal"));
    Ok([file_hash(&db)?, file_hash(&wal)?])
}

/// Every diag log file of the app, concatenated in name order.
fn log_text(world: &World) -> String {
    let dir = world.data_dir().join(LOG_DIR_NAME);
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    files.sort();
    files
        .iter()
        .filter_map(|f| fs::read_to_string(f).ok())
        .collect()
}

/// Waits (at most 20 s) until the app is idle and its log is live: two reads of `audit.db` and
/// `-wal` 300 ms apart agree and the log holds the app's `serve_started` line (so a log check can
/// not pass on an empty or unreadable log). Returns the agreed hashes.
async fn wait_idle(world: &World) -> Result<[Option<String>; 2]> {
    let start = std::time::Instant::now();
    loop {
        let first = live_hashes(world)?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let second = live_hashes(world)?;
        if first == second && log_text(world).contains("serve_started") {
            return Ok(second);
        }
        if start.elapsed() > Duration::from_secs(20) {
            return Err(format!(
                "the app was not idle with a live log within 20 s\n{}",
                world.diagnostics()
            )
            .into());
        }
    }
}

/// What the log gained between two snapshots (the whole later text when it does not extend the
/// earlier one, e.g. after a rotation: stricter, never looser).
fn gained<'a>(before: &str, after: &'a str) -> &'a str {
    after.strip_prefix(before).unwrap_or(after)
}

/// True when `text` holds a forwarded-launch or a window-open line.
fn shows_launch_or_window(text: &str) -> Option<&str> {
    text.lines()
        .find(|l| l.contains("forwarded_launch") || l.contains("window_open"))
}

/// The arguments of one case's `verify-export` run.
fn args_of(case: &Case, info: &FixtureInfo) -> Result<Vec<String>> {
    let mut args = vec![
        "verify-export".to_owned(),
        info.dir
            .to_str()
            .ok_or("non-UTF-8 fixture path")?
            .to_owned(),
    ];
    if case.with_root {
        args.push("--manifest-sha256".to_owned());
        args.push(hex(&info.manifest_sha256));
    }
    if let Some(anchor) = &info.anchor_dir {
        args.push("--anchor-dir".to_owned());
        args.push(
            anchor
                .to_str()
                .ok_or("non-UTF-8 anchor dir path")?
                .to_owned(),
        );
    }
    Ok(args)
}

struct Ran {
    stdout: String,
    stderr: String,
    exit: i32,
}

/// Runs `program` with `args` in the world's environment, to its end (60 s).
async fn run_child(world: &World, program: &str, args: &[String]) -> Result<Ran> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args).env_clear().current_dir(world.root());
    for (k, v) in world.env() {
        cmd.env(k, v);
    }
    let mut cmd = tokio::process::Command::from(cmd);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let child = cmd.spawn()?;
    let out = tokio::time::timeout(RUN_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| format!("{program} {args:?} did not end within {RUN_TIMEOUT:?}"))??;
    Ok(Ran {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        exit: out.status.code().unwrap_or(-1),
    })
}

/// The `-Command` text of the Windows case: the CLI through the call operator, then its exit code.
/// Every argument is single-quoted (a quote inside doubles).
#[cfg_attr(not(windows), allow(dead_code))]
fn powershell_command(cli: &str, args: &[String]) -> String {
    let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let mut text = format!("& {}", quote(cli));
    for a in args {
        text.push(' ');
        text.push_str(&quote(a));
    }
    // The `| Write-Output` stage makes PowerShell read the native command's stdout through a pipe
    // and re-emit it on its own stdout. Without it the exit code came back but the report did
    // not reach PowerShell's stdout (Windows CI run 40232178967: exit 0, empty stdout; the
    // app checks its stdout writes, so it did write). `$LASTEXITCODE` stays the CLI's: the
    // last pipeline stage is a cmdlet.
    text.push_str(" | Write-Output; exit $LASTEXITCODE");
    text
}

/// The report assertions shared by the direct and the PowerShell run.
fn assert_report(label: &str, case: &Case, expected: u8, run: &Ran, world: &World) {
    assert_eq!(
        run.exit,
        i32::from(expected),
        "{label}: stdout: {}\nstderr: {}\n{}",
        run.stdout,
        run.stderr,
        world.diagnostics()
    );
    let last = run.stdout.lines().last().unwrap_or_default();
    assert!(
        last.starts_with(case.last_line),
        "{label}: the report ends with {:?}, got: {}",
        case.last_line,
        run.stdout
    );
    assert!(
        run.stdout.lines().count() > 1,
        "{label}: the report has a body above its verdict line: {}",
        run.stdout
    );
    assert!(
        !run.stdout.trim_start().starts_with('{'),
        "{label}: the CLI prints no envelope: {}",
        run.stdout
    );
}

/// S-03: the three fixtures through the CLI (and PowerShell on Windows) while the app runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s03_verify_export_runs_beside_the_app() -> Result<()> {
    if !opted_in("s03_verify_export_runs_beside_the_app") {
        return Ok(());
    }
    let mut world = World::new(WorldOpts::default())?;
    world
        .provision_store(&[("jira-main", Product::Jira)])
        .await?;
    let _app = world.start_app().await?;

    let exports = world.root().join("s03-exports");
    fs::create_dir_all(&exports)?;
    let cli = CLI_EXE.to_owned();

    for case in &CASES {
        let out = exports.join(format!("{:?}", case.kind));
        fs::create_dir(&out)?;
        let info = export_fixture(case.kind, &out)?;
        let args = args_of(case, &info)?;
        let label = format!("{:?}", case.kind);

        // Direct run.
        let hashes_before = wait_idle(&world).await?;
        let log_before = log_text(&world);
        let run = run_child(&world, &cli, &args).await?;
        assert_report(&label, case, info.expected_exit, &run, &world);
        assert!(
            run.stderr.is_empty(),
            "{label}: stderr must be empty: {:?}",
            run.stderr
        );
        tokio::time::sleep(LOG_SETTLE).await;
        let log_after = log_text(&world);
        if let Some(line) = shows_launch_or_window(gained(&log_before, &log_after)) {
            return Err(format!(
                "{label}: the run left a launch/window line in the app's log: {line}\n{}",
                world.diagnostics()
            )
            .into());
        }
        assert_eq!(
            live_hashes(&world)?,
            hashes_before,
            "{label}: audit.db / -wal changed"
        );

        // Windows: the same case through PowerShell, asserting its own exit code.
        #[cfg(windows)]
        {
            let ps_args = vec![
                "-NoProfile".to_owned(),
                "-Command".to_owned(),
                powershell_command(&cli, &args),
            ];
            let hashes_before = wait_idle(&world).await?;
            let log_before = log_text(&world);
            let run = run_child(&world, "powershell", &ps_args).await?;
            assert_report(
                &format!("{label} via powershell"),
                case,
                info.expected_exit,
                &run,
                &world,
            );
            assert!(
                run.stderr.is_empty(),
                "{label} via powershell: stderr must be empty: {:?}",
                run.stderr
            );
            tokio::time::sleep(LOG_SETTLE).await;
            let log_after = log_text(&world);
            if let Some(line) = shows_launch_or_window(gained(&log_before, &log_after)) {
                return Err(format!(
                    "{label} via powershell: launch/window line in the app's log: {line}"
                )
                .into());
            }
            assert_eq!(
                live_hashes(&world)?,
                hashes_before,
                "{label} via powershell: audit.db / -wal changed"
            );
        }
    }

    // The app was running throughout and still is.
    assert!(world.app_running()?, "the app is gone");
    world.quit_app().await?;
    Ok(())
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[test]
    fn the_powershell_command_quotes_every_argument_and_returns_the_exit_code() {
        let args = vec!["verify-export".to_owned(), "C:\\a b\\o'k".to_owned()];
        assert_eq!(
            powershell_command("C:\\bin\\atlas-duck.exe", &args),
            "& 'C:\\bin\\atlas-duck.exe' 'verify-export' 'C:\\a b\\o''k' | Write-Output; exit $LASTEXITCODE"
        );
    }

    #[test]
    fn a_log_snapshot_diff_is_the_appended_part_or_the_whole_text() {
        assert_eq!(gained("a\n", "a\nb\n"), "b\n");
        assert_eq!(gained("x\n", "y\n"), "y\n");
        assert!(shows_launch_or_window("event=forwarded_launch\n").is_some());
        assert!(shows_launch_or_window("event=window_open_failed\n").is_some());
        assert!(shows_launch_or_window("event=window_opened window=approvals\n").is_some());
        assert!(shows_launch_or_window("event=serve_started\n").is_none());
    }
}
