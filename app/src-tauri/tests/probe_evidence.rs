//! Prints this OS's §9.4 probe report as `PROBE_EVIDENCE` lines, the source of the per-probe
//! table in docs/m1/go-no-go.md (plan task T22).
//!
//! It runs the real startup probe (`sandbox_probe::run_startup_probe`) against the dev-built
//! `atlas-duck-sandbox`, copied into a temporary install directory. The floor verdict is not
//! asserted here: the live assertions are in probes_linux.rs, probes_macos.rs and
//! probes_windows.rs, and the go/no-go record carries the verdict per OS. This test fails only if
//! the probe produced no records at all.
//!
//! Read it with: cargo test -p atlas-duck-app --test probe_evidence --locked -- --nocapture
//!
//! `ATLAS_DUCK_SANDBOX_BIN` overrides the worker (used by the Fedora container job, where the
//! compile-time `CARGO_BIN_EXE_atlas-duck-sandbox` path does not exist).

use std::path::PathBuf;

use atlas_duck_app_lib::sandbox_probe::{run_startup_probe, sandbox_worker_path};
use atlas_duck_app_lib::startup::crash::set_non_dumpable;

fn worker_source() -> PathBuf {
    match std::env::var_os("ATLAS_DUCK_SANDBOX_BIN") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(env!("CARGO_BIN_EXE_atlas-duck-sandbox")),
    }
}

/// `FileInProfile` -> `file_in_profile`; the spelling of `ProbeId`'s serde `snake_case`
/// (`Clone3` -> `clone3`), which is what the go/no-go document uses.
fn snake_case(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn snake_case_matches_the_probe_id_spelling() {
    assert_eq!(snake_case("FileInProfile"), "file_in_profile");
    assert_eq!(snake_case("Clone3"), "clone3");
    assert_eq!(snake_case("MemReadProcMem"), "mem_read_proc_mem");
    assert_eq!(snake_case("MachLookupSecurityd"), "mach_lookup_securityd");
    assert_eq!(snake_case("Blocked"), "blocked");
}

#[test]
fn print_probe_evidence() {
    // Linux: the app is non-dumpable (§2.5), which the memory-read probes rely on (§9.4).
    // Other OSes return Unsupported; that is printed, not an error.
    let non_dumpable = set_non_dumpable();

    // Under target/tmp, not the system temp dir: on Windows the probe grants (L)PAC ACEs on the
    // copied worker, and those must stay inside the build tree.
    let install_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("atlas-duck-probe-evidence-{}", std::process::id()));
    std::fs::create_dir_all(&install_dir).expect("create the temporary install dir");
    std::fs::copy(worker_source(), sandbox_worker_path(&install_dir))
        .expect("copy the sandbox worker");

    let profile = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .unwrap_or_else(|| install_dir.clone());

    let app_pid = std::process::id();
    let (report, ace) = run_startup_probe(&install_dir, app_pid, &profile);

    println!(
        "PROBE_EVIDENCE os={} arch={} app_pid={app_pid} non_dumpable={non_dumpable:?} ace_ensure_ran={}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        ace.is_some()
    );
    println!(
        "PROBE_EVIDENCE worker_version={:?} engine_version={:?}",
        report.worker_version, report.engine_version
    );
    println!("PROBE_EVIDENCE floor={:?}", report.floor);
    println!("PROBE_EVIDENCE confinement={:?}", report.confinement);
    println!("PROBE_EVIDENCE threads={:?}", report.threads);
    println!("PROBE_EVIDENCE extra_layers={:?}", report.extra_layers);
    println!("PROBE_EVIDENCE identity={:?}", report.identity);
    println!(
        "PROBE_EVIDENCE control={:?} lpac_failed={:?}",
        report.control, report.lpac_failed
    );
    for record in &report.records {
        println!(
            "PROBE_EVIDENCE probe={} outcome={} evidence={:?}",
            snake_case(&format!("{:?}", record.probe)),
            snake_case(&format!("{:?}", record.outcome)),
            record.evidence
        );
    }
    println!("PROBE_EVIDENCE done records={}", report.records.len());

    // Best effort: the worker may still be exiting on Windows.
    let _ = std::fs::remove_dir_all(&install_dir);

    assert!(
        !report.records.is_empty(),
        "the startup probe produced no records"
    );
}
