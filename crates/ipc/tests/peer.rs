//! Peer identity: ancestor walk to the origin (§3.1 "Peer origin", PD-36,
//! §15 V07, V18).
#![cfg(feature = "async")]

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use atlas_duck_ipc::peer::{MAX_HOPS, OsPeerSource, PeerSource, is_skipped_hop, peer_info};
use atlas_duck_ipc::proto::{PeerHop, PeerInfo};

/// One fake process: `(parent, start_time, exe)`; `None` = that lookup fails.
type FakeProc = (Option<u32>, Option<u64>, Option<&'static str>);

struct Fake(HashMap<u32, FakeProc>);

impl Fake {
    fn new(procs: &[(u32, FakeProc)]) -> Self {
        Self(procs.iter().copied().collect())
    }
}

impl PeerSource for Fake {
    fn parent(&self, pid: u32) -> Option<u32> {
        self.0.get(&pid)?.0
    }
    fn start_time(&self, pid: u32) -> Option<u64> {
        self.0.get(&pid)?.1
    }
    fn exe(&self, pid: u32) -> Option<PathBuf> {
        self.0.get(&pid)?.2.map(PathBuf::from)
    }
}

fn hop(pid: u32, start_time: u64, exe: &str) -> PeerHop {
    PeerHop {
        pid,
        start_time,
        exe: PathBuf::from(exe),
    }
}

fn pids(info: &PeerInfo) -> Vec<u32> {
    info.peer_chain.iter().map(|h| h.pid).collect()
}

#[test]
fn walk_skips_atlas_and_shells_stops_at_origin() {
    let src = Fake::new(&[
        (100, (Some(90), Some(400), Some("/opt/atlas/atlas-duck"))),
        (90, (Some(80), Some(300), Some("/bin/bash"))),
        (80, (Some(1), Some(200), Some("/usr/bin/python3"))),
        (1, (Some(0), Some(1), Some("/sbin/init"))),
    ]);
    let info = peer_info(Some(100), &src);
    assert_eq!(
        info,
        PeerInfo {
            peer_pid: Some(100),
            peer_exe: Some(PathBuf::from("/opt/atlas/atlas-duck")),
            peer_chain: vec![
                hop(100, 400, "/opt/atlas/atlas-duck"),
                hop(90, 300, "/bin/bash"),
                hop(80, 200, "/usr/bin/python3"),
            ],
            peer_origin_exe: Some(PathBuf::from("/usr/bin/python3")),
            peer_origin_start_time: Some(200),
        }
    );
}

#[test]
fn walk_stops_on_pid_reuse() {
    // Parent started after the child: the parent pid was reused.
    let later = Fake::new(&[
        (100, (Some(90), Some(400), Some("atlas-duck"))),
        (90, (Some(80), Some(500), Some("bash"))),
        (80, (Some(1), Some(200), Some("python3"))),
    ]);
    let info = peer_info(Some(100), &later);
    assert_eq!(pids(&info), vec![100]);
    assert_eq!(info.peer_origin_exe, None);
    assert_eq!(info.peer_origin_start_time, None);

    // "Not earlier than" includes an equal start time.
    let equal = Fake::new(&[
        (100, (Some(90), Some(400), Some("atlas-duck"))),
        (90, (Some(80), Some(300), Some("bash"))),
        (80, (Some(1), Some(300), Some("python3"))),
    ]);
    let info = peer_info(Some(100), &equal);
    assert_eq!(pids(&info), vec![100, 90]);
    assert_eq!(info.peer_origin_exe, None);
}

#[test]
fn walk_bounded_at_four() {
    assert_eq!(MAX_HOPS, 4);
    // Four skipped hops: the fifth (an origin candidate) is never visited.
    let all_skipped = Fake::new(&[
        (100, (Some(90), Some(500), Some("atlas-duck"))),
        (90, (Some(80), Some(400), Some("sh"))),
        (80, (Some(70), Some(300), Some("sh"))),
        (70, (Some(60), Some(200), Some("bash"))),
        (60, (Some(1), Some(100), Some("python3"))),
    ]);
    let info = peer_info(Some(100), &all_skipped);
    assert_eq!(pids(&info), vec![100, 90, 80, 70]);
    assert_eq!(info.peer_origin_exe, None);

    // The fourth hop is not skipped: it is the origin.
    let fourth = Fake::new(&[
        (100, (Some(90), Some(500), Some("atlas-duck"))),
        (90, (Some(80), Some(400), Some("sh"))),
        (80, (Some(70), Some(300), Some("bash"))),
        (70, (Some(60), Some(200), Some("node"))),
    ]);
    let info = peer_info(Some(100), &fourth);
    assert_eq!(pids(&info), vec![100, 90, 80, 70]);
    assert_eq!(info.peer_origin_exe, Some(PathBuf::from("node")));
    assert_eq!(info.peer_origin_start_time, Some(200));
}

#[test]
fn walk_partial_on_lookup_failure() {
    // Parent exe unreadable (e.g. another user's process): stop before it.
    let no_exe = Fake::new(&[
        (100, (Some(90), Some(400), Some("atlas-duck"))),
        (90, (Some(80), Some(300), None)),
        (80, (Some(1), Some(200), Some("python3"))),
    ]);
    let info = peer_info(Some(100), &no_exe);
    assert_eq!(pids(&info), vec![100]);
    assert_eq!(info.peer_origin_exe, None);

    // Parent start time unreadable.
    let no_start = Fake::new(&[
        (100, (Some(90), Some(400), Some("atlas-duck"))),
        (90, (Some(80), None, Some("python3"))),
    ]);
    assert_eq!(pids(&peer_info(Some(100), &no_start)), vec![100]);

    // Parent unknown.
    let no_parent = Fake::new(&[(100, (None, Some(400), Some("atlas-duck")))]);
    let info = peer_info(Some(100), &no_parent);
    assert_eq!(pids(&info), vec![100]);
    assert_eq!(info.peer_origin_exe, None);

    // Direct peer's start time unreadable: no chain, but pid and exe stay.
    let direct = Fake::new(&[(100, (Some(90), None, Some("atlas-duck")))]);
    let info = peer_info(Some(100), &direct);
    assert_eq!(info.peer_pid, Some(100));
    assert_eq!(info.peer_exe, Some(PathBuf::from("atlas-duck")));
    assert!(info.peer_chain.is_empty());
    assert_eq!(info.peer_origin_exe, None);

    // Nothing known about the direct peer at all.
    let info = peer_info(Some(100), &Fake::new(&[]));
    assert_eq!(
        info,
        PeerInfo {
            peer_pid: Some(100),
            ..PeerInfo::default()
        }
    );
}

#[test]
fn walk_without_pid_is_empty() {
    let src = Fake::new(&[(100, (Some(90), Some(400), Some("python3")))]);
    assert_eq!(peer_info(None, &src), PeerInfo::default());
}

#[test]
fn walk_stops_at_pid_zero_and_one() {
    let src = Fake::new(&[
        (100, (Some(1), Some(400), Some("atlas-duck"))),
        (1, (Some(0), Some(1), Some("python3"))),
        (200, (Some(0), Some(400), Some("bash"))),
        (0, (Some(0), Some(0), Some("node"))),
    ]);
    let info = peer_info(Some(100), &src);
    assert_eq!(pids(&info), vec![100]);
    assert_eq!(info.peer_origin_exe, None);
    assert_eq!(pids(&peer_info(Some(200), &src)), vec![200]);
    // pid 0/1 as the direct peer: exe recorded, never walked.
    let info = peer_info(Some(1), &src);
    assert_eq!(info.peer_exe, Some(PathBuf::from("python3")));
    assert!(info.peer_chain.is_empty());
}

#[test]
fn walk_stops_on_self_parent() {
    let src = Fake::new(&[(100, (Some(100), Some(400), Some("bash")))]);
    let info = peer_info(Some(100), &src);
    assert_eq!(pids(&info), vec![100]);
    assert_eq!(info.peer_origin_exe, None);
}

#[test]
fn direct_peer_not_skipped_is_origin() {
    let src = Fake::new(&[
        (100, (Some(90), Some(400), Some("/usr/bin/node"))),
        (90, (Some(1), Some(300), Some("/usr/bin/python3"))),
    ]);
    let info = peer_info(Some(100), &src);
    assert_eq!(pids(&info), vec![100]);
    assert_eq!(info.peer_origin_exe, Some(PathBuf::from("/usr/bin/node")));
    assert_eq!(info.peer_origin_start_time, Some(400));
}

#[test]
fn skip_list_table() {
    let cases: &[(&str, bool)] = &[
        ("/tmp/.mount_abc/AppRun", true),
        ("/tmp/.mount_abc/usr/bin/helper", true),
        ("x.AppImage", true),
        ("/home/u/Apps/atlas-duck-1.0-x86_64.AppImage", true),
        ("PWSH.EXE", true),
        ("cmd.exe", true),
        ("atlas-duck-app.exe", true),
        ("atlas-duck", true),
        ("atlas-duck.exe", true),
        ("AppRun", true),
        ("/bin/sh", true),
        ("bash", true),
        ("zsh", true),
        ("fish", true),
        ("dash", true),
        ("powershell.exe", true),
        ("pwsh", true),
        ("node", false),
        ("Code.exe", false),
        ("python3", false),
        ("bash.exe.bak", false),
        ("shell", false),
        ("/tmp/mount_abc/AppRunner", false),
        ("", false),
    ];
    for (exe, skipped) in cases {
        assert_eq!(is_skipped_hop(Path::new(exe)), *skipped, "{exe}");
    }
}

#[test]
fn os_source_sees_own_process() {
    let src = OsPeerSource::default();
    let me = std::process::id();
    let start = src.start_time(me).expect("own start time");
    let exe = src.exe(me).expect("own exe");
    assert_eq!(
        canon(&exe),
        canon(&std::env::current_exe().expect("current_exe"))
    );
    let parent = src.parent(me).expect("own parent");
    assert_ne!(parent, me);
    if let Some(parent_start) = src.start_time(parent) {
        assert!(parent_start < start, "{parent_start} !< {start}");
    }
    assert_eq!(src.parent(u32::MAX - 1), None);
    assert_eq!(src.exe(u32::MAX - 1), None);
    assert_eq!(src.start_time(u32::MAX - 1), None);
}

fn canon(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|e| panic!("canonicalize {}: {e}", p.display()))
}

fn assert_start_times_decrease(info: &PeerInfo) {
    for pair in info.peer_chain.windows(2) {
        assert!(
            pair[1].start_time < pair[0].start_time,
            "start times not strictly decreasing: {:?}",
            info.peer_chain
        );
    }
}

const CHILD_ENV: &str = "ATLAS_DUCK_TEST_PEER_CHILD";
const CHILD_MARKER: &str = "PEER_CHILD_REPORT ";

/// V18 on the real OS: this test binary → shell (`sh -c` / `cmd /c`) → this
/// test binary again. The parent walks from the shell's pid while the child
/// blocks on stdin; the child reports `peer_info(Some(own pid))`.
#[test]
fn v18_walk_finds_test_origin() {
    let me = std::env::current_exe().expect("current_exe");
    let me_canon = canon(&me);
    // Linux start times have clock-tick (10 ms) resolution: make sure the
    // shell cannot start in the same tick as this process.
    std::thread::sleep(Duration::from_millis(50));

    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/c").arg(&me);
        c.args(["--ignored", "--exact", "peer_child_report", "--nocapture"]);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg("-c")
            .arg(r#""$0" --ignored --exact peer_child_report --nocapture"#)
            .arg(&me);
        c
    };
    let mut child = cmd
        .env(CHILD_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn shell");

    // The shell (or, if it exec'd, the child test binary) is alive and
    // blocked until stdin gets a line.
    let from_shell = peer_info(Some(child.id()), &OsPeerSource::default());

    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(b"go\n").expect("release child");
    drop(stdin);
    let stdout = child.stdout.take().expect("stdout");
    let mut report = None;
    for line in std::io::BufReader::new(stdout).lines() {
        let line = line.expect("child stdout");
        if let Some(json) = line.strip_prefix(CHILD_MARKER) {
            report = Some(json.to_owned());
        }
    }
    let status = child.wait().expect("wait child");
    assert!(status.success(), "child failed: {status}");
    let report = report.expect("child printed no report");
    let from_child: PeerInfo = serde_json::from_str(&report).expect("child report json");

    for (what, info) in [("shell", &from_shell), ("child", &from_child)] {
        let names: Vec<_> = info
            .peer_chain
            .iter()
            .map(|h| h.exe.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        println!(
            "V18 walk={what} chain={names:?} origin={:?}",
            info.peer_origin_exe.as_deref().and_then(Path::file_name)
        );
        assert!(!info.peer_chain.is_empty(), "{what}: empty chain");
        assert_start_times_decrease(info);
        let origin = info
            .peer_origin_exe
            .as_deref()
            .unwrap_or_else(|| panic!("{what}: no origin: {info:?}"));
        assert_eq!(canon(origin), me_canon, "{what}: origin");
        let last = info.peer_chain.last().expect("non-empty");
        assert_eq!(Some(last.start_time), info.peer_origin_start_time);
        assert!(info.peer_chain.iter().any(|h| canon(&h.exe) == me_canon));
    }

    // Walking from the shell: either the shell exec'd into the test binary
    // (origin = the child itself) or it is a skipped hop and the origin is
    // this very process.
    let first = &from_shell.peer_chain[0];
    assert_eq!(first.pid, child.id());
    if is_skipped_hop(&first.exe) {
        assert_eq!(from_shell.peer_chain.len(), 2, "{from_shell:?}");
        assert_eq!(from_shell.peer_chain[1].pid, std::process::id());
    } else {
        assert_eq!(from_shell.peer_chain.len(), 1, "{from_shell:?}");
    }

    // The child walked from itself: it is its own origin.
    assert_eq!(from_child.peer_chain.len(), 1, "{from_child:?}");
    assert_eq!(from_child.peer_pid, Some(from_child.peer_chain[0].pid));
}

/// Child half of `v18_walk_finds_test_origin`; does nothing unless spawned by it.
#[test]
#[ignore = "spawned by v18_walk_finds_test_origin"]
fn peer_child_report() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).expect("stdin");
    let info = peer_info(Some(std::process::id()), &OsPeerSource::default());
    let json = serde_json::to_string(&info).expect("json");
    println!("{CHILD_MARKER}{json}");
}

#[cfg(target_os = "macos")]
#[test]
fn v07_macos_peer_pid_options() {
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    use atlas_duck_ipc::peer::{peer_epid, peer_pid};

    let (a, _b) = UnixStream::pair().expect("socketpair");
    let pid = peer_pid(a.as_fd());
    let epid = peer_epid(a.as_fd());
    println!(
        "V07 peerpid={} peerepid={}",
        pid.map_or_else(|| "none".to_owned(), |p| p.to_string()),
        epid.map_or_else(|| "none".to_owned(), |p| p.to_string())
    );
    assert_eq!(pid, Some(std::process::id()));
    assert_eq!(epid, Some(std::process::id()));
}
