//! `instance.lock` exclusivity and holder record (§3.1).

use std::path::Path;
use std::process::Command;

use atlas_duck_audit::lock::{INSTANCE_LOCK_FILE, InstanceLock, LockError, LockHolder};
use atlas_duck_ipc::paths::{DataDirResolution, LocalDataDir, check_data_dir};

/// Set by the parent test for the re-executed child; unset in normal runs.
const CHILD_DIR_ENV: &str = "ATLAS_DUCK_LOCK_CHILD_DIR";
const CHILD_TEST: &str = "lock_child_entry";
const RESULT_PREFIX: &str = "LOCK_CHILD_RESULT ";

fn local(dir: &Path) -> LocalDataDir {
    match check_data_dir(dir).expect("check_data_dir") {
        DataDirResolution::Local(data) => data,
        _ => panic!("{} is not a local data dir", dir.display()),
    }
}

fn describe(result: Result<InstanceLock, LockError>) -> String {
    match result {
        Ok(_lock) => "acquired".to_owned(),
        Err(LockError::Held(Some(holder))) => format!("held_some {} {}", holder.host, holder.pid),
        Err(LockError::Held(None)) => "held_none".to_owned(),
        Err(LockError::Io(e)) => format!("io {e}"),
    }
}

/// Child half of the cross-process tests. A no-op unless the parent set `CHILD_DIR_ENV`.
#[test]
fn lock_child_entry() {
    let Some(dir) = std::env::var_os(CHILD_DIR_ENV) else {
        return;
    };
    let data = local(Path::new(&dir));
    let line = describe(InstanceLock::acquire(&data, "childhost"));
    println!("{RESULT_PREFIX}{line}");
}

/// Re-executes this test binary as a second process that tries to take the lock.
fn child_acquire(dir: &Path) -> String {
    let out = Command::new(std::env::current_exe().expect("current_exe"))
        .args([CHILD_TEST, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_DIR_ENV, dir)
        .output()
        .expect("spawn child test process");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "child failed: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
        .lines()
        .find_map(|l| {
            l.split_once(RESULT_PREFIX)
                .map(|(_, rest)| rest.trim().to_owned())
        })
        .unwrap_or_else(|| panic!("no child result in: {stdout}"))
}

fn read_record(dir: &Path) -> LockHolder {
    let text = std::fs::read_to_string(dir.join(INSTANCE_LOCK_FILE)).expect("read instance.lock");
    assert!(text.ends_with('\n'), "record must be one line: {text:?}");
    assert_eq!(text.lines().count(), 1, "record must be one line: {text:?}");
    serde_json::from_str(text.trim_end()).expect("record is JSON {host, pid}")
}

#[test]
fn second_process_is_refused_until_the_first_lock_drops() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = local(tmp.path());
    let lock = InstanceLock::acquire(&data, "parenthost").expect("first acquire");
    assert_eq!(lock.path(), tmp.path().join(INSTANCE_LOCK_FILE));
    assert!(tmp.path().join(INSTANCE_LOCK_FILE).exists());

    let refused = child_acquire(tmp.path());
    if cfg!(unix) {
        assert_eq!(
            refused,
            format!("held_some parenthost {}", std::process::id())
        );
    } else {
        // Share mode 0: the second process cannot even open the file to read the record.
        assert_eq!(refused, "held_none");
    }

    drop(lock);
    assert_eq!(child_acquire(tmp.path()), "acquired");
    let record = read_record(tmp.path());
    assert_eq!(record.host, "childhost");
    assert_ne!(record.pid, std::process::id());
}

#[test]
fn second_acquire_in_the_same_process_is_held() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = local(tmp.path());
    let _first = InstanceLock::acquire(&data, "hosta").expect("first acquire");
    let second = describe(InstanceLock::acquire(&data, "hostb"));
    if cfg!(unix) {
        assert_eq!(second, format!("held_some hosta {}", std::process::id()));
    } else {
        assert_eq!(second, "held_none");
    }
}

#[test]
fn record_is_one_json_line_with_exactly_host_and_pid() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = local(tmp.path());
    drop(InstanceLock::acquire(&data, "recordhost").expect("acquire"));
    let text = std::fs::read_to_string(tmp.path().join(INSTANCE_LOCK_FILE)).expect("read");
    let value: serde_json::Value = serde_json::from_str(text.trim_end()).expect("json");
    let object = value.as_object().expect("json object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["host", "pid"]);
    assert_eq!(
        read_record(tmp.path()),
        LockHolder {
            host: "recordhost".to_owned(),
            pid: std::process::id()
        }
    );
}

#[test]
fn stale_record_from_a_dead_holder_is_replaced() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join(INSTANCE_LOCK_FILE),
        "{\"host\":\"crashedhost\",\"pid\":1}\ntrailing garbage that is longer than the new record\n",
    )
    .expect("write stale record");
    let data = local(tmp.path());
    drop(InstanceLock::acquire(&data, "freshhost").expect("acquire over a stale file"));
    assert_eq!(
        read_record(tmp.path()),
        LockHolder {
            host: "freshhost".to_owned(),
            pid: std::process::id()
        }
    );
}

#[cfg(unix)]
#[test]
fn unparsable_record_of_a_live_holder_gives_held_none() {
    use std::os::fd::AsRawFd;

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join(INSTANCE_LOCK_FILE);
    std::fs::write(&path, "not json\n").expect("write");
    let holder = std::fs::File::open(&path).expect("open");
    // SAFETY: `holder` owns an open descriptor for the duration of the call.
    let rc = unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(rc, 0, "test holder could not flock");
    let data = local(tmp.path());
    assert_eq!(describe(InstanceLock::acquire(&data, "x")), "held_none");
    assert_eq!(std::fs::read_to_string(&path).expect("read"), "not json\n");
}
