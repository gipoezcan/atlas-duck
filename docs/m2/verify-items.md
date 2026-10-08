# M2 verify items (spec §15: V08, V22, V27, V29 keyring half)

Filled from the CI logs of the pushed `m2-audit-store` branch. Every field marked
`TO FILL FROM CI RUN` is completed from the job logs of one commit on which all legs of the
exit-criterion table (plan Task 18, Step 5) are green. Cite the job name and the run URL.

- Commit: TO FILL FROM CI RUN
- GitHub Actions run: TO FILL FROM CI RUN
- GitLab pipeline: TO FILL FROM CI RUN

## V08: keychain crates, pins and per-OS behaviour

Store crates (no `keyring` umbrella crate; the master plan's `keyring 4.2.0` pin is dropped):

| Crate | Pin | Used on | Feature |
|---|---|---|---|
| `keyring-core` | 1.0.0 | all | |
| `windows-native-keyring-store` | 1.1.0 | Windows | Credential Manager, `persistence=Local` forced on every write |
| `apple-native-keyring-store` | 1.0.2 | macOS | `keychain` (the legacy login keychain) |
| `zbus-secret-service-keyring-store` | 1.0.1 | Linux | `crypto-rust`; talks to the Secret Service over D-Bus |

Evidence per OS (job `rust (...)` step "Audit OS keychain tests ...", Linux and GitLab
`rust:audit-keychain` through `ci/keyring-ci.sh`):

- **Windows (RF-3a).** Target names and `Persist` values printed by `rf3a_*`: TO FILL FROM CI RUN.
  Whether an update of an Enterprise entry kept Enterprise (`rf3a_existing_enterprise_entry_rewritten_local`
  expects it was rewritten Local), and which `set` path is used: TO FILL FROM CI RUN.
- **macOS.** Whether the runner's login keychain worked without setup (macos-15 arm64 and the
  Rosetta leg): TO FILL FROM CI RUN. If it did not: the fallback pre-step is documented in plan
  Task 18 (temporary keychain made default; the locality dir stays `~/Library/Keychains`); record the
  error text and the pre-step used here.
- **Linux.** GNOME Keyring on a private session bus (`dbus-run-session`), file-backed in
  `$XDG_DATA_HOME/keyrings/login.keyring`. Secret Service attribute names printed by
  `os_secret_service_attributes`: TO FILL FROM CI RUN. Keyring files listed before and after:
  TO FILL FROM CI RUN.
- Test results per leg (`os_round_trip_all_kinds`, `os_absent_is_none_and_delete_idempotent`,
  `os_canary_self_test`, `os_two_installs_isolated`, `os_u18_keychain_wiped`): TO FILL FROM CI RUN.

## V22: `PRAGMA user_version` inside a WAL transaction

`v22_user_version_rolls_back` (`crates/audit/tests/schema.rs`) result on the three OS legs:
TO FILL FROM CI RUN. Expected: the pragma set inside a transaction rolls back with it, so a
migration that fails after bumping the version leaves the old version.

## V27: clock sources and sleep behaviour

Clock sources as implemented (`crates/audit/src/clock.rs`, `SystemClock::suspend_aware_elapsed`):

| OS | Wall clock | Suspend-aware elapsed |
|---|---|---|
| Linux | `SystemTime::now()` | `CLOCK_BOOTTIME` |
| macOS | `SystemTime::now()` | `CLOCK_MONOTONIC` (keeps counting in sleep, unlike `CLOCK_UPTIME_RAW`) |
| Windows | `SystemTime::now()` | `QueryInterruptTime` (100 ns units, includes time asleep) |

CI proves monotonicity only (`SystemClock` tests on the three legs: TO FILL FROM CI RUN). Whether the
suspend-aware clock counts sleep and hibernate is not testable on hosted runners.

Manual check, once per OS before release (status: **open** for all three):

1. Start a small program or test that prints `suspend_aware_elapsed()` and the wall time (UTC)
   every second, or note both values by hand.
2. Note both values (`e0`, `w0`).
3. Put the machine to sleep for 5 minutes (second run: hibernate for 5 minutes). Wake it.
4. Read both again (`e1`, `w1`).
5. Pass when `e1 - e0` is at least 295 s and within a few seconds of `w1 - w0`: the clock counts the
   time asleep. A `e1 - e0` near the awake time only (a few seconds) means the clock stops in sleep:
   record it; §8.8 (U-13) then relies on the wall-clock corroboration alone on that OS.

| OS | Machine | Sleep: e1-e0 / w1-w0 | Hibernate: e1-e0 / w1-w0 | Result | Date |
|---|---|---|---|---|---|
| Windows | | | | open | |
| macOS | | | | open | |
| Linux | | | | open | |

## V29 (keyring half): keyring locality and NFS refusal

Keyring dirs checked per OS (`keyring_dirs()`):

| OS | Dirs |
|---|---|
| Linux | `$XDG_DATA_HOME/keyrings`, `$XDG_DATA_HOME/kwalletd` (when set and absolute) and `<passwd home>/.local/share/{keyrings,kwalletd}` |
| macOS | `<passwd home>/Library/Keychains` |
| Windows | none (Credential Manager is per machine, persistence Local) |

Evidence, job `locality-mounts (ubuntu-22.04)`:

- Mount facts (`V29 nfs f_type=...` line of the mount step): TO FILL FROM CI RUN.
- `locality_nfs_from_env` (step "Keyring locality against the NFS mount"): TO FILL FROM CI RUN.
- Step "Shared keyring I-43/I-44 (§8.6)" (`ci/shared-keyring.sh`): lines `shared-keyring: A ok`,
  `B1 ok`, `B2 ok`, `C ok`: TO FILL FROM CI RUN. `C ok` is the refusal evidence:
  `i44_keyring_on_nfs_refused` saw `NotLocal` for the NFS keyrings dir, `create_new_store` ended in
  `KeyStore(NotLocal)`, `open` ended in `Locked(KeyringNotLocal)`, and the NFS `keyrings` dir (listing,
  sizes, mtimes, contents) was identical before and after.
- Phase C keeps a daemon on a local `XDG_DATA_HOME` and only the test process sees the NFS one,
  because `OsKeyStore::new` opens a Secret Service session on the bus before any path check.
