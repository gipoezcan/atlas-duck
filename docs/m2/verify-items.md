# M2 verify items (spec §15: V08, V22, V27, V29 keyring half)

Filled from the CI logs of one commit on the pushed `m2-audit-store` branch. Where a log does not
contain a fact, this file says so instead of guessing.

- Commit: `664d484` (all legs green)
- GitHub Actions run: https://github.com/gipoezcan/atlas-duck/actions/runs/37828437132 (9 jobs). Job ids used below:
  `rust (x86_64-unknown-linux-gnu)` 113487226354, `rust (x86_64-apple-darwin under Rosetta)` 113487226404,
  `rust (x86_64-pc-windows-msvc)` 113487226539, `rust (aarch64-apple-darwin)` 113487226643,
  `locality-mounts (ubuntu-22.04)` 113487226512, `locality-mounts (windows-2022)` 113487226687,
  `probe-evidence-fedora` 113487226397 (each at `<run URL>/job/<id>`).
- GitLab pipeline 39621: `rust:test` and `rust:audit-keychain` succeeded (status reported by the
  controller; the job log of this commit is not in the evidence directory, so the overlayfs diagnostic
  lines of `ci/keyring-ci.sh` for GitLab were not read).

## Exit-criterion run (plan Task 18, Step 5)

| Command / job | Where | Result on `664d484` |
|---|---|---|
| `cargo test --workspace --locked` (includes `-p atlas-duck-audit`) | `rust` Windows, macOS arm64, Ubuntu 22.04; Rosetta job; GitLab `rust:test` | green (audit suites incl. `v22_user_version_rolls_back`, `system_clock_monotonic`, `locality_nfs_from_env` pass in the logs) |
| `os_keystore --ignored --test-threads=1` | `rust` Windows (7 tests), macOS arm64 (6), Rosetta (6); Linux via `ci/keyring-ci.sh` (6); GitLab `rust:audit-keychain` | green on GitHub (tests listed below); GitLab green per controller |
| `ATLAS_DUCK_SHARED_STATE=... bash ci/shared-keyring.sh` | `locality-mounts (ubuntu-22.04)` | `A ok`, `B1 ok`, `B2 ok`, `C ok`, `all phases ok` |
| `node ci/check-audit-vectors.mjs` | `rust` jobs | green |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | every `rust` leg | green |
| `cargo deny --locked check`, `cargo audit` | `supply-chain` | `advisories ok, bans ok, licenses ok, sources ok` |
| `node ci/check-workspace.mjs`, `node --test "ci/*.test.mjs"` | `rust` jobs | green |

## V08: keychain crates, pins and per-OS behaviour

Store crates (no `keyring` umbrella crate; the master plan's `keyring 4.2.0` pin is dropped):

| Crate | Pin | Used on | Feature |
|---|---|---|---|
| `keyring-core` | 1.0.0 | all | |
| `windows-native-keyring-store` | 1.1.0 | Windows | Credential Manager, `persistence=Local` forced on every write |
| `apple-native-keyring-store` | 1.0.2 | macOS | `keychain` (the legacy login keychain) |
| `zbus-secret-service-keyring-store` | 1.0.1 | Linux | `crypto-rust`; talks to the Secret Service over D-Bus |

- **Windows (RF-3a)**, job `rust (x86_64-pc-windows-msvc)`: all 7 `os_*` tests pass, including
  `win::rf3a_keyring_persist_local` and `win::rf3a_existing_enterprise_entry_rewritten_local`. The tests
  assert `Persist == 2` (`CRED_PERSIST_LOCAL_MACHINE`) on first write and on update, `TargetName ==
  atlas-duck/<install_id>/<account>`, and that an existing Enterprise (`3`) entry is rewritten Local. They
  print nothing, so the logs hold no target-name or `Persist` values beyond pass/fail, and they do not show
  which `set` path was taken (update in place or delete and rewrite); the code is the only source for that.
- **macOS**, jobs `rust (aarch64-apple-darwin)` (macos-15) and the Rosetta job: the runner's login keychain
  worked **without any setup step**; all 6 tests pass on both (`os_entry_visible_under_service_and_account`
  confirms `security find-generic-password -s atlas-duck/<install_id> -a kek`). The fallback pre-step of
  the plan was not needed.
- **Linux**, job `rust (x86_64-unknown-linux-gnu)`, `ci/keyring-ci.sh` (GNOME Keyring on `dbus-run-session`):
  all 6 tests pass. `os_secret_service_attributes` found the entry with `secret-tool lookup service
  atlas-duck/<install_id> username kek`, i.e. the attribute names are `service` and `username`; the test
  prints attributes only on a failed lookup, so nothing more is in the log. The keyring dir was empty before
  the run and held `login.keyring` (105 bytes) and `user.keystore` (207 bytes) afterwards, file-backed under
  `<workspace>/.ci-xdg/keyrings`.

## V22: `PRAGMA user_version` inside a WAL transaction

`v22_user_version_rolls_back` (`crates/audit/tests/schema.rs`) passed on Windows, macOS arm64, Rosetta and
Linux (GitHub `rust` jobs): `PRAGMA user_version` set inside a WAL transaction rolls back with it.

## V27: clock sources and sleep behaviour

Clock sources as implemented (`crates/audit/src/clock.rs`, `SystemClock::suspend_aware_elapsed`):

| OS | Wall clock | Suspend-aware elapsed |
|---|---|---|
| Linux | `SystemTime::now()` | `CLOCK_BOOTTIME` |
| macOS | `SystemTime::now()` | `CLOCK_MONOTONIC` (keeps counting in sleep, unlike `CLOCK_UPTIME_RAW`) |
| Windows | `SystemTime::now()` | `QueryInterruptTime` (100 ns units, includes time asleep) |

CI proves monotonicity only: `system_clock_monotonic` passes in the `rust` jobs (seen in the Linux log; the
test is in the common suite run on every leg). Whether the suspend-aware clock counts sleep and hibernate is
not testable on hosted runners.

Manual check, once per OS before release (status: **OPEN** for all three):

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

- Mounts: `V29 nfs f_type=0x6969 (nfs)`, `V29 cifs f_type=0xfe534d42 (smb2)`.
- `locality_nfs_from_env` (step "Keyring locality against the NFS mount") passes.
- Step "Shared keyring I-43/I-44 (§8.6)" prints `shared-keyring: A ok`, `B1 ok`, `B2 ok`, `C ok` and
  `all phases ok`. `A` is `i43_shared_home_sequential` (two installs: `6817e654...` / `4a269e55...`),
  `B1`/`B2` are `i44_concurrent_phase1`/`phase2` around a daemon restart, `C` is
  `i44_keyring_on_nfs_refused`: `NotLocal` for the NFS keyrings dir, `create_new_store` ends in
  `KeyStore(NotLocal)`, `open` ends in `Locked(KeyringNotLocal)`, and the NFS `keyrings` dir (listing, sizes,
  mtimes, contents) is identical before and after.
- Phase C keeps a daemon on a local `XDG_DATA_HOME` and only the test process sees the NFS one,
  because `OsKeyStore::new` opens a Secret Service session on the bus before any path check.
- Windows leg (`locality-mounts (windows-2022)`): mapped drive `NotLocal(RemoteDrive)`, symlink to UNC
  `NotLocal(Unc)`, `subst` drive `Local` (ipc locality tests, not the keyring).

## CI-round notes (lessons from getting this green)

- **`mod common;` inside an inline module.** `mod common;` inside `mod u18 { }` resolves under
  `tests/u18/`, which does not exist; the block was `cfg`'d out on Windows so only Linux/macOS failed. Declare
  shared test modules at the file top level (`tests/common/mod.rs` already has `#![allow(dead_code)]`, do not
  add a second `allow`: clippy rejects the duplicate). A `cfg(target_os)` block that was never compiled on the
  author's OS needs a cross `cargo clippy --target ...` or a CI run before it counts as checked.
- **Overlayfs passwd home in containers.** The Linux keyring check also covers
  `<passwd home>/.local/share/{keyrings,kwalletd}`, and the home comes from `getpwuid`, not `$HOME`. In the
  GitLab `rust:1.95` container that is `/root` on overlayfs, so `create_new_store` returned
  `KeyStore(NotLocal)` although `XDG_DATA_HOME` was on the project volume. `ci/keyring-ci.sh` symlinks an
  absent `<passwd home>/.local/share` to `$XDG_DATA_HOME` when the home is overlayfs, and prints the checked
  dirs with their filesystem types so a refusal can be diagnosed from the log. The locality code is
  unchanged and still fails closed.
- **Panic test on slow runners.** `panicking_keychain_does_not_hang_flush` waits for
  `health().anchor_thread_dead` first: the thread is marked dead only after the panic hook (backtrace
  symbolisation under `RUST_BACKTRACE=1`) has run, which on Windows can outlast the 500 ms flush timeout.
