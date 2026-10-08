# atlas-duck M2 (Audit store) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Before your first task, read the sections **Global Constraints**, **Formats (F.1–F.12)** and **Crate layout** of this file: every task refers to them by id instead of repeating them.

**Goal:** Build the `atlas-duck-audit` crate's encrypted, hash-chained audit store as a library, fully tested in isolation: schema, canonical encoding (`FIELD_LIST[1]` frozen by golden vectors), payload crypto, chain and `GENESIS`, `install_id`-scoped OS keychain entries with the keyring locality check, keychain anchors, `prune_log`, recovery passphrase, corroborated epoch and clock guards, prune with crypto-shredding, verification and incidents, backup and restore-as-continuation, keychain-loss recovery, archive-and-start-fresh, schema versions and the newer-store refusal.

**Architecture:** One library crate (`crates/audit`, package `atlas-duck-audit`) that owns the SQLite file `<data>/audit.db`. A `Store` handle is a cheap `Clone` over one **writer thread** (owns the only read-write connection, the chain head, the clock state, the settings view and prune) and one **anchor thread** (the only code that writes head/first-retained anchors to the keychain). Callers prepare rows (JCS bytes, SHA-256, zstd) on their own thread; the writer stamps `seq`/`ts_utc`/`epoch`/flags, encrypts with AES-256-GCM, hashes and commits with `synchronous=FULL`, then replies. `open()` runs §8.7 steps 1–4 and needs the M1 `InstanceLock`. Keychain access goes through the `KeyStore` trait: `OsKeyStore` (keyring-core 1.0 + one native store crate per OS) in production, `testing::MemKeyStore` in tests. Nothing in this crate imports `core`, `atlassian` or Tauri; the only workspace edge is `audit → ipc` [M1].

**Tech Stack:** Rust 1.95.0 / edition 2024. New pins (verified on crates.io/docs.rs 2026-10-08, table in "Dependency pins"): `rusqlite =0.40.2` (`bundled`), `aes-gcm =0.11.1`, `sha2 =0.11.0`, `hmac =0.13.0`, `hkdf =0.13.0`, `argon2 =0.6.0`, `zstd =0.14.0`, `getrandom =0.4.3`, `zeroize =1.9.0`, `secrecy =0.10.3`, `serde_jcs =0.2.0`, `unicode-normalization =0.1.25`, `chrono =0.4.45`, `base64 =0.22.1`, `hex =0.4.3`, `keyring-core =1.0.0`, `windows-native-keyring-store =1.1.0`, `apple-native-keyring-store =1.0.2` (`keychain`), `zbus-secret-service-keyring-store =1.0.1` (`crypto-rust`), `proptest =1.11.0` (dev).

**Spec:** `docs/superpowers/specs/2026-10-07-atlas-duck-design.md` (§3.1, §7.7, §8.1–§8.13, §10.1, §11.1, §11.3, §12.5, §13 Unit/Integration clauses), ledger `docs/superpowers/specs/2026-10-07-atlas-duck-review-ledger.md` (L09, L10, L23, L24, L27, L32, L34, L36–L41). **Master plan:** `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md` (C.3 audit contract, M2 entry, Traceability U-06..U-22, X-01..X-03, RF-1a/1b, RF-3a, I-43/I-44/I-46). **M1 record:** `docs/m1/go-no-go.md`.

Conventions: `§n` = spec section; `Lnn` = master-plan ledger id; `C.3` = master-plan audit contract; `[M1]` = exists in the repo; **Plan decision (spec silent)** = a choice this plan makes where the spec says nothing (listed again in "Plan decisions" at the end so the user can overrule them); `F.n` = the Formats section of this plan. Test ids (`U-06`, `RF-1a`, …) are the master plan's.

---

## Global Constraints

The master plan's Global Constraints bind every task. The subset M2 touches, verbatim in substance:

- **Dependency rule:** `audit` depends only on `ipc` (for `LocalDataDir`) among workspace crates [M1]; it never imports `core`, `atlassian`, `registry` or Tauri. `ci/check-workspace.mjs` does not check plan-level edges, so the reviewer checks `crates/audit/Cargo.toml` by hand in every task. `ipc` gains one module (`ipc::jcs`, T01) and no new workspace edge.
- **Single writer:** only the app's single writer thread opens the DB read-write; CLI and sandbox never open it (§8.1). In this crate that is the `audit-writer` thread (T07). Read-only connections for `read_payload`/`headers_*`/verification are allowed (WAL readers).
- **Lock:** `open()`, `create_new_store()`, `recover_this_log()`, `finish_restore()`, `restore_from_source()`, `archive_and_start_fresh()` take `&InstanceLock` (§3.1, type-enforced; `InstanceLock` [M1] in `crates/audit/src/lock.rs`).
- **Pragmas:** `journal_mode=WAL`, `synchronous=FULL`, `secure_delete=ON`, `page_size=8192`, `auto_vacuum=INCREMENTAL`; after each prune `PRAGMA incremental_vacuum` then `PRAGMA wal_checkpoint(TRUNCATE)` (§8.1).
- **Crypto:** payload zstd level 3 → AES-256-GCM, random 96-bit nonces only; KEK 32 B random in the OS keychain; DEK 32 B random per UTC month of `epoch` plus the uncorroborated DEK (`month` NULL, L36), wrapped by the KEK; keys in `zeroize::Zeroizing<[u8; 32]>`, passphrases in `secrecy::SecretString` (§8.4, §8.6, §10.1).
- **Recovery passphrase:** mandatory at first run of a new store, ≥ 12 characters, typed twice, Argon2id m = 64 MiB, t = 3, p = 4, 16-byte salt; after wrapping, unwrap once with the second entry and compare before committing the `recovery` row (§8.6).
- **Hash domains:** `record_hash = SHA-256("atlas-duck/audit/v<format_version>" ‖ prev_hash ‖ canonical_bytes)`; AAD domain `atlas-duck/aad/v1`; `GENESIS.prev_hash` = 32 zero bytes (§8.4).
- **Keychain names** [L24]: `atlas-duck/<install_id>/kek`, `…/head_anchor`, `…/first_retained_anchor`, `…/canary`, `…/pat/<instance-id>`; Windows persistence = Local (`CRED_PERSIST_LOCAL_MACHINE`), never the store default Enterprise (RF-3); never a silent fallback to an insecure store (§8.6).
- **Keyring locality** [L34]: macOS/Linux, before the canary self-test, at first run and every start: the §7.7 local-filesystem check on the keyring backing dirs; not local → `keyring_not_local`, no keyring read or write (§8.6, §8.7).
- **v1 is keychain mode only** [L39]: no `vault` table, no `<data>/anchor`, no unlock passphrase, no `locked` reason `passphrase`. Restore still drops `vault` rows/tables found in a snapshot.
- **Epoch** [L36]: `epoch = max(prev_epoch, min(today_utc, corroborated_date))` with corroboration in this process, else `prev_epoch`; `GENESIS` and every record before the store's first corroboration carry `epoch` NULL; effective epoch rule; uncorroborated DEK (§8.2, §8.6).
- **Prune** [L37]: cadence ≤ 1 run per epoch day across restarts, none while the head's `epoch` is NULL, baseline = latest `prune_log.cutoff_epoch` else `GENESIS`'s effective epoch, advance > 2 epochs clamped to baseline + 2 (no dialog; `confirm_large_advance` lifts the clamp for one run); retention default 100, minimum 92 [L09]; legal hold pauses prune and shredding (§8.8).
- **Startup order** (§8.7): 1 version gate (writes nothing) → 2 KEK (locality, canary, backoff 60–120 s, `keychain_lost`) → 3 load anchors, decrypt newest record, verify pre-migration → 4 migrations + `SCHEMA_MIGRATED`, then the `VERIFY` of step 3 → (5 is M3: `reconcile_after_crash` + `APP_START`). **No anchor write of any kind before the step-3 `VERIFY` is committed.**
- **Fail closed** (§11.1): append failure → `AuditError`, nothing partially committed; keychain unavailable/lost/not local → `Locked`, never `FirstRun`, never a new `GENESIS`; newer store → `StoreNewer`, files byte-identical.
- **Anchor writer is M10** (P7): M2 ships anchor-dir *line types and the verifier side* only. M2 writes no file into an anchor dir.
- **Lints:** `cargo clippy --workspace --all-targets --locked -- -D warnings` stays green. In `audit`, no `unwrap()`/`expect()` outside tests (plan rule; not enforced by lint).
- **Secrets in errors/logs:** no `Debug`/`Display` of `AuditError`, `KeyStoreError` or any type in this crate may print key bytes, passphrases, payload plaintext or ciphertext. Keyring-core errors that carry bytes (`BadEncoding`, `BadDataFormat`) are mapped to `KeyStoreError::Other("bad data")` without the bytes.
- **CI:** GitHub has Windows/macOS/Linux runners; GitLab mirrors Linux only. Containers (GitLab, Fedora) have an overlayfs `/tmp` and `$HOME`: the locality checks fail closed there, so every container job that creates data dirs or keyrings sets `TMPDIR` and `XDG_DATA_HOME` onto the project volume first.

---

## Review Focus

The five failure modes most likely to bite M2. Each line: condition → required behaviour → task and test.

1. **NULL epoch leaking into DEK, prune or verification (L36, RF-1a).** A first run with the clock 1 year ahead, then a corrected clock; a restart before the first corroboration; a restore while the head's `epoch` is NULL. → No non-NULL `epoch`, month DEK or `keys.month` later than the corroborated date ever exists; NULL-epoch rows use the newest `month IS NULL` DEK; prune never deletes a row without an effective epoch; full verification judges NULL-epoch rows by their effective epoch; AAD/canonical bytes encode NULL as `00 00000000`. Tasks T06, T07, T11, T13; tests `rf1a_first_run_forward_clock`, `null_epoch_rows_use_uncorroborated_dek`, `no_prune_while_head_epoch_null`.
2. **Anchor ordering across crashes (§8.5, §8.7).** A crash or keychain-write failure between a `PRUNE`/`RESTORE` commit and its anchor update; a migration on a tail-truncated DB; a batched flush racing a prune. → The head anchor never passes a `PRUNE` whose first-retained update has not succeeded and never moves at all across a `RESTORE` until the reset; no anchor write before the startup `VERIFY` commits; Drop never writes an anchor. Tasks T08, T09, T11, T16; tests `head_anchor_stops_at_unfinished_prune`, `no_anchor_write_before_verify`, `u22_interrupted_prune_*`, `u22_interrupted_restore_*`.
3. **Keychain naming and persistence per OS (L24, RF-3, V08).** keyring-core builds Windows target names as `user.service` by default, and Windows persistence defaults to Enterprise (roams). → Every entry is created through `OsKeyStore` with service `atlas-duck/<install_id>`, account `kek|head_anchor|…`, and on Windows the explicit `target` modifier `atlas-duck/<install_id>/<account>` plus `persistence=Local`; `CredReadW` reports `Persist == CRED_PERSIST_LOCAL_MACHINE` for all five kinds, including an entry that existed with Enterprise persistence before. Task T05; tests `rf3a_keyring_persist_local`, `rf3a_existing_enterprise_entry_rewritten_local`, `entry_names_render_exactly`.
4. **Canonical bytes and JCS frozen forever (U-07).** A JCS crate that sorts keys by UTF-8 instead of UTF-16 code units, an integer written with the wrong width, a NULL encoded differently from an empty string, a domain string with a trailing NUL. → Golden vectors fixed at the end of M2 (`crates/audit/tests/vectors/format_v1.json`), cross-checked by an independent Node implementation (`ci/check-audit-vectors.mjs`), including the JCS keys `"\u{FFFF}"`/`"\u{10000}"` order test and the RFC 8785 number vectors. Tasks T01, T02; tests `jcs_*`, `golden_vectors_match`, `node ci/check-audit-vectors.mjs`.
5. **Settings and policy lost to prune (P5).** `retention_days`, legal hold and instance origins live only in `CONFIG_CHANGED`/`LEGAL_HOLD_CHANGED` events, which prune deletes after ≥ 92 days. → Every `PRUNE` payload carries the full settings snapshot; the view = latest retained `PRUNE` snapshot overlaid with later policy events; a store whose policy events were all pruned still reports retention 150 and legal hold on. Tasks T11, T12; test `settings_survive_prune_of_their_events`.

Master-plan Review Focus lines owned by M2: **RF-1a** (`rf1a_first_run_forward_clock`, T13), **RF-1b** (`rf1b_prune_after_long_gap_no_baseline`, T13), **RF-3a** (`rf3a_keyring_persist_local`, T05). RF-3b is M6.

---

## Dependency pins

All pins exact (`=x.y.z`) in the root `[workspace.dependencies]`; members reference them with `{ workspace = true }`. Versions and licenses read from the crates.io API on 2026-10-08. cargo-deny (`deny.toml` [M1]) must stay green: every license below is already on the allow list (`MIT`, `Apache-2.0`, `BSD-3-Clause`, …). `cargo deny` reads each crate's `license` metadata, so for `zstd-sys`/`zstd-safe` and `security-framework` T01 runs `cargo deny --locked check licenses` and reports the printed license of each; if any crate shows a license outside the allow list, STOP and report (do not widen the list without the user).

| Crate | Pin | Used by | Features | License | Why this one |
|---|---|---|---|---|---|
| `rusqlite` | `=0.40.2` | audit | `bundled` | MIT | Master-plan pin; bundled SQLite avoids system-lib drift; `backup`/`VACUUM INTO` and `user_version` via SQL |
| `aes-gcm` | `=0.11.1` | audit | `default-features = false`, `["aes", "alloc", "zeroize"]` | Apache-2.0 OR MIT | §8.4 AES-256-GCM; RustCrypto 2026 generation (aead 0.6); nonces come from `getrandom` directly, so its `getrandom` feature stays off |
| `sha2` | `=0.11.0` | audit | default | MIT OR Apache-2.0 | Matches `digest 0.11` of `hmac`/`hkdf`/`argon2`. Coexists with the transitive `sha2 0.10.9` already in `Cargo.lock`; `deny.toml` has `multiple-versions = "warn"`, so this is a warning, not a failure |
| `hmac` | `=0.13.0` | audit | default | MIT OR Apache-2.0 | L38 query tag (`Hmac<Sha256>::new_from_slice`, traits `KeyInit`, `Mac`) |
| `hkdf` | `=0.13.0` | audit | default | MIT OR Apache-2.0 | L38 `K_q = HKDF-SHA256(KEK, info)` (`Hkdf::<Sha256>::new(None, ikm)`, `expand`) |
| `argon2` | `=0.6.0` | audit | `default-features = false`, `["alloc", "zeroize"]` | MIT OR Apache-2.0 | §8.6 Argon2id; only `hash_password_into` is used, so `password-hash`/`getrandom` stay off |
| `zstd` | `=0.14.0` | audit | `default-features = false` | BSD-3-Clause | Master-plan pin; `zstd::bulk::compress(data, 3)`/`decompress`. The license changed to BSD-3-Clause in 0.14 (allowed) |
| `getrandom` | `=0.4.3` | audit | default | MIT OR Apache-2.0 | Already in `Cargo.lock`; `getrandom::fill(&mut [u8])` for KEK, DEKs, nonces, salts, ids |
| `zeroize` | `=1.9.0` | audit | default | Apache-2.0 OR MIT | `Zeroizing<[u8; 32]>` (§10.1). 1.9.1 is two days old (2026-10-06); 1.9.0 (2026-06-12) chosen. If cargo resolves another crate's `zeroize` requirement above 1.9.0, take the version cargo picks and say so in the commit message |
| `secrecy` | `=0.10.3` | audit | default | Apache-2.0 OR MIT | `SecretString` for the recovery passphrase (§10.1) |
| `serde_jcs` | `=0.2.0` | ipc | default | MIT OR Apache-2.0 | RFC 8785 JCS for payload bytes (and `params_sha256` in M3, same module); verified against RFC vectors in T01 |
| `unicode-normalization` | `=0.1.25` | audit | default | MIT OR Apache-2.0 | NFC for the query tag (L38) and the recovery passphrase bytes |
| `chrono` | `=0.4.45` | audit | `default-features = false`, `["std"]` | MIT OR Apache-2.0 | Already in `Cargo.lock`; `NaiveDate` arithmetic and RFC 3339 formatting; no clock feature (time comes only from the injected `Clock`) |
| `base64` | `=0.22.1` | audit | default | MIT OR Apache-2.0 | Already in `Cargo.lock`; `requests[].body_b64` in `WRITE_APPROVED` (F.8) |
| `hex` | `=0.4.3` | audit | default | MIT OR Apache-2.0 | Already in `Cargo.lock`; lowercase hex in payloads, tags, ids |
| `keyring-core` | `=1.0.0` | audit | default | MIT OR Apache-2.0 | V08: the store-agnostic API (`Entry`, `CredentialStoreApi::build`, `Error`). The `keyring` 4.2.0 umbrella is **not** used: its docs say apps that need control over stores link `keyring-core` and the store crates directly (Plan decision) |
| `windows-native-keyring-store` | `=1.1.0` | audit (cfg windows) | default | MIT OR Apache-2.0 | Windows Credential Manager; entry modifiers `target` and `persistence` (`Session`/`Local`/`Enterprise`, default Enterprise) |
| `apple-native-keyring-store` | `=1.0.2` | audit (cfg macos) | `default-features = false`, `["keychain"]` | MIT OR Apache-2.0 | macOS legacy (login) keychain, file-backed under `~/Library/Keychains` (what the locality check guards). `protected` (data-protection keychain) needs signing entitlements and is not used |
| `zbus-secret-service-keyring-store` | `=1.0.1` | audit (cfg linux) | `default-features = false`, `["crypto-rust"]` | MIT OR Apache-2.0 | Linux Secret Service over zbus 5 (already `=5.19.0` in the workspace for the tray-host check), pure Rust; sync API (`crypto-rust`), never `crypto-openssl`, never `rt-tokio-*` (audit has no tokio) |
| `windows-sys` | `=0.61.2` [M1] | audit (cfg windows) | add `Win32_Foundation`, `Win32_Security_Credentials`, `Win32_Storage_FileSystem`, `Win32_System_WindowsProgramming` | MIT OR Apache-2.0 | `CredReadW` (RF-3a test and the Windows persistence self-check), `GetDiskFreeSpaceExW` (admission), `QueryInterruptTime` (V27) |
| `libc` | `=0.2.190` [M1] | audit (cfg unix) | — | MIT OR Apache-2.0 | `statvfs` (admission), `clock_gettime(CLOCK_BOOTTIME / CLOCK_MONOTONIC)` (V27) |
| `proptest` | `=1.11.0` | audit (dev) | default | MIT OR Apache-2.0 | Encoding round-trip and tamper property tests |
| `tempfile` | `=3.27.0` [M1] | audit (dev) | — | MIT OR Apache-2.0 | Test data dirs |

Transitive crates that arrive with these and that cargo-deny must accept: `libsqlite3-sys` (MIT), `zstd-safe`/`zstd-sys` (check in T01), `aead`/`aes`/`ghash`/`polyval`/`cipher` (MIT OR Apache-2.0), `blake2` (argon2), `secret-service =5.x` (MIT OR Apache-2.0, last release 5.2.0), `security-framework` 3.x (check in T01), `ryu-js` (serde_jcs).

---

## Crate layout

```
crates/audit/
  Cargo.toml                       # deps per "Dependency pins"; [features] testing = []
  src/lib.rs                       # re-exports the C.3 surface (T01, grown by every task)
  src/lock.rs                      # [M1] InstanceLock (unchanged)
  src/types.rs                     # EventType, EventFlags, DecisionColumn, Actor, NewEvent, Committed, EventHeader, UtcInstant, ids (T01/T07)
  src/error.rs                     # AuditError, OpenError (T01)
  src/encoding.rs                  # FIELD_LIST[1], frame(), canonical_bytes, record_hash, aad, wtf8 (T02)
  src/request_set.rs               # RequestRecord, request_set_hash, requests JSON (T02)
  src/crypto.rs                    # envelope, DEK wrap, Kek/Dek types, query_tag (T03)
  src/recovery.rs                  # recovery blob (T03)
  src/schema.rs                    # DDL v1, pragmas, SCHEMA_HEAD, MIGRATIONS, version gate reader (T04)
  src/keystore/mod.rs              # KeyStore trait, EntryName, KeyStoreError, KeyringLocality, canary (T05)
  src/keystore/os.rs               # OsKeyStore over keyring-core (T05)
  src/keystore/locality.rs         # keyring backing dirs per OS (T05)
  src/keystore/windows.rs          # CredReadW persist check (T05, cfg windows)
  src/clock.rs                     # Clock trait, SystemClock (V27), ClockState (epoch/flags) (T06)
  src/writer.rs                    # writer thread, Cmd, PreparedEvent, DEK selection, append (T07)
  src/store.rs                     # Store handle and its public methods (T07 onward)
  src/admission.rs                 # free-space probe (T07)
  src/anchors.rs                   # anchor layouts, AnchorState, anchor thread (T08)
  src/verify.rs                    # chain/prune_log verification, startup rules, full_verify (T09)
  src/incidents.rs                 # open_incidents, acknowledge (T09)
  src/open.rs                      # open(), create_new_store(), keychain cases, retry schedule (T07/T10)
  src/prune.rs                     # prune selection, cadence, clamp, shredding (T11)
  src/settings.rs                  # Settings view, SettingChange, config-file reconcile (T12)
  src/anchor_dir.rs                # AnchorLine types, parser, checks (verifier side) (T14)
  src/recover.rs                   # recover_this_log, archive_and_start_fresh (T15)
  src/backup.rs                    # backup bundle (T16)
  src/restore.rs                   # restore sources, restore, finish_restore (T16)
  src/requests.rs                  # is_terminal, reconcile_after_crash, header queries (T17)
  src/testing.rs                   # cfg(any(test, feature = "testing")): FakeClock, MemKeyStore, FreeSpace stub, FaultPoint (T01 onward)
  tests/common/mod.rs              # helpers: tmp data dir → LocalDataDir, store builder, scenario driver (T07)
  tests/encoding.rs, tests/golden.rs, tests/crypto.rs, tests/schema.rs, tests/keystore.rs,
  tests/os_keystore.rs (#[ignore], real OS keychain), tests/clock.rs, tests/store.rs, tests/anchors.rs,
  tests/verify.rs, tests/open.rs, tests/prune.rs, tests/settings.rs, tests/clock_scenarios.rs,
  tests/anchor_dir.rs, tests/recover.rs, tests/backup_restore.rs, tests/requests.rs, tests/shared_keyring.rs (#[ignore], Linux CI)
  tests/vectors/format_v1.json     # golden vectors (T02, frozen at the end of M2)
  tests/fixtures/schema/v1.db      # schema-v1 fixture DB (T04)
  tests/fixtures/anchor_dir/*.jsonl  # anchor-dir fixtures (T14)
crates/ipc/src/jcs.rs              # to_jcs_vec (T01)
ci/check-audit-vectors.mjs (+ .test.mjs)   # independent Node re-implementation of F.2–F.9 (T02)
ci/keyring-ci.sh                   # Linux: dbus-run-session + gnome-keyring + keychain tests (T18)
ci/shared-keyring.sh               # Linux: I-43/I-44 phases with daemon restart and the NFS case (T18)
.github/workflows/ci.yml, .gitlab-ci.yml   # keychain steps (T18)
docs/m2/verify-items.md            # V08, V22, V27, V29 (keyring half) findings (T18)
```

`testing` feature: `crates/audit/Cargo.toml` declares `[features] testing = []`; `src/testing.rs` is `#[cfg(any(test, feature = "testing"))]`. Integration tests in `crates/audit/tests/` get it through a self dev-dependency: `[dev-dependencies] atlas-duck-audit = { path = ".", features = ["testing"] }` (Cargo allows a package to dev-depend on itself with extra features). Release builds never enable it (M3/M4 enable it only from `[dev-dependencies]`).

---

## Formats (F.1–F.12)

Everything here is frozen by the golden vectors of T02 at the end of M2. Changing any byte afterwards is a `format_version` bump (rows) or a layout-version bump (blobs).

### F.1 Identifiers, time and file names

- `install_id`, `chain_id`: 16 bytes from `getrandom::fill`, lowercase hex, 32 characters. **Plan decision (spec silent).**
- `UtcInstant(i64)`: milliseconds since 1970-01-01T00:00:00Z. Text form of `ts_utc`: `YYYY-MM-DDTHH:MM:SS.mmmZ`, always 24 ASCII bytes, always `Z` (RFC 3339 with ms, §8.2).
- `epoch`: `YYYY-MM-DD` (10 bytes) or SQL NULL. DEK `month`: `YYYY-MM` or NULL.
- Hashes, tags, nonces in JSON payloads: lowercase hex.
- Files inside the data dir (**Plan decision (spec silent)** for every name): `<data>/audit.db` (+ SQLite's `-wal`, `-shm`); `<data>/archived/audit-<chain_id>-<head_seq>-<YYYYMMDDTHHMMSSZ>.db` (+ `-wal` if present) for archive-and-start-fresh and for a DB replaced by restore; `<data>/audit.db.restoring` (restore staging; deleted at the next start if found).
- Backup bundle: a directory `<chosen>/atlas-duck-backup-<YYYYMMDDTHHMMSSZ>-<chain_id[0..8]>/` holding `audit.db` (snapshot), `recovery.bin` (the recovery blob, F.5), `manifest.json` (written last, F.11).

### F.2 Canonical encoding `FIELD_LIST[1]` (§8.4)

`FIELD_LIST[1]` = every `events` column except `record_hash`, in this order:

| # | Column | SQLite type | Encoding of a present value | NULL allowed |
|---|---|---|---|---|
| 1 | `seq` | INTEGER | u64 BE, 8 bytes | no |
| 2 | `format_version` | INTEGER | u64 BE (value 1) | no |
| 3 | `chain_id` | TEXT | UTF-8 | no |
| 4 | `ts_utc` | TEXT | UTF-8 (F.1, 24 bytes) | no |
| 5 | `epoch` | TEXT | UTF-8 `YYYY-MM-DD` | **yes (L36)** |
| 6 | `request_id` | TEXT | UTF-8 | yes |
| 7 | `event_type` | TEXT | UTF-8, the §8.3 name (`REQUEST_RECEIVED` …) | no |
| 8 | `op_id` | TEXT | UTF-8 | yes |
| 9 | `op_class` | TEXT | UTF-8 (`read`/`write`, set by M3) | yes |
| 10 | `instance_id` | TEXT | UTF-8 | yes |
| 11 | `target` | TEXT | UTF-8 | yes |
| 12 | `agent_name` | TEXT | UTF-8 | yes |
| 13 | `agent_name_source` | TEXT | UTF-8 | yes |
| 14 | `client_kind` | TEXT | UTF-8 | yes |
| 15 | `connection_id` | TEXT | UTF-8 | yes |
| 16 | `peer_pid` | INTEGER | u64 BE | yes |
| 17 | `peer_exe` | BLOB | OS path bytes: Unix `OsStrExt::as_bytes`, Windows WTF-8 of the UTF-16 units (code below) | yes |
| 18 | `peer_origin_exe` | BLOB | as 17 | yes |
| 19 | `os_user` | TEXT | UTF-8 | yes |
| 20 | `atlassian_user` | TEXT | UTF-8 | yes |
| 21 | `atlassian_user_key` | TEXT | UTF-8 | yes |
| 22 | `decision` | TEXT | UTF-8, one of `approve approve_edited release release_redacted deny expire cancel reject` | yes |
| 23 | `flags` | INTEGER | u64 BE bitmask (below); 0 when no flag | no |
| 24 | `payload_len` | INTEGER | u64 BE | no |
| 25 | `payload_sha256` | BLOB | 32 raw bytes | no |
| 26 | `key_id` | INTEGER | u64 BE | no |
| 27 | `nonce` | BLOB | 12 raw bytes | no |
| 28 | `payload_ct` | BLOB | raw bytes (ciphertext ‖ 16-byte tag) | no |
| 29 | `prev_hash` | BLOB | 32 raw bytes | no |

Field frame: present → `0x01 ‖ u32 BE length ‖ bytes`; NULL → `0x00 ‖ 0x00000000` (5 bytes, no data). An empty string is present with length 0 (`01 00000000`), so it never collides with NULL. `canonical_bytes` = concatenation of the 29 frames, no count prefix. **Plan decision (spec silent):** "every INTEGER column is u64 BE" (one rule), NULL keeps the length word (uniform frame), domains are raw ASCII prefixes with no length or terminator.

`flags` bits (**Plan decision (spec silent)**, spec order of §8.2): `edited` 1<<0, `redacted` 1<<1, `batch` 1<<2, `stale` 1<<3, `clock_backwards` 1<<4, `clock_forward` 1<<5, `clock_behind` 1<<6, `integrity_incident` 1<<7. Any other bit set in a stored row is a verification finding (`unknown_flag_bits`).

```rust
// src/encoding.rs — the subtle part, write exactly this.
pub const FORMAT_VERSION: u64 = 1;
pub const NULL_FRAME: [u8; 5] = [0, 0, 0, 0, 0];

pub enum Field<'a> { Null, Int(u64), Bytes(&'a [u8]) }

pub fn push_frame(out: &mut Vec<u8>, f: &Field<'_>) -> Result<(), AuditError> {
    match f {
        Field::Null => out.extend_from_slice(&NULL_FRAME),
        Field::Int(v) => { out.push(1); out.extend_from_slice(&8u32.to_be_bytes()); out.extend_from_slice(&v.to_be_bytes()); }
        Field::Bytes(b) => {
            // > 4 GiB cannot occur (payloads are bounded upstream, §5.2), but never truncate silently.
            let len = u32::try_from(b.len()).map_err(|_| AuditError::Invalid("field longer than u32::MAX"))?;
            out.push(1);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(b);
        }
    }
    Ok(())
}

pub fn record_domain(format_version: u64) -> Vec<u8> { format!("atlas-duck/audit/v{format_version}").into_bytes() }
pub const AAD_DOMAIN: &[u8] = b"atlas-duck/aad/v1";

/// record_hash = SHA-256(domain ‖ prev_hash ‖ canonical_bytes)  (§8.4)
pub fn record_hash(format_version: u64, prev_hash: &[u8; 32], canonical: &[u8]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(record_domain(format_version));
    h.update(prev_hash);
    h.update(canonical);
    h.finalize().into()
}

/// AAD = "atlas-duck/aad/v1" ‖ frames of [format_version, chain_id, seq, ts_utc, epoch,
/// event_type, request_id, op_id, target, key_id, payload_sha256] in exactly this order (§8.4).
pub fn aad(r: &RowFields<'_>) -> Result<Vec<u8>, AuditError> { /* push AAD_DOMAIN, then push_frame for the 11 fields in the listed order */ }
```

`RowFields<'a>` (T02) borrows the 29 column values of one row; `canonical_bytes(&RowFields) -> Result<Vec<u8>, AuditError>` pushes the 29 frames in F.2 order.

Windows WTF-8 of a path (**the encoding of columns 17/18**):

```rust
#[cfg(windows)]
pub fn os_path_bytes(p: &std::path::Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    let units: Vec<u16> = p.as_os_str().encode_wide().collect();
    let mut out = Vec::with_capacity(units.len() * 3);
    let mut i = 0;
    while i < units.len() {
        let u = units[i] as u32;
        let cp = if (0xD800..0xDC00).contains(&u) && i + 1 < units.len() && (0xDC00..0xE000).contains(&(units[i + 1] as u32)) {
            i += 1;
            0x10000 + ((u - 0xD800) << 10) + (units[i] as u32 - 0xDC00)
        } else { u }; // a lone surrogate stays as its own code point (WTF-8)
        // generalized UTF-8 encoding of cp (1–4 bytes), surrogates included
        if cp < 0x80 { out.push(cp as u8) }
        else if cp < 0x800 { out.push(0xC0 | (cp >> 6) as u8); out.push(0x80 | (cp & 0x3F) as u8) }
        else if cp < 0x10000 { out.push(0xE0 | (cp >> 12) as u8); out.push(0x80 | ((cp >> 6) & 0x3F) as u8); out.push(0x80 | (cp & 0x3F) as u8) }
        else { out.push(0xF0 | (cp >> 18) as u8); out.push(0x80 | ((cp >> 12) & 0x3F) as u8); out.push(0x80 | ((cp >> 6) & 0x3F) as u8); out.push(0x80 | (cp & 0x3F) as u8) }
        i += 1;
    }
    out
}
#[cfg(unix)]
pub fn os_path_bytes(p: &std::path::Path) -> Vec<u8> { use std::os::unix::ffi::OsStrExt; p.as_os_str().as_bytes().to_vec() }
```

### F.3 Payload envelope (§8.2, §8.4)

1. `plain = ipc::jcs::to_jcs_vec(&payload)` (RFC 8785). Every event has a payload; "no payload" is `{}`.
2. `payload_len = plain.len()`, `payload_sha256 = SHA-256(plain)`.
3. `compressed = zstd::bulk::compress(&plain, 3)`.
4. `nonce` = 12 bytes `getrandom::fill`.
5. `payload_ct = AES-256-GCM(DEK[key_id]).encrypt(nonce, Payload { msg: &compressed, aad: &aad(row) })`.
Decrypt is the reverse; after decompress, `SHA-256(plain) == payload_sha256` is checked on every read (`read_payload`, verification). Steps 1–3 run on the caller's thread, 4–5 on the writer after `seq`/`ts_utc`/`epoch`/`key_id` are known (the AAD needs them). **Plan decision (spec silent):** §8.1's "zstd and AES-GCM run off the writer thread" is met for zstd; AES-GCM runs on the writer because the AAD includes `seq` (it is the cheap part; §8.1 calls it an engineering note, not a guarantee).

### F.4 DEK wrapping (§8.6)

`keys.wrapped_dek` = `nonce(12) ‖ AES-256-GCM(KEK).encrypt(nonce, Payload { msg: dek(32), aad: b"atlas-duck/dek/v1" ‖ frame(Int key_id) ‖ frame(month or Null) })` = 60 bytes. Destroyed DEK: `wrapped_dek` set to NULL and `destroyed_at` set, in the `PRUNE` transaction (`secure_delete=ON` plus the `wal_checkpoint(TRUNCATE)` after prune remove the old bytes). **Plan decision (spec silent):** AAD binds `key_id` and `month` so wrapped keys cannot be swapped between rows.

### F.5 Recovery blob (§8.6, §8.13 layout byte)

```
0x01                          layout version
salt[16]                      getrandom
u32 BE m_kib = 65536          Argon2id memory (64 MiB)
u32 BE t = 3
u32 BE p = 4
nonce[12]
ct[48]                        AES-256-GCM(key = Argon2id_v0x13(NFC(passphrase) as UTF-8, salt, m, t, p, out 32 B),
                              nonce, msg = KEK(32), aad = b"atlas-duck/recovery/v1" ‖ the first 29 bytes above)
```
Total 89 bytes. Stored in `recovery(id = 1, blob, created_at)` and copied verbatim into `recovery.bin` of a backup. Passphrase rules: `NFC(passphrase).chars().count() >= 12`, no trimming. **Plan decision (spec silent):** NFC so the same passphrase typed on another OS keyboard yields the same bytes; the parameters are stored in the blob so a later change is a new layout byte.

### F.6 Keychain entries (§8.5, §8.6, L24)

Rendering of `EntryName` for install `I`: service = `atlas-duck/I`; account = `kek` | `head_anchor` | `first_retained_anchor` | `canary` | `pat/<instance_id>`; full name = `atlas-duck/I/<account>` (what docs, `doctor` and the Windows `target_name` show).

| Entry | Value (bytes) |
|---|---|
| `kek` | `0x01 ‖ KEK(32)` (33 bytes) |
| `head_anchor` | `0x01 ‖ JCS({"chain_id":…, "record_hash":"<hex>", "seq":N})` |
| `first_retained_anchor` | `0x01 ‖ JCS({"chain_id":…, "first_retained_prev_hash":"<hex>", "first_retained_seq":N, "genesis_hash":"<hex>"})` |
| `canary` | 16 random bytes (no layout byte; never parsed) |
| `pat/<id>` | owned by M3; M2 only renders the name and deletes it on restore/recovery (T15, T16) |

A leading byte other than `0x01` on `kek`/anchors → `StoreNewer` if greater, `Locked(keychain_lost)` if `0x00` or unparsable (§8.13 version gate applied at first read, before any write). Per-OS mapping in T05.

### F.7 Query tag (§8.2, L38)

`K_q = HKDF-SHA256(salt = none, ikm = KEK, info = b"atlas-duck/query-tag/v1", L = 32)`; `normalized = NFC(query).trim()` (Rust `str::trim`, Unicode whitespace, applied after NFC); `tag = lowercase_hex(HMAC-SHA256(K_q, normalized.as_bytes()))`; `Store::query_tag(Jql, q)` = `"jql:" + tag`, `Cql` → `"cql:" + tag`. `K_q` is derived once at open and held in `Zeroizing<[u8; 32]>`.

### F.8 `request_set_hash` and the `requests` JSON (§5.1 inv. 3)

```
request_set_hash = SHA-256( b"atlas-duck/request-set/v1"
                            ‖ u32 BE count
                            ‖ for each record in slice order:
                                frame(Int index) ‖ frame(method) ‖ frame(resolved_url)
                                ‖ frame(content_type or Null) ‖ frame(body_bytes) )
```
`WRITE_APPROVED` payload (written by M3) stores `requests` as `[{"index":0,"method":"POST","url":"https://…","content_type":"application/json"|null,"body_b64":"<RFC 4648 base64, padded>"}]`. M2 parses exactly this shape in `full_verify` (T09) and fails the finding `request_set_hash_mismatch` when the recomputed hash differs from the payload's `request_set_hash` (lowercase hex). **Plan decision (spec silent):** layout and JSON field names.

Long frame (F.8 and F.9 only, L60): `request_set_hash` and `prune_row_hash` are infallible (C.3), so a field longer than `u32::MAX` bytes, unreachable because every request body is bounded by the 24 MiB frame cap (§3.3, §5.2), is framed `0x02 ‖ u64 BE length ‖ bytes` instead of failing; no regular frame starts with `0x02`, so the encoding stays injective. A count above `u32::MAX` saturates; the records are self-delimiting frames, so the count is redundant. `canonical_bytes` and `aad` keep the strict 0/1 presence byte of §8.4 and return `Invalid` instead.

### F.9 `prune_log` row hash

`row_hash = SHA-256(b"atlas-duck/prune-log/v1" ‖ prev_row_hash ‖ frame(Int prune_seq) ‖ frame(Int range_start) ‖ frame(cutoff_epoch) ‖ frame(last_pruned_record_hash) ‖ frame(Int first_retained_seq))`, `prev_row_hash` of the first row = 32 zero bytes; frames as in F.8, including the unreachable `0x02` long frame. Every `PRUNE` payload carries its row's `row_hash`. **Plan decision (spec silent):** U-06 requires that deleting *or altering* any `prune_log` row fails verification, but old `PRUNE` records are themselves pruned; chaining the rows and binding the latest row hash into the always-retained latest `PRUNE` record makes any alteration detectable.

### F.10 Schema v1 (`PRAGMA user_version = 1`)

```sql
-- applied by schema::create_v1() on a new file, in this order:
PRAGMA page_size = 8192;              -- before the first table
PRAGMA auto_vacuum = INCREMENTAL;     -- before the first table
PRAGMA journal_mode = WAL;
-- per connection (every open, read-write and read-only):
PRAGMA synchronous = FULL;
PRAGMA secure_delete = ON;
PRAGMA foreign_keys = OFF;
PRAGMA busy_timeout = 5000;

CREATE TABLE events (
  seq                INTEGER PRIMARY KEY,   -- assigned by the writer: head + 1; GENESIS = 1
  format_version     INTEGER NOT NULL,
  chain_id           TEXT    NOT NULL,
  ts_utc             TEXT    NOT NULL,
  epoch              TEXT,
  request_id         TEXT,
  event_type         TEXT    NOT NULL,
  op_id              TEXT,
  op_class           TEXT,
  instance_id        TEXT,
  target             TEXT,
  agent_name         TEXT,
  agent_name_source  TEXT,
  client_kind        TEXT,
  connection_id      TEXT,
  peer_pid           INTEGER,
  peer_exe           BLOB,
  peer_origin_exe    BLOB,
  os_user            TEXT,
  atlassian_user     TEXT,
  atlassian_user_key TEXT,
  decision           TEXT,
  flags              INTEGER NOT NULL,
  payload_len        INTEGER NOT NULL,
  payload_sha256     BLOB    NOT NULL,
  key_id             INTEGER NOT NULL,
  nonce              BLOB    NOT NULL,
  payload_ct         BLOB    NOT NULL,
  prev_hash          BLOB    NOT NULL,
  record_hash        BLOB    NOT NULL
);
CREATE INDEX events_request_id ON events(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX events_event_type ON events(event_type);
CREATE INDEX events_key_id     ON events(key_id);

CREATE TABLE prune_log (
  prune_seq               INTEGER PRIMARY KEY,  -- seq of the PRUNE record of this row
  range_start             INTEGER NOT NULL,     -- the spec's `range` is [range_start, first_retained_seq)
  cutoff_epoch            TEXT    NOT NULL,
  last_pruned_record_hash BLOB    NOT NULL,     -- record_hash of seq first_retained_seq-1; for an empty range the previous row's value (32 zero bytes before any record was pruned)
  first_retained_seq      INTEGER NOT NULL,
  prev_row_hash           BLOB    NOT NULL,     -- F.9
  row_hash                BLOB    NOT NULL      -- F.9
);

CREATE TABLE keys (
  key_id       INTEGER PRIMARY KEY,   -- 1, 2, 3 … (rowid)
  month        TEXT,                  -- 'YYYY-MM', NULL = uncorroborated DEK (L36)
  wrapped_dek  BLOB,                  -- F.4; NULL once destroyed
  created_at   TEXT NOT NULL,         -- ts_utc form
  destroyed_at TEXT
);

CREATE TABLE recovery (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  blob       BLOB NOT NULL,           -- F.5
  created_at TEXT NOT NULL
);

CREATE TABLE meta (                   -- plaintext, outside the chain, advisory only (T04)
  key   TEXT PRIMARY KEY,             -- v1 has one key: 'written_by'
  value TEXT NOT NULL                 -- ipc::build_info::APP_VERSION of the last binary that opened the store read-write
);
```
**Plan decision (spec silent):** `range` as two integers (`range_start` + `first_retained_seq`, contiguous seqs make the count `first_retained_seq − range_start`), `prune_seq`/`prev_row_hash`/`row_hash` columns (F.9); the store's `install_id` is not stored separately (it is read from `target` of the latest `RESTORE`, else `GENESIS`, else the newest retained `APP_START`, §8.6); the only metadata is `meta.written_by`, which exists solely for the §8.13 message "audit data was written by atlas-duck vX" (no plaintext source for `vX` exists otherwise) and is never used for a security decision.

### F.11 Payloads this crate writes or parses

All JSON objects, JCS-encoded. `null` where a value is absent.

| Event | Payload (M2-owned fields) | Plaintext columns M2 sets |
|---|---|---|
| `GENESIS` | `{chain_id, install_id, created_at, archived_db: {file, chain_id, head_seq, head_hash}|null, previous_chain_id: null, previous_last_anchor: null}` (the last two M10) | `target` = install_id |
| `SCHEMA_MIGRATED` | `{from, to, app_version}` | — |
| `VERIFY` | `{scope: "startup"|"full"|"recover"|"restore", result, findings: [{kind, expected_seq, expected_hash, observed_seq, observed_hash, detail}], detected_at, unanchored_tail: N|null}`; `result` = first incident kind, else `"ok"`, `"unanchored_tail"`, `"interrupted_prune_reconciled"`, `"interrupted_restore_reconciled"` | flag `integrity_incident` iff any finding is an incident kind |
| `INTEGRITY_ACK` | `{verify_seq, os_user, note}` | `os_user` |
| `CLOCK_ANOMALY` | `{kind: "local_ahead"|"local_behind"|"prune_skipped", local: ts, server: ts|null, reason: "now_before_head"|"now_before_last_prune"|null}` | — |
| `PRUNE` | `{range: [range_start, first_retained_seq], count, cutoff: "YYYY-MM-DD", clamped: bool, baseline, destroyed_key_ids: [..], prune_log_row_hash, settings: <Settings JSON, T12>}` | — |
| `CONFIG_CHANGED` (policy keys only) | `{source: "app"|"file", key, old, new, requested, applied: bool, confirmed: {dialog_text_sha256}|null}` | — |
| `LEGAL_HOLD_CHANGED` | `{source, old, new, applied, confirmed}` | — |
| `BACKUP` | `{bundle_dir_name, head: {seq, record_hash}, manifest_sha256}` | — |
| `RESTORE` | §8.11 step 5 fields verbatim: `{install_id, source_install_id, source_chain_id, source_head_seq, source_head_hash, new_chain_id, backup_created_at, prior_keychain_anchor: {chain_id, seq, record_hash}|null, replaced_db: {file, chain_id, head_seq, head_hash}|null, records_lost, pats_lost}` | `target` = live install_id; `chain_id` column = `new_chain_id` |
| `KEY_RECOVERED` | `{what: ["kek", "head_anchor", "first_retained_anchor", "pats_lost"]}` | — |
| `WRITE_OUTCOME_UNKNOWN` (reconciliation) | `{request_index, reason: "crash"}` | copies `request_id`, `op_id`, `op_class`, `instance_id`, `target` from the `WRITE_APPROVED` row |
| `ABANDONED` | `{reason: "crash"}` | copies `request_id`, `op_id`, `op_class`, `instance_id`, `target` from the first row of the request |
| `WRITE_APPROVED` (parsed only) | `{candidate_rev, request_set_hash: hex, requests: [F.8]}` | — |
| `SCRIPT_FAILED` (parsed only) | `{reason, queued, dispatched, data_free, direct}` | — |

Backup `manifest.json` (written last, JCS, **Plan decision (spec silent)**): `{"format":"atlas-duck-backup/v1", "created_at", "app_version", "install_id", "chain_id", "head":{"seq","record_hash"}, "first_retained":{"seq","prev_hash"}, "genesis_hash", "user_version", "snapshot_sha256", "recovery_sha256"}`.

### F.12 Locked reasons, outcomes, errors (names; C.3 types made concrete)

```rust
pub enum LockedReason { KeychainUnavailable, KeychainLost { offer: RecoveryOffer }, KeyringNotLocal }  // §4.3 strings: keychain_unavailable | keychain_lost | keyring_not_local
pub enum RecoveryOffer { RecoverThisLog, FinishRestore }                                              // which credential-window purpose M6 shows
pub enum StartupOutcome { Ready { store: Store, verify: VerifyOutcome }, FirstRun, Locked(LockedReason), StoreNewer { found: String } }  // C.3
pub enum OpenError { Io(std::io::Error), Sqlite(String), MigrationFailed { from: u32, to: u32, message: String }, AlreadyExists, NotFirstRun,
                     PassphraseTooShort, PassphraseMismatch, KeyStore(KeyStoreError), WrongPassphrase, Integrity(String), Restore(RestoreError) }
pub enum AuditError { AppendFailed(String), StorageLow, Closed, Decrypt { seq: u64 }, PayloadHash { seq: u64 }, NotFound { seq: u64 },
                      NeedsConfirmation(&'static str), Invalid(&'static str), KeyStore(KeyStoreError), Restore(RestoreError), Io(String) }
pub enum RestoreError { SnapshotNewer { found: String }, NotABundle, ManifestMismatch, ChainBroken(String), WrongPassphrase,
                        RollbackNeedsConfirmation { records_lost: u64 }, AnchorDirMismatch(String) }
pub struct Confirmed { pub dialog_text_sha256: [u8; 32] }   // built by core after NativeConfirmer::confirm == Ok (M3); recorded in CONFIG_CHANGED
pub struct RustChosenPath(std::path::PathBuf);              // pub fn from_native_dialog(p: PathBuf) -> Self; pub fn path(&self) -> &Path
```
**Plan decision (spec silent):** `Confirmed` and `RustChosenPath` have public constructors (audit cannot depend on `core`/`app`); their names document that only the native-dialog paths in M3/M6/M10 may construct them, and a grep check in M10 enforces it. `RecoveryOffer` tells M6 whether to show "Recover this log" or "Finish restore" (§8.7).

---
## Task overview

| Task | Title | Main tests (ids) |
|---|---|---|
| T01 | Pins, crate skeleton, `ipc::jcs`, core types, `testing` doubles | `jcs_*` (U-07 part) |
| T02 | Canonical encoding, `record_hash`, AAD, `request_set_hash`, prune-log row hash, golden vectors + Node cross-check | U-07 |
| T03 | Payload crypto, DEK wrap, recovery blob, query tag | U-08, L38 |
| T04 | Schema v1, pragmas, migration runner, version gate | U-19 (runner), U-21 (`store_newer`), V22 |
| T05 | `KeyStore`, `OsKeyStore` per OS, Windows persistence, keyring locality, canary | RF-3a, I-44 (locality half), V08, V29 |
| T06 | `Clock`, `SystemClock` (suspend-aware), `ClockState` (epoch, flags, anomalies) | U-11/U-13/U-14 unit level, V27 |
| T07 | Writer thread, `append`/`append_batch`, DEK selection, `create_new_store` + `GENESIS`, read API, admission | X-03 (store half) |
| T08 | Anchors: layouts, anchor thread, batching ≤ 1 s, barriers, "no anchor before verify" | U-17 (anchor half) |
| T09 | Verification engine, startup anchor rule, interrupted prune, `full_verify`, incidents, tamper suite | U-06, U-17, U-22 (prune half) |
| T10 | `open()`: steps 1–4, keychain cases, `install_id` cross-check, retry schedule | U-18 (start half), U-20, U-21 |
| T11 | Prune, `prune_log`, cadence/baseline/clamp, crypto-shredding, legal hold, post-prune anchor | U-09, U-10, U-12 |
| T12 | Settings view, `apply_setting`, config-file reconcile | X-01, X-02 (store half) |
| T13 | Clock scenario suite over simulated months | U-10, U-11, U-12, U-13, U-14, RF-1a, RF-1b |
| T14 | Anchor-dir line types and the verifier side | U-06 (anchor-dir verifier clauses), U-14 (anchored `clock_behind`) |
| T15 | "Recover this log" and "Archive old DB and start fresh" | U-18 |
| T16 | Backup bundle, restore-as-continuation, interrupted restore, "Finish restore" | I-46, U-15, U-16, U-22 (restore half), `backup_restore_roundtrip` |
| T17 | M3-facing request API: `is_terminal`, `reconcile_after_crash`, header queries | (I-26 groundwork, P6) |
| T18 | CI keychain legs, Linux Secret Service, shared-keyring phases, verify-items record, exit criterion | I-43, I-44, RF-3a on CI, exit criterion |

Order is strict (each task consumes the previous ones). Every task ends with `cargo test -p atlas-duck-audit --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings` and one commit. Commit trailer on every commit:

```
Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>
```

All commands run from `C:/Code/atlas-duck` (Git Bash or PowerShell). On the Windows dev box only Windows runs locally; macOS/Linux behaviour is checked by the CI steps T18 adds (push the branch and read the job log).

---

### Task 1: Pins, crate skeleton, `ipc::jcs`, core types and the `testing` doubles

**Files:**
- Modify: `Cargo.toml` (root): add the pins of "Dependency pins" to `[workspace.dependencies]`; add `[profile.dev.package.argon2] opt-level = 3` and `[profile.dev.package.blake2] opt-level = 3` (Argon2id with 64 MiB takes tens of seconds unoptimized; tests inherit the dev profile).
- Modify: `crates/audit/Cargo.toml`, `crates/ipc/Cargo.toml`
- Create: `crates/ipc/src/jcs.rs`; modify `crates/ipc/src/lib.rs` (`pub mod jcs;`)
- Create: `crates/audit/src/{types.rs, error.rs, clock.rs (trait + UtcInstant only), keystore/mod.rs (trait + EntryName + errors only), testing.rs}`; modify `crates/audit/src/lib.rs`
- Modify: `ci/check-workspace.mjs`, `ci/check-workspace.test.mjs` (Step 1b)
- Test: `crates/ipc/tests/jcs.rs`, `crates/audit/tests/types.rs`

**Interfaces:**
- Consumes: `atlas_duck_ipc::paths::LocalDataDir` [M1], `atlas_duck_audit::lock::InstanceLock` [M1].
- Produces:
  - `atlas_duck_ipc::jcs::{to_jcs_vec(&serde_json::Value) -> Result<Vec<u8>, JcsError>, JcsError { IntegerOutOfRange, Serialize(String) }, MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991}`.
  - `atlas_duck_audit::types::{EventType (the 49 §8.3 names, C.3; `as_str()`, `parse(&str) -> Option<EventType>`, `ALL: [EventType; 49]`), EventFlags (u64 bitset, F.2 bits, consts EDITED … INTEGRITY_INCIDENT, CALLER_SETTABLE = EDITED|REDACTED|BATCH|STALE, CLOCK_MASK = BACKWARDS|FORWARD|BEHIND), DecisionColumn (8 values, `as_str`), Actor {agent_name, agent_name_source, client_kind, connection_id, peer_pid: Option<u32>, peer_exe: Option<PathBuf>, peer_origin_exe: Option<PathBuf>, os_user, atlassian_user, atlassian_user_key} (all `Option`, `Default`), NewEvent (C.3 fields), Committed {seq, record_hash}, UtcInstant(i64) {to_rfc3339_ms(), parse_rfc3339_ms(&str), date() -> NaiveDate}, QueryKind {Jql, Cql}, Confirmed, RustChosenPath}`.
  - `atlas_duck_audit::error::{AuditError, OpenError, RestoreError}` (F.12), each with a manual `Display` that never prints bytes.
  - `atlas_duck_audit::clock::Clock` (C.3: `now_utc() -> UtcInstant`, `suspend_aware_elapsed() -> Duration`).
  - `atlas_duck_audit::keystore::{KeyStore, EntryName, KeyStoreError, KeyringLocality}` (signatures in T05; this task writes them so `testing` compiles).
  - `atlas_duck_audit::testing::{FakeClock, MemKeyring, MemKeyStore, KeyOp}` (behaviour below).

**Spec:** §8.2 (columns, `decision`/`flags` values), §8.3 (closed event list), §8.4 (canonical encoding), C.3 (names), master plan "RFC 8785 (JCS) crate … M2/M3".

**Plan decisions (spec silent):**
- JCS lives in `ipc` (not `audit`) because `ipc::proto::params_sha256` (M3) needs the same canonicalization and `ipc` may not depend on `audit`. One implementation, one pin.
- `to_jcs_vec` rejects any JSON integer with |v| > 2^53 − 1 (`IntegerOutOfRange`) instead of letting it through: RFC 8785 serializes numbers as IEEE-754 doubles, and `serde_jcs` writes `u64`/`i64` values as integers, so a larger integer would produce bytes no other JCS implementation reproduces. Payload builders (M2/M3) must keep integers inside that range (sizes, seqs and counts always are).
- `EventType::as_str()` returns the §8.3 name exactly (`"REQUEST_RECEIVED"`), which is also the `event_type` column value.

- [ ] **Step 1: Add the pins**

Add to the root `[workspace.dependencies]` (keep the existing comment style; one line each, exact `=` pins, features as in the table): `rusqlite`, `aes-gcm`, `sha2`, `hmac`, `hkdf`, `argon2`, `zstd`, `getrandom`, `zeroize`, `secrecy`, `serde_jcs`, `unicode-normalization`, `chrono`, `base64`, `hex`, `keyring-core`, `windows-native-keyring-store`, `apple-native-keyring-store`, `zbus-secret-service-keyring-store`, `proptest`. Example lines:

```toml
rusqlite = { version = "=0.40.2", features = ["bundled"] }
aes-gcm = { version = "=0.11.1", default-features = false, features = ["aes", "alloc", "zeroize"] }
argon2 = { version = "=0.6.0", default-features = false, features = ["alloc", "zeroize"] }
zstd = { version = "=0.14.0", default-features = false }
chrono = { version = "=0.4.45", default-features = false, features = ["std"] }
apple-native-keyring-store = { version = "=1.0.2", default-features = false, features = ["keychain"] }
zbus-secret-service-keyring-store = { version = "=1.0.1", default-features = false, features = ["crypto-rust"] }
```

`crates/audit/Cargo.toml`:

```toml
[features]
# Test doubles (FakeClock, MemKeyStore, fault points). Never enabled by a release build.
testing = []

[dependencies]
atlas-duck-ipc = { path = "../ipc" }
serde = { workspace = true }
serde_json = { workspace = true }
rusqlite = { workspace = true }
aes-gcm = { workspace = true }
sha2 = { workspace = true }
hmac = { workspace = true }
hkdf = { workspace = true }
argon2 = { workspace = true }
zstd = { workspace = true }
getrandom = { workspace = true }
zeroize = { workspace = true }
secrecy = { workspace = true }
unicode-normalization = { workspace = true }
chrono = { workspace = true }
base64 = { workspace = true }
hex = { workspace = true }
keyring-core = { workspace = true }

[target.'cfg(unix)'.dependencies]
libc = { workspace = true }

[target.'cfg(windows)'.dependencies]
windows-native-keyring-store = { workspace = true }
windows-sys = { workspace = true, features = ["Win32_Foundation", "Win32_Security_Credentials", "Win32_Storage_FileSystem", "Win32_System_WindowsProgramming"] }

[target.'cfg(target_os = "macos")'.dependencies]
apple-native-keyring-store = { workspace = true }

[target.'cfg(target_os = "linux")'.dependencies]
zbus-secret-service-keyring-store = { workspace = true }

[dev-dependencies]
atlas-duck-audit = { path = ".", features = ["testing"] }
tempfile = { workspace = true }
proptest = { workspace = true }
```

`crates/ipc/Cargo.toml`: add `serde_jcs = { workspace = true }` under `[dependencies]` (not feature-gated; the sandbox worker and CLI may link it, it does no I/O).

Run: `cargo check -p atlas-duck-audit -p atlas-duck-ipc` (this updates `Cargo.lock`; the network fetch of crates is expected).
Expected: compiles (empty modules are fine). Then `cargo tree -p atlas-duck-audit -e normal --target all | grep -E "zeroize|sha2|digest"` and note the resolved versions for the commit message.

Run: `cargo deny --locked check licenses bans sources` if `cargo-deny` is installed locally; otherwise push and read the `supply-chain` job. Expected: `licenses ok`. If a license outside the allow list is reported, STOP and report the crate and license (do not edit `deny.toml`).

- [ ] **Step 1b: Extend the CLI/worker closure ban (`ci/check-workspace.mjs`)**

The checker matches crate names exactly (`closure.has(b)`), so the new keyring crates are not caught by the existing `"keyring"` entry. `audit` links them, and `atlas-duck-cli` and `atlas-duck-sandbox-worker` must never reach them (§2.1: no keychain or DB code linked).

1. First write the failing tests in `ci/check-workspace.test.mjs`: change the `BANNED` array (line 216) to `["reqwest", "hyper", "rusqlite", "libsqlite3-sys", "keyring", "keyring-core", "windows-native-keyring-store", "apple-native-keyring-store", "zbus-secret-service-keyring-store", "secret-service", "security-framework"]`. The existing loop then generates, for both `atlas-duck-cli` and `atlas-duck-sandbox-worker`, the case "with <crate> in its closure (transitively) is a violation" (cli/worker → `some-wrapper` → crate) and expects exactly `` `${pkg}: banned crate ${banned} in normal-dependency closure (§2.1)` ``: 8 new cases (4 crates x 2 packages). Add two more tests after the "banned crates are allowed outside cli and sandbox-worker" test:
   - `serde_jcs is allowed in the closure of cli and sandbox-worker` (JCS lives in `ipc`, which both crates may depend on): `e = baseEdges(); e["atlas-duck-ipc"].push("serde_jcs"); e["serde_jcs"] = ["ryu-js"];` then `assert.deepEqual(graph(e), [])`.
   - extend "banned crates are allowed outside cli and sandbox-worker" with `e["atlas-duck-audit"].push("keyring-core", "windows-native-keyring-store", "apple-native-keyring-store", "zbus-secret-service-keyring-store");` before the `deepEqual(graph(e), [])`, so `audit` (and through it `core`, which is not cli/worker) stays legal.
2. Run `node --test ci/check-workspace.test.mjs` → Expected: the 8 new ban cases FAIL (no violation reported), the two allow tests pass.
3. In `ci/check-workspace.mjs` add `"keyring-core"`, `"windows-native-keyring-store"`, `"apple-native-keyring-store"` and `"zbus-secret-service-keyring-store"` to `BANNED_IN_CLI_AND_WORKER` right after `"keyring"` (keep `"keyring"`, `"secret-service"`, `"security-framework"`); update the comment above it to mention the keyring-core store crates. Do NOT add `serde_jcs` or `ryu-js` (it does no I/O, §2.1 does not forbid it).
4. Run `node --test "ci/*.test.mjs"` → all pass. Run `node ci/check-workspace.mjs` after Step 1's `cargo check` → `check-workspace: ok (11 workspace members)`; if it reports a banned crate for cli or worker, a dependency edge was added wrongly: STOP and report it.

- [ ] **Step 2: Write the failing JCS tests** (`crates/ipc/tests/jcs.rs`)

Each test parses an input with `serde_json::from_str` and compares `to_jcs_vec` output as UTF-8 text:
1. `jcs_rfc8785_example`: input `{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}` → exactly `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`.
2. `jcs_utf16_key_order`: input object with keys `"\u20ac"`, `"\r"`, `"\ufb33"`, `"1"`, `"\ud83d\ude00"`, `"\u0080"`, `"\u00f6"` (values = any strings) → keys appear in the order `"\r"`, `"1"`, `"\u0080"`, `"ö"`, `"€"`, `"😀"`, `"דּ"` (RFC 8785 §3.2.3; UTF-8 byte order would put U+FB33 before the emoji).
3. `jcs_bmp_edge_order`: keys `"\uffff"` and `"\ud800\udc00"` (U+10000) → U+10000 first.
4. `jcs_numbers`: `0`, `-0.0` → `0`; `1e21` → `1e+21`; `1e20` → `100000000000000000000`; `5e-324` → `5e-324`; `1.7976931348623157e308` → `1.7976931348623157e+308`; `0.000001` → `0.000001`; `1e-7` → `1e-7`; `-1.5` → `-1.5`; `9007199254740991` → `9007199254740991`.
5. `jcs_rejects_unsafe_integers`: `9007199254740992`, `-9007199254740992`, `18446744073709551615` → `Err(JcsError::IntegerOutOfRange)`, also when nested in arrays/objects.
6. `jcs_is_idempotent`: for 3 nested sample objects, `to_jcs_vec(parse(to_jcs_vec(v))) == to_jcs_vec(v)`.

Run: `cargo test -p atlas-duck-ipc --test jcs --locked`
Expected: fails to compile (`jcs` module missing).

- [ ] **Step 3: Implement `ipc::jcs`**

```rust
//! RFC 8785 JSON Canonicalization Scheme, one implementation for the audit payload bytes
//! (§8.4) and `params_sha256` (§4.2, M3).
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JcsError { IntegerOutOfRange, Serialize(String) }

pub fn to_jcs_vec(v: &serde_json::Value) -> Result<Vec<u8>, JcsError> {
    check_integers(v)?;
    serde_jcs::to_vec(v).map_err(|e| JcsError::Serialize(e.to_string()))
}

fn check_integers(v: &serde_json::Value) -> Result<(), JcsError> {
    use serde_json::Value::*;
    match v {
        Number(n) => {
            if let Some(i) = n.as_i64() { if i.unsigned_abs() > MAX_SAFE_INTEGER as u64 { return Err(JcsError::IntegerOutOfRange) } }
            else if n.as_u64().is_some() { return Err(JcsError::IntegerOutOfRange) } // > i64::MAX
            Ok(())
        }
        Array(a) => a.iter().try_for_each(check_integers),
        Object(o) => o.values().try_for_each(check_integers),
        _ => Ok(()),
    }
}
```
If test 2, 3 or 4 fails because `serde_jcs 0.2.0` sorts or formats differently, do not patch around it silently: STOP and report the failing output; the fallback (a ~80-line in-crate JCS serializer sorting keys by `encode_utf16()` and formatting numbers with `ryu-js`) needs the lead's approval because it changes a pin.

Run: `cargo test -p atlas-duck-ipc --test jcs --locked` → Expected: `test result: ok. 6 passed`.

- [ ] **Step 4: Write the failing type tests** (`crates/audit/tests/types.rs`)
- `event_type_names_round_trip`: for every `EventType::ALL`, `EventType::parse(t.as_str()) == Some(t)`; `ALL.len() == 49`; the list equals the C.3 list (write the 49 names literally in the test).
- `flags_bits_are_fixed`: `EventFlags::EDITED.bits() == 1`, …, `INTEGRITY_INCIDENT.bits() == 128`; `CALLER_SETTABLE.bits() == 15`; `CLOCK_MASK.bits() == 112`.
- `decision_strings`: the 8 strings of §8.2.
- `utc_instant_format`: `UtcInstant(0).to_rfc3339_ms() == "1970-01-01T00:00:00.000Z"`; `UtcInstant(1_791_460_800_123)` formats to `"2026-10-08T12:00:00.123Z"` (compute in the test with chrono, then hard-code the string after checking it by hand); round trip through `parse_rfc3339_ms`; parse rejects `"2026-10-08T12:00:00Z"` (no ms) and offsets other than `Z`.
- `errors_never_print_bytes`: `format!("{}", AuditError::Decrypt { seq: 7 })` contains `7` and no hex longer than 8 chars; same for `KeyStoreError::Other("bad data".into())`.

- [ ] **Step 5: Implement `types.rs`, `error.rs`, `clock.rs` (trait only), `keystore/mod.rs` (declarations only)**

`EventFlags`: a `#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)] pub struct EventFlags(u64)` with `const` items, `bits()`, `from_bits(u64)`, `contains`, `|`, `|=`, `&`. No external bitflags crate.

`NewEvent` exactly as C.3 (`event_type, request_id, op_id, op_class, instance_id, target, actor: Actor, decision: Option<DecisionColumn>, flags: EventFlags, payload: serde_json::Value`). The writer masks `flags` with `CALLER_SETTABLE` (clock flags and `integrity_incident` are store-managed).

- [ ] **Step 6: Implement `testing.rs`**

`#![cfg(any(test, feature = "testing"))]` module with:
- `FakeClock { wall: Mutex<UtcInstant>, mono: Mutex<Duration> }`: `new(start: UtcInstant)`, `advance(d)` (wall and mono), `advance_mono_only(d)`, `advance_wall_only(d)`, `set_wall(UtcInstant)`, `jump_wall_days(i64)` (wall only, can be negative). `impl Clock`.
- `MemKeyring { entries: Mutex<BTreeMap<(String /*service*/, String /*account*/), Vec<u8>>>, faults: Mutex<Vec<Fault>>, unavailable: AtomicBool, locality: Mutex<KeyringLocality>, log: Mutex<Vec<KeyOp>> }` (one shared keyring, like one daemon) and `MemKeyStore { install_id, ring: Arc<MemKeyring> }` (`MemKeyStore::new(ring, install_id)`). `impl KeyStore for MemKeyStore` with the rendering of F.6. Fault API: `ring.fail_next(op: KeyOpKind /*Get|Set|Delete*/, entry: Option<EntryName> /*None = any*/, err: KeyStoreError, times: u32)`, `ring.set_unavailable(bool)` (every op → `Unavailable`), `ring.set_locality(KeyringLocality)`, `ring.wipe_install(install_id)` ("keychain wiped"), `ring.raw_get(service, account)`, `ring.ops() -> Vec<KeyOp>` (records `{kind, full_name}` of every call, for "no keyring write" assertions).

- [ ] **Step 7: Run and fix until green**

Run: `cargo test -p atlas-duck-audit -p atlas-duck-ipc --locked`
Expected: all tests pass, including the M1 `lock` tests.
Run: `cargo clippy --workspace --all-targets --locked -- -D warnings` → Expected: no warnings.
Run: `node ci/check-workspace.mjs` → Expected: `check-workspace: ok (11 workspace members)` on stderr, exit 0.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock ci crates/ipc crates/audit
git commit -m "feat(audit): M2 pins, core types, ipc::jcs (RFC 8785) and the testing doubles

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Canonical encoding, `record_hash`, AAD, `request_set_hash`, prune-log row hash, golden vectors

**Files:**
- Create: `crates/audit/src/encoding.rs`, `crates/audit/src/request_set.rs`
- Create: `crates/audit/tests/encoding.rs`, `crates/audit/tests/golden.rs`, `crates/audit/tests/vectors/format_v1.json` (generated, then hand-checked)
- Create: `ci/check-audit-vectors.mjs`, `ci/check-audit-vectors.test.mjs`
- Modify: `.github/workflows/ci.yml` (`rust` job: add a step `node ci/check-audit-vectors.mjs` next to "CI script tests"), `.gitlab-ci.yml` (`node:ci-checks` job: same command)

**Interfaces:**
- Consumes: T01 types, `ipc::jcs`.
- Produces:
  - `encoding::{FORMAT_VERSION = 1, Field, push_frame, RowFields<'a> {seq, format_version, chain_id, ts_utc, epoch: Option<&str>, request_id: Option<&str>, event_type, op_id, op_class, instance_id, target, agent_name, agent_name_source, client_kind, connection_id, peer_pid: Option<u64>, peer_exe: Option<&[u8]>, peer_origin_exe: Option<&[u8]>, os_user, atlassian_user, atlassian_user_key, decision, flags: u64, payload_len: u64, payload_sha256: &[u8;32], key_id: u64, nonce: &[u8;12], payload_ct: &[u8], prev_hash: &[u8;32]}, canonical_bytes, record_hash, aad, os_path_bytes, ZERO_HASH: [u8; 32]}`.
  - `request_set::{RequestRecord (C.3), request_set_hash(&[RequestRecord]) -> [u8; 32], requests_to_json(&[RequestRecord]) -> serde_json::Value, requests_from_json(&serde_json::Value) -> Result<Vec<RequestRecord>, AuditError>}`; `lib.rs` re-exports `request_set_hash` and `RequestRecord` at the crate root (C.3).
  - `encoding::prune_row_hash(prev_row_hash, prune_seq, range_start, cutoff_epoch, last_pruned_record_hash, first_retained_seq) -> [u8; 32]` (F.9).

**Spec:** §8.4 (encoding, `record_hash`, AAD field list), §5.1 inv. 3 (`request_set_hash` over index, method, resolved URL, `Content-Type`, body bytes), §13 "canonical-encoding golden vectors".

**Plan decisions (spec silent):** all of F.2, F.8, F.9 (frame of NULL, integer width, domain prefixing, flag bits, request-set and prune-row layouts).

- [ ] **Step 1: Write the failing encoding tests** (`tests/encoding.rs`)
- `null_and_empty_differ`: `push_frame(Null)` = `00 00 00 00 00`; `push_frame(Bytes(b""))` = `01 00 00 00 00`; `push_frame(Int(1))` = `01 00 00 00 08 00 00 00 00 00 00 00 01`.
- `canonical_layout_minimal_row`: a `RowFields` with `seq=1, format_version=1, chain_id="c", ts_utc="1970-01-01T00:00:00.000Z", epoch=None, event_type="GENESIS", target="i", flags=64, payload_len=2, payload_sha256=[0xAA;32], key_id=1, nonce=[0x11;12], payload_ct=[0x22;3], prev_hash=[0;32]`, everything else `None` → `canonical_bytes` equals the concatenation built by hand in the test from the F.2 table (write the 29 expected frames as literal byte arrays; total length = 29·5 + (8+8+1+24+7+1+8+8+32+8+12+3+32) = 145 + 152 = 297 bytes; assert `len() == 297`; the hand-built concatenation is the real assertion).
- `record_hash_domain`: `record_hash(1, &ZERO_HASH, b"x")` equals `Sha256::digest(b"atlas-duck/audit/v1" ++ [0u8;32] ++ b"x")` computed in the test.
- `aad_field_order`: changing any one of the 11 AAD fields changes `aad()`; changing any other field (e.g. `agent_name`, `prev_hash`, `payload_ct`) leaves `aad()` unchanged; `aad()` starts with `b"atlas-duck/aad/v1\x01"`.
- `every_field_is_hashed`: for each of the 29 fields, a one-field change changes `canonical_bytes` (proptest over random rows: two rows differing in exactly one field never produce equal bytes).
- `canonical_injective_on_boundaries`: rows `{agent_name: "ab", os_user: "c"}` vs `{agent_name: "a", os_user: "bc"}` differ in bytes.
- `wtf8_paths` (cfg windows): a path from `OsString::from_wide(&[0x0061, 0xD83D, 0xDE00, 0xD800, 0x0062])` → bytes `61 F0 9F 98 80 ED A0 80 62`. (cfg unix): a path from `OsStr::from_bytes(b"/tmp/\xff")` → identical bytes.
- `request_set_hash_vector`: two records `[{0, "POST", "https://h/rest/api/2/issue", Some("application/json"), b"{}"}]` → equals SHA-256 of the literal byte string built in the test per F.8; order matters (swapping two records changes the hash); `content_type: None` differs from `Some("")`.
- `requests_json_round_trip`: `requests_from_json(requests_to_json(r)) == r` for bodies containing non-UTF-8 bytes; `requests_from_json` rejects a missing `body_b64`, unpadded base64 and unknown fields (`Invalid`).
- `prune_row_hash_chain`: first row with `ZERO_HASH` prev; changing `cutoff_epoch` changes the hash.

Run: `cargo test -p atlas-duck-audit --test encoding --locked` → Expected: compile errors (module missing).

- [ ] **Step 2: Implement `encoding.rs` and `request_set.rs`** exactly per F.2/F.8/F.9 and the code in F.2. `canonical_bytes` pushes the 29 frames in table order; `RowFields` is built by the writer (T07) and by the verifier (T09) from a SQLite row, so add `RowFields::from_row(&rusqlite::Row)` here with the column order of F.10.

Run: `cargo test -p atlas-duck-audit --test encoding --locked` → Expected: all pass.

- [ ] **Step 3: Golden-vector generator and checker** (`tests/golden.rs`)

The file `tests/vectors/format_v1.json` holds (all bytes lowercase hex):
```json
{
  "format_version": 1,
  "rows": [ { "name": "...", "fields": { "...F.2 columns, bytes as hex, nulls as null..." },
              "dek": "...", "plaintext_jcs": "<utf8 text>", "compressed": "...", "canonical": "...", "aad": "...", "record_hash": "..." } ],
  "request_sets": [ { "records": [ {"index":0,"method":"POST","url":"...","content_type":"...|null","body":"<hex>"} ], "hash": "..." } ],
  "prune_rows": [ { "prev_row_hash": "...", "prune_seq": 9, "range_start": 1, "cutoff_epoch": "2026-01-10", "last_pruned_record_hash": "...", "first_retained_seq": 9, "row_hash": "..." } ],
  "jcs": [ { "input": "<json text>", "output": "<jcs text>" } ]
}
```
Rows (deterministic: fixed DEK, fixed nonce, payload sealed with an internal `crypto::seal_with_nonce`; T03 provides crypto, so in this task the `compressed`/`payload_ct` are produced with the plain `aes-gcm` and `zstd` calls inline in the test and T03 later asserts it reproduces them):
1. `genesis_null_epoch`: `seq 1`, `epoch null`, `event_type "GENESIS"`, `flags 0`, `target` = an install id, payload `{"archived_db":null,"chain_id":"…","created_at":"…","install_id":"…","previous_chain_id":null,"previous_last_anchor":null}`, `prev_hash` zero.
2. `request_received_all_columns`: every column present, `agent_name ""` (present-empty), `peer_exe` with non-ASCII bytes (`/home/jürgen/bin/agent` as UTF-8), `peer_pid 4294967295`.
3. `decision_and_flags`: `decision "approve_edited"`, `flags 1|4|16` = 21, `epoch "2026-10-08"`.
4. `utf16_order_payload`: payload with keys `"😀"` and `"דּ"` (pins the JCS order inside a hashed record).

Mechanics: `golden_vectors_match` recomputes every entry from its inputs and asserts equality with the file. With env `ATLAS_DUCK_REGEN_VECTORS=1` it instead writes the file (pretty-printed, stable key order) and passes. The committed file is generated once in this task, then **frozen**: after M2, a test diff on this file is a format break.

Run: `ATLAS_DUCK_REGEN_VECTORS=1 cargo test -p atlas-duck-audit --test golden --locked` (PowerShell: `$env:ATLAS_DUCK_REGEN_VECTORS=1; cargo test ...; Remove-Item Env:ATLAS_DUCK_REGEN_VECTORS`)
Then: `cargo test -p atlas-duck-audit --test golden --locked` → Expected: `golden_vectors_match ... ok`.
Hand check (write the result into the commit message): for row 1, the first 10 bytes of `canonical` are `01 00 00 00 08 00 00 00 00 00` (seq frame start) and bytes 13..26 are the `format_version` frame `01 00 00 00 08 00 00 00 00 00 00 00 01`; the `epoch` frame (5th) is `00 00 00 00 00`.

- [ ] **Step 4: Independent Node cross-check** (`ci/check-audit-vectors.mjs`, no npm dependencies, `node:crypto` only)

Re-implement in JavaScript, from F.2/F.3/F.8/F.9 (not by porting the Rust code line by line): frame, canonical bytes (29 fields), `record_hash`, AAD, `request_set_hash`, `prune_row_hash`; AES-256-GCM decrypt of each row's `payload_ct` with `dek`, `nonce`, `aad` (`crypto.createDecipheriv('aes-256-gcm', key, nonce)`, `setAAD`, `setAuthTag(last 16 bytes)`) and compare with `compressed`; SHA-256 of `plaintext_jcs` equals `payload_sha256`; JCS: `canonicalize(JSON.parse(input))` with keys sorted by the default JS string comparison (UTF-16 code units) and numbers printed by `String(n)` / `JSON.stringify` (ECMAScript = RFC 8785) equals `output`, and `canonicalize(JSON.parse(plaintext_jcs)) === plaintext_jcs`. Exit 0 and print `check-audit-vectors: ok (<n> rows, <m> request sets, <k> prune rows, <j> jcs)` on stderr; exit 1 with one line per mismatch.
`ci/check-audit-vectors.test.mjs` (node:test): the checker passes on the committed file and fails on a copy with one flipped hex digit in `canonical`, in `aad` and in `plaintext_jcs`.

Run: `node ci/check-audit-vectors.mjs` → Expected: exit 0, the ok line.
Run: `node --test "ci/*.test.mjs"` → Expected: all pass (existing M1 tests included).

- [ ] **Step 5: CI wiring**

`ci.yml` `rust` job, after "CI script tests": step `name: Audit golden vectors (independent Node check, §8.4)` → `run: node ci/check-audit-vectors.mjs`. `.gitlab-ci.yml` `node:ci-checks`: add the same command.

- [ ] **Step 6: Clippy and commit**

Run: `cargo clippy --workspace --all-targets --locked -- -D warnings` → no warnings.
```bash
git add crates/audit ci/check-audit-vectors.mjs ci/check-audit-vectors.test.mjs .github/workflows/ci.yml .gitlab-ci.yml
git commit -m "feat(audit): canonical encoding FIELD_LIST[1], record_hash, AAD, request_set_hash; golden vectors + Node cross-check

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Payload crypto, DEK wrapping, recovery blob, query tag

**Files:**
- Create: `crates/audit/src/crypto.rs`, `crates/audit/src/recovery.rs`
- Create: `crates/audit/tests/crypto.rs`
- Modify: `crates/audit/tests/golden.rs`, `tests/vectors/format_v1.json` (add `dek_wraps`, `recovery`, `query_tags` sections), `ci/check-audit-vectors.mjs` (check `dek_wraps` and `query_tags`; recovery is Rust-only, no Argon2 in `node:crypto` 22)

**Interfaces:**
- Consumes: T02 `aad`, F.3–F.5, F.7.
- Produces:
  - `crypto::{Kek, Dek}`: newtypes over `Zeroizing<[u8; 32]>`; `Kek::generate()`, `Kek::from_entry_bytes(&[u8]) -> Result<Kek, KekEntryError {NewerLayout(u8), Malformed}>`, `Kek::to_entry_bytes(&self) -> Zeroizing<Vec<u8>>` (F.6 `0x01 ‖ 32`), `Dek::generate()`; no `Debug` that prints bytes (`Debug` prints `Kek([REDACTED])`); `PartialEq` via `subtle`-free constant-time compare written by hand (`fold` of XOR over 32 bytes).
  - `crypto::{random_nonce() -> [u8; 12], compress(&[u8]) -> Result<Vec<u8>, AuditError>, decompress(&[u8], payload_len: u64) -> Result<Vec<u8>, AuditError>, seal(dek, nonce, aad, compressed) -> Result<Vec<u8>, AuditError>, open(dek, nonce, aad, ct) -> Result<Vec<u8>, AuditError::Decrypt>}`.
  - `crypto::{wrap_dek(kek, key_id: u64, month: Option<&str>, dek) -> Result<Vec<u8>, AuditError>, wrap_dek_with_nonce(..), unwrap_dek(kek, key_id, month, wrapped) -> Result<Dek, UnwrapError>}`.
  - `crypto::{query_key(&Kek) -> Zeroizing<[u8; 32]>, query_tag(k_q, QueryKind, &str) -> String}`.
  - `recovery::{RECOVERY_LAYOUT = 1, MIN_PASSPHRASE_CHARS = 12, seal_recovery(&SecretString, &Kek) -> Result<Vec<u8>, OpenError>, seal_recovery_with(pass, kek, salt, nonce), open_recovery(&SecretString, &[u8]) -> Result<Kek, RecoveryError {WrongPassphrase, NewerLayout(u8), Malformed}>, new_recovery_blob(first: &SecretString, second: &SecretString, kek: &Kek) -> Result<Vec<u8>, OpenError /* PassphraseTooShort | PassphraseMismatch */>, recovery_layout(&[u8]) -> Option<u8>}`.

**Spec:** §8.4 (AAD), §8.6 (KEK, DEKs, recovery passphrase: Argon2id m = 64 MiB, t = 3, p = 4, 16-byte salt; wrap with the first entry, unwrap with the second, compare before committing), §8.2/L38 (query tag), §10.1 (`Zeroizing`).

**Plan decisions (spec silent):** F.4 wrap AAD, F.5 blob layout, NFC of the passphrase, constant-time KEK compare.

- [ ] **Step 1: Write the failing tests** (`tests/crypto.rs`)
- `payload_round_trip`: JCS bytes of a 1 MiB JSON string → compress → seal → open → decompress → equal; `payload_sha256` check passes.
- `aad_binding`: sealing under AAD of row A and opening with AAD of row B (differs only in `seq`, then only in `epoch` NULL→`"2026-10-08"`, then only in `key_id`) fails with `Decrypt`.
- `ciphertext_swap_fails`: two rows sealed with the same DEK; opening row A's `payload_ct` with row B's nonce+AAD fails.
- `nonces_unique`: 100 000 `random_nonce()` values are distinct.
- `wrong_dek_fails`.
- `dek_wrap_round_trip_and_binding`: wrap (key_id 3, month `"2026-10"`) → unwrap ok; unwrap with key_id 4 or month `None` or another KEK → `UnwrapError`; wrapped length 60.
- `kek_entry_layout`: `to_entry_bytes()[0] == 1`, length 33; `from_entry_bytes([2, ..])` → `NewerLayout(2)`; length 32 → `Malformed`.
- `recovery_round_trip`: a 12-char passphrase seals and opens to the same KEK; blob length 89, `blob[0] == 1`, bytes 17..29 = `00 01 00 00 | 00 00 00 03 | 00 00 00 04`.
- `recovery_wrong_passphrase`: → `WrongPassphrase` (never `Malformed`).
- `recovery_nfc`: `"Passphrase-é123"` with composed `é` (U+00E9) seals; the decomposed form (`e` + U+0301) opens it.
- `recovery_rules`: 11 characters → `PassphraseTooShort`; 12 emoji characters → ok (characters, not bytes); `new_recovery_blob(first, second_different)` → `PassphraseMismatch` and returns no blob.
- `recovery_newer_layout`: blob with first byte 2 → `NewerLayout(2)`.
- `argon2_params_pinned`: decode the 12 parameter bytes from a fresh blob and assert m = 65536, t = 3, p = 4.
- `argon2id_rfc9106_vector` (only if `argon2 0.6` exposes secret + associated data; otherwise mark the test `#[ignore = "argon2 0.6 API has no secret/ad"]` and say so in the commit message): password 32 × `0x01`, salt 16 × `0x02`, secret 8 × `0x03`, associated data 12 × `0x04`, m = 32, t = 3, p = 4, version 0x13, 32-byte tag = `0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659` (RFC 9106 §5.3).
- `query_tag_rules`: `query_tag(k, Jql, "project = ABC")` starts with `"jql:"` and has 64 hex chars; `"  project = ABC \n"` gives the same tag (trim); composed vs decomposed `"Müller"` give the same tag (NFC); `Cql` prefix `"cql:"`; another KEK gives a different tag; HKDF/HMAC reproduce: `K_q == HKDF-SHA256(salt none, ikm KEK, info "atlas-duck/query-tag/v1")` computed in the test with the `hkdf` crate directly.
- `secrets_not_in_debug`: `format!("{:?}", kek)` contains `REDACTED` and not the hex of the key.

Run: `cargo test -p atlas-duck-audit --test crypto --locked` → Expected: compile errors.

- [ ] **Step 2: Implement `crypto.rs` and `recovery.rs`**

Key code (aead 0.6 API, adjust names only if the compiler insists; keep the semantics):
```rust
use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit, Payload}};
pub fn seal(dek: &Dek, nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, AuditError> {
    let cipher = Aes256Gcm::new_from_slice(dek.as_bytes()).map_err(|_| AuditError::Invalid("dek length"))?;
    let n = Nonce::try_from(&nonce[..]).map_err(|_| AuditError::Invalid("nonce length"))?;  // aead 0.6 `Array`; use `Nonce::from_slice` if that is what 0.6 offers
    cipher.encrypt(&n, Payload { msg, aad }).map_err(|_| AuditError::AppendFailed("encrypt".into()))
}
pub fn query_key(kek: &Kek) -> Zeroizing<[u8; 32]> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, kek.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    // 32 bytes is always a valid HKDF-SHA256 output length
    let _ = hk.expand(b"atlas-duck/query-tag/v1", okm.as_mut());
    okm
}
pub fn query_tag(k_q: &[u8; 32], kind: QueryKind, query: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use unicode_normalization::UnicodeNormalization;
    let normalized: String = query.nfc().collect::<String>();
    let normalized = normalized.trim();
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(k_q).unwrap_or_else(|_| unreachable!()); // HMAC accepts any key length; replace with a match returning a fixed error string if clippy objects
    mac.update(normalized.as_bytes());
    let tag = hex::encode(mac.finalize().into_bytes());
    match kind { QueryKind::Jql => format!("jql:{tag}"), QueryKind::Cql => format!("cql:{tag}") }
}
```
Argon2: `argon2::Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(65536, 3, 4, Some(32))?)` then `hash_password_into(pass_bytes, &salt, key.as_mut())`; keep the derived key in `Zeroizing`. `decompress` uses `zstd::bulk::decompress(c, payload_len as usize)` and rejects `payload_len > 64 MiB` (`Invalid`) before allocating.

- [ ] **Step 3: Extend the golden vectors** with `dek_wraps` (fixed KEK, key_id, month incl. `null`, DEK, nonce → wrapped), `recovery` (fixed passphrase `"correct horse battery"`, salt, nonce, KEK → blob), `query_tags` (fixed KEK, kind, query incl. a decomposed `Müller` and surrounding whitespace → tag). Regenerate with `ATLAS_DUCK_REGEN_VECTORS=1`, re-run without it, extend the Node checker for `dek_wraps` (AES-GCM decrypt) and `query_tags` (`crypto.hkdfSync('sha256', kek, Buffer.alloc(0), 'atlas-duck/query-tag/v1', 32)`, `createHmac`, `String.prototype.normalize('NFC')` then `.trim()`). Also assert in `golden.rs` that `crypto::seal` reproduces the T02 row ciphertexts with the vectors' DEK/nonce.

Note for the Node `trim`: JS `trim()` strips the same Unicode `White_Space` set plus U+FEFF that Rust's `str::trim` does except U+FEFF (not White_Space in Rust). The vectors therefore use only ASCII spaces, tabs and newlines around queries; document this in a comment in both files.

Run: `cargo test -p atlas-duck-audit --test crypto --test golden --locked` → all pass. `node ci/check-audit-vectors.mjs` → ok.

- [ ] **Step 4: Clippy, commit**

```bash
git commit -am "feat(audit): payload envelope (zstd + AES-256-GCM), DEK wrap, Argon2id recovery blob, keyed query tag

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```
(`git add` the new files first.)

---

### Task 4: Schema v1, pragmas, migration runner and the version gate

**Files:**
- Create: `crates/audit/src/schema.rs`
- Create: `crates/audit/tests/schema.rs`
- (Fixture `tests/fixtures/schema/v1.db` is generated in T10, when a full store exists.)

**Interfaces:**
- Consumes: F.10, F.5 (`recovery_layout`).
- Produces:
  - `schema::{SCHEMA_HEAD: u32 = 1, DB_FILE = "audit.db", db_path(&LocalDataDir) -> PathBuf, create_v1(&rusqlite::Connection) -> rusqlite::Result<()>, open_rw(&Path) -> Result<Connection, OpenError>, open_ro(&Path) -> Result<Connection, OpenError>, apply_connection_pragmas(&Connection)}`.
  - `schema::Migration { from: u32, to: u32, apply: fn(&rusqlite::Transaction) -> rusqlite::Result<()> }`, `schema::MIGRATIONS: &[Migration] = &[]` (none in v1), `schema::run_migrations(conn, migrations, on_step: &mut dyn FnMut(&Transaction, u32, u32) -> Result<(), AuditError>) -> Result<Option<(u32, u32)>, OpenError>`: one transaction for all pending steps; inside it each `apply`, then `PRAGMA user_version = <to>`, then `on_step` (T10 appends `SCHEMA_MIGRATED` there); any error rolls back everything and returns `MigrationFailed`.
  - `schema::{StoreVersions { user_version: u32, head_format_version: Option<u64>, recovery_layout: Option<u8>, written_by: Option<String> }, read_versions(&Path) -> Result<StoreVersions, OpenError>, gate(&StoreVersions) -> Result<(), String /* found */>}`.
  - The plaintext `meta` table of F.10 with one key `written_by` = `ipc::build_info::APP_VERSION`, written at first run and updated by the writer after step 4 of every open. **Plan decision (spec silent):** §8.13 shows "audit data was written by atlas-duck vX" before the KEK is available, so `vX` needs a plaintext source; `meta` is outside the chain, advisory only, never used for a security decision.

**Spec:** §8.1 pragmas, §8.13 (versions, gate writes nothing, migrations in one transaction, failure rolls back and is not an incident), §15 V22 (`user_version` inside a transaction with WAL).

- [ ] **Step 1: Write the failing tests** (`tests/schema.rs`, temp dirs)
- `create_v1_pragmas`: after `create_v1` on a new file: `journal_mode` = `wal`, `page_size` = 8192, `auto_vacuum` = 2 (incremental), `user_version` = 1; a new connection via `open_rw` reports `synchronous` = 2 (FULL) and `secure_delete` = 1.
- `tables_exist`: `events`, `prune_log`, `keys`, `recovery`, `meta` with exactly the F.10 columns in order (`PRAGMA table_info`), no `vault` table.
- `v22_user_version_rolls_back`: a test migration 1→2 that creates a table then fails → `user_version` still 1, table absent, `MigrationFailed {from 1, to 2}`; a succeeding 1→2 → `user_version` 2 and `on_step` called once with `(1, 2)` inside the same transaction (the test's `on_step` inserts a row into a scratch table; after rollback of a later failing step 2→3 in the same run that row is gone too).
- `read_versions_writes_nothing`: create a v1 DB with one `events` row (insert raw via SQL), close; record SHA-256 and mtime of `audit.db` and `audit.db-wal` (if present); `read_versions` → `{1, Some(1), recovery layout, written_by}`; re-hash: identical bytes and mtimes for both files. (`-shm` is SQLite's shared-memory index and may change; it is excluded and the test says so.)
- `gate_refuses_newer`: `user_version 2` → `Err("user_version 2")`; `head_format_version 2` → `Err("format_version 2")`; recovery layout 2 → `Err("recovery layout 2")`; all equal → `Ok(())`.

- [ ] **Step 2: Implement `schema.rs`.** `read_versions` opens with `OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX`, runs `PRAGMA user_version`, `SELECT format_version FROM events ORDER BY seq DESC LIMIT 1`, `SELECT blob FROM recovery WHERE id=1`, `SELECT value FROM meta WHERE key='written_by'`, and closes. Never `PRAGMA journal_mode` on a read-only open (that would try to write).

Run: `cargo test -p atlas-duck-audit --test schema --locked` → all pass.

- [ ] **Step 3: Clippy, commit** (`feat(audit): schema v1, pragmas, migration runner, read-only version gate`).

---

### Task 5: `KeyStore`, `OsKeyStore` per OS, Windows persistence, keyring locality, canary

**Files:**
- Modify: `crates/audit/src/keystore/mod.rs`
- Create: `crates/audit/src/keystore/os.rs`, `crates/audit/src/keystore/locality.rs`, `crates/audit/src/keystore/windows.rs`
- Create: `crates/audit/tests/keystore.rs` (MemKeyStore + pure functions; runs everywhere), `crates/audit/tests/os_keystore.rs` (real OS keychain; every test `#[ignore = "touches the OS keychain; run in the CI keychain step"]`)

**Interfaces:**
- Consumes: `ipc::paths::{check_locality, Locality, base_dirs}` [M1].
- Produces:
```rust
pub trait KeyStore: Send + Sync {                       // C.3 + two added methods (allowed: additions)
    fn install_id(&self) -> &str;
    fn get(&self, e: &EntryName) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError>;   // absent → Ok(None)
    fn set(&self, e: &EntryName, v: &[u8]) -> Result<(), KeyStoreError>;
    fn delete(&self, e: &EntryName) -> Result<(), KeyStoreError>;                       // absent → Ok(())
    fn locality(&self) -> KeyringLocality { KeyringLocality::Local }
}
pub enum EntryName { Kek, HeadAnchor, FirstRetainedAnchor, Canary, Pat(String) }      // C.3
impl EntryName { pub fn account(&self) -> String; pub fn full_name(&self, install_id: &str) -> String; }
pub fn service_name(install_id: &str) -> String;                                       // "atlas-duck/<install_id>"
pub enum KeyStoreError { Unavailable, Locked, NotLocal, Other(String) }                // C.3
pub enum KeyringLocality { Local, NotLocal { dir: PathBuf }, Unknown { reason: String } }
pub fn canary_self_test(ks: &dyn KeyStore) -> Result<(), KeyStoreError>;               // §8.6
pub struct OsKeyStore;  impl OsKeyStore {
    pub fn new(install_id: &str) -> Result<OsKeyStore, KeyStoreError>;                 // real keyring dirs
    pub fn with_keyring_dirs(install_id: &str, dirs: Vec<PathBuf>) -> Result<OsKeyStore, KeyStoreError>;  // tests and the I-44 phase
}
pub fn keyring_dirs() -> Vec<PathBuf>;                                                  // per OS, below
pub fn keyring_locality(dirs: &[PathBuf]) -> KeyringLocality;                           // pure apart from statfs
#[cfg(windows)] pub fn credential_persist(target: &str) -> Result<Option<u32>, KeyStoreError>;  // CredReadW → Persist
```

**Spec:** §8.6 (install-scoped entries, KEK in the keychain with Windows persistence Local, keyring locality dirs, canary self-test, never a silent fallback), §7.1/§8.6 (Windows persistence = Local), §15 V08 (store crates, Windows persistence), V29 (keyring-dir half), L24, L34, RF-3a.

**Plan decisions (spec silent):**
- Mapping onto keyring-core's `(service, user)`: service `atlas-duck/<install_id>`, user = account (F.6). Windows additionally passes the entry modifiers `target = atlas-duck/<install_id>/<account>` (so Credential Manager shows the spec name; the store default would be `<user>.<service>`) and `persistence = Local` on **every** `build` (the store default is Enterprise, which roams: RF-3). The process-wide `keyring_core::set_default_store` is never called; `OsKeyStore` holds its own store handle and calls `build()` on it.
- Windows: `OsKeyStore::set` reads the credential back with `CredReadW` and returns `Other("credential persistence is not local")` unless `Persist == CRED_PERSIST_LOCAL_MACHINE` (2). Fail closed instead of trusting the modifier.
- Linux keyring dirs: `$XDG_DATA_HOME/keyrings` and `$XDG_DATA_HOME/kwalletd` when `XDG_DATA_HOME` is set and absolute, plus `<passwd home>/.local/share/keyrings` and `<passwd home>/.local/share/kwalletd` (both sets are checked; checking more dirs can only refuse more). macOS: `<passwd home>/Library/Keychains`. Windows: none (Credential Manager is per machine with persistence Local). A dir that does not exist is judged by its nearest existing ancestor. An I/O error during the check → `Unknown`, which callers treat like `Unavailable` (retry), never as local.
- Error mapping from `keyring_core::Error`: `NoEntry` → `Ok(None)` (get) / `Ok(())` (delete); `NoStorageAccess(_)` → `Locked`; `PlatformFailure(_)` → `Unavailable`; `NoDefaultStore` → `Unavailable`; `Ambiguous(_)` → `Other("ambiguous entry")`; `BadEncoding(_)`, `BadDataFormat(_, _)` → `Other("bad data")` (no bytes); `TooLong(a, n)` → `Other(format!("{a} too long (max {n})"))`; `Invalid(p, _)` → `Other(format!("invalid {p}"))`; `BadStoreFormat(_)`, `NotSupportedByStore(_)` and any future variant (`#[non_exhaustive]`) → `Other("keyring error")`.

- [ ] **Step 1: Write the failing portable tests** (`tests/keystore.rs`)
- `entry_names_render_exactly`: for install `0123…` (32 hex): `Kek.full_name` = `atlas-duck/0123…/kek`; `HeadAnchor` → `…/head_anchor`; `FirstRetainedAnchor` → `…/first_retained_anchor`; `Canary` → `…/canary`; `Pat("inst-7")` → `…/pat/inst-7`; `service_name` = `atlas-duck/0123…`.
- `canary_passes_on_mem` and `canary_detects_mismatch` (a `MemKeyring` fault that returns other bytes on the next get → `Other`), `canary_leaves_no_entry` (after the test, `raw_get` of the canary is `None`).
- `two_installs_share_one_keyring`: `MemKeyStore` A and B on one `MemKeyring`; A's `Kek` is invisible to B (I-43 unit half).
- `error_mapping_table`: a pure `map_keyring_error(keyring_core::Error) -> MappedError` returns the table above for every constructible variant (build `PlatformError` values with `Box::new(std::io::Error::other("x"))`; skip variants whose payload cannot be constructed and list them in a comment).
- `locality_local_tmp`: `keyring_locality(&[tmp.path().join("keyrings")])` (nonexistent dir under a local temp dir) → `Local`.
- `locality_nfs_from_env`: if `ATLAS_DUCK_TEST_NFS_DIR` is set (CI `locality-mounts` job, Linux), `keyring_locality(&[nfs.join("xdg/keyrings")])` → `NotLocal { dir }`; otherwise the test prints `skipped: ATLAS_DUCK_TEST_NFS_DIR not set` and returns.
- `keyring_dirs_per_os`: Linux returns the 2 or 4 paths above (set/unset `XDG_DATA_HOME` in a child process via `std::process::Command` re-running the test binary with a filter, to avoid racing the env in parallel tests); macOS returns exactly `<home>/Library/Keychains`; Windows returns an empty list.

- [ ] **Step 2: Write the failing OS tests** (`tests/os_keystore.rs`, all `#[ignore]`, each uses a fresh random install id and a guard that deletes all five entries on drop, so a failure leaves nothing behind)
- `os_round_trip_all_kinds`: set/get/overwrite/get/delete/get for `Kek`, `HeadAnchor`, `FirstRetainedAnchor`, `Canary`, `Pat("ci")` with 33–200-byte values (include bytes `0x00` and `0xFF`).
- `os_absent_is_none_and_delete_idempotent`.
- `os_canary_self_test`.
- `os_two_installs_isolated`: two `OsKeyStore`s with different install ids; each sees only its own entries (I-43 keyring half).
- (cfg windows) `rf3a_keyring_persist_local`: after `set` of each of the five kinds, `credential_persist(full_name)` == `Some(2)` (`CRED_PERSIST_LOCAL_MACHINE`), and `CredReadW`'s `TargetName` equals `full_name` exactly.
- (cfg windows) `rf3a_existing_enterprise_entry_rewritten_local`: create the `Kek` target first with `CredWriteW` (`Type = CRED_TYPE_GENERIC`, `Persist = CRED_PERSIST_ENTERPRISE` (3), blob `[1; 33]`), then `OsKeyStore::set(Kek, …)` → `credential_persist` == `Some(2)` and the value reads back. If `set` returns the "persistence is not local" error instead, the store crate keeps the old persistence on update: then implement `set` on Windows as `CredWriteW` directly (full `CREDENTIALW` with `Persist = CRED_PERSIST_LOCAL_MACHINE`, `TargetName = full_name`, `UserName = account`, `Type = CRED_TYPE_GENERIC`) for writes only, keep keyring-core for get/delete, and record the finding under V08 in `docs/m2/verify-items.md` (T18).
- (cfg macos) `os_entry_visible_under_service_and_account`: after `set`, `security find-generic-password -s atlas-duck/<id> -a kek` (run via `std::process::Command`) exits 0 (proves the naming), then cleanup.
- (cfg linux) `os_secret_service_attributes`: after `set`, `secret-tool lookup service atlas-duck/<id> username kek` prints nothing on stdout but exits 0 (value is binary; the exit code proves the attributes). If the store crate names the account attribute differently, the test prints the item's attributes (`secret-tool search --all service atlas-duck/<id>`) and asserts only on `service`; record the attribute names under V08.

Run (Windows dev box): `cargo test -p atlas-duck-audit --test os_keystore --locked -- --ignored --test-threads=1`
Expected before implementation: compile errors. After Step 3: all Windows tests pass locally.

- [ ] **Step 3: Implement**

`os.rs` core (the subtle part):
```rust
pub struct OsKeyStore { install_id: String, service: String, store: std::sync::Arc<keyring_core::CredentialStore>, dirs: Vec<PathBuf> }

impl OsKeyStore {
    fn platform_store() -> Result<std::sync::Arc<keyring_core::CredentialStore>, KeyStoreError> {
        #[cfg(windows)] { windows_native_keyring_store::Store::new().map(|s| s as _).map_err(map_init) }
        #[cfg(target_os = "macos")] { apple_native_keyring_store::keychain::Store::new().map(|s| s as _).map_err(map_init) }
        #[cfg(target_os = "linux")] { zbus_secret_service_keyring_store::Store::new().map(|s| s as _).map_err(map_init) }
    }
    fn entry(&self, e: &EntryName) -> Result<keyring_core::Entry, KeyStoreError> {
        let account = e.account();
        #[cfg(windows)] {
            let target = e.full_name(&self.install_id);
            let mods = std::collections::HashMap::from([("target", target.as_str()), ("persistence", "Local")]);
            return self.store.build(&self.service, &account, Some(&mods)).map_err(map_err);
        }
        #[cfg(not(windows))]
        self.store.build(&self.service, &account, None).map_err(map_err)
    }
}
// get: entry.get_secret() → Ok(Some(Zeroizing::new(v))) | NoEntry → Ok(None)
// set: (non-Windows) entry.set_secret(v); (Windows) entry.set_secret(v) then credential_persist(&full_name) must be Some(2)
// delete: entry.delete_credential() → NoEntry → Ok(())
```
The constructor names (`Store::new`, `keychain::Store::new`) and the `CredentialStore` alias come from the crates' docs as read on 2026-10-08; if one differs, read the crate source under `~/.cargo/registry/src/*/<crate>-<version>/src/` and the crate's `examples/` and adapt the call only (the plan's semantics stay). `OsKeyStore::new` and `with_keyring_dirs` do **not** touch the keyring; `locality()` returns `keyring_locality(&self.dirs)`.

`windows.rs`: `credential_persist(target)`: `CredReadW(wide(target), CRED_TYPE_GENERIC, 0, &mut p)`; on `ERROR_NOT_FOUND` → `Ok(None)`; else read `(*p).Persist`, `CredFree(p)`, return `Ok(Some(persist))`. `unsafe` blocks with `// SAFETY:` comments like M1's `lock.rs`.

Run: `cargo test -p atlas-duck-audit --test keystore --locked` → all pass on Windows; `cargo test -p atlas-duck-audit --test os_keystore --locked -- --ignored --test-threads=1` → all Windows tests pass. macOS/Linux are proven in T18's CI steps.

- [ ] **Step 4: Clippy, commit** (`feat(audit): KeyStore over keyring-core with per-OS stores, Windows persistence Local, keyring locality check, canary`).

---

### Task 6: `Clock`, `SystemClock` (suspend-aware), `ClockState` (epoch, flags, anomalies)

**Files:**
- Modify: `crates/audit/src/clock.rs`
- Create: `crates/audit/tests/clock.rs`

**Interfaces:**
- Consumes: T01 `Clock`, `UtcInstant`, `EventFlags`.
- Produces:
  - `clock::SystemClock` (`impl Clock`): `now_utc` from `SystemTime::now()`; `suspend_aware_elapsed` = Linux `clock_gettime(CLOCK_BOOTTIME)`, macOS `clock_gettime(CLOCK_MONOTONIC)` (on Darwin it keeps counting during sleep, unlike `CLOCK_UPTIME_RAW`), Windows `QueryInterruptTime` (100 ns units, includes sleep; not `QueryUnbiasedInterruptTime`), each minus the value captured at construction.
  - `clock::{ClockState, Corroboration, Stamp, ClockAnomaly { kind: AnomalyKind /* LocalAhead | LocalBehind */, local: UtcInstant, server: UtcInstant }}` with the code below.
  - `clock::{date_of(UtcInstant) -> NaiveDate, epoch_text(NaiveDate) -> String, month_text(NaiveDate) -> String, parse_epoch(&str) -> Option<NaiveDate>}`.

**Spec:** §8.2 `epoch` + L36, §8.8 corroborated date, local ahead, local behind, `clock_behind` (a)(b) [L47: the old GENESIS rule is gone, old (c) is now (b)], `clock_backwards` (> 5 s), §15 V27.

**Plan decisions (spec silent):**
- "More than 1 day ahead/behind" is evaluated on UTC **dates**, the same predicate §8.8 states for `clock_behind` (a): behind ⇔ `today < corroborated_date − 1 day`; ahead ⇔ `today > header_date + 1 day`; an episode ends when the predicate is false at the next evaluation.
- A new `Date` header replaces the corroboration only if it is not older than the current extrapolation (`corroborated date` is the *newest* confirmed date, §8.8).
- `ClockState` is per store per process; episodes reset at every open (so `CLOCK_ANOMALY` is logged at most once per episode per process).
- `clock_behind` follows §8.8 as amended by L47: rule (a) (corroborated and `today < corroborated_date − 1 day`) and rule (b) (before the first corroboration in this process: `date(ts_utc)` earlier than the predecessor's `epoch`, or the predecessor carries `clock_behind`). A `GENESIS` has a NULL `epoch` and no predecessor, so it is never flagged; a wrong clock at first run is handled by the effective epoch (§8.2) alone. `stamp` takes no `is_genesis` argument.

- [ ] **Step 1: Write the failing tests** (`tests/clock.rs`; all drive `ClockState` directly with explicit instants)
1. `genesis_is_null_and_unflagged`: fresh state, `stamp(now, mono)` → `epoch None`, flags empty (no `CLOCK_BEHIND`).
2. `uncorroborated_records_stay_null_and_unflagged`: 3 more stamps → `epoch None`, none carries `CLOCK_BEHIND` (rule (b) needs a non-NULL predecessor epoch or a flagged predecessor).
3. `first_corroboration_sets_min_today_corroborated`: wall 2027-10-08 (clock 1 year ahead), `observe(server = 2026-10-08T10:00Z)` → anomaly `LocalAhead` once; next stamp → `epoch 2026-10-08`, flags `CLOCK_FORWARD` (no `CLOCK_BEHIND`: (a) is false, and after corroboration (b) no longer applies).
4. `extrapolation_caps_epoch`: after `observe(2026-10-08T23:00Z)` with mono advancing 2 h and wall correct, stamp → `epoch 2026-10-09`.
5. `mono_undercount_holds_epoch_back`: mono frozen for 14 days, wall correct (+14 d) → `epoch` stays at the corroboration date, flags empty, no anomaly (U-13 unit half).
6. `backward_clock_sets_behind_once`: corroborated 2026-10-08, wall set back 60 days → stamp flags `CLOCK_BEHIND`, `behind_transition` returns `Some(LocalBehind)` once, `None` on the next 100 calls; epoch stays at `prev_epoch` (non-decreasing); wall corrected → flag off, episode ends; a new backward step → a second anomaly (new episode).
7. `ten_day_backward_variant`: same with 10 days.
8. `clock_backwards_step_flag`: `ts` 6 s earlier than predecessor → `CLOCK_BACKWARDS`; 5 s earlier → no flag.
9. `cmos_reset_before_corroboration`: prev_epoch 2026-10-08 (from a previous process), new process (no corroboration), wall 2000-01-01 → `CLOCK_BEHIND` via (b), epoch stays 2026-10-08; the next uncorroborated stamp stays flagged (predecessor flagged).
13. `genesis_with_wrong_clock_not_flagged`: fresh state, wall 2000-01-01: `GENESIS` and 2 more stamps → `epoch None`, flags empty; then `observe(server = 2026-10-08T10:00Z)` with wall still 2000 → the next stamp carries `CLOCK_BEHIND` via (a) and `behind_transition` returns `Some(LocalBehind)`.
10. `epoch_never_decreases_and_never_exceeds_corroborated`: proptest over random sequences of `observe`/`stamp`/wall jumps (±5 years)/mono advances: every non-NULL epoch ≥ the previous non-NULL epoch and ≤ the newest corroborated date at that moment; once non-NULL, never NULL again.
11. `ahead_episode_ends_when_header_agrees`: ahead → `CLOCK_FORWARD` on stamps; a later `observe` within 1 day → no flag on later stamps.
12. `system_clock_monotonic` (real `SystemClock`): two reads 50 ms apart; `suspend_aware_elapsed` increases by ≥ 40 ms; `now_utc` within 5 s of `SystemTime::now()`.

- [ ] **Step 2: Implement `ClockState`** — write exactly this logic:

```rust
#[derive(Clone, Debug, Default)]
pub struct ClockState {
    pub(crate) prev_epoch: Option<NaiveDate>,   // head record's epoch (NULL possible)
    pub(crate) prev_ts: Option<UtcInstant>,     // head record's ts_utc
    pub(crate) prev_flags: EventFlags,          // head record's flags
    corr: Option<Corroboration>,                // this process only
    ahead_episode: bool,
    behind_episode: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct Corroboration { pub server: UtcInstant, pub mono_at: Duration }

impl ClockState {
    pub fn from_head(epoch: Option<NaiveDate>, ts: UtcInstant, flags: EventFlags) -> Self { /* corr None, episodes false */ }
    pub fn corroborated_at(&self, mono_now: Duration) -> Option<UtcInstant> {
        self.corr.map(|c| UtcInstant(c.server.0 + mono_now.saturating_sub(c.mono_at).as_millis() as i64))
    }
    pub fn corroborated_date(&self, mono_now: Duration) -> Option<NaiveDate> { self.corroborated_at(mono_now).map(date_of) }
    pub fn is_corroborated(&self) -> bool { self.corr.is_some() }

    /// Source (a): a server Date header (successful, parsed, TLS-verified response; the caller guarantees it).
    pub fn observe(&mut self, server: UtcInstant, now: UtcInstant, mono_now: Duration) -> Option<ClockAnomaly> {
        let newest = match self.corroborated_at(mono_now) { Some(cur) if cur.0 > server.0 => cur, _ => server };
        self.corr = Some(Corroboration { server: newest, mono_at: mono_now });
        let ahead = date_of(now) > date_of(server) + Days::new(1);
        let started = ahead && !self.ahead_episode;
        self.ahead_episode = ahead;
        started.then(|| ClockAnomaly { kind: AnomalyKind::LocalAhead, local: now, server })
    }

    /// Called by the writer before each append batch. Starts/ends the local-behind episode.
    pub fn behind_transition(&mut self, now: UtcInstant, mono_now: Duration) -> Option<ClockAnomaly> {
        let Some(cd_at) = self.corroborated_at(mono_now) else { return None };
        let behind = date_of(now) < date_of(cd_at) - Days::new(1);
        let started = behind && !self.behind_episode;
        self.behind_episode = behind;
        started.then(|| ClockAnomaly { kind: AnomalyKind::LocalBehind, local: now, server: cd_at })
    }

    /// Stamps one record, in seq order. Mutates the "previous record" view.
    pub fn stamp(&mut self, now: UtcInstant, mono_now: Duration) -> Stamp {
        let today = date_of(now);
        let cd = self.corroborated_date(mono_now);
        let epoch = match cd {
            Some(cd) => { let cand = today.min(cd); Some(match self.prev_epoch { Some(p) if p > cand => p, _ => cand }) }
            None => self.prev_epoch,
        };
        let mut flags = EventFlags::default();
        if let Some(p) = self.prev_ts { if now.0 < p.0 - 5_000 { flags |= EventFlags::CLOCK_BACKWARDS } }
        if self.ahead_episode { flags |= EventFlags::CLOCK_FORWARD }
        match cd {
            Some(cd) => if today < cd - Days::new(1) { flags |= EventFlags::CLOCK_BEHIND },          // (a)
            None => {
                let cmos = matches!(self.prev_epoch, Some(pe) if today < pe);
                if self.prev_flags.contains(EventFlags::CLOCK_BEHIND) || cmos { flags |= EventFlags::CLOCK_BEHIND } // (b) (L47: no GENESIS clause)
            }
        }
        self.prev_epoch = epoch; self.prev_ts = Some(now); self.prev_flags = flags;
        Stamp { ts_utc: now, epoch, clock_flags: flags }
    }
}
```
(`date - Days::new(1)` stands for `checked_sub_days`; on underflow treat the predicate as false. `Days` is `chrono::Days`.)

- [ ] **Step 3: `SystemClock`** per OS as in Interfaces, `unsafe` FFI with `// SAFETY:` comments; Windows `QueryInterruptTime` from `windows_sys::Win32::System::WindowsProgramming` (if the symbol lives in another module of `windows-sys 0.61.2`, use the path the compiler suggests and adjust the feature list in `crates/audit/Cargo.toml`).

Run: `cargo test -p atlas-duck-audit --test clock --locked` → all pass.

- [ ] **Step 4: Clippy, commit** (`feat(audit): corroborated epoch state machine and suspend-aware system clock`).

---

### Task 7: Writer thread, `append`/`append_batch`, DEK selection, `create_new_store` + `GENESIS`, read API, admission

**Files:**
- Create: `crates/audit/src/writer.rs`, `crates/audit/src/store.rs`, `crates/audit/src/admission.rs`, `crates/audit/src/open.rs` (first-run part only)
- Create: `crates/audit/tests/common/mod.rs`, `crates/audit/tests/store.rs`
- Modify: `crates/audit/src/lib.rs`, `crates/audit/src/testing.rs` (add `Faults`/`FaultPoint`, `FreeSpaceStub`)

**Interfaces:**
- Consumes: T02–T06.
- Produces:
```rust
pub struct OpenConfig {                                     // C.3 fields first, then additions
    pub clock: Arc<dyn Clock>, pub keys: Arc<dyn KeyStore>, pub pinned_install_id: Option<String>, pub anchor_dir: Option<PathBuf>,
    pub min_free_bytes: u64,                                // default 2 GiB (§8.1; the 4 × 24 MiB term is inert)
    pub free_space: Option<Arc<dyn FreeSpaceProbe>>,        // None = OS (GetDiskFreeSpaceExW / statvfs)
    pub hooks: Hooks,                                       // empty unless feature "testing": faults, extra migrations
}
impl OpenConfig { pub fn new(clock: Arc<dyn Clock>, keys: Arc<dyn KeyStore>) -> Self /* defaults */ }
pub trait FreeSpaceProbe: Send + Sync { fn free_bytes(&self, path: &Path) -> std::io::Result<u64>; }
pub struct FirstRunInput { pub install_id: String, pub chain_id: String, pub passphrase: SecretString, pub passphrase_confirm: SecretString, pub archived_db: Option<ArchivedDb> }
pub struct ArchivedDb { pub file: String /* relative to the data dir, '/' separators */, pub chain_id: String, pub head_seq: u64, pub head_hash: [u8; 32] }
pub fn new_ids() -> (String /* install_id */, String /* chain_id */);
pub fn create_new_store(data: &LocalDataDir, lock: &InstanceLock, cfg: OpenConfig, input: FirstRunInput) -> Result<Store, OpenError>;   // C.3
#[derive(Clone)] pub struct Store { /* Arc<Inner> */ }
impl Store {
    pub fn append(&self, ev: NewEvent) -> Result<Committed, AuditError>;                 // C.3
    pub fn append_batch(&self, evs: Vec<NewEvent>) -> Result<Vec<Committed>, AuditError>;  // C.3: one transaction, all or nothing
    pub fn admission_check(&self) -> Result<(), AuditError>;                           // C.3: StorageLow
    pub fn query_tag(&self, kind: QueryKind, query: &str) -> String;                   // C.3 / F.7
    pub fn read_payload(&self, seq: u64) -> Result<Zeroizing<Vec<u8>>, AuditError>;   // C.3: JCS bytes, payload_sha256 checked
    pub fn observe_server_date(&self, instance_id: &str, server_date: SystemTime, at: Instant);   // C.3; never blocks on the writer
    pub fn head(&self) -> (u64, [u8; 32], String /* chain_id */);
    pub fn install_id(&self) -> &str;
    pub fn health(&self) -> StoreHealth;                                               // T08 fills it
    pub fn shutdown(&self);                                                            // stop threads; never writes an anchor
}
pub struct EventHeader { pub seq: u64, pub ts_utc: String, pub epoch: Option<String>, pub chain_id: String, pub event_type: EventType,
    pub request_id: Option<String>, pub op_id: Option<String>, pub op_class: Option<String>, pub instance_id: Option<String>, pub target: Option<String>,
    pub decision: Option<DecisionColumn>, pub flags: EventFlags, pub actor: Actor, pub payload_len: u64, pub key_id: u64 }   // plaintext columns only
```

**Spec:** §8.1 (single writer, `synchronous=FULL`, low-space admission, system events continue), §8.2 (columns), §8.4 (`GENESIS`, chain), §8.6 (DEK per month of `epoch`, uncorroborated DEK created with `GENESIS`, never a future month; recovery passphrase flow), §2.5 (1b order: ids → passphrase → `GENESIS`), §3.1 (lock), §5.1 inv. 1 (append returns only after a durable commit), C.3.

**Plan decisions (spec silent):**
- Writer protocol: `Store` holds `SyncSender<Cmd>` (bound 64); `append` prepares on the caller thread (JCS, SHA-256, zstd: F.3 steps 1–3), sends `Cmd::Append { evs, reply }` and blocks on the reply. The writer is the only owner of the read-write `Connection`, `ClockState`, head state, DEK cache writes, settings cache and prune state. Every multi-row operation (append batch, `PRUNE`, `RESTORE`, migrations + `SCHEMA_MIGRATED`) is one `BEGIN IMMEDIATE` transaction.
- On any error inside the transaction the writer rolls back **and restores the in-memory `ClockState`/head snapshot taken before it**, so a failed append leaves no trace in memory either.
- `ts_utc` is assigned by the writer (`clock.now_utc()` per record), not by the caller, so `seq` order and `ts_utc` come from one place.
- `observe_server_date` sends `Cmd::ObserveDate` with `try_send` (dropped with a counter if the channel is full; corroboration is best effort and repeated on every response). `mono_at = clock.suspend_aware_elapsed() − at.elapsed()`.
- First run writes the new DB under `<data>/audit.db.new` and renames it to `audit.db` only after `GENESIS` committed and the file was closed and fsynced, so a crash during first run never leaves a DB without `GENESIS` (a leftover `.new` is deleted by the next `open`/`create_new_store`).
- `create_new_store` order: refuse an existing `audit.db` → `cfg.keys.install_id() == input.install_id` (else `Invalid`) → keyring locality (`NotLocal` → `KeyStore(NotLocal)` with no keyring call) → canary self-test under the new `install_id` (§8.6 "before first run, a canary named with the `install_id` about to be generated") → passphrase rules and `new_recovery_blob` (compare) → KEK to the keychain → DB under `audit.db.new` → `GENESIS` → rename → both anchors.
- KEK is written to the keychain **before** the DB is created (if the keychain write fails, nothing exists on disk); if the write itself returns an error after storing something (Windows: the post-write `CredReadW` check reports a persistence other than Local) or DB creation then fails, the KEK entry is deleted best-effort before the error is returned.
- `GENESIS` gets `seq = 1`, `key_id = 1` (uncorroborated DEK, `month` NULL), `target = install_id`, `flags = 0` (L47: a NULL-epoch `GENESIS` is never `clock_behind`, T06), payload per F.11.

- [ ] **Step 1: Test helpers** (`tests/common/mod.rs`): `tmp_data_dir() -> (TempDir, LocalDataDir, InstanceLock)` (via `ipc::paths::check_data_dir` on a fresh temp dir and `InstanceLock::acquire`); `new_store(clock, ring) -> (Store, Fixture)` running `create_new_store` with a fixed 12-char passphrase; `ev(EventType, Option<&str> request_id, serde_json::Value)` builder; `raw_conn(&Fixture) -> rusqlite::Connection` for tamper tests; `dump_rows(&Fixture) -> Vec<RawRow>`.

- [ ] **Step 2: Write the failing tests** (`tests/store.rs`)
- `first_run_creates_genesis`: after `create_new_store`: `audit.db` exists, no `audit.db.new`; one row: `seq 1`, `GENESIS`, `epoch NULL`, `flags 0`, `target = install_id`, `prev_hash` zero, `key_id 1`; `keys` has one row (`key_id 1`, `month NULL`); `recovery` has one 89-byte blob that `open_recovery(passphrase)` opens to the keychain KEK; `read_payload(1)` JCS contains `chain_id`, `install_id`, `created_at`, `archived_db: null`; MemKeyring holds `kek`, `head_anchor` (seq 1), `first_retained_anchor` (seq 1, prev zero, `genesis_hash` = row 1 hash).
- `first_run_refuses_existing_db`: second `create_new_store` on the same dir → `AlreadyExists`, DB byte-identical, no keychain op (MemKeyring `ops()` empty for the second install id).
- `first_run_passphrase_rules`: short → `PassphraseTooShort`, mismatch → `PassphraseMismatch`; in both cases no file in the data dir besides `instance.lock` and no keychain write.
- `first_run_keychain_failure_leaves_nothing`: MemKeyring fault on `Set(Kek)` → `KeyStore(Unavailable)`, no DB file.
- `first_run_keyring_not_local`: `ring.set_locality(NotLocal)` → `KeyStore(NotLocal)`, `ops()` is empty (no canary, nothing written).
- `append_chains_and_is_durable`: append 100 events (mixed types, with/without request ids); rows `seq 2..=101` contiguous, each `prev_hash` = previous `record_hash`, each `record_hash` recomputes (T02 functions), `format_version 1`; reopen the DB file with a raw connection after `shutdown()` and see all 101 rows (durability via `synchronous=FULL` is SQLite's guarantee; the test proves the commit happened before `append` returned by reading from a second connection *inside* the loop right after each `append`).
- `append_batch_atomic`: a batch of 3 where the 3rd payload contains an integer > 2^53 (JCS error) → `Err`, zero rows added, head unchanged; then a valid append gets the next seq (no gap).
- `append_failure_restores_memory`: `FaultPoint::WriterBeforeCommit` → `AppendFailed`; next append succeeds with contiguous seq and a `prev_hash` equal to the last committed hash.
- `caller_cannot_set_clock_flags`: `NewEvent.flags = CLOCK_FORWARD | EDITED` → stored flags contain `EDITED` and only the clock flags the store computed.
- `null_epoch_rows_use_uncorroborated_dek`: before any `observe_server_date`, appended rows have `epoch NULL` and `key_id 1`; after `observe_server_date(2026-10-08)` the next row has `epoch 2026-10-08` and a new key row with `month 2026-10`; no `keys` row with a month later than the corroborated month exists, even with the wall clock 5 years ahead.
- `month_dek_rollover`: corroboration date advanced to 2026-11-01 via FakeClock (mono) → new key row `month 2026-11` created exactly when the first record's epoch enters November.
- `read_payload_checks_hash`: tamper `payload_ct` byte via raw SQL → `read_payload` → `Decrypt { seq }`; tamper `payload_sha256` → `Decrypt` (AAD covers it) or `PayloadHash`; unknown seq → `NotFound`.
- `query_tag_matches_crypto`: `store.query_tag(Jql, q)` == `crypto::query_tag(query_key(kek), Jql, q)` with the KEK read from MemKeyring.
- `observe_server_date_never_blocks`: 10 000 calls in a loop while the writer is blocked in a `FaultPoint::WriterPause` hook finish in < 1 s.
- `admission_storage_low` (X-03 store half): `FreeSpaceStub(1 GiB)` → `admission_check()` = `Err(StorageLow)`; `append` of a system event (`CONFIG_CHANGED`) still succeeds (admission is the caller's gate, §8.1 "system events and pruning continue"); `FreeSpaceStub(3 GiB)` → `Ok(())`.
- `admission_real_fs`: `OpenConfig.min_free_bytes = 1` with the OS probe on the temp dir → `Ok(())`.
- `synchronous_full_by_default`: a store built with `OpenConfig::new` reports `PRAGMA synchronous` = 2 (FULL) on the writer connection; only `hooks.synchronous_normal` (feature `testing`) lowers it (used by the long scenario tests, T13).
- `os_path_columns`: an event with `actor.peer_exe = Some(path with non-ASCII)` stores the F.2 bytes in the BLOB column.

- [ ] **Step 3: Implement.** The append transaction (subtle, write exactly in this order):

```rust
fn append_tx(&mut self, evs: Vec<PreparedEvent>) -> Result<Vec<Committed>, AuditError> {
    let snapshot = (self.clock_state.clone(), self.head.clone());
    let result = (|| {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mono = self.clock.suspend_aware_elapsed();
        let mut out = Vec::with_capacity(evs.len() + 1);
        let mut rows = Vec::new();
        if let Some(a) = self.clock_state.behind_transition(self.clock.now_utc(), mono) {
            rows.push(PreparedEvent::clock_anomaly(&a)?);           // CLOCK_ANOMALY first, same transaction
        }
        rows.extend(evs);
        for p in rows {
            let now = self.clock.now_utc();
            let st = self.clock_state.stamp(now, mono);
            let (key_id, dek) = self.dek_for(&tx, st.epoch, &st.ts_utc)?;          // creates the month DEK row if missing
            let seq = self.head.seq + 1;
            let flags = (p.flags & EventFlags::CALLER_SETTABLE) | st.clock_flags | p.store_flags; // store_flags: integrity_incident on VERIFY only
            let nonce = crypto::random_nonce();
            let mut fields = RowFields::new(seq, &self.head.chain_id, &st, &p, flags, key_id, &nonce, &self.head.hash);
            let aad = encoding::aad(&fields)?;
            let ct = crypto::seal(&dek, &nonce, &aad, &p.compressed)?;
            fields.payload_ct = &ct;
            let canonical = encoding::canonical_bytes(&fields)?;
            let rh = encoding::record_hash(FORMAT_VERSION, &self.head.hash, &canonical);
            insert_row(&tx, &fields, &rh)?;
            self.head = Head { seq, hash: rh, chain_id: self.head.chain_id.clone(), epoch: st.epoch };
            out.push(Committed { seq, record_hash: rh });
        }
        self.hooks.fault(FaultPoint::WriterBeforeCommit)?;
        tx.commit()?;
        Ok(out)
    })();
    if result.is_err() { (self.clock_state, self.head) = snapshot; }
    result
}
```
`dek_for(tx, epoch, ts)`: `month = epoch.map(month_text)`; `SELECT key_id, wrapped_dek FROM keys WHERE month IS ?1 AND wrapped_dek IS NOT NULL ORDER BY key_id DESC LIMIT 1`; if found → unwrap (cache by key_id in `Inner.dek_cache: Mutex<HashMap<u64, Dek>>`); else create (`key_id = COALESCE(MAX(key_id),0)+1`, `wrap_dek`, insert with `created_at = ts`). Post-commit (writer, after `commit()` returned): publish the head to the anchor state (T08 adds it), update caches, and if the head's epoch date advanced, queue a prune attempt (T11 adds it).

Admission: Windows `GetDiskFreeSpaceExW(dir, &mut avail_to_caller, …)`; Unix `statvfs` → `f_bavail * f_frsize`; on error → `StorageLow` (fail closed).

Run: `cargo test -p atlas-duck-audit --test store --locked` → all pass.

- [ ] **Step 4: Clippy, commit** (`feat(audit): single-writer store, append/append_batch, month and uncorroborated DEKs, first run with GENESIS, admission`).

---

### Task 8: Anchors: layouts, anchor thread, batching, barriers, "no anchor before verify"

**Files:**
- Create: `crates/audit/src/anchors.rs`, `crates/audit/tests/anchors.rs`
- Modify: `crates/audit/src/store.rs`, `crates/audit/src/writer.rs`

**Interfaces:**
- Consumes: T05 `KeyStore`, T07 writer post-commit hook.
- Produces:
```rust
pub struct HeadAnchor { pub chain_id: String, pub seq: u64, pub record_hash: [u8; 32] }                      // F.6
pub struct FirstRetainedAnchor { pub chain_id: String, pub genesis_hash: [u8; 32], pub first_retained_seq: u64, pub first_retained_prev_hash: [u8; 32] }
impl HeadAnchor { pub fn to_entry(&self) -> Vec<u8>; pub fn from_entry(&[u8]) -> Result<Self, AnchorEntryError {NewerLayout(u8), Malformed}>; }  // same for FirstRetainedAnchor
pub(crate) enum Barrier { Prune { seq: u64, record_hash: [u8; 32], first_retained: FirstRetainedAnchor }, Restore { seq: u64 } }
pub(crate) struct AnchorState { enabled: bool, head: Option<HeadAnchor>, written_head: Option<HeadAnchor>, barrier: Option<Barrier>,
                                dirty_since: Option<Instant>, flush_requested: bool, stop: bool, failures: u32, next_retry: Option<Instant>, last_error: Option<KeyStoreError> }
pub struct StoreHealth { pub anchor_write_failing: bool, pub first_retained_update_pending: bool, pub storage_low: bool, pub open_incidents: usize, pub prune_backlog_days: u32 }
impl Store { pub fn flush_head_anchor(&self) -> Result<(), AuditError>; /* C.3 */ }
```

**Spec:** §8.5 (head anchor batched ≤ 1 s, flushed on `APP_STOP`; first-retained updated only by prune/restore; anchor ordering: never past a `PRUNE`/`RESTORE` until its update/reset succeeded, flushes stop at that seq), §8.7 ("No anchor writes before verification"), §8.8 (failed keychain update after prune is retried with backoff and shown in Settings/tray, never an incident).

**Plan decisions (spec silent):**
- One `audit-anchor` thread is the only writer of the two anchor entries. The writer thread publishes into `Mutex<AnchorState>` + `Condvar`; the anchor thread waits with a timeout ≤ 1 s. Keychain latency therefore never blocks `append`.
- Barrier semantics: `Prune { seq }` lets the head anchor reach `seq` itself but not beyond until the first-retained update succeeded (§8.7 (d) accepts "at or after the head anchor"); `Restore { seq }` stops head-anchor writes entirely until the restore completion step has re-sealed the KEK and written both anchors (an anchor from before the `RESTORE` would describe the replaced DB).
- Retry backoff for a failing anchor write: 1, 2, 4, 8, 16, 32, 60, 60 … s; `health().anchor_write_failing` is true from the first failure until the next success.
- `flush_head_anchor()` writes synchronously (respecting the barrier and `enabled`) and returns the keychain error, if any; `Drop`/`shutdown()` never write.

- [ ] **Step 1: Write the failing tests** (`tests/anchors.rs`, FakeClock + MemKeyring; poll with a 3 s deadline instead of fixed sleeps)
- `anchor_entry_layouts`: `to_entry()` starts with `0x01` then JCS with the F.6 keys in sorted order; round trip; `[0x02, …]` → `NewerLayout(2)`.
- `head_anchor_batched_within_one_second`: append 50 events quickly → within 1.5 s the keychain head anchor names seq 51; MemKeyring `ops()` shows far fewer than 50 `Set(HeadAnchor)` (batching).
- `flush_on_demand`: append, then `flush_head_anchor()` → keychain head == store head immediately.
- `no_anchor_while_disabled`: a store started with anchors disabled (internal `Store::start_writer(.., anchors_enabled = false)`) → appends produce no `Set(HeadAnchor)`/`Set(FirstRetainedAnchor)`; `flush_head_anchor()` returns `Ok(())` and writes nothing; after `enable_anchors()` the head is written.
- `head_anchor_stops_at_unfinished_prune`: install a `Prune` barrier at seq N (internal API used by T11) with a MemKeyring fault that fails `Set(FirstRetainedAnchor)` 3 times; append 10 more events; the head anchor never exceeds N while the fault lasts; `health().anchor_write_failing` and `first_retained_update_pending` are true; after the fault clears (backoff ≤ 1+2+4 s, FakeClock does not drive `Instant`, so use the real time here and a test-only `BACKOFF_SCALE` of 1/10 under `hooks`), the first-retained entry holds the new value, then the head reaches the newest seq.
- `restore_barrier_blocks_head`: `Restore` barrier → no head writes until `complete_restore_anchors()` (internal) writes both entries.
- `drop_never_writes`: append (dirty), then `shutdown()` and drop immediately → MemKeyring head anchor still at the old seq.
- `anchor_failure_is_not_an_incident`: failing head writes for 3 s → no `VERIFY` row appended.

- [ ] **Step 2: Implement** the anchor thread loop:

```rust
loop {
    let mut st = state.lock();
    st = cv.wait_timeout_while(st, next_wakeup(&st), |s| !s.work_due(Instant::now()) && !s.stop).0;
    if st.stop { break }
    // 1. a pending first-retained update (prune) comes first
    if let Some(Barrier::Prune { first_retained, .. }) = st.barrier.clone() {
        drop(st);
        let r = keys.set(&EntryName::FirstRetainedAnchor, &first_retained.to_entry());
        st = state.lock();
        match r { Ok(()) => { st.barrier = None; st.failures = 0; st.last_error = None }
                  Err(e) => { st.schedule_retry(e); continue } }
    }
    // 2. head anchor up to the barrier-capped target, at most once per second of dirtiness
    if let Some(target) = st.flush_target() {
        if st.written_head.as_ref() != Some(&target) && (st.flush_requested || st.dirty_for(Instant::now()) >= BATCH_WINDOW) {
            drop(st);
            let r = keys.set(&EntryName::HeadAnchor, &target.to_entry());
            st = state.lock();
            match r { Ok(()) => { st.written_head = Some(target); st.failures = 0; st.last_error = None; st.dirty_since = None }
                      Err(e) => st.schedule_retry(e) }
        }
    }
}
fn flush_target(&self) -> Option<HeadAnchor> {
    if !self.enabled { return None }
    match &self.barrier {
        Some(Barrier::Restore { .. }) => None,
        Some(Barrier::Prune { seq, record_hash, .. }) =>
            self.head.as_ref().map(|h| if h.seq > *seq { HeadAnchor { chain_id: h.chain_id.clone(), seq: *seq, record_hash: *record_hash } } else { h.clone() }),
        None => self.head.clone(),
    }
}
```
`BATCH_WINDOW = 900 ms`. `work_due` is true when (a) a prune barrier's update is pending and the retry time (if any) has come, or (b) `flush_target()` differs from `written_head` and either `flush_requested` is set or `dirty_since` is older than `BATCH_WINDOW`, and the retry time (if any) has come. After each commit the writer sets `dirty_since = Some(now)` only if it was `None` (the first unflushed commit opens the window) and notifies only on that first commit of a window (so the idle thread starts timing it; later commits in the window do not notify); the anchor thread's `wait_timeout` is computed from `dirty_since + BATCH_WINDOW`, so the head anchor trails the newest commit by ≤ 1 s and many commits share one keychain write. Beyond the first commit of a window the writer notifies only for a new barrier, `enable_anchors`, `flush_head_anchor` (sets `flush_requested` and waits on a reply channel) and shutdown. `flush_requested` is cleared after the write attempt and the attempt's result is returned to the waiting `flush_head_anchor` call.

Run: `cargo test -p atlas-duck-audit --test anchors --locked` → all pass.

- [ ] **Step 3: Clippy, commit** (`feat(audit): keychain head/first-retained anchors with ≤1 s batching, prune/restore barriers, no write before enable`).

---

### Task 9: Verification engine, startup anchor rule, interrupted prune, `full_verify`, incidents, tamper suite

**Files:**
- Create: `crates/audit/src/verify.rs`, `crates/audit/src/incidents.rs`, `crates/audit/tests/verify.rs`
- Modify: `crates/audit/src/store.rs`

**Interfaces:**
- Consumes: T02 (recompute), T03 (decrypt, DEK unwrap), T08 (anchor types).
- Produces:
```rust
pub enum FindingKind { // incident kinds
    ChainBroken, SeqGap, UnknownFlagBits, FormatVersionUnsupported, PruneLogBroken, PruneLogNotContiguous, PruneLogRowMismatch,
    FirstRetainedMismatch, AnchorMismatch, AnchorAhead, AnchorMissing, InstallIdMismatch, PayloadHashMismatch, DecryptFailed,
    RequestSetHashMismatch, DestroyedKeyReferenced, PruneInsideRetention, RestoreBoundaryMismatch, AnchorDirMismatch, AnchoredRecordPrunedEarly,
    // informational kinds
    UnanchoredTail, InterruptedPruneReconciled, InterruptedRestoreReconciled }
impl FindingKind { pub fn as_str(&self) -> &'static str /* snake_case */; pub fn is_incident(&self) -> bool; }
pub struct VerifyFinding { pub kind: FindingKind, pub expected_seq: Option<u64>, pub expected_hash: Option<[u8; 32]>, pub observed_seq: Option<u64>, pub observed_hash: Option<[u8; 32]>, pub detail: String }
pub struct VerifyOutcome { pub findings: Vec<VerifyFinding>, pub unanchored_tail: u64, pub verify_seq: Option<u64> }   // C.3 name; verify_seq = the VERIFY row appended
pub(crate) struct StartupInputs<'a> { conn: &'a Connection, kek: &'a Kek, head_anchor: Option<HeadAnchor>, first_retained: Option<FirstRetainedAnchor>, store_install_id: Option<String>, pinned_install_id: Option<String>, anchor_lines: Option<Vec<AnchorLine>> /* T14 */ }
pub(crate) struct StartupVerdict { findings, unanchored_tail, anchor_actions: AnchorActions { advance_head: bool, set_first_retained: Option<FirstRetainedAnchor>, complete_restore: Option<RestoreCompletion> } }
pub(crate) fn startup(inp: &StartupInputs) -> Result<StartupVerdict, OpenError>;
impl Store {
    pub fn full_verify(&self) -> Vec<VerifyFinding>;                                         // C.3: runs on a read-only connection, then appends one VERIFY (scope "full", result "ok" when clean)
    pub fn open_incidents(&self) -> Vec<u64>;                                                // C.3: seqs of incident VERIFYs without a later INTEGRITY_ACK
    pub fn acknowledge_incident(&self, verify_seq: u64, os_user: &str, note: &str) -> Result<Committed, AuditError>;  // C.3; Invalid if not an open incident
}
```

**Spec:** §8.7 (startup order and scope "from the latest `PRUNE`, `RESTORE` or `APP_START` to the head", anchor rule incl. unanchored tail, interrupted prune (a)–(d), missing anchors, full verification list, incidents persist, `INTEGRITY_ACK`), §8.5 (`prune_log` contiguity), §8.11 (`RESTORE` segment boundary), §13 U-06/U-17/U-22 (prune half).

**Plan decisions (spec silent):**
- One `VERIFY` row per verification run (`findings` array), flagged `integrity_incident` iff any finding is an incident kind; `INTEGRITY_ACK {verify_seq}` acknowledges the whole run.
- `full_verify` on a clean store appends `VERIFY {scope: "full", result: "ok"}` (evidence for the M6 E2E "Verify now passes" and daily runs).
- The newest record that *startup* decrypts is the head row; the latest `PRUNE` payload is also decrypted at startup to compare its `prune_log_row_hash` (two decrypts, bounded).
- `PruneInsideRetention` is judged with the retention and legal hold **in force at that prune** (the settings snapshot inside the `PRUNE` payload, F.11): `cutoff_epoch` must be ≤ `PRUNE.epoch − retention_days` and legal hold must be off. Judging old prunes against today's retention would raise false incidents after a retention increase.

- [ ] **Step 1: Write the failing tests** (`tests/verify.rs`). Build stores with T07 helpers; tamper with raw SQL on a closed store (`shutdown()`, then raw connection), then either reopen through `open()` (T10 does not exist yet: call the crate-internal `verify::startup` through a `#[cfg(feature = "testing")] pub fn testing::startup_verdict(dir, keys) -> StartupVerdict` shim) or call `full_verify()` on a fresh store handle.

U-06 tamper suite (each → the named incident in `full_verify`, and the store is still usable afterwards):
1. `tamper_modify_each_column_class`: change `agent_name`, `epoch`, `flags`, `payload_len`, `target` of a middle row → `ChainBroken` at that seq.
2. `tamper_delete_middle_row` → `SeqGap` (or `ChainBroken`) at the gap.
3. `tamper_reorder`: swap all non-key columns of two adjacent rows → `ChainBroken`.
4. `tamper_truncate_tail`: delete the last 5 rows after the head anchor named the last row → startup verdict `AnchorAhead` (`expected_seq` = anchor seq, `observed_seq` = db head).
5. `tamper_truncate_head`: delete rows 1..=10 without a `prune_log` row → `FirstRetainedMismatch`.
6. `tamper_ciphertext_swap_naive`: swap `nonce`+`payload_ct` of rows 5 and 6 → `ChainBroken`.
7. `tamper_ciphertext_swap_rehashed`: same swap, then recompute every `record_hash`/`prev_hash` from row 5 on with the T02 functions (an attacker without the KEK can do this) and rewrite the keychain head anchor too → chain verifies, but the decrypt pass reports `DecryptFailed` at 5 and 6 (AAD binds `seq`).
8. `tamper_rewrite_chain_consistently`: change a payload-free column of row 5 and rehash everything to the head without touching the keychain → startup `AnchorMismatch`.
9. `tamper_prune_log_delete_row` (needs a store with 2 prunes; T11 provides `Store::prune`; until T11 lands, write `prune_log` rows + `PRUNE` events with a crate-internal test helper `testing::insert_fake_prune`) → `PruneLogNotContiguous` or `PruneLogBroken`.
10. `tamper_prune_log_alter_cutoff` of the older row → `PruneLogBroken` (row-hash chain) and, after rehashing the row chain, `PruneLogRowMismatch` (latest `PRUNE` payload's `prune_log_row_hash`).
11. `tamper_unknown_flag_bit` (set bit 1<<20 and rehash) → `UnknownFlagBits`.
12. `tamper_destroyed_key_referenced`: set `keys.wrapped_dek = NULL, destroyed_at = ts` for a key still referenced → `DestroyedKeyReferenced`.
13. `tamper_request_set_hash`: a `WRITE_APPROVED` appended with `requests` whose recomputed hash differs from the payload's `request_set_hash` → `RequestSetHashMismatch`; a correct one → no finding.
14. `clean_store_verifies_ok`: 300 mixed events → `full_verify()` returns no finding and appends `VERIFY {result: "ok"}` without the incident flag.

U-17:
15. `unanchored_tail_is_informational`: append 20 events, `FaultPoint::AnchorThreadPaused` so the keychain head stays at an older seq, shut down; startup verdict → `UnanchoredTail` with count 20, no incident, `advance_head = true`.
16. `incident_persists_until_ack`: produce an incident (case 4), append the VERIFY (via the shim's `apply`), restart (new store handle) → `open_incidents()` lists it; `acknowledge_incident(seq, "alice", "checked")` → appends `INTEGRITY_ACK` (plaintext `os_user = alice`), `open_incidents()` empty, also after another restart; acknowledging a non-incident seq → `Invalid`.
17. `anchor_missing_is_incident`: delete `head_anchor` from MemKeyring (KEK kept) → startup `AnchorMissing`.
18. `install_id_mismatch`: `pinned_install_id = Some(other)` → `InstallIdMismatch`.

U-22 (prune half; uses `testing::insert_fake_prune` now, re-run against real prunes in T11):
19. `u22_interrupted_prune_reconciled`: a committed `PRUNE` whose first-retained keychain update did not happen (keychain still holds the previous row's values), `PRUNE` seq ≥ head anchor seq → verdict `InterruptedPruneReconciled` (informational), `set_first_retained` = latest row values, no incident.
20. `u22_forged_prune_before_head_anchor`: a fake `PRUNE` inserted (and rehashed) at a seq below the head anchor → incident (`FirstRetainedMismatch` or `AnchorMismatch`).
21. `u22_first_retained_two_prunes_behind`: keychain first-retained equals the third-latest row → incident.

- [ ] **Step 2: Implement `verify.rs`.** Startup algorithm (write in this order; every step appends findings, none returns early except a hard I/O error):

```text
1. head = SELECT max(seq); first = SELECT min(seq) FROM events.
2. prune_log: load all rows ordered by prune_seq; check row-hash chain from ZERO_HASH (PruneLogBroken), contiguity
   (row0.range_start == 1, row[i].range_start == row[i-1].first_retained_seq; PruneLogNotContiguous).
   latest = last row or the GENESIS values {first_retained_seq: 1, last_pruned: ZERO_HASH}.
3. First retained record: first == latest.first_retained_seq and row(first).prev_hash == latest.last_pruned_record_hash
   (if first == 1: it is GENESIS and prev_hash == ZERO_HASH), else FirstRetainedMismatch.
4. Latest PRUNE record (if any): decrypt, payload.prune_log_row_hash == latest.row_hash, else PruneLogRowMismatch.
5. Scope start = max(seq) of the latest PRUNE, RESTORE or APP_START (else `first`); recompute canonical/record_hash and
   prev_hash links from scope start to head (ChainBroken / SeqGap / UnknownFlagBits / FormatVersionUnsupported).
6. Decrypt the head row (DecryptFailed / PayloadHashMismatch).
7. install_id: store_install_id vs pinned (InstallIdMismatch).
8. Anchors (§8.7 anchor rule), with A = head anchor, F = first-retained anchor:
   - A or F missing → if interrupted-restore rule applies (step 9) handle there; else AnchorMissing.
   - A.chain_id != head row chain_id → step 9, else AnchorMismatch.
   - A.seq > head → AnchorAhead.  row(A.seq) missing or its hash != A.record_hash → AnchorMismatch.
   - A.seq < head → verify (already covered by step 5 only if A.seq ≥ scope start; otherwise verify A.seq..scope start too)
     → UnanchoredTail(head − A.seq), advance_head.
   - F vs latest row: equal → ok. Else interrupted prune iff ALL: (a) F == second-latest row values (or GENESIS values when one row);
     (b) latest row contiguous with it; (c) latest PRUNE verifies and row(first).prev_hash == latest.last_pruned_record_hash;
     (d) latest PRUNE seq ≥ A.seq or lies in the verified unanchored tail → InterruptedPruneReconciled, set_first_retained = latest.
     Otherwise FirstRetainedMismatch.
9. Interrupted restore (T16 completes it; implement the predicate now): the latest RESTORE R (if R.seq ≥ scope start):
   A == R.prior_keychain_anchor, or A absent and prior null, and R verifies as the latest segment boundary
   → InterruptedRestoreReconciled, complete_restore = Some(..). Else fall back to the normal rule.
```
`full_verify` = steps 1–3 over the whole table, chain from `first` to head, every row decrypted (`DecryptFailed`, `PayloadHashMismatch`), every `WRITE_APPROVED` recomputed (F.8), `keys` references (`DestroyedKeyReferenced`), every `PRUNE` judged by its own settings snapshot (`PruneInsideRetention`), every `RESTORE` boundary (`source_head_seq == seq − 1`, `source_head_hash == prev_hash`, rows before it carry `source_chain_id`, rows from it on carry `new_chain_id` until the next `RESTORE`: `RestoreBoundaryMismatch`), keychain anchors as in step 8 (but no "advance" actions), anchor-dir checks (T14 hook, empty until then). Runs on a read-only connection on the calling thread; only the final `VERIFY` append goes through the writer.

`incidents.rs`: on open, scan `event_type IN ('VERIFY','INTEGRITY_ACK')` (plaintext), decrypt only `INTEGRITY_ACK` payloads (small) to map `verify_seq`; keep the open set in the writer's cache; update it on every `VERIFY`/`INTEGRITY_ACK` append.

Run: `cargo test -p atlas-duck-audit --test verify --locked` → all pass.

- [ ] **Step 3: Clippy, commit** (`feat(audit): chain/prune_log/anchor verification, interrupted-prune rule, full verify with decrypt pass, persistent incidents`).

---

### Task 10: `open()`: startup steps 1–4, keychain cases, `install_id` cross-check, retry schedule, schema fixture

**Files:**
- Modify: `crates/audit/src/open.rs`, `crates/audit/src/store.rs`, `crates/audit/src/lib.rs`
- Create: `crates/audit/tests/open.rs`, `crates/audit/tests/fixtures/schema/v1.db`, `crates/audit/tests/fixtures/schema/v1.keyring.json`

**Interfaces:**
- Consumes: T04 (gate, migrations), T05 (canary, locality), T08 (enable anchors), T09 (startup verdict).
- Produces:
  - `pub fn open(data: &LocalDataDir, lock: &InstanceLock, cfg: OpenConfig) -> Result<StartupOutcome, OpenError>` (C.3; F.12 types).
  - `pub fn keychain_retry_schedule() -> &'static [Duration]` = `[2, 4, 8, 16, 30, 30]` s (sum 90 s, inside the §8.7 60–120 s window; the app loop of M4 calls `open` again after each delay while showing "Waiting for keyring").
  - `pub fn read_store_install_id(data: &LocalDataDir) -> Result<Option<String>, OpenError>` (plaintext only; for the M6 wizard path (1a) "write this host's pinned file with the store's `install_id`").
  - `LockedReason::as_str()` → `keychain_unavailable` | `keychain_lost` | `keyring_not_local` (§4.3 strings; M3's gate handler uses them).

**Spec:** §8.7 steps 1–4 and the keychain cases (unreachable → backoff, not local → no keyring access, entries missing or undecryptable → `keychain_lost`, never `GENESIS`/first run), §8.6 (`install_id` cross-check: latest `RESTORE`, else `GENESIS`, else retained `APP_START`; mismatch = incident), §8.13 (gate first, migrations after verification, `SCHEMA_MIGRATED` in the same transaction, failure rolls back and is not an incident), §2.5 (first run = no DB in a local pinned dir), §13 U-18 (start half), U-19, U-20, U-21 (store half).

**Plan decisions (spec silent):** the retry schedule values; `FirstRun` is returned only when `audit.db` does not exist (a leftover `audit.db.new`/`.restoring` is deleted first and never counts as a DB); the locked outcomes never touch the DB file (no `-wal` checkpoint, no `meta` update).

- [ ] **Step 1: Write the failing tests** (`tests/open.rs`)
- `open_fresh_dir_is_first_run`: empty data dir → `FirstRun`; with a leftover `audit.db.new` → `FirstRun` and the leftover is gone.
- `open_ready_round_trip`: `create_new_store`, append 10, `flush_head_anchor`, `shutdown`; `open` → `Ready { verify }` with no incident findings; appends continue at seq 12 (after the startup `VERIFY` only if there was a finding; a clean start appends no `VERIFY`).
- `startup_order_migration_then_verify` (U-20 order): a store with a tail-truncation incident **and** a pending test migration (hooks: `extra_migrations = [1→2]`): rows appended by `open` are `SCHEMA_MIGRATED` (seq h+1) then `VERIFY` with `integrity_incident` (seq h+2); MemKeyring `ops()` recorded up to the moment the `VERIFY` row commits (captured by `FaultPoint::AfterStartupVerifyAppend` observer) contain no `Set(HeadAnchor)`/`Set(FirstRetainedAnchor)`; afterwards the head anchor names seq ≥ h+2.
- `u20_keychain_unavailable_then_ready`: `ring.set_unavailable(true)` → `Locked(KeychainUnavailable)`, DB and WAL bytes + mtimes unchanged, no migration ran (`user_version` still 1); `set_unavailable(false)` → `open` → `Ready`, `SCHEMA_MIGRATED {from 1, to 2}` appended (with the test migration hook). Never `OpenError` for the unavailable case.
- `keychain_locked_maps_to_unavailable`: MemKeyring fault `Get(Kek) → Locked` → `Locked(KeychainUnavailable)`.
- `retry_schedule_window`: `keychain_retry_schedule().iter().sum()` is ≥ 60 s and ≤ 120 s.
- `u18_keychain_wiped_is_lost_not_first_run`: `ring.wipe_install(id)` → `Locked(KeychainLost { offer: RecoverThisLog })`; DB byte-identical; no `GENESIS` anywhere; `create_new_store` on this dir → `AlreadyExists`.
- `kek_undecryptable_is_lost`: replace the keychain KEK with another valid 33-byte entry → `Locked(KeychainLost { RecoverThisLog })` (the newest record's DEK does not unwrap), not an incident.
- `keyring_not_local_reads_nothing`: `ring.set_locality(NotLocal{..})` → `Locked(KeyringNotLocal)`; `ring.ops()` is empty.
- `u21_store_newer_is_byte_identical`: (a) `PRAGMA user_version = 2` set raw; (b) head row `format_version = 2` (raw UPDATE); (c) recovery blob first byte 2; (d) keychain `head_anchor` first byte 2 → each `StoreNewer { found }` naming what is newer and the `written_by` version; DB + WAL bytes and mtimes unchanged; no `VERIFY`; no keychain `Set`.
- `install_id_cross_check`: `pinned_install_id = Some(other)` → `Ready` with an `InstallIdMismatch` incident `VERIFY` appended.
- `migration_failure_is_internal_not_incident`: a test migration that fails → `Err(MigrationFailed)`, `user_version` unchanged, no `VERIFY`, no anchor write; the next `open` with a good migration succeeds.
- `u19_v1_fixture_migrates_to_head`: copy `tests/fixtures/schema/v1.db`, load `v1.keyring.json` into a MemKeyring, `open` with the test migration 1→2 → `Ready`, `SCHEMA_MIGRATED` appended, then `full_verify()` has no incident.
- `generate_v1_fixture` (`#[ignore = "regenerates the committed schema-v1 fixture"]`): builds a deterministic-content store (fixed ids, FakeClock at 2026-10-08, 40 mixed events incl. one corroboration, so both NULL and non-NULL epochs and two DEKs exist), copies `audit.db` (after `wal_checkpoint(TRUNCATE)`) and writes the KEK and both anchor entries as hex to `v1.keyring.json`. Run once in this task, commit the two files; they are frozen like the vectors.

- [ ] **Step 2: Implement `open`** in exactly this order:

```rust
pub fn open(data: &LocalDataDir, _lock: &InstanceLock, cfg: OpenConfig) -> Result<StartupOutcome, OpenError> {
    let db = schema::db_path(data);
    remove_staging_leftovers(data)?;                                   // audit.db.new, audit.db.restoring only
    if !db.try_exists()? { return Ok(StartupOutcome::FirstRun) }
    // 1. version gate: read-only, writes nothing (§8.13)
    let v = schema::read_versions(&db)?;
    if let Err(found) = schema::gate(&v) { return Ok(StartupOutcome::StoreNewer { found: with_written_by(found, &v) }) }
    // 2. KEK (§8.6, §8.7): locality before any keyring access, then canary
    match cfg.keys.locality() {
        KeyringLocality::NotLocal { .. } => return Ok(StartupOutcome::Locked(LockedReason::KeyringNotLocal)),
        KeyringLocality::Unknown { .. } => return Ok(StartupOutcome::Locked(LockedReason::KeychainUnavailable)),
        KeyringLocality::Local => {}
    }
    if let Err(e) = keystore::canary_self_test(&*cfg.keys) {
        return Ok(StartupOutcome::Locked(if matches!(e, KeyStoreError::NotLocal) { LockedReason::KeyringNotLocal } else { LockedReason::KeychainUnavailable }));
    }
    let ro = schema::open_ro(&db)?;
    let offer = if newest_is_restore_of(&ro, cfg.keys.install_id())? { RecoveryOffer::FinishRestore } else { RecoveryOffer::RecoverThisLog };
    let kek = match cfg.keys.get(&EntryName::Kek) {
        Err(KeyStoreError::NotLocal) => return Ok(StartupOutcome::Locked(LockedReason::KeyringNotLocal)),
        Err(_) => return Ok(StartupOutcome::Locked(LockedReason::KeychainUnavailable)),
        Ok(None) => return Ok(StartupOutcome::Locked(LockedReason::KeychainLost { offer })),
        Ok(Some(b)) => match Kek::from_entry_bytes(&b) {
            Err(KekEntryError::NewerLayout(n)) => return Ok(StartupOutcome::StoreNewer { found: format!("keychain kek layout {n}") }),
            Err(KekEntryError::Malformed) => return Ok(StartupOutcome::Locked(LockedReason::KeychainLost { offer })),
            Ok(k) => k,
        },
    };
    if !newest_dek_unwraps(&ro, &kek)? { return Ok(StartupOutcome::Locked(LockedReason::KeychainLost { offer })) }
    // 3. anchors + pre-migration verification, held in memory (§8.7 step 3)
    let (head_anchor, first_retained) = match load_anchors(&*cfg.keys) {
        Ok(a) => a,
        Err(AnchorLoad::Newer(n)) => return Ok(StartupOutcome::StoreNewer { found: format!("keychain anchor layout {n}") }),
        Err(AnchorLoad::Unavailable) => return Ok(StartupOutcome::Locked(LockedReason::KeychainUnavailable)),
    };
    let store_install_id = read_store_install_id_conn(&ro)?;
    let verdict = verify::startup(&StartupInputs { conn: &ro, kek: &kek, head_anchor, first_retained, store_install_id,
                                                   pinned_install_id: cfg.pinned_install_id.clone(), anchor_lines: anchor_dir::load(cfg.anchor_dir.as_deref(), &ro)? })?;
    drop(ro);
    // 4. writer up (anchors disabled) → migrations + SCHEMA_MIGRATED → the step-3 VERIFY → only then anchors (§8.7, §8.13)
    let store = Store::start_writer(&db, kek, cfg, /* anchors_enabled */ false)?;
    store.run_migrations()?;                         // MigrationFailed → Err; the store is shut down first
    let verify = store.append_startup_verify(&verdict)?;   // no row when verdict has no findings
    store.enable_anchors(verdict.anchor_actions)?;   // advance head, write first-retained (interrupted prune), complete restore (T16)
    store.update_written_by()?;
    Ok(StartupOutcome::Ready { store, verify })
}
```
(`anchor_dir::load` returns `None` until T14; add it as a stub now.)

Run: `cargo test -p atlas-duck-audit --test open --locked` → all pass. Re-run `--test verify` (its shim now delegates to `open`).

- [ ] **Step 3: Clippy, commit** (`feat(audit): open() with version gate, keychain cases, pre-migration verification, migrations then VERIFY then anchors; schema-v1 fixture`).

---

### Task 11: Prune, `prune_log`, cadence/baseline/clamp, crypto-shredding, legal hold

**Files:**
- Create: `crates/audit/src/prune.rs`, `crates/audit/tests/prune.rs`
- Modify: `crates/audit/src/writer.rs` (cadence triggers, `append_in_tx` for the `PRUNE` row), `crates/audit/src/store.rs`

**T08 notes:** release builds use `panic = "abort"` (§7.7), so `AuditError::AnchorThreadDead` (anchor thread caught a panic) is defence in depth for debug/test builds only. `complete_restore` timing out takes its job back (`AnchorFlushTimeout`, safe to retry) unless the thread already started it (`AnchorOutcomeUnknown`: re-read the keychain before retrying).

**T08 handoff (barriers):** `Store::install_barrier(Barrier::Prune{..}) -> Result<BarrierGuard, AuditError>` must be called BEFORE the `PRUNE` commit becomes visible to the anchor thread (it can otherwise write a head above the PRUNE seq in the window between commit and install). Hold the guard across the whole prune; `guard.complete()` only after the work succeeded (the anchor thread lifts the barrier when the first-retained update succeeded), so every error path releases it by drop. Only one barrier can exist at a time (a second install is `Invalid`). `health().anchors_blocked` shows a leaked one.

**Interfaces:**
- Consumes: T06 `ClockState`, T07 writer, T08 `Barrier::Prune`, T09 (verification reused in tests), T12's `Settings` snapshot type (write a minimal `Settings { retention_days: 100, legal_hold: false, anchor_dir: None, instances: {} }` struct here; T12 fills the view).
- Produces:
```rust
impl Store { pub fn prune(&self, confirm_large_advance: Option<Confirmed>) -> Result<PruneOutcome, AuditError>; }   // C.3
pub enum PruneOutcome { Pruned { prune_seq: u64, range_start: u64, first_retained_seq: u64, count: u64, cutoff: NaiveDate, baseline: NaiveDate, clamped: bool, destroyed_key_ids: Vec<u64> },
                        Skipped(PruneSkip) }
pub enum PruneSkip { NotCorroborated, HeadEpochNull, LegalHold, AlreadyRanThisEpoch, ClockBeforeHead, ClockBeforeLastPrune, NothingToAdvance, ConfigNotReconciled }
pub(crate) fn effective_epochs(epochs: &[Option<NaiveDate>]) -> Vec<Option<NaiveDate>>;
pub(crate) fn prunable_prefix_len(rows: &[PruneRow], eff: &[Option<NaiveDate>], cutoff: NaiveDate) -> usize;
```

**Spec:** §8.8 (prune rule with the `ts_utc`/`clock_forward`/`clock_behind` clauses, "only after the date has been corroborated in this process", one transaction writing `PRUNE` + `prune_log` row, then first-retained update with retry; clock guards; cadence, baseline, clamp per L37; crypto-shredding reference rule, never the current DEK, never under legal hold; legal hold pauses prune and shredding), §8.5 (`prune_log` never pruned, contiguous), §8.1 (after each prune `incremental_vacuum` then `wal_checkpoint(TRUNCATE)`), L36 (effective epoch, no prune while the head's `epoch` is NULL).

**Plan decisions (spec silent):**
- **Empty-range prunes:** a run whose (possibly clamped) cutoff is later than the baseline writes `PRUNE` + a `prune_log` row even when no record qualifies (`count 0`, `range_start == first_retained_seq`, `last_pruned_record_hash` carried over). Without this, a stretch of days with no records would freeze the baseline (and with it the clamp) forever, because the baseline only moves with a `prune_log` row. A run whose cutoff is not later than the baseline writes nothing (`NothingToAdvance`).
- A confirmed manual run (`prune(Some(confirmed))`, Settings "Prune backlog now") lifts the clamp **and** the cadence check for that one run; every other guard applies. `prune(None)` behaves like an automatic run.
- Automatic attempts are queued by the writer (a) after the first corroboration of the process, (b) after any commit whose `epoch` date is later than the previous head's; they run on the writer between commands and are deferred until `reconcile_config_file` (T12) has run once in this process (`ConfigNotReconciled`), which is how "the difference is logged … before any prune" (§8.8) is enforced. M3 must call `reconcile_config_file` in `Core::start`.
- Clock-guard skips log `CLOCK_ANOMALY {kind: "prune_skipped", reason}` at most once per reason per process.
- DEK destruction set = every non-destroyed `key_id` not referenced by any row with `seq ≥ first_retained_seq`, except the DEK the writer would select for the current head epoch (the "current" DEK). This covers the month and uncorroborated DEKs alike.

- [ ] **Step 1: Write the failing unit tests** (pure functions, `tests/prune.rs`)
- `effective_epoch_backward_fill`: `[None, None, Some(d1), None, Some(d2), None]` → `[d1, d1, d1, d2, d2, None]`.
- `prefix_requires_epoch_and_ts`: rows with epochs older than the cutoff but the last of them with `date(ts)` newer and no later old unflagged ts → prefix stops there.
- `prefix_any_later_record_clause`: a row with a future `ts_utc` (uncorroborated forward jump) followed by a row whose `date(ts)` is older than the cutoff → both prunable.
- `prefix_clock_behind_ts_never_counts`: a `clock_behind` row with an old `ts_utc` and no later unflagged row older than the cutoff → not prunable; adding such a later row → prunable.
- `prefix_clock_forward_needs_only_epoch`.
- `prefix_stops_at_null_effective_epoch`.

- [ ] **Step 2: Write the failing store tests** (FakeClock; a helper `day(sim, n_events)` advances wall + mono by 24 h, calls `observe_server_date` with the real date, appends n events)
- `prune_daily_keeps_verifiability` (U-09): retention 92, 200 days × 4 events: from day 93 on exactly one `PRUNE` per epoch day; `prune_log` contiguous from `range_start 1`; GENESIS gone after the first prune that removes it; MemKeyring first-retained == latest row; `full_verify()` clean after every 20 days; no retained row older than 92 days by `ts_utc` was deleted too early (check every deleted row: `today − date(ts) ≥ 92`).
- `cadence_one_run_per_epoch_day`: three restarts (shutdown + `open`) on the same day with corroboration each time → one `PRUNE` with that epoch.
- `no_prune_without_corroboration_in_process`: restart, no `observe_server_date` → no `PRUNE` even after `prune(None)` (`NotCorroborated`).
- `no_prune_while_head_epoch_null`: store never corroborated → `HeadEpochNull`.
- `legal_hold_pauses_prune_and_shredding` (X-02 store half): legal hold on (via T12 API; until T12, set the writer's settings directly through a `testing` setter) → `Skipped(LegalHold)`, no DEK destroyed; off (confirmed) → the next day's run prunes.
- `clamp_after_gap_no_dialog` (RF-1b core): retention 92, history of 120 days with daily prunes, then the app is off for 30 days (FakeClock jumps 30 d, real server date too): each subsequent daily run has `clamped: true`, `cutoff == baseline + 2`, never returns or requires a confirmation; the cutoff gap to `today − 92` shrinks by one day per day until runs are unclamped again.
- `first_prune_baseline_is_genesis_effective_epoch`: no `prune_log` row; GENESIS epoch NULL; first corroboration on day 0; 100 days later the first run's baseline is day 0's date and its cutoff ≤ baseline + 2.
- `confirmed_run_lifts_clamp_once`: during the backlog, `prune(Some(confirmed))` → `clamped: false`, cutoff = `min(today, corroborated, head epoch) − 92`; next automatic run clamps again relative to the new baseline only if needed.
- `empty_range_prune_written`: no events for 10 days inside the retention window → a run whose cutoff advances writes `PRUNE {count: 0}` and a row with `range_start == first_retained_seq`; the next runs keep advancing.
- `clock_guards_skip_and_log_once`: wall clock set before the head's `ts_utc` → `ClockBeforeHead` + one `CLOCK_ANOMALY {prune_skipped}`; a second attempt logs nothing new; clock restored → prune runs.
- `crypto_shredding_reference_checked` (U-12 core): months Jan–May with records; held-back records written in early June before corroboration keep `epoch` = last May date and the May DEK; after the prunes that remove all April rows, the April DEK is destroyed (`wrapped_dek NULL`, `destroyed_at` set, listed in `PRUNE.destroyed_key_ids`) while the May DEK survives until the `PRUNE` that removes the last May-epoch row; the current DEK is never destroyed; `full_verify()` has no `DestroyedKeyReferenced`.
- `post_prune_vacuum_and_checkpoint`: after a prune that deletes > 100 rows: `PRAGMA freelist_count` == 0 and the `-wal` file is 0 bytes.
- `prune_payload_and_settings_snapshot`: the `PRUNE` payload has `range`, `count`, `cutoff`, `clamped`, `baseline`, `destroyed_key_ids`, `prune_log_row_hash` (== the row's `row_hash`) and `settings.retention_days`.
- `u22_crash_after_prune_commit_reconciles` (U-22 prune half, real prune): `FaultPoint::AfterPruneCommit` makes the writer stop before setting the barrier (simulated crash: `shutdown()` without anchor update); `open` → `Ready`, `VERIFY {result: "interrupted_prune_reconciled"}` without `integrity_incident`, MemKeyring first-retained == latest row, head anchor advanced.
- `u22_keychain_failure_after_prune_retried`: MemKeyring fails `Set(FirstRetainedAnchor)` 3× → `health().first_retained_update_pending` and `anchor_write_failing` true, then false after success; no `VERIFY` incident; head anchor never passed the `PRUNE` seq meanwhile.

- [ ] **Step 3: Implement** `prune_run` in the writer exactly in this order:

```rust
fn prune_run(&mut self, confirm: Option<&Confirmed>) -> Result<PruneOutcome, AuditError> {
    if !self.config_reconciled { return Ok(PruneOutcome::Skipped(PruneSkip::ConfigNotReconciled)) }
    let now = self.clock.now_utc();
    let mono = self.clock.suspend_aware_elapsed();
    let Some(cd) = self.clock_state.corroborated_date(mono) else { return Ok(Skipped(NotCorroborated)) };
    let Some(head_epoch) = self.head.epoch else { return Ok(Skipped(HeadEpochNull)) };
    let s = self.settings.current();
    if s.legal_hold { return Ok(Skipped(LegalHold)) }
    if confirm.is_none() && prune_exists_with_epoch(&self.conn, head_epoch)? { return Ok(Skipped(AlreadyRanThisEpoch)) }
    if now < self.head.ts { self.log_prune_skip_once("now_before_head")?; return Ok(Skipped(ClockBeforeHead)) }
    if let Some(t) = latest_prune_ts(&self.conn)? { if now < t { self.log_prune_skip_once("now_before_last_prune")?; return Ok(Skipped(ClockBeforeLastPrune)) } }
    let raw_cutoff = date_of(now).min(cd).min(head_epoch) - Days::new(s.retention_days as u64);
    let latest = latest_prune_row(&self.conn)?;                       // None before the first prune
    let baseline = match &latest { Some(r) => r.cutoff_epoch, None => genesis_effective_epoch(&self.conn)? };
    let cap = baseline + Days::new(2);
    let (cutoff, clamped) = if confirm.is_some() || raw_cutoff <= cap { (raw_cutoff, false) } else { (cap, true) };
    self.prune_backlog_days = (raw_cutoff - cutoff).num_days().max(0) as u32;
    if cutoff <= baseline { return Ok(Skipped(NothingToAdvance)) }
    let rows = load_prune_rows(&self.conn)?;                          // retained rows ascending: seq, epoch, ts, flags, key_id, record_hash
    let eff = effective_epochs(&rows.iter().map(|r| r.epoch).collect::<Vec<_>>());
    let n = prunable_prefix_len(&rows, &eff, cutoff);
    let range_start = latest.as_ref().map_or(1, |r| r.first_retained_seq);
    let first_retained_seq = range_start + n as u64;
    let last_pruned = if n > 0 { rows[n - 1].record_hash } else { latest.as_ref().map_or(ZERO_HASH, |r| r.last_pruned_record_hash) };
    let prev_row_hash = latest.as_ref().map_or(ZERO_HASH, |r| r.row_hash);
    let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current_key = self.current_dek_id(&tx, head_epoch)?;          // selection only, never creates
    let destroy: Vec<u64> = unreferenced_keys(&tx, first_retained_seq, current_key)?;   // non-destroyed, no row with seq >= first_retained_seq
    tx.execute("DELETE FROM events WHERE seq < ?1", [first_retained_seq])?;
    for k in &destroy { tx.execute("UPDATE keys SET wrapped_dek = NULL, destroyed_at = ?2 WHERE key_id = ?1", params![k, now.to_rfc3339_ms()])?; }
    let prune_seq = self.head.seq + 1;
    let row_hash = encoding::prune_row_hash(&prev_row_hash, prune_seq, range_start, &epoch_text(cutoff), &last_pruned, first_retained_seq);
    tx.execute("INSERT INTO prune_log (prune_seq, range_start, cutoff_epoch, last_pruned_record_hash, first_retained_seq, prev_row_hash, row_hash) VALUES (?1,?2,?3,?4,?5,?6,?7)", ...)?;
    let payload = json!({ "range": [range_start, first_retained_seq], "count": n, "cutoff": epoch_text(cutoff), "clamped": clamped,
                          "baseline": epoch_text(baseline), "destroyed_key_ids": destroy, "prune_log_row_hash": hex::encode(row_hash), "settings": s.to_json() });
    let committed = self.append_in_tx(&tx, PreparedEvent::system(EventType::PRUNE, payload)?)?;   // must get seq == prune_seq
    self.hooks.fault(FaultPoint::AfterPruneTxBeforeCommit)?;
    tx.commit()?;
    for k in &destroy { self.dek_cache.remove(k); }
    self.hooks.fault(FaultPoint::AfterPruneCommit)?;                  // crash simulation: barrier never set
    let _ = self.conn.execute_batch("PRAGMA incremental_vacuum; PRAGMA wal_checkpoint(TRUNCATE);");  // failures logged, not fatal
    self.anchors.set_barrier(Barrier::Prune { seq: committed.seq, record_hash: committed.record_hash,
        first_retained: FirstRetainedAnchor { chain_id: self.head.chain_id.clone(), genesis_hash: self.genesis_hash, first_retained_seq, first_retained_prev_hash: last_pruned } });
    Ok(PruneOutcome::Pruned { prune_seq: committed.seq, range_start, first_retained_seq, count: n as u64, cutoff, baseline, clamped, destroyed_key_ids: destroy })
}
```
`prunable_prefix_len` (write exactly):
```rust
pub(crate) fn prunable_prefix_len(rows: &[PruneRow], eff: &[Option<NaiveDate>], cutoff: NaiveDate) -> usize {
    // suffix_min[i] = min date(ts_utc) over rows j >= i that do not carry clock_behind
    let mut suffix_min: Vec<Option<NaiveDate>> = vec![None; rows.len() + 1];
    for i in (0..rows.len()).rev() {
        let own = (!rows[i].flags.contains(EventFlags::CLOCK_BEHIND)).then(|| date_of(rows[i].ts));
        suffix_min[i] = match (own, suffix_min[i + 1]) { (Some(a), Some(b)) => Some(a.min(b)), (a, b) => a.or(b) };
    }
    let mut n = 0;
    for i in 0..rows.len() {
        let Some(e) = eff[i] else { break };                      // no effective epoch: never prunable (L36)
        if e >= cutoff { break }
        let ts_ok = rows[i].flags.contains(EventFlags::CLOCK_FORWARD) || matches!(suffix_min[i], Some(d) if d < cutoff);
        if !ts_ok { break }
        n += 1;
    }
    n
}
```
The `genesis_hash` the writer holds comes from the first-retained anchor read at open (or from `GENESIS` at first run); `append_in_tx` is the per-row body of T07's `append_tx` factored out so `PRUNE`, `RESTORE`, migrations and `VERIFY` share it.

Run: `cargo test -p atlas-duck-audit --test prune --locked` → all pass; re-run `--test verify` (cases 9, 10, 19–21 now also run against real prunes: replace `insert_fake_prune` with `prune()` where the test only needs a real prune).

- [ ] **Step 4: Clippy, commit** (`feat(audit): prune with prune_log row chain, L37 cadence/baseline/clamp, reference-checked crypto-shredding, legal hold`).

---

### Task 12: Settings view, `apply_setting`, config-file reconcile

**Files:**
- Create: `crates/audit/src/settings.rs`, `crates/audit/tests/settings.rs`
- Modify: `crates/audit/src/writer.rs`, `crates/audit/src/store.rs`, `crates/audit/src/prune.rs` (use the real view)

**Interfaces:**
- Produces:
```rust
pub struct Settings { pub retention_days: u32, pub legal_hold: bool, pub anchor_dir: Option<String>, pub instances: BTreeMap<String, InstancePolicy> }   // C.3 `Settings`
pub struct InstancePolicy { pub origin: Option<String>, pub ca_fingerprint: Option<String>, pub proxy: Option<String> }
// keyed by instance_id (never alias). origin Some = confirmed origin (L32; None = unconfirmed/removed).
// proxy: None = no per-instance setting (OS static proxy applies, L42); Some("direct") = direct; Some("host:port") = explicit proxy.
// The audit store stores these strings verbatim; validation and normalisation are core's (M3).
pub enum SettingChange { RetentionDays(u32), LegalHold(bool), AnchorDir(Option<String>),
    InstanceOrigin { instance_id: String, origin: Option<String> }, InstanceCaFingerprint { instance_id: String, fingerprint: Option<String> },
    InstanceProxy { instance_id: String, proxy: Option<String> } }
pub struct FilePolicy { pub retention_days: Option<u32>, pub legal_hold: Option<bool>, pub anchor_dir: Option<Option<String>> }
pub const RETENTION_DEFAULT: u32 = 100; pub const RETENTION_MIN: u32 = 92;
impl Settings { pub fn to_json(&self) -> serde_json::Value; pub fn from_json(&serde_json::Value) -> Result<Self, AuditError>; }
impl Store {
    pub fn settings(&self) -> Settings;                                                                       // C.3
    pub fn apply_setting(&self, change: SettingChange, confirmed: Option<Confirmed>) -> Result<Committed, AuditError>;  // C.3
    pub fn reconcile_config_file(&self, file: &FilePolicy) -> Result<Vec<Committed>, AuditError>;            // X-01; M3 calls it in Core::start
}
```

**Spec:** §8.8 (retention default 100, minimum 92, authoritative in the DB, changed only via the UI with `CONFIG_CHANGED`; legal hold `LEGAL_HOLD_CHANGED`; file differences logged `CONFIG_CHANGED {source: file, old, new}` before any prune; values below 92 raised to 92; lifting legal hold or lowering retention never from a file edit), §7.7/§7.1/L32 (instance origin, CA fingerprint, proxy authoritative in the DB; origin changes need a native confirmation), §10.3 (security-weakening list: lower retention, lift legal hold, change/remove anchor dir, add custom CA, change base URL or add an instance), §8.5 (anchor dir change is security-weakening), P5.

**Plan decisions (spec silent):**
- View = the `settings` snapshot of the latest retained `PRUNE` (defaults before the first prune) overlaid, in seq order, with every later `CONFIG_CHANGED` (policy keys only) and `LEGAL_HOLD_CHANGED` whose payload has `applied: true`. Built at open (decrypting only those rows: `event_type` is plaintext) and maintained by the writer. Readable only after the KEK is available (C.3 note): nothing reads retention or instance origins while locked.
- Confirmation rules: needs `Some(Confirmed)` → lower `retention_days`, `LegalHold(false)` while on, any `AnchorDir` change, any `InstanceOrigin` change (add, change, remove), setting or changing a `ca_fingerprint` (removing one is stricter and plain); `retention_days < 92` → `Invalid`; without the needed confirmation → `NeedsConfirmation(<key>)` and nothing is logged. Proxy changes are plain (not on the §10.3 list).
- Policy keys in `CONFIG_CHANGED.key`: `retention_days`, `anchor_dir`, `instance.<id>.origin`, `instance.<id>.ca_fingerprint`, `instance.<id>.proxy`. `CONFIG_CHANGED` rows with other keys (written by M3/M6: proxy effective changes, attention mode, "Prepare for removal") are ignored by the view.
- File reconcile: an event is logged for each file value that differs from the view: retention `requested` = file value, `new = max(requested, 92)`, `applied = new > old`; legal hold: `true` while off → applied, `false` while on → logged `applied: false`; anchor dir: always `applied: false` (security-weakening). Each with `source: "file"`. Then `config_reconciled = true` (unblocks prune, T11).

- [ ] **Step 1: Write the failing tests** (`tests/settings.rs`)
- `defaults`: fresh store → retention 100, legal hold off, no anchor dir, no instances.
- `x01_file_below_minimum_raised_and_logged`: file retention 50 → one `CONFIG_CHANGED {source: file, key: retention_days, old: 100, requested: 50, new: 92, applied: false}`, view still 100; file retention 150 → `applied: true`, view 150; logged before any prune (the writer had a corroboration queued: assert the first `PRUNE` seq > the `CONFIG_CHANGED` seq).
- `x01_prune_waits_for_reconcile`: corroborated store without `reconcile_config_file` → `prune(None)` = `Skipped(ConfigNotReconciled)`.
- `x02_lift_legal_hold_needs_confirmation`: set on (plain) → `LEGAL_HOLD_CHANGED {applied: true}`; file `false` → logged `applied: false`, still on; `apply_setting(LegalHold(false), None)` → `NeedsConfirmation("legal_hold")`, nothing logged; with `Confirmed` → off, payload carries `confirmed.dialog_text_sha256`.
- `lower_retention_needs_confirmation`, `retention_below_92_invalid`, `anchor_dir_change_needs_confirmation`, `instance_origin_needs_confirmation`, `ca_fingerprint_add_needs_confirmation_remove_does_not`, `proxy_change_plain`.
- `settings_survive_prune_of_their_events` (Review Focus 5): retention 150 and legal hold toggled on/off on day 0, instance origin set; 400 simulated days with prunes (retention 150) → every early `CONFIG_CHANGED`/`LEGAL_HOLD_CHANGED` row is pruned; `settings()` still reports 150 and the origin, also after a restart.
- `non_policy_config_changed_ignored`: a `CONFIG_CHANGED {key: "attention_mode"}` appended by a caller does not change the view.

- [ ] **Step 2: Implement**, then make T11's prune use `self.settings.current()` and embed `to_json()` (JCS-stable: object with sorted keys) in `PRUNE`.

Run: `cargo test -p atlas-duck-audit --test settings --test prune --locked` → all pass.

- [ ] **Step 3: Clippy, commit** (`feat(audit): audit-authoritative settings view with prune snapshots, confirmation rules, config-file reconcile`).

---

### Task 13: Clock scenario suite over simulated months (U-10 … U-14, RF-1a, RF-1b)

**Files:**
- Create: `crates/audit/tests/clock_scenarios.rs`; extend `crates/audit/tests/common/mod.rs` with the `Sim` driver.

**Interfaces:**
- Consumes: everything up to T12. Produces only tests (and fixes found by them, in the module they concern).
- `Sim` (test helper): holds a FakeClock (local wall + mono), a separate **real** time `real: UtcInstant`, the store, a map `seq → real instant written`. Methods: `day(n_events)` (real += 24 h; wall += 24 h unless a wall offset is active; mono += 24 h unless suspended; then `server_date()` and appends), `server_date()` (calls `observe_server_date(real)`), `set_wall_offset_days(i64)` (local clock wrong from now on), `suspend(days)` (real and wall advance, mono does not, no server response), `off(days)` (app not running: shutdown, real/wall/mono advance, then `open` + `reconcile_config_file`), `restart()`, `assert_no_early_prune(retention)` (every seq deleted so far was written ≥ `retention` real days before the real time of the `PRUNE` that deleted it), `assert_no_future_epoch_or_dek()` (every non-NULL `epoch` and every `keys.month` ≤ the real date/month at the time they were written), `anomalies() -> Vec<payload>`.

**Spec:** §13 Unit clauses quoted in the test names; §8.2, §8.6, §8.8, L36, L37.

- [ ] **Step 1: Write the scenarios** (each a `#[test]`, retention 92 unless stated; ≤ 8 events per simulated day to keep runtime < 60 s per test on CI)
1. `u10_forward_jump_never_over_prunes`: 120 normal days, then local clock +40 days for 5 days (server corroborates the real date daily), then corrected, 100 more days → `assert_no_early_prune(92)`, `assert_no_future_epoch_or_dek()`.
2. `u10_backward_jump_never_over_prunes`: same with −40 days.
3. `u11_five_year_forward_jump_at_start`: first run with the local clock +5 years, instance traffic on day 0 (server = real date) → `epoch` = real date from the first corroborated record; exactly one `CLOCK_ANOMALY {local_ahead}`; clock corrected on day 3; no `keys.month` beyond the real month; pruning later runs on the real date (first `PRUNE` cutoff ≈ real day 0 + 1 day after 93 real days).
4. `u11_five_year_forward_jump_mid_process`: corroborated history of 50 days, then +5 years mid-process for 2 days, then corrected → `epoch` never moves past the real date, one anomaly, no future DEK.
5. `u12_records_before_first_corroboration_after_30_day_gap`: history ending on 2026-05-20; app off 30 days; restart on real 2026-06-19, write 5 records **before** any server response (held back at `epoch` 2026-05-20, May DEK, current `ts_utc`), then corroborate; keep running daily until all other May-epoch rows are pruned and a shred pass has run → those 5 rows still decrypt, `full_verify()` decrypt pass clean, the May DEK is still present; they are pruned only ≥ 92 real days after 2026-06-19, by a `PRUNE` that also lists the May DEK in `destroyed_key_ids`; no `integrity_incident` ever.
6. `u12_restart_across_month_boundary_before_corroboration`: last record 2026-07-31; restart on 2026-08-01 before corroboration → records keep `epoch` 2026-07-31 and the July DEK; no August DEK until corroboration.
7. `u13_suspend_14_days` and `u13_suspend_2_5_days`: corroborated in process, then `suspend(14)` (resp. 2.5 days), then releases/denials appended **before** the next server response → no `clock_forward` flag, no `CLOCK_ANOMALY`; each such record survives ≥ 92 real days (`assert_no_early_prune`).
8. `u14_backward_60_days_mid_life` and `u14_backward_10_days_mid_life`: corroborated history, then local clock −60 (−10) days for 60 real days, then corrected → episode records carry `clock_behind`, exactly one `CLOCK_ANOMALY {local_behind}` per episode, `assert_no_early_prune(92)`.
9. `u14_backward_first_run_variant`: first run with the local clock −60 days (`GENESIS` with the clock behind) and no server traffic for 2 days, then traffic, corrected after 60 days → same assertions; `GENESIS` and the records before the first corroboration carry no `clock_behind` (L47: they hold a NULL epoch resolved by the effective epoch), the records after the first corroboration while the clock is still behind carry it via (a).
10. `rf1a_first_run_forward_clock` (RF-1a): first run with the local clock +1 year; instance added; traffic → no non-NULL `epoch`, month DEK or `keys.month` later than the corroborated (real) date ever; `CLOCK_ANOMALY` exactly once; clock corrected on day 5; 200 days later `assert_no_early_prune(retention)` holds for retention 100.
11. `rf1b_prune_after_long_gap_no_baseline` (RF-1b): (a) store whose first-ever prune comes after the app was off for 3 days past day 95; (b) separately a 30-day gap after a steady state → no `NeedsConfirmation`/dialog path is ever taken (automatic runs only), every run advances the cutoff by ≤ 2 epochs beyond its baseline, the backlog shrinks by a net one day per day (`health().prune_backlog_days` decreases by 1 per simulated day), `assert_no_early_prune(92)`.

Runtime: the scenario suite and the long-running tests of T11/T12 (`prune_daily_keeps_verifiability`, `settings_survive_prune_of_their_events`) open their stores with the `testing`-only hook `hooks.synchronous_normal = true` (`PRAGMA synchronous=NORMAL`), because hundreds of simulated days × `synchronous=FULL` fsyncs exceed CI budgets on Windows. Durability under `FULL` is proven by `append_chains_and_is_durable` (T07) and by every other test, which keep the production pragma; the hook is compiled only with the `testing` feature and a test (`synchronous_full_by_default`, T07) asserts that `OpenConfig::new` yields `FULL`. Do not reduce event counts or simulated days to save time; use the hook.

- [ ] **Step 2: Run, fix, iterate.** Run: `cargo test -p atlas-duck-audit --test clock_scenarios --locked -- --test-threads=2` → all pass. Any failure is a bug in T06/T07/T11/T12: fix it there with a focused unit test added to that task's test file, and say in the commit message which rule was wrong.

- [ ] **Step 3: Clippy, commit** (`test(audit): clock and retention scenario suite (U-10..U-14, RF-1a, RF-1b)`).

---

### Task 14: Anchor-dir line types and the verifier side

**Files:**
- Create: `crates/audit/src/anchor_dir.rs`, `crates/audit/tests/anchor_dir.rs`, `crates/audit/tests/fixtures/anchor_dir/{all_line_types.jsonl, bad_lines.jsonl}`
- Modify: `crates/audit/src/verify.rs` (startup step 3 compare, `full_verify` checks), `crates/audit/src/open.rs` (`anchor_dir::load`)

**Interfaces:**
```rust
pub enum AnchorLine {
    Header { chain_id: String, install_id: String, host: String, os_user: String, created_at: String },
    Record { seq: u64, record_hash: [u8; 32], epoch: Option<String>, clock_behind: bool },        // daily, APP_STOP and RESTORE lines (§8.5)
    Immediate { seq: u64, record_hash: [u8; 32], epoch: Option<String>, event_type: String },     // PRUNE, RESTORE, LEGAL_HOLD_CHANGED, policy CONFIG_CHANGED, INTEGRITY_ACK, CLOCK_ANOMALY
    Prune { first_retained_seq: u64, first_retained_prev_hash: [u8; 32], cutoff_epoch: String },
    Detached { seq: u64, record_hash: [u8; 32], epoch: Option<String>, detached_at: String },     // {"event_type":"ANCHOR_DETACHED", …}
}
pub fn parse_line(s: &str) -> Result<AnchorLine, AnchorLineError>;
pub fn to_line(l: &AnchorLine) -> String;                  // JCS text, no trailing newline; M10's writer uses it
pub fn file_name(chain_id: &str) -> String;                // "<chain_id>.jsonl"
pub(crate) fn load(dir: Option<&Path>, conn: &Connection) -> Result<Option<BTreeMap<String /*chain_id*/, Vec<AnchorLine>>>, OpenError>;
pub(crate) fn check(lines: &BTreeMap<String, Vec<AnchorLine>>, ctx: &VerifyCtx) -> Vec<VerifyFinding>;
```

**Spec:** §8.5 (line shapes, header line, immediate lines, `ANCHOR_DETACHED`, `epoch: null` lines and no daily line for NULL-epoch records per L36), §8.7 (anchor-dir checks in full verification, `clock_behind` lines judged by the first later unflagged record), §13 U-06 anchor-dir clauses (verifier half; the writer clauses are M10), U-14 "an anchored `clock_behind` record pruned early is flagged by full verification", P7.

**Plan decisions (spec silent):** line discrimination by keys (`first_retained_seq` → `Prune`; `event_type == "ANCHOR_DETACHED"` → `Detached`; other `event_type` → `Immediate`; `install_id` + `host` → `Header`; else `Record`), unknown keys rejected, hashes as 64 lowercase hex chars; the anchor dir used by verification is the store's `settings().anchor_dir` (authoritative), falling back to `OpenConfig.anchor_dir` only when the store has none; a missing file for a chain is not a finding in M2 (the writer is M10).

- [ ] **Step 1: Write the failing tests** (`tests/anchor_dir.rs`): fixture lines are produced by `to_line` from a real test store's rows and written into a temp anchor dir (`<dir>/<chain_id>.jsonl`), then the store's `anchor_dir` setting is pointed at it (confirmed).
- `parse_all_line_types` (fixture `all_line_types.jsonl`: one line of each kind incl. `epoch: null` and `clock_behind: true`) and `to_line` round trip; `bad_lines.jsonl` (unknown key, short hash, uppercase hex, missing `seq`) → each `Err`.
- `anchored_record_matches`: lines for seqs ≥ first retained that match → no finding.
- `u06_anchored_record_rewritten`: rehash-rewrite rows from seq k on (attacker without the anchor dir) → `AnchorDirMismatch` at the first anchored seq ≥ k, even though the keychain head anchor was rewritten consistently too.
- `u06_anchored_seq_beyond_head`: a line for a seq above the DB head (rollback/truncation) → `AnchorDirMismatch`.
- `immediate_line_event_type_mismatch` → `AnchorDirMismatch`.
- `prune_line_mismatch`: a `Prune` line whose `cutoff_epoch` differs from its `prune_log` row → `AnchorDirMismatch`.
- `u06_anchored_record_pruned_inside_retention`: a `Record` line with epoch E for a seq that a forged prune (prune_log row with cutoff ≤ E, written by the test) removed → `AnchoredRecordPrunedEarly`.
- `u14_anchored_clock_behind_pruned_early`: a `Record` line `{clock_behind: true}` whose first later unflagged retained record has `date(ts_utc)` not older than the covering row's `cutoff_epoch` → `AnchoredRecordPrunedEarly`.
- `null_epoch_lines_accepted`: `Immediate`/`Record` lines with `epoch: null` for NULL-epoch rows verify.
- `startup_compares_anchor_dir`: the U-06 rewrite case is also reported by `open` (startup step 3) as an incident `VERIFY`.

- [ ] **Step 2: Implement** `parse_line` with `serde_json::Value` inspection (no `untagged` enum: explicit key checks give exact errors), `check` per §8.7 using `ctx` = first retained seq, head seq, `prune_log` rows, a seq → (record_hash, event_type, flags, ts) lookup on a read-only connection.

Run: `cargo test -p atlas-duck-audit --test anchor_dir --test verify --test open --locked` → all pass.

- [ ] **Step 3: Clippy, commit** (`feat(audit): anchor-dir line types and verifier checks (writer is M10)`).

---

### Task 15: "Recover this log" and "Archive old DB and start fresh"

**Files:**
- Create: `crates/audit/src/recover.rs`, `crates/audit/tests/recover.rs`
- Modify: `crates/audit/tests/os_keystore.rs` (per-OS U-18 run), `crates/audit/src/lib.rs`

**Interfaces:**
```rust
pub fn recover_this_log(data: &LocalDataDir, lock: &InstanceLock, cfg: OpenConfig, passphrase: &SecretString) -> Result<(Store, RecoverReport), OpenError>;
pub struct RecoverReport { pub verify_seq: u64, pub key_recovered_seq: u64, pub pats_deleted: Vec<String> /* instance ids whose Pat entry was deleted */ }
pub fn archive_and_start_fresh(data: &LocalDataDir, lock: &InstanceLock, confirmed: Confirmed) -> Result<ArchivedDb, OpenError>;   // then the caller runs create_new_store with archived_db
```

**Spec:** §8.7 "Recover this log" steps 1–4 (unwrap KEK from `recovery`; verify from the first retained record against the latest `prune_log` row and the anchor dir; migrations + `SCHEMA_MIGRATED`; `VERIFY {result: anchor_missing}` with `integrity_incident`; `KEY_RECOVERED {what: [kek, head_anchor, first_retained_anchor, pats_lost]}`; re-seal the KEK; rebuild both anchors from the verified DB, no anchor before this step; every instance `needs_token`; `chain_id` unchanged), "Archive old DB and start fresh" (native confirmation, old DB with WAL moved aside within the data dir, never deleted, new `GENESIS` records `archived_db {file, chain_id, head_seq, head_hash}`), §2.5 (never first run on a lost keychain), §13 U-18.

**Plan decisions (spec silent):**
- "Every instance `needs_token`" is realised in M2 by deleting this install's `Pat(<id>)` keychain entries for every instance id in the settings view (ignoring absent ones) and returning the ids; M3 logs `INSTANCE_STATE_CHANGED` for them at `Core::start`.
- If `GENESIS` is no longer retained, the rebuilt first-retained anchor's `genesis_hash` is 32 zero bytes (informational; verification never compares it when `GENESIS` is pruned).
- A wrong passphrase writes nothing (DB and keychain untouched) and returns `WrongPassphrase`.

- [ ] **Step 1: Write the failing tests** (`tests/recover.rs`)
- `u18_wiped_keychain_recover_same_chain`: store with 50 events, two instances in settings, PAT entries for both in MemKeyring; `ring.wipe_install(id)` (deletes everything of the install, PATs included) → `open` = `Locked(KeychainLost { RecoverThisLog })`; `recover_this_log(wrong)` → `WrongPassphrase`, DB bytes unchanged, `ops()` shows no `Set`; `recover_this_log(right)` → same `chain_id`; appended rows in order: (`SCHEMA_MIGRATED` if a test migration is pending), `VERIFY {scope: recover, result: anchor_missing}` with `integrity_incident`, `KEY_RECOVERED {what: [...]}`; keychain holds KEK + both anchors (head = the `KEY_RECOVERED` seq or later); `open_incidents()` contains the `VERIFY`; `pats_deleted` lists both instance ids; restart → `Ready` with no new incident.
- `recover_no_anchor_write_before_rebuild`: MemKeyring `ops()` show the first `Set(HeadAnchor)`/`Set(FirstRetainedAnchor)` only after `Set(Kek)` and after the `KEY_RECOVERED` row exists (observer at `FaultPoint::AfterKeyRecoveredAppend`).
- `recover_detects_tamper`: a tampered row → the recovery `VERIFY` contains `ChainBroken` besides `AnchorMissing`; recovery still completes (the incident is the record).
- `archive_requires_existing_db`: empty dir → `Err(NotFirstRun)`-style error (`Io`/`NotFound`), nothing created.
- `archive_and_start_fresh_keeps_old_db`: locked-lost store → `archive_and_start_fresh(confirmed)` moves `audit.db` (+ `-wal`) to `archived/audit-<chain>-<seq>-<ts>.db`, nothing deleted (old file bytes hash equal to before the move, after a checkpoint the test performs on its own copy), returns `ArchivedDb`; `open` → `FirstRun`; `create_new_store(.., archived_db: Some(a))` → `GENESIS` payload `archived_db` equals `a` (file relative path with `/`, chain id, head seq, head hash hex); the archived file opens with its own recovery passphrase via `restore_from_source(ArchivedDb)` in T16.
- `os_u18_keychain_wiped` (in `tests/os_keystore.rs`, `#[ignore]`): the same flow with `OsKeyStore` on the real keychain (wipe = delete the five entries), proving "per OS" (§13).

- [ ] **Step 2: Implement** `recover_this_log`: gate (`StoreNewer` → `Err(Integrity("store newer"))` mapped by the caller), locality must be `Local` (else `KeyStore(NotLocal)`), `open_recovery`, full verification without keychain anchors (T09 `full` mode with `anchors: None`, plus anchor dir), start writer with anchors disabled, migrations, append `VERIFY` (findings = `AnchorMissing` + any others), append `KEY_RECOVERED`, `keys.set(Kek)`, write both anchors synchronously, enable anchors, delete PATs, return. `archive_and_start_fresh`: read plaintext head (`seq`, `record_hash`, `chain_id`) on a read-only connection, close it, `rename` `audit.db` and `audit.db-wal` (if present) into `archived/`, delete `audit.db-shm`, fsync the data dir (Unix: open the dir and `sync_all`; Windows: skip, NTFS rename is metadata-journaled).

Run: `cargo test -p atlas-duck-audit --test recover --locked` → all pass; `cargo test -p atlas-duck-audit --test os_keystore --locked -- --ignored --test-threads=1 os_u18` on Windows → pass.

- [ ] **Step 3: Clippy, commit** (`feat(audit): Recover this log and archive-and-start-fresh`).

---

### Task 16: Backup bundle, restore-as-continuation, interrupted restore, "Finish restore"

**Files:**
- Create: `crates/audit/src/backup.rs`, `crates/audit/src/restore.rs`, `crates/audit/tests/backup_restore.rs`
- Modify: `crates/audit/src/writer.rs` (`Cmd::Backup`, `Cmd::Restore`, re-initialisation on a new DB), `crates/audit/src/verify.rs` (complete the interrupted-restore action), `crates/audit/src/open.rs`

**Interfaces:**
```rust
impl Store {
    pub fn backup(&self, out: RustChosenPath) -> Result<BackupReceipt, AuditError>;                                     // C.3
    pub fn restore(&self, source: RustChosenPath, passphrase: &SecretString, confirm_rollback: Option<Confirmed>) -> Result<RestoreReport, AuditError>;  // C.3
}
pub struct BackupReceipt { pub bundle_dir: PathBuf, pub head_seq: u64, pub head_hash: [u8; 32], pub manifest_sha256: [u8; 32], pub backup_seq: u64 }
pub struct RestoreReport { pub restore_seq: u64, pub new_chain_id: String, pub source_install_id: String, pub source_chain_id: String,
                           pub replaced_db: Option<ArchivedDb>, pub records_lost: u64, pub pats_lost: bool, pub pats_deleted: Vec<String> }
pub fn restore_from_source(data: &LocalDataDir, lock: &InstanceLock, cfg: OpenConfig, source: RustChosenPath, passphrase: &SecretString,
                           confirm_rollback: Option<Confirmed>) -> Result<(Store, RestoreReport), OpenError>;   // no live Store: new machine (FirstRun) or a locked live DB
pub fn finish_restore(data: &LocalDataDir, lock: &InstanceLock, cfg: OpenConfig, passphrase: &SecretString) -> Result<(Store, VerifyOutcome), OpenError>;  // RecoveryOffer::FinishRestore
```
`RustChosenPath` for restore is either a bundle directory (contains `manifest.json`) or a single DB file (an `archived/` DB); for backup it is the directory in which the bundle directory is created.

**Spec:** §8.10 (full backup = `VACUUM INTO` snapshot + recovery blob + manifest with the snapshot head; logged `BACKUP`; never contains credentials: `vault` rows deleted, `secure_delete`, `VACUUM` again, manifest last), §8.11 steps 1–5 and the segment-boundary rule, §8.7 interrupted restore and "Finish restore", §8.13 (refuse a newer snapshot, migrate an older one only after it verified), L27, L39 (drop `vault` of a crafted snapshot), L40, §13 U-15, U-16, U-22 (restore half), I-46.

**T09 handoff (interrupted-restore predicate):** `verify::startup` reconciles an interrupted restore only while the latest `RESTORE` is the scope start (no `PRUNE`/`RESTORE`/`APP_START` after it, brief step 9). If the completion step fails at startup (keychain down), `open()` still returns `Ready` and M3 appends `APP_START`; the next start would then see the head anchor of the old chain without the predicate firing, a false `AnchorMismatch` incident. T16 must either complete the restore (re-seal + anchor reset) before any `APP_START` can be appended, or widen the predicate to "no record after R other than `VERIFY`/`SCHEMA_MIGRATED`/`APP_START`", keeping the anchor (`prior_keychain_anchor`) and segment-boundary conditions. `Store::apply_startup` already installs `Barrier::Restore` for `complete_restore`; `RestoreCompletion.first_retained.genesis_hash` must be replaced with the backup manifest's value.

**Plan decisions (spec silent):**
- Restore stages the source into `<data>/audit.db.restoring` with `VACUUM INTO` from a read-only connection on the source (works for a bundle snapshot and for an archived DB with its WAL), and does all checks and the `RESTORE` append on the staging file. The "`RESTORE` commit" of §8.7/§8.11 is the atomic rename of the staging file to `audit.db`; before it the live DB is untouched (a crash leaves only a staging file that the next start deletes).
- Order inside the staging transaction: `DROP TABLE IF EXISTS vault` (then, outside the transaction, `PRAGMA secure_delete=ON; VACUUM` so no vault ciphertext survives in free pages), schema migrations of an older snapshot, the new DEK (month of the snapshot head's `epoch`, or `month NULL` when that epoch is NULL), `RESTORE` (chained to the snapshot head; `chain_id` column = `new_chain_id`; `target` = live `install_id`), then `SCHEMA_MIGRATED` if a migration ran. `SCHEMA_MIGRATED` therefore follows `RESTORE` in the chain (so `RESTORE.source_head_*` are the record right before it, as the verifier requires).
- `pats_lost` is always `true` in v1 (stored tokens are never restored); PAT entries of this install are deleted for every instance id in the live and the restored settings views.
- The rollback check compares this install's keychain head anchor with the snapshot head: same `chain_id` and `anchor.seq > snapshot head seq` → `RollbackNeedsConfirmation { records_lost }` unless `confirm_rollback` is given. Any present head anchor is recorded as `prior_keychain_anchor`.
- The "restore backup" security-weakening confirmation (§10.3) is the caller's (M10 UI); `Store::restore` keeps the C.3 signature.
- Backup bundles are written to `<chosen>/atlas-duck-backup-<ts>-<chain8>/`; on any failure the partial bundle directory is removed best-effort (a bundle without `manifest.json` is never valid).

- [ ] **Step 1: Write the failing tests** (`tests/backup_restore.rs`)
- `backup_bundle_contents`: `backup()` → bundle dir with `audit.db`, `recovery.bin` (== the `recovery` row), `manifest.json` (F.11 fields; `head` = store head at backup time; `snapshot_sha256`/`recovery_sha256` match the files); the snapshot has no `vault` table; a `BACKUP` row is appended **after** the snapshot head (not inside the snapshot) with `manifest_sha256` == SHA-256 of `manifest.json` bytes.
- `backup_restore_roundtrip`: store A (two months of events, one prune), backup, restore into a fresh data dir with `restore_from_source` and a new install → `RESTORE` fields per F.11 (`source_install_id` = A, `install_id` = B, `new_chain_id` ≠ A's, `prior_keychain_anchor: null`, `replaced_db: null`, `records_lost: 0`, `pats_lost: true`); every retained payload decrypts; `full_verify()` clean (segment boundary accepted); keychain of B holds A's KEK, anchors with `new_chain_id`; appends continue.
- `i46_backup_has_no_credentials`: MemKeyring holds PATs `PAT-CANARY-<random>` for two instances; backup → the raw bytes of `audit.db`, `recovery.bin`, `manifest.json` contain the canary neither raw, nor standard/URL-safe base64 (with and without padding), nor percent-encoded.
- `i46_crafted_snapshot_with_vault_rows`: take a bundle, add `CREATE TABLE vault(instance_id TEXT, ct BLOB)` with a row whose `ct` contains the canary, fix `snapshot_sha256` in the manifest (an attacker can) → restore succeeds; the restored `audit.db` has no `vault` table and its raw bytes (and `-wal` after checkpoint) do not contain the canary; `RESTORE.pats_lost == true`; `pats_deleted` lists the settings' instances.
- `u16_cross_machine_restore_crash_between_reseal_and_anchor_reset`: machine A store + bundle; machine B (own data dir, own install id, own live chain with 30 events) → `Store::restore` with `FaultPoint::AfterKekReseal` (crash before the anchor reset) → drop; `open` on B → `Ready` (no `keychain_lost`), `VERIFY {result: interrupted_restore_reconciled}` without incident, anchors reset to `new_chain_id`; B's `install_id` kept (`RESTORE.install_id` == B, `cfg.pinned_install_id` unchanged); B's old DB moved to `archived/` and recorded in `replaced_db`; `prior_keychain_anchor` = B's old head anchor.
- `u16_archived_db_restored_same_machine`: archive-and-start-fresh (T15) then restore the archived DB file with its own passphrase and the same crash point → same assertions.
- `finish_restore_after_crash_before_reseal`: `FaultPoint::AfterRestoreCommit` → `open` = `Locked(KeychainLost { offer: FinishRestore })`; `finish_restore(passphrase)` → `Ready`, `VERIFY {interrupted_restore_reconciled}` informational, no incident, KEK re-sealed, anchors reset.
- `u22_restore_keychain_write_failure_retried`: MemKeyring fails `Set(HeadAnchor)` 3× during completion → `health().anchor_write_failing`, no incident; later success; head anchor never written with a pre-`RESTORE` value meanwhile.
- `same_machine_rollback_needs_confirmation`: backup at seq 50, 20 more events, `restore(bundle, pass, None)` → `RollbackNeedsConfirmation { records_lost: ≥ 20 }` and nothing changed (live DB bytes, keychain); with `Some(confirmed)` → restored, `records_lost` recorded.
- `u15_restore_segments_verify`: two successive restores → `full_verify()` accepts both boundaries; rows between them carry the middle `chain_id`; tamper `RESTORE.source_head_hash` (decrypt-free: rewrite `prev_hash` of the `RESTORE` row and rehash) → `RestoreBoundaryMismatch` or `ChainBroken`.
- `restore_refuses_newer_snapshot`: snapshot with `user_version 2` → `SnapshotNewer`, no staging file left, live DB and keychain untouched.
- `restore_migrates_older_snapshot_after_verify`: the v1 fixture DB (T10) as an archived source with a test migration 1→2 → `RESTORE` then `SCHEMA_MIGRATED` (in that seq order); a tampered v1 source → `ChainBroken`, no migration applied anywhere.
- `restore_wrong_passphrase_writes_nothing`.

- [ ] **Step 2: Implement**
Backup on the writer (no append can interleave): head = (seq, hash); `VACUUM INTO '<bundle>/audit.db'` (escape the path as an SQL string literal: double every `'`); open the snapshot read-write, `DROP TABLE IF EXISTS vault; PRAGMA secure_delete=ON; VACUUM;`, close; write `recovery.bin`; hash both; write `manifest.json` via `manifest.json.tmp` + fsync + rename; append `BACKUP`.

Restore (`restore_core`, shared by `Store::restore` and `restore_from_source`), in this order:
```text
 1. stage: VACUUM INTO <data>/audit.db.restoring from the source (bundle: first check snapshot/recovery SHA-256 against the manifest → ManifestMismatch)
 2. versions of the staging file (T04 gate) → SnapshotNewer (delete staging)
 3. verify staging: prune_log chain, first retained vs its latest row, chain to head; bundle: head == manifest head;
    anchor-dir lines for that chain_id if an anchor dir is configured → ChainBroken / AnchorDirMismatch (delete staging)
 4. KEK_s = open_recovery(passphrase, staging recovery row) → WrongPassphrase (delete staging); decrypt the staging head row
 5. rollback check against this install's keychain head anchor (read-only) → RollbackNeedsConfirmation; prior_keychain_anchor
 6. decide replaced_db name (archived/audit-<chain>-<seq>-<ts>.db) from the live DB's plaintext head, if a live DB exists
 7. staging tx: DROP vault; migrations; new DEK; RESTORE; SCHEMA_MIGRATED?; commit; then (outside any transaction) PRAGMA secure_delete=ON; VACUUM;
    PRAGMA wal_checkpoint(TRUNCATE); close the staging connection (removes audit.db.restoring-wal/-shm); assert no -wal file is left; fsync the file
 8. live writer (Store::restore) closes its connection; rename live audit.db(+wal) → replaced_db; delete -shm
 9. rename staging → audit.db; fsync dir                               ← "RESTORE commit"; FaultPoint::AfterRestoreCommit
10. anchor barrier Restore{seq}; keys.set(Kek, KEK_s)                   ← FaultPoint::AfterKekReseal
11. write first-retained {new_chain_id, genesis_hash (manifest, or zero), first_retained_seq, prev} and head {new_chain_id, head}; clear barrier
12. delete Pat(<id>) for every instance id in the live ∪ restored settings views; re-initialise the writer on the new DB (KEK_s, caches, ClockState from the RESTORE row, settings, incidents); return the report
```
`finish_restore`: gate; newest row must be a `RESTORE` with `target == keys.install_id()` (else `Integrity`); `open_recovery` on the live `recovery` row → KEK_s; T09 startup verdict must yield `InterruptedRestoreReconciled`; then steps 10–12 and append `VERIFY {result: interrupted_restore_reconciled}`. In `open`, the verdict's `complete_restore` action performs steps 10–11 (KEK already re-sealed) after the `VERIFY` is appended. In T09 step 8, when the interrupted-restore rule applies, the first-retained comparison is skipped (the keychain still holds the replaced chain's values).

Run: `cargo test -p atlas-duck-audit --test backup_restore --locked` → all pass; full suite `cargo test -p atlas-duck-audit --locked` → all pass.

- [ ] **Step 3: Clippy, commit** (`feat(audit): credential-free backup bundle, restore-as-continuation with interrupted-restore reconciliation and Finish restore`).

---

### Task 17: M3-facing request API: `is_terminal`, `reconcile_after_crash`, header queries

**Files:**
- Create: `crates/audit/src/requests.rs`, `crates/audit/tests/requests.rs`
- Modify: `crates/audit/src/store.rs`, `crates/audit/src/lib.rs`

**Interfaces:**
```rust
pub struct ScriptFailedFlags { pub direct: bool, pub reason: String }
pub fn is_terminal(h: &EventHeader, script_failed: Option<&ScriptFailedFlags>) -> bool;                // C.3, §8.3
impl Store {
    pub fn headers_for_request(&self, request_id: &str) -> Result<Vec<EventHeader>, AuditError>;      // C.3; seq order; no decrypt
    pub fn recent_headers(&self, since: Duration) -> Result<Vec<EventHeader>, AuditError>;            // C.3; `since` capped at 24 h; rows with ts_utc ≥ now − since
    pub fn script_failed_flags(&self, seq: u64) -> Result<ScriptFailedFlags, AuditError>;             // decrypts exactly that row (P6)
    pub fn reconcile_after_crash(&self) -> Result<ReconcileReport, AuditError>;                       // C.3, §11.3; M3 runs it at startup step 5 before APP_START
}
pub struct ReconcileReport { pub outcome_unknown: Vec<ReconciledWrite>, pub abandoned: Vec<String> }
pub struct ReconciledWrite { pub request_id: String, pub op_id: Option<String>, pub instance_id: Option<String>, pub target: Option<String>, pub request_index: u64 }
```

**Spec:** §8.3 (terminal set incl. the `SCRIPT_FAILED` predicate: terminal iff `direct = true` or `reason = audit_failure`), §11.3 (scan request ids with no terminal event; write rule first: latest `WRITE_APPROVED` not followed by `WRITE_STALE`, `WRITE_EDITED` or `WRITE_DENIED` → `WRITE_OUTCOME_UNKNOWN {request_index, reason: crash}`, whatever non-terminal events trail it; then every remaining non-terminal request → `ABANDONED`), P6.

**Plan decisions (spec silent):** reconciliation is implemented in the audit crate because it is a pure function of the log (C.3 already places it on `Store`); M3 owns the startup notice and the I-26 end-to-end tests. All reconciliation records go into one `append_batch`, every `WRITE_OUTCOME_UNKNOWN` before every `ABANDONED`; `request_index` is read from the decrypted `WRITE_APPROVED` payload (`requests[0].index`), defaulting to 0 if the payload has no `requests` (v1 writes are one request).

- [ ] **Step 1: Write the failing tests** (`tests/requests.rs`)
- `terminal_table`: every `EventType` against the §8.3 list (write the expected set literally); `SCRIPT_FAILED` with `{direct: true}` → terminal; `{direct: false, reason: "audit_failure"}` → terminal; `{direct: false, reason: "killed_by_user"}`, `"app_quit"`, `"cancelled_by_client"` → not terminal; `SCRIPT_FAILED` without flags → `false` (callers must decrypt).
- `reconcile_write_trailing_events`: request with `REQUEST_RECEIVED`, `PREVIEW_SHOWN`, `WRITE_APPROVED {requests:[{index:0,…}]}`, `PREVIEW_FETCH {stale_check}`, `DECISION_STALE`, `DELIVERED` → `WRITE_OUTCOME_UNKNOWN {request_index: 0, reason: crash}` with `op_id`/`instance_id`/`target` copied.
- `reconcile_write_stale_then_refresh_is_abandoned`: `WRITE_APPROVED`, `WRITE_STALE`, `PREVIEW_FETCH {refresh}` → `ABANDONED`.
- `reconcile_reads_and_scripts`: pending read (`REQUEST_RECEIVED`, `READ_FETCHED`) → `ABANDONED`; script with non-direct `SCRIPT_FAILED {killed_by_user}` → `ABANDONED`; script with `SCRIPT_FAILED {app_quit}` + `CANCELLED` → untouched.
- `reconcile_leaves_terminal_requests`: released, denied, expired, executed requests untouched.
- `reconcile_order_and_idempotence`: all `WRITE_OUTCOME_UNKNOWN` seqs < all `ABANDONED` seqs; a second call returns an empty report and appends nothing.
- `headers_are_plaintext_only`: `headers_for_request` returns the plaintext columns in seq order and never calls the decrypt path (assert via a `testing` decrypt counter).
- `recent_headers_window`: rows 30 h, 23 h and 1 h old → `recent_headers(24 h)` returns the last two; `recent_headers(48 h)` is capped to 24 h.

- [ ] **Step 2: Implement**; `reconcile_after_crash` reads `request_id`, `seq`, `event_type` of all retained rows with a request id (one indexed scan), groups them, decrypts only `SCRIPT_FAILED` rows and the relevant `WRITE_APPROVED` rows.

Run: `cargo test -p atlas-duck-audit --test requests --locked` → all pass.

- [ ] **Step 3: Clippy, commit** (`feat(audit): terminal predicate, §11.3 crash reconciliation, header queries for core`).

---

### Task 18: CI keychain legs, Linux Secret Service, shared-keyring phases, verify-items record, exit criterion

**Files:**
- Create: `ci/keyring-ci.sh`, `ci/shared-keyring.sh`, `crates/audit/tests/shared_keyring.rs`, `docs/m2/verify-items.md`
- Modify: `.github/workflows/ci.yml`, `.gitlab-ci.yml`

**Interfaces:** CI only; `tests/shared_keyring.rs` tests are all `#[ignore]` and read `ATLAS_DUCK_SHARED_STATE` (a directory shared between phases).

**Spec:** §13 CI row and the Integration clauses "Shared home" (I-43) and "Concurrent shared keyring" (I-44), §8.6 keyring locality, L39 (Linux needs a Secret Service; "CI already runs a file-backed Secret Service"), §15 V08, V22, V27, V29, master-plan M2 exit criterion.

**Plan decisions (spec silent):**
- **Linux Secret Service in CI:** GNOME Keyring on a private session bus: `dbus-run-session -- bash -c 'printf "<pw>" | gnome-keyring-daemon --components=secrets --daemonize --unlock; cargo test …'`. `--unlock` creates and unlocks the `login` collection as the default collection, file-backed in `$XDG_DATA_HOME/keyrings/login.keyring` (the same pattern the upstream `zbus-secret-service-keyring-store` CI uses, with `dbus-run-session` added so no host session bus is assumed). This is the "file-backed Secret Service" of §13; no in-process fake is used for the OS tests.
- **Containers:** every container job (GitLab `rust:1.95`) sets `TMPDIR` and `XDG_DATA_HOME` under `$CI_PROJECT_DIR` before any test, because the container's overlayfs `/tmp` and `$HOME` fail the locality checks closed (M1 finding, `.gitlab-ci.yml` comment); otherwise the keychain tests would see `keyring_not_local` where they expect `Ready`.
- **macOS:** the GitHub runner's login keychain is used as is (the upstream `apple-native-keyring-store` CI runs its keychain tests on `macos-latest` without setup). If the first CI run fails with an interaction/locked error, add this pre-step and record it under V08: `security create-keychain -p ci atlas-ci.keychain-db && security set-keychain-settings atlas-ci.keychain-db && security unlock-keychain -p ci atlas-ci.keychain-db && security list-keychains -d user -s atlas-ci.keychain-db $(security list-keychains -d user | tr -d '"') && security default-keychain -d user -s atlas-ci.keychain-db` (and point the locality dir check at `~/Library/Keychains`, where it lives).
- **I-44 NFS case:** no daemon is needed: `OsKeyStore` refuses on the path check before any D-Bus call. The test asserts that the NFS keyrings dir is byte- and mtime-identical before and after.

- [ ] **Step 1: `tests/shared_keyring.rs`** (all `#[ignore]`, Linux only, `OsKeyStore`)
- `i43_shared_home_sequential`: one shared config dir (simulated home), two data dirs, hostnames `host-a`/`host-b` → pinned files `paths-host-a.toml`/`paths-host-b.toml` via `ipc::paths::write_pinned` with each install's `install_id`; first run A, first run B, restart A, restart B (each `open` → `Ready`, no incident, no `keychain_lost`); each install's keychain entries exist only under its own `install_id`; a `Pat("inst-1")` set by A is absent for B; each pinned file names only its own install.
- `i44_concurrent_phase1`: two stores open at the same time in two threads, 200 interleaved appends each with `flush_head_anchor` every 10, a `Pat` set by each; shut down; write both install ids and data dir paths into `$ATLAS_DUCK_SHARED_STATE/state.json`.
- `i44_concurrent_phase2` (after the script restarts the daemon): reopen both → `Ready`, no `VERIFY` incident, no `keychain_lost`, both PATs present.
- `i44_keyring_on_nfs_refused` (needs `ATLAS_DUCK_TEST_NFS_DIR`; `XDG_DATA_HOME` = `<nfs>/xdg`, created by the script with a sentinel file in `<nfs>/xdg/keyrings`): `OsKeyStore::new(id).locality()` = `NotLocal`; `create_new_store` → `KeyStore(NotLocal)`; `open` of a store created earlier in phase 1 (pinned to a local data dir) → `Locked(KeyringNotLocal)`; the NFS `keyrings` dir listing, sizes and mtimes are unchanged.

- [ ] **Step 2: `ci/keyring-ci.sh`** (Linux)
```bash
#!/usr/bin/env bash
# Linux OS-keychain tests against a file-backed Secret Service (GNOME Keyring) on a private
# session bus (§13, L39, V08). Extra args are passed to the test binary (e.g. a name filter).
set -euo pipefail
command -v gnome-keyring-daemon >/dev/null || { echo "keyring-ci: gnome-keyring-daemon missing" >&2; exit 2; }
command -v dbus-run-session >/dev/null || { echo "keyring-ci: dbus-run-session missing" >&2; exit 2; }
export XDG_DATA_HOME="${XDG_DATA_HOME:-$PWD/.ci-xdg}"   # never an overlayfs home: the locality check fails closed there
mkdir -p "$XDG_DATA_HOME"
exec dbus-run-session -- bash -euo pipefail -c '
  printf "atlas-duck-ci" | gnome-keyring-daemon --components=secrets --daemonize --unlock >/dev/null
  echo "keyring-ci: keyring files: $(ls "$XDG_DATA_HOME/keyrings" 2>/dev/null | tr "\n" " ")"
  cargo test -p atlas-duck-audit --test os_keystore --locked -- --ignored --test-threads=1 "$@"
  echo "keyring-ci: keyring files after: $(ls -l "$XDG_DATA_HOME/keyrings")"
' keyring-ci "$@"
```
`ci/shared-keyring.sh` (Linux, run in the `locality-mounts` job after the NFS mount step): phase A (`i43_shared_home_sequential`) and phase B1 (`i44_concurrent_phase1`) inside one `dbus-run-session` with one daemon; then `pkill -u "$(id -u)" -x gnome-keyring-d || true` (exact process name; `-f` would also match wrapper shells whose command line contains the string; Linux truncates `comm` to 15 characters, hence `gnome-keyring-d`), wait until `pgrep -u "$(id -u)" -x gnome-keyring-d` finds nothing, start a new daemon in a **second** `dbus-run-session` (same `XDG_DATA_HOME`) and run B2 (`i44_concurrent_phase2`); then C (`i44_keyring_on_nfs_refused`) with `XDG_DATA_HOME="$ATLAS_DUCK_TEST_NFS_DIR/../xdg"` and no daemon. Each phase prints `shared-keyring: <phase> ok`; any failure exits non-zero.

- [ ] **Step 3: Workflows**
- `ci.yml` `rust` job: Linux system packages step adds `gnome-keyring libsecret-tools`; new steps after "Test":
  - `Audit OS keychain tests (Windows Credential Manager, RF-3a)` (`if: runner.os == 'Windows'`): `cargo test -p atlas-duck-audit --test os_keystore --locked -- --ignored --test-threads=1`
  - `Audit OS keychain tests (macOS login keychain)` (`if: runner.os == 'macOS'`): same command.
  - `Audit OS keychain tests (Linux, file-backed Secret Service)` (`if: runner.os == 'Linux'`): `bash ci/keyring-ci.sh`
- `rust-macos-x86_64-rosetta` job: `cargo test -p atlas-duck-audit --test os_keystore --locked --target x86_64-apple-darwin -- --ignored --test-threads=1`.
- `locality-mounts` job (Linux): packages add `gnome-keyring libsecret-tools`; after "Locality tests against the mounts": `name: Shared keyring I-43/I-44 (§8.6)`, `run: ATLAS_DUCK_SHARED_STATE="$RUNNER_TEMP/shared" bash ci/shared-keyring.sh`. Also run `cargo test -p atlas-duck-audit --test keystore --locked -- locality_nfs_from_env` there (the NFS env var is set).
- `.gitlab-ci.yml`: new job `rust:audit-keychain` (stage `check`, no UI artifact needed): `apt-get install -y --no-install-recommends gnome-keyring dbus libsecret-tools`; `export TMPDIR="$CI_PROJECT_DIR/.tmp" XDG_DATA_HOME="$CI_PROJECT_DIR/.xdg"; mkdir -p "$TMPDIR" "$XDG_DATA_HOME"`; `bash ci/keyring-ci.sh`. The existing `rust:test` job already sets `TMPDIR`; add `export XDG_DATA_HOME="$CI_PROJECT_DIR/.xdg"` there too.

- [ ] **Step 4: `docs/m2/verify-items.md`**: one section each, filled from the CI logs of the pushed branch (cite job names and run URLs):
  - **V08** — store crates and pins (table above); Windows: target names and `Persist` values printed by `rf3a_*` (whether an update of an Enterprise entry kept Enterprise, and which `set` path is used); macOS: whether the runner's login keychain worked without setup; Linux: the Secret Service attribute names printed by `os_secret_service_attributes`.
  - **V22** — `v22_user_version_rolls_back` result: `PRAGMA user_version` inside a WAL transaction rolls back with it.
  - **V27** — clock sources per OS as implemented; CI proves monotonicity only; sleep/hibernate behaviour is not testable on hosted runners: manual check procedure (note `suspend_aware_elapsed` and wall time, sleep the machine 5 min, compare) to run once per OS before release, listed as open.
  - **V29 (keyring half)** — the keyring dirs checked per OS and the NFS refusal evidence from `shared-keyring: C ok`.

- [ ] **Step 5: Exit-criterion run.** Push the branch; all of these must be green on one commit, and the run URLs go into `docs/m2/verify-items.md` and the commit message:

| Command / job | Where | Covers |
|---|---|---|
| `cargo test -p atlas-duck-audit --locked` (inside `cargo test --workspace --locked`) | `rust` Windows, macOS arm64, Ubuntu 22.04; Rosetta job; GitLab `rust:test` | U-06…U-22, X-01…X-03, RF-1a, RF-1b, golden vectors |
| `cargo test -p atlas-duck-audit --test os_keystore --locked -- --ignored --test-threads=1` | `rust` Windows (Credential Manager), macOS (login keychain), Rosetta; Linux via `ci/keyring-ci.sh` (GitHub + GitLab `rust:audit-keychain`) | RF-3a, U-18 per OS, V08 |
| `ATLAS_DUCK_SHARED_STATE=… bash ci/shared-keyring.sh` | `locality-mounts` Linux | I-43 (keyring half), I-44 |
| `node ci/check-audit-vectors.mjs` | `rust` jobs, GitLab `node:ci-checks` | U-07 independent check |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | every `rust` leg | lint gate |
| `cargo deny --locked check`, `cargo audit` | `supply-chain` | licenses/advisories of the new pins |
| `node ci/check-workspace.mjs`, `node --test "ci/*.test.mjs"` | `rust` jobs | §2.2 rule, CI scripts |

- [ ] **Step 6: Commit** (`ci(audit): per-OS keychain tests, file-backed Secret Service, shared-keyring I-43/I-44 phases; M2 verify items`). Then hand the branch to the lead for the M2 review (do not push to the default branch or tag anything).

---

## Handoff to later milestones (what M2 leaves for M3/M4/M6/M10)

- **M3 (`Core::start`)**: call `store.reconcile_config_file(&file_policy)` first (prune stays blocked until then), then `reconcile_after_crash()`, then append `APP_START` (payload per §8.3, `target` = `store.install_id()`); feed every successful, parsed, TLS-verified Atlassian response's `Date` into `observe_server_date`; put `store.query_tag(..)` in `NewEvent.target` for `jira.search`/`confluence.search`; after a restore or recovery, log `INSTANCE_STATE_CHANGED {needs_token}` for `RestoreReport.pats_deleted`/`RecoverReport.pats_deleted`; build `Confirmed` only from `NativeConfirmer::confirm == Ok`; payload integers stay within ±(2^53 − 1) (`ipc::jcs`); `WRITE_APPROVED.requests` uses the F.8 JSON shape; `params_sha256` uses `ipc::jcs::to_jcs_vec`.
- **M4**: the app's startup loop retries `open` on `Locked(KeychainUnavailable)` with `keychain_retry_schedule()`; `LockedReason::as_str()` gives the `details.reason`; `doctor` `keyring_local` uses `OsKeyStore::new(id).locality()`.
- **M6**: wizard (1a) uses `read_store_install_id`; (1b) `new_ids()` → passphrase → `create_new_store`; credential window purposes from `RecoveryOffer`; Settings/tray read `Store::health()` (anchor failures, prune backlog) and offer "Prune backlog now" → `prune(Some(confirmed))`; `verify_now` → `try_full_verify()` (T09): its `Err` (store closed, keychain not answering, DB unreadable) is shown as "verification did not complete", never as a pass; the C.3 `full_verify()` `Vec` API has no error channel and reports the same non-completion as a `ChainBroken` finding whose `detail` starts "verification did not complete".
- **M10**: anchor-dir writer uses `anchor_dir::to_line`/`file_name`; export and `verify_export` reuse `encoding`, `request_set_hash`, `prune_row_hash`, `anchor_dir::check`; grep check that only native-dialog code constructs `RustChosenPath`/`Confirmed`.

---

## Plan decisions needing the user's eye (spec silent)

1. **Keychain mapping** (T05): keyring-core `(service, user)` = `(atlas-duck/<install_id>, kek|head_anchor|…)`; Windows target name forced to `atlas-duck/<install_id>/<account>` and `persistence=Local` on every write, verified by `CredReadW` after each write (fail closed).
2. **No `keyring` umbrella crate**: `keyring-core 1.0.0` + `windows-native-keyring-store 1.1.0`, `apple-native-keyring-store 1.0.2` (`keychain`, the legacy login keychain), `zbus-secret-service-keyring-store 1.0.1` (`crypto-rust`). The master plan's "keyring 4.2.0" pin is dropped.
3. **Formats frozen by M2** (F.1–F.11): u64 BE for every INTEGER column, NULL frame `00 00000000`, flag bit order, domain strings, ids as 32 hex chars, `requests` JSON shape, prune-log row hash chain (added columns `prune_seq`, `prev_row_hash`, `row_hash`; `range` stored as `range_start` + `first_retained_seq`), a plaintext `meta.written_by` for the "written by vX" message.
4. **Settings survive prune** by embedding a settings snapshot in every `PRUNE` payload (P5 made concrete).
5. **Empty-range prunes** are logged so the L37 baseline can keep moving across days without records.
6. **Restore staging and order**: staging file + atomic rename as the "`RESTORE` commit"; `SCHEMA_MIGRATED` after `RESTORE`; PAT entries of this install deleted on restore and recovery; restore accepts an archived DB file as well as a bundle.
7. **CI keychains**: GNOME Keyring under `dbus-run-session` (GitHub and GitLab), `XDG_DATA_HOME`/`TMPDIR` on the project volume in containers, the macOS runner keychain as is (fallback temp keychain documented).
8. **JCS in `ipc`** and integers limited to ±(2^53 − 1) in payloads.
9. **U-19 scope at M2**: only schema v1 exists, so "every released schema" = the committed v1 fixture plus a test-only 1→2 migration that exercises the runner.
10. **No `clock_behind` on `GENESIS`** (§8.8 as amended by L47): `ClockState::stamp` has no genesis special case; the old rule (c) is the only pre-corroboration rule.

## Spec defects found while planning (for spec + ledger, not fixed here)

1. (Resolved by L47: §8.8 `clock_behind` no longer flags a `GENESIS` written before any corroboration; decision 10 follows the amended text.)
2. §8.8/L37 baseline: the baseline moves only with a `prune_log` row, and the spec does not say whether a run that deletes nothing writes `PRUNE`; if it does not, the clamp freezes after any stretch without records. This plan logs empty-range prunes (decision 5); the spec should say so.
3. §8.13 UI text "audit data was written by atlas-duck vX" has no plaintext source for `vX` before the KEK (all app versions are in encrypted payloads); the plan adds `meta.written_by`.
4. §8.11 step 1 says an older snapshot is migrated "before the anchors are reset", and the verifier requires `RESTORE.source_head_*` to be the record right before `RESTORE`; a `SCHEMA_MIGRATED` appended before `RESTORE` would break that. The spec should state that `SCHEMA_MIGRATED` follows `RESTORE`.
5. §13 U-06 requires that *altering* any `prune_log` row fails verification, but old `PRUNE` records are themselves pruned and `prune_log` has no integrity field; the spec should name the mechanism (this plan chains the rows, F.9).
6. §8.7 full verification "no `PRUNE` cutoff lies inside `today − retention_days`" read literally flags every old prune after a retention increase; the plan judges each prune by the retention in force at that prune.
7. §8.6 "every instance is set to `needs_token`" after restore/recovery is not achievable by the audit store alone on the same machine (the live install's PAT entries keep their names); the spec should say that restore and recovery delete this install's PAT entries.
8. §8.10/§10.3: "restore backup" is security-weakening, but C.3 `Store::restore` has only `confirm_rollback`; the general confirmation is left to the caller (M10).
9. §8.8 "values below 92 are raised to 92" plus "lowering retention never takes effect from a file edit": the spec does not say whether a file value *above* the current retention takes effect; the plan applies raises and logs lowerings as `applied: false`.

---

## Traceability (self-check against the M2 exit criterion)

| Exit-criterion item (master plan M2) | Spec | Task | Test(s) |
|---|---|---|---|
| U-06 tamper tests (except anchor-dir writer clauses) | §8.4, §8.5, §8.7 | T09, T14 | `tamper_*` (1–13), `u06_anchored_record_rewritten`, `u06_anchored_seq_beyond_head`, `u06_anchored_record_pruned_inside_retention` |
| U-07 canonical-encoding golden vectors | §8.4 | T01, T02, T03 | `jcs_*`, `canonical_layout_minimal_row`, `golden_vectors_match`, `node ci/check-audit-vectors.mjs` |
| U-08 crypto round-trips | §8.4, §8.6 | T03 | `payload_round_trip`, `aad_binding`, `dek_wrap_round_trip_and_binding`, `recovery_*` |
| U-09 prune keeps verifiability | §8.5, §8.8 | T11 | `prune_daily_keeps_verifiability` |
| U-10 clock jumps never over-prune | §8.8 | T11, T13 | `u10_forward_jump_never_over_prunes`, `u10_backward_jump_never_over_prunes` |
| U-11 corroborated epoch, 5-year jump | §8.2, §8.8 | T06, T13 | `first_corroboration_sets_min_today_corroborated`, `u11_*` |
| U-12 records before first corroboration after a 30-day gap | §8.6, §8.8 | T11, T13 | `crypto_shredding_reference_checked`, `u12_*` |
| U-13 suspend 14 / 2.5 days | §8.8 | T06, T13 | `mono_undercount_holds_epoch_back`, `u13_*` |
| U-14 backward clock 60 / 10 days, first-run + mid-life, anchored `clock_behind` flagged | §8.8, §8.7 | T06, T13, T14 | `backward_clock_sets_behind_once`, `u14_*`, `u14_anchored_clock_behind_pruned_early` |
| U-15 restore segments (fork report is M10) | §8.11 | T16 | `u15_restore_segments_verify` |
| U-16 cross-machine restore, archived DB, crash between re-seal and reset, Finish restore, install_id kept | §8.6, §8.7, §8.11 | T16 | `u16_*`, `finish_restore_after_crash_before_reseal`, `install_id_cross_check` (T10) |
| U-17 anchor rules after crash, incident persistence | §8.5, §8.7 | T08, T09 | `unanchored_tail_is_informational`, `incident_persists_until_ack`, `head_anchor_stops_at_unfinished_prune` |
| U-18 keychain wiped → `keychain_lost`, Recover, Archive (per OS) | §2.5, §8.7 | T10, T15 | `u18_keychain_wiped_is_lost_not_first_run`, `u18_wiped_keychain_recover_same_chain`, `archive_and_start_fresh_keeps_old_db`, `os_u18_keychain_wiped` |
| U-19 schema fixtures migrate to head; newer refused byte-identical; restore refuses newer / migrates older after verify | §8.13 | T04, T10, T16 | `v22_user_version_rolls_back`, `u19_v1_fixture_migrates_to_head`, `u21_store_newer_is_byte_identical`, `restore_refuses_newer_snapshot`, `restore_migrates_older_snapshot_after_verify` |
| U-20 upgrade starts: keychain unavailable → retries, `locked`, migrates when ready; `keychain_lost` → Recover migrates after verify; truncated DB → incident before any anchor change | §8.7, §8.13 | T10, T15 | `u20_keychain_unavailable_then_ready`, `retry_schedule_window`, `startup_order_migration_then_verify`, `u18_wiped_keychain_recover_same_chain` |
| U-21 (store half) newer `user_version` → `store_newer` | §8.13 | T10 | `u21_store_newer_is_byte_identical` |
| U-22 interrupted prune/restore incl. keychain-write failure; forged prune / two prunes behind → incident | §8.7, §8.8, §8.11 | T09, T11, T16 | `u22_*` |
| X-01 retention < 92 raised, `CONFIG_CHANGED {source: file}` before any prune | §8.8 | T12 | `x01_*` |
| X-02 legal hold pauses prune and shredding; lifting needs confirmation (store half) | §8.8, §10.3 | T11, T12 | `legal_hold_pauses_prune_and_shredding`, `x02_lift_legal_hold_needs_confirmation` |
| X-03 (store half) low-space admission, system events continue | §8.1 | T07 | `admission_storage_low` |
| RF-1a first-run forward clock | L36, §8.2, §8.6 | T13 | `rf1a_first_run_forward_clock` |
| RF-1b prune after long gap, no baseline | L37, §8.8 | T11, T13 | `clamp_after_gap_no_dialog`, `first_prune_baseline_is_genesis_effective_epoch`, `rf1b_prune_after_long_gap_no_baseline` |
| RF-3a keyring persist local (Windows) | §7.1, §8.6 | T05, T18 | `rf3a_keyring_persist_local`, `rf3a_existing_enterprise_entry_rewritten_local` |
| I-43 shared home (keyring half) | §7.7, §8.6 | T05, T18 | `os_two_installs_isolated`, `i43_shared_home_sequential` |
| I-44 keyring locality, refused NFS mount, shared local keyring | §8.6 | T05, T18 | `locality_nfs_from_env`, `keyring_not_local_reads_nothing`, `i44_concurrent_phase1/2`, `i44_keyring_on_nfs_refused` |
| I-46 credential-free backups (keychain mode + crafted `vault` snapshot) | §8.10, §8.11, L39 | T16 | `i46_backup_has_no_credentials`, `i46_crafted_snapshot_with_vault_rows` |
| `backup_restore_roundtrip` | §8.10, §8.11 | T16 | `backup_restore_roundtrip` |
| Per-OS keychain tests (Windows `Persist == CRED_PERSIST_LOCAL_MACHINE`, macOS Keychain, Linux file-backed Secret Service) | §8.6, §13 | T05, T18 | `tests/os_keystore.rs` on the three legs + Rosetta |
| Golden vector file committed | §8.4 | T02, T03 | `tests/vectors/format_v1.json` + `ci/check-audit-vectors.mjs` |
| §15 V08, V22, V27, V29 (keyring half) | §15 | T05, T04, T06, T18 | `docs/m2/verify-items.md` |
| L38 keyed query tag | §8.2 | T03, T07 | `query_tag_rules`, `query_tag_matches_crypto` |
| §11.3 reconciliation primitive (M3 consumes) | §8.3, §11.3 | T17 | `reconcile_*`, `terminal_table` |
