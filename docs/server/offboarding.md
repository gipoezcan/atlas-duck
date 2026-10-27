# Offboarding

SM-6.5: a user who is disabled or gone from the directory loses all PATs and API keys at once.
Their audit chain stays for auditors for the retention period and is then deleted, recorded in
the anchor chain.

## What deactivation does

`admin users deactivate <username>`, and the daily check below, both run the same code
(`admin::users::deactivate`):

1. The user is marked deactivated (`deactivated_at`, `deactivated_by`: `admin` or
   `offboarding`). From now on every login is refused with `auth/not_permitted`, whatever the
   directory says.
2. Every session ends, in memory and in the store. Open browser tabs fall back to the login page.
3. Every API key is revoked, and the key cache is evicted. Each revocation is recorded in the
   user's chain as `API_KEY_REVOKED {by: deactivation}`.
4. Every PAT is deleted, each after a `CREDENTIAL_CHANGED {reason: user_deactivated}` record.
5. The chain's final head is anchored as `USER_DEACTIVATED` (a leaf, no name in clear).

Deactivation is final: an account that shows up in the directory again stays refused. Running
it twice changes nothing the second time.

## Two configurations (PD-M13-14)

Which one applies depends on Q6, the approval of a read-only directory service account.

### Without a service account (manual)

The server cannot read a user's account state without that user's password. It refuses a
disabled or missing account at its next **login**, but until then the user's API keys still
work. So deactivation is an operator duty:

- On every HR leaver notice, run `admin users deactivate <username>` on the leaving day.
- Weekly, compare `admin users list` with the directory and deactivate what is left.

`/readyz` reports `offboarding: "manual"`, and `atlas_duck_offboarding_enabled` is 0.

### With a read-only service account (daily check)

1. Have the directory team create an account that may only read user entries
   (`userPrincipalName`, `userAccountControl`) under `LDAP_BASE_DN`. It needs no group
   membership and no write rights.
2. Create its password Secret (item `password`):

   ```sh
   kubectl --context team-dux@gip -n team-dux create secret generic atlas-duck-ldap-bind \
     --from-file=password=/media/offline/bind-password
   ```

3. Set `directory.serviceBind.dn` and `directory.serviceBind.existingSecret: atlas-duck-ldap-bind`
   in the production values, then deploy. The password is a mounted file
   (`ATLAS_DUCK_LDAP_SERVICE_BIND_PASSWORD_FILE`), never an env value, and never logged.

Every day at `ATLAS_DUCK_OFFBOARDING_AT` (UTC, default `02:00`) the server binds as that account,
looks up every active user by UPN, and deactivates those whose account is disabled or gone. Then:

- **A failed or doubtful lookup** (unreachable directory, failed bind, missing
  `userAccountControl`) never deactivates anyone. If any lookup in a run fails, that run
  deactivates nobody at all, counts as failed, and is retried an hour later.
- **Gone needs two runs.** An empty search is not proof: a lost read right on an OU or a wrong
  base DN looks the same. A user the directory does not find is deactivated only when a run at
  least 20 h earlier did not find them either. A disabled account is deactivated at once.
- **Implausibly many leavers.** If one run would deactivate more than `max(3, answered / 4)`
  users,
  it deactivates nobody (`offboarding_implausible` in the log). A permission change on the
  service account must not offboard everyone overnight. Investigate, then deactivate by hand if
  it is real.
- `/readyz` reports `offboarding: "directory"`, and `atlas_duck_offboarding_enabled` is 1. Watch
  `atlas_duck_scheduler_last_success_seconds{job="offboarding"}`.

Rotating the bind password:

1. The directory team sets a new password.
2. Replace the Secret (`--dry-run=client -o yaml | kubectl apply -f -`).
3. Run `kubectl rollout restart deploy/atlas-duck`. The password is read at start.

Review environments use the test directory's file as the lookup (`offboarding: "stub"`): mark a
test user `disabled` in the ConfigMap, and the next daily run (or a restart past the slot)
deactivates them.

## Retention and auditor access

- A deactivated user's chain stays readable for auditors for `ATLAS_DUCK_RETENTION_DAYS` (default
  365) after deactivation (`retention_until`).
- After that, the daily retention sweep (or `admin retention run`) does all of the following:
  - deletes the user's store;
  - purges the user's remaining server rows;
  - wipes the wrapped data key;
  - records `CHAIN_DELETED {user_id, chain_id, head_seq}` and `RETENTION_RUN` in the anchor
    chain.
- The user's row stays as a tombstone (`users list` shows `deleted`), so the account stays
  refused.
- `admin retention run --dry-run` lists what is due without deleting anything.

An auditor who needs a chain longer than the period must export it before `retention_until`.

Backups are not touched by retention: a bundle taken before a chain was deleted still contains
it. Keep off-cluster backups only as long as the backup policy needs them, and remove kept
bundles on the volume with `admin backups remove` ([backup-restore.md](backup-restore.md)).
