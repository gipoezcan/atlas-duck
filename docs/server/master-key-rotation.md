# Rotating the master key

The master key wraps every user's data key (SM-6.2, ADR 0002). Rotating it re-wraps every data
key under a new master key. The users' stores and their audit chains stay as they are: their
data keys do not change.

**What rotation does not do (final review I5).** Rotation protects against someone who holds the
old key but not yet the data. Anyone who once had the old key **and** `server.db` (the volume,
a backup, a kept bundle) can unwrap every data key, and those keys stay valid for every PAT
sealed now and later. After a suspected exposure of the key together with data, rotation alone
is not enough:

1. rotate the master key (below);
2. tell every user to replace their Jira/Confluence PATs (revoke the old token at Atlassian, store
   the new one on **Credentials**) and to revoke and recreate their API keys. Admins announce it
   through the usual staff channel with the date of the suspected exposure; `admin users list`
   gives the accounts to follow up;
3. remove or re-take kept bundles (`admin backups list`/`remove`) and treat off-cluster copies
   taken before the rotation as exposed.

Re-sealing data with new data keys is not implemented (follow-up work).

## When

- The key may have been exposed: a Secret read by someone who should not have, a lost medium,
  a leaked log.
- Someone who held the key or could read Secrets in `team-dux` leaves.
- Otherwise yearly.

## Before you start

- Take a backup and copy it off the cluster ([backup-restore.md](backup-restore.md)). It is
  wrapped under the **old** key, so keep the old key's escrow until you no longer need backups
  made before the rotation.
- Create the new key offline exactly like the first one ([deployment.md](deployment.md)), with a
  **new key id**, for example `prod-2027-11`. The rotation refuses the same id
  (`rotate/same_key`) and the same bytes under another id.

## Steps

```sh
NS="--context team-dux@gip -n team-dux"
A="kubectl $NS exec deploy/atlas-duck -- /app/atlas-duck-server admin"
```

1. Create the next-key Secret (item `key`):

   ```sh
   kubectl $NS create secret generic atlas-duck-master-key-next --from-file=key=/media/offline/new-key
   ```

2. Set `masterKey.nextSecret: atlas-duck-master-key-next` in `deployment/values-production.yaml`
   and deploy. The pod restarts with both keys:
   - the old one as `ATLAS_DUCK_MASTER_KEY_FILE`;
   - the new one as `ATLAS_DUCK_MASTER_KEY_NEXT_FILE`, accepted for unwrapping only.
3. Rotate:

   ```sh
   $A rotate-master-key --new-key-file /run/secrets/atlas-duck/master-key-next/key
   # {"old_key_id":"prod-2026-11","new_key_id":"prod-2027-11","rewrapped":N,"already_rewrapped":0}
   ```

   The file must be the mounted next key; any other is refused
   (`rotate/next_key_not_mounted`), so a restart can never find rows under a key nobody mounts.
   The new key becomes the primary first, so first logins during the run already go under it.
   Every row is then re-wrapped in its own step (compare-and-set), pass after pass, until none is
   left under the old key, and `MASTER_KEY_ROTATED {old_key_id, new_key_id}` goes into the anchor
   chain. The output shows key ids and counts only, ending with `rows_not_primary: 0`. A restart
   while the next key is mounted and already in use keeps it as the primary.
4. Check before the swap: `$A master-key status` must show `rows_not_primary: 0`. If not, run
   step 3 again.
5. Swap the production Secret to the new key, then remove the next one:

   ```sh
   kubectl $NS create secret generic atlas-duck-master-key --from-file=key=/media/offline/new-key \
     --dry-run=client -o yaml \
     | kubectl $NS apply --server-side --force-conflicts --field-manager=atlas-duck-ops \
       --validate=false -f -
   ```

   The apply runs server-side: a client-side `kubectl apply` fetches the cluster's `/openapi/v2`,
   which this cluster answers 503. `--validate=false` skips the same schema fetch. The API server
   still validates the Secret.

   Set `masterKey.nextSecret: ""`, deploy, then
   `kubectl $NS delete secret atlas-duck-master-key-next`.
6. Verify:
   - `/readyz` is 200, with no `master_key_mismatch`;
   - `atlas_duck_master_key_info` shows only the new id, as `primary`;
   - a user can sign in and an existing API key works;
   - `$A anchor verify` exits 0.
7. Destroy every copy of the old key except the sealed escrow kept for old backups. Record the
   date and the new key id in the key log.

## If something goes wrong

- **The rotation stopped part-way** (the pod died, or `rotate/unwrap_failed`). Some rows carry the
  new id, the rest the old one. Leave `masterKey.nextSecret` set: with both keys loaded the
  restarted server opens every user. Run step 3 again; it re-wraps only the rows still under the
  old key (`already_rewrapped` counts the others).
- **`/readyz` says `master_key_mismatch` after step 4.** The pod runs a key that does not open
  some data keys. Usually the Secret was not swapped, or the old key was mounted again after the
  rotation finished. Mount the key whose id the users' data keys carry (the new one, from the
  offline medium) as `atlas-duck-master-key`. After step 5 the `-next` Secret is gone, and the old
  key lives only in escrow.
- **`rotate/concurrent_change`.** A row changed during the run. Run it again.
- **A restore of a pre-rotation backup** needs the old key loaded, not necessarily as the
  primary. The restore accepts a bundle when every key id its manifest lists is loaded and every
  data key opens (`restore/unknown_master_key` otherwise). The procedure:
  1. Mount the old key from escrow as the next key: create a Secret (for example
     `atlas-duck-master-key-old`, item `key`), set `masterKey.nextSecret` to it, and deploy. The new
     key stays `atlas-duck-master-key`.
  2. `admin maintenance on`, restore the bundle, `admin anchor verify`.
  3. The restored rows are under the old key. To move them to the new key, rotate with the new key
     as the next key: swap the two (old as `atlas-duck-master-key`, new as `masterKey.nextSecret`),
     deploy, then run steps 3 to 7.
