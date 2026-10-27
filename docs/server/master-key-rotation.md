# Rotating the master key

The master key wraps every user's data key (SM-6.2, ADR 0002). Rotating it re-wraps every data
key under a new master key. The users' stores and their audit chains stay as they are: their
data keys do not change.

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

   Each user's row is re-wrapped in its own step (compare-and-set), so every row is always
   wrapped under one of the two loaded keys. The new key becomes the primary, and
   `MASTER_KEY_ROTATED {old_key_id, new_key_id}` goes into the anchor chain. The output shows key
   ids and counts only.
4. Swap the production Secret to the new key, then remove the next one:

   ```sh
   kubectl $NS create secret generic atlas-duck-master-key --from-file=key=/media/offline/new-key \
     --dry-run=client -o yaml | kubectl $NS apply -f -
   ```

   Set `masterKey.nextSecret: ""`, deploy, then
   `kubectl $NS delete secret atlas-duck-master-key-next`.
5. Verify:
   - `/readyz` is 200, with no `master_key_mismatch`;
   - `atlas_duck_master_key_info` shows only the new id, as `primary`;
   - a user can sign in and an existing API key works;
   - `$A anchor verify` exits 0.
6. Destroy every copy of the old key except the sealed escrow kept for old backups. Record the
   date and the new key id in the key log.

## If something goes wrong

- **The rotation stopped part-way** (the pod died, or `rotate/unwrap_failed`). Some rows carry the
  new id, the rest the old one. Leave `masterKey.nextSecret` set: with both keys loaded the
  restarted server opens every user. Run step 3 again; it re-wraps only the rows still under the
  old key (`already_rewrapped` counts the others).
- **`/readyz` says `master_key_mismatch` after step 4.** The pod runs a key that does not open
  some data keys. Usually the Secret was not swapped, or the old key was mounted again after the
  rotation finished. Mount the key whose id the users' data keys carry (the new one), or set
  `masterKey.nextSecret` to it again.
- **`rotate/concurrent_change`.** A row changed during the run. Run it again.
- **A restore of a pre-rotation backup** needs the old key mounted as the master key. The restore
  refuses a bundle whose data keys the loaded key cannot open (`restore/unknown_master_key`).
  Restoring an old backup after a rotation means: mount the old key, restore, then rotate again.
