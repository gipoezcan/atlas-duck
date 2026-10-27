# Backup and restore

`admin backup` takes a consistent snapshot of every store while the server keeps running.
`admin restore` puts a snapshot back in maintenance mode, inside the same pod.

## What a backup holds

A bundle is a directory `atlas-duck-server-backup-<YYYYMMDDTHHMMSSZ>/` with:

- `server.db`: users with their **wrapped** data keys, sessions, API key hashes, instances and the
  server anchor chain;
- `users/<user_id>/…`: every user's store (the audit chain and its encrypted payloads);
- `manifest.json`, written last:
  - the SHA-256 of every file;
  - the anchor-chain head;
  - every user's last anchored head;
  - the id (not the key) of the master key that wraps the data keys.

`BACKUP_TAKEN` with the manifest's SHA-256 goes into the anchor chain.

**A backup is not a key.** Without the master key whose id is in the manifest, a bundle cannot
be opened. Keep the two apart: the escrowed key never sits next to a backup, and a backup copy
never sits next to the key ([deployment.md](deployment.md)).

## Taking a backup (daily)

```sh
NS="--context team-dux@gip -n team-dux"
kubectl $NS exec deploy/atlas-duck -- /app/atlas-duck-server admin backup /var/lib/atlas-duck/backups
# prints {"bundle": "/var/lib/atlas-duck/backups/atlas-duck-server-backup-…", "manifest_sha256": …}
```

### Copying files in and out

The image is distroless: it has no shell and no `tar`, so `kubectl cp` against the server
container does not work. Use an ephemeral debug container that targets it. It inherits the pod's
user (65532) and sees the pod's filesystem under `/proc/1/root`:

```sh
POD=$(kubectl $NS get pod -l app.kubernetes.io/instance=atlas-duck -o name | cut -d/ -f2)
kubectl $NS debug "$POD" --image=alpine:3.20.3 --target=server --container=ops -- sleep 3600
kubectl $NS cp -c ops "$POD:/proc/1/root/var/lib/atlas-duck/backups/atlas-duck-server-backup-…" ./atlas-duck-server-backup-…
```

This procedure is to be confirmed in the review drill (T15): the cluster's policy may forbid
ephemeral containers, in which case the backup copy-out needs another route (an open item).

- Allowed targets are `/var/lib/atlas-duck/backups` (same volume) and `/tmp`. `/tmp` is an
  emptyDir capped at 1Gi, so use it only for small installations.
- A copy on the same PVC does not survive the loss of the PVC. **Copy every bundle off the
  cluster** (`kubectl cp`, as above) to the agreed backup store, then delete it from the volume.
- Record the `manifest_sha256` with the copy. The anchor chain's `BACKUP_TAKEN` row carries the
  same value.
- During the copy every user runtime is closed and none opens (seconds to minutes). Requests
  that need a user store answer 503 meanwhile. Run backups outside working hours.
- Schedule: daily, operator-run, until a CronJob-free schedule is agreed. A CronJob cannot mount
  the RWO volume (ADR 0003). Also take one before every upgrade that may change the schema
  ([deployment.md](deployment.md), "Rollback").

## Restoring

Every restore first writes the live data as a full bundle,
`<data>/backups/pre-restore-<stamp>/`, with a manifest. Going back is therefore an ordinary
`admin restore` of that bundle. Still copy it off the cluster afterwards, like any backup.

1. `admin maintenance on`. Users get 503 `server/maintenance`; the probes and `/metrics` still
   answer.
2. Copy the bundle in (see "Copying files in and out").
3. `admin restore /var/lib/atlas-duck/backups/atlas-duck-server-backup-…`. Before anything live
   changes, the server:
   - copies the bundle to `<data>/restore-staging-<stamp>/` and checks every file's SHA-256;
   - requires the loaded master key to be the one in the manifest **and** to open every wrapped
     data key (`restore/unknown_master_key` otherwise; restore with the matching key mounted);
   - verifies the staged anchor chain (`restore/anchor_chain_invalid`);
   - opens and fully verifies every staged user chain, which must reach its manifest head
     (`restore/chain_invalid`). This verification appends `APP_START`, `VERIFY` and `APP_STOP`
     to the restored chains;
   - migrates an older bundle's `server.db` on the staged copy (after the hash checks).

   Any failure leaves the live data untouched and removes the staging copy.
4. The swap:
   - the runtimes close;
   - the live data is written as the pre-restore bundle;
   - the journal `<data>/restore-in-progress` is written and flushed to disk;
   - the staged users move in;
   - the live database takes the staged content in one step (SQLite backup API);
   - sessions and the API-key cache reload;
   - `RESTORED` goes into the restored anchor chain, and the journal goes.

   Sessions and API keys created after the backup are gone.
5. `admin anchor verify`. It must exit 0.
6. `admin maintenance off`.

A restore needs about **three times** the live data in free space: the staging copy, the
pre-restore bundle, and the live data.

### A restore interrupted mid-swap

If the pod dies during the swap, the journal is still there at the next start. The server then:

- stays in maintenance;
- answers `/readyz` with `restore_interrupted`;
- logs `store/restore_interrupted`;
- refuses `admin maintenance off`.

To recover, either:

- `admin restore --resume` finishes the swap. The staged copy was fully verified before the
  journal was written. Or:
- `admin restore /var/lib/atlas-duck/backups/pre-restore-<stamp>` goes back to the data as it
  was before.

Then run `admin anchor verify` and `admin maintenance off`.

## Drill

Run a restore drill at least quarterly, and after every change to the backup or key handling, on
a review environment: `verify:review-ops-drill`. It backs up, rotates the key, refuses the old
bundle, restores the new one and checks login. Keep the job log as evidence.

## Losing the PVC

1. Recreate the PVC: redeploy, which creates an empty one.
2. Make sure the master key Secret is the one named in the latest off-cluster bundle's manifest
   (`master_key_id`).
3. `admin maintenance on`, copy the bundle in, `admin restore`, `admin anchor verify`,
   `admin maintenance off`.

Anything after the bundle's time is lost: sessions, API keys created later, and audit records
written later. The anchor chain shows where the restored history ends (`RESTORED`).
