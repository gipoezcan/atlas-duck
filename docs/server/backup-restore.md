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

A restore cannot be undone by another restore: the copy it keeps of the replaced data is not a
bundle. So **take a backup immediately before every restore.**

1. `admin backup /var/lib/atlas-duck/backups`, then copy it off the cluster.
2. `admin maintenance on`. Users get 503 `server/maintenance`; the probes and `/metrics` still
   answer.
3. Copy the bundle in through the debug container (see "Copying files in and out"):
   `kubectl $NS cp -c ops ./atlas-duck-server-backup-… "$POD:/proc/1/root/var/lib/atlas-duck/backups/"`.
4. `admin restore /var/lib/atlas-duck/backups/atlas-duck-server-backup-…`. Before anything live
   changes, the server:
   - copies the bundle to `<data>/restore-staging-<stamp>/` and checks every file's SHA-256;
   - requires the loaded master key to be the one in the manifest **and** to open every wrapped
     data key (`restore/unknown_master_key` otherwise; restore with the matching key mounted);
   - verifies the staged anchor chain (`restore/anchor_chain_invalid`);
   - opens and fully verifies every staged user chain, which must reach its manifest head
     (`restore/chain_invalid`). This verification appends `APP_START`, `VERIFY` and `APP_STOP`
     to the restored chains.

   Any failure leaves the live data untouched and removes the staging copy.
5. The swap:
   - the runtimes close;
   - the live `server.db` is copied and `<data>/users` moved to `<data>/pre-restore-<stamp>/`;
   - the staged users move in;
   - the live database takes the staged content in one step (SQLite backup API);
   - sessions and the API-key cache reload;
   - `RESTORED` goes into the restored anchor chain.

   Sessions and API keys created after the backup are gone.
6. `admin anchor verify`. It must exit 0.
7. `admin maintenance off`.

### After a restore

`<data>/pre-restore-<stamp>/` keeps the replaced data until an admin deletes it:

```sh
kubectl $NS exec "$POD" -c ops -- rm -rf /proc/1/root/var/lib/atlas-duck/pre-restore-<stamp>
```

The image has no `rm` of its own; the debug container `ops` does. Check free space before each restore: it needs about **three times** the live data
(staging, the pre-restore copy and the live data).

### A restore interrupted mid-swap

`server.db` changes in one step, but moving the users directory is two renames. If the pod dies
between them, `<data>/users` is missing or incomplete, and `<data>/pre-restore-<stamp>/users`
holds the previous one. Recovery:

1. Keep the pod in maintenance after the restart (`admin maintenance on`).
2. Restore the bundle taken in step 1 again.

If you cannot restore, move `pre-restore-<stamp>/users` back from a debug container.

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
