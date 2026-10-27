# Server data on node-local storage, with daily backups on NFS

The cluster offers no ReadWriteOnce block storage class: every team class is NFS, which SQLite must not use (ADR 0003), and the only other class is `local-path`, a ReadWriteOnce volume on one node's disk. We put the live stores on `local-path` and add a second volume on the team's NFS class (`team-dux-storage`) to which the server itself writes a consistent backup bundle every day, keeping the newest 14 (`ATLAS_DUCK_BACKUP_DIR`, `ATLAS_DUCK_BACKUP_KEEP`). SQLite never runs on NFS; only finished bundles live there.

## Consequences

The pod is pinned to the node that holds its volume. If that node is lost, so is the live data: recovery is a new data volume restored from the newest bundle on the NFS volume, losing at most a day (docs/server/backup-restore.md, "Losing the node or the data volume"). The NFS volume holds wrapped data keys and every chain of the last 14 days, so it widens the exposure of ADR 0002 to whoever can read that share; retention-deleted chains disappear from it within 14 days. A real RWO block class, when one exists, replaces `local-path` without code changes.