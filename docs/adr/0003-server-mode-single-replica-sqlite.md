# Server mode runs one replica on per-user SQLite stores

Server mode reuses the desktop audit store (one SQLite-backed store per user) on a ReadWriteOnce persistent volume with exactly one replica, instead of moving to PostgreSQL. This keeps the tested M2 store and its hash-chain guarantees unchanged and fits the expected load of one organisation; the cost is no high availability (a pod restart is downtime). Storage sits behind an interface so a PostgreSQL backend and multiple replicas can follow later.

## Consequences

ReadWriteMany volumes must not be used: SQLite locking over shared network filesystems is unsafe. The Deployment uses the `Recreate` strategy so two pods never open the same store.
