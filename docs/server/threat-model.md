# Server mode: what is protected, from whom, and what is not

This page covers atlas-duck in server mode: one pod in the `team-dux` namespace, serving the web
UI, the HTTP API and remote MCP. The desktop app has its own page
([docs/user/threat-model-limits.md](../user/threat-model-limits.md)). The decisions behind this
page are ADR 0001 (no shared service account), ADR 0002 (master key in a Kubernetes Secret) and
ADR 0003 (SQLite, one replica).

## What is worth protecting

| Asset | Where it lives | Protection |
|---|---|---|
| Users' Jira/Confluence PATs | `server.db`, sealed with the user's data key (AES-256-GCM) | Readable only by the server process holding the master key |
| Data keys | `server.db`, wrapped by the master key (bound to the user id) | The master key |
| Master key | Kubernetes Secret `atlas-duck-master-key`, mounted read-only as a file; offline escrow | Created out of band, never an env value, CI variable, image layer or log (SM-9.1) |
| Audit chains | One store per user on the PVC; payloads encrypted | Hash chain, plus the server anchor chain, which records every head at least every 15 min and on deactivation |
| Sessions | Cookie (`HttpOnly; Secure; SameSite=Strict`, `__Host-`); `server.db` stores only the SHA-256 of the id | CSRF token and `Origin` check on every state change |
| API keys | Shown once; `server.db` stores only an argon2id hash and a public prefix | Revocable; revoked or expired keys are refused at once |
| Directory service-bind password (optional) | Kubernetes Secret, mounted read-only as a file | Read once at start, never logged |

## Who we consider

- **A user** sees and changes only their own PATs, keys, approvals and chain. The isolation suite
  checks this.
- **An agent** holds an API key. It can read and propose writes, but never approve (SM-3.4).
  Approvals need a browser session.
- **An admin** (directory group) manages instances and runs the admin CLI. An admin has no route
  to another user's PATs, decrypted audit contents or approvals (SM-2.5).
- **An auditor** (M14) reads and exports chains; every read is itself audited.
- **A namespace cluster admin** of `team-dux` can read Secrets and exec into the pod.
- **A node admin, or anyone with access to the PV backend.**
- **A CI maintainer** can change `.gitlab-ci.yml` and the chart.
- **A network attacker inside the cluster** can reach pod IPs.

## Accepted risk: whoever can read the Secret can read every PAT (ADR 0002)

Anyone who can `get secret` in `team-dux`, or who has root on the node, or who can read the PV
backend **and** the Secret, can decrypt every stored PAT. That person can then act as any user
towards Jira and Confluence, within each PAT's permissions.

The anchor chain makes later tampering with audit chains detectable; it does not prevent the
disclosure. This was accepted because the organisation runs no Vault or KMS for this workload,
and keys derived from users' passwords would lock agents out and lose data on every password
change.

Mitigations, none of which remove the risk:

- Review the RBAC of `team-dux`: who may `get secret`, `exec` and `port-forward`, and who may
  read the PVs.
- Create the key out of band and keep it in two-person offline escrow
  ([deployment.md](deployment.md)). It never passes through CI.
- Rotate on staff change, on suspected exposure, and yearly
  ([master-key-rotation.md](master-key-rotation.md)).
- If the cluster's audit logging is available, alert on reads of `atlas-duck-master-key`.
- Users should give PATs the least permissions their work needs, and rotate them.

`kubectl exec` access is admin CLI access, and more: whoever can exec into the pod can read the
mounted key file. That is the same risk as reading the Secret. The admin CLI itself never prints
key material, PATs or audit contents.

## Further residual risks

- **Plain HTTP between the ingress and the pod.** TLS ends at the ingress controller; inside the
  cluster the traffic is plain HTTP. The NetworkPolicy admits only the ingress and monitoring
  namespaces (and `helm test` pods). Someone who can sniff pod traffic on a node sees session
  cookies and API keys.
- **One replica means downtime.** SQLite on a ReadWriteOnce volume allows exactly one process
  (ADR 0003). Upgrades, node drains and crashes are outages of seconds to minutes. There is no
  PodDisruptionBudget, because with one replica it would only block drains.
- **CI maintainers can change the pipeline.** A changed pipeline could build a different image or
  deploy different values. Mitigations:
  - `deploy:production` is manual and runs only on master; protect master and the `production`
    environment;
  - the image is deployed by digest;
  - `server:guards` refuses build arguments other than `GIT_SHA`, secret-like `ENV`s, private
    keys and disabled TLS verification.
  It cannot stop a maintainer who also controls the review of their own change.
- **Review environments use a test directory and a test key.** That is fine only because they
  never hold real data. Never sign in there with a real account and never store a real PAT
  there. Production refuses the test directory twice (chart guard, then server exit 78).
- **Backups contain the wrapped keys.** A bundle is useless without the master key whose id is
  in its manifest. Store bundles off-cluster and apart from the key escrow
  ([backup-restore.md](backup-restore.md)).
- **Offboarding without a service account is manual.** Until an operator runs
  `users deactivate`, a leaver's API keys keep working; a disabled account is refused only at
  its next login. With the optional service bind the daily check closes that gap within a day
  ([offboarding.md](offboarding.md)).
- **The directory decides who is a user.** Anyone who can add accounts to `GROUP_USERS`, or reset
  a user's password, can sign in as a user. Group changes take effect at the next login.
- **Admins choose the instances.** An admin can point an alias at a host of their choosing and
  collect the PATs users then enter for it. Instance changes are recorded in the anchor chain
  (`INSTANCE_ADDED` / `INSTANCE_REMOVED`), and users see the base URL before storing a PAT.

## What the server never does

- It never disables TLS verification. LDAPS and the instances are verified against the mounted
  organisation CA bundle, with no option to skip.
- It never takes a secret from an environment variable. The master key comes only from a file;
  any `*MASTER_KEY` variable stops the server.
- It never logs passwords, PATs, API keys, key material, session ids or payloads (SM-8.3).
- It never lets an API key or OAuth token approve a request.
- It never opens the stores from a second process. The admin CLI talks to the running server.
