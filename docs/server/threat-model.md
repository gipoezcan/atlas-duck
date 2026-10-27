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
- Rotate on staff change and yearly. Rotation only re-wraps: it does not change data keys, so
  after a suspected exposure of the key together with data (volume, backup or kept bundle) users
  must also replace their PATs and API keys ([master-key-rotation.md](master-key-rotation.md));
  re-sealing with new data keys is follow-up work.
- Keep few bundles: every bundle on the volume or off-cluster (`admin backups list`) widens the
  `PV backend + Secret` exposure to past data and to chains retention has since deleted. Prune
  with `admin backups remove`.
- Rotate on suspected exposure too, and yearly
  ([master-key-rotation.md](master-key-rotation.md)).
- If the cluster's audit logging is available, alert on reads of `atlas-duck-master-key`.
- Users should give PATs the least permissions their work needs, and rotate them.

`kubectl exec` access is admin CLI access, and more: whoever can exec into the pod can read the
mounted key file. That is the same risk as reading the Secret. The admin CLI itself never prints
key material, PATs or audit contents.

## Further residual risks

- **Review deploys share the namespace.** `deploy:review` runs `kubectl` with the `team-dux`
  context from any branch whose server paths changed, in the namespace that holds
  `atlas-duck-master-key`. If that context is available to pipelines of unprotected branches,
  anyone who can push a branch can read the production key. Either restrict the cluster context
  to protected refs (and give review environments a separate namespace), or accept this as part
  of the ADR 0002 risk: whoever can run CI with the context can read Secrets.

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

- **OAuth clients choose their own name.** Any MCP client can register (rate limited per IP,
  capped in total); its name is its own claim, and the consent page says so. What protects the
  user is the consent itself: the redirect host shown in bold, scopes the user can only drop, a
  consent request bound to the browser session, PKCE S256, and an access token valid for one
  resource. A user who consents to a malicious client gives it what the scopes allow until the
  grant is revoked (**Connected apps**, the revocation endpoint, deactivation), and never the
  right to approve anything ([oauth.md](oauth.md)).
- **A stolen authorization code ends the grant.** Whoever presents a code first burns it; the
  real client's redemption then counts as reuse and revokes the grant. That is a denial of
  service by design (RFC 9700), traded for reuse detection.
- **Scripts run in the server pod.** User scripts run in the sandbox worker inside the same
  container, confined by seccomp with no-new-privileges, Landlock where the kernel has it and
  resource limits, with no capability and no user namespace. The worker runs as the server's
  UID; the confinement, not the UID, keeps a script from the server's files, its memory and
  other users' workers. A kernel escape from the seccomp/Landlock sandbox would reach the server
  process and so every user's data. Where the sandbox cannot start (`scripts: not_met`) no
  script runs; there is no degraded mode on a server ([scripts.md](scripts.md)).
- **Exports sit on the volume for a while.** An export job writes the exported chain under
  `<data>/exports` and keeps it for `ATLAS_DUCK_EXPORT_TTL_HOURS` (default 24). Whoever can read
  the volume can read those files in clear, as they could the stores with the master key.
- **The anchor excerpt reveals a little about other users.** Rows of the excerpt that name the
  exported chain carry every leaf hash of that anchoring: other users' leaf hashes and how many
  users were anchored, never a user id, chain id or record (L248, [auditing.md](auditing.md)).
- **Auditors read every chain.** Each auditor read is recorded before it returns data, in the
  auditor's chain and in the anchor chain (`AUDITOR_READ`). An auditor's exports are recorded in
  the target's chain (`EXPORT`).

## What the server never does

- It never disables TLS verification. LDAPS and the instances are verified against the mounted
  organisation CA bundle, with no option to skip.
- It never takes a secret from an environment variable. The master key comes only from a file;
  any `*MASTER_KEY` variable stops the server.
- It never logs passwords, PATs, API keys, key material, session ids or payloads (SM-8.3).
- It never lets an API key or OAuth token approve a request.
- It never runs a script outside the sandbox: no `*ALLOW_DEGRADED*` setting is accepted.
- It never opens the stores from a second process. The admin CLI talks to the running server.
