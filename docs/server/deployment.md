# Deploying atlas-duck-server

How the server reaches the cluster `team-dux@gip`, namespace `team-dux`. Day-to-day operation is
in [operations-runbook.md](operations-runbook.md). The design is in the server-mode spec
(`docs/superpowers/specs/2026-10-26-atlas-duck-server-mode.md`), ADR 0002 (master key in a
Kubernetes Secret) and ADR 0003 (SQLite, one replica).

## What gets deployed

- One pod (`replicas: 1`, `strategy: Recreate`) running `atlas-duck-server serve`, with a hardened
  security context: non-root user 65532, read-only root filesystem, all capabilities dropped,
  seccomp `RuntimeDefault`, and no service-account token.
- A `ReadWriteOnce` PVC at `/var/lib/atlas-duck`, holding `server/server.db` and one store per
  user. Production marks it `helm.sh/resource-policy: keep`.
- Secrets created outside the chart, mounted read-only as files:
  - `atlas-duck-master-key`, item `key`, at `/run/secrets/atlas-duck/master-key/key`;
  - during a rotation, the next key at `/run/secrets/atlas-duck/master-key-next/key`;
  - optionally, the directory service-bind password at `/run/secrets/atlas-duck/ldap-bind/password`.
- A CA bundle ConfigMap built from `deployment/ca/org-ca.pem`.
- An Ingress, which serves TLS with an existing Secret; the chart never creates a TLS Secret.
- A NetworkPolicy: ingress only from the selected namespaces; egress only to DNS, LDAPS (636),
  HTTPS (443) and any extra ports you list.
- In review environments only: a ConfigMap holding the test users.

Upgrades use `Recreate`, so each one has a short downtime. Sessions survive it because they are
stored in `server.db`.

## Before the first deploy (open questions)

Every open item appears as `CHANGE-ME` in `deployment/values-production.yaml`,
`deployment/values-review.yaml`, `deployment/ca/org-ca.pem` or the `.gitlab-ci.yml` variables
`REVIEW_DOMAIN` and `REVIEW_TLS_SECRET`. The deploy jobs refuse to run while one is left.

| # | Question | Where it goes |
|---|---|---|
| Q1 | A storage class offering `ReadWriteOnce` block storage (not NFS) | `persistence.storageClassName` in both values files |
| Q2 | Production host, review host pattern, ingress and monitoring namespace labels | `publicUrl`, `ingress.host`, `networkPolicy.ingressNamespaceSelectors`, `REVIEW_DOMAIN` |
| Q3 | TLS Secret names: production, and the wildcard for review hosts | `ingress.tls.secretName`, `REVIEW_TLS_SECRET` |
| Q4 | `LDAP_URL`, UPN suffix, base DN, the three group DNs, the organisation's CA certificates | `directory.ldap.*`, `groups.*`, `deployment/ca/org-ca.pem` |
| Q5 | Who creates the production master key and keeps its offline copy | this document, "Production master key" |
| Q6 | Is a read-only directory service account approved for the daily offboarding check? | `directory.serviceBind.*` (see [offboarding.md](offboarding.md)) |

## Production master key

The master key wraps every user's data key. Anyone who holds it together with the volume can
read every stored PAT (ADR 0002, [threat-model.md](threat-model.md)). Treat it that way:

1. On an offline machine, write the key file. Its single line is
   `atlas-duck-master-key/v1 <key-id> <base64 of 32 random bytes>`, where the key id matches
   `[a-z0-9-]{1,32}` and is not secret (for example `prod-2026-11`):

   ```sh
   umask 077
   printf 'atlas-duck-master-key/v1 prod-2026-11 %s\n' \
     "$(head -c 32 /dev/urandom | base64 -w0)" > /media/offline/atlas-duck-master-key
   ```

   The key never goes into shell history, an environment variable, a CI variable, a ticket or a
   chat.
2. Escrow: two people seal one copy on offline media and store it apart from any backup. A
   backup is useless without the key, and the key must never sit next to a backup.
3. Create the Secret from the file (the item name must be `key`):

   ```sh
   kubectl --context team-dux@gip -n team-dux create secret generic atlas-duck-master-key \
     --from-file=key=/media/offline/atlas-duck-master-key
   ```

4. Remove the file from the machine that ran `kubectl`. The escrowed copy is the only other one.

`deploy:production` checks that the Secret exists (by name only) and stops otherwise.

## Directory service bind (optional, Q6)

Only if a read-only service account is approved: create its password Secret the same way, as
item `password`, then set both `directory.serviceBind.dn` and
`directory.serviceBind.existingSecret`. The chart refuses one without the other. See
[offboarding.md](offboarding.md).

## CA bundle

`deployment/ca/org-ca.pem` holds the organisation's **public** CA certificates (PEM). The server
verifies LDAPS and the Jira/Confluence instances against this bundle only, and verification is
never switched off. To change it, edit the file in a merge request, let `server:guards` pass (it
accepts only certificate blocks and comments), then deploy. The pod restarts because the
ConfigMap checksum is a pod annotation.

## Pipeline

All server jobs live in `.gitlab-ci.yml`, in the stages `server-prepare` through
`server-verify`:

- `chart:test` lints and renders the chart against `chart/ci/*`, checks that every
  `chart/ci-fail/*` file fails, and runs the policy check over the rendered YAML.
- `server:guards` checks that no secret material and no disabled TLS verification are in the repo.
- `server:image` builds `crates/server/Dockerfile` with kaniko. The only build argument is
  `GIT_SHA`.
- The image is published to Harbor and Artifactory by digest. The chart is published as an OCI
  artifact.
- `deploy:review` runs on branches whose server paths changed against master. It creates a test
  master key Secret on first deploy, validates the rendered manifests with a server-side dry run,
  then applies them. The environment stops itself after 3 days.
- `stop:review` uninstalls the release and deletes the review PVC and the review key Secrets.
- `deploy:production` runs only on master, is triggered manually, and blocks the pipeline until
  someone decides. It is triggered only after the product owner's explicit go-ahead.

## GitLab settings (once, before the first production deploy)

- Protect `master` (Settings > Repository > Protected branches). `deploy:production` refuses to
  run from an unprotected ref.
- Protect the `production` environment and require an approval from the product owner (Settings >
  CI/CD > Protected environments). Without it, anyone who can run pipelines on master can trigger
  the manual job.
- `deploy:review` reaches the cluster from any branch whose server paths changed (PD-M13-12).
  Review environments hold test data only.

## First production deploy

1. Answer Q1–Q6, fill the values files and the CA bundle, and merge to master.
2. Create the master key Secret, plus the service-bind Secret if Q6 approved it.
3. Wait for the master pipeline. The image, chart, `chart:test` and `server:guards` jobs must be
   green.
4. Trigger `deploy:production`. Afterwards:

   ```sh
   kubectl --context team-dux@gip -n team-dux rollout status deploy/atlas-duck
   kubectl --context team-dux@gip -n team-dux exec deploy/atlas-duck -- \
     /app/atlas-duck-server admin anchor verify
   ```

   Open the public URL, sign in, and add the instances through **Admin** or
   `admin instances add`.

## Rollback

`helm rollback atlas-duck <revision> -n team-dux --kube-context team-dux@gip` returns to an
earlier chart and image, with downtime (Recreate), as long as the database schema did not change.

Schema migrations only go forward. Once a newer build has migrated `server.db`, an older build
refuses to start on it (`store/newer`), never opens its admin socket, and the image has no shell
to remove the file. The newer build's own restore would migrate an old bundle forward again. So
before every upgrade that may change the schema, stream a backup **off the cluster**
(`admin backup --stdout > pre-upgrade.tar`, [backup-restore.md](backup-restore.md)). The rollback
is then:

1. `kubectl $NS scale deploy/atlas-duck --replicas=0` (the PVC cannot be deleted while mounted).
2. Remove the PVC: `kubectl $NS annotate pvc atlas-duck-data helm.sh/resource-policy-` (production
   keeps it otherwise), then `kubectl $NS delete pvc atlas-duck-data`.
3. Deploy the older chart and image (`helm rollback` or the old pipeline's `deploy:production`);
   Helm creates an empty PVC and the old build starts on it.
4. `admin maintenance on`, `admin restore --stdin < pre-upgrade.tar`, `admin anchor verify`,
   `admin maintenance off`.

Everything after the pre-upgrade backup is lost. The older build must itself have
`restore --stdin` (M13 or later): a rollback to an M12 build is not possible this way.

## Review environments

A review environment has:

- its own release `atlas-duck-<slug>`;
- a throwaway volume (1Gi, deleted by `stop:review`);
- a test master key generated by the job into a Secret, never printed;
- the test directory with the users in `deployment/testdir/users.json`.

Those passwords are fixed test values, not secrets. Production refuses the test directory
twice: a chart guard, then the server itself (exit 78). No real account or data belongs in a
review environment.
