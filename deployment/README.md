# deployment/

Review environments and production (M13 plan T11). `helmfile.yaml` deploys the packaged chart with
`values-review.yaml` or `values-production.yaml`; the GitLab jobs `deploy:review`,
`deploy:production` and `stop:review` (`.gitlab-ci.yml`) run it.

- `ca/org-ca.pem`: the organisation's public root CA (`CN=SRO-AD-3-CA`), the root of the
  LDAPS certificate of `sro-ad-4.intern.gipmbh.de`. Public certificate only.
- `testdir/users.json`: review-only test users (M12 PD-198 format). The passwords are fixed test
  values and not secret; production refuses the test directory twice (chart guard, server exit 78).
- Storage: live data and daily backups on two `team-dux-storage` (NFS) ReadWriteOnce claims;
  SQLite runs in rollback-journal mode there (`persistence.sqliteJournal: delete`), ADR 0004.
  `local-path` is not provisioned on this cluster.
- TLS: cert-manager `Certificate` per host (ClusterIssuer `letsencrypt`), Secret `atlas-duck-tls`
  (production) or `atlas-duck-<slug>-tls` (review). No key is ever committed.

## Before the first pipeline

GitLab CI/CD variables (masked and protected where secret). The first group is what
dux-deployment-bot's pipeline already uses; the facts gathered on 2026-10-27 could not show
whether they are set at group level (`gip/teams/g-dux`) or only on that project, so check
**Settings > CI/CD > Variables** of the group, and set them on the atlas-duck project if they
are not inherited.

| Variable | Secret | Used by | dux-deploy has it |
|---|---|---|---|
| `HARBOR_HOST` | no | image build, publish, deploy | yes |
| `HARBOR_PROJECT` | no | image build (CI images) | yes |
| `HARBOR_USERNAME` | no | kaniko, skopeo | yes |
| `HARBOR_PASSWORD` | **yes** (masked) | kaniko, skopeo | yes |
| `ARTIFACTORY_USERNAME` | no | skopeo, helm push | yes |
| `ARTIFACTORY_PASSWORD` | **yes** (masked) | skopeo, helm push | yes |
| `DOCKER_DEV_REPO`, `DOCKER_RELEASE_REPO` | no | optional (defaults in `server:version`) | yes |
| `HELM_DEV_REPO`, `HELM_RELEASE_REPO` | no | optional (defaults in `server:version`) | yes |

The cluster context `team-dux@gip` comes from the runner, as for dux-deploy. Nothing else is a
CI variable: no application secret is ever passed through CI (SM-9.1).

Cluster objects (namespace `team-dux`):

- Secret `atlas-duck-master-key` (item `key`), created out of band before `deploy:production`
  (docs/server/deployment.md). Review environments create their own test key Secret
  `atlas-duck-<slug>-master-key` automatically.
- GitLab: protect `master` and the `production` environment with a required approval.
- DNS: `atlas-duck.dux.intern.gipmbh.de` and `*.atlas-duck.dux.intern.gipmbh.de` (review hosts)
  must resolve to the ingress controller, and the `letsencrypt` ClusterIssuer must be able to
  issue for them.