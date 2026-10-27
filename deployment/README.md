# deployment/

Review environments and production (M13 plan T11). `helmfile.yaml` deploys the packaged chart with
`values-review.yaml` or `values-production.yaml`; the GitLab jobs `deploy:review`,
`deploy:production` and `stop:review` (`.gitlab-ci.yml`) run it.

- `ca/org-ca.pem`: the organisation's public CA certificates (PEM), mounted as the CA bundle.
- `testdir/users.json`: review-only test users (M12 PD-198 format). The passwords are fixed test
  values and not secret; production refuses the test directory twice (chart guard, server exit 78).
- Every `CHANGE-ME` is an open question (plan Q1-Q6); the deploy jobs refuse to run while one is
  left in the files they use.