# The server-mode master key lives in a Kubernetes Secret

The organisation runs no Vault or KMS for this workload, and a key derived from each user's domain password would lock agents out while the user is signed out and lose the data on every password change. We chose one master key, created out of band as a Kubernetes Secret (never a CI variable, never in the image), that wraps each user's data key; an admin CLI rotates it.

## Consequences

Cluster administrators of the `team-dux` namespace can in principle read the master key and therefore decrypt stored PATs. This is an accepted, documented risk in the threat-model docs; the server anchor chain makes later tampering with audit chains detectable but does not prevent token disclosure by a cluster admin.
