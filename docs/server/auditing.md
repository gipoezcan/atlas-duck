# Auditing in server mode

Every user has their own encrypted, hash-chained audit log, as on the desktop. The server adds an
**anchor chain** of its own that commits to every user's chain head at least every 15 minutes, and
milestone M14 adds reading and exporting chains over the web.

## Your own chain

The **Audit** page shows the signed-in user's chain: the event list with filters, a request's
trail and record payloads. It reads through `POST /api/cmd/audit_query`, `audit_trail`,
`audit_payload` and `audit_status`. Reading your own chain is not recorded. The desktop-only parts
(verify now, incident acknowledgement, backup and restore, the anchor dir) are not shown.

## Auditors

A user in `GROUP_AUDITORS` gets the **Auditor** page: every user (deactivated ones included) with
state and chain head, and the same audit view for any of them. The routes are
`GET /api/auditor/users` and `POST /api/auditor/users/{user_id}/{audit_query|audit_trail|audit_payload|audit_status}`;
without the auditor role they answer 403 `auth/role_required`, and an unknown user 404
`audit/user_unknown`. Admins have no audit route.

Every auditor request that returns data is recorded first, as `AUDITOR_READ` in the auditor's
own chain and in the server's anchor chain, with the action (`list_users`, `query`, `trail`,
`payload`, `export`) and the target user. If the record cannot be written the request fails with
503 `audit/read_not_recorded` and returns nothing. Reading a chain does not start the target's
runtime and writes nothing into the target's chain; an export does (`EXPORT`).

## Exports

Users export their own chain, auditors any user's chain:

| Step | Own chain | Any chain (auditor) |
|---|---|---|
| start (`{"from_utc": …}` or `{}` for all) | `POST /api/me/audit/exports` | `POST /api/auditor/users/{user_id}/exports` |
| poll | `GET …/exports/{job}` | `GET …/exports/{job}` |
| download | `GET …/exports/{job}/download` | `GET …/exports/{job}/download` |

The job first anchors the target's current head in the anchor chain (a `HEADS` row), then exports
through that head. Only the requester sees the job. The download is an uncompressed tar,
`atlas-duck-export-<user>-<from>-<to>.tar`, with `manifest.json`, `events.jsonl`,
`prune_log.jsonl`, `anchor-chain.jsonl`, `anchor-chain.manifest.json` and `README.txt`. Its
`X-Atlas-Duck-Manifest-Sha256` header and the job page carry the manifest's SHA-256.

Export files live on the data volume for `ATLAS_DUCK_EXPORT_TTL_HOURS` (default 24, 1..=168) and
are then deleted. At most `ATLAS_DUCK_EXPORT_MAX_CONCURRENT` (default 2, 1..=8) jobs run at once,
and one per requester and target (409 `audit/export_busy`). Other errors: `audit/export_unknown`
(404), `audit/export_expired` (410), `audit/export_failed` (500).

## Verifying an export

The job page shows the pin, the job's own anchor head `<seq>:<hash>`, and the full command:

    atlas-duck verify-export <dir> --manifest-sha256 <hex> \
      --anchor-chain <dir>/anchor-chain.jsonl --anchor-chain-head <seq>:<hash>

The server image has the same verifier: `atlas-duck-server verify-export …`.

- `--manifest-sha256` binds the files to the manifest you copied from the page.
- `--anchor-chain` checks the anchor-chain excerpt: row hashes, links, and every leaf that names
  the exported chain against the export's records.
- `--anchor-chain-head` pins the excerpt to a head you trust. **Without a pin the excerpt is
  reported as unanchored** and counts for nothing: a self-consistent excerpt can be fabricated
  whole.

Where to get a pin you trust, besides the job page: the server logs `anchor_head {seq, hash}` at
every anchoring (the log store is the out-of-band witness), `GET /api/anchor/head` and the admin
CLI's `anchor head` answer the current head. Use the job's own head: the live head moves on after the export.

Exit codes: 0 verified against a supplied trust root, 20 consistent but no trust root covers all
of it, 21 tampering or a fork, 22 usage or I/O error (also `--anchor-dir` together with
`--anchor-chain`).

## What the excerpt reveals

Rows that name the exported chain carry their full body: the sorted leaf hashes of every user
anchored in that row, which reveals other users' leaf hashes and how many users were anchored, but
no user id, chain id or record content. Other rows are opaque (hashes only).
