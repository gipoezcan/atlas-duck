---
id: error-reference
title: Error reference
mode: both
order: 120
---

## Errors of the command line and agents {#errors-envelope}

Every failed request of an agent carries an `error` object with a `code`, a `retryable` flag and a message. The code tells you what went wrong. The flag tells the agent whether sending the same request again can work. Agents should decide on `status`, `error.code` and `error.retryable` together, not on the exit code alone.

::: desktop

The command line also sets an exit code, see [The response format](agents-desktop#envelope).

:::

Many of these errors reach you only through the agent. If you see one in the app, for example in "Recently decided (24 h)", the entry says what to do.

### `usage` {#err-usage}

The request was not valid: a command, an option or a combination of options that atlas-duck does not know. Nothing was queued. Exit 2, not retryable. Check the command with `--help`.

### `validation` {#err-validation}

The request was well formed but did not pass validation, for example a missing or wrong parameter of an operation. Nothing was queued. Exit 2, not retryable. Look up the operation with `ops describe <op-id>` and correct the parameters.

### `markdown_placeholders` {#err-markdown-placeholders}

The text contains placeholders that cannot be sent as written. When an agent writes a Confluence page or comment in Markdown, atlas-duck refuses a text that still contains placeholders that it put there when the agent read a page as Markdown (for example for macros or mentions). Written back, they would not mean what they stood for. Nothing was queued. Exit 2, not retryable. The agent should replace the placeholders with real content, or leave that part of the page out.

### `op_unsupported_by_instance` {#err-op-unsupported-by-instance}

This instance does not support the operation, for example because its version is too old. Exit 2, not retryable. Use another operation or another instance, or ask the administrator of the instance.

### `internal` {#err-internal}

An internal error occurred in atlas-duck, or in the server. Not retryable. Try again later. If it keeps happening, tell your administrator, and give them the request id and the time.

### `audit_failure` {#err-audit-failure}

The audit log could not be written, so nothing was done. atlas-duck never acts without recording it. Exit 1. For reads and scripts the agent may try again; for writes it is not retryable, because the write has to be decided again. Check that the disk of the audit log is not full, see [The audit storage is low](troubleshooting#audit-storage).

### `audit_storage_low` {#err-audit-storage-low}

The storage for the audit log is almost full. atlas-duck refuses new requests so that the log can always be written. Nothing was queued. Exit 1, retryable. Free disk space on the drive that holds the audit log, then try again. See [The audit storage is low](troubleshooting#audit-storage).

### `busy` {#err-busy}

Another operation is running. Nothing was queued. Exit 11, retryable. Wait for the time that `retry_after_s` names and try again.

### `unreachable` {#err-unreachable}

The command line could not reach the app, so nothing was queued. Exit 5. The `details.reason` says why:

| Reason | What to do |
| --- | --- |
| `not_running` | The app is not running. Start it. |
| `launch_timeout` | The app did not start in time, or the `--timeout` ran out before submission. Start the app yourself and try again. |
| `no_gui_session` | There is no desktop session to start the app in. Start it in a desktop session. |
| `launch_blocked_by_job` | On Windows, the app could not be started from the agent's process. Start the app yourself. |
| `app_upgraded` | The command line is newer than the running app. Restart the app. |
| `app_shutting_down` | The app is closing. Start it again. |
| `store_newer` | The audit data was written by a newer atlas-duck. Install that version or a newer one. |
| `store_unavailable` | The audit store could not be opened. Restart atlas-duck. Not retryable. |
| `connection_lost` | The connection dropped after the request was sent. The request exists; wait for it with `await <id>`, it may be `abandoned`. |

Except for `store_unavailable`, the error is retryable.

### `server_identity` {#err-server-identity}

The program that answered is not the app that belongs to your user. atlas-duck refuses to talk to it. Exit 5, not retryable. This is a safety check. Make sure that no other program uses the app's connection and restart atlas-duck. If it persists, tell your administrator.

### `protocol_mismatch` {#err-protocol-mismatch}

The command line and the app speak versions of the protocol that do not fit. Exit 5. Update both to the same version and restart the app. Restart the MCP server of the agent as well.

### `upstream_http` {#err-upstream-http}

The Jira or Confluence server answered with an error. This code appears when a write failed after you approved it, when you released the error of a read, or when you denied a request and attached the HTTP status as a hint. Exit 6 or 3, not retryable. The `details` carry the HTTP status and the error messages of the instance. Read them: usually a permission, a value that the instance rejects, or a deleted object.

### `upstream_network` {#err-upstream-network}

The connection to the instance failed. Exit 6. When it happened before the request was sent, it is retryable. When it came out of a read and you released it, it is a fixed message without data and not retryable. Check that the instance can be reached, see [An instance cannot be reached](troubleshooting#cannot-connect).

### `upstream_unavailable` {#err-upstream-unavailable}

The instance is not available right now. Exit 6. Reads can be retried later. If the reason is `identity_header_missing` or `identity_header_mismatch`, a proxy in front of Jira changes the user header, so a retry does not help; ask the administrator of the instance. See [Instances and tokens](instances-and-tokens).

### `upstream_unknown_outcome` {#err-upstream-unknown-outcome}

A write was sent, but atlas-duck does not know whether the instance carried it out, for example after a timeout, a server error or a crash. Status `outcome_unknown`, exit 6, not retryable. **Check the target in Jira or Confluence before you do anything else.** Only when the change is missing should it be requested again. The entry is under "Needs attention" with "check target", see [Needs attention](approvals#needs-attention).

### `result_too_large` {#err-result-too-large}

The result is too large to return. Exit 6, not retryable. The agent should ask for less: a smaller page, fewer fields, or a narrower search.

### `needs_token` {#err-needs-token}

A token is needed for this instance. The token is missing, or the instance has refused it. Exit 9. Add or replace the token, see [Instances and tokens](instances-and-tokens) and [A token is rejected](troubleshooting#token-rejected). Agents should not retry in a loop.

### `locked` {#err-locked}

The app is locked: it cannot open its audit log or its keys. Exit 9. The `details.reason` says why, for example that the keychain is not available yet, that it was lost, or that the keyring lies on a network drive. Follow [The app is locked](troubleshooting#locked).

### `not_configured` {#err-not-configured}

This instance, or the app, is not set up yet. Exit 9. The `details.reason` names the gap: the first-run wizard is not finished, no instance exists for the product, an instance uses `http://` instead of `https://`, an instance is not confirmed, the data directory is missing or not on a local drive, or the settings file cannot be read. Finish the setup.

::: desktop

See [Getting started](getting-started-desktop).

:::

### `script_syntax` {#err-script-syntax}

The script has a syntax error. atlas-duck compiles every script on submission and refuses a faulty one. Exit 8, not retryable. Fix the script. See [Scripts](scripts#what-are-scripts).

### `script_limit` {#err-script-limit}

The script hit a limit and was stopped: time, memory, number of calls, data fetched or size of the result. Exit 8, not retryable. Make the script do less, or raise the limit in Settings, see [Limits and confinement](scripts#limits).

### `sandbox_unavailable` {#err-sandbox-unavailable}

The script sandbox is not available, so scripts cannot run. Exit 8, not retryable. If the reason is `app_upgraded`, restart the app and try again. Otherwise the operating system does not allow the confinement, see [Limits and confinement](scripts#limits).

### `result_evicted` {#err-result-evicted}

The outcome is known, but the result is no longer stored. Exit 10. For reads and scripts the agent can submit the request again; for a write do not repeat it, because the change was already made.

### `denied` {#err-denied}

You denied the request. The message holds your reason. Exit 3, not retryable. The agent should resubmit only when the reason asks for a change. See [Approve, release or deny](approvals#approve-or-deny).

### `resolution_failed` {#err-resolution-failed}

A name in the request could not be resolved, for example a user, a field or a project that does not exist under that name. Exit 3 when you attached it as a hint to a deny. The `details` name the parameter and may list candidates. The agent should fix the named parameter.

### `expired` {#err-expired}

Nobody decided the request in time. Exit 7, not retryable. Submit again only if you want that.

### `cancelled` {#err-cancelled}

The request was cancelled: by the agent (`cancel`, not retryable), because the app was quit or the system shut down (retryable). Exit 7. Nothing was executed, and a cancelled result never reaches your queue.

### `abandoned` {#err-abandoned}

The request was still pending when the app crashed or was killed. Exit 7, retryable. Submit it again. A write that was already approved becomes `outcome_unknown` instead, see [upstream_unknown_outcome](error-reference#err-upstream-unknown-outcome).

### `unknown_request` {#err-unknown-request}

There is no request with this id. Exit 2. Check the id, or find it with `requests list`.

### `protocol_error` {#err-protocol-error}

The app and the command line tool could not agree on a message. Exit 1, not retryable. This usually means that they have different versions. Update both and restart the app.

## Errors when deciding {#errors-decision}

These errors appear in the Approvals window when a decision cannot be applied. In every case nothing was decided, and the request is as it was.

### `stale` {#err-stale}

The request changed in the meantime, for example it received a new revision. Re-read the queue, open the request again and decide on what you see.

### `invalid` {#err-invalid}

The decision is not allowed for this request, for example approving something that cannot be approved, or releasing with a preview that you have not opened. Open the preview first, or decide individually.

### `edit_rejected` {#err-edit-rejected}

The edit was refused, for example because it changes the target, is not valid, or is too large. The message names the reason. Correct the field, or deny the request. See [Editing and redacting](approvals#edit-and-redact).

### `audit` {#err-audit}

The decision could not be recorded in the audit log, so nothing was done. Check the free space of the audit log, then try again. See [The audit storage is low](troubleshooting#audit-storage).

### `batch_rejected` {#err-batch-rejected}

The batch was rejected and nothing was decided. At least one request did not qualify. The reasons are listed per request, see below and [Batch decisions](approvals#batch-decisions).

### `not_decidable` {#err-not-decidable}

The request is not waiting for a decision. Someone else decided it, it expired, or it was cancelled. Re-read the queue.

## Errors in batch decisions {#errors-batch}

A batch lists these reasons per request. Remove the request from the batch or decide it individually.

### `not_pending` {#err-not-pending}

The request is no longer pending. It was decided, expired or cancelled in the meantime.

### `target_param_edit` {#err-target-param-edit}

The target of the request cannot be edited. Decide it individually, or deny it so that the agent asks again with the right target.

### `not_opened` {#err-not-opened}

The preview of the request was not opened. Open the preview of every selected request before you decide as a batch.

### `not_approvable` {#err-not-approvable}

The request cannot be approved as it is, for example because required fields are missing. Decide it individually.

### `batch_item_flagged` {#err-batch-item-flagged}

The request is flagged as a possible duplicate or as a similar request. Look at it and approve it individually.

::: server

## Errors of the server commands {#errors-cmd}

The server pages send commands to the server. These errors come back when a command fails. The error `internal` is described [above](error-reference#err-internal).

### `invalid_argument` {#err-invalid-argument}

The request contains an invalid value. Check what you entered and try again.

### `not_found` {#err-not-found}

The request, or the thing that it names, does not exist any more. Reload the page.

### `release_blocked` {#err-release-blocked}

This request cannot be released. The redactions that you made, or the data itself, would let through something that should have been held back. The page names the reason. See "When a release is blocked" in [Editing and redacting](approvals#edit-and-redact).

### `unknown_command` {#err-unknown-command}

The server does not know this command. The page and the server are of different versions. Reload the page; if it persists, tell your administrator.

### `not_ready` {#err-not-ready}

Your store is not ready yet, for example right after a restart. Try again in a moment.

### `audit_unreadable` {#err-audit-unreadable}

An audit entry could not be read. The rest of the log is not affected. If it keeps happening, tell your administrator.

### `audit_failed` {#err-audit-failed}

The audit log could not be read. Try again later. If it persists, tell your administrator.

:::

::: server

## Errors of the server API {#errors-server}

The server answers errors with an HTTP status and a code. The web pages translate the code into a message. The code is useful when you talk to your administrator.

### `auth/invalid_credentials` {#err-auth-invalid-credentials}

HTTP 401. The username or password is wrong. Sign in again with your directory account.

### `auth/empty_password` {#err-auth-empty-password}

HTTP 400. You did not enter a password.

### `auth/directory_unavailable` {#err-auth-directory-unavailable}

HTTP 503. The server cannot reach the directory that checks your password. People who are signed in can keep working. Try again later, or tell your administrator.

### `auth/not_permitted` {#err-auth-not-permitted}

HTTP 403. This account may not use atlas-duck: it belongs to none of the groups that the server admits, or it was deactivated. Ask your administrator, see [Users and roles](admin#users-and-roles).

### `auth/no_session` {#err-auth-no-session}

HTTP 401. You are not signed in. Sign in first.

### `auth/session_expired` {#err-auth-session-expired}

HTTP 401. The session expired. Sign in again.

### `auth/csrf_mismatch` {#err-auth-csrf-mismatch}

HTTP 403. The request token does not match your session, for example because the page was open for a long time or in two sessions. Reload the page.

### `auth/origin_mismatch` {#err-auth-origin-mismatch}

HTTP 403. The request comes from another origin than the server's own address. Use the address that your administrator gave you, and do not call the server from another website.

### `auth/role_required` {#err-auth-role-required}

HTTP 403. The page or action needs a role that your account does not have, such as admin or auditor. See [Users and roles](admin#users-and-roles).

### `auth/bearer_not_accepted` {#err-auth-bearer-not-accepted}

HTTP 403. API keys and OAuth tokens cannot be used here. Only the MCP endpoint accepts them; decisions can only be made by a person who is signed in. See [The MCP endpoint](agents-server#mcp-endpoint).

### `auth/api_key_invalid` {#err-auth-api-key-invalid}

HTTP 401. The API key or token is not valid: it is mistyped, revoked or expired, or its user was deactivated. Create a new key, see [API keys](agents-server#api-keys).

### `auth/scope_missing` {#err-auth-scope-missing}

HTTP 403. The key lacks the scope that this needs. Create a key with the scope, see [Scopes](agents-server#scopes).

### `api/bad_request` {#err-api-bad-request}

HTTP 400. The request is malformed. If you use the web pages, reload them. If an own program sends it, check the body.

### `api/not_found` {#err-api-not-found}

HTTP 404. Not found. The address or the object does not exist.

### `api/unknown_command` {#err-api-unknown-command}

HTTP 404. The server does not know this command. Reload the page; the page and the server may be of different versions.

### `api/body_too_large` {#err-api-body-too-large}

HTTP 413. The request body is too large. Send less data.

### `api/too_many_streams` {#err-api-too-many-streams}

HTTP 429. You have too many pages open that wait for live updates. Close some tabs.

### `instance/invalid` {#err-instance-invalid}

HTTP 400. The instance is not valid. Check the alias (letters, digits, `-` and `_`), the product, an `https://` base URL and the proxy, and that the product has only one default. See [Manage instances](admin#instances-admin).

### `instance/exists` {#err-instance-exists}

HTTP 409. An instance with this alias exists already. Choose another alias.

### `instance/unknown` {#err-instance-unknown}

HTTP 404. No instance has this alias, perhaps because an administrator removed it. Reload the page.

### `pat/check_failed` {#err-pat-check-failed}

HTTP 422. The instance refused the token. Check that you copied it completely and that it has not expired or been revoked. See [A token is rejected](troubleshooting#token-rejected).

### `pat/instance_unreachable` {#err-pat-instance-unreachable}

HTTP 502. The server cannot reach the instance to check the token. Try again later, or ask your administrator. See [An instance cannot be reached](troubleshooting#cannot-connect).

### `api_key/limit_reached` {#err-api-key-limit-reached}

HTTP 409. You have the maximum of 25 active keys. Revoke one first, see [API keys](agents-server#api-keys).

### `api_key/expiry_out_of_range` {#err-api-key-expiry-out-of-range}

HTTP 400. The expiry must be a whole number of days from 1 to 90.

### `api_key/name_invalid` {#err-api-key-name-invalid}

HTTP 400. The name must be 1 to 64 characters long and contain no control characters.

### `api_key/scope_invalid` {#err-api-key-scope-invalid}

HTTP 400. Choose at least one scope, and only known ones.

### `store/unavailable` {#err-store-unavailable}

HTTP 503. The store is not available. Try again in a moment. If it persists, tell your administrator.

### `oauth/disabled` {#err-oauth-disabled}

HTTP 404. OAuth is not enabled on this server. Use an API key instead, see [API keys](agents-server#api-keys).

### `oauth/request_unknown` {#err-oauth-request-unknown}

HTTP 404. This authorization request is unknown. It may have been answered already, or it belongs to another session. Start again from the app, see [Authorising an app](agents-server#oauth-consent).

### `oauth/request_expired` {#err-oauth-request-expired}

HTTP 410. This authorization request expired. Start again from the app.

### `oauth/grant_unknown` {#err-oauth-grant-unknown}

HTTP 404. There is no such connected app. It may be revoked already. Reload "Connected apps".

### `audit/user_unknown` {#err-audit-user-unknown}

HTTP 404. No such user has an audit log. Go back to the list of users.

### `audit/read_not_recorded` {#err-audit-read-not-recorded}

HTTP 503. The read could not be recorded, so nothing was read. Auditing is itself audited, and the server refuses to show data that it cannot record. Try again later. See [The auditor role](auditor#auditor-role).

### `audit/export_busy` {#err-audit-export-busy}

HTTP 409. An export of this log is already running, or the server runs its maximum number of exports. Try again when it has finished.

### `audit/export_unknown` {#err-audit-export-unknown}

HTTP 404. There is no such export, or it belongs to someone else.

### `audit/export_expired` {#err-audit-export-expired}

HTTP 410. The export is no longer available: it expired or was already downloaded. Start a new one, see [Export the log](audit#export).

### `audit/export_failed` {#err-audit-export-failed}

HTTP 500. The export failed. Start a new one. If it keeps failing, tell your administrator.

### `server/maintenance` {#err-server-maintenance}

HTTP 503. The server is in maintenance, for example for a restore. Try again later. See [Maintenance](admin#maintenance).

### `auth/rate_limited` {#err-auth-rate-limited}

HTTP 429. Too many failed sign-ins. Wait for the time that the `Retry-After` header names, then try again.

:::
