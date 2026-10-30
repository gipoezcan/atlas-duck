---
id: troubleshooting
title: Troubleshooting
mode: both
order: 110
---

## An instance cannot be reached {#cannot-connect}

Symptoms: agents get `unreachable`, `upstream_network` or `upstream_unavailable`; a token check says that the instance cannot be reached (`pat/instance_unreachable` on the server).

First separate two cases. Every `unreachable` error concerns the app, not the instance: the command line cannot reach the app. See the reasons in [`unreachable`](error-reference#err-unreachable). Only `upstream_network`, `upstream_unavailable` and `pat/instance_unreachable` point at the instance. Then the instance is the problem:

1. Open the address of the instance in a browser on the same computer. If it does not load, the cause is the network, the VPN or the instance itself. atlas-duck cannot do more than your browser can.
2. Check the state of the instance. On the desktop, Settings lists it under "Instances". The states "unconfirmed", "needs token" and "insecure scheme (http)" say what to do, see [Instances and tokens](instances-and-tokens).
3. If the instance uses an internal certificate authority, add it as the custom CA of the instance, or, on the server, ask the administrator to use the organisation CA bundle.
4. If you need a proxy, set it for the instance. The desktop app does not evaluate proxy auto-config scripts: enter the proxy as host and port.
5. `upstream_unavailable` with `identity_header_missing` or `identity_header_mismatch` means that a proxy in front of Jira removes or changes the `X-AUSERNAME` header. Ask the Jira administrator.

A request that failed with `upstream_network` before it was sent can simply be sent again.

## A token is rejected {#token-rejected}

Symptoms: "The token was refused by the instance.", state "needs token", agents get `needs_token`.

- The token may be mistyped or cut off when you copied it. Paste it again.
- The token may have expired or been revoked in Jira or Confluence. Create a new personal access token there and replace the stored one.
- The token must belong to your own account. If you replace it by a token of another Atlassian user, atlas-duck refuses it: "This token belongs to another Atlassian user. Remove the stored token first."
- On the server, the page "Credentials" shows "Token stored, not usable" when the instance refuses the stored token.

See [Instances and tokens](instances-and-tokens). Agents must not retry `needs_token` in a loop: it will not heal by itself, see [`needs_token`](error-reference#err-needs-token).

## A request stays pending {#nothing-happens}

A request waits until you decide. It is not stuck, it waits for you. Check:

1. Open the Approvals window and look in "Pending approvals". The request may wait there, perhaps below others.
2. If nothing is listed, the request may have expired, been denied or cancelled. Look under "Recently decided (24 h)".
3. If the agent does not see your decision, it may have stopped waiting. An agent that submitted with a short `--timeout` gets `pending` and has to fetch the result with `await <id>`. It must never submit the request again.
4. If the agent lost the id, it can find the request with `requests list`.
5. After a restart of the app, a request that was pending is no longer pending: it became `abandoned`, see [`abandoned`](error-reference#err-abandoned).

A write that you approved can show "executing" for a while. If it ends as `outcome_unknown`, check the target yourself, see [`upstream_unknown_outcome`](error-reference#err-upstream-unknown-outcome).

## The app is locked {#locked}

Symptoms: agents get `locked` (exit 9); the tray shows "Waiting for keyring" or a locked message.

This is about the desktop app. The app is locked when it cannot get the key to its audit log. The `details.reason` tells you which case it is:

- **`keychain_unavailable`**: the system keychain is not ready yet, which can happen right after login. atlas-duck retries for one to two minutes and then offers a manual retry. Unlock or start your keychain; on Linux this needs a Secret Service provider such as GNOME Keyring or KWallet.
- **`keychain_lost`**: the keychain entries are gone, for example after a password reset, a profile wipe or a reinstall. The log is intact. The credential window offers "Recover this log": enter your recovery passphrase. Afterwards every instance needs its token again, and an integrity incident is recorded that you acknowledge, see [Integrity incidents](audit#integrity-incident). Without the passphrase the only alternative is to archive the old log and start fresh; the old log is then kept aside and you must keep it for its retention period.
- **`keyring_not_local`**: the keyring files lie on a network drive. atlas-duck does not use such a keyring, because two computers would overwrite each other's entries. Use a local home directory.

Never delete the keychain entries or the data directory to get unlocked: that loses the audit log. See [`locked`](error-reference#err-locked).

## The audit storage is low {#audit-storage}

Symptoms: agents get `audit_storage_low`; a warning shows in the app and in the tray; decisions fail with an audit error.

This is about the desktop app; on the server the operator watches the storage. atlas-duck only acts when it can record it. When the free space of the drive that holds the audit log falls under a threshold (by default 2 GiB), it refuses new requests. System entries and pruning continue.

1. Free disk space on that drive. Empty the trash, remove old downloads, backups and exports that you no longer need.
2. Check "Retention and legal hold" in Settings. If a legal hold is on, nothing is pruned. A long retention period keeps more data.
3. Try again. Requests that were refused were not queued, so the agent has to submit them again.

See [`audit_storage_low`](error-reference#err-audit-storage-low) and [Retention and legal hold](audit#retention).
