---
id: audit
title: Audit log
mode: both
order: 70
---

## What the audit log records {#audit-log}

atlas-duck keeps a record of everything that happens around a request: that it arrived, what you saw, what you decided, what was sent to the instance and what came back, and what the agent received. The records are chained: each one contains a fingerprint of the one before, so a changed or removed record breaks the chain and can be found. The content of each record (the "payload") is stored encrypted.

::: desktop

The log is yours, on your computer. Open it with "Audit" in the header of the Approvals window. The window has these parts:

- "Verification" with "Verify now" (see [Verify the chain](audit#verify)) and the list of "Integrity incidents";
- "Anchor directory": the folder that holds extra copies of the log head, or "none" (see below);
- "Records": the list of records, newest first, with "Filters";
- "Export and backup" (see [Export the log](audit#export)).

:::

::: server

Every user has a separate audit log of their own. The page "My audit" in the header shows yours: the list of records with filters, the trail of a request and the payload of a record. Reading your own log is not recorded. Verification, acknowledging incidents, backup and the anchor directory belong to the desktop app; on the server the operator looks after them. Users with the auditor role can read other users' logs, see [The auditor role](auditor#auditor-role).

:::

**Filters.** You can filter by time range ("From (UTC)", "To (UTC)"), "Agent name", "Operation", "Class", "Instance id", "Target (starts with)", "Decision" and "Flags (any of)". Filters match only the plaintext columns of a record; payloads are not searched. "Load more" continues a search.

**Decisions** in the log are: approve, approve (edited), release, release (redacted), deny, expire, cancel and reject. **Flags** are: edited, redacted, batch, stale, clock backwards, clock forward, clock behind and integrity incident. The clock flags mark records written while the computer's clock went backwards, jumped ahead or was behind the date that the servers reported. They exist so that a wrong clock cannot shorten retention.

**A record.** "Open record" shows the fields: Time (UTC), Event, Request, Operation, Class, Instance id, Target, Decision, Flags, Agent name and where it came from, Client, Connection, Peer process id, Peer program, Origin program, OS user, Atlassian user and "Payload bytes". "Show the decrypted payload" opens the content page by page.

**Request trail.** "Request trail" shows every record of one request in order. "Delivered N times" counts how often the answer was handed over. "delivered more than once" and "delivered to a different program" are advisory: they compare the program that asked with the program that received the answer, and they point at something to check, not at proof.

**What the log can and cannot do.** The log shows who decided what and when, and it reveals later changes. It does not stop anyone from acting. It does not protect against malware that runs as your own user while you are logged in: such code can read the keys and rewrite the log. The audited user can also delete the log or confirm destructive actions. Protection against that needs an anchor directory that you cannot rewrite, see [Verify the chain](audit#verify).

The log contains personal data, for example names and comments from Jira and Confluence. Handle exports accordingly.

## Verify the chain {#verify}

Verification checks that the chain is complete and unchanged: every record belongs to its predecessor, the payloads match their fingerprints, and the log head matches the copies kept elsewhere.

::: desktop

atlas-duck verifies the log when it starts and once a day in the background. "Verify now" runs it on demand. The result is one of:

| Result | Meaning |
| --- | --- |
| verified | The chain is intact. |
| verification did not complete | atlas-duck could not finish the check. This is not a finding that something is wrong; try again. |
| integrity incident: see Audit | The check found something wrong. See [Integrity incidents](audit#integrity-incident). |

Two kinds of copies protect the head of the chain. atlas-duck keeps one in the system keychain of your computer. That detects a log that was cut short, but anyone who controls your account can change the keychain too. For more, set an **anchor directory** in Settings ("External anchor directory", "Set anchor directory…"): atlas-duck then writes copies of the log head into a folder, once a day and after important changes such as retention or legal hold changes. This protects against a rewritten history only if you cannot rewrite the folder yourself, for example a share that someone else administers and that only accepts appends. atlas-duck asks you to confirm every change of the anchor directory in its own dialog, because changing or removing it weakens the protection. "Anchor directory" in the Audit window tells you if writing to it fails; the lines then wait and are retried.

:::

::: server

The server does not verify chains in the web pages. Besides each user's chain, the server keeps an **anchor chain** that records the head of every user's chain, at intervals of 15 minutes at most. The operator can run `admin anchor verify`: it recomputes the anchor chain and compares each user's latest anchored head with that user's log. It reports a chain that was cut short, a replaced head record or a missing log. It does not check a user's whole chain or the payloads, and it cannot find a change made before the anchored head. Nothing is detected by itself: a finding appears only when the operator runs the command. The anchor chain is also written by the server, so it protects against a user's mistakes and against partial damage, but not against someone who controls the server and its keys.

:::

## Export the log {#export}

An export copies records of a time range, with their decrypted payloads, so that someone else can check them, for example an auditor or the compliance owner. The files are readable by anyone who can open them. Keep them as safe as the original data.

::: desktop

In the Audit window, "Compliance export" under "Export and backup" has the fields "Export from (UTC)" and "Export to (UTC)". Leave both empty for the whole log. Choose "Export…". atlas-duck shows a warning and asks for the folder in its own dialogs. It writes the export into a new folder and gives it its final name only when everything has been written. A folder whose name still ends in ".partial" is unfinished and must not be handed over. If atlas-duck says that the export is complete but the folder kept its name, remove ".partial" from the end of the name yourself before you hand it over, and do not export again.

When the export is done, atlas-duck shows a SHA-256 of the manifest, the fingerprint that binds the files together. Give it to the recipient **by another channel** than the files. Without it the recipient cannot be sure that the files are the ones you made.

"Full backup" with "Back up now…" is something else: it saves the whole log with its recovery data, so that you can restore it. A backup never contains stored tokens, so after a restore every instance needs its token again. Backups and exports are outside retention; keeping and deleting them is up to you.

:::

::: server

Open the export function on "My audit". Choose "All records" or "From date (UTC)", then "Start export". When "The export is ready" appears, use "Download". The download is a tar file with the records, the decrypted payloads and the other files that the verifier needs. The page also shows the "Manifest SHA-256" and the "Anchor head". Give both to the recipient by another channel than the archive.

Only one export of the same log runs at a time ("An export is already running"). The server deletes export files after 24 hours by default; after that, "This export is no longer available. Start a new one."

Auditors can export any user's log in the same way, see [Exports](auditor#auditor-exports).

:::

## Check an export with verify-export {#verify-export}

The recipient checks an export with the command `atlas-duck verify-export`. It needs no access to your computer or server, and it works offline.

```
atlas-duck verify-export <dir> [--manifest-sha256 <hex>] [--anchor-dir <dir>]
```

It recomputes every record fingerprint and the chain, checks that the decrypted payloads match their fingerprints, and compares the result with what you give it as a **trust root**:

- `--manifest-sha256` is the fingerprint that you passed on separately. It proves that the files are those that were exported.
- `--anchor-dir` is a copy of the anchor directory. It shows that the history matches what was written there earlier.

Both are optional, but without any trust root the result can only be "consistent in itself" (exit 20).

::: server

For a server export, the page shows the full command, including `--anchor-chain <dir>/anchor-chain.jsonl` and `--anchor-chain-head <seq>:<hash>`. The anchor chain in the archive is only an excerpt. Without the head you pin, it is reported as unanchored and counts for nothing, because a consistent excerpt can be made up completely. Take the head from the export page or from the operator, not from the archive. The server image also has the verifier: `atlas-duck-server verify-export …`.

:::

The exit code tells you how far to trust the result:

| Exit code | Meaning |
| --- | --- |
| 0 | Verified against a trust root that covers the whole export. |
| 20 | Consistent in itself, but no trust root covers all of it. The command says "internally consistent; trust root NOT verified". Treat this as not verified. |
| 21 | Tampering, or a fork: two exports that share a start but diverge. |
| 22 | The command could not run: wrong usage (for example `--anchor-dir` together with `--anchor-chain`), unreadable files, an unfinished `.partial` folder, or the atlas-duck app was not found. |

A fork is not necessarily an attack. It happens when a log was restored from a backup while the old installation kept running. The old installation should be shut down.

## Retention and legal hold {#retention}

The audit log is not kept forever. The retention period says how long records stay.

::: desktop

In Settings, "Retention and legal hold" has "Audit retention (days)". The default is 100 days and the minimum is 92. atlas-duck deletes the oldest records only after they are older than the period, and only from the start of the log, so that the chain stays checkable. Each deletion is itself recorded. The payloads are protected by keys per month. A month's key is destroyed when no record needs it any more, so that the deleted records cannot be read from leftovers (crypto-shredding).

"Legal hold (pruning stops)" stops all deletion, and the keys stay. Use it when you must keep records, for example for an investigation. Switching it on or off is recorded in the log and in the anchor directory. Lifting it, or lowering the retention period, needs your confirmation in the app; a change in the configuration file alone does not do it.

Settings shows "Pruning". If atlas-duck was off for a longer time, it catches up slowly, and the page says "pruning is N days behind". "Prune backlog now" lets you catch up at once after you confirm. If pruning was skipped, Settings gives the reason, for example "legal hold is on", "no server date has confirmed the current date yet", or "the system clock is behind the server date". atlas-duck trusts a date only when an Atlassian server has confirmed it, so that a wrong clock cannot delete records early.

Retention does not reach backups, exports, or copies of your data that the operating system made, such as snapshots. They can still hold records that were deleted. Remove them yourself when they are no longer needed. Uninstalling atlas-duck does not delete the log either. "Prepare for removal" tells you how long the newest record has to be kept.

:::

::: server

On the server, the operator sets the retention period, not the individual user, and the log of an active user is kept. This guide describes what the server does when a user is deactivated, for example because they left the organisation: their log stays available to auditors for 365 days by default. After that period the server deletes it, including the user's keys, and records the deletion in the anchor chain. An auditor who needs a log for longer must export it before then. Backups are not touched by this: a backup taken earlier still contains the deleted log, so the operator has to remove old backups too.

:::

## Integrity incidents {#integrity-incident}

An integrity incident means that a check found something that should not be. Possible causes range from a harmless one, such as restoring a backup, to tampering. atlas-duck cannot tell which one it is.

::: desktop

When it happens, atlas-duck records the finding in the log before it does anything else, and shows a red banner in the app and in the tray. The Audit window lists it under "Integrity incidents" with its "Result" and when it was "Detected".

What to do:

1. Do not ignore it, and do not acknowledge it before you know the cause. Tell your compliance owner or administrator.
2. Make an export of the log, so that the state is kept, see [Export the log](audit#export).
3. Find the cause. Typical reasons are: a restore from an older backup, a lost keychain entry, or a used anchor directory that belongs to an earlier installation.
4. When you understand it, choose "Acknowledge integrity incident", write a note (up to 1000 characters) and confirm in atlas-duck's own dialog. The note and your user name are recorded. The red banner then disappears for this incident.

Acknowledging does not repair anything. It records that you have seen the incident and what you concluded. The incident itself stays in the log.

If Settings reports that an anchor entry is missing in the keychain, "Re-anchor…" writes it again from the log as it is now. That is only safe when you trust the log, and it is recorded as an integrity incident that you then acknowledge.

:::

::: server

Integrity incidents, with a banner and an acknowledgement, exist only in the desktop app. The server does not show them on the web pages. When the operator runs `admin anchor verify`, it reports findings that name the user and the sequence number, and exits with an error. If you think that your log is affected, tell your administrator.

:::
