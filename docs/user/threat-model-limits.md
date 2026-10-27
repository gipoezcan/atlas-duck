# What the audit log protects against, and what it does not

atlas-duck keeps a tamper-evident audit log of what agents asked for and what people approved. This page states the limits of that protection in plain terms. Read it before you rely on the log for compliance, and give it to the people who will audit it.

## What the log protects against

- **Theft of the audit file.** The records are encrypted. A copy of `audit.db` without the keychain entries or the recovery passphrase does not open.
- **Casual or accidental change.** Every record is chained to the one before it. A changed, removed or inserted record breaks the chain, and verification (daily, at start, and "Verify now" in the Audit window) finds it.
- **Silent cutting of the end of the log.** The newest record is also remembered outside the file, in the OS keychain (the head anchor). A log that ends earlier than that anchor fails verification.
- **Silent cutting of the start of the log.** Pruning writes a prune log. The first record that is kept is remembered in the keychain (the first-retained anchor) and must match the prune log.
- **Rolled-back or rewritten history, only with an external anchor directory that the audited user cannot rewrite.** If you set an anchor directory in Settings, atlas-duck writes copies of the head to it. That protects against rollback only if the audited user cannot change that folder, for example a write-once or append-only share run by someone else.

## What it does not protect against

- **Malware running as the same OS user while the session is unlocked.** Such a program can call the keychain, rewrite the chain and re-seal the anchors. The log cannot tell it from you.
- **A script that escapes its sandbox.** If script confinement is degraded (Settings shows "scripts run with degraded confinement"), an escape from the script worker equals code running as your user, which is the case above. Allowing scripts with degraded confinement is a decision you confirm in a native dialog.
- **The audited user.** The local log does not protect against the user whose actions it records, if that user deliberately deletes data, reinstalls, or confirms destructive actions in atlas-duck: a prune after a clock jump, removing the anchor directory, acknowledging their own integrity incidents. To hold a record against that user, you need an external anchor directory that the user cannot rewrite, run by someone else. Its immediate lines record these actions.
- **An anchor directory that the audited user can write to.** It protects against nothing in this list. Ask who can write to it.
- **Copies outside the log.** Everything in the next section.

## Copies that retention and shredding do not reach

Old months are erased by destroying their key, but only a whole month at a time, only after the retention period, only when no kept record uses that key, and never during a legal hold. This does not reach:

- backups and exports you made. They are outside retention. How long you keep them and when you delete them is up to you;
- crash dumps of the web view processes;
- swap and hibernation files on a disk without full-disk encryption;
- OS backups and snapshots of the data folder (Time Machine, Volume Shadow Copy and File History, file system snapshots). They copy the wrapped keys together with the recovery data, so a "shredded" month stays recoverable from them.

atlas-duck assumes full-disk encryption on the machine. Your erasure procedure must cover all of the copies above. atlas-duck does not exclude its data folder from OS backups, because that would endanger retention.

## Exports and backups

- **An export is trustworthy only against an anchor directory or against a manifest SHA-256 that you got through another channel.** An export alone shows no more than that it is consistent with itself. See [verify-export.md](verify-export.md) for the exit codes and what each trust root proves.
- An export holds decrypted data. A backup holds the encrypted log and the recovery data, and never a token.
- The log records who approved what. The person who approves a request acts as the owner of the access token and is the accountable person. The agent name and program paths in the log are advisory. They are claims of the calling program, not proof.

## Keys, tokens and passphrases

- **Keychain mode only.** Version 1 keeps the keys, the anchors and the tokens in the OS keychain. There is no mode without a keychain. On Linux this needs a Secret Service provider, or setup stops (see [install-and-uninstall.md](install-and-uninstall.md)).
- **The keychain must be local to the host.** Keyring files on a network file system are refused, because two hosts would overwrite each other's entries. The check is a heuristic.
- **The recovery passphrase is not your Atlassian password.** It opens the log after a keychain loss, from a backup and on a new machine. Changing it re-wraps the same key. Earlier backups still open with the old passphrase, so a leaked passphrase is not undone by changing it.
- **Stored tokens are never recovered or backed up.** After a restore or a keychain loss, every instance needs its token again.
- **A Data Center token stays valid on the server until it is revoked there.** Deleting it from atlas-duck does not revoke it. "Prepare for removal" asks you to revoke each one in Jira or Confluence (Profile → Personal Access Tokens) and records your answer. See [offboarding.md](offboarding.md).
- **Re-anchoring is an incident by design.** If an anchor entry is missing from the keychain, "Re-anchor…" writes it again from the log as it is. It is recorded as an integrity incident, because it cannot prove that the end of the log was not cut off.
- **"Forget" for an old installation** deletes its keychain entries. The keys of its archived log are kept unless you also accept the second dialog. Without those keys the archive opens only through its own recovery passphrase.

## Clocks

atlas-duck dates records from the system clock and checks the date against the `Date` header of Atlassian answers. When the clock is wrong it flags the affected records and keeps them for the full retention period. It also limits how far one prune can move the cutoff, so a clock set far forward cannot delete the log at once. One case cannot be detected: the app was off for a long time, and the local clock and the clocks of every configured server are all too far ahead. That looks like honest time. The limit then only slows the pruning to at most two days of cutoff per run, one run per day.

## Personal data in the log

The log holds personal data of Atlassian users (names, comments, work logs) and of approvers, for the retention period. The following columns are plaintext in the file: the target tag, agent name, the paths of the calling programs (which may contain a user name), the OS user, the Atlassian user and its key, and timestamps. The target holds a keyed tag, not a guessable hash of the real target.

- Erasure is possible only by whole month after retention (see above). Version 1 refuses erasure of single records or of one person's data, because deleting or rewriting a record breaks the chain and the log is kept for accountability and for defending legal claims.
- Version 1 has no search by person. A request from a data subject is answered from a compliance export (decrypted payloads) or from the filters of the Audit window. The filters match the plaintext columns only.
- Uninstalling does not erase the log. [leftover-paths.md](leftover-paths.md) lists what stays.
- Reflect this in your records of processing.

## What to send when you ask for support

`atlas-duck doctor` output and the diagnostic logs in the `logs` folder of the data folder only. The diagnostic logs hold metadata: operation, request id, instance alias, method, path template, status, duration and error class. They never hold headers, query strings, JQL or CQL, bodies, titles, keys, Atlassian error text or the contents of a panic. Never send the audit database, an export, a backup, the `webview` folder or a screenshot of a preview.

## Running the app and the CLI

On Windows, run the app and the command line at the same privilege level. An elevated app with a non-elevated CLI can make the CLI fail its identity check and exit with code 5 (`server_identity`). See [install-and-uninstall.md](install-and-uninstall.md).

## Two installations must not run in parallel

A restored log starts a new chain. An old installation that keeps running next to the new one produces a fork, which `verify-export` reports with exit code 21. Decommission the old installation. See [offboarding.md](offboarding.md).

## Packages

The release workflow signs the Windows installer and the macOS bundle. The Linux packages are not signed in this build. Get them only from the project's release page.

Server mode (atlas-duck running in the cluster) has its own page: [docs/server/threat-model.md](../server/threat-model.md).
