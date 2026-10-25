# Offboarding and changing machines

This is the procedure for retiring a machine that ran atlas-duck, for moving atlas-duck to another machine and for removing it for good. The audit log is a retained record, so the order of the steps matters: secure the log first, then remove the access, then wipe.

Do the steps in this order. Each step says what it does and what it does not do.

## 1. Make a full backup

In Settings, "Recovery and backup", choose "Back up now…". atlas-duck asks for a folder in its own dialog. Choose a folder your organisation controls, not a folder on the machine you are about to wipe.

- The backup is a folder named `atlas-duck-backup-<UTC time>-<first 8 characters of the chain id>` with `audit.db`, `recovery.bin` and `manifest.json`.
- A backup never contains a token, in any form. After a restore, every instance needs its token again.
- The log inside the backup is encrypted. It opens only with the recovery passphrase.
- Backups are outside the retention period and outside the shredding of old months. How long you keep a backup and when you delete it is your responsibility. Records that atlas-duck prunes from the live log stay in older backups.

Make a full backup before every upgrade as well. atlas-duck does not make one by itself, because an automatic copy could outlive the retention period.

## 2. Export the log if someone needs to read it

A backup is for continuing the log. An export is for reading it. If an auditor or lawyer needs the records, use the Audit window, "Export and backup", "Export…". See [verify-export.md](verify-export.md) for what an export holds and how the recipient checks it. An export contains decrypted data. Treat it like the data itself.

## 3. Hand over the recovery passphrase

The recovery passphrase is the only way to open the log after the keychain is lost, from a backup, or on a new machine. Give it to your compliance owner through your usual secret channel, and make sure the owner can retrieve it later. It is not your Atlassian password. atlas-duck does not store it, and nobody can recover it for you.

The recovery note that the app offers after first setup lists host, OS user, `install_id`, `chain_id`, the data folder and these steps, with a blank line to write the passphrase by hand. The note never contains the passphrase.

Changing the passphrase later ("Change recovery passphrase…") re-wraps the same key. Backups made earlier still open with the old passphrase. So changing the passphrase after it leaked does not take access away from someone who already holds a copy of the log or a backup.

## 4. Check the backup

Check that the backup folder holds the three files and that the copy you moved to its final place is complete. atlas-duck has no separate check command for a backup. The check happens when a backup is restored: the restore verifies the whole chain and stops with "The backup does not verify. Nothing was changed." if it is broken. If the machine is being replaced, restore the backup on the new machine before you wipe the old one (step 7). Keep the old machine intact until that restore has worked.

## 5. Run "Prepare for removal"

In Settings, "Prepare for removal". atlas-duck asks for a confirmation in its own dialog. Then it walks through these steps:

1. It offers the export and the backup, and shows how many days the newest audit record is kept. With a legal hold on, it says the record is kept indefinitely.
2. "Delete the stored tokens" deletes every stored token on this machine. Then, for every instance, it shows "Revoke this token in Jira/Confluence (Profile → Personal Access Tokens)" with the instance alias and the identity of the token. You tick "I revoked it" or choose "Skip" for each instance. Do the revocation in Jira or Confluence yourself. A Data Center token stays valid on the server until it is revoked there, even after the machine's copy is deleted. A skipped instance means the token stays valid on the server.
3. Your answers are recorded in the audit log and are final. If atlas-duck is restarted in the middle, the procedure continues. It ends only with "Finish removal".
4. "Finish removal" needs every instance ticked or skipped. It removes the login item (autostart), the command line (the PATH entry on Windows, the `~/.local/bin` link or wrapper and the launcher on macOS and Linux) and `cli.toml`. It keeps the audit log, its keys and its anchors, so the log stays verifiable until the retention period has passed.

When every step worked, atlas-duck says that you can uninstall it now. If the command line could not be removed, it says "Not done" and tells you to remove the `atlas-duck` command and the `cli.toml` file by hand or to run the procedure again.

"Prepare for removal" does not delete the audit log and does not revoke tokens on the server.

## 6. Uninstall

Uninstall the program as described in [install-and-uninstall.md](install-and-uninstall.md). The uninstaller leaves the log, the settings and the keychain entries (see [leftover-paths.md](leftover-paths.md)).

## 7. Restore on the new machine

Install atlas-duck on the new machine. In the first-run wizard, choose "Restore from a backup…" (the wizard offers it before it creates a new log), or use Settings, "Restore backup…" on an installation that already runs.

- atlas-duck shows a confirmation first. In substance: the current audit log, if there is one, is moved to the `archived` folder of the data folder and is never deleted; the backup's log continues as a new segment; open integrity incidents of the old log stay with its archived copy; you need the backup's recovery passphrase, which becomes this log's recovery passphrase; this computer's stored tokens are deleted and none are restored; requests wait while the restore runs.
- If the backup is older than the log on this computer, a second confirmation tells you how many records the restore gives up. Records still in the current log file stay in its archived copy. Records that the file does not hold are kept nowhere.
- A restore gets a new chain id. It does not count as an integrity incident. The restore is recorded in the log and, if an anchor directory is set, in its file for the new chain.
- If the wizard is given an anchor directory that already holds a log of this computer and this user (for example after an archive or an earlier restore), it says so ("The anchor directory already holds an atlas-duck log of this computer and user. This was recorded as an integrity incident; see Audit.") and records an integrity incident. Acknowledge it in the Audit window after you have checked that the old log is yours.
- Enter every instance's token again. Tokens are never restored.
- If atlas-duck is stopped during the restore, the next start finishes it. The window then says "Restore will be completed at the next start". Quit and start atlas-duck again. A restore from Settings can ask for the recovery passphrase again when the key had not been re-sealed yet ("Finish restore").
- After a restore from Settings, atlas-duck offers to change the recovery passphrase. The wizard does not offer this, but Settings has it.

The keychain and the data folder of the new machine must be local. See [install-and-uninstall.md](install-and-uninstall.md).

## 8. Decommission the old installation

A restore on a new machine starts a new branch of the log. If the old installation keeps running after the restore, or someone restores the same backup on two machines, two logs share a common start and then continue with different chain ids. `verify-export` reports two exports like that as a fork (exit code 21), not as tampering, but a fork is still a defect in the record: it is not clear which log is the real one.

Decommission the old installation as soon as the new one works: run "Prepare for removal" on it, uninstall it and wipe it. Do not start the old data folder again after the restore on the new machine. When you must keep the old log, keep it only as an archive and never as a second running copy.

## 9. Wipe

Wipe the old machine. The erasure must also cover the places where copies of the data can remain:

- OS backups and snapshots (Time Machine, Volume Shadow Copy and File History, file system snapshots). They copy the wrapped keys together with the recovery blob, so a month that atlas-duck shredded stays readable from them.
- Swap and hibernation files, and crash dumps of the web view, on disks without full-disk encryption.
- Every backup and export you made (steps 1 and 2) once their own retention allows.

atlas-duck assumes full-disk encryption. It does not exclude its data folder from OS backups, because that would endanger the retention.

## Other recovery situations you may meet

- **The keychain is gone, the log is still there** (reset of the Windows account password by IT, reset of the macOS keychain, a wiped virtual desktop profile, a reinstall). The app starts locked and requests get exit code 9 (`locked`). The credential window offers "Recover this log", which needs the recovery passphrase. Recovery checks the log, re-seals the key into the keychain, rebuilds the anchors and sets every instance to "needs token". The check cannot rule out that the end of the log was cut off, so recovery records an integrity incident that you acknowledge in the Audit window.
- **The passphrase is gone as well.** The only way out is "Archive old DB and start fresh". It moves `audit.db` (with its write-ahead log) to the `archived` folder of the data folder as `audit-<chain_id>-<last record>-<time>.db` and never deletes it. Keep it for its remaining retention period. It can be opened later only with its own recovery passphrase, through a restore. After that, setup runs again with a new passphrase and all tokens must be entered again.
- **An anchor entry is missing from the keychain** while everything else works. Settings shows an "Anchors" section with "Re-anchor…". Re-anchoring writes both anchors again from the log as it is now and is recorded as an integrity incident by design. It cannot show that the end of the log was not cut off, so use it only when you know why the entry is missing.
- **Old installations on the machine.** Settings, "Old installs", lists installations that left an archived log or keychain entries. "Forget" deletes their entries after native confirmations. It keeps the key of the archived log unless you accept the second dialog, and without that key the archive opens only through its own recovery passphrase.

## Keychain mode only (Linux: Secret Service)

Version 1 stores keys and tokens in the OS keychain only. There is no mode that works without one. On Linux this needs a Secret Service provider. Without one, setup stops with "atlas-duck needs a system keyring (Secret Service, e.g. GNOME Keyring or KWallet). Install or unlock one, then restart atlas-duck." The keyring must be local to the host (see [install-and-uninstall.md](install-and-uninstall.md)). On a shared home, each host has its own keyring, its own `install_id` and its own entries.
