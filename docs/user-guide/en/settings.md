---
id: settings
title: Settings
mode: both
order: 80
---

::: desktop

In desktop mode, Settings is its own window. Besides the topics on this page it holds your instances ([Instances and tokens](instances-and-tokens)), the limits for requests and [scripts](scripts#limits), retention and legal hold ([Audit log](audit#retention)), pruning, and "Prepare for removal".

:::

::: server

In server mode there is no settings page. The choices that are yours, the language and notifications, sit in the header and on the Approvals page. Instances, keys and the rest of the deployment belong to the admins ([Administration](admin)).

:::

## Language {#language}

atlas-duck is available in English and German. The language applies to the windows and pages, notifications and native dialogs, and to this guide. Text that agents read, audit records, logs, the command line and the operations documentation stay in English.

The choices are:

- **Automatic**: German if the language of your operating system (desktop) or browser (server) is German, otherwise English.
- **Deutsch**
- **English**

::: desktop

Open Settings, find the section "Language" and use the "Language" menu. Every open window switches at once. The choice is an app setting, stored outside the audit log, and it is not audited.

:::

::: server

Use the "Language" menu in the header of any page. The page switches without reloading. The choice is saved for you, so it applies on every browser you sign in from, and it is not audited. If saving fails, atlas-duck says "Saving the language failed. Try again."

:::

Every page of this guide has a link to the same page in the other language, so you can switch here as well.

## Notifications and attention {#notifications}

::: desktop

"Attention mode" in Settings decides what happens when a request needs you:

| Option | What happens |
| --- | --- |
| Show the window without taking focus | The approvals window appears but does not take the keyboard focus. |
| Badge only | No window opens. Only a badge shows that something is pending. |
| Show the window and take focus | The approvals window appears and takes the focus. |

Choose an option and select "Apply". "Presentation mode" is a toggle in the tray menu. It switches to "badge only" and is not saved in Settings.

:::

::: server

On the Approvals page, choose "Enable notifications" to let your browser alert you when a request needs your decision. Your browser asks for permission. The page then says "Notifications are on.", or "Notifications are blocked in this browser." if you refused. The notification has the fixed title "atlas-duck: approval needed" and shows only the operation id, never text written by an agent.

:::

::: desktop

## Install the command line {#cli-install}

Agents call the `atlas-duck` command from a terminal. The section "Command line" in Settings tells you whether it is on your PATH ("The atlas-duck command is on your PATH." or "...is not on your PATH.") and has the buttons "Install CLI to PATH" and "Remove CLI from PATH". What the install does depends on the system:

| System | Install |
| --- | --- |
| Windows | Adds the install folder to your user PATH. |
| macOS | Creates the link `~/.local/bin/atlas-duck` to the program inside the app. |
| Linux AppImage | Writes a wrapper script `~/.local/bin/atlas-duck` and a launcher in `~/.local/share/applications`. |
| Linux `.deb` and `.rpm` | Nothing to do: the command is on the PATH already, and Settings says so. |

After an install, open a new terminal and restart your MCP clients so they find the command. If `~/.local/bin` is not on the PATH of your terminals, Settings tells you to add it. If you move or rename the AppImage file, choose "Install CLI to PATH" again: until then the wrapper reports that the AppImage was not found.

## Backup and restore {#backup}

The section "Recovery and backup" in Settings protects your audit log.

- "Back up now…" makes a full backup into a folder you choose. Make one before every upgrade.
- Backups never contain stored tokens. After a restore every instance needs its token again.
- Backups and exports are outside retention and crypto-shredding: keeping and deleting them is up to you.
- "Restore backup…" replaces this audit log with the log of a backup. atlas-duck asks you to confirm in its own dialogs and to enter the recovery passphrase of the backup. Requests wait while the restore runs. Records written after the backup are no longer in the log, and stored tokens are deleted.
- "Change recovery passphrase…" opens the credential window. The recovery passphrase unlocks the audit log after a keychain loss, from a backup or on a new machine.

Before you uninstall atlas-duck, run "Prepare for removal": it can make a backup, deletes the stored tokens, asks you to revoke each token on its server, and removes the login item and the command line. The audit log, its keys and its anchors stay on the computer.

:::
