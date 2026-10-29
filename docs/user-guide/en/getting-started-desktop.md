---
id: getting-started-desktop
title: Getting started (desktop)
mode: desktop
order: 20
---

## Install {#install}

atlas-duck installs three programs side by side: `atlas-duck-app` (the tray application with the approval windows), `atlas-duck` (the command line and the MCP server that agents call) and `atlas-duck-sandbox` (the helper that runs agent scripts). The command line and the MCP server do nothing on their own. They ask the running app, and the app asks you before any write.

| System | Versions | Package |
| --- | --- | --- |
| Windows | Windows 10 22H2 and later, Windows 11 (x86_64) | NSIS installer |
| macOS | macOS 13 and later (arm64 and x86_64, one build each) | `.dmg` |
| Ubuntu | 22.04 and later | `.deb`, AppImage |
| Fedora | 40 and later | `.rpm`, AppImage |

- **Windows:** the installer offers a per-user and a per-machine install. The per-machine install (Program Files) is recommended, because ordinary users cannot change the program files. Do not run atlas-duck as administrator. If the app runs elevated and the agent's terminal does not, the command line refuses to talk to it; start both at the same privilege level.
- **macOS:** open the `.dmg` and move the app to Applications.
- **Linux:** atlas-duck keeps its keys and your tokens in the operating system keychain. That needs a Secret Service provider with a usable default collection, for example GNOME Keyring or KWallet. Without one, the first start stops and says: "atlas-duck needs a system keyring (Secret Service, e.g. GNOME Keyring or KWallet). Install or unlock one, then restart atlas-duck."

The `atlas-duck` command is not on your PATH after the install, except with the Linux `.deb` and `.rpm` packages. See [Install the command line](settings#cli-install).

An uninstall removes the programs and nothing else: the audit log, your settings and your keychain entries stay. Use "Prepare for removal" in Settings before you uninstall.

## First start and setup {#first-start}

The first time atlas-duck starts, the setup window leads you through these steps in order. Until setup is finished, requests from agents are refused and the window shows "Setup required" with the number of refused requests.

1. **Where atlas-duck keeps its data.** The audit log and the settings live in one folder on a local disk. Choose "Use the default folder" or "Choose another folder…". A network folder is refused. If the folder already holds an audit log, atlas-duck says "An audit log already exists here", keeps it, and you choose "Continue with this log".
2. **Anchor directory (optional).** For advanced use: a folder outside this computer, for example a network share, to which atlas-duck also writes its audit anchors. You can skip it and change it later in Settings.
3. **Recovery passphrase.** It lets you read the audit log again if this computer's keychain is lost. You enter it twice in the credential window, and atlas-duck cannot show it again. It is not your Atlassian password. Store it where your compliance owner can retrieve it.
4. **Creating the audit log.** atlas-duck creates the log.
5. **Recovery note.** The credential window offers to save a note with your install id, chain id and data folder. Save it if you want one.
6. **Add your Jira or Confluence instances.** See [Connect an instance](#connect-instance). You can also do this later.
7. **Command line.** "Install CLI to PATH" puts the `atlas-duck` command on your PATH so agents can find it.
8. **Agent onboarding.** Instructions to copy into the `CLAUDE.md` or `AGENTS.md` of the repositories your agents work in. See [Agents (desktop)](agents-desktop).
9. **Finish setup.** "Setup is complete": atlas-duck is ready and the approvals window opens.

If you already have a backup of an atlas-duck audit log, the setup window offers "Restore from a backup…" instead of a new log, on the anchor directory step, before the log exists. You then enter the recovery passphrase of the backup and no new passphrase is set.

## Connect an instance {#connect-instance}

An instance is one Jira or Confluence Data Center server. In desktop mode you define your own, either in the setup window or later in Settings under "Add an instance".

1. Enter an alias, the product (Jira or Confluence) and the base URL. The URL must use https and include the context path. If the server uses an internal certificate authority, choose "Use a custom CA certificate".
2. Choose "Add instance". atlas-duck shows the alias and the origin in its own dialog; confirm it ("Confirm instance").
3. Add your personal access token. The setup window leaves this for Settings: "Add its token in Settings after setup."

Details, fields and the token steps are in [Instances and tokens](instances-and-tokens).

## The tray menu {#tray}

atlas-duck runs in the system tray. Closing a window only hides it. The tooltip shows how many requests are pending ("atlas-duck: N pending"). The menu has these entries:

| Entry | What it does |
| --- | --- |
| Open approvals (N) | Opens the approvals window, or the window atlas-duck needs from you instead. N is the number of pending requests. |
| Unlock… | Opens the credential window. Only while atlas-duck is locked. |
| Retry keychain | One more attempt to reach the keychain. Only while the keychain is unavailable. |
| Presentation mode | Switches to "badge only" without confirmation, until you switch it off again. |
| Help | Opens this guide. |
| Quit | Shuts atlas-duck down. |

Status lines above the entries show why atlas-duck cannot serve, for example "Locked", "Setup required" or "Waiting for keyring".
