# Install, upgrade and uninstall

This page is for the people who install atlas-duck and for the operators who look after it.
It states what the installers do, what they leave behind and what you must do yourself.
The list of files that stay after an uninstall is in [leftover-paths.md](leftover-paths.md).
Moving to another machine or removing atlas-duck for good is in [offboarding.md](offboarding.md).

## Supported systems

| System | Versions | Package |
| --- | --- | --- |
| Windows | Windows 10 22H2 and later, Windows 11 (x86_64) | NSIS installer |
| macOS | macOS 13 and later (arm64 and x86_64, one build each) | `.dmg` |
| Ubuntu | 22.04 and later | `.deb`, AppImage |
| Fedora | 40 and later | `.rpm`, AppImage |

## What is installed

Three programs are installed side by side:

- `atlas-duck-app`: the tray application with the approval windows. It holds the audit log and the stored tokens.
- `atlas-duck`: the command line and the MCP server that agents call.
- `atlas-duck-sandbox`: the helper that runs agent scripts.

The command line and the MCP server do nothing on their own. They ask the running app, and the app asks you before any write.

## Windows

- The installer offers a per-user and a per-machine install. The per-machine install (Program Files) is recommended, because ordinary users cannot change the program files.
- In both modes the installer gives the two AppContainer groups (`ALL APPLICATION PACKAGES` and `ALL RESTRICTED APPLICATION PACKAGES`) read and execute rights on the script helper and on the DLLs in the install folder. Scripts need this. If this step fails, the installer reports a non-zero exit code. The app still starts but reports that script confinement is not met, and a per-machine install then needs a repair install.
- The installer downloads the WebView2 bootstrapper if WebView2 is missing.
- The command line is not on your PATH after the install. Use Settings, "Install CLI to PATH" (see below).

### Upgrade on Windows

Before it copies files, the installer asks a running atlas-duck to quit and waits up to 90 seconds for it. The app then shuts down the normal way and records `APP_STOP` with the reason `installer`. After the wait, the installer stops every remaining atlas-duck process that runs from the install folder (`atlas-duck-app.exe`, `atlas-duck.exe`, `atlas-duck-sandbox.exe`). This includes long-running `atlas-duck mcp` processes, which would otherwise lock `atlas-duck.exe`. Processes of another atlas-duck install, and other programs in the same folder, are left alone.

If this step fails or times out, the installer writes a line to its log and goes on. A file that is still in use then stops the copy with the usual installer retry dialog.

The last page of the installer says: "Restart your MCP clients so they use the new version." Do this. An MCP client that keeps its old `atlas-duck mcp` process talks to the old version.

### Uninstall on Windows

The uninstaller removes the program files and nothing else. It never touches the audit log, the settings, the pinned path files, the anchor directory or the stored keys and tokens. The uninstaller shows Tauri's "delete app data" check box, but the box is switched off in code and deletes nothing. The folder name that option would clean (from the app identifier `dev.atlasduck.desktop`) also differs from the data folder name `atlas-duck`, so even that option could not reach the audit log. A CI check inspects every built installer and package script for both rules.

## macOS

Open the `.dmg` and move the app to Applications. The app is signed and notarized for release builds.

To put the `atlas-duck` command on your PATH, use Settings, "Install CLI to PATH". On macOS this creates a symbolic link `~/.local/bin/atlas-duck` that points at the `atlas-duck` program inside the app bundle. If `~/.local/bin` is not on the PATH of your terminals, Settings says so and tells you to add it. The installation into `/usr/local/bin` that asks for an administrator password is not part of version 1.

To uninstall, run "Prepare for removal" first (see below), then move the app to the Trash. This leaves everything listed in [leftover-paths.md](leftover-paths.md).

Replacing the app while it runs is handled like a Linux package upgrade (next section): the old app keeps running until you restart it.

## Linux

### .deb and .rpm

The package installs `atlas-duck-app`, `atlas-duck` and `atlas-duck-sandbox` in `/usr/bin` and one launcher, `/usr/share/applications/atlas-duck.desktop`. The command line is on the PATH at once.

- The `.deb` depends on `libwebkit2gtk-4.1-0` and `libayatana-appindicator3-1`.
- The `.rpm` depends on `webkit2gtk4.1` and `libayatana-appindicator-gtk3`.

`apt remove`, `apt purge` and `dnf remove` leave your data, settings and keychain entries in place. The packages contain no step that purges user data. This is on purpose: the audit log must survive an uninstall until its retention period has passed.

### AppImage

Start the AppImage file. The app does not install `atlas-duck` on the PATH by itself. Use Settings, "Install CLI to PATH". This writes:

- a small wrapper script `~/.local/bin/atlas-duck` that starts your AppImage file with the CLI entry point, and
- a launcher in `~/.local/share/applications`.

The wrapper has the absolute path of the AppImage file in it. If you move or rename the AppImage, run "Install CLI to PATH" again. Until then the wrapper prints a message that the AppImage was not found and exits with code 5.

### Upgrading a Linux package or the macOS app

A package upgrade replaces files under a running app. The old app keeps serving until it is restarted. Script runs are refused until then, and the tray shows "Updated — restart to apply". The CLI reports `app_upgraded` when its build differs from the running app. Quit and start atlas-duck again, and restart your MCP clients.

### Linux needs a system keyring

atlas-duck keeps its keys and your tokens in the operating system keychain. On Linux that means a Secret Service provider with a usable default collection, for example GNOME Keyring or the Secret Service interface of KWallet. There is no other storage mode in version 1 and no silent fallback.

If no provider answers on the session bus, or its default collection cannot be unlocked, the first-run wizard stops before it creates anything. It shows this text and a Quit button:

> atlas-duck needs a system keyring (Secret Service, e.g. GNOME Keyring or KWallet). Install or unlock one, then restart atlas-duck.

Nothing is written at that point. Install or unlock a keyring and start atlas-duck again. If the audit log already exists and the keyring is not reachable at login (for example the keyring is not unlocked yet at autostart), the app retries for one to two minutes, shows "Waiting for keyring" in the tray, refuses requests with exit code 9 (`locked`) meanwhile and offers a retry.

### The keyring must be on a local disk

If your home directory is shared over NFS, the keyring files in it are shared too. The keyring daemon of each host keeps the file in memory and rewrites all of it on every change, so two hosts would overwrite each other's keys. atlas-duck therefore checks, at first run and at every start, that the keyring files are on a local disk. It checks `~/.local/share/keyrings` (or `$XDG_DATA_HOME/keyrings`), the KWallet folder `$XDG_DATA_HOME/kwalletd` and, on macOS, `~/Library/Keychains`. The check is a heuristic, because the Secret Service interface does not say where it keeps its file. Other providers are not supported on a shared home.

If the keyring is not local, the wizard stops, and a later start stays locked with the text "atlas-duck is locked (keyring_not_local)". Requests get exit code 9. atlas-duck writes nothing to the keyring in that state. There is no way around this in version 1: use a machine with a local home directory, or a local keyring.

The data folder must be on a local disk as well. A network folder (UNC path, NFS, SMB and similar) is refused, because SQLite's write-ahead log and file locking are not safe there and two hosts could share one audit log.

## Install the command line on the PATH

Settings has "Install CLI to PATH" and "Remove CLI from PATH".

- Windows: the install folder is added to your user PATH (`HKCU\Environment\Path`). Open a new terminal afterwards.
- macOS: a link `~/.local/bin/atlas-duck`, as above.
- Linux AppImage: a wrapper and a launcher, as above.
- Linux `.deb` and `.rpm`: nothing to do. Settings says the command is already on the PATH.

The app records where it is installed in the machine-local file `cli.toml` (`cli-<hostname>.toml` on macOS and Linux). "Prepare for removal" and "Remove CLI from PATH" delete it again.

## Run the app and the CLI at the same privilege level (Windows)

The CLI checks that the program it talks to is really your own atlas-duck. It does this by comparing the user of the app process with your own user. If you start the app elevated ("Run as administrator") and the CLI or the agent's terminal is not elevated, Windows can refuse the CLI access to the elevated process. The CLI then fails closed: it answers `server_identity` and exits with code 5. This is not a bug in your setup, it is the check working against a mixed setup.

Start both at the same level. For normal use that means: do not run atlas-duck as administrator. If you must run the app elevated, run the agent and its terminal elevated too.

## Uninstall: what you must do yourself

An uninstall removes programs, not data. The audit log, its keys, your settings and the keychain entries stay, because the log is a retained record. To remove atlas-duck cleanly:

1. Read [offboarding.md](offboarding.md). If the machine is being retired or the log must move, make an export, a backup and a passphrase handover first.
2. Open Settings and run "Prepare for removal". It deletes the stored tokens, asks you to revoke each token on its Jira or Confluence server, removes the login item and the command line, and keeps the audit log.
3. Uninstall the package or move the app to the Trash.
4. Delete the leftover folders and keychain entries only after the retention period has passed. They are listed in [leftover-paths.md](leftover-paths.md).

Stored tokens on the server stay valid until you revoke them there. Deleting the token on the machine does not revoke it.

## Reinstall

If you install atlas-duck again on a machine with an existing data folder, the new installation continues the existing audit log. The first-run wizard recognises the log, verifies it and does not ask for a new recovery passphrase. If the keychain entries are gone (for example after a reset of the Windows account password by IT, or a reset of the macOS keychain), the app starts locked and offers "Recover this log", which needs the recovery passphrase. See [offboarding.md](offboarding.md).

## Packages and signatures

- The release workflow signs the Windows installer (Authenticode) and the macOS bundle (Developer ID, notarized) and verifies both signatures before it publishes. Which certificates a given release uses is decided by the project; check the signature on the file you downloaded (the Windows file properties, or `spctl` on macOS).
- The Linux packages (`.deb`, `.rpm`, AppImage) are not signed in this build of the project: no Linux signing step exists in the release workflow. Get them only from the project's release page. If the project later signs them, this page will name the published key.
