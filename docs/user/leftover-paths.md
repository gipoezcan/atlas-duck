# What stays on the machine after an uninstall

Uninstalling atlas-duck removes the programs and nothing else. The Windows uninstaller, `apt remove`, `apt purge`, `dnf remove` and moving the macOS app to the Trash all leave the items on this page in place. The audit log is a retained record, and the log holds personal data (names, comments, work logs of Atlassian users, and the approvers) for the retention period. It is not erased by an uninstall.

Delete the items below by hand once the retention period of the newest record has passed. "Prepare for removal" in Settings shows the remaining days of the newest record. Do not delete anything while a legal hold is on. See [offboarding.md](offboarding.md) for the full procedure and [threat-model-limits.md](threat-model-limits.md) for copies that this page cannot reach (OS backups, swap files, crash dumps).

Home folders below are the ones of the user who ran atlas-duck. Replace `<user>` with that user's name.

## Windows

| What | Path | Notes |
| --- | --- | --- |
| Data folder | `%LOCALAPPDATA%\atlas-duck` (by default `C:\Users\<user>\AppData\Local\atlas-duck`) | The audit log `audit.db` (with `audit.db-wal` and `audit.db-shm` while it is open), `instance.lock`, `endpoint`, `logs\` (diagnostic logs), `webview\`, `archived\` (audit logs that were set aside). The first-run wizard can place the data folder elsewhere. The real path is the `data_dir` line in `paths.toml`. |
| Pinned path file | `%LOCALAPPDATA%\atlas-duck\paths.toml` | Holds `data_dir`, `config_dir` and the `install_id` of this installation. Read it before you delete anything. |
| Command line record | `%LOCALAPPDATA%\atlas-duck\cli.toml` | Removed by "Prepare for removal". |
| Settings | `%APPDATA%\atlas-duck\config.toml` | In the roaming profile. It may exist on other machines of the same user as well. |
| Keychain entries | Credential Manager, Windows Credentials, entries named `atlas-duck/<install_id>/...` | See "Keychain entries" below. Persistence is "Local". |
| Anchor directory | The folder you chose in Settings, if you chose one | Files named `<chain_id>.jsonl` and `<chain_id>.incident-<n>.json`. Often a share run by someone else. |
| User PATH | `HKCU\Environment\Path` | "Prepare for removal" removes the entry that "Install CLI to PATH" added. The uninstaller does not. |

No runtime socket folder exists on Windows. The app listens on a named pipe `\\.\pipe\atlas-duck-<hash>-<random>`, and the pipe disappears when the app ends.

## macOS

| What | Path | Notes |
| --- | --- | --- |
| Data folder, settings folder and pinned files | `~/Library/Application Support/atlas-duck` | All three are the same folder on macOS. It holds `audit.db`, `instance.lock`, `endpoint`, `logs/`, `webview/`, `archived/`, `config.toml`, `paths-<hostname>.toml` and `cli-<hostname>.toml`. The wizard can place the data folder elsewhere: read `data_dir` in `paths-<hostname>.toml`. |
| Runtime socket folder | `atlas-duck/` inside the per-user temporary folder (`getconf DARWIN_USER_TEMP_DIR`, below `/var/folders/...`), or `~/Library/Caches/atlas-duck` when that path would be too long | Holds only the socket `atlas-duck.sock`. Safe to delete when the app is not running. |
| Command link | `~/.local/bin/atlas-duck` | A link to the program in the app bundle. Removed by "Prepare for removal". |
| Keychain entries | Keychain Access, login keychain, items whose service is `atlas-duck/<install_id>` | See "Keychain entries" below. |
| Anchor directory | The folder you chose in Settings, if you chose one | As on Windows. |

## Linux

| What | Path | Notes |
| --- | --- | --- |
| Data folder | `~/.local/share/atlas-duck` (or `$XDG_DATA_HOME/atlas-duck` if that variable was set when the app first ran) | `audit.db`, `instance.lock`, `endpoint`, `logs/`, `webview/`, `archived/`. The real path is `data_dir` in `paths-<hostname>.toml`. |
| Settings folder | `~/.config/atlas-duck` (or `$XDG_CONFIG_HOME/atlas-duck`, as above) | `config.toml`. |
| Pinned path files | `~/.config/atlas-duck/paths-<hostname>.toml` and `cli-<hostname>.toml` | Always in `~/.config/atlas-duck` under the home folder from the password database, whatever `XDG_CONFIG_HOME` says. |
| Runtime socket folder | `/run/user/<uid>/atlas-duck/`, or `~/.local/state/atlas-duck/run-<hostname>/` when `/run/user/<uid>` is not a directory owned by you with mode 0700 | Holds only the socket `atlas-duck.sock`. Safe to delete when the app is not running. |
| AppImage command wrapper and launcher | `~/.local/bin/atlas-duck`, `~/.local/share/applications/` (a launcher file) | Only if you used "Install CLI to PATH" with an AppImage. Removed by "Prepare for removal". |
| Keychain entries | Secret Service (GNOME Keyring, KWallet), items with the service attribute `atlas-duck/<install_id>` | See "Keychain entries" below. |
| Anchor directory | The folder you chose in Settings, if you chose one | As on Windows. |

`.deb` and `.rpm` packages install their programs in `/usr/bin` and the launcher in `/usr/share/applications`. Removing the package removes those. Nothing in them is user data.

## The `<hostname>` in file names (macOS and Linux)

On macOS and Linux the two pinned files carry the host name, `paths-<hostname>.toml` and `cli-<hostname>.toml`. The host name is lower-cased and reduced to letters, digits, dot, underscore and hyphen. Other characters are escaped, and a very long name is shortened with a hash. Windows has plain `paths.toml` and `cli.toml`.

## Shared home folders (NFS) and one set per host

On macOS and Linux a home folder may be shared between machines. Each host has its own pinned file pair and its own `install_id`, and therefore its own keychain entries. When you clean up, do it for every host that ever ran atlas-duck on that home: delete that host's `paths-<hostname>.toml` and `cli-<hostname>.toml`, and the keychain entries of that host's `install_id`. Do not delete the pair of another host. A host with no pinned file of its own counts as "before first run" and starts the wizard, even if the files of another host are next to it.

The audit log itself must not be shared between hosts. atlas-duck refuses a data folder on a network file system and refuses to start on a data folder that another machine is using ("atlas-duck is running on another machine (<host>) with this data directory").

## Keychain entries

All entries of one installation start with `atlas-duck/<install_id>`. `<install_id>` is 32 lowercase hexadecimal digits. You find it in the `install_id` line of `paths.toml` or `paths-<hostname>.toml`, and in the recovery note, if you saved one. The entries are:

- `atlas-duck/<install_id>/kek`: the key that protects the audit log. The log cannot be read without it, except through the recovery passphrase.
- `atlas-duck/<install_id>/head_anchor` and `atlas-duck/<install_id>/first_retained_anchor`: the anchors that show whether the log was cut at its end or its start.
- `atlas-duck/<install_id>/pat/<instance-id>`: one stored access token per instance. "Prepare for removal" deletes these.
- `atlas-duck/<install_id>/canary`: a test entry that is deleted again right after each start. It is normally absent.

On Windows the name above is the Credential Manager target. On macOS it is the service of the item and the account is the last part (`kek`, `head_anchor`, `pat/<instance-id>`). A machine can hold the entries of several installations, for example after a restore on another machine or after "Archive old DB and start fresh". Only entries of the `install_id` you mean to delete belong to it. The Settings page "Old installs" lists installations that left an archived log or keychain entries, and "Forget" deletes their entries after two native confirmations (the second one asks whether to delete the keys of the archived log too). On macOS, listing old installs reads their entries, and an item that an older or differently signed build of atlas-duck wrote can raise a keychain password prompt.

If you delete the `kek` entry while the audit log still exists and retention has not passed, the log can only be opened again with the recovery passphrase ("Recover this log"). Copies of the log in backups, exports and OS snapshots stay readable by their own means, so a deletion of the data folder and the keychain entries does not reach them.

## Folders you chose yourself

atlas-duck also wrote to folders that you picked. It never removes them.

- **Backups**: a folder `atlas-duck-backup-<UTC time>-<first 8 characters of the chain id>` with `audit.db`, `recovery.bin` and `manifest.json`. A backup holds the whole audit log in the same encrypted form and never holds a token.
- **Exports**: folders `atlas-duck-export-<chain id>-<first seq>-<last seq>-<UTC time>`, with decrypted data. See [verify-export.md](verify-export.md).
- **Recovery notes**: the text files you saved. They never contain the passphrase.
- **Unfinished folders**: a backup or export folder that was cut short by a crash or a failure may be left behind. Names ending in `.partial` are exports. They may hold decrypted audit data: delete them.

Backups and exports are outside retention and outside the shredding of old months. Their lifecycle is up to you.

## Do not send these in a support request

Send `atlas-duck doctor` output and the diagnostic logs in `logs/` only. Never send the audit database, an export, a backup, the `webview` folder or screenshots of previews. The diagnostic logs hold metadata only (operation, request id, instance alias, method, path template, status code, duration, error class), never headers, queries, bodies, titles, keys or passphrases.
