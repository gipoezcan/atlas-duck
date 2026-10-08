# Testing atlas-duck M1

## What this build is

M1 is the skeleton. It is a tray app that starts, runs its startup checks, probes its own sandbox and writes a diagnostic log. There are no Atlassian features yet: no Jira or Confluence connection, no settings window, no script execution. You are testing that it installs, starts, stays alive in the tray, refuses to start twice and behaves sensibly when its data directory is wrong.

## Where to get it

- GitLab release page: https://gitlab.intern.gipmbh.de/gip/teams/g-dux/atlas-duck/-/releases (release `v0.1.0-m1`)
- GitHub Actions artifacts of the latest green `bundle.yml` run (artifact names `bundle-x86_64-pc-windows-msvc`, `bundle-aarch64-apple-darwin`, `bundle-x86_64-apple-darwin`, `bundle-x86_64-unknown-linux-gnu`)

Pick the file for your OS. The builds are unsigned.

## Install

### Windows (NSIS installer, `*-setup.exe`)

1. Run the installer. SmartScreen will warn about an unknown publisher: click **More info**, then **Run anyway**.
2. The installer asks for per-user or all-users. Per-user needs no admin rights; all-users asks for elevation. Either is fine to test, please say which one you used.
3. If WebView2 is missing the installer downloads it (needs internet access).

### macOS (`*.dmg`)

There is one dmg for Apple Silicon (`aarch64`) and one for Intel (`x86_64`). Use the one that matches your Mac.

1. Open the dmg and drag the app to Applications.
2. The app is unsigned (ad-hoc). The first start is blocked by Gatekeeper. Either right-click the app and choose **Open**, then **Open** again, or run:
   `xattr -dr com.apple.quarantine "/Applications/Atlas Duck.app"`

### Linux

- Debian/Ubuntu: `sudo apt install ./atlas-duck_*.deb`
- Fedora: `sudo dnf install ./atlas-duck-*.rpm`
- AppImage: `chmod +x ./atlas-duck_*.AppImage`, then run it. It needs `libfuse2` (`sudo apt install libfuse2` on Ubuntu 22.04).

GNOME has no tray by default. Install the AppIndicator/StatusNotifier extension (package `gnome-shell-extension-appindicator`) and enable it, otherwise you will not see the tray icon. Without a tray the app should still run (no crash, it just has nothing visible); that is expected and worth reporting if it is not what you see.

## First start: the data directory

On a fresh machine the app is "before first run" (the setup wizard comes in a later milestone). In that state it runs, shows the tray icon and writes nothing to disk, so there is no log either. To get a log, give the app a data directory by pinning it in a small file. Create the data directory first (the app never creates it).

Windows (PowerShell):

```powershell
$data = "$env:LOCALAPPDATA\atlas-duck-data"
New-Item -ItemType Directory -Force $data, "$env:LOCALAPPDATAtlas-duck" | Out-Null
$toml = "schema_version = 1`ndata_dir = '$data'`nconfig_dir = '$data'`n"
Set-Content -Path "$env:LOCALAPPDATA\atlas-duck\paths.toml" -Value $toml -Encoding ascii
```

(create `%LOCALAPPDATA%\atlas-duck` first if it does not exist)

macOS:

```sh
data="$HOME/Library/Application Support/atlas-duck/data"
mkdir -p "$data"
host=$(scutil --get LocalHostName | tr 'A-Z' 'a-z')
printf 'schema_version = 1\ndata_dir = "%s"\nconfig_dir = "%s"\n' "$data" "$data" \
  > "$HOME/Library/Application Support/atlas-duck/paths-$host.toml"
```

Linux:

```sh
data="${XDG_DATA_HOME:-$HOME/.local/share}/atlas-duck"
mkdir -p "$data" "$HOME/.config/atlas-duck"
host=$(hostname | tr 'A-Z' 'a-z')
printf 'schema_version = 1\ndata_dir = "%s"\nconfig_dir = "%s"\n' "$data" "$data" \
  > "$HOME/.config/atlas-duck/paths-$host.toml"
```

The host part of the file name must equal your host name in lower case (letters, digits, `-` and inner dots only). If your host name contains anything else, tell us what it is and skip the pinned file.

Data directories after pinning: `%LOCALAPPDATA%\atlas-duck-data`, `~/Library/Application Support/atlas-duck/data`, `$XDG_DATA_HOME/atlas-duck` (default `~/.local/share/atlas-duck`). On a real first run the app will use `%LOCALAPPDATA%\atlas-duck`, `~/Library/Application Support/atlas-duck` and `$XDG_DATA_HOME/atlas-duck`.

## What to check

1. **Tray.** After starting the app a tray (menu bar) icon appears. Its menu has **Quit**. Quit ends the process (check Task Manager, Activity Monitor or `pgrep atlas-duck-app`).
2. **One instance.** Start the app a second time while it is running. No second tray icon appears and no second process stays alive. The second launch just exits (it is forwarded to the first one).
3. **Diagnostic log.** With the pinned file in place, `<data dir>/logs/diag.log` exists after start. Each line is `key=value` metadata. Look for:
   - `event=startup startup_state=...` (`ready` when the data dir is fine)
   - `event=sandbox_probe floor=met|not_met failed=... extra_layers=... engine_version=... worker_version=...`
   The log holds no secrets, paths or Jira data.
4. **The `sandbox_probe` line.** The app starts a confined helper process and checks that the sandbox really blocks file access, network, process spawning and similar. `floor=met` means every check was blocked. `floor=not_met` means at least one was not; `failed=` names which. **Windows is expected to say `floor=not_met failed=connect_loopback+connect_public+cred_read`.** That is a known open item. M1 has no script feature, so nothing is exposed because of it; when scripts arrive they stay disabled on Windows until the floor is met. Linux and macOS are expected to say `floor=met failed=none`.
5. **CLI.** The command-line tool prints exactly one JSON error envelope and exits with code 2 for an unknown command:
   - Windows (PowerShell, in the install folder): `.\atlas-duck.exe bogus; $LASTEXITCODE`
     or `.\atlas-duck-app.exe __cli bogus; $LASTEXITCODE`
   - macOS: `"/Applications/Atlas Duck.app/Contents/MacOS/atlas-duck" bogus; echo $?`
   - Linux: `atlas-duck bogus; echo $?` (AppImage: `./atlas-duck_*.AppImage __cli bogus; echo $?`)
   Expected: a single line of JSON with an error code `usage`, then exit status 2.
6. **Bad data directory (optional).** Edit the pinned file so `data_dir` points at a folder that does not exist, then start the app. A dialog says `data directory <path> not found` and the app does not create the folder. Try a network share or an unmounted volume too: the dialog says `data directory <path> is not on a local filesystem` (or `could not be opened`). Delete or fix the pinned file afterwards.

## Report

Send us:

- OS and version (for example `Windows 11 24H2`, `macOS 15.1 arm64`, `Ubuntu 22.04 GNOME`), CPU architecture
- which package you used (file name) and, on Windows, per-user or all-users
- the lines of `diag.log` that contain `event=` (the whole file is fine, it contains metadata only, no secrets)
- what you expected and what happened, plus screenshots of any dialog or of the tray

## Known limitations

- Builds are unsigned: SmartScreen on Windows, Gatekeeper on macOS.
- Icons are placeholders.
- Startup dialog texts are placeholders and will change (`data directory <path> is not on a local filesystem`, `atlas-duck path settings <path> could not be read`, `data directory <path> could not be opened`).
- Windows reports `floor=not_met`; scripts would be disabled there. There is no script engine in M1.
- macOS `task_for_pid` confinement cannot be proven independently on CI; it is accepted for M1 with that caveat.
- No auto-update.
- Uninstalling keeps your data directory and the pinned file.
- No first-run wizard and no settings window yet, hence the manual pinned file above.
