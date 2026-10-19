#requires -Version 5.1
<#
.SYNOPSIS
  CI-06 inspection of the NSIS installer script (spec 12.5, L35, V19).

.DESCRIPTION
  Reads the installer.nsi that `cargo tauri build --bundles nsis` generated and passes it, with the
  installerHooks file, tauri.conf.json and crates/ipc/src/paths/mod.rs, to ci/check-installers-lib.mjs
  (tested by ci/check-installers.test.mjs). The check prints the app-data deletion lines it matched
  (the V19 evidence: record them from the first CI run) and fails when
    - a recursive delete under %APPDATA%/%LOCALAPPDATA%/profile names anything but the bundle-identifier
      folder, or is not behind the opt-in checkbox and the not-an-update guard,
    - the bundle identifier equals the data-dir folder name (case-insensitive; the name is read from
      APP_DIR_NAME in paths/mod.rs, not a literal),
    - the hooks file deletes anything under app data or outside $INSTDIR (Delete/RmDir or a
      nsExec/ExecWait command string),
    - the PREINSTALL or PREUNINSTALL hook macro is undefined or not invoked.
  Run from the repository root. Needs node (set up before the build in bundle.yml).

.PARAMETER NsisDir
  Directory holding installer.nsi (target/<triple>/release/nsis/x64).
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$NsisDir
)

$ErrorActionPreference = 'Stop'

$nsi = Join-Path $NsisDir 'installer.nsi'
$hooks = 'app/src-tauri/windows/hooks.nsh'
$conf = 'app/src-tauri/tauri.conf.json'
$pathsRs = 'crates/ipc/src/paths/mod.rs'
$lib = 'ci/check-installers-lib.mjs'

foreach ($f in @($nsi, $hooks, $conf, $pathsRs, $lib)) {
  if (-not (Test-Path -LiteralPath $f -PathType Leaf)) {
    throw "check-installers: $f not found (run from the repository root after the NSIS build)"
  }
}

Write-Host "installer script: $nsi"
& node $lib nsis $nsi $hooks $conf $pathsRs
if ($LASTEXITCODE -ne 0) { throw "check-installers: NSIS inspection failed (exit $LASTEXITCODE)" }
Write-Host 'OK: installer.nsi inspection passed'
