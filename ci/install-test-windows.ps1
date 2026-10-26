# ci/install-test-windows.ps1 -Mode CurrentUser|AllUsers -InstallerDir <dir> -FixtureDir <dir> [-TimeoutSeconds 90]
#
# M10 Task 27 (spec sec. 12.2, sec. 12.5, sec. 13 I-40, I-45, S-04, sec. 15 V19, V32; PD-179):
# uninstall and reinstall of the NSIS package keep the user's data, the installer's quit request
# drains the running app (APP_STOP {installer}), and the upgrade drain terminates nothing outside
# $INSTDIR. CI only: it installs the app, writes this user's pinned paths.toml
# (ci/pinned-fixture.ps1), writes keychain entries in this user's Credential Manager (through the
# fixture test binary) and kills what it started.
#
# -FixtureDir holds the ci_fixture test binary (artifact ci-fixture-x86_64-pc-windows-msvc, built
# by bundle.yml from crates/audit/tests/ci_fixture.rs). The job has no cargo. Credential Manager
# does not bind an item to the executable that created it, so the installed release app reads the
# entries the test binary wrote, without a prompt (PD-179).
#
# Flow (each wait is bounded):
#   1. pinned fixture -> ci_fixture_store (a store with the real OS keystore, anchor dir, pinned
#      install_id) -> ci_fixture_entries (E0)
#   2. install (setup /S /<Mode>) -> start --background -> `event=serve_started serve_state=core`
#      (the core appended APP_START) -> `atlas-duck doctor` (exit 0, the core answers) -> snapshot
#      S0 of the pinned file and the config dir
#   3. silent uninstall WITH THE APP RUNNING: the uninstaller's drain is the quit. Asserts the diag
#      lines `event=os_end_session reason=installer_quit` and `event=app_stop reason=installer`, the
#      app process gone, the install dir without our exes, the uninstall key gone; then (after the
#      quit, PD-157) pinned file and config dir equal S0, audit.db present, the anchor dir still
#      holds its files, E1 == E0
#   4. full snapshot S1 (app stopped) -> reinstall -> S2 == S1 (the install touches no user data)
#   5. Windows upgrade drain: decoy (a copy of PING.EXE named atlas-duck-app.exe in the runner temp
#      dir, started first) -> start the app -> install the SAME build again (setup /S /<Mode>, the
#      app running) -> the app is gone with a second `app_stop reason=installer`, the decoy is alive
#   6. full snapshot S3 -> silent uninstall with the app stopped -> S4 == S3, E2 == E0 -> reinstall
#      -> S5 == S4
#   7. ci_fixture_verify (Ready, full verification passes, no incident, APP_START/APP_STOP pairs
#      chained, at least 2 starts)
#   8. S-04 against the installed app (ci/s04-no-debug-port.ps1, TAURI_WEBVIEW_AUTOMATION=true)
#   V32: the WebView2 runtime version is printed (RUNTIME_VERSIONS).
#
# The silent switches: setup /S /CurrentUser|/AllUsers (Tauri's installer.nsi, MultiUser.nsh, as
# ci/install-probe-windows.ps1); uninstall.exe /S. The same-version reinstall under /S: the
# "already installed" page of Tauri's installer.nsi (PageReinstall) is a custom page, and NSIS runs
# no page callbacks in a silent install, so /S installs over the existing version without a prompt
# and without the page's "uninstall first" choice; the running app is drained by the PREINSTALL hook
# (T23), and Tauri's own CheckIfAppIsRunning selects by path (a Restart Manager session on
# $INSTDIR\atlas-duck-app.exe, task-23-report finding 3), so the decoy outside $INSTDIR is not
# selected by either. Not confirmed from the template text in this task: if the first CI run shows
# a hang at step 5, the installer timeout (300 s) names it. The NSIS uninstaller copies itself to
# %TEMP% and returns at once, so the script waits (bounded) for the uninstall key and the app exe
# to disappear.
[CmdletBinding()]
param(
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Mode = 'CurrentUser',
    [string]$InstallerDir = 'dist',
    [string]$FixtureDir = 'ci-fixture',
    [int]$TimeoutSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProductName = 'Atlas Duck'
$AppExe = 'atlas-duck-app.exe'
$CliExe = 'atlas-duck.exe'
$WorkerExe = 'atlas-duck-sandbox.exe'
$UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' + $ProductName
$WebView2ClientKey = 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'

function Write-Step([string]$Text) { Write-Host "== $Text" }
function Fail([string]$Text) { throw "install-test: $Text" }

# --- registry, paths ------------------------------------------------------------------------

function Get-InstallLocation([string]$Hive) {
    $base = if ($Hive -eq 'HKLM') { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::CurrentUser }
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey($base, $view)
        try {
            $key = $root.OpenSubKey($UninstallKey)
            if ($null -ne $key) {
                try {
                    $value = $key.GetValue('InstallLocation')
                    if ($null -ne $value -and "$value" -ne '') { return ("$value").Trim('"') }
                } finally { $key.Dispose() }
            }
        } finally { $root.Dispose() }
    }
    return $null
}

# V32: the Evergreen WebView2 runtime version (pv of its EdgeUpdate client key, machine or user).
function Get-WebView2Version {
    foreach ($spec in @(
            @([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32),
            @([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64),
            @([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64))) {
        $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey($spec[0], $spec[1])
        try {
            $key = $root.OpenSubKey($WebView2ClientKey)
            if ($null -ne $key) {
                try {
                    $pv = $key.GetValue('pv')
                    if ($null -ne $pv -and "$pv" -ne '' -and "$pv" -ne '0.0.0.0') { return "$pv" }
                } finally { $key.Dispose() }
            }
        } finally { $root.Dispose() }
    }
    return 'unknown'
}

# --- the diag log ---------------------------------------------------------------------------

# Every line of the diag log; the app keeps it open, so every share flag is passed.
function Get-LogLines([string]$LogPath) {
    $lines = @()
    if (-not (Test-Path -LiteralPath $LogPath)) { return $lines }
    $stream = [System.IO.File]::Open($LogPath, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    try {
        $reader = New-Object System.IO.StreamReader($stream)
        try {
            while ($null -ne ($line = $reader.ReadLine())) { $lines += $line }
        } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    return $lines
}

function Get-LogCount([string]$LogPath, [string]$Pattern) {
    return @(Get-LogLines $LogPath | Where-Object { $_ -match $Pattern }).Count
}

function Show-Log([string]$LogPath) {
    Write-Host "---- $LogPath (last 60 lines) ----"
    Get-LogLines $LogPath | Select-Object -Last 60 | ForEach-Object { Write-Host $_ }
    Write-Host '----'
}

$PatServing = '(^|\s)event=serve_started(\s.*)?\sserve_state=core(\s|$)'
$PatInstallerQuit = '(^|\s)event=os_end_session(\s.*)?\sreason=installer_quit(\s|$)'
$PatStopInstaller = '(^|\s)event=app_stop(\s.*)?\sreason=installer(\s|$)'

# Waits until the log holds more than $Known lines matching $Pattern. Fails when $Process exits
# first (if given) or after $Seconds.
function Wait-LogLine([string]$LogPath, [string]$Pattern, [int]$Known, $Process, [int]$Seconds, [string]$What) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if ((Get-LogCount $LogPath $Pattern) -gt $Known) { return }
        if ($null -ne $Process -and $Process.HasExited) {
            Show-Log $LogPath
            Fail "$AppExe exited with code $($Process.ExitCode) before it logged $What"
        }
        Start-Sleep -Milliseconds 250
    }
    Show-Log $LogPath
    Fail "no new $What line within $Seconds s in $LogPath"
}

# --- processes ------------------------------------------------------------------------------

function Start-App([string]$InstallDir) {
    $p = Start-Process -FilePath (Join-Path $InstallDir $AppExe) -ArgumentList '--background' `
        -WorkingDirectory $InstallDir -PassThru
    $null = $p.Handle
    return $p
}

function Wait-Exit($Process, [int]$Seconds, [string]$What) {
    if (-not $Process.WaitForExit($Seconds * 1000)) { Fail "$What did not exit within $Seconds s" }
}

function Stop-Everything {
    foreach ($name in @('atlas-duck-sandbox', 'atlas-duck-app', 'atlas-duck')) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

# Runs an executable with a bounded wait; returns @{ ExitCode; Out; Err }.
function Invoke-Bounded([string]$File, [string[]]$Arguments, [int]$Seconds, [string]$What) {
    $tag = [guid]::NewGuid().ToString('N')
    $out = Join-Path $script:work "$tag.out"
    $err = Join-Path $script:work "$tag.err"
    $p = Start-Process -FilePath $File -ArgumentList $Arguments -PassThru -NoNewWindow `
        -RedirectStandardOutput $out -RedirectStandardError $err
    $null = $p.Handle
    if (-not $p.WaitForExit($Seconds * 1000)) {
        try { $p.Kill() } catch { }
        Fail "$What did not finish within $Seconds s"
    }
    return @{ ExitCode = $p.ExitCode; Out = (Get-Content -LiteralPath $out -Raw); Err = (Get-Content -LiteralPath $err -Raw) }
}

function Invoke-Setup([string]$Setup) {
    $r = Invoke-Bounded $Setup @('/S', "/$Mode") 300 "setup /S /$Mode"
    if ($r.ExitCode -ne 0) { Fail "setup /S /$Mode exited with $($r.ExitCode)" }
}

function Wait-Installed([int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $dir = Get-InstallLocation $script:hive
        if ($null -ne $dir -and (Test-Path -LiteralPath (Join-Path $dir $AppExe))) { return $dir }
        Start-Sleep -Milliseconds 500
    }
    Fail "no installed $AppExe within $Seconds s"
}

# The uninstaller re-launches itself from %TEMP% and returns; done = key and app exe gone.
function Invoke-Uninstall([string]$InstallDir) {
    $uninstaller = Join-Path $InstallDir 'uninstall.exe'
    if (-not (Test-Path -LiteralPath $uninstaller)) { Fail "no $uninstaller" }
    $r = Invoke-Bounded $uninstaller @('/S') 300 'uninstall.exe /S'
    if ($r.ExitCode -ne 0) { Fail "uninstall.exe /S exited with $($r.ExitCode)" }
    $deadline = (Get-Date).AddSeconds(300)
    while ((Get-Date) -lt $deadline) {
        $key = Get-InstallLocation $script:hive
        $exeLeft = Test-Path -LiteralPath (Join-Path $InstallDir $AppExe)
        if ($null -eq $key -and -not $exeLeft) { break }
        Start-Sleep -Milliseconds 500
    }
    if ($null -ne (Get-InstallLocation $script:hive)) { Fail 'the uninstall key is still there 300 s after uninstall.exe /S' }
    # The relaunched uninstaller (%TEMP%\Au_.exe, NSIS) may still remove shortcuts and folders; a
    # reinstall right away would race it (review M-2). Bounded wait for it to exit.
    $deadline = (Get-Date).AddSeconds(120)
    while (@(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'Au_*' -or $_.ProcessName -like 'Un_*' }).Count -gt 0) {
        if ((Get-Date) -gt $deadline) { Fail 'the relaunched NSIS uninstaller (Au_*/Un_*) did not exit within 120 s' }
        Start-Sleep -Milliseconds 500
    }
    foreach ($exe in @($AppExe, $CliExe, $WorkerExe)) {
        if (Test-Path -LiteralPath (Join-Path $InstallDir $exe)) { Fail "$exe is still in $InstallDir after the uninstall" }
    }
}

# --- fixture binary -------------------------------------------------------------------------

function Invoke-Fixture([string]$Test, [string]$Marker) {
    $r = Invoke-Bounded $script:fixtureExe @('--exact', $Test, '--ignored', '--nocapture', '--test-threads=1') 180 "ci_fixture $Test"
    Write-Host $r.Out
    if ($r.Err) { Write-Host $r.Err }
    if ($r.ExitCode -ne 0) { Fail "ci_fixture $Test exited with $($r.ExitCode)" }
    # libtest prints a passing test's output right after "test <name> ... " on the same line.
    $pat = '(?:^|\.\.\. )(' + [regex]::Escape($Marker) + ' .*)$'
    $line = @(($r.Out -split "`r?`n") | ForEach-Object { $m = [regex]::Match($_, $pat); if ($m.Success) { $m.Groups[1].Value } }) | Select-Object -Last 1
    if (-not $line) { Fail "ci_fixture $Test printed no $Marker line" }
    if (($r.Out -notmatch '(?m)^test result: ok\. 1 passed')) { Fail "ci_fixture $Test did not report exactly one passed test" }
    return $line
}

# --- snapshots ------------------------------------------------------------------------------

# "<label>/<relative path> <sha256>" for every file below each root (a file root is hashed
# itself), sorted. Empty directories are listed as "<label>/<relative path>/ dir".
function Get-Snapshot([hashtable]$Roots) {
    $rows = New-Object System.Collections.Generic.List[string]
    foreach ($label in ($Roots.Keys | Sort-Object)) {
        $root = $Roots[$label]
        if (Test-Path -LiteralPath $root -PathType Leaf) {
            $rows.Add("$label $((Get-FileHash -LiteralPath $root -Algorithm SHA256).Hash)")
            continue
        }
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { $rows.Add("$label MISSING"); continue }
        $full = (Resolve-Path -LiteralPath $root).Path.TrimEnd('\')
        foreach ($item in @(Get-ChildItem -LiteralPath $full -Recurse -Force)) {
            $rel = $item.FullName.Substring($full.Length).TrimStart('\')
            if ($item.PSIsContainer) {
                if (@(Get-ChildItem -LiteralPath $item.FullName -Force).Count -eq 0) { $rows.Add("$label/$rel/ dir") }
            } else {
                $rows.Add("$label/$rel $((Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash)")
            }
        }
    }
    return @($rows | Sort-Object)
}

function Assert-SameSnapshot([string[]]$Before, [string[]]$After, [string]$What) {
    $diff = @(Compare-Object -ReferenceObject $Before -DifferenceObject $After)
    if ($diff.Count -gt 0) {
        $diff | ForEach-Object { Write-Host "$($_.SideIndicator) $($_.InputObject)" }
        Fail "$What changed the user's data ($($diff.Count) differing rows; <= before only, => after only)"
    }
    Write-Host "ok: $What left $($Before.Count) files unchanged"
}

# --- run ------------------------------------------------------------------------------------

$evidenceDir = if ($env:INSTALL_PROBE_EVIDENCE) { $env:INSTALL_PROBE_EVIDENCE } else { Join-Path $env:RUNNER_TEMP 'install-test-evidence' }
New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
$script:work = Join-Path $env:RUNNER_TEMP ('install-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $script:work | Out-Null
$script:hive = if ($Mode -eq 'AllUsers') { 'HKLM' } else { 'HKCU' }
$app = $null
$decoy = $null
$logPath = $null

try {
    if ($env:CI -ne 'true') { Fail 'CI only (CI=true): it replaces the pinned paths file and writes Credential Manager entries' }
    if ($Mode -eq 'AllUsers') {
        $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Fail 'AllUsers needs an elevated session (as ci/install-probe-windows.ps1)'
        }
    }
    $setups = @(Get-ChildItem -LiteralPath $InstallerDir -Filter '*-setup.exe' -File -Recurse)
    if ($setups.Count -ne 1) { Fail "expected exactly one *-setup.exe under $InstallerDir, found $($setups.Count)" }
    $setup = $setups[0].FullName
    $fixtures = @(Get-ChildItem -LiteralPath $FixtureDir -Filter 'ci_fixture*.exe' -File -Recurse)
    if ($fixtures.Count -ne 1) { Fail "expected exactly one ci_fixture*.exe under $FixtureDir, found $($fixtures.Count)" }
    $script:fixtureExe = $fixtures[0].FullName
    Write-Host "installer: $setup"
    Write-Host "fixture:   $script:fixtureExe"
    foreach ($h in @('HKCU', 'HKLM')) {
        if ($null -ne (Get-InstallLocation $h)) { Fail "$h already has an Atlas Duck install; this job needs a fresh machine" }
    }
    Write-Host "RUNTIME_VERSIONS os=$([Environment]::OSVersion.VersionString) webview2=$(Get-WebView2Version)"

    Write-Step '1. pinned fixture, store with the real OS keystore, keychain entries'
    $global:LASTEXITCODE = 0
    $dataOut = @(& (Join-Path $PSScriptRoot 'pinned-fixture.ps1'))
    if ($LASTEXITCODE -ne 0 -or $dataOut.Count -ne 1) { Fail "ci/pinned-fixture.ps1 failed (exit $LASTEXITCODE)" }
    $dataDir = "$($dataOut[0])".Trim()
    $configDir = Join-Path (Split-Path -Parent $dataDir) 'config'
    $anchorDir = Join-Path (Split-Path -Parent $dataDir) 'anchors'
    New-Item -ItemType Directory -Force -Path $anchorDir | Out-Null
    $pinnedFile = Join-Path $env:LOCALAPPDATA 'atlas-duck\paths.toml'
    $logPath = Join-Path $dataDir 'logs\diag.log'
    $env:ATLAS_DUCK_CI_FIXTURE_PINNED = $pinnedFile
    $env:ATLAS_DUCK_CI_FIXTURE_ANCHOR_DIR = $anchorDir
    $roots = @{ data = $dataDir; config = $configDir; anchors = $anchorDir; pinned = $pinnedFile }
    Write-Host (Invoke-Fixture 'ci_fixture_store' 'CI_FIXTURE_STORE')
    $e0 = Invoke-Fixture 'ci_fixture_entries' 'CI_FIXTURE_ENTRIES'
    Write-Host "E0: $e0"

    Write-Step "2. install (setup /S /$Mode), start, serve core, doctor"
    Invoke-Setup $setup
    $installDir = Wait-Installed 60
    Write-Host "install dir: $installDir"
    $app = Start-App $installDir
    Wait-LogLine $logPath $PatServing 0 $app $TimeoutSeconds 'event=serve_started serve_state=core'
    Write-Host 'ok: the installed app serves the core (APP_START appended)'
    $doc = Invoke-Bounded (Join-Path $installDir $CliExe) @('--timeout', '60', 'doctor') 120 'atlas-duck doctor'
    Write-Host "DOCTOR $($doc.Out -replace '\s+', ' ')"
    if ($doc.ExitCode -ne 0) { Fail "atlas-duck doctor exited with $($doc.ExitCode): $($doc.Err)" }
    $docJson = $doc.Out | ConvertFrom-Json
    $appPart = $docJson.data.app
    if ($null -eq $appPart) { Fail 'doctor has no data.app (the app did not answer)' }
    if ($appPart.PSObject.Properties.Name -contains 'gate') { Fail "doctor answered from the gate ($($appPart.gate)), not from the core" }
    if (-not ($appPart.PSObject.Properties.Name -contains 'instances')) { Fail 'doctor data.app has no instances (not the core answer)' }
    $s0 = Get-Snapshot @{ config = $configDir; pinned = $pinnedFile }
    $anchorNames0 = @(Get-ChildItem -LiteralPath $anchorDir -Recurse -File -Force | ForEach-Object { $_.Name } | Sort-Object)
    Write-Host "anchor dir files: $($anchorNames0 -join ', ')"

    Write-Step '3. silent uninstall with the app running: the uninstaller drain quits it (APP_STOP installer)'
    $quits = Get-LogCount $logPath $PatInstallerQuit
    $stops = Get-LogCount $logPath $PatStopInstaller
    Invoke-Uninstall $installDir
    Wait-Exit $app 30 'the drained app'
    $app = $null
    if ((Get-LogCount $logPath $PatInstallerQuit) -le $quits) { Show-Log $logPath; Fail 'no event=os_end_session reason=installer_quit line after the uninstall' }
    if ((Get-LogCount $logPath $PatStopInstaller) -le $stops) { Show-Log $logPath; Fail 'no event=app_stop reason=installer line after the uninstall (the drain did not run the shutdown path)' }
    Get-LogLines $logPath | Where-Object { $_ -match $PatInstallerQuit -or $_ -match $PatStopInstaller } | Select-Object -Last 2 | ForEach-Object { Write-Host "DRAIN_LINE $_" }
    Write-Host 'I40 uninstall drain: os_end_session reason=installer_quit, app_stop reason=installer'
    Assert-SameSnapshot $s0 (Get-Snapshot @{ config = $configDir; pinned = $pinnedFile }) 'the uninstall (pinned file, config dir)'
    if (-not (Test-Path -LiteralPath (Join-Path $dataDir 'audit.db'))) { Fail 'audit.db is gone after the uninstall' }
    $anchorNames1 = @(Get-ChildItem -LiteralPath $anchorDir -Recurse -File -Force | ForEach-Object { $_.Name } | Sort-Object)
    foreach ($n in $anchorNames0) { if ($anchorNames1 -notcontains $n) { Fail "anchor file $n is gone after the uninstall" } }
    $e1 = Invoke-Fixture 'ci_fixture_entries' 'CI_FIXTURE_ENTRIES'
    if ($e1 -ne $e0) { Fail "keychain entries changed by the uninstall: before '$e0', after '$e1'" }
    Write-Host 'ok: keychain entries unchanged by the uninstall'

    Write-Step '4. reinstall: the install touches no user data'
    $s1 = Get-Snapshot $roots
    Invoke-Setup $setup
    $installDir = Wait-Installed 60
    Assert-SameSnapshot $s1 (Get-Snapshot $roots) 'the reinstall'

    Write-Step '5. upgrade drain: same build installed again with the app running; a decoy outside $INSTDIR stays alive'
    $decoyDir = Join-Path $script:work 'decoy'
    New-Item -ItemType Directory -Force -Path $decoyDir | Out-Null
    $decoyExe = Join-Path $decoyDir $AppExe
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\PING.EXE') -Destination $decoyExe
    $decoy = Start-Process -FilePath $decoyExe -ArgumentList @('-n', '900', '127.0.0.1') -PassThru -WindowStyle Hidden
    $null = $decoy.Handle
    Start-Sleep -Seconds 1
    if ($decoy.HasExited) { Fail 'the decoy exited at once' }
    $serving = Get-LogCount $logPath $PatServing
    $app = Start-App $installDir
    Wait-LogLine $logPath $PatServing $serving $app $TimeoutSeconds 'event=serve_started serve_state=core (after the reinstall)'
    $stops = Get-LogCount $logPath $PatStopInstaller
    Invoke-Setup $setup
    Wait-Exit $app 30 'the app drained by the upgrade'
    $app = $null
    if ((Get-LogCount $logPath $PatStopInstaller) -le $stops) { Show-Log $logPath; Fail 'no new event=app_stop reason=installer line after the upgrade' }
    if ($decoy.HasExited) { Fail "the decoy $decoyExe (outside `$INSTDIR) was terminated by the upgrade drain" }
    $installDir = Wait-Installed 60
    Write-Host "I40 upgrade drain: app_stop reason=installer, decoy pid $($decoy.Id) at $decoyExe alive"

    Write-Step '6. uninstall with the app stopped: user data unchanged (full hashes), then reinstall'
    $s3 = Get-Snapshot $roots
    Invoke-Uninstall $installDir
    Assert-SameSnapshot $s3 (Get-Snapshot $roots) 'the uninstall (app stopped)'
    $e2 = Invoke-Fixture 'ci_fixture_entries' 'CI_FIXTURE_ENTRIES'
    if ($e2 -ne $e0) { Fail "keychain entries changed: before '$e0', after '$e2'" }
    Invoke-Setup $setup
    $installDir = Wait-Installed 60
    Assert-SameSnapshot $s3 (Get-Snapshot $roots) 'the second reinstall'

    Write-Step '7. ci_fixture_verify'
    $env:ATLAS_DUCK_CI_FIXTURE_MIN_STARTS = '2'
    $verify = Invoke-Fixture 'ci_fixture_verify' 'CI_FIXTURE_VERIFY'
    Write-Host $verify
    Write-Host "I45 OK mode=$Mode uninstall/reinstall kept data dir, config dir, pinned file, anchor dir and keychain entries"

    Write-Step '8. S-04 against the installed app (TAURI_WEBVIEW_AUTOMATION=true)'
    Stop-Everything
    # s04 fails on any msedgewebview2 that exists before its app starts (strays of the runs above).
    Get-Process -Name msedgewebview2 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $s04 = Join-Path $PSScriptRoot 's04-no-debug-port.ps1'
    & pwsh -NoProfile -File $s04 -Exe (Join-Path $installDir $AppExe)
    if ($LASTEXITCODE -ne 0) { Fail "S-04 on the installed app failed (exit $LASTEXITCODE)" }
    Write-Host "RUNTIME_VERSIONS os=$([Environment]::OSVersion.VersionString) webview2=$(Get-WebView2Version)"
    Write-Host "OK: install-test $Mode"
} finally {
    Stop-Everything
    if ($null -ne $decoy -and -not $decoy.HasExited) { $decoy.Kill() }
    if ($null -ne $logPath -and (Test-Path -LiteralPath $logPath)) {
        Copy-Item -LiteralPath $logPath -Destination (Join-Path $evidenceDir 'diag.log') -Force
    }
}
