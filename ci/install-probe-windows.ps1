# ci/install-probe-windows.ps1 -Mode CurrentUser|AllUsers [-InstallerDir <dir>] [-TimeoutSeconds 60]
# ci/install-probe-windows.ps1 -SelfTest
#
# Installed-package probe for the NSIS installer (spec sec. 9.4 Windows, sec. 12.2, sec. 13
# scripts-enabled matrix, sec. 15 V09/V30). CI-only: it installs the app, replaces this user's
# pinned paths.toml (through ci/pinned-fixture.ps1) and kills the app it started.
#
#   -Mode CurrentUser   per-user install:  setup.exe /S /CurrentUser
#   -Mode AllUsers      per-machine install: setup.exe /S /AllUsers (needs an elevated session)
#
# The switches come from Tauri's installer.nsi: with installMode "both" it defines
# MULTIUSER_INSTALLMODE_COMMANDLINE, so NSIS MultiUser.nsh honours /CurrentUser and /AllUsers.
# Without a switch an elevated session defaults to AllUsers, so a switch is always passed.
#
# Steps: install -> resolve the install dir from the uninstall registry key -> assert the dir
# is not the data dir, holds the three exes, and both (L)PAC SIDs have read+execute on the worker
# and every DLL -> pinned fixture (local temp data dir) -> start `atlas-duck-app.exe --background`
# -> poll <data>\logs\diag.log up to 60 s for `event=sandbox_probe` -> ASSERT floor=met
# failed=none and ace=present -> WER exclusions -> (CurrentUser only) remove the S-1-15-2-2 ACE,
# restart, assert ace=reapplied and the ACE is back -> kill the app.
#
# The Windows floor is MET on the installed package (sec. 9.4): the host scores the LPAC Winsock /
# credential-service failures and the loopback timeout from unconfined controls, or falls back to a
# plain AppContainer. The line says which one ran (appcontainer_mode=lpac|appcontainer) and whether
# the controls held (control_ok=true); both are recorded. Besides the floor this leg asserts what
# the installer is responsible for: the ACEs, the install location, the ace= re-apply outcome and
# the WER exclusions. The job log is the record (T22 reads it); the evidence directory is uploaded
# too.
#
# ACEs are read through Get-Acl and SecurityIdentifier values, never from icacls text: icacls
# prints localized account names. The icacls text is only logged as evidence.
[CmdletBinding()]
param(
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Mode = 'CurrentUser',
    [string]$InstallerDir = 'dist',
    [int]$TimeoutSeconds = 60,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProductName = 'Atlas Duck'
$DataDirName = 'atlas-duck'
$AppExe = 'atlas-duck-app.exe'
$CliExe = 'atlas-duck.exe'
$WorkerExe = 'atlas-duck-sandbox.exe'
$SidAllAppPackages = 'S-1-15-2-1'
$SidAllRestrictedAppPackages = 'S-1-15-2-2'
$UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' + $ProductName
# WerAddExcludedApplication(name, FALSE) writes a DWORD named after the exe here (spec sec. 2.5).
$WerKey = 'HKCU:\Software\Microsoft\Windows\Windows Error Reporting\ExcludedApplications'
$ProbeEvent = 'sandbox_probe'

function Write-Step([string]$Text) { Write-Host "== $Text" }

function Fail([string]$Text) { throw "install-probe: $Text" }

# --- sandbox_probe log line (T20) -----------------------------------------------------------

# Returns the key=value fields of an `event=sandbox_probe floor=...` line as a hashtable, or
# $null for any other line (including the sandbox_probe warnings, which carry `reason=` and no
# `floor=`).
function ConvertFrom-ProbeLine([string]$Line) {
    if ($Line -notmatch '(^|\s)event=sandbox_probe(\s|$)') { return $null }
    $fields = @{}
    foreach ($m in [regex]::Matches($Line, '(?<k>[a-z_]+)=(?<v>\S+)')) {
        $fields[$m.Groups['k'].Value] = $m.Groups['v'].Value
    }
    if (-not $fields.ContainsKey('floor')) { return $null }
    return $fields
}

# Every sandbox_probe summary line in the log, oldest first. The app keeps the file open, so the
# file is opened with every share flag.
function Get-ProbeLines([string]$LogPath) {
    $found = @()
    if (-not (Test-Path -LiteralPath $LogPath)) { return $found }
    $stream = [System.IO.File]::Open($LogPath, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    try {
        $reader = New-Object System.IO.StreamReader($stream)
        try {
            while ($null -ne ($line = $reader.ReadLine())) {
                $fields = ConvertFrom-ProbeLine $line
                if ($null -ne $fields) { $found += , $fields }
            }
        } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    return $found
}

# Asserts floor=met failed=none, appcontainer_mode=lpac lpac_failed=n/a (a silent LPAC regression that
# the plain-AppContainer fallback hides must turn the leg red) and the expected ace=.
function Assert-ProbeFields($Fields, [string]$ExpectedAce) {
    $summary = ($Fields.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' '
    if ($Fields['floor'] -ne 'met') { Fail "floor is not met (failed=$($Fields['failed'])): $summary" }
    if ($Fields['failed'] -ne 'none') { Fail "failed probes reported although floor=met: $summary" }
    if ($Fields['appcontainer_mode'] -ne 'lpac') { Fail "appcontainer_mode=$($Fields['appcontainer_mode']), expected lpac: $summary" }
    if ($Fields['lpac_failed'] -ne 'n/a') { Fail "lpac_failed=$($Fields['lpac_failed']), expected n/a (LPAC floor met without fallback): $summary" }
    if ($Fields['ace'] -ne $ExpectedAce) { Fail "ace=$($Fields['ace']), expected ${ExpectedAce}: $summary" }
}

# Waits until the log holds more than $KnownCount summary lines and returns the newest one. Fails
# when the app exits first or when $TimeoutSeconds pass.
function Wait-ProbeLine([string]$LogPath, $Process, [int]$KnownCount, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $lines = @(Get-ProbeLines $LogPath)
        if ($lines.Count -gt $KnownCount) { return $lines[$lines.Count - 1] }
        if ($Process.HasExited) {
            Show-Log $LogPath
            Fail "$AppExe exited with code $($Process.ExitCode) before it logged $ProbeEvent"
        }
        Start-Sleep -Milliseconds 250
    }
    Show-Log $LogPath
    Fail "no $ProbeEvent line within $Seconds s in $LogPath"
}

function Show-Log([string]$LogPath) {
    if (Test-Path -LiteralPath $LogPath) {
        Write-Host "---- $LogPath ----"
        Get-Content -LiteralPath $LogPath -Tail 60 | ForEach-Object { Write-Host $_ }
        Write-Host '----'
    } else {
        Write-Host "(no log file at $LogPath)"
    }
}

# --- ACEs ---------------------------------------------------------------------------------

# SIDs that hold an Allow ACE with at least read+execute on $Path.
function Get-RxSids([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $mask = [int][System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $sids = @()
    foreach ($r in $rules) {
        if ($r.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            (([int]$r.FileSystemRights -band $mask) -eq $mask)) {
            $sids += $r.IdentityReference.Value
        }
    }
    return $sids
}

function Assert-PackageSids([string]$Path) {
    $sids = @(Get-RxSids $Path)
    foreach ($sid in @($SidAllAppPackages, $SidAllRestrictedAppPackages)) {
        if ($sids -notcontains $sid) {
            & icacls.exe $Path | Out-Host
            Fail "$Path has no read+execute ACE for $sid"
        }
    }
}

function Remove-SidAce([string]$Path, [string]$Sid) {
    & icacls.exe $Path /remove "*$Sid" | Out-Host
    if ($LASTEXITCODE -ne 0) { Fail "icacls /remove *$Sid failed for $Path (exit $LASTEXITCODE)" }
}

# The worker and every DLL directly in the install dir: the set the installer hook grants.
function Get-AceFiles([string]$InstallDir) {
    $files = @(Join-Path $InstallDir $WorkerExe)
    $files += @(Get-ChildItem -LiteralPath $InstallDir -Filter '*.dll' -File | ForEach-Object { $_.FullName })
    return $files
}

# --- install location -----------------------------------------------------------------------

# `InstallLocation` of the uninstall key, quotes removed. NSIS wrote it through SHCTX, so the
# hive follows the install mode. Both registry views are tried.
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

function Test-SamePath([string]$A, [string]$B) {
    $x = [System.IO.Path]::GetFullPath($A).TrimEnd('\')
    $y = [System.IO.Path]::GetFullPath($B).TrimEnd('\')
    return [string]::Equals($x, $y, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-UnderPath([string]$Child, [string]$Parent) {
    $c = [System.IO.Path]::GetFullPath($Child).TrimEnd('\') + '\'
    $p = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    return $c.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-WerExcluded([string]$ExeName) {
    $key = Get-Item -LiteralPath $WerKey -ErrorAction SilentlyContinue
    if ($null -eq $key) { return $false }
    return (@($key.GetValueNames()) -contains $ExeName)
}

# --- processes ------------------------------------------------------------------------------

function Start-App([string]$InstallDir) {
    $p = Start-Process -FilePath (Join-Path $InstallDir $AppExe) -ArgumentList '--background' `
        -WorkingDirectory $InstallDir -PassThru
    $null = $p.Handle   # keeps ExitCode readable after the process ends (Windows PowerShell 5.1)
    return $p
}

function Stop-App($Process) {
    if ($null -ne $Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $null = $Process.WaitForExit(15000)
    }
    foreach ($name in @('atlas-duck-sandbox', 'atlas-duck-app')) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

# --- self test ------------------------------------------------------------------------------

function Assert-Equal($Actual, $Expected, [string]$What) {
    if ($Actual -ne $Expected) { throw "self-test: $What is '$Actual', expected '$Expected'" }
}

function Assert-Throws([scriptblock]$Block, [string]$What) {
    $threw = $false
    try { & $Block } catch { $threw = $true }
    if (-not $threw) { throw "self-test: $What did not fail" }
}

function Invoke-SelfTest {
    $met = '2026-10-07T10:00:00.123Z INFO atlas_duck_app_lib::sandbox_probe src/sandbox_probe.rs:301 event=sandbox_probe floor=met failed=none extra_layers=none engine_version=0.16.2 worker_version=0.1.0+0123456789ab ace=present appcontainer_mode=lpac control_ok=true lpac_failed=n/a dropped_fields=0'
    $notMet = '2026-10-07T10:00:00.123Z INFO atlas_duck_app_lib::sandbox_probe src/sandbox_probe.rs:301 event=sandbox_probe floor=not_met failed=file_in_profile+task_for_pid extra_layers=landlock:on engine_version=unknown worker_version=unknown ace=missing_no_write_dac appcontainer_mode=appcontainer control_ok=false lpac_failed=n/a dropped_fields=0'
    $warn = '2026-10-07T10:00:00.123Z WARN atlas_duck_app_lib::sandbox_probe src/sandbox_probe.rs:99 event=sandbox_probe reason=install_dir_unknown dropped_fields=0'
    $other = '2026-10-07T10:00:00.123Z INFO atlas_duck_app_lib::tray_host src/tray_host.rs:58 event=tray_host_checked tray_host=missing dropped_fields=0'

    $f = ConvertFrom-ProbeLine $met
    Assert-Equal $f['floor'] 'met' 'floor of the met line'
    Assert-Equal $f['ace'] 'present' 'ace of the met line'
    Assert-Equal $f['failed'] 'none' 'failed of the met line'
    Assert-Equal $f['appcontainer_mode'] 'lpac' 'appcontainer_mode of the met line'
    Assert-Equal $f['control_ok'] 'true' 'control_ok of the met line'
    $g = ConvertFrom-ProbeLine $notMet
    Assert-Equal $g['failed'] 'file_in_profile+task_for_pid' 'failed of the not_met line'
    Assert-Equal $g['ace'] 'missing_no_write_dac' 'ace of the not_met line'
    if ($null -ne (ConvertFrom-ProbeLine $warn)) { throw 'self-test: a sandbox_probe warning parsed as a summary line' }
    if ($null -ne (ConvertFrom-ProbeLine $other)) { throw 'self-test: another event parsed as a summary line' }

    Assert-ProbeFields $f 'present'
    Assert-Throws { Assert-ProbeFields $g 'present' } 'Assert-ProbeFields on a not_met line'
    Assert-Throws { Assert-ProbeFields $f 'reapplied' } 'Assert-ProbeFields with the wrong ace'
    # a not_met floor fails whatever the ace is
    Assert-Throws { Assert-ProbeFields $g 'missing_no_write_dac' } 'Assert-ProbeFields on a not_met line with its own ace'
    $fallback = ConvertFrom-ProbeLine ($met -replace 'appcontainer_mode=lpac', 'appcontainer_mode=appcontainer' -replace 'lpac_failed=n/a', 'lpac_failed=cred_read')
    Assert-Throws { Assert-ProbeFields $fallback 'present' } 'Assert-ProbeFields on a floor=met line that fell back to plain AppContainer'
    $metFailed = ConvertFrom-ProbeLine ($met -replace 'failed=none', 'failed=cred_read')
    Assert-Throws { Assert-ProbeFields $metFailed 'present' } 'Assert-ProbeFields on floor=met with failed probes'

    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('atlas-duck-t21-selftest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    try {
        # The log is read while a writer still holds it open, like the running app.
        $log = Join-Path $dir 'diag.log'
        $writer = New-Object System.IO.FileStream($log, [System.IO.FileMode]::Create,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes("$other`n$met`n$warn`n$notMet`n")
            $writer.Write($bytes, 0, $bytes.Length)
            $writer.Flush()
            $lines = @(Get-ProbeLines $log)
            Assert-Equal $lines.Count 2 'number of summary lines in the log'
            Assert-Equal $lines[1]['floor'] 'not_met' 'floor of the newest line'
        } finally { $writer.Dispose() }
        Assert-Equal @(Get-ProbeLines (Join-Path $dir 'missing.log')).Count 0 'summary lines of a missing log'

        # ACE reading follows SIDs, whatever language icacls prints.
        $file = Join-Path $dir 'worker.exe'
        Set-Content -LiteralPath $file -Value 'x'
        $before = @(Get-RxSids $file)
        if ($before -contains $SidAllAppPackages -or $before -contains $SidAllRestrictedAppPackages) {
            throw 'self-test: a fresh temp file already carries a package SID'
        }
        Assert-Throws { Assert-PackageSids $file } 'Assert-PackageSids on a file without the ACEs'
        & icacls.exe $file /grant "*${SidAllAppPackages}:(RX)" | Out-Null
        $one = @(Get-RxSids $file)
        if ($one -notcontains $SidAllAppPackages) { throw 'self-test: S-1-15-2-1 not seen after the grant' }
        if ($one -contains $SidAllRestrictedAppPackages) { throw 'self-test: S-1-15-2-2 seen before its grant' }
        & icacls.exe $file /grant "*${SidAllRestrictedAppPackages}:(RX)" | Out-Null
        Assert-PackageSids $file
        Remove-SidAce $file $SidAllRestrictedAppPackages
        if (@(Get-RxSids $file) -contains $SidAllRestrictedAppPackages) { throw 'self-test: S-1-15-2-2 still seen after the removal' }
        Assert-Throws { Assert-PackageSids $file } 'Assert-PackageSids after removing S-1-15-2-2'
        # (W) is not read+execute only: a write-only ACE must not count.
        & icacls.exe $file /grant "*${SidAllRestrictedAppPackages}:(W)" | Out-Null
        if (@(Get-RxSids $file) -contains $SidAllRestrictedAppPackages) { throw 'self-test: a write-only ACE counted as read+execute' }

        Assert-Equal (Test-SamePath 'C:\Users\x\AppData\Local\Atlas-Duck\' 'c:\users\x\appdata\local\atlas-duck') $true 'Test-SamePath ignoring case and a trailing slash'
        Assert-Equal (Test-UnderPath 'C:\a\atlas-duck2' 'C:\a\atlas-duck') $false 'Test-UnderPath on a name that only shares a prefix'
        Assert-Equal (Test-UnderPath 'C:\a\atlas-duck\x' 'C:\a\atlas-duck') $true 'Test-UnderPath on a child'
    } finally {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host 'install-probe-windows self-test ok'
}

if ($SelfTest) {
    Invoke-SelfTest
    exit 0
}

# --- the probe ------------------------------------------------------------------------------

$evidenceDir = if ($env:INSTALL_PROBE_EVIDENCE) { $env:INSTALL_PROBE_EVIDENCE }
    elseif ($env:RUNNER_TEMP) { Join-Path $env:RUNNER_TEMP 'install-probe-evidence' }
    else { Join-Path ([System.IO.Path]::GetTempPath()) 'install-probe-evidence' }
New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
$evidence = [ordered]@{ mode = $Mode }
$app = $null
$logPath = $null

try {
    $hive = if ($Mode -eq 'AllUsers') { 'HKLM' } else { 'HKCU' }
    $switch = $Mode   # NSIS MultiUser.nsh: /CurrentUser and /AllUsers

    if ($Mode -eq 'AllUsers') {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
        if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Fail 'AllUsers needs an elevated session: /AllUsers without administrator rights opens a MessageBox, even with /S'
        }
    }

    Write-Step 'locate the installer'
    $setups = @(Get-ChildItem -LiteralPath $InstallerDir -Filter '*-setup.exe' -File -Recurse)
    if ($setups.Count -ne 1) { Fail "expected exactly one *-setup.exe under $InstallerDir, found $($setups.Count)" }
    $setup = $setups[0].FullName
    Write-Host "installer: $setup"

    Write-Step 'a fresh install: no Atlas Duck uninstall key in either hive'
    foreach ($h in @('HKCU', 'HKLM')) {
        $old = Get-InstallLocation $h
        if ($null -ne $old) { Fail "$h already has an Atlas Duck install at $old; this job needs a fresh machine" }
    }

    Write-Step "install: setup /S /$switch"
    $installer = Start-Process -FilePath $setup -ArgumentList @('/S', "/$switch") -PassThru
    $null = $installer.Handle
    if (-not $installer.WaitForExit(300000)) {
        $installer.Kill()
        Fail 'the installer did not finish within 300 s (a MessageBox under /S would hang it)'
    }
    if ($installer.ExitCode -ne 0) {
        Fail "the installer exited with $($installer.ExitCode); the hook sets 1 when icacls fails"
    }

    Write-Step 'install location'
    $installDir = Get-InstallLocation $hive
    if ($null -eq $installDir) { Fail "no InstallLocation in $hive\$UninstallKey after the install" }
    $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
    $dataDir = Join-Path $localAppData $DataDirName
    Write-Host "install dir:  $installDir"
    Write-Host "data/pinned dir (never the install dir): $dataDir"
    $evidence['install_dir'] = $installDir
    if (-not (Test-Path -LiteralPath $installDir -PathType Container)) { Fail "$installDir does not exist" }
    if (Test-SamePath $installDir $dataDir) { Fail "the install dir is the data dir $dataDir" }
    if (Test-UnderPath $installDir $dataDir) { Fail "the install dir lies inside the data dir $dataDir" }
    if (Test-UnderPath $dataDir $installDir) { Fail "the data dir lies inside the install dir $installDir" }
    if ($Mode -eq 'CurrentUser') {
        if (-not (Test-UnderPath $installDir $localAppData)) { Fail "a per-user install must lie under $localAppData" }
        $programs = Join-Path $localAppData ('Programs\' + $ProductName)
        $form = if (Test-SamePath $installDir $programs) { 'LocalAppData\Programs\<productName>' }
                elseif (Test-SamePath $installDir (Join-Path $localAppData $ProductName)) { 'LocalAppData\<productName>' }
                else { 'other' }
        Write-Host "per-user install dir form: $form"
        $evidence['install_dir_form'] = $form
    } else {
        $programFiles = [Environment]::GetFolderPath('ProgramFiles')
        if (-not (Test-UnderPath $installDir $programFiles)) { Fail "a per-machine install must lie under $programFiles" }
    }
    foreach ($exe in @($AppExe, $CliExe, $WorkerExe)) {
        if (-not (Test-Path -LiteralPath (Join-Path $installDir $exe) -PathType Leaf)) { Fail "$exe is missing from $installDir" }
    }

    Write-Step 'ACEs granted by the installer hook (S-1-15-2-1 and S-1-15-2-2, read+execute)'
    $aceFiles = @(Get-AceFiles $installDir)
    foreach ($file in $aceFiles) {
        Assert-PackageSids $file
        Write-Host "ok: $file"
    }
    $worker = Join-Path $installDir $WorkerExe
    & icacls.exe $worker | Tee-Object -FilePath (Join-Path $evidenceDir 'icacls-worker.txt') | Out-Host
    $evidence['ace_files'] = @($aceFiles | ForEach-Object { Split-Path -Leaf $_ })

    Write-Step 'pinned paths fixture (a local temp data dir)'
    $fixture = Join-Path $PSScriptRoot 'pinned-fixture.ps1'
    $global:LASTEXITCODE = 0
    $dataOut = @(& $fixture)
    if ($LASTEXITCODE -ne 0 -or $dataOut.Count -ne 1) { Fail "ci/pinned-fixture.ps1 failed (exit $LASTEXITCODE, output '$dataOut')" }
    $fixtureData = "$($dataOut[0])".Trim()
    $logPath = Join-Path $fixtureData 'logs\diag.log'
    Write-Host "fixture data dir: $fixtureData"

    Write-Step "start $AppExe --background, poll $logPath up to $TimeoutSeconds s for $ProbeEvent"
    $app = Start-App $installDir
    $line = Wait-ProbeLine $logPath $app 0 $TimeoutSeconds
    $evidence['probe_line_1'] = $line
    # floor=met failed=none and ace= are asserted; the mode and the control are recorded.
    Assert-ProbeFields $line 'present'
    $evidence['floor'] = $line['floor']
    $evidence['failed'] = $line['failed']
    $evidence['appcontainer_mode'] = $line['appcontainer_mode']
    $evidence['control_ok'] = $line['control_ok']
    Write-Host "PROBE_RECORD mode=$Mode floor=$($line['floor']) failed=$($line['failed']) appcontainer_mode=$($line['appcontainer_mode']) control_ok=$($line['control_ok']) lpac_failed=$($line['lpac_failed']) ace=$($line['ace']) extra_layers=$($line['extra_layers']) engine_version=$($line['engine_version']) worker_version=$($line['worker_version'])"
    foreach ($file in $aceFiles) { Assert-PackageSids $file }

    Write-Step 'WER exclusions (spec sec. 2.5, sec. 15 V30): HKCU ...\ExcludedApplications'
    foreach ($exe in @($AppExe, $WorkerExe)) {
        if (-not (Test-WerExcluded $exe)) { Fail "no WER exclusion value for $exe under $WerKey" }
        Write-Host "ok: $exe is excluded"
    }
    $evidence['wer_excluded'] = @($AppExe, $WorkerExe)

    if ($Mode -eq 'CurrentUser') {
        Write-Step 'per-user re-apply: remove the S-1-15-2-2 ACE from the installed worker, restart'
        Stop-App $app
        $app = $null
        Remove-SidAce $worker $SidAllRestrictedAppPackages
        if (@(Get-RxSids $worker) -contains $SidAllRestrictedAppPackages) { Fail 'S-1-15-2-2 is still on the worker after the removal' }
        $known = @(Get-ProbeLines $logPath).Count
        $app = Start-App $installDir
        $line = Wait-ProbeLine $logPath $app $known $TimeoutSeconds
        $evidence['probe_line_2'] = $line
        Assert-ProbeFields $line 'reapplied'
        Assert-PackageSids $worker
        Write-Host "ok: ace=reapplied, S-1-15-2-2 is back on the worker (floor=$($line['floor']) asserted)"

        Write-Step 'a third start finds everything in place'
        Stop-App $app
        $app = $null
        $known = @(Get-ProbeLines $logPath).Count
        $app = Start-App $installDir
        $line = Wait-ProbeLine $logPath $app $known $TimeoutSeconds
        $evidence['probe_line_3'] = $line
        Assert-ProbeFields $line 'present'
        Write-Host "ok: ace=present (floor=$($line['floor']) asserted)"
    } else {
        Write-Host 'per-machine: the re-apply path needs WRITE_DAC and an admin runner always has it; the MissingNoWriteDac outcome is covered by the T20 unit test (can_write_dac forced false)'
    }

    $evidence['result'] = 'ok'
    Write-Host "OK: $Mode install, ACEs granted by the installer, WER exclusions set, floor=$($evidence['floor']) failed=$($evidence['failed']) appcontainer_mode=$($evidence['appcontainer_mode']) control_ok=$($evidence['control_ok'])"
} finally {
    Stop-App $app
    if ($null -ne $logPath -and (Test-Path -LiteralPath $logPath)) {
        Copy-Item -LiteralPath $logPath -Destination (Join-Path $evidenceDir 'diag.log') -Force
    }
    $json = $evidence | ConvertTo-Json -Depth 5
    $json | Set-Content -LiteralPath (Join-Path $evidenceDir 'evidence.json') -Encoding UTF8
    # The job log is the record T22 reads (the uploaded evidence directory is a copy).
    Write-Host "EVIDENCE_JSON $($json -replace '\s+', ' ')"
    if ($env:GITHUB_STEP_SUMMARY) {
        $tick = [string][char]96   # a backtick, spelled out so this file holds no code-fence text
        $fence = $tick + $tick + $tick
        Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value ("### install-probe ($Mode)`n`n" + $fence + "json`n" + $json + "`n" + $fence)
    }
}
