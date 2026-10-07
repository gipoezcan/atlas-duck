#requires -Version 5.1
<#
.SYNOPSIS
  Checks the NSIS installer that `cargo tauri build --bundles nsis` wrote (spec 12.1, 12.2, 13).

.DESCRIPTION
  Lists the installer with 7-Zip and asserts that the executables it installs are exactly
  atlas-duck-app.exe, atlas-duck.exe and atlas-duck-sandbox.exe, all in the install root.
  It then extracts those three and checks that each is a non-empty 64-bit x86 PE image
  (MZ header, machine 0x8664).

.PARAMETER BundleDir
  Directory holding exactly one *-setup.exe (target/<triple>/release/bundle/nsis).
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$BundleDir
)

$ErrorActionPreference = 'Stop'

$expected = [string[]]@('atlas-duck-app.exe', 'atlas-duck-sandbox.exe', 'atlas-duck.exe')
[Array]::Sort($expected, [System.StringComparer]::Ordinal)

$installers = @(Get-ChildItem -LiteralPath $BundleDir -Filter '*-setup.exe' -File -ErrorAction Stop)
if ($installers.Count -ne 1) {
  throw "expected exactly one *-setup.exe in $BundleDir, found $($installers.Count)"
}
$installer = $installers[0].FullName
Write-Host "installer: $installer"

$sevenZip = $null
$cmd = Get-Command 7z -ErrorAction SilentlyContinue
if ($cmd) { $sevenZip = $cmd.Source }
if (-not $sevenZip) {
  foreach ($candidate in @(
      (Join-Path $env:ProgramFiles '7-Zip\7z.exe'),
      (Join-Path ${env:ProgramFiles(x86)} '7-Zip\7z.exe'))) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) { $sevenZip = $candidate; break }
  }
}
if (-not $sevenZip) { throw '7z.exe not found (7-Zip is preinstalled on windows-2022 runners)' }

# `7z l -slt -ba` prints one "Path = ..." line per archive entry. An NSIS installer lists the
# files it installs plus its own plug-ins under $PLUGINSDIR.
$listing = & $sevenZip l -slt -ba $installer
if ($LASTEXITCODE -ne 0) { throw "7z l failed with exit code $LASTEXITCODE" }
$entries = @($listing | Where-Object { $_ -like 'Path = *' } | ForEach-Object { $_.Substring(7) })
Write-Host "installer entries ($($entries.Count)):"
$entries | ForEach-Object { Write-Host "  $_" }

[string[]]$executables = @($entries | Where-Object { $_ -like '*.exe' -and $_ -notlike '$PLUGINSDIR*' })
[Array]::Sort($executables, [System.StringComparer]::Ordinal)
$failures = @()

if (($executables -join '|') -ne ($expected -join '|')) {
  $failures += "installer executables are [$($executables -join ', ')], expected exactly [$($expected -join ', ')]"
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("atlas-duck-nsis-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
  & $sevenZip x -y "-o$work" $installer | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "7z x failed with exit code $LASTEXITCODE" }

  foreach ($name in $expected) {
    $path = Join-Path $work $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
      $failures += "$name was not extracted to the install root"
      continue
    }
    $bytes = [System.IO.File]::ReadAllBytes($path)
    if ($bytes.Length -lt 0x100 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
      $failures += "$name is not a PE image (no MZ header, $($bytes.Length) bytes)"
      continue
    }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    Write-Host ("{0}: {1} bytes, PE machine 0x{2:X4}" -f $name, $bytes.Length, $machine)
    if ($machine -ne 0x8664) {
      $failures += ("{0} has PE machine 0x{1:X4}, expected 0x8664 (x86_64)" -f $name, $machine)
    }
  }
}
finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
  $failures | ForEach-Object { Write-Error $_ -ErrorAction Continue }
  throw "check-windows-bundle: $($failures.Count) failure(s)"
}
Write-Host "OK: the NSIS installer holds exactly $($expected -join ', ')"
