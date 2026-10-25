<#
.SYNOPSIS
  Release verification of the Authenticode-signed NSIS installer (M10 Task 26; spec §3.2,
  §14 M10 exit).
.DESCRIPTION
  signtool verify /pa /v on the one *-setup.exe in -InstallerDir, then on the three payload
  executables (atlas-duck-app.exe, atlas-duck.exe, atlas-duck-sandbox.exe) extracted from it with
  7z. Fails on a missing or extra executable and on any verification failure.
.PARAMETER InstallerDir
  Directory holding exactly one *-setup.exe (the downloaded bundle-x86_64-pc-windows-msvc artifact).
#>
param(
  [Parameter(Mandatory = $true)][string]$InstallerDir
)
$ErrorActionPreference = 'Stop'

function Find-SignTool {
  $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
  $found = Get-ChildItem -LiteralPath $kits -Recurse -Filter signtool.exe -File -ErrorAction SilentlyContinue |
    Where-Object { $_.DirectoryName -match '\\x64$' } |
    Sort-Object { [version]($_.Directory.Parent.Name -replace '[^0-9.]', '') } -Descending |
    Select-Object -First 1
  if (-not $found) { throw 'signtool.exe not found (Windows SDK)' }
  return $found.FullName
}

function Find-7z {
  $cmd = Get-Command 7z.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $p = Join-Path $env:ProgramFiles '7-Zip\7z.exe'
  if (Test-Path -LiteralPath $p) { return $p }
  throw '7z.exe not found'
}

function Invoke-Verify([string]$signtool, [string]$file) {
  Write-Host "signtool verify /pa /v $file"
  & $signtool verify /pa /v $file
  if ($LASTEXITCODE -ne 0) { throw "signtool verify /pa failed on $file (exit $LASTEXITCODE)" }
}

$installers = @(Get-ChildItem -LiteralPath $InstallerDir -Filter '*-setup.exe' -File)
if ($installers.Count -ne 1) { throw "expected exactly one *-setup.exe in $InstallerDir, found $($installers.Count)" }
$installer = $installers[0].FullName

$signtool = Find-SignTool
$sevenZip = Find-7z
Invoke-Verify $signtool $installer

$out = Join-Path $env:RUNNER_TEMP 'release-verify-nsis'
if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Recurse -Force }
New-Item -ItemType Directory -Path $out | Out-Null
& $sevenZip x -y "-o$out" $installer | Out-Null
if ($LASTEXITCODE -ne 0) { throw "7z could not extract $installer (exit $LASTEXITCODE)" }

$expected = @('atlas-duck-app.exe', 'atlas-duck.exe', 'atlas-duck-sandbox.exe')
foreach ($name in $expected) {
  $hits = @(Get-ChildItem -LiteralPath $out -Recurse -File -Filter $name)
  if ($hits.Count -ne 1) { throw "expected exactly one $name in the installer, found $($hits.Count)" }
  Invoke-Verify $signtool $hits[0].FullName
}
Write-Host "release-verify-windows: $($installers[0].Name) and its three executables carry valid Authenticode signatures"
