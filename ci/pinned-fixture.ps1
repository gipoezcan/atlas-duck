# CI-only (spec §7.7 "Machine-local files"): writes THIS host's pinned paths file
# (%LOCALAPPDATA%\atlas-duck\paths.toml) so that a started app finds a local, existing
# data directory instead of being "before first run". It stands in for the state the
# first-run wizard (M6) will produce. Never run it on a developer machine: it replaces
# the real paths.toml.
#
# Usage:  pwsh -NoProfile -File ci/pinned-fixture.ps1 [-DataDir <dir>]
# Output: exactly one line on stdout, the data directory path. Diagnostics go to stderr.
[CmdletBinding()]
param([string]$DataDir = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info([string]$Text) { [Console]::Error.WriteLine("pinned-fixture: $Text") }

if ($env:CI -ne 'true' -and $env:ATLAS_DUCK_FIXTURE_FORCE -ne '1') {
    Write-Info 'refusing to replace the pinned paths file outside CI (set ATLAS_DUCK_FIXTURE_FORCE=1 to override)'
    exit 2
}
if (-not $env:LOCALAPPDATA) {
    Write-Info 'LOCALAPPDATA is not set'
    exit 2
}

# Pinned location on Windows: <FOLDERID_LocalAppData>\atlas-duck\paths.toml (no host part).
$pinnedDir = Join-Path $env:LOCALAPPDATA 'atlas-duck'
$pinnedFile = Join-Path $pinnedDir 'paths.toml'

if ($DataDir -eq '') {
    $base = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
    $root = Join-Path $base ('atlas-duck-fixture-' + [guid]::NewGuid().ToString('N'))
    $DataDir = Join-Path $root 'data'
    $configDir = Join-Path $root 'config'
} else {
    $configDir = Join-Path (Split-Path -Parent $DataDir) 'config'
}
New-Item -ItemType Directory -Force -Path $DataDir, $configDir, $pinnedDir | Out-Null

foreach ($p in @($DataDir, $configDir)) {
    if ($p.Contains("'")) {
        Write-Info "path contains a single quote, which a TOML literal string cannot hold: $p"
        exit 2
    }
}

# TOML literal strings (single quotes) keep the backslashes of Windows paths as they are.
$text = "schema_version = 1`n" +
        "data_dir = '$DataDir'`n" +
        "config_dir = '$configDir'`n"

# UTF-8 without a BOM (Windows PowerShell 5.1's -Encoding UTF8 would add one), written to a
# temp file and renamed, so a reader never sees a half-written file.
$utf8 = New-Object System.Text.UTF8Encoding($false)
$tmp = "$pinnedFile.tmp"
[System.IO.File]::WriteAllText($tmp, $text, $utf8)
Move-Item -Force -LiteralPath $tmp -Destination $pinnedFile

Write-Info "wrote $pinnedFile (data_dir = $DataDir)"
Write-Output $DataDir
