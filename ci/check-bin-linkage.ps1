# §2.1: the CLI never touches keychain or DB; the sandbox links no HTTP client, keychain or DB code.
# Fails if atlas-duck.exe or atlas-duck-sandbox.exe imports a webview, TLS, SQLite, secret-store or
# tray DLL. Prints every bin's full import list (the record Task 19 and Task 22 read).
# Usage: powershell -File ci/check-bin-linkage.ps1 -BinDir target/debug
# Exit: 0 ok, 1 forbidden DLL imported, 2 usage error / missing binary / dumpbin not found / control failed.
param(
    [Parameter(Mandatory = $true)][string]$BinDir
)
$ErrorActionPreference = 'Stop'

$pattern = 'webkit|gtk|gdk|soup|javascriptcore|ssl|crypto|sqlite|secret|WebView2Loader|ayatana'

# Control: the pattern must match the DLL name this check exists to catch.
if ('WebView2Loader.dll' -notmatch $pattern) {
    Write-Host 'CONTROL FAILED: the pattern does not match WebView2Loader.dll'
    exit 2
}

$dumpbin = $null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path $vswhere) {
    $dumpbin = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -find 'VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe' | Select-Object -First 1
}
if (-not $dumpbin) {
    $cmd = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($cmd) { $dumpbin = $cmd.Source }
}
if (-not $dumpbin) { Write-Host 'dumpbin.exe not found (install the MSVC build tools)'; exit 2 }

function Get-Imports([string]$exe) {
    $out = & $dumpbin /nologo /dependents $exe
    if ($LASTEXITCODE -ne 0) { throw "dumpbin failed on $exe" }
    # Import lines are indented DLL names, for example "    KERNEL32.dll".
    @($out | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '\.dll$' } | Sort-Object -Unique)
}

foreach ($bin in 'atlas-duck-app', 'atlas-duck', 'atlas-duck-sandbox') {
    if (-not (Test-Path (Join-Path $BinDir "$bin.exe"))) { Write-Host "missing $BinDir\$bin.exe"; exit 2 }
}

$status = 0
foreach ($bin in 'atlas-duck', 'atlas-duck-sandbox', 'atlas-duck-app') {
    $imports = Get-Imports (Join-Path $BinDir "$bin.exe")
    Write-Host "== $bin.exe imports =="
    $imports | ForEach-Object { Write-Host $_ }
    if ($imports.Count -eq 0) {
        Write-Host "CONTROL FAILED: no imports listed for $bin.exe; the dumpbin parsing is broken"
        exit 2
    }
    if ($bin -eq 'atlas-duck-app') { continue } # listed for the record only
    $bad = @($imports | Where-Object { $_ -match $pattern })
    if ($bad.Count -gt 0) {
        Write-Host "FAIL: $bin.exe imports forbidden DLLs: $($bad -join ', ')"
        $status = 1
    }
}
if ($status -eq 0) {
    Write-Host 'OK: atlas-duck.exe and atlas-duck-sandbox.exe import no webview/TLS/SQLite/secret-store/tray DLLs'
}
exit $status
