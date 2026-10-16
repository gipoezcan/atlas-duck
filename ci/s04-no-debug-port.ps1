# Spec §13 S-04 (Windows), M6 plan Task 33: a RELEASE build started with the WebView2 debugging
# variables set (and the E2E opt-in, which a release build must ignore) opens no debug port while
# a real webview runs. CI only.
#
# Usage:  pwsh -NoProfile -File ci/s04-no-debug-port.ps1 -Exe <release atlas-duck-app.exe>
#
# The diag log lives in <data dir>\logs, so the app gets a pinned data dir (ci/pinned-fixture.ps1, CI only).
# A pinned dir with no store is the first-run state: a no-argument start opens the Setup window,
# a real WebView2 webview (a cold `--background` start opens no window: the check would be vacuous).
# The script requires an msedgewebview2 process, a listener on a control port it opened itself
# (the probe sees listeners), no listener on the debug port, no `remote-debugging` switch on any
# msedgewebview2 command line, and a `startup_env_scrubbed` line per variable set. Only msedgewebview2
# processes in the app's own process tree count (a leftover from an earlier step, such as the
# msedgedriver session of the e2e flows, would otherwise satisfy "a webview exists" or carry a
# --remote-debugging-port of its own); any msedgewebview2 process that exists before the app starts
# fails the script, and the CI job kills strays before this step.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Exe)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string]$Text) { [Console]::Error.WriteLine("FAIL: $Text"); exit 1 }

if ($env:CI -ne 'true') { [Console]::Error.WriteLine('s04: refusing to run outside CI (CI=true)'); exit 2 }
if (-not (Test-Path -LiteralPath $Exe)) { [Console]::Error.WriteLine("s04: $Exe not found"); exit 2 }

function Get-FreePort {
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $l.Start()
    $p = $l.LocalEndpoint.Port
    $l.Stop()
    return $p
}

function Test-Listening([int]$Port) {
    $c = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return ($null -ne $c)
}

# The descendants of a process (children, grandchildren, ...) by walking Win32_Process.ParentProcessId:
# WebView2's browser process is a child of the app and its renderers are children of that.
function Get-Descendants([int]$RootPid) {
    $all = @(Get-CimInstance Win32_Process)
    $found = New-Object System.Collections.Generic.List[object]
    $queue = New-Object System.Collections.Generic.Queue[int]
    $queue.Enqueue($RootPid)
    $seenIds = New-Object System.Collections.Generic.HashSet[int]
    while ($queue.Count -gt 0) {
        $parent = $queue.Dequeue()
        foreach ($p in $all) {
            if ([int]$p.ParentProcessId -eq $parent -and $seenIds.Add([int]$p.ProcessId)) {
                $found.Add($p)
                $queue.Enqueue([int]$p.ProcessId)
            }
        }
    }
    # Callers wrap the call in @(): under StrictMode a bare ",array" return reaches Where-Object as ONE array object.
    return $found.ToArray()
}

function Get-WebViewsOf([int]$RootPid) {
    return @(@(Get-Descendants $RootPid) | Where-Object { $_.Name -eq 'msedgewebview2.exe' })
}

$port = Get-FreePort
$control = Get-FreePort
while ($control -eq $port) { $control = Get-FreePort }

$work = Join-Path $env:RUNNER_TEMP ('s04-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null

# Positive control: the probe sees a listener that exists.
$holder = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $control)
$holder.Start()
$app = $null
try {
    if (-not (Test-Listening $control)) { Fail "positive control: the probe does not see the listener on $control" }
    if (Test-Listening $port) { Fail "port $port is taken before the app starts" }
    Write-Host "S04 control_port=$control seen, debug_port=$port free"

    $dataDir = (& (Join-Path $PSScriptRoot 'pinned-fixture.ps1') -DataDir (Join-Path $work 'data') | Select-Object -Last 1)
    $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=$port"
    $env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $work 'wv2'
    $env:WEBKIT_INSPECTOR_SERVER = "127.0.0.1:$port"
    $env:WEBKIT_INSPECTOR_HTTP_SERVER = "127.0.0.1:$port"
    $env:ATLAS_DUCK_E2E_ALLOW_DRIVER = '1'
    $strays = @(Get-Process -Name msedgewebview2 -ErrorAction SilentlyContinue)
    if ($strays.Count -gt 0) { Fail "$($strays.Count) msedgewebview2 process(es) exist before the app starts (strays from an earlier step)" }
    $app = Start-Process -FilePath $Exe -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $work 'app.out') -RedirectStandardError (Join-Path $work 'app.err')

    # A real webview: WebView2's msedgewebview2 child processes.
    $seen = $false
    for ($i = 0; $i -lt 300; $i++) {
        if ($app.HasExited) { Fail "the release app exited ($($app.ExitCode)) before a webview process appeared" }
        if (@(Get-WebViewsOf $app.Id).Count -gt 0) { $seen = $true; break }
        Start-Sleep -Milliseconds 200
    }
    if (-not $seen) { Fail 'no msedgewebview2 process in the app process tree within 60 s: no webview, the check would be vacuous' }
    Write-Host "S04 webview_processes_in_app_tree=$(@(Get-WebViewsOf $app.Id).Count)"

    Start-Sleep -Seconds 15
    if ($app.HasExited) { Fail "the release app died during the check ($($app.ExitCode))" }
    if (Test-Listening $port) { Fail "a debug port opened on $port with the WebView2 variables set (S-04)" }
    $cmdlines = @(Get-WebViewsOf $app.Id | ForEach-Object { $_.CommandLine })
    Write-Host "S04 msedgewebview2 processes in the app tree: $($cmdlines.Count)"
    foreach ($c in $cmdlines) {
        if ($c -match 'remote-debugging') { Fail 'an msedgewebview2 process carries a remote-debugging switch (S-04)' }
    }

    $diag = Join-Path $dataDir 'logs\diag.log'
    if (-not (Test-Path -LiteralPath $diag)) { Fail "no $diag" }
    Write-Host "--- $diag"
    $log = Get-Content -LiteralPath $diag -Raw
    Write-Host $log
    foreach ($v in @('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS', 'WEBVIEW2_USER_DATA_FOLDER', 'WEBKIT_INSPECTOR_SERVER', 'WEBKIT_INSPECTOR_HTTP_SERVER')) {
        if ($log -notmatch "startup_env_scrubbed.*removed_var=$v") { Fail "no startup_env_scrubbed line for $v" }
    }
    Write-Host "S04 OK: no listener on $port with the WebView2 variables set; the release build scrubbed them"
}
finally {
    $holder.Stop()
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $env:LOCALAPPDATA 'atlas-duck\paths.toml')
    if ($null -ne $app -and -not $app.HasExited) { $app.Kill() }
    Get-Process -Name atlas-duck-app, msedgewebview2 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
