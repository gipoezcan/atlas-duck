# The CI-07 step of the scripts-enabled matrix on Windows (spec 13 "Scripts-enabled matrix", PD-150,
# R6 option (a)); M8 plan Task 28. The twin of ci/script-matrix-step.sh, whose header says what each
# mode asserts. Written and wired in M8, switched on in M10 (`if: false` until then); its syntax and
# its parsing are checked on every ci.yml run by -SelfTest, which executes no package and no app.
#
#   ./ci/script-matrix-step.ps1 -Mode release -EvidenceDir <dir>
#       A release package job: <dir>\evidence.json (written by ci/install-probe-windows.ps1) must
#       show floor=met failed=none and a worker_version in the sandbox_probe line, i.e. the installed
#       worker answered in probe mode through the app's spawner. No script runs: a fresh release
#       install is in the first-run state and serves no core.
#
#   ./ci/script-matrix-step.ps1 -Mode debug -WorkDir <dir> -Cli <exe> [-CliArgs <words>]
#       A debug scripted-approver bundle serving a configured core: `script run --dry-run=full`
#       (succeeded, exit 0) and a real run released by the scripted approver (reason
#       atlas-test:release; released, exit 0). Degraded confinement stays off (the default).
#
#   ./ci/script-matrix-step.ps1 -SelfTest
param(
    [ValidateSet('release', 'debug')][string]$Mode,
    [string]$EvidenceDir,
    [string]$WorkDir,
    [string]$Cli,
    [string[]]$CliArgs = @(),
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    throw "script-matrix-step: $Message"
}

# Asserts the release-package half of the matrix on the fields of the sandbox_probe line.
function Assert-ReleaseFields($Floor, $Failed, $Worker, [string]$Where) {
    if ($Floor -ne 'met') { Fail "floor=$Floor (failed=$Failed), expected floor=met: $Where" }
    if ($Failed -ne 'none') { Fail "failed=$Failed although floor=met: $Where" }
    if ([string]::IsNullOrEmpty($Worker) -or $Worker -eq 'unknown') {
        Fail "the sandbox_probe line has no worker_version ($Worker): the installed worker did not answer in probe mode through the app's spawner: $Where"
    }
}

# Asserts the exit code and the status of the CLI's one-line envelope; returns the parsed envelope.
function Assert-Envelope([string]$Label, [string]$Text, [int]$Code, [int]$WantCode, [string]$WantStatus) {
    if ($Code -ne $WantCode) { Fail "$Label exited $Code, expected ${WantCode}: $Text" }
    try { $parsed = $Text | ConvertFrom-Json } catch { Fail "$Label printed no JSON envelope: $Text" }
    if ($parsed.status -ne $WantStatus) { Fail "$Label status is '$($parsed.status)', expected ${WantStatus}: $Text" }
    return $parsed
}

function Assert-Throws([scriptblock]$Body, [string]$What) {
    $threw = $false
    try { & $Body } catch { $threw = $true }
    if (-not $threw) { throw "self-test: $What was accepted" }
}

function Invoke-Release([string]$Dir) {
    if (-not $Dir) { Fail 'release needs -EvidenceDir' }
    $file = Join-Path $Dir 'evidence.json'
    if (-not (Test-Path -LiteralPath $file)) { Fail "$file is missing (ci/install-probe-windows.ps1 writes it)" }
    $e = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
    $line = $e.probe_line_1
    if ($null -eq $line) { Fail "$file has no probe_line_1" }
    Assert-ReleaseFields $line.floor $line.failed $line.worker_version $file
    Write-Host "CI07 mode=release floor=$($line.floor) failed=$($line.failed) worker_version=$($line.worker_version) engine_version=$($line.engine_version)"
}

# Runs the CLI with the given words; returns the exit code and the stdout text.
function Invoke-Cli([string[]]$Words) {
    $out = & $Cli @CliArgs @Words 2>$null | Out-String
    return [pscustomobject]@{ Code = $LASTEXITCODE; Text = $out.Trim() }
}

function Invoke-Debug {
    if (-not $WorkDir -or -not $Cli) { Fail 'debug needs -WorkDir and -Cli' }
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    $script = Join-Path $WorkDir 'matrix.js'
    [System.IO.File]::WriteAllText($script, "return {n: 1 + 1};`n", (New-Object System.Text.UTF8Encoding($false)))

    $dry = Invoke-Cli @('script', 'run', $script, '--dry-run=full', '--timeout', '120')
    $null = Assert-Envelope 'script run --dry-run=full' $dry.Text $dry.Code 0 'succeeded'
    if ($dry.Text -notmatch 'dry_run') { Fail "the dry run's envelope carries no dry_run marker: $($dry.Text)" }

    $real = Invoke-Cli @('script', 'run', $script, '--reason', 'atlas-test:release', '--timeout', '120')
    $answer = Assert-Envelope 'script run (released by the scripted approver)' $real.Text $real.Code 0 'released'
    if ($answer.data.result.n -ne 2) { Fail "the released run delivered another result than {n: 2}: $($real.Text)" }
    Write-Host 'CI07 mode=debug dry_run=succeeded real=released'
}

function Invoke-SelfTest {
    Assert-ReleaseFields 'met' 'none' '0.1.0+0123456789ab' 'canned'
    Assert-Throws { Assert-ReleaseFields 'not_met' 'raw_clone' '0.1.0+0123456789ab' 'canned' } 'a floor=not_met line'
    Assert-Throws { Assert-ReleaseFields 'met' 'cred_read' '0.1.0+0123456789ab' 'canned' } 'floor=met with failed probes'
    Assert-Throws { Assert-ReleaseFields 'met' 'none' 'unknown' 'canned' } 'a line without a worker version'
    Assert-Throws { Assert-ReleaseFields 'met' 'none' $null 'canned' } 'a line with no worker field'

    $ok = '{"status":"released","request_id":"req_1","data":{"result":{"n":2}}}'
    $answer = Assert-Envelope 'self-test' $ok 0 0 'released'
    if ($answer.data.result.n -ne 2) { throw 'self-test: the envelope result was not read' }
    Assert-Throws { Assert-Envelope 'self-test' '{"status":"failed"}' 9 0 'released' } 'a failed envelope'
    Assert-Throws { Assert-Envelope 'self-test' 'not json' 0 0 'released' } 'text that is no envelope'

    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("script-matrix-selftest-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    try {
        '{"mode":"CurrentUser","probe_line_1":{"floor":"met","failed":"none","worker_version":"0.1.0+0123456789ab","engine_version":"0.16.2"}}' |
            Set-Content -LiteralPath (Join-Path $dir 'evidence.json') -Encoding UTF8
        Invoke-Release $dir
    } finally {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host 'OK: script-matrix-step self-test'
}

if ($SelfTest) { Invoke-SelfTest; return }
switch ($Mode) {
    'release' { Invoke-Release $EvidenceDir }
    'debug' { Invoke-Debug }
    default { Fail 'usage: -Mode release -EvidenceDir <dir> | -Mode debug -WorkDir <dir> -Cli <exe> | -SelfTest' }
}
