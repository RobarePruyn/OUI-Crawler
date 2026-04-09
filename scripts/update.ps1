# NetCaster self-update runner.
#
# This script is invoked every minute by a Windows Scheduled Task
# (see scripts/install-update-task.ps1). It checks for an update flag
# file written by the webapp's "Update now" button and, if present,
# performs a git pull + dependency install + service restart.
#
# The webapp itself never runs git or nssm — it just drops the flag.
# This keeps privileged operations in the scheduled task (which runs
# as SYSTEM) and out of the web process.

$ErrorActionPreference = "Stop"

$InstallDir = "C:\NetCaster"
$FlagFile   = Join-Path $InstallDir "update.flag"
$LogDir     = Join-Path $InstallDir "logs"
$UpdateLog  = Join-Path $LogDir "update.log"
$StatusFile = Join-Path $LogDir "last-update-status.txt"
$NssmExe    = Join-Path $InstallDir "tools\nssm.exe"
$ServiceName = "OUIPortMapper"
$VenvPython = Join-Path $InstallDir ".venv\Scripts\python.exe"

function Write-Log($msg) {
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$stamp] $msg"
    Write-Host $line
    Add-Content -Path $UpdateLog -Value $line -ErrorAction SilentlyContinue
}

function Set-Status($msg) {
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Set-Content -Path $StatusFile -Value "$stamp  $msg" -ErrorAction SilentlyContinue
}

# No flag, no work
if (-not (Test-Path $FlagFile)) { exit 0 }

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Write-Log "Update flag detected"

# Remove the flag first so a crashing updater can't spin forever
try { Remove-Item $FlagFile -Force -ErrorAction Stop } catch {
    Write-Log "Could not remove flag: $_"
    Set-Status "FAILED: could not remove flag file"
    exit 1
}

try {
    Write-Log "Stopping $ServiceName"
    & $NssmExe stop $ServiceName | Out-Null

    Write-Log "Running git pull in $InstallDir"
    Push-Location $InstallDir
    try {
        $pullOutput = & git pull 2>&1
        Write-Log "git: $pullOutput"
        if ($LASTEXITCODE -ne 0) { throw "git pull failed: $pullOutput" }

        Write-Log "Installing/updating dependencies"
        $pipOutput = & $VenvPython -m pip install --quiet -r requirements.txt 2>&1
        if ($LASTEXITCODE -ne 0) { throw "pip install failed: $pipOutput" }

        $version = (Get-Content (Join-Path $InstallDir "VERSION") -ErrorAction SilentlyContinue).Trim()
        if (-not $version) { $version = "unknown" }

        Write-Log "Starting $ServiceName"
        & $NssmExe start $ServiceName | Out-Null

        Set-Status "OK: updated to $version"
        Write-Log "Update complete: $version"
    } finally {
        Pop-Location
    }
} catch {
    $err = $_.Exception.Message
    Write-Log "Update failed: $err"
    Set-Status "FAILED: $err"
    # Make sure the service is running even if the update failed
    try { & $NssmExe start $ServiceName | Out-Null } catch { }
    exit 1
}
