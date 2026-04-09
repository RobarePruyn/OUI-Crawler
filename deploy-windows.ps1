#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploy NetCaster as a Windows service.

.DESCRIPTION
    Installs Python dependencies, configures environment, installs NSSM,
    and registers the app as an auto-start Windows service.

    Run from an elevated PowerShell prompt inside the project directory:
        .\deploy-windows.ps1

    To uninstall:
        .\deploy-windows.ps1 -Uninstall

.PARAMETER Port
    Port to bind (default 8000).

.PARAMETER ServiceName
    Windows service name (default NetCaster).

.PARAMETER Uninstall
    Remove the service and firewall rule.
#>

param(
    [int]$Port = 8000,
    [string]$ServiceName = "NetCaster",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$VenvDir    = Join-Path $ProjectDir ".venv"
$LogDir     = Join-Path $ProjectDir "logs"
$EnvFile    = Join-Path $ProjectDir ".env"
$NssmDir    = Join-Path $ProjectDir "tools"
$NssmExe    = Join-Path $NssmDir "nssm.exe"
$NssmZip    = Join-Path $NssmDir "nssm.zip"
$NssmUrl    = "https://nssm.cc/release/nssm-2.24.zip"

# ── Helpers ──────────────────────────────────────────────────────────

function Write-Step($msg) { Write-Host "`n>> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "   $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "   $msg" -ForegroundColor Yellow }

function Install-Python {
    $PythonVersion = "3.12.9"
    $InstallerUrl  = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.exe"
    $InstallerPath = Join-Path $env:TEMP "python-$PythonVersion-installer.exe"

    Write-Step "Python not found - downloading Python $PythonVersion"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath -UseBasicParsing
    Write-Ok "Downloaded installer"

    Write-Step "Installing Python $PythonVersion (this may take a minute)"
    $installArgs = "/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1"
    Start-Process -FilePath $InstallerPath -ArgumentList $installArgs -Wait
    Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue

    # Disable the Microsoft Store python.exe aliases if present
    $aliasPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\python.exe"
    Remove-Item $aliasPath -Force -ErrorAction SilentlyContinue 2>$null

    # Refresh PATH in current session
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath    = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path    = "$machinePath;$userPath"

    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) {
        Write-Error "Python installed but still not found on PATH. Close and reopen PowerShell, then re-run this script."
    }
    Write-Ok "Python $PythonVersion installed successfully"
}

function Test-PythonWorks {
    try {
        $out = & python --version 2>&1
        if ($LASTEXITCODE -ne 0) { return $false }
        if ("$out" -like "*was not found*") { return $false }
        if ("$out" -like "*not recognized*") { return $false }
        return $true
    } catch {
        return $false
    }
}

function Assert-Python {
    if (-not (Test-PythonWorks)) {
        Install-Python
    }
    if (-not (Test-PythonWorks)) {
        Write-Error "Python installed but still not working. Disable the Microsoft Store python alias (Settings > Apps > Advanced app settings > App execution aliases), then re-run."
    }
    $ver = & python --version 2>&1
    Write-Ok "Found $ver"
}

function Get-Nssm {
    if (Test-Path $NssmExe) {
        Write-Ok "NSSM already present at $NssmExe"
        return
    }

    # Check if nssm is already on PATH
    $existing = Get-Command nssm -ErrorAction SilentlyContinue
    if ($existing) {
        $script:NssmExe = $existing.Source
        Write-Ok "Using system NSSM at $($existing.Source)"
        return
    }

    Write-Step "Downloading NSSM"
    New-Item -ItemType Directory -Path $NssmDir -Force | Out-Null

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $NssmUrl -OutFile $NssmZip -UseBasicParsing

    Expand-Archive -Path $NssmZip -DestinationPath $NssmDir -Force
    # The zip contains nssm-2.24/win64/nssm.exe
    $found = Get-ChildItem -Path $NssmDir -Recurse -Filter "nssm.exe" |
             Where-Object { $_.DirectoryName -like "*win64*" } |
             Select-Object -First 1
    if (-not $found) {
        $found = Get-ChildItem -Path $NssmDir -Recurse -Filter "nssm.exe" | Select-Object -First 1
    }
    if (-not $found) {
        Write-Error "Could not find nssm.exe in downloaded archive."
    }
    Copy-Item $found.FullName $NssmExe -Force
    Remove-Item $NssmZip -Force
    Write-Ok "NSSM installed to $NssmExe"
}

# ── Uninstall path ───────────────────────────────────────────────────

if ($Uninstall) {
    Write-Step "Stopping service $ServiceName"
    & $NssmExe stop $ServiceName 2>$null
    Start-Sleep -Seconds 2

    Write-Step "Removing service $ServiceName"
    & $NssmExe remove $ServiceName confirm 2>$null

    Write-Step "Removing firewall rule"
    netsh advfirewall firewall delete rule name="$ServiceName" 2>$null

    Write-Ok "Uninstall complete. Virtual environment and data left in place."
    exit 0
}

# ── Install ──────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  NetCaster - Windows Deployment" -ForegroundColor White
Write-Host "  =====================================" -ForegroundColor DarkGray
Write-Host "  Project:  $ProjectDir"
Write-Host "  Service:  $ServiceName"
Write-Host "  Port:     $Port"
Write-Host ""

# 1. Python
Write-Step "Checking Python"
Assert-Python

# 2. Virtual environment
Write-Step "Setting up virtual environment"
if (-not (Test-Path $VenvDir)) {
    & python -m venv $VenvDir
    Write-Ok "Created $VenvDir"
} else {
    Write-Ok "Virtual environment already exists"
}

$pyExe  = Join-Path $VenvDir "Scripts\python.exe"
$uvicorn = Join-Path $VenvDir "Scripts\uvicorn.exe"

Write-Step "Installing dependencies"
& $pyExe -m pip install --upgrade pip --quiet 2>$null
& $pyExe -m pip install -r (Join-Path $ProjectDir "requirements.txt") --quiet
Write-Ok "Dependencies installed"

# 3. Verify uvicorn is present
if (-not (Test-Path $uvicorn)) {
    Write-Error "uvicorn not found at $uvicorn after pip install. Check requirements.txt."
}
Write-Ok "uvicorn found at $uvicorn"

# 4. Logs directory
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
Write-Ok "Log directory: $LogDir"

# 5. Generate secret key and .env if needed
Write-Step "Configuring environment"
if (-not (Test-Path $EnvFile)) {
    $pyExe = Join-Path $VenvDir "Scripts\python.exe"
    $secret = & $pyExe -c "import secrets; print(secrets.token_urlsafe(32))"
    $dbPath = Join-Path $ProjectDir "netcaster.db"

    $envContent = "NETCASTER_SECRET_KEY=$secret`nNETCASTER_DB_PATH=$dbPath"
    $envContent | Set-Content -Path $EnvFile -Encoding UTF8

    Write-Ok "Created $EnvFile with generated secret key"
} else {
    Write-Warn ".env already exists - not overwriting"
}

# 6. Quick smoke test
Write-Step "Smoke test - starting app for 5 seconds"
$pyExe = Join-Path $VenvDir "Scripts\python.exe"
$proc = Start-Process -FilePath $uvicorn -ArgumentList "run:app --host 127.0.0.1 --port $Port --workers 1" `
    -WorkingDirectory $ProjectDir -PassThru -NoNewWindow -RedirectStandardError (Join-Path $LogDir "smoke-test.log")

Start-Sleep -Seconds 5

# Any HTTP response (even 401/404/500) means the server is up. We only
# want to warn when we can't reach it at all (connection refused, timeout).
# PS 5.1 doesn't know HttpResponseException, so we inspect the exception
# by type name string rather than a typed catch.
try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port" -UseBasicParsing -TimeoutSec 5
    Write-Ok "App responded (HTTP $($response.StatusCode))"
} catch {
    # If the exception carries a Response object, the server did reply —
    # it was just a non-2xx status (e.g. 401 Unauthorized on the login
    # redirect), which still proves the app is alive.
    if ($_.Exception.Response) {
        $code = [int]$_.Exception.Response.StatusCode
        Write-Ok "App responded (HTTP $code)"
    } else {
        Write-Warn "Could not reach app during smoke test - check $LogDir\smoke-test.log"
    }
}

if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
Start-Sleep -Seconds 1

# 7. Install NSSM
Get-Nssm

# 8. Remove existing service if present (clean reinstall)
$existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingSvc) {
    Write-Step "Removing existing service for clean install"
    & $NssmExe stop $ServiceName 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    & $NssmExe remove $ServiceName confirm 2>&1 | Out-Null
    Start-Sleep -Seconds 1
}

# 9. Install the Windows service
Write-Step "Installing Windows service"
& $NssmExe install $ServiceName $uvicorn "run:app --host 0.0.0.0 --port $Port --workers 1"
& $NssmExe set $ServiceName AppDirectory $ProjectDir
& $NssmExe set $ServiceName DisplayName "NetCaster"
& $NssmExe set $ServiceName Description "NetCaster web application - Mediacast Network Solutions"
& $NssmExe set $ServiceName Start SERVICE_AUTO_START
& $NssmExe set $ServiceName AppStdout (Join-Path $LogDir "stdout.log")
& $NssmExe set $ServiceName AppStderr (Join-Path $LogDir "stderr.log")
& $NssmExe set $ServiceName AppStdoutCreationDisposition 4  # append
& $NssmExe set $ServiceName AppStderrCreationDisposition 4  # append
& $NssmExe set $ServiceName AppRotateFiles 1
& $NssmExe set $ServiceName AppRotateBytes 5242880  # 5 MB
& $NssmExe set $ServiceName AppEnvironmentExtra "PYTHONUNBUFFERED=1"

Write-Ok "Service $ServiceName installed"

# 10. Start the service
Write-Step "Starting service"
& $NssmExe start $ServiceName

Start-Sleep -Seconds 3
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Ok "Service is running"
} else {
    Write-Warn "Service status: $($svc.Status) - check $LogDir\stderr.log"
}

# 11. Firewall rule
Write-Step "Configuring firewall"
netsh advfirewall firewall delete rule name="$ServiceName" >$null 2>&1
netsh advfirewall firewall add rule name="$ServiceName" dir=in action=allow protocol=tcp localport=$Port >$null
Write-Ok "Firewall rule added for port $Port"

# ── Done ─────────────────────────────────────────────────────────────

$ip = (Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.PrefixOrigin -ne "WellKnown" } |
       Select-Object -First 1).IPAddress

Write-Host ""
Write-Host "  =====================================" -ForegroundColor DarkGray
Write-Host "  Deployment complete." -ForegroundColor Green
Write-Host ""
Write-Host "  Local:    http://localhost:$Port"
if ($ip) {
    Write-Host "  Network:  http://${ip}:$Port"
}
Write-Host ""
Write-Host "  Manage:"
Write-Host "    nssm status $ServiceName"
Write-Host "    nssm restart $ServiceName"
Write-Host "    nssm stop $ServiceName"
Write-Host ""
Write-Host "  Uninstall:"
Write-Host "    .\deploy-windows.ps1 -Uninstall"
Write-Host ""
Write-Host "  Logs:     $LogDir" -ForegroundColor DarkGray
Write-Host ""
