# Register the NetCaster update-watcher Scheduled Task.
# Run once, as Administrator.
#
# The task runs update.ps1 every minute as SYSTEM. update.ps1 is a
# no-op unless C:\NetCaster\update.flag exists.

$ErrorActionPreference = "Stop"

$TaskName = "NetCaster Update Watcher"
$ScriptPath = "C:\NetCaster\scripts\update.ps1"

if (-not (Test-Path $ScriptPath)) {
    throw "update.ps1 not found at $ScriptPath. Check your install location."
}

$Action = New-ScheduledTaskAction `
    -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

# Every minute, forever
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
$Trigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 1) `
    -RepetitionDuration (New-TimeSpan -Days (365 * 20))).Repetition

$Principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

# Replace any existing task
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description "Watches for C:\NetCaster\update.flag and applies self-updates."

Write-Host "Scheduled task '$TaskName' registered."
Write-Host "It will run every minute as SYSTEM and do nothing unless update.flag exists."
