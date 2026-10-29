<#
.SYNOPSIS
    Applies PowerShell Script Block Logging, Module Logging, and Event Log capacity baselines.
.DESCRIPTION
    Enables ScriptBlockLogging and ModuleLogging (with wildcard *).
    Ensures Microsoft-Windows-PowerShell/Operational and Microsoft-Windows-TaskScheduler/Operational are enabled.
    Configures minimum retention capacities for Security, PowerShell, TaskScheduler, and Sysmon.
    Does NOT enable PowerShell transcription (to avoid plaintext secret exposure on disk).
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "[+] Configuring PowerShell Script Block Logging..."
$sbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $sbPath)) {
    New-Item -Path $sbPath -Force | Out-Null
}
Set-ItemProperty -Path $sbPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force

Write-Host "[+] Configuring PowerShell Module Logging..."
$mlPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $mlPath)) {
    New-Item -Path $mlPath -Force | Out-Null
}
Set-ItemProperty -Path $mlPath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force

$modNamesPath = "$mlPath\ModuleNames"
if (-not (Test-Path $modNamesPath)) {
    New-Item -Path $modNamesPath -Force | Out-Null
}
Set-ItemProperty -Path $modNamesPath -Name "*" -Value "*" -Type String -Force

Write-Host "[+] Enabling operational event channels..."
# Ensure PowerShell Operational is enabled
& wevtutil.exe sl "Microsoft-Windows-PowerShell/Operational" /e:true

# Ensure TaskScheduler Operational is enabled
& wevtutil.exe sl "Microsoft-Windows-TaskScheduler/Operational" /e:true

Write-Host "[+] Configuring event log retention capacities..."
# Security: 256 MiB (268435456 bytes)
& wevtutil.exe sl "Security" /ms:268435456

# PowerShell Operational: 128 MiB (134217728 bytes)
& wevtutil.exe sl "Microsoft-Windows-PowerShell/Operational" /ms:134217728

# Task Scheduler Operational: 64 MiB (67108864 bytes)
& wevtutil.exe sl "Microsoft-Windows-TaskScheduler/Operational" /ms:67108864

# Sysmon Operational: 256 MiB (268435456 bytes) if channel exists
try {
    $sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
    if ($sysmonLog) {
        Write-Host "    Configuring Sysmon log capacity (256 MiB)..."
        & wevtutil.exe sl "Microsoft-Windows-Sysmon/Operational" /ms:268435456
    }
} catch {
    Write-Host "    Sysmon channel not yet registered; log size configuration deferred to post-install."
}

Write-Host "[+] PowerShell logging and channel capacity configuration successfully completed."
