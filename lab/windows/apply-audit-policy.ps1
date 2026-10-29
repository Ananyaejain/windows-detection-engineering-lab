<#
.SYNOPSIS
    Applies the canonical SOC lab advanced audit policy and process command-line auditing.
.DESCRIPTION
    Configures advanced audit policy subcategories on WIN11-01 and DC01.
    Forces advanced audit subcategories to override legacy categories.
    Enables process creation command line auditing (supplementing Security Event ID 4688).
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "[+] Configuring SCENoApplyLegacyAuditPolicy = 1 to enforce subcategory auditing..."
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $lsaPath)) {
    New-Item -Path $lsaPath -Force | Out-Null
}
Set-ItemProperty -Path $lsaPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord -Force

Write-Host "[+] Configuring ProcessCreationIncludeCmdLine_Enabled = 1..."
$auditPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $auditPolicyPath)) {
    New-Item -Path $auditPolicyPath -Force | Out-Null
}
Set-ItemProperty -Path $auditPolicyPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force

Write-Host "[+] Applying common advanced audit subcategories..."
$commonSubcategories = @(
    @{ Name = "Logon"; Success = "enable"; Failure = "enable" },
    @{ Name = "Logoff"; Success = "enable"; Failure = "disable" },
    @{ Name = "Account Lockout"; Success = "enable"; Failure = "disable" },
    @{ Name = "Special Logon"; Success = "enable"; Failure = "enable" },
    @{ Name = "Other Logon/Logoff Events"; Success = "enable"; Failure = "enable" },
    @{ Name = "Process Creation"; Success = "enable"; Failure = "disable" },
    @{ Name = "User Account Management"; Success = "enable"; Failure = "enable" },
    @{ Name = "Security Group Management"; Success = "enable"; Failure = "enable" },
    @{ Name = "Other Account Management Events"; Success = "enable"; Failure = "enable" },
    @{ Name = "File Share"; Success = "enable"; Failure = "enable" },
    @{ Name = "Detailed File Share"; Success = "enable"; Failure = "enable" },
    @{ Name = "Other Object Access Events"; Success = "enable"; Failure = "enable" },
    @{ Name = "Audit Policy Change"; Success = "enable"; Failure = "enable" },
    @{ Name = "Authentication Policy Change"; Success = "enable"; Failure = "enable" },
    @{ Name = "Sensitive Privilege Use"; Success = "enable"; Failure = "enable" },
    @{ Name = "Security State Change"; Success = "enable"; Failure = "enable" },
    @{ Name = "Security System Extension"; Success = "enable"; Failure = "enable" },
    @{ Name = "System Integrity"; Success = "enable"; Failure = "enable" }
)

foreach ($sub in $commonSubcategories) {
    Write-Host "    Applying subcategory: $($sub.Name) (Success: $($sub.Success), Failure: $($sub.Failure))"
    & auditpol.exe /set /subcategory:"$($sub.Name)" /success:$($sub.Success) /failure:$($sub.Failure)
}

# Determine if running on Domain Controller
$isDC = $false
try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs.DomainRole -ge 4) {
        $isDC = $true
    }
} catch {}

if (-not $isDC) {
    if ((hostname).ToUpper() -eq "DC01") {
        $isDC = $true
    }
}

if ($isDC) {
    Write-Host "[+] Domain Controller detected. Applying additional DC audit subcategories..."
    $dcSubcategories = @(
        @{ Name = "Credential Validation"; Success = "enable"; Failure = "enable" },
        @{ Name = "Kerberos Authentication Service"; Success = "enable"; Failure = "enable" },
        @{ Name = "Kerberos Service Ticket Operations"; Success = "enable"; Failure = "enable" },
        @{ Name = "Other Account Logon Events"; Success = "enable"; Failure = "enable" },
        @{ Name = "Computer Account Management"; Success = "enable"; Failure = "enable" },
        @{ Name = "Directory Service Changes"; Success = "enable"; Failure = "enable" },
        @{ Name = "Directory Service Access"; Success = "enable"; Failure = "enable" }
    )

    foreach ($sub in $dcSubcategories) {
        Write-Host "    Applying DC subcategory: $($sub.Name) (Success: $($sub.Success), Failure: $($sub.Failure))"
        & auditpol.exe /set /subcategory:"$($sub.Name)" /success:$($sub.Success) /failure:$($sub.Failure)
    }
} else {
    Write-Host "[*] Host is member endpoint (non-DC). Skipped DC-specific subcategories."
}

Write-Host "[+] Audit policy configuration successfully completed."
