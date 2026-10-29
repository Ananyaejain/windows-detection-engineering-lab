# Active Directory Account Discovery — Execution

## Activity Summary
- **ATT&CK Technique:** T1087.002 — Account Discovery: Domain Account
- **Host:** WIN11-01 (querying DC01 at `10.50.0.10`)
- **User Context:** `SOCLAB\employee01` (Standard domain user, Medium integrity `S-1-16-8192`)
- **Execution Command:**
  ```powershell
  ([adsisearcher]"objectcategory=user").FindAll(); ([adsisearcher]"objectcategory=user").FindOne()
  ```
- **Observed Result:** Read-only LDAP query executed successfully, enumerating domain user accounts.

## Key Windows Event Records

| Host | Provider / Channel | Event ID | Record ID | Event Details |
| :--- | :--- | :--- | :--- | :--- |
| WIN11-01 | Microsoft-Windows-PowerShell/Operational | 4104 | 10133 | ScriptBlock Logging captured ADSISearcher query for `objectcategory=user` with `FindAll()` and `FindOne()`. |
| WIN11-01 | Microsoft-Windows-Sysmon/Operational | 3 | 256426 | Outbound TCP connection from `powershell.exe` (PID 7660) to `10.50.0.10:389` (LDAP) via source port 49531. |
| WIN11-01 | Microsoft-Windows-Sysmon/Operational | 3 | 256427 | Second outbound connection to `10.50.0.10:389` via source port 49532. |
| DC01 | Security | 4624 | 41568 | Network Logon (Type 3, Kerberos) from `10.50.0.20` (`SOCLAB\employee01`) matching source port 49531. |
| DC01 | Security | 4624 | 41570 | Second Network Logon matching source port 49532. |

## Cross-Host Correlation
- **Transport Correlation:** Ephemeral source ports (`49531` and `49532`) recorded on WIN11-01 align identically with the inbound connection records logged on DC01.
- **Session Attribution:** Telemetry directly links endpoint PowerShell discovery commands to directory-service authentication and query flows on the domain controller.

## Remediation & Cleanup
- Read-only reconnaissance activity; no persistent artifacts created on endpoint or domain controller.

## Scope Limitation
This execution proves domain user enumeration by an unprivileged domain user. It does not claim credential theft, Kerberoasting, password cracking, or Active Directory modifications.
