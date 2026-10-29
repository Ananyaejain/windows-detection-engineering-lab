# Run-Key Persistence — Execution

## Activity Summary
- **ATT&CK Technique:** T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **Host:** WIN11-01 (Windows 11 Enterprise)
- **User Context:** `SOCLAB\employee01` (Standard domain user, Medium integrity `S-1-16-8192`)
- **Execution Command:**
  ```cmd
  REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"
  ```
- **Observed Result:** Persistence value successfully created under user Run key via native `reg.exe`.

## Key Windows Event Records

| Provider / Channel | Event ID | Record ID | Event Details |
| :--- | :--- | :--- | :--- |
| Microsoft-Windows-Sysmon/Operational | 13 | 279657 | Value Set (`EventType=SetValue`) on `...\Software\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team` with Data `C:\Path\AtomicRedTeam.exe` by `reg.exe` (PID 8024, ProcessGuid `{e99b4396-b8f8-6ae1-c40c-000000001000}`). |
| Microsoft-Windows-Sysmon/Operational | 1 | 279655 | Process Creation for `reg.exe` (PID 8024, ProcessGuid `{e99b4396-b8f8-6ae1-c40c-000000001000}`, Parent PID 8336 `cmd.exe`). |
| Security | 4688 | 43631 | Process Creation for `reg.exe` (PID 8024, Creator PID 8336) under user `SOCLAB\employee01`. |

## Correlation Analysis
- **Process ↔ State Change Linkage:** Sysmon Event 13 shares the exact `ProcessGuid` (`{e99b4396-b8f8-6ae1-c40c-000000001000}`) and PID (`8024`) of the `reg.exe` process created in Sysmon Event 1.
- **Persistence Verification:** Confirms that the exact executing process enacted the persistence state change in the user registry hive.

## Remediation & Cleanup
- Removed persistence entry via `REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /f`.
- Sysmon Event 12 (RecordId 279680) recorded the deletion (`DeleteValue`).
- Query verification confirmed the value was completely absent (exit code 1).

## Scope Limitation
This execution proves user-context autostart persistence configuration creation. It does not claim payload execution, surviving a reboot, or administrative elevation.
