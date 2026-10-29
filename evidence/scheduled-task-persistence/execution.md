# Scheduled-Task Persistence — Execution

## Activity Summary
- **ATT&CK Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task
- **Host:** WIN11-01 (Windows 11 Enterprise)
- **User Context:** `SOCLAB\employee01` (Standard domain user, Medium integrity `S-1-16-8192`)
- **Execution Workflow:**
  1. Staged encoded payload (`ping 127.0.0.1` -> `cGluZyAxMjcuMC4wLjE=`) to `HKCU\SOFTWARE\ATOMIC-T1053.005` (Value: `test`).
  2. Created persistence scheduled task `ATOMIC-T1053.005`:
     ```cmd
     schtasks /Create /TN "ATOMIC-T1053.005" /TR "cmd /c start /min \"\" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\SOFTWARE\ATOMIC-T1053.005).test)))" /SC daily /ST 07:45 /F
     ```
- **Observed Result:** Scheduled task registered unblocked under user context; task XML definition created in `C:\Windows\System32\Tasks\ATOMIC-T1053.005`.

## Key Windows Event Records

| Provider / Channel | Event ID | Record ID | Event Details |
| :--- | :--- | :--- | :--- |
| Security | 4698 | 44656 | Scheduled task created (`\ATOMIC-T1053.005`). Preserves embedded Task XML (daily trigger, 07:45, user principal `SOCLAB\employee01`, Base64 decoding action chain) and creator process linkage (`ClientProcessId: 10956`). |
| Microsoft-Windows-TaskScheduler/Operational | 106 | 10676 | Task registered confirmation under `SOCLAB\employee01` (TaskScheduler execution PID 1592). |
| Microsoft-Windows-Sysmon/Operational | 11 | 288247 | File creation of task definition `C:\Windows\System32\Tasks\ATOMIC-T1053.005` by PID 1592 (`svchost.exe`). |
| Microsoft-Windows-Sysmon/Operational | 1 | 288245 | Process Creation for `schtasks.exe` (PID 10956, Parent PID 10632 `cmd.exe`). |
| Security | 4688 | 44655 | Security auditing of `schtasks.exe` (PID 10956, Creator PID 10632). |

## Correlation Analysis
- **Creator Process Linkage:** Windows Security Event 4698 `ClientProcessId` (10956) correlates directly with the `schtasks.exe` process ID in Sysmon Event 1 and Security Event 4688.
- **Task Definition Linkage:** Shared provider PID 1592 links task registration (TaskScheduler Event 106) with task file creation (Sysmon Event 11).

## Remediation & Cleanup
- Scheduled task was deleted via `schtasks /delete /tn "ATOMIC-T1053.005" /F` (recorded by TaskScheduler Event 141 and Security Event 4699).
- Staging registry key was deleted via `reg delete HKCU\SOFTWARE\ATOMIC-T1053.005 /F`.
- Host verification confirmed complete removal of all artifacts.

## Scope Limitation
This execution proves persistence configuration creation. The task action itself was intentionally not triggered (`schtasks /Run` was not executed); this finding does not claim future action execution, payload execution, or privilege escalation.
