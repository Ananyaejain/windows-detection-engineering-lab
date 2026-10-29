# Rundll32 Proxy Execution — Execution

## Activity Summary
- **ATT&CK Technique:** T1218.011 — System Binary Proxy Execution: Rundll32
- **Host:** WIN11-01 (Windows 11 Enterprise)
- **User Context:** `SOCLAB\employee01` (Standard domain user, Medium integrity `S-1-16-8192`)
- **Execution Command:**
  ```cmd
  rundll32.exe pcwutl.dll,LaunchApplication C:\WINDOWS\System32\notepad.exe
  ```
- **Observed Result:** Native binary executed unblocked and spawned `notepad.exe` as a direct child process.

## Key Windows Event Records

| Provider / Channel | Event ID | Record ID | Process | Details |
| :--- | :--- | :--- | :--- | :--- |
| Microsoft-Windows-Sysmon/Operational | 1 | 213562 | `rundll32.exe` (PID 9080) | ProcessGuid `{e99b4396-4f94-6adb-9405-000000000f00}`, spawned by `cmd.exe` (PID 1384). |
| Microsoft-Windows-Sysmon/Operational | 1 | 213567 | `notepad.exe` (PID 5740) | Direct child. ParentProcessGuid `{e99b4396-4f94-6adb-9405-000000000f00}`, ParentProcessId 9080. |
| Security | 4688 | 37633 | `rundll32.exe` (PID 9080) | Security auditing of process creation under standard user `SOCLAB\employee01`. |

## Correlation Analysis
- **Process Lineage Match:** Sysmon Event 1 Record 213567 has `ParentProcessGuid` matching the `ProcessGuid` of `rundll32.exe` (Record 213562).
- **Process ID Match:** Parent PID 9080 matches `rundll32.exe` PID 9080.
- **Lineage Classification:** Confirms direct parent-child relationship between proxy binary and child application.

## Remediation & Cleanup
- Both stub and application instances of `notepad.exe` were terminated.
- Confirmed zero residual instances running on the target endpoint.

## Scope Limitation
This execution proves signed proxy execution and direct child process lineage under a standard user account. It does not claim malicious DLL payload execution, code injection, or privilege escalation.
