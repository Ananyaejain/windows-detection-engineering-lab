# PowerShell Fileless Script Execution — Execution

## Activity Summary
- **ATT&CK Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell
- **Host:** WIN11-01 (Windows 11 Enterprise)
- **User Context:** `SOCLAB\employee01` (Standard domain user, Medium integrity `S-1-16-8192`)
- **Execution Workflow:**
  1. Staged encoded payload into `HKCU:\Software\Classes\AtomicRedTeam` (Value: `test`).
  2. Executed fileless PowerShell invocation:
     ```powershell
     powershell.exe -Command "IEX ([System.Text.Encoding]::UNICODE.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path 'HKCU:\Software\Classes\AtomicRedTeam').test)))"
     ```
- **Observed Result:** Command decoded in memory and created marker file `C:\Windows\Temp\art-marker.txt`.

## Key Windows Event Records

| Provider / Channel | Event ID | Record ID | Event Details |
| :--- | :--- | :--- | :--- |
| Microsoft-Windows-PowerShell/Operational | 4104 | 10025 | ScriptBlock Logging captured the decoded payload: `Set-Content -Path 'C:\Windows\Temp\art-marker.txt' -Value 'Hello from Atomic Red Team'`. |
| Microsoft-Windows-PowerShell/Operational | 4103 | 10024 | Pipeline Execution captured `Get-ItemProperty` retrieval from `HKCU:\Software\Classes\AtomicRedTeam`. |
| Microsoft-Windows-PowerShell/Operational | 4103 | 10027 | Pipeline Execution captured `Invoke-Expression` executing the decoded payload. |
| Microsoft-Windows-Sysmon/Operational | 11 | 247648 | File creation of `C:\Windows\Temp\art-marker.txt` attributed to `powershell.exe` (PID 4824). |

## Remediation & Cleanup
- Test registry key `HKCU:\Software\Classes\AtomicRedTeam` was deleted.
- Marker file `C:\Windows\Temp\art-marker.txt` was removed.
- Absence of both artifacts was verified on the host.

## Scope Limitation
This execution validates local registry staging, in-memory decoding, and dynamic evaluation. It does not claim remote network download, external C2 communication, persistence, or privilege escalation.
