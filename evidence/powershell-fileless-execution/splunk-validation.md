# PowerShell Fileless Script Execution — Splunk Validation

## Telemetry Ingestion
- **Index:** `windows`
- **Host:** `WIN11-01`
- **Sources:** `Wineventlog:Microsoft-Windows-PowerShell/Operational`, `Wineventlog:Microsoft-Windows-Sysmon/Operational`

## Validated Events

| Channel | Event ID | Record ID | Event Time (UTC) | Key Extracted Fields |
| :--- | :--- | :--- | :--- | :--- |
| PowerShell | 4104 | 10025 | 2026-10-27T10:12:41.718Z | `ScriptBlockText: Set-Content -Path 'C:\Windows\Temp\art-marker.txt' -Value 'Hello from Atomic Red Team'`, `Opcode: Create` |
| PowerShell | 4103 | 10024 | 2026-10-27T10:12:41.644Z | `ContextInfo: Get-ItemProperty`, `Payload: HKCU:\Software\Classes\AtomicRedTeam` |
| PowerShell | 4103 | 10027 | 2026-10-27T10:12:41.785Z | `ContextInfo: Invoke-Expression`, `Payload: Set-Content -Path ...` |
| Sysmon | 11 | 247648 | 2026-10-27T10:12:41.792Z | `TargetFilename: C:\Windows\Temp\art-marker.txt`, `Image: ...\powershell.exe`, `ProcessId: 4824` |

## Correlation Analysis
- **Execution Chain Reconstruction:** PowerShell Event 4103 proves registry retrieval, followed immediately by Event 4104 capturing the decoded script text, Event 4103 capturing `Invoke-Expression`, and Sysmon Event 11 confirming marker file creation.
- **De-obfuscation Visibility:** Demonstrates that PowerShell ScriptBlock Logging (Event 4104) captures the underlying plaintext command syntax even when the initial command line is encoded or obfuscated in the registry.

## Result
Complete fileless staging, decoding, and in-memory execution pipeline verified in centralized telemetry.

## Splunk Investigation Query
- Link: [`splunk/powershell-fileless-execution.spl`](../../splunk/powershell-fileless-execution.spl)
