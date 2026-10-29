# Run-Key Persistence — Splunk Validation

## Telemetry Ingestion
- **Index:** `windows`
- **Host:** `WIN11-01`
- **Sources:** `Wineventlog:Microsoft-Windows-Sysmon/Operational`, `Wineventlog:Security`

## Validated Events

| Channel | Event ID | Record ID | Event Time (UTC) | Key Extracted Fields |
| :--- | :--- | :--- | :--- | :--- |
| Sysmon | 13 | 279657 | 2026-10-28T08:57:28.028Z | `EventType: SetValue`, `TargetObject: ...\Software\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team`, `Details: C:\Path\AtomicRedTeam.exe`, `ProcessId: 8024`, `ProcessGuid: {e99b4396-b8f8-6ae1-c40c-000000001000}` |
| Sysmon | 1 | 279655 | 2026-10-28T08:57:28.018Z | `Image: C:\Windows\System32\reg.exe`, `ProcessId: 8024`, `ProcessGuid: {e99b4396-b8f8-6ae1-c40c-000000001000}`, `ParentProcessId: 8336` |
| Security | 4688 | 43631 | 2026-10-28T08:57:28.010Z | `NewProcessName: C:\Windows\System32\reg.exe`, `NewProcessId: 0x1f58` (8024), `CreatorProcessId: 0x2090` (8336), `TargetUserName: employee01` |

## Correlation Analysis
- **Process to State Change:** Splunk search links the registry modification (Sysmon Event 13) directly to the parent process execution (Sysmon Event 1) through matching `ProcessGuid` (`{e99b4396-b8f8-6ae1-c40c-000000001000}`) and PID (`8024`).
- **State Change Detection:** Proves that monitoring registry state changes (`SetValue`) provides high-fidelity persistence detection independently of command-line obfuscation.

## Result
User-context autostart persistence creation verified with deterministic process-to-state-change linkage.

## Splunk Investigation Query
- Link: [`splunk/run-key-persistence.spl`](../../splunk/run-key-persistence.spl)
