# Rundll32 Proxy Execution — Splunk Validation

## Telemetry Ingestion
- **Index:** `windows`
- **Host:** `WIN11-01`
- **Sources:** `Wineventlog:Microsoft-Windows-Sysmon/Operational`, `Wineventlog:Security`

## Validated Events

| Channel | Event ID | Record ID | Event Time (UTC) | Key Extracted Fields |
| :--- | :--- | :--- | :--- | :--- |
| Sysmon | 1 | 213562 | 2026-10-23T12:14:12.248Z | `Image: C:\Windows\System32\rundll32.exe`, `ProcessId: 9080`, `ProcessGuid: {e99b4396-4f94-6adb-9405-000000000f00}`, `ParentProcessId: 1384` |
| Sysmon | 1 | 213567 | 2026-10-23T12:14:12.435Z | `Image: C:\Windows\System32\notepad.exe`, `ProcessId: 5740`, `ParentProcessId: 9080`, `ParentProcessGuid: {e99b4396-4f94-6adb-9405-000000000f00}` |
| Security | 4688 | 37633 | 2026-10-23T12:14:12.235Z | `NewProcessName: C:\Windows\System32\rundll32.exe`, `NewProcessId: 0x2378` (9080), `TargetUserName: employee01` |

## Correlation Analysis
- **Process Lineage Correlation:** Splunk query correlates parent `rundll32.exe` to child `notepad.exe` via matching `ProcessGuid` / `ParentProcessGuid` (`{e99b4396-4f94-6adb-9405-000000000f00}`) and PID (`9080`).
- **Cross-Source Agreement:** Windows Security Event 4688 independently confirms the creation of PID 9080 under `SOCLAB\employee01`.

## Result
Parent-child execution lineage between `rundll32.exe` and `notepad.exe` is established deterministically from centralized telemetry.

## Splunk Investigation Query
- Link: [`splunk/rundll32-proxy-execution.spl`](../../splunk/rundll32-proxy-execution.spl)
