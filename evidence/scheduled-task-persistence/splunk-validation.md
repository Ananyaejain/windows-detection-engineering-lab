# Scheduled-Task Persistence — Splunk Validation

## Telemetry Ingestion
- **Index:** `windows`
- **Host:** `WIN11-01`
- **Sources:** `Wineventlog:Security`, `Wineventlog:Microsoft-Windows-TaskScheduler/Operational`, `Wineventlog:Microsoft-Windows-Sysmon/Operational`

## Validated Events

| Channel | Event ID | Record ID | Event Time (UTC) | Key Extracted Fields |
| :--- | :--- | :--- | :--- | :--- |
| Security | 4698 | 44656 | 2026-10-28T10:57:32.486Z | `TaskName: \ATOMIC-T1053.005`, `ClientProcessId: 10956`, `TaskContent` XML containing daily trigger at 07:45 and Base64 decode command action |
| TaskScheduler | 106 | 10676 | 2026-10-28T10:57:32.485Z | `TaskName: \ATOMIC-T1053.005`, `UserContext: SOCLAB\employee01`, `ProcessId: 1592` |
| Sysmon | 11 | 288247 | 2026-10-28T10:57:32.485Z | `TargetFilename: C:\Windows\System32\Tasks\ATOMIC-T1053.005`, `ProcessId: 1592` |
| Sysmon | 1 | 288245 | 2026-10-28T10:57:30.380Z | `Image: C:\Windows\System32\schtasks.exe`, `ProcessId: 10956`, `ParentProcessId: 10632` |
| Security | 4688 | 44655 | 2026-10-28T10:57:32.486Z | `NewProcessName: C:\Windows\System32\schtasks.exe`, `NewProcessId: 0x2acc` (10956), `CreatorProcessId: 0x2988` (10632) |

## Correlation Analysis
- **Creator Process Linkage:** Splunk query correlates Windows Security Event 4698 `ClientProcessId` directly to `schtasks.exe` process creation (PID 10956), proving which process registered the persistence task.
- **Task Definition Linkage:** Shared provider PID 1592 links task registration (Event 106) with task definition file creation (Sysmon Event 11).
- **Configuration Fidelity:** Event 4698 preserves the complete XML configuration inside the event record, allowing defenders to inspect scheduled execution actions without querying the live endpoint.

## Result
User-context scheduled task persistence verified with creator process attribution and complete task XML definition in central telemetry.

## Splunk Investigation Query
- Link: [`splunk/scheduled-task-persistence.spl`](../../splunk/scheduled-task-persistence.spl)
