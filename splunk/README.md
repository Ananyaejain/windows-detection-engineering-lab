# Splunk Queries

Queries used to retrieve and correlate telemetry from the five documented lab scenarios. These are investigation/validation searches, not production detection rules.

| Technique | What the query shows | Query |
| --- | --- | --- |
| T1218.011 Rundll32 | Parent → child process lineage | [rundll32-proxy-execution.spl](rundll32-proxy-execution.spl) |
| T1059.001 PowerShell | Registry → decode → dynamic execution | [powershell-fileless-execution.spl](powershell-fileless-execution.spl) |
| T1087.002 AD Account Discovery | ADSISearcher enumeration | [ad-account-discovery.spl](ad-account-discovery.spl) |
| T1547.001 Run Key | Registry persistence state change | [run-key-persistence.spl](run-key-persistence.spl) |
| T1053.005 Scheduled Task | Task definition + creator linkage | [scheduled-task-persistence.spl](scheduled-task-persistence.spl) |
