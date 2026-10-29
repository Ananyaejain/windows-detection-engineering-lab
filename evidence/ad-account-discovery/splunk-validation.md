# Active Directory Account Discovery — Splunk Validation

## Telemetry Ingestion
- **Index:** `windows`
- **Hosts:** `WIN11-01`, `DC01`
- **Sources:** `Wineventlog:Microsoft-Windows-PowerShell/Operational`, `Wineventlog:Microsoft-Windows-Sysmon/Operational`, `Wineventlog:Security`

## Validated Events

| Host | Channel | Event ID | Record ID | Event Time (UTC) | Key Extracted Fields |
| :--- | :--- | :--- | :--- | :--- | :--- |
| WIN11-01 | PowerShell | 4104 | 10133 | 2026-10-27T11:52:06.901Z | `ScriptBlockText: ([adsisearcher]"objectcategory=user").FindAll()...` |
| WIN11-01 | Sysmon | 3 | 256426 | 2026-10-27T11:52:09.157Z | `Image: ...\powershell.exe`, `DestinationIp: 10.50.0.10`, `DestinationPort: 389`, `SourcePort: 49531` |
| WIN11-01 | Sysmon | 3 | 256427 | 2026-10-27T11:52:09.411Z | `DestinationIp: 10.50.0.10`, `DestinationPort: 389`, `SourcePort: 49532` |
| DC01 | Security | 4624 | 41568 | 2026-10-27T11:52:07.113Z | `LogonType: 3`, `TargetUserName: employee01`, `IpAddress: 10.50.0.20`, `IpPort: 49531` |
| DC01 | Security | 4624 | 41570 | 2026-10-27T11:52:07.141Z | `LogonType: 3`, `TargetUserName: employee01`, `IpAddress: 10.50.0.20`, `IpPort: 49532` |

## Correlation Analysis
- **Command & Network Linkage:** PowerShell Event 4104 proves the exact ADSI enumeration script executed on the endpoint.
- **Cross-Host Correlation:** Splunk query correlates outbound endpoint connections (Sysmon Event 3) with domain controller network logons (Security Event 4624) via matching source IP (`10.50.0.20`), user identity (`employee01`), and ephemeral source ports (`49531` and `49532`).

## Result
Native Living-off-the-Land directory reconnaissance detected and correlated end-to-end between endpoint execution and domain controller telemetry.

## Splunk Investigation Query
- Link: [`splunk/ad-account-discovery.spl`](../../splunk/ad-account-discovery.spl)
