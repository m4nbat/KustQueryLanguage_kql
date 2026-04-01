# Tampering with the Windows Event Log

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.002 | Impair Defenses: Disable Windows Event Logging | [Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/) |

#### Description
Detects possible tampering with the Windows event log via PowerShell modifications to event log publisher registry keys. Also includes a Sentinel/Security Events query using Windows Event IDs 1107 (audit log tampering) and 1108 (event processing error) to catch tampering activity at the OS level.

#### Risk
Attackers tamper with Windows event logs to hinder forensic investigation and cover their tracks. Detecting these modifications enables defenders to identify defense evasion activity and preserve the integrity of log data.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://www.linkedin.com/feed/update/urn:li:activity:7038997228815867904/

## Defender For Endpoint
```KQL
//Detect possible tampering with the Windows event log registry keys
DeviceRegistryEvents
| where InitiatingProcessCommandLine has @"powershell.exe"
| where ActionType == @"RegistryValueSet"
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\" and RegistryValueData endswith ".dll"
```

## Sentinel
```KQL
//Detect possible tampering with the Windows event log registry keys
SecurityEvent
| where EventID in (1108,1107)
```
