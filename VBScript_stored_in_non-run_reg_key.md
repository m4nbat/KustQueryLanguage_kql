# VBScript Stored in Non-Run CurrentVersion Registry Key

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1112 | Modify Registry | [Modify Registry](https://attack.mitre.org/techniques/T1112/) |

#### Description
Detects VBScript, JScript, or other script data stored in non-standard CurrentVersion registry keys. This technique is used by malware to store and execute scripts via registry persistence.

#### Risk
Adversaries store malicious scripts in non-standard registry locations to evade Run key-focused detection tools.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://www.cyborgsecurity.com/

## Defender For Endpoint
```KQL
DeviceRegistryEvents
| where RegistryKey has "\\CurrentVersion" 
| where RegistryKey !has "\\Run"
| where RegistryValueData has_any ("RunHTMLApplication","vbscript","jscript","mshtml","mshtml","mshtml ","Execute","CreateObject","RegRead","window.close")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, PreviousRegistryValueName, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessParentId, DeviceId, ReportId
| order by Timestamp
```

## Sentinel
```KQL
SecurityEvent
| where ObjectName has "\\CurrentVersion"
| where ObjectName !has "\\Run"
| where NewValue has_any ("RunHTMLApplication","vbscript","jscript","mshtml","mshtml","mshtml ","Execute","CreateObject","RegRead","window.close")
| project TimeGenerated, Computer, Process, ObjectName, ObjectValueName, NewValue, OldValue, SubjectUserName, NewProcessId, SourceComputerId
| order by TimeGenerated
```
