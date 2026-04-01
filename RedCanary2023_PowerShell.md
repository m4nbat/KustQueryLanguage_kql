# Red Canary 2023: PowerShell Suspicious Activity Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | [PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| T1620 | Reflective Code Loading | [Reflective Code Loading](https://attack.mitre.org/techniques/T1620/) |

#### Description
Detection queries for suspicious PowerShell activity. Covers rundll32 child processes with web requests, iex/iwr regex detection, and system.management.automation.dll loading by unusual processes.

#### Risk
PowerShell is one of the most commonly abused tools by adversaries for execution, persistence, and lateral movement. Detecting anomalous PowerShell module loads and command patterns is essential for catching threats early.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/threat-detection-report/techniques/powershell/

## Defender For Endpoint
```KQL
DeviceImageLoadEvents
| where InitiatingProcessParentFileName =~ "rundll32.exe" and InitiatingProcessCommandLine has_any ("iwr","Invoke-webrequest")
```

```KQL
DeviceProcessEvents
| where ProcessCommandLine matches regex @"[^\w]iex[^\w]|invoke-expression"
```

```KQL
DeviceProcessEvents
| where ProcessCommandLine matches regex @"[^\w]iwr[^\w]|invoke-webrequest"
```

```KQL
let excludedParentProcesses = datatable (process:string)["SenseIR.exe","SenseCM.exe"];
DeviceImageLoadEvents
| where FileName contains "system.management.automation.dll" and InitiatingProcessParentFileName !in~ (excludedParentProcesses)
| project InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## Sentinel
```KQL
DeviceImageLoadEvents
| where InitiatingProcessParentFileName =~ "rundll32.exe" and InitiatingProcessCommandLine has_any ("iwr","Invoke-webrequest")
```

```KQL
DeviceProcessEvents
| where ProcessCommandLine matches regex @"[^\w]iex[^\w]|invoke-expression"
```

```KQL
DeviceProcessEvents
| where ProcessCommandLine matches regex @"[^\w]iwr[^\w]|invoke-webrequest"
```

```KQL
let excludedParentProcesses = datatable (process:string)["SenseIR.exe","SenseCM.exe"];
DeviceImageLoadEvents
| where FileName contains "system.management.automation.dll" and InitiatingProcessParentFileName !in~ (excludedParentProcesses)
| project InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```
