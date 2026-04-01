# Red Canary 2023: Service Execution Detection (T1569.002)

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1569.002 | System Services: Service Execution | [Service Execution](https://attack.mitre.org/techniques/T1569/002/) |

#### Description
Detection queries for malicious service execution based on Red Canary 2023 threat report. Identifies suspicious services being created or executed by unexpected parent processes.

#### Risk
Adversaries create or modify system services to execute malicious code. Service execution allows code to run with SYSTEM privileges and persists across reboots, making it a high-impact technique.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/threat-detection-report/techniques/service-execution/

## Defender For Endpoint
```KQL
// Suspicious service installation via services.exe
DeviceEvents
| where ActionType =~ "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
| extend ImagePath = tostring(parse_json(AdditionalFields).ServiceImagePath)
| where ImagePath matches regex @"C:\\Windows\\[a-zA-Z]{8}.exe"
```

## Sentinel
```KQL
// Suspicious service creation - SecurityEvent
SecurityEvent
| where EventID == 7045
| where ServiceFileName matches regex @"C:\\Windows\\[a-zA-Z]{8}.exe"
```
