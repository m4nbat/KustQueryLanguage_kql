# Remote Access Tool (RAT) Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1219 | Remote Access Software | [Remote Access Software](https://attack.mitre.org/techniques/T1219/) |

#### Description
Catch-all detection queries for identifying Remote Access Tools (RATs) including AnyDesk, GoToAssist, LogMeIn, TeamViewer, Action1, and VNC. Uses file metadata and process data to identify RAT activity.

#### Risk
Threat actors abuse legitimate remote access tools to maintain persistent access to compromised systems. These tools are often installed under the guise of IT support or delivered as malware payloads.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://twitter.com/Kostastsale/status/1646256901506605063
- https://attack.mitre.org/techniques/T1219/

## Defender For Endpoint
```KQL
let RATs = datatable (name:string)["action1","anydesk","gotoassist","logmein","teamviewer","vnc"];
let RATNames = DeviceFileEvents 
| where InitiatingProcessVersionInfoOriginalFileName has_any (RATs) or FileName has_any (RATs) | distinct FileName;
DeviceNetworkEvents | where InitiatingProcessFileName in~ (RATNames) and ActionType contains "connection"
```

```KQL
let action1FileNames = DeviceFileEvents
| where InitiatingProcessVersionInfoOriginalFileName contains "action1" or FileName contains "action1" | distinct FileName;
DeviceProcessEvents
| where InitiatingProcessFileName in~ (action1FileNames) or FileName in~ (action1FileNames) or InitiatingProcessParentFileName in~ (action1FileNames)
```

```KQL
let action1FileNames = DeviceFileEvents
| where InitiatingProcessVersionInfoOriginalFileName contains "action1" or FileName contains "action1" | distinct FileName;
DeviceProcessEvents
| where InitiatingProcessFileName in~ (action1FileNames) and FileName in~ ("PowerShell.exe","cmd.exe")
```

## Sentinel
```KQL
let RATs = datatable (name:string)["action1","anydesk","gotoassist","logmein","teamviewer","vnc"];
let RATNames = DeviceFileEvents 
| where InitiatingProcessVersionInfoOriginalFileName has_any (RATs) or FileName has_any (RATs) | distinct FileName;
DeviceNetworkEvents | where InitiatingProcessFileName in~ (RATNames) and ActionType contains "connection"
```

```KQL
let action1FileNames = DeviceFileEvents
| where InitiatingProcessVersionInfoOriginalFileName contains "action1" or FileName contains "action1" | distinct FileName;
DeviceProcessEvents
| where InitiatingProcessFileName in~ (action1FileNames) or FileName in~ (action1FileNames) or InitiatingProcessParentFileName in~ (action1FileNames)
```

```KQL
let action1FileNames = DeviceFileEvents
| where InitiatingProcessVersionInfoOriginalFileName contains "action1" or FileName contains "action1" | distinct FileName;
DeviceProcessEvents
| where InitiatingProcessFileName in~ (action1FileNames) and FileName in~ ("PowerShell.exe","cmd.exe")
```
