# ClearFake Malware - Suspicious VFS AppData Activity Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1543.003 | Create or Modify System Process: Windows Service | [Windows Service](https://attack.mitre.org/techniques/T1543/003/) |

#### Description
Detects suspicious activity associated with ClearFake malware in VFS/AppData paths, including ExploitGuard enforcement events, suspicious file creation in AppData VFS paths, and service installations from AppData.

#### Risk
ClearFake creates services and drops executables to unusual VFS AppData paths. These patterns help identify malware families delivered via fake browser updates.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://blog.sekoia.io/clearfake-a-newcomer-to-the-fake-updates-threats-landscape/

## Defender For Endpoint
```KQL
DeviceEvents
| where ActionType =~ "OtherAlertRelatedActivity"
| sort by TimeGenerated desc
```

```KQL
DeviceEvents
| where ActionType =~ "ExploitGuardAcgEnforced"
| sort by TimeGenerated desc
```

```KQL
DeviceFileEvents
| where FolderPath endswith @"\\VFS\\AppData\\KSPSService.exe" and FileName =~ "KSPSService.exe"
```

```KQL
DeviceFileEvents
| where FolderPath matches regex @"\\VFS\\AppData\\[a-zA-Z0-9]+.exe" and FileName endswith "exe"
```

```KQL
DeviceEvents
| where ActionType contains "ServiceInstalled"
| extend ServiceAccount_ = tostring(AdditionalFields.ServiceAccount)
| extend ServiceName_ = tostring(AdditionalFields.ServiceName)
| extend ServiceStartType_ = tostring(AdditionalFields.ServiceStartType)
| extend ServiceType_ = tostring(AdditionalFields.ServiceType)
| where FolderPath matches regex @"\\VFS\\AppData\\[a-zA-Z0-9]+.exe"
```

## Sentinel
```KQL
DeviceEvents
| where ActionType =~ "OtherAlertRelatedActivity"
| sort by TimeGenerated desc
```

```KQL
DeviceEvents
| where ActionType =~ "ExploitGuardAcgEnforced"
| sort by TimeGenerated desc
```

```KQL
DeviceFileEvents
| where FolderPath endswith @"\\VFS\\AppData\\KSPSService.exe" and FileName =~ "KSPSService.exe"
```

```KQL
DeviceFileEvents
| where FolderPath matches regex @"\\VFS\\AppData\\[a-zA-Z0-9]+.exe" and FileName endswith "exe"
```

```KQL
DeviceEvents
| where ActionType contains "ServiceInstalled"
| extend ServiceAccount_ = tostring(AdditionalFields.ServiceAccount)
| extend ServiceName_ = tostring(AdditionalFields.ServiceName)
| extend ServiceStartType_ = tostring(AdditionalFields.ServiceStartType)
| extend ServiceType_ = tostring(AdditionalFields.ServiceType)
| where FolderPath matches regex @"\\VFS\\AppData\\[a-zA-Z0-9]+.exe"
```
