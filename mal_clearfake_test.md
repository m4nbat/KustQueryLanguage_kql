# ClearFake Test Detection Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1027 | Obfuscated Files or Information | [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) |
| T1543 | Create or Modify System Process | [Create or Modify System Process](https://attack.mitre.org/techniques/T1543/) |

#### Description
Detection queries for ClearFake malware activity, including alert-related events, ExploitGuard enforcement, VFS AppData file drops, and suspicious service installations associated with ClearFake campaigns.

#### Risk
ClearFake is a fake browser update campaign that delivers malware via malicious JavaScript injected into compromised websites. These queries help identify execution and persistence artefacts on endpoints.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
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
| where FolderPath endswith @"\VFS\AppData\KSPSService.exe" and FileName =~ "KSPSService.exe"
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
| where FolderPath matches regex @"\\VFS\\AppData\\[a-zA-Z0-9]+.exe" //and ServiceName_ =~ "KSPSService.exe"
```
