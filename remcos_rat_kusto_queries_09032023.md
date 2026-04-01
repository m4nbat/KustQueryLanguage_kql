# Remcos RAT Hunt Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | [Bypass UAC](https://attack.mitre.org/techniques/T1548/002/) |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) |
| T1036 | Masquerading | [Masquerading](https://attack.mitre.org/techniques/T1036/) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |

#### Description
Hunt queries for DBATLoader delivering Remcos RAT, targeting Eastern Europe. Covers mock trusted directory creation for UAC bypass, cleanup of mock directories, file drops into the fake Windows path, PowerShell-based Microsoft Defender exclusion, and registry run key persistence.

#### Risk
Remcos RAT provides attackers with full remote access capabilities including keylogging, screen capture, file transfer, and shell command execution. These detections target the DBATLoader delivery mechanism and UAC bypass techniques used to install Remcos with elevated privileges.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://www.sentinelone.com/blog/dbatloader-and-remcos-rat-sweep-eastern-europe/
- https://www.bleepingcomputer.com/news/security/bypassing-windows-10-uac-with-mock-folders-and-dll-hijacking/

## Defender For Endpoint

### Addition of mock trusted directories to attempt to bypass UAC
```KQL
//Addition of mock trusted directories to attempt to bypass user account control
//https://www.bleepingcomputer.com/news/security/bypassing-windows-10-uac-with-mock-folders-and-dll-hijacking/
DeviceProcessEvents
| where ProcessCommandLine endswith @"mkdir \\?\C:\Windows " or ProcessCommandLine endswith @"mkdir \\?\C:\Windows \System32"
```

### Deletion of mock trusted directories as part of cleanup
```KQL
//Deletion of mock trusted directories as part of cleanup
DeviceProcessEvents
| where ProcessCommandLine has_all ("del","/q",@"C:\Windows \System32") or ProcessCommandLine has_all ('rmdir',@"C:\Windows \System32") or ProcessCommandLine has_all ('rmdir',@"C:\Windows \")
```

### Detection of files created in mock trusted directory
```KQL
//Detection of files created in the above folder possibly dropped by the DBATLoader
DeviceFileEvents
| where ActionType =~ "FileCreated" and FileName has_any (".bat",".exe",".dll") and (FolderPath startswith @"C:\Windows \System32" or FolderPath startswith @"C:\Windows \")
```

### PowerShell defense evasion via Microsoft Defender exclusions
```KQL
//Detection of PowerShell defese evasion via Micrososft Defender exclusions
DeviceProcessEvents
| where ProcessCommandLine has_all ("-WindowStyle","Hidden","-Command","Add-MpPreference","-ExclusionPath",@"C:\Users")
```

### Registry run key creation for persistence (DBATLoader / Remcos campaign)
```KQL
// Hunt for registry run key being created for persistence when hunting for DBatLoader as part of Remcos RAT campaign
DeviceRegistryEvents
| where ActionType =~ "RegistryValueSet" and RegistryKey =~ @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
```
