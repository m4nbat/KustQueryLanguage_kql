# Registry Run Key Persistence Forensics

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) |

#### Description
Forensic queries for investigating standard Windows Registry Run key activity on potentially compromised devices. Queries cover the four most common Run key locations (HKLM and HKCU Run/RunOnce) and summarize all changes made within a configurable time window.

#### Risk
Registry Run keys are a well-known persistence mechanism used by malware and threat actors to survive reboots. These queries support DFIR investigations by providing a complete picture of Run key modifications on targeted devices.

#### Author <Optional>
- **Name:** Bert-JanP
- **Github:** https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/edit/main/DFIR/DFE%20-%20Registry-Run-Keys-Forensics.md

## Defender For Endpoint
```KQL
let RegistryRunKeys = dynamic 
([@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",  
@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"]);
let CompromisedDevices = dynamic (["laptop1", "server1"]);
let SearchWindow = 7d; //Customizable h = hours, d = days
DeviceRegistryEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName has_any (CompromisedDevices)
| where RegistryKey has_any (RegistryRunKeys)
| extend RegistryChangeInfo = bag_pack("RegistryKey", RegistryKey, "Action Performed", ActionType, "Old Value", PreviousRegistryKey, "New Value", RegistryValueData)
| summarize TotalRunKeysChanged = count(), RegistryInfo = make_set(RegistryChangeInfo) by DeviceName
```

## Sentinel
```KQL
let RegistryRunKeys = dynamic 
([@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"
]);
let CompromisedDevices = dynamic (["laptop1", "server1"]);
let SearchWindow = 7d; //Customizable h = hours, d = days
DeviceRegistryEvents
| where TimeGenerated > ago(SearchWindow)
| where DeviceName has_any (CompromisedDevices)
| where RegistryKey has_any (RegistryRunKeys)
| extend RegistryChangeInfo = pack_dictionary("RegistryKey", RegistryKey, "Action Performed", ActionType, "Old Value", PreviousRegistryKey, "New Value", RegistryValueData)
| summarize TotalRunKeysChanged = count(), RegistryInfo = make_set(RegistryChangeInfo) by DeviceName
```
