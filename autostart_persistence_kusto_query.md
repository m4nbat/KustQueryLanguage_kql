# Autostart Persistence Registry Key Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1547 | Boot or Logon Autostart Execution | [Autostart Execution](https://attack.mitre.org/techniques/T1547/) |

#### Description
Detects modifications to autostart persistence registry keys beyond the standard Run keys. Based on 'Beyond Good Ol Run Key' research tracking less common persistence locations.

#### Risk
Adversaries use obscure autostart registry keys to establish persistence that survives reboots. These non-standard locations are often overlooked by security tools.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://www.hexacorn.com/blog/2017/01/28/beyond-good-ol-run-key-all-parts/

## Defender For Endpoint
```KQL
let CompromisedDevices = dynamic (["laptop1", "server1"]);
let SearchWindow = 7d; //Customizable h = hours, d = days
DeviceRegistryEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName has_any (CompromisedDevices)
| where PreviousRegistryKey startswith "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Extension\PeerdistDllName=peerdist.dll"
| extend RegistryChangeInfo = pack_dictionary("RegistryKey", RegistryKey, "Action Performed", ActionType, "Old Value", PreviousRegistryKey, "New Value", RegistryValueData)
| summarize TotalKeysChanged = count(), RegistryInfo = make_set(RegistryChangeInfo) by DeviceName
```

## Sentinel
```KQL
let CompromisedDevices = dynamic (["laptop1", "server1"]);
let SearchWindow = 7d; //Customizable h = hours, d = days
DeviceRegistryEvents
| where TimeGenerated > ago(SearchWindow)
| where DeviceName has_any (CompromisedDevices)
| where PreviousRegistryKey startswith "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Extension\PeerdistDllName=peerdist.dll"
| extend RegistryChangeInfo = pack_dictionary("RegistryKey", RegistryKey, "Action Performed", ActionType, "Old Value", PreviousRegistryKey, "New Value", RegistryValueData)
| summarize TotalKeysChanged = count(), RegistryInfo = make_set(RegistryChangeInfo) by DeviceName
```
