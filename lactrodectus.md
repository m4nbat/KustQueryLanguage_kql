# Latrodectus Malware Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218.011 | Signed Binary Proxy Execution: Rundll32 | [Rundll32](https://attack.mitre.org/techniques/T1218/011/) |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | [Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/) |

#### Description
Detection queries for Latrodectus malware activity. Covers rundll32 loading Latrodectus DLLs (capisp.dll, aclui.dll), MSI/DLL file creation in user directories, and registry persistence via Run keys.

#### Risk
Latrodectus is a malware loader first observed in 2023. It uses renamed legitimate Windows DLLs and MSI files for delivery, establishing persistence via registry run keys.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://attack.mitre.org/software/S1089/

## Defender For Endpoint
```KQL
DeviceProcessEvents
| where InitiatingProcessCommandLine has_any("capisp.dll", "aclui.dll") and InitiatingProcessFileName in ("rundll32.exe", "msiexec.exe")
```

```KQL
DeviceFileEvents
| where FolderPath has_any ("Roaming\\aclui", "Roaming\\capisp", "temp\\vpn.msi", "neuro.msi", "bst.msi") and InitiatingProcessCommandLine has_any("msiexec", "rundll32")
```

```KQL
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"CurrentVersion\\Run"
| where RegistryValueData has_any(@"AppData\\Roaming\\capisp.dll", @"AppData\\Roaming\\aclui.dll")
| where InitiatingProcessFileName == "rundll32.exe"
```

## Sentinel
```KQL
DeviceProcessEvents
| where InitiatingProcessCommandLine has_any("capisp.dll", "aclui.dll") and InitiatingProcessFileName in ("rundll32.exe", "msiexec.exe")
```

```KQL
DeviceFileEvents
| where FolderPath has_any ("Roaming\\aclui", "Roaming\\capisp", "temp\\vpn.msi", "neuro.msi", "bst.msi") and InitiatingProcessCommandLine has_any("msiexec", "rundll32")
```

```KQL
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"CurrentVersion\\Run"
| where RegistryValueData has_any(@"AppData\\Roaming\\capisp.dll", @"AppData\\Roaming\\aclui.dll")
| where InitiatingProcessFileName == "rundll32.exe"
```
