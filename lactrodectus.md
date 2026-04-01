# Latrodectus Malware Detection Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218.011 | System Binary Proxy Execution: Rundll32 | [Rundll32](https://attack.mitre.org/techniques/T1218/011/) |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | [Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/) |
| T1059 | Command and Scripting Interpreter | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |

#### Description
Queries to detect Latrodectus malware activity including DLL loading via rundll32/msiexec, file creation of malicious MSI and DLL files, and persistence via startup registry keys.

#### Risk
Latrodectus is a malware loader that uses DLL side-loading and registry-based persistence to maintain access to compromised systems. Detection of these indicators suggests an active Latrodectus infection.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [Latrodectus malware analysis](https://attack.mitre.org/software/)

## Defender For Endpoint

```KQL
//Loading Latrodectus DLLs
//The following query looks for evidence of rundll32 loading the Latrodectus DLL.
DeviceProcessEvents
| where InitiatingProcessCommandLine has_any("capisp.dll", "aclui.dll") and InitiatingProcessFileName in ("rundll32.exe", "msiexec.exe")
```

```KQL
//This query identifies newly created (dropped) Latrodectus MSI and DLL files.
DeviceFileEvents
| where FolderPath has_any ("Roaming\\aclui", "Roaming\\capisp", "temp\vpn.msi", "neuro.msi", "bst.msi") and InitiatingProcessCommandLine has_any("msiexec", "rundll32")
```

```KQL
//The following query looks for evidence of Latrodectus DLL persistence using the startup registry key.
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"CurrentVersion\Run"
| where RegistryValueData has_any(@"AppData\Roaming\capisp.dll", @"AppData\Roaming\aclui.dll")
| where InitiatingProcessFileName == "rundll32.exe"
```
