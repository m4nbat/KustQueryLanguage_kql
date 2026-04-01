# PowerShell Creating LNK Files in Startup Directory (Yellow Cockatoo)

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [Startup Folder](https://attack.mitre.org/techniques/T1547/001/) |

#### Description
Detects PowerShell creating LNK (shortcut) files in the Windows startup folder, which is used by Yellow Cockatoo malware and other threats for persistence. This method ensures the malware runs on every user login.

#### Risk
Yellow Cockatoo and similar malware use PowerShell to create LNK files in startup directories for persistence. This is delivered via fake installer binaries and establishes persistence that survives reboots.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/blog/intelligence-insights-december-2022/

## Defender For Endpoint
```KQL
//PowerShell creating LNK files within a startup directory
//The following detection analytic identifies PowerShell creating LNK files in a startup directory. Malware like Yellow Cockatoo can be introduced as a fake installer binary, resulting in malicious PowerShell script execution. Some benign homegrown utilities or installers may create .lnk files in startup locations, so additional investigation of the activity may be necessary.
//https://redcanary.com/blog/intelligence-insights-december-2022/
let trusedUtilsInstallingLnkInStartup = datatable (util:string)["mytrustedutility.exe"];
DeviceFileEvents
| where ActionType =~ "FileCreated" and InitiatingProcessFileName =~ "powershell.exe" and FolderPath contains @"start menu\programs\startup" and not(InitiatingProcessCommandLine has_any (trusedUtilsInstallingLnkInStartup))
```

## Sentinel
```KQL
//PowerShell creating LNK files within a startup directory
//The following detection analytic identifies PowerShell creating LNK files in a startup directory. Malware like Yellow Cockatoo can be introduced as a fake installer binary, resulting in malicious PowerShell script execution. Some benign homegrown utilities or installers may create .lnk files in startup locations, so additional investigation of the activity may be necessary.
//https://redcanary.com/blog/intelligence-insights-december-2022/
let trusedUtilsInstallingLnkInStartup = datatable (util:string)["mytrustedutility.exe"];
DeviceFileEvents
| where ActionType =~ "FileCreated" and InitiatingProcessFileName =~ "powershell.exe" and FolderPath contains @"start menu\programs\startup" and not(InitiatingProcessCommandLine has_any (trusedUtilsInstallingLnkInStartup))
```
