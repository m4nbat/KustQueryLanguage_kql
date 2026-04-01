# Scheduled Task Abuse Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1053.005 | Scheduled Task/Job: Scheduled Task | [Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |

#### Description
Detection queries for scheduled task abuse across Windows versions. Covers task scheduler processes, temp directory task execution, file type-based detection, and remote scheduled task creation.

#### Risk
Scheduled tasks are one of the most commonly abused persistence mechanisms. Adversaries use them to maintain access, execute payloads at set intervals, and elevate privileges. Detection focuses on anomalous process execution chains from the task scheduler.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://attack.mitre.org/techniques/T1053/005/

## Defender For Endpoint
```KQL
//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule") or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| summarize count() by InitiatingProcessCommandLine, ProcessCommandLine
```

```KQL
//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule") or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| where ProcessCommandLine !endswith "AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe" and ProcessCommandLine !~ '"MicrosoftEdgeUpdate.exe" /ua /installsource scheduler' and ProcessCommandLine !endswith "gpupdate.exe /target:computer" and ProcessCommandLine !endswith "gpupdate.exe /target:user"
| summarize count() by InitiatingProcessCommandLine, ProcessCommandLine
| where  count_ <= 100
```

```KQL
//scheduled tasks
DeviceProcessEvents
| where (ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule") and InitiatingProcessCommandLine contains "%TEMP%") or (InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule") and ProcessCommandLine contains "%TEMP%"))
| summarize count() by InitiatingProcessCommandLine, ProcessCommandLine
```

```KQL
//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("taskeng.exe","{") or InitiatingProcessCommandLine has_all ("taskeng.exe","{")
| summarize count() by InitiatingProcessCommandLine, ProcessCommandLine
```

```KQL
//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")  or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| summarize count() by FileName
```

```KQL
//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")  or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| summarize count() by FolderPath
```

```KQL
//scheduled tasks associated with certain filetypes associated with badness
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")  or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| where FileName contains "powershell" or FileName contains "cmd"  or FileName contains "rundll32" or FileName contains "regsvr32"  or FileName contains "wmic" 
| summarize count() by ProcessCommandLine
```

```KQL
DeviceProcessEvents
| where FileName contains "powershell" or FileName contains "cmd"  or FileName contains "rundll32" or FileName contains "regsvr32"  or FileName contains "wmic" 
| summarize count() by ProcessCommandLine
```

```KQL
DeviceProcessEvents
| where FileName contains ".ps1" or FileName contains ".bat"  or FileName contains ".vbs" or FileName contains ".cmd"  or FileName contains ".hta" or FileName contains ".js" 
| summarize count() by ProcessCommandLine
```

```KQL
//scheduled tasks created by wscript or cscript and is not a common script extension (scrip interpreter but using a script file)
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")  or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| where FileName has_any ("wscript.exe","cscript.exe")  and not (ProcessCommandLine has_any (".vbs",".js"))
| summarize count() by ProcessCommandLine
```

```KQL
DeviceImageLoadEvents
| where FileName =~ "mswsock.dll" and InitiatingProcessFileName has_any ("schtasks.exe","mmc.exe","at.exe")
//| project FileName, InitiatingProcessFileName, InitiatingProcessParentFileName
```

## Sentinel
```KQL
//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule") or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| summarize count() by InitiatingProcessCommandLine, ProcessCommandLine
```

```KQL
//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule") or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| where ProcessCommandLine !endswith "AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe" and ProcessCommandLine !~ '"MicrosoftEdgeUpdate.exe" /ua /installsource scheduler' and ProcessCommandLine !endswith "gpupdate.exe /target:computer" and ProcessCommandLine !endswith "gpupdate.exe /target:user"
| summarize count() by InitiatingProcessCommandLine, ProcessCommandLine
| where  count_ <= 100
```

```KQL
//scheduled tasks
DeviceProcessEvents
| where (ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule") and InitiatingProcessCommandLine contains "%TEMP%") or (InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule") and ProcessCommandLine contains "%TEMP%"))
| summarize count() by InitiatingProcessCommandLine, ProcessCommandLine
```

```KQL
//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("taskeng.exe","{") or InitiatingProcessCommandLine has_all ("taskeng.exe","{")
| summarize count() by InitiatingProcessCommandLine, ProcessCommandLine
```

```KQL
//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")  or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| summarize count() by FileName
```

```KQL
//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")  or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| summarize count() by FolderPath
```

```KQL
//scheduled tasks associated with certain filetypes associated with badness
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")  or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| where FileName contains "powershell" or FileName contains "cmd"  or FileName contains "rundll32" or FileName contains "regsvr32"  or FileName contains "wmic" 
| summarize count() by ProcessCommandLine
```

```KQL
DeviceProcessEvents
| where FileName contains "powershell" or FileName contains "cmd"  or FileName contains "rundll32" or FileName contains "regsvr32"  or FileName contains "wmic" 
| summarize count() by ProcessCommandLine
```

```KQL
DeviceProcessEvents
| where FileName contains ".ps1" or FileName contains ".bat"  or FileName contains ".vbs" or FileName contains ".cmd"  or FileName contains ".hta" or FileName contains ".js" 
| summarize count() by ProcessCommandLine
```

```KQL
//scheduled tasks created by wscript or cscript and is not a common script extension (scrip interpreter but using a script file)
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")  or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| where FileName has_any ("wscript.exe","cscript.exe")  and not (ProcessCommandLine has_any (".vbs",".js"))
| summarize count() by ProcessCommandLine
```

```KQL
DeviceImageLoadEvents
| where FileName =~ "mswsock.dll" and InitiatingProcessFileName has_any ("schtasks.exe","mmc.exe","at.exe")
//| project FileName, InitiatingProcessFileName, InitiatingProcessParentFileName
```
