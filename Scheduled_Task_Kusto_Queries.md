## Windows 10

`//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule") or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| summarize count() by InitiatingProcessCommandLine, ProcessCommandLine`

`//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule") or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| where ProcessCommandLine !endswith "AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe" and ProcessCommandLine !~ '"MicrosoftEdgeUpdate.exe" /ua /installsource scheduler' and ProcessCommandLine !endswith "gpupdate.exe /target:computer" and ProcessCommandLine !endswith "gpupdate.exe /target:user"
| summarize count() by InitiatingProcessCommandLine, ProcessCommandLine
| where  count_ <= 100`

`//scheduled tasks
DeviceProcessEvents
| where (ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule") and InitiatingProcessCommandLine contains "%TEMP%") or (InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule") and ProcessCommandLine contains "%TEMP%"))
| summarize count() by InitiatingProcessCommandLine, ProcessCommandLine`

## Windows 7

`//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("taskeng.exe","{") or InitiatingProcessCommandLine has_all ("taskeng.exe","{")
| summarize count() by InitiatingProcessCommandLine, ProcessCommandLine`

## Windows XP

Wmic process where processid-1234 get parentprocessid

`//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")  or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| summarize count() by FileName`

`//scheduled tasks
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")  or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| summarize count() by FolderPath`

## Scheduled tasks associated with certain filetypes associated with badness
`//scheduled tasks associated with certain filetypes associated with badness
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")  or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| where FileName contains "powershell" or FileName contains "cmd"  or FileName contains "rundll32" or FileName contains "regsvr32"  or FileName contains "wmic" 
| summarize count() by ProcessCommandLine`

`DeviceProcessEvents
| where FileName contains "powershell" or FileName contains "cmd"  or FileName contains "rundll32" or FileName contains "regsvr32"  or FileName contains "wmic" 
| summarize count() by ProcessCommandLine`

`DeviceProcessEvents
| where FileName contains ".ps1" or FileName contains ".bat"  or FileName contains ".vbs" or FileName contains ".cmd"  or FileName contains ".hta" or FileName contains ".js" 
| summarize count() by ProcessCommandLine`

`//scheduled tasks created by wscript or cscript and is not a common script extension (scrip interpreter but using a script file)
DeviceProcessEvents
| where ProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")  or InitiatingProcessCommandLine has_all ("svchost.exe","-k","netsvcs","-p","-s","Schedule")
| where FileName has_any ("wscript.exe","cscript.exe")  and not (ProcessCommandLine has_any (".vbs",".js"))
| summarize count() by ProcessCommandLine`

ToDo: Identify common files in system32 that are being run from non system32 locations

## Remote scheduled tasks

`DeviceImageLoadEvents
| where FileName =~ "mswsock.dll" and InitiatingProcessFileName has_any ("schtasks.exe","mmc.exe","at.exe")
//| project FileName, InitiatingProcessFileName, InitiatingProcessParentFileName`
