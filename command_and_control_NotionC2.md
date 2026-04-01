# Notion Used as C2 Channel Detection (OffensiveNotion)

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1102.002 | Web Service: Bidirectional Communication | [Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/) |

#### Description
Detects non-browser processes making connections to Notion API endpoints (api.notion.com), which may indicate use of the OffensiveNotion C2 framework that uses Notion as a command and control channel.

#### Risk
OffensiveNotion is a C2 framework that uses the Notion productivity platform as its communication channel, making C2 traffic difficult to distinguish from legitimate Notion usage.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://github.com/mttaggart/OffensiveNotion

## Defender For Endpoint
```KQL
let excludedProcesses = datatable(name:string)["browser1.exe","browser2.exe"]; //examples but check your environment first to remove false positives and use the filename and file path to reduce risk of false negative or evasion from the bad guys
DeviceNetworkEvents
| where RemoteUrl has "api.notion.com" and not (InitiatingProcessFileName has_any (excludedProcesses)) and InitiatingProcessVersionInfoCompanyName != "Notion Labs, Inc"
```

```KQL
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe", "swi_fc.exe"]; //add more browsers or mail clients where needed for exclusion 
    DeviceNetworkEvents
    | where RemoteUrl contains "notion.com"
    | where not(InitiatingProcessFileName has_any (excludedProcessFileNames)) and InitiatingProcessVersionInfoCompanyName != "Notion Labs, Inc"
    | extend joinkey = strcat(InitiatingProcessFileName, DeviceName, InitiatingProcessAccountName)
    | join kind=leftouter (DeviceProcessEvents | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize ProcessesRanByParent = make_set(InitiatingProcessCommandLine) by joinkey) on joinkey
    | join kind=leftouter (DeviceFileEvents | where ActionType == "FileCreated" | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize FilesCreated = make_set(FileName) by joinkey) on joinkey
    | project TimeGenerated,  DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FilesCreated, ProcessesRanByParent, LocalIP, RemoteIP, RemoteUrl
```

## Sentinel
```KQL
let excludedProcesses = datatable(name:string)["browser1.exe","browser2.exe"]; //examples but check your environment first to remove false positives and use the filename and file path to reduce risk of false negative or evasion from the bad guys
DeviceNetworkEvents
| where RemoteUrl has "api.notion.com" and not (InitiatingProcessFileName has_any (excludedProcesses)) and InitiatingProcessVersionInfoCompanyName != "Notion Labs, Inc"
```

```KQL
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe", "swi_fc.exe"]; //add more browsers or mail clients where needed for exclusion 
    DeviceNetworkEvents
    | where RemoteUrl contains "notion.com"
    | where not(InitiatingProcessFileName has_any (excludedProcessFileNames)) and InitiatingProcessVersionInfoCompanyName != "Notion Labs, Inc"
    | extend joinkey = strcat(InitiatingProcessFileName, DeviceName, InitiatingProcessAccountName)
    | join kind=leftouter (DeviceProcessEvents | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize ProcessesRanByParent = make_set(InitiatingProcessCommandLine) by joinkey) on joinkey
    | join kind=leftouter (DeviceFileEvents | where ActionType == "FileCreated" | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize FilesCreated = make_set(FileName) by joinkey) on joinkey
    | project TimeGenerated,  DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FilesCreated, ProcessesRanByParent, LocalIP, RemoteIP, RemoteUrl
```
