# Notion C2

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1102.002 | Web Service: Bidirectional Communication | [Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/) |

#### Description
Detects non-Notion processes communicating with the Notion API (api.notion.com or notion.com) that may indicate use of the OffensiveNotion framework for C2. OffensiveNotion is a red team tool that abuses the Notion note-taking platform as a C2 channel.

#### Risk
Attackers using OffensiveNotion can establish C2 communication through the Notion API, blending malicious traffic with legitimate Notion usage. Identifying non-Notion company processes communicating with Notion endpoints helps detect this activity early and prevent further compromise.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://github.com/mttaggart/OffensiveNotion

## Defender For Endpoint
```KQL
let excludedProcesses = datatable(name:string)["browser1.exe","browser2.exe"]; //examples but check your environment first to remove false positives and use the filename and file path to reduce risk of false negative or evasion from the bad guys
DeviceNetworkEvents
| where RemoteUrl has "api.notion.com" and not (InitiatingProcessFileName has_any (excludedProcesses)) and InitiatingProcessVersionInfoCompanyName != "Notion Labs, Inc"
```

## Sentinel
```KQL
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe", "swi_fc.exe"]; //add more browsers or mail clients where needed for exclusion 
    DeviceNetworkEvents
    | where RemoteUrl contains "notion.com"
    | where not(InitiatingProcessFileName has_any (excludedProcessFileNames)) and InitiatingProcessVersionInfoCompanyName != "Notion Labs, Inc"
    | extend joinkey = strcat(InitiatingProcessFileName, DeviceName, InitiatingProcessAccountName)
    | join kind=leftouter (DeviceProcessEvents | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize ProcessesRanByParent = make_set(InitiatingProcessCommandLine) by joinkey) on joinkey
    | join kind=leftouter (DeviceFileEvents | where ActionType == "FileCreated" | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize FilesCreated = make_set(FileName) by joinkey) on joinkey
    | project TimeGenerated,  DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FilesCreated, ProcessesRanByParent, LocalIP, RemoteIP, RemoteUrl
```
