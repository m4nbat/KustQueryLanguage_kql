
# Title: Notion C2

# Source: 

- https://github.com/mttaggart/OffensiveNotion

# Tactic: Command and Control

# Technique: 

# MDE and Sentinel Kusto Query

```
let excludedProcesses = datatable(name:string)["browser1.exe","browser2.exe"]; //examples but check your environment first to remove false positives and use the filename and file path to reduce risk of false negative or evasion from the bad guys
DeviceNetworkEvents
| where RemoteUrl has "api.notion.com" and not (InitiatingProcessFileName has_any (excludedProcesses)) and InitiatingProcessVersionInfoCompanyName != "Notion Labs, Inc"
```

# Sentinel query to identify commandlines associated with suspicious processes communicating with googleapis.com endpoints
```
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe", "swi_fc.exe"]; //add more browsers or mail clients where needed for exclusion 
    DeviceNetworkEvents
    | where RemoteUrl contains "notion.com"
    | where not(InitiatingProcessFileName has_any (excludedProcessFileNames)) and InitiatingProcessVersionInfoCompanyName != "Notion Labs, Inc"
    | extend joinkey = strcat(InitiatingProcessFileName, DeviceName, InitiatingProcessAccountName)
    | join kind=leftouter (DeviceProcessEvents | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize ProcessesRanByParent = make_set(InitiatingProcessCommandLine) by joinkey) on joinkey
    | join kind=leftouter (DeviceFileEvents | where ActionType == "FileCreated" | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize FilesCreated = make_set(FileName) by joinkey) on joinkey
    | project TimeGenerated,  DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FilesCreated, ProcessesRanByParent, LocalIP, RemoteIP, RemoteUrl
```
