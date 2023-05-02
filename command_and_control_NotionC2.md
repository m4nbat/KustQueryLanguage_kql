
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

