# Title
ClearFake Detection Analytics

# Description
Queries to detect initial download of .appx file

# Source
- https://blog.sekoia.io/clearfake-a-newcomer-to-the-fake-updates-threats-landscape/

# MITRE ATT&CK
-

# Queries for sentinel and MDE

```
//TTP: ClearFake - Possible download of malicious .appx file
let browsers = datatable(name:string)["edge.exe","chrome.exe","firefox.exe"];
DeviceFileEvents
| where ActionType in~ ("FileCreated","FileRenamed") and InitiatingProcessFileName has_any (browsers) and FileName endswith ".appx"
```
